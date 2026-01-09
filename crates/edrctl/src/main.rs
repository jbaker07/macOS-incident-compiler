//! edrctl - EDR Stack Orchestrator
//!
//! One command to start/stop the entire EDR stack:
//! - edrctl up    - Start capture + locald + server
//! - edrctl down  - Stop all components
//! - edrctl status - Show running status
//!
//! Platform-aware: handles macOS BSM (sudo), Linux eBPF, Windows ETW

use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

/// EDR Stack Orchestrator
#[derive(Parser)]
#[command(name = "edrctl")]
#[command(about = "One command to start/stop the EDR stack", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the EDR stack (capture + locald + server)
    Up {
        /// Port for the server (default: 3000)
        #[arg(short, long, default_value = "3000")]
        port: u16,
        /// Skip capture (run server+locald only)
        #[arg(long)]
        no_capture: bool,
    },
    /// Stop the EDR stack
    Down,
    /// Show status of EDR components
    Status,
}

/// PID file structure
#[derive(Debug, Serialize, Deserialize)]
struct PidFile {
    server_pid: Option<u32>,
    locald_pid: Option<u32>,
    capture_pid: Option<u32>,
    started_at: DateTime<Utc>,
    telemetry_root: String,
    platform: String,
}

impl PidFile {
    fn path(telemetry_root: &PathBuf) -> PathBuf {
        telemetry_root.join("pids.json")
    }

    fn load(telemetry_root: &PathBuf) -> Option<Self> {
        let path = Self::path(telemetry_root);
        fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    }

    fn save(&self, telemetry_root: &PathBuf) -> Result<(), String> {
        let path = Self::path(telemetry_root);
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize pids: {}", e))?;
        fs::write(&path, json).map_err(|e| format!("Failed to write pids.json: {}", e))
    }

    fn remove(telemetry_root: &PathBuf) {
        let path = Self::path(telemetry_root);
        let _ = fs::remove_file(&path);
    }
}

/// Get platform-appropriate telemetry root
fn get_telemetry_root() -> PathBuf {
    std::env::var("EDR_TELEMETRY_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            if cfg!(target_os = "windows") {
                PathBuf::from(r"C:\ProgramData\edr")
            } else if cfg!(target_os = "macos") {
                // Use /var/lib/edr for production, but ~/.edr for dev
                dirs::home_dir()
                    .map(|h| h.join(".edr"))
                    .unwrap_or_else(|| PathBuf::from("/var/lib/edr"))
            } else {
                PathBuf::from("/var/lib/edr")
            }
        })
}

/// Get the binary directory (where edrctl lives)
fn get_bin_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Get platform name
fn get_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}

/// Get capture binary name for platform
fn get_capture_binary() -> &'static str {
    if cfg!(target_os = "macos") {
        "capture_macos_rotating"
    } else if cfg!(target_os = "windows") {
        "capture_windows_etw"
    } else {
        "capture_linux_ebpf"
    }
}

/// Check if running as root/admin
fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        // On Windows, check for admin - simplified
        false
    }
}

/// Check if a process is running
fn is_process_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }
    #[cfg(windows)]
    {
        // Simplified Windows check
        Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid)])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
            .unwrap_or(false)
    }
}

/// Kill a process
fn kill_process(pid: u32) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid as i32, libc::SIGTERM) == 0 }
    }
    #[cfg(windows)]
    {
        Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

/// Wait for server health check
fn wait_for_server(port: u16, timeout_secs: u64) -> bool {
    let url = format!("http://127.0.0.1:{}/api/health", port);
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    while start.elapsed() < timeout {
        if let Ok(resp) = reqwest::blocking::get(&url) {
            if resp.status().is_success() {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

/// Spawn a process in a new session (properly daemonized)
fn spawn_process(
    cmd: &str,
    args: &[&str],
    env: &[(&str, &str)],
    description: &str,
) -> Result<u32, String> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        
        let mut command = Command::new(cmd);
        command
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null());

        for (k, v) in env {
            command.env(k, v);
        }

        // Create a new session so the process is fully detached
        // This is equivalent to running with setsid
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }

        let child = command
            .spawn()
            .map_err(|e| format!("Failed to start {}: {}", description, e))?;

        let pid = child.id();
        eprintln!("  [{}] Started (PID {})", description, pid);

        // Let the child handle itself - we've detached it via setsid
        std::mem::forget(child);

        Ok(pid)
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        const DETACHED_PROCESS: u32 = 0x00000008;

        let mut command = Command::new(cmd);
        command
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);

        for (k, v) in env {
            command.env(k, v);
        }

        let child = command
            .spawn()
            .map_err(|e| format!("Failed to start {}: {}", description, e))?;

        let pid = child.id();
        eprintln!("  [{}] Started (PID {})", description, pid);

        std::mem::forget(child);

        Ok(pid)
    }
}

/// Start the EDR stack
fn cmd_up(port: u16, no_capture: bool) -> Result<(), String> {
    let platform = get_platform();
    let telemetry_root = get_telemetry_root();
    let bin_dir = get_bin_dir();

    eprintln!("edrctl up - Starting EDR stack");
    eprintln!("  Platform: {}", platform);
    eprintln!("  Telemetry root: {}", telemetry_root.display());
    eprintln!("  Binary dir: {}", bin_dir.display());

    // Check if already running
    if let Some(pids) = PidFile::load(&telemetry_root) {
        let mut any_running = false;
        if let Some(pid) = pids.server_pid {
            if is_process_running(pid) {
                eprintln!("  Server already running (PID {})", pid);
                any_running = true;
            }
        }
        if any_running {
            return Err("Stack already running. Use 'edrctl down' first.".to_string());
        }
    }

    // Create directories
    let segments_dir = telemetry_root.join("segments");
    fs::create_dir_all(&segments_dir)
        .map_err(|e| format!("Failed to create telemetry dirs: {}", e))?;
    eprintln!("  Created: {}", segments_dir.display());

    // Platform-specific capture requirements
    if !no_capture && platform == "macos" && !is_root() {
        return Err(
            "macOS BSM capture requires root. Run: sudo edrctl up\n\
             Or skip capture with: edrctl up --no-capture"
                .to_string(),
        );
    }

    let telemetry_root_str = telemetry_root.to_string_lossy().to_string();
    let port_str = port.to_string();

    // Start server
    let server_bin = bin_dir.join("edr-server");
    let server_pid = spawn_process(
        server_bin.to_str().unwrap_or("edr-server"),
        &["--port", &port_str],
        &[("EDR_TELEMETRY_ROOT", &telemetry_root_str)],
        "edr-server",
    )?;

    // Start locald
    let locald_bin = bin_dir.join("edr-locald");
    let locald_pid = spawn_process(
        locald_bin.to_str().unwrap_or("edr-locald"),
        &[],
        &[("EDR_TELEMETRY_ROOT", &telemetry_root_str)],
        "edr-locald",
    )?;

    // Start capture (platform-specific)
    let capture_pid = if no_capture {
        eprintln!("  [capture] Skipped (--no-capture)");
        None
    } else {
        let capture_bin = bin_dir.join(get_capture_binary());
        let pid = spawn_process(
            capture_bin.to_str().unwrap_or(get_capture_binary()),
            &[],
            &[("EDR_TELEMETRY_ROOT", &telemetry_root_str)],
            get_capture_binary(),
        )?;
        Some(pid)
    };

    // Save PID file
    let pids = PidFile {
        server_pid: Some(server_pid),
        locald_pid: Some(locald_pid),
        capture_pid,
        started_at: Utc::now(),
        telemetry_root: telemetry_root_str.clone(),
        platform: platform.to_string(),
    };
    pids.save(&telemetry_root)?;

    // Wait for server health
    eprintln!("\n  Waiting for server...");
    if wait_for_server(port, 15) {
        eprintln!("\n✅ EDR stack is running!");
        eprintln!("   Open http://127.0.0.1:{}", port);
        eprintln!("   Telemetry: {}", telemetry_root_str);
        
        // macOS audit warning
        if platform == "macos" && capture_pid.is_some() {
            eprintln!();
            eprintln!("   ⚠️  macOS NOTE: OpenBSM audit is DISABLED by default on macOS 14+.");
            eprintln!("      To enable real BSM capture, you must:");
            eprintln!("        1. sudo cp /etc/security/audit_control.example /etc/security/audit_control");
            eprintln!("        2. sudo launchctl enable system/com.apple.auditd");
            eprintln!("        3. Reboot");
            eprintln!("      Without this, capture will run but receive no events.");
        }
        
        eprintln!("\n   To stop: edrctl down");
        Ok(())
    } else {
        eprintln!("\n⚠️  Server did not respond in time.");
        eprintln!("   Check logs or try: edrctl status");
        Ok(()) // Don't fail - processes may still be starting
    }
}

/// Stop the EDR stack
fn cmd_down() -> Result<(), String> {
    let telemetry_root = get_telemetry_root();

    eprintln!("edrctl down - Stopping EDR stack");

    let pids = match PidFile::load(&telemetry_root) {
        Some(p) => p,
        None => {
            eprintln!("  No pids.json found. Stack may not be running.");
            return Ok(());
        }
    };

    let mut stopped = 0;

    // Stop capture first
    if let Some(pid) = pids.capture_pid {
        if is_process_running(pid) {
            if kill_process(pid) {
                eprintln!("  [capture] Stopped (PID {})", pid);
                stopped += 1;
            }
        }
    }

    // Stop locald
    if let Some(pid) = pids.locald_pid {
        if is_process_running(pid) {
            if kill_process(pid) {
                eprintln!("  [locald] Stopped (PID {})", pid);
                stopped += 1;
            }
        }
    }

    // Stop server
    if let Some(pid) = pids.server_pid {
        if is_process_running(pid) {
            if kill_process(pid) {
                eprintln!("  [server] Stopped (PID {})", pid);
                stopped += 1;
            }
        }
    }

    // Remove PID file
    PidFile::remove(&telemetry_root);

    if stopped > 0 {
        eprintln!("\n✅ Stopped {} processes", stopped);
    } else {
        eprintln!("\n  No running processes found.");
    }

    Ok(())
}

/// Show status of EDR components
fn cmd_status() -> Result<(), String> {
    let telemetry_root = get_telemetry_root();

    eprintln!("edrctl status");
    eprintln!("  Telemetry root: {}", telemetry_root.display());

    let pids = match PidFile::load(&telemetry_root) {
        Some(p) => p,
        None => {
            eprintln!("\n  Status: NOT RUNNING (no pids.json)");
            return Ok(());
        }
    };

    eprintln!("  Started: {}", pids.started_at);
    eprintln!("  Platform: {}", pids.platform);
    eprintln!();

    // Check each component
    let server_status = pids
        .server_pid
        .map(|pid| {
            if is_process_running(pid) {
                format!("✅ Running (PID {})", pid)
            } else {
                format!("❌ Dead (was PID {})", pid)
            }
        })
        .unwrap_or_else(|| "⚪ Not started".to_string());

    let locald_status = pids
        .locald_pid
        .map(|pid| {
            if is_process_running(pid) {
                format!("✅ Running (PID {})", pid)
            } else {
                format!("❌ Dead (was PID {})", pid)
            }
        })
        .unwrap_or_else(|| "⚪ Not started".to_string());

    let capture_status = pids
        .capture_pid
        .map(|pid| {
            if is_process_running(pid) {
                format!("✅ Running (PID {})", pid)
            } else {
                format!("❌ Dead (was PID {})", pid)
            }
        })
        .unwrap_or_else(|| "⚪ Not started".to_string());

    eprintln!("  server:  {}", server_status);
    eprintln!("  locald:  {}", locald_status);
    eprintln!("  capture: {}", capture_status);

    // Check segments
    let segments_dir = telemetry_root.join("segments");
    if let Ok(entries) = fs::read_dir(&segments_dir) {
        let count = entries.filter_map(|e| e.ok()).count();
        eprintln!("\n  Segments: {}", count);
    }

    // Check signals in DB
    let db_path = telemetry_root.join("workbench.db");
    if db_path.exists() {
        eprintln!("  Database: {}", db_path.display());
    }

    Ok(())
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Up { port, no_capture } => cmd_up(port, no_capture),
        Commands::Down => cmd_down(),
        Commands::Status => cmd_status(),
    };

    if let Err(e) = result {
        eprintln!("\n❌ Error: {}", e);
        std::process::exit(1);
    }
}
