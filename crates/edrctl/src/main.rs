//! edrctl: start, stop and check the macOS stack.
//!
//! - `edrctl up` starts edr-server and edr-locald, and capture_macos_rotating
//!   unless `--no-capture` is given
//! - `edrctl down` stops them
//! - `edrctl status` shows what is running and what the server holds
//!
//! Only the capture agent needs root, because /dev/auditpipe is root only.
//! When edrctl runs under sudo it starts the capture agent as root and starts
//! the server and locald as the user who ran sudo, so the HTTP server and the
//! YAML playbook engine never run with root privileges.

use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

#[derive(Parser)]
#[command(name = "edrctl")]
#[command(about = "Start, stop and check the macOS incident compiler stack")]
struct Cli {
    /// Telemetry folder (default: $EDR_TELEMETRY_ROOT, else ~/.edr)
    #[arg(long, global = true)]
    telemetry_root: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start edr-server, edr-locald and (with sudo) the capture agent
    Up {
        /// Port for edr-server
        #[arg(short, long, default_value = "3000")]
        port: u16,
        /// Run only edr-server and edr-locald, no capture and no sudo
        #[arg(long)]
        no_capture: bool,
    },
    /// Stop everything edrctl started
    Down,
    /// Show which processes are running and how many detections exist
    Status,
}

#[derive(Debug, Serialize, Deserialize)]
struct PidFile {
    server_pid: Option<u32>,
    locald_pid: Option<u32>,
    capture_pid: Option<u32>,
    port: u16,
    started_at: DateTime<Utc>,
    telemetry_root: String,
}

impl PidFile {
    fn path(root: &Path) -> PathBuf {
        root.join("pids.json")
    }

    fn load(root: &Path) -> Option<Self> {
        fs::read_to_string(Self::path(root))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    }

    fn save(&self, root: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(Self::path(root), json).map_err(|e| format!("write pids.json: {}", e))
    }
}

/// The user who ran sudo, if edrctl is running under sudo.
struct InvokingUser {
    uid: u32,
    gid: u32,
    home: PathBuf,
}

fn invoking_user() -> Option<InvokingUser> {
    let uid: u32 = std::env::var("SUDO_UID").ok()?.parse().ok()?;
    let gid: u32 = std::env::var("SUDO_GID").ok()?.parse().ok()?;
    if uid == 0 {
        return None;
    }
    // Look the home folder up from the password database rather than
    // trusting HOME, which sudo may or may not pass through.
    let home = unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return None;
        }
        let dir = std::ffi::CStr::from_ptr((*pw).pw_dir);
        PathBuf::from(dir.to_string_lossy().to_string())
    };
    Some(InvokingUser { uid, gid, home })
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn telemetry_root(cli_root: &Option<PathBuf>) -> PathBuf {
    if let Some(root) = cli_root {
        return root.clone();
    }
    if let Ok(root) = std::env::var("EDR_TELEMETRY_ROOT") {
        return PathBuf::from(root);
    }
    let home = invoking_user()
        .map(|u| u.home)
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".edr")
}

fn bin_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn is_running(pid: u32) -> bool {
    // Signal 0 checks that the pid exists. EPERM means it exists but belongs
    // to another user, for example the root capture agent.
    let rc = unsafe { libc::kill(pid as i32, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn stop(pid: u32) -> Result<(), String> {
    let rc = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

fn wait_for_server(port: u16, timeout: Duration) -> bool {
    let url = format!("http://127.0.0.1:{}/api/health", port);
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if let Ok(resp) = reqwest::blocking::get(&url) {
            if resp.status().is_success() {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    false
}

/// Start one process detached in its own session, with output in logs/.
fn spawn(
    program: &Path,
    args: &[&str],
    root: &Path,
    name: &str,
    run_as: Option<&InvokingUser>,
) -> Result<u32, String> {
    if !program.exists() {
        return Err(format!(
            "{} not found next to edrctl. Build it first with cargo build --workspace.",
            program.display()
        ));
    }
    let log_path = root.join("logs").join(format!("{}.log", name));
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| format!("open {}: {}", log_path.display(), e))?;
    let log_err = log.try_clone().map_err(|e| e.to_string())?;

    let mut command = Command::new(program);
    command
        .args(args)
        .env("EDR_TELEMETRY_ROOT", root)
        .stdin(Stdio::null())
        .stdout(log)
        .stderr(log_err);
    if let Some(user) = run_as {
        // Drop root for this child before exec.
        command.uid(user.uid).gid(user.gid).env("HOME", &user.home);
    }
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let child = command.spawn().map_err(|e| format!("start {}: {}", name, e))?;
    let pid = child.id();
    eprintln!("  {:<24} pid {:<7} log {}", name, pid, log_path.display());
    std::mem::forget(child);
    Ok(pid)
}

fn chown(path: &Path, user: &InvokingUser) {
    if let Ok(c) = std::ffi::CString::new(path.as_os_str().to_string_lossy().as_bytes()) {
        unsafe {
            libc::chown(c.as_ptr(), user.uid, user.gid);
        }
    }
}

fn cmd_up(root: &Path, port: u16, no_capture: bool) -> Result<(), String> {
    if !no_capture && !is_root() {
        return Err("live capture reads /dev/auditpipe, which needs root.\n  \
             Run: sudo edrctl up\n  \
             Or start only the server and locald: edrctl up --no-capture"
            .to_string());
    }
    if let Some(pids) = PidFile::load(root) {
        let alive = [pids.server_pid, pids.locald_pid, pids.capture_pid]
            .iter()
            .flatten()
            .any(|pid| is_running(*pid));
        if alive {
            return Err("the stack is already running. Run edrctl down first.".to_string());
        }
    }

    let user = if is_root() { invoking_user() } else { None };
    for dir in [root.to_path_buf(), root.join("segments"), root.join("logs")] {
        fs::create_dir_all(&dir).map_err(|e| format!("create {}: {}", dir.display(), e))?;
        if let Some(u) = &user {
            chown(&dir, u);
        }
    }

    let bins = bin_dir();
    eprintln!("edrctl up");
    eprintln!("  telemetry root: {}", root.display());
    if let Some(u) = &user {
        eprintln!("  server and locald run as uid {}, capture runs as root", u.uid);
    }

    let port_text = port.to_string();
    let server_pid = spawn(&bins.join("edr-server"), &["--port", &port_text], root, "edr-server", user.as_ref())?;
    let locald_pid = spawn(&bins.join("edr-locald"), &[], root, "edr-locald", user.as_ref())?;
    let capture_pid = if no_capture {
        eprintln!("  capture_macos_rotating   skipped (--no-capture)");
        None
    } else {
        Some(spawn(&bins.join("capture_macos_rotating"), &[], root, "capture_macos_rotating", None)?)
    };

    let pids = PidFile {
        server_pid: Some(server_pid),
        locald_pid: Some(locald_pid),
        capture_pid,
        port,
        started_at: Utc::now(),
        telemetry_root: root.display().to_string(),
    };
    pids.save(root)?;
    if let Some(u) = &user {
        chown(&PidFile::path(root), u);
    }

    if wait_for_server(port, Duration::from_secs(15)) {
        eprintln!("\nRunning. Open http://127.0.0.1:{}", port);
    } else {
        eprintln!("\nedr-server did not answer within 15 seconds. See {}", root.join("logs/edr-server.log").display());
    }
    if capture_pid.is_some() {
        eprintln!("If no detections appear, BSM auditing may be off in the kernel. The README explains how to turn it on.");
    }
    eprintln!("Stop with: edrctl down{}", if capture_pid.is_some() { " (with sudo, the capture agent runs as root)" } else { "" });
    Ok(())
}

fn cmd_down(root: &Path) -> Result<(), String> {
    let pids = match PidFile::load(root) {
        Some(p) => p,
        None => {
            eprintln!("edrctl down: no pids.json in {}, nothing to stop", root.display());
            return Ok(());
        }
    };
    let mut failed = false;
    for (name, pid) in [
        ("capture_macos_rotating", pids.capture_pid),
        ("edr-locald", pids.locald_pid),
        ("edr-server", pids.server_pid),
    ] {
        let pid = match pid {
            Some(p) => p,
            None => continue,
        };
        if !is_running(pid) {
            continue;
        }
        match stop(pid) {
            Ok(()) => eprintln!("  stopped {} (pid {})", name, pid),
            Err(e) => {
                eprintln!("  could not stop {} (pid {}): {}", name, pid, e);
                failed = true;
            }
        }
    }
    if failed {
        return Err("some processes are still running. The capture agent runs as root, so use sudo edrctl down.".to_string());
    }
    let _ = fs::remove_file(PidFile::path(root));
    eprintln!("edrctl down: done");
    Ok(())
}

fn cmd_status(root: &Path) -> Result<(), String> {
    println!("telemetry root: {}", root.display());
    let pids = match PidFile::load(root) {
        Some(p) => p,
        None => {
            println!("not running (no pids.json)");
            return Ok(());
        }
    };
    println!("started:        {}", pids.started_at);
    for (name, pid) in [
        ("edr-server", pids.server_pid),
        ("edr-locald", pids.locald_pid),
        ("capture", pids.capture_pid),
    ] {
        let state = match pid {
            Some(p) if is_running(p) => format!("running, pid {}", p),
            Some(p) => format!("not running, was pid {}", p),
            None => "not started".to_string(),
        };
        println!("{:<15} {}", format!("{}:", name), state);
    }
    let segments = fs::read_dir(root.join("segments"))
        .map(|d| d.flatten().filter(|e| e.path().extension().map(|x| x == "jsonl").unwrap_or(false)).count())
        .unwrap_or(0);
    println!("segments:       {}", segments);
    let url = format!("http://127.0.0.1:{}/api/signals/stats", pids.port);
    match reqwest::blocking::get(&url).and_then(|r| r.json::<serde_json::Value>()) {
        Ok(body) => println!("detections:     {}", body["data"]["total"]),
        Err(_) => println!("detections:     server not reachable on port {}", pids.port),
    }
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    let root = telemetry_root(&cli.telemetry_root);
    let result = match cli.command {
        Commands::Up { port, no_capture } => cmd_up(&root, port, no_capture),
        Commands::Down => cmd_down(&root),
        Commands::Status => cmd_status(&root),
    };
    if let Err(e) = result {
        eprintln!("edrctl: {}", e);
        std::process::exit(1);
    }
}
