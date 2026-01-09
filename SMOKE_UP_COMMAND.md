# SMOKE_UP_COMMAND.md — edrctl One-Command Stack

**Date**: 2026-01-09  
**Component**: `edrctl` - EDR Stack Orchestrator

## Overview

`edrctl` provides a single command to start/stop the entire EDR stack:
- `edrctl up` - Start capture + locald + server
- `edrctl down` - Stop all components  
- `edrctl status` - Show running status

## Quick Start

### macOS (Real BSM Capture)

```bash
# Build all binaries
cargo build -p edrctl -p edr-server -p edr-locald -p agent-macos

# Start full stack (requires sudo for BSM auditpipe)
sudo ./target/debug/edrctl up

# Check status
./target/debug/edrctl status

# Stop
sudo ./target/debug/edrctl down
```

### macOS (No Capture - Server Only)

```bash
# Start without capture (no sudo needed)
./target/debug/edrctl up --no-capture

# Stop
./target/debug/edrctl down
```

### Linux

```bash
# Build
cargo build -p edrctl -p edr-server -p edr-locald -p agent-linux

# Start (eBPF may need caps or root)
./target/debug/edrctl up

# Or without capture
./target/debug/edrctl up --no-capture
```

### Windows

```powershell
# Build
cargo build -p edrctl -p edr-server -p edr-locald -p agent-windows

# Start
.\target\debug\edrctl.exe up

# Stop
.\target\debug\edrctl.exe down
```

## Options

```
edrctl up [OPTIONS]

Options:
  -p, --port <PORT>  Port for the server (default: 3000)
      --no-capture   Skip capture (run server+locald only)
  -h, --help         Print help
```

## Telemetry Root

Default locations:
- **macOS**: `~/.edr` (dev) or `/var/lib/edr` (prod)
- **Linux**: `/var/lib/edr`
- **Windows**: `C:\ProgramData\edr`

Override with environment variable:
```bash
export EDR_TELEMETRY_ROOT=/custom/path
edrctl up
```

## PID Management

`edrctl` stores PIDs in `$EDR_TELEMETRY_ROOT/pids.json`:

```json
{
  "server_pid": 12345,
  "locald_pid": 12346,
  "capture_pid": 12347,
  "started_at": "2026-01-09T06:46:57Z",
  "telemetry_root": "/Users/you/.edr",
  "platform": "macos"
}
```

## Example Output

### edrctl up (macOS with sudo)

```
edrctl up - Starting EDR stack
  Platform: macos
  Telemetry root: /Users/you/.edr
  Binary dir: /path/to/target/debug
  Created: /Users/you/.edr/segments
  [edr-server] Started (PID 11163)
  [edr-locald] Started (PID 11164)
  [capture_macos_rotating] Started (PID 11165)

  Waiting for server...

✅ EDR stack is running!
   Open http://127.0.0.1:3000
   Telemetry: /Users/you/.edr

   To stop: edrctl down
```

### edrctl status

```
edrctl status
  Telemetry root: /Users/you/.edr
  Started: 2026-01-09 06:46:57 UTC
  Platform: macos

  server:  ✅ Running (PID 11163)
  locald:  ✅ Running (PID 11164)
  capture: ✅ Running (PID 11165)

  Segments: 3
  Database: /Users/you/.edr/workbench.db
```

### edrctl down

```
edrctl down - Stopping EDR stack
  [capture] Stopped (PID 11165)
  [locald] Stopped (PID 11164)
  [server] Stopped (PID 11163)

✅ Stopped 3 processes
```

## Platform-Specific Notes

### macOS BSM

- Requires `sudo` to access `/dev/auditpipe`
- Without root: `edrctl up` fails with clear message
- Use `--no-capture` to run server+locald without BSM

### Linux eBPF

- May require `CAP_BPF` or root for full capture
- Falls back gracefully if eBPF unavailable

### Windows ETW

- Runs as normal user
- May need admin for certain event providers

## Troubleshooting

### "macOS BSM capture requires root"

Run with sudo:
```bash
sudo ./target/debug/edrctl up
```

Or skip capture:
```bash
./target/debug/edrctl up --no-capture
```

### Server not responding

Check status:
```bash
./target/debug/edrctl status
```

Check logs manually:
```bash
ps aux | grep edr
```

### Port already in use

Use a different port:
```bash
./target/debug/edrctl up --port 3001
```
