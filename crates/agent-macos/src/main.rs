// agent-macos binary entry point
// This is the macOS capture agent main entry point

fn main() {
    eprintln!("agent-macos: macOS capture agent");
    eprintln!("Use the capture_macos_rotating module for production capture");

    // TODO: Integrate with actual capture logic once modules are fully wired
    // For now, just show a help message
    eprintln!();
    eprintln!("Available modules:");
    eprintln!("  - sensors::bsm - OpenBSM event parsing");
    eprintln!("  - sensors::es  - Endpoint Security events");
    eprintln!("  - platform     - Detection platform");
    eprintln!();
    eprintln!("Run with TELEMETRY_ROOT=/path/to/output to enable capture");
}
