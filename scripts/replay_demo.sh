#!/bin/bash
#Replays the recorded BSM audit trails through the whole pipeline without root.
#capture_macos_rotating decodes the trails into segments, edr-locald runs the
#macOS playbooks over them, and the script prints what fired.
#Usage: scripts/replay_demo.sh [output_folder]

set -e

if [ $# -gt 1 ]; then
    echo "Usage: $0 [output_folder]"
    exit 1
fi

REPO_ROOT_FOLDER="$(cd "$(dirname "$0")/.." && pwd)"
DEMO_TELEMETRY_ROOT="${1:-$(mktemp -d /tmp/edr-replay-demo.XXXXXX)}"
ATTACK_TRAIL_FILE="$REPO_ROOT_FOLDER/tests/fixtures/bsm/attack_chain.bsm"
BENIGN_TRAIL_FILE="$REPO_ROOT_FOLDER/tests/fixtures/bsm/benign_session.bsm"
BINARY_FOLDER="$REPO_ROOT_FOLDER/target/debug"

#Build first so the script always runs the current code.
cargo build --quiet --manifest-path "$REPO_ROOT_FOLDER/Cargo.toml" -p agent-macos -p edr-locald

#--host pins the host name so the output is the same on every machine.
"$BINARY_FOLDER/capture_macos_rotating" --telemetry-root "$DEMO_TELEMETRY_ROOT" --host demo-mac \
    --bsm-file "$ATTACK_TRAIL_FILE" --bsm-file "$BENIGN_TRAIL_FILE"

#--once processes the segments that exist now and exits instead of watching.
"$BINARY_FOLDER/edr-locald" --telemetry-root "$DEMO_TELEMETRY_ROOT" --once

DETECTION_COUNT=$(sqlite3 "$DEMO_TELEMETRY_ROOT/workbench.db" "SELECT COUNT(*) FROM signals")
echo
echo "Detections stored in $DEMO_TELEMETRY_ROOT/workbench.db:"
sqlite3 -separator "  " "$DEMO_TELEMETRY_ROOT/workbench.db" \
    "SELECT severity, signal_type FROM signals ORDER BY ts_start"
echo
echo "Wrote $DETECTION_COUNT detections. To browse them: edrctl --telemetry-root $DEMO_TELEMETRY_ROOT up --no-capture"
