#!/bin/bash
#Live smoke test for the whole pipeline on a real kernel audit stream.
#Turns BSM auditing on if it can, captures from /dev/auditpipe for 40 seconds
#while running commands that eight playbooks watch for, runs edr-locald over
#what was captured and checks that all eight fired.
#
#Usage:
#  sudo scripts/live_smoke.sh [output_folder]
#  scripts/live_smoke.sh --replay TRAIL.bsm [output_folder]
#
#--replay skips root, auditing and the commands, replays a recorded trail
#instead and runs the same checks. CI uses it when live auditing cannot start.
#
#Exit codes: 0 every check passed, 1 a check failed, 3 auditing could not be
#started without a reboot, so nothing was tested live.
#Build first with cargo build --workspace. The script does not build, because
#a build run as root would leave root owned files in target/.

AUDIT_UNAVAILABLE_EXIT_CODE=3
CAPTURE_SECONDS=40
REPLAY_TRAIL_FILE=""
if [ "$1" = "--replay" ]; then
    if [ $# -lt 2 ]; then
        echo "Usage: $0 --replay TRAIL.bsm [output_folder]"
        exit 1
    fi
    REPLAY_TRAIL_FILE="$2"
    shift 2
fi
if [ $# -gt 1 ]; then
    echo "Usage: sudo $0 [output_folder]"
    echo "       $0 --replay TRAIL.bsm [output_folder]"
    exit 1
fi

REPO_ROOT_FOLDER="$(cd "$(dirname "$0")/.." && pwd)"
BINARY_FOLDER="$REPO_ROOT_FOLDER/target/debug"
SMOKE_OUTPUT_FOLDER="${1:-/private/tmp/edr-smoke-$(date +%s)}"
SMOKE_TELEMETRY_ROOT="$SMOKE_OUTPUT_FOLDER/telemetry"
SMOKE_WORK_FOLDER="$SMOKE_OUTPUT_FOLDER/work"
SUMMARY_FILE="$SMOKE_OUTPUT_FOLDER/summary.md"

#The playbooks the commands below are written to trigger.
EXPECTED_PLAYBOOKS="macos_keychain_dump
macos_osascript_shell
macos_quarantine_attribute_removed
macos_exec_from_writable_dir
macos_writable_exec_then_egress
macos_shell_history_deletion
macos_ssh_private_key_read
macos_launch_agent_persistence"

for BINARY_NAME in capture_macos_rotating edr-locald; do
    if [ ! -x "$BINARY_FOLDER/$BINARY_NAME" ]; then
        echo "$BINARY_FOLDER/$BINARY_NAME is missing. Run cargo build --workspace first."
        exit 1
    fi
done
mkdir -p "$SMOKE_TELEMETRY_ROOT" "$SMOKE_WORK_FOLDER" || exit 1
: >"$SUMMARY_FILE"

#Try every way to turn auditing on that does not need a reboot. The man pages
#for audit(8), auditd(8) and audit_control(5) on macOS 14 and later say to
#copy audit_control.example, run launchctl enable and reboot. The reboot is
#what loads the auditd job into launchd, so bootstrap loads it now instead,
#and audit -i asks auditd to start auditing.
enable_auditing(){
if /usr/sbin/audit -c >/dev/null 2>&1; then
    echo "auditing was already enabled"
    return 0
fi
if [ ! -f /etc/security/audit_control ]; then
    echo "+ cp /etc/security/audit_control.example /etc/security/audit_control"
    cp /etc/security/audit_control.example /etc/security/audit_control
fi
echo "+ launchctl enable system/com.apple.auditd"
launchctl enable system/com.apple.auditd 2>&1
echo "+ launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.auditd.plist"
launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.auditd.plist 2>&1
echo "+ audit -i"
/usr/sbin/audit -i 2>&1
sleep 2
if /usr/sbin/audit -c >/dev/null 2>&1; then
    return 0
fi
echo "+ launchctl kickstart -k system/com.apple.auditd"
launchctl kickstart -k system/com.apple.auditd 2>&1
/usr/sbin/audit -i 2>&1
sleep 2
if /usr/sbin/audit -c >/dev/null 2>&1; then
    return 0
fi
echo "launchctl print system/com.apple.auditd:"
launchctl print system/com.apple.auditd 2>&1 | head -20
return 1
}

#Run each command a playbook watches for. They all run inside the work
#folder and touch nothing outside it except the network request.
trigger_behaviours(){
cd "$SMOKE_WORK_FOLDER" || return
echo "+ security find-generic-password (keychain dump playbook)"
/usr/bin/security find-generic-password -s edr-smoke-test >/dev/null 2>&1
echo "+ osascript do shell script (AppleScript playbook)"
/usr/bin/osascript -e 'do shell script "id"' >/dev/null 2>&1
echo "+ xattr -d com.apple.quarantine (Gatekeeper bypass playbook)"
: >downloaded.bin
/usr/bin/xattr -d com.apple.quarantine downloaded.bin >/dev/null 2>&1
echo "+ run a copy of curl from a writable folder and connect out (two playbooks)"
/bin/cp /usr/bin/curl "$SMOKE_WORK_FOLDER/curl"
#macOS kills a copied Apple platform binary on launch (SIGKILL from code
#signing checks), so give the copy its own ad hoc signature first.
/usr/bin/codesign --force --sign - "$SMOKE_WORK_FOLDER/curl" >/dev/null 2>&1
"$SMOKE_WORK_FOLDER/curl" -s -o /dev/null --max-time 10 https://example.com
echo "+ delete a .zsh_history file (history wipe playbook)"
: >.zsh_history
/bin/rm -f .zsh_history
echo "+ read a file named like an SSH private key (credential playbook)"
mkdir -p .ssh
echo "not a real key" >.ssh/id_edrsmoke
/bin/cat .ssh/id_edrsmoke >/dev/null
echo "+ write a plist into a LaunchAgents folder (persistence playbook)"
mkdir -p Library/LaunchAgents
printf '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict><key>Label</key><string>edr.smoke</string></dict></plist>\n' >agent.plist
/bin/cp agent.plist Library/LaunchAgents/edr.smoke.plist
cd - >/dev/null || return
}

if [ -n "$REPLAY_TRAIL_FILE" ]; then
    echo "== Replay mode: $REPLAY_TRAIL_FILE"
    "$BINARY_FOLDER/capture_macos_rotating" --telemetry-root "$SMOKE_TELEMETRY_ROOT" --bsm-file "$REPLAY_TRAIL_FILE" || exit 1
    echo "Mode: replay of $(basename "$REPLAY_TRAIL_FILE")" >>"$SUMMARY_FILE"
else
    if [ "$(id -u)" -ne 0 ]; then
        echo "Live capture reads /dev/auditpipe, which needs root. Run: sudo $0"
        exit 1
    fi
    echo "== Turning on BSM auditing"
    if ! enable_auditing; then
        echo "AUDIT_UNAVAILABLE: auditing could not be started without a reboot on this machine."
        echo "Live capture was NOT tested." | tee -a "$SUMMARY_FILE"
        exit $AUDIT_UNAVAILABLE_EXIT_CODE
    fi
    echo "Mode: live capture from /dev/auditpipe" >>"$SUMMARY_FILE"

    echo "== Capturing for $CAPTURE_SECONDS seconds"
    "$BINARY_FOLDER/capture_macos_rotating" --telemetry-root "$SMOKE_TELEMETRY_ROOT" --duration $CAPTURE_SECONDS &
    CAPTURE_PID=$!
    #Give the pipe a moment to be configured before the commands run.
    sleep 5
    trigger_behaviours
    wait $CAPTURE_PID
    CAPTURE_EXIT_CODE=$?
    if [ $CAPTURE_EXIT_CODE -ne 0 ]; then
        echo "capture_macos_rotating exited with $CAPTURE_EXIT_CODE"
        exit 1
    fi
fi

echo "== Running edr-locald"
"$BINARY_FOLDER/edr-locald" --telemetry-root "$SMOKE_TELEMETRY_ROOT" --once || exit 1

HEARTBEAT_FILE="$SMOKE_TELEMETRY_ROOT/capture_heartbeat.json"
RECORDS_READ=$(grep -o '"records_read": [0-9]*' "$HEARTBEAT_FILE" | grep -o '[0-9]*$')
DECODE_ERRORS=$(grep -o '"decode_errors": [0-9]*' "$HEARTBEAT_FILE" | grep -o '[0-9]*$')
UNKNOWN_TOKEN_RECORDS=$(grep -o '"records_with_unknown_token": [0-9]*' "$HEARTBEAT_FILE" | grep -o '[0-9]*$')
#Records the kernel dropped because the audit pipe queue was full. null in replay mode or if the ioctl failed.
PIPE_DROPS=$(grep -o '"pipe_drops": [0-9a-z]*' "$HEARTBEAT_FILE" | grep -o '[0-9a-z]*$')
echo "Records read: ${RECORDS_READ:-0}, decode errors: ${DECODE_ERRORS:-0}, records with an unknown token: ${UNKNOWN_TOKEN_RECORDS:-0}, dropped by the audit pipe: ${PIPE_DROPS:-unknown}" | tee -a "$SUMMARY_FILE"

FAILED_CHECKS=0
if [ "${RECORDS_READ:-0}" -eq 0 ]; then
    echo "FAIL: no audit records were read" | tee -a "$SUMMARY_FILE"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi
if [ "${DECODE_ERRORS:-0}" -ne 0 ]; then
    echo "FAIL: $DECODE_ERRORS records did not decode" | tee -a "$SUMMARY_FILE"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi
if [ "${UNKNOWN_TOKEN_RECORDS:-0}" -ne 0 ]; then
    #Not a failure: the subject and return tokens are still recovered.
    echo "NOTE: $UNKNOWN_TOKEN_RECORDS records had a token type the parser does not size yet" | tee -a "$SUMMARY_FILE"
fi

for PLAYBOOK_ID in $EXPECTED_PLAYBOOKS; do
    FIRED_COUNT=$(sqlite3 "$SMOKE_TELEMETRY_ROOT/workbench.db" "SELECT COUNT(*) FROM signals WHERE signal_type = '$PLAYBOOK_ID'")
    if [ "${FIRED_COUNT:-0}" -gt 0 ]; then
        echo "PASS: $PLAYBOOK_ID fired" | tee -a "$SUMMARY_FILE"
    else
        echo "FAIL: $PLAYBOOK_ID did not fire" | tee -a "$SUMMARY_FILE"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
done

echo "Detections stored: $(sqlite3 "$SMOKE_TELEMETRY_ROOT/workbench.db" "SELECT COUNT(*) FROM signals")"
if [ $FAILED_CHECKS -ne 0 ]; then
    #Show what the capture recorded for the trigger files, so a miss can be told apart
    #from a record the audit pipe dropped.
    for TRIGGER_FILE in LaunchAgents agent.plist /work/curl zsh_history id_edrsmoke; do
        echo "Captured events that name $TRIGGER_FILE (first 5):"
        cat "$SMOKE_TELEMETRY_ROOT"/segments/*.jsonl 2>/dev/null | python3 -c '
import json, sys
shown = 0
for line in sys.stdin:
    if sys.argv[1] not in line:
        continue
    f = json.loads(line).get("fields", {})
    print("  ", f.get("aue_name"), f.get("op"), f.get("path"), f.get("new_path", ""), f.get("exe"), "success", f.get("success"))
    shown += 1
    if shown == 5:
        break
if shown == 0:
    print("   none")
' "$TRIGGER_FILE"
    done
    echo "$FAILED_CHECKS checks failed. Output is in $SMOKE_OUTPUT_FOLDER"
    exit 1
fi
echo "All checks passed. Output is in $SMOKE_OUTPUT_FOLDER"
