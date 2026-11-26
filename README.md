# macOS Incident Compiler

A detection pipeline for macOS written in Rust. It reads the kernel audit trail (OpenBSM), decodes each binary audit record into a flat event, runs YAML playbooks that join related events into detections, and stores every detection with pointers to the exact records behind it. The pointers carry a SHA-256 of each record, so an analyst can check any claim against the source data.

```text
/dev/auditpipe (live, root)  or  audit trail file (replay, no root)
        |
        v
capture_macos_rotating   decode BSM tokens, name the syscall, write JSONL segments + index.json
        |
        v
edr-locald               events -> facts -> playbook slots -> detections in workbench.db
        |
        v
edr-server               HTTP API and detections page on 127.0.0.1:3000
```

`edrctl` starts, stops and checks the three processes.

## Why BSM and not Endpoint Security

Apple's Endpoint Security framework is the supported way to watch process, file and network activity on current macOS. A client needs the `com.apple.developer.endpoint-security.client` entitlement, which Apple grants to approved developers on request, plus root and Full Disk Access. Without the entitlement an ES client only runs with System Integrity Protection turned off. This project does not have the entitlement, so it uses the BSM audit subsystem instead and contains no Endpoint Security code.

BSM has a cost. `man audit` on macOS 27.2 says the audit subsystem has been deprecated since macOS 11, disabled by default since macOS 14, and will be removed in a future release. `/dev/auditpipe` is still present on macOS 27.2, but the kernel only produces records after auditing is turned back on (see [Live capture](#live-capture)).

## What has been checked

On macOS 27.2 (Apple silicon) with Rust 1.100.0:

- `cargo build --workspace` and `cargo test --workspace` pass (256 tests).
- The audit event numbers in `crates/agent-macos/src/sensors/bsm/aue.rs` are compared by a test with `<bsm/audit_kevents.h>` from the SDK and with `/etc/security/audit_event`.
- The token parser is tested against binary audit trails written with Apple's libbsm (`tools/bsm-fixtures/make_bsm_fixtures.c`). Another test runs Apple's `praudit` on the same files and checks that the event number, timestamp, pid and paths of every record match.
- `scripts/replay_demo.sh` replays those trails through capture and edr-locald. The attack trail fires all 16 playbooks it was written for and the benign trail fires none.
- A test kills edr-locald between the two steps of the launchd playbook (the plist write and the `launchctl load`), restarts it, and still gets the detection.
- `scripts/live_smoke.sh --replay` runs the live smoke test's checks on the recorded trail and passes.
- `edrctl up --no-capture`, `edrctl status` and `edrctl down` were run, and the detections page was opened in a browser.

Not checked on this Mac: live capture from the kernel and `sudo edrctl up`, because both need root. The `live-capture` CI job runs `scripts/live_smoke.sh` with sudo on a GitHub macOS runner (see [Live capture](#live-capture)). On November 24, 2026 it turned auditing on without a reboot and passed: 131,493 records read, 0 decode errors, and all eight playbooks fired from live records.

## Quick start without root

```bash
cargo build --workspace
scripts/replay_demo.sh /tmp/edr-demo
./target/debug/edrctl --telemetry-root /tmp/edr-demo up --no-capture
open http://127.0.0.1:3000
./target/debug/edrctl --telemetry-root /tmp/edr-demo down
```

The demo prints the 16 detections. On the page, click one to see its playbook slots, the audit events that filled them and whether each event still matches its SHA-256.

## Live capture

Auditing is off by default since macOS 14. The man pages for `audit(8)`, `auditd(8)` and `audit_control(5)` on macOS 27.2 all carry the same notice: deprecated since macOS 11, disabled since macOS 14, to be removed in a future release, and to turn it back on, copy `audit_control.example` to `audit_control`, run `launchctl enable system/com.apple.auditd` as root and reboot. The reboot is what loads the auditd job into launchd.

### Smoke test

One line, from the repository root after `cargo build --workspace`:

```bash
sudo scripts/live_smoke.sh
```

It changes system settings: if auditing is off it copies `/etc/security/audit_control.example` to `/etc/security/audit_control`, runs `launchctl enable system/com.apple.auditd`, loads the job with `launchctl bootstrap` and starts auditing with `audit -i`, to avoid the reboot. Then it captures from `/dev/auditpipe` for 40 seconds while it runs eight harmless commands inside its own work folder (`security find-generic-password`, `osascript` with `do shell script`, `xattr -d com.apple.quarantine`, an ad hoc signed copy of curl run from `/private/tmp` that fetches https://example.com, deleting a `.zsh_history` file, reading a file named `.ssh/id_edrsmoke`, and copying a plist into a `Library/LaunchAgents` folder). Last it runs edr-locald and checks the result.

It passed if it ends with `All checks passed`, after a `PASS` line for each of the eight playbooks and a line showing records read above 0 and decode errors at 0. A `NOTE` about records with an unknown token is not a failure, but it means the kernel wrote a token type the parser does not size yet. Exit code 3 with `AUDIT_UNAVAILABLE` means auditing could not be started without a reboot. In that case reboot and run it again.

To turn auditing back off afterwards:

```bash
sudo audit -t
sudo launchctl bootout system/com.apple.auditd
sudo launchctl disable system/com.apple.auditd
sudo rm /etc/security/audit_control
```

The CI job `live-capture` runs the same script on a GitHub macOS runner, which has passwordless sudo. If the runner cannot start auditing without a reboot, the job prints a warning that live capture was not tested and runs `scripts/live_smoke.sh --replay tests/fixtures/bsm/attack_chain.bsm` instead, so it does not fail for that reason alone.

### Running the stack live

Only the capture agent runs as root. Under sudo, `edrctl` starts edr-locald and edr-server as the user who ran sudo.

```bash
sudo ./target/debug/edrctl up
sudo ./target/debug/edrctl down
```

## Components

| Component | Location | What it does |
|-----------|----------|--------------|
| `capture_macos_rotating` | `crates/agent-macos` | Opens `/dev/auditpipe`, switches it to local preselection with its own audit classes (default `ex,pc,fr,fw,fc,fd,fm,nt,ad`) and raises the queue limit, or reads trail files with `--bsm-file`. Splits the byte stream into records, parses the tokens the kernel writes for audited calls (header, subject, process, return, path, text, arguments, exec arguments and environment, attributes, sockets, identity and the rest of the fixed size tokens in `<bsm/audit_record.h>`) and turns each record into one event. If it meets a token it cannot size, it still recovers the subject and return tokens from their fixed place before the trailer and counts the record in the heartbeat. Writes segments atomically, records a SHA-256 per segment in `index.json` and chains each version of the index to the previous one. |
| `edr-locald` | `crates/locald` | Reads segments in index order, checks each segment's SHA-256 against the index and skips any that changed, extracts facts, and runs the playbooks. Each detection goes into `workbench.db` with an explanation. After every segment it saves the finished segment list and every open hypothesis in one SQLite transaction, and reads both back on start, so a restart in the middle of a multi step playbook loses nothing. `--once` processes what exists and exits. |
| `edr-server` | `crates/server` | Read only axum server on `127.0.0.1:3000` (`--port` to change). Serves the detections page, compiled into the binary, and the five API routes below. |
| `edrctl` | `crates/edrctl` | `up`, `down`, `status`. Keeps PIDs in `pids.json` and process logs in `logs/` under the telemetry root (`~/.edr` by default). |
| playbooks | `playbooks/macos/*.yaml` | 19 detections in one schema, compiled into edr-locald. |
| fixtures | `tests/fixtures/bsm/`, `tools/bsm-fixtures/` | Binary audit trails and the C program that writes them with libbsm. Rebuilding gives byte identical files. |

### API used by the pipeline

```bash
curl http://127.0.0.1:3000/api/health
curl http://127.0.0.1:3000/api/signals
curl http://127.0.0.1:3000/api/signals/stats
curl http://127.0.0.1:3000/api/signals/<signal_id>
curl http://127.0.0.1:3000/api/signals/<signal_id>/explain
```

Those are the only API routes. The API has no authentication, which is why the server listens on loopback only (`EDR_SERVER_BIND=0.0.0.0` changes that) and sends no CORS headers, so a web page from another site cannot read the responses.

## Event format

Every event has three tags, `["macos", category, operation]`, and flat fields:

| Category | Operations | Main fields |
|----------|------------|-------------|
| `process` | `exec`, `fork`, `exit`, `kill`, `task_for_pid`, `ptrace` | `exe`, `argv`, `cmdline`, `ppid`, `signing_id`, `team_id`, `cdhash`, `target_pid` |
| `file` | `read`, `write`, `create`, `delete`, `rename`, `chmod`, `chown`, `truncate`, `link` | `path`, `new_path`, `access`, `open_flags`, `new_mode`, `inode` |
| `privilege` | `setuid`, `seteuid`, `setgid`, `setgroups` and the other set id calls | `target_uid`, `target_gid` |
| `network` | `connect`, `accept`, `bind`, `listen`, `socket` | `remote_ip`, `remote_port`, `family`, `fd` |
| `fs` | `mount`, `unmount` | `path`, `fs_type` |
| `audit_config` | `auditon`, `auditctl`, `audit` | |

Every event also has `pid`, `uid`, `euid`, `gid`, `egid`, `auid`, `asid`, `success`, `errno` when the call failed, `aue_code` and `aue_name`. File and network records only carry a pid, so the agent fills in `exe` from the last exec it saw for that pid. A posix_spawn record names the parent as its subject, so the agent takes the new pid from the `child PID` argument.

## Playbooks

| Playbook | Severity | ATT&CK | Fires on |
|----------|----------|--------|----------|
| `macos_keychain_dump` | HIGH | T1555.001 | `security dump-keychain`, `find-generic-password`, `find-internet-password` or `export` |
| `macos_ssh_private_key_read` | MEDIUM | T1552.004 | read of `~/.ssh/id_*` by anything but the OpenSSH tools |
| `macos_browser_credential_read` | HIGH | T1555.003 | read of Chrome, Brave or Firefox password and cookie stores by anything but the browser |
| `macos_tcc_database_access` | HIGH | T1548.006 | open of a `TCC.db`, failed opens included, by anything but tccd |
| `macos_launch_agent_persistence` | HIGH | T1543.001 | plist created, written or renamed into a LaunchAgents folder |
| `macos_launch_daemon_persistence` | HIGH | T1543.004 | plist written into `/Library/LaunchDaemons` |
| `macos_launchd_plist_written_then_loaded` | HIGH | T1543.001, T1569.001 | a LaunchAgents or LaunchDaemons plist write and a `launchctl load`, `bootstrap`, `enable` or `kickstart` in the same login session |
| `macos_cron_persistence` | MEDIUM | T1053.003 | crontab written |
| `macos_shell_profile_persistence` | LOW | T1546.004 | `.zshrc`, `.bash_profile` and similar written by something that is not an editor |
| `macos_exec_from_writable_dir` | MEDIUM | T1204.002 | exec from `/tmp`, `/var/tmp`, `/private/var/folders` or `/Users/Shared` |
| `macos_writable_exec_then_egress` | HIGH | T1105, T1071 | exec from a writable folder and an outbound connect by that same binary |
| `macos_sudo_root_shell` | MEDIUM | T1548.003 | `sudo -s`, `sudo -i` or `sudo su` followed by setuid to root |
| `macos_system_log_deletion` | HIGH | T1070.002 | delete under `/var/log`, `/var/audit` or the unified log store |
| `macos_shell_history_deletion` | MEDIUM | T1070.003 | `.zsh_history` or `.bash_history` deleted |
| `macos_quarantine_attribute_removed` | MEDIUM | T1553.001 | `xattr -d com.apple.quarantine` or `xattr -c` |
| `macos_gatekeeper_disabled` | HIGH | T1562.001 | `spctl --master-disable`, `--global-disable` or `--disable` |
| `macos_audit_disabled` | HIGH | T1562.001 | `audit -t` |
| `macos_osascript_shell` | MEDIUM | T1059.002 | `osascript` running `do shell script` |
| `macos_task_port_access` | HIGH | T1055 | successful `task_for_pid` or `ptrace` by a program outside the system folders and developer tools |

A playbook is a list of slots. Each slot names a fact type (`Exec`, `ReadPath`, `CreatePath`, `DeletePath`, `PersistArtifact`, `PrivilegeBoundary`, `OutboundConnect`, `Injection` and a few others) and optional filters: `path_regex`, `cmdline_regex`, `actor_exe_regex` and `actor_exe_not_regex`. A detection fires when every required slot is filled inside the playbook's time window. Playbooks are checked when they load: an unknown fact type or a regex that does not compile stops edr-locald instead of silently disabling a detection. Set `EDR_PLAYBOOK_DIR` or pass `--playbooks <dir>` to load a folder of YAML files instead of the built in set.

How facts are grouped: every fact is keyed to the audit session of the process behind it, the `auid` (audit user id) and `asid` (audit session id) from the BSM subject token. The audit user id is set at login and survives sudo and su, and everything started from one login shares the session id. That is how the two slot launchd playbook joins a `cp` writing the plist and a `launchctl load` spawned from the shell. Time windows, slot lifetimes and cooldowns all run on event time, so replaying an old trail gives the same result as live capture.

## Limits

- Live capture loses records under a burst. When the audit pipe's queue is full (1,024 records, the maximum the pipe reports), the kernel drops records: 10,709 in the passing CI run, about 7 percent. A dropped record is a missed event, so a detection can miss. The smoke test prints the count.
- edr-locald took about 4 minutes on the 32,098 events of that CI run (a debug build). It compiled each playbook regex again for every event and stored each detection in its own synced SQLite transaction. Both are fixed: patterns are compiled once and the database uses write-ahead logging. On a 30,800 event test segment it now takes 1.3 s in a release build (4.6 s before) and 9.6 s in a debug build (31 s before), with the same 1,760 detections.
- BSM records the path a program passed. A relative path is joined to the process's working folder, which the reader learns from chdir, fchdir, fork and posix_spawn records. A process that changed folder before capture started keeps the relative path, marked `path_relative`.
- The test trails are written with libbsm in the token order XNU uses. They were not recorded from a live kernel.
- libbsm on macOS 27.2 writes the two bytes of an IPv6 port swapped (`au_to_sock_inet128` converts a port that is already in network order a second time), so `praudit` shows port 8443 as 64288. The parser swaps them back. XNU's token code also comes from OpenBSM, but this has not been checked on a live record.
- BSM does not audit `setxattr` or `removexattr`, so stripping the quarantine attribute is only visible as the `xattr` command. Exec environment variables, and so `DYLD_INSERT_LIBRARIES`, are only recorded when the audit policy includes `arge`.

## Layout

```text
crates/
  agent-macos/   capture agent: auditpipe setup, BSM record and token parser, event normalizer
  locald/        edr-locald: fact extractor, playbook loader, hypothesis controller, saved state
  server/        edr-server: read only HTTP API and detections page
  edrctl/        stack control
  core/          shared event and evidence pointer types
playbooks/macos/ YAML playbooks
scripts/         replay_demo.sh, live_smoke.sh
tests/fixtures/  binary BSM trails
tools/           fixture generator
ui/              detections page served by edr-server
```

## License

MIT. See [LICENSE](LICENSE).
