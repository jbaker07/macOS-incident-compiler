//! End to end: recorded BSM trails -> capture replay -> edr-locald -> workbench.db.
//!
//! Uses the same binary audit trails as the agent-macos tests, built with
//! Apple's libbsm by tools/bsm-fixtures/make_bsm_fixtures.c.

use rusqlite::Connection;
use std::path::PathBuf;
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bsm").join(name)
}

#[test]
fn attack_trail_fires_every_expected_playbook_and_benign_trail_fires_none() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let stats = agent_macos::capture_macos_rotating::run_replay(
        &[fixture("attack_chain.bsm"), fixture("benign_session.bsm")],
        root,
        "test-mac",
    )
    .unwrap();
    assert_eq!(stats.decode_errors, 0);

    let output = Command::new(env!("CARGO_BIN_EXE_edr-locald"))
        .arg("--telemetry-root")
        .arg(root)
        .arg("--once")
        .env_remove("EDR_PLAYBOOK_DIR")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let log = String::from_utf8_lossy(&output.stderr);
    assert!(log.contains("seg_000001") && log.contains("8 events, 0 detections"), "{}", log);

    let db = Connection::open(root.join("workbench.db")).unwrap();
    let mut stmt = db.prepare("SELECT signal_type FROM signals ORDER BY signal_type").unwrap();
    let fired: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    let expected = vec![
        "macos_audit_disabled",
        "macos_browser_credential_read",
        "macos_exec_from_writable_dir",
        "macos_gatekeeper_disabled",
        "macos_keychain_dump",
        "macos_launch_agent_persistence",
        "macos_launchd_plist_written_then_loaded",
        "macos_osascript_shell",
        "macos_quarantine_attribute_removed",
        "macos_shell_history_deletion",
        "macos_ssh_private_key_read",
        "macos_sudo_root_shell",
        "macos_system_log_deletion",
        "macos_task_port_access",
        "macos_tcc_database_access",
        "macos_writable_exec_then_egress",
    ];
    assert_eq!(fired, expected);

    // Every explanation points at real lines whose SHA-256 still matches.
    let mut stmt = db.prepare("SELECT explanation_json FROM signal_explanations").unwrap();
    let explanations: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(explanations.len(), expected.len());
    for text in explanations {
        let exp: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(exp["evidence_verified"], true, "{}", exp["playbook_id"]);
        for slot in exp["slots"].as_array().unwrap() {
            if slot["required"] == true {
                assert_eq!(slot["filled"], true);
                assert!(!slot["evidence"].as_array().unwrap().is_empty());
            }
        }
    }

    // The two slot playbook joined a cp write and a posix_spawn of launchctl
    // through the shared audit session.
    let text: String = db
        .query_row(
            "SELECT e.explanation_json FROM signal_explanations e JOIN signals s ON s.signal_id = e.signal_id
             WHERE s.signal_type = 'macos_launchd_plist_written_then_loaded'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let exp: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(exp["scope"], "session:test-mac:auid=501:asid=100005");
    assert_eq!(exp["slots"][0]["evidence"][0]["event"]["fields"]["exe"], "/bin/cp");
    assert_eq!(exp["slots"][1]["evidence"][0]["event"]["fields"]["exe"], "/bin/launchctl");

    // Running again finds nothing new: the checkpoint remembers both segments.
    let again = Command::new(env!("CARGO_BIN_EXE_edr-locald"))
        .arg("--telemetry-root")
        .arg(root)
        .arg("--once")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&again.stderr).contains("0 events, 0 detections this run"));
}

#[test]
fn tampered_segment_is_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    agent_macos::capture_macos_rotating::run_replay(&[fixture("attack_chain.bsm")], root, "test-mac").unwrap();
    let segment = std::fs::read_dir(root.join("segments"))
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .path();
    let text = std::fs::read_to_string(&segment).unwrap();
    std::fs::write(&segment, text.replace("/usr/bin/security", "/usr/bin/securitx")).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_edr-locald"))
        .arg("--telemetry-root")
        .arg(root)
        .arg("--once")
        .output()
        .unwrap();
    let log = String::from_utf8_lossy(&output.stderr);
    assert!(log.contains("hash mismatch"), "{}", log);
    let db = Connection::open(root.join("workbench.db")).unwrap();
    let count: i64 = db.query_row("SELECT COUNT(*) FROM signals", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 0);
}

/// Stop edr-locald after the LaunchAgent plist write and start it again
/// before the launchctl load arrives. The two slot playbook must still fire,
/// which only works if the half filled hypothesis survived the restart.
#[test]
fn restart_between_the_two_steps_of_a_playbook_keeps_the_detection() {
    use agent_macos::sensors::bsm::RecordSplitter;
    use std::time::{Duration, Instant};

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("telemetry");

    // Split the attack trail after record 14 (cp writes the plist). Record 15
    // is the posix_spawn of launchctl load.
    let data = std::fs::read(fixture("attack_chain.bsm")).unwrap();
    let mut splitter = RecordSplitter::new();
    splitter.feed(&data);
    let mut records = Vec::new();
    while let Some(record) = splitter.next_record() {
        records.push(record);
    }
    assert_eq!(records.len(), 28);
    let first_half: Vec<u8> = records[..15].concat();
    let second_half: Vec<u8> = records[15..].concat();
    let first_path = dir.path().join("first.bsm");
    let second_path = dir.path().join("second.bsm");
    std::fs::write(&first_path, first_half).unwrap();
    std::fs::write(&second_path, second_half).unwrap();

    agent_macos::capture_macos_rotating::run_replay(&[first_path], &root, "test-mac").unwrap();

    // Run edr-locald in watch mode, wait until it has finished segment 0,
    // then kill it without warning.
    let mut child = Command::new(env!("CARGO_BIN_EXE_edr-locald"))
        .arg("--telemetry-root")
        .arg(&root)
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let db_path = root.join("workbench.db");
    let started = Instant::now();
    loop {
        let done = Connection::open(&db_path)
            .ok()
            .and_then(|db| {
                db.query_row(
                    "SELECT value FROM locald_checkpoint WHERE key = 'segments_done'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .ok()
            })
            .unwrap_or_default();
        if done.split(',').any(|s| s == "0") {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(30), "edr-locald never finished segment 0");
        std::thread::sleep(Duration::from_millis(100));
    }
    child.kill().unwrap();
    child.wait().unwrap();

    let fired = |db: &Connection| -> Vec<String> {
        let mut stmt = db.prepare("SELECT signal_type FROM signals ORDER BY signal_type").unwrap();
        let rows: Vec<String> = stmt.query_map([], |row| row.get(0)).unwrap().map(|r| r.unwrap()).collect();
        rows
    };
    let db = Connection::open(&db_path).unwrap();
    let before = fired(&db);
    assert!(before.contains(&"macos_launch_agent_persistence".to_string()));
    assert!(!before.contains(&"macos_launchd_plist_written_then_loaded".to_string()));
    drop(db);

    // The second half arrives while edr-locald is down, then it starts again.
    agent_macos::capture_macos_rotating::run_replay(&[second_path], &root, "test-mac").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_edr-locald"))
        .arg("--telemetry-root")
        .arg(&root)
        .arg("--once")
        .output()
        .unwrap();
    let log = String::from_utf8_lossy(&output.stderr);
    assert!(log.contains("restored"), "{}", log);

    let db = Connection::open(&db_path).unwrap();
    let after = fired(&db);
    assert!(after.contains(&"macos_launchd_plist_written_then_loaded".to_string()), "{}", log);
    // Nothing fired twice.
    let mut unique = after.clone();
    unique.dedup();
    assert_eq!(unique.len(), after.len());

    // The first slot's evidence still points at segment 0 and still verifies.
    let text: String = db
        .query_row(
            "SELECT e.explanation_json FROM signal_explanations e JOIN signals s ON s.signal_id = e.signal_id
             WHERE s.signal_type = 'macos_launchd_plist_written_then_loaded'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let exp: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(exp["evidence_verified"], true);
    assert_eq!(exp["slots"][0]["evidence"][0]["segment_seq"], 0);
    assert_eq!(exp["slots"][0]["evidence"][0]["record_index"], 14);
    assert_eq!(exp["slots"][1]["evidence"][0]["segment_seq"], 1);
}
