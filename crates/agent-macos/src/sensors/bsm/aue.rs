//! Audit event numbers (AUE_*) used by the capture agent.
//!
//! Every value here is copied from the macOS SDK header
//! `<bsm/audit_kevents.h>` (find it with `xcrun --show-sdk-path`). The same
//! numbers appear in `/etc/security/audit_event` on every Mac. The test at the
//! bottom of this file reads both sources and fails if any constant drifts.
//!
//! An earlier version of this crate mixed up system call numbers and audit
//! event numbers (execve as 59, which is its system call number, open as 3 to
//! 5, connect as 43) and would not have classified a real audit stream
//! correctly. Do not add a number here without checking the header.

// Process execution
pub const AUE_EXEC: u16 = 7;
pub const AUE_EXECVE: u16 = 23;
pub const AUE_MAC_EXECVE: u16 = 43131;
pub const AUE_POSIX_SPAWN: u16 = 43190;
pub const AUE_FORK: u16 = 2;
pub const AUE_VFORK: u16 = 25;
pub const AUE_EXIT: u16 = 1;

// Process control
pub const AUE_KILL: u16 = 15;
pub const AUE_PTRACE: u16 = 43002;
pub const AUE_TASKFORPID: u16 = 43048;
pub const AUE_PIDFORTASK: u16 = 43049;
pub const AUE_TASKNAMEFORPID: u16 = 43161;

// open(2). The kernel records open with AUE_OPEN_RWTC and rewrites it to the
// variant that matches the flags when the record is committed.
pub const AUE_OPEN: u16 = 3;
pub const AUE_CREAT: u16 = 4;
pub const AUE_OPEN_R: u16 = 72;
pub const AUE_OPEN_RC: u16 = 73;
pub const AUE_OPEN_RT: u16 = 74;
pub const AUE_OPEN_RTC: u16 = 75;
pub const AUE_OPEN_W: u16 = 76;
pub const AUE_OPEN_WC: u16 = 77;
pub const AUE_OPEN_WT: u16 = 78;
pub const AUE_OPEN_WTC: u16 = 79;
pub const AUE_OPEN_RW: u16 = 80;
pub const AUE_OPEN_RWC: u16 = 81;
pub const AUE_OPEN_RWT: u16 = 82;
pub const AUE_OPEN_RWTC: u16 = 83;

// openat(2), same twelve variants starting at 270
pub const AUE_OPENAT: u16 = 43184;
pub const AUE_OPENAT_R: u16 = 270;
pub const AUE_OPENAT_RWTC: u16 = 281;

// open_extended(2), same twelve variants starting at 43170
pub const AUE_OPEN_EXTENDED: u16 = 43169;
pub const AUE_OPEN_EXTENDED_R: u16 = 43170;
pub const AUE_OPEN_EXTENDED_RWTC: u16 = 43181;

// openbyid_np(2) has six variants without create
pub const AUE_OPENBYID_R: u16 = 43204;
pub const AUE_OPENBYID_RT: u16 = 43205;
pub const AUE_OPENBYID_W: u16 = 43206;
pub const AUE_OPENBYID_WT: u16 = 43207;
pub const AUE_OPENBYID_RW: u16 = 43208;
pub const AUE_OPENBYID_RWT: u16 = 43209;

// Delete, rename, links
pub const AUE_UNLINK: u16 = 6;
pub const AUE_CHDIR: u16 = 8;
pub const AUE_FCHDIR: u16 = 68;
pub const AUE_UNLINKAT: u16 = 286;
pub const AUE_RMDIR: u16 = 48;
pub const AUE_RENAME: u16 = 42;
pub const AUE_RENAMEAT: u16 = 282;
pub const AUE_LINK: u16 = 5;
pub const AUE_LINKAT: u16 = 43147;
pub const AUE_SYMLINK: u16 = 21;
pub const AUE_SYMLINKAT: u16 = 43152;
pub const AUE_CLONEFILEAT: u16 = 43210;
pub const AUE_FCLONEFILEAT: u16 = 43211;
pub const AUE_EXCHANGEDATA: u16 = 43028;

// Attribute changes
pub const AUE_CHMOD: u16 = 10;
pub const AUE_FCHMOD: u16 = 39;
pub const AUE_LCHMOD: u16 = 43044;
pub const AUE_FCHMODAT: u16 = 43146;
pub const AUE_CHMOD_EXTENDED: u16 = 43163;
pub const AUE_FCHMOD_EXTENDED: u16 = 43164;
pub const AUE_CHOWN: u16 = 11;
pub const AUE_FCHOWN: u16 = 38;
pub const AUE_LCHOWN: u16 = 237;
pub const AUE_FCHOWNAT: u16 = 284;
pub const AUE_TRUNCATE: u16 = 43;
pub const AUE_FTRUNCATE: u16 = 44;

// Credentials
pub const AUE_SETUID: u16 = 200;
pub const AUE_SETGID: u16 = 205;
pub const AUE_SETEUID: u16 = 215;
pub const AUE_SETEGID: u16 = 214;
pub const AUE_SETREUID: u16 = 40;
pub const AUE_SETREGID: u16 = 41;
pub const AUE_SETRESUID: u16 = 43057;
pub const AUE_SETRESGID: u16 = 43059;
pub const AUE_SETGROUPS: u16 = 26;
pub const AUE_SETAUID: u16 = 131;
pub const AUE_SETLOGIN: u16 = 43007;

// Network
pub const AUE_SOCKET: u16 = 183;
pub const AUE_CONNECT: u16 = 32;
pub const AUE_ACCEPT: u16 = 33;
pub const AUE_BIND: u16 = 34;
pub const AUE_LISTEN: u16 = 43140;

// File systems
pub const AUE_MOUNT: u16 = 62;
pub const AUE_UNMOUNT: u16 = 56;
pub const AUE_FMOUNT: u16 = 43213;

// Changes to the audit system itself
pub const AUE_AUDITON: u16 = 138;
pub const AUE_AUDITCTL: u16 = 43042;
pub const AUE_AUDIT: u16 = 211;

/// Every constant above with its header name. Used for display names and
/// checked against the SDK header by the tests.
pub const KNOWN_EVENTS: &[(&str, u16)] = &[
    ("AUE_EXEC", AUE_EXEC),
    ("AUE_EXECVE", AUE_EXECVE),
    ("AUE_MAC_EXECVE", AUE_MAC_EXECVE),
    ("AUE_POSIX_SPAWN", AUE_POSIX_SPAWN),
    ("AUE_FORK", AUE_FORK),
    ("AUE_VFORK", AUE_VFORK),
    ("AUE_EXIT", AUE_EXIT),
    ("AUE_CHDIR", AUE_CHDIR),
    ("AUE_FCHDIR", AUE_FCHDIR),
    ("AUE_KILL", AUE_KILL),
    ("AUE_PTRACE", AUE_PTRACE),
    ("AUE_TASKFORPID", AUE_TASKFORPID),
    ("AUE_PIDFORTASK", AUE_PIDFORTASK),
    ("AUE_TASKNAMEFORPID", AUE_TASKNAMEFORPID),
    ("AUE_OPEN", AUE_OPEN),
    ("AUE_CREAT", AUE_CREAT),
    ("AUE_OPEN_R", AUE_OPEN_R),
    ("AUE_OPEN_RC", AUE_OPEN_RC),
    ("AUE_OPEN_RT", AUE_OPEN_RT),
    ("AUE_OPEN_RTC", AUE_OPEN_RTC),
    ("AUE_OPEN_W", AUE_OPEN_W),
    ("AUE_OPEN_WC", AUE_OPEN_WC),
    ("AUE_OPEN_WT", AUE_OPEN_WT),
    ("AUE_OPEN_WTC", AUE_OPEN_WTC),
    ("AUE_OPEN_RW", AUE_OPEN_RW),
    ("AUE_OPEN_RWC", AUE_OPEN_RWC),
    ("AUE_OPEN_RWT", AUE_OPEN_RWT),
    ("AUE_OPEN_RWTC", AUE_OPEN_RWTC),
    ("AUE_OPENAT", AUE_OPENAT),
    ("AUE_OPENAT_R", AUE_OPENAT_R),
    ("AUE_OPENAT_RWTC", AUE_OPENAT_RWTC),
    ("AUE_OPEN_EXTENDED", AUE_OPEN_EXTENDED),
    ("AUE_OPEN_EXTENDED_R", AUE_OPEN_EXTENDED_R),
    ("AUE_OPEN_EXTENDED_RWTC", AUE_OPEN_EXTENDED_RWTC),
    ("AUE_OPENBYID_R", AUE_OPENBYID_R),
    ("AUE_OPENBYID_RT", AUE_OPENBYID_RT),
    ("AUE_OPENBYID_W", AUE_OPENBYID_W),
    ("AUE_OPENBYID_WT", AUE_OPENBYID_WT),
    ("AUE_OPENBYID_RW", AUE_OPENBYID_RW),
    ("AUE_OPENBYID_RWT", AUE_OPENBYID_RWT),
    ("AUE_UNLINK", AUE_UNLINK),
    ("AUE_UNLINKAT", AUE_UNLINKAT),
    ("AUE_RMDIR", AUE_RMDIR),
    ("AUE_RENAME", AUE_RENAME),
    ("AUE_RENAMEAT", AUE_RENAMEAT),
    ("AUE_LINK", AUE_LINK),
    ("AUE_LINKAT", AUE_LINKAT),
    ("AUE_SYMLINK", AUE_SYMLINK),
    ("AUE_SYMLINKAT", AUE_SYMLINKAT),
    ("AUE_CLONEFILEAT", AUE_CLONEFILEAT),
    ("AUE_FCLONEFILEAT", AUE_FCLONEFILEAT),
    ("AUE_EXCHANGEDATA", AUE_EXCHANGEDATA),
    ("AUE_CHMOD", AUE_CHMOD),
    ("AUE_FCHMOD", AUE_FCHMOD),
    ("AUE_LCHMOD", AUE_LCHMOD),
    ("AUE_FCHMODAT", AUE_FCHMODAT),
    ("AUE_CHMOD_EXTENDED", AUE_CHMOD_EXTENDED),
    ("AUE_FCHMOD_EXTENDED", AUE_FCHMOD_EXTENDED),
    ("AUE_CHOWN", AUE_CHOWN),
    ("AUE_FCHOWN", AUE_FCHOWN),
    ("AUE_LCHOWN", AUE_LCHOWN),
    ("AUE_FCHOWNAT", AUE_FCHOWNAT),
    ("AUE_TRUNCATE", AUE_TRUNCATE),
    ("AUE_FTRUNCATE", AUE_FTRUNCATE),
    ("AUE_SETUID", AUE_SETUID),
    ("AUE_SETGID", AUE_SETGID),
    ("AUE_SETEUID", AUE_SETEUID),
    ("AUE_SETEGID", AUE_SETEGID),
    ("AUE_SETREUID", AUE_SETREUID),
    ("AUE_SETREGID", AUE_SETREGID),
    ("AUE_SETRESUID", AUE_SETRESUID),
    ("AUE_SETRESGID", AUE_SETRESGID),
    ("AUE_SETGROUPS", AUE_SETGROUPS),
    ("AUE_SETAUID", AUE_SETAUID),
    ("AUE_SETLOGIN", AUE_SETLOGIN),
    ("AUE_SOCKET", AUE_SOCKET),
    ("AUE_CONNECT", AUE_CONNECT),
    ("AUE_ACCEPT", AUE_ACCEPT),
    ("AUE_BIND", AUE_BIND),
    ("AUE_LISTEN", AUE_LISTEN),
    ("AUE_MOUNT", AUE_MOUNT),
    ("AUE_UNMOUNT", AUE_UNMOUNT),
    ("AUE_FMOUNT", AUE_FMOUNT),
    ("AUE_AUDITON", AUE_AUDITON),
    ("AUE_AUDITCTL", AUE_AUDITCTL),
    ("AUE_AUDIT", AUE_AUDIT),
];

/// Header name for an event number, when it is one this crate knows.
pub fn event_name(code: u16) -> Option<&'static str> {
    if let Some(variant) = open_variant(code) {
        return Some(variant.name);
    }
    for (name, value) in KNOWN_EVENTS {
        if *value == code {
            return Some(name);
        }
    }
    None
}

/// What an open style event says about the access, decoded from its variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenVariant {
    pub name: &'static str,
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub truncate: bool,
}

/// The twelve open variants share one layout in all three ranges:
/// R, RC, RT, RTC, W, WC, WT, WTC, RW, RWC, RWT, RWTC.
const OPEN_SUFFIXES: [(&str, bool, bool, bool, bool); 12] = [
    ("R", true, false, false, false),
    ("RC", true, false, true, false),
    ("RT", true, false, false, true),
    ("RTC", true, false, true, true),
    ("W", false, true, false, false),
    ("WC", false, true, true, false),
    ("WT", false, true, false, true),
    ("WTC", false, true, true, true),
    ("RW", true, true, false, false),
    ("RWC", true, true, true, false),
    ("RWT", true, true, false, true),
    ("RWTC", true, true, true, true),
];

const OPEN_NAMES: [&str; 12] = [
    "AUE_OPEN_R", "AUE_OPEN_RC", "AUE_OPEN_RT", "AUE_OPEN_RTC", "AUE_OPEN_W", "AUE_OPEN_WC",
    "AUE_OPEN_WT", "AUE_OPEN_WTC", "AUE_OPEN_RW", "AUE_OPEN_RWC", "AUE_OPEN_RWT", "AUE_OPEN_RWTC",
];
const OPENAT_NAMES: [&str; 12] = [
    "AUE_OPENAT_R", "AUE_OPENAT_RC", "AUE_OPENAT_RT", "AUE_OPENAT_RTC", "AUE_OPENAT_W",
    "AUE_OPENAT_WC", "AUE_OPENAT_WT", "AUE_OPENAT_WTC", "AUE_OPENAT_RW", "AUE_OPENAT_RWC",
    "AUE_OPENAT_RWT", "AUE_OPENAT_RWTC",
];
const OPEN_EXTENDED_NAMES: [&str; 12] = [
    "AUE_OPEN_EXTENDED_R", "AUE_OPEN_EXTENDED_RC", "AUE_OPEN_EXTENDED_RT",
    "AUE_OPEN_EXTENDED_RTC", "AUE_OPEN_EXTENDED_W", "AUE_OPEN_EXTENDED_WC",
    "AUE_OPEN_EXTENDED_WT", "AUE_OPEN_EXTENDED_WTC", "AUE_OPEN_EXTENDED_RW",
    "AUE_OPEN_EXTENDED_RWC", "AUE_OPEN_EXTENDED_RWT", "AUE_OPEN_EXTENDED_RWTC",
];

/// Decode an open style event number. Returns None for anything that is not
/// one of the open variants.
pub fn open_variant(code: u16) -> Option<OpenVariant> {
    let ranges: [(u16, &[&str; 12]); 3] = [
        (AUE_OPEN_R, &OPEN_NAMES),
        (AUE_OPENAT_R, &OPENAT_NAMES),
        (AUE_OPEN_EXTENDED_R, &OPEN_EXTENDED_NAMES),
    ];
    for (base, names) in ranges.iter() {
        if code >= *base && code < *base + 12 {
            let index = (code - *base) as usize;
            let (_, read, write, create, truncate) = OPEN_SUFFIXES[index];
            return Some(OpenVariant {
                name: names[index],
                read,
                write,
                create,
                truncate,
            });
        }
    }
    let by_id: [(u16, &str, bool, bool, bool); 6] = [
        (AUE_OPENBYID_R, "AUE_OPENBYID_R", true, false, false),
        (AUE_OPENBYID_RT, "AUE_OPENBYID_RT", true, false, true),
        (AUE_OPENBYID_W, "AUE_OPENBYID_W", false, true, false),
        (AUE_OPENBYID_WT, "AUE_OPENBYID_WT", false, true, true),
        (AUE_OPENBYID_RW, "AUE_OPENBYID_RW", true, true, false),
        (AUE_OPENBYID_RWT, "AUE_OPENBYID_RWT", true, true, true),
    ];
    for (value, name, read, write, truncate) in by_id.iter() {
        if code == *value {
            return Some(OpenVariant {
                name,
                read: *read,
                write: *write,
                create: false,
                truncate: *truncate,
            });
        }
    }
    // The generic codes only show up if the kernel could not pick a variant.
    if code == AUE_OPEN || code == AUE_OPENAT || code == AUE_OPEN_EXTENDED {
        return Some(OpenVariant {
            name: if code == AUE_OPEN {
                "AUE_OPEN"
            } else if code == AUE_OPENAT {
                "AUE_OPENAT"
            } else {
                "AUE_OPEN_EXTENDED"
            },
            read: true,
            write: false,
            create: false,
            truncate: false,
        });
    }
    if code == AUE_CREAT {
        return Some(OpenVariant {
            name: "AUE_CREAT",
            read: false,
            write: true,
            create: true,
            truncate: true,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Read `#define AUE_NAME <number>` lines from audit_kevents.h.
    fn header_values() -> Option<HashMap<String, u16>> {
        let output = std::process::Command::new("xcrun")
            .arg("--show-sdk-path")
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let sdk = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let header = std::fs::read_to_string(format!("{}/usr/include/bsm/audit_kevents.h", sdk)).ok()?;
        let mut values = HashMap::new();
        for line in header.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[0] == "#define" && parts[1].starts_with("AUE_") {
                if let Ok(value) = parts[2].parse::<u16>() {
                    values.insert(parts[1].to_string(), value);
                }
            }
        }
        Some(values)
    }

    /// Read `number:AUE_NAME:description:classes` lines from /etc/security/audit_event.
    fn system_event_file() -> Option<HashMap<String, u16>> {
        let text = std::fs::read_to_string("/etc/security/audit_event").ok()?;
        let mut values = HashMap::new();
        for line in text.lines() {
            if line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 2 {
                if let Ok(value) = parts[0].parse::<u16>() {
                    values.insert(parts[1].to_string(), value);
                }
            }
        }
        Some(values)
    }

    fn all_names_and_values() -> Vec<(String, u16)> {
        let mut all: Vec<(String, u16)> = KNOWN_EVENTS
            .iter()
            .map(|(name, value)| (name.to_string(), *value))
            .collect();
        for code in 0..=u16::MAX {
            if let Some(variant) = open_variant(code) {
                all.push((variant.name.to_string(), code));
            }
        }
        all
    }

    #[test]
    fn constants_match_sdk_header() {
        let header = match header_values() {
            Some(values) => values,
            None => {
                eprintln!("skipping: macOS SDK header not found (xcrun missing)");
                return;
            }
        };
        let mut checked = 0;
        for (name, value) in all_names_and_values() {
            let expected = header
                .get(&name)
                .unwrap_or_else(|| panic!("{} is not defined in audit_kevents.h", name));
            assert_eq!(*expected, value, "{} is {} in the header, {} here", name, expected, value);
            checked += 1;
        }
        assert!(checked > 100, "checked only {} names", checked);
    }

    #[test]
    fn constants_match_system_audit_event_file() {
        let system = match system_event_file() {
            Some(values) => values,
            None => {
                eprintln!("skipping: /etc/security/audit_event not present");
                return;
            }
        };
        for (name, value) in all_names_and_values() {
            if let Some(expected) = system.get(&name) {
                assert_eq!(*expected, value, "{} differs from /etc/security/audit_event", name);
            }
        }
    }

    #[test]
    fn values_the_old_code_got_wrong() {
        assert_eq!(AUE_EXECVE, 23);
        assert_eq!(AUE_POSIX_SPAWN, 43190);
        assert_eq!(AUE_OPEN_R, 72);
        assert_eq!(AUE_OPEN_W, 76);
        assert_eq!(AUE_OPEN_RW, 80);
        assert_eq!(AUE_CONNECT, 32);
        assert_eq!(AUE_ACCEPT, 33);
        assert_eq!(AUE_BIND, 34);
        assert_eq!(AUE_LISTEN, 43140);
        assert_eq!(AUE_SETUID, 200);
        assert_eq!(AUE_SETGID, 205);
        assert_eq!(AUE_MOUNT, 62);
    }

    #[test]
    fn open_variants_decode_flags() {
        let read_only = open_variant(AUE_OPEN_R).unwrap();
        assert!(read_only.read && !read_only.write && !read_only.create);
        let write_create = open_variant(AUE_OPEN_WTC).unwrap();
        assert!(write_create.write && write_create.create && write_create.truncate);
        let openat_rwc = open_variant(AUE_OPENAT_R + 9).unwrap();
        assert_eq!(openat_rwc.name, "AUE_OPENAT_RWC");
        assert!(openat_rwc.read && openat_rwc.write && openat_rwc.create);
        assert!(open_variant(AUE_OPEN_RWTC + 1).is_none());
        assert_eq!(event_name(AUE_POSIX_SPAWN), Some("AUE_POSIX_SPAWN"));
    }
}
