//! Opening and configuring /dev/auditpipe.
//!
//! By default an audit pipe only shows records that the system audit trail
//! (auditd) already selected. This module switches the pipe to local
//! preselection, so the agent chooses its own audit classes, and raises the
//! queue limit so bursts are less likely to drop records.
//!
//! The ioctl request numbers below are the `_IOR` and `_IOW` values from
//! `<security/audit/audit_ioctl.h>` in the macOS SDK. The test checks the
//! encoding, and the values were also printed from the header with a small C
//! program.

use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;

/// Audit classes from /etc/security/audit_class.
pub const AUDIT_CLASSES: &[(&str, u32)] = &[
    ("fr", 0x0000_0001),
    ("fw", 0x0000_0002),
    ("fa", 0x0000_0004),
    ("fm", 0x0000_0008),
    ("fc", 0x0000_0010),
    ("fd", 0x0000_0020),
    ("cl", 0x0000_0040),
    ("pc", 0x0000_0080),
    ("nt", 0x0000_0100),
    ("ip", 0x0000_0200),
    ("na", 0x0000_0400),
    ("ad", 0x0000_0800),
    ("lo", 0x0000_1000),
    ("aa", 0x0000_2000),
    ("ap", 0x0000_4000),
    ("io", 0x2000_0000),
    ("ex", 0x4000_0000),
    ("ot", 0x8000_0000),
];

/// Classes the agent asks for unless told otherwise: exec, process, file
/// read, write, create, delete and attribute change, network, administrative.
pub const DEFAULT_CLASSES: &str = "ex,pc,fr,fw,fc,fd,fm,nt,ad";

pub const AUDITPIPE_PRESELECT_MODE_LOCAL: i32 = 2;

// _IOC(direction, 'A', number, size): direction in the top bits, size in
// bits 16 to 28, group letter in bits 8 to 15, number in the low byte.
const IOC_VOID: u64 = 0x2000_0000;
const IOC_OUT: u64 = 0x4000_0000;
const IOC_IN: u64 = 0x8000_0000;
const fn ioc(direction: u64, number: u64, size: u64) -> u64 {
    direction | ((size & 0x1fff) << 16) | ((b'A' as u64) << 8) | number
}

pub const AUDITPIPE_SET_QLIMIT: u64 = ioc(IOC_IN, 3, 4);
pub const AUDITPIPE_GET_QLIMIT_MAX: u64 = ioc(IOC_OUT, 5, 4);
pub const AUDITPIPE_SET_PRESELECT_FLAGS: u64 = ioc(IOC_IN, 7, 8);
pub const AUDITPIPE_SET_PRESELECT_NAFLAGS: u64 = ioc(IOC_IN, 9, 8);
pub const AUDITPIPE_SET_PRESELECT_MODE: u64 = ioc(IOC_IN, 15, 4);
pub const AUDITPIPE_FLUSH: u64 = ioc(IOC_VOID, 16, 0);
pub const AUDITPIPE_GET_MAXAUDITDATA: u64 = ioc(IOC_OUT, 17, 4);
pub const AUDITPIPE_GET_DROPS: u64 = ioc(IOC_OUT, 102, 8);

/// au_mask_t: one class mask for successful events, one for failed events.
#[repr(C)]
struct AuMask {
    am_success: u32,
    am_failure: u32,
}

/// Turn "ex,pc,nt" into a class bit mask.
pub fn parse_classes(list: &str) -> Result<u32, String> {
    let mut mask = 0u32;
    for name in list.split(',') {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let mut found = false;
        for (class_name, bit) in AUDIT_CLASSES {
            if *class_name == name {
                mask |= bit;
                found = true;
            }
        }
        if !found {
            return Err(format!("unknown audit class '{}'", name));
        }
    }
    if mask == 0 {
        return Err("no audit classes given".to_string());
    }
    Ok(mask)
}

#[cfg(target_os = "macos")]
unsafe fn ioctl_ptr<T>(file: &File, request: u64, value: *mut T) -> io::Result<()> {
    let rc = libc::ioctl(file.as_raw_fd(), request as libc::c_ulong, value);
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// An open, configured audit pipe.
pub struct AuditPipe {
    pub file: File,
    pub max_record_bytes: usize,
    pub queue_limit: u32,
}

#[cfg(target_os = "macos")]
impl AuditPipe {
    /// Open /dev/auditpipe and select `class_mask` for both attributable and
    /// non attributable events, success and failure.
    pub fn open(class_mask: u32) -> io::Result<AuditPipe> {
        let file = File::open("/dev/auditpipe")?;
        unsafe {
            let mut mode: i32 = AUDITPIPE_PRESELECT_MODE_LOCAL;
            ioctl_ptr(&file, AUDITPIPE_SET_PRESELECT_MODE, &mut mode)?;

            let mut mask = AuMask {
                am_success: class_mask,
                am_failure: class_mask,
            };
            ioctl_ptr(&file, AUDITPIPE_SET_PRESELECT_FLAGS, &mut mask)?;
            ioctl_ptr(&file, AUDITPIPE_SET_PRESELECT_NAFLAGS, &mut mask)?;

            let mut queue_limit: u32 = 0;
            ioctl_ptr(&file, AUDITPIPE_GET_QLIMIT_MAX, &mut queue_limit)?;
            ioctl_ptr(&file, AUDITPIPE_SET_QLIMIT, &mut queue_limit)?;

            let mut max_data: u32 = 0;
            if ioctl_ptr(&file, AUDITPIPE_GET_MAXAUDITDATA, &mut max_data).is_err() {
                max_data = 32 * 1024;
            }

            // Drop anything queued under the old trail selection.
            let rc = libc::ioctl(file.as_raw_fd(), AUDITPIPE_FLUSH as libc::c_ulong);
            if rc == -1 {
                return Err(io::Error::last_os_error());
            }

            Ok(AuditPipe {
                file,
                max_record_bytes: (max_data as usize).max(32 * 1024),
                queue_limit,
            })
        }
    }

    /// Records the kernel dropped because this pipe's queue was full.
    pub fn drops(&self) -> Option<u64> {
        let mut drops: u64 = 0;
        unsafe { ioctl_ptr(&self.file, AUDITPIPE_GET_DROPS, &mut drops).ok()? };
        Some(drops)
    }

    /// Wait up to `timeout_ms` for a record. Returns false on timeout.
    pub fn wait_readable(&self, timeout_ms: i32) -> io::Result<bool> {
        let mut fds = libc::pollfd {
            fd: self.file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut fds, 1, timeout_ms) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(err);
        }
        Ok(rc > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_numbers_match_sdk_header_values() {
        // Printed from <security/audit/audit_ioctl.h> on macOS 27.2.
        assert_eq!(AUDITPIPE_SET_PRESELECT_MODE, 0x8004_410f);
        assert_eq!(AUDITPIPE_SET_PRESELECT_FLAGS, 0x8008_4107);
        assert_eq!(AUDITPIPE_SET_PRESELECT_NAFLAGS, 0x8008_4109);
        assert_eq!(AUDITPIPE_GET_QLIMIT_MAX, 0x4004_4105);
        assert_eq!(AUDITPIPE_SET_QLIMIT, 0x8004_4103);
        assert_eq!(AUDITPIPE_FLUSH, 0x2000_4110);
        assert_eq!(AUDITPIPE_GET_MAXAUDITDATA, 0x4004_4111);
        assert_eq!(AUDITPIPE_GET_DROPS, 0x4008_4166);
    }

    #[test]
    fn class_names_match_system_file() {
        let text = match std::fs::read_to_string("/etc/security/audit_class") {
            Ok(t) => t,
            Err(_) => return,
        };
        for line in text.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 2 || !parts[0].starts_with("0x") {
                continue;
            }
            let value = u32::from_str_radix(parts[0].trim_start_matches("0x"), 16).unwrap();
            for (name, bit) in AUDIT_CLASSES {
                if *name == parts[1] {
                    assert_eq!(*bit, value, "class {} differs from /etc/security/audit_class", name);
                }
            }
        }
    }

    #[test]
    fn parses_class_lists() {
        assert_eq!(parse_classes("ex").unwrap(), 0x4000_0000);
        assert_eq!(parse_classes("ex, pc").unwrap(), 0x4000_0080);
        assert!(parse_classes("zz").is_err());
        assert!(parse_classes(DEFAULT_CLASSES).is_ok());
    }
}
