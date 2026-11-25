//! Turns decoded BSM records into `edr_core::Event` values.
//!
//! The capture agent runs as root, so it does as little as possible: decode
//! the record, name the operation and copy the facts into a flat event.
//! It makes no detection decisions. Detection lives in `edr-locald` and the
//! YAML playbooks, which run unprivileged.
//!
//! Every event has three tags, `["macos", <category>, <operation>]`:
//!
//! | category       | operations |
//! |----------------|------------|
//! | `process`      | `exec`, `fork`, `exit`, `kill`, `task_for_pid`, `pid_for_task`, `task_name_for_pid`, `ptrace` |
//! | `file`         | `read`, `write`, `create`, `delete`, `rename`, `chmod`, `chown`, `truncate`, `link` |
//! | `privilege`    | `setuid`, `seteuid`, `setreuid`, `setresuid`, `setgid`, `setegid`, `setregid`, `setresgid`, `setgroups`, `setauid`, `setlogin` |
//! | `network`      | `socket`, `connect`, `accept`, `bind`, `listen` |
//! | `fs`           | `mount`, `unmount` |
//! | `audit_config` | `auditon`, `auditctl`, `audit` |

use super::aue::*;
use super::record::{BsmRecord, AU_DEFAUDITID};
use crate::sensors::hash_keys;
use edr_core::Event;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};

/// How many pid to executable entries to remember. File and network records
/// carry only a pid, so the exe comes from the last exec seen for that pid.
const PID_CACHE_LIMIT: usize = 8192;

/// Category and operation for an event number, or None if the agent does
/// not handle that event.
pub fn classify(code: u16) -> Option<(&'static str, &'static str)> {
    if let Some(variant) = open_variant(code) {
        let op = if variant.create {
            "create"
        } else if variant.write {
            "write"
        } else {
            "read"
        };
        return Some(("file", op));
    }
    let pair = match code {
        AUE_EXECVE | AUE_EXEC | AUE_MAC_EXECVE | AUE_POSIX_SPAWN => ("process", "exec"),
        AUE_FORK | AUE_VFORK => ("process", "fork"),
        AUE_EXIT => ("process", "exit"),
        AUE_KILL => ("process", "kill"),
        AUE_PTRACE => ("process", "ptrace"),
        AUE_TASKFORPID => ("process", "task_for_pid"),
        AUE_PIDFORTASK => ("process", "pid_for_task"),
        AUE_TASKNAMEFORPID => ("process", "task_name_for_pid"),

        AUE_UNLINK | AUE_UNLINKAT | AUE_RMDIR => ("file", "delete"),
        AUE_RENAME | AUE_RENAMEAT => ("file", "rename"),
        AUE_CHMOD | AUE_FCHMOD | AUE_LCHMOD | AUE_FCHMODAT | AUE_CHMOD_EXTENDED | AUE_FCHMOD_EXTENDED => {
            ("file", "chmod")
        }
        AUE_CHOWN | AUE_FCHOWN | AUE_LCHOWN | AUE_FCHOWNAT => ("file", "chown"),
        AUE_TRUNCATE | AUE_FTRUNCATE => ("file", "truncate"),
        AUE_LINK | AUE_LINKAT | AUE_SYMLINK | AUE_SYMLINKAT | AUE_CLONEFILEAT | AUE_FCLONEFILEAT
        | AUE_EXCHANGEDATA => ("file", "link"),

        AUE_SETUID => ("privilege", "setuid"),
        AUE_SETEUID => ("privilege", "seteuid"),
        AUE_SETREUID => ("privilege", "setreuid"),
        AUE_SETRESUID => ("privilege", "setresuid"),
        AUE_SETGID => ("privilege", "setgid"),
        AUE_SETEGID => ("privilege", "setegid"),
        AUE_SETREGID => ("privilege", "setregid"),
        AUE_SETRESGID => ("privilege", "setresgid"),
        AUE_SETGROUPS => ("privilege", "setgroups"),
        AUE_SETAUID => ("privilege", "setauid"),
        AUE_SETLOGIN => ("privilege", "setlogin"),

        AUE_SOCKET => ("network", "socket"),
        AUE_CONNECT => ("network", "connect"),
        AUE_ACCEPT => ("network", "accept"),
        AUE_BIND => ("network", "bind"),
        AUE_LISTEN => ("network", "listen"),

        AUE_MOUNT | AUE_FMOUNT => ("fs", "mount"),
        AUE_UNMOUNT => ("fs", "unmount"),

        AUE_AUDITON => ("audit_config", "auditon"),
        AUE_AUDITCTL => ("audit_config", "auditctl"),
        AUE_AUDIT => ("audit_config", "audit"),
        _ => return None,
    };
    Some(pair)
}

/// Converts records to events and remembers which program each pid runs.
pub struct Normalizer {
    host: String,
    stream_id: String,
    exe_by_pid: HashMap<u32, String>,
    parent_by_pid: HashMap<u32, u32>,
    /// Working directory per pid, from chdir and fchdir records and inherited on fork
    /// and posix_spawn. The kernel records the path a program passed, so a file created
    /// with a relative path (cp x Library/LaunchAgents/y.plist) has no folder in front.
    cwd_by_pid: HashMap<u32, String>,
    insertion_order: VecDeque<u32>,
}

impl Normalizer {
    pub fn new(host: &str, stream_id: &str) -> Self {
        Normalizer {
            host: host.to_string(),
            stream_id: stream_id.to_string(),
            exe_by_pid: HashMap::new(),
            parent_by_pid: HashMap::new(),
            cwd_by_pid: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    fn remember(&mut self, pid: u32, exe: Option<&str>, parent: Option<u32>) {
        if !self.exe_by_pid.contains_key(&pid) && !self.parent_by_pid.contains_key(&pid) {
            self.insertion_order.push_back(pid);
        }
        if let Some(exe) = exe {
            self.exe_by_pid.insert(pid, exe.to_string());
        }
        if let Some(parent) = parent {
            self.parent_by_pid.insert(pid, parent);
        }
        while self.insertion_order.len() > PID_CACHE_LIMIT {
            if let Some(old) = self.insertion_order.pop_front() {
                self.exe_by_pid.remove(&old);
                self.parent_by_pid.remove(&old);
                self.cwd_by_pid.remove(&old);
            }
        }
    }

    /// The child starts in its parent's working directory.
    fn inherit_cwd(&mut self, parent: u32, child: u32) {
        if let Some(cwd) = self.cwd_by_pid.get(&parent).cloned() {
            self.cwd_by_pid.insert(child, cwd);
        }
    }

    /// An absolute path for `path`, joined to the pid's working directory when the
    /// program passed a relative one. None when it is relative and the folder is not
    /// known, because the process changed folder before the capture started.
    fn absolute(&self, pid: u32, path: &str) -> Option<String> {
        if path.starts_with('/') {
            return Some(path.to_string());
        }
        let cwd = self.cwd_by_pid.get(&pid)?;
        let mut parts: Vec<&str> = cwd.split('/').filter(|p| !p.is_empty()).collect();
        for part in path.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                other => parts.push(other),
            }
        }
        Some(format!("/{}", parts.join("/")))
    }

    /// Normalize one record. Returns None for event numbers the agent does
    /// not handle and for records without a subject token.
    pub fn normalize(&mut self, rec: &BsmRecord) -> Option<Event> {
        if rec.event == AUE_CHDIR || rec.event == AUE_FCHDIR {
            // Kept as state for relative paths, not written out as an event.
            let subject = rec.subject.as_ref()?;
            if rec.success() {
                if let Some(dir) = rec.paths.last() {
                    if let Some(dir) = self.absolute(subject.pid, dir) {
                        self.cwd_by_pid.insert(subject.pid, dir);
                    }
                }
            }
            return None;
        }
        let (category, op) = classify(rec.event)?;
        let subject = rec.subject.as_ref()?;

        let mut fields: BTreeMap<String, Value> = BTreeMap::new();
        fields.insert("aue_code".into(), json!(rec.event));
        if let Some(name) = event_name(rec.event) {
            fields.insert("aue_name".into(), json!(name));
        }
        fields.insert("op".into(), json!(op));
        fields.insert("success".into(), json!(rec.success()));
        if let Some(ret) = &rec.ret {
            if ret.error != 0 {
                fields.insert("errno".into(), json!(ret.error));
            }
        }

        // Subject. ruid is the user who started the process, euid is the
        // identity the kernel checked. auid is the login user and survives
        // sudo, which is why playbooks scope on it.
        let mut pid = subject.pid;
        fields.insert("uid".into(), json!(subject.ruid));
        fields.insert("euid".into(), json!(subject.euid));
        fields.insert("gid".into(), json!(subject.rgid));
        fields.insert("egid".into(), json!(subject.egid));
        if subject.auid != AU_DEFAUDITID {
            fields.insert("auid".into(), json!(subject.auid));
        }
        fields.insert("asid".into(), json!(subject.asid));
        if subject.terminal_addr != "0.0.0.0" {
            fields.insert("terminal_addr".into(), json!(subject.terminal_addr));
        }

        let mut file_path: Option<String> = None;

        match category {
            "process" if op == "exec" => {
                let exe = rec.paths.last().cloned().unwrap_or_default();
                if rec.event == AUE_POSIX_SPAWN {
                    // The subject of a posix_spawn record is the parent. The
                    // new process id is in the "child PID" argument.
                    if let Some(child) = rec.arg_named("child PID") {
                        fields.insert("ppid".into(), json!(subject.pid));
                        pid = child.value as u32;
                        self.inherit_cwd(subject.pid, pid);
                    }
                } else if let Some(parent) = self.parent_by_pid.get(&subject.pid) {
                    fields.insert("ppid".into(), json!(parent));
                }
                if let Some(parent_pid) = fields.get("ppid").and_then(|v| v.as_u64()) {
                    if let Some(parent_exe) = self.exe_by_pid.get(&(parent_pid as u32)) {
                        fields.insert("parent_exe".into(), json!(parent_exe));
                    }
                }
                fields.insert("exe".into(), json!(exe));
                fields.insert("argv".into(), json!(rec.exec_args));
                fields.insert("cmdline".into(), json!(rec.exec_args.join(" ")));
                if !rec.exec_env.is_empty() {
                    fields.insert("env".into(), json!(rec.exec_env));
                }
                if let Some(id) = &rec.identity {
                    fields.insert("signing_id".into(), json!(id.signing_id));
                    fields.insert("team_id".into(), json!(id.team_id));
                    fields.insert("signer_type".into(), json!(id.signer_type));
                    fields.insert("cdhash".into(), json!(id.cdhash));
                }
                if rec.success() {
                    let parent = fields.get("ppid").and_then(|v| v.as_u64()).map(|p| p as u32);
                    self.remember(pid, Some(&exe), parent);
                }
                file_path = Some(exe);
            }
            "process" if op == "fork" => {
                // fork returns the child pid to the parent.
                if let Some(ret) = &rec.ret {
                    if ret.error == 0 && ret.value > 0 {
                        let child = ret.value as u32;
                        fields.insert("child_pid".into(), json!(child));
                        let parent_exe = self.exe_by_pid.get(&subject.pid).cloned();
                        self.remember(child, parent_exe.as_deref(), Some(subject.pid));
                        self.inherit_cwd(subject.pid, child);
                    }
                }
            }
            "process" => {
                // kill, ptrace and the task port calls name a target process.
                let target = rec
                    .process
                    .as_ref()
                    .map(|p| p.pid)
                    .or_else(|| rec.arg_named("pid").map(|a| a.value as u32));
                if let Some(target) = target {
                    fields.insert("target_pid".into(), json!(target));
                    if let Some(target_exe) = self.exe_by_pid.get(&target) {
                        fields.insert("target_exe".into(), json!(target_exe));
                    }
                }
                if let Some(signal) = rec.arg_named("signal") {
                    fields.insert("signal".into(), json!(signal.value));
                }
                if op == "exit" {
                    self.exe_by_pid.remove(&subject.pid);
                    self.parent_by_pid.remove(&subject.pid);
                    self.cwd_by_pid.remove(&subject.pid);
                }
            }
            "file" => {
                let path = if op == "rename" {
                    rec.paths.first().cloned()
                } else {
                    rec.paths.last().cloned()
                };
                let given = path?;
                let path = match self.absolute(subject.pid, &given) {
                    Some(full) => full,
                    None => {
                        fields.insert("path_relative".into(), json!(true));
                        given.clone()
                    }
                };
                if path != given {
                    fields.insert("path_given".into(), json!(given));
                }
                if op == "rename" && rec.paths.len() >= 2 {
                    let new_given = &rec.paths[rec.paths.len() - 1];
                    let new_path = self.absolute(subject.pid, new_given).unwrap_or_else(|| new_given.clone());
                    fields.insert("new_path".into(), json!(new_path));
                }
                if let Some(variant) = open_variant(rec.event) {
                    let access = match (variant.read, variant.write) {
                        (true, true) => "rw",
                        (false, true) => "w",
                        _ => "r",
                    };
                    fields.insert("access".into(), json!(access));
                    fields.insert("truncate".into(), json!(variant.truncate));
                    if let Some(flags) = rec.arg_named("flags") {
                        fields.insert("open_flags".into(), json!(flags.value));
                    }
                }
                if op == "chmod" {
                    if let Some(mode) = rec.arg_named("new file mode") {
                        fields.insert("new_mode".into(), json!(format!("{:o}", mode.value)));
                    }
                }
                if op == "chown" {
                    if let Some(owner) = rec.arg_named("new file uid") {
                        fields.insert("new_uid".into(), json!(owner.value));
                    }
                }
                if let Some(attr) = rec.attrs.first() {
                    fields.insert("inode".into(), json!(attr.node_id));
                    fields.insert("file_mode".into(), json!(format!("{:o}", attr.mode)));
                    fields.insert("file_uid".into(), json!(attr.uid));
                }
                fields.insert("path".into(), json!(path));
                file_path = Some(path);
            }
            "privilege" => {
                // The first argument is the id being set. setre* and setres*
                // carry one argument per id.
                let mut values: Vec<u64> = Vec::new();
                for arg in &rec.args {
                    values.push(arg.value);
                }
                if let Some(first) = values.first() {
                    if op.contains("gid") || op == "setgroups" {
                        fields.insert("target_gid".into(), json!(first));
                    } else {
                        fields.insert("target_uid".into(), json!(first));
                    }
                }
                if values.len() > 1 {
                    fields.insert("target_ids".into(), json!(values));
                }
            }
            "network" => {
                if let Some(sock) = rec.sockets.last() {
                    let (ip_key, port_key) = if op == "bind" {
                        ("local_ip", "local_port")
                    } else {
                        ("remote_ip", "remote_port")
                    };
                    fields.insert("family".into(), json!(sock.family));
                    if sock.family == "unix" {
                        fields.insert("socket_path".into(), json!(sock.address));
                    } else {
                        fields.insert(ip_key.into(), json!(sock.address));
                        fields.insert(port_key.into(), json!(sock.port));
                    }
                }
                if let Some(fd) = rec.arg_named("fd") {
                    fields.insert("fd".into(), json!(fd.value));
                }
            }
            "fs" => {
                if let Some(path) = rec.paths.last() {
                    fields.insert("path".into(), json!(path));
                }
                if let Some(fs_type) = rec.texts.first() {
                    fields.insert("fs_type".into(), json!(fs_type));
                }
            }
            _ => {}
        }

        fields.insert("pid".into(), json!(pid));
        if !fields.contains_key("exe") {
            if let Some(exe) = self.exe_by_pid.get(&pid) {
                fields.insert("exe".into(), json!(exe));
            }
        }

        let identity_uid = if subject.auid != AU_DEFAUDITID { subject.auid } else { subject.ruid };
        Some(Event {
            ts_ms: rec.ts_ms as i64,
            host: self.host.clone(),
            tags: vec!["macos".to_string(), category.to_string(), op.to_string()],
            proc_key: Some(hash_keys::proc_key(&self.host, pid, &self.stream_id)),
            file_key: file_path
                .as_deref()
                .filter(|p| !p.is_empty())
                .map(|p| hash_keys::file_key(&self.host, p, &self.stream_id)),
            identity_key: Some(hash_keys::identity_key(&self.host, identity_uid, &self.stream_id)),
            evidence_ptr: None,
            fields,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::record::{Arg, ReturnInfo, Subject};
    use super::*;

    #[test]
    fn classify_covers_the_playbook_inputs() {
        assert_eq!(classify(AUE_EXECVE), Some(("process", "exec")));
        assert_eq!(classify(AUE_POSIX_SPAWN), Some(("process", "exec")));
        assert_eq!(classify(AUE_OPEN_R), Some(("file", "read")));
        assert_eq!(classify(AUE_OPEN_W), Some(("file", "write")));
        assert_eq!(classify(AUE_OPEN_RWTC), Some(("file", "create")));
        assert_eq!(classify(AUE_OPENAT_R + 4), Some(("file", "write")));
        assert_eq!(classify(AUE_UNLINKAT), Some(("file", "delete")));
        assert_eq!(classify(AUE_RENAME), Some(("file", "rename")));
        assert_eq!(classify(AUE_SETUID), Some(("privilege", "setuid")));
        assert_eq!(classify(AUE_CONNECT), Some(("network", "connect")));
        assert_eq!(classify(AUE_LISTEN), Some(("network", "listen")));
        assert_eq!(classify(AUE_MOUNT), Some(("fs", "mount")));
        assert_eq!(classify(AUE_TASKFORPID), Some(("process", "task_for_pid")));
        assert_eq!(classify(AUE_AUDITCTL), Some(("audit_config", "auditctl")));
        // Old wrong numbers must not be treated as exec or open.
        assert_eq!(classify(59), None);
        assert_eq!(classify(5), Some(("file", "link"))); // 5 is AUE_LINK
    }

    fn record(event: u16, pid: u32, paths: &[&str], ret_value: u64) -> BsmRecord {
        BsmRecord {
            event,
            subject: Some(Subject {
                auid: 501,
                euid: 0,
                egid: 0,
                ruid: 0,
                rgid: 0,
                pid,
                asid: 100002,
                terminal_addr: "0.0.0.0".to_string(),
            }),
            paths: paths.iter().map(|p| p.to_string()).collect(),
            ret: Some(ReturnInfo { error: 0, value: ret_value }),
            ..Default::default()
        }
    }

    fn path_of(event: &Event) -> &str {
        event.fields.get("path").and_then(|v| v.as_str()).unwrap_or("")
    }

    #[test]
    fn relative_paths_are_joined_to_the_working_folder() {
        // The live run on a GitHub macOS runner: the shell cds into the work folder,
        // forks cp, and cp creates Library/LaunchAgents/edr.smoke.plist by a relative path.
        let mut n = Normalizer::new("host", "bsm");
        assert!(n.normalize(&record(AUE_CHDIR, 100, &["/private/tmp/edr-live/work"], 0)).is_none());
        n.normalize(&record(AUE_FORK, 100, &[], 200)).unwrap();
        let create = n.normalize(&record(AUE_OPENAT_R + 11, 200, &["Library/LaunchAgents/edr.smoke.plist"], 3)).unwrap();
        assert_eq!(path_of(&create), "/private/tmp/edr-live/work/Library/LaunchAgents/edr.smoke.plist");
        assert_eq!(create.fields.get("path_given").and_then(|v| v.as_str()), Some("Library/LaunchAgents/edr.smoke.plist"));

        // ./ and ../ are applied, and an absolute path is left alone.
        let up = n.normalize(&record(AUE_OPEN_R, 200, &["../other/./notes.txt"], 3)).unwrap();
        assert_eq!(path_of(&up), "/private/tmp/edr-live/other/notes.txt");
        let abs = n.normalize(&record(AUE_OPEN_R, 200, &["/etc/hosts"], 3)).unwrap();
        assert_eq!(path_of(&abs), "/etc/hosts");
        assert!(abs.fields.get("path_given").is_none());
    }

    #[test]
    fn an_unknown_working_folder_keeps_the_path_and_says_so() {
        let mut n = Normalizer::new("host", "bsm");
        let create = n.normalize(&record(AUE_OPEN_RWTC, 300, &["Library/LaunchAgents/x.plist"], 3)).unwrap();
        assert_eq!(path_of(&create), "Library/LaunchAgents/x.plist");
        assert_eq!(create.fields.get("path_relative").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn posix_spawn_children_inherit_the_folder_and_exit_forgets_it() {
        let mut n = Normalizer::new("host", "bsm");
        n.normalize(&record(AUE_CHDIR, 10, &["/Users/alice"], 0));
        let mut spawn = record(AUE_POSIX_SPAWN, 10, &["/bin/cp"], 0);
        spawn.args = vec![Arg { number: 0, value: 11, name: "child PID".to_string() }];
        n.normalize(&spawn).unwrap();
        let create = n.normalize(&record(AUE_OPEN_RWTC, 11, &["Library/LaunchAgents/y.plist"], 3)).unwrap();
        assert_eq!(path_of(&create), "/Users/alice/Library/LaunchAgents/y.plist");
        n.normalize(&record(AUE_EXIT, 11, &[], 0)).unwrap();
        let after = n.normalize(&record(AUE_OPEN_R, 11, &["z.txt"], 3)).unwrap();
        assert_eq!(path_of(&after), "z.txt");
    }
}
