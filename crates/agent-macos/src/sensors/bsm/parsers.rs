// macos/sensors/bsm/parsers.rs
// Low-level BSM parsing utilities
// Extracts fields from OpenBSM audit tokens and records

/// BSM magic header (identifies start of record)
pub const BSM_HEADER: u8 = 0x17; // Traditional BSM header byte

/// AUE (Audit User Event) codes
pub mod aue {
    /// Process execution
    pub const AUE_EXECVE: i32 = 23027;
    /// File open
    pub const AUE_OPEN: i32 = 3;
    /// File read
    pub const AUE_READ: i32 = 4;
    /// File write
    pub const AUE_WRITE: i32 = 5;
    /// File create
    pub const AUE_CREATE: i32 = 300;
    /// File delete
    pub const AUE_UNLINK: i32 = 7;
    /// File attribute change
    pub const AUE_FCHMOD: i32 = 17;
    /// Mount operation
    pub const AUE_MOUNT: i32 = 25;
    /// Unmount operation
    pub const AUE_UNMOUNT: i32 = 26;
}

/// Parse process execution event from BSM record
/// Extracts: exe, cmdline, pid, ppid, uid, cwd
pub fn parse_proc_exec(data: &[u8]) -> Option<(String, String, u32, u32, u32, String)> {
    // TODO: Implement BSM EXECVE parsing
    // BSM format: Header | AUE code | Timestamp | Return value | Subject token | Text token | ...
    // Extract: exe path, cmdline args, pid, ppid, uid, cwd
    None
}

/// Parse file open event from BSM record
pub fn parse_file_open(data: &[u8]) -> Option<(String, u32, u32)> {
    // TODO: Implement BSM OPEN parsing
    // Extract: path, uid, pid
    None
}

/// Parse file read event from BSM record
pub fn parse_file_read(data: &[u8]) -> Option<(String, u32, u32)> {
    // TODO: Implement BSM READ parsing
    // Extract: path, uid, pid
    None
}

/// Parse file write event from BSM record
pub fn parse_file_write(data: &[u8]) -> Option<(String, u64, u32, u32)> {
    // TODO: Implement BSM WRITE parsing
    // Extract: path, bytes_written, uid, pid
    None
}

/// Parse file attribute change event from BSM record
pub fn parse_file_setattr(data: &[u8]) -> Option<(String, u32, u32)> {
    // TODO: Implement BSM FCHMOD/CHMOD parsing
    // Extract: path, mode, uid
    None
}

/// Parse mount operation from BSM record
pub fn parse_mount(data: &[u8]) -> Option<(String, String, bool)> {
    // TODO: Implement BSM MOUNT parsing
    // Extract: mountpoint, device, is_mount (true) or is_unmount (false)
    None
}

/// Extract subject token (process info) from BSM record
pub struct SubjectToken {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub ppid: u32,
    pub sid: u32,
}

pub fn parse_subject_token(data: &[u8]) -> Option<SubjectToken> {
    // TODO: Parse BSM subject token
    None
}
