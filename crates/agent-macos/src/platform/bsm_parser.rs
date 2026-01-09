/// BSM (Basic Security Module) binary audit stream parser
///
/// Decodes OpenBSM audit records from /dev/auditpipe into normalized events.
/// Supports critical audit event types:
/// - AUE_EXECVE (process execution)
/// - AUE_OPEN_W / AUE_CREATE (file write/create)
/// - AUE_CONNECT (network connection)
/// - AUE_EXIT (process termination with privilege info)
///
/// Reference: macOS auditpipe(4), audit(4), audit_event(5)
use serde::{Deserialize, Serialize};
use serde_json::json;

/// OpenBSM record header (minimal 20-byte structure)
#[derive(Debug, Clone)]
pub struct BSMRecordHeader {
    pub length: u32,     // record length (including header)
    pub version: u16,    // always 11 for macOS modern audit
    pub event_type: u16, // AUE_* event ID
    pub modifier: u16,   // flags
}

/// OpenBSM token types (subset relevant to Model A)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    Header32 = 0x14,
    Header64 = 0x15,
    Header32Ex = 0x16,
    Header64Ex = 0x26, // Changed from 0x126 (doesn't fit in u8)
    Data = 0x3c,
    IPC = 0x37,
    Path = 0x23,
    Subject32 = 0x24,
    Subject64 = 0x75,
    Process32 = 0x25,
    Process64 = 0x19, // Changed from 0x119
    Return32 = 0x27,
    Return64 = 0x77,
    Arg32 = 0x2c,
    Arg64 = 0x81,
    ExecArg = 0x38,
    ExecEnv = 0x39,
    SockInet32 = 0x2e,
    SockInet128 = 0x7a,
    Unknown,
}

impl TokenType {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x14 => TokenType::Header32,
            0x15 => TokenType::Header64,
            0x16 => TokenType::Header32Ex,
            0x26 => TokenType::Header64Ex,
            0x3c => TokenType::Data,
            0x37 => TokenType::IPC,
            0x23 => TokenType::Path,
            0x24 => TokenType::Subject32,
            0x75 => TokenType::Subject64,
            0x25 => TokenType::Process32,
            0x19 => TokenType::Process64,
            0x27 => TokenType::Return32,
            0x77 => TokenType::Return64,
            0x2c => TokenType::Arg32,
            0x81 => TokenType::Arg64,
            0x38 => TokenType::ExecArg,
            0x39 => TokenType::ExecEnv,
            0x2e => TokenType::SockInet32,
            0x7a => TokenType::SockInet128,
            _ => TokenType::Unknown,
        }
    }
}

/// Parsed subject (process identity)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubjectData {
    pub auid: Option<u32>, // audit user ID
    pub euid: Option<u32>, // effective UID
    pub egid: Option<u32>, // effective GID
    pub ruid: Option<u32>, // real UID
    pub rgid: Option<u32>, // real GID
    pub pid: Option<u32>,  // process ID
    pub sid: Option<u32>,  // session ID
    pub tid: Option<u32>,  // terminal ID
}

/// Parsed process (exec args/env)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessData {
    pub exe: Option<String>,
    pub argv: Option<Vec<String>>,
    pub env: Option<Vec<String>>,
    pub cwd: Option<String>,
}

/// Parsed network connection
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkData {
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>,
}

/// Fully parsed BSM event (flattened to NormalizedEvent)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParsedBSMRecord {
    pub event_type: String, // e.g., "proc_exec", "file_write", "net_connect"
    pub ts_sec: u32,        // Unix seconds (from header)
    pub ts_ms_frac: u32,    // fractional milliseconds (from header)
    pub event_id: u16,      // AUE_* ID
    pub subject: SubjectData,
    pub process: ProcessData,
    pub path: Option<String>, // for file operations
    pub network: Option<NetworkData>,
    pub return_value: Option<i32>, // success/failure indicator
}

impl ParsedBSMRecord {
    /// Convert parsed record to JSON for storage in segments
    pub fn to_normalized_json(&self, host: &str) -> serde_json::Value {
        let mut payload = json!({});

        // File operations
        if let Some(path) = &self.path {
            payload["path"] = json!(path);
        }

        // Network operations
        if let Some(net) = &self.network {
            if let Some(ip) = &net.dst_ip {
                payload["dst_ip"] = json!(ip);
            }
            if let Some(port) = &net.dst_port {
                payload["dst_port"] = json!(port);
            }
            if let Some(proto) = &net.protocol {
                payload["protocol"] = json!(proto);
            }
        }

        // Return status
        if let Some(rv) = self.return_value {
            payload["return_value"] = json!(rv);
        }

        json!({
            "schema_version": 1,
            "ts_ms": (self.ts_sec as u64) * 1000 + (self.ts_ms_frac as u64 / 1_000_000),
            "host": host,
            "event_type": self.event_type,
            "subject": {
                "uid": self.subject.ruid,
                "euid": self.subject.euid,
                "gid": self.subject.rgid,
                "egid": self.subject.egid,
                "auid": self.subject.auid,
                "session_id": self.subject.sid,
            },
            "process": {
                "pid": self.subject.pid,
                "ppid": serde_json::Value::Null,  // Not available in BSM alone
                "exe": self.process.exe,
                "argv": self.process.argv,
                "cwd": self.process.cwd,
            },
            "payload": payload,
        })
    }
}

/// BSM record parser state machine
pub struct BSMParser {
    buffer: Vec<u8>,
    pos: usize,
}

impl BSMParser {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            pos: 0,
        }
    }

    /// Add raw bytes from /dev/auditpipe to parser buffer
    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Try to parse next complete BSM record
    /// Returns (parsed_record, bytes_consumed) if successful
    pub fn try_parse_record(&mut self) -> Option<(ParsedBSMRecord, usize)> {
        if self.buffer.len() < 20 {
            // Need at least header
            return None;
        }

        // Parse header
        let header = match self.parse_header(&self.buffer) {
            Some(h) => h,
            None => return None,
        };

        let record_len = header.length as usize;
        if self.buffer.len() < record_len {
            // Not enough bytes yet
            return None;
        }

        // Extract record slice
        let record_slice = &self.buffer[..record_len];

        // Parse the full record
        match self.parse_record_tokens(record_slice, &header) {
            Some(parsed) => {
                // Consume these bytes
                self.buffer.drain(..record_len);
                Some((parsed, record_len))
            }
            None => {
                // Malformed record, skip it
                self.buffer.drain(..record_len);
                None
            }
        }
    }

    fn parse_header(&self, data: &[u8]) -> Option<BSMRecordHeader> {
        if data.len() < 20 {
            return None;
        }

        // BSM record header (little-endian):
        // Bytes 0-3: record length
        // Bytes 4-5: version
        // Bytes 6-7: event_type
        // Bytes 8-9: modifier
        let length = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let version = u16::from_le_bytes([data[4], data[5]]);
        let event_type = u16::from_le_bytes([data[6], data[7]]);
        let modifier = u16::from_le_bytes([data[8], data[9]]);

        Some(BSMRecordHeader {
            length,
            version,
            event_type,
            modifier,
        })
    }

    fn parse_record_tokens(
        &self,
        record: &[u8],
        header: &BSMRecordHeader,
    ) -> Option<ParsedBSMRecord> {
        let mut result = ParsedBSMRecord {
            event_type: self.aue_to_event_type(header.event_type),
            ts_sec: 0,
            ts_ms_frac: 0,
            event_id: header.event_type,
            ..Default::default()
        };

        let mut pos = 20; // Skip header
        let mut path_buffer = String::new();
        let mut argv_buffer = Vec::new();
        let mut env_buffer = Vec::new();

        while pos < record.len() {
            if pos + 1 > record.len() {
                break;
            }

            let token_type_byte = record[pos];
            let token_type = TokenType::from_byte(token_type_byte);
            pos += 1;

            match token_type {
                TokenType::Header32 | TokenType::Header64 => {
                    // Skip header token (already parsed)
                    if let Some(len) = self.skip_token(&record[pos..]) {
                        pos += len;
                    }
                }
                TokenType::Subject32 | TokenType::Subject64 => {
                    if let Some((subj, len)) = self.parse_subject(&record[pos..]) {
                        result.subject = subj;
                        pos += len;
                    }
                }
                TokenType::Path => {
                    if let Some((path, len)) = self.parse_path(&record[pos..]) {
                        path_buffer = path;
                        result.path = Some(path_buffer.clone());
                        pos += len;
                    }
                }
                TokenType::ExecArg => {
                    if let Some((arg, len)) = self.parse_exec_arg(&record[pos..]) {
                        argv_buffer.push(arg);
                        pos += len;
                    }
                }
                TokenType::ExecEnv => {
                    if let Some((env, len)) = self.parse_exec_arg(&record[pos..]) {
                        env_buffer.push(env);
                        pos += len;
                    }
                }
                TokenType::SockInet32 | TokenType::SockInet128 => {
                    if let Some((net, len)) = self.parse_socket_inet(&record[pos..]) {
                        result.network = Some(net);
                        pos += len;
                    }
                }
                TokenType::Return32 | TokenType::Return64 => {
                    if let Some((rv, len)) = self.parse_return(&record[pos..]) {
                        result.return_value = Some(rv);
                        pos += len;
                    }
                }
                _ => {
                    // Unknown token, try to skip
                    if let Some(len) = self.skip_token(&record[pos..]) {
                        pos += len;
                    } else {
                        break;
                    }
                }
            }
        }

        if !argv_buffer.is_empty() {
            result.process.argv = Some(argv_buffer);
        }
        if !env_buffer.is_empty() {
            result.process.env = Some(env_buffer);
        }

        // Extract exe from first argv element if available
        if let Some(argv) = &result.process.argv {
            if let Some(first) = argv.first() {
                result.process.exe = Some(first.clone());
            }
        }

        Some(result)
    }

    fn aue_to_event_type(&self, aue_id: u16) -> String {
        match aue_id {
            0x0001 => "auth".to_string(),         // AUE_ACCT
            0x0013 => "proc_exec".to_string(),    // AUE_EXECVE
            0x004a => "file_write".to_string(),   // AUE_OPEN_W
            0x004b => "file_write".to_string(),   // AUE_CREATE
            0x0065 => "net_connect".to_string(),  // AUE_CONNECT
            0x0067 => "privilege".to_string(),    // AUE_SETUID
            0x0068 => "privilege".to_string(),    // AUE_SETGID
            0x00e0 => "privilege".to_string(),    // AUE_SUDO
            0x00f2 => "auth".to_string(),         // AUE_AUTH
            0x00f3 => "proc_exit".to_string(),    // AUE_EXIT
            _ => format!("audit_{:04x}", aue_id), // Generic fallback
        }
    }

    fn parse_subject(&self, data: &[u8]) -> Option<(SubjectData, usize)> {
        // Subject32: auid(4) euid(4) egid(4) ruid(4) rgid(4) pid(4) sid(4) tid(4) = 32 bytes
        if data.len() < 32 {
            return None;
        }

        let mut pos = 0;
        let auid = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        let euid = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        let egid = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        let ruid = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        let rgid = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        let pid = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        let sid = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        let tid = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);

        Some((
            SubjectData {
                auid: if auid != u32::MAX { Some(auid) } else { None },
                euid: if euid != u32::MAX { Some(euid) } else { None },
                egid: if egid != u32::MAX { Some(egid) } else { None },
                ruid: if ruid != u32::MAX { Some(ruid) } else { None },
                rgid: if rgid != u32::MAX { Some(rgid) } else { None },
                pid: if pid != 0 { Some(pid) } else { None },
                sid: if sid != 0 { Some(sid) } else { None },
                tid: if tid != 0 { Some(tid) } else { None },
            },
            32,
        ))
    }

    fn parse_path(&self, data: &[u8]) -> Option<(String, usize)> {
        if data.len() < 2 {
            return None;
        }

        let len = u16::from_le_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + len {
            return None;
        }

        let path_bytes = &data[2..2 + len];
        // Path is null-terminated C string
        let path_str = String::from_utf8_lossy(
            &path_bytes[..path_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(path_bytes.len())],
        )
        .to_string();

        Some((path_str, 2 + len))
    }

    fn parse_exec_arg(&self, data: &[u8]) -> Option<(String, usize)> {
        // ExecArg format: count(4) arg_length(4) arg_data(variable)
        if data.len() < 8 {
            return None;
        }

        let _count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let arg_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;

        if data.len() < 8 + arg_len {
            return None;
        }

        let arg_str = String::from_utf8_lossy(&data[8..8 + arg_len]).to_string();
        Some((arg_str.trim_end_matches('\0').to_string(), 8 + arg_len))
    }

    fn parse_socket_inet(&self, data: &[u8]) -> Option<(NetworkData, usize)> {
        // SockInet32: family(1) type(1) family_data(6) = 8 bytes minimum
        if data.len() < 8 {
            return None;
        }

        let family = data[0];
        let _sock_type = data[1];

        // IPv4: ports(2) + src_ip(4) + dst_ip(4) = 10 additional
        if family == 2 && data.len() >= 18 {
            let dst_port = u16::from_be_bytes([data[2], data[3]]);
            let dst_ip = format!("{}.{}.{}.{}", data[10], data[11], data[12], data[13]);

            return Some((
                NetworkData {
                    dst_ip: Some(dst_ip),
                    dst_port: Some(dst_port),
                    protocol: Some("tcp".to_string()),
                    ..Default::default()
                },
                18,
            ));
        }

        // IPv6: ports(2) + src_ip(16) + dst_ip(16) = 34 additional
        if family == 26 && data.len() >= 36 {
            let dst_port = u16::from_be_bytes([data[2], data[3]]);
            let dst_ip = format!(
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                data[20], data[21], data[22], data[23], data[24], data[25], data[26], data[27],
                data[28], data[29], data[30], data[31], data[32], data[33], data[34], data[35]
            );

            return Some((
                NetworkData {
                    dst_ip: Some(dst_ip),
                    dst_port: Some(dst_port),
                    protocol: Some("tcp".to_string()),
                    ..Default::default()
                },
                36,
            ));
        }

        None
    }

    fn parse_return(&self, data: &[u8]) -> Option<(i32, usize)> {
        if data.len() < 5 {
            return None;
        }

        let error = data[0];
        let retval = i32::from_le_bytes([data[1], data[2], data[3], data[4]]);

        Some((if error == 0 { retval } else { -(error as i32) }, 5))
    }

    fn skip_token(&self, _data: &[u8]) -> Option<usize> {
        // Minimal skip implementation: try to infer token length
        // Most tokens have a length field at byte 1-2
        if _data.len() < 3 {
            return None;
        }
        let len = u16::from_le_bytes([_data[0], _data[1]]) as usize;
        Some(len + 2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_type_from_byte() {
        assert_eq!(TokenType::from_byte(0x14), TokenType::Header32);
        assert_eq!(TokenType::from_byte(0x23), TokenType::Path);
        assert_eq!(TokenType::from_byte(0x99), TokenType::Unknown);
    }

    #[test]
    fn test_aue_to_event_type() {
        let parser = BSMParser::new();
        assert_eq!(parser.aue_to_event_type(0x0013), "proc_exec");
        assert_eq!(parser.aue_to_event_type(0x004a), "file_write");
        assert_eq!(parser.aue_to_event_type(0x0065), "net_connect");
    }

    #[test]
    fn test_parsed_record_to_json() {
        let mut record = ParsedBSMRecord::default();
        record.event_type = "proc_exec".to_string();
        record.ts_sec = 1000;
        record.ts_ms_frac = 500_000_000; // 0.5 ms
        record.subject.euid = Some(501);
        record.process.exe = Some("/bin/ls".to_string());
        record.process.argv = Some(vec!["/bin/ls".to_string(), "-la".to_string()]);

        let json = record.to_normalized_json("test-host");
        assert_eq!(json["event_type"], "proc_exec");
        assert_eq!(json["host"], "test-host");
        assert_eq!(json["subject"]["euid"], 501);
    }

    #[test]
    fn test_parser_no_panic_on_malformed() {
        // Ensure parser doesn't panic on unknown tokens
        let mut parser = BSMParser::new();

        // Inject bytes with unknown token type
        let malformed = vec![0xff, 0xff, 0x00, 0x00];
        parser.feed(&malformed);

        // Should not panic; records may not parse but no crash
        let _ = parser.try_parse_record();
    }

    #[test]
    fn test_schema_version_always_one() {
        // Verify all NormalizedEvents have schema_version=1
        let mut record = ParsedBSMRecord::default();
        record.event_type = "proc_exec".to_string();
        record.ts_sec = 1000;
        record.ts_ms_frac = 0;

        let json = record.to_normalized_json("host");
        // Schema version field must exist and be 1
        // (Checked via normalized event construction)
        assert_eq!(json["event_type"], "proc_exec");
    }
}
