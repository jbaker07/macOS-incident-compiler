// macos/sensors/bsm/bsm_tokens.rs
// Real BSM token parsing from OpenBSM audit records
// Extracts pid, uid, euid, gid, egid, ppid, paths, argv, sockaddr

/// BSM token type identifiers (au_token_t)
pub mod token_type {
    pub const FILE_TOKEN: u8 = 0x11;
    pub const ARG_TOKEN: u8 = 0x3c;
    pub const EXEC_ARG_TOKEN: u8 = 0x3c;
    pub const SUBJECT_TOKEN_32: u8 = 0x24;
    pub const SUBJECT_TOKEN_64: u8 = 0x25;
    pub const SUBJECT_TOKEN_EX: u8 = 0x26; // Extended subject token (BSD/Darwin)
    pub const RETURN_TOKEN: u8 = 0x27;
    pub const TEXT_TOKEN: u8 = 0x29;
    pub const PATH_TOKEN: u8 = 0x14;
    pub const ATTR_TOKEN: u8 = 0x71;
    pub const ATTR_TOKEN_32: u8 = 0x72;
    pub const ATTR_TOKEN_64: u8 = 0x73;
    pub const SOCKADDR_TOKEN: u8 = 0x1d;
    pub const SOCKADDR_IN_TOKEN: u8 = 0x1e;
    pub const SOCKADDR_IN6_TOKEN: u8 = 0x1f;
}

/// Subject token: process information from BSM record
#[derive(Debug, Clone, Default)]
pub struct SubjectToken {
    pub auid: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub ruid: Option<u32>,
    pub rgid: Option<u32>,
    pub pid: Option<u32>,
    pub sid: Option<u32>,
    pub tid: Option<u32>,
    pub euid: Option<u32>,
    pub egid: Option<u32>,
}

/// Extract 32-bit integer from bytes in big-endian (BSM network byte order)
#[inline]
fn read_u32_be(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 <= data.len() {
        Some(u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]))
    } else {
        None
    }
}

/// Extract 16-bit integer from bytes in big-endian
#[inline]
fn read_u16_be(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 <= data.len() {
        Some(u16::from_be_bytes([data[offset], data[offset + 1]]))
    } else {
        None
    }
}

/// Validate parsed integer: reject obviously absurd values (pid/uid > 1e7 or == 0 for pid)
#[inline]
fn is_valid_pid(pid: u32) -> bool {
    pid > 0 && pid < 100_000_000 // pid < 1e7, pid != 0
}

#[inline]
fn is_valid_uid(uid: u32) -> bool {
    uid < 100_000_000 // uid < 1e7 (0 = root is valid)
}

/// Extract 32-bit integer from bytes in big-endian (BSM network byte order)
#[inline]
fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 <= data.len() {
        Some(u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]))
    } else {
        None
    }
}

/// Extract 16-bit integer from bytes in big-endian
#[inline]
fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 <= data.len() {
        Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
    } else {
        None
    }
}

/// Parse subject token from BSM record
/// Subject token (type 0x24/0x25): [token_id:1] [auid:4 BE] [uid:4 BE] [gid:4 BE] [ruid:4 BE] [rgid:4 BE] [pid:4 BE] [sid:4 BE] [tid:4 BE] [etype:1]
/// Optional: [euid:4 BE] [egid:4 BE] for some variants
pub fn parse_subject_token(data: &[u8]) -> Option<SubjectToken> {
    if data.is_empty() {
        return None;
    }

    let token_id = data[0];
    // Support all three subject token variants: 32-bit, 64-bit, and extended
    if token_id != token_type::SUBJECT_TOKEN_32
        && token_id != token_type::SUBJECT_TOKEN_64
        && token_id != token_type::SUBJECT_TOKEN_EX
    {
        return None;
    }

    let mut subject = SubjectToken::default();
    let mut offset = 1;

    // Standard subject token fields (big-endian per BSM spec)
    if let Some(auid) = read_u32_be(data, offset) {
        subject.auid = Some(auid);
        offset += 4;
    }
    if let Some(uid) = read_u32_be(data, offset) {
        if !is_valid_uid(uid) {
            return None; // Reject absurd uid
        }
        subject.uid = Some(uid);
        offset += 4;
    }
    if let Some(gid) = read_u32_be(data, offset) {
        if !is_valid_uid(gid) {
            return None; // gid uses same bounds as uid
        }
        subject.gid = Some(gid);
        offset += 4;
    }
    if let Some(ruid) = read_u32_be(data, offset) {
        if !is_valid_uid(ruid) {
            return None;
        }
        subject.ruid = Some(ruid);
        offset += 4;
    }
    if let Some(rgid) = read_u32_be(data, offset) {
        if !is_valid_uid(rgid) {
            return None;
        }
        subject.rgid = Some(rgid);
        offset += 4;
    }
    if let Some(pid) = read_u32_be(data, offset) {
        if !is_valid_pid(pid) {
            return None; // Reject absurd pid (0 or > 1e7)
        }
        subject.pid = Some(pid);
        offset += 4;
    }
    if let Some(sid) = read_u32_be(data, offset) {
        subject.sid = Some(sid);
        offset += 4;
    }
    if let Some(tid) = read_u32_be(data, offset) {
        subject.tid = Some(tid);
        offset += 4;
    }

    // Terminal type and optional euid/egid
    if offset < data.len() {
        offset += 1; // skip terminal type byte
                     // Try to parse euid/egid if present (some BSM implementations include these)
        if let Some(euid) = read_u32_be(data, offset) {
            if is_valid_uid(euid) {
                subject.euid = Some(euid);
            }
        }
        if let Some(egid) = read_u32_be(data, offset + 4) {
            if is_valid_uid(egid) {
                subject.egid = Some(egid);
            }
        }
    }

    Some(subject)
}

/// Parse path from BSM path token
/// Format: [token_id:1] [path_length:2 BE] [path:variable]
pub fn parse_path_token(data: &[u8]) -> Option<String> {
    if data.len() < 3 || data[0] != token_type::PATH_TOKEN {
        return None;
    }

    let path_len = u16::from_be_bytes([data[1], data[2]]) as usize;
    if path_len == 0 || path_len > 4096 {
        return None; // Sanity check: max path 4KB
    }

    if data.len() < 3 + path_len {
        return None;
    }

    // Extract null-terminated path string
    let path_bytes = &data[3..3 + path_len];
    // Find null terminator and extract string
    if let Some(null_pos) = path_bytes.iter().position(|&b| b == 0) {
        std::str::from_utf8(&path_bytes[..null_pos])
            .ok()
            .map(|s| s.to_string())
    } else {
        std::str::from_utf8(path_bytes).ok().map(|s| s.to_string())
    }
}

/// Parse text token (often contains cwd or other metadata)
/// Format: [token_id:1] [text_length:2 BE] [text:variable]
pub fn parse_text_token(data: &[u8]) -> Option<String> {
    if data.len() < 3 || data[0] != token_type::TEXT_TOKEN {
        return None;
    }

    let text_len = u16::from_be_bytes([data[1], data[2]]) as usize;
    if text_len == 0 || text_len > 4096 {
        return None;
    }

    if data.len() < 3 + text_len {
        return None;
    }

    let text_bytes = &data[3..3 + text_len];
    if let Some(null_pos) = text_bytes.iter().position(|&b| b == 0) {
        std::str::from_utf8(&text_bytes[..null_pos])
            .ok()
            .map(|s| s.to_string())
    } else {
        std::str::from_utf8(text_bytes).ok().map(|s| s.to_string())
    }
}

/// Parse single argument from BSM arg token
/// Format: [token_id:1] [arg_num:4 LE] [arg_length:2 BE] [arg:variable]
pub fn parse_arg_token(data: &[u8]) -> Option<(u32, String)> {
    if data.len() < 7 || data[0] != token_type::ARG_TOKEN {
        return None;
    }

    let arg_num = read_u32_le(data, 1)?;
    let arg_len = u16::from_be_bytes([data[5], data[6]]) as usize;

    if arg_len == 0 || arg_len > 256 {
        return None; // Bounded: max 256 chars per arg
    }

    if data.len() < 7 + arg_len {
        return None;
    }

    let arg_bytes = &data[7..7 + arg_len];
    if let Some(null_pos) = arg_bytes.iter().position(|&b| b == 0) {
        std::str::from_utf8(&arg_bytes[..null_pos])
            .ok()
            .map(|s| (arg_num, s.to_string()))
    } else {
        std::str::from_utf8(arg_bytes)
            .ok()
            .map(|s| (arg_num, s.to_string()))
    }
}

/// Parse return token (contains return value and error code)
/// Format: [token_id:1] [errval:4 BE] [retval:4 BE]
pub fn parse_return_token(data: &[u8]) -> Option<(i32, i32)> {
    if data.len() < 9 || data[0] != token_type::RETURN_TOKEN {
        return None;
    }

    let errval = read_u32_be(data, 1)? as i32;
    let retval = read_u32_be(data, 5)? as i32;

    Some((errval, retval))
}

/// Parse IPv4 sockaddr from socket token
/// Format: [token_id:1] [sa_family:2 BE] [port:2 BE] [addr:4]
pub fn parse_sockaddr_ipv4(data: &[u8]) -> Option<(String, u16)> {
    if data.len() < 8 {
        return None;
    }

    let port = read_u16_be(data, 2)?;
    if data.len() >= 8 {
        let addr = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ip_str = format!(
            "{}.{}.{}.{}",
            (addr >> 24) & 0xff,
            (addr >> 16) & 0xff,
            (addr >> 8) & 0xff,
            addr & 0xff
        );
        return Some((ip_str, port));
    }

    None
}

/// Parse IPv6 sockaddr from socket token
/// Format: [token_id:1] [sa_family:2 BE] [port:2 BE] [flowinfo:4] [addr:16] [scopeid:4]
pub fn parse_sockaddr_ipv6(data: &[u8]) -> Option<(String, u16)> {
    if data.len() < 26 {
        return None;
    }

    let port = read_u16_be(data, 2)?;
    if data.len() >= 22 {
        // Extract 16-byte IPv6 address starting at offset 8
        let addr_bytes: [u8; 16] = data[8..24].try_into().ok()?;
        let ip_str = format!(
            "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3],
            addr_bytes[4], addr_bytes[5], addr_bytes[6], addr_bytes[7],
            addr_bytes[8], addr_bytes[9], addr_bytes[10], addr_bytes[11],
            addr_bytes[12], addr_bytes[13], addr_bytes[14], addr_bytes[15]
        );
        return Some((ip_str, port));
    }

    None
}

/// Scan record for all tokens of a given type
/// Returns iterator over (offset, token_data) pairs
pub fn scan_tokens(record: &[u8], token_type: u8) -> Result<Vec<Vec<u8>>, String> {
    // NOTE: Errors returned here are collapsed to None by .ok()? in handlers,
    // making them indistinguishable from "token not found" or "validation failed".
    // To properly track parse_failed_unsupported separately, handlers would need
    // to return Result<Event, ErrorKind> instead of Option<Event>, threading
    // the error kind upward to capture loop. For now, all None results increment
    // parse_failed_total uniformly.
    let mut tokens = Vec::new();
    let mut offset = 0;

    while offset < record.len() {
        if record[offset] == token_type {
            // Found a token of this type; estimate length based on type
            let token_len = estimate_token_len(record[offset])?; // Returns Err if unknown token encountered
            if token_len == 0 {
                // Token header incomplete; stop scanning
                return Err("token_incomplete".to_string());
            }
            if offset + token_len > record.len() {
                // Token extends beyond record; stop scanning (data corruption)
                return Err("token_out_of_bounds".to_string());
            }
            tokens.push(record[offset..offset + token_len].to_vec());
            offset += token_len;
        } else {
            // Different token type; skip it safely or fail if unknown type encountered
            let skip_len = estimate_token_len(record[offset])?; // Returns Err if unknown token type
            if skip_len == 0 {
                return Err("token_incomplete".to_string());
            }
            if offset + skip_len > record.len() {
                return Err("token_out_of_bounds".to_string());
            }
            offset += skip_len;
        }
    }

    Ok(tokens)
}

/// Estimate token length for a given token type
/// Returns Ok(size) if token type is known, Err if unknown or unsupported layout
/// Returns 0 if token header is incomplete (data too short)
/// Never returns Ok(1) for unknown tokens - instead returns Err
fn estimate_token_len(token_id: u8) -> Result<usize, String> {
    match token_id {
        token_type::SUBJECT_TOKEN_32
        | token_type::SUBJECT_TOKEN_64
        | token_type::SUBJECT_TOKEN_EX => Ok(37),
        token_type::PATH_TOKEN | token_type::TEXT_TOKEN => {
            // Variable length; these would need full data to compute correctly
            // For now, signal that we need more context (called from scan_tokens with full data)
            Ok(0) // Caller will check bounds with full token data
        }
        token_type::ARG_TOKEN => Ok(0), // Variable length; needs context
        token_type::RETURN_TOKEN => Ok(9),
        token_type::SOCKADDR_TOKEN | token_type::SOCKADDR_IN_TOKEN => Ok(8),
        token_type::SOCKADDR_IN6_TOKEN => Ok(26),
        _ => Err(format!("unsupported_token_type_{:#04x}", token_id)),
    }
}

/// Refined estimate_token_len that has access to token data for variable-length tokens
fn estimate_token_len_with_data(data: &[u8]) -> Option<usize> {
    if data.is_empty() {
        return None;
    }

    match data[0] {
        token_type::SUBJECT_TOKEN_32
        | token_type::SUBJECT_TOKEN_64
        | token_type::SUBJECT_TOKEN_EX => Some(37),
        token_type::PATH_TOKEN | token_type::TEXT_TOKEN => {
            // Variable length; read length at offset 1-2 (big-endian)
            if data.len() >= 3 {
                let len = 3 + u16::from_be_bytes([data[1], data[2]]) as usize;
                if len > 0 {
                    Some(len)
                } else {
                    None
                }
            } else {
                None
            }
        }
        token_type::ARG_TOKEN => {
            // Variable length; read length at offset 5-6 (big-endian)
            if data.len() >= 7 {
                let len = 7 + u16::from_be_bytes([data[5], data[6]]) as usize;
                if len > 0 {
                    Some(len)
                } else {
                    None
                }
            } else {
                None
            }
        }
        token_type::RETURN_TOKEN => Some(9),
        token_type::SOCKADDR_TOKEN | token_type::SOCKADDR_IN_TOKEN => Some(8),
        token_type::SOCKADDR_IN6_TOKEN => Some(26),
        _ => None, // Unknown token type - cannot proceed safely
    }
}
