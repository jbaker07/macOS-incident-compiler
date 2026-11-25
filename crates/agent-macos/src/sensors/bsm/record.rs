//! BSM record framing and token parsing.
//!
//! A BSM audit record is a header token, a run of tokens that describe the
//! event, and a trailer token. Every multi byte integer is big endian. The
//! token ids and layouts below come from the macOS SDK header
//! `<bsm/audit_record.h>` and from the token writers in OpenBSM's
//! `bsm_token.c`, which is the code both libbsm and the XNU kernel use.
//!
//! The kernel writes the tokens for one system call in this order:
//!
//! ```text
//! header | event specific tokens (args, paths, attributes, sockets) | subject | return | trailer
//! ```
//!
//! `parse_record` walks every token it knows the length of. If it meets a
//! token it does not know, it cannot find the start of the next token, so it
//! stops and then tries to recover the subject and return tokens from their
//! fixed positions just before the trailer.

use std::fmt;

/// Token ids from `<bsm/audit_record.h>`.
pub mod token_id {
    pub const OTHER_FILE32: u8 = 0x11;
    pub const TRAILER: u8 = 0x13;
    pub const HEADER32: u8 = 0x14;
    pub const HEADER32_EX: u8 = 0x15;
    pub const DATA: u8 = 0x21;
    pub const IPC: u8 = 0x22;
    pub const PATH: u8 = 0x23;
    pub const SUBJECT32: u8 = 0x24;
    pub const PROCESS32: u8 = 0x26;
    pub const RETURN32: u8 = 0x27;
    pub const TEXT: u8 = 0x28;
    pub const OPAQUE: u8 = 0x29;
    pub const IN_ADDR: u8 = 0x2a;
    pub const IP: u8 = 0x2b;
    pub const IPORT: u8 = 0x2c;
    pub const ARG32: u8 = 0x2d;
    pub const SOCKET: u8 = 0x2e;
    pub const SEQ: u8 = 0x2f;
    pub const ATTR: u8 = 0x31;
    pub const IPC_PERM: u8 = 0x32;
    pub const GROUPS: u8 = 0x34;
    pub const NEWGROUPS: u8 = 0x3b;
    pub const EXEC_ARGS: u8 = 0x3c;
    pub const EXEC_ENV: u8 = 0x3d;
    pub const ATTR32: u8 = 0x3e;
    pub const EXIT: u8 = 0x52;
    pub const ZONENAME: u8 = 0x60;
    pub const HOST: u8 = 0x70;
    pub const ARG64: u8 = 0x71;
    pub const RETURN64: u8 = 0x72;
    pub const ATTR64: u8 = 0x73;
    pub const HEADER64: u8 = 0x74;
    pub const SUBJECT64: u8 = 0x75;
    pub const PROCESS64: u8 = 0x77;
    pub const HEADER64_EX: u8 = 0x79;
    pub const SUBJECT32_EX: u8 = 0x7a;
    pub const PROCESS32_EX: u8 = 0x7b;
    pub const SUBJECT64_EX: u8 = 0x7c;
    pub const PROCESS64_EX: u8 = 0x7d;
    pub const IN_ADDR_EX: u8 = 0x7e;
    pub const SOCKET_EX: u8 = 0x7f;
    pub const SOCKINET32: u8 = 0x80;
    pub const SOCKINET128: u8 = 0x81;
    pub const SOCKUNIX: u8 = 0x82;
    pub const IDENTITY: u8 = 0xed;
    pub const KRB5_PRINCIPAL: u8 = 0xee;
    pub const CERT_HASH: u8 = 0xef;
}

/// Magic number in every trailer token.
pub const TRAILER_MAGIC: u16 = 0xb105;

/// Audit id the kernel uses for processes that never logged in.
pub const AU_DEFAUDITID: u32 = 0xffff_ffff;

/// Largest record we accept. The kernel limit (MAXAUDITDATA) is 32 KB.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    NotAHeader(u8),
    BadLength(usize),
    Truncated { token: u8, offset: usize },
    BadTrailer,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::TooShort => write!(f, "record shorter than a header"),
            ParseError::NotAHeader(id) => write!(f, "record starts with token {:#04x}, not a header", id),
            ParseError::BadLength(len) => write!(f, "header byte count {} is not plausible", len),
            ParseError::Truncated { token, offset } => {
                write!(f, "token {:#04x} at offset {} runs past the record", token, offset)
            }
            ParseError::BadTrailer => write!(f, "trailer missing or does not match the header"),
        }
    }
}

impl std::error::Error for ParseError {}

/// The process that made the call (subject token) or the process it acted on
/// (process token). Field names follow the BSM token layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    /// Audit user id. Set at login and kept across sudo and su.
    pub auid: u32,
    pub euid: u32,
    pub egid: u32,
    pub ruid: u32,
    pub rgid: u32,
    pub pid: u32,
    /// Audit session id. Every process started from one login shares it.
    pub asid: u32,
    /// Terminal address as text, for example 0.0.0.0 or 2001:db8::1
    pub terminal_addr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arg {
    pub number: u8,
    pub value: u64,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attr {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub fsid: u32,
    pub node_id: u64,
    pub device: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SockAddr {
    /// "inet", "inet6" or "unix"
    pub family: &'static str,
    pub port: u16,
    pub address: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub signer_type: u32,
    pub signing_id: String,
    pub team_id: String,
    pub cdhash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnInfo {
    /// BSM error number. 0 means the call succeeded.
    pub error: u8,
    pub value: u64,
}

/// One decoded audit record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BsmRecord {
    pub event: u16,
    pub modifier: u16,
    pub version: u8,
    /// Record time in milliseconds since the Unix epoch
    pub ts_ms: u64,
    pub subject: Option<Subject>,
    pub process: Option<Subject>,
    pub paths: Vec<String>,
    pub texts: Vec<String>,
    pub args: Vec<Arg>,
    pub exec_args: Vec<String>,
    pub exec_env: Vec<String>,
    pub attrs: Vec<Attr>,
    pub sockets: Vec<SockAddr>,
    pub identity: Option<Identity>,
    pub ret: Option<ReturnInfo>,
    /// Set when the walk stopped on a token id this parser does not know.
    pub unknown_token: Option<u8>,
    /// Total bytes in the record, from the header
    pub byte_count: usize,
}

impl BsmRecord {
    pub fn success(&self) -> bool {
        self.ret.as_ref().map(|r| r.error == 0).unwrap_or(true)
    }

    pub fn arg_named(&self, name: &str) -> Option<&Arg> {
        self.args.iter().find(|a| a.name == name)
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pid {} auid {} euid {} asid {}", self.pid, self.auid, self.euid, self.asid)
    }
}

// Small big endian readers that fail cleanly at the end of the buffer.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    token: u8,
    token_start: usize,
}

impl<'a> Reader<'a> {
    fn truncated(&self) -> ParseError {
        ParseError::Truncated {
            token: self.token,
            offset: self.token_start,
        }
    }

    fn bytes(&mut self, count: usize) -> Result<&'a [u8], ParseError> {
        if self.pos + count > self.data.len() {
            return Err(self.truncated());
        }
        let slice = &self.data[self.pos..self.pos + count];
        self.pos += count;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, ParseError> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ParseError> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, ParseError> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, ParseError> {
        let b = self.bytes(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    /// A string stored as a 2 byte length then that many bytes, NUL included.
    fn counted_string(&mut self) -> Result<String, ParseError> {
        let len = self.u16()? as usize;
        let raw = self.bytes(len)?;
        Ok(c_string(raw))
    }

    /// One NUL terminated string, as used inside exec argument tokens.
    fn nul_string(&mut self) -> Result<String, ParseError> {
        let rest = &self.data[self.pos..];
        match rest.iter().position(|b| *b == 0) {
            Some(end) => {
                let text = String::from_utf8_lossy(&rest[..end]).into_owned();
                self.pos += end + 1;
                Ok(text)
            }
            None => Err(self.truncated()),
        }
    }

    /// Address that follows a 4 byte type field (AU_IPv4 = 4, AU_IPv6 = 16).
    fn typed_address(&mut self) -> Result<String, ParseError> {
        let addr_type = self.u32()?;
        if addr_type == 16 {
            Ok(ipv6_text(self.bytes(16)?))
        } else if addr_type == 4 {
            Ok(ipv4_text(self.bytes(4)?))
        } else {
            Err(self.truncated())
        }
    }
}

fn c_string(raw: &[u8]) -> String {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

fn ipv4_text(b: &[u8]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn ipv6_text(b: &[u8]) -> String {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&b[..16]);
    std::net::Ipv6Addr::from(octets).to_string()
}

/// Read the size of a record from its header without parsing the rest.
/// Returns None when `data` does not start with a header token or is too
/// short to hold the byte count.
pub fn record_length(data: &[u8]) -> Option<usize> {
    if data.len() < 5 {
        return None;
    }
    match data[0] {
        token_id::HEADER32 | token_id::HEADER32_EX | token_id::HEADER64 | token_id::HEADER64_EX => {
            Some(u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize)
        }
        _ => None,
    }
}

/// Parse one complete record (header through trailer).
pub fn parse_record(data: &[u8]) -> Result<BsmRecord, ParseError> {
    if data.len() < 18 {
        return Err(ParseError::TooShort);
    }
    let header = data[0];
    let byte_count = match record_length(data) {
        Some(n) => n,
        None => return Err(ParseError::NotAHeader(header)),
    };
    if byte_count < 18 + 7 || byte_count > MAX_RECORD_BYTES || byte_count > data.len() {
        return Err(ParseError::BadLength(byte_count));
    }
    let data = &data[..byte_count];

    // The trailer is the last 7 bytes: id, magic, byte count.
    let trailer = &data[byte_count - 7..];
    let trailer_count = u32::from_be_bytes([trailer[3], trailer[4], trailer[5], trailer[6]]) as usize;
    if trailer[0] != token_id::TRAILER
        || u16::from_be_bytes([trailer[1], trailer[2]]) != TRAILER_MAGIC
        || trailer_count != byte_count
    {
        return Err(ParseError::BadTrailer);
    }

    let mut record = BsmRecord {
        byte_count,
        ..Default::default()
    };
    let mut r = Reader {
        data,
        pos: 1,
        token: header,
        token_start: 0,
    };

    // Header layouts:
    //   header32:    id, count(4), version(1), event(2), modifier(2), seconds(4), msec(4)
    //   header32_ex: same, with address type(4) and address(4 or 16) before the time
    //   header64:    id, count(4), version(1), event(2), modifier(2), seconds(8), msec(8)
    //   header64_ex: 64 bit time with the extended address
    let _count = r.u32()?;
    record.version = r.u8()?;
    record.event = r.u16()?;
    record.modifier = r.u16()?;
    if header == token_id::HEADER32_EX || header == token_id::HEADER64_EX {
        let _host = r.typed_address()?;
    }
    let (seconds, millis) = if header == token_id::HEADER64 || header == token_id::HEADER64_EX {
        (r.u64()?, r.u64()?)
    } else {
        (r.u32()? as u64, r.u32()? as u64)
    };
    record.ts_ms = seconds * 1000 + millis;

    let body_end = byte_count - 7;
    while r.pos < body_end {
        r.token_start = r.pos;
        r.token = r.u8()?;
        if !parse_token(&mut r, &mut record)? {
            record.unknown_token = Some(r.token);
            recover_tail(&data[..body_end], &mut record);
            break;
        }
        if r.pos > body_end {
            return Err(ParseError::Truncated {
                token: r.token,
                offset: r.token_start,
            });
        }
    }

    Ok(record)
}

/// Parse one token body. Returns Ok(false) if the token id is unknown.
fn parse_token(r: &mut Reader, record: &mut BsmRecord) -> Result<bool, ParseError> {
    use token_id::*;
    match r.token {
        SUBJECT32 | PROCESS32 | SUBJECT64 | PROCESS64 | SUBJECT32_EX | PROCESS32_EX | SUBJECT64_EX
        | PROCESS64_EX => {
            let subject = parse_subject(r)?;
            let is_process = matches!(r.token, PROCESS32 | PROCESS64 | PROCESS32_EX | PROCESS64_EX);
            if is_process {
                record.process = Some(subject);
            } else {
                record.subject = Some(subject);
            }
        }
        RETURN32 => {
            let error = r.u8()?;
            let value = r.u32()? as u64;
            record.ret = Some(ReturnInfo { error, value });
        }
        RETURN64 => {
            let error = r.u8()?;
            let value = r.u64()?;
            record.ret = Some(ReturnInfo { error, value });
        }
        PATH => record.paths.push(r.counted_string()?),
        TEXT => record.texts.push(r.counted_string()?),
        ZONENAME => {
            let _ = r.counted_string()?;
        }
        ARG32 | ARG64 => {
            let number = r.u8()?;
            let value = if r.token == ARG32 { r.u32()? as u64 } else { r.u64()? };
            let name = r.counted_string()?;
            record.args.push(Arg { number, value, name });
        }
        EXEC_ARGS | EXEC_ENV | CERT_HASH | KRB5_PRINCIPAL => {
            let count = r.u32()? as usize;
            if count > 4096 {
                return Err(r.truncated());
            }
            let mut strings = Vec::with_capacity(count);
            for _ in 0..count {
                strings.push(r.nul_string()?);
            }
            if r.token == EXEC_ARGS {
                record.exec_args = strings;
            } else if r.token == EXEC_ENV {
                record.exec_env = strings;
            }
        }
        ATTR | ATTR32 => {
            let mode = r.u32()?;
            let uid = r.u32()?;
            let gid = r.u32()?;
            let fsid = r.u32()?;
            let node_id = r.u64()?;
            let device = r.u32()? as u64;
            record.attrs.push(Attr { mode, uid, gid, fsid, node_id, device });
        }
        ATTR64 => {
            let mode = r.u32()?;
            let uid = r.u32()?;
            let gid = r.u32()?;
            let fsid = r.u32()?;
            let node_id = r.u64()?;
            let device = r.u64()?;
            record.attrs.push(Attr { mode, uid, gid, fsid, node_id, device });
        }
        SOCKINET32 => {
            let _family = r.u16()?;
            // sockinet32 copies the port bytes straight from the sockaddr,
            // so they are already in network order.
            let port = r.u16()?;
            let address = ipv4_text(r.bytes(4)?);
            record.sockets.push(SockAddr { family: "inet", port, address });
        }
        SOCKINET128 => {
            let _family = r.u16()?;
            // OpenBSM's au_to_sock_inet128 passes sin6_port, which is already
            // in network order, through ADD_U_INT16, which converts it again.
            // On a little endian Mac the two port bytes land swapped. The
            // fixture generator in tools/bsm-fixtures shows this with
            // Apple's libbsm, and praudit prints the swapped value. Swap back.
            let port = r.u16()?.swap_bytes();
            let address = ipv6_text(r.bytes(16)?);
            record.sockets.push(SockAddr { family: "inet6", port, address });
        }
        SOCKUNIX => {
            let _family = r.u16()?;
            // The path is NUL terminated. libbsm reads up to the NUL, or 105
            // bytes if there is no NUL in the first 104.
            let rest = &r.data[r.pos..];
            let limit = rest.len().min(104);
            let take = match rest[..limit].iter().position(|b| *b == 0) {
                Some(end) => end + 1,
                None => 105,
            };
            let raw = r.bytes(take)?;
            let address = c_string(raw);
            record.sockets.push(SockAddr { family: "unix", port: 0, address });
        }
        SOCKET => {
            // type(2), local port(2), local addr(4), remote port(2), remote addr(4)
            let _socket_type = r.u16()?;
            let _local_port = r.u16()?;
            let _local = r.bytes(4)?;
            let port = r.u16()?;
            let address = ipv4_text(r.bytes(4)?);
            record.sockets.push(SockAddr { family: "inet", port, address });
        }
        SOCKET_EX => {
            // domain(2), type(2), address size(2), local port, local addr,
            // remote port, remote addr
            let _domain = r.u16()?;
            let _socket_type = r.u16()?;
            let size = r.u16()? as usize;
            if size != 4 && size != 16 {
                return Err(r.truncated());
            }
            let _local_port = r.u16()?;
            let _local = r.bytes(size)?;
            let port = r.u16()?;
            let raw = r.bytes(size)?;
            let (family, address) = if size == 16 {
                ("inet6", ipv6_text(raw))
            } else {
                ("inet", ipv4_text(raw))
            };
            record.sockets.push(SockAddr { family, port, address });
        }
        IDENTITY => {
            let signer_type = r.u32()?;
            let signing_id = r.counted_string()?;
            let _signing_id_truncated = r.u8()?;
            let team_id = r.counted_string()?;
            let _team_id_truncated = r.u8()?;
            let hash_len = r.u16()? as usize;
            let hash = r.bytes(hash_len)?;
            let mut cdhash = String::with_capacity(hash_len * 2);
            for b in hash {
                cdhash.push_str(&format!("{:02x}", b));
            }
            record.identity = Some(Identity { signer_type, signing_id, team_id, cdhash });
        }
        IN_ADDR => {
            r.bytes(4)?;
        }
        IN_ADDR_EX => {
            let _ = r.typed_address()?;
        }
        IPORT => {
            r.bytes(2)?;
        }
        SEQ | HOST => {
            r.bytes(4)?;
        }
        EXIT => {
            r.bytes(8)?;
        }
        IPC => {
            r.bytes(5)?;
        }
        IPC_PERM => {
            r.bytes(28)?;
        }
        IP => {
            r.bytes(20)?;
        }
        GROUPS | NEWGROUPS => {
            let count = r.u16()? as usize;
            r.bytes(count * 4)?;
        }
        OPAQUE => {
            let len = r.u16()? as usize;
            r.bytes(len)?;
        }
        OTHER_FILE32 => {
            r.bytes(8)?;
            let _ = r.counted_string()?;
        }
        DATA => {
            let _how_to_print = r.u8()?;
            let unit = r.u8()?;
            let count = r.u8()? as usize;
            let unit_size = match unit {
                0 => 1,
                1 => 2,
                2 => 4,
                3 => 8,
                _ => return Err(r.truncated()),
            };
            r.bytes(unit_size * count)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// Subject and process tokens share layouts:
///   32:     auid, euid, egid, ruid, rgid, pid, sid (4 bytes each), port(4), addr(4)
///   64:     same, then port(8), addr(4)
///   32_ex:  same, then port(4), addr type(4), addr(4 or 16)
///   64_ex:  same, then port(8), addr type(4), addr(4 or 16)
fn parse_subject(r: &mut Reader) -> Result<Subject, ParseError> {
    use token_id::*;
    let auid = r.u32()?;
    let euid = r.u32()?;
    let egid = r.u32()?;
    let ruid = r.u32()?;
    let rgid = r.u32()?;
    let pid = r.u32()?;
    let asid = r.u32()?;
    let terminal_addr = match r.token {
        SUBJECT32 | PROCESS32 => {
            r.u32()?;
            ipv4_text(r.bytes(4)?)
        }
        SUBJECT64 | PROCESS64 => {
            r.u64()?;
            ipv4_text(r.bytes(4)?)
        }
        SUBJECT32_EX | PROCESS32_EX => {
            r.u32()?;
            r.typed_address()?
        }
        _ => {
            r.u64()?;
            r.typed_address()?
        }
    };
    Ok(Subject {
        auid,
        euid,
        egid,
        ruid,
        rgid,
        pid,
        asid,
        terminal_addr,
    })
}

/// When the walk stops early, the subject and return tokens can still be
/// found because they sit at fixed sizes right before the trailer.
fn recover_tail(body: &[u8], record: &mut BsmRecord) {
    use token_id::*;
    let return_sizes: [(u8, usize); 2] = [(RETURN32, 6), (RETURN64, 10)];
    let subject_sizes: [(u8, usize); 4] = [(SUBJECT32, 37), (SUBJECT64, 41), (SUBJECT32_EX, 41), (SUBJECT64_EX, 45)];
    for (ret_id, ret_len) in return_sizes.iter() {
        if body.len() < *ret_len {
            continue;
        }
        let ret_start = body.len() - ret_len;
        if body[ret_start] != *ret_id {
            continue;
        }
        for (subj_id, subj_len) in subject_sizes.iter() {
            if ret_start < *subj_len {
                continue;
            }
            let subj_start = ret_start - subj_len;
            if body[subj_start] != *subj_id {
                continue;
            }
            let mut r = Reader {
                data: &body[..ret_start],
                pos: subj_start + 1,
                token: *subj_id,
                token_start: subj_start,
            };
            if let Ok(subject) = parse_subject(&mut r) {
                if record.subject.is_none() {
                    record.subject = Some(subject);
                }
                let mut rr = Reader {
                    data: body,
                    pos: ret_start + 1,
                    token: *ret_id,
                    token_start: ret_start,
                };
                let error = rr.u8().unwrap_or(0);
                let value = if *ret_id == RETURN32 {
                    rr.u32().map(|v| v as u64).unwrap_or(0)
                } else {
                    rr.u64().unwrap_or(0)
                };
                if record.ret.is_none() {
                    record.ret = Some(ReturnInfo { error, value });
                }
                return;
            }
        }
    }
}

/// Splits a byte stream into whole records.
///
/// /dev/auditpipe returns one whole record per read, but a trail file from
/// auditd is just records back to back, with a bare file token at the start
/// and end of the file. This handles both.
#[derive(Default)]
pub struct RecordSplitter {
    buffer: Vec<u8>,
    /// Bytes thrown away while looking for the next header
    pub skipped_bytes: u64,
}

impl RecordSplitter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Next complete record, if one is buffered.
    pub fn next_record(&mut self) -> Option<Vec<u8>> {
        loop {
            if self.buffer.is_empty() {
                return None;
            }
            // auditd writes a file token (id, seconds, msec, name) when it
            // opens and closes a trail. Skip it.
            if self.buffer[0] == token_id::OTHER_FILE32 {
                if self.buffer.len() < 11 {
                    return None;
                }
                let name_len = u16::from_be_bytes([self.buffer[9], self.buffer[10]]) as usize;
                if self.buffer.len() < 11 + name_len {
                    return None;
                }
                self.buffer.drain(..11 + name_len);
                continue;
            }
            match record_length(&self.buffer) {
                Some(len) if (25..=MAX_RECORD_BYTES).contains(&len) => {
                    if self.buffer.len() < len {
                        return None;
                    }
                    // A real record ends in a trailer with the magic number.
                    // If it does not, this was a stray header byte.
                    let t = &self.buffer[len - 7..len];
                    if t[0] == token_id::TRAILER && u16::from_be_bytes([t[1], t[2]]) == TRAILER_MAGIC {
                        let record: Vec<u8> = self.buffer.drain(..len).collect();
                        return Some(record);
                    }
                    self.buffer.drain(..1);
                    self.skipped_bytes += 1;
                }
                Some(_) | None => {
                    if self.buffer.len() < 5 && record_length(&self.buffer).is_none() && is_header_id(self.buffer[0]) {
                        return None;
                    }
                    // Not at a record boundary. Drop one byte and look again.
                    self.buffer.drain(..1);
                    self.skipped_bytes += 1;
                }
            }
        }
    }
}

fn is_header_id(id: u8) -> bool {
    matches!(
        id,
        token_id::HEADER32 | token_id::HEADER32_EX | token_id::HEADER64 | token_id::HEADER64_EX
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a header32 record around a body, the way the kernel frames it.
    pub(crate) fn frame32(event: u16, seconds: u32, msec: u32, body: &[u8]) -> Vec<u8> {
        let total = 18 + body.len() + 7;
        let mut out = vec![token_id::HEADER32];
        out.extend_from_slice(&(total as u32).to_be_bytes());
        out.push(11);
        out.extend_from_slice(&event.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&seconds.to_be_bytes());
        out.extend_from_slice(&msec.to_be_bytes());
        out.extend_from_slice(body);
        out.push(token_id::TRAILER);
        out.extend_from_slice(&TRAILER_MAGIC.to_be_bytes());
        out.extend_from_slice(&(total as u32).to_be_bytes());
        out
    }

    fn subject32(auid: u32, euid: u32, pid: u32, asid: u32) -> Vec<u8> {
        let mut t = vec![token_id::SUBJECT32];
        for v in [auid, euid, 20, 501, 20, pid, asid, 0x0300_0002] {
            t.extend_from_slice(&v.to_be_bytes());
        }
        t.extend_from_slice(&[0, 0, 0, 0]);
        t
    }

    fn path(p: &str) -> Vec<u8> {
        let mut t = vec![token_id::PATH];
        t.extend_from_slice(&((p.len() + 1) as u16).to_be_bytes());
        t.extend_from_slice(p.as_bytes());
        t.push(0);
        t
    }

    fn return32(error: u8, value: u32) -> Vec<u8> {
        let mut t = vec![token_id::RETURN32, error];
        t.extend_from_slice(&value.to_be_bytes());
        t
    }

    #[test]
    fn parses_hand_built_execve() {
        let mut body = vec![token_id::EXEC_ARGS];
        body.extend_from_slice(&2u32.to_be_bytes());
        body.extend_from_slice(b"ls\0-la\0");
        body.extend_from_slice(&path("/bin/ls"));
        body.extend_from_slice(&subject32(501, 501, 4242, 100005));
        body.extend_from_slice(&return32(0, 0));
        let bytes = frame32(23, 1_795_446_000, 250, &body);

        let rec = parse_record(&bytes).expect("parse");
        assert_eq!(rec.event, 23);
        assert_eq!(rec.ts_ms, 1_795_446_000_250);
        assert_eq!(rec.exec_args, vec!["ls", "-la"]);
        assert_eq!(rec.paths, vec!["/bin/ls"]);
        let subject = rec.subject.clone().unwrap();
        assert_eq!(subject.pid, 4242);
        assert_eq!(subject.auid, 501);
        assert_eq!(subject.asid, 100005);
        assert!(rec.success());
        assert!(rec.unknown_token.is_none());
    }

    #[test]
    fn recovers_subject_after_unknown_token() {
        let mut body = vec![0x38, 1, 2, 3]; // AUT_PRIV, not parsed
        body.extend_from_slice(&subject32(501, 0, 77, 9));
        body.extend_from_slice(&return32(13, 0xffff_ffff));
        let bytes = frame32(200, 1, 0, &body);
        let rec = parse_record(&bytes).unwrap();
        assert_eq!(rec.unknown_token, Some(0x38));
        assert_eq!(rec.subject.as_ref().unwrap().pid, 77);
        assert_eq!(rec.ret.as_ref().unwrap().error, 13);
        assert!(!rec.success());
    }

    #[test]
    fn rejects_bad_trailer_and_truncation() {
        let mut body = path("/tmp/x");
        body.extend_from_slice(&subject32(501, 501, 1, 1));
        body.extend_from_slice(&return32(0, 0));
        let mut bytes = frame32(72, 1, 0, &body);
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        assert_eq!(parse_record(&bytes), Err(ParseError::BadTrailer));

        let mut short_path = vec![token_id::PATH, 0x01, 0x00]; // claims 256 bytes
        short_path.extend_from_slice(b"/tmp\0");
        let bytes = frame32(72, 1, 0, &short_path);
        assert!(matches!(parse_record(&bytes), Err(ParseError::Truncated { .. })));
    }

    #[test]
    fn splitter_skips_file_tokens_and_garbage() {
        let rec = frame32(23, 1, 0, &return32(0, 0));
        let mut stream = vec![token_id::OTHER_FILE32, 0, 0, 0, 1, 0, 0, 0, 0, 0, 3, b'a', b'b', 0];
        stream.extend_from_slice(&[0xaa, 0xbb]);
        stream.extend_from_slice(&rec);
        stream.extend_from_slice(&rec[..10]);

        let mut splitter = RecordSplitter::new();
        splitter.feed(&stream);
        assert_eq!(splitter.next_record(), Some(rec.clone()));
        assert_eq!(splitter.next_record(), None);
        splitter.feed(&rec[10..]);
        assert_eq!(splitter.next_record(), Some(rec));
        assert_eq!(splitter.skipped_bytes, 2);
    }
}
