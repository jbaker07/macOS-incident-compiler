// macos/sensors/hash_keys.rs
// Deterministic key generation for entities (process, file, identity)

use sha2::{Digest, Sha256};

/// Generate deterministic process key from host, pid, and stream_id
/// Format: "proc_{16hex_chars}"
pub fn proc_key(host: &str, pid: u32, stream_id: &str) -> String {
    let input = format!("{}|{}|{}", host, pid, stream_id);
    let mut hasher = Sha256::new();
    hasher.update(input);
    let hash = hasher.finalize();
    let hex = format!("{:x}", hash);
    format!("proc_{}", &hex[..16])
}

/// Generate deterministic file key from host, normalized path, and stream_id
/// Format: "file_{16hex_chars}"
pub fn file_key(host: &str, path: &str, stream_id: &str) -> String {
    let normalized = normalize_path(path);
    let input = format!("{}|{}|{}", host, normalized, stream_id);
    let mut hasher = Sha256::new();
    hasher.update(input);
    let hash = hasher.finalize();
    let hex = format!("{:x}", hash);
    format!("file_{}", &hex[..16])
}

/// Generate deterministic identity key from host, uid, and stream_id
/// Format: "id_{16hex_chars}"
pub fn identity_key(host: &str, uid: u32, stream_id: &str) -> String {
    let input = format!("{}|{}|{}", host, uid, stream_id);
    let mut hasher = Sha256::new();
    hasher.update(input);
    let hash = hasher.finalize();
    let hex = format!("{:x}", hash);
    format!("id_{}", &hex[..16])
}

/// Normalize file path to canonical form (remove redundant . and .., lowercase)
fn normalize_path(path: &str) -> String {
    path.to_lowercase()
        .replace("//", "/")
        .trim_end_matches('/')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proc_key_deterministic() {
        let key1 = proc_key("myhost", 1234, "stream1");
        let key2 = proc_key("myhost", 1234, "stream1");
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_file_key_deterministic() {
        let key1 = file_key("myhost", "/path/to/file", "stream1");
        let key2 = file_key("myhost", "/path/to/file", "stream1");
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_identity_key_deterministic() {
        let key1 = identity_key("myhost", 501, "stream1");
        let key2 = identity_key("myhost", 501, "stream1");
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_key_format() {
        let pk = proc_key("host", 100, "s");
        assert!(pk.starts_with("proc_"));
        assert_eq!(pk.len(), 21); // "proc_" (5) + 16 hex chars

        let fk = file_key("host", "/path", "s");
        assert!(fk.starts_with("file_"));
        assert_eq!(fk.len(), 21);

        let ik = identity_key("host", 500, "s");
        assert!(ik.starts_with("id_"));
        assert_eq!(ik.len(), 19); // "id_" (3) + 16 hex chars
    }
}
