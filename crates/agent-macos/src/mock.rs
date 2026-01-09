/// JSONL reader for Event fixtures
/// Tolerant parsing: skip malformed lines, continue reading
use edr_core::Event;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Load Event JSONL fixture file
/// Skips unparseable lines, returns count of successful reads
pub fn load_events_jsonl<P: AsRef<Path>>(path: P) -> Result<(Vec<Event>, usize), String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    let reader = BufReader::new(file);

    let mut events = Vec::new();
    let mut skipped = 0;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match serde_json::from_str::<Event>(trimmed) {
            Ok(evt) => events.push(evt),
            Err(_) => {
                skipped += 1;
            }
        }
    }

    Ok((events, skipped))
}
