// macos/sensors/es/es_client.rs
// Centralized ES event subscription and dispatch

use super::{
    file_create, file_metadata, file_open, file_rename, file_unlink, file_write, mounts, proc_exec,
    proc_lifecycle,
};
use edr_core::Event;

/// ES event client: subscribes to events and dispatches to primitive handlers
pub struct ESClient {
    /// Whether client is initialized
    pub enabled: bool,
}

impl ESClient {
    /// Create new ES client
    pub fn new() -> Self {
        ESClient { enabled: false }
    }

    /// Initialize ES subscriptions
    /// Returns true if successful, false if not available (macOS < 10.15, no perms, etc.)
    pub fn initialize(&mut self) -> bool {
        // TODO: Call EndpointSecurity framework
        // 1. es_new_client() with handler
        // 2. Subscribe to events: ES_EVENT_TYPE_EXEC, ES_EVENT_TYPE_OPEN, etc.
        // 3. Set up response mode (ALLOW by default, DENY for threats)
        // 4. Spawn background thread to drain event queue
        self.enabled = true;
        true
    }

    /// Dispatch ES event to appropriate primitive handler
    /// Returns canonical Event if one was generated
    pub fn handle_event(
        &self,
        host: String,
        stream_id: String,
        segment_id: String,
        record_index: usize,
        event_type: u32,
        event_data: Vec<u8>,
        ts_millis: u64,
    ) -> Option<Event> {
        dispatch_event(
            event_type,
            host,
            stream_id,
            segment_id,
            record_index,
            event_data,
            ts_millis,
        )
    }
}

/// Public dispatcher for ES events (for testing and direct use)
pub fn dispatch_event(
    event_type: u32,
    host: String,
    stream_id: String,
    segment_id: String,
    record_index: usize,
    event_data: Vec<u8>,
    ts_millis: u64,
) -> Option<Event> {
    // Match on ES_EVENT_TYPE_* and dispatch to handlers
    // Each handler returns Option<Event> with proper tagging

    match event_type {
        // Process events
        0 => proc_exec::handle_exec(
            host,
            stream_id,
            segment_id,
            record_index,
            event_data,
            ts_millis,
        ),
        1 => proc_lifecycle::handle_fork(
            host,
            stream_id,
            segment_id,
            record_index,
            event_data,
            ts_millis,
        ),
        2 => proc_lifecycle::handle_exit(
            host,
            stream_id,
            segment_id,
            record_index,
            event_data,
            ts_millis,
        ),

        // File events
        3 => file_open::handle_open(
            host,
            stream_id,
            segment_id,
            record_index,
            event_data,
            ts_millis,
        ),
        4 => file_write::handle_write(
            host,
            stream_id,
            segment_id,
            record_index,
            event_data,
            ts_millis,
        ),
        5 => {
            // ES_EVENT_TYPE_CLOSE - currently no handler (TODO if needed)
            None
        }
        6 => file_create::handle_create(
            host,
            stream_id,
            segment_id,
            record_index,
            event_data,
            ts_millis,
        ),
        7 => file_rename::handle_rename(
            host,
            stream_id,
            segment_id,
            record_index,
            event_data,
            ts_millis,
        ),
        8 => file_unlink::handle_unlink(
            host,
            stream_id,
            segment_id,
            record_index,
            event_data,
            ts_millis,
        ),
        9 => file_metadata::handle_metadata(
            host,
            stream_id,
            segment_id,
            record_index,
            event_data,
            ts_millis,
        ),

        // Mount events
        10 => mounts::handle_mount(
            host,
            stream_id,
            segment_id,
            record_index,
            event_data,
            ts_millis,
        ),
        11 => mounts::handle_unmount(
            host,
            stream_id,
            segment_id,
            record_index,
            event_data,
            ts_millis,
        ),

        _ => None,
    }
}
