use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

/// Appends a structured audit event entry directly to the persistent security ledger file.
pub fn log_event(event: &str) {
    // Retrieve the current UNIX timestamp
    let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    };

    // Format the log line cleanly
    let log_line = format!("[UNIX: {}] {}\n", timestamp, event);

    // Attempt to open the audit log file in append mode (create if it doesn't exist)
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("ironvault_audit.log")
    {
        // Write the log line to persistent storage
        let _ = file.write_all(log_line.as_bytes());
    }
}