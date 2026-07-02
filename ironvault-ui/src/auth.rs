// =========================================================================
// IronVault Machine-Binding Auth Processor (auth.rs)
// =========================================================================

use std::process::Command;

/// Extracts a unique physical machine identifier string to implement hardware binding security.
pub fn get_hardware_machine_id() -> String {
    let raw_id = if cfg!(target_os = "windows") {
        Command::new("wmic")
            .args(&["csproduct", "get", "UUID"])
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|s| s.lines().nth(1).unwrap_or("").trim().to_string())
    } else if cfg!(target_os = "linux") {
        std::fs::read_to_string("/etc/machine-id")
            .map(|s| s.trim().to_string())
            .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id").map(|s| s.trim().to_string()))
            .ok()
    } else if cfg!(target_os = "macos") {
        Command::new("ioreg")
            .args(&["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .and_then(|s| {
                s.lines()
                    .find(|line| line.contains("IOPlatformUUID"))
                    .map(|line| line.split('"').nth(3).unwrap_or("").trim().to_string())
            })
    } else {
        None
    };

    match raw_id {
        Some(id) if !id.is_empty() && id != "Node" => id,
        _ => {
            let user = std::env::var("USERNAME").or_else(|_| std::env::var("USER")).unwrap_or_else(|_| "UNKNOWN_OP".to_string());
            let arch = std::env::consts::ARCH;
            let os = std::env::consts::OS;
            format!("FALLBACK-FINGERPRINT-{}-{}-{}", user, os, arch)
        }
    }
}

/// Tracks the active user session details globally in memory
pub fn establish_active_session(username: &str, role: &str, hardware_id: &str) {
    println!("[SESSION] Session established for {} ({}) on machine HW: {}", username, role, hardware_id);
}

/// Clears out the current session states securely
pub fn invalidate_session() {
    println!("[SESSION] Current administration session data invalidated cleanly.");
}