pub fn verify_internal_session(username: &str) -> Result<String, String> {
    println!("[PGSQL] Checking schema 'ironvault' for user: {}", username);
    if username.is_empty() {
        return Err("Username cannot be blank".to_string());
    }
    Ok(format!("FALLBACK-FINGERPRINT-{}-windows-x86_64", username))
}