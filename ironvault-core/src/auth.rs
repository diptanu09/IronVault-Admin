use crate::sdk_vmp;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Role {
    SuperAdmin,
    Admin,
    Operator,
    Viewer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub role: Role,
    pub last_login: String,
}
// Re-added to satisfy ironvault-core/src/lib.rs exports perfectly
pub struct AuthManager;

impl AuthManager {
    pub fn new() -> Self {
        Self
    }
}

pub struct UserSession {
    pub username: String,
    pub role: Role,
    pub last_login: String,
}

pub enum AuthDecision {
    GrantFullSession,
    RequireForcedPasswordReset,
    Deny,
}

pub fn classify_auth_outcome(
    normal_auth_result: &Result<(), ()>,
    temp_token_result: &Result<(), ()>,
) -> AuthDecision {
    sdk_vmp::vmp_begin_ultra("ClassifyAuthOutcome");

    let decision = if normal_auth_result.is_ok() {
        AuthDecision::GrantFullSession
    } else if temp_token_result.is_ok() {
        AuthDecision::RequireForcedPasswordReset
    } else {
        AuthDecision::Deny
    };

    sdk_vmp::vmp_end();
    decision
}

impl From<String> for Role {
    fn from(s: String) -> Self {
        match s.as_str() {
            "SuperAdmin" => Role::SuperAdmin,
            "Admin" => Role::Admin,
            "Operator" => Role::Operator,
            _ => Role::Viewer,
        }
    }
}

impl ToString for Role {
    fn to_string(&self) -> String {
        match self {
            Role::SuperAdmin => "SuperAdmin".to_string(),
            Role::Admin => "Admin".to_string(),
            Role::Operator => "Operator".to_string(),
            Role::Viewer => "Viewer".to_string(),
        }
    }
}

/// Tracks recent failed login attempts per (username, hwid) pair, entirely
/// in memory. Resets on app restart — acceptable for a single-instance
/// desktop admin tool; the goal is to slow down rapid automated retry
/// against the local bcrypt/token checks, not to build a distributed
/// rate-limiting service.

pub struct LoginRateLimiter {
    failures: Mutex<HashMap<String, (u32, Instant)>>,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self {
            failures: Mutex::new(HashMap::new()),
        }
    }

    fn key(username: &str, hwid: &str) -> String {
        format!("{}::{}", username.to_lowercase(), hwid)
    }

    /// Returns Some(remaining_lockout) if this pair is currently locked out,
    /// None if the attempt is allowed to proceed.
    pub fn check_locked(&self, username: &str, hwid: &str) -> Option<Duration> {
        let key = Self::key(username, hwid);
        let map = self.failures.lock().unwrap();
        if let Some((count, last_attempt)) = map.get(&key) {
            let lockout = Self::lockout_duration(*count);
            let elapsed = last_attempt.elapsed();
            if elapsed < lockout {
                return Some(lockout - elapsed);
            }
        }
        None
    }

    pub fn record_failure(&self, username: &str, hwid: &str) {
        let key = Self::key(username, hwid);
        let mut map = self.failures.lock().unwrap();
        let entry = map.entry(key).or_insert((0, Instant::now()));
        entry.0 += 1;
        entry.1 = Instant::now();
    }

    pub fn record_success(&self, username: &str, hwid: &str) {
        let key = Self::key(username, hwid);
        self.failures.lock().unwrap().remove(&key);
    }

    /// Escalating lockout: 3 fails -> 30s, 5 fails -> 2min, 8+ fails -> 15min.
    fn lockout_duration(failure_count: u32) -> Duration {
        match failure_count {
            0..=2 => Duration::from_secs(0),
            3..=4 => Duration::from_secs(30),
            5..=7 => Duration::from_secs(120),
            _ => Duration::from_secs(900),
        }
    }
}
