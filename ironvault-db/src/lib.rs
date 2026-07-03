//! IronVault Database Access Layer
//!
//! Provides ORM and database operations for PostgreSQL and Oracle

use sqlx::{PgPool, Row};
use sqlx::postgres::PgConnectOptions;
use ironvault_core::auth::{User, Role};
use bcrypt::{hash, verify, DEFAULT_COST};

pub struct DbClient {
    pub pool: PgPool,
}

impl DbClient {
    pub async fn connect_with_credentials(
        host: &str,
        port: u16,
        database: &str,
        username: &str,
        password: &str,
    ) -> Result<Self, sqlx::Error> {
        let options = PgConnectOptions::new()
            .host(host)
            .port(port)
            .database(database)
            .username(username)
            .password(password);

        let pool = PgPool::connect_with(options).await?;
        Ok(Self { pool })
    }

    /// Validates login, dynamically captures HWID on first login, and enforces it on subsequent ones
    pub async fn authenticate_user(&self, user: &str, pass: &str, current_hwid: &str) -> Result<User, String> {
        let result = sqlx::query(
            "SELECT id, username, password, role, status, hardware_fingerprint FROM ironvault.users WHERE username = $1"
        )
        .bind(user)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| e.to_string())?;

        if let Some(row) = result {
            let status: String = row.get("status");
            let norm_status = status.trim().to_uppercase();
            
            if norm_status == "PENDING" {
                return Err("ACCESS DENIED: Your registration profile is currently PENDING administrative approval.".to_string());
            } else if norm_status == "DENIED" {
                return Err("ACCESS DENIED: Your request was rejected by a system administrator.".to_string());
            } else if norm_status != "ACTIVE" {
                return Err("ACCESS DENIED: This account has been deactivated.".to_string());
            }

            let db_password_hash: String = row.get("password");
            match verify(pass, &db_password_hash) {
                Ok(true) => {
                    let numeric_id: i32 = row.get("id");
                    let db_hwid: Option<String> = row.get("hardware_fingerprint");

                    match db_hwid {
                        None => {
                            sqlx::query(
                                "UPDATE ironvault.users SET hardware_fingerprint = $1 WHERE id = $2"
                            )
                            .bind(current_hwid)
                            .bind(numeric_id)
                            .execute(&self.pool)
                            .await
                            .map_err(|e| format!("Failed to lock hardware fingerprint: {}", e))?;
                        }
                        Some(stored_fingerprint) => {
                            let clean_fingerprint = stored_fingerprint.trim();
                            if clean_fingerprint != current_hwid && !clean_fingerprint.is_empty() {
                                return Err("SECURITY VIOLATION: Hardware signature mismatch.".to_string());
                            }
                        }
                    }

                    let username: String = row.get("username");
                    let role_str: String = row.get("role");
                    let now_stamp = chrono::Utc::now().to_rfc3339();

                    sqlx::query("UPDATE ironvault.users SET last_login_at = NOW() WHERE id = $1").bind(numeric_id).execute(&self.pool).await.ok();
                    return Ok(User { id: numeric_id.to_string(), username, role: Role::from(role_str), last_login: now_stamp });
                }
                _ => return Err("Authentication failure: Password verification failed.".to_string())
            }
        }
        Err("Authentication failure: Invalid credentials.".to_string())
    }

    pub async fn register_user(&self, username: &str, pass: &str, _current_hwid: &str) -> Result<(), String> {
        let secure_hash = hash(pass, DEFAULT_COST).map_err(|e| format!("Security Engine Failure: {}", e))?;
        sqlx::query("INSERT INTO ironvault.users (username, password, role, status, hardware_fingerprint) VALUES ($1, $2, 'Viewer', 'PENDING', NULL)")
            .bind(username).bind(secure_hash).execute(&self.pool).await
            .map_err(|e| format!("Registration rejected: {}", e))?;
        Ok(())
    }

    /// Fetches the name of the oldest user currently stuck in the pending queue
    pub async fn fetch_next_pending_user(&self) -> Result<Option<String>, String> {
        // Safe, bulletproof whitespace text formatting check using ILIKE
        let row = sqlx::query(
            "SELECT username FROM ironvault.users WHERE status ILIKE '%pending%' ORDER BY id ASC LIMIT 1"
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| format!("PostgreSQL Exception Error: {}", e))?;

        if let Some(r) = row {
            let name: String = r.get("username");
            Ok(Some(name.trim().to_string()))
        } else {
            Ok(None)
        }
    }

    /// Approves a user and updates their role
    pub async fn approve_user(&self, admin_username: &str, target_username: &str, assigned_role: &str) -> Result<(), String> {
        sqlx::query("UPDATE ironvault.users SET role = $1, status = 'ACTIVE' WHERE username = $2")
            .bind(assigned_role).bind(target_username).execute(&self.pool).await.map_err(|e| e.to_string())?;

        sqlx::query("INSERT INTO ironvault.system_audit_logs (operator_username, action_type, details) VALUES ($1, 'PROVISION_APPROVED', $2)")
            .bind(admin_username).bind(&format!("Approved user '{}' as '{}'", target_username, assigned_role)).execute(&self.pool).await.ok();
        Ok(())
    }

    /// Explicitly denies a user request, changing status to 'DENIED' so they leave the pending queue
    pub async fn deny_user(&self, admin_username: &str, target_username: &str) -> Result<(), String> {
        sqlx::query("UPDATE ironvault.users SET status = 'DENIED' WHERE username = $2")
            .bind(admin_username).bind(target_username).execute(&self.pool).await
            .map_err(|e| format!("Failed to reject profile entry: {}", e))?;

        sqlx::query("INSERT INTO ironvault.system_audit_logs (operator_username, action_type, details) VALUES ($1, 'PROVISION_DENIED', $2)")
            .bind(admin_username).bind(&format!("Denied access request for user '{}'", target_username)).execute(&self.pool).await.ok();
        Ok(())
    }
} // <-- End of impl DbClient block