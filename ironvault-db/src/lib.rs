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
    /// Connects using raw credential strings to bypass URL parsers and isolate sqlx types from the UI crate
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

    /// Validates an incoming operator login request by matching cryptographic hashes and hardware fingerprints
    pub async fn authenticate_user(&self, user: &str, pass: &str, current_hwid: &str) -> Result<User, String> {
        let result = sqlx::query(
            "SELECT id, username, password, role, hardware_fingerprint FROM ironvault.users WHERE username = $1 AND status = 'ACTIVE'"
        )
        .bind(user)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| e.to_string())?;

        if let Some(row) = result {
            let db_password_hash: String = row.get("password");
            
            // 1. Verify cryptographic password matrix
            match verify(pass, &db_password_hash) {
                Ok(true) => {
                    // 2. HARDWARE FINGERPRINT ENFORCEMENT
                    let db_hwid: Option<String> = row.get("hardware_fingerprint");
                    if let Some(stored_fingerprint) = db_hwid {
                        if stored_fingerprint != current_hwid {
                            return Err("SECURITY VIOLATION: Hardware signature mismatch. Access Denied.".to_string());
                        }
                    }

                    let numeric_id: i32 = row.get("id");
                    let username: String = row.get("username");
                    let role_str: String = row.get("role");
                    
                    let now_stamp = chrono::Utc::now().to_rfc3339();

                    // Log session to table ledger
                    sqlx::query(
                        "INSERT INTO ironvault.system_audit_logs (operator_username, action_type, details) 
                         VALUES ($1, $2, $3)"
                    )
                    .bind(&username)
                    .bind("LOGIN_SUCCESS")
                    .bind(&format!("Operator signed in successfully. HWID verified: {}", current_hwid))
                    .execute(&self.pool)
                    .await
                    .ok();

                    return Ok(User {
                        id: numeric_id.to_string(),
                        username,
                        role: Role::from(role_str),
                        last_login: now_stamp,
                    });
                }
                _ => return Err("Authentication failure: Password verification failed.".to_string())
            }
        }
        Err("Authentication failure: Invalid credentials or account deactivated.".to_string())
    }

    /// Registers a new operator record, binding them to their current hardware fingerprint securely
    pub async fn register_user(&self, username: &str, pass: &str, role: &str, current_hwid: &str) -> Result<(), String> {
        // Convert raw input into a safe salted cryptographic string
        let secure_hash = hash(pass, DEFAULT_COST)
            .map_err(|e| format!("Security Engine Failure: {}", e))?;

        sqlx::query(
            "INSERT INTO ironvault.users (username, password, role, status, hardware_fingerprint) 
             VALUES ($1, $2, $3, 'ACTIVE', $4)"
        )
        .bind(username)
        .bind(secure_hash)
        .bind(role)
        .bind(current_hwid)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Registration rejected by schema constraints: {}", e))?;

        println!("[PGSQL] New Operator Profile Registered securely into ironvault.users // Name: {} // Bound HWID: {}", username, current_hwid);
        Ok(())
    }
}