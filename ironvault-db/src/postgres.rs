//! PostgreSQL Core User Profile Storage Manager
//! Handles operator authentication, enrollment, leasing, and account revocations securely.

use sqlx::{postgres::PgPoolOptions, PgPool, Row};

#[derive(Clone, Debug)]
pub struct DbUser {
    pub username: String,
    pub role: String,
    pub last_login: String,
}

#[derive(Clone, Debug)]
pub struct ActiveUser {
    pub username: String,
    pub role: String,
    pub last_login: String,
    pub full_name: String,
    pub designation: String,
    pub expires_at: String,
}

#[derive(Clone)]
pub struct DbClient {
    pool: PgPool,
}

#[derive(Clone, Debug)]
pub struct DbAuditEntry {
    pub timestamp: String,
    pub operator_id: String,
    pub operation_action: String,
    pub level: String,
}

impl DbClient {
    /// Public getter mapping to expose the underlying PgPool reference safely
    pub fn get_pool(&self) -> &sqlx::PgPool {
        &self.pool
    }

    pub async fn connect_with_credentials(
        host: &str,
        port: u16,
        db_name: &str,
        user: &str,
        pass: &str,
    ) -> Result<Self, String> {
        let database_url = format!("postgres://{}:{}@{}:{}/{}", user, pass, host, port, db_name);

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .map_err(|e| format!("Database cluster handshake failed: {}", e))?;

        Ok(Self { pool })
    }

    pub async fn authenticate_user(
        &self,
        username: &str,
        password_plain: &str,
        hwid: &str,
    ) -> Result<DbUser, String> {
        let row = sqlx::query(
            "SELECT username, password, role, \
             COALESCE(TO_CHAR(last_login_at, 'YYYY-MM-DD HH24:MI'), 'NEVER') as last_login \
             FROM ironvault.users \
             WHERE username = $1 AND hardware_fingerprint = $2 AND status = 'ACTIVE' \
             AND (expires_at IS NULL OR expires_at > NOW())",
        )
        .bind(username)
        .bind(hwid)
        .fetch_optional(self.get_pool())
        .await
        .map_err(|e| e.to_string())?;

        let row = match row {
            Some(r) => r,
            None => {
                return Err(
                    "Authentication Failed: Invalid token, HWID mismatch, or account subscription has EXPIRED."
                        .to_string(),
                )
            }
        };

        let stored_hash: String = row.get("password");

        if !ironvault_core::crypto::verify_password(password_plain, &stored_hash) {
            return Err(
                "Authentication Failed: Invalid token, HWID mismatch, or account subscription has EXPIRED."
                    .to_string(),
            );
        }

        sqlx::query("UPDATE ironvault.users SET last_login_at = NOW() WHERE username = $1")
            .bind(username)
            .execute(&self.pool)
            .await
            .ok();

        Ok(DbUser {
            username: row.get("username"),
            role: row.get("role"),
            last_login: row.get("last_login"),
        })
    }

    pub async fn register_user(
        &self,
        username: &str,
        password_plain: &str,
        hwid: &str,
        first: &str,
        middle: &str,
        last: &str,
        designation: &str,
        section: &str,
    ) -> Result<(), String> {
        let full_name = if middle.trim().is_empty() {
            format!("{} {}", first.trim(), last.trim())
        } else {
            format!("{} {} {}", first.trim(), middle.trim(), last.trim())
        };

        let secure_hashed_pass = ironvault_core::crypto::hash_password(password_plain)
            .map_err(|_| "Registration record reject: password hashing failed".to_string())?;

        // FIXED (item #9): expires_at is no longer set at registration time.
        // A PENDING account has no active lease yet — the 30-day window should
        // only begin once a SuperAdmin actually approves it (see approve_user),
        // not while the request is still sitting unreviewed. Leaving this NULL
        // for PENDING rows also means any future "expiry" queries/dashboards
        // can't misread a pending request as having an active, ticking lease.
        sqlx::query(
            "INSERT INTO ironvault.users (username, password, role, status, hardware_fingerprint, first_name, middle_name, last_name, full_name, designation, section, expires_at) \
             VALUES ($1, $2, 'Operator', 'PENDING', $3, $4, $5, $6, $7, $8, $9, NULL) ON CONFLICT DO NOTHING"
        )
        .bind(username)
        .bind(&secure_hashed_pass)
        .bind(hwid)
        .bind(first)
        .bind(middle)
        .bind(last)
        .bind(full_name)
        .bind(designation)
        .bind(section)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Registration record reject: {}", e))?;
        Ok(())
    }

    pub async fn log_audit_event(
        &self,
        operator: &str,
        action: &str,
        level: &str,
        schema: &str,
    ) -> Result<(), String> {
        sqlx::query(
            "INSERT INTO ironvault.db_audit_logs (operator_id, operation_action, impact_level, target_schema) \
             VALUES ($1, $2, $3, $4)"
        )
        .bind(operator)
        .bind(action)
        .bind(level)
        .bind(schema)
        .execute(&self.pool)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// FIXED (item #10): reads audit history back from Postgres so the
    /// dashboard's audit tab reflects the *actual* single source of truth,
    /// instead of only ever showing file-log entries while DB entries sat
    /// unused.
    ///
    /// NOTE: assumes `ironvault.db_audit_logs` has a `created_at` timestamp
    /// column with a default of NOW() (standard for an append-only log table).
    /// If your schema uses a different column name, adjust the SELECT/ORDER BY
    /// below to match.
    pub async fn fetch_recent_audit_logs(&self, limit: i64) -> Result<Vec<DbAuditEntry>, String> {
        let rows = sqlx::query(
            "SELECT COALESCE(TO_CHAR(created_at AT TIME ZONE 'Asia/Kolkata', 'YYYY-MM-DD HH24:MI'), 'UNKNOWN') as ts, \
                    operator_id, operation_action, impact_level \
             FROM ironvault.db_audit_logs \
             ORDER BY created_at DESC \
             LIMIT $1"
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| e.to_string())?;

        Ok(rows
            .into_iter()
            .map(|r| DbAuditEntry {
                timestamp: r.get("ts"),
                operator_id: r.get("operator_id"),
                operation_action: r.get("operation_action"),
                level: r.get("impact_level"),
            })
            .collect())
    }

    pub async fn fetch_next_pending_user(&self) -> Result<Option<String>, String> {
        let row =
            sqlx::query("SELECT username FROM ironvault.users WHERE status = 'PENDING' LIMIT 1")
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| e.to_string())?;

        Ok(row.map(|r| r.get("username")))
    }

    pub async fn approve_user(
        &self,
        admin: &str,
        target_user: &str,
        assigned_role: &str,
    ) -> Result<(), String> {
        sqlx::query(
            "UPDATE ironvault.users SET status = 'ACTIVE', role = $1, expires_at = NOW() + INTERVAL '30 days', \
             approved_by = $3 \
             WHERE username = $2"
        )
        .bind(assigned_role)
        .bind(target_user)
        .bind(admin)
        .execute(&self.pool)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }
    /// FIXED (regression from bcrypt migration): restores the ability for an
    /// operator holding a one-time reset token to authenticate, distinct from
    /// the normal password path in `authenticate_user`. Returns Ok(DbUser) on
    /// a valid, matching token for an EXPIRED account on the bound HWID; the
    /// caller (main.rs) is responsible for routing this into the forced
    /// password-reset UI state rather than a normal logged-in session.
    pub async fn authenticate_via_temp_token(
        &self,
        username: &str,
        token_plain: &str,
        hwid: &str,
    ) -> Result<DbUser, String> {
        let row = sqlx::query(
            "SELECT username, temp_token, role, \
             COALESCE(TO_CHAR(last_login_at, 'YYYY-MM-DD HH24:MI'), 'NEVER') as last_login \
             FROM ironvault.users \
             WHERE username = $1 AND hardware_fingerprint = $2 AND status = 'EXPIRED' AND temp_token IS NOT NULL"
        )
        .bind(username)
        .bind(hwid)
        .fetch_optional(self.get_pool())
        .await
        .map_err(|e| e.to_string())?;

        let row =
            match row {
                Some(r) => r,
                None => return Err(
                    "Authentication Failed: No pending one-time token for this operator/machine."
                        .to_string(),
                ),
            };

        let stored_hash: String = row.get("temp_token");
        if !ironvault_core::crypto::verify_token(token_plain, &stored_hash) {
            return Err("Authentication Failed: Invalid one-time token.".to_string());
        }

        Ok(DbUser {
            username: row.get("username"),
            role: row.get("role"),
            last_login: row.get("last_login"),
        })
    }

    pub async fn deny_user(&self, admin: &str, target_user: &str) -> Result<(), String> {
        log::info!(
            "[AUDIT] Operator @{} denied pending registration for @{}",
            admin,
            target_user
        );
        sqlx::query("DELETE FROM ironvault.users WHERE username = $1 AND status = 'PENDING'")
            .bind(target_user)
            .execute(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn ban_user(&self, admin: &str, target_user: &str) -> Result<(), String> {
        log::info!(
            "[AUDIT] Operator @{} banned/purged account @{}",
            admin,
            target_user
        );
        sqlx::query("DELETE FROM ironvault.users WHERE username = $1")
            .bind(target_user)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Failed to execute revocation purge: {}", e))?;
        Ok(())
    }

    pub async fn get_active_users(&self) -> Result<Vec<ActiveUser>, String> {
        let rows = sqlx::query(
            "SELECT username, role, \
             COALESCE(TO_CHAR(last_login_at, 'YYYY-MM-DD HH24:MI'), 'NEVER') as last_login, \
             COALESCE(full_name, 'NOT SET') as full_name, \
             COALESCE(designation, 'NOT SET') as designation, \
             COALESCE(TO_CHAR(expires_at, 'YYYY-MM-DD HH24:MI'), 'LIFETIME') as expires_at \
             FROM ironvault.users WHERE status = 'ACTIVE' ORDER BY role, username",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("Failed to fetch operators: {}", e))?;

        let users = rows
            .into_iter()
            .map(|r| ActiveUser {
                username: r.get("username"),
                role: r.get("role"),
                last_login: r.get("last_login"),
                full_name: r.get("full_name"),
                designation: r.get("designation"),
                expires_at: r.get("expires_at"),
            })
            .collect();
        Ok(users)
    }

    pub async fn update_user_lease(
        &self,
        target_user: &str,
        new_role: &str,
        days_valid: i32,
    ) -> Result<(), String> {
        // FIXED: String concatenation interval casting vulnerability eliminated
        sqlx::query(
            "UPDATE ironvault.users \
             SET role = $1, expires_at = NOW() + ($2 * INTERVAL '1 day') \
             WHERE username = $3 AND status = 'ACTIVE'",
        )
        .bind(new_role)
        .bind(days_valid)
        .bind(target_user)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to update access lease parameters: {}", e))?;
        Ok(())
    }

    pub async fn update_user_role(
        &self,
        admin_name: &str,
        target_user: &str,
        new_role: &str,
    ) -> Result<(), String> {
        log::info!(
            "[AUDIT] Operator @{} altered role profile for @{} to {}",
            admin_name,
            target_user,
            new_role
        );
        sqlx::query(
            "UPDATE ironvault.users SET role = $1 WHERE username = $2 AND status = 'ACTIVE'",
        )
        .bind(new_role)
        .bind(target_user)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to update role state: {}", e))?;
        Ok(())
    }

    pub async fn update_user_full_access(
        &self,
        target_user: &str,
        new_role: &str,
        days_valid: i32,
        schemas: &str,
    ) -> Result<(), String> {
        // FIXED: String concatenation interval casting vulnerability eliminated
        sqlx::query(
            "UPDATE ironvault.users \
             SET role = $1, \
                 expires_at = NOW() + ($2 * INTERVAL '1 day'), \
                 section = $3, \
                 status = 'ACTIVE' \
             WHERE username = $4",
        )
        .bind(new_role)
        .bind(days_valid)
        .bind(schemas)
        .bind(target_user)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to update access matrix: {}", e))?;
        Ok(())
    }
}
