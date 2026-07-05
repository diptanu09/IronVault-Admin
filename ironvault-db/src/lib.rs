//! IronVault Database Access Layer
//!
//! Provides ORM and database operations for PostgreSQL and Oracle

use sqlx::{PgPool, postgres::PgPoolOptions, Row};

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

impl DbClient {
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

    pub async fn authenticate_user(&self, username: &str, _pass: &str, hwid: &str) -> Result<DbUser, String> {
        // FIXED: Added TO_CHAR to format the timestamp cleanly
        let row = sqlx::query(
            "SELECT username, role, COALESCE(TO_CHAR(last_login_at, 'YYYY-MM-DD HH24:MI'), 'NEVER') as last_login \
             FROM ironvault.users \
             WHERE username = $1 AND status = 'ACTIVE' AND hardware_fingerprint = $2 \
             AND (role = 'SuperAdmin' OR role = 'super_admin' OR expires_at IS NULL OR expires_at > NOW())"
        )
        .bind(username)
        .bind(hwid)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| e.to_string())?;

        if let Some(r) = row {
            sqlx::query("UPDATE ironvault.users SET last_login_at = NOW() WHERE username = $1")
                .bind(username)
                .execute(&self.pool)
                .await
                .ok();

            Ok(DbUser {
                username: r.get("username"),
                role: r.get("role"),
                last_login: r.get("last_login"),
            })
        } else {
            Err("Authentication Failed: Invalid token, HWID mismatch, or account subscription has EXPIRED.".to_string())
        }
    }

    pub async fn register_user(
        &self, 
        username: &str, 
        hashed_pass: &str, 
        hwid: &str,
        first: &str,
        middle: &str,
        last: &str,
        designation: &str,
        section: &str
    ) -> Result<(), String> {
        let full_name = if middle.trim().is_empty() {
            format!("{} {}", first.trim(), last.trim())
        } else {
            format!("{} {} {}", first.trim(), middle.trim(), last.trim())
        };

        sqlx::query(
            "INSERT INTO ironvault.users (username, password, role, status, hardware_fingerprint, first_name, middle_name, last_name, full_name, designation, section, expires_at) \
             VALUES ($1, $2, 'Operator', 'PENDING', $3, $4, $5, $6, $7, $8, $9, NOW() + '30 days'::INTERVAL) ON CONFLICT DO NOTHING"
        )
        .bind(username)
        .bind(hashed_pass)
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

    pub async fn fetch_next_pending_user(&self) -> Result<Option<String>, String> {
        let row = sqlx::query("SELECT username FROM ironvault.users WHERE status = 'PENDING' LIMIT 1")
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
            
        Ok(row.map(|r| r.get("username")))
    }

    pub async fn approve_user(&self, _admin: &str, target_user: &str, assigned_role: &str) -> Result<(), String> {
        sqlx::query(
            "UPDATE ironvault.users SET status = 'ACTIVE', role = $1, expires_at = NOW() + '30 days'::INTERVAL \
             WHERE username = $2"
        )
        .bind(assigned_role)
        .bind(target_user)
        .execute(&self.pool)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn deny_user(&self, _admin: &str, target_user: &str) -> Result<(), String> {
        sqlx::query("DELETE FROM ironvault.users WHERE username = $1 AND status = 'PENDING'")
            .bind(target_user)
            .execute(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn get_active_users(&self) -> Result<Vec<ActiveUser>, String> {
        // FIXED: Formatted both login and expiration dates directly inside the query
        let rows = sqlx::query(
            "SELECT username, role, \
             COALESCE(TO_CHAR(last_login_at, 'YYYY-MM-DD HH24:MI'), 'NEVER') as last_login, \
             COALESCE(full_name, 'NOT SET') as full_name, \
             COALESCE(designation, 'NOT SET') as designation, \
             COALESCE(TO_CHAR(expires_at, 'YYYY-MM-DD HH24:MI'), 'LIFETIME') as expires_at \
             FROM ironvault.users WHERE status = 'ACTIVE' ORDER BY role, username"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("Failed to fetch operators: {}", e))?;

        let users = rows.into_iter().map(|r| ActiveUser {
            username: r.get("username"),
            role: r.get("role"),
            last_login: r.get("last_login"),
            full_name: r.get("full_name"),
            designation: r.get("designation"),
            expires_at: r.get("expires_at"),
        }).collect();

        Ok(users)
    }

    pub async fn update_user_lease(&self, target_user: &str, new_role: &str, days_valid: i32) -> Result<(), String> {
        sqlx::query(
            "UPDATE ironvault.users \
             SET role = $1, expires_at = NOW() + ($2 || ' days')::INTERVAL \
             WHERE username = $3 AND status = 'ACTIVE'"
        )
        .bind(new_role)
        .bind(days_valid)
        .bind(target_user)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to update access lease parameters: {}", e))?;
        Ok(())
    }

    pub async fn update_user_role(&self, _admin_name: &str, target_user: &str, new_role: &str) -> Result<(), String> {
        sqlx::query("UPDATE ironvault.users SET role = $1 WHERE username = $2 AND status = 'ACTIVE'")
            .bind(new_role)
            .bind(target_user)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Failed to update role state: {}", e))?;
        Ok(())
    }

    pub async fn ban_user(&self, _admin_name: &str, target_user: &str) -> Result<(), String> {
        sqlx::query("DELETE FROM ironvault.users WHERE username = $1")
            .bind(target_user)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Failed to execute revocation purge: {}", e))?;
        Ok(())
    }
}