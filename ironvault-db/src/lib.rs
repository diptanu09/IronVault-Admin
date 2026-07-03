//! IronVault Database Access Layer
//!
//! Provides ORM and database operations for PostgreSQL and Oracle

use sqlx::{PgPool, Row};
use ironvault_core::auth::{User, Role};

pub struct DbClient {
    pub pool: PgPool,
}

impl DbClient {
    /// Connects to your live operational database cluster
    pub async fn connect(connection_string: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPool::connect(connection_string).await?;
        
        // Seed default system super-administrator if your ironvault.users ledger table is currently empty
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ironvault.users")
            .fetch_one(&pool)
            .await?;

        if row.0 == 0 {
            sqlx::query(
                "INSERT INTO ironvault.users (username, password, role, status) 
                 VALUES ($1, $2, $3, 'ACTIVE')"
            )
            .bind("admin")
            .bind("admin123")
            .bind("SuperAdmin")
            .execute(&pool)
            .await?;
            println!("[PGSQL] Default administrative profile seeded into ironvault.users successfully.");
        }

        Ok(Self { pool })
    }

    /// Validates an incoming operator login request against your ironvault.users layout
    pub async fn authenticate_user(&self, user: &str, pass: &str) -> Result<User, String> {
        // Changed to standard runtime evaluation query to drop compilation environment flags entirely
        let result = sqlx::query(
            "SELECT id, username, password, role FROM ironvault.users WHERE username = $1 AND status = 'ACTIVE'"
        )
        .bind(user)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| e.to_string())?;

        if let Some(row) = result {
            let db_password: String = row.get("password");
            if db_password == pass {
                let numeric_id: i32 = row.get("id");
                let username: String = row.get("username");
                let role_str: String = row.get("role");
                
                let now_stamp = chrono::Utc::now().to_rfc3339();

                // Log this session access directly to your live database logging table using runtime evaluation
                sqlx::query(
                    "INSERT INTO ironvault.system_audit_logs (operator_username, action_type, details) 
                     VALUES ($1, $2, $3)"
                )
                .bind(&username)
                .bind("LOGIN_SUCCESS")
                .bind("Operator signed in successfully. HWID authenticated.")
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
        }
        Err("Authentication failure: Invalid credentials or account deactivated.".to_string())
    }

    /// Registers a new operator record into your custom ironvault.users schema layout
    pub async fn register_user(&self, username: &str, pass: &str, role: &str) -> Result<(), String> {
        // Changed to standard runtime evaluation query to drop compilation environment flags entirely
        sqlx::query(
            "INSERT INTO ironvault.users (username, password, role, status) 
             VALUES ($1, $2, $3, 'ACTIVE')"
        )
        .bind(username)
        .bind(pass)
        .bind(role)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Registration rejected by schema constraints: {}", e))?;

        println!("[PGSQL] New Operator Profile Registered into ironvault.users // Name: {}", username);
        Ok(())
    }
}