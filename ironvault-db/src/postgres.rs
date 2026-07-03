//! PostgreSQL database adapter
//!
//! Handles all database operations for the primary application state
//! using PostgreSQL as the main data store

use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{DbError, DatabaseConnection};

/// PostgreSQL connection pool wrapper
pub struct PostgresConnection {
    pool: PgPool,
}

/// User model for database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbUser {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub role: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Audit log model for database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbAuditLog {
    pub id: Uuid,
    pub user_id: Uuid,
    pub action: String,
    pub resource: String,
    pub timestamp: DateTime<Utc>,
    pub details: Option<String>,
}

impl PostgresConnection {
    /// Create new PostgreSQL connection pool
    pub async fn new(database_url: &str) -> Result<Self, DbError> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await
            .map_err(|_| DbError::ConnectionFailed)?;

        Ok(PostgresConnection { pool })
    }

    /// Create user in database
    pub async fn create_user(&self, user: &DbUser) -> Result<Uuid, DbError> {
        sqlx::query!(
            "INSERT INTO users (id, username, email, password_hash, role, is_active, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            user.id,
            user.username,
            user.email,
            user.password_hash,
            user.role,
            user.is_active,
            user.created_at,
            user.updated_at
        )
        .execute(&self.pool)
        .await
        .map_err(|_| DbError::ConstraintViolation)?;

        Ok(user.id)
    }

    /// Get user by ID
    pub async fn get_user(&self, user_id: Uuid) -> Result<DbUser, DbError> {
        sqlx::query_as::<_, (Uuid, String, String, String, String, bool, DateTime<Utc>, DateTime<Utc>)>(
            "SELECT id, username, email, password_hash, role, is_active, created_at, updated_at FROM users WHERE id = $1"
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .map(|(id, username, email, password_hash, role, is_active, created_at, updated_at)| DbUser {
            id,
            username,
            email,
            password_hash,
            role,
            is_active,
            created_at,
            updated_at,
        })
        .map_err(|_| DbError::NotFound)
    }

    /// Get user by username
    pub async fn get_user_by_username(&self, username: &str) -> Result<DbUser, DbError> {
        sqlx::query_as::<_, (Uuid, String, String, String, String, bool, DateTime<Utc>, DateTime<Utc>)>(
            "SELECT id, username, email, password_hash, role, is_active, created_at, updated_at FROM users WHERE username = $1"
        )
        .bind(username)
        .fetch_one(&self.pool)
        .await
        .map(|(id, username, email, password_hash, role, is_active, created_at, updated_at)| DbUser {
            id,
            username,
            email,
            password_hash,
            role,
            is_active,
            created_at,
            updated_at,
        })
        .map_err(|_| DbError::NotFound)
    }

    /// Insert audit log entry
    pub async fn log_audit(&self, log: &DbAuditLog) -> Result<Uuid, DbError> {
        sqlx::query!(
            "INSERT INTO audit_logs (id, user_id, action, resource, timestamp, details)
             VALUES ($1, $2, $3, $4, $5, $6)",
            log.id,
            log.user_id,
            log.action,
            log.resource,
            log.timestamp,
            log.details
        )
        .execute(&self.pool)
        .await
        .map_err(|_| DbError::QueryFailed)?;

        Ok(log.id)
    }

    /// Run database migrations
    pub async fn migrate(&self) -> Result<(), DbError> {
        // TODO: Implement migrations using sqlx-cli or embedded migrations
        Ok(())
    }
}

#[async_trait::async_trait]
impl DatabaseConnection for PostgresConnection {
    async fn health_check(&self) -> Result<(), DbError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|_| DbError::ConnectionFailed)?;
        Ok(())
    }

    async fn close(&self) -> Result<(), DbError> {
        self.pool.close().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn test_connection() {
        let conn = PostgresConnection::new("postgresql://user:password@localhost/ironvault")
            .await
            .unwrap();
        assert!(conn.health_check().await.is_ok());
    }
}
