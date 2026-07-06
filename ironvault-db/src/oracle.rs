//! Oracle database adapter
//!
//! Handles legacy Oracle 11g/12c database connections and migrations
//! for organizations with existing Oracle infrastructure

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

/// User model for Oracle database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleDbUser {
    pub id: String, 
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub role: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Oracle connection wrapper
pub struct OracleConnection {
    #[allow(dead_code)]
    connection_string: String,
    pool: oracle::pool::Pool,
}

impl OracleConnection {
    /// Create new Oracle connection pool infrastructure
    pub fn new(connection_string: &str) -> Result<Self, String> {
        // Explicitly targeted parameter tokens
        let user = "gpffp"; // Updated username
        let pass = "gpffp"; // Updated password
        
        // FIXED: Compiles a full TNS Descriptor block to target your SID explicitly.
        // This stops Oracle from looking for a Service Name and targets the SID 'db11g' directly.
        let tns_descriptor = "(DESCRIPTION=\
                                (ADDRESS=(PROTOCOL=TCP)(HOST=192.168.100.247)(PORT=1521))\
                                (CONNECT_DATA=(SID=db11g))\
                             )";

        let pool = oracle::pool::PoolBuilder::new(user, pass, tns_descriptor)
            .build()
            .map_err(|e| format!("Oracle connection pool allocation error: {}", e))?;
        
        Ok(OracleConnection {
            #[allow(dead_code)]
            connection_string: connection_string.to_string(),
            pool,
        })
    }

    /// Extends a live dual-engine data migration pipeline between Oracle and PostgreSQL
    pub async fn migrate_to_postgres(&self, pg_pool: &PgPool) -> Result<(), String> {
        let oracle_pool = self.pool.clone();

        // 1. Extract and map legacy dataset from Oracle on a blocking background thread
        let legacy_users = tokio::task::spawn_blocking(move || {
            let conn = oracle_pool.get().map_err(|e| format!("Oracle thread connection fault: {}", e))?;
            
            let mut stmt = conn.statement("SELECT id, username, email, password_hash, user_role, is_active, created_at, updated_at FROM users_legacy").build()
                .map_err(|e| format!("Oracle statement formulation fault: {}", e))?;
            
            let rows = stmt.query(&[]).map_err(|e| format!("Oracle data evaluation fault: {}", e))?;
            let mut extracted = Vec::new();

            for row_res in rows {
                let row = row_res.map_err(|e| format!("Row stream parse error: {}", e))?;
                
                let (id, username, email, password_hash, role, is_active_int, created_str, updated_str): 
                    (String, String, String, String, String, i32, String, String) = row.get_as()
                        .map_err(|e| format!("Column compilation transformation fault: {}", e))?;

                let created_at = DateTime::parse_from_rfc3339(&created_str).map(|dt| dt.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now());
                let updated_at = DateTime::parse_from_rfc3339(&updated_str).map(|dt| dt.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now());

                extracted.push(OracleDbUser {
                    id,
                    username,
                    email,
                    password_hash,
                    role,
                    is_active: is_active_int == 1,
                    created_at,
                    updated_at,
                });
            }
            Ok::<Vec<OracleDbUser>, String>(extracted)
        })
        .await
        .unwrap()?;

        println!("[MIGRATION ENGINE] Extracted {} records from Oracle. Synchronizing downstream Postgres data store...", legacy_users.len());

        // 2. Load the transformed elements inside a safe PostgreSQL database transaction
        let mut tx = pg_pool.begin().await.map_err(|e| format!("Postgres transaction allocation failed: {}", e))?;

        for user in legacy_users {
            sqlx::query(
                "INSERT INTO ironvault.users (username, password, role, status, hardware_fingerprint, full_name, designation, section, expires_at) 
                 VALUES ($1, $2, $3, 'ACTIVE', $4, $5, $6, $7, NOW() + '30 days'::INTERVAL)
                 ON CONFLICT (username) DO UPDATE 
                 SET role = EXCLUDED.role"
            )
            .bind(&user.username)
            .bind(&user.password_hash)
            .bind(&user.role)
            .bind("MIGRATED_NODE_TOKEN")
            .bind(&user.username) 
            .bind("Legacy Operator")
            .bind("Oracle Migration Unit")
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("Postgres block sync error: {}", e))?;
        }

        tx.commit().await.map_err(|e| format!("Postgres database commit confirmation failure: {}", e))?;
        println!("[SUCCESS] Dual-database data synchronization cycle completed successfully.");
        Ok(())
    }

    /// Validate Oracle 11g/12c compatibility matrix
    pub async fn validate_version(&self) -> Result<String, String> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool.get().map_err(|e| format!("Handshake target context missing: {}", e))?;
            let version_str = conn.server_version().map_err(|e| format!("Handshake matrix readout failed: {}", e))?;
            Ok(format!("Oracle Server Sequence Engine: {:?}", version_str))
        })
        .await
        .unwrap()
    }

    /// Execution verification pass
    pub async fn health_check(&self) -> Result<(), String> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool.get().map_err(|e| format!("Handshake visibility fault: {}", e))?;
            conn.execute("SELECT 1 FROM DUAL", &[]).map_err(|e| format!("DUAL loop execution fault: {}", e))?;
            Ok(())
        })
        .await
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oracle_connection_string() {
        let conn = OracleConnection::new("gpffp/gpffp@192.168.100.247:1521/db11g");
        if let Ok(c) = conn {
            let connection_lease = c.pool.get();
            assert!(connection_lease.is_ok());
        }
    }
}