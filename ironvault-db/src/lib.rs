//! IronVault Database Access Layer
//!
//! Provides ORM and database operations for PostgreSQL and Oracle

pub mod postgres;
pub mod oracle;

pub use postgres::PostgresConnection;
pub use oracle::OracleConnection;

/// Database error types
#[derive(Debug)]
pub enum DbError {
    ConnectionFailed,
    QueryFailed,
    MigrationFailed,
    NotFound,
    ConstraintViolation,
}

/// Generic database connection trait
pub trait DatabaseConnection {
    async fn health_check(&self) -> Result<(), DbError>;
    async fn close(&self) -> Result<(), DbError>;
}
