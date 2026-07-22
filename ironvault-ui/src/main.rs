//! IronVault Admin UI - Bootstrapper & Main Thread
//! Initializes the Slint UI framework and establishes connections
//! to the core security and database layers with automated relational tracking.

slint::include_modules!();
use slint::ComponentHandle;
mod context;
mod handlers;
use context::AppContext;
use ironvault_core::audit::AuditLogger;
use ironvault_db::{DbClient, OracleConnection};
use sqlx::postgres::PgSslMode;
use std::sync::Arc;

// FFI Link definitions for Oreans Themida SecureEngine SDK
#[link(name = "SecureEngineSDK64")]
extern "C" {
    fn VMStart();
    fn VMEnd();
}

#[tokio::main]
async fn main() -> Result<(), slint::PlatformError> {
    println!("[BOOT] Engaging IronVault Core Security...");

    if let Err(e) = dotenvy::dotenv() {
        log::warn!(
            "[CONFIG] No .env file loaded ({}). Falling back to process environment / defaults.",
            e
        );
    }

    let hwid = ironvault_core::licensing::generate_hwid();
    ironvault_core::security::enforce_core_security_checks(&hwid);

    let db_host = std::env::var("IRONVAULT_DB_HOST").unwrap_or_else(|_| "localhost".to_string());
    let db_port: u16 = std::env::var("IRONVAULT_DB_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5432);
    let db_name = std::env::var("IRONVAULT_DB_NAME")
        .expect("[FATAL CONFIG ERROR] IRONVAULT_DB_NAME must be set");
    let db_user = std::env::var("IRONVAULT_DB_USER")
        .expect("[FATAL CONFIG ERROR] IRONVAULT_DB_USER must be set");
    let db_password = std::env::var("IRONVAULT_DB_PASSWORD")
        .expect("[FATAL CONFIG ERROR] IRONVAULT_DB_PASSWORD must be set");

    let ssl_mode_str =
        std::env::var("IRONVAULT_DB_SSL_MODE").unwrap_or_else(|_| "require".to_string());
    let ssl_mode = match ssl_mode_str.to_lowercase().as_str() {
        "disable" => PgSslMode::Disable,
        "prefer" => PgSslMode::Prefer,
        "verify-full" => PgSslMode::VerifyFull,
        "verify-ca" => PgSslMode::VerifyCa,
        _ => PgSslMode::Require, // safe default even on an unrecognized/typo'd value
    };

    if matches!(ssl_mode, PgSslMode::Disable) {
        log::warn!(
            "[CONFIG] IRONVAULT_DB_SSL_MODE=disable — database traffic will NOT be encrypted. \
             Only use this for a same-machine, localhost-only Postgres instance."
        );
    }

    let db = match DbClient::connect_with_credentials(
        &db_host,
        db_port,
        &db_name,
        &db_user,
        &db_password,
        ssl_mode,
    )
    .await
    {
        Ok(client) => Arc::new(client),
        Err(err) => {
            eprintln!("[FATAL DATABASE ERROR]: {}", err);
            std::process::exit(1);
        }
    };

    let oracle = match OracleConnection::new() {
        Ok(client) => Arc::new(client),
        Err(e) => {
            eprintln!("[FATAL] Oracle matrix allocation failure: {:?}", e);
            std::process::exit(1);
        }
    };

    let audit = Arc::new(AuditLogger::new("ironvault.audit.log"));

    let ctx = Arc::new(AppContext {
        db,
        oracle,
        audit,
        hwid: hwid.clone(),
        rate_limiter: ironvault_core::auth::LoginRateLimiter::new(),
    });

    let app = AppWindow::new()?;
    app.set_hwid_string(format!("HWID: {}", hwid).into());

    // FFI security wrapping is invoked per-sensitive-op inside auth.rs at
    // login time; VMStart/VMEnd here just bracket window construction.
    unsafe {
        VMStart();
    }
    handlers::register_all(&app, ctx);
    unsafe {
        VMEnd();
    }

    app.run()?;
    Ok(())
}
