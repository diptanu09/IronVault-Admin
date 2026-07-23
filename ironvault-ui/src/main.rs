//! IronVault Admin UI - Bootstrapper & Main Thread
//! Initializes the Slint UI framework and establishes connections
//! to the core security and database layers with automated relational tracking.

slint::include_modules!();

mod context;
mod handlers;

use context::AppContext;
use ironvault_core::audit::AuditLogger;
use ironvault_db::{DbClient, OracleConnection};
use slint::ComponentHandle;
use sqlx::postgres::PgSslMode;
use std::sync::Arc;

// FFI Link definitions for Oreans Themida SecureEngine SDK
#[link(name = "SecureEngineSDK64")]
extern "C" {
    fn VMStart();
    fn VMEnd();
}

/// Searches upward from the current executable's directory (and, as a
/// fallback, the current working directory) for a `.env` file, so
/// environment loading works consistently whether launched via
/// `cargo run` from the workspace root, from a package subdirectory, or
/// by running the compiled .exe directly from target/debug or
/// target/release.
fn find_and_load_dotenv() -> bool {
    if let Ok(exe_path) = std::env::current_exe() {
        let mut dir = exe_path.parent().map(|p| p.to_path_buf());
        while let Some(d) = dir {
            let candidate = d.join(".env");
            // println!("[DEBUG] Checking for .env at: {:?}", candidate);
            if candidate.exists() {
                // println!("[DEBUG] Found .env at: {:?}", candidate);
                if dotenvy::from_path(&candidate).is_ok() {
                    return true;
                }
            }
            dir = d.parent().map(|p| p.to_path_buf());
        }
    }
    dotenvy::dotenv().is_ok()
}

#[tokio::main]
async fn main() -> Result<(), slint::PlatformError> {
    println!("[BOOT] Engaging IronVault Core Security...");

    let env_loaded = find_and_load_dotenv();
    if !env_loaded {
        log::warn!("[CONFIG] No .env file found via binary-relative search or CWD. Falling back to process environment / defaults.");
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

    // Prefer Credential Manager, fall back to .env / process environment
    let db_password = match ironvault_core::credential_store::read_password() {
        Ok(Some(pw)) => {
            log::info!("[CONFIG] Database password loaded from Windows Credential Manager.");
            pw
        }
        Ok(None) => {
            log::warn!(
                "[CONFIG] No password found in Windows Credential Manager, falling back to IRONVAULT_DB_PASSWORD in .env. \
                 Run the credential-setup step to move this to Credential Manager."
            );
            std::env::var("IRONVAULT_DB_PASSWORD")
                .expect("[FATAL CONFIG ERROR] IRONVAULT_DB_PASSWORD must be set (in .env or Credential Manager)")
        }
        Err(e) => {
            log::warn!(
                "[CONFIG] Credential Manager read failed ({}), falling back to .env.",
                e
            );
            std::env::var("IRONVAULT_DB_PASSWORD")
                .expect("[FATAL CONFIG ERROR] IRONVAULT_DB_PASSWORD must be set (in .env or Credential Manager)")
        }
    };

    let ssl_mode_str =
        std::env::var("IRONVAULT_DB_SSL_MODE").unwrap_or_else(|_| "require".to_string());
    let ssl_mode = match ssl_mode_str.to_lowercase().as_str() {
        "disable" => PgSslMode::Disable,
        "prefer" => PgSslMode::Prefer,
        "verify-ca" => PgSslMode::VerifyCa,
        "verify-full" => PgSslMode::VerifyFull,
        "require" => PgSslMode::Require,
        other => {
            log::warn!(
                "[CONFIG] Unrecognized IRONVAULT_DB_SSL_MODE '{}', defaulting to 'require'.",
                other
            );
            PgSslMode::Require
        }
    };

    let ssl_root_cert = std::env::var("IRONVAULT_DB_SSL_ROOT_CERT").ok();
    // println!("[DEBUG] ssl_root_cert read as: {:?}", ssl_root_cert);

    let db = match DbClient::connect_with_credentials(
        &db_host,
        db_port,
        &db_name,
        &db_user,
        &db_password,
        ssl_mode,
        ssl_root_cert.as_deref(),
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
