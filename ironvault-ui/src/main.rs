//! IronVault Admin UI - Bootstrapper & Main Thread
//!
//! Initializes the Slint UI framework and establishes connections
//! to the core security and database layers

// Reverted back to the native slint macro to fix the rust-analyzer macro-error completely

slint::include_modules!();

use slint::ComponentHandle;
use ironvault_core::audit::AuditLogger;
use ironvault_core::auth::User;
use ironvault_db::DbClient;
use std::sync::Arc;

#[tokio::main] // Run main event loop using an async tokio framework thread pool
async fn main() -> Result<(), slint::PlatformError> {
    println!("[BOOT] Engaging IronVault Core Security...");
    
    ironvault_core::security::enforce_anti_debug();
    let hwid = ironvault_core::licensing::generate_hwid();
    println!("[SECURITY] Computed System HWID: {}", hwid);

    let audit_logger = Arc::new(AuditLogger::new("ironvault.audit.log"));

    // Connect to PostgreSQL database container
    println!("[PGSQL] Connecting to data target host server cluster...");
    let db_url = "postgres://ironvault:P@ssw()rd123@localhost:5432/ironvault"; // Customize URL to match parameters
    
    let db = match DbClient::connect(db_url).await {
        Ok(client) => Arc::new(client),
        Err(err) => {
            eprintln!("[FATAL DATABASE ACCESS ERROR]: {}", err);
            std::process::exit(1);
        }
    };
    println!("[SUCCESS] Database connections established. Schemas bound safely.");

    let app = AppWindow::new()?;
    app.set_hwid_string(format!("HWID: {}", hwid).into());
    
    // Bind event hooks to the asynchronous runtime environment
    let app_weak = app.as_weak();
    let db_login_clone = Arc::clone(&db);
    let audit_login_clone = Arc::clone(&audit_logger);
    
    app.on_request_authentication(move |username, password| {
        let ui = app_weak.unwrap();
        let db = Arc::clone(&db_login_clone);
        let audit = Arc::clone(&audit_login_clone);
        
        // Block and safely resolve async futures from inside the synchronous Slint UI loop handle context
        tokio::spawn(async move {
            match db.authenticate_user(&username, &password).await {
                Ok(user) => {
                    slint::invoke_from_event_loop(move || {
                        ui.set_login_error("".into());
                        ui.set_current_user_name(user.username.clone().into());
                        ui.set_current_user_role(user.role.to_string().into());
                        ui.set_last_login(user.last_login.into());
                        ui.set_is_logged_in(true);
                    }).unwrap();

                    audit.log_action(&user, "OPERATOR_DB_LOGIN_SUCCESS", "CRITICAL").ok();
                }
                Err(err) => {
                    slint::invoke_from_event_loop(move || {
                        ui.set_login_error(err.into());
                    }).unwrap();
                }
            }
        });
    });

    let app_weak_reg = app.as_weak();
    let db_reg_clone = Arc::clone(&db);
    app.on_request_registration(move |username, password, role| {
        let ui = app_weak_reg.unwrap();
        let db = Arc::clone(&db_reg_clone);
        
        tokio::spawn(async move {
            match db.register_user(&username, &password, &role).await {
                Ok(_) => {
                    slint::invoke_from_event_loop(move || {
                        ui.set_login_error("Account Registered Successfully! Toggle view to sign in.".into());
                    }).unwrap();
                }
                Err(err) => {
                    slint::invoke_from_event_loop(move || {
                        ui.set_login_error(err.into());
                    }).unwrap();
                }
            }
        });
    });

    app.run()
}