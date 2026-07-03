//! IronVault Admin UI - Bootstrapper & Main Thread
//! Initializes the Slint UI framework and establishes connections
//! to the core security and database layers

// Reverted back to the native slint macro to fix the rust-analyzer macro-error completely

// FIXED: We drop include_modules! and load your markup explicitly via path to keep rust-analyzer quiet

// FIXED: Changed 'import' to 'export' to completely satisfy the Slint compiler specs
slint::slint!{
    export { AppWindow } from "ui/main.slint";
}

use slint::ComponentHandle;
use ironvault_core::audit::AuditLogger;
use ironvault_db::DbClient;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), slint::PlatformError> {
    println!("[BOOT] Engaging IronVault Core Security...");
    
    // 1. Enforce Hardware Anti-Debug Protection
    ironvault_core::security::enforce_anti_debug();
    
    // 2. Generate Irreversible Hardware ID
    let hwid = ironvault_core::licensing::generate_hwid();
    println!("[SECURITY] Computed System HWID: {}", hwid);

    // 3. Initialize Immutable Secure Audit Ledger Engine
    let audit_logger = Arc::new(AuditLogger::new("ironvault.audit.log"));

    // 4. Pass raw credentials straight to our custom db layer handler
    println!("[PGSQL] Connecting to data target host server cluster...");
    let db = match DbClient::connect_with_credentials(
        "localhost",
        5432,
        "AsstPro",
        "egpf_app_user",
        "P@ssw()rd",
    ).await {
        Ok(client) => Arc::new(client),
        Err(err) => {
            eprintln!("[FATAL DATABASE ACCESS ERROR]: {}", err);
            std::process::exit(1);
        }
    };
    println!("[SUCCESS] Database connections established. Schemas bound safely.");

    // 5. Launch UI Components
    let app = AppWindow::new()?;
    app.set_hwid_string(format!("HWID: {}", hwid).into());
    
    // --- LOGIN HANDLER BOUND SAFELY WITH THREAD ISOLATION ---
    let app_weak_login = app.as_weak();
    let db_login_clone = Arc::clone(&db);
    let audit_login_clone = Arc::clone(&audit_logger);
    let current_hwid_login = hwid.clone();
    
    app.on_request_authentication(move |username, password| {
        let ui_weak = app_weak_login.clone();
        let db = Arc::clone(&db_login_clone);
        let audit = Arc::clone(&audit_login_clone);
        let target_hwid = current_hwid_login.clone();
        
        tokio::spawn(async move {
            match db.authenticate_user(&username, &password, &target_hwid).await {
                Ok(user) => {
                    let ui_username = user.username.clone();
                    let ui_role = user.role.to_string();
                    let ui_last_login = user.last_login.clone();

                    let ui_weak_inner = ui_weak.clone();
                    slint::invoke_from_event_loop(move || {
                        let ui = ui_weak_inner.unwrap();
                        ui.set_login_error("".into());
                        ui.set_current_user_name(ui_username.into());
                        ui.set_current_user_role(ui_role.into());
                        ui.set_last_login(ui_last_login.into());
                        ui.set_is_logged_in(true);
                    }).unwrap();

                    audit.log_action(&user, "OPERATOR_DB_LOGIN_SUCCESS", "CRITICAL").ok();
                }
                Err(err) => {
                    let ui_weak_inner = ui_weak.clone();
                    slint::invoke_from_event_loop(move || {
                        let ui = ui_weak_inner.unwrap();
                        ui.set_login_error(err.into());
                    }).unwrap();
                }
            }
        });
    });

    // --- REGISTRATION HANDLER BOUND SAFELY WITH THREAD ISOLATION ---
    let app_weak_reg = app.as_weak();
    let db_reg_clone = Arc::clone(&db);
    let current_hwid_reg = hwid.clone();
    
    app.on_request_registration(move |username, password, role| {
        let ui_weak = app_weak_reg.clone();
        let db = Arc::clone(&db_reg_clone);
        let target_hwid = current_hwid_reg.clone();
        
        tokio::spawn(async move {
            match db.register_user(&username, &password, &role, &target_hwid).await {
                Ok(_) => {
                    slint::invoke_from_event_loop(move || {
                        let ui = ui_weak.unwrap();
                        ui.set_login_error("Account Registered Successfully! Toggle view to sign in.".into());
                    }).unwrap();
                }
                Err(err) => {
                    slint::invoke_from_event_loop(move || {
                        let ui = ui_weak.unwrap();
                        ui.set_login_error(err.into());
                    }).unwrap();
                }
            }
        });
    });

    app.run()
}