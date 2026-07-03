//! IronVault Admin UI - Bootstrapper & Main Thread
//! Initializes the Slint UI framework and establishes connections
//! to the core security and database layers

slint::include_modules!();

use slint::ComponentHandle;
use ironvault_core::audit::AuditLogger;
use ironvault_db::DbClient;
use std::sync::Arc;
use rand::Rng;

#[tokio::main]
async fn main() -> Result<(), slint::PlatformError> {
    println!("[BOOT] Engaging IronVault Core Security...");
    
    ironvault_core::security::enforce_anti_debug();
    let hwid = ironvault_core::licensing::generate_hwid();
    println!("[SECURITY] Computed System HWID: {}", hwid);

    let audit_logger = Arc::new(AuditLogger::new("ironvault.audit.log"));

    println!("[PGSQL] Connecting to data target host server cluster... ");
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

    let app = AppWindow::new()?;
    app.set_hwid_string(format!("HWID: {}", hwid).into());
    
    let mut rng = rand::thread_rng();
    let val1 = rng.gen_range(5..20);
    let val2 = rng.gen_range(2..10);
    let captcha_q = format!("{} + {}", val1, val2);
    let captcha_a = (val1 + val2).to_string();
    
    app.set_captcha_q_main(captcha_q.into());
    app.set_captcha_a_main(captcha_a.into());
    app.set_login_error("".into());

    // --- REAL-TIME POLLING BACKGROUND TIMEOUT LOOP ---
    let app_weak_poll = app.as_weak();
    let db_poll_clone = Arc::clone(&db);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(2500)).await;

            let db_result = db_poll_clone.fetch_next_pending_user().await;
            let app_weak_inner = app_weak_poll.clone();

            slint::invoke_from_event_loop(move || {
                if let Some(ui) = app_weak_inner.upgrade() {
                    let role = ui.get_current_user_role().to_string().to_lowercase();
                    let is_superadmin = role.contains("super") && role.contains("admin");

                    if ui.get_is_logged_in() && is_superadmin {
                        match db_result {
                            Ok(Some(pending_name)) => {
                                ui.set_pending_notification_name(pending_name.into());
                                ui.set_polling_error_msg("".into());
                            }
                            Ok(None) => {
                                ui.set_pending_notification_name("NONE".into());
                                ui.set_polling_error_msg("".into());
                            }
                            Err(err) => {
                                println!("[POLLING ERROR]: {}", err);
                                ui.set_polling_error_msg(err.into());
                                ui.set_pending_notification_name("NONE".into());
                            }
                        }
                    }
                }
            }).ok();
        }
    });

    // --- AUTHENTICATION DISPATCHER ---
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

                    slint::invoke_from_event_loop(move || {
                        let ui = ui_weak.unwrap();
                        ui.set_login_error("".into());
                        ui.set_current_user_name(ui_username.into());
                        ui.set_current_user_role(ui_role.into());
                        ui.set_last_login(ui_last_login.into());
                        ui.set_is_logged_in(true);
                        ui.set_active_tab("overview".into());
                    }).unwrap();

                    audit.log_action(&user, "OPERATOR_DB_LOGIN_SUCCESS", "CRITICAL").ok();
                }
                Err(err) => {
                    slint::invoke_from_event_loop(move || {
                        ui_weak.unwrap().set_login_error(err.into());
                    }).unwrap();
                }
            }
        });
    });

    // --- REGISTRATION PENDING REQUEST ROUTER ---
    let app_weak_reg = app.as_weak();
    let db_reg_clone = Arc::clone(&db);
    let current_hwid_reg = hwid.clone();
    
    app.on_request_registration(move |username, password| {
        let ui_weak = app_weak_reg.clone();
        let db = Arc::clone(&db_reg_clone);
        let target_hwid = current_hwid_reg.clone();
        
        tokio::spawn(async move {
            match db.register_user(&username, &password, &target_hwid).await {
                Ok(_) => {
                    slint::invoke_from_event_loop(move || {
                        let ui = ui_weak.unwrap();
                        ui.set_login_error("Account requested! Awaiting SuperAdmin role assignment.".into());
                    }).unwrap();
                }
                Err(err) => {
                    slint::invoke_from_event_loop(move || {
                        ui_weak.unwrap().set_login_error(err.into());
                    }).unwrap();
                }
            }
        });
    });

    // --- SUPERADMIN OPERATOR APPROVAL MATRIX ---
    let app_weak_appr = app.as_weak();
    let db_appr_clone = Arc::clone(&db);
    
    app.on_approve_pending_operator(move |target_user, assigned_role| {
        let ui_weak = app_weak_appr.clone();
        let db = Arc::clone(&db_appr_clone);
        let admin_name = ui_weak.unwrap().get_current_user_name().to_string();
        
        tokio::spawn(async move {
            match db.approve_user(&admin_name, &target_user, &assigned_role).await {
                Ok(_) => {
                    slint::invoke_from_event_loop(move || {
                        let ui = ui_weak.unwrap();
                        ui.set_pending_notification_name("NONE".into());
                    }).unwrap();
                }
                Err(err) => {
                    println!("[ERROR] Admin validation fail: {}", err);
                }
            }
        });
    });

    // --- SUPERADMIN OPERATOR DENIAL DISPATCHER ---
    let app_weak_deny = app.as_weak();
    let db_deny_clone = Arc::clone(&db);
    
    app.on_deny_pending_operator(move |target_user| {
        let ui_weak = app_weak_deny.clone();
        let db = Arc::clone(&db_deny_clone);
        let admin_name = ui_weak.unwrap().get_current_user_name().to_string();
        
        tokio::spawn(async move {
            match db.deny_user(&admin_name, &target_user).await {
                Ok(_) => {
                    slint::invoke_from_event_loop(move || {
                        let ui = ui_weak.unwrap();
                        ui.set_pending_notification_name("NONE".into());
                    }).unwrap();
                }
                Err(err) => {
                    println!("[ERROR] Admin denial execution fail: {}", err);
                }
            }
        });
    });

    // --- FIXED: INTERFACE OPERATOR LOG OUT CHANNEL ---
    let app_weak_logout = app.as_weak();
    app.on_request_logout(move || {
        if let Some(ui) = app_weak_logout.upgrade() {
            // Reset state variables back to guest defaults cleanly
            ui.set_is_logged_in(false);
            ui.set_current_user_name("GUEST".into());
            ui.set_current_user_role("UNAUTHORIZED".into());
            ui.set_pending_notification_name("NONE".into());
            ui.set_login_error("".into());

            // Refresh the verification CAPTCHA to prevent session reuse replays
            let mut fresh_rng = rand::thread_rng();
            let v1 = fresh_rng.gen_range(5..20);
            let v2 = fresh_rng.gen_range(2..10);
            ui.set_captcha_q_main(format!("{} + {}", v1, v2).into());
            ui.set_captcha_a_main((v1 + v2).to_string().into());
            
            println!("[SECURITY] Session terminated by user request. Session state scrubbed.");
        }
    });

    app.run()
}