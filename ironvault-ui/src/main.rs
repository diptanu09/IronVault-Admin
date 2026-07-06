//! IronVault Admin UI - Bootstrapper & Main Thread
//! Initializes the Slint UI framework and establishes connections
//! to the core security and database layers

slint::include_modules!();

use slint::ComponentHandle;
use slint::{ModelRc, VecModel};
use ironvault_core::audit::AuditLogger;
use ironvault_db::DbClient;
use std::sync::Arc;
use std::rc::Rc;
use rand::Rng;

#[tokio::main]
async fn main() -> Result<(), slint::PlatformError> {
    println!("[BOOT] Engaging IronVault Core Security...");
    
    let hwid = ironvault_core::licensing::generate_hwid();
    ironvault_core::security::enforce_core_security_checks(&hwid);
    
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
    
    let mut rng = rand::thread_rng();
    let val1 = rng.gen_range(5..20);
    let val2 = rng.gen_range(2..10);
    app.set_captcha_q_main(format!("{} + {}", val1, val2).into());
    app.set_captcha_a_main((val1 + val2).to_string().into());
    app.set_login_error("".into());
    app.set_auth_screen_state("landing".into());

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

                    let core_user = ironvault_core::User {
                        id: Default::default(),
                        username: user.username.clone(),
                        role: user.role.clone().into(),
                        last_login: user.last_login.clone(),
                    };
                    audit.log_action(&core_user, "OPERATOR_DB_LOGIN_SUCCESS", "CRITICAL").ok();
                }
                Err(err) => {
                    slint::invoke_from_event_loop(move || {
                        ui_weak.unwrap().set_login_error(err.into());
                    }).unwrap();
                }
            }
        });
    });

    // --- STRUCT-BASED REGISTRATION PROCESSOR ---
    let app_weak_reg = app.as_weak();
    let db_reg_clone = Arc::clone(&db);
    let current_hwid_reg = hwid.clone();
    
    app.on_request_registration(move |username, password, first, middle, last, designation, section| {
        let ui_weak = app_weak_reg.clone();
        let db = Arc::clone(&db_reg_clone);
        let target_hwid = current_hwid_reg.clone();
        
        let f_str = first.to_string();
        let m_str = middle.to_string();
        let l_str = last.to_string();
        let desig_str = designation.to_string();
        let sec_str = section.to_string();
        
        tokio::spawn(async move {
            match db.register_user(&username, &password, &target_hwid, &f_str, &m_str, &l_str, &desig_str, &sec_str).await {
                Ok(_) => {
                    slint::invoke_from_event_loop(move || {
                        let ui = ui_weak.unwrap();
                        ui.set_auth_screen_state("landing".into()); 
                        ui.set_login_error("Registration submitted! Awaiting SuperAdmin verification approval.".into());
                        
                        // FIXED: Safely purge the correctly named memory tokens
                        ui.set_form_user("".into());
                        ui.set_form_pass("".into());
                        ui.set_form_captcha_login("".into());
                        ui.set_registration_fields(RegisterFormFields::default());
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

    // --- INTERFACE OPERATOR LOG OUT CHANNEL ---
    let app_weak_logout = app.as_weak();
    app.on_request_logout(move || {
        if let Some(ui) = app_weak_logout.upgrade() {
            ui.set_is_logged_in(false);
            ui.set_current_user_name("GUEST".into());
            ui.set_current_user_role("UNAUTHORIZED".into());
            ui.set_pending_notification_name("NONE".into());
            ui.set_login_error("".into());
            ui.set_auth_screen_state("landing".into());
            
            // FIXED: Safely purge the correctly named memory tokens
            ui.set_form_user("".into());
            ui.set_form_pass("".into());
            ui.set_form_captcha_login("".into());
            ui.set_registration_fields(RegisterFormFields::default());

            let mut fresh_rng = rand::thread_rng();
            let v1 = fresh_rng.gen_range(5..20);
            let v2 = fresh_rng.gen_range(2..10);
            ui.set_captcha_q_main(format!("{} + {}", v1, v2).into());
            ui.set_captcha_a_main((v1 + v2).to_string().into());
            
            println!("[SECURITY] Session terminated by user request. Session state scrubbed.");
        }
    });

    // --- OPERATOR USER MANAGEMENT TAB MATRIX LOGIC ROUTERS ---
    let app_weak_users = app.as_weak();
    let db_users_clone = Arc::clone(&db);
    
    app.on_load_users_list(move || {
        let ui_weak = app_weak_users.clone();
        let db = Arc::clone(&db_users_clone);
        
        tokio::spawn(async move {
            if let Ok(users) = db.get_active_users().await {
                let mut slint_users = Vec::new();
                for u in users {
                    slint_users.push(UserData {
                        username: u.username.into(),
                        role: u.role.into(),
                        last_login: u.last_login.into(),
                        full_name: u.full_name.into(),
                        designation: u.designation.into(),
                        expires_at: u.expires_at.into(),
                    });
                }
                
                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_active_users_list(ModelRc::from(Rc::new(VecModel::from(slint_users))));
                    }
                }).unwrap();
            }
        });
    });

    // --- EXTEND ACCESS LEASE AND ASSIGN PRIVILEGE ---
    let app_weak_lease = app.as_weak();
    let db_lease_clone = Arc::clone(&db);

    app.on_extend_user_lease(move |target_user, new_role, days_string| {
        let ui_weak = app_weak_lease.clone();
        let db = Arc::clone(&db_lease_clone);
        
        let target_str = target_user.to_string();
        let role_str = new_role.to_string();
        let days_valid: i32 = days_string.to_string().parse().unwrap_or(30);

        tokio::spawn(async move {
            if db.update_user_lease(&target_str, &role_str, days_valid).await.is_ok() {
                println!("[SECURITY] Access lease updated for operator {}: Assigned to {}, extended by {} days.", target_str, role_str, days_valid);
                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.invoke_load_users_list();
                    }
                }).unwrap();
            }
        });
    });

    // --- BAN USER PURGE CONTROL MATRIX CHANNEL ---
    let app_weak_ban = app.as_weak();
    let db_ban_clone = Arc::clone(&db);

    app.on_ban_user(move |target_user| {
        let ui_weak = app_weak_ban.clone();
        let db = Arc::clone(&db_ban_clone);
        let admin_name = ui_weak.unwrap().get_current_user_name().to_string();
        let target_str = target_user.to_string();

        tokio::spawn(async move {
            if db.ban_user(&admin_name, &target_str).await.is_ok() {
                println!("[SECURITY] Operator {} has BANNED user {}", admin_name, target_str);
                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.invoke_load_users_list();
                    }
                }).unwrap();
            }
        });
    });

    // --- SECURE TCP COMMAND CENTER LISTENER ---
    let network_secret = ironvault_core::crypto::derive_key("IronVault_Master_Node_Key_2026", "Salt_Secure_Comm");
    let decryptor = Arc::new(ironvault_core::crypto::Decryptor::new(&network_secret));
    let encryptor = Arc::new(ironvault_core::crypto::Encryptor::new(&network_secret));

    tokio::spawn(async move {
        match tokio::net::TcpListener::bind("0.0.0.0:9443").await {
            Ok(listener) => {
                println!("[NETWORK] TCP Command Center actively listening for encrypted nodes on port 9443");
                
                loop {
                    if let Ok((mut socket, addr)) = listener.accept().await {
                        println!("[NETWORK] Connection intercepted from node IP: {}", addr);
                        let dec = Arc::clone(&decryptor);
                        let enc = Arc::clone(&encryptor);

                        tokio::spawn(async move {
                            match ironvault_core::network::receive_secure_payload::<ironvault_core::network::NodeCommand>(&mut socket, &dec).await {
                                Ok(command) => {
                                    println!("[NETWORK] Validated Secure Payload from {}: {:?}", addr, command);

                                    let response = ironvault_core::network::NodeResponse::StatusData("Command execution authorized by Matrix.".to_string());
                                    if let Err(e) = ironvault_core::network::send_secure_payload(&mut socket, &enc, &response).await {
                                        println!("[NETWORK] Failed to transmit secure response: {}", e);
                                    }
                                }
                                Err(e) => {
                                    println!("[SECURITY FAULT] Handshake failed or payload expired from {}: {}", addr, e);
                                }
                            }
                        });
                    }
                }
            }
            Err(e) => println!("[NETWORK FAULT] Could not bind to TCP port 9443: {}", e),
        }
    });

    app.run()
}