// =========================================================================
// IronVault Core UI Event Handlers & Controllers (controllers.rs)
// =========================================================================

use ironvault_core::crypto;
use ironvault_core::database::postgres;
use crate::auth;

pub fn wire_ui_event_handlers(app: &slint::Weak<crate::AppWindow>, db_uri: String, machine_id: String) {
    let app_window = app.unwrap();
    
    app_window.set_hardware_id(machine_id.clone().into());
    app_window.set_selected_schema("ironvault".into());

    // -------------------------------------------------------------
    // 1. AUTHENTICATE LOGIN CALLBACK (Returns bool)
    // -------------------------------------------------------------
    let app_weak = app.clone();
    let db_uri_clone = db_uri.clone();
    let login_hw_id = machine_id.clone();
    
    app_window.on_attempt_login(move |username, password| {
        let ui = app_weak.unwrap();
        let user_str = username.as_str().trim().to_string();
        let pass_str = password.as_str().trim().to_string();

        ui.set_error_message("".into()); 

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let mut is_authorized = false;
        let mut assigned_role = "operator".to_string();

        runtime.block_on(async {
            match postgres::establish_secure_connection(&db_uri_clone).await {
                Ok(client) => {
                    let calculated_hash = crypto::secure_hash_password(&pass_str, &user_str);
                    let query = "SELECT password, role FROM ironvault.users WHERE username = $1";
                    
                    match client.query(query, &[&user_str]).await {
                        Ok(rows) if !rows.is_empty() => {
                            let db_hash: &str = rows[0].get(0);
                            let db_role: &str = rows[0].get(1);

                            if db_hash == calculated_hash {
                                is_authorized = true;
                                assigned_role = db_role.to_string();
                                
                                let log_query = "
                                    INSERT INTO ironvault.system_audit_logs (operator_username, action_type, details) 
                                    VALUES ($1, 'AUTH_SUCCESS', $2)";
                                let log_msg = format!("Authorized secure session token generated. HW: {}", login_hw_id);
                                let _ = client.execute(log_query, &[&user_str, &log_msg]).await;
                            } else {
                                let log_query = "INSERT INTO ironvault.system_audit_logs (operator_username, action_type, details) VALUES ($1, 'AUTH_FAILURE', 'Mismatched password hash submission.')";
                                let _ = client.execute(log_query, &[&user_str]).await;
                            }
                        }
                        Ok(_) => ui.set_error_message("User profile not registered inside ironvault namespace.".into()),
                        Err(e) => eprintln!("[DB CORRUPTION] Failed matching query attributes: {}", e),
                    }
                }
                Err(e) => eprintln!("[NET EXCEPTION] Remote SQL pool unreached: {}", e),
            }
        });

        if is_authorized {
            auth::establish_active_session(&user_str, &assigned_role, &login_hw_id);
            ui.set_session_user(user_str.into());
            ui.set_session_role(assigned_role.into());
            ui.set_app_status("OPERATOR SESSION COMPLETED AND BOUND".into());
            ui.set_app_status_color(slint::Color::from_rgb_u8(16, 185, 129));
            ui.set_is_logged_in(true);
        } else {
            ui.set_error_message("CRITICAL SECURITY ALERT: Authentication verification rejected.".into());
        }

        is_authorized // Cleanly returns bool back to Slint engine
    });

    // -------------------------------------------------------------
    // 2. PROVISION USER REGISTRATION CALLBACK (Returns bool)
    // -------------------------------------------------------------
    let app_weak = app.clone();
    let db_uri_clone = db_uri.clone();
    
    app_window.on_create_new_user(move |username, password, role| {
        let ui = app_weak.unwrap();
        let user_str = username.as_str().trim().to_string();
        let pass_str = password.as_str().trim().to_string();
        let role_str = role.as_str().trim().to_string();

        if user_str.is_empty() || pass_str.is_empty() {
            ui.set_error_message("Parameters cannot be empty strings.".into());
            return false;
        }

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let mut success = false;

        runtime.block_on(async {
            if let Ok(client) = postgres::establish_secure_connection(&db_uri_clone).await {
                let hashed_password = crypto::secure_hash_password(&pass_str, &user_str);
                let insert_query = "INSERT INTO ironvault.users (username, password, role) VALUES ($1, $2, $3)";
                
                match client.execute(insert_query, &[&user_str, &hashed_password, &role_str]).await {
                    Ok(_) => {
                        success = true;
                        let log_query = "INSERT INTO ironvault.system_audit_logs (operator_username, action_type, details) VALUES ($1, 'USER_PROVISIONED', 'Appended user node.')";
                        let _ = client.execute(log_query, &[&user_str, &"Success"]).await;
                    }
                    Err(e) => eprintln!("[DB RESTRICTION] User write rejected: {}", e),
                }
            }
        });

        if success {
            ui.set_error_message("Account successfully registered to core cluster!".into());
        } else {
            ui.set_error_message("Identity assignment rejected: Duplicate profile profile detected.".into());
        }

        success // Cleanly returns bool back to Slint engine
    });

    // -------------------------------------------------------------
    // 3. CRYPTOGRAPHIC KEY VALIDATION CHECK
    // -------------------------------------------------------------
    let app_weak = app.clone();
    app_window.on_verify_supervisor_keys(move |op_key, sv_key| {
        let ui = app_weak.unwrap();
        let op_valid = crypto::verify_authority_signature(op_key.as_str().trim());
        let sv_valid = crypto::verify_authority_signature(sv_key.as_str().trim());

        if op_valid && sv_valid {
            ui.set_crypto_signature_status("✅ PRIVILEGE INTERLOCK ENGAGED".into());
            ui.set_app_status("DUAL-KEY REPLICATION CONTEXT AUTHORIZED".into());
            ui.set_app_status_color(slint::Color::from_rgb_u8(16, 185, 129));
        } else {
            ui.set_crypto_signature_status("❌ SIGNATURE VERIFICATION REFUSED".into());
            ui.set_app_status("VERIFICATION ERROR: CERTIFICATE KEYS MISMATCH".into());
            ui.set_app_status_color(slint::Color::from_rgb_u8(239, 68, 68));
        }
    });

    // -------------------------------------------------------------
    // 4. DISCONNECT / SESSION INVALIDATION DISMISSAL
    // -------------------------------------------------------------
    let app_weak = app.clone();
    app_window.on_execute_downgrade_pump(move |schema_str, _dir| {
        let ui = app_weak.unwrap();
        ui.set_app_status(format!("REPLICATION SEQUENCE COMPILED ON: {}", schema_str).into());
        ui.set_app_status_color(slint::Color::from_rgb_u8(16, 185, 129));
    });

    let app_weak = app.clone();
    app_window.on_trigger_logout(move || {
        let ui = app_weak.unwrap();
        auth::invalidate_session();
        ui.set_is_logged_in(false);
        ui.set_session_user("".into());
        ui.set_session_role("Auditor".into());
        ui.set_app_status("SYSTEM ONLINE // RE-LOGIN REQUIRED".into());
        ui.set_app_status_color(slint::Color::from_rgb_u8(100, 116, 139));
    });
}