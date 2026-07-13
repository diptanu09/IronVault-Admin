//! IronVault Admin UI - Bootstrapper & Main Thread
//! Initializes the Slint UI framework and establishes connections
//! to the core security and database layers

slint::include_modules!();
use slint::ComponentHandle;
use slint::{ModelRc, VecModel};
use ironvault_core::audit::AuditLogger;
use ironvault_db::{DbClient, OracleConnection};
use std::sync::Arc;
use std::rc::Rc;
use rand::Rng;
use sqlx::Row; 

#[tokio::main]
async fn main() -> Result<(), slint::PlatformError> {
    println!("[BOOT] Engaging IronVault Core Security...");
    
    let hwid = ironvault_core::licensing::generate_hwid();
    ironvault_core::security::enforce_core_security_checks(&hwid);
    let audit_logger = Arc::new(AuditLogger::new("ironvault.audit.log"));

    let db = match DbClient::connect_with_credentials("localhost", 5432, "AsstPro", "egpf_app_user", "P@ssw()rd123").await {
        Ok(client) => Arc::new(client),
        Err(err) => { eprintln!("[FATAL DATABASE ERROR]: {}", err); std::process::exit(1); }
    };

    let oracle_client = match OracleConnection::new() {
        Ok(client) => Arc::new(client),
        Err(e) => { eprintln!("[FATAL] Oracle matrix allocation failure: {:?}", e); std::process::exit(1); }
    };

    let app = AppWindow::new()?;
    app.set_hwid_string(format!("HWID: {}", hwid).into());
    
    let mut rng = rand::thread_rng();
    let (v1, v2) = (rng.gen_range(5..20), rng.gen_range(2..10));
    app.set_captcha_q_main(format!("{} + {}", v1, v2).into());
    app.set_captcha_a_main((v1 + v2).to_string().into());
    
    let app_weak_login = app.as_weak();
    let db_login_clone = Arc::clone(&db);
    let audit_login_clone = Arc::clone(&audit_logger);
    let current_hwid_login = hwid.clone();
    
    app.on_request_authentication(move |username, password| {
        let ui_weak = app_weak_login.clone();
        let db = Arc::clone(&db_login_clone);
        let audit = Arc::clone(&audit_login_clone);
        let target_hwid = current_hwid_login.clone();
        let u_name = username.to_string();
        let plain_password = password.to_string();
        
        tokio::spawn(async move {
            match db.authenticate_user(&u_name, &plain_password, &target_hwid).await {
                Ok(user) => {
                    let pool = db.get_pool().clone();
                    let profile_query = sqlx::query("SELECT full_name, designation, expires_at, section FROM ironvault.users WHERE username = $1")
                        .bind(&u_name)
                        .fetch_optional(&pool).await.unwrap_or(None);
                        
                    let mut full_name = "System Operator".to_string();
                    let mut designation = "Assigned Personnel".to_string();
                    let mut expires = "Unknown".to_string();
                    let mut allowed_schemas_str = "".to_string();

                    if let Some(row) = profile_query {
                        full_name = row.try_get("full_name").unwrap_or(full_name);
                        designation = row.try_get("designation").unwrap_or(designation);
                        allowed_schemas_str = row.try_get("section").unwrap_or(allowed_schemas_str).to_lowercase();
                        
                        if let Ok(dt) = row.try_get::<chrono::DateTime<chrono::Utc>, _>("expires_at") {
                            expires = dt.format("%Y-%m-%d").to_string();
                        }
                    }

                    let is_super = user.role.to_lowercase().contains("superadmin");
                    let mut schema_str_display = if is_super { "ALL SYSTEMS AUTHORIZED (SUPERADMIN)".to_string() } else { allowed_schemas_str.clone() };
                    if schema_str_display.trim().is_empty() { schema_str_display = "NO SCHEMAS ASSIGNED".to_string(); }

                    let access = SchemaAccessState {
                        gpffp: is_super || allowed_schemas_str.contains("gpffp"),
                        vlcs: is_super || allowed_schemas_str.contains("vlcs"),
                        agtall: is_super || allowed_schemas_str.contains("agtall"),
                        agdak: is_super || allowed_schemas_str.contains("agdak"),
                        sai_agartala: is_super || allowed_schemas_str.contains("sai_agartala") || allowed_schemas_str.contains("sai"),
                        pendak: is_super || allowed_schemas_str.contains("pendak"),
                        penindex: is_super || allowed_schemas_str.contains("penindex") || allowed_schemas_str.contains("penidx"),
                    };

                    let ui_username = user.username.clone();
                    let ui_role = user.role.to_string();
                    
                    let avatar_path = std::path::Path::new("./storage/avatars/").join(format!("{}.png", ui_username));

                    slint::invoke_from_event_loop(move || {
                        let ui = ui_weak.unwrap();
                        ui.set_login_error("".into());
                        ui.set_current_user_name(ui_username.into());
                        ui.set_current_user_role(ui_role.into());
                        ui.set_current_user_full_name(full_name.into());
                        ui.set_current_user_designation(designation.into());
                        ui.set_current_user_expires(expires.into());
                        ui.set_current_user_schemas_string(schema_str_display.into());
                        ui.set_schema_access(access);
                        
                        if avatar_path.exists() {
                            if let Ok(slint_img) = slint::Image::load_from_path(&avatar_path) {
                                ui.set_current_avatar_image(slint_img);
                                ui.set_current_avatar_loaded(true);
                            } else {
                                ui.set_current_avatar_loaded(false);
                            }
                        } else {
                            ui.set_current_avatar_loaded(false);
                        }
                        
                        ui.set_is_logged_in(true);
                        ui.set_show_welcome_popup(true);
                        ui.set_active_tab("overview".into());
                    }).unwrap();
                    
                    let core_user = ironvault_core::auth::User { id: Default::default(), username: user.username.clone(), role: user.role.clone().into(), last_login: user.last_login.clone() };
                    audit.log_action(&core_user, "OPERATOR_DB_LOGIN_SUCCESS", "CRITICAL").ok();
                }
                Err(err) => slint::invoke_from_event_loop(move || { ui_weak.unwrap().set_login_error(err.into()); }).unwrap(),
            }
        });
    });

    // --- SECURE SYSTEM OPERATOR ENROLLMENT CHANNELS HOOK ---
    let app_weak_reg = app.as_weak();
    let db_reg_clone = Arc::clone(&db);
    let current_hwid_reg = hwid.clone();
    app.on_request_registration(move |username, secret, first, middle, last, desg, sect| {
        let ui_weak = app_weak_reg.clone();
        let db = Arc::clone(&db_reg_clone);
        let hwid = current_hwid_reg.clone();
        let u_name = username.to_string();
        let f_name = first.to_string();
        let m_name = middle.to_string();
        let l_name = last.to_string();
        let d_name = desg.to_string();
        let s_name = sect.to_string();
        
        // SECURED: Pass word token undergoes cryptographic salting hashing routine before transmission
        let secure_hashed_password = ironvault_core::crypto::hash_password(&secret.to_string(), &u_name);

        tokio::spawn(async move {
            match db.register_user(&u_name, &secure_hashed_password, &hwid, &f_name, &m_name, &l_name, &d_name, &s_name).await {
                Ok(_) => slint::invoke_from_event_loop(move || {
                    let ui = ui_weak.unwrap();
                    ui.set_login_error("".into());
                    ui.set_auth_screen_state("login".into());
                    ui.set_op_is_error(false);
                    ui.set_op_status_msg("Enrollment request transmitted successfully. Awaiting SuperAdmin verification token sign.".into());
                }).unwrap(),
                Err(e) => slint::invoke_from_event_loop(move || {
                    let ui = ui_weak.unwrap();
                    ui.set_login_error(format!("Enrollment Fault: {}", e).into());
                }).unwrap(),
            }
        });
    });

    // --- BACKGROUND ACCESS REQUEST SIGNALS POLLING THREAD ---
    let app_weak_poll = app.as_weak();
    let db_poll_clone = Arc::clone(&db);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            
            let should_poll = {
                if let Some(ui) = app_weak_poll.upgrade() {
                    ui.get_is_logged_in() && ui.get_current_user_role().to_string().contains("SuperAdmin")
                } else {
                    false
                }
            }; 

            if should_poll {
                if let Ok(pending_operator) = db_poll_clone.fetch_next_pending_user().await {
                    let app_weak_copy = app_weak_poll.clone();
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui_layer) = app_weak_copy.upgrade() {
                            ui_layer.set_pending_notification_name(pending_operator.unwrap_or_else(|| "NONE".to_string()).into());
                        }
                    }).unwrap();
                }
            }
        }
    });

    let app_weak_approve = app.as_weak();
    let db_approve_clone = Arc::clone(&db);
    app.on_approve_pending_operator(move |target_user, role_str| {
        let ui_weak = app_weak_approve.clone();
        let db = Arc::clone(&db_approve_clone);
        let target = target_user.to_string();
        let assigned_role = role_str.to_string();
        tokio::spawn(async move {
            if db.approve_user("ADMIN", &target, &assigned_role).await.is_ok() {
                slint::invoke_from_event_loop(move || {
                    let ui = ui_weak.unwrap();
                    ui.set_pending_notification_name("NONE".into());
                    ui.set_op_is_error(false);
                    ui.set_op_status_msg("SUCCESS: Access registration token signed into active matrix.".into());
                }).unwrap();
            }
        });
    });

    let app_weak_deny = app.as_weak();
    let db_deny_clone = Arc::clone(&db);
    app.on_deny_pending_operator(move |target_user| {
        let ui_weak = app_weak_deny.clone();
        let db = Arc::clone(&db_deny_clone);
        let target = target_user.to_string();
        tokio::spawn(async move {
            if db.deny_user("ADMIN", &target).await.is_ok() {
                slint::invoke_from_event_loop(move || {
                    let ui = ui_weak.unwrap();
                    ui.set_pending_notification_name("NONE".into());
                    ui.set_op_is_error(true);
                    ui.set_op_status_msg("Purged: Verification request discarded successfully.".into());
                }).unwrap();
            }
        });
    });

    // --- USER MANAGEMENT CONTROLS Matrix ---
    let app_weak_users = app.as_weak();
    let db_users_clone = Arc::clone(&db);
    app.on_load_users_list(move || {
        let ui_weak = app_weak_users.clone();
        let db = Arc::clone(&db_users_clone);
        tokio::spawn(async move {
            let pool = db.get_pool().clone();
            let query = "SELECT username, role, full_name, designation, TO_CHAR(expires_at, 'YYYY-MM-DD') as exp_date, section FROM ironvault.users WHERE status = 'ACTIVE'";
            if let Ok(rows) = sqlx::query(query).fetch_all(&pool).await {
                let mut slint_users = Vec::new();
                for r in rows {
                    let u: String = r.try_get("username").unwrap_or_default();
                    let ro: String = r.try_get("role").unwrap_or_default();
                    let f: String = r.try_get("full_name").unwrap_or_default();
                    let d: String = r.try_get("designation").unwrap_or_default();
                    let e_dt: String = r.try_get("exp_date").unwrap_or_else(|_| "Unknown".to_string());
                    let s: String = r.try_get("section").unwrap_or_default();
                    slint_users.push(UserData { username: u.into(), role: ro.into(), last_login: "ACTIVE".into(), full_name: f.into(), designation: d.into(), expires_at: e_dt.into(), allowed_schemas: s.into() });
                }
                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_active_users_list(ModelRc::from(Rc::new(VecModel::from(slint_users))));
                    }
                }).unwrap();
            }
        });
    });

    let app_weak_lease = app.as_weak();
    let db_lease_clone = Arc::clone(&db);
    app.on_extend_user_lease(move |target_user, new_role, days_string, new_schemas| {
        let ui_weak = app_weak_lease.clone();
        let db = Arc::clone(&db_lease_clone);
        let user_str = target_user.to_string();
        let role_str = new_role.to_string();
        let schema_str = new_schemas.to_string().to_lowercase();
        let days_valid: i32 = days_string.to_string().parse().unwrap_or(30);
        tokio::spawn(async move {
            if db.update_user_lease(&user_str, &role_str, days_valid).await.is_ok() {
                let pool = db.get_pool().clone();
                let _ = sqlx::query("UPDATE ironvault.users SET section = $1 WHERE username = $2").bind(&schema_str).bind(&user_str).execute(&pool).await;
                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.invoke_load_users_list();
                    }
                }).unwrap();
            }
        });
    });

    let app_weak_ban = app.as_weak();
    let db_ban_clone = Arc::clone(&db);
    app.on_ban_user(move |target_user| {
        let ui_weak = app_weak_ban.clone();
        let db = Arc::clone(&db_ban_clone);
        let user_str = target_user.to_string();
        tokio::spawn(async move {
            if db.ban_user("SUPERADMIN", &user_str).await.is_ok() {
                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.invoke_load_users_list();
                        ui.set_op_is_error(true);
                        ui.set_op_status_msg("REVOCATION SUCCESS: Operator credentials blacklisted and purged from registry.".into());
                    }
                }).unwrap();
            }
        });
    });

    // --- CRYPTOGRAPHIC PASSWORD RESET RUNTIME CALLBACK HOOK ---
    // --- SECURE SYSTEM OPERATOR CREDENTIAL RECOVERY OVERRIDE ---
    let app_weak_reset = app.as_weak();
    let db_reset_clone = Arc::clone(&db);
    app.on_reset_user_password(move |target_user| {
        let ui_weak = app_weak_reset.clone();
        let db = Arc::clone(&db_reset_clone);
        let user_str = target_user.to_string();
        
        tokio::spawn(async move {
            let pool = db.get_pool().clone();
            let default_temp_pass = "IronVault@2026";
            let secure_hashed_pass = ironvault_core::crypto::hash_password(default_temp_pass, &user_str);
            
            let query = "UPDATE ironvault.users SET password = $1 WHERE username = $2 AND status = 'ACTIVE'";
            match sqlx::query(query)
                .bind(&secure_hashed_pass)
                .bind(&user_str)
                .execute(&pool)
                .await 
            {
                Ok(_) => slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        // UNLOCKED: Pushes an active visual feedback message onto the UI matrix
                        ui.set_op_is_error(false);
                        ui.set_op_status_msg(format!("🛡️ OVERRIDE SUCCESS: Password for @{} has been reset to: {}", user_str, default_temp_pass).into());
                        ui.invoke_load_users_list();
                    }
                }).unwrap(),
                Err(e) => slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_op_is_error(true);
                        ui.set_op_status_msg(format!("🚨 DATABASE OVERRIDE WRITE FAULT: {}", e).into());
                    }
                }).unwrap(),
            }
        });
    });

    // --- SECURE AVATAR CARRIER ENGINE ---
    let app_weak_pic = app.as_weak();
    app.on_request_profile_pic_update(move || {
        let ui = app_weak_pic.unwrap();
        let username = ui.get_current_user_name().to_string();
        let file_picker = rfd::FileDialog::new()
            .set_title("Select Operator Profile Image")
            .add_filter("Supported Images (*.png, *.jpg, *.jpeg)", &["png", "jpg", "jpeg"])
            .pick_file();
        if let Some(path) = file_picker {
            if let Ok(metadata) = std::fs::metadata(&path) {
                if metadata.len() > 2 * 1024 * 1024 {
                    ui.set_op_is_error(true); ui.set_op_status_msg("Security Fault: File size exceeds maximum 2MB limit.".into());
                    return;
                }
            } else { return; }
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
            if ext != "png" && ext != "jpg" && ext != "jpeg" {
                ui.set_op_is_error(true); ui.set_op_status_msg("Security Fault: Forbidden image file extension.".into());
                return;
            }
            let storage_dir = std::path::Path::new("./storage/avatars/");
            let _ = std::fs::create_dir_all(storage_dir);
            let target_destination = storage_dir.join(format!("{}.png", username));
            if std::fs::copy(&path, &target_destination).is_ok() {
                if let Ok(slint_img) = slint::Image::load_from_path(&target_destination) {
                    ui.set_current_avatar_image(slint_img); ui.set_current_avatar_loaded(true);
                    ui.set_op_is_error(false); ui.set_op_status_msg("SUCCESS: Profile picture updated successfully.".into());
                }
            }
        }
    });

    let app_weak_logout = app.as_weak();
    app.on_request_logout(move || {
        if let Some(ui) = app_weak_logout.upgrade() {
            ui.set_is_logged_in(false); ui.set_current_user_name("GUEST".into()); ui.set_auth_screen_state("landing".into());
            ui.set_form_user("".into()); ui.set_form_pass("".into()); ui.set_form_captcha_login("".into());
            let mut fresh_rng = rand::thread_rng();
            let (new_v1, new_v2) = (fresh_rng.gen_range(5..20), fresh_rng.gen_range(2..10));
            ui.set_captcha_q_main(format!("{} + {}", new_v1, new_v2).into());
            ui.set_captcha_a_main((new_v1 + new_v2).to_string().into());
        }
    });

    // --- GPFFP CASE DISCOVERY MATRIX LOGIC ---
    let app_weak_find = app.as_weak();
    let oracle_find = Arc::clone(&oracle_client);
    app.on_request_find_gpf_case(move |regd_no| {
        let ui_weak = app_weak_find.clone(); let oracle = Arc::clone(&oracle_find); let r_no = regd_no.to_string();
        tokio::spawn(async move {
            match oracle.gpffp_find_case_profile(&r_no).await {
                Ok(Some(record)) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_gpf_case_found(true); ui.set_op_is_error(false); ui.set_op_status_msg("SUCCESS: GPF Case entity located.".into());
                            ui.set_active_gpf_case(GpfCaseDetails {
                                regd_no: record.regd_no.into(), holder_name: record.acc_holder_name.into(), series_id: record.series_id.into(),
                                account_no: record.account_no.into(), balance: record.closing_balance.to_string().into(), status: record.current_status.into(),
                            });
                        }
                    }).unwrap();
                }
                Ok(None) => { slint::invoke_from_event_loop(move || { let ui = ui_weak.upgrade(); if let Some(ui) = ui_weak.upgrade() { ui.set_gpf_case_found(false); ui.set_op_is_error(true); ui.set_op_status_msg("Discovery Fault: No matching records found.".into()); } }).unwrap(); }
                Err(e) => { slint::invoke_from_event_loop(move || { let ui = ui_weak.upgrade(); if let Some(ui) = ui_weak.upgrade() { ui.set_gpf_case_found(false); ui.set_op_is_error(true); ui.set_op_status_msg(format!("ORACLE TRANSACTION FAILURE: {:?}", e).into()); } }).unwrap(); }
            }
        });
    });

    let app_weak_op1 = app.as_weak(); let oracle_op1 = Arc::clone(&oracle_client);
    app.on_request_delete_full_case(move |regd_no, series_id, account_no| {
        let ui_weak = app_weak_op1.clone(); let oracle = Arc::clone(&oracle_op1); let (r_no, s_id, a_no) = (regd_no.to_string(), series_id.to_string(), account_no.to_string());
        tokio::spawn(async move {
            match oracle.gpffp_delete_full_case(&r_no, &s_id, &a_no).await {
                Ok(_) => { slint::invoke_from_event_loop(move || { if let Some(ui) = ui_weak.upgrade() { ui.set_op_is_error(false); ui.set_op_status_msg("SUCCESS: GPFFP Final payment case completely cleared.".into()); ui.set_op_regd_no("".into()); ui.set_op_series_id("".into()); ui.set_op_account_no("".into()); ui.set_gpf_case_found(false); } }).unwrap(); }
                Err(e) => { slint::invoke_from_event_loop(move || { if let Some(ui) = ui_weak.upgrade() { ui.set_op_is_error(true); ui.set_op_status_msg(format!("GPFFP TRANSACTION FAILURE: {}", e).into()); } }).unwrap(); }
            }
        });
    });

    let app_weak_op2 = app.as_weak(); let oracle_op2 = Arc::clone(&oracle_client);
    app.on_request_delete_application(move |regd_no| {
        let ui_weak = app_weak_op2.clone(); let oracle = Arc::clone(&oracle_op2); let r_no = regd_no.to_string();
        tokio::spawn(async move {
            match oracle.gpffp_delete_from_application(&r_no).await {
                Ok(_) => { slint::invoke_from_event_loop(move || { if let Some(ui) = ui_weak.upgrade() { ui.set_op_is_error(false); ui.set_op_status_msg("SUCCESS: GPFFP Application Record purged.".into()); ui.set_op_regd_no("".into()); ui.set_gpf_case_found(false); } }).unwrap(); }
                Err(e) => { slint::invoke_from_event_loop(move || { if let Some(ui) = ui_weak.upgrade() { ui.set_op_is_error(true); ui.set_op_status_msg(format!("GPFFP TRANSACTION FAILURE: {}", e).into()); } }).unwrap(); }
            }
        });
    });

    let app_weak_op3 = app.as_weak(); let oracle_op3 = Arc::clone(&oracle_client);
    app.on_request_delete_precalc(move |regd_no| {
        let ui_weak = app_weak_op3.clone(); let oracle = Arc::clone(&oracle_op3); let r_no = regd_no.to_string();
        tokio::spawn(async move {
            match oracle.gpffp_delete_from_pre_calculation(&r_no).await {
                Ok(_) => { slint::invoke_from_event_loop(move || { if let Some(ui) = ui_weak.upgrade() { ui.set_op_is_error(false); ui.set_op_status_msg("SUCCESS: GPFFP Pre-Calculation values updated.".into()); ui.set_op_regd_no("".into()); ui.set_gpf_case_found(false); } }).unwrap(); }
                Err(e) => { slint::invoke_from_event_loop(move || { if let Some(ui) = ui_weak.upgrade() { ui.set_op_is_error(true); ui.set_op_status_msg(format!("GPFFP TRANSACTION FAILURE: {}", e).into()); } }).unwrap(); }
            }
        });
    });

    // Sub-stubs
    app.on_request_update_gpf_status(|_, _| {}); app.on_request_vlcs_get_ddo(|_| {}); app.on_request_vlcs_update_ddo(|_| {}); app.on_request_vlcs_get_emp(|_| {}); app.on_request_vlcs_update_emp(|_, _| {});

    // --- LIVE AUTO-LOOKUP HOOK CONTEXT ---
    let app_weak_dak_find = app.as_weak();
    let oracle_dak_find = Arc::clone(&oracle_client);
    app.on_request_find_pension_dak_meta(move |search_app_num| {
        let ui = app_weak_dak_find.unwrap(); let oracle = Arc::clone(&oracle_dak_find); let target_app = search_app_num.to_string().trim().to_string();
        if target_app.is_empty() {
            ui.set_dak_ppo("".into()); ui.set_dak_fppo("".into()); ui.set_dak_gpo("".into()); ui.set_dak_cpo("".into());
            return;
        }
        let ui_weak = app_weak_dak_find.clone();
        tokio::spawn(async move {
            match oracle.pendak_fetch_auth_details(&target_app).await {
                Ok(Some(details)) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui_handle) = ui_weak.upgrade() {
                            ui_handle.set_dak_ppo(if details.ppo_no.is_empty() { "N/A".to_string() } else { details.ppo_no }.into());
                            ui_handle.set_dak_fppo(if details.fppo_no.is_empty() { "N/A".to_string() } else { details.fppo_no }.into());
                            ui_handle.set_dak_gpo(if details.gpo_no.is_empty() { "N/A".to_string() } else { details.gpo_no }.into());
                            ui_handle.set_dak_cpo(if details.cpo_no.is_empty() { "N/A".to_string() } else { details.cpo_no }.into());
                            ui_handle.set_op_is_error(false); ui_handle.set_op_status_msg("SUCCESS: Associated pension authorities auto-fetched.".into());
                        }
                    }).unwrap();
                }
                Ok(None) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui_handle) = ui_weak.upgrade() {
                            ui_handle.set_dak_ppo("N/A".into()); ui_handle.set_dak_fppo("N/A".into()); ui_handle.set_dak_gpo("N/A".into()); ui_handle.set_dak_cpo("N/A".into());
                        }
                    }).unwrap();
                }
                Err(e) => { slint::invoke_from_event_loop(move || { if let Some(ui_handle) = ui_weak.upgrade() { ui_handle.set_op_is_error(true); ui_handle.set_op_status_msg(format!("Auto-Fetch Error: {}", e).into()); } }).unwrap(); }
            }
        });
    });

    // --- PENSION DAK SYSTEM: OUTWARD MASTER RECORD ENTRY SUBMISSION ---
    let app_weak_dak = app.as_weak();
    let oracle_dak = Arc::clone(&oracle_client);
    app.on_request_submit_outward_dak(move || {
        let ui = app_weak_dak.unwrap(); let oracle = Arc::clone(&oracle_dak);
        
        let app_num = ui.get_entry_app_num().to_string().trim().to_string();
        let letter_no = ui.get_entry_letter_no().to_string().trim().to_string();
        let ppo = ui.get_dak_ppo().to_string();
        let fppo = ui.get_dak_fppo().to_string();
        let gpo = ui.get_dak_gpo().to_string().trim().to_string();
        let cpo = ui.get_dak_cpo().to_string().trim().to_string();
        let section = ui.get_entry_section().to_string().trim().to_string();
        let subject = ui.get_entry_subject().to_string().trim().to_string();
        let copies_str = ui.get_entry_no_of_copies().to_string();
        let copies_count: i32 = copies_str.parse().unwrap_or(1);

        if app_num.is_empty() || letter_no.is_empty() || section.is_empty() || subject.is_empty() {
            ui.set_op_is_error(true); ui.set_op_status_msg("Validation Fault: All fields marked with * are strictly mandatory.".into());
            return;
        }

        let mut recipients = Vec::new();
        if copies_count >= 1 {
            recipients.push(ironvault_db::oracle::DakRecipientDetail { addressee: ui.get_dak_adr_1().to_string(), barcode: ui.get_dak_bar_1().to_string(), sent_by: ui.get_dak_sent_1().to_string(), service_book: ui.get_dak_sb_1().to_string() });
        }
        if copies_count >= 2 && (copies_str == "2" || copies_str == "3") {
            recipients.push(ironvault_db::oracle::DakRecipientDetail { addressee: ui.get_dak_adr_2().to_string(), barcode: ui.get_dak_bar_2().to_string(), sent_by: ui.get_dak_sent_2().to_string(), service_book: ui.get_dak_sb_2().to_string() });
        }
        if copies_count == 3 && copies_str == "3" {
            recipients.push(ironvault_db::oracle::DakRecipientDetail { addressee: ui.get_dak_adr_3().to_string(), barcode: ui.get_dak_bar_3().to_string(), sent_by: ui.get_dak_sent_3().to_string(), service_book: ui.get_dak_sb_3().to_string() });
        }

        let ui_weak = app_weak_dak.clone();
        let ppo_combined = format!("PPO: {} / FPPO: {}", ppo, fppo);
        
        let transaction_payload = ironvault_db::oracle::PensionDakEntry {
            app_num: app_num.clone(), letter_no, ppo_fppo: ppo_combined, gpo, cpo, section, subject, copies_count, recipients,
        };

        tokio::spawn(async move {
            match oracle.pendak_insert_outward_case(transaction_payload).await {
                Ok(_) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui_handle) = ui_weak.upgrade() {
                            ui_handle.set_op_is_error(false); ui_handle.set_op_status_msg(format!("SUCCESS: Outward case record for Application {} logged.", app_num).into());
                            ui_handle.set_entry_app_num("".into()); ui_handle.set_entry_letter_no("".into());
                            ui_handle.set_dak_ppo("".into()); ui_handle.set_dak_fppo("".into()); ui_handle.set_dak_gpo("".into()); ui_handle.set_dak_cpo("".into());
                            ui_handle.set_entry_section("".into()); ui_handle.set_entry_subject("".into()); ui_handle.set_entry_no_of_copies("1".into());
                            ui_handle.set_dak_adr_1("".into()); ui_handle.set_dak_bar_1("".into());
                            ui_handle.set_dak_adr_2("".into()); ui_handle.set_dak_bar_2("".into());
                            ui_handle.set_dak_adr_3("".into()); ui_handle.set_dak_bar_3("".into());
                        }
                    }).unwrap();
                }
                Err(err_msg) => { slint::invoke_from_event_loop(move || { if let Some(ui_handle) = ui_weak.upgrade() { ui_handle.set_op_is_error(true); ui_handle.set_op_status_msg(format!("DATABASE WRITE REFUSAL: {}", err_msg).into()); } }).unwrap(); }
            }
        });
    });

    // ACTION 3: Find Outward Record Archive Task
    let app_weak_dak_query = app.as_weak();
    let oracle_dak_query = Arc::clone(&oracle_client);
    app.on_request_find_outward_dak(move |search_key| {
        let ui_weak = app_weak_dak_query.clone(); let oracle = Arc::clone(&oracle_dak_query);
        let target = search_key.to_string().trim().to_string();
        if target.is_empty() { return; }
        tokio::spawn(async move {
            match oracle.pendak_select_outward_case_full(&target).await {
                Ok(Some(record)) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_dak_case_found(true); ui.set_op_is_error(false); ui.set_op_status_msg("SUCCESS: Outward Case matched inside storage vault.".into());
                            ui.set_view_dak_letter(record.letter_no.into()); ui.set_view_dak_section(record.section.into()); ui.set_view_dak_subject(record.subject.into());
                            ui.set_dak_corr_date(record.created_at.into());
                            ui.set_dak_ppo(record.ppo_no.into()); ui.set_dak_fppo(record.fppo_no.into());
                            ui.set_dak_gpo(record.gpo_no.into()); ui.set_dak_cpo(record.cpo_no.into());
                            ui.set_dak_adr_1(record.addressee.into()); ui.set_dak_bar_1(record.barcode.into()); ui.set_dak_sent_1(record.sent_by.into());
                        }
                    }).unwrap();
                }
                Ok(None) => { slint::invoke_from_event_loop(move || { if let Some(ui) = ui_weak.upgrade() { ui.set_dak_case_found(false); ui.set_op_is_error(true); ui.set_op_status_msg("Discovery Fault: Given index key doesn't exist inside archive registry.".into()); } }).unwrap(); }
                Err(e) => { slint::invoke_from_event_loop(move || { if let Some(ui) = ui_weak.upgrade() { ui.set_dak_case_found(false); ui.set_op_is_error(true); ui.set_op_status_msg(format!("ORACLE LOOKUP REJECTION: {}", e).into()); } }).unwrap(); }
            }
        });
    });

    // ACTION 4: Edit or Update Outward Case Option
    let app_weak_dak_modify = app.as_weak();
    let oracle_dak_modify = Arc::clone(&oracle_client);
    app.on_request_update_outward_dak(move || {
        let ui_weak = app_weak_dak_modify.clone(); let oracle = Arc::clone(&oracle_dak_modify);
        let ui = app_weak_dak_modify.unwrap();
        
        let app_num = ui.get_edit_app_num().to_string().trim().to_string();
        let section = ui.get_edit_section().to_string().trim().to_string();
        let subject = ui.get_edit_subject().to_string().trim().to_string();
        
        if app_num.is_empty() || section.is_empty() || subject.is_empty() {
            ui.set_op_is_error(true); ui.set_op_status_msg("Fault: Fields required to execute modifications are empty.".into());
            return;
        }
        tokio::spawn(async move {
            match oracle.pendak_update_outward_case(&app_num, &section, &subject).await {
                Ok(_) => { slint::invoke_from_event_loop(move || { if let Some(ui_handle) = ui_weak.upgrade() { ui_handle.set_op_is_error(false); ui_handle.set_op_status_msg(format!("SUCCESS: Modification matrix applied cleanly to profile record {}", app_num).into()); ui_handle.set_edit_app_num("".into()); ui_handle.set_edit_section("".into()); ui_handle.set_edit_subject("".into()); } }).unwrap(); }
                Err(e) => { slint::invoke_from_event_loop(move || { if let Some(ui_handle) = ui_weak.upgrade() { ui_handle.set_op_is_error(true); ui_handle.set_op_status_msg(format!("ORACLE UPDATE FAULT: {}", e).into()); } }).unwrap(); }
            }
        });
    });

    // ACTION 5: Outward Letters Binding Link Option
    let app_weak_dak_letter = app.as_weak();
    let oracle_dak_letter = Arc::clone(&oracle_client);
    app.on_request_submit_correspondence(move || {
        let ui_weak = app_weak_dak_letter.clone(); let oracle = Arc::clone(&oracle_dak_letter);
        let ui = app_weak_dak_letter.unwrap();
        
        let app_num = ui.get_letter_app_num().to_string().trim().to_string();
        let letter_no = ui.get_letter_letter_no().to_string().trim().to_string();
        let section = ui.get_letter_section().to_string().trim().to_string();
        let subject = ui.get_letter_subject().to_string().trim().to_string();
        let copies_count: i32 = ui.get_letter_no_of_copies().to_string().parse().unwrap_or(1);
        
        let letter_payload = ironvault_db::oracle::PensionDakEntry {
            app_num: app_num.clone(), letter_no: letter_no.clone(), ppo_fppo: ui.get_dak_ppo().to_string(), gpo: ui.get_dak_gpo().to_string(), cpo: ui.get_dak_cpo().to_string(),
            section: section.clone(), subject: subject.clone(), copies_count,
            recipients: vec![ironvault_db::oracle::DakRecipientDetail {
                addressee: ui.get_dak_adr_1().to_string(), barcode: ui.get_dak_bar_1().to_string(), sent_by: ui.get_dak_sent_1().to_string(), service_book: "N".to_string()
            }],
        };

        tokio::spawn(async move {
            match oracle.pendak_insert_outward_case(letter_payload).await {
                Ok(_) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui_handle) = ui_weak.upgrade() {
                            ui_handle.set_op_is_error(false); ui_handle.set_op_status_msg(format!("SUCCESS: Letter component {} successfully linked into dairy registry.", letter_no).into());
                            ui_handle.set_letter_app_num("".into()); ui_handle.set_letter_letter_no("".into()); ui_handle.set_letter_section("".into()); ui_handle.set_letter_subject("".into());
                            ui_handle.set_dak_adr_1("".into()); ui_handle.set_dak_bar_1("".into()); ui_handle.set_dak_sent_1("".into());
                        }
                    }).unwrap();
                }
                Err(e) => { slint::invoke_from_event_loop(move || { if let Some(ui_handle) = ui_weak.upgrade() { ui_handle.set_op_is_error(true); ui_handle.set_op_status_msg(format!("ORACLE LETTER FAULT: {}", e).into()); } }).unwrap(); }
            }
        });
    });

    // =========================================================================
    // --- SAI_AGARTALA / PENSION COMPONENT CHANNELS ---
    // =========================================================================
    let app_weak_pnsr_det = app.as_weak();
    let oracle_pnsr_det = Arc::clone(&oracle_client);
    app.on_request_pension_details(move |query_term| {
        let ui_weak = app_weak_pnsr_det.clone(); let oracle = Arc::clone(&oracle_pnsr_det);
        let term = query_term.to_string();
        tokio::spawn(async move {
            match oracle.pnsr_get_details(&term).await {
                Ok(records) => {
                    let slint_records: Vec<PensionDetailsSlint> = records.into_iter().map(|r| {
                        PensionDetailsSlint {
                            application_no: r.application_no.into(), pensioner_name: r.pensioner_name.into(), employee_code: r.employee_code.to_string().into(),
                            designation: r.designation.into(), mobile_no: r.mobile_no.into(), date_of_birth: r.date_of_birth.into(),
                        }
                    }).collect();
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_sai_data_found(!slint_records.is_empty());
                            ui.set_sai_biographical_list(slint::ModelRc::from(std::rc::Rc::new(slint::VecModel::from(slint_records))));
                            ui.set_op_is_error(false);
                        }
                    }).unwrap();
                }
                Err(e) => { slint::invoke_from_event_loop(move || { if let Some(ui) = ui_weak.upgrade() { ui.set_op_is_error(true); ui.set_op_status_msg(format!("Lookup failure: {}", e).into()); } }).unwrap(); }
            }
        });
    });

    let app_weak_pnsr_stat = app.as_weak();
    let oracle_pnsr_stat = Arc::clone(&oracle_client);
    app.on_request_pension_status(move |app_no| {
        let ui_weak = app_weak_pnsr_stat.clone(); let oracle = Arc::clone(&oracle_pnsr_stat);
        let query_app = app_no.to_string();
        tokio::spawn(async move {
            match oracle.pnsr_get_status_tracking(&query_app).await {
                Ok(Some(record)) => {
                    let slint_record = PensionStatusSlint {
                        application_no: record.application_no.into(), application_date: record.application_date.into(), name: record.name.into(),
                        last_work_office_name: record.last_work_office_name.into(), status: record.status.into(), date_of_settle: record.date_of_settle.into(),
                        ppo: record.ppo.into(), gpo: record.gpo.into(), cpo: record.cpo.into(), dak_outward_date: record.dak_outward_date.into(),
                        speed_post: record.speed_post.into(), treasury: record.treasury.into(),
                    };
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_sai_data_found(true); ui.set_op_is_error(false); ui.set_sai_status_record(slint_record);
                        }
                    }).unwrap();
                }
                Ok(None) => { slint::invoke_from_event_loop(move || { if let Some(ui) = ui_weak.upgrade() { ui.set_sai_data_found(false); ui.set_op_is_error(true); ui.set_op_status_msg("No settlement matches located for criteria token.".into()); } }).unwrap(); }
                Err(e) => { slint::invoke_from_event_loop(move || { if let Some(ui) = ui_weak.upgrade() { ui.set_op_is_error(true); ui.set_op_status_msg(format!("Tracking Engine Error: {}", e).into()); } }).unwrap(); }
            }
        });
    });

    app.run()?;
    Ok(())
}