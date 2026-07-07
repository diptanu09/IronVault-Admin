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
        
        tokio::spawn(async move {
            match db.authenticate_user(&u_name, &password, &target_hwid).await {
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
                    
                    // Fixed: Keep path reference thread-safe to avoid Send/Sync constraint failures
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
                        
                        // Safely initialize the Slint non-send GUI elements strictly inside the Main GUI Thread Loop Context
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
                        ui.set_active_tab("overview".into());
                    }).unwrap();
                    
                    let core_user = ironvault_core::auth::User { id: Default::default(), username: user.username.clone(), role: user.role.clone().into(), last_login: user.last_login.clone() };
                    audit.log_action(&core_user, "OPERATOR_DB_LOGIN_SUCCESS", "CRITICAL").ok();
                }
                Err(err) => slint::invoke_from_event_loop(move || { ui_weak.unwrap().set_login_error(err.into()); }).unwrap(),
            }
        });
    });

    // --- USER MANAGEMENT TAB MATRIX ---
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
                slint::invoke_from_event_loop(move || ui_weak.unwrap().set_active_users_list(ModelRc::from(Rc::new(VecModel::from(slint_users))))).unwrap();
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
        let schema_str = new_schemas.to_string();
        let days_valid: i32 = days_string.to_string().parse().unwrap_or(30);
        
        tokio::spawn(async move {
            if db.update_user_lease(&user_str, &role_str, days_valid).await.is_ok() {
                let pool = db.get_pool().clone();
                let _ = sqlx::query("UPDATE ironvault.users SET section = $1 WHERE username = $2").bind(&schema_str).bind(&user_str).execute(&pool).await;
                slint::invoke_from_event_loop(move || ui_weak.unwrap().invoke_load_users_list()).unwrap();
            }
        });
    });

    // --- SECURE AVATAR CARRIER ENGINE ---
    let app_weak_pic = app.as_weak();
    app.on_request_profile_pic_update(move || {
        let ui = app_weak_pic.unwrap();
        let username = ui.get_current_user_name().to_string();
        
        println!("[SECURITY] Initializing Native File Dialog intercept for operator: {}", username);
        
        let file_picker = rfd::FileDialog::new()
            .set_title("Select Operator Profile Image")
            .add_filter("Supported Images (*.png, *.jpg, *.jpeg)", &["png", "jpg", "jpeg"])
            .pick_file();
            
        if let Some(path) = file_picker {
            if let Ok(metadata) = std::fs::metadata(&path) {
                let file_size = metadata.len();
                if file_size > 2 * 1024 * 1024 {
                    ui.set_op_is_error(true);
                    ui.set_op_status_msg("Security Fault: File size exceeds maximum 2MB limit.".into());
                    return;
                }
            } else { return; }

            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
            if ext != "png" && ext != "jpg" && ext != "jpeg" {
                ui.set_op_is_error(true);
                ui.set_op_status_msg("Security Fault: Forbidden image file extension.".into());
                return;
            }

            match image::ImageReader::open(&path) {
                Ok(reader) => {
                    if let Ok(guessed) = reader.with_guessed_format() {
                        if guessed.format().is_none() {
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg("Security Violation: Malicious file signature matched.".into());
                            return;
                        }
                    }
                }
                Err(_) => return,
            }

            let storage_dir = std::path::Path::new("./storage/avatars/");
            let _ = std::fs::create_dir_all(storage_dir);
            let target_destination = storage_dir.join(format!("{}.png", username));
            
            if std::fs::copy(&path, &target_destination).is_ok() {
                if let Ok(slint_img) = slint::Image::load_from_path(&target_destination) {
                    ui.set_current_avatar_image(slint_img);
                    ui.set_current_avatar_loaded(true);
                    ui.set_op_is_error(false);
                    ui.set_op_status_msg("SUCCESS: Profile picture updated successfully.".into());
                }
            }
        }
    });

    // --- SECURE LOGOUT SYSTEM CLEANUP ---
    let app_weak_logout = app.as_weak();
    app.on_request_logout(move || {
        if let Some(ui) = app_weak_logout.upgrade() {
            ui.set_is_logged_in(false); 
            ui.set_current_user_name("GUEST".into()); 
            ui.set_auth_screen_state("landing".into());
            
            ui.set_form_user("".into());
            ui.set_form_pass("".into());
            ui.set_form_captcha_login("".into());
            
            let mut fresh_rng = rand::thread_rng();
            let (new_v1, new_v2) = (fresh_rng.gen_range(5..20), fresh_rng.gen_range(2..10));
            ui.set_captcha_q_main(format!("{} + {}", new_v1, new_v2).into());
            ui.set_captcha_a_main((new_v1 + new_v2).to_string().into());
        }
    });

    // --- GPFFP ORACLE OPERATIONS CHANNEL MATRIX ---
    let app_weak_op1 = app.as_weak(); let oracle_op1 = Arc::clone(&oracle_client);
    app.on_request_delete_full_case(move |regd_no, series_id, account_no| {
        let ui_weak = app_weak_op1.clone(); let oracle = Arc::clone(&oracle_op1); let (r_no, s_id, a_no) = (regd_no.to_string(), series_id.to_string(), account_no.to_string());
        tokio::spawn(async move {
            match oracle.gpffp_delete_full_case(&r_no, &s_id, &a_no).await {
                Ok(_) => slint::invoke_from_event_loop(move || { let ui = ui_weak.unwrap(); ui.set_op_is_error(false); ui.set_op_status_msg("SUCCESS: GPFFP Full Case cleared.".into()); ui.set_op_regd_no("".into()); ui.set_op_series_id("".into()); ui.set_op_account_no("".into()); }).unwrap(),
                Err(e) => slint::invoke_from_event_loop(move || { let ui = ui_weak.unwrap(); ui.set_op_is_error(true); ui.set_op_status_msg(format!("GPFFP TRANSACTION FAILURE: {}", e).into()); }).unwrap(),
            }
        });
    });

    let app_weak_op2 = app.as_weak(); let oracle_op2 = Arc::clone(&oracle_client);
    app.on_request_delete_application(move |regd_no| {
        let ui_weak = app_weak_op2.clone(); let oracle = Arc::clone(&oracle_op2); let r_no = regd_no.to_string();
        tokio::spawn(async move {
            match oracle.gpffp_delete_from_application(&r_no).await {
                Ok(_) => slint::invoke_from_event_loop(move || { let ui = ui_weak.unwrap(); ui.set_op_is_error(false); ui.set_op_status_msg("SUCCESS: GPFFP Application Record purged.".into()); ui.set_op_regd_no("".into()); }).unwrap(),
                Err(e) => slint::invoke_from_event_loop(move || { let ui = ui_weak.unwrap(); ui.set_op_is_error(true); ui.set_op_status_msg(format!("GPFFP TRANSACTION FAILURE: {}", e).into()); }).unwrap(),
            }
        });
    });

    let app_weak_op3 = app.as_weak(); let oracle_op3 = Arc::clone(&oracle_client);
    app.on_request_delete_precalc(move |regd_no| {
        let ui_weak = app_weak_op3.clone(); let oracle = Arc::clone(&oracle_op3); let r_no = regd_no.to_string();
        tokio::spawn(async move {
            match oracle.gpffp_delete_from_pre_calculation(&r_no).await {
                Ok(_) => slint::invoke_from_event_loop(move || { let ui = ui_weak.unwrap(); ui.set_op_is_error(false); ui.set_op_status_msg("SUCCESS: GPFFP Pre-Calculation values updated.".into()); ui.set_op_regd_no("".into()); }).unwrap(),
                Err(e) => slint::invoke_from_event_loop(move || { let ui = ui_weak.unwrap(); ui.set_op_is_error(true); ui.set_op_status_msg(format!("GPFFP TRANSACTION FAILURE: {}", e).into()); }).unwrap(),
            }
        });
    });

    app.run()?;
    Ok(())
}