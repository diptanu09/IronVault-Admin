//! IronVault Admin UI - Bootstrapper & Main Thread
//! Initializes the Slint UI framework and establishes connections
//! to the core security and database layers with automated relational tracking.

slint::include_modules!();
use ironvault_core::audit::AuditLogger;
use ironvault_db::{DbClient, OracleConnection};
use rand::distributions::Alphanumeric;
use rand::Rng;
use slint::ComponentHandle;
use slint::{ModelRc, VecModel};
use sqlx::Row;
use std::rc::Rc;
use std::sync::Arc;

// FFI Link definitions for Oreans Themida SecureEngine SDK
#[link(name = "SecureEngineSDK64")]
extern "C" {
    fn VMStart();
    fn VMEnd();
}

/// Helper function to log user movements directly into the PostgreSQL relational audit table
#[allow(dead_code)]
async fn log_to_db(pool: &sqlx::PgPool, operator: &str, action: &str, level: &str, schema: &str) {
    let query = "INSERT INTO ironvault.db_audit_logs (operator_id, operation_action, impact_level, target_schema) VALUES ($1, $2, $3, $4)";
    let _ = sqlx::query(query)
        .bind(operator)
        .bind(action)
        .bind(level)
        .bind(schema)
        .execute(pool)
        .await;
}

#[tokio::main]
async fn main() -> Result<(), slint::PlatformError> {
    println!("[BOOT] Engaging IronVault Core Security...");

    // Load .env into the process environment (no-op if the file doesn't exist,
    // e.g. in a deployment that sets real env vars directly instead).
    if let Err(e) = dotenvy::dotenv() {
        log::warn!(
            "[CONFIG] No .env file loaded ({}). Falling back to process environment / defaults.",
            e
        );
    }

    let hwid = ironvault_core::licensing::generate_hwid();
    ironvault_core::security::enforce_core_security_checks(&hwid);
    let audit_logger = Arc::new(AuditLogger::new("ironvault.audit.log"));

    // FIXED: credentials now come from environment variables instead of being
    // hardcoded in source. Fails fast with a clear message if anything required
    // is missing, rather than silently falling back to a guessable default.
    let db_host = std::env::var("IRONVAULT_DB_HOST").unwrap_or_else(|_| "localhost".to_string());
    let db_port: u16 = std::env::var("IRONVAULT_DB_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5432);
    let db_name = std::env::var("IRONVAULT_DB_NAME")
        .expect("[FATAL CONFIG ERROR] IRONVAULT_DB_NAME must be set (check .env)");
    let db_user = std::env::var("IRONVAULT_DB_USER")
        .expect("[FATAL CONFIG ERROR] IRONVAULT_DB_USER must be set (check .env)");
    let db_password = std::env::var("IRONVAULT_DB_PASSWORD")
        .expect("[FATAL CONFIG ERROR] IRONVAULT_DB_PASSWORD must be set (check .env)");

    let db = match DbClient::connect_with_credentials(
        &db_host,
        db_port,
        &db_name,
        &db_user,
        &db_password,
    )
    .await
    {
        Ok(client) => Arc::new(client),
        Err(err) => {
            eprintln!("[FATAL DATABASE ERROR]: {}", err);
            std::process::exit(1);
        }
    };

    let oracle_client = match OracleConnection::new() {
        Ok(client) => Arc::new(client),
        Err(e) => {
            eprintln!("[FATAL] Oracle matrix allocation failure: {:?}", e);
            std::process::exit(1);
        }
    };

    let app = AppWindow::new()?;
    app.set_hwid_string(format!("HWID: {}", hwid).into());

    let mut rng = rand::thread_rng();
    let (v1, v2) = (rng.gen_range(5..20), rng.gen_range(2..10));
    app.set_captcha_q_main(format!("{} + {}", v1, v2).into());
    app.set_captcha_a_main((v1 + v2).to_string().into());

    // --- INITIALIZE MASTER SMART POINTER REFERENCE CONTEXTS ---
    let app_weak_main = app.as_weak();
    let db_clone = Arc::clone(&db);
    let oracle_master = Arc::clone(&oracle_client);
    let audit_clone = Arc::clone(&audit_logger);
    let target_hwid_main = hwid.clone();

    // =========================================================================
    // --- AUTHENTICATION: LOGIN ---
    // =========================================================================
    let app_weak_login = app_weak_main.clone();
    let db_login = Arc::clone(&db_clone);
    let audit_login = Arc::clone(&audit_clone);
    let hwid_login = target_hwid_main.clone();
    app.on_request_authentication(move |username, password| {
        let ui_weak = app_weak_login.clone();
        let db = Arc::clone(&db_login);
        let audit = Arc::clone(&audit_login);
        let target_hwid = hwid_login.clone();

        let typed_username = username.to_string().trim().to_string();
        let plain_password = password.to_string().trim().to_string();

        tokio::spawn(async move {
            unsafe { VMStart(); } // Themida API Wrapping Gate Entry

            // Password verification (bcrypt) now happens inside authenticate_user,
            // so the plaintext is passed straight through instead of pre-hashing here.
            match db.authenticate_user(&typed_username, &plain_password, &target_hwid).await {
                Ok(user) => {
                    let pool = db.get_pool().clone();

                    let profile_query = sqlx::query("SELECT full_name, designation, section, expires_at FROM ironvault.users WHERE username = $1")
                        .bind(&user.username)
                        .fetch_optional(&pool).await.unwrap_or(None);

                    let mut full_name = "System Operator".to_string();
                    let mut designation_str = "Personnel Node".to_string();
                    let mut allowed_schemas_str = "".to_string();
                    let mut expires = "Unknown".to_string();

                    if let Some(p_row) = profile_query {
                        full_name = p_row.try_get("full_name").unwrap_or(full_name);
                        designation_str = p_row.try_get("designation").unwrap_or(designation_str);
                        allowed_schemas_str = p_row.try_get("section").unwrap_or(allowed_schemas_str).to_lowercase();

                        if let Ok(dt) = p_row.try_get::<chrono::DateTime<chrono::Utc>, _>("expires_at") {
                            expires = dt.format("%Y-%m-%d").to_string();
                        }
                    }

                    let is_super = user.role.to_lowercase().contains("superadmin");
                    let mut schema_str_display = if is_super { "ALL SYSTEMS AUTHORIZED (SUPERADMIN)".to_string() } else { allowed_schemas_str.clone() };
                    if schema_str_display.trim().is_empty() { schema_str_display = "NO SCHEMAS ASSIGNED".to_string(); }

                    let access = SchemaAccessState {
                        gpffp: is_super || allowed_schemas_str.contains("gpffp"),
                        vlcs: is_super || allowed_schemas_str.contains("vlcs"),
                        agtall: is_super || allowed_schemas_str.contains("gpffp"),
                        agdak: is_super || allowed_schemas_str.contains("pendak"),
                        sai_agartala: is_super || allowed_schemas_str.contains("sai_agartala") || allowed_schemas_str.contains("sai"),
                        pendak: is_super || allowed_schemas_str.contains("pendak"),
                        penindex: is_super || allowed_schemas_str.contains("sai_agartala"),
                    };

                    let ui_username = user.username.clone();
                    let ui_role = user.role.clone();
                    let avatar_path = std::path::Path::new("./storage/avatars/").join(format!("{}.png", ui_username));

                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_login_error("".into());
                            ui.set_current_user_name(ui_username.into());
                            ui.set_current_user_role(ui_role.into());
                            ui.set_current_user_full_name(full_name.into());
                            ui.set_current_user_designation(designation_str.into());
                            ui.set_current_user_expires(expires.into());
                            ui.set_current_user_schemas_string(schema_str_display.into());
                            ui.set_schema_access(access);
                            ui.set_is_logged_in(true);
                            ui.set_show_welcome_popup(true);
                            ui.set_active_tab("overview".into());
                            ui.invoke_trigger_log_stream_reload();

                            if avatar_path.exists() {
                                if let Ok(slint_img) = slint::Image::load_from_path(&avatar_path) {
                                    ui.set_current_avatar_image(slint_img);
                                    ui.set_current_avatar_loaded(true);
                                }
                            }
                        }
                    }).unwrap();

                    let login_pool = db.get_pool().clone();
                    log_to_db(&login_pool, &user.username, "USER_LOGIN_SUCCESS", "NOMINAL", "SYSTEM").await;
                    let core_user = ironvault_core::auth::User {
                        id: Default::default(),
                        username: user.username,
                        role: user.role.into(),
                        last_login: user.last_login,
                    };
                    audit.log_action(&core_user, "OPERATOR_DB_LOGIN_SUCCESS", "CRITICAL").ok();
                }
                Err(err_msg) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_login_error(err_msg.into());
                        }
                    }).unwrap();
                }
            }

            unsafe { VMEnd(); } // Themida Wrapping Gate Closure
        });
    });

    // =========================================================================
    // --- AUTHENTICATION: LOGOUT ---
    // =========================================================================
    let app_weak_logout = app_weak_main.clone();
    let db_logout = Arc::clone(&db_clone);
    app.on_request_logout(move || {
        let ui_weak = app_weak_logout.clone();
        let db = db_logout.clone();

        let username_str = if let Some(ui) = ui_weak.upgrade() {
            ui.get_current_user_name().to_string()
        } else {
            "UNKNOWN".to_string()
        };

        tokio::spawn(async move {
            let pool = db.get_pool().clone();
            let ui_weak_clear = ui_weak.clone();

            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak_clear.upgrade() {
                    ui.set_is_logged_in(false);
                    ui.set_current_user_name("GUEST".into());
                    ui.set_current_user_role("UNAUTHORIZED".into());
                    ui.set_current_user_full_name("Unknown Operator".into());
                    ui.set_current_user_designation("Unassigned".into());
                    ui.set_form_user("".into());
                    ui.set_form_pass("".into());
                    ui.set_form_captcha_login("".into());
                    ui.set_auth_screen_state("landing".into());
                }
            });

            if username_str != "UNKNOWN" && !username_str.is_empty() {
                log_to_db(
                    &pool,
                    &username_str,
                    "USER_LOGOUT_SUCCESS",
                    "NOMINAL",
                    "SYSTEM",
                )
                .await;
            }
        });
    });

    // =========================================================================
    // --- AUTHENTICATION: REGISTRATION ---
    // =========================================================================
    let app_weak_reg = app_weak_main.clone();
    let db_reg = Arc::clone(&db_clone);
    let hwid_reg = target_hwid_main.clone();
    app.on_request_registration(move |username, secret, first, middle, last, desg, sect| {
        let ui_weak = app_weak_reg.clone();
        let db = Arc::clone(&db_reg);
        let hwid = hwid_reg.clone();
        let u_name = username.to_string().trim().to_string();
        let plain_secret = secret.to_string(); // register_user hashes internally now
        let f_name = first.to_string();
        let m_name = middle.to_string();
        let l_name = last.to_string();
        let d_name = desg.to_string();
        let s_name = sect.to_string();

        tokio::spawn(async move {
            match db.register_user(&u_name, &plain_secret, &hwid, &f_name, &m_name, &l_name, &d_name, &s_name).await {
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

    // =========================================================================
    // --- BACKGROUND: PENDING OPERATOR POLLING ---
    // =========================================================================
    let app_weak_poll = app_weak_main.clone();
    let db_poll = Arc::clone(&db_clone);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;

            let should_poll = {
                if let Some(ui) = app_weak_poll.upgrade() {
                    ui.get_is_logged_in()
                        && ui
                            .get_current_user_role()
                            .to_string()
                            .contains("SuperAdmin")
                } else {
                    false
                }
            };

            if should_poll {
                if let Ok(pending_operator) = db_poll.fetch_next_pending_user().await {
                    let app_weak_copy = app_weak_poll.clone();
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui_layer) = app_weak_copy.upgrade() {
                            let name_val = pending_operator.unwrap_or_else(|| "NONE".to_string());
                            ui_layer.set_pending_notification_name(name_val.into());
                            ui_layer.invoke_load_pending_users_list();
                        }
                    })
                    .unwrap();
                }
            }
        }
    });

    // =========================================================================
    // --- OPERATOR APPROVAL / DENIAL (audited, real acting user + role) ---
    // =========================================================================
    let app_weak_approve = app_weak_main.clone();
    let db_approve = Arc::clone(&db_clone);
    let audit_approve = Arc::clone(&audit_clone);
    app.on_approve_pending_operator(move |target_user, role_str| {
        let ui_weak = app_weak_approve.clone();
        let db = Arc::clone(&db_approve);
        let audit = Arc::clone(&audit_approve);
        let target = target_user.to_string().trim().to_string();
        let assigned_role = role_str.to_string();

        let (acting_user, acting_role_str) = if let Some(ui) = ui_weak.upgrade() {
            (
                ui.get_current_user_name().to_string(),
                ui.get_current_user_role().to_string(),
            )
        } else {
            ("UNKNOWN".to_string(), "Viewer".to_string())
        };
        let acting_role: ironvault_core::auth::Role = acting_role_str.into();

        tokio::spawn(async move {
            match db.approve_user(&acting_user, &target, &assigned_role).await {
                Ok(_) => {
                    let core_user = ironvault_core::auth::User {
                        id: Default::default(),
                        username: acting_user.clone(),
                        role: acting_role,
                        last_login: "".to_string(),
                    };
                    audit
                        .log_action(
                            &core_user,
                            &format!(
                                "APPROVED_OPERATOR target=@{} assigned_role={}",
                                target, assigned_role
                            ),
                            "CRITICAL",
                        )
                        .ok();

                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_pending_notification_name("NONE".into());
                            ui.set_op_is_error(false);
                            ui.set_op_status_msg(
                                "SUCCESS: Access registration token signed into active matrix."
                                    .into(),
                            );
                            ui.invoke_load_pending_users_list();
                        }
                    })
                    .unwrap();
                }
                Err(e) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(format!("Approval Fault: {}", e).into());
                        }
                    })
                    .unwrap();
                }
            }
        });
    });

    let app_weak_deny = app_weak_main.clone();
    let db_deny = Arc::clone(&db_clone);
    let audit_deny = Arc::clone(&audit_clone);
    app.on_deny_pending_operator(move |target_user| {
        let ui_weak = app_weak_deny.clone();
        let db = Arc::clone(&db_deny);
        let audit = Arc::clone(&audit_deny);
        let target = target_user.to_string().trim().to_string();

        let (acting_user, acting_role_str) = if let Some(ui) = ui_weak.upgrade() {
            (
                ui.get_current_user_name().to_string(),
                ui.get_current_user_role().to_string(),
            )
        } else {
            ("UNKNOWN".to_string(), "Viewer".to_string())
        };
        let acting_role: ironvault_core::auth::Role = acting_role_str.into();

        tokio::spawn(async move {
            match db.deny_user(&acting_user, &target).await {
                Ok(_) => {
                    let core_user = ironvault_core::auth::User {
                        id: Default::default(),
                        username: acting_user.clone(),
                        role: acting_role,
                        last_login: "".to_string(),
                    };
                    audit
                        .log_action(
                            &core_user,
                            &format!("DENIED_OPERATOR target=@{}", target),
                            "WARNING",
                        )
                        .ok();

                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_pending_notification_name("NONE".into());
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(
                                "Purged: Verification request discarded successfully.".into(),
                            );
                            ui.invoke_load_pending_users_list();
                        }
                    })
                    .unwrap();
                }
                Err(e) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(format!("Denial Fault: {}", e).into());
                        }
                    })
                    .unwrap();
                }
            }
        });
    });

    let app_weak_pnd_list = app_weak_main.clone();
    let db_pnd_list = Arc::clone(&db_clone);
    app.on_load_pending_users_list(move || {
        let ui_weak = app_weak_pnd_list.clone();
        let db = Arc::clone(&db_pnd_list);
        tokio::spawn(async move {
            let pool = db.get_pool().clone();
            let query = "SELECT username, role, full_name, designation, section FROM ironvault.users WHERE status = 'PENDING'";
            if let Ok(rows) = sqlx::query(query).fetch_all(&pool).await {
                let mut slint_pending = Vec::new();
                for r in rows {
                    let u: String = r.try_get("username").unwrap_or_default();
                    let ro: String = r.try_get("role").unwrap_or_default();
                    let f: String = r.try_get("full_name").unwrap_or_default();
                    let d: String = r.try_get("designation").unwrap_or_default();
                    let s: String = r.try_get("section").unwrap_or_default();
                    slint_pending.push(UserData { username: u.into(), role: ro.into(), last_login: "PENDING".into(), full_name: f.into(), designation: d.into(), expires_at: "".into(), allowed_schemas: s.into() });
                }
                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_pending_users_list(ModelRc::from(Rc::new(VecModel::from(slint_pending))));
                    }
                }).unwrap();
            }
        });
    });

    // =========================================================================
    // --- ACTIVE OPERATOR LEDGER ---
    // =========================================================================
    let app_weak_users_ledger = app_weak_main.clone();
    let db_users = Arc::clone(&db_clone);
    app.on_load_users_list(move || {
        let ui_weak = app_weak_users_ledger.clone();
        let db = Arc::clone(&db_users);
        tokio::spawn(async move {
            let pool = db.get_pool().clone();
            let query = "SELECT username, role, full_name, designation, status, section FROM ironvault.users WHERE status = 'ACTIVE' OR status = 'EXPIRED'";
            if let Ok(rows) = sqlx::query(query).fetch_all(&pool).await {
                let mut slint_users = Vec::new();
                for r in rows {
                    let u: String = r.try_get("username").unwrap_or_default();
                    let ro: String = r.try_get("role").unwrap_or_default();
                    let f: String = r.try_get("full_name").unwrap_or_default();
                    let d: String = r.try_get("designation").unwrap_or_default();
                    let st: String = r.try_get("status").unwrap_or_default();
                    let s: String = r.try_get("section").unwrap_or_default();

                    let display_expiry = if st == "EXPIRED" { "ONE-TIME ACCESS ACTIVE".to_string() } else { "ACTIVE LEASE".to_string() };
                    slint_users.push(UserData { username: u.into(), role: ro.into(), last_login: "ONLINE".into(), full_name: f.into(), designation: d.into(), expires_at: display_expiry.into(), allowed_schemas: s.into() });
                }
                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_active_users_list(ModelRc::from(Rc::new(VecModel::from(slint_users))));
                    }
                }).unwrap();
            }
        });
    });

    // =========================================================================
    // --- COMBINED ACCESS SETTINGS COMMIT (role + lease + schema, atomic) ---
    // FIXED (schema-toggle race, item #8): previously `extend_user_lease` and
    // `commit_schema_toggles` fired as two independent async writes to the same
    // `section` column, and could overwrite each other depending on which
    // completed last. This single callback + single SQL statement removes the
    // race entirely, and is now audited like the other privilege-affecting
    // actions above.
    // =========================================================================
    let app_weak_settings = app_weak_main.clone();
    let db_settings = Arc::clone(&db_clone);
    let audit_settings = Arc::clone(&audit_clone);
    app.on_commit_user_settings_pass(move |target_user, new_role, days_string, gpf, vlcs, sai, dak| {
        let ui_weak = app_weak_settings.clone();
        let db = Arc::clone(&db_settings);
        let audit = Arc::clone(&audit_settings);

        let user_str = target_user.to_string().trim().to_string();
        let role_str = new_role.to_string();
        let days_valid: i32 = days_string.to_string().parse().unwrap_or(30);

        let mut schema_str = String::new();
        if gpf { schema_str.push_str("gpffp,"); }
        if vlcs { schema_str.push_str("vlcs,"); }
        if sai { schema_str.push_str("sai_agartala,"); }
        if dak { schema_str.push_str("pendak,"); }

        let (acting_user, acting_role_str) = if let Some(ui) = ui_weak.upgrade() {
            (ui.get_current_user_name().to_string(), ui.get_current_user_role().to_string())
        } else {
            ("UNKNOWN".to_string(), "Viewer".to_string())
        };
        let acting_role: ironvault_core::auth::Role = acting_role_str.into();

        tokio::spawn(async move {
            match db.update_user_full_access(&user_str, &role_str, days_valid, &schema_str).await {
                Ok(_) => {
                    let core_user = ironvault_core::auth::User {
                        id: Default::default(),
                        username: acting_user.clone(),
                        role: acting_role,
                        last_login: "".to_string(),
                    };
                    audit.log_action(
                        &core_user,
                        &format!(
                            "UPDATED_ACCESS target=@{} role={} lease_days={} schemas=[{}]",
                            user_str, role_str, days_valid, schema_str
                        ),
                        "CRITICAL",
                    ).ok();

                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(false);
                            ui.set_op_status_msg(
                                format!("🛡️ MATRIX SUCCESS: Access updated for @{} — role={}, schemas=[{}]", user_str, role_str, schema_str).into()
                            );
                            ui.invoke_load_users_list();
                        }
                    }).unwrap();
                }
                Err(e) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(format!("Matrix Fault: {}", e).into());
                        }
                    }).unwrap();
                }
            }
        });
    });

    let app_weak_ban = app_weak_main.clone();
    let db_ban = Arc::clone(&db_clone);
    let audit_ban = Arc::clone(&audit_clone);
    app.on_ban_user(move |target_user| {
        let ui_weak = app_weak_ban.clone();
        let db = Arc::clone(&db_ban);
        let audit = Arc::clone(&audit_ban);
        let user_str = target_user.to_string().trim().to_string();

        let (acting_user, acting_role_str) = if let Some(ui) = ui_weak.upgrade() {
            (ui.get_current_user_name().to_string(), ui.get_current_user_role().to_string())
        } else {
            ("UNKNOWN".to_string(), "Viewer".to_string())
        };
        let acting_role: ironvault_core::auth::Role = acting_role_str.into();

        tokio::spawn(async move {
            match db.ban_user(&acting_user, &user_str).await {
                Ok(_) => {
                    let core_user = ironvault_core::auth::User {
                        id: Default::default(),
                        username: acting_user.clone(),
                        role: acting_role,
                        last_login: "".to_string(),
                    };
                    audit.log_action(
                        &core_user,
                        &format!("BANNED_OPERATOR target=@{}", user_str),
                        "CRITICAL",
                    ).ok();

                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.invoke_load_users_list();
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg("REVOCATION SUCCESS: Operator credentials blacklisted and purged from registry.".into());
                        }
                    }).unwrap();
                }
                Err(e) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(format!("Ban Fault: {}", e).into());
                        }
                    }).unwrap();
                }
            }
        });
    });

    // =========================================================================
    // --- PASSWORD RESET / FORCED UPDATE ---
    // =========================================================================
    let app_weak_reset = app_weak_main.clone();
    let db_reset = Arc::clone(&db_clone);
    app.on_reset_user_password(move |target_user| {
        let ui_weak = app_weak_reset.clone();
        let db = Arc::clone(&db_reset);
        let user_str = target_user.to_string().trim().to_string();

        tokio::spawn(async move {
            let pool = db.get_pool().clone();

            let dynamic_token: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(8)
                .map(char::from)
                .collect();

            let query = "UPDATE ironvault.users SET password = 'RESET_PENDING', temp_token = $1, status = 'EXPIRED' WHERE username = $2 OR LOWER(username) = LOWER($2)";
            match sqlx::query(query)
                .bind(&dynamic_token)
                .bind(&user_str)
                .execute(&pool)
                .await
            {
                Ok(_) => slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_op_is_error(false);
                        ui.set_op_status_msg(format!("🛡️ OTA ACTIVATED: Temporary token generated for @{} -> [ {} ]", user_str, dynamic_token).into());
                        ui.invoke_load_users_list();
                    }
                }).unwrap(),
                Err(e) => slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_op_is_error(true);
                        ui.set_op_status_msg(format!("OVERRIDE FAULT: {}", e).into());
                    }
                }).unwrap()
            }
        });
    });

    let app_weak_commit = app_weak_main.clone();
    let db_commit = Arc::clone(&db_clone);
    app.on_commit_forced_password_update(move |username, new_password| {
        let ui_weak = app_weak_commit.clone();
        let db = Arc::clone(&db_commit);
        let u_name = username.to_string().trim().to_string();
        let new_pass = new_password.to_string();

        tokio::spawn(async move {
            let pool = db.get_pool().clone();

            // hash_password now takes only the password (bcrypt embeds its own salt)
            // and returns a Result, so it must be unwrapped before binding to the query.
            let final_secure_hash = match ironvault_core::crypto::hash_password(&new_pass) {
                Ok(h) => h,
                Err(_) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_password_reset_error("Internal error: failed to secure new password.".into());
                        }
                    }).unwrap();
                    return;
                }
            };

            let query = "UPDATE ironvault.users SET password = $1, temp_token = NULL, status = 'ACTIVE' WHERE username = $2 OR LOWER(username) = LOWER($2)";
            match sqlx::query(query).bind(&final_secure_hash).bind(&u_name).execute(&pool).await {
                Ok(_) => slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_forced_password_reset_state(false);
                        ui.set_form_new_pass("".into());
                        ui.set_form_confirm_pass("".into());
                        ui.set_password_reset_error("".into());
                        ui.set_show_welcome_popup(true);
                        ui.set_active_tab("overview".into());
                    }
                }).unwrap(),
                Err(e) => slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_password_reset_error(format!("Database Fault: {}", e).into());
                    }
                }).unwrap()
            }
        });
    });

    let app_weak_hwid = app_weak_main.clone();
    let db_hwid = Arc::clone(&db_clone);
    app.on_request_hwid_unblock(move |target_user| {
        let ui_weak = app_weak_hwid.clone();
        let db = Arc::clone(&db_hwid);
        let user_str = target_user.to_string().trim().to_string();
        tokio::spawn(async move {
            let pool = db.get_pool().clone();
            let query = "UPDATE ironvault.users SET hardware_fingerprint = 'UNKNOWN' WHERE username = $1 OR LOWER(username) = LOWER($1)";
            match sqlx::query(query).bind(&user_str).execute(&pool).await {
                Ok(_) => slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_op_is_error(false);
                        ui.set_op_status_msg(format!("🔓 HWID RELEASE SUCCESS: Hardware fingerprint bindings cleared for @{}", user_str).into());
                    }
                }).unwrap(),
                Err(e) => slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_op_is_error(true);
                        ui.set_op_status_msg(format!("HWID Override Error: {}", e).into());
                    }
                }).unwrap()
            }
        });
    });

    // --- CHECKBOX STATE FETCH (single registration) ---
    let app_weak_chk_fetch = app_weak_main.clone();
    let db_chk_fetch = Arc::clone(&db_clone);
    app.on_request_checkbox_states_fetch(move |target_user| {
        let ui_weak = app_weak_chk_fetch.clone();
        let db = db_chk_fetch.clone();
        let user_str = target_user.to_string().trim().to_string();
        tokio::spawn(async move {
            let pool = db.get_pool().clone();
            if let Ok(Some(row)) = sqlx::query("SELECT section FROM ironvault.users WHERE username = $1 OR LOWER(username) = LOWER($1)").bind(&user_str).fetch_optional(&pool).await {
                let section_str: String = row.try_get::<String, _>("section").unwrap_or_default().to_lowercase();
                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_cb_gpf(section_str.contains("gpffp"));
                        ui.set_cb_vlcs(section_str.contains("vlcs"));
                        ui.set_cb_sai(section_str.contains("sai_agartala"));
                        ui.set_cb_dak(section_str.contains("pendak"));
                    }
                }).unwrap();
            }
        });
    });

    // --- AUDIT LOG STREAM RELOAD (single registration) ---
    let app_weak_logs_reload = app_weak_main.clone();
    let audit_logs_reload = Arc::clone(&audit_clone);
    app.on_trigger_log_stream_reload(move || {
        let ui_weak = app_weak_logs_reload.clone();
        let logger = audit_logs_reload.clone();

        tokio::spawn(async move {
            let raw_records = logger.query_logs_optimized(40);

            let ui_mapped_records: Vec<AuditLogUiData> = raw_records
                .into_iter()
                .map(|item| {
                    let formatted_time = if item.timestamp.len() >= 16 {
                        item.timestamp[11..16].to_string()
                    } else {
                        item.timestamp
                    };

                    AuditLogUiData {
                        timestamp: formatted_time.into(),
                        operator_id: item.username.into(),
                        operation_action: item.action.into(),
                        level: item.impact_level.into(),
                    }
                })
                .collect();

            slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_dashboard_audit_stream(ModelRc::from(Rc::new(VecModel::from(
                        ui_mapped_records,
                    ))));
                }
            })
            .unwrap();
        });
    });

    // =========================================================================
    // --- GPFFP MODULE LISTENER CLONES ---
    // =========================================================================
    let app_weak_find = app_weak_main.clone();
    let oracle_find = Arc::clone(&oracle_master);
    app.on_request_find_gpf_case(move |regd_no| {
        let ui_weak = app_weak_find.clone();
        let oracle = oracle_find.clone();
        let r_no = regd_no.to_string();
        tokio::spawn(async move {
            match oracle.gpffp_find_case_profile(&r_no).await {
                Ok(Some(record)) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_gpf_case_found(true);
                            ui.set_op_is_error(false);
                            ui.set_op_status_msg("SUCCESS: GPF Case entity located.".into());
                            ui.set_active_gpf_case(GpfCaseDetails {
                                regd_no: record.regd_no.into(),
                                holder_name: record.acc_holder_name.into(),
                                series_id: record.series_id.into(),
                                account_no: record.account_no.into(),
                                balance: record.closing_balance.to_string().into(),
                                status: record.current_status.into(),
                            });
                        }
                    })
                    .unwrap();
                }
                Ok(None) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_gpf_case_found(false);
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(
                                "Discovery Fault: No matching records found.".into(),
                            );
                        }
                    })
                    .unwrap();
                }
                Err(e) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_gpf_case_found(false);
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(
                                format!("ORACLE TRANSACTION FAILURE: {:?}", e).into(),
                            );
                        }
                    })
                    .unwrap();
                }
            }
        });
    });

    let app_weak_op1 = app_weak_main.clone();
    let oracle_op1 = Arc::clone(&oracle_master);
    app.on_request_delete_full_case(move |regd_no, series_id, account_no| {
        let ui_weak = app_weak_op1.clone();
        let oracle = oracle_op1.clone();
        let (r_no, s_id, a_no) = (
            regd_no.to_string(),
            series_id.to_string(),
            account_no.to_string(),
        );
        tokio::spawn(async move {
            match oracle.gpffp_delete_full_case(&r_no, &s_id, &a_no).await {
                Ok(_) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(false);
                            ui.set_op_status_msg(
                                "SUCCESS: GPFFP Final payment case completely cleared.".into(),
                            );
                            ui.set_op_regd_no("".into());
                            ui.set_op_series_id("".into());
                            ui.set_op_account_no("".into());
                            ui.set_gpf_case_found(false);
                        }
                    })
                    .unwrap();
                }
                Err(e) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(
                                format!("GPFFP TRANSACTION FAILURE: {}", e).into(),
                            );
                        }
                    })
                    .unwrap();
                }
            }
        });
    });

    let app_weak_op2 = app_weak_main.clone();
    let oracle_op2 = Arc::clone(&oracle_master);
    app.on_request_delete_application(move |regd_no| {
        let ui_weak = app_weak_op2.clone();
        let oracle = oracle_op2.clone();
        let r_no = regd_no.to_string();
        tokio::spawn(async move {
            match oracle.gpffp_delete_from_application(&r_no).await {
                Ok(_) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(false);
                            ui.set_op_status_msg(
                                "SUCCESS: GPFFP Application Record purged.".into(),
                            );
                            ui.set_op_regd_no("".into());
                            ui.set_gpf_case_found(false);
                        }
                    })
                    .unwrap();
                }
                Err(e) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(
                                format!("GPFFP TRANSACTION FAILURE: {}", e).into(),
                            );
                        }
                    })
                    .unwrap();
                }
            }
        });
    });

    let app_weak_op3 = app_weak_main.clone();
    let oracle_op3 = Arc::clone(&oracle_master);
    app.on_request_delete_precalc(move |regd_no| {
        let ui_weak = app_weak_op3.clone();
        let oracle = oracle_op3.clone();
        let r_no = regd_no.to_string();
        tokio::spawn(async move {
            match oracle.gpffp_delete_from_pre_calculation(&r_no).await {
                Ok(_) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(false);
                            ui.set_op_status_msg(
                                "SUCCESS: GPFFP Pre-Calculation values updated.".into(),
                            );
                            ui.set_op_regd_no("".into());
                            ui.set_gpf_case_found(false);
                        }
                    })
                    .unwrap();
                }
                Err(e) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(
                                format!("GPFFP TRANSACTION FAILURE: {}", e).into(),
                            );
                        }
                    })
                    .unwrap();
                }
            }
        });
    });

    let app_weak_op4 = app_weak_main.clone();
    let oracle_op4 = Arc::clone(&oracle_master);
    app.on_request_delete_auth_reports(move |regd_no| {
        let ui_weak = app_weak_op4.clone();
        let oracle = oracle_op4.clone();
        let r_no = regd_no.to_string();
        tokio::spawn(async move {
            match oracle.gpffp_delete_authority_reports(&r_no).await {
                Ok(_) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(false);
                            ui.set_op_status_msg("SUCCESS: Associated Signed Authority & Uploaded Reports completely dropped from transaction registry.".into());
                            ui.set_op_regd_no("".into());
                            ui.set_gpf_case_found(false);
                        }
                    }).unwrap();
                }
                Err(e) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(format!("GPFFP TRANSACTION FAILURE: {}", e).into());
                        }
                    }).unwrap();
                }
            }
        });
    });

    // =========================================================================
    // --- VLCS / PENDAK MODULE LISTENERS ---
    // =========================================================================
    let app_weak_dak_find = app_weak_main.clone();
    let oracle_dak_find = Arc::clone(&oracle_master);
    app.on_request_find_pension_dak_meta(move |search_app_num| {
        let ui = app_weak_dak_find.unwrap();
        let oracle = oracle_dak_find.clone();
        let target_app = search_app_num.to_string().trim().to_string();
        if target_app.is_empty() {
            ui.set_dak_ppo("".into());
            ui.set_dak_fppo("".into());
            ui.set_dak_gpo("".into());
            ui.set_dak_cpo("".into());
            return;
        }
        let ui_weak = app_weak_dak_find.clone();
        tokio::spawn(async move {
            match oracle.pendak_fetch_auth_details(&target_app).await {
                Ok(Some(details)) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui_handle) = ui_weak.upgrade() {
                            ui_handle.set_dak_ppo(
                                if details.ppo_no.is_empty() {
                                    "N/A".to_string()
                                } else {
                                    details.ppo_no
                                }
                                .into(),
                            );
                            ui_handle.set_dak_fppo(
                                if details.fppo_no.is_empty() {
                                    "N/A".to_string()
                                } else {
                                    details.fppo_no
                                }
                                .into(),
                            );
                            ui_handle.set_dak_gpo(
                                if details.gpo_no.is_empty() {
                                    "N/A".to_string()
                                } else {
                                    details.gpo_no
                                }
                                .into(),
                            );
                            ui_handle.set_dak_cpo(
                                if details.cpo_no.is_empty() {
                                    "N/A".to_string()
                                } else {
                                    details.cpo_no
                                }
                                .into(),
                            );
                            ui_handle.set_op_is_error(false);
                            ui_handle.set_op_status_msg(
                                "SUCCESS: Associated pension authorities auto-fetched.".into(),
                            );
                        }
                    })
                    .unwrap();
                }
                Ok(None) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui_handle) = ui_weak.upgrade() {
                            ui_handle.set_dak_ppo("N/A".into());
                            ui_handle.set_dak_fppo("N/A".into());
                            ui_handle.set_dak_gpo("N/A".into());
                            ui_handle.set_dak_cpo("N/A".into());
                        }
                    })
                    .unwrap();
                }
                Err(e) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui_handle) = ui_weak.upgrade() {
                            ui_handle.set_op_is_error(true);
                            ui_handle.set_op_status_msg(format!("Auto-Fetch Error: {}", e).into());
                        }
                    })
                    .unwrap();
                }
            }
        });
    });

    let app_weak_dak = app_weak_main.clone();
    let oracle_dak = Arc::clone(&oracle_master);
    app.on_request_submit_outward_dak(move || {
        let ui = app_weak_dak.unwrap();
        let oracle = oracle_dak.clone();

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
            ui.set_op_is_error(true);
            ui.set_op_status_msg(
                "Validation Fault: All fields marked with * are strictly mandatory.".into(),
            );
            return;
        }

        let mut recipients = Vec::new();
        if copies_count >= 1 {
            recipients.push(ironvault_db::oracle::DakRecipientDetail {
                addressee: ui.get_dak_adr_1().to_string(),
                barcode: ui.get_dak_bar_1().to_string(),
                sent_by: ui.get_dak_sent_1().to_string(),
                service_book: "N".to_string(),
            });
        }
        if copies_count >= 2 && (copies_str == "2" || copies_str == "3") {
            recipients.push(ironvault_db::oracle::DakRecipientDetail {
                addressee: ui.get_dak_adr_2().to_string(),
                barcode: ui.get_dak_bar_2().to_string(),
                sent_by: ui.get_dak_sent_2().to_string(),
                service_book: "N".to_string(),
            });
        }
        if copies_count == 3 && copies_str == "3" {
            recipients.push(ironvault_db::oracle::DakRecipientDetail {
                addressee: ui.get_dak_adr_3().to_string(),
                barcode: ui.get_dak_bar_3().to_string(),
                sent_by: ui.get_dak_sent_3().to_string(),
                service_book: "N".to_string(),
            });
        }

        let ui_weak = app_weak_dak.clone();
        let ppo_combined = format!("PPO: {} / FPPO: {}", ppo, fppo);

        let transaction_payload = ironvault_db::oracle::PensionDakEntry {
            app_num: app_num.clone(),
            letter_no,
            ppo_fppo: ppo_combined,
            gpo,
            cpo,
            section,
            subject,
            copies_count,
            recipients,
        };

        tokio::spawn(async move {
            match oracle.pendak_insert_outward_case(transaction_payload).await {
                Ok(_) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui_handle) = ui_weak.upgrade() {
                            ui_handle.set_op_is_error(false);
                            ui_handle.set_op_status_msg(
                                format!(
                                    "SUCCESS: Outward case record for Application {} logged.",
                                    app_num
                                )
                                .into(),
                            );
                            ui_handle.set_entry_app_num("".into());
                            ui_handle.set_entry_letter_no("".into());
                            ui_handle.set_dak_ppo("".into());
                            ui_handle.set_dak_fppo("".into());
                            ui_handle.set_dak_gpo("".into());
                            ui_handle.set_dak_cpo("".into());
                            ui_handle.set_entry_section("".into());
                            ui_handle.set_entry_subject("".into());
                            ui_handle.set_entry_no_of_copies("1".into());
                            ui_handle.set_dak_adr_1("".into());
                            ui_handle.set_dak_bar_1("".into());
                            ui_handle.set_dak_adr_2("".into());
                            ui_handle.set_dak_bar_2("".into());
                            ui_handle.set_dak_adr_3("".into());
                            ui_handle.set_dak_bar_3("".into());
                        }
                    })
                    .unwrap();
                }
                Err(err_msg) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui_handle) = ui_weak.upgrade() {
                            ui_handle.set_op_is_error(true);
                            ui_handle.set_op_status_msg(
                                format!("DATABASE WRITE REFUSAL: {}", err_msg).into(),
                            );
                        }
                    })
                    .unwrap();
                }
            }
        });
    });

    let app_weak_dak_query = app_weak_main.clone();
    let oracle_dak_query = Arc::clone(&oracle_master);
    app.on_request_find_outward_dak(move |search_key| {
        let ui_weak = app_weak_dak_query.clone();
        let oracle = oracle_dak_query.clone();
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

    let app_weak_dak_modify = app_weak_main.clone();
    let oracle_dak_modify = Arc::clone(&oracle_master);
    app.on_request_update_outward_dak(move || {
        let ui_weak = app_weak_dak_modify.clone();
        let oracle = oracle_dak_modify.clone();
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

    let app_weak_dak_letter = app_weak_main.clone();
    let oracle_dak_letter = Arc::clone(&oracle_master);
    app.on_request_submit_correspondence(move || {
        let ui_weak = app_weak_dak_letter.clone();
        let oracle = oracle_dak_letter.clone();
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
    // --- P-SAI CORE PENSION BINDINGS ---
    // =========================================================================
    let app_weak_pnsr_det = app_weak_main.clone();
    let oracle_pnsr_det = Arc::clone(&oracle_master);
    app.on_request_pension_details(move |query_term| {
        let ui_weak = app_weak_pnsr_det.clone();
        let oracle = oracle_pnsr_det.clone();
        let term = query_term.to_string();
        tokio::spawn(async move {
            match oracle.pnsr_get_details(&term).await {
                Ok(records) => {
                    let slint_records: Vec<PensionDetailsSlint> = records
                        .into_iter()
                        .map(|r| PensionDetailsSlint {
                            application_no: r.application_no.into(),
                            pensioner_name: r.pensioner_name.into(),
                            employee_code: r.employee_code.to_string().into(),
                            designation: r.designation.into(),
                            mobile_no: r.mobile_no.into(),
                            date_of_birth: r.date_of_birth.into(),
                        })
                        .collect();
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_sai_data_found(!slint_records.is_empty());
                            ui.set_sai_biographical_list(slint::ModelRc::from(std::rc::Rc::new(
                                slint::VecModel::from(slint_records),
                            )));
                            ui.set_op_is_error(false);
                        }
                    })
                    .unwrap();
                }
                Err(e) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(format!("Lookup failure: {}", e).into());
                        }
                    })
                    .unwrap();
                }
            }
        });
    });

    let app_weak_pnsr_stat = app_weak_main.clone();
    let oracle_pnsr_stat = Arc::clone(&oracle_master);
    app.on_request_pension_status(move |app_no| {
        let ui_weak = app_weak_pnsr_stat.clone();
        let oracle = oracle_pnsr_stat.clone();
        let query_app = app_no.to_string();
        tokio::spawn(async move {
            match oracle.pnsr_get_status_tracking(&query_app).await {
                Ok(Some(record)) => {
                    let slint_record = PensionStatusSlint {
                        application_no: record.application_no.into(),
                        application_date: record.application_date.into(),
                        name: record.name.into(),
                        last_work_office_name: record.last_work_office_name.into(),
                        status: record.status.into(),
                        date_of_settle: record.date_of_settle.into(),
                        ppo: record.ppo.into(),
                        gpo: record.gpo.into(),
                        cpo: record.cpo.into(),
                        dak_outward_date: record.dak_outward_date.into(),
                        speed_post: record.speed_post.into(),
                        treasury: record.treasury.into(),
                    };
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_sai_data_found(true);
                            ui.set_op_is_error(false);
                            ui.set_sai_status_record(slint_record);
                        }
                    })
                    .unwrap();
                }
                Ok(None) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_sai_data_found(false);
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(
                                "No settlement matches located for criteria token.".into(),
                            );
                        }
                    })
                    .unwrap();
                }
                Err(e) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(format!("Tracking Engine Error: {}", e).into());
                        }
                    })
                    .unwrap();
                }
            }
        });
    });

    app.run()?;
    Ok(())
}
