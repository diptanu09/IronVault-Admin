//! Authentication: login (password + one-time-token fallback), logout,
//! registration, and forced password reset after a token login.

use crate::context::{record_audit, SharedContext};
use crate::{AppWindow, SchemaAccessState};
use ironvault_core::auth::{classify_auth_outcome, AuthDecision};
use slint::ComponentHandle;
use sqlx::Row;

pub fn register(app: &AppWindow, ctx: SharedContext) {
    // --- LOGIN ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_request_authentication(move |username, password| {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();
            let typed_username = username.to_string().trim().to_string();
            let plain_password = password.to_string().trim().to_string();

            tokio::spawn(async move {
                // Rate Limiter Check: Block immediate processing if the account is currently locked out
                if let Some(remaining) = ctx.rate_limiter.check_locked(&typed_username, &ctx.hwid) {
                    let secs = remaining.as_secs();
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_login_error(format!("Account temporarily locked due to repeated failures. Try again in {}s.", secs).into());
                        }
                    }).unwrap();
                    return;
                }

                let normal_result = ctx.db.authenticate_user(&typed_username, &plain_password, &ctx.hwid).await;

                // Only attempt the temp-token check if the normal path failed — no point
                // spending a DB round-trip if the primary credential already succeeded.
                let temp_token_result = if normal_result.is_err() {
                    Some(ctx.db.authenticate_via_temp_token(&typed_username, &plain_password, &ctx.hwid).await)
                } else {
                    None
                };

                // Reduce both async results down to plain Ok(())/Err(()) shape for the
                // synchronous classifier — this is the hand-off point from async I/O
                // results into the virtualized decision function.
                let normal_ok = normal_result.as_ref().map(|_| ()).map_err(|_| ());
                let token_ok = temp_token_result.as_ref()
                    .map(|r| r.as_ref().map(|_| ()).map_err(|_| ()))
                    .unwrap_or(Err(()));

                let decision = classify_auth_outcome(&normal_ok, &token_ok);

                match decision {
                    AuthDecision::GrantFullSession => {
                        ctx.rate_limiter.record_success(&typed_username, &ctx.hwid);

                        let user = normal_result.expect("GrantFullSession implies normal_result was Ok");
                        
                        let pool = ctx.db.get_pool().clone();
                        let profile_query = sqlx::query(
                            "SELECT full_name, designation, section, expires_at FROM ironvault.users WHERE username = $1"
                        )
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
                                // FIXED: include time, and convert from the stored UTC instant into
                                // IST for display — same timezone-correctness fix applied to the
                                // audit log timestamps.
                                let ist = dt.with_timezone(&chrono_tz::Asia::Kolkata);
                                expires = ist.format("%Y-%m-%d %H:%M").to_string();
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
                                    if let Ok(img) = slint::Image::load_from_path(&avatar_path) {
                                        ui.set_current_avatar_image(img);
                                        ui.set_current_avatar_loaded(true);
                                    }
                                }
                            }
                        }).unwrap();

                        let role_for_audit: ironvault_core::auth::Role = user.role.clone().into();
                        record_audit(&ctx, &user.username, role_for_audit, "USER_LOGIN_SUCCESS", "CRITICAL").await;
                    }
                    AuthDecision::RequireForcedPasswordReset => {
                        ctx.rate_limiter.record_success(&typed_username, &ctx.hwid);

                        let user = temp_token_result
                            .expect("RequireForcedPasswordReset implies temp_token_result was Some")
                            .expect("RequireForcedPasswordReset implies temp_token_result was Ok");
                        let ui_username = user.username.clone();
                        record_audit(&ctx, &ui_username, user.role.clone().into(), "OTA_TOKEN_LOGIN_SUCCESS", "CRITICAL").await;
                        slint::invoke_from_event_loop(move || {
                            if let Some(ui) = ui_weak.upgrade() {
                                ui.set_login_error("".into());
                                ui.set_current_user_name(ui_username.into());
                                ui.set_forced_password_reset_state(true);
                            }
                        }).unwrap();
                    }
                    AuthDecision::Deny => {
                        ctx.rate_limiter.record_failure(&typed_username, &ctx.hwid);

                        slint::invoke_from_event_loop(move || {
                            if let Some(ui) = ui_weak.upgrade() {
                                ui.set_login_error(
                                    "Authentication Failed: Invalid credentials, token, or HWID mismatch.".into()
                                );
                            }
                        }).unwrap();
                    }
                }
            });
        });
    }

    // --- LOGOUT ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_request_logout(move || {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();

            let (username_str, role_str) = if let Some(ui) = ui_weak.upgrade() {
                (
                    ui.get_current_user_name().to_string(),
                    ui.get_current_user_role().to_string(),
                )
            } else {
                ("UNKNOWN".to_string(), "Viewer".to_string())
            };

            tokio::spawn(async move {
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
                        ui.set_auth_screen_state("landing".into());
                    }
                });

                if username_str != "UNKNOWN" && !username_str.is_empty() {
                    let acting_role: ironvault_core::auth::Role = role_str.into();
                    record_audit(
                        &ctx,
                        &username_str,
                        acting_role,
                        "USER_LOGOUT_SUCCESS",
                        "NOMINAL",
                    )
                    .await;
                }
            });
        });
    }

    // --- REGISTRATION ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_request_registration(move |username, secret, first, middle, last, desg, sect| {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();
            let u_name = username.to_string().trim().to_string();
            let plain_secret = secret.to_string(); // register_user hashes internally
            let f_name = first.to_string();
            let m_name = middle.to_string();
            let l_name = last.to_string();
            let d_name = desg.to_string();
            let s_name = sect.to_string();

            tokio::spawn(async move {
                match ctx.db.register_user(&u_name, &plain_secret, &ctx.hwid, &f_name, &m_name, &l_name, &d_name, &s_name).await {
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
    }

    // --- FORCED PASSWORD UPDATE (after one-time-token login) ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_commit_forced_password_update(move |username, new_password| {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();
            let u_name = username.to_string().trim().to_string();
            let new_pass = new_password.to_string();

            tokio::spawn(async move {
                let pool = ctx.db.get_pool().clone();

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
                    Ok(_) => {
                        record_audit(&ctx, &u_name, ironvault_core::auth::Role::Operator, "COMPLETED_FORCED_PASSWORD_RESET", "NOMINAL").await;
                        slint::invoke_from_event_loop(move || {
                            if let Some(ui) = ui_weak.upgrade() {
                                ui.set_forced_password_reset_state(false);
                                ui.set_form_new_pass("".into());
                                ui.set_form_confirm_pass("".into());
                                ui.set_password_reset_error("".into());
                                ui.set_show_welcome_popup(true);
                                ui.set_active_tab("overview".into());
                            }
                        }).unwrap();
                    }
                    Err(e) => slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_password_reset_error(format!("Database Fault: {}", e).into());
                        }
                    }).unwrap()
                }
            });
        });
    }
}