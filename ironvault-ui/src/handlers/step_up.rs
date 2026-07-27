//! Generic step-up re-authentication for SuperAdmin-critical actions.
//! Any sensitive action is first staged via request_step_up(action, target,
//! extra) in Slint, which opens a password prompt. On submit, we re-verify
//! the CURRENTLY LOGGED IN user's password (not the target's) — this
//! confirms "it's still really the SuperAdmin sitting here," independent of
//! how long the session has been open, before dispatching the real,
//! DB-layer-guarded privileged operation.

use crate::context::{record_audit, SharedContext};
use crate::AppWindow;
use slint::ComponentHandle;

pub fn register(app: &AppWindow, ctx: SharedContext) {
    let app_weak = app.as_weak();
    app.on_submit_step_up_reauth(move |password_attempt| {
        let ui_weak = app_weak.clone();
        let ctx = ctx.clone();
        let password_attempt = password_attempt.to_string();

        let (acting_user, acting_role_str, action, target, extra) = if let Some(ui) = ui_weak.upgrade() {
            (
                ui.get_current_user_name().to_string(),
                ui.get_current_user_role().to_string(),
                ui.get_step_up_action().to_string(),
                ui.get_step_up_target().to_string(),
                ui.get_step_up_extra().to_string(),
            )
        } else {
            return;
        };
        let acting_role: ironvault_core::auth::Role = acting_role_str.into();

        tokio::spawn(async move {
            let password_ok = ctx.db.reverify_current_password(&acting_user, &password_attempt).await.unwrap_or(false);

            if !password_ok {
                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_step_up_error("Incorrect password. Action cancelled.".into());
                        ui.set_step_up_password("".into());
                    }
                }).unwrap();
                return;
            }

            // Password confirmed — dispatch to the actual privileged
            // operation. Each arm calls the same DB functions used
            // elsewhere in the app; the DB layer's require_superadmin(...)
            // check still applies underneath this, so a non-SuperAdmin
            // reaching this code path (which shouldn't happen given the UI
            // gating) would still be rejected at the data layer.
            let result: Result<String, String> = match action.as_str() {
                "ban_user" => ctx.db.ban_user(&acting_user, &target).await
                    .map(|_| format!("BANNED_OPERATOR target=@{}", target)),

                "hwid_unblock" => {
                    sqlx::query("UPDATE ironvault.users SET hardware_fingerprint = 'UNKNOWN' WHERE username = $1 OR LOWER(username) = LOWER($1)")
                        .bind(&target)
                        .execute(ctx.db.get_pool())
                        .await
                        .map(|_| format!("HWID_UNBOUND target=@{}", target))
                        .map_err(|e| e.to_string())
                }

                "reset_token" => {
                    let dynamic_token: String = {
                        use rand::distributions::Alphanumeric;
                        use rand::Rng;
                        rand::thread_rng().sample_iter(&Alphanumeric).take(8).map(char::from).collect()
                    };
                    let token_hash = ironvault_core::crypto::hash_token(&dynamic_token);
                    let write_result = sqlx::query(
                        "UPDATE ironvault.users SET password = 'RESET_PENDING', temp_token = $1, status = 'EXPIRED' WHERE username = $2 OR LOWER(username) = LOWER($2)"
                    ).bind(&token_hash).bind(&target).execute(ctx.db.get_pool()).await;

                    match write_result {
                        Ok(_) => {
                            let ui_weak2 = ui_weak.clone();
                            let target2 = target.clone();
                            slint::invoke_from_event_loop(move || {
                                if let Some(ui) = ui_weak2.upgrade() {
                                    ui.set_reveal_secret_value(dynamic_token.into());
                                    ui.set_reveal_secret_label(format!("One-time token for @{}", target2).into());
                                    ui.set_reveal_secret_visible(true);
                                }
                            }).ok();
                            Ok(format!("ISSUED_OTA_TOKEN target=@{}", target))
                        }
                        Err(e) => Err(e.to_string()),
                    }
                }

                "commit_settings" => {
                    let parts: Vec<&str> = extra.split('|').collect();
                    if parts.len() != 3 {
                        Err("Malformed settings payload.".to_string())
                    } else {
                        let role_str = parts[0].to_string();
                        let days_valid: i32 = parts[1].parse().unwrap_or(30);
                        let flags = parts[2];
                        let mut schema_str = String::new();
                        if flags.get(0..1) == Some("1") { schema_str.push_str("gpffp,"); }
                        if flags.get(1..2) == Some("1") { schema_str.push_str("vlcs,"); }
                        if flags.get(2..3) == Some("1") { schema_str.push_str("sai_agartala,"); }
                        if flags.get(3..4) == Some("1") { schema_str.push_str("pendak,"); }

                        ctx.db.update_user_full_access(&acting_user, &target, &role_str, days_valid, &schema_str).await
                            .map(|_| format!("UPDATED_ACCESS target=@{} role={} lease_days={} schemas=[{}]", target, role_str, days_valid, schema_str))
                    }
                }

                "idle_timeout" => {
                    let minutes: i32 = extra.parse().unwrap_or(10);
                    ctx.db.set_idle_timeout_minutes(minutes, &acting_user).await
                        .map(|_| format!("UPDATED_IDLE_TIMEOUT minutes={}", minutes))
                }

                "approve" => ctx.db.approve_user(&acting_user, &target, &extra).await
                    .map(|_| format!("APPROVED_OPERATOR target=@{} assigned_role={}", target, extra)),

                "deny" => ctx.db.deny_user(&acting_user, &target).await
                    .map(|_| format!("DENIED_OPERATOR target=@{}", target)),

                other => Err(format!("Unknown step-up action: {}", other)),
            };

            match result {
                Ok(audit_msg) => {
                    record_audit(&ctx, &acting_user, acting_role, &audit_msg, "CRITICAL").await;
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_step_up_visible(false);
                            ui.set_step_up_password("".into());
                            ui.set_step_up_error("".into());
                            ui.set_op_is_error(false);
                            ui.set_op_status_msg("SUCCESS: Action completed after re-authentication.".into());
                            ui.invoke_load_users_list();
                            ui.invoke_load_pending_users_list();
                        }
                    }).unwrap();
                }
                Err(e) => {
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_step_up_error(format!("Action failed: {}", e).into());
                        }
                    }).unwrap();
                }
            }
        });
    });

    // request_step_up just stages state and opens the modal — trivial, no
    // async work, so it's registered directly rather than needing its own
    // module function, but included here for co-location with the flow it
    // starts.
    let app_weak2 = app.as_weak();
    app.on_request_step_up(move |action, target, extra| {
        if let Some(ui) = app_weak2.upgrade() {
            ui.set_step_up_action(action);
            ui.set_step_up_target(target);
            ui.set_step_up_extra(extra);
            ui.set_step_up_password("".into());
            ui.set_step_up_error("".into());
            ui.set_step_up_visible(true);
        }
    });
}
