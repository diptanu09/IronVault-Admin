//! Operator lifecycle: pending polling, approve/deny, active ledger,
//! combined settings commit, ban, one-time token reset, HWID unblock,
//! and schema checkbox state fetch.

use crate::context::{record_audit, SharedContext};
use crate::{AppWindow, UserData};
use rand::distributions::Alphanumeric;
use rand::Rng;
use slint::{ComponentHandle, ModelRc, VecModel};
use sqlx::Row;
use std::rc::Rc;

pub fn register(app: &AppWindow, ctx: SharedContext) {
    // --- BACKGROUND: PENDING OPERATOR POLLING ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                let should_poll = if let Some(ui) = app_weak.upgrade() {
                    ui.get_is_logged_in()
                        && ui
                            .get_current_user_role()
                            .to_string()
                            .contains("SuperAdmin")
                } else {
                    false
                };
                if should_poll {
                    if let Ok(pending_operator) = ctx.db.fetch_next_pending_user().await {
                        let app_weak_copy = app_weak.clone();
                        slint::invoke_from_event_loop(move || {
                            if let Some(ui_layer) = app_weak_copy.upgrade() {
                                let name_val =
                                    pending_operator.unwrap_or_else(|| "NONE".to_string());
                                ui_layer.set_pending_notification_name(name_val.into());
                                ui_layer.invoke_load_pending_users_list();
                            }
                        })
                        .unwrap();
                    }
                }
            }
        });
    }

    // --- APPROVE / DENY ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_approve_pending_operator(move |target_user, role_str| {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();
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
                match ctx
                    .db
                    .approve_user(&acting_user, &target, &assigned_role)
                    .await
                {
                    Ok(_) => {
                        record_audit(
                            &ctx,
                            &acting_user,
                            acting_role,
                            &format!(
                                "APPROVED_OPERATOR target=@{} assigned_role={}",
                                target, assigned_role
                            ),
                            "CRITICAL",
                        )
                        .await;
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
                    Err(e) => slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(format!("Approval Fault: {}", e).into());
                        }
                    })
                    .unwrap(),
                }
            });
        });
    }

    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_deny_pending_operator(move |target_user| {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();
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
                match ctx.db.deny_user(&acting_user, &target).await {
                    Ok(_) => {
                        record_audit(
                            &ctx,
                            &acting_user,
                            acting_role,
                            &format!("DENIED_OPERATOR target=@{}", target),
                            "WARNING",
                        )
                        .await;
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
                    Err(e) => slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(format!("Denial Fault: {}", e).into());
                        }
                    })
                    .unwrap(),
                }
            });
        });
    }

    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_load_pending_users_list(move || {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let pool = ctx.db.get_pool().clone();
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
    }

    // --- ACTIVE OPERATOR LEDGER ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_load_users_list(move || {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let pool = ctx.db.get_pool().clone();
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
    }

    // --- PROFILE PICTURE UPDATE ---
    {
        let app_weak = app.as_weak();
        app.on_request_profile_pic_update(move || {
            let ui_weak = app_weak.clone();

            let username = if let Some(ui) = ui_weak.upgrade() {
                ui.get_current_user_name().to_string()
            } else {
                return;
            };
            if username.is_empty() || username == "GUEST" {
                return;
            }

            std::thread::spawn(move || {
                let picked = rfd::FileDialog::new()
                    .add_filter("Images", &["png", "jpg", "jpeg"])
                    .set_title("Select Profile Picture")
                    .pick_file();

                let Some(source_path) = picked else {
                    return;
                };

                let dest_dir = std::path::Path::new("./storage/avatars/");
                if let Err(e) = std::fs::create_dir_all(dest_dir) {
                    log::error!("[AVATAR] Failed to create avatars directory: {}", e);
                    return;
                }
                let dest_path = dest_dir.join(format!("{}.png", username));

                let save_result = (|| -> Result<std::path::PathBuf, image::ImageError> {
                    let img = image::open(&source_path)?;
                    img.save(&dest_path)?;
                    Ok(dest_path)
                })();

                match save_result {
                    Ok(saved_path) => {
                        // FIXED: slint::Image is not Send (it wraps a raw
                        // pointer internally, like the file-dialog handle
                        // did). We only carry the path — a plain String,
                        // which IS Send — across into the event-loop
                        // closure, and construct the actual slint::Image
                        // there, on the UI thread, where it's safe.
                        let path_string = saved_path.to_string_lossy().to_string();
                        slint::invoke_from_event_loop(move || {
                            if let Some(ui) = ui_weak.upgrade() {
                                if let Ok(slint_img) =
                                    slint::Image::load_from_path(std::path::Path::new(&path_string))
                                {
                                    ui.set_current_avatar_image(slint_img);
                                    ui.set_current_avatar_loaded(true);
                                } else {
                                    log::error!(
                                        "[AVATAR] Failed to load saved image back into UI: {}",
                                        path_string
                                    );
                                }
                            }
                        })
                        .unwrap();
                    }
                    Err(e) => log::error!("[AVATAR] Failed to save/convert image: {}", e),
                }
            });
        });
    }

    // --- COMBINED ACCESS SETTINGS COMMIT (role + lease + schema, atomic) ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_commit_user_settings_pass(move |target_user, new_role, days_string, gpf, vlcs, sai, dak| {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();
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
            } else { ("UNKNOWN".to_string(), "Viewer".to_string()) };
            let acting_role: ironvault_core::auth::Role = acting_role_str.into();

            tokio::spawn(async move {
                match ctx.db.update_user_full_access(&user_str, &role_str, days_valid, &schema_str).await {
                    Ok(_) => {
                        record_audit(&ctx, &acting_user, acting_role, &format!("UPDATED_ACCESS target=@{} role={} lease_days={} schemas=[{}]", user_str, role_str, days_valid, schema_str), "CRITICAL").await;
                        slint::invoke_from_event_loop(move || {
                            if let Some(ui) = ui_weak.upgrade() {
                                ui.set_op_is_error(false);
                                ui.set_op_status_msg(format!("🛡️ MATRIX SUCCESS: Access updated for @{} — role={}, schemas=[{}]", user_str, role_str, schema_str).into());
                                ui.invoke_load_users_list();
                            }
                        }).unwrap();
                    }
                    Err(e) => slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(format!("Matrix Fault: {}", e).into());
                        }
                    }).unwrap(),
                }
            });
        });
    }

    // --- BAN ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_ban_user(move |target_user| {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();
            let user_str = target_user.to_string().trim().to_string();

            let (acting_user, acting_role_str) = if let Some(ui) = ui_weak.upgrade() {
                (ui.get_current_user_name().to_string(), ui.get_current_user_role().to_string())
            } else { ("UNKNOWN".to_string(), "Viewer".to_string()) };
            let acting_role: ironvault_core::auth::Role = acting_role_str.into();

            tokio::spawn(async move {
                match ctx.db.ban_user(&acting_user, &user_str).await {
                    Ok(_) => {
                        record_audit(&ctx, &acting_user, acting_role, &format!("BANNED_OPERATOR target=@{}", user_str), "CRITICAL").await;
                        slint::invoke_from_event_loop(move || {
                            if let Some(ui) = ui_weak.upgrade() {
                                ui.invoke_load_users_list();
                                ui.set_op_is_error(true);
                                ui.set_op_status_msg("REVOCATION SUCCESS: Operator credentials blacklisted and purged from registry.".into());
                            }
                        }).unwrap();
                    }
                    Err(e) => slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(format!("Ban Fault: {}", e).into());
                        }
                    }).unwrap(),
                }
            });
        });
    }

    // --- ONE-TIME RESET TOKEN ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_reset_user_password(move |target_user| {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();
            let user_str = target_user.to_string().trim().to_string();

            let (acting_user, acting_role_str) = if let Some(ui) = ui_weak.upgrade() {
                (ui.get_current_user_name().to_string(), ui.get_current_user_role().to_string())
            } else { ("UNKNOWN".to_string(), "Viewer".to_string()) };
            let acting_role: ironvault_core::auth::Role = acting_role_str.into();

            tokio::spawn(async move {
                let pool = ctx.db.get_pool().clone();
                let dynamic_token: String = rand::thread_rng().sample_iter(&Alphanumeric).take(8).map(char::from).collect();
                let token_hash = ironvault_core::crypto::hash_token(&dynamic_token);

                let query = "UPDATE ironvault.users SET password = 'RESET_PENDING', temp_token = $1, status = 'EXPIRED' WHERE username = $2 OR LOWER(username) = LOWER($2)";
                match sqlx::query(query).bind(&token_hash).bind(&user_str).execute(&pool).await {
                    Ok(_) => {
                        record_audit(&ctx, &acting_user, acting_role, &format!("ISSUED_OTA_TOKEN target=@{}", user_str), "CRITICAL").await;
                        slint::invoke_from_event_loop(move || {
                            if let Some(ui) = ui_weak.upgrade() {
                                ui.set_reveal_secret_value(dynamic_token.into());
                                ui.set_reveal_secret_label(format!("One-time token for @{}", user_str).into());
                                ui.set_reveal_secret_visible(true);
                                ui.invoke_load_users_list();
                            }
                        }).unwrap();
                    }
                    Err(e) => slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(format!("OVERRIDE FAULT: {}", e).into());
                        }
                    }).unwrap(),
                }
            });
        });
    }

    // --- HWID UNBLOCK ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_request_hwid_unblock(move |target_user| {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();
            let user_str = target_user.to_string().trim().to_string();

            let (acting_user, acting_role_str) = if let Some(ui) = ui_weak.upgrade() {
                (ui.get_current_user_name().to_string(), ui.get_current_user_role().to_string())
            } else { ("UNKNOWN".to_string(), "Viewer".to_string()) };
            let acting_role: ironvault_core::auth::Role = acting_role_str.into();

            tokio::spawn(async move {
                let pool = ctx.db.get_pool().clone();
                let query = "UPDATE ironvault.users SET hardware_fingerprint = 'UNKNOWN' WHERE username = $1 OR LOWER(username) = LOWER($1)";
                match sqlx::query(query).bind(&user_str).execute(&pool).await {
                    Ok(_) => {
                        record_audit(&ctx, &acting_user, acting_role, &format!("HWID_UNBOUND target=@{}", user_str), "WARNING").await;
                        slint::invoke_from_event_loop(move || {
                            if let Some(ui) = ui_weak.upgrade() {
                                ui.set_op_is_error(false);
                                ui.set_op_status_msg(format!("🔓 HWID RELEASE SUCCESS: Hardware fingerprint bindings cleared for @{}", user_str).into());
                            }
                        }).unwrap();
                    }
                    Err(e) => slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(format!("HWID Override Error: {}", e).into());
                        }
                    }).unwrap(),
                }
            });
        });
    }

    // --- CHECKBOX STATE FETCH ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_request_checkbox_states_fetch(move |target_user| {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();
            let user_str = target_user.to_string().trim().to_string();
            tokio::spawn(async move {
                let pool = ctx.db.get_pool().clone();
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
    }
}
