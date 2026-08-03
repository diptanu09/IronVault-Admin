//! GPF Final Payment System: case lookup and the four destructive override
//! operations (full drop, application purge, precalc flush, auth-report drop).

use crate::context::SharedContext;
use crate::{AppWindow, GpfCaseDetails};
use slint::ComponentHandle;

pub fn register(app: &AppWindow, ctx: SharedContext) {
    // --- FIND CASE ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_request_find_gpf_case(move |regd_no| {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();
            let r_no = regd_no.to_string();

            // Set busy immediately, synchronously, before spawning — this is what
            // makes the spinner appear the instant the click registers, not after
            // some delay.
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_gpf_find_busy(true);
            }

            tokio::spawn(async move {
                let result = ctx.oracle.gpffp_find_case_profile(&r_no).await;

                // Clear busy first, unconditionally, regardless of success/failure —
                // then apply the existing result-handling logic exactly as before.
                slint::invoke_from_event_loop({
                    let ui_weak = ui_weak.clone();
                    move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_gpf_find_busy(false);
                        }
                    }
                })
                .ok();

                match result {
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
    }

    // --- DROP FULL SETTLEMENT PROFILE ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_request_delete_full_case(move |regd_no, series_id, account_no| {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();
            let (r_no, s_id, a_no) = (
                regd_no.to_string(),
                series_id.to_string(),
                account_no.to_string(),
            );

            if let Some(ui) = ui_weak.upgrade() {
                ui.set_gpf_drop_busy(true);
            }

            tokio::spawn(async move {
                let result = ctx.oracle.gpffp_delete_full_case(&r_no, &s_id, &a_no).await;
                slint::invoke_from_event_loop({
                    let ui_weak = ui_weak.clone();
                    move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_gpf_drop_busy(false);
                        }
                    }
                })
                .ok();

                match result {
                    Ok(_) => slint::invoke_from_event_loop(move || {
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
                    .unwrap(),
                    Err(e) => slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(
                                format!("GPFFP TRANSACTION FAILURE: {}", e).into(),
                            );
                        }
                    })
                    .unwrap(),
                }
            });
        });
    }

    // --- PURGE APPLICATION ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_request_delete_application(move |regd_no| {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();
            let r_no = regd_no.to_string();

            if let Some(ui) = ui_weak.upgrade() {
                ui.set_gpf_purge_busy(true);
            }

            tokio::spawn(async move {
                let result = ctx.oracle.gpffp_delete_from_application(&r_no).await;
                slint::invoke_from_event_loop({
                    let ui_weak = ui_weak.clone();
                    move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_gpf_purge_busy(false);
                        }
                    }
                })
                .ok();

                match result {
                    Ok(_) => slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(false);
                            ui.set_op_status_msg(
                                "SUCCESS: GPFFP Application Record purged.".into(),
                            );
                            ui.set_op_regd_no("".into());
                            ui.set_gpf_case_found(false);
                        }
                    })
                    .unwrap(),
                    Err(e) => slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(
                                format!("GPFFP TRANSACTION FAILURE: {}", e).into(),
                            );
                        }
                    })
                    .unwrap(),
                }
            });
        });
    }

    // --- FLUSH PRE-CALCULATIONS ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_request_delete_precalc(move |regd_no| {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();
            let r_no = regd_no.to_string();

            if let Some(ui) = ui_weak.upgrade() {
                ui.set_gpf_flush_busy(true);
            }

            tokio::spawn(async move {
                let result = ctx.oracle.gpffp_delete_from_pre_calculation(&r_no).await;
                slint::invoke_from_event_loop({
                    let ui_weak = ui_weak.clone();
                    move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_gpf_flush_busy(false);
                        }
                    }
                })
                .ok();

                match result {
                    Ok(_) => slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(false);
                            ui.set_op_status_msg(
                                "SUCCESS: GPFFP Pre-Calculation values updated.".into(),
                            );
                            ui.set_op_regd_no("".into());
                            ui.set_gpf_case_found(false);
                        }
                    })
                    .unwrap(),
                    Err(e) => slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(
                                format!("GPFFP TRANSACTION FAILURE: {}", e).into(),
                            );
                        }
                    })
                    .unwrap(),
                }
            });
        });
    }

    // --- DROP SIGNED AUTHORITY CERTIFICATES ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_request_delete_auth_reports(move |regd_no| {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();
            let r_no = regd_no.to_string();

            if let Some(ui) = ui_weak.upgrade() { ui.set_gpf_auth_drop_busy(true); }

            tokio::spawn(async move {
                let result = ctx.oracle.gpffp_delete_authority_reports(&r_no).await;
                slint::invoke_from_event_loop({
                    let ui_weak = ui_weak.clone();
                    move || { if let Some(ui) = ui_weak.upgrade() { ui.set_gpf_auth_drop_busy(false); } }
                }).ok();

                match result {
                    Ok(_) => slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(false);
                            ui.set_op_status_msg("SUCCESS: Associated Signed Authority & Uploaded Reports completely dropped from transaction registry.".into());
                            ui.set_op_regd_no("".into());
                            ui.set_gpf_case_found(false);
                        }
                    }).unwrap(),
                    Err(e) => slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_op_is_error(true);
                            ui.set_op_status_msg(format!("GPFFP TRANSACTION FAILURE: {}", e).into());
                        }
                    }).unwrap(),
                }
            });
        });
    }
}
