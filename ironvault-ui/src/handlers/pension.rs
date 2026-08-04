//! P-SAI Core Pension System: biographical search and lifecycle/settlement
//! status tracking.

use crate::context::SharedContext;
use crate::{AppWindow, PensionDetailsSlint, PensionStatusSlint};
use slint::ComponentHandle;

pub fn register(app: &AppWindow, ctx: SharedContext) {
    // --- PENSIONER BIOGRAPHICAL SEARCH ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_request_pension_details(move |query_term| {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();
            let term = query_term.to_string();

            if let Some(ui) = ui_weak.upgrade() {
                ui.set_sai_query_busy(true);
            }

            tokio::spawn(async move {
                let result = ctx.oracle.pnsr_get_details(&term).await;
                slint::invoke_from_event_loop({
                    let ui_weak = ui_weak.clone();
                    move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_sai_query_busy(false);
                        }
                    }
                })
                .ok();

                match result {
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
                                ui.set_sai_biographical_list(slint::ModelRc::from(
                                    std::rc::Rc::new(slint::VecModel::from(slint_records)),
                                ));
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
    }

    // --- LIFECYCLE / SETTLEMENT STATUS TRACKING ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_request_pension_status(move |app_no| {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();
            let query_app = app_no.to_string();

            if let Some(ui) = ui_weak.upgrade() {
                ui.set_sai_query_busy(true);
            }

            tokio::spawn(async move {
                let result = ctx.oracle.pnsr_get_status_tracking(&query_app).await;
                slint::invoke_from_event_loop({
                    let ui_weak = ui_weak.clone();
                    move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_sai_query_busy(false);
                        }
                    }
                })
                .ok();

                match result {
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
                                ui.set_op_status_msg(
                                    format!("Tracking Engine Error: {}", e).into(),
                                );
                            }
                        })
                        .unwrap();
                    }
                }
            });
        });
    }
}
