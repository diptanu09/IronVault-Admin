//! Pension DAK Diary UI event handlers: authority auto-fetch, outward case
//! submission, find/update/link-correspondence flows.

use crate::context::SharedContext;
use crate::AppWindow;
use slint::ComponentHandle;

pub fn register(app: &AppWindow, ctx: SharedContext) {
    // --- AUTO-FETCH PPO/FPPO/GPO/CPO & ADDRESSEE FOR AN APPLICATION NO ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_request_find_pension_dak_meta(move |search_app_num| {
            let ui = app_weak.unwrap();
            let ctx = ctx.clone();
            let target_app = search_app_num.to_string().trim().to_string();
            if target_app.is_empty() {
                ui.set_dak_ppo("".into());
                ui.set_dak_fppo("".into());
                ui.set_dak_gpo("".into());
                ui.set_dak_cpo("".into());
                ui.set_dak_adr_1("".into());
                ui.set_dak_adr_2("".into());
                ui.set_dak_adr_3("".into());
                return;
            }
            let ui_weak = app_weak.clone();
            tokio::spawn(async move {
                match ctx.oracle.pendak_fetch_auth_details(&target_app).await {
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

                                // Auto-fill Addressee Name across ALL recipient fields (#1, #2, #3)
                                if !details.addressee_name.is_empty() {
                                    let name: slint::SharedString = details.addressee_name.into();
                                    ui_handle.set_dak_adr_1(name.clone());
                                    ui_handle.set_dak_adr_2(name.clone());
                                    ui_handle.set_dak_adr_3(name);
                                }

                                ui_handle.set_op_is_error(false);
                                ui_handle.set_op_status_msg(
                                    "SUCCESS: Associated pension authorities and addressee auto-fetched."
                                        .into(),
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
                                ui_handle
                                    .set_op_status_msg(format!("Auto-Fetch Error: {}", e).into());
                            }
                        })
                        .unwrap();
                    }
                }
            });
        });
    }

    // --- SUBMIT OUTWARD DAK CASE ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_request_submit_outward_dak(move || {
            let ui = app_weak.unwrap();
            let ctx = ctx.clone();

            let app_num = ui.get_entry_app_num().to_string().trim().to_string();
            let ppo = ui.get_dak_ppo().to_string();
            let fppo = ui.get_dak_fppo().to_string();
            let gpo = ui.get_dak_gpo().to_string().trim().to_string();
            let cpo = ui.get_dak_cpo().to_string().trim().to_string();
            let section = ui.get_entry_section().to_string().trim().to_string();
            let subject = ui.get_entry_subject().to_string().trim().to_string();
            let copies_str = ui.get_entry_no_of_copies().to_string();
            let copies_count: i32 = copies_str.parse().unwrap_or(1);

            // Mandatory Validation: Application No, Section, and Subject are required
            if app_num.is_empty() || section.is_empty() || subject.is_empty() {
                ui.set_op_is_error(true);
                ui.set_op_status_msg(
                    "Validation Fault: Application No, Section, and Subject fields are strictly mandatory.".into(),
                );
                return;
            }

            let sb_to_code = |val: slint::SharedString| -> String {
                if val.to_lowercase().contains("yes") || val.to_lowercase() == "y" {
                    "Y".to_string()
                } else {
                    "N".to_string()
                }
            };

            let mut recipients = Vec::new();
            if copies_count >= 1 {
                recipients.push(ironvault_db::oracle::DakRecipientDetail {
                    addressee: ui.get_dak_adr_1().to_string(),
                    barcode: ui.get_dak_bar_1().to_string(),
                    sent_by: ui.get_dak_sent_1().to_string(),
                    service_book: sb_to_code(ui.get_dak_sb_1()),
                });
            }
            if copies_count >= 2 && (copies_str == "2" || copies_str == "3") {
                recipients.push(ironvault_db::oracle::DakRecipientDetail {
                    addressee: ui.get_dak_adr_2().to_string(),
                    barcode: ui.get_dak_bar_2().to_string(),
                    sent_by: ui.get_dak_sent_2().to_string(),
                    service_book: sb_to_code(ui.get_dak_sb_2()),
                });
            }
            if copies_count == 3 && copies_str == "3" {
                recipients.push(ironvault_db::oracle::DakRecipientDetail {
                    addressee: ui.get_dak_adr_3().to_string(),
                    barcode: ui.get_dak_bar_3().to_string(),
                    sent_by: ui.get_dak_sent_3().to_string(),
                    service_book: sb_to_code(ui.get_dak_sb_3()),
                });
            }

            let ui_weak = app_weak.clone();
            let ppo_combined = format!("PPO: {} / FPPO: {}", ppo, fppo);

            let transaction_payload = ironvault_db::oracle::PensionDakEntry {
                app_num: app_num.clone(),
                letter_no: format!("DAK-{}", app_num),
                ppo_fppo: ppo_combined,
                gpo,
                cpo,
                section,
                subject,
                copies_count,
                recipients,
            };

            tokio::spawn(async move {
                match ctx
                    .oracle
                    .pendak_insert_outward_case(transaction_payload)
                    .await
                {
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
                                ui_handle.set_dak_ppo("".into());
                                ui_handle.set_dak_fppo("".into());
                                ui_handle.set_dak_gpo("".into());
                                ui_handle.set_dak_cpo("".into());
                                ui_handle.set_entry_section("".into());
                                ui_handle.set_entry_subject("".into());
                                ui_handle.set_entry_no_of_copies("1".into());
                                ui_handle.set_dak_adr_1("".into());
                                ui_handle.set_dak_bar_1("".into());
                                ui_handle.set_dak_sent_1("Speed Post".into());
                                ui_handle.set_dak_sb_1("No".into());
                                ui_handle.set_dak_adr_2("".into());
                                ui_handle.set_dak_bar_2("".into());
                                ui_handle.set_dak_sent_2("Speed Post".into());
                                ui_handle.set_dak_sb_2("No".into());
                                ui_handle.set_dak_adr_3("".into());
                                ui_handle.set_dak_bar_3("".into());
                                ui_handle.set_dak_sent_3("Speed Post".into());
                                ui_handle.set_dak_sb_3("No".into());
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
    }

    // --- FIND OUTWARD DAK CASE ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_request_find_outward_dak(move |search_key| {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();
            let target = search_key.to_string().trim().to_string();
            if target.is_empty() {
                return;
            }
            tokio::spawn(async move {
                match ctx.oracle.pendak_select_outward_case_full(&target).await {
                    Ok(Some(record)) => {
                        slint::invoke_from_event_loop(move || {
                            if let Some(ui) = ui_weak.upgrade() {
                                ui.set_dak_case_found(true);
                                ui.set_op_is_error(false);
                                ui.set_op_status_msg(
                                    "SUCCESS: Outward Case matched inside storage vault.".into(),
                                );
                                ui.set_view_dak_letter(record.letter_no.into());
                                ui.set_view_dak_section(record.section.into());
                                ui.set_view_dak_subject(record.subject.into());
                                ui.set_dak_corr_date(record.created_at.into());
                                ui.set_dak_ppo(record.ppo_no.into());
                                ui.set_dak_fppo(record.fppo_no.into());
                                ui.set_dak_gpo(record.gpo_no.into());
                                ui.set_dak_cpo(record.cpo_no.into());
                                ui.set_dak_adr_1(record.addressee.into());
                                ui.set_dak_bar_1(record.barcode.into());
                                ui.set_dak_sent_1(record.sent_by.into());
                            }
                        })
                        .unwrap();
                    }
                    Ok(None) => {
                        slint::invoke_from_event_loop(move || {
                            if let Some(ui) = ui_weak.upgrade() {
                                ui.set_dak_case_found(false);
                                ui.set_op_is_error(true);
                                ui.set_op_status_msg(
                                    "Discovery Fault: Given index key doesn't exist inside archive registry.".into(),
                                );
                            }
                        })
                        .unwrap();
                    }
                    Err(e) => {
                        slint::invoke_from_event_loop(move || {
                            if let Some(ui) = ui_weak.upgrade() {
                                ui.set_dak_case_found(false);
                                ui.set_op_is_error(true);
                                ui.set_op_status_msg(
                                    format!("ORACLE LOOKUP REJECTION: {}", e).into(),
                                );
                            }
                        })
                        .unwrap();
                    }
                }
            });
        });
    }

    // --- UPDATE OUTWARD DAK CASE ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_request_update_outward_dak(move || {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();
            let ui = app_weak.unwrap();

            let app_num = ui.get_edit_app_num().to_string().trim().to_string();
            let section = ui.get_edit_section().to_string().trim().to_string();
            let subject = ui.get_edit_subject().to_string().trim().to_string();

            if app_num.is_empty() || section.is_empty() || subject.is_empty() {
                ui.set_op_is_error(true);
                ui.set_op_status_msg(
                    "Fault: Fields required to execute modifications are empty.".into(),
                );
                return;
            }
            tokio::spawn(async move {
                match ctx
                    .oracle
                    .pendak_update_outward_case(&app_num, &section, &subject)
                    .await
                {
                    Ok(_) => {
                        slint::invoke_from_event_loop(move || {
                            if let Some(ui_handle) = ui_weak.upgrade() {
                                ui_handle.set_op_is_error(false);
                                ui_handle.set_op_status_msg(
                                    format!(
                                        "SUCCESS: Modification matrix applied cleanly to profile record {}",
                                        app_num
                                    )
                                    .into(),
                                );
                                ui_handle.set_edit_app_num("".into());
                                ui_handle.set_edit_section("".into());
                                ui_handle.set_edit_subject("".into());
                            }
                        })
                        .unwrap();
                    }
                    Err(e) => {
                        slint::invoke_from_event_loop(move || {
                            if let Some(ui_handle) = ui_weak.upgrade() {
                                ui_handle.set_op_is_error(true);
                                ui_handle.set_op_status_msg(
                                    format!("ORACLE UPDATE FAULT: {}", e).into(),
                                );
                            }
                        })
                        .unwrap();
                    }
                }
            });
        });
    }

    // --- LINK CORRESPONDENCE (LETTER) ---
    {
        let app_weak = app.as_weak();
        let ctx = ctx.clone();
        app.on_request_submit_correspondence(move || {
            let ui_weak = app_weak.clone();
            let ctx = ctx.clone();
            let ui = app_weak.unwrap();

            let app_num = ui.get_letter_app_num().to_string().trim().to_string();
            let letter_no = ui.get_letter_letter_no().to_string().trim().to_string();
            let section = ui.get_letter_section().to_string().trim().to_string();
            let subject = ui.get_letter_subject().to_string().trim().to_string();
            let copies_count: i32 = ui
                .get_letter_no_of_copies()
                .to_string()
                .parse()
                .unwrap_or(1);

            let letter_payload = ironvault_db::oracle::PensionDakEntry {
                app_num: app_num.clone(),
                letter_no: letter_no.clone(),
                ppo_fppo: ui.get_dak_ppo().to_string(),
                gpo: ui.get_dak_gpo().to_string(),
                cpo: ui.get_dak_cpo().to_string(),
                section: section.clone(),
                subject: subject.clone(),
                copies_count,
                recipients: vec![ironvault_db::oracle::DakRecipientDetail {
                    addressee: ui.get_dak_adr_1().to_string(),
                    barcode: ui.get_dak_bar_1().to_string(),
                    sent_by: ui.get_dak_sent_1().to_string(),
                    service_book: "N".to_string(),
                }],
            };

            tokio::spawn(async move {
                match ctx
                    .oracle
                    .pendak_insert_outward_case(letter_payload)
                    .await
                {
                    Ok(_) => {
                        slint::invoke_from_event_loop(move || {
                            if let Some(ui_handle) = ui_weak.upgrade() {
                                ui_handle.set_op_is_error(false);
                                ui_handle.set_op_status_msg(
                                    format!(
                                        "SUCCESS: Letter component {} successfully linked into diary registry.",
                                        letter_no
                                    )
                                    .into(),
                                );
                                ui_handle.set_letter_app_num("".into());
                                ui_handle.set_letter_letter_no("".into());
                                ui_handle.set_letter_section("".into());
                                ui_handle.set_letter_subject("".into());
                                ui_handle.set_dak_adr_1("".into());
                                ui_handle.set_dak_bar_1("".into());
                                ui_handle.set_dak_sent_1("Speed Post".into());
                            }
                        })
                        .unwrap();
                    }
                    Err(e) => {
                        slint::invoke_from_event_loop(move || {
                            if let Some(ui_handle) = ui_weak.upgrade() {
                                ui_handle.set_op_is_error(true);
                                ui_handle.set_op_status_msg(
                                    format!("ORACLE LETTER FAULT: {}", e).into(),
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
