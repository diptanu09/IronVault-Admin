// =========================================================================
// IronVault Core UI Event Handlers & Controllers (controllers.rs)
// =========================================================================
use crate::AppWindow;
use slint::ComponentHandle;

pub fn setup_event_handlers(app: &AppWindow) {
    let app_weak = app.as_weak();

    // 1. Hook Up Oracle 11g Button Processing
    app.on_execute_11g_action(move |schema, action| {
        let ui = app_weak.unwrap();
        let target_schema = schema.as_str().trim().to_string();
        let action_type = action.as_str().trim().to_string();

        ui.set_status_text(format!("CONNECTING LIVE TO ORACLE 11G [{}]...", target_schema).into());

        let app_handle = app_weak.clone();
        std::thread::spawn(move || {
            // Forward variables directly to the core 11g driver engine
            let result = ironvault_db::oracle_11g::run_11g_operation(&target_schema, &action_type);

            let _ = slint::invoke_from_event_loop(move || {
                let ui_thread = app_handle.unwrap();
                match result {
                    Ok(msg) => {
                        ui_thread.set_status_text(msg.into());
                    }
                    Err(err) => {
                        ui_thread.set_status_text(format!("11G SYSTEM FAULT: {}", err).into());
                    }
                }
            });
        });
    });

    let app_weak_12c = app.as_weak();
    // 2. Hook Up Oracle 12c Button Processing
    app.on_execute_12c_action(move |schema, action| {
        let ui = app_weak_12c.unwrap();
        let target_schema = schema.as_str().trim().to_string();
        let action_type = action.as_str().trim().to_string();

        ui.set_status_text(format!("ROUTING COMMAND TO ORACLE 12C [{}]...", target_schema).into());

        let app_handle = app_weak_12c.clone();
        std::thread::spawn(move || {
            // Forward variables directly to the core 12c driver engine
            let result = ironvault_db::oracle_12c::run_12c_operation(&target_schema, &action_type);

            let _ = slint::invoke_from_event_loop(move || {
                let ui_thread = app_handle.unwrap();
                match result {
                    Ok(msg) => {
                        ui_thread.set_status_text(msg.into());
                    }
                    Err(err) => {
                        ui_thread.set_status_text(format!("12C SYSTEM FAULT: {}", err).into());
                    }
                }
            });
        });
    });
}