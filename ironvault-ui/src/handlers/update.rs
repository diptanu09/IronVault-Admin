use crate::context::SharedContext;
use crate::AppWindow;
use slint::ComponentHandle;

// Point this at wherever you host version.json.
const UPDATE_MANIFEST_URL: &str =
    "https://raw.githubusercontent.com/diptanu09/ironvault-admin/main/version.json";

pub fn register(app: &AppWindow, _ctx: SharedContext) {
    let app_weak = app.as_weak();
    tokio::spawn(async move {
        match ironvault_core::update_check::check_for_update(UPDATE_MANIFEST_URL).await {
            Ok(status) if status.update_available => {
                let changelog_joined = status.manifest.changelog.join("\n• ");
                let download_url = status.manifest.download_url.clone();
                let latest = status.manifest.latest_version.clone();
                let mandatory = status.mandatory;

                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = app_weak.upgrade() {
                        ui.set_update_available(true);
                        ui.set_update_mandatory(mandatory);
                        ui.set_update_latest_version(latest.into());
                        ui.set_update_changelog(format!("• {}", changelog_joined).into());
                        ui.set_update_download_url(download_url.into());
                    }
                })
                .ok();
            }
            Ok(_) => { /* already up to date, nothing to show */ }
            Err(e) => log::warn!("[UPDATE] Version check failed (non-fatal): {}", e),
        }
    });

    let app_weak2 = app.as_weak();
    app.on_request_open_download_url(move || {
        if let Some(ui) = app_weak2.upgrade() {
            let url = ui.get_update_download_url().to_string();
            // Opens the OS-default browser to the download page — the
            // operator (or you, centrally) still controls the actual
            // install, nothing runs automatically.
            let _ = std::process::Command::new("cmd")
                .args(["/C", "start", "", &url])
                .spawn();
        }
    });
}
