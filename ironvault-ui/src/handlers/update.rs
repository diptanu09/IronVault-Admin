use crate::context::SharedContext;
use crate::AppWindow;
use slint::ComponentHandle;
use std::path::PathBuf;

// Point this at wherever you host version.json.
const UPDATE_MANIFEST_URL: &str =
    "https://raw.githubusercontent.com/diptanu09/ironvault-admin/main/version.json";

fn dismissed_version_path() -> PathBuf {
    PathBuf::from("./storage/.dismissed_update_version")
}

fn already_dismissed(version: &str) -> bool {
    std::fs::read_to_string(dismissed_version_path())
        .map(|s| s.trim() == version)
        .unwrap_or(false)
}

fn record_dismissal(version: &str) {
    let path = dismissed_version_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, version);
}

pub fn register(app: &AppWindow, _ctx: SharedContext) {
    let app_weak = app.as_weak();
    tokio::spawn(async move {
        match ironvault_core::update_check::check_for_update(UPDATE_MANIFEST_URL).await {
            Ok(status) if status.update_available => {
                // Mandatory updates always show, regardless of prior dismissal.
                // Optional updates respect a prior "remind me later" for this
                // specific version — a NEWER version released later will still
                // show, since the dismissal is tied to the exact version string.
                if !status.mandatory && already_dismissed(&status.manifest.latest_version) {
                    return;
                }

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
            // Opens the OS-default browser to the download page
            let _ = std::process::Command::new("cmd")
                .args(["/C", "start", "", &url])
                .spawn();
        }
    });

    let app_weak3 = app.as_weak();
    app.on_request_dismiss_update_notice(move |version| {
        let _ = app_weak3;
        record_dismissal(&version.to_string());
    });
}
