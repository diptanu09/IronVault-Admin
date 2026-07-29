//! Update notification: checks a remotely-hosted version manifest and
//! compares it against this build's own version. Does NOT download or
//! execute anything automatically — it only informs the UI layer, which
//! presents a manual "go download" action to the operator. See module docs
//! in the UI layer for why silent self-updating is deliberately not
//! implemented here yet.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct VersionManifest {
    pub latest_version: String,
    pub release_date: String,
    pub changelog: Vec<String>,
    pub download_url: String,
    pub minimum_supported_version: String,
}

#[derive(Debug, Clone)]
pub struct UpdateStatus {
    pub update_available: bool,
    pub mandatory: bool,
    pub manifest: VersionManifest,
}

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn check_for_update(manifest_url: &str) -> Result<UpdateStatus, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .map_err(|e| e.to_string())?;

    let manifest: VersionManifest = client
        .get(manifest_url)
        .send()
        .await
        .map_err(|e| format!("Update check failed: {}", e))?
        .json()
        .await
        .map_err(|e| format!("Malformed version manifest: {}", e))?;

    let current = semver::Version::parse(CURRENT_VERSION).map_err(|e| e.to_string())?;
    let latest = semver::Version::parse(&manifest.latest_version).map_err(|e| e.to_string())?;
    let minimum =
        semver::Version::parse(&manifest.minimum_supported_version).map_err(|e| e.to_string())?;

    Ok(UpdateStatus {
        update_available: latest > current,
        mandatory: current < minimum,
        manifest,
    })
}
