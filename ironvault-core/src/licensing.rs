//! Hardware licensing and HWID generation
//!
//! Manages HWID generation and MAC address binding for license enforcement

use sha2::{Sha256, Digest};
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Hardware identifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareId {
    pub id: String,
    pub mac_address: String,
    pub generated_at: DateTime<Utc>,
}

/// License information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    pub id: Uuid,
    pub hwid: String,
    pub customer_name: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub is_active: bool,
}

/// License manager for validation and generation
pub struct LicenseManager;

impl LicenseManager {
    /// Generate Hardware ID from MAC address and system info
    pub fn generate_hwid(mac_address: &str) -> String {
        let combined = format!("{}-{}", mac_address, Self::system_fingerprint());
        let mut hasher = Sha256::new();
        hasher.update(combined.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Get current MAC address (platform-specific)
    pub fn get_mac_address() -> Result<String, LicenseError> {
        #[cfg(target_os = "windows")]
        {
            Self::get_mac_windows()
        }
        #[cfg(target_os = "linux")]
        {
            Self::get_mac_linux()
        }
        #[cfg(target_os = "macos")]
        {
            Self::get_mac_macos()
        }
    }

    /// Verify if a license is valid for the current hardware
    pub fn verify_license(license: &License, current_hwid: &str) -> Result<(), LicenseError> {
        if !license.is_active {
            return Err(LicenseError::LicenseInactive);
        }

        if license.hwid != current_hwid {
            return Err(LicenseError::HardwareIdMismatch);
        }

        if Utc::now() > license.expires_at {
            return Err(LicenseError::LicenseExpired);
        }

        Ok(())
    }

    /// Create a new license for a customer
    pub fn create_license(
        customer_name: &str,
        hwid: &str,
        validity_days: i64,
    ) -> License {
        let now = Utc::now();
        License {
            id: Uuid::new_v4(),
            hwid: hwid.to_string(),
            customer_name: customer_name.to_string(),
            issued_at: now,
            expires_at: now + Duration::days(validity_days),
            is_active: true,
        }
    }

    fn system_fingerprint() -> String {
        // TODO: Collect additional system info for fingerprinting
        // (CPU ID, Motherboard serial, etc.)
        "default".to_string()
    }

    #[cfg(target_os = "windows")]
    fn get_mac_windows() -> Result<String, LicenseError> {
        // TODO: Use Windows API to retrieve MAC address
        Ok("00:00:00:00:00:00".to_string())
    }

    #[cfg(target_os = "linux")]
    fn get_mac_linux() -> Result<String, LicenseError> {
        // TODO: Parse /sys/class/net or use ip command
        Ok("00:00:00:00:00:00".to_string())
    }

    #[cfg(target_os = "macos")]
    fn get_mac_macos() -> Result<String, LicenseError> {
        // TODO: Use macOS APIs to retrieve MAC address
        Ok("00:00:00:00:00:00".to_string())
    }
}

/// Licensing errors
#[derive(Debug)]
pub enum LicenseError {
    LicenseExpired,
    LicenseInactive,
    HardwareIdMismatch,
    InvalidLicense,
    MacAddressNotFound,
}
