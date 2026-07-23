//! Windows Credential Manager integration for storing/retrieving the
//! database password outside of plaintext config files.
//!
//! Uses DPAPI-backed Windows Credential Manager (via the CredRead/CredWrite
//! Win32 APIs) rather than custom encryption — this ties the stored secret
//! to the Windows user account and machine, and is the OS-native answer to
//! "how do I store a secret at rest on this machine" rather than a
//! home-rolled scheme.
//!
//! Given physical access is part of the deployment's threat model, this
//! closes a real gap: previously IRONVAULT_DB_PASSWORD sat as plaintext in
//! .env, readable by anyone with filesystem access to the machine. Credential
//! Manager entries are encrypted at rest and only decryptable by the same
//! Windows user account (or, depending on persistence flags, machine) that
//! stored them.

#[cfg(target_os = "windows")]
mod windows_impl {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_NOT_FOUND;
    use windows::Win32::Security::Credentials::{
        CredDeleteW, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
        CRED_TYPE_GENERIC,
    };

    const TARGET_NAME: &str = "IronVault_DB_Password";

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn store_password(password: &str) -> Result<(), String> {
        let target_wide = to_wide(TARGET_NAME);
        let mut blob = password.as_bytes().to_vec();

        let credential = CREDENTIALW {
            Flags: windows::Win32::Security::Credentials::CRED_FLAGS(0),
            Type: CRED_TYPE_GENERIC,
            TargetName: PCWSTR(target_wide.as_ptr() as *mut u16),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_mut_ptr(),
            ..Default::default()
        };

        unsafe {
            CredWriteW(&credential, 0).map_err(|e| {
                format!(
                    "Failed to write credential to Windows Credential Manager: {:?}",
                    e
                )
            })
        }
    }

    pub fn read_password() -> Result<Option<String>, String> {
        let target_wide = to_wide(TARGET_NAME);
        let mut pcred: *mut CREDENTIALW = std::ptr::null_mut();

        unsafe {
            match CredReadW(
                PCWSTR(target_wide.as_ptr()),
                CRED_TYPE_GENERIC,
                0,
                &mut pcred,
            ) {
                Ok(()) => {
                    let cred = &*pcred;
                    let blob = std::slice::from_raw_parts(
                        cred.CredentialBlob,
                        cred.CredentialBlobSize as usize,
                    );
                    let password = String::from_utf8_lossy(blob).to_string();
                    windows::Win32::Security::Credentials::CredFree(pcred as *const _);
                    Ok(Some(password))
                }
                Err(e) if e.code() == ERROR_NOT_FOUND.to_hresult() => Ok(None),
                Err(e) => Err(format!(
                    "Failed to read credential from Windows Credential Manager: {:?}",
                    e
                )),
            }
        }
    }

    pub fn delete_password() -> Result<(), String> {
        let target_wide = to_wide(TARGET_NAME);
        unsafe {
            CredDeleteW(PCWSTR(target_wide.as_ptr()), CRED_TYPE_GENERIC, 0)
                .map_err(|e| format!("Failed to delete credential: {:?}", e))
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod fallback_impl {
    // Non-Windows targets: no Credential Manager equivalent wired up here.
    // Falls through to .env-based password loading in main.rs. If IronVault
    // ever targets Linux/macOS, this would need a platform-appropriate
    // secret store (e.g. libsecret on Linux, Keychain on macOS) — flagging
    // rather than silently pretending cross-platform support exists.
    pub fn store_password(_password: &str) -> Result<(), String> {
        Err("Credential Manager integration is Windows-only in this build.".to_string())
    }
    pub fn read_password() -> Result<Option<String>, String> {
        Ok(None)
    }
    pub fn delete_password() -> Result<(), String> {
        Err("Credential Manager integration is Windows-only in this build.".to_string())
    }
}

#[cfg(not(target_os = "windows"))]
pub use fallback_impl::*;
#[cfg(target_os = "windows")]
pub use windows_impl::*;
