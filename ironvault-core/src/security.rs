//! Security validation for anti-debug, anti-dump, and VM detection
//!
//! Provides runtime security checks to prevent unauthorized access and
//! tampering. All VMProtect FFI calls are routed through `sdk_vmp`, which is
//! the single source of truth for that library's ABI — this module contains
//! no `extern "C"` declarations of its own, avoiding the risk of two
//! independent, potentially-drifting declarations for the same native
//! function signatures.

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    CheckRemoteDebuggerPresent, IsDebuggerPresent,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use crate::sdk_vmp;
use std::time::Duration;

// Idiomatic CPUID intrinsics to safely bypass LLVM rbx/ebx register constraints
#[cfg(target_arch = "x86")]
use std::arch::x86::__cpuid;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::__cpuid;

/// Synchronous, best-effort security-fault logger for use in contexts about
/// to hard-exit (where spawning an async DB write isn't reliable). Appends
/// directly to the same file AuditLogger uses, bypassing its async API.
fn log_security_fault_sync(event: &str) {
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("ironvault.audit.log")
    {
        let line = format!(
            "{{\"timestamp\":\"{}\",\"event\":\"{}\",\"source\":\"security.rs\"}}\n",
            chrono::Utc::now().to_rfc3339(),
            event
        );
        let _ = file.write_all(line.as_bytes());
    }
}

/// Executes critical system checks wrapped in native VMProtect virtualization markers.
/// Spawns a background worker loop thread to continuously check system integrity states.
pub fn enforce_core_security_checks(current_hwid: &str) {
    sdk_vmp::vmp_begin_ultra("CoreEnforceChecks");
    std::hint::black_box(current_hwid);

    SecurityValidator::enforce_anti_debug();
    SecurityValidator::enforce_vm_detection();

    tokio::spawn(async {
        loop {
            tokio::time::sleep(Duration::from_secs(4)).await;
            SecurityValidator::enforce_anti_debug();
            SecurityValidator::enforce_vm_detection(); // now also periodic, not just at boot
        }
    });

    println!("[SECURITY Engine] All runtime environment integrity tokens verified and active monitor engaged.");
    sdk_vmp::vmp_end();
}

pub struct SecurityValidator;

impl SecurityValidator {
    pub fn new() -> Self {
        Self
    }

    /// Multi-layered baseline check to intercept basic local and remote debuggers
    pub fn enforce_anti_debug() {
        sdk_vmp::vmp_begin_mutation("AntiDebugCheck");

        // Tier 1 SDK Engine Check (routed through the shared sdk_vmp module,
        // not a locally-declared FFI signature).
        if sdk_vmp::vmp_check_debugger() {
            eprintln!(
                "[SECURITY_FAULT] Hardware debugger intercepted via ring-0 virtualization hook."
            );
            log_security_fault_sync("DEBUGGER_DETECTED_SDK_CHECK");
            std::process::exit(1);
        }

        #[cfg(target_os = "windows")]
        unsafe {
            if IsDebuggerPresent() != 0 {
                eprintln!(
                    "[SECURITY_FAULT] Unauthorized debug attachment detected. Self-terminating."
                );
                log_security_fault_sync("DEBUGGER_DETECTED_PEB_FLAG");
                std::process::exit(1);
            }

            let mut is_remote_debugger = 0;
            let current_proc = GetCurrentProcess();
            if CheckRemoteDebuggerPresent(current_proc, &mut is_remote_debugger) != 0
                && is_remote_debugger != 0
            {
                eprintln!(
                    "[SECURITY_FAULT] Remote socket debugging engine intercepted. Access revoked."
                );
                log_security_fault_sync("DEBUGGER_DETECTED_REMOTE");
                std::process::exit(1);
            }
        }

        sdk_vmp::vmp_end();
    }

    /// Hardened hardware-level hypervisor validation using intrinsic x86/x64 CPUID registers
    pub fn enforce_vm_detection() {
        sdk_vmp::vmp_begin_mutation("VmDetectionCheck");

        if sdk_vmp::vmp_check_vm() {
            eprintln!("[SECURITY_FAULT] Dynamic virtualization runtime container identified.");
            log_security_fault_sync("VM_DETECTED_SDK_CHECK");
            std::process::exit(1);
        }

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            let leaf_1 = __cpuid(1);

            if (leaf_1.ecx & (1 << 31)) != 0 {
                let signature_leaf = __cpuid(0x40000000);

                let mut brand_bytes = Vec::new();
                brand_bytes.extend_from_slice(&signature_leaf.ebx.to_le_bytes());
                brand_bytes.extend_from_slice(&signature_leaf.ecx.to_le_bytes());
                brand_bytes.extend_from_slice(&signature_leaf.edx.to_le_bytes());

                let vm_signature = String::from_utf8_lossy(&brand_bytes).trim().to_string();

                eprintln!(
                    "[SECURITY_FAULT] Virtualized sandbox environment intercepted (Type: {}). Execution blocked.",
                    vm_signature
                );
                log_security_fault_sync(&format!(
                    "VM_DETECTED_CPUID_HYPERVISOR_BIT type={}",
                    vm_signature
                ));
                std::process::exit(1);
            }
        }

        sdk_vmp::vmp_end();
    }
}

pub fn enforce_anti_debug() {
    SecurityValidator::enforce_anti_debug();
}

pub fn enforce_vm_detection() {
    SecurityValidator::enforce_vm_detection();
}
// TEMPORARY test-only function to verify log_security_fault_sync actually
// writes to disk, without needing to trigger a real debugger/VM detection
// event. Remove this function once verified.
// pub fn test_log_security_fault() {
//     log_security_fault_sync("TEST_MANUAL_TRIGGER");
//     println!("[TEST] Attempted to write TEST_MANUAL_TRIGGER to ironvault.audit.log");
// }
