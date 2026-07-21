//! VMProtect Native SDK Bindings
//! Enforces hardware virtualization and mutation markers at compile time.
//! This is the SINGLE source of truth for the VMProtectSDK64 FFI boundary —
//! no other module in this crate should declare its own `extern "C"` block
//! for these symbols. Call the safe wrappers below instead.

use std::ffi::CString;

#[link(name = "VMProtectSDK64")]
extern "C" {
    fn VMProtectBegin(marker: *const std::ffi::c_char);
    fn VMProtectBeginMutation(marker: *const std::ffi::c_char);
    fn VMProtectBeginUltra(marker: *const std::ffi::c_char);
    fn VMProtectEnd();
    fn VMProtectIsDebuggerPresent(check_kernel_mode: bool) -> bool;
    fn VMProtectIsVirtualMachinePresent() -> bool;
}

pub fn vmp_begin(marker_name: &str) {
    if let Ok(c_name) = CString::new(marker_name) {
        unsafe {
            VMProtectBegin(c_name.as_ptr());
        }
    }
}

pub fn vmp_begin_ultra(marker_name: &str) {
    if let Ok(c_name) = CString::new(marker_name) {
        unsafe {
            VMProtectBeginUltra(c_name.as_ptr());
        }
    }
}

pub fn vmp_begin_mutation(marker_name: &str) {
    if let Ok(c_name) = CString::new(marker_name) {
        unsafe {
            VMProtectBeginMutation(c_name.as_ptr());
        }
    }
}

pub fn vmp_end() {
    unsafe {
        VMProtectEnd();
    }
}

pub fn vmp_check_debugger() -> bool {
    unsafe { VMProtectIsDebuggerPresent(true) }
}

pub fn vmp_check_vm() -> bool {
    unsafe { VMProtectIsVirtualMachinePresent() }
}
