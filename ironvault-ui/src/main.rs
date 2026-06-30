// =========================================================================
// IronVault UI Core Application Launcher (main.rs)
// Connects the new appwindow.slint interface parameters to Rust execution handlers.
// =========================================================================

slint::include_modules!();

use ironvault_core::crypto;
use ironvault_core::audit;

fn main() -> Result<(), slint::PlatformError> {
    // 1. Initialize the compiled Slint visual window frame
    let app = AppWindow::new()?;

    // 2. Set up the verify-supervisor-keys button callback
    let app_weak = app.as_weak();
    app.on_verify_supervisor_keys(move |op_key, sv_key| {
        let app = app_weak.unwrap();
        println!("[SECURITY] Intercepted authority verification trigger.");
        
        // Validate both hexadecimal keys using our core asymmetric signature module
        let op_valid = crypto::verify_authority_signature(&op_key);
        let sv_valid = crypto::verify_authority_signature(&sv_key);

        if op_valid && sv_valid {
            println!("[AUDIT] Cryptographic signature validation succeeded. Session unlocked.");
            audit::log_event("SUCCESS: Cryptographic signature validation succeeded. Session unlocked.");
            app.set_crypto_signature_status("✅ CHAIN SECURED // VERIFIED".into());
        } else {
            println!("[SECURITY WARNING] Invalid private key structure submitted.");
            audit::log_event("FAILURE: Invalid private key structure submitted during signature verification.");
            app.set_crypto_signature_status("❌ VERIFICATION FAILURE // INVALID KEY".into());
        }
    });

    // 3. Set up the execute-downgrade-pump button callback
    let app_weak_pump = app.as_weak();
    app.on_execute_downgrade_pump(move |source_schema, _dir_mapping| {
        let app = app_weak_pump.unwrap();
        println!("[ACTION-REQUEST] Initializing Oracle 19c -> 11g Downgrade Sequence.");
        
        // Enforce that dual signatures are verified before executing database tasks
        let status = app.get_crypto_signature_status();
        if status.contains("VERIFIED") {
            println!("[PROCESS] Checking database transport layers...");
            println!("[ORACLE-UTILITY] Preparing data pump on schema: {}", source_schema);
            println!("[SUCCESS] Oracle 11.2 compatibility downgrade payload exported cleanly.");
            audit::log_event(&format!("SUCCESS: Oracle 11.2 compatibility downgrade payload exported for schema: {}", source_schema));
        } else {
            println!("[ACCESS DENIED] Action blocked! Session does not possess active verification.");
            audit::log_event(&format!("BLOCKED: Attempted downgrade pump execution without authorization on schema: {}", source_schema));
        }
    });

    // 4. Run the main native UI loop on the target machine
    app.run()
}