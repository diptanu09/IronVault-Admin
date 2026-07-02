// =========================================================================
// IronVault Main Executable Controller & Event Handler (main.rs)
// =========================================================================

slint::include_modules!();

mod auth;
mod controllers;

use ironvault_core::database::postgres;

fn main() -> Result<(), slint::PlatformError> {
    // 1. Securely load target DB URI from environment variables or default to standard parameters
    let db_uri = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "host=10.47.240.169 port=5432 user=egpf_app_user password=P@ssw()rd123 dbname=AsstPro sslmode=disable".to_string()
    });

    println!("[BOOT] Launching IronVault Administration Console Services...");

    // 2. Compute physical workstation machine binding tracking footprint
    let machine_fingerprint = auth::get_hardware_machine_id();
    println!("[SECURITY] Computed Local Machine Binding Token: '{}'", machine_fingerprint);

    // 3. Perform a cold startup diagnostic test to ensure network database cluster is live
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let boot_uri = db_uri.clone();
    
    runtime.block_on(async {
        match postgres::establish_secure_connection(&boot_uri).await {
            Ok(_) => {
                println!("[SUCCESS] Secure socket handshake confirmed with database target cluster.");
            }
            Err(e) => {
                eprintln!("[BOOT WARNING] Remote database cluster unreached over active interfaces: {}", e);
            }
        }
    });

    // 4. Instantiate the desktop UI window object
    let app = AppWindow::new()?;

    // 5. Wire the user interface controllers up to your schema endpoints
    controllers::wire_ui_event_handlers(&app.as_weak(), db_uri, machine_fingerprint);

    // 6. Enter the main operating system thread execution loop
    println!("[RUNTIME] IronVault Admin Window active. Relaying input event chains.");
    app.run()
}