//! IronVault Admin UI - Bootstrapper & Main Thread
//!
//! Initializes the Slint UI framework and establishes connections
//! to the core security and database layers

mod controllers;

use ironvault_core::{SecurityValidator, LicenseManager};
use ironvault_db::PostgresConnection;
use log::info;

slint::include_modules!();

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_default_env()
        .format_timestamp_millis()
        .init();

    info!("=== IronVault Admin Starting ===");

    // Perform security validation
    if let Err(e) = SecurityValidator::validate_environment() {
        log::error!("Security validation failed: {:?}", e);
        return Err(format!("Security check failed: {:?}", e).into());
    }

    info!("✓ Security validation passed");

    // Initialize database connection
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://admin:password@localhost/ironvault".to_string());
    
    let db = PostgresConnection::new(&db_url).await?;
    info!("✓ Database connection established");

    // Initialize Slint UI
    let ui = MainWindow::new()?;
    
    // Configure window properties
    ui.set_app_version("1.0.0".into());
    ui.set_copyright_text("© 2024 IronVault. All rights reserved.".into());

    // Setup event handlers
    setup_event_handlers(&ui)?;

    info!("✓ UI initialized successfully");
    info!("=== IronVault Admin Ready ===");

    // Run the UI event loop
    ui.run()?;

    // Cleanup
    db.close().await?;
    info!("✓ Application shutdown complete");

    Ok(())
}

/// Setup event handlers and signal connections
fn setup_event_handlers(ui: &MainWindow) -> Result<(), Box<dyn std::error::Error>> {
    // Wire up button callbacks
    let ui_handle = ui.as_weak();
    
    ui.on_login_clicked(move |username, password| {
        let ui = ui_handle.upgrade().unwrap();
        // Delegate to controller
        controllers::handle_login_action(&username, &password, &ui);
    });

    Ok(())
}
