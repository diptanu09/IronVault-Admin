slint::include_modules!();
mod controllers;

fn main() -> Result<(), slint::PlatformError> {
    println!("[BOOT] Launching IronVault Integrated Management Engine...");
    
    // Fire up our connection tracker simulator
    if let Ok(token) = ironvault_db::postgres::verify_internal_session("admin") {
        println!("[SUCCESS] Secure local state binding token compiled: '{}'", token);
    }

    let app = AppWindow::new()?;
    controllers::setup_event_handlers(&app);
    
    app.run()
}