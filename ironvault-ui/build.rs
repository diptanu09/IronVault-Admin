// =========================================================================
// IronVault Slint UI Builder Script (build.rs)
// Instructs Cargo to compile the Slint markup and export the AppWindow module.
// =========================================================================

fn main() {
    // Compile and export the main UI module
    slint_build::compile("ui/appwindow.slint").expect("Failed to compile Slint UI assets!");
}