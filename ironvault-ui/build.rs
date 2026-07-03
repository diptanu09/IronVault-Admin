// Build script for Slint UI compilation

fn main() {
    let config = slint_build::CompilerConfiguration::new()
        .with_style("fluent-dark".into());
    
    slint_build::compile_with_config("ui/main.slint", config)
        .expect("Failed to compile Slint UI");
}
