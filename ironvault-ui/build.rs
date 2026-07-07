// Build script for Slint UI compilation

use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;

fn main() {
    // Register all required Lucide vector mappings
    let required_icons = vec![
        ("layout-dashboard", "layout-dashboard.svg"),
        ("database", "database.svg"),
        ("bell", "bell.svg"),
        ("users", "users.svg"),
        ("log-out", "log-out.svg"),
    ];

    let assets_dir = Path::new("ui/assets");
    if !assets_dir.exists() {
        create_dir_all(assets_dir).unwrap();
    }

    // Verify presence or handle background download execution loop
    for (icon_name, filename) in required_icons {
        let dest_path = assets_dir.join(filename);
        
        if !dest_path.exists() {
            println!("cargo:warning=[LUCIDE PIPELINE] Downloading vector mapping: {}", filename);
            let target_url = format!(
                "https://raw.githubusercontent.com/lucide-icons/lucide/main/icons/{}.svg",
                icon_name
            );

            if let Ok(response) = reqwest::blocking::get(&target_url) {
                if response.status().is_success() {
                    if let Ok(svg_content) = response.text() {
                        let mut file = File::create(&dest_path).unwrap();
                        file.write_all(svg_content.as_bytes()).unwrap();
                    }
                } else {
                    panic!("[FATAL SYNC REJECTION] Icon download failure from remote repository: {}", icon_name);
                }
            }
        }
    }

    // Pass task execution to Slint compiler step
    slint_build::compile("ui/main.slint").unwrap();
}