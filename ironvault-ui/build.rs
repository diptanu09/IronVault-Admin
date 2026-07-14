// Build script for Slint UI compilation

use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;

fn main() {
    // 1. Tell Cargo when to rerun this script (improves incremental build speeds)
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=ui/main.slint");

    // Register all required Lucide vector mappings (CDN name, local filename)
    let required_icons = vec![
        ("layout-dashboard", "layout-dashboard.svg"),
        ("database", "database.svg"),
        ("bell", "bell.svg"),
        ("users", "users.svg"),
        ("log-out", "log-out.svg"),
        ("check", "check.svg"),
        ("settings", "settings.svg"),
        ("shield", "shield.svg"),
        ("file-text", "file-text.svg"),
        ("activity", "activity.svg"),
        ("mail", "mail.svg"),
        ("radio", "radio.svg"),
        ("zap", "zap.svg"),
    ];

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR env var is missing; are you running via Cargo?");
    let base_path = Path::new(&manifest_dir);
    let assets_dir = base_path.join("ui/assets");

    // Ensure the ui/assets folder exists
    if !assets_dir.exists() {
        create_dir_all(&assets_dir).unwrap_or_else(|e| {
            panic!(
                "[FATAL] Failed to create assets directory {:?}: {}",
                assets_dir, e
            )
        });
    }

    // Set up a reusable HTTP client with a custom User-Agent to avoid GitHub API blocks
    let client = reqwest::blocking::Client::builder()
        .user_agent("ironvault-admin-builder/0.1.0")
        .build()
        .expect("Failed to initialize HTTP client");

    // Verify presence or handle background download execution loop
    for (icon_name, filename) in required_icons {
        let dest_path = assets_dir.join(filename);

        if !dest_path.exists() {
            println!(
                "cargo:warning=[LUCIDE PIPELINE] Downloading missing vector asset: {}",
                filename
            );

            let target_url = format!(
                "https://raw.githubusercontent.com/lucide-icons/lucide/main/icons/{}.svg",
                icon_name
            );

            // Fetch with proper error handling for offline/network issues
            match client.get(&target_url).send() {
                Ok(response) => {
                    if response.status().is_success() {
                        let svg_content = response.text().unwrap_or_else(|e| {
                            panic!(
                                "[FATAL] Failed to read response body for {}: {}",
                                filename, e
                            )
                        });

                        let mut file = File::create(&dest_path).unwrap_or_else(|e| {
                            panic!("[FATAL] Failed to create local file {:?}: {}", dest_path, e)
                        });

                        file.write_all(svg_content.as_bytes()).unwrap_or_else(|e| {
                            panic!(
                                "[FATAL] Failed to write SVG content to {:?}: {}",
                                dest_path, e
                            )
                        });
                    } else {
                        panic!(
                            "[FATAL SYNC REJECTION] Icon download failure from GitHub (Status {}): {}\nURL tried: {}",
                            response.status(),
                            icon_name,
                            target_url
                        );
                    }
                }
                Err(err) => {
                    panic!(
                        "[FATAL NETWORK ERROR] Could not connect to GitHub to download {}.\nAre you offline? Error details: {}",
                        filename, err
                    );
                }
            }
        }
    }

    // Build absolute base include paths to make views globally discoverable
    let ui_dir = base_path.join("ui");
    let config = slint_build::CompilerConfiguration::new().with_include_paths(vec![ui_dir]);

    let main_slint_path = base_path.join("ui/main.slint");

    slint_build::compile_with_config(
        main_slint_path
            .to_str()
            .expect("Valid UTF-8 path for main.slint"),
        config,
    )
    .unwrap_or_else(|e| panic!("[FATAL] Slint compilation failed: {}", e));
}
