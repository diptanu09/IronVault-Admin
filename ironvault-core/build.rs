// ironvault-core/build.rs
fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR env var is missing; are you running via Cargo?");
    let base_path = std::path::Path::new(&manifest_dir);

    let parent_workspace = base_path
        .parent()
        .expect("Failed to locate parent workspace directory");
    let absolute_lib_dir = parent_workspace.join("lib");

    println!(
        "cargo:rustc-link-search=native={}",
        absolute_lib_dir.display()
    );
}
