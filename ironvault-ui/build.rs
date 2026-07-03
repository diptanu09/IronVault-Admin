// =========================================================================
// IronVault Slint UI Build Compiler Hook (build.rs)
// =========================================================================

fn main() {
    slint_build::compile("ui/main.slint").unwrap();
}