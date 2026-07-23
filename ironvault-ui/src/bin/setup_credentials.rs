//! One-time setup utility: prompts for the DB password and stores it in
//! Windows Credential Manager, so it no longer needs to live in .env.
//! Run once per machine after deployment: `cargo run --bin setup_credentials`

fn main() {
    println!("IronVault Credential Setup");
    println!("Enter the database password to store in Windows Credential Manager:");

    let password = rpassword::prompt_password("Password: ").expect("Failed to read password input");

    match ironvault_core::credential_store::store_password(&password) {
        Ok(()) => println!(
            "Password stored successfully. You can now remove IRONVAULT_DB_PASSWORD from .env."
        ),
        Err(e) => eprintln!("Failed to store password: {}", e),
    }
}
