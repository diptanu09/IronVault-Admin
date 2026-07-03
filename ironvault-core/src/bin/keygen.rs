// =========================================================================
// IronVault Standalone Cryptographic Key Generator (keygen.rs)
// Run this utility to produce unique public/private keys for administrators.
// =========================================================================

use ed25519_dalek::SigningKey;
use rand_core::OsRng;

fn main() {
    println!("====================================================");
    println!("      IRONVAULT CRYPTOGRAPHIC KEY GENERATOR");
    println!("====================================================\n");

    let mut csprng = OsRng;

    let op_signing_key = SigningKey::generate(&mut csprng);
    let op_verifying_key = op_signing_key.verifying_key();

    println!("▶ OPERATOR KEYS:");
    print!("  SECRET KEY: ");
    for byte in op_signing_key.to_bytes() { print!("{:02x}", byte); }
    println!();
    print!("  PUBLIC KEY: ");
    for byte in op_verifying_key.to_bytes() { print!("{:02x}", byte); }
    println!("\n");

    let sv_signing_key = SigningKey::generate(&mut csprng);
    let sv_verifying_key = sv_signing_key.verifying_key();

    println!("▶ SUPERVISOR KEYS:");
    print!("  SECRET KEY: ");
    for byte in sv_signing_key.to_bytes() { print!("{:02x}", byte); }
    println!();
    print!("  PUBLIC KEY: ");
    for byte in sv_verifying_key.to_bytes() { print!("{:02x}", byte); }
    println!("\n====================================================");
}