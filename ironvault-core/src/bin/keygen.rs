// =========================================================================
// IronVault Standalone Cryptographic Key Generator (keygen.rs)
// Run this utility to produce unique public/private keys for administrators.
// =========================================================================

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;

fn main() {
    println!("===========================================================");
    println!("       IRONVAULT SECURE KEYPAIR GENERATOR (Ed25519)       ");
    println!("===========================================================");
    
    let mut csprng = OsRng;

    // 1. Generate Operator Keypair
    let op_signing_key = SigningKey::generate(&mut csprng);
    let op_verifying_key = VerifyingKey::from(&op_signing_key);

    // 2. Generate Supervisor Keypair
    let sv_signing_key = SigningKey::generate(&mut csprng);
    let sv_verifying_key = VerifyingKey::from(&sv_signing_key);

    println!("\n🔑 [1] OPERATOR KEYPAIR DETAILS:");
    println!("-----------------------------------------------------------");
    println!("PRIVATE KEY (Hex - Keep Secret! Paste into UI to Authorize):");
    println!("{}", to_hex(&op_signing_key.to_bytes()));
    println!("\nPUBLIC KEY (Hex - Share/Register in Database Profile):");
    println!("{}", to_hex(&op_verifying_key.to_bytes()));
    
    println!("\n🔑 [2] SUPERVISOR KEYPAIR DETAILS:");
    println!("-----------------------------------------------------------");
    println!("PRIVATE KEY (Hex - Keep Secret! Paste into UI to Authorize):");
    println!("{}", to_hex(&sv_signing_key.to_bytes()));
    println!("\nPUBLIC KEY (Hex - Share/Register in Database Profile):");
    println!("{}", to_hex(&sv_verifying_key.to_bytes()));
    println!("===========================================================");
}

/// Helper to format raw bytes into a hex string for easy terminal copying
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
