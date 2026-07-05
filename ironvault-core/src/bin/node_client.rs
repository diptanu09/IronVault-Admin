//! Edge Node Simulation Client
//! Fires an encrypted payload to the IronVault Central Command server

use ironvault_core::crypto::{derive_key, Decryptor, Encryptor};
use ironvault_core::network::{receive_secure_payload, send_secure_payload, NodeCommand, NodeResponse};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), String> {
    println!("[NODE BOOT] Initializing Edge Node uplink sequence...");

    // 1. Derive the exact same 32-byte AES key used by the Command Center
    let network_secret = derive_key("IronVault_Master_Node_Key_2026", "Salt_Secure_Comm");
    let encryptor = Encryptor::new(&network_secret);
    let decryptor = Decryptor::new(&network_secret);

    // 2. Connect to the UI Server (ensure this matches the port you just updated)
    println!("[NODE] Attempting TCP Handshake with Command Center on 127.0.0.1:9443...");
    let mut stream = TcpStream::connect("127.0.0.1:9443")
        .await
        .map_err(|e| format!("Failed to connect to Command Center: {}", e))?;
        
    println!("[NODE] Handshake successful. Socket open.");

    // 3. Construct the secure command
    let command = NodeCommand::TriggerLockdown("CRITICAL_THREAT_DETECTED".to_string());
    println!("[NODE] Sealing envelope: {:?}", command);

    // 4. Encrypt and transmit with a strict 60-second TTL
    send_secure_payload(&mut stream, &encryptor, &command).await?;
    println!("[NODE] Encrypted payload transmitted over TCP.");

    // 5. Await the Command Center's encrypted response
    println!("[NODE] Awaiting secure verification response...");
    match receive_secure_payload::<NodeResponse>(&mut stream, &decryptor).await {
        Ok(response) => {
            println!("\n========================================");
            println!("[SUCCESS] Validated Response from Command Center:");
            println!("{:?}", response);
            println!("========================================\n");
        }
        Err(e) => {
            println!("[SECURITY FAULT] Failed to verify Command Center response: {}", e);
        }
    }

    Ok(())
}