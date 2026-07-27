//! Edge Node Simulation Client
//! Connects to the IronVault Command Center over mutual TLS and sends a
//! test command.

use ironvault_core::network::{
    build_node_connector, receive_secure_payload, send_secure_payload, NodeCommand, NodeResponse,
};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;

#[tokio::main]
async fn main() -> Result<(), String> {
    println!("[NODE BOOT] Initializing Edge Node uplink sequence...");

    // Paths would normally come from this node's own .env/config, not be
    // hardcoded — left explicit here since this is a demo/test client.
    let connector = build_node_connector(
        "certs/generated/node-01.crt",
        "certs/generated/node-01.key",
        "certs/generated/ca.crt",
    )?;

    println!("[NODE] Attempting TCP + TLS Handshake with Command Center on 127.0.0.1:9443...");
    let tcp_stream = TcpStream::connect("127.0.0.1:9443")
        .await
        .map_err(|e| format!("Failed to connect to Command Center: {}", e))?;

    let server_name = ServerName::try_from("ironvault-command-center")
        .map_err(|e| format!("Invalid server name: {:?}", e))?;

    let mut tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| format!("TLS handshake failed: {}", e))?;

    println!("[NODE] mTLS handshake successful. Both sides authenticated.");

    let command = NodeCommand::TriggerLockdown("CRITICAL_THREAT_DETECTED".to_string());
    println!("[NODE] Sending command: {:?}", command);

    send_secure_payload(&mut tls_stream, &command).await?;
    println!("[NODE] Encrypted, authenticated payload transmitted.");

    println!("[NODE] Awaiting response...");
    match receive_secure_payload::<NodeResponse, _>(&mut tls_stream).await {
        Ok(response) => {
            println!("\n========================================");
            println!("[SUCCESS] Validated Response from Command Center:");
            println!("{:?}", response);
            println!("========================================\n");
        }
        Err(e) => {
            println!(
                "[SECURITY FAULT] Failed to verify Command Center response: {}",
                e
            );
        }
    }

    Ok(())
}
