//! Command Center: accepts mTLS connections from Edge Nodes and responds
//! to their commands. This is the server side that node_client.rs connects
//! to — if you already have an existing listener elsewhere in your
//! codebase, use this as the reference for how it should authenticate
//! connections, not as a mandatory replacement.

use ironvault_core::network::{
    build_command_center_acceptor, receive_secure_payload, send_secure_payload, NodeCommand,
    NodeResponse,
};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), String> {
    println!("[COMMAND CENTER] Booting mTLS listener...");

    let acceptor = build_command_center_acceptor(
        "certs/generated/command_center.crt",
        "certs/generated/command_center.key",
        "certs/generated/ca.crt",
    )?;

    let listener = TcpListener::bind("0.0.0.0:9443")
        .await
        .map_err(|e| format!("Failed to bind listener: {}", e))?;

    println!("[COMMAND CENTER] Listening on 0.0.0.0:9443 (mTLS required)");

    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                log::warn!("[COMMAND CENTER] Failed to accept connection: {}", e);
                continue;
            }
        };

        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            println!("[COMMAND CENTER] Incoming connection from {}", peer_addr);

            let mut tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    // A failed handshake here means the peer either didn't
                    // present a valid client certificate signed by our CA,
                    // or presented an expired/revoked one — this IS the
                    // authentication check; log it as a security-relevant
                    // rejection, not just a generic connection error.
                    log::warn!(
                        "[SECURITY] mTLS handshake rejected from {}: {}",
                        peer_addr,
                        e
                    );
                    return;
                }
            };

            println!(
                "[COMMAND CENTER] mTLS handshake succeeded with {} — peer certificate verified.",
                peer_addr
            );

            match receive_secure_payload::<NodeCommand, _>(&mut tls_stream).await {
                Ok(command) => {
                    println!(
                        "[COMMAND CENTER] Received command from {}: {:?}",
                        peer_addr, command
                    );
                    let response = match command {
                        NodeCommand::Ping => NodeResponse::Acknowledged,
                        NodeCommand::ReportStatus => {
                            NodeResponse::StatusData("Nominal".to_string())
                        }
                        NodeCommand::TriggerLockdown(reason) => {
                            println!("[COMMAND CENTER] LOCKDOWN TRIGGERED: {}", reason);
                            NodeResponse::Acknowledged
                        }
                    };
                    if let Err(e) = send_secure_payload(&mut tls_stream, &response).await {
                        log::warn!(
                            "[COMMAND CENTER] Failed to send response to {}: {}",
                            peer_addr,
                            e
                        );
                    }
                }
                Err(e) => {
                    log::warn!(
                        "[COMMAND CENTER] Failed to receive command from {}: {}",
                        peer_addr,
                        e
                    );
                }
            }
        });
    }
}
