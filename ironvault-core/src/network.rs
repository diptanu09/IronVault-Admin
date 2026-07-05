//! Secure TCP networking layer for IronVault node communication
//! Wraps Tokio streams in AES-256-GCM time-bound envelopes.

use crate::crypto::{Decryptor, EncryptedPayload, Encryptor};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Standardized commands that the Command Center can send/receive
#[derive(Debug, Serialize, Deserialize)]
pub enum NodeCommand {
    Ping,
    ReportStatus,
    TriggerLockdown(String),
}

/// Standardized responses from Edge Nodes
#[derive(Debug, Serialize, Deserialize)]
pub enum NodeResponse {
    Acknowledged,
    StatusData(String),
    Error(String),
}

/// Packages a Rust struct into a time-bound envelope, encrypts it, and sends it over TCP
pub async fn send_secure_payload<T: Serialize>(
    stream: &mut TcpStream,
    encryptor: &Encryptor,
    data: &T,
) -> Result<(), String> {
    // 1. Seal the payload with a strict 60-second Time-To-Live (TTL)
    let payload = encryptor.seal_envelope(data, Some(60)).map_err(|e| format!("{:?}", e))?;

    // 2. Serialize the EncryptedPayload wrapper into bytes
    let serialized = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;

    // 3. Send a 4-byte length prefix, followed by the actual encrypted data
    let len = serialized.len() as u32;
    stream.write_all(&len.to_be_bytes()).await.map_err(|e| e.to_string())?;
    stream.write_all(&serialized).await.map_err(|e| e.to_string())?;

    Ok(())
}

/// Reads an encrypted stream from TCP, verifies the TTL, and decrypts it back into a Rust struct
pub async fn receive_secure_payload<T: DeserializeOwned>(
    stream: &mut TcpStream,
    decryptor: &Decryptor,
) -> Result<T, String> {
    // 1. Read the 4-byte length prefix
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Security: Prevent malicious massive allocation attacks
    if len > 10 * 1024 * 1024 {
        return Err("SECURITY FAULT: Incoming payload exceeds memory boundaries".to_string());
    }

    // 2. Read the exact number of incoming bytes
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.map_err(|e| e.to_string())?;

    // 3. Deserialize back into the EncryptedPayload wrapper
    let payload: EncryptedPayload = serde_json::from_slice(&buf).map_err(|e| e.to_string())?;

    // 4. Decrypt, verify the timestamp, and extract the original struct
    decryptor.open_envelope(&payload).map_err(|e| format!("{:?}", e))
}