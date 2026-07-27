//! Secure TCP networking layer for IronVault node communication.
//!
//! Uses mutual TLS (mTLS) via rustls rather than a hand-rolled AES-GCM
//! envelope over a shared static key. This gives genuine peer
//! authentication (each side presents a certificate signed by the shared
//! internal CA, verified by the other side) and forward secrecy (TLS
//! session keys are ephemeral per-connection), neither of which a static
//! shared secret can provide — a compromised key under the old scheme
//! decrypted every past and future connection from every node; a
//! compromised individual node certificate under this scheme can be
//! revoked without affecting any other node.

use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::BufReader;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

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

const MAX_PAYLOAD_BYTES: usize = 10 * 1024 * 1024;

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let file = std::fs::File::open(path)
        .map_err(|e| format!("Failed to open cert file {}: {}", path, e))?;
    let mut reader = BufReader::new(file);
    certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse cert file {}: {}", path, e))
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let file = std::fs::File::open(path)
        .map_err(|e| format!("Failed to open key file {}: {}", path, e))?;
    let mut reader = BufReader::new(file);
    let mut keys = pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse key file {}: {}", path, e))?;
    keys.pop()
        .map(PrivateKeyDer::Pkcs8)
        .ok_or_else(|| format!("No private key found in {}", path))
}

fn load_root_store(ca_path: &str) -> Result<RootCertStore, String> {
    let mut store = RootCertStore::empty();
    for cert in load_certs(ca_path)? {
        store
            .add(cert)
            .map_err(|e| format!("Failed to add CA cert to trust store: {:?}", e))?;
    }
    Ok(store)
}

/// Builds the Command Center's TLS acceptor: presents its own server
/// certificate, and REQUIRES the connecting node to present a valid client
/// certificate signed by the shared CA. This is the mutual part of mTLS —
/// without it, any client could connect even without a valid node cert.
pub fn build_command_center_acceptor(
    server_cert_path: &str,
    server_key_path: &str,
    ca_cert_path: &str,
) -> Result<TlsAcceptor, String> {
    let certs = load_certs(server_cert_path)?;
    let key = load_private_key(server_key_path)?;
    let client_root_store = load_root_store(ca_cert_path)?;

    let client_verifier =
        tokio_rustls::rustls::server::WebPkiClientVerifier::builder(Arc::new(client_root_store))
            .build()
            .map_err(|e| format!("Failed to build client cert verifier: {:?}", e))?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)
        .map_err(|e| format!("Failed to build server TLS config: {:?}", e))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Builds an Edge Node's TLS connector: presents its own client certificate,
/// and verifies the Command Center's server certificate against the shared
/// CA before trusting the connection.
pub fn build_node_connector(
    node_cert_path: &str,
    node_key_path: &str,
    ca_cert_path: &str,
) -> Result<TlsConnector, String> {
    let certs = load_certs(node_cert_path)?;
    let key = load_private_key(node_key_path)?;
    let root_store = load_root_store(ca_cert_path)?;

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .map_err(|e| format!("Failed to build client TLS config: {:?}", e))?;

    Ok(TlsConnector::from(Arc::new(config)))
}

/// Sends a length-prefixed, JSON-serialized payload over an already-
/// established TLS stream. TLS itself provides confidentiality and
/// integrity here — no additional application-layer encryption envelope
/// is needed on top of it.
pub async fn send_secure_payload<T: Serialize, S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    data: &T,
) -> Result<(), String> {
    let serialized = serde_json::to_vec(data).map_err(|e| e.to_string())?;

    if serialized.len() > MAX_PAYLOAD_BYTES {
        return Err("SECURITY FAULT: Outgoing payload exceeds memory boundaries".to_string());
    }

    let len = serialized.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&serialized)
        .await
        .map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;

    Ok(())
}

/// Reads a length-prefixed, JSON-serialized payload from an already-
/// established TLS stream.
pub async fn receive_secure_payload<T: DeserializeOwned, S: AsyncReadExt + Unpin>(
    stream: &mut S,
) -> Result<T, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_PAYLOAD_BYTES {
        return Err("SECURITY FAULT: Incoming payload exceeds memory boundaries".to_string());
    }

    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| e.to_string())?;

    serde_json::from_slice(&buf).map_err(|e| e.to_string())
}
