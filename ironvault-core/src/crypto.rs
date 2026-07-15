//! Cryptographic operations for payload encryption and decryption
//!
//! Uses AES-256-GCM for authenticated encryption and introduces Time-Bound Envelopes

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use chrono::Utc;
use rand::rngs::OsRng; // HARDENED: Switched to hardware/OS entropy pool
use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Encryptor for securing payloads
pub struct Encryptor {
    key: Key<Aes256Gcm>,
}

/// Decryptor for recovering encrypted payloads
pub struct Decryptor {
    key: Key<Aes256Gcm>,
}

/// Encrypted payload wrapper containing the necessary extraction vectors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub aad: Vec<u8>,
}

/// A time-bound metadata wrapper to prevent Replay Attacks
#[derive(Debug, Serialize, Deserialize)]
struct SecureEnvelope<T> {
    pub payload: T,
    pub timestamp: i64,
    pub expires_in_secs: Option<i64>,
}

/// Derives a strict 32-byte AES key from a standard string password and salt
pub fn derive_key(password: &str, salt: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt.as_bytes());
    let result = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Hashes an operator password with a username-based salt to prevent plaintext database leaks
pub fn hash_password(password: &str, username: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(username.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

impl Encryptor {
    /// Create a new encryptor with a 32-byte key
    pub fn new(key_bytes: &[u8; 32]) -> Self {
        Encryptor {
            key: Key::<Aes256Gcm>::from_slice(key_bytes).clone(),
        }
    }

    /// Base layer: Encrypt raw plaintext with optional additional authenticated data (AAD)
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<EncryptedPayload, CryptoError> {
        let mut nonce_bytes = [0u8; 12];

        // HARDENED: Use OsRng instead of thread_rng to extract cryptographically secure entropy
        // sourced directly from hardware random number generators (e.g., RDRAND instruction or OS kernel pools).
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new(&self.key);

        let payload = Payload {
            msg: plaintext,
            aad: aad.unwrap_or(b""),
        };

        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok(EncryptedPayload {
            nonce: nonce_bytes.to_vec(),
            ciphertext,
            aad: aad.unwrap_or(&[]).to_vec(),
        })
    }

    /// High-level layer: Wraps any Rust struct in a secure, time-stamped JSON envelope and encrypts it
    pub fn seal_envelope<T: Serialize>(
        &self,
        data: &T,
        expires_in_secs: Option<i64>,
    ) -> Result<EncryptedPayload, CryptoError> {
        let envelope = SecureEnvelope {
            payload: data,
            timestamp: Utc::now().timestamp(),
            expires_in_secs,
        };

        let serialized =
            serde_json::to_string(&envelope).map_err(|_| CryptoError::SerializationFailed)?;

        // We use the application namespace as baseline Authenticated Data
        self.encrypt(serialized.as_bytes(), Some(b"IRONVAULT_SECURE_PAYLOAD"))
    }
}

impl Decryptor {
    /// Create a new decryptor with a 32-byte key
    pub fn new(key_bytes: &[u8; 32]) -> Self {
        Decryptor {
            key: Key::<Aes256Gcm>::from_slice(key_bytes).clone(),
        }
    }

    /// Base layer: Decrypt an encrypted payload back into raw bytes
    pub fn decrypt(&self, payload: &EncryptedPayload) -> Result<Vec<u8>, CryptoError> {
        let nonce = Nonce::from_slice(&payload.nonce);
        let cipher = Aes256Gcm::new(&self.key);

        let decrypt_payload = Payload {
            msg: &payload.ciphertext,
            aad: &payload.aad,
        };

        cipher
            .decrypt(nonce, decrypt_payload)
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    /// High-level layer: Decrypts, verifies TTL timestamps, and deserializes back into a native Rust struct
    pub fn open_envelope<T: DeserializeOwned>(
        &self,
        payload: &EncryptedPayload,
    ) -> Result<T, CryptoError> {
        let decrypted_bytes = self.decrypt(payload)?;

        let envelope: SecureEnvelope<T> = serde_json::from_slice(&decrypted_bytes)
            .map_err(|_| CryptoError::SerializationFailed)?;

        // Verify Anti-Replay TTL
        if let Some(ttl) = envelope.expires_in_secs {
            let now = Utc::now().timestamp();
            if now > envelope.timestamp + ttl {
                return Err(CryptoError::PayloadExpired);
            }
        }

        Ok(envelope.payload)
    }
}

/// Expanded Cryptographic errors
#[derive(Debug)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidKeySize,
    SerializationFailed,
    PayloadExpired,
}
