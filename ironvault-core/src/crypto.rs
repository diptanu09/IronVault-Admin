//! Cryptographic operations for payload encryption and decryption
//!
//! Uses AES-256-GCM for authenticated encryption

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Encryptor for securing payloads
pub struct Encryptor {
    key: Key<Aes256Gcm>,
}

/// Decryptor for recovering encrypted payloads
pub struct Decryptor {
    key: Key<Aes256Gcm>,
}

/// Encrypted payload wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub aad: Vec<u8>,
}

impl Encryptor {
    /// Create a new encryptor with a 32-byte key
    pub fn new(key_bytes: &[u8; 32]) -> Self {
        Encryptor {
            key: Key::<Aes256Gcm>::from(*key_bytes),
        }
    }

    /// Encrypt plaintext with optional additional authenticated data (AAD)
    pub fn encrypt(&self, plaintext: &[u8], aad: Option<&[u8]>) -> Result<EncryptedPayload, CryptoError> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let cipher = Aes256Gcm::new(&self.key);
        let payload = Payload {
            msg: plaintext,
            aad: aad.unwrap_or(b""),
        };

        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok(EncryptedPayload {
            nonce: nonce_bytes.to_vec(),
            ciphertext,
            aad: aad.unwrap_or(&[]).to_vec(),
        })
    }
}

impl Decryptor {
    /// Create a new decryptor with a 32-byte key
    pub fn new(key_bytes: &[u8; 32]) -> Self {
        Decryptor {
            key: Key::<Aes256Gcm>::from(*key_bytes),
        }
    }

    /// Decrypt an encrypted payload
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
}

/// Cryptographic errors
#[derive(Debug)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidKeySize,
}
