//! Cryptographic operations for payload encryption and decryption
//!
//! Uses AES-256-GCM for authenticated encryption and introduces Time-Bound Envelopes.
//! Password hashing uses bcrypt (adaptive cost, per-hash random salt) rather than
//! a bare SHA-256 digest, since password material must resist offline brute force.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use chrono::Utc;
use rand::rngs::OsRng; // HARDENED: hardware/OS entropy pool
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

/// Derives a strict 32-byte AES key from a standard string password and salt.
/// NOTE: this is for deriving a symmetric *encryption* key (e.g. network transport key),
/// NOT for hashing user login passwords — see `hash_password` / `verify_password` below.
pub fn derive_key(password: &str, salt: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt.as_bytes());
    let result = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Bcrypt work factor. 12 is a reasonable default in 2026; raise if login latency
/// budget allows it and you want more resistance to offline cracking.
const BCRYPT_COST: u32 = 12;

/// Hashes an operator's login password using bcrypt.
///
/// bcrypt generates and embeds its own cryptographically random salt internally,
/// so no external salt/username needs to be (or should be) supplied here — doing so
/// would just be redundant and, if done wrong (e.g. using the username as salt, as
/// the previous implementation did), would weaken rather than strengthen the scheme.
///
/// The returned string is a self-describing bcrypt hash (e.g. `$2b$12$...`) which
/// already encodes the cost factor and salt, so it can be stored directly in the
/// `password` column and later verified with `verify_password`.
pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    bcrypt::hash(password, BCRYPT_COST).map_err(|_| CryptoError::HashingFailed)
}

/// Verifies a plaintext password attempt against a stored bcrypt hash.
///
/// Returns `false` (rather than propagating an error) on any malformed-hash or
/// internal bcrypt error, since from the caller's perspective that should be
/// treated identically to "wrong password" — never leak *why* verification failed.
pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    bcrypt::verify(password, stored_hash).unwrap_or(false)
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
/// Hashes a one-time reset token. Uses SHA-256 rather than bcrypt because,
/// unlike a user-chosen password, this token is a short, single-use,
/// high-entropy value generated by our own CSPRNG (see the `dynamic_token`
/// generation in main.rs) — there's no dictionary/guessing surface worth
/// slowing down, so a fast deterministic hash is appropriate here and keeps
/// verification cheap. This is intentionally a different function from
/// `hash_password`/`verify_password`, which remain bcrypt-based for actual
/// user-chosen credentials.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
 

   hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn verify_token(token: &str, stored_hash: &str) -> bool {
    hash_token(token) == stored_hash
}

/// Expanded Cryptographic errors
#[derive(Debug)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidKeySize,
    SerializationFailed,
    PayloadExpired,
    HashingFailed, // <-- ADDED
}