//! ironvault-core crate root
//!
//! Re-export commonly-used components from submodules.

pub mod audit;
pub mod auth;
pub mod crypto;
pub mod licensing;
pub mod security;

// Re-export commonly used types for downstream crates
pub use security::SecurityValidator;
pub use licensing::LicenseManager;
pub use auth::{AuthManager, User, Role};
pub use audit::AuditLogger;
pub use crypto::{Encryptor, Decryptor, EncryptedPayload, CryptoError};
