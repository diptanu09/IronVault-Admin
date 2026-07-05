//! ironvault-core crate root
//! Re-export commonly-used components from submodules.

// Declare all active modules in the core folder
pub mod auth;
pub mod security;
pub mod licensing;
pub mod audit;
pub mod crypto;
pub mod network; // ADDED: The new secure TCP layer

// Export the specific structs requested by your architecture
pub use security::SecurityValidator;
pub use licensing::LicenseManager;
pub use auth::{AuthManager, User};

// Re-export audit and cryptographic engines cleanly to the workspace
pub use audit::AuditLogger;
pub use crypto::{Encryptor, Decryptor, EncryptedPayload, CryptoError};