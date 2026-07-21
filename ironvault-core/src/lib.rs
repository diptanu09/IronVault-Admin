//! ironvault-core crate root
//! Re-export commonly-used components from submodules.

// Declare all active modules in the core folder
pub mod audit;
pub mod auth;
pub mod crypto;
pub mod licensing;
pub mod network; // ADDED: The new secure TCP layer
pub mod sdk_themida;
pub mod sdk_vmp;
pub mod security;
// Export the specific structs requested by your architecture
pub use auth::{AuthManager, User};
pub use licensing::LicenseManager;
pub use security::SecurityValidator;

// Re-export audit and cryptographic engines cleanly to the workspace
pub use audit::AuditLogger;
pub use crypto::{CryptoError, Decryptor, EncryptedPayload, Encryptor};
