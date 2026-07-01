// =========================================================================
// IronVault Data Models (models.rs)
// Structures the database schema, security accounts, and active session roles.
// =========================================================================

use serde::{Serialize, Deserialize};

/// Security clearance roles matching authorization controls
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthorizationRole {
    SuperAdministrator,
    Operator,
    Auditor,
}

/// Dynamic record structure used for real-time table visualizations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableRecord {
    pub record_id: String,
    pub payload_data: String,
    pub owner_schema: String,
    pub active_status: String,
}

/// Registered user security credentials saved to the authentication pool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminUser {
    pub username: String,
    pub password_hash: String,
    pub assigned_role: String,
}

/// Structure representing a dynamic log entry for database auditing tasks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAuditRecord {
    pub timestamp: String,
    pub requested_by: String,
    pub action_performed: String,
    pub target_schema: String,
    pub signature_hash: String,
    pub verified_by_authority: bool,
}