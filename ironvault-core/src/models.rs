// =========================================================================
// IronVault Data Models (models.rs)
// Structures the relational database properties, logging events, and security roles.
// =========================================================================


use serde::{Serialize, Deserialize};

/// Security clearance tiers for application users
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthorizationRole {
    SuperAdministrator,
    Operator,
    Auditor,
}

/// Structure representing a log entries for auditing tasks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAuditRecord {
    pub timestamp: String,
    pub requested_by: String,
    pub action_performed: String,
    pub target_schema: String,
    pub signature_hash: String,
    pub verified_by_authority: bool,
}


/// Structure holding network metrics for the Oracle/PostgreSQL nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationalDatabaseNode {
    pub node_id: String,
    pub instance_name: String,
    pub connection_string: String,
    pub connection_protocol: String,
    pub encryption_enabled: bool,
}