//! Shared context passed to every handler module: DB client, Oracle client,
//! audit logger, and the HWID computed at boot. Centralizing this avoids
//! each handler module needing to know how these are constructed.

use ironvault_core::audit::AuditLogger;
use ironvault_core::auth::LoginRateLimiter;
use ironvault_db::{DbClient, OracleConnection};
use std::sync::Arc;

pub struct AppContext {
    pub db: Arc<DbClient>,
    pub oracle: Arc<OracleConnection>,
    pub audit: Arc<AuditLogger>,
    pub hwid: String,
    pub rate_limiter: LoginRateLimiter, // new
}

/// Single entry point for recording an audit event. Writes to Postgres first
/// (the authoritative store); if that write fails, falls back to the
/// file-based AuditLogger so the event isn't lost during a DB outage.
pub async fn record_audit(
    ctx: &AppContext,
    actor_username: &str,
    actor_role: ironvault_core::auth::Role,
    action: &str,
    level: &str,
) {
    if let Err(e) = ctx
        .db
        .log_audit_event(actor_username, action, level, "SYSTEM")
        .await
    {
        log::warn!(
            "[AUDIT] DB write failed ({}), falling back to file logger for: {}",
            e,
            action
        );
        let core_user = ironvault_core::auth::User {
            id: Default::default(),
            username: actor_username.to_string(),
            role: actor_role,
            last_login: "".to_string(),
        };
        ctx.audit.log_action(&core_user, action, level).ok();
    }
}

pub type SharedContext = Arc<AppContext>;
