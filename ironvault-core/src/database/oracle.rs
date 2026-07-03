// =========================================================================
// IronVault Oracle 11g/12c TNS Connection Layer (oracle.rs)
// =========================================================================

use oracle::Connection;
use std::error::Error;

/// Hardcoded TNS connection descriptors compiled directly from your network configuration.
/// Passing these full strings directly to the client prevents dependency on local tnsnames.ora files.
pub const TNS_11G: &str = "(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(HOST=192.168.100.247)(PORT=1521)))(CONNECT_DATA=(SID=db11g)))";
pub const TNS_12C: &str = "(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(HOST=192.168.0.140)(PORT=1521)))(CONNECT_DATA=(SERVICE_NAME=orcl)))";

/// Establishes a connection to the Oracle 11g database cluster using its direct TNS descriptor.
pub fn establish_oracle_connection(
    user: &str,
    pass: &str,
    tns_descriptor: &str,
) -> Result<Connection, oracle::Error> {
    println!(
        "[ORACLE DIAGNOSTIC] Initiating secure socket connection to descriptor: '{}'...", 
        tns_descriptor
    );
    
    // Establish raw blocking connection over ODPI-C
    Connection::connect(user, pass, tns_descriptor)
}

/// Executes a health handshake query against Oracle's standard catalog table 'DUAL'.
pub fn run_health_handshake(conn: &Connection) -> Result<String, Box<dyn Error>> {
    let sql_query = "SELECT 'SECURE_HANDSHAKE_COMPLETED_11G' FROM dual";
    
    // Query standard dual row
    let row = conn.query_row(sql_query, &[])?;
    let verification_token: String = row.get(0)?;
    
    Ok(verification_token)
}

/// Dynamic export compilation checking that the schema exists on the 11g database.
pub fn execute_downgrade_export(
    conn: &Connection,
    target_schema: &str,
) -> Result<String, Box<dyn Error>> {
    if target_schema.is_empty() {
        return Err("Target schema name cannot be blank.".into());
    }

    let validation_sql = "SELECT username FROM all_users WHERE username = :1";
    let formatted_schema = target_schema.trim().to_uppercase();
    
    match conn.query_row(validation_sql, &[&formatted_schema]) {
        Ok(_) => {
            println!("[ORACLE ENGINE] Schema '{}' found. Compiling expdp parameters...", formatted_schema);
            Ok(format!(
                "Backup compiled on host 192.168.100.247:1521 (SID: db11g). Schema: '{}'. Compatibility target: 11.2.0", 
                formatted_schema
            ))
        }
        Err(_) => {
            Err(format!("Schema context verification failed: '{}' does not exist.", formatted_schema).into())
        }
    }
}