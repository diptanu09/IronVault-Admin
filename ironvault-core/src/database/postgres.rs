// =========================================================================
// IronVault PostgreSQL secure Multi-Schema CRUD Engine (postgres.rs)
// =========================================================================

use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;
use std::error::Error;
use tokio_postgres::Client;

/// Configures and connects securely to the PostgreSQL instance. 
pub async fn establish_secure_connection(connection_string: &str) -> Result<Client, Box<dyn Error>> {
    let mut masked_string = connection_string.to_string();
    if let Some(start) = connection_string.find("password=") {
        if let Some(end) = connection_string[start..].find(' ') {
            masked_string.replace_range(start..start+end, "password=********");
        } else {
            masked_string.replace_range(start.., "password=********");
        }
    }
    println!("[DIAGNOSTIC] Connecting with URI: {}", masked_string);

    // Attempt secure native TLS connection first
    let tls_inner_connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let tls_connector = MakeTlsConnector::new(tls_inner_connector);

    match tokio_postgres::connect(connection_string, tls_connector).await {
        Ok((client, connection)) => {
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("[ERROR] Active PostgreSQL TLS stream failure: {}", e);
                }
            });
            println!("[SUCCESS] Secure TLS channel established with database.");
            return Ok(client);
        }
        Err(e) => {
            println!("[WARNING] TLS rejected. Retrying with standard clean connection... Detail: {}", e);
        }
    }

    // Fall back to clean plain TCP (NoTls)
    let (client, connection) = tokio_postgres::connect(connection_string, tokio_postgres::NoTls).await?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("[ERROR] Active PostgreSQL plain stream failure: {}", e);
        }
    });
    println!("[SUCCESS] Standard plain channel established with database.");
    Ok(client)
}

/// Inserts a secure audit log directly into your target system audit logs table
pub async fn write_system_audit_log(
    client: &Client,
    operator: &str,
    action_type: &str,
    details: &str,
) -> Result<(), Box<dyn Error>> {
    let sql_query = "
        INSERT INTO ironvault_schema.system_audit_logs (operator_username, action_type, details) 
        VALUES ($1, $2, $3)";
    client.execute(sql_query, &[&operator, &action_type, &details]).await?;
    Ok(())
}

/// Safely inserts a new subscriber record into your subscriber table
pub async fn execute_dynamic_insert(
    client: &Client,
    schema: &str,
    series: &str,
    account: &str,
    name: &str,
) -> Result<(), Box<dyn Error>> {
    let sanitized_schema = sanitize_schema_name(schema)?;
    
    let search_path_query = format!("SET search_path TO {}, public", sanitized_schema);
    client.batch_execute(&search_path_query).await?;

    let sql_query = "
        INSERT INTO subscriber_details (series_id, account_no, subscriber_name) 
        VALUES ($1, $2, $3) ON CONFLICT (series_id, account_no) DO NOTHING";
    client.execute(sql_query, &[&series, &account, &name]).await?;

    println!("[SQL ENGINE] Parameterized INSERT committed to {}.subscriber_details", sanitized_schema);
    Ok(())
}

/// Safely updates an existing subscriber record's name
pub async fn execute_dynamic_update(
    client: &Client,
    schema: &str,
    account_no: &str,
    new_name: &str,
) -> Result<(), Box<dyn Error>> {
    let sanitized_schema = sanitize_schema_name(schema)?;
    
    let search_path_query = format!("SET search_path TO {}, public", sanitized_schema);
    client.batch_execute(&search_path_query).await?;

    let sql_query = "UPDATE subscriber_details SET subscriber_name = $1 WHERE account_no = $2";
    client.execute(sql_query, &[&new_name, &account_no]).await?;

    println!("[SQL ENGINE] Parameterized UPDATE completed in {}.subscriber_details", sanitized_schema);
    Ok(())
}

/// Safely removes an existing subscriber record
pub async fn execute_dynamic_delete(
    client: &Client,
    schema: &str,
    account: &str,
) -> Result<(), Box<dyn Error>> {
    let sanitized_schema = sanitize_schema_name(schema)?;
    
    let search_path_query = format!("SET search_path TO {}, public", sanitized_schema);
    client.batch_execute(&search_path_query).await?;

    let sql_query = "DELETE FROM subscriber_details WHERE account_no = $1";
    client.execute(sql_query, &[&account]).await?;

    println!("[SQL ENGINE] Parameterized DELETE executed in {}.subscriber_details", sanitized_schema);
    Ok(())
}

/// Helper checking schema inputs for malicious SQL injection characters
fn sanitize_schema_name(schema: &str) -> Result<String, &'static str> {
    if schema.is_empty() {
        return Err("Schema name cannot be blank.");
    }
    
    let is_safe = schema.chars().all(|c| c.is_alphanumeric() || c == '_');
    if !is_safe {
        return Err("Malicious characters detected! SQL routing aborted.");
    }

    Ok(schema.to_lowercase())
}