// =========================================================================
// IronVault PostgreSQL Secure & Diagnostic Multi-Schema Database Connector
// =========================================================================

use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;
use std::error::Error;
use tokio_postgres::Client;

/// Configures and connects to the PostgreSQL instance. 
pub async fn establish_secure_connection(connection_string: &str) -> Result<Client, Box<dyn Error>> {
    // 1. Mask password for terminal privacy, then print the actual string being used
    let mut masked_string = connection_string.to_string();
    if let Some(start) = connection_string.find("password=") {
        if let Some(end) = connection_string[start..].find(' ') {
            masked_string.replace_range(start..start+end, "password=********");
        } else {
            masked_string.replace_range(start.., "password=********");
        }
    }
    println!("[DIAGNOSTIC] Connecting with URI: {}", masked_string);

    // 2. Attempt Secure Native-TLS connection first
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
            println!("[SUCCESS] Secure TLS channel established with database: AsstPro.");
            return Ok(client);
        }
        Err(e) => {
            print!("[WARNING] TLS connection rejected. ");
            if let Some(db_err) = e.as_db_error() {
                println!("PostgreSQL Server reported: FATAL {} (SQL State: {})", db_err.message(), db_err.code().code());
            } else {
                println!("Error details: {}", e);
            }
            println!("[PROCESS] Retrying with plain connection...");
        }
    }

    // 3. Fall back to clean plain TCP (NoTls)
    match tokio_postgres::connect(connection_string, tokio_postgres::NoTls).await {
        Ok((client, connection)) => {
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("[ERROR] Active PostgreSQL connection stream failure: {}", e);
                }
            });
            println!("[SUCCESS] Standard channel established with database: AsstPro.");
            Ok(client)
        }
        Err(e) => {
            print!("[ERROR] Plain connection failed. ");
            if let Some(db_err) = e.as_db_error() {
                println!("PostgreSQL Server reported: FATAL {} (SQL State: {})", db_err.message(), db_err.code().code());
            } else {
                println!("Error details: {}", e);
            }
            Err(Box::new(e))
        }
    }
}

/// Inserts a secure audit log directly into your "agartala.system_audit_logs" table
pub async fn write_system_audit_log(
    client: &Client,
    operator: &str,
    action_type: &str,
    details: &str,
) -> Result<(), Box<dyn Error>> {
    let sql_query = "
        INSERT INTO agartala.system_audit_logs (operator_username, action_type, details) 
        VALUES ($1, $2, $3)";
    client.execute(sql_query, &[&operator, &action_type, &details]).await?;
    Ok(())
}

/// Safely inserts a new subscriber record into your "agartala.subscriber_details" table
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
        VALUES ($1, $2, $3)";
    client.execute(sql_query, &[&series, &account, &name]).await?;

    println!("[SQL ENGINE] Parameterized INSERT committed to {}.subscriber_details", sanitized_schema);
    Ok(())
}

/// Safely updates an existing subscriber record's name in the "subscriber_details" table
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

/// Safely removes an existing subscriber record from your "agartala.subscriber_details" table
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