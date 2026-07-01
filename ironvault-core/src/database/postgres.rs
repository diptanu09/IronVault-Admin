// =========================================================================
// IronVault PostgreSQL secure Multi-Schema CRUD Engine (postgres.rs)
// Executes fully parameterized CRUD commands dynamically across multiple schemas.
// =========================================================================

use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;
use std::error::Error;
use tokio_postgres::Client;

/// Configures and connects securely to the PostgreSQL instance
pub async fn establish_secure_connection(connection_string: &str) -> Result<Client, Box<dyn Error>> {
    println!("[PROCESS] Initializing Native-TLS layer for PostgreSQL connection...");

    let tls_inner_connector = TlsConnector::builder().build()?;
    let tls_connector = MakeTlsConnector::new(tls_inner_connector);

    println!("[PROCESS] Opening TCP socket connection and executing TLS Handshake...");
    let (client, connection) = tokio_postgres::connect(connection_string, tls_connector).await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("[ERROR] Active PostgreSQL connection stream failure: {}", e);
        }
    });

    println!("[SUCCESS] Secure TLS channel established. Target database is responsive.");
    Ok(client)
}

/// Executes dynamic schema switching securely using safe identifiers and parameterized structures.
pub async fn execute_dynamic_insert(
    client: &Client,
    schema: &str,
    record_id: &str,
    payload_data: &str,
    status: &str,
) -> Result<(), Box<dyn Error>> {
    let sanitized_schema = sanitize_schema_name(schema)?;
    
    let search_path_query = format!("SET search_path TO {}, public", sanitized_schema);
    client.batch_execute(&search_path_query).await?;

    let sql_query = "INSERT INTO data_records (id, payload, active_status) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING";
    client.execute(sql_query, &[&record_id, &payload_data, &status]).await?;

    println!("[SQL ENGINE] Parameterized INSERT successfully committed to schema: {}", sanitized_schema);
    Ok(())
}

/// Safely updates an existing record in the target schema using parameterized parameters
pub async fn execute_dynamic_update(
    client: &Client,
    schema: &str,
    record_id: &str,
    new_payload_data: &str,
) -> Result<(), Box<dyn Error>> {
    let sanitized_schema = sanitize_schema_name(schema)?;
    
    let search_path_query = format!("SET search_path TO {}, public", sanitized_schema);
    client.batch_execute(&search_path_query).await?;

    let sql_query = "UPDATE data_records SET payload = $1 WHERE id = $2";
    client.execute(sql_query, &[&new_payload_data, &record_id]).await?;

    println!("[SQL ENGINE] Parameterized UPDATE successfully committed to schema: {}", sanitized_schema);
    Ok(())
}

/// Safely removes a record from the target schema table
pub async fn execute_dynamic_delete(
    client: &Client,
    schema: &str,
    record_id: &str,
) -> Result<(), Box<dyn Error>> {
    let sanitized_schema = sanitize_schema_name(schema)?;
    
    let search_path_query = format!("SET search_path TO {}, public", sanitized_schema);
    client.batch_execute(&search_path_query).await?;

    let sql_query = "DELETE FROM data_records WHERE id = $1";
    client.execute(sql_query, &[&record_id]).await?;

    println!("[SQL ENGINE] Parameterized DELETE successfully committed from schema: {}", sanitized_schema);
    Ok(())
}

/// Internal helper ensuring schema strings only contain safe, alphanumeric characters
fn sanitize_schema_name(schema: &str) -> Result<String, &'static str> {
    if schema.is_empty() {
        return Err("Schema name cannot be blank.");
    }
    
    let is_safe = schema.chars().all(|c| c.is_alphanumeric() || c == '_');
    if !is_safe {
        return Err("Malicious SQL characters detected! Schema switching aborted.");
    }

    Ok(schema.to_lowercase())
}