use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;
use std::error::Error;

/// Establishes a secure, real-time TLS connection loop with a target PostgreSQL instance.
/// 
/// # Arguments
/// * `connection_string` - Standard format: "host=127.0.0.1 user=postgres password=secret dbname=ironvault sslmode=require"
pub async fn establish_secure_connection(connection_string: &str) -> Result<(), Box<dyn Error>> {
    println!("[PROCESS] Initializing Native-TLS layer for PostgreSQL connection...");

    // 1. Build the system's native TLS pipeline wrapper
    let tls_inner_connector = TlsConnector::builder()
        // If using a self-signed corporate DB certificate, you would uncomment this line:
        // .add_root_certificate(native_tls::Certificate::from_pem(&std::fs::read("root_ca.pem")?)?)
        .build()?;

    // 2. Wrap it into the adapter format required by the tokio-postgres driver stack
    let tls_connector = MakeTlsConnector::new(tls_inner_connector);

    println!("[PROCESS] Opening TCP socket connection and executing TLS Handshake...");

    // 3. Establish the socket layer handshake
    let (client, connection) = tokio_postgres::connect(connection_string, tls_connector).await?;

    // 4. Spawn the background connection worker loop. 
    // This maintains the active network channel separately from our analytical queries.
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("[ERROR] Active PostgreSQL connection stream failure: {}", e);
        }
    });

    println!("[SUCCESS] Secure TLS channel established. Target database is fully responsive.");
    
    // Quick validation query to ensure the pool is healthy
    let rows = client.query("SELECT version();", &[]).await?;
    if let Some(row) = rows.first() {
        let db_version: String = row.get(0);
        println!("[DATABASE INFO] Connected to: {}", db_version);
    }

    Ok(())
}