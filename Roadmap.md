IronVault-Admin: Enterprise Completion Roadmap

This document serves as your step-by-step master plan to transition the IronVault-Admin suite from its current cryptographic mockup state into a secure, production-hardened, multi-schema database management system.

🗺️ The 5-Stage Completion Roadmap

+------------------------------------+
|  STAGE 1: Network & DB Drivers     |  <-- Establish real connections, configure Oracle
+------------------------------------+      Client, and set up Postgres TLS pinning.
                  |
                  v
+------------------------------------+
|  STAGE 2: Multi-Schema SQL Engine  |  <-- Build dynamic schema switching and write
+------------------------------------+      parameterized CRUD (Insert, Update, Delete).
                  |
                  v
+------------------------------------+
|  STAGE 3: User Auth & RBAC         |  <-- Implement user creation, login sessions,
+------------------------------------+      and password hashing via Argon2.
                  |
                  v
+------------------------------------+
|  STAGE 4: Dual-Authorization Hooks |  <-- Connect Ed25519 keys to lock dangerous
+------------------------------------+      operations behind supervisor signatures.
                  |
                  v
+------------------------------------+
|  STAGE 5: Live UI Telemetry        |  <-- Build interactive log viewing grids and
+------------------------------------+      database performance health charts in QML.


Stage 1: Native Database Driver Configuration

To connect to your physical databases, you must replace the mock network clients with active, connection-pooled drivers.

1. PostgreSQL (with Certificate Pinning)

Update your postgres client configuration inside ironvault-core/src/database/postgres.rs to demand encrypted channels (ssl=on) using a local self-signed certificate authority:

Add the native-tls crate to your core dependencies.

Compile your local server's public key fingerprint into the binary.

Enforce certificate verification upon every connection handshake.

2. Oracle 11g / 12c / 19c (Instant Client)

Oracle database connections depend on the C-based Oracle Instant Client libraries.

Download the basic instant client zip from Oracle's developer portal.

Configure your operating system environment variables (LD_LIBRARY_PATH on Linux or PATH on Windows) to point directly to these compiled dynamic link libraries (oci.dll or libclntsh.so).

Stage 2: Dynamic Multi-Schema CRUD Engine

A single database cluster can hold dozens of schemas. Your application needs the ability to perform operations across different schemas dynamically while preventing SQL injection.

1. Schema Switching Strategies

Do not write hardcoded SQL strings matching different database schemas. Instead, execute session-level environment switches immediately after checking out a database connection:

For Oracle:

ALTER SESSION SET CURRENT_SCHEMA = target_schema_name;


For PostgreSQL:

SET search_path TO target_schema_name, public;


2. Parameterized CRUD Blueprint

Never concatenate SQL strings like "SELECT * FROM users WHERE id = " + user_input. Attackers can input malicious statements to wipe tables (SQL Injection). Always pass user-supplied variables using parameterized placeholders.

// Production-grade PostgreSQL parameterized update template
pub async fn safe_update_user_status(
    client: &tokio_postgres::Client,
    schema: &str,
    user_id: i32,
    new_status: &str
) -> Result<(), tokio_postgres::Error> {
    // 1. Force the target schema context safely
    let schema_query = format!("SET search_path TO {}, public", sanitize_identifier(schema));
    client.batch_execute(&schema_query).await?;

    // 2. Execute SQL with parameter bindings ($1, $2)
    client.execute(
        "UPDATE user_records SET status = $1 WHERE id = $2",
        &[&new_status, &user_id]
    ).await?;

    Ok(())
}


Stage 3: User Authentication & Role-Based Access Control (RBAC)

To control which users can view schemas, insert records, or request legacy exports, you must implement local user accounts locked with secure cryptographic credentials.

1. Security Baseline: Argon2id Password Hashing

Never store plain-text passwords in your database. When creating users, run their passwords through the Argon2id hashing algorithm.

Registration:
[Plain Password] ---> [Argon2id Hashing Function] ---> [Secure Hash String] ---> Store in DB

Login Validation:
[Input Password] + [Stored Hash] ---> [Argon2id Verify] ---> Success / Failure


2. Role Permissions Matrix

Map specific administrative boundaries to your users to restrict access before any database instructions are executed:

Permission Tier

Allowed Operations

Security Constraints

Auditor

Read-Only Schema View, Export Audit Log.

Denied all modification queries.

Operator

Insert Records, Update Records, Initiate Data Pump.

High-impact items write to PENDING_LEDGER for approval.

Supervisor

Approve Pending Ledger Items, Delete Records, Set Keys.

Demands physical Ed25519 key signing.

Stage 4: Dual-Authorization Enforcement Pipeline

Your application features a highly secure dual-authorization overlay. In production, this overlay must act as a physical block protecting database executions.

                  [Operator initiates "Truncate Table" action]
                                       |
                                       v
                     [Write to PENDING_TRANSACTIONS table]
                                       |
                                       v
                 [Supervisor logs in with cryptographic private key]
                                       |
                                       v
               [Approve action -> Generate dual-signature payload]
                                       |
                                       v
[Backend Middleware validates signatures -> Executes SQL -> Logs to Audit Trail]


Stage 5: Front-End UI Polish & Interactive Logging

Your modern Slint-based front-end interface should be enhanced to display the following live administrative views:

Interactive Logs Table: Build a dynamic scrolling data grid displaying the contents of ironvault_audit.log inside your UI.

Schema Table Explorer: Build a table grid where users can select schemas from a dropdown menu and double-click individual cells to edit, delete, or insert rows dynamically.