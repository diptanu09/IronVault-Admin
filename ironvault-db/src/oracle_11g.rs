pub fn run_11g_operation(schema: &str, operation: &str) -> Result<String, String> {
    println!("[ORACLE 11G] Executing '{}' on schema context: {}", operation, schema);
    
    // Check for valid active schemas
    let lower_schema = schema.to_lowercase();
    if lower_schema != "gpffp" && lower_schema != "agdak" && lower_schema != "vlcs" {
        return Err(format!("Schema context verification failed: '{}' does not exist in 11g target.", schema));
    }
    
    Ok(format!("SUCCESS: 11g Operation [{}] completed on {}", operation, schema))
}