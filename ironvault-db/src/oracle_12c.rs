pub fn run_12c_operation(schema: &str, operation: &str) -> Result<String, String> {
    println!("[ORACLE 12C] Executing '{}' on schema context: {}", operation, schema);
    
    let lower_schema = schema.to_lowercase();
    if lower_schema != "pendak" && lower_schema != "sai_agartala" && lower_schema != "penindex" {
        return Err(format!("Schema context verification failed: '{}' does not exist in 12c target.", schema));
    }
    
    Ok(format!("SUCCESS: 12c Operation [{}] completed on {}", operation, schema))
}