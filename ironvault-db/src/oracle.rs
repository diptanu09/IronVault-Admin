//! Oracle database adapter
//!
//! Executes real-time operational tasks directly on the Oracle 11g database.

pub struct OracleConnection {
    #[allow(dead_code)]
    connection_string: String,
    pool: oracle::pool::Pool,
}

impl OracleConnection {
    /// Create new Oracle connection pool infrastructure
    pub fn new(connection_string: &str) -> Result<Self, String> {
        let user = "gpffp"; 
        let pass = "gpffp"; 
        
        let tns_descriptor = "(DESCRIPTION=\
                                (ADDRESS=(PROTOCOL=TCP)(HOST=192.168.100.247)(PORT=1521))\
                                (CONNECT_DATA=(SID=db11g))\
                             )";

        let pool = oracle::pool::PoolBuilder::new(user, pass, tns_descriptor)
            .build()
            .map_err(|e| format!("Oracle connection pool allocation error: {}", e))?;
        
        Ok(OracleConnection {
            connection_string: connection_string.to_string(),
            pool,
        })
    }

    /// Task 1: Delete Full Case 
    pub async fn delete_full_case(&self, regd_no: &str, series_id: &str, account_no: &str) -> Result<(), String> {
        let pool = self.pool.clone();
        let r_no = regd_no.to_string();
        let s_id = series_id.to_string();
        let a_no = account_no.to_string();

        tokio::task::spawn_blocking(move || {
            let conn = pool.get().map_err(|e| format!("Oracle thread connection fault: {}", e))?;
            
            // Execute statements sequentially. Bound variables prevent SQL injection.
            conn.execute("DELETE FROM FP_INWARD_DIARY WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_APPLICATION WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_MAIN WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_SUBSCRIPTION_DETAILS WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_MISSING_CREDIT WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_ACCOUNT_CALCULATION WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            
            // Note: Oracle treats '' as NULL. We explicitly use NULL for standard compliance.
            conn.execute("UPDATE VLCS.GP_ACCOUNTS SET ACCOUNT_CLOSED_TAG = NULL WHERE SERIES_ID = :1 AND ACCOUNT_NO = :2", &[&s_id, &a_no])
                .map_err(|e| e.to_string())?;
            
            // Commit the transaction to the database
            conn.commit().map_err(|e| format!("Transaction commit failed: {}", e))?;
            Ok(())
        })
        .await
        .unwrap()
    }

    /// Task 2: Delete From Application
    pub async fn delete_from_application(&self, regd_no: &str) -> Result<(), String> {
        let pool = self.pool.clone();
        let r_no = regd_no.to_string();

        tokio::task::spawn_blocking(move || {
            let conn = pool.get().map_err(|e| format!("Oracle thread connection fault: {}", e))?;
            
            conn.execute("DELETE FROM FP_APPLICATION WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_MAIN WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_SUBSCRIPTION_DETAILS WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_MISSING_CREDIT WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_ACCOUNT_CALCULATION WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            
            conn.commit().map_err(|e| format!("Transaction commit failed: {}", e))?;
            Ok(())
        })
        .await
        .unwrap()
    }

    /// Task 3: Delete From Pre-Calculation
    pub async fn delete_from_pre_calculation(&self, regd_no: &str) -> Result<(), String> {
        let pool = self.pool.clone();
        let r_no = regd_no.to_string();

        tokio::task::spawn_blocking(move || {
            let conn = pool.get().map_err(|e| format!("Oracle thread connection fault: {}", e))?;
            
            conn.execute("DELETE FROM FP_MAIN WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_SUBSCRIPTION_DETAILS WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_MISSING_CREDIT WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_ACCOUNT_CALCULATION WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("UPDATE FP_APPLICATION SET CALCULATION_DATE = NULL WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            
            conn.commit().map_err(|e| format!("Transaction commit failed: {}", e))?;
            Ok(())
        })
        .await
        .unwrap()
    }

    /// Validate Oracle 11g/12c compatibility matrix
    pub async fn validate_version(&self) -> Result<String, String> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool.get().map_err(|e| format!("Handshake target context missing: {}", e))?;
            let version_str = conn.server_version().map_err(|e| format!("Handshake matrix readout failed: {}", e))?;
            Ok(format!("Oracle Server Sequence Engine: {:?}", version_str))
        })
        .await
        .unwrap()
    }

    /// Execution verification pass
    pub async fn health_check(&self) -> Result<(), String> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool.get().map_err(|e| format!("Handshake visibility fault: {}", e))?;
            let row = conn.query_row("SELECT 1 FROM DUAL", &[]).map_err(|e| format!("DUAL loop query failure: {}", e))?;
            let _check_val: i32 = row.get(0).map_err(|e| format!("Column unpacking failure: {}", e))?;
            Ok(())
        })
        .await
        .unwrap()
    }
}