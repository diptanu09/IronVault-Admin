//! Oracle Multi-Pool Matrix Controller
//!
//! Manages separate connection pools for completely distinct schemas
//! and handles individual workloads per node without cross-contamination.

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OracleTarget {
    Gpffp,
    Vlcs,
    Agtall,
    Agdak,
    SaiAgartala,
    Pendak,
    Penindex,
}

// --- DATA RETRIEVAL BRIDGE STRUCTURES ---
#[derive(Debug, Clone)]
pub struct GpfCaseRecord {
    pub regd_no: String,
    pub acc_holder_name: String,
    pub series_id: String,
    pub account_no: String,
    pub closing_balance: f64,
    pub current_status: String,
}

#[derive(Debug, Clone)]
pub struct PensionDakEntry {
    pub app_num: String,
    pub letter_no: String,
    pub ppo_fppo: String,
    pub gpo: String,
    pub cpo: String,
    pub section: String,
    pub subject: String,
    pub copies_count: i32,
    pub recipients: Vec<DakRecipientDetail>,
}

#[derive(Debug, Clone)]
pub struct DakRecipientDetail {
    pub addressee: String,
    pub barcode: String,
    pub sent_by: String,
    pub service_book: String,
}

#[derive(Debug, Clone, Default)]
pub struct PensionAuthDetails {
    pub ppo_no: String,
    pub fppo_no: String,
    pub gpo_no: String,
    pub cpo_no: String,
}

// --- PRODUCTION COMPATIBLE RETRIEVAL LAYOUT ---
#[derive(Debug, Clone, Default)]
pub struct FullPensionDakRecord {
    pub app_num: String,
    pub letter_no: String,
    pub ppo_no: String,
    pub fppo_no: String,
    pub gpo_no: String,
    pub cpo_no: String,
    pub section: String,
    pub subject: String,
    pub addressee: String,
    pub barcode: String,
    pub sent_by: String,
    pub created_at: String,
}

pub struct OracleConnection {
    pool_gpffp: oracle::pool::Pool,
    pool_vlcs: oracle::pool::Pool,
    pool_agtall: oracle::pool::Pool,
    pool_agdak: oracle::pool::Pool,
    pool_sai_agartala: oracle::pool::Pool,
    pool_pendak: oracle::pool::Pool,
    pool_penindex: oracle::pool::Pool,
}

impl OracleConnection {
    /// Initialize all 7 discrete schema connection pools across both network clusters
    pub fn new() -> Result<Self, String> {
        let tns_100 = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=192.168.100.247)(PORT=1521))(CONNECT_DATA=(SID=db11g)))";
        
        let pool_gpffp = oracle::pool::PoolBuilder::new("gpffp", "gpffp", tns_100)
            .build().map_err(|e| format!("gpffp node link failure: {}", e))?;
        let pool_vlcs = oracle::pool::PoolBuilder::new("vlcs", "vlcs", tns_100)
            .build().map_err(|e| format!("vlcs node link failure: {}", e))?;
        let pool_agtall = oracle::pool::PoolBuilder::new("agtall", "agtall", tns_100)
            .build().map_err(|e| format!("agtall node link failure: {}", e))?;
        let pool_agdak = oracle::pool::PoolBuilder::new("agdak", "agdak", tns_100)
            .build().map_err(|e| format!("agdak node link failure: {}", e))?;

        let tns_0 = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=192.168.0.140)(PORT=1521))(CONNECT_DATA=(SID=orcl)))";
        
        let pool_sai_agartala = oracle::pool::PoolBuilder::new("sai_agartala", "sai_agartala", tns_0)
            .build().map_err(|e| format!("sai_agartala node link failure: {}", e))?;
        let pool_pendak = oracle::pool::PoolBuilder::new("pendak", "pendak", tns_0)
            .build().map_err(|e| format!("pendak node link failure: {}", e))?;
        let pool_penindex = oracle::pool::PoolBuilder::new("penindex", "penindex", tns_0)
            .build().map_err(|e| format!("penindex node link failure: {}", e))?;

        Ok(Self {
            pool_gpffp, pool_vlcs, pool_agtall, pool_agdak, pool_sai_agartala, pool_pendak, pool_penindex,
        })
    }

    fn get_connection(&self, target: OracleTarget) -> Result<oracle::Connection, String> {
        match target {
            OracleTarget::Gpffp => self.pool_gpffp.get().map_err(|e| e.to_string()),
            OracleTarget::Vlcs => self.pool_vlcs.get().map_err(|e| e.to_string()),
            OracleTarget::Agtall => self.pool_agtall.get().map_err(|e| e.to_string()),
            OracleTarget::Agdak => self.pool_agdak.get().map_err(|e| e.to_string()),
            OracleTarget::SaiAgartala => self.pool_sai_agartala.get().map_err(|e| e.to_string()),
            OracleTarget::Pendak => self.pool_pendak.get().map_err(|e| e.to_string()),
            OracleTarget::Penindex => self.pool_penindex.get().map_err(|e| e.to_string()),
        }
    }

    /// WORKLOAD: Pension DAK System - Single Pass Optimized Auto-fetch Mapping Module
    pub async fn pendak_fetch_auth_details(&self, appln_no: &str) -> Result<Option<PensionAuthDetails>, String> {
        let app_no = appln_no.trim().to_string();
        if app_no.is_empty() { return Ok(None); }
        let conn = self.get_connection(OracleTarget::Penindex)?;

        tokio::task::spawn_blocking(move || {
            let query = "
                SELECT a.APA_AUTH_TYPE, a.APA_AUTH_NO 
                FROM SAI_AGARTALA.T_APPLN_AUTHORITY a 
                INNER JOIN SAI_AGARTALA.T_APPLICATION_HDR b ON a.APA_APPLN_PK = b.APPLN_PK 
                WHERE b.APPLN_NO = :app_no 
                  AND a.APA_AUTH_TYPE IN ('760', '761', '762', '763')
            ";
            let mut stmt = conn.statement(query).build().map_err(|e| e.to_string())?;
            let rows = stmt.query_named(&[("app_no", &app_no.as_str())]).map_err(|e| e.to_string())?;

            let mut details = PensionAuthDetails::default();
            let mut found_any = false;
            for row_result in rows {
                let row = row_result.map_err(|e| e.to_string())?;
                let auth_type: String = row.get(0).map_err(|e| e.to_string())?;
                let auth_no: String = row.get(1).map_err(|e| e.to_string())?;
                found_any = true;
                match auth_type.trim() {
                    "760" => details.ppo_no = auth_no,
                    "761" => details.gpo_no = auth_no,
                    "762" => details.cpo_no = auth_no,
                    "763" => details.fppo_no = auth_no,
                    _ => {}
                }
            }
            if found_any { Ok(Some(details)) } else { Ok(None) }
        }).await.unwrap()
    }

    /// WORKLOAD: Pension DAK System - Insert Flat Copy Entries into Production Diary
    pub async fn pendak_insert_outward_case(&self, entry: PensionDakEntry) -> Result<(), String> {
        let conn = self.get_connection(OracleTarget::Pendak)?;
        tokio::task::spawn_blocking(move || {
            let query = "
                INSERT INTO PEN_DAK_OUTWARD_DAIRY (
                    APPLN_NO, LETTER_NO, PPO_FPPO, GPO, CPO, SECTION, SUBJECT, 
                    ADDRESSEE, BAR_CODE, SENT_BY, SERVICE_BOOK, OUTWARD_DATE, CREATE_DATE
                ) VALUES (:1, :2, :3, :4, :5, :6, :7, :8, :9, :10, :11, SYSDATE, SYSDATE)
            ";

            let app_numeric: i64 = entry.app_num.parse().unwrap_or(0);
            let ppo_numeric: i64 = entry.ppo_fppo.parse().unwrap_or(0);
            let gpo_numeric: i64 = entry.gpo.parse().unwrap_or(0);
            let cpo_numeric: i64 = entry.cpo.parse().unwrap_or(0);
            let section_numeric: i32 = entry.section.parse().unwrap_or(0);

            for recipient in entry.recipients.iter() {
                conn.execute(query, &[
                    &app_numeric,
                    &entry.letter_no,
                    &ppo_numeric,
                    &gpo_numeric,
                    &cpo_numeric,
                    &section_numeric,
                    &entry.subject,
                    &recipient.addressee,
                    &recipient.barcode,
                    &recipient.sent_by,
                    &recipient.service_book,
                ]).map_err(|e| format!("Insertion failed into PEN_DAK_OUTWARD_DAIRY: {}", e))?;
            }

            conn.commit().map_err(|e| format!("PENDAK Commit failure: {}", e))?;
            Ok(())
        }).await.unwrap()
    }

    /// WORKLOAD: Pension DAK System - Query and Retrieve Flat Archive Rows (FIXED)
    pub async fn pendak_select_outward_case_full(&self, appln_no: &str) -> Result<Option<FullPensionDakRecord>, String> {
        let app_no_numeric: i64 = appln_no.trim().parse().unwrap_or(0);
        if app_no_numeric == 0 { return Ok(None); }

        let conn = self.get_connection(OracleTarget::Pendak)?;
        tokio::task::spawn_blocking(move || {
            let query = "
                SELECT APPLN_NO, LETTER_NO, PPO_FPPO, GPO, CPO, SECTION, SUBJECT, 
                       ADDRESSEE, BAR_CODE, SENT_BY, TO_CHAR(OUTWARD_DATE, 'YYYY-MM-DD') 
                FROM PEN_DAK_OUTWARD_DAIRY 
                WHERE APPLN_NO = :1 AND ROWNUM <= 1
            ";
            let mut stmt = conn.statement(query).build().map_err(|e| e.to_string())?;
            let rows = stmt.query(&[&app_no_numeric]).map_err(|e| e.to_string())?;
            
            for row_res in rows {
                let row = row_res.map_err(|e| e.to_string())?;
                
                // FIXED TYPE ANNOTATION CASTS TO ELIMINATE UNKNOWN PROPERTY ERRS
                let app_num_val: i64 = row.get(0).unwrap_or(0);
                let letter_no_val: String = row.get(1).unwrap_or_default();
                let ppo_val: i64 = row.get(2).unwrap_or(0);
                let gpo_val: i64 = row.get(3).unwrap_or(0);
                let cpo_val: i64 = row.get(4).unwrap_or(0);
                let section_val: i32 = row.get(5).unwrap_or(0);
                let subject_val: String = row.get(6).unwrap_or_default();
                let addressee_val: String = row.get(7).unwrap_or_default();
                let barcode_val: String = row.get(8).unwrap_or_default();
                let sent_by_val: String = row.get(9).unwrap_or_default();
                let created_val: String = row.get(10).unwrap_or_default();

                return Ok(Some(FullPensionDakRecord {
                    app_num: app_num_val.to_string(),
                    letter_no: letter_no_val,
                    ppo_no: ppo_val.to_string(),
                    fppo_no: "See PPO Field".to_string(),
                    gpo_no: gpo_val.to_string(),
                    cpo_no: cpo_val.to_string(),
                    section: section_val.to_string(),
                    subject: subject_val,
                    addressee: addressee_val,
                    barcode: barcode_val,
                    sent_by: sent_by_val,
                    created_at: created_val,
                }));
            }
            Ok(None)
        }).await.unwrap()
    }

    /// WORKLOAD: Pension DAK System - Update target record inside production ledger
    pub async fn pendak_update_outward_case(&self, app_num: &str, section: &str, subject: &str) -> Result<(), String> {
        let app_no_numeric: i64 = app_num.trim().parse().unwrap_or(0);
        let section_numeric: i32 = section.trim().parse().unwrap_or(0);
        let sub = subject.to_string();

        let conn = self.get_connection(OracleTarget::Pendak)?;
        tokio::task::spawn_blocking(move || {
            let query = "UPDATE PEN_DAK_OUTWARD_DAIRY SET SECTION = :1, SUBJECT = :2 WHERE APPLN_NO = :3";
            conn.execute(query, &[&section_numeric, &sub, &app_no_numeric]).map_err(|e| e.to_string())?;
            conn.commit().map_err(|e| e.to_string())?;
            Ok(())
        }).await.unwrap()
    }

    /// WORKLOAD: GPFFP Task - Search and Discover Case Profiles from FP_APPLICATION
    pub async fn gpffp_find_case_profile(&self, regd_no: &str) -> Result<Option<GpfCaseRecord>, String> {
        let r_no = regd_no.trim().to_string();
        if r_no.is_empty() { return Ok(None); }
        let conn = self.get_connection(OracleTarget::Gpffp)?;
        tokio::task::spawn_blocking(move || {
            let query = "SELECT REGD_NO, ACC_HOLDER_NAME, SERIES_ID, ACCOUNT_NO, SANCTION_AMOUNT, STATUS FROM FP_APPLICATION WHERE REGD_NO = :regd AND ROWNUM <= 1";
            let mut stmt = conn.statement(query).build().map_err(|e| e.to_string())?;
            let rows = stmt.query_named(&[("regd", &r_no.as_str())]).map_err(|e| e.to_string())?;
            for row_result in rows {
                let row = row_result.map_err(|e| e.to_string())?;
                
                let regd_val: String = row.get(0).map_err(|e| e.to_string())?;
                let holder_val: String = row.get(1).map_err(|e| e.to_string())?;
                let series_val: String = row.get(2).map_err(|e| e.to_string())?;
                let account_val: String = row.get(3).map_err(|e| e.to_string())?;
                let balance_val: f64 = row.get(4).unwrap_or(0.0);
                let status_val: String = row.get(5).unwrap_or_else(|_| "UNKNOWN".to_string());

                return Ok(Some(GpfCaseRecord {
                    regd_no: regd_val,
                    acc_holder_name: holder_val,
                    series_id: series_val,
                    account_no: account_val,
                    closing_balance: balance_val,
                    current_status: status_val,
                }));
            }
            Ok(None)
        }).await.unwrap()
    }

    pub async fn gpffp_delete_full_case(&self, regd_no: &str, series_id: &str, account_no: &str) -> Result<(), String> {
        let (r_no, s_id, a_no) = (regd_no.to_string(), series_id.to_string(), account_no.to_string());
        let conn = self.get_connection(OracleTarget::Gpffp)?;
        tokio::task::spawn_blocking(move || {
            conn.execute("DELETE FROM FP_INWARD_DIARY WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_APPLICATION WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_MAIN WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_SUBSCRIPTION_DETAILS WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_MISSING_CREDIT WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_ACCOUNT_CALCULATION WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("UPDATE VLCS.GP_ACCOUNTS SET ACCOUNT_CLOSED_TAG = NULL WHERE SERIES_ID = :1 AND ACCOUNT_NO = :2", &[&s_id, &a_no]).map_err(|e| e.to_string())?;
            conn.commit().map_err(|e| format!("GPFFP Commit failure: {}", e))?;
            Ok(())
        }).await.unwrap()
    }

    pub async fn gpffp_delete_from_application(&self, regd_no: &str) -> Result<(), String> {
        let r_no = regd_no.to_string();
        let conn = self.get_connection(OracleTarget::Gpffp)?;
        tokio::task::spawn_blocking(move || {
            conn.execute("DELETE FROM FP_APPLICATION WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_MAIN WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_SUBSCRIPTION_DETAILS WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_MISSING_CREDIT WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_ACCOUNT_CALCULATION WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.commit().map_err(|e| format!("GPFFP Commit failure: {}", e))?;
            Ok(())
        }).await.unwrap()
    }

    pub async fn gpffp_delete_from_pre_calculation(&self, regd_no: &str) -> Result<(), String> {
        let r_no = regd_no.to_string();
        let conn = self.get_connection(OracleTarget::Gpffp)?;
        tokio::task::spawn_blocking(move || {
            conn.execute("DELETE FROM FP_MAIN WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_SUBSCRIPTION_DETAILS WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_MISSING_CREDIT WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_ACCOUNT_CALCULATION WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("UPDATE FP_APPLICATION SET CALCULATION_DATE = NULL WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.commit().map_err(|e| format!("GPFFP Commit failure: {}", e))?;
            Ok(())
        }).await.unwrap()
    }

    pub async fn health_check(&self) -> Result<(), String> {
        for target in &[OracleTarget::Gpffp, OracleTarget::SaiAgartala] {
            let conn = self.get_connection(*target)?;
            let row = conn.query_row("SELECT 1 FROM DUAL", &[]).map_err(|e| e.to_string())?;
            let _: i32 = row.get(0).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}