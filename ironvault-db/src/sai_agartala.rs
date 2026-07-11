//! Sai_Agartala Pension Subsystem Business Logics Module

use crate::oracle::{OracleConnection, OracleTarget};

#[derive(Debug, Clone, Default)]
pub struct PensionDetailsRecord {
    pub application_no: String,
    pub pensioner_name: String,
    pub employee_code: i64,
    pub beneficiary_code: String,
    pub designation: String,
    pub sex: String,
    pub mobile_no: String,
    pub email_id: String,
    pub date_of_birth: String,
    pub date_of_joining: String,
}

#[derive(Debug, Clone, Default)]
pub struct PensionStatusRecord {
    pub application_no: String,
    pub application_date: String,
    pub name: String,
    pub last_work_office_name: String,
    pub status: String,
    pub date_of_settle: String,
    pub ppo: String,
    pub gpo: String,
    pub cpo: String,
    pub dak_outward_date: String,
    pub speed_post: String,
    pub treasury: String,
}

impl OracleConnection {
    /// Fetch pensioner biographical details based on target Application No or Employee ID lookup
    pub async fn pnsr_get_details(&self, search_term: &str) -> Result<Vec<PensionDetailsRecord>, String> {
        let term = search_term.trim().to_string();
        if term.is_empty() { return Ok(Vec::new()); }
        let conn = self.get_connection(OracleTarget::SaiAgartala)?;

        tokio::task::spawn_blocking(move || {
            let query = "
                SELECT 
                    b.APPLN_NO as \"APPLICATION_NO\", 
                    INITCAP(REGEXP_REPLACE(TRIM(REGEXP_REPLACE(b.APPLN_PNSR_SALUTE || ' ' || b.APPLN_PNSNR_NAME, '[.]', '')), '\\s+', ' ')) AS \"PENSIONER_NAME\",
                    NVL(b.EMP_NO,0) AS \"EMPLOYEE_CODE\",
                    'NA' AS \"BBENEFICIARY_CODE\",
                    COALESCE(INITCAP(TRIM(REGEXP_REPLACE(c.DESG_NAME, '\\s+,', ', '))), 'NA') AS \"DESIGNATION\",
                    'NA' AS \"SEX\",
                    COALESCE(a.APEN_AR_MOBILE,'NA') AS \"MOBILE_NO\",
                    'NA' AS EMAIL_ID, 
                    COALESCE(TO_CHAR(a.APEN_DOB, 'yyyy-MM-dd'),'1970-01-01') AS DATE_OF_BIRTH, 
                    '1970-01-01' AS DATE_OF_JOINING 
                FROM T_APPLN_PENSIONER a 
                INNER JOIN T_APPLICATION_HDR b on a.APEN_APPLN_PK=b.APPLN_PK 
                INNER JOIN M_DESIGNATION c ON a.APEN_DESG_PK=c.DESG_PK 
                WHERE a.APEN_AR_MOBILE NOT LIKE '%/%' 
                  AND (b.APPLN_NO = :1 OR b.EMP_NO = :2 OR INITCAP(b.APPLN_PNSNR_NAME) LIKE :3)
            ";

            let search_like = format!("%{}%", term);
            let mut stmt = conn.statement(query).build().map_err(|e| e.to_string())?;
            let rows = stmt.query(&[&term, &term, &search_like]).map_err(|e| e.to_string())?;

            let mut records = Vec::new();
            for row_res in rows {
                let row = row_res.map_err(|e| e.to_string())?;
                
                let app_no_val: String = row.get(0).unwrap_or_default();
                let pensioner_name_val: String = row.get(1).unwrap_or_default();
                let employee_code_val: i64 = row.get(2).unwrap_or(0);
                let beneficiary_code_val: String = row.get(3).unwrap_or_default();
                let designation_val: String = row.get(4).unwrap_or_default();
                let sex_val: String = row.get(5).unwrap_or_default();
                let mobile_no_val: String = row.get(6).unwrap_or_default();
                let email_id_val: String = row.get(7).unwrap_or_default();
                let date_of_birth_val: String = row.get(8).unwrap_or_default();
                let date_of_joining_val: String = row.get(9).unwrap_or_default();

                records.push(PensionDetailsRecord {
                    application_no: app_no_val,
                    pensioner_name: pensioner_name_val,
                    employee_code: employee_code_val,
                    beneficiary_code: beneficiary_code_val,
                    designation: designation_val,
                    sex: sex_val,
                    mobile_no: mobile_no_val,
                    email_id: email_id_val,
                    date_of_birth: date_of_birth_val,
                    date_of_joining: date_of_joining_val,
                });
            }
            Ok(records)
        }).await.unwrap()
    }

    /// Track lifecycle settlement and speed post dispatches across Sai_Agartala & PenDak registries
    pub async fn pnsr_get_status_tracking(&self, search_app_no: &str) -> Result<Option<PensionStatusRecord>, String> {
        let app_no = search_app_no.trim().to_string();
        if app_no.is_empty() { return Ok(None); }
        let conn = self.get_connection(OracleTarget::SaiAgartala)?;

        tokio::task::spawn_blocking(move || {
            let query = "
                WITH app_data AS (
                    SELECT 
                        INITCAP(REGEXP_REPLACE(TRIM(REGEXP_REPLACE(b.APPLN_PNSR_SALUTE || ' ' || b.APPLN_PNSNR_NAME, '[.]', '')), '\\s+', ' ')) AS PNSNR_NAME,
                        COALESCE(INITCAP(TRIM(REGEXP_REPLACE(b.APPLN_FWD_OFF_NAME, '\\s+,', ', '))), 'NA') AS PREV_OFFC,
                        COALESCE(INITCAP(TRIM(REGEXP_REPLACE(e.DESG_NAME, '\\s+,', ', '))), 'NA') AS DESG_NAME,
                        COALESCE(INITCAP(TRIM(REGEXP_REPLACE(b.APPLN_DDO_NAME, '\\s+,', ', '))), 'NA') AS DDO_NAME,
                        COALESCE(INITCAP(TRIM(REGEXP_REPLACE(f.adbk_addr1, '\\s+,', ', '))), 'NA') AS TRSY_NAME,
                        b.APPLN_NO AS APPLICATION_NO,
                        COALESCE(TO_CHAR(b.APPLN_DATE, 'YYYY-MM-DD'), '1970-01-01') AS APPLICATION_DATE,
                        COALESCE(c.LOV_NAME, 'NA') AS APPLICATION_TYPE,
                        a.APA_AUTH_NO AS AUTHORITY_NO,
                        COALESCE(TO_CHAR(a.APA_APPRVL_DATE, 'YYYY-MM-DD'), '1970-01-01') AS DATE_OF_SETTLE,
                        b.APPLN_STAT_DESC AS STATUS,
                        g.INOUT_TXNTP_ID AS INOUT_TYPE,
                        REGEXP_SUBSTR(g.INOUT_NO, '[^/]+$', 1, 1) AS INOUT_NO,
                        COALESCE(TO_CHAR(g.INOUT_DATE, 'YYYY-MM-DD'), '1970-01-01') AS INOUT_DATE
                    FROM 
                        SAI_AGARTALA.T_APPLICATION_HDR b
                        LEFT JOIN SAI_AGARTALA.T_APPLN_AUTHORITY a ON a.APA_APPLN_PK = b.APPLN_PK 
                        LEFT JOIN SAI_AGARTALA.M_LOV c ON c.LOV_PK = a.APA_AUTH_TYPE
                        LEFT JOIN SAI_AGARTALA.T_APPLN_PENSIONER d ON b.APPLN_PK = d.APEN_APPLN_PK
                        LEFT JOIN SAI_AGARTALA.M_DESIGNATION e ON d.APEN_DESG_PK = e.DESG_PK
                        LEFT JOIN SAI_AGARTALA.M_ADDR_BOOK f ON f.ADBK_PK = a.APA_TRSY
                        LEFT JOIN SAI_AGARTALA.T_INWARD_OUTWARD g ON a.APA_PK = g.INOUT_PK
                    WHERE b.APPLN_NO = :1
                ),
                latest_outward AS (
                    SELECT 
                        APPLN_NO,
                        OUTWARD_DATE,
                        BAR_CODE,
                        ROW_NUMBER() OVER (PARTITION BY APPLN_NO ORDER BY OUTWARD_DATE DESC) as rn
                    FROM PENDAK.PEN_DAK_OUTWARD_DIARY WHERE APPLN_NO = :2
                )
                SELECT DISTINCT
                    t.APPLICATION_NO AS \"APPLICATION_NO\",
                    t.APPLICATION_DATE AS \"APPLICATION_DATE\",
                    t.PNSNR_NAME AS \"NAME\",
                    t.PREV_OFFC AS \"LAST_WORK_OFFICE_NAME\",
                    t.STATUS AS \"STATUS\",
                    t.DATE_OF_SETTLE AS \"DATE_OF_SETTLE\",
                    MAX(CASE WHEN t.APPLICATION_TYPE = 'PPO' THEN t.AUTHORITY_NO END) OVER (PARTITION BY t.APPLICATION_NO) AS \"PPO\",
                    MAX(CASE WHEN t.APPLICATION_TYPE = 'GPO' THEN t.AUTHORITY_NO END) OVER (PARTITION BY t.APPLICATION_NO) AS \"GPO\",    
                    MAX(CASE WHEN t.APPLICATION_TYPE = 'CPO' THEN t.AUTHORITY_NO END) OVER (PARTITION BY t.APPLICATION_NO) AS \"CPO\",
                    COALESCE(TO_CHAR(r.OUTWARD_DATE, 'YYYY-MM-DD'), '1970-01-01') AS \"DAK_OUTWARD_DATE\",
                    CASE WHEN r.OUTWARD_DATE IS NOT NULL THEN REGEXP_REPLACE(TRIM(r.BAR_CODE), '[^A-Za-z0-9]', '') END AS \"SPEED_POST\",
                    t.TRSY_NAME AS \"TREASURY\"
                FROM 
                    app_data t
                    LEFT JOIN latest_outward r ON t.APPLICATION_NO = r.APPLN_NO AND r.rn = 1
            ";

            let mut stmt = conn.statement(query).build().map_err(|e| e.to_string())?;
            let rows = stmt.query(&[&app_no, &app_no]).map_err(|e| e.to_string())?;

            for row_res in rows {
                let row = row_res.map_err(|e| e.to_string())?;

                let app_no_val: String = row.get(0).unwrap_or_default();
                let app_date_val: String = row.get(1).unwrap_or_default();
                let name_val: String = row.get(2).unwrap_or_default();
                let office_val: String = row.get(3).unwrap_or_default();
                let status_val: String = row.get(4).unwrap_or_default();
                let settle_val: String = row.get(5).unwrap_or_default();
                
                // FIXED: Omit explicit type arguments entirely to allow clean contextual type inference
                let ppo_val: Option<String> = row.get(6).unwrap_or(None);
                let gpo_val: Option<String> = row.get(7).unwrap_or(None);
                let cpo_val: Option<String> = row.get(8).unwrap_or(None);
                
                let outward_date_val: String = row.get(9).unwrap_or_default();
                let speed_post_val: Option<String> = row.get(10).unwrap_or(None);
                let treasury_val: String = row.get(11).unwrap_or_default();

                return Ok(Some(PensionStatusRecord {
                    application_no: app_no_val,
                    application_date: app_date_val,
                    name: name_val,
                    last_work_office_name: office_val,
                    status: status_val,
                    date_of_settle: settle_val,
                    ppo: ppo_val.unwrap_or_else(|| "N/A".to_string()),
                    gpo: gpo_val.unwrap_or_else(|| "N/A".to_string()),
                    cpo: cpo_val.unwrap_or_else(|| "N/A".to_string()),
                    dak_outward_date: outward_date_val,
                    speed_post: speed_post_val.unwrap_or_else(|| "NOT DISPATCHED".to_string()),
                    treasury: treasury_val,
                }));
            }
            Ok(None)
        }).await.unwrap()
    }
}