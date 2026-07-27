//! Pension DAK Subsystem Ledger Methods Module

use crate::oracle::{OracleConnection, OracleTarget};

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
    pub addressee_name: String,
}

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

impl OracleConnection {
    /// Fetch associated pension authorities (PPO, FPPO, GPO, CPO) and pensioner addressee name for a given application number
    pub async fn pendak_fetch_auth_details(
        &self,
        appln_no: &str,
    ) -> Result<Option<PensionAuthDetails>, String> {
        let app_no = appln_no.trim().to_string();
        if app_no.is_empty() {
            return Ok(None);
        }
        let conn = self.get_connection(OracleTarget::Penindex)?;

        tokio::task::spawn_blocking(move || {
            let query = "
                SELECT 
                    a.APA_AUTH_TYPE, 
                    a.APA_AUTH_NO,
                    INITCAP(REGEXP_REPLACE(TRIM(REGEXP_REPLACE(b.APPLN_PNSR_SALUTE || ' ' || b.APPLN_PNSNR_NAME, '[.]', '')), '\\s+', ' ')) AS PNSNR_NAME
                FROM SAI_AGARTALA.T_APPLICATION_HDR b
                LEFT JOIN SAI_AGARTALA.T_APPLN_AUTHORITY a ON a.APA_APPLN_PK = b.APPLN_PK AND a.APA_AUTH_TYPE IN ('760', '761', '762', '763')
                WHERE b.APPLN_NO = :app_no
            ";
            let mut stmt = conn.statement(query).build().map_err(|e| e.to_string())?;
            let rows = stmt
                .query_named(&[("app_no", &app_no.as_str())])
                .map_err(|e| e.to_string())?;

            let mut details = PensionAuthDetails::default();
            let mut found_any = false;
            for row_result in rows {
                let row = row_result.map_err(|e| e.to_string())?;
                let auth_type: Option<String> = row.get(0).unwrap_or(None);
                let auth_no: Option<String> = row.get(1).unwrap_or(None);
                let name: String = row.get(2).unwrap_or_default();

                found_any = true;
                if !name.is_empty() {
                    details.addressee_name = name;
                }
                if let (Some(at), Some(an)) = (auth_type, auth_no) {
                    match at.trim() {
                        "760" => details.ppo_no = an,
                        "761" => details.gpo_no = an,
                        "762" => details.cpo_no = an,
                        "763" => details.fppo_no = an,
                        _ => {}
                    }
                }
            }
            if found_any {
                Ok(Some(details))
            } else {
                Ok(None)
            }
        })
        .await
        .unwrap()
    }

    /// Insert an outward DAK case entry into PEN_DAK_OUTWARD_DIARY
    pub async fn pendak_insert_outward_case(&self, entry: PensionDakEntry) -> Result<(), String> {
        let conn = self.get_connection(OracleTarget::Pendak)?;
        tokio::task::spawn_blocking(move || {
            let query = "
                INSERT INTO PEN_DAK_OUTWARD_DIARY (
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
                conn.execute(
                    query,
                    &[
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
                    ],
                )
                .map_err(|e| format!("Insertion failed: {}", e))?;
            }
            conn.commit()
                .map_err(|e| format!("Commit failure: {}", e))?;
            Ok(())
        })
        .await
        .unwrap()
    }

    /// Query full details for an outward DAK case record
    pub async fn pendak_select_outward_case_full(
        &self,
        appln_no: &str,
    ) -> Result<Option<FullPensionDakRecord>, String> {
        let app_no_numeric: i64 = appln_no.trim().parse().unwrap_or(0);
        if app_no_numeric == 0 {
            return Ok(None);
        }
        let conn = self.get_connection(OracleTarget::Pendak)?;

        tokio::task::spawn_blocking(move || {
            let query = "
                SELECT APPLN_NO, LETTER_NO, PPO_FPPO, GPO, CPO, SECTION, SUBJECT, 
                       ADDRESSEE, BAR_CODE, SENT_BY, TO_CHAR(OUTWARD_DATE, 'YYYY-MM-DD') 
                FROM PEN_DAK_OUTWARD_DIARY WHERE APPLN_NO = :1 AND ROWNUM <= 1
            ";
            let mut stmt = conn.statement(query).build().map_err(|e| e.to_string())?;
            let rows = stmt.query(&[&app_no_numeric]).map_err(|e| e.to_string())?;

            for row_res in rows {
                let row = row_res.map_err(|e| e.to_string())?;

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
        })
        .await
        .unwrap()
    }

    /// Apply section and subject modifications to an existent outward DAK case record
    pub async fn pendak_update_outward_case(
        &self,
        app_num: &str,
        section: &str,
        subject: &str,
    ) -> Result<(), String> {
        let app_no_numeric: i64 = app_num.trim().parse().unwrap_or(0);
        let section_numeric: i32 = section.trim().parse().unwrap_or(0);
        let sub = subject.to_string();
        let conn = self.get_connection(OracleTarget::Pendak)?;

        tokio::task::spawn_blocking(move || {
            conn.execute(
                "UPDATE PEN_DAK_OUTWARD_DIARY SET SECTION = :1, SUBJECT = :2 WHERE APPLN_NO = :3",
                &[&section_numeric, &sub, &app_no_numeric],
            )
            .map_err(|e| e.to_string())?;
            conn.commit().map_err(|e| e.to_string())?;
            Ok(())
        })
        .await
        .unwrap()
    }
}
