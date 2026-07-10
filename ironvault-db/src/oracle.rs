//! Oracle Multi-Pool Matrix Controller Connection Hub
//!
//! Handles configuration pools across distinct host locations without
//! cross-contaminating schema transaction pipelines.

// --- BACKWARD COMPATIBILITY BRIDGE MODULE RE-EXPORTS ---
pub use crate::gpf::GpfCaseRecord;
pub use crate::pendak::{
    DakRecipientDetail, FullPensionDakRecord, PensionAuthDetails, PensionDakEntry,
};

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

pub struct OracleConnection {
    pub(crate) pool_gpffp: oracle::pool::Pool,
    pub(crate) pool_vlcs: oracle::pool::Pool,
    pub(crate) pool_agtall: oracle::pool::Pool,
    pub(crate) pool_agdak: oracle::pool::Pool,
    pub(crate) pool_sai_agartala: oracle::pool::Pool,
    pub(crate) pool_pendak: oracle::pool::Pool,
    pub(crate) pool_penindex: oracle::pool::Pool,
}

impl OracleConnection {
    /// Initialize all 7 discrete schema connection pools across network clusters
    pub fn new() -> Result<Self, String> {
        let tns_100 = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=192.168.100.247)(PORT=1521))(CONNECT_DATA=(SID=db11g)))";

        let pool_gpffp = oracle::pool::PoolBuilder::new("gpffp", "gpffp", tns_100)
            .build()
            .map_err(|e| format!("gpffp node link failure: {}", e))?;
        let pool_vlcs = oracle::pool::PoolBuilder::new("vlcs", "vlcs", tns_100)
            .build()
            .map_err(|e| format!("vlcs node link failure: {}", e))?;
        let pool_agtall = oracle::pool::PoolBuilder::new("agtall", "agtall", tns_100)
            .build()
            .map_err(|e| format!("agtall node link failure: {}", e))?;
        let pool_agdak = oracle::pool::PoolBuilder::new("agdak", "agdak", tns_100)
            .build()
            .map_err(|e| format!("agdak node link failure: {}", e))?;

        let tns_0 = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=192.168.0.140)(PORT=1521))(CONNECT_DATA=(SID=orcl)))";

        let pool_sai_agartala =
            oracle::pool::PoolBuilder::new("sai_agartala", "sai_agartala", tns_0)
                .build()
                .map_err(|e| format!("sai_agartala node link failure: {}", e))?;
        let pool_pendak = oracle::pool::PoolBuilder::new("pendak", "pendak", tns_0)
            .build()
            .map_err(|e| format!("pendak node link failure: {}", e))?;
        let pool_penindex = oracle::pool::PoolBuilder::new("penindex", "penindex", tns_0)
            .build()
            .map_err(|e| format!("penindex node link failure: {}", e))?;

        Ok(Self {
            pool_gpffp,
            pool_vlcs,
            pool_agtall,
            pool_agdak,
            pool_sai_agartala,
            pool_pendak,
            pool_penindex,
        })
    }

    /// Internal helper method to grab an active connection from requested pool context safely
    pub(crate) fn get_connection(
        &self,
        target: OracleTarget,
    ) -> Result<oracle::Connection, String> {
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

    pub async fn health_check(&self) -> Result<Option<()>, String> {
        for target in &[OracleTarget::Gpffp, OracleTarget::SaiAgartala] {
            let conn = self.get_connection(*target)?;
            let row = conn
                .query_row("SELECT 1 FROM DUAL", &[])
                .map_err(|e| e.to_string())?;
            let _: i32 = row.get(0).map_err(|e| e.to_string())?;
        }
        Ok(Some(()))
    }
}
