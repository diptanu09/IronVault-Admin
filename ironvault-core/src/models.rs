use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DatabaseRecord {
    pub id: i32,
    pub title: String,
    pub schema_origin: String,
    pub status: String,
}