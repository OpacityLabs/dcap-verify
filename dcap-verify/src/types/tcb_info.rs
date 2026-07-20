use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfo {
    pub id: String,
    pub version: u32,
    pub issue_date: DateTime<Utc>,
    pub next_update: DateTime<Utc>,
    pub fmspc: String,
    pub pce_id: String,
    pub tcb_type: u32,
    pub tcb_evaluation_data_number: u32,
    pub tcb_levels: Vec<TcbLevel>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    pub tcb: TcbPlatform,
    pub tcb_date: DateTime<Utc>,
    pub tcb_status: String,
    #[serde(rename = "advisoryIDs", default)]
    pub advisory_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TcbPlatform {
    pub sgxtcbcomponents: Vec<TcbComponent>,
    pub pcesvn: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TcbComponent {
    pub svn: u32,
}
