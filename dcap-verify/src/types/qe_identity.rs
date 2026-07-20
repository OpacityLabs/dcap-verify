use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QeIdentity {
    pub id: String,
    pub version: u32,
    pub issue_date: DateTime<Utc>,
    pub next_update: DateTime<Utc>,
    pub tcb_evaluation_data_number: u32,
    pub miscselect: String,
    pub miscselect_mask: String,
    pub attributes: String,
    pub attributes_mask: String,
    pub mrsigner: String,
    pub isvprodid: u16,
    pub tcb_levels: Vec<QeTcbLevel>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QeTcbLevel {
    pub tcb: QeTcb,
    pub tcb_date: DateTime<Utc>,
    pub tcb_status: String,
    #[serde(rename = "advisoryIDs", default)]
    pub advisory_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct QeTcb {
    pub isvsvn: u16,
}
