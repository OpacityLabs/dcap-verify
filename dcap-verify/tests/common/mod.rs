//! Shared fixture loader for the integration tests. Per-case inputs (verification
//! time, pinned MRENCLAVE, expected verdict/category/standing) are read from each
//! case's `meta.json` through this single helper — never hardcoded — so a fixture
//! recapture can never leave a test green while exercising stale constants.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dcap_verify::types::report::MREnclave;
use dcap_verify::{ErrorCategory, VerifyError};

pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures")
}

/// One fixture case, with every input loaded from its `meta.json`.
pub struct FixtureCase {
    pub name: String,
    pub quote_bytes: Vec<u8>,
    pub collateral_bytes: Vec<u8>,
    pub mrenclave: MREnclave,
    pub current_time: SystemTime,
    pub min_tcb_evaluation_data_number: u32,
    pub verdict: String,
    pub category: Option<String>,
    pub tcb_standing: Option<serde_json::Value>,
}

pub fn load_case(name: &str) -> FixtureCase {
    let dir = fixtures_dir().join(name);
    let meta: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("meta.json")).expect("meta.json unreadable"))
            .expect("meta.json undecodable");
    let time_unix = meta["current_time_unix"]
        .as_u64()
        .expect("meta.json current_time_unix");
    let mrenclave_hex = meta["expected_mrenclave_hex"]
        .as_str()
        .expect("meta.json expected_mrenclave_hex");
    let mr = hex::decode(mrenclave_hex).expect("expected_mrenclave_hex not hex");
    let mrenclave = MREnclave::try_from(mr.as_slice()).expect("expected_mrenclave not 32 bytes");

    FixtureCase {
        name: name.to_string(),
        quote_bytes: fs::read(dir.join("quote.bin")).expect("quote.bin unreadable"),
        collateral_bytes: fs::read(dir.join("collateral.json"))
            .expect("collateral.json unreadable"),
        mrenclave,
        current_time: UNIX_EPOCH + Duration::from_secs(time_unix),
        min_tcb_evaluation_data_number: meta
            .get("min_tcb_evaluation_data_number")
            .map(|v| {
                let n = v
                    .as_u64()
                    .expect("meta.json min_tcb_evaluation_data_number");
                u32::try_from(n).expect("min_tcb_evaluation_data_number exceeds u32")
            })
            .unwrap_or(0),
        verdict: meta["verdict"]
            .as_str()
            .expect("meta.json verdict")
            .to_string(),
        category: meta
            .get("category")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        tcb_standing: meta.get("tcb_standing").cloned(),
    }
}

/// Every fixture case directory (one holding a `meta.json`), sorted for determinism.
pub fn all_case_names() -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(fixtures_dir())
        .expect("fixtures directory unreadable")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.join("meta.json").is_file())
        .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect();
    names.sort();
    names
}

/// The public API surfaces rejections as `VerifyError`, whose `category()`
/// classifies the failure.
pub fn category_of(err: &VerifyError) -> ErrorCategory {
    err.category
}

/// Split a PEM string into its individual CERTIFICATE blocks (each re-wrapped
/// with a trailing newline), preserving document order.
pub fn cert_blocks(pem: &str) -> Vec<String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(begin) = rest.find(BEGIN) {
        let after = &rest[begin..];
        let end = after
            .find(END)
            .expect("certificate block without END marker")
            + END.len();
        out.push(format!("{}\n", &after[..end]));
        rest = &after[end..];
    }
    out
}
