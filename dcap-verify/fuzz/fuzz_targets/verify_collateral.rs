#![no_main]

use std::sync::LazyLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libfuzzer_sys::fuzz_target;

const QUOTE: &[u8] = include_bytes!("../../../fixtures/prod-1/quote.bin");
const META: &str = include_str!("../../../fixtures/prod-1/meta.json");

struct CaseParams {
    mrenclave: [u8; 32],
    current_time: SystemTime,
}

// The pinned MRENCLAVE and verification time are read from the fixture's meta.json,
// never hardcoded, so a recapture cannot leave this target silently stale.
static PARAMS: LazyLock<CaseParams> = LazyLock::new(|| {
    let meta: serde_json::Value = serde_json::from_str(META).expect("meta.json parses");
    let mr = hex::decode(
        meta["expected_mrenclave_hex"]
            .as_str()
            .expect("mrenclave hex"),
    )
    .expect("mrenclave is hex");
    let mrenclave: [u8; 32] = mr.as_slice().try_into().expect("mrenclave is 32 bytes");
    let unix = meta["current_time_unix"]
        .as_u64()
        .expect("current_time_unix");
    CaseParams {
        mrenclave,
        current_time: UNIX_EPOCH + Duration::from_secs(unix),
    }
});

fuzz_target!(|data: &[u8]| {
    let Ok(collateral) = serde_json::from_slice::<dcap_verify::SgxCollateral>(data) else {
        return;
    };
    let mut cursor = QUOTE;
    let quote = dcap_verify::SgxQuote::read(&mut cursor).expect("embedded quote parses");
    let _ = dcap_verify::verify_remote_attestation(
        PARAMS.current_time,
        collateral,
        quote,
        &PARAMS.mrenclave,
        0,
    );
});
