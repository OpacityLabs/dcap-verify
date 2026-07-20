mod common;

use common::{all_case_names, fixtures_dir, load_case};
use dcap_verify::{SgxCollateral, SgxQuote, verify_remote_attestation};
use proptest::prelude::*;
use std::fs;

fn all_fixture_quotes() -> Vec<Vec<u8>> {
    all_case_names()
        .iter()
        .map(|n| fs::read(fixtures_dir().join(n).join("quote.bin")).expect("quote.bin"))
        .collect()
}

#[test]
fn quote_truncations_return_errors() {
    for quote in all_fixture_quotes() {
        for len in 0..=quote.len() {
            let mut cursor = &quote[..len];
            let _ = SgxQuote::read(&mut cursor);
        }
    }
}

#[test]
fn collateral_truncations_return_errors() {
    let case = load_case("prod-1");
    for len in 0..=case.collateral_bytes.len() {
        if let Ok(parsed) = serde_json::from_slice::<SgxCollateral>(&case.collateral_bytes[..len]) {
            let mut cursor: &[u8] = &case.quote_bytes;
            let quote = SgxQuote::read(&mut cursor).expect("prod-1 quote parses");
            let _ = verify_remote_attestation(case.current_time, parsed, quote, &case.mrenclave, 0);
        }
    }
}

proptest! {
    #[test]
    fn mutated_quotes_never_panic(
        flips in prop::collection::vec((0usize..8192, any::<u8>()), 1..8),
        tail in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let case = load_case("prod-1");
        let mut quote = case.quote_bytes.clone();
        for (pos, byte) in flips {
            let len = quote.len();
            quote[pos % len] = byte;
        }
        quote.extend_from_slice(&tail);
        let mut cursor: &[u8] = &quote;
        if let Ok(parsed) = SgxQuote::read(&mut cursor) {
            let collateral: SgxCollateral =
                serde_json::from_slice(&case.collateral_bytes).expect("collateral");
            let _ = verify_remote_attestation(case.current_time, collateral, parsed, &case.mrenclave, 0);
        }
    }

    #[test]
    fn mutated_collateral_never_panics(
        flips in prop::collection::vec((0usize..16384, any::<u8>()), 1..8),
    ) {
        let case = load_case("prod-1");
        let mut collateral = case.collateral_bytes.clone();
        for (pos, byte) in flips {
            let len = collateral.len();
            collateral[pos % len] = byte;
        }
        if let Ok(parsed) = serde_json::from_slice::<SgxCollateral>(&collateral) {
            let mut cursor: &[u8] = &case.quote_bytes;
            let quote = SgxQuote::read(&mut cursor).expect("prod-1 quote parses");
            let _ = verify_remote_attestation(case.current_time, parsed, quote, &case.mrenclave, 0);
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let mut cursor: &[u8] = &data;
        let _ = SgxQuote::read(&mut cursor);
        let _ = serde_json::from_slice::<SgxCollateral>(&data);
    }
}
