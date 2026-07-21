mod common;

use common::{all_case_names, fixtures_dir};
use dcap_verify::{
    PckCa, SgxCollateral, SgxQuote, pck_collateral_params, peek_mrenclave, peek_report_data,
};
use std::fs;

/// The peek helpers use fixed byte offsets; the parser walks the full layout.
/// Pin their agreement over every parseable fixture quote so the offsets can
/// never silently drift from what the parser (and thus verification) sees.
#[test]
fn peek_offsets_agree_with_parser_on_all_fixtures() {
    let mut checked = 0usize;
    for name in all_case_names() {
        let quote_path = fixtures_dir().join(&name).join("quote.bin");
        let bytes = fs::read(&quote_path).expect("fixture quote unreadable");
        let mut cursor: &[u8] = &bytes;
        let Ok(quote) = SgxQuote::read(&mut cursor) else {
            continue; // deliberately corrupt fixtures are exercised elsewhere
        };
        assert_eq!(
            peek_mrenclave(&bytes).expect("peek_mrenclave on parseable quote"),
            &quote.report_body.mrenclave,
            "{quote_path:?}"
        );
        assert_eq!(
            peek_report_data(&bytes).expect("peek_report_data on parseable quote"),
            &quote.report_body.sgx_report_data_bytes,
            "{quote_path:?}"
        );
        checked += 1;
    }
    assert!(
        checked >= 10,
        "only {checked} parseable fixture quotes seen"
    );
}

/// `pck_collateral_params` reads the collateral selectors from the QUOTE side.
/// Cross-check against the signed collateral: every internally consistent
/// fixture pair agrees on the FMSPC, and the one fixture built from a
/// different platform's quote (`tcb-info-wrong-fmspc`) must disagree —
/// proving the helper does not read the collateral's value.
#[test]
fn pck_collateral_params_agree_with_collateral_on_all_fixtures() {
    let mut checked = 0usize;
    for name in all_case_names() {
        let dir = fixtures_dir().join(&name);
        let bytes = fs::read(dir.join("quote.bin")).expect("fixture quote unreadable");
        let mut cursor: &[u8] = &bytes;
        let Ok(quote) = SgxQuote::read(&mut cursor) else {
            continue;
        };
        let collateral_bytes =
            fs::read(dir.join("collateral.json")).expect("fixture collateral unreadable");
        let Ok(collateral) = serde_json::from_slice::<SgxCollateral>(&collateral_bytes) else {
            continue; // deliberately corrupt collateral is exercised elsewhere
        };
        let (fmspc, ca) = pck_collateral_params(&quote).expect("fixture PCK chain readable");
        assert_eq!(
            ca,
            PckCa::Processor,
            "{name}: fixture fleet is Processor CA"
        );
        let quote_fmspc = hex::encode(fmspc);
        let collateral_fmspc = collateral.tcb_info.body.fmspc.to_lowercase();
        if name == "tcb-info-wrong-fmspc" {
            assert_ne!(quote_fmspc, collateral_fmspc, "{name}");
        } else {
            assert_eq!(quote_fmspc, collateral_fmspc, "{name}");
        }
        checked += 1;
    }
    assert!(checked >= 10, "only {checked} fixture pairs checked");
}
