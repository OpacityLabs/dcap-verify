mod common;

use common::{all_case_names, fixtures_dir};
use dcap_verify::{SgxQuote, peek_mrenclave, peek_report_data};
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
