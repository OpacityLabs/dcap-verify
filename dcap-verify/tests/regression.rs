mod common;

use common::{category_of, load_case};
use dcap_verify::types::report::MREnclave;
use dcap_verify::{
    ErrorCategory, PckCa, SgxCollateral, SgxQuote, TcbStanding, pck_collateral_params,
    verify_remote_attestation,
};
use serde_json::json;

fn last_cert_block(chain_pem: &str) -> String {
    const END: &str = "-----END CERTIFICATE-----";
    let end_idx = chain_pem.rfind(END).expect("no END marker") + END.len();
    let start_idx = chain_pem[..end_idx]
        .rfind("-----BEGIN CERTIFICATE-----")
        .expect("no BEGIN marker");
    format!("{}\n", &chain_pem[start_idx..end_idx])
}

/// The PCK CRL only covers serials issued by the CA that signed the quote's PCK leaf.
/// This substitutes a genuine-but-mis-scoped CRL (the root CA CRL, correctly signed by
/// the pinned root) together with a root-only issuer chain. Every signature and validity
/// check passes, but the CRL is scoped to `Intel SGX Root CA`, not the PCK leaf's issuer.
/// A verifier that trusts the collateral-supplied CRL scope would accept it (fail-open);
/// the issuer-binding guard must reject it.
#[test]
fn pck_crl_scope_substitution_is_rejected() {
    let case = load_case("prod-1");
    let mut collateral: serde_json::Value =
        serde_json::from_slice(&case.collateral_bytes).expect("collateral json");

    // Root-only issuer chain (subject `Intel SGX Root CA`), pulled from a genuine chain.
    let tcb_chain = collateral["tcb_info_issuer_chain"]
        .as_str()
        .expect("tcb chain is a string")
        .to_string();
    let root_only = last_cert_block(&tcb_chain);

    // Point the PCK CRL and its issuer chain at the root CA instead of the PCK CA.
    collateral["pck_crl"] = collateral["root_ca_crl"].clone();
    collateral["pck_crl_issuer_chain"] = serde_json::Value::String(root_only);

    let collateral: SgxCollateral =
        serde_json::from_value(collateral).expect("mutated collateral still deserializes");

    let mut cursor: &[u8] = &case.quote_bytes;
    let quote = SgxQuote::read(&mut cursor).expect("prod-1 quote parses");

    let err = verify_remote_attestation(case.current_time, collateral, quote, &case.mrenclave, 0)
        .expect_err("mis-scoped PCK CRL must be rejected, not accepted");
    assert_eq!(
        category_of(&err),
        ErrorCategory::CrlInvalid,
        "expected the mis-scoped PCK CRL to be rejected as crl-invalid, got: {err}"
    );
}

/// Locks in the exact `SgxReportBody` surface that downstream callers rely
/// on: the public 64-byte `sgx_report_data_bytes` field, `mrenclave`,
/// and the `(TcbStanding, SgxReportBody)` return tuple shape.
#[test]
fn report_body_surface_is_stable() {
    let case = load_case("prod-1");
    let collateral: SgxCollateral =
        serde_json::from_slice(&case.collateral_bytes).expect("collateral");
    let mut cursor: &[u8] = &case.quote_bytes;
    let quote = SgxQuote::read(&mut cursor).expect("prod-1 quote parses");

    let (_standing, report_body) =
        verify_remote_attestation(case.current_time, collateral, quote, &case.mrenclave, 0)
            .expect("prod-1 accepts");

    // Exact accesses a freshness-binding wrapper performs on the report body.
    let data_hash: &[u8] = &report_body.sgx_report_data_bytes[..32];
    let nonce: &[u8] = &report_body.sgx_report_data_bytes[32..64];
    let returned: [u8; 64] = report_body.sgx_report_data_bytes;
    assert_eq!(data_hash.len(), 32);
    assert_eq!(nonce.len(), 32);
    assert_eq!(returned.len(), 64);
    let expected_mr: MREnclave = case.mrenclave;
    assert_eq!(report_body.mrenclave, expected_mr);
}

/// Locks the kebab-case serde tags and advisory-id shape of every public
/// `TcbStanding` variant. The fixture oracle only exercises the variant its
/// accept fixtures happen to return; downstream consumers rely on all three
/// tags.
#[test]
fn tcb_standing_serde_tags_are_stable() {
    let cases = [
        (TcbStanding::UpToDate, json!("up-to-date")),
        (
            TcbStanding::SWHardeningNeeded {
                advisory_ids: vec!["INTEL-SA-00615".to_string()],
            },
            json!({"sw-hardening-needed": {"advisory_ids": ["INTEL-SA-00615"]}}),
        ),
        (
            TcbStanding::ConfigurationAndSWHardeningNeeded {
                advisory_ids: vec!["INTEL-SA-00289".to_string(), "INTEL-SA-00615".to_string()],
            },
            json!({"configuration-and-sw-hardening-needed": {"advisory_ids": ["INTEL-SA-00289", "INTEL-SA-00615"]}}),
        ),
    ];
    for (standing, expected) in cases {
        let got = serde_json::to_value(&standing).expect("TcbStanding serializes");
        assert_eq!(got, expected, "serde tag drifted for {standing:?}");
        let back: TcbStanding =
            serde_json::from_value(got).expect("TcbStanding round-trips from its own JSON");
        assert_eq!(back, standing);
    }
}

/// Locks the collateral-selection helper surface downstream fetchers rely on:
/// the `([u8; 6], PckCa)` return shape and the PCS v4 `pckcrl?ca=` wire
/// strings. The FMSPC value is cross-checked against the signed collateral in
/// the peek suite; here only the shape and the wire strings are pinned.
#[test]
fn pck_collateral_params_surface_is_stable() {
    let case = load_case("prod-1");
    let mut cursor: &[u8] = &case.quote_bytes;
    let quote = SgxQuote::read(&mut cursor).expect("prod-1 quote parses");

    let (fmspc, ca): ([u8; 6], PckCa) =
        pck_collateral_params(&quote).expect("prod-1 selectors readable");
    assert_eq!(fmspc.len(), 6);
    assert_eq!(ca, PckCa::Processor);
    assert_eq!(ca.as_str(), "processor");
    assert_eq!(PckCa::Platform.as_str(), "platform");
}
