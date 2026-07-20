mod common;

use common::{category_of, load_case};
use dcap_verify::types::report::MREnclave;
use dcap_verify::{
    ErrorCategory, SgxCollateral, SgxQuote, TcbPolicy, TcbStanding, verify_remote_attestation,
    verify_remote_attestation_with_policy,
};

fn prod_inputs() -> (
    std::time::SystemTime,
    SgxCollateral,
    SgxQuote,
    MREnclave,
    u32,
) {
    let case = load_case("prod-1");
    let collateral: SgxCollateral =
        serde_json::from_slice(&case.collateral_bytes).expect("collateral");
    let mut cursor: &[u8] = &case.quote_bytes;
    let quote = SgxQuote::read(&mut cursor).expect("prod-1 quote parses");
    (
        case.current_time,
        collateral,
        quote,
        case.mrenclave,
        case.min_tcb_evaluation_data_number,
    )
}

/// A permissive policy must reproduce `verify_remote_attestation`'s own result
/// exactly — same standing, same report body.
#[test]
fn with_policy_permissive_matches_plain_verification() {
    let (time, collateral, quote, mrenclave, floor) = prod_inputs();
    let policy = TcbPolicy {
        min_tcb_evaluation_data_number: floor,
        accept_sw_hardening_needed: true,
        accept_configuration_and_sw_hardening_needed: true,
    };
    let (standing, report_body) =
        verify_remote_attestation_with_policy(time, collateral, quote, &mrenclave, &policy)
            .expect("prod-1 accepts under a permissive policy");

    let (time, collateral, quote, mrenclave, floor) = prod_inputs();
    let (plain_standing, plain_report_body) =
        verify_remote_attestation(time, collateral, quote, &mrenclave, floor)
            .expect("prod-1 accepts");
    assert_eq!(standing, plain_standing);
    assert_eq!(
        report_body.sgx_report_data_bytes,
        plain_report_body.sgx_report_data_bytes
    );
    assert_eq!(report_body.mrenclave, plain_report_body.mrenclave);
}

/// prod-1's genuine standing is ConfigurationAndSWHardeningNeeded; a policy
/// that refuses it must reject with the `tcb-standing-rejected` category.
#[test]
fn with_policy_strict_rejects_degraded_standing() {
    let (time, collateral, quote, mrenclave, floor) = prod_inputs();
    let policy = TcbPolicy {
        min_tcb_evaluation_data_number: floor,
        accept_sw_hardening_needed: true,
        accept_configuration_and_sw_hardening_needed: false,
    };
    let err = verify_remote_attestation_with_policy(time, collateral, quote, &mrenclave, &policy)
        .expect_err("strict policy must reject prod-1's degraded standing");
    assert_eq!(category_of(&err), ErrorCategory::TcbStandingRejected);
    assert!(err.detail.contains("configuration-and-sw-hardening-needed"));
}

/// The policy's floor must actually reach verification: an impossible floor
/// rejects as stale collateral, not as a standing rejection.
#[test]
fn with_policy_forwards_the_evaluation_round_floor() {
    let (time, collateral, quote, mrenclave, _) = prod_inputs();
    let policy = TcbPolicy {
        min_tcb_evaluation_data_number: u32::MAX,
        accept_sw_hardening_needed: true,
        accept_configuration_and_sw_hardening_needed: true,
    };
    let err = verify_remote_attestation_with_policy(time, collateral, quote, &mrenclave, &policy)
        .expect_err("u32::MAX floor must reject");
    assert_eq!(category_of(&err), ErrorCategory::TcbInfoStale);
}

/// The check refusing a standing the pipeline never returns must not be
/// reachable through genuine acceptance: UpToDate always passes even the
/// all-false policy (pinned at the unit level too, but exercised here against
/// the public API surface).
#[test]
fn check_is_pure_and_reusable_on_returned_standings() {
    let (time, collateral, quote, mrenclave, floor) = prod_inputs();
    let (standing, _) = verify_remote_attestation(time, collateral, quote, &mrenclave, floor)
        .expect("prod-1 accepts");
    let strict = TcbPolicy {
        min_tcb_evaluation_data_number: floor,
        accept_sw_hardening_needed: false,
        accept_configuration_and_sw_hardening_needed: false,
    };
    let err = strict.check(&standing).expect_err("strict rejects prod-1");
    assert_eq!(category_of(&err), ErrorCategory::TcbStandingRejected);
    assert!(matches!(
        standing,
        TcbStanding::ConfigurationAndSWHardeningNeeded { .. }
    ));
}
