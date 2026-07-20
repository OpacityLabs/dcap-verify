mod common;

use common::{FixtureCase, all_case_names, category_of, load_case};
use dcap_verify::{SgxCollateral, SgxQuote, TcbStanding, verify_remote_attestation};

// Every committed fixture case, pinned by name so an accidental deletion fails
// loud. New cases are auto-discovered and run without being listed, but add
// them here so they are protected too.
const REQUIRED_CASES: &[&str] = &[
    "attest-pubkey-bitflip",
    "attributes-debug-bit-cleared",
    "base-debug-enclave",
    "collateral-truncated",
    "isv-signature-bitflip",
    "prod-1",
    "prod-1-stale-qe-evaluation",
    "prod-1-stale-tcb-evaluation",
    "prod-1-time-far-future",
    "prod-1-wrong-mrenclave",
    "qe-auth-data-bitflip",
    "qe-identity-tampered",
    "qe-report-signature-bitflip",
    "qe-vendor-id-flip",
    "quote-att-key-type-1",
    "quote-cert-data-type-1",
    "quote-sig-section-slack",
    "quote-truncated",
    "quote-version-4",
    "tcb-info-tampered",
    "tcb-info-wrong-fmspc",
    "time-far-future",
    "time-far-past",
    "wrong-mrenclave",
];

enum Outcome {
    Accept(TcbStanding),
    Reject { category: String, message: String },
}

fn run_case(case: &FixtureCase) -> Outcome {
    let collateral: SgxCollateral = match serde_json::from_slice(&case.collateral_bytes) {
        Ok(c) => c,
        Err(e) => {
            return Outcome::Reject {
                category: "collateral-parse-error".to_string(),
                message: e.to_string(),
            };
        }
    };

    let mut cursor: &[u8] = &case.quote_bytes;
    let quote = match SgxQuote::read(&mut cursor) {
        Ok(q) => q,
        Err(e) => {
            return Outcome::Reject {
                category: category_of(&e).as_str().to_string(),
                message: e.to_string(),
            };
        }
    };

    match verify_remote_attestation(
        case.current_time,
        collateral,
        quote,
        &case.mrenclave,
        case.min_tcb_evaluation_data_number,
    ) {
        Ok((standing, _report)) => Outcome::Accept(standing),
        Err(e) => Outcome::Reject {
            category: category_of(&e).as_str().to_string(),
            message: e.to_string(),
        },
    }
}

#[test]
fn fixture_oracle() {
    let names = all_case_names();
    let mut failures: Vec<String> = Vec::new();

    for name in &names {
        let case = load_case(name);
        match (case.verdict.as_str(), run_case(&case)) {
            ("accept", Outcome::Accept(standing)) => {
                let got = serde_json::to_value(&standing).expect("standing serializable");
                let expected = case.tcb_standing.clone().unwrap_or(serde_json::Value::Null);
                if got != expected {
                    failures.push(format!(
                        "{name}: accepted with standing {got}, oracle expects {expected}"
                    ));
                }
            }
            ("accept", Outcome::Reject { category, message }) => {
                failures.push(format!(
                    "{name}: expected accept, got rejection [{category}] {message}"
                ));
            }
            ("reject", Outcome::Accept(standing)) => {
                failures.push(format!(
                    "{name}: expected rejection [{}], got accept with {standing:?}",
                    case.category.as_deref().unwrap_or("?")
                ));
            }
            ("reject", Outcome::Reject { category, message }) => {
                let expected = case.category.as_deref().unwrap_or("?");
                if category != expected {
                    failures.push(format!(
                        "{name}: expected rejection [{expected}], got [{category}] {message}"
                    ));
                }
            }
            (other, _) => {
                failures.push(format!("{name}: unknown verdict '{other}' in meta.json"));
            }
        }
    }

    let missing: Vec<&&str> = REQUIRED_CASES
        .iter()
        .filter(|required| !names.iter().any(|n| n == **required))
        .collect();
    assert!(
        missing.is_empty(),
        "fixture cases missing from the corpus: {missing:?} — accidentally deleted?"
    );
    assert!(
        failures.is_empty(),
        "{} of {} fixture cases diverged from the oracle:\n{}",
        failures.len(),
        names.len(),
        failures.join("\n")
    );
}
