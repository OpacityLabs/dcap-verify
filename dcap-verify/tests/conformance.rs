//! Targeted tests for verifier requirements the frozen fixtures cannot stress
//! (document-format gates, X.509 path role constraints, signer-identity pinning,
//! the outer signatureAlgorithm ↔ inner copy agreement, and the validity-window
//! bounds on both edges). Each builds a minimally-mutated prod-1 collateral so a
//! bug in these checks — which would still pass the oracle — is caught here.
mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::{category_of, cert_blocks, load_case};
use dcap_verify::{ErrorCategory, SgxCollateral, SgxQuote, verify_remote_attestation};
use serde_json::Value;

/// prod-1 collateral as mutable JSON, plus the parsed quote and case inputs.
struct Harness {
    collateral: Value,
    quote_bytes: Vec<u8>,
    mrenclave: [u8; 32],
    current_time: SystemTime,
    min_eval: u32,
}

fn harness() -> Harness {
    let case = load_case("prod-1");
    Harness {
        collateral: serde_json::from_slice(&case.collateral_bytes).expect("collateral json"),
        quote_bytes: case.quote_bytes,
        mrenclave: case.mrenclave,
        current_time: case.current_time,
        min_eval: 0,
    }
}

impl Harness {
    /// Run verification with the (possibly mutated) collateral and return the
    /// rejection category, asserting the run did not accept.
    fn expect_reject(self) -> ErrorCategory {
        let collateral: SgxCollateral =
            serde_json::from_value(self.collateral).expect("mutated collateral still deserializes");
        let mut cursor: &[u8] = &self.quote_bytes;
        let quote = SgxQuote::read(&mut cursor).expect("prod-1 quote parses");
        let err = verify_remote_attestation(
            self.current_time,
            collateral,
            quote,
            &self.mrenclave,
            self.min_eval,
        )
        .expect_err("mutation must be rejected, not accepted");
        category_of(&err)
    }

    /// Run verification and assert it accepts.
    fn expect_accept(self) {
        let collateral: SgxCollateral =
            serde_json::from_value(self.collateral).expect("collateral deserializes");
        let mut cursor: &[u8] = &self.quote_bytes;
        let quote = SgxQuote::read(&mut cursor).expect("prod-1 quote parses");
        verify_remote_attestation(
            self.current_time,
            collateral,
            quote,
            &self.mrenclave,
            self.min_eval,
        )
        .expect("case must accept");
    }

    fn at_time(mut self, unix: u64) -> Self {
        self.current_time = UNIX_EPOCH + Duration::from_secs(unix);
        self
    }

    fn tcb_evaluation_round(&self) -> u32 {
        self.collateral["tcb_info"]["tcbInfo"]["tcbEvaluationDataNumber"]
            .as_u64()
            .expect("tcbEvaluationDataNumber") as u32
    }
}

// Baseline: unmutated prod-1 accepts, so any rejection below is caused by the
// mutation under test, not a broken harness.
#[test]
fn baseline_prod1_accepts() {
    let h = harness();
    let collateral: SgxCollateral =
        serde_json::from_value(h.collateral).expect("collateral deserializes");
    let mut cursor: &[u8] = &h.quote_bytes;
    let quote = SgxQuote::read(&mut cursor).expect("quote parses");
    assert!(
        verify_remote_attestation(h.current_time, collateral, quote, &h.mrenclave, 0).is_ok(),
        "unmutated prod-1 must accept"
    );
}

// ---- Evaluation-round floor ----
// A floor one round above the collateral's own evaluation round must reject it
// as stale even though its nextUpdate window is satisfied, while a floor at
// exactly its round must not change the accept.

#[test]
fn evaluation_round_below_floor_is_rejected_as_stale() {
    let mut h = harness();
    h.min_eval = h.tcb_evaluation_round() + 1;
    assert_eq!(h.expect_reject(), ErrorCategory::TcbInfoStale);
}

#[test]
fn evaluation_round_at_floor_still_accepts() {
    let mut h = harness();
    h.min_eval = h.tcb_evaluation_round();
    h.expect_accept();
}

// ---- Document-format gates ----

#[test]
fn collateral_version_not_3_is_rejected() {
    let mut h = harness();
    h.collateral["version"] = Value::from(4);
    assert_eq!(h.expect_reject(), ErrorCategory::CollateralParse);
}

#[test]
fn tcb_info_version_not_3_is_rejected() {
    let mut h = harness();
    // tcbInfo body is a raw sub-object; mutate the inner version field.
    h.collateral["tcb_info"]["tcbInfo"]["version"] = Value::from(4);
    assert_eq!(h.expect_reject(), ErrorCategory::CollateralParse);
}

#[test]
fn tcb_info_version_2_is_rejected_by_the_format_gate() {
    // A v2-labeled document must die at the format gate, not limp on to the
    // signature check: the TcbPlatform type only parses the v3 shape, so a v2
    // label can only ever sit on a v3-shaped body — reject it fail-closed.
    let mut h = harness();
    h.collateral["tcb_info"]["tcbInfo"]["version"] = Value::from(2);
    assert_eq!(h.expect_reject(), ErrorCategory::CollateralParse);
}

#[test]
fn enclave_identity_version_not_2_is_rejected() {
    let mut h = harness();
    h.collateral["qe_identity"]["enclaveIdentity"]["version"] = Value::from(3);
    assert_eq!(h.expect_reject(), ErrorCategory::CollateralParse);
}

#[test]
fn tcb_type_not_0_is_rejected() {
    let mut h = harness();
    h.collateral["tcb_info"]["tcbInfo"]["tcbType"] = Value::from(1);
    assert_eq!(h.expect_reject(), ErrorCategory::CollateralParse);
}

// A format gate must fire BEFORE any document processing. This is a genuine
// ordering discriminator: the substituted TCB-info issuer chain alone yields
// `root-ca-untrusted` (proven by `non_tcb_signing_leaf_for_tcb_info_is_rejected`),
// so adding the bad collateral version and still seeing `collateral-parse-error`
// proves the format gate ran before the chain/signer work — not the reverse.
#[test]
fn format_gate_precedes_document_processing() {
    let mut h = harness();
    let pck_crl_chain = h.collateral["pck_crl_issuer_chain"].clone();
    h.collateral["tcb_info_issuer_chain"] = pck_crl_chain; // alone → root-ca-untrusted
    h.collateral["version"] = Value::from(99); // format gate must win → collateral-parse-error
    assert_eq!(h.expect_reject(), ErrorCategory::CollateralParse);
}

// ---- issueDate not-yet-valid lower bound ----

// prod-1's certs and both CRLs are valid at unix 1783470600 (2026-07-08 00:30Z),
// but that is before tcbInfo.issueDate (00:45Z) and qe.issueDate (00:16Z is
// earlier, so tcbInfo is the one that trips). A verifier lacking the lower-bound
// check would accept; it must reject as tcb-info-stale.
#[test]
fn tcb_info_not_yet_valid_is_rejected() {
    let cat = harness().at_time(1783470600).expect_reject();
    assert_eq!(cat, ErrorCategory::TcbInfoStale);
}

// The QE-identity issueDate lower bound cannot be isolated end-to-end (its window
// check runs after its own signature, and any issueDate mutation breaks that
// signature first). The bound itself — symmetric for both documents — is proven by
// the `check_validity_window` unit tests in the library. Here we only guard that
// verification proceeds past a valid tcbInfo window to the QE-identity stage at a
// time before the (unmutated) qe.issueDate would matter, i.e. the tcbInfo lower
// bound above is what a not-yet-valid collateral trips first.

// ---- Path role constraints and signer-identity pin ----

// Substitute the TCB-info issuer chain with the PCK-CRL issuer chain
// [Intel SGX PCK Processor CA, Intel SGX Root CA]. That chain validates fully — it
// terminates at the pinned root, links correctly, and its issuers are CAs — but its
// leaf is "Intel SGX PCK Processor CA", not the pinned "Intel SGX TCB Signing"
// identity. This isolates the signer-identity pin: the chain passes path validation
// and is rejected solely because the signing leaf is the wrong identity.
#[test]
fn non_tcb_signing_leaf_for_tcb_info_is_rejected() {
    let mut h = harness();
    let pck_crl_chain = h.collateral["pck_crl_issuer_chain"].clone();
    h.collateral["tcb_info_issuer_chain"] = pck_crl_chain;
    assert_eq!(h.expect_reject(), ErrorCategory::RootCaUntrusted);
}

// Same substitution for the QE-identity issuer chain.
#[test]
fn non_tcb_signing_leaf_for_qe_identity_is_rejected() {
    let mut h = harness();
    let pck_crl_chain = h.collateral["pck_crl_issuer_chain"].clone();
    h.collateral["qe_identity_issuer_chain"] = pck_crl_chain;
    assert_eq!(h.expect_reject(), ErrorCategory::RootCaUntrusted);
}

// A single self-signed leaf presented as its own issuer: not the pinned root key,
// so the anchor check rejects before any CA-role logic.
#[test]
fn chain_not_terminating_at_pinned_root_is_rejected() {
    let mut h = harness();
    let tcb_chain = h.collateral["tcb_info_issuer_chain"].as_str().unwrap();
    let leaf = cert_blocks(tcb_chain)
        .into_iter()
        .next()
        .expect("leaf block");
    // Leaf alone: it is not self-signed by the pinned root key.
    h.collateral["tcb_info_issuer_chain"] = Value::from(leaf);
    assert_eq!(h.expect_reject(), ErrorCategory::RootCaUntrusted);
}

// A chain longer than the sane cap is rejected before unbounded signature work.
#[test]
fn oversized_chain_is_rejected() {
    let mut h = harness();
    let tcb_chain = h.collateral["tcb_info_issuer_chain"].as_str().unwrap();
    let blocks = cert_blocks(tcb_chain);
    let leaf = &blocks[0];
    // 11 copies of the leaf then the genuine chain — over the cap of 10.
    let mut oversized = leaf.repeat(11);
    oversized.push_str(tcb_chain);
    h.collateral["tcb_info_issuer_chain"] = Value::from(oversized);
    assert_eq!(h.expect_reject(), ErrorCategory::CollateralParse);
}

// ---- The outer signatureAlgorithm of every certificate and CRL must be
// well-formed and equal the inner signed copy ----
//
// Certificate and CertificateList share the outer DER shape
// `SEQUENCE { tbs, signatureAlgorithm, signatureValue }`, and the outer
// signatureAlgorithm is the one field a signature never covers. The helpers below
// rewrite exactly that element, leaving the tbs bytes — and therefore every
// signature — intact.

/// Length of a DER header at `pos` and of the content it announces.
fn der_header(bytes: &[u8], pos: usize) -> (usize, usize) {
    let len_byte = bytes[pos + 1];
    if len_byte < 0x80 {
        (2, usize::from(len_byte))
    } else {
        let n = usize::from(len_byte & 0x7f);
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | usize::from(bytes[pos + 2 + i]);
        }
        (2 + n, len)
    }
}

/// Byte range of the outer signatureAlgorithm element (the second element of the
/// outer SEQUENCE, right after the tbs).
fn outer_alg_range(der: &[u8]) -> std::ops::Range<usize> {
    let (h0, _) = der_header(der, 0);
    let (h1, c1) = der_header(der, h0);
    let alg_start = h0 + h1 + c1;
    let (h2, c2) = der_header(der, alg_start);
    alg_start..alg_start + h2 + c2
}

/// Rebuild the DER with the outer signatureAlgorithm replaced by `new_alg`,
/// re-encoding the enclosing SEQUENCE length.
fn replace_outer_alg(der: &[u8], new_alg: &[u8]) -> Vec<u8> {
    let range = outer_alg_range(der);
    let (h0, c0) = der_header(der, 0);
    let mut content = der[h0..range.start].to_vec();
    content.extend_from_slice(new_alg);
    content.extend_from_slice(&der[range.end..h0 + c0]);
    let mut out = vec![0x30];
    if content.len() < 0x80 {
        out.push(content.len() as u8);
    } else {
        let len_bytes: Vec<u8> = content
            .len()
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        out.push(0x80 | len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
    }
    out.extend_from_slice(&content);
    out
}

/// The document's outer algorithm with a NULL parameters element appended:
/// still a well-formed AlgorithmIdentifier carrying the same OID, but no longer
/// equal to the signed inner copy.
fn alg_with_null_params(der: &[u8]) -> Vec<u8> {
    let range = outer_alg_range(der);
    let alg = &der[range];
    let (h, c) = der_header(alg, 0);
    let mut inner = alg[h..h + c].to_vec();
    inner.extend([0x05, 0x00]);
    assert!(inner.len() < 0x80, "algorithm element stays short-form");
    let mut out = vec![0x30, inner.len() as u8];
    out.extend(inner);
    out
}

/// `SEQUENCE { NULL }` — correctly framed DER, but not a valid
/// AlgorithmIdentifier (no OID where one is mandatory). x509-parser normalizes
/// this shape to an AlgorithmIdentifier with an empty OID instead of failing,
/// so it is the outer↔inner agreement check that must reject it.
const MALFORMED_ALG: [u8; 4] = [0x30, 0x02, 0x05, 0x00];

/// A SEQUENCE announcing three content bytes with only two present: the element
/// overruns into the following signature field, so the document cannot parse.
const OVERRUN_ALG: [u8; 4] = [0x30, 0x03, 0x05, 0x00];

fn to_pem(tag: &str, der: Vec<u8>) -> String {
    ::pem::encode(&::pem::Pem::new(tag, der))
}

/// The prod-1 TCB-info issuer chain with its leaf's outer signatureAlgorithm
/// rewritten by `mutate`, the other certificates untouched.
fn tcb_chain_with_mutated_leaf_alg(h: &Harness, mutate: impl Fn(&[u8]) -> Vec<u8>) -> String {
    let chain = h.collateral["tcb_info_issuer_chain"]
        .as_str()
        .expect("tcb_info_issuer_chain");
    let blocks = cert_blocks(chain);
    let leaf_der = ::pem::parse(blocks[0].as_bytes())
        .expect("leaf pem")
        .into_contents();
    let mutated = replace_outer_alg(&leaf_der, &mutate(&leaf_der));
    let mut new_chain = to_pem("CERTIFICATE", mutated);
    for block in &blocks[1..] {
        new_chain.push_str(block);
    }
    new_chain
}

/// The prod-1 PCK CRL with its outer signatureAlgorithm rewritten by `mutate`.
fn pck_crl_with_mutated_alg(h: &Harness, mutate: impl Fn(&[u8]) -> Vec<u8>) -> String {
    let crl_pem = h.collateral["pck_crl"].as_str().expect("pck_crl");
    let block = ::pem::parse(crl_pem).expect("crl pem");
    let tag = block.tag().to_string();
    let der = block.into_contents();
    let mutated = replace_outer_alg(&der, &mutate(&der));
    to_pem(&tag, mutated)
}

// The mutated leaf keeps its OID and its untouched (still-verifying) signature —
// only the unsigned outer parameters differ from the signed inner copy. Without
// the outer↔inner agreement check exactly this shape would be accepted.
#[test]
fn cert_outer_alg_mismatching_inner_is_rejected() {
    let mut h = harness();
    h.collateral["tcb_info_issuer_chain"] =
        Value::from(tcb_chain_with_mutated_leaf_alg(&h, alg_with_null_params));
    assert_eq!(h.expect_reject(), ErrorCategory::RootCaUntrusted);
}

// A malformed outer field the parser happens to normalize (SEQUENCE { NULL }
// becomes an empty-OID AlgorithmIdentifier) must still reject: the normalized
// value cannot equal the signed inner copy.
#[test]
fn cert_malformed_outer_alg_is_rejected() {
    let mut h = harness();
    h.collateral["tcb_info_issuer_chain"] =
        Value::from(tcb_chain_with_mutated_leaf_alg(&h, |_| {
            MALFORMED_ALG.to_vec()
        }));
    assert_eq!(h.expect_reject(), ErrorCategory::RootCaUntrusted);
}

// A malformed outer field that breaks the DER framing fails the certificate
// parse — it is never skipped in favor of the hardcoded algorithms.
#[test]
fn cert_undecodable_outer_alg_is_rejected() {
    let mut h = harness();
    h.collateral["tcb_info_issuer_chain"] =
        Value::from(tcb_chain_with_mutated_leaf_alg(&h, |_| {
            OVERRUN_ALG.to_vec()
        }));
    assert_eq!(h.expect_reject(), ErrorCategory::CollateralParse);
}

// Same shapes on a CRL: the outer field disagreeing with the signed
// tbsCertList.signature copy rejects…
#[test]
fn crl_outer_alg_mismatching_inner_is_rejected() {
    let mut h = harness();
    h.collateral["pck_crl"] = Value::from(pck_crl_with_mutated_alg(&h, alg_with_null_params));
    assert_eq!(h.expect_reject(), ErrorCategory::CrlInvalid);
}

// …a parser-normalized malformed outer field rejects on the agreement check…
#[test]
fn crl_malformed_outer_alg_is_rejected() {
    let mut h = harness();
    h.collateral["pck_crl"] = Value::from(pck_crl_with_mutated_alg(&h, |_| MALFORMED_ALG.to_vec()));
    assert_eq!(h.expect_reject(), ErrorCategory::CrlInvalid);
}

// …and a framing-breaking one fails the CRL parse. Both land in the same
// category: every CRL defect is a crl-invalid rejection.
#[test]
fn crl_undecodable_outer_alg_is_rejected() {
    let mut h = harness();
    h.collateral["pck_crl"] = Value::from(pck_crl_with_mutated_alg(&h, |_| OVERRUN_ALG.to_vec()));
    assert_eq!(h.expect_reject(), ErrorCategory::CrlInvalid);
}

// ---- The expiry boundary is exclusive ----

fn crl_next_update_unix(pem: &str) -> i64 {
    use x509_parser::prelude::{CertificateRevocationList, FromDer};
    let block = ::pem::parse(pem).expect("crl pem");
    let (_, crl) = CertificateRevocationList::from_der(block.contents()).expect("crl der");
    crl.next_update().expect("nextUpdate present").timestamp()
}

fn rfc3339_unix(value: &Value) -> i64 {
    chrono::DateTime::parse_from_rfc3339(value.as_str().expect("date string"))
        .expect("RFC 3339 date")
        .timestamp()
}

fn chain_earliest_not_after_unix(pem: &str) -> i64 {
    use x509_parser::prelude::{FromDer, X509Certificate};
    cert_blocks(pem)
        .iter()
        .map(|block| {
            let der = ::pem::parse(block.as_bytes())
                .expect("cert pem")
                .into_contents();
            let (_, cert) = X509Certificate::from_der(&der).expect("cert der");
            cert.validity().not_after.timestamp()
        })
        .min()
        .expect("chain is non-empty")
}

// A collateral evaluated exactly at its earliest nextUpdate instant rejects,
// while one second before it accepts. prod-1's earliest-expiring dated item is
// its PCK CRL — asserted below over every dated item readable from the
// collateral, so a recapture that reorders the expiries fails loudly here
// instead of silently blunting the boundary probe. (The quote-embedded PCK
// chain cannot be read from the collateral JSON, but if any of its certificates
// expired earlier, the accept leg below would fail.)
#[test]
fn collateral_at_exact_next_update_rejects_one_second_before_accepts() {
    let h = harness();
    let pck_crl_next = crl_next_update_unix(h.collateral["pck_crl"].as_str().unwrap());
    let other_expiries = [
        crl_next_update_unix(h.collateral["root_ca_crl"].as_str().unwrap()),
        rfc3339_unix(&h.collateral["tcb_info"]["tcbInfo"]["nextUpdate"]),
        rfc3339_unix(&h.collateral["qe_identity"]["enclaveIdentity"]["nextUpdate"]),
        chain_earliest_not_after_unix(h.collateral["tcb_info_issuer_chain"].as_str().unwrap()),
        chain_earliest_not_after_unix(h.collateral["pck_crl_issuer_chain"].as_str().unwrap()),
        chain_earliest_not_after_unix(h.collateral["qe_identity_issuer_chain"].as_str().unwrap()),
    ];
    assert!(
        other_expiries.iter().all(|&t| pck_crl_next < t),
        "the PCK CRL must be prod-1's earliest-expiring dated item for this probe"
    );

    let boundary = u64::try_from(pck_crl_next).expect("nextUpdate after the epoch");
    harness().at_time(boundary - 1).expect_accept();
    assert_eq!(
        harness().at_time(boundary).expect_reject(),
        ErrorCategory::CertOrCrlTimeInvalid
    );
}
