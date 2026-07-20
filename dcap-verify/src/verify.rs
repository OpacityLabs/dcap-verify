//! The verification pipeline behind [`verify_remote_attestation`]. The order of
//! the checks is load-bearing — see the comments at each gate.

use std::time::SystemTime;

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::TcbStanding;
use crate::error::{ErrorCategory, VerifyError};
use crate::pki::{self, CertChain, ChainKind};
use crate::tcb;
use crate::types::collateral::SgxCollateral;
use crate::types::quote::SgxQuote;
use crate::types::report::{MREnclave, SgxReportBody};

/// Verify a DCAP v3 SGX quote against PCS v4 collateral at `current_time`, pinning
/// `expected_mrenclave`. On success returns the platform's TCB standing and the verified
/// report body. On rejection returns a [`crate::error::VerifyError`], whose
/// [`VerifyError::category`] classifies the failure.
///
/// `min_tcb_evaluation_data_number` is a caller-supplied freshness floor: collateral
/// whose tcbInfo or QE identity comes from an Intel TCB evaluation round below it is
/// rejected as stale even inside its nextUpdate window, closing the round-downgrade
/// window after a TCB recovery. Pass 0 to accept any round.
pub fn verify_remote_attestation(
    current_time: SystemTime,
    collateral: SgxCollateral,
    quote: SgxQuote,
    expected_mrenclave: &MREnclave,
    min_tcb_evaluation_data_number: u32,
) -> Result<(TcbStanding, SgxReportBody), VerifyError> {
    let now = unix_seconds(current_time);

    if quote.header.qe_vendor_id != pki::INTEL_QE_VENDOR_ID {
        return Err(VerifyError::new(
            ErrorCategory::QeVendorInvalid,
            format!(
                "quote names QE vendor {}, only Intel's QE ({}) is accepted",
                hex::encode(quote.header.qe_vendor_id),
                hex::encode(pki::INTEL_QE_VENDOR_ID)
            ),
        ));
    }

    // Cheapest self-contained identity gate first: a wrong measurement is rejected
    // without touching the collateral-heavy chain/TCB work. The DEBUG gate cannot
    // move this early — several negative fixtures are debug-mode captures that must
    // reject for their specific mutation's reason, so DEBUG stays after the
    // signature checks (see the gate near the end of this function).
    if quote.report_body.mrenclave != *expected_mrenclave {
        return Err(VerifyError::new(
            ErrorCategory::MrenclaveMismatch,
            format!(
                "report measures {}, caller pinned {}",
                hex::encode(quote.report_body.mrenclave),
                hex::encode(expected_mrenclave)
            ),
        ));
    }

    // Fail-closed document-format gates: reject any collateral
    // whose declared versions/algorithm are not exactly what this verifier was
    // written for, before deriving any status from the documents.
    check_document_formats(&collateral)?;

    let tcb_info_chain = CertChain::from_pem(
        ChainKind::TcbInfoIssuer,
        collateral.tcb_info_issuer_chain.as_bytes(),
    )?;
    let pck_crl_chain = CertChain::from_pem(
        ChainKind::PckCrlIssuer,
        collateral.pck_crl_issuer_chain.as_bytes(),
    )?;
    let qe_identity_chain = CertChain::from_pem(
        ChainKind::QeIdentityIssuer,
        collateral.qe_identity_issuer_chain.as_bytes(),
    )?;
    let pck_chain = CertChain::from_pem(ChainKind::QuotePck, &quote.signature.cert_data)?;

    // Parse each chain's DER exactly once and reuse the parsed certs across every
    // check below (efficiency note: the entry point runs inside a mobile TLS
    // handshake).
    let tcb_info_chain = tcb_info_chain.parse()?;
    let pck_crl_chain = pck_crl_chain.parse()?;
    let qe_identity_chain = qe_identity_chain.parse()?;
    let pck_chain = pck_chain.parse()?;
    let chains = [
        &tcb_info_chain,
        &pck_crl_chain,
        &qe_identity_chain,
        &pck_chain,
    ];
    for chain in chains {
        chain.validate(now)?;
    }

    // Signer-identity pinning: the leaves that sign tcbInfo and
    // enclaveIdentity must be Intel's dedicated "Intel SGX TCB Signing" cert, not
    // merely some leaf that chains to the root.
    require_tcb_signing_leaf(&tcb_info_chain, "TCB info")?;
    require_tcb_signing_leaf(&qe_identity_chain, "QE identity")?;

    // The PCK CRL only covers revocations issued by the CA that signed the quote's PCK
    // certificate. Intel operates two sibling PCK CAs (Processor and Platform), each with
    // its own CRL, so the supplied PCK CRL issuer chain must terminate at the exact CA that
    // issued this quote's PCK leaf — otherwise a genuine-but-unrelated sibling CRL could be
    // substituted and the leaf's revocation would silently never apply.
    let pck_leaf_issuer = pck_chain.leaf_issuer_raw();
    if pck_crl_chain.leaf_subject_raw() != pck_leaf_issuer {
        return Err(VerifyError::new(
            ErrorCategory::CrlInvalid,
            "PCK CRL issuer chain does not terminate at the CA that issued the quote's PCK certificate",
        ));
    }

    let root_key = pki::pinned_root_key();
    let mut revoked = pki::check_crl(
        "root CA CRL",
        collateral.root_ca_crl.as_bytes(),
        &pck_chain.root_subject_raw(),
        &root_key,
        now,
    )?;
    revoked.extend(pki::check_crl(
        "PCK CRL",
        collateral.pck_crl.as_bytes(),
        &pck_leaf_issuer,
        &pck_crl_chain.leaf_verifying_key()?,
        now,
    )?);
    pki::ensure_none_revoked(&chains, &revoked)?;

    let tcb_info = &collateral.tcb_info;
    verify_raw_hex_signature(
        &tcb_info_chain.leaf_verifying_key()?,
        tcb_info.body_json.as_bytes(),
        &tcb_info.signature_hex,
    )
    .map_err(|d| VerifyError::new(ErrorCategory::TcbInfoSignatureInvalid, d))?;
    if tcb_info.body.id != "SGX" {
        return Err(VerifyError::new(
            ErrorCategory::CollateralParse,
            format!("TCB info is for '{}', expected SGX", tcb_info.body.id),
        ));
    }
    check_validity_window(
        "TCB info",
        tcb_info.body.issue_date.timestamp(),
        tcb_info.body.next_update.timestamp(),
        now,
        ErrorCategory::TcbInfoStale,
    )?;
    check_evaluation_round(
        "TCB info",
        tcb_info.body.tcb_evaluation_data_number,
        min_tcb_evaluation_data_number,
        ErrorCategory::TcbInfoStale,
    )?;

    let qe_identity = &collateral.qe_identity;
    verify_raw_hex_signature(
        &qe_identity_chain.leaf_verifying_key()?,
        qe_identity.body_json.as_bytes(),
        &qe_identity.signature_hex,
    )
    .map_err(|d| VerifyError::new(ErrorCategory::QeIdentitySignatureInvalid, d))?;
    check_validity_window(
        "QE identity",
        qe_identity.body.issue_date.timestamp(),
        qe_identity.body.next_update.timestamp(),
        now,
        ErrorCategory::QeIdentityStale,
    )?;
    check_evaluation_round(
        "QE identity",
        qe_identity.body.tcb_evaluation_data_number,
        min_tcb_evaluation_data_number,
        ErrorCategory::QeIdentityStale,
    )?;
    tcb::check_qe_identity(&qe_identity.body, &quote.signature.qe_report)?;

    let pck_leaf_key = pck_chain.leaf_verifying_key()?;
    let qe_report_sig =
        Signature::from_slice(&quote.signature.qe_report_signature).map_err(|e| {
            VerifyError::new(
                ErrorCategory::QeReportSignatureInvalid,
                format!("undecodable signature: {e}"),
            )
        })?;
    pck_leaf_key
        .verify(&quote.signature.qe_report_raw, &qe_report_sig)
        .map_err(|_| {
            VerifyError::new(
                ErrorCategory::QeReportSignatureInvalid,
                "QE report was not signed by the platform's PCK key".to_string(),
            )
        })?;

    let mut hasher = Sha256::new();
    hasher.update(quote.signature.attestation_pub_key);
    hasher.update(&quote.signature.qe_auth_data);
    let binding = hasher.finalize();
    let qe_report_data = &quote.signature.qe_report.sgx_report_data_bytes;
    if qe_report_data[..32] != binding[..] || qe_report_data[32..] != [0u8; 32] {
        return Err(VerifyError::new(
            ErrorCategory::QeBindingInvalid,
            "QE report data does not commit to the attestation key and auth data".to_string(),
        ));
    }

    let mut attestation_key_sec1 = [0u8; 65];
    attestation_key_sec1[0] = 0x04;
    attestation_key_sec1[1..].copy_from_slice(&quote.signature.attestation_pub_key);
    let attestation_key = VerifyingKey::from_sec1_bytes(&attestation_key_sec1).map_err(|e| {
        VerifyError::new(
            ErrorCategory::QuoteSignatureInvalid,
            format!("attestation public key is not a usable P-256 point: {e}"),
        )
    })?;
    let quote_sig = Signature::from_slice(&quote.signature.isv_signature).map_err(|e| {
        VerifyError::new(
            ErrorCategory::QuoteSignatureInvalid,
            format!("undecodable signature: {e}"),
        )
    })?;
    attestation_key
        .verify(quote.signed_bytes(), &quote_sig)
        .map_err(|_| {
            VerifyError::new(
                ErrorCategory::QuoteSignatureInvalid,
                "quote header and report body were not signed by the attestation key".to_string(),
            )
        })?;

    // DEBUG gate: kept after the signature/identity checks above because several
    // negative fixtures are debug-mode captures whose recorded rejection category
    // is their specific mutation (bad signature, tampered document, …), which must
    // win over the debug attribute. Every check still runs regardless of order.
    if quote.report_body.is_debug() {
        return Err(VerifyError::new(
            ErrorCategory::DebugEnclaveRejected,
            format!(
                "report attributes {} carry the DEBUG flag",
                hex::encode(quote.report_body.attributes)
            ),
        ));
    }

    let platform_tcb = pki::extract_pck_platform_tcb(&pck_chain)?;
    let standing = tcb::platform_standing(&tcb_info.body, &platform_tcb)?;

    Ok((standing, quote.report_body))
}

/// Fail-closed document-format gates. Each field must be present
/// (the deserializer guarantees that) and equal the exact value this verifier was
/// built for; any other value is a rejection, never a best-effort evaluation.
fn check_document_formats(collateral: &SgxCollateral) -> Result<(), VerifyError> {
    if collateral.version != 3 {
        return Err(VerifyError::new(
            ErrorCategory::CollateralParse,
            format!(
                "collateral is version {}, only version 3 is supported",
                collateral.version
            ),
        ));
    }
    let tcb_version = collateral.tcb_info.body.version;
    if tcb_version != 3 {
        return Err(VerifyError::new(
            ErrorCategory::CollateralParse,
            format!("tcbInfo is version {tcb_version}, only version 3 is supported"),
        ));
    }
    let qe_version = collateral.qe_identity.body.version;
    if qe_version != 2 {
        return Err(VerifyError::new(
            ErrorCategory::CollateralParse,
            format!("enclaveIdentity is version {qe_version}, only version 2 is supported"),
        ));
    }
    let tcb_type = collateral.tcb_info.body.tcb_type;
    if tcb_type != 0 {
        return Err(VerifyError::new(
            ErrorCategory::CollateralParse,
            format!(
                "tcbInfo declares tcbType {tcb_type}; only type 0 (the component-wise SVN comparison) is supported"
            ),
        ));
    }
    Ok(())
}

/// Signer-identity pin: the document-signing leaf must be Intel's
/// dedicated "Intel SGX TCB Signing" certificate.
fn require_tcb_signing_leaf(chain: &pki::ParsedChain, document: &str) -> Result<(), VerifyError> {
    let cn = chain.leaf_common_name()?;
    if cn != pki::INTEL_TCB_SIGNING_CN {
        return Err(VerifyError::new(
            ErrorCategory::RootCaUntrusted,
            format!(
                "{document} is signed by a leaf named '{cn}', not Intel's dedicated '{}' certificate",
                pki::INTEL_TCB_SIGNING_CN
            ),
        ));
    }
    Ok(())
}

/// Validity-window check for a signed collateral document: reject both when it
/// is stale (now >= `nextUpdate`, matching Intel's QVL expiry boundary) and
/// when it is not yet valid (`issueDate` > now; the document is valid from its
/// issue instant). Both bounds map to the document's own staleness category.
fn check_validity_window(
    document: &str,
    issue_date: i64,
    next_update: i64,
    now: i64,
    stale: ErrorCategory,
) -> Result<(), VerifyError> {
    if next_update <= now {
        return Err(VerifyError::new(
            stale,
            format!("{document} expired at unix {next_update}, verification time is {now}"),
        ));
    }
    if issue_date > now {
        return Err(VerifyError::new(
            stale,
            format!("{document} is not valid until unix {issue_date}, verification time is {now}"),
        ));
    }
    Ok(())
}

fn check_evaluation_round(
    document: &str,
    round: u32,
    minimum: u32,
    stale: ErrorCategory,
) -> Result<(), VerifyError> {
    if round < minimum {
        return Err(VerifyError::new(
            stale,
            format!(
                "{document} is from TCB evaluation round {round}, caller requires at least {minimum}"
            ),
        ));
    }
    Ok(())
}

fn verify_raw_hex_signature(
    key: &VerifyingKey,
    message: &[u8],
    signature_hex: &str,
) -> Result<(), String> {
    let sig_bytes =
        hex::decode(signature_hex).map_err(|e| format!("signature is not valid hex: {e}"))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| format!("signature is not a 64-byte P-256 signature: {e}"))?;
    key.verify(message, &sig)
        .map_err(|_| "signature does not match the signed document body".to_string())
}

fn unix_seconds(t: SystemTime) -> i64 {
    match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_secs()).unwrap_or(i64::MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The document validity window rejects on both sides of the
    // window and accepts strictly inside it — identical logic for tcbInfo and QE
    // identity, which is why the end-to-end lower-bound coverage lives on the
    // tcbInfo path only (see tests/conformance.rs).
    #[test]
    fn validity_window_rejects_both_bounds() {
        for stale in [ErrorCategory::TcbInfoStale, ErrorCategory::QeIdentityStale] {
            // issue = 100, nextUpdate = 200. Valid on [issueDate, nextUpdate):
            // the issue instant is in, the expiry instant is out.
            assert!(check_validity_window("doc", 100, 200, 150, stale).is_ok());
            assert!(check_validity_window("doc", 100, 200, 100, stale).is_ok()); // issue == now
            assert!(check_validity_window("doc", 100, 200, 199, stale).is_ok()); // last second inside

            // Not yet valid: now < issueDate. Stale: now >= nextUpdate, including
            // the exact expiry instant — both use the document's own category.
            let not_yet = check_validity_window("doc", 100, 200, 99, stale).unwrap_err();
            let at_expiry = check_validity_window("doc", 100, 200, 200, stale).unwrap_err();
            let expired = check_validity_window("doc", 100, 200, 201, stale).unwrap_err();
            assert_eq!(not_yet.category, stale);
            assert_eq!(at_expiry.category, stale);
            assert_eq!(expired.category, stale);
        }
    }

    // Pre-epoch verification times map to negative seconds; a clock set before
    // 1970 must not alias into valid positive time.
    #[test]
    fn unix_seconds_is_negative_before_the_epoch() {
        use std::time::Duration;
        let epoch = SystemTime::UNIX_EPOCH;
        assert_eq!(unix_seconds(epoch + Duration::from_secs(5)), 5);
        assert_eq!(unix_seconds(epoch - Duration::from_secs(5)), -5);
    }

    // The evaluation-round floor is inclusive at the minimum and disabled at 0 —
    // identical logic for both documents, each rejecting under its own category.
    #[test]
    fn evaluation_round_floor_is_inclusive_and_zero_disables() {
        for stale in [ErrorCategory::TcbInfoStale, ErrorCategory::QeIdentityStale] {
            assert!(check_evaluation_round("doc", 19, 0, stale).is_ok());
            assert!(check_evaluation_round("doc", 19, 19, stale).is_ok());
            let err = check_evaluation_round("doc", 19, 20, stale).unwrap_err();
            assert_eq!(err.category, stale);
        }
    }

    #[test]
    fn validity_window_uses_the_documents_own_category() {
        let tcb = check_validity_window("tcbInfo", 100, 200, 99, ErrorCategory::TcbInfoStale)
            .unwrap_err();
        assert_eq!(tcb.category, ErrorCategory::TcbInfoStale);
        let qe =
            check_validity_window("QE", 100, 200, 99, ErrorCategory::QeIdentityStale).unwrap_err();
        assert_eq!(qe.category, ErrorCategory::QeIdentityStale);
    }
}
