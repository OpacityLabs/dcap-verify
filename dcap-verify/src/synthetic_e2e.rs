//! End-to-end pins for the two rejection call sites that no Intel-signed input
//! can ever exercise: a CRL revoking the quote's own PCK certificate, and a QE
//! identity contradicting the quote's QE report. Both run through the public
//! [`verify_remote_attestation`] over a synthetic PKI accepted via the
//! test-only anchor override in [`crate::pki`]. A control case proves the same
//! harness sails past both call sites and dies only at the QE-report signature
//! check (the real quote's QE report is signed by Intel's PCK key, not ours),
//! and a no-override case proves the synthetic chain cannot pass the anchor in
//! a normal build configuration.

use std::sync::LazyLock;
use std::time::{Duration, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType, IsCa, Issuer,
    KeyIdMethod, KeyPair, KeyUsagePurpose, RevokedCertParams, SerialNumber, date_time_ymd,
};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::error::ErrorCategory;
use crate::pki::TEST_ROOT_ANCHOR;
use crate::types::collateral::{SgxCollateral, Signed};
use crate::types::qe_identity::{QeIdentity, QeTcb, QeTcbLevel};
use crate::types::quote::SgxQuote;
use crate::types::report::SgxReportBody;
use crate::types::tcb_info::{TcbComponent, TcbInfo, TcbLevel, TcbPlatform};
use crate::{VerifyError, verify_remote_attestation};

const NOW_UNIX: u64 = 1_780_000_000; // 2026-05-29, inside every synthetic window
const DOC_ISSUE_UNIX: i64 = 1_767_225_600; // 2026-01-01
const DOC_NEXT_UNIX: i64 = 1_798_761_600; // 2027-01-01
const PCK_LEAF_SERIAL: &[u8] = &[0x5a, 0x01];
const UNRELATED_SERIAL: &[u8] = &[0x5a, 0x02];

struct TestPki {
    root_sec1: [u8; 65],
    quote_bytes: Vec<u8>,
    mrenclave: [u8; 32],
    qe_report: SgxReportBody,
    tcb_chain_pem: String,
    pck_crl_chain_pem: String,
    root_crl_pem: String,
    pck_crl_clean_pem: String,
    pck_crl_revoking_leaf_pem: String,
    doc_key: SigningKey,
}

static PKI: LazyLock<TestPki> = LazyLock::new(build_pki);

fn ca_params(cn: &str) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.distinguished_name.push(DnType::CommonName, cn);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}

fn crl(issuer: &Issuer<'_, KeyPair>, revoked_serial: &[u8]) -> String {
    CertificateRevocationListParams {
        this_update: date_time_ymd(2026, 1, 1),
        next_update: date_time_ymd(2027, 1, 1),
        crl_number: SerialNumber::from_slice(&[0x01]),
        issuing_distribution_point: None,
        revoked_certs: vec![RevokedCertParams {
            serial_number: SerialNumber::from_slice(revoked_serial),
            revocation_time: date_time_ymd(2026, 2, 1),
            reason_code: None,
            invalidity_date: None,
        }],
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(issuer)
    .expect("CRL")
    .pem()
    .expect("CRL PEM")
}

fn chain_pem(ders: &[&[u8]]) -> String {
    ders.iter()
        .map(|d| ::pem::encode(&::pem::Pem::new("CERTIFICATE", d.to_vec())))
        .collect()
}

// Quote v3 layout: the u32 signature-section length sits at 432 and the section
// starts at 436; within it, after the 64-byte ISV signature, 64-byte attestation
// key, 384-byte QE report, 64-byte QE report signature, u16+32-byte auth data,
// and u16 cert data type, the u32 cert data length sits at 1048 with the PEM
// chain at 1052 (same offsets as fixtures/tools/derive_fixtures.py).
fn splice_cert_data(orig: &[u8], chain: &str) -> Vec<u8> {
    let mut q = orig[..1052].to_vec();
    q[1048..1052].copy_from_slice(&(chain.len() as u32).to_le_bytes());
    q.extend_from_slice(chain.as_bytes());
    let sig_len = (q.len() - 436) as u32;
    q[432..436].copy_from_slice(&sig_len.to_le_bytes());
    q
}

fn build_pki() -> TestPki {
    let root_key = KeyPair::generate().expect("root key");
    let root_params = ca_params("dcap-verify synthetic Root CA");
    let root_der = root_params
        .self_signed(&root_key)
        .expect("root cert")
        .der()
        .to_vec();
    let root_issuer = Issuer::new(root_params, root_key);
    let (_, root_cert) = X509Certificate::from_der(&root_der).expect("root der");
    let root_sec1: [u8; 65] = root_cert
        .public_key()
        .subject_public_key
        .data
        .as_ref()
        .try_into()
        .expect("uncompressed P-256 point");

    let pck_ca_key = KeyPair::generate().expect("PCK CA key");
    let pck_ca_params = ca_params("dcap-verify synthetic PCK CA");
    let pck_ca_der = pck_ca_params
        .signed_by(&pck_ca_key, &root_issuer)
        .expect("PCK CA cert")
        .der()
        .to_vec();
    let pck_ca_issuer = Issuer::new(pck_ca_params, pck_ca_key);

    let pck_leaf_key = KeyPair::generate().expect("PCK leaf key");
    let mut pck_leaf_params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
    pck_leaf_params
        .distinguished_name
        .push(DnType::CommonName, "dcap-verify synthetic PCK leaf");
    pck_leaf_params.serial_number = Some(SerialNumber::from_slice(PCK_LEAF_SERIAL));
    let pck_leaf_der = pck_leaf_params
        .signed_by(&pck_leaf_key, &pck_ca_issuer)
        .expect("PCK leaf cert")
        .der()
        .to_vec();

    let tcb_key = KeyPair::generate().expect("TCB signing key");
    let mut tcb_params = CertificateParams::new(Vec::<String>::new()).expect("tcb params");
    tcb_params
        .distinguished_name
        .push(DnType::CommonName, crate::pki::INTEL_TCB_SIGNING_CN);
    let tcb_leaf_der = tcb_params
        .signed_by(&tcb_key, &root_issuer)
        .expect("TCB signing cert")
        .der()
        .to_vec();
    let doc_key = SigningKey::from_pkcs8_der(&tcb_key.serialize_der()).expect("PKCS#8 P-256 key");

    let root_crl_pem = crl(&root_issuer, UNRELATED_SERIAL);
    let pck_crl_clean_pem = crl(&pck_ca_issuer, UNRELATED_SERIAL);
    let pck_crl_revoking_leaf_pem = crl(&pck_ca_issuer, PCK_LEAF_SERIAL);

    let quote_chain = chain_pem(&[&pck_leaf_der, &pck_ca_der, &root_der]);
    let orig = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/prod-1/quote.bin"
    ))
    .expect("prod-1 quote.bin");
    let quote_bytes = splice_cert_data(&orig, &quote_chain);
    let mrenclave = *crate::peek_mrenclave(&quote_bytes).expect("mrenclave");
    let mut cursor: &[u8] = &quote_bytes;
    let qe_report = SgxQuote::read(&mut cursor)
        .expect("spliced quote parses")
        .signature
        .qe_report;

    TestPki {
        root_sec1,
        quote_bytes,
        mrenclave,
        qe_report,
        tcb_chain_pem: chain_pem(&[&tcb_leaf_der, &root_der]),
        pck_crl_chain_pem: chain_pem(&[&pck_ca_der, &root_der]),
        root_crl_pem,
        pck_crl_clean_pem,
        pck_crl_revoking_leaf_pem,
        doc_key,
    }
}

fn ts(unix: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(unix, 0).expect("valid timestamp")
}

fn sign_doc(key: &SigningKey, body_json: &str) -> String {
    let sig: Signature = key.sign(body_json.as_bytes());
    hex::encode(sig.to_bytes())
}

fn tcb_info(pki: &TestPki) -> Signed<TcbInfo> {
    let body = TcbInfo {
        id: "SGX".to_string(),
        version: 3,
        issue_date: ts(DOC_ISSUE_UNIX),
        next_update: ts(DOC_NEXT_UNIX),
        fmspc: "00a067110000".to_string(),
        pce_id: "0000".to_string(),
        tcb_type: 0,
        tcb_evaluation_data_number: 1,
        tcb_levels: vec![TcbLevel {
            tcb: TcbPlatform {
                sgxtcbcomponents: (0..16).map(|_| TcbComponent { svn: 0 }).collect(),
                pcesvn: 0,
            },
            tcb_date: ts(DOC_ISSUE_UNIX),
            tcb_status: "UpToDate".to_string(),
            advisory_ids: vec![],
        }],
    };
    let body_json = format!("{{\"synthetic-tcb-info\":{DOC_ISSUE_UNIX}}}");
    let signature_hex = sign_doc(&pki.doc_key, &body_json);
    Signed {
        body_json,
        body,
        signature_hex,
    }
}

fn qe_identity(pki: &TestPki, mrsigner_hex: String) -> Signed<QeIdentity> {
    let body = QeIdentity {
        id: "QE".to_string(),
        version: 2,
        issue_date: ts(DOC_ISSUE_UNIX),
        next_update: ts(DOC_NEXT_UNIX),
        tcb_evaluation_data_number: 1,
        miscselect: "00000000".to_string(),
        miscselect_mask: "00000000".to_string(),
        attributes: "00000000000000000000000000000000".to_string(),
        attributes_mask: "00000000000000000000000000000000".to_string(),
        mrsigner: mrsigner_hex,
        isvprodid: pki.qe_report.isv_prod_id,
        tcb_levels: vec![QeTcbLevel {
            tcb: QeTcb { isvsvn: 0 },
            tcb_date: ts(DOC_ISSUE_UNIX),
            tcb_status: "UpToDate".to_string(),
            advisory_ids: vec![],
        }],
    };
    let body_json = format!("{{\"synthetic-qe-identity\":{DOC_ISSUE_UNIX}}}");
    let signature_hex = sign_doc(&pki.doc_key, &body_json);
    Signed {
        body_json,
        body,
        signature_hex,
    }
}

fn collateral(pki: &TestPki, pck_crl: &str, qe: Signed<QeIdentity>) -> SgxCollateral {
    SgxCollateral {
        version: 3,
        root_ca_crl: pki.root_crl_pem.clone(),
        pck_crl: pck_crl.to_string(),
        tcb_info_issuer_chain: pki.tcb_chain_pem.clone(),
        pck_crl_issuer_chain: pki.pck_crl_chain_pem.clone(),
        qe_identity_issuer_chain: pki.tcb_chain_pem.clone(),
        tcb_info: tcb_info(pki),
        qe_identity: qe,
    }
}

fn run_with_anchor(pki: &TestPki, collateral: SgxCollateral) -> Result<(), VerifyError> {
    TEST_ROOT_ANCHOR.with(|c| c.set(Some(pki.root_sec1)));
    let out = run_without_anchor(pki, collateral);
    TEST_ROOT_ANCHOR.with(|c| c.set(None));
    out
}

fn run_without_anchor(pki: &TestPki, collateral: SgxCollateral) -> Result<(), VerifyError> {
    let mut cursor: &[u8] = &pki.quote_bytes;
    let quote = SgxQuote::read(&mut cursor).expect("spliced quote parses");
    let now = UNIX_EPOCH + Duration::from_secs(NOW_UNIX);
    verify_remote_attestation(now, collateral, quote, &pki.mrenclave, 0).map(|_| ())
}

fn matching_qe_identity(pki: &TestPki) -> Signed<QeIdentity> {
    qe_identity(pki, hex::encode(pki.qe_report.mrsigner))
}

// The call-site pin for `pki::ensure_none_revoked` in verify_remote_attestation:
// a CRL naming the quote's own PCK serial must reject through the entry point.
#[test]
fn revoked_pck_leaf_rejects_through_the_entry_point() {
    let pki = &*PKI;
    let c = collateral(
        pki,
        &pki.pck_crl_revoking_leaf_pem,
        matching_qe_identity(pki),
    );
    let err = run_with_anchor(pki, c).unwrap_err();
    assert_eq!(err.category, ErrorCategory::CrlInvalid);
    assert!(err.detail.contains("revoked"), "{}", err.detail);
}

// The call-site pin for `tcb::check_qe_identity` in verify_remote_attestation.
#[test]
fn qe_identity_mismatch_rejects_through_the_entry_point() {
    let pki = &*PKI;
    let c = collateral(
        pki,
        &pki.pck_crl_clean_pem,
        qe_identity(pki, "22".repeat(32)),
    );
    let err = run_with_anchor(pki, c).unwrap_err();
    assert_eq!(
        err.category,
        ErrorCategory::QeIdentityMismatch,
        "{}",
        err.detail
    );
}

// Control: with clean CRLs and a matching QE identity the synthetic harness
// passes both pinned call sites and fails only at the QE-report signature —
// proving the two tests above reject at their own gates, not incidentally.
#[test]
fn control_reaches_the_qe_report_signature_check() {
    let pki = &*PKI;
    let c = collateral(pki, &pki.pck_crl_clean_pem, matching_qe_identity(pki));
    let err = run_with_anchor(pki, c).unwrap_err();
    assert_eq!(
        err.category,
        ErrorCategory::QeReportSignatureInvalid,
        "{}",
        err.detail
    );
}

// Without the override the same synthetic input dies at the pinned Intel
// anchor: the hook is required for these tests and absent everywhere else.
#[test]
fn synthetic_chain_without_override_dies_at_the_anchor() {
    let pki = &*PKI;
    let c = collateral(pki, &pki.pck_crl_clean_pem, matching_qe_identity(pki));
    let err = run_without_anchor(pki, c).unwrap_err();
    assert_eq!(
        err.category,
        ErrorCategory::RootCaUntrusted,
        "{}",
        err.detail
    );
}
