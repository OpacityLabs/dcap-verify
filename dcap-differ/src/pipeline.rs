use std::ffi::c_char;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dcap_verify::{
    ErrorCategory, SgxCollateral, SgxQuote, TcbStanding, peek_mrenclave, verify_remote_attestation,
};
use intel_tee_quote_verification_rs::{
    QuoteCollateral, quote3_error_t, sgx_ql_qv_result_t, tee_verify_quote,
};
use serde::Deserialize;
use serde_json::json;
use serde_json::value::RawValue;

// The default panic hook prints to stderr mid-sweep; capture the message instead
// so a dcap-verify panic becomes a reportable finding.
static LAST_PANIC: Mutex<Option<String>> = Mutex::new(None);

pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        *LAST_PANIC.lock().unwrap() = Some(info.to_string());
    }));
}

#[derive(Debug)]
pub enum DcapOutcome {
    Accept(TcbStanding),
    Reject {
        category: ErrorCategory,
        detail: String,
    },
    Panic(String),
}

impl DcapOutcome {
    pub fn label(&self) -> String {
        match self {
            Self::Accept(standing) => format!("accept({})", standing_slug(standing)),
            Self::Reject { category, .. } => format!("reject({})", category.as_str()),
            Self::Panic(_) => "panic".to_string(),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Self::Accept(standing) => json!({
                "kind": "accept",
                "standing": serde_json::to_value(standing).expect("TcbStanding serializes"),
            }),
            Self::Reject { category, detail } => json!({
                "kind": "reject",
                "category": category.as_str(),
                "detail": detail,
            }),
            Self::Panic(msg) => json!({ "kind": "panic", "msg": msg }),
        }
    }
}

fn standing_slug(standing: &TcbStanding) -> &'static str {
    match standing {
        TcbStanding::UpToDate => "up-to-date",
        TcbStanding::SWHardeningNeeded { .. } => "sw-hardening-needed",
        TcbStanding::ConfigurationAndSWHardeningNeeded { .. } => {
            "configuration-and-sw-hardening-needed"
        }
    }
}

#[derive(Debug)]
pub enum QvlOutcome {
    NotRun(String),
    Error(quote3_error_t),
    Verdict {
        exp_status: u32,
        result: sgx_ql_qv_result_t,
    },
}

impl QvlOutcome {
    pub fn label(&self) -> String {
        match self {
            Self::NotRun(reason) => format!("not-run({reason})"),
            Self::Error(code) => format!("err({code:?})"),
            Self::Verdict { exp_status, result } => format!("exp={exp_status} {result:?}"),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Self::NotRun(reason) => json!({ "kind": "not-run", "reason": reason }),
            Self::Error(code) => json!({ "kind": "error", "code": format!("{code:?}") }),
            Self::Verdict { exp_status, result } => json!({
                "kind": "verdict",
                "exp_status": exp_status,
                "result": format!("{result:?}"),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlForm {
    Pem,
    Der,
}

impl CrlForm {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pem => "pem",
            Self::Der => "der",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MarshalConfig {
    pub major: u16,
    pub minor: u16,
    pub tee_type: u32,
    pub crl_form: CrlForm,
}

impl MarshalConfig {
    pub fn label(&self) -> String {
        format!(
            "version={}.{} tee_type={} crl={}",
            self.major,
            self.minor,
            self.tee_type,
            self.crl_form.label()
        )
    }
}

// Chosen by `dcap-differ calibrate` on fixtures/prod-1: this cell yields
// SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED with exp_status == 0.
pub const DEFAULT_MARSHAL: MarshalConfig = MarshalConfig {
    major: 3,
    minor: 1,
    tee_type: 0,
    crl_form: CrlForm::Pem,
};

// tcb_info / qe_identity stay as raw JSON text so QVL sees the exact signed
// bytes from the fixture; re-serializing could reorder or reformat them.
#[derive(Deserialize)]
pub struct RawCollateral {
    #[allow(dead_code)]
    pub version: u32,
    pub root_ca_crl: String,
    pub pck_crl: String,
    pub tcb_info_issuer_chain: String,
    pub pck_crl_issuer_chain: String,
    pub qe_identity_issuer_chain: String,
    pub tcb_info: Box<RawValue>,
    pub qe_identity: Box<RawValue>,
}

// Intel's QPL hands the QVL NUL-terminated buffers whose sizes include the NUL.
fn blob(bytes: &[u8]) -> Vec<c_char> {
    bytes
        .iter()
        .map(|&b| b as c_char)
        .chain(std::iter::once(0))
        .collect()
}

fn crl_blob(pem_text: &str, form: CrlForm) -> Result<Vec<c_char>, String> {
    match form {
        CrlForm::Pem => Ok(blob(pem_text.as_bytes())),
        CrlForm::Der => {
            let parsed = pem::parse(pem_text).map_err(|e| format!("CRL PEM decode: {e}"))?;
            Ok(parsed.contents().iter().map(|&b| b as c_char).collect())
        }
    }
}

pub fn build_quote_collateral(
    raw: &RawCollateral,
    cfg: MarshalConfig,
) -> Result<QuoteCollateral, String> {
    Ok(QuoteCollateral {
        major_version: cfg.major,
        minor_version: cfg.minor,
        tee_type: cfg.tee_type,
        pck_crl_issuer_chain: blob(raw.pck_crl_issuer_chain.as_bytes()),
        root_ca_crl: crl_blob(&raw.root_ca_crl, cfg.crl_form)?,
        pck_crl: crl_blob(&raw.pck_crl, cfg.crl_form)?,
        tcb_info_issuer_chain: blob(raw.tcb_info_issuer_chain.as_bytes()),
        tcb_info: blob(raw.tcb_info.get().as_bytes()),
        qe_identity_issuer_chain: blob(raw.qe_identity_issuer_chain.as_bytes()),
        qe_identity: blob(raw.qe_identity.get().as_bytes()),
    })
}

fn system_time(unix: i64) -> SystemTime {
    if unix >= 0 {
        UNIX_EPOCH + Duration::from_secs(unix as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs(unix.unsigned_abs())
    }
}

pub fn run_dcap(quote_bytes: &[u8], collateral_json: &[u8], current_time: i64) -> DcapOutcome {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let collateral: SgxCollateral = match serde_json::from_slice(collateral_json) {
            Ok(c) => c,
            Err(e) => {
                return DcapOutcome::Reject {
                    category: ErrorCategory::CollateralParse,
                    detail: format!("collateral JSON: {e}"),
                };
            }
        };
        let mut cursor = quote_bytes;
        let quote = match SgxQuote::read(&mut cursor) {
            Ok(q) => q,
            Err(e) => {
                return DcapOutcome::Reject {
                    category: e.category,
                    detail: e.detail,
                };
            }
        };
        // Pin the quote's own measurement so the MRENCLAVE gate never fires,
        // and pass 0 to disable the TCB evaluation-round floor; QVL has no
        // equivalent gate for either.
        let expected = peek_mrenclave(quote_bytes).copied().unwrap_or([0u8; 32]);
        match verify_remote_attestation(system_time(current_time), collateral, quote, &expected, 0)
        {
            Ok((standing, _report)) => DcapOutcome::Accept(standing),
            Err(e) => DcapOutcome::Reject {
                category: e.category,
                detail: e.detail,
            },
        }
    }));
    match outcome {
        Ok(o) => o,
        Err(_) => {
            let msg = LAST_PANIC
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| "panic (no message captured)".to_string());
            DcapOutcome::Panic(msg)
        }
    }
}

pub fn run_qvl(
    quote_bytes: &[u8],
    collateral_json: &[u8],
    current_time: i64,
    cfg: MarshalConfig,
) -> QvlOutcome {
    let raw: RawCollateral = match serde_json::from_slice(collateral_json) {
        Ok(r) => r,
        Err(e) => return QvlOutcome::NotRun(format!("marshal-failed: {e}")),
    };
    let collateral = match build_quote_collateral(&raw, cfg) {
        Ok(c) => c,
        Err(e) => return QvlOutcome::NotRun(format!("marshal-failed: {e}")),
    };
    match tee_verify_quote(quote_bytes, Some(&collateral), current_time, None, None) {
        Ok((exp_status, result)) => QvlOutcome::Verdict { exp_status, result },
        Err(code) => QvlOutcome::Error(code),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bucket {
    AgreeAccept,
    AgreeReject,
    StandingMismatch,
    Dangerous(&'static str),
    KnownDelta(&'static str),
    UnexplainedSafe,
    DcapPanic,
}

impl Bucket {
    pub fn label(&self) -> String {
        match self {
            Self::AgreeAccept => "agree-accept".to_string(),
            Self::AgreeReject => "agree-reject".to_string(),
            Self::StandingMismatch => "standing-mismatch".to_string(),
            Self::Dangerous(kind) => format!("DANGEROUS({kind})"),
            Self::KnownDelta(kind) => format!("known-delta({kind})"),
            Self::UnexplainedSafe => "unexplained-safe".to_string(),
            Self::DcapPanic => "dcap-panic".to_string(),
        }
    }

    pub fn is_agreement(&self) -> bool {
        matches!(self, Self::AgreeAccept | Self::AgreeReject)
    }

    pub fn is_finding(&self) -> bool {
        matches!(
            self,
            Self::StandingMismatch | Self::Dangerous(_) | Self::UnexplainedSafe | Self::DcapPanic
        )
    }
}

/// Process exit code carrying the run's verdict, so `mise test-dcap-differ` and CI
/// can act on the result rather than on "the binary didn't crash".
pub const EXIT_CLEAN: i32 = 0;
pub const EXIT_REVIEW: i32 = 10;
pub const EXIT_FAIL: i32 = 20;

/// Running count of comparison buckets, collapsed to a verdict. `standing-mismatch`
/// and `dcap-panic` are unambiguous defects (FAIL); `dangerous` (dcap accepts where
/// QVL rejects) is surfaced for REVIEW — on the current crate every such case is
/// triaged framing/parser leniency (FINDINGS.md F1–F5), not a bypass; everything
/// else (agreements, known policy deltas, dcap-stricter safe-direction) is CLEAN.
/// A dangerous record matched by the `--allow` list counts as `dangerous_known`
/// (CLEAN); an in-scope allowlist entry that did not fire counts as `vanished`
/// (REVIEW) so a silently disappearing finding is surfaced too.
#[derive(Default)]
pub struct Tally {
    pub agree_accept: u64,
    pub agree_reject: u64,
    pub known_delta: u64,
    pub unexplained_safe: u64,
    pub dangerous: u64,
    pub dangerous_known: u64,
    pub vanished: u64,
    pub standing_mismatch: u64,
    pub dcap_panic: u64,
}

impl Tally {
    pub fn add(&mut self, bucket: &Bucket) {
        match bucket {
            Bucket::AgreeAccept => self.agree_accept += 1,
            Bucket::AgreeReject => self.agree_reject += 1,
            Bucket::KnownDelta(_) => self.known_delta += 1,
            Bucket::UnexplainedSafe => self.unexplained_safe += 1,
            Bucket::Dangerous(_) => self.dangerous += 1,
            Bucket::StandingMismatch => self.standing_mismatch += 1,
            Bucket::DcapPanic => self.dcap_panic += 1,
        }
    }

    pub fn exit_code(&self) -> i32 {
        if self.dcap_panic > 0 || self.standing_mismatch > 0 {
            EXIT_FAIL
        } else if self.dangerous > 0 || self.vanished > 0 {
            EXIT_REVIEW
        } else {
            EXIT_CLEAN
        }
    }

    /// Print the one-line verdict. Returns the exit code so the caller can propagate it.
    pub fn print_verdict(&self) -> i32 {
        let code = self.exit_code();
        let counts = format!(
            "{} agree ({} accept / {} reject), {} known-delta, {} safe-direction (dcap stricter), {} dangerous, {} known-dangerous (allowlisted), {} vanished, {} standing-mismatch, {} panic",
            self.agree_accept + self.agree_reject,
            self.agree_accept,
            self.agree_reject,
            self.known_delta,
            self.unexplained_safe,
            self.dangerous,
            self.dangerous_known,
            self.vanished,
            self.standing_mismatch,
            self.dcap_panic,
        );
        match code {
            EXIT_FAIL => println!(
                "RESULT: FAIL — {} dcap-panic, {} standing-mismatch (real defect). [{counts}]",
                self.dcap_panic, self.standing_mismatch
            ),
            EXIT_REVIEW => println!(
                "RESULT: REVIEW — {} unrecorded dcap-accept/QVL-reject divergence(s), {} allowlisted case(s) that no longer reproduce; triage against dcap-differ/FINDINGS.md. [{counts}]",
                self.dangerous, self.vanished
            ),
            _ => println!(
                "RESULT: CLEAN — dcap-verify matches Intel QVL (only expected deltas). [{counts}]"
            ),
        }
        code
    }
}

fn qvl_accepts(result: sgx_ql_qv_result_t) -> bool {
    matches!(
        result,
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK
            | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED
            | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED
    )
}

fn standing_matches(result: sgx_ql_qv_result_t, standing: &TcbStanding) -> bool {
    matches!(
        (result, standing),
        (
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK,
            TcbStanding::UpToDate
        ) | (
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED,
            TcbStanding::SWHardeningNeeded { .. }
        ) | (
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED,
            TcbStanding::ConfigurationAndSWHardeningNeeded { .. }
        )
    )
}

const FORMAT_GATE_MARKERS: [&str; 4] = [
    "only version 3 is supported",
    "only versions 2 and 3 are supported",
    "only version 2 is supported",
    "tcbType",
];

const STALENESS_CATEGORIES: [ErrorCategory; 3] = [
    ErrorCategory::TcbInfoStale,
    ErrorCategory::QeIdentityStale,
    ErrorCategory::CertOrCrlTimeInvalid,
];

enum QvlClass {
    Accept,
    AcceptExpired,
    Reject,
}

pub fn classify(dcap: &DcapOutcome, qvl: &QvlOutcome) -> Bucket {
    if matches!(dcap, DcapOutcome::Panic(_)) {
        return Bucket::DcapPanic;
    }
    let (class, exp_status) = match qvl {
        QvlOutcome::NotRun(_) | QvlOutcome::Error(_) => (QvlClass::Reject, 0),
        QvlOutcome::Verdict { exp_status, result } => {
            let class = if qvl_accepts(*result) {
                if *exp_status == 0 {
                    QvlClass::Accept
                } else {
                    QvlClass::AcceptExpired
                }
            } else {
                QvlClass::Reject
            };
            (class, *exp_status)
        }
    };
    match (dcap, class) {
        (DcapOutcome::Accept(standing), QvlClass::Accept) => {
            let QvlOutcome::Verdict { result, .. } = qvl else {
                unreachable!("QvlClass::Accept only arises from a verdict");
            };
            if standing_matches(*result, standing) {
                Bucket::AgreeAccept
            } else {
                Bucket::StandingMismatch
            }
        }
        (DcapOutcome::Accept(_), QvlClass::AcceptExpired) => {
            Bucket::Dangerous("qvl-accept-expired")
        }
        (DcapOutcome::Accept(_), QvlClass::Reject) => match qvl {
            QvlOutcome::NotRun(_) => Bucket::Dangerous("qvl-not-run"),
            _ => Bucket::Dangerous("qvl-rejects"),
        },
        (DcapOutcome::Reject { .. }, QvlClass::Reject) => Bucket::AgreeReject,
        (DcapOutcome::Reject { category, detail }, QvlClass::Accept | QvlClass::AcceptExpired) => {
            if *category == ErrorCategory::DebugEnclaveRejected {
                Bucket::KnownDelta("debug-gate")
            } else if *category == ErrorCategory::CollateralParse
                && FORMAT_GATE_MARKERS.iter().any(|m| detail.contains(m))
            {
                Bucket::KnownDelta("format-gate")
            } else if STALENESS_CATEGORIES.contains(category) && exp_status != 0 {
                Bucket::KnownDelta("expiry-model")
            } else {
                Bucket::UnexplainedSafe
            }
        }
        (DcapOutcome::Panic(_), _) => unreachable!("handled above"),
    }
}

#[derive(Debug)]
pub struct ComparisonRecord {
    pub dcap: DcapOutcome,
    pub qvl: QvlOutcome,
    pub bucket: Bucket,
}

pub fn run_case(
    quote_bytes: &[u8],
    collateral_json: &[u8],
    current_time: i64,
    cfg: MarshalConfig,
) -> ComparisonRecord {
    let dcap = run_dcap(quote_bytes, collateral_json, current_time);
    let qvl = run_qvl(quote_bytes, collateral_json, current_time, cfg);
    let bucket = classify(&dcap, &qvl);
    ComparisonRecord { dcap, qvl, bucket }
}
