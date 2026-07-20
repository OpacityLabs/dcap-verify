//! Verifier for Intel SGX DCAP quote v3 attestations against PCS v4 collateral.

pub mod error;
pub mod types;

mod pki;
#[cfg(test)]
mod synthetic_e2e;
mod tcb;
mod verify;

use serde::{Deserialize, Serialize};

pub use error::{ErrorCategory, VerifyError};
pub use types::collateral::SgxCollateral;
pub use types::quote::{SgxQuote, peek_mrenclave, peek_report_data};
pub use types::report::{MREnclave, SgxReportBody};
pub use verify::verify_remote_attestation;

/// The platform's true TCB status, as read from the selected TCB level — not a
/// policy verdict. The library returns this only for statuses it accepts; the
/// caller decides how to react to an accepted-but-degraded status. The distinct
/// `SWHardeningNeeded` and `ConfigurationAndSWHardeningNeeded` statuses are kept
/// as separate variants so a caller can tell them apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcbStanding {
    #[serde(rename = "up-to-date")]
    UpToDate,
    #[serde(rename = "sw-hardening-needed")]
    SWHardeningNeeded { advisory_ids: Vec<String> },
    #[serde(rename = "configuration-and-sw-hardening-needed")]
    ConfigurationAndSWHardeningNeeded { advisory_ids: Vec<String> },
}
