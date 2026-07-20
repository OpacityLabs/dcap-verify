//! Caller-owned TCB acceptance policy. [`TcbPolicy`] is plain data the caller
//! constructs and passes explicitly — the crate holds no policy state and
//! ships no default. See [`crate::verify_remote_attestation_with_policy`] for
//! the one-call form.

use crate::TcbStanding;
use crate::error::{ErrorCategory, VerifyError};

/// A caller-owned acceptance policy over the degraded-but-accepted TCB
/// standings, plus the evaluation-round floor forwarded to verification.
///
/// [`crate::verify_remote_attestation`] itself rejects the never-acceptable
/// statuses (`OutOfDate`, `Revoked`, no matching level, …) outright; the three
/// [`TcbStanding`] variants are the statuses Intel defines as acceptable, and
/// this policy decides which of the degraded two the caller tolerates.
/// `UpToDate` is always accepted.
///
/// Deliberately has no `Default` — every field is a security decision the
/// caller must make explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcbPolicy {
    /// Freshness floor against TCB-recovery round downgrades: collateral from
    /// an Intel evaluation round below this rejects even inside its
    /// `nextUpdate` window. `0` accepts any round.
    pub min_tcb_evaluation_data_number: u32,
    /// Accept `TcbStanding::SWHardeningNeeded`.
    pub accept_sw_hardening_needed: bool,
    /// Accept `TcbStanding::ConfigurationAndSWHardeningNeeded`.
    pub accept_configuration_and_sw_hardening_needed: bool,
}

impl TcbPolicy {
    /// Judge an already-verified standing against this policy. Pure and
    /// stateless: rejection is a [`VerifyError`] with the
    /// `tcb-standing-rejected` category naming the standing and its advisory
    /// IDs.
    pub fn check(&self, standing: &TcbStanding) -> Result<(), VerifyError> {
        match standing {
            TcbStanding::UpToDate => Ok(()),
            TcbStanding::SWHardeningNeeded { advisory_ids } => {
                if self.accept_sw_hardening_needed {
                    Ok(())
                } else {
                    Err(rejection("sw-hardening-needed", advisory_ids))
                }
            }
            TcbStanding::ConfigurationAndSWHardeningNeeded { advisory_ids } => {
                if self.accept_configuration_and_sw_hardening_needed {
                    Ok(())
                } else {
                    Err(rejection(
                        "configuration-and-sw-hardening-needed",
                        advisory_ids,
                    ))
                }
            }
        }
    }
}

fn rejection(standing_tag: &str, advisory_ids: &[String]) -> VerifyError {
    VerifyError::new(
        ErrorCategory::TcbStandingRejected,
        format!("caller policy rejects TCB standing {standing_tag} (advisories: {advisory_ids:?})"),
    )
}

#[cfg(test)]
mod tests {
    use super::TcbPolicy;
    use crate::TcbStanding;
    use crate::error::ErrorCategory;

    fn sw() -> TcbStanding {
        TcbStanding::SWHardeningNeeded {
            advisory_ids: vec!["INTEL-SA-00615".into()],
        }
    }

    fn config_sw() -> TcbStanding {
        TcbStanding::ConfigurationAndSWHardeningNeeded {
            advisory_ids: vec!["INTEL-SA-00289".into(), "INTEL-SA-00615".into()],
        }
    }

    const STRICT: TcbPolicy = TcbPolicy {
        min_tcb_evaluation_data_number: 0,
        accept_sw_hardening_needed: false,
        accept_configuration_and_sw_hardening_needed: false,
    };

    const PERMISSIVE: TcbPolicy = TcbPolicy {
        min_tcb_evaluation_data_number: 0,
        accept_sw_hardening_needed: true,
        accept_configuration_and_sw_hardening_needed: true,
    };

    #[test]
    fn up_to_date_is_always_accepted() {
        assert!(STRICT.check(&TcbStanding::UpToDate).is_ok());
        assert!(PERMISSIVE.check(&TcbStanding::UpToDate).is_ok());
    }

    #[test]
    fn sw_hardening_needed_follows_its_flag_only() {
        assert!(PERMISSIVE.check(&sw()).is_ok());
        let cross = TcbPolicy {
            accept_sw_hardening_needed: false,
            ..PERMISSIVE
        };
        let err = cross.check(&sw()).unwrap_err();
        assert_eq!(err.category, ErrorCategory::TcbStandingRejected);
        assert!(err.detail.contains("sw-hardening-needed"));
        assert!(err.detail.contains("INTEL-SA-00615"));
        // The other flag must not bleed over.
        let other = TcbPolicy {
            accept_configuration_and_sw_hardening_needed: false,
            ..PERMISSIVE
        };
        assert!(other.check(&sw()).is_ok());
    }

    #[test]
    fn configuration_and_sw_hardening_needed_follows_its_flag_only() {
        assert!(PERMISSIVE.check(&config_sw()).is_ok());
        let cross = TcbPolicy {
            accept_configuration_and_sw_hardening_needed: false,
            ..PERMISSIVE
        };
        let err = cross.check(&config_sw()).unwrap_err();
        assert_eq!(err.category, ErrorCategory::TcbStandingRejected);
        assert!(err.detail.contains("configuration-and-sw-hardening-needed"));
        assert!(err.detail.contains("INTEL-SA-00289"));
        let other = TcbPolicy {
            accept_sw_hardening_needed: false,
            ..PERMISSIVE
        };
        assert!(other.check(&config_sw()).is_ok());
    }
}
