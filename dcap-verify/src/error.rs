use thiserror::Error;

/// The classification of a verification rejection — the single source of truth
/// for rejection reasons. Add a variant here (the compiler then forces its
/// [`ErrorCategory::as_str`] arm), and raise it at the rejection site with
/// [`VerifyError::new`]. There is no parallel variant list or category mapping
/// to keep in sync, so a category can never be silently mis-mapped.
///
/// `#[non_exhaustive]`: the category set grows over time, so downstream
/// matches must carry a wildcard arm — new categories are then additive, not
/// breaking.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCategory {
    QuoteParse,
    CollateralParse,
    QuoteSignatureInvalid,
    QeReportSignatureInvalid,
    QeBindingInvalid,
    QeVendorInvalid,
    QeIdentitySignatureInvalid,
    QeIdentityStale,
    QeIdentityMismatch,
    TcbInfoSignatureInvalid,
    TcbInfoStale,
    CertOrCrlTimeInvalid,
    CrlInvalid,
    RootCaUntrusted,
    TcbLevelUnsupported,
    TcbStandingRejected,
    MrenclaveMismatch,
    DebugEnclaveRejected,
}

impl ErrorCategory {
    /// The stable slug used in fixture `meta.json` and in error display. The
    /// exhaustive match means a new variant cannot be added without giving it a
    /// slug here — it will not compile otherwise.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::QuoteParse => "quote-parse-error",
            Self::CollateralParse => "collateral-parse-error",
            Self::QuoteSignatureInvalid => "quote-signature-invalid",
            Self::QeReportSignatureInvalid => "qe-report-signature-invalid",
            Self::QeBindingInvalid => "qe-binding-invalid",
            Self::QeVendorInvalid => "qe-vendor-invalid",
            Self::QeIdentitySignatureInvalid => "qe-identity-signature-invalid",
            Self::QeIdentityStale => "qe-identity-stale",
            Self::QeIdentityMismatch => "qe-identity-mismatch",
            Self::TcbInfoSignatureInvalid => "tcb-info-signature-invalid",
            Self::TcbInfoStale => "tcb-info-stale",
            Self::CertOrCrlTimeInvalid => "cert-or-crl-time-invalid",
            Self::CrlInvalid => "crl-invalid",
            Self::RootCaUntrusted => "root-ca-untrusted",
            Self::TcbLevelUnsupported => "tcb-level-unsupported",
            Self::TcbStandingRejected => "tcb-standing-rejected",
            Self::MrenclaveMismatch => "mrenclave-mismatch",
            Self::DebugEnclaveRejected => "debug-enclave-rejected",
        }
    }
}

impl std::fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A verification rejection: a machine-checkable [`ErrorCategory`] plus a
/// human-readable detail specific enough to debug the failure. The category is
/// chosen at the rejection site via [`VerifyError::new`], so — unlike a separate
/// variant-to-category mapping — it cannot be silently mis-mapped.
#[derive(Debug, Error)]
#[error("[{category}] {detail}")]
pub struct VerifyError {
    pub category: ErrorCategory,
    pub detail: String,
}

impl VerifyError {
    pub fn new(category: ErrorCategory, detail: impl Into<String>) -> Self {
        Self {
            category,
            detail: detail.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ErrorCategory;

    // Display is the slug — rejection messages must name their category.
    #[test]
    fn display_matches_the_stable_slug() {
        assert_eq!(ErrorCategory::QuoteParse.to_string(), "quote-parse-error");
        assert_eq!(
            ErrorCategory::DebugEnclaveRejected.to_string(),
            "debug-enclave-rejected"
        );
        assert_eq!(
            ErrorCategory::TcbStandingRejected.to_string(),
            "tcb-standing-rejected"
        );
    }
}
