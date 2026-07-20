use std::sync::LazyLock;

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use x509_parser::oid_registry::{
    OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ECDSA_WITH_SHA256,
};
use x509_parser::prelude::*;

use crate::error::{ErrorCategory, VerifyError};

pub(crate) const INTEL_QE_VENDOR_ID: [u8; 16] = [
    0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07,
];

/// Subject common name of Intel's dedicated collateral-signing certificate. The
/// leaves that sign `tcbInfo` and `enclaveIdentity` must carry this exact name;
/// merely chaining to the root is not enough.
pub(crate) const INTEL_TCB_SIGNING_CN: &str = "Intel SGX TCB Signing";

/// Intel PKI paths are three certificates (leaf, intermediate, root). A generous
/// cap bounds the per-certificate signature work an attacker-supplied chain can
/// force before the pinned-root anchor is even reached.
const MAX_CHAIN_LEN: usize = 10;

/// Byte cap on a PEM chain, checked before any decoding. Real Intel chains are
/// ~2 KiB and even `MAX_CHAIN_LEN` certificates fit in a fraction of this; the
/// cap bounds the base64/DER work an oversized attacker-supplied blob can force
/// before the certificate-count cap is reachable.
const MAX_CHAIN_PEM_LEN: usize = 64 * 1024;

// Uncompressed P-256 point of the Intel SGX Provisioning Certification Root CA key,
// taken from Intel's published root certificate.
const INTEL_SGX_ROOT_CA_PUBLIC_KEY_SEC1: [u8; 65] = [
    0x04, 0x0b, 0xa9, 0xc4, 0xc0, 0xc0, 0xc8, 0x61, 0x93, 0xa3, 0xfe, 0x23, 0xd6, 0xb0, 0x2c, 0xda,
    0x10, 0xa8, 0xbb, 0xd4, 0xe8, 0x8e, 0x48, 0xb4, 0x45, 0x85, 0x61, 0xa3, 0x6e, 0x70, 0x55, 0x25,
    0xf5, 0x67, 0x91, 0x8e, 0x2e, 0xdc, 0x88, 0xe4, 0x0d, 0x86, 0x0b, 0xd0, 0xcc, 0x4e, 0xe2, 0x6a,
    0xac, 0xc9, 0x88, 0xe5, 0x05, 0xa9, 0x53, 0x55, 0x8c, 0x45, 0x3f, 0x6b, 0x09, 0x04, 0xae, 0x73,
    0x94,
];

const SGX_PCK_EXTENSION_OID: &str = "1.2.840.113741.1.13.1";

/// The pinned Intel SGX Root CA key, decoded once per process. The bytes are a
/// crate constant we control, so a decode failure is an internal invariant
/// violation, not an attacker-reachable condition.
static PINNED_ROOT_KEY: LazyLock<VerifyingKey> = LazyLock::new(|| {
    VerifyingKey::from_sec1_bytes(&INTEL_SGX_ROOT_CA_PUBLIC_KEY_SEC1)
        .expect("embedded Intel SGX Root CA key must be a valid P-256 point")
});

// Test-only trust-anchor override for the synthetic end-to-end suite
// (`crate::synthetic_e2e`), whose scenarios require inputs Intel will never
// sign (e.g. a CRL revoking our own PCK certificate). `cfg(test)` code is
// compiled only into this crate's own test harness — never into a dependent
// or release build, by Rust semantics rather than by policy — so every
// shipped artifact anchors unconditionally at the Intel constant above.
// Thread-local so tests exercising the real Intel anchor are unaffected.
#[cfg(test)]
thread_local! {
    pub(crate) static TEST_ROOT_ANCHOR: std::cell::Cell<Option<[u8; 65]>> =
        const { std::cell::Cell::new(None) };
}

fn anchor_sec1() -> [u8; 65] {
    #[cfg(test)]
    if let Some(key) = TEST_ROOT_ANCHOR.with(|c| c.get()) {
        return key;
    }
    INTEL_SGX_ROOT_CA_PUBLIC_KEY_SEC1
}

pub(crate) fn pinned_root_key() -> VerifyingKey {
    #[cfg(test)]
    if let Some(key) = TEST_ROOT_ANCHOR.with(|c| c.get()) {
        return VerifyingKey::from_sec1_bytes(&key)
            .expect("test anchor must be a valid P-256 point");
    }
    *PINNED_ROOT_KEY
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ChainKind {
    TcbInfoIssuer,
    PckCrlIssuer,
    QeIdentityIssuer,
    QuotePck,
}

impl ChainKind {
    fn label(self) -> &'static str {
        match self {
            Self::TcbInfoIssuer => "TCB info issuer chain",
            Self::PckCrlIssuer => "PCK CRL issuer chain",
            Self::QeIdentityIssuer => "QE identity issuer chain",
            Self::QuotePck => "PCK chain embedded in the quote",
        }
    }

    fn parse_error(self, detail: String) -> VerifyError {
        let msg = format!("{}: {detail}", self.label());
        match self {
            Self::QuotePck => VerifyError::new(ErrorCategory::QuoteParse, msg),
            _ => VerifyError::new(ErrorCategory::CollateralParse, msg),
        }
    }
}

/// A PEM certificate chain with its DER bytes owned. Parse it exactly once into a
/// [`ParsedChain`] and reuse that across every check — the entry point runs
/// inside a mobile TLS handshake.
pub(crate) struct CertChain {
    kind: ChainKind,
    ders: Vec<Vec<u8>>,
}

impl CertChain {
    pub(crate) fn from_pem(kind: ChainKind, data: &[u8]) -> Result<Self, VerifyError> {
        if data.len() > MAX_CHAIN_PEM_LEN {
            return Err(kind.parse_error(format!(
                "chain is {} bytes, more than the accepted maximum of {MAX_CHAIN_PEM_LEN}",
                data.len()
            )));
        }
        let trimmed = trim_trailing_junk(data);
        let blocks = ::pem::parse_many(trimmed)
            .map_err(|e| kind.parse_error(format!("PEM decoding failed: {e}")))?;
        let ders: Vec<Vec<u8>> = blocks
            .into_iter()
            .filter(|b| b.tag() == "CERTIFICATE")
            .map(|b| b.into_contents())
            .collect();
        if ders.is_empty() {
            return Err(kind.parse_error("no certificates present".to_string()));
        }
        if ders.len() > MAX_CHAIN_LEN {
            return Err(kind.parse_error(format!(
                "chain holds {} certificates, more than the accepted maximum of {MAX_CHAIN_LEN}",
                ders.len()
            )));
        }
        Ok(Self { kind, ders })
    }

    /// Decode every certificate in the chain a single time.
    pub(crate) fn parse(&self) -> Result<ParsedChain<'_>, VerifyError> {
        let certs = self
            .ders
            .iter()
            .enumerate()
            .map(|(i, der)| {
                X509Certificate::from_der(der)
                    .map(|(_, cert)| cert)
                    .map_err(|e| {
                        self.kind
                            .parse_error(format!("certificate {i} is not valid DER: {e}"))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ParsedChain {
            kind: self.kind,
            certs,
        })
    }
}

/// A certificate chain decoded once. All path checks and accessors read the
/// already-parsed certificates rather than re-decoding DER.
pub(crate) struct ParsedChain<'a> {
    kind: ChainKind,
    certs: Vec<X509Certificate<'a>>,
}

impl ParsedChain<'_> {
    fn leaf(&self) -> &X509Certificate<'_> {
        // `CertChain::from_pem` rejects an empty chain, so a parsed chain always
        // has at least one certificate.
        &self.certs[0]
    }

    fn root(&self) -> &X509Certificate<'_> {
        &self.certs[self.certs.len() - 1]
    }

    /// Full X.509 path validation to the pinned Intel SGX Root CA.
    pub(crate) fn validate(&self, now: i64) -> Result<(), VerifyError> {
        let label = self.kind.label();

        // Anchor first: reject before any unbounded per-certificate signature work
        // if the terminal certificate is not the pinned root.
        let root = self.root();
        let anchor = anchor_sec1();
        if root.public_key().subject_public_key.data.as_ref() != anchor.as_slice() {
            return Err(VerifyError::new(
                ErrorCategory::RootCaUntrusted,
                format!(
                    "{label}: terminal certificate '{}' does not hold the pinned Intel SGX Root CA key",
                    root.subject()
                ),
            ));
        }

        for cert in &self.certs {
            let subject = cert.subject().to_string();
            let not_before = cert.validity().not_before.timestamp();
            let not_after = cert.validity().not_after.timestamp();
            // Expiry bound matches Intel's QVL: a certificate is no
            // longer accepted at the exact notAfter instant, while the lower
            // bound is inclusive — valid from the notBefore instant.
            if now < not_before || now >= not_after {
                return Err(VerifyError::new(
                    ErrorCategory::CertOrCrlTimeInvalid,
                    format!(
                        "{label}: '{subject}' is valid from unix {not_before} until unix {not_after}, verification time is {now}"
                    ),
                ));
            }
            check_p256_sha256_algs(label, cert)?;
        }

        // Every certificate used as an issuer (index >= 1 signs the cert below it,
        // and the root signs itself) must assert CA capability. This is what stops
        // an end-entity leaf from being spliced in as an issuer.
        for (i, cert) in self.certs.iter().enumerate().skip(1) {
            require_ca(label, i, cert)?;
        }

        for i in 0..self.certs.len() {
            let child = &self.certs[i];
            let parent = self.certs.get(i + 1).unwrap_or(&self.certs[i]);
            if child.issuer().as_raw() != parent.subject().as_raw() {
                return Err(VerifyError::new(
                    ErrorCategory::RootCaUntrusted,
                    format!(
                        "{label}: certificate {i} ('{}') was not issued by the next certificate in the chain ('{}')",
                        child.subject(),
                        parent.subject()
                    ),
                ));
            }
            let issuer_key = spki_verifying_key(label, parent)?;
            let sig = Signature::from_der(child.signature_value.data.as_ref()).map_err(|e| {
                VerifyError::new(
                    ErrorCategory::RootCaUntrusted,
                    format!("{label}: certificate {i} carries an undecodable signature: {e}"),
                )
            })?;
            issuer_key
                .verify(child.tbs_certificate.as_ref(), &sig)
                .map_err(|_| {
                    VerifyError::new(ErrorCategory::RootCaUntrusted, format!(
                        "{label}: signature on certificate {i} ('{}') does not verify against its issuer",
                        child.subject()
                    ))
                })?;
        }

        Ok(())
    }

    pub(crate) fn leaf_verifying_key(&self) -> Result<VerifyingKey, VerifyError> {
        spki_verifying_key(self.kind.label(), self.leaf())
    }

    pub(crate) fn leaf_subject_raw(&self) -> Vec<u8> {
        self.leaf().subject().as_raw().to_vec()
    }

    pub(crate) fn leaf_issuer_raw(&self) -> Vec<u8> {
        self.leaf().issuer().as_raw().to_vec()
    }

    pub(crate) fn root_subject_raw(&self) -> Vec<u8> {
        self.root().subject().as_raw().to_vec()
    }

    /// The leaf certificate's subject common name, for signer-identity pinning.
    pub(crate) fn leaf_common_name(&self) -> Result<String, VerifyError> {
        self.leaf()
            .subject()
            .iter_common_name()
            .next()
            .and_then(|attr| attr.as_str().ok())
            .map(str::to_string)
            .ok_or_else(|| {
                self.kind
                    .parse_error("leaf certificate has no readable common name".to_string())
            })
    }
}

fn require_ca(label: &str, index: usize, cert: &X509Certificate<'_>) -> Result<(), VerifyError> {
    let subject = cert.subject();
    let bc = cert
        .basic_constraints()
        .map_err(|e| {
            VerifyError::new(ErrorCategory::RootCaUntrusted, format!(
                "{label}: certificate {index} ('{subject}') has an unparseable basicConstraints extension: {e}"
            ))
        })?
        .ok_or_else(|| {
            VerifyError::new(ErrorCategory::RootCaUntrusted, format!(
                "{label}: issuer certificate {index} ('{subject}') lacks a basicConstraints extension"
            ))
        })?;
    if !bc.value.ca {
        return Err(VerifyError::new(
            ErrorCategory::RootCaUntrusted,
            format!(
                "{label}: certificate {index} ('{subject}') is used as an issuer but is not a CA (basicConstraints cA=false)"
            ),
        ));
    }
    // keyUsage is enforced only where present.
    let key_usage = cert.key_usage().map_err(|e| {
        VerifyError::new(ErrorCategory::RootCaUntrusted, format!(
            "{label}: certificate {index} ('{subject}') has an unparseable keyUsage extension: {e}"
        ))
    })?;
    if let Some(ku) = key_usage
        && !ku.value.key_cert_sign()
    {
        return Err(VerifyError::new(
            ErrorCategory::RootCaUntrusted,
            format!(
                "{label}: issuer certificate {index} ('{subject}') keyUsage does not permit keyCertSign"
            ),
        ));
    }
    Ok(())
}

fn trim_trailing_junk(data: &[u8]) -> &[u8] {
    let mut end = data.len();
    while end > 0 && (data[end - 1] == 0 || data[end - 1].is_ascii_whitespace()) {
        end -= 1;
    }
    &data[..end]
}

fn check_p256_sha256_algs(label: &str, cert: &X509Certificate<'_>) -> Result<(), VerifyError> {
    // RFC 5280 §4.1.1.2: the outer signatureAlgorithm
    // is not covered by the signature, so it must byte-for-byte agree (OID and
    // parameters) with the signed tbsCertificate.signature copy.
    if cert.signature_algorithm != cert.tbs_certificate.signature {
        return Err(VerifyError::new(
            ErrorCategory::RootCaUntrusted,
            format!(
                "{label}: '{}' declares an outer signatureAlgorithm that differs from the signed tbsCertificate.signature field",
                cert.subject()
            ),
        ));
    }
    if cert.signature_algorithm.algorithm != OID_SIG_ECDSA_WITH_SHA256 {
        return Err(VerifyError::new(
            ErrorCategory::RootCaUntrusted,
            format!(
                "{label}: '{}' is signed with algorithm {} instead of ECDSA-with-SHA256",
                cert.subject(),
                cert.signature_algorithm.algorithm
            ),
        ));
    }
    let spki_alg = &cert.public_key().algorithm;
    if spki_alg.algorithm != OID_KEY_TYPE_EC_PUBLIC_KEY {
        return Err(VerifyError::new(
            ErrorCategory::RootCaUntrusted,
            format!(
                "{label}: '{}' holds a non-EC public key ({})",
                cert.subject(),
                spki_alg.algorithm
            ),
        ));
    }
    let curve = spki_alg
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .ok_or_else(|| {
            VerifyError::new(
                ErrorCategory::RootCaUntrusted,
                format!(
                    "{label}: '{}' does not name an EC curve in its key parameters",
                    cert.subject()
                ),
            )
        })?;
    if curve != OID_EC_P256 {
        return Err(VerifyError::new(
            ErrorCategory::RootCaUntrusted,
            format!(
                "{label}: '{}' uses curve {curve} instead of P-256",
                cert.subject()
            ),
        ));
    }
    Ok(())
}

fn spki_verifying_key(
    label: &str,
    cert: &X509Certificate<'_>,
) -> Result<VerifyingKey, VerifyError> {
    VerifyingKey::from_sec1_bytes(cert.public_key().subject_public_key.data.as_ref()).map_err(|e| {
        VerifyError::new(
            ErrorCategory::RootCaUntrusted,
            format!(
                "{label}: public key of '{}' is not a usable P-256 point: {e}",
                cert.subject()
            ),
        )
    })
}

pub(crate) struct RevokedEntry {
    issuer_raw: Vec<u8>,
    serial: Vec<u8>,
}

fn normalized_serial(raw: &[u8]) -> Vec<u8> {
    let stripped: &[u8] = {
        let mut s = raw;
        while !s.is_empty() && s[0] == 0 {
            s = &s[1..];
        }
        s
    };
    if stripped.is_empty() {
        vec![0]
    } else {
        stripped.to_vec()
    }
}

pub(crate) fn check_crl(
    label: &str,
    pem_data: &[u8],
    expected_issuer_raw: &[u8],
    issuer_key: &VerifyingKey,
    now: i64,
) -> Result<Vec<RevokedEntry>, VerifyError> {
    let blocks = ::pem::parse_many(trim_trailing_junk(pem_data)).map_err(|e| {
        VerifyError::new(
            ErrorCategory::CrlInvalid,
            format!("{label}: PEM decoding failed: {e}"),
        )
    })?;
    let der = blocks
        .iter()
        .find(|b| b.tag().contains("CRL"))
        .map(|b| b.contents())
        .ok_or_else(|| {
            VerifyError::new(
                ErrorCategory::CrlInvalid,
                format!("{label}: no CRL block present"),
            )
        })?;
    let (_, crl) = CertificateRevocationList::from_der(der).map_err(|e| {
        VerifyError::new(
            ErrorCategory::CrlInvalid,
            format!("{label}: not valid DER: {e}"),
        )
    })?;

    // RFC 5280 §4.1.1.2: the unsigned outer
    // signatureAlgorithm must agree with the signed tbsCertList.signature copy.
    if crl.signature_algorithm != crl.tbs_cert_list.signature {
        return Err(VerifyError::new(
            ErrorCategory::CrlInvalid,
            format!(
                "{label}: declares an outer signatureAlgorithm that differs from the signed tbsCertList.signature field"
            ),
        ));
    }
    if crl.signature_algorithm.algorithm != OID_SIG_ECDSA_WITH_SHA256 {
        return Err(VerifyError::new(
            ErrorCategory::CrlInvalid,
            format!(
                "{label}: signed with algorithm {} instead of ECDSA-with-SHA256",
                crl.signature_algorithm.algorithm
            ),
        ));
    }
    if crl.issuer().as_raw() != expected_issuer_raw {
        return Err(VerifyError::new(
            ErrorCategory::CrlInvalid,
            format!(
                "{label}: issued by '{}', which is not the expected authority",
                crl.issuer()
            ),
        ));
    }

    let this_update = crl.last_update().timestamp();
    if now < this_update {
        return Err(VerifyError::new(
            ErrorCategory::CertOrCrlTimeInvalid,
            format!("{label}: takes effect at unix {this_update}, verification time is {now}"),
        ));
    }
    // Expiry bound matches Intel's QVL: the CRL is no longer accepted
    // at the exact nextUpdate instant; the thisUpdate lower bound is inclusive.
    if let Some(next_update) = crl.next_update() {
        let next_update = next_update.timestamp();
        if now >= next_update {
            return Err(VerifyError::new(
                ErrorCategory::CertOrCrlTimeInvalid,
                format!("{label}: superseded at unix {next_update}, verification time is {now}"),
            ));
        }
    }

    let sig = Signature::from_der(crl.signature_value.data.as_ref()).map_err(|e| {
        VerifyError::new(
            ErrorCategory::CrlInvalid,
            format!("{label}: undecodable signature: {e}"),
        )
    })?;
    issuer_key
        .verify(crl.tbs_cert_list.as_ref(), &sig)
        .map_err(|_| {
            VerifyError::new(
                ErrorCategory::CrlInvalid,
                format!("{label}: signature does not verify against the issuing key"),
            )
        })?;

    let issuer_raw = crl.issuer().as_raw().to_vec();
    Ok(crl
        .iter_revoked_certificates()
        .map(|rc| RevokedEntry {
            issuer_raw: issuer_raw.clone(),
            serial: normalized_serial(&rc.user_certificate.to_bytes_be()),
        })
        .collect())
}

pub(crate) fn ensure_none_revoked(
    chains: &[&ParsedChain],
    revoked: &[RevokedEntry],
) -> Result<(), VerifyError> {
    for chain in chains {
        for cert in &chain.certs {
            let serial = normalized_serial(cert.raw_serial());
            if revoked
                .iter()
                .any(|r| r.issuer_raw == cert.issuer().as_raw() && r.serial == serial)
            {
                return Err(VerifyError::new(
                    ErrorCategory::CrlInvalid,
                    format!(
                        "{}: certificate '{}' (serial {}) is revoked by its issuer",
                        chain.kind.label(),
                        cert.subject(),
                        cert.tbs_certificate.raw_serial_as_string()
                    ),
                ));
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PckPlatformTcb {
    pub fmspc: [u8; 6],
    pub pce_id: [u8; 2],
    pub comp_svns: [u32; 16],
    pub pcesvn: u32,
}

pub(crate) fn extract_pck_platform_tcb(chain: &ParsedChain) -> Result<PckPlatformTcb, VerifyError> {
    let leaf = chain.leaf();
    let ext = leaf
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == SGX_PCK_EXTENSION_OID)
        .ok_or_else(|| {
            VerifyError::new(
                ErrorCategory::QuoteParse,
                "PCK leaf certificate lacks the SGX platform extension".to_string(),
            )
        })?;

    let (_, top) = x509_parser::der_parser::der::parse_der(ext.value).map_err(|e| {
        VerifyError::new(
            ErrorCategory::QuoteParse,
            format!("SGX platform extension is not parseable DER: {e}"),
        )
    })?;
    let entries = top.as_sequence().map_err(|e| {
        VerifyError::new(
            ErrorCategory::QuoteParse,
            format!("SGX platform extension is not a sequence: {e}"),
        )
    })?;

    let mut fmspc: Option<[u8; 6]> = None;
    let mut pce_id: Option<[u8; 2]> = None;
    let mut comp_svns: [Option<u32>; 16] = [None; 16];
    let mut pcesvn: Option<u32> = None;

    let bad = |what: &str| {
        VerifyError::new(
            ErrorCategory::QuoteParse,
            format!("SGX platform extension: {what}"),
        )
    };

    for entry in entries {
        let Ok(pair) = entry.as_sequence() else {
            continue;
        };
        let (Some(oid_obj), Some(value)) = (pair.first(), pair.get(1)) else {
            continue;
        };
        let Ok(oid) = oid_obj.as_oid() else {
            continue;
        };
        let oid = oid.to_id_string();
        match oid.strip_prefix("1.2.840.113741.1.13.1.") {
            Some("3") => {
                let bytes = value
                    .as_slice()
                    .map_err(|_| bad("PCE-ID is not a byte string"))?;
                pce_id = Some(bytes.try_into().map_err(|_| bad("PCE-ID is not 2 bytes"))?);
            }
            Some("4") => {
                let bytes = value
                    .as_slice()
                    .map_err(|_| bad("FMSPC is not a byte string"))?;
                fmspc = Some(bytes.try_into().map_err(|_| bad("FMSPC is not 6 bytes"))?);
            }
            Some("2") => {
                let tcb_entries = value
                    .as_sequence()
                    .map_err(|_| bad("TCB field is not a sequence"))?;
                for tcb_entry in tcb_entries {
                    let Ok(tcb_pair) = tcb_entry.as_sequence() else {
                        continue;
                    };
                    let (Some(tcb_oid_obj), Some(tcb_value)) = (tcb_pair.first(), tcb_pair.get(1))
                    else {
                        continue;
                    };
                    let Ok(tcb_oid) = tcb_oid_obj.as_oid() else {
                        continue;
                    };
                    let tcb_oid = tcb_oid.to_id_string();
                    let Some(comp) = tcb_oid.strip_prefix("1.2.840.113741.1.13.1.2.") else {
                        continue;
                    };
                    let Ok(index) = comp.parse::<usize>() else {
                        continue;
                    };
                    if (1..=16).contains(&index) {
                        let svn = tcb_value
                            .as_u32()
                            .map_err(|_| bad("a TCB component SVN is not a small integer"))?;
                        comp_svns[index - 1] = Some(svn);
                    } else if index == 17 {
                        pcesvn = Some(
                            tcb_value
                                .as_u32()
                                .map_err(|_| bad("PCESVN is not a small integer"))?,
                        );
                    }
                }
            }
            _ => {}
        }
    }

    let fmspc = fmspc.ok_or_else(|| bad("FMSPC missing"))?;
    let pce_id = pce_id.ok_or_else(|| bad("PCE-ID missing"))?;
    let pcesvn = pcesvn.ok_or_else(|| bad("PCESVN missing"))?;
    let mut svns = [0u32; 16];
    for (i, svn) in comp_svns.iter().enumerate() {
        svns[i] = svn.ok_or_else(|| bad("a TCB component SVN is missing"))?;
    }
    Ok(PckPlatformTcb {
        fmspc,
        pce_id,
        comp_svns: svns,
        pcesvn,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    use rcgen::{
        BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType, IsCa, Issuer,
        KeyIdMethod, KeyPair, KeyUsagePurpose, RevokedCertParams, SerialNumber, date_time_ymd,
    };

    fn prod1_collateral() -> serde_json::Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/prod-1/collateral.json");
        serde_json::from_slice(&fs::read(path).expect("collateral.json")).expect("json")
    }

    // The two certificates of prod-1's TCB-info issuer chain:
    // ders[0] = "Intel SGX TCB Signing" (an end-entity, cA=false);
    // ders[1] = "Intel SGX Root CA" (cA=true, keyCertSign).
    fn tcb_chain_ders() -> Vec<Vec<u8>> {
        let collateral = prod1_collateral();
        let chain = collateral["tcb_info_issuer_chain"]
            .as_str()
            .expect("tcb_info_issuer_chain");
        ::pem::parse_many(chain.trim())
            .expect("pem")
            .into_iter()
            .filter(|b| b.tag() == "CERTIFICATE")
            .map(|b| b.into_contents())
            .collect()
    }

    // A non-CA end-entity certificate must be rejected when used in
    // an issuer position; a genuine CA is accepted.
    #[test]
    fn require_ca_rejects_non_ca_accepts_ca() {
        let ders = tcb_chain_ders();
        let (_, leaf) = X509Certificate::from_der(&ders[0]).expect("leaf der");
        assert!(
            require_ca("test", 1, &leaf).is_err(),
            "the end-entity TCB Signing leaf (cA=false) must not be accepted as an issuer"
        );
        let (_, root) = X509Certificate::from_der(&ders[1]).expect("root der");
        assert!(
            require_ca("test", 1, &root).is_ok(),
            "the Intel SGX Root CA must be accepted as an issuer"
        );
    }

    // Certificate expiry is exclusive — a chain evaluated exactly at its
    // earliest notAfter instant rejects, one second before it validates.
    #[test]
    fn cert_at_exact_not_after_rejects_one_second_before_validates() {
        let chain = CertChain {
            kind: ChainKind::TcbInfoIssuer,
            ders: tcb_chain_ders(),
        };
        let parsed = chain.parse().expect("chain parses");
        let earliest_not_after = parsed
            .certs
            .iter()
            .map(|c| c.validity().not_after.timestamp())
            .min()
            .expect("chain is non-empty");
        assert!(parsed.validate(earliest_not_after - 1).is_ok());
        let err = parsed.validate(earliest_not_after).unwrap_err();
        assert_eq!(err.category, ErrorCategory::CertOrCrlTimeInvalid);
    }

    // CRL expiry is exclusive — evaluated exactly at nextUpdate the CRL
    // rejects, one second before it passes the full check (signature included).
    #[test]
    fn crl_at_exact_next_update_rejects_one_second_before_passes() {
        let collateral = prod1_collateral();
        let crl_pem = collateral["root_ca_crl"].as_str().expect("root_ca_crl");
        let blocks = ::pem::parse_many(crl_pem.trim()).expect("pem");
        let der = blocks
            .iter()
            .find(|b| b.tag().contains("CRL"))
            .expect("CRL block")
            .contents();
        let (_, crl) = CertificateRevocationList::from_der(der).expect("crl der");
        let next_update = crl.next_update().expect("nextUpdate present").timestamp();

        let ders = tcb_chain_ders();
        let (_, root) = X509Certificate::from_der(&ders[1]).expect("root der");
        let issuer_raw = root.subject().as_raw();
        let key = pinned_root_key();
        assert!(
            check_crl(
                "root CA CRL",
                crl_pem.as_bytes(),
                issuer_raw,
                &key,
                next_update - 1
            )
            .is_ok()
        );
        let err = check_crl(
            "root CA CRL",
            crl_pem.as_bytes(),
            issuer_raw,
            &key,
            next_update,
        )
        .err()
        .expect("a CRL evaluated exactly at nextUpdate must reject");
        assert_eq!(err.category, ErrorCategory::CertOrCrlTimeInvalid);
    }

    // The CRL lower bound is inclusive — evaluated exactly at thisUpdate the CRL
    // passes, one second before it rejects as not yet in effect. (The far-past
    // fixture never reaches this branch: certificate notBefore fails first.)
    #[test]
    fn crl_at_exact_this_update_passes_one_second_before_rejects() {
        let collateral = prod1_collateral();
        let crl_pem = collateral["root_ca_crl"].as_str().expect("root_ca_crl");
        let blocks = ::pem::parse_many(crl_pem.trim()).expect("pem");
        let der = blocks
            .iter()
            .find(|b| b.tag().contains("CRL"))
            .expect("CRL block")
            .contents();
        let (_, crl) = CertificateRevocationList::from_der(der).expect("crl der");
        let this_update = crl.last_update().timestamp();

        let ders = tcb_chain_ders();
        let (_, root) = X509Certificate::from_der(&ders[1]).expect("root der");
        let issuer_raw = root.subject().as_raw();
        let key = pinned_root_key();
        assert!(
            check_crl(
                "root CA CRL",
                crl_pem.as_bytes(),
                issuer_raw,
                &key,
                this_update
            )
            .is_ok()
        );
        let err = check_crl(
            "root CA CRL",
            crl_pem.as_bytes(),
            issuer_raw,
            &key,
            this_update - 1,
        )
        .err()
        .expect("a CRL evaluated before thisUpdate must reject");
        assert_eq!(err.category, ErrorCategory::CertOrCrlTimeInvalid);
    }

    // The rejection-path tests below generate their PKI with rcgen, since real
    // Intel collateral never violates these invariants. `require_ca` and
    // `ensure_none_revoked` are called directly, bypassing the pinned-root
    // anchor that would otherwise reject any non-Intel chain first.

    fn test_cert_der(is_ca: IsCa, key_usages: Vec<KeyUsagePurpose>) -> Vec<u8> {
        let key = KeyPair::generate().expect("P-256 key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .distinguished_name
            .push(DnType::CommonName, "dcap-verify test certificate");
        params.is_ca = is_ca;
        params.key_usages = key_usages;
        params
            .self_signed(&key)
            .expect("self-signed certificate")
            .der()
            .to_vec()
    }

    fn require_ca_on(der: &[u8]) -> Result<(), VerifyError> {
        let (_, cert) = X509Certificate::from_der(der).expect("certificate DER");
        require_ca("test", 1, &cert)
    }

    // basicConstraints cA=false in an issuer position rejects.
    #[test]
    fn require_ca_rejects_basic_constraints_ca_false() {
        let der = test_cert_der(IsCa::ExplicitNoCa, vec![]);
        let err = require_ca_on(&der).expect_err("cA=false must not be accepted as an issuer");
        assert_eq!(err.category, ErrorCategory::RootCaUntrusted);
    }

    // A certificate with no basicConstraints extension at all
    // rejects in an issuer position.
    #[test]
    fn require_ca_rejects_missing_basic_constraints() {
        let der = test_cert_der(IsCa::NoCa, vec![]);
        let err = require_ca_on(&der)
            .expect_err("a cert without basicConstraints must not be accepted as an issuer");
        assert_eq!(err.category, ErrorCategory::RootCaUntrusted);
    }

    // A keyUsage extension that is present but lacks keyCertSign
    // rejects, even with cA=true.
    #[test]
    fn require_ca_rejects_key_usage_without_key_cert_sign() {
        let der = test_cert_der(
            IsCa::Ca(BasicConstraints::Unconstrained),
            vec![KeyUsagePurpose::DigitalSignature],
        );
        let err = require_ca_on(&der)
            .expect_err("keyUsage without keyCertSign must not be accepted as an issuer");
        assert_eq!(err.category, ErrorCategory::RootCaUntrusted);
    }

    // cA=true passes with keyCertSign asserted, and with no
    // keyUsage extension at all (keyUsage is enforced only where present).
    #[test]
    fn require_ca_accepts_valid_issuer() {
        let der = test_cert_der(
            IsCa::Ca(BasicConstraints::Unconstrained),
            vec![KeyUsagePurpose::KeyCertSign],
        );
        require_ca_on(&der).expect("cA=true with keyCertSign must be accepted");

        let der = test_cert_der(IsCa::Ca(BasicConstraints::Unconstrained), vec![]);
        require_ca_on(&der).expect("cA=true without a keyUsage extension must be accepted");
    }

    const LEAF_SERIAL: &[u8] = &[0x03, 0x9f];
    const OTHER_SERIAL: &[u8] = &[0x04, 0x11];

    // A CA, a leaf it issued (leaf issuer DN == CA subject DN), and a CA-signed
    // CRL revoking `revoked_serial`, all generated fresh per test.
    fn fake_ca_leaf_and_crl(revoked_serial: &[u8]) -> (Vec<u8>, Vec<u8>, String) {
        let ca_key = KeyPair::generate().expect("CA key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "dcap-verify test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_der = ca_params
            .self_signed(&ca_key)
            .expect("CA certificate")
            .der()
            .to_vec();
        let issuer = Issuer::new(ca_params, ca_key);

        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf_params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "dcap-verify test leaf");
        leaf_params.serial_number = Some(SerialNumber::from_slice(LEAF_SERIAL));
        let leaf_der = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("leaf certificate")
            .der()
            .to_vec();

        let crl_pem = CertificateRevocationListParams {
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
        .signed_by(&issuer)
        .expect("CRL")
        .pem()
        .expect("CRL PEM");

        (ca_der, leaf_der, crl_pem)
    }

    // Run the fake CRL through the full `check_crl` gate (signature against the
    // CA key, issuer DN match, validity window) to obtain the revoked set.
    fn revoked_entries(ca_der: &[u8], crl_pem: &str) -> Vec<RevokedEntry> {
        let (_, ca) = X509Certificate::from_der(ca_der).expect("CA DER");
        let ca_key = spki_verifying_key("test CRL", &ca).expect("CA verifying key");
        let now = date_time_ymd(2026, 6, 1).unix_timestamp();
        check_crl(
            "test CRL",
            crl_pem.as_bytes(),
            ca.subject().as_raw(),
            &ca_key,
            now,
        )
        .expect("a well-formed CA-signed CRL must pass check_crl")
    }

    // A CRL listing the leaf's serial, issued by the leaf's own CA, must make
    // the revocation gate reject a chain holding that leaf.
    #[test]
    fn crl_listing_leaf_serial_rejects_chain() {
        let (ca_der, leaf_der, crl_pem) = fake_ca_leaf_and_crl(LEAF_SERIAL);
        let revoked = revoked_entries(&ca_der, &crl_pem);
        assert_eq!(revoked.len(), 1, "the CRL revokes exactly one serial");

        let chain = CertChain {
            kind: ChainKind::QuotePck,
            ders: vec![leaf_der],
        };
        let parsed = chain.parse().expect("leaf chain parses");
        let err = ensure_none_revoked(&[&parsed], &revoked)
            .expect_err("a leaf listed in its issuer's CRL must be rejected");
        assert_eq!(err.category, ErrorCategory::CrlInvalid);
    }

    // The same CA-signed CRL revoking a different serial leaves the leaf alone:
    // the issuer matches, so only the serial comparison keeps the chain valid.
    #[test]
    fn crl_without_leaf_serial_passes_revocation_check() {
        let (ca_der, leaf_der, crl_pem) = fake_ca_leaf_and_crl(OTHER_SERIAL);
        let revoked = revoked_entries(&ca_der, &crl_pem);
        assert_eq!(revoked.len(), 1, "the CRL revokes exactly one serial");

        let chain = CertChain {
            kind: ChainKind::QuotePck,
            ders: vec![leaf_der],
        };
        let parsed = chain.parse().expect("leaf chain parses");
        ensure_none_revoked(&[&parsed], &revoked)
            .expect("a leaf whose serial the CRL does not list must pass");
    }

    // Revocation matching against Intel-shaped names: an entry carrying the real
    // issuer DN and the real serial of the "Intel SGX TCB Signing" cert must
    // reject prod-1's parsed TCB-info issuer chain; the same DN with a different
    // serial must not.
    #[test]
    fn revocation_entry_matches_real_tcb_signing_cert() {
        let chain = CertChain {
            kind: ChainKind::TcbInfoIssuer,
            ders: tcb_chain_ders(),
        };
        let parsed = chain.parse().expect("chain parses");
        let leaf = &parsed.certs[0];
        let entry = RevokedEntry {
            issuer_raw: leaf.issuer().as_raw().to_vec(),
            serial: normalized_serial(leaf.raw_serial()),
        };
        let err = ensure_none_revoked(&[&parsed], &[entry]).unwrap_err();
        assert_eq!(err.category, ErrorCategory::CrlInvalid);
        assert!(err.detail.contains("TCB Signing"), "{}", err.detail);

        let other = RevokedEntry {
            issuer_raw: leaf.issuer().as_raw().to_vec(),
            serial: vec![0xde, 0xad, 0xbe, 0xef],
        };
        ensure_none_revoked(&[&parsed], &[other])
            .expect("same issuer DN with a different serial must not match");
    }

    // Same for the quote-embedded PCK chain: the real PCK CA DN plus the real
    // PCK leaf serial, both read out of prod-1's captured quote, must reject.
    #[test]
    fn revocation_entry_matches_real_quote_pck_leaf() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/prod-1/quote.bin");
        let quote_bytes = fs::read(path).expect("quote.bin");
        let mut cursor: &[u8] = &quote_bytes;
        let quote = crate::types::quote::SgxQuote::read(&mut cursor).expect("quote parses");

        let chain = CertChain::from_pem(ChainKind::QuotePck, &quote.signature.cert_data)
            .expect("PCK chain PEM");
        let parsed = chain.parse().expect("PCK chain parses");
        let leaf = &parsed.certs[0];
        let entry = RevokedEntry {
            issuer_raw: leaf.issuer().as_raw().to_vec(),
            serial: normalized_serial(leaf.raw_serial()),
        };
        let err = ensure_none_revoked(&[&parsed], &[entry]).unwrap_err();
        assert_eq!(err.category, ErrorCategory::CrlInvalid);
        assert!(
            err.detail.contains("embedded in the quote"),
            "{}",
            err.detail
        );
    }

    // The certificate lower time bound is inclusive — a chain evaluated exactly
    // at its latest notBefore validates, one second before it rejects. (The
    // far-past fixture cannot pin this: with the bound broken, the CRL
    // thisUpdate check rejects with the same category.)
    #[test]
    fn cert_at_exact_not_before_validates_one_second_before_rejects() {
        let chain = CertChain {
            kind: ChainKind::TcbInfoIssuer,
            ders: tcb_chain_ders(),
        };
        let parsed = chain.parse().expect("chain parses");
        let latest_not_before = parsed
            .certs
            .iter()
            .map(|c| c.validity().not_before.timestamp())
            .max()
            .expect("chain is non-empty");
        assert!(parsed.validate(latest_not_before).is_ok());
        let err = parsed.validate(latest_not_before - 1).unwrap_err();
        assert_eq!(err.category, ErrorCategory::CertOrCrlTimeInvalid);
    }

    // Serial normalization strips leading zero octets. The revocation tests feed
    // both sides of the comparison through it, so a normalization regression
    // cancels out there and must be pinned directly.
    #[test]
    fn normalized_serial_strips_leading_zeros() {
        assert_eq!(normalized_serial(&[0x00, 0xa3]), vec![0xa3]);
        assert_eq!(normalized_serial(&[0x00, 0x00]), vec![0x00]);
        assert_eq!(normalized_serial(&[0x5a, 0x01]), vec![0x5a, 0x01]);
    }

    // Unparseable chain bytes classify by chain kind: the quote-embedded chain
    // is a quote-parse failure, collateral chains are collateral-parse failures.
    #[test]
    fn chain_parse_errors_carry_the_chain_kind_category() {
        let err = CertChain::from_pem(ChainKind::QuotePck, b"no certificates here")
            .err()
            .expect("garbage must not parse");
        assert_eq!(err.category, ErrorCategory::QuoteParse);
        let err = CertChain::from_pem(ChainKind::TcbInfoIssuer, b"no certificates here")
            .err()
            .expect("garbage must not parse");
        assert_eq!(err.category, ErrorCategory::CollateralParse);
    }

    // The chain-length cap admits exactly MAX_CHAIN_LEN certificates and
    // rejects one more.
    #[test]
    fn chain_length_cap_boundary() {
        let root_pem = ::pem::encode(&::pem::Pem::new("CERTIFICATE", tcb_chain_ders()[1].clone()));
        assert!(
            CertChain::from_pem(
                ChainKind::TcbInfoIssuer,
                root_pem.repeat(MAX_CHAIN_LEN).as_bytes()
            )
            .is_ok()
        );
        let err = CertChain::from_pem(
            ChainKind::TcbInfoIssuer,
            root_pem.repeat(MAX_CHAIN_LEN + 1).as_bytes(),
        )
        .err()
        .expect("an over-cap chain must not parse");
        assert_eq!(err.category, ErrorCategory::CollateralParse);
    }

    // The byte cap admits exactly MAX_CHAIN_PEM_LEN bytes and rejects one
    // more, before any base64/DER decoding happens.
    #[test]
    fn chain_byte_cap_boundary() {
        let root_pem = ::pem::encode(&::pem::Pem::new("CERTIFICATE", tcb_chain_ders()[1].clone()));
        let mut data = root_pem.into_bytes();
        data.resize(MAX_CHAIN_PEM_LEN, b' ');
        assert!(CertChain::from_pem(ChainKind::TcbInfoIssuer, &data).is_ok());
        data.push(b' ');
        let err = CertChain::from_pem(ChainKind::TcbInfoIssuer, &data)
            .err()
            .expect("an over-cap chain must not parse");
        assert_eq!(err.category, ErrorCategory::CollateralParse);
    }

    // Only trailing NULs and whitespace are trimmed — the deliberate PEM-trailer
    // leniency, pinned so it is neither widened nor silently dropped.
    #[test]
    fn trim_trailing_junk_semantics() {
        assert_eq!(trim_trailing_junk(b"abc\n\0 "), b"abc");
        assert_eq!(trim_trailing_junk(b"abc"), b"abc");
        assert_eq!(trim_trailing_junk(b"\0\n"), b"");
        assert_eq!(trim_trailing_junk(b""), b"");
        assert_eq!(trim_trailing_junk(b"\0abc"), b"\0abc");
    }
}
