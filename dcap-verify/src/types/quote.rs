use super::ByteReader;
use super::report::SgxReportBody;
use crate::error::{ErrorCategory, VerifyError};

pub const QUOTE_SIGNED_LEN: usize = 432;

const QUOTE_VERSION_3: u16 = 3;
const ATT_KEY_TYPE_ECDSA_P256: u16 = 2;
const CERT_DATA_TYPE_PCK_CHAIN: u16 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SgxQuoteHeader {
    pub version: u16,
    pub att_key_type: u16,
    pub reserved: u32,
    pub qe_svn: u16,
    pub pce_svn: u16,
    pub qe_vendor_id: [u8; 16],
    pub user_data: [u8; 20],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SgxEcdsaSignature {
    pub isv_signature: [u8; 64],
    pub attestation_pub_key: [u8; 64],
    pub qe_report: SgxReportBody,
    pub qe_report_raw: [u8; 384],
    pub qe_report_signature: [u8; 64],
    pub qe_auth_data: Vec<u8>,
    pub cert_data_type: u16,
    pub cert_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SgxQuote {
    pub header: SgxQuoteHeader,
    pub report_body: SgxReportBody,
    pub signature: SgxEcdsaSignature,
    signed_bytes: Vec<u8>,
}

impl SgxQuote {
    /// Parse a DCAP v3 quote, advancing `bytes` past the consumed input on success.
    /// On failure returns a [`crate::error::VerifyError`], whose
    /// [`VerifyError::category`] classifies the failure.
    pub fn read(bytes: &mut &[u8]) -> Result<Self, VerifyError> {
        let input = *bytes;
        let mut r = ByteReader::new(input);

        let version = r.u16_le("quote version")?;
        if version != QUOTE_VERSION_3 {
            return Err(VerifyError::new(
                ErrorCategory::QuoteParse,
                format!(
                    "only quote structure version {QUOTE_VERSION_3} is supported, header says {version}"
                ),
            ));
        }
        let att_key_type = r.u16_le("attestation key type")?;
        if att_key_type != ATT_KEY_TYPE_ECDSA_P256 {
            return Err(VerifyError::new(
                ErrorCategory::QuoteParse,
                format!(
                    "only ECDSA-P256 attestation keys (type {ATT_KEY_TYPE_ECDSA_P256}) are supported, header says {att_key_type}"
                ),
            ));
        }
        let reserved = r.u32_le("header reserved field")?;
        let qe_svn = r.u16_le("QE SVN")?;
        let pce_svn = r.u16_le("PCE SVN")?;
        let qe_vendor_id = r.array::<16>("QE vendor id")?;
        let user_data = r.array::<20>("header user data")?;
        let header = SgxQuoteHeader {
            version,
            att_key_type,
            reserved,
            qe_svn,
            pce_svn,
            qe_vendor_id,
            user_data,
        };

        let report_body = SgxReportBody::parse(r.take(384, "report body")?)?;
        let signed_bytes = input
            .get(..QUOTE_SIGNED_LEN)
            .ok_or_else(|| {
                VerifyError::new(
                    ErrorCategory::QuoteParse,
                    "quote shorter than its signed portion".to_string(),
                )
            })?
            .to_vec();

        let sig_len = r.u32_le("signature section length")? as usize;
        let sig_raw = r.take(sig_len, "signature section")?;
        let signature = Self::read_signature(sig_raw)?;

        *bytes = r.rest();
        Ok(Self {
            header,
            report_body,
            signature,
            signed_bytes,
        })
    }

    fn read_signature(raw: &[u8]) -> Result<SgxEcdsaSignature, VerifyError> {
        let mut r = ByteReader::new(raw);
        let isv_signature = r.array::<64>("quote body signature")?;
        let attestation_pub_key = r.array::<64>("attestation public key")?;
        let qe_report_raw = r.array::<384>("QE report")?;
        let qe_report = SgxReportBody::parse(&qe_report_raw)?;
        let qe_report_signature = r.array::<64>("QE report signature")?;
        let auth_len = r.u16_le("QE authentication data length")? as usize;
        let qe_auth_data = r.take(auth_len, "QE authentication data")?.to_vec();
        let cert_data_type = r.u16_le("certification data type")?;
        if cert_data_type != CERT_DATA_TYPE_PCK_CHAIN {
            return Err(VerifyError::new(
                ErrorCategory::QuoteParse,
                format!(
                    "certification data type {cert_data_type} is not supported; expected an embedded PCK chain (type {CERT_DATA_TYPE_PCK_CHAIN})"
                ),
            ));
        }
        let cert_len = r.u32_le("certification data length")? as usize;
        let cert_data = r.take(cert_len, "certification data")?.to_vec();
        if !r.rest().is_empty() {
            return Err(VerifyError::new(
                ErrorCategory::QuoteParse,
                format!(
                    "signature section declares {} unconsumed bytes after the certification data",
                    r.rest().len()
                ),
            ));
        }
        Ok(SgxEcdsaSignature {
            isv_signature,
            attestation_pub_key,
            qe_report,
            qe_report_raw,
            qe_report_signature,
            qe_auth_data,
            cert_data_type,
            cert_data,
        })
    }

    pub fn signed_bytes(&self) -> &[u8] {
        &self.signed_bytes
    }
}

// Fixed v3 layout offsets for the peek helpers: 48-byte header, then the report
// body, which places MRENCLAVE at body offset 64 and report_data at body offset
// 320. Kept next to the parser so the layout lives in exactly one crate; the
// peek/parse agreement is pinned by a fixture test.
const PEEK_MRENCLAVE_OFFSET: usize = 48 + 64;
const PEEK_REPORT_DATA_OFFSET: usize = 48 + 320;

/// Borrow the MRENCLAVE field out of raw v3 quote bytes without a full parse.
/// For pre-verification peeking only — proves nothing about authenticity.
pub fn peek_mrenclave(quote: &[u8]) -> Option<&[u8; 32]> {
    quote
        .get(PEEK_MRENCLAVE_OFFSET..PEEK_MRENCLAVE_OFFSET + 32)?
        .try_into()
        .ok()
}

/// Borrow the 64-byte report_data field out of raw v3 quote bytes without a
/// full parse. For pre-verification peeking only — proves nothing about
/// authenticity.
pub fn peek_report_data(quote: &[u8]) -> Option<&[u8; 64]> {
    quote
        .get(PEEK_REPORT_DATA_OFFSET..PEEK_REPORT_DATA_OFFSET + 64)?
        .try_into()
        .ok()
}
