use super::ByteReader;
use crate::error::{ErrorCategory, VerifyError};

pub type MREnclave = [u8; 32];

pub const REPORT_BODY_LEN: usize = 384;

const ATTRIBUTE_FLAG_DEBUG: u64 = 1 << 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SgxReportBody {
    pub cpu_svn: [u8; 16],
    pub misc_select: [u8; 4],
    pub isv_ext_prod_id: [u8; 16],
    pub attributes: [u8; 16],
    pub mrenclave: MREnclave,
    pub mrsigner: [u8; 32],
    pub config_id: [u8; 64],
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    pub config_svn: u16,
    pub isv_family_id: [u8; 16],
    pub sgx_report_data_bytes: [u8; 64],
}

impl SgxReportBody {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self, VerifyError> {
        if raw.len() != REPORT_BODY_LEN {
            return Err(VerifyError::new(
                ErrorCategory::QuoteParse,
                format!(
                    "report body must be {REPORT_BODY_LEN} bytes, got {}",
                    raw.len()
                ),
            ));
        }
        let mut r = ByteReader::new(raw);
        let cpu_svn = r.array::<16>("cpu_svn")?;
        let misc_select = r.array::<4>("misc_select")?;
        r.take(12, "report reserved1")?;
        let isv_ext_prod_id = r.array::<16>("isv_ext_prod_id")?;
        let attributes = r.array::<16>("attributes")?;
        let mrenclave = r.array::<32>("mrenclave")?;
        r.take(32, "report reserved2")?;
        let mrsigner = r.array::<32>("mrsigner")?;
        r.take(32, "report reserved3")?;
        let config_id = r.array::<64>("config_id")?;
        let isv_prod_id = r.u16_le("isv_prod_id")?;
        let isv_svn = r.u16_le("isv_svn")?;
        let config_svn = r.u16_le("config_svn")?;
        r.take(42, "report reserved4")?;
        let isv_family_id = r.array::<16>("isv_family_id")?;
        let sgx_report_data_bytes = r.array::<64>("report_data")?;
        Ok(Self {
            cpu_svn,
            misc_select,
            isv_ext_prod_id,
            attributes,
            mrenclave,
            mrsigner,
            config_id,
            isv_prod_id,
            isv_svn,
            config_svn,
            isv_family_id,
            sgx_report_data_bytes,
        })
    }

    pub fn attribute_flags(&self) -> u64 {
        let mut flags = [0u8; 8];
        flags.copy_from_slice(&self.attributes[..8]);
        u64::from_le_bytes(flags)
    }

    pub fn is_debug(&self) -> bool {
        self.attribute_flags() & ATTRIBUTE_FLAG_DEBUG != 0
    }
}
