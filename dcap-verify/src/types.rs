pub mod collateral;
pub mod qe_identity;
pub mod quote;
pub mod report;
pub mod tcb_info;

use crate::error::{ErrorCategory, VerifyError};

pub(crate) struct ByteReader<'a> {
    rest: &'a [u8],
}

impl<'a> ByteReader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { rest: data }
    }

    pub(crate) fn rest(&self) -> &'a [u8] {
        self.rest
    }

    pub(crate) fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8], VerifyError> {
        if n > self.rest.len() {
            return Err(VerifyError::new(
                ErrorCategory::QuoteParse,
                format!("{what} needs {n} bytes but only {} remain", self.rest.len()),
            ));
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    pub(crate) fn array<const N: usize>(&mut self, what: &str) -> Result<[u8; N], VerifyError> {
        let bytes = self.take(N, what)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    pub(crate) fn u16_le(&mut self, what: &str) -> Result<u16, VerifyError> {
        Ok(u16::from_le_bytes(self.array::<2>(what)?))
    }

    pub(crate) fn u32_le(&mut self, what: &str) -> Result<u32, VerifyError> {
        Ok(u32::from_le_bytes(self.array::<4>(what)?))
    }
}

#[cfg(test)]
mod tests {
    use super::ByteReader;

    // `rest` is the trailing-bytes contract callers use to detect data after a
    // parsed quote; it must return exactly the unconsumed tail.
    #[test]
    fn rest_returns_exactly_the_unconsumed_tail() {
        let data = [1u8, 2, 3, 4, 5];
        let mut r = ByteReader::new(&data);
        r.take(2, "head").expect("in bounds");
        assert_eq!(r.rest(), &[3, 4, 5]);
        r.take(3, "tail").expect("in bounds");
        assert_eq!(r.rest(), &[] as &[u8]);
    }
}
