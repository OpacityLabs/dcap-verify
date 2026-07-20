use std::fmt;
use std::marker::PhantomData;

use serde::Deserialize;
use serde::de::{self, DeserializeOwned, Deserializer, MapAccess, Visitor};
use serde_json::value::RawValue;

use super::qe_identity::QeIdentity;
use super::tcb_info::TcbInfo;

#[derive(Debug, Clone, Deserialize)]
pub struct SgxCollateral {
    pub version: u32,
    pub root_ca_crl: String,
    pub pck_crl: String,
    pub tcb_info_issuer_chain: String,
    pub pck_crl_issuer_chain: String,
    pub qe_identity_issuer_chain: String,
    pub tcb_info: SignedTcbInfo,
    pub qe_identity: SignedQeIdentity,
}

pub type SignedTcbInfo = Signed<TcbInfo>;
pub type SignedQeIdentity = Signed<QeIdentity>;

/// A collateral document paired with the exact JSON bytes its signature covers.
/// The signature is verified over `body_json` verbatim, so the raw text is
/// retained alongside the parsed `body`.
#[derive(Debug, Clone)]
pub struct Signed<T> {
    pub body_json: String,
    pub body: T,
    pub signature_hex: String,
}

/// A body type that appears inside a `{ <field>: {...}, "signature": "..." }`
/// envelope, tagging the JSON key that carries it.
pub trait SignedBody {
    const WIRE_FIELD: &'static str;
}

impl SignedBody for TcbInfo {
    const WIRE_FIELD: &'static str = "tcbInfo";
}

impl SignedBody for QeIdentity {
    const WIRE_FIELD: &'static str = "enclaveIdentity";
}

impl<'de, T> Deserialize<'de> for Signed<T>
where
    T: SignedBody + DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SignedVisitor<T>(PhantomData<T>);

        impl<'de, T> Visitor<'de> for SignedVisitor<T>
        where
            T: SignedBody + DeserializeOwned,
        {
            type Value = Signed<T>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a signed {} document", T::WIRE_FIELD)
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut body_raw: Option<Box<RawValue>> = None;
                let mut signature_hex: Option<String> = None;
                while let Some(key) = map.next_key::<String>()? {
                    if key == T::WIRE_FIELD {
                        if body_raw.is_some() {
                            return Err(de::Error::duplicate_field(T::WIRE_FIELD));
                        }
                        body_raw = Some(map.next_value()?);
                    } else if key == "signature" {
                        if signature_hex.is_some() {
                            return Err(de::Error::duplicate_field("signature"));
                        }
                        signature_hex = Some(map.next_value()?);
                    } else {
                        map.next_value::<de::IgnoredAny>()?;
                    }
                }
                let body_raw = body_raw.ok_or_else(|| de::Error::missing_field(T::WIRE_FIELD))?;
                let signature_hex =
                    signature_hex.ok_or_else(|| de::Error::missing_field("signature"))?;
                let body = serde_json::from_str(body_raw.get()).map_err(de::Error::custom)?;
                Ok(Signed {
                    body_json: body_raw.get().to_owned(),
                    body,
                    signature_hex,
                })
            }
        }

        deserializer.deserialize_map(SignedVisitor(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::SignedTcbInfo;

    // The deserializer's `expecting` text names the wire field so a
    // wrong-shaped document is diagnosable from the serde error alone.
    #[test]
    fn signed_deserialize_error_names_the_document() {
        let err = serde_json::from_str::<SignedTcbInfo>("42")
            .expect_err("a bare number is not a signed document");
        let msg = err.to_string();
        assert!(msg.contains("a signed tcbInfo document"), "{msg}");
    }
}
