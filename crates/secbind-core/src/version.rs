use crate::error::SecBindError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeVersion {
    V1,
    V2,
}

impl EnvelopeVersion {
    pub const fn as_str(self) -> &'static str {
        match self {
            EnvelopeVersion::V1 => "1",
            EnvelopeVersion::V2 => "2",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, SecBindError> {
        match raw {
            "1" => Ok(EnvelopeVersion::V1),
            "2" => Ok(EnvelopeVersion::V2),
            other => Err(SecBindError::UnsupportedEnvelopeVersion(other.to_string())),
        }
    }
}

pub const LATEST_ENVELOPE_VERSION: EnvelopeVersion = EnvelopeVersion::V2;
