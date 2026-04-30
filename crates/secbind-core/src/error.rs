use chrono::{DateTime, Utc};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecBindError {
    #[error("fingerprint mismatch: secret bound to different context")]
    FingerprintMismatch,

    #[error("antigen violation: {antigen}")]
    AntigenViolation { antigen: String },

    #[error("envelope expired at {expired_at}")]
    EnvelopeExpired { expired_at: DateTime<Utc> },

    #[error("signature invalid")]
    SignatureInvalid,

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("KEM error: {0}")]
    KemError(String),

    #[error("serialization error: {0}")]
    SerializationError(String),

    #[error("unsupported envelope version: {0}")]
    UnsupportedEnvelopeVersion(String),

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error("env var not found: {0}")]
    EnvVarNotFound(String),
}
