use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::crypto::{seal as crypto_seal, SealedSecret};
use crate::error::SecBindError;
use crate::fingerprint::RuntimeContext;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Antigens {
    pub not_after: Option<DateTime<Utc>>,
    pub environment: Option<String>,
    pub allowed_cidr: Option<String>,
    pub custom_tags: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SecEnvFile {
    pub version: String,
    pub env_label: String,
    pub sealing_public_key: String,
    pub verify_key: String,
    pub antigens: Antigens,
    pub secrets: HashMap<String, SealedSecret>,
    pub envelope_signature: Option<String>,
}

impl SecEnvFile {
    pub fn new(env_label: &str, ttl_hours: Option<u64>) -> (SecEnvFile, Vec<u8>) {
        use pqcrypto_traits::kem::{PublicKey as KemPk, SecretKey as KemSk};

        let (kem_pk, kem_sk) = pqcrypto_mlkem::mlkem768::keypair();
        let (dsa_vk, dsa_sk) = mldsa65::keypair();

        let not_after = ttl_hours.map(|h| Utc::now() + Duration::hours(h as i64));

        let antigens = Antigens {
            not_after,
            environment: Some(env_label.to_string()),
            ..Default::default()
        };

        let mut combined_sk = Vec::with_capacity(kem_sk.as_bytes().len() + dsa_sk.as_bytes().len());
        combined_sk.extend_from_slice(kem_sk.as_bytes());
        combined_sk.extend_from_slice(dsa_sk.as_bytes());

        let file = SecEnvFile {
            version: "1".to_string(),
            env_label: env_label.to_string(),
            sealing_public_key: STANDARD.encode(kem_pk.as_bytes()),
            verify_key: STANDARD.encode(dsa_vk.as_bytes()),
            antigens,
            secrets: HashMap::new(),
            envelope_signature: None,
        };

        (file, combined_sk)
    }

    pub fn signable_bytes(&self) -> Result<Vec<u8>, SecBindError> {
        let mut val = serde_json::to_value(self)
            .map_err(|e| SecBindError::SerializationError(e.to_string()))?;

        if let Some(obj) = val.as_object_mut() {
            obj.remove("envelope_signature");
        }

        let sorted: BTreeMap<String, Value> = match val {
            Value::Object(map) => map.into_iter().collect(),
            _ => {
                return Err(SecBindError::SerializationError(
                    "expected JSON object".to_string(),
                ))
            }
        };

        let canonical = serde_json::to_string(&sorted)
            .map_err(|e| SecBindError::SerializationError(e.to_string()))?;

        Ok(canonical.into_bytes())
    }

    pub fn sign(&mut self, dsa_sk_bytes: &[u8]) -> Result<(), SecBindError> {
        let sk = mldsa65::SecretKey::from_bytes(dsa_sk_bytes)
            .map_err(|e| SecBindError::KemError(e.to_string()))?;
        let msg = self.signable_bytes()?;
        let sig = mldsa65::detached_sign(&msg, &sk);
        self.envelope_signature = Some(STANDARD.encode(sig.as_bytes()));
        Ok(())
    }

    pub fn verify_signature(&self) -> Result<(), SecBindError> {
        let sig_b64 = self
            .envelope_signature
            .as_ref()
            .ok_or(SecBindError::SignatureInvalid)?;
        let sig_bytes = STANDARD
            .decode(sig_b64)
            .map_err(|_| SecBindError::SignatureInvalid)?;
        let vk_bytes = STANDARD
            .decode(&self.verify_key)
            .map_err(|_| SecBindError::SignatureInvalid)?;

        let sig = mldsa65::DetachedSignature::from_bytes(&sig_bytes)
            .map_err(|_| SecBindError::SignatureInvalid)?;
        let vk = mldsa65::PublicKey::from_bytes(&vk_bytes)
            .map_err(|_| SecBindError::SignatureInvalid)?;

        let msg = self.signable_bytes()?;

        mldsa65::verify_detached_signature(&sig, &msg, &vk)
            .map_err(|_| SecBindError::SignatureInvalid)
    }

    pub fn check_antigens(&self, ctx: &RuntimeContext) -> Result<(), SecBindError> {
        if let Some(not_after) = self.antigens.not_after {
            if Utc::now() > not_after {
                return Err(SecBindError::EnvelopeExpired {
                    expired_at: not_after,
                });
            }
        }

        if let Some(env) = &self.antigens.environment {
            if env != &ctx.env_label {
                return Err(SecBindError::AntigenViolation {
                    antigen: format!("environment: expected '{}', got '{}'", env, ctx.env_label),
                });
            }
        }

        Ok(())
    }

    pub fn add_secret(
        &mut self,
        key: &str,
        value: &[u8],
        ctx: &RuntimeContext,
    ) -> Result<(), SecBindError> {
        let pk_bytes = STANDARD
            .decode(&self.sealing_public_key)
            .map_err(|e| SecBindError::SerializationError(e.to_string()))?;
        let fingerprint = ctx.digest();
        let sealed = crypto_seal(value, &pk_bytes, &fingerprint)?;
        self.secrets.insert(key.to_string(), sealed);
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, SecBindError> {
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str(&content).map_err(|e| SecBindError::SerializationError(e.to_string()))
    }

    pub fn save(&self, path: &Path) -> Result<(), SecBindError> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| SecBindError::SerializationError(e.to_string()))?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
