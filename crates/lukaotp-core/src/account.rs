use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Algorithm {
    #[default]
    SHA1,
    SHA256,
    SHA512,
}

/// TOTP account. The `secret` field is wrapped in `SecretBox` to prevent
/// accidental leakage via Debug/Display/log.
#[derive(Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub issuer: String,
    pub label: String,
    #[serde(with = "secret_bytes_serde")]
    pub secret: SecretBox<SecretBytes>,
    #[serde(default)]
    pub algorithm: Algorithm,
    #[serde(default = "default_digits")]
    pub digits: u8,
    #[serde(default = "default_period")]
    pub period: u64,
}

/// Newtype wrapper for raw TOTP secret bytes. Zeroized on drop.
#[derive(Clone, Zeroize, Serialize, Deserialize)]
pub struct SecretBytes(pub Vec<u8>);

impl secrecy::SerializableSecret for SecretBytes {}
impl secrecy::CloneableSecret for SecretBytes {}
impl zeroize::ZeroizeOnDrop for SecretBytes {}

fn default_digits() -> u8 {
    6
}
fn default_period() -> u64 {
    30
}

impl Account {
    pub fn new(issuer: &str, label: &str, secret_base32: &str) -> Option<Self> {
        Self::with_params(
            issuer,
            label,
            secret_base32,
            Algorithm::default(),
            default_digits(),
            default_period(),
        )
    }

    /// Like [`Account::new`] but with explicit algorithm/digits/period, for
    /// callers (e.g. QR/otpauth import) that must honor values parsed from
    /// an external source rather than assuming RFC 6238 defaults.
    pub fn with_params(
        issuer: &str,
        label: &str,
        secret_base32: &str,
        algorithm: Algorithm,
        digits: u8,
        period: u64,
    ) -> Option<Self> {
        // Keep this constructor safe for every caller, not just the strict
        // otpauth parser. RFC 6238 applications supported by LukaOTP use 6
        // or 8 digits and need a non-zero time step.
        if !matches!(digits, 6 | 8) || period == 0 || period > 300 {
            return None;
        }
        let decoded = data_encoding::BASE32_NOPAD
            .decode(secret_base32.to_uppercase().replace(' ', "").as_bytes())
            .ok()?;
        Some(Self {
            id: uuid::Uuid::new_v4().to_string(),
            issuer: issuer.to_string(),
            label: label.to_string(),
            secret: SecretBox::new(Box::new(SecretBytes(decoded))),
            algorithm,
            digits,
            period,
        })
    }
}

mod secret_bytes_serde {
    use super::SecretBytes;
    use secrecy::{ExposeSecret, SecretBox};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(secret: &SecretBox<SecretBytes>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let b32 = data_encoding::BASE32_NOPAD.encode(&secret.expose_secret().0);
        serializer.serialize_str(&b32)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SecretBox<SecretBytes>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = data_encoding::BASE32_NOPAD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)?;
        Ok(SecretBox::new(Box::new(SecretBytes(bytes))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_create_account_valid_base32() {
        let account = Account::new("GitHub", "user@example.com", "JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(account.issuer, "GitHub");
        assert_eq!(account.label, "user@example.com");
        assert_eq!(account.digits, 6);
        assert_eq!(account.period, 30);
        assert_eq!(account.algorithm, Algorithm::SHA1);
        assert!(!account.secret.expose_secret().0.is_empty());
    }

    #[test]
    fn test_create_account_invalid_base32() {
        assert!(Account::new("Test", "test", "!!!INVALID!!!").is_none());
    }

    #[test]
    fn test_explicit_params_reject_unsupported_totp_values() {
        assert!(
            Account::with_params("Test", "test", "JBSWY3DPEHPK3PXP", Algorithm::SHA1, 7, 30)
                .is_none()
        );
        assert!(
            Account::with_params("Test", "test", "JBSWY3DPEHPK3PXP", Algorithm::SHA1, 6, 0)
                .is_none()
        );
        assert!(
            Account::with_params("Test", "test", "JBSWY3DPEHPK3PXP", Algorithm::SHA1, 6, 301)
                .is_none()
        );
    }

    #[test]
    fn test_account_serialization_roundtrip() {
        let account = Account::new("AWS", "admin@co.com", "JBSWY3DPEHPK3PXP").unwrap();
        let json = serde_json::to_string(&account).unwrap();
        assert!(json.contains("JBSWY3DPEHPK3PXP"));
        let restored: Account = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.issuer, "AWS");
        assert_eq!(
            restored.secret.expose_secret().0,
            account.secret.expose_secret().0
        );
    }

    #[test]
    fn test_algorithm_default() {
        assert_eq!(Algorithm::default(), Algorithm::SHA1);
    }

    #[test]
    fn test_secret_bytes_length() {
        let account = Account::new("Test", "test", "JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(account.secret.expose_secret().0.len(), 10);
    }
}
