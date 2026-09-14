//! Strict parser for `otpauth://totp/` provisioning URIs (as produced by QR
//! codes from GitHub/Google/etc). Only the TOTP variant is accepted — HOTP
//! and any other scheme/type are rejected outright, with no fallback
//! interpretation.
use crate::account::Algorithm;

/// Result of successfully parsing an `otpauth://totp/` URI. `secret_base32`
/// is still Base32 text (not yet decoded into `SecretBytes`); callers should
/// hand it to `Account::new` promptly and avoid retaining or logging it.
pub struct ParsedOtpAuth {
    pub issuer: String,
    pub label: String,
    pub secret_base32: String,
    pub algorithm: Algorithm,
    pub digits: u8,
    pub period: u64,
}

/// Parse errors carry no user input (not the secret, not the raw URI) so
/// they can be surfaced to the UI or logs without leaking QR content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpAuthError {
    InvalidUri,
    UnsupportedScheme,
    UnsupportedType,
    MissingSecret,
    InvalidSecret,
    MissingIssuer,
    MissingLabel,
    IssuerMismatch,
    InvalidAlgorithm,
    InvalidDigits,
    InvalidPeriod,
}

impl std::fmt::Display for OtpAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            OtpAuthError::InvalidUri => "二维码内容不是合法的 URI",
            OtpAuthError::UnsupportedScheme => "二维码内容不是 otpauth:// 格式",
            OtpAuthError::UnsupportedType => "仅支持 TOTP 类型（otpauth://totp/）",
            OtpAuthError::MissingSecret => "二维码缺少 secret 参数",
            OtpAuthError::InvalidSecret => "secret 不是合法的 Base32 编码",
            OtpAuthError::MissingIssuer => "二维码缺少 issuer 信息",
            OtpAuthError::MissingLabel => "二维码缺少账户名称",
            OtpAuthError::IssuerMismatch => "label 与 issuer 参数不一致",
            OtpAuthError::InvalidAlgorithm => "不支持的 algorithm 参数",
            OtpAuthError::InvalidDigits => "digits 参数必须是 6 或 8",
            OtpAuthError::InvalidPeriod => "period 参数必须是 1-300 之间的整数",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for OtpAuthError {}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

/// Strictly parse and validate an `otpauth://totp/` provisioning URI.
///
/// Rejects anything that is not exactly `otpauth://totp/...`, validates the
/// Base32 secret, cross-checks issuer consistency between the label prefix
/// and the `issuer` query parameter, and only accepts known-safe
/// algorithm/digits/period values.
pub fn parse_otpauth_uri(uri: &str) -> Result<ParsedOtpAuth, OtpAuthError> {
    let parsed = url::Url::parse(uri).map_err(|_| OtpAuthError::InvalidUri)?;

    if parsed.scheme() != "otpauth" {
        return Err(OtpAuthError::UnsupportedScheme);
    }
    if parsed.host_str() != Some("totp") {
        return Err(OtpAuthError::UnsupportedType);
    }

    let raw_label = percent_decode(parsed.path().trim_start_matches('/'));
    let (label_issuer, account_name) = match raw_label.split_once(':') {
        Some((issuer, name)) => (Some(issuer.trim().to_string()), name.trim().to_string()),
        None => (None, raw_label.trim().to_string()),
    };
    if account_name.is_empty() {
        return Err(OtpAuthError::MissingLabel);
    }

    let mut secret: Option<String> = None;
    let mut issuer_param: Option<String> = None;
    let mut algorithm: Algorithm = Algorithm::SHA1;
    let mut digits: u8 = 6;
    let mut period: u64 = 30;

    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "secret" => secret = Some(value.into_owned()),
            "issuer" => issuer_param = Some(value.into_owned()),
            "algorithm" => {
                algorithm = match value.to_uppercase().as_str() {
                    "SHA1" => Algorithm::SHA1,
                    "SHA256" => Algorithm::SHA256,
                    "SHA512" => Algorithm::SHA512,
                    _ => return Err(OtpAuthError::InvalidAlgorithm),
                };
            }
            "digits" => {
                digits = value
                    .parse::<u8>()
                    .map_err(|_| OtpAuthError::InvalidDigits)?;
                if digits != 6 && digits != 8 {
                    return Err(OtpAuthError::InvalidDigits);
                }
            }
            "period" => {
                period = value
                    .parse::<u64>()
                    .map_err(|_| OtpAuthError::InvalidPeriod)?;
                if period == 0 || period > 300 {
                    return Err(OtpAuthError::InvalidPeriod);
                }
            }
            _ => {}
        }
    }

    let secret_raw = secret.ok_or(OtpAuthError::MissingSecret)?;
    let normalized_secret = secret_raw.to_uppercase().replace(' ', "");
    if normalized_secret.is_empty() {
        return Err(OtpAuthError::InvalidSecret);
    }
    let decoded = data_encoding::BASE32_NOPAD
        .decode(normalized_secret.as_bytes())
        .map_err(|_| OtpAuthError::InvalidSecret)?;
    if decoded.is_empty() {
        return Err(OtpAuthError::InvalidSecret);
    }

    let issuer = match (label_issuer, issuer_param) {
        (Some(from_label), Some(from_param)) => {
            if from_label != from_param {
                return Err(OtpAuthError::IssuerMismatch);
            }
            from_param
        }
        (Some(from_label), None) => from_label,
        (None, Some(from_param)) => from_param,
        (None, None) => return Err(OtpAuthError::MissingIssuer),
    };
    if issuer.is_empty() {
        return Err(OtpAuthError::MissingIssuer);
    }

    Ok(ParsedOtpAuth {
        issuer,
        label: account_name,
        secret_base32: normalized_secret,
        algorithm,
        digits,
        period,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30";

    #[test]
    fn parses_valid_uri_with_all_fields() {
        let parsed = parse_otpauth_uri(VALID).unwrap();
        assert_eq!(parsed.issuer, "GitHub");
        assert_eq!(parsed.label, "alice@example.com");
        assert_eq!(parsed.secret_base32, "JBSWY3DPEHPK3PXP");
        assert_eq!(parsed.algorithm, Algorithm::SHA1);
        assert_eq!(parsed.digits, 6);
        assert_eq!(parsed.period, 30);
    }

    #[test]
    fn applies_defaults_when_optional_params_absent() {
        let uri = "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP";
        let parsed = parse_otpauth_uri(uri).unwrap();
        assert_eq!(parsed.algorithm, Algorithm::SHA1);
        assert_eq!(parsed.digits, 6);
        assert_eq!(parsed.period, 30);
    }

    #[test]
    fn derives_issuer_from_label_when_query_param_absent() {
        let uri = "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP";
        let parsed = parse_otpauth_uri(uri).unwrap();
        assert_eq!(parsed.issuer, "GitHub");
        assert_eq!(parsed.label, "alice@example.com");
    }

    #[test]
    fn derives_issuer_from_query_param_when_label_has_no_prefix() {
        let uri = "otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";
        let parsed = parse_otpauth_uri(uri).unwrap();
        assert_eq!(parsed.issuer, "GitHub");
        assert_eq!(parsed.label, "alice@example.com");
    }

    #[test]
    fn rejects_non_otpauth_scheme() {
        let uri = "https://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP";
        assert!(matches!(
            parse_otpauth_uri(uri),
            Err(OtpAuthError::UnsupportedScheme)
        ));
    }

    #[test]
    fn rejects_hotp_type() {
        let uri = "otpauth://hotp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&counter=0";
        assert!(matches!(
            parse_otpauth_uri(uri),
            Err(OtpAuthError::UnsupportedType)
        ));
    }

    #[test]
    fn rejects_malformed_uri() {
        assert!(matches!(
            parse_otpauth_uri("not a uri"),
            Err(OtpAuthError::InvalidUri)
        ));
    }

    #[test]
    fn rejects_missing_secret() {
        let uri = "otpauth://totp/GitHub:alice@example.com?issuer=GitHub";
        assert!(matches!(
            parse_otpauth_uri(uri),
            Err(OtpAuthError::MissingSecret)
        ));
    }

    #[test]
    fn rejects_invalid_base32_secret() {
        let uri = "otpauth://totp/GitHub:alice@example.com?secret=not-base32!!!&issuer=GitHub";
        assert!(matches!(
            parse_otpauth_uri(uri),
            Err(OtpAuthError::InvalidSecret)
        ));
    }

    #[test]
    fn rejects_missing_label() {
        let uri = "otpauth://totp/?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";
        assert!(matches!(
            parse_otpauth_uri(uri),
            Err(OtpAuthError::MissingLabel)
        ));
    }

    #[test]
    fn rejects_missing_issuer_when_no_prefix_and_no_param() {
        let uri = "otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP";
        assert!(matches!(
            parse_otpauth_uri(uri),
            Err(OtpAuthError::MissingIssuer)
        ));
    }

    #[test]
    fn rejects_issuer_mismatch_between_label_and_param() {
        let uri = "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Google";
        assert!(matches!(
            parse_otpauth_uri(uri),
            Err(OtpAuthError::IssuerMismatch)
        ));
    }

    #[test]
    fn rejects_unsupported_algorithm() {
        let uri = "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=MD5";
        assert!(matches!(
            parse_otpauth_uri(uri),
            Err(OtpAuthError::InvalidAlgorithm)
        ));
    }

    #[test]
    fn accepts_sha256_and_sha512() {
        let uri256 = "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=sha256";
        assert_eq!(
            parse_otpauth_uri(uri256).unwrap().algorithm,
            Algorithm::SHA256
        );
        let uri512 = "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA512";
        assert_eq!(
            parse_otpauth_uri(uri512).unwrap().algorithm,
            Algorithm::SHA512
        );
    }

    #[test]
    fn rejects_invalid_digits() {
        let uri = "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=4";
        assert!(matches!(
            parse_otpauth_uri(uri),
            Err(OtpAuthError::InvalidDigits)
        ));
        let uri_nan = "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=abc";
        assert!(matches!(
            parse_otpauth_uri(uri_nan),
            Err(OtpAuthError::InvalidDigits)
        ));
    }

    #[test]
    fn accepts_eight_digits() {
        let uri = "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=8";
        assert_eq!(parse_otpauth_uri(uri).unwrap().digits, 8);
    }

    #[test]
    fn rejects_invalid_period() {
        let uri_zero = "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&period=0";
        assert!(matches!(
            parse_otpauth_uri(uri_zero),
            Err(OtpAuthError::InvalidPeriod)
        ));
        let uri_huge = "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&period=99999";
        assert!(matches!(
            parse_otpauth_uri(uri_huge),
            Err(OtpAuthError::InvalidPeriod)
        ));
    }

    #[test]
    fn error_messages_never_contain_secret_or_raw_uri() {
        let uri = "otpauth://totp/GitHub:alice@example.com?secret=SUPERSECRETVALUE&issuer=Google";
        let msg = match parse_otpauth_uri(uri) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected an error"),
        };
        assert!(!msg.contains("SUPERSECRETVALUE"));
        assert!(!msg.contains(uri));
    }

    #[test]
    fn handles_percent_encoded_label() {
        let uri =
            "otpauth://totp/Google%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Google";
        let parsed = parse_otpauth_uri(uri).unwrap();
        assert_eq!(parsed.issuer, "Google");
        assert_eq!(parsed.label, "alice@example.com");
    }
}
