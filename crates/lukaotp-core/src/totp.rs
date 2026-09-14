use hmac::digest::{KeyInit, Mac};
use hmac::SimpleHmac;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::account::Algorithm;

pub fn generate_totp(
    secret: &[u8],
    timestamp: u64,
    period: u64,
    digits: u8,
    algorithm: Algorithm,
) -> String {
    let time_step = timestamp / period;
    let time_bytes = time_step.to_be_bytes();

    let hash = match algorithm {
        Algorithm::SHA1 => hmac_compute::<Sha1>(secret, &time_bytes),
        Algorithm::SHA256 => hmac_compute::<Sha256>(secret, &time_bytes),
        Algorithm::SHA512 => hmac_compute::<Sha512>(secret, &time_bytes),
    };

    truncate(&hash, digits)
}

pub fn remaining_seconds(period: u64, timestamp: u64) -> u64 {
    period - (timestamp % period)
}

fn hmac_compute<D>(secret: &[u8], message: &[u8]) -> Vec<u8>
where
    D: hmac::digest::Digest + hmac::digest::core_api::BlockSizeUser,
    SimpleHmac<D>: Mac + KeyInit,
{
    let mut mac =
        <SimpleHmac<D> as KeyInit>::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn truncate(hash: &[u8], digits: u8) -> String {
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let code = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    let modulus = 10u32.pow(digits as u32);
    format!("{:0>width$}", code % modulus, width = digits as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_SHA1: &[u8] = b"12345678901234567890";
    const SECRET_SHA256: &[u8] = b"12345678901234567890123456789012";
    const SECRET_SHA512: &[u8] =
        b"1234567890123456789012345678901234567890123456789012345678901234";

    #[test]
    fn test_rfc6238_sha1_8digits() {
        let cases: Vec<(u64, &str)> = vec![
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ];
        for (timestamp, expected) in cases {
            let result = generate_totp(SECRET_SHA1, timestamp, 30, 8, Algorithm::SHA1);
            assert_eq!(result, expected, "SHA1 failed at timestamp {}", timestamp);
        }
    }

    #[test]
    fn test_rfc6238_sha256_8digits() {
        let cases: Vec<(u64, &str)> = vec![
            (59, "46119246"),
            (1111111109, "68084774"),
            (1111111111, "67062674"),
            (1234567890, "91819424"),
            (2000000000, "90698825"),
            (20000000000, "77737706"),
        ];
        for (timestamp, expected) in cases {
            let result = generate_totp(SECRET_SHA256, timestamp, 30, 8, Algorithm::SHA256);
            assert_eq!(result, expected, "SHA256 failed at timestamp {}", timestamp);
        }
    }

    #[test]
    fn test_rfc6238_sha512_8digits() {
        let cases: Vec<(u64, &str)> = vec![
            (59, "90693936"),
            (1111111109, "25091201"),
            (1111111111, "99943326"),
            (1234567890, "93441116"),
            (2000000000, "38618901"),
            (20000000000, "47863826"),
        ];
        for (timestamp, expected) in cases {
            let result = generate_totp(SECRET_SHA512, timestamp, 30, 8, Algorithm::SHA512);
            assert_eq!(result, expected, "SHA512 failed at timestamp {}", timestamp);
        }
    }

    #[test]
    fn test_6digit_output() {
        let result = generate_totp(SECRET_SHA1, 59, 30, 6, Algorithm::SHA1);
        assert_eq!(result.len(), 6);
        assert_eq!(result, "287082");
    }

    #[test]
    fn test_remaining_seconds() {
        assert_eq!(remaining_seconds(30, 0), 30);
        assert_eq!(remaining_seconds(30, 1), 29);
        assert_eq!(remaining_seconds(30, 29), 1);
        assert_eq!(remaining_seconds(30, 30), 30);
        assert_eq!(remaining_seconds(30, 45), 15);
    }

    #[test]
    fn test_leading_zeros_preserved() {
        let result = generate_totp(SECRET_SHA1, 1111111109, 30, 8, Algorithm::SHA1);
        assert_eq!(result, "07081804");
        assert_eq!(result.len(), 8);
    }
}
