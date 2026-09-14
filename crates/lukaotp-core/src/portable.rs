//! 可移植、离线的加密备份格式。
//!
//! # 背景
//!
//! 内部持久化密钥与备份凭据相互独立，因此备份不直接暴露内部存储文件，而是使用
//! **独立的、密码保护的可移植格式**：调用方提供导出密码，并以统一的
//! Argon2id + AES-256-GCM 流程生成和解析。
//!
//! # 格式（schema_version = 1）
//!
//! ```json
//! { "schema_version": 1, "salt": "<base64 16B>", "blob": "<base64 nonce(12B)‖ciphertext>" }
//! ```
//!
//! `blob` 复用 [`crate::encrypted_store::encrypt_accounts`] / `decrypt_accounts` 的格式，
//! `salt` 与导出密码经 [`crate::encrypted_store::EncryptedFileStore::derive_key`] 派生出
//! 该 blob 的 AES 密钥。
//!
//! # 版本策略
//!
//! - 新增**向后兼容**字段：不 bump `schema_version`，新增字段在 struct 上用
//!   `#[serde(default)]`，旧版本读取时缺省，不报错。
//! - **破坏性变更**（加密算法、KDF 参数、字段语义变化）：必须 bump `schema_version`；
//!   [`import_portable`] 对未识别的版本号返回 [`crate::storage::StoreError::Crypto`]
//!   明确报错，绝不尝试用旧逻辑硬解新格式（避免静默产出错误明文）。
//! - 两端解析该 struct 时都应保留未知字段的兼容读取能力（serde 默认丢弃未知字段，
//!   不会因为对端加了新字段而解析失败）。

use serde::{Deserialize, Serialize};

use crate::account::Account;
use crate::encrypted_store::{decrypt_accounts, encrypt_accounts, EncryptedFileStore};
use crate::storage::{StoreError, StoreResult};

/// 当前支持的最新 schema 版本。
pub const CURRENT_SCHEMA_VERSION: u32 = 1;
/// Portable exports are account metadata plus encrypted secrets; reject
/// unbounded ciphertext before allocating/decrypting it.
pub const MAX_PORTABLE_BLOB_BYTES: usize = 8 * 1024 * 1024;

/// 可移植导出信封：用于离线备份与恢复账户数据的稳定格式。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableExport {
    pub schema_version: u32,
    /// Base64 编码的 16 字节 Argon2id salt。
    pub salt: String,
    /// Base64 编码的 nonce(12B) ‖ AES-256-GCM 密文。
    pub blob: String,
}

/// 用导出密码加密账户列表，生成可移植信封。随机 salt，每次导出结果不同（即便账户不变）。
pub fn export_portable(accounts: &[Account], export_password: &str) -> StoreResult<PortableExport> {
    use rand::RngCore;
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let key = EncryptedFileStore::derive_key(export_password.as_bytes(), &salt)?;
    let ciphertext = encrypt_accounts(accounts, &key)?;
    Ok(PortableExport {
        schema_version: CURRENT_SCHEMA_VERSION,
        salt: data_encoding::BASE64.encode(&salt),
        blob: data_encoding::BASE64.encode(&ciphertext),
    })
}

/// 用导出密码解析可移植信封，还原账户列表。
///
/// 错误密码或损坏数据返回 `StoreError::Crypto`；不支持的 `schema_version` 明确报错，
/// 不做静默降级解析。
pub fn import_portable(
    export: &PortableExport,
    export_password: &str,
) -> StoreResult<Vec<Account>> {
    if export.schema_version != CURRENT_SCHEMA_VERSION {
        return Err(StoreError::Crypto(format!(
            "unsupported export schema_version: {} (expected {})",
            export.schema_version, CURRENT_SCHEMA_VERSION
        )));
    }
    let salt_bytes = data_encoding::BASE64
        .decode(export.salt.as_bytes())
        .map_err(|e| StoreError::Crypto(format!("invalid salt encoding: {e}")))?;
    let salt: [u8; 16] = salt_bytes
        .try_into()
        .map_err(|_| StoreError::Crypto("salt must be 16 bytes".to_string()))?;
    let ciphertext = data_encoding::BASE64
        .decode(export.blob.as_bytes())
        .map_err(|e| StoreError::Crypto(format!("invalid blob encoding: {e}")))?;
    if ciphertext.len() > MAX_PORTABLE_BLOB_BYTES {
        return Err(StoreError::Crypto("portable blob is too large".to_string()));
    }
    let key = EncryptedFileStore::derive_key(export_password.as_bytes(), &salt)?;
    let accounts = decrypt_accounts(&ciphertext, &key)?;
    if accounts
        .iter()
        .any(|account| uuid::Uuid::parse_str(&account.id).is_err())
    {
        return Err(StoreError::Crypto(
            "account id must be a valid UUID".to_string(),
        ));
    }
    Ok(accounts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Account;

    fn make_account(issuer: &str) -> Account {
        Account::new(issuer, "user@example.com", "JBSWY3DPEHPK3PXP").unwrap()
    }

    #[test]
    fn test_export_import_roundtrip() {
        let accounts = vec![make_account("GitHub"), make_account("AWS")];
        let export = export_portable(&accounts, "export-pw-123").unwrap();
        assert_eq!(export.schema_version, CURRENT_SCHEMA_VERSION);

        let imported = import_portable(&export, "export-pw-123").unwrap();
        assert_eq!(imported.len(), 2);
        assert_eq!(imported[0].issuer, "GitHub");
        assert_eq!(imported[1].issuer, "AWS");
    }

    #[test]
    fn test_wrong_password_rejected() {
        let accounts = vec![make_account("GitHub")];
        let export = export_portable(&accounts, "correct-pw").unwrap();
        assert!(import_portable(&export, "wrong-pw").is_err());
    }

    #[test]
    fn test_unsupported_schema_version_rejected() {
        // Account 未实现 Debug（防 secret 泄漏），故不能 unwrap_err()，用 match 取错误
        let accounts = vec![make_account("GitHub")];
        let mut export = export_portable(&accounts, "pw").unwrap();
        export.schema_version = 999;
        match import_portable(&export, "pw") {
            Err(StoreError::Crypto(_)) => {}
            other => panic!("expected Crypto error, got {:?}", other.map(|v| v.len())),
        }
    }

    #[test]
    fn test_corrupted_blob_rejected() {
        let accounts = vec![make_account("GitHub")];
        let mut export = export_portable(&accounts, "pw").unwrap();
        export.blob = data_encoding::BASE64.encode(b"not encrypted data at all!!");
        assert!(import_portable(&export, "pw").is_err());
    }

    #[test]
    fn test_invalid_salt_encoding_rejected() {
        let accounts = vec![make_account("GitHub")];
        let mut export = export_portable(&accounts, "pw").unwrap();
        export.salt = "not-base64!!!".to_string();
        assert!(import_portable(&export, "pw").is_err());
    }

    #[test]
    fn test_json_serialization_roundtrip() {
        let accounts = vec![make_account("GitHub")];
        let export = export_portable(&accounts, "pw").unwrap();
        let json = serde_json::to_string(&export).unwrap();
        let parsed: PortableExport = serde_json::from_str(&json).unwrap();
        let imported = import_portable(&parsed, "pw").unwrap();
        assert_eq!(imported[0].issuer, "GitHub");
    }

    #[test]
    fn test_each_export_has_unique_salt_and_ciphertext() {
        // 随机 salt/nonce 保证同一账户集合每次导出结果都不同，避免密文可比对分析
        let accounts = vec![make_account("GitHub")];
        let e1 = export_portable(&accounts, "pw").unwrap();
        let e2 = export_portable(&accounts, "pw").unwrap();
        assert_ne!(e1.salt, e2.salt);
        assert_ne!(e1.blob, e2.blob);
    }

    #[test]
    fn test_import_rejects_invalid_account_uuid() {
        let mut account = make_account("GitHub");
        account.id = "not-a-uuid\"><div>forged</div>".to_string();
        let export = export_portable(&[account], "pw").unwrap();

        assert!(import_portable(&export, "pw").is_err());
    }
}
