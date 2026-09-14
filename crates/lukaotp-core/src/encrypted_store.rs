use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;

use crate::account::Account;
use crate::storage::{AccountStore, StoreError, StoreResult};

const ARGON2_M_COST_KIB: u32 = 19_456;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;
const ARGON2_OUTPUT_LEN: usize = 32;

pub struct EncryptedFileStore {
    file_path: std::path::PathBuf,
    key: [u8; 32],
    accounts: Vec<Account>,
}

impl EncryptedFileStore {
    pub fn open(file_path: std::path::PathBuf, key: [u8; 32]) -> StoreResult<Self> {
        let accounts = if file_path.exists() {
            let data = std::fs::read(&file_path).map_err(|e| StoreError::Io(e.to_string()))?;
            decrypt_accounts(&data, &key)?
        } else {
            Vec::new()
        };
        Ok(Self {
            file_path,
            key,
            accounts,
        })
    }

    pub fn derive_key(password: &[u8], salt: &[u8; 16]) -> Result<[u8; 32], StoreError> {
        let mut key = [0u8; 32];
        let params = Params::new(
            ARGON2_M_COST_KIB,
            ARGON2_T_COST,
            ARGON2_P_COST,
            Some(ARGON2_OUTPUT_LEN),
        )
        .map_err(|e| StoreError::Crypto(e.to_string()))?;
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(password, salt, &mut key)
            .map_err(|e| StoreError::Crypto(e.to_string()))?;
        Ok(key)
    }

    fn persist(&self) -> StoreResult<()> {
        let data = encrypt_accounts(&self.accounts, &self.key)?;
        let tmp_path = self.file_path.with_extension("tmp");
        std::fs::write(&tmp_path, &data).map_err(|e| StoreError::Io(e.to_string()))?;
        std::fs::rename(&tmp_path, &self.file_path).map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }

    /// 合并一批已解密的账户（来自 `portable::import_portable`）到当前存储：按 `id` 去重
    /// （已存在的 id 跳过），一次性持久化，返回 `(added, skipped)`。
    ///
    /// 幂等：重复导入同一批账户不产生重复记录。原子：只在合并全部完成后落盘一次；若
    /// 持久化失败，内存状态回滚到调用前，磁盘上不会留下部分导入的痕迹。
    pub fn import_accounts(&mut self, incoming: Vec<Account>) -> StoreResult<(usize, usize)> {
        let mut existing_ids: std::collections::HashSet<String> =
            self.accounts.iter().map(|a| a.id.clone()).collect();
        let original_len = self.accounts.len();
        let mut added = 0usize;
        let mut skipped = 0usize;
        for account in incoming {
            if !existing_ids.insert(account.id.clone()) {
                skipped += 1;
            } else {
                self.accounts.push(account);
                added += 1;
            }
        }
        if added == 0 {
            return Ok((0, skipped));
        }
        if let Err(e) = self.persist() {
            self.accounts.truncate(original_len);
            return Err(e);
        }
        Ok((added, skipped))
    }

    /// 按 `ordered_ids` 重新排列账户存储顺序（存储的 `Vec` 顺序即显示/分组内排序，
    /// 不额外引入 sort_order 字段）。`ordered_ids` 必须与当前账户 id 集合完全一致
    /// （同一批、无缺漏、无多余），否则拒绝并原样保留原顺序。
    pub fn reorder(&mut self, ordered_ids: &[String]) -> StoreResult<()> {
        let original = self.accounts.clone();
        reorder_accounts(&mut self.accounts, ordered_ids)?;
        if let Err(e) = self.persist() {
            self.accounts = original;
            return Err(e);
        }
        Ok(())
    }
}

/// Reorder an in-memory account vector using the same full-permutation contract
/// as [`EncryptedFileStore::reorder`]. Callers that own persistence can use
/// this helper before serializing their encrypted state.
pub fn reorder_accounts(accounts: &mut Vec<Account>, ordered_ids: &[String]) -> StoreResult<()> {
    let existing: std::collections::HashSet<&str> =
        accounts.iter().map(|a| a.id.as_str()).collect();
    let requested: std::collections::HashSet<&str> =
        ordered_ids.iter().map(|s| s.as_str()).collect();
    if ordered_ids.len() != accounts.len() || existing != requested {
        return Err(StoreError::InvalidReorder(
            "ordered_ids must be exactly the current set of account ids, each once".to_string(),
        ));
    }

    let mut by_id: std::collections::HashMap<String, Account> =
        accounts.drain(..).map(|a| (a.id.clone(), a)).collect();
    *accounts = ordered_ids
        .iter()
        .map(|id| by_id.remove(id).expect("id set validated above"))
        .collect();
    Ok(())
}

impl AccountStore for EncryptedFileStore {
    fn list(&self) -> StoreResult<Vec<Account>> {
        Ok(self.accounts.clone())
    }
    fn get(&self, id: &str) -> StoreResult<Account> {
        self.accounts
            .iter()
            .find(|a| a.id == id)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(id.to_string()))
    }
    fn add(&mut self, account: Account) -> StoreResult<()> {
        if self.accounts.iter().any(|a| a.id == account.id) {
            return Err(StoreError::AlreadyExists(account.id));
        }
        self.accounts.push(account);
        if let Err(error) = self.persist() {
            self.accounts.pop();
            return Err(error);
        }
        Ok(())
    }
    fn remove(&mut self, id: &str) -> StoreResult<()> {
        let index = self
            .accounts
            .iter()
            .position(|account| account.id == id)
            .ok_or_else(|| StoreError::NotFound(id.to_string()))?;
        let account = self.accounts.remove(index);
        if let Err(error) = self.persist() {
            self.accounts.insert(index, account);
            return Err(error);
        }
        Ok(())
    }
    fn update(&mut self, account: Account) -> StoreResult<()> {
        let index = self
            .accounts
            .iter()
            .position(|existing| existing.id == account.id)
            .ok_or_else(|| StoreError::NotFound(account.id.clone()))?;
        let previous = std::mem::replace(&mut self.accounts[index], account);
        if let Err(error) = self.persist() {
            self.accounts[index] = previous;
            return Err(error);
        }
        Ok(())
    }
}

/// 加密账户列表为可持久化 blob：nonce(12) ‖ AES-256-GCM(JSON)。
/// 此稳定格式用于 Core 的本地持久化和可移植备份处理。
pub fn encrypt_accounts(accounts: &[Account], key: &[u8; 32]) -> StoreResult<Vec<u8>> {
    let json = serde_json::to_vec(accounts).map_err(|e| StoreError::Crypto(e.to_string()))?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| StoreError::Crypto(e.to_string()))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, json.as_ref())
        .map_err(|e| StoreError::Crypto(e.to_string()))?;
    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// 解密 encrypt_accounts 产出的 blob；密钥错误或数据损坏返回 Crypto 错误。
pub fn decrypt_accounts(data: &[u8], key: &[u8; 32]) -> StoreResult<Vec<Account>> {
    if data.len() < 12 {
        return Err(StoreError::Crypto("data too short".to_string()));
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| StoreError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| StoreError::Crypto(e.to_string()))?;
    serde_json::from_slice(&plaintext).map_err(|e| StoreError::Crypto(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Account;
    use tempfile::TempDir;

    fn test_key() -> [u8; 32] {
        [0xAA; 32]
    }

    fn make_account(issuer: &str) -> Account {
        Account::new(issuer, "test@test.com", "JBSWY3DPEHPK3PXP").unwrap()
    }

    #[test]
    fn test_open_new_file() {
        let dir = TempDir::new().unwrap();
        let store = EncryptedFileStore::open(dir.path().join("acc.enc"), test_key()).unwrap();
        assert_eq!(store.list().unwrap().len(), 0);
    }

    #[test]
    fn test_add_persist_reopen() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("acc.enc");
        {
            let mut store = EncryptedFileStore::open(path.clone(), test_key()).unwrap();
            store.add(make_account("GitHub")).unwrap();
        }
        {
            let store = EncryptedFileStore::open(path, test_key()).unwrap();
            let accounts = store.list().unwrap();
            assert_eq!(accounts.len(), 1);
            assert_eq!(accounts[0].issuer, "GitHub");
        }
    }

    #[test]
    fn test_wrong_key_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("acc.enc");
        {
            let mut store = EncryptedFileStore::open(path.clone(), test_key()).unwrap();
            store.add(make_account("GitHub")).unwrap();
        }
        assert!(EncryptedFileStore::open(path, [0xBB; 32]).is_err());
    }

    #[test]
    fn test_remove_persists() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("acc.enc");
        let id;
        {
            let mut store = EncryptedFileStore::open(path.clone(), test_key()).unwrap();
            let acc = make_account("GitHub");
            id = acc.id.clone();
            store.add(acc).unwrap();
            store.remove(&id).unwrap();
        }
        {
            let store = EncryptedFileStore::open(path, test_key()).unwrap();
            assert_eq!(store.list().unwrap().len(), 0);
        }
    }

    #[test]
    fn test_failed_add_restores_in_memory_state() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("missing").join("acc.enc");
        let mut store = EncryptedFileStore::open(path, test_key()).unwrap();

        assert!(store.add(make_account("GitHub")).is_err());
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn test_failed_remove_restores_in_memory_state_and_order() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("acc.enc");
        let mut store = EncryptedFileStore::open(path, test_key()).unwrap();
        let first = make_account("GitHub");
        let first_id = first.id.clone();
        let second = make_account("AWS");
        let expected_ids = vec![first_id.clone(), second.id.clone()];
        store.add(first).unwrap();
        store.add(second).unwrap();
        store.file_path = dir.path().join("missing").join("acc.enc");

        assert!(store.remove(&first_id).is_err());
        let actual_ids: Vec<String> = store
            .list()
            .unwrap()
            .into_iter()
            .map(|account| account.id)
            .collect();
        assert_eq!(actual_ids, expected_ids);
    }

    #[test]
    fn test_failed_update_restores_in_memory_metadata() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("acc.enc");
        let mut store = EncryptedFileStore::open(path, test_key()).unwrap();
        let account = make_account("GitHub");
        let id = account.id.clone();
        store.add(account).unwrap();
        store.file_path = dir.path().join("missing").join("acc.enc");

        let mut changed = store.get(&id).unwrap();
        changed.issuer = "Changed".to_string();
        assert!(store.update(changed).is_err());
        assert_eq!(store.get(&id).unwrap().issuer, "GitHub");
    }

    #[test]
    fn test_derive_key_matches_fixed_vector() {
        let salt = [0x42u8; 16];
        let key = EncryptedFileStore::derive_key(b"password123", &salt).unwrap();
        assert_eq!(
            key,
            [
                28, 245, 177, 94, 126, 234, 198, 181, 236, 55, 30, 252, 141, 212, 139, 47, 134,
                115, 165, 72, 161, 240, 95, 6, 54, 152, 12, 176, 95, 105, 104, 90,
            ]
        );
    }

    #[test]
    fn test_import_accounts_merges_new() {
        let dir = TempDir::new().unwrap();
        let mut store = EncryptedFileStore::open(dir.path().join("acc.enc"), test_key()).unwrap();
        let (added, skipped) = store
            .import_accounts(vec![make_account("GitHub"), make_account("AWS")])
            .unwrap();
        assert_eq!((added, skipped), (2, 0));
        assert_eq!(store.list().unwrap().len(), 2);
    }

    #[test]
    fn test_import_accounts_skips_existing_ids() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("acc.enc");
        let mut store = EncryptedFileStore::open(path, test_key()).unwrap();
        let existing = make_account("GitHub");
        let existing_id = existing.id.clone();
        store.add(existing.clone()).unwrap();

        let (added, skipped) = store
            .import_accounts(vec![existing, make_account("AWS")])
            .unwrap();
        assert_eq!((added, skipped), (1, 1));
        let accounts = store.list().unwrap();
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts.iter().filter(|a| a.id == existing_id).count(), 1);
    }

    #[test]
    fn test_import_accounts_skips_duplicate_ids_in_one_backup() {
        let dir = TempDir::new().unwrap();
        let mut store = EncryptedFileStore::open(dir.path().join("acc.enc"), test_key()).unwrap();
        let account = make_account("GitHub");

        let (added, skipped) = store
            .import_accounts(vec![account.clone(), account])
            .unwrap();

        assert_eq!((added, skipped), (1, 1));
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn test_import_accounts_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("acc.enc");
        let mut store = EncryptedFileStore::open(path, test_key()).unwrap();
        let batch = vec![make_account("GitHub"), make_account("AWS")];

        let (added1, _) = store.import_accounts(batch.clone()).unwrap();
        let (added2, skipped2) = store.import_accounts(batch).unwrap();
        assert_eq!(added1, 2);
        assert_eq!((added2, skipped2), (0, 2));
        assert_eq!(store.list().unwrap().len(), 2);
    }

    #[test]
    fn test_import_accounts_persists_across_reopen() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("acc.enc");
        {
            let mut store = EncryptedFileStore::open(path.clone(), test_key()).unwrap();
            store.import_accounts(vec![make_account("GitHub")]).unwrap();
        }
        let store = EncryptedFileStore::open(path, test_key()).unwrap();
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn test_reorder_changes_list_order() {
        let dir = TempDir::new().unwrap();
        let mut store = EncryptedFileStore::open(dir.path().join("acc.enc"), test_key()).unwrap();
        let a = make_account("GitHub");
        let b = make_account("AWS");
        let c = make_account("Google");
        let (a_id, b_id, c_id) = (a.id.clone(), b.id.clone(), c.id.clone());
        store.add(a).unwrap();
        store.add(b).unwrap();
        store.add(c).unwrap();

        store
            .reorder(&[c_id.clone(), a_id.clone(), b_id.clone()])
            .unwrap();
        let ids: Vec<String> = store.list().unwrap().iter().map(|a| a.id.clone()).collect();
        assert_eq!(ids, vec![c_id, a_id, b_id]);
    }

    #[test]
    fn test_reorder_persists_across_reopen() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("acc.enc");
        let (a_id, b_id);
        {
            let mut store = EncryptedFileStore::open(path.clone(), test_key()).unwrap();
            let a = make_account("GitHub");
            let b = make_account("AWS");
            a_id = a.id.clone();
            b_id = b.id.clone();
            store.add(a).unwrap();
            store.add(b).unwrap();
            store.reorder(&[b_id.clone(), a_id.clone()]).unwrap();
        }
        let store = EncryptedFileStore::open(path, test_key()).unwrap();
        let ids: Vec<String> = store.list().unwrap().iter().map(|a| a.id.clone()).collect();
        assert_eq!(ids, vec![b_id, a_id]);
    }

    #[test]
    fn test_reorder_rejects_missing_id() {
        let dir = TempDir::new().unwrap();
        let mut store = EncryptedFileStore::open(dir.path().join("acc.enc"), test_key()).unwrap();
        let a = make_account("GitHub");
        let b = make_account("AWS");
        let a_id = a.id.clone();
        store.add(a).unwrap();
        store.add(b).unwrap();

        // Missing b's id: not a full permutation, must be rejected and leave order untouched.
        let err = store.reorder(std::slice::from_ref(&a_id));
        assert!(matches!(err, Err(StoreError::InvalidReorder(_))));
        assert_eq!(store.list().unwrap().len(), 2);
    }

    #[test]
    fn test_reorder_rejects_unknown_id() {
        let dir = TempDir::new().unwrap();
        let mut store = EncryptedFileStore::open(dir.path().join("acc.enc"), test_key()).unwrap();
        let a = make_account("GitHub");
        let a_id = a.id.clone();
        store.add(a).unwrap();

        let err = store.reorder(&[a_id, "not-a-real-id".to_string()]);
        assert!(matches!(err, Err(StoreError::InvalidReorder(_))));
    }

    #[test]
    fn test_reorder_rejects_duplicate_id() {
        let dir = TempDir::new().unwrap();
        let mut store = EncryptedFileStore::open(dir.path().join("acc.enc"), test_key()).unwrap();
        let a = make_account("GitHub");
        let b = make_account("AWS");
        let a_id = a.id.clone();
        store.add(a).unwrap();
        store.add(b).unwrap();

        let err = store.reorder(&[a_id.clone(), a_id]);
        assert!(matches!(err, Err(StoreError::InvalidReorder(_))));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let accounts = vec![make_account("GitHub"), make_account("AWS")];
        let encrypted = encrypt_accounts(&accounts, &key).unwrap();
        let decrypted = decrypt_accounts(&encrypted, &key).unwrap();
        assert_eq!(decrypted.len(), 2);
        assert_eq!(decrypted[0].issuer, "GitHub");
        assert_eq!(decrypted[1].issuer, "AWS");
    }
}
