use crate::account::Account;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("account not found: {0}")]
    NotFound(String),
    #[error("account already exists: {0}")]
    AlreadyExists(String),
    #[error("storage I/O error: {0}")]
    Io(String),
    #[error("encryption error: {0}")]
    Crypto(String),
    #[error("invalid reorder: {0}")]
    InvalidReorder(String),
}

pub type StoreResult<T> = Result<T, StoreError>;

pub trait AccountStore: Send + Sync {
    fn list(&self) -> StoreResult<Vec<Account>>;
    fn get(&self, id: &str) -> StoreResult<Account>;
    fn add(&mut self, account: Account) -> StoreResult<()>;
    fn remove(&mut self, id: &str) -> StoreResult<()>;
    fn update(&mut self, account: Account) -> StoreResult<()>;
}

#[derive(Default)]
pub struct InMemoryStore {
    accounts: Vec<Account>,
}

impl AccountStore for InMemoryStore {
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
        Ok(())
    }
    fn remove(&mut self, id: &str) -> StoreResult<()> {
        let len_before = self.accounts.len();
        self.accounts.retain(|a| a.id != id);
        if self.accounts.len() == len_before {
            return Err(StoreError::NotFound(id.to_string()));
        }
        Ok(())
    }
    fn update(&mut self, account: Account) -> StoreResult<()> {
        let existing = self
            .accounts
            .iter_mut()
            .find(|a| a.id == account.id)
            .ok_or_else(|| StoreError::NotFound(account.id.clone()))?;
        *existing = account;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Account;

    fn make_account(issuer: &str) -> Account {
        Account::new(issuer, "test@test.com", "JBSWY3DPEHPK3PXP").unwrap()
    }

    #[test]
    fn test_add_and_list() {
        let mut store = InMemoryStore::default();
        store.add(make_account("GitHub")).unwrap();
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn test_get_by_id() {
        let mut store = InMemoryStore::default();
        let acc = make_account("AWS");
        let id = acc.id.clone();
        store.add(acc).unwrap();
        assert_eq!(store.get(&id).unwrap().issuer, "AWS");
    }

    #[test]
    fn test_get_not_found() {
        let store = InMemoryStore::default();
        assert!(matches!(
            store.get("nonexistent"),
            Err(StoreError::NotFound(_))
        ));
    }

    #[test]
    fn test_remove() {
        let mut store = InMemoryStore::default();
        let acc = make_account("Google");
        let id = acc.id.clone();
        store.add(acc).unwrap();
        store.remove(&id).unwrap();
        assert_eq!(store.list().unwrap().len(), 0);
    }

    #[test]
    fn test_remove_not_found() {
        let mut store = InMemoryStore::default();
        assert!(matches!(store.remove("x"), Err(StoreError::NotFound(_))));
    }

    #[test]
    fn test_update() {
        let mut store = InMemoryStore::default();
        let mut acc = make_account("GitHub");
        let id = acc.id.clone();
        store.add(acc.clone()).unwrap();
        acc.label = "new@label.com".to_string();
        store.update(acc).unwrap();
        assert_eq!(store.get(&id).unwrap().label, "new@label.com");
    }

    #[test]
    fn test_duplicate_add_fails() {
        let mut store = InMemoryStore::default();
        let acc = make_account("GitHub");
        store.add(acc.clone()).unwrap();
        assert!(matches!(store.add(acc), Err(StoreError::AlreadyExists(_))));
    }
}
