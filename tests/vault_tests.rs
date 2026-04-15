#[cfg(test)]
mod vault_tests {
    use tempfile::TempDir;
    use vaultlocal::Vault;

    #[test]
    fn insert_and_retrieve_entry() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::init(dir.path(), b"test-password").unwrap();

        vault.insert_entry("service", "user@example.com", b"my-secret-password").unwrap();
        let recovered = vault.get_entry("service", "user@example.com").unwrap();

        assert_eq!(recovered, b"my-secret-password");
    }

    #[test]
    fn multiple_entries_isolated() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::init(dir.path(), b"pw").unwrap();

        vault.insert_entry("github", "alice", b"alice-secret").unwrap();
        vault.insert_entry("github", "bob", b"bob-secret").unwrap();
        vault.insert_entry("gitlab", "alice", b"gitlab-alice").unwrap();

        assert_eq!(vault.get_entry("github", "alice").unwrap(), b"alice-secret");
        assert_eq!(vault.get_entry("github", "bob").unwrap(), b"bob-secret");
        assert_eq!(vault.get_entry("gitlab", "alice").unwrap(), b"gitlab-alice");
    }

    #[test]
    fn reopen_vault_succeeds() {
        let dir = TempDir::new().unwrap();

        {
            let vault = Vault::init(dir.path(), b"correct-pw").unwrap();
            vault.insert_entry("service", "id", b"secret").unwrap();
        }

        let vault2 = Vault::open(dir.path(), b"correct-pw").unwrap();
        let recovered = vault2.get_entry("service", "id").unwrap();
        assert_eq!(recovered, b"secret");
    }

    #[test]
    fn wrong_password_rejected() {
        let dir = TempDir::new().unwrap();

        {
            let _vault = Vault::init(dir.path(), b"correct-pw").unwrap();
        }

        let result = Vault::open(dir.path(), b"wrong-pw");
        assert!(result.is_err());
    }

    #[test]
    fn missing_entry_returns_error() {
        let dir = TempDir::new().unwrap();
        let vault = Vault::init(dir.path(), b"pw").unwrap();
        let result = vault.get_entry("nonexistent", "nobody");
        assert!(result.is_err());
    }
}