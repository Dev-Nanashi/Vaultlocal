#[cfg(test)]
mod integration {
    use tempfile::TempDir;
    use vaultlocal::Vault;

    /// Full lifecycle: init → insert → close → reopen → verify → insert more → reopen again
    #[test]
    fn full_lifecycle() {
        let dir = TempDir::new().unwrap();
        let password = b"hunter2-but-longer-and-better";

        // Phase 1: init and populate
        {
            let vault = Vault::init(dir.path(), password).unwrap();
            vault.insert_entry("email", "user@example.com", b"email-pass-1").unwrap();
            vault.insert_entry("ssh", "prod-server", b"ssh-key-material").unwrap();
        }

        // Phase 2: reopen and verify
        {
            let vault = Vault::open(dir.path(), password).unwrap();
            let email_pass = vault.get_entry("email", "user@example.com").unwrap();
            let ssh_key = vault.get_entry("ssh", "prod-server").unwrap();

            assert_eq!(email_pass, b"email-pass-1");
            assert_eq!(ssh_key, b"ssh-key-material");

            // Add more entries
            vault.insert_entry("db", "postgres", b"pg-s3cr3t").unwrap();
        }

        // Phase 3: reopen again, verify all three
        {
            let vault = Vault::open(dir.path(), password).unwrap();
            assert_eq!(vault.get_entry("email", "user@example.com").unwrap(), b"email-pass-1");
            assert_eq!(vault.get_entry("ssh", "prod-server").unwrap(), b"ssh-key-material");
            assert_eq!(vault.get_entry("db", "postgres").unwrap(), b"pg-s3cr3t");
        }
    }

    #[test]
    fn wrong_password_at_every_open_attempt() {
        let dir = TempDir::new().unwrap();

        {
            let _v = Vault::init(dir.path(), b"right").unwrap();
        }

        for wrong in &[b"wrong".as_slice(), b"Righ".as_slice(), b"".as_slice(), b"RIGHT".as_slice()] {
            let result = Vault::open(dir.path(), wrong);
            assert!(result.is_err(), "expected error for password {:?}", wrong);
        }
    }

    #[test]
    fn double_init_fails() {
        let dir = TempDir::new().unwrap();
        let _v = Vault::init(dir.path(), b"pw").unwrap();
        let result = Vault::init(dir.path(), b"pw");
        assert!(result.is_err(), "second init should fail");
    }
}