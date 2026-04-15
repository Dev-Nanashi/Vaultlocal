#[cfg(test)]
mod crypto_tests {
    use vaultlocal::crypto::kdf;
    use vaultlocal::crypto::cipher;
    use vaultlocal::crypto::constants::SALT_LEN;

    fn test_salt() -> [u8; SALT_LEN] {
        [0x42u8; SALT_LEN]
    }

    #[test]
    fn kdf_root_key_determinism() {
        let salt = test_salt();
        let k1 = kdf::derive_root_key(b"password", &salt).unwrap();
        let k2 = kdf::derive_root_key(b"password", &salt).unwrap();
        assert_eq!(k1.as_slice(), k2.as_slice());
    }

    #[test]
    fn kdf_different_passwords_differ() {
        let salt = test_salt();
        let k1 = kdf::derive_root_key(b"password1", &salt).unwrap();
        let k2 = kdf::derive_root_key(b"password2", &salt).unwrap();
        assert_ne!(k1.as_slice(), k2.as_slice());
    }

    #[test]
    fn kdf_different_salts_differ() {
        let salt1 = [0x01u8; SALT_LEN];
        let salt2 = [0x02u8; SALT_LEN];
        let k1 = kdf::derive_root_key(b"password", &salt1).unwrap();
        let k2 = kdf::derive_root_key(b"password", &salt2).unwrap();
        assert_ne!(k1.as_slice(), k2.as_slice());
    }

    #[test]
    fn kdf_db_master_keys_separated() {
        let salt = test_salt();
        let root = kdf::derive_root_key(b"password", &salt).unwrap();
        let db_key = kdf::derive_db_key(&root).unwrap();
        let master_key = kdf::derive_master_key(&root).unwrap();
        assert_ne!(db_key.as_slice(), master_key.as_slice());
    }

    #[test]
    fn kdf_entry_keys_domain_separated() {
        let salt = test_salt();
        let root = kdf::derive_root_key(b"password", &salt).unwrap();
        let master = kdf::derive_master_key(&root).unwrap();

        let k1 = kdf::derive_entry_key(&master, "github", "alice").unwrap();
        let k2 = kdf::derive_entry_key(&master, "github", "bob").unwrap();
        let k3 = kdf::derive_entry_key(&master, "gitlab", "alice").unwrap();

        assert_ne!(k1.as_slice(), k2.as_slice());
        assert_ne!(k1.as_slice(), k3.as_slice());
        assert_ne!(k2.as_slice(), k3.as_slice());
    }

    #[test]
    fn kdf_entry_key_deterministic() {
        let salt = test_salt();
        let root = kdf::derive_root_key(b"password", &salt).unwrap();
        let master = kdf::derive_master_key(&root).unwrap();

        let k1 = kdf::derive_entry_key(&master, "github", "alice").unwrap();
        let k2 = kdf::derive_entry_key(&master, "github", "alice").unwrap();
        assert_eq!(k1.as_slice(), k2.as_slice());
    }

    #[test]
    fn cipher_encrypt_decrypt_roundtrip() {
        let key = [0xABu8; 32];
        let plaintext = b"hello, vault!";
        let aad = b"label:identifier";

        let (nonce, ciphertext) = cipher::encrypt(&key, plaintext, aad).unwrap();
        let recovered = cipher::decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn cipher_wrong_key_fails() {
        let key1 = [0xABu8; 32];
        let key2 = [0xCDu8; 32];
        let plaintext = b"hello, vault!";
        let aad = b"aad";

        let (nonce, ciphertext) = cipher::encrypt(&key1, plaintext, aad).unwrap();
        let result = cipher::decrypt(&key2, &nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn cipher_wrong_aad_fails() {
        let key = [0xABu8; 32];
        let plaintext = b"hello, vault!";

        let (nonce, ciphertext) = cipher::encrypt(&key, plaintext, b"correct-aad").unwrap();
        let result = cipher::decrypt(&key, &nonce, &ciphertext, b"wrong-aad");
        assert!(result.is_err());
    }

    #[test]
    fn cipher_empty_plaintext_rejected() {
        let key = [0xABu8; 32];
        let result = cipher::encrypt(&key, b"", b"aad");
        assert!(result.is_err());
    }

    #[test]
    fn cipher_nonces_differ_per_call() {
        let key = [0xABu8; 32];
        let plaintext = b"hello";
        let aad = b"aad";

        let (n1, _) = cipher::encrypt(&key, plaintext, aad).unwrap();
        let (n2, _) = cipher::encrypt(&key, plaintext, aad).unwrap();
        // With OsRng, nonces should be distinct with overwhelming probability
        assert_ne!(n1, n2);
    }
}