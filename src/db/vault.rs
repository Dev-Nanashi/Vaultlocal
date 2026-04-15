use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::{RngCore, rngs::OsRng};
use rusqlite::Connection;

use crate::crypto::constants::*;
use crate::crypto::kdf;
use crate::crypto::cipher;
use crate::db::{connection, meta::MetaFile, schema};
use crate::error::VaultError;
use crate::secure_mem::types::SecureVec;

pub struct Vault {
    conn: Connection,
    master_key: SecureVec,
}

impl Vault {
    /// Initialise a new vault at `vault_dir`.
    ///
    /// Generates a fresh salt, derives the full key hierarchy,
    /// creates the encrypted database, and stores a canary entry.
    pub fn init(vault_dir: &Path, password: &[u8]) -> Result<Self, VaultError> {
        let db_path = db_path(vault_dir);
        let meta_path = meta_path(vault_dir);

        if db_path.exists() || meta_path.exists() {
            return Err(VaultError::DbOpen); // vault already exists
        }

        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);

        let (conn, master_key) = open_with_keys(&db_path, password, &salt)?;

        schema::create_schema(&conn)?;

        let mut vault = Vault { conn, master_key };
        vault.store_canary()?;

        MetaFile::new(salt).write(&meta_path)?;

        Ok(vault)
    }

    /// Open an existing vault.
    pub fn open(vault_dir: &Path, password: &[u8]) -> Result<Self, VaultError> {
        let db_path = db_path(vault_dir);
        let meta_path = meta_path(vault_dir);

        let meta = MetaFile::read(&meta_path)?;
        let (conn, master_key) = open_with_keys(&db_path, password, &meta.salt)?;

        schema::verify_schema(&conn)?;

        let mut vault = Vault { conn, master_key };
        vault.verify_canary()?;

        Ok(vault)
    }

    /// Insert or replace an entry.
    pub fn insert_entry(&self, label: &str, identifier: &str, plaintext: &[u8]) -> Result<(), VaultError> {
        let entry_key = kdf::derive_entry_key(&self.master_key, label, identifier)?;
        let aad = entry_aad(label, identifier);
        let (nonce, ciphertext) = cipher::encrypt(&entry_key, plaintext, &aad)?;

        let now = unix_ts();
        self.conn
            .execute(
                "INSERT OR REPLACE INTO entries (label, identifier, nonce, ciphertext, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![label, identifier, nonce, ciphertext, now],
            )
            .map_err(|_| VaultError::CorruptDatabase)?;

        Ok(())
    }

    /// Retrieve and decrypt an entry.
    pub fn get_entry(&self, label: &str, identifier: &str) -> Result<Vec<u8>, VaultError> {
        let result: rusqlite::Result<(Vec<u8>, Vec<u8>)> = self.conn.query_row(
            "SELECT nonce, ciphertext FROM entries WHERE label = ?1 AND identifier = ?2",
            rusqlite::params![label, identifier],
            |row| Ok((row.get(0)?, row.get(1)?)),
        );

        let (nonce, ciphertext) = result.map_err(|_| VaultError::DecryptionError)?;

        let entry_key = kdf::derive_entry_key(&self.master_key, label, identifier)?;
        let aad = entry_aad(label, identifier);

        cipher::decrypt(&entry_key, &nonce, &ciphertext, &aad)
    }

    /// Delete an entry by label + identifier.
    ///
    /// Returns `VaultError::DecryptionError` (entry not found) if no row matched,
    /// keeping the error surface consistent with `get_entry`.
    pub fn delete_entry(&self, label: &str, identifier: &str) -> Result<(), VaultError> {
        let affected = self.conn
            .execute(
                "DELETE FROM entries WHERE label = ?1 AND identifier = ?2",
                rusqlite::params![label, identifier],
            )
            .map_err(|_| VaultError::CorruptDatabase)?;

        if affected == 0 {
            return Err(VaultError::DecryptionError); // reused as "not found"
        }

        Ok(())
    }

    /// List all (label, identifier) pairs, excluding the internal canary entry.
    pub fn list_entries(&self) -> Result<Vec<(String, String)>, VaultError> {
        let mut stmt = self.conn
            .prepare(
                "SELECT label, identifier FROM entries
                 WHERE NOT (label = ?1 AND identifier = ?2)
                 ORDER BY label, identifier",
            )
            .map_err(|_| VaultError::CorruptDatabase)?;

        let rows = stmt
            .query_map(
                rusqlite::params![CANARY_LABEL, CANARY_IDENTIFIER],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .map_err(|_| VaultError::CorruptDatabase)?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(|_| VaultError::CorruptDatabase)?);
        }

        Ok(entries)
    }

    fn store_canary(&mut self) -> Result<(), VaultError> {
        self.insert_entry(CANARY_LABEL, CANARY_IDENTIFIER, CANARY_PLAINTEXT)
    }

    fn verify_canary(&mut self) -> Result<(), VaultError> {
        let plaintext = self.get_entry(CANARY_LABEL, CANARY_IDENTIFIER)
            .map_err(|_| VaultError::WrongPassword)?;

        if plaintext != CANARY_PLAINTEXT {
            return Err(VaultError::WrongPassword);
        }

        Ok(())
    }
}

// ---- helpers ----

fn open_with_keys(
    db_path: &Path,
    password: &[u8],
    salt: &[u8; SALT_LEN],
) -> Result<(Connection, SecureVec), VaultError> {
    let root_key = kdf::derive_root_key(password, salt)?;
    let db_key = kdf::derive_db_key(&root_key)?;
    let master_key = kdf::derive_master_key(&root_key)?;

    let path_str = db_path
        .to_str()
        .ok_or(VaultError::DbOpen)?;

    let conn = connection::open_encrypted(path_str, &db_key)?;

    Ok((conn, master_key))
}

fn db_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join("vault.db")
}

fn meta_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join("vault.meta")
}

fn entry_aad(label: &str, identifier: &str) -> Vec<u8> {
    let mut aad = Vec::new();
    let lb = label.as_bytes();
    let ib = identifier.as_bytes();
    aad.extend_from_slice(&(lb.len() as u32).to_le_bytes());
    aad.extend_from_slice(lb);
    aad.extend_from_slice(&(ib.len() as u32).to_le_bytes());
    aad.extend_from_slice(ib);
    aad
}

fn unix_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}