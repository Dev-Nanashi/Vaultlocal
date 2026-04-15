use argon2::{Argon2, Algorithm, Version, Params};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::constants::*;
use crate::error::VaultError;
use crate::secure_mem::types::SecureVec;

/// Derives root_key from password + salt via Argon2id.
pub fn derive_root_key(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<SecureVec, VaultError> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(ROOT_KEY_LEN))
        .map_err(|_| VaultError::KeyApplyFailed)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut root_key = SecureVec::zeroed(ROOT_KEY_LEN);
    argon2
        .hash_password_into(password, salt, root_key.as_mut())
        .map_err(|_| VaultError::KeyApplyFailed)?;

    Ok(root_key)
}

/// Derives the SQLCipher database key from root_key.
pub fn derive_db_key(root_key: &[u8]) -> Result<SecureVec, VaultError> {
    hkdf_expand(root_key, HKDF_INFO_DB, DB_KEY_LEN)
}

/// Derives the master encryption key from root_key.
pub fn derive_master_key(root_key: &[u8]) -> Result<SecureVec, VaultError> {
    hkdf_expand(root_key, HKDF_INFO_MASTER, MASTER_KEY_LEN)
}

/// Derives a per-entry key from master_key using length-prefixed context.
///
/// Context encoding:
///   HKDF_INFO_ENTRY || u32_le(len(label)) || label || u32_le(len(identifier)) || identifier
pub fn derive_entry_key(
    master_key: &[u8],
    label: &str,
    identifier: &str,
) -> Result<SecureVec, VaultError> {
    let label_bytes = label.as_bytes();
    let id_bytes = identifier.as_bytes();

    let mut info = Vec::with_capacity(
        HKDF_INFO_ENTRY.len() + 4 + label_bytes.len() + 4 + id_bytes.len(),
    );
    info.extend_from_slice(HKDF_INFO_ENTRY);
    info.extend_from_slice(&(label_bytes.len() as u32).to_le_bytes());
    info.extend_from_slice(label_bytes);
    info.extend_from_slice(&(id_bytes.len() as u32).to_le_bytes());
    info.extend_from_slice(id_bytes);

    hkdf_expand(master_key, &info, ENTRY_KEY_LEN)
}

fn hkdf_expand(ikm: &[u8], info: &[u8], len: usize) -> Result<SecureVec, VaultError> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = SecureVec::zeroed(len);
    hk.expand(info, okm.as_mut())
        .map_err(|_| VaultError::KeyApplyFailed)?;
    Ok(okm)
}