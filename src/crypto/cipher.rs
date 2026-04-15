use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce, aead::{Aead, KeyInit, Payload}};
use rand::{RngCore, rngs::OsRng};

use crate::crypto::constants::NONCE_LEN;
use crate::error::VaultError;

/// Encrypts plaintext with AES-256-GCM-SIV.
///
/// Returns nonce || ciphertext.
/// AAD is authenticated but not included in output.
pub fn encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
    if plaintext.is_empty() {
        return Err(VaultError::EmptyPlaintext);
    }
    if key.len() != 32 {
        return Err(VaultError::EncryptionError);
    }

    let cipher_key = Key::<Aes256GcmSiv>::from_slice(key);
    let cipher = Aes256GcmSiv::new(cipher_key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = Payload { msg: plaintext, aad };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| VaultError::EncryptionError)?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

/// Decrypts ciphertext with AES-256-GCM-SIV.
///
/// nonce and ciphertext are separate (as stored in DB).
/// AAD must match what was used during encryption.
pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, VaultError> {
    if key.len() != 32 {
        return Err(VaultError::DecryptionError);
    }
    if nonce.len() != NONCE_LEN {
        return Err(VaultError::DecryptionError);
    }

    let cipher_key = Key::<Aes256GcmSiv>::from_slice(key);
    let cipher = Aes256GcmSiv::new(cipher_key);
    let nonce = Nonce::from_slice(nonce);

    let payload = Payload { msg: ciphertext, aad };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| VaultError::DecryptionError)
}