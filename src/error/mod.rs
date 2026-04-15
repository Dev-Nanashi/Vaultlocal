use std::fmt;

#[derive(Debug)]
pub enum VaultError {
    DbOpen,
    SqlcipherMissing,
    KeyApplyFailed,
    InvalidMeta,
    CorruptDatabase,
    WrongPassword,
    EncryptionError,
    DecryptionError,
    Io(std::io::Error),
    EmptyPlaintext,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::DbOpen => write!(f, "failed to open database"),
            VaultError::SqlcipherMissing => write!(f, "SQLCipher not available"),
            VaultError::KeyApplyFailed => write!(f, "failed to apply encryption key"),
            VaultError::InvalidMeta => write!(f, "invalid or corrupt meta file"),
            VaultError::CorruptDatabase => write!(f, "database integrity check failed"),
            VaultError::WrongPassword => write!(f, "wrong password or corrupt vault"),
            VaultError::EncryptionError => write!(f, "encryption failed"),
            VaultError::DecryptionError => write!(f, "decryption failed — wrong key or corrupt data"),
            VaultError::Io(e) => write!(f, "I/O error: {}", e),
            VaultError::EmptyPlaintext => write!(f, "plaintext must not be empty"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Io(e)
    }
}