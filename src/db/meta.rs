use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::crypto::constants::*;
use crate::error::VaultError;

pub struct MetaFile {
    pub salt: [u8; SALT_LEN],
}

impl MetaFile {
    pub fn new(salt: [u8; SALT_LEN]) -> Self {
        MetaFile { salt }
    }

    pub fn write(&self, path: &Path) -> Result<(), VaultError> {
        let mut buf = Vec::with_capacity(META_TOTAL_LEN);
        buf.extend_from_slice(META_MAGIC);
        buf.push(META_VERSION);
        buf.extend_from_slice(&[0u8; META_RESERVED_LEN]);
        buf.extend_from_slice(&self.salt);

        assert_eq!(buf.len(), META_TOTAL_LEN);

        // Atomic write: write to temp file, then rename
        let tmp_path = tmp_path(path);
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)?;
            f.write_all(&buf)?;
            f.sync_all()?;
        }
        fs::rename(&tmp_path, path)?;

        Ok(())
    }

    pub fn read(path: &Path) -> Result<Self, VaultError> {
        let mut f = fs::File::open(path).map_err(|_| VaultError::InvalidMeta)?;
        let mut buf = vec![0u8; META_TOTAL_LEN];
        f.read_exact(&mut buf).map_err(|_| VaultError::InvalidMeta)?;

        // Validate magic
        if &buf[0..8] != META_MAGIC {
            return Err(VaultError::InvalidMeta);
        }

        // Validate version
        if buf[8] != META_VERSION {
            return Err(VaultError::InvalidMeta);
        }

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&buf[16..16 + SALT_LEN]);

        Ok(MetaFile { salt })
    }
}

fn tmp_path(base: &Path) -> PathBuf {
    let mut p = base.to_path_buf();
    let ext = p
        .extension()
        .map(|e| format!("{}.tmp", e.to_string_lossy()))
        .unwrap_or_else(|| "tmp".to_string());
    p.set_extension(ext);
    p
}