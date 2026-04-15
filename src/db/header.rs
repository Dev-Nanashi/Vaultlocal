/// Structured stub for a future binary vault header embedded in vault.db.
///
/// Currently the meta file (`.meta`) handles salt storage.
/// This module is reserved for a future custom binary header format
/// that may be prepended to vault.db for additional metadata.

#[derive(Debug)]
pub struct VaultHeader {
    /// Magic bytes identifying the vault format.
    pub magic: [u8; 8],
    /// Format version.
    pub version: u8,
    /// Reserved for future flags or metadata.
    pub reserved: [u8; 7],
}

impl VaultHeader {
    pub const MAGIC: [u8; 8] = *b"VLTLOCL\x01";
    pub const VERSION: u8 = 1;

    pub fn new() -> Self {
        VaultHeader {
            magic: Self::MAGIC,
            version: Self::VERSION,
            reserved: [0u8; 7],
        }
    }
}

impl Default for VaultHeader {
    fn default() -> Self {
        Self::new()
    }
}