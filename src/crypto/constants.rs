// Key sizes
pub const ROOT_KEY_LEN: usize = 32;
pub const DB_KEY_LEN: usize = 32;
pub const MASTER_KEY_LEN: usize = 32;
pub const ENTRY_KEY_LEN: usize = 32;

// Nonce size for AES-256-GCM-SIV
pub const NONCE_LEN: usize = 12;

// Salt size for Argon2id
pub const SALT_LEN: usize = 32;

// Argon2id parameters (OWASP recommended minimum for high-security)
pub const ARGON2_M_COST: u32 = 65536; // 64 MiB
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 4;

// HKDF domain separation labels
pub const HKDF_INFO_DB: &[u8] = b"vaultlocal/db";
pub const HKDF_INFO_MASTER: &[u8] = b"vaultlocal/master";
pub const HKDF_INFO_ENTRY: &[u8] = b"vaultlocal/entry";

// Meta file
pub const META_MAGIC: &[u8; 8] = b"VLTLOCL\x01";
pub const META_VERSION: u8 = 1;
pub const META_RESERVED_LEN: usize = 7;
pub const META_TOTAL_LEN: usize = 8 + 1 + 7 + SALT_LEN; // 48 bytes

// Canary label used to verify correct password
pub const CANARY_LABEL: &str = "__canary__";
pub const CANARY_IDENTIFIER: &str = "__verify__";
pub const CANARY_PLAINTEXT: &[u8] = b"vaultlocal-canary-ok";