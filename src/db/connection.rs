use rusqlite::Connection;

use crate::error::VaultError;

/// Opens an encrypted SQLCipher database at `path` using the given key.
///
/// Enforces SQLCipher availability and applies all required PRAGMAs.
/// Hard-fails if SQLCipher is not present or key application fails.
pub fn open_encrypted(path: &str, db_key: &[u8]) -> Result<Connection, VaultError> {
    let conn = Connection::open(path).map_err(|_| VaultError::DbOpen)?;

    verify_sqlcipher(&conn)?;
    apply_key(&conn, db_key)?;
    apply_pragmas(&conn)?;

    Ok(conn)
}

fn verify_sqlcipher(conn: &Connection) -> Result<(), VaultError> {
    // SQLCipher exposes the cipher_version pragma; plain SQLite does not.
    let result: rusqlite::Result<String> =
        conn.query_row("PRAGMA cipher_version", [], |row| row.get(0));

    match result {
        Ok(v) if !v.is_empty() => Ok(()),
        _ => Err(VaultError::SqlcipherMissing),
    }
}

fn apply_key(conn: &Connection, db_key: &[u8]) -> Result<(), VaultError> {
    // Key must be passed as raw bytes via PRAGMA key = "x'<hex>'";
    let hex_key = hex::encode(db_key);
    let pragma = format!("PRAGMA key = \"x'{}'\";", hex_key);

    conn.execute_batch(&pragma).map_err(|_| VaultError::KeyApplyFailed)?;

    // Verify the key works by executing a simple query
    conn.execute_batch("SELECT count(*) FROM sqlite_master;")
        .map_err(|_| VaultError::WrongPassword)?;

    Ok(())
}

fn apply_pragmas(conn: &Connection) -> Result<(), VaultError> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA secure_delete = ON;
         PRAGMA journal_mode = WAL;",
    )
    .map_err(|_| VaultError::DbOpen)
}