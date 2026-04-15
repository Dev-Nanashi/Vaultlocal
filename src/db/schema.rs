use rusqlite::Connection;
use crate::error::VaultError;

pub fn create_schema(conn: &Connection) -> Result<(), VaultError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS entries (
            id          INTEGER PRIMARY KEY,
            label       TEXT    NOT NULL,
            identifier  TEXT    NOT NULL,
            nonce       BLOB    NOT NULL,
            ciphertext  BLOB    NOT NULL,
            created_at  INTEGER,
            UNIQUE(label, identifier)
        );",
    )
    .map_err(|_| VaultError::CorruptDatabase)
}

pub fn verify_schema(conn: &Connection) -> Result<(), VaultError> {
    // Check that the entries table exists with expected columns
    let count: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master
             WHERE type='table' AND name='entries'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| VaultError::CorruptDatabase)?;

    if count != 1 {
        return Err(VaultError::CorruptDatabase);
    }

    Ok(())
}