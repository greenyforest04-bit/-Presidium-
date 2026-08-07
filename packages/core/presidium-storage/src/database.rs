//! Encrypted database opening, pragmas and schema migration.
//!
//! The database engine is sqleet (vendored): SQLite with ChaCha20-Poly1305
//! page encryption, activated via the raw 32-byte Argon2id-derived key.

use std::path::Path;
use std::time::Duration;

use presidium_sqleet::Connection;
use zeroize::Zeroizing;

use crate::error::{Result, StorageError};

/// Schema migrations, applied in order via `PRAGMA user_version`.
const MIGRATIONS: &[(&str, &str)] = &[(
    "0001_init.sql",
    include_str!("../migrations/0001_init.sql"),
)];

/// An open encrypted database with the schema applied.
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open (creating if needed) an encrypted database file.
    ///
    /// `key` is the raw 32-byte sqleet key; derive it from a passphrase with
    /// [`crate::kdf::derive_db_key`].
    pub fn open(path: &Path, key: &[u8]) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::finish(conn, key)
    }

    /// Open an in-memory encrypted database (used by tests and tooling).
    pub fn open_in_memory(key: &[u8]) -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::finish(conn, key)
    }

    fn finish(mut conn: Connection, key: &[u8]) -> Result<Self> {
        let _key_guard = Zeroizing::new(key.to_vec());
        conn.key(key)
            .map_err(|e| StorageError::KeyDerivation(format!("sqleet key: {e}")))?;

        conn.pragma_set_string("journal_mode", "WAL")?;
        conn.execute_batch("PRAGMA foreign_keys = ON")?;
        conn.busy_timeout(Duration::from_secs(5))?;

        run_migrations(&conn)?;
        Ok(Self { conn })
    }

    /// Access the underlying connection (queries go through [`crate::store`]).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Close the database, flushing the WAL.
    pub fn close(self) -> Result<()> {
        self.conn.close().map_err(StorageError::Database)
    }
}

/// Apply pending schema migrations.
pub fn run_migrations(conn: &Connection) -> Result<()> {
    let current = conn.pragma_i64("user_version")?;
    for (index, (name, sql)) in MIGRATIONS.iter().enumerate() {
        let target = i64::try_from(index + 1).unwrap_or(i64::MAX);
        if target <= current {
            continue;
        }
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.execute_batch(&format!("PRAGMA user_version = {target}"))?;
        tx.commit()?;
        tracing::info!(migration = name, version = target, "applied");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::derive_db_key;

    #[test]
    fn migration_applies_on_fresh_database() {
        let key = derive_db_key(b"pw", b"0123456789abcdef").unwrap();
        let db = Database::open_in_memory(key.as_slice()).unwrap();
        assert_eq!(
            db.conn().pragma_i64("user_version").unwrap(),
            MIGRATIONS.len() as i64
        );
    }

    #[test]
    fn wrong_key_fails_queries() {
        let good = derive_db_key(b"right", b"0123456789abcdef").unwrap();
        let db = Database::open_in_memory(good.as_slice()).unwrap();
        db.conn()
            .execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES (42)")
            .unwrap();

        let bad = derive_db_key(b"wrong", b"0123456789abcdef").unwrap();
        let db2 = Database::open_in_memory(bad.as_slice()).unwrap();
        let result = db2
            .conn()
            .query_row("SELECT x FROM t", &[], |row| row.get::<i64>(0));
        assert!(result.is_err(), "wrong key must not read plaintext");
    }

    #[test]
    fn file_database_reopens_with_same_key() {
        let dir = std::env::temp_dir().join(format!("presidium-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.db");
        let key = derive_db_key(b"pw", b"0123456789abcdef").unwrap();

        let db = Database::open(&path, key.as_slice()).unwrap();
        db.conn()
            .execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES (42)")
            .unwrap();
        drop(db);

        let reopened = Database::open(&path, key.as_slice()).unwrap();
        let value = reopened
            .conn()
            .query_row("SELECT x FROM t", &[], |row| row.get::<i64>(0))
            .unwrap()
            .unwrap();
        assert_eq!(value, 42);

        let wrong = derive_db_key(b"nope", b"0123456789abcdef").unwrap();
        let bad = Database::open(&path, wrong.as_slice());
        assert!(bad.is_err(), "sqleet must reject a wrong key at open() time");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parameter_binding_roundtrip() {
        use presidium_sqleet::Param;

        let key = derive_db_key(b"pw", b"0123456789abcdef").unwrap();
        let db = Database::open_in_memory(key.as_slice()).unwrap();
        db.conn()
            .execute(
                "CREATE TABLE t(a INTEGER, b TEXT, c BLOB, d TEXT)",
                &[],
            )
            .unwrap();
        db.conn()
            .execute(
                "INSERT INTO t VALUES (?1, ?2, ?3, ?4)",
                &[
                    Param::I64(7),
                    Param::Text("hello".into()),
                    Param::Blob(vec![1, 2, 3]),
                    Param::Null,
                ],
            )
            .unwrap();
        let row = db
            .conn()
            .query_row("SELECT a, b, c, d FROM t", &[], |row| {
                Ok((
                    row.get::<i64>(0)?,
                    row.get::<String>(1)?,
                    row.get::<Vec<u8>>(2)?,
                    row.get::<Option<String>>(3)?,
                ))
            })
            .unwrap()
            .unwrap();
        assert_eq!(row, (7, "hello".to_string(), vec![1, 2, 3], None));
    }
}
