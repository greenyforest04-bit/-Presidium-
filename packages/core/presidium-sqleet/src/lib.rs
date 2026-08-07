//! Minimal safe wrapper over the vendored sqleet C amalgamation.
//!
//! sqleet is SQLite with built-in ChaCha20-Poly1305 page encryption
//! (public domain, https://github.com/resilar/sqleet). Only the subset of
//! the SQLite C API needed by the Presidium storage layer is exposed.

#![deny(missing_docs)]

use std::ffi::{c_char, c_int, c_void};
use std::marker::PhantomData;
use std::path::Path;
use std::ptr;
use std::time::Duration;

mod ffi {
    use super::*;

    extern "C" {
        pub fn sqlite3_open_v2(
            filename: *const c_char,
            pp_db: *mut *mut c_void,
            flags: c_int,
            z_vfs: *const c_char,
        ) -> c_int;
        pub fn sqlite3_close_v2(db: *mut c_void) -> c_int;
        pub fn sqlite3_key(db: *mut c_void, key: *const c_void, n_key: c_int) -> c_int;
        pub fn sqlite3_errcode(db: *mut c_void) -> c_int;
        pub fn sqlite3_errmsg(db: *mut c_void) -> *const c_char;
        pub fn sqlite3_exec(
            db: *mut c_void,
            sql: *const c_char,
            callback: Option<unsafe extern "C" fn(*mut c_void, c_int, *mut *mut c_char, *mut *mut c_char) -> c_int>,
            arg: *mut c_void,
            errmsg: *mut *mut c_char,
        ) -> c_int;
        pub fn sqlite3_prepare_v2(
            db: *mut c_void,
            sql: *const c_char,
            n_byte: c_int,
            pp_stmt: *mut *mut c_void,
            pz_tail: *mut *const c_char,
        ) -> c_int;
        pub fn sqlite3_finalize(stmt: *mut c_void) -> c_int;
        pub fn sqlite3_bind_int64(stmt: *mut c_void, index: c_int, value: i64) -> c_int;
        pub fn sqlite3_bind_text(
            stmt: *mut c_void,
            index: c_int,
            value: *const c_char,
            len: c_int,
            destructor: Option<unsafe extern "C" fn(*mut c_void)>,
        ) -> c_int;
        pub fn sqlite3_bind_blob(
            stmt: *mut c_void,
            index: c_int,
            value: *const c_void,
            len: c_int,
            destructor: Option<unsafe extern "C" fn(*mut c_void)>,
        ) -> c_int;
        pub fn sqlite3_bind_null(stmt: *mut c_void, index: c_int) -> c_int;
        pub fn sqlite3_step(stmt: *mut c_void) -> c_int;
        pub fn sqlite3_column_count(stmt: *mut c_void) -> c_int;
        pub fn sqlite3_column_type(stmt: *mut c_void, col: c_int) -> c_int;
        pub fn sqlite3_column_int64(stmt: *mut c_void, col: c_int) -> i64;
        pub fn sqlite3_column_blob(stmt: *mut c_void, col: c_int) -> *const c_void;
        pub fn sqlite3_column_bytes(stmt: *mut c_void, col: c_int) -> c_int;
        pub fn sqlite3_last_insert_rowid(db: *mut c_void) -> i64;
        pub fn sqlite3_busy_timeout(db: *mut c_void, ms: c_int) -> c_int;
        pub fn sqlite3_changes(db: *mut c_void) -> c_int;
    }
}

const OPEN_READWRITE: c_int = 0x0000_0002;
const OPEN_CREATE: c_int = 0x0000_0004;
const OPEN_FULLMUTEX: c_int = 0x0000_1000;
const SQLITE_OK: c_int = 0;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;
const SQLITE_NULL: c_int = 5;

/// Errors produced by the sqleet wrapper.
#[derive(Debug)]
pub struct SqlError {
    /// SQLite result code.
    pub code: i32,
    /// Human-readable message from the engine.
    pub message: String,
}

impl std::fmt::Display for SqlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sqleet error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for SqlError {}

/// Convert a SQLite result code into `Ok`/`Err`.
fn check(db: *mut c_void, code: c_int) -> Result<(), SqlError> {
    if code == SQLITE_OK {
        Ok(())
    } else {
        unsafe {
            let msg = ffi::sqlite3_errmsg(db);
            let message = if msg.is_null() {
                "unknown error".to_string()
            } else {
                std::ffi::CStr::from_ptr(msg).to_string_lossy().into_owned()
            };
            Err(SqlError { code, message })
        }
    }
}

/// A bound parameter value.
#[derive(Debug, Clone)]
pub enum Param {
    /// SQL NULL.
    Null,
    /// 64-bit integer.
    I64(i64),
    /// Text (UTF-8).
    Text(String),
    /// Raw bytes.
    Blob(Vec<u8>),
}

impl From<i64> for Param {
    fn from(v: i64) -> Self {
        Self::I64(v)
    }
}

impl From<bool> for Param {
    fn from(v: bool) -> Self {
        Self::I64(i64::from(v))
    }
}

impl From<&str> for Param {
    fn from(v: &str) -> Self {
        Self::Text(v.to_string())
    }
}

impl From<&String> for Param {
    fn from(v: &String) -> Self {
        Self::Text(v.clone())
    }
}

impl From<String> for Param {
    fn from(v: String) -> Self {
        Self::Text(v)
    }
}

impl From<&[u8]> for Param {
    fn from(v: &[u8]) -> Self {
        Self::Blob(v.to_vec())
    }
}

impl From<&Vec<u8>> for Param {
    fn from(v: &Vec<u8>) -> Self {
        Self::Blob(v.clone())
    }
}

impl From<Vec<u8>> for Param {
    fn from(v: Vec<u8>) -> Self {
        Self::Blob(v)
    }
}

impl From<Option<i64>> for Param {
    fn from(v: Option<i64>) -> Self {
        v.map_or(Self::Null, Self::I64)
    }
}

impl From<Option<String>> for Param {
    fn from(v: Option<String>) -> Self {
        v.map_or(Self::Null, Self::Text)
    }
}

impl From<&Option<String>> for Param {
    fn from(v: &Option<String>) -> Self {
        v.clone().map_or(Self::Null, Self::Text)
    }
}

/// Helper macro mirroring `rusqlite::params!`: `params![a, b, c]`.
#[macro_export]
macro_rules! params {
    ($($param:expr),+ $(,)?) => {
        &[$($crate::Param::from($param)),+]
    };
}

/// A row of a query result.
pub struct Row<'stmt> {
    stmt: *mut c_void,
    _marker: PhantomData<&'stmt ()>,
}

/// Values that can be extracted from a [`Row`].
pub trait FromSqleetValue: Sized {
    /// Extract from column `idx`.
    fn from_sqleet(row: &Row, idx: usize) -> Result<Self, SqlError>;
}

fn column_bytes(row: &Row, idx: usize) -> (c_int, *const c_void) {
    unsafe {
        (
            ffi::sqlite3_column_bytes(row.stmt, idx as c_int),
            ffi::sqlite3_column_blob(row.stmt, idx as c_int),
        )
    }
}

fn column_type(row: &Row, idx: usize) -> c_int {
    unsafe { ffi::sqlite3_column_type(row.stmt, idx as c_int) }
}

fn column_i64(row: &Row, idx: usize) -> i64 {
    unsafe { ffi::sqlite3_column_int64(row.stmt, idx as c_int) }
}

fn column_bytes_owned(row: &Row, idx: usize) -> Result<Vec<u8>, SqlError> {
    if column_type(row, idx) == SQLITE_NULL {
        return Err(SqlError {
            code: SQLITE_OK,
            message: "attempted to read a NULL column as a value".into(),
        });
    }
    let (len, ptr) = column_bytes(row, idx);
    if ptr.is_null() {
        return Ok(Vec::new());
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) }.to_vec())
}

impl FromSqleetValue for i64 {
    fn from_sqleet(row: &Row, idx: usize) -> Result<Self, SqlError> {
        Ok(column_i64(row, idx))
    }
}

impl FromSqleetValue for bool {
    fn from_sqleet(row: &Row, idx: usize) -> Result<Self, SqlError> {
        Ok(column_i64(row, idx) != 0)
    }
}

impl FromSqleetValue for String {
    fn from_sqleet(row: &Row, idx: usize) -> Result<Self, SqlError> {
        Ok(String::from_utf8_lossy(&column_bytes_owned(row, idx)?).into_owned())
    }
}

impl FromSqleetValue for Vec<u8> {
    fn from_sqleet(row: &Row, idx: usize) -> Result<Self, SqlError> {
        column_bytes_owned(row, idx)
    }
}

impl FromSqleetValue for Option<i64> {
    fn from_sqleet(row: &Row, idx: usize) -> Result<Self, SqlError> {
        if column_type(row, idx) == SQLITE_NULL {
            Ok(None)
        } else {
            Ok(Some(column_i64(row, idx)))
        }
    }
}

impl FromSqleetValue for Option<String> {
    fn from_sqleet(row: &Row, idx: usize) -> Result<Self, SqlError> {
        if column_type(row, idx) == SQLITE_NULL {
            Ok(None)
        } else {
            <String as FromSqleetValue>::from_sqleet(row, idx).map(Some)
        }
    }
}

impl FromSqleetValue for Option<Vec<u8>> {
    fn from_sqleet(row: &Row, idx: usize) -> Result<Self, SqlError> {
        if column_type(row, idx) == SQLITE_NULL {
            Ok(None)
        } else {
            <Vec<u8> as FromSqleetValue>::from_sqleet(row, idx).map(Some)
        }
    }
}

impl<'stmt> Row<'stmt> {
    /// Read column `idx` as `T`.
    pub fn get<T: FromSqleetValue>(&self, idx: usize) -> Result<T, SqlError> {
        T::from_sqleet(self, idx)
    }

    /// Number of columns in this row.
    pub fn column_count(&self) -> usize {
        unsafe { ffi::sqlite3_column_count(self.stmt) as usize }
    }
}

/// An open sqleet database connection (thread-safe engine, single-user use).
pub struct Connection {
    db: *mut c_void,
}

impl Connection {
    /// Open a database file, creating it if missing.
    pub fn open(path: &Path) -> Result<Self, SqlError> {
        let path_c = path
            .to_str()
            .ok_or_else(|| SqlError {
                code: SQLITE_OK,
                message: "database path is not valid UTF-8".into(),
            })?
            .to_owned();
        let mut db = ptr::null_mut();
        let flags = OPEN_READWRITE | OPEN_CREATE | OPEN_FULLMUTEX;
        let c_path = std::ffi::CString::new(path_c).map_err(|_| SqlError {
            code: SQLITE_OK,
            message: "database path contains a NUL byte".into(),
        })?;
        let code = unsafe { ffi::sqlite3_open_v2(c_path.as_ptr(), &mut db, flags, ptr::null()) };
        if db.is_null() {
            return Err(SqlError {
                code,
                message: "failed to allocate connection".into(),
            });
        }
        check(db, code)?;
        Ok(Self { db })
    }

    /// Open an in-memory database.
    pub fn open_in_memory() -> Result<Self, SqlError> {
        let mut db = ptr::null_mut();
        let code = unsafe {
            ffi::sqlite3_open_v2(
                c":memory:".as_ptr(),
                &mut db,
                OPEN_READWRITE | OPEN_CREATE | OPEN_FULLMUTEX,
                ptr::null(),
            )
        };
        if db.is_null() {
            return Err(SqlError {
                code,
                message: "failed to allocate connection".into(),
            });
        }
        check(db, code)?;
        Ok(Self { db })
    }

    /// Set the raw encryption key (ChaCha20-Poly1305, 32 bytes).
    ///
    /// Must be called before any other operation.
    pub fn key(&mut self, key: &[u8]) -> Result<(), SqlError> {
        let code = unsafe { ffi::sqlite3_key(self.db, key.as_ptr().cast(), key.len() as c_int) };
        check(self.db, code)
    }

    /// Execute a statement with bound parameters, returning rows changed.
    pub fn execute(&self, sql: &str, params: &[Param]) -> Result<usize, SqlError> {
        let mut stmt = Statement::prepare(self.db, sql)?;
        stmt.bind_all(params)?;
        stmt.consume()?;
        Ok(unsafe { ffi::sqlite3_changes(self.db) } as usize)
    }

    /// Execute a batch of SQL statements (no parameters).
    pub fn execute_batch(&self, sql: &str) -> Result<(), SqlError> {
        let c_sql = std::ffi::CString::new(sql)
            .map_err(|_| SqlError { code: SQLITE_OK, message: "SQL contains a NUL byte".into() })?;
        let code = unsafe {
            ffi::sqlite3_exec(self.db, c_sql.as_ptr(), None, ptr::null_mut(), ptr::null_mut())
        };
        check(self.db, code)
    }

    /// Run a query returning at most one row.
    pub fn query_row<T>(
        &self,
        sql: &str,
        params: &[Param],
        map: impl FnOnce(&Row) -> Result<T, SqlError>,
    ) -> Result<Option<T>, SqlError> {
        let mut stmt = Statement::prepare(self.db, sql)?;
        stmt.bind_all(params)?;
        match stmt.step()? {
            None => Ok(None),
            Some(row) => Ok(Some(map(&row)?)),
        }
    }

    /// Run a query mapping all rows.
    pub fn query_rows<T>(
        &self,
        sql: &str,
        params: &[Param],
        map: impl Fn(&Row) -> Result<T, SqlError>,
    ) -> Result<Vec<T>, SqlError> {
        let mut stmt = Statement::prepare(self.db, sql)?;
        stmt.bind_all(params)?;
        let mut out = Vec::new();
        while let Some(row) = stmt.step()? {
            out.push(map(&row)?);
        }
        Ok(out)
    }

    /// Row id of the last successful insert.
    pub fn last_insert_rowid(&self) -> i64 {
        unsafe { ffi::sqlite3_last_insert_rowid(self.db) }
    }

    /// Set the busy timeout.
    pub fn busy_timeout(&self, duration: Duration) -> Result<(), SqlError> {
        let ms = duration.as_millis().min(i32::MAX as u128) as i32;
        check(self.db, unsafe { ffi::sqlite3_busy_timeout(self.db, ms) })
    }

    /// Read a scalar PRAGMA value.
    pub fn pragma_i64(&self, name: &str) -> Result<i64, SqlError> {
        let sql = format!("PRAGMA {name}");
        Ok(self
            .query_row(&sql, &[], |row| row.get::<i64>(0))?
            .unwrap_or(0))
    }

    /// Set a PRAGMA with a quoted string value.
    pub fn pragma_set_string(&self, name: &str, value: &str) -> Result<(), SqlError> {
        let escaped = value.replace('\'', "''");
        let sql = format!("PRAGMA {name} = '{escaped}'");
        self.execute_batch(&sql)
    }

    /// Begin a transaction.
    pub fn transaction(&self) -> Result<Transaction<'_>, SqlError> {
        self.execute_batch("BEGIN")?;
        Ok(Transaction {
            conn: self,
            done: false,
        })
    }

    /// Close the connection, freeing the underlying handle.
    pub fn close(self) -> Result<(), SqlError> {
        let code = unsafe { ffi::sqlite3_close_v2(self.db) };
        check(self.db, code)
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        unsafe {
            ffi::sqlite3_close_v2(self.db);
        }
    }
}

unsafe impl Send for Connection {}

/// A prepared statement.
struct Statement {
    stmt: *mut c_void,
    db: *mut c_void,
    /// CStrings backing text params, kept alive until the statement is finalized.
    owned_texts: Vec<std::ffi::CString>,
}

impl Statement {
    fn prepare(db: *mut c_void, sql: &str) -> Result<Self, SqlError> {
        let c_sql = std::ffi::CString::new(sql)
            .map_err(|_| SqlError { code: SQLITE_OK, message: "SQL contains a NUL byte".into() })?;
        let mut stmt = ptr::null_mut();
        let code = unsafe {
            ffi::sqlite3_prepare_v2(db, c_sql.as_ptr(), -1, &mut stmt, ptr::null_mut())
        };
        if stmt.is_null() {
            return Err(SqlError {
                code,
                message: check(db, code).err().map_or_else(|| "no rows returned".into(), |e| e.message),
            });
        }
        Ok(Self {
            stmt,
            db,
            owned_texts: Vec::new(),
        })
    }

    fn bind_all(&mut self, params: &[Param]) -> Result<(), SqlError> {
        for (i, param) in params.iter().enumerate() {
            let index = (i + 1) as c_int;
            let code = match param {
                Param::Null => unsafe { ffi::sqlite3_bind_null(self.stmt, index) },
                Param::I64(v) => unsafe { ffi::sqlite3_bind_int64(self.stmt, index, *v) },
                Param::Text(s) => {
                    let c = std::ffi::CString::new(s.as_str()).map_err(|_| SqlError {
                        code: SQLITE_OK,
                        message: "text param contains a NUL byte".into(),
                    })?;
                    self.owned_texts.push(c);
                    let ptr = self.owned_texts.last().unwrap().as_ptr();
                    unsafe {
                        ffi::sqlite3_bind_text(self.stmt, index, ptr, -1, None)
                    }
                }
                Param::Blob(b) => unsafe {
                    ffi::sqlite3_bind_blob(
                        self.stmt,
                        index,
                        b.as_ptr().cast(),
                        b.len() as c_int,
                        None,
                    )
                },
            };
            check(self.db, code)?;
        }
        Ok(())
    }

    /// Step once, returning the row or `None` at end of data.
    fn step(&self) -> Result<Option<Row<'_>>, SqlError> {
        let code = unsafe { ffi::sqlite3_step(self.stmt) };
        match code {
            SQLITE_ROW => Ok(Some(Row {
                stmt: self.stmt,
                _marker: PhantomData,
            })),
            SQLITE_DONE => Ok(None),
            other => Err(self.error(other)),
        }
    }

    fn consume(&self) -> Result<(), SqlError> {
        loop {
            let code = unsafe { ffi::sqlite3_step(self.stmt) };
            match code {
                SQLITE_DONE => return Ok(()),
                SQLITE_ROW => {}
                other => return Err(self.error(other)),
            }
        }
    }

    fn error(&self, code: c_int) -> SqlError {
        let _ = code;
        let mut message = "unknown error".to_string();
        unsafe {
            let raw = ffi::sqlite3_errmsg(self.db);
            if !raw.is_null() {
                message = std::ffi::CStr::from_ptr(raw).to_string_lossy().into_owned();
            }
        }
        SqlError {
            code: unsafe { ffi::sqlite3_errcode(self.db) },
            message,
        }
    }
}

impl Drop for Statement {
    fn drop(&mut self) {
        unsafe {
            ffi::sqlite3_finalize(self.stmt);
        }
    }
}

/// A transaction; rolls back on drop unless committed.
pub struct Transaction<'conn> {
    conn: &'conn Connection,
    done: bool,
}

impl<'conn> Transaction<'conn> {
    /// Execute a statement within the transaction.
    pub fn execute(&self, sql: &str, params: &[Param]) -> Result<usize, SqlError> {
        self.conn.execute(sql, params)
    }

    /// Run a query within the transaction returning at most one row.
    pub fn query_row<T>(
        &self,
        sql: &str,
        params: &[Param],
        map: impl FnOnce(&Row) -> Result<T, SqlError>,
    ) -> Result<Option<T>, SqlError> {
        self.conn.query_row(sql, params, map)
    }

    /// Run a query within the transaction mapping all rows.
    pub fn query_rows<T>(
        &self,
        sql: &str,
        params: &[Param],
        map: impl Fn(&Row) -> Result<T, SqlError>,
    ) -> Result<Vec<T>, SqlError> {
        self.conn.query_rows(sql, params, map)
    }

    /// Execute a batch of statements within the transaction.
    pub fn execute_batch(&self, sql: &str) -> Result<(), SqlError> {
        self.conn.execute_batch(sql)
    }

    /// Commit the transaction.
    pub fn commit(mut self) -> Result<(), SqlError> {
        self.done = true;
        self.conn.execute_batch("COMMIT")
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.conn.execute_batch("ROLLBACK");
        }
    }
}
