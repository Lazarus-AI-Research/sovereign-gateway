//! End-to-end exercise of `SqliteStore` against a real temp-file database.
//!
//! `:memory:` SQLite databases are not shared across pool connections, so we
//! create the DB in the OS temp dir and clean it up on drop.
//!
//! Identity model: a **user** is the login account that owns keys. There is no
//! installation/tenancy layer.

use std::path::PathBuf;

use yb_store::SqliteStore;

type TestStore = SqliteStore;

/// A temp DB path that deletes its files (incl. WAL/SHM) on drop.
struct TempDb {
    path: PathBuf,
}

impl TempDb {
    fn new() -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("yb_store_test_{}.db", yb_core::new_id()));
        TempDb { path }
    }
    fn as_str(&self) -> &str {
        self.path.to_str().unwrap()
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let p = format!("{}{}", self.path.display(), suffix);
            let _ = std::fs::remove_file(p);
        }
    }
}

async fn fresh_store() -> Option<(SqliteStore, TempDb)> {
    let db = TempDb::new();
    let store = SqliteStore::connect(db.as_str()).await.expect("connect");
    store.migrate().await.expect("migrate");
    // migrate is idempotent — running twice must not error.
    store.migrate().await.expect("migrate twice");
    Some((store, db))
}

async fn set_column(store: &SqliteStore, table: &str, column: &str, value: &str, id: &str) {
    sqlx::query(&format!("UPDATE {table} SET {column} = ? WHERE id = ?"))
        .bind(value)
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();
}

include!("common/store_contract.rs");
