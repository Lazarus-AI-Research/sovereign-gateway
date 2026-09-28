//! The store contract against Postgres, the backend the appliance runs.
//!
//! `YB_TEST_POSTGRES_URL` names a server the tests may create databases on,
//! for example `postgres://test:test@127.0.0.1:55432/test`. Each test gets a
//! database of its own, dropped when the test ends. Without the variable
//! every test is skipped.

use sqlx::{Connection, PgConnection};
use yb_store::PostgresStore;

type TestStore = PostgresStore;

/// A database made for one test, dropped with it.
struct TempDatabase {
    server: String,
    name: String,
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        let (server, name) = (self.server.clone(), self.name.clone());
        // Drop cannot wait on the test's runtime; the database is dropped
        // on a runtime of its own, ending the store's connections with it.
        let _ = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async {
                if let Ok(mut connection) = PgConnection::connect(&server).await {
                    let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
                        .execute(&mut connection)
                        .await;
                }
            });
        })
        .join();
    }
}

/// The server's URL with another database in place of its own, or added
/// where it names none.
fn database_url(server: &str, name: &str) -> String {
    let (address, query) = server.split_once('?').unwrap_or((server, ""));
    let authority_start = address.find("://").map_or(0, |scheme| scheme + 3);
    let base = match address[authority_start..].find('/') {
        Some(path) => &address[..authority_start + path],
        None => address,
    };
    match query {
        "" => format!("{base}/{name}"),
        query => format!("{base}/{name}?{query}"),
    }
}

async fn fresh_store() -> Option<(PostgresStore, TempDatabase)> {
    let server = std::env::var("YB_TEST_POSTGRES_URL").ok()?;
    let name = format!("yb_store_test_{}", yb_core::new_id().replace('-', "_"));
    let mut connection = PgConnection::connect(&server)
        .await
        .expect("connect to the test server");
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut connection)
        .await
        .expect("create the test database");
    let database = TempDatabase {
        server: server.clone(),
        name: name.clone(),
    };
    let store = PostgresStore::connect(&database_url(&server, &name))
        .await
        .expect("connect");
    store.migrate().await.expect("migrate");
    // migrate is idempotent — running twice must not error.
    store.migrate().await.expect("migrate twice");
    Some((store, database))
}

#[test]
fn a_test_database_takes_the_servers_address() {
    for (server, want) in [
        ("postgres://u:p@h:5432/test", "postgres://u:p@h:5432/db"),
        (
            "postgres://u:p@h:5432/test?sslmode=disable",
            "postgres://u:p@h:5432/db?sslmode=disable",
        ),
        ("postgres://u:p@h:5432", "postgres://u:p@h:5432/db"),
        (
            "postgres://u:p@h:5432?sslmode=disable",
            "postgres://u:p@h:5432/db?sslmode=disable",
        ),
    ] {
        assert_eq!(database_url(server, "db"), want, "{server}");
    }
}

async fn set_column(store: &PostgresStore, table: &str, column: &str, value: &str, id: &str) {
    sqlx::query(&format!("UPDATE {table} SET {column} = $1 WHERE id = $2"))
        .bind(value)
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();
}

include!("common/store_contract.rs");
