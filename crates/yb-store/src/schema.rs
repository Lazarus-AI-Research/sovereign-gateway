//! Embedded, versioned migrations — one set per dialect.
//!
//! Tables are unprefixed (the database is already the namespace). Migrations are
//! applied by [`sqlx::migrate::Migrator`], which records what it has run in
//! `_sqlx_migrations`, so [`crate::Store::migrate`] is safe to call repeatedly.
//!
//! Identity model: **users** own **keys**; users group into **teams**. There is
//! no tenancy ("installation") layer, so no `installation_id` column appears.
//! **Models** are entities; a model has N **deployments** (the load-balancing
//! fan-out) and N **aliases**. Everything internal references `models.id`, so a
//! model can be renamed with a single `UPDATE`.
//!
//! Type deltas between dialects:
//! - ids / JSON columns: `TEXT` in both (JSON is stored as text, not jsonb,
//!   to avoid pulling in the sqlx `json` feature).
//! - timestamps: RFC3339 `TEXT` in SQLite, `TIMESTAMPTZ` in Postgres.
//! - money: `BIGINT` micro-dollars in both.
//! - ciphertext: `BLOB` in SQLite, `BYTEA` in Postgres.
//! - booleans: `INTEGER` 0/1 in SQLite, `BOOLEAN` in Postgres.

/// SQLite migrations. ids/timestamps as TEXT, money as INTEGER, blobs as BLOB.
pub static SQLITE_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");

/// Postgres migrations. ids/JSON as TEXT, timestamps TIMESTAMPTZ, money BIGINT,
/// ciphertext BYTEA, booleans BOOLEAN.
pub static POSTGRES_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    /// Every table one dialect creates, the other must create too.
    ///
    /// `model_aliases` was absent from the Postgres DDL for its entire life
    /// while three queries in `postgres.rs` referenced it — so aliases were
    /// wholly broken there, and because `reload_models` calls `list_aliases`,
    /// every model mutation failed *after* committing its write. Nothing caught
    /// it, because no CI job runs Postgres. Comparing the two files does.
    #[test]
    fn both_dialects_create_the_same_tables() {
        fn tables(sql: &str) -> BTreeSet<String> {
            sql.lines()
                .filter_map(|l| l.trim().strip_prefix("CREATE TABLE "))
                .map(|rest| rest.split_whitespace().next().unwrap_or("").to_string())
                .collect()
        }
        let sqlite = tables(include_str!("../migrations/sqlite/0000_initial.sql"));
        let postgres = tables(include_str!("../migrations/postgres/0000_initial.sql"));
        assert!(!sqlite.is_empty(), "no CREATE TABLE found — parser drifted");
        assert_eq!(sqlite, postgres);
    }
}
