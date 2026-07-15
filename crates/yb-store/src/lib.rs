//! # yb-store
//!
//! Storage adapters for the gateway. Two concrete backends — [`SqliteStore`] and
//! [`PostgresStore`] — implement the frozen [`yb_core::Store`] trait, plus the
//! crypto adapters ([`AesGcmEncryptor`], [`Argon2Hasher`]) and virtual-key
//! helpers ([`generate_api_key`], [`hash_token`], [`issue_api_key`]).
//!
//! Everything is runtime sqlx (no compile-time macros / no DB at build), rows
//! are mapped by hand, and migrations are embedded idempotent SQL keyed by the
//! `yb_` table prefix.

mod common;
pub mod crypto;
pub mod keys;
pub mod postgres;
pub mod schema;
pub mod sqlite;

pub use crypto::{AesGcmEncryptor, Argon2Hasher};
pub use keys::{generate_api_key, hash_token, issue_api_key, KEY_PREFIX};
pub use postgres::PostgresStore;
pub use sqlite::SqliteStore;

// Re-export the core crypto/store contracts these adapters implement, so a
// downstream crate can `use yb_store::Store` etc. without reaching into yb-core.
pub use yb_core::crypto::{Encryptor, PasswordHasher};
pub use yb_core::Store;
