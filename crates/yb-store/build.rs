//! Rebuild when a migration changes.
//!
//! `sqlx::migrate!()` embeds the SQL at compile time, so without a rerun key an
//! edited `.sql` file would sit stale inside the binary while the source on disk
//! looked correct.
fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
