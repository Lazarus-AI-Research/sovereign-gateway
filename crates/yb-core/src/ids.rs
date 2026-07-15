//! Core scalar aliases and id helpers used throughout the domain.

/// Opaque identifier. We store UUIDv4 as text so the same value round-trips
/// identically through SQLite (`TEXT`) and Postgres (`uuid`/`text`).
pub type Id = String;

/// USD amount stored as integer micro-dollars (1 USD = 1_000_000 micros).
/// Money is never a float at rest.
pub type Micros = i64;

/// UTC timestamp. Serialized as RFC3339 so it sorts lexically in SQLite.
pub type Timestamp = chrono::DateTime<chrono::Utc>;

/// Generate a fresh opaque id (application-side, dialect-agnostic).
pub fn new_id() -> Id {
    uuid::Uuid::new_v4().to_string()
}

/// Current wall-clock time, UTC.
pub fn now() -> Timestamp {
    chrono::Utc::now()
}

/// Convert a USD float to micros (round to nearest).
pub fn usd_to_micros(usd: f64) -> Micros {
    (usd * 1_000_000.0).round() as Micros
}

/// Convert micros back to a USD float (for display only).
pub fn micros_to_usd(micros: Micros) -> f64 {
    micros as f64 / 1_000_000.0
}
