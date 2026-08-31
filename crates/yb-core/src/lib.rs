//! # yb-core
//!
//! The inner-ring domain for the gateway: value types, errors, and the contracts
//! (`Store`, `Router`, `RequestLogger`, `Encryptor`, `PasswordHasher`) that the
//! adapter crates implement. Pure and I/O-free — no HTTP, DB, or filesystem here.

pub mod catalog;
pub mod config;
pub mod crypto;
pub mod error;
pub mod ids;
pub mod model;
pub mod observe;
pub mod principal;
pub mod ratelimit;
pub mod rbac;
pub mod reqlog;
pub mod routing;
pub mod spend;
pub mod store;

pub use error::{Error, Result};
pub use ids::{micros_to_usd, new_id, now, usd_to_micros, Id, Micros, Timestamp};
pub use model::{
    AccessPolicy, ApiKey, ExternalKey, IssuedKey, KeyScope, ModelAlias, ResolvedCredential, Role,
    Session,
    Team, TeamMembership, TelemetryRecord, User,
};
pub use principal::{KeyAuth, Principal};
pub use observe::{NullObserver, Observer};
pub use reqlog::{NullLogger, RequestLogRecord, RequestLogger};
pub use routing::{
    Decision, Deployment, DeploymentRecord, EmbedFormat, Extra, HealthCheck, RouteRequest,
    Router, UpstreamFormat,
    WireFormat,
};
pub use store::{LimitColumns, Store};
