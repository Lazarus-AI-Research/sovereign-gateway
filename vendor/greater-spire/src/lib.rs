//! SPIFFE-authenticated connections using local certificates or embedded SPIRE.
//!
//! [`IdentityRuntime`] owns credential refresh; [`IdentitySource`] supplies the
//! same mTLS API for both providers. Incoming connections expose an
//! [`AuthenticatedPeer`]; the receiving application owns authorization.
//! See the README for configuration, provisioning, and HTTP integration.

#![doc = include_str!("../README.md")]

/// Exact stock SPIRE Server release this crate's private agent protocol is tested against.
///
/// SPIRE does not expose a version-negotiation RPC on this surface, so deployments
/// must enforce this pin when selecting the server artifact.
pub const SPIRE_SERVER_VERSION: &str = "1.15.3";

/// Upstream SPIRE API schema snapshot represented by the reduced local protobuf files.
pub const SPIRE_API_SCHEMA_VERSION: &str = "v1.15.3";

mod agent;
mod config;
mod error;
#[cfg(feature = "http")]
mod http_transport;
mod material;
/// Legacy application authorization helpers. Not used by the identity runtime or TLS.
#[cfg(feature = "legacy-policy")]
pub mod policy;
mod proto;
mod runtime;
mod state;
#[cfg(any(feature = "static-ca", test))]
pub mod static_ca;
mod status;
mod tls;

pub use agent::{AgentStatus, EmbeddedAgent};
pub use config::{
    AgentConfig, Config, IdentityConfig, IdentityProviderConfig, PeerConfig, Selector,
    TransportConfig,
};
pub use error::{Error, PeerIdentityError, Result, TimeoutPhase};
#[cfg(feature = "http")]
pub use http_transport::{HttpBody, HttpClient};
pub use runtime::IdentityRuntime;
pub use spiffe::{SpiffeId, TrustDomain};
pub use status::{IdentityStatus, RefreshStatus};
pub use tls::{
    AuthenticatedPeer, AuthenticatedStream, IdentitySource, MtlsAcceptor, MtlsConnector,
};
