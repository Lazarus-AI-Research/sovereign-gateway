//! # yb-gateway
//!
//! The orchestration service at the centre of the gateway. It owns no transport,
//! storage, or wire knowledge of its own; instead it composes the four adapter
//! contracts from `yb-core` —
//!
//! - [`yb_providers::UpstreamClient`] (the network),
//! - [`yb_core::Router`] (model → deployment selection),
//! - [`yb_core::Store`] (telemetry + spend persistence), and
//! - [`yb_core::RequestLogger`] (request/response capture) —
//!
//! and drives a single inbound request through parse → route → dispatch (with
//! fallback) → translate → record.
//!
//! Two pieces live here:
//!
//! - [`DeploymentRouter`] — a [`yb_core::Router`] built from a
//!   [`yb_core::config::RoutingConfig`], implementing the LiteLLM-style routing
//!   table (filtering, weighted/round-robin/least-busy ordering, fallbacks).
//! - [`Gateway`] — the service whose [`Gateway::handle`] method performs the
//!   end-to-end orchestration and returns a [`GatewayResponse`].
//!
//! The crate also exposes the per-[`yb_core::WireFormat`] dispatch helpers in
//! [`wire`], used by both pieces and reusable by `yb-server`.

pub mod embed;
pub mod health;
pub mod router;
pub mod service;
pub mod wire;

pub use router::DeploymentRouter;
pub use service::{Gateway, GatewayResponse, RequestCtx};
pub use health::HealthReport;
