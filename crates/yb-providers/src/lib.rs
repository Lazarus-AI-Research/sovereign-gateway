//! # yb-providers
//!
//! Upstream HTTP clients for the gateway. This crate is deliberately thin: it knows
//! how to take a fully-formed [`UpstreamRequest`] (URL, headers, and a body that
//! the gateway/emitter already rendered into the correct vendor wire format) and
//! perform the network round-trip, returning either a full body or a streamed
//! one.
//!
//! The crate does **not** know about wire translation — that lives in `yb-wire`
//! and is orchestrated by `yb-gateway`. The only vendor-specific knowledge here
//! is mechanical: how to build the request URL and the auth headers for each
//! [`WireFormat`](yb_core::WireFormat) (see [`route`]), and which HTTP
//! statuses are worth retrying.
//!
//! ## Components
//! - [`UpstreamClient`]: the async send contract.
//! - [`HttpClient`]: a `reqwest`-backed implementation usable for all provider
//!   kinds (they differ only in URL + auth, which the caller supplies).
//! - [`MockClient`]: a canned-response client for tests and smoke checks.
//! - [`route`]: URL/auth-header builders and status classifiers.

pub mod http;
pub mod mock;
pub mod route;

use std::pin::Pin;

use bytes::Bytes;
use futures::Stream;

pub use http::HttpClient;
pub use mock::{MockBody, MockClient};
pub use route::{append_headers, 
    auth_headers, build_embed_url, build_url, cloudflare_access_headers, embed_auth_headers,
    is_model_not_found, is_retryable,
};

/// A boxed, owned byte stream as returned by a streaming upstream response.
///
/// Each item is a chunk of raw response bytes (typically a slice of one or more
/// SSE events) or a transport error mapped to [`yb_core::Error`].
pub type ByteStream = Pin<Box<dyn Stream<Item = yb_core::Result<Bytes>> + Send>>;

/// A request to an upstream provider.
///
/// The body and headers are produced by the gateway after wire translation;
/// this crate treats them as opaque. `url` and the auth headers are normally
/// built with [`build_url`] and [`auth_headers`].
/// The HTTP method of an [`UpstreamRequest`]. Inference is always `Post`;
/// `Get` exists for health checks (`/health`, `/v1/models`, …).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HttpMethod {
    #[default]
    Post,
    Get,
}

#[derive(Debug, Clone)]
pub struct UpstreamRequest {
    /// Fully-qualified request URL (including any query string).
    pub url: String,
    /// HTTP method (Post for inference; Get for health checks).
    pub method: HttpMethod,
    /// Header pairs to send. Order is preserved; duplicates are allowed.
    pub headers: Vec<(String, String)>,
    /// The raw request body (already serialized to the upstream wire format;
    /// ignored for `Get`).
    pub body: Vec<u8>,
    /// Whether to consume the response as a stream. When `true`, the resulting
    /// [`UpstreamResponse::body`] is a [`ResponseBody::Stream`].
    pub stream: bool,
}

/// The body of an [`UpstreamResponse`]: either fully buffered or streamed.
pub enum ResponseBody {
    /// The complete response body, buffered in memory.
    Full(Vec<u8>),
    /// A streamed response body, yielding raw byte chunks as they arrive.
    Stream(ByteStream),
}

impl std::fmt::Debug for ResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseBody::Full(b) => f.debug_tuple("Full").field(&b.len()).finish(),
            ResponseBody::Stream(_) => f.write_str("Stream(..)"),
        }
    }
}

impl ResponseBody {
    /// Returns the buffered bytes if this is a [`ResponseBody::Full`].
    pub fn as_full(&self) -> Option<&[u8]> {
        match self {
            ResponseBody::Full(b) => Some(b),
            ResponseBody::Stream(_) => None,
        }
    }

    /// Returns `true` if this is a streamed body.
    pub fn is_stream(&self) -> bool {
        matches!(self, ResponseBody::Stream(_))
    }
}

/// A response from an upstream provider.
#[derive(Debug)]
pub struct UpstreamResponse {
    /// The HTTP status code returned by the upstream.
    pub status: u16,
    /// Response header pairs, in arrival order.
    pub headers: Vec<(String, String)>,
    /// The response body (buffered or streamed).
    pub body: ResponseBody,
}

impl UpstreamResponse {
    /// Looks up the first header value matching `name` (ASCII case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The contract for performing an upstream LLM request.
///
/// Implementors own whatever transport state they need (e.g. a connection pool)
/// and must be cheaply shareable across tasks (`Send + Sync`).
#[async_trait::async_trait]
pub trait UpstreamClient: Send + Sync {
    /// Sends `req` upstream and returns the response.
    ///
    /// A non-2xx HTTP status is **not** an `Err`: it is reported via
    /// [`UpstreamResponse::status`] so the caller can decide whether to fail
    /// over (see [`is_retryable`] / [`is_model_not_found`]). `Err` is reserved
    /// for transport-level failures (DNS, connect, TLS, the body stream
    /// breaking mid-flight).
    async fn send(&self, req: UpstreamRequest) -> yb_core::Result<UpstreamResponse>;
}
