//! A `reqwest`-backed [`UpstreamClient`].
//!
//! One [`HttpClient`] serves every wire format: the vendors differ only in URL and auth headers, which the caller bakes into the
//! [`UpstreamRequest`] (see [`crate::route`]). All requests are `POST`s.

use futures::StreamExt;
use yb_core::Error;

use crate::{ResponseBody, UpstreamClient, UpstreamRequest, UpstreamResponse};

/// A shared HTTP client over a pooled `reqwest::Client`.
///
/// Cloning is cheap (the inner client is reference-counted) and safe to share
/// across tasks.
#[derive(Debug, Clone)]
pub struct HttpClient {
    inner: reqwest::Client,
}

impl HttpClient {
    /// Builds a client with sensible defaults: connection pooling on, a 10s
    /// connect timeout (so a dead upstream fails over quickly instead of
    /// hanging on the OS connect timeout), and no global timeout — streaming
    /// responses are long-lived (stall detection is the gateway's job).
    ///
    /// Panics only if the platform TLS backend cannot be initialized, which is
    /// not a recoverable condition.
    pub fn new() -> Self {
        let inner = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build reqwest client");
        Self { inner }
    }

    /// Wraps an externally-configured `reqwest::Client` (e.g. with custom
    /// timeouts or proxy settings).
    pub fn with_client(inner: reqwest::Client) -> Self {
        Self { inner }
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Maps a transport-level `reqwest` error onto a [`yb_core::Error`].
///
/// These are connect/DNS/TLS failures or a body stream breaking mid-flight —
/// not HTTP error statuses (those are surfaced via the response). We model them
/// as an [`Error::Upstream`] with a `502 Bad Gateway`, which is what the gateway
/// reports to the client when no candidate can be reached.
fn map_transport_err(e: reqwest::Error) -> Error {
    Error::Upstream {
        provider: "upstream".to_string(),
        status: 502,
        message: e.to_string(),
    }
}

/// Collects a `reqwest::HeaderMap` into ordered `(name, value)` pairs, lossily
/// decoding any non-UTF-8 header values.
fn collect_headers(map: &reqwest::header::HeaderMap) -> Vec<(String, String)> {
    map.iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                v.to_str().map(str::to_string).unwrap_or_else(|_| {
                    String::from_utf8_lossy(v.as_bytes()).into_owned()
                }),
            )
        })
        .collect()
}

#[async_trait::async_trait]
impl UpstreamClient for HttpClient {
    async fn send(&self, req: UpstreamRequest) -> yb_core::Result<UpstreamResponse> {
        let mut builder = match req.method {
            crate::HttpMethod::Post => self.inner.post(&req.url).body(req.body),
            crate::HttpMethod::Get => self.inner.get(&req.url),
        };
        for (name, value) in &req.headers {
            builder = builder.header(name, value);
        }

        let resp = builder.send().await.map_err(map_transport_err)?;

        let status = resp.status().as_u16();
        let headers = collect_headers(resp.headers());

        let body = if req.stream {
            // Lazily map each chunk's transport error into our domain error.
            let stream = resp
                .bytes_stream()
                .map(|chunk| chunk.map_err(map_transport_err));
            ResponseBody::Stream(Box::pin(stream))
        } else {
            let bytes = resp.bytes().await.map_err(map_transport_err)?;
            ResponseBody::Full(bytes.to_vec())
        };

        Ok(UpstreamResponse {
            status,
            headers,
            body,
        })
    }
}
