//! A canned-response [`UpstreamClient`] for tests and smoke checks.
//!
//! [`MockClient`] never touches the network. It returns a pre-configured
//! [`UpstreamResponse`] and records every [`UpstreamRequest`] it receives so
//! tests can assert on what would have been sent upstream.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures::stream;

use crate::{ResponseBody, UpstreamClient, UpstreamRequest, UpstreamResponse};

/// The canned body a [`MockClient`] replays.
#[derive(Debug, Clone)]
pub enum MockBody {
    /// A single buffered body returned as [`ResponseBody::Full`].
    Full(Vec<u8>),
    /// An ordered list of byte chunks replayed as a [`ResponseBody::Stream`].
    /// Typically each chunk is one or more SSE events (`"data: {..}\n\n"`).
    Stream(Vec<Bytes>),
}

/// A non-networked [`UpstreamClient`] returning a fixed response.
///
/// The response is the same for every call; the list of received requests is
/// captured in [`MockClient::requests`] for assertions.
#[derive(Debug, Clone)]
pub struct MockClient {
    status: u16,
    headers: Vec<(String, String)>,
    body: MockBody,
    requests: Arc<Mutex<Vec<UpstreamRequest>>>,
}

impl MockClient {
    /// A client returning a buffered `200 OK` response with `body`.
    pub fn full(body: impl Into<Vec<u8>>) -> Self {
        Self::new(200, MockBody::Full(body.into()))
    }

    /// A client returning a buffered `200 OK` JSON response.
    ///
    /// Sets `content-type: application/json`. Equivalent to [`MockClient::full`]
    /// with that header added.
    pub fn json(body: impl Into<Vec<u8>>) -> Self {
        Self::new(200, MockBody::Full(body.into()))
            .with_header("content-type", "application/json")
    }

    /// A client returning a streamed `200 OK` SSE response.
    ///
    /// Each entry in `events` becomes one stream chunk; the `text/event-stream`
    /// content type is set automatically.
    pub fn sse<I, S>(events: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<Bytes>,
    {
        let chunks = events.into_iter().map(Into::into).collect();
        Self::new(200, MockBody::Stream(chunks))
            .with_header("content-type", "text/event-stream")
    }

    /// The fully general constructor: a `status` and a [`MockBody`].
    pub fn new(status: u16, body: MockBody) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body,
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Overrides the response status (builder style).
    pub fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    /// Adds a response header (builder style).
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Returns a snapshot of every request this client has received, oldest
    /// first.
    pub fn requests(&self) -> Vec<UpstreamRequest> {
        self.requests.lock().expect("mock mutex poisoned").clone()
    }

    /// Returns the most recently received request, if any.
    pub fn last_request(&self) -> Option<UpstreamRequest> {
        self.requests
            .lock()
            .expect("mock mutex poisoned")
            .last()
            .cloned()
    }

    /// Number of requests received so far.
    pub fn request_count(&self) -> usize {
        self.requests.lock().expect("mock mutex poisoned").len()
    }

    /// Materializes the configured body into a fresh [`ResponseBody`].
    fn make_body(&self) -> ResponseBody {
        match &self.body {
            MockBody::Full(bytes) => ResponseBody::Full(bytes.clone()),
            MockBody::Stream(chunks) => {
                let owned: Vec<yb_core::Result<Bytes>> =
                    chunks.iter().cloned().map(Ok).collect();
                ResponseBody::Stream(Box::pin(stream::iter(owned)))
            }
        }
    }
}

#[async_trait::async_trait]
impl UpstreamClient for MockClient {
    async fn send(&self, req: UpstreamRequest) -> yb_core::Result<UpstreamResponse> {
        self.requests
            .lock()
            .expect("mock mutex poisoned")
            .push(req);
        Ok(UpstreamResponse {
            status: self.status,
            headers: self.headers.clone(),
            body: self.make_body(),
        })
    }
}
