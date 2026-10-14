//! HTTP transport bound to one configured origin and one expected SPIFFE ID.
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, Uri};
use http_body_util::Full;
use hyper::body::{Body, Incoming};
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper::service::{service_fn, Service};
use hyper_util::client::legacy::{
    connect::{Connected, Connection},
    Client,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpStream;

use crate::config::{PeerConfig, TransportConfig};
use crate::error::{Error, Result, TimeoutPhase};
use crate::material::WorkloadMaterial;
use crate::{AuthenticatedStream, IdentitySource, MtlsAcceptor, MtlsConnector, SpiffeId};

pub type HttpBody = Full<Bytes>;
type Pool = Client<FleetConnector, HttpBody>;
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Cloneable HTTP client for one named peer. Pools are replaced on credential
/// rotation. It never follows redirects or consults proxy environment variables.
/// Retain and clone a client to reuse its pool; constructing another client for
/// the same peer creates an independent pool. Keep its identity runtime alive.
#[derive(Clone)]
pub struct HttpClient(Arc<HttpClientInner>);

struct HttpClientInner {
    identity: IdentitySource,
    origin: Uri,
    peer: SpiffeId,
    transport: TransportConfig,
    pool: Mutex<Option<(Arc<WorkloadMaterial>, Pool)>>,
}

impl HttpClient {
    pub fn new(
        identity: IdentitySource,
        peer: PeerConfig,
        transport: TransportConfig,
    ) -> Result<Self> {
        peer.validate()?;
        transport.validate()?;
        identity.current()?;
        let origin = peer
            .url
            .parse()
            .map_err(|e| Error::Config(format!("invalid peer URL: {e}")))?;
        let peer = peer
            .spiffe_id
            .as_str()
            .try_into()
            .map_err(|e| Error::Config(format!("invalid peer SPIFFE ID: {e}")))?;
        Ok(Self(Arc::new(HttpClientInner {
            identity,
            origin,
            peer,
            transport,
            pool: Mutex::new(None),
        })))
    }

    pub fn expected_peer(&self) -> &SpiffeId {
        &self.0.peer
    }

    /// Accept a relative path or this client's exact configured HTTPS origin.
    /// The request timeout covers connection establishment through response
    /// headers; the authenticated connection lifetime also bounds body streaming.
    /// Applications must enforce response-body size and total-time limits.
    /// Non-idempotent requests are never automatically retried by this wrapper.
    pub async fn request(&self, mut request: Request<HttpBody>) -> Result<Response<Incoming>> {
        if request.uri().scheme().is_some() || request.uri().authority().is_some() {
            check_origin(request.uri(), &self.0.origin)?;
        } else {
            let path = request
                .uri()
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/");
            *request.uri_mut() = Uri::builder()
                .scheme("https")
                .authority(self.0.origin.authority().expect("validated origin").clone())
                .path_and_query(path)
                .build()
                .map_err(|e| Error::Config(e.to_string()))?;
        }
        // Bind HTTP/1 Host to the same origin as the TLS destination.
        request.headers_mut().insert(
            http::header::HOST,
            self.0
                .origin
                .authority()
                .expect("validated origin")
                .as_str()
                .parse()
                .map_err(|e| Error::Config(format!("invalid authority: {e}")))?,
        );
        let material = self.0.identity.current()?;
        let pool = {
            let mut cached = self
                .0
                .pool
                .lock()
                .map_err(|_| Error::Transport("HTTP pool lock poisoned".into()))?;
            if cached
                .as_ref()
                .is_none_or(|(previous, _)| !Arc::ptr_eq(previous, &material))
            {
                let connector = FleetConnector {
                    connector: self
                        .0
                        .identity
                        .connector()
                        .with_transport(self.0.transport.clone())?,
                    origin: self.0.origin.clone(),
                    peer: self.0.peer.clone(),
                };
                let pool = Client::builder(TokioExecutor::new())
                    .pool_idle_timeout(Duration::from_secs(30))
                    .pool_max_idle_per_host(8)
                    .retry_canceled_requests(false)
                    .build(connector);
                *cached = Some((material, pool));
            }
            cached.as_ref().expect("pool initialized").1.clone()
        };
        tokio::time::timeout(
            Duration::from_secs(self.0.transport.request_timeout_secs),
            pool.request(request),
        )
        .await
        .map_err(|_| Error::Timeout(TimeoutPhase::ResponseHeaders))?
        .map_err(Error::HttpRequest)
    }

    pub async fn get(&self, path: &str) -> Result<Response<Incoming>> {
        let request = Request::get(path)
            .body(Full::new(Bytes::new()))
            .map_err(|e| Error::Config(e.to_string()))?;
        self.request(request).await
    }
}

impl MtlsAcceptor {
    /// Serve one HTTP/1 or HTTP/2 connection and attach AuthenticatedPeer to every
    /// request's extensions. The service must authorize each request itself.
    /// Axum/Tower services can use hyper_util::service::TowerToHyperService.
    pub async fn serve_http_connection<S, B>(&self, stream: TcpStream, service: S) -> Result<()>
    where
        S: Service<Request<Incoming>, Response = Response<B>> + Send + Sync + 'static,
        S::Future: Send,
        S::Error: Into<BoxError> + 'static,
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<BoxError> + 'static,
    {
        self.serve_http_connection_with_shutdown(stream, service, std::future::pending())
            .await
    }

    /// Serve HTTP with a caller-supplied graceful-shutdown signal. When `shutdown`
    /// completes, close idle connections and let accepted requests and response
    /// bodies finish using Hyper's HTTP/1 keep-alive shutdown or HTTP/2 GOAWAY.
    /// A signal received before the TLS handshake completes simply closes it.
    ///
    /// Keep polling this future after signaling shutdown. The application owns
    /// the listener and overall drain deadline: stop accepting, signal every
    /// connection, await them with a bound, and only then shut down the identity
    /// runtime. Dropping this future aborts the connection, not a graceful drain.
    /// Authentication expiry, maximum connection age, and trust invalidation
    /// remain hard limits; draining never extends them.
    pub async fn serve_http_connection_with_shutdown<S, B, F>(
        &self,
        stream: TcpStream,
        service: S,
        shutdown: F,
    ) -> Result<()>
    where
        S: Service<Request<Incoming>, Response = Response<B>> + Send + Sync + 'static,
        S::Future: Send,
        S::Error: Into<BoxError> + 'static,
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<BoxError> + 'static,
        F: Future<Output = ()> + Send,
    {
        tokio::pin!(shutdown);
        let (stream, peer) = tokio::select! {
            biased;
            () = &mut shutdown => return Ok(()),
            accepted = self.accept(stream) => accepted?,
        };
        let (identity, material, deadline, expires_at) = stream.authentication();
        let service = Arc::new(service);
        let service = service_fn(move |mut request: Request<Incoming>| {
            request.extensions_mut().insert(peer.clone());
            let service = service.clone();
            let identity = identity.clone();
            let material = material.clone();
            async move {
                let current = identity.current()?;
                if tokio::time::Instant::now() >= deadline
                    || crate::material::unix_now() >= expires_at
                    || current.bundles != material.bundles
                {
                    return Err::<Response<B>, Error>(if current.bundles != material.bundles {
                        Error::TrustChanged
                    } else {
                        Error::ConnectionExpired
                    });
                }
                service
                    .call(request)
                    .await
                    .map_err(|e| Error::HttpService(e.into()))
            }
        });
        let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
        let connection = builder.serve_connection(TokioIo::new(stream), service);
        tokio::pin!(connection);
        // Bound even a handler that is pending without polling its transport.
        // The stream and per-request checks still enforce trust and wall-clock validity.
        tokio::time::timeout_at(deadline, async {
            tokio::select! {
                biased;
                () = &mut shutdown => {
                    connection.as_mut().graceful_shutdown();
                    connection.await
                }
                result = &mut connection => result,
            }
        })
        .await
        .map_err(|_| Error::ConnectionExpired)?
        .map_err(Error::HttpConnection)
    }
}

#[derive(Clone)]
struct FleetConnector {
    connector: MtlsConnector,
    origin: Uri,
    peer: SpiffeId,
}

impl tower_service::Service<Uri> for FleetConnector {
    type Response = HttpIo;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<HttpIo>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, uri: Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            check_origin(&uri, &this.origin)?;
            let host = uri
                .host()
                .expect("validated origin")
                .trim_start_matches('[')
                .trim_end_matches(']');
            let port = uri.port_u16().unwrap_or(443);
            let (stream, _) = this
                .connector
                .connect_with_server_name((host, port), &this.peer, host)
                .await?;
            let h2 = stream.get_ref().get_ref().1.alpn_protocol() == Some(b"h2");
            Ok(HttpIo {
                inner: TokioIo::new(stream),
                h2,
            })
        })
    }
}

fn check_origin(uri: &Uri, origin: &Uri) -> Result<()> {
    if uri.scheme_str() != Some("https") || uri.authority() != origin.authority() {
        return Err(Error::Config(
            "request origin differs from the authenticated peer's configured origin".into(),
        ));
    }
    Ok(())
}

struct HttpIo {
    inner: TokioIo<AuthenticatedStream<tokio_rustls::client::TlsStream<TcpStream>>>,
    h2: bool,
}

impl Connection for HttpIo {
    fn connected(&self) -> Connected {
        if self.h2 {
            Connected::new().negotiated_h2()
        } else {
            Connected::new()
        }
    }
}
impl Read for HttpIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}
impl Write for HttpIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
