#![cfg(all(feature = "http", feature = "static-ca"))]

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use greater_spire::static_ca::StaticCa;
use greater_spire::{AuthenticatedPeer, IdentitySource, MtlsAcceptor, SpiffeId, TransportConfig};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::{service_fn, Service};
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

type TestBody = http_body_util::combinators::UnsyncBoxBody<Bytes, Infallible>;
type ResponseFuture = Pin<Box<dyn Future<Output = hyper::Result<Response<Incoming>>> + Send>>;

fn id(name: &str) -> SpiffeId {
    format!("spiffe://fleet.test/service/{name}")
        .as_str()
        .try_into()
        .unwrap()
}

fn ca() -> StaticCa {
    StaticCa::generate("fleet.test".try_into().unwrap(), Duration::from_secs(86400)).unwrap()
}

fn source(ca: &StaticCa, name: &str, lifetime: u64) -> IdentitySource {
    ca.issue_svid(&id(name), Duration::from_secs(lifetime))
        .unwrap()
        .identity_source()
        .unwrap()
}

enum Sender {
    Http1(hyper::client::conn::http1::SendRequest<Full<Bytes>>),
    Http2(hyper::client::conn::http2::SendRequest<Full<Bytes>>),
}

impl Sender {
    fn send(&mut self) -> ResponseFuture {
        let request = Request::get("https://fleet.test/")
            .body(Full::new(Bytes::new()))
            .unwrap();
        match self {
            Self::Http1(sender) => Box::pin(sender.send_request(request)),
            Self::Http2(sender) => Box::pin(sender.send_request(request)),
        }
    }
}

struct Connection {
    sender: Sender,
    shutdown: CancellationToken,
    draining: oneshot::Receiver<()>,
    server: JoinHandle<greater_spire::Result<()>>,
    client: JoinHandle<hyper::Result<()>>,
}

async fn connect<S>(
    http2: bool,
    acceptor: MtlsAcceptor,
    client: IdentitySource,
    service: S,
) -> Connection
where
    S: Service<Request<Incoming>, Response = Response<TestBody>, Error = Infallible>
        + Send
        + Sync
        + 'static,
    S::Future: Send,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    let (started, draining) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        acceptor
            .serve_http_connection_with_shutdown(tcp, service, async move {
                signal.cancelled().await;
                let _ = started.send(());
            })
            .await
    });
    let alpn: &[u8] = if http2 { b"h2" } else { b"http/1.1" };
    let (tls, _) = client
        .connector()
        .with_alpn(&[alpn])
        .connect(address, &id("vkg"))
        .await
        .unwrap();
    let (sender, client) = if http2 {
        let (sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .unwrap();
        (Sender::Http2(sender), tokio::spawn(connection))
    } else {
        let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        (Sender::Http1(sender), tokio::spawn(connection))
    };
    Connection {
        sender,
        shutdown,
        draining,
        server,
        client,
    }
}

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("operation timed out")
}

#[tokio::test]
async fn idle_keep_alive_connections_drain_for_http1_and_http2() {
    for http2 in [false, true] {
        let ca = ca();
        let service = service_fn(|request: Request<Incoming>| async move {
            assert_eq!(
                request
                    .extensions()
                    .get::<AuthenticatedPeer>()
                    .unwrap()
                    .spiffe_id(),
                &id("nexis")
            );
            Ok::<_, Infallible>(Response::new(
                Full::new(Bytes::from_static(b"ok")).boxed_unsync(),
            ))
        });
        let mut connection = connect(
            http2,
            source(&ca, "vkg", 3600).acceptor(),
            source(&ca, "nexis", 3600),
            service,
        )
        .await;
        bounded(connection.sender.send())
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        connection.shutdown.cancel();
        bounded(connection.server).await.unwrap().unwrap();
        bounded(connection.client).await.unwrap().unwrap();
        assert!(connection.sender.send().await.is_err());
    }
}

#[tokio::test]
async fn accepted_requests_finish_and_http2_goaway_stops_new_streams() {
    for http2 in [false, true] {
        let ca = ca();
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let service = service_fn({
            let entered = entered.clone();
            let release = release.clone();
            let calls = calls.clone();
            move |_: Request<Incoming>| {
                let entered = entered.clone();
                let release = release.clone();
                let first = calls.fetch_add(1, Ordering::SeqCst) == 0;
                async move {
                    if first {
                        entered.notify_one();
                        release.notified().await;
                    }
                    Ok::<_, Infallible>(Response::new(
                        Full::new(Bytes::from_static(b"finished")).boxed_unsync(),
                    ))
                }
            }
        });
        let mut connection = connect(
            http2,
            source(&ca, "vkg", 3600).acceptor(),
            source(&ca, "nexis", 3600),
            service,
        )
        .await;
        let response = tokio::spawn(connection.sender.send());
        bounded(entered.notified()).await;
        connection.shutdown.cancel();
        bounded(connection.draining).await.unwrap();
        assert!(
            !connection.server.is_finished(),
            "drain aborted an accepted request"
        );
        if http2 {
            // Drive the sender to observe GOAWAY while the old stream is live.
            // HTTP/2's graceful GOAWAY exchange permits in-transit streams, so
            // any requests racing that exchange finish immediately in this handler.
            bounded(async {
                while let Ok(response) = connection.sender.send().await {
                    response.into_body().collect().await.unwrap();
                }
            })
            .await;
        }
        release.notify_one();
        let response = bounded(response).await.unwrap().unwrap();
        assert_eq!(
            bounded(response.into_body().collect())
                .await
                .unwrap()
                .to_bytes(),
            b"finished"[..]
        );
        bounded(connection.server).await.unwrap().unwrap();
        bounded(connection.client).await.unwrap().unwrap();
        assert!(connection.sender.send().await.is_err());
    }
}

#[tokio::test]
async fn streaming_response_bodies_finish_during_drain() {
    for http2 in [false, true] {
        let ca = ca();
        let (frames, receiver) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(2);
        let receiver = Arc::new(Mutex::new(Some(receiver)));
        let service = service_fn(move |_: Request<Incoming>| {
            let body = StreamBody::new(ReceiverStream::new(
                receiver.lock().unwrap().take().unwrap(),
            ));
            async move { Ok::<_, Infallible>(Response::new(body.boxed_unsync())) }
        });
        let mut connection = connect(
            http2,
            source(&ca, "vkg", 3600).acceptor(),
            source(&ca, "nexis", 3600),
            service,
        )
        .await;
        frames
            .send(Ok(Frame::data(Bytes::from_static(b"first "))))
            .await
            .unwrap();
        let mut body = bounded(connection.sender.send()).await.unwrap().into_body();
        assert_eq!(
            bounded(body.frame())
                .await
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap(),
            b"first "[..]
        );
        connection.shutdown.cancel();
        bounded(connection.draining).await.unwrap();
        assert!(!connection.server.is_finished());
        frames
            .send(Ok(Frame::data(Bytes::from_static(b"last"))))
            .await
            .unwrap();
        drop(frames);
        assert_eq!(
            bounded(body.collect()).await.unwrap().to_bytes(),
            b"last"[..]
        );
        bounded(connection.server).await.unwrap().unwrap();
        bounded(connection.client).await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn expiry_and_maximum_connection_age_still_bound_draining() {
    for http2 in [false, true] {
        for expire_certificate in [false, true] {
            let ca = ca();
            let entered = Arc::new(Notify::new());
            let service = service_fn({
                let entered = entered.clone();
                move |_: Request<Incoming>| {
                    entered.notify_one();
                    std::future::pending::<Result<Response<TestBody>, Infallible>>()
                }
            });
            let lifetime = if expire_certificate { 2 } else { 3600 };
            let transport = TransportConfig {
                max_connection_age_secs: if expire_certificate { 300 } else { 1 },
                ..Default::default()
            };
            let mut connection = connect(
                http2,
                source(&ca, "vkg", lifetime)
                    .acceptor()
                    .with_transport(transport)
                    .unwrap(),
                source(&ca, "nexis", 3600),
                service,
            )
            .await;
            let response = tokio::spawn(connection.sender.send());
            bounded(entered.notified()).await;
            connection.shutdown.cancel();
            bounded(connection.draining).await.unwrap();
            assert!(bounded(connection.server).await.unwrap().is_err());
            assert!(bounded(response).await.unwrap().is_err());
            let _ = bounded(connection.client).await.unwrap();
        }
    }
}

#[tokio::test]
async fn shutdown_interrupts_an_unfinished_tls_handshake() {
    let ca = ca();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (tcp, _) = listener.accept().await.unwrap();
    let acceptor = source(&ca, "vkg", 3600).acceptor();
    let shutdown = CancellationToken::new();
    let service = service_fn(|_: Request<Incoming>| async {
        panic!("unauthenticated connection reached a handler");
        #[allow(unreachable_code)]
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
    });
    let signal = shutdown.clone();
    let task = tokio::spawn(async move {
        acceptor
            .serve_http_connection_with_shutdown(tcp, service, signal.cancelled())
            .await
    });
    tokio::task::yield_now().await;
    shutdown.cancel();
    bounded(task).await.unwrap().unwrap();
    drop(client);
}

#[cfg(unix)]
#[tokio::test]
async fn trust_invalidation_still_rejects_responses_during_drain() {
    for http2 in [false, true] {
        let ca = ca();
        let temp = tempfile::tempdir().unwrap();
        let mut issued = ca
            .issue_svid(&id("vkg"), Duration::from_secs(3600))
            .unwrap();
        issued.publish(temp.path()).unwrap();
        let config = greater_spire::Config::from_toml(
            &format!(
                r#"
version = 1
[identity]
spiffe_id = "spiffe://fleet.test/service/vkg"
[identity.source]
kind = "files"
directory = {:?}
poll_interval_secs = 3600
"#,
                temp.path().join("current").to_str().unwrap()
            ),
            "/",
        )
        .unwrap();
        let mut runtime = greater_spire::IdentityRuntime::start(config).await.unwrap();
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let service = service_fn({
            let entered = entered.clone();
            let release = release.clone();
            move |_: Request<Incoming>| {
                let entered = entered.clone();
                let release = release.clone();
                async move {
                    entered.notify_one();
                    release.notified().await;
                    Ok::<_, Infallible>(Response::new(
                        Full::new(Bytes::from_static(b"must not arrive")).boxed_unsync(),
                    ))
                }
            }
        });
        let mut connection = connect(
            http2,
            runtime.acceptor(),
            source(&ca, "nexis", 3600),
            service,
        )
        .await;
        let response = tokio::spawn(connection.sender.send());
        bounded(entered.notified()).await;
        connection.shutdown.cancel();
        bounded(connection.draining).await.unwrap();
        issued.bundle_pem.push_str(self::ca().certificate_pem());
        issued.publish(temp.path()).unwrap();
        runtime.reload().await.unwrap();
        release.notify_one();
        assert!(bounded(connection.server).await.unwrap().is_err());
        assert!(bounded(response).await.unwrap().is_err());
        let _ = bounded(connection.client).await.unwrap();
        runtime.shutdown().await;
    }
}
