#![cfg(all(feature = "http", feature = "static-ca"))]

use std::convert::Infallible;
use std::error::Error as _;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use bytes::Bytes;
use greater_spire::static_ca::StaticCa;
use greater_spire::{
    Error, HttpClient, IdentitySource, PeerConfig, PeerIdentityError, SpiffeId, TimeoutPhase,
    TransportConfig,
};
use http_body_util::Full;
use hyper::{body::Incoming, service::service_fn, Request, Response};
use tokio::net::TcpListener;

fn id(name: &str) -> SpiffeId {
    format!("spiffe://fleet.test/service/{name}")
        .as_str()
        .try_into()
        .unwrap()
}
fn ca() -> StaticCa {
    StaticCa::generate("fleet.test".try_into().unwrap(), Duration::from_secs(86400)).unwrap()
}
fn identity(ca: &StaticCa, name: &str) -> IdentitySource {
    ca.issue_svid(&id(name), Duration::from_secs(3600))
        .unwrap()
        .identity_source()
        .unwrap()
}
fn client(
    identity: IdentitySource,
    address: std::net::SocketAddr,
    expected: &str,
    transport: TransportConfig,
) -> HttpClient {
    HttpClient::new(
        identity,
        PeerConfig {
            url: format!("https://{address}"),
            spiffe_id: id(expected).to_string(),
        },
        transport,
    )
    .unwrap()
}

#[tokio::test]
async fn http_preserves_spiffe_mismatch_and_untrusted_issuer_causes() {
    for wrong_id in [false, true] {
        let ca = ca();
        let server = if wrong_id {
            identity(&ca, "vkg")
        } else {
            identity(&self::ca(), "vkg")
        };
        let caller = identity(&ca, "scribe");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let service = service_fn(move |_: Request<Incoming>| {
                count.fetch_add(1, Ordering::SeqCst);
                async { Ok::<_, Infallible>(Response::new(Full::new(Bytes::new()))) }
            });
            server.acceptor().serve_http_connection(tcp, service).await
        });
        let expected = if wrong_id { "hexis" } else { "vkg" };
        let error = client(caller, address, expected, TransportConfig::default())
            .get("/")
            .await
            .unwrap_err();
        assert!(matches!(error, Error::HttpRequest(_)));
        assert!(error.source().is_some());
        assert!(error.find_cause::<std::io::Error>().is_some());
        assert!(matches!(
            error.find_cause::<rustls::Error>(),
            Some(rustls::Error::InvalidCertificate(_))
        ));
        if wrong_id {
            assert!(
                matches!(error.find_cause::<PeerIdentityError>(), Some(PeerIdentityError::Mismatch { expected, presented })
                if expected == &id("hexis") && presented == &id("vkg"))
            );
        } else {
            assert!(error.find_cause::<PeerIdentityError>().is_none());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(task.await.unwrap().is_err());
    }
}

#[tokio::test]
async fn http_preserves_connection_refused_and_local_origin_rejection() {
    let ca = ca();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let client = client(
        identity(&ca, "scribe"),
        address,
        "vkg",
        TransportConfig::default(),
    );
    let error = client.get("/").await.unwrap_err();
    assert_eq!(
        error.find_cause::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::ConnectionRefused
    );
    assert!(error.find_cause::<rustls::Error>().is_none());
    assert!(matches!(
        client.get("https://other.invalid/").await,
        Err(Error::Config(_))
    ));
}

#[tokio::test]
async fn timeout_phase_distinguishes_handshake_from_response_headers() {
    let ca = ca();
    let caller = identity(&ca, "scribe");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let _tcp = tcp;
        std::future::pending::<()>().await;
    });
    let error = caller
        .connector()
        .with_transport(TransportConfig {
            handshake_timeout_secs: 1,
            ..Default::default()
        })
        .unwrap()
        .connect(address, &id("vkg"))
        .await
        .err()
        .unwrap();
    assert_eq!(
        error.find_cause::<TimeoutPhase>(),
        Some(&TimeoutPhase::ConnectAndHandshake)
    );
    server.abort();

    // Here the server has received the request, so timeout cannot imply that a
    // mutation did not run. The library must neither retry nor hide the stage.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let identity = identity(&ca, "vkg");
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        identity
            .acceptor()
            .serve_http_connection(
                tcp,
                service_fn(move |_: Request<Incoming>| {
                    count.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<Result<Response<Full<Bytes>>, Infallible>>()
                }),
            )
            .await
    });
    let error = client(
        caller,
        address,
        "vkg",
        TransportConfig {
            request_timeout_secs: 1,
            ..Default::default()
        },
    )
    .get("/")
    .await
    .unwrap_err();
    assert_eq!(
        error.find_cause::<TimeoutPhase>(),
        Some(&TimeoutPhase::ResponseHeaders)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    server.abort();
}

#[derive(Debug, thiserror::Error)]
#[error("example application failure")]
struct ApplicationError;

#[tokio::test]
async fn server_preserves_application_error_without_exposing_it_to_the_caller() {
    let ca = ca();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_identity = identity(&ca, "vkg");
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        // A service error terminates HTTP/1. HTTP/2 can reset just that stream;
        // its connection future need not return a request's application error.
        server_identity
            .acceptor()
            .with_alpn(&[b"http/1.1"])
            .serve_http_connection(
                tcp,
                service_fn(|_: Request<Incoming>| async {
                    Err::<Response<Full<Bytes>>, _>(ApplicationError)
                }),
            )
            .await
    });
    let error = client(
        identity(&ca, "scribe"),
        address,
        "vkg",
        TransportConfig::default(),
    )
    .get("/")
    .await
    .unwrap_err();
    assert!(error.find_cause::<ApplicationError>().is_none());
    let error = server.await.unwrap().unwrap_err();
    assert!(error.find_cause::<ApplicationError>().is_some());
}
