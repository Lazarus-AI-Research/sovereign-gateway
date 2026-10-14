//! Read-only VKG capabilities probe; application types/limits stay in this example.
//! Run: cargo run --example service_client -- /path/to/scribe-identity.toml
//! The config must name peer `vkg`; VKG must authorize this caller for discovery.
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use greater_spire::{Config, HttpClient, IdentityRuntime, IdentityStatus, RefreshStatus};
use http_body_util::BodyExt;
use hyper::body::Body;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
const MAX_BODY_BYTES: usize = 64 * 1024;
const BODY_TIMEOUT: Duration = Duration::from_secs(5);

// A small application-owned view of VKG's v1 capabilities response, not a
// greater-spire protocol type. Unknown additive fields are intentionally ignored.
#[derive(Debug, Deserialize, Serialize)]
struct Capabilities {
    service_id: String,
    api_version: String,
    schema_version: String,
    capabilities: CapabilityFlags,
}

#[derive(Debug, Deserialize, Serialize)]
struct CapabilityFlags {
    read_acl_v1: bool,
}

#[derive(Debug, thiserror::Error)]
enum BodyError {
    #[error("response body exceeded its total time budget")]
    Timeout,
    #[error("response body exceeded the {limit} byte limit")]
    TooLarge { limit: usize },
    #[error("response body was interrupted: {0}")]
    Interrupted(#[source] BoxError),
}

/// Enforce limits while reading, not after an unbounded collect. Content-Length
/// is not trusted. The timer covers the entire body, not each individual frame.
async fn bounded_body<B>(body: B, limit: usize, timeout: Duration) -> Result<Bytes, BodyError>
where
    B: Body<Data = Bytes>,
    B::Error: Into<BoxError>,
{
    tokio::pin!(body);
    tokio::time::timeout(timeout, async {
        let mut bytes = BytesMut::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|error| BodyError::Interrupted(error.into()))?;
            if let Ok(data) = frame.into_data() {
                if data.len() > limit.saturating_sub(bytes.len()) {
                    return Err(BodyError::TooLarge { limit });
                }
                bytes.extend_from_slice(&data);
            }
        }
        Ok(bytes.freeze())
    })
    .await
    .map_err(|_| BodyError::Timeout)?
}

async fn inspect(client: &HttpClient) -> Result<Capabilities, BoxError> {
    // This timeout ends at response headers. BODY_TIMEOUT below is separate.
    let response = client.get("/v1/capabilities").await?;
    let status = response.status();
    let content_type_is_json = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        });
    // Error responses are bounded too, and their bodies are not logged as public
    // diagnostics. Failure here is not evidence that a mutation was uncommitted.
    let body = bounded_body(response.into_body(), MAX_BODY_BYTES, BODY_TIMEOUT).await?;
    if !status.is_success() {
        return Err(format!("VKG returned HTTP {status}").into());
    }
    if !content_type_is_json {
        return Err("VKG returned a non-JSON capabilities response".into());
    }
    let capabilities: Capabilities = serde_json::from_slice(&body)?;
    if capabilities.api_version != "v1" {
        return Err(format!("unsupported VKG API version {}", capabilities.api_version).into());
    }
    Ok(capabilities)
}

async fn observe(mut changes: watch::Receiver<IdentityStatus>, stop: CancellationToken) {
    loop {
        let status = changes.borrow_and_update().clone();
        tracing::info!(
            usable = status.usable,
            valid_until = status.valid_until_unix,
            "identity status"
        );
        if let RefreshStatus::Error {
            error, since_unix, ..
        } = status.refresh
        {
            tracing::warn!(%error, since_unix, "identity refresh unhealthy");
        }
        tokio::select! {
            () = stop.cancelled() => break,
            changed = changes.changed() => {
                if changed.is_err() { break; }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let path = std::env::args_os()
        .nth(1)
        .ok_or("usage: service_client <identity.toml>")?;
    let mut runtime = IdentityRuntime::start(Config::from_file(path)?).await?;
    // Retain the client alongside the runtime so repeated operations reuse its pool.
    let client = match runtime.http_client("vkg") {
        Ok(client) => client,
        Err(error) => {
            runtime.shutdown().await;
            return Err(error.into());
        }
    };
    let stop_observer = CancellationToken::new();
    let observer = tokio::spawn(observe(runtime.watch(), stop_observer.clone()));
    // Retain the runtime until the complete operation (including body reading)
    // finishes. Capture errors so shutdown runs on both the success and error paths.
    let result = inspect(&client).await;
    stop_observer.cancel();
    let observed = observer.await;
    runtime.shutdown().await;
    observed?;
    let capabilities = result?;
    println!("{}", serde_json::to_string_pretty(&capabilities)?);
    // In a real application, check required capabilities before each associated
    // operation. These flags describe protocol support, not caller permissions.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{Full, StreamBody};
    use hyper::body::Frame;
    use std::convert::Infallible;
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;

    #[tokio::test]
    async fn bounded_collection_accepts_exact_limit_and_rejects_excess() {
        assert_eq!(
            bounded_body(Full::new(Bytes::from_static(b"abcd")), 4, BODY_TIMEOUT)
                .await
                .unwrap(),
            b"abcd"[..]
        );
        assert!(matches!(
            bounded_body(Full::new(Bytes::from_static(b"abcde")), 4, BODY_TIMEOUT).await,
            Err(BodyError::TooLarge { limit: 4 })
        ));
        let frames = tokio_stream::iter([
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"abc"))),
            Ok(Frame::data(Bytes::from_static(b"de"))),
        ]);
        assert!(matches!(
            bounded_body(StreamBody::new(frames), 4, BODY_TIMEOUT).await,
            Err(BodyError::TooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn body_timeout_is_total_even_while_frames_keep_arriving() {
        let (sender, receiver) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(1);
        let task = tokio::spawn(async move {
            while sender
                .send(Ok(Frame::data(Bytes::from_static(b"a"))))
                .await
                .is_ok()
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        assert!(matches!(
            bounded_body(
                StreamBody::new(ReceiverStream::new(receiver)),
                1_000_000,
                Duration::from_millis(50)
            )
            .await,
            Err(BodyError::Timeout)
        ));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn partial_response_is_not_returned_after_a_body_error() {
        let frames = tokio_stream::iter([
            Ok(Frame::data(Bytes::from_static(b"partial"))),
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated",
            )),
        ]);
        let error = bounded_body(StreamBody::new(frames), 100, BODY_TIMEOUT)
            .await
            .unwrap_err();
        let BodyError::Interrupted(source) = error else {
            panic!("wrong error");
        };
        assert_eq!(
            source.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn typed_contract_rejects_missing_required_fields_and_accepts_additions() {
        let valid = br#"{"service_id":"vkg","api_version":"v1","schema_version":"example", "capabilities":{"read_acl_v1":true,"future":true},"future":{}}"#;
        let parsed: Capabilities = serde_json::from_slice(valid).unwrap();
        assert!(parsed.capabilities.read_acl_v1);
        assert!(serde_json::from_slice::<Capabilities>(br#"{"service_id":"vkg"}"#).is_err());
        let round_trip: Capabilities =
            serde_json::from_slice(&serde_json::to_vec(&parsed).unwrap()).unwrap();
        assert_eq!(round_trip.service_id, parsed.service_id);
    }

    #[cfg(all(feature = "static-ca", unix))]
    #[tokio::test]
    async fn typed_probe_runs_over_real_mtls_before_runtime_shutdown() {
        use greater_spire::{static_ca::StaticCa, AuthenticatedPeer, SpiffeId};
        use hyper::{body::Incoming, service::service_fn, Request, Response};
        use tokio::net::TcpListener;

        let ca = StaticCa::generate("fleet.test".try_into().unwrap(), Duration::from_secs(86400))
            .unwrap();
        let caller_id: SpiffeId = "spiffe://fleet.test/service/scribe".try_into().unwrap();
        let receiver_id: SpiffeId = "spiffe://fleet.test/service/vkg".try_into().unwrap();
        let temp = tempfile::tempdir().unwrap();
        ca.issue_svid(&caller_id, Duration::from_secs(3600))
            .unwrap()
            .publish(temp.path())
            .unwrap();
        let server = ca
            .issue_svid(&receiver_id, Duration::from_secs(3600))
            .unwrap()
            .identity_source()
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let config = Config::from_toml(
            &format!(
                r#"
version = 1
[identity]
spiffe_id = "{caller_id}"
[identity.source]
kind = "files"
directory = {:?}
[peers.vkg]
url = "https://{address}"
spiffe_id = "{receiver_id}"
"#,
                temp.path().join("current").to_str().unwrap()
            ),
            "/",
        )
        .unwrap();
        let mut runtime = IdentityRuntime::start(config).await.unwrap();
        let drain = CancellationToken::new();
        let stop = drain.clone();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            server.acceptor().serve_http_connection_with_shutdown(tcp, service_fn(move |request: Request<Incoming>| {
                assert_eq!(request.uri().path(), "/v1/capabilities");
                assert_eq!(request.extensions().get::<AuthenticatedPeer>().unwrap().spiffe_id(), &caller_id);
                async {
                    Ok::<_, Infallible>(Response::builder().header(http::header::CONTENT_TYPE, "application/json")
                        .body(Full::new(Bytes::from_static(br#"{"service_id":"vkg","api_version":"v1","schema_version":"example","capabilities":{"read_acl_v1":true}}"#))).unwrap())
                }
            }), stop.cancelled()).await
        });
        let client = runtime.http_client("vkg").unwrap();
        let result = inspect(&client).await.unwrap();
        assert!(result.capabilities.read_acl_v1);
        assert!(runtime.status().await.usable);
        drain.cancel();
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        runtime.shutdown().await;
        assert!(!runtime.status().await.usable);
    }
}
