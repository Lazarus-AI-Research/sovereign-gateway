#![cfg(feature = "static-ca")]

use std::path::Path;
use std::time::Duration;

use greater_spire::static_ca::{IssuedIdentity, StaticCa};
use greater_spire::{Config, IdentityRuntime, IdentitySource, SpiffeId, TransportConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
fn issue(ca: &StaticCa, name: &str) -> IssuedIdentity {
    ca.issue_svid(&id(name), Duration::from_secs(3600)).unwrap()
}
fn config(directory: &Path, name: &str) -> Config {
    Config::from_toml(
        &format!(
            r#"
version = 1
[identity]
spiffe_id = "{}"
[identity.source]
kind = "files"
directory = {:?}
poll_interval_secs = 1
"#,
            id(name),
            directory.to_str().unwrap()
        ),
        "/",
    )
    .unwrap()
}

#[test]
fn issuance_import_and_pem_validation() {
    let ca = ca();
    let identity = issue(&ca, "nexis");
    let source = identity.identity_source().unwrap();
    assert_eq!(source.spiffe_id(), id("nexis"));
    let der = rustls_pemfile::certs(&mut identity.cert_chain_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    let (_, leaf) = x509_parser::parse_x509_certificate(&der).unwrap();
    assert_eq!(
        source.expires_at_unix(),
        leaf.validity().not_after.timestamp()
    );
    assert!(!format!("{identity:?} {source:?} {ca:?}").contains("PRIVATE KEY"));

    let imported = StaticCa::from_pem(
        ca.trust_domain().clone(),
        ca.certificate_pem().as_bytes(),
        ca.private_key_pem().as_bytes(),
    )
    .unwrap();
    assert_eq!(imported.certificate_pem(), ca.certificate_pem());
    issue(&imported, "hexis").identity_source().unwrap();
    assert!(ca
        .issue_svid(
            &"spiffe://other.test/service/nexis".try_into().unwrap(),
            Duration::from_secs(60)
        )
        .is_err());
    assert!(ca.issue_svid(&id("nexis"), Duration::ZERO).is_err());
    assert!(ca
        .issue_svid(&id("nexis"), Duration::from_secs(86401))
        .is_err());

    let other = issue(&ca, "vkg");
    assert!(IdentitySource::from_pem(
        &id("vkg"),
        identity.cert_chain_pem.as_bytes(),
        identity.key_pkcs8_pem.as_bytes(),
        identity.bundle_pem.as_bytes()
    )
    .is_err());
    assert!(IdentitySource::from_pem(
        &id("nexis"),
        identity.cert_chain_pem.as_bytes(),
        other.key_pkcs8_pem.as_bytes(),
        identity.bundle_pem.as_bytes()
    )
    .is_err());
    assert!(IdentitySource::from_pem(
        &id("nexis"),
        identity.cert_chain_pem.as_bytes(),
        identity.key_pkcs8_pem.as_bytes(),
        other.cert_chain_pem.as_bytes()
    )
    .is_err());
    assert!(IdentitySource::from_pem(
        &id("nexis"),
        b"garbage",
        identity.key_pkcs8_pem.as_bytes(),
        identity.bundle_pem.as_bytes()
    )
    .is_err());
    let duplicate_key = format!("{}{}", &*identity.key_pkcs8_pem, &*identity.key_pkcs8_pem);
    assert!(IdentitySource::from_pem(
        &id("nexis"),
        identity.cert_chain_pem.as_bytes(),
        duplicate_key.as_bytes(),
        identity.bundle_pem.as_bytes()
    )
    .is_err());
    let wrong_ca = self::ca();
    assert!(IdentitySource::from_pem(
        &id("nexis"),
        identity.cert_chain_pem.as_bytes(),
        identity.key_pkcs8_pem.as_bytes(),
        wrong_ca.certificate_pem().as_bytes()
    )
    .is_err());

    let temp = tempfile::tempdir().unwrap();
    ca.write_new(temp.path().join("ca")).unwrap();
    assert!(wrong_ca.write_new(temp.path().join("ca")).is_err());
    assert_eq!(
        StaticCa::load(temp.path().join("ca"))
            .unwrap()
            .certificate_pem(),
        ca.certificate_pem()
    );
}

#[test]
fn invalid_svid_profiles_and_validity_are_rejected() {
    use rcgen::{
        CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, Issuer, KeyPair,
        KeyUsagePurpose, SanType,
    };
    let ca = ca();
    let issuer = Issuer::from_ca_cert_pem(
        ca.certificate_pem(),
        KeyPair::from_pem(&ca.private_key_pem()).unwrap(),
    )
    .unwrap();
    for case in [
        "expired",
        "future",
        "multiple-uri",
        "missing-uri",
        "ca",
        "key-usage",
        "server-only",
    ] {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = DistinguishedName::new();
        params.subject_alt_names = vec![SanType::URI(id("nexis").to_string().try_into().unwrap())];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(1);
        params.not_after = now + time::Duration::hours(1);
        match case {
            "expired" => {
                params.not_before = now - time::Duration::hours(2);
                params.not_after = now - time::Duration::hours(1);
            }
            "future" => params.not_before = now + time::Duration::minutes(30),
            "multiple-uri" => params
                .subject_alt_names
                .push(SanType::URI("https://example.com".try_into().unwrap())),
            "missing-uri" => params.subject_alt_names.clear(),
            "ca" => params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained),
            "key-usage" => params.key_usages.push(KeyUsagePurpose::KeyCertSign),
            "server-only" => params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth],
            _ => unreachable!(),
        }
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &issuer).unwrap();
        assert!(
            IdentitySource::from_pem(
                &id("nexis"),
                cert.pem().as_bytes(),
                key.serialize_pem().as_bytes(),
                ca.certificate_pem().as_bytes()
            )
            .is_err(),
            "accepted {case}"
        );
    }
}

#[test]
fn config_is_strict_and_resolves_relative_paths() {
    let valid = r#"
version = 1
[identity]
spiffe_id = "spiffe://fleet.test/service/vkg"
[identity.source]
kind = "files"
directory = "identity/current"
[peers.nexis]
url = "https://nexis.example:8443"
spiffe_id = "spiffe://fleet.test/service/nexis"
"#;
    let parsed = Config::from_toml(valid, "/etc/greater-spire").unwrap();
    match parsed.identity.source {
        greater_spire::IdentityProviderConfig::Files { directory, .. } => {
            assert_eq!(directory, Path::new("/etc/greater-spire/identity/current"))
        }
        _ => panic!(),
    }
    for extra in [
        "[callers.nexis]\nmay_delegate_user = true",
        "[app]\ntenant_id = 1",
        "[server]\nport = 8443",
        "[transport]\nscopes = []",
    ] {
        assert!(Config::from_toml(&format!("{valid}\n{extra}"), "/").is_err());
    }
    for url in [
        "http://nexis:8443",
        "https://user:pass@nexis:8443",
        "https://nexis:8443/api",
        "https://nexis:8443/?x=1",
        "https://nexis:65536",
        "https://nexis:garbage",
        "https://nexis:",
        "https://nexis:0",
    ] {
        assert!(Config::from_toml(&valid.replace("https://nexis.example:8443", url), "/").is_err());
    }
    assert!(Config::from_toml(&valid.replace("version = 1", "version = 2"), "/").is_err());
    assert!(Config::from_toml(&valid.replace("kind = \"files\"", "kind = \"auto\""), "/").is_err());
    assert!(Config::load("../vkg", None).is_err());
    let embedded = r#"
version = 1
[identity]
spiffe_id = "spiffe://fleet.test/service/vkg"
[identity.source]
kind = "embedded_spire"
server_address = "localhost:8081"
bootstrap_bundle_path = "bootstrap.pem"
state_dir = "state"
join_token_file = "join-token"
"#;
    Config::from_toml(embedded, "/tmp").unwrap();
    assert!(Config::from_toml(&format!("{embedded}\ntenant_id = 1"), "/tmp").is_err());
}

#[tokio::test]
async fn tls_authenticates_both_sides_without_application_policy() {
    let ca = ca();
    let server = issue(&ca, "vkg").identity_source().unwrap();
    let client = issue(&ca, "nexis").identity_source().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let (mut tls, peer) = server.acceptor().accept(tcp).await.unwrap();
        assert_eq!(peer.spiffe_id(), &id("nexis"));
        assert_eq!(tls.read_u8().await.unwrap(), 42);
        tls.write_u8(43).await.unwrap();
        tls.flush().await.unwrap();
    });
    let (mut tls, peer) = client
        .connector()
        .connect(address, &id("vkg"))
        .await
        .unwrap();
    assert_eq!(peer.spiffe_id(), &id("vkg"));
    tls.write_u8(42).await.unwrap();
    tls.flush().await.unwrap();
    assert_eq!(tls.read_u8().await.unwrap(), 43);
    task.await.unwrap();
}

#[tokio::test]
async fn wrong_peer_or_untrusted_client_is_rejected() {
    for wrong_peer in [false, true] {
        let ca = ca();
        let server = issue(&ca, "vkg").identity_source().unwrap();
        let client = issue(&ca, "nexis");
        let unrelated = self::ca();
        let client = if wrong_peer {
            client
        } else {
            let mut untrusted = issue(&unrelated, "nexis");
            // Authenticate the real server, while presenting an untrusted client certificate.
            untrusted.bundle_pem.push_str(ca.certificate_pem());
            untrusted
        }
        .identity_source()
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            server.acceptor().accept(tcp).await
        });
        let expected = if wrong_peer { id("hexis") } else { id("vkg") };
        let result = client.connector().connect(address, &expected).await;
        if wrong_peer {
            assert!(result.is_err());
        }
        assert!(task.await.unwrap().is_err());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn file_rotation_retains_last_valid_identity_and_stops_on_shutdown() {
    let ca = ca();
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("vkg");
    issue(&ca, "vkg").publish(&directory).unwrap();
    let mut runtime = IdentityRuntime::start(config(&directory.join("current"), "vkg"))
        .await
        .unwrap();
    let source = runtime.identity_source();
    let initial_expiry = source.expires_at_unix();
    ca.issue_svid(&id("vkg"), Duration::from_secs(7200))
        .unwrap()
        .publish(&directory)
        .unwrap();
    runtime.reload().await.unwrap();
    assert!(source.expires_at_unix() > initial_expiry);
    let renewed_expiry = source.expires_at_unix();
    issue(&ca, "nexis").publish(&directory).unwrap();
    assert!(runtime.reload().await.is_err());
    assert_eq!(source.spiffe_id(), id("vkg"));
    assert_eq!(source.expires_at_unix(), renewed_expiry);
    let status = runtime.status().await;
    assert!(status.ready);
    assert!(status.last_error.is_some());
    issue(&ca, "vkg").publish(&directory).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while runtime.status().await.last_error.is_some() {
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .unwrap();
    runtime.shutdown().await;
    assert!(!source.is_valid());
    assert!(!runtime.status().await.ready);
    assert!(runtime.reload().await.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn projected_secrets_are_supported_and_mixed_generations_rejected() {
    use std::os::unix::fs::symlink;
    let ca = ca();
    let temp = tempfile::tempdir().unwrap();
    issue(&ca, "vkg")
        .write_generation(temp.path().join("generation-1"))
        .unwrap();
    issue(&ca, "vkg")
        .write_generation(temp.path().join("generation-2"))
        .unwrap();
    symlink("generation-1", temp.path().join("..data")).unwrap();
    for name in ["key.pem", "cert-chain.pem", "bundle.pem"] {
        symlink(format!("..data/{name}"), temp.path().join(name)).unwrap();
    }
    let mut runtime = IdentityRuntime::start(config(temp.path(), "vkg"))
        .await
        .unwrap();
    symlink("generation-2", temp.path().join("..data-new")).unwrap();
    std::fs::rename(temp.path().join("..data-new"), temp.path().join("..data")).unwrap();
    runtime.reload().await.unwrap();
    symlink("generation-1/key.pem", temp.path().join("key-new")).unwrap();
    std::fs::rename(temp.path().join("key-new"), temp.path().join("key.pem")).unwrap();
    assert!(runtime.reload().await.is_err());
    runtime.shutdown().await;
}

#[tokio::test]
async fn connection_lifetime_is_enforced_on_existing_tls_streams() {
    let ca = ca();
    let server = issue(&ca, "vkg").identity_source().unwrap();
    let client = issue(&ca, "nexis").identity_source().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let (mut tls, _) = server
            .acceptor()
            .with_transport(TransportConfig {
                max_connection_age_secs: 1,
                ..Default::default()
            })
            .unwrap()
            .accept(tcp)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), tls.read_u8())
            .await
            .unwrap()
            .is_err()
    });
    let (_tls, _) = client
        .connector()
        .connect(address, &id("vkg"))
        .await
        .unwrap();
    assert!(task.await.unwrap());
}

#[cfg(all(feature = "http", unix))]
#[tokio::test]
async fn http_reuses_connections_rotates_credentials_and_exposes_authenticated_peer() {
    use bytes::Bytes;
    use greater_spire::{AuthenticatedPeer, HttpClient, PeerConfig};
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Incoming, service::service_fn, Request, Response};
    use std::convert::Infallible;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let ca = ca();
    let temp = tempfile::tempdir().unwrap();
    issue(&ca, "nexis")
        .publish(temp.path().join("nexis"))
        .unwrap();
    let mut runtime = IdentityRuntime::start(config(&temp.path().join("nexis/current"), "nexis"))
        .await
        .unwrap();
    let server = issue(&ca, "vkg").identity_source().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let count = connections.clone();
    let task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (tcp, _) = accepted.unwrap();
                    count.fetch_add(1, Ordering::SeqCst);
                    let acceptor = server.acceptor();
                    tasks.spawn(async move {
                        let service = service_fn(|request: Request<Incoming>| async move {
                            let peer = request.extensions().get::<AuthenticatedPeer>().unwrap();
                            // This is application-owned authorization, outside greater-spire config.
                            let allowed = peer.spiffe_id() == &id("nexis");
                            let response = Response::builder().status(if allowed { 200 } else { 403 })
                                .body(Full::new(Bytes::from(peer.spiffe_id().to_string()))).unwrap();
                            Ok::<_, Infallible>(response)
                        });
                        let _ = acceptor.serve_http_connection(tcp, service).await;
                    });
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    });
    let peer = PeerConfig {
        url: format!("https://{address}"),
        spiffe_id: id("vkg").to_string(),
    };
    let client = HttpClient::new(
        runtime.identity_source(),
        peer.clone(),
        TransportConfig::default(),
    )
    .unwrap();
    for _ in 0..2 {
        let response = client.get("/hello").await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            id("nexis").to_string()
        );
    }
    assert_eq!(connections.load(Ordering::SeqCst), 1);
    runtime.reload().await.unwrap();
    client
        .get("/unchanged")
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    assert_eq!(connections.load(Ordering::SeqCst), 1);
    issue(&ca, "nexis")
        .publish(temp.path().join("nexis"))
        .unwrap();
    runtime.reload().await.unwrap();
    client
        .get("/rotated")
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    assert_eq!(connections.load(Ordering::SeqCst), 2);
    assert!(client.get("https://somewhere-else.example/").await.is_err());
    assert!(client.get(&format!("http://{address}/")).await.is_err());
    let other = HttpClient::new(
        issue(&ca, "hexis").identity_source().unwrap(),
        peer,
        TransportConfig::default(),
    )
    .unwrap();
    assert_eq!(other.get("/hello").await.unwrap().status(), 403);
    runtime.shutdown().await;
    assert!(client.get("/stopped").await.is_err());
    task.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn expired_last_good_credentials_fail_readiness_and_new_connections() {
    let ca = ca();
    let temp = tempfile::tempdir().unwrap();
    ca.issue_svid(&id("nexis"), Duration::from_secs(2))
        .unwrap()
        .publish(temp.path().join("nexis"))
        .unwrap();
    let mut runtime = IdentityRuntime::start(config(&temp.path().join("nexis/current"), "nexis"))
        .await
        .unwrap();
    let source = runtime.identity_source();
    // A valid certificate for the wrong local identity cannot replace the old one.
    issue(&ca, "vkg")
        .publish(temp.path().join("nexis"))
        .unwrap();
    assert!(runtime.reload().await.is_err());
    tokio::time::timeout(Duration::from_secs(5), async {
        while source.is_valid() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    assert!(!runtime.status().await.ready);
    // Fails locally before touching this unused address.
    assert!(matches!(
        source.connector().connect("127.0.0.1:1", &id("vkg")).await,
        Err(greater_spire::Error::IdentityExpired)
    ));
    runtime.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn trust_change_rejects_io_on_existing_connections() {
    let ca = ca();
    let temp = tempfile::tempdir().unwrap();
    let mut issued = issue(&ca, "vkg");
    issued.publish(temp.path().join("vkg")).unwrap();
    let mut runtime = IdentityRuntime::start(config(&temp.path().join("vkg/current"), "vkg"))
        .await
        .unwrap();
    let acceptor = runtime.acceptor();
    let client = issue(&ca, "nexis").identity_source().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (server, client) = tokio::join!(
        async {
            let (tcp, _) = listener.accept().await.unwrap();
            acceptor.accept(tcp).await.unwrap()
        },
        async {
            client
                .connector()
                .connect(address, &id("vkg"))
                .await
                .unwrap()
        }
    );
    let (mut server, _) = server;
    let (_client, _) = client;
    issued.bundle_pem.push_str(self::ca().certificate_pem());
    issued.publish(temp.path().join("vkg")).unwrap();
    runtime.reload().await.unwrap();
    assert_eq!(
        server.write_u8(1).await.unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    runtime.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn insecure_private_key_permissions_are_rejected() {
    use std::os::unix::fs::PermissionsExt;
    let ca = ca();
    let temp = tempfile::tempdir().unwrap();
    issue(&ca, "vkg")
        .write_generation(temp.path().join("generation"))
        .unwrap();
    std::fs::set_permissions(
        temp.path().join("generation/key.pem"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(
        IdentityRuntime::start(config(&temp.path().join("generation"), "vkg"))
            .await
            .is_err()
    );
    std::fs::set_permissions(
        temp.path().join("generation/key.pem"),
        std::fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    let mut runtime = IdentityRuntime::start(config(&temp.path().join("generation"), "vkg"))
        .await
        .unwrap();
    runtime.shutdown().await;
}

#[cfg(feature = "http")]
#[tokio::test]
async fn axum_receives_transport_authenticated_peer() {
    use axum::{extract::Extension, routing::get, Router};
    use greater_spire::{AuthenticatedPeer, HttpClient, PeerConfig};
    use http_body_util::BodyExt;
    use hyper_util::service::TowerToHyperService;
    let ca = ca();
    let server = issue(&ca, "vkg").identity_source().unwrap();
    let client = issue(&ca, "nexis").identity_source().unwrap();
    let router =
        Router::new().route(
            "/",
            get(|Extension(peer): Extension<AuthenticatedPeer>| async move {
                peer.spiffe_id().to_string()
            }),
        );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let _ = server
            .acceptor()
            .serve_http_connection(tcp, TowerToHyperService::new(router))
            .await;
    });
    let client = HttpClient::new(
        client,
        PeerConfig {
            url: format!("https://{address}"),
            spiffe_id: id("vkg").to_string(),
        },
        TransportConfig::default(),
    )
    .unwrap();
    let response = client.get("/").await.unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        id("nexis").to_string()
    );
    task.abort();
}
