use greater_spire::{
    Config, IdentityProviderConfig, IdentityRuntime, IdentitySource, RefreshStatus,
    SPIRE_API_SCHEMA_VERSION, SPIRE_SERVER_VERSION,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Operator-provisioned integration test against stock SPIRE v1.15.3.
///
/// GREATER_SPIRE_TEST_CONFIG points at the new embedded-provider TOML schema
/// (examples/spire.toml.example), with a fresh token and private agent state.
///
/// Optionally set GREATER_SPIRE_TEST_FILES_CONFIG to a file-provider config.
/// Its certificates and the SPIRE-issued certificates must trust each other,
/// for example by configuring SPIRE with an upstream authority under the same CA.
/// This exercises file -> SPIRE and SPIRE -> file mTLS in the same process.
///
/// Run: cargo test --test stock_spire -- --ignored --nocapture
#[tokio::test]
#[ignore = "requires stock SPIRE v1.15.3 and GREATER_SPIRE_TEST_CONFIG"]
async fn attests_mints_interoperates_and_restarts_without_token() {
    assert_eq!(SPIRE_SERVER_VERSION, "1.15.3");
    assert_eq!(SPIRE_API_SCHEMA_VERSION, "v1.15.3");
    let path = std::env::var_os("GREATER_SPIRE_TEST_CONFIG")
        .expect("set GREATER_SPIRE_TEST_CONFIG to an embedded-provider TOML file");
    let mut config = Config::from_file(path).expect("load integration config");
    assert!(matches!(
        config.identity.source,
        IdentityProviderConfig::EmbeddedSpire { .. }
    ));
    if let IdentityProviderConfig::EmbeddedSpire {
        sync_interval_secs, ..
    } = &mut config.identity.source
    {
        *sync_interval_secs = 1;
    }
    let expected = config.identity.spiffe_id.clone();
    let mut runtime = IdentityRuntime::start(config.clone())
        .await
        .expect("attest and mint");
    assert!(runtime.status().await.ready);
    let mut changes = runtime.watch();
    let initial_success = changes.borrow_and_update().last_success_unix;
    let refreshed = tokio::time::timeout(
        Duration::from_secs(60),
        changes.wait_for(|status| {
            status.last_success_unix > initial_success
                && matches!(status.refresh, RefreshStatus::Ok)
        }),
    )
    .await
    .expect("embedded refresh status timed out")
    .unwrap()
    .clone();
    assert!(refreshed.usable);
    assert_eq!(refreshed.provider, "embedded_spire");
    assert_eq!(runtime.identity_source().spiffe_id().to_string(), expected);
    exchange(runtime.identity_source(), runtime.identity_source()).await;

    if let Some(path) = std::env::var_os("GREATER_SPIRE_TEST_FILES_CONFIG") {
        let config = Config::from_file(path).unwrap();
        assert!(matches!(
            config.identity.source,
            IdentityProviderConfig::Files { .. }
        ));
        let mut files = IdentityRuntime::start(config).await.unwrap();
        exchange(files.identity_source(), runtime.identity_source()).await;
        exchange(runtime.identity_source(), files.identity_source()).await;
        files.shutdown().await;
    } else {
        eprintln!("mixed-provider checks skipped: GREATER_SPIRE_TEST_FILES_CONFIG is unset");
    }
    runtime.shutdown().await;
    assert!(!changes.borrow().usable);
    if let IdentityProviderConfig::EmbeddedSpire {
        join_token_file, ..
    } = &mut config.identity.source
    {
        *join_token_file = None;
    }
    let mut runtime = IdentityRuntime::start(config)
        .await
        .expect("restart without bootstrap secret");
    assert!(runtime.status().await.ready);
    assert_eq!(runtime.identity_source().spiffe_id().to_string(), expected);
    runtime.shutdown().await;
}

async fn exchange(client: IdentitySource, server: IdentitySource) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let expected_client = client.spiffe_id();
    let expected_server = server.spiffe_id();
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let (mut tls, peer) = server.acceptor().accept(tcp).await.unwrap();
        assert_eq!(peer.spiffe_id(), &expected_client);
        assert_eq!(tls.read_u8().await.unwrap(), 41);
        tls.write_u8(42).await.unwrap();
        tls.flush().await.unwrap();
    });
    let (mut tls, peer) = client
        .connector()
        .connect(address, &expected_server)
        .await
        .unwrap();
    assert_eq!(peer.spiffe_id(), &expected_server);
    tls.write_u8(41).await.unwrap();
    tls.flush().await.unwrap();
    assert_eq!(tls.read_u8().await.unwrap(), 42);
    task.await.unwrap();
}
