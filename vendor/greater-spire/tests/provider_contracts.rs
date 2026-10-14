#![cfg(all(feature = "static-ca", unix))]

use std::path::Path;
use std::time::Duration;

use greater_spire::static_ca::{IssuedIdentity, StaticCa};
use greater_spire::{Config, Error, IdentityRuntime, IdentitySource, SpiffeId};
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
fn config(path: &Path, name: &str) -> Config {
    Config::from_toml(
        &format!(
            r#"
version = 1
[identity]
spiffe_id = "{}"
[identity.source]
kind = "files"
directory = {:?}
poll_interval_secs = 3600
"#,
            id(name),
            path.to_str().unwrap()
        ),
        "/",
    )
    .unwrap()
}

async fn interoperates(client: IdentitySource, server: IdentitySource) -> bool {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let expected_client = client.spiffe_id();
    let expected_server = server.spiffe_id();
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(
            async {
                let (tcp, _) = listener.accept().await.unwrap();
                server.acceptor().accept(tcp).await
            },
            async { client.connector().connect(address, &expected_server).await }
        )
    })
    .await
    .expect("mTLS exchange timed out");
    match result {
        (Ok((_, caller)), Ok((_, receiver))) => {
            assert_eq!(caller.spiffe_id(), &expected_client);
            assert_eq!(receiver.spiffe_id(), &expected_server);
            true
        }
        _ => false,
    }
}

#[tokio::test]
async fn removing_files_does_not_revoke_loaded_identity_and_valid_publication_recovers_expiry() {
    let ca = ca();
    let temp = tempfile::tempdir().unwrap();
    ca.issue_svid(&id("scribe"), Duration::from_secs(4))
        .unwrap()
        .publish(temp.path())
        .unwrap();
    let mut runtime = IdentityRuntime::start(config(&temp.path().join("current"), "scribe"))
        .await
        .unwrap();
    let mut changes = runtime.watch();
    let server = issue(&ca, "vkg").identity_source().unwrap();
    assert!(interoperates(runtime.identity_source(), server.clone()).await);
    // Hide the active symlink without destroying any generation or key.
    std::fs::rename(temp.path().join("current"), temp.path().join("offline")).unwrap();
    assert!(runtime.reload().await.is_err());
    assert!(changes.borrow().usable);
    assert!(changes.borrow().last_error.is_some());
    // A fresh connection still succeeds with the retained certificate.
    assert!(interoperates(runtime.identity_source(), server.clone()).await);
    let expired = tokio::time::timeout(
        Duration::from_secs(6),
        changes.wait_for(|status| !status.usable),
    )
    .await
    .unwrap()
    .unwrap()
    .clone();
    assert!(expired.last_error.is_some());
    assert!(matches!(
        runtime.connector().connect("127.0.0.1:1", &id("vkg")).await,
        Err(Error::IdentityExpired)
    ));
    issue(&ca, "scribe").publish(temp.path()).unwrap();
    runtime.reload().await.unwrap();
    assert!(changes.borrow().usable);
    assert!(changes.borrow().last_error.is_none());
    assert!(interoperates(runtime.identity_source(), server).await);
    runtime.shutdown().await;
}

#[tokio::test]
async fn overlapping_root_migration_requires_both_peers_then_rejects_retired_issuer() {
    let old_ca = ca();
    let new_ca = ca();
    let temp = tempfile::tempdir().unwrap();
    let caller_dir = temp.path().join("scribe");
    let receiver_dir = temp.path().join("vkg");
    let mut old_caller = issue(&old_ca, "scribe");
    let mut old_receiver = issue(&old_ca, "vkg");
    old_caller.publish(&caller_dir).unwrap();
    old_receiver.publish(&receiver_dir).unwrap();
    let mut caller = IdentityRuntime::start(config(&caller_dir.join("current"), "scribe"))
        .await
        .unwrap();
    let mut receiver = IdentityRuntime::start(config(&receiver_dir.join("current"), "vkg"))
        .await
        .unwrap();
    assert!(interoperates(caller.identity_source(), receiver.identity_source()).await);
    let mut new_caller = issue(&new_ca, "scribe");
    let mut new_receiver = issue(&new_ca, "vkg");
    // Identical SPIFFE IDs with unrelated issuers do not establish trust.
    assert!(
        !interoperates(
            new_caller.identity_source().unwrap(),
            receiver.identity_source()
        )
        .await
    );
    let overlap = format!("{}{}", old_ca.certificate_pem(), new_ca.certificate_pem());
    old_caller.bundle_pem = overlap.clone();
    old_receiver.bundle_pem = overlap.clone();
    old_caller.publish(&caller_dir).unwrap();
    old_receiver.publish(&receiver_dir).unwrap();
    caller.reload().await.unwrap();
    receiver.reload().await.unwrap();
    assert!(interoperates(caller.identity_source(), receiver.identity_source()).await);
    new_caller.bundle_pem = overlap.clone();
    new_caller.publish(&caller_dir).unwrap();
    caller.reload().await.unwrap();
    assert!(interoperates(caller.identity_source(), receiver.identity_source()).await);
    new_receiver.bundle_pem = overlap;
    new_receiver.publish(&receiver_dir).unwrap();
    receiver.reload().await.unwrap();
    assert!(interoperates(caller.identity_source(), receiver.identity_source()).await);
    new_caller.bundle_pem = new_ca.certificate_pem().to_owned();
    new_receiver.bundle_pem = new_ca.certificate_pem().to_owned();
    new_caller.publish(&caller_dir).unwrap();
    new_receiver.publish(&receiver_dir).unwrap();
    caller.reload().await.unwrap();
    receiver.reload().await.unwrap();
    assert!(interoperates(caller.identity_source(), receiver.identity_source()).await);
    // The old credential can trust the new server, but the server no longer
    // accepts the old issuer. Revocation is enforced by the receiver's trust.
    assert!(
        !interoperates(
            old_caller.identity_source().unwrap(),
            receiver.identity_source()
        )
        .await
    );
    assert!(
        !interoperates(
            caller.identity_source(),
            old_receiver.identity_source().unwrap()
        )
        .await
    );
    caller.shutdown().await;
    receiver.shutdown().await;
}
