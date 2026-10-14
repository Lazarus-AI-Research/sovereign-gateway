#![cfg(all(feature = "static-ca", unix))]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use greater_spire::static_ca::StaticCa;
use greater_spire::{Config, IdentityRuntime, IdentityStatus, RefreshStatus, SpiffeId};
use tokio::sync::watch;

fn id(name: &str) -> SpiffeId {
    format!("spiffe://fleet.test/service/{name}")
        .as_str()
        .try_into()
        .unwrap()
}

fn config(directory: &std::path::Path) -> Config {
    Config::from_toml(
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
            directory.to_str().unwrap()
        ),
        "/",
    )
    .unwrap()
}

async fn changed(receiver: &mut watch::Receiver<IdentityStatus>) -> IdentityStatus {
    tokio::time::timeout(Duration::from_secs(5), receiver.changed())
        .await
        .unwrap()
        .unwrap();
    receiver.borrow_and_update().clone()
}

#[tokio::test]
async fn watch_reports_refresh_errors_recovery_unchanged_reload_and_shutdown() {
    let ca =
        StaticCa::generate("fleet.test".try_into().unwrap(), Duration::from_secs(86400)).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let issued = ca
        .issue_svid(&id("vkg"), Duration::from_secs(3600))
        .unwrap();
    issued.publish(temp.path()).unwrap();
    let mut runtime = IdentityRuntime::start(config(&temp.path().join("current")))
        .await
        .unwrap();
    let mut changes = runtime.watch();
    let initial = changes.borrow_and_update().clone();
    assert_eq!(initial, runtime.status().await);
    assert!(changes.borrow().usable);
    assert_eq!(changes.borrow().refresh, RefreshStatus::Ok);
    assert!(!changes.has_changed().unwrap());

    // A wrong identity must not replace the usable current generation.
    ca.issue_svid(&id("nexis"), Duration::from_secs(3600))
        .unwrap()
        .publish(temp.path())
        .unwrap();
    assert!(runtime.reload().await.is_err());
    let failed = changed(&mut changes).await;
    assert!(failed.ready && failed.usable);
    let RefreshStatus::Error {
        error,
        since_unix,
        last_attempt_unix,
    } = failed.refresh
    else {
        panic!("refresh failure not published");
    };
    assert_eq!(failed.last_error.as_deref(), Some(error.as_str()));
    assert_eq!(since_unix, last_attempt_unix);
    assert!(runtime.reload().await.is_err());
    let failed_again = changed(&mut changes).await;
    assert!(matches!(failed_again.refresh, RefreshStatus::Error {
        since_unix: since, last_attempt_unix: latest, ..
    } if since == since_unix && latest >= last_attempt_unix));

    issued.publish(temp.path()).unwrap();
    runtime.reload().await.unwrap();
    let recovered = changed(&mut changes).await;
    assert!(recovered.usable);
    assert_eq!(recovered.refresh, RefreshStatus::Ok);
    assert_eq!(recovered.last_error, None);
    // Even a no-op reload in the same second wakes subscribers.
    runtime.reload().await.unwrap();
    assert!(changed(&mut changes).await.usable);

    runtime.shutdown().await;
    let stopped = changed(&mut changes).await;
    assert!(!stopped.ready && !stopped.usable);
    assert_eq!(stopped.refresh, RefreshStatus::Ok);
    assert_eq!(stopped, runtime.status().await);
    assert!(runtime.reload().await.is_err());
    drop(runtime);
    assert!(changes.changed().await.is_err());
}

#[tokio::test]
async fn watch_expires_without_reload_and_rotation_rearms_the_timer() {
    let ca =
        StaticCa::generate("fleet.test".try_into().unwrap(), Duration::from_secs(86400)).unwrap();
    let temp = tempfile::tempdir().unwrap();
    ca.issue_svid(&id("vkg"), Duration::from_secs(2))
        .unwrap()
        .publish(temp.path())
        .unwrap();
    let mut runtime = IdentityRuntime::start(config(&temp.path().join("current")))
        .await
        .unwrap();
    let mut changes = runtime.watch();
    let old_expiration = changes.borrow_and_update().valid_until_unix;
    // Let the expiry monitor arm the original deadline before rotating.
    tokio::task::yield_now().await;
    ca.issue_svid(&id("vkg"), Duration::from_secs(4))
        .unwrap()
        .publish(temp.path())
        .unwrap();
    runtime.reload().await.unwrap();
    let renewed = changed(&mut changes).await;
    assert!(renewed.valid_until_unix > old_expiration);
    let old_deadline = UNIX_EPOCH + Duration::from_secs(old_expiration as u64);
    tokio::time::sleep(
        old_deadline
            .duration_since(SystemTime::now())
            .unwrap_or_default()
            + Duration::from_millis(50),
    )
    .await;
    assert!(
        !changes.has_changed().unwrap(),
        "old expiry timer invalidated the new identity"
    );
    assert!(changes.borrow().usable);
    // No status() call or refresh drives this transition (poll interval is one hour).
    let expired = changed(&mut changes).await;
    assert!(!expired.usable && !expired.ready);
    assert_eq!(expired.last_success_unix, renewed.last_success_unix);
    assert_eq!(expired.refresh, RefreshStatus::Ok);
    assert_eq!(expired.valid_until_unix, renewed.valid_until_unix);

    ca.issue_svid(&id("vkg"), Duration::from_secs(3600))
        .unwrap()
        .publish(temp.path())
        .unwrap();
    runtime.reload().await.unwrap();
    assert!(changed(&mut changes).await.usable);
    runtime.shutdown().await;
}

#[tokio::test]
async fn dropping_runtime_publishes_unusable_and_closes_watch() {
    let ca =
        StaticCa::generate("fleet.test".try_into().unwrap(), Duration::from_secs(86400)).unwrap();
    let temp = tempfile::tempdir().unwrap();
    ca.issue_svid(&id("vkg"), Duration::from_secs(3600))
        .unwrap()
        .publish(temp.path())
        .unwrap();
    let runtime = IdentityRuntime::start(config(&temp.path().join("current")))
        .await
        .unwrap();
    let mut changes = runtime.watch();
    drop(runtime);
    assert!(!changed(&mut changes).await.usable);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), changes.changed())
            .await
            .unwrap()
            .is_err()
    );
}

#[tokio::test]
async fn automatic_file_reload_publishes_failure_and_recovery() {
    let ca =
        StaticCa::generate("fleet.test".try_into().unwrap(), Duration::from_secs(86400)).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let issued = ca
        .issue_svid(&id("vkg"), Duration::from_secs(3600))
        .unwrap();
    issued.publish(temp.path()).unwrap();
    let mut config = config(&temp.path().join("current"));
    if let greater_spire::IdentityProviderConfig::Files {
        poll_interval_secs, ..
    } = &mut config.identity.source
    {
        *poll_interval_secs = 1;
    }
    let mut runtime = IdentityRuntime::start(config).await.unwrap();
    let mut changes = runtime.watch();
    ca.issue_svid(&id("nexis"), Duration::from_secs(3600))
        .unwrap()
        .publish(temp.path())
        .unwrap();
    let failure = tokio::time::timeout(
        Duration::from_secs(5),
        changes.wait_for(|status| matches!(status.refresh, RefreshStatus::Error { .. })),
    )
    .await
    .unwrap()
    .unwrap()
    .clone();
    assert!(failure.usable);
    issued.publish(temp.path()).unwrap();
    let recovered = tokio::time::timeout(
        Duration::from_secs(5),
        changes.wait_for(|status| matches!(status.refresh, RefreshStatus::Ok)),
    )
    .await
    .unwrap()
    .unwrap()
    .clone();
    assert!(recovered.usable);
    assert_eq!(recovered.last_error, None);
    runtime.shutdown().await;
}
