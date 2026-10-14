use super::*;
use crate::{static_ca::StaticCa, Config, RefreshStatus};

fn fixture() -> (tempfile::TempDir, AgentConfig, NodeState) {
    let temp = tempfile::tempdir().unwrap();
    let ca =
        StaticCa::generate("fleet.test".try_into().unwrap(), Duration::from_secs(86400)).unwrap();
    let bootstrap = temp.path().join("bootstrap.pem");
    std::fs::write(&bootstrap, ca.certificate_pem()).unwrap();
    let agent_id: SpiffeId = "spiffe://fleet.test/nodes/test".try_into().unwrap();
    let issued = ca.issue_svid(&agent_id, Duration::from_secs(3600)).unwrap();
    let source = issued.identity_source().unwrap();
    let material = source.0.load_full();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let config = Config::from_toml(
        &format!(
            r#"
version = 1
[identity]
spiffe_id = "spiffe://fleet.test/service/vkg"
[identity.source]
kind = "embedded_spire"
server_address = "{address}"
bootstrap_bundle_path = {:?}
state_dir = {:?}
rpc_timeout_secs = 1
"#,
            bootstrap.to_str().unwrap(),
            temp.path().join("state").to_str().unwrap()
        ),
        "/",
    )
    .unwrap()
    .agent_config(None)
    .unwrap();
    let state = NodeState {
        trust_domain: "fleet.test".into(),
        agent_id: agent_id.to_string(),
        key_pkcs8: material.key_pkcs8.clone(),
        cert_chain: material.cert_chain.clone(),
        expires_at: material.expires_at,
        reattestable: false,
        bundle_sequence: 0,
        bundle: material.bundles["fleet.test"].clone(),
    };
    (temp, config, state)
}

#[tokio::test]
async fn valid_persisted_node_is_not_an_offline_workload_cache() {
    let (_temp, config, state) = fixture();
    StateStore::open(&config.state_dir)
        .unwrap()
        .save(&state)
        .unwrap();
    let error = tokio::time::timeout(Duration::from_secs(3), EmbeddedAgent::start(config))
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(error, Error::SpireTransport(_)));
    assert!(error.find_cause::<tonic::transport::Error>().is_some());
}

#[tokio::test]
async fn expired_persisted_lease_requires_new_enrollment() {
    let (_temp, config, mut state) = fixture();
    state.expires_at = unix_now() - 1;
    StateStore::open(&config.state_dir)
        .unwrap()
        .save(&state)
        .unwrap();
    assert!(matches!(
        EmbeddedAgent::start(config).await,
        Err(Error::AgentIdentityExpired)
    ));
}

#[test]
fn node_state_expiration_must_match_the_certificate() {
    let (_temp, config, mut state) = fixture();
    validate_node_state(&config, &state).unwrap();
    state.expires_at += 3600;
    assert!(matches!(
        validate_node_state(&config, &state),
        Err(Error::Protocol(_))
    ));
}

#[test]
fn workload_renewal_uses_chain_deadline_and_registration_revision() {
    let (_temp, _config, state) = fixture();
    let id: SpiffeId = state.agent_id.as_str().try_into().unwrap();
    let mut material = WorkloadMaterial::from_der(
        &id,
        state.cert_chain,
        state.key_pkcs8,
        BTreeMap::from([(state.trust_domain, state.bundle)]),
    )
    .unwrap();
    let now = unix_now();
    assert!(workload_needs_renewal(Some(&material), 1, now, 300));
    material.spire_entry_revision = Some(1);
    assert!(!workload_needs_renewal(Some(&material), 1, now, 300));
    assert!(workload_needs_renewal(None, 1, now, 300));
    assert!(workload_needs_renewal(Some(&material), 2, now, 300));
    material.valid_until = now + 200;
    assert!(material.expires_at > now + 300);
    assert!(workload_needs_renewal(Some(&material), 1, now, 300));
}

fn workload_publication_fixture() -> (IdentitySource, StatusPublisher, WorkloadMaterial) {
    let ca =
        StaticCa::generate("fleet.test".try_into().unwrap(), Duration::from_secs(86400)).unwrap();
    let id: SpiffeId = "spiffe://fleet.test/service/vkg".try_into().unwrap();
    let material = |revision| {
        let source = ca
            .issue_svid(&id, Duration::from_secs(3600))
            .unwrap()
            .identity_source()
            .unwrap();
        let mut material = (*source.0.load_full()).clone();
        material.spire_entry_revision = Some(revision);
        material
    };
    let identity = IdentitySource::new(material(1));
    let publisher = StatusPublisher::new("embedded_spire", identity.clone());
    (identity, publisher, material(2))
}

#[test]
fn rejected_registration_candidate_retries_until_material_and_revision_are_published() {
    let (identity, publisher, replacement) = workload_publication_fixture();
    let original = identity.current().unwrap();
    let mut changes = publisher.watch();
    // R1 is well outside its expiry renewal window; only a registration change
    // should trigger replacement. R2 must stay unapplied across failed attempts.
    assert!(!workload_needs_renewal(Some(&original), 1, unix_now(), 300));
    assert!(workload_needs_renewal(Some(&original), 2, unix_now(), 300));
    let mut expired = replacement.clone();
    // Deterministically inject expiry after validation, at the publication
    // boundary where persistence/lock delays could otherwise expose the race.
    expired.valid_until = unix_now() - 1;
    for _ in 0..2 {
        assert!(matches!(
            publisher.record_reload(Ok(expired.clone())),
            Err(Error::IdentityExpired)
        ));
        let active = identity.current().unwrap();
        assert!(Arc::ptr_eq(&original, &active));
        assert_eq!(active.spire_entry_revision, Some(1));
        assert!(workload_needs_renewal(Some(&active), 2, unix_now(), 300));
        assert!(changes.has_changed().unwrap());
        let status = changes.borrow_and_update().clone();
        assert!(status.usable);
        assert!(matches!(status.refresh, RefreshStatus::Error { .. }));
    }

    // Only a successfully published replacement acknowledges R2 and permits
    // certificate reuse on the next refresh.
    publisher.record_reload(Ok(replacement.clone())).unwrap();
    let active = identity.current().unwrap();
    assert!(!Arc::ptr_eq(&original, &active));
    assert_eq!(active.spire_entry_revision, Some(2));
    assert_eq!(active.cert_chain, replacement.cert_chain);
    assert_ne!(active.cert_chain, original.cert_chain);
    assert!(!workload_needs_renewal(Some(&active), 2, unix_now(), 300));
    assert_eq!(changes.borrow_and_update().refresh, RefreshStatus::Ok);
    // An unchanged successful refresh still preserves the installed snapshot.
    publisher.record_reload(Ok(replacement)).unwrap();
    assert!(Arc::ptr_eq(&active, &identity.current().unwrap()));
}

#[test]
fn shutdown_rejects_registration_candidate_without_advancing_revision() {
    let (identity, publisher, replacement) = workload_publication_fixture();
    let original = identity.current().unwrap();
    let mut changes = publisher.watch();
    publisher.stop();
    let stopped = changes.borrow_and_update().clone();
    assert!(matches!(
        publisher.record_reload(Ok(replacement)),
        Err(Error::Stopped)
    ));
    let retained = identity.0.load_full();
    assert!(Arc::ptr_eq(&original, &retained));
    assert_eq!(retained.spire_entry_revision, Some(1));
    assert!(workload_needs_renewal(Some(&retained), 2, unix_now(), 300));
    // The revision remains unapplied, but a stopped runtime cannot use it or
    // become usable again. No late refresh notification is published either.
    assert!(matches!(identity.current(), Err(Error::Stopped)));
    assert!(!stopped.usable);
    assert_eq!(publisher.snapshot(), stopped);
    assert!(!changes.has_changed().unwrap());
}

#[test]
fn registration_metadata_is_part_of_the_immutable_snapshot() {
    let (identity, publisher, _) = workload_publication_fixture();
    let original = identity.current().unwrap();
    let mut candidate = (*original).clone();
    candidate.spire_entry_revision = Some(2);
    // Snapshot deduplication must include provider metadata, even if certificate
    // bytes are identical; readers cannot observe credentials and revision apart.
    publisher.record_reload(Ok(candidate)).unwrap();
    let active = identity.current().unwrap();
    assert!(!Arc::ptr_eq(&original, &active));
    assert_eq!(active.cert_chain, original.cert_chain);
    assert_eq!(active.spire_entry_revision, Some(2));
    assert_eq!(original.spire_entry_revision, Some(1));
    assert!(!workload_needs_renewal(Some(&active), 2, unix_now(), 300));
}
