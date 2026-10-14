use std::collections::{BTreeMap, BTreeSet};
use std::io::BufReader;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::client::danger::ServerCertVerifier;
use spiffe::SpiffeId;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Identity};
use zeroize::Zeroize as _;

use crate::config::{AgentConfig, Selector};
use crate::error::{io, Error, Result};
use crate::material::WorkloadMaterial;
use crate::proto::types;
use crate::proto::{agent as agent_pb, bundle as bundle_pb, entry as entry_pb, svid as svid_pb};
use crate::state::{NodeState, StateStore};
use crate::status::StatusPublisher;
use crate::tls::{exact_server_verifier, root_store, IdentitySource};

/// Health and rotation status for an embedded agent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentStatus {
    pub healthy: bool,
    pub agent_spiffe_id: String,
    pub workload_spiffe_id: String,
    pub agent_expires_at_unix: i64,
    pub workload_expires_at_unix: i64,
    pub last_success_unix: i64,
    pub last_error: Option<String>,
}

struct Inner {
    config: AgentConfig,
    state_store: StateStore,
    node: tokio::sync::RwLock<NodeState>,
    identity: IdentitySource,
    status: StatusPublisher,
    cancel: CancellationToken,
    task: Mutex<Option<JoinHandle<()>>>,
}

/// An in-process replacement for the SPIRE agent in a single Rust service.
///
/// It performs join-token node attestation directly against a stock SPIRE
/// Server, persists the agent SVID/key, selects one authorized registration
/// entry, mints the workload SVID, and refreshes both identities in place.
#[derive(Clone)]
pub struct EmbeddedAgent {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for EmbeddedAgent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EmbeddedAgent")
            .field("config", &self.inner.config)
            .field("identity", &self.inner.identity.spiffe_id())
            .finish_non_exhaustive()
    }
}

impl EmbeddedAgent {
    /// Start the embedded agent and wait for an initial workload SVID.
    ///
    /// Startup fails closed: callers never receive a handle without a verified,
    /// currently valid workload identity and trust bundle.
    pub async fn start(mut config: AgentConfig) -> Result<Self> {
        config.validate()?;
        crate::tls::ensure_crypto_provider();
        let state_store = StateStore::open(&config.state_dir)?;
        let bootstrap_bundle = read_pem_certificates(&config.bootstrap_bundle_path)?;
        let node = load_or_attest(&config, &state_store, &bootstrap_bundle).await?;

        // The join token has served its only purpose. Do not retain it in the
        // long-lived task or accidentally include it in a crash dump.
        if let Some(token) = config.join_token.as_mut() {
            token.zeroize();
        }
        config.join_token = None;

        let initial = refresh_workload(&config, &node, None).await?;
        state_store.save(&initial.node)?;
        let identity = IdentitySource::new(initial.material);
        let status = StatusPublisher::new("embedded_spire", identity.clone());
        let cancel = CancellationToken::new();
        let inner = Arc::new(Inner {
            config,
            state_store,
            node: tokio::sync::RwLock::new(initial.node),
            identity,
            status,
            cancel,
            task: Mutex::new(None),
        });
        let weak = Arc::downgrade(&inner);
        let task = tokio::spawn(supervise(weak));
        *inner.task.lock().expect("task lock poisoned") = Some(task);
        Ok(Self { inner })
    }

    pub fn identity_source(&self) -> IdentitySource {
        self.inner.identity.clone()
    }

    pub async fn status(&self) -> AgentStatus {
        let node = self.inner.node.read().await;
        let workload_expiry = self.inner.identity.expires_at_unix();
        let now = unix_now();
        let status = self.inner.status.snapshot();
        AgentStatus {
            healthy: node.expires_at > now && self.inner.identity.is_valid(),
            agent_spiffe_id: node.agent_id.clone(),
            workload_spiffe_id: self.inner.identity.spiffe_id().to_string(),
            agent_expires_at_unix: node.expires_at,
            workload_expires_at_unix: workload_expiry,
            last_success_unix: status.last_success_unix,
            last_error: status.last_error,
        }
    }

    pub async fn shutdown(&self) {
        self.request_shutdown();
        let task = self.inner.task.lock().expect("task lock poisoned").take();
        if let Some(task) = task {
            let _ = task.await;
        }
    }

    pub(crate) fn request_shutdown(&self) {
        self.inner.cancel.cancel();
        self.inner.status.stop();
    }

    pub(crate) fn status_publisher(&self) -> StatusPublisher {
        self.inner.status.clone()
    }
}

async fn supervise(inner: Weak<Inner>) {
    loop {
        let Some(strong) = inner.upgrade() else {
            return;
        };
        let interval = strong.config.sync_interval();
        let cancel = strong.cancel.clone();
        drop(strong);
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(interval) => {}
        }
        let Some(strong) = inner.upgrade() else {
            return;
        };
        let refreshed = tokio::select! {
            _ = strong.cancel.cancelled() => return,
            result = strong.refresh() => result,
        };
        // Publication can itself reject a candidate (expiry or shutdown).
        // Report that outcome as well as failures while fetching credentials.
        if let Err(error) = strong.status.record_reload(refreshed) {
            tracing::warn!(error = %error, "embedded SPIRE agent refresh failed; retaining last-known-good identity");
        }
    }
}

impl Inner {
    async fn refresh(&self) -> Result<WorkloadMaterial> {
        let mut node = self.node.read().await.clone();
        let rotate_before = self.config.rotate_before().as_secs() as i64;
        if node.expires_at <= unix_now() {
            return Err(Error::AgentIdentityExpired);
        }
        if node.expires_at - unix_now() <= rotate_before {
            node = renew_node(&self.config, &node).await?;
            // Persist before the first RPC that presents the new certificate.
            // SPIRE activates a renewed agent SVID on first use and retires the
            // old one; losing the new key after that point is unrecoverable.
            self.state_store.save(&node)?;
            *self.node.write().await = node.clone();
        }

        let current = self.identity.0.load_full();
        let refreshed = refresh_workload(&self.config, &node, Some(&current)).await?;
        // Agent recovery state is persisted separately from workload publication.
        // The workload revision travels only with its credential snapshot.
        self.state_store.save(&refreshed.node)?;
        *self.node.write().await = refreshed.node;
        Ok(refreshed.material)
    }
}

struct RefreshResult {
    node: NodeState,
    material: WorkloadMaterial,
}

async fn load_or_attest(
    config: &AgentConfig,
    state_store: &StateStore,
    bootstrap_bundle: &[Vec<u8>],
) -> Result<NodeState> {
    if let Some(state) = state_store.load()? {
        if state.expires_at > unix_now() {
            validate_node_state(config, &state)?;
            tracing::info!(agent_id = %state.agent_id, "loaded embedded SPIRE agent identity");
            return Ok(state);
        }
        tracing::warn!(agent_id = %state.agent_id, "stored embedded SPIRE agent identity expired");
        if config.join_token.is_none() {
            return Err(Error::AgentIdentityExpired);
        }
    }

    let token = config.join_token.as_deref().ok_or_else(|| {
        Error::Config("join_token is required because no usable agent state exists".into())
    })?;
    let state = attest_node(config, token, bootstrap_bundle).await?;
    // A join token is one-use bootstrap material. Persist the returned SVID
    // before any subsequent RPC so a crash cannot strand the installation.
    state_store.save(&state)?;
    Ok(state)
}

async fn attest_node(
    config: &AgentConfig,
    token: &str,
    bootstrap_bundle: &[Vec<u8>],
) -> Result<NodeState> {
    let (key_pkcs8, csr) = new_key_and_csr()?;
    let server_id = server_spiffe_id(&config.trust_domain)?;
    let verifier = exact_server_verifier(root_store(bootstrap_bundle)?, server_id)?;
    let channel =
        grpc_channel(&config.server_address, verifier, None, config.rpc_timeout()).await?;
    // GetBundle is deliberately unauthenticated on a stock SPIRE server. The
    // response is still protected by the pinned bootstrap TLS trust root.
    let mut bundle_client = bundle_pb::bundle_client::BundleClient::new(channel.clone());
    let bundle = bundle_client
        .get_bundle(bundle_pb::GetBundleRequest {
            output_mask: Some(bundle_mask()),
        })
        .await?
        .into_inner();
    let (bundle_sequence, bundle_certs) = parse_bundle(&bundle, &config.trust_domain)?;

    let mut client = agent_pb::agent_client::AgentClient::new(channel);
    let request = agent_pb::AttestAgentRequest {
        step: Some(agent_pb::attest_agent_request::Step::Params(
            agent_pb::attest_agent_request::Params {
                data: Some(types::AttestationData {
                    r#type: "join_token".into(),
                    payload: token.as_bytes().to_vec(),
                }),
                params: Some(agent_pb::AgentX509svidParams { csr }),
            },
        )),
    };
    let mut stream = client
        .attest_agent(tokio_stream::iter([request]))
        .await?
        .into_inner();
    let response = stream
        .message()
        .await?
        .ok_or_else(|| Error::Protocol("AttestAgent returned an empty stream".into()))?;
    let result = match response.step {
        Some(agent_pb::attest_agent_response::Step::Result(result)) => result,
        Some(agent_pb::attest_agent_response::Step::Challenge(_)) => {
            return Err(Error::Protocol(
                "join_token attestation unexpectedly returned a challenge".into(),
            ));
        }
        None => return Err(Error::Protocol("AttestAgent response has no result".into())),
    };
    let svid = result
        .svid
        .ok_or_else(|| Error::Protocol("AttestAgent response has no SVID".into()))?;
    let agent_id = validate_svid(&svid, None, &key_pkcs8)?;

    Ok(NodeState {
        trust_domain: config.trust_domain.clone(),
        agent_id: agent_id.to_string(),
        key_pkcs8,
        cert_chain: svid.cert_chain,
        expires_at: svid.expires_at,
        reattestable: result.reattestable,
        bundle_sequence,
        bundle: bundle_certs,
    })
}

async fn renew_node(config: &AgentConfig, node: &NodeState) -> Result<NodeState> {
    let (key_pkcs8, csr) = new_key_and_csr()?;
    let channel = authenticated_channel(config, node).await?;
    let mut client = agent_pb::agent_client::AgentClient::new(channel);
    let response = client
        .renew_agent(agent_pb::RenewAgentRequest {
            params: Some(agent_pb::AgentX509svidParams { csr }),
        })
        .await?
        .into_inner();
    let svid = response
        .svid
        .ok_or_else(|| Error::Protocol("RenewAgent response has no SVID".into()))?;
    let expected: SpiffeId = node
        .agent_id
        .as_str()
        .try_into()
        .map_err(|error| Error::Protocol(format!("stored agent ID is invalid: {error}")))?;
    validate_svid(&svid, Some(&expected), &key_pkcs8)?;
    let mut renewed = node.clone();
    renewed.key_pkcs8 = key_pkcs8;
    renewed.cert_chain = svid.cert_chain;
    renewed.expires_at = svid.expires_at;
    Ok(renewed)
}

async fn refresh_workload(
    config: &AgentConfig,
    node: &NodeState,
    current: Option<&WorkloadMaterial>,
) -> Result<RefreshResult> {
    let channel = authenticated_channel(config, node).await?;
    let entry = fetch_entry(config, channel.clone()).await?;
    let entry_id = entry.id.clone();
    let expected: SpiffeId = config
        .workload_spiffe_id
        .as_str()
        .try_into()
        .map_err(|error| Error::Config(format!("invalid workload ID: {error}")))?;

    let rotate_before = config.rotate_before().as_secs() as i64;
    let must_mint =
        workload_needs_renewal(current, entry.revision_number, unix_now(), rotate_before);

    let (key_pkcs8, cert_chain, _expires_at) = if must_mint {
        mint_workload_svid(channel.clone(), &entry_id, &expected).await?
    } else {
        let current = current.expect("checked above");
        (
            current.key_pkcs8.clone(),
            current.cert_chain.clone(),
            current.expires_at,
        )
    };

    let mut bundle_client = bundle_pb::bundle_client::BundleClient::new(channel);
    let local = bundle_client
        .get_bundle(bundle_pb::GetBundleRequest {
            output_mask: Some(bundle_mask()),
        })
        .await?
        .into_inner();
    let (sequence, local_certs) = parse_bundle(&local, &config.trust_domain)?;
    let mut bundles = BTreeMap::from([(config.trust_domain.clone(), local_certs.clone())]);
    for domain in &entry.federates_with {
        let bundle = bundle_client
            .get_federated_bundle(bundle_pb::GetFederatedBundleRequest {
                trust_domain: domain.clone(),
                output_mask: Some(bundle_mask()),
            })
            .await?
            .into_inner();
        let (_, certs) = parse_bundle(&bundle, domain)?;
        bundles.insert(domain.clone(), certs);
    }

    let mut node = node.clone();
    node.bundle_sequence = sequence;
    node.bundle = local_certs;
    let mut material = WorkloadMaterial::from_der(&expected, cert_chain, key_pkcs8, bundles)?;
    material.spire_entry_revision = Some(entry.revision_number);
    Ok(RefreshResult { node, material })
}

fn workload_needs_renewal(
    current: Option<&WorkloadMaterial>,
    entry_revision: i64,
    now: i64,
    rotate_before: i64,
) -> bool {
    current.is_none_or(|material| {
        material.spire_entry_revision != Some(entry_revision)
            || material.valid_until.saturating_sub(now) <= rotate_before
    })
}

async fn fetch_entry(config: &AgentConfig, channel: Channel) -> Result<types::Entry> {
    let mut client = entry_pb::entry_client::EntryClient::new(channel);
    let response = client
        .get_authorized_entries(entry_pb::GetAuthorizedEntriesRequest {
            output_mask: Some(entry_mask()),
        })
        .await?
        .into_inner();
    let mut candidates = response
        .entries
        .into_iter()
        .filter(|entry| {
            proto_spiffe_id(entry.spiffe_id.as_ref())
                .is_ok_and(|id| id.to_string() == config.workload_spiffe_id)
        })
        .filter(|entry| selectors_match(&entry.selectors, &config.expected_selectors))
        .collect::<Vec<_>>();
    match candidates.len() {
        0 => Err(Error::WorkloadEntryNotFound(
            config.workload_spiffe_id.clone(),
        )),
        1 => Ok(candidates.remove(0)),
        _ => Err(Error::AmbiguousWorkloadEntry(
            config.workload_spiffe_id.clone(),
        )),
    }
}

fn selectors_match(actual: &[types::Selector], expected: &[Selector]) -> bool {
    if expected.is_empty() {
        return true;
    }
    let actual = actual
        .iter()
        .map(|selector| (selector.r#type.as_str(), selector.value.as_str()))
        .collect::<BTreeSet<_>>();
    let expected = expected
        .iter()
        .map(|selector| (selector.kind.as_str(), selector.value.as_str()))
        .collect::<BTreeSet<_>>();
    actual == expected
}

async fn mint_workload_svid(
    channel: Channel,
    entry_id: &str,
    expected: &SpiffeId,
) -> Result<(Vec<u8>, Vec<Vec<u8>>, i64)> {
    let (key_pkcs8, csr) = new_key_and_csr()?;
    let mut client = svid_pb::svid_client::SvidClient::new(channel);
    let response = client
        .batch_new_x509svid(svid_pb::BatchNewX509svidRequest {
            params: vec![svid_pb::NewX509svidParams {
                entry_id: entry_id.into(),
                csr,
            }],
        })
        .await?
        .into_inner();
    let result = response
        .results
        .into_iter()
        .next()
        .ok_or_else(|| Error::Protocol("BatchNewX509SVID returned no result".into()))?;
    if let Some(status) = result.status {
        if status.code != 0 {
            return Err(Error::Protocol(format!(
                "BatchNewX509SVID failed with status {}: {}",
                status.code, status.message
            )));
        }
    }
    let svid = result
        .svid
        .ok_or_else(|| Error::Protocol("BatchNewX509SVID returned no SVID".into()))?;
    validate_svid(&svid, Some(expected), &key_pkcs8)?;
    Ok((key_pkcs8, svid.cert_chain, svid.expires_at))
}

async fn authenticated_channel(config: &AgentConfig, node: &NodeState) -> Result<Channel> {
    if node.expires_at <= unix_now() {
        return Err(Error::AgentIdentityExpired);
    }
    let _agent_id: SpiffeId = node
        .agent_id
        .as_str()
        .try_into()
        .map_err(|error| Error::Protocol(format!("stored agent ID is invalid: {error}")))?;
    let server = server_spiffe_id(&config.trust_domain)?;
    let verifier = exact_server_verifier(root_store(&node.bundle)?, server)?;
    let identity = tonic_identity(&node.cert_chain, &node.key_pkcs8);
    grpc_channel(
        &config.server_address,
        verifier,
        Some(identity),
        config.rpc_timeout(),
    )
    .await
}

async fn grpc_channel(
    address: &str,
    verifier: Arc<dyn ServerCertVerifier>,
    identity: Option<Identity>,
    timeout: Duration,
) -> Result<Channel> {
    let uri = format!("https://{address}");
    let endpoint = Endpoint::from_shared(uri)
        .map_err(|error| Error::Config(format!("invalid SPIRE server address: {error}")))?
        .connect_timeout(timeout)
        .timeout(timeout);
    let mut tls = ClientTlsConfig::new().assume_http2(true).timeout(timeout);
    if let Some(identity) = identity {
        tls = tls.identity(identity);
    }
    endpoint
        .tls_config_with_verifier(tls, verifier)
        .map_err(Error::SpireTransport)?
        .connect()
        .await
        .map_err(Error::SpireTransport)
}

fn tonic_identity(cert_chain: &[Vec<u8>], key_pkcs8: &[u8]) -> Identity {
    let mut certificates = Vec::new();
    for certificate in cert_chain {
        append_pem(&mut certificates, "CERTIFICATE", certificate);
    }
    let mut key = Vec::new();
    append_pem(&mut key, "PRIVATE KEY", key_pkcs8);
    Identity::from_pem(certificates, key)
}

fn append_pem(output: &mut Vec<u8>, label: &str, der: &[u8]) {
    output.extend_from_slice(format!("-----BEGIN {label}-----\n").as_bytes());
    let encoded = STANDARD.encode(der);
    for line in encoded.as_bytes().chunks(64) {
        output.extend_from_slice(line);
        output.push(b'\n');
    }
    output.extend_from_slice(format!("-----END {label}-----\n").as_bytes());
}

fn new_key_and_csr() -> Result<(Vec<u8>, Vec<u8>)> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|error| Error::Certificate(error.to_string()))?;
    let key_pkcs8 = key.serialize_der();
    let params = CertificateParams::new(Vec::<String>::new())
        .map_err(|error| Error::Certificate(error.to_string()))?;
    let csr = params
        .serialize_request(&key)
        .map_err(|error| Error::Certificate(error.to_string()))?
        .der()
        .to_vec();
    Ok((key_pkcs8, csr))
}

fn validate_svid(
    svid: &types::X509svid,
    expected: Option<&SpiffeId>,
    key_pkcs8: &[u8],
) -> Result<SpiffeId> {
    let leaf = svid
        .cert_chain
        .first()
        .ok_or_else(|| Error::Protocol("X.509-SVID certificate chain is empty".into()))?;
    let id = spiffe::cert::spiffe_id_from_der(leaf)
        .map_err(|error| Error::Protocol(format!("invalid X.509-SVID: {error}")))?;
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf)
        .map_err(|error| Error::Protocol(format!("invalid X.509-SVID: {error}")))?;
    if parsed.validity().not_after.timestamp() != svid.expires_at {
        return Err(Error::Protocol(
            "SVID expiration disagrees with its leaf certificate".into(),
        ));
    }
    let now = unix_now();
    for der in &svid.cert_chain {
        let (remaining, cert) = x509_parser::parse_x509_certificate(der)
            .map_err(|error| Error::Protocol(format!("invalid SVID chain: {error}")))?;
        if !remaining.is_empty()
            || now < cert.validity().not_before.timestamp()
            || now >= cert.validity().not_after.timestamp()
        {
            return Err(Error::Protocol(
                "SVID chain is malformed or not currently valid".into(),
            ));
        }
    }
    if let Some(expected) = expected {
        if &id != expected {
            return Err(Error::Protocol(format!(
                "server issued SVID {id}, expected {expected}"
            )));
        }
    }
    let proto_id = proto_spiffe_id(svid.id.as_ref())?;
    if proto_id != id {
        return Err(Error::Protocol(format!(
            "SVID certificate ID {id} disagrees with response ID {proto_id}"
        )));
    }
    if svid.expires_at <= unix_now() {
        return Err(Error::Protocol(
            "server issued an expired X.509-SVID".into(),
        ));
    }
    // `with_client_auth_cert` verifies that this PKCS#8 key matches the leaf.
    let mut bundles = BTreeMap::new();
    bundles.insert(id.trust_domain().to_string(), vec![leaf.clone()]);
    let _ = rustls::sign::CertifiedKey::from_der(
        svid.cert_chain
            .iter()
            .cloned()
            .map(rustls::pki_types::CertificateDer::from)
            .collect(),
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            key_pkcs8.to_vec(),
        )),
        rustls::crypto::CryptoProvider::get_default()
            .ok_or_else(|| Error::Tls("rustls crypto provider is unavailable".into()))?,
    )
    .map_err(|error| Error::Protocol(format!("SVID key mismatch: {error:?}")))?;
    Ok(id)
}

fn validate_node_state(config: &AgentConfig, state: &NodeState) -> Result<()> {
    if state.trust_domain != config.trust_domain {
        return Err(Error::UnsafeState(format!(
            "stored trust domain {} differs from configured {}",
            state.trust_domain, config.trust_domain
        )));
    }
    let svid = types::X509svid {
        cert_chain: state.cert_chain.clone(),
        id: Some(spiffe_to_proto(&state.agent_id)?),
        expires_at: state.expires_at,
        hint: String::new(),
    };
    let expected: SpiffeId = state
        .agent_id
        .as_str()
        .try_into()
        .map_err(|error| Error::UnsafeState(format!("invalid stored agent ID: {error}")))?;
    validate_svid(&svid, Some(&expected), &state.key_pkcs8)?;
    if state.bundle.is_empty() {
        return Err(Error::UnsafeState("stored trust bundle is empty".into()));
    }
    Ok(())
}

fn read_pem_certificates(path: &std::path::Path) -> Result<Vec<Vec<u8>>> {
    let file = std::fs::File::open(path).map_err(|error| io(path, error))?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| Error::Certificate(format!("{}: {error}", path.display())))?
        .into_iter()
        .map(|cert| cert.as_ref().to_vec())
        .collect::<Vec<_>>();
    if certs.is_empty() {
        return Err(Error::Certificate(format!(
            "{} contains no PEM certificates",
            path.display()
        )));
    }
    Ok(certs)
}

fn parse_bundle(bundle: &types::Bundle, expected_domain: &str) -> Result<(u64, Vec<Vec<u8>>)> {
    if bundle.trust_domain != expected_domain {
        return Err(Error::Protocol(format!(
            "bundle trust domain {} differs from expected {expected_domain}",
            bundle.trust_domain
        )));
    }
    let certs = bundle
        .x509_authorities
        .iter()
        .filter(|certificate| !certificate.tainted)
        .map(|certificate| certificate.asn1.clone())
        .collect::<Vec<_>>();
    if certs.is_empty() {
        return Err(Error::Protocol(format!(
            "bundle for {expected_domain} has no usable X.509 authorities"
        )));
    }
    crate::tls::root_store(&certs)?;
    Ok((bundle.sequence_number, certs))
}

fn server_spiffe_id(trust_domain: &str) -> Result<SpiffeId> {
    format!("spiffe://{trust_domain}/spire/server")
        .as_str()
        .try_into()
        .map_err(|error| Error::Config(format!("invalid server SPIFFE ID: {error}")))
}

fn proto_spiffe_id(value: Option<&types::Spiffeid>) -> Result<SpiffeId> {
    let value = value.ok_or_else(|| Error::Protocol("response is missing a SPIFFE ID".into()))?;
    format!("spiffe://{}{}", value.trust_domain, value.path)
        .as_str()
        .try_into()
        .map_err(|error| Error::Protocol(format!("response has invalid SPIFFE ID: {error}")))
}

fn spiffe_to_proto(value: &str) -> Result<types::Spiffeid> {
    let id: SpiffeId = value
        .try_into()
        .map_err(|error| Error::Protocol(format!("invalid SPIFFE ID: {error}")))?;
    Ok(types::Spiffeid {
        trust_domain: id.trust_domain().to_string(),
        path: id.path().to_owned(),
    })
}

fn entry_mask() -> types::EntryMask {
    types::EntryMask {
        spiffe_id: true,
        parent_id: true,
        selectors: true,
        x509_svid_ttl: true,
        federates_with: true,
        admin: true,
        downstream: true,
        expires_at: true,
        dns_names: true,
        revision_number: true,
        store_svid: true,
        jwt_svid_ttl: true,
        hint: true,
        created_at: true,
    }
}

fn bundle_mask() -> types::BundleMask {
    types::BundleMask {
        x509_authorities: true,
        refresh_hint: true,
        sequence_number: true,
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod contract_tests;
