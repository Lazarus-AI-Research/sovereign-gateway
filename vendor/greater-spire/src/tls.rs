use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Once};
use std::task::{Context, Poll};
use std::time::Duration;

use arc_swap::ArcSwap;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme};
use spiffe::SpiffeId;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_rustls::{client, server, TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

use crate::config::TransportConfig;
use crate::error::{Error, PeerIdentityError, Result, TimeoutPhase};
use crate::material::{unix_now, WorkloadMaterial};

static INSTALL_PROVIDER: Once = Once::new();

/// Certificate-authenticated identity. Contains no application permissions.
/// The optional `test-utils` feature also permits synthetic peers for tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPeer {
    spiffe_id: SpiffeId,
    expires_at_unix: i64,
    valid_until: i64,
}

impl AuthenticatedPeer {
    /// Construct a synthetic peer for application handler and authorization tests.
    ///
    /// Available only with the non-default `test-utils` feature. Enable that
    /// feature through a dev-dependency, not a production dependency. This
    /// bypasses certificate authentication: never use it to identify real
    /// callers or create peers from request headers or other untrusted input.
    ///
    /// `expires_at_unix` is an explicit Unix timestamp in seconds. It is retained
    /// verbatim, including past timestamps, so tests can represent expired peers
    /// without clocks, certificates, or network I/O. This value alone does not
    /// exercise TLS verification or connection-lifetime enforcement; retain real
    /// handshake tests for those behaviors.
    #[cfg(feature = "test-utils")]
    pub fn for_test(spiffe_id: SpiffeId, expires_at_unix: i64) -> Self {
        Self {
            spiffe_id,
            expires_at_unix,
            valid_until: expires_at_unix,
        }
    }

    pub fn spiffe_id(&self) -> &SpiffeId {
        &self.spiffe_id
    }
    pub fn expires_at_unix(&self) -> i64 {
        self.expires_at_unix
    }
}

/// TLS I/O bounded by certificate expiry and configured connection age.
/// Trust-bundle changes and runtime shutdown reject further I/O. Applications
/// must still authorize each request, including on an existing connection.
pub struct AuthenticatedStream<S> {
    inner: S,
    identity: IdentitySource,
    material: Arc<WorkloadMaterial>,
    expires_at: i64,
    deadline: Pin<Box<tokio::time::Sleep>>,
}

impl<S> AuthenticatedStream<S> {
    fn new(
        inner: S,
        identity: IdentitySource,
        material: Arc<WorkloadMaterial>,
        peer: &AuthenticatedPeer,
        transport: &TransportConfig,
    ) -> Result<Self> {
        material.check_valid()?;
        let current = identity.current()?;
        if current.bundles != material.bundles {
            return Err(Error::TrustChanged);
        }
        let expires_at = material.valid_until.min(peer.valid_until);
        if expires_at <= unix_now() {
            return Err(Error::IdentityExpired);
        }
        let expiration = std::time::UNIX_EPOCH
            .checked_add(Duration::from_secs(expires_at as u64))
            .ok_or(Error::IdentityExpired)?;
        let remaining = expiration
            .duration_since(std::time::SystemTime::now())
            .map_err(|_| Error::IdentityExpired)?;
        let age = remaining.min(Duration::from_secs(transport.max_connection_age_secs));
        Ok(Self {
            inner,
            identity,
            material,
            expires_at,
            deadline: Box::pin(tokio::time::sleep(age)),
        })
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    #[cfg(feature = "http")]
    pub(crate) fn authentication(
        &self,
    ) -> (
        IdentitySource,
        Arc<WorkloadMaterial>,
        tokio::time::Instant,
        i64,
    ) {
        (
            self.identity.clone(),
            self.material.clone(),
            self.deadline.deadline(),
            self.expires_at,
        )
    }

    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.deadline.as_mut().poll(cx).is_ready() || unix_now() >= self.expires_at {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                Error::ConnectionExpired,
            ));
        }
        let current = self
            .identity
            .current()
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
        if !Arc::ptr_eq(&current, &self.material) && current.bundles != self.material.bundles {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                Error::TrustChanged,
            ));
        }
        Ok(())
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for AuthenticatedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(e) = this.check(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for AuthenticatedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Err(e) = this.check(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(e) = this.check(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub(crate) fn ensure_crypto_provider() {
    INSTALL_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// A shared, validated credential snapshot. It owns no refresh task.
#[derive(Clone)]
pub struct IdentitySource(pub(crate) Arc<ArcSwap<WorkloadMaterial>>, CancellationToken);

impl fmt::Debug for IdentitySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let material = self.0.load();
        formatter
            .debug_struct("IdentitySource")
            .field("spiffe_id", &material.spiffe_id)
            .field("expires_at", &material.expires_at)
            .finish_non_exhaustive()
    }
}

impl IdentitySource {
    /// Load a complete X.509-SVID and its local trust-domain bundle.
    /// Validates the chain, validity interval, key match, and exact expected ID.
    pub fn from_pem(
        expected: &SpiffeId,
        cert_chain_pem: &[u8],
        key_pkcs8_pem: &[u8],
        bundle_pem: &[u8],
    ) -> Result<Self> {
        Ok(Self::new(WorkloadMaterial::from_pem(
            expected,
            cert_chain_pem,
            key_pkcs8_pem,
            bundle_pem,
        )?))
    }

    pub(crate) fn new(material: WorkloadMaterial) -> Self {
        Self(
            Arc::new(ArcSwap::from_pointee(material)),
            CancellationToken::new(),
        )
    }

    pub(crate) fn publish(&self, material: WorkloadMaterial) {
        if **self.0.load() != material {
            self.0.store(Arc::new(material));
        }
    }

    pub(crate) fn stop(&self) {
        self.1.cancel();
    }

    pub(crate) fn is_stopped(&self) -> bool {
        self.1.is_cancelled()
    }

    pub(crate) fn current(&self) -> Result<Arc<WorkloadMaterial>> {
        if self.1.is_cancelled() {
            return Err(Error::Stopped);
        }
        let material = self.0.load_full();
        material.check_valid()?;
        Ok(material)
    }

    pub fn spiffe_id(&self) -> SpiffeId {
        self.0.load().spiffe_id.clone()
    }

    pub fn expires_at_unix(&self) -> i64 {
        self.0.load().expires_at
    }

    pub fn is_valid(&self) -> bool {
        self.current().is_ok()
    }

    pub fn connector(&self) -> MtlsConnector {
        MtlsConnector {
            identity: self.clone(),
            transport: TransportConfig::default(),
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            cache: Arc::new(Mutex::new(None)),
        }
    }

    /// Authenticate clients from configured trust domains. Applications authorize them.
    pub fn acceptor(&self) -> MtlsAcceptor {
        MtlsAcceptor {
            identity: self.clone(),
            transport: TransportConfig::default(),
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            cache: Arc::new(Mutex::new(None)),
        }
    }
}

#[derive(Clone)]
pub struct MtlsConnector {
    identity: IdentitySource,
    transport: TransportConfig,
    alpn: Vec<Vec<u8>>,
    cache: Arc<Mutex<Option<CachedClientConfigs>>>,
}

struct CachedClientConfigs {
    identity: Arc<WorkloadMaterial>,
    configs: HashMap<String, Arc<rustls::ClientConfig>>,
}

impl fmt::Debug for MtlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MtlsConnector")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl MtlsConnector {
    pub fn with_transport(mut self, transport: TransportConfig) -> Result<Self> {
        transport.validate()?;
        self.transport = transport;
        Ok(self)
    }

    pub fn with_alpn(mut self, protocols: &[&[u8]]) -> Self {
        self.alpn = protocols.iter().map(|p| p.to_vec()).collect();
        self.cache = Arc::new(Mutex::new(None));
        self
    }

    /// Connect to a TCP peer and require its exact SPIFFE ID.
    ///
    /// The destination IP is used as the TLS server name, so no DNS SNI is sent.
    /// Server certificate authorization is based on `expected_peer`, not the IP.
    pub async fn connect(
        &self,
        address: impl ToSocketAddrs,
        expected_peer: &SpiffeId,
    ) -> Result<(
        AuthenticatedStream<client::TlsStream<TcpStream>>,
        AuthenticatedPeer,
    )> {
        self.connect_inner(address, expected_peer, None).await
    }

    /// Connect with an explicit TLS server name for SNI/certificate selection.
    ///
    /// Peer authorization still requires the exact `expected_peer` SPIFFE ID and
    /// its trust-domain bundle. `server_name` does not weaken or replace that check.
    pub async fn connect_with_server_name(
        &self,
        address: impl ToSocketAddrs,
        expected_peer: &SpiffeId,
        server_name: &str,
    ) -> Result<(
        AuthenticatedStream<client::TlsStream<TcpStream>>,
        AuthenticatedPeer,
    )> {
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|error| Error::Config(format!("invalid TLS server name: {error}")))?;
        self.connect_inner(address, expected_peer, Some(server_name))
            .await
    }

    async fn connect_inner(
        &self,
        address: impl ToSocketAddrs,
        expected_peer: &SpiffeId,
        server_name: Option<ServerName<'static>>,
    ) -> Result<(
        AuthenticatedStream<client::TlsStream<TcpStream>>,
        AuthenticatedPeer,
    )> {
        let material = self.identity.current()?;
        let config = self.client_config(&material, expected_peer)?;
        let tls = tokio::time::timeout(
            Duration::from_secs(self.transport.handshake_timeout_secs),
            async {
                let tcp = TcpStream::connect(address).await.map_err(Error::Connect)?;
                let name = match server_name {
                    Some(name) => name,
                    None => {
                        ServerName::IpAddress(tcp.peer_addr().map_err(Error::Connect)?.ip().into())
                    }
                };
                TlsConnector::from(config)
                    .connect(name, tcp)
                    .await
                    .map_err(Error::Handshake)
            },
        )
        .await
        .map_err(|_| Error::Timeout(TimeoutPhase::ConnectAndHandshake))??;
        let (_, connection) = tls.get_ref();
        let peer = peer_identity(connection.peer_certificates())?;
        if peer.spiffe_id() != expected_peer {
            return Err(PeerIdentityError::Mismatch {
                expected: expected_peer.clone(),
                presented: peer.spiffe_id().clone(),
            }
            .into());
        }
        let stream =
            AuthenticatedStream::new(tls, self.identity.clone(), material, &peer, &self.transport)?;
        Ok((stream, peer))
    }

    fn client_config(
        &self,
        material: &Arc<WorkloadMaterial>,
        peer: &SpiffeId,
    ) -> Result<Arc<rustls::ClientConfig>> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| Error::Tls("client config cache poisoned".into()))?;
        let cached = cache.get_or_insert_with(|| CachedClientConfigs {
            identity: material.clone(),
            configs: HashMap::new(),
        });
        if !Arc::ptr_eq(&cached.identity, material) {
            cached.identity = material.clone();
            cached.configs.clear();
        }
        let key = peer.to_string();
        if let Some(config) = cached.configs.get(&key) {
            return Ok(config.clone());
        }
        let alpn: Vec<_> = self.alpn.iter().map(Vec::as_slice).collect();
        let config = Arc::new(build_client_config(material, peer, &alpn)?);
        if cached.configs.len() >= 128 {
            cached.configs.clear();
        }
        cached.configs.insert(key, config.clone());
        Ok(config)
    }
}

#[derive(Clone)]
pub struct MtlsAcceptor {
    identity: IdentitySource,
    transport: TransportConfig,
    alpn: Vec<Vec<u8>>,
    cache: Arc<Mutex<Option<CachedServerConfig>>>,
}

impl fmt::Debug for MtlsAcceptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MtlsAcceptor")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

struct CachedServerConfig {
    identity: Arc<WorkloadMaterial>,
    config: Arc<rustls::ServerConfig>,
}

impl MtlsAcceptor {
    pub fn with_transport(mut self, transport: TransportConfig) -> Result<Self> {
        transport.validate()?;
        self.transport = transport;
        Ok(self)
    }

    pub fn with_alpn(mut self, protocols: &[&[u8]]) -> Self {
        self.alpn = protocols.iter().map(|p| p.to_vec()).collect();
        self.cache = Arc::new(Mutex::new(None));
        self
    }

    /// Require a valid client SVID in its explicitly trusted domain.
    /// A successful handshake does not grant any application permissions.
    pub async fn accept(
        &self,
        stream: TcpStream,
    ) -> Result<(
        AuthenticatedStream<server::TlsStream<TcpStream>>,
        AuthenticatedPeer,
    )> {
        let material = self.identity.current()?;
        let config = self.server_config(&material)?;
        let tls = tokio::time::timeout(
            Duration::from_secs(self.transport.handshake_timeout_secs),
            TlsAcceptor::from(config).accept(stream),
        )
        .await
        .map_err(|_| Error::Timeout(TimeoutPhase::Handshake))?
        .map_err(Error::Handshake)?;
        let (_, connection) = tls.get_ref();
        let peer = peer_identity(connection.peer_certificates())?;
        let stream =
            AuthenticatedStream::new(tls, self.identity.clone(), material, &peer, &self.transport)?;
        Ok((stream, peer))
    }

    fn server_config(&self, material: &Arc<WorkloadMaterial>) -> Result<Arc<rustls::ServerConfig>> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| Error::Tls("mTLS server-config cache lock is poisoned".into()))?;
        if let Some(cached) = cache.as_ref() {
            if Arc::ptr_eq(&cached.identity, material) {
                return Ok(Arc::clone(&cached.config));
            }
        }

        let alpn: Vec<_> = self.alpn.iter().map(Vec::as_slice).collect();
        let config = build_server_config(material, &alpn)?;
        let config = Arc::new(config);
        *cache = Some(CachedServerConfig {
            identity: material.clone(),
            config: Arc::clone(&config),
        });
        Ok(config)
    }
}

pub(crate) fn build_client_config(
    material: &WorkloadMaterial,
    expected_peer: &SpiffeId,
    alpn: &[&[u8]],
) -> Result<rustls::ClientConfig> {
    ensure_crypto_provider();
    material.check_valid()?;
    let roots = roots_for(material, expected_peer.trust_domain().as_ref())?;
    let verifier = exact_server_verifier(roots, expected_peer.clone())?;
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(
            certs(&material.cert_chain),
            private_key(&material.key_pkcs8),
        )
        .map_err(|error| Error::Tls(error.to_string()))?;
    config.alpn_protocols = alpn.iter().map(|value| value.to_vec()).collect();
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}

pub(crate) fn exact_server_verifier(
    roots: Arc<RootCertStore>,
    expected_peer: SpiffeId,
) -> Result<Arc<dyn ServerCertVerifier>> {
    ensure_crypto_provider();
    Ok(Arc::new(ExactServerVerifier::new(roots, expected_peer)?))
}

fn build_server_config(
    material: &WorkloadMaterial,
    alpn: &[&[u8]],
) -> Result<rustls::ServerConfig> {
    ensure_crypto_provider();
    material.check_valid()?;
    let verifier = Arc::new(ExactClientVerifier::new(material)?);
    let mut config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            certs(&material.cert_chain),
            private_key(&material.key_pkcs8),
        )
        .map_err(|error| Error::Tls(error.to_string()))?;
    config.alpn_protocols = alpn.iter().map(|value| value.to_vec()).collect();
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Ok(config)
}

fn certs(chain: &[Vec<u8>]) -> Vec<CertificateDer<'static>> {
    chain.iter().cloned().map(CertificateDer::from).collect()
}

fn private_key(bytes: &[u8]) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(bytes.to_vec()))
}

fn roots_for(material: &WorkloadMaterial, trust_domain: &str) -> Result<Arc<RootCertStore>> {
    let roots = material
        .bundles
        .get(trust_domain)
        .ok_or_else(|| PeerIdentityError::UntrustedDomain(trust_domain.to_owned()))?;
    root_store(roots)
}

pub(crate) fn root_store(roots: &[Vec<u8>]) -> Result<Arc<RootCertStore>> {
    for der in roots {
        let (remaining, parsed) =
            x509_parser::parse_x509_certificate(der).map_err(crate::material::cert_error)?;
        if !remaining.is_empty()
            || !parsed
                .basic_constraints()
                .map_err(crate::material::cert_error)?
                .is_some_and(|c| c.value.ca)
            || !parsed
                .key_usage()
                .map_err(crate::material::cert_error)?
                .is_some_and(|u| u.value.key_cert_sign())
        {
            return Err(Error::Certificate(
                "trust bundle contains a certificate without CA signing authority".into(),
            ));
        }
    }
    let mut store = RootCertStore::empty();
    let (accepted, rejected) = store.add_parsable_certificates(certs(roots));
    if accepted == 0 || rejected != 0 {
        return Err(Error::Certificate(format!(
            "trust bundle contained {accepted} usable and {rejected} invalid certificates"
        )));
    }
    Ok(Arc::new(store))
}

fn peer_identity(certs: Option<&[CertificateDer<'_>]>) -> Result<AuthenticatedPeer> {
    let leaf = certs
        .and_then(|values| values.first())
        .ok_or_else(|| Error::Tls("peer did not present a certificate".into()))?;
    let spiffe_id = spiffe::cert::spiffe_id_from_der(leaf.as_ref())
        .map_err(|error| Error::Tls(format!("invalid peer X.509-SVID: {error}")))?;
    let (_, parsed) =
        x509_parser::parse_x509_certificate(leaf).map_err(crate::material::cert_error)?;
    let expires_at_unix = parsed.validity().not_after.timestamp();
    let mut valid_until = expires_at_unix;
    for cert in certs.unwrap_or_default() {
        let (_, parsed) =
            x509_parser::parse_x509_certificate(cert).map_err(crate::material::cert_error)?;
        valid_until = valid_until.min(parsed.validity().not_after.timestamp());
    }
    Ok(AuthenticatedPeer {
        spiffe_id,
        expires_at_unix,
        valid_until,
    })
}

struct ExactServerVerifier {
    expected: SpiffeId,
    roots: Arc<RootCertStore>,
    inner: Arc<dyn ServerCertVerifier>,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ExactServerVerifier {
    fn new(roots: Arc<RootCertStore>, expected: SpiffeId) -> Result<Self> {
        let inner: Arc<dyn ServerCertVerifier> =
            rustls::client::WebPkiServerVerifier::builder(Arc::clone(&roots))
                .build()
                .map_err(|error| Error::Tls(format!("build server verifier: {error}")))?;
        let algorithms = rustls::crypto::CryptoProvider::get_default()
            .ok_or_else(|| Error::Tls("rustls crypto provider is unavailable".into()))?
            .signature_verification_algorithms;
        Ok(Self {
            expected,
            roots,
            inner,
            algorithms,
        })
    }
}

impl fmt::Debug for ExactServerVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactServerVerifier")
            .field("expected", &self.expected)
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for ExactServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let id = spiffe::cert::spiffe_id_from_der(end_entity.as_ref())
            .map_err(|error| PeerIdentityError::InvalidSvid(error.to_string()).into_rustls())?;
        if id != self.expected {
            return Err(PeerIdentityError::Mismatch {
                expected: self.expected.clone(),
                presented: id,
            }
            .into_rustls());
        }
        check_leaf(end_entity)?;
        let parsed = rustls::server::ParsedCertificate::try_from(end_entity)?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &parsed,
            &self.roots,
            intermediates,
            now,
            self.algorithms.all,
        )?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

struct ExactClientVerifier {
    verifiers: HashMap<String, Arc<dyn ClientCertVerifier>>,
}

impl ExactClientVerifier {
    fn new(material: &WorkloadMaterial) -> Result<Self> {
        let mut verifiers = HashMap::new();
        for domain in material.bundles.keys() {
            let roots = roots_for(material, domain)?;
            let verifier: Arc<dyn ClientCertVerifier> =
                rustls::server::WebPkiClientVerifier::builder(roots)
                    .build()
                    .map_err(|error| Error::Tls(format!("build client verifier: {error}")))?;
            verifiers.insert(domain.clone(), verifier);
        }
        Ok(Self { verifiers })
    }

    fn verifier_for(
        &self,
        cert: &CertificateDer<'_>,
    ) -> std::result::Result<(SpiffeId, &Arc<dyn ClientCertVerifier>), rustls::Error> {
        let id = spiffe::cert::spiffe_id_from_der(cert.as_ref())
            .map_err(|error| PeerIdentityError::InvalidSvid(error.to_string()).into_rustls())?;
        let verifier = self
            .verifiers
            .get(&id.trust_domain().to_string())
            .ok_or_else(|| {
                PeerIdentityError::UntrustedDomain(id.trust_domain().to_string()).into_rustls()
            })?;
        Ok((id, verifier))
    }
}

impl fmt::Debug for ExactClientVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactClientVerifier")
            .field("trust_domains", &self.verifiers.keys())
            .finish_non_exhaustive()
    }
}

impl ClientCertVerifier for ExactClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        let (_, verifier) = self.verifier_for(end_entity)?;
        check_leaf(end_entity)?;
        verifier.verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.verifier_for(cert)?
            .1
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.verifier_for(cert)?
            .1
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        let mut values = self
            .verifiers
            .values()
            .next()
            .map(|verifier| verifier.supported_verify_schemes())
            .unwrap_or_default();
        for verifier in self.verifiers.values().skip(1) {
            let supported = verifier.supported_verify_schemes();
            values.retain(|scheme| supported.contains(scheme));
        }
        values
    }
}

pub(crate) fn check_leaf(cert: &CertificateDer<'_>) -> std::result::Result<(), rustls::Error> {
    let invalid = |reason: String| PeerIdentityError::InvalidSvid(reason).into_rustls();
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|error| invalid(error.to_string()))?;
    if parsed
        .basic_constraints()
        .map_err(|error| invalid(error.to_string()))?
        .is_some_and(|constraints| constraints.value.ca)
    {
        return Err(invalid("leaf is a CA".into()));
    }
    let usage = parsed
        .key_usage()
        .map_err(|error| invalid(error.to_string()))?
        .ok_or_else(|| invalid("leaf has no key usage".into()))?;
    if !usage.value.digital_signature() || usage.value.key_cert_sign() || usage.value.crl_sign() {
        return Err(invalid("leaf has invalid key usage".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose, SanType, PKCS_ECDSA_P256_SHA256,
    };

    #[test]
    fn configs_are_cached_until_material_changes() {
        let material = test_material();
        let identity = IdentitySource::new(material.clone());
        let acceptor = identity.acceptor();

        let first = acceptor
            .server_config(&identity.current().unwrap())
            .unwrap();
        let second = acceptor
            .server_config(&identity.current().unwrap())
            .unwrap();
        let cloned = acceptor
            .clone()
            .server_config(&identity.current().unwrap())
            .unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert!(Arc::ptr_eq(&first, &cloned));

        identity.publish(material);
        assert!(Arc::ptr_eq(
            &first,
            &acceptor
                .server_config(&identity.current().unwrap())
                .unwrap()
        ));
        let connector = identity.connector();
        let before = connector
            .client_config(&identity.current().unwrap(), &identity.spiffe_id())
            .unwrap();
        assert!(Arc::ptr_eq(
            &before,
            &connector
                .client_config(&identity.current().unwrap(), &identity.spiffe_id())
                .unwrap()
        ));
        identity.publish(test_material());
        assert!(!Arc::ptr_eq(
            &first,
            &acceptor
                .server_config(&identity.current().unwrap())
                .unwrap()
        ));
        assert!(!Arc::ptr_eq(
            &before,
            &connector
                .client_config(&identity.current().unwrap(), &identity.spiffe_id())
                .unwrap()
        ));
    }

    fn test_material() -> WorkloadMaterial {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca = CertifiedIssuer::self_signed(
            ca_params,
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap(),
        )
        .unwrap();

        let spiffe_id: SpiffeId = "spiffe://internal/service/server".try_into().unwrap();
        let mut leaf_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        leaf_params.subject_alt_names =
            vec![SanType::URI(spiffe_id.to_string().try_into().unwrap())];
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &ca).unwrap();

        WorkloadMaterial::from_der(
            &spiffe_id,
            vec![leaf.der().to_vec()],
            leaf_key.serialize_der(),
            std::collections::BTreeMap::from([("internal".into(), vec![ca.der().to_vec()])]),
        )
        .unwrap()
    }
}
