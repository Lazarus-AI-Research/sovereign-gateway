use std::path::PathBuf;

use crate::SpiffeId;

/// The bound that elapsed, not a statement about whether a mutation committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum TimeoutPhase {
    #[error("TCP connection and TLS handshake")]
    ConnectAndHandshake,
    #[error("TLS handshake")]
    Handshake,
    #[error("HTTP request through response headers")]
    ResponseHeaders,
}

/// SPIFFE-specific authentication rejection. Certificate identities in diagnostics
/// are claims from the presented certificate, not successfully authenticated peers.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum PeerIdentityError {
    #[error("SPIFFE peer {presented} is not expected {expected}")]
    Mismatch {
        expected: SpiffeId,
        presented: SpiffeId,
    },
    #[error("invalid X.509-SVID: {0}")]
    InvalidSvid(String),
    #[error("no trust bundle for peer trust domain {0}")]
    UntrustedDomain(String),
}

impl PeerIdentityError {
    pub(crate) fn into_rustls(self) -> rustls::Error {
        rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(
            std::sync::Arc::new(self),
        )))
    }
}

/// Errors returned by identity providers and authenticated transports.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid configuration: {0}")]
    Config(String),

    #[error("I/O error at {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to encode or decode agent state: {0}")]
    StateFormat(#[from] serde_json::Error),

    #[error("agent state is unsafe: {0}")]
    UnsafeState(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("TCP connection failed: {0}")]
    Connect(#[source] std::io::Error),

    #[error("TLS handshake failed: {0}")]
    Handshake(#[source] std::io::Error),

    #[error("timed out during {0}")]
    Timeout(#[source] TimeoutPhase),

    #[error(transparent)]
    PeerIdentity(#[from] PeerIdentityError),

    #[error("authenticated connection lifetime ended")]
    ConnectionExpired,

    #[error("trust bundle changed; reconnect")]
    TrustChanged,

    #[error("SPIRE connection failed: {0}")]
    SpireTransport(#[source] tonic::transport::Error),

    #[cfg(feature = "http")]
    #[error("HTTP request failed: {0}")]
    HttpRequest(#[source] hyper_util::client::legacy::Error),

    #[cfg(feature = "http")]
    #[error("HTTP connection failed: {0}")]
    HttpConnection(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[cfg(feature = "http")]
    #[error("HTTP handler failed: {0}")]
    HttpService(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("SPIRE RPC failed: {0}")]
    Rpc(#[from] tonic::Status),

    #[error("SPIRE returned an invalid response: {0}")]
    Protocol(String),

    #[error("certificate operation failed: {0}")]
    Certificate(String),

    #[error("TLS operation failed: {0}")]
    Tls(String),

    #[error("no registration entry for workload {0}")]
    WorkloadEntryNotFound(String),

    #[error("multiple registration entries match workload {0}; configure expected_selectors")]
    AmbiguousWorkloadEntry(String),

    #[error("the current agent SVID has expired and cannot be renewed; issue a new join token")]
    AgentIdentityExpired,

    #[error("the workload identity has expired or is not yet valid")]
    IdentityExpired,

    #[error("identity runtime stopped")]
    Stopped,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Find a typed cause without parsing diagnostic text, including this error.
    /// Also visits I/O payloads and rustls custom certificate errors, which their
    /// standard `source()` implementations do not consistently expose.
    ///
    /// Examples: `PeerIdentityError`, `TimeoutPhase`, `rustls::Error`, or
    /// `std::io::Error`. Classification is diagnostic, never permission to retry
    /// a mutation: an HTTP failure or timeout can have an indeterminate outcome.
    pub fn find_cause<T: std::error::Error + 'static>(&self) -> Option<&T> {
        self.causes().find_map(|cause| cause.downcast_ref::<T>())
    }

    /// Walk this error and its underlying causes, including I/O/rustls payloads.
    /// Use this when several layers can contain the same error type. Traversal
    /// stops after 64 entries to tolerate cyclic third-party error implementations.
    pub fn causes(&self) -> impl Iterator<Item = &(dyn std::error::Error + 'static)> {
        let mut next: Option<&(dyn std::error::Error + 'static)> = Some(self);
        std::iter::from_fn(move || {
            let current = next?;
            next = if let Some(error) = current.downcast_ref::<std::io::Error>() {
                error
                    .get_ref()
                    .map(|cause| cause as &dyn std::error::Error)
                    .or_else(|| current.source())
            } else if let Some(error) = current.downcast_ref::<rustls::Error>() {
                match error {
                    rustls::Error::InvalidCertificate(rustls::CertificateError::Other(other))
                    | rustls::Error::Other(other) => {
                        Some(other.0.as_ref() as &dyn std::error::Error)
                    }
                    _ => current.source(),
                }
            } else if let Some(Self::PeerIdentity(error)) = current.downcast_ref::<Self>() {
                Some(error as &dyn std::error::Error)
            } else {
                current.source()
            };
            Some(current)
        })
        .take(64)
    }
}

pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Error {
    Error::Io {
        path: path.into(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cause_iterator_keeps_nested_library_errors_and_transparent_peer_errors() {
        let error = Error::Handshake(std::io::Error::other(Error::Stopped));
        assert!(error
            .causes()
            .any(|cause| matches!(cause.downcast_ref::<Error>(), Some(Error::Stopped))));
        let error = Error::PeerIdentity(PeerIdentityError::UntrustedDomain("other.test".into()));
        assert!(matches!(
            error.find_cause::<PeerIdentityError>(),
            Some(PeerIdentityError::UntrustedDomain(_))
        ));
    }

    #[derive(Debug)]
    struct CyclicError;
    impl std::fmt::Display for CyclicError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("cycle")
        }
    }
    impl std::error::Error for CyclicError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(self)
        }
    }

    #[test]
    fn third_party_cycles_cannot_make_diagnostics_loop_forever() {
        let error = Error::Handshake(std::io::Error::other(CyclicError));
        assert_eq!(error.causes().count(), 64);
        assert!(error.find_cause::<PeerIdentityError>().is_none());
    }
}
