use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use http::{HeaderMap, HeaderName};
use serde::Deserialize;
use spiffe::SpiffeId;

use crate::error::{io, Error, Result};

pub const DELEGATED_USER_HEADER: HeaderName = HeaderName::from_static("x-delegated-user");
const MAX_DELEGATED_USER_BYTES: usize = 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ServerPolicy {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ServicePolicy {
    pub name: String,
    pub spiffe_id: String,
    #[serde(default)]
    pub may_delegate_user: bool,
    #[serde(default)]
    pub may_sync_acls: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    #[serde(default)]
    server: Option<ServerPolicy>,
    #[serde(default)]
    services: Vec<ServicePolicy>,
}

#[derive(Clone, Debug)]
pub struct Policy {
    server: Option<ServerPolicy>,
    by_id: HashMap<String, ServicePolicy>,
}

impl Policy {
    pub fn from_toml(text: &str) -> Result<Self> {
        let document: PolicyDocument =
            toml::from_str(text).map_err(|error| Error::Config(error.to_string()))?;
        let mut by_id = HashMap::new();
        let mut names = HashSet::new();
        for service in document.services {
            let id: SpiffeId = service.spiffe_id.as_str().try_into().map_err(|error| {
                Error::Config(format!(
                    "service {} has invalid spiffe_id: {error}",
                    service.name
                ))
            })?;
            if service.name.trim().is_empty() {
                return Err(Error::Config("service name cannot be empty".into()));
            }
            if !names.insert(service.name.clone()) {
                return Err(Error::Config(format!(
                    "duplicate service name {}",
                    service.name
                )));
            }
            if by_id.insert(id.to_string(), service).is_some() {
                return Err(Error::Config(format!("duplicate service SPIFFE ID {id}")));
            }
        }
        Ok(Self {
            server: document.server,
            by_id,
        })
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|error| io(path, error))?;
        Self::from_toml(&text)
            .map_err(|error| Error::Config(format!("{}: {error}", path.display())))
    }

    pub fn server(&self) -> Option<&ServerPolicy> {
        self.server.as_ref()
    }

    pub fn allowed_spiffe_ids(&self) -> Vec<SpiffeId> {
        self.by_id
            .keys()
            .map(|id| {
                id.as_str()
                    .try_into()
                    .expect("validated when policy was loaded")
            })
            .collect()
    }

    pub fn service(&self, peer: &SpiffeId) -> Option<&ServicePolicy> {
        self.by_id.get(&peer.to_string())
    }

    /// Resolve a TLS-authenticated machine and optional delegated-user header.
    ///
    /// This authorizes which machine may assert delegation. It does not prove the
    /// human grant. The receiving service must resolve the returned opaque user key
    /// through SSO/IAM and enforce its own resource ACLs.
    pub fn authorize(
        &self,
        peer: &SpiffeId,
        headers: &HeaderMap,
    ) -> std::result::Result<Caller, PolicyError> {
        let service = self
            .service(peer)
            .ok_or_else(|| PolicyError::UnknownService(peer.to_string()))?;
        let delegated_user = match headers.get(&DELEGATED_USER_HEADER) {
            None => None,
            Some(value) => {
                if !service.may_delegate_user {
                    return Err(PolicyError::DelegationForbidden(service.name.clone()));
                }
                let value = value
                    .to_str()
                    .map_err(|_| PolicyError::InvalidDelegatedUser)?;
                validate_delegated_user(value)?;
                Some(value.to_owned())
            }
        };
        Ok(Caller {
            service_name: service.name.clone(),
            spiffe_id: peer.clone(),
            delegated_user,
            may_sync_acls: service.may_sync_acls,
        })
    }
}

fn validate_delegated_user(value: &str) -> std::result::Result<(), PolicyError> {
    if value.is_empty()
        || value.len() > MAX_DELEGATED_USER_BYTES
        || value.trim() != value
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(PolicyError::InvalidDelegatedUser);
    }
    let Some(separator) = value.find(':') else {
        return Err(PolicyError::InvalidDelegatedUser);
    };
    if separator == 0 || separator + 1 == value.len() {
        return Err(PolicyError::InvalidDelegatedUser);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Caller {
    pub service_name: String,
    pub spiffe_id: SpiffeId,
    /// Opaque `<issuer>:<external_id>` asserted by the authenticated service.
    pub delegated_user: Option<String>,
    pub may_sync_acls: bool,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum PolicyError {
    #[error("unknown machine identity {0}")]
    UnknownService(String),
    #[error("service {0} may not delegate a user")]
    DelegationForbidden(String),
    #[error("X-Delegated-User must be a bounded, visible <issuer>:<external_id> value")]
    InvalidDelegatedUser,
}

/// Atomically reloadable policy. Existing requests keep their resolved caller;
/// new TLS handshakes and requests observe the new snapshot.
#[derive(Clone, Debug)]
pub struct PolicyStore(Arc<ArcSwap<Policy>>);

impl PolicyStore {
    pub fn new(policy: Policy) -> Self {
        Self(Arc::new(ArcSwap::from_pointee(policy)))
    }

    pub fn current(&self) -> Arc<Policy> {
        self.0.load_full()
    }

    pub fn replace(&self, policy: Policy) {
        self.0.store(Arc::new(policy));
    }

    pub fn reload_file(&self, path: impl AsRef<Path>) -> Result<()> {
        self.replace(Policy::from_file(path)?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    const DOCUMENT: &str = r#"
[server]
host = "127.0.0.1"
port = 9090

[[services]]
name = "product-server-a"
spiffe_id = "spiffe://internal/service/product-server-a"
may_delegate_user = true
may_sync_acls = true

[[services]]
name = "analytics-worker"
spiffe_id = "spiffe://internal/service/analytics-worker"
"#;

    #[test]
    fn delegation_is_bound_to_authenticated_service_policy() {
        let policy = Policy::from_toml(DOCUMENT).unwrap();
        assert_eq!(
            policy.server(),
            Some(&ServerPolicy {
                host: "127.0.0.1".into(),
                port: 9090,
            })
        );
        let product: SpiffeId = "spiffe://internal/service/product-server-a"
            .try_into()
            .unwrap();
        let analytics: SpiffeId = "spiffe://internal/service/analytics-worker"
            .try_into()
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            &DELEGATED_USER_HEADER,
            HeaderValue::from_static("sso:user-123"),
        );

        let caller = policy.authorize(&product, &headers).unwrap();
        assert_eq!(caller.delegated_user.as_deref(), Some("sso:user-123"));
        assert!(caller.may_sync_acls);
        assert_eq!(
            policy.authorize(&analytics, &headers),
            Err(PolicyError::DelegationForbidden("analytics-worker".into()))
        );
    }

    #[test]
    fn unknown_machine_is_rejected() {
        let policy = Policy::from_toml(DOCUMENT).unwrap();
        let peer: SpiffeId = "spiffe://internal/service/intruder".try_into().unwrap();
        assert!(matches!(
            policy.authorize(&peer, &HeaderMap::new()),
            Err(PolicyError::UnknownService(_))
        ));
    }

    #[test]
    fn server_binding_is_optional() {
        let policy = Policy::from_toml(
            r#"
[[services]]
name = "product-server-a"
spiffe_id = "spiffe://internal/service/product-server-a"
"#,
        )
        .unwrap();

        assert!(policy.server().is_none());
        assert_eq!(policy.allowed_spiffe_ids().len(), 1);
    }
}
