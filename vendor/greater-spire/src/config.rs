use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use spiffe::{SpiffeId, TrustDomain};

use crate::error::{io, Error, Result};

/// Configuration owned by greater-spire. Application authorization does not belong here.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub identity: IdentityConfig,
    #[serde(default)]
    pub transport: TransportConfig,
    #[serde(default)]
    pub peers: std::collections::BTreeMap<String, PeerConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    pub spiffe_id: String,
    pub source: IdentityProviderConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentityProviderConfig {
    Files {
        /// One generation containing cert-chain.pem, key.pem, and bundle.pem.
        directory: PathBuf,
        #[serde(default = "default_poll_interval")]
        poll_interval_secs: u64,
    },
    EmbeddedSpire {
        server_address: String,
        bootstrap_bundle_path: PathBuf,
        state_dir: PathBuf,
        #[serde(default)]
        join_token_file: Option<PathBuf>,
        #[serde(default)]
        expected_selectors: Vec<Selector>,
        #[serde(default = "default_sync_interval_secs")]
        sync_interval_secs: u64,
        #[serde(default = "default_rotate_before_secs")]
        rotate_before_secs: u64,
        #[serde(default = "default_rpc_timeout_secs")]
        rpc_timeout_secs: u64,
    },
}

fn default_poll_interval() -> u64 {
    5
}
fn default_handshake_timeout() -> u64 {
    10
}
fn default_connection_age() -> u64 {
    300
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportConfig {
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout_secs: u64,
    #[serde(default = "default_connection_age")]
    pub max_connection_age_secs: u64,
    #[serde(default = "default_rpc_timeout_secs")]
    pub request_timeout_secs: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            handshake_timeout_secs: 10,
            max_connection_age_secs: 300,
            request_timeout_secs: 30,
        }
    }
}

impl TransportConfig {
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("handshake_timeout_secs", self.handshake_timeout_secs),
            ("max_connection_age_secs", self.max_connection_age_secs),
            ("request_timeout_secs", self.request_timeout_secs),
        ] {
            if value == 0 || value > 86_400 {
                return Err(Error::Config(format!("{name} must be between 1 and 86400")));
            }
        }
        Ok(())
    }
}

/// An outbound transport destination and its required authenticated identity.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub url: String,
    pub spiffe_id: String,
}

impl PeerConfig {
    pub fn validate(&self) -> Result<()> {
        let _: SpiffeId = self
            .spiffe_id
            .as_str()
            .try_into()
            .map_err(|e| Error::Config(format!("invalid peer SPIFFE ID: {e}")))?;
        let uri: http::Uri = self
            .url
            .parse()
            .map_err(|e| Error::Config(format!("invalid peer URL: {e}")))?;
        if uri.scheme_str() != Some("https")
            || uri.host().is_none_or(str::is_empty)
            || uri.authority().is_some_and(|a| a.as_str().contains('@'))
            || uri.path_and_query().is_some_and(|p| p.as_str() != "/")
        {
            return Err(Error::Config(
                "peer URL must be an https origin without credentials, path, or query".into(),
            ));
        }
        let authority = uri.authority().expect("validated authority").as_str();
        let host = uri.host().expect("validated host");
        if authority != host && uri.port_u16().is_none_or(|port| port == 0) {
            return Err(Error::Config("peer URL has an invalid port".into()));
        }
        Ok(())
    }
}

impl Config {
    /// Explicit path, then GREATER_SPIRE_CONFIG, then /etc/greater-spire/<service>.toml.
    pub fn load(service: &str, explicit: Option<&Path>) -> Result<Self> {
        if service.is_empty()
            || !service
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(Error::Config(
                "invalid service name for configuration discovery".into(),
            ));
        }
        let path = explicit
            .map(Path::to_owned)
            .or_else(|| std::env::var_os("GREATER_SPIRE_CONFIG").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(format!("/etc/greater-spire/{service}.toml")));
        Self::from_file(path)
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|e| io(path, e))?;
        let base = std::fs::canonicalize(path)
            .map_err(|e| io(path, e))?
            .parent()
            .expect("file has parent")
            .to_owned();
        Self::from_toml(&text, base).map_err(|e| Error::Config(format!("{}: {e}", path.display())))
    }

    /// Parse with an explicit base directory for relative credential paths.
    pub fn from_toml(text: &str, base: impl AsRef<Path>) -> Result<Self> {
        let mut config: Self = toml::from_str(text).map_err(|e| Error::Config(e.to_string()))?;
        let resolve = |p: &mut PathBuf| {
            if p.is_relative() {
                *p = base.as_ref().join(&*p);
            }
        };
        match &mut config.identity.source {
            IdentityProviderConfig::Files { directory, .. } => resolve(directory),
            IdentityProviderConfig::EmbeddedSpire {
                bootstrap_bundle_path,
                state_dir,
                join_token_file,
                ..
            } => {
                resolve(bootstrap_bundle_path);
                resolve(state_dir);
                if let Some(path) = join_token_file {
                    resolve(path);
                }
            }
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Config(format!(
                "unsupported config version {}",
                self.version
            )));
        }
        let _: SpiffeId = self
            .identity
            .spiffe_id
            .as_str()
            .try_into()
            .map_err(|e| Error::Config(format!("invalid local SPIFFE ID: {e}")))?;
        self.transport.validate()?;
        match &self.identity.source {
            IdentityProviderConfig::Files {
                directory,
                poll_interval_secs,
            } => {
                if directory.as_os_str().is_empty()
                    || *poll_interval_secs == 0
                    || *poll_interval_secs > 86400
                {
                    return Err(Error::Config("files provider requires a directory and poll interval between 1 and 86400 seconds".into()));
                }
            }
            IdentityProviderConfig::EmbeddedSpire { .. } => {
                self.agent_config(None)?.validate()?;
            }
        }
        for (name, peer) in &self.peers {
            if name.is_empty() {
                return Err(Error::Config("peer name cannot be empty".into()));
            }
            peer.validate()?;
        }
        Ok(())
    }

    pub(crate) fn agent_config(&self, join_token: Option<String>) -> Result<AgentConfig> {
        let IdentityProviderConfig::EmbeddedSpire {
            server_address,
            bootstrap_bundle_path,
            state_dir,
            expected_selectors,
            sync_interval_secs,
            rotate_before_secs,
            rpc_timeout_secs,
            ..
        } = &self.identity.source
        else {
            return Err(Error::Config(
                "identity provider is not embedded_spire".into(),
            ));
        };
        let id: SpiffeId = self
            .identity
            .spiffe_id
            .as_str()
            .try_into()
            .map_err(|e| Error::Config(format!("invalid local SPIFFE ID: {e}")))?;
        Ok(AgentConfig {
            server_address: server_address.clone(),
            trust_domain: id.trust_domain().to_string(),
            bootstrap_bundle_path: bootstrap_bundle_path.clone(),
            state_dir: state_dir.clone(),
            join_token,
            workload_spiffe_id: id.to_string(),
            expected_selectors: expected_selectors.clone(),
            sync_interval_secs: *sync_interval_secs,
            rotate_before_secs: *rotate_before_secs,
            rpc_timeout_secs: *rpc_timeout_secs,
        })
    }
}

fn default_sync_interval_secs() -> u64 {
    30
}

fn default_rotate_before_secs() -> u64 {
    300
}

fn default_rpc_timeout_secs() -> u64 {
    30
}

/// A SPIRE selector as stored on a registration entry.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
pub struct Selector {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
}

/// Configuration for one embedded agent instance.
///
/// A deployment should create a join token with an explicit, stable agent ID and
/// register `workload_spiffe_id` beneath that agent. The join token is consumed
/// only when no usable state exists and is never persisted by this library.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// Stock SPIRE Server gRPC address, for example `127.0.0.1:8081`.
    pub server_address: String,
    /// SPIFFE trust domain, for example `internal`.
    pub trust_domain: String,
    /// PEM trust bundle used to authenticate the SPIRE Server during bootstrap.
    pub bootstrap_bundle_path: PathBuf,
    /// Root-private directory holding the agent SVID, key, and refreshed bundle.
    pub state_dir: PathBuf,
    /// One-time join token. Required only for first boot or disaster recovery.
    #[serde(default)]
    pub join_token: Option<String>,
    /// Exact workload SPIFFE ID this process is allowed to mint.
    pub workload_spiffe_id: String,
    /// Optional exact selector set used to disambiguate multiple entries for one ID.
    #[serde(default)]
    pub expected_selectors: Vec<Selector>,
    #[serde(default = "default_sync_interval_secs")]
    pub sync_interval_secs: u64,
    #[serde(default = "default_rotate_before_secs")]
    pub rotate_before_secs: u64,
    #[serde(default = "default_rpc_timeout_secs")]
    pub rpc_timeout_secs: u64,
}

impl fmt::Debug for AgentConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentConfig")
            .field("server_address", &self.server_address)
            .field("trust_domain", &self.trust_domain)
            .field("bootstrap_bundle_path", &self.bootstrap_bundle_path)
            .field("state_dir", &self.state_dir)
            .field(
                "join_token",
                &self.join_token.as_ref().map(|_| "<redacted>"),
            )
            .field("workload_spiffe_id", &self.workload_spiffe_id)
            .field("expected_selectors", &self.expected_selectors)
            .field("sync_interval_secs", &self.sync_interval_secs)
            .field("rotate_before_secs", &self.rotate_before_secs)
            .field("rpc_timeout_secs", &self.rpc_timeout_secs)
            .finish()
    }
}

impl AgentConfig {
    pub fn from_toml_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|error| io(path, error))?;
        let config: Self = toml::from_str(&text)
            .map_err(|error| Error::Config(format!("{}: {error}", path.display())))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.server_address.trim().is_empty() {
            return Err(Error::Config("server_address is empty".into()));
        }
        let trust_domain: TrustDomain = self
            .trust_domain
            .as_str()
            .try_into()
            .map_err(|error| Error::Config(format!("invalid trust_domain: {error}")))?;
        let workload: SpiffeId = self
            .workload_spiffe_id
            .as_str()
            .try_into()
            .map_err(|error| Error::Config(format!("invalid workload_spiffe_id: {error}")))?;
        if workload.trust_domain() != &trust_domain {
            return Err(Error::Config(format!(
                "workload_spiffe_id belongs to {}, not configured trust domain {}",
                workload.trust_domain(),
                trust_domain
            )));
        }
        if self.sync_interval_secs == 0 {
            return Err(Error::Config("sync_interval_secs must be positive".into()));
        }
        if self.rpc_timeout_secs == 0 {
            return Err(Error::Config("rpc_timeout_secs must be positive".into()));
        }
        if self.join_token.as_deref().is_some_and(str::is_empty) {
            return Err(Error::Config("join_token cannot be empty".into()));
        }
        for selector in &self.expected_selectors {
            if selector.kind.is_empty() || selector.value.is_empty() {
                return Err(Error::Config(
                    "expected selector type and value must be non-empty".into(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn sync_interval(&self) -> Duration {
        Duration::from_secs(self.sync_interval_secs)
    }

    pub(crate) fn rotate_before(&self) -> Duration {
        Duration::from_secs(self.rotate_before_secs)
    }

    pub(crate) fn rpc_timeout(&self) -> Duration {
        Duration::from_secs(self.rpc_timeout_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_join_token() {
        let config = AgentConfig {
            server_address: "127.0.0.1:8081".into(),
            trust_domain: "internal".into(),
            bootstrap_bundle_path: "bundle.pem".into(),
            state_dir: "state".into(),
            join_token: Some("do-not-print".into()),
            workload_spiffe_id: "spiffe://internal/service/scribe".into(),
            expected_selectors: Vec::new(),
            sync_interval_secs: 30,
            rotate_before_secs: 300,
            rpc_timeout_secs: 30,
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains("do-not-print"));
        assert!(debug.contains("<redacted>"));
    }
}
