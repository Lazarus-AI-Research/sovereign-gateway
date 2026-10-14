use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::config::{Config, IdentityProviderConfig};
use crate::error::{io, Error, Result};
use crate::material::WorkloadMaterial;
use crate::status::StatusPublisher;
use crate::{EmbeddedAgent, IdentitySource, IdentityStatus, MtlsAcceptor, MtlsConnector, SpiffeId};

/// Own this handle for the lifetime of the service. Dropping it stops refresh
/// and invalidates its transport handles; use shutdown() to await completion.
pub struct IdentityRuntime {
    config: Config,
    identity: IdentitySource,
    agent: Option<EmbeddedAgent>,
    status: StatusPublisher,
    cancel: CancellationToken,
    task: Option<JoinHandle<()>>,
    expiry_task: Option<JoinHandle<()>>,
    reload_lock: Arc<tokio::sync::Mutex<()>>,
}

impl IdentityRuntime {
    pub async fn start(config: Config) -> Result<Self> {
        config.validate()?;
        let expected: SpiffeId = config
            .identity
            .spiffe_id
            .as_str()
            .try_into()
            .map_err(|e| Error::Config(format!("invalid local SPIFFE ID: {e}")))?;
        let cancel = CancellationToken::new();
        let reload_lock = Arc::new(tokio::sync::Mutex::new(()));
        let (identity, agent, task, status) = match &config.identity.source {
            IdentityProviderConfig::Files {
                directory,
                poll_interval_secs,
            } => {
                let directory = directory.clone();
                let identity =
                    IdentitySource::new(load_files(directory.clone(), expected.clone()).await?);
                let status = StatusPublisher::new("files", identity.clone());
                let state = status.clone();
                let stop = cancel.clone();
                let lock = reload_lock.clone();
                let interval = Duration::from_secs(*poll_interval_secs);
                let task = tokio::spawn(async move {
                    loop {
                        tokio::select! { _ = stop.cancelled() => break, _ = tokio::time::sleep(interval) => {} }
                        let result = tokio::select! {
                            biased;
                            () = stop.cancelled() => break,
                            result = async {
                                let _guard = lock.lock().await;
                                let result = load_files(directory.clone(), expected.clone()).await;
                                state.record_reload(result)
                            } => result,
                        };
                        match &result {
                            Ok(_) => {}
                            Err(e) => {
                                tracing::warn!(error = %e, "credential reload failed; retaining last valid generation")
                            }
                        }
                    }
                });
                (identity, None, Some(task), status)
            }
            IdentityProviderConfig::EmbeddedSpire {
                join_token_file, ..
            } => {
                // It is normal for the one-use secret to have been removed after enrollment.
                // An absent secret is still fatal when the agent has no usable persisted state.
                let token = match join_token_file {
                    Some(path) => match std::fs::canonicalize(path)
                        .map_err(|e| io(path, e))
                        .and_then(|resolved| read_file(&resolved, true))
                    {
                        Ok(bytes) => {
                            let text = std::str::from_utf8(&bytes)
                                .map_err(|_| Error::Config("join token must be UTF-8".into()))?;
                            Some(text.trim().to_owned())
                        }
                        Err(Error::Io { source, .. })
                            if source.kind() == std::io::ErrorKind::NotFound =>
                        {
                            None
                        }
                        Err(e) => return Err(e),
                    },
                    None => None,
                };
                let agent = EmbeddedAgent::start(config.agent_config(token)?).await?;
                let status = agent.status_publisher();
                (agent.identity_source(), Some(agent), None, status)
            }
        };
        let expiry_task = tokio::spawn(status.clone().monitor_expiry(cancel.clone()));
        Ok(Self {
            config,
            identity,
            agent,
            status,
            cancel,
            task,
            expiry_task: Some(expiry_task),
            reload_lock,
        })
    }

    pub fn identity_source(&self) -> IdentitySource {
        self.identity.clone()
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn connector(&self) -> MtlsConnector {
        self.identity
            .connector()
            .with_transport(self.config.transport.clone())
            .expect("validated configuration")
    }
    pub fn acceptor(&self) -> MtlsAcceptor {
        self.identity
            .acceptor()
            .with_transport(self.config.transport.clone())
            .expect("validated configuration")
    }

    #[cfg(feature = "http")]
    pub fn http_client(&self, peer: &str) -> Result<crate::HttpClient> {
        let destination = self
            .config
            .peers
            .get(peer)
            .ok_or_else(|| Error::Config(format!("unknown outbound peer {peer}")))?;
        crate::HttpClient::new(
            self.identity.clone(),
            destination.clone(),
            self.config.transport.clone(),
        )
    }

    /// Reload file credentials immediately, for example from a SIGHUP handler.
    /// Provider selection and expected local identity are fixed for this runtime.
    pub async fn reload(&self) -> Result<()> {
        if self.cancel.is_cancelled() {
            return Err(Error::Stopped);
        }
        let IdentityProviderConfig::Files { directory, .. } = &self.config.identity.source else {
            return Err(Error::Config(
                "embedded SPIRE manages its own refresh".into(),
            ));
        };
        let _guard = self.reload_lock.lock().await;
        let result = load_files(directory.clone(), self.identity.spiffe_id()).await;
        self.status.record_reload(result)
    }

    /// Current usability and refresh health. Failed refreshes preserve usable
    /// last-known-good credentials; expiration or shutdown makes them unusable.
    pub async fn status(&self) -> IdentityStatus {
        self.status.snapshot()
    }

    /// Subscribe to the current status and subsequent refresh, expiration, and
    /// shutdown updates, for either provider. An expiry timer runs independently
    /// of refresh attempts. Slow receivers may coalesce updates: this is a latest
    /// state channel, not an audit log. Clone the borrowed value before awaiting.
    ///
    /// Applications own admission lead times: rearm their timer against
    /// `valid_until_unix` whenever a new identity is published. `ready`/`usable`
    /// report actual credential usability, not an application-specific lead time.
    pub fn watch(&self) -> watch::Receiver<IdentityStatus> {
        self.status.watch()
    }

    pub async fn shutdown(&mut self) {
        self.cancel.cancel();
        self.status.stop();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.expiry_task.take() {
            let _ = task.await;
        }
        if let Some(agent) = &self.agent {
            agent.shutdown().await;
        }
    }
}

impl Drop for IdentityRuntime {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.status.stop();
        if let Some(task) = &self.task {
            task.abort();
        }
        if let Some(task) = &self.expiry_task {
            task.abort();
        }
        if let Some(agent) = &self.agent {
            agent.request_shutdown();
        }
    }
}

async fn load_files(directory: std::path::PathBuf, expected: SpiffeId) -> Result<WorkloadMaterial> {
    tokio::task::spawn_blocking(move || {
        let directory = std::fs::canonicalize(&directory).map_err(|e| io(&directory, e))?;
        let resolve = |name: &str| {
            let path = directory.join(name);
            std::fs::canonicalize(&path).map_err(|e| io(path, e))
        };
        // Resolve each projected-volume symlink before opening any files. A
        // concurrent Kubernetes ..data switch produces different parents and
        // is rejected instead of combining generations. Never edit a generation in place.
        let key = resolve("key.pem")?;
        let chain = resolve("cert-chain.pem")?;
        let bundle = resolve("bundle.pem")?;
        if key.parent() != chain.parent() || key.parent() != bundle.parent() {
            return Err(Error::Certificate(
                "credential files do not belong to one generation".into(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let parent = key.parent().expect("credential file has parent");
            let metadata = std::fs::metadata(parent).map_err(|e| io(parent, e))?;
            if metadata.permissions().mode() & 0o022 != 0 {
                return Err(Error::UnsafeState(
                    "credential generation directory permits group or other writes".into(),
                ));
            }
        }
        WorkloadMaterial::from_pem(
            &expected,
            &read_file(&chain, false)?,
            &read_file(&key, true)?,
            &read_file(&bundle, false)?,
        )
    })
    .await
    .map_err(|e| Error::Transport(format!("credential loader failed: {e}")))?
}

pub(crate) fn read_file(path: &Path, private: bool) -> Result<Zeroizing<Vec<u8>>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|e| io(path, e))?;
    let metadata = file.metadata().map_err(|e| io(path, e))?;
    if !metadata.is_file() {
        return Err(Error::UnsafeState(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Permit root-owned Kubernetes volumes with a dedicated fsGroup; reject
        // world access and group writes. Installer-generated keys use 0600.
        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 || (private && mode & 0o007 != 0) {
            return Err(Error::UnsafeState(format!(
                "{} permits other-user access or group writes",
                path.display()
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = private;
    const LIMIT: u64 = 4 * 1024 * 1024;
    let mut data = Zeroizing::new(Vec::new());
    file.take(LIMIT + 1)
        .read_to_end(&mut data)
        .map_err(|e| io(path, e))?;
    if data.len() as u64 > LIMIT {
        return Err(Error::Certificate("credential file exceeds 4 MiB".into()));
    }
    Ok(data)
}
