use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::error::{io, Error, Result};

const STATE_VERSION: u32 = 1;
const STATE_FILE: &str = "agent-state.json";
const MAX_STATE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct NodeState {
    pub trust_domain: String,
    pub agent_id: String,
    pub key_pkcs8: Vec<u8>,
    pub cert_chain: Vec<Vec<u8>>,
    pub expires_at: i64,
    pub reattestable: bool,
    pub bundle_sequence: u64,
    pub bundle: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskState {
    version: u32,
    trust_domain: String,
    agent_id: String,
    key_pkcs8: String,
    cert_chain: Vec<String>,
    expires_at: i64,
    reattestable: bool,
    bundle_sequence: u64,
    bundle: Vec<String>,
}

impl From<&NodeState> for DiskState {
    fn from(value: &NodeState) -> Self {
        Self {
            version: STATE_VERSION,
            trust_domain: value.trust_domain.clone(),
            agent_id: value.agent_id.clone(),
            key_pkcs8: STANDARD.encode(&value.key_pkcs8),
            cert_chain: value
                .cert_chain
                .iter()
                .map(|der| STANDARD.encode(der))
                .collect(),
            expires_at: value.expires_at,
            reattestable: value.reattestable,
            bundle_sequence: value.bundle_sequence,
            bundle: value
                .bundle
                .iter()
                .map(|der| STANDARD.encode(der))
                .collect(),
        }
    }
}

impl TryFrom<DiskState> for NodeState {
    type Error = Error;

    fn try_from(value: DiskState) -> Result<Self> {
        if value.version != STATE_VERSION {
            return Err(Error::UnsafeState(format!(
                "unsupported state version {}",
                value.version
            )));
        }
        let decode = |label: &str, encoded: &str| {
            STANDARD
                .decode(encoded)
                .map_err(|error| Error::UnsafeState(format!("invalid {label}: {error}")))
        };
        let cert_chain = value
            .cert_chain
            .iter()
            .map(|item| decode("certificate", item))
            .collect::<Result<Vec<_>>>()?;
        let bundle = value
            .bundle
            .iter()
            .map(|item| decode("bundle certificate", item))
            .collect::<Result<Vec<_>>>()?;
        if cert_chain.is_empty() || bundle.is_empty() {
            return Err(Error::UnsafeState(
                "state must contain an agent certificate and trust bundle".into(),
            ));
        }
        Ok(Self {
            trust_domain: value.trust_domain,
            agent_id: value.agent_id,
            key_pkcs8: decode("private key", &value.key_pkcs8)?,
            cert_chain,
            expires_at: value.expires_at,
            reattestable: value.reattestable,
            bundle_sequence: value.bundle_sequence,
            bundle,
        })
    }
}

#[derive(Debug)]
pub(crate) struct StateStore {
    dir: PathBuf,
    path: PathBuf,
}

impl StateStore {
    pub fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir).map_err(|error| io(dir, error))?;
        set_private_dir_permissions(dir)?;
        let path = dir.join(STATE_FILE);
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(Error::UnsafeState(format!(
                    "{} is not a regular file",
                    path.display()
                )));
            }
            check_private_file_permissions(&path, &metadata)?;
        }
        Ok(Self {
            dir: dir.to_owned(),
            path,
        })
    }

    pub fn load(&self) -> Result<Option<NodeState>> {
        let mut file = match OpenOptions::new().read(true).open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io(&self.path, error)),
        };
        let metadata = file.metadata().map_err(|error| io(&self.path, error))?;
        check_private_file_permissions(&self.path, &metadata)?;
        if metadata.len() > MAX_STATE_BYTES {
            return Err(Error::UnsafeState(format!(
                "{} exceeds the {} byte limit",
                self.path.display(),
                MAX_STATE_BYTES
            )));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)
            .map_err(|error| io(&self.path, error))?;
        let disk: DiskState = serde_json::from_slice(&bytes)?;
        Ok(Some(disk.try_into()?))
    }

    pub fn save(&self, state: &NodeState) -> Result<()> {
        let bytes = serde_json::to_vec(&DiskState::from(state))?;
        let temporary = self
            .dir
            .join(format!(".{STATE_FILE}.{}.tmp", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        set_private_open_permissions(&mut options);
        let mut file = options
            .open(&temporary)
            .map_err(|error| io(&temporary, error))?;
        file.write_all(&bytes)
            .map_err(|error| io(&temporary, error))?;
        file.sync_all().map_err(|error| io(&temporary, error))?;
        fs::rename(&temporary, &self.path).map_err(|error| io(&self.path, error))?;
        sync_directory(&self.dir)?;
        Ok(())
    }
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| io(path, error))
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_open_permissions(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_open_permissions(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn check_private_file_permissions(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    if metadata.mode() & 0o077 != 0 {
        return Err(Error::UnsafeState(format!(
            "{} must not be accessible by group or other users",
            path.display()
        )));
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(Error::UnsafeState(format!(
            "{} is not owned by the current user",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_file_permissions(_path: &Path, _metadata: &fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    let dir = std::fs::File::open(path).map_err(|error| io(path, error))?;
    dir.sync_all().map_err(|error| io(path, error))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trip() {
        let temp = tempfile::tempdir().unwrap();
        let store = StateStore::open(temp.path()).unwrap();
        let state = NodeState {
            trust_domain: "internal".into(),
            agent_id: "spiffe://internal/spire/agent/test".into(),
            key_pkcs8: vec![1, 2, 3],
            cert_chain: vec![vec![4, 5]],
            expires_at: 42,
            reattestable: false,
            bundle_sequence: 7,
            bundle: vec![vec![8, 9]],
        };
        store.save(&state).unwrap();
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.agent_id, state.agent_id);
        assert_eq!(loaded.key_pkcs8, state.key_pkcs8);
        assert_eq!(loaded.bundle_sequence, 7);
    }
}
