use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::material::{unix_now, WorkloadMaterial};
use crate::{Error, IdentitySource, Result, SpiffeId};

/// Refresh health, independent of whether the current credentials are usable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RefreshStatus {
    Ok,
    Error {
        /// Most recent refresh error.
        error: String,
        /// Start of this uninterrupted run of failed refreshes, in Unix seconds.
        /// A successful refresh clears it, even if the credentials did not change.
        since_unix: i64,
        /// Time of the most recent failed attempt, in Unix seconds.
        last_attempt_unix: i64,
    },
}

/// Common credential usability and refresh status for either provider.
/// Application readiness may apply a stricter policy or an expiry lead time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityStatus {
    pub provider: &'static str,
    /// Compatibility alias for `usable`; refresh failure alone does not clear it.
    pub ready: bool,
    /// Whether the current identity is valid and the runtime has not stopped.
    pub usable: bool,
    pub spiffe_id: SpiffeId,
    /// Leaf certificate expiration in Unix seconds.
    pub expires_at_unix: i64,
    /// Earliest expiration in the presented chain, in Unix seconds. Use this
    /// deadline, rather than just the leaf expiration, for admission lead times.
    pub valid_until_unix: i64,
    pub refresh: RefreshStatus,
    pub last_success_unix: i64,
    /// Compatibility projection of the error in `refresh`.
    pub last_error: Option<String>,
}

/// All provider results and lifecycle transitions use the same publication lock.
/// A shutdown cannot be followed by a late refresh that revives the status.
#[derive(Clone)]
pub(crate) struct StatusPublisher {
    identity: IdentitySource,
    sender: watch::Sender<IdentityStatus>,
}

impl StatusPublisher {
    pub(crate) fn new(provider: &'static str, identity: IdentitySource) -> Self {
        let material = identity.0.load_full();
        let usable = !identity.is_stopped() && material.check_valid().is_ok();
        let (sender, _) = watch::channel(IdentityStatus {
            provider,
            ready: usable,
            usable,
            spiffe_id: material.spiffe_id.clone(),
            expires_at_unix: material.expires_at,
            valid_until_unix: material.valid_until,
            refresh: RefreshStatus::Ok,
            last_success_unix: unix_now(),
            last_error: None,
        });
        Self { identity, sender }
    }

    pub(crate) fn snapshot(&self) -> IdentityStatus {
        self.update_usability();
        self.sender.borrow().clone()
    }

    pub(crate) fn watch(&self) -> watch::Receiver<IdentityStatus> {
        self.update_usability();
        self.sender.subscribe()
    }

    pub(crate) fn record_reload(&self, result: Result<WorkloadMaterial>) -> Result<()> {
        let mut outcome = Ok(());
        self.sender.send_if_modified(|status| {
            if self.identity.is_stopped() {
                outcome = Err(Error::Stopped);
                return false;
            }
            let now = unix_now();
            // Loading/validation can finish before this publication lock is
            // acquired. Never replace usable material with an already-expired
            // candidate merely because it was valid earlier in the load.
            match result.and_then(|material| {
                material.check_valid()?;
                Ok(material)
            }) {
                Ok(material) => {
                    self.identity.publish(material);
                    status.last_success_unix = now;
                    status.last_error = None;
                    status.refresh = RefreshStatus::Ok;
                }
                Err(error) => {
                    let since_unix = match &status.refresh {
                        RefreshStatus::Ok => now,
                        RefreshStatus::Error { since_unix, .. } => *since_unix,
                    };
                    status.last_error = Some(error.to_string());
                    status.refresh = RefreshStatus::Error {
                        error: error.to_string(),
                        since_unix,
                        last_attempt_unix: now,
                    };
                    outcome = Err(error);
                }
            }
            self.sync_identity(status);
            // Notify even if an unchanged reload completed in the same second.
            true
        });
        outcome
    }

    pub(crate) fn stop(&self) {
        self.sender.send_if_modified(|status| {
            self.identity.stop();
            self.sync_identity(status)
        });
    }

    fn update_usability(&self) {
        self.sender
            .send_if_modified(|status| self.sync_identity(status));
    }

    fn sync_identity(&self, status: &mut IdentityStatus) -> bool {
        let material = self.identity.0.load_full();
        let usable = !self.identity.is_stopped() && material.check_valid().is_ok();
        let changed = status.usable != usable
            || status.spiffe_id != material.spiffe_id
            || status.expires_at_unix != material.expires_at
            || status.valid_until_unix != material.valid_until;
        status.ready = usable;
        status.usable = usable;
        status.spiffe_id = material.spiffe_id.clone();
        status.expires_at_unix = material.expires_at;
        status.valid_until_unix = material.valid_until;
        changed
    }

    /// Rearm on every provider result. Expiration does not depend on the file or
    /// SPIRE refresh interval, and an old timer always checks the newest identity.
    pub(crate) async fn monitor_expiry(self, cancel: CancellationToken) {
        let mut changes = self.watch();
        loop {
            let status = changes.borrow_and_update().clone();
            let expiration = UNIX_EPOCH
                .checked_add(Duration::from_secs(status.valid_until_unix.max(0) as u64))
                .expect("validated certificate expiration");
            let remaining = expiration
                .duration_since(SystemTime::now())
                .unwrap_or_default();
            tokio::select! {
                biased;
                () = cancel.cancelled() => return,
                changed = changes.changed() => {
                    if changed.is_err() { return; }
                }
                () = tokio::time::sleep(remaining), if status.usable => {
                    self.update_usability();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::static_ca::StaticCa;

    fn publisher(provider: &'static str) -> StatusPublisher {
        let ca = StaticCa::generate("fleet.test".try_into().unwrap(), Duration::from_secs(86400))
            .unwrap();
        let identity = ca
            .issue_svid(
                &"spiffe://fleet.test/service/vkg".try_into().unwrap(),
                Duration::from_secs(3600),
            )
            .unwrap()
            .identity_source()
            .unwrap();
        StatusPublisher::new(provider, identity)
    }

    #[test]
    fn both_providers_preserve_error_since_until_success_and_reject_late_refresh() {
        for provider in ["files", "embedded_spire"] {
            let publisher = publisher(provider);
            let mut changes = publisher.watch();
            let material = publisher.identity.0.load_full();
            assert!(publisher
                .record_reload(Err(Error::Transport("first".into())))
                .is_err());
            assert!(changes.borrow_and_update().usable);
            publisher.sender.send_modify(|status| {
                if let RefreshStatus::Error { since_unix, .. } = &mut status.refresh {
                    *since_unix = 1;
                }
            });
            assert!(publisher
                .record_reload(Err(Error::Transport("second".into())))
                .is_err());
            assert!(matches!(&changes.borrow_and_update().refresh,
                RefreshStatus::Error { since_unix: 1, error, last_attempt_unix }
                    if error.contains("second") && *last_attempt_unix > 1));
            publisher.record_reload(Ok((*material).clone())).unwrap();
            assert_eq!(changes.borrow_and_update().refresh, RefreshStatus::Ok);
            assert!(publisher
                .record_reload(Err(Error::Transport("new failure".into())))
                .is_err());
            assert!(matches!(changes.borrow_and_update().refresh,
                RefreshStatus::Error { since_unix, .. } if since_unix > 1));
            publisher.stop();
            assert!(!changes.borrow_and_update().usable);
            let stopped = publisher.snapshot();
            assert!(matches!(
                publisher.record_reload(Ok((*material).clone())),
                Err(Error::Stopped)
            ));
            assert!(!changes.has_changed().unwrap());
            assert_eq!(publisher.snapshot(), stopped);
        }
    }

    #[tokio::test]
    async fn expiry_monitor_uses_chain_deadline_not_just_leaf() {
        let publisher = publisher("embedded_spire");
        let mut material = (*publisher.identity.0.load_full()).clone();
        // Model a validated chain whose intermediate expires before its leaf.
        material.valid_until = unix_now() + 2;
        publisher.record_reload(Ok(material)).unwrap();
        let mut changes = publisher.watch();
        assert!(changes.borrow().valid_until_unix < changes.borrow().expires_at_unix);
        let cancel = CancellationToken::new();
        let task = tokio::spawn(publisher.clone().monitor_expiry(cancel.clone()));
        tokio::time::timeout(Duration::from_secs(5), changes.changed())
            .await
            .unwrap()
            .unwrap();
        let expired = changes.borrow_and_update().clone();
        assert!(!expired.usable);
        assert!(expired.expires_at_unix > unix_now());
        assert_eq!(expired.refresh, RefreshStatus::Ok);
        cancel.cancel();
        task.await.unwrap();
    }

    #[test]
    fn expired_candidate_cannot_replace_usable_last_known_good_material() {
        let publisher = publisher("files");
        let before = publisher.snapshot();
        let original = publisher.identity.0.load_full();
        let mut expired = (*original).clone();
        expired.valid_until = unix_now() - 1;
        assert!(matches!(
            publisher.record_reload(Ok(expired)),
            Err(Error::IdentityExpired)
        ));
        let after = publisher.snapshot();
        assert!(after.usable);
        assert_eq!(after.valid_until_unix, before.valid_until_unix);
        assert!(std::sync::Arc::ptr_eq(
            &original,
            &publisher.identity.0.load_full()
        ));
        assert!(matches!(after.refresh, RefreshStatus::Error { .. }));
    }
}
