//! Lease coordination for guarded paths.
//!
//! Modeled on locksmithd's time-boxed lease pattern
//! (`crates/locksmith-core` in github.com/elci-group/locksmith): any process
//! that wants exclusive or destructive access to a guarded path (a database
//! file, an object-store root, a quarantine directory) must acquire a
//! time-boxed lease first. Unlike locksmithd, an expired or absent lease does
//! not merely block a competing *lock* request -- it blocks the underlying
//! filesystem mutation from proceeding at all, via the sequester layer.
//!
//! See ADR-001 for why this is required in addition to passive watching.
//!
//! Phase 1 (CLI-driven, manual lease acquisition): leases are persisted to a
//! single JSON file per state directory. This is deliberately not safe under
//! concurrent multi-process acquisition -- there is no file locking around
//! the load-modify-save cycle -- because Phase 1's only client is an
//! operator or script invoking the `sayfguard` binary directly, one command
//! at a time. Making this safe for a resident daemon handling concurrent
//! requests is Phase 4 scope.

use crate::audit::AuditLog;
use crate::sequester::{self, SequesterConfig, SequesterError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub resource: String,
    pub owner: String,
    pub acquired_at: u64,
    pub ttl_seconds: u64,
    /// The sequestered copy proving a pre-image existed before this lease
    /// was granted; see ADR-001. Always present -- a `Lease` value cannot be
    /// constructed without one existing first.
    pub sequestered_artifact_sha256: String,
}

impl Lease {
    pub fn expires_at(&self) -> u64 {
        self.acquired_at.saturating_add(self.ttl_seconds)
    }

    pub fn is_expired_at(&self, now: u64) -> bool {
        now >= self.expires_at()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error(
        "resource '{resource}' is already leased by '{holder}' until unix time {expires_at}"
    )]
    AlreadyHeld {
        resource: String,
        holder: String,
        expires_at: u64,
    },
    #[error("sequestration failed before a lease could be granted: {0}")]
    Sequester(#[from] SequesterError),
    #[error("I/O error accessing lease state: {0}")]
    Io(#[from] std::io::Error),
    #[error("lease state file is corrupt: {0}")]
    Corrupt(#[from] serde_json::Error),
    #[error("no lease on resource '{0}' is held by owner '{1}'")]
    NotHeld(String, String),
    #[error("lease was granted but could not be recorded in the audit trail: {0}")]
    Audit(#[from] crate::audit::AuditError),
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct LeaseState {
    leases: HashMap<String, Lease>,
}

/// Durable store of active leases, one JSON file per Sayfguard state
/// directory (`<state_dir>/leases.json`).
pub struct LeaseStore {
    state_path: PathBuf,
}

impl LeaseStore {
    pub fn open(state_dir: &Path) -> Result<Self, LeaseError> {
        fs::create_dir_all(state_dir)?;
        Ok(Self {
            state_path: state_dir.join("leases.json"),
        })
    }

    fn load(&self) -> Result<LeaseState, LeaseError> {
        if !self.state_path.is_file() {
            return Ok(LeaseState::default());
        }
        let raw = fs::read_to_string(&self.state_path)?;
        if raw.trim().is_empty() {
            return Ok(LeaseState::default());
        }
        Ok(serde_json::from_str(&raw)?)
    }

    fn save(&self, state: &LeaseState) -> Result<(), LeaseError> {
        let raw = serde_json::to_string_pretty(state)?;
        // Write-then-rename so a crash mid-write can never leave leases.json
        // truncated or half-written -- a corrupt lease file must not be able
        // to silently look like "no leases held".
        let tmp_path = self.state_path.with_extension("json.tmp");
        fs::write(&tmp_path, raw)?;
        fs::rename(&tmp_path, &self.state_path)?;
        Ok(())
    }

    /// Requests a lease on `resource`. Per ADR-001, sequestration happens
    /// synchronously here, before the lease is recorded: `owner` never
    /// receives a `Lease` value without a retrievable pre-image already
    /// existing on disk. An unexpired lease held by a different owner is
    /// rejected outright; re-acquiring your own still-valid lease re-runs
    /// sequestration and refreshes the TTL rather than erroring, since a
    /// caller renewing its own lease is not a conflict.
    ///
    /// Per ADR-002, every grant is chained into `audit_log`. That append
    /// happens after the lease is already saved to `leases.json`: if it
    /// fails, the caller sees `LeaseError::Audit` even though the lease
    /// itself was granted successfully -- a real gap for a case as
    /// exceptional as the audit log's own storage failing, not silently
    /// swallowed. Rolling back an already-persisted lease to keep this
    /// perfectly atomic isn't attempted; Phase 1-2's single-writer-at-a-time
    /// assumption already accepts a comparable, narrower window.
    pub fn acquire(
        &self,
        resource: &str,
        owner: &str,
        ttl: Duration,
        sequester_config: &SequesterConfig,
        audit_log: &AuditLog,
    ) -> Result<Lease, LeaseError> {
        let now = now_unix();
        let mut state = self.load()?;

        if let Some(existing) = state.leases.get(resource) {
            if !existing.is_expired_at(now) && existing.owner != owner {
                return Err(LeaseError::AlreadyHeld {
                    resource: resource.to_string(),
                    holder: existing.owner.clone(),
                    expires_at: existing.expires_at(),
                });
            }
        }

        let artifact = sequester::sequester(sequester_config)?;

        let lease = Lease {
            resource: resource.to_string(),
            owner: owner.to_string(),
            acquired_at: now,
            ttl_seconds: ttl.as_secs(),
            sequestered_artifact_sha256: artifact.sha256,
        };
        state.leases.insert(resource.to_string(), lease.clone());
        self.save(&state)?;
        audit_log.append(
            Some(resource),
            "lease_granted",
            Some(&format!("owner={owner} sha256={}", lease.sequestered_artifact_sha256)),
        )?;
        Ok(lease)
    }

    /// Releases a lease early. Only the current holder may release it; an
    /// expired lease is treated the same as no lease (`NotHeld`), since it
    /// no longer blocks anything for anyone to release.
    pub fn release(&self, resource: &str, owner: &str) -> Result<(), LeaseError> {
        let now = now_unix();
        let mut state = self.load()?;
        match state.leases.get(resource) {
            Some(existing) if existing.owner == owner && !existing.is_expired_at(now) => {
                state.leases.remove(resource);
                self.save(&state)
            }
            _ => Err(LeaseError::NotHeld(resource.to_string(), owner.to_string())),
        }
    }

    /// All leases not yet expired, as of now.
    pub fn active_leases(&self) -> Result<Vec<Lease>, LeaseError> {
        let now = now_unix();
        Ok(self
            .load()?
            .leases
            .into_values()
            .filter(|lease| !lease.is_expired_at(now))
            .collect())
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn write_fake_backup_engine(dir: &Path) -> PathBuf {
        let script_path = dir.join("fake-backup.py");
        fs::write(
            &script_path,
            "#!/usr/bin/env python3\n\
             import sys\n\
             output = sys.argv[sys.argv.index('--output') + 1]\n\
             with open(output, 'wb') as f:\n\
             \tf.write(b'archive')\n",
        )
        .unwrap();
        let mut perms = fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).unwrap();
        script_path
    }

    fn sequester_config(temp: &TempDir, resource: &str) -> SequesterConfig {
        SequesterConfig {
            python: PathBuf::from("python3"),
            backup_script: write_fake_backup_engine(temp.path()),
            registry_path: temp.path().join("registry.db"),
            objects_root: temp.path().join("objects"),
            chronology_path: None,
            sequester_root: temp.path().join("sequester"),
            passphrase_file: temp.path().join("passphrase.txt"),
            resource: resource.to_string(),
        }
    }

    fn audit_log(temp: &TempDir) -> AuditLog {
        AuditLog::open(&temp.path().join("audit.jsonl"))
    }

    #[test]
    fn grants_a_lease_and_records_the_sequestered_artifact() {
        let temp = TempDir::new().unwrap();
        let store = LeaseStore::open(&temp.path().join("state")).unwrap();
        let config = sequester_config(&temp, "case-AC");
        let log = audit_log(&temp);

        let lease = store
            .acquire("case-AC/registry.db", "operator-1", Duration::from_secs(900), &config, &log)
            .unwrap();

        assert_eq!(lease.owner, "operator-1");
        assert!(!lease.sequestered_artifact_sha256.is_empty());
    }

    #[test]
    fn grants_are_chained_into_the_audit_log() {
        let temp = TempDir::new().unwrap();
        let store = LeaseStore::open(&temp.path().join("state")).unwrap();
        let config = sequester_config(&temp, "case-AC");
        let log = audit_log(&temp);

        store
            .acquire("case-AC/registry.db", "operator-1", Duration::from_secs(900), &config, &log)
            .unwrap();

        let events = log.read_all().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "lease_granted");
        assert_eq!(events[0].resource.as_deref(), Some("case-AC/registry.db"));
    }

    #[test]
    fn rejects_a_conflicting_acquire_by_a_different_owner() {
        let temp = TempDir::new().unwrap();
        let store = LeaseStore::open(&temp.path().join("state")).unwrap();
        let config = sequester_config(&temp, "case-AC");
        let log = audit_log(&temp);

        store
            .acquire("case-AC/registry.db", "operator-1", Duration::from_secs(900), &config, &log)
            .unwrap();
        let error = store
            .acquire("case-AC/registry.db", "operator-2", Duration::from_secs(900), &config, &log)
            .unwrap_err();

        assert!(matches!(error, LeaseError::AlreadyHeld { .. }));
    }

    #[test]
    fn allows_the_same_owner_to_reacquire_and_refresh_their_own_lease() {
        let temp = TempDir::new().unwrap();
        let store = LeaseStore::open(&temp.path().join("state")).unwrap();
        let config = sequester_config(&temp, "case-AC");
        let log = audit_log(&temp);

        let first = store
            .acquire("case-AC/registry.db", "operator-1", Duration::from_secs(900), &config, &log)
            .unwrap();
        let second = store
            .acquire("case-AC/registry.db", "operator-1", Duration::from_secs(900), &config, &log)
            .unwrap();

        assert_eq!(first.owner, second.owner);
        assert!(second.acquired_at >= first.acquired_at);
    }

    #[test]
    fn allows_acquiring_a_resource_whose_previous_lease_has_expired() {
        let temp = TempDir::new().unwrap();
        let store = LeaseStore::open(&temp.path().join("state")).unwrap();
        let config = sequester_config(&temp, "case-AC");
        let log = audit_log(&temp);

        store
            .acquire("case-AC/registry.db", "operator-1", Duration::from_secs(0), &config, &log)
            .unwrap();
        // ttl_seconds = 0 means the lease is already expired as of the next
        // call to now_unix(), so a different owner should be able to acquire.
        let second = store.acquire(
            "case-AC/registry.db",
            "operator-2",
            Duration::from_secs(900),
            &config,
            &log,
        );

        assert!(second.is_ok());
    }

    #[test]
    fn does_not_grant_a_lease_when_sequestration_fails() {
        let temp = TempDir::new().unwrap();
        let store = LeaseStore::open(&temp.path().join("state")).unwrap();
        let mut config = sequester_config(&temp, "case-AC");
        config.python = PathBuf::from("no-such-interpreter-binary");
        let log = audit_log(&temp);

        let error = store
            .acquire("case-AC/registry.db", "operator-1", Duration::from_secs(900), &config, &log)
            .unwrap_err();

        assert!(matches!(error, LeaseError::Sequester(_)));
        assert!(store.active_leases().unwrap().is_empty());
        assert!(log.read_all().unwrap().is_empty());
    }

    #[test]
    fn release_removes_a_lease_held_by_its_owner() {
        let temp = TempDir::new().unwrap();
        let store = LeaseStore::open(&temp.path().join("state")).unwrap();
        let config = sequester_config(&temp, "case-AC");
        let log = audit_log(&temp);
        store
            .acquire("case-AC/registry.db", "operator-1", Duration::from_secs(900), &config, &log)
            .unwrap();

        store.release("case-AC/registry.db", "operator-1").unwrap();

        assert!(store.active_leases().unwrap().is_empty());
    }

    #[test]
    fn release_rejects_a_non_holder() {
        let temp = TempDir::new().unwrap();
        let store = LeaseStore::open(&temp.path().join("state")).unwrap();
        let config = sequester_config(&temp, "case-AC");
        let log = audit_log(&temp);
        store
            .acquire("case-AC/registry.db", "operator-1", Duration::from_secs(900), &config, &log)
            .unwrap();

        let error = store.release("case-AC/registry.db", "operator-2").unwrap_err();

        assert!(matches!(error, LeaseError::NotHeld(_, _)));
    }

    #[test]
    fn active_leases_excludes_expired_ones() {
        let temp = TempDir::new().unwrap();
        let store = LeaseStore::open(&temp.path().join("state")).unwrap();
        let config = sequester_config(&temp, "case-AC");
        let log = audit_log(&temp);
        store
            .acquire("case-AC/registry.db", "operator-1", Duration::from_secs(0), &config, &log)
            .unwrap();

        assert!(store.active_leases().unwrap().is_empty());
    }

    #[test]
    fn persists_across_separate_lease_store_instances() {
        let temp = TempDir::new().unwrap();
        let state_dir = temp.path().join("state");
        let config = sequester_config(&temp, "case-AC");
        let log = audit_log(&temp);
        LeaseStore::open(&state_dir)
            .unwrap()
            .acquire("case-AC/registry.db", "operator-1", Duration::from_secs(900), &config, &log)
            .unwrap();

        let reopened = LeaseStore::open(&state_dir).unwrap();

        assert_eq!(reopened.active_leases().unwrap().len(), 1);
    }
}
