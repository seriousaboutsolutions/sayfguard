//! Filesystem change detection for guarded paths.
//!
//! Modeled on kaptaind's `src/watcher/` (github.com/elci-group/kaptaind):
//! `notify::recommended_watcher` on a dedicated thread, events piped through
//! a channel. This module exists for observability and for triggering
//! the retention/notification sweep, NOT as the sequestration mechanism
//! itself -- a `notify` event fires after the OS-level write has already
//! happened, which is too late to guarantee a pre-image exists. See ADR-001.
//!
//! Phase 2 scope: lease-less-mutation alerting. `check_mutation` is the
//! decision -- "did this event happen without an active lease?" -- kept
//! pure with respect to the filesystem so it's directly unit-testable; `run`
//! is the thin, mostly-untested `notify` integration that calls it for real
//! events and also drives the retention sweep's timing per the technical
//! directive (a sweep tick fires whenever no event arrives within
//! `sweep_interval`, not on a separate schedule -- Phase 3 is where a real
//! cron-style scheduler for *notifications* is planned).

use crate::audit::AuditLog;
use crate::lease::{LeaseError, LeaseStore};
use crate::retention::{self, RetentionError};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A guarded filesystem path and the resource name its lease is filed under.
/// The two are only linked by this struct -- `lease::Lease::resource` and
/// `sequester::SequesteredArtifact::resource` don't know about paths at all.
#[derive(Debug, Clone)]
pub struct WatchedPath {
    pub resource: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct IntegrityAlert {
    pub resource: String,
    pub path: PathBuf,
    pub detected_at: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum WatcherError {
    #[error("failed to read lease state: {0}")]
    Lease(#[from] LeaseError),
    #[error("retention sweep failed: {0}")]
    Retention(#[from] RetentionError),
    #[error("filesystem watch error: {0}")]
    Notify(#[from] notify::Error),
}

/// Whether an observed mutation of `watched` is alertable: true when no
/// unexpired lease is currently held on its resource. Deliberately takes the
/// lease store's current view as an argument rather than reaching into
/// global state, so this is testable without a real filesystem watcher.
pub fn check_mutation(
    watched: &WatchedPath,
    lease_store: &LeaseStore,
) -> Result<Option<IntegrityAlert>, LeaseError> {
    let has_lease = lease_store
        .active_leases()?
        .iter()
        .any(|lease| lease.resource == watched.resource);
    Ok(if has_lease {
        None
    } else {
        Some(IntegrityAlert {
            resource: watched.resource.clone(),
            path: watched.path.clone(),
            detected_at: now_unix(),
        })
    })
}

/// Runs a blocking watch loop over every path in `watches`. For each
/// filesystem event, resolves it back to the `WatchedPath` it fell under and
/// calls `check_mutation`; every resulting alert goes to `on_alert`. When no
/// event arrives for `sweep_interval`, runs `retention::sweep` against
/// `sequester_root` instead and reports its outcomes to `on_sweep`. Returns
/// only on a fatal setup or channel error -- this is meant to run for the
/// life of the process (e.g. under a supervisor), not to be polled.
#[allow(clippy::too_many_arguments)]
pub fn run(
    watches: &[WatchedPath],
    lease_store: &LeaseStore,
    sequester_root: &std::path::Path,
    degrade_window_secs: u64,
    attest_grace_secs: u64,
    audit_log: &AuditLog,
    sweep_interval: Duration,
    mut on_alert: impl FnMut(&IntegrityAlert),
    mut on_sweep: impl FnMut(&[retention::SweepOutcome]),
) -> Result<(), WatcherError> {
    use notify::{RecursiveMode, Watcher};

    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher = notify::recommended_watcher(tx)?;
    for watched in watches {
        // A guarded path that's a directory needs a recursive watch: content-
        // addressed object stores nest files several levels deep (e.g.
        // Combine Harvester's objects/objects/sha256/<prefix>/<hash>), and a
        // non-recursive watch on the top directory only reports events on
        // its immediate children, silently missing writes further down.
        let mode = if watched.path.is_dir() {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };
        watcher.watch(&watched.path, mode)?;
    }

    loop {
        match rx.recv_timeout(sweep_interval) {
            Ok(Ok(event)) => {
                for event_path in &event.paths {
                    if let Some(watched) = watches
                        .iter()
                        .find(|watched| event_path.starts_with(&watched.path))
                    {
                        if let Some(alert) = check_mutation(watched, lease_store)? {
                            on_alert(&alert);
                        }
                    }
                }
            }
            Ok(Err(_watch_error)) => continue,
            Err(RecvTimeoutError::Timeout) => {
                let outcomes = retention::sweep(
                    sequester_root,
                    degrade_window_secs,
                    attest_grace_secs,
                    audit_log,
                )?;
                if !outcomes.is_empty() {
                    on_sweep(&outcomes);
                }
            }
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
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
    use crate::retention::{DEFAULT_ATTESTED_GRACE_SECS, DEFAULT_FULL_FIDELITY_WINDOW_SECS};
    use crate::sequester::SequesterConfig;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::thread;
    use std::time::Duration;
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

    #[test]
    fn alerts_when_no_lease_is_held_for_the_resource() {
        let temp = TempDir::new().unwrap();
        let store = LeaseStore::open(&temp.path().join("state")).unwrap();
        let watched = WatchedPath {
            resource: "case-AC/registry".to_string(),
            path: temp.path().join("registry.db"),
        };

        let alert = check_mutation(&watched, &store).unwrap();

        let alert = alert.expect("no lease was ever acquired, so this must alert");
        assert_eq!(alert.resource, "case-AC/registry");
        assert_eq!(alert.path, watched.path);
    }

    fn audit_log(temp: &TempDir) -> AuditLog {
        AuditLog::open(&temp.path().join("audit.jsonl"))
    }

    #[test]
    fn does_not_alert_while_an_unexpired_lease_is_held() {
        let temp = TempDir::new().unwrap();
        let store = LeaseStore::open(&temp.path().join("state")).unwrap();
        let config = sequester_config(&temp, "case-AC/registry");
        let log = audit_log(&temp);
        store
            .acquire(
                "case-AC/registry",
                "operator-1",
                Duration::from_secs(900),
                &config,
                &log,
            )
            .unwrap();
        let watched = WatchedPath {
            resource: "case-AC/registry".to_string(),
            path: temp.path().join("registry.db"),
        };

        assert!(check_mutation(&watched, &store).unwrap().is_none());
    }

    #[test]
    fn alerts_again_once_the_held_lease_has_expired() {
        let temp = TempDir::new().unwrap();
        let store = LeaseStore::open(&temp.path().join("state")).unwrap();
        let config = sequester_config(&temp, "case-AC/registry");
        let log = audit_log(&temp);
        store
            .acquire("case-AC/registry", "operator-1", Duration::from_secs(0), &config, &log)
            .unwrap();
        let watched = WatchedPath {
            resource: "case-AC/registry".to_string(),
            path: temp.path().join("registry.db"),
        };

        assert!(check_mutation(&watched, &store).unwrap().is_some());
    }

    #[test]
    fn a_lease_on_a_different_resource_does_not_suppress_the_alert() {
        let temp = TempDir::new().unwrap();
        let store = LeaseStore::open(&temp.path().join("state")).unwrap();
        let config = sequester_config(&temp, "case-XY/registry");
        let log = audit_log(&temp);
        store
            .acquire(
                "case-XY/registry",
                "operator-1",
                Duration::from_secs(900),
                &config,
                &log,
            )
            .unwrap();
        let watched = WatchedPath {
            resource: "case-AC/registry".to_string(),
            path: temp.path().join("registry.db"),
        };

        assert!(check_mutation(&watched, &store).unwrap().is_some());
    }

    #[test]
    fn run_detects_a_write_nested_several_directories_deep_in_a_guarded_directory() {
        use std::sync::mpsc;

        let temp = TempDir::new().unwrap();
        let store = LeaseStore::open(&temp.path().join("state")).unwrap();
        let guarded_dir = temp.path().join("objects");
        fs::create_dir_all(guarded_dir.join("objects/sha256/ab")).unwrap();
        let watched = [WatchedPath {
            resource: "case-AC/objects".to_string(),
            path: guarded_dir.clone(),
        }];

        let (alert_tx, alert_rx) = mpsc::channel();
        let run_thread = thread::spawn(move || {
            let _ = run(
                &watched,
                &store,
                &temp.path().join("sequester"),
                DEFAULT_FULL_FIDELITY_WINDOW_SECS,
                DEFAULT_ATTESTED_GRACE_SECS,
                &AuditLog::open(&temp.path().join("audit.jsonl")),
                Duration::from_secs(3600),
                |alert| {
                    let _ = alert_tx.send(alert.clone());
                },
                |_outcomes| {},
            );
        });

        // Give the watcher a moment to install before writing, matching how
        // a real deployment's watch process would already be running before
        // any mutation happens.
        thread::sleep(Duration::from_millis(300));
        fs::write(guarded_dir.join("objects/sha256/ab/deadbeef"), b"blob").unwrap();

        let alert = alert_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("a write nested several directories deep must still be detected");
        assert_eq!(alert.resource, "case-AC/objects");

        // The watch loop blocks forever on a real deployment; this test
        // doesn't join run_thread; the process ending at test exit is enough.
        drop(run_thread);
    }
}
