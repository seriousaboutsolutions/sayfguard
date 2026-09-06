//! Tiered retention and degrade-on-schedule for sequestered artifacts.
//!
//! Modeled on locksmithd's export-then-prune retention sweeper
//! (`crates/locksmith-core/src/manager.rs`), extended to three stages instead
//! of a single prune, per ADR-002:
//!
//! 1. Full-fidelity: encrypted bytes + manifest, immediately restorable.
//! 2. Degraded: manifest only (hash + provenance metadata), bytes purged.
//! 3. Attested: manifest purged too; only a tamper-evident hash-chain entry
//!    remains, proving the artifact existed and was handled correctly
//!    without retaining personal data past its purpose.
//!
//! Transition to stage 2 fires at `min(90 days, task completion)`. Transition
//! to stage 3 fires a fixed grace period after stage 2 (default 30 days).
//! Both transitions append an entry to `audit::AuditLog` (ADR-002: every
//! stage transition must be hash-chained) -- for the stage 3 transition,
//! that audit entry is the *only* record left once the manifest is deleted.
//! Uses the encryption and integrity-verification already implemented in
//! combine-harvester's `scripts/harvester-backup.py` rather than
//! reimplementing GPG/AES handling here -- see the technical directive,
//! "Relationship to existing tooling."

use crate::audit::AuditLog;
use crate::sequester::SequesteredArtifact;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// ADR-002's documented default for the full-fidelity -> degraded window.
/// Deployments needing a different window (see the ADR's Risks section) pass
/// it explicitly to `sweep` instead.
pub const DEFAULT_FULL_FIDELITY_WINDOW_SECS: u64 = 90 * 24 * 60 * 60;

/// ADR-002's documented default grace period between degraded and attested.
pub const DEFAULT_ATTESTED_GRACE_SECS: u64 = 30 * 24 * 60 * 60;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionStage {
    #[default]
    FullFidelity,
    Degraded,
    Attested,
}

#[derive(Debug, thiserror::Error)]
pub enum RetentionError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest at {path} is corrupt: {source}")]
    Corrupt {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to write manifest: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("failed to record stage transition in the audit trail: {0}")]
    Audit(#[from] crate::audit::AuditError),
}

#[derive(Debug, Clone, Serialize)]
pub struct SweepOutcome {
    pub manifest_path: PathBuf,
    pub resource: String,
    pub stage: RetentionStage,
    /// True if this sweep call is what caused the transition (as opposed to
    /// the artifact already having been in this stage beforehand).
    pub transitioned: bool,
}

/// True once `artifact` has hit `min(window, task completion)` -- per
/// ADR-002, task completion always wins regardless of age, so this checks it
/// first rather than only as a tiebreak.
fn is_due_to_degrade(artifact: &SequesteredArtifact, now: u64, window_secs: u64) -> bool {
    artifact.task_complete || now.saturating_sub(artifact.sequestered_at) >= window_secs
}

fn is_due_to_attest(degraded_at: u64, now: u64, grace_secs: u64) -> bool {
    now.saturating_sub(degraded_at) >= grace_secs
}

/// Marks every sequestered artifact for `resource` under `sequester_root` as
/// task-complete, without otherwise changing its stage -- the next `sweep`
/// call is what actually performs the degrade. Separate from `sweep` so a
/// caller can record completion the moment it's known, independent of
/// whatever cadence sweeps run on. Not itself a stage transition, so per
/// ADR-002's literal wording this is not chained into the audit trail.
pub fn mark_task_complete(sequester_root: &Path, resource: &str) -> Result<usize, RetentionError> {
    let mut updated = 0;
    for path in manifest_paths(sequester_root)? {
        let mut artifact = read_manifest(&path)?;
        if artifact.resource == resource && !artifact.task_complete {
            artifact.task_complete = true;
            write_manifest(&path, &artifact)?;
            updated += 1;
        }
    }
    Ok(updated)
}

/// Scans every `*.manifest.json` under `sequester_root` and advances any
/// artifact that's due a stage transition:
///
/// - Full-fidelity -> degraded, at `min(degrade_window_secs, task
///   completion)`: the encrypted archive bytes are deleted and the manifest
///   is rewritten recording `RetentionStage::Degraded`.
/// - Degraded -> attested, `attest_grace_secs` after degrading: the manifest
///   itself is deleted. Only the audit-chain entry this call appends
///   survives -- by design, per ADR-002's stage 3 definition.
///
/// Each transition appends one entry to `audit_log` before (for degrade) or
/// as part of (for attest, since the manifest disappears) the transition,
/// so a caller can distinguish "already at this stage" from "moved to it
/// just now" via `SweepOutcome::transitioned`.
pub fn sweep(
    sequester_root: &Path,
    degrade_window_secs: u64,
    attest_grace_secs: u64,
    audit_log: &AuditLog,
) -> Result<Vec<SweepOutcome>, RetentionError> {
    let now = now_unix();
    let mut outcomes = Vec::new();

    for path in manifest_paths(sequester_root)? {
        let mut artifact = read_manifest(&path)?;

        if artifact.stage == RetentionStage::FullFidelity
            && is_due_to_degrade(&artifact, now, degrade_window_secs)
        {
            if artifact.archive_path.is_file() {
                fs::remove_file(&artifact.archive_path)?;
            }
            artifact.stage = RetentionStage::Degraded;
            artifact.degraded_at = Some(now);
            write_manifest(&path, &artifact)?;
            audit_log.append(Some(&artifact.resource), "artifact_degraded", Some(&artifact.sha256))?;
            outcomes.push(SweepOutcome {
                manifest_path: path,
                resource: artifact.resource,
                stage: RetentionStage::Degraded,
                transitioned: true,
            });
            continue;
        }

        if artifact.stage == RetentionStage::Degraded {
            let degraded_at = artifact.degraded_at.unwrap_or(now);
            if is_due_to_attest(degraded_at, now, attest_grace_secs) {
                audit_log.append(Some(&artifact.resource), "artifact_attested", Some(&artifact.sha256))?;
                fs::remove_file(&path)?;
                outcomes.push(SweepOutcome {
                    manifest_path: path,
                    resource: artifact.resource,
                    stage: RetentionStage::Attested,
                    transitioned: true,
                });
                continue;
            }
        }

        outcomes.push(SweepOutcome {
            manifest_path: path,
            resource: artifact.resource.clone(),
            stage: artifact.stage,
            transitioned: false,
        });
    }
    Ok(outcomes)
}

pub(crate) fn manifest_paths(sequester_root: &Path) -> Result<Vec<PathBuf>, RetentionError> {
    if !sequester_root.is_dir() {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    for entry in fs::read_dir(sequester_root)? {
        let path = entry?.path();
        if path.is_file() && path.to_string_lossy().ends_with(".manifest.json") {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

pub(crate) fn read_manifest(path: &Path) -> Result<SequesteredArtifact, RetentionError> {
    let raw = fs::read_to_string(path)?;
    serde_json::from_str(&raw).map_err(|source| RetentionError::Corrupt {
        path: path.to_path_buf(),
        source,
    })
}

pub(crate) fn write_manifest(path: &Path, artifact: &SequesteredArtifact) -> Result<(), RetentionError> {
    fs::write(path, serde_json::to_string_pretty(artifact)?)?;
    Ok(())
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
    use crate::sequester::SequesteredArtifact;
    use tempfile::TempDir;

    fn write_artifact(
        dir: &Path,
        resource: &str,
        sequestered_at: u64,
        task_complete: bool,
    ) -> PathBuf {
        write_artifact_at_stage(dir, resource, sequestered_at, task_complete, RetentionStage::FullFidelity, None)
    }

    fn write_artifact_at_stage(
        dir: &Path,
        resource: &str,
        sequestered_at: u64,
        task_complete: bool,
        stage: RetentionStage,
        degraded_at: Option<u64>,
    ) -> PathBuf {
        let archive_path = dir.join(format!("{resource}.tar.gpg"));
        let manifest_path = dir.join(format!("{resource}.manifest.json"));
        if stage == RetentionStage::FullFidelity {
            fs::write(&archive_path, b"archive bytes").unwrap();
        }
        let artifact = SequesteredArtifact {
            sha256: "deadbeef".to_string(),
            sequestered_at,
            resource: resource.to_string(),
            source_path: dir.join("source"),
            archive_path,
            manifest_path: manifest_path.clone(),
            task_complete,
            stage,
            degraded_at,
            last_notified_at: None,
        };
        fs::write(&manifest_path, serde_json::to_string_pretty(&artifact).unwrap()).unwrap();
        manifest_path
    }

    fn audit_log(temp: &TempDir) -> AuditLog {
        AuditLog::open(&temp.path().join("audit.jsonl"))
    }

    #[test]
    fn degrades_an_artifact_older_than_the_window() {
        let temp = TempDir::new().unwrap();
        let now = now_unix();
        write_artifact(temp.path(), "case-AC", now - 200, false);

        let outcomes = sweep(temp.path(), 100, DEFAULT_ATTESTED_GRACE_SECS, &audit_log(&temp)).unwrap();

        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].transitioned);
        assert_eq!(outcomes[0].stage, RetentionStage::Degraded);
    }

    #[test]
    fn leaves_a_recent_incomplete_artifact_at_full_fidelity() {
        let temp = TempDir::new().unwrap();
        let now = now_unix();
        write_artifact(temp.path(), "case-AC", now, false);

        let outcomes = sweep(temp.path(), 100, DEFAULT_ATTESTED_GRACE_SECS, &audit_log(&temp)).unwrap();

        assert!(!outcomes[0].transitioned);
        assert_eq!(outcomes[0].stage, RetentionStage::FullFidelity);
    }

    #[test]
    fn task_completion_degrades_regardless_of_age() {
        let temp = TempDir::new().unwrap();
        let now = now_unix();
        write_artifact(temp.path(), "case-AC", now, true);

        let outcomes = sweep(
            temp.path(),
            DEFAULT_FULL_FIDELITY_WINDOW_SECS,
            DEFAULT_ATTESTED_GRACE_SECS,
            &audit_log(&temp),
        )
        .unwrap();

        assert!(outcomes[0].transitioned);
    }

    #[test]
    fn degrading_deletes_the_archive_bytes_but_keeps_the_manifest() {
        let temp = TempDir::new().unwrap();
        let now = now_unix();
        let manifest_path = write_artifact(temp.path(), "case-AC", now - 200, false);
        let archive_path = temp.path().join("case-AC.tar.gpg");
        assert!(archive_path.is_file());

        sweep(temp.path(), 100, DEFAULT_ATTESTED_GRACE_SECS, &audit_log(&temp)).unwrap();

        assert!(!archive_path.is_file());
        assert!(manifest_path.is_file());
        let artifact = read_manifest(&manifest_path).unwrap();
        assert_eq!(artifact.stage, RetentionStage::Degraded);
        assert!(artifact.degraded_at.is_some());
    }

    #[test]
    fn degrading_appends_an_audit_entry() {
        let temp = TempDir::new().unwrap();
        let now = now_unix();
        write_artifact(temp.path(), "case-AC", now - 200, false);
        let log = audit_log(&temp);

        sweep(temp.path(), 100, DEFAULT_ATTESTED_GRACE_SECS, &log).unwrap();

        let events = log.read_all().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "artifact_degraded");
        assert_eq!(events[0].resource.as_deref(), Some("case-AC"));
    }

    #[test]
    fn does_not_re_degrade_an_already_degraded_artifact() {
        let temp = TempDir::new().unwrap();
        let now = now_unix();
        write_artifact(temp.path(), "case-AC", now - 200, false);
        let log = audit_log(&temp);
        sweep(temp.path(), 100, DEFAULT_ATTESTED_GRACE_SECS, &log).unwrap();

        let outcomes = sweep(temp.path(), 100, DEFAULT_ATTESTED_GRACE_SECS, &log).unwrap();

        assert!(!outcomes[0].transitioned);
        assert_eq!(outcomes[0].stage, RetentionStage::Degraded);
        assert_eq!(log.read_all().unwrap().len(), 1);
    }

    #[test]
    fn attests_a_degraded_artifact_past_the_grace_period() {
        let temp = TempDir::new().unwrap();
        let now = now_unix();
        let manifest_path = write_artifact_at_stage(
            temp.path(),
            "case-AC",
            now - 10_000,
            false,
            RetentionStage::Degraded,
            Some(now - 200),
        );
        let log = audit_log(&temp);

        let outcomes = sweep(temp.path(), DEFAULT_FULL_FIDELITY_WINDOW_SECS, 100, &log).unwrap();

        assert_eq!(outcomes[0].stage, RetentionStage::Attested);
        assert!(outcomes[0].transitioned);
        assert!(!manifest_path.is_file(), "manifest must be purged on attestation");
        let events = log.read_all().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "artifact_attested");
    }

    #[test]
    fn leaves_a_recently_degraded_artifact_alone() {
        let temp = TempDir::new().unwrap();
        let now = now_unix();
        write_artifact_at_stage(
            temp.path(),
            "case-AC",
            now - 10_000,
            false,
            RetentionStage::Degraded,
            Some(now),
        );

        let outcomes = sweep(
            temp.path(),
            DEFAULT_FULL_FIDELITY_WINDOW_SECS,
            DEFAULT_ATTESTED_GRACE_SECS,
            &audit_log(&temp),
        )
        .unwrap();

        assert!(!outcomes[0].transitioned);
        assert_eq!(outcomes[0].stage, RetentionStage::Degraded);
    }

    #[test]
    fn sweeping_an_empty_or_missing_directory_is_a_noop() {
        let temp = TempDir::new().unwrap();
        let missing = temp.path().join("does-not-exist");
        let log = audit_log(&temp);

        assert!(sweep(&missing, DEFAULT_FULL_FIDELITY_WINDOW_SECS, DEFAULT_ATTESTED_GRACE_SECS, &log)
            .unwrap()
            .is_empty());
        assert!(sweep(temp.path(), DEFAULT_FULL_FIDELITY_WINDOW_SECS, DEFAULT_ATTESTED_GRACE_SECS, &log)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn mark_task_complete_updates_only_the_named_resource() {
        let temp = TempDir::new().unwrap();
        let now = now_unix();
        write_artifact(temp.path(), "case-AC", now, false);
        write_artifact(temp.path(), "case-XY", now, false);

        let updated = mark_task_complete(temp.path(), "case-AC").unwrap();

        assert_eq!(updated, 1);
        let outcomes = sweep(
            temp.path(),
            DEFAULT_FULL_FIDELITY_WINDOW_SECS,
            DEFAULT_ATTESTED_GRACE_SECS,
            &audit_log(&temp),
        )
        .unwrap();
        let ac = outcomes.iter().find(|o| o.resource == "case-AC").unwrap();
        let xy = outcomes.iter().find(|o| o.resource == "case-XY").unwrap();
        assert!(ac.transitioned);
        assert!(!xy.transitioned);
    }
}
