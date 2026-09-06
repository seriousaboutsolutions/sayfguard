//! Hash-chained audit trail for lease grants and retention-stage transitions.
//!
//! ADR-002: "Sayfguard's audit trail for every stage transition and every
//! lease grant must be hash-chained (each entry includes the previous
//! entry's hash), matching Combine Harvester's own audit-chain standard
//! rather than locksmithd's unchained `AuditRecord` shape -- a system built
//! to protect evidence should not have weaker tamper-evidence than the
//! evidence it protects."
//!
//! This mirrors Combine Harvester's own algorithm exactly
//! (`crates/harvester-registry/src/registry.rs`'s `audit_event_hash`/
//! `append_audit_row`/`verify_audit_chain`): each entry's hash is the
//! SHA-256 hex digest of a JSON array `[previous_hash, occurred_at,
//! resource, action, details_or_empty]`, with the previous entry's hash
//! chained in and `""` as the genesis value. Two deliberate departures from
//! that implementation, not omissions:
//!
//! - Combine Harvester stores this in a SQLite table (`audit_events`);
//!   Sayfguard has no SQLite dependency anywhere in its Phase 1-2 file-based
//!   state (`leases.json`, artifact manifests), so this appends to a flat,
//!   append-only JSONL file instead of adding a second storage engine for
//!   one table. The hash-chain guarantee is identical either way.
//! - `occurred_at` is a unix-epoch second count, not Combine Harvester's
//!   RFC3339 string -- avoids a datetime-formatting dependency for a field
//!   whose only real requirement is being covered by the hash, not being
//!   typeset for a human reader.
//!
//! Only lease grants (`lease::LeaseStore::acquire`) and stage transitions
//! (`retention::sweep`) append here, per the literal ADR-002 wording above.
//! Lease releases and retention warnings are not chained -- neither is a
//! "stage transition" or a "lease grant" in the ADR's sense.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub occurred_at: u64,
    pub resource: Option<String>,
    pub action: String,
    pub details: Option<String>,
    pub previous_hash: String,
    pub event_hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditVerification {
    pub valid: bool,
    pub event_count: usize,
    /// Index into the chain (0-based) of the first entry whose recorded
    /// hashes don't match what recomputing them produces.
    pub first_invalid_index: Option<usize>,
    pub head_hash: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("audit log entry is corrupt: {0}")]
    Corrupt(#[from] serde_json::Error),
}

pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn open(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }

    /// Appends one entry, chaining it to the current head hash. Not safe
    /// under concurrent writers -- same caveat as `lease::LeaseStore` today
    /// (Phase 1-2 are single-process CLI invocations, one at a time).
    pub fn append(
        &self,
        resource: Option<&str>,
        action: &str,
        details: Option<&str>,
    ) -> Result<AuditEvent, AuditError> {
        let previous_hash = self.read_all()?.last().map(|e| e.event_hash.clone()).unwrap_or_default();
        let occurred_at = now_unix();
        let event_hash = compute_hash(&previous_hash, occurred_at, resource, action, details);
        let event = AuditEvent {
            occurred_at,
            resource: resource.map(str::to_string),
            action: action.to_string(),
            details: details.map(str::to_string),
            previous_hash,
            event_hash,
        };

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        writeln!(file, "{}", serde_json::to_string(&event)?)?;
        Ok(event)
    }

    pub fn read_all(&self) -> Result<Vec<AuditEvent>, AuditError> {
        if !self.path.is_file() {
            return Ok(Vec::new());
        }
        let file = fs::File::open(&self.path)?;
        let mut events = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            events.push(serde_json::from_str(&line)?);
        }
        Ok(events)
    }

    /// Recomputes every entry's hash from its recorded fields and compares
    /// against what's stored on disk, exactly like Combine Harvester's own
    /// `verify_audit_chain` -- reports the first entry (if any) whose
    /// recorded `previous_hash` or `event_hash` doesn't match.
    pub fn verify(&self) -> Result<AuditVerification, AuditError> {
        let events = self.read_all()?;
        let mut expected_previous = String::new();
        for (index, event) in events.iter().enumerate() {
            let expected_hash = compute_hash(
                &expected_previous,
                event.occurred_at,
                event.resource.as_deref(),
                &event.action,
                event.details.as_deref(),
            );
            if event.previous_hash != expected_previous || event.event_hash != expected_hash {
                return Ok(AuditVerification {
                    valid: false,
                    event_count: events.len(),
                    first_invalid_index: Some(index),
                    head_hash: events.last().map(|e| e.event_hash.clone()).unwrap_or_default(),
                });
            }
            expected_previous = event.event_hash.clone();
        }
        Ok(AuditVerification {
            valid: true,
            event_count: events.len(),
            first_invalid_index: None,
            head_hash: expected_previous,
        })
    }
}

fn compute_hash(
    previous_hash: &str,
    occurred_at: u64,
    resource: Option<&str>,
    action: &str,
    details: Option<&str>,
) -> String {
    let canonical = serde_json::json!([previous_hash, occurred_at, resource, action, details.unwrap_or("")]);
    let mut hasher = Sha256::new();
    hasher.update(canonical.to_string().as_bytes());
    format!("{:x}", hasher.finalize())
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
    use tempfile::TempDir;

    #[test]
    fn first_entry_chains_from_the_empty_genesis_hash() {
        let temp = TempDir::new().unwrap();
        let log = AuditLog::open(&temp.path().join("audit.jsonl"));

        let event = log.append(Some("case-AC"), "lease_granted", None).unwrap();

        assert_eq!(event.previous_hash, "");
        assert!(!event.event_hash.is_empty());
    }

    #[test]
    fn each_entry_chains_to_the_previous_entrys_hash() {
        let temp = TempDir::new().unwrap();
        let log = AuditLog::open(&temp.path().join("audit.jsonl"));

        let first = log.append(Some("case-AC"), "lease_granted", None).unwrap();
        let second = log.append(Some("case-AC"), "artifact_degraded", Some("sha")).unwrap();

        assert_eq!(second.previous_hash, first.event_hash);
    }

    #[test]
    fn verify_passes_on_an_untouched_chain() {
        let temp = TempDir::new().unwrap();
        let log = AuditLog::open(&temp.path().join("audit.jsonl"));
        log.append(Some("case-AC"), "lease_granted", None).unwrap();
        log.append(Some("case-AC"), "artifact_degraded", Some("sha")).unwrap();

        let verification = log.verify().unwrap();

        assert!(verification.valid);
        assert_eq!(verification.event_count, 2);
        assert!(verification.first_invalid_index.is_none());
    }

    #[test]
    fn verify_detects_a_tampered_entry() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("audit.jsonl");
        let log = AuditLog::open(&path);
        log.append(Some("case-AC"), "lease_granted", None).unwrap();
        log.append(Some("case-AC"), "artifact_degraded", Some("sha")).unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = raw.lines().map(str::to_string).collect();
        let mut first: AuditEvent = serde_json::from_str(&lines[0]).unwrap();
        first.details = Some("tampered".to_string());
        lines[0] = serde_json::to_string(&first).unwrap();
        fs::write(&path, lines.join("\n") + "\n").unwrap();

        let verification = log.verify().unwrap();

        assert!(!verification.valid);
        assert_eq!(verification.first_invalid_index, Some(0));
    }

    #[test]
    fn verify_on_an_empty_or_missing_log_is_valid() {
        let temp = TempDir::new().unwrap();
        let missing = AuditLog::open(&temp.path().join("does-not-exist.jsonl"));

        let verification = missing.verify().unwrap();

        assert!(verification.valid);
        assert_eq!(verification.event_count, 0);
    }
}
