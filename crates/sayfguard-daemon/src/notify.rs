//! Retention-warning delivery.
//!
//! Modeled on kaptaind's `src/angler/webhooks.rs` (HMAC-signed payloads,
//! exponential backoff retry) and `src/schedule/` (cadence scheduling), with
//! two deliberate departures recorded here rather than left implicit:
//!
//! - kaptaind's `next_fire_after` computes the next firing of an absolute,
//!   wall-clock cron schedule shared across many event types. Sayfguard's
//!   warning cadence is a *relative*, per-artifact interval -- "every 7 days
//!   from this specific artifact's sequestration time" -- so there is no
//!   shared cron expression to schedule against. `is_due` below tracks each
//!   artifact's own `last_notified_at` instead of pulling in the `cron`
//!   crate for a case it doesn't fit.
//! - kaptaind's rate limiter is a sliding per-endpoint requests-per-minute
//!   window sized for many concurrent event types arriving in real time.
//!   Sayfguard sends to one configured endpoint on a 7-day cadence with
//!   typically few artifacts due at once, so `min_interval_between_sends` (a
//!   flat minimum delay between consecutive deliveries within one notify
//!   run) covers the same "don't hammer the endpoint" intent without the
//!   sliding-window bookkeeping.
//!
//! No warning fires once an artifact leaves `RetentionStage::FullFidelity`
//! (ADR-002) -- there is nothing left to lose at that point. Retention
//! warnings are not chained into the audit trail (`audit.rs`): ADR-002
//! requires that for stage transitions and lease grants, not for
//! notifications about an upcoming one.
//!
//! No webhook is required. The technical directive's own open questions
//! note that "not every deployed context" has an addressable owner to send
//! to; `LogNotifier` is the default so a deployment with nothing configured
//! still gets a visible warning (on stderr) instead of the warning silently
//! never firing.

use crate::retention::{self, RetentionStage};
use crate::sequester::SequesteredArtifact;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use std::path::Path;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// ADR-002's documented cadence.
pub const DEFAULT_NOTIFICATION_INTERVAL_SECS: u64 = 7 * 24 * 60 * 60;

pub const SIGNATURE_HEADER: &str = "X-Sayfguard-Signature";

#[derive(Debug, Clone, Serialize)]
pub struct RetentionWarning {
    pub artifact_sha256: String,
    pub resource: String,
    pub sequestered_at: u64,
    pub sent_at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NotificationOutcome {
    pub resource: String,
    pub artifact_sha256: String,
    pub delivered: bool,
    pub attempts: u32,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial_delay: Duration,
    pub backoff_multiplier: f64,
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(500),
            backoff_multiplier: 2.0,
            max_delay: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NotifyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Retention(#[from] retention::RetentionError),
    #[error("failed to serialize warning: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// A place a `RetentionWarning` can be delivered. `HttpNotifier` is the real
/// implementation; `LogNotifier` is the no-webhook-configured fallback;
/// tests substitute a recording fake.
pub trait Notifier {
    fn deliver(&self, body: &[u8], signature_header: Option<(&str, &str)>) -> Result<(), String>;
}

/// Writes the warning to stderr instead of delivering it anywhere. Always
/// succeeds -- this is the default when no webhook is configured, so a
/// deployment with nothing wired up still gets a visible warning rather than
/// the notification silently vanishing.
pub struct LogNotifier;

impl Notifier for LogNotifier {
    fn deliver(&self, body: &[u8], _signature_header: Option<(&str, &str)>) -> Result<(), String> {
        eprintln!(
            "sayfguard: retention warning (no webhook configured): {}",
            String::from_utf8_lossy(body)
        );
        Ok(())
    }
}

/// Delivers via HTTP POST using a blocking client (`ureq`) -- Sayfguard has
/// no async runtime anywhere else (Phases 1-2 are synchronous throughout),
/// so this stays synchronous rather than pulling in tokio + reqwest for one
/// delivery path.
pub struct HttpNotifier {
    pub url: String,
}

impl Notifier for HttpNotifier {
    fn deliver(&self, body: &[u8], signature_header: Option<(&str, &str)>) -> Result<(), String> {
        let mut request = ureq::post(&self.url).set("Content-Type", "application/json");
        if let Some((name, value)) = signature_header {
            request = request.set(name, value);
        }
        request
            .send_bytes(body)
            .map(|_response| ())
            .map_err(|error| error.to_string())
    }
}

/// True once `artifact` is due another warning: still full-fidelity, and at
/// least `interval_secs` has passed since sequestration or the last warning,
/// whichever is later.
pub fn is_due(artifact: &SequesteredArtifact, now: u64, interval_secs: u64) -> bool {
    if artifact.stage != RetentionStage::FullFidelity {
        return false;
    }
    let last = artifact.last_notified_at.unwrap_or(artifact.sequestered_at);
    now.saturating_sub(last) >= interval_secs
}

/// HMAC-SHA256-signs `body` with `secret`, matching kaptaind's
/// `"sha256=<hex>"` header-value convention (a familiar shape for anything
/// already consuming kaptaind webhooks) under a Sayfguard-specific header
/// name (`SIGNATURE_HEADER`).
pub fn sign(body: &[u8], secret: &str) -> Option<String> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(body);
    Some(format!("sha256={}", hex::encode(mac.finalize().into_bytes())))
}

/// Delivers `body` via `notifier`, retrying on failure per `policy` with
/// exponential backoff (no jitter -- deterministic, so tests don't need to
/// tolerate a jitter window; kaptaind's jitter exists to avoid a thundering
/// herd across many endpoints, which doesn't apply to Sayfguard's single
/// configured endpoint). Returns the number of attempts made on success.
pub fn deliver_with_retry(
    notifier: &dyn Notifier,
    body: &[u8],
    signature_header: Option<(&str, &str)>,
    policy: &RetryPolicy,
) -> Result<u32, String> {
    let mut last_error = String::new();
    for attempt in 1..=policy.max_attempts {
        match notifier.deliver(body, signature_header) {
            Ok(()) => return Ok(attempt),
            Err(error) => {
                last_error = error;
                if attempt < policy.max_attempts {
                    let delay = policy
                        .initial_delay
                        .mul_f64(policy.backoff_multiplier.powi(attempt as i32 - 1))
                        .min(policy.max_delay);
                    thread::sleep(delay);
                }
            }
        }
    }
    Err(last_error)
}

/// Scans every sequestered artifact under `sequester_root`, delivers a
/// `RetentionWarning` for each one due per `interval_secs`, and records
/// `last_notified_at` on successful delivery -- a failed delivery leaves it
/// unset, so the next run retries promptly rather than waiting out the full
/// interval again. `secret` is optional: unsigned payloads still deliver,
/// they're just not verifiable by the receiver.
pub fn run_notifications(
    sequester_root: &Path,
    interval_secs: u64,
    secret: Option<&str>,
    notifier: &dyn Notifier,
    policy: &RetryPolicy,
    min_interval_between_sends: Duration,
) -> Result<Vec<NotificationOutcome>, NotifyError> {
    let now = now_unix();
    let mut outcomes = Vec::new();
    let mut sent_any = false;

    for path in retention::manifest_paths(sequester_root)? {
        let mut artifact = retention::read_manifest(&path)?;
        if !is_due(&artifact, now, interval_secs) {
            continue;
        }

        if sent_any {
            thread::sleep(min_interval_between_sends);
        }

        let warning = RetentionWarning {
            artifact_sha256: artifact.sha256.clone(),
            resource: artifact.resource.clone(),
            sequestered_at: artifact.sequestered_at,
            sent_at: now,
        };
        let body = serde_json::to_vec(&warning)?;
        let signature = secret.and_then(|s| sign(&body, s));
        let signature_header = signature.as_deref().map(|value| (SIGNATURE_HEADER, value));

        let result = deliver_with_retry(notifier, &body, signature_header, policy);
        sent_any = true;

        match result {
            Ok(attempts) => {
                artifact.last_notified_at = Some(now);
                retention::write_manifest(&path, &artifact)?;
                outcomes.push(NotificationOutcome {
                    resource: artifact.resource,
                    artifact_sha256: warning.artifact_sha256,
                    delivered: true,
                    attempts,
                    error: None,
                });
            }
            Err(error) => {
                outcomes.push(NotificationOutcome {
                    resource: artifact.resource,
                    artifact_sha256: warning.artifact_sha256,
                    delivered: false,
                    attempts: policy.max_attempts,
                    error: Some(error),
                });
            }
        }
    }
    Ok(outcomes)
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
    use crate::retention::RetentionStage;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use tempfile::TempDir;

    fn artifact(sequestered_at: u64, last_notified_at: Option<u64>, stage: RetentionStage) -> SequesteredArtifact {
        SequesteredArtifact {
            sha256: "deadbeef".to_string(),
            sequestered_at,
            resource: "case-AC".to_string(),
            source_path: PathBuf::from("/source"),
            archive_path: PathBuf::from("/archive.tar.gpg"),
            manifest_path: PathBuf::from("/archive.manifest.json"),
            task_complete: false,
            stage,
            degraded_at: None,
            last_notified_at,
        }
    }

    #[test]
    fn due_at_the_interval_boundary_from_sequestration() {
        let now = 1_000_000;
        let a = artifact(now - DEFAULT_NOTIFICATION_INTERVAL_SECS, None, RetentionStage::FullFidelity);

        assert!(is_due(&a, now, DEFAULT_NOTIFICATION_INTERVAL_SECS));
    }

    #[test]
    fn not_due_before_the_first_interval_elapses() {
        let now = 1_000_000;
        let a = artifact(now - 100, None, RetentionStage::FullFidelity);

        assert!(!is_due(&a, now, DEFAULT_NOTIFICATION_INTERVAL_SECS));
    }

    #[test]
    fn due_again_one_interval_after_the_last_notification_not_after_sequestration() {
        let now = 1_000_000_000;
        // Sequestered long ago, but notified recently -- should not be due
        // yet even though it's long past the sequestration-relative window.
        let a = artifact(
            now - 100 * DEFAULT_NOTIFICATION_INTERVAL_SECS,
            Some(now - 100),
            RetentionStage::FullFidelity,
        );

        assert!(!is_due(&a, now, DEFAULT_NOTIFICATION_INTERVAL_SECS));
    }

    #[test]
    fn never_due_once_degraded() {
        let now = 1_000_000_000;
        let a = artifact(now - 10 * DEFAULT_NOTIFICATION_INTERVAL_SECS, None, RetentionStage::Degraded);

        assert!(!is_due(&a, now, DEFAULT_NOTIFICATION_INTERVAL_SECS));
    }

    #[test]
    fn sign_produces_a_verifiable_hmac() {
        let body = b"{\"resource\":\"case-AC\"}";
        let signature = sign(body, "secret").unwrap();

        assert!(signature.starts_with("sha256="));
        // Signing again with the same inputs is deterministic.
        assert_eq!(signature, sign(body, "secret").unwrap());
        // A different secret produces a different signature.
        assert_ne!(signature, sign(body, "other-secret").unwrap());
    }

    struct FailingNotifier {
        failures_then_success: Mutex<u32>,
    }

    impl Notifier for FailingNotifier {
        fn deliver(&self, _body: &[u8], _signature_header: Option<(&str, &str)>) -> Result<(), String> {
            let mut remaining = self.failures_then_success.lock().unwrap();
            if *remaining > 0 {
                *remaining -= 1;
                Err("simulated failure".to_string())
            } else {
                Ok(())
            }
        }
    }

    struct AlwaysFailingNotifier;

    impl Notifier for AlwaysFailingNotifier {
        fn deliver(&self, _body: &[u8], _signature_header: Option<(&str, &str)>) -> Result<(), String> {
            Err("simulated permanent failure".to_string())
        }
    }

    fn fast_retry_policy() -> RetryPolicy {
        RetryPolicy {
            max_attempts: 3,
            initial_delay: Duration::from_millis(1),
            backoff_multiplier: 1.0,
            max_delay: Duration::from_millis(2),
        }
    }

    #[test]
    fn deliver_with_retry_succeeds_after_transient_failures() {
        let notifier = FailingNotifier {
            failures_then_success: Mutex::new(2),
        };

        let attempts = deliver_with_retry(&notifier, b"body", None, &fast_retry_policy()).unwrap();

        assert_eq!(attempts, 3);
    }

    #[test]
    fn deliver_with_retry_gives_up_after_max_attempts() {
        let error = deliver_with_retry(&AlwaysFailingNotifier, b"body", None, &fast_retry_policy()).unwrap_err();

        assert_eq!(error, "simulated permanent failure");
    }

    fn write_artifact(dir: &Path, resource: &str, sequestered_at: u64) {
        let archive_path = dir.join(format!("{resource}.tar.gpg"));
        let manifest_path = dir.join(format!("{resource}.manifest.json"));
        let artifact = SequesteredArtifact {
            sha256: "deadbeef".to_string(),
            sequestered_at,
            resource: resource.to_string(),
            source_path: dir.join("source"),
            archive_path,
            manifest_path: manifest_path.clone(),
            task_complete: false,
            stage: RetentionStage::FullFidelity,
            degraded_at: None,
            last_notified_at: None,
        };
        fs::write(&manifest_path, serde_json::to_string_pretty(&artifact).unwrap()).unwrap();
    }

    struct RecordingNotifier {
        deliveries: Mutex<Vec<Vec<u8>>>,
    }

    impl Notifier for RecordingNotifier {
        fn deliver(&self, body: &[u8], _signature_header: Option<(&str, &str)>) -> Result<(), String> {
            self.deliveries.lock().unwrap().push(body.to_vec());
            Ok(())
        }
    }

    #[test]
    fn run_notifications_delivers_due_artifacts_and_records_last_notified_at() {
        let temp = TempDir::new().unwrap();
        let now = now_unix();
        write_artifact(temp.path(), "case-AC", now - DEFAULT_NOTIFICATION_INTERVAL_SECS - 10);
        let notifier = RecordingNotifier {
            deliveries: Mutex::new(Vec::new()),
        };

        let outcomes = run_notifications(
            temp.path(),
            DEFAULT_NOTIFICATION_INTERVAL_SECS,
            None,
            &notifier,
            &fast_retry_policy(),
            Duration::from_millis(0),
        )
        .unwrap();

        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].delivered);
        assert_eq!(notifier.deliveries.lock().unwrap().len(), 1);

        let manifest_path = temp.path().join("case-AC.manifest.json");
        let updated = retention::read_manifest(&manifest_path).unwrap();
        assert_eq!(updated.last_notified_at, Some(now));
    }

    #[test]
    fn run_notifications_skips_artifacts_not_yet_due() {
        let temp = TempDir::new().unwrap();
        let now = now_unix();
        write_artifact(temp.path(), "case-AC", now);
        let notifier = RecordingNotifier {
            deliveries: Mutex::new(Vec::new()),
        };

        let outcomes = run_notifications(
            temp.path(),
            DEFAULT_NOTIFICATION_INTERVAL_SECS,
            None,
            &notifier,
            &fast_retry_policy(),
            Duration::from_millis(0),
        )
        .unwrap();

        assert!(outcomes.is_empty());
    }

    #[test]
    fn run_notifications_does_not_update_last_notified_at_on_delivery_failure() {
        let temp = TempDir::new().unwrap();
        let now = now_unix();
        write_artifact(temp.path(), "case-AC", now - DEFAULT_NOTIFICATION_INTERVAL_SECS - 10);

        let outcomes = run_notifications(
            temp.path(),
            DEFAULT_NOTIFICATION_INTERVAL_SECS,
            None,
            &AlwaysFailingNotifier,
            &fast_retry_policy(),
            Duration::from_millis(0),
        )
        .unwrap();

        assert!(!outcomes[0].delivered);
        let manifest_path = temp.path().join("case-AC.manifest.json");
        let updated = retention::read_manifest(&manifest_path).unwrap();
        assert!(updated.last_notified_at.is_none());
    }

    #[test]
    fn log_notifier_always_succeeds() {
        assert!(LogNotifier.deliver(b"test", None).is_ok());
    }
}
