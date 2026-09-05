//! Retention-warning delivery.
//!
//! Modeled on kaptaind's `src/angler/webhooks.rs`: HMAC-signed payloads,
//! exponential backoff retry, per-endpoint rate limiting. Scheduling is
//! modeled on kaptaind's `src/schedule/` (a thin wrapper over the `cron`
//! crate's `next_fire_after`). Fires every 7 days from sequestration until
//! the artifact leaves `RetentionStage::FullFidelity`; see ADR-002 for the
//! exact cadence and the reasoning for a recurring rather than one-shot
//! warning.

#![allow(dead_code)]

pub struct RetentionWarning {
    pub artifact_sha256: String,
    pub days_remaining: u32,
}
