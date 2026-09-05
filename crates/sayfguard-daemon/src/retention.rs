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
//! to stage 3 fires a fixed grace period after stage 2. Uses the encryption
//! and integrity-verification already implemented in
//! combine-harvester's `scripts/harvester-backup.py` rather than
//! reimplementing GPG/AES handling here -- see the technical directive,
//! "Relationship to existing tooling."

#![allow(dead_code)]

pub enum RetentionStage {
    FullFidelity,
    Degraded,
    Attested,
}
