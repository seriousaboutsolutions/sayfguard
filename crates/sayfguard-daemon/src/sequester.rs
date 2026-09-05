//! Pre-write sequestration: copy-before-mutate for guarded paths.
//!
//! This is the module that actually satisfies "sequestered securely and
//! retrievable prior to any overwrite or edit" -- see ADR-001 for why this
//! must be a synchronous, lease-gated copy-before-mutate operation rather
//! than an asynchronous reaction to a filesystem watch event.
//!
//! Deliberately does NOT reuse kaptaind's `CaptureAction::Quarantine` name or
//! shape: that action only labels a file to exclude it from a git commit and
//! copies no bytes. Sequestration here always produces a retrievable,
//! encrypted, hash-identified copy. It also deliberately does not reuse
//! kaptaind's `EvidenceRecord` type name (`src/evidence.rs`), which means
//! release/supply-chain provenance in that project; the record type here is
//! `SequesteredArtifact` to avoid the collision.

#![allow(dead_code)]

pub struct SequesteredArtifact {
    pub sha256: String,
    pub sequestered_at: std::time::SystemTime,
    pub source_path: std::path::PathBuf,
    /// Set when the owning case/task is marked complete; see ADR-002.
    pub task_complete: bool,
}
