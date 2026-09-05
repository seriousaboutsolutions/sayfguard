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

#![allow(dead_code)]

pub struct Lease {
    pub resource: String,
    pub owner: String,
    pub acquired_at: std::time::SystemTime,
    pub ttl: std::time::Duration,
}
