//! Filesystem change detection for guarded paths.
//!
//! Modeled on kaptaind's `src/watcher/` (github.com/elci-group/kaptaind):
//! `notify::recommended_watcher` on a dedicated thread, events piped through
//! an async channel. This module exists for observability and for triggering
//! the retention/notification sweep, NOT as the sequestration mechanism
//! itself -- a `notify` event fires after the OS-level write has already
//! happened, which is too late to guarantee a pre-image exists. See ADR-001.

#![allow(dead_code)]

pub struct WatchedPath {
    pub path: std::path::PathBuf,
}
