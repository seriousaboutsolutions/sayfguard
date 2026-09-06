//! Sayfguard: lease-gated evidence sequestration and time-boxed retention.
//!
//! Phase 1 (see the technical directive's deployment-phasing table): lease
//! and sequester modules, driven manually from this CLI. Phase 2 adds
//! `watcher.rs` (lease-less-mutation alerting) and the full-fidelity ->
//! degraded transition in `retention.rs`, both reachable below via `watch`,
//! `sweep`, and `complete`. `notify.rs` (Phase 3: scheduled 7-day
//! notifications, degraded -> attested) remains a scaffold. The
//! architecture, retention policy, and GDPR posture are specified in
//! `docs/SAYFGUARD_TECHNICAL_DIRECTIVE.md` and `docs/ADR/`.

mod lease;
mod notify;
mod retention;
mod sequester;
mod watcher;

use clap::{Parser, Subcommand};
use lease::LeaseStore;
use retention::DEFAULT_FULL_FIDELITY_WINDOW_SECS;
use sequester::SequesterConfig;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;
use watcher::WatchedPath;

#[derive(Parser)]
#[command(
    name = "sayfguard",
    version,
    about = "Lease-gated evidence sequestration, lease-less-mutation alerting, and tiered retention"
)]
struct Cli {
    /// Directory holding Sayfguard's lease state (leases.json).
    #[arg(long, global = true, default_value = "./sayfguard-state")]
    state_dir: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Acquire a lease on a guarded resource. Sequesters the resource's
    /// current state first (ADR-001) -- this fails, and grants no lease, if
    /// sequestration fails for any reason.
    Acquire {
        /// Name identifying the guarded resource, e.g. "case-AC/registry".
        #[arg(long)]
        resource: String,
        /// Identity of whoever is requesting the lease.
        #[arg(long)]
        owner: String,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        objects: PathBuf,
        #[arg(long)]
        chronology: Option<PathBuf>,
        /// Directory sequestered archives and manifests are written into.
        #[arg(long)]
        sequester_root: PathBuf,
        #[arg(long)]
        passphrase_file: PathBuf,
        #[arg(long, default_value_t = 900)]
        ttl_seconds: u64,
        #[arg(long, default_value = "python3")]
        python: PathBuf,
        /// Path to the backup engine (e.g. Combine Harvester's
        /// scripts/harvester-backup.py).
        #[arg(long)]
        backup_script: PathBuf,
    },
    /// Release a held lease before its TTL expires.
    Release {
        #[arg(long)]
        resource: String,
        #[arg(long)]
        owner: String,
    },
    /// List currently active (unexpired) leases.
    Status,
    /// Watch guarded paths, alerting on any mutation with no active lease
    /// (ADR-001's bypass-detection mechanism), and run a retention sweep
    /// whenever nothing has fired for `--sweep-interval-seconds`. Blocks
    /// until interrupted.
    Watch {
        /// A guarded path and the resource name its lease is filed under,
        /// as `resource=path`. Repeatable.
        #[arg(long = "guard", value_parser = parse_watched_path, required = true)]
        guards: Vec<WatchedPath>,
        #[arg(long)]
        sequester_root: PathBuf,
        #[arg(long, default_value_t = DEFAULT_FULL_FIDELITY_WINDOW_SECS)]
        window_seconds: u64,
        #[arg(long, default_value_t = 60)]
        sweep_interval_seconds: u64,
    },
    /// Run a retention sweep now: degrades any full-fidelity artifact under
    /// `--sequester-root` that has hit the window or been marked complete
    /// (ADR-002's stage 1 -> stage 2 transition).
    Sweep {
        #[arg(long)]
        sequester_root: PathBuf,
        #[arg(long, default_value_t = DEFAULT_FULL_FIDELITY_WINDOW_SECS)]
        window_seconds: u64,
    },
    /// Mark every sequestered artifact for a resource as task-complete, so
    /// the next sweep degrades them regardless of age (ADR-002:
    /// `min(90 days, task completion)`).
    Complete {
        #[arg(long)]
        resource: String,
        #[arg(long)]
        sequester_root: PathBuf,
    },
}

fn parse_watched_path(raw: &str) -> Result<WatchedPath, String> {
    let (resource, path) = raw
        .split_once('=')
        .ok_or_else(|| format!("expected resource=path, got '{raw}'"))?;
    if resource.is_empty() || path.is_empty() {
        return Err(format!("expected resource=path, got '{raw}'"));
    }
    Ok(WatchedPath {
        resource: resource.to_string(),
        path: PathBuf::from(path),
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let store = match LeaseStore::open(&cli.state_dir) {
        Ok(store) => store,
        Err(error) => {
            eprintln!(
                "sayfguard: failed to open lease state at {}: {error}",
                cli.state_dir.display()
            );
            return ExitCode::FAILURE;
        }
    };

    let outcome = match cli.command {
        Command::Acquire {
            resource,
            owner,
            registry,
            objects,
            chronology,
            sequester_root,
            passphrase_file,
            ttl_seconds,
            python,
            backup_script,
        } => {
            let config = SequesterConfig {
                python,
                backup_script,
                registry_path: registry,
                objects_root: objects,
                chronology_path: chronology,
                sequester_root,
                passphrase_file,
                resource: resource.clone(),
            };
            store
                .acquire(&resource, &owner, Duration::from_secs(ttl_seconds), &config)
                .map(|lease| print_json(&lease))
                .map_err(|error| error.to_string())
        }
        Command::Release { resource, owner } => store
            .release(&resource, &owner)
            .map(|()| println!("released"))
            .map_err(|error| error.to_string()),
        Command::Status => store
            .active_leases()
            .map(|leases| print_json(&leases))
            .map_err(|error| error.to_string()),
        Command::Watch {
            guards,
            sequester_root,
            window_seconds,
            sweep_interval_seconds,
        } => watcher::run(
            &guards,
            &store,
            &sequester_root,
            window_seconds,
            Duration::from_secs(sweep_interval_seconds),
            |alert| {
                eprintln!(
                    "sayfguard: INTEGRITY ALERT: resource '{}' at {} mutated with no active lease (detected at unix time {})",
                    alert.resource,
                    alert.path.display(),
                    alert.detected_at
                );
            },
            |outcomes| {
                let degraded: Vec<_> = outcomes.iter().filter(|o| o.transitioned).collect();
                if !degraded.is_empty() {
                    eprintln!("sayfguard: retention sweep degraded {} artifact(s)", degraded.len());
                }
            },
        )
        .map_err(|error| error.to_string()),
        Command::Sweep {
            sequester_root,
            window_seconds,
        } => retention::sweep(&sequester_root, window_seconds)
            .map(|outcomes| print_json(&outcomes))
            .map_err(|error| error.to_string()),
        Command::Complete {
            resource,
            sequester_root,
        } => retention::mark_task_complete(&sequester_root, &resource)
            .map(|updated| println!("marked {updated} artifact(s) task-complete for '{resource}'"))
            .map_err(|error| error.to_string()),
    };

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("sayfguard: {message}");
            ExitCode::FAILURE
        }
    }
}

fn print_json<T: serde::Serialize>(value: &T) {
    println!("{}", serde_json::to_string_pretty(value).expect("value is always serializable"));
}
