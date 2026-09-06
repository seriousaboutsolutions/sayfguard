//! Sayfguard: lease-gated evidence sequestration and time-boxed retention.
//!
//! Phase 1 (see the technical directive's deployment-phasing table): lease
//! and sequester modules, driven manually from this CLI. There is no
//! resident daemon process yet -- `watcher.rs`, `retention.rs`, and
//! `notify.rs` remain scaffolds pending Phases 2 and 3. The architecture,
//! retention policy, and GDPR posture are specified in
//! `docs/SAYFGUARD_TECHNICAL_DIRECTIVE.md` and `docs/ADR/`.

mod lease;
mod notify;
mod retention;
mod sequester;
mod watcher;

use clap::{Parser, Subcommand};
use lease::LeaseStore;
use sequester::SequesterConfig;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "sayfguard",
    version,
    about = "Lease-gated evidence sequestration (Phase 1: manual CLI-driven lease acquisition)"
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
