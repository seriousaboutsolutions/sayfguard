//! Sayfguard: lease-gated evidence sequestration and time-boxed retention.
//!
//! Phase 1 (see the technical directive's deployment-phasing table): lease
//! and sequester modules, driven manually from this CLI. Phase 2 adds
//! `watcher.rs` (lease-less-mutation alerting) and the full-fidelity ->
//! degraded transition in `retention.rs`, reachable via `watch`, `sweep`,
//! and `complete`. Phase 3 adds `notify.rs` (scheduled 7-day warnings, via
//! `notify`), the degraded -> attested transition (folded into `sweep`),
//! and `audit.rs` (a hash-chained trail for every lease grant and stage
//! transition, inspectable via `audit-verify`). The architecture, retention
//! policy, and GDPR posture are specified in
//! `docs/SAYFGUARD_TECHNICAL_DIRECTIVE.md` and `docs/ADR/`.

mod audit;
mod lease;
mod notify;
mod retention;
mod sequester;
mod watcher;

use audit::AuditLog;
use clap::{Parser, Subcommand};
use lease::LeaseStore;
use notify::{HttpNotifier, LogNotifier, Notifier, RetryPolicy};
use retention::{DEFAULT_ATTESTED_GRACE_SECS, DEFAULT_FULL_FIDELITY_WINDOW_SECS};
use sequester::SequesterConfig;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;
use watcher::WatchedPath;

#[derive(Parser)]
#[command(
    name = "sayfguard",
    version,
    about = "Lease-gated evidence sequestration, lease-less-mutation alerting, tiered retention, and retention-warning delivery"
)]
struct Cli {
    /// Directory holding Sayfguard's lease state (leases.json).
    #[arg(long, global = true, default_value = "./sayfguard-state")]
    state_dir: PathBuf,

    /// Path to Sayfguard's hash-chained audit log (ADR-002: every lease
    /// grant and retention-stage transition is recorded here). Defaults to
    /// `<state-dir>/audit.jsonl` -- deliberately derived from `--state-dir`
    /// rather than given its own independent literal default, so overriding
    /// `--state-dir` alone can't silently leave the audit log behind in the
    /// old location.
    #[arg(long, global = true)]
    audit_log: Option<PathBuf>,

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
        #[arg(long, default_value_t = DEFAULT_ATTESTED_GRACE_SECS)]
        attest_grace_seconds: u64,
        #[arg(long, default_value_t = 60)]
        sweep_interval_seconds: u64,
    },
    /// Run a retention sweep now: degrades any due full-fidelity artifact
    /// under `--sequester-root` (ADR-002 stage 1 -> 2) and attests any
    /// degraded artifact past its grace period (stage 2 -> 3, which purges
    /// its manifest -- only the audit-log entry survives).
    Sweep {
        #[arg(long)]
        sequester_root: PathBuf,
        #[arg(long, default_value_t = DEFAULT_FULL_FIDELITY_WINDOW_SECS)]
        window_seconds: u64,
        #[arg(long, default_value_t = DEFAULT_ATTESTED_GRACE_SECS)]
        attest_grace_seconds: u64,
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
    /// Deliver a retention warning for every full-fidelity artifact due one
    /// (ADR-002's 7-day cadence, counted from sequestration or the last
    /// warning). Delivers to `--webhook-url` if given (HMAC-signed with
    /// `--secret-file` if that's also given), otherwise logs the warning to
    /// stderr.
    Notify {
        #[arg(long)]
        sequester_root: PathBuf,
        #[arg(long, default_value_t = notify::DEFAULT_NOTIFICATION_INTERVAL_SECS)]
        interval_seconds: u64,
        #[arg(long)]
        webhook_url: Option<String>,
        /// File containing the HMAC secret used to sign delivered payloads.
        /// Ignored (with a warning) if `--webhook-url` isn't also set.
        #[arg(long)]
        secret_file: Option<PathBuf>,
        #[arg(long, default_value_t = 200)]
        min_interval_between_sends_ms: u64,
    },
    /// Verify Sayfguard's hash-chained audit log hasn't been tampered with,
    /// mirroring Combine Harvester's own `verify_audit_chain`.
    AuditVerify,
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
    let audit_log_path = cli
        .audit_log
        .clone()
        .unwrap_or_else(|| cli.state_dir.join("audit.jsonl"));
    let audit_log = AuditLog::open(&audit_log_path);

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
                .acquire(&resource, &owner, Duration::from_secs(ttl_seconds), &config, &audit_log)
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
            attest_grace_seconds,
            sweep_interval_seconds,
        } => watcher::run(
            &guards,
            &store,
            &sequester_root,
            window_seconds,
            attest_grace_seconds,
            &audit_log,
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
                let transitioned: Vec<_> = outcomes.iter().filter(|o| o.transitioned).collect();
                if !transitioned.is_empty() {
                    eprintln!("sayfguard: retention sweep transitioned {} artifact(s)", transitioned.len());
                }
            },
        )
        .map_err(|error| error.to_string()),
        Command::Sweep {
            sequester_root,
            window_seconds,
            attest_grace_seconds,
        } => retention::sweep(&sequester_root, window_seconds, attest_grace_seconds, &audit_log)
            .map(|outcomes| print_json(&outcomes))
            .map_err(|error| error.to_string()),
        Command::Complete {
            resource,
            sequester_root,
        } => retention::mark_task_complete(&sequester_root, &resource)
            .map(|updated| println!("marked {updated} artifact(s) task-complete for '{resource}'"))
            .map_err(|error| error.to_string()),
        Command::Notify {
            sequester_root,
            interval_seconds,
            webhook_url,
            secret_file,
            min_interval_between_sends_ms,
        } => {
            if secret_file.is_some() && webhook_url.is_none() {
                eprintln!("sayfguard: --secret-file has no effect without --webhook-url; ignoring it");
            }
            let secret = match &webhook_url {
                Some(_) => match secret_file {
                    Some(path) => match std::fs::read_to_string(&path) {
                        Ok(contents) => Some(contents.trim().to_string()),
                        Err(error) => {
                            eprintln!("sayfguard: failed to read secret file {}: {error}", path.display());
                            return ExitCode::FAILURE;
                        }
                    },
                    None => None,
                },
                None => None,
            };
            let notifier: Box<dyn Notifier> = match &webhook_url {
                Some(url) => Box::new(HttpNotifier { url: url.clone() }),
                None => Box::new(LogNotifier),
            };
            notify::run_notifications(
                &sequester_root,
                interval_seconds,
                secret.as_deref(),
                notifier.as_ref(),
                &RetryPolicy::default(),
                Duration::from_millis(min_interval_between_sends_ms),
            )
            .map(|outcomes| print_json(&outcomes))
            .map_err(|error| error.to_string())
        }
        Command::AuditVerify => audit_log
            .verify()
            .map(|verification| print_json(&verification))
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
