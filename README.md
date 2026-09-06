# Sayfguard

Lease-gated evidence sequestration and time-boxed retention for data paths
that must never be silently overwritten.

Sayfguard guarantees that a guarded path — a database, an object store, a
quarantine directory — has a secure, retrievable copy taken *before* any
write, overwrite, or delete is allowed to proceed against it, then retains,
degrades, and eventually purges that copy on a defined, auditable schedule.

Read the full specification before implementing anything:

- [`docs/SAYFGUARD_TECHNICAL_DIRECTIVE.md`](docs/SAYFGUARD_TECHNICAL_DIRECTIVE.md)
- [`docs/ADR/ADR-001-lease-gated-sequestration-over-passive-watching.md`](docs/ADR/ADR-001-lease-gated-sequestration-over-passive-watching.md)
- [`docs/ADR/ADR-002-tiered-retention-and-gdpr-posture.md`](docs/ADR/ADR-002-tiered-retention-and-gdpr-posture.md)

## Status

Phase 1 of the deployment-phasing table (technical directive) is
implemented: `lease.rs` and `sequester.rs` are real, tested, and wired into
a CLI (`sayfguard acquire|release|status`). Acquiring a lease synchronously
sequesters the guarded resource by invoking an external backup engine (e.g.
Combine Harvester's `scripts/harvester-backup.py`) before the lease is
granted, per ADR-001; leases persist to a JSON file under `--state-dir` and
are CLI-driven only — there is no resident daemon process yet.

`watcher.rs`, `retention.rs`, and `notify.rs` remain scaffolds (Phases 2-3):
no lease-less-mutation alerting, no automatic retention-stage transitions,
no scheduled 7-day warnings yet. See each module's doc comment.

```
cargo run -p sayfguard-daemon -- \
  --state-dir ./sayfguard-state \
  acquire \
  --resource case-AC/registry --owner alice \
  --registry /path/to/registry.db --objects /path/to/objects \
  --sequester-root ./sequestered --passphrase-file ./passphrase.txt \
  --backup-script /path/to/harvester-backup.py
```

## Origin

This project exists because a live production evidence database was deleted
by an automated test-setup script that treated it as disposable data, with
nothing in place to signal otherwise. The technical directive covers the
incident and the architecture in full.

## Architecture at a glance

Combines two existing patterns rather than inventing from scratch:

- **kaptaind**'s (github.com/elci-group/kaptaind) filesystem watching,
  change clustering, and notification delivery.
- **locksmithd**'s (github.com/elci-group/locksmith) time-boxed resource
  leasing.

Neither alone is sufficient — see the technical directive for why lease
acquisition, not a filesystem watch event, has to be the point where
sequestration happens.
