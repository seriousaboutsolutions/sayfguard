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

Scaffold only. `crates/sayfguard-daemon` compiles but has no runtime
behavior yet — see the module doc comments for what each one will own and
which ADR governs it.

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
