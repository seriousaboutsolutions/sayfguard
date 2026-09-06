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

All three of the technical directive's daemon-logic phases (1-3) are
implemented; only Phase 4 (Combine Harvester-specific integration) remains.

**Phase 1** — `lease.rs` and `sequester.rs` are real, tested, and wired into
a CLI. Acquiring a lease synchronously sequesters the guarded resource by
invoking an external backup engine (e.g. Combine Harvester's
`scripts/harvester-backup.py`) before the lease is granted, per ADR-001;
leases persist to a JSON file under `--state-dir`.

**Phase 2** — `watcher.rs` watches guarded paths for real (via the `notify`
crate) and raises an integrity alert whenever a mutation occurs with no
active lease on record for that resource (ADR-001's bypass-detection
mechanism). `retention.rs` implements ADR-002's stage 1 -> stage 2
transition: `sayfguard sweep` degrades any full-fidelity artifact that has
hit the retention window or been marked complete via `sayfguard complete`,
deleting the encrypted archive bytes while keeping the manifest.

**Phase 3** — `retention.rs` also now performs stage 2 -> 3 (degraded ->
attested): once past the grace period, `sweep` deletes the manifest itself,
leaving only a hash-chained entry in `audit.rs`'s tamper-evident log
(`sayfguard audit-verify` checks it, mirroring Combine Harvester's own
`verify_audit_chain`). Every lease grant is chained into that same log.
`notify.rs` delivers a retention warning for every full-fidelity artifact
due one (`sayfguard notify`) -- HMAC-signed and retried with backoff if a
`--webhook-url` is configured, logged to stderr otherwise, since not every
deployment has an addressable owner to send to.

There is still no resident daemon process managing all of this together —
`watch` is one long-running CLI invocation an operator or supervisor (e.g. a
systemd service) starts explicitly, and `sweep`/`notify` are meant to be run
periodically (cron, a systemd timer) rather than continuously.

```
cargo run -p sayfguard-daemon -- \
  --state-dir ./sayfguard-state \
  acquire \
  --resource case-AC/registry --owner alice \
  --registry /path/to/registry.db --objects /path/to/objects \
  --sequester-root ./sequestered --passphrase-file ./passphrase.txt \
  --backup-script /path/to/harvester-backup.py

# In a separate, long-running process:
cargo run -p sayfguard-daemon -- \
  --state-dir ./sayfguard-state \
  watch --guard case-AC/registry=/path/to/registry.db \
  --sequester-root ./sequestered

# Periodically (e.g. from cron or a systemd timer):
cargo run -p sayfguard-daemon -- sweep --sequester-root ./sequestered
cargo run -p sayfguard-daemon -- notify --sequester-root ./sequestered \
  --webhook-url https://example.org/sayfguard-warnings \
  --secret-file ./webhook-secret.txt

# Check the audit trail hasn't been tampered with:
cargo run -p sayfguard-daemon -- --state-dir ./sayfguard-state audit-verify
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
