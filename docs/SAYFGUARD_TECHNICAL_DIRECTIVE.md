# Sayfguard Technical Directive

**Date**: 2026-09-05
**Status**: Draft specification — no runtime implementation yet (scaffold only)
**Prepared by**: Claude Sonnet 5, on behalf of Serious About Solutions
**Governing ADRs**: [ADR-001](ADR/ADR-001-lease-gated-sequestration-over-passive-watching.md), [ADR-002](ADR/ADR-002-tiered-retention-and-gdpr-posture.md)

---

## Executive summary

Sayfguard is a Rust daemon that guarantees any guarded data path — a
database file, an object store, a quarantine directory — has a secure,
retrievable copy taken *before* any write, overwrite, or delete is allowed
to proceed against it, and that copy is retained, degraded, and eventually
purged on a defined, auditable schedule.

It exists because a live production evidence database (Combine Harvester's
case registry and object store, holding a real client's legal case) was
deleted by an automated test-setup script that treated the directory as
disposable, with nothing in place to signal otherwise, no lease/permission
check before the delete, and no backup less than twelve days stale. This
directive specifies the system that prevents a repeat.

Sayfguard borrows two existing architectures rather than inventing from
scratch: kaptaind's (github.com/elci-group/kaptaind) filesystem-watching,
clustering, and notification-delivery machinery, and locksmithd's
(github.com/elci-group/locksmith) time-boxed resource-leasing model. Neither
alone is sufficient — kaptaind's watcher is reactive and fires after a
write has already happened; locksmithd's leases coordinate access but don't
preserve data. Sayfguard's core architectural decision (ADR-001) is that
the lease grant itself is the point at which sequestration happens,
synchronously, before the lease is issued — not a side effect of watching
for changes after the fact.

---

## The incident this directive addresses

During routine verification of an unrelated frontend change, an automated
end-to-end test suite (Playwright) was run against what was assumed to be
disposable development data. Its setup script, by design, deletes and
recreates the target data directory before every test run — a legitimate
and correct thing to do against a throwaway fixture directory. The problem
was that the throwaway fixture directory and the real production data
directory were the same path, with nothing distinguishing them and nothing
gating the delete.

The result: a real case's database rows, and the underlying evidence files
in the object store and quarantine directories, were deleted. The most
recent backup available was twelve days old (produced by
`scripts/harvester-backup.py`, which is correct and already handles
encryption and integrity verification well — it simply wasn't run on a
schedule). Anything harvested in the gap between that backup and the
incident is not recoverable from any copy found on disk.

Three independent failures compounded: no isolation between disposable and
real data, no gate in front of the destructive operation, and no recent
backup. Sayfguard is designed to close the first two structurally, and to
schedule the third rather than leave it to manual discipline.

---

## Architecture

### Why passive watching alone was rejected

kaptaind's watcher (`src/watcher/`) runs `notify::recommended_watcher` on a
dedicated thread and delivers `FsEvent`s after the underlying OS write
completes. This is the right architecture for kaptaind's own purpose —
reacting to completed code changes to compute a version bump — but it
cannot be the primary mechanism here: if a destroying process deletes the
only copy of a file in one syscall, a watcher callback firing microseconds
later has nothing left to sequester. A reactive design can shrink the
window of loss; it cannot close it.

### Why leasing alone was rejected

locksmithd's lease model (`crates/locksmith-core`) is the right shape for
"nothing mutates a resource without permission," but locksmithd doesn't
preserve anything — a lease holder is free to destroy the resource once
they hold the lease. Reusing the lease *coordination* mechanism without
adding preservation would have given us permission-checking with no safety
net.

### The combined model

1. **Lease gate** (`lease.rs`) — any process wanting to mutate a guarded
   path must request a lease from Sayfguard first.
2. **Synchronous sequestration** (`sequester.rs`) — granting the lease
   triggers an immediate, encrypted, hash-identified copy of the guarded
   path's current state. The lease is not issued until this copy exists.
3. **Watcher** (`watcher.rs`) — retained from kaptaind's model, but
   demoted to an observability and scheduling role: it drives the
   retention sweep's timing and flags any mutation that occurred without a
   corresponding lease as an integrity alert.
4. **Tiered retention** (`retention.rs`) — sequestered copies degrade
   through three stages on a schedule; see ADR-002 and the section below.
5. **Notification** (`notify.rs`) — HMAC-signed, retried, rate-limited
   delivery modeled on kaptaind's `src/angler/webhooks.rs`, scheduled via
   the `cron`-based pattern in kaptaind's `src/schedule/`.

Deliberate naming departures from kaptaind, recorded so a future
integration attempt doesn't assume shared vocabulary: Sayfguard's
sequestration is not kaptaind's `CaptureAction::Quarantine` (that only
excludes a file from a git commit; it copies nothing), and Sayfguard's
`SequesteredArtifact` is not kaptaind's `EvidenceRecord` (that type means
release/supply-chain provenance in kaptaind, not forensic evidence).

### What Sayfguard does not do

It is not a kernel-level access-control system. A process with direct
filesystem access can still bypass the lease API entirely, exactly as
happened in the motivating incident. Sayfguard's answer to that is
twofold: make bypass detectable (the watcher's lease-less-mutation alert)
and make bypass less likely by removing the structural cause (guarded
paths should not sit in a location — like a bare `data/` shared with test
fixtures — that invites a disposable-data assumption). Closing the bypass
path in Combine Harvester specifically (separating its real data directory
from its e2e test fixture directory) is tracked as an integration
prerequisite below, not something Sayfguard's daemon alone can fix.

---

## Retention, degrade, and GDPR posture

See ADR-002 for the full reasoning; summarized here for reference.

| Stage | Trigger | Contents | Purpose |
|---|---|---|---|
| Full-fidelity | Sequestration time | Encrypted bytes + manifest | Immediately restorable safety net |
| Degraded | `min(90 days, task completion)` | Manifest only (hash, provenance, timestamps) | Proof of correct handling, no personal data retained |
| Attested | Fixed grace period after degrade (default 30 days) | Hash-chain entry only | Permanent audit continuity, nothing retrievable |

Notifications fire every 7 days from sequestration for as long as an
artifact remains full-fidelity, addressed to whoever owns the task/case so
the warning is actionable, and stop once nothing is left to lose.

**On GDPR**: no data-protection policy exists anywhere in the codebase this
directive was written against, so this is establishing a first policy, not
aligning with an existing one. The assumed lawful basis — legitimate
interest in operational continuity, and, for litigation evidence
specifically, the establishment/exercise/defence of legal claims — is an
engineering assumption that requires confirmation from the deploying
organization's data protection counsel before Sayfguard handles real
personal data in production. This directive does not constitute that
confirmation, and no claim of GDPR compliance should be made on the basis
of this document alone. What this design does provide, concretely: a
bounded storage-limitation window (stage transitions), purpose limitation
(sequestered copies are explicitly not a second archive), a defined erasure
cascade requirement for upstream systems to implement against, and
encryption plus tamper-evident audit trail for security and accountability.

---

## Relationship to existing tooling

Sayfguard does not reimplement encryption or integrity verification.
Combine Harvester's `scripts/harvester-backup.py` already does this
correctly: SQLite's online-consistent `.backup()` API, a full re-hash of
every committed blob against its filename-encoded SHA-256 before
finalizing, and GPG/AES-256 symmetric encryption of the resulting archive.
Sayfguard's sequestration step should invoke this script (or an equivalent
already-verified engine for a non-Combine-Harvester protected system)
rather than hand-rolling a second encryption path. This also means
Sayfguard is a natural home for the "Disaster recovery" item already listed
in `docs/DEVELOPMENT_STATE_AND_ROADMAP.md` (item 5: scheduled, verified,
signed recovery) — that item and this daemon should be planned together,
not as two separate initiatives that duplicate each other.

Sayfguard's audit trail is hash-chained, matching Combine Harvester's own
`audit_events` standard rather than locksmithd's unchained `AuditRecord`
shape (`crates/locksmith-core/src/audit.rs`) — a system built to protect
evidence should not have weaker tamper-evidence than the evidence it
protects.

---

## Integration prerequisites (not Sayfguard's to fix alone)

Before Sayfguard can protect Combine Harvester specifically:

1. **Separate real and test data directories.** The e2e suite's
   `global-setup.ts` must be repointed at a disposable directory (e.g.
   `data-e2e/`) that is never the same path as production `data/`. This is
   the single highest-value fix and would have prevented the motivating
   incident on its own, independent of whether Sayfguard exists yet.
2. **Wire lease acquisition into every entry point that can mutate a
   guarded path** — the harvest-submit handler, the backup/restore script,
   and any test or migration tooling that touches `data/` directly.
3. **Define a task/case completion signal** Combine Harvester can emit to
   Sayfguard, so the retention window can end early instead of always
   running the full 90 days.
4. **Implement or designate an erasure-request handler** upstream, since
   Combine Harvester does not currently have one, and Sayfguard's erasure
   cascade (ADR-002) has nothing to cascade from without it.

---

## Deployment phasing

| Phase | Scope | Depends on | Status |
|---|---|---|---|
| 0 | This directive + ADRs + Rust workspace scaffold | — | Done |
| 1 | Lease + sequester modules; invoke `harvester-backup.py` as the encryption engine; manual lease acquisition via CLI | ADR-001 | Done — `lease.rs`, `sequester.rs`, `sayfguard acquire\|release\|status` |
| 2 | Watcher + lease-less-mutation alerting; retention stage transitions (full-fidelity → degraded) | Phase 1 | Not started |
| 3 | Notification scheduling (7-day cadence); degraded → attested transition; hash-chained audit trail | Phase 2 | Not started |
| 4 | Combine Harvester integration: data-directory separation (prerequisite 1 above, can and should happen independently of Sayfguard's own timeline), lease wiring, completion signal, erasure cascade | Phases 1-3 + prerequisite 1 | Not started |

Phase 4's Combine-Harvester-specific integration work is deliberately
listed last in Sayfguard's own build order but should be scheduled in
parallel, since prerequisite 1 (directory separation) requires no
Sayfguard code at all and closes the largest part of the actual risk on
its own.

---

## Open questions requiring sign-off before production use

- Confirmation of lawful basis and retention windows from data protection
  counsel (see GDPR posture above) — engineering cannot resolve this
  unilaterally.
- Whether 90 days is the right default window for this organization's
  actual case durations, or should be configured per deployment from day
  one rather than defaulting silently.
- Who receives the 7-day retention warnings in practice — an individual
  case owner, a shared inbox, or an on-call rotation — since the
  notification design assumes an addressable owner that not every deployed
  context will have.

---

## Conclusion

The incident this directive responds to was not a failure of any single
tool — the test runner did exactly what its setup script told it to do,
correctly, against the wrong directory, with nothing in the system able to
tell the difference. Sayfguard's job is to make that difference visible and
enforceable: nothing overwrites a guarded path without first proving a
retrievable copy exists, and every such copy has a bounded, auditable
lifetime instead of living or dying by manual discipline. The architecture
here reuses proven patterns from kaptaind and locksmithd rather than
inventing new ones, and is deliberately scoped so that the single highest-
value fix (separating real data from disposable test fixtures) doesn't wait
on the daemon's full build-out to happen.
