# ADR-001: Lease-gated sequestration, not passive watching, is the core mechanism

## Status

Accepted

## Context

Sayfguard exists because a live production evidence database and object
store were destroyed by an automated test-setup script that deleted them
directly, outside the owning application's own write path, with no signal to
any observer that the directory held anything other than disposable data.

kaptaind's filesystem watcher (`notify::recommended_watcher` on a dedicated
thread, `src/watcher/` in github.com/elci-group/kaptaind) is the obvious
architectural starting point, since Sayfguard is explicitly meant to mimic
its diff-based change monitoring. But a `notify` event fires *after* the
underlying write or delete has already completed at the OS level. A purely
reactive watcher can react quickly, but it cannot guarantee a pre-image of
the file existed anywhere before the event fired -- if the destroying process
deletes the only copy in one syscall, there is nothing left to sequester by
the time the watcher's callback runs.

locksmithd (github.com/elci-group/locksmith) solves a related but distinct
problem: coordinating exclusive, time-boxed leases over mutable resources so
concurrent actors don't race each other. It doesn't sequester data, but its
lease model demonstrates the missing piece -- a gate that runs *before* a
mutation is allowed to proceed, not a callback that runs after.

## Decision

Sayfguard combines both: a lease gate in front of every guarded path, and a
watcher for observability and scheduling, but the watcher is never the
mechanism that guarantees preservation.

Any process that wants to write, overwrite, or delete within a guarded path
(a registry database file, an object-store root, a quarantine directory)
must hold a valid lease (`lease.rs`, modeled on locksmith-core's lease
shape) issued by Sayfguard. Acquiring a lease synchronously triggers
sequestration (`sequester.rs`) of the current state of the guarded path
*before* the lease is granted, producing an encrypted, hash-identified,
retrievable copy. Only once that copy exists does the caller receive the
lease and proceed.

A process that mutates a guarded path without holding a lease is not
prevented at the OS level (Sayfguard is not a kernel-level access-control
system), but the absence of a lease is itself detectable and alertable: the
watcher module observes the mutation, finds no corresponding lease, and
raises an integrity alert immediately rather than discovering the gap during
a later audit.

No module may treat kaptaind's `notify`-based watcher as sufficient on its
own for a preservation guarantee. No module may reuse kaptaind's
`CaptureAction::Quarantine` semantics (a git-staging exclusion label, not a
data-preservation action) or its `EvidenceRecord` type name (release
provenance, not forensic evidence) -- see `sequester.rs` for the naming this
displaces.

## Consequences

- Any tool (test harness, migration script, operator shell session) that
  needs to legitimately reset or wipe a guarded path must go through
  Sayfguard's lease API rather than touching files directly. This is a real
  integration cost for every such tool, not just a Sayfguard-side change.
- Sequestration adds latency to the start of any guarded operation
  (proportional to the guarded path's size at that moment), unlike a
  passive watcher which adds none.
- The watcher remains valuable independently: it drives the retention sweep
  schedule (ADR-002) and surfaces lease-less mutations as alerts, which is
  the closest Sayfguard gets to detecting a bypass after the fact.

## Risks

- A caller can still bypass the lease API entirely, as the incident that
  motivated this project demonstrates was possible. Mitigated by the
  watcher's lease-less-mutation alert, and by the deployment requirement
  (see the technical directive) that guarded paths be moved out of
  locations any casual script would target by convention (e.g. a bare
  `data/` directory shared with test fixtures).
- Lease acquisition becomes a single point of contention for
  high-throughput guarded paths. Mitigated by scoping leases to the
  narrowest resource that needs protection (a single database file, not an
  entire directory tree) wherever the guarded system's own structure
  allows it.
