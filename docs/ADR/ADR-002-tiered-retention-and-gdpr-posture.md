# ADR-002: Tiered retention, not a single purge date, governs sequestered copies

## Status

Accepted

## Context

The requirement is that sequestered copies "degrade after 90 days or task
completion" and that a notification system warn at 7-day intervals. Taken
literally, "degrade" implies something more graduated than a single
delete-on-day-90 cliff edge, and the 90-day/task-completion pairing needs a
concrete precedence rule.

Sequestered copies are a short-term operational safety net against
accidental loss (the incident that motivated this project), not the
canonical evidentiary record. The canonical record is whatever system
Sayfguard is protecting (for Combine Harvester: its SQLite registry and
content-addressed object store, retained per that project's own case-length
retention rules). Conflating the two would be a mistake: a legal case can
run far longer than 90 days, but Sayfguard's copies exist to catch
operational accidents in the near term, not to serve as a second permanent
archive.

No GDPR-relevant policy exists anywhere in the codebase this directive was
written against (confirmed: no retention statement, lawful-basis statement,
or data-subject-rights language in `docs/THREAT_MODEL.md` or elsewhere).
This ADR is establishing a first policy, not aligning with an existing one.
locksmithd's retention sweeper (`crates/locksmith-core/src/manager.rs`)
exports records to a JSONL archive before pruning them from the live store,
which is a reasonable shape for stage transitions but was designed for
operational audit logs, not personal data subject to erasure rights, and
has no GDPR-specific concept (no lawful basis field, no erasure-request
handling) to inherit from.

## Decision

A sequestered artifact moves through three retention stages, entered at
`min(90 days since sequestration, task/case completion signal)` for the
first transition:

1. **Full-fidelity** -- encrypted bytes plus manifest, immediately
   restorable. This is the only stage capable of satisfying "sequestered
   securely and retrievable."
2. **Degraded** -- entered at the 90-day/completion trigger. Bytes are
   purged; only the manifest (hash, provenance metadata, timestamps)
   remains. This is what "degrade" means here: proof that preservation
   happened, without continuing to hold the underlying personal/case data
   past the point its operational purpose (accident recovery) has expired.
3. **Attested** -- entered a fixed grace period after stage 2 (default 30
   days). The manifest itself is purged; only a tamper-evident entry in
   Sayfguard's audit hash chain remains, sufficient to prove the artifact
   existed and was retired correctly, with no personal data retrievable
   from it at all.

The notification system fires a warning every 7 days from the moment of
sequestration for as long as an artifact remains in the full-fidelity stage,
addressed to the artifact's owning task/case rather than to Sayfguard
operators generically, so the warning is actionable by whoever can mark the
task complete. No warning fires once an artifact leaves full-fidelity --
there is nothing left to lose at that point.

Data subject erasure requests against the protected system must cascade to
Sayfguard: an erasure applied to the canonical record deletes any
corresponding sequestered artifact in stages 1 or 2 immediately, not on the
normal schedule. This is a required integration point for whatever handles
erasure requests upstream (Combine Harvester does not currently implement
one), not something Sayfguard can satisfy unilaterally.

The lawful basis assumed for processing personal data incidental to
sequestered case evidence is legitimate interest in operational continuity
of the protected system, and, where the protected data is itself litigation
evidence, the establishment/exercise/defence of legal claims. This is an
engineering assumption, not a legal determination -- it must be confirmed
by the deploying organization's data protection counsel before Sayfguard
handles real personal data in production, and this ADR does not constitute
that confirmation.

Sayfguard's audit trail for every stage transition and every lease grant
must be hash-chained (each entry includes the previous entry's hash),
matching Combine Harvester's own audit-chain standard rather than
locksmithd's unchained `AuditRecord` shape -- a system built to protect
evidence should not have weaker tamper-evidence than the evidence it
protects.

## Consequences

- Sequestered copies are never a substitute for the protected system's own
  long-term retention; documentation and onboarding must say this
  explicitly so operators don't mistake Sayfguard for an archive.
- The degrade-to-manifest stage gives auditors a permanent, lightweight
  record of every preservation event without the storage or compliance
  liability of holding the bytes indefinitely.
- Task-completion as a trigger requires the protected system to actually
  signal completion to Sayfguard; systems that never signal completion fall
  back to the 90-day default, which must be stated as the safe default in
  the technical directive's integration guidance.

## Risks

- 90 days may be shorter than some jurisdictions' or firms' operational
  recovery expectations for a case-length incident. Mitigated by making the
  window configurable per deployment, with 90 days as the documented
  default rather than a hard-coded constant.
- An erasure cascade that isn't actually wired up by the protected system
  leaves Sayfguard holding personal data an erasure request should have
  removed. Mitigated by treating "erasure cascade implemented" as a
  required item in any deployment's go-live checklist, not an optional
  enhancement.
- Legal-claims-defence as a lawful basis does not automatically extend to
  every category of data a protected system might contain (e.g. special
  category data). Mitigated by requiring per-deployment legal review before
  production use, stated explicitly above rather than assumed away.
