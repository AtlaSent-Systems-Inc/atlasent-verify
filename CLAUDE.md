# CLAUDE.md — atlasent-verify

Standalone, source-open CLI that independently validates an AtlaSent audit-chain export
per **ADR-020**. Read-only, no network, no database access. Specified by
`atlasent-docs/architecture/specs/audit-chain-canonical-form.md` (currently v5).

## What this repo does

`atlasent-audit-verify` is the offline audit chain verifier for AtlaSent evaluation
records. It accepts a newline-delimited JSON (NDJSON) chain export and verifies:

1. **Hash chain continuity** — every `entry_hash` matches
   `SHA-256(previous_hash_bytes || canonical_payload)`.
2. **Ed25519 signatures** — when a PEM keyfile is supplied (`--keys`), each entry's
   signature is checked against the key identified by `key_version`.
3. **Causal ordering** — strict monotonic sequence per `(org_id)`, gaps are findings.
4. **Genesis entry constraints** — sequence == 1, 32-zero previous_hash, chain_version >= 5.
5. **Canonical-form re-serialization** — re-canonicalizing each entry reproduces the
   bytes that were hashed.
6. **Completeness / anti-truncation** — when an out-of-band anchor file is supplied
   (`--head`), the verified per-org head is compared to the trusted anchor to detect
   tail truncation.

The verifier is source-open so it can be audited by a customer or auditor without an
NDA. Its releases are reproducibly built and Sigstore-signed.

## Two input shapes: NDJSON chain vs signed export ENVELOPE

The CLI accepts two shapes and **auto-detects** between them (an envelope is a
single JSON object carrying `public_key_pem`/`evaluations` and no
`chain_version`/`entry_hash`; anything else is treated as NDJSON):

1. **NDJSON audit chain** — the per-row hash-chain + Ed25519 verification above.
2. **Signed export ENVELOPE** — the `v1-export-audit` bundle: one JSON object
   with record arrays (`evaluations`, `verification_events`,
   `correlation_events`, …), a `key_id`, an embedded `public_key_pem`, and an
   **outer** Ed25519 signature over `jcs.Canonicalize(envelope-minus-signature)`.
   The non-`evaluations` arrays ride that outer signature; they are **not**
   folded into the per-row `entry_hash` chain (ADR-020 offline-verifier parity;
   ADR-048 single evidence ledger).

### Envelope verification is 4 independent layers

`internal/envelope` produces a `VerificationResult` with four verdicts —
`envelope_integrity`, `ledger_integrity`, `correlation_integrity`,
`archive_integrity`. The
machine-readable (`--json`) wire vocabulary is `verified` / `invalid` /
`absent` (plus `verified_untrusted_key` for the envelope layer when the outer
signature verifies only against the envelope's **embedded** `public_key_pem`,
i.e. trust is not externally anchored via `--keys`). `correlation_integrity`
is `verified` only when the outer signature is valid **AND** every correlation
reference is internally valid — never merely because the outer signature
verified. A verified correlation layer additionally reports a per-stage
`correlation_stages` tally (`permit_resolved` / `observed` / `not_observed`)
that backs the CLI's honest Permit / Observation / Correlation lifecycle lines
— a stage line is shown only when real records evidence it.

- **Envelope** — the outer Ed25519 signature (standard base64, distinct from
  the NDJSON per-row `ed25519:<base64url>`), verified against a **trusted** key
  resolved from `--keys` by `key_id`. Any tampering with any record (including a
  correlation field) breaks this signature.
- **Ledger** — the `evaluations[]` entry-hash chain: `entry_hash ==
  sha256_hex(canonical_payload)` (the execution_evaluations scheme embeds
  `prev_hash` as `canonical_payload`'s trailing field) plus prev_hash→entry_hash
  continuity. Genesis is **not** asserted (an export is a window).
- **Correlation** — semantic validation of `correlation_events[]` against the
  **other records in the same signed envelope**. A correlation record is
  verified only when its reference resolves in-export (by `permit_token_hash` /
  `decision_id`), the lifecycle is permitted (permit → execution → observation →
  correlation; a correlation for a non-`allow` Decision is contradictory), the
  action/target bindings agree with the same-permit verification record, and
  there is no duplicate/conflict. `correlation_protection` is always
  `outer_envelope_signature`. Absence of correlation records is a SUCCESS
  (`absent`), never an error.
- **Evidence Archive** — semantic validation of `retrieval_events[]` (governed
  archive DISCLOSURES) and `probe_events[]` (sampled-object integrity
  VERDICTS), added at certification version 5. Same posture as correlation:
  the signature proves the bytes weren't altered; this layer asks whether the
  records are internally coherent and anchored to the rest of the bundle.
  Absence is a SUCCESS (`absent`) — that is every v4-and-earlier bundle, and
  every v5 bundle from an org with no archive activity.

Machine-readable failure codes: `ENVELOPE_SIGNATURE_INVALID`,
`UNSUPPORTED_ENVELOPE_VERSION`, `LEDGER_HASH_MISMATCH`, `LEDGER_CHAIN_BROKEN`,
`CORRELATION_REFERENCE_MISSING`, `CORRELATION_REFERENCE_OUTSIDE_EXPORT`,
`CORRELATION_ORG_MISMATCH`, `CORRELATION_ACTION_MISMATCH`,
`CORRELATION_TARGET_MISMATCH`, `CORRELATION_DECISION_MISMATCH`,
`CORRELATION_LIFECYCLE_INVALID`,
`CORRELATION_DUPLICATE`, `CORRELATION_CONFLICT`,
`ARCHIVE_REFERENCE_MISSING`, `ARCHIVE_REFERENCE_OUTSIDE_EXPORT`,
`ARCHIVE_ORG_MISMATCH`, `ARCHIVE_DUPLICATE`, `ARCHIVE_CONFLICT`,
`ARCHIVE_OUTCOME_UNKNOWN`, `UNSUPPORTED_CERTIFICATION_VERSION`,
`CERTIFICATION_COUNT_MISMATCH`.

`CORRELATION_DECISION_MISMATCH` (added alongside this hardening pass) fires
when a correlation's declared `decision_id` disagrees with the Decision its
own `permit_token_hash` actually resolves to in the export — i.e. the
record's two reference fields point at two different decisions ("a permit
belonging to another decision"). Distinct from
`CORRELATION_REFERENCE_OUTSIDE_EXPORT`: here the reference DOES resolve,
just to the wrong Decision.

The `ARCHIVE_*` family is deliberately separate from `CORRELATION_*`: a
consumer branching on codes must be able to tell "the post-execution
correlation section is incoherent" from "the archive-disclosure section is
incoherent" — different owners, different remediations.

**Org binding honesty:** org binding is reported per section
(`org_binding` for correlation, `archive_org_binding` for the archive
sections) with three states — `checked`, `not_present_in_export`, and
`not_applicable` (no records of that kind). A record carrying no
`organization_id` is reported as `not_present_in_export`, never as a pass; and
when some records in a section carry it and some do not, the weaker state is
reported, because a partial check is not a check.

### Evidence Archive layer (certification version 5)

Two sections, four distinct states, reported separately — the distinctions are
load-bearing. "The archive was read" is not "the read was allowed", and "a
probe ran" is not "the bytes were confirmed". `archive_stages` carries all of
`retrieval_attempted` / `retrieval_succeeded` / `retrieval_failed` /
`probe_executed` / `integrity_confirmed` / `integrity_failed` /
`integrity_inconclusive`.

`integrity_inconclusive` is **never** folded into confirmed or failed. A probe
that ran and had nothing to check against is a third fact; a reader given only
two buckets will read it as one of them.

Rejected per record: MISSING required fields (a disclosure with no WHAT, WHO,
or WHY is a rumour of a disclosure, not evidence of one), DUPLICATE ids (they
inflate any count an auditor derives), CROSS-ORGANIZATION records, UNKNOWN
outcomes (a status outside the closed vocabulary would be read as neither
success nor failure), CONFLICTS (a success recording no bytes; a refusal
recording released bytes; a refusal with no reason code; a `verified` probe
with no subject hash), and OUT-OF-BUNDLE references (a disclosure naming a
`decision_id` the export does not contain — reported only when the bundle
carries evaluations at all, since a narrow export legitimately has none).

**Denials are first-class.** They are exported, verified, and counted, because
a bundle carrying only successful reads makes "nobody was refused" and
"refusals were dropped" indistinguishable.

#### Retention is RECORDED, never verified

`retention_assurance` has exactly three values — `not_applicable`,
`not_recorded`, and `recorded_not_verified_offline` — and **there is no fourth**.
This verifier is offline by contract: it never contacts an object store, so
exported retention metadata is a claim the producer recorded, not proof that a
retention lock exists on real storage. `archive_retention_records` is a count
of *claims recorded*, and a record whose `archive_retention_enforced` is not
true is deliberately not counted (a term the provider never accepted is not a
recorded retention).

**Do not add a code path that upgrades this.** Support for these records in
the export format is not evidence that a six-year retention guarantee is
active; that requires provider-enforced storage and a live acceptance run.

#### Certification version gate

`SupportedCertificationVersion = 5`. A **lower** version is accepted unchanged
— v1–v4 bundles predate the archive sections and verify exactly as before,
which is the backward-compatibility contract. A **higher** version fails closed
(`UNSUPPORTED_CERTIFICATION_VERSION`): a newer producer may bind sections this
build cannot see, and silently ignoring them would report a partial check as a
complete one. The manifest's `record_counts` census is cross-checked against
the arrays present (`CERTIFICATION_COUNT_MISMATCH`) — only for sections the
manifest actually declares, so an older manifest is not treated as claiming
zero.

#### ADR-052 spec stamp — echoed, never checked

An envelope may carry a top-level `audit_chain_spec`
(`{spec_id, spec_version, adr, evaluation_chain_versions}`) — the ADR-052
provenance stamp naming which revision of
`atlasent-docs/architecture/audit-chain-v1-spec.md` the **producer** claims to
have conformed to. It is emitted by `atlasent-api`'s `v1-export-audit`.

Three rules, all load-bearing:

- **It is a producer claim, not a verification result.** A verified outer
  signature proves these bytes are the bytes the producer signed; it does not
  prove the producer conformed to the revision it names, and this tool checks
  none of it. The CLI prints it labelled `DECLARED BY PRODUCER, not verified by
  this tool`, and `evaluation_chain_versions` is echoed as declared — **not**
  re-derived from `evaluations[]`, so a green run does not rule out a mismatch
  between that list and the rows.
- **Absence is a clean pass, permanently.** Every bundle exported before the
  stamp existed has no `audit_chain_spec`, and its `--json` output is
  byte-identical to what it was before this field was added (both new keys are
  `omitempty`). This is the same backward-compatibility contract the pre-v5
  archive sections get.
- **There is deliberately NO version gate on it.** Unlike
  `certification.version` — which gates because it selects the recompute
  formula — this field selects nothing, so no value of it can fail a bundle or
  relax one. **Do not add a ceiling, a finding, or a branch that varies
  verification behaviour on it**: a self-described spec version that could
  switch verification paths would let a producer choose how strictly it is
  checked. The stamp is echoed only after the outer signature verifies; an
  unauthenticated stamp is not surfaced at all.

None of this is a canonical-form change: `entry_hash`, `canonical_payload`, and
the v5 export projection are untouched.

Committed deterministic fixtures live in `cmd/atlasent-audit-verify/testdata/`
(`archive-export.json`, signed once under a fixed key; the trusted keyfile is
derived from the fixture at test time because `.gitignore` blanket-ignores
`*.pem`). If
canonicalization or the wire shape ever drifts, the committed signature stops
verifying and the drift surfaces in CI rather than in a customer's audit.

### JCS canonicalization (`internal/jcs`)

The outer signature is computed over RFC 8785 JCS bytes. `internal/jcs`
reproduces `atlasent-api/supabase/functions/_shared/canonical.ts`
**byte-for-byte** (sorted UTF-16 keys at all depths, JSON.stringify string
escaping, ECMAScript `Number::toString` for numbers) — verified against the
real producer over a parity-vector suite. This is a distinct canonical form
from `internal/canonical` (the per-row audit-chain pipe form).

```bash
# Verify a signed export envelope against a trusted R3 audit-export key
atlasent-audit-verify --chain export.json --keys keys.pem

# Strict acceptance: require the outer signature to verify against a TRUSTED
# key (not merely the envelope's embedded public_key_pem)
atlasent-audit-verify --chain export.json --keys keys.pem --require-signatures

# Machine-readable result
atlasent-audit-verify --chain export.json --keys keys.pem --json
```

## How to run the verifier

```bash
# Build
go build -o atlasent-audit-verify ./cmd/atlasent-audit-verify

# Verify a chain export with signature checking
atlasent-audit-verify --chain chain.ndjson --keys keys.pem

# Strict acceptance (pilot evidence): fail unless EVERY entry's signature was
# verified against a known key. A skipped signature (unknown key_version)
# becomes a failure, so exit 0 positively proves the correct key was loaded.
atlasent-audit-verify --chain chain.ndjson --keys keys.pem --require-signatures

# Also check completeness against a trusted head anchor
atlasent-audit-verify --chain chain.ndjson --keys keys.pem --head head.json

# Read chain from stdin
cat chain.ndjson | atlasent-audit-verify --chain - --keys keys.pem

# Run tests
go test -race -count=1 ./...
```

Exit codes: `0` = valid, `1` = findings (integrity failures), `2` = environment error.

## Audit chain v5 schema

The chain export is NDJSON; each line is one entry with these fields:

| Field | Type | Notes |
|---|---|---|
| `chain_version` | integer | Must be >= 5 for this verifier |
| `org_id` | string | Org identifier |
| `sequence` | integer | Monotonically increasing per org (1-based, no gaps) |
| `event_type` | string | e.g. `evaluation.completed` |
| `actor_id` | string | The actor for this evaluation |
| `decision` | string? | Optional: `allow`, `deny`, `hold`, `escalate` |
| `decision_id` | string? | Optional: UUID of the evaluation decision |
| `engine_version` | string? | Optional: `"<name>@<semver>"` e.g. `"wire-v1@1.0.0"` — **ADDITIVE METADATA** |
| `payload` | object | Evaluation event payload |
| `previous_hash` | string | 64-char lowercase hex; all-zeros for genesis |
| `entry_hash` | string | 64-char lowercase hex — `SHA-256(prev_hash_bytes \|\| canonical_payload)` |
| `key_version` | string | Selects which Ed25519 key was used to sign |
| `signature` | string | `"ed25519:<base64url>"` (v5) or plain base64 (legacy) |

### Signature field format (v5)

The `signature` field in v5 uses the prefixed format:

```
"ed25519:<base64url-no-padding>"
```

Example: `"ed25519:a1b2c3..."` where the value after the colon is
base64url-encoded (RFC 4648 §5, URL-safe alphabet, no `=` padding) and
represents the 64-byte Ed25519 signature over the 32-byte `entry_hash` digest.

Legacy exports (pre-v5) use plain standard-base64 without a prefix. The verifier
accepts both for backwards compatibility.

### key_version field

`key_version` identifies which Ed25519 public key signed the entry. The verifier
resolves it from the PEM keyfile supplied via `--keys`. Each PEM block must carry
a `kid` header matching the `key_version` value.

If a `key_version` is not present in the supplied keyfile, the verifier emits a
**warning** (not a finding) and continues. The hash chain is still verified; only
the signature check is skipped for that entry. This allows operators to verify
chains that span key rotations when they only have the current key, without
causing a false-positive integrity failure.

### `--require-signatures` (strict acceptance) — exit 0 must MEAN "signatures verified"

The default warn-on-skip behaviour has a trap for acceptance evidence: run with
`--keys keys.pem` where `keys.pem` does **not** contain the exported chain's
`key_version`, and *every* signature is silently skipped — yet the run still
exits 0 on hash continuity alone. A bare exit 0 is therefore **not** proof that
signatures were verified.

`--require-signatures` closes this. It requires `--keys`, and turns a skipped
signature into a **failure** (exit 1). On success it prints a positive
`ACCEPTED` line stating how many signatures were verified and that zero were
skipped. Use it whenever the verifier output is being preserved as pilot /
acceptance evidence — it guarantees the correct verification key was loaded and
every entry was actually signature-checked. Every run (strict or not) now also
prints a `signature(s) verified` coverage line when `--keys` is supplied, so a
green run is self-describing.

The counts backing this live on `chain.Result` (`SignaturesVerified` /
`SignaturesSkipped`) with the pure contract helper
`Result.StrictSignatureAcceptance(keysSupplied bool)`.

### engine_version — ADDITIVE METADATA, NOT in the chain hash

**INVARIANT: `engine_version` is NOT included in the chain hash.**

The AtlaSent runtime writes `engine_version` to the `audit_events` table as an
additive evidence field. It was deliberately excluded from the canonical payload
fed to SHA-256 (see the audit chain v5 spec and the migration log entry for
`20260524020000_audit_chain_v5_engine_version.sql`).

Consequence for the verifier: when recomputing `entry_hash`, the verifier strips
`engine_version` (along with `entry_hash` and `signature`) from the entry before
canonicalizing. This means:

- An entry WITH `engine_version` in the exported JSON verifies correctly.
- An entry WITHOUT `engine_version` verifies correctly.
- The presence or absence of the field does not affect the hash.

Do not include `engine_version` in any hash recomputation. Any change to this
invariant is a canonical-form spec version bump.

## Architecture

```
cmd/atlasent-audit-verify/   main entrypoint + CLI flags
internal/canonical/          JSON canonicalizer (audit-chain v5 canonical form)
internal/chain/              entry types, verify loop, head anchors, key interface
internal/envelope/           signed-export envelope: outer signature, ledger,
                             correlation (correlation.go), Evidence Archive
                             disclosures + integrity probes (archive.go)
internal/jcs/                RFC 8785 JCS canonicalizer (outer-signature bytes)
internal/keys/               PEM keystore (kid → ed25519.PublicKey)
.github/workflows/
  ci.yml                     vet + test (race) + static build sanity on every PR
  release.yml                signed multi-platform release on vX.Y.Z tags
  reproducibility.yml        byte-identical reproducibility check on every PR
  canary.yml                 weekly trust-chain canary (Sigstore + golden fixtures)
```

## Key rules

- **Read-only** — no network calls, no DB access, no chain modification.
- **Canonical-form lock** — any change to `internal/canonical/canonical.go` is a chain-version
  bump. Do not edit golden test values to fix a failing test; fix the canonicalizer.
- **Fail findings only, warn for recoverable** — unknown `key_version` is a warning
  (printed to stderr, exit 0). Hash mismatches, chain breaks, and signature failures
  against known keys are findings (exit 1). **Exception:** under `--require-signatures`
  a skipped signature (unknown `key_version`) is promoted to a failure (exit 1) — see
  the strict-acceptance section above.
- **Backwards compatible** — the verifier accepts both the v5 prefixed `"ed25519:<base64url>"`
  signature format and the legacy plain base64 format. On the envelope path,
  certification versions 1–5 are all accepted; a bundle with no Evidence
  Archive sections verifies exactly as it did before those sections existed.
- **Never claim retention this tool cannot observe** — the verifier is offline
  by contract, so `retention_assurance` tops out at
  `recorded_not_verified_offline`. Do not add a branch that reports retention
  as verified, and do not let CLI wording imply a live retention guarantee
  because the export format carries the records.

## Branch convention

Use `claude/<topic>` for all work in this repo.
