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
  signature format and the legacy plain base64 format.

## Branch convention

Use `claude/<topic>` for all work in this repo.
