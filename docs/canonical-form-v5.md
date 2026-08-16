# AtlaSent Audit Chain Canonical Form — Version 5

**Status:** Public verification contract for chain version 5.

This document freezes the byte-level serialization, hashing, signing, and
completeness rules used by `atlasent-audit-verify`. Its purpose is to let an
independent party recompute the same result without trusting the AtlaSent
runtime.

## Entry schema

A version-5 audit entry contains these top-level fields:

| Field | Type | Verification meaning |
|---|---|---|
| `chain_version` | integer | Must be `5` for this contract. |
| `org_id` | string | Tenant identifier. |
| `sequence` | integer | Monotonic sequence within the chain. |
| `event_type` | string | Event category. |
| `actor_id` | string | Principal associated with the event. |
| `decision` | string or null | `allow`, `hold`, `deny`, `escalate`, or null for non-decision events. |
| `decision_id` | string or null | Stable decision identifier when applicable. |
| `engine_version` | string or null | Runtime engine identifier bound into the hash. |
| `payload` | object | Event-specific body. |
| `previous_hash` | string | 64-character lowercase SHA-256 hex of the prior entry; all zeroes for genesis. |
| `entry_hash` | string | 64-character lowercase SHA-256 hex for this entry. |
| `key_version` | string | Selects the Ed25519 public verification key. |
| `signature` | string | Standard-base64 Ed25519 signature over the raw entry-hash digest. |

`entry_hash` and `signature` are produced by the writer; the verifier recomputes
and validates them independently.

## Canonical JSON

Before hashing, the entry with `entry_hash` and `signature` removed is serialized
recursively using these rules:

1. Object keys are sorted lexicographically by Unicode code point.
2. No insignificant whitespace, BOM, or trailing newline is emitted.
3. Strings are UTF-8. Required JSON escapes are used; non-ASCII characters are
   emitted as UTF-8 rather than gratuitous `\uXXXX` escapes.
4. Integers have no leading zero, `+` sign, or trailing `.0`. Floating-point
   values are not valid canonical payload scalars; use strings when a
   non-integer scalar must be represented.
5. Booleans and null are the lowercase JSON literals `true`, `false`, and `null`.
6. Array order is preserved and each element is canonicalized recursively.
7. Duplicate object keys are invalid and must fail verification.

A conforming implementation should satisfy:

```text
canonicalize(parse(canonicalize(x))) == canonicalize(x)
```

## Hash formula

```text
canonical_payload = canonicalize(entry_without_entry_hash_and_signature)
entry_hash = lowercase_hex(
  SHA-256(previous_hash_bytes || canonical_payload)
)
```

`previous_hash_bytes` is the raw 32-byte digest represented by
`previous_hash`, not the 64-byte ASCII hex string. For a genesis entry it is 32
zero bytes.

## Signature

- Algorithm: Ed25519.
- Signed bytes: the raw 32-byte digest represented by `entry_hash`.
- Key selection: `key_version` identifies the public verification key.
- JSON encoding: `signature` uses standard base64, not URL-safe base64.

## Genesis

The first entry of a version-5 chain must have:

```text
sequence = 1
chain_version = 5
previous_hash = 0000000000000000000000000000000000000000000000000000000000000000
```

A verifier must reject a chain whose genesis record violates these rules.

## Export format

The CLI consumes newline-delimited JSON (`.ndjson`), one entry per line. Entries
for a given `org_id` are supplied in causal sequence order. A file may contain
more than one organization chain.

Continuity proves that the entries *present* in an export were not altered or
reordered. It does not by itself prove that the tail was not truncated.

## Head anchor and completeness

To test completeness, supply a trusted head anchor with `--head`:

```json
{
  "anchors": [
    {
      "org_id": "org-1",
      "sequence": 4096,
      "entry_hash": "<64-character lowercase hex>"
    }
  ]
}
```

For every anchored organization, the verifier distinguishes these outcomes:

| Condition | Finding |
|---|---|
| verified sequence is below anchor | `truncation` |
| same sequence but different entry hash | `head_hash_mismatch` |
| anchored org is absent from the export | `anchor_org_missing` |
| verified sequence is beyond the anchor | `anchor_behind` |

Without `--head`, the CLI must state that completeness was not checked. An
internally valid prefix is not the same claim as a complete export.

## Versioning rule

A new `chain_version` is required when a change alters bytes covered by the
hash, including a change to the top-level entry fields, canonical serialization,
hash function, or chaining formula. Purely event-specific payload evolution does
not by itself require a chain-version bump.

A verifier may support multiple chain versions, but it must never silently
interpret a newer unknown version as an older one.

## Reference implementation

The source in this repository is the executable reference for this public
contract:

- `internal/canonical/` — canonical JSON implementation
- `internal/chain/` — entry validation, continuity, signatures, and head anchors
- `cmd/atlasent-audit-verify/` — CLI behavior and exit codes

Golden fixtures and tests lock the emitted bytes. Changing a golden value merely
to make a regression pass is not a valid versioning strategy.
