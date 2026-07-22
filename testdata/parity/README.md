# Offline-verifier parity fixture

This directory holds the committed fixture behind the **parity CI job**
(`.github/workflows/parity.yml`) and the in-repo parity test
(`cmd/atlasent-audit-verify/parity_test.go`). Together they continuously
prove that an AtlaSent audit-chain export in canonical **v5** form verifies
cleanly under the standalone `atlasent-audit-verify` CLI — closing pilot
blocker **B2** / SOC2 **GAP-030** ("no CI job proves service-output ⇄ CLI
parity").

## Files

| File | What it is |
|---|---|
| `chain.ndjson` | A 3-entry v5 audit-chain export (`evaluation.completed` events; allow/deny mix; `decision` / `decision_id` / `engine_version` / evaluation `payload` populated as the runtime writes them). |
| `keys.pem` | The Ed25519 **public** key, with a `kid` header equal to each entry's `key_version` (`audit-r3-2026-07`). |
| `head.json` | The trusted head anchor (`org_id`, highest `sequence`, that entry's `entry_hash`) for the `--head` anti-truncation / completeness check. |
| `gen/main.go` | The deterministic generator that produced the three files above (build-tagged `//go:build ignore`). |

## What the CI job runs

```
atlasent-audit-verify \
  --chain testdata/parity/chain.ndjson \
  --keys  testdata/parity/keys.pem \
  --head  testdata/parity/head.json \
  --require-signatures
```

It asserts **exit 0** plus the strict-acceptance evidence lines:

- `ACCEPTED (--require-signatures): 3/3 entr(ies) signature-verified … 0 skipped`
- `ok: 3 signature(s) verified`
- `ok: 1/1 anchored head(s) match — no tail truncation`

`--require-signatures` is load-bearing: it turns a *skipped* signature
(unknown `key_version`) into exit 1, so a green run positively proves the
correct key was loaded and **every** signature was checked — not that the
chain merely satisfied hash continuity.

## Provenance — this fixture is SYNTHETIC and DETERMINISTIC

- The signing key is derived from a **fixed, in-source 32-byte seed**
  (`gen/main.go`). It is a throwaway **test** key — **not** a production
  key, and the file holds only its **public** half.
- The data is **not** a real tenant export. `org_id`, actors, and
  decision IDs are obviously-synthetic placeholders.
- Every `entry_hash` and `signature` is produced by the repo's **own**
  canonicalizer (`internal/canonical`) and `crypto/ed25519`, exactly
  mirroring `internal/chain.canonicalizeForHash` — including the v5
  invariant that `engine_version` is **additive metadata excluded from
  the chain hash** (it is emitted in each line yet stripped before
  hashing).

Regenerate byte-identically at any time:

```
go run testdata/parity/gen/main.go
```

Because the seed is fixed and the canonicalizer is the repo's own, the
output is reproducible and fully auditable — nothing here is hand-computed
or hand-signed.

## What this proves — and the remaining gap

**Proven, continuously, with no network or prod access:** a correctly
**canonicalized, signed v5 export verifies under the CLI** with strict
signature acceptance and completeness — i.e. **canonical-form ⇄ CLI
parity**. The canonical-form contract exercised is identical to the one
the runtime must satisfy, because the same `internal/canonical` package
produces the bytes.

**Not proven here (the documented gap):** that the **runtime service**
emits bytes that are byte-identical in canonical form and signed by the
real **R3 audit key**. Establishing that end-to-end requires a genuine
export the CI environment cannot obtain without prod/staging access. It is
an **operator step against staging**:

1. Drive one or more real evaluations on a staging tenant so
   `audit_events` gains signed `evaluation.completed` rows.
2. Export the chain via `v1-export-audit` (NDJSON, v5 canonical form).
3. Fetch the matching R3 public JWKS from the trust root
   (`atlasent-keys` → `.well-known/atlasent-verifier-keys.json`) and
   convert to PEM (`kid` = `key_version`).
4. Obtain the trusted head anchor out-of-band (transparency anchor) for a
   real `--head` completeness check.
5. Run the exact CLI invocation above against those real files and retain
   the `ACCEPTED (--require-signatures)` output as pilot evidence.

That staging round-trip is the last mile of B2; this fixture makes the CLI
side of the contract a permanent, self-contained CI gate so a canonical-form
or signature-format regression is caught the moment it lands — independent
of when the staging proof is next run.
