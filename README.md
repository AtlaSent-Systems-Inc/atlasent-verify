# atlasent-audit-verify

Standalone, source-open CLI that independently validates an AtlaSent
audit-chain export — with **no AtlaSent runtime cooperation, no network
calls, and no database access**. Specified by **ADR-020** in
[`atlasent-docs`](https://github.com/AtlaSent-Systems-Inc/atlasent-docs/blob/main/architecture/adr/ADR-020-external-audit-verify-cli.md).
Canonical form specified by
`atlasent-docs/architecture/specs/audit-chain-canonical-form.md`
(currently at v5).

This repository is the public home of the verifier: its source is
auditable by a customer's or auditor's security team **without an NDA**,
and its releases are reproducibly built and signed. The differentiated
value of the AtlaSent audit chain is that a non-AtlaSent operator can run
this verifier on their own machine, against bundles AtlaSent gave them,
and produce a self-contained proof that the chain is intact.

## Status

**Beta.** Single-file canonicalizer + chain verifier; Ed25519 signature
verification wired; Cosign-keyless signed multi-platform releases;
byte-identical reproducible builds verified on every PR; a weekly
trust-chain canary.

## Build

```
go build -o atlasent-audit-verify ./cmd/atlasent-audit-verify
```

Produces a statically-linkable binary (`CGO_ENABLED=0` recommended for
full static linkage; the verifier has no cgo deps).

## Install a signed release

Download the binary for your platform from the
[Releases](https://github.com/AtlaSent-Systems-Inc/atlasent-verify/releases)
page, then verify it before use. Each artifact is signed with Sigstore
Cosign (keyless OIDC) — no long-lived AtlaSent key is involved, so you
verify against the public transparency log, not against us:

```bash
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/AtlaSent-Systems-Inc/atlasent-verify/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature <artifact>.sig \
  --certificate <artifact>.pem \
  <artifact>
```

Or verify the aggregate `CHECKSUMS.txt` once (with its `.sig` + `.pem`)
and then `sha256sum -c CHECKSUMS.txt` for each artifact you downloaded.

## Use

```
atlasent-audit-verify --chain chain.ndjson --keys keys.pem --head head.json
```

- `--chain` — newline-delimited JSON (one entry per line), in causal
  order per `org_id`. Use `-` to read from stdin.
- `--keys` — *(optional)* PEM file containing Ed25519 public keys, each
  PEM block with a header `kid` (the `key_version` selector). If absent,
  signature verification is skipped and the CLI says so.
- `--head` — *(optional)* a trusted head-anchor JSON file obtained **out
  of band** (independent of the export). Enables tail-truncation
  detection — see "Completeness / anti-truncation" below.
- `--version` — print version + supported chain-version and exit.

Exit codes:

- `0` — chain valid under the supplied keys (and, if `--head` given,
  complete up to the trusted head).
- `1` — at least one finding (chain break, signature mismatch, ordering
  violation, canonical-form drift, or — with `--head` — truncation /
  head-hash mismatch / missing anchored org).
- `2` — environment error (missing flag, unreadable file, malformed PEM,
  malformed anchor file).

### Completeness / anti-truncation (`--head`)

Hash continuity proves every entry *present* chains correctly, but a
**tail truncation** — silently dropping entries from the *end* — leaves a
shorter, still-internally-valid chain. Continuity alone cannot catch it.
Closing that gap requires one piece of out-of-band trusted state: the
chain head.

Supply it via `--head`, a JSON file the customer obtains through a
channel independent of the export (a published transparency anchor, a
contractual attestation, a prior verified run):

```json
{
  "anchors": [
    { "org_id": "org-1", "sequence": 4096, "entry_hash": "<64-char lowercase hex>" }
  ]
}
```

With an anchor present the verifier additionally reports, per anchored
org:

- `truncation` — the chain's verified head is **below** the anchor
  sequence (entries dropped from the tail, or a break short of head).
- `head_hash_mismatch` — head sequence matches the anchor but the
  `entry_hash` differs (the head entry was substituted).
- `anchor_org_missing` — an anchored org has no verified entries.
- `anchor_behind` — the chain extends **past** the anchor (stale anchor
  or entries appended after it; reconcile before trusting either side).

Orgs in the chain but absent from the anchor set are not flagged — the
anchor set is authoritative only for the orgs it names. Without `--head`
the CLI prints a note that completeness was **not** checked, so the
limitation is never silent.

## What the CLI verifies

Per ADR-020 + the canonical-form spec:

1. Hash chain continuity:
   `entry.entry_hash == SHA-256(previous_hash_bytes || canonical_payload)`.
2. Signature validity (Ed25519) under the key identified by
   `key_version`.
3. Causal ordering (strict monotonic sequence per `(org_id, principal_id)`;
   gaps are findings).
4. Genesis-entry constraints (sequence == 1, 32-zero previous_hash,
   `chain_version >= 5`).
5. Canonical-form re-serialization: parsing each entry and
   re-canonicalizing reproduces the bytes that were hashed.
6. Completeness (with `--head`): the verified per-org head matches a
   trusted out-of-band anchor — the only check that detects tail
   truncation.

## What the CLI does NOT do

- Network calls — none.
- Database access — none.
- Semantic policy validation ("should this principal have been
  allowed?") — out of scope. Audit verification is structural, not
  policy.
- Modification of the chain — read-only.

## Layout

```
cmd/atlasent-audit-verify/   main entrypoint
internal/canonical/          JSON canonicalizer (audit-chain v5 form)
internal/chain/              chain entry types + verify loop + head anchors
internal/keys/               PEM keystore (kid → ed25519.PublicKey)
```

## Tests

```
go test ./...
```

Tests are golden-data driven: a small fixed chain is hashed, signed (with
a fixture key), and re-verified. Any canonical-form drift in
`internal/canonical` fails the golden test, so the test suite IS the
canonical-form lock. **Do not edit a golden value to make a failing test
pass** — treat the failure as a canonical-form regression and fix the
canonicalizer (a genuine change is a chain-version bump per the spec).

## Releases

Tagged releases (`vX.Y.Z`) trigger
[`release.yml`](.github/workflows/release.yml), which:

1. Builds a fully-static binary for each platform in the matrix
   (`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`,
   `windows/amd64`).
2. Computes SHA-256 checksums.
3. Signs each artifact with Sigstore Cosign keyless via GitHub Actions
   OIDC — no long-lived private key.
4. Publishes to a GitHub Release.

## Reproducibility

Builds are reproducible: two cold builds with identical flags produce
byte-identical binaries. This is verified by
[`reproducibility.yml`](.github/workflows/reproducibility.yml) on every
PR — if any change to build flags, dependencies, or the Go toolchain
breaks reproducibility, the PR fails before merge.

The canonical reproducibility build flags are:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build \
    -trimpath \
    -buildvcs=false \
    -ldflags "-s -w -buildid= -X main.Version=<version>" \
    -o atlasent-audit-verify \
    ./cmd/atlasent-audit-verify
```

## Trust-chain canary

[`canary.yml`](.github/workflows/canary.yml) runs weekly (Mondays 12:00
UTC). It catches breakage that build-time CI cannot: Sigstore TUF root
rotations, Fulcio / OIDC drift, and verifier-source rot. It builds from
current source, runs `go test` against the golden fixtures, and
re-verifies the latest released binary under the current Sigstore trust
root — surfacing breakage within 7 days. It supplements, but does not
replace, the human quarterly proof.

## Versioning

The CLI is version-pinned 1:1 with the AtlaSent runtime release. The
canonical-form version (currently v5) and the chain-version supported are
stamped into `--version` output. Bumping the supported chain-version is
the canonical-form-spec version bump.

## References

- ADR-020 (External audit-verify CLI).
- `atlasent-docs/architecture/specs/audit-chain-canonical-form.md`.
- ADR-019 (Authority key lifecycle) — what `key_version` refers to.

## License

Apache-2.0 — see [`LICENSE`](LICENSE). The verifier is source-open so it
can be audited without an NDA (ADR-020 § "Distribution & trust").
