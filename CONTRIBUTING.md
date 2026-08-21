# Contributing to atlasent-audit-verify

Thanks for your interest in this repo. This is the offline, read-only AtlaSent
audit-chain verifier (ADR-020) — no network calls, no database access, no
chain modification. Contributions should preserve that contract.

## Reporting issues

- **Bugs and feature requests**: open a GitHub issue in this repository.
  Include the CLI invocation, input shape (NDJSON chain or signed export
  envelope), and the exit code / output you got vs. what you expected.
- **Security vulnerabilities**: do **not** open a public issue. Follow the
  private reporting process in [`SECURITY.md`](SECURITY.md).

## Building and testing locally

Requires Go (see `go.mod` for the minimum version).

```bash
# Build
go build -o atlasent-audit-verify ./cmd/atlasent-audit-verify

# Run the full test suite (race detector on, as CI does)
go test -race -count=1 ./...

# Vet
go vet ./...
```

For a fully static build, set `CGO_ENABLED=0`.

## Before opening a PR

- Read [`CLAUDE.md`](CLAUDE.md) first — it is the authoritative spec for what
  this tool verifies, the two accepted input shapes (NDJSON chain vs. signed
  export envelope), and several invariants that are easy to violate by
  accident (e.g. `engine_version` must never enter the hash computation).
- **Canonical-form changes are chain-version bumps, not bug fixes.** Do not
  edit `internal/canonical/canonical.go` or a golden test value to make a
  failing test pass — if the byte contract genuinely needs to change, that
  requires an explicit chain-version bump and corresponding verifier support.
- Keep exit-code semantics intact: `0` = verified, `1` = findings, `2` =
  environment/input error. Findings and warnings are not interchangeable —
  see the "Fail findings only, warn for recoverable" rule in `CLAUDE.md`.
- Add or update tests alongside any behavior change; this repo is
  golden-data / fixture driven, so most changes need a fixture update or
  addition, not just an assertion change.

## Pull request process

1. Branch off `main` using this repo's convention: `claude/<topic>` (or a
   similarly descriptive branch name if you're not using Claude Code).
2. Make sure `go build ./...`, `go vet ./...`, and `go test -race -count=1
   ./...` all pass locally.
3. Open a PR against `main` with a clear description of what changed and why.
   CI (`ci.yml`) runs vet, race-enabled tests, and a static build sanity
   check on every PR; `reproducibility.yml` checks that release builds stay
   byte-identical.
4. Keep PRs scoped to one change where practical — this makes review and any
   necessary chain-version discussion easier.

## Release process

Releases are cut from tags by `.github/workflows/release.yml` and are
Sigstore/Cosign-signed. Contributors don't need to do anything release-related
as part of a normal PR; maintainers handle tagging.
