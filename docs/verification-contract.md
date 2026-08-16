# Independent Verification Contract

`atlasent-audit-verify` exists so a customer, auditor, or security reviewer can
validate exported AtlaSent evidence without granting the verifier access to the
AtlaSent runtime, database, or network.

## Trust boundary

The verifier is deliberately offline. It consumes artifacts supplied by the
operator and performs local checks only. A successful run means the checks
requested by the operator passed under the supplied verification material; it
does not ask the AtlaSent service to attest to itself.

## Inputs

The core inputs are:

- an NDJSON audit chain (`--chain`);
- optional Ed25519 public keys (`--keys`) keyed by `key_version`;
- optional out-of-band chain-head anchors (`--head`) for tail-truncation checks.

The byte-level chain contract is public in
[`canonical-form-v5.md`](./canonical-form-v5.md).

## What is verified

For supported chain versions, the CLI checks:

1. canonical re-serialization;
2. hash-chain continuity;
3. Ed25519 signatures when keys are supplied;
4. causal sequence ordering;
5. genesis constraints;
6. head completeness when an independent anchor is supplied.

For signed certification/export envelopes, additional supported sections are
validated according to the versioned envelope contract implemented by the CLI.
The verifier reports checks separately rather than collapsing an absent or
inconclusive check into success.

## What is not claimed

The CLI does not claim that:

- a policy decision was substantively correct;
- a person should have been authorized;
- retention guarantees were operationally satisfied merely because metadata says
  they were;
- an export is complete when no independent head anchor was supplied;
- a signature was checked when no applicable public key was supplied.

Those distinctions are intentional. Structural verification and policy judgment
are different assurance layers.

## Offline requirement

A normal verification run must not require:

- AtlaSent API credentials;
- an AtlaSent database connection;
- a callback to an AtlaSent service;
- outbound network access.

Release-artifact authenticity is separately verifiable with Sigstore/Cosign and
the public GitHub Actions identity used to produce a release.

## Fail-closed version handling

A verifier may accept versions it explicitly supports. A future chain or envelope
version containing fields the verifier does not understand must not be reported as
fully verified. Upgrade the verifier or use the matching versioned verifier.

## Reproducibility

Release builds are intended to be reproducible and signed. Repository CI and
golden fixtures provide regression evidence for canonicalization and verification
behavior. The source, tests, release workflow, and public specification are all in
this repository so an external reviewer can examine the complete verification
path without an NDA.
