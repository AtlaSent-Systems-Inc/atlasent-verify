package main

// Offline-verifier parity test. Runs the built CLI against the committed
// service-shaped fixture in testdata/parity/ and asserts strict signature
// acceptance + completeness — the same contract the parity.yml workflow
// enforces, exercised here so it also runs under `go test ./...` (ci.yml
// and the weekly canary's golden-fixture step).
//
// Closes pilot blocker B2 / SOC2 GAP-030 at the test layer: a committed,
// signed, canonical-v5 export must verify cleanly (exit 0, every signature
// verified against a known key, zero skipped, no tail truncation).
//
// The fixture is SYNTHETIC and DETERMINISTIC (produced by
// testdata/parity/gen from the repo's own canonicalizer with an in-source
// throwaway key). It locks the canonical-form ⇄ CLI contract; it does not
// stand in for a real runtime staging export. See testdata/parity/README.md.

import (
	"path/filepath"
	"strings"
	"testing"
)

// fixturePath resolves a file in testdata/parity relative to this package
// directory (cmd/atlasent-audit-verify → repo root is two levels up).
func fixturePath(name string) string {
	return filepath.Join("..", "..", "testdata", "parity", name)
}

// TestParityFixtureStrictAcceptance is the core B2 assertion: the committed
// export verifies under --require-signatures + --head with exit 0 and the
// positive evidence lines.
func TestParityFixtureStrictAcceptance(t *testing.T) {
	out, code := run(t,
		"--chain", fixturePath("chain.ndjson"),
		"--keys", fixturePath("keys.pem"),
		"--head", fixturePath("head.json"),
		"--require-signatures",
	)
	if code != 0 {
		t.Fatalf("exit=%d, want 0; out=%s", code, out)
	}
	for _, want := range []string{
		"ACCEPTED (--require-signatures)",
		"signature(s) verified",
		"no tail truncation",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; out=%s", want, out)
		}
	}
	// The real skip indicator. Its presence would mean the correct key
	// was not loaded and a signature was silently skipped — the exact
	// false-green this fixture guards against. (The ACCEPTED line contains
	// the substring "0 skipped", so we assert on the skip *reason*, not a
	// bare "skipped".)
	if strings.Contains(out, "key_version not in keystore") {
		t.Errorf("a signature was SKIPPED (unknown key_version); out=%s", out)
	}
}

// TestParityFixtureCoverageCount asserts every entry in the fixture was
// signature-verified (the fixture is 3 entries, all under one known key).
func TestParityFixtureCoverageCount(t *testing.T) {
	out, code := run(t,
		"--chain", fixturePath("chain.ndjson"),
		"--keys", fixturePath("keys.pem"),
		"--require-signatures",
	)
	if code != 0 {
		t.Fatalf("exit=%d, want 0; out=%s", code, out)
	}
	if !strings.Contains(out, "3 signature(s) verified") {
		t.Errorf("expected all 3 signatures verified; out=%s", out)
	}
	if !strings.Contains(out, "3 entries verified across 1 org(s)") {
		t.Errorf("expected 3-entry single-org chain; out=%s", out)
	}
}
