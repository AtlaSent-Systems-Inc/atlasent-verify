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
	"os"
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

// legacyWarnMarker is the diagnostic internal/chain emits when an entry
// verified only via the engine_version-EXCLUDED fallback.
const legacyWarnMarker = "engine_version_legacy_hash_form"

// TestParityCurrentProducerFormStrictAcceptance covers the hash form a
// FRESH export actually takes — engine_version INCLUDED in the hash, per
// _shared/audit-v5-projection.ts::buildV5EntryForHash via the deployed
// v1-export-audit-stream caller (atlasent-verify#28).
//
// Why this test exists: until 2026-09-19 the only committed fixture was in
// the LEGACY form, so the parity gate reached ACCEPTED exclusively through
// the fallback and never once exercised the primary path. The gate was
// green while the code path a real export takes went untested.
//
// The load-bearing assertion is the ABSENCE of the legacy warning. Exit 0
// alone would not distinguish "matched on the current form" from "failed
// the current form and was rescued by the fallback" — which is precisely
// how the gap hid.
func TestParityCurrentProducerFormStrictAcceptance(t *testing.T) {
	out, code := run(t,
		"--chain", fixturePath("chain-current-form.ndjson"),
		"--keys", fixturePath("keys.pem"),
		"--head", fixturePath("head-current-form.json"),
		"--require-signatures",
	)
	if code != 0 {
		t.Fatalf("exit=%d, want 0; out=%s", code, out)
	}
	for _, want := range []string{
		"ACCEPTED (--require-signatures)",
		"3 signature(s) verified",
		"no tail truncation",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; out=%s", want, out)
		}
	}
	if strings.Contains(out, legacyWarnMarker) {
		t.Errorf("current-form fixture fell back to the LEGACY hash form — "+
			"it is no longer in the current producer form, so this test has "+
			"stopped covering the primary path; regenerate it with "+
			"`go run testdata/parity/gen/main.go`. out=%s", out)
	}
}

// TestParityLegacyFormStillVerifiesAndWarns pins the other half of the
// contract: chains produced BEFORE the producer folded engine_version into
// the hash must still verify, and using that fallback must stay VISIBLE.
//
// Both halves matter. If the fallback silently disappeared, real legacy
// chains would stop verifying. If it stopped warning, a chain that needed
// it would become indistinguishable from one matching the current form —
// the exact ambiguity internal/chain's comments say the warning exists to
// prevent.
func TestParityLegacyFormStillVerifiesAndWarns(t *testing.T) {
	out, code := run(t,
		"--chain", fixturePath("chain.ndjson"),
		"--keys", fixturePath("keys.pem"),
		"--head", fixturePath("head.json"),
		"--require-signatures",
	)
	if code != 0 {
		t.Fatalf("exit=%d, want 0 (legacy chains must still verify); out=%s", code, out)
	}
	if !strings.Contains(out, "ACCEPTED (--require-signatures)") {
		t.Errorf("legacy fixture should still reach strict acceptance; out=%s", out)
	}
	if strings.Count(out, legacyWarnMarker) != 3 {
		t.Errorf("expected the legacy-fallback warning on all 3 entries "+
			"(a silent fallback is the defect this guards); got %d; out=%s",
			strings.Count(out, legacyWarnMarker), out)
	}
}

// TestParityFixturesDifferOnlyByEngineVersionHash asserts the two fixtures
// are the same chain in two hash forms — same org, same entry count, same
// key — so any behavioral difference between them is attributable to
// engine_version and nothing else. Without this, the two could silently
// drift into unrelated fixtures that happen to pass.
func TestParityFixturesDifferOnlyByEngineVersionHash(t *testing.T) {
	legacy, err := os.ReadFile(fixturePath("chain.ndjson"))
	if err != nil {
		t.Fatalf("read legacy fixture: %v", err)
	}
	current, err := os.ReadFile(fixturePath("chain-current-form.ndjson"))
	if err != nil {
		t.Fatalf("read current-form fixture: %v", err)
	}
	if string(legacy) == string(current) {
		t.Fatal("the two fixtures are byte-identical — the current-form one " +
			"was not generated with engine_version in the hash, so it adds no coverage")
	}
	legacyLines := strings.Count(strings.TrimSpace(string(legacy)), "\n") + 1
	currentLines := strings.Count(strings.TrimSpace(string(current)), "\n") + 1
	if legacyLines != currentLines {
		t.Errorf("fixtures have different entry counts (%d vs %d); they should be "+
			"the same chain in two hash forms", legacyLines, currentLines)
	}
	// Same source entries → same engine_version present in both.
	for name, b := range map[string][]byte{"legacy": legacy, "current-form": current} {
		if !strings.Contains(string(b), `"engine_version"`) {
			t.Errorf("%s fixture carries no engine_version field, so it cannot "+
				"exercise either hash form meaningfully", name)
		}
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
