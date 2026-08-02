package main

// CLI black-box tests for the Evidence Archive sections of a signed export
// (certification version 5). These run against a COMMITTED, deterministic
// fixture rather than a freshly generated one on purpose: the fixture was
// signed once with a fixed key, so if canonicalization or the wire shape ever
// drifts, the committed signature stops verifying and the drift surfaces here
// instead of in a customer's audit.

import (
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtureExport = "testdata/archive-export.json"

// archiveKeyfile writes a kid-tagged PEM keystore derived from the committed
// fixture's own embedded public_key_pem, rather than committing a second
// keyfile. Two reasons: the repo's .gitignore blanket-ignores *.pem so a
// private key can never be committed by accident, and deriving the trusted key
// from the fixture makes it structurally impossible for the two to drift apart.
// (Deriving it is safe for THIS test's purpose — it proves the trusted-key code
// path and the archive verdicts; the "embedded key is not externally anchored"
// property is covered by the strict-acceptance tests elsewhere.)
func archiveKeyfile(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(fixtureExport)
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		KeyID        string `json:"key_id"`
		PublicKeyPEM string `json:"public_key_pem"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(env.PublicKeyPEM))
	if block == nil {
		t.Fatal("fixture carries no decodable public_key_pem")
	}
	out := pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Headers: map[string]string{"kid": env.KeyID}, Bytes: block.Bytes,
	})
	path := filepath.Join(t.TempDir(), "keys.pem")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCLIArchiveFixtureVerifies(t *testing.T) {
	fixtureKeys := archiveKeyfile(t)
	stdout, code := run(t, "--chain", fixtureExport, "--keys", fixtureKeys)
	if code != 0 {
		t.Fatalf("exit=%d\noutput:\n%s", code, stdout)
	}

	// The four states must each be reported on their own line. Collapsing any
	// pair would let a reader infer assurance the records do not carry.
	for _, want := range []string{
		"Evidence archive integrity",
		"4/4 record(s) verified",
		"Retrieval attempted",
		"Retrieval succeeded",
		"Retrieval refused",
		"Probe executed",
		"Integrity confirmed",
		"Integrity failed",
		"Integrity inconclusive",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("missing %q in:\n%s", want, stdout)
		}
	}

	// The retention ceiling must be stated, and must not be stated as verified.
	if !strings.Contains(stdout, "RECORDED, not verified by this tool") {
		t.Errorf("retention ceiling not stated:\n%s", stdout)
	}
	for _, forbidden := range []string{"retention verified", "retention guaranteed", "six-year retention active"} {
		if strings.Contains(strings.ToLower(stdout), forbidden) {
			t.Errorf("output claims %q, which this offline tool cannot know:\n%s", forbidden, stdout)
		}
	}
}

func TestCLIArchiveJSONShape(t *testing.T) {
	fixtureKeys := archiveKeyfile(t)
	stdout, code := run(t, "--chain", fixtureExport, "--keys", fixtureKeys, "--json")
	if code != 0 {
		t.Fatalf("exit=%d\noutput:\n%s", code, stdout)
	}
	var out struct {
		ArchiveIntegrity        string `json:"archive_integrity"`
		ArchiveRecordsVerified  int    `json:"archive_records_verified"`
		ArchiveRecordsTotal     int    `json:"archive_records_total"`
		ArchiveRetentionRecords int    `json:"archive_retention_records"`
		RetentionAssurance      string `json:"retention_assurance"`
		CertificationVersion    int    `json:"certification_version"`
		ArchiveStages           struct {
			RetrievalAttempted    int `json:"retrieval_attempted"`
			RetrievalSucceeded    int `json:"retrieval_succeeded"`
			RetrievalFailed       int `json:"retrieval_failed"`
			ProbeExecuted         int `json:"probe_executed"`
			IntegrityConfirmed    int `json:"integrity_confirmed"`
			IntegrityFailed       int `json:"integrity_failed"`
			IntegrityInconclusive int `json:"integrity_inconclusive"`
		} `json:"archive_stages"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout)
	}
	if out.ArchiveIntegrity != "verified" {
		t.Errorf("archive_integrity = %q, want verified", out.ArchiveIntegrity)
	}
	if out.ArchiveRecordsVerified != 4 || out.ArchiveRecordsTotal != 4 {
		t.Errorf("archive counts = %d/%d, want 4/4", out.ArchiveRecordsVerified, out.ArchiveRecordsTotal)
	}
	if out.CertificationVersion != 5 {
		t.Errorf("certification_version = %d, want 5", out.CertificationVersion)
	}
	if out.RetentionAssurance != "recorded_not_verified_offline" {
		t.Errorf("retention_assurance = %q — this tool must never report retention as verified", out.RetentionAssurance)
	}
	if out.ArchiveRetentionRecords != 2 {
		t.Errorf("archive_retention_records = %d, want 2", out.ArchiveRetentionRecords)
	}
	s := out.ArchiveStages
	if s.RetrievalAttempted != 2 || s.RetrievalSucceeded != 1 || s.RetrievalFailed != 1 {
		t.Errorf("retrieval stages = %+v, want 2/1/1", s)
	}
	if s.ProbeExecuted != 2 || s.IntegrityConfirmed != 1 || s.IntegrityFailed != 0 || s.IntegrityInconclusive != 1 {
		t.Errorf("probe stages = %+v, want executed 2, confirmed 1, failed 0, inconclusive 1", s)
	}
}

// Tampering with a committed fixture's archive section must break the outer
// signature — the archive records' only protection.
func TestCLIArchiveFixtureTamperRejected(t *testing.T) {
	fixtureKeys := archiveKeyfile(t)
	raw, err := os.ReadFile(fixtureExport)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	// Flip a refusal into a success: the single most consequential edit an
	// adversary could want in a disclosure log.
	m["retrieval_events"].([]any)[1].(map[string]any)["retrieval_status"] = "retrieved"
	tampered, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tampered.json")
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, code := run(t, "--chain", path, "--keys", fixtureKeys)
	if code == 0 {
		t.Fatalf("tampered fixture accepted:\n%s", stdout)
	}
	if !strings.Contains(stdout, "ENVELOPE_SIGNATURE_INVALID") {
		t.Fatalf("want ENVELOPE_SIGNATURE_INVALID, got:\n%s", stdout)
	}
}
