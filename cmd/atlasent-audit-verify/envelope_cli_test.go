package main

// CLI black-box tests for the signed audit-export ENVELOPE path (auto-detected
// alongside the NDJSON chain path). Exercises detection, the trusted-key
// requirement under --require-signatures, --json output, and tamper rejection.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atlasent-systems-inc/atlasent-verify/internal/jcs"
)

// writeSignedEnvelope writes a signed export envelope + a PEM keyfile whose kid
// matches the envelope key_id. Returns their paths and the raw wire bytes.
func writeSignedEnvelope(t *testing.T, dir, keyID string, withCorrelation bool) (envPath, keysPath string, wire []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubPem := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	// One ledger-valid evaluation: entry_hash = sha256(canonical_payload).
	cp := "v2|org-1|ac|d1|actor|allow||fp|ph1|b|1|rh|rf|2026-08-01T00:00:00.000000Z|GENESIS"
	sum := sha256.Sum256([]byte(cp))
	eval := map[string]any{
		"id": "d1", "decision": "allow", "permit_token_hash": "ph1",
		"prev_hash": "", "entry_hash": hex.EncodeToString(sum[:]), "canonical_payload": cp,
	}
	env := map[string]any{
		"version": 1, "org_id": "org-1", "key_id": keyID, "public_key_pem": pubPem,
		"generated_at": "2026-08-01T00:00:00.000Z",
		"evaluations":  []any{eval},
	}
	if withCorrelation {
		env["verification_events"] = []any{map[string]any{
			"id": "ver-1", "decision_id": "d1", "permit_token_hash": "ph1",
			"presented_action_type": "production.deploy", "presented_environment": "live",
			"presented_payload_hash": "payhash1", "outcome": "verified",
		}}
		env["correlation_events"] = []any{map[string]any{
			"id": "corr-1", "decision_id": "d1", "permit_token_hash": "ph1",
			"presented_action_type": "production.deploy", "presented_environment": "live",
			"presented_payload_hash": "payhash1", "correlation_status": "MATCH",
			"confidence": 0.95, "provider_request_id": "req-1", "provider": "aws",
		}}
	}

	unsigned, _ := json.Marshal(env)
	canon, err := jcs.CanonicalizeRaw(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	env["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canon))
	wire, _ = json.Marshal(env)

	envPath = filepath.Join(dir, "export.json")
	if err := os.WriteFile(envPath, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Headers: map[string]string{"kid": keyID}, Bytes: der,
	})
	keysPath = filepath.Join(dir, "keys.pem")
	if err := os.WriteFile(keysPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return envPath, keysPath, wire
}

func TestCLIEnvelopeAutodetectAndVerify(t *testing.T) {
	dir := t.TempDir()
	envPath, keysPath, _ := writeSignedEnvelope(t, dir, "eks_test", true)
	out, code := run(t, "--chain", envPath, "--keys", keysPath)
	if code != 0 {
		t.Fatalf("want exit 0, got %d\n%s", code, out)
	}
	for _, want := range []string{"Envelope signature", "Ledger", "Correlation integrity", "1/1 record(s) verified", "outer_envelope_signature", "ok: audit export verified"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}
}

func TestCLIEnvelopeStrictRequiresTrustedKey(t *testing.T) {
	dir := t.TempDir()
	envPath, keysPath, _ := writeSignedEnvelope(t, dir, "eks_test", true)

	// With the trusted key: ACCEPTED, exit 0.
	out, code := run(t, "--chain", envPath, "--keys", keysPath, "--require-signatures")
	if code != 0 || !strings.Contains(out, "ACCEPTED (--require-signatures)") {
		t.Fatalf("want ACCEPTED exit 0, got %d\n%s", code, out)
	}
}

func TestCLIEnvelopeNoKeysIsUntrustedNonStrictOK(t *testing.T) {
	dir := t.TempDir()
	envPath, _, _ := writeSignedEnvelope(t, dir, "eks_test", false)

	// No --keys: verifies against the embedded key (WARN), non-strict exit 0.
	out, code := run(t, "--chain", envPath)
	if code != 0 {
		t.Fatalf("non-strict untrusted-key should exit 0, got %d\n%s", code, out)
	}
	if !strings.Contains(out, "embedded key") {
		t.Errorf("expected embedded-key trust note\n%s", out)
	}

	// No --keys BUT --require-signatures needs --keys → exit 2 guard fires first.
	out2, code2 := run(t, "--chain", envPath, "--require-signatures")
	if code2 != 2 || !strings.Contains(out2, "requires --keys") {
		t.Errorf("want exit 2 guard for --require-signatures without --keys, got %d\n%s", code2, out2)
	}
}

func TestCLIEnvelopeTamperExit1(t *testing.T) {
	dir := t.TempDir()
	envPath, keysPath, wire := writeSignedEnvelope(t, dir, "eks_test", true)
	tampered := strings.Replace(string(wire), `"confidence":0.95`, `"confidence":0.1`, 1)
	if tampered == string(wire) {
		t.Fatal("tamper did not apply")
	}
	if err := os.WriteFile(envPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := run(t, "--chain", envPath, "--keys", keysPath)
	if code != 1 || !strings.Contains(out, "ENVELOPE_SIGNATURE_INVALID") {
		t.Fatalf("tampered envelope must exit 1 with ENVELOPE_SIGNATURE_INVALID, got %d\n%s", code, out)
	}
}

func TestCLIEnvelopeJSONOutput(t *testing.T) {
	dir := t.TempDir()
	envPath, keysPath, _ := writeSignedEnvelope(t, dir, "eks_test", true)
	out, code := run(t, "--chain", envPath, "--keys", keysPath, "--json")
	if code != 0 {
		t.Fatalf("want exit 0, got %d\n%s", code, out)
	}
	// The JSON object is emitted before any trailing plain lines; decode the
	// first object.
	dec := json.NewDecoder(strings.NewReader(out))
	var res map[string]any
	if err := dec.Decode(&res); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if res["envelope_integrity"] != "valid" || res["correlation_integrity"] != "valid" {
		t.Errorf("json verdicts wrong: %v", res)
	}
	if res["correlation_protection"] != "outer_envelope_signature" {
		t.Errorf("correlation_protection wrong: %v", res["correlation_protection"])
	}
}
