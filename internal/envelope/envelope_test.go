package envelope

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/atlasent-systems-inc/atlasent-verify/internal/jcs"
)

// ─── test harness ────────────────────────────────────────────────────────────

// memKeys is an in-memory chain.KeyStore keyed by kid.
type memKeys map[string]ed25519.PublicKey

func (m memKeys) PublicKey(kid string) (ed25519.PublicKey, bool) {
	pk, ok := m[kid]
	return pk, ok
}

func spkiPem(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal spki: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// mkEval builds a ledger-valid evaluation row: entry_hash = sha256(canonical_payload).
func mkEval(id, decision, permit, prevHash string) map[string]any {
	cp := "v2|org|ac|" + id + "|actor|" + decision + "||fp|" + permit + "|b|1|rh|rf|2026-08-01T00:00:00.000000Z|" + orDefault(prevHash, "GENESIS")
	sum := sha256.Sum256([]byte(cp))
	return map[string]any{
		"id":                id,
		"decision":          decision,
		"permit_token_hash": permit,
		"prev_hash":         prevHash,
		"entry_hash":        hex.EncodeToString(sum[:]),
		"canonical_payload": cp,
	}
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// buildWire assembles + signs an envelope exactly as the producer does:
// signature = base64.Std(ed25519.Sign(priv, jcs.Canonicalize(envelope-minus-signature))).
// Returns the wire JSON bytes.
func buildWire(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, version int, keyID, orgID string, evals, vers, corrs []map[string]any) []byte {
	t.Helper()
	env := map[string]any{
		"version":             version,
		"org_id":              orgID,
		"key_id":              keyID,
		"public_key_pem":      spkiPem(t, pub),
		"generated_at":        "2026-08-01T00:00:00.000Z",
		"evaluations":         toAnySlice(evals),
		"verification_events": toAnySlice(vers),
		"correlation_events":  toAnySlice(corrs),
	}
	if len(corrs) == 0 {
		delete(env, "correlation_events")
	}
	if len(vers) == 0 {
		delete(env, "verification_events")
	}
	// Sign over CanonicalizeRaw(marshal(env)) — the exact bytes the verifier
	// recomputes (it parses the wire with UseNumber, deletes signature, then
	// canonicalizes). Signing the marshaled form avoids Go int/float typing
	// differences from the JSON number path.
	unsigned, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal unsigned: %v", err)
	}
	canon, err := jcs.CanonicalizeRaw(unsigned)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	sig := ed25519.Sign(priv, canon)
	env["signature"] = base64.StdEncoding.EncodeToString(sig)
	wire, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return wire
}

func toAnySlice(ms []map[string]any) []any {
	out := make([]any, len(ms))
	for i, m := range ms {
		out[i] = m
	}
	return out
}

func hasCode(res *VerificationResult, code FailureCode) bool {
	for _, f := range res.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

// A correlation row that references permit "ph1" / decision "d1" for the happy path.
func mkCorr(overrides map[string]any) map[string]any {
	c := map[string]any{
		"id":                     "corr-1",
		"decision_id":            "d1",
		"permit_token_hash":      "ph1",
		"presented_action_type":  "production.deploy",
		"presented_environment":  "live",
		"presented_payload_hash": "payhash1",
		"correlation_status":     "MATCH",
		"confidence":             0.95,
		"provider_request_id":    "req-1",
		"provider":               "aws",
	}
	for k, v := range overrides {
		c[k] = v
	}
	return c
}

func mkVer(overrides map[string]any) map[string]any {
	v := map[string]any{
		"id":                     "ver-1",
		"decision_id":            "d1",
		"permit_token_hash":      "ph1",
		"presented_action_type":  "production.deploy",
		"presented_environment":  "live",
		"presented_payload_hash": "payhash1",
		"outcome":                "verified",
	}
	for k, val := range overrides {
		v[k] = val
	}
	return v
}

// ─── acceptance tests (spec 1..10 + lifecycle/reference/untrusted) ───────────

// 1. Legacy NDJSON succeeds, correlation absent.
func TestAcceptance01_LegacyNDJSON_CorrelationAbsent(t *testing.T) {
	if LooksLikeEnvelope([]byte(`{"chain_version":5,"org_id":"o"}` + "\n" + `{"chain_version":5}`)) {
		t.Error("NDJSON with no top-level signature must NOT be detected as an envelope")
	}
	if !LooksLikeEnvelope([]byte(`{"version":1,"signature":"abc","evaluations":[]}`)) {
		t.Error("a signed export object must be detected as an envelope")
	}
}

// 2. R3 envelope without correlations succeeds (correlation absent).
func TestAcceptance02_EnvelopeNoCorrelations(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, nil)
	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.EnvelopeIntegrity != LayerValid {
		t.Errorf("envelope integrity = %s, want valid", res.EnvelopeIntegrity)
	}
	if res.CorrelationIntegrity != LayerAbsent {
		t.Errorf("correlation integrity = %s, want absent", res.CorrelationIntegrity)
	}
	if !res.OK() {
		t.Errorf("want OK, findings: %+v", res.Findings)
	}
	if ok, reason := res.StrictOK(); !ok {
		t.Errorf("want StrictOK (trusted key), got: %s", reason)
	}
}

// 3. Valid R3 correlations succeed.
func TestAcceptance03_ValidCorrelations(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")},
		[]map[string]any{mkVer(nil)},
		[]map[string]any{mkCorr(nil)})
	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.EnvelopeIntegrity != LayerValid || res.CorrelationIntegrity != LayerValid {
		t.Errorf("envelope=%s correlation=%s, want valid/valid; findings %+v", res.EnvelopeIntegrity, res.CorrelationIntegrity, res.Findings)
	}
	if res.CorrelationRecordsVerified != 1 {
		t.Errorf("verified=%d, want 1", res.CorrelationRecordsVerified)
	}
	if !res.OK() {
		t.Errorf("want OK, findings: %+v", res.Findings)
	}
}

// 4. Modified correlation field invalidates the outer signature.
func TestAcceptance04_TamperedCorrelationBreaksSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")},
		[]map[string]any{mkVer(nil)},
		[]map[string]any{mkCorr(nil)})
	// Tamper: flip the correlation confidence in the wire bytes without re-signing.
	tampered := []byte(strings.Replace(string(wire), `"confidence":0.95`, `"confidence":0.1`, 1))
	if string(tampered) == string(wire) {
		t.Fatal("tamper replacement did not apply")
	}
	res, err := Verify(tampered, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.EnvelopeIntegrity != LayerInvalid || !hasCode(res, CodeEnvelopeSignatureInvalid) {
		t.Errorf("tampered correlation must invalidate outer signature; got envelope=%s findings=%+v", res.EnvelopeIntegrity, res.Findings)
	}
	if res.OK() {
		t.Error("tampered envelope must not be OK")
	}
}

// 5. Re-signed envelope with a missing reference fails semantic validation.
func TestAcceptance05_MissingReference(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	// Correlation references permit "phX"/decision "dX" absent from the export.
	corr := mkCorr(map[string]any{"decision_id": "dX", "permit_token_hash": "phX"})
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")},
		[]map[string]any{mkVer(nil)},
		[]map[string]any{corr})
	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.EnvelopeIntegrity != LayerValid {
		t.Fatalf("envelope must still verify (it was re-signed): %s", res.EnvelopeIntegrity)
	}
	if res.CorrelationIntegrity != LayerInvalid || !hasCode(res, CodeCorrelationReferenceOutsideExport) {
		t.Errorf("want CORRELATION_REFERENCE_OUTSIDE_EXPORT; got correlation=%s findings=%+v", res.CorrelationIntegrity, res.Findings)
	}
}

// 6. Cross-org fails (once organization_id is present on the record).
func TestAcceptance06_CrossOrg(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	corr := mkCorr(map[string]any{"organization_id": "org-OTHER"})
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")},
		[]map[string]any{mkVer(nil)},
		[]map[string]any{corr})
	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(res, CodeCorrelationOrgMismatch) {
		t.Errorf("want CORRELATION_ORG_MISMATCH; findings=%+v", res.Findings)
	}
	if res.OrgBinding != OrgBindingChecked {
		t.Errorf("org binding should be 'checked' when the field is present, got %s", res.OrgBinding)
	}
}

// 7. Cross-action and cross-target fail.
func TestAcceptance07_ActionAndTargetMismatch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	// Action mismatch: correlation asserts a different action than the permit-verification.
	corrA := mkCorr(map[string]any{"presented_action_type": "database.execute_sql"})
	wireA := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")},
		[]map[string]any{mkVer(nil)},
		[]map[string]any{corrA})
	resA, _ := Verify(wireA, memKeys{"eks_test": pub})
	if !hasCode(resA, CodeCorrelationActionMismatch) {
		t.Errorf("want CORRELATION_ACTION_MISMATCH; findings=%+v", resA.Findings)
	}

	// Target mismatch: correlation payload_hash differs from the permit-verification's.
	corrT := mkCorr(map[string]any{"presented_payload_hash": "DIFFERENT"})
	wireT := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")},
		[]map[string]any{mkVer(nil)},
		[]map[string]any{corrT})
	resT, _ := Verify(wireT, memKeys{"eks_test": pub})
	if !hasCode(resT, CodeCorrelationTargetMismatch) {
		t.Errorf("want CORRELATION_TARGET_MISMATCH; findings=%+v", resT.Findings)
	}
}

// 8. Duplicate identical correlation records.
func TestAcceptance08_Duplicate(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	c1 := mkCorr(map[string]any{"id": "corr-1"})
	c2 := mkCorr(map[string]any{"id": "corr-2"}) // same identity + same verdict
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")},
		[]map[string]any{mkVer(nil)},
		[]map[string]any{c1, c2})
	res, _ := Verify(wire, memKeys{"eks_test": pub})
	if !hasCode(res, CodeCorrelationDuplicate) {
		t.Errorf("want CORRELATION_DUPLICATE; findings=%+v", res.Findings)
	}
}

// 9. Two conflicting correlations for the same identity.
func TestAcceptance09_Conflict(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	c1 := mkCorr(map[string]any{"id": "corr-1", "correlation_status": "MATCH"})
	c2 := mkCorr(map[string]any{"id": "corr-2", "correlation_status": "MISMATCH"}) // contradictory verdict
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")},
		[]map[string]any{mkVer(nil)},
		[]map[string]any{c1, c2})
	res, _ := Verify(wire, memKeys{"eks_test": pub})
	if !hasCode(res, CodeCorrelationConflict) {
		t.Errorf("want CORRELATION_CONFLICT; findings=%+v", res.Findings)
	}
	if hasCode(res, CodeCorrelationDuplicate) {
		t.Error("conflicting records must not be reported as a duplicate")
	}
}

// 10. Unknown envelope version fails closed.
func TestAcceptance10_UnknownVersion(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 2, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, nil)
	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.EnvelopeIntegrity != LayerInvalid || !hasCode(res, CodeUnsupportedEnvelopeVersion) {
		t.Errorf("unknown version must fail closed with UNSUPPORTED_ENVELOPE_VERSION; got %s findings=%+v", res.EnvelopeIntegrity, res.Findings)
	}
	if res.OK() {
		t.Error("unknown version must not be OK")
	}
}

// Lifecycle: a correlation for a non-allow Decision is contradictory.
func TestLifecycleInvalid_DenyDecision(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	corr := mkCorr(nil) // references ph1/d1
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "deny", "ph1", "")}, // permit was NOT issued
		nil,
		[]map[string]any{corr})
	res, _ := Verify(wire, memKeys{"eks_test": pub})
	if !hasCode(res, CodeCorrelationLifecycleInvalid) {
		t.Errorf("want CORRELATION_LIFECYCLE_INVALID for a correlation on a deny Decision; findings=%+v", res.Findings)
	}
}

// Reference-missing: a correlation with neither decision_id nor permit_token_hash.
func TestReferenceMissing(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	corr := mkCorr(map[string]any{"decision_id": "", "permit_token_hash": ""})
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, []map[string]any{corr})
	res, _ := Verify(wire, memKeys{"eks_test": pub})
	if !hasCode(res, CodeCorrelationReferenceMissing) {
		t.Errorf("want CORRELATION_REFERENCE_MISSING; findings=%+v", res.Findings)
	}
}

// Untrusted key: no --keys supplied → verifies against the embedded PEM but
// trust is not anchored (OK yes, StrictOK no).
func TestUntrustedKey_NoKeystore(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, nil)
	res, err := Verify(wire, nil) // no trusted keystore
	if err != nil {
		t.Fatal(err)
	}
	if res.EnvelopeIntegrity != LayerUntrustedKey {
		t.Errorf("envelope integrity = %s, want valid_untrusted_key", res.EnvelopeIntegrity)
	}
	if !res.OK() {
		t.Errorf("untrusted key should still be OK under normal acceptance; findings=%+v", res.Findings)
	}
	if ok, _ := res.StrictOK(); ok {
		t.Error("untrusted key must NOT pass strict acceptance")
	}
}

// Ledger tampering: an altered canonical_payload breaks the ledger layer even
// though (in this test) we re-sign so the envelope layer passes.
func TestLedgerHashMismatch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	bad := mkEval("d1", "allow", "ph1", "")
	bad["canonical_payload"] = bad["canonical_payload"].(string) + "TAMPER" // entry_hash no longer matches
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{bad}, nil, nil)
	res, _ := Verify(wire, memKeys{"eks_test": pub})
	if res.LedgerIntegrity != LayerInvalid || !hasCode(res, CodeLedgerHashMismatch) {
		t.Errorf("want LEDGER_HASH_MISMATCH; ledger=%s findings=%+v", res.LedgerIntegrity, res.Findings)
	}
}
