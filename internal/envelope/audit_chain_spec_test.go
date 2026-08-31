package envelope

import (
	"encoding/json"
	"testing"
)

// ADR-052 spec stamp — INFORMATIONAL ECHO ONLY.
//
// The contract these tests pin, in the order it matters:
//
//  1. ABSENCE is a clean pass and produces byte-identical --json output to
//     what a pre-stamp build produced. Every bundle exported before
//     atlasent-api started emitting the stamp is in this case, forever.
//  2. PRESENCE is echoed with an explicit "protected by the outer signature"
//     attribution and changes NOTHING about the verdict.
//  3. NO value of the stamp can fail a bundle, and no value can relax one.
//     There is deliberately no version ceiling here — unlike
//     certification.version, which gates because it selects the recompute
//     formula. This field selects nothing, so gating on it would invent a
//     failure mode with no verification behind it.

// mkSpec builds a well-formed stamp, applying overrides.
func mkSpec(overrides map[string]any) map[string]any {
	s := map[string]any{
		"spec_id":                   "audit-chain-v1-spec",
		"spec_version":              "1.1",
		"adr":                       "ADR-052",
		"evaluation_chain_versions": []any{"evaluation-chain-v2", "evaluation-chain-v4"},
	}
	for k, v := range overrides {
		s[k] = v
	}
	return s
}

// (1) A bundle with no stamp verifies exactly as it always did, and the new
// fields are omitted from the JSON entirely — not rendered as null, not as an
// empty object. This is the compatibility guarantee that matters most: it is
// what every archived pre-stamp export relies on.
func TestAuditChainSpecAbsentIsACleanPassAndOmittedFromJSON(t *testing.T) {
	pub, priv, keys := archiveKeys(t)
	wire := buildArchiveWire(t, priv, pub, fxOrg,
		[]map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, nil, nil)

	res, err := Verify(wire, keys)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK() {
		t.Fatalf("a pre-stamp bundle must verify clean, findings=%v", res.Findings)
	}
	if res.AuditChainSpec != nil {
		t.Fatalf("audit_chain_spec must stay nil when the bundle carries none, got %+v", res.AuditChainSpec)
	}
	if res.AuditChainSpecProtection != "" {
		t.Fatalf("protection must stay empty when there is no stamp, got %q", res.AuditChainSpecProtection)
	}

	out, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := m["audit_chain_spec"]; present {
		t.Fatal("audit_chain_spec must be omitted from --json output on a pre-stamp bundle")
	}
	if _, present := m["audit_chain_spec_protection"]; present {
		t.Fatal("audit_chain_spec_protection must be omitted on a pre-stamp bundle")
	}
}

// (2) A present stamp is echoed verbatim and attributed to the outer
// signature, and the verdict is unchanged.
func TestAuditChainSpecPresentIsEchoedInformationally(t *testing.T) {
	pub, priv, keys := archiveKeys(t)
	wire := buildArchiveWire(t, priv, pub, fxOrg,
		[]map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, nil,
		map[string]any{"audit_chain_spec": mkSpec(nil)})

	res, err := Verify(wire, keys)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK() {
		t.Fatalf("a stamped bundle must verify clean, findings=%v", res.Findings)
	}
	if res.AuditChainSpec == nil {
		t.Fatal("audit_chain_spec was not echoed")
	}
	if got := res.AuditChainSpec.SpecID; got != "audit-chain-v1-spec" {
		t.Fatalf("spec_id = %q", got)
	}
	if got := res.AuditChainSpec.SpecVersion; got != "1.1" {
		t.Fatalf("spec_version = %q", got)
	}
	if got := res.AuditChainSpec.ADR; got != "ADR-052" {
		t.Fatalf("adr = %q", got)
	}
	if got := res.AuditChainSpec.EvaluationChainVersions; len(got) != 2 ||
		got[0] != "evaluation-chain-v2" || got[1] != "evaluation-chain-v4" {
		t.Fatalf("evaluation_chain_versions = %v", got)
	}
	// The stamp rides the outer signature — the same protection the
	// correlation and archive sections carry, named the same way.
	if res.AuditChainSpecProtection != "outer_envelope_signature" {
		t.Fatalf("protection = %q, want outer_envelope_signature", res.AuditChainSpecProtection)
	}
}

// (2b) Adding the stamp does not perturb any other reported value. Verified by
// comparing the FULL result JSON of a stamped and an unstamped bundle that are
// otherwise identical: the only difference must be the two new keys.
func TestAuditChainSpecDoesNotPerturbAnyOtherReportedValue(t *testing.T) {
	pub, priv, keys := archiveKeys(t)
	evals := []map[string]any{mkEval("d1", "allow", "ph1", "")}

	resultMap := func(extra map[string]any) map[string]json.RawMessage {
		t.Helper()
		wire := buildArchiveWire(t, priv, pub, fxOrg, evals, nil, nil, extra)
		res, err := Verify(wire, keys)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if !res.OK() {
			t.Fatalf("expected OK, findings=%v", res.Findings)
		}
		out, err := json.Marshal(res)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(out, &m); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return m
	}

	before := resultMap(nil)
	after := resultMap(map[string]any{"audit_chain_spec": mkSpec(nil)})

	delete(after, "audit_chain_spec")
	delete(after, "audit_chain_spec_protection")

	if len(before) != len(after) {
		t.Fatalf("key count changed: %d → %d", len(before), len(after))
	}
	for k, v := range before {
		other, ok := after[k]
		if !ok {
			t.Fatalf("key %q disappeared when the stamp was added", k)
		}
		if string(v) != string(other) {
			t.Fatalf("key %q changed when the stamp was added: %s → %s", k, v, other)
		}
	}
}

// (3) No stamp value can fail a bundle. A malformed, empty, unknown-version,
// or downright contradictory stamp is still just an echoed producer claim —
// this verifier checks none of it, so it must not invent a failure it did not
// actually detect.
func TestNoAuditChainSpecValueCanFailABundle(t *testing.T) {
	cases := map[string]map[string]any{
		"empty object":       {},
		"unknown spec id":    mkSpec(map[string]any{"spec_id": "some-other-spec"}),
		"far-future version": mkSpec(map[string]any{"spec_version": "99.0"}),
		"unknown chain id": mkSpec(map[string]any{
			"evaluation_chain_versions": []any{"evaluation-chain-v9"}}),
		"empty chain list": mkSpec(map[string]any{"evaluation_chain_versions": []any{}}),
		"no chain list":    {"spec_id": "audit-chain-v1-spec", "spec_version": "1.1", "adr": "ADR-052"},
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			pub, priv, keys := archiveKeys(t)
			wire := buildArchiveWire(t, priv, pub, fxOrg,
				[]map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, nil,
				map[string]any{"audit_chain_spec": spec})

			res, err := Verify(wire, keys)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if !res.OK() {
				t.Fatalf("the stamp must never fail a bundle, findings=%v", res.Findings)
			}
			if len(res.Findings) != 0 {
				t.Fatalf("the stamp must never produce a finding, got %v", res.Findings)
			}
		})
	}
}

// (3b) The stamp is under the signature, so tampering with it breaks the
// envelope layer — that, and only that, is what the signature actually proves
// about it. Nothing here claims the stamp's CONTENT was checked.
func TestTamperingWithTheStampBreaksTheOuterSignature(t *testing.T) {
	pub, priv, keys := archiveKeys(t)
	wire := buildArchiveWire(t, priv, pub, fxOrg,
		[]map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, nil,
		map[string]any{"audit_chain_spec": mkSpec(nil)})

	var env map[string]any
	if err := json.Unmarshal(wire, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	env["audit_chain_spec"] = mkSpec(map[string]any{"spec_version": "1.0"})
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	res, err := Verify(tampered, keys)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK() {
		t.Fatal("editing a signed field must break the envelope signature")
	}
	if !hasCode(res, CodeEnvelopeSignatureInvalid) {
		t.Fatalf("want ENVELOPE_SIGNATURE_INVALID, got %v", res.Findings)
	}
	// The envelope layer is invalid, so the unauthenticated stamp is NOT
	// surfaced: nothing carried under a broken signature is worth reporting.
	if res.AuditChainSpec != nil {
		t.Fatal("an unauthenticated stamp must not be echoed")
	}
}

// (4) The stamp must never be mistaken for a chain entry by the NDJSON /
// envelope auto-detector. It is not a `chain_version` key and must not behave
// like one.
func TestStampedEnvelopeIsStillDetectedAsAnEnvelope(t *testing.T) {
	pub, priv, _ := archiveKeys(t)
	wire := buildArchiveWire(t, priv, pub, fxOrg,
		[]map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, nil,
		map[string]any{"audit_chain_spec": mkSpec(nil)})
	if !LooksLikeEnvelope(wire) {
		t.Fatal("a stamped envelope must still auto-detect as an envelope")
	}
}
