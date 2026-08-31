from pathlib import Path


def replace(path: str, old: str, new: str) -> None:
    p = Path(path)
    s = p.read_text()
    if old not in s:
        raise SystemExit(f"expected snippet not found in {path}: {old[:120]!r}")
    p.write_text(s.replace(old, new, 1))

# v5 chain parity: engine_version is part of the frozen v5 hash surface.
replace(
    "internal/chain/entry.go",
    '''//   - "engine_version" is additive metadata — it was NOT included in
//     the hash when the runtime produced the entry.  Removing it here
//     keeps the verifier's recomputed hash consistent with the stored
//     entry_hash regardless of whether the field is present in the
//     exported JSON.
''',
    '''//   - "engine_version" is part of the frozen v5 top-level schema and is
//     bound into the entry hash. The producer and canonical-form spec both
//     include it when present; the verifier must therefore preserve it.
''',
)
replace(
    "internal/chain/entry.go",
    '''\tdelete(m, "entry_hash")
\tdelete(m, "signature")
\tdelete(m, "engine_version") // additive metadata — not in chain hash (audit chain v5)
\treturn canonical.Bytes(m)
''',
    '''\tdelete(m, "entry_hash")
\tdelete(m, "signature")
\treturn canonical.Bytes(m)
''',
)

# Certification v6 model + all producer-bound census fields.
replace(
    "internal/envelope/model.go",
    '''\tCodeUnsupportedCertificationVersion FailureCode = "UNSUPPORTED_CERTIFICATION_VERSION"
\tCodeCertificationCountMismatch      FailureCode = "CERTIFICATION_COUNT_MISMATCH"
''',
    '''\tCodeUnsupportedCertificationVersion FailureCode = "UNSUPPORTED_CERTIFICATION_VERSION"
\tCodeCertificationCountMismatch      FailureCode = "CERTIFICATION_COUNT_MISMATCH"
\tCodeCertificationBundleHashMismatch FailureCode = "CERTIFICATION_BUNDLE_HASH_MISMATCH"
''',
)
replace("internal/envelope/model.go", "const SupportedCertificationVersion = 5\n", "const SupportedCertificationVersion = 6\n")
replace(
    "internal/envelope/model.go",
    '''\tEvaluations   []json.RawMessage `json:"evaluations"`
\tVerifications []VerificationRow `json:"verification_events"`
\tCorrelations  []CorrelationRow  `json:"correlation_events"`

\t// Evidence Archive sections, added at certification version 5. Absent on
''',
    '''\tEvaluations           []json.RawMessage `json:"evaluations"`
\tContextEnvelopes       []json.RawMessage `json:"context_envelopes"`
\tGovernanceTransitions []json.RawMessage `json:"governance_transitions"`
\tAdminLog              []json.RawMessage `json:"admin_log"`
\tVerifications         []VerificationRow `json:"verification_events"`
\tExceptions            []json.RawMessage `json:"exception_events"`
\tCorrelations          []CorrelationRow  `json:"correlation_events"`
\tProtectionConfigs     []json.RawMessage `json:"protection_configurations"`

\t// Evidence Archive sections, added at certification version 5. Absent on
''',
)
replace(
    "internal/envelope/model.go",
    '''type Certification struct {
\tVersion      int                       `json:"version"`
\tRecordCounts CertificationRecordCounts `json:"record_counts"`
}
''',
    '''type Certification struct {
\tVersion      int                       `json:"version"`
\tRecordCounts CertificationRecordCounts `json:"record_counts"`
\tBundleSHA256 string                    `json:"bundle_sha256"`
}
''',
)
replace(
    "internal/envelope/model.go",
    '''type CertificationRecordCounts struct {
\tEvaluations        *int `json:"evaluations"`
\tVerificationEvents *int `json:"verification_events"`
\tCorrelationEvents  *int `json:"correlation_events"`
\tRetrievalEvents    *int `json:"retrieval_events"`
\tProbeEvents        *int `json:"probe_events"`
}
''',
    '''type CertificationRecordCounts struct {
\tEvaluations           *int `json:"evaluations"`
\tContextEnvelopes      *int `json:"context_envelopes"`
\tGovernanceTransitions *int `json:"governance_transitions"`
\tAdminLog              *int `json:"admin_log"`
\tVerificationEvents    *int `json:"verification_events"`
\tExceptionEvents       *int `json:"exception_events"`
\tCorrelationEvents     *int `json:"correlation_events"`
\tRetrievalEvents       *int `json:"retrieval_events"`
\tProbeEvents           *int `json:"probe_events"`
\tProtectionConfigs     *int `json:"protection_configurations"`
\tTotal                 *int `json:"total"`
}
''',
)

# Verification: recompute the certification census and bundle hash exactly by manifest version.
replace(
    "internal/envelope/verify.go",
    '''import (
\t"bytes"
\t"crypto/ed25519"
\t"crypto/x509"
''',
    '''import (
\t"bytes"
\t"crypto/ed25519"
\t"crypto/sha256"
\t"crypto/x509"
''',
)
replace(
    "internal/envelope/verify.go",
    '''\t// (5) Certification census cross-check. A manifest claiming more records
\t// than the bundle carries is what a truncated export looks like from the
\t// outside; a manifest claiming fewer means sections were appended after it
\t// was written. Either way the signed count and the signed arrays disagree,
\t// which the reader must be told.
\tcheckCertificationCounts(&env, res)

\treturn res, nil
}
''',
    '''\t// (5) Certification completeness cross-check. Counts catch section-level
\t// truncation/addition; bundle_sha256 cryptographically binds the exact record
\t// set using the producer's versioned section envelope.
\tcheckCertificationCounts(&env, res)
\tcheckCertificationBundleHash(raw, &env, res)

\treturn res, nil
}
''',
)
replace(
    "internal/envelope/verify.go",
    '''\tcmp("evaluations", rc.Evaluations, len(env.Evaluations))
\tcmp("verification_events", rc.VerificationEvents, len(env.Verifications))
\tcmp("correlation_events", rc.CorrelationEvents, len(env.Correlations))
\tcmp("retrieval_events", rc.RetrievalEvents, len(env.Retrievals))
\tcmp("probe_events", rc.ProbeEvents, len(env.Probes))
}
''',
    '''\tcmp("evaluations", rc.Evaluations, len(env.Evaluations))
\tcmp("context_envelopes", rc.ContextEnvelopes, len(env.ContextEnvelopes))
\tcmp("governance_transitions", rc.GovernanceTransitions, len(env.GovernanceTransitions))
\tcmp("admin_log", rc.AdminLog, len(env.AdminLog))
\tcmp("verification_events", rc.VerificationEvents, len(env.Verifications))
\tcmp("exception_events", rc.ExceptionEvents, len(env.Exceptions))
\tcmp("correlation_events", rc.CorrelationEvents, len(env.Correlations))
\tcmp("retrieval_events", rc.RetrievalEvents, len(env.Retrievals))
\tcmp("probe_events", rc.ProbeEvents, len(env.Probes))
\tcmp("protection_configurations", rc.ProtectionConfigs, len(env.ProtectionConfigs))
\tactualTotal := len(env.Evaluations) + len(env.ContextEnvelopes) + len(env.GovernanceTransitions) + len(env.AdminLog) +
\t\tlen(env.Verifications) + len(env.Exceptions) + len(env.Correlations) + len(env.Retrievals) + len(env.Probes) + len(env.ProtectionConfigs)
\tcmp("total", rc.Total, actualTotal)
}

// checkCertificationBundleHash recomputes the certified-copy fingerprint from
// the exact versioned section set used by atlasent-api's certified-copy.ts.
// Missing top-level arrays are treated as empty arrays, matching producer defaults.
func checkCertificationBundleHash(raw []byte, env *Envelope, res *VerificationResult) {
\tif env.Certification == nil {
\t\treturn
\t}
\tvar root map[string]any
\tdec := json.NewDecoder(bytes.NewReader(raw))
\tdec.UseNumber()
\tif err := dec.Decode(&root); err != nil {
\t\tres.AddFinding(CodeCertificationBundleHashMismatch, "", "cannot decode envelope for certification bundle hash: "+err.Error())
\t\treturn
\t}
\tsection := func(name string) any {
\t\tif v, ok := root[name]; ok && v != nil {
\t\t\treturn v
\t\t}
\t\treturn []any{}
\t}
\tmaterial := map[string]any{
\t\t"evaluations": section("evaluations"),
\t\t"context_envelopes": section("context_envelopes"),
\t\t"governance_transitions": section("governance_transitions"),
\t\t"admin_log": section("admin_log"),
\t}
\tif env.Certification.Version >= 2 { material["verification_events"] = section("verification_events") }
\tif env.Certification.Version >= 3 { material["exception_events"] = section("exception_events") }
\tif env.Certification.Version >= 4 { material["correlation_events"] = section("correlation_events") }
\tif env.Certification.Version >= 5 {
\t\tmaterial["retrieval_events"] = section("retrieval_events")
\t\tmaterial["probe_events"] = section("probe_events")
\t}
\tif env.Certification.Version >= 6 { material["protection_configurations"] = section("protection_configurations") }
\tcanonicalBytes, err := jcs.Canonicalize(material)
\tif err != nil {
\t\tres.AddFinding(CodeCertificationBundleHashMismatch, "", "cannot canonicalize certification record set: "+err.Error())
\t\treturn
\t}
\tdigest := sha256.Sum256(canonicalBytes)
\tgot := fmt.Sprintf("%x", digest[:])
\tif env.Certification.BundleSHA256 == "" || got != env.Certification.BundleSHA256 {
\t\tres.AddFinding(CodeCertificationBundleHashMismatch, "", fmt.Sprintf("certification bundle_sha256 mismatch: manifest=%q recomputed=%q", env.Certification.BundleSHA256, got))
\t}
}
''',
)

# Focused regression tests.
Path("internal/chain/engine_version_v5_test.go").write_text(r'''package chain

import (
    "bytes"
    "testing"
)

func TestCanonicalizeForHashV5PreservesEngineVersion(t *testing.T) {
    raw := []byte(`{"chain_version":5,"org_id":"org-1","sequence":1,"event_type":"x","actor_id":"a","engine_version":"runtime@1.2.3","payload":{},"previous_hash":"0000000000000000000000000000000000000000000000000000000000000000","key_version":"k1","entry_hash":"deadbeef","signature":"sig"}`)
    got, err := canonicalizeForHash(raw)
    if err != nil { t.Fatal(err) }
    if !bytes.Contains(got, []byte(`"engine_version":"runtime@1.2.3"`)) {
        t.Fatalf("v5 canonical bytes dropped engine_version: %s", got)
    }
    if bytes.Contains(got, []byte(`"entry_hash"`)) || bytes.Contains(got, []byte(`"signature"`)) {
        t.Fatalf("hash/signature fields must be excluded: %s", got)
    }
}
''')
Path("internal/envelope/certification_v6_test.go").write_text(r'''package envelope

import "testing"

func intp(v int) *int { return &v }

func TestCertificationV6CountsProtectionConfigurationsAndTotal(t *testing.T) {
    env := &Envelope{
        Evaluations: []json.RawMessage{json.RawMessage(`{"id":"e1"}`)},
        ProtectionConfigs: []json.RawMessage{json.RawMessage(`{"manifest":"pc1"}`)},
        Certification: &Certification{Version: 6, RecordCounts: CertificationRecordCounts{
            Evaluations: intp(1), ProtectionConfigs: intp(1), Total: intp(2),
        }},
    }
    res := &VerificationResult{}
    checkCertificationCounts(env, res)
    if len(res.Findings) != 0 { t.Fatalf("unexpected findings: %+v", res.Findings) }
    env.Certification.RecordCounts.ProtectionConfigs = intp(0)
    checkCertificationCounts(env, res)
    if len(res.Findings) == 0 || res.Findings[len(res.Findings)-1].Code != CodeCertificationCountMismatch {
        t.Fatalf("expected protection configuration count mismatch, got %+v", res.Findings)
    }
}

func TestCertificationV6BundleHashBindsProtectionConfigurations(t *testing.T) {
    raw := []byte(`{"version":1,"evaluations":[{"id":"e1","x":1}],"context_envelopes":[],"governance_transitions":[],"admin_log":[],"verification_events":[],"exception_events":[],"correlation_events":[],"retrieval_events":[],"probe_events":[],"protection_configurations":[{"manifest":"pc1"}]}`)
    env := &Envelope{Certification: &Certification{Version: 6, BundleSHA256: "d7ffacab64a6b4862ba67dc93d1726869ad10fd4b55e0dbaecd45cc09c1c2b11"}}
    res := &VerificationResult{}
    checkCertificationBundleHash(raw, env, res)
    if len(res.Findings) != 0 { t.Fatalf("unexpected hash finding: %+v", res.Findings) }
    env.Certification.BundleSHA256 = "00"
    checkCertificationBundleHash(raw, env, res)
    if len(res.Findings) == 0 || res.Findings[len(res.Findings)-1].Code != CodeCertificationBundleHashMismatch {
        t.Fatalf("expected bundle hash mismatch, got %+v", res.Findings)
    }
}
''').write_text if False else None
# Write the envelope test separately to keep imports explicit.
Path("internal/envelope/certification_v6_test.go").write_text('''package envelope

import (
    "encoding/json"
    "testing"
)

func intpV6(v int) *int { return &v }

func TestCertificationV6CountsProtectionConfigurationsAndTotal(t *testing.T) {
    env := &Envelope{
        Evaluations: []json.RawMessage{json.RawMessage(`{"id":"e1"}`)},
        ProtectionConfigs: []json.RawMessage{json.RawMessage(`{"manifest":"pc1"}`)},
        Certification: &Certification{Version: 6, RecordCounts: CertificationRecordCounts{
            Evaluations: intpV6(1), ProtectionConfigs: intpV6(1), Total: intpV6(2),
        }},
    }
    res := &VerificationResult{}
    checkCertificationCounts(env, res)
    if len(res.Findings) != 0 { t.Fatalf("unexpected findings: %+v", res.Findings) }
    env.Certification.RecordCounts.ProtectionConfigs = intpV6(0)
    checkCertificationCounts(env, res)
    if len(res.Findings) == 0 || res.Findings[len(res.Findings)-1].Code != CodeCertificationCountMismatch {
        t.Fatalf("expected protection configuration count mismatch, got %+v", res.Findings)
    }
}

func TestCertificationV6BundleHashBindsProtectionConfigurations(t *testing.T) {
    raw := []byte(`{"version":1,"evaluations":[{"id":"e1","x":1}],"context_envelopes":[],"governance_transitions":[],"admin_log":[],"verification_events":[],"exception_events":[],"correlation_events":[],"retrieval_events":[],"probe_events":[],"protection_configurations":[{"manifest":"pc1"}]}`)
    env := &Envelope{Certification: &Certification{Version: 6, BundleSHA256: "d7ffacab64a6b4862ba67dc93d1726869ad10fd4b55e0dbaecd45cc09c1c2b11"}}
    res := &VerificationResult{}
    checkCertificationBundleHash(raw, env, res)
    if len(res.Findings) != 0 { t.Fatalf("unexpected hash finding: %+v", res.Findings) }
    env.Certification.BundleSHA256 = "00"
    checkCertificationBundleHash(raw, env, res)
    if len(res.Findings) == 0 || res.Findings[len(res.Findings)-1].Code != CodeCertificationBundleHashMismatch {
        t.Fatalf("expected bundle hash mismatch, got %+v", res.Findings)
    }
}
''')
