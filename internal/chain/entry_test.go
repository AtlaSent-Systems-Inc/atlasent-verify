package chain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/atlasent-systems-inc/atlasent-verify/internal/canonical"
)

type memKeys struct{ pk ed25519.PublicKey }

func (m memKeys) PublicKey(kid string) (ed25519.PublicKey, bool) {
	if kid == "k1" {
		return m.pk, true
	}
	return nil, false
}

// buildEntry mints a v5 entry given prior hash + sequence + signing
// key, and returns the JSON line.
func buildEntry(t *testing.T, prevHash []byte, seq int64, sk ed25519.PrivateKey, payload map[string]any) []byte {
	t.Helper()
	prevHex := hex.EncodeToString(prevHash)
	entry := map[string]any{
		"chain_version": json.Number("5"),
		"org_id":        "org-1",
		"sequence":      json.Number(itoa(seq)),
		"event_type":    "test.event",
		"actor_id":      "actor-1",
		"payload":       payload,
		"previous_hash": prevHex,
		"key_version":   "k1",
	}
	canonBytes, err := canonical.Bytes(entry)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	h := sha256.New()
	h.Write(prevHash)
	h.Write(canonBytes)
	hash := h.Sum(nil)
	entry["entry_hash"] = hex.EncodeToString(hash)
	entry["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(sk, hash))
	out, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func TestVerifyHappyPath(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)

	// Build 3 entries chained off genesis.
	e1 := buildEntry(t, zeros, 1, sk, map[string]any{"k": "v1"})
	// To get e2's prev_hash, parse e1 and pull entry_hash out.
	prev := mustEntryHash(t, e1)
	e2 := buildEntry(t, prev, 2, sk, map[string]any{"k": "v2"})
	prev = mustEntryHash(t, e2)
	e3 := buildEntry(t, prev, 3, sk, map[string]any{"k": "v3"})

	chain := append(append(append([]byte{}, e1...), '\n'), e2...)
	chain = append(append(chain, '\n'), e3...)

	res, err := Verify(bytes.NewReader(chain), memKeys{pk: pk})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got: %+v", res.Findings)
	}
	if res.EntriesScanned != 3 {
		t.Errorf("scanned=%d, want 3", res.EntriesScanned)
	}
	if res.HeadByOrg["org-1"] != 3 {
		t.Errorf("head=%d, want 3", res.HeadByOrg["org-1"])
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntry(t, zeros, 1, sk, map[string]any{"k": "v1"})

	// Tamper: flip a payload bit.
	tampered := bytes.Replace(e1, []byte(`"v1"`), []byte(`"v2"`), 1)

	res, err := Verify(bytes.NewReader(tampered), memKeys{pk: pk})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected findings, got none")
	}
	// The first finding should be a hash_mismatch.
	if res.Findings[0].Kind != "hash_mismatch" {
		t.Errorf("first finding kind=%q, want hash_mismatch", res.Findings[0].Kind)
	}
}

func TestVerifyDetectsGap(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntry(t, zeros, 1, sk, map[string]any{"k": "v1"})
	prev := mustEntryHash(t, e1)
	// Skip sequence 2; build at sequence 3 with prev = e1's hash.
	e3 := buildEntry(t, prev, 3, sk, map[string]any{"k": "v3"})

	chain := append(append([]byte{}, e1...), '\n')
	chain = append(chain, e3...)

	res, err := Verify(bytes.NewReader(chain), memKeys{pk: pk})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if f.Kind == "ordering" && strings.Contains(f.Detail, "expected sequence 2") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ordering finding for skipped sequence, got: %+v", res.Findings)
	}
}

func TestVerifyDetectsBadSignature(t *testing.T) {
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Use a DIFFERENT signing key to mint the entry.
	_, badSk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntry(t, zeros, 1, badSk, map[string]any{"k": "v1"})

	res, err := Verify(bytes.NewReader(e1), memKeys{pk: pk})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if f.Kind == "signature_invalid" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected signature_invalid finding, got: %+v", res.Findings)
	}
}

// TestSignatureCountersAllVerified confirms that a fully-signed chain
// verified against a known key reports SignaturesVerified == entries and
// SignaturesSkipped == 0, and that the strict-acceptance contract accepts it.
func TestSignatureCountersAllVerified(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntry(t, zeros, 1, sk, map[string]any{"k": "v1"})
	prev := mustEntryHash(t, e1)
	e2 := buildEntry(t, prev, 2, sk, map[string]any{"k": "v2"})
	chain := bytes.Join([][]byte{e1, e2}, []byte{'\n'})

	res, err := Verify(bytes.NewReader(chain), memKeys{pk: pk})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.SignaturesVerified != 2 {
		t.Errorf("SignaturesVerified=%d, want 2", res.SignaturesVerified)
	}
	if res.SignaturesSkipped != 0 {
		t.Errorf("SignaturesSkipped=%d, want 0", res.SignaturesSkipped)
	}
	ok, reason := res.StrictSignatureAcceptance(true)
	if !ok {
		t.Errorf("StrictSignatureAcceptance rejected a fully-verified chain: %s", reason)
	}
}

// TestStrictAcceptanceRejectsSkippedSignature is the core acceptance-weakness
// fix: when --keys is supplied but the chain's key_version is absent from the
// keystore, the signature is SKIPPED. Hash continuity still passes (0
// findings, a bare exit-0), but the strict contract must REJECT it because no
// signature was actually verified — "exit 0" alone is not pilot evidence.
func TestStrictAcceptanceRejectsSkippedSignature(t *testing.T) {
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// keystore only knows "k1"; the entry below uses "future-v99".
	pkOther, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	raw := map[string]any{
		"chain_version": json.Number("5"),
		"org_id":        "org-1",
		"sequence":      json.Number("1"),
		"event_type":    "test.event",
		"actor_id":      "actor-1",
		"payload":       map[string]any{"k": "v1"},
		"previous_hash": hex.EncodeToString(zeros),
		"key_version":   "future-v99",
	}
	canonBytes, err := canonical.Bytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	h.Write(zeros)
	h.Write(canonBytes)
	hash := h.Sum(nil)
	raw["entry_hash"] = hex.EncodeToString(hash)
	raw["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(sk, hash))
	line, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	res, err := Verify(bytes.NewReader(line), memKeys{pk: pkOther})
	if err != nil {
		t.Fatal(err)
	}
	// Hash chain is intact — a bare run is green.
	if len(res.Findings) != 0 {
		t.Fatalf("expected 0 integrity findings (hash intact), got: %+v", res.Findings)
	}
	if res.SignaturesVerified != 0 || res.SignaturesSkipped != 1 {
		t.Fatalf("verified=%d skipped=%d, want verified=0 skipped=1", res.SignaturesVerified, res.SignaturesSkipped)
	}
	// Strict acceptance must reject it and say WHY (skipped signature).
	ok, reason := res.StrictSignatureAcceptance(true)
	if ok {
		t.Fatal("strict acceptance MUST reject a chain whose signatures were all skipped")
	}
	if !strings.Contains(reason, "SKIPPED") {
		t.Errorf("reason should name the skipped signature; got %q", reason)
	}
}

// TestStrictAcceptanceRejectsNoKeys: without a keystore, nothing could have
// been verified, so strict acceptance must fail regardless of hash results.
func TestStrictAcceptanceRejectsNoKeys(t *testing.T) {
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntry(t, zeros, 1, sk, map[string]any{"k": "v1"})
	res, err := Verify(bytes.NewReader(e1), nil) // no keystore
	if err != nil {
		t.Fatal(err)
	}
	if ok, reason := res.StrictSignatureAcceptance(false); ok {
		t.Errorf("strict acceptance must fail with no keys; got ok (reason=%q)", reason)
	}
}

// TestStrictAcceptanceRejectsEmptyChain: an empty chain verified zero
// signatures, so there is nothing to accept.
func TestStrictAcceptanceRejectsEmptyChain(t *testing.T) {
	res, err := Verify(bytes.NewReader([]byte("")), memKeys{})
	if err != nil {
		t.Fatal(err)
	}
	if ok, reason := res.StrictSignatureAcceptance(true); ok {
		t.Errorf("strict acceptance must fail on an empty chain; got ok (reason=%q)", reason)
	}
}

// TestVerifyDetectsMalformedSignature: a syntactically invalid signature
// string (not decodable as base64url or standard-base64) is a hard finding
// (signature_decode), not a warning. The signature is excluded from the chain
// hash, so hash continuity still passes — only the signature bytes are corrupt.
// This closes the decode-error branch, which previously had no regression test.
func TestVerifyDetectsMalformedSignature(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntry(t, zeros, 1, sk, map[string]any{"k": "v1"})

	// Swap the signature for a non-decodable value. entry_hash stays valid
	// because signature is stripped before canonicalization.
	var m map[string]any
	if err := json.Unmarshal(e1, &m); err != nil {
		t.Fatal(err)
	}
	m["signature"] = "ed25519:@@@not-base64@@@"
	e1Bad, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	res, err := Verify(bytes.NewReader(e1Bad), memKeys{pk: pk})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if f.Kind == "signature_decode" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected signature_decode finding for malformed signature, got: %+v", res.Findings)
	}
	if res.SignaturesVerified != 0 {
		t.Errorf("SignaturesVerified=%d, want 0", res.SignaturesVerified)
	}
	// Strict acceptance must reject a chain carrying a decode finding.
	if ok, _ := res.StrictSignatureAcceptance(true); ok {
		t.Error("strict acceptance must reject a chain with a malformed signature")
	}
}

func mustEntryHash(t *testing.T, raw []byte) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	s, ok := m["entry_hash"].(string)
	if !ok {
		t.Fatal("entry_hash missing")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// buildEntryPrefixedSig is like buildEntry but uses the audit chain v5
// "ed25519:<base64url>" (URL-safe, no padding) signature format, matching
// what the AtlaSent runtime writes in production.
func buildEntryPrefixedSig(t *testing.T, prevHash []byte, seq int64, sk ed25519.PrivateKey, payload map[string]any) []byte {
	t.Helper()
	prevHex := hex.EncodeToString(prevHash)
	entry := map[string]any{
		"chain_version": json.Number("5"),
		"org_id":        "org-1",
		"sequence":      json.Number(itoa(seq)),
		"event_type":    "test.event",
		"actor_id":      "actor-1",
		"payload":       payload,
		"previous_hash": prevHex,
		"key_version":   "k1",
	}
	canonBytes, err := canonical.Bytes(entry)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	h := sha256.New()
	h.Write(prevHash)
	h.Write(canonBytes)
	hash := h.Sum(nil)
	entry["entry_hash"] = hex.EncodeToString(hash)
	// v5 prefixed format: "ed25519:<base64url>" (RawURL = no padding)
	entry["signature"] = "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(sk, hash))
	out, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

// TestVerifyPrefixedSignature checks that the v5 "ed25519:<base64url>"
// signature format is accepted by the verifier.
func TestVerifyPrefixedSignature(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)

	e1 := buildEntryPrefixedSig(t, zeros, 1, sk, map[string]any{"k": "v1"})
	prev := mustEntryHash(t, e1)
	e2 := buildEntryPrefixedSig(t, prev, 2, sk, map[string]any{"k": "v2"})

	chain := bytes.Join([][]byte{e1, e2}, []byte{'\n'})
	res, err := Verify(bytes.NewReader(chain), memKeys{pk: pk})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings for prefixed-signature entries, got: %+v", res.Findings)
	}
	if res.EntriesScanned != 2 {
		t.Errorf("scanned=%d, want 2", res.EntriesScanned)
	}
}

// TestVerifyEngineVersionAdditive checks that an "engine_version" field
// present in the exported JSON does not affect the recomputed hash.
// The runtime writes engine_version as additive metadata and does NOT
// include it in the canonical_payload fed to SHA-256, so the verifier
// must also exclude it.
func TestVerifyEngineVersionAdditive(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)

	// Build a well-formed entry (hash computed without engine_version).
	e1 := buildEntry(t, zeros, 1, sk, map[string]any{"k": "v1"})

	// Inject engine_version into the JSON — simulates a runtime that
	// writes the field as additive metadata but excluded it from the hash.
	var m map[string]any
	if err := json.Unmarshal(e1, &m); err != nil {
		t.Fatal(err)
	}
	m["engine_version"] = "wire-v1@1.0.0"
	e1WithEV, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	res, err := Verify(bytes.NewReader(e1WithEV), memKeys{pk: pk})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("engine_version must be additive (excluded from hash); got findings: %+v", res.Findings)
	}
	if res.EntriesScanned != 1 {
		t.Errorf("scanned=%d, want 1", res.EntriesScanned)
	}
}

// TestVerifyUnknownKeyVersionWarns checks that an entry whose key_version
// is not present in the keystore produces a warning (not a finding).  The
// hash chain is still verified; only signature verification is skipped.
// Exit code must be 0 for this case (no finding).
func TestVerifyUnknownKeyVersionWarns(t *testing.T) {
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// A separate public key whose kid is known to the keystore; the
	// entry will reference "future-v99" which the keystore does not have.
	pk2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	zeros := make([]byte, 32)
	prevHex := hex.EncodeToString(zeros)

	// Build the entry with key_version="future-v99" from the start so
	// the stored entry_hash is correct for that key_version value.
	// (key_version is part of the canonical payload, so it must be set
	// before the hash is computed.)
	raw := map[string]any{
		"chain_version": json.Number("5"),
		"org_id":        "org-1",
		"sequence":      json.Number("1"),
		"event_type":    "test.event",
		"actor_id":      "actor-1",
		"payload":       map[string]any{"k": "v1"},
		"previous_hash": prevHex,
		"key_version":   "future-v99",
	}
	canonBytes, err := canonical.Bytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	h.Write(zeros)
	h.Write(canonBytes)
	hash := h.Sum(nil)
	raw["entry_hash"] = hex.EncodeToString(hash)
	raw["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(sk, hash))
	e1Unknown, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	// Use a keystore that only knows "k1" — "future-v99" is absent.
	res, err := Verify(bytes.NewReader(e1Unknown), memKeys{pk: pk2})
	if err != nil {
		t.Fatal(err)
	}
	// Must be a warning, not a finding — the hash was still verified.
	if len(res.Findings) != 0 {
		t.Fatalf("unknown key_version should warn, not error; got findings: %+v", res.Findings)
	}
	found := false
	for _, w := range res.Warnings {
		if w.Kind == "unknown_key_version" && strings.Contains(w.Detail, "future-v99") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected unknown_key_version warning containing 'future-v99', got warnings: %+v", res.Warnings)
	}
	// The entry should still count as scanned and advance the head.
	if res.EntriesScanned != 1 {
		t.Errorf("scanned=%d, want 1", res.EntriesScanned)
	}
	if res.HeadByOrg["org-1"] != 1 {
		t.Errorf("HeadByOrg[org-1]=%d, want 1", res.HeadByOrg["org-1"])
	}
}
