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
