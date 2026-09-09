package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestParseLooksUpPublicKeyByKID(t *testing.T) {
	pk1, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pemBytes := appendPEM(t, nil, "runtime-v1", pk1)
	pemBytes = append(pemBytes, encodePEM(t, "ATLASENT PUBLIC KEY", map[string]string{"kid": "runtime-v2"}, pk2)...)

	store, err := Parse(pemBytes)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, ok := store.PublicKey("runtime-v1"); !ok || !got.Equal(pk1) {
		t.Fatalf("runtime-v1 lookup mismatch: ok=%v got=%x want=%x", ok, got, pk1)
	}
	if got, ok := store.PublicKey("runtime-v2"); !ok || !got.Equal(pk2) {
		t.Fatalf("runtime-v2 lookup mismatch: ok=%v got=%x want=%x", ok, got, pk2)
	}
	if _, ok := store.PublicKey("missing"); ok {
		t.Fatal("missing kid unexpectedly resolved")
	}
}

func TestParseAllowsSurroundingWhitespace(t *testing.T) {
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := appendPEM(t, nil, "runtime-v1", pk)
	pemBytes = append([]byte("\n\t"), pemBytes...)
	pemBytes = append(pemBytes, []byte("\n  ")...)

	store, err := Parse(pemBytes)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, ok := store.PublicKey("runtime-v1"); !ok || !got.Equal(pk) {
		t.Fatalf("runtime-v1 lookup mismatch: ok=%v got=%x want=%x", ok, got, pk)
	}
}

func TestParseAllowsBeginTextWithinKID(t *testing.T) {
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := "release-----BEGIN 2026"

	store, err := Parse(appendPEM(t, nil, kid, pk))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, ok := store.PublicKey(kid); !ok || !got.Equal(pk) {
		t.Fatalf("kid lookup mismatch: ok=%v got=%x want=%x", ok, got, pk)
	}
}

func TestParseRejectsAmbiguousTrustRootInput(t *testing.T) {
	pk1, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	first := appendPEM(t, nil, "runtime-v1", pk1)
	duplicate := appendPEM(t, append([]byte{}, first...), "runtime-v1", pk2)
	duplicateHeader := bytes.Replace(first,
		[]byte("kid: runtime-v1\n"),
		[]byte("kid: runtime-v1\nkid: runtime-v2\n"), 1)
	if bytes.Equal(duplicateHeader, first) {
		t.Fatal("duplicate-header fixture replacement did not apply")
	}
	normalizedDuplicateHeader := bytes.Replace(first,
		[]byte("kid: runtime-v1\n"),
		[]byte("kid: runtime-v1\n kid: runtime-v2\n"), 1)
	if bytes.Equal(normalizedDuplicateHeader, first) {
		t.Fatal("normalized-duplicate-header fixture replacement did not apply")
	}
	malformedPrefix := append([]byte("-----BEGIN PUBLIC KEY-----\nkid: broken\n"), first...)
	wrongType := encodePEM(t, "PRIVATE KEY", map[string]string{"kid": "runtime-v1"}, pk1)
	unknownHeader := encodePEM(t, "PUBLIC KEY", map[string]string{"kid": "runtime-v1", "KID": "runtime-v2"}, pk1)
	cases := map[string][]byte{
		"duplicate kid":               duplicate,
		"duplicate header":            duplicateHeader,
		"normalized duplicate header": normalizedDuplicateHeader,
		"malformed prefix":            malformedPrefix,
		"leading junk":                append([]byte("not-a-trust-root\n"), first...),
		"trailing junk":               append(append([]byte{}, first...), []byte("not-a-trust-root")...),
		"wrong PEM type":              wrongType,
		"unknown header":              unknownHeader,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(input); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestParseRejectsTrustRootWithoutKID(t *testing.T) {
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	bad := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if _, err := Parse(bad); err == nil {
		t.Fatal("expected missing kid header to be rejected")
	}
}

// TestParseHasNoRevocationConcept documents, with a regression test, a real
// architectural boundary rather than a bug: the PEM Store loaded via --keys
// carries kid -> public key only. It has no field, header, or code path for
// "revoked" — that state exists only in the published trust root's JWKS
// (atlasent-keys' .well-known/atlasent-verifier-keys.json, each key entry
// carrying a `revoked` boolean) and the atlasent-revocations.json list.
//
// Concretely: if an operator's --keys PEM file happens to still include a
// key whose kid the trust root marks revoked (e.g. an over-broad export
// from the JWKS that didn't filter on `revoked: false`), this verifier
// treats it as fully trusted — because it is fully offline by contract (see
// docs/verification-contract.md's "Offline requirement") and never fetches
// live revocation state. Filtering out revoked kids before constructing the
// PEM keyfile is therefore the OPERATOR's responsibility, not something
// this tool can enforce for itself. This test locks that boundary so a
// future change doesn't silently assume the PEM format carries revocation
// semantics it never has.
func TestParseHasNoRevocationConcept(t *testing.T) {
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// A kid named the way a revoked trust-root entry would be (mirroring
	// atlasent-keys' "revoked-kid" placeholder) — nothing about the kid
	// STRING itself carries revocation meaning to this package.
	pemBytes := appendPEM(t, nil, "revoked-kid", pk)
	store, err := Parse(pemBytes)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got, ok := store.PublicKey("revoked-kid")
	if !ok || !got.Equal(pk) {
		t.Fatal("expected the key to resolve — Store has no revocation gate to test around")
	}
	// KIDs() likewise reports it as an ordinary loaded kid, with no
	// distinction from a live one.
	found := false
	for _, k := range store.KIDs() {
		if k == "revoked-kid" {
			found = true
		}
	}
	if !found {
		t.Error("revoked-kid missing from KIDs()")
	}
}

func appendPEM(t *testing.T, dst []byte, kid string, pk ed25519.PublicKey) []byte {
	return append(dst, encodePEM(t, "PUBLIC KEY", map[string]string{"kid": kid}, pk)...)
}

func encodePEM(t *testing.T, blockType string, headers map[string]string, pk ed25519.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Headers: headers, Bytes: der})
}
