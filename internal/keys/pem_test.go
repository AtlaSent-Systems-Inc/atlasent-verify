package keys

import (
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
	pemBytes = appendPEM(t, pemBytes, "runtime-v2", pk2)

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

func appendPEM(t *testing.T, dst []byte, kid string, pk ed25519.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	return append(dst, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{"kid": kid}, Bytes: der})...)
}
