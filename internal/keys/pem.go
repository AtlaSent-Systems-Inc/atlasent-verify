// Package keys loads Ed25519 public keys from a PEM file for the
// audit-verify CLI. Each PEM block is expected to have:
//
//   - Type: "ATLASENT PUBLIC KEY"  (or the standard "PUBLIC KEY")
//   - Header: kid: <key_version>   (the selector matching entry.key_version)
//   - Body: the Ed25519 public key (32 bytes, DER-encoded SubjectPublicKeyInfo)
//
// The keystore is in-memory; the file is read once at CLI startup
// per ADR-020 (no network, no DB).
package keys

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// Store maps key_version → ed25519.PublicKey.
type Store struct {
	m map[string]ed25519.PublicKey
}

// LoadFile reads a PEM file and returns a Store.
func LoadFile(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keys: read %s: %w", path, err)
	}
	return Parse(data)
}

// Parse reads PEM bytes and returns a Store.
func Parse(data []byte) (*Store, error) {
	s := &Store{m: map[string]ed25519.PublicKey{}}
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest

		kid := block.Headers["kid"]
		if kid == "" {
			return nil, fmt.Errorf("keys: PEM block missing required 'kid' header")
		}

		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("keys: parse PKIX for kid=%s: %w", kid, err)
		}
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("keys: kid=%s is not ed25519", kid)
		}
		s.m[kid] = edPub
	}
	if len(s.m) == 0 {
		return nil, errors.New("keys: no PEM blocks found")
	}
	return s, nil
}

// PublicKey implements chain.KeyStore.
func (s *Store) PublicKey(kid string) (ed25519.PublicKey, bool) {
	pk, ok := s.m[kid]
	return pk, ok
}

// KIDs returns the set of loaded key versions (sorted insertion is
// not preserved; for testing).
func (s *Store) KIDs() []string {
	out := make([]string, 0, len(s.m))
	for k := range s.m {
		out = append(out, k)
	}
	return out
}
