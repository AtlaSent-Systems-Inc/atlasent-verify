package chain

import (
	"encoding/base64"
	"strings"
)

// decodeSignature decodes the entry's signature field.
//
// Audit chain v5 uses the prefixed format "ed25519:<base64url>" (URL-safe
// alphabet, no padding). Legacy exports use plain standard-base64 without a
// prefix. Both are accepted so older chain exports continue to verify.
func decodeSignature(s string) ([]byte, error) {
	const prefix = "ed25519:"
	if strings.HasPrefix(s, prefix) {
		return base64.RawURLEncoding.DecodeString(s[len(prefix):])
	}
	// Legacy: plain standard-base64 (pre-v5 exports).
	return base64.StdEncoding.DecodeString(s)
}

// decodeStd is the plain standard-base64 decoder retained for test
// helpers that mint entries without the "ed25519:" prefix. Production
// verification uses decodeSignature.
func decodeStd(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
