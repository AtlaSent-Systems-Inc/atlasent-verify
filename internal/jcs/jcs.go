// Package jcs implements RFC 8785 JSON Canonicalization Scheme, byte-identical
// to atlasent-api's _shared/canonical.ts (sorted keys at all depths, no
// whitespace, JSON.stringify string escaping, ECMAScript Number::toString for
// numbers). It is the canonical form the export-audit ENVELOPE outer signature
// is computed over — distinct from internal/canonical (the per-row audit-chain
// form). Reproducing these bytes exactly is what lets the verifier check the
// outer Ed25519 signature offline.
package jcs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
)

// Canonicalize returns the JCS canonical form of an already-decoded JSON value
// (numbers must be json.Number or float64; maps are map[string]any).
func Canonicalize(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := encodeValue(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// CanonicalizeRaw decodes raw JSON (preserving number tokens) then canonicalizes.
func CanonicalizeRaw(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return Canonicalize(v)
}

func encodeValue(b *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		encodeString(b, t)
	case json.Number:
		f, err := strconv.ParseFloat(t.String(), 64)
		if err != nil {
			return fmt.Errorf("jcs: invalid number %q: %w", t.String(), err)
		}
		s, err := esNumber(f)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case float64:
		s, err := esNumber(t)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encodeValue(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sortKeysUTF16(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			encodeString(b, k)
			b.WriteByte(':')
			if err := encodeValue(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("jcs: unsupported value type %T", v)
	}
	return nil
}

// encodeString writes a JSON string escaped exactly as ECMAScript
// JSON.stringify (= RFC 8785 §3.2.2.2): only ", \, and the C0 control chars are
// escaped (with the short forms \b \t \n \f \r, else \u00xx lowercase hex);
// every other code point — including non-ASCII and '/' — is emitted literally.
func encodeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// sortKeysUTF16 sorts object keys by UTF-16 code units, matching RFC 8785
// §3.2.3 and JavaScript's Array.prototype.sort default (which _shared/
// canonical.ts relies on via Object.keys().sort()). For the ASCII keys in
// these envelopes this equals byte order, but non-ASCII customer-jsonb keys
// require the UTF-16 comparison to match the producer exactly.
func sortKeysUTF16(keys []string) {
	sort.SliceStable(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
}

func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}
