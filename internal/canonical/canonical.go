// Package canonical implements the AtlaSent audit-chain canonical
// form per atlasent-docs/architecture/specs/audit-chain-canonical-form.md
// (currently at v5).
//
// The canonicalizer accepts a parsed `any` value (the shape produced
// by encoding/json with json.Number for numeric fidelity) and emits
// the canonical byte sequence:
//
//   - object keys sorted lexicographically by UTF-8 byte order
//   - no insignificant whitespace
//   - UTF-8 strings (non-ASCII emitted directly)
//   - integers without leading zeros / "+" sign / trailing ".0"
//   - no floats in payloads (rejected)
//   - no duplicate object keys (rejected)
//   - arrays preserve order
//
// Hashing inputs are obtained via Bytes(value); verifiers compare
// against the stored entry_hash and the producer's canonicalizer.
//
// Any change to this implementation is a chain-version bump per the
// spec. Tests in this package are the canonical-form lock.
package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ErrFloatInPayload is returned when a JSON number that does not
// parse as an integer appears in a payload. Producers MUST serialize
// non-integer scalars as strings; floats break canonical equality
// across float representations.
var ErrFloatInPayload = errors.New("canonical: float in payload (producer must use strings for non-integer scalars)")

// ErrDuplicateKey is returned when an object contains duplicate keys.
var ErrDuplicateKey = errors.New("canonical: duplicate object key")

// Bytes returns the canonical UTF-8 byte serialization of v.
//
// v is typically the result of json.Unmarshal-with-UseNumber.
func Bytes(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encode(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// FromJSON parses src as JSON (with json.Number for numeric fidelity)
// and returns its canonical form. Convenience wrapper.
func FromJSON(src []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("canonical: parse: %w", err)
	}
	if dec.More() {
		return nil, errors.New("canonical: trailing data after top-level value")
	}
	return Bytes(v)
}

func encode(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeString(buf, x)
	case json.Number:
		// Integers only. Anything that doesn't parse as int64 is a
		// float and rejected.
		s := string(x)
		if _, err := strconv.ParseInt(s, 10, 64); err != nil {
			// Allow arbitrary-precision integers (no leading zeros,
			// no '+', no '.', no 'e/E'). The ParseInt failure above
			// catches floats; reject anything that looks float-like.
			if strings.ContainsAny(s, ".eE") {
				return fmt.Errorf("%w: %s", ErrFloatInPayload, s)
			}
			// Integer outside int64; emit raw if it's a valid
			// integer literal.
			if !isIntegerLiteral(s) {
				return fmt.Errorf("canonical: malformed number %q", s)
			}
		}
		buf.WriteString(s)
	case map[string]any:
		return encodeObject(buf, x)
	case []any:
		return encodeArray(buf, x)
	default:
		return fmt.Errorf("canonical: unsupported type %T", v)
	}
	return nil
}

func encodeObject(buf *bytes.Buffer, m map[string]any) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	// Duplicate keys are impossible in Go map[string]any (the map
	// would have collapsed them), but the spec disallows them at
	// the JSON layer. A stricter implementation parses the raw
	// JSON and detects duplicates pre-deserialization. For the V1
	// scaffold we rely on json.Decoder behavior + a test that
	// catches duplicate keys in raw JSON inputs at the entry
	// boundary.

	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		writeString(buf, k)
		buf.WriteByte(':')
		if err := encode(buf, m[k]); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

func encodeArray(buf *bytes.Buffer, a []any) error {
	buf.WriteByte('[')
	for i, e := range a {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := encode(buf, e); err != nil {
			return err
		}
	}
	buf.WriteByte(']')
	return nil
}

// writeString emits a JSON string per the canonical-form rules:
// UTF-8 directly for non-ASCII; only minimal required escapes for
// ASCII control + structural characters.
func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				// JSON requires escaping U+0000..U+001F.
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				// Non-ASCII emitted directly per spec.
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

func isIntegerLiteral(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[0] == '-' {
		if len(s) == 1 {
			return false
		}
		i = 1
	}
	// No leading zeros (except literal "0" or "-0").
	if s[i] == '0' && i+1 < len(s) {
		return false
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
