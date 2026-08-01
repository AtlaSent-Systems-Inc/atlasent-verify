package jcs

import (
	"bytes"
	"testing"
)

// TestESNumber covers the ECMAScript Number::toString serialization that RFC
// 8785 3.2.2.3 mandates. Each expected value is what JavaScript's String(n) /
// JSON.stringify(n) emits — the bytes the producer (_shared/canonical.ts, via
// JSON.stringify) signs. If any of these drift the outer-envelope signature
// can never be reproduced offline.
func TestESNumber(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		// integers
		{0, "0"},
		{-0, "0"}, // ECMAScript: -0 stringifies to "0"
		{1, "1"},
		{5, "5"},
		{-5, "-5"},
		{100, "100"},
		{1000, "1000"},
		{-1000, "-1000"},
		{9007199254740991, "9007199254740991"}, // Number.MAX_SAFE_INTEGER
		// simple fractions
		{0.1, "0.1"},
		{0.5, "0.5"},
		{1.5, "1.5"},
		{-1.5, "-1.5"},
		{0.99, "0.99"},
		{123.456, "123.456"},
		{-123.456, "-123.456"},
		{0.001, "0.001"},
		{0.0001, "0.0001"},
		{0.000001, "0.000001"}, // n = -5, still fixed notation
		// exponential boundaries
		{1e21, "1e+21"},                 // n = 22 -> exponential
		{1e-7, "1e-7"},                  // n = -6 -> exponential
		{1.5e21, "1.5e+21"},             // multi-digit mantissa
		{1.23e-7, "1.23e-7"},            //
		{1e20, "100000000000000000000"}, // n = 21 -> still fixed
		// confidence-style values (the float that actually rides the envelope)
		{0.0, "0"},
		{0.85, "0.85"},
		{0.9999, "0.9999"},
		{1.0, "1"},
	}
	for _, c := range cases {
		got, err := esNumber(c.in)
		if err != nil {
			t.Errorf("esNumber(%v) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("esNumber(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestESNumberNonFinite(t *testing.T) {
	inf := 1.0
	for i := 0; i < 400; i++ {
		inf *= 10 // overflow to +Inf
	}
	nan := inf - inf
	for _, f := range []float64{inf, -inf, nan} {
		if _, err := esNumber(f); err != ErrNonFiniteNumber {
			t.Errorf("esNumber(%v) err = %v, want ErrNonFiniteNumber", f, err)
		}
	}
}

// TestEncodeStringLiteral covers the JSON.stringify string escaping RFC 8785
// 3.2.2.2 requires for the non-escaped code points: quote and backslash
// escaped; every other printable/non-ASCII code point (including '/') emitted
// literally.
func TestEncodeStringLiteral(t *testing.T) {
	q := `"`
	bs := "\\" // one backslash
	cases := []struct {
		in   string
		want string
	}{
		{"", q + q},
		{"hello", q + "hello" + q},
		{`a"b`, q + "a" + bs + `"` + "b" + q},
		{`a\b`, q + "a" + bs + bs + "b" + q},
		{"slash/here", q + "slash/here" + q}, // '/' NOT escaped
		{"café", q + "café" + q},             // non-ASCII literal
		{"emoji😀", q + "emoji😀" + q},          // supplementary plane literal
		{"日本語", q + "日本語" + q},                // CJK literal
	}
	for _, c := range cases {
		var b bytes.Buffer
		encodeString(&b, c.in)
		if got := b.String(); got != c.want {
			t.Errorf("encodeString(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

// TestEncodeStringEscapes covers the two-char short escapes and the \u00xx
// long form for C0 controls without a short form (lowercase hex). Expectations
// are built by concatenation so no literal backslash-u appears in source.
func TestEncodeStringEscapes(t *testing.T) {
	q := `"`
	bs := "\\" // one backslash
	u := func(hex string) string { return bs + "u" + hex }
	cases := []struct {
		in   string
		want string
	}{
		{"\x08", q + bs + "b" + q}, // backspace short form
		{"\x09", q + bs + "t" + q}, // tab short form
		{"\x0a", q + bs + "n" + q}, // LF short form
		{"\x0c", q + bs + "f" + q}, // FF short form
		{"\x0d", q + bs + "r" + q}, // CR short form
		{"\x00", q + u("0000") + q},
		{"\x01", q + u("0001") + q},
		{"\x1b", q + u("001b") + q}, // ESC -> lowercase hex
		{"\x1f", q + u("001f") + q}, // unit separator
		{"a\x07b", q + "a" + u("0007") + "b" + q}, // BEL embedded
	}
	for _, c := range cases {
		var b bytes.Buffer
		encodeString(&b, c.in)
		if got := b.String(); got != c.want {
			t.Errorf("encodeString(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

// TestCanonicalizeObjects covers key sorting at all depths plus nested arrays,
// matching _shared/canonical.ts (Object.keys().sort() at every level).
func TestCanonicalizeObjects(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"empty object", map[string]any{}, `{}`},
		{"empty array", []any{}, `[]`},
		{"scalar sort", map[string]any{"b": 1.0, "a": 2.0, "c": 3.0}, `{"a":2,"b":1,"c":3}`},
		{"nested object sort", map[string]any{
			"z": map[string]any{"y": 1.0, "x": 2.0},
			"a": 3.0,
		}, `{"a":3,"z":{"x":2,"y":1}}`},
		{"array preserves order", []any{3.0, 1.0, 2.0}, `[3,1,2]`},
		{"array of objects", []any{
			map[string]any{"b": 1.0, "a": 2.0},
			map[string]any{"d": 3.0, "c": 4.0},
		}, `[{"a":2,"b":1},{"c":4,"d":3}]`},
		{"mixed types", map[string]any{
			"num":  1.5,
			"str":  "hi",
			"bool": true,
			"nul":  nil,
			"arr":  []any{1.0, 2.0},
		}, `{"arr":[1,2],"bool":true,"nul":null,"num":1.5,"str":"hi"}`},
		{"utf16 key order", map[string]any{"é": 1.0, "a": 2.0, "z": 3.0}, `{"a":2,"z":3,"é":1}`},
	}
	for _, c := range cases {
		got, err := Canonicalize(c.in)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", c.name, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("%s: Canonicalize = %s, want %s", c.name, got, c.want)
		}
	}
}

// TestCanonicalizeRaw exercises the JSON-decode path (json.Number preservation)
// against a representative export-envelope shape. The expected string is the
// hand-computed _shared/canonical.ts output: sorted keys, no whitespace,
// ES-number scalars.
func TestCanonicalizeRaw(t *testing.T) {
	// A miniature export envelope minus its signature (the exact object the
	// producer canonicalizes + signs). Keys deliberately out of order.
	raw := `{
	  "version": "export-audit-v1",
	  "correlation_events": [
	    {"decision_id": "d-1", "correlation_status": "MATCH", "confidence": 0.95}
	  ],
	  "org_id": "org-1",
	  "evaluations": []
	}`
	want := `{"correlation_events":[{"confidence":0.95,"correlation_status":"MATCH","decision_id":"d-1"}],"evaluations":[],"org_id":"org-1","version":"export-audit-v1"}`
	got, err := CanonicalizeRaw([]byte(raw))
	if err != nil {
		t.Fatalf("CanonicalizeRaw error: %v", err)
	}
	if string(got) != want {
		t.Errorf("CanonicalizeRaw =\n  %s\nwant\n  %s", got, want)
	}
}

// TestCanonicalizeRawIntegerNumbers confirms integer JSON tokens round-trip as
// integers (not "1.0") through the json.Number -> esNumber path.
func TestCanonicalizeRawIntegerNumbers(t *testing.T) {
	got, err := CanonicalizeRaw([]byte(`{"count":216,"ratio":0.5,"big":1000000}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"big":1000000,"count":216,"ratio":0.5}`
	if string(got) != want {
		t.Errorf("CanonicalizeRaw = %s, want %s", got, want)
	}
}
