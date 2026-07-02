package canonical

import (
	"bytes"
	"testing"
)

// These tests are the canonical-form LOCK for AtlaSent audit chain
// v5. Any change here is a chain-version bump per the spec. Do not
// edit a golden value to make a failing test pass — instead, treat
// the failure as a canonical-form regression and fix the
// canonicalizer.

func TestPrimitives(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`null`, `null`},
		{`true`, `true`},
		{`false`, `false`},
		{`0`, `0`},
		{`-0`, `-0`},
		{`42`, `42`},
		{`-42`, `-42`},
		{`9007199254740992`, `9007199254740992`}, // int53+ — must round-trip
		{`"hello"`, `"hello"`},
		{`"\""`, `"\""`},
		{`"\\"`, `"\\"`},
		{`"café"`, `"café"`}, // unicode escape input → direct UTF-8 output
		{`"line1\nline2"`, `"line1\nline2"`},
		{`"\u0001"`, `"\u0001"`}, // U+0001 stays escaped
	}
	for _, c := range cases {
		got, err := FromJSON([]byte(c.in))
		if err != nil {
			t.Errorf("FromJSON(%q) error: %v", c.in, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("FromJSON(%q) = %q, want %q", c.in, string(got), c.want)
		}
	}
}

func TestObjectKeySorting(t *testing.T) {
	in := `{"b":1,"a":2,"c":3}`
	want := `{"a":2,"b":1,"c":3}`
	got, err := FromJSON([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestNestedObjectKeySorting(t *testing.T) {
	in := `{"outer":{"z":1,"a":2,"m":3},"prefix":"x"}`
	want := `{"outer":{"a":2,"m":3,"z":1},"prefix":"x"}`
	got, err := FromJSON([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestArrayPreservesOrder(t *testing.T) {
	in := `[3,1,2]`
	want := `[3,1,2]`
	got, err := FromJSON([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestNoWhitespace(t *testing.T) {
	// Heavy whitespace input; canonical output has none.
	in := "{\n  \"a\": [\n    1,\n    2\n  ],\n  \"b\": \"x\"\n}"
	want := `{"a":[1,2],"b":"x"}`
	got, err := FromJSON([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestFloatRejected(t *testing.T) {
	// Producers must use strings for non-integer scalars.
	_, err := FromJSON([]byte(`3.14`))
	if err == nil {
		t.Fatal("expected error for float, got nil")
	}
	if !contains(err.Error(), "float in payload") {
		t.Errorf("expected float-in-payload error, got: %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	// canonicalize(parse(canonicalize(x))) == canonicalize(x)
	in := `{"z":[1,{"b":2,"a":3}],"x":"é"}`
	first, err := FromJSON([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	second, err := FromJSON(first)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("round-trip drift:\n first  = %s\n second = %s", first, second)
	}
}

func TestTrailingDataRejected(t *testing.T) {
	_, err := FromJSON([]byte(`{"a":1} extra`))
	if err == nil {
		t.Fatal("expected error for trailing data, got nil")
	}
}

func TestEmptyContainers(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`{}`, `{}`},
		{`[]`, `[]`},
		{`{"a":[]}`, `{"a":[]}`},
		{`{"a":{}}`, `{"a":{}}`},
	}
	for _, c := range cases {
		got, err := FromJSON([]byte(c.in))
		if err != nil {
			t.Errorf("FromJSON(%q): %v", c.in, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("FromJSON(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

func contains(s, sub string) bool {
	return bytes.Contains([]byte(s), []byte(sub))
}
