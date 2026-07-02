package chain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

// build3 returns a valid 3-entry chain for org-1 plus the verified
// Result, so anchor tests can assert against a known-good head.
func build3(t *testing.T) (*Result, ed25519.PublicKey) {
	t.Helper()
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntry(t, zeros, 1, sk, map[string]any{"k": "v1"})
	prev := mustEntryHash(t, e1)
	e2 := buildEntry(t, prev, 2, sk, map[string]any{"k": "v2"})
	prev = mustEntryHash(t, e2)
	e3 := buildEntry(t, prev, 3, sk, map[string]any{"k": "v3"})

	chain := bytes.Join([][]byte{e1, e2, e3}, []byte{'\n'})
	res, err := Verify(bytes.NewReader(chain), memKeys{pk: pk})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("setup chain should verify clean, got: %+v", res.Findings)
	}
	return res, pk
}

func findingKinds(res *Result) []string {
	out := make([]string, 0, len(res.Findings))
	for _, f := range res.Findings {
		out = append(out, f.Kind)
	}
	return out
}

func hasKind(res *Result, kind string) bool {
	for _, f := range res.Findings {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

func TestParseAnchorsValid(t *testing.T) {
	in := `{"anchors":[{"org_id":"org-1","sequence":3,"entry_hash":"` + strings.Repeat("a", 64) + `"}]}`
	set, err := ParseAnchors(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseAnchors: %v", err)
	}
	if len(set) != 1 || set["org-1"].Sequence != 3 {
		t.Fatalf("unexpected set: %+v", set)
	}
}

func TestParseAnchorsRejectsBad(t *testing.T) {
	cases := map[string]string{
		"empty":         `{"anchors":[]}`,
		"missing org":   `{"anchors":[{"sequence":1,"entry_hash":"` + strings.Repeat("a", 64) + `"}]}`,
		"zero sequence": `{"anchors":[{"org_id":"o","sequence":0,"entry_hash":"` + strings.Repeat("a", 64) + `"}]}`,
		"short hash":    `{"anchors":[{"org_id":"o","sequence":1,"entry_hash":"abc"}]}`,
		"unknown field": `{"anchors":[{"org_id":"o","sequence":1,"entry_hash":"` + strings.Repeat("a", 64) + `","x":1}]}`,
		"duplicate org": `{"anchors":[{"org_id":"o","sequence":1,"entry_hash":"` + strings.Repeat("a", 64) + `"},{"org_id":"o","sequence":2,"entry_hash":"` + strings.Repeat("b", 64) + `"}]}`,
		"not json":      `nope`,
	}
	for name, in := range cases {
		if _, err := ParseAnchors(strings.NewReader(in)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestCheckAnchorsMatch(t *testing.T) {
	res, _ := build3(t)
	anchors := AnchorSet{"org-1": {OrgID: "org-1", Sequence: 3, EntryHash: res.HeadHashByOrg["org-1"]}}
	CheckAnchors(res, anchors)
	if len(res.Findings) != 0 {
		t.Fatalf("matching anchor should produce no findings, got: %v", findingKinds(res))
	}
	if got := AnchoredOrgs(res, anchors); got != 1 {
		t.Errorf("AnchoredOrgs=%d, want 1", got)
	}
}

func TestCheckAnchorsDetectsTruncation(t *testing.T) {
	res, _ := build3(t)
	// Trusted head is sequence 5, but the chain only reaches 3.
	anchors := AnchorSet{"org-1": {OrgID: "org-1", Sequence: 5, EntryHash: strings.Repeat("f", 64)}}
	CheckAnchors(res, anchors)
	if !hasKind(res, "truncation") {
		t.Fatalf("expected truncation finding, got: %v", findingKinds(res))
	}
	for _, f := range res.Findings {
		if f.Kind == "truncation" && !strings.Contains(f.Detail, "2 entries missing") {
			t.Errorf("truncation detail should report 2 entries missing, got: %q", f.Detail)
		}
	}
}

func TestCheckAnchorsDetectsHeadHashMismatch(t *testing.T) {
	res, _ := build3(t)
	// Right sequence, wrong hash → the head entry was substituted.
	anchors := AnchorSet{"org-1": {OrgID: "org-1", Sequence: 3, EntryHash: strings.Repeat("d", 64)}}
	CheckAnchors(res, anchors)
	if !hasKind(res, "head_hash_mismatch") {
		t.Fatalf("expected head_hash_mismatch, got: %v", findingKinds(res))
	}
}

func TestCheckAnchorsDetectsMissingOrg(t *testing.T) {
	res, _ := build3(t)
	anchors := AnchorSet{"org-absent": {OrgID: "org-absent", Sequence: 1, EntryHash: strings.Repeat("a", 64)}}
	CheckAnchors(res, anchors)
	if !hasKind(res, "anchor_org_missing") {
		t.Fatalf("expected anchor_org_missing, got: %v", findingKinds(res))
	}
}

func TestCheckAnchorsDetectsAnchorBehind(t *testing.T) {
	res, _ := build3(t)
	// Anchor is stale: it only knows about sequence 1, chain has 3.
	anchors := AnchorSet{"org-1": {OrgID: "org-1", Sequence: 1, EntryHash: strings.Repeat("a", 64)}}
	CheckAnchors(res, anchors)
	if !hasKind(res, "anchor_behind") {
		t.Fatalf("expected anchor_behind, got: %v", findingKinds(res))
	}
}

// A truncated chain on its own verifies clean (the bug this feature
// closes); only the anchor catches it.
func TestTruncatedChainVerifiesCleanWithoutAnchor(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntry(t, zeros, 1, sk, map[string]any{"k": "v1"})
	prev := mustEntryHash(t, e1)
	e2 := buildEntry(t, prev, 2, sk, map[string]any{"k": "v2"})
	// Drop e3 entirely (tail truncation).
	chain := bytes.Join([][]byte{e1, e2}, []byte{'\n'})
	res, err := Verify(bytes.NewReader(chain), memKeys{pk: pk})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("truncated chain unexpectedly produced findings without an anchor: %v", findingKinds(res))
	}
	// With an anchor at sequence 3, the truncation is caught.
	anchors := AnchorSet{"org-1": {OrgID: "org-1", Sequence: 3, EntryHash: strings.Repeat("c", 64)}}
	CheckAnchors(res, anchors)
	if !hasKind(res, "truncation") {
		t.Fatalf("anchor should catch the tail truncation, got: %v", findingKinds(res))
	}
}
