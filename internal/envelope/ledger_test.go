package envelope

import (
	"crypto/ed25519"
	"testing"
)

// TestLedgerChainBrokenPrevHashMismatch: two evaluations rows, each
// individually hash-self-consistent (entry_hash == sha256(canonical_payload)
// for its own row), but row[1]'s prev_hash does not link to row[0]'s
// entry_hash — the "wrong previous hash" attack applied to the envelope's
// ledger layer. Must be reported as LEDGER_CHAIN_BROKEN, distinct from a
// per-row LEDGER_HASH_MISMATCH.
func TestLedgerChainBrokenPrevHashMismatch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	row0 := mkEval("d1", "allow", "ph1", "")
	row1 := mkEval("d2", "allow", "ph2", "")
	// row1's prev_hash should be row0's entry_hash; corrupt it to something
	// else. row1 remains internally self-consistent (its own entry_hash
	// still matches sha256(canonical_payload)).
	row1["prev_hash"] = "not-the-real-prior-hash"

	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{row0, row1}, nil, nil)
	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.LedgerIntegrity != LayerInvalid || !hasCode(res, CodeLedgerChainBroken) {
		t.Fatalf("want LEDGER_CHAIN_BROKEN; ledger=%s findings=%+v", res.LedgerIntegrity, res.Findings)
	}
	if hasCode(res, CodeLedgerHashMismatch) {
		t.Error("a prev_hash-only break must not also report LEDGER_HASH_MISMATCH for the same row — the row's own hash is fine")
	}
}

// TestLedgerReorderedRowsBreaksContinuity: three validly-chained rows
// (rowA -> rowB -> rowC) written with the last two swapped (rowA, rowC,
// rowB). Continuity is a strict linear scan (row[i].prev_hash ==
// row[i-1].entry_hash), so reordering two NON-window-boundary rows (both
// carry a real, non-empty prev_hash — the window-boundary row, rowA, is
// deliberately left in place) must surface as a chain break: the ledger has
// no independent sequence field to recover the correct order from, unlike
// the NDJSON chain's `sequence`.
func TestLedgerReorderedRowsBreaksContinuity(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	rowA := mkEval("d1", "allow", "ph1", "") // window boundary: empty prev_hash
	rowB := mkEval("d2", "allow", "ph2", rowA["entry_hash"].(string))
	rowC := mkEval("d3", "allow", "ph3", rowB["entry_hash"].(string))

	// Reordered: A, C, B (the last two swapped).
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{rowA, rowC, rowB}, nil, nil)
	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.LedgerIntegrity != LayerInvalid || !hasCode(res, CodeLedgerChainBroken) {
		t.Fatalf("want LEDGER_CHAIN_BROKEN for reordered rows; ledger=%s findings=%+v", res.LedgerIntegrity, res.Findings)
	}
}

// TestLedgerEntryHashTamperedButPayloadUnchanged: canonical_payload is left
// EXACTLY as originally produced (a legitimate, unaltered payload string),
// but the row's entry_hash field is swapped for a different well-formed
// value, and the envelope is RE-SIGNED over the tampered bytes (simulating
// a producer bug or a party with signing access misattributing the hash —
// this is the ledger-layer analogue of the chain-level "modified hash,
// unchanged signature" attack, since the outer signature here plays the
// role the per-row Ed25519 signature plays in the NDJSON chain). Envelope
// integrity passes (it WAS re-signed); ledger integrity must still catch
// the per-row hash mismatch.
func TestLedgerEntryHashTamperedButPayloadUnchanged(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	row := mkEval("d1", "allow", "ph1", "")
	row["entry_hash"] = row["entry_hash"].(string)[:63] + "0" // flip the last hex digit

	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1", []map[string]any{row}, nil, nil)
	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.EnvelopeIntegrity != LayerValid {
		t.Fatalf("envelope must verify (it was re-signed over the tampered bytes): %s", res.EnvelopeIntegrity)
	}
	if res.LedgerIntegrity != LayerInvalid || !hasCode(res, CodeLedgerHashMismatch) {
		t.Fatalf("want LEDGER_HASH_MISMATCH; ledger=%s findings=%+v", res.LedgerIntegrity, res.Findings)
	}
}
