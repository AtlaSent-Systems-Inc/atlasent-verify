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

// TestLedgerMalformedRowFailsClosed: a row whose canonical_payload carries the
// wrong JSON TYPE (a number, not a string) is not the "content is wrong" case
// covered by LEDGER_HASH_MISMATCH above — the row can't even be decoded into
// the shape verifyLedger expects. This exercises CodeLedgerMalformed, which
// previously had zero test coverage anywhere in this repo (go test -cover
// showed 0% for this branch) despite being a real, wired FailureCode a
// producer bug or a tampered export can genuinely trigger. The bundle is
// still correctly re-signed over the malformed bytes, so the outer envelope
// signature legitimately passes — this must fail closed at the ledger layer
// specifically, not silently skip the bad row or panic.
func TestLedgerMalformedRowFailsClosed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	row := mkEval("d1", "allow", "ph1", "")
	row["canonical_payload"] = 12345 // wrong JSON type: number, not string

	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1", []map[string]any{row}, nil, nil)
	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.EnvelopeIntegrity != LayerValid {
		t.Fatalf("envelope must still verify (it was signed over the malformed row's real bytes): %s", res.EnvelopeIntegrity)
	}
	if res.LedgerIntegrity != LayerInvalid || !hasCode(res, CodeLedgerMalformed) {
		t.Fatalf("want LEDGER_MALFORMED; ledger=%s findings=%+v", res.LedgerIntegrity, res.Findings)
	}
	if res.LedgerEntriesVerified != 0 {
		t.Errorf("a malformed row must verify zero entries, got %d", res.LedgerEntriesVerified)
	}
}

// TestLedgerMalformedRowDoesNotCreditEarlierGoodRows: the malformed row is
// second in a two-row ledger. A partial-credit implementation might report
// the first (genuinely valid) row as verified before bailing on the second;
// verifyLedger's actual contract is to report zero on any malformed row, not
// "verified up to the point of failure" — pin that here so a future change
// can't silently start awarding partial credit for a ledger this tool cannot
// fully vouch for.
func TestLedgerMalformedRowDoesNotCreditEarlierGoodRows(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	row0 := mkEval("d1", "allow", "ph1", "")
	row1 := mkEval("d2", "allow", "ph2", row0["entry_hash"].(string))
	row1["id"] = 999 // wrong JSON type: number, not string

	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1", []map[string]any{row0, row1}, nil, nil)
	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.LedgerIntegrity != LayerInvalid || !hasCode(res, CodeLedgerMalformed) {
		t.Fatalf("want LEDGER_MALFORMED; ledger=%s findings=%+v", res.LedgerIntegrity, res.Findings)
	}
	if res.LedgerEntriesVerified != 0 {
		t.Errorf("a malformed row must not credit an earlier well-formed row, got %d verified", res.LedgerEntriesVerified)
	}
	// The finding must name the malformed row by its position, not the first
	// (unrelated, well-formed) row.
	for _, f := range res.Findings {
		if f.Code == CodeLedgerMalformed && f.Record != "evaluations[1]" {
			t.Errorf("want the finding to reference evaluations[1], got %q", f.Record)
		}
	}
}
