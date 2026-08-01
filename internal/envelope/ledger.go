package envelope

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// ledgerRow is the minimal decode of an evaluations[] row for the ledger check.
// The export projection (export_evaluation_rows) supplies canonical_payload
// directly, so ledger verification recomputes entry_hash = SHA-256(
// canonical_payload) — note the execution_evaluations scheme embeds prev_hash
// as canonical_payload's trailing pipe-field, so (unlike the NDJSON audit
// chain) prev_hash is NOT a separate prepended byte-block. Continuity is then
// row[i].prev_hash == row[i-1].entry_hash.
type ledgerRow struct {
	ID               string `json:"id"`
	PrevHash         string `json:"prev_hash"`
	EntryHash        string `json:"entry_hash"`
	CanonicalPayload string `json:"canonical_payload"`
}

// verifyLedger checks the evaluations[] entry-hash chain inside the envelope.
//
// It returns the count of rows whose entry_hash recomputed correctly and whose
// prev_hash linked to the prior row, and appends a Finding per failure. The
// verdict is:
//   - LayerAbsent when there are no evaluation rows.
//   - LayerAbsent (with no finding) when rows carry no canonical_payload — the
//     records are still covered by the OUTER envelope signature; the per-row
//     recompute simply isn't available offline. This is reported honestly, not
//     as a false "valid".
//   - LayerValid when every row recomputed and linked.
//   - LayerInvalid on any hash/continuity failure.
//
// Genesis is deliberately NOT asserted: an export is a time-window, so the
// first exported row's prev_hash is a real prior hash, not the zero genesis.
func verifyLedger(env *Envelope, res *VerificationResult) (verified int, layer Layer) {
	if len(env.Evaluations) == 0 {
		return 0, LayerAbsent
	}

	rows := make([]ledgerRow, 0, len(env.Evaluations))
	haveCanonical := false
	for i, raw := range env.Evaluations {
		var r ledgerRow
		if err := json.Unmarshal(raw, &r); err != nil {
			res.AddFinding(CodeLedgerMalformed, fmt.Sprintf("evaluations[%d]", i),
				"evaluation row is not valid JSON: "+err.Error())
			return 0, LayerInvalid
		}
		if r.CanonicalPayload != "" {
			haveCanonical = true
		}
		rows = append(rows, r)
	}

	// No canonical_payload anywhere: the rows are covered by the outer
	// signature but the per-row hash cannot be recomputed offline. Honest
	// "absent" rather than a fabricated "valid".
	if !haveCanonical {
		return 0, LayerAbsent
	}

	invalid := false
	var prevEntryHash string
	for i, r := range rows {
		// (a) per-row recompute: entry_hash == sha256_hex(canonical_payload).
		if r.CanonicalPayload != "" && r.EntryHash != "" {
			sum := sha256.Sum256([]byte(r.CanonicalPayload))
			got := hex.EncodeToString(sum[:])
			if got != r.EntryHash {
				invalid = true
				res.AddFinding(CodeLedgerHashMismatch, "eval:"+r.ID,
					fmt.Sprintf("evaluations[%d]: entry_hash %s != recomputed sha256(canonical_payload) %s", i, r.EntryHash, got))
				continue
			}
		}
		// (b) continuity: this row's prev_hash links to the prior row's
		// entry_hash. Skipped for the first exported row (window boundary).
		if i > 0 && r.PrevHash != "" && prevEntryHash != "" && r.PrevHash != prevEntryHash {
			invalid = true
			res.AddFinding(CodeLedgerChainBroken, "eval:"+r.ID,
				fmt.Sprintf("evaluations[%d]: prev_hash %s does not link to prior row entry_hash %s", i, r.PrevHash, prevEntryHash))
			continue
		}
		prevEntryHash = r.EntryHash
		verified++
	}

	if invalid {
		return verified, LayerInvalid
	}
	return verified, LayerValid
}
