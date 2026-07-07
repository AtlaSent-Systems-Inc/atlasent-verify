// Package chain defines the AtlaSent audit-chain entry shape (v5)
// and a streaming verifier.
//
// Specified by ADR-020 and the canonical-form spec at
// atlasent-docs/architecture/specs/audit-chain-canonical-form.md.
package chain

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/atlasent-systems-inc/atlasent-verify/internal/canonical"
)

// GenesisPreviousHashHex is the documented genesis previous-hash.
const GenesisPreviousHashHex = "0000000000000000000000000000000000000000000000000000000000000000"

// MinChainVersion is the minimum chain_version this verifier supports.
const MinChainVersion = 5

// Entry is the v5 audit-chain entry shape.
//
// `Payload` is held as raw JSON so the canonicalizer sees the
// producer's bytes directly (we re-parse + re-canonicalize for the
// hash check).
type Entry struct {
	ChainVersion  int             `json:"chain_version"`
	OrgID         string          `json:"org_id"`
	Sequence      int64           `json:"sequence"`
	EventType     string          `json:"event_type"`
	ActorID       string          `json:"actor_id"`
	Decision      *string         `json:"decision,omitempty"`
	DecisionID    *string         `json:"decision_id,omitempty"`
	EngineVersion *string         `json:"engine_version,omitempty"`
	Payload       json.RawMessage `json:"payload"`
	PreviousHash  string          `json:"previous_hash"`
	EntryHash     string          `json:"entry_hash"`
	KeyVersion    string          `json:"key_version"`
	Signature     string          `json:"signature"` // base64-std
}

// KeyStore is the verifier-side public-key surface. The CLI's PEM
// loader implements this; tests use an in-memory map.
type KeyStore interface {
	PublicKey(keyVersion string) (ed25519.PublicKey, bool)
}

// Finding is a single verification failure. Multiple findings may
// be returned per chain; the verifier does not stop at the first.
type Finding struct {
	LineNumber int
	Sequence   int64
	OrgID      string
	Kind       string // e.g. "hash_mismatch", "signature_invalid", "ordering"
	Detail     string
}

// Result aggregates the verifier's findings + per-org head state.
//
// Findings are integrity failures (hash mismatches, chain breaks,
// signature errors against a known key) that cause exit code 1.
//
// Warnings are non-fatal observations, for example an entry whose
// key_version is not present in the supplied keystore: the hash chain
// was still verified, but the signature could not be checked because
// the key is not available. Warnings are printed to stderr and do not
// affect the exit code.
type Result struct {
	EntriesScanned int
	Findings       []Finding
	Warnings       []Finding         // non-fatal; signature skipped for unknown key_version
	HeadByOrg      map[string]int64  // org_id → last verified sequence
	HeadHashByOrg  map[string]string // org_id → last verified entry_hash (lowercase hex)
}

// Verify reads an NDJSON chain export from r and returns a Result.
// Verification is best-effort: it does not stop at the first
// finding, so callers can see the full picture.
func Verify(r io.Reader, keys KeyStore) (*Result, error) {
	res := &Result{HeadByOrg: map[string]int64{}, HeadHashByOrg: map[string]string{}}
	sc := bufio.NewScanner(r)
	// Allow large lines: payloads can be tens of KB.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	// Track per-org chain state: previous_hash (bytes) of the prior
	// entry we accepted, and the expected next sequence.
	type orgState struct {
		prevHashBytes []byte
		nextSeq       int64
	}
	state := map[string]*orgState{}

	line := 0
	for sc.Scan() {
		line++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}

		var e Entry
		if err := json.Unmarshal(raw, &e); err != nil {
			res.Findings = append(res.Findings, Finding{
				LineNumber: line, Kind: "parse_error", Detail: err.Error(),
			})
			continue
		}
		res.EntriesScanned++

		// Chain version
		if e.ChainVersion < MinChainVersion {
			res.Findings = append(res.Findings, Finding{
				LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
				Kind:   "chain_version_unsupported",
				Detail: fmt.Sprintf("chain_version %d < min %d", e.ChainVersion, MinChainVersion),
			})
			continue
		}

		st, ok := state[e.OrgID]
		if !ok {
			// First entry for this org. Expect genesis.
			st = &orgState{nextSeq: 1}
			state[e.OrgID] = st
			if e.Sequence != 1 {
				res.Findings = append(res.Findings, Finding{
					LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
					Kind: "ordering", Detail: "first entry for org must have sequence=1",
				})
			}
			if e.PreviousHash != GenesisPreviousHashHex {
				res.Findings = append(res.Findings, Finding{
					LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
					Kind:   "genesis_previous_hash",
					Detail: "first entry must reference the documented genesis previous_hash",
				})
			}
			st.prevHashBytes = make([]byte, 32) // 32 zero bytes
		} else {
			// Subsequent entry. Sequence must be contiguous.
			if e.Sequence != st.nextSeq {
				res.Findings = append(res.Findings, Finding{
					LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
					Kind:   "ordering",
					Detail: fmt.Sprintf("expected sequence %d, got %d", st.nextSeq, e.Sequence),
				})
				continue
			}
			// previous_hash must match prior entry's entry_hash.
			gotPrev, err := hex.DecodeString(e.PreviousHash)
			if err != nil || len(gotPrev) != 32 {
				res.Findings = append(res.Findings, Finding{
					LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
					Kind: "malformed_previous_hash", Detail: e.PreviousHash,
				})
				continue
			}
			if !bytes.Equal(gotPrev, st.prevHashBytes) {
				res.Findings = append(res.Findings, Finding{
					LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
					Kind:   "chain_break",
					Detail: "previous_hash does not match prior entry's entry_hash",
				})
				// Don't continue past the break — subsequent entries
				// would all chain off a broken parent. Mark the head
				// at the last good entry and stop processing this org.
				delete(state, e.OrgID)
				continue
			}
		}

		// Recompute entry_hash:
		//   canonical_payload = canonicalize(entry without entry_hash + signature)
		//   entry_hash = lowercase_hex(SHA-256(prev_hash_bytes || canonical_payload))
		canonBytes, err := canonicalizeForHash(raw)
		if err != nil {
			res.Findings = append(res.Findings, Finding{
				LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
				Kind: "canonical_form", Detail: err.Error(),
			})
			continue
		}
		h := sha256.New()
		h.Write(st.prevHashBytes)
		h.Write(canonBytes)
		gotHash := h.Sum(nil)
		gotHashHex := hex.EncodeToString(gotHash)

		if gotHashHex != e.EntryHash {
			res.Findings = append(res.Findings, Finding{
				LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
				Kind: "hash_mismatch",
				Detail: fmt.Sprintf("expected entry_hash %s, recomputed %s",
					e.EntryHash, gotHashHex),
			})
			continue
		}

		// Verify signature over the raw 32-byte entry_hash digest.
		// Unknown key_version is a warning (not a finding): the hash chain
		// was verified, but the signature cannot be checked without the key.
		// A future key rotation or a partial keyset is a normal operational
		// state and should not block chain verification.
		if keys != nil {
			pk, ok := keys.PublicKey(e.KeyVersion)
			if !ok {
				res.Warnings = append(res.Warnings, Finding{
					LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
					Kind:   "unknown_key_version",
					Detail: "key_version " + e.KeyVersion + " not in keystore; signature verification skipped for this entry",
				})
				// Hash was verified above; advance state without sig check.
			} else {
				// Signature field format: "ed25519:<base64url>" (v5) or
				// plain standard-base64 (legacy). decodeSignature handles both.
				sig, err := decodeSignature(e.Signature)
				if err != nil {
					res.Findings = append(res.Findings, Finding{
						LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
						Kind: "signature_decode", Detail: err.Error(),
					})
					continue
				}
				if !ed25519.Verify(pk, gotHash, sig) {
					res.Findings = append(res.Findings, Finding{
						LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
						Kind: "signature_invalid",
					})
					continue
				}
			}
		}

		// Entry valid — advance state.
		st.prevHashBytes = gotHash
		st.nextSeq = e.Sequence + 1
		res.HeadByOrg[e.OrgID] = e.Sequence
		res.HeadHashByOrg[e.OrgID] = gotHashHex
	}
	if err := sc.Err(); err != nil {
		return res, fmt.Errorf("chain: scan: %w", err)
	}
	return res, nil
}

// canonicalizeForHash strips the fields that are excluded from the
// chain hash, then canonicalizes the remainder.
//
// Per the canonical-form spec (v5):
//
//   - "entry_hash" and "signature" are always removed (they are the
//     hash and its proof, not inputs to it).
//   - "engine_version" is additive metadata — it was NOT included in
//     the hash when the runtime produced the entry.  Removing it here
//     keeps the verifier's recomputed hash consistent with the stored
//     entry_hash regardless of whether the field is present in the
//     exported JSON.
func canonicalizeForHash(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	delete(m, "entry_hash")
	delete(m, "signature")
	delete(m, "engine_version") // additive metadata — not in chain hash (audit chain v5)
	return canonical.Bytes(m)
}
