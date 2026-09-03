// Package reconcile implements ADR CROSS-043 ("Cross-runtime reconciliation")
// — the fifth, OFFLINE, PAIRWISE verification layer atlasent-verify runs
// across TWO already-independently-verified signed export envelopes
// (internal/envelope's envelope/ledger/correlation/archive layers), following
// exactly the pattern internal/envelope/correlation.go and
// internal/envelope/archive.go set for adding a layer without reinventing the
// posture: reuse the "absent is a SUCCESS" convention, reuse the
// findings-with-a-record-ref shape, reuse the certification-version-style
// fail-closed-on-the-unrecognized-shape instinct.
//
// WHAT THIS PACKAGE DOES NOT DO
// ------------------------------
// It never mutates, invalidates, or overrides either input envelope's own
// envelope_integrity / ledger_integrity / correlation_integrity /
// archive_integrity verdict. Reconciliation is evidence only (ADR
// CROSS-043 §5, mirroring CROSS-038's evidence-not-authority framing): a
// SEPARATE, ADDITIVE verdict line, never wired into any live decision. Callers
// MUST run internal/envelope.Verify on each side first and are expected to
// have done so — this package only compares the two ALREADY-PARSED envelope
// structures; it does not re-verify signatures, hash chains, or semantic
// correlation/archive validity itself.
//
// SCOPE (V1, per the ADR — do not silently expand)
// -------------------------------------------------
//   - Strictly pairwise. No N-way topology.
//   - No live network path, no discovery mechanism: both envelopes are
//     already-read local files (or bytes), supplied by the caller.
//   - Exactly two named findings: CROSS_RUNTIME_DUPLICATE_CONSUMPTION and
//     CROSS_RUNTIME_POST_REVOCATION_VALIDITY, over verification_events[]
//     (an existing record type — this package adds no new one).
//   - No automatic remediation of anything found: a finding is reported, never
//     acted on (no revocation push, no permit invalidation, nothing).
package reconcile

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/AtlaSent-Systems-Inc/atlasent-verify/internal/envelope"
)

// FailureCode enumerates reconciliation's machine-readable finding codes —
// registered in ADR CROSS-043 §4, mirroring how CORRELATION_*/ARCHIVE_* codes
// are registered in internal/envelope/model.go.
type FailureCode string

const (
	// CodeScopeMismatch fires when the two exports do not declare the SAME
	// org_id AND the same reconciliation_scope.deployment_id — including
	// when either side lacks reconciliation_scope entirely. Refused BEFORE
	// any record-level comparison is attempted; never a silent skip, never a
	// false pass.
	CodeScopeMismatch FailureCode = "RECONCILIATION_SCOPE_MISMATCH"

	// CodeDuplicateConsumption fires when the SAME permit_token_hash is
	// recorded outcome=verified (successfully consumed) in BOTH exports. Each
	// instance individually enforces single-use correctly (that is checked
	// independently, per-export, elsewhere); this asks whether the SAME
	// permit was independently and successfully consumed at two different
	// enforcement points — the distributed-enforcement failure P3's claim is
	// about.
	CodeDuplicateConsumption FailureCode = "CROSS_RUNTIME_DUPLICATE_CONSUMPTION"

	// CodePostRevocationValidity fires when a permit is recorded
	// outcome=verified (valid) in one export at a timestamp AFTER the OTHER
	// export's REAL revocation moment (verification_events.revoked_at, NOT
	// verified_at) for the SAME permit_token_hash. Revocation-propagation lag
	// made visible, not resolved — V1 detects and reports; it never revokes,
	// retracts, or pushes state between instances.
	CodePostRevocationValidity FailureCode = "CROSS_RUNTIME_POST_REVOCATION_VALIDITY"

	// CodeRevocationTimestampUnavailable fires when the outcome=revoked row
	// for a permit_token_hash under comparison carries no USABLE revoked_at
	// (the revoking export predates ADR CROSS-043 §2's revoked_at field, or
	// the value is malformed). Refused for that specific pair — never
	// silently skipped, and never approximated from verified_at (a
	// verification ATTEMPT time, not the real revocation moment: a rejected
	// re-presentation can happen long after the actual revocation, or never
	// at all).
	CodeRevocationTimestampUnavailable FailureCode = "RECONCILIATION_REVOCATION_TIMESTAMP_UNAVAILABLE"
)

// outcomeValid / outcomeRevoked are the two verification_events.outcome
// values reconciliation cares about. The CHECK constraint on
// verification_events.outcome (atlasent-api migration
// 20260703000000_verification_events.sql) is
// verified/mismatch/expired/revoked/replay_blocked/invalid — there is no
// "valid" value. "verified" is the existing convention this repo already
// uses for "the permit was successfully validated" — see
// internal/envelope/correlation.go's verificationOutcomeAdmitsExecution,
// which treats "verified" as the one outcome that positively evidences a
// permit was honored. (An earlier draft of ADR CROSS-043 used "valid" here;
// corrected before this package was implemented against it — see the ADR's
// §1 note.)
const (
	outcomeValid   = "verified"
	outcomeRevoked = "revoked"
)

// Verdict is the reconciliation_integrity verdict — a FIFTH line alongside
// (never replacing) envelope_integrity / ledger_integrity /
// correlation_integrity / archive_integrity, per ADR CROSS-043 §4.
type Verdict string

const (
	// VerdictVerified: both exports verify independently, scopes match, at
	// least one permit_token_hash overlaps, and every overlap is coherent
	// (no duplicate consumption, no post-revocation validity).
	VerdictVerified Verdict = "verified"
	// VerdictInvalid: scopes match, but at least one finding was raised over
	// an overlapping permit_token_hash.
	VerdictInvalid Verdict = "invalid"
	// VerdictAbsent: scopes match and both exports verify independently, but
	// there is NO overlapping permit_token_hash at all — the expected
	// steady state for two correctly-operating, disjoint instances. A
	// SUCCESS, not an error — exactly the posture internal/envelope's
	// correlation/archive layers already use for their own "absent" states.
	VerdictAbsent Verdict = "absent"
	// VerdictRefused: the scope-match gate itself failed (missing
	// reconciliation_scope on either side, or a declared org_id/deployment_id
	// disagreement) — refused before any record-level comparison was
	// attempted.
	VerdictRefused Verdict = "refused"
)

// MarshalJSON emits the stable wire vocabulary the ADR names: "verified" /
// "invalid" / "absent" / "refused". Deliberately its own type (not
// envelope.Layer) — envelope.Layer's four states (valid/invalid/absent/
// untrusted-key) don't have a "refused before comparison" state, and folding
// this into that enum would blur two different questions: "did this layer's
// own crypto/semantics check out" (envelope.Layer) vs. "was a
// cross-export comparison even attempted" (reconcile.Verdict).
func (v Verdict) MarshalJSON() ([]byte, error) {
	switch v {
	case VerdictVerified:
		return []byte(`"verified"`), nil
	case VerdictInvalid:
		return []byte(`"invalid"`), nil
	case VerdictAbsent:
		return []byte(`"absent"`), nil
	case VerdictRefused:
		return []byte(`"refused"`), nil
	default:
		return []byte(`"unknown"`), nil
	}
}

// Finding is one machine-readable reconciliation failure — same shape as
// envelope.Finding (Code / Detail / Record), kept as reconcile's own type so
// this package has no import-time coupling to envelope beyond the Envelope
// struct it reads.
type Finding struct {
	Code   FailureCode `json:"code"`
	Detail string      `json:"detail"`
	// Record locates the offending permit_token_hash (shortened) when
	// applicable. Empty for the scope-mismatch refusal, which precedes any
	// per-record comparison.
	Record string `json:"record,omitempty"`
}

// Result is the reconciliation_integrity verdict plus its machine-readable
// projection fields — the natural sibling of envelope.VerificationResult for
// the fifth layer.
type Result struct {
	// ReconciliationIntegrity is the top-line verdict (see Verdict).
	ReconciliationIntegrity Verdict `json:"reconciliation_integrity"`

	// OrgID / DeploymentID echo the matched scope once the scope-match gate
	// passes. Both empty when ReconciliationIntegrity is VerdictRefused.
	OrgID        string `json:"org_id,omitempty"`
	DeploymentID string `json:"deployment_id,omitempty"`

	// OverlappingPermitTokenHashes counts the DISTINCT permit_token_hash
	// values present in BOTH exports' verification_events[] — the population
	// this run actually compared. Zero with ReconciliationIntegrity=absent is
	// the expected steady state, not a degraded result.
	OverlappingPermitTokenHashes int `json:"overlapping_permit_token_hashes"`

	// Findings is every reconciliation failure, most-relevant first (the
	// scope-mismatch refusal, when present, is always alone — no per-record
	// comparison is attempted once refused).
	Findings []Finding `json:"findings"`
}

// AddFinding appends a finding.
func (r *Result) AddFinding(code FailureCode, record, detail string) {
	r.Findings = append(r.Findings, Finding{Code: code, Detail: detail, Record: record})
}

// OK reports a clean reconciliation pass: verified or absent, never invalid
// or refused. Mirrors envelope.VerificationResult.OK()'s "no findings, no
// invalid layer" shape, adjusted for reconcile's extra "refused" state.
func (r *Result) OK() bool {
	return r.ReconciliationIntegrity == VerdictVerified || r.ReconciliationIntegrity == VerdictAbsent
}

// Reconcile compares two ALREADY-PARSED, ALREADY-INDEPENDENTLY-VERIFIED export
// envelopes per ADR CROSS-043. Callers MUST have run envelope.Verify on each
// side first; this function does not re-verify either envelope's signature,
// ledger, correlation, or archive layers, and its result never alters theirs.
//
// Step 1 — the scope-match gate: refuse (VerdictRefused,
// CodeScopeMismatch) unless both envelopes declare the SAME org_id AND the
// same reconciliation_scope.deployment_id. Either envelope lacking
// reconciliation_scope entirely is ALSO a refusal — never a silent skip, and
// never treated as "compare anyway".
//
// Step 2 — over the matched scope, index each export's verification_events[]
// by permit_token_hash and find the overlap. No overlap is VerdictAbsent (a
// SUCCESS): the expected steady state for two correctly-operating, disjoint
// instances. An overlap with no finding is VerdictVerified. An overlap with
// at least one finding is VerdictInvalid.
func Reconcile(a, b *envelope.Envelope) *Result {
	res := &Result{ReconciliationIntegrity: VerdictAbsent}

	// ── (1) scope-match gate ──────────────────────────────────────────────
	switch {
	case a.ReconciliationScope == nil && b.ReconciliationScope == nil:
		res.ReconciliationIntegrity = VerdictRefused
		res.AddFinding(CodeScopeMismatch, "",
			"neither export declares reconciliation_scope; cross-runtime reconciliation was not opted into by either side")
		return res
	case a.ReconciliationScope == nil:
		res.ReconciliationIntegrity = VerdictRefused
		res.AddFinding(CodeScopeMismatch, "",
			"export A (--chain) carries no reconciliation_scope; cross-runtime reconciliation was not opted into for that export")
		return res
	case b.ReconciliationScope == nil:
		res.ReconciliationIntegrity = VerdictRefused
		res.AddFinding(CodeScopeMismatch, "",
			"export B (--reconcile-with) carries no reconciliation_scope; cross-runtime reconciliation was not opted into for that export")
		return res
	}
	if strings.TrimSpace(a.OrgID) == "" || strings.TrimSpace(b.OrgID) == "" ||
		a.OrgID != b.OrgID ||
		strings.TrimSpace(a.ReconciliationScope.DeploymentID) == "" ||
		strings.TrimSpace(b.ReconciliationScope.DeploymentID) == "" ||
		a.ReconciliationScope.DeploymentID != b.ReconciliationScope.DeploymentID {
		res.ReconciliationIntegrity = VerdictRefused
		res.AddFinding(CodeScopeMismatch, "",
			fmt.Sprintf("export A declares org_id=%q deployment_id=%q; export B declares org_id=%q deployment_id=%q — refusing to compare exports not declared as the same customer's same logical deployment",
				a.OrgID, a.ReconciliationScope.DeploymentID, b.OrgID, b.ReconciliationScope.DeploymentID))
		return res
	}
	res.OrgID = a.OrgID
	res.DeploymentID = a.ReconciliationScope.DeploymentID

	// ── (2) index verification_events[] by permit_token_hash, per side ────
	aRows := indexByPermit(a.Verifications)
	bRows := indexByPermit(b.Verifications)

	overlap := overlappingHashes(aRows, bRows)
	res.OverlappingPermitTokenHashes = len(overlap)
	if len(overlap) == 0 {
		// SUCCESS, not an error: genuinely disjoint action streams is the
		// normal case for two correctly-operating instances, exactly the
		// posture internal/envelope's correlation/archive layers use for
		// their own zero-record "absent" states.
		res.ReconciliationIntegrity = VerdictAbsent
		return res
	}

	for _, h := range overlap {
		checkDuplicateConsumption(h, aRows[h], bRows[h], res)
		checkPostRevocationValidity(h, aRows[h], bRows[h], res)
	}

	if len(res.Findings) > 0 {
		res.ReconciliationIntegrity = VerdictInvalid
	} else {
		res.ReconciliationIntegrity = VerdictVerified
	}
	return res
}

// indexByPermit groups verification_events rows by permit_token_hash. A
// single export can legitimately carry more than one verification attempt for
// the same permit (e.g. a replay attempt recorded as a separate row), so the
// value is a slice, not a single row.
func indexByPermit(rows []envelope.VerificationRow) map[string][]envelope.VerificationRow {
	out := map[string][]envelope.VerificationRow{}
	for _, r := range rows {
		h := strings.TrimSpace(r.PermitTokenHash)
		if h == "" {
			continue
		}
		out[h] = append(out[h], r)
	}
	return out
}

// overlappingHashes returns the permit_token_hash values present in BOTH
// maps, sorted for deterministic finding order (map iteration is not
// stable).
func overlappingHashes(a, b map[string][]envelope.VerificationRow) []string {
	var out []string
	for h := range a {
		if _, ok := b[h]; ok {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

// checkDuplicateConsumption reports CodeDuplicateConsumption when the same
// permit_token_hash was independently recorded outcome=verified in BOTH
// exports — the same permit successfully consumed at two enforcement points.
// One finding per hash (not per row-pair): the identity of the permit is what
// matters here, not how many verification attempts either side logged.
func checkDuplicateConsumption(hash string, aRows, bRows []envelope.VerificationRow, res *Result) {
	aValid, aOK := firstWithOutcome(aRows, outcomeValid)
	bValid, bOK := firstWithOutcome(bRows, outcomeValid)
	if !aOK || !bOK {
		return
	}
	res.AddFinding(CodeDuplicateConsumption, permitRef(hash),
		fmt.Sprintf("permit_token_hash=%s is recorded outcome=%s (successfully consumed) in BOTH exports — export A record id=%q at %s, export B record id=%q at %s; the same permit was independently and successfully consumed at two enforcement points",
			shortHash(hash), outcomeValid, aValid.ID, orUnknown(aValid.VerifiedAt), bValid.ID, orUnknown(bValid.VerifiedAt)))
}

// checkPostRevocationValidity reports CodePostRevocationValidity when the
// same permit_token_hash is outcome=verified in one export at a timestamp
// AFTER the OTHER export's real revocation moment (revoked_at, NOT
// verified_at — see ADR CROSS-043 §2's own correction: verified_at on a
// revoked row is a rejected-presentation ATTEMPT time, which may postdate the
// real revocation by an arbitrary amount, or never occur at all) for that
// same hash. Checked in both directions (A revoked before B's valid; B
// revoked before A's valid) since neither instance is privileged.
//
// When a side DOES record the permit as revoked but that row carries no
// usable revoked_at (an export produced before ADR CROSS-043 §2's field
// existed, or a malformed value), this refuses the comparison for that pair
// (CodeRevocationTimestampUnavailable) rather than silently skipping it or
// falling back to verified_at as an approximation — an approximation here is
// exactly the defect ADR CROSS-043 §1 documents review catching.
func checkPostRevocationValidity(hash string, aRows, bRows []envelope.VerificationRow, res *Result) {
	checkDirection(hash, "A", "B", aRows, bRows, res)
	checkDirection(hash, "B", "A", bRows, aRows, res)
}

// checkDirection checks whether `laterSideRows` (labelled laterLabel) records
// outcome=verified at a timestamp after `earlierSideRows` (labelled
// earlierLabel)'s real revocation moment for this permit_token_hash. One
// finding per direction per hash: the earliest usable revoked_at and the
// earliest post-revocation validity are the two facts that matter for the
// report, not every subsequent occurrence.
func checkDirection(hash, earlierLabel, laterLabel string, earlierSideRows, laterSideRows []envelope.VerificationRow, res *Result) {
	revoked := revokedRowsFor(earlierSideRows)
	if len(revoked) == 0 {
		return // this side never recorded the permit as revoked — nothing to compare
	}
	revokedRow, revokedAt, hasUsableRevokedAt := earliestRevokedAt(revoked)
	if !hasUsableRevokedAt {
		res.AddFinding(CodeRevocationTimestampUnavailable, permitRef(hash),
			fmt.Sprintf("permit_token_hash=%s is outcome=%s in export %s (record id=%q) but carries no usable revoked_at — the export predates ADR CROSS-043 §2's revoked_at field, or the value is malformed; refusing to compare post-revocation validity for this permit rather than approximating from verified_at (a verification ATTEMPT time, not the real revocation moment)",
				shortHash(hash), outcomeRevoked, earlierLabel, revoked[0].ID))
		return
	}
	validRow, validAt, hasLaterValid := earliestValidAfter(laterSideRows, revokedAt)
	if !hasLaterValid {
		return
	}
	res.AddFinding(CodePostRevocationValidity, permitRef(hash),
		fmt.Sprintf("permit_token_hash=%s was revoked in export %s at %s (revoked_at, record id=%q), but export %s recorded outcome=%s (valid) for the same permit at %s (record id=%q) — AFTER the real revocation",
			shortHash(hash), earlierLabel, revokedAt.Format(time.RFC3339), revokedRow.ID,
			laterLabel, outcomeValid, validAt.Format(time.RFC3339), validRow.ID))
}

// firstWithOutcome returns the first row (in slice order) whose outcome
// case-insensitively matches, and whether one was found.
func firstWithOutcome(rows []envelope.VerificationRow, outcome string) (envelope.VerificationRow, bool) {
	for _, r := range rows {
		if strings.EqualFold(strings.TrimSpace(r.Outcome), outcome) {
			return r, true
		}
	}
	return envelope.VerificationRow{}, false
}

// revokedRowsFor returns every row on this side recording the permit as
// outcome=revoked, regardless of whether revoked_at is populated (that check
// is earliestRevokedAt's job — this function answers "was it revoked here at
// all", not "do we know when").
func revokedRowsFor(rows []envelope.VerificationRow) []envelope.VerificationRow {
	var out []envelope.VerificationRow
	for _, r := range rows {
		if strings.EqualFold(strings.TrimSpace(r.Outcome), outcomeRevoked) {
			out = append(out, r)
		}
	}
	return out
}

// earliestRevokedAt returns the revoked row carrying the EARLIEST parseable
// revoked_at (ADR CROSS-043 §2 — the real permit_revocations.revoked_at
// moment, NOT verified_at), and that timestamp. False when NONE of the
// supplied (already outcome=revoked-filtered) rows carry a usable revoked_at
// — the caller reports CodeRevocationTimestampUnavailable in that case rather
// than falling back to verified_at.
func earliestRevokedAt(revoked []envelope.VerificationRow) (envelope.VerificationRow, time.Time, bool) {
	var best envelope.VerificationRow
	var bestAt time.Time
	found := false
	for _, r := range revoked {
		t, ok := parseTimestamp(r.RevokedAt)
		if !ok {
			continue
		}
		if !found || t.Before(bestAt) {
			best, bestAt, found = r, t, true
		}
	}
	return best, bestAt, found
}

// earliestValidAfter returns the outcome=verified row with the EARLIEST
// parseable verified_at strictly after `after`, and that timestamp.
func earliestValidAfter(rows []envelope.VerificationRow, after time.Time) (envelope.VerificationRow, time.Time, bool) {
	var best envelope.VerificationRow
	var bestAt time.Time
	found := false
	for _, r := range rows {
		if !strings.EqualFold(strings.TrimSpace(r.Outcome), outcomeValid) {
			continue
		}
		t, ok := parseTimestamp(r.VerifiedAt)
		if !ok || !t.After(after) {
			continue
		}
		if !found || t.Before(bestAt) {
			best, bestAt, found = r, t, true
		}
	}
	return best, bestAt, found
}

// parseTimestamp accepts RFC3339 with or without fractional seconds — the two
// shapes a Postgres timestamptz export column (verified_at) renders as.
func parseTimestamp(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	return time.Time{}, false
}

func permitRef(hash string) string {
	return "permit:" + shortHash(hash)
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "…"
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(no verified_at recorded)"
	}
	return s
}
