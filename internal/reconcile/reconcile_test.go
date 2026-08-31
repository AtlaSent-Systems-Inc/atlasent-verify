package reconcile

import (
	"testing"

	"github.com/AtlaSent-Systems-Inc/atlasent-verify/internal/envelope"
)

// These tests build *envelope.Envelope literals directly — Reconcile operates
// on already-parsed, already-verified structures (see the package doc), so
// unlike internal/envelope's own tests, no signing or JSON round-trip is
// needed to exercise the comparison logic itself. CLI-level black-box tests
// (cmd/atlasent-audit-verify/reconcile_cli_test.go) cover the real signed
// envelope + --reconcile-with flag path end-to-end.

func scoped(orgID, deploymentID string) envelope.Envelope {
	return envelope.Envelope{
		OrgID:               orgID,
		ReconciliationScope: &envelope.ReconciliationScope{DeploymentID: deploymentID},
	}
}

func TestReconcile_ScopeMismatch_BothMissing(t *testing.T) {
	a := envelope.Envelope{OrgID: "org-1"}
	b := envelope.Envelope{OrgID: "org-1"}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictRefused {
		t.Fatalf("verdict = %s, want refused", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != CodeScopeMismatch {
		t.Fatalf("findings = %+v, want exactly one RECONCILIATION_SCOPE_MISMATCH", res.Findings)
	}
}

func TestReconcile_ScopeMismatch_OneMissing(t *testing.T) {
	a := scoped("org-1", "dep-1")
	b := envelope.Envelope{OrgID: "org-1"} // no reconciliation_scope at all
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictRefused {
		t.Fatalf("verdict = %s, want refused", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != CodeScopeMismatch {
		t.Fatalf("findings = %+v, want exactly one RECONCILIATION_SCOPE_MISMATCH", res.Findings)
	}
}

func TestReconcile_ScopeMismatch_DifferentDeploymentID(t *testing.T) {
	a := scoped("org-1", "dep-1")
	b := scoped("org-1", "dep-2")
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictRefused {
		t.Fatalf("verdict = %s, want refused", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != CodeScopeMismatch {
		t.Fatalf("findings = %+v, want exactly one RECONCILIATION_SCOPE_MISMATCH", res.Findings)
	}
}

func TestReconcile_ScopeMismatch_DifferentOrgID(t *testing.T) {
	a := scoped("org-1", "dep-1")
	b := scoped("org-2", "dep-1")
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictRefused {
		t.Fatalf("verdict = %s, want refused", res.ReconciliationIntegrity)
	}
}

func TestReconcile_ScopeMismatch_NeverSilentlySkipped(t *testing.T) {
	// Even with fully overlapping, duplicate-consumed permits, a scope
	// mismatch must refuse BEFORE any record-level comparison — never a
	// silent skip, never treated as "compare anyway".
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
	}
	b := scoped("org-1", "dep-2")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictRefused {
		t.Fatalf("verdict = %s, want refused (scope gate must run before any record comparison)", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %+v, want exactly the one scope-mismatch finding, no duplicate-consumption finding underneath it", res.Findings)
	}
}

func TestReconcile_Absent_NoOverlap(t *testing.T) {
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va", PermitTokenHash: "ph-a-only", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb", PermitTokenHash: "ph-b-only", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictAbsent {
		t.Fatalf("verdict = %s, want absent", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("findings = %+v, want none", res.Findings)
	}
	if !res.OK() {
		t.Fatalf("absent must be OK() (a success), not a failure")
	}
	if res.OverlappingPermitTokenHashes != 0 {
		t.Fatalf("overlap = %d, want 0", res.OverlappingPermitTokenHashes)
	}
	if res.OrgID != "org-1" || res.DeploymentID != "dep-1" {
		t.Fatalf("scope not echoed: org=%q dep=%q", res.OrgID, res.DeploymentID)
	}
}

func TestReconcile_Absent_NoVerificationRecordsAtAll(t *testing.T) {
	a := scoped("org-1", "dep-1")
	b := scoped("org-1", "dep-1")
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictAbsent {
		t.Fatalf("verdict = %s, want absent", res.ReconciliationIntegrity)
	}
}

func TestReconcile_Verified_OverlapNoDivergence(t *testing.T) {
	// Overlapping permit, but only ONE side ever validated it (e.g. it was
	// presented to B and rejected as expired) — no duplicate consumption, no
	// revocation-after-valid ordering problem. This must be VERIFIED
	// (something was compared and came out clean), distinct from ABSENT
	// (nothing to compare).
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va", PermitTokenHash: "ph-shared", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb", PermitTokenHash: "ph-shared", Outcome: "expired", VerifiedAt: "2026-08-02T00:00:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictVerified {
		t.Fatalf("verdict = %s, want verified", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("findings = %+v, want none", res.Findings)
	}
	if res.OverlappingPermitTokenHashes != 1 {
		t.Fatalf("overlap = %d, want 1", res.OverlappingPermitTokenHashes)
	}
	if !res.OK() {
		t.Fatalf("verified must be OK()")
	}
}

func TestReconcile_DuplicateConsumption(t *testing.T) {
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va", PermitTokenHash: "ph-dup", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb", PermitTokenHash: "ph-dup", Outcome: "verified", VerifiedAt: "2026-08-01T00:05:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictInvalid {
		t.Fatalf("verdict = %s, want invalid", res.ReconciliationIntegrity)
	}
	if res.OK() {
		t.Fatalf("invalid must not be OK()")
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != CodeDuplicateConsumption {
		t.Fatalf("findings = %+v, want exactly one CROSS_RUNTIME_DUPLICATE_CONSUMPTION", res.Findings)
	}
	if res.Findings[0].Record == "" {
		t.Fatalf("finding carries no record ref (permit hash)")
	}
}

func TestReconcile_DuplicateConsumption_OnlyOneSideValid_NoFinding(t *testing.T) {
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb", PermitTokenHash: "ph-1", Outcome: "replay_blocked", VerifiedAt: "2026-08-01T00:05:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictVerified {
		t.Fatalf("verdict = %s, want verified (only one side actually consumed it)", res.ReconciliationIntegrity)
	}
}

func TestReconcile_PostRevocationValidity_ARevokedThenBValid(t *testing.T) {
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va-revoke", PermitTokenHash: "ph-1", Outcome: "revoked", RevokedAt: "2026-08-01T00:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb-valid", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T01:00:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictInvalid {
		t.Fatalf("verdict = %s, want invalid", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != CodePostRevocationValidity {
		t.Fatalf("findings = %+v, want exactly one CROSS_RUNTIME_POST_REVOCATION_VALIDITY", res.Findings)
	}
}

func TestReconcile_PostRevocationValidity_ReverseDirection(t *testing.T) {
	// Same shape, but B is the one that revoked first and A is valid after —
	// must be caught symmetrically; neither side is privileged.
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va-valid", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T02:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb-revoke", PermitTokenHash: "ph-1", Outcome: "revoked", RevokedAt: "2026-08-01T01:00:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictInvalid {
		t.Fatalf("verdict = %s, want invalid", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != CodePostRevocationValidity {
		t.Fatalf("findings = %+v, want exactly one CROSS_RUNTIME_POST_REVOCATION_VALIDITY", res.Findings)
	}
}

func TestReconcile_PostRevocationValidity_UsesRevokedAt_NotVerifiedAt(t *testing.T) {
	// The regression ADR CROSS-043's own review caught: the revoked row's
	// verified_at is a rejected-presentation ATTEMPT time, which can postdate
	// (or never relate to) the real revocation moment. Here the revoked row's
	// verified_at (a LATE re-presentation attempt) is AFTER B's valid
	// timestamp — if the code wrongly compared against verified_at, B's valid
	// record would NOT look "after revocation" and no finding would fire.
	// Comparing against the real revoked_at (deliberately much EARLIER than
	// verified_at) must still catch it.
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va-revoke", PermitTokenHash: "ph-1", Outcome: "revoked",
			RevokedAt: "2026-08-01T00:00:00Z", VerifiedAt: "2026-08-01T23:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb-valid", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T12:00:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictInvalid {
		t.Fatalf("verdict = %s, want invalid (must compare against revoked_at=00:00, not verified_at=23:00)", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != CodePostRevocationValidity {
		t.Fatalf("findings = %+v, want exactly one CROSS_RUNTIME_POST_REVOCATION_VALIDITY", res.Findings)
	}
}

func TestReconcile_RevocationTimestampUnavailable(t *testing.T) {
	// A revoked row with NO revoked_at (a pre-CROSS-043-§2 export). Must
	// refuse the comparison for this pair with the dedicated code — never
	// silently skip, and never approximate from verified_at even though
	// verified_at IS present here.
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va-revoke", PermitTokenHash: "ph-1", Outcome: "revoked", VerifiedAt: "2026-08-01T00:00:00Z"}, // no RevokedAt
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb-valid", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T01:00:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictInvalid {
		t.Fatalf("verdict = %s, want invalid", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != CodeRevocationTimestampUnavailable {
		t.Fatalf("findings = %+v, want exactly one RECONCILIATION_REVOCATION_TIMESTAMP_UNAVAILABLE (never approximated from verified_at)", res.Findings)
	}
}

func TestReconcile_RevocationTimestampUnavailable_MalformedRevokedAt(t *testing.T) {
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va-revoke", PermitTokenHash: "ph-1", Outcome: "revoked", RevokedAt: "not-a-timestamp"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb-valid", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T01:00:00Z"},
	}
	res := Reconcile(&a, &b)
	if len(res.Findings) != 1 || res.Findings[0].Code != CodeRevocationTimestampUnavailable {
		t.Fatalf("findings = %+v, want exactly one RECONCILIATION_REVOCATION_TIMESTAMP_UNAVAILABLE", res.Findings)
	}
}

func TestReconcile_RevocationBeforeValidity_NotAFinding(t *testing.T) {
	// The honest, non-lagging case: revoked strictly AFTER the other side's
	// validity — a normal "instance A revoked what instance B legitimately
	// validated earlier" story, not the lag defect this check targets.
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va-revoke", PermitTokenHash: "ph-1", Outcome: "revoked", RevokedAt: "2026-08-01T02:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb-valid", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T01:00:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictVerified {
		t.Fatalf("verdict = %s, want verified (valid strictly precedes revocation — no lag to report)", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("findings = %+v, want none", res.Findings)
	}
}

func TestReconcile_UnparseableTimestamp_NoFinding(t *testing.T) {
	// No revocation recorded on either side at all here (outcome=expired, not
	// revoked) — nothing to compare, so no finding of any kind. Distinct from
	// TestReconcile_RevocationTimestampUnavailable*, where a revocation WAS
	// recorded but its timestamp isn't usable (a refusal, not silence).
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va-expired", PermitTokenHash: "ph-1", Outcome: "expired", VerifiedAt: ""},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb-valid", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "not-a-timestamp"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictVerified {
		t.Fatalf("verdict = %s, want verified (no revocation recorded on either side, so no timing comparison is even attempted)", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("findings = %+v, want none", res.Findings)
	}
}

func TestReconcile_ValidWithUnparseableTimestamp_NoFinding(t *testing.T) {
	// A real revocation IS recorded with a usable revoked_at, but the OTHER
	// side's candidate "valid" row has no parseable verified_at — cannot
	// order it against the revocation, so no finding (not a fabricated one).
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va-revoke", PermitTokenHash: "ph-1", Outcome: "revoked", RevokedAt: "2026-08-01T00:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb-valid", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "garbage"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictVerified {
		t.Fatalf("verdict = %s, want verified (the candidate valid row's timestamp could not be ordered)", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("findings = %+v, want none", res.Findings)
	}
}

func TestReconcile_BothFindingsOnSameHash(t *testing.T) {
	// A permit that is BOTH independently double-consumed AND shows a
	// post-revocation validity lag against the same counterpart export — both
	// findings must surface, not just the first one detected.
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va-valid", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
		{ID: "va-revoke", PermitTokenHash: "ph-1", Outcome: "revoked", RevokedAt: "2026-08-01T00:30:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb-valid", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T01:00:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictInvalid {
		t.Fatalf("verdict = %s, want invalid", res.ReconciliationIntegrity)
	}
	var haveDup, haveRevoke bool
	for _, f := range res.Findings {
		switch f.Code {
		case CodeDuplicateConsumption:
			haveDup = true
		case CodePostRevocationValidity:
			haveRevoke = true
		}
	}
	if !haveDup || !haveRevoke {
		t.Fatalf("findings = %+v, want both CROSS_RUNTIME_DUPLICATE_CONSUMPTION and CROSS_RUNTIME_POST_REVOCATION_VALIDITY", res.Findings)
	}
}

func TestReconcile_MultipleOverlappingHashes_Deterministic(t *testing.T) {
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va-1", PermitTokenHash: "ph-zzz", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
		{ID: "va-2", PermitTokenHash: "ph-aaa", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb-1", PermitTokenHash: "ph-zzz", Outcome: "verified", VerifiedAt: "2026-08-01T00:05:00Z"},
		{ID: "vb-2", PermitTokenHash: "ph-aaa", Outcome: "verified", VerifiedAt: "2026-08-01T00:05:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.OverlappingPermitTokenHashes != 2 {
		t.Fatalf("overlap = %d, want 2", res.OverlappingPermitTokenHashes)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %+v, want 2 (one duplicate-consumption per hash)", res.Findings)
	}
	// Sorted permit-hash order ("ph-aaa" before "ph-zzz") for stable output.
	if res.Findings[0].Record != "permit:ph-aaa" || res.Findings[1].Record != "permit:ph-zzz" {
		t.Fatalf("findings not in deterministic sorted-hash order: %+v", res.Findings)
	}
}

func TestReconcile_DoesNotMutateInput(t *testing.T) {
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T00:05:00Z"},
	}
	origALen, origBLen := len(a.Verifications), len(b.Verifications)
	_ = Reconcile(&a, &b)
	if len(a.Verifications) != origALen || len(b.Verifications) != origBLen {
		t.Fatalf("Reconcile mutated an input envelope's Verifications slice")
	}
}
