package envelope

import (
	"encoding/json"
	"fmt"
	"strings"
)

// validateArchiveEvents semantically validates the Evidence Archive record
// sections of a signed export bundle (ADR-064): governed archive DISCLOSURES
// (`retrieval_events`) and read-assurance VERDICTS (`probe_events`).
//
// Same posture as validateCorrelations: the outer signature already proves the
// bytes were not altered. This layer asks the different question — whether the
// records are internally coherent and actually anchored to the rest of the
// bundle. A record can be perfectly signed and still be nonsense (a disclosure
// of an object nothing in the bundle archived; a "succeeded" retrieval that
// returned no bytes; two records with the same id; a record belonging to
// another org). Signature validity is not semantic validity.
//
// WHAT THIS LAYER CANNOT DO, AND SAYS SO
// --------------------------------------
// It CANNOT confirm that any retention is actually in force. The verifier is
// offline by contract — no network, no object store — so exported retention
// metadata is read as a CLAIM RECORDED BY THE PRODUCER, never as proof that a
// six-year lock exists on real storage. `RetentionAssurance` reports exactly
// that, and there is deliberately no code path that upgrades it.
func validateArchiveEvents(env *Envelope, res *VerificationResult) (retrievalsOK, probesOK int, org OrgBinding) {
	orgChecked := false
	orgUncheckable := false

	// Decision anchors present in THIS bundle. A retrieval naming a decision
	// that is not here is an out-of-bundle reference: the export cannot show
	// what authorized the disclosure, which is the one thing a disclosure
	// record exists to be checkable against.
	decisions := map[string]EvaluationLite{}
	for _, raw := range env.Evaluations {
		var e EvaluationLite
		if err := json.Unmarshal(raw, &e); err != nil {
			continue // the ledger layer reports malformed evaluation rows
		}
		if e.ID != "" {
			decisions[e.ID] = e
		}
	}

	// Objects this bundle's archive records mention, so a probe can be tied to
	// the same object a disclosure names.
	seenRetrievalIDs := map[string]int{}
	seenProbeIDs := map[string]int{}

	// ── retrievals ───────────────────────────────────────────────────────────
	for i, r := range env.Retrievals {
		ref := archiveRecordRef("retrieval", r.ID, r.ObjectID)
		bad := false

		// MISSING — a disclosure record without WHAT or WHY is a rumour of a
		// disclosure, not evidence of one. Mirrors the producer-side CHECK, so
		// a row that somehow bypassed it is still caught here.
		var missing []string
		if strings.TrimSpace(r.ID) == "" {
			missing = append(missing, "id")
		}
		if strings.TrimSpace(r.ObjectID) == "" {
			missing = append(missing, "object_id")
		}
		if strings.TrimSpace(r.Purpose) == "" {
			missing = append(missing, "purpose")
		}
		if strings.TrimSpace(r.RetrievalStatus) == "" {
			missing = append(missing, "retrieval_status")
		}
		if strings.TrimSpace(r.VerifiedAt) == "" {
			missing = append(missing, "verified_at")
		}
		if strings.TrimSpace(r.PresentedActorID) == "" {
			missing = append(missing, "presented_actor_id")
		}
		if len(missing) > 0 {
			res.AddFinding(CodeArchiveReferenceMissing, ref,
				fmt.Sprintf("archive retrieval record %d is missing required field(s): %s", i, strings.Join(missing, ", ")))
			bad = true
		}

		// DUPLICATE — the same disclosure recorded twice would inflate any
		// count derived from the bundle, and an auditor counting disclosures is
		// the primary consumer of this section.
		if r.ID != "" {
			if prev, dup := seenRetrievalIDs[r.ID]; dup {
				res.AddFinding(CodeArchiveDuplicate, ref,
					fmt.Sprintf("archive retrieval id %q appears at records %d and %d", r.ID, prev, i))
				bad = true
			} else {
				seenRetrievalIDs[r.ID] = i
			}
		}

		// CROSS-ORGANIZATION — every record in a bundle belongs to the bundle's
		// org. A record naming another org is either a hand-assembled envelope
		// or a producer bug; neither is something to pass.
		if r.OrganizationID != "" {
			orgChecked = true
			if !strings.EqualFold(r.OrganizationID, env.OrgID) {
				res.AddFinding(CodeArchiveOrgMismatch, ref,
					fmt.Sprintf("archive retrieval organization_id %q does not match the envelope org %q", r.OrganizationID, env.OrgID))
				bad = true
			}
		} else {
			orgUncheckable = true
		}

		// UNKNOWN OUTCOME — a status outside the closed vocabulary must not be
		// silently tolerated: a reader that only knows "retrieved" and "denied"
		// would treat anything else as neither, and a disclosure that counts as
		// neither is a disclosure nobody sees.
		switch r.RetrievalStatus {
		case "retrieved", "denied":
		case "":
			// already reported as missing
		default:
			res.AddFinding(CodeArchiveOutcomeUnknown, ref,
				fmt.Sprintf("archive retrieval status %q is outside the closed vocabulary (retrieved|denied)", r.RetrievalStatus))
			bad = true
		}

		// CONFLICT — the record contradicts itself. A refusal cannot carry the
		// bytes it refused to release, and a success that records no hash
		// cannot be checked against anything, which defeats the point of
		// exporting it.
		switch r.RetrievalStatus {
		case "retrieved":
			if strings.TrimSpace(r.ReturnedSHA256) == "" {
				res.AddFinding(CodeArchiveConflict, ref,
					"archive retrieval reports a successful disclosure but records no returned_sha256; the released bytes cannot be identified")
				bad = true
			}
		case "denied":
			if strings.TrimSpace(r.ReturnedSHA256) != "" {
				res.AddFinding(CodeArchiveConflict, ref,
					"archive retrieval reports a REFUSAL yet records returned_sha256; a denial released nothing")
				bad = true
			}
			if strings.TrimSpace(r.VerifyErrorCode) == "" {
				res.AddFinding(CodeArchiveConflict, ref,
					"archive retrieval reports a refusal with no verify_error_code; a denial that does not say why cannot be reviewed")
				bad = true
			}
		}

		// OUT-OF-BUNDLE REFERENCE — a disclosure naming a decision this export
		// does not contain. Reported when the bundle has evaluations at all: a
		// bundle with no evaluations is a legitimately narrow export, and
		// demanding an anchor that was never requested would be a false alarm.
		if r.DecisionID != "" && len(decisions) > 0 {
			if _, ok := decisions[r.DecisionID]; !ok {
				res.AddFinding(CodeArchiveReferenceOutsideExport, ref,
					fmt.Sprintf("archive retrieval references decision_id %q, which is not among the %d evaluation record(s) in this export", r.DecisionID, len(decisions)))
				bad = true
			}
		}

		if !bad {
			retrievalsOK++
			res.ArchiveStages.RetrievalAttempted++
			switch r.RetrievalStatus {
			case "retrieved":
				res.ArchiveStages.RetrievalSucceeded++
			case "denied":
				res.ArchiveStages.RetrievalFailed++
			}
			if archiveRetentionRecorded(r.ArchiveRetentionMode, r.ArchiveRetainUntil, r.ArchiveRetentionEnforced) {
				res.ArchiveRetentionRecords++
			}
		}
	}

	// ── probes ───────────────────────────────────────────────────────────────
	for i, p := range env.Probes {
		ref := archiveRecordRef("probe", p.ID, p.ObjectID)
		bad := false

		var missing []string
		if strings.TrimSpace(p.ID) == "" {
			missing = append(missing, "id")
		}
		if strings.TrimSpace(p.ObjectID) == "" {
			missing = append(missing, "object_id")
		}
		if strings.TrimSpace(p.ProbeStatus) == "" {
			missing = append(missing, "probe_status")
		}
		if strings.TrimSpace(p.VerifiedAt) == "" {
			missing = append(missing, "verified_at")
		}
		if len(missing) > 0 {
			res.AddFinding(CodeArchiveReferenceMissing, ref,
				fmt.Sprintf("archive probe record %d is missing required field(s): %s", i, strings.Join(missing, ", ")))
			bad = true
		}

		if p.ID != "" {
			if prev, dup := seenProbeIDs[p.ID]; dup {
				res.AddFinding(CodeArchiveDuplicate, ref,
					fmt.Sprintf("archive probe id %q appears at records %d and %d", p.ID, prev, i))
				bad = true
			} else {
				seenProbeIDs[p.ID] = i
			}
		}

		if p.OrganizationID != "" {
			orgChecked = true
			if !strings.EqualFold(p.OrganizationID, env.OrgID) {
				res.AddFinding(CodeArchiveOrgMismatch, ref,
					fmt.Sprintf("archive probe organization_id %q does not match the envelope org %q", p.OrganizationID, env.OrgID))
				bad = true
			}
		} else {
			orgUncheckable = true
		}

		switch p.ProbeStatus {
		case "verified", "mismatch", "unreadable", "inconclusive":
		case "":
			// already reported as missing
		default:
			res.AddFinding(CodeArchiveOutcomeUnknown, ref,
				fmt.Sprintf("archive probe status %q is outside the closed vocabulary (verified|mismatch|unreadable|inconclusive)", p.ProbeStatus))
			bad = true
		}

		// CONFLICT — a confirmed integrity check is a claim about specific
		// bytes, so it must carry their hash. The two non-reading outcomes
		// legitimately carry none; `mismatch` may or may not, because it can be
		// discovered either by hashing bytes that disagree or by an unverifiable
		// manifest over bytes that were read.
		if p.ProbeStatus == "verified" && strings.TrimSpace(p.ReturnedSHA256) == "" {
			res.AddFinding(CodeArchiveConflict, ref,
				"archive probe reports integrity CONFIRMED but records no returned_sha256; there is no stated subject for the claim")
			bad = true
		}
		if p.ProbeStatus == "verified" && p.IntegrityVerified != nil && !*p.IntegrityVerified {
			res.AddFinding(CodeArchiveConflict, ref,
				"archive probe status is `verified` while integrity_verified is false; the record contradicts itself")
			bad = true
		}

		if !bad {
			probesOK++
			res.ArchiveStages.ProbeExecuted++
			switch p.ProbeStatus {
			case "verified":
				res.ArchiveStages.IntegrityConfirmed++
			case "mismatch", "unreadable":
				res.ArchiveStages.IntegrityFailed++
			case "inconclusive":
				// Reported on its own line, NEVER folded into confirmed or
				// failed. "We could not check" is a third fact, and a reader
				// who only sees two buckets will read it as one of them.
				res.ArchiveStages.IntegrityInconclusive++
			}
			if archiveRetentionRecorded(p.ArchiveRetentionMode, p.ArchiveRetainUntil, p.ArchiveRetentionEnforced) {
				res.ArchiveRetentionRecords++
			}
		}
	}

	switch {
	case orgChecked && !orgUncheckable:
		org = OrgBindingChecked
	case orgChecked && orgUncheckable:
		// Some records carry the field and some do not. Report the weaker
		// state: a partial check is not a check.
		org = OrgBindingNotInExport
	case orgUncheckable:
		org = OrgBindingNotInExport
	default:
		org = OrgBindingNotApplicable
	}
	return retrievalsOK, probesOK, org
}

// archiveRetentionRecorded reports whether a record carries retention metadata
// worth counting. It answers "did the producer record a retention claim for
// this object", NOT "is retention in force" — nothing offline can answer the
// second, which is why the result feeds a count labelled `recorded`.
//
// A retain-until with enforcement FALSE is deliberately not counted: a term
// that was requested and never confirmed by the provider is not a recorded
// retention, and counting it would let an unenforced archive read as protected.
func archiveRetentionRecorded(mode, retainUntil string, enforced *bool) bool {
	if strings.TrimSpace(mode) == "" || strings.TrimSpace(retainUntil) == "" {
		return false
	}
	return enforced != nil && *enforced
}

func archiveRecordRef(kind, id, objectID string) string {
	switch {
	case id != "" && objectID != "":
		return fmt.Sprintf("%s:%s object=%s", kind, id, objectID)
	case id != "":
		return fmt.Sprintf("%s:%s", kind, id)
	case objectID != "":
		return fmt.Sprintf("%s:object=%s", kind, objectID)
	default:
		return kind + ":<unidentified>"
	}
}
