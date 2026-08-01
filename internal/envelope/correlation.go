package envelope

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// validateCorrelations runs the semantic validation of the correlation records
// against the OTHER records in the same signed envelope. The outer signature
// has ALREADY been verified by the caller, so "covered by the signed payload"
// is established: correlation records are top-level members of the envelope
// object that was canonicalized and signature-checked, so any tampering with a
// correlation field would have failed the outer signature. This function adds
// the remaining conditions: reference resolution, permitted lifecycle, and
// org/action/target binding, plus duplicate/conflict detection.
//
// It returns the count of correlation records that passed EVERY check and
// appends a Finding for each failure. OrgBinding reports whether the org tie
// was checkable from the available fields.
func validateCorrelations(env *Envelope, res *VerificationResult) (verified int, org OrgBinding) {
	if len(env.Correlations) == 0 {
		return 0, OrgBindingNotApplicable
	}

	// Per-record lifecycle evidence, tallied only for records that survive
	// every check (see the failed[] flags below).
	resolvedPermit := make([]bool, len(env.Correlations))

	// Index the Decision anchors (evaluations[]) by permit_token_hash. The
	// evaluations rows are raw JSON (the ledger layer needs byte fidelity); we
	// decode a lite view here for the reference/lifecycle checks.
	decByPermit := map[string]EvaluationLite{}
	for _, raw := range env.Evaluations {
		var d EvaluationLite
		if err := json.Unmarshal(raw, &d); err != nil {
			continue // a malformed evaluation is the ledger layer's finding, not ours
		}
		if d.PermitTokenHash != "" {
			decByPermit[d.PermitTokenHash] = d
		}
	}

	// Index the permit-verification records by their two join keys.
	verByPermit := map[string]VerificationRow{}
	verByDecision := map[string]VerificationRow{}
	for _, v := range env.Verifications {
		if v.PermitTokenHash != "" {
			verByPermit[v.PermitTokenHash] = v
		}
		if v.DecisionID != "" {
			verByDecision[v.DecisionID] = v
		}
	}

	// Track org-binding checkability: it is "checked" only if at least one
	// correlation (or its resolved anchor) actually carried an organization_id
	// we could compare against the envelope org. Otherwise the current
	// projections simply don't carry it (honest not_present_in_export).
	orgCheckable := false

	// Group correlations by identity for duplicate/conflict detection.
	type ident struct{ decision, permit, req string }
	groups := map[ident][]int{}

	// Per-record failure flags so a record with multiple problems still counts
	// as one non-verified record (not double-subtracted).
	failed := make([]bool, len(env.Correlations))
	markFail := func(i int, code FailureCode, detail string) {
		failed[i] = true
		res.AddFinding(code, correlationRecordRef(env.Correlations[i]), detail)
	}

	for i, c := range env.Correlations {
		groups[ident{c.DecisionID, c.PermitTokenHash, c.ProviderRequestID}] = append(
			groups[ident{c.DecisionID, c.PermitTokenHash, c.ProviderRequestID}], i)

		// (1) Reference present at all?
		if c.DecisionID == "" && c.PermitTokenHash == "" {
			markFail(i, CodeCorrelationReferenceMissing,
				"correlation record carries neither decision_id nor permit_token_hash; it cannot be tied to any Decision or Permit")
			continue
		}

		// (2) Reference resolves WITHIN this export?
		dec, hasDec := EvaluationLite{}, false
		if c.PermitTokenHash != "" {
			if d, ok := decByPermit[c.PermitTokenHash]; ok {
				dec, hasDec = d, true
			}
		}
		ver, hasVer := VerificationRow{}, false
		if c.PermitTokenHash != "" {
			if v, ok := verByPermit[c.PermitTokenHash]; ok {
				ver, hasVer = v, true
			}
		}
		if !hasVer && c.DecisionID != "" {
			if v, ok := verByDecision[c.DecisionID]; ok {
				ver, hasVer = v, true
			}
		}
		if !hasDec && !hasVer {
			markFail(i, CodeCorrelationReferenceOutsideExport,
				fmt.Sprintf("correlation references decision_id=%q permit_token_hash=%q but neither a Decision nor a permit-verification for it is present in this export",
					c.DecisionID, shortHash(c.PermitTokenHash)))
			continue
		}
		resolvedPermit[i] = true // a Permit (Decision and/or verification) was resolved in-export

		// (4-lifecycle) permit -> execution -> observation -> correlation.
		// A correlation asserts an execution was observed. That is only
		// coherent if the referenced Decision issued a permit (decision=allow).
		// A correlation for a non-allow Decision is contradictory; a
		// correlation whose only anchor is a non-successful permit-verification
		// (expired/revoked/invalid/replay_blocked) with no allow-Decision is a
		// broken lifecycle.
		if hasDec {
			if strings.ToLower(dec.Decision) != "allow" {
				markFail(i, CodeCorrelationLifecycleInvalid,
					fmt.Sprintf("correlation references Decision id=%s whose outcome is %q (not allow) — no permit was issued, so no execution could be authorized",
						dec.ID, dec.Decision))
				continue
			}
		} else if hasVer && !verificationOutcomeAdmitsExecution(ver.Outcome) {
			markFail(i, CodeCorrelationLifecycleInvalid,
				fmt.Sprintf("correlation's only in-export anchor is a permit-verification with outcome %q, which never authorized an execution to observe", ver.Outcome))
			continue
		}

		// (5) org / action / target bindings. Checked against the resolved
		// permit-verification (both carry the "presented" fields).
		if hasVer {
			if !bindingAgrees(c.PresentedActionType, ver.PresentedActionType) ||
				!bindingAgrees(c.PresentedEnvironment, ver.PresentedEnvironment) {
				markFail(i, CodeCorrelationActionMismatch,
					fmt.Sprintf("correlation asserts action=%q env=%q but the permit-verification for the same permit recorded action=%q env=%q",
						c.PresentedActionType, c.PresentedEnvironment, ver.PresentedActionType, ver.PresentedEnvironment))
				continue
			}
			if !bindingAgrees(c.PresentedPayloadHash, ver.PresentedPayloadHash) {
				markFail(i, CodeCorrelationTargetMismatch,
					fmt.Sprintf("correlation payload_hash=%q disagrees with the permit-verification payload_hash=%q for the same permit",
						shortHash(c.PresentedPayloadHash), shortHash(ver.PresentedPayloadHash)))
				continue
			}
		}

		// (5-org) org binding, when the fields are present.
		corrOrg := c.OrganizationID
		anchorOrg := ""
		if hasDec {
			anchorOrg = dec.OrganizationID
		} else if hasVer {
			anchorOrg = ver.OrganizationID
		}
		if corrOrg != "" || anchorOrg != "" || env.OrgID != "" {
			// Only assert a mismatch when we actually have two org values to
			// compare; absence of the projection column is not a mismatch.
			if corrOrg != "" && env.OrgID != "" {
				orgCheckable = true
				if corrOrg != env.OrgID {
					markFail(i, CodeCorrelationOrgMismatch,
						fmt.Sprintf("correlation organization_id=%q differs from the envelope org_id=%q", corrOrg, env.OrgID))
					continue
				}
			}
			if anchorOrg != "" && env.OrgID != "" {
				orgCheckable = true
				if anchorOrg != env.OrgID {
					markFail(i, CodeCorrelationOrgMismatch,
						fmt.Sprintf("correlation's referenced Decision/Verification organization_id=%q differs from the envelope org_id=%q", anchorOrg, env.OrgID))
					continue
				}
			}
		}
	}

	// (6) duplicate / conflict across records sharing an identity key.
	// Iterate deterministically for stable finding order.
	keys := make([]ident, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(a, b int) bool {
		if keys[a].decision != keys[b].decision {
			return keys[a].decision < keys[b].decision
		}
		if keys[a].permit != keys[b].permit {
			return keys[a].permit < keys[b].permit
		}
		return keys[a].req < keys[b].req
	})
	for _, k := range keys {
		idxs := groups[k]
		if len(idxs) < 2 {
			continue
		}
		// Compare material verdict fields across the group.
		allEqual := true
		first := materialKey(env.Correlations[idxs[0]])
		for _, j := range idxs[1:] {
			if materialKey(env.Correlations[j]) != first {
				allEqual = false
				break
			}
		}
		code := CodeCorrelationDuplicate
		detail := fmt.Sprintf("%d byte-identical correlation records share identity (decision_id=%q permit=%q request=%q)",
			len(idxs), k.decision, shortHash(k.permit), k.req)
		if !allEqual {
			code = CodeCorrelationConflict
			detail = fmt.Sprintf("%d correlation records share identity (decision_id=%q permit=%q request=%q) but carry CONTRADICTORY verdicts",
				len(idxs), k.decision, shortHash(k.permit), k.req)
		}
		// Fail every member of a conflicting/duplicate group that isn't
		// already failed for another reason.
		for _, j := range idxs {
			if !failed[j] {
				failed[j] = true
			}
		}
		res.AddFinding(code, correlationRecordRef(env.Correlations[idxs[0]]), detail)
	}

	for i, f := range failed {
		if f {
			continue
		}
		verified++
		// Lifecycle-stage tally, only for fully-verified records.
		if resolvedPermit[i] {
			res.Stages.PermitResolved++
		}
		switch strings.ToUpper(strings.TrimSpace(env.Correlations[i].CorrelationStatus)) {
		case "MATCH", "MISMATCH":
			res.Stages.Observed++
		case "NOT_OBSERVED":
			res.Stages.NotObserved++
		}
	}

	if orgCheckable {
		return verified, OrgBindingChecked
	}
	return verified, OrgBindingNotInExport
}

// verificationOutcomeAdmitsExecution reports whether a permit-verification
// outcome is consistent with an execution having occurred (a real permit
// consumption). "verified" is the success outcome; "mismatch" still evidences
// a presentation. expired/revoked/invalid/replay_blocked never authorized an
// execution to observe.
func verificationOutcomeAdmitsExecution(outcome string) bool {
	switch strings.ToLower(strings.TrimSpace(outcome)) {
	case "verified", "mismatch", "":
		return true
	default:
		return false
	}
}

// bindingAgrees returns true when two presented values agree. An empty value on
// EITHER side is treated as "not asserted" and does not create a mismatch —
// only two non-empty, differing values are a disagreement.
func bindingAgrees(a, b string) bool {
	if a == "" || b == "" {
		return true
	}
	return a == b
}

// materialKey is the verdict fingerprint used to tell a duplicate (identical)
// from a conflict (contradictory) within an identity group.
func materialKey(c CorrelationRow) string {
	return strings.Join([]string{
		c.CorrelationStatus,
		fmt.Sprintf("%v", c.Confidence),
		c.ObservedActionHash,
		c.PresentedPayloadHash,
		fmt.Sprintf("%v", c.BypassDetected),
	}, "\x1f")
}

func correlationRecordRef(c CorrelationRow) string {
	if c.ID != "" {
		return c.ID
	}
	if c.DecisionID != "" {
		return "decision:" + c.DecisionID
	}
	if c.PermitTokenHash != "" {
		return "permit:" + shortHash(c.PermitTokenHash)
	}
	return "(anonymous correlation)"
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "…"
}
