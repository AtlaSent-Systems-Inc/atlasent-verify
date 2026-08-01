// Package envelope verifies an AtlaSent audit-export ENVELOPE — the signed
// JSON bundle produced by v1-export-audit — as distinct from the NDJSON
// per-row audit chain (internal/chain).
//
// The envelope is a single JSON object carrying record arrays (evaluations,
// verification_events, correlation_events, exception_events, admin_log, …), a
// key_id, an embedded public_key_pem, and an OUTER Ed25519 signature over
// jcs.Canonicalize(envelope-minus-signature). The non-evaluations arrays ride
// that OUTER signature; they are NOT folded into the per-row entry_hash chain
// (ADR-020 offline-verifier parity).
//
// The design rule (ADR-048 single evidence ledger): do NOT force correlation
// artifacts into the NDJSON entry-hash chain. Verify them as a separately
// signed section of the same export envelope — which is exactly what the outer
// signature does. Correlation is therefore accepted ONLY when the outer
// signature is valid AND the correlation records pass semantic validation
// (reference resolution, permitted lifecycle, org/action/target bindings, no
// duplicates/conflicts) against the OTHER records in the same signed envelope.
package envelope

import "encoding/json"

// FailureCode enumerates the machine-readable verification failure codes.
// Every code is stable; consumers may branch on them.
type FailureCode string

const (
	// Envelope-level.
	CodeEnvelopeSignatureInvalid   FailureCode = "ENVELOPE_SIGNATURE_INVALID"
	CodeUnsupportedEnvelopeVersion FailureCode = "UNSUPPORTED_ENVELOPE_VERSION"

	// Ledger-level (evaluations[] entry-hash chain inside the envelope). These
	// sit outside the user's enumerated correlation/envelope failure set — the
	// ledger is the per-row hash chain, a distinct layer.
	CodeLedgerHashMismatch FailureCode = "LEDGER_HASH_MISMATCH"
	CodeLedgerChainBroken  FailureCode = "LEDGER_CHAIN_BROKEN"
	CodeLedgerMalformed    FailureCode = "LEDGER_MALFORMED"

	// Correlation-level (semantic validation against the signed record set).
	CodeCorrelationReferenceMissing       FailureCode = "CORRELATION_REFERENCE_MISSING"
	CodeCorrelationReferenceOutsideExport FailureCode = "CORRELATION_REFERENCE_OUTSIDE_EXPORT"
	CodeCorrelationOrgMismatch            FailureCode = "CORRELATION_ORG_MISMATCH"
	CodeCorrelationActionMismatch         FailureCode = "CORRELATION_ACTION_MISMATCH"
	CodeCorrelationTargetMismatch         FailureCode = "CORRELATION_TARGET_MISMATCH"
	CodeCorrelationLifecycleInvalid       FailureCode = "CORRELATION_LIFECYCLE_INVALID"
	CodeCorrelationDuplicate              FailureCode = "CORRELATION_DUPLICATE"
	CodeCorrelationConflict               FailureCode = "CORRELATION_CONFLICT"
)

// SupportedEnvelopeVersion is the only envelope `version` this verifier
// accepts. Any other value fails closed (UNSUPPORTED_ENVELOPE_VERSION) — an
// unknown envelope shape is never assumed safe.
const SupportedEnvelopeVersion = 1

// Layer is a per-layer verdict in the 3-layer VerificationResult.
type Layer string

const (
	// LayerValid means the layer was present and verified.
	LayerValid Layer = "valid"
	// LayerInvalid means the layer was present and FAILED verification.
	LayerInvalid Layer = "invalid"
	// LayerAbsent means the layer's artifacts were not present at all — a
	// legitimate, reported state, NOT an error (e.g. an envelope with no
	// correlation_events, or a legacy NDJSON chain with no envelope).
	LayerAbsent Layer = "absent"
	// LayerUntrustedKey means the outer signature verified against the
	// envelope's EMBEDDED public_key_pem, but that key was not supplied as a
	// trusted key via --keys, so trust is not externally anchored. The
	// signature math is sound; the key provenance is not. Under strict
	// acceptance this is treated as a failure.
	LayerUntrustedKey Layer = "valid_untrusted_key"
)

// Finding is one machine-readable verification failure.
type Finding struct {
	Code   FailureCode `json:"code"`
	Detail string      `json:"detail"`
	// Record locates the offending record when applicable (e.g. a
	// correlation event id / decision_id). Empty for envelope-level codes.
	Record string `json:"record,omitempty"`
}

// OrgBinding reports whether the correlation→decision org binding could be
// checked. The current export projections carry no per-record organization_id,
// so within a single re-signed envelope there is no field to bind a record to
// an org; this is reported honestly as "not_present_in_export" rather than a
// false pass. It becomes "checked" once the producer surfaces organization_id
// on the correlation / evaluation projections.
type OrgBinding string

const (
	OrgBindingChecked       OrgBinding = "checked"
	OrgBindingNotInExport   OrgBinding = "not_present_in_export"
	OrgBindingNotApplicable OrgBinding = "not_applicable" // no correlation records
)

// VerificationResult is the 3-layer result the user's spec calls for:
// envelope integrity, ledger integrity, and correlation integrity — each an
// independent verdict — plus machine-readable projection fields.
type VerificationResult struct {
	// EnvelopeIntegrity is the outer Ed25519 signature verdict. For an
	// envelope input this is never "absent"; for a legacy NDJSON input the
	// whole result is ledger-only and this is "absent".
	EnvelopeIntegrity Layer `json:"envelope_integrity"`

	// LedgerIntegrity is the per-row hash-chain + Ed25519 verdict over the
	// evaluations[] records (reusing internal/chain semantics). "absent" when
	// the bundle carries no evaluation records.
	LedgerIntegrity Layer `json:"ledger_integrity"`

	// CorrelationIntegrity is the semantic verdict over correlation_events[].
	// "absent" (SUCCESS) when the bundle carries no correlation records.
	CorrelationIntegrity Layer `json:"correlation_integrity"`

	// CorrelationProtection names WHAT protects the correlation records. It is
	// always "outer_envelope_signature" — correlation is deliberately NOT in
	// the per-row entry_hash chain; it is covered by the envelope signature.
	CorrelationProtection string `json:"correlation_protection"`

	// CorrelationRecordsVerified counts correlation records that passed every
	// semantic check.
	CorrelationRecordsVerified int `json:"correlation_records_verified"`
	// CorrelationRecordsTotal is the number of correlation records present.
	CorrelationRecordsTotal int `json:"correlation_records_total"`

	// LedgerEntriesVerified counts evaluation records whose hash chain + (when
	// keys supplied) signature verified.
	LedgerEntriesVerified int `json:"ledger_entries_verified"`

	// OrgBinding reports whether the correlation→decision org tie was
	// checkable (see OrgBinding).
	OrgBinding OrgBinding `json:"org_binding"`

	// KeyID is the envelope's declared signing key id (echoed for the reader).
	KeyID string `json:"key_id,omitempty"`
	// KeyTrusted is true when the outer signature verified against a key
	// supplied via --keys (externally anchored trust), false when it verified
	// only against the envelope's embedded public_key_pem.
	KeyTrusted bool `json:"key_trusted"`

	// Findings is every failure across all three layers, most-relevant first
	// (envelope, then ledger, then correlation).
	Findings []Finding `json:"findings"`
}

// OK reports whether the result is a clean pass under NORMAL acceptance:
// no findings, and neither envelope nor ledger nor correlation is invalid.
// An untrusted-key envelope is a WARNING under normal acceptance (OK stays
// true) but a failure under strict acceptance (see StrictOK).
func (r *VerificationResult) OK() bool {
	if len(r.Findings) > 0 {
		return false
	}
	if r.EnvelopeIntegrity == LayerInvalid ||
		r.LedgerIntegrity == LayerInvalid ||
		r.CorrelationIntegrity == LayerInvalid {
		return false
	}
	return true
}

// StrictOK reports whether the result is acceptable as pilot/acceptance
// evidence: OK() AND the outer signature was verified against an EXTERNALLY
// TRUSTED key (supplied via --keys), not merely the envelope's embedded key.
// A bare pass that trusted the envelope's own self-described key is NOT proof.
func (r *VerificationResult) StrictOK() (bool, string) {
	if !r.OK() {
		return false, "verification findings present"
	}
	if r.EnvelopeIntegrity == LayerUntrustedKey || !r.KeyTrusted {
		return false, "outer signature verified only against the envelope's embedded public_key_pem; supply the R3 audit-export key via --keys to anchor trust externally"
	}
	return true, "envelope signature verified against a trusted key; ledger + correlation integrity confirmed"
}

// AddFinding appends a finding.
func (r *VerificationResult) AddFinding(code FailureCode, record, detail string) {
	r.Findings = append(r.Findings, Finding{Code: code, Detail: detail, Record: record})
}

// ─── Envelope + record decode shapes ─────────────────────────────────────────

// Envelope is the decoded audit-export bundle. Record arrays are held as raw
// JSON where a byte-faithful re-hash is needed (evaluations, for the ledger
// layer) and as typed structs where only field values matter (correlation,
// verification).
type Envelope struct {
	Version       int               `json:"version"`
	OrgID         string            `json:"org_id"`
	KeyID         string            `json:"key_id"`
	PublicKeyPEM  string            `json:"public_key_pem"`
	Signature     string            `json:"signature"` // standard base64 (btoa) over canonicalize(envelope-minus-signature)
	Evaluations   []json.RawMessage `json:"evaluations"`
	Verifications []VerificationRow `json:"verification_events"`
	Correlations  []CorrelationRow  `json:"correlation_events"`
}

// VerificationRow mirrors export_verification_events_rows (the permit-
// verification stage). Only the fields the correlation validator consults are
// modeled; unknown fields are ignored.
type VerificationRow struct {
	ID                   string `json:"id"`
	DecisionID           string `json:"decision_id"`
	PermitTokenHash      string `json:"permit_token_hash"`
	PresentedActorID     string `json:"presented_actor_id"`
	PresentedActionType  string `json:"presented_action_type"`
	PresentedEnvironment string `json:"presented_environment"`
	PresentedTargetID    string `json:"presented_target_id"`
	PresentedPayloadHash string `json:"presented_payload_hash"`
	Outcome              string `json:"outcome"`
	OrganizationID       string `json:"organization_id"` // optional; present only once the producer surfaces it
}

// CorrelationRow mirrors export_correlation_events_rows (the post-execution
// Evidence stage; verification_events rows with event_type=execution_correlation).
type CorrelationRow struct {
	ID                   string   `json:"id"`
	DecisionID           string   `json:"decision_id"`
	PermitTokenHash      string   `json:"permit_token_hash"`
	PresentedActorID     string   `json:"presented_actor_id"`
	PresentedActionType  string   `json:"presented_action_type"`
	PresentedEnvironment string   `json:"presented_environment"`
	PresentedPayloadHash string   `json:"presented_payload_hash"`
	CorrelationStatus    string   `json:"correlation_status"`
	Confidence           float64  `json:"confidence"`
	ReasonCodes          []string `json:"reason_codes"`
	BypassDetected       bool     `json:"bypass_detected"`
	ObservedActionHash   string   `json:"observed_action_hash"`
	ObservedPrincipal    string   `json:"observed_principal"`
	ProviderRequestID    string   `json:"provider_request_id"`
	Provider             string   `json:"provider"`
	OrganizationID       string   `json:"organization_id"` // optional; see VerificationRow
}

// EvaluationLite is the minimal decode of an evaluations[] row the correlation
// validator needs (the Decision anchor). The ledger layer re-parses the raw
// bytes independently for the hash check.
type EvaluationLite struct {
	ID              string `json:"id"`
	Decision        string `json:"decision"`
	PermitTokenHash string `json:"permit_token_hash"`
	OrganizationID  string `json:"organization_id"` // optional
}
