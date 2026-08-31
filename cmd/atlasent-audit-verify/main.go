// Command atlasent-audit-verify validates an AtlaSent audit export per
// ADR-020. Read-only, no network, no DB.
//
// It accepts two input shapes and auto-detects between them:
//
//   - NDJSON audit chain (one entry per line): per-row hash-chain + Ed25519
//     verification (the original mode).
//   - Signed audit-export ENVELOPE (a single JSON object with an outer
//     signature): the 3-layer envelope / ledger / correlation verification
//     (ADR-048 — correlation is verified as a separately-signed section of the
//     same export envelope, NOT folded into the per-row entry-hash chain).
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/AtlaSent-Systems-Inc/atlasent-verify/internal/chain"
	"github.com/AtlaSent-Systems-Inc/atlasent-verify/internal/envelope"
	"github.com/AtlaSent-Systems-Inc/atlasent-verify/internal/keys"
)

// Version is stamped at build time via -ldflags
// "-X main.Version=<version>". The chain-version supported is
// hard-coded; bumping it is the canonical-form-spec version bump.
var Version = "v0.0.0-dev"

const supportedChainVersion = 5

func main() {
	chainPath := flag.String("chain", "", "Path to the audit export to verify (required, '-' for stdin). Accepts an NDJSON chain OR a signed export envelope (auto-detected).")
	keysPath := flag.String("keys", "", "Path to PEM file of Ed25519 public keys (optional; signature verification skipped if absent). For an envelope, resolves the R3 audit-export key_id to an externally trusted key.")
	headPath := flag.String("head", "", "Path to a trusted head-anchor JSON file (NDJSON mode only; tail-truncation / completeness check skipped if absent)")
	requireSigs := flag.Bool("require-signatures", false, "Strict acceptance: fail (exit 1) unless signatures were verified against a known key. Requires --keys. In envelope mode, requires the outer signature to verify against an externally trusted key (not merely the envelope's embedded public_key_pem).")
	bundle := flag.Bool("bundle", false, "Force envelope (signed export bundle) verification even if auto-detection is unsure.")
	jsonOut := flag.Bool("json", false, "Emit the machine-readable verification result as JSON (envelope mode).")
	showVer := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVer {
		fmt.Printf("atlasent-audit-verify %s (chain v%d)\n", Version, supportedChainVersion)
		return
	}

	if *chainPath == "" {
		fmt.Fprintln(os.Stderr, "error: --chain is required")
		flag.Usage()
		os.Exit(2)
	}

	if *requireSigs && *keysPath == "" {
		fmt.Fprintln(os.Stderr, "error: --require-signatures requires --keys (there is nothing to verify signatures against)")
		os.Exit(2)
	}

	// Read the whole input into memory: envelope detection needs to inspect the
	// leading bytes, and an export bundle is a single object anyway.
	var raw []byte
	if *chainPath == "-" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: read stdin: %v\n", err)
			os.Exit(2)
		}
		raw = b
	} else {
		b, err := os.ReadFile(*chainPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: open chain: %v\n", err)
			os.Exit(2)
		}
		raw = b
	}

	var ks chain.KeyStore
	if *keysPath != "" {
		store, err := keys.LoadFile(*keysPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: load keys: %v\n", err)
			os.Exit(2)
		}
		ks = store
	}

	if *bundle || envelope.LooksLikeEnvelope(raw) {
		os.Exit(runEnvelope(raw, ks, *requireSigs, *jsonOut, ks != nil))
	}

	runNDJSON(raw, ks, *headPath, *requireSigs)
}

// runEnvelope verifies a signed export envelope and returns the process exit
// code (0 pass, 1 findings).
func runEnvelope(raw []byte, ks chain.KeyStore, requireSigs, jsonOut, keysSupplied bool) int {
	res, err := envelope.Verify(raw, ks)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: verify envelope: %v\n", err)
		return 2
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		printEnvelopeHuman(res)
	}

	// Exit policy. Under --require-signatures, demand StrictOK (trusted key).
	if requireSigs {
		ok, reason := res.StrictOK()
		if !ok {
			fmt.Fprintf(os.Stdout, "NOT ACCEPTED (--require-signatures): %s\n", reason)
			return 1
		}
		fmt.Fprintf(os.Stdout, "ACCEPTED (--require-signatures): %s\n", reason)
		return 0
	}
	if !res.OK() {
		return 1
	}
	return 0
}

// printEnvelopeHuman prints a defensible human summary. A lifecycle stage line
// is printed with a check ONLY when that layer was actually verified — never a
// blanket green.
func printEnvelopeHuman(res *envelope.VerificationResult) {
	mark := func(l envelope.Layer) string {
		switch l {
		case envelope.LayerValid:
			return "OK  "
		case envelope.LayerUntrustedKey:
			return "WARN"
		case envelope.LayerInvalid:
			return "FAIL"
		case envelope.LayerAbsent:
			return "—   "
		default:
			return "?   "
		}
	}

	fmt.Fprintf(os.Stdout, "[%s] Envelope signature", mark(res.EnvelopeIntegrity))
	if res.KeyID != "" {
		fmt.Fprintf(os.Stdout, " (key_id=%s, %s)", res.KeyID, trustLabel(res.KeyTrusted))
	}
	fmt.Fprintln(os.Stdout)

	fmt.Fprintf(os.Stdout, "[%s] Ledger (evaluations hash-chain)", mark(res.LedgerIntegrity))
	if res.LedgerIntegrity != envelope.LayerAbsent {
		fmt.Fprintf(os.Stdout, " — %d entr(ies)", res.LedgerEntriesVerified)
	}
	fmt.Fprintln(os.Stdout)

	fmt.Fprintf(os.Stdout, "[%s] Correlation integrity", mark(res.CorrelationIntegrity))
	if res.CorrelationIntegrity == envelope.LayerAbsent {
		fmt.Fprint(os.Stdout, " — absent (no post-execution correlation records in this export)")
	} else {
		fmt.Fprintf(os.Stdout, " — %d/%d record(s) verified, protection: %s, org_binding: %s",
			res.CorrelationRecordsVerified, res.CorrelationRecordsTotal, res.CorrelationProtection, res.OrgBinding)
	}
	fmt.Fprintln(os.Stdout)

	// Honest CCAM lifecycle breakdown — shown ONLY when the correlation layer
	// actually verified, and each stage line is backed by records that carry
	// that stage's evidence. Never a blanket green just because the outer
	// signature is valid.
	if res.CorrelationIntegrity == envelope.LayerValid && res.CorrelationRecordsVerified > 0 {
		st := res.Stages
		fmt.Fprintf(os.Stdout, "    ├─ Permit       %s  %d/%d correlation(s) resolve to an issued permit\n",
			stageMark(st.PermitResolved == res.CorrelationRecordsVerified), st.PermitResolved, res.CorrelationRecordsVerified)
		if st.NotObserved > 0 {
			fmt.Fprintf(os.Stdout, "    ├─ Observation  %s  %d observed, %d not-observed (collector found no provider event)\n",
				stageMark(st.Observed > 0), st.Observed, st.NotObserved)
		} else {
			fmt.Fprintf(os.Stdout, "    ├─ Observation  %s  %d execution(s) observed in the provider log\n",
				stageMark(st.Observed == res.CorrelationRecordsVerified), st.Observed)
		}
		fmt.Fprintf(os.Stdout, "    └─ Correlation  OK   %d record(s), signed by the R3 outer envelope\n",
			res.CorrelationRecordsVerified)
	}

	fmt.Fprintf(os.Stdout, "[%s] Evidence archive integrity", mark(res.ArchiveIntegrity))
	if res.ArchiveIntegrity == envelope.LayerAbsent {
		fmt.Fprint(os.Stdout, " — absent (no archive disclosure or integrity-probe records in this export)")
	} else {
		fmt.Fprintf(os.Stdout, " — %d/%d record(s) verified, protection: %s, org_binding: %s",
			res.ArchiveRecordsVerified, res.ArchiveRecordsTotal, res.ArchiveProtection, res.ArchiveOrgBinding)
	}
	fmt.Fprintln(os.Stdout)

	// Archive breakdown. The four states are printed as four separate lines on
	// purpose: "the archive was read" is not "the read was allowed", and "a
	// probe ran" is not "the bytes were confirmed". Collapsing either pair
	// would let a reader infer assurance the records do not carry.
	if res.ArchiveIntegrity == envelope.LayerValid && res.ArchiveRecordsVerified > 0 {
		st := res.ArchiveStages
		row := func(label, detail string) {
			fmt.Fprintf(os.Stdout, "    ├─ %-22s %s\n", label, detail)
		}
		if st.RetrievalAttempted > 0 {
			row("Retrieval attempted", fmt.Sprintf("%d disclosure request(s) recorded", st.RetrievalAttempted))
			row("Retrieval succeeded", fmt.Sprintf("%d released bytes to the caller", st.RetrievalSucceeded))
			row("Retrieval refused", fmt.Sprintf("%d denied", st.RetrievalFailed))
		}
		if st.ProbeExecuted > 0 {
			row("Probe executed", fmt.Sprintf("%d sampled-object check(s) ran", st.ProbeExecuted))
			row("Integrity confirmed", fmt.Sprintf("%d object(s) matched every assertion", st.IntegrityConfirmed))
			row("Integrity failed", fmt.Sprintf("%d mismatched or unreadable", st.IntegrityFailed))
			if st.IntegrityInconclusive > 0 {
				row("Integrity inconclusive", fmt.Sprintf("%d had nothing to check against (NOT a pass)", st.IntegrityInconclusive))
			}
		}
		// The ceiling statement. Printed whenever archive records verified,
		// including when zero of them carry retention metadata, so nobody
		// reads a green archive line as a retention guarantee.
		fmt.Fprintf(os.Stdout, "    └─ %-22s %s\n", "Retention", retentionLine(res))
	}

	// Certified-copy (21 CFR Part 11 §11.10(b)/(c)) summary. Only printed when
	// the bundle actually carries a certification manifest — an uncertified
	// export is a normal, valid export and prints nothing extra. "OK" here
	// means every certification-level check that ran actually passed. It does
	// NOT mean every possible check ran: a manifest may omit bundle_sha256 or
	// individual record_counts fields (tolerated for older/hand-built
	// manifests — see checkCertificationCounts/checkCertificationBundleHash),
	// and a skipped check must never be reported as a verified one
	// (atlasent-verify#28 follow-up) — the summary line below names exactly
	// what was checked and calls out anything that was declared-absent and
	// therefore skipped. When the outer envelope signature itself is
	// invalid, Verify returns before any certification check ever runs (a
	// certification manifest rides the same signature as every other
	// section), so this is reported as FAIL too — never a false "OK" for a
	// completeness check that was never actually performed.
	if res.CertificationVersion > 0 {
		switch {
		case res.EnvelopeIntegrity == envelope.LayerInvalid:
			fmt.Fprintf(os.Stdout, "[FAIL] Certified copy (v%d) — outer envelope signature invalid; completeness was not checked\n", res.CertificationVersion)
		case hasCertificationFinding(res):
			fmt.Fprintf(os.Stdout, "[FAIL] Certified copy (v%d) — completeness/accuracy check failed (see findings below)\n", res.CertificationVersion)
		default:
			fmt.Fprintf(os.Stdout, "[OK  ] Certified copy (v%d) — %s\n", res.CertificationVersion, certificationSummaryDetail(res))
		}
	}

	for _, f := range res.Findings {
		if f.Record != "" {
			fmt.Fprintf(os.Stdout, "  ! %s [%s]: %s\n", f.Code, f.Record, f.Detail)
		} else {
			fmt.Fprintf(os.Stdout, "  ! %s: %s\n", f.Code, f.Detail)
		}
	}

	if res.OK() {
		if res.EnvelopeIntegrity == envelope.LayerUntrustedKey {
			fmt.Fprintln(os.Stdout, "ok: verified against the envelope's embedded key — supply --keys to anchor trust externally")
		} else {
			fmt.Fprintln(os.Stdout, "ok: audit export verified")
		}
	} else {
		fmt.Fprintf(os.Stderr, "\nfound %d issue(s)\n", len(res.Findings))
	}
}

// hasCertificationFinding reports whether any finding is a certification-
// level failure (record-count census mismatch, bundle_sha256 mismatch, or an
// unsupported certification version). Matched by code prefix rather than an
// exhaustive list so a future CERTIFICATION_* code is picked up automatically.
func hasCertificationFinding(res *envelope.VerificationResult) bool {
	for _, f := range res.Findings {
		if strings.HasPrefix(string(f.Code), "CERTIFICATION_") {
			return true
		}
	}
	return false
}

// allCertificationCountSections is every record_counts field
// checkCertificationCounts knows how to compare, in report order. Used only
// to say how many of the possible sections were actually declared/checked —
// not every bundle carries all of them (an older manifest has no
// protection_configurations count at all, for example).
var allCertificationCountSections = []string{
	"evaluations", "verification_events", "correlation_events",
	"retrieval_events", "probe_events", "protection_configurations",
}

// certificationSummaryDetail builds the OK-line detail for a certification
// manifest with no findings. It must never claim a check ran when it was
// actually skipped because the manifest declared no value for it
// (atlasent-verify#28 follow-up: a skipped check is not a verified one).
func certificationSummaryDetail(res *envelope.VerificationResult) string {
	checked := len(res.CertificationCountsChecked)
	total := len(allCertificationCountSections)
	var countsPart string
	if checked == total {
		countsPart = "record counts verified"
	} else if checked == 0 {
		countsPart = "record counts not declared, not checked"
	} else {
		countsPart = fmt.Sprintf("record counts verified for %d/%d declared section(s)", checked, total)
	}

	var hashPart string
	if res.CertificationBundleHashChecked {
		hashPart = "bundle_sha256 verified"
	} else {
		hashPart = "bundle_sha256 not declared, not checked"
	}

	return countsPart + "; " + hashPart
}

// retentionLine states exactly what this tool can say about retention, and no
// more. The verifier is offline by contract — it never contacts an object
// store — so exported retention metadata is a claim the producer recorded, not
// evidence a lock exists on real storage. There is deliberately no branch here
// that reports retention as verified.
func retentionLine(res *envelope.VerificationResult) string {
	switch res.RetentionAssurance {
	case envelope.RetentionRecordedNotVerified:
		return fmt.Sprintf("%d record(s) carry provider-confirmed retention metadata — RECORDED, not verified by this tool (offline: no object store is contacted)",
			res.ArchiveRetentionRecords)
	case envelope.RetentionNotRecorded:
		return "no retention metadata recorded on these archive records — this export does NOT evidence a retention term"
	default:
		return "not applicable (no archive records)"
	}
}

// stageMark renders a lifecycle-stage marker. A stage is "OK" only when every
// verified correlation evidences it; otherwise "~~" flags a partial stage
// (surfaced, never hidden).
func stageMark(full bool) string {
	if full {
		return "OK  "
	}
	return "~~  "
}

func trustLabel(trusted bool) string {
	if trusted {
		return "trusted key"
	}
	return "embedded key — trust NOT externally anchored"
}

// runNDJSON is the original per-row audit-chain verification path, unchanged.
func runNDJSON(raw []byte, ks chain.KeyStore, headPath string, requireSigs bool) {
	res, err := chain.Verify(bytes.NewReader(raw), ks)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: verify: %v\n", err)
		os.Exit(2)
	}

	// Completeness / anti-truncation: compare the verified per-org head
	// against an out-of-band trusted anchor, if one was supplied.
	var anchors chain.AnchorSet
	if headPath != "" {
		hf, err := os.Open(headPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: open head anchor: %v\n", err)
			os.Exit(2)
		}
		anchors, err = chain.ParseAnchors(hf)
		hf.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		chain.CheckAnchors(res, anchors)
	}

	for _, w := range res.Warnings {
		fmt.Fprintf(os.Stderr, "warn: L%d org=%s seq=%d %s: %s\n",
			w.LineNumber, w.OrgID, w.Sequence, w.Kind, w.Detail)
	}

	if len(res.Findings) == 0 {
		fmt.Fprintf(os.Stdout, "ok: %d entries verified across %d org(s)\n",
			res.EntriesScanned, len(res.HeadByOrg))
		if anchors != nil {
			fmt.Fprintf(os.Stdout, "ok: %d/%d anchored head(s) match — no tail truncation\n",
				chain.AnchoredOrgs(res, anchors), len(anchors))
		} else {
			fmt.Fprintln(os.Stderr, "note: --head not supplied; tail-truncation / completeness was not checked")
		}
		if ks == nil {
			fmt.Fprintln(os.Stderr, "note: --keys not supplied; signature verification was skipped")
		} else {
			fmt.Fprintf(os.Stdout, "ok: %d signature(s) verified", res.SignaturesVerified)
			if res.SignaturesSkipped > 0 {
				fmt.Fprintf(os.Stdout, ", %d skipped (key_version not in keystore)", res.SignaturesSkipped)
			}
			fmt.Fprintln(os.Stdout)
		}

		if requireSigs {
			ok, reason := res.StrictSignatureAcceptance(ks != nil)
			if !ok {
				fmt.Fprintf(os.Stdout, "NOT ACCEPTED (--require-signatures): %s\n", reason)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stdout, "ACCEPTED (--require-signatures): %s\n", reason)
		}
		return
	}

	for _, f := range res.Findings {
		fmt.Fprintf(os.Stdout, "L%d org=%s seq=%d %s: %s\n",
			f.LineNumber, f.OrgID, f.Sequence, f.Kind, f.Detail)
	}
	fmt.Fprintf(os.Stderr, "\nfound %d issue(s) across %d entries scanned\n",
		len(res.Findings), res.EntriesScanned)
	os.Exit(1)
}
