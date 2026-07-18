// Command atlasent-audit-verify validates an AtlaSent audit-chain
// export per ADR-020. Read-only, no network, no DB.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/atlasent-systems-inc/atlasent-verify/internal/chain"
	"github.com/atlasent-systems-inc/atlasent-verify/internal/keys"
)

// Version is stamped at build time via -ldflags
// "-X main.Version=<version>". The chain-version supported is
// hard-coded; bumping it is the canonical-form-spec version bump.
var Version = "v0.0.0-dev"

const supportedChainVersion = 5

func main() {
	chainPath := flag.String("chain", "", "Path to NDJSON chain export (required, '-' for stdin)")
	keysPath := flag.String("keys", "", "Path to PEM file of Ed25519 public keys (optional; signature verification skipped if absent)")
	headPath := flag.String("head", "", "Path to a trusted head-anchor JSON file (optional; tail-truncation / completeness check skipped if absent)")
	requireSigs := flag.Bool("require-signatures", false, "Strict acceptance: fail (exit 1) unless EVERY entry's signature was verified against a known key. Requires --keys. Turns a skipped signature (unknown key_version) into a failure instead of a warning, so exit 0 positively proves the correct key was loaded and no signature was skipped.")
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

	var r io.Reader
	if *chainPath == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(*chainPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: open chain: %v\n", err)
			os.Exit(2)
		}
		defer f.Close()
		r = f
	}

	if *requireSigs && *keysPath == "" {
		fmt.Fprintln(os.Stderr, "error: --require-signatures requires --keys (there is nothing to verify signatures against)")
		os.Exit(2)
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

	res, err := chain.Verify(r, ks)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: verify: %v\n", err)
		os.Exit(2)
	}

	// Completeness / anti-truncation: compare the verified per-org head
	// against an out-of-band trusted anchor, if one was supplied. Hash
	// continuity alone cannot catch a tail truncation — a dropped suffix
	// is still an internally-valid chain — so this is the only check
	// that detects entries silently removed from the end.
	var anchors chain.AnchorSet
	if *headPath != "" {
		hf, err := os.Open(*headPath)
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

	// Print warnings (non-fatal: unknown key versions, etc.).
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
			// Report signature coverage explicitly so a green run is
			// self-describing: how many signatures were actually checked,
			// and how many were skipped because their key was not loaded.
			fmt.Fprintf(os.Stdout, "ok: %d signature(s) verified", res.SignaturesVerified)
			if res.SignaturesSkipped > 0 {
				fmt.Fprintf(os.Stdout, ", %d skipped (key_version not in keystore)", res.SignaturesSkipped)
			}
			fmt.Fprintln(os.Stdout)
		}

		// Strict acceptance: exit-0 must positively prove every entry was
		// signature-verified against a known key. A chain that verified on
		// hash continuity alone but skipped every signature is NOT pilot
		// evidence and fails here.
		if *requireSigs {
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
