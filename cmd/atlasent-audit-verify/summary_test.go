package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/atlasent-systems-inc/atlasent-verify/internal/chain"
)

// TestPrintStageSummary covers the CCAM stage-summary formatting: stages present
// are printed in Decision → Verification → Correlation order, the correlation
// breakdown is deterministic (sorted), and absent stages are omitted.
func TestPrintStageSummary(t *testing.T) {
	res := &chain.Result{
		EventTypeCounts: map[string]int64{
			"evaluation.completed": 3,
			"execution.receipt":    2,
			"execution.correlated": 4,
			"some.other":           9, // not a CCAM stage → must NOT print
		},
		CorrelationByStatus: map[string]int64{
			"MATCH": 3, "NOT_OBSERVED": 1,
		},
	}
	var b bytes.Buffer
	printStageSummary(&b, res)
	out := b.String()

	for _, want := range []string{
		"CCAM stages present:",
		"decision", "3 evaluation.completed",
		"verification", "2 execution.receipt",
		"correlation", "4 execution.correlated",
		"3 MATCH, 1 NOT_OBSERVED", // deterministic sorted breakdown
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q; got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "some.other") {
		t.Errorf("non-CCAM event_type should not appear in the stage summary; got:\n%s", out)
	}

	// Decision must precede verification must precede correlation.
	di, vi, ci := strings.Index(out, "decision"), strings.Index(out, "verification"), strings.Index(out, "correlation")
	if !(di < vi && vi < ci) {
		t.Errorf("stages out of order: decision=%d verification=%d correlation=%d", di, vi, ci)
	}
}

// TestPrintStageSummaryEmpty: no entries → nothing printed (no header).
func TestPrintStageSummaryEmpty(t *testing.T) {
	var b bytes.Buffer
	printStageSummary(&b, &chain.Result{EventTypeCounts: map[string]int64{}})
	if b.Len() != 0 {
		t.Errorf("expected no output for an empty chain; got %q", b.String())
	}
}
