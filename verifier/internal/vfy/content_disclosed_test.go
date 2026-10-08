package vfy

// Tests for section 4.18 (CONTENT_DISCLOSED, spec change S1b):
//
//   - a valid disclosure entry with its immediate checkpoint is NOT a finding
//     (exit 0, no class at all — unlike CONTENT_DELETED, which draws a note);
//   - the type is critical: without the immediate checkpoint the verdict is
//     MISSING_CHECKPOINT (exit 2), like every other critical type;
//   - the payload contract is strict: reason outside the enum, a missing
//     field, or a negative byte count is FORMAT_ERROR (exit 3).
//
// Red without the S1b mirror in schema.go: the type is unknown to the
// verifier, so the valid chain draws UNKNOWN_ENTRY_TYPE (exit 1) instead of
// exit 0, the unanchored chain draws no MISSING_CHECKPOINT (10.6 R2: an
// unknown type is not critical), and the malformed payloads pass unchecked
// (10.6 R2: only "payload is an object" is required of an unknown type).
// TestContentDisclosedNoContentDeletedFinding is a control, green in both
// states: it pins that the CONTENT_DELETED note is never drawn for a
// disclosure.

import (
	"strings"
	"testing"
	"time"
)

// disclosedPayload is the valid CONTENT_DISCLOSED payload of these tests;
// mutate edits a copy before it is chained.
func disclosedPayload(mutate func(map[string]any)) map[string]any {
	p := map[string]any{
		"target_seq":     int64(4),
		"vault_ref":      "vault/seg-1/4",
		"actor":          "pruefer",
		"role":           "aufsicht",
		"reason":         "audit",
		"request_bytes":  int64(120),
		"response_bytes": int64(480),
	}
	if mutate != nil {
		mutate(p)
	}
	return p
}

// disclosedChain builds GENESIS, CP, RECEIPT, an AI_CALL (seq 4) whose content
// is later disclosed, the CONTENT_DISCLOSED entry (seq 5), optionally its
// immediate checkpoint, and keeps the chain running so the entry is never the
// terminal one. The chain ends sealed (spec 8.6), so the verdicts below are
// exactly those of the disclosure entry and not joined by UNSEALED_END.
func disclosedChain(t *testing.T, mutate func(map[string]any), anchored bool) *gen {
	t.Helper()
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.aiCall(time.Minute, strings.Repeat("a", 64), strings.Repeat("b", 64))     // seq 4
	g.add(time.Minute, "CONTENT_DISCLOSED", "portal", disclosedPayload(mutate)) // seq 5
	if anchored {
		g.checkpoint(time.Second)
	}
	g.tick(time.Minute)
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.seal("shutdown")
	return g
}

func TestContentDisclosedValidIsGreen(t *testing.T) {
	res := verifyGen(disclosedChain(t, nil, true), Options{})
	wantClasses(t, res, 0)
	if len(res.Findings) != 0 {
		t.Errorf("a disclosure is not a finding; got %+v", res.Findings)
	}
	if !res.Valid {
		t.Error("chain with a valid CONTENT_DISCLOSED must be valid")
	}
}

func TestContentDisclosedWithoutCheckpointIsMissingCheckpoint(t *testing.T) {
	res := verifyGen(disclosedChain(t, nil, false), Options{})
	wantClasses(t, res, 2, ClsMissingCheckpoint)
	fs := findingsOf(res, ClsMissingCheckpoint)
	if len(fs) != 1 || fs[0].Seq != 5 {
		t.Errorf("want one MISSING_CHECKPOINT at seq 5, got %+v", fs)
	}
}

func TestContentDisclosedReasonOutsideEnumIsFormatError(t *testing.T) {
	res := verifyGen(disclosedChain(t, func(p map[string]any) { p["reason"] = "neugier" }, true), Options{})
	wantClasses(t, res, 3, ClsFormatError)
}

func TestContentDisclosedMissingFieldIsFormatError(t *testing.T) {
	res := verifyGen(disclosedChain(t, func(p map[string]any) { delete(p, "role") }, true), Options{})
	wantClasses(t, res, 3, ClsFormatError)
}

func TestContentDisclosedNegativeBytesIsFormatError(t *testing.T) {
	for _, field := range []string{"request_bytes", "response_bytes"} {
		t.Run(field, func(t *testing.T) {
			res := verifyGen(disclosedChain(t, func(p map[string]any) { p[field] = int64(-1) }, true), Options{})
			wantClasses(t, res, 3, ClsFormatError)
		})
	}
}

// A disclosure must not be mistaken for a deletion: the CONTENT_DELETED note
// belongs to CONTENT_DELETED entries only.
func TestContentDisclosedNoContentDeletedFinding(t *testing.T) {
	res := verifyGen(disclosedChain(t, nil, true), Options{})
	if len(findingsOf(res, ClsContentDeleted)) != 0 {
		t.Errorf("CONTENT_DELETED note drawn for a disclosure: %+v", res.Findings)
	}
}
