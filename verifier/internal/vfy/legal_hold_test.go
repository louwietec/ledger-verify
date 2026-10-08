package vfy

// Tests for spec 1.7: the critical entry type LEGAL_HOLD (section 4.24) and
// the finding HOLD_VIOLATION (section 9.3, exit 1).
//
// What these tests hold the implementation to:
//   - a hold is active from its LEGAL_HOLD set until a release with the same
//     hold_id; a further set of an active hold_id replaces its scope; a
//     release without an active hold of that id has no effect and no finding;
//   - a hold covers an AI_CALL whose ts_captured lies in [scope_from,
//     scope_to], both bounds inclusive, compared as points in time; the
//     unbounded sentinels 0001-01-01T00:00:00Z / 9999-12-31T23:59:59Z work;
//   - HOLD_VIOLATION is a CONTENT_DELETED whose target_seq names an AI_CALL
//     covered by a hold active AT THE POSITION of the deletion — reported
//     once per deletion at its seq, naming target_seq and every covering
//     hold_id; a target that is no AI_CALL (or no entry) draws none;
//   - LEGAL_HOLD is critical: without its immediate checkpoint mid-chain it is
//     MISSING_CHECKPOINT (exit 2); its payload is strict (FORMAT_ERROR);
//   - stats.legal_holds lists the holds active at the chain end, and the text
//     report names them under "Legal hold active:" / "Legal Hold aktiv:".
//
// Every chain here ends sealed (g.seal, spec 8.6), so the verdict is exactly
// the one of the case under test and not joined by UNSEALED_END.
//
// Red against the 1.6 verifier: LEGAL_HOLD is an unknown type there
// (UNKNOWN_ENTRY_TYPE, not critical, payload unchecked) and HOLD_VIOLATION
// does not exist. The red proofs by mutation of this implementation are listed
// in the commit message.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The unbounded scope values of spec 4.24.
const (
	holdUnboundedFrom = "0001-01-01T00:00:00Z"
	holdUnboundedTo   = "9999-12-31T23:59:59Z"
)

// The capture time of the AI_CALL most tests delete, and a scope around it.
// The generator clock (ts_chained) starts on 2026-08-01; the AI_CALLs here are
// captured earlier on purpose — spec 9.3 judges ts_captured, not ts_chained.
const (
	tsCall      = "2026-07-20T12:00:00Z"
	scopeJulyLo = "2026-07-01T00:00:00Z"
	scopeJulyHi = "2026-07-31T23:59:59Z"
)

// holdBase opens a chain for the hold tests: GENESIS, its checkpoint and a
// receipt on it (so the chain is anchored and draws no NO_ANCHOR).
func holdBase(t *testing.T) *gen {
	t.Helper()
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	return g
}

// aiCallCaptured writes an AI_CALL whose ts_captured is the given instant
// (ts_chained stays the generator clock) and returns its seq.
func (g *gen) aiCallCaptured(tsCaptured string) int64 {
	g.extraEnv = map[string]any{"ts_captured": tsCaptured}
	g.aiCall(time.Minute, nil, nil)
	g.extraEnv = nil
	return g.seq
}

// legalHold writes a LEGAL_HOLD with its immediate checkpoint (spec 6.2) and
// returns the seq of the LEGAL_HOLD.
func (g *gen) legalHold(action, id, from, to, ref string) int64 {
	g.add(time.Minute, "LEGAL_HOLD", "portal", map[string]any{
		"action": action, "hold_id": id, "scope_from": from, "scope_to": to,
		"reference": ref, "actor": "admin",
	})
	s := g.seq
	g.checkpoint(time.Second)
	return s
}

// contentDeleted writes a CONTENT_DELETED on target with its immediate
// checkpoint and returns the seq of the CONTENT_DELETED.
func (g *gen) contentDeleted(target int64) int64 {
	g.add(time.Minute, "CONTENT_DELETED", "portal", map[string]any{
		"target_seq": target, "vault_ref": "vault/1", "reason": "retention", "actor": "admin",
	})
	s := g.seq
	g.checkpoint(time.Second)
	return s
}

// verifySealed seals the chain (spec 8.6) and verifies it.
func verifySealed(g *gen) Result {
	g.seal("shutdown")
	return verifyGen(g, Options{})
}

// onlyHoldViolation returns the single HOLD_VIOLATION, failing unless there is
// exactly one and it sits at the seq of the deletion.
func onlyHoldViolation(t *testing.T, res Result, delSeq int64) Finding {
	t.Helper()
	fs := findingsOf(res, ClsHoldViolation)
	if len(fs) != 1 {
		t.Fatalf("want HOLD_VIOLATION exactly once, got %d: %+v", len(fs), res.Findings)
	}
	if fs[0].Seq != delSeq {
		t.Errorf("HOLD_VIOLATION at seq %d, want the CONTENT_DELETED's seq %d", fs[0].Seq, delSeq)
	}
	return fs[0]
}

// --- the violation and its controls -------------------------------------------

// A hold covers the deleted AI_CALL: exit 1 with CONTENT_DELETED and
// HOLD_VIOLATION, the latter at the deletion's seq naming hold_id and
// target_seq (spec 9.3).
func TestHoldCoversTargetIsViolation(t *testing.T) {
	g := holdBase(t)
	call := g.aiCallCaptured(tsCall)
	set := g.legalHold("set", "H-1", scopeJulyLo, scopeJulyHi, "Az 4 O 12/26")
	del := g.contentDeleted(call)
	res := verifySealed(g)
	wantClasses(t, res, 1, ClsContentDeleted, ClsHoldViolation)
	f := onlyHoldViolation(t, res, del)
	for _, w := range []string{
		fmt.Sprintf("target_seq=%d", call),
		`hold_id="H-1"`,
		fmt.Sprintf(`"H-1" set at seq %d, scope %s..%s`, set, scopeJulyLo, scopeJulyHi),
		`reference "Az 4 O 12/26"`,
		"ts_captured " + tsCall,
	} {
		if !strings.Contains(f.Detail, w) {
			t.Errorf("detail lacks %q: %s", w, f.Detail)
		}
	}
	if !res.Valid || res.Status != "valid" {
		t.Errorf("HOLD_VIOLATION is exit class 1, the chain stays valid: valid=%v status=%s", res.Valid, res.Status)
	}
}

// The hold is active, but the AI_CALL lies outside its scope — before it and
// after it. Only the CONTENT_DELETED note remains.
func TestHoldTargetOutsideScope(t *testing.T) {
	for _, c := range []struct{ name, lo, hi string }{
		{"scope_after_call", "2026-07-21T00:00:00Z", scopeJulyHi},
		{"scope_before_call", scopeJulyLo, "2026-07-19T23:59:59Z"},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := holdBase(t)
			call := g.aiCallCaptured(tsCall)
			g.legalHold("set", "H-1", c.lo, c.hi, "case")
			g.contentDeleted(call)
			wantClasses(t, verifySealed(g), 1, ClsContentDeleted)
		})
	}
}

// Deletion after the hold was released: no violation.
func TestHoldDeleteAfterRelease(t *testing.T) {
	g := holdBase(t)
	call := g.aiCallCaptured(tsCall)
	g.legalHold("set", "H-1", scopeJulyLo, scopeJulyHi, "case")
	g.legalHold("release", "H-1", scopeJulyLo, scopeJulyHi, "case closed")
	g.contentDeleted(call)
	res := verifySealed(g)
	wantClasses(t, res, 1, ClsContentDeleted)
	if len(res.Stats.LegalHolds) != 0 {
		t.Errorf("released hold still listed as active: %+v", res.Stats.LegalHolds)
	}
}

// Deletion before the hold was set: the hold state counts at the position of
// the CONTENT_DELETED, not at the chain end — no violation, although the hold
// covering the call is active when the chain ends.
func TestHoldDeleteBeforeSet(t *testing.T) {
	g := holdBase(t)
	call := g.aiCallCaptured(tsCall)
	g.contentDeleted(call)
	g.legalHold("set", "H-1", scopeJulyLo, scopeJulyHi, "case")
	res := verifySealed(g)
	wantClasses(t, res, 1, ClsContentDeleted)
	if len(res.Stats.LegalHolds) != 1 {
		t.Errorf("the hold is active at the chain end and must be listed: %+v", res.Stats.LegalHolds)
	}
}

// Both bounds are inclusive, and they are compared as points in time
// (spec 9.3, 2): a capture time written with fractional seconds is the same
// instant as the bound without them. One millisecond outside is outside.
func TestHoldScopeBoundsInclusive(t *testing.T) {
	for _, c := range []struct {
		name, lo, hi, captured string
		violation              bool
	}{
		{"ts_equals_scope_from", tsCall, scopeJulyHi, tsCall, true},
		{"ts_equals_scope_to", scopeJulyLo, tsCall, tsCall, true},
		{"scope_of_one_instant", tsCall, tsCall, tsCall, true},
		{"fraction_equals_scope_from", tsCall, scopeJulyHi, "2026-07-20T12:00:00.000Z", true},
		{"fraction_equals_scope_to", scopeJulyLo, "2026-07-20T12:00:00.000000Z", tsCall, true},
		{"one_ms_before_scope_from", tsCall, scopeJulyHi, "2026-07-20T11:59:59.999Z", false},
		{"one_ms_after_scope_to", scopeJulyLo, tsCall, "2026-07-20T12:00:00.001Z", false},
		// Literal reading: a scope whose scope_from lies after its scope_to
		// covers no instant (9.3 makes it no finding of its own).
		{"inverted_scope_covers_nothing", scopeJulyHi, scopeJulyLo, tsCall, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := holdBase(t)
			call := g.aiCallCaptured(c.captured)
			g.legalHold("set", "H-1", c.lo, c.hi, "case")
			del := g.contentDeleted(call)
			res := verifySealed(g)
			if c.violation {
				wantClasses(t, res, 1, ClsContentDeleted, ClsHoldViolation)
				onlyHoldViolation(t, res, del)
			} else {
				wantClasses(t, res, 1, ClsContentDeleted)
			}
		})
	}
}

// The unbounded sentinels of spec 4.24 are ordinary bounds: a hold over
// 0001-01-01T00:00:00Z..9999-12-31T23:59:59Z covers every capture time the
// format can carry, the extreme ones included; a half-bounded scope stays
// bounded on its other side.
func TestHoldUnboundedSentinels(t *testing.T) {
	for _, c := range []struct {
		name, lo, hi, captured string
		violation              bool
	}{
		{"unbounded_covers_ordinary", holdUnboundedFrom, holdUnboundedTo, tsCall, true},
		{"unbounded_covers_earliest", holdUnboundedFrom, holdUnboundedTo, holdUnboundedFrom, true},
		{"unbounded_covers_latest", holdUnboundedFrom, holdUnboundedTo, holdUnboundedTo, true},
		{"open_start_covers", holdUnboundedFrom, scopeJulyHi, tsCall, true},
		{"open_end_covers", scopeJulyLo, holdUnboundedTo, tsCall, true},
		{"open_start_bounded_end", holdUnboundedFrom, "2026-07-19T23:59:59Z", tsCall, false},
		{"open_end_bounded_start", "2026-07-21T00:00:00Z", holdUnboundedTo, tsCall, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := holdBase(t)
			call := g.aiCallCaptured(c.captured)
			g.legalHold("set", "H-ALL", c.lo, c.hi, "case")
			del := g.contentDeleted(call)
			res := verifySealed(g)
			if c.violation {
				wantClasses(t, res, 1, ClsContentDeleted, ClsHoldViolation)
				onlyHoldViolation(t, res, del)
			} else {
				wantClasses(t, res, 1, ClsContentDeleted)
			}
		})
	}
}

// Two holds cover the same AI_CALL: ONE finding for the one deletion, naming
// both hold_ids; a third active hold that does not cover it is not named.
func TestHoldTwoHoldsOneFinding(t *testing.T) {
	g := holdBase(t)
	call := g.aiCallCaptured(tsCall)
	s1 := g.legalHold("set", "H-1", scopeJulyLo, scopeJulyHi, "case 1")
	g.legalHold("set", "H-OTHER", "2026-09-01T00:00:00Z", holdUnboundedTo, "case 3")
	s2 := g.legalHold("set", "H-2", holdUnboundedFrom, holdUnboundedTo, "case 2")
	del := g.contentDeleted(call)
	res := verifySealed(g)
	wantClasses(t, res, 1, ClsContentDeleted, ClsHoldViolation)
	f := onlyHoldViolation(t, res, del)
	for _, w := range []string{
		fmt.Sprintf("target_seq=%d", call),
		`hold_id="H-1","H-2"`,
		"2 active holds",
		fmt.Sprintf(`"H-1" set at seq %d`, s1),
		fmt.Sprintf(`"H-2" set at seq %d`, s2),
	} {
		if !strings.Contains(f.Detail, w) {
			t.Errorf("detail lacks %q: %s", w, f.Detail)
		}
	}
	if strings.Contains(f.Detail, "H-OTHER") {
		t.Errorf("a hold that does not cover the call is named: %s", f.Detail)
	}
	// Two deletions under the same hold are two findings — one per deletion.
	g2 := holdBase(t)
	a := g2.aiCallCaptured(tsCall)
	b := g2.aiCallCaptured("2026-07-21T08:00:00Z")
	g2.legalHold("set", "H-1", scopeJulyLo, scopeJulyHi, "case")
	d1 := g2.contentDeleted(a)
	d2 := g2.contentDeleted(b)
	fs := findingsOf(verifySealed(g2), ClsHoldViolation)
	if len(fs) != 2 || fs[0].Seq != d1 || fs[1].Seq != d2 {
		t.Errorf("want one HOLD_VIOLATION per deletion at seq %d and %d, got %+v", d1, d2, fs)
	}
}

// A further set of an active hold_id replaces its scope (spec 9.3): it neither
// keeps the old scope alongside nor starts a second hold that a single
// release would leave behind.
func TestHoldResetReplacesScope(t *testing.T) {
	t.Run("narrowed_away_from_call", func(t *testing.T) {
		g := holdBase(t)
		call := g.aiCallCaptured(tsCall)
		g.legalHold("set", "H-1", scopeJulyLo, scopeJulyHi, "case")
		g.legalHold("set", "H-1", "2026-08-01T00:00:00Z", "2026-08-31T23:59:59Z", "case")
		g.contentDeleted(call)
		wantClasses(t, verifySealed(g), 1, ClsContentDeleted)
	})
	t.Run("widened_onto_call", func(t *testing.T) {
		g := holdBase(t)
		call := g.aiCallCaptured(tsCall)
		set := g.legalHold("set", "H-1", "2026-08-01T00:00:00Z", "2026-08-31T23:59:59Z", "case")
		reset := g.legalHold("set", "H-1", scopeJulyLo, scopeJulyHi, "case")
		del := g.contentDeleted(call)
		res := verifySealed(g)
		wantClasses(t, res, 1, ClsContentDeleted, ClsHoldViolation)
		f := onlyHoldViolation(t, res, del)
		w := fmt.Sprintf(`"H-1" set at seq %d, scope %s..%s (scope replaced at seq %d)`, set, scopeJulyLo, scopeJulyHi, reset)
		if !strings.Contains(f.Detail, w) {
			t.Errorf("detail lacks %q: %s", w, f.Detail)
		}
	})
	t.Run("one_release_ends_the_reset_hold", func(t *testing.T) {
		g := holdBase(t)
		call := g.aiCallCaptured(tsCall)
		g.legalHold("set", "H-1", scopeJulyLo, scopeJulyHi, "case")
		g.legalHold("set", "H-1", holdUnboundedFrom, holdUnboundedTo, "case")
		g.legalHold("release", "H-1", holdUnboundedFrom, holdUnboundedTo, "case")
		g.contentDeleted(call)
		res := verifySealed(g)
		wantClasses(t, res, 1, ClsContentDeleted)
		if len(res.Stats.LegalHolds) != 0 {
			t.Errorf("a re-set hold survived its release: %+v", res.Stats.LegalHolds)
		}
	})
}

// A release without an active hold of its hold_id has no effect and is no
// finding (spec 9.3): it neither ends another hold, nor pre-empts a later set
// of the same id, nor draws a class of its own.
func TestHoldReleaseUnknownIDNoEffect(t *testing.T) {
	t.Run("alone_no_finding", func(t *testing.T) {
		g := holdBase(t)
		g.legalHold("release", "H-NEVER", holdUnboundedFrom, holdUnboundedTo, "case")
		res := verifySealed(g)
		wantClasses(t, res, 0)
		if len(res.Findings) != 0 {
			t.Errorf("a release without an active hold is no finding: %+v", res.Findings)
		}
	})
	t.Run("other_hold_stays_active", func(t *testing.T) {
		g := holdBase(t)
		call := g.aiCallCaptured(tsCall)
		g.legalHold("set", "H-1", scopeJulyLo, scopeJulyHi, "case")
		g.legalHold("release", "H-2", scopeJulyLo, scopeJulyHi, "case")
		del := g.contentDeleted(call)
		res := verifySealed(g)
		wantClasses(t, res, 1, ClsContentDeleted, ClsHoldViolation)
		onlyHoldViolation(t, res, del)
	})
	t.Run("release_before_set_does_not_pre_empt", func(t *testing.T) {
		g := holdBase(t)
		call := g.aiCallCaptured(tsCall)
		g.legalHold("release", "H-1", scopeJulyLo, scopeJulyHi, "case")
		g.legalHold("set", "H-1", scopeJulyLo, scopeJulyHi, "case")
		del := g.contentDeleted(call)
		res := verifySealed(g)
		wantClasses(t, res, 1, ClsContentDeleted, ClsHoldViolation)
		onlyHoldViolation(t, res, del)
	})
	t.Run("set_again_after_release", func(t *testing.T) {
		g := holdBase(t)
		call := g.aiCallCaptured(tsCall)
		g.legalHold("set", "H-1", scopeJulyLo, scopeJulyHi, "case")
		g.legalHold("release", "H-1", scopeJulyLo, scopeJulyHi, "case")
		again := g.legalHold("set", "H-1", scopeJulyLo, scopeJulyHi, "case reopened")
		del := g.contentDeleted(call)
		res := verifySealed(g)
		f := onlyHoldViolation(t, res, del)
		if !strings.Contains(f.Detail, fmt.Sprintf(`"H-1" set at seq %d`, again)) {
			t.Errorf("the new hold starts at its new set (seq %d): %s", again, f.Detail)
		}
	})
}

// Only the deletion of an AI_CALL's content is judged (9.3): a target_seq
// naming a TICK or no entry at all draws no HOLD_VIOLATION, even under an
// unbounded hold — the verifier does not validate target_seq (as before 1.7).
func TestHoldTargetNotAICall(t *testing.T) {
	for _, c := range []struct {
		name   string
		target func(g *gen) int64
	}{
		{"tick", func(g *gen) int64 { g.tick(time.Minute); return g.seq }},
		{"genesis", func(g *gen) int64 { return 1 }},
		{"no_such_entry", func(g *gen) int64 { return 999 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := holdBase(t)
			target := c.target(g)
			g.legalHold("set", "H-ALL", holdUnboundedFrom, holdUnboundedTo, "case")
			g.contentDeleted(target)
			wantClasses(t, verifySealed(g), 1, ClsContentDeleted)
		})
	}
}

// Literal reading of 9.3 ("names an AI_CALL"): the target is looked up in the
// whole chain, so an AI_CALL written AFTER the deletion that names it is
// judged like any other — its ts_captured against the holds active at the
// position of the deletion.
func TestHoldTargetLaterInChain(t *testing.T) {
	g := holdBase(t)
	g.legalHold("set", "H-1", scopeJulyLo, scopeJulyHi, "case")
	// seq of the AI_CALL that follows the deletion and its checkpoint
	del := g.contentDeleted(g.seq + 3)
	call := g.aiCallCaptured(tsCall)
	if call != del+2 {
		t.Fatalf("test setup: AI_CALL at seq %d, want %d", call, del+2)
	}
	res := verifySealed(g)
	wantClasses(t, res, 1, ClsContentDeleted, ClsHoldViolation)
	onlyHoldViolation(t, res, del)
}

// --- critical type and payload schema --------------------------------------

// LEGAL_HOLD is critical (spec 4, 6.2): followed mid-chain by anything but its
// checkpoint it is MISSING_CHECKPOINT, exit 2, at the LEGAL_HOLD's seq.
func TestLegalHoldWithoutCheckpointIsMissingCheckpoint(t *testing.T) {
	g := holdBase(t)
	g.add(time.Minute, "LEGAL_HOLD", "portal", map[string]any{
		"action": "set", "hold_id": "H-1", "scope_from": scopeJulyLo, "scope_to": scopeJulyHi,
		"reference": "case", "actor": "admin",
	})
	holdSeq := g.seq
	g.tick(time.Minute) // a TICK where the immediate checkpoint belongs
	g.checkpoint(time.Second)
	res := verifySealed(g)
	wantClasses(t, res, 2, ClsMissingCheckpoint)
	fs := findingsOf(res, ClsMissingCheckpoint)
	if len(fs) != 1 || fs[0].Seq != holdSeq {
		t.Errorf("want one MISSING_CHECKPOINT at seq %d, got %+v", holdSeq, fs)
	}
}

// A valid LEGAL_HOLD is a known type: no UNKNOWN_ENTRY_TYPE, no finding at
// all (a hold is no finding, only a broken one is).
func TestLegalHoldValidIsGreen(t *testing.T) {
	g := holdBase(t)
	g.aiCallCaptured(tsCall)
	g.legalHold("set", "H-1", scopeJulyLo, scopeJulyHi, "case")
	res := verifySealed(g)
	wantClasses(t, res, 0)
	if len(res.Findings) != 0 {
		t.Errorf("a hold is no finding: %+v", res.Findings)
	}
}

// The payload is strict like every known type's (spec 2, 10.6 R3).
func TestLegalHoldPayloadStrict(t *testing.T) {
	for _, c := range []struct {
		name   string
		mutate func(p map[string]any)
	}{
		{"action_outside_enum", func(p map[string]any) { p["action"] = "extend" }},
		{"hold_id_too_long", func(p map[string]any) { p["hold_id"] = strings.Repeat("h", 65) }},
		{"reference_too_long", func(p map[string]any) { p["reference"] = strings.Repeat("r", 201) }},
		{"actor_too_long", func(p map[string]any) { p["actor"] = strings.Repeat("a", 129) }},
		{"scope_from_not_utc", func(p map[string]any) { p["scope_from"] = "2026-07-01T02:00:00+02:00" }},
		{"scope_to_date_only", func(p map[string]any) { p["scope_to"] = "2026-07-31" }},
		{"scope_from_year_0000", func(p map[string]any) { p["scope_from"] = "0000-12-31T23:59:59Z" }},
		{"scope_to_null", func(p map[string]any) { p["scope_to"] = nil }},
		{"missing_reference", func(p map[string]any) { delete(p, "reference") }},
		{"undefined_field", func(p map[string]any) { p["expires"] = scopeJulyHi }},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := map[string]any{
				"action": "set", "hold_id": "H-1", "scope_from": scopeJulyLo, "scope_to": scopeJulyHi,
				"reference": "case", "actor": "admin",
			}
			c.mutate(p)
			g := holdBase(t)
			g.add(time.Minute, "LEGAL_HOLD", "portal", p)
			g.checkpoint(time.Second)
			wantClasses(t, verifySealed(g), 3, ClsFormatError)
		})
	}
	// Boundary controls: exactly maxlen is valid.
	g := holdBase(t)
	g.legalHold("set", strings.Repeat("h", 64), scopeJulyLo, scopeJulyHi, strings.Repeat("r", 200))
	wantClasses(t, verifySealed(g), 0)
}

// --- stats.legal_holds and the text report ----------------------------------

// holdStatsChain leaves two holds active at the chain end: H-A (re-set, so its
// scope comes from the later set) and H-C; H-B was released.
func holdStatsChain(t *testing.T) (g *gen, setA, resetA, setC int64) {
	g = holdBase(t)
	setA = g.legalHold("set", "H-A", scopeJulyLo, scopeJulyHi, "Az 1")
	g.legalHold("set", "H-B", holdUnboundedFrom, holdUnboundedTo, "Az 2")
	g.legalHold("release", "H-B", holdUnboundedFrom, holdUnboundedTo, "Az 2")
	setC = g.legalHold("set", "H-C", "2026-08-01T00:00:00Z", holdUnboundedTo, "Az 3")
	resetA = g.legalHold("set", "H-A", "2026-06-01T00:00:00Z", "2026-06-30T23:59:59Z", "Az 1b")
	return g, setA, resetA, setC
}

func TestLegalHoldsInStats(t *testing.T) {
	g, setA, resetA, setC := holdStatsChain(t)
	b, err := RenderJSON(verifySealed(g))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Stats struct {
			LegalHolds []map[string]any `json:"legal_holds"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	want := []map[string]any{
		{"hold_id": "H-A", "scope_from": "2026-06-01T00:00:00Z", "scope_to": "2026-06-30T23:59:59Z",
			"set_seq": float64(setA), "reference": "Az 1", "scope_seq": float64(resetA)},
		{"hold_id": "H-C", "scope_from": "2026-08-01T00:00:00Z", "scope_to": holdUnboundedTo,
			"set_seq": float64(setC), "reference": "Az 3"},
	}
	if fmt.Sprint(m.Stats.LegalHolds) != fmt.Sprint(want) {
		t.Errorf("stats.legal_holds =\n  %v\nwant\n  %v", m.Stats.LegalHolds, want)
	}

	// No active hold at the end: the key is omitted, not an empty list.
	released := holdBase(t)
	released.legalHold("set", "H", scopeJulyLo, scopeJulyHi, "x")
	released.legalHold("release", "H", scopeJulyLo, scopeJulyHi, "x")
	released.seal("shutdown")
	for name, h := range map[string]*gen{"no_hold": validSealedChain(t), "released": released} {
		b, err := RenderJSON(verifyGen(h, Options{}))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "legal_holds") {
			t.Errorf("%s: stats.legal_holds present although no hold is active:\n%s", name, b)
		}
	}

	// A format error is not read as a chain (like chain_end, spec 8.6). A
	// GENESIS at seq > 1 is a FORMAT_ERROR that does not stop the run, so the
	// hold replay does run here and only the exit-3 rule keeps it out.
	g2 := holdBase(t)
	g2.legalHold("set", "H-1", scopeJulyLo, scopeJulyHi, "case")
	g2.genesis()
	g2.checkpoint(time.Second)
	g2.seal("shutdown")
	res := verifyGen(g2, Options{})
	if res.ExitCode != 3 || res.Stats.LegalHolds != nil {
		t.Errorf("format error: exit=%d legal_holds=%+v, want exit 3 without legal_holds", res.ExitCode, res.Stats.LegalHolds)
	}
}

func TestLegalHoldsInTextReport(t *testing.T) {
	g, setA, resetA, setC := holdStatsChain(t)
	call := g.aiCallCaptured("2026-06-15T00:00:00Z")
	del := g.contentDeleted(call)
	res := verifySealed(g)
	wantClasses(t, res, 1, ClsContentDeleted, ClsHoldViolation)

	for _, c := range []struct {
		lang, label, result string
		want                []string
	}{
		{"en", "Legal hold active:", "Result:", []string{
			fmt.Sprintf("%-28s %s", "Legal hold active:",
				fmt.Sprintf(`"H-A": scope 2026-06-01T00:00:00Z to 2026-06-30T23:59:59Z, set at seq %d, reference "Az 1" (scope replaced at seq %d)`, setA, resetA)),
			fmt.Sprintf("%-28s %s", "",
				fmt.Sprintf(`"H-C": scope 2026-08-01T00:00:00Z to 9999-12-31T23:59:59Z, set at seq %d, reference "Az 3"`, setC)),
			fmt.Sprintf("[HOLD_VIOLATION] seq=%d — content deleted despite an active deletion hold (section 9.3)", del),
		}},
		{"de", "Legal Hold aktiv:", "Ergebnis:", []string{
			fmt.Sprintf("%-28s %s", "Legal Hold aktiv:",
				fmt.Sprintf(`"H-A": Umfang 2026-06-01T00:00:00Z bis 2026-06-30T23:59:59Z, gesetzt bei seq %d, Anlass "Az 1" (Umfang ersetzt bei seq %d)`, setA, resetA)),
			fmt.Sprintf("%-28s %s", "",
				fmt.Sprintf(`"H-C": Umfang 2026-08-01T00:00:00Z bis 9999-12-31T23:59:59Z, gesetzt bei seq %d, Anlass "Az 3"`, setC)),
			fmt.Sprintf("[HOLD_VIOLATION] seq=%d — Inhalt trotz aktiver Löschsperre gelöscht (Abschnitt 9.3)", del),
		}},
	} {
		txt := RenderText(res, "pkg", c.lang)
		for _, w := range c.want {
			if !strings.Contains(txt, w+"\n") {
				t.Errorf("%s report lacks line %q:\n%s", c.lang, w, txt)
			}
		}
		if strings.Count(txt, c.label) != 1 {
			t.Errorf("%s report: label %q not exactly once:\n%s", c.lang, c.label, txt)
		}
		if strings.Contains(txt, "MISSING:") || strings.Contains(txt, "%!") {
			t.Errorf("%s report has a missing key or a broken format verb:\n%s", c.lang, txt)
		}
		if i, j := strings.Index(txt, c.label), strings.Index(txt, c.result); i < 0 || j < 0 || i > j {
			t.Errorf("%s report: hold line not before the result line:\n%s", c.lang, txt)
		}
		// Without an active hold there is no such line at all.
		if plain := RenderText(verifyGen(validSealedChain(t), Options{}), "pkg", c.lang); strings.Contains(plain, c.label) {
			t.Errorf("%s report names a hold although none is active:\n%s", c.lang, plain)
		}
	}
}
