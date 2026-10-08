package vfy

// Tests for section 6.2 trigger 3 (immediate checkpoint after every critical
// entry) and its interaction with the SEAL/RESUME handover of section 8.4.
//
// The obligations these tests hold the implementation to:
//   1. a critical entry followed by an entry other than its checkpoint MUST
//      yield exit 2 and the class MISSING_CHECKPOINT,
//   2. a correctly anchored chain MUST NOT yield the class (false-positive
//      control),
//   3. SEAL + immediate checkpoint + RESUME MUST stay green (the regression
//      that guards against a false red on the handover),
//   4. from spec 1.6: a critical entry that is the LAST entry of the chain is
//      NOT MISSING_CHECKPOINT but an incomplete chain end (UNSEALED_END, exit
//      4, spec 6.2 last paragraph and 8.6).
//
// Where the chain end is not the subject, the chains below end with
// g.seal(...) — SEAL + immediate checkpoint — so that the verdict is exactly
// the one of the case under test and not joined by UNSEALED_END (spec 8.6).

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// hasClass reports whether the result carries the given finding class.
func hasClass(res Result, cls string) bool { return classSet(res)[cls] }

// mustHaveClass / mustNotHaveClass assert membership without pinning the
// remaining classes — used where a scenario unavoidably produces further
// findings (e.g. a GAP always also yields COVERED_GAP).
func mustHaveClass(t *testing.T, res Result, cls string) {
	t.Helper()
	if !hasClass(res, cls) {
		t.Errorf("missing class %s; got exit=%d classes=%v", cls, res.ExitCode, sortedKeys(classSet(res)))
	}
}

func mustNotHaveClass(t *testing.T, res Result, cls string) {
	t.Helper()
	if hasClass(res, cls) {
		t.Errorf("unexpected class %s; got exit=%d findings=%+v", cls, res.ExitCode, res.Findings)
	}
}

// --- 1. the exact-class case ------------------------------------------------

// A MODE_CHANGE without its immediate checkpoint: MODE_CHANGE draws no
// informative finding of its own, so MISSING_CHECKPOINT must be the ONLY class.
func TestMissingCheckpointExactClass(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.add(time.Minute, "MODE_CHANGE", "system", map[string]any{
		"from": "full", "to": "hash_only", "cause": "disk_pressure", "actor": "admin",
	})
	g.tick(time.Minute) // TICK where the immediate checkpoint belongs
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.seal("shutdown") // sealed end: MISSING_CHECKPOINT stays the only class
	res := verifyGen(g, Options{})
	wantClasses(t, res, 2, ClsMissingCheckpoint)
}

// The defect the spec change targets: a SEAL directly followed by its RESUME.
// sealed_entry_hash is correct and the pause stays inside the 450 s tolerance,
// so the missing anchor is the only defect — and it is MISSING_CHECKPOINT, not
// HANDOVER_BROKEN (section 8.4 assigns the two separately).
func TestMissingCheckpointSealDirectlyFollowedByResume(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	sealHash := g.add(time.Minute, "SEAL", "system", map[string]any{
		"version": "1.0.0", "reason": "update",
	})
	g.addMono(90*time.Second, -1, "RESUME", "system", map[string]any{
		"prev_version": "1.0.0", "new_version": "1.1.0",
		"sealed_entry_hash": sealHash,
	})
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.seal("shutdown") // sealed end: the mid-chain defect is judged alone
	res := verifyGen(g, Options{})
	wantClasses(t, res, 2, ClsMissingCheckpoint)
}

// Same chain, but the planned pause now exceeds the silence tolerance. Section
// 8.2 condition 3 anchors coverage on the SEAL's immediate checkpoint, which is
// absent here, so the silence is concealed on top of the missing anchor: two
// independent defects, reported as two.
func TestMissingCheckpointAndConcealedSilenceOnUnanchoredHandover(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	sealHash := g.add(time.Minute, "SEAL", "system", map[string]any{
		"version": "1.0.0", "reason": "update",
	})
	g.addMono(30*time.Minute, -1, "RESUME", "system", map[string]any{
		"prev_version": "1.0.0", "new_version": "1.1.0",
		"sealed_entry_hash": sealHash,
	})
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.seal("shutdown") // sealed end: the two mid-chain defects are judged alone
	res := verifyGen(g, Options{})
	wantClasses(t, res, 2, ClsMissingCheckpoint, ClsConcealedSilence)
}

// --- 2. every critical type, each with its paired control -------------------

// appendCritical writes one entry of the given critical type and returns its
// seq. GENESIS is only legal as the first entry, so the caller opens the chain
// accordingly.
func appendCritical(t *testing.T, g *gen, typ string) {
	t.Helper()
	switch typ {
	case "GENESIS":
		g.genesis()
	case "GAP":
		start := g.now.Format(time.RFC3339)
		g.addAt(g.seq+1, "GAP", "system", -1, map[string]any{
			"reason": "manual", "started_ts": start, "ended_ts": start,
			"lost_count": int64(0), "detail": nil,
		})
	case "MODE_CHANGE":
		g.add(time.Minute, "MODE_CHANGE", "system", map[string]any{
			"from": "full", "to": "hash_only", "cause": "manual", "actor": "admin",
		})
	case "SEAL":
		g.add(time.Minute, "SEAL", "system", map[string]any{
			"version": "1.0.0", "reason": "shutdown",
		})
	case "OVERSIGHT":
		g.add(time.Minute, "OVERSIGHT", "portal", map[string]any{
			"action": "approval", "user": "u1", "role": "reviewer",
			"reference": "case-1", "justification": "checked",
		})
	case "KEY_ROTATION":
		newPriv, newPub := keyFromSeed(7)
		subject := canonGo(t, map[string]any{
			"old_key_id": g.curKey, "new_key_id": "dev-9", "new_pubkey": newPub,
		})
		sig := hex.EncodeToString(ed25519.Sign(g.devPriv[g.curKey], subject))
		g.add(time.Minute, "KEY_ROTATION", "portal", map[string]any{
			"old_key_id": g.curKey, "new_key_id": "dev-9",
			"new_pubkey": newPub, "signature_by_old_key": sig,
		})
		g.devPriv["dev-9"] = newPriv
		g.devPub["dev-9"] = newPub
		g.curKey = "dev-9"
	case "CONTENT_DELETED":
		g.add(time.Minute, "CONTENT_DELETED", "portal", map[string]any{
			"target_seq": int64(1), "vault_ref": "vault/1",
			"reason": "retention", "actor": "admin",
		})
	case "CONTENT_DISCLOSED":
		g.add(time.Minute, "CONTENT_DISCLOSED", "portal", map[string]any{
			"target_seq": int64(1), "vault_ref": "vault/1",
			"actor": "pruefer", "role": "aufsicht", "reason": "audit",
			"request_bytes": int64(10), "response_bytes": int64(20),
		})
	case "LEGAL_HOLD":
		g.add(time.Minute, "LEGAL_HOLD", "portal", map[string]any{
			"action": "set", "hold_id": "H-1",
			"scope_from": holdUnboundedFrom, "scope_to": holdUnboundedTo,
			"reference": "case-1", "actor": "admin",
		})
	default:
		t.Fatalf("unhandled critical type %q", typ)
	}
}

// buildCriticalChain writes a chain containing one entry of typ, either with
// (anchored) or without its immediate checkpoint, and keeps the chain running
// afterwards so the entry is never the terminal one.
func buildCriticalChain(t *testing.T, typ string, anchored bool) *gen {
	t.Helper()
	g := newGen(t)
	if typ != "GENESIS" {
		g.genesis()
		g.checkpoint(time.Second)
	}
	appendCritical(t, g, typ)
	if anchored {
		g.checkpoint(time.Second)
	}
	g.tick(time.Minute)
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	return g
}

// The list is not invented here: it is exactly criticalTypes, which mirrors the
// registry flag critical_checkpoint. Iterating the map itself keeps test and
// implementation tied to the same source — a type added to the registry and
// mirrored into criticalTypes is covered automatically.
func TestMissingCheckpointEveryCriticalType(t *testing.T) {
	if len(criticalTypes) != 9 {
		t.Fatalf("criticalTypes holds %d types, spec 6.2 names 9", len(criticalTypes))
	}
	for typ := range criticalTypes {
		t.Run(typ+"/unanchored", func(t *testing.T) {
			res := verifyGen(buildCriticalChain(t, typ, false), Options{})
			mustHaveClass(t, res, ClsMissingCheckpoint)
			if res.ExitCode != 2 {
				t.Errorf("exit = %d, want 2; findings %+v", res.ExitCode, res.Findings)
			}
		})
		// Paired false-positive control: the identical chain with the immediate
		// checkpoint present must not draw the class.
		t.Run(typ+"/anchored", func(t *testing.T) {
			res := verifyGen(buildCriticalChain(t, typ, true), Options{})
			mustNotHaveClass(t, res, ClsMissingCheckpoint)
		})
	}
}

// Broad false-positive control: the ordinary valid chain, sealed (spec 8.6),
// must stay green and free of the class; unsealed it is incomplete (exit 4),
// and still free of it.
func TestMissingCheckpointAbsentOnValidChain(t *testing.T) {
	res := verifyGen(validSealedChain(t), Options{})
	wantClasses(t, res, 0)
	mustNotHaveClass(t, res, ClsMissingCheckpoint)
	res = verifyGen(validChain(t), Options{})
	wantClasses(t, res, 4, ClsUnsealedEnd)
}

// --- 3. the regression that guards against a false red ----------------------

// SEAL + immediate checkpoint + RESUME is the shape the spec now prescribes and
// the ledger writes. It MUST be green: the checkpoint between SEAL and RESUME
// is the one permitted entry, and the pause it spans is covered silence.
func TestSealCheckpointResumeIsGreen(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	sealHash := g.add(time.Minute, "SEAL", "system", map[string]any{
		"version": "1.0.0", "reason": "update",
	})
	g.checkpoint(time.Second) // the SEAL's immediate checkpoint
	g.addMono(30*time.Minute, -1, "RESUME", "system", map[string]any{
		"prev_version": "1.0.0", "new_version": "1.1.0",
		"sealed_entry_hash": sealHash,
	})
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.seal("update") // and the chain END sealed (spec 8.6): green means no finding at all
	res := verifyGen(g, Options{})
	wantClasses(t, res, 0)
	if len(res.Findings) != 0 {
		t.Errorf("expected no findings, got %+v", res.Findings)
	}
}

// The checkpoint is the ONLY entry permitted in that window (8.4 rule 3). A
// receipt countersigning it is an additional entry and stays HANDOVER_BROKEN.
func TestReceiptBetweenSealAndResumeStaysHandoverBroken(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	sealHash := g.add(time.Minute, "SEAL", "system", map[string]any{
		"version": "1.0.0", "reason": "update",
	})
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second) // additional entry in the sealed window
	g.addMono(5*time.Minute, -1, "RESUME", "system", map[string]any{
		"prev_version": "1.0.0", "new_version": "1.1.0",
		"sealed_entry_hash": sealHash,
	})
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	res := verifyGen(g, Options{})
	mustHaveClass(t, res, ClsHandoverBroken)
	mustNotHaveClass(t, res, ClsMissingCheckpoint) // the checkpoint IS present
}

// --- 4. the edge case: critical entry as the terminal entry -----------------

// Up to spec 1.5 this test pinned the opposite decision: a critical entry at
// the end of the chain without its checkpoint was MISSING_CHECKPOINT (exit 2).
// Spec 1.6 decides the case in 6.2 (last paragraph): no entry is missing
// between two present ones — the chain END is unanchored, which is the status
// "incomplete" of 8.6: UNSEALED_END, exit 4, exactly once, at the last seq.
// The reasoning why this opens no gap is on checkImmediateCheckpoint. What the
// old finding said is kept in the chain-end status
// (last_critical_without_checkpoint), and the paired control — the same
// critical entry followed by a TICK — stays MISSING_CHECKPOINT
// (TestMissingCheckpointEveryCriticalType, .../unanchored).
// 8.5 remains a separate question: inside the freshness window no
// TRAILING_SILENCE.
func TestMissingCheckpointTerminalCriticalEntry(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.add(time.Minute, "MODE_CHANGE", "system", map[string]any{
		"from": "full", "to": "hash_only", "cause": "manual", "actor": "admin",
	})
	res := verifyGen(g, Options{}) // now = +1h, well inside the freshness window
	wantClasses(t, res, 4, ClsUnsealedEnd)
	mustNotHaveClass(t, res, ClsMissingCheckpoint)
	mustNotHaveClass(t, res, ClsTrailingSilence) // 8.5 is a separate question
	if ce := res.Stats.ChainEnd; ce == nil || ce.Status != "incomplete" || !ce.LastCriticalWithoutCheckpoint || ce.LastType != "MODE_CHANGE" {
		t.Errorf("chain end must be incomplete with a terminal critical entry, got %+v", ce)
	}
}

// The same for every critical type, each as the very last entry.
func TestTerminalCriticalEntryEveryTypeIsUnsealedEnd(t *testing.T) {
	for typ := range criticalTypes {
		t.Run(typ, func(t *testing.T) {
			g := newGen(t)
			if typ != "GENESIS" {
				g.genesis()
				g.checkpoint(time.Second)
				g.receiptForLast(time.Second)
			}
			appendCritical(t, g, typ)
			res := verifyGen(g, Options{})
			if res.ExitCode != 4 {
				t.Errorf("exit = %d, want 4; findings %+v", res.ExitCode, res.Findings)
			}
			mustNotHaveClass(t, res, ClsMissingCheckpoint)
			fs := findingsOf(res, ClsUnsealedEnd)
			if len(fs) != 1 || fs[0].Seq != g.seq {
				t.Errorf("want UNSEALED_END exactly once at seq %d, got %+v", g.seq, fs)
			}
			if len(fs) == 1 && !strings.Contains(fs[0].Detail, "critical entry ("+typ+") without its immediate checkpoint") {
				t.Errorf("detail does not say the last entry is a critical entry without checkpoint: %s", fs[0].Detail)
			}
			if ce := res.Stats.ChainEnd; ce == nil || !ce.LastCriticalWithoutCheckpoint {
				t.Errorf("chain_end.last_critical_without_checkpoint not set: %+v", ce)
			}
		})
	}
}

// Up to spec 1.5 the textual anchor of the old decision: 8.4 granted a regular
// closure only to a chain ending with SEAL *plus* immediate checkpoint. That
// half still holds in 1.6 — a terminal SEAL without its checkpoint is not a
// sealed end (8.6) — but it is now the status "incomplete" (UNSEALED_END, exit
// 4), not MISSING_CHECKPOINT (exit 2).
func TestTerminalDecommissionSealNeedsItsCheckpoint(t *testing.T) {
	withCP := newGen(t)
	withCP.genesis()
	withCP.checkpoint(time.Second)
	withCP.receiptForLast(time.Second)
	withCP.add(time.Minute, "SEAL", "system", map[string]any{
		"version": "1.0.0", "reason": "decommission",
	})
	withCP.checkpoint(time.Second)
	withCP.receiptForLast(time.Second)
	wantClasses(t, verifyGen(withCP, Options{}), 0)

	withoutCP := newGen(t)
	withoutCP.genesis()
	withoutCP.checkpoint(time.Second)
	withoutCP.receiptForLast(time.Second)
	withoutCP.add(time.Minute, "SEAL", "system", map[string]any{
		"version": "1.0.0", "reason": "decommission",
	})
	res := verifyGen(withoutCP, Options{})
	wantClasses(t, res, 4, ClsUnsealedEnd)
	if ce := res.Stats.ChainEnd; ce == nil || ce.Status != "incomplete" || ce.SealSeq != 0 {
		t.Errorf("a bare terminal SEAL must not read as sealed: %+v", ce)
	}
}

// --- 5. registry parity -----------------------------------------------------

// The gate that would have caught this defect at its root: the classes the
// verifier can actually report must be exactly the registry's
// verifier.finding_classes, with the same exit codes. Reading the registry here
// is a test-time comparison against the open specification — it introduces no
// runtime dependency and no dependency on appliance/.
func TestFindingClassesMatchRegistry(t *testing.T) {
	path := filepath.Join(repoRoot(t), "spec", "registry.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("registry not readable — spec/registry.json belongs to the repository: %v", err)
	}
	var reg struct {
		Verifier struct {
			FindingClasses map[string]struct {
				Exit int `json:"exit"`
			} `json:"finding_classes"`
		} `json:"verifier"`
	}
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatalf("registry unparsable: %v", err)
	}
	want := reg.Verifier.FindingClasses
	if len(want) == 0 {
		t.Fatal("registry lists no finding classes")
	}
	for cls, spec := range want {
		got, ok := classExit[cls]
		if !ok {
			t.Errorf("registry class %s is not implemented by the verifier", cls)
			continue
		}
		if got != spec.Exit {
			t.Errorf("class %s: exit = %d, registry says %d", cls, got, spec.Exit)
		}
	}
	for cls := range classExit {
		if _, ok := want[cls]; !ok {
			t.Errorf("verifier reports class %s, which the registry does not define", cls)
		}
	}
}
