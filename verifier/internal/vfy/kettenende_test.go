package vfy

// Tests for spec 1.6, section 8.6 (chain end: sealed or incomplete) and the
// exit-code precedence of section 10.3.
//
// What these tests hold the implementation to:
//   - a chain whose last entries are SEAL, its immediate checkpoint and at most
//     receipts on exactly that checkpoint is SEALED, whatever the reason: exit
//     0 without findings (1 with informative ones), and the report names seq,
//     ts_chained and reason of the SEAL;
//   - every other chain is INCOMPLETE: UNSEALED_END exactly once, at the seq of
//     the last entry, also alongside exit-2 findings; a critical entry (a bare
//     SEAL included) as the last entry is no MISSING_CHECKPOINT any more;
//   - SEAL + checkpoint followed by anything but RESUME stays HANDOVER_BROKEN;
//   - the exit code follows the precedence 3 > 2 > 4 > 1 > 0, not the numeric
//     maximum, and the Go list is held against registry.verifier.exit_precedence;
//   - with an incomplete end the verifier names the last countersigned
//     checkpoint (or none) and the comparison with the vendor's most recent
//     countersigned root — and that comparison actually closes the documented
//     gap "truncation at an earlier seal" (spec 11.2).
// Each one is red against the 1.5 verifier: there a sealed update/shutdown
// chain was HANDOVER_BROKEN, an unsealed chain exit 0, a terminal critical
// entry MISSING_CHECKPOINT, and the exit code the numeric maximum.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// cutAfter returns a copy of g holding only its first n entries — the package
// a truncating party would present. now is the generator clock of the copy
// (the time of its last entry), from which verifyGen derives the check time.
func (g *gen) cutAfter(n int, now time.Time) *gen {
	c := *g
	c.lines = append([][]byte(nil), g.lines[:n]...)
	c.hashesRw = append([][]byte(nil), g.hashesRw[:n]...)
	c.seq = int64(n)
	c.now = now
	return &c
}

// onlyUnsealedEnd returns the single UNSEALED_END finding, failing the test
// unless there is exactly one and it sits at the last entry's seq.
func onlyUnsealedEnd(t *testing.T, res Result, lastSeq int64) Finding {
	t.Helper()
	fs := findingsOf(res, ClsUnsealedEnd)
	if len(fs) != 1 {
		t.Fatalf("want UNSEALED_END exactly once, got %d: %+v", len(fs), res.Findings)
	}
	if fs[0].Seq != lastSeq {
		t.Errorf("UNSEALED_END at seq %d, want the last entry's seq %d", fs[0].Seq, lastSeq)
	}
	return fs[0]
}

// --- sealed ends -------------------------------------------------------------

// The shape the ledger writes on shutdown: exit 0 without findings, and the
// chain-end status names the SEAL.
func TestSealedShutdownIsValid(t *testing.T) {
	g := validChain(t) // seq 1..8
	g.seal("shutdown") // SEAL seq 9, CP seq 10
	sealTS := g.now.Add(-time.Second).Format(time.RFC3339)
	res := verifyGen(g, Options{})
	wantClasses(t, res, 0)
	if len(res.Findings) != 0 || !res.Valid {
		t.Fatalf("sealed chain: valid=%v findings=%+v", res.Valid, res.Findings)
	}
	want := ChainEndStat{
		Status: "sealed", LastSeq: 10, LastTS: g.ts(), LastType: "CHECKPOINT",
		SealSeq: 9, SealTS: sealTS, SealReason: "shutdown", SealCheckpointSeq: 10,
	}
	if res.Stats.ChainEnd == nil || *res.Stats.ChainEnd != want {
		t.Errorf("chain_end = %+v, want %+v", res.Stats.ChainEnd, want)
	}
}

// Every SEAL reason closes a chain (spec 8.4, 8.6) — up to 1.5 only
// decommission and key_loss did, update and shutdown were HANDOVER_BROKEN.
// With and without receipts on the seal's checkpoint trailing the end.
func TestSealedEndAnyReason(t *testing.T) {
	for _, reason := range []string{"update", "shutdown", "key_loss", "decommission"} {
		for _, quittungen := range []int{0, 1, 2} {
			t.Run(fmt.Sprintf("%s/%d_receipts", reason, quittungen), func(t *testing.T) {
				g := validChain(t)
				g.seal(reason)
				cpSeq := g.seq
				for i := 0; i < quittungen; i++ {
					g.receipt(time.Second, cpSeq, cpSeq-1, g.merkleRootAt(cpSeq-1))
				}
				res := verifyGen(g, Options{})
				wantClasses(t, res, 0)
				ce := res.Stats.ChainEnd
				if ce == nil || ce.Status != "sealed" || ce.SealReason != reason || ce.SealCheckpointSeq != cpSeq || ce.SealSeq != cpSeq-1 {
					t.Errorf("chain_end = %+v", ce)
				}
			})
		}
	}
}

// The ledger's update path: SEAL(update), its checkpoint, and the vendor's
// receipt on that checkpoint as the last entry. Exit 0, and the receipt on the
// seal's checkpoint is the last countersigned checkpoint.
func TestSealedUpdateWithReceiptOnSealCheckpoint(t *testing.T) {
	g := validChain(t)
	g.seal("update") // SEAL 9, CP 10
	g.receiptForLast(time.Second)
	res := verifyGen(g, Options{})
	wantClasses(t, res, 0)
	lc := res.Stats.LastCountersigned
	want := CountersignStat{ReceiptSeq: 11, CheckpointSeq: 10, TreeSize: 9, MerkleRoot: g.merkleRootAt(9),
		ServerTS: g.ts(), ServerKeyID: "vendor-1", KeyEstablished: true}
	if lc == nil || *lc != want {
		t.Errorf("last_countersigned = %+v, want %+v", lc, want)
	}
}

// Freshness (8.5) applies to a sealed chain too: the seal does not prove it is
// the chain's most recent one. Sealed + stale = exit 1, TRAILING_SILENCE only.
func TestSealedStaleIsTrailingSilence(t *testing.T) {
	g := validSealedChain(t)
	res := verifyGen(g, Options{Now: g.now.Add(48 * time.Hour)})
	wantClasses(t, res, 1, ClsTrailingSilence)
	if !res.Valid || res.Stats.ChainEnd == nil || res.Stats.ChainEnd.Status != "sealed" {
		t.Errorf("sealed stale chain: valid=%v chain_end=%+v", res.Valid, res.Stats.ChainEnd)
	}
}

// --- incomplete ends ---------------------------------------------------------

// An export from a running installation: the chain stops at a TICK.
func TestUnsealedEndWithTick(t *testing.T) {
	g := validChain(t) // 1..8, last receipt at 8 on checkpoint 7 (tree_size 6)
	lastRoot := g.merkleRootAt(6)
	g.tick(time.Minute) // seq 9
	res := verifyGen(g, Options{})
	wantClasses(t, res, 4, ClsUnsealedEnd)
	// Spec 10.3: exit 4 must not be marked invalid in the JSON output;
	// the verdict "incomplete" is carried by Status.
	if !res.Valid || res.Status != "incomplete" {
		t.Errorf("incomplete chain (exit 4): valid=%v status=%q, want true/incomplete", res.Valid, res.Status)
	}
	f := onlyUnsealedEnd(t, res, 9)
	for _, s := range []string{
		"entry seq 9 (TICK, ts_chained " + g.ts() + ")",
		"checkpoint_seq 7, tree_size 6, merkle_root " + lastRoot,
		"chain_id " + g.chainID, "--expect-root", "MERKLE_INCONSISTENT",
	} {
		if !strings.Contains(f.Detail, s) {
			t.Errorf("UNSEALED_END detail lacks %q:\n%s", s, f.Detail)
		}
	}
	if strings.Contains(f.Detail, "critical entry") {
		t.Errorf("a TICK is no critical entry: %s", f.Detail)
	}
	ce := res.Stats.ChainEnd
	if ce == nil || ce.Status != "incomplete" || ce.LastSeq != 9 || ce.LastType != "TICK" || ce.LastTS != g.ts() ||
		ce.LastCriticalWithoutCheckpoint || ce.SealSeq != 0 || ce.SealReason != "" {
		t.Errorf("chain_end = %+v", ce)
	}
}

// A bare critical entry at the end: incomplete, not MISSING_CHECKPOINT (6.2).
func TestUnsealedEndBareCritical(t *testing.T) {
	g := validChain(t)
	g.add(time.Minute, "OVERSIGHT", "portal", map[string]any{
		"action": "approval", "user": "u1", "role": "reviewer",
		"reference": "case-1", "justification": "checked",
	})
	res := verifyGen(g, Options{})
	wantClasses(t, res, 4, ClsUnsealedEnd)
	f := onlyUnsealedEnd(t, res, g.seq)
	if !strings.Contains(f.Detail, "critical entry (OVERSIGHT) without its immediate checkpoint") {
		t.Errorf("detail does not name the unanchored critical entry: %s", f.Detail)
	}
}

// A bare SEAL at the end is not sealed: the checkpoint is part of the seal.
func TestUnsealedEndBareSeal(t *testing.T) {
	for _, reason := range []string{"update", "shutdown", "key_loss", "decommission"} {
		t.Run(reason, func(t *testing.T) {
			g := validChain(t)
			g.add(time.Minute, "SEAL", "system", map[string]any{"version": "1.0.0", "reason": reason})
			res := verifyGen(g, Options{})
			wantClasses(t, res, 4, ClsUnsealedEnd)
			onlyUnsealedEnd(t, res, g.seq)
			if ce := res.Stats.ChainEnd; ce == nil || ce.Status != "incomplete" || !ce.LastCriticalWithoutCheckpoint {
				t.Errorf("chain_end = %+v", ce)
			}
		})
	}
}

// Paired control for the terminal case: the same critical entry followed by a
// non-checkpoint entry in mid-chain stays MISSING_CHECKPOINT (exit 2) — the
// end of this chain is sealed, so it is the only finding.
func TestCriticalFollowedByOtherEntryStaysMissingCheckpoint(t *testing.T) {
	g := validChain(t)
	g.add(time.Minute, "OVERSIGHT", "portal", map[string]any{
		"action": "approval", "user": "u1", "role": "reviewer",
		"reference": "case-1", "justification": "checked",
	})
	g.tick(time.Minute)
	g.checkpoint(time.Second)
	g.seal("shutdown")
	res := verifyGen(g, Options{})
	wantClasses(t, res, 2, ClsMissingCheckpoint)
}

// SEAL + checkpoint followed by anything other than RESUME (or receipts on
// that checkpoint at the very end) stays HANDOVER_BROKEN — and the end is
// incomplete on top: both, exit 2.
func TestSealCheckpointThenEntryIsHandoverBroken(t *testing.T) {
	faelle := map[string]func(g *gen){
		"TICK": func(g *gen) { g.tick(time.Minute) },
		"receipt on the seal checkpoint, then TICK": func(g *gen) {
			g.receiptForLast(time.Second)
			g.tick(time.Minute)
		},
		"trailing receipt on another checkpoint": func(g *gen) {
			g.receipt(time.Second, 7, 6, g.merkleRootAt(6))
		},
	}
	for name, danach := range faelle {
		t.Run(name, func(t *testing.T) {
			g := validChain(t)
			g.seal("shutdown")
			danach(g)
			res := verifyGen(g, Options{})
			wantClasses(t, res, 2, ClsHandoverBroken, ClsUnsealedEnd)
			onlyUnsealedEnd(t, res, g.seq)
		})
	}
}

// --- precedence (spec 10.3) --------------------------------------------------

// An exit-2 finding beside UNSEALED_END: exit 2. The numeric maximum would
// have said 4 — "incomplete" for a chain with concealed silence.
func TestPrecedenceInvalidBeforeIncomplete(t *testing.T) {
	g := validChain(t)
	g.tick(time.Hour) // one silent hour without any declaration
	res := verifyGen(g, Options{})
	wantClasses(t, res, 2, ClsConcealedSilence, ClsUnsealedEnd)
	if res.Valid {
		t.Error("exit 2 must not be valid")
	}
}

// An exit-1 finding beside UNSEALED_END: exit 4.
func TestPrecedenceIncompleteBeforeFindings(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	start := g.now.Format(time.RFC3339)
	g.now = g.now.Add(time.Hour)
	g.addAt(g.seq+1, "GAP", "system", -1, map[string]any{
		"reason": "power_loss", "started_ts": start, "ended_ts": g.ts(),
		"lost_count": int64(-1), "detail": nil,
	})
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	res := verifyGen(g, Options{})
	wantClasses(t, res, 4, ClsCoveredGap, ClsUnsealedEnd)
}

// finish() on bare finding lists: the precedence, independent of any chain.
// The first row is the one the numeric maximum gets wrong.
func TestFinishPrecedenceTable(t *testing.T) {
	for _, c := range []struct {
		klassen []string
		exit    int
		valid   bool // spec 10.3: no manipulation proven (exit 0, 1, 4)
		status  string
	}{
		{[]string{ClsHashMismatch, ClsUnsealedEnd}, 2, false, "invalid"},
		{[]string{ClsUnsealedEnd, ClsHashMismatch}, 2, false, "invalid"},
		{[]string{ClsUnsealedEnd, ClsTrailingSilence}, 4, true, "incomplete"},
		{[]string{ClsTrailingSilence, ClsUnsealedEnd}, 4, true, "incomplete"},
		{[]string{ClsUnsealedEnd}, 4, true, "incomplete"},
		{[]string{ClsTrailingSilence, ClsNoAnchor}, 1, true, "valid"},
		{[]string{ClsHashMismatch, ClsUnsealedEnd, ClsFormatError}, 3, false, "format_error"},
		{[]string{ClsFormatError, ClsUnsealedEnd}, 3, false, "format_error"},
		{nil, 0, true, "valid"},
	} {
		r := &run{}
		for _, k := range c.klassen {
			r.add(k, 1, "x")
		}
		res := r.finish()
		if res.ExitCode != c.exit || res.Valid != c.valid || res.Status != c.status {
			t.Errorf("%v: exit=%d valid=%v status=%q, want exit=%d valid=%v status=%q",
				c.klassen, res.ExitCode, res.Valid, res.Status, c.exit, c.valid, c.status)
		}
	}
}

// The Go precedence and exit codes against the registry — the counterpart of
// TestFindingClassesMatchRegistry for verifier.exit_precedence and
// verifier.exit_codes. Besides the list itself it runs finish() on every
// pair of exit classes and requires the registry's winner: a finish() that
// took the numeric maximum would fail on (2, 4).
func TestExitPrecedenceMatchesRegistry(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "registry.json"))
	if err != nil {
		t.Fatalf("registry not readable — spec/registry.json belongs to the repository: %v", err)
	}
	type text struct {
		DE string `json:"de"`
		EN string `json:"en"`
	}
	var reg struct {
		Verifier struct {
			ExitCodes      map[string]text `json:"exit_codes"`
			ExitPrecedence []int           `json:"exit_precedence"`
			FindingClasses map[string]struct {
				Exit int `json:"exit"`
				text
			} `json:"finding_classes"`
		} `json:"verifier"`
	}
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatalf("registry unparsable: %v", err)
	}
	v := reg.Verifier
	if len(v.ExitPrecedence) == 0 || len(v.ExitCodes) == 0 {
		t.Fatal("registry lists no exit_precedence or no exit_codes")
	}
	if fmt.Sprint(exitPrecedence) != fmt.Sprint(v.ExitPrecedence) {
		t.Errorf("exitPrecedence = %v, registry verifier.exit_precedence = %v", exitPrecedence, v.ExitPrecedence)
	}
	// exit_codes and exit_precedence name the same codes, each once.
	var codes []int
	for k, tx := range v.ExitCodes {
		var c int
		if _, err := fmt.Sscanf(k, "%d", &c); err != nil || fmt.Sprint(c) != k {
			t.Errorf("registry exit code %q is not a number", k)
			continue
		}
		codes = append(codes, c)
		// the report prints exactly the registry's words
		if got := tableEN.get(fmt.Sprintf("exit.%d", c)); got != tx.EN {
			t.Errorf("exit.%d EN = %q, registry says %q", c, got, tx.EN)
		}
		if got := tableDE.get(fmt.Sprintf("exit.%d", c)); got != tx.DE {
			t.Errorf("exit.%d DE = %q, registry says %q", c, got, tx.DE)
		}
	}
	sort.Ints(codes)
	prec := append([]int(nil), exitPrecedence...)
	sort.Ints(prec)
	if fmt.Sprint(codes) != fmt.Sprint(prec) {
		t.Errorf("registry exit_codes %v and the precedence %v name different codes", codes, prec)
	}
	// every exit class a finding can carry takes part in the precedence
	for cls, c := range classExit {
		found := false
		for _, p := range exitPrecedence {
			found = found || p == c
		}
		if !found || c == 0 {
			t.Errorf("class %s has exit class %d, which the precedence does not rank", cls, c)
		}
	}
	// the new class's texts are the registry's
	if u := v.FindingClasses[ClsUnsealedEnd]; tableEN.get("class."+ClsUnsealedEnd) != u.EN || tableDE.get("class."+ClsUnsealedEnd) != u.DE {
		t.Errorf("class.UNSEALED_END texts differ from the registry: %q / %q", tableEN.get("class."+ClsUnsealedEnd), tableDE.get("class."+ClsUnsealedEnd))
	}
	// behaviour: every pair of exit classes, the registry's winner
	rang := map[int]int{}
	for i, c := range v.ExitPrecedence {
		rang[c] = i
	}
	vertreter := map[int]string{}
	var namen []string
	for cls := range classExit {
		namen = append(namen, cls)
	}
	sort.Strings(namen)
	for _, cls := range namen {
		if _, ok := vertreter[classExit[cls]]; !ok {
			vertreter[classExit[cls]] = cls
		}
	}
	for a, ka := range vertreter {
		for b, kb := range vertreter {
			r := &run{}
			r.add(ka, 1, "a")
			r.add(kb, 2, "b")
			want := a
			if rang[b] < rang[a] {
				want = b
			}
			if got := r.finish().ExitCode; got != want {
				t.Errorf("findings %s (exit class %d) + %s (exit class %d): exit %d, registry precedence says %d", ka, a, kb, b, got, want)
			}
		}
	}
}

// --- format error: the chain end is not judged (8.6) -------------------------

// A FORMAT_ERROR that does not stop the run (first entry not GENESIS) still
// makes the package exit 3, and its chain end is not judged: no UNSEALED_END,
// no chain_end, no countersignature named.
func TestFormatErrorChainEndNotJudged(t *testing.T) {
	g := newGen(t)
	g.tick(0) // seq 1 is a TICK, not GENESIS
	g.tick(time.Minute)
	res := verifyGen(g, Options{})
	if res.ExitCode != 3 || !classSet(res)[ClsFormatError] {
		t.Fatalf("want exit 3 FORMAT_ERROR, got %d %+v", res.ExitCode, res.Findings)
	}
	mustNotHaveClass(t, res, ClsUnsealedEnd)
	if res.Stats.ChainEnd != nil || res.Stats.LastCountersigned != nil {
		t.Errorf("chain end judged on a format error: %+v %+v", res.Stats.ChainEnd, res.Stats.LastCountersigned)
	}
	for lang, s := range map[string]string{"de": "nicht bewertet (Formatfehler", "en": "not judged (format error"} {
		if txt := RenderText(res, "pkg", lang); !strings.Contains(txt, s) {
			t.Errorf("%s report does not say the chain end was not judged:\n%s", lang, txt)
		}
	}
}

// --- the last countersigned checkpoint ---------------------------------------

// The largest tree_size counts, not the last receipt written; a receipt whose
// signature does not hold does not count at all; without any receipt there is
// none, the JSON omits the field and the finding says so.
func TestLastCountersignedSelection(t *testing.T) {
	t.Run("largest tree_size, not the last receipt", func(t *testing.T) {
		g := validChain(t)                              // receipt 8 on checkpoint 7 (tree_size 6)
		g.receipt(time.Second, 2, 1, g.merkleRootAt(1)) // late receipt for checkpoint 2 (tree_size 1)
		g.seal("shutdown")
		res := verifyGen(g, Options{})
		wantClasses(t, res, 0)
		if lc := res.Stats.LastCountersigned; lc == nil || lc.CheckpointSeq != 7 || lc.TreeSize != 6 || lc.ReceiptSeq != 8 {
			t.Errorf("last_countersigned = %+v, want checkpoint 7 / tree_size 6 / receipt 8", lc)
		}
	})
	t.Run("a receipt whose signature does not hold is not counted", func(t *testing.T) {
		g := validChain(t)
		g.tick(time.Minute)
		g.checkpoint(time.Second) // seq 10, tree_size 9
		echt := g.vendPriv
		g.vendPriv, _ = keyFromSeed(9) // "receipt" under a foreign key
		g.receiptForLast(time.Second)
		g.vendPriv = echt
		res := verifyGen(g, Options{})
		wantClasses(t, res, 2, ClsReceiptInvalid, ClsUnsealedEnd)
		if lc := res.Stats.LastCountersigned; lc == nil || lc.CheckpointSeq != 7 {
			t.Errorf("last_countersigned = %+v, want the valid receipt on checkpoint 7", lc)
		}
	})
	t.Run("key not established by the auditor", func(t *testing.T) {
		g := validChain(t)
		res := Verify(g.writePkg(), Options{Now: g.now.Add(time.Hour)}) // no anchor at all
		wantClasses(t, res, 4, ClsReceiptUnverified, ClsUnsealedEnd)
		lc := res.Stats.LastCountersigned
		if lc == nil || lc.KeyEstablished || lc.CheckpointSeq != 7 {
			t.Errorf("last_countersigned = %+v, want checkpoint 7 with key_established false", lc)
		}
		if f := onlyUnsealedEnd(t, res, g.seq); !strings.Contains(f.Detail, "NOT established") {
			t.Errorf("detail does not say the key is not established: %s", f.Detail)
		}
	})
	t.Run("none", func(t *testing.T) {
		g := newGen(t)
		g.genesis()
		g.checkpoint(time.Second)
		g.tick(time.Minute)
		res := verifyGen(g, Options{})
		wantClasses(t, res, 4, ClsNoAnchor, ClsUnsealedEnd)
		if res.Stats.LastCountersigned != nil {
			t.Errorf("last_countersigned = %+v, want none", res.Stats.LastCountersigned)
		}
		if f := onlyUnsealedEnd(t, res, g.seq); !strings.Contains(f.Detail, "last countersigned checkpoint: none in this package") {
			t.Errorf("detail does not say there is none: %s", f.Detail)
		}
		b, _ := RenderJSON(res)
		var m struct {
			Stats map[string]any `json:"stats"`
		}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		if _, ok := m.Stats["last_countersigned"]; ok {
			t.Error("JSON carries last_countersigned although there is none")
		}
		for lang, s := range map[string]string{"de": "keine in diesem Paket", "en": "none in this package"} {
			if txt := RenderText(res, "pkg", lang); !strings.Contains(txt, s) {
				t.Errorf("%s report does not say there is no countersignature:\n%s", lang, txt)
			}
		}
	})
}

// --- the documented gap: truncation at an earlier seal (8.6, 11.2) -----------

// An honest chain with a mid-chain handover (SEAL shutdown, its checkpoint,
// RESUME) and receipts after the RESUME, cut off right behind the seal's
// checkpoint, looks properly sealed: exit 0, no finding — the limit of proof
// the spec documents. The comparison closes it: with the vendor's most recent
// root countersigned before the package was requested (a checkpoint after the
// RESUME — the truncating party presents an old cut) as expected root, the
// truncated package is MERKLE_INCONSISTENT (exit 2), and the untruncated
// chain passes the same comparison.
func TestTruncationAtEarlierSealAndTheComparison(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.tick(5 * time.Minute)
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	sealHash := g.seal("shutdown") // SEAL + its immediate checkpoint, no receipt before RESUME (8.4)
	cut := g.cutAfter(len(g.lines), g.now)
	cutRoot := cut.merkleRootAt(cut.seq)
	g.addMono(30*time.Minute, -1, "RESUME", "system", map[string]any{
		"prev_version": "1.0.0", "new_version": "1.1.0", "sealed_entry_hash": sealHash,
	})
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.tick(5 * time.Minute)
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.seal("shutdown") // the honest chain's real, later seal

	// The honest chain: its most recent countersigned root is the one the
	// vendor keeps for this chain_id.
	full := verifyGen(g, Options{})
	wantClasses(t, full, 0)
	vendorRoot := full.Stats.LastCountersigned
	if vendorRoot == nil || vendorRoot.MerkleRoot != g.merkleRootAt(vendorRoot.TreeSize) {
		t.Fatalf("honest chain: last countersigned %+v", vendorRoot)
	}

	// The truncated package on its own: sealed, valid, silent.
	res := verifyGen(cut, Options{})
	wantClasses(t, res, 0)
	if ce := res.Stats.ChainEnd; ce == nil || ce.Status != "sealed" || ce.SealReason != "shutdown" {
		t.Fatalf("truncated package: chain_end %+v", ce)
	}
	if lc := res.Stats.LastCountersigned; lc == nil || lc.TreeSize >= vendorRoot.TreeSize {
		t.Fatalf("truncated package names %+v as last countersigned, the vendor holds tree_size %d", lc, vendorRoot.TreeSize)
	}
	if cutRoot == vendorRoot.MerkleRoot {
		t.Fatal("test broken: the vendor's root equals the truncated chain's root")
	}

	// The comparison: the vendor's most recent countersigned root as expected root.
	res = verifyGen(cut, Options{ExpectRoot: vendorRoot.MerkleRoot})
	wantClasses(t, res, 2, ClsMerkleInconsistent)
	if res.Valid {
		t.Error("truncated package with the vendor's root must not be valid")
	}
	// ... which the honest chain passes.
	wantClasses(t, verifyGen(g, Options{ExpectRoot: vendorRoot.MerkleRoot}), 0)
}

// --- output: JSON and text report --------------------------------------------

func TestChainEndInJSON(t *testing.T) {
	for _, c := range []struct {
		g      *gen
		status string
	}{{validSealedChain(t), "sealed"}, {validChain(t), "incomplete"}} {
		b, err := RenderJSON(verifyGen(c.g, Options{}))
		if err != nil {
			t.Fatal(err)
		}
		var m struct {
			Stats struct {
				ChainEnd          map[string]any `json:"chain_end"`
				LastCountersigned map[string]any `json:"last_countersigned"`
			} `json:"stats"`
		}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		ce := m.Stats.ChainEnd
		if ce["status"] != c.status || ce["last_seq"] == nil || ce["last_ts"] == nil || ce["last_type"] == nil {
			t.Errorf("stats.chain_end = %v, want status %s with last_seq/last_ts/last_type", ce, c.status)
		}
		_, hatSiegel := ce["seal_seq"]
		if hatSiegel != (c.status == "sealed") {
			t.Errorf("stats.chain_end seal fields present=%v for status %s: %v", hatSiegel, c.status, ce)
		}
		for _, k := range []string{"checkpoint_seq", "tree_size", "merkle_root", "server_ts", "server_key_id", "key_established"} {
			if _, ok := m.Stats.LastCountersigned[k]; !ok {
				t.Errorf("stats.last_countersigned lacks %s: %v", k, m.Stats.LastCountersigned)
			}
		}
	}
}

func TestChainEndInTextReport(t *testing.T) {
	sealed := validSealedChain(t)
	sealTS := sealed.now.Add(-time.Second).Format(time.RFC3339)
	resS := verifyGen(sealed, Options{})
	unsealed := validChain(t)
	unsealed.tick(time.Minute)
	resU := verifyGen(unsealed, Options{})
	lc := resS.Stats.LastCountersigned

	for _, c := range []struct {
		res  Result
		lang string
		want []string
	}{
		{resS, "de", []string{
			fmt.Sprintf("%-28s ordnungsgemäß versiegelt am %s (Grund shutdown, seq 9)", "Kettenende:", sealTS),
			fmt.Sprintf("%-28s Checkpoint seq 7, tree_size 6, server_ts %s", "Letzte Gegenzeichnung:", lc.ServerTS),
			"merkle_root " + lc.MerkleRoot,
			"Ergebnis: gültig ohne Befunde (Exit-Code 0)",
			"Versiegelt belegt nicht, dass dies das jüngste Siegel der Kette ist",
			"chain_id " + sealed.chainID, "--expect-root <merkle_root>",
		}},
		{resS, "en", []string{
			fmt.Sprintf("%-28s properly sealed at %s (reason shutdown, seq 9)", "Chain end:", sealTS),
			fmt.Sprintf("%-28s checkpoint seq 7, tree_size 6, server_ts %s", "Last countersignature:", lc.ServerTS),
			"Result: valid, no findings (Exit code 0)",
			"chain_id " + sealed.chainID, "--expect-root <merkle_root>",
		}},
		{resU, "de", []string{
			fmt.Sprintf("%-28s nicht versiegelt — letzter Eintrag seq 9 (TICK) am %s", "Kettenende:", unsealed.ts()),
			fmt.Sprintf("%-28s Checkpoint seq 7, tree_size 6, server_ts", "Letzte Gegenzeichnung:"),
			"Ergebnis: unvollständig: Kettenende nicht versiegelt (Exit-Code 4)",
			"[UNSEALED_END] seq=9 — Kette endet ohne Siegel: unvollständig (Abschnitt 8.6)",
			"Kettenende unvollständig:", "chain_id " + unsealed.chainID, "MERKLE_INCONSISTENT",
		}},
		{resU, "en", []string{
			fmt.Sprintf("%-28s not sealed — last entry seq 9 (TICK) at %s", "Chain end:", unsealed.ts()),
			"Result: incomplete: chain end not sealed (Exit code 4)",
			"[UNSEALED_END] seq=9 — chain ends without a seal: incomplete (section 8.6)",
			"Chain end incomplete:", "chain_id " + unsealed.chainID, "MERKLE_INCONSISTENT",
		}},
	} {
		txt := RenderText(c.res, "pkg", c.lang)
		for _, w := range c.want {
			if !strings.Contains(txt, w) {
				t.Errorf("%s report lacks %q:\n%s", c.lang, w, txt)
			}
		}
		if strings.Contains(txt, "MISSING:") || strings.Contains(txt, "%!") {
			t.Errorf("%s report has a missing key or a broken format verb:\n%s", c.lang, txt)
		}
		// the chain-end line stands before the result line
		ende := strings.Index(txt, map[string]string{"de": "Kettenende:", "en": "Chain end:"}[c.lang])
		ergebnis := strings.Index(txt, map[string]string{"de": "Ergebnis:", "en": "Result:"}[c.lang])
		if ende < 0 || ergebnis < 0 || ende > ergebnis {
			t.Errorf("%s report: chain-end line not before the result line:\n%s", c.lang, txt)
		}
	}
}
