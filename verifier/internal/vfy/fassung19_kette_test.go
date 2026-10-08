package vfy

// Spec 1.9, the chain side: whole-millisecond arithmetic (2, 8.2, 8.5, 9.2),
// the late immediate checkpoint (8.2 conditions 3 and 4), the export seal
// (4.10, 8.4, 8.6), the auditor's expected roots (10.8), the statement about
// completeness (8.6) and the measured residual window (11.2).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// --- 6. whole milliseconds (spec 2, "Time arithmetic") --------------------------

func TestUnixMS(t *testing.T) {
	for _, c := range []struct {
		ts   string
		want int64
	}{
		{"1970-01-01T00:00:00Z", 0},
		{"1970-01-01T00:00:00.0009999Z", 0}, // digits after the third are dropped
		{"1970-01-01T00:00:00.001Z", 1},
		{"1969-12-31T23:59:59.9995Z", -1}, // truncation of the instant, also before 1970
		{"1969-12-31T23:59:59Z", -1000},
		{"2026-01-01T00:00:00.123456789Z", 1767225600123},
	} {
		tm, err := ParseTime(c.ts)
		if err != nil {
			t.Fatal(err)
		}
		if got := unixMS(tm); got != c.want {
			t.Errorf("unixMS(%s) = %d, want %d", c.ts, got, c.want)
		}
	}
	// No saturation across the whole year range: time.Duration stops at
	// about 292 years, the millisecond integers do not.
	a, _ := ParseTime("0001-01-01T00:00:00Z")
	b, _ := ParseTime("9999-12-31T23:59:59.999Z")
	if got, want := unixMS(b)-unixMS(a), int64(315537897599999); got != want {
		t.Errorf("span 0001..9999 = %d ms, want %d", got, want)
	}
	if s := fmtMS(315537897599999); s != "315537897599999 ms" {
		t.Errorf("fmtMS beyond a Duration = %q", s)
	}
	if s := fmtMS(600000); s != "600000 ms (10m0s)" {
		t.Errorf("fmtMS(600000) = %q", s)
	}
}

// msChain is an anchored chain with sub-second timestamps: GENESIS, CP,
// RECEIPT at whole seconds; the tests append from there.
func msChain(t *testing.T) *gen {
	g := newGen(t)
	g.tsLayout = time.RFC3339Nano
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	return g
}

// 8.2: Δ > 450,000 ms in whole milliseconds. 450 s plus 999 µs is 450,000 ms
// — no silence; 450,001 ms is (map f1: the 1.8 verifier counted 100 ns).
func TestSilenceBoundaryInWholeMilliseconds(t *testing.T) {
	for _, c := range []struct {
		d        time.Duration
		conceals bool
	}{
		{450*time.Second + 999*time.Microsecond, false},
		{450*time.Second + 100*time.Nanosecond, false},
		{450*time.Second + time.Millisecond, true},
	} {
		t.Run(c.d.String(), func(t *testing.T) {
			g := msChain(t)
			g.tick(c.d)
			g.seal("shutdown")
			res := verifyGen(g, Options{})
			if c.conceals {
				wantClasses(t, res, 2, ClsConcealedSilence)
			} else {
				wantClasses(t, res, 0)
			}
		})
	}
}

// 8.2 condition 1 in whole milliseconds: a GAP starting 450,000.9 ms after a
// covers (truncated to 450,000), one starting at 450,001 ms does not (map f4).
func TestGapBoundInWholeMilliseconds(t *testing.T) {
	for _, c := range []struct {
		off    time.Duration
		covers bool
	}{
		{450*time.Second + 900*time.Microsecond, true},
		{450*time.Second + time.Millisecond, false},
	} {
		t.Run(c.off.String(), func(t *testing.T) {
			g := msChain(t)
			aTS := g.now
			g.now = g.now.Add(time.Hour)
			g.addAt(g.seq+1, "GAP", "system", -1, map[string]any{
				"reason": "power_loss", "started_ts": g.fmtTS(aTS.Add(c.off)), "ended_ts": g.ts(),
				"lost_count": int64(-1), "detail": nil,
			})
			g.checkpoint(time.Second)
			g.seal("shutdown")
			res := verifyGen(g, Options{})
			if c.covers {
				wantClasses(t, res, 1, ClsCoveredGap)
			} else {
				wantClasses(t, res, 2, ClsConcealedSilence, ClsCoveredGap)
			}
		})
	}
}

// 9.2 in whole milliseconds: each instant is truncated, then subtracted. A
// wall delta of 300,000.1 ns-exact ms between a at .0009 s and b is 300,001
// whole ms (the 1.8 verifier truncated the difference to 300,000 and
// passed it); 300,000.9 ms from a whole-ms a is 300,000 and passes.
func TestClockBoundaryInWholeMilliseconds(t *testing.T) {
	for _, c := range []struct {
		name    string
		aFrac   time.Duration // fraction added to a's timestamp
		d       time.Duration // b − a, exact
		anomaly bool
	}{
		{"300000.9 ms from a whole ms", 0, 300000*time.Millisecond + 900*time.Microsecond, false},
		{"a at .0009, b 300000.1 ms later", 900 * time.Microsecond, 300000*time.Millisecond + 100*time.Microsecond, true},
		{"300001 ms", 0, 300001 * time.Millisecond, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := msChain(t)
			g.addMono(time.Minute+c.aFrac, 60000, "TICK", "system", map[string]any{"uptime_s": int64(1), "spool_backlog": int64(0), "disk_pct": int64(1)})
			g.addMono(c.d, 0, "TICK", "system", map[string]any{"uptime_s": int64(1), "spool_backlog": int64(0), "disk_pct": int64(1)})
			g.seal("shutdown")
			res := verifyGen(g, Options{})
			if c.anomaly {
				wantClasses(t, res, 2, ClsClockAnomaly)
			} else {
				wantClasses(t, res, 0)
			}
		})
	}
}

// 8.5: now − last > window, in whole milliseconds (map f3).
func TestFreshnessInWholeMilliseconds(t *testing.T) {
	g := validSealedChain(t)
	last := g.now
	for _, c := range []struct {
		after time.Duration
		stale bool
	}{
		{24*time.Hour + 999*time.Microsecond, false},
		{24*time.Hour + time.Millisecond, true},
	} {
		res := verifyGen(g, Options{Now: last.Add(c.after)})
		if c.stale {
			wantClasses(t, res, 1, ClsTrailingSilence)
		} else {
			wantClasses(t, res, 0)
		}
	}
}

// --- 8. the late immediate checkpoint (spec 8.2 conditions 3 and 4) ------------

// spaet describes the chain the ledger writes when it crashes between a
// critical entry a and its immediate checkpoint b and restarts after pause:
// b late with mono_delta_ms −1, then RESTART and GAP (fixed ledger, 1.9).
type spaet struct {
	aType        string
	pause        time.Duration
	cpMono       int64
	noRestart    bool
	restartAfter time.Duration
	downtime     int64
	noGap        bool
	gapFrom      func(aTS, bTS time.Time) time.Time
	gapTo        func(aTS, bTS time.Time) time.Time
	unsealed     bool
}

// fixedLedger is the shape of the ledger that declares the outage (vector
// gap_late_checkpoint_restart): downtime = pause, GAP window ts(a)..ts(b).
func fixedLedger() spaet {
	return spaet{
		aType: "OVERSIGHT", pause: 10 * time.Minute, cpMono: -1, downtime: 600_000,
		gapFrom: func(aTS, _ time.Time) time.Time { return aTS },
		gapTo:   func(_, bTS time.Time) time.Time { return bTS },
	}
}

func lateCheckpointChain(t *testing.T, v spaet) *gen {
	t.Helper()
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.tick(5 * time.Minute)
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	if criticalTypes[v.aType] {
		appendCritical(t, g, v.aType) // a, one minute later
	} else {
		g.tick(time.Minute) // a non-critical a (condition 4 (a) fails)
	}
	aTS := g.now
	g.checkpointMono(v.pause, v.cpMono) // b, written late at the restart
	bTS := g.now
	if !v.noRestart {
		g.addMono(v.restartAfter, v.restartAfter.Milliseconds(), "RESTART", "system", map[string]any{
			"reason": "crash_recovery", "downtime_ms_estimate": v.downtime, "version": "1.0.0",
		})
	}
	if !v.noGap {
		g.addAt(g.seq+1, "GAP", "system", 0, map[string]any{
			"reason": "power_loss", "started_ts": g.fmtTS(v.gapFrom(aTS, bTS)), "ended_ts": g.fmtTS(v.gapTo(aTS, bTS)),
			"lost_count": int64(-1), "detail": nil,
		})
		g.checkpoint(0) // the GAP is critical
	}
	g.tick(time.Minute)
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	if !v.unsealed {
		g.seal("shutdown")
	}
	return g
}

// The fixed ledger's chain: the silence before the late checkpoint is covered
// by condition 4 — COVERED_GAP (exit 1), and with an open end exit 4. Up to
// 1.8 it was CONCEALED_SILENCE (exit 2), the decision of 2026-09-03 the
// client changed on 2026-09-29. For every critical type other than SEAL.
func TestLateCheckpointCoveredByRestartAndGap(t *testing.T) {
	for typ := range criticalTypes {
		if typ == "SEAL" || typ == "GENESIS" || typ == "GAP" {
			continue // SEAL: condition 3; GENESIS only at seq 1; GAP: below
		}
		t.Run(typ, func(t *testing.T) {
			v := fixedLedger()
			v.aType = typ
			res := verifyGen(lateCheckpointChain(t, v), Options{})
			want := []string{ClsCoveredGap}
			if typ == "CONTENT_DELETED" {
				want = append(want, ClsContentDeleted) // stays its own finding (8.2, "Why condition 4")
			}
			wantClasses(t, res, 1, want...)
		})
	}
	t.Run("open chain end", func(t *testing.T) {
		v := fixedLedger()
		v.unsealed = true
		wantClasses(t, verifyGen(lateCheckpointChain(t, v), Options{}), 4, ClsCoveredGap, ClsUnsealedEnd)
	})
	t.Run("downtime unknown (-1)", func(t *testing.T) {
		v := fixedLedger()
		v.downtime = -1
		wantClasses(t, verifyGen(lateCheckpointChain(t, v), Options{}), 1, ClsCoveredGap)
	})
	t.Run("downtime exactly Δ − 450,000", func(t *testing.T) {
		v := fixedLedger()
		v.downtime = 150_000
		wantClasses(t, verifyGen(lateCheckpointChain(t, v), Options{}), 1, ClsCoveredGap)
	})
	t.Run("RESTART exactly 450,000 ms after b", func(t *testing.T) {
		v := fixedLedger()
		v.restartAfter = 450 * time.Second
		v.gapTo = func(_, bTS time.Time) time.Time { return bTS.Add(450 * time.Second) }
		wantClasses(t, verifyGen(lateCheckpointChain(t, v), Options{}), 1, ClsCoveredGap)
	})
	t.Run("GAP window at the tolerance on both sides", func(t *testing.T) {
		v := fixedLedger()
		v.gapFrom = func(aTS, _ time.Time) time.Time { return aTS.Add(450 * time.Second) }
		v.gapTo = func(_, bTS time.Time) time.Time { return bTS.Add(-450 * time.Second) }
		wantClasses(t, verifyGen(lateCheckpointChain(t, v), Options{}), 1, ClsCoveredGap)
	})
}

// Each of the four parts of condition 4 is necessary: a variant that breaks
// one of them stays CONCEALED_SILENCE (exit 2).
func TestLateCheckpointConditionFourEveryPart(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(v *spaet)
		extra []string
	}{
		{"(a) a is not critical (TICK)", func(v *spaet) { v.aType = "TICK" }, []string{ClsCoveredGap}},
		{"(a) a is a SEAL (condition 3 wants the RESUME)", func(v *spaet) { v.aType = "SEAL" }, []string{ClsCoveredGap, ClsHandoverBroken}},
		{"(b) stalled writer: mono_delta_ms ≥ 0", func(v *spaet) { v.cpMono = 600_000 }, []string{ClsCoveredGap}},
		{"(b) stalled writer: mono_delta_ms 0", func(v *spaet) { v.cpMono = 0 }, []string{ClsCoveredGap, ClsClockAnomaly}},
		{"(c) no RESTART after b", func(v *spaet) { v.noRestart = true }, []string{ClsCoveredGap}},
		{"(c) RESTART 451 s after b", func(v *spaet) {
			v.restartAfter = 451 * time.Second
			v.gapTo = func(_, bTS time.Time) time.Time { return bTS.Add(v.restartAfter) }
		}, []string{ClsCoveredGap}},
		{"(c) downtime 0 (the ledger up to 1.8)", func(v *spaet) { v.downtime = 0 }, []string{ClsCoveredGap}},
		{"(c) downtime one below Δ − 450,000", func(v *spaet) { v.downtime = 149_999 }, []string{ClsCoveredGap}},
		{"(d) no GAP after the RESTART", func(v *spaet) { v.noGap = true }, nil},
		{"(d) GAP starting at the restart (the ledger up to 1.8)", func(v *spaet) {
			v.gapFrom = func(_, bTS time.Time) time.Time { return bTS }
		}, []string{ClsCoveredGap}},
		{"(d) GAP ending too early", func(v *spaet) {
			v.gapTo = func(aTS, _ time.Time) time.Time { return aTS }
		}, []string{ClsCoveredGap}},
		{"(c)+(d) both as the ledger up to 1.8 wrote them", func(v *spaet) {
			v.downtime = 0
			v.gapFrom = func(_, bTS time.Time) time.Time { return bTS }
		}, []string{ClsCoveredGap}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := fixedLedger()
			c.edit(&v)
			res := verifyGen(lateCheckpointChain(t, v), Options{})
			wantClasses(t, res, 2, append([]string{ClsConcealedSilence}, c.extra...)...)
			if cs := findingsOf(res, ClsConcealedSilence); len(cs) != 1 || !strings.Contains(cs[0].Detail, "600000 ms (10m0s)") {
				t.Errorf("want one CONCEALED_SILENCE naming 600000 ms: %+v", cs)
			}
		})
	}
	// A GAP that covers but stands one entry further (a TICK between RESTART
	// and GAP) is outside the position condition 4 names.
	t.Run("(d) GAP not directly after the RESTART", func(t *testing.T) {
		g := newGen(t)
		g.genesis()
		g.checkpoint(time.Second)
		g.receiptForLast(time.Second)
		appendCritical(t, g, "OVERSIGHT")
		aTS := g.now
		g.checkpointMono(10*time.Minute, -1)
		bTS := g.now
		g.addMono(0, 0, "RESTART", "system", map[string]any{"reason": "crash_recovery", "downtime_ms_estimate": int64(600000), "version": "1.0.0"})
		g.tick(0)
		g.addAt(g.seq+1, "GAP", "system", 0, map[string]any{"reason": "power_loss", "started_ts": g.fmtTS(aTS), "ended_ts": g.fmtTS(bTS), "lost_count": int64(-1), "detail": nil})
		g.checkpoint(0)
		g.seal("shutdown")
		wantClasses(t, verifyGen(g, Options{}), 2, ClsConcealedSilence, ClsCoveredGap)
	})
}

// sealLateChain: SEAL, its immediate checkpoint written late after pause with
// mono, then the RESUME with sealedHash (the SEAL's own hash if empty) — the
// shape the ledger writes for a crash between SEAL and checkpoint (vector
// gap_late_seal_checkpoint). No RESTART/GAP: the chain is sealed.
func sealLateChain(t *testing.T, pause time.Duration, mono int64, wrongHash bool) *gen {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	sealHash := g.add(time.Minute, "SEAL", "system", map[string]any{"version": "1.0.0", "reason": "update"})
	g.checkpointMono(pause, mono)
	if wrongHash {
		sealHash = strings.Repeat("ef", 32)
	}
	g.addMono(time.Millisecond, 1, "RESUME", "system", map[string]any{"prev_version": "1.0.0", "new_version": "1.1.0", "sealed_entry_hash": sealHash})
	g.checkpoint(time.Millisecond)
	g.receiptForLast(time.Second)
	g.seal("shutdown")
	return g
}

// 8.2 condition 3, second sentence (from 1.9): the bare-SEAL variant is
// covered by the handover; the stalled writer (mono ≥ 0) and a RESUME that
// does not continue this SEAL are not.
func TestLateSealCheckpointCoveredByHandover(t *testing.T) {
	wantClasses(t, verifyGen(sealLateChain(t, 10*time.Minute, -1, false), Options{}), 0)
	wantClasses(t, verifyGen(sealLateChain(t, 10*time.Minute, 600_000, false), Options{}), 2, ClsConcealedSilence)
	wantClasses(t, verifyGen(sealLateChain(t, 10*time.Minute, -1, true), Options{}), 2, ClsConcealedSilence, ClsHandoverBroken)
	// A late seal checkpoint within the tolerance needs no coverage at all.
	wantClasses(t, verifyGen(sealLateChain(t, 7*time.Minute, 420_000, false), Options{}), 0)
}

// --- 9. the export seal (spec 4.10, 8.4, 8.6) -------------------------------------

func exportChain(t *testing.T) *gen {
	g := validChain(t) // ... CP 7, RECEIPT 8
	g.seal("export")   // SEAL 9, CP 10
	return g
}

// A package that ends with SEAL(export) and its immediate checkpoint is sealed
// — exit 0 without findings, also with receipts on exactly that checkpoint —
// and a mid-chain export seal is an ordinary handover.
func TestExportSeal(t *testing.T) {
	t.Run("sealed at the export seal", func(t *testing.T) {
		res := verifyGen(exportChain(t), Options{})
		wantClasses(t, res, 0)
		if ce := res.Stats.ChainEnd; ce == nil || ce.Status != "sealed" || ce.SealReason != "export" || ce.SealSeq != 9 || ce.SealCheckpointSeq != 10 {
			t.Errorf("chain_end = %+v", ce)
		}
	})
	t.Run("receipts on the export checkpoint trail", func(t *testing.T) {
		g := exportChain(t)
		g.receiptForLast(time.Second)
		g.receipt(time.Second, 10, 9, g.merkleRootAt(9))
		wantClasses(t, verifyGen(g, Options{}), 0)
	})
	t.Run("mid-chain export seal, chain sealed later", func(t *testing.T) {
		g := exportChain(t)
		sealHash := hex.EncodeToString(g.hashesRw[8])
		g.addMono(time.Millisecond, 1, "RESUME", "system", map[string]any{"prev_version": "1.0.0", "new_version": "1.0.0", "sealed_entry_hash": sealHash})
		g.checkpoint(time.Millisecond)
		g.receiptForLast(time.Second)
		g.tick(5 * time.Minute)
		g.seal("shutdown")
		wantClasses(t, verifyGen(g, Options{}), 0)
	})
	t.Run("mid-chain export seal, open end", func(t *testing.T) {
		g := exportChain(t)
		sealHash := hex.EncodeToString(g.hashesRw[8])
		g.addMono(time.Millisecond, 1, "RESUME", "system", map[string]any{"prev_version": "1.0.0", "new_version": "1.0.0", "sealed_entry_hash": sealHash})
		g.checkpoint(time.Millisecond)
		wantClasses(t, verifyGen(g, Options{}), 4, ClsUnsealedEnd)
	})
	t.Run("export seal followed by an entry other than RESUME", func(t *testing.T) {
		g := exportChain(t)
		g.tick(time.Minute)
		wantClasses(t, verifyGen(g, Options{}), 2, ClsHandoverBroken, ClsUnsealedEnd)
	})
}

// The export package and the comparison of 8.6: completeness is not
// established by the package alone; the vendor's most recent root from
// BEFORE the request establishes it up to its tree_size; a root the vendor
// countersigned after the export lies beyond the package and is
// MERKLE_INCONSISTENT even for this honest package — which is why the report
// asks for the one from before.
func TestExportPackageAndTheComparison(t *testing.T) {
	g := exportChain(t)
	pkg := g.cutAfter(len(g.lines), g.now)
	vorher := fmt.Sprintf("%d:%s", 6, g.merkleRootAt(6)) // receipt 8 on CP 7: countersigned before the request
	sealHash := hex.EncodeToString(g.hashesRw[8])
	g.addMono(time.Millisecond, 1, "RESUME", "system", map[string]any{"prev_version": "1.0.0", "new_version": "1.0.0", "sealed_entry_hash": sealHash})
	g.checkpoint(time.Millisecond)
	g.receiptForLast(time.Second)
	nachher := fmt.Sprintf("%d:%s", 11, g.merkleRootAt(11)) // countersigned after the export

	res := verifyGen(pkg, Options{})
	wantClasses(t, res, 0)
	if c := res.Stats.Completeness; c == nil || c.Status != "not_established" || c.UpToTreeSize != nil {
		t.Errorf("completeness = %+v, want not_established", c)
	}
	x, _ := ParseExpectedRoot(vorher)
	res = verifyGen(pkg, Options{ExpectRoots: []ExpectedRoot{x}})
	wantClasses(t, res, 0)
	if c := res.Stats.Completeness; c == nil || c.Status != "established" || c.UpToTreeSize == nil || *c.UpToTreeSize != 6 {
		t.Errorf("completeness = %+v, want established up to 6", c)
	}
	y, _ := ParseExpectedRoot(nachher)
	res = verifyGen(pkg, Options{ExpectRoots: []ExpectedRoot{y}})
	wantClasses(t, res, 2, ClsMerkleInconsistent)
	if f := findingsOf(res, ClsMerkleInconsistent); len(f) != 1 || !strings.Contains(f[0].Detail, "exceeds the 10 entries") {
		t.Errorf("detail does not say the root lies beyond the package: %+v", f)
	}
}

// --- 4. expected roots (spec 10.8) ---------------------------------------------

func TestParseExpectedRoot(t *testing.T) {
	root := strings.Repeat("ab", 32)
	for _, c := range []struct {
		in   string
		want ExpectedRoot
	}{
		{root, ExpectedRoot{Root: root}},
		{strings.ToUpper(root), ExpectedRoot{Root: root}},
		{"7:" + root, ExpectedRoot{TreeSize: 7, Root: root}},
		{"9007199254740991:" + root, ExpectedRoot{TreeSize: 9007199254740991, Root: root}},
	} {
		got, err := ParseExpectedRoot(c.in)
		if err != nil || got != c.want {
			t.Errorf("ParseExpectedRoot(%q) = %+v, %v; want %+v", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "abc", root[:63], root + "a", "0:" + root, "07:" + root, "-1:" + root, "x:" + root, "7:" + root[:63],
		"9007199254740992:" + root, "7 :" + root, " " + root, "7:" + root + ":1", root[:62] + "zz"} {
		if _, err := ParseExpectedRoot(bad); err == nil {
			t.Errorf("ParseExpectedRoot(%q) accepted", bad)
		}
	}
}

// With tree_size the root must equal the one over exactly that prefix;
// without, some prefix; beyond the entries it is not found. Every found root
// is an anchor and establishes completeness; every one not found is
// MERKLE_INCONSISTENT and anchors nothing.
func TestExpectedRoots(t *testing.T) {
	// An unanchored sealed chain: GENESIS, CP, TICK, SEAL, CP (5 entries).
	unanchored := func(t *testing.T) *gen {
		g := newGen(t)
		g.genesis()
		g.checkpoint(time.Second)
		g.tick(time.Minute)
		g.seal("shutdown")
		return g
	}
	g := unanchored(t)
	r2, r4, r5 := g.merkleRootAt(2), g.merkleRootAt(4), g.merkleRootAt(5)
	x := func(s string) ExpectedRoot {
		e, err := ParseExpectedRoot(s)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	cases := []struct {
		name  string
		roots []ExpectedRoot
		exit  int
		cls   []string
		upTo  int64 // 0 = not established
	}{
		{"none", nil, 1, []string{ClsNoAnchor}, 0},
		{"TREE_SIZE:ROOT found", []ExpectedRoot{x("4:" + r4)}, 0, nil, 4},
		{"ROOT found at its prefix", []ExpectedRoot{x(strings.ToUpper(r2))}, 0, nil, 2},
		{"TREE_SIZE:ROOT with the root of another size", []ExpectedRoot{x("5:" + r4)}, 2, []string{ClsMerkleInconsistent, ClsNoAnchor}, 0},
		{"TREE_SIZE beyond the entries", []ExpectedRoot{x("6:" + r5)}, 2, []string{ClsMerkleInconsistent, ClsNoAnchor}, 0},
		{"ROOT matching no prefix", []ExpectedRoot{x(strings.Repeat("12", 32))}, 2, []string{ClsMerkleInconsistent, ClsNoAnchor}, 0},
		{"several, all found: the largest tree_size counts", []ExpectedRoot{x("2:" + r2), x(r5), x("4:" + r4)}, 0, nil, 5},
		{"one found, one not", []ExpectedRoot{x("2:" + r2), x("3:" + r4)}, 2, []string{ClsMerkleInconsistent}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := verifyGen(unanchored(t), Options{ExpectRoots: c.roots})
			wantClasses(t, res, c.exit, c.cls...)
			comp := res.Stats.Completeness
			if comp == nil {
				t.Fatal("no completeness statement")
			}
			if c.upTo == 0 {
				if comp.Status != "not_established" || comp.UpToTreeSize != nil {
					t.Errorf("completeness = %+v, want not_established", comp)
				}
			} else if comp.Status != "established" || comp.UpToTreeSize == nil || *comp.UpToTreeSize != c.upTo {
				t.Errorf("completeness = %+v, want established up to %d", comp, c.upTo)
			}
			if n := countClass(res, ClsMerkleInconsistent); n > 1 {
				t.Errorf("MERKLE_INCONSISTENT %d times", n)
			}
		})
	}
	// The single option of 1.8 takes both forms, and a value that is neither
	// is never found.
	t.Run("legacy ExpectRoot, TREE_SIZE:ROOT", func(t *testing.T) {
		wantClasses(t, verifyGen(unanchored(t), Options{ExpectRoot: "4:" + r4}), 0)
	})
	t.Run("legacy ExpectRoot, bare root", func(t *testing.T) {
		wantClasses(t, verifyGen(unanchored(t), Options{ExpectRoot: r2}), 0)
	})
	t.Run("legacy ExpectRoot, garbage", func(t *testing.T) {
		wantClasses(t, verifyGen(unanchored(t), Options{ExpectRoot: "nonsense"}), 2, ClsMerkleInconsistent, ClsNoAnchor)
	})
}

// --- 10. completeness (spec 8.6) ------------------------------------------------

func TestCompletenessInJSONAndText(t *testing.T) {
	g := validSealedChain(t)
	decode := func(res Result) map[string]any {
		b, err := RenderJSON(res)
		if err != nil {
			t.Fatal(err)
		}
		var m struct {
			Stats map[string]any `json:"stats"`
		}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		c, _ := m.Stats["completeness"].(map[string]any)
		return c
	}
	res := verifyGen(g, Options{})
	c := decode(res)
	if c == nil || c["status"] != "not_established" {
		t.Fatalf("stats.completeness = %v", c)
	}
	if v, ok := c["up_to_tree_size"]; !ok || v != nil {
		t.Errorf("up_to_tree_size = %v (present %v), want null", v, ok)
	}
	for lang, want := range map[string][]string{
		"en": {"Completeness:", "not established", "no statement is possible", "chain_id " + g.chainID, "BEFORE this package was requested",
			"--expect-root <tree_size>:<merkle_root>", "--expect-root <merkle_root>", "MERKLE_INCONSISTENT"},
		"de": {"Vollständigkeit:", "nicht belegt", "keine Aussage darüber möglich", "chain_id " + g.chainID, "VOR der Anforderung dieses Pakets",
			"--expect-root <tree_size>:<merkle_root>", "--expect-root <merkle_root>", "MERKLE_INCONSISTENT"},
	} {
		txt := RenderText(res, "pkg", lang)
		for _, w := range want {
			if !strings.Contains(txt, w) {
				t.Errorf("%s report lacks %q:\n%s", lang, w, txt)
			}
		}
		// The old wording asked for the vendor's most recent root overall.
		for _, alt := range []string{"most recent countersigned root", "jüngste gegengezeichnete Wurzel"} {
			if strings.Contains(txt, alt) {
				t.Errorf("%s report still asks for %q", lang, alt)
			}
		}
	}

	root := g.merkleRootAt(6)
	res = verifyGen(g, Options{ExpectRoots: []ExpectedRoot{{TreeSize: 6, Root: root}}})
	c = decode(res)
	if c["status"] != "established" || c["up_to_tree_size"] != float64(6) {
		t.Errorf("stats.completeness = %v, want established / 6", c)
	}
	for lang, w := range map[string]string{"en": "established up to tree_size 6 by the expected root passed", "de": "belegt bis tree_size 6 durch die übergebene erwartete Wurzel"} {
		if txt := RenderText(res, "pkg", lang); !strings.Contains(txt, w) {
			t.Errorf("%s report lacks %q:\n%s", lang, w, txt)
		}
	}

	// A format error states neither completeness nor residual window.
	f := newGen(t)
	f.tick(0)
	res = verifyGen(f, Options{})
	if res.ExitCode != 3 || res.Stats.Completeness != nil || res.Stats.ResidualWindow != nil {
		t.Errorf("exit %d, completeness %+v, residual %+v — want neither for exit 3", res.ExitCode, res.Stats.Completeness, res.Stats.ResidualWindow)
	}
	if b, _ := RenderJSON(res); strings.Contains(string(b), "completeness") || strings.Contains(string(b), "residual_window") {
		t.Errorf("JSON of a format error carries completeness/residual_window:\n%s", b)
	}
}

// --- 11. the residual window (spec 11.2) ----------------------------------------

// adminAnchor appends an ADMIN entry with message_type "anchor" — the
// appliance chains every anchor before sending it.
func (g *gen) adminAnchor(d time.Duration) {
	body := fmt.Sprintf(`{"tree_size":%d}`, g.seq)
	sum := sha256.Sum256([]byte(body))
	g.add(d, "ADMIN", "system", map[string]any{"message_type": "anchor", "payload_canonical": body, "payload_hash": hex.EncodeToString(sum[:])})
}

func TestResidualWindowMeasured(t *testing.T) {
	t.Run("after the last countersigned checkpoint", func(t *testing.T) {
		g := validChain(t) // T = 6 (CP 7, receipt 8), N = 8
		res := verifyGen(g, Options{})
		wantRW(t, res, ResidualWindowStat{AfterTreeSize: 6, FirstSeq: 7, LastSeq: 8, Entries: 2,
			FromTS: strp(tsOf(g, 6)), ToTS: tsOf(g, 8), SpanMS: i64p(2000)})
	})
	t.Run("anchor messages after the receipt count, earlier ones do not", func(t *testing.T) {
		g := newGen(t)
		g.genesis()
		g.adminAnchor(time.Second) // 2, answered by the receipt at 4
		g.checkpoint(time.Second)  // 3
		g.receiptForLast(time.Second)
		g.adminAnchor(time.Minute) // 5, unanswered
		g.tick(time.Minute)
		g.adminAnchor(time.Minute) // 7, unanswered
		g.checkpoint(time.Second)
		res := verifyGen(g, Options{})
		wantRW(t, res, ResidualWindowStat{AfterTreeSize: 2, FirstSeq: 3, LastSeq: 8, Entries: 6,
			FromTS: strp(tsOf(g, 2)), ToTS: tsOf(g, 8), SpanMS: i64p(183000), UnansweredAnchorMessages: 2})
	})
	t.Run("no countersigned checkpoint: T = 0", func(t *testing.T) {
		g := newGen(t)
		g.genesis()
		g.adminAnchor(time.Second)
		g.checkpoint(time.Second)
		g.adminAnchor(time.Minute)
		g.seal("shutdown")
		res := verifyGen(g, Options{})
		wantRW(t, res, ResidualWindowStat{AfterTreeSize: 0, FirstSeq: 1, LastSeq: 6, Entries: 6,
			ToTS: tsOf(g, 6), UnansweredAnchorMessages: 2, BeyondCadence: true})
		b, _ := RenderJSON(res)
		for _, w := range []string{`"from_ts": null`, `"span_ms": null`, `"beyond_cadence": true`} {
			if !strings.Contains(string(b), w) {
				t.Errorf("JSON lacks %s:\n%s", w, b)
			}
		}
	})
	for _, c := range []struct {
		d      time.Duration
		beyond bool
	}{{447 * time.Second, false}, {448 * time.Second, true}} {
		// T = 1 (the receipt at seq 3 countersigns CP 2 over GENESIS), so the
		// span runs from ts_chained of seq 1: 1 s (CP) + 1 s (receipt) + d +
		// 1 s (CP) — 450,000 ms is within the cadence, 451,000 ms beyond.
		t.Run(fmt.Sprintf("span %s", c.d+3*time.Second), func(t *testing.T) {
			g := newGen(t)
			g.genesis()
			g.checkpoint(time.Second)
			g.receiptForLast(time.Second)
			g.tick(c.d)
			g.checkpoint(time.Second)
			res := verifyGen(g, Options{})
			rw := res.Stats.ResidualWindow
			if rw == nil || rw.BeyondCadence != c.beyond {
				t.Errorf("residual_window = %+v, want beyond_cadence %v", rw, c.beyond)
			}
		})
	}
	t.Run("the JSON members of spec 11.2", func(t *testing.T) {
		b, _ := RenderJSON(verifyGen(validChain(t), Options{}))
		var m struct {
			Stats struct {
				RW map[string]any `json:"residual_window"`
			} `json:"stats"`
		}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		want := []string{"after_tree_size", "first_seq", "last_seq", "entries", "from_ts", "to_ts", "span_ms", "unanswered_anchor_messages", "beyond_cadence"}
		if len(m.Stats.RW) != len(want) {
			t.Errorf("residual_window has %d members, want %d: %v", len(m.Stats.RW), len(want), m.Stats.RW)
		}
		for _, k := range want {
			if _, ok := m.Stats.RW[k]; !ok {
				t.Errorf("residual_window lacks %s", k)
			}
		}
	})
}

// The fixed "~5 minutes or up to 1,000 entries" is gone; the report states
// the measured window, and beyond the cadence the causes and the comparison.
func TestResidualWindowInTextReport(t *testing.T) {
	g := validChain(t)
	res := verifyGen(g, Options{})
	for lang, want := range map[string][]string{
		"en": {"Residual window:", "2 entries (seq 7 to 8) after tree_size 6, spanning 2000 ms (2s)", "Residual window (spec 11.2): the 2 entries after the last countersigned tree state (tree_size 6) — seq 7 to 8"},
		"de": {"Restfenster:", "2 Einträge (seq 7 bis 8) nach tree_size 6, Dauer 2000 ms (2s)", "Restfenster (Spezifikation 11.2): Die 2 Einträge nach dem letzten gegengezeichneten Stand (tree_size 6) — seq 7 bis 8"},
	} {
		txt := RenderText(res, "pkg", lang)
		for _, w := range want {
			if !strings.Contains(txt, w) {
				t.Errorf("%s report lacks %q:\n%s", lang, w, txt)
			}
		}
		for _, alt := range []string{"1,000", "1.000 Einträge", "~5"} {
			if strings.Contains(txt, alt) {
				t.Errorf("%s report still carries the fixed bound %q", lang, alt)
			}
		}
		if strings.Contains(txt, "licence lapsed") || strings.Contains(txt, "Lizenz abgelaufen") {
			t.Errorf("%s report names causes although the window is within the cadence", lang)
		}
	}
	g = newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.tick(time.Minute)
	res = verifyGen(g, Options{})
	for lang, want := range map[string][]string{
		"en": {"all 3 entries (seq 1 to 3): no countersigned checkpoint in this package — beyond the anchoring cadence", "licence lapsed", "egress is switched off", "vendor was unreachable", "the export is old", "spec 8.6"},
		"de": {"alle 3 Einträge (seq 1 bis 3): kein gegengezeichneter Checkpoint in diesem Paket — über dem Verankerungstakt", "Lizenz abgelaufen", "Egress abgeschaltet", "Hersteller nicht erreichbar", "alter Export", "Spezifikation 8.6"},
	} {
		txt := RenderText(res, "pkg", lang)
		for _, w := range want {
			if !strings.Contains(txt, w) {
				t.Errorf("%s report lacks %q:\n%s", lang, w, txt)
			}
		}
		if strings.Contains(txt, "MISSING:") || strings.Contains(txt, "%!") {
			t.Errorf("%s report has a missing key or a broken verb:\n%s", lang, txt)
		}
	}
}

func wantRW(t *testing.T, res Result, want ResidualWindowStat) {
	t.Helper()
	got := res.Stats.ResidualWindow
	if got == nil {
		t.Fatalf("no residual_window (exit %d, %+v)", res.ExitCode, res.Findings)
	}
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(want)
	if string(a) != string(b) {
		t.Errorf("residual_window\n got %s\nwant %s", a, b)
	}
}

// tsOf is ts_chained of the entry at seq (1-based) as the generator wrote it.
func tsOf(g *gen, seq int) string {
	var e struct {
		TS string `json:"ts_chained"`
	}
	_ = json.Unmarshal(g.lines[seq-1], &e)
	return e.TS
}

func strp(s string) *string { return &s }
func i64p(n int64) *int64   { return &n }
