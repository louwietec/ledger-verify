package vfy

// The members of stats.evidence_level that an expected file does not carry
// (registry expected_files.evidence_level names state, level, reach,
// segments without basis, the reasons, the notes and the affiliation):
// entries, the basis of each segment, next and the shape of each condition.
// Format spec 10.9.5 derives them from the reaches of the conditions, so
// the vector matrix recomputes them on every run with the formula of the
// spec, written here once more from its text and not from the code under
// test.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// formulaOrder is registry verifier.evidence_level.condition_order.
var formulaOrder = []string{"time_witness", "expected_root_found", "receipt_key_confirmed",
	"time_witness_qualified", "receipts_logged", "completeness_from_history", "log_day_qualified"}

// evidenceFormula checks an object evidence_level against format spec
// 10.9.4 (the four members of a condition), 10.9.5 (r0 to r3, level,
// up_to_tree_size, segments with basis, next) and 10.10.2 (null and empty
// outside the state rated, qualified_time exactly at level 3) for a
// package of n entries; it returns what differs.
func evidenceFormula(ev *EvidenceLevelStat, n int64) string {
	if ev == nil {
		return "no evidence_level in a report"
	}
	var out []string
	if ev.State != EvRated {
		// "level, entries (N), up_to_tree_size, conditions, next,
		// qualified_time und anchors sind null, segments und notes leer,
		// wenn der Zustand nicht rated ist" (10.10.2).
		if ev.Level != nil || ev.Entries != nil || ev.UpToTreeSize != nil || ev.Conditions != nil || ev.Next != nil || ev.QualifiedTime != nil || ev.Anchors != nil || len(ev.Segments) != 0 || len(ev.Notes) != 0 {
			out = append(out, "state "+ev.State+" with a level, conditions, next, qualified_time, anchors, segments or notes")
		}
		return strings.Join(out, "; ")
	}
	if ev.Entries == nil || *ev.Entries != n {
		out = append(out, fmt.Sprintf("entries %v, package %d", ev.Entries, n))
	}
	if ev.Conditions == nil {
		return strings.Join(append(out, "conditions null in the state rated"), "; ")
	}
	reach := map[string]int64{}
	for _, code := range formulaOrder {
		c := ev.Conditions.Get(code)
		// "met (bool) sagt, ob sie vorliegt; up_to_tree_size ist ihre
		// Reichweite, null, wenn sie nicht vorliegt; count ist die Zahl
		// der angerechneten Gegenstände, 0, wenn keiner angerechnet ist;
		// reason ist genau dann null, wenn sie vorliegt" (10.9.4).
		switch {
		case c.Met && (c.Reason != nil || c.UpToTreeSize == nil || *c.UpToTreeSize < 1):
			out = append(out, code+": met with a reason or without a reach")
		case !c.Met && (c.Reason == nil || c.UpToTreeSize != nil || c.Count != 0):
			out = append(out, code+": not met without a reason, with a reach or with a count")
		case c.Met:
			reach[code] = min(*c.UpToTreeSize, n)
		}
	}
	met := func(code string) bool { return ev.Conditions.Get(code).Met }
	// 10.9.5: r0 = N; r1 = max(reach(1), reach(2), reach(3)); r2 =
	// reach(3); r3 = min(reach(3), max(reach(4), reach(7)), reach(5),
	// reach(6)) when (3), (5), (6) and at least one of (4) and (7) hold,
	// else 0.
	r := [4]int64{n, max(reach["time_witness"], reach["expected_root_found"], reach["receipt_key_confirmed"]), reach["receipt_key_confirmed"], 0}
	if met("receipt_key_confirmed") && (met("time_witness_qualified") || met("log_day_qualified")) && met("receipts_logged") && met("completeness_from_history") {
		r[3] = min(reach["receipt_key_confirmed"], max(reach["time_witness_qualified"], reach["log_day_qualified"]), reach["receipts_logged"], reach["completeness_from_history"])
	}
	// The codes of (3) to (7) in condition_order.
	three := []string{"receipt_key_confirmed", "time_witness_qualified", "receipts_logged", "completeness_from_history", "log_day_qualified"}
	level := 0
	for k := 3; k >= 1; k-- {
		if r[k] >= 1 {
			level = k
			break
		}
	}
	upTo := r[level]
	if ev.Level == nil || *ev.Level != level {
		out = append(out, fmt.Sprintf("level %v, formula %d", formulaVal(ev.Level), level))
	}
	if ev.UpToTreeSize == nil || *ev.UpToTreeSize != upTo {
		out = append(out, fmt.Sprintf("up_to_tree_size %v, formula %d", formulaVal(ev.UpToTreeSize), upTo))
	}
	// Segments: the maximal runs of equal lvl(p), each with its basis
	// (10.9.5): at level 3 the met codes of (3) to (7) whose reach is r3,
	// at level 2 receipt_key_confirmed, at level 1 the codes of (1) to (3)
	// that hold with reach r1, at level 0 none.
	basis := func(k int) []string {
		var codes []string
		switch k {
		case 3:
			codes = three
		case 2:
			return []string{"receipt_key_confirmed"}
		case 1:
			codes = []string{"time_witness", "expected_root_found", "receipt_key_confirmed"}
		default:
			return []string{}
		}
		b := []string{}
		for _, c := range codes {
			if met(c) && reach[c] == r[k] {
				b = append(b, c)
			}
		}
		return b
	}
	want := []EvidenceSegment{}
	end := int64(0)
	for k := 3; k >= 0; k-- {
		if r[k] > end {
			want = append(want, EvidenceSegment{Level: k, FirstSeq: end + 1, LastSeq: r[k], Basis: basis(k)})
			end = r[k]
		}
	}
	if g, w := formulaJSON(ev.Segments), formulaJSON(want); g != w {
		out = append(out, fmt.Sprintf("segments %s, formula %s", g, w))
	}
	// next: below level 3 {L + 1, any at L = 0 else all, the conditions of
	// L + 1 that do not hold, in condition_order}; for level 3, (4) and (7)
	// count as one: both when neither holds, neither when one holds; null
	// at level 3.
	var next *EvidenceNext
	if level < 3 {
		need, of := "all", map[int][]string{0: {"time_witness", "expected_root_found", "receipt_key_confirmed"}, 1: {"receipt_key_confirmed"}, 2: three}[level]
		if level == 0 {
			need = "any"
		}
		next = &EvidenceNext{Level: level + 1, Need: need, Missing: []string{}}
		either := met("time_witness_qualified") || met("log_day_qualified")
		for _, c := range of {
			if !met(c) && !(level == 2 && either && (c == "time_witness_qualified" || c == "log_day_qualified")) {
				next.Missing = append(next.Missing, c)
			}
		}
	}
	if g, w := formulaJSON(ev.Next), formulaJSON(next); g != w {
		out = append(out, fmt.Sprintf("next %s, formula %s", g, w))
	}
	// qualified_time: an object exactly at level 3 (10.10.2), from a met
	// (4) or (7) whose reach reaches up_to_tree_size, latest in the form
	// YYYY-MM-DDThh:mm:ss.sssZ, gap_ms exactly for (7) and at most G_q
	// (10.9.4).
	q := ev.QualifiedTime
	switch {
	case (q != nil) != (level == 3):
		out = append(out, fmt.Sprintf("qualified_time %s at level %d", formulaJSON(q), level))
	case q != nil:
		c := ev.Conditions.Get(q.Via)
		switch {
		case q.Via != "time_witness_qualified" && q.Via != "log_day_qualified", c == nil, !c.Met:
			out = append(out, "qualified_time via "+q.Via+", which is not met")
		case q.TreeSize < upTo || *c.UpToTreeSize < q.TreeSize:
			out = append(out, fmt.Sprintf("qualified_time tree_size %d outside %d to %d", q.TreeSize, upTo, *c.UpToTreeSize))
		case !reMillisTS.MatchString(q.Latest):
			out = append(out, "qualified_time latest "+q.Latest)
		case (q.GapMS != nil) != (q.Via == "log_day_qualified") || q.GapMS != nil && (*q.GapMS < 0 || *q.GapMS > 129_600_000):
			out = append(out, fmt.Sprintf("qualified_time gap_ms %v via %s", formulaVal(q.GapMS), q.Via))
		}
	}
	return strings.Join(out, "; ")
}

func formulaVal[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}

func formulaJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return err.Error()
	}
	return string(b)
}

// TestEvidenceFormulaKAT: the check reproduces the reference values of
// format spec 10.9.5 (KAT2, KAT4, KAT7 and, with condition (7), KAT8 to
// KAT10) and turns red on every member that breaks the formula.
func TestEvidenceFormulaKAT(t *testing.T) {
	cond := func(reach int64) EvidenceCondition {
		if reach == 0 {
			return EvidenceCondition{Reason: strp("no_time_anchor")}
		}
		return EvidenceCondition{Met: true, Count: 1, UpToTreeSize: &reach}
	}
	qt := func(via string, ts int64) *EvidenceQualifiedTime {
		q := &EvidenceQualifiedTime{Via: via, TreeSize: ts, Latest: "2026-08-02T00:10:00.000Z"}
		if via == "log_day_qualified" {
			gap := int64(43_800_000)
			q.GapMS = &gap
		}
		return q
	}
	build := func(n int64, r [7]int64, level int, upTo int64, segs []EvidenceSegment, next *EvidenceNext, q *EvidenceQualifiedTime) *EvidenceLevelStat {
		c := &EvidenceConditions{}
		for i, code := range formulaOrder {
			*c.Get(code) = cond(r[i])
		}
		return &EvidenceLevelStat{State: EvRated, Level: &level, Entries: &n, UpToTreeSize: &upTo, Segments: segs, Conditions: c, Next: next, QualifiedTime: q}
	}
	kat2 := build(5050, [7]int64{5000, 0, 1000, 10, 900, 4990, 0}, 3, 10, []EvidenceSegment{
		{3, 1, 10, []string{"time_witness_qualified"}}, {2, 11, 1000, []string{"receipt_key_confirmed"}},
		{1, 1001, 5000, []string{"time_witness"}}, {0, 5001, 5050, []string{}}}, nil, qt("time_witness_qualified", 10))
	kat4 := build(16, [7]int64{}, 0, 16, []EvidenceSegment{{0, 1, 16, []string{}}},
		&EvidenceNext{1, "any", []string{"time_witness", "expected_root_found", "receipt_key_confirmed"}}, nil)
	kat7 := func() *EvidenceLevelStat {
		return build(320, [7]int64{310, 0, 309, 300, 300, 309, 0}, 3, 300, []EvidenceSegment{
			{3, 1, 300, []string{"time_witness_qualified", "receipts_logged"}}, {2, 301, 309, []string{"receipt_key_confirmed"}},
			{1, 310, 310, []string{"time_witness"}}, {0, 311, 320, []string{}}}, nil, qt("time_witness_qualified", 300))
	}
	kat8 := build(400, [7]int64{0, 0, 396, 0, 300, 390, 350}, 3, 300, []EvidenceSegment{
		{3, 1, 300, []string{"receipts_logged"}}, {2, 301, 396, []string{"receipt_key_confirmed"}}, {0, 397, 400, []string{}}}, nil, qt("log_day_qualified", 350))
	kat9 := build(400, [7]int64{10, 0, 396, 10, 300, 390, 200}, 3, 200, []EvidenceSegment{
		{3, 1, 200, []string{"log_day_qualified"}}, {2, 201, 396, []string{"receipt_key_confirmed"}}, {0, 397, 400, []string{}}}, nil, qt("log_day_qualified", 200))
	kat10 := build(32, [7]int64{0, 0, 28, 0, 28, 28, 0}, 2, 28, []EvidenceSegment{
		{2, 1, 28, []string{"receipt_key_confirmed"}}, {0, 29, 32, []string{}}},
		&EvidenceNext{3, "all", []string{"time_witness_qualified", "log_day_qualified"}}, nil)
	for name, ev := range map[string]*EvidenceLevelStat{"KAT2": kat2, "KAT4": kat4, "KAT7": kat7(), "KAT8": kat8, "KAT9": kat9, "KAT10": kat10} {
		if why := evidenceFormula(ev, *ev.Entries); why != "" {
			t.Errorf("%s: %s", name, why)
		}
	}
	for i, edit := range []func(e *EvidenceLevelStat){
		func(e *EvidenceLevelStat) { e.Segments[0].Basis = []string{"receipts_logged"} },
		func(e *EvidenceLevelStat) { e.Next = &EvidenceNext{Level: 4, Need: "all", Missing: []string{}} },
		func(e *EvidenceLevelStat) { n := int64(1); e.Entries = &n },
		func(e *EvidenceLevelStat) { e.Conditions.TimeWitness.Count = 0; e.Conditions.TimeWitness.Met = false },
		func(e *EvidenceLevelStat) { e.Conditions.LogDayQualified.Count = 2 },
		func(e *EvidenceLevelStat) { l := 2; e.Level = &l },
		func(e *EvidenceLevelStat) { e.QualifiedTime = nil },
		func(e *EvidenceLevelStat) { e.QualifiedTime.TreeSize = 299 },
		func(e *EvidenceLevelStat) { e.QualifiedTime.Latest = "2026-08-02T00:10:00Z" },
		func(e *EvidenceLevelStat) { gap := int64(5); e.QualifiedTime.GapMS = &gap },
		func(e *EvidenceLevelStat) { e.QualifiedTime.Via = "log_day_qualified" },
	} {
		ev := kat7()
		edit(ev)
		if why := evidenceFormula(ev, 320); why == "" {
			t.Errorf("edit %d passed", i)
		}
	}
	for i, edit := range []func(e *EvidenceLevelStat){
		func(e *EvidenceLevelStat) { e.Next.Missing = []string{"time_witness_qualified"} },
		func(e *EvidenceLevelStat) {
			e.QualifiedTime = &EvidenceQualifiedTime{Via: "log_day_qualified", TreeSize: 28, Latest: "2026-08-02T00:10:00.000Z"}
		},
	} {
		ev := build(32, [7]int64{0, 0, 28, 0, 28, 28, 0}, 2, 28, []EvidenceSegment{
			{2, 1, 28, []string{"receipt_key_confirmed"}}, {0, 29, 32, []string{}}},
			&EvidenceNext{3, "all", []string{"time_witness_qualified", "log_day_qualified"}}, nil)
		edit(ev)
		if why := evidenceFormula(ev, 32); why == "" {
			t.Errorf("KAT10 edit %d passed", i)
		}
	}
	gap := int64(129_600_001)
	over := build(400, [7]int64{10, 0, 396, 10, 300, 390, 200}, 3, 200, []EvidenceSegment{
		{3, 1, 200, []string{"log_day_qualified"}}, {2, 201, 396, []string{"receipt_key_confirmed"}}, {0, 397, 400, []string{}}}, nil,
		&EvidenceQualifiedTime{Via: "log_day_qualified", TreeSize: 200, Latest: "2026-08-02T00:10:00.000Z", GapMS: &gap})
	if why := evidenceFormula(over, 400); why == "" {
		t.Error("gap_ms above G_q passed")
	}
	if why := evidenceFormula(&EvidenceLevelStat{State: EvChainInvalid, Segments: []EvidenceSegment{}, Notes: []string{"unsealed_end"}}, 5); why == "" {
		t.Error("notes in the state chain_invalid passed")
	}
}
