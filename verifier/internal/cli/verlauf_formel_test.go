package cli

// The members of stats.evidence_level that an expected file does not carry
// (entries, the basis of each segment, next, the shape of each condition),
// recomputed for each run with an audit environment from the reaches of
// the conditions after format spec 10.9.4, 10.9.5 and 10.10.2, as the
// vector matrix of internal/vfy does for the corpus environment.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"louwietec.com/ledger-verify/verifier/internal/vfy"
)

// verlaufNachFormel checks stats.evidence_level of a JSON report against
// the formula of format spec 10.9.5 and returns what differs.
func verlaufNachFormel(t *testing.T, out string) string {
	t.Helper()
	var r struct {
		Stats struct {
			Entries       int64                  `json:"entries"`
			EvidenceLevel *vfy.EvidenceLevelStat `json:"evidence_level"`
		} `json:"stats"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		return err.Error()
	}
	ev, n := r.Stats.EvidenceLevel, r.Stats.Entries
	if ev == nil {
		return "no evidence_level in a report"
	}
	if ev.State != vfy.EvRated {
		if ev.Level != nil || ev.Entries != nil || ev.UpToTreeSize != nil || ev.Conditions != nil || ev.Next != nil || ev.QualifiedTime != nil || ev.Anchors != nil || len(ev.Segments) != 0 || len(ev.Notes) != 0 {
			return "state " + ev.State + " with a level, conditions, next, qualified_time, anchors, segments or notes (10.10.2)"
		}
		return ""
	}
	var diffs []string
	if ev.Entries == nil || *ev.Entries != n {
		diffs = append(diffs, fmt.Sprintf("entries differ from the %d entries of the package", n))
	}
	if ev.Conditions == nil {
		return strings.Join(append(diffs, "conditions null in the state rated"), "; ")
	}
	order := []string{"time_witness", "expected_root_found", "receipt_key_confirmed", "time_witness_qualified", "receipts_logged", "completeness_from_history", "log_day_qualified"}
	reach := map[string]int64{}
	for _, code := range order {
		c := ev.Conditions.Get(code)
		switch {
		case c.Met && (c.Reason != nil || c.UpToTreeSize == nil || *c.UpToTreeSize < 1):
			diffs = append(diffs, code+": met with a reason or without a reach (10.9.4)")
		case !c.Met && (c.Reason == nil || c.UpToTreeSize != nil || c.Count != 0):
			diffs = append(diffs, code+": not met without a reason, with a reach or with a count (10.9.4)")
		case c.Met:
			reach[code] = min(*c.UpToTreeSize, n)
		}
	}
	met := func(code string) bool { return ev.Conditions.Get(code).Met }
	// 10.9.5: level 3 needs (3), (4) or (7), (5) and (6); of (4) and (7)
	// the larger reach counts. three are the codes of (3) to (7) in
	// condition_order.
	three := []string{"receipt_key_confirmed", "time_witness_qualified", "receipts_logged", "completeness_from_history", "log_day_qualified"}
	rk := [4]int64{n, max(reach["time_witness"], reach["expected_root_found"], reach["receipt_key_confirmed"]), reach["receipt_key_confirmed"], 0}
	if met("receipt_key_confirmed") && (met("time_witness_qualified") || met("log_day_qualified")) && met("receipts_logged") && met("completeness_from_history") {
		rk[3] = min(reach["receipt_key_confirmed"], max(reach["time_witness_qualified"], reach["log_day_qualified"]), reach["receipts_logged"], reach["completeness_from_history"])
	}
	level := 0
	for k := 3; k >= 1 && level == 0; k-- {
		if rk[k] >= 1 {
			level = k
		}
	}
	if ev.Level == nil || *ev.Level != level || ev.UpToTreeSize == nil || *ev.UpToTreeSize != rk[level] {
		diffs = append(diffs, fmt.Sprintf("level or up_to_tree_size differ from level %d up to %d", level, rk[level]))
	}
	basis := func(k int) []string {
		codes := map[int][]string{3: three, 1: {"time_witness", "expected_root_found", "receipt_key_confirmed"}}[k]
		if k == 2 {
			return []string{"receipt_key_confirmed"}
		}
		b := []string{}
		for _, c := range codes {
			if met(c) && reach[c] == rk[k] {
				b = append(b, c)
			}
		}
		return b
	}
	want := []vfy.EvidenceSegment{}
	end := int64(0)
	for k := 3; k >= 0; k-- {
		if rk[k] > end {
			want = append(want, vfy.EvidenceSegment{Level: k, FirstSeq: end + 1, LastSeq: rk[k], Basis: basis(k)})
			end = rk[k]
		}
	}
	var next *vfy.EvidenceNext
	if level < 3 {
		need, of := "all", map[int][]string{0: {"time_witness", "expected_root_found", "receipt_key_confirmed"}, 1: {"receipt_key_confirmed"}, 2: three}[level]
		if level == 0 {
			need = "any"
		}
		next = &vfy.EvidenceNext{Level: level + 1, Need: need, Missing: []string{}}
		// For level 3, (4) and (7) count as one condition: both when
		// neither is met, neither when one is met.
		either := met("time_witness_qualified") || met("log_day_qualified")
		for _, c := range of {
			if !met(c) && !(level == 2 && either && (c == "time_witness_qualified" || c == "log_day_qualified")) {
				next.Missing = append(next.Missing, c)
			}
		}
	}
	// 10.10.2: qualified_time exactly at level 3, from a met (4) or (7)
	// whose item reaches up_to_tree_size; gap_ms exactly for (7), at most
	// G_q = 129 600 000 ms (10.9.4).
	if q := ev.QualifiedTime; (q != nil) != (level == 3) {
		diffs = append(diffs, fmt.Sprintf("qualified_time at level %d: %+v", level, q))
	} else if q != nil {
		c := ev.Conditions.Get(q.Via)
		switch {
		case c == nil || !c.Met || q.Via != "time_witness_qualified" && q.Via != "log_day_qualified":
			diffs = append(diffs, "qualified_time via "+q.Via+", which is not met")
		case q.TreeSize < rk[3] || *c.UpToTreeSize < q.TreeSize:
			diffs = append(diffs, fmt.Sprintf("qualified_time tree_size %d outside %d to %d", q.TreeSize, rk[3], *c.UpToTreeSize))
		case (q.GapMS != nil) != (q.Via == "log_day_qualified") || q.GapMS != nil && (*q.GapMS < 0 || *q.GapMS > 129_600_000):
			diffs = append(diffs, fmt.Sprintf("qualified_time gap_ms %v via %s", q.GapMS, q.Via))
		}
	}
	for _, p := range [][2]any{{ev.Segments, want}, {ev.Next, next}} {
		g, _ := json.Marshal(p[0])
		w, _ := json.Marshal(p[1])
		if string(g) != string(w) {
			diffs = append(diffs, fmt.Sprintf("%s, formula %s", g, w))
		}
	}
	return strings.Join(diffs, "; ")
}

// TestVerlaufNachFormelRotbeweis: the check passes an honest report and
// turns red on a basis, a next and an entries that break the formula.
func TestVerlaufNachFormelRotbeweis(t *testing.T) {
	_, out, _ := lauf(append(append([]string{"--json", "--now-from-package"}, pruefAnker(t)...), vektor("valid_basic"))...)
	if why := verlaufNachFormel(t, out); why != "" {
		t.Fatalf("honest run: %s", why)
	}
	for i, edit := range []func(ev map[string]any){
		func(ev map[string]any) { ev["segments"].([]any)[0].(map[string]any)["basis"] = []any{} },
		func(ev map[string]any) { ev["next"].(map[string]any)["need"] = "any" },
		func(ev map[string]any) { ev["entries"] = 1 },
		func(ev map[string]any) {
			ev["conditions"].(map[string]any)["log_day_qualified"].(map[string]any)["count"] = 1
		},
		// 10.9.5: missing names log_day_qualified when neither (4) nor (7)
		// is met.
		func(ev map[string]any) {
			ev["next"].(map[string]any)["missing"] = []any{"time_witness_qualified", "receipts_logged", "completeness_from_history"}
		},
		// 10.10.2: no qualified_time below level 3.
		func(ev map[string]any) {
			ev["qualified_time"] = map[string]any{"via": "time_witness_qualified", "tree_size": 309, "latest": "2026-01-01T00:00:00.000Z", "gap_ms": nil}
		},
	} {
		var r map[string]any
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatal(err)
		}
		edit(r["stats"].(map[string]any)["evidence_level"].(map[string]any))
		b, _ := json.Marshal(r)
		if why := verlaufNachFormel(t, string(b)); why == "" {
			t.Errorf("edit %d passed", i)
		}
	}
}
