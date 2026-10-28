package vfy

// The evidence level (format spec 10.9) and its report object (10.10.2):
// the rules on the recorded values (evInputs) one by one, then whole runs.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
	"louwietec.com/ledger-verify/verifier/internal/tsa"
)

// ratedInputs is a package of n entries without findings and without any
// anchor: the state rated, every condition missing.
func ratedInputs(n int64) *evInputs {
	return &evInputs{exit: 0, classes: map[string]bool{}, entries: n, pkgSPKI: map[string]bool{}, deviceKeys: map[string]bool{},
		vlStatus: VendorLogNotSupplied, compl: HistoryComplStat{Status: "not_established", Reason: strp("not_supplied")},
		affiliation: &EvidenceAffiliation{Status: AffNotChecked}}
}

// met builds a condition that is met with the reach given.
func met(reach int64) evCond { return evCond{met: true, reach: reach, count: 1} }

// segs renders segments as "level:first-last[basis]" for comparison.
func segs(ss []EvidenceSegment) string {
	var out []string
	for _, s := range ss {
		out = append(out, fmt.Sprintf("%d:%d-%d%v", s.Level, s.FirstSeq, s.LastSeq, s.Basis))
	}
	return strings.Join(out, " ")
}

// katCase is one reference value of 10.9.5 in the form of registry
// verifier.evidence_level.kat.
type katCase struct {
	Case     string           `json:"case"`
	Entries  int64            `json:"entries"`
	Reaches  map[string]int64 `json:"reaches"`
	Level    int              `json:"level"`
	UpTo     int64            `json:"up_to_tree_size"`
	Segments [][]any          `json:"segments"`
	Next     *EvidenceNext    `json:"next"`
}

// katTwoWays are the reference values KAT8 to KAT10 of format spec 10.9.5
// (condition (7) as the second way to level 3), as the table writes them;
// they count where the registry does not carry them yet.
var katTwoWays = []katCase{
	{Case: "KAT8", Entries: 400, Reaches: map[string]int64{CondReceiptKeyConfirmed: 396, CondReceiptsLogged: 300, CondCompleteness: 390, CondLogDayQualified: 350},
		Level: 3, UpTo: 300, Segments: [][]any{{3, 1, 300, []any{CondReceiptsLogged}}, {2, 301, 396, []any{CondReceiptKeyConfirmed}}, {0, 397, 400, []any{}}}},
	{Case: "KAT9", Entries: 400, Reaches: map[string]int64{CondTimeWitness: 10, CondReceiptKeyConfirmed: 396, CondTimeWitnessQualified: 10, CondReceiptsLogged: 300, CondCompleteness: 390, CondLogDayQualified: 200},
		Level: 3, UpTo: 200, Segments: [][]any{{3, 1, 200, []any{CondLogDayQualified}}, {2, 201, 396, []any{CondReceiptKeyConfirmed}}, {0, 397, 400, []any{}}}},
	{Case: "KAT10", Entries: 32, Reaches: map[string]int64{CondReceiptKeyConfirmed: 28, CondReceiptsLogged: 28, CondCompleteness: 28},
		Level: 2, UpTo: 28, Segments: [][]any{{2, 1, 28, []any{CondReceiptKeyConfirmed}}, {0, 29, 32, []any{}}},
		Next: &EvidenceNext{Level: 3, Need: "all", Missing: []string{CondTimeWitnessQualified, CondLogDayQualified}}},
}

// TestEvidenceKAT holds 10.9.5 against its reference values KAT1 to KAT10
// (format spec 10.9.5 table, registry verifier.evidence_level.kat; KAT8 to
// KAT10 from the table where the registry lacks them).
func TestEvidenceKAT(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		Verifier struct {
			EL struct {
				KAT []katCase `json:"kat"`
			} `json:"evidence_level"`
		} `json:"verifier"`
	}
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatal(err)
	}
	if len(reg.Verifier.EL.KAT) < 7 {
		t.Fatalf("registry kat has %d cases", len(reg.Verifier.EL.KAT))
	}
	cases := reg.Verifier.EL.KAT
	have := map[string]bool{}
	for _, k := range cases {
		have[k.Case] = true
	}
	for _, k := range katTwoWays {
		if !have[k.Case] {
			cases = append(cases, k)
		}
	}
	if len(cases) != 10 {
		t.Fatalf("%d reference values, the table of 10.9.5 has 10", len(cases))
	}
	for _, k := range cases {
		t.Run("10.9.5 "+k.Case, func(t *testing.T) {
			conds := map[string]evCond{}
			for c, r := range k.Reaches {
				conds[c] = met(r)
			}
			level, up, ss, next := evLevels(k.Entries, conds)
			var want []string
			for _, s := range k.Segments {
				var basis []string
				for _, b := range s[3].([]any) {
					basis = append(basis, b.(string))
				}
				if basis == nil {
					basis = []string{}
				}
				want = append(want, fmt.Sprintf("%v:%v-%v%v", s[0], s[1], s[2], basis))
			}
			if level != k.Level || up != k.UpTo || segs(ss) != strings.Join(want, " ") {
				t.Errorf("level %d up %d segments %s, want %d %d %s", level, up, segs(ss), k.Level, k.UpTo, strings.Join(want, " "))
			}
			if k.Next != nil && (next == nil || next.Level != k.Next.Level || next.Need != k.Next.Need || strings.Join(next.Missing, ",") != strings.Join(k.Next.Missing, ",")) {
				t.Errorf("next %+v, want %+v", next, k.Next)
			}
			if level == 3 && next != nil {
				t.Errorf("next %+v at level 3", next)
			}
		})
	}
}

// TestEvidenceLevels covers 10.9.5 beyond the reference values: next per
// level, (4) and (7) as the two ways to level 3 (r3, basis, next), and the
// properties of the segments (10.9.7 number 4).
func TestEvidenceLevels(t *testing.T) {
	cases := []struct {
		name  string
		n     int64
		conds map[string]evCond
		level int
		up    int64
		segs  string
		next  string
	}{
		{"10.9.5 level 0: next any of (1) to (3)", 16, nil, 0, 16, "0:1-16[]", "1 any [time_witness expected_root_found receipt_key_confirmed]"},
		{"10.9.5 level 1 by (2): next all, (3)", 32, map[string]evCond{CondExpectedRootFound: met(14)}, 1, 14, "1:1-14[expected_root_found] 0:15-32[]", "2 all [receipt_key_confirmed]"},
		{"10.9.5 level 2: next names the missing of level 3, (4) and (7) both when neither is met", 20, map[string]evCond{CondReceiptKeyConfirmed: met(20), CondReceiptsLogged: met(20)}, 2, 20, "2:1-20[receipt_key_confirmed]",
			"3 all [time_witness_qualified completeness_from_history log_day_qualified]"},
		{"10.9.5 level 2 with (7) met: next names neither (4) nor (7)", 10, map[string]evCond{CondReceiptKeyConfirmed: met(10), CondLogDayQualified: met(10)}, 2, 10, "2:1-10[receipt_key_confirmed]",
			"3 all [receipts_logged completeness_from_history]"},
		{"10.9.5 level 2 with (4) met: next names neither (4) nor (7)", 10, map[string]evCond{CondReceiptKeyConfirmed: met(10), CondTimeWitnessQualified: met(10), CondCompleteness: met(10)}, 2, 10, "2:1-10[receipt_key_confirmed]",
			"3 all [receipts_logged]"},
		{"10.9.5 level 3 to N: no next, no level-0 segment", 10, map[string]evCond{CondReceiptKeyConfirmed: met(10), CondTimeWitnessQualified: met(10), CondReceiptsLogged: met(10), CondCompleteness: met(10)}, 3, 10,
			"3:1-10[receipt_key_confirmed time_witness_qualified receipts_logged completeness_from_history]", ""},
		{"10.9.1 (7) alone gives no level: it is no condition of level 1", 10, map[string]evCond{CondLogDayQualified: met(10)}, 0, 10, "0:1-10[]", "1 any [time_witness expected_root_found receipt_key_confirmed]"},
		{"10.9.1 level 3 through (7): (3), (7), (5) and (6)", 10, map[string]evCond{CondReceiptKeyConfirmed: met(10), CondReceiptsLogged: met(10), CondCompleteness: met(10), CondLogDayQualified: met(10)}, 3, 10,
			"3:1-10[receipt_key_confirmed receipts_logged completeness_from_history log_day_qualified]", ""},
		{"10.9.5 (4) and (7) both met: the larger reach counts", 20, map[string]evCond{CondReceiptKeyConfirmed: met(20), CondTimeWitnessQualified: met(5), CondReceiptsLogged: met(20), CondCompleteness: met(20), CondLogDayQualified: met(12)}, 3, 12,
			"3:1-12[log_day_qualified] 2:13-20[receipt_key_confirmed]", ""},
		{"10.9.5 basis at level 3: every met code of (3) to (7) whose reach equals r3", 20, map[string]evCond{CondReceiptKeyConfirmed: met(20), CondTimeWitnessQualified: met(8), CondReceiptsLogged: met(8), CondCompleteness: met(20), CondLogDayQualified: met(12)}, 3, 8,
			"3:1-8[time_witness_qualified receipts_logged] 2:9-20[receipt_key_confirmed]", ""},
		{"10.9.5 r3 is 0 without (5) even with (4) and (7)", 10, map[string]evCond{CondReceiptKeyConfirmed: met(10), CondTimeWitnessQualified: met(10), CondCompleteness: met(10), CondLogDayQualified: met(10)}, 2, 10,
			"2:1-10[receipt_key_confirmed]", "3 all [receipts_logged]"},
		{"10.9.5 r3 is 0 unless (3), (5), (6) and one of (4) and (7) are met", 10, map[string]evCond{CondReceiptKeyConfirmed: met(9), CondTimeWitnessQualified: met(9), CondReceiptsLogged: met(9)}, 2, 9, "2:1-9[receipt_key_confirmed] 0:10-10[]", "3 all [completeness_from_history]"},
		{"10.9.5 level 1 basis: every met code with reach r1", 10, map[string]evCond{CondTimeWitness: met(8), CondExpectedRootFound: met(8), CondReceiptKeyConfirmed: met(5)}, 2, 5,
			"2:1-5[receipt_key_confirmed] 1:6-8[time_witness expected_root_found] 0:9-10[]", "3 all [time_witness_qualified receipts_logged completeness_from_history log_day_qualified]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conds := c.conds
			if conds == nil {
				conds = map[string]evCond{}
			}
			level, up, ss, next := evLevels(c.n, conds)
			nx := ""
			if next != nil {
				nx = fmt.Sprintf("%d %s %v", next.Level, next.Need, next.Missing)
			}
			if level != c.level || up != c.up || segs(ss) != c.segs || nx != c.next {
				t.Errorf("got %d %d %q %q, want %d %d %q %q", level, up, segs(ss), nx, c.level, c.up, c.segs, c.next)
			}
			// 10.9.7 number 4: the segments cover 1 to N, levels fall
			// strictly, the first has the level.
			var at int64 = 1
			for i, s := range ss {
				if s.FirstSeq != at || s.LastSeq < s.FirstSeq || i > 0 && s.Level >= ss[i-1].Level {
					t.Errorf("segments %s break 10.9.7 number 4", segs(ss))
				}
				at = s.LastSeq + 1
			}
			if at != c.n+1 || ss[0].Level != level {
				t.Errorf("segments %s do not cover 1 to %d from level %d", segs(ss), c.n, level)
			}
		})
	}
}

// TestEvidenceState is the table of 10.9.2 with the null rules of 10.10.2.
func TestEvidenceState(t *testing.T) {
	cases := []struct {
		name     string
		exit     int
		classes  []string
		state    string
		material bool
	}{
		{"10.9.2 exit 3: format_error", 3, []string{ClsFormatError}, EvFormatError, false},
		{"10.9.2 exit 2 from SIG_INVALID: chain_invalid", 2, []string{ClsSigInvalid}, EvChainInvalid, false},
		{"10.9.2 exit 2 from a material class and another: chain_invalid", 2, []string{ClsContentMismatch, ClsForkDetected}, EvChainInvalid, false},
		{"10.9.2 exit 2 only from material_classes: rated", 2, []string{ClsContentMismatch, ClsReportMismatch, ClsUnsealedEnd}, EvRated, true},
		{"10.9.2 exit 4: rated", 4, []string{ClsUnsealedEnd}, EvRated, false},
		{"10.9.2 exit 1: rated", 1, []string{ClsNoAnchor}, EvRated, false},
		{"10.9.2 exit 1 from the vendor log and the anchor history: rated", 1, []string{ClsReceiptNotLogged, ClsLoggedRootMismatch, ClsHistoryFork, ClsHistoryContradict}, EvRated, false},
		{"10.9.2 exit 0: rated", 0, nil, EvRated, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := ratedInputs(5)
			in.exit = c.exit
			for _, k := range c.classes {
				in.classes[k] = true
			}
			if c.exit == 3 {
				in.affiliation = nil
			}
			ev := evaluateEvidence(in)
			if ev.State != c.state || ev.text.material != c.material {
				t.Fatalf("state %s material %v, want %s %v", ev.State, ev.text.material, c.state, c.material)
			}
			rated := c.state == EvRated
			if rated != (ev.Level != nil && ev.Entries != nil && ev.UpToTreeSize != nil && ev.Conditions != nil && ev.Next != nil && ev.Anchors != nil) {
				t.Errorf("10.10.2: level, entries, up_to_tree_size, conditions, next, anchors null outside rated: %+v", ev)
			}
			if !rated && (len(ev.Segments) != 0 || len(ev.Notes) != 0) {
				t.Errorf("10.10.2: segments and notes empty outside rated")
			}
			if (ev.Affiliation == nil) != (c.state == EvFormatError) {
				t.Errorf("10.10.2: affiliation null only for format_error, got %+v", ev.Affiliation)
			}
			if c.material != (indexOf(ev.Notes, ntMaterialContradiction) >= 0) {
				t.Errorf("10.9.6 material_contradiction: notes %v", ev.Notes)
			}
			b, _ := json.Marshal(ev)
			if !strings.Contains(string(b), `"segments":[]`) && !rated {
				t.Errorf("segments must be [] in JSON: %s", b)
			}
		})
	}
}

// witness is a TIME_ANCHOR that passes every stage of (1) and (4) for the
// root "Q": signature checked, a path, no test key, Z.6 bound, QS present.
func witness(treeSize int64, roots ...string) evWitness {
	w := evWitness{seq: treeSize + 2, treeSize: treeSize, checked: true, valid: true, genTime: time.Date(2026, 8, 1, 8, 2, 0, 0, time.UTC),
		paths: map[string]bool{}, z6: tsa.Z6Bound, qs: tsa.QSPresent}
	for _, r := range roots {
		w.paths[r] = true
	}
	return w
}

// qroot is a root of the purposes chain and qualified from 2026-01-01.
func qroot(sha string) evRoot {
	return evRoot{certSHA: sha, spki: "spki-" + sha, chain: true, qualified: true, from: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

// TestConditionTimeWitness is condition (1) of 10.9.4: the reasons without
// item, every stage, and that stages of different roots never combine.
func TestConditionTimeWitness(t *testing.T) {
	chain := evRoot{certSHA: "C", spki: "spki-C", chain: true}
	cases := []struct {
		name   string
		edit   func(in *evInputs)
		met    bool
		reason string
		reach  int64
		count  int
	}{
		{"10.9.4 (1) no_time_anchor", func(in *evInputs) {}, false, rsNoTimeAnchor, 0, 0},
		{"10.9.4 (1) no_tsa_root_supplied: a root only for the log", func(in *evInputs) {
			in.timeAnchors, in.witnesses = 1, []evWitness{witness(4, "L")}
			in.roots = []evRoot{{certSHA: "L", log: true}}
		}, false, rsNoTSARoot, 0, 0},
		{"10.9.4 (1) signature_not_checkable", func(in *evInputs) {
			w := witness(4, "C")
			w.checked, w.valid = false, false
			in.timeAnchors, in.witnesses, in.roots = 1, []evWitness{w}, []evRoot{chain}
		}, false, rsSignatureNotCheckable, 0, 0},
		{"10.9.4 (1) not_chained_to_auditor_root", func(in *evInputs) {
			in.timeAnchors, in.witnesses, in.roots = 1, []evWitness{witness(4, "X")}, []evRoot{chain}
		}, false, rsNotChainedAuditor, 0, 0},
		{"10.9.4 (1) published_test_key of the signer", func(in *evInputs) {
			w := witness(4, "C")
			w.signerTestKey = true
			in.timeAnchors, in.witnesses, in.roots = 1, []evWitness{w}, []evRoot{chain}
		}, false, rsPublishedTestKey, 0, 0},
		{"10.9.4 (1) published_test_key of the root", func(in *evInputs) {
			r := chain
			r.testKey = true
			in.timeAnchors, in.witnesses, in.roots = 1, []evWitness{witness(4, "C")}, []evRoot{r}
		}, false, rsPublishedTestKey, 0, 0},
		{"10.9.4 (1) token_extensions_unusable", func(in *evInputs) {
			w := witness(4, "C")
			w.qs = tsa.QSUnusable
			in.timeAnchors, in.witnesses, in.roots = 1, []evWitness{w}, []evRoot{chain}
		}, false, rsTokenExtUnusable, 0, 0},
		{"10.9.4 (1) QS absent or malformed does not matter", func(in *evInputs) {
			a, b := witness(4, "C"), witness(7, "C")
			a.qs, b.qs = tsa.QSAbsent, tsa.QSMalformed
			in.timeAnchors, in.witnesses, in.roots = 2, []evWitness{a, b}, []evRoot{chain}
		}, true, "", 7, 2},
		{"10.9.4 (1) the reason is the stage of max(s) over all pairs", func(in *evInputs) {
			a := witness(4, "X")
			b := witness(5, "C")
			b.signerTestKey = true
			in.timeAnchors, in.witnesses, in.roots = 2, []evWitness{a, b}, []evRoot{chain}
		}, false, rsPublishedTestKey, 0, 0},
		{"10.9.4 (1) stages of different roots are never combined", func(in *evInputs) {
			// A path to C, and D is no test key, but the pair with D has no
			// path and the pair with C is a test key.
			c := chain
			c.testKey = true
			d := evRoot{certSHA: "D", spki: "spki-D", chain: true}
			in.timeAnchors, in.witnesses, in.roots = 1, []evWitness{witness(4, "C")}, []evRoot{c, d}
		}, false, rsPublishedTestKey, 0, 0},
		{"10.9.4 (1) credited: reach the largest tree_size, count the TIME_ANCHOR entries", func(in *evInputs) {
			in.timeAnchors, in.witnesses, in.roots = 3, []evWitness{witness(4, "C"), witness(9, "C", "D"), witness(12, "X")},
				[]evRoot{chain, {certSHA: "D", spki: "spki-D", chain: true}}
		}, true, "", 9, 2},
		{"10.9.4 (1) a qualified root counts for the purpose chain", func(in *evInputs) {
			in.timeAnchors, in.witnesses, in.roots = 1, []evWitness{witness(4, "Q")}, []evRoot{qroot("Q")}
		}, true, "", 4, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := ratedInputs(20)
			c.edit(in)
			got, _ := condTimeWitness(in)
			if got.met != c.met || got.reason != c.reason || c.met && (got.reach != c.reach || got.count != c.count) {
				t.Errorf("got %+v, want met %v reason %q reach %d count %d", got, c.met, c.reason, c.reach, c.count)
			}
		})
	}
}

// TestConditionTimeWitnessQualified is condition (4) of 10.9.4, every stage
// in table order, the window on nanoseconds and the priority of malformed.
func TestConditionTimeWitnessQualified(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		edit   func(in *evInputs, w *evWitness, r *evRoot)
		reason string
	}{
		{"10.9.4 (4) credited", func(in *evInputs, w *evWitness, r *evRoot) {}, ""},
		{"10.9.4 (4) no_qualified_root_supplied: a root of the purpose chain only", func(in *evInputs, w *evWitness, r *evRoot) { r.qualified = false }, rsNoQualifiedRoot},
		{"10.9.4 (4) signature_not_checkable: 5a", func(in *evInputs, w *evWitness, r *evRoot) { w.checked, w.valid = false, false }, rsSignatureNotCheckable},
		{"10.9.4 (4) signature_not_checkable: Z.6 not checkable", func(in *evInputs, w *evWitness, r *evRoot) { w.z6 = tsa.Z6NotCheckable }, rsSignatureNotCheckable},
		{"10.9.4 (4) not_chained_to_qualified_root", func(in *evInputs, w *evWitness, r *evRoot) { w.paths = map[string]bool{} }, rsNotChainedQualified},
		{"10.9.4 (4) published_test_key", func(in *evInputs, w *evWitness, r *evRoot) { r.testKey = true }, rsPublishedTestKey},
		{"10.9.4 (4) qualified_root_in_package", func(in *evInputs, w *evWitness, r *evRoot) { in.pkgSPKI[r.spki] = true }, rsQualifiedRootInPackage},
		{"10.9.4 (4) outside_qualified_window: before qualifiziert_ab by one nanosecond", func(in *evInputs, w *evWitness, r *evRoot) { w.genTime = from.Add(-time.Nanosecond) }, rsOutsideWindow},
		{"10.9.4 (4) inside: genTime equal to qualifiziert_ab", func(in *evInputs, w *evWitness, r *evRoot) { w.genTime = from }, ""},
		{"10.9.4 (4) outside_qualified_window: genTime equal to qualifiziert_bis", func(in *evInputs, w *evWitness, r *evRoot) { r.until = w.genTime }, rsOutsideWindow},
		{"10.9.4 (4) inside: one nanosecond before qualifiziert_bis", func(in *evInputs, w *evWitness, r *evRoot) { r.until = w.genTime.Add(time.Nanosecond) }, ""},
		{"10.9.4 (4) signing_certificate_not_bound", func(in *evInputs, w *evWitness, r *evRoot) { w.z6 = tsa.Z6Violated }, rsSigningCertNotBound},
		{"10.9.4 (4) token_extensions_unusable", func(in *evInputs, w *evWitness, r *evRoot) { w.qs = tsa.QSUnusable }, rsTokenExtUnusable},
		{"10.9.4 (4) qualified_statement malformed", func(in *evInputs, w *evWitness, r *evRoot) { w.qs = tsa.QSMalformed }, rsQSMalformed},
		{"10.9.4 (4) qualified_statement absent", func(in *evInputs, w *evWitness, r *evRoot) { w.qs = tsa.QSAbsent }, rsNoQS},
		{"10.9.4 (4) the stage order: Z.6 violated before QS", func(in *evInputs, w *evWitness, r *evRoot) { w.z6, w.qs = tsa.Z6Violated, tsa.QSAbsent }, rsSigningCertNotBound},
		{"10.9.4 (4) the stage order: in the package before outside the window", func(in *evInputs, w *evWitness, r *evRoot) {
			in.pkgSPKI[r.spki] = true
			w.genTime = from.Add(-time.Hour)
		}, rsQualifiedRootInPackage},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := ratedInputs(20)
			w, r := witness(6, "Q"), qroot("Q")
			c.edit(in, &w, &r)
			in.timeAnchors, in.witnesses, in.roots = 1, []evWitness{w}, []evRoot{r}
			got, credited, cands := condTimeWitnessQualified(in)
			if c.reason == "" {
				if !got.met || got.reach != 6 || got.count != 1 || !credited["Q"] {
					t.Errorf("got %+v %v, want credited", got, credited)
				}
				// 10.10.2: the credited pair is a candidate for qualified_time.
				if len(cands) != 1 || cands[0].via != CondTimeWitnessQualified || cands[0].treeSize != 6 || !cands[0].genTime.Equal(w.genTime) {
					t.Errorf("candidates %+v", cands)
				}
				// 10.9.4: an item credited for (4) is credited for (1).
				if c1, _ := condTimeWitness(in); !c1.met {
					t.Errorf("(4) credited, (1) not: %+v", c1)
				}
				return
			}
			if got.met || got.reason != c.reason {
				t.Errorf("got %+v, want %s", got, c.reason)
			}
		})
	}
	t.Run("10.9.4 (4) at qualified_statement malformed goes before absent", func(t *testing.T) {
		in := ratedInputs(20)
		a, b := witness(6, "Q"), witness(7, "Q")
		a.qs, b.qs = tsa.QSAbsent, tsa.QSMalformed
		in.timeAnchors, in.witnesses, in.roots = 2, []evWitness{a, b}, []evRoot{qroot("Q")}
		if got, _, _ := condTimeWitnessQualified(in); got.reason != rsQSMalformed {
			t.Errorf("got %+v", got)
		}
	})
	t.Run("10.9.4 (4) no_time_anchor first", func(t *testing.T) {
		in := ratedInputs(20)
		in.roots = []evRoot{qroot("Q")}
		if got, _, _ := condTimeWitnessQualified(in); got.reason != rsNoTimeAnchor {
			t.Errorf("got %+v", got)
		}
	})
}

// TestConditionExpectedRootFound is condition (2) of 10.9.4.
func TestConditionExpectedRootFound(t *testing.T) {
	cases := []struct {
		name    string
		found   []evFound
		met     bool
		reach   int64
		count   int
		sources string
	}{
		{"10.9.4 (2) no_expected_root_found", nil, false, 0, 0, ""},
		{"10.9.4 (2) a root of the auditor", []evFound{{foundAt: 8, root: "a", auditor: true}}, true, 8, 1, "auditor"},
		{"10.9.4 (2) roots of both sources, reach the largest found_at", []evFound{{foundAt: 8, root: "a", history: true}, {foundAt: 5, root: "b", auditor: true}}, true, 8, 2, "auditor,anchor_history"},
		{"10.10.1 (2) one pair from both sources", []evFound{{foundAt: 8, root: "a", auditor: true, history: true}}, true, 8, 1, "auditor,anchor_history"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := ratedInputs(20)
			in.found = c.found
			got, src := condExpectedRootFound(in)
			if got.met != c.met || got.met && (got.reach != c.reach || got.count != c.count) || strings.Join(src, ",") != c.sources {
				t.Errorf("got %+v %v", got, src)
			}
			if !c.met && got.reason != rsNoExpectedRoot {
				t.Errorf("reason %q", got.reason)
			}
		})
	}
}

// TestConditionReceiptKeyConfirmed is condition (3) of 10.9.4.
func TestConditionReceiptKeyConfirmed(t *testing.T) {
	ok := func(seq, ts int64) evReceipt {
		return evReceipt{seq: seq, treeSize: ts, keyID: "v1", pub: strings.Repeat("ab", 32), via: keyViaPinned, established: true}
	}
	cases := []struct {
		name     string
		receipts []evReceipt
		device   string
		reason   string
		reach    int64
		count    int
	}{
		{"10.9.4 (3) no_receipt", nil, "", rsNoReceipt, 0, 0},
		{"10.9.4 (3) key_not_confirmed: key only from the manifest", []evReceipt{{seq: 3, treeSize: 2, via: keyViaManifest}}, "", rsKeyNotConfirmed, 0, 0},
		{"10.9.4 (3) key_is_device_key", []evReceipt{ok(3, 2)}, strings.Repeat("AB", 32), rsKeyIsDeviceKey, 0, 0},
		{"10.9.4 (3) max(s): one not confirmed, one device key", []evReceipt{{seq: 3, treeSize: 2, via: keyViaManifest}, ok(5, 4)}, strings.Repeat("ab", 32), rsKeyIsDeviceKey, 0, 0},
		{"10.9.4 (3) credited: reach the largest tree_size, count the receipts", []evReceipt{ok(3, 2), {seq: 5, treeSize: 9, via: keyViaManifest}, ok(7, 6), ok(8, 6)}, "", "", 6, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := ratedInputs(20)
			in.receipts = c.receipts
			if c.device != "" {
				in.deviceKeys[strings.ToLower(c.device)] = true
			}
			got, credited := condReceiptKeyConfirmed(in)
			if c.reason != "" {
				if got.met || got.reason != c.reason || len(credited) != 0 {
					t.Errorf("got %+v", got)
				}
				return
			}
			if !got.met || got.reach != c.reach || got.count != c.count || len(credited) != c.count {
				t.Errorf("got %+v", got)
			}
		})
	}
}

// l8 is a receipt of step L8 with its class.
// Its server_ts lies 12 h 10 min before the genTime of stamp(), within G_q.
func l8(seq, ts int64, class string, sub ...string) evL8 {
	x := evL8{seq: seq, treeSize: ts, class: class, serverTS: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)}
	if len(sub) > 0 {
		x.sub = sub[0]
	}
	return x
}

// TestConditionReceiptsLogged is condition (5) of 10.9.4 with the table "Zu
// (5), je Quittung", r5', the cap at t_m and the order of the reasons.
func TestConditionReceiptsLogged(t *testing.T) {
	cases := []struct {
		name   string
		edit   func(in *evInputs)
		reason string
		reach  int64
		count  int
	}{
		{"10.9.4 (5) vendor_log_not_supplied", func(in *evInputs) {}, rsVLNotSupplied, 0, 0},
		{"10.9.4 (5) vendor_log_not_established", func(in *evInputs) { in.vlStatus = VendorLogNoProtocolKey }, rsVLNotEstablished, 0, 0},
		{"10.9.4 (5) vendor_log_contradiction before no_receipt", func(in *evInputs) { in.vlStatus, in.vlContradiction = VendorLogChecked, true }, rsVLContradiction, 0, 0},
		{"10.9.4 (5) no_receipt", func(in *evInputs) { in.vlStatus = VendorLogChecked }, rsNoReceipt, 0, 0},
		{"10.9.4 (5) receipts_before_log_start", func(in *evInputs) {
			in.vlStatus, in.l8 = VendorLogChecked, []evL8{l8(3, 2, RcBeforeStart), l8(5, 4, RcBeforeStart)}
		}, rsReceiptsBeforeStart, 0, 0},
		{"10.9.4 (5) met: neutral then good", func(in *evInputs) {
			in.vlStatus, in.l8 = VendorLogChecked, []evL8{l8(3, 2, RcBeforeStart), l8(5, 4, RcIncluded), l8(7, 6, RcIncluded)}
		}, "", 6, 2},
		{"10.9.4 (5) the reach ends before the first bad receipt", func(in *evInputs) {
			in.vlStatus, in.l8 = VendorLogChecked, []evL8{l8(3, 2, RcIncluded), l8(5, 4, RcPending), l8(7, 6, RcIncluded)}
		}, "", 2, 1},
		{"10.9.4 (5) r5' by tree_size, not chain order", func(in *evInputs) {
			in.vlStatus, in.l8 = VendorLogChecked, []evL8{l8(3, 6, RcIncluded), l8(5, 4, RcMissing), l8(7, 2, RcIncluded)}
		}, "", 2, 1},
		{"10.9.4 (5) the code of the foremost bad receipt in chain order", func(in *evInputs) {
			in.vlStatus, in.l8 = VendorLogChecked, []evL8{l8(3, 6, RcPending), l8(5, 2, RcNotIncluded)}
		}, rsReceiptDayNotClosed, 0, 0},
		{"10.9.4 (5) day_not_witnessed gives day_timestamp_not_confirmed", func(in *evInputs) {
			in.vlStatus, in.l8 = VendorLogChecked, []evL8{l8(3, 2, RcUnchecked, UcDayNotWitnessed)}
		}, rsDayStampNotConfirmed, 0, 0},
		{"10.9.4 (5) another unchecked gives receipt_not_checkable", func(in *evInputs) {
			in.vlStatus, in.l8 = VendorLogChecked, []evL8{l8(3, 2, RcUnchecked, UcNoRecord)}
		}, rsReceiptNotCheckable, 0, 0},
		{"10.9.4 (5) missing", func(in *evInputs) { in.vlStatus, in.l8 = VendorLogChecked, []evL8{l8(3, 2, RcMissing)} }, rsLogDayNotSupplied, 0, 0},
		{"10.9.4 (5) future", func(in *evInputs) { in.vlStatus, in.l8 = VendorLogChecked, []evL8{l8(3, 2, RcFuture)} }, rsReceiptAfterCheckTime, 0, 0},
		{"10.9.4 (5) not_included", func(in *evInputs) {
			in.vlStatus, in.l8 = VendorLogChecked, []evL8{l8(3, 2, RcNotIncluded), l8(5, 4, RcIncluded)}
		}, rsReceiptNotLogged, 0, 0},
		{"10.9.4 (5) cap: min(r5', t_m - 1)", func(in *evInputs) {
			in.vlStatus, in.tM, in.l8 = VendorLogChecked, 5, []evL8{l8(3, 2, RcIncluded), l8(7, 6, RcIncluded)}
		}, "", 4, 1},
		{"10.9.4 (5) logged_root_mismatch when the cap sets the reach to 0", func(in *evInputs) {
			in.vlStatus, in.tM, in.l8 = VendorLogChecked, 1, []evL8{l8(3, 2, RcIncluded)}
		}, rsLoggedRootMismatch, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := ratedInputs(20)
			c.edit(in)
			got := condReceiptsLogged(in)
			if c.reason != "" {
				if got.met || got.reason != c.reason {
					t.Errorf("got %+v, want %s", got, c.reason)
				}
				return
			}
			if !got.met || got.reach != c.reach || got.count != c.count {
				t.Errorf("got %+v, want reach %d count %d", got, c.reach, c.count)
			}
		})
	}
}

// TestConditionCompleteness is condition (6) of 10.9.4: met exactly when
// anchor_history.completeness is established, else the reason after the
// table, held against registry from_completeness.
func TestConditionCompleteness(t *testing.T) {
	six := conditionSixReasons(t)
	for reason, code := range six {
		t.Run("10.9.4 (6) "+reason, func(t *testing.T) {
			in := ratedInputs(20)
			in.compl = HistoryComplStat{Status: "not_established", Reason: strp(reason)}
			got := condCompleteness(in)
			if code == nil {
				if _, ok := evFromCompleteness[reason]; ok {
					t.Errorf("%s maps to a code, registry null", reason)
				}
				return
			}
			if got.met || got.reason != *code || evFromCompleteness[reason] != *code {
				t.Errorf("got %+v, registry %s", got, *code)
			}
		})
	}
	if len(evFromCompleteness)+1 != len(six) {
		t.Errorf("mirror %v, registry %v", evFromCompleteness, six)
	}
	in := ratedInputs(20)
	up := int64(12)
	in.compl, in.historyFound = HistoryComplStat{Status: "established", UpToTreeSize: &up}, 3
	if got := condCompleteness(in); !got.met || got.reach != 12 || got.count != 3 {
		t.Errorf("established: %+v", got)
	}
}

// stamp is a time stamp of c(d) that passes every stage of (7) for "QL".
func stamp() evDayStamp {
	return evDayStamp{checked: true, genTime: time.Date(2026, 8, 2, 0, 10, 0, 0, time.UTC), paths: map[string]bool{"QL": true}, qs: tsa.QSPresent}
}

// TestConditionLogDayQualified is condition (7) of 10.9.4, the second way
// to level 3: the reasons without item, every stage in table order with
// qualified_day_stamp_gap after qualified_day_stamp_late, and the limit
// G_q = 129 600 000 ms on whole milliseconds.
func TestConditionLogDayQualified(t *testing.T) {
	qlRoot := func() evRoot { r := qroot("QL"); r.log = true; return r }
	gq := time.Duration(evQualifiedGapMS) * time.Millisecond
	cases := []struct {
		name   string
		edit   func(in *evInputs, s *evDayStamp, r *evRoot)
		reason string
		reach  int64
		count  int
	}{
		{"10.9.4 (7) credited", func(in *evInputs, s *evDayStamp, r *evRoot) {}, "", 6, 2},
		{"10.9.4 (7) vendor_log_not_supplied", func(in *evInputs, s *evDayStamp, r *evRoot) { in.vlStatus = VendorLogNotSupplied }, rsVLNotSupplied, 0, 0},
		{"10.9.4 (7) vendor_log_not_established", func(in *evInputs, s *evDayStamp, r *evRoot) { in.vlStatus = VendorLogNoProtocolKey }, rsVLNotEstablished, 0, 0},
		{"10.9.4 (7) vendor_log_contradiction", func(in *evInputs, s *evDayStamp, r *evRoot) { in.vlContradiction = true }, rsVLContradiction, 0, 0},
		{"10.9.4 (7) no_qualified_log_root_supplied: qualified, not log", func(in *evInputs, s *evDayStamp, r *evRoot) { r.log = false }, rsNoQualifiedLogRoot, 0, 0},
		{"10.9.4 (7) no_qualified_log_root_supplied: log, not qualified", func(in *evInputs, s *evDayStamp, r *evRoot) { r.qualified = false }, rsNoQualifiedLogRoot, 0, 0},
		{"10.9.4 (7) no_receipt_included", func(in *evInputs, s *evDayStamp, r *evRoot) { in.l8[0].class, in.l8[1].class = RcPending, RcMissing }, rsNoReceiptIncluded, 0, 0},
		{"10.9.4 (7) signature_not_checkable", func(in *evInputs, s *evDayStamp, r *evRoot) { s.checked = false }, rsSignatureNotCheckable, 0, 0},
		{"10.9.4 (7) not_chained_to_qualified_log_root", func(in *evInputs, s *evDayStamp, r *evRoot) { s.paths = map[string]bool{} }, rsNotChainedQualifiedLog, 0, 0},
		{"10.9.4 (7) published_test_key", func(in *evInputs, s *evDayStamp, r *evRoot) { s.signerTestKey = true }, rsPublishedTestKey, 0, 0},
		{"10.9.4 (7) no stage qualified_root_in_package", func(in *evInputs, s *evDayStamp, r *evRoot) { in.pkgSPKI[r.spki] = true }, "", 6, 2},
		{"10.9.4 (7) outside_qualified_window", func(in *evInputs, s *evDayStamp, r *evRoot) { r.from = s.genTime.Add(time.Nanosecond) }, rsOutsideWindow, 0, 0},
		{"10.9.4 (7) qualified_day_stamp_late", func(in *evInputs, s *evDayStamp, r *evRoot) { s.late = true }, rsDayStampLate, 0, 0},
		{"10.9.4 (7) qualified_day_stamp_gap: G_q + 1 ms after both receipts", func(in *evInputs, s *evDayStamp, r *evRoot) {
			in.l8[0].serverTS = s.genTime.Add(-gq - time.Millisecond)
			in.l8[1].serverTS = s.genTime.Add(-gq - time.Millisecond)
		}, rsDayStampGap, 0, 0},
		{"10.9.4 (7) gap exactly G_q: credited (at most G_q)", func(in *evInputs, s *evDayStamp, r *evRoot) {
			in.l8[0].serverTS = s.genTime.Add(-gq)
			in.l8[1].serverTS = s.genTime.Add(-gq)
		}, "", 6, 2},
		{"10.9.4 (7) gap on whole milliseconds: genTime G_q + 0.9 ms after server_ts is credited", func(in *evInputs, s *evDayStamp, r *evRoot) {
			s.genTime = s.genTime.Add(900 * time.Microsecond)
			in.l8[0].serverTS = s.genTime.Add(-gq - 900*time.Microsecond)
			in.l8[1].serverTS = in.l8[0].serverTS
		}, "", 6, 2},
		{"10.9.4 (7) gap per receipt: only the receipt within G_q is credited", func(in *evInputs, s *evDayStamp, r *evRoot) {
			in.l8[1].serverTS = s.genTime.Add(-gq - time.Second)
		}, "", 2, 1},
		{"10.9.4 (7) stage order: late before gap", func(in *evInputs, s *evDayStamp, r *evRoot) {
			s.late = true
			in.l8[0].serverTS, in.l8[1].serverTS = s.genTime.Add(-2*gq), s.genTime.Add(-2*gq)
		}, rsDayStampLate, 0, 0},
		{"10.9.4 (7) stage order: gap before token_extensions_unusable", func(in *evInputs, s *evDayStamp, r *evRoot) {
			s.qs = tsa.QSUnusable
			in.l8[0].serverTS, in.l8[1].serverTS = s.genTime.Add(-2*gq), s.genTime.Add(-2*gq)
		}, rsDayStampGap, 0, 0},
		{"10.9.4 (7) token_extensions_unusable", func(in *evInputs, s *evDayStamp, r *evRoot) { s.qs = tsa.QSUnusable }, rsTokenExtUnusable, 0, 0},
		{"10.9.4 (7) qualified_statement_malformed", func(in *evInputs, s *evDayStamp, r *evRoot) { s.qs = tsa.QSMalformed }, rsQSMalformed, 0, 0},
		{"10.9.4 (7) no_qualified_statement", func(in *evInputs, s *evDayStamp, r *evRoot) { s.qs = tsa.QSAbsent }, rsNoQS, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := ratedInputs(20)
			in.vlStatus = VendorLogChecked
			s, r := stamp(), qlRoot()
			in.l8 = []evL8{l8(3, 2, RcIncluded), l8(7, 6, RcIncluded)}
			c.edit(in, &s, &r)
			in.l8[0].stamps, in.l8[1].stamps = []evDayStamp{s}, []evDayStamp{s}
			in.roots = []evRoot{r}
			got, credited, cands := condLogDayQualified(in)
			if c.reason == "" {
				if !got.met || got.reach != c.reach || got.count != c.count || !credited["QL"] || len(cands) != c.count {
					t.Errorf("got %+v %v %d candidates, want reach %d count %d", got, credited, len(cands), c.reach, c.count)
				}
				for _, x := range cands {
					if x.via != CondLogDayQualified || !x.genTime.Equal(s.genTime) {
						t.Errorf("candidate %+v", x)
					}
				}
				return
			}
			if got.met || got.reason != c.reason || len(cands) != 0 {
				t.Errorf("got %+v (%d candidates), want %s", got, len(cands), c.reason)
			}
		})
	}
	t.Run("10.9.4 (7) at qualified_statement malformed goes before absent", func(t *testing.T) {
		in := ratedInputs(20)
		in.vlStatus = VendorLogChecked
		a, b := stamp(), stamp()
		a.qs, b.qs = tsa.QSAbsent, tsa.QSMalformed
		x := l8(3, 2, RcIncluded)
		x.stamps = []evDayStamp{a, b}
		in.l8, in.roots = []evL8{x}, []evRoot{qlRoot()}
		if got, _, _ := condLogDayQualified(in); got.reason != rsQSMalformed {
			t.Errorf("got %+v", got)
		}
	})
}

// TestEvidenceNotes holds every note of 10.9.6 that a run can give, each
// once and in note_order.
func TestEvidenceNotes(t *testing.T) {
	pinned := evReceipt{seq: 3, treeSize: 2, keyID: "v1", pub: strings.Repeat("ab", 32), via: keyViaPinned, established: true}
	builtinList := &evList{version: 2, rootID: "w", rootFrom: rootFromBuiltin, rootPub: strings.Repeat("cd", 32)}
	viaBuiltin := evReceipt{seq: 5, treeSize: 4, keyID: "v2", pub: strings.Repeat("ef", 32), via: keyViaList, established: true, list: builtinList}
	cases := []struct {
		name string
		edit func(in *evInputs)
		want []string
	}{
		{"10.9.6 none", func(in *evInputs) {}, nil},
		{"10.9.6 unsealed_end, stale_package, package_not_fully_known", func(in *evInputs) {
			in.exit = 4
			in.classes[ClsUnsealedEnd], in.classes[ClsTrailingSilence], in.classes[ClsUnknownManifestFld] = true, true, true
		}, []string{ntUnsealedEnd, ntStalePackage, ntPackageNotFullyKnown}},
		{"10.9.6 material_contradiction first", func(in *evInputs) {
			in.exit = 2
			in.classes[ClsReportMismatch], in.classes[ClsSpecNewer] = true, true
		}, []string{ntMaterialContradiction, ntPackageNotFullyKnown}},
		{"10.9.6 vendor_root_builtin_only", func(in *evInputs) { in.receipts = []evReceipt{viaBuiltin} }, []string{ntVendorRootBuiltinOnly}},
		{"10.9.6 not builtin only with a pinned credited receipt", func(in *evInputs) { in.receipts = []evReceipt{viaBuiltin, pinned} }, nil},
		{"10.9.6 published_test_key_credited: key of a credited receipt", func(in *evInputs) {
			r := pinned
			r.pub = PublishedTestEd25519[1]
			in.receipts = []evReceipt{r}
		}, []string{ntPublishedTestKey}},
		{"10.9.6 published_test_key_credited: vendor root of the list", func(in *evInputs) {
			r := viaBuiltin
			l := *builtinList
			l.rootPub, l.rootFrom = PublishedTestEd25519[0], rootFromAuditor
			r.list = &l
			in.receipts = []evReceipt{r}
		}, []string{ntPublishedTestKey}},
		{"10.9.6 no published_test_key_credited from a receipt not credited", func(in *evInputs) {
			in.receipts = []evReceipt{{seq: 3, treeSize: 2, pub: PublishedTestEd25519[1], via: keyViaManifest}}
		}, nil},
		{"10.9.6 published_test_key_credited: protocol key, (5) met", func(in *evInputs) {
			in.vlStatus, in.protocolTestKey, in.l8 = VendorLogChecked, true, []evL8{l8(3, 2, RcIncluded)}
		}, []string{ntPublishedTestKey}},
		{"10.9.6 no published_test_key_credited from a protocol key, (5) not met", func(in *evInputs) {
			in.vlStatus, in.protocolTestKey, in.l8 = VendorLogChecked, true, []evL8{l8(3, 2, RcPending)}
		}, []string{ntReceiptsPendingLog}},
		{"10.9.6 published_test_key_credited: key of a page, (6) met", func(in *evInputs) {
			up := int64(4)
			in.compl = HistoryComplStat{Status: "established", UpToTreeSize: &up}
			in.pagesCompl = []evPage{{keyID: "s1", pub: PublishedTestEd25519[4], pinned: true}}
		}, []string{ntPublishedTestKey}},
		{"10.9.6 published_test_key_credited: root of the role list, (2) from the history", func(in *evInputs) {
			in.found = []evFound{{foundAt: 4, root: "r", history: true}}
			in.pagesFound = []evPage{{keyID: "s1", pub: strings.Repeat("12", 32)}}
			in.roleList = &evList{version: 1, rootID: "testwurzel-1", rootFrom: rootFromAuditor, rootPub: PublishedTestEd25519[0]}
		}, []string{ntPublishedTestKey}},
		{"10.9.6 last_receipt_not_confirmed", func(in *evInputs) {
			in.receipts = []evReceipt{pinned, {seq: 7, treeSize: 6, via: keyViaManifest}}
			in.lastCountersignedSeq = 7
		}, []string{ntLastReceiptNotConfirm}},
		{"10.9.6 expected_root_auditor_only", func(in *evInputs) { in.found = []evFound{{foundAt: 4, root: "r", auditor: true}} }, []string{ntExpectedRootAuditor}},
		{"10.9.6 no expected_root_auditor_only with a source anchor_history", func(in *evInputs) {
			in.found = []evFound{{foundAt: 4, root: "r", auditor: true, history: true}}
		}, nil},
		{"10.9.6 no expected_root_auditor_only with (1)", func(in *evInputs) {
			in.found = []evFound{{foundAt: 4, root: "r", auditor: true}}
			in.timeAnchors, in.witnesses, in.roots = 1, []evWitness{witness(2, "C")}, []evRoot{{certSHA: "C", spki: "s", chain: true}}
		}, nil},
		{"10.9.6 tsa_root_in_package", func(in *evInputs) {
			in.timeAnchors, in.witnesses, in.roots = 1, []evWitness{witness(2, "C")}, []evRoot{{certSHA: "C", spki: "s", chain: true}}
			in.pkgSPKI["s"] = true
		}, []string{ntTSARootInPackage}},
		{"10.9.6 history_recent_roots_skipped", func(in *evInputs) { in.recentRootsSkipped = true }, []string{ntHistoryRecentSkipped}},
		{"10.9.6 receipts_pending_log, receipt_not_logged, log_day_not_supplied, logged_root_mismatch", func(in *evInputs) {
			in.vlStatus, in.l8 = VendorLogChecked, []evL8{l8(3, 2, RcMissing), l8(5, 4, RcPending)}
			in.classes[ClsReceiptNotLogged], in.classes[ClsLoggedRootMismatch] = true, true
			in.exit = 1
		}, []string{ntReceiptsPendingLog, ntReceiptNotLogged, ntLogDayNotSupplied, ntLoggedRootMismatch}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := ratedInputs(20)
			c.edit(in)
			ev := evaluateEvidence(in)
			if ev.State != EvRated {
				t.Fatalf("state %s", ev.State)
			}
			if strings.Join(ev.Notes, ",") != strings.Join(c.want, ",") {
				t.Errorf("notes %v, want %v", ev.Notes, c.want)
			}
		})
	}
	// 10.9.6: notes only in the state rated.
	in := ratedInputs(20)
	in.exit = 2
	in.classes[ClsSigInvalid], in.classes[ClsUnsealedEnd] = true, true
	if ev := evaluateEvidence(in); len(ev.Notes) != 0 {
		t.Errorf("notes %v in chain_invalid", ev.Notes)
	}
}

// TestEvidenceAnchors holds the object anchors of 10.10.2: vendor keys with
// their origin, statements keys of the pages (2) with the source
// anchor_history and (6) rest on, the crediting roots with credited_for in
// condition_order, the file of qualified roots and the sources.
func TestEvidenceAnchors(t *testing.T) {
	in := ratedInputs(20)
	l := &evList{version: 3, rootID: "w-1", rootFrom: rootFromBuiltin, rootPub: strings.Repeat("cd", 32)}
	in.receipts = []evReceipt{
		{seq: 9, treeSize: 8, keyID: "v-b", pub: strings.Repeat("01", 32), via: keyViaList, established: true, list: l},
		{seq: 3, treeSize: 2, keyID: "v-a", pub: strings.Repeat("02", 32), via: keyViaPinned, established: true},
		{seq: 5, treeSize: 4, keyID: "v-a", pub: strings.Repeat("02", 32), via: keyViaPinned, established: true},
		{seq: 7, treeSize: 6, keyID: "v-c", pub: strings.Repeat("03", 32), via: keyViaManifest},
	}
	in.timeAnchors = 2
	in.witnesses = []evWitness{witness(4, "Q", "C")}
	in.roots = []evRoot{qroot("Q"), {certSHA: "C", spki: "spki-C", chain: true}}
	in.qualifiedFile = &EvidenceQualifiedFile{Stand: "2026-10-01T00:00:00Z", Quelle: "Liste des Prüfers"}
	in.found = []evFound{{foundAt: 6, root: "r", history: true}}
	in.roleList = &evList{version: 1, rootID: "w-2", rootFrom: rootFromAuditor}
	in.pagesFound = []evPage{{keyID: "s-2", pub: "x"}}
	in.pagesCompl = []evPage{{keyID: "s-1", pub: "y", pinned: true}, {keyID: "s-2", pub: "x"}}
	ev := evaluateEvidence(in)
	b, err := json.Marshal(ev.Anchors)
	if err != nil {
		t.Fatal(err)
	}
	got := canonJSON(t, b)
	want := `{"expected_root_sources":["anchor_history"],"qualified_roots_file":{"quelle":"Liste des Prüfers","stand":"2026-10-01T00:00:00Z"},` +
		`"statement_keys":[{"key_id":"s-2","list_version":1,"root_from":"auditor","root_id":"w-2","via":"role_list"}],` +
		`"tsa_roots":[{"cert_sha256":"C","credited_for":["time_witness"]},{"cert_sha256":"Q","credited_for":["time_witness","time_witness_qualified"]}],` +
		`"vendor_keys":[{"key_id":"v-a","list_version":null,"root_from":null,"root_id":null,"via":"pinned"},{"key_id":"v-b","list_version":3,"root_from":"builtin","root_id":"w-1","via":"list"}]}`
	if got != want {
		t.Errorf("anchors\n%s\nwant\n%s", got, want)
	}
	// (6) met: the keys of every used page of the package that enters the
	// completeness (10.10.2).
	up := int64(6)
	in.compl = HistoryComplStat{Status: "established", UpToTreeSize: &up}
	ev = evaluateEvidence(in)
	if len(ev.Anchors.StatementKeys) != 2 || ev.Anchors.StatementKeys[0].KeyID != "s-1" || ev.Anchors.StatementKeys[0].Via != SourcePinned {
		t.Errorf("statement_keys %+v", ev.Anchors.StatementKeys)
	}
}

// canonJSON is the JCS form of JSON bytes.
func canonJSON(t *testing.T, b []byte) string {
	t.Helper()
	v, err := jcs.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return string(jcs.Canon(v))
}

// TestEvidenceNeutrality is the neutrality of 10.9.7: the affiliation
// changes neither level nor up_to_tree_size nor segments.
func TestEvidenceNeutrality(t *testing.T) {
	var first string
	for _, st := range []string{AffAffiliated, AffNotAffiliated, AffNotDetermined, AffNotChecked} {
		in := ratedInputs(20)
		in.receipts = []evReceipt{{seq: 3, treeSize: 12, keyID: "v", pub: strings.Repeat("ab", 32), via: keyViaPinned, established: true}}
		in.affiliation = &EvidenceAffiliation{Status: st, VendorItself: st == AffAffiliated}
		ev := evaluateEvidence(in)
		got := fmt.Sprintf("%d %d %s", *ev.Level, *ev.UpToTreeSize, segs(ev.Segments))
		if first == "" {
			first = got
		} else if got != first {
			t.Errorf("affiliation %s: %s, %s otherwise", st, got, first)
		}
		if ev.Affiliation.Status != st {
			t.Errorf("affiliation %+v", ev.Affiliation)
		}
	}
}

// TestEvidenceQualifiedTime is qualified_time of format spec 10.10.2: at
// level 3 at seq 1 the credited item of (4) or (7) with tree_size >=
// up_to_tree_size and the earliest genTime, on a tie (4) before (7), then
// the smaller tree_size, then for (7) the earlier server_ts; latest is
// genTime truncated to whole milliseconds, gap_ms latest minus server_ts
// for (7) and null for (4); null below level 3.
func TestEvidenceQualifiedTime(t *testing.T) {
	g := time.Date(2026, 8, 2, 0, 10, 0, 0, time.UTC)
	srv := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	c4 := func(ts int64, gen time.Time) evQTCand {
		return evQTCand{via: CondTimeWitnessQualified, treeSize: ts, genTime: gen}
	}
	c7 := func(ts int64, gen, server time.Time) evQTCand {
		return evQTCand{via: CondLogDayQualified, treeSize: ts, genTime: gen, serverTS: server}
	}
	cases := []struct {
		name  string
		cands []evQTCand
		upTo  int64
		want  string // via tree_size latest gap_ms
	}{
		{"10.10.2 the earliest genTime", []evQTCand{c4(9, g.Add(time.Hour)), c7(9, g, srv)}, 9, "log_day_qualified 9 2026-08-02T00:10:00.000Z 43800000"},
		{"10.10.2 only tree_size >= up_to_tree_size", []evQTCand{c4(5, g), c7(9, g.Add(time.Hour), srv)}, 9, "log_day_qualified 9 2026-08-02T01:10:00.000Z 47400000"},
		{"10.10.2 tie on genTime: (4) before (7)", []evQTCand{c7(9, g, srv), c4(12, g)}, 9, "time_witness_qualified 12 2026-08-02T00:10:00.000Z <nil>"},
		{"10.10.2 tie on genTime and condition: the smaller tree_size", []evQTCand{c7(12, g, srv), c7(10, g, srv.Add(time.Minute))}, 9, "log_day_qualified 10 2026-08-02T00:10:00.000Z 43740000"},
		{"10.10.2 tie on genTime and tree_size, (7): the earlier server_ts", []evQTCand{c7(10, g, srv.Add(time.Minute)), c7(10, g, srv)}, 9, "log_day_qualified 10 2026-08-02T00:10:00.000Z 43800000"},
		{"10.10.2 genTime compared on nanoseconds, latest truncated", []evQTCand{c4(9, g.Add(900*time.Microsecond)), c7(9, g.Add(100*time.Microsecond), srv)}, 9,
			"log_day_qualified 9 2026-08-02T00:10:00.000Z 43800000"},
		{"10.10.2 gap_ms on whole milliseconds", []evQTCand{c7(9, g.Add(1500*time.Microsecond), srv.Add(700*time.Microsecond))}, 9, "log_day_qualified 9 2026-08-02T00:10:00.001Z 43800001"},
		{"10.10.2 no candidate", nil, 9, "<nil>"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := chooseQualifiedTime(c.cands, c.upTo)
			got := "<nil>"
			if q != nil {
				got = fmt.Sprintf("%s %d %s %v", q.Via, q.TreeSize, q.Latest, formulaVal(q.GapMS))
			}
			if got != c.want {
				t.Errorf("got %s, want %s", got, c.want)
			}
		})
	}
	// Whole runs of evaluateEvidence: level 3 through (7) alone carries the
	// receipt; level 2 with (4) and (7) met carries none.
	level3 := func(in *evInputs) {
		in.vlStatus = VendorLogChecked
		r := qroot("QL")
		r.log = true
		x := l8(3, 2, RcIncluded)
		x.stamps = []evDayStamp{stamp()}
		in.l8, in.roots = []evL8{x}, []evRoot{r}
		in.receipts = []evReceipt{{seq: 3, treeSize: 2, keyID: "v", pub: strings.Repeat("ab", 32), via: keyViaPinned, established: true}}
		up := int64(2)
		in.compl = HistoryComplStat{Status: "established", UpToTreeSize: &up}
	}
	in := ratedInputs(4)
	level3(in)
	ev := evaluateEvidence(in)
	if *ev.Level != 3 || ev.QualifiedTime == nil || ev.QualifiedTime.Via != CondLogDayQualified || ev.QualifiedTime.TreeSize != 2 ||
		ev.QualifiedTime.Latest != "2026-08-02T00:10:00.000Z" || formulaVal(ev.QualifiedTime.GapMS) != any(int64(43_800_000)) {
		t.Errorf("level %d qualified_time %+v", *ev.Level, ev.QualifiedTime)
	}
	b, _ := json.Marshal(ev.QualifiedTime)
	if string(b) != `{"via":"log_day_qualified","tree_size":2,"latest":"2026-08-02T00:10:00.000Z","gap_ms":43800000}` {
		t.Errorf("JSON %s", b)
	}
	in = ratedInputs(4)
	level3(in)
	in.compl = HistoryComplStat{Status: "not_established", Reason: strp("not_supplied")}
	if ev := evaluateEvidence(in); *ev.Level != 2 || ev.QualifiedTime != nil {
		t.Errorf("level %d qualified_time %+v", *ev.Level, ev.QualifiedTime)
	}
	// 10.10.2: qualified_time is a member of the object, null below level 3.
	b, _ = json.Marshal(evaluateEvidence(ratedInputs(4)))
	if !strings.Contains(string(b), `"qualified_time":null`) {
		t.Errorf("no member qualified_time: %s", b)
	}
	in = ratedInputs(4)
	in.exit, in.affiliation = 3, nil
	if b, _ := json.Marshal(evaluateEvidence(in)); !strings.Contains(string(b), `"qualified_time":null`) {
		t.Errorf("format_error: %s", b)
	}
}

// TestEvidencePagesOfFoundRoots: condition (2) with the source
// anchor_history rests on the used pages that carry the recorded recording
// of a found expected root (format spec 10.10.2, anchors.statement_keys,
// with the term "festgehalten" of 8.8.5: recorded_as countersigned or
// gap_witness), a recording that still counts for its history root after
// H7. A page that lists the found root only as reported, a page with a
// root that is not found and a page whose recording H7 dropped carry none.
func TestEvidencePagesOfFoundRoots(t *testing.T) {
	r := strings.Repeat("aa", 32)
	ts := "2026-01-02T23:59:00.000Z"
	rec := func(as, ts string) ahRec { return ahRec{t: 15, root: r, as: as, ts: ts} }
	page := func(x ...ahRec) *ahPage { return &ahPage{c: &ahContent{roots: x}} }
	found := &histRoot{t: 15, r: r, found: true, kept: []ahRec{rec("countersigned", ts), rec("gap_witness", ts), rec("reported", ts)}}
	cases := []struct {
		name  string
		p     *ahPage
		roots []*histRoot
		want  bool
	}{
		{"countersigned", page(rec("countersigned", ts)), []*histRoot{found}, true},
		{"gap_witness", page(rec("gap_witness", ts)), []*histRoot{found}, true},
		{"reported only", page(rec("reported", ts)), []*histRoot{found}, false},
		{"root not found", page(rec("countersigned", ts)), []*histRoot{{t: 15, r: r, kept: found.kept}}, false},
		{"dropped by H7", page(rec("countersigned", ts)), []*histRoot{{t: 15, r: r, found: true, kept: []ahRec{rec("reported", ts)}}}, false},
		{"other server_ts", page(rec("countersigned", "2026-01-02T23:58:00.000Z")), []*histRoot{found}, false},
	}
	for _, c := range cases {
		if got := pageCarriesFoundRoot(c.p, c.roots); got != c.want {
			t.Errorf("%s: pageCarriesFoundRoot = %v, want %v", c.name, got, c.want)
		}
	}
}

// 10.10.2 anchors.statement_keys: one entry per distinct (key_id, public
// key, source), not per key_id.
func TestPageKeyRefsDistinctTriples(t *testing.T) {
	pages := []evPage{
		{keyID: "s-1", pub: "bb", pinned: true},
		{keyID: "s-1", pub: "aa", pinned: true},
		{keyID: "s-1", pub: "aa", pinned: true},
		{keyID: "s-0", pub: "cc", pinned: true},
	}
	got := pageKeyRefs(pages, nil)
	if len(got) != 3 || got[0].KeyID != "s-0" || got[1].KeyID != "s-1" || got[2].KeyID != "s-1" {
		t.Fatalf("got %+v, want s-0 and s-1 twice (two public keys)", got)
	}
	if len(pageKeyRefs(nil, nil)) != 0 {
		t.Fatal("no pages must give an empty list")
	}
}
