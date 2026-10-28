package cli

// Vectors of the anchor history whose expectation lies in members that the
// expected files do not carry (registry testvectors.history, "why"): which
// reasons H5 gives between which pages (format spec 8.8.4), whether they
// hinder the completeness (H11), contradictory (8.8.6 item 9) and the result
// of each linked chain (8.8.6 item 11). The run is the one of the audit
// environment of the vector, as in TestKorpusMitPruefumgebung.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"louwietec.com/ledger-verify/verifier/internal/vfy"
)

// historyDetail is what this test compares of stats.anchor_history and
// stats.affiliation (format spec 10.10.2).
type historyDetail struct {
	Completeness  string   // status, with ":" and the reason when there is one
	Contradiction []string // reasons.contradiction
	Fork          []string // reasons.fork
	Notes         []string // anchor_history.notes
	Affiliation   string   // affiliation.status
	Contradictory bool
	Linked        []string // "<relation>:<status>" per linked chain
	MergedPeriod  bool     // some period of affiliation.periods has merged true
}

func (d historyDetail) String() string {
	return fmt.Sprintf("completeness %s, contradiction %v, fork %v, notes %v, affiliation %s, contradictory %v, linked %v, merged period %v",
		d.Completeness, d.Contradiction, d.Fork, d.Notes, d.Affiliation, d.Contradictory, d.Linked, d.MergedPeriod)
}

// readHistoryDetail reads the compared members from a JSON report.
func readHistoryDetail(out string) (historyDetail, error) {
	var r struct {
		Stats struct {
			AnchorHistory *struct {
				Completeness struct {
					Status string  `json:"status"`
					Reason *string `json:"reason"`
				} `json:"completeness"`
				Reasons struct {
					Contradiction []string `json:"contradiction"`
					Fork          []string `json:"fork"`
				} `json:"reasons"`
				Notes []string `json:"notes"`
			} `json:"anchor_history"`
			Affiliation *struct {
				Status        string `json:"status"`
				Contradictory bool   `json:"contradictory"`
				Periods       []struct {
					Merged bool `json:"merged"`
				} `json:"periods"`
				Linked []struct {
					Relation string `json:"relation"`
					Status   string `json:"status"`
				} `json:"linked"`
			} `json:"affiliation"`
		} `json:"stats"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		return historyDetail{}, err
	}
	ah, af := r.Stats.AnchorHistory, r.Stats.Affiliation
	if ah == nil || af == nil {
		return historyDetail{}, fmt.Errorf("anchor_history or affiliation is null")
	}
	d := historyDetail{
		Completeness:  ah.Completeness.Status,
		Contradiction: append([]string{}, ah.Reasons.Contradiction...),
		Fork:          append([]string{}, ah.Reasons.Fork...),
		Notes:         append([]string{}, ah.Notes...),
		Affiliation:   af.Status,
		Contradictory: af.Contradictory,
		Linked:        []string{},
	}
	if ah.Completeness.Reason != nil {
		d.Completeness += ":" + *ah.Completeness.Reason
	}
	for _, l := range af.Linked {
		d.Linked = append(d.Linked, l.Relation+":"+l.Status)
	}
	for _, p := range af.Periods {
		d.MergedPeriod = d.MergedPeriod || p.Merged
	}
	return d, nil
}

// historyVectorDetails are the expectations, each after the spec text that
// decides it.
var historyVectorDetails = map[string]historyDetail{
	// H5 (f): "Ein zusammengefasster Zeitraum von B (merged = true) ergibt
	// diesen Grund nie"; no reason, so H11 establishes and item 9 leaves
	// contradictory false.
	"history_affiliation_merged_gap": {
		Completeness: "established", Contradiction: []string{}, Fork: []string{}, Notes: []string{},
		Affiliation: "affiliated", Linked: []string{}, MergedPeriod: true,
	},
	// The same pages with merged false: affiliation_withheld (H5 (f)),
	// hindering after H11 (b), and contradictory true (8.8.6 item 9).
	"history_affiliation_gap_not_merged": {
		Completeness: "partial:contradiction", Contradiction: []string{"affiliation_withheld"}, Fork: []string{}, Notes: []string{},
		Affiliation: "affiliated", Contradictory: true, Linked: []string{},
	},
	// affiliation_narrowed between the pages of the linked predecessor chain:
	// reported (8.8.7), not hindering ("Nicht hindernd sind die Gruende aus
	// H5 zwischen verknuepften Seiten einer anderen Kette", H11), and "ein
	// solcher Grund zwischen Seiten einer verknuepften Kette setzt
	// contradictory nicht" (8.8.6 item 9); the predecessor is affiliated
	// under linked (item 11).
	"history_linked_affiliation_narrowed": {
		Completeness: "established", Contradiction: []string{"affiliation_narrowed"}, Fork: []string{}, Notes: []string{},
		Affiliation: "affiliated", Linked: []string{"predecessor:affiliated"},
	},
	// The successor chain named by the page of the package is linked (H2
	// item 7), both statements on the change name T = 32 (H5), N = T gives
	// neither root_beyond_handover nor package_beyond_handover (H9); the
	// successor without roots and receipts is not_affiliated (item 11).
	"history_successor_linked": {
		Completeness: "established", Contradiction: []string{}, Fork: []string{}, Notes: []string{},
		Affiliation: "not_affiliated", Linked: []string{"successor:not_affiliated"},
	},
	// "ist L die Nachfolgekette (P.successor = {L, T}), muss jede verwendete
	// Seite von L, deren predecessor nicht null ist, predecessor = {P, T}
	// tragen. Sonst Grund succession_mismatch" (H5), hindering after H11 (b);
	// not one of the three reasons of 8.8.6 item 9, so contradictory false.
	"history_successor_mismatch": {
		Completeness: "partial:contradiction", Contradiction: []string{"succession_mismatch"}, Fork: []string{}, Notes: []string{},
		Affiliation: "not_affiliated", Linked: []string{"successor:not_affiliated"},
	},
}

func TestAnchorHistoryVectorDetails(t *testing.T) {
	dir := vektor("")
	for name, want := range historyVectorDetails {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Logf("SKIP %s: vector package not present", name)
			continue
		}
		env, err := os.ReadFile(filepath.Join(dir, "pruefer_"+name+".json"))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		args, err := vfy.AuditEnvironmentArgs(env, dir)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		_, out, errOut := lauf(append(append([]string{"--json", "--now-from-package"}, args...), vektor(name))...)
		got, err := readHistoryDetail(out)
		if err != nil {
			t.Errorf("%s: %v (stderr %q)", name, err, strings.TrimSpace(errOut))
			continue
		}
		if got.String() != want.String() {
			t.Errorf("%s:\n got  %s\n want %s", name, got, want)
		}
	}
}

// TestAnchorHistoryVectorDetailsRotbeweis: the comparison turns red when the
// run of a vector differs in one compared member.
func TestAnchorHistoryVectorDetailsRotbeweis(t *testing.T) {
	name := "history_linked_affiliation_narrowed"
	if _, err := os.Stat(filepath.Join(vektor(""), name)); err != nil {
		t.Fatalf("vector package %s missing from the corpus", name)
	}
	env, err := os.ReadFile(filepath.Join(vektor(""), "pruefer_"+name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	args, err := vfy.AuditEnvironmentArgs(env, vektor(""))
	if err != nil {
		t.Fatal(err)
	}
	_, out, _ := lauf(append(append([]string{"--json", "--now-from-package"}, args...), vektor(name))...)
	got, err := readHistoryDetail(out)
	if err != nil {
		t.Fatal(err)
	}
	for i, edit := range []func(d *historyDetail){
		func(d *historyDetail) { d.Contradictory = true },
		func(d *historyDetail) { d.Completeness = "partial:contradiction" },
		func(d *historyDetail) { d.Contradiction = nil },
		func(d *historyDetail) { d.Linked = []string{"predecessor:not_determined"} },
		func(d *historyDetail) { d.MergedPeriod = true },
	} {
		want := historyVectorDetails[name]
		edit(&want)
		if got.String() == want.String() {
			t.Errorf("edit %d passed the comparison", i)
		}
	}
}
