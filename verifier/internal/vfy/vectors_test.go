package vfy

// Matrix test: run the verifier against every spec test vector listed under
// spec/testvectors/expected/ and compare exit code and finding classes
// exactly. Vector packages that do not exist yet (the generator has not
// written them) are honestly counted as SKIP, never as green.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func repoRoot(t *testing.T) string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate source file")
	}
	// file = <repo>/verifier/internal/vfy/vectors_test.go
	return filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(file))))
}

// expected holds the members compared here, for the audit environment of the
// corpus. From spec 1.10 an expected file may also carry auditor_inputs (the
// run with the vector's pruefer_<name>.json, compared through the switches
// in internal/cli/korpus_test.go, since an unusable invocation is judged on
// the command line) and evidence_level (format spec 10.9, registry
// expected_files.evidence_level), compared here member by member against
// stats.evidence_level.
type expected struct {
	ExitCode       int             `json:"exit_code"`
	FindingClasses []string        `json:"finding_classes"`
	EvidenceLevel  json.RawMessage `json:"evidence_level"`
}

// expectedEvidence is the form of registry expected_files.evidence_level:
// state, level, reach, the segments as [level, first_seq, last_seq], per
// condition its reason or null when it is met, the notes and the status of
// the affiliation.
type expectedEvidence struct {
	State        string              `json:"state"`
	Level        *int                `json:"level"`
	UpToTreeSize *int64              `json:"up_to_tree_size"`
	Segments     [][3]int64          `json:"segments"`
	Conditions   *map[string]*string `json:"conditions"`
	Notes        []string            `json:"notes"`
	Affiliation  *string             `json:"affiliation"`
}

// CondenseEvidence writes an object evidence_level (10.10.2) in the form
// of an expected file (registry expected_files.evidence_level).
func condenseEvidence(ev *EvidenceLevelStat) *expectedEvidence {
	if ev == nil {
		return nil
	}
	out := &expectedEvidence{State: ev.State, Level: ev.Level, UpToTreeSize: ev.UpToTreeSize, Segments: [][3]int64{}, Notes: ev.Notes}
	for _, s := range ev.Segments {
		out.Segments = append(out.Segments, [3]int64{int64(s.Level), s.FirstSeq, s.LastSeq})
	}
	if c := ev.Conditions; c != nil {
		m := map[string]*string{}
		for _, code := range evConditionOrder {
			m[code] = c.Get(code).Reason
		}
		out.Conditions = &m
	}
	if ev.Affiliation != nil {
		st := ev.Affiliation.Status
		out.Affiliation = &st
	}
	return out
}

// evidenceAgainstExpected compares stats.evidence_level with the member
// evidence_level of an expected file (both in the form of the expected
// file, JCS) and returns what differs; "" without an expectation.
func evidenceAgainstExpected(t *testing.T, ev *EvidenceLevelStat, want json.RawMessage) string {
	t.Helper()
	if len(want) == 0 {
		return ""
	}
	g, err := json.Marshal(condenseEvidence(ev))
	if err != nil {
		t.Fatal(err)
	}
	got, exp := canonJSON(t, g), canonJSON(t, want)
	if got == exp {
		return ""
	}
	return fmt.Sprintf("got %s, want %s", got, exp)
}

// evidenceProperties checks the properties 1 to 5 of format spec 10.9.7 on
// one run and the members of evidence_level that the report objects decide
// (8.8.6 for the affiliation, 10.9.4 for conditions (2) and (6)); it
// returns what fails.
func evidenceProperties(res Result, six map[string]*string) string {
	ev := res.Stats.EvidenceLevel
	if ev == nil {
		return "no evidence_level in a report"
	}
	var out []string
	cls := classSet(res)
	// 5. state format_error exactly with exit 3.
	if (ev.State == EvFormatError) != (res.ExitCode == 3) {
		out = append(out, fmt.Sprintf("state %s with exit %d", ev.State, res.ExitCode))
	}
	if ev.State == EvRated && ev.Level != nil {
		// 1. NO_ANCHOR in the state rated gives level 0, and from level 1
		// on there is no NO_ANCHOR.
		if cls[ClsNoAnchor] && *ev.Level != 0 {
			out = append(out, fmt.Sprintf("NO_ANCHOR at level %d", *ev.Level))
		}
		// 2. From level 2 on a receipt holds under a key an anchor of the
		// auditor confirms.
		if *ev.Level >= 2 && res.Stats.ReceiptsEstablished == 0 {
			out = append(out, "level 2 without an established receipt")
		}
		// 3. At level 3 the completeness from the history is established.
		if *ev.Level == 3 && (res.Stats.AnchorHistory == nil || res.Stats.AnchorHistory.Completeness.Status != "established") {
			out = append(out, "level 3 without completeness from the history")
		}
		// 4. The segments cover seq 1 to N with strictly falling levels;
		// the first has the level.
		at := int64(1)
		for i, s := range ev.Segments {
			if s.FirstSeq != at || s.LastSeq < s.FirstSeq || i > 0 && s.Level >= ev.Segments[i-1].Level || i == 0 && s.Level != *ev.Level {
				out = append(out, fmt.Sprintf("segments break 10.9.7 number 4 at %d", i))
			}
			at = s.LastSeq + 1
		}
		if at != res.Stats.Entries+1 {
			out = append(out, fmt.Sprintf("segments end at %d of %d", at-1, res.Stats.Entries))
		}
		// (2) and (6) as the report objects decide them (10.9.4).
		two := ev.Conditions.ExpectedRootFound.Met
		if two != (res.Stats.Completeness != nil && len(res.Stats.Completeness.Sources) > 0) {
			out = append(out, "condition (2) disagrees with completeness.sources")
		}
		if ah := res.Stats.AnchorHistory; ah != nil {
			c6 := ev.Conditions.CompletenessFromHistory
			if comp := ah.Completeness; comp.Status == "established" {
				if !c6.Met {
					out = append(out, "condition (6) not met with completeness established")
				}
			} else if comp.Reason == nil || six[*comp.Reason] == nil || c6.Reason == nil || *c6.Reason != *six[*comp.Reason] {
				out = append(out, "condition (6) disagrees with anchor_history.completeness")
			}
		}
	}
	// "affiliation: status und vendor_itself des Objekts affiliation, auch
	// im Zustand chain_invalid; null nur im Zustand format_error" (10.10.2).
	if af := res.Stats.Affiliation; (af == nil) != (ev.Affiliation == nil) || af != nil && (af.Status != ev.Affiliation.Status || af.VendorItself != ev.Affiliation.VendorItself) {
		out = append(out, "affiliation disagrees with the object affiliation")
	}
	return strings.Join(out, "; ")
}

// conditionSixReasons reads registry verifier.evidence_level.conditions.
// completeness_from_history.from_completeness: the reason of condition (6)
// for each reason of anchor_history.completeness (format spec 10.9.4).
func conditionSixReasons(t *testing.T) map[string]*string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "registry.json"))
	if err != nil {
		t.Fatalf("registry not readable: %v", err)
	}
	var reg struct {
		Verifier struct {
			EvidenceLevel struct {
				Conditions struct {
					CompletenessFromHistory struct {
						FromCompleteness map[string]*string `json:"from_completeness"`
					} `json:"completeness_from_history"`
				} `json:"conditions"`
			} `json:"evidence_level"`
		} `json:"verifier"`
	}
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatalf("registry: %v", err)
	}
	m := reg.Verifier.EvidenceLevel.Conditions.CompletenessFromHistory.FromCompleteness
	if len(m) == 0 {
		t.Fatal("registry: from_completeness of completeness_from_history is empty")
	}
	return m
}

func TestVectorMatrix(t *testing.T) {
	root := repoRoot(t)
	expDir := filepath.Join(root, "spec", "testvectors", "expected")
	entries, err := os.ReadDir(expDir)
	if err != nil {
		t.Fatalf("no expected/ directory — the frozen vector corpus belongs to the repository: %v", err)
	}

	var logLines []string
	logf := func(format string, args ...any) {
		logLines = append(logLines, fmt.Sprintf(format, args...))
	}
	logf("ledger-verify vector matrix — %s", time.Now().UTC().Format(time.RFC3339))
	logf("spec dir: %s", filepath.Join(root, "spec", "testvectors"))
	logf("")

	six := conditionSixReasons(t)
	pass, fail, skip := 0, 0, 0
	for _, de := range entries {
		name := strings.TrimSuffix(de.Name(), ".json")
		if name == de.Name() {
			continue
		}
		vecDir := filepath.Join(root, "spec", "testvectors", name)
		if st, err := os.Stat(vecDir); err != nil || !st.IsDir() {
			skip++
			logf("SKIP %-24s vector package not present yet", name)
			continue
		}
		expBytes, err := os.ReadFile(filepath.Join(expDir, de.Name()))
		if err != nil {
			fail++
			logf("FAIL %-24s cannot read expectation: %v", name, err)
			continue
		}
		var exp expected
		if err := json.Unmarshal(expBytes, &exp); err != nil {
			fail++
			logf("FAIL %-24s cannot parse expectation: %v", name, err)
			continue
		}
		// Frozen vectors carry their own check time in verify_args.json;
		// honouring it is an explicit opt-in, never the default.
		// The audit environment (spec 7.1) is part of the corpus: the
		// expectations hold for the test vendor's root and pinned key.
		res := Verify(vecDir, mitPruefAnker(t, Options{NowFromPackage: true}))
		got := sortedKeys(classSet(res))
		want := append([]string{}, exp.FindingClasses...)
		sort.Strings(want)
		// Without an extract the report object vendor_log is not_supplied
		// (format spec 10.10.2), and null for a format error (10.10.1).
		if why := vendorLogNotSupplied(res); why != "" {
			t.Errorf("vector %s: stats.vendor_log %s", name, why)
		}
		// Format spec 10.9, 10.10.2: the evidence level against the
		// expected file, and the properties of 10.9.7 on every run.
		if why := evidenceAgainstExpected(t, res.Stats.EvidenceLevel, exp.EvidenceLevel); why != "" {
			t.Errorf("vector %s: evidence_level: %s", name, why)
		}
		if why := evidenceProperties(res, six); why != "" {
			t.Errorf("vector %s: evidence_level (10.9.7): %s", name, why)
		}
		// Format spec 10.9.5: entries, basis and next, which the expected
		// file does not carry, from the reaches of the conditions.
		if why := evidenceFormula(res.Stats.EvidenceLevel, res.Stats.Entries); why != "" {
			t.Errorf("vector %s: evidence_level (10.9.5): %s", name, why)
		}
		if res.ExitCode == exp.ExitCode && fmt.Sprint(got) == fmt.Sprint(want) {
			pass++
			logf("PASS %-24s exit=%d classes=%v", name, res.ExitCode, got)
		} else {
			fail++
			logf("FAIL %-24s exit=%d (want %d) classes=%v (want %v)", name, res.ExitCode, exp.ExitCode, got, want)
			t.Errorf("vector %s: exit=%d (want %d), classes=%v (want %v)", name, res.ExitCode, exp.ExitCode, got, want)
		}
	}
	logf("")
	logf("summary: %d PASS, %d FAIL, %d SKIP", pass, fail, skip)

	// Nur wo das Belegverzeichnis neben dem Modul schon existiert, landet die
	// Matrix auch als Beleg dort; im oeffentlichen Verifier-Repository (ohne
	// artefakte/) legt der Test KEIN Verzeichnis ausserhalb seines Moduls an.
	// / Only where the evidence directory exists; never creates a directory
	// outside the module (public verifier repository).
	// Und nur mit BELEGE=1 (Entscheidung vom 02.10.2026): ein gewoehnliches
	// "go test" schreibt keinen Beleg; die Matrix steht trotzdem vollstaendig
	// im Testlog. / And only with BELEGE=1.
	logDir := filepath.Join(root, "artefakte", "P03")
	if fi, err := os.Stat(logDir); err == nil && fi.IsDir() && os.Getenv("BELEGE") == "1" {
		_ = os.WriteFile(filepath.Join(logDir, "vektor_matrix.log"), []byte(strings.Join(logLines, "\n")+"\n"), 0o644)
	}
	t.Logf("\n%s", strings.Join(logLines, "\n"))
	if skip > 0 {
		t.Logf("NOTE: %d vectors skipped, packages not yet generated", skip)
	}
}

// vendorLogNotSupplied checks the object vendor_log of a run without an
// extract: "Ohne Auszug ist status not_supplied, log_id, first_day,
// key_source, key_list, head, receipts, last_countersigned und logged_roots
// sind null, places ist leer, und jeder Zaehlwert ist 0" (format spec
// 10.10.2); null for a format error (10.10.1). It returns what differs.
func vendorLogNotSupplied(res Result) string {
	vl := res.Stats.VendorLog
	if res.ExitCode == 3 {
		if vl != nil {
			return "is not null for a format error"
		}
		return ""
	}
	switch {
	case vl == nil:
		return "is null"
	case vl.Status != VendorLogNotSupplied:
		return "status " + vl.Status
	case vl.LogID != nil || vl.FirstDay != nil || vl.KeySource != nil || vl.KeyList != nil || vl.Head != nil ||
		vl.Receipts != nil || vl.LastCountersigned != nil || vl.LoggedRoots != nil:
		return "has a member that is not null"
	case len(vl.Places) != 0 || vl.Files != 0 || vl.DistinctFiles != 0 || vl.ForeignChainRecords != 0 ||
		vl.Days != (VendorLogDaysStat{}) || vl.TSA.RootsSupplied != 0:
		return "has a count that is not 0"
	case !vl.TSA.CMSChecked:
		return "tsa.cms_checked is false"
	}
	return ""
}

// TestEvidenceAgainstExpectedRotbeweis: the comparison with the expected
// evidence level turns red on every member that differs, and the
// properties of 10.9.7 turn red on a broken object.
func TestEvidenceAgainstExpectedRotbeweis(t *testing.T) {
	root := repoRoot(t)
	six := conditionSixReasons(t)
	res := Verify(filepath.Join(root, "spec", "testvectors", "valid_sealed_export"), mitPruefAnker(t, Options{NowFromPackage: true}))
	honest, err := json.Marshal(condenseEvidence(res.Stats.EvidenceLevel))
	if err != nil {
		t.Fatal(err)
	}
	if why := evidenceAgainstExpected(t, res.Stats.EvidenceLevel, honest); why != "" {
		t.Fatalf("honest run: %s", why)
	}
	if why := evidenceProperties(res, six); why != "" {
		t.Fatalf("honest run: %s", why)
	}
	for i, edit := range []func(m map[string]any){
		func(m map[string]any) { m["state"] = EvChainInvalid },
		func(m map[string]any) { m["level"] = 1 },
		func(m map[string]any) { m["up_to_tree_size"] = nil },
		func(m map[string]any) { m["segments"] = []any{} },
		func(m map[string]any) { m["notes"] = []any{"unsealed_end"} },
		func(m map[string]any) { m["affiliation"] = "affiliated" },
		func(m map[string]any) { m["conditions"].(map[string]any)["receipt_key_confirmed"] = "no_receipt" },
		func(m map[string]any) { m["conditions"].(map[string]any)["log_day_qualified"] = nil },
		func(m map[string]any) { delete(m["conditions"].(map[string]any), "time_witness") },
	} {
		var m map[string]any
		if err := json.Unmarshal(honest, &m); err != nil {
			t.Fatal(err)
		}
		edit(m)
		b, _ := json.Marshal(m)
		if why := evidenceAgainstExpected(t, res.Stats.EvidenceLevel, b); why == "" {
			t.Errorf("edit %d passed the comparison", i)
		}
	}
	if why := evidenceAgainstExpected(t, res.Stats.EvidenceLevel, json.RawMessage("null")); why == "" {
		t.Error("null passed the comparison of a report")
	}
	for i, edit := range []func(st *Stats){
		func(st *Stats) { st.EvidenceLevel = nil },
		func(st *Stats) { e := *st.EvidenceLevel; e.State = EvFormatError; st.EvidenceLevel = &e },
		func(st *Stats) { e := *st.EvidenceLevel; e.Segments = e.Segments[:1]; st.EvidenceLevel = &e },
		func(st *Stats) { e := *st.EvidenceLevel; e.Affiliation = nil; st.EvidenceLevel = &e },
		func(st *Stats) {
			e := *st.EvidenceLevel
			c := *e.Conditions
			c.CompletenessFromHistory.Reason = strp(rsHistoryPartial)
			e.Conditions = &c
			st.EvidenceLevel = &e
		},
	} {
		r := res
		edit(&r.Stats)
		if why := evidenceProperties(r, six); why == "" {
			t.Errorf("properties: edit %d passed", i)
		}
	}
}
