package cli

// The test corpus with the audit environment of each vector (format spec
// 10.8, ledger-pruefumgebung/1; registry expected_files.auditor_inputs): an
// expected file with auditor_inputs names the file pruefer_<name>.json, whose
// members become switches, and the exit code and finding classes of that run.
// An unusable invocation writes no report: exit 3, no finding classes and
// no evidence level (format spec 10.9.2, 10.10.1: evidence_level null).
//
// finding_classes is the set of classes (spec/testvectors README 3): a class
// that the run reports twice, such as VENDOR_LOG_UNVERIFIED on a day and
// for the run of missing days that contains it (format spec 7.4.11,
// "Mehrfachmeldungen"), is listed once. Every report of the run also carries
// stats.vendor_log, stats.anchor_history and stats.affiliation as the
// schemas report_vendor_log.schema.json, report_anchor_history.schema.json
// and report_affiliation.schema.json describe them (10.10.2), or null for a
// format error (10.10.1), and stats.evidence_level after
// report_evidence_level.schema.json in every report; its members in the
// form of the expected file are compared with auditor_inputs.evidence_level
// (format spec 10.9), and the reaches with those of the corpus environment
// (monotonicity, 10.9.7).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
	"louwietec.com/ledger-verify/verifier/internal/vfy"
)

func TestKorpusMitPruefumgebung(t *testing.T) {
	dir := vektor("")
	exp := filepath.Join(dir, "expected")
	entries, err := os.ReadDir(exp)
	if err != nil {
		t.Fatal(err)
	}
	six := bedingungSechs(t)
	n := 0
	for _, de := range entries {
		name := strings.TrimSuffix(de.Name(), ".json")
		if name == de.Name() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(exp, de.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var e struct {
			Auditor *struct {
				File     string          `json:"file"`
				Exit     int             `json:"exit_code"`
				Findings []string        `json:"finding_classes"`
				Evidence json.RawMessage `json:"evidence_level"`
			} `json:"auditor_inputs"`
		}
		if err := json.Unmarshal(b, &e); err != nil {
			t.Fatalf("%s: %v", de.Name(), err)
		}
		if e.Auditor == nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			continue // the package is not there yet
		}
		env, err := os.ReadFile(filepath.Join(dir, e.Auditor.File))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		args, err := vfy.AuditEnvironmentArgs(env, dir)
		if err != nil {
			t.Errorf("%s: %s: %v", name, e.Auditor.File, err)
			continue
		}
		n++
		code, out, errOut := lauf(append(append([]string{"--json", "--now-from-package"}, args...), vektor(name))...)
		var got []string
		if out != "" {
			if k := klassen(t, out); k != "" {
				got = jeEinmal(strings.Split(k, ","))
			}
			if err := vendorLogNachSchema(t, out); err != nil {
				t.Errorf("%s with %s: stats.vendor_log: %v", name, e.Auditor.File, err)
			}
			// Format spec 10.10.2: anchor_history and affiliation after their
			// generated schemas.
			for m, sc := range map[string]string{"anchor_history": "report_anchor_history.schema.json", "affiliation": "report_affiliation.schema.json"} {
				if err := reportNachSchema(t, out, m, sc); err != nil {
					t.Errorf("%s with %s: stats.%s: %v", name, e.Auditor.File, m, err)
				}
			}
			// Format spec 10.9, 10.10.2: the evidence level after its
			// schema, against the expected file, and its members that the
			// report objects decide.
			if err := stufeNachSchema(t, out); err != nil {
				t.Errorf("%s with %s: stats.evidence_level: %v", name, e.Auditor.File, err)
			}
			if why := stufeGegenSoll(t, out, e.Auditor.Evidence); why != "" {
				t.Errorf("%s with %s: evidence_level: %s", name, e.Auditor.File, why)
			}
			if why := stufeAusBericht(t, out, six); why != "" {
				t.Errorf("%s with %s: evidence_level: %s", name, e.Auditor.File, why)
			}
			// Format spec 10.9.5: entries, basis and next from the reaches.
			if why := verlaufNachFormel(t, out); why != "" {
				t.Errorf("%s with %s: evidence_level (10.9.5): %s", name, e.Auditor.File, why)
			}
			if korpusIn(t, env) {
				_, kout, _ := lauf(append(append([]string{"--json", "--now-from-package"}, pruefAnker(t)...), vektor(name))...)
				if why := monotonie(t, kout, out); why != "" {
					t.Errorf("%s with %s: 10.9.7 monotonicity against the corpus environment: %s", name, e.Auditor.File, why)
				}
			}
		} else if len(e.Auditor.Evidence) > 0 && string(e.Auditor.Evidence) != "null" {
			// Format spec 10.8, 10.9.2, 10.10.1: an unusable invocation
			// writes no report and has no evidence level.
			t.Errorf("%s with %s: no report (exit %d), so no evidence level; the expected file names %s", name, e.Auditor.File, code, e.Auditor.Evidence)
		}
		want := append([]string{}, e.Auditor.Findings...)
		sort.Strings(want)
		if code != e.Auditor.Exit || strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s with %s: exit %d %v (stderr %q), want exit %d %v", name, e.Auditor.File, code, got, strings.TrimSpace(errOut), e.Auditor.Exit, want)
		}
		if code == 3 && out == "" && errOut == "" {
			t.Errorf("%s: exit 3 without a reason on stderr", name)
		}
	}
	t.Logf("%d vectors with an audit environment", n)
}

// bedingungSechs reads registry verifier.evidence_level.conditions.
// completeness_from_history.from_completeness (format spec 10.9.4).
func bedingungSechs(t *testing.T) map[string]*string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vektor(""), "..", "registry.json"))
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

// stufeAusBericht checks the members of stats.evidence_level that the
// report objects decide (format spec 10.9.4, 10.10.2): the affiliation
// (null only for a format error), condition (2) from completeness.sources
// and condition (6) from anchor_history.completeness; it returns what
// differs.
func stufeAusBericht(t *testing.T, out string, six map[string]*string) string {
	t.Helper()
	type cond struct {
		Met    bool    `json:"met"`
		Reason *string `json:"reason"`
	}
	var r struct {
		Stats struct {
			Completeness *struct {
				Sources []string `json:"sources"`
			} `json:"completeness"`
			AnchorHistory *struct {
				Completeness struct {
					Status string  `json:"status"`
					Reason *string `json:"reason"`
				} `json:"completeness"`
			} `json:"anchor_history"`
			Affiliation *struct {
				Status string `json:"status"`
			} `json:"affiliation"`
			EvidenceLevel *struct {
				State       string `json:"state"`
				Affiliation *struct {
					Status string `json:"status"`
				} `json:"affiliation"`
				Conditions *struct {
					Two cond `json:"expected_root_found"`
					Six cond `json:"completeness_from_history"`
				} `json:"conditions"`
			} `json:"evidence_level"`
		} `json:"stats"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		return err.Error()
	}
	ev := r.Stats.EvidenceLevel
	if ev == nil {
		return "no evidence_level in a report"
	}
	str := func(p *string) string {
		if p == nil {
			return "null"
		}
		return *p
	}
	var diffs []string
	got, want := "null", "null"
	if ev.Affiliation != nil {
		got = ev.Affiliation.Status
	}
	if r.Stats.Affiliation != nil {
		want = r.Stats.Affiliation.Status
	}
	if got != want {
		diffs = append(diffs, fmt.Sprintf("affiliation %s, object affiliation %s", got, want))
	}
	if c := ev.Conditions; c != nil {
		if two := r.Stats.Completeness != nil && len(r.Stats.Completeness.Sources) > 0; two != c.Two.Met {
			diffs = append(diffs, fmt.Sprintf("condition expected_root_found met %v, completeness.sources %v", c.Two.Met, two))
		}
		if ah := r.Stats.AnchorHistory; ah == nil {
			diffs = append(diffs, "anchor_history is null in the state rated")
		} else if comp := ah.Completeness; comp.Status == "established" {
			if !c.Six.Met {
				diffs = append(diffs, "condition completeness_from_history not met with completeness established")
			}
		} else if comp.Reason == nil || six[*comp.Reason] == nil || str(c.Six.Reason) != *six[*comp.Reason] {
			diffs = append(diffs, fmt.Sprintf("condition completeness_from_history %s, anchor_history.completeness %s", str(c.Six.Reason), str(comp.Reason)))
		}
	}
	return strings.Join(diffs, "; ")
}

// verdichtet writes stats.evidence_level of a JSON report in the form of
// an expected file (registry expected_files.evidence_level): state, level,
// up_to_tree_size, segments as [level, first_seq, last_seq], per
// condition its reason or null when it is met, notes and the status of
// the affiliation.
func verdichtet(t *testing.T, out string) (string, error) {
	t.Helper()
	var r struct {
		Stats struct {
			EvidenceLevel *struct {
				State        string `json:"state"`
				Level        *int   `json:"level"`
				UpToTreeSize *int64 `json:"up_to_tree_size"`
				Segments     []struct {
					Level    int   `json:"level"`
					FirstSeq int64 `json:"first_seq"`
					LastSeq  int64 `json:"last_seq"`
				} `json:"segments"`
				Conditions *map[string]struct {
					Met    bool    `json:"met"`
					Reason *string `json:"reason"`
				} `json:"conditions"`
				Notes       []string `json:"notes"`
				Affiliation *struct {
					Status string `json:"status"`
				} `json:"affiliation"`
			} `json:"evidence_level"`
		} `json:"stats"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		return "", err
	}
	ev := r.Stats.EvidenceLevel
	if ev == nil {
		return "null", nil
	}
	// jcs.CanonGo takes plain values: nil, string, int64, slices and maps.
	var level, upTo any
	if ev.Level != nil {
		level = int64(*ev.Level)
	}
	if ev.UpToTreeSize != nil {
		upTo = *ev.UpToTreeSize
	}
	notes := []any{}
	for _, n := range ev.Notes {
		notes = append(notes, n)
	}
	m := map[string]any{"state": ev.State, "level": level, "up_to_tree_size": upTo, "notes": notes, "affiliation": nil, "conditions": nil}
	segs := []any{}
	for _, s := range ev.Segments {
		segs = append(segs, []any{int64(s.Level), s.FirstSeq, s.LastSeq})
	}
	m["segments"] = segs
	if ev.Conditions != nil {
		c := map[string]any{}
		for code, x := range *ev.Conditions {
			c[code] = nil
			if !x.Met && x.Reason != nil {
				c[code] = *x.Reason
			}
		}
		m["conditions"] = c
	}
	if ev.Affiliation != nil {
		m["affiliation"] = ev.Affiliation.Status
	}
	b, err := jcs.CanonGo(m)
	return string(b), err
}

// stufeGegenSoll compares stats.evidence_level with the member
// evidence_level of the expected file (both in its form, JCS) and returns
// what differs; "" without an expectation.
func stufeGegenSoll(t *testing.T, out string, want json.RawMessage) string {
	t.Helper()
	if len(want) == 0 {
		return ""
	}
	got, err := verdichtet(t, out)
	if err != nil {
		return err.Error()
	}
	v, err := jcs.Parse(want)
	if err != nil {
		return err.Error()
	}
	if exp := string(jcs.Canon(v)); got != exp {
		return fmt.Sprintf("got %s, want %s", got, exp)
	}
	return ""
}

// stufeNachSchema checks stats.evidence_level after the generated schema
// report_evidence_level.schema.json: an object in every report, also for a
// format error (format spec 10.10.1).
//
// The member qualified_time (10.10.2, since the decisions of 26.10.) is
// checked after the text of 10.10.2 where the generated schema does not
// name it yet (the registry lags the specification), and then left out of
// the schema check; once the schema names it, the schema decides.
func stufeNachSchema(t *testing.T, out string) error {
	t.Helper()
	var r struct {
		Stats map[string]json.RawMessage `json:"stats"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		return err
	}
	raw, ok := r.Stats["evidence_level"]
	if !ok || strings.TrimSpace(string(raw)) == "null" {
		return fmt.Errorf("missing or null in a report")
	}
	s, err := reportSchema("report_evidence_level.schema.json")
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	if _, named := s.Properties["qualified_time"]; named {
		return reportNachSchema(t, out, "evidence_level", "report_evidence_level.schema.json")
	}
	var ev map[string]json.RawMessage
	if err := json.Unmarshal(raw, &ev); err != nil {
		return err
	}
	q, ok := ev["qualified_time"]
	if !ok {
		return fmt.Errorf("no member qualified_time (10.10.2)")
	}
	if err := qualifiedTimeForm(q); err != nil {
		return fmt.Errorf("qualified_time: %v", err)
	}
	var full map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &full); err != nil {
		return err
	}
	delete(ev, "qualified_time")
	r.Stats["evidence_level"], _ = json.Marshal(ev)
	full["stats"], _ = json.Marshal(r.Stats)
	b, _ := json.Marshal(full)
	return reportNachSchema(t, string(b), "evidence_level", "report_evidence_level.schema.json")
}

// reMillis is the form YYYY-MM-DDThh:mm:ss.sssZ (format spec 10.10.1).
var reMillis = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$`)

// qualifiedTimeForm is the form of evidence_level.qualified_time of format
// spec 10.10.2: null, or exactly via, tree_size, latest and gap_ms, with
// via time_witness_qualified or log_day_qualified, tree_size an integer of
// at least 1, latest in the form YYYY-MM-DDThh:mm:ss.sssZ and gap_ms an
// integer for log_day_qualified and null for time_witness_qualified.
func qualifiedTimeForm(raw json.RawMessage) error {
	if strings.TrimSpace(string(raw)) == "null" {
		return nil
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	var q map[string]any
	if err := d.Decode(&q); err != nil {
		return err
	}
	if len(q) != 4 {
		return fmt.Errorf("members %v", q)
	}
	via, _ := q["via"].(string)
	ts, _ := q["tree_size"].(json.Number)
	latest, _ := q["latest"].(string)
	if via != "time_witness_qualified" && via != "log_day_qualified" {
		return fmt.Errorf("via %v", q["via"])
	}
	if n, err := ts.Int64(); err != nil || n < 1 {
		return fmt.Errorf("tree_size %v", q["tree_size"])
	}
	if !reMillis.MatchString(latest) {
		return fmt.Errorf("latest %v", q["latest"])
	}
	gap, has := q["gap_ms"]
	if !has {
		return fmt.Errorf("no gap_ms")
	}
	if via == "time_witness_qualified" {
		if gap != nil {
			return fmt.Errorf("gap_ms %v for time_witness_qualified", gap)
		}
		return nil
	}
	g, ok := gap.(json.Number)
	if !ok {
		return fmt.Errorf("gap_ms %v for log_day_qualified", gap)
	}
	if _, err := g.Int64(); err != nil {
		return fmt.Errorf("gap_ms %v", gap)
	}
	return nil
}

// korpusIn reports whether an audit environment ledger-pruefumgebung/1
// contains the one of the corpus (member korpus true): its inputs are then
// a superset I' of the inputs I of the corpus (format spec 10.9.7).
func korpusIn(t *testing.T, env []byte) bool {
	t.Helper()
	var e struct {
		Korpus bool `json:"korpus"`
	}
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	return e.Korpus
}

// reichweiten are r1, r2 and r3 of format spec 10.9.5 from the conditions
// of an object evidence_level, with its state, the details of the findings
// by class and the object key_roles.
func reichweiten(t *testing.T, out string) (r [4]int64, state string, classes map[string]string, kr map[string]any) {
	t.Helper()
	var x struct {
		Findings []struct {
			Class  string `json:"class"`
			Detail string `json:"detail"`
		} `json:"findings"`
		Stats struct {
			KeyRoles      map[string]any `json:"key_roles"`
			EvidenceLevel struct {
				State      string `json:"state"`
				Conditions map[string]struct {
					Met          bool   `json:"met"`
					UpToTreeSize *int64 `json:"up_to_tree_size"`
				} `json:"conditions"`
			} `json:"evidence_level"`
		} `json:"stats"`
	}
	if err := json.Unmarshal([]byte(out), &x); err != nil {
		t.Fatal(err)
	}
	classes = map[string]string{}
	for _, f := range x.Findings {
		classes[f.Class] += f.Detail + "\n"
	}
	reach := func(c string) int64 {
		if v, ok := x.Stats.EvidenceLevel.Conditions[c]; ok && v.Met && v.UpToTreeSize != nil {
			return *v.UpToTreeSize
		}
		return 0
	}
	r[1] = max(reach("time_witness"), reach("expected_root_found"), reach("receipt_key_confirmed"))
	r[2] = reach("receipt_key_confirmed")
	met := func(c string) bool { return x.Stats.EvidenceLevel.Conditions[c].Met }
	// 10.9.5: level 3 with (3), (4) or (7), (5) and (6).
	if met("receipt_key_confirmed") && (met("time_witness_qualified") || met("log_day_qualified")) && met("receipts_logged") && met("completeness_from_history") {
		r[3] = min(reach("receipt_key_confirmed"), max(reach("time_witness_qualified"), reach("log_day_qualified")), reach("receipts_logged"), reach("completeness_from_history"))
	}
	return r, x.Stats.EvidenceLevel.State, classes, x.Stats.KeyRoles
}

// monotonie is the monotonicity of format spec 10.9.7: with the inputs I of
// the corpus and I' of the vector (I a subset of I'), r_k(I') >= r_k(I) for
// every k, unless the run with I' has something the run with I has not
// from the list of exceptions. The exceptions that depend on why a finding
// arose (ANCHOR_HISTORY_UNVERIFIED with key_not_established or
// key_other_role) are taken whenever the finding is new, which can only
// leave a breach unseen, never report one that is none.
func monotonie(t *testing.T, korpus, pruefer string) string {
	t.Helper()
	if korpus == "" || pruefer == "" {
		return ""
	}
	rI, stateI, clsI, _ := reichweiten(t, korpus)
	rJ, stateJ, clsJ, krJ := reichweiten(t, pruefer)
	// 10.9.7: the property holds for runs in which the run with I has the
	// state rated; the states chain_invalid and format_error of the run
	// with I' are exceptions (format_error, for instance, from an added
	// --requested-at after the check time, 10.8).
	if stateI != "rated" || stateJ == "chain_invalid" || stateJ == "format_error" {
		return ""
	}
	neu := func(c string) bool { _, a := clsJ[c]; _, b := clsI[c]; return a && !b }
	for _, c := range []string{"RECEIPT_NOT_LOGGED", "LOGGED_ROOT_MISMATCH", "VENDOR_LOG_CONTRADICTION", "ANCHOR_HISTORY_CONTRADICTION", "ANCHOR_HISTORY_FORK"} {
		if neu(c) {
			return ""
		}
	}
	if neu("VENDOR_LOG_UNVERIFIED") && (strings.Contains(clsJ["VENDOR_LOG_UNVERIFIED"], "key_in_two_roles") || strings.Contains(clsJ["VENDOR_LOG_UNVERIFIED"], "lists_contradictory")) {
		return ""
	}
	if neu("ANCHOR_HISTORY_UNVERIFIED") {
		for _, why := range []string{"key_not_valid", "signing_time_not_proven", "key_not_established", "key_other_role"} {
			if strings.Contains(clsJ["ANCHOR_HISTORY_UNVERIFIED"], "reason "+why) {
				return ""
			}
		}
	}
	if krJ != nil {
		if r, _ := krJ["reason"].(string); krJ["status"] == "not_effective" && (r == "lists_contradictory" || r == "key_in_two_roles") {
			return ""
		}
		if pd, _ := krJ["pins_dropped"].([]any); len(pd) > 0 {
			return ""
		}
	}
	var out []string
	for k := 1; k <= 3; k++ {
		if rJ[k] < rI[k] {
			out = append(out, fmt.Sprintf("r%d %d < %d", k, rJ[k], rI[k]))
		}
	}
	return strings.Join(out, "; ")
}

// TestBerichtsSchemaRotbeweis: the schema check of the report objects turns
// red on an object that breaks its generated schema (format spec 10.10.2):
// a value of another type in a gap, an unknown status, a missing member.
func TestBerichtsSchemaRotbeweis(t *testing.T) {
	_, out, _ := lauf("--json", "--now-from-package", vektor("valid_sealed_export"))
	for m, sc := range map[string]string{"anchor_history": "report_anchor_history.schema.json", "affiliation": "report_affiliation.schema.json"} {
		if err := reportNachSchema(t, out, m, sc); err != nil {
			t.Fatalf("stats.%s of an honest run: %v", m, err)
		}
	}
	for _, f := range []struct {
		member, schema string
		edit           func(o map[string]any)
	}{
		{"anchor_history", "report_anchor_history.schema.json", func(o map[string]any) {
			o["coverage"].(map[string]any)["gaps"] = []any{[]any{0, "x"}}
		}},
		{"anchor_history", "report_anchor_history.schema.json", func(o map[string]any) { o["status"] = "unknown" }},
		{"anchor_history", "report_anchor_history.schema.json", func(o map[string]any) { o["coverage"].(map[string]any)["gaps"] = []any{[]any{0, nil, 1}} }},
		{"affiliation", "report_affiliation.schema.json", func(o map[string]any) { delete(o, "contradictory") }},
	} {
		var r map[string]any
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatal(err)
		}
		f.edit(r["stats"].(map[string]any)[f.member].(map[string]any))
		b, _ := json.Marshal(r)
		if err := reportNachSchema(t, string(b), f.member, f.schema); err == nil {
			t.Errorf("a broken %s passed its schema: %s", f.member, b)
		}
	}
}

// TestStufeAusBerichtRotbeweis: the comparisons of the evidence level turn
// red on a wrong member against the expected file, on a broken object
// against the report objects and the schema, and on a breach of the
// monotonicity.
func TestStufeAusBerichtRotbeweis(t *testing.T) {
	six := bedingungSechs(t)
	_, out, _ := lauf("--json", "--now-from-package", vektor("valid_sealed_export"))
	honest, err := verdichtet(t, out)
	if err != nil {
		t.Fatal(err)
	}
	if why := stufeGegenSoll(t, out, json.RawMessage(honest)); why != "" {
		t.Fatalf("honest run: %s", why)
	}
	if why := stufeAusBericht(t, out, six); why != "" {
		t.Fatalf("honest run: %s", why)
	}
	if err := stufeNachSchema(t, out); err != nil {
		t.Fatalf("honest run: %v", err)
	}
	for i, edit := range []func(m map[string]any){
		func(m map[string]any) { m["level"] = 3 },
		func(m map[string]any) { m["affiliation"] = "affiliated" },
		func(m map[string]any) { m["notes"] = []any{"stale_package"} },
		func(m map[string]any) { m["conditions"].(map[string]any)["expected_root_found"] = nil },
		func(m map[string]any) { m["segments"] = []any{[]any{0, 1, 2}} },
	} {
		var m map[string]any
		if err := json.Unmarshal([]byte(honest), &m); err != nil {
			t.Fatal(err)
		}
		edit(m)
		b, _ := json.Marshal(m)
		if why := stufeGegenSoll(t, out, b); why == "" {
			t.Errorf("expected file: edit %d passed", i)
		}
	}
	for i, edit := range []func(ev map[string]any){
		func(ev map[string]any) { ev["affiliation"] = nil },
		func(ev map[string]any) {
			ev["conditions"].(map[string]any)["completeness_from_history"].(map[string]any)["reason"] = "anchor_history_partial"
		},
		func(ev map[string]any) {
			ev["conditions"].(map[string]any)["expected_root_found"].(map[string]any)["met"] = true
		},
	} {
		var r map[string]any
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatal(err)
		}
		edit(r["stats"].(map[string]any)["evidence_level"].(map[string]any))
		b, _ := json.Marshal(r)
		if why := stufeAusBericht(t, string(b), six); why == "" {
			t.Errorf("report objects: edit %d passed", i)
		}
	}
	for i, edit := range []func(ev map[string]any){
		func(ev map[string]any) { ev["state"] = "unknown" },
		func(ev map[string]any) { delete(ev, "anchors") },
		func(ev map[string]any) { ev["level"] = 4 },
		func(ev map[string]any) { ev["notes"] = []any{"no_such_note"} },
	} {
		var r map[string]any
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatal(err)
		}
		edit(r["stats"].(map[string]any)["evidence_level"].(map[string]any))
		b, _ := json.Marshal(r)
		if err := stufeNachSchema(t, string(b)); err == nil {
			t.Errorf("schema: edit %d passed", i)
		}
	}
	// Monotonicity: the run without the anchors of the corpus has the
	// smaller reach; the other way round it is a breach.
	_, without, _ := lauf("--json", "--now-from-package", vektor("valid_sealed_export"))
	_, with, _ := lauf(append(append([]string{"--json", "--now-from-package"}, pruefAnker(t)...), vektor("valid_sealed_export"))...)
	if why := monotonie(t, without, with); why != "" {
		t.Errorf("monotone pair: %s", why)
	}
	if why := monotonie(t, with, without); why == "" {
		t.Error("a breach of the monotonicity passed")
	}
}
