package cli

// Regel "Kein Pruefertext ohne LEDGER" / rule: every text an
// auditor gets from the command line — report (DE and EN) for a valid, an
// invalid and an incomplete chain, --version, the usage text and the error
// messages — names LEDGER and never the former product name.
//
// Gemessen wird an echten Laeufen von Main ueber eingefrorene Testvektoren mit
// der Pruefumgebung der Erwartungen (spec/testvectors/pruefer_*), nicht an den
// Texttabellen: ein Titel, der in der Tabelle stimmt, aber nie gedruckt wird,
// waere kein Beleg. / Measured on real runs of Main over frozen vectors.

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// eingefroreneKennungen are identifiers the old name stays in on purpose:
// signed, normative format ids of the specification. A report may quote them
// (e.g. a vendor list with a wrong format); they are no product name.
var eingefroreneKennungen = []string{"rekorder-herstellerschluessel/1"}

// alterName reports whether s names the former product: "Rekorder",
// "rekorder-verify" or any other spelling, frozen identifiers excepted.
func alterName(s string) bool {
	for _, k := range eingefroreneKennungen {
		s = strings.ReplaceAll(s, k, "")
	}
	return strings.Contains(strings.ToLower(s), "rekorder")
}

// vektor is the path of a frozen vector RELATIVE to this package: the report
// prints the path it was given, and an absolute path would make the check
// depend on the directory the repository happens to be checked out in.
func vektor(name string) string {
	return filepath.Join("..", "..", "..", "spec", "testvectors", name)
}

// pruefAnker returns the audit environment the frozen expectations hold for
// (spec 7.1): the test vendor's root and its pinned keys, as flags.
func pruefAnker(t *testing.T) []string {
	t.Helper()
	dir := vektor("")
	args := []string{"--vendor-root", filepath.Join(dir, "pruefer_herstellerwurzel.json")}
	b, err := os.ReadFile(filepath.Join(dir, "pruefer_herstellerschluessel.txt"))
	if err != nil {
		t.Fatalf("audit environment missing: %v", err)
	}
	for _, k := range strings.Fields(string(b)) {
		args = append(args, "--vendor-key", k)
	}
	return args
}

func lauf(args ...string) (code int, stdout, stderr string) {
	var o, e bytes.Buffer
	code = Main(args, &o, &e)
	return code, o.String(), e.String()
}

// pruefeText is the acceptance itself: LEDGER present, old name absent.
func pruefeText(t *testing.T, quelle, text string) {
	t.Helper()
	if strings.TrimSpace(text) == "" {
		t.Errorf("%s: no text at all — nothing to check", quelle)
		return
	}
	if !strings.Contains(text, Product) {
		t.Errorf("%s: does not name %s:\n%s", quelle, Product, text)
	}
	if alterName(text) {
		t.Errorf("%s: names the former product (Rekorder / rekorder-verify):\n%s", quelle, text)
	}
}

func TestBerichteNennenLEDGER(t *testing.T) {
	faelle := []struct {
		name, vektor string
		exit         int
	}{
		{"gueltig / valid", "valid_sealed_shutdown", 0},
		{"ungueltig / invalid", "tamper_rewrite", 2},
		{"unvollstaendig / incomplete", "valid_basic", 4},
	}
	for _, f := range faelle {
		for _, lang := range []string{"de", "en"} {
			args := append([]string{"--lang", lang, "--now-from-package"}, pruefAnker(t)...)
			code, out, errOut := lauf(append(args, vektor(f.vektor))...)
			quelle := f.name + " " + f.vektor + " [" + lang + "]"
			if code != f.exit {
				t.Errorf("%s: exit %d, want %d (stderr %q)", quelle, code, f.exit, errOut)
			}
			if errOut != "" {
				t.Errorf("%s: unexpected stderr %q", quelle, errOut)
			}
			pruefeText(t, quelle, out)
			// The title is the first line and carries both names.
			erste := strings.SplitN(out, "\n", 2)[0]
			if !strings.HasPrefix(erste, Product+": ") || !strings.Contains(erste, "("+Name+")") {
				t.Errorf("%s: title line %q does not read \"LEDGER: … (ledger-verify)\"", quelle, erste)
			}
		}
	}
}

func TestVersionNenntLEDGER(t *testing.T) {
	code, out, errOut := lauf("--version")
	if code != 0 || errOut != "" {
		t.Fatalf("--version: exit %d, stderr %q", code, errOut)
	}
	pruefeText(t, "--version", out)
	zeilen := strings.Split(strings.TrimRight(out, "\n"), "\n")
	want := Name + " " + Version + " (spec " + SpecVersion + ") · " + Product
	if zeilen[0] != want {
		t.Errorf("--version first line %q, want %q", zeilen[0], want)
	}
	// Appliance tests and the WASM equivalence proof read the spec edition
	// back with exactly this pattern (appliance/cmd/kern/aufbewahrung_test.go).
	if m := regexp.MustCompile(`\(spec (\d+\.\d+)\)`).FindStringSubmatch(zeilen[0]); m == nil || m[1] != SpecVersion {
		t.Errorf("--version: \"(spec X.Y)\" not readable from %q", zeilen[0])
	}
	// Spec 7.1: the version output names the compiled-in vendor root.
	if len(zeilen) != 2 || !strings.HasPrefix(zeilen[1], "vendor root compiled in: ") {
		t.Errorf("--version: second line must name the compiled-in vendor root (spec 7.1), got %q", out)
	}
}

func TestAufrufUndFehlerNennenLEDGER(t *testing.T) {
	faelle := []struct {
		quelle string
		args   []string
		stderr string // expected in stderr
	}{
		{"usage (ohne Argument / no argument)", nil, "usage: " + Name + " [flags]"},
		{"unbekannter Schalter / unknown flag", []string{"--gibtsnicht", "x"}, "usage: " + Name + " [flags]"},
		{"--lang falsch / wrong", []string{"--lang", "fr", vektor("valid_basic")}, Name + ": --lang must be de or en"},
		{"--expect-root falsch / wrong", []string{"--expect-root", "abc", vektor("valid_basic")}, Name + ": --expect-root must be 64 hex characters"},
		{"--vendor-root fehlt / missing", []string{"--vendor-root", filepath.Join(t.TempDir(), "fehlt.json"), vektor("valid_basic")}, Name + ": --vendor-root: "},
	}
	for _, f := range faelle {
		code, out, errOut := lauf(f.args...)
		if code != 3 {
			t.Errorf("%s: exit %d, want 3", f.quelle, code)
		}
		if out != "" {
			t.Errorf("%s: unexpected stdout %q", f.quelle, out)
		}
		if !strings.Contains(errOut, f.stderr) {
			t.Errorf("%s: stderr lacks %q:\n%s", f.quelle, f.stderr, errOut)
		}
		if alterName(errOut) {
			t.Errorf("%s: names the former product:\n%s", f.quelle, errOut)
		}
		// Every line the verifier writes itself starts with its name or is
		// part of the usage block, which names LEDGER in its first line.
		if !strings.Contains(errOut, Product) && !strings.HasPrefix(errOut, Name+": ") {
			t.Errorf("%s: message carries neither %s nor the prefix %q:\n%s", f.quelle, Product, Name+": ", errOut)
		}
	}
	// The usage header names the product twice: the tool and the packages.
	_, _, usage := lauf()
	kopf := strings.SplitN(usage, "\n", 2)[0]
	if want := Name + " " + Version + ": " + Product + " offline verifier for " + Product + " verification packages (spec " + SpecVersion + ")"; kopf != want {
		t.Errorf("usage header %q, want %q", kopf, want)
	}
}

// Red check of the check itself: the helper must see the old name in every
// spelling that could come back, and must let the frozen format id pass.
func TestAlterNameErkennung(t *testing.T) {
	for _, s := range []string{"Rekorder — Prüfbericht", "Rekorder: Prüfbericht", "rekorder-verify 1.0.0", "REKORDER", "des Rekorders"} {
		if !alterName(s) {
			t.Errorf("alterName(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"LEDGER: Prüfbericht (ledger-verify)", "format rekorder-herstellerschluessel/1 expected"} {
		if alterName(s) {
			t.Errorf("alterName(%q) = true, want false", s)
		}
	}
}

// Spec 10.8 (from 1.9): the auditor's check time is read with the grammar of
// the package — UTC with Z, uppercase T, ASCII digits, year 0001-9999 —
// and anything else is an unusable invocation (exit 3), never read in the
// host's time zone. time.Parse(RFC3339Nano) took an offset, a comma before
// the fraction and a one-digit hour.
func TestNowGrammar(t *testing.T) {
	anker := pruefAnker(t)
	for _, gut := range []string{"2026-01-01T12:02:00Z", "2026-01-01T12:02:00.5Z", "2026-01-01T12:02:00.1234567891Z"} {
		code, out, errOut := lauf(append(append([]string{"--json", "--now", gut}, anker...), vektor("valid_basic"))...)
		if code != 4 || errOut != "" || !strings.Contains(out, `"now_source": "flag"`) {
			t.Errorf("--now %s: exit %d, stderr %q", gut, code, errOut)
		}
	}
	for _, schlecht := range []string{"2026-01-01T12:02:00", "2026-01-01", "2026-01-01 12:02:00Z", "20260101T120200Z", "2026-W01-4T12:02:00Z",
		"2026-01-01T12:02Z", "2026-01-01T12:02:00.Z", "2026-01-01T12:02:00,5Z", "2026-01-01T1:02:00Z", "0000-01-01T00:00:00Z",
		"2026-01-01T12:02:00+01:00", "2026-01-01t12:02:00z"} {
		code, out, errOut := lauf("--now", schlecht, vektor("valid_basic"))
		if code != 3 || out != "" || !strings.Contains(errOut, Name+": --now: ") {
			t.Errorf("--now %q: exit %d, stdout %q, stderr %q — want exit 3 with the reason", schlecht, code, out, errOut)
		}
	}
}

// Spec 10.8: --expect-root takes ROOT or TREE_SIZE:ROOT, any number of times;
// every one not found is MERKLE_INCONSISTENT, every one found is an anchor
// and establishes completeness up to its tree_size.
func TestExpectRootForms(t *testing.T) {
	// valid_basic: the last countersigned checkpoint covers tree_size 309.
	const root309 = "82694f14b24d78ba0ec8146f808694d18927194e32835ad7bd1c03fdfeb8ecb4"
	anker := pruefAnker(t)
	laufMit := func(extra ...string) (int, string, string) {
		args := append([]string{"--json", "--now-from-package"}, anker...)
		args = append(args, extra...)
		return lauf(append(args, vektor("valid_basic"))...)
	}
	for _, c := range []struct {
		name  string
		args  []string
		exit  int
		upTo  string
		klass string
	}{
		{"TREE_SIZE:ROOT", []string{"--expect-root", "309:" + root309}, 4, `"up_to_tree_size": 309`, ""},
		{"ROOT, upper case", []string{"--expect-root", strings.ToUpper(root309)}, 4, `"up_to_tree_size": 309`, ""},
		{"wrong tree_size", []string{"--expect-root", "308:" + root309}, 2, `"up_to_tree_size": null`, "MERKLE_INCONSISTENT"},
		{"beyond the package", []string{"--expect-root", "312:" + root309}, 2, `"up_to_tree_size": null`, "MERKLE_INCONSISTENT"},
		{"repeated: one found, one not", []string{"--expect-root", "309:" + root309, "--expect-root", strings.Repeat("ab", 32)}, 2, `"up_to_tree_size": 309`, "MERKLE_INCONSISTENT"},
	} {
		code, out, errOut := laufMit(c.args...)
		if code != c.exit || errOut != "" {
			t.Errorf("%s: exit %d (want %d), stderr %q", c.name, code, c.exit, errOut)
		}
		if !strings.Contains(out, c.upTo) {
			t.Errorf("%s: stats.completeness lacks %s:\n%s", c.name, c.upTo, out)
		}
		if c.klass != "" && !strings.Contains(out, `"class": "`+c.klass+`"`) {
			t.Errorf("%s: no %s:\n%s", c.name, c.klass, out)
		}
	}
	for _, schlecht := range []string{"abc", "0:" + root309, "07:" + root309, "x:" + root309, root309 + "0", "309:" + root309[:63]} {
		code, out, errOut := laufMit("--expect-root", schlecht)
		if code != 3 || out != "" || !strings.Contains(errOut, Name+": --expect-root must be 64 hex characters") {
			t.Errorf("--expect-root %q: exit %d, stdout %q, stderr %q — want exit 3", schlecht, code, out, errOut)
		}
	}
}

// The JSON output carries the two statements of 1.9 for every package that
// is not a format error: stats.completeness (8.6) and stats.residual_window
// (11.2) — with the values the specification's example gives for
// valid_basic (T = 309, N = 311, 2 entries, 1,000 ms) and valid_no_anchor
// (T = 0, 16 entries).
func TestJSONCompletenessAndResidualWindow(t *testing.T) {
	anker := pruefAnker(t)
	for _, c := range []struct {
		vektor string
		want   []string
	}{
		{"valid_basic", []string{`"completeness": {`, `"status": "not_established"`, `"after_tree_size": 309`, `"first_seq": 310`, `"last_seq": 311`,
			`"entries": 2`, `"span_ms": 1000`, `"unanswered_anchor_messages": 0`, `"beyond_cadence": false`}},
		{"valid_no_anchor", []string{`"after_tree_size": 0`, `"first_seq": 1`, `"entries": 16`, `"from_ts": null`, `"span_ms": null`, `"beyond_cadence": true`}},
	} {
		code, out, errOut := lauf(append(append([]string{"--json", "--now-from-package"}, anker...), vektor(c.vektor))...)
		if code != 4 || errOut != "" {
			t.Errorf("%s: exit %d, stderr %q", c.vektor, code, errOut)
		}
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("%s: JSON lacks %s:\n%s", c.vektor, w, out)
			}
		}
	}
	code, out, _ := lauf(append(append([]string{"--json", "--now-from-package"}, anker...), vektor("format_broken_json"))...)
	if code != 3 || !strings.Contains(out, `"completeness": null`) || !strings.Contains(out, `"residual_window": null`) {
		t.Errorf("format error: exit %d, JSON lacks completeness/residual_window null (spec 10.10.1):\n%s", code, out)
	}
}
