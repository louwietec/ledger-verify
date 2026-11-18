package cli

// The command line of verifier 1.1.0: ledger-verify and verifier2 read every
// command line alike (.ci/check_cli_gleich.py runs both over the same
// command lines; verifier2_test.py, class Aufruf110, holds the same cases for
// verifier2). Every switch stands before the package and is written with two
// dashes, "--" ends them; a switch without a value takes none; --version
// stands alone; -h and --help print the usage on stderr with exit 3;
// --freshness DUR follows the grammar of spec 10.8. Any other form is an
// unusable invocation: exit 3, nothing on stdout, the reason on stderr.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// aufrufPaket is exit 0 in the audit environment of the corpus; its last
// entry is at 2026-01-01T01:01:00.500Z, aufrufNow 7 200 000 ms later.
const aufrufNow = "2026-01-01T03:01:00.500Z"

func aufrufBasis(t *testing.T) []string {
	return append([]string{"--now", aufrufNow}, pruefAnker(t)...)
}

func unbrauchbar(t *testing.T, args ...string) string {
	t.Helper()
	code, out, errOut := lauf(args...)
	if code != 3 || out != "" || !strings.HasPrefix(errOut, Name) {
		t.Errorf("%q: exit %d, stdout %q, stderr %q; want exit 3, no stdout, the reason on stderr", args, code, out, errOut)
	}
	return errOut
}

func TestAufrufSchalterNachDemPaket(t *testing.T) {
	p := vektor("valid_sealed_shutdown")
	for _, nach := range [][]string{{"--json"}, {"--lang", "de"}, {"--", "--json"}, {p}, {"--help"}, {"--version"}, {"--bogus"}} {
		args := append(append(aufrufBasis(t), p), nach...)
		if e := unbrauchbar(t, args...); !strings.Contains(e, "every flag stands before it") {
			t.Errorf("%q: stderr does not say where flags stand: %q", nach, e)
		}
	}
	// "--" ends the switches; after it even "--json" is the package.
	if code, _, errOut := lauf(append(append(aufrufBasis(t), "--"), p)...); code != 0 || errOut != "" {
		t.Errorf("-- <package>: exit %d, stderr %q", code, errOut)
	}
	code, out, _ := lauf("--json", "--", "--json")
	if code != 3 || !strings.Contains(out, `"class": "FORMAT_ERROR"`) {
		t.Errorf("--json -- --json: exit %d, want 3 with FORMAT_ERROR: %s", code, out)
	}
}

func TestAufrufHilfeIstExit3(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}, {"--help", vektor("valid_sealed_shutdown")}, {"zeitstempel", "--help"}, {"zeitstempel", "-h"}} {
		code, out, errOut := lauf(args...)
		if code != 3 || out != "" || !strings.Contains(errOut, "usage: "+Name) {
			t.Errorf("%q: exit %d, stdout %q, stderr %q; want exit 3 and the usage on stderr", args, code, out, errOut)
		}
		// The usage lists every switch in the one spelling accepted.
		if strings.Contains(errOut, "\n  -json") || !strings.Contains(errOut, "\n  --json") {
			t.Errorf("%q: usage does not list --json with two dashes:\n%s", args, errOut)
		}
	}
	// -help is a single dash, refused as such (verifier2 refuses it too).
	unbrauchbar(t, "-help")
}

func TestAufrufVersionAllein(t *testing.T) {
	if code, out, errOut := lauf("--version"); code != 0 || errOut != "" || !strings.HasPrefix(out, VersionLine()+"\n") {
		t.Errorf("--version: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	p := vektor("valid_sealed_shutdown")
	for _, args := range [][]string{{"--version", "--json"}, {"--lang", "xx", "--version"}, {"--lang", "de", "--version"},
		{"--version", "--bogus"}, {"--bogus", "--version"}, {"--version", p}, {p, "--version"}, {"--version=1"}, {"-version"},
		{"zeitstempel", "--version"}} {
		unbrauchbar(t, args...)
	}
}

func TestAufrufSchreibweisen(t *testing.T) {
	p := vektor("valid_sealed_shutdown")
	for _, sw := range [][]string{{"-json"}, {"-lang", "de"}, {"-now", aufrufNow}, {"--json=true"}, {"--json=false"}, {"--json=1"},
		{"--now-from-package=true"}, {"--JSON"}, {"---json"}, {"--js"}, {"-j"}, {"--format", "json"}, {"--freshness-hours", "24"},
		{"--registry", filepath.Join("..", "..", "..", "spec", "registry.json")}} {
		unbrauchbar(t, append(append(sw, aufrufBasis(t)...), p)...)
	}
	for _, sw := range [][]string{{"--json", "--json"}, {"--now-from-package", "--now-from-package"}, {"--lang=de"}} {
		if code, _, errOut := lauf(append(append(sw, aufrufBasis(t)...), p)...); code != 0 || errOut != "" {
			t.Errorf("%q: exit %d, stderr %q", sw, code, errOut)
		}
	}
	if code, _, errOut := lauf(append(append([]string{"--now=" + aufrufNow}, pruefAnker(t)...), p)...); code != 0 || errOut != "" {
		t.Errorf("--now=: exit %d, stderr %q", code, errOut)
	}
	// The value of a switch is the next argument, whatever it looks like.
	if e := unbrauchbar(t, "--now", "--json", p); !strings.Contains(e, "--now: ") {
		t.Errorf("--now --json: %q", e)
	}
	// zeitstempel: the same forms.
	for _, args := range [][]string{{"zeitstempel", "-json"}, {"zeitstempel", "--json=true"}, {"zeitstempel", "--token"}} {
		unbrauchbar(t, args...)
	}
}

func TestAufrufFrischeFenster(t *testing.T) {
	p := vektor("valid_sealed_shutdown")
	for _, f := range []struct {
		wert   string
		exit   int
		klasse string
	}{
		{"2h", 0, ""}, {"120m", 0, ""}, {"7200s", 0, ""}, {"7199s", 1, "TRAILING_SILENCE"}, {"1h", 1, "TRAILING_SILENCE"},
		{"999999h", 0, ""}, {"24h", 0, ""}, {"1s", 1, "TRAILING_SILENCE"},
	} {
		code, out, errOut := lauf(append(append([]string{"--json", "--freshness", f.wert}, aufrufBasis(t)...), p)...)
		var r struct {
			Findings []struct {
				Class string `json:"class"`
			} `json:"findings"`
		}
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatalf("--freshness %s: %v (stderr %q)", f.wert, err, errOut)
		}
		var klassen []string
		for _, x := range r.Findings {
			klassen = append(klassen, x.Class)
		}
		if code != f.exit || strings.Join(klassen, ",") != f.klasse {
			t.Errorf("--freshness %s: exit %d %v, want %d [%s]", f.wert, code, klassen, f.exit, f.klasse)
		}
	}
	for _, schlecht := range []string{"0", "0h", "01h", "-1h", "+1h", "1.5h", "1h30m", "24", " 24h", "24h ", "24H", "1d", "1000000h",
		"nan", "inf", "1_0h", "\u0661h", "", "1e3s", "0x10h", "1ns", "1ms", "1us"} {
		if e := unbrauchbar(t, append(append([]string{"--freshness", schlecht}, aufrufBasis(t)...), p)...); !strings.Contains(e, "--freshness") {
			t.Errorf("--freshness %q: stderr does not name the switch: %q", schlecht, e)
		}
	}
	unbrauchbar(t, append(append([]string{"--freshness", "1h", "--freshness", "1h"}, aufrufBasis(t)...), p)...)
	// The grammar as the registry states it (auditor_inputs.freshness_window).
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		AuditorInputs struct {
			FreshnessWindow struct {
				Flag     string                   `json:"flag"`
				MaxCount int                      `json:"max_count"`
				Pattern  string                   `json:"pattern"`
				UnitMS   map[string]time.Duration `json:"unit_ms"`
				Default  string                   `json:"default"`
			} `json:"freshness_window"`
		} `json:"auditor_inputs"`
	}
	if err := json.Unmarshal(b, &reg); err != nil {
		t.Fatal(err)
	}
	fw := reg.AuditorInputs.FreshnessWindow
	if fw.Flag != "--freshness" || fw.MaxCount != 1 || fw.Pattern != strings.ReplaceAll(frischeRe.String(), "([1-9][0-9]{0,5})([hms])", "[1-9][0-9]{0,5}[hms]") {
		t.Errorf("registry auditor_inputs.freshness_window %+v does not match %s", fw, frischeRe)
	}
	for einheit, ms := range fw.UnitMS {
		if d, err := frischeFenster("1" + einheit); err != nil || d != ms*time.Millisecond {
			t.Errorf("unit %s: %v %v, registry %d ms", einheit, d, err, ms)
		}
	}
	if d, err := frischeFenster(fw.Default); err != nil || d != 24*time.Hour {
		t.Errorf("default %q: %v %v", fw.Default, d, err)
	}
	// The window itself, independent of the flag package.
	for wert, want := range map[string]time.Duration{"1s": time.Second, "90m": 90 * time.Minute, "240h": 240 * time.Hour, "999999h": 999999 * time.Hour} {
		if d, err := frischeFenster(wert); err != nil || d != want {
			t.Errorf("frischeFenster(%q) = %v, %v; want %v", wert, d, err, want)
		}
	}
}

func TestAufrufSpracheEnglischVorgabe(t *testing.T) {
	p := vektor("valid_sealed_shutdown")
	_, en, _ := lauf(append(aufrufBasis(t), p)...)
	_, de, _ := lauf(append(append([]string{"--lang", "de"}, aufrufBasis(t)...), p)...)
	if !strings.Contains(en, "verification report") || !strings.Contains(de, "Prüfbericht") {
		t.Errorf("default en / --lang de:\n%s\n%s", en, de)
	}
}

// A package that cannot be opened: exit 3 with a report (FORMAT_ERROR), no
// check-time line and no missing text key, in both languages and with every
// source of the check time (verifier2 prints no such line either; spec
// 10.10.3 prescribes none). Before 1.1.0 the line read "not determined:
// verify_args.json unusable (⟪MISSING:report.now_source.⟫)".
func TestAufrufPaketNichtLesbar(t *testing.T) {
	fehlt := filepath.Join(t.TempDir(), "fehlt")
	for _, lang := range []string{"de", "en"} {
		for _, zeit := range [][]string{{"--now", aufrufNow}, nil, {"--now-from-package"}} {
			args := append(append(append([]string{"--lang", lang}, zeit...), pruefAnker(t)...), fehlt)
			code, out, errOut := lauf(args...)
			if code != 3 || errOut != "" || !strings.Contains(out, "FORMAT_ERROR") {
				t.Errorf("%q: exit %d, stderr %q:\n%s", args, code, errOut, out)
			}
			if strings.Contains(out, "MISSING") || strings.Contains(out, "(now)") || strings.Contains(out, "verify_args.json") {
				t.Errorf("%q: report shows a check-time line or a missing text:\n%s", args, out)
			}
		}
	}
	// A check time requested from a package that is opened but lacks the
	// file still has its line, with the source named.
	dir := t.TempDir()
	code, out, _ := lauf(append(append([]string{"--lang", "en", "--now-from-package"}, pruefAnker(t)...), dir)...)
	if code != 3 || strings.Contains(out, "MISSING") || !strings.Contains(out, "Verification time (now):") ||
		!strings.Contains(out, "not determined") || !strings.Contains(out, "taken from the package's verify_args.json") {
		t.Errorf("empty directory: exit %d, want 3 and the check-time line naming verify_args.json:\n%s", code, out)
	}
}

// absolut makes the paths of an argument list absolute, for tests that
// change into a directory of their own.
func absolut(t *testing.T, args []string) []string {
	t.Helper()
	out := append([]string(nil), args...)
	for i, a := range out {
		if strings.HasPrefix(a, "..") {
			p, err := filepath.Abs(a)
			if err != nil {
				t.Fatal(err)
			}
			out[i] = p
		}
	}
	return out
}

// The arguments around the switches, as verifier2 reads them since its own
// reading of the command line (verifier2.read_command_line): a "--" after
// the package is a second argument; the value of a switch is the next
// argument even when it begins with a dash; a package whose name begins
// with a dash ("-1", "-x y") is a single-dash switch unless "--" stands
// before it. Before, verifier2 judged "<package> --", "-1" and "-x y" and
// refused "--tsa-root -roots.pem" (argparse), where this verifier did the
// opposite.
func TestAufrufTrennerUndWerte(t *testing.T) {
	p, _ := filepath.Abs(vektor("valid_sealed_shutdown"))
	basis := absolut(t, aufrufBasis(t))
	for _, args := range [][]string{append(append(basis, p), "--"), append(append(append([]string{"--json"}, basis...), p), "--"),
		append(append(basis, "--", p), "--")} {
		if e := unbrauchbar(t, args...); !strings.Contains(e, "every flag stands before it") {
			t.Errorf("%q: %q", args[len(args)-2:], e)
		}
	}
	pem, err := os.ReadFile(vektor("zeitstempel_timestamp_ess_both.wurzel.pem"))
	if err != nil {
		t.Fatal(err)
	}
	wurzel, err := os.ReadFile(vektor("pruefer_herstellerwurzel.json"))
	if err != nil {
		t.Fatal(err)
	}
	zs := absolut(t, []string{"zeitstempel", "--token", vektor("zeitstempel_timestamp_ess_both.token.der"),
		"--data", vektor("zeitstempel_timestamp_ess_both.daten.json"), "--purpose", "chain"})
	t.Chdir(t.TempDir())
	for name, b := range map[string][]byte{"-roots.pem": pem, "--": pem, "-root.json": wurzel} {
		if err := os.WriteFile(name, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"-1", "-x y"} {
		if err := os.Symlink(p, n); err != nil {
			t.Fatalf("symlink for a package named %q: %v", n, err)
		}
	}
	for _, args := range [][]string{
		append(append([]string{"--tsa-root", "-roots.pem"}, basis...), p),
		append(append([]string{"--tsa-root", "--"}, basis...), p),
		append(append([]string{"--vendor-root", "-root.json"}, basis...), p),
		append(append([]string{"--vendor-statement-key", "-=" + strings.Repeat("ab", 32)}, basis...), p),
		append(basis, "--", "-1"),
		append(basis, "--", "-x y"),
	} {
		if code, _, errOut := lauf(args...); code != 0 || errOut != "" {
			t.Errorf("%q: exit %d, stderr %q; want the verdict 0", args, code, errOut)
		}
	}
	for _, n := range []string{"-1", "-x y"} {
		unbrauchbar(t, append(basis, n)...)
	}
	// zeitstempel: "--" ends the switches there too, and nothing may follow.
	code0, out0, _ := lauf(append(zs, "--tsa-root", "-roots.pem")...)
	code1, out1, _ := lauf(append(zs, "--tsa-root", "-roots.pem", "--")...)
	if code0 == 3 || code0 != code1 || out0 != out1 {
		t.Errorf("zeitstempel with and without a final --: exit %d and %d", code0, code1)
	}
	unbrauchbar(t, append(zs, "--", "x")...)
}

// --now 0001-01-01T00:00:00Z is grammatical (spec 10.8, year 0001 to 9999)
// and is the zero time.Time: before 1.1.0 it read as "not given", and the
// system clock took its place (exit 1, TRAILING_SILENCE), while verifier2
// honoured it (exit 0). A check time of that instant from verify_args.json
// was reported as "not determined" in a run without FORMAT_ERROR.
func TestAufrufNullzeit(t *testing.T) {
	p := vektor("valid_sealed_shutdown")
	code, out, errOut := lauf(append(append([]string{"--json", "--now", "0001-01-01T00:00:00Z"}, pruefAnker(t)...), p)...)
	var r struct {
		Stats struct {
			Now       string `json:"now"`
			NowSource string `json:"now_source"`
		} `json:"stats"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil || code != 0 || r.Stats.Now != "0001-01-01T00:00:00Z" || r.Stats.NowSource != "flag" {
		t.Errorf("--now 0001-01-01T00:00:00Z: exit %d, stats %+v, %v, stderr %q; want exit 0 with now from the flag", code, r.Stats, err, errOut)
	}
	if e := unbrauchbar(t, append(append([]string{"--now", "0001-01-01T00:00:00Z", "--requested-at", "2025-01-01T00:00:00Z"}, pruefAnker(t)...), p)...); !strings.Contains(e, "after the check time") {
		t.Errorf("--requested-at after --now 0001-...: %q", e)
	}
	kopie := t.TempDir()
	if err := os.CopyFS(kopie, os.DirFS(p)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(kopie, "verify_args.json"), []byte(`{"now":"0001-01-01T00:00:00Z"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ = lauf(append(append([]string{"--lang", "en", "--now-from-package"}, pruefAnker(t)...), kopie)...)
	if code != 0 || strings.Contains(out, "not determined") || !strings.Contains(out, "0001-01-01T00:00:00Z (taken from the package's verify_args.json") {
		t.Errorf("verify_args.json with 0001-01-01T00:00:00Z: exit %d:\n%s", code, out)
	}
}

// Every file of the auditor is read up to its limit plus one byte, never
// further: os.Stat says 0 bytes for /dev/zero, and before 1.1.0 it was read
// until the runtime died (exit 2, "invalid"). A file without a limit in spec
// 10.8 is read up to MaxDateiOhneGrenze, as by verifier2.
func TestAufrufGrenzenOhneStat(t *testing.T) {
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Fatalf("/dev/zero: %v", err)
	}
	p := vektor("valid_sealed_shutdown")
	for _, sw := range []string{"--vendor-key-list", "--tsa-qualified-roots", "--vendor-log", "--anchor-history", "--tsa-root",
		"--vendor-log-tsa-root", "--vendor-root"} {
		if e := unbrauchbar(t, append(append([]string{sw, "/dev/zero"}, aufrufBasis(t)...), p)...); !strings.Contains(e, "more than") {
			t.Errorf("%s /dev/zero: %q", sw, e)
		}
	}
	unbrauchbar(t, "zeitstempel", "--token", "/dev/zero", "--data", vektor("zeitstempel_timestamp_ess_both.daten.json"))
	gross := filepath.Join(t.TempDir(), "gross.pem")
	if err := os.WriteFile(gross, make([]byte, MaxDateiOhneGrenze+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if e := unbrauchbar(t, append(append([]string{"--tsa-root", gross}, aufrufBasis(t)...), p)...); !strings.Contains(e, "more than 33554432 bytes") {
		t.Errorf("--tsa-root above the bound: %q", e)
	}
}

type kaputt struct{}

func (kaputt) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }

// An output that cannot be written is exit 3 with the reason on stderr, in
// every mode; before 1.1.0 the error was dropped and the verdict returned.
func TestAufrufAusgabeNichtSchreibbar(t *testing.T) {
	p := vektor("valid_sealed_shutdown")
	for _, args := range [][]string{append(aufrufBasis(t), p), append(append([]string{"--json"}, aufrufBasis(t)...), p), {"--version"},
		{"zeitstempel", "--token", vektor("zeitstempel_timestamp_ess_both.token.der"), "--data", vektor("zeitstempel_timestamp_ess_both.daten.json")}} {
		var e strings.Builder
		if code := Main(args, kaputt{}, &e); code != 3 || !strings.Contains(e.String(), "cannot write the output") {
			t.Errorf("%q: exit %d, stderr %q; want 3 and the reason", args, code, e.String())
		}
	}
}
