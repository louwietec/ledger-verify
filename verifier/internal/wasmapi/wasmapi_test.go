package wasmapi

// Tests of the browser edition without WebAssembly: the options against the
// table of format spec 10.8, every unusable invocation of 10.8 as an error
// message instead of a verdict, the texts of the two lines under the verdict
// against spec/registry.json (10.10.3), and the whole corpus through pruefen
// against cli.Main, byte for byte in JSON and text, with the audit
// environment of the corpus and with each vector's own pruefer_<name>.json
// (10.8, ledger-pruefumgebung/1). tests/wasm/aequivalenz.mjs measures the
// same on the compiled module.
// / The browser path without WebAssembly, held against the spec, the
// registry and the native command line.

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"louwietec.com/ledger-verify/verifier/internal/cli"
	"louwietec.com/ledger-verify/verifier/internal/vfy"
)

func vektoren(name string) string {
	return filepath.Join("..", "..", "..", "spec", "testvectors", name)
}

func text(s string) wert     { return wert{art: artText, text: s} }
func bytesW(b []byte) wert   { return wert{art: artBytes, bytes: b} }
func zahl(f float64) wert    { return wert{art: artZahl, zahl: f} }
func wahr(b bool) wert       { return wert{art: artWahr, wahr: b} }
func liste(w ...wert) wert   { return wert{art: artListe, liste: w} }
func texte(s ...string) wert { return liste(mapW(s, text)...) }
func mapW[T any](xs []T, f func(T) wert) []wert {
	out := []wert{}
	for _, x := range xs {
		out = append(out, f(x))
	}
	return out
}

func lies(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// packen zips a vector directory like tests/wasm/lauf.sh: every file with
// its path relative to the directory, sorted.
func packen(t *testing.T, dir string) []byte {
	t.Helper()
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	var pfade []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			pfade = append(pfade, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(pfade)
	for _, p := range pfade {
		rel, _ := filepath.Rel(dir, p)
		w, err := z.CreateHeader(&zip.FileHeader{Name: filepath.ToSlash(rel), Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		w.Write(lies(t, p))
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// korpus is the audit environment of the corpus (spec/testvectors README 3):
// the test vendor's root and its pinned keys, as options and as switches.
func korpus(t *testing.T) ([]angabe, []string) {
	t.Helper()
	wurzel := vektoren("pruefer_herstellerwurzel.json")
	pins := strings.Fields(string(lies(t, vektoren("pruefer_herstellerschluessel.txt"))))
	args := []string{"--vendor-root", wurzel}
	for _, p := range pins {
		args = append(args, "--vendor-key", p)
	}
	return []angabe{{"vendorRootJson", bytesW(lies(t, wurzel))}, {"vendorKeys", texte(pins...)}}, args
}

// pruefumgebung turns a file ledger-pruefumgebung/1 into the options of the
// browser edition, each member into the option of the same switch (format
// spec 10.8, table), and into the switches of vfy.AuditEnvironmentArgs.
func pruefumgebung(t *testing.T, datei string) ([]angabe, []string) {
	t.Helper()
	roh := lies(t, vektoren(datei))
	args, err := vfy.AuditEnvironmentArgs(roh, vektoren(""))
	if err != nil {
		t.Fatalf("%s: %v", datei, err)
	}
	var u struct {
		Korpus             bool     `json:"korpus"`
		VendorRoot         []string `json:"vendor_root"`
		VendorKey          []string `json:"vendor_key"`
		VendorKeyList      []string `json:"vendor_key_list"`
		VendorLogKey       []string `json:"vendor_log_key"`
		VendorStatementKey []string `json:"vendor_statement_key"`
		TSARoot            []string `json:"tsa_root"`
		TSAQualifiedRoots  *string  `json:"tsa_qualified_roots"`
		VendorLogTSARoot   []string `json:"vendor_log_tsa_root"`
		ExpectRoot         []string `json:"expect_root"`
		VendorLog          []string `json:"vendor_log"`
		AnchorHistory      []string `json:"anchor_history"`
		RequestedAt        *string  `json:"requested_at"`
	}
	if err := json.Unmarshal(roh, &u); err != nil {
		t.Fatalf("%s: %v", datei, err)
	}
	dateien := func(namen []string) wert {
		return liste(mapW(namen, func(n string) wert { return bytesW(lies(t, vektoren(n))) })...)
	}
	var roots, keys []string
	if u.Korpus {
		roots = append(roots, "pruefer_herstellerwurzel.json")
		keys = strings.Fields(string(lies(t, vektoren("pruefer_herstellerschluessel.txt"))))
	}
	roots = append(roots, u.VendorRoot...)
	keys = append(keys, u.VendorKey...)
	a := []angabe{
		{"vendorRootJson", dateien(roots)},
		{"vendorKeys", texte(keys...)},
		{"vendorKeyListJson", dateien(u.VendorKeyList)},
		{"vendorLogKeys", texte(u.VendorLogKey...)},
		{"vendorStatementKeys", texte(u.VendorStatementKey...)},
		{"tsaRootsPem", dateien(u.TSARoot)},
		{"vendorLogTsaRootsPem", dateien(u.VendorLogTSARoot)},
		{"expectRoots", texte(u.ExpectRoot...)},
		{"vendorLogJson", dateien(u.VendorLog)},
		{"anchorHistoryJson", dateien(u.AnchorHistory)},
	}
	if u.TSAQualifiedRoots != nil {
		a = append(a, angabe{"tsaQualifiedRootsJson", bytesW(lies(t, vektoren(*u.TSAQualifiedRoots)))})
	}
	if u.RequestedAt != nil {
		a = append(a, angabe{"requestedAt", text(*u.RequestedAt)})
	}
	return a, args
}

func registry(t *testing.T) map[string]any {
	t.Helper()
	var r map[string]any
	if err := json.Unmarshal(lies(t, filepath.Join("..", "..", "..", "spec", "registry.json")), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// at walks a decoded JSON value along keys.
func at(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func atS(v any, keys ...string) string { s, _ := at(v, keys...).(string); return s }

// ------------------------------------------------------------ the texts

// TestTexteWieRegistry holds every copied text of zeilen.go against
// spec/registry.json, in both languages, and the identity of the module
// against the command line.
func TestTexteWieRegistry(t *testing.T) {
	r := registry(t)
	ev := at(r, "verifier", "evidence_level")
	af := at(r, "verifier", "affiliation", "texts")
	for _, lang := range []string{"de", "en"} {
		soll := map[string]string{}
		for _, k := range []string{"browser", "head_level0", "state_line", "label", "label_chain"} {
			soll[k] = atS(ev, "texts", k, lang)
		}
		soll["level0_name"] = atS(ev, "levels", "0", "name_"+lang)
		for _, s := range []string{"chain_invalid", "format_error"} {
			soll["state."+s] = atS(ev, "states", s, lang)
		}
		// The common start of every text that opens the line on affiliation.
		var anfang string
		for i, k := range []string{"affiliated", "affiliated_vendor_itself", "not_affiliated", "not_determined", "not_checked"} {
			s := atS(af, k, lang)
			if s == "" {
				t.Fatalf("registry verifier.affiliation.texts.%s.%s missing", k, lang)
			}
			if i == 0 {
				anfang = s
			}
			for !strings.HasPrefix(s, anfang) {
				anfang = anfang[:len(anfang)-1]
			}
		}
		soll["affiliation_prefix"] = strings.TrimSpace(anfang)
		if len(zeilenTexte[lang]) != len(soll) {
			t.Errorf("%s: zeilen.go carries %d texts, the registry places %d", lang, len(zeilenTexte[lang]), len(soll))
		}
		for k, s := range soll {
			if s == "" {
				t.Errorf("%s: registry text for %s missing", lang, k)
			}
			if zeilenTexte[lang][k] != s {
				t.Errorf("%s: %s is %q in zeilen.go, %q in the registry", lang, k, zeilenTexte[lang][k], s)
			}
		}
		// The label swap of beweisstufenZeile needs the browser text to
		// begin with the label.
		if !strings.HasPrefix(soll["browser"], soll["label"]) {
			t.Errorf("%s: the browser text %q does not begin with the label %q", lang, soll["browser"], soll["label"])
		}
	}
	if specVersion != cli.SpecVersion || Version != cli.Version || name != cli.Name || product != cli.Product {
		t.Errorf("module %s %s (spec %s) %s, command line %s %s (spec %s) %s", name, Version, specVersion, product, cli.Name, cli.Version, cli.SpecVersion, cli.Product)
	}
	if v := fassung(); v["spec"] != specVersion || v["name"] != name || v["product"] != product {
		t.Errorf("ledgerVerifyVersion %v", v)
	}
}

// ------------------------------------------------------------ the options

// TestOptionenWieSpezifikation reads the table of format spec 10.8 (both
// languages) and requires every option of its column "Option im Browser"
// with exactly its form; a switch the table allows at most once takes no
// list.
func TestOptionenWieSpezifikation(t *testing.T) {
	formen := map[string]form{}
	for _, o := range optionen {
		if _, doppelt := formen[o.name]; doppelt {
			t.Errorf("option %s twice", o.name)
		}
		formen[o.name] = o.form
	}
	zeile := regexp.MustCompile("^\\| [^|]+ \\| (`--[^|]+) \\| `([A-Za-z]+)` \\(([^)]*)\\) \\|")
	for _, sp := range []struct{ datei, oder, einmal string }{
		{"format.de.md", " oder ", "höchstens einmal"},
		{"format.en.md", " or ", "at most once"},
	} {
		n := 0
		for _, z := range strings.Split(string(lies(t, filepath.Join("..", "..", "..", "spec", sp.datei))), "\n") {
			m := zeile.FindStringSubmatch(z)
			if m == nil {
				continue
			}
			n++
			soll := map[string]form{
				"`Uint8Array`": formBytes, "`Uint8Array[]`": formBytesListe, "`string`": formText, "`string[]`": formTextListe,
				"`Uint8Array`" + sp.oder + "`Uint8Array[]`": formBytesOderListe,
			}
			f, ok := soll[m[3]]
			if !ok {
				t.Errorf("%s: option %s has the form %q this test does not know", sp.datei, m[2], m[3])
				continue
			}
			if got, ok := formen[m[2]]; !ok {
				t.Errorf("%s: option %s of the table is not an option of the module", sp.datei, m[2])
			} else if got != f {
				t.Errorf("%s: option %s takes form %d, the table says %q", sp.datei, m[2], got, m[3])
			}
			if strings.Contains(m[1], sp.einmal) && (f == formBytesListe || f == formTextListe || f == formBytesOderListe) {
				t.Errorf("%s: %s stands at most once, but %s takes a list", sp.datei, m[1], m[2])
			}
		}
		if n != 9 {
			t.Errorf("%s: %d rows with a browser option in the table of 10.8, want 9", sp.datei, n)
		}
	}
}

// paket is valid_basic, packed once.
var paketCache []byte

func paket(t *testing.T) []byte {
	if paketCache == nil {
		paketCache = packen(t, vektoren("valid_basic"))
	}
	return paketCache
}

// zusammen puts extra over basis: an option of extra replaces the option of
// the same name in basis, every other one is added.
func zusammen(basis []angabe, extra ...angabe) []angabe {
	out := append([]angabe{}, basis...)
	for _, e := range extra {
		ersetzt := false
		for i := range out {
			if out[i].name == e.name {
				out[i], ersetzt = e, true
			}
		}
		if !ersetzt {
			out = append(out, e)
		}
	}
	return out
}

// pruefenMit judges valid_basic in the audit environment of the corpus with
// the check time from verify_args.json, extra put over it.
func pruefenMit(t *testing.T, extra ...angabe) map[string]any {
	t.Helper()
	k, _ := korpus(t)
	a := zusammen(append([]angabe{{"nowFromPackage", wahr(true)}}, k...), extra...)
	return pruefen(bytesW(paket(t)), a, func() time.Time { return time.Date(2026, 1, 1, 12, 2, 0, 0, time.UTC) })
}

// TestUnbrauchbareAufrufe: every violation of a name, type, grammar, limit or
// rule of format spec 10.8 is an error message instead of a verdict: exit 3,
// error set, no report, none of the result members of 10.10.1.
func TestUnbrauchbareAufrufe(t *testing.T) {
	hex := strings.Repeat("ab", 32)
	pem := lies(t, vektoren("valid_time_anchor/keys/tsa/probestelle.pem"))
	auszug := lies(t, vektoren("pruefer_evidence_level_3.vendor_log-1.json"))
	historie := lies(t, vektoren("pruefer_evidence_level_3.anchor_history-1.json"))
	viele := func(b []byte, n int) wert {
		w := liste()
		for i := 0; i < n; i++ {
			w.liste = append(w.liste, bytesW(b))
		}
		return w
	}
	gross := func(n int) []byte { return bytes.Repeat([]byte(" "), n) }
	faelle := []struct {
		name   string
		paket  *wert    // another first argument, with extra as the whole options
		extra  []angabe // put over the corpus environment with nowFromPackage
		enthae string
	}{
		{name: "package not a Uint8Array", paket: &wert{art: artText, text: "x"}, enthae: "erstes Argument"},
		{name: "package missing", paket: &wert{art: artFehlt}, enthae: "erstes Argument"},
		{name: "package an array", paket: &wert{art: artListe}, enthae: "erstes Argument"},
		{name: "unknown option", extra: []angabe{{"tsaRoot", bytesW(pem)}}, enthae: `unknown option "tsaRoot"`},
		{name: "unknown option, case", extra: []angabe{{"RequestedAt", text("2026-01-01T00:00:00Z")}}, enthae: "unknown option"},
		{name: "option twice", paket: &wert{art: artBytes}, extra: []angabe{{"lang", text("de")}, {"lang", text("en")}}, enthae: "more than once"},
		{name: "lang number", extra: []angabe{{"lang", zahl(1)}}, enthae: "lang muss eine Zeichenkette"},
		{name: "lang fr", extra: []angabe{{"lang", text("fr")}}, enthae: "lang muss de oder en"},
		{name: "name bytes", extra: []angabe{{"name", bytesW(nil)}}, enthae: "name muss eine Zeichenkette"},
		{name: "nowFromPackage string", extra: []angabe{{"nowFromPackage", text("true")}}, enthae: "Wahrheitswert"},
		{name: "freshness string", extra: []angabe{{"freshnessSeconds", text("60")}}, enthae: "Zahl"},
		{name: "freshness 0", extra: []angabe{{"freshnessSeconds", zahl(0)}}, enthae: "freshnessSeconds"},
		{name: "freshness negative", extra: []angabe{{"freshnessSeconds", zahl(-60)}}, enthae: "freshnessSeconds"},
		{name: "freshness NaN", extra: []angabe{{"freshnessSeconds", zahl(math.NaN())}}, enthae: "freshnessSeconds"},
		{name: "freshness Inf", extra: []angabe{{"freshnessSeconds", zahl(math.Inf(1))}}, enthae: "freshnessSeconds"},
		{name: "freshness below 1 ns", extra: []angabe{{"freshnessSeconds", zahl(1e-12)}}, enthae: "freshnessSeconds"},
		{name: "freshness beyond a Duration", extra: []angabe{{"freshnessSeconds", zahl(1e300)}}, enthae: "freshnessSeconds"},
		{name: "now with a space", extra: []angabe{{"now", text("2026-01-01 12:00:00Z")}}, enthae: "now ist kein Zeitpunkt"},
		{name: "now with an offset", extra: []angabe{{"now", text("2026-01-01T12:00:00+01:00")}}, enthae: "now ist kein Zeitpunkt"},
		{name: "now without seconds", extra: []angabe{{"now", text("2026-01-01T12:00Z")}}, enthae: "now ist kein Zeitpunkt"},
		{name: "now without zone", extra: []angabe{{"now", text("2026-01-01T12:00:00")}}, enthae: "now ist kein Zeitpunkt"},
		{name: "expectRoots a string", extra: []angabe{{"expectRoots", text(hex)}}, enthae: "Array von Zeichenketten"},
		{name: "expectRoots a number", extra: []angabe{{"expectRoots", liste(zahl(1))}}, enthae: "anderes als Zeichenketten"},
		{name: "expectRoot 0:", extra: []angabe{{"expectRoot", text("0:" + hex)}}, enthae: "erwartete Wurzel"},
		{name: "expectRoot leading zero", extra: []angabe{{"expectRoots", texte("01:" + hex)}}, enthae: "erwartete Wurzel"},
		{name: "expectRoot above 2^53-1", extra: []angabe{{"expectRoots", texte("9007199254740992:" + hex)}}, enthae: "erwartete Wurzel"},
		{name: "expectRoot 63 hex", extra: []angabe{{"expectRoots", texte(hex[1:])}}, enthae: "erwartete Wurzel"},
		{name: "tsaRootsPem a string", extra: []angabe{{"tsaRootsPem", text("x")}}, enthae: "kein Uint8Array"},
		{name: "tsaRootsPem a nested list", extra: []angabe{{"tsaRootsPem", liste(wert{art: artAnderes})}}, enthae: "kein Uint8Array"},
		{name: "tsaRootsPem other label", extra: []angabe{{"tsaRootsPem", bytesW([]byte("-----BEGIN X509 CRL-----\nMAA=\n-----END X509 CRL-----\n"))}}, enthae: "tsaRootsPem, Datei 1"},
		{name: "tsaRootsPem header in a block", extra: []angabe{{"tsaRootsPem", liste(bytesW(pem), bytesW([]byte(strings.Replace(string(pem), "-----\n", "-----\nProc-Type: 4\n", 1))))}}, enthae: "tsaRootsPem, Datei 2"},
		{name: "tsaRootsPem no block", extra: []angabe{{"tsaRootsPem", bytesW([]byte("# nur Text\n"))}}, enthae: "no CERTIFICATE block"},
		{name: "tsaQualifiedRootsJson a list", extra: []angabe{{"tsaQualifiedRootsJson", liste(bytesW([]byte("{}")))}}, enthae: "keine Liste"},
		{name: "tsaQualifiedRootsJson above 8 MiB", extra: []angabe{{"tsaQualifiedRootsJson", bytesW(gross(vfy.MaxQualifiedRootsBytes + 1))}}, enthae: "above the limit"},
		{name: "tsaQualifiedRootsJson other format", extra: []angabe{{"tsaQualifiedRootsJson", bytesW([]byte(`{"format":"x","stand":"2026-01-01T00:00:00Z","quelle":"q","wurzeln":[]}`))}}, enthae: "tsaQualifiedRootsJson, Datei 1"},
		{name: "vendorLogTsaRootsPem single", extra: []angabe{{"vendorLogTsaRootsPem", bytesW(pem)}}, enthae: "Array von Uint8Array"},
		{name: "vendorLogJson single", extra: []angabe{{"vendorLogJson", bytesW(auszug)}}, enthae: "Array von Uint8Array"},
		{name: "vendorLogJson above 32 MiB", extra: []angabe{{"vendorLogJson", liste(bytesW(gross(vfy.MaxVendorLogFileBytes + 1)))}}, enthae: "vendorLogJson, Datei 1"},
		{name: "vendorLogJson 129 files", extra: []angabe{{"vendorLogJson", viele(auszug, vfy.MaxVendorLogFiles+1)}}, enthae: "above 128 per run"},
		{name: "vendorLogJson not JSON", extra: []angabe{{"vendorLogJson", liste(bytesW([]byte("{")))}}, enthae: "not I-JSON"},
		{name: "vendorKeyListJson single", extra: []angabe{{"vendorKeyListJson", bytesW([]byte(`{"format":"ledger-schluesselrollen/1"}`))}}, enthae: "Array von Uint8Array"},
		{name: "vendorKeyListJson above 1 MiB", extra: []angabe{{"vendorKeyListJson", liste(bytesW(gross(vfy.MaxKeyListBytes + 1)))}}, enthae: "above the limit"},
		{name: "vendorKeyListJson unknown format", extra: []angabe{{"vendorKeyListJson", liste(bytesW([]byte(`{"format":"ledger-schluesselrollen/2"}`)))}}, enthae: "unknown format"},
		{name: "vendorKeyListJson no format", extra: []angabe{{"vendorKeyListJson", liste(bytesW([]byte(`{"version":1}`)))}}, enthae: "no format"},
		{name: "vendorKeyListJson duplicate member", extra: []angabe{{"vendorKeyListJson", liste(bytesW([]byte(`{"format":"ledger-schluesselrollen/1","format":"ledger-schluesselrollen/1"}`)))}}, enthae: "not I-JSON"},
		{name: "anchorHistoryJson single", extra: []angabe{{"anchorHistoryJson", bytesW(historie)}}, enthae: "Array von Uint8Array"},
		{name: "anchorHistoryJson above 32 MiB", extra: []angabe{{"anchorHistoryJson", liste(bytesW(gross(vfy.MaxHistoryFileBytes + 1)))}}, enthae: "anchorHistoryJson, Datei 1"},
		{name: "anchorHistoryJson 4097 files", extra: []angabe{{"anchorHistoryJson", viele(historie, vfy.MaxHistoryFiles+1)}}, enthae: "above 4096 per run"},
		{name: "vendorLogKeys a string", extra: []angabe{{"vendorLogKeys", text("k=" + hex)}}, enthae: "Array von Zeichenketten"},
		{name: "vendorLogKeys upper hex", extra: []angabe{{"vendorLogKeys", texte("k=" + strings.ToUpper(hex))}}, enthae: "key_id=hex64"},
		{name: "vendorStatementKeys bytes", extra: []angabe{{"vendorStatementKeys", liste(bytesW(nil))}}, enthae: "anderes als Zeichenketten"},
		{name: "vendorStatementKeys no id", extra: []angabe{{"vendorStatementKeys", texte("=" + hex)}}, enthae: "key_id=hex64"},
		{name: "statement pin twice, two keys", extra: []angabe{{"vendorStatementKeys", texte("s="+hex, "s="+strings.Repeat("cd", 32))}}, enthae: "pinned twice"},
		{name: "one key in two roles", extra: []angabe{{"vendorLogKeys", texte("p=" + hex)}, {"vendorStatementKeys", texte("s=" + hex)}}, enthae: "two roles"},
		{name: "requestedAt a list", extra: []angabe{{"requestedAt", texte("2026-01-01T00:00:00Z")}}, enthae: "requestedAt muss eine Zeichenkette"},
		{name: "requestedAt without zone", extra: []angabe{{"requestedAt", text("2026-01-01T00:00:00")}}, enthae: "requestedAt"},
		{name: "requestedAt after now", extra: []angabe{{"nowFromPackage", wahr(false)}, {"now", text("2026-01-01T12:00:00Z")}, {"requestedAt", text("2026-01-01T12:00:00.001Z")}}, enthae: "lies after the check time"},
		{name: "vendorRootJson a string", extra: []angabe{{"vendorRootJson", text("{}")}}, enthae: "kein Uint8Array"},
		{name: "vendorKeys a string", extra: []angabe{{"vendorKeys", text("k=" + hex)}}, enthae: "Array von Zeichenketten"},
	}
	for _, f := range faelle {
		t.Run(f.name, func(t *testing.T) {
			var r map[string]any
			if f.paket != nil {
				r = pruefen(*f.paket, f.extra, time.Now)
			} else {
				r = pruefenMit(t, f.extra...)
			}
			pruefeFehler(t, r, f.enthae)
		})
	}
}

func pruefeFehler(t *testing.T, r map[string]any, enthae string) {
	t.Helper()
	e, _ := r["error"].(string)
	if r["exit"] != 3 || !strings.HasPrefix(e, "ledgerVerify: ") || !strings.Contains(e, enthae) {
		t.Errorf("exit %v error %q, want exit 3 and an error with %q", r["exit"], e, enthae)
	}
	if r["report"] != "" || r["json"] != "" {
		t.Errorf("an unusable invocation wrote a report")
	}
	for _, k := range []string{"evidenceLevel", "evidenceState", "affiliationStatus", "evidenceLine", "affiliationLine"} {
		if _, ok := r[k]; ok {
			t.Errorf("an unusable invocation carries %s (spec 10.10.1: no report, none of these objects)", k)
		}
	}
}

// TestGleicheAngabeGleichesUrteil: the forms an option may take give the same
// verdict: a single file or a list of one, null for an absent option, the
// default window of 24 h given explicitly, a request time equal to the check
// time.
func TestGleicheAngabeGleichesUrteil(t *testing.T) {
	pem := lies(t, vektoren("valid_time_anchor/keys/tsa/probestelle.pem"))
	wurzel := lies(t, vektoren("pruefer_herstellerwurzel.json"))
	basis := pruefenMit(t)
	if basis["error"] != "" {
		t.Fatalf("valid_basic: %v", basis["error"])
	}
	gleich := func(name string, r map[string]any, w map[string]any) {
		t.Helper()
		if r["error"] != "" || r["json"] != w["json"] || r["report"] != w["report"] {
			t.Errorf("%s: another result (error %q)", name, r["error"])
		}
	}
	gleich("tsaRootsPem single and list", pruefenMit(t, angabe{"tsaRootsPem", bytesW(pem)}), pruefenMit(t, angabe{"tsaRootsPem", liste(bytesW(pem))}))
	gleich("null options", pruefenMit(t, angabe{"requestedAt", wert{art: artFehlt}}, angabe{"vendorLogJson", wert{art: artFehlt}}), basis)
	gleich("freshness 86400", pruefenMit(t, angabe{"freshnessSeconds", zahl(86400)}), basis)
	k, _ := korpus(t)
	einzeln := pruefen(bytesW(paket(t)), []angabe{{"nowFromPackage", wahr(true)}, {"vendorRootJson", bytesW(wurzel)}, k[1]}, time.Now)
	gleich("vendorRootJson single and list", einzeln, basis)
	jetzt := pruefenMit(t, angabe{"nowFromPackage", wert{art: artFehlt}}, angabe{"now", text("2026-01-01T12:02:00Z")}, angabe{"requestedAt", text("2026-01-01T12:02:00.000Z")})
	if jetzt["error"] != "" || jetzt["evidenceState"] != "rated" {
		t.Errorf("a request time equal to the check time is no error: %v", jetzt["error"])
	}
	if r := pruefenMit(t, angabe{"freshnessSeconds", zahl(0.5)}); r["error"] != "" {
		t.Errorf("freshnessSeconds 0.5: %v", r["error"])
	}
}

// ------------------------------------------------------------ the corpus

// sollZeile builds the first line under the verdict from the registry and
// the report object evidence_level, independently of zeilen.go.
func sollZeile(r map[string]any, ev map[string]any, lang string) string {
	tx := func(k string) string { return atS(r, "verifier", "evidence_level", "texts", k, lang) }
	label := tx("label")
	state, _ := ev["state"].(string)
	if state != "rated" {
		return strings.NewReplacer("{label}", label, "{state}", atS(r, "verifier", "evidence_level", "states", state, lang)).Replace(tx("state_line"))
	}
	material := false
	for _, n := range ev["notes"].([]any) {
		material = material || n == "material_contradiction"
	}
	num := func(k string) string { b, _ := json.Marshal(ev[k]); return string(b) }
	if num("level") == "0" {
		if material {
			label = tx("label_chain")
		}
		return strings.NewReplacer("{label}", label, "{name}", atS(r, "verifier", "evidence_level", "levels", "0", "name_"+lang), "{entries}", num("entries")).Replace(tx("head_level0"))
	}
	s := strings.NewReplacer("{level}", num("level"), "{up_to_tree_size}", num("up_to_tree_size"), "{entries}", num("entries")).Replace(tx("browser"))
	if material {
		s = tx("label_chain") + strings.TrimPrefix(s, label)
	}
	return s
}

// anfangVerbundenheit is the fixed start of the line on affiliation for a
// status (registry verifier.affiliation.texts, up to the first placeholder).
func anfangVerbundenheit(r map[string]any, status, lang string) []string {
	af := func(k string) string {
		s := atS(r, "verifier", "affiliation", "texts", k, lang)
		if i := strings.Index(s, "{"); i >= 0 {
			s = s[:i]
		}
		return s
	}
	switch status {
	case "affiliated":
		return []string{af("affiliated"), af("affiliated_vendor_itself")}
	case "not_affiliated", "not_determined", "not_checked":
		return []string{af(status)}
	}
	return nil
}

// TestKorpusWieKommandozeile runs every vector of spec/testvectors through
// pruefen and through cli.Main with the same zip file: with the audit
// environment of the corpus, and with the vector's own pruefer_<name>.json
// where its expected file names one. JSON and text report must be byte-equal;
// an unusable invocation must be one in both; the result members of 10.10.1
// must name the report objects; both runs must match the expected file; and
// the two lines under the verdict must follow the registry.
func TestKorpusWieKommandozeile(t *testing.T) {
	if testing.Short() {
		t.Skip("corpus run")
	}
	r := registry(t)
	exp := vektoren("expected")
	eintraege, err := os.ReadDir(exp)
	if err != nil {
		t.Fatal(err)
	}
	kA, kArgs := korpus(t)
	tmp := t.TempDir()
	gesehen := map[string]int{}
	laeufe := 0
	for _, de := range eintraege {
		vname := strings.TrimSuffix(de.Name(), ".json")
		if vname == de.Name() {
			continue
		}
		if st, err := os.Stat(vektoren(vname)); err != nil || !st.IsDir() {
			continue
		}
		var e struct {
			Exit     int             `json:"exit_code"`
			Findings []string        `json:"finding_classes"`
			Evidence json.RawMessage `json:"evidence_level"`
			Auditor  *struct {
				File     string          `json:"file"`
				Exit     int             `json:"exit_code"`
				Findings []string        `json:"finding_classes"`
				Evidence json.RawMessage `json:"evidence_level"`
			} `json:"auditor_inputs"`
		}
		if err := json.Unmarshal(lies(t, filepath.Join(exp, de.Name())), &e); err != nil {
			t.Fatalf("%s: %v", de.Name(), err)
		}
		zipPfad := filepath.Join(tmp, vname+".zip")
		roh := packen(t, vektoren(vname))
		if err := os.WriteFile(zipPfad, roh, 0o644); err != nil {
			t.Fatal(err)
		}
		type lauf struct {
			umgebung string
			angaben  []angabe
			args     []string
			exit     int
			klassen  []string
			evidence json.RawMessage
		}
		ls := []lauf{{"corpus", kA, kArgs, e.Exit, e.Findings, e.Evidence}}
		if e.Auditor != nil {
			a, args := pruefumgebung(t, e.Auditor.File)
			ls = append(ls, lauf{e.Auditor.File, a, args, e.Auditor.Exit, e.Auditor.Findings, e.Auditor.Evidence})
		}
		for _, l := range ls {
			laeufe++
			wo := vname + " (" + l.umgebung + ")"
			w := pruefen(bytesW(roh), append([]angabe{{"nowFromPackage", wahr(true)}, {"lang", text("de")}, {"name", text(zipPfad)}}, l.angaben...), time.Now)
			var jo, je, to, te bytes.Buffer
			nExit := cli.Main(append(append([]string{"--json", "--now-from-package"}, l.args...), zipPfad), &jo, &je)
			cli.Main(append(append([]string{"--lang", "de", "--now-from-package"}, l.args...), zipPfad), &to, &te)
			if w["exit"] != nExit {
				t.Errorf("%s: browser exit %v, command line exit %d (stderr %q, error %q)", wo, w["exit"], nExit, strings.TrimSpace(je.String()), w["error"])
				continue
			}
			if nExit != l.exit {
				t.Errorf("%s: exit %d, expected %d", wo, nExit, l.exit)
			}
			if jo.Len() == 0 {
				// An unusable invocation: no report on either side.
				gesehen["unusable"]++
				pruefeFehler(t, w, "")
				if je.Len() == 0 {
					t.Errorf("%s: the command line gave exit 3 without a reason", wo)
				}
				if len(l.evidence) > 0 && string(l.evidence) != "null" {
					t.Errorf("%s: no report, but the expected file names an evidence level", wo)
				}
				continue
			}
			if w["error"] != "" {
				t.Errorf("%s: browser error %q, the command line wrote a report", wo, w["error"])
				continue
			}
			if w["json"] != jo.String() {
				t.Errorf("%s: JSON differs from the command line", wo)
			}
			if w["report"] != to.String() {
				t.Errorf("%s: text report differs from the command line", wo)
			}
			var out struct {
				Findings []struct {
					Class string `json:"class"`
				} `json:"findings"`
				Stats struct {
					Affiliation *struct {
						Status string `json:"status"`
					} `json:"affiliation"`
					EvidenceLevel map[string]any `json:"evidence_level"`
				} `json:"stats"`
			}
			if err := json.Unmarshal(jo.Bytes(), &out); err != nil {
				t.Fatalf("%s: %v", wo, err)
			}
			klassen := map[string]bool{}
			for _, f := range out.Findings {
				klassen[f.Class] = true
			}
			soll := map[string]bool{}
			for _, k := range l.klassen {
				soll[k] = true
			}
			if len(klassen) != len(soll) {
				t.Errorf("%s: finding classes %v, expected %v", wo, klassen, l.klassen)
			}
			for k := range soll {
				if !klassen[k] {
					t.Errorf("%s: finding classes %v, expected %v", wo, klassen, l.klassen)
					break
				}
			}
			// Spec 10.10.1: the three result members name the report objects.
			ev := out.Stats.EvidenceLevel
			if ev == nil {
				t.Errorf("%s: a report without evidence_level", wo)
				continue
			}
			var affSoll any
			if out.Stats.Affiliation != nil {
				affSoll = out.Stats.Affiliation.Status
			}
			var levelSoll any
			if lv, ok := ev["level"].(float64); ok {
				levelSoll = int(lv)
			}
			if w["evidenceState"] != ev["state"] || w["evidenceLevel"] != levelSoll || w["affiliationStatus"] != affSoll {
				t.Errorf("%s: evidenceState %v evidenceLevel %v affiliationStatus %v, report objects %v %v %v",
					wo, w["evidenceState"], w["evidenceLevel"], w["affiliationStatus"], ev["state"], levelSoll, affSoll)
			}
			// ... and the expected file (registry expected_files).
			if len(l.evidence) > 0 && string(l.evidence) != "null" {
				var x struct {
					State       string  `json:"state"`
					Level       *int    `json:"level"`
					Affiliation *string `json:"affiliation"`
				}
				if err := json.Unmarshal(l.evidence, &x); err != nil {
					t.Fatalf("%s: %v", wo, err)
				}
				var xl, xa any
				if x.Level != nil {
					xl = *x.Level
				}
				if x.Affiliation != nil {
					xa = *x.Affiliation
				}
				if w["evidenceState"] != x.State || w["evidenceLevel"] != xl || w["affiliationStatus"] != xa {
					t.Errorf("%s: evidenceState %v evidenceLevel %v affiliationStatus %v, expected %v %v %v",
						wo, w["evidenceState"], w["evidenceLevel"], w["affiliationStatus"], x.State, xl, xa)
				}
			}
			// Spec 10.10.3, "Browser-Fassung": the two lines.
			gesehen["state "+ev["state"].(string)]++
			if levelSoll != nil {
				gesehen["level "+string(rune('0'+levelSoll.(int)))]++
			}
			if z := sollZeile(r, ev, "de"); w["evidenceLine"] != z {
				t.Errorf("%s: evidenceLine %q, registry %q", wo, w["evidenceLine"], z)
			}
			if affSoll == nil {
				if w["affiliationLine"] != nil {
					t.Errorf("%s: affiliationLine %q without affiliation", wo, w["affiliationLine"])
				}
				continue
			}
			gesehen["affiliation "+affSoll.(string)]++
			zeile, _ := w["affiliationLine"].(string)
			passt := false
			for _, a := range anfangVerbundenheit(r, affSoll.(string), "de") {
				passt = passt || (a != "" && strings.HasPrefix(zeile, a))
			}
			if !passt || !strings.Contains(to.String(), "\n  "+zeile+"\n") {
				t.Errorf("%s: affiliationLine %q is not the line of the report for %v", wo, zeile, affSoll)
			}
		}
	}
	// The corpus must reach every state, level and status, or the lines
	// would be measured on fewer cases than they have.
	for _, k := range []string{"state rated", "state chain_invalid", "state format_error", "level 0", "level 1", "level 2", "level 3",
		"affiliation affiliated", "affiliation not_affiliated", "affiliation not_determined", "affiliation not_checked", "unusable"} {
		if gesehen[k] == 0 {
			t.Errorf("no run of the corpus reaches %s", k)
		}
	}
	t.Logf("%d runs: %v", laeufe, gesehen)
}

// TestZeilenEnglisch: the lines in English for the cases of the four
// affiliation statuses (the corpus run above checks German).
func TestZeilenEnglisch(t *testing.T) {
	r := registry(t)
	for _, v := range []string{"valid_basic", "evidence_level_3", "evidence_level_3_affiliated", "evidence_chain_invalid", "evidence_format_error", "evidence_material_contradiction"} {
		a, _ := korpus(t)
		if _, err := os.Stat(vektoren("pruefer_" + v + ".json")); err == nil {
			a, _ = pruefumgebung(t, "pruefer_"+v+".json")
		}
		w := pruefen(bytesW(packen(t, vektoren(v))), append([]angabe{{"nowFromPackage", wahr(true)}, {"lang", text("en")}}, a...), time.Now)
		if w["error"] != "" {
			t.Fatalf("%s: %v", v, w["error"])
		}
		var out struct {
			Stats struct {
				EvidenceLevel map[string]any `json:"evidence_level"`
			} `json:"stats"`
		}
		json.Unmarshal([]byte(w["json"].(string)), &out)
		if z := sollZeile(r, out.Stats.EvidenceLevel, "en"); w["evidenceLine"] != z {
			t.Errorf("%s: evidenceLine %q, registry %q", v, w["evidenceLine"], z)
		}
		if st, ok := w["affiliationStatus"].(string); ok {
			zeile, _ := w["affiliationLine"].(string)
			passt := false
			for _, p := range anfangVerbundenheit(r, st, "en") {
				passt = passt || strings.HasPrefix(zeile, p)
			}
			if !passt {
				t.Errorf("%s: affiliationLine %q for %s", v, zeile, st)
			}
		} else if w["affiliationLine"] != nil {
			t.Errorf("%s: affiliationLine without affiliation", v)
		}
	}
}

// TestVerbundenheitsZeileMarkiert: a report without the line gives a visible
// marker, never an empty line.
func TestVerbundenheitsZeileMarkiert(t *testing.T) {
	if z := verbundenheitsZeile("Beweisstufe: 2 von 3\n  Hinweis: x\n\nkeine Befunde.\n", "de"); !strings.HasPrefix(z, "⟪MISSING:") {
		t.Errorf("got %q", z)
	}
	if z := beweisstufenZeile(nil, "de"); !strings.HasPrefix(z, "⟪MISSING:") {
		t.Errorf("got %q", z)
	}
}
