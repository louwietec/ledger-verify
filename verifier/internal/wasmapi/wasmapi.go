// Package wasmapi ist derselbe freie Verifier wie ledger-verify (LEDGER),
// uebersetzt nach WebAssembly und mit einer einzigen JavaScript-Funktion nach
// aussen. Die Kommandos verifier/cmd/ledger-verify-wasm und (Alias unter dem
// frueheren Namen, fuer Bauwege, die ihn noch nennen) verifier/cmd/rekorder-verify-wasm
// rufen nur Registrieren; beide Module pruefen mit derselben Logik (byte-gleich
// sind sie nicht: der Kommandopfad steht in der Bauinformation).
//
// WARUM ES DAS GIBT: das Kernversprechen des Produkts ist "jeder Dritte kann
// jede Kette selbst pruefen". Die Menschen, die wirklich pruefen (Auditoren,
// Juristen, Betriebsraete, Aufsicht), arbeiten oft auf verwalteten Rechnern,
// auf denen eine fremde unsignierte Binaerdatei gar nicht startet. Hier
// laeuft derselbe Code im Browser: Paket auswaehlen, Urteil lesen. Ohne
// Installation, ohne Upload, ohne Netz.
//
// DREI EIGENSCHAFTEN, DIE DAS TRAGEN:
//
//  1. DIESELBE QUELLE. Dieser Einstieg ruft vfy.VerifyBytes; die Pruefkette ist
//     Zeile fuer Zeile die des Kommandozeilen-Verifiers (verifyFS), und die
//     Angaben des Pruefers liest er mit denselben Methoden wie die
//     Kommandozeile (vfy.Options.Add..., FinishAuditorInputs). Eine eigene
//     Browser-Implementierung waere eine dritte Handkopie neben Go und Python.
//  2. GEMESSEN, NICHT BEHAUPTET. tests/wasm/aequivalenz.mjs fuehrt jeden
//     eingefrorenen Testvektor durch dieses Modul UND durch das native Binaer,
//     einmal mit der Pruefumgebung des Korpus und einmal mit der eigenen
//     Pruefumgebung pruefer_<name>.json des Vektors, und verlangt denselben
//     Exit-Code, dieselben Befundklassen, dieselbe Beweisstufe und denselben
//     Status der Verbundenheit. wasmapi_test.go haelt denselben Weg ohne
//     WebAssembly gegen cli.Main, byte-gleich in JSON und Textbericht.
//  3. KEIN NETZ. Dieses Modul kennt keine Netzfunktion; es bekommt Bytes und
//     gibt ein Urteil zurueck. Die Seite laedt nichts nach (alles liegt in
//     einer Datei), und `go list -deps` zeigt kein net/http.
//
// AUFBAU: diese Datei und zeilen.go sind ohne WebAssembly uebersetzbar und
// tragen die ganze Logik (Optionen lesen, pruefen, Ergebnis bilden);
// bruecke_js.go uebersetzt nur JavaScript-Werte in wert und das Ergebnis
// zurueck. So laeuft die Logik auch unter `go test` auf dem Rechner.
// / This file and zeilen.go build without WebAssembly and hold all logic;
// bruecke_js.go only converts JavaScript values.
//
// JavaScript-Schnittstelle / JavaScript interface (Spec 10.8, 10.10.1):
//
//	ledgerVerify(bytes: Uint8Array, opts?: {
//	    lang?: "de" | "en",        // Berichtssprache, Vorgabe "de"
//	    name?: string,             // Dateiname des Pakets fuer den Textbericht
//	    now?: string,              // Pruefzeitpunkt, rfc3339 (UTC mit Z, Spec 2/10.7);
//	                               // Vorgabe: Uhr des Browsers
//	    nowFromPackage?: boolean,  // Pruefzeit aus verify_args.json (nur Vektoren; fehlt sie
//	                               // oder ist sie unbrauchbar: FORMAT_ERROR, Exit 3, Spec 10.8)
//	    freshnessSeconds?: number, // Frischefenster in Sekunden, endlich und positiv, Vorgabe 24 h
//	    expectRoot?: string,       // erwartete Wurzel: ROOT (64 Hex) oder TREE_SIZE:ROOT (Spec 10.8)
//	    expectRoots?: string[],    // beliebig viele weitere in denselben Formen
//	    tsaRootsPem?: Uint8Array | Uint8Array[],  // --tsa-root: Zweck chain, strenges PEM
//	    tsaQualifiedRootsJson?: Uint8Array,       // --tsa-qualified-roots: ledger-tsa-qualifiziert/1
//	    vendorLogTsaRootsPem?: Uint8Array[],      // --vendor-log-tsa-root: Zweck log, strenges PEM
//	    vendorLogJson?: Uint8Array[],             // --vendor-log: ledger-protokollauszug/1
//	    vendorLogKeys?: string[],                 // --vendor-log-key: key_id=hex64
//	    vendorStatementKeys?: string[],           // --vendor-statement-key: key_id=hex64
//	    vendorKeyListJson?: Uint8Array[],         // --vendor-key-list: Schluessellisten
//	    anchorHistoryJson?: Uint8Array[],         // --anchor-history: Seite oder ledger-ankerhistorie/2
//	    requestedAt?: string,                     // --requested-at: rfc3339
//	    vendorRootJson?: Uint8Array | Uint8Array[], // --vendor-root: {"wurzel_id","pubkey"} (Spec 7.1)
//	    vendorKeys?: string[],                    // --vendor-key: key_id=hex64 (Spec 7.1, 10.7.4)
//	}) => {
//	    exit: number,              // 0 gueltig / 1 gueltig mit Befunden / 2 ungueltig / 3 Formatfehler
//	                               // / 4 unvollstaendig: Kettenende nicht versiegelt (Spec 8.6)
//	    report: string,            // der Prueftext in der gewaehlten Sprache
//	    json: string,              // dieselbe Ausgabe wie --json
//	    error: string,             // nur bei unbrauchbarem Aufruf, sonst ""
//	    evidenceLevel: number | null,     // Beweisstufe 0 bis 3 (Spec 10.9, 10.10.1),
//	                                      // null ausserhalb des Zustands rated
//	    evidenceState: string,            // rated, chain_invalid oder format_error
//	    affiliationStatus: string | null, // Status der Verbundenheit (Spec 8.8.6), null bei Exit 3
//	    evidenceLine: string,             // die Zeile zur Beweisstufe unter dem Urteil (Spec 10.10.3)
//	    affiliationLine: string | null,   // die Zeile zur Verbundenheit, null bei Exit 3
//	}
//
// Die fuenf letzten Member fehlen bei einem unbrauchbaren Aufruf (Spec 10.10.1:
// kein Bericht, keines dieser Objekte). Jede Angabe liest das Modul beim
// Aufruf, bevor es das Paket oeffnet, mit den Grammatiken, Grenzen und Regeln
// von Spec 10.8; ein Verstoss, ein Wert eines anderen Typs, ein Name einer
// Option, den diese Fassung nicht kennt (Spec 7.6, 10.6), und jeder andere
// Bedienfehler ist ein unbrauchbarer Aufruf: Exit 3 mit Begruendung in error,
// kein Urteil. undefined und null gelten als nicht angegeben. vendorRootJson
// nimmt wie --vendor-root auch mehrere Dateien (Spec 7.1, 10.8: die Schalter
// fuer Herstellerwurzeln duerfen mehrfach stehen).
//
//	ledgerVerifyVersion = {
//	    name: "ledger-verify", product: "LEDGER",
//	    version: string, spec: string, vendorRoot: string,
//	}
//
// ALTE NAMEN / old names: rekorderVerify und rekorderVerifyVersion bleiben als
// Aliase auf DIESELBE Funktion und DASSELBE Objekt gesetzt; Seiten und
// Einbettungen, die das Modul unter dem alten Produktnamen aufrufen, laufen
// weiter und bekommen dieselbe Ausgabe, die ledger-verify und LEDGER nennt.
//
// Exit 4 ist kein Fehlschlag: die vorhandenen Eintraege sind geprueft und
// intakt, nur belegt das Paket nicht, dass nach dem letzten nichts mehr kam.
// Der Exit-Code folgt der Rangfolge 3 > 2 > 4 > 1 > 0 (Spec 10.3), nicht der
// Groesse der Zahl; dieselbe Regel wie im nativen Verifier, weil beide
// denselben Pruefablauf (vfy.VerifyBytes/verifyFS) rufen.
// / Exit 4 = incomplete, chain end not sealed (spec 8.6); precedence
// 3 > 2 > 4 > 1 > 0, not the numeric maximum.
package wasmapi

import (
	"fmt"
	"math"
	"time"

	"louwietec.com/ledger-verify/verifier/internal/vfy"
)

// name und product stehen in ledgerVerifyVersion und damit in der Fusszeile
// der Seite: dieselben Werte wie cli.Name und cli.Product des nativen
// Verifiers. Das Modul importiert internal/cli bewusst nicht: flag, os und
// regexp wuerden es nur groesser machen. tests/wasm/aequivalenz.mjs haelt die
// Versionszeile beider Fassungen gegeneinander, wasmapi_test.go die Werte.
// / Same values as cli.Name and cli.Product.
const (
	name    = "ledger-verify"
	product = "LEDGER"
)

// Version ist eine Variable, damit ein Release-Bau sie wie cli.Version per
// -ldflags "-X <module>/internal/wasmapi.Version=..." setzen kann (<module>
// ist der Modulpfad, go list -m). / A var so a release build can stamp it.
var Version = "1.1.0"

// specVersion ist die Spezifikationsversion, die dieser Verifier umsetzt,
// gespiegelt aus spec/registry.json und gehalten von .ci/check_typlisten.py
// (SPEC_VERSION_KOPIEN). 1.10: Herstellerprotokoll, Anker-Historie v2,
// Verbundenheit, Beweisstufe, Angaben des Pruefers (Spec 7.4, 8.8, 10.8,
// 10.9, 10.10). / The spec version, held by .ci/check_typlisten.py.
const specVersion = "1.10"

// art is the JavaScript type of a value, as the bridge hands it over.
type art int

const (
	artFehlt   art = iota // undefined or null: not given
	artText               // string
	artZahl               // number
	artWahr               // boolean
	artBytes              // Uint8Array
	artListe              // Array; its elements one level deep
	artAnderes            // every other value: object, function, symbol, bigint, a nested array
)

// wert is one value of the JavaScript call.
type wert struct {
	art   art
	text  string
	zahl  float64
	wahr  bool
	bytes []byte
	liste []wert
}

// angabe is one option with its name, in the order of Object.keys.
type angabe struct {
	name string
	wert wert
}

// form is the type an option takes (spec 10.8, column "Option im Browser").
type form int

const (
	formText           form = iota // string
	formZahl                       // number
	formWahr                       // boolean
	formBytes                      // Uint8Array
	formBytesOderListe             // Uint8Array or Uint8Array[]
	formBytesListe                 // Uint8Array[]
	formTextListe                  // string[]
)

// optionen are the option names of this edition with their form. The nine
// options of the table in spec 10.8 carry its names and forms exactly;
// wasmapi_test.go holds them against spec/format.de.md.
var optionen = []struct {
	name string
	form form
}{
	{"lang", formText},
	{"name", formText},
	{"now", formText},
	{"nowFromPackage", formWahr},
	{"freshnessSeconds", formZahl},
	{"expectRoot", formText},
	{"expectRoots", formTextListe},
	{"tsaRootsPem", formBytesOderListe},
	{"tsaQualifiedRootsJson", formBytes},
	{"vendorLogTsaRootsPem", formBytesListe},
	{"vendorLogJson", formBytesListe},
	{"vendorLogKeys", formTextListe},
	{"vendorStatementKeys", formTextListe},
	{"vendorKeyListJson", formBytesListe},
	{"anchorHistoryJson", formBytesListe},
	{"requestedAt", formText},
	{"vendorRootJson", formBytesOderListe},
	{"vendorKeys", formTextListe},
}

// fehler builds the answer for an unusable invocation (spec 10.8). Exit 3 is
// the honest code here: exit 2 would claim the chain is broken, exit 1 that it
// is valid; both would be statements about content that was never read.
func fehler(msg string) map[string]any {
	return map[string]any{"exit": 3, "report": "", "json": "", "error": msg}
}

// gelesen holds the options after their names and types are checked.
type gelesen struct {
	text  map[string]string
	zahl  map[string]float64
	wahr  map[string]bool
	bytes map[string][][]byte
	texte map[string][]string
}

// lesen checks every option against its name and form (spec 7.6, 10.6, 10.8:
// an unknown name or a value of another type is an unusable invocation).
func lesen(angaben []angabe) (*gelesen, error) {
	formen := map[string]form{}
	for _, o := range optionen {
		formen[o.name] = o.form
	}
	g := &gelesen{text: map[string]string{}, zahl: map[string]float64{}, wahr: map[string]bool{},
		bytes: map[string][][]byte{}, texte: map[string][]string{}}
	gesehen := map[string]bool{}
	for _, a := range angaben {
		f, ok := formen[a.name]
		if !ok {
			return nil, fmt.Errorf("ledgerVerify: unbekannte Option / unknown option %q (Spec 7.6, 10.6, 10.8)", a.name)
		}
		if gesehen[a.name] {
			return nil, fmt.Errorf("ledgerVerify: Option %s steht mehrfach / option %s is given more than once (Spec 10.8)", a.name, a.name)
		}
		gesehen[a.name] = true
		w := a.wert
		if w.art == artFehlt {
			continue
		}
		switch f {
		case formText:
			if w.art != artText {
				return nil, fmt.Errorf("ledgerVerify: %s muss eine Zeichenkette sein / must be a string", a.name)
			}
			g.text[a.name] = w.text
		case formZahl:
			if w.art != artZahl {
				return nil, fmt.Errorf("ledgerVerify: %s muss eine Zahl sein / must be a number", a.name)
			}
			g.zahl[a.name] = w.zahl
		case formWahr:
			if w.art != artWahr {
				return nil, fmt.Errorf("ledgerVerify: %s muss ein Wahrheitswert sein / must be a boolean", a.name)
			}
			g.wahr[a.name] = w.wahr
		case formTextListe:
			if w.art != artListe {
				return nil, fmt.Errorf("ledgerVerify: %s muss ein Array von Zeichenketten sein / must be an array of strings", a.name)
			}
			liste := []string{}
			for _, e := range w.liste {
				if e.art != artText {
					return nil, fmt.Errorf("ledgerVerify: %s enthaelt etwas anderes als Zeichenketten / holds a non-string", a.name)
				}
				liste = append(liste, e.text)
			}
			g.texte[a.name] = liste
		case formBytes, formBytesOderListe, formBytesListe:
			teile := []wert{w}
			switch {
			case w.art == artListe && f == formBytes:
				return nil, fmt.Errorf("ledgerVerify: %s muss ein einzelnes Uint8Array sein, keine Liste / must be a single Uint8Array, not a list (Spec 10.8: hoechstens einmal / at most once)", a.name)
			case w.art == artListe:
				teile = w.liste
			case f == formBytesListe:
				return nil, fmt.Errorf("ledgerVerify: %s muss ein Array von Uint8Array sein / must be an array of Uint8Array", a.name)
			}
			liste := [][]byte{}
			for i, t := range teile {
				if t.art != artBytes {
					return nil, fmt.Errorf("ledgerVerify: %s, Datei %d / file %d: kein Uint8Array / not a Uint8Array", a.name, i+1, i+1)
				}
				liste = append(liste, t.bytes)
			}
			g.bytes[a.name] = liste
		}
	}
	return g, nil
}

// pruefen is ledgerVerify without JavaScript: the package, the options in the
// order of Object.keys and the clock (time.Now in the browser). It reads every
// input of the auditor before it opens the package (spec 10.8) and returns
// the result object of spec 10.10.1.
func pruefen(paket wert, angaben []angabe, uhr func() time.Time) (erg map[string]any) {
	// Ein Fehler im Verifier darf die Seite nicht stilllegen: ein beendetes
	// Go-Programm nimmt seine Funktionen mit, und jeder weitere Aufruf
	// scheiterte ohne Begruendung. Statt dessen eine Fehlermeldung, kein
	// Urteil. / A panic answers with an error message, never a verdict.
	defer func() {
		if p := recover(); p != nil {
			erg = fehler(fmt.Sprintf("ledgerVerify: interner Fehler, kein Urteil / internal error, no verdict: %v", p))
		}
	}()
	if paket.art != artBytes {
		return fehler("ledgerVerify: erstes Argument muss ein Uint8Array mit dem Pruefpaket sein / first argument must be a Uint8Array holding the package")
	}
	data := paket.bytes
	g, err := lesen(angaben)
	if err != nil {
		return fehler(err.Error())
	}

	lang := "de"
	if s, ok := g.text["lang"]; ok {
		lang = s
	}
	if lang != "de" && lang != "en" {
		return fehler("ledgerVerify: lang muss de oder en sein / lang must be de or en")
	}
	// Der Pfadname steht im Textbericht; im Browser gibt es keinen Pfad, also
	// wird der Dateiname genannt, den der Pruefer ausgewaehlt hat.
	paketName := g.text["name"]
	if paketName == "" {
		paketName = "(Pruefpaket / verification package)"
	}

	opt := vfy.Options{Freshness: 24 * time.Hour}
	if s, ok := g.zahl["freshnessSeconds"]; ok {
		// vfy.Options.Freshness 0 heisst "Vorgabe 24 h": ein Wert, der auf
		// 0 ns faellt (etwa 1e-10), waere sonst still das Vorgabefenster.
		// / A value that truncates to 0 ns would silently become 24 h.
		ns := s * float64(time.Second)
		if math.IsNaN(s) || math.IsInf(s, 0) || s <= 0 || ns >= math.MaxInt64 || time.Duration(ns) <= 0 {
			return fehler("ledgerVerify: freshnessSeconds muss eine endliche positive Zahl sein / must be a finite positive number")
		}
		opt.Freshness = time.Duration(ns)
	}
	opt.NowFromPackage = g.wahr["nowFromPackage"]
	// Spec 10.8 (1.9): Pruefzeit und erwartete Wurzeln in derselben Grammatik
	// wie im Paket und wie auf der Kommandozeile; alles andere ist ein
	// unbrauchbarer Aufruf, nie eine stille Deutung (keine Ortszeit des
	// Browsers). / Same grammar as the package and the CLI (spec 10.8).
	if s, ok := g.text["now"]; ok {
		t, err := vfy.ParseTime(s)
		if err != nil {
			return fehler("ledgerVerify: now ist kein Zeitpunkt der Form JJJJ-MM-TTThh:mm:ss[.Bruchteil]Z / now is not an instant of the form YYYY-MM-DDThh:mm:ss[.fraction]Z (Spec 10.8)")
		}
		// NowSet: auch 0001-01-01T00:00:00Z gilt als angegeben (wie im CLI).
		// / The zero time counts as given too (as in the CLI).
		opt.Now, opt.NowSet = t, true
	}
	wurzeln := g.texte["expectRoots"]
	if s, ok := g.text["expectRoot"]; ok {
		wurzeln = append([]string{s}, wurzeln...)
	}
	for _, s := range wurzeln {
		x, err := vfy.ParseExpectedRoot(s)
		if err != nil {
			return fehler(fmt.Sprintf("ledgerVerify: erwartete Wurzel %q muss 64 Hex-Zeichen (ROOT) oder TREE_SIZE:ROOT sein, TREE_SIZE eine ganze Zahl ab 1 / expected root must be 64 hex characters (ROOT) or TREE_SIZE:ROOT with TREE_SIZE a whole number from 1 (Spec 10.8)", s))
		}
		opt.ExpectRoots = append(opt.ExpectRoots, x)
	}
	// Die Angaben des Pruefers (Spec 10.8) in der Reihenfolge der
	// Kommandozeile und mit denselben Methoden, damit beide dieselben Angaben
	// ablehnen: Grammatik, Grenzen je Datei und je Aufruf, Widersprueche.
	// Der Browser hat keinen Systemwurzelspeicher, und ab Fassung 1.10 zaehlt
	// er ohnehin fuer keinen Zweck. / The same methods as the command line.
	dateien := []struct {
		option string
		add    func([]byte) error
	}{
		{"tsaRootsPem", opt.AddTSARootPEM},
		{"tsaQualifiedRootsJson", opt.SetTSAQualifiedRoots},
		{"vendorLogTsaRootsPem", opt.AddVendorLogTSARootPEM},
		{"vendorLogJson", opt.AddVendorLog},
		{"vendorKeyListJson", opt.AddVendorKeyList},
		{"anchorHistoryJson", opt.AddAnchorHistory},
	}
	for _, d := range dateien {
		for i, b := range g.bytes[d.option] {
			if err := d.add(b); err != nil {
				return fehler(fmt.Sprintf("ledgerVerify: %s, Datei %d / file %d: %v", d.option, i+1, i+1, err))
			}
		}
	}
	for _, p := range []struct {
		option string
		add    func(string) error
	}{{"vendorLogKeys", opt.AddVendorLogKey}, {"vendorStatementKeys", opt.AddVendorStatementKey}} {
		for _, s := range g.texte[p.option] {
			if err := p.add(s); err != nil {
				return fehler("ledgerVerify: " + p.option + ": " + err.Error())
			}
		}
	}
	if s, ok := g.text["requestedAt"]; ok {
		if err := opt.SetRequestedAt(s); err != nil {
			return fehler("ledgerVerify: requestedAt: " + err.Error())
		}
	}

	// Vertrauensanker fuer Hersteller-Quittungen (Spec 7.1, 10.7): die Wurzel
	// des Herstellers als Datei {"wurzel_id","pubkey"} und/oder einzelne
	// angeheftete Schluessel "key_id=hex". Beides waehlt der PRUEFER.
	if w, ok, err := vfy.Builtin(); err != nil {
		return fehler("ledgerVerify: " + err.Error())
	} else if ok {
		opt.VendorRoots = append(opt.VendorRoots, w)
	}
	for i, roh := range g.bytes["vendorRootJson"] {
		w, err := vfy.ParseVendorRoot(roh)
		if err != nil {
			return fehler(fmt.Sprintf("ledgerVerify: vendorRootJson, Datei %d / file %d: Herstellerwurzel / vendor root: %v", i+1, i+1, err))
		}
		opt.VendorRoots = append(opt.VendorRoots, w)
	}
	for _, s := range g.texte["vendorKeys"] {
		k, err := vfy.ParseVendorKey(s)
		if err != nil {
			return fehler("ledgerVerify: vendorKeys: " + err.Error())
		}
		opt.VendorKeys = append(opt.VendorKeys, k)
	}

	// Widerspruechliche Anker gleichen Namens (auch gegen die eingebaute
	// Wurzel) sind ein Bedienfehler, nicht "der letzte gewinnt" (Spec 7.1).
	if opt.VendorRoots, opt.VendorKeys, err = vfy.AnkerZusammenfuehren(opt.VendorRoots, opt.VendorKeys); err != nil {
		return fehler("ledgerVerify: " + err.Error())
	}
	// Die Regeln ueber mehrere Angaben (Spec 10.8, 7.4.10 L0, 10.7.4). Den
	// Anforderungszeitpunkt vergleicht das Modul hier mit now oder der Uhr des
	// Browsers; mit dem Pruefzeitpunkt aus verify_args.json vergleicht ihn
	// der Lauf in Stufe 5. / As the CLI: at invocation, or at stage 5.
	checkNow := opt.Now
	if !opt.NowSet && !opt.NowFromPackage {
		checkNow = uhr().UTC()
	}
	if err := opt.FinishAuditorInputs(checkNow); err != nil {
		return fehler("ledgerVerify: " + err.Error())
	}

	res := vfy.VerifyBytes(data, opt)
	jsonBytes, err := vfy.RenderJSON(res)
	if err != nil {
		return fehler("ledgerVerify: Bericht nicht darstellbar / cannot render report: " + err.Error())
	}
	report := vfy.RenderText(res, paketName, lang)
	// Spec 10.10.1 (from 1.10): the result also carries affiliationStatus,
	// the status of the report object affiliation, null for a format error.
	var affiliation any
	if af := res.Stats.Affiliation; af != nil {
		affiliation = af.Status
	}
	// Spec 10.10.1: evidenceLevel (a number or null) and evidenceState from
	// the report object evidence_level; the colour of the verdict stays bound
	// to the exit code (10.10.3).
	var level any
	state := ""
	if ev := res.Stats.EvidenceLevel; ev != nil {
		state = ev.State
		if ev.Level != nil {
			level = *ev.Level
		}
	}
	// Spec 10.10.3, "Browser-Fassung": the two lines under the verdict, from
	// the registry texts the command line uses (zeilen.go).
	var affiliationLine any
	if affiliation != nil {
		affiliationLine = verbundenheitsZeile(report, lang)
	}
	return map[string]any{
		"exit":              res.ExitCode,
		"report":            report,
		"json":              string(jsonBytes),
		"error":             "",
		"affiliationStatus": affiliation,
		"evidenceLevel":     level,
		"evidenceState":     state,
		"evidenceLine":      beweisstufenZeile(res.Stats.EvidenceLevel, lang),
		"affiliationLine":   affiliationLine,
	}
}

// fassung is the object ledgerVerifyVersion. vendorRoot names the built-in
// vendor root like `--version` of the native verifier (spec 7.1: a build that
// carries one MUST name it).
func fassung() map[string]any {
	wurzel := "none"
	if w, ok, err := vfy.Builtin(); err == nil && ok {
		wurzel = w.ID + " " + w.Pubkey
	}
	return map[string]any{
		"name":       name,
		"product":    product,
		"version":    Version,
		"spec":       specVersion,
		"vendorRoot": wurzel,
	}
}
