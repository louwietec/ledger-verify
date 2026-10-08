//go:build js && wasm

// Package wasmapi ist derselbe freie Verifier wie ledger-verify (LEDGER),
// uebersetzt nach WebAssembly und mit einer einzigen JavaScript-Funktion nach
// aussen. Die Kommandos verifier/cmd/ledger-verify-wasm und (Alias unter dem
// frueheren Namen, fuer Bauwege, die ihn noch nennen) verifier/cmd/rekorder-verify-wasm
// rufen nur Registrieren — beide Module pruefen mit derselben Logik (byte-gleich
// sind sie nicht: der Kommandopfad steht in der Bauinformation).
//
// WARUM ES DAS GIBT: das Kernversprechen des Produkts ist "jeder Dritte kann
// jede Kette selbst pruefen". In der Praxis hiess das bis zum 15.09.:
// Hersteller-Binaerdatei herunterladen, Pruefsumme vergleichen, chmod +x, eine
// Kommandozeile bedienen und einen Exit-Code deuten. Die Menschen, die wirklich
// pruefen — Auditoren, Juristen, Betriebsraete, Aufsicht —, arbeiten auf
// verwalteten Rechnern, auf denen eine fremde unsignierte Binaerdatei oft gar
// nicht startet. Das Versprechen war damit fuer die meisten Adressaten
// theoretisch.
//
// Hier laeuft derselbe Code im Browser: Paket auswaehlen, Urteil lesen. Ohne
// Installation, ohne Upload, ohne Netz.
//
// DREI EIGENSCHAFTEN, DIE DAS TRAGEN:
//
//  1. DIESELBE QUELLE. Dieser Einstieg ruft vfy.VerifyBytes; die Pruefkette ist
//     Zeile fuer Zeile die des Kommandozeilen-Verifiers (verifyFS). Eine
//     eigene Browser-Implementierung waere eine dritte Handkopie neben Go und
//     Python — genau die Klasse, gegen die dieses Repo check_typlisten und
//     check_registry_matrix gebaut hat.
//  2. GEMESSEN, NICHT BEHAUPTET. tests/wasm/aequivalenz.mjs fuehrt jeden
//     eingefrorenen Testvektor durch dieses Modul UND durch das native Binaer
//     und verlangt denselben Exit-Code und dieselbe Befundliste. Ein Verifier,
//     der im Browser milder urteilt als auf der Kommandozeile, waere
//     schlimmer als gar keiner.
//  3. KEIN NETZ. Dieses Modul kennt keine Netzfunktion; es bekommt Bytes und
//     gibt ein Urteil zurueck. Das ist nachpruefbar, nicht zugesichert: die
//     Seite laedt nichts nach (alles liegt in einer Datei) und `go list -deps`
//     zeigt kein net/http.
//
// JavaScript-Schnittstelle / JavaScript interface:
//
//	ledgerVerify(bytes: Uint8Array, opts?: {
//	    lang?: "de" | "en",        // Berichtssprache, Vorgabe "de"
//	    now?: string,              // UTC mit Z in der Grammatik von Spec 2/10.7, Vorgabe: Uhr des Browsers
//	    nowFromPackage?: boolean,  // Pruefzeit aus verify_args.json (nur Vektoren; fehlt sie
//	                               // oder ist sie unbrauchbar: FORMAT_ERROR, Exit 3, Spec 10.8)
//	    expectRoot?: string,       // erwartete Wurzel: ROOT (64 Hex) oder TREE_SIZE:ROOT (Spec 10.8) —
//	                               // Papier-Anker oder die juengste VOR der Anforderung des Pakets
//	                               // vom Hersteller gegengezeichnete Wurzel
//	    expectRoots?: string[],    // beliebig viele weitere in denselben Formen
//	    freshnessSeconds?: number, // Frischefenster, Vorgabe 24 h
//	}) => {
//	    exit: number,              // 0 gueltig / 1 gueltig mit Befunden / 2 ungueltig / 3 Formatfehler
//	                               // / 4 unvollstaendig: Kettenende nicht versiegelt (Spec 8.6)
//	    report: string,            // der Prueftext in der gewaehlten Sprache
//	    json: string,              // dieselbe Ausgabe wie --json
//	    error: string,             // nur bei unbrauchbarem Aufruf, sonst ""
//	}
//
//	ledgerVerifyVersion = {
//	    name: "ledger-verify", product: "LEDGER",
//	    version: string, spec: string, vendorRoot: string,
//	}
//
// ALTE NAMEN / old names: rekorderVerify und rekorderVerifyVersion bleiben als
// Aliase auf DIESELBE Funktion und DASSELBE Objekt gesetzt — Seiten und
// Einbettungen, die das Modul unter dem alten Produktnamen ("Rekorder")
// aufrufen, laufen weiter und bekommen dieselbe Ausgabe, die ledger-verify und
// LEDGER nennt. / rekorderVerify and rekorderVerifyVersion stay registered as
// aliases of the very same function and object for existing embedders.
//
// Exit 4 ist kein Fehlschlag: die vorhandenen Eintraege sind geprueft und
// intakt, nur belegt das Paket nicht, dass nach dem letzten nichts mehr kam.
// Der Exit-Code folgt der Rangfolge 3 > 2 > 4 > 1 > 0 (Spec 10.3), nicht der
// Groesse der Zahl — dieselbe Regel wie im nativen Verifier, weil beide
// denselben Pruefablauf (vfy.VerifyBytes/verifyFS) rufen.
// / Exit 4 = incomplete, chain end not sealed (spec 8.6); precedence
// 3 > 2 > 4 > 1 > 0, not the numeric maximum.
package wasmapi

import (
	"encoding/pem"
	"strings"
	"syscall/js"
	"time"

	"github.com/louwietec/ledger-verify/verifier/internal/vfy"
)

// name und product stehen in ledgerVerifyVersion und damit in der Fusszeile
// der Seite — dieselben Werte wie cli.Name und cli.Product des nativen
// Verifiers. Das Modul importiert internal/cli bewusst nicht: flag, os und
// regexp wuerden es nur groesser machen. tests/wasm/aequivalenz.mjs haelt die
// Versionszeile beider Fassungen gegeneinander.
// / Same values as cli.Name and cli.Product; the equivalence proof compares
// the version line of both builds.
const (
	name    = "ledger-verify"
	product = "LEDGER"
)

// Version ist eine Variable, damit ein Release-Bau sie wie cli.Version per
// -ldflags "-X github.com/louwietec/ledger-verify/verifier/internal/wasmapi.Version=..."
// setzen kann. / A var so a release build can stamp it.
var Version = "1.0.0"

// specVersion ist die Spezifikationsversion, die dieser Verifier umsetzt —
// gespiegelt aus spec/registry.json, gehalten von .ci/check_typlisten.py.
//
// Der Satz darueber stimmte bis zum 15.09. nicht: die Datei stand NICHT in
// SPEC_VERSION_KOPIEN, die Wache hielt hier also gar nichts. Genau der Fehler,
// der einen Tag zuvor im CLI-Verifier gefunden wurde ("spec 1.0" bei
// umgesetztem 1.1) — nur diesmal in der Fassung, die ein Pruefer OHNE
// Installation benutzt, also in der mit der niedrigsten Huerde. Jetzt steht
// sie in der Liste. Seit dem 28.09. (abends) 1.6: Kettenende versiegelt oder
// unvollstaendig (Spec 8.6, Exit 4). Seit dem 29.09. 1.7: Eintragstyp
// LEGAL_HOLD und Befund HOLD_VIOLATION (Spec 4.24, 9.3). Seit dem 29.09.
// (abends) 1.8: GENESIS.license_id ist das Lizenz-Commitment (Spec 4.1).
// 1.9: Export-Siegel, Randfaelle, gemessenes Restfenster (Spec 8.2-8.6, 10.1,
// 10.5, 10.8, 11.2).
const specVersion = "1.9"

// fehler baut die Antwort fuer einen unbrauchbaren Aufruf. Exit 3 ist hier der
// ehrliche Code: Exit 2 wuerde behaupten, die Kette sei gebrochen, Exit 1 sie
// sei gueltig — beides waeren Aussagen ueber einen Inhalt, den wir nicht
// gelesen haben.
func fehler(msg string) map[string]any {
	return map[string]any{"exit": 3, "report": "", "json": "", "error": msg}
}

func optString(o js.Value, name string) string {
	if o.IsUndefined() || o.IsNull() {
		return ""
	}
	v := o.Get(name)
	if v.Type() != js.TypeString {
		return ""
	}
	return v.String()
}

func verify(this js.Value, args []js.Value) any {
	if len(args) < 1 || args[0].IsUndefined() || args[0].IsNull() {
		return fehler("ledgerVerify: erstes Argument muss ein Uint8Array mit dem Pruefpaket sein / first argument must be a Uint8Array holding the package")
	}
	src := args[0]
	n := src.Get("length")
	if n.Type() != js.TypeNumber {
		return fehler("ledgerVerify: erstes Argument ist kein Uint8Array / first argument is not a Uint8Array")
	}
	data := make([]byte, n.Int())
	if len(data) > 0 {
		js.CopyBytesToGo(data, src)
	}

	// Ohne zweites Argument ein leeres Objekt statt undefined: opts.Get auf
	// undefined bricht in syscall/js mit einer Panik ab, und die Lesestellen
	// unten sollen nicht jede fuer sich darauf achten muessen.
	opts := js.Global().Get("Object").New()
	if len(args) > 1 && !args[1].IsUndefined() && !args[1].IsNull() {
		opts = args[1]
	}

	lang := optString(opts, "lang")
	if lang == "" {
		lang = "de"
	}
	if lang != "de" && lang != "en" {
		return fehler("ledgerVerify: lang muss de oder en sein / lang must be de or en")
	}

	opt := vfy.Options{Freshness: 24 * time.Hour}
	if !opts.IsUndefined() && !opts.IsNull() {
		if v := opts.Get("freshnessSeconds"); v.Type() == js.TypeNumber && v.Float() > 0 {
			opt.Freshness = time.Duration(v.Float()) * time.Second
		}
		if v := opts.Get("nowFromPackage"); v.Type() == js.TypeBoolean {
			opt.NowFromPackage = v.Bool()
		}
	}
	// Spec 10.8 (1.9): Pruefzeit und erwartete Wurzeln in derselben Grammatik
	// wie im Paket und wie auf der Kommandozeile; alles andere ist ein
	// unbrauchbarer Aufruf, nie eine stille Deutung (keine Ortszeit des
	// Browsers). / Same grammar as the package and the CLI (spec 10.8).
	if s := optString(opts, "now"); s != "" {
		t, err := vfy.ParseTime(s)
		if err != nil {
			return fehler("ledgerVerify: now ist kein Zeitpunkt der Form JJJJ-MM-TTThh:mm:ss[.Bruchteil]Z / now is not an instant of the form YYYY-MM-DDThh:mm:ss[.fraction]Z (spec 10.8)")
		}
		opt.Now = t
	}
	wurzeln := []string{}
	if s := optString(opts, "expectRoot"); s != "" {
		wurzeln = append(wurzeln, s)
	}
	if v := opts.Get("expectRoots"); !v.IsUndefined() && !v.IsNull() {
		l := v.Get("length")
		if l.Type() != js.TypeNumber {
			return fehler("ledgerVerify: expectRoots muss ein Array sein / must be an array")
		}
		for i := 0; i < l.Int(); i++ {
			if el := v.Index(i); el.Type() == js.TypeString {
				wurzeln = append(wurzeln, el.String())
			} else {
				return fehler("ledgerVerify: expectRoots enthaelt etwas anderes als Zeichenketten / holds a non-string")
			}
		}
	}
	for _, s := range wurzeln {
		x, err := vfy.ParseExpectedRoot(strings.TrimSpace(s))
		if err != nil {
			return fehler("ledgerVerify: erwartete Wurzel muss 64 Hex-Zeichen (ROOT) oder TREE_SIZE:ROOT sein / expected root must be 64 hex characters (ROOT) or TREE_SIZE:ROOT (spec 10.8)")
		}
		opt.ExpectRoots = append(opt.ExpectRoots, x)
	}
	// Vertrauensanker fuer Zeitzeugen (Spec 7.3). Der Browser hat KEINEN
	// Systemwurzelspeicher — ohne diesen Weg koennte die Seite einen Zeitzeugen
	// niemals unabhaengig belegen und muesste ihn fuer immer als
	// TIME_ANCHOR_UNVERIFIED melden. Die Datei waehlt der PRUEFER; sie kommt
	// nie aus dem Pruefpaket.
	if v := opts.Get("tsaRootsPem"); !v.IsUndefined() && !v.IsNull() {
		l := v.Get("length")
		if l.Type() != js.TypeNumber {
			return fehler("ledgerVerify: tsaRootsPem muss ein Uint8Array sein / must be a Uint8Array")
		}
		pemBytes := make([]byte, l.Int())
		if len(pemBytes) > 0 {
			js.CopyBytesToGo(pemBytes, v)
		}
		anzahl := 0
		for rest := pemBytes; len(rest) > 0; {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				break
			}
			if blk.Type == "CERTIFICATE" {
				opt.TSARoots = append(opt.TSARoots, blk.Bytes)
				anzahl++
			}
		}
		if anzahl == 0 {
			return fehler("ledgerVerify: tsaRootsPem enthaelt keinen CERTIFICATE-Block / contains no CERTIFICATE block")
		}
	}

	// Vertrauensanker fuer Hersteller-Quittungen (Spec 7.1, 10.7): die Wurzel
	// des Herstellers als Datei {"wurzel_id","pubkey"} und/oder einzelne
	// angeheftete Schluessel "key_id=hex". Beides waehlt der PRUEFER; ohne es
	// meldet die Seite jede Quittung als RECEIPT_UNVERIFIED, weil der
	// Schluessel sonst nur aus dem Paket kaeme.
	if w, ok, err := vfy.Builtin(); err != nil {
		return fehler("ledgerVerify: " + err.Error())
	} else if ok {
		opt.VendorRoots = append(opt.VendorRoots, w)
	}
	if v := opts.Get("vendorRootJson"); !v.IsUndefined() && !v.IsNull() {
		l := v.Get("length")
		if l.Type() != js.TypeNumber {
			return fehler("ledgerVerify: vendorRootJson muss ein Uint8Array sein / must be a Uint8Array")
		}
		roh := make([]byte, l.Int())
		if len(roh) > 0 {
			js.CopyBytesToGo(roh, v)
		}
		w, err := vfy.ParseVendorRoot(roh)
		if err != nil {
			return fehler("ledgerVerify: Herstellerwurzel / vendor root: " + err.Error())
		}
		opt.VendorRoots = append(opt.VendorRoots, w)
	}
	if v := opts.Get("vendorKeys"); !v.IsUndefined() && !v.IsNull() {
		l := v.Get("length")
		if l.Type() != js.TypeNumber {
			return fehler("ledgerVerify: vendorKeys muss ein Array sein / must be an array")
		}
		for i := 0; i < l.Int(); i++ {
			k, err := vfy.ParseVendorKey(v.Index(i).String())
			if err != nil {
				return fehler("ledgerVerify: vendorKeys: " + err.Error())
			}
			opt.VendorKeys = append(opt.VendorKeys, k)
		}
	}

	var err error
	if opt.VendorRoots, opt.VendorKeys, err = vfy.AnkerZusammenfuehren(opt.VendorRoots, opt.VendorKeys); err != nil {
		return fehler("ledgerVerify: " + err.Error())
	}

	res := vfy.VerifyBytes(data, opt)
	jsonBytes, err := vfy.RenderJSON(res)
	if err != nil {
		return fehler("ledgerVerify: Bericht nicht darstellbar / cannot render report: " + err.Error())
	}
	// Der Pfadname steht im Textbericht; im Browser gibt es keinen Pfad, also
	// wird der Dateiname genannt, den der Pruefer ausgewaehlt hat.
	name := optString(opts, "name")
	if name == "" {
		name = "(Pruefpaket / verification package)"
	}
	return map[string]any{
		"exit":   res.ExitCode,
		"report": vfy.RenderText(res, name, lang),
		"json":   string(jsonBytes),
		"error":  "",
	}
}

// Registrieren setzt ledgerVerify und ledgerVerifyVersion (und die Aliase unter
// dem frueheren Namen) im globalen JavaScript-Objekt. Der Aufrufer muss danach
// am Leben bleiben (select {}): ein beendetes Go-Programm loescht seine
// exportierten Funktionen. / Registers the globals; the caller must stay alive.
func Registrieren() {
	fn := js.FuncOf(verify)
	js.Global().Set("ledgerVerify", fn)
	// vendorRoot nennt die eingebaute Herstellerwurzel wie `--version` des
	// nativen Verifiers (Spec 7.1: ein Bau, der sie traegt, MUSS sie nennen).
	wurzel := "none"
	if w, ok, err := vfy.Builtin(); err == nil && ok {
		wurzel = w.ID + " " + w.Pubkey
	}
	fassung := js.ValueOf(map[string]any{
		"name":       name,
		"product":    product,
		"version":    Version,
		"spec":       specVersion,
		"vendorRoot": wurzel,
	})
	js.Global().Set("ledgerVerifyVersion", fassung)
	// Aliase unter dem alten Namen: dieselbe Funktion, dasselbe Objekt (kein
	// zweites js.FuncOf, keine Kopie) — tests/wasm/seitenprobe.mjs prueft
	// rekorderVerify === ledgerVerify. / Aliases: the same function and object.
	js.Global().Set("rekorderVerify", fn)
	js.Global().Set("rekorderVerifyVersion", fassung)
}
