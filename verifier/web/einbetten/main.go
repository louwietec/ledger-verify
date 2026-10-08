// Command einbetten baut aus der Vorlage, dem WebAssembly-Modul und Gos Lader
// EINE eigenstaendige HTML-Datei.
//
// WARUM ALS GO-PROGRAMM statt als Shell-Zeile: der Bau muss an zwei Orten
// laufen — auf der Entwicklerkiste (verifier/web/bauen.sh) und IM
// Appliance-Abbild (deploy/images/Dockerfile), damit das Portal die Seite
// beilegen kann. Eine Shell-Loesung braucht dort python3, gzip und base64;
// das golang-Abbild bringt sie nicht zuverlaessig mit, und jede fehlende
// davon waere ein Bauabbruch aus einem Grund, der nichts mit dem Produkt zu
// tun hat. Go ist an beiden Orten ohnehin da.
//
// DETERMINISTISCH: der gzip-Kopf bekommt weder Zeitstempel noch Dateinamen.
// Zwei Laeufe ueber dasselbe Modul ergeben dieselbe Seite, byte fuer byte —
// sonst koennte ein Pruefer die Pruefsumme nicht vergleichen, die der
// Hersteller veroeffentlicht.
//
// Aufruf / usage:
//
//	go run ./web/einbetten -vorlage web/verifier.html -wasm rv.wasm \
//	   -lader "$(go env GOROOT)/lib/wasm/wasm_exec.js" -aus dist/ledger-verify.html
//
// verifier/web/bauen.sh legt danach eine bytegleiche Kopie unter dem alten
// Namen dist/rekorder-verify.html ab, die Portal, Dockerfile und CI noch
// erwarten. / bauen.sh also writes a byte-identical copy under the old name.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	markeModul = "__WASM_GZIP_BASE64__"
	markeLader = "__WASM_EXEC_JS__"
)

func main() {
	vorlage := flag.String("vorlage", "", "HTML-Vorlage mit den Platzhaltern")
	wasm := flag.String("wasm", "", "das uebersetzte WebAssembly-Modul")
	lader := flag.String("lader", "", "wasm_exec.js der benutzten Go-Fassung")
	aus := flag.String("aus", "", "Zieldatei")
	flag.Parse()
	if *vorlage == "" || *wasm == "" || *lader == "" || *aus == "" {
		fmt.Fprintln(os.Stderr, "einbetten: -vorlage, -wasm, -lader und -aus sind Pflicht")
		os.Exit(2)
	}

	html, err := os.ReadFile(*vorlage)
	must(err, "Vorlage")
	modul, err := os.ReadFile(*wasm)
	must(err, "WebAssembly-Modul")
	ladercode, err := os.ReadFile(*lader)
	must(err, "wasm_exec.js")

	text := string(html)
	// GENAU EINMAL, nicht "mindestens einmal": stand die Marke auch im
	// Kopfkommentar der Vorlage, ersetzte strings.Replace(..., 1) den
	// Kommentar und liess die Konstante stehen. Ergebnis war eine 1,8 MB
	// grosse Seite, in der das Modul fehlte — sie haette im Browser gar nicht
	// erst gestartet, und der Aequivalenzlauf ueber das MODUL waere gruen
	// geblieben, weil er die Seite nie ansieht. Gefunden von
	// tests/wasm/seitenprobe.mjs beim ersten Lauf; hier ist der Riegel.
	for _, m := range []string{markeModul, markeLader} {
		switch n := strings.Count(text, m); {
		case n == 0:
			fmt.Fprintf(os.Stderr, "einbetten: die Vorlage fuehrt den Platzhalter %s nicht\n", m)
			os.Exit(1)
		case n > 1:
			fmt.Fprintf(os.Stderr, "einbetten: der Platzhalter %s steht %dx in der Vorlage — "+
				"er muss genau einmal vorkommen, sonst wird die falsche Stelle ersetzt\n", m, n)
			os.Exit(1)
		}
	}

	var gepackt bytes.Buffer
	zw, err := gzip.NewWriterLevel(&gepackt, gzip.BestCompression)
	must(err, "gzip")
	// Kein Name, kein Zeitstempel: sonst waere die Seite nie zweimal gleich.
	zw.Header.Name, zw.Header.ModTime = "", zeitNull()
	_, err = zw.Write(modul)
	must(err, "packen")
	must(zw.Close(), "packen abschliessen")

	text = strings.Replace(text, markeLader, string(ladercode), 1)
	text = strings.Replace(text, markeModul,
		base64.StdEncoding.EncodeToString(gepackt.Bytes()), 1)

	must(os.WriteFile(*aus, []byte(text), 0o644), "schreiben")

	summe := sha256.Sum256([]byte(text))
	fmt.Printf("Datei / file : %s\n", *aus)
	fmt.Printf("Modul / module: %d Bytes roh, %d Bytes gepackt\n", len(modul), gepackt.Len())
	fmt.Printf("Groesse/size : %d Bytes\n", len(text))
	fmt.Printf("SHA-256      : %s\n", hex.EncodeToString(summe[:]))
}

// zeitNull ist die Nullzeit des gzip-Kopfs: kein Zeitstempel im Ergebnis.
func zeitNull() time.Time { return time.Time{} }

func must(err error, was string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "einbetten: %s: %v\n", was, err)
		os.Exit(1)
	}
}
