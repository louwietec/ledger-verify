package vfy

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
)

// Klarstellungen der Spezifikation 1.4 vom 25.09. (freigegeben): vier
// Stellen, an denen die beiden Verifier dasselbe Paket verschieden
// beurteilten, weil die Spezifikation schwieg. Jeder Test hier ist gegen den
// Stand davor rot.
//
// Seit Spezifikation 1.6 (Abschnitt 8.6) enden die kurzen Ketten hier
// unversiegelt und tragen UNSEALED_END daneben; der Exit-Code bleibt 2
// (Rangfolge 2 vor 4, Abschnitt 10.3). "Ohne Folgebefund" meint weiter: kein
// zweiter Befund ueber die Quittung selbst.

// 7.1: Eine Quittung, deren Signatur nicht traegt, ist RECEIPT_INVALID — und
// sonst nichts. Vorher lief die Praefixpruefung trotzdem und meldete
// MERKLE_INCONSISTENT ueber einen Inhalt, den kein Hersteller gesagt hat.
func TestUngueltigeQuittungOhneFolgebefund(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receipt(time.Second, g.seq, g.seq-1, strings.Repeat("ab", 32))
	_, fremd := keyFromSeed(9)
	res := pruefe(t, g, g.writePkg(), Options{VendorKeys: []VendorKey{{ID: "vendor-1", Pubkey: fremd}}})
	erwarte(t, res, 2, ClsReceiptInvalid, ClsNoAnchor, ClsUnsealedEnd)
}

// 7.1: Passt eine gueltig signierte Quittung zum Praefix, widerspricht aber
// ihrem Checkpoint, ist das RECEIPT_INVALID — und sie verankert nichts
// ("Eine Quittung mit RECEIPT_INVALID zaehlt nicht"). Vorher meldete dieser
// Verifier RECEIPT_INVALID, zaehlte sie aber als Anker; verifier2 meldete
// FORK_DETECTED.
func TestQuittungWidersprichtIhremCheckpoint(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	// quittiert tree_size 1 (passt zum Praefix), verweist aber auf seq 1 — die
	// Genesis, keinen CHECKPOINT
	g.receipt(time.Second, 1, 1, g.merkleRootAt(1))
	erwarte(t, verifyGen(g, Options{}), 2, ClsReceiptInvalid, ClsNoAnchor, ClsUnsealedEnd)
}

// Bei einem Fork bleibt es bei FORK_DETECTED allein: die Checkpoint-Pruefung
// entfaellt, damit kein Folgebefund den Fork verwischt.
func TestForkOhneCheckpointFolgebefund(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receipt(time.Second, 1, 1, strings.Repeat("cd", 32))
	erwarte(t, verifyGen(g, Options{}), 2, ClsForkDetected, ClsUnsealedEnd)
}

// Abschnitt 2: das Jahr liegt zwischen 0001 und 9999. Go nahm 0000 an,
// Pythons datetime nicht — Exit 0 gegen Exit 3 fuer dieselbe Kette.
func TestJahr0000IstFormatfehler(t *testing.T) {
	if _, err := parseRFC3339("0000-01-01T00:00:00Z"); err == nil {
		t.Fatal("Jahr 0000 angenommen")
	}
	if _, err := parseRFC3339("0001-01-01T00:00:00Z"); err != nil {
		t.Fatalf("Jahr 0001 abgelehnt: %v", err)
	}
	g := validChain(t)
	g.editLine(0, func(v *jcs.Value) { setMember(v, "ts_captured", jStr("0000-08-01T08:00:00Z")) })
	res := verifyGen(g, Options{})
	if res.ExitCode != 3 || !classSet(res)[ClsFormatError] {
		t.Fatalf("erwartet Exit 3 FORMAT_ERROR, bekam %d %v", res.ExitCode, sortedKeys(classSet(res)))
	}
}

// 10.1: Namen im ZIP in Normalform, keiner doppelt. Vorher bereinigte dieser
// Verifier die Namen und verwarf alles mit "..", verifier2 nahm sie roh: ein
// ZIP mit manifest.json UND ./manifest.json bekam hier Exit 3, dort Exit 0.
func TestZipNamenInNormalform(t *testing.T) {
	g := validSealedChain(t) // versiegelt (Spez. 8.6): das gute Paket bleibt Exit 0
	dir := g.writePkg()
	opt := genAnker(Options{Now: g.now.Add(time.Hour)})
	dateien := map[string][]byte{}
	var namen []string
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			b, _ := os.ReadFile(p)
			dateien[filepath.ToSlash(rel)] = b
			namen = append(namen, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(namen)
	baue := func(praefix string, extra ...string) []byte {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		schreib := func(n string, b []byte) {
			w, err := zw.Create(n)
			if err != nil {
				t.Fatal(err)
			}
			w.Write(b)
		}
		for _, n := range namen {
			schreib(praefix+n, dateien[n])
		}
		for i := 0; i+1 < len(extra); i += 2 {
			schreib(extra[i], []byte(extra[i+1]))
		}
		zw.Close()
		return buf.Bytes()
	}
	m := string(dateien["manifest.json"])
	if res := VerifyBytes(baue(""), opt); res.ExitCode != 0 {
		t.Fatalf("Ausgangspaket als ZIP: exit %d %+v", res.ExitCode, res.Findings)
	}
	if res := VerifyBytes(baue("paket/"), opt); res.ExitCode != 0 {
		t.Fatalf("gezipptes Verzeichnis: exit %d %+v", res.ExitCode, res.Findings)
	}
	for name, zipb := range map[string][]byte{
		"./manifest.json daneben":        baue("", "./manifest.json", m),
		"a/../manifest.json daneben":     baue("", "a/../manifest.json", m),
		"fuehrendes /":                   baue("", "/x.txt", "x"),
		"Backslash":                      baue("", "keys\\x.hex", "x"),
		"leerer Pfadteil":                baue("", "keys//x.hex", "x"),
		"doppelter Name":                 baue("", "manifest.json", m),
		"Datei neben dem Wrapper-Ordner": baue("paket/", "paket", "x"),
	} {
		res := VerifyBytes(zipb, opt)
		if res.ExitCode != 3 || !classSet(res)[ClsFormatError] {
			t.Errorf("%s: erwartet Exit 3 FORMAT_ERROR, bekam %d %v", name, res.ExitCode, sortedKeys(classSet(res)))
		}
	}
}
