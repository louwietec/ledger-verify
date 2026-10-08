package vfy

// Tests for spec 10.6 R5: the evidence-package manifest is extensible.
//
// Ohne die Behebung sind diese Tests rot, und zwar alle aus demselben Grund:
// loadManifest prüfte das Manifest strikt, meldete bei einem undefinierten Feld
// FORMAT_ERROR und BRACH DEN LAUF AB. Eine künftige Minor-Version, die EIN
// Manifest-Feld ergänzt, hätte damit jeden ausgelieferten Verifier dazu
// gebracht, ein gültiges Paket mit Exit 3 und NULL Kettenprüfungen abzulehnen.
//
// Geprüft werden die vier Zusicherungen der Regel getrennt: (1) das Feld wird
// angenommen und gemeldet statt das Paket zu verwerfen; (2) die Prüfungen
// laufen wirklich weiter — nachgewiesen an einem Befund, der nur aus der Kette
// kommen kann; (3) Unterobjekte sind ebenso offen, und der Pfad wird ohne Index
// gemeldet, je Feldpfad einmal; (4) die definierten Felder bleiben streng — die
// Regel öffnet das Manifest, sie weicht es nicht auf.
// / Four separate promises of the rule, each red without the fix.
//
// Seit Spezifikation 1.6 enden die Ketten hier versiegelt (validSealedChain,
// Abschnitt 8.6): sonst träte UNSEALED_END (Exit 4) zu jeder Erwartung, und
// „Exit 1, nicht schlimmer" wäre nicht mehr zu sehen.
// / The chains end sealed (spec 8.6), so the exit-1 verdict stays visible.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/louwietec/ledger-verify/verifier/internal/jcs"
)

// (1) Ein unbekanntes Manifest-Feld wird angenommen und gemeldet.
func TestR5UnbekanntesManifestFeldIstBefund(t *testing.T) {
	g := validSealedChain(t)
	g.extraMan = map[string]any{"retention_days": int64(3650)}
	res := verifyGen(g, Options{})
	wantClasses(t, res, 1, ClsUnknownManifestFld)

	fs := findingsOf(res, ClsUnknownManifestFld)
	if len(fs) != 1 {
		t.Fatalf("want exactly one UNKNOWN_MANIFEST_FIELD, got %d: %+v", len(fs), fs)
	}
	if !strings.Contains(fs[0].Detail, "manifest.retention_days") {
		t.Errorf("finding must name the field path, got %q", fs[0].Detail)
	}
	if fs[0].Seq != 0 {
		t.Errorf("a manifest finding carries no seq, got %d", fs[0].Seq)
	}
}

// (2) Die Kettenprüfungen laufen weiter — der eigentliche Punkt der Regel.
//
// Nachgewiesen an einer Manipulation, die NUR aus der Kette kommen kann: bricht
// der Lauf nach dem Manifest ab, fehlt HASH_MISMATCH und der Test ist rot. Ein
// Test, der bloß den Exit-Code prüft, hätte den Abbruch nicht gesehen.
func TestR5PruefungenLaufenWeiter(t *testing.T) {
	g := validSealedChain(t)
	g.extraMan = map[string]any{"partial_export": true}
	g.editLine(3, func(v *jcs.Value) { setMember(v.Get("payload"), "disk_pct", jInt(99)) })
	res := verifyGen(g, Options{})
	wantClasses(t, res, 2, ClsUnknownManifestFld, ClsHashMismatch)
}

// (3) Auch die Objekte in segments sind offen, und der Pfad wird ohne Index
// gemeldet — sonst wäre ein Zusatzfeld in hundert Segmenten hundert Befunde.
func TestR5UnterobjektOffenUndOhneIndex(t *testing.T) {
	g := validSealedChain(t)
	g.extraSeg = map[string]any{"first_ts": "2026-01-01T00:00:00.000Z"}
	res := verifyGen(g, Options{})
	wantClasses(t, res, 1, ClsUnknownManifestFld)

	fs := findingsOf(res, ClsUnknownManifestFld)
	if len(fs) != 1 {
		t.Fatalf("want one finding, got %d: %+v", len(fs), fs)
	}
	if !strings.Contains(fs[0].Detail, "manifest.segments[].first_ts") {
		t.Errorf("path must be reported without an index, got %q", fs[0].Detail)
	}
}

// (3b) Die Entdopplung selbst, als reine Logik geprüft: hundert Segmente mit
// demselben Zusatzfeld ergeben EINEN Pfad, und die Ausgabe ist sortiert.
//
// Die Sortierung ist keine Kosmetik: validateObjectOffen sammelt beim Gang über
// eine Go-Map, deren Reihenfolge absichtlich zufällig ist. Ohne Sortieren
// meldeten zwei Läufe über dasselbe Paket die Befunde in verschiedener
// Reihenfolge — und der zweite Verifier müsste dieselbe Menge reproduzieren.
func TestR5PfadeEntdoppeltUndSortiert(t *testing.T) {
	var roh []string
	for i := 99; i >= 0; i-- { // absichtlich absteigend eingespeist
		roh = append(roh, "manifest.segments["+itoa(i)+"].first_ts")
	}
	roh = append(roh, "manifest.zuletzt", "manifest.device_pubkeys[3].label", "manifest.als_erstes")

	got := unbekanntePfade(roh)
	want := []string{
		"manifest.als_erstes",
		"manifest.device_pubkeys[].label",
		"manifest.segments[].first_ts",
		"manifest.zuletzt",
	}
	if len(got) != len(want) {
		t.Fatalf("want %d paths, got %d: %v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("path %d: got %q, want %q (whole list: %v)", i, got[i], want[i], got)
		}
	}
}

// (4) Die DEFINIERTEN Felder bleiben streng: ein fehlendes bleibt
// FORMAT_ERROR. Ohne diesen Test wäre R5 nicht von "das Manifest wird nicht
// mehr geprüft" zu unterscheiden.
func TestR5DefinierteFelderBleibenStreng(t *testing.T) {
	g := validSealedChain(t)
	g.extraMan = map[string]any{"etwas_neues": "x"}
	dir := g.writePkg()
	manifestFeldEntfernen(t, dir, "tree_size")

	res := Verify(dir, genAnker(Options{Now: g.now.Add(time.Hour)}))
	if res.ExitCode != 3 {
		t.Fatalf("a missing DEFINED field must stay exit 3, got %d (%+v)", res.ExitCode, res.Findings)
	}
	if len(findingsOf(res, ClsFormatError)) == 0 {
		t.Errorf("want FORMAT_ERROR, got %+v", res.Findings)
	}
}

// manifestFeldEntfernen drops one member from the written manifest.json.
func manifestFeldEntfernen(t *testing.T, dir, key string) {
	t.Helper()
	p := filepath.Join(dir, "manifest.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	v, err := jcs.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	var rest []jcs.Member
	for _, m := range v.Members {
		if m.Key != key {
			rest = append(rest, m)
		}
	}
	if len(rest) == len(v.Members) {
		t.Fatalf("manifest.json has no field %q to remove", key)
	}
	v.Members = rest
	if err := os.WriteFile(p, jcs.Canon(v), 0o644); err != nil {
		t.Fatal(err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
