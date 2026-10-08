package vfy

// Spec 7.1/10.7 (spec 1.4): the vendor key of a receipt is established by the
// AUDITOR's trust anchor — a pinned key or the vendor root, which vouches for
// keys through the signed list in the package — never by the package alone.
// Every case here builds its options by hand: none uses genAnker.
//
// The chains end sealed (validSealedChain, spec 8.6) wherever the verdict is
// about the vendor key alone — otherwise UNSEALED_END (exit 4) would join
// every expectation and hide the difference between exit 0 and exit 1 these
// tests are about. The short fork chains below end unsealed and list
// UNSEALED_END alongside; their exit-2 finding decides (spec 10.3).

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// wurzel is the test vendor root for these cases (seed 7).
func wurzel() (VendorRoot, ed25519.PrivateKey) {
	priv, pub := keyFromSeed(7)
	return VendorRoot{ID: "wurzel-test", Pubkey: pub}, priv
}

type listKey struct {
	id, pub, ab, bis, widerr string
}

// signierteListe builds a list and signs it with priv as root rootID.
func signierteListe(t *testing.T, rootID string, priv ed25519.PrivateKey, keys ...listKey) []byte {
	t.Helper()
	var ks []any
	for _, k := range keys {
		m := map[string]any{"key_id": k.id, "pubkey": k.pub, "gueltig_ab": k.ab}
		if k.bis != "" {
			m["gueltig_bis"] = k.bis
		}
		if k.widerr != "" {
			m["widerrufen_ab"] = k.widerr
		}
		ks = append(ks, m)
	}
	l := map[string]any{
		"format": VendorListFormat, "version": int64(3),
		"ausgestellt": "2026-07-01T00:00:00Z", "schluessel": ks,
	}
	sig := hex.EncodeToString(ed25519.Sign(priv, canonGo(t, l)))
	l["signatur"] = map[string]any{"wurzel_id": rootID, "sig": sig}
	return canonGo(t, l)
}

func legeListe(t *testing.T, dir string, liste []byte) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(VendorListPath))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, liste, 0o644); err != nil {
		t.Fatal(err)
	}
}

func pruefe(t *testing.T, g *gen, dir string, opt Options) Result {
	t.Helper()
	opt.Now = g.now.Add(time.Hour)
	return Verify(dir, opt)
}

func erwarte(t *testing.T, res Result, exit int, klassen ...string) {
	t.Helper()
	got := sortedKeys(classSet(res))
	want := append([]string{}, klassen...)
	if res.ExitCode != exit || strings.Join(got, ",") != strings.Join(sortedStrings(want), ",") {
		t.Fatalf("exit=%d %v, erwartet exit=%d %v; %+v", res.ExitCode, got, exit, want, res.Findings)
	}
}

func sortedStrings(xs []string) []string {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return sortedKeys(m)
}

// Die Faelschung aus faelschung_test.go, im Kleinen: ohne jeden Anker gilt
// eine Quittung nie als Herstellerquittung. EIN Befund je Schluessel, nicht je
// Quittung; die Quittung zaehlt trotzdem als Verankerung (kein NO_ANCHOR,
// wie beim Zeitzeugen, Spec 7.3).
func TestOhneAnkerIstJedeQuittungUnbelegt(t *testing.T) {
	g := validSealedChain(t)
	res := pruefe(t, g, g.writePkg(), Options{})
	erwarte(t, res, 1, ClsReceiptUnverified)
	n := 0
	for _, f := range res.Findings {
		if f.Class == ClsReceiptUnverified {
			n++
			if !strings.Contains(f.Detail, "vendor-1") || !strings.Contains(f.Detail, g.vendPub) {
				t.Errorf("der Befund muss Kennung und Publikey nennen, damit der Pruefer nachschlagen kann: %s", f.Detail)
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d RECEIPT_UNVERIFIED fuer zwei Quittungen unter EINEM Schluessel, erwartet 1", n)
	}
	if res.Stats.Receipts != 2 || res.Stats.ReceiptsEstablished != 0 {
		t.Fatalf("Statistik %d/%d, erwartet 2/0", res.Stats.Receipts, res.Stats.ReceiptsEstablished)
	}
}

func TestAngehefteterSchluesselBelegt(t *testing.T) {
	g := validSealedChain(t)
	res := pruefe(t, g, g.writePkg(), Options{VendorKeys: []VendorKey{{ID: "vendor-1", Pubkey: g.vendPub}}})
	erwarte(t, res, 0)
	if res.Stats.ReceiptsEstablished != 2 {
		t.Fatalf("ReceiptsEstablished=%d, erwartet 2", res.Stats.ReceiptsEstablished)
	}
}

// Der Pruefer heftet fuer vendor-1 einen ANDEREN Schluessel an, als das Paket
// behauptet: geprueft wird gegen den angehefteten — und das scheitert.
func TestAngehefteterSchluesselWidersprichtDemPaket(t *testing.T) {
	g := validSealedChain(t)
	_, fremd := keyFromSeed(9)
	res := pruefe(t, g, g.writePkg(), Options{VendorKeys: []VendorKey{{ID: "vendor-1", Pubkey: fremd}}})
	erwarte(t, res, 2, ClsReceiptInvalid, ClsNoAnchor)
}

func TestListeDerWurzelBelegt(t *testing.T) {
	g := validSealedChain(t)
	w, priv := wurzel()
	dir := g.writePkg()
	legeListe(t, dir, signierteListe(t, w.ID, priv, listKey{id: "vendor-1", pub: g.vendPub, ab: "2026-01-01T00:00:00Z", bis: "2027-01-01T00:00:00Z"}))
	res := pruefe(t, g, dir, Options{VendorRoots: []VendorRoot{w}})
	erwarte(t, res, 0)
	if res.Stats.ReceiptsEstablished != 2 {
		t.Fatalf("ReceiptsEstablished=%d, erwartet 2", res.Stats.ReceiptsEstablished)
	}
}

// Spec 7.1: Ob es eine neuere Liste gibt, sieht der Verifier nicht. Bericht
// und JSON nennen deshalb Version, Ausstellzeit und Wurzel der verwendeten
// Liste — und nennen keine, wenn keine Liste gezaehlt hat.
func TestBerichtNenntDieListe(t *testing.T) {
	g := validSealedChain(t)
	w, priv := wurzel()
	dir := g.writePkg()
	legeListe(t, dir, signierteListe(t, w.ID, priv, listKey{id: "vendor-1", pub: g.vendPub, ab: "2026-01-01T00:00:00Z"}))
	res := pruefe(t, g, dir, Options{VendorRoots: []VendorRoot{w}})
	want := VendorListStat{Version: 3, Issued: "2026-07-01T00:00:00Z", Root: w.ID}
	if res.Stats.VendorList == nil || *res.Stats.VendorList != want {
		t.Fatalf("Stats.VendorList=%+v, erwartet %+v", res.Stats.VendorList, want)
	}
	for lang, wort := range map[string]string{"de": "Version 3, ausgestellt 2026-07-01T00:00:00Z, Wurzel " + w.ID,
		"en": "version 3, issued 2026-07-01T00:00:00Z, root " + w.ID} {
		if txt := RenderText(res, dir, lang); !strings.Contains(txt, wort) {
			t.Errorf("%s-Bericht nennt die Liste nicht (%q):\n%s", lang, wort, txt)
		}
	}
	// Ohne Wurzel zaehlt die Liste nicht: keine Angabe, die nach Beleg aussieht.
	if res := pruefe(t, g, dir, Options{}); res.Stats.VendorList != nil {
		t.Fatalf("Liste ohne Wurzel im Bericht: %+v", res.Stats.VendorList)
	}
}

// Die signierte Aussage des Herstellers widerspricht der Quittung. Weil hier
// JEDE Quittung betroffen ist, verankert nichts mehr: NO_ANCHOR daneben (7.1 —
// nur eine Quittung, die ihre Signatur traegt, zaehlt als Verankerung).
func TestListeWiderspricht(t *testing.T) {
	faelle := []struct {
		name string
		k    listKey
		wort string
	}{
		{"noch nicht gueltig", listKey{ab: "2026-09-01T00:00:00Z"}, "valid from"},
		{"abgelaufen", listKey{ab: "2026-01-01T00:00:00Z", bis: "2026-08-01T00:00:00Z"}, "valid until"},
		{"widerrufen", listKey{ab: "2026-01-01T00:00:00Z", widerr: "2026-07-31T00:00:00Z"}, "REVOKED"},
		{"widerrufen genau zum Zeitpunkt", listKey{ab: "2026-01-01T00:00:00Z", widerr: "2026-08-01T08:00:02Z"}, "REVOKED"},
	}
	for _, f := range faelle {
		t.Run(f.name, func(t *testing.T) {
			g := validSealedChain(t)
			w, priv := wurzel()
			dir := g.writePkg()
			k := f.k
			k.id, k.pub = "vendor-1", g.vendPub
			legeListe(t, dir, signierteListe(t, w.ID, priv, k))
			res := pruefe(t, g, dir, Options{VendorRoots: []VendorRoot{w}})
			erwarte(t, res, 2, ClsReceiptInvalid, ClsNoAnchor)
			if !strings.Contains(res.Findings[0].Detail, f.wort) {
				t.Errorf("Begruendung ohne %q: %s", f.wort, res.Findings[0].Detail)
			}
		})
	}
}

// Die Liste bindet die Kennung an einen anderen Publikey als das Manifest.
func TestListeBindetAnderenPublikey(t *testing.T) {
	g := validSealedChain(t)
	w, priv := wurzel()
	_, fremd := keyFromSeed(9)
	dir := g.writePkg()
	legeListe(t, dir, signierteListe(t, w.ID, priv, listKey{id: "vendor-1", pub: fremd, ab: "2026-01-01T00:00:00Z"}))
	res := pruefe(t, g, dir, Options{VendorRoots: []VendorRoot{w}})
	erwarte(t, res, 2, ClsReceiptInvalid, ClsNoAnchor)
}

// Eine Liste, die der Pruefer nicht pruefen kann oder die nicht traegt,
// macht nichts glaubwuerdig — aber sie ist auch kein Faelschungsbeweis.
func TestListeZaehltNicht(t *testing.T) {
	w, priv := wurzel()
	andereWurzel, anderePriv := VendorRoot{ID: "wurzel-anders"}, ed25519.PrivateKey(nil)
	anderePriv, andereWurzel.Pubkey = keyFromSeed(8)
	faelle := []struct {
		name  string
		liste func(g *gen) []byte
		opt   Options
		grund string
	}{
		{"keine Wurzel beigebracht", func(g *gen) []byte {
			return signierteListe(t, w.ID, priv, listKey{id: "vendor-1", pub: g.vendPub, ab: "2026-01-01T00:00:00Z"})
		}, Options{VendorKeys: []VendorKey{{ID: "vendor-x", Pubkey: w.Pubkey}}}, "no vendor root was supplied"},
		{"fremde Wurzel", func(g *gen) []byte {
			return signierteListe(t, andereWurzel.ID, anderePriv, listKey{id: "vendor-1", pub: g.vendPub, ab: "2026-01-01T00:00:00Z"})
		}, Options{VendorRoots: []VendorRoot{w}}, "signed by root"},
		{"Signatur passt nicht", func(g *gen) []byte {
			return signierteListe(t, w.ID, anderePriv, listKey{id: "vendor-1", pub: g.vendPub, ab: "2026-01-01T00:00:00Z"})
		}, Options{VendorRoots: []VendorRoot{w}}, "does not verify"},
		{"undefiniertes Feld", func(g *gen) []byte {
			b := signierteListe(t, w.ID, priv, listKey{id: "vendor-1", pub: g.vendPub, ab: "2026-01-01T00:00:00Z"})
			return []byte(strings.Replace(string(b), `{"ausgestellt"`, `{"anmerkung":"x","ausgestellt"`, 1))
		}, Options{VendorRoots: []VendorRoot{w}}, "undefined field"},
		{"Zeit mit Versatz statt Z", func(g *gen) []byte {
			return signierteListe(t, w.ID, priv, listKey{id: "vendor-1", pub: g.vendPub, ab: "2026-01-01T00:00:00+01:00"})
		}, Options{VendorRoots: []VendorRoot{w}}, "UTC timestamp"},
		{"Schluessel nicht gelistet", func(g *gen) []byte {
			_, anderer := keyFromSeed(9)
			return signierteListe(t, w.ID, priv, listKey{id: "vendor-9", pub: anderer, ab: "2026-01-01T00:00:00Z"})
		}, Options{VendorRoots: []VendorRoot{w}}, "not in the vendor's list"},
	}
	for _, f := range faelle {
		t.Run(f.name, func(t *testing.T) {
			g := validSealedChain(t)
			dir := g.writePkg()
			legeListe(t, dir, f.liste(g))
			res := pruefe(t, g, dir, f.opt)
			erwarte(t, res, 1, ClsReceiptUnverified)
			if !strings.Contains(res.Findings[0].Detail, f.grund) {
				t.Errorf("Begruendung ohne %q: %s", f.grund, res.Findings[0].Detail)
			}
		})
	}
}

// Eine Quittung unter unbelegtem Schluessel ist trotzdem gueltig signiert:
// eine Zweitgeschichte bleibt FORK_DETECTED und wird nicht zu etwas
// Harmloserem.
func TestUnbelegterSchluesselVerdecktKeinenFork(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receipt(time.Second, g.seq, g.seq-1, strings.Repeat("ab", 32))
	res := pruefe(t, g, g.writePkg(), Options{})
	erwarte(t, res, 2, ClsForkDetected, ClsReceiptUnverified, ClsUnsealedEnd)
}

func TestAnkerEingabenStreng(t *testing.T) {
	if _, err := ParseVendorRoot([]byte(`{"wurzel_id":"w","pubkey":"` + strings.Repeat("a", 64) + `","x":1}`)); err == nil {
		t.Error("Wurzeldatei mit undefiniertem Feld angenommen")
	}
	if _, err := ParseVendorRoot([]byte(`{"wurzel_id":"w","pubkey":"` + strings.Repeat("A", 64) + `"}`)); err == nil {
		t.Error("Wurzel mit Grossbuchstaben-Hex angenommen")
	}
	if _, err := ParseVendorKey("vendor-1" + strings.Repeat("a", 64)); err == nil {
		t.Error("Anheftung ohne = angenommen")
	}
	if k, err := ParseVendorKey("vendor-1=" + strings.Repeat("a", 64)); err != nil || k.ID != "vendor-1" {
		t.Errorf("gueltige Anheftung abgelehnt: %v", err)
	}
	alt := BuiltinVendorRoot
	defer func() { BuiltinVendorRoot = alt }()
	BuiltinVendorRoot = "w=zz"
	if _, _, err := Builtin(); err == nil {
		t.Error("kaputte eingebaute Wurzel angenommen")
	}
}

// Gegenpruefung vom 25.09., H1: die Manifest-Kopie eines belegten Schluessels
// ist nicht beweistragend (Spec 10.1). Frueher machte eine unsignierte
// Manifest-Aenderung aus echten Herstellerquittungen RECEIPT_INVALID +
// NO_ANCHOR — und verdeckte damit ein FORK_DETECTED.
func TestManifestKopieIstOhneBelang(t *testing.T) {
	g := validSealedChain(t)
	w, priv := wurzel()
	dir := g.writePkg()
	legeListe(t, dir, signierteListe(t, w.ID, priv, listKey{id: "vendor-1", pub: g.vendPub, ab: "2026-01-01T00:00:00Z"}))
	faelscheManifestKey(t, dir, strings.Repeat("11", 32))
	erwarte(t, pruefe(t, g, dir, Options{VendorRoots: []VendorRoot{w}}), 0)
	erwarte(t, pruefe(t, g, dir, Options{VendorKeys: []VendorKey{{ID: "vendor-1", Pubkey: g.vendPub}}}), 0)
}

func TestManifestKopieVerdecktKeinenFork(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receipt(time.Second, g.seq, g.seq-1, strings.Repeat("ab", 32))
	w, priv := wurzel()
	dir := g.writePkg()
	legeListe(t, dir, signierteListe(t, w.ID, priv, listKey{id: "vendor-1", pub: g.vendPub, ab: "2026-01-01T00:00:00Z"}))
	faelscheManifestKey(t, dir, strings.Repeat("11", 32))
	erwarte(t, pruefe(t, g, dir, Options{VendorRoots: []VendorRoot{w}}), 2, ClsForkDetected, ClsUnsealedEnd)
}

// Eine Quittung, der die Liste widerspricht, traegt ihre Signatur trotzdem:
// die Praefix-Pruefung laeuft (Spec 7.1), der Fork bleibt sichtbar.
func TestWiderspruchVerdecktKeinenFork(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receipt(time.Second, g.seq, g.seq-1, strings.Repeat("ab", 32))
	w, priv := wurzel()
	dir := g.writePkg()
	legeListe(t, dir, signierteListe(t, w.ID, priv, listKey{id: "vendor-1", pub: g.vendPub, ab: "2026-01-01T00:00:00Z", widerr: "2026-02-01T00:00:00Z"}))
	erwarte(t, pruefe(t, g, dir, Options{VendorRoots: []VendorRoot{w}}), 2, ClsForkDetected, ClsReceiptInvalid, ClsNoAnchor, ClsUnsealedEnd)
}

func faelscheManifestKey(t *testing.T, dir, pub string) {
	t.Helper()
	p := filepath.Join(dir, "manifest.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m["vendor_pubkeys"].([]any)[0].(map[string]any)["pubkey"] = pub
	b, _ = json.Marshal(m)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// L1/L5: Zeitgrammatik der Liste wie in Spec 10.7 — Jahr 0001 bis 9999,
// Sekundenbruchteile beliebiger Laenge, verglichen auf Nanosekunden.
func TestListenzeitGrammatik(t *testing.T) {
	if _, ok := parseUTC("0000-01-01T00:00:00Z"); ok {
		t.Error("Jahr 0000 angenommen")
	}
	a, ok1 := parseUTC("2026-01-01T00:00:00.1234567891234Z")
	b, ok2 := parseUTC("2026-01-01T00:00:00.123456789Z")
	if !ok1 || !ok2 || !a.Equal(b) {
		t.Errorf("zehn und mehr Nachkommastellen: %v %v %v %v", a, ok1, b, ok2)
	}
	if _, ok := parseUTC("2026-01-01T00:00:00.1234567891234"); ok {
		t.Error("ohne Z angenommen")
	}
}

// L3: widerspruechliche Anker desselben Namens sind ein Aufruffehler.
func TestWiderspruechlicheAnker(t *testing.T) {
	a, b := strings.Repeat("aa", 32), strings.Repeat("bb", 32)
	if _, _, err := AnkerZusammenfuehren([]VendorRoot{{ID: "w", Pubkey: a}, {ID: "w", Pubkey: b}}, nil); err == nil {
		t.Error("zwei Wurzeln gleichen Namens, verschiedener Schluessel: angenommen")
	}
	if _, _, err := AnkerZusammenfuehren(nil, []VendorKey{{ID: "k", Pubkey: a}, {ID: "k", Pubkey: b}}); err == nil {
		t.Error("zwei Anheftungen gleicher Kennung, verschiedener Schluessel: angenommen")
	}
	r, k, err := AnkerZusammenfuehren([]VendorRoot{{ID: "w", Pubkey: a}, {ID: "w", Pubkey: a}}, []VendorKey{{ID: "k", Pubkey: b}, {ID: "k", Pubkey: b}})
	if err != nil || len(r) != 1 || len(k) != 1 {
		t.Errorf("gleiche Anker doppelt: %v %v %v", r, k, err)
	}
	if _, _, err := AnkerZusammenfuehren([]VendorRoot{{ID: "w", Pubkey: "zz"}}, nil); err == nil {
		t.Error("kaputte Wurzel angenommen")
	}
}

// 14: ein unbrauchbarer Anker, der die Bibliothek erreicht, verschwindet
// nicht still — der Befund sagt, dass er verworfen wurde.
func TestUnbrauchbarerAnkerWirdGenannt(t *testing.T) {
	g := validSealedChain(t)
	res := pruefe(t, g, g.writePkg(), Options{VendorKeys: []VendorKey{{ID: "vendor-1", Pubkey: "kein-hex"}}})
	erwarte(t, res, 1, ClsReceiptUnverified)
	if !strings.Contains(res.Findings[0].Detail, "malformed") {
		t.Errorf("verworfener Anker nicht genannt: %s", res.Findings[0].Detail)
	}
}

// M2: ein nicht-kanonisch kodierter Publikey (y >= p) ist kein Schluessel —
// der Zweitverifier lehnte ihn ab, der Go-Verifier nahm ihn an.
func TestNichtKanonischerPublikey(t *testing.T) {
	pub := "ee" + strings.Repeat("ff", 30) + "7f"
	sig := "01" + strings.Repeat("00", 63)
	if verifySig(pub, []byte("irgendwas"), sig) {
		t.Fatal("nicht-kanonischer Publikey (Identitaetspunkt, y = p+1) verifiziert eine Signatur")
	}
}
