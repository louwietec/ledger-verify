package vfy

// Spec 4.1 (from 1.8): GENESIS.license_id is the licence commitment. A
// GENESIS of spec 1.8 or newer with anything else is FORMAT_ERROR; a GENESIS
// of 1.7 or earlier with a value that is not 64 lowercase hex gets a notice —
// no finding, no change of the result, the value never printed.

import (
	"strings"
	"testing"
)

// klartextLizenz stands in cleartext in a 1.7 GENESIS of these tests and is
// therefore disclosed by construction (decision of 02.10.: keys from chains
// before 1.8 are replaced and never issued). It is used nowhere else.
const klartextLizenz = "LEDGER-OFFN-GELG-T17V-ERIF"

func sealedChainWith(t *testing.T, version, license string) *gen {
	g := newGen(t)
	g.specVersion = version
	g.license = license
	g.genesis()
	g.checkpoint(0)
	g.receiptForLast(0)
	g.tick(5 * 60e9)
	g.checkpoint(0)
	g.receiptForLast(0)
	g.seal("shutdown")
	return g
}

func TestGenesisLizenzAbFassung18NurCommitment(t *testing.T) {
	// the verifier's own version, cleartext: FORMAT_ERROR (exit 3)
	res := verifyGen(sealedChainWith(t, currentSpecVersion(), klartextLizenz), Options{})
	wantClasses(t, res, 3, ClsFormatError)
	if fs := findingsOf(res, ClsFormatError); len(fs) != 1 || !strings.Contains(fs[0].Detail, "licence commitment") || fs[0].Seq != 1 {
		t.Fatalf("want one FORMAT_ERROR at seq 1 naming the licence commitment, got %+v", fs)
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Detail, klartextLizenz) {
			t.Fatalf("the finding prints the licence value: %q", f.Detail)
		}
	}
	// a newer MINOR, cleartext: the narrowing binds from 1.8 on, so it binds
	// at 1.9 too; SPEC_NEWER is reported alongside (10.6 R3, last sentence)
	res = verifyGen(sealedChainWith(t, newerMinorVersion(), klartextLizenz), Options{})
	wantClasses(t, res, 3, ClsFormatError, ClsSpecNewer)
	// the commitment at the verifier's own version: clean, no notice
	res = verifyGen(sealedChainWith(t, currentSpecVersion(), ""), Options{})
	wantClasses(t, res, 0)
	if res.Stats.GenesisLicenseNotCommitment {
		t.Fatal("notice for a GENESIS that carries the commitment")
	}
	// 64 hex characters, but uppercase: not the commitment form
	res = verifyGen(sealedChainWith(t, currentSpecVersion(), strings.ToUpper(testLicenseCommitment())), Options{})
	wantClasses(t, res, 3, ClsFormatError)
}

func TestGenesisLizenzBis17NurHinweis(t *testing.T) {
	// cleartext under 1.7: the result is untouched, the notice is set and the
	// text report carries it in both languages without the value
	res := verifyGen(sealedChainWith(t, "1.7", klartextLizenz), Options{})
	wantClasses(t, res, 0)
	if !res.Stats.GenesisLicenseNotCommitment {
		t.Fatal("no notice for a 1.7 GENESIS with a cleartext license_id")
	}
	for lang, want := range map[string]string{"en": "licence key itself could stand there", "de": "Lizenzschlüssel selbst stehen"} {
		txt := RenderText(res, "pkg", lang)
		if !strings.Contains(txt, want) {
			t.Errorf("%s report lacks the notice:\n%s", lang, txt)
		}
		if strings.Contains(txt, klartextLizenz) {
			t.Errorf("%s report prints the licence value", lang)
		}
	}
	js, err := RenderJSON(res)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), `"genesis_license_not_commitment": true`) || strings.Contains(string(js), klartextLizenz) {
		t.Fatalf("JSON must carry the notice and not the value:\n%s", js)
	}
	// the commitment under 1.7 (the vendor-side mitigation before 1.8): no notice
	res = verifyGen(sealedChainWith(t, "1.7", ""), Options{})
	wantClasses(t, res, 0)
	if res.Stats.GenesisLicenseNotCommitment {
		t.Fatal("notice for a 1.7 GENESIS that already carries the commitment")
	}
	js, _ = RenderJSON(res)
	if strings.Contains(string(js), "genesis_license_not_commitment") {
		t.Fatal("the JSON names the notice although it does not apply")
	}
}
