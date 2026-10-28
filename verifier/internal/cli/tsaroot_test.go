package cli

// --tsa-root (spec 7.3, 10.8): repeatable, each file in the strict PEM of
// spec 10.8 (from 1.10); a file that is missing or does not read is an
// unusable invocation, exit 3 with the reason, never an anchor silently
// dropped. Measured on the frozen vector valid_time_anchor and its
// authority's certificate, which the test hands over as the auditor's root.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func probestelle(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(vektor(filepath.Join("valid_time_anchor", "keys", "tsa", "probestelle.pem")))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func datei(t *testing.T, name, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func klassen(t *testing.T, out string) string {
	t.Helper()
	var r struct {
		Findings []struct {
			Class string `json:"class"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("no JSON: %v\n%s", err, out)
	}
	var k []string
	for _, f := range r.Findings {
		k = append(k, f.Class)
	}
	sort.Strings(k)
	return strings.Join(k, ",")
}

func TestTSARootWiederholbar(t *testing.T) {
	gut := probestelle(t)
	basis := append([]string{"--json", "--now-from-package"}, pruefAnker(t)...)
	ziel := vektor("valid_time_anchor")
	for _, f := range []struct {
		why   string
		roots []string
		exit  int
		cls   string
	}{
		{"no root", nil, 4, "TIME_ANCHOR_UNVERIFIED,UNSEALED_END"},
		{"the authority's root", []string{gut}, 4, "UNSEALED_END"},
		{"a bundle with comments and the root twice", []string{"# bundle\n" + gut + "\n" + gut}, 4, "UNSEALED_END"},
		{"two files, the root in the second", []string{fremdeWurzel(t), gut}, 4, "UNSEALED_END"},
		{"another root only", []string{fremdeWurzel(t)}, 4, "TIME_ANCHOR_UNVERIFIED,UNSEALED_END"},
	} {
		args := append([]string{}, basis...)
		for i, r := range f.roots {
			args = append(args, "--tsa-root", datei(t, "r"+string(rune('0'+i))+".pem", r))
		}
		code, out, errOut := lauf(append(args, ziel)...)
		if code != f.exit || errOut != "" {
			t.Errorf("%s: exit %d (stderr %q), want %d", f.why, code, errOut, f.exit)
			continue
		}
		if got := klassen(t, out); got != f.cls {
			t.Errorf("%s: %s, want %s", f.why, got, f.cls)
		}
	}
}

func TestTSARootUnbrauchbar(t *testing.T) {
	gut := probestelle(t)
	b64 := strings.Join(strings.Split(strings.TrimSpace(gut), "\n")[1:3], "\n")
	for _, f := range []struct {
		why, text, grund string
	}{
		{"no block", "only text\n", "no CERTIFICATE block"},
		{"empty", "", "no CERTIFICATE block"},
		{"another block", "-----BEGIN X509 CRL-----\nMAA=\n-----END X509 CRL-----\n" + gut, "only CERTIFICATE blocks are read"},
		{"BEGIN without END", "-----BEGIN CERTIFICATE-----\n" + b64 + "\n", "has no END line"},
		// Strict PEM (10.8): an END line outside a block is text outside a
		// block; the file then has no block at all.
		{"END without BEGIN", b64 + "\n-----END CERTIFICATE-----\n", "no CERTIFICATE block"},
		{"no certificate inside", "-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n", "is no certificate"},
		{"bad base64", strings.Replace(gut, b64[:8], "!!!!!!!!", 1), "B64"},
		{"one good, one cut", gut + gut[:len(gut)-40], "has no END line"},
	} {
		p := datei(t, "root.pem", f.text)
		for _, extra := range [][]string{nil, {"--tsa-root", datei(t, "gut.pem", gut)}} {
			args := append(append([]string{"--json", "--now-from-package"}, extra...), "--tsa-root", p, vektor("valid_time_anchor"))
			code, out, errOut := lauf(args...)
			if code != 3 || out != "" || !strings.HasPrefix(errOut, Name+": --tsa-root "+p+": ") || !strings.Contains(errOut, f.grund) {
				t.Errorf("%s: exit %d, stdout %q, stderr %q; want exit 3 naming the file and %q", f.why, code, out, errOut, f.grund)
			}
		}
	}
	fehlt := filepath.Join(t.TempDir(), "fehlt.pem")
	code, out, errOut := lauf("--tsa-root", fehlt, vektor("valid_time_anchor"))
	if code != 3 || out != "" || !strings.HasPrefix(errOut, Name+": --tsa-root "+fehlt+": ") {
		t.Errorf("missing file: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

// fremdeWurzel is a certificate of another authority, the foreign fixture of
// the tsa package: a root that anchors nothing here.
func fremdeWurzel(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "tsa", "testdata", "fremd_tsa.crt"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
