package tsa

// Strict PEM (format spec 10.8), the order of the rows of 7.5.7, and the
// mirror of the registry (published_test_keys, outcome cases, states).

import (
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	tt "louwietec.com/ledger-verify/verifier/internal/tsa/tsatest"
)

func pemOf(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestStrictPEM(t *testing.T) {
	a := pemOf(probeCert())
	b := pemOf(tt.Cert(tt.CertSpec{CN: "Second", Key: edKey("second")}))
	body := strings.Join(strings.Split(strings.TrimSpace(a), "\n")[1:3], "\n")
	for _, f := range []struct {
		why  string
		text string
		n    int // certificates; -1: unusable
	}{
		{"one block", a, 1},
		{"two blocks", a + b, 2},
		{"text and colons outside the blocks", "# bundle: roots\nSubject: x\n" + a + "comment: y\n" + b, 2},
		{"CRLF line ends", strings.ReplaceAll(a, "\n", "\r\n"), 1},
		{"blanks and tabs at line ends", strings.ReplaceAll(a, "\n", " \t\n"), 1},
		{"a last line without line end", strings.TrimSuffix(a, "\n"), 1},
		{"an empty content line", strings.Replace(a, "\n", "\n\n", 2), 1},
		{"an END line outside a block is text", "-----END CERTIFICATE-----\n" + a, 1},
		{"another label", "-----BEGIN X509 CRL-----\nMAA=\n-----END X509 CRL-----\n" + a, -1},
		{"an empty label", "-----BEGIN -----\n" + a, -1},
		{"a header line inside a block", strings.Replace(a, "-----BEGIN CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n", 1), -1},
		{"a block without END", "-----BEGIN CERTIFICATE-----\n" + body + "\n", -1},
		{"one good, one cut", a + a[:len(a)-40], -1},
		{"no block", "only text\n", -1},
		{"empty", "", -1},
		{"a blank inside the content", strings.Replace(a, "\n", "\nM I", 2), -1},
		{"leading blanks on a content line", strings.Replace(a, "-----\n", "-----\n  ", 1), -1},
		{"not a certificate", "-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n", -1},
		{"BEGIN indented is text, its END outside", "  " + a, -1},
	} {
		got, err := ParsePEMRoots([]byte(f.text))
		switch {
		case f.n < 0 && err == nil:
			t.Errorf("PEM %s: accepted %d certificates", f.why, len(got))
		case f.n >= 0 && err != nil:
			t.Errorf("PEM %s: %v", f.why, err)
		case f.n >= 0 && len(got) != f.n:
			t.Errorf("PEM %s: %d certificates, want %d", f.why, len(got), f.n)
		}
	}
}

// TestAssessOrder: for both purposes the topmost row of 7.5.7 decides
// (spec/testvectors/README 10.4, "die oberste zutreffende Zeile"), Z.6
// included; a published test key confirms no time stamp of either purpose.
func TestAssessOrder(t *testing.T) {
	root := probeCert()
	other := tt.Cert(tt.CertSpec{CN: "Other", Key: edKey("other root")})
	type want struct{ state, cs string }
	for _, f := range []struct {
		why        string
		der        []byte
		data       []byte
		roots      [][]byte
		day, chain want
	}{
		{"confirmed", probeToken(nil), stamped, [][]byte{root}, want{StateConfirmed, ""}, want{StateConfirmed, ""}},
		{"grammar before everything", append(probeToken(nil), 0), []byte("x"), nil,
			want{StateDefective, CaseGrammar}, want{StateDefective, CaseGrammar}},
		{"imprint before 5a", probeToken(func(s *tt.TokenSpec) { s.NoCerts = true }), []byte("x"), nil,
			want{StateDefective, CaseImprint}, want{StateDefective, CaseImprint}},
		{"5a before Z.6 and the path", probeToken(func(s *tt.TokenSpec) { s.Digest, s.ESS = tt.SHA1, "none" }), stamped, nil,
			want{StateUnconfirmed, CaseNotPerformable}, want{StateUnconfirmed, CaseNotPerformable}},
		{"5b before Z.6", probeToken(func(s *tt.TokenSpec) { s.ESS, s.Tamper = "none", tt.FlipLast }), stamped, [][]byte{root},
			want{StateDefective, CaseFailed}, want{StateDefective, CaseFailed}},
		{"Z.6 before the path", probeToken(func(s *tt.TokenSpec) { s.ESS = "none" }), stamped, [][]byte{other},
			want{StateDefective, CaseZ6Violated}, want{StateDefective, CaseZ6Violated}},
		{"Z.6 not checkable before the path", probeToken(func(s *tt.TokenSpec) {
			s.ESSAttr = essV2(essIDv2(tt.Alg(tt.SHA3_256), []byte{1}, nil))
		}), stamped, nil, want{StateUnconfirmed, CaseZ6NotCheckable}, want{StateUnconfirmed, CaseZ6NotCheckable}},
		{"no root at all", probeToken(nil), stamped, nil, want{StateUnconfirmed, CaseNoPath}, want{StateUnconfirmed, CaseNoPath}},
	} {
		for purpose, w := range map[string]want{PurposeLog: f.day, PurposeChain: f.chain} {
			a := Assess(f.der, f.data, certs(t, f.roots...), purpose)
			if a.State != w.state || a.Case != w.cs {
				t.Errorf("7.5.7 %s (%s): %s %s (%s), want %s %s", f.why, purpose, a.State, a.Case, a.Detail, w.state, w.cs)
			}
		}
	}
	// Published test keys: a signer or a root in the list confirms no time
	// stamp, whatever the purpose (format spec 7.5.7: "bestätigt keinen
	// Zeitstempel"). The probe authority stands in for a listed key here.
	c := cert(t, root)
	h := c.SPKISHA256()
	saved := PublishedTestSPKI
	PublishedTestSPKI = append([]string{}, saved...)
	PublishedTestSPKI = append(PublishedTestSPKI, hex.EncodeToString(h[:]))
	defer func() { PublishedTestSPKI = saved }()
	if a := Assess(probeToken(nil), stamped, []*Certificate{c}, PurposeLog); a.State != StateUnconfirmed || a.Case != CaseTestKey {
		t.Errorf("test key, log: %s %s", a.State, a.Case)
	}
	if a := Assess(probeToken(nil), stamped, []*Certificate{c}, PurposeChain); a.State != StateUnconfirmed || a.Case != CaseTestKey {
		t.Errorf("test key, chain: %s %s", a.State, a.Case)
	}
	if a := Assess(probeToken(nil), stamped, []*Certificate{cert(t, other)}, PurposeLog); a.Case != CaseNoPath {
		t.Errorf("test key without path: %s %s", a.State, a.Case)
	}
}

// TestRegistryMirror holds the hand-copied lists of this package against
// spec/registry.json: the SPKI values of published_test_keys, the outcome
// cases of 7.5.7, the day token states, the QS results and the token limits.
func TestRegistryMirror(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		Verifier struct {
			TP struct {
				MaxDER   int `json:"token_max_der_bytes"`
				MaxB64   int `json:"token_max_b64_chars"`
				Outcomes []struct {
					Case string `json:"case"`
				} `json:"outcomes"`
				States []string `json:"day_token_states"`
				QS     struct {
					Results []string `json:"results"`
				} `json:"qs"`
				Keys []struct {
					SPKI string `json:"spki_sha256"`
				} `json:"published_test_keys"`
				Z4 struct {
					MaxDepth int `json:"max_depth"`
				} `json:"z4_path"`
			} `json:"timestamp_profile"`
		} `json:"verifier"`
	}
	if err := json.Unmarshal(b, &reg); err != nil {
		t.Fatal(err)
	}
	tp := reg.Verifier.TP
	if tp.MaxDER != MaxTokenDER || tp.MaxB64 != MaxTokenB64 || tp.Z4.MaxDepth != MaxPathDepth {
		t.Errorf("limits %d %d %d", tp.MaxDER, tp.MaxB64, tp.Z4.MaxDepth)
	}
	var spki []string
	for _, k := range tp.Keys {
		if k.SPKI != "" {
			spki = append(spki, k.SPKI)
		}
	}
	got := append([]string{}, PublishedTestSPKI...)
	sort.Strings(spki)
	sort.Strings(got)
	if strings.Join(spki, ",") != strings.Join(got, ",") {
		t.Errorf("published_test_keys %v, mirrored %v", spki, got)
	}
	var cases []string
	for _, o := range tp.Outcomes {
		cases = append(cases, o.Case)
	}
	mine := []string{CaseGrammar, CaseImprint, CaseNotPerformable, CaseFailed, CaseZ6Violated, CaseZ6NotCheckable, CaseNoPath, CaseTestKey, "qs_unusable_malformed_or_absent"}
	if strings.Join(cases, ",") != strings.Join(mine, ",") {
		t.Errorf("outcome cases %v, mirrored %v", cases, mine)
	}
	if strings.Join(tp.States, ",") != strings.Join([]string{StateDefective, StateUnconfirmed, StateConfirmed}, ",") {
		t.Errorf("states %v", tp.States)
	}
	if strings.Join(tp.QS.Results, ",") != strings.Join([]string{QSAbsent, QSPresent, QSMalformed, QSUnusable}, ",") {
		t.Errorf("QS results %v", tp.QS.Results)
	}
}
