package mldsa

// Known-answer tests from the NIST ACVP ML-DSA sigVer vectors (FIPS 204),
// reduced subset in testdata/acvp_sigver.json; source and selection in
// testdata/README.md.

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type acvpFile struct {
	Algorithm  string      `json:"algorithm"`
	Mode       string      `json:"mode"`
	Revision   string      `json:"revision"`
	TestGroups []acvpGroup `json:"testGroups"`
}

type acvpGroup struct {
	TgID               int        `json:"tgId"`
	ParameterSet       string     `json:"parameterSet"`
	SignatureInterface string     `json:"signatureInterface"`
	PreHash            string     `json:"preHash"`
	ExternalMu         bool       `json:"externalMu"`
	Tests              []acvpCase `json:"tests"`
}

type acvpCase struct {
	TcID       int    `json:"tcId"`
	TestPassed bool   `json:"testPassed"`
	Reason     string `json:"reason"`
	PK         hexStr `json:"pk"`
	Message    hexStr `json:"message"`
	Mu         hexStr `json:"mu"`
	Context    hexStr `json:"context"`
	Signature  hexStr `json:"signature"`
}

type hexStr []byte

func (h *hexStr) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	*h = v
	return nil
}

func paramsByName(name string) *Params {
	for _, p := range []*Params{MLDSA44, MLDSA65, MLDSA87} {
		if p.Name() == name {
			return p
		}
	}
	return nil
}

func TestACVPSigVer(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "acvp_sigver.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f acvpFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Algorithm != "ML-DSA" || f.Mode != "sigVer" || f.Revision != "FIPS204" {
		t.Fatalf("unexpected file header %s/%s/%s", f.Algorithm, f.Mode, f.Revision)
	}
	total := 0
	for _, g := range f.TestGroups {
		p := paramsByName(g.ParameterSet)
		if p == nil {
			t.Fatalf("tgId %d: unknown parameter set %q", g.TgID, g.ParameterSet)
		}
		if g.PreHash == "preHash" {
			t.Fatalf("tgId %d: pre-hash groups are not supported and must not be selected", g.TgID)
		}
		pass, fail := 0, 0
		for _, c := range g.Tests {
			var got outcome
			switch {
			case g.SignatureInterface == "external":
				got = verify(p, c.PK, c.Message, c.Context, c.Signature)
				// The public API must agree with the internal outcome.
				if Verify(p, c.PK, c.Message, c.Context, c.Signature) != (got == valid) {
					t.Errorf("tcId %d: Verify and verify disagree", c.TcID)
				}
			case g.ExternalMu:
				got = verifyInternal(p, c.PK, c.Signature, c.Mu)
			default:
				got = verifyInternal(p, c.PK, c.Signature, nil, c.Message)
			}
			if (got == valid) != c.TestPassed {
				t.Errorf("tgId %d tcId %d (%s): outcome %d, expected testPassed=%v",
					g.TgID, c.TcID, c.Reason, got, c.TestPassed)
				continue
			}
			if c.TestPassed {
				pass++
			} else {
				fail++
			}
		}
		total += len(g.Tests)
		t.Logf("tgId %2d %s %-8s externalMu=%-5v: %d cases, %d valid and %d invalid as expected",
			g.TgID, g.ParameterSet, g.SignatureInterface, g.ExternalMu, len(g.Tests), pass, fail)
	}
	if total == 0 {
		t.Fatal("no sigVer cases")
	}
}
