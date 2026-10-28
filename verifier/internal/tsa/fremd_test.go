package tsa

// Tokens from foreign hands (format spec 7.5): the OpenSSL fixtures of
// testdata/erzeugen.sh and the token of the frozen vector valid_time_anchor.
// A parser written by hand from the rules must read what other
// implementations write, not only what its own test writer produces.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func laden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("testdata/%s: %v", name, err)
	}
	return b
}

func pemRoots(t *testing.T, b []byte) []*Certificate {
	t.Helper()
	r, err := ParsePEMRoots(b)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestOpenSSLTokenConfirmed: spec 7.5.7, an OpenSSL token (RSA 2048,
// sha256WithRSAEncryption, signingCertificateV2, accuracy, ordering and
// tsa present) is confirmed against its own authority and only against it.
func TestOpenSSLTokenConfirmed(t *testing.T) {
	der := laden(t, "openssl_token.der")
	data := laden(t, "openssl_data.bin")
	own := pemRoots(t, laden(t, "openssl_tsa.crt"))
	foreign := pemRoots(t, laden(t, "fremd_tsa.crt"))
	for _, purpose := range []string{PurposeLog, PurposeChain} {
		a := Assess(der, data, own, purpose)
		if a.State != StateConfirmed {
			t.Errorf("%s: %s %s (%s)", purpose, a.State, a.Case, a.Detail)
		}
		if a.Z6 != Z6Bound || a.QS != QSAbsent {
			t.Errorf("%s: Z.6 %s, QS %s", purpose, a.Z6, a.QS)
		}
		if b := Assess(der, data, foreign, purpose); b.State != StateUnconfirmed || b.Case != CaseNoPath {
			t.Errorf("%s with a foreign root: %s %s", purpose, b.State, b.Case)
		}
		if b := Assess(der, []byte("other bytes"), own, purpose); b.State != StateDefective || b.Case != CaseImprint {
			t.Errorf("%s over other bytes: %s %s", purpose, b.State, b.Case)
		}
	}
	tok, err := ParseToken(der)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(data)
	if tok.HashAlgorithm != "sha256" || string(tok.HashedMessage) != string(want[:]) || tok.Policy != "1.2.3.4.1" {
		t.Errorf("readings: %s %x %s", tok.HashAlgorithm, tok.HashedMessage, tok.Policy)
	}
}

// TestCorpusTokenTestKey: the token of valid_time_anchor chains to the test
// authority of the corpus, whose SPKI registry published_test_keys names; a
// day time stamp under it is not confirmed (7.5.7), a time witness has a
// path (no effect on the exit code).
func TestCorpusTokenTestKey(t *testing.T) {
	root := filepath.Join("..", "..", "..", "spec", "testvectors", "valid_time_anchor")
	pemB, err := os.ReadFile(filepath.Join(root, "keys", "tsa", "probestelle.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := pemRoots(t, pemB)
	if !IsPublishedTestKey(roots[0]) {
		t.Fatal("the corpus authority is not recognized as a published test key")
	}
	seg, err := os.ReadFile(filepath.Join(root, "segments", "chain-000001.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var der []byte
	for _, l := range strings.Split(string(seg), "\n") {
		if strings.Contains(l, `"TIME_ANCHOR"`) {
			var e struct {
				Payload struct {
					Token string `json:"token_base64"`
				} `json:"payload"`
			}
			if err := json.Unmarshal([]byte(l), &e); err != nil {
				t.Fatal(err)
			}
			if der, err = base64.StdEncoding.DecodeString(e.Payload.Token); err != nil {
				t.Fatal(err)
			}
		}
	}
	tok, err := ParseToken(der)
	if err != nil {
		t.Fatalf("grammar T: %v", err)
	}
	sig := tok.CheckSignature()
	if !sig.Performable || !sig.Valid {
		t.Fatalf("step 5: %+v", sig)
	}
	if !tok.PathExists(sig, roots[0]) {
		t.Fatal("no path to the corpus authority")
	}
	if tok.GenTimeMillis() != "2026-01-01T00:40:01.000Z" || tok.SerialHex() != "2a" {
		t.Errorf("readings %s %s", tok.GenTimeMillis(), tok.SerialHex())
	}
	a := Assess(der, nil, roots, PurposeLog)
	if a.State != StateDefective || a.Case != CaseImprint {
		t.Errorf("log over nil: %s %s", a.State, a.Case)
	}
}

// TestFlippedBytes: no single flipped byte of the OpenSSL token leaves it
// confirmed against its authority (format spec 7.5). A byte that survived
// would be a second encoding carrying the same statement.
func TestFlippedBytes(t *testing.T) {
	der := laden(t, "openssl_token.der")
	data := laden(t, "openssl_data.bin")
	roots := pemRoots(t, laden(t, "openssl_tsa.crt"))
	var survived []int
	for i := range der {
		flipped := append([]byte{}, der...)
		flipped[i] ^= 0xff
		if a := Assess(flipped, data, roots, PurposeLog); a.State == StateConfirmed {
			survived = append(survived, i)
		}
	}
	if len(survived) != 0 {
		t.Errorf("%d of %d flipped bytes stay confirmed: %v", len(survived), len(der), survived)
	}
}
