package tsa

import (
	"crypto"
	"crypto/elliptic"
	"testing"

	"louwietec.com/ledger-verify/verifier/internal/tsa/tsatest"
)

// stamped are the bytes every test token stamps.
var stamped = []byte("subject")

func rsaKey() crypto.Signer { return tsatest.RSA("tsa test rsa") }

// probeCert is the self-signed RSA authority most tests use.
func probeCert() []byte {
	return tsatest.Cert(tsatest.CertSpec{CN: "Probe TSA RSA", Key: rsaKey()})
}

// probeToken writes a token of the probe authority; edit changes the spec.
func probeToken(edit func(*tsatest.TokenSpec)) []byte {
	s := tsatest.TokenSpec{Subject: stamped, Key: rsaKey(), Cert: probeCert()}
	if edit != nil {
		edit(&s)
	}
	return tsatest.Token(s)
}

func cert(t *testing.T, der []byte) *Certificate {
	t.Helper()
	c, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	return c
}

func certs(t *testing.T, ders ...[]byte) []*Certificate {
	t.Helper()
	var out []*Certificate
	for _, d := range ders {
		out = append(out, cert(t, d))
	}
	return out
}

// assessLog judges der over stamped as a day time stamp against roots.
func assessLog(t *testing.T, der []byte, roots ...[]byte) Assessment {
	t.Helper()
	return Assess(der, stamped, certs(t, roots...), PurposeLog)
}

func ecKey(label string, c elliptic.Curve) crypto.Signer { return tsatest.EC(label, c) }

func edKey(label string) crypto.Signer { return tsatest.Ed25519Key(label) }
