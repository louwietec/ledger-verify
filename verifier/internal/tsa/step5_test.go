package tsa

// Step 5 of format spec 7.3 under the profile: 5a performability (Z.1 for
// every element of certificates, Z.5 signer found exactly once, Z.2
// algorithms and key, key and algorithm fitting), 5b the check itself.

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	tt "louwietec.com/ledger-verify/verifier/internal/tsa/tsatest"
)

type step5 int

const (
	s5NotPerformable step5 = iota
	s5Failed
	s5Valid
)

func (s step5) String() string { return [...]string{"5a not performable", "5b failed", "valid"}[s] }

func step5Of(t *testing.T, der []byte) (step5, Signature) {
	t.Helper()
	tok, err := ParseToken(der)
	if err != nil {
		t.Fatalf("grammar T: %v", err)
	}
	sig := tok.CheckSignature()
	switch {
	case !sig.Performable:
		return s5NotPerformable, sig
	case !sig.Valid:
		return s5Failed, sig
	}
	return s5Valid, sig
}

// TestZ2AlgorithmsHold: every key and signature algorithm of Z.2 gives a
// signature that holds and a path to its authority (format spec 7.5.4).
func TestZ2AlgorithmsHold(t *testing.T) {
	type fall struct {
		why  string
		spec tt.TokenSpec
	}
	ed := edKey("tsa test ed25519")
	edCert := tt.Cert(tt.CertSpec{CN: "Probe TSA Ed25519", Key: ed})
	var faelle []fall
	for _, sig := range []string{"rsa256", "rsa384", "rsa512", "pss256", "pss384", "pss512"} {
		faelle = append(faelle, fall{"RSA " + sig, tt.TokenSpec{Key: rsaKey(), Cert: probeCert(), Sig: sig}})
	}
	for _, d := range []string{tt.SHA256, tt.SHA384, tt.SHA512} {
		faelle = append(faelle, fall{"rsaEncryption with digest " + d, tt.TokenSpec{Key: rsaKey(), Cert: probeCert(), Sig: "rsa-bare", Digest: d}})
	}
	for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		k := ecKey("tsa test ec", c)
		ce := tt.Cert(tt.CertSpec{CN: "Probe TSA " + c.Params().Name, Key: k})
		for _, sig := range []string{"ecdsa256", "ecdsa384", "ecdsa512", "ecdsa-bare"} {
			faelle = append(faelle, fall{c.Params().Name + " " + sig, tt.TokenSpec{Key: k, Cert: ce, Sig: sig}})
		}
	}
	faelle = append(faelle, fall{"Ed25519", tt.TokenSpec{Key: ed, Cert: edCert, Digest: tt.SHA512}})
	faelle = append(faelle, fall{"digest sha384 under sha256WithRSA (hashes need not agree)", tt.TokenSpec{Key: rsaKey(), Cert: probeCert(), Digest: tt.SHA384}})
	for _, f := range faelle {
		f.spec.Subject = stamped
		der := tt.Token(f.spec)
		got, sig := step5Of(t, der)
		if got != s5Valid {
			t.Errorf("%s: %s (%s)", f.why, got, sig.Reason)
			continue
		}
		if a := assessLog(t, der, f.spec.Cert); a.State != StateConfirmed {
			t.Errorf("%s: %s %s %s", f.why, a.State, a.Case, a.Detail)
		}
	}
}

// TestStep5aNotPerformable: every case of the table in format spec 7.3 for
// 5a, and the boundaries of Z.2 (7.5.4).
func TestStep5aNotPerformable(t *testing.T) {
	k1 := tt.Seq(tt.Alg("1.2.840.10045.2.1", tt.OID("1.3.132.0.10")), tt.TLV(0x03, append([]byte{0, 4}, make([]byte, 64)...)))
	brainpool := tt.Seq(tt.Alg("1.2.840.10045.2.1", tt.OID("1.3.36.3.3.2.8.1.1.7")), tt.TLV(0x03, append([]byte{0, 4}, make([]byte, 64)...)))
	small := tt.Seq(tt.Alg(tt.RSAKey, tt.Null), tt.TLV(0x03, append([]byte{0}, tt.Seq(tt.BigInt(oddBits(1024)), tt.Int(65537))...)))
	e3 := tt.Seq(tt.Alg(tt.RSAKey, tt.Null), tt.TLV(0x03, append([]byte{0}, tt.Seq(tt.BigInt(tt.RSA("tsa test rsa").N), tt.Int(3))...)))
	noNull := tt.Seq(tt.Alg(tt.RSAKey), tt.TLV(0x03, append([]byte{0}, tt.Seq(tt.BigInt(tt.RSA("tsa test rsa").N), tt.Int(65537))...)))
	withKey := func(spki []byte) []byte {
		return tt.Cert(tt.CertSpec{CN: "Probe TSA RSA", Key: rsaKey(), SPKI: spki})
	}
	ed := edKey("tsa test ed25519")
	edCert := tt.Cert(tt.CertSpec{CN: "Probe TSA Ed25519", Key: ed})
	faelle := []struct {
		why  string
		edit func(*tt.TokenSpec)
	}{
		{"no signed attributes", func(s *tt.TokenSpec) { s.NoSignedAttrs = true }},
		{"no certificates", func(s *tt.TokenSpec) { s.NoCerts = true }},
		{"empty certificates", func(s *tt.TokenSpec) { s.Carried = [][]byte{} }},
		{"the content of certificates does not split into TLVs (T.2)", func(s *tt.TokenSpec) { s.Carried = [][]byte{s.Cert, {0x30, 0x05, 0x01}} }},
		{"an element of certificates is no certificate", func(s *tt.TokenSpec) { s.Carried = [][]byte{s.Cert, tt.TLV(0xa1, tt.Null)} }},
		{"another element of certificates violates Z.1", func(s *tt.TokenSpec) { s.Carried = [][]byte{s.Cert, tt.Seq(tt.Null)} }},
		{"no certificate matches the signer identifier", func(s *tt.TokenSpec) {
			s.Carried = [][]byte{tt.Cert(tt.CertSpec{CN: "Other", Key: rsaKey()})}
		}},
		{"a subjectKeyIdentifier no certificate carries", func(s *tt.TokenSpec) { s.SID = tt.TLV(0x80, []byte{1, 2, 3}) }},
		{"two certificates match the signer identifier", func(s *tt.TokenSpec) {
			other := tt.Cert(tt.CertSpec{CN: "Probe TSA RSA", Key: edKey("other"), Serial: 1})
			s.Carried = [][]byte{s.Cert, other}
		}},
		{"a sid SEQUENCE that is no IssuerAndSerialNumber", func(s *tt.TokenSpec) { s.SID = tt.Seq(tt.Null) }},
		{"a sid SEQUENCE whose content is not TLVs (T.4)", func(s *tt.TokenSpec) { s.SID = tt.TLV(0x30, []byte{0x02}) }},
		{"digest SHA-1", func(s *tt.TokenSpec) { s.Digest = tt.SHA1 }},
		{"digest MD5", func(s *tt.TokenSpec) { s.Digest = "1.2.840.113549.2.5" }},
		{"digest SHA3-256", func(s *tt.TokenSpec) { s.Digest = tt.SHA3_256 }},
		{"sha1WithRSAEncryption", func(s *tt.TokenSpec) { s.SigAlg = tt.Alg("1.2.840.113549.1.1.5", tt.Null) }},
		{"md5WithRSAEncryption", func(s *tt.TokenSpec) { s.SigAlg = tt.Alg("1.2.840.113549.1.1.4", tt.Null) }},
		{"sha224WithRSAEncryption", func(s *tt.TokenSpec) { s.SigAlg = tt.Alg("1.2.840.113549.1.1.14", tt.Null) }},
		{"sha256WithRSAEncryption with other parameters", func(s *tt.TokenSpec) { s.SigAlg = tt.Alg("1.2.840.113549.1.1.11", tt.Int(0)) }},
		{"rsaEncryption with digest SHA-1", func(s *tt.TokenSpec) { s.Sig, s.Digest = "rsa-bare", tt.SHA1 }},
		{"PSS without parameters", func(s *tt.TokenSpec) { s.Sig, s.SigAlg = "pss256", tt.Alg(tt.RSASSAPSS) }},
		{"PSS with a mask over another hash", func(s *tt.TokenSpec) {
			s.Sig = "pss256"
			s.SigAlg = tt.Alg(tt.RSASSAPSS, tt.Seq(tt.TLV(0xa0, tt.Alg(tt.SHA256)), tt.TLV(0xa1, tt.Alg(tt.MGF1, tt.Alg(tt.SHA512))), tt.TLV(0xa2, tt.Int(32))))
		}},
		{"PSS with salt 20", func(s *tt.TokenSpec) { s.Sig, s.Salt = "pss256", 20 }},
		{"PSS over SHA-1 by default", func(s *tt.TokenSpec) {
			s.Sig = "pss256"
			s.SigAlg = tt.Alg(tt.RSASSAPSS, tt.Seq(tt.TLV(0xa2, tt.Int(32))))
		}},
		{"PSS with trailerField 2", func(s *tt.TokenSpec) {
			s.Sig = "pss256"
			s.SigAlg = tt.Alg(tt.RSASSAPSS, tt.Seq(tt.TLV(0xa0, tt.Alg(tt.SHA256)), tt.TLV(0xa1, tt.Alg(tt.MGF1, tt.Alg(tt.SHA256))), tt.TLV(0xa2, tt.Int(32)), tt.TLV(0xa3, tt.Int(2))))
		}},
		{"a key on secp256k1", func(s *tt.TokenSpec) { s.Cert, s.SigAlg = withKey(k1), tt.Alg("1.2.840.10045.4.3.2") }},
		{"a key on brainpoolP256r1", func(s *tt.TokenSpec) { s.Cert, s.SigAlg = withKey(brainpool), tt.Alg("1.2.840.10045.4.3.2") }},
		{"an RSA key of 1024 bits", func(s *tt.TokenSpec) { s.Cert = withKey(small) }},
		{"an RSA key with exponent 3", func(s *tt.TokenSpec) { s.Cert = withKey(e3) }},
		{"rsaEncryption key without NULL", func(s *tt.TokenSpec) { s.Cert = withKey(noNull) }},
		{"Ed25519 on an RSA key", func(s *tt.TokenSpec) { s.SigAlg = tt.Alg(tt.Ed25519) }},
		{"ECDSA on an RSA key", func(s *tt.TokenSpec) { s.SigAlg = tt.Alg("1.2.840.10045.4.3.2") }},
		{"RSA on an Ed25519 key", func(s *tt.TokenSpec) {
			s.Key, s.Cert, s.Sig, s.SigAlg = ed, edCert, "ed25519", tt.Alg("1.2.840.113549.1.1.11", tt.Null)
		}},
		{"Ed25519 with parameters", func(s *tt.TokenSpec) {
			s.Key, s.Cert, s.Sig, s.SigAlg = ed, edCert, "ed25519", tt.Alg(tt.Ed25519, tt.Null)
		}},
		{"ecdsa-with-SHA256 with NULL", func(s *tt.TokenSpec) {
			k := ecKey("tsa test ec", elliptic.P256())
			s.Key, s.Cert, s.Sig = k, tt.Cert(tt.CertSpec{CN: "Probe EC", Key: k}), "ecdsa256"
			s.SigAlg = tt.Alg("1.2.840.10045.4.3.2", tt.Null)
		}},
	}
	for _, f := range faelle {
		der := probeToken(f.edit)
		got, sig := step5Of(t, der)
		if got != s5NotPerformable {
			t.Errorf("%s: %s, want 5a not performable", f.why, got)
		}
		if sig.Reason == "" {
			t.Errorf("%s: no reason", f.why)
		}
		if a := assessLog(t, der, probeCert()); a.State != StateUnconfirmed || a.Case != CaseNotPerformable {
			t.Errorf("%s: day token %s %s", f.why, a.State, a.Case)
		}
	}
}

// oddBits is an odd number of exactly n bits, a stand-in RSA modulus.
func oddBits(n int) *big.Int {
	x := new(big.Int).Lsh(big.NewInt(1), uint(n-1))
	return x.Add(x, big.NewInt(1))
}

// TestStep5bFails: the cases of 5b (format spec 7.3): contentType not
// id-ct-TSTInfo, messageDigest not the hash of eContent, the signature not
// holding. A token that does not carry its own signature is defective.
func TestStep5bFails(t *testing.T) {
	for why, edit := range map[string]func(*tt.TokenSpec){
		"contentType id-data": func(s *tt.TokenSpec) {
			s.ContentTypeAttr = tt.Seq(tt.OID(tt.ContentType), tt.Set(tt.OID("1.2.840.113549.1.7.1")))
		},
		"messageDigest of other bytes": func(s *tt.TokenSpec) { s.MessageDigest = tt.Digest(tt.SHA256, []byte("x")) },
		"messageDigest of 20 octets":   func(s *tt.TokenSpec) { s.MessageDigest = make([]byte, 20) },
		"signature flipped":            func(s *tt.TokenSpec) { s.Tamper = tt.FlipLast },
		"PSS flipped":                  func(s *tt.TokenSpec) { s.Sig, s.Tamper = "pss384", tt.FlipLast },
		"signature of another key": func(s *tt.TokenSpec) {
			s.Key = tt.RSA("another rsa")
		},
	} {
		der := probeToken(edit)
		got, sig := step5Of(t, der)
		if got != s5Failed {
			t.Errorf("%s: %s (%s), want 5b failed", why, got, sig.Reason)
		}
		if a := assessLog(t, der, probeCert()); a.State != StateDefective || a.Case != CaseFailed {
			t.Errorf("%s: day token %s %s", why, a.State, a.Case)
		}
	}
	// ECDSA r and s are minimal positive INTEGERs below the order.
	k := ecKey("tsa test ec", elliptic.P256())
	ce := tt.Cert(tt.CertSpec{CN: "Probe EC", Key: k})
	order := elliptic.P256().Params().N
	for why, sigVal := range map[string][]byte{
		"r = 0":          tt.Seq(tt.Int(0), tt.Int(1)),
		"r = order":      tt.Seq(tt.BigInt(order), tt.Int(1)),
		"trailing octet": append(tt.Seq(tt.Int(1), tt.Int(1)), 0),
	} {
		der := tt.Token(tt.TokenSpec{Subject: stamped, Key: k, Cert: ce, Tamper: func(b []byte) []byte { return b }})
		tok, err := ParseToken(der)
		if err != nil {
			t.Fatal(err)
		}
		tok.signature = sigVal
		if s := tok.CheckSignature(); !s.Performable || s.Valid {
			t.Errorf("ECDSA %s: %+v", why, s)
		}
	}
}

// TestZ5SubjectKeyIdentifier: a [0] sid matches the content of the
// subjectKeyIdentifier extension of the signer (format spec 7.5.5, Z.5).
func TestZ5SubjectKeyIdentifier(t *testing.T) {
	ski := []byte{0xde, 0xad, 0xbe, 0xef}
	c := tt.Cert(tt.CertSpec{CN: "Probe TSA SKI", Key: rsaKey(), SubjectKeyID: ski})
	der := tt.Token(tt.TokenSpec{Subject: stamped, Key: rsaKey(), Cert: c, SID: tt.TLV(0x80, ski), SIVersion: 3})
	if got, sig := step5Of(t, der); got != s5Valid {
		t.Fatalf("%s (%s)", got, sig.Reason)
	}
	// Equal bytes count once: the signer twice in certificates is one match.
	der = tt.Token(tt.TokenSpec{Subject: stamped, Key: rsaKey(), Cert: c, Carried: [][]byte{c, c}})
	if got, sig := step5Of(t, der); got != s5Valid {
		t.Fatalf("signer twice: %s (%s)", got, sig.Reason)
	}
	// The serial is compared as a value: a sid with a non-minimal INTEGER is
	// grammatical in T (only the SEQUENCE is read there) and matches nothing.
	name, _ := tt.Issuer(c)
	der = tt.Token(tt.TokenSpec{Subject: stamped, Key: rsaKey(), Cert: c, SID: tt.Seq(name, []byte{0x02, 0x02, 0x00, 0x01})})
	if got, _ := step5Of(t, der); got != s5NotPerformable {
		t.Errorf("non-minimal serial in sid: %s", got)
	}
}
