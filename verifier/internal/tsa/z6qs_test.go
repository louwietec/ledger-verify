package tsa

// Z.6 the binding of the signer certificate and rule QS (format spec 7.5.6).

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	tt "louwietec.com/ledger-verify/verifier/internal/tsa/tsatest"
)

func essV1(certHash []byte, extra ...[]byte) []byte {
	id := tt.Seq(append([][]byte{tt.Octets(certHash)}, extra...)...)
	return tt.Seq(tt.OID(tt.SigningCert), tt.Set(tt.Seq(tt.Seq(id))))
}

func essV2(ids ...[]byte) []byte {
	return tt.Seq(tt.OID(tt.SigningCert2), tt.Set(tt.Seq(tt.Seq(ids...))))
}

func essIDv2(alg []byte, certHash []byte, issuerSerial []byte) []byte {
	return tt.Seq(alg, tt.Octets(certHash), issuerSerial)
}

func TestZ6Binding(t *testing.T) {
	c := probeCert()
	h1 := sha1.Sum(c)
	h256 := sha256.Sum256(c)
	h384 := sha512.Sum384(c)
	h512 := sha512.Sum512(c)
	name, serial := tt.Issuer(c)
	is := tt.Seq(tt.Seq(tt.TLV(0xa4, name)), tt.BigInt(serial))
	isWrongSerial := tt.Seq(tt.Seq(tt.TLV(0xa4, name)), tt.Int(99))
	isWrongName := tt.Seq(tt.Seq(tt.TLV(0xa4, tt.Seq())), tt.BigInt(serial))
	isOtherFirst := tt.Seq(tt.Seq(tt.TLV(0x86, []byte("uri")), tt.TLV(0xa4, name)), tt.BigInt(serial))
	gn := func(names ...[]byte) []byte { return tt.Seq(tt.Seq(names...), tt.BigInt(serial)) } // IssuerSerial over GeneralNames names
	sha3 := tt.Digest(tt.SHA3_256, c)
	for _, f := range []struct {
		why  string
		edit func(*tt.TokenSpec)
		want string
	}{
		{"v2, hash absent (SHA-256)", nil, Z6Bound},
		{"v1", func(s *tt.TokenSpec) { s.ESS = "v1" }, Z6Bound},
		{"v1 and v2", func(s *tt.TokenSpec) { s.Attrs = [][]byte{essV1(h1[:])} }, Z6Bound},
		{"none", func(s *tt.TokenSpec) { s.ESS = "none" }, Z6Violated},
		{"v2 with SHA-256 encoded (DEFAULT)", func(s *tt.TokenSpec) { s.ESSAttr = essV2(essIDv2(tt.Alg(tt.SHA256), h256[:], nil)) }, Z6Bound},
		{"v2 with SHA-384", func(s *tt.TokenSpec) { s.ESSAttr = essV2(essIDv2(tt.Alg(tt.SHA384), h384[:], nil)) }, Z6Bound},
		{"v2 with SHA-512 and NULL", func(s *tt.TokenSpec) { s.ESSAttr = essV2(essIDv2(tt.Alg(tt.SHA512, tt.Null), h512[:], nil)) }, Z6Bound},
		{"v2 with SHA-1 (not compared)", func(s *tt.TokenSpec) { s.ESSAttr = essV2(essIDv2(tt.Alg(tt.SHA1), h1[:], nil)) }, Z6NotCheckable},
		{"v2 with SHA3-256 (not compared)", func(s *tt.TokenSpec) { s.ESSAttr = essV2(essIDv2(tt.Alg(tt.SHA3_256), sha3, nil)) }, Z6NotCheckable},
		{"v2 not compared, v1 bound", func(s *tt.TokenSpec) {
			s.ESSAttr, s.Attrs = essV2(essIDv2(tt.Alg(tt.SHA3_256), []byte{1}, nil)), [][]byte{essV1(h1[:])}
		}, Z6NotCheckable},
		{"v2 not compared, v1 wrong", func(s *tt.TokenSpec) {
			s.ESSAttr, s.Attrs = essV2(essIDv2(tt.Alg(tt.SHA3_256), []byte{1}, nil)), [][]byte{essV1(make([]byte, 20))}
		}, Z6Violated},
		{"v2 not compared, issuerSerial wrong", func(s *tt.TokenSpec) {
			s.ESSAttr = essV2(essIDv2(tt.Alg(tt.SHA3_256), []byte{1}, isWrongSerial))
		}, Z6Violated},
		{"v2 wrong certHash", func(s *tt.TokenSpec) { s.ESSAttr = essV2(essIDv2(nil, make([]byte, 32), nil)) }, Z6Violated},
		{"v1 wrong certHash", func(s *tt.TokenSpec) { s.ESSAttr = essV1(make([]byte, 20)) }, Z6Violated},
		{"v1 twice", func(s *tt.TokenSpec) { s.ESS, s.Attrs = "v1", [][]byte{essV1(h1[:])} }, Z6Violated},
		{"v2 with two values", func(s *tt.TokenSpec) {
			v := tt.Seq(tt.Seq(tt.Seq(tt.Octets(h256[:]))))
			s.ESSAttr = tt.Seq(tt.OID(tt.SigningCert2), tt.Set(v, v))
		}, Z6Violated},
		{"v2 with empty certs", func(s *tt.TokenSpec) { s.ESSAttr = essV2() }, Z6Violated},
		{"v2 value not DER", func(s *tt.TokenSpec) {
			s.ESSAttr = tt.Seq(tt.OID(tt.SigningCert2), tt.Set(tt.TLV(0x30, []byte{0x30, 0x81, 0x00})))
		}, Z6Violated},
		{"v2 with a malformed second ESSCertIDv2", func(s *tt.TokenSpec) {
			s.ESSAttr = essV2(essIDv2(nil, h256[:], nil), tt.Seq(tt.Int(1)))
		}, Z6Violated},
		{"v2, the second ESSCertIDv2 names another certificate", func(s *tt.TokenSpec) {
			s.ESSAttr = essV2(essIDv2(nil, h256[:], nil), essIDv2(nil, make([]byte, 32), nil))
		}, Z6Bound},
		{"v2 with policies", func(s *tt.TokenSpec) {
			s.ESSAttr = tt.Seq(tt.OID(tt.SigningCert2), tt.Set(tt.Seq(tt.Seq(essIDv2(nil, h256[:], nil)), tt.Seq(tt.Seq(tt.OID("1.2.3"))))))
		}, Z6Bound},
		{"v2 with issuerSerial", func(s *tt.TokenSpec) { s.ESSAttr = essV2(essIDv2(nil, h256[:], is)) }, Z6Bound},
		{"v2 with issuerSerial, directoryName second", func(s *tt.TokenSpec) { s.ESSAttr = essV2(essIDv2(nil, h256[:], isOtherFirst)) }, Z6Bound},
		{"v2 with issuerSerial of another serial", func(s *tt.TokenSpec) { s.ESSAttr = essV2(essIDv2(nil, h256[:], isWrongSerial)) }, Z6Violated},
		{"v2 with issuerSerial of another name", func(s *tt.TokenSpec) { s.ESSAttr = essV2(essIDv2(nil, h256[:], isWrongName)) }, Z6Violated},
		{"v1 with issuerSerial", func(s *tt.TokenSpec) { s.ESSAttr = essV1(h1[:], is) }, Z6Bound},
		// Z.6: every directoryName A4 of GeneralNames holds exactly one Name
		// after Z.1, in the issuerSerial of every element of certs; of every
		// other element only the outer TLV is checked, and a [4] elsewhere is
		// no directoryName.
		{"v2, a directoryName holding no Name before the right one", func(s *tt.TokenSpec) {
			s.ESSAttr = essV2(essIDv2(nil, h256[:], gn(tt.TLV(0xa4, tt.Octets([]byte("kein Name"))), tt.TLV(0xa4, name))))
		}, Z6Violated},
		{"v2, a directoryName holding two Names", func(s *tt.TokenSpec) {
			s.ESSAttr = essV2(essIDv2(nil, h256[:], gn(tt.TLV(0xa4, name, name))))
		}, Z6Violated},
		{"v2, a directoryName holding a SET", func(s *tt.TokenSpec) {
			s.ESSAttr = essV2(essIDv2(nil, h256[:], gn(tt.TLV(0xa4, tt.Set()), tt.TLV(0xa4, name))))
		}, Z6Violated},
		{"v2, a directoryName holding a Name with an empty RDN", func(s *tt.TokenSpec) {
			s.ESSAttr = essV2(essIDv2(nil, h256[:], gn(tt.TLV(0xa4, name), tt.TLV(0xa4, tt.Seq(tt.Set())))))
		}, Z6Violated},
		{"v2, an empty directoryName", func(s *tt.TokenSpec) {
			s.ESSAttr = essV2(essIDv2(nil, h256[:], gn(tt.TLV(0xa4), tt.TLV(0xa4, name))))
		}, Z6Violated},
		{"v2, the second ESSCertIDv2 with a directoryName holding no Name", func(s *tt.TokenSpec) {
			s.ESSAttr = essV2(essIDv2(nil, h256[:], nil), essIDv2(nil, make([]byte, 32), gn(tt.TLV(0xa4, tt.Octets([]byte("kein Name"))))))
		}, Z6Violated},
		{"v1, a directoryName holding no Name before the right one", func(s *tt.TokenSpec) {
			s.ESSAttr = essV1(h1[:], gn(tt.TLV(0xa4, tt.Null), tt.TLV(0xa4, name)))
		}, Z6Violated},
		{"v2, a directoryName with a constructed attribute value (one TLV)", func(s *tt.TokenSpec) {
			other := tt.Seq(tt.Set(tt.Seq(tt.OID("2.5.4.3"), tt.TLV(0x2c, []byte{0xff, 0xff}))))
			s.ESSAttr = essV2(essIDv2(nil, h256[:], gn(tt.TLV(0xa4, other), tt.TLV(0xa4, name))))
		}, Z6Bound},
		{"v2, a [4] inside an otherName is no directoryName", func(s *tt.TokenSpec) {
			on := tt.TLV(0xa0, tt.OID("1.2.3.4"), tt.TLV(0xa0, tt.TLV(0xa4, tt.Octets([]byte("x")))))
			s.ESSAttr = essV2(essIDv2(nil, h256[:], gn(on, tt.TLV(0xa4, name))))
		}, Z6Bound},
		{"v2, an otherName with content not DER (outer TLV only)", func(s *tt.TokenSpec) {
			on := tt.TLV(0xa0, tt.OID("1.2.3.4"), tt.TLV(0xa0, []byte{0x02, 0x02, 0x00, 0x01}))
			s.ESSAttr = essV2(essIDv2(nil, h256[:], gn(on, tt.TLV(0xa4, name))))
		}, Z6Bound},
		{"v2, a primitive [4] is no directoryName", func(s *tt.TokenSpec) {
			s.ESSAttr = essV2(essIDv2(nil, h256[:], gn(tt.TLV(0x84, []byte{0x01}), tt.TLV(0xa4, name))))
		}, Z6Bound},
		{"v2, policies holding a [4] without a Name (outer TLV only)", func(s *tt.TokenSpec) {
			pol := tt.Seq(tt.TLV(0xa4, tt.Octets([]byte("x"))))
			s.ESSAttr = tt.Seq(tt.OID(tt.SigningCert2), tt.Set(tt.Seq(tt.Seq(essIDv2(nil, h256[:], is)), pol)))
		}, Z6Bound},
		{"v2, policies with content not DER (outer TLV only)", func(s *tt.TokenSpec) {
			pol := tt.Seq([]byte{0x02, 0x02, 0x00, 0x01})
			s.ESSAttr = tt.Seq(tt.OID(tt.SigningCert2), tt.Set(tt.Seq(tt.Seq(essIDv2(nil, h256[:], nil)), pol)))
		}, Z6Bound},
	} {
		der := probeToken(f.edit)
		tok, err := ParseToken(der)
		if err != nil {
			t.Fatalf("%s: grammar T: %v", f.why, err)
		}
		sig := tok.CheckSignature()
		if !sig.Valid {
			t.Fatalf("%s: step 5: %s", f.why, sig.Reason)
		}
		got, why := tok.Z6(sig.Signer)
		if got != f.want {
			t.Errorf("Z.6 %s: %s (%s), want %s", f.why, got, why, f.want)
		}
		// 7.5.7: Z.6 decides a day time stamp. The helper mode takes the
		// topmost row for roots of either purpose (spec/testvectors/README
		// 10.4); that Z.6 never changes the finding of a TIME_ANCHOR in a
		// chain is shown by the vectors timestamp_ess_* (package vfy).
		day := assessLog(t, der, c)
		chain := Assess(der, stamped, certs(t, c), PurposeChain)
		wantDay := map[string]string{Z6Bound: StateConfirmed, Z6Violated: StateDefective, Z6NotCheckable: StateUnconfirmed}[f.want]
		if day.State != wantDay || chain.State != wantDay || chain.Case != day.Case {
			t.Errorf("Z.6 %s: day %s %s, chain %s %s", f.why, day.State, day.Case, chain.State, chain.Case)
		}
	}
}

func TestRuleQS(t *testing.T) {
	ext := func(id string, crit []byte, value []byte) []byte { return tt.Seq(tt.OID(id), crit, tt.Octets(value)) }
	stmts := func(s ...[]byte) []byte { return tt.Seq(s...) }
	qc := func(crit []byte, s ...[]byte) []byte { return ext(tt.QCStatements, crit, stmts(s...)) }
	qtst := tt.Seq(tt.OID(tt.QTST))
	other := tt.Seq(tt.OID("0.4.0.1862.1.1"))
	ff, zero, one := []byte{0x01, 0x01, 0xff}, []byte{0x01, 0x01, 0x00}, []byte{0x01, 0x01, 0x01}
	for _, f := range []struct {
		why  string
		edit func(*tt.TokenSpec)
		want string
	}{
		{"no [1]: absent", nil, QSAbsent},
		{"the statement", func(s *tt.TokenSpec) { s.Exts = [][]byte{qc(nil, qtst)} }, QSPresent},
		{"another statement only", func(s *tt.TokenSpec) { s.Exts = [][]byte{qc(nil, other)} }, QSAbsent},
		{"both statements", func(s *tt.TokenSpec) { s.Exts = [][]byte{qc(nil, other, qtst)} }, QSPresent},
		{"statement with statementInfo", func(s *tt.TokenSpec) { s.Exts = [][]byte{qc(nil, tt.Seq(tt.OID(tt.QTST), tt.Seq()))} }, QSPresent},
		{"qcStatements marked critical", func(s *tt.TokenSpec) { s.Exts = [][]byte{qc(ff, qtst)} }, QSPresent},
		{"qcStatements with an encoded FALSE", func(s *tt.TokenSpec) { s.Exts = [][]byte{qc(zero, qtst)} }, QSPresent},
		{"an empty SEQUENCE OF QCStatement", func(s *tt.TokenSpec) { s.Exts = [][]byte{qc(nil)} }, QSAbsent},
		{"no qcStatements, another extension", func(s *tt.TokenSpec) { s.Exts = [][]byte{ext("1.2.3.4", nil, tt.Null)} }, QSAbsent},
		{"another extension marked critical", func(s *tt.TokenSpec) { s.Exts = [][]byte{ext("1.2.3.4", ff, tt.Null), qc(nil, qtst)} }, QSUnusable},
		{"another extension, not critical, and the statement", func(s *tt.TokenSpec) { s.Exts = [][]byte{ext("1.2.3.4", zero, tt.Null), qc(nil, qtst)} }, QSPresent},
		{"an empty [1]", func(s *tt.TokenSpec) { s.ExtsRaw = tt.TLV(0xa1) }, QSUnusable},
		{"[1] content not an Extension", func(s *tt.TokenSpec) { s.ExtsRaw = tt.TLV(0xa1, []byte{0xff}) }, QSUnusable},
		{"[1] holding a NULL", func(s *tt.TokenSpec) { s.ExtsRaw = tt.TLV(0xa1, tt.Null) }, QSUnusable},
		{"qcStatements twice", func(s *tt.TokenSpec) { s.Exts = [][]byte{qc(nil, qtst), qc(nil, qtst)} }, QSUnusable},
		{"critical with content 01", func(s *tt.TokenSpec) { s.Exts = [][]byte{qc(one, qtst)} }, QSUnusable},
		{"extnValue two TLVs", func(s *tt.TokenSpec) { s.Exts = [][]byte{ext(tt.QCStatements, nil, append(stmts(qtst), tt.Null...))} }, QSUnusable},
		{"extnValue not DER", func(s *tt.TokenSpec) {
			s.Exts = [][]byte{ext(tt.QCStatements, nil, []byte{0x30, 0x81, 0x02, 0x05, 0x00})}
		}, QSUnusable},
		{"extnValue a SET", func(s *tt.TokenSpec) { s.Exts = [][]byte{ext(tt.QCStatements, nil, tt.Set(qtst))} }, QSMalformed},
		{"a QCStatement of three elements", func(s *tt.TokenSpec) {
			s.Exts = [][]byte{qc(nil, tt.Seq(tt.OID(tt.QTST), tt.Null, tt.Null))}
		}, QSMalformed},
		{"a statementId not an OID", func(s *tt.TokenSpec) { s.Exts = [][]byte{qc(nil, tt.Seq(tt.Int(1)))} }, QSMalformed},
		{"a QCStatement not a SEQUENCE", func(s *tt.TokenSpec) { s.Exts = [][]byte{qc(nil, tt.OID(tt.QTST))} }, QSMalformed},
		// Z.1 reads the content of basicConstraints only in a certificate;
		// among the TSTInfo extensions only its outer TLV counts (QS item 2).
		{"basicConstraints with content not DER (outer TLV only)", func(s *tt.TokenSpec) {
			s.Exts = [][]byte{ext("2.5.29.19", nil, tt.Seq([]byte{0x01, 0x01, 0x01}, []byte{0x02, 0x02, 0x00, 0x05})), qc(nil, qtst)}
		}, QSPresent},
		{"the nine bytes in the nonce (no byte search)", func(s *tt.TokenSpec) {
			s.TSTOptional = [][]byte{tt.TLV(0x02, []byte{0x06, 0x07, 0x04, 0x00, 0x81, 0x97, 0x5e, 0x01, 0x01})}
		}, QSAbsent},
	} {
		der := probeToken(f.edit)
		tok, err := ParseToken(der)
		if err != nil {
			t.Fatalf("%s: grammar T: %v", f.why, err)
		}
		if got := tok.QualifiedStatement(); got != f.want {
			t.Errorf("QS %s: %s, want %s", f.why, got, f.want)
		}
		// QS never decides a state (7.5.7).
		if a := assessLog(t, der, probeCert()); a.State != StateConfirmed || a.QS != f.want {
			t.Errorf("QS %s: day token %s %s, QS %s", f.why, a.State, a.Case, a.QS)
		}
	}
}
