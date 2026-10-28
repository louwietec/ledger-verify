package tsa

// Z.1 certificates (format spec 7.5.3), applied to every element of
// certificates and to every certificate the auditor supplies.

import (
	"bytes"
	"testing"

	tt "louwietec.com/ledger-verify/verifier/internal/tsa/tsatest"
)

func TestZ1Certificates(t *testing.T) {
	base := probeCert()
	key := rsaKey()
	resign := func(edit func([][]byte) [][]byte) []byte { return tt.Resign(base, key, edit, nil) }
	setField := func(i int, v []byte) func([][]byte) [][]byte {
		return func(f [][]byte) [][]byte { f[i] = v; return f }
	}
	outer := func(edit func([][]byte) [][]byte) []byte {
		e, _ := single(base)
		ch, _ := elements(e.content)
		parts := [][]byte{ch[0].full, ch[1].full, ch[2].full}
		return tt.Seq(edit(parts)...)
	}
	validity := func(nb, na []byte) []byte { return tt.Seq(nb, na) }
	utc := func(s string) []byte { return tt.TLV(0x17, []byte(s)) }
	gen := func(s string) []byte { return tt.TLV(0x18, []byte(s)) }
	ext := func(list ...[]byte) []byte { return tt.TLV(0xa3, tt.Seq(list...)) }
	ekuExt := tt.Seq(tt.OID("2.5.29.37"), []byte{0x01, 0x01, 0xff}, tt.Octets(tt.Seq(tt.OID(tt.TimeStamping))))
	name := func(rdns ...[]byte) []byte { return tt.Seq(rdns...) }
	cn := tt.Set(tt.Seq(tt.OID("2.5.4.3"), tt.TLV(0x0c, []byte("X"))))
	faelle := []struct {
		why string
		der []byte
		ok  bool
	}{
		{"the probe certificate", base, true},
		{"re-signed unchanged", resign(nil), true},
		{"version absent (v1)", resign(func(f [][]byte) [][]byte { return f[1:] }), false},
		{"version 1 (v2)", resign(setField(0, tt.TLV(0xa0, tt.Int(1)))), false},
		{"version not EXPLICIT", resign(setField(0, tt.TLV(0x80, []byte{2}))), false},
		{"serialNumber 0", resign(setField(1, tt.Int(0))), false},
		{"serialNumber negative", resign(setField(1, tt.Int(-5))), false},
		{"serialNumber of 21 octets", resign(setField(1, tt.TLV(0x02, append([]byte{0x00, 0x80}, make([]byte, 19)...)))), true},
		{"serialNumber of 22 octets", resign(setField(1, tt.TLV(0x02, append([]byte{0x01}, make([]byte, 21)...)))), false},
		{"serialNumber not minimal", resign(setField(1, tt.TLV(0x02, []byte{0x00, 0x05}))), false},
		{"inner signature differs from the outer", tt.Resign(base, key, nil, tt.Alg("1.2.840.113549.1.1.11")), false},
		{"issuer with an empty RDN", resign(setField(3, name(tt.Set()))), false},
		{"issuer attribute with three elements", resign(setField(3, name(tt.Set(tt.Seq(tt.OID("2.5.4.3"), tt.Null, tt.Null))))), false},
		{"issuer attribute type not an OID", resign(setField(3, name(tt.Set(tt.Seq(tt.Int(3), tt.Null))))), false},
		{"issuer empty Name", resign(setField(3, name())), true},
		{"issuer value with a high tag number", resign(setField(3, name(cn, tt.Set(tt.Seq(tt.OID("1.2.3"), []byte{0x9f, 0x40, 0x00}))))), true},
		// T.6: the value of a Name attribute is one TLV; only the outer TLV
		// is checked, a constructed form with any content passes Z.1.
		{"issuer value in constructed form", resign(setField(3, name(cn, tt.Set(tt.Seq(tt.OID("2.5.4.3"), tt.TLV(0x2c, []byte{0xff, 0xff})))))), true},
		{"issuer value with a malformed identifier", resign(setField(3, name(cn, tt.Set(tt.Seq(tt.OID("1.2.3"), []byte{0x9f, 0x1e, 0x00}))))), false},
		{"subject not a SEQUENCE", resign(setField(5, tt.Set())), false},
		{"validity GeneralizedTime", resign(setField(4, validity(gen("20200101000000Z"), gen("20450101000000Z")))), true},
		{"validity UTCTime 1950", resign(setField(4, validity(utc("500101000000Z"), utc("491231235959Z")))), true},
		{"validity with a fraction", resign(setField(4, validity(gen("20200101000000.5Z"), gen("20450101000000Z")))), false},
		{"validity UTCTime without Z", resign(setField(4, validity(utc("200101000000+0000"), utc("450101000000Z")))), false},
		{"validity UTCTime without seconds", resign(setField(4, validity(utc("2001010000Z"), utc("450101000000Z")))), false},
		{"validity 31 April", resign(setField(4, validity(utc("200431000000Z"), utc("450101000000Z")))), false},
		{"validity second 60", resign(setField(4, validity(utc("200101000060Z"), utc("450101000000Z")))), false},
		{"validity an OCTET STRING", resign(setField(4, validity(tt.Octets([]byte("200101000000Z")), utc("450101000000Z")))), false},
		{"validity with three times", resign(setField(4, tt.Seq(utc("200101000000Z"), utc("450101000000Z"), utc("450101000000Z")))), false},
		{"subjectPublicKey with an unused bit", resign(func(f [][]byte) [][]byte {
			sp, _ := single(f[6])
			ch, _ := elements(sp.content)
			bits := append([]byte{}, ch[1].content...)
			bits[0] = 1
			f[6] = tt.Seq(ch[0].full, tt.TLV(0x03, bits))
			return f
		}), false},
		{"issuerUniqueID", resign(func(f [][]byte) [][]byte {
			return append(f[:7], append([][]byte{tt.TLV(0x81, []byte{0x00})}, f[7:]...)...)
		}), false},
		{"subjectUniqueID", resign(func(f [][]byte) [][]byte {
			return append(f[:7], append([][]byte{tt.TLV(0x82, []byte{0x00})}, f[7:]...)...)
		}), false},
		{"extensions empty", resign(setField(7, ext())), false},
		{"extensions without EXPLICIT", resign(setField(7, tt.TLV(0xa3, ekuExt))), false},
		{"an extension twice", resign(setField(7, ext(ekuExt, ekuExt))), false},
		{"critical encoded FALSE", resign(setField(7, ext(tt.Seq(tt.OID("2.5.29.37"), []byte{0x01, 0x01, 0x00}, tt.Octets(tt.Seq(tt.OID(tt.TimeStamping))))))), true},
		{"critical 01", resign(setField(7, ext(tt.Seq(tt.OID("2.5.29.37"), []byte{0x01, 0x01, 0x01}, tt.Octets(tt.Seq(tt.OID(tt.TimeStamping))))))), false},
		{"extnValue two TLVs", resign(setField(7, ext(tt.Seq(tt.OID("1.2.3.4"), tt.Octets(append(tt.Null, tt.Null...)))))), false},
		{"extnValue empty", resign(setField(7, ext(tt.Seq(tt.OID("1.2.3.4"), tt.Octets(nil))))), false},
		{"extnValue not DER", resign(setField(7, ext(tt.Seq(tt.OID("1.2.3.4"), tt.Octets([]byte{0x04, 0x81, 0x01, 0x00}))))), false},
		// T.6 (60aa776a): of an extension no rule reads only the outer TLV
		// of extnValue is checked; its content need not be DER.
		{"extnValue of an unread extension with non-DER content", resign(setField(7, ext(tt.Seq(tt.OID("1.2.3.4"), tt.Octets(tt.Seq([]byte{0x02, 0x81, 0x01, 0x05})))))), true},
		{"extnValue of an unread extension with a BOOLEAN 01", resign(setField(7, ext(readExt("1.2.3.4", tt.Seq([]byte{0x01, 0x01, 0x01}))))), true},
		// Z.1: the content of extnValue of basicConstraints, keyUsage,
		// extKeyUsage and subjectKeyIdentifier is DER after T.6 throughout.
		{"basicConstraints cA FF, pathLen 0", resign(setField(7, ext(readExt("2.5.29.19", tt.Seq([]byte{0x01, 0x01, 0xff}, tt.Int(0)))))), true},
		{"basicConstraints cA with the content 01", resign(setField(7, ext(readExt("2.5.29.19", tt.Seq([]byte{0x01, 0x01, 0x01}))))), false},
		{"basicConstraints pathLen not minimal", resign(setField(7, ext(readExt("2.5.29.19", tt.Seq([]byte{0x01, 0x01, 0xff}, []byte{0x02, 0x02, 0x00, 0x05}))))), false},
		{"basicConstraints a primitive SEQUENCE", resign(setField(7, ext(readExt("2.5.29.19", []byte{0x10, 0x00})))), false},
		{"keyUsage a constructed BIT STRING", resign(setField(7, ext(readExt("2.5.29.15", tt.TLV(0x23, tt.TLV(0x03, []byte{0x00, 0x80})))))), false},
		{"keyUsage with a one among the unused bits (not checked, T.6)", resign(setField(7, ext(readExt("2.5.29.15", tt.TLV(0x03, []byte{0x07, 0x81}))))), true},
		{"extKeyUsage purpose not minimal", resign(setField(7, ext(readExt("2.5.29.37", tt.Seq(tt.TLV(0x06, []byte{0x2b, 0x80, 0x01})))))), false},
		{"extKeyUsage a non-minimal INTEGER inside a context tag", resign(setField(7, ext(readExt("2.5.29.37", tt.Seq(tt.TLV(0xa0, []byte{0x02, 0x02, 0xff, 0x80})))))), false},
		{"subjectKeyIdentifier an OCTET STRING", resign(setField(7, ext(readExt("2.5.29.14", tt.Octets([]byte{1, 2, 3}))))), true},
		{"subjectKeyIdentifier a constructed OCTET STRING", resign(setField(7, ext(readExt("2.5.29.14", tt.TLV(0x24, tt.Octets([]byte{1})))))), false},
		{"subjectKeyIdentifier holding the universal tag 0", resign(setField(7, ext(readExt("2.5.29.14", tt.Seq([]byte{0x00, 0x00}))))), false},
		{"an element after the extensions", resign(func(f [][]byte) [][]byte { return append(f, tt.Null) }), false},
		{"signatureValue with an unused bit", outer(func(p [][]byte) [][]byte {
			e, _ := single(p[2])
			b := append([]byte{}, e.content...)
			b[0] = 1
			p[2] = tt.TLV(0x03, b)
			return p
		}), false},
		{"signatureValue an OCTET STRING", outer(func(p [][]byte) [][]byte {
			e, _ := single(p[2])
			p[2] = tt.Octets(e.content[1:])
			return p
		}), false},
		{"a fourth element", outer(func(p [][]byte) [][]byte { return append(p, tt.Null) }), false},
		{"a byte after the certificate", append(append([]byte{}, base...), 0), false},
	}
	for _, f := range faelle {
		_, err := ParseCertificate(f.der)
		if (err == nil) != f.ok {
			t.Errorf("Z.1 %s: err %v, want ok=%v", f.why, err, f.ok)
		}
	}
	// A certificate whose own signature does not hold is still Z.1: Z.1 is a
	// grammar, the signature belongs to Z.4.
	broken := append([]byte{}, base...)
	broken[len(broken)-1] ^= 1
	if _, err := ParseCertificate(broken); err != nil {
		t.Errorf("a certificate with a broken signature fails Z.1: %v", err)
	}
	if !bytes.Equal(cert(t, base).DER, base) {
		t.Error("DER not kept")
	}
}

// readExt is a non-critical Extension with extnID id and extnValue value.
func readExt(id string, value []byte) []byte { return tt.Seq(tt.OID(id), tt.Octets(value)) }

// TestZ1ReadExtensionContent is T.6 throughout one TLV (format spec 7.5.2),
// as Z.1 reads it for the content of extnValue of the extensions a rule
// reads (7.5.3): every header, the form of every universal type, BOOLEAN,
// INTEGER and OID content, a descent into every constructed encoding of any
// class, exactly one element.
func TestZ1ReadExtensionContent(t *testing.T) {
	deep := tt.Null
	for i := 0; i < 1000; i++ {
		deep = tt.Seq(deep)
	}
	for _, f := range []struct {
		why string
		in  []byte
		ok  bool
	}{
		{"an empty SEQUENCE", tt.Seq(), true},
		{"nothing", nil, false},
		{"two elements", append(append([]byte{}, tt.Null...), tt.Null...), false},
		{"a byte after the element", append(tt.Seq(), 0x00), false},
		{"BOOLEAN FF", tt.Seq([]byte{0x01, 0x01, 0xff}), true},
		{"BOOLEAN 01", tt.Seq([]byte{0x01, 0x01, 0x01}), false},
		{"BOOLEAN of two octets", tt.Seq([]byte{0x01, 0x02, 0xff, 0xff}), false},
		{"INTEGER minimal", tt.Seq(tt.Int(-129)), true},
		{"INTEGER not minimal", tt.Seq([]byte{0x02, 0x02, 0x00, 0x05}), false},
		{"INTEGER empty", tt.Seq([]byte{0x02, 0x00}), false},
		{"OID minimal", tt.Seq(tt.OID(tt.TimeStamping)), true},
		{"OID subidentifier not minimal", tt.Seq(tt.TLV(0x06, []byte{0x2b, 0x80, 0x01})), false},
		{"OID cut off", tt.Seq(tt.TLV(0x06, []byte{0x2b, 0x86})), false},
		{"length not minimal inside", tt.Seq([]byte{0x04, 0x81, 0x01, 0x00}), false},
		{"content cut off inside", tt.Seq([]byte{0x04, 0x02, 0x00}), false},
		{"a primitive SEQUENCE", []byte{0x10, 0x00}, false},
		{"a constructed OCTET STRING", tt.TLV(0x24, tt.Octets(nil)), false},
		{"a constructed UTF8String", tt.TLV(0x2c, tt.TLV(0x0c, []byte("x"))), false},
		{"EXTERNAL constructed", tt.TLV(0x28), true},
		{"EXTERNAL primitive", []byte{0x08, 0x00}, false},
		{"the universal tag 0", tt.Seq([]byte{0x00, 0x00}), false},
		{"a universal tag in the high tag number form", tt.Seq([]byte{0x1f, 0x1f, 0x00}), false},
		{"a context tag in the high tag number form", tt.Seq([]byte{0x9f, 0x1f, 0x00}), true},
		{"a PrintableString with any content (not read)", tt.Seq(tt.TLV(0x13, []byte{0xff})), true},
		{"a primitive context tag with any content (not read)", tt.Seq(tt.TLV(0x80, []byte{0x00, 0x01})), true},
		{"a constructed context tag is read", tt.Seq(tt.TLV(0xa0, []byte{0x02, 0x02, 0x00, 0x05})), false},
		{"a constructed application tag is read", tt.Seq(tt.TLV(0x61, []byte{0x01, 0x01, 0x01})), false},
		{"a constructed private tag in the high form is read", tt.Seq([]byte{0xff, 0x1f, 0x03, 0x01, 0x01, 0x01}), false},
		{"a BIT STRING with a one among the unused bits (not checked)", tt.TLV(0x03, []byte{0x07, 0x81}), true},
		{"1000 nested SEQUENCEs", deep, true},
	} {
		if err := derThroughout(f.in); (err == nil) != f.ok {
			t.Errorf("%s: err %v, want ok=%v", f.why, err, f.ok)
		}
	}
}

// TestZ1ReadExtensionsInToken: a certificate of certificates whose
// basicConstraints or extKeyUsage content is not DER violates Z.1, and step
// 5 is then not performable (5a, format spec 7.3), also for a certificate on
// no path. The extensions of the TSTInfo are rule QS's: there only the outer
// TLV of extnValue counts (TestRuleQS).
func TestZ1ReadExtensionsInToken(t *testing.T) {
	base := probeCert()
	key := rsaKey()
	withExt := func(serial int64, x []byte) []byte {
		return tt.Resign(base, key, func(f [][]byte) [][]byte {
			f[1] = tt.Int(serial)
			f[7] = tt.TLV(0xa3, tt.Seq(x))
			return f
		}, nil)
	}
	ts := tt.Seq(tt.OID(tt.TimeStamping))
	tsLong := tt.Seq(tt.TLV(0x06, []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x80, 0x08}))
	eku := func(v []byte) []byte { return tt.Seq(tt.OID("2.5.29.37"), []byte{0x01, 0x01, 0xff}, tt.Octets(v)) }
	for _, f := range []struct {
		why    string
		signer []byte
		extra  []byte
		want   step5
	}{
		{"another certificate, pathLen minimal", base, withExt(7, readExt("2.5.29.19", tt.Seq([]byte{0x01, 0x01, 0xff}, tt.Int(5)))), s5Valid},
		{"another certificate, pathLen not minimal", base, withExt(7, readExt("2.5.29.19", tt.Seq([]byte{0x01, 0x01, 0xff}, []byte{0x02, 0x02, 0x00, 0x05}))), s5NotPerformable},
		{"another certificate, cA 01", base, withExt(7, readExt("2.5.29.19", tt.Seq([]byte{0x01, 0x01, 0x01}))), s5NotPerformable},
		{"the signer, extKeyUsage minimal", withExt(1, eku(ts)), nil, s5Valid},
		{"the signer, extKeyUsage purpose not minimal", withExt(1, eku(tsLong)), nil, s5NotPerformable},
	} {
		carried := [][]byte{f.signer}
		if f.extra != nil {
			carried = append(carried, f.extra)
		}
		der := tt.Token(tt.TokenSpec{Subject: stamped, Key: key, Cert: f.signer, Carried: carried})
		got, sig := step5Of(t, der)
		if got != f.want {
			t.Errorf("Z.1 %s: %s (%s), want %s", f.why, got, sig.Reason, f.want)
			continue
		}
		root := base
		if f.want == s5Valid {
			root = f.signer
		}
		a := assessLog(t, der, root)
		if f.want == s5NotPerformable && (a.State != StateUnconfirmed || a.Case != CaseNotPerformable) {
			t.Errorf("Z.1 %s: day token %s %s, want unconfirmed %s", f.why, a.State, a.Case, CaseNotPerformable)
		}
		if f.want == s5Valid && a.State != StateConfirmed {
			t.Errorf("Z.1 %s: day token %s %s, want confirmed", f.why, a.State, a.Case)
		}
	}
}
