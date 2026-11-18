package tsa

// Grammar B64 (format spec 2, 7.5.1), strict DER (T.6) and grammar T (T.1 to
// T.5, format spec 7.5.2): what step 2 of 7.3 refuses (TIME_ANCHOR_INVALID,
// a defective day time stamp) and what it lets through.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	tt "louwietec.com/ledger-verify/verifier/internal/tsa/tsatest"
)

// TestB64Grammar is grammar B64 of format spec 2.
func TestB64Grammar(t *testing.T) {
	for _, f := range []struct {
		in string
		ok bool
	}{
		{"", true},
		{"QQ==", true},
		{"QUI=", true},
		{"QUJD", true},
		{"QR==", true}, // unused bits are not checked
		{"QQ", false},
		{"QQ=", false},
		{"Q===", false},
		{"QQ==QUJD", false},
		{"QU=D", false},
		{"QUJD\n", false},
		{"QU\r\nJD", false},
		{"QU JD", false},
		{"QUJ-", false},
		{"QUJ_", false},
		{"QUJDé", false},
	} {
		_, err := DecodeB64(f.in)
		if (err == nil) != f.ok {
			t.Errorf("B64 %q: err %v, want ok=%v", f.in, err, f.ok)
		}
	}
}

// TestT6Elements is T.6 on single elements: minimal definite lengths,
// minimal INTEGER, BOOLEAN 00/FF, minimal OID subidentifiers, BIT STRING.
func TestT6Elements(t *testing.T) {
	for _, f := range []struct {
		why string
		in  []byte
		ok  bool
	}{
		{"short form", []byte{0x04, 0x01, 0xaa}, true},
		{"indefinite length", []byte{0x30, 0x80, 0x00, 0x00}, false},
		{"long form below 128", []byte{0x04, 0x81, 0x01, 0xaa}, false},
		{"leading zero length octet", append([]byte{0x04, 0x82, 0x00, 0x81}, make([]byte, 0x81)...), false},
		{"long form 129", append([]byte{0x04, 0x81, 0x81}, make([]byte, 0x81)...), true},
		{"five length octets", []byte{0x04, 0x85, 0, 0, 0, 0, 1, 0}, false},
		{"content cut off", []byte{0x04, 0x03, 0xaa}, false},
		{"high tag number 31", []byte{0x9f, 0x1f, 0x00}, true},
		{"high tag form for 30", []byte{0x9f, 0x1e, 0x00}, false},
		{"high tag with leading 0x80", []byte{0x9f, 0x80, 0x1f, 0x00}, false},
		// X.690 8.1.2.4 sets no upper bound on the tag number.
		{"high tag number 2^32", []byte{0x9f, 0x90, 0x80, 0x80, 0x80, 0x00, 0x00}, true},
		{"high tag number 2^70", []byte{0x9f, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00, 0x00}, true},
		{"high tag cut off", []byte{0x9f, 0x81, 0x80}, false},
		{"missing length", []byte{0x04}, false},
	} {
		_, err := single(f.in)
		if (err == nil) != f.ok {
			t.Errorf("%s: err %v, want ok=%v", f.why, err, f.ok)
		}
	}
	ints := []struct {
		in []byte
		ok bool
	}{
		{[]byte{0x00}, true}, {[]byte{0x7f}, true}, {[]byte{0x00, 0x80}, true}, {[]byte{0xff, 0x7f}, true},
		{[]byte{0x00, 0x01}, false}, {[]byte{0xff, 0x80}, false}, {nil, false},
	}
	for _, f := range ints {
		err := intContent(element{id: []byte{tagInteger}, content: f.in}, "x")
		if (err == nil) != f.ok {
			t.Errorf("INTEGER %x: err %v, want ok=%v", f.in, err, f.ok)
		}
	}
	for _, f := range []struct {
		in []byte
		ok bool
	}{{[]byte{0x00}, true}, {[]byte{0xff}, true}, {[]byte{0x01}, false}, {[]byte{0xff, 0xff}, false}, {nil, false}} {
		_, err := boolean(element{id: []byte{tagBoolean}, content: f.in}, "x")
		if (err == nil) != f.ok {
			t.Errorf("BOOLEAN %x: err %v, want ok=%v", f.in, err, f.ok)
		}
	}
	for _, f := range []struct {
		in   []byte
		want oid
	}{
		{[]byte{0x2a, 0x86, 0x48}, "1.2.840"},
		{[]byte{0x04, 0x00, 0x81, 0x97, 0x5e, 0x01, 0x01}, "0.4.0.19422.1.1"},
		{[]byte{0x88, 0x37}, "2.999"},
		{[]byte{0x80, 0x01}, ""},
		{[]byte{0x2a, 0x80, 0x01}, ""},
		{[]byte{0x2a, 0x86}, ""},
		{nil, ""},
	} {
		got, err := readOID(element{id: []byte{tagOID}, content: f.in}, "x")
		if got != f.want || (err == nil) != (f.want != "") {
			t.Errorf("OID %x: %q %v, want %q", f.in, got, err, f.want)
		}
	}
	for _, f := range []struct {
		in []byte
		ok bool
	}{{[]byte{0x00}, true}, {[]byte{0x00, 0xff}, true}, {[]byte{0x07, 0x80}, true}, {nil, false}, {[]byte{0x08, 0x00}, false}, {[]byte{0x01}, false}} {
		_, _, err := bitString(element{id: []byte{tagBitString}, content: f.in}, "x")
		if (err == nil) != f.ok {
			t.Errorf("BIT STRING %x: err %v, want ok=%v", f.in, err, f.ok)
		}
	}
}

// TestOIDArcOfAnySize: an arc of an OBJECT IDENTIFIER reads in decimal
// whatever its size, as big.Int.String() writes it, also beyond the 4300
// digits up to which Python's str() converts an int. The SHA-256 values of
// the two texts stand in verifier2_test.py (IntegerText110) as well, so both
// verifiers are held to the same text.
func TestOIDArcOfAnySize(t *testing.T) {
	for _, f := range []struct {
		in     []byte
		first  string
		minus  int64
		sha256 string
	}{
		{append(append([]byte{0x2b}, bytes.Repeat([]byte{0x81}, 2100)...), 0x01), "1.3.", 0, "8e90d728a5b72eb5bf840e6c151aaa3b1e6c27aefc78200a570a4494e68947d7"},
		{append(bytes.Repeat([]byte{0x81}, 2200), 0x01), "2.", 80, "b547298edafad1c5325f0c86deeb8519b6937d567558efa58587e98440756696"},
	} {
		// the last subidentifier: 128^k + ... + 128 + 1 with k the number of octets 81
		n, k := new(big.Int), bytes.Count(f.in, []byte{0x81})
		for i := 0; i <= k; i++ {
			n.Add(n, new(big.Int).Lsh(big.NewInt(1), uint(7*i)))
		}
		want := f.first + n.Sub(n, big.NewInt(f.minus)).String()
		got, err := readOID(element{id: []byte{tagOID}, content: f.in}, "x")
		sum := sha256.Sum256([]byte(got))
		if err != nil || string(got) != want || len(want) <= 4300 || hex.EncodeToString(sum[:]) != f.sha256 {
			t.Errorf("OID of %d octets: %v, %d digits, SHA-256 %x", len(f.in), err, len(got), sum)
		}
	}
}

// rebuild walks the token along path (child indexes, each step into a
// constructed element) and replaces the children of the element there.
func rebuild(t *testing.T, der []byte, path []int, f func([][]byte) [][]byte) []byte {
	t.Helper()
	e, err := single(der)
	if err != nil {
		t.Fatal(err)
	}
	var walk func(e element, path []int) []byte
	walk = func(e element, path []int) []byte {
		ch, err := elements(e.content)
		if err != nil {
			t.Fatal(err)
		}
		parts := make([][]byte, len(ch))
		for i, c := range ch {
			parts[i] = c.full
		}
		if len(path) == 0 {
			parts = f(parts)
		} else {
			parts[path[0]] = walk(ch[path[0]], path[1:])
		}
		return tt.TLV(e.id[0], parts...)
	}
	return walk(e, path)
}

// Paths into a token of tsatest: ContentInfo [content] SignedData.
var (
	pSignedData = []int{1, 0}
	pEncap      = []int{1, 0, 2}
	pSignerInfo = []int{1, 0, 4, 0} // with certificates present
)

func replaceFirst(old, new []byte) func([]byte) []byte {
	return func(b []byte) []byte { return bytes.Replace(b, old, new, 1) }
}

// TestGrammarT holds T.1 to T.5 on whole tokens: each case either violates
// grammar T (step 2) or passes it.
func TestGrammarT(t *testing.T) {
	good := probeToken(nil)
	cases := []struct {
		why  string
		der  []byte
		pass bool
	}{
		{"T: the probe token", good, true},
		{"T.1: a byte after the ContentInfo", append(append([]byte{}, good...), 0x00), false},
		{"T.1: contentType id-data", probeToken(func(s *tt.TokenSpec) {
			s.Tamper = replaceFirst(tt.OID(tt.SignedData), tt.OID("1.2.840.113549.1.7.1"))
		}), false},
		{"T.1: an element after content", rebuild(t, good, nil, func(p [][]byte) [][]byte { return append(p, tt.Null) }), false},
		{"T.1: content [0] holds two elements", rebuild(t, good, []int{1}, func(p [][]byte) [][]byte { return append(p, tt.Null) }), false},
		{"T.6: ContentInfo length in long form with a leading zero", func() []byte {
			e, _ := single(good)
			n := len(e.content)
			return append([]byte{0x30, 0x83, 0x00, byte(n >> 8), byte(n)}, e.content...)
		}(), false},
		{"T.2: SignedData version -1", probeToken(func(s *tt.TokenSpec) { s.SDVersion = -1 }), false},
		{"T.2: SignedData version 6", probeToken(func(s *tt.TokenSpec) { s.SDVersion = 6 }), false},
		{"T.2: SignedData version 1", probeToken(func(s *tt.TokenSpec) { s.SDVersion = 1 }), true},
		{"T.2: SignedData version 5", probeToken(func(s *tt.TokenSpec) { s.SDVersion = 5 }), true},
		{"T.2: digestAlgorithms not a SET", probeToken(func(s *tt.TokenSpec) { s.DigestAlgs = tt.Seq(tt.Alg(tt.SHA256)) }), false},
		{"T.2: two SignerInfos", probeToken(func(s *tt.TokenSpec) { s.ExtraSignerInfo = tt.Seq(tt.Int(1)) }), false},
		{"T.2: no SignerInfo", rebuild(t, good, append(pSignedData, 4), func([][]byte) [][]byte { return nil }), false},
		{"T.2: certificates primitive", rebuild(t, good, pSignedData, func(p [][]byte) [][]byte {
			p[3] = append([]byte{0x80}, p[3][1:]...)
			return p
		}), false},
		// T.2 (60aa776a): a content of certificates that does not split into
		// TLVs makes step 5 not performable (5a) and does not violate T.
		{"T.2: certificates content not TLVs", probeToken(func(s *tt.TokenSpec) { s.Carried = [][]byte{{0x30, 0x05, 0x01}} }), true},
		{"T.2: certificates empty", probeToken(func(s *tt.TokenSpec) { s.Carried = [][]byte{} }), true},
		{"T.2: crls read as a TLV only", probeToken(func(s *tt.TokenSpec) { s.CRLs = tt.TLV(0xa1, []byte{0xff, 0xff}) }), true},
		{"T.2: crls primitive", probeToken(func(s *tt.TokenSpec) { s.CRLs = tt.TLV(0x81, []byte{0x01}) }), false},
		{"T.3: eContentType id-data", probeToken(func(s *tt.TokenSpec) {
			s.Tamper = replaceFirst(tt.OID(tt.TSTInfo), tt.OID("1.2.840.113549.1.7.1"))
		}), false},
		{"T.3: no eContent", rebuild(t, good, pEncap, func(p [][]byte) [][]byte { return p[:1] }), false},
		{"T.3: eContent in constructed form", rebuild(t, good, append(pEncap, 1), func(p [][]byte) [][]byte {
			p[0] = tt.TLV(0x24, p[0])
			return p
		}), false},
		{"T.3: bytes after the TSTInfo", probeToken(func(s *tt.TokenSpec) { s.EContentTail = tt.Null }), false},
		{"T.4: SignerInfo version 2", probeToken(func(s *tt.TokenSpec) { s.SIVersion = 2 }), false},
		{"T.4: version 3 with IssuerAndSerialNumber", probeToken(func(s *tt.TokenSpec) { s.SIVersion = 3 }), true},
		{"T.4: version 1 with subjectKeyIdentifier", probeToken(func(s *tt.TokenSpec) { s.SID = tt.TLV(0x80, []byte{1, 2, 3}) }), true},
		{"T.4: sid [0] constructed", probeToken(func(s *tt.TokenSpec) { s.SID = tt.TLV(0xa0, tt.Octets([]byte{1})) }), false},
		{"T.4: sid an INTEGER", probeToken(func(s *tt.TokenSpec) { s.SID = tt.Int(1) }), false},
		// T.4: of sid only the SEQUENCE or the primitive [0] is checked; its
		// content, even one that does not split into TLVs, is read in Z.5.
		{"T.4: sid SEQUENCE whose content is not TLVs", probeToken(func(s *tt.TokenSpec) { s.SID = tt.TLV(0x30, []byte{0x02}) }), true},
		{"T.4: sid SEQUENCE with the serial as OCTET STRING", probeToken(func(s *tt.TokenSpec) {
			s.SID = tt.Seq(tt.Seq(), tt.Octets([]byte{1}))
		}), true},
		{"T.4: digestAlgorithm with NULL", probeToken(func(s *tt.TokenSpec) { s.DigestParams = tt.Null }), true},
		{"T.4: digestAlgorithm with other parameters", probeToken(func(s *tt.TokenSpec) { s.DigestParams = tt.Int(5) }), false},
		{"T.4: digestAlgorithm not in digestAlgorithms", probeToken(func(s *tt.TokenSpec) { s.DigestAlgs = tt.Set(tt.Alg(tt.SHA384)) }), false},
		{"T.4: digestAlgorithms element with parameters", probeToken(func(s *tt.TokenSpec) {
			s.DigestAlgs = tt.Set(tt.Alg(tt.SHA256), tt.Alg(tt.SHA512, tt.Int(1)))
		}), false},
		{"T.4: SHA-1 as digestAlgorithm is grammatical", probeToken(func(s *tt.TokenSpec) { s.Digest = tt.SHA1 }), true},
		{"T.4: an attribute without a value", probeToken(func(s *tt.TokenSpec) { s.Attrs = [][]byte{tt.Seq(tt.OID("1.2.3.4"), tt.Set())} }), false},
		{"T.4: an attribute type not an OID", probeToken(func(s *tt.TokenSpec) { s.Attrs = [][]byte{tt.Seq(tt.Int(1), tt.Set(tt.Null))} }), false},
		{"T.4: two contentType attributes", probeToken(func(s *tt.TokenSpec) {
			s.Attrs = [][]byte{tt.Seq(tt.OID(tt.ContentType), tt.Set(tt.OID(tt.TSTInfo)))}
		}), false},
		{"T.4: contentType with two values", probeToken(func(s *tt.TokenSpec) {
			s.ContentTypeAttr = tt.Seq(tt.OID(tt.ContentType), tt.Set(tt.OID(tt.TSTInfo), tt.OID(tt.TSTInfo)))
		}), false},
		{"T.4: contentType value not an OID", probeToken(func(s *tt.TokenSpec) {
			s.ContentTypeAttr = tt.Seq(tt.OID(tt.ContentType), tt.Set(tt.Int(1)))
		}), false},
		{"T.4: contentType naming id-data is grammatical", probeToken(func(s *tt.TokenSpec) {
			s.ContentTypeAttr = tt.Seq(tt.OID(tt.ContentType), tt.Set(tt.OID("1.2.840.113549.1.7.1")))
		}), true},
		{"T.4: no messageDigest", probeToken(func(s *tt.TokenSpec) { s.MessageDigestAttr = tt.Seq(tt.OID("1.2.3.4"), tt.Set(tt.Null)) }), false},
		{"T.4: messageDigest not an OCTET STRING", probeToken(func(s *tt.TokenSpec) {
			s.MessageDigestAttr = tt.Seq(tt.OID(tt.MessageDig), tt.Set(tt.Int(1)))
		}), false},
		{"T.4: no signed attributes is grammatical", probeToken(func(s *tt.TokenSpec) { s.NoSignedAttrs = true }), true},
		{"T.4: signatureAlgorithm with two parameters", probeToken(func(s *tt.TokenSpec) {
			s.SigAlg = tt.Seq(tt.OID("1.2.840.113549.1.1.11"), tt.Null, tt.Null)
		}), false},
		{"T.4: signatureAlgorithm parameters any TLV", probeToken(func(s *tt.TokenSpec) {
			s.SigAlg = tt.Alg("1.2.840.113549.1.1.11", tt.Int(7))
		}), true},
		{"T.4: unsignedAttrs read as a TLV only", probeToken(func(s *tt.TokenSpec) { s.UnsignedAttrs = tt.TLV(0xa1, []byte{0xff}) }), true},
		{"T.4: unsignedAttrs primitive", probeToken(func(s *tt.TokenSpec) { s.UnsignedAttrs = tt.TLV(0x81, []byte{0x01}) }), false},
		{"T.4: an element after unsignedAttrs", probeToken(func(s *tt.TokenSpec) { s.UnsignedAttrs = append(tt.TLV(0xa1), tt.Null...) }), false},
		{"T.5: TSTInfo version 2", probeToken(func(s *tt.TokenSpec) { s.TSTVersion = 2 }), false},
		{"T.5: imprint sha1", probeToken(func(s *tt.TokenSpec) { s.ImprintAlg = tt.SHA1 }), false},
		{"T.5: imprint sha3-256", probeToken(func(s *tt.TokenSpec) { s.ImprintAlg = tt.SHA3_256 }), false},
		{"T.5: imprint sha384", probeToken(func(s *tt.TokenSpec) { s.ImprintAlg = tt.SHA384 }), true},
		{"T.5: imprint sha512", probeToken(func(s *tt.TokenSpec) { s.ImprintAlg = tt.SHA512 }), true},
		{"T.5: imprint algorithm with NULL", probeToken(func(s *tt.TokenSpec) { s.ImprintParams = tt.Null }), true},
		{"T.5: imprint algorithm with other parameters", probeToken(func(s *tt.TokenSpec) { s.ImprintParams = tt.Int(0) }), false},
		{"T.5: hashedMessage of 20 octets for sha256", probeToken(func(s *tt.TokenSpec) { s.Imprint = make([]byte, 20) }), false},
		{"T.5: genTime with fraction", probeToken(func(s *tt.TokenSpec) { s.GenTime = "20260801080200.5Z" }), true},
		{"T.5: genTime with 9 fraction digits", probeToken(func(s *tt.TokenSpec) { s.GenTime = "20260801080200.123456789Z" }), true},
		{"T.5: genTime with a trailing 0", probeToken(func(s *tt.TokenSpec) { s.GenTime = "20260801080200.50Z" }), false},
		{"T.5: genTime with 10 fraction digits", probeToken(func(s *tt.TokenSpec) { s.GenTime = "20260801080200.1234567891Z" }), false},
		{"T.5: genTime with an empty fraction", probeToken(func(s *tt.TokenSpec) { s.GenTime = "20260801080200.Z" }), false},
		{"T.5: genTime with a comma", probeToken(func(s *tt.TokenSpec) { s.GenTime = "20260801080200,5Z" }), false},
		{"T.5: genTime with an offset", probeToken(func(s *tt.TokenSpec) { s.GenTime = "20260801080200+0100" }), false},
		{"T.5: genTime without seconds", probeToken(func(s *tt.TokenSpec) { s.GenTime = "202608010802Z" }), false},
		{"T.5: genTime 30 February", probeToken(func(s *tt.TokenSpec) { s.GenTime = "20260230080200Z" }), false},
		{"T.5: genTime 29 February 2024", probeToken(func(s *tt.TokenSpec) { s.GenTime = "20240229080200Z" }), true},
		{"T.5: genTime 29 February 2100", probeToken(func(s *tt.TokenSpec) { s.GenTime = "21000229080200Z" }), false},
		{"T.5: genTime hour 24", probeToken(func(s *tt.TokenSpec) { s.GenTime = "20260801240000Z" }), false},
		{"T.5: genTime second 60", probeToken(func(s *tt.TokenSpec) { s.GenTime = "20260801080260Z" }), false},
		{"T.5: genTime year 0000", probeToken(func(s *tt.TokenSpec) { s.GenTime = "00000801080200Z" }), false},
		{"T.5: genTime as UTCTime", probeToken(func(s *tt.TokenSpec) {
			s.Tamper = replaceFirst(append([]byte{0x18, 0x0f}, "2026"...), append([]byte{0x17, 0x0f}, "2026"...))
		}), false},
		{"T.5: accuracy", probeToken(func(s *tt.TokenSpec) {
			s.Accuracy = tt.Seq(tt.Int(1), tt.TLV(0x80, []byte{0x01, 0xf4}), tt.TLV(0x81, []byte{0x64}))
		}), true},
		{"T.5: accuracy out of order", probeToken(func(s *tt.TokenSpec) { s.Accuracy = tt.Seq(tt.TLV(0x80, []byte{0x01}), tt.Int(1)) }), false},
		{"T.5: accuracy with a non-minimal INTEGER", probeToken(func(s *tt.TokenSpec) { s.Accuracy = tt.Seq(tt.TLV(0x02, []byte{0x00, 0x01})) }), false},
		{"T.5: ordering TRUE", probeToken(func(s *tt.TokenSpec) { s.TSTOptional = [][]byte{{0x01, 0x01, 0xff}} }), true},
		{"T.5: ordering FALSE encoded (DEFAULT)", probeToken(func(s *tt.TokenSpec) { s.TSTOptional = [][]byte{{0x01, 0x01, 0x00}} }), true},
		{"T.5: ordering 01", probeToken(func(s *tt.TokenSpec) { s.TSTOptional = [][]byte{{0x01, 0x01, 0x01}} }), false},
		{"T.5: nonce", probeToken(func(s *tt.TokenSpec) { s.TSTOptional = [][]byte{tt.Int(123456789)} }), true},
		{"T.5: nonce not minimal", probeToken(func(s *tt.TokenSpec) { s.TSTOptional = [][]byte{{0x02, 0x02, 0x00, 0x05}} }), false},
		{"T.5: nonce before ordering", probeToken(func(s *tt.TokenSpec) {
			s.TSTOptional = [][]byte{tt.Int(5), {0x01, 0x01, 0xff}}
		}), false},
		{"T.5: tsa read as a TLV only", probeToken(func(s *tt.TokenSpec) { s.TSTOptional = [][]byte{tt.TLV(0xa0, []byte{0xff})} }), true},
		{"T.5: tsa primitive", probeToken(func(s *tt.TokenSpec) { s.TSTOptional = [][]byte{tt.TLV(0x80, []byte{0x01})} }), false},
		{"T.5: extensions primitive", probeToken(func(s *tt.TokenSpec) { s.ExtsRaw = tt.TLV(0x81, []byte{0x01}) }), false},
		{"T.5: extensions content not read by T", probeToken(func(s *tt.TokenSpec) { s.ExtsRaw = tt.TLV(0xa1, []byte{0xff}) }), true},
		{"T.5: an element after the extensions", probeToken(func(s *tt.TokenSpec) { s.TSTTail = [][]byte{tt.Null} }), false},
	}
	for _, f := range cases {
		if f.der == nil {
			continue
		}
		_, err := ParseToken(f.der)
		if (err == nil) != f.pass {
			t.Errorf("%s: err %v, want pass=%v", f.why, err, f.pass)
		}
		if err != nil && !errors.Is(err, ErrGrammar) {
			t.Errorf("%s: %v is not ErrGrammar", f.why, err)
		}
	}
	// Size: a token above 16 384 bytes fails before it is read; at the limit
	// it is read (and here fails on its content).
	big := probeToken(func(s *tt.TokenSpec) { s.UnsignedAttrs = tt.TLV(0xa1, make([]byte, MaxTokenDER)) })
	if _, err := ParseToken(big); err == nil || !strings.Contains(err.Error(), "above 16384") {
		t.Errorf("an oversized token: %v", err)
	}
}

// TestGenTimeReading: genTime is read as written and truncated, not rounded,
// to milliseconds (format spec 7.3 step 3).
func TestGenTimeReading(t *testing.T) {
	for in, want := range map[string]string{
		"20260801080200Z":           "2026-08-01T08:02:00.000Z",
		"20260801080200.5Z":         "2026-08-01T08:02:00.500Z",
		"20260801080200.9999Z":      "2026-08-01T08:02:00.999Z",
		"20260801235959.999999999Z": "2026-08-01T23:59:59.999Z",
		"20260801080200.0001Z":      "2026-08-01T08:02:00.000Z",
	} {
		tok, err := ParseToken(probeToken(func(s *tt.TokenSpec) { s.GenTime = in }))
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if tok.GenTimeRaw != in || tok.GenTimeMillis() != want {
			t.Errorf("%s: read %q, %q; want %q", in, tok.GenTimeRaw, tok.GenTimeMillis(), want)
		}
	}
	tok, _ := ParseToken(probeToken(func(s *tt.TokenSpec) { s.GenTime = "20260801080200.123456789Z" }))
	if tok.GenTime.Nanosecond() != 123456789 {
		t.Errorf("genTime is not kept at full precision: %d", tok.GenTime.Nanosecond())
	}
}
