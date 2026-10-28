package tsa

// Z.3 extensions on a path and Z.4 the path to genTime (format spec 7.5.5).

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"testing"
	"time"

	tt "louwietec.com/ledger-verify/verifier/internal/tsa/tsatest"
)

type issued struct {
	der []byte
	key crypto.Signer
}

func mkCA(label string, parent *issued, mod func(*tt.CertSpec)) issued {
	k := tt.RSA(label)
	s := tt.CertSpec{CN: label, Key: k, CA: true, NoEKU: true}
	if parent != nil {
		s.IssuerCert, s.IssuerKey = parent.der, parent.key
	}
	if mod != nil {
		mod(&s)
	}
	return issued{tt.Cert(s), s.Key}
}

func mkSigner(label string, parent issued, mod func(*tt.CertSpec)) issued {
	k := crypto.Signer(tt.RSA(label))
	s := tt.CertSpec{CN: label, Key: k, IssuerCert: parent.der, IssuerKey: parent.key}
	if mod != nil {
		mod(&s)
	}
	return issued{tt.Cert(s), s.Key}
}

// pathTo builds a token of signer carrying carried and reports whether a
// path to root exists.
func pathTo(t *testing.T, signer issued, carried [][]byte, root []byte) bool {
	t.Helper()
	der := tt.Token(tt.TokenSpec{Subject: stamped, Key: signer.key, Cert: signer.der, Carried: append([][]byte{signer.der}, carried...)})
	tok, err := ParseToken(der)
	if err != nil {
		t.Fatal(err)
	}
	sig := tok.CheckSignature()
	if !sig.Performable || !sig.Valid {
		t.Fatalf("step 5: %s", sig.Reason)
	}
	return tok.PathExists(sig, cert(t, root))
}

var genTime = time.Date(2026, 8, 1, 8, 2, 0, 0, time.UTC) // tsatest's default genTime

// signerKU writes the keyUsage of a certificate as the bytes v, signerBC its
// basicConstraints.
func signerKU(v []byte) func(*tt.CertSpec) {
	return func(s *tt.CertSpec) {
		s.NoKeyUsage = true
		s.Extra = append(s.Extra, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Value: v})
	}
}

func signerBC(v []byte) func(*tt.CertSpec) {
	return func(s *tt.CertSpec) {
		s.NoBasicConstraints = true
		s.Extra = append(s.Extra, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: v})
	}
}

func TestZ4Path(t *testing.T) {
	root := mkCA("path root", nil, nil)
	inter := mkCA("path inter", &root, nil)
	signer := mkSigner("path signer", inter, nil)

	ekuExt := func(critical bool, ids ...string) pkix.Extension {
		var o []asn1.ObjectIdentifier
		for _, id := range ids {
			var x asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(tt.OID(id), &x); err != nil {
				t.Fatal(err)
			}
			o = append(o, x)
		}
		v, _ := asn1.Marshal(o)
		return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: critical, Value: v}
	}
	faelle := []struct {
		why     string
		signer  issued
		carried [][]byte
		root    []byte
		want    bool
	}{
		{"signer, intermediate, root", signer, [][]byte{inter.der}, root.der, true},
		{"the root carried in the token too", signer, [][]byte{inter.der, root.der}, root.der, true},
		{"intermediate not carried", signer, nil, root.der, false},
		{"the intermediate as the root (k = 1)", signer, nil, inter.der, true},
		{"the signer itself as the root (k = 0)", signer, nil, signer.der, true},
		{"a root of another name", signer, [][]byte{inter.der}, mkCA("other root", nil, nil).der, false},
		{"same name, other key", signer, [][]byte{inter.der}, mkCA("path root", nil, func(s *tt.CertSpec) { s.Key = tt.RSA("other key") }).der, false},
	}
	// Rules on the intermediate (position 1).
	interWith := func(mod func(*tt.CertSpec)) (issued, issued) {
		i := mkCA("path inter", &root, mod)
		return i, mkSigner("path signer", i, nil)
	}
	for _, f := range []struct {
		why  string
		mod  func(*tt.CertSpec)
		want bool
	}{
		{"intermediate cA FALSE", func(s *tt.CertSpec) { s.CA = false; s.KeyUsage = x509.KeyUsageCertSign }, false},
		{"intermediate without basicConstraints", func(s *tt.CertSpec) { s.NoBasicConstraints = true }, false},
		{"intermediate keyUsage without keyCertSign", func(s *tt.CertSpec) { s.KeyUsage = x509.KeyUsageDigitalSignature }, false},
		{"intermediate without keyUsage", func(s *tt.CertSpec) { s.NoKeyUsage = true }, true},
		{"intermediate pathLen 0", func(s *tt.CertSpec) { s.PathLenSet, s.PathLen = true, 0 }, true},
		{"intermediate EKU serverAuth", func(s *tt.CertSpec) { s.Extra = []pkix.Extension{ekuExt(false, "1.3.6.1.5.5.7.3.1")} }, false},
		{"intermediate EKU timeStamping", func(s *tt.CertSpec) { s.Extra = []pkix.Extension{ekuExt(false, tt.TimeStamping)} }, true},
		{"intermediate EKU anyExtendedKeyUsage", func(s *tt.CertSpec) { s.Extra = []pkix.Extension{ekuExt(true, "2.5.29.37.0")} }, true},
		{"intermediate nameConstraints", func(s *tt.CertSpec) { s.PermittedDNS = []string{"example.org"} }, false},
		{"intermediate policyMappings, not critical", func(s *tt.CertSpec) {
			s.Extra = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 33}, Value: tt.Seq()}}
		}, false},
		{"intermediate inhibitAnyPolicy, not critical", func(s *tt.CertSpec) {
			s.Extra = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 54}, Value: tt.Int(0)}}
		}, false},
		{"intermediate unknown critical extension", func(s *tt.CertSpec) {
			s.Extra = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: tt.Null}}
		}, false},
		{"intermediate unknown extension, not critical", func(s *tt.CertSpec) {
			s.Extra = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: tt.Null}}
		}, true},
		{"intermediate expired before genTime", func(s *tt.CertSpec) { s.NotAfter = genTime.Add(-time.Second) }, false},
		{"intermediate not yet valid at genTime", func(s *tt.CertSpec) { s.NotBefore = genTime.Add(time.Second) }, false},
		{"intermediate notAfter equal to genTime", func(s *tt.CertSpec) { s.NotAfter = genTime }, true},
		{"intermediate expired now, valid at genTime", func(s *tt.CertSpec) { s.NotAfter = genTime.Add(time.Hour) }, true},
		{"intermediate signed with RSASSA-PSS", func(s *tt.CertSpec) { s.SigAlg = x509.SHA384WithRSAPSS }, true},
		{"intermediate signed with SHA-512", func(s *tt.CertSpec) { s.SigAlg = x509.SHA512WithRSA }, true},
	} {
		i, sg := interWith(f.mod)
		faelle = append(faelle, struct {
			why     string
			signer  issued
			carried [][]byte
			root    []byte
			want    bool
		}{f.why, sg, [][]byte{i.der}, root.der, f.want})
	}
	// Rules on the intermediate whose keyUsage crypto/x509 would not issue
	// under: written as given and re-signed by the root.
	for _, f := range []struct {
		why  string
		ku   []byte
		want bool
	}{
		{"intermediate keyUsage keyCertSign the last of six bits", []byte{0x03, 0x02, 0x02, 0x04}, true},
		{"intermediate keyUsage keyCertSign among the unused bits", []byte{0x03, 0x02, 0x03, 0x04}, false},
		{"intermediate keyUsage keyCertSign in the first of two octets", []byte{0x03, 0x03, 0x07, 0x04, 0x00}, true},
		{"intermediate keyUsage an empty BIT STRING", []byte{0x03, 0x01, 0x00}, false},
	} {
		i := mkCA("path inter", &root, func(s *tt.CertSpec) { s.NoKeyUsage = true })
		sg := mkSigner("path signer", i, nil)
		i.der = tt.Resign(i.der, root.key, func(fields [][]byte) [][]byte {
			x, _ := single(fields[7])
			seq, _ := single(x.content)
			fields[7] = tt.TLV(0xa3, tt.TLV(0x30, seq.content, readExt("2.5.29.15", f.ku)))
			return fields
		}, nil)
		faelle = append(faelle, struct {
			why     string
			signer  issued
			carried [][]byte
			root    []byte
			want    bool
		}{f.why, sg, [][]byte{i.der}, root.der, f.want})
	}
	// The signer as the root (k = 0): Z.3 holds there too.
	for _, f := range []struct {
		why  string
		mod  func(*tt.CertSpec)
		want bool
	}{
		{"the signer as the root, keyUsage an empty BIT STRING", signerKU([]byte{0x03, 0x01, 0x00}), true},
		{"the signer as the root, keyUsage with eight unused bits", signerKU([]byte{0x03, 0x02, 0x08, 0x80}), false},
	} {
		sg := mkSigner("path signer", inter, f.mod)
		faelle = append(faelle, struct {
			why     string
			signer  issued
			carried [][]byte
			root    []byte
			want    bool
		}{f.why, sg, nil, sg.der, f.want})
	}
	// Rules on the signer (position 0).
	for _, f := range []struct {
		why  string
		mod  func(*tt.CertSpec)
		want bool
	}{
		{"signer EKU not critical", func(s *tt.CertSpec) { s.EKUNotCritical = true }, false},
		{"signer EKU timeStamping and serverAuth", func(s *tt.CertSpec) { s.EKU = []string{tt.TimeStamping, "1.3.6.1.5.5.7.3.1"} }, false},
		{"signer without EKU", func(s *tt.CertSpec) { s.NoEKU = true }, false},
		{"signer keyUsage keyCertSign only (not checked)", func(s *tt.CertSpec) { s.KeyUsage = x509.KeyUsageCertSign }, true},
		{"signer expired at genTime", func(s *tt.CertSpec) { s.NotAfter = genTime.Add(-time.Hour) }, false},
		{"signer unknown critical extension", func(s *tt.CertSpec) {
			s.Extra = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: tt.Null}}
		}, false},
		{"signer without basicConstraints (not needed at position 0)", func(s *tt.CertSpec) { s.NoBasicConstraints = true }, true},
		// Z.3: basicConstraints, keyUsage and extKeyUsage follow their
		// grammar at every position, c0 included, though Z.4 does not
		// evaluate keyUsage or basicConstraints there.
		{"signer keyUsage an empty BIT STRING (readable, not evaluated)", signerKU([]byte{0x03, 0x01, 0x00}), true},
		{"signer keyUsage with eight unused bits", signerKU([]byte{0x03, 0x02, 0x08, 0x80}), false},
		{"signer keyUsage with an unused bit and no bits", signerKU([]byte{0x03, 0x01, 0x01}), false},
		{"signer keyUsage an OCTET STRING", signerKU(tt.Octets([]byte{0x80})), false},
		{"signer basicConstraints pathLen without cA (readable, not evaluated)", signerBC(tt.Seq(tt.Int(3))), true},
		{"signer basicConstraints with a negative pathLenConstraint", signerBC(tt.Seq(tt.Int(-1))), false},
		{"signer basicConstraints a SET", signerBC(tt.Set()), false},
		{"signer basicConstraints in the wrong order", signerBC(tt.Seq(tt.Int(0), []byte{0x01, 0x01, 0xff})), false},
	} {
		faelle = append(faelle, struct {
			why     string
			signer  issued
			carried [][]byte
			root    []byte
			want    bool
		}{f.why, mkSigner("path signer", inter, f.mod), [][]byte{inter.der}, root.der, f.want})
	}
	// Rules on the root (position k).
	for _, f := range []struct {
		why  string
		mod  func(*tt.CertSpec)
		want bool
	}{
		{"root pathLen 0 above one intermediate", func(s *tt.CertSpec) { s.PathLenSet, s.PathLen = true, 0 }, false},
		{"root pathLen 1 above one intermediate", func(s *tt.CertSpec) { s.PathLenSet, s.PathLen = true, 1 }, true},
		{"root cA FALSE", func(s *tt.CertSpec) { s.CA = false; s.KeyUsage = x509.KeyUsageCertSign }, false},
		{"root expired at genTime", func(s *tt.CertSpec) { s.NotAfter = genTime.Add(-time.Hour) }, false},
		{"root nameConstraints", func(s *tt.CertSpec) { s.PermittedDNS = []string{"example.org"} }, false},
	} {
		r := mkCA("path root", nil, f.mod)
		i := mkCA("path inter", &r, nil)
		faelle = append(faelle, struct {
			why     string
			signer  issued
			carried [][]byte
			root    []byte
			want    bool
		}{f.why, mkSigner("path signer", i, nil), [][]byte{i.der}, r.der, f.want})
	}
	for _, f := range faelle {
		if got := pathTo(t, f.signer, f.carried, f.root); got != f.want {
			t.Errorf("Z.4 %s: path %v, want %v", f.why, got, f.want)
		}
	}
}

// TestZ4Depth: k <= 8 (format spec 7.5.5): signer, seven intermediates and
// the root are a path; one intermediate more is not.
func TestZ4Depth(t *testing.T) {
	for _, n := range []int{7, 8} {
		root := mkCA("depth root", nil, nil)
		parent := root
		var carried [][]byte
		for i := 1; i <= n; i++ {
			label := fmt.Sprintf("depth ca %d", i)
			c := mkCA(label, &parent, func(s *tt.CertSpec) { s.Key = tt.Ed25519Key(label) })
			carried = append([][]byte{c.der}, carried...)
			parent = c
		}
		signer := mkSigner("depth signer", parent, nil)
		if got, want := pathTo(t, signer, carried, root.der), n <= 7; got != want {
			t.Errorf("%d intermediates (k = %d): path %v, want %v", n, n+1, got, want)
		}
	}
}

// TestZ4Search: the path is an existence statement; decoys (the same name
// under another key, an intermediate the root did not sign) and their order
// in the token do not change the result. Mixed key algorithms on one path.
func TestZ4Search(t *testing.T) {
	root := mkCA("search root", nil, func(s *tt.CertSpec) { s.Key = tt.Ed25519Key("search root ed") })
	inter := mkCA("search inter", &root, func(s *tt.CertSpec) { s.Key = tt.EC("search inter", elliptic.P384()) })
	// Serial 7: with serial 1 the decoy would match the signer identifier
	// too (issuer and serial of the signer), and Z.5 would find two.
	decoy := mkCA("search inter", nil, func(s *tt.CertSpec) { s.Key, s.Serial = tt.RSA("decoy"), 7 })
	signer := mkSigner("search signer", inter, func(s *tt.CertSpec) { s.Key = tt.EC("search signer", elliptic.P256()) })
	for _, order := range [][][]byte{
		{decoy.der, inter.der},
		{inter.der, decoy.der},
		{decoy.der, decoy.der, inter.der},
	} {
		if !pathTo(t, signer, order, root.der) {
			t.Errorf("no path with the order %d", len(order))
		}
	}
	if pathTo(t, signer, [][]byte{decoy.der}, root.der) {
		t.Error("a path through the decoy")
	}
}

// TestZ4ManyCertificatesUnderOneKey: twelve intermediates with one name and
// one key sign each other; the search stays bounded and finds no path to a
// root they do not reach.
func TestZ4ManyCertificatesUnderOneKey(t *testing.T) {
	k := tt.RSA("loop key")
	var loop []issued
	for i := 0; i < 12; i++ {
		s := tt.CertSpec{CN: "loop", Key: k, CA: true, NoEKU: true, Serial: int64(i + 2)}
		loop = append(loop, issued{tt.Cert(s), k})
	}
	signer := mkSigner("loop signer", loop[0], nil)
	var carried [][]byte
	for _, l := range loop {
		carried = append(carried, l.der)
	}
	start := time.Now()
	if pathTo(t, signer, carried, mkCA("elsewhere", nil, nil).der) {
		t.Error("a path to a root nothing reaches")
	}
	if !pathTo(t, signer, carried, loop[5].der) {
		t.Error("no path to one of the loop certificates as the root")
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("search took %s", d)
	}
}
