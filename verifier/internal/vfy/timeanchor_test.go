package vfy

// Time witnesses (format spec 7.3) through the whole verifier under the
// time-stamp profile of 7.5 (from edition 1.10): tokens from tsa/tsatest on
// a generated chain, against the table of the auditor's roots (10.8).

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"louwietec.com/ledger-verify/verifier/internal/tsa"
	"louwietec.com/ledger-verify/verifier/internal/tsa/tsatest"
)

func probeStelle() (cert []byte) {
	return tsatest.Cert(tsatest.CertSpec{CN: "Probe TSA RSA", Key: tsatest.RSA("tsa test rsa")})
}

// tsaTS is the reading tsa_ts of a genTime: truncated to milliseconds.
func tsaTS(gt string) string {
	frac := ""
	if i := strings.IndexByte(gt, '.'); i >= 0 {
		frac = strings.TrimSuffix(gt[i+1:], "Z")
	}
	frac = (frac + "000")[:3]
	return fmt.Sprintf("%s-%s-%sT%s:%s:%s.%sZ", gt[0:4], gt[4:6], gt[6:8], gt[8:10], gt[10:12], gt[12:14], frac)
}

// timeAnchor writes a TIME_ANCHOR on the checkpoint at cpSeq, its token over
// that checkpoint's signed subject; edit changes the token before it is
// written.
func (g *gen) timeAnchor(cpSeq int64, edit func(*tsatest.TokenSpec)) {
	s := tsatest.TokenSpec{Subject: g.cpSubject[cpSeq], Key: tsatest.RSA("tsa test rsa"), Cert: probeStelle(),
		GenTime: "20260801080200Z", Serial: 0x2a, Policy: tsatest.Policy}
	if edit != nil {
		edit(&s)
	}
	g.timeAnchorB64(cpSeq, s, base64.StdEncoding.EncodeToString(tsatest.Token(s)), tsaTS(s.GenTime))
}

// timeAnchorB64 writes the TIME_ANCHOR with the readings of s and the token
// as given.
func (g *gen) timeAnchorB64(cpSeq int64, s tsatest.TokenSpec, b64, ts string) {
	g.add(time.Second, "TIME_ANCHOR", "system", map[string]any{
		"checkpoint_seq": cpSeq,
		"tree_size":      cpSeq - 1,
		"merkle_root":    g.merkleRootAt(cpSeq - 1),
		"tsa_name":       "Probe",
		"tsa_policy":     s.Policy,
		"tsa_serial":     fmt.Sprintf("%x", s.Serial),
		"tsa_ts":         ts,
		"token_base64":   b64,
	})
}

// zeugenKette is GENESIS, CHECKPOINT, the TIME_ANCHOR on it, SEAL and its
// checkpoint: a sealed chain whose only anchor is the time witness, so a
// token that binds nothing also shows as NO_ANCHOR.
func zeugenKette(t *testing.T, edit func(*tsatest.TokenSpec)) *gen {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.timeAnchor(g.seq, edit)
	g.seal("shutdown")
	return g
}

func mitWurzel(ders ...[]byte) Options { return Options{TSARoots: ders} }

func detailOf(res Result, cls string) string {
	var s []string
	for _, f := range res.Findings {
		if f.Class == cls {
			s = append(s, f.Detail)
		}
	}
	return strings.Join(s, " | ")
}

// TestZeitzeugeSchritte is the table of format spec 7.3 (from 1.10) on whole
// chains: which step decides, and with which finding.
func TestZeitzeugeSchritte(t *testing.T) {
	root := probeStelle()
	other := tsatest.Cert(tsatest.CertSpec{CN: "Other TSA", Key: tsatest.Ed25519Key("other tsa")})
	k1 := tsatest.Seq(tsatest.Alg("1.2.840.10045.2.1", tsatest.OID("1.3.36.3.3.2.8.1.1.7")), tsatest.TLV(0x03, append([]byte{0, 4}, make([]byte, 64)...)))
	brainpool := tsatest.Cert(tsatest.CertSpec{CN: "Probe TSA RSA", Key: tsatest.RSA("tsa test rsa"), SPKI: k1})
	type fall struct {
		why     string
		edit    func(*tsatest.TokenSpec)
		roots   [][]byte
		exit    int
		classes []string
		detail  string
	}
	faelle := []fall{
		{"step 6 holds", nil, [][]byte{root}, 0, nil, ""},
		{"no root: step 6 fails", nil, nil, 1, []string{ClsTimeAnchorUnverif}, "No root for time witnesses was supplied"},
		{"another root: step 6 fails", nil, [][]byte{other}, 1, []string{ClsTimeAnchorUnverif}, "1 root(s) for time witnesses"},
		{"step 2: grammar T", func(s *tsatest.TokenSpec) { s.EContentTail = tsatest.Null }, [][]byte{root}, 2, []string{ClsTimeAnchorInvalid, ClsNoAnchor}, "grammar T"},
		{"step 2: genTime with a trailing 0", func(s *tsatest.TokenSpec) { s.GenTime = "20260801080200.50Z" }, [][]byte{root}, 2, []string{ClsTimeAnchorInvalid, ClsNoAnchor}, "genTime"},
		{"step 3: genTime with a fraction is read", func(s *tsatest.TokenSpec) { s.GenTime = "20260801080200.5Z" }, [][]byte{root}, 0, nil, ""},
		{"step 3: truncated, not rounded", func(s *tsatest.TokenSpec) { s.GenTime = "20260801080259.9999Z" }, [][]byte{root}, 0, nil, ""},
		{"step 4: imprint over another subject", func(s *tsatest.TokenSpec) { s.Subject = []byte("other") }, [][]byte{root}, 2, []string{ClsTimeAnchorInvalid, ClsNoAnchor}, "step 4"},
		{"step 4: imprint sha512", func(s *tsatest.TokenSpec) { s.ImprintAlg = tsatest.SHA512 }, [][]byte{root}, 0, nil, ""},
		{"step 5a: digest SHA-1 is not checkable, never INVALID", func(s *tsatest.TokenSpec) { s.Digest = tsatest.SHA1 }, [][]byte{root}, 1, []string{ClsTimeAnchorUnverif}, "step 5a"},
		{"step 5a: sha1WithRSAEncryption", func(s *tsatest.TokenSpec) { s.SigAlg = tsatest.Alg("1.2.840.113549.1.1.5", tsatest.Null) }, [][]byte{root}, 1, []string{ClsTimeAnchorUnverif}, "step 5a"},
		{"step 5a: md5WithRSAEncryption", func(s *tsatest.TokenSpec) { s.SigAlg = tsatest.Alg("1.2.840.113549.1.1.4", tsatest.Null) }, [][]byte{root}, 1, []string{ClsTimeAnchorUnverif}, "step 5a"},
		{"step 5a: signer on brainpoolP256r1", func(s *tsatest.TokenSpec) {
			s.Cert, s.SigAlg = brainpool, tsatest.Alg("1.2.840.10045.4.3.2")
		}, [][]byte{root, brainpool}, 1, []string{ClsTimeAnchorUnverif}, "outside the profile"},
		{"step 5a: no certificates", func(s *tsatest.TokenSpec) { s.NoCerts = true }, [][]byte{root}, 1, []string{ClsTimeAnchorUnverif}, "no certificates"},
		{"step 5a: no signed attributes", func(s *tsatest.TokenSpec) { s.NoSignedAttrs = true }, [][]byte{root}, 1, []string{ClsTimeAnchorUnverif}, "no signed attributes"},
		{"step 5b: signature broken", func(s *tsatest.TokenSpec) { s.Tamper = tsatest.FlipLast }, [][]byte{root}, 2, []string{ClsTimeAnchorInvalid}, "step 5b"},
		{"step 5b: messageDigest wrong", func(s *tsatest.TokenSpec) { s.MessageDigest = make([]byte, 32) }, [][]byte{root}, 2, []string{ClsTimeAnchorInvalid}, "messageDigest"},
		{"Z.6 violated has no effect", func(s *tsatest.TokenSpec) { s.ESS = "none" }, [][]byte{root}, 0, nil, ""},
		{"Z.6 naming another certificate has no effect", func(s *tsatest.TokenSpec) {
			s.ESSAttr = tsatest.Seq(tsatest.OID(tsatest.SigningCert2), tsatest.Set(tsatest.Seq(tsatest.Seq(tsatest.Seq(tsatest.Octets(make([]byte, 32)))))))
		}, [][]byte{root}, 0, nil, ""},
		{"rule QS has no effect", func(s *tsatest.TokenSpec) { s.ExtsRaw = tsatest.TLV(0xa1) }, [][]byte{root}, 0, nil, ""},
		{"Ed25519 authority", func(s *tsatest.TokenSpec) {
			s.Key, s.Cert, s.Digest = tsatest.Ed25519Key("other tsa"), other, tsatest.SHA512
		}, [][]byte{other}, 0, nil, ""},
	}
	for _, f := range faelle {
		var opt Options
		for _, r := range f.roots {
			opt.TSARoots = append(opt.TSARoots, r)
		}
		res := verifyGen(zeugenKette(t, f.edit), opt)
		t.Run(f.why, func(t *testing.T) { wantClasses(t, res, f.exit, f.classes...) })
		if f.detail != "" && !strings.Contains(detailOf(res, f.classes[0]), f.detail) {
			t.Errorf("%s: detail %q lacks %q", f.why, detailOf(res, f.classes[0]), f.detail)
		}
	}
	// Step 3 with readings that contradict the token.
	for why, change := range map[string]func(p map[string]string){
		"tsa_policy":            func(p map[string]string) { p["policy"] = "1.2.3" },
		"tsa_serial":            func(p map[string]string) { p["serial"] = "2b" },
		"tsa_ts without millis": func(p map[string]string) { p["ts"] = "2026-08-01T08:02:00Z" },
		"tsa_ts rounded":        func(p map[string]string) { p["ts"] = "2026-08-01T08:03:00.000Z" },
	} {
		g := newGen(t)
		g.genesis()
		g.checkpoint(time.Second)
		s := tsatest.TokenSpec{Subject: g.cpSubject[g.seq], Key: tsatest.RSA("tsa test rsa"), Cert: root,
			GenTime: "20260801080259.9999Z", Serial: 0x2a, Policy: tsatest.Policy}
		p := map[string]string{"policy": s.Policy, "serial": "2a", "ts": tsaTS(s.GenTime)}
		change(p)
		g.add(time.Second, "TIME_ANCHOR", "system", map[string]any{
			"checkpoint_seq": g.seq, "tree_size": g.seq - 1, "merkle_root": g.merkleRootAt(g.seq - 1), "tsa_name": "Probe",
			"tsa_policy": p["policy"], "tsa_serial": p["serial"], "tsa_ts": p["ts"],
			"token_base64": base64.StdEncoding.EncodeToString(tsatest.Token(s)),
		})
		g.seal("shutdown")
		res := verifyGen(g, mitWurzel(root))
		wantClasses(t, res, 2, ClsTimeAnchorInvalid, ClsNoAnchor)
		if !strings.Contains(detailOf(res, ClsTimeAnchorInvalid), "step 3") {
			t.Errorf("%s: %q", why, detailOf(res, ClsTimeAnchorInvalid))
		}
	}
}

// TestZeitzeugeB64: token_base64 follows grammar B64 (format spec 2): a line
// break, a blank or a missing padding is TIME_ANCHOR_INVALID, never a format
// error of the package.
func TestZeitzeugeB64(t *testing.T) {
	for why, mangle := range map[string]func(string) string{
		"line break": func(b string) string { return b[:40] + "\n" + b[40:] },
		"blank":      func(b string) string { return b[:40] + " " + b[40:] },
		"no padding": func(b string) string { return strings.TrimRight(b, "=") + "A" },
		"url-safe":   func(b string) string { return strings.NewReplacer("+", "-", "/", "_").Replace(b) },
	} {
		g := newGen(t)
		g.genesis()
		g.checkpoint(time.Second)
		s := tsatest.TokenSpec{Subject: g.cpSubject[g.seq], Key: tsatest.RSA("tsa test rsa"), Cert: probeStelle(),
			GenTime: "20260801080200Z", Serial: 0x2a, Policy: tsatest.Policy}
		b64 := base64.StdEncoding.EncodeToString(tsatest.Token(s))
		if why == "url-safe" && !strings.ContainsAny(b64, "+/") {
			continue
		}
		g.timeAnchorB64(g.seq, s, mangle(b64), tsaTS(s.GenTime))
		g.seal("shutdown")
		res := verifyGen(g, mitWurzel(probeStelle()))
		wantClasses(t, res, 2, ClsTimeAnchorInvalid, ClsNoAnchor)
		if !strings.Contains(detailOf(res, ClsTimeAnchorInvalid), "B64") {
			t.Errorf("%s: %q", why, detailOf(res, ClsTimeAnchorInvalid))
		}
	}
}

// TestZeitzeugeZwecke: only roots of the purpose chain count for a time
// witness (format spec 7.5.7, 10.8): --tsa-root and the file of qualified
// roots, never a root for the vendor log; byte-equal certificates are one
// entry with the union of their purposes.
func TestZeitzeugeZwecke(t *testing.T) {
	root := probeStelle()
	q := &QualifiedRoots{Stand: "2026-10-01T00:00:00Z", Quelle: "test", Roots: []QualifiedRoot{{Cert: mustCert(t, root), From: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}}}
	for _, f := range []struct {
		why  string
		opt  Options
		exit int
	}{
		{"a root of the purpose chain", Options{TSARoots: [][]byte{root}}, 0},
		{"a root for the vendor log only", Options{VendorLogTSARoots: [][]byte{root}}, 1},
		{"a qualified root counts for chain at any time", Options{TSAQualified: q}, 0},
		{"the same root for the log and for the chain", Options{TSARoots: [][]byte{root}, VendorLogTSARoots: [][]byte{root}}, 0},
	} {
		res := verifyGen(zeugenKette(t, nil), f.opt)
		if f.exit == 0 {
			wantClasses(t, res, 0)
		} else {
			wantClasses(t, res, 1, ClsTimeAnchorUnverif)
		}
	}
	table := BuildTSARootTable(Options{TSARoots: [][]byte{root}, VendorLogTSARoots: [][]byte{root}, TSAQualified: q})
	if len(table) != 1 || !table[0].Chain || !table[0].Log || table[0].Qualified == nil {
		t.Fatalf("root table %+v", table)
	}
	if table[0].QualifiedAt(time.Date(2026, 12, 31, 23, 59, 59, 999999999, time.UTC)) || !table[0].QualifiedAt(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("qualifiziert_ab is not compared on nanoseconds")
	}
}

func mustCert(t *testing.T, der []byte) *tsa.Certificate {
	t.Helper()
	c, err := tsa.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestZeitzeugePaket: a certificate of keys/tsa/ in the package is no root
// (format spec 7.3); a path to it only lets the report name the authority.
func TestZeitzeugePaket(t *testing.T) {
	g := zeugenKette(t, nil)
	dir := g.writePkg()
	if err := os.MkdirAll(filepath.Join(dir, "keys", "tsa"), 0o755); err != nil {
		t.Fatal(err)
	}
	pemText := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: probeStelle()})
	if err := os.WriteFile(filepath.Join(dir, "keys", "tsa", "stelle.pem"), pemText, 0o644); err != nil {
		t.Fatal(err)
	}
	res := Verify(dir, genAnker(Options{Now: g.now.Add(time.Hour)}))
	wantClasses(t, res, 1, ClsTimeAnchorUnverif)
	if d := detailOf(res, ClsTimeAnchorUnverif); !strings.Contains(d, "keys/tsa/") || !strings.Contains(d, "Probe TSA RSA") {
		t.Errorf("the authority is not named: %q", d)
	}
}

// TestZeitzeugeDetails: what the run keeps per witness for the evidence
// level (format spec 10.5, stage 5, step 10), and that the JSON output does
// not carry it.
func TestZeitzeugeDetails(t *testing.T) {
	root := probeStelle()
	logRoot := tsatest.Cert(tsatest.CertSpec{CN: "Other TSA", Key: tsatest.Ed25519Key("other tsa")})
	res := verifyGen(zeugenKette(t, func(s *tsatest.TokenSpec) {
		s.Exts = [][]byte{tsatest.QCStatement("", tsatest.QTST)}
		s.ESS = "v1"
		s.GenTime = "20260801080200.123456789Z"
	}), Options{TSARoots: [][]byte{root}, VendorLogTSARoots: [][]byte{logRoot}})
	wantClasses(t, res, 0)
	det := res.Stats.TimeAnchorDetails
	if len(det) != 1 {
		t.Fatalf("details %+v", det)
	}
	d := det[0]
	if !d.SignatureChecked || !d.SignatureValid || !d.Verified || d.QS != tsa.QSPresent || d.Z6 != tsa.Z6Bound ||
		len(d.PathRoots) != 1 || d.Seq != 3 || d.CheckpointSeq != 2 || d.GenTime.Nanosecond() != 123456789 || d.SignerTestKey {
		t.Errorf("detail %+v", d)
	}
	if res.Stats.TimeAnchorsVerified != 1 || res.Stats.TimeAnchors != 1 {
		t.Errorf("counts %d %d", res.Stats.TimeAnchors, res.Stats.TimeAnchorsVerified)
	}
	js, _ := RenderJSON(res)
	ohne := res
	ohne.Stats.TimeAnchorDetails = nil
	js2, _ := RenderJSON(ohne)
	if string(js) != string(js2) {
		t.Error("the details reach the JSON output")
	}
}

// TestKeinSystemwurzelspeicher: the system root store counts for no purpose
// (format spec 7.3 step 6, 7.5.7, 10.8; E3). No source file of the verifier
// may consult it.
func TestKeinSystemwurzelspeicher(t *testing.T) {
	root := filepath.Join(repoRoot(t), "verifier")
	fset := token.NewFileSet()
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		if strings.Contains(filepath.ToSlash(p), "/tsa/tsatest/") {
			return nil // test material: writes certificates, imported only by tests
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), "SystemCertPool") {
			t.Errorf("%s consults the system root store", p)
		}
		for _, im := range f.Imports {
			if im.Path.Value == `"crypto/x509"` {
				t.Errorf("%s imports crypto/x509; the profile reads certificates itself (format spec 7.5)", p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestParseTSARoots: --tsa-root in the strict PEM of format spec 10.8; the
// cases of the grammar are in the tsa package (TestStrictPEM).
func TestParseTSARoots(t *testing.T) {
	good := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: probeStelle()}))
	if ders, err := ParseTSARoots([]byte("# roots\n" + good + good)); err != nil || len(ders) != 2 {
		t.Errorf("a bundle: %d, %v", len(ders), err)
	}
	if _, err := ParseTSARoots([]byte("-----BEGIN PUBLIC KEY-----\nMAA=\n-----END PUBLIC KEY-----\n" + good)); err == nil {
		t.Error("another label accepted")
	}
}
