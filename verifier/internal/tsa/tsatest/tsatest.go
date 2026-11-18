// Package tsatest writes RFC 3161 time-stamp tokens for the verifier's own
// tests. It is test material, imported only by _test.go files, and never part
// of a verifier binary.
//
// Every key comes from a fixed label: RSA primes are searched upwards from a
// SHA-256 stream of the label, Ed25519 keys are the SHA-256 of it. Tokens are
// therefore reproducible byte for byte, and no private key is stored
// anywhere. The writer builds DER by hand from RFC 5652 and RFC 3161 and
// signs RSASSA-PSS by hand from RFC 8017, so the verifier's parser and
// crypto/rsa are checked against an encoder that is not theirs.
package tsatest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Object identifiers the tests name.
const (
	SHA1         = "1.3.14.3.2.26"
	SHA256       = "2.16.840.1.101.3.4.2.1"
	SHA384       = "2.16.840.1.101.3.4.2.2"
	SHA512       = "2.16.840.1.101.3.4.2.3"
	SHA3_256     = "2.16.840.1.101.3.4.2.8"
	RSAKey       = "1.2.840.113549.1.1.1"
	RSASSAPSS    = "1.2.840.113549.1.1.10"
	MGF1         = "1.2.840.113549.1.1.8"
	Ed25519      = "1.3.101.112"
	ContentType  = "1.2.840.113549.1.9.3"
	MessageDig   = "1.2.840.113549.1.9.4"
	SigningCert  = "1.2.840.113549.1.9.16.2.12"
	SigningCert2 = "1.2.840.113549.1.9.16.2.47"
	TSTInfo      = "1.2.840.113549.1.9.16.1.4"
	SignedData   = "1.2.840.113549.1.7.2"
	QCStatements = "1.3.6.1.5.5.7.1.3"
	QTST         = "0.4.0.19422.1.1"
	TimeStamping = "1.3.6.1.5.5.7.3.8"
	Policy       = "1.3.6.1.4.1.99999.3.161.1"
)

// ---------------------------------------------------------------- DER

// TLV is one DER element with identifier tag and the parts as content.
func TLV(tag byte, parts ...[]byte) []byte {
	var c []byte
	for _, p := range parts {
		c = append(c, p...)
	}
	n := len(c)
	switch {
	case n < 0x80:
		return append([]byte{tag, byte(n)}, c...)
	case n < 0x100:
		return append([]byte{tag, 0x81, byte(n)}, c...)
	default:
		return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, c...)
	}
}

func Seq(parts ...[]byte) []byte { return TLV(0x30, parts...) }
func Set(parts ...[]byte) []byte { return TLV(0x31, parts...) }
func Octets(b []byte) []byte     { return TLV(0x04, b) }

// Null is the DER NULL.
var Null = []byte{0x05, 0x00}

// Int is a DER INTEGER.
func Int(n int64) []byte { return BigInt(big.NewInt(n)) }

// BigInt is a DER INTEGER of any size.
func BigInt(n *big.Int) []byte {
	b, err := asn1.Marshal(n)
	if err != nil {
		panic(err)
	}
	return b
}

// OID is a DER OBJECT IDENTIFIER, arcs of any size.
func OID(dotted string) []byte {
	var arcs []*big.Int
	for _, s := range strings.Split(dotted, ".") {
		a, ok := new(big.Int).SetString(s, 10)
		if !ok {
			panic("tsatest: OID " + dotted)
		}
		arcs = append(arcs, a)
	}
	first := new(big.Int).Add(new(big.Int).Mul(arcs[0], big.NewInt(40)), arcs[1])
	var out []byte
	for _, a := range append([]*big.Int{first}, arcs[2:]...) {
		enc := []byte{byte(a.Int64() & 0x7f)}
		for v := new(big.Int).Rsh(a, 7); v.Sign() > 0; v.Rsh(v, 7) {
			enc = append([]byte{0x80 | byte(new(big.Int).And(v, big.NewInt(0x7f)).Int64())}, enc...)
		}
		out = append(out, enc...)
	}
	return TLV(0x06, out)
}

// Alg is an AlgorithmIdentifier, the parameters as given (none: absent).
func Alg(oid string, params ...[]byte) []byte { return Seq(append([][]byte{OID(oid)}, params...)...) }

// ---------------------------------------------------------------- keys

var (
	rsaKeys sync.Map
	edKeys  sync.Map
	ecKeys  sync.Map
)

// RSA returns the 2048-bit RSA key of label, the same for every call.
func RSA(label string) *rsa.PrivateKey {
	if k, ok := rsaKeys.Load(label); ok {
		return k.(*rsa.PrivateKey)
	}
	p, q := prime(label+"/p", 1024), prime(label+"/q", 1024)
	e := big.NewInt(65537)
	one := big.NewInt(1)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	k := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: new(big.Int).Mul(p, q), E: 65537},
		D:         new(big.Int).ModInverse(e, phi),
		Primes:    []*big.Int{p, q},
	}
	k.Precompute()
	if err := k.Validate(); err != nil {
		panic(err)
	}
	k2, _ := rsaKeys.LoadOrStore(label, k)
	return k2.(*rsa.PrivateKey)
}

// prime is the first prime from a SHA-256 stream of label upwards, with its
// two top bits set and p-1 prime to 65537.
func prime(label string, bits int) *big.Int {
	var b []byte
	for i := 0; len(b) < bits/8; i++ {
		h := sha256.Sum256([]byte(label + "/" + strconv.Itoa(i)))
		b = append(b, h[:]...)
	}
	n := new(big.Int).SetBytes(b[:bits/8])
	n.SetBit(n, bits-1, 1)
	n.SetBit(n, bits-2, 1)
	n.SetBit(n, 0, 1)
	e, one, two := big.NewInt(65537), big.NewInt(1), big.NewInt(2)
	for {
		if new(big.Int).Mod(new(big.Int).Sub(n, one), e).Sign() != 0 && n.ProbablyPrime(20) {
			return n
		}
		n.Add(n, two)
	}
}

// EC returns the ECDSA key of label on curve (P-256, P-384 or P-521): the
// scalar is a SHA-512 stream of the label reduced into [1, n-1].
func EC(label string, curve elliptic.Curve) *ecdsa.PrivateKey {
	key := label + "/" + curve.Params().Name
	if k, ok := ecKeys.Load(key); ok {
		return k.(*ecdsa.PrivateKey)
	}
	var b []byte
	for i := 0; len(b) < 80; i++ {
		h := sha512.Sum512([]byte(key + "/" + strconv.Itoa(i)))
		b = append(b, h[:]...)
	}
	n := curve.Params().N
	d := new(big.Int).Mod(new(big.Int).SetBytes(b), new(big.Int).Sub(n, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	x, y := curve.ScalarBaseMult(d.FillBytes(make([]byte, (n.BitLen()+7)/8)))
	k := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}
	k2, _ := ecKeys.LoadOrStore(key, k)
	return k2.(*ecdsa.PrivateKey)
}

// Ed25519Key returns the Ed25519 key of label.
func Ed25519Key(label string) ed25519.PrivateKey {
	if k, ok := edKeys.Load(label); ok {
		return k.(ed25519.PrivateKey)
	}
	seed := sha256.Sum256([]byte(label))
	k, _ := edKeys.LoadOrStore(label, ed25519.NewKeyFromSeed(seed[:]))
	return k.(ed25519.PrivateKey)
}

// ---------------------------------------------------------------- certificates

// CertSpec describes a certificate.
type CertSpec struct {
	CN        string
	Serial    int64     // default 1
	NotBefore time.Time // default 2020-01-01
	NotAfter  time.Time // default 2045-01-01
	Key       crypto.Signer
	CA        bool
	// NoEKU leaves the extended key usage out; otherwise it is EKU (default
	// id-kp-timeStamping), critical unless EKUNotCritical.
	NoEKU          bool
	EKU            []string
	EKUNotCritical bool
	// IssuerCert and IssuerKey sign the certificate; nil: self-signed.
	IssuerCert []byte
	IssuerKey  crypto.Signer
	// SPKI is written in place of the subject key, re-signed by the issuer: a
	// key the verifier does not implement.
	SPKI []byte
	// SigAlg is the signature algorithm of the issuer (default: the one
	// crypto/x509 picks for the issuer key).
	SigAlg x509.SignatureAlgorithm
	// PathLenSet writes pathLenConstraint PathLen (with CA); otherwise it is
	// absent.
	PathLenSet bool
	PathLen    int
	// KeyUsage replaces the default key usage; NoKeyUsage leaves it out.
	KeyUsage   x509.KeyUsage
	NoKeyUsage bool
	// NoBasicConstraints leaves basicConstraints out.
	NoBasicConstraints bool
	// Extra are further extensions, written as given.
	Extra []pkix.Extension
	// SubjectKeyID sets the subjectKeyIdentifier.
	SubjectKeyID []byte
	// PermittedDNS writes nameConstraints.
	PermittedDNS []string
}

// Cert writes the certificate described by s.
func Cert(s CertSpec) []byte {
	if s.Serial == 0 {
		s.Serial = 1
	}
	if s.NotBefore.IsZero() {
		s.NotBefore = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	if s.NotAfter.IsZero() {
		s.NotAfter = time.Date(2045, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(s.Serial),
		Subject:               pkix.Name{CommonName: s.CN, Organization: []string{"Probe"}},
		NotBefore:             s.NotBefore,
		NotAfter:              s.NotAfter,
		BasicConstraintsValid: !s.NoBasicConstraints,
		IsCA:                  s.CA,
		SignatureAlgorithm:    s.SigAlg,
		SubjectKeyId:          s.SubjectKeyID,
		PermittedDNSDomains:   s.PermittedDNS,
		MaxPathLen:            -1,
	}
	if s.CA && s.PathLenSet {
		tmpl.MaxPathLen, tmpl.MaxPathLenZero = s.PathLen, s.PathLen == 0
	}
	switch {
	case s.NoKeyUsage:
	case s.KeyUsage != 0:
		tmpl.KeyUsage = s.KeyUsage
	case s.CA:
		tmpl.KeyUsage = x509.KeyUsageCertSign
	default:
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, s.Extra...)
	if !s.NoEKU {
		if s.EKU == nil {
			s.EKU = []string{TimeStamping}
		}
		var oids []asn1.ObjectIdentifier
		for _, o := range s.EKU {
			oids = append(oids, oidOf(o))
		}
		v, err := asn1.Marshal(oids)
		if err != nil {
			panic(err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: !s.EKUNotCritical, Value: v})
	}
	parent, signer := tmpl, s.Key
	if s.IssuerCert != nil {
		p, err := x509.ParseCertificate(s.IssuerCert)
		if err != nil {
			panic(err)
		}
		parent, signer = p, s.IssuerKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, s.Key.Public(), signer)
	if err != nil {
		panic(err)
	}
	if s.SPKI != nil {
		der = mitSPKI(der, s.SPKI, signer)
	}
	return der
}

// mitSPKI writes spki into the certificate der in place of its key and signs
// the result again with signer, under the algorithm der names.
func mitSPKI(der, spki []byte, signer crypto.Signer) []byte {
	var c struct {
		TBS    asn1.RawValue
		SigAlg asn1.RawValue
		Sig    asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &c); err != nil {
		panic(err)
	}
	var f []asn1.RawValue
	for rest := c.TBS.Bytes; len(rest) > 0; {
		var v asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &v); err != nil {
			panic(err)
		}
		f = append(f, v)
	}
	var body []byte
	for i, e := range f {
		if i == 6 { // version [0], serial, signature, issuer, validity, subject, spki
			body = append(body, spki...)
		} else {
			body = append(body, e.FullBytes...)
		}
	}
	tbs := Seq(body)
	return Seq(tbs, c.SigAlg.FullBytes, TLV(0x03, append([]byte{0}, sign(signer, tbs, "rsa256", SHA256)...)))
}

// Resign rebuilds the certificate der with its tbsCertificate fields edited
// (version [0], serialNumber, signature, issuer, validity, subject,
// subjectPublicKeyInfo, then the optional fields) and signs the result with
// key under sha256WithRSAEncryption (an RSA key) or Ed25519. With outerAlg the
// outer signatureAlgorithm is written as given instead of the one signed
// with; edit may change the inner one (field 2) as well.
func Resign(der []byte, key crypto.Signer, edit func(fields [][]byte) [][]byte, outerAlg []byte) []byte {
	var c struct {
		TBS    asn1.RawValue
		SigAlg asn1.RawValue
		Sig    asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &c); err != nil {
		panic(err)
	}
	var f [][]byte
	for rest := c.TBS.Bytes; len(rest) > 0; {
		var v asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &v); err != nil {
			panic(err)
		}
		f = append(f, v.FullBytes)
	}
	alg, how := Alg("1.2.840.113549.1.1.11", Null), "rsa256"
	if _, ok := key.(ed25519.PrivateKey); ok {
		alg, how = Alg(Ed25519), "ed25519"
	}
	f[2] = alg
	if edit != nil {
		f = edit(f)
	}
	tbs := Seq(f...)
	if outerAlg == nil {
		outerAlg = alg
	}
	return Seq(tbs, outerAlg, TLV(0x03, append([]byte{0}, sign(key, tbs, how, SHA256)...)))
}

func oidOf(dotted string) asn1.ObjectIdentifier {
	var o asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(OID(dotted), &o); err != nil {
		panic(err)
	}
	return o
}

// Issuer returns the issuer Name and serial number of a certificate, read
// from its DER (crypto/x509 refuses some of the certificates written here).
func Issuer(cert []byte) (name []byte, serial *big.Int) {
	var c struct {
		TBS struct {
			Version int `asn1:"optional,explicit,default:0,tag:0"`
			Serial  *big.Int
			SigAlg  asn1.RawValue
			Issuer  asn1.RawValue
		}
	}
	if _, err := asn1.Unmarshal(cert, &c); err != nil {
		panic(err)
	}
	return c.TBS.Issuer.FullBytes, c.TBS.Serial
}

// ---------------------------------------------------------------- tokens

// TokenSpec describes a TimeStampToken. Zero fields take the defaults named.
type TokenSpec struct {
	Subject []byte        // the stamped bytes; the imprint is their hash
	Key     crypto.Signer // *rsa.PrivateKey, *ecdsa.PrivateKey or ed25519.PrivateKey
	Cert    []byte        // the signer certificate
	Carried [][]byte      // the certificates in the token; nil: Cert alone
	NoCerts bool          // no certificates field at all
	GenTime string        // GeneralizedTime, default "20260801080200Z"
	Serial  int64         // default 0x2a
	Policy  string        // default Policy
	// Sig names how the signature is made: "rsa256", "rsa384", "rsa512"
	// (PKCS#1 v1.5, default for RSA), "rsa-bare" (rsaEncryption with the
	// CMS digest), "pss256", "pss384", "pss512" (RSASSA-PSS, MGF1 over the
	// same hash), "ecdsa256", "ecdsa384", "ecdsa512" (default for ECDSA:
	// the hash of the curve size), "ecdsa-bare" (id-ecPublicKey with the CMS
	// digest) or "ed25519" (default for Ed25519).
	Sig string
	// Salt is the PSS salt length; 0 means the hash length.
	Salt int
	// SigAlg is written in place of the AlgorithmIdentifier signed with.
	SigAlg []byte
	// Digest is the CMS digest, default SHA256; DigestParams are written as
	// the parameters of digestAlgorithm in the SignerInfo, DigestAlgs in
	// place of the SET digestAlgorithms.
	Digest       string
	DigestParams []byte
	DigestAlgs   []byte
	// ImprintAlg is the imprint algorithm (default SHA256, its parameters
	// ImprintParams), Imprint replaces hashedMessage.
	ImprintAlg    string
	ImprintParams []byte
	Imprint       []byte
	// ESS is "v2" (default, signingCertificateV2 over the signer), "v1"
	// (signingCertificate) or "none"; ESSAttr is an attribute written instead.
	ESS     string
	ESSAttr []byte
	Attrs   [][]byte // further signed attributes
	// ContentTypeAttr and MessageDigest replace the two attributes and the
	// digest value; NoSignedAttrs leaves the signed attributes out (the
	// signature then covers the eContent).
	ContentTypeAttr   []byte
	MessageDigest     []byte
	MessageDigestAttr []byte
	NoSignedAttrs     bool
	Exts              [][]byte // TSTInfo extensions
	ExtsRaw           []byte   // written in place of the [1] of the extensions
	// TSTVersion is the TSTInfo version (default 1). Accuracy is written
	// after genTime, TSTOptional after it (ordering, nonce, tsa in this
	// order); TSTTail after the extensions, inside the TSTInfo;
	// EContentTail after the TSTInfo, inside the eContent. The
	// messageDigest covers all of them.
	TSTVersion   int
	Accuracy     []byte
	TSTOptional  [][]byte
	TSTTail      [][]byte
	EContentTail []byte
	// SDVersion and SIVersion are the SignedData and SignerInfo versions
	// (default 3 and 1); SID replaces the signer identifier; CRLs and
	// UnsignedAttrs are written as given; ExtraSignerInfo is a second
	// SignerInfo.
	SDVersion       int
	SIVersion       int
	SID             []byte
	CRLs            []byte
	UnsignedAttrs   []byte
	ExtraSignerInfo []byte
	// Tamper changes the finished DER, e.g. to break the signature.
	Tamper func([]byte) []byte
}

// Token writes the TimeStampToken described by s.
func Token(s TokenSpec) []byte {
	if s.GenTime == "" {
		s.GenTime = "20260801080200Z"
	}
	if s.Serial == 0 {
		s.Serial = 0x2a
	}
	if s.Policy == "" {
		s.Policy = Policy
	}
	if s.Digest == "" {
		s.Digest = SHA256
	}
	if s.ImprintAlg == "" {
		s.ImprintAlg = SHA256
	}
	if s.TSTVersion == 0 {
		s.TSTVersion = 1
	}
	if s.SDVersion == 0 {
		s.SDVersion = 3
	}
	if s.SIVersion == 0 {
		s.SIVersion = 1
	}
	if s.Sig == "" {
		switch k := s.Key.(type) {
		case ed25519.PrivateKey:
			s.Sig = "ed25519"
		case *ecdsa.PrivateKey:
			s.Sig = map[int]string{256: "ecdsa256", 384: "ecdsa384", 521: "ecdsa512"}[k.Curve.Params().BitSize]
		default:
			s.Sig = "rsa256"
		}
	}
	if s.ESS == "" {
		s.ESS = "v2"
	}
	imprint := s.Imprint
	if imprint == nil {
		imprint = Digest(s.ImprintAlg, s.Subject)
	}
	ext := s.ExtsRaw
	if ext == nil && len(s.Exts) > 0 {
		ext = TLV(0xa1, s.Exts...)
	}
	tst := Seq(Int(int64(s.TSTVersion)), OID(s.Policy), Seq(Alg(s.ImprintAlg, s.ImprintParams), Octets(imprint)), Int(s.Serial),
		TLV(0x18, []byte(s.GenTime)), s.Accuracy, concat(s.TSTOptional...), ext, concat(s.TSTTail...))
	tst = append(tst, s.EContentTail...)
	md := s.MessageDigest
	if md == nil {
		md = Digest(s.Digest, tst)
	}
	ct := s.ContentTypeAttr
	if ct == nil {
		ct = Seq(OID(ContentType), Set(OID(TSTInfo)))
	}
	mda := s.MessageDigestAttr
	if mda == nil {
		mda = Seq(OID(MessageDig), Set(Octets(md)))
	}
	attrs := [][]byte{ct, mda}
	switch {
	case s.ESSAttr != nil:
		attrs = append(attrs, s.ESSAttr)
	case s.ESS == "v2":
		h := sha256.Sum256(s.Cert)
		attrs = append(attrs, Seq(OID(SigningCert2), Set(Seq(Seq(Seq(Octets(h[:])))))))
	case s.ESS == "v1":
		h := sha1.Sum(s.Cert)
		attrs = append(attrs, Seq(OID(SigningCert), Set(Seq(Seq(Seq(Octets(h[:])))))))
	}
	attrs = append(attrs, s.Attrs...)
	signed := Set(attrs...)
	var signedAttrs []byte
	if s.NoSignedAttrs {
		signed = tst
	} else {
		signedAttrs = TLV(0xa0, attrs...)
	}
	sig := sign(s.Key, signed, s.Sig, s.Digest, s.Salt)
	alg := s.SigAlg
	if alg == nil {
		alg = SigAlg(s.Sig, s.Digest, s.Salt)
	}
	sid := s.SID
	if sid == nil {
		name, serial := Issuer(s.Cert)
		sid = Seq(name, BigInt(serial))
	}
	si := Seq(Int(int64(s.SIVersion)), sid, Alg(s.Digest, s.DigestParams), signedAttrs, alg, Octets(sig), s.UnsignedAttrs)
	carried := s.Carried
	if carried == nil {
		carried = [][]byte{s.Cert}
	}
	var certs []byte
	if !s.NoCerts {
		certs = TLV(0xa0, carried...)
	}
	das := s.DigestAlgs
	if das == nil {
		das = Set(Alg(s.Digest))
	}
	sd := Seq(Int(int64(s.SDVersion)), das, Seq(OID(TSTInfo), TLV(0xa0, Octets(tst))), certs, s.CRLs, Set(si, s.ExtraSignerInfo))
	tok := Seq(OID(SignedData), TLV(0xa0, sd))
	if s.Tamper != nil {
		tok = s.Tamper(tok)
	}
	return tok
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// Digest is the digest oid names over b (SHA-1, SHA-2, SHA3-256).
func Digest(oid string, b []byte) []byte {
	switch oid {
	case SHA1:
		h := sha1.Sum(b)
		return h[:]
	case SHA384:
		h := sha512.Sum384(b)
		return h[:]
	case SHA512:
		h := sha512.Sum512(b)
		return h[:]
	case SHA3_256:
		h := sha3.Sum256(b)
		return h[:]
	}
	h := sha256.Sum256(b)
	return h[:]
}

// SigAlg is the AlgorithmIdentifier of a signature made by Token's sig.
func SigAlg(sig, digest string, salt int) []byte {
	if strings.HasPrefix(sig, "pss") {
		h, hl := pssHash(sig)
		if salt == 0 {
			salt = hl
		}
		return Alg(RSASSAPSS, Seq(TLV(0xa0, Alg(h)), TLV(0xa1, Alg(MGF1, Alg(h))), TLV(0xa2, Int(int64(salt)))))
	}
	switch sig {
	case "ecdsa256":
		return Alg("1.2.840.10045.4.3.2")
	case "ecdsa384":
		return Alg("1.2.840.10045.4.3.3")
	case "ecdsa512":
		return Alg("1.2.840.10045.4.3.4")
	case "ecdsa-bare":
		return Alg("1.2.840.10045.2.1")
	case "rsa384":
		return Alg("1.2.840.113549.1.1.12", Null)
	case "rsa512":
		return Alg("1.2.840.113549.1.1.13", Null)
	case "rsa-bare":
		return Alg(RSAKey, Null)
	case "ed25519":
		return Alg(Ed25519)
	}
	return Alg("1.2.840.113549.1.1.11", Null)
}

func pssHash(sig string) (string, int) {
	switch sig {
	case "pss384":
		return SHA384, 48
	case "pss512":
		return SHA512, 64
	}
	return SHA256, 32
}

// sign signs msg with key as Token's sig describes; digest is the CMS digest
// (for "rsa-bare" and "ecdsa-bare"), salt the PSS salt length (0: the hash
// length).
func sign(key crypto.Signer, msg []byte, sig, digest string, salt ...int) []byte {
	if ed, ok := key.(ed25519.PrivateKey); ok {
		return ed25519.Sign(ed, msg)
	}
	if ec, ok := key.(*ecdsa.PrivateKey); ok {
		oid := map[string]string{"ecdsa256": SHA256, "ecdsa384": SHA384, "ecdsa512": SHA512, "ecdsa-bare": digest}[sig]
		if oid == "" {
			oid = SHA256
		}
		out, err := ecdsa.SignASN1(rand.Reader, ec, Digest(oid, msg))
		if err != nil {
			panic(err)
		}
		return out
	}
	k := key.(*rsa.PrivateKey)
	if strings.HasPrefix(sig, "pss") {
		oid, hl := pssHash(sig)
		n := hl
		if len(salt) > 0 && salt[0] != 0 {
			n = salt[0]
		}
		return signPSS(k, oid, msg, n)
	}
	h, oid := crypto.SHA256, SHA256
	switch {
	case sig == "rsa384":
		h, oid = crypto.SHA384, SHA384
	case sig == "rsa512":
		h, oid = crypto.SHA512, SHA512
	case sig == "rsa-bare" && digest == SHA384:
		h, oid = crypto.SHA384, SHA384
	case sig == "rsa-bare" && digest == SHA512:
		h, oid = crypto.SHA512, SHA512
	}
	out, err := rsa.SignPKCS1v15(nil, k, h, Digest(oid, msg))
	if err != nil {
		panic(err)
	}
	return out
}

// signPSS is RSASSA-PSS-SIGN of RFC 8017 section 8.1.1 with EMSA-PSS-ENCODE
// (section 9.1.1) and MGF1 over the same hash, written out by hand; the salt
// is derived from msg, so the signature is reproducible.
func signPSS(k *rsa.PrivateKey, hashOID string, msg []byte, saltLen int) []byte {
	hl := len(Digest(hashOID, nil))
	emBits := k.N.BitLen() - 1
	emLen := (emBits + 7) / 8
	var salt []byte
	for i := 0; len(salt) < saltLen; i++ {
		salt = append(salt, Digest(SHA512, append([]byte(fmt.Sprintf("salt/%d/", i)), msg...))...)
	}
	salt = salt[:saltLen]
	mHash := Digest(hashOID, msg)
	h := Digest(hashOID, append(append(make([]byte, 8), mHash...), salt...))
	db := append(make([]byte, emLen-saltLen-hl-2), 1)
	db = append(db, salt...)
	var mask []byte
	for c := uint32(0); len(mask) < len(db); c++ {
		mask = append(mask, Digest(hashOID, append(append([]byte{}, h...), byte(c>>24), byte(c>>16), byte(c>>8), byte(c)))...)
	}
	for i := range db {
		db[i] ^= mask[i]
	}
	db[0] &= 0xff >> (8*emLen - emBits)
	em := append(append(db, h...), 0xbc)
	s := new(big.Int).Exp(new(big.Int).SetBytes(em), k.D, k.N)
	return s.FillBytes(make([]byte, (k.N.BitLen()+7)/8))
}

// FlipLast flips the last byte of a token, which is the last byte of its
// signature.
func FlipLast(der []byte) []byte {
	out := append([]byte{}, der...)
	out[len(out)-1] ^= 1
	return out
}

// QCStatement is the TSTInfo extension qcStatements holding the statements
// named, critical as given: "" absent, "true" or "false" written out.
func QCStatement(critical string, statements ...string) []byte {
	var st [][]byte
	for _, s := range statements {
		st = append(st, Seq(OID(s)))
	}
	var crit []byte
	switch critical {
	case "true":
		crit = []byte{0x01, 0x01, 0xff}
	case "false":
		crit = []byte{0x01, 0x01, 0x00}
	}
	return Seq(OID(QCStatements), crit, Octets(Seq(st...)))
}
