package tsa

// Z.2 algorithms and keys (format spec 7.5.4): which keys and signature
// algorithms the profile admits, when key and algorithm fit each other, and
// the signature checks themselves. The primitives come from the standard
// library; what they are applied to is decided here, byte by byte.

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"math/big"
)

// Object identifiers of Z.2 and of the attributes and extensions the profile
// reads, all from the RFCs and standards named in format spec 7.5.
const (
	oidSHA1      oid = "1.3.14.3.2.26"
	oidSHA256    oid = "2.16.840.1.101.3.4.2.1"
	oidSHA384    oid = "2.16.840.1.101.3.4.2.2"
	oidSHA512    oid = "2.16.840.1.101.3.4.2.3"
	oidRSA       oid = "1.2.840.113549.1.1.1"
	oidRSAPSS    oid = "1.2.840.113549.1.1.10"
	oidMGF1      oid = "1.2.840.113549.1.1.8"
	oidRSASHA256 oid = "1.2.840.113549.1.1.11"
	oidRSASHA384 oid = "1.2.840.113549.1.1.12"
	oidRSASHA512 oid = "1.2.840.113549.1.1.13"
	oidECKey     oid = "1.2.840.10045.2.1"
	oidECSHA256  oid = "1.2.840.10045.4.3.2"
	oidECSHA384  oid = "1.2.840.10045.4.3.3"
	oidECSHA512  oid = "1.2.840.10045.4.3.4"
	oidP256      oid = "1.2.840.10045.3.1.7"
	oidP384      oid = "1.3.132.0.34"
	oidP521      oid = "1.3.132.0.35"
	oidEd25519   oid = "1.3.101.112"
)

// keyFamily is the kind of a key or of a signature algorithm; Z.2 says they
// fit when the families are equal.
type keyFamily int

const (
	famRSA keyFamily = iota + 1
	famEC
	famEd25519
)

func (f keyFamily) String() string {
	switch f {
	case famRSA:
		return "RSA"
	case famEC:
		return "ECDSA"
	case famEd25519:
		return "Ed25519"
	}
	return "unknown"
}

// publicKey is a key inside Z.2.
type publicKey struct {
	family keyFamily
	rsa    *rsa.PublicKey
	ec     *ecdsa.PublicKey
	order  *big.Int
	ed     ed25519.PublicKey
}

// sha2 maps the three digests of the profile to their hash.
func sha2(o oid) (crypto.Hash, bool) {
	switch o {
	case oidSHA256:
		return crypto.SHA256, true
	case oidSHA384:
		return crypto.SHA384, true
	case oidSHA512:
		return crypto.SHA512, true
	}
	return 0, false
}

func newHash(h crypto.Hash) hash.Hash {
	switch h {
	case crypto.SHA384:
		return sha512.New384()
	case crypto.SHA512:
		return sha512.New()
	}
	return sha256.New()
}

func digest(h crypto.Hash, b []byte) []byte {
	x := newHash(h)
	x.Write(b)
	return x.Sum(nil)
}

func hashName(h crypto.Hash) string {
	switch h {
	case crypto.SHA256:
		return "sha256"
	case crypto.SHA384:
		return "sha384"
	case crypto.SHA512:
		return "sha512"
	}
	return "unknown"
}

// profileKey returns the key of c if it lies in Z.2: rsaEncryption
// (parameters NULL) with RSAPublicKey { n, e }, n positive and odd with
// 2048 <= bitlen(n) <= 8192, e odd with 65537 <= e <= 2^31-1; id-ecPublicKey
// with namedCurve P-256, P-384 or P-521 and an uncompressed point on the
// curve; id-Ed25519 without parameters, 32 octets, y canonical.
func (c *Certificate) profileKey() (*publicKey, error) {
	switch c.keyAlg.oid {
	case oidRSA:
		if c.keyAlg.params == nil || !isNull(*c.keyAlg.params) {
			return nil, fmt.Errorf("rsaEncryption key without NULL parameters")
		}
		e, err := single(c.keyBits)
		if err != nil {
			return nil, fmt.Errorf("RSAPublicKey: %w", err)
		}
		cur, err := newCursor(e, "RSAPublicKey")
		if err != nil {
			return nil, err
		}
		nE, err := cur.take(tagInteger, "modulus")
		if err != nil {
			return nil, err
		}
		eE, err := cur.take(tagInteger, "publicExponent")
		if err != nil {
			return nil, err
		}
		if err := cur.done(); err != nil {
			return nil, err
		}
		n, err := bigInt(nE, "modulus")
		if err != nil {
			return nil, err
		}
		x, err := bigInt(eE, "publicExponent")
		if err != nil {
			return nil, err
		}
		if n.Sign() <= 0 || n.Bit(0) == 0 || n.BitLen() < 2048 || n.BitLen() > 8192 {
			return nil, fmt.Errorf("RSA modulus of %d bits outside 2048 to 8192 or not odd", n.BitLen())
		}
		if x.Bit(0) == 0 || x.Cmp(big.NewInt(65537)) < 0 || x.Cmp(big.NewInt(1<<31-1)) > 0 {
			return nil, fmt.Errorf("RSA exponent %s outside the profile", x)
		}
		return &publicKey{family: famRSA, rsa: &rsa.PublicKey{N: n, E: int(x.Int64())}}, nil
	case oidECKey:
		if c.keyAlg.params == nil {
			return nil, fmt.Errorf("id-ecPublicKey without a named curve")
		}
		curveID, err := readOID(*c.keyAlg.params, "namedCurve")
		if err != nil {
			return nil, fmt.Errorf("id-ecPublicKey parameters are no named curve")
		}
		var curve elliptic.Curve
		var dh ecdh.Curve
		switch curveID {
		case oidP256:
			curve, dh = elliptic.P256(), ecdh.P256()
		case oidP384:
			curve, dh = elliptic.P384(), ecdh.P384()
		case oidP521:
			curve, dh = elliptic.P521(), ecdh.P521()
		default:
			return nil, fmt.Errorf("the curve %s is outside the profile", curveID)
		}
		size := (curve.Params().BitSize + 7) / 8
		if len(c.keyBits) != 1+2*size || c.keyBits[0] != 0x04 {
			return nil, fmt.Errorf("EC point is not uncompressed 04 || X || Y")
		}
		if _, err := dh.NewPublicKey(c.keyBits); err != nil {
			return nil, fmt.Errorf("EC point is not on the curve")
		}
		pub := &ecdsa.PublicKey{Curve: curve,
			X: new(big.Int).SetBytes(c.keyBits[1 : 1+size]),
			Y: new(big.Int).SetBytes(c.keyBits[1+size:])}
		return &publicKey{family: famEC, ec: pub, order: curve.Params().N}, nil
	case oidEd25519:
		if c.keyAlg.params != nil {
			return nil, fmt.Errorf("id-Ed25519 key with parameters")
		}
		if len(c.keyBits) != ed25519.PublicKeySize || !CanonicalEd25519(c.keyBits) {
			return nil, fmt.Errorf("Ed25519 key is not 32 octets with a canonical y")
		}
		return &publicKey{family: famEd25519, ed: ed25519.PublicKey(c.keyBits)}, nil
	}
	return nil, fmt.Errorf("the key algorithm %s is outside the profile", c.keyAlg.oid)
}

// CanonicalEd25519 reports whether a 32-byte Ed25519 public key encodes y
// canonically, y < p = 2^255-19 (RFC 8032 5.1.3 step 1), the rule the
// verifier applies to receipts as well.
func CanonicalEd25519(pub []byte) bool {
	if len(pub) != 32 {
		return false
	}
	var p [32]byte
	p[0] = 0xed
	for i := 1; i < 31; i++ {
		p[i] = 0xff
	}
	p[31] = 0x7f
	for i := 31; i >= 0; i-- {
		b := pub[i]
		if i == 31 {
			b &= 0x7f
		}
		if b != p[i] {
			return b < p[i]
		}
	}
	return false
}

// scheme is a signature algorithm of Z.2 with the hash it is checked with.
type scheme struct {
	family keyFamily
	pss    bool
	hash   crypto.Hash // 0 for Ed25519
}

// signatureScheme maps an AlgorithmIdentifier to a scheme of Z.2. inSigner
// admits the two forms Z.2 allows only in the SignerInfo, rsaEncryption and
// id-ecPublicKey, which take the hash of digestAlgorithm (digestHash, 0 when
// digestAlgorithm is not SHA-2).
func signatureScheme(a algorithm, inSigner bool, digestHash crypto.Hash) (scheme, error) {
	switch a.oid {
	case oidRSASHA256, oidRSASHA384, oidRSASHA512:
		if !a.paramsAbsentOrNull() {
			return scheme{}, fmt.Errorf("parameters of %s are neither absent nor NULL", a.oid)
		}
		h := map[oid]crypto.Hash{oidRSASHA256: crypto.SHA256, oidRSASHA384: crypto.SHA384, oidRSASHA512: crypto.SHA512}[a.oid]
		return scheme{family: famRSA, hash: h}, nil
	case oidRSAPSS:
		h, err := pssParams(a)
		if err != nil {
			return scheme{}, err
		}
		return scheme{family: famRSA, pss: true, hash: h}, nil
	case oidECSHA256, oidECSHA384, oidECSHA512:
		if a.params != nil {
			return scheme{}, fmt.Errorf("parameters of %s are not absent", a.oid)
		}
		h := map[oid]crypto.Hash{oidECSHA256: crypto.SHA256, oidECSHA384: crypto.SHA384, oidECSHA512: crypto.SHA512}[a.oid]
		return scheme{family: famEC, hash: h}, nil
	case oidEd25519:
		if a.params != nil {
			return scheme{}, fmt.Errorf("parameters of Ed25519 are not absent")
		}
		return scheme{family: famEd25519}, nil
	case oidRSA:
		// Z.2 (format spec 7.5.4): in the SignerInfo only, parameters absent
		// or NULL as for the SHA-2 forms.
		if inSigner && digestHash != 0 && a.paramsAbsentOrNull() {
			return scheme{family: famRSA, hash: digestHash}, nil
		}
	case oidECKey:
		// Z.2: the same for id-ecPublicKey, parameters absent as for
		// ecdsa-with-SHA256.
		if inSigner && digestHash != 0 && a.params == nil {
			return scheme{family: famEC, hash: digestHash}, nil
		}
	}
	return scheme{}, fmt.Errorf("the signature algorithm %s is outside the profile here", a.oid)
}

// pssParams reads RSASSA-PSS-params after Z.2: exactly { [0] hashAlgorithm
// SHA-2, [1] maskGenAlgorithm MGF1 with the same hash, [2] saltLength = hash
// length, [3] trailerField absent or 1 }. The digests inside carry no
// parameters or NULL, as everywhere in the profile.
func pssParams(a algorithm) (crypto.Hash, error) {
	bad := func(why string) (crypto.Hash, error) { return 0, fmt.Errorf("RSASSA-PSS parameters: %s", why) }
	if a.params == nil {
		return bad("absent")
	}
	c, err := newCursor(*a.params, "RSASSA-PSS-params")
	if err != nil {
		return bad("not a SEQUENCE")
	}
	explicit := func(tag byte, name string) (element, error) {
		w, err := c.take(tag, name)
		if err != nil {
			return element{}, err
		}
		return single(w.content)
	}
	hE, err := explicit(tagCtx0Cons, "hashAlgorithm")
	if err != nil {
		return bad("hashAlgorithm missing")
	}
	ha, err := readAlgorithm(hE, "hashAlgorithm")
	if err != nil || !ha.paramsAbsentOrNull() {
		return bad("hashAlgorithm malformed")
	}
	h, ok := sha2(ha.oid)
	if !ok {
		return bad("hashAlgorithm is not SHA-2")
	}
	mE, err := explicit(tagCtx1Cons, "maskGenAlgorithm")
	if err != nil {
		return bad("maskGenAlgorithm missing")
	}
	mgf, err := readAlgorithm(mE, "maskGenAlgorithm")
	if err != nil || mgf.oid != oidMGF1 || mgf.params == nil {
		return bad("maskGenAlgorithm is not MGF1")
	}
	mh, err := readAlgorithm(*mgf.params, "MGF1 hash")
	if err != nil || mh.oid != ha.oid || !mh.paramsAbsentOrNull() {
		return bad("MGF1 does not use the same hash")
	}
	sE, err := explicit(tagCtx2Cons, "saltLength")
	if err != nil || sE.tag() != tagInteger {
		return bad("saltLength missing")
	}
	salt, err := smallInt(sE, "saltLength")
	if err != nil || salt != int64(h.Size()) {
		return bad("saltLength is not the hash length")
	}
	if tw, ok := c.optional(tagCtx3Cons); ok {
		tE, err := single(tw.content)
		if err != nil || tE.tag() != tagInteger {
			return bad("trailerField malformed")
		}
		if v, err := smallInt(tE, "trailerField"); err != nil || v != 1 {
			return bad("trailerField is not 1")
		}
	}
	if err := c.done(); err != nil {
		return bad("further elements")
	}
	return h, nil
}

// verify checks sig over msg under key with the scheme; key and scheme must
// be of one family (the caller checks that they fit).
func (k *publicKey) verify(s scheme, msg, sig []byte) bool {
	switch s.family {
	case famRSA:
		if k.rsa == nil {
			return false
		}
		d := digest(s.hash, msg)
		if s.pss {
			return rsa.VerifyPSS(k.rsa, s.hash, d, sig, &rsa.PSSOptions{SaltLength: s.hash.Size(), Hash: s.hash}) == nil
		}
		// crypto/rsa compares the complete encoded message and requires a
		// signature as long as the modulus (RFC 8017 8.2.2).
		return len(sig) == k.rsa.Size() && rsa.VerifyPKCS1v15(k.rsa, s.hash, d, sig) == nil
	case famEC:
		if k.ec == nil {
			return false
		}
		r, sv, ok := ecdsaValue(sig, k.order)
		return ok && ecdsa.Verify(k.ec, digest(s.hash, msg), r, sv)
	case famEd25519:
		return k.ed != nil && len(sig) == ed25519.SignatureSize && ed25519.Verify(k.ed, msg, sig)
	}
	return false
}

// ecdsaValue reads Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } of
// minimal positive INTEGERs with 1 <= r, s < order.
func ecdsaValue(sig []byte, order *big.Int) (*big.Int, *big.Int, bool) {
	e, err := single(sig)
	if err != nil {
		return nil, nil, false
	}
	c, err := newCursor(e, "Ecdsa-Sig-Value")
	if err != nil {
		return nil, nil, false
	}
	rE, err1 := c.take(tagInteger, "r")
	sE, err2 := c.take(tagInteger, "s")
	if err1 != nil || err2 != nil || c.done() != nil {
		return nil, nil, false
	}
	r, err1 := bigInt(rE, "r")
	s, err2 := bigInt(sE, "s")
	if err1 != nil || err2 != nil || r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(order) >= 0 || s.Cmp(order) >= 0 {
		return nil, nil, false
	}
	return r, s, true
}
