// Package tsa parses and verifies RFC 3161 TimeStampTokens using nothing but
// the Go standard library.
//
// WHY THIS PACKAGE EXISTS AT ALL: an RFC 3161 token is a CMS SignedData
// structure (RFC 5652) whose encapsulated content is a TSTInfo. Go's standard
// library has ASN.1 (encoding/asn1) and certificates (crypto/x509), but it has
// no CMS/PKCS#7 package — checked, it is not there. The free verifier may not
// take a dependency (spec-only rule, docs/BAUPLAN.md), so the walk through the
// structure is written out here. It is deliberately narrow: it parses exactly
// the shape RFC 3161 mandates and rejects everything else, rather than being a
// general CMS implementation.
//
// WHAT IT PROVES AND WHAT IT DOES NOT: Parse alone proves nothing — it only
// reads what the token claims. The binding to a LEDGER checkpoint (does the
// message imprint equal the hash of the checkpoint signature subject?) is the
// caller's job and is mandatory. Verify adds the cryptographic half: the
// signature is by the enclosed signer certificate, and that certificate chains
// to a trust anchor the CALLER supplies. A trust anchor taken out of the
// verification package itself proves only self-consistency — the package is
// written by the party the anchor is meant to constrain. That distinction is
// carried out in the finding classes, not hidden here.
package tsa

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"time"
)

// Object identifiers, all from the RFCs named beside them.
var (
	oidSignedData     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}        // RFC 5652 id-signedData
	oidTSTInfo        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4} // RFC 3161 id-ct-TSTInfo
	oidAttrContentTyp = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}        // RFC 5652 id-contentType
	oidAttrMsgDigest  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}        // RFC 5652 id-messageDigest
	oidExtKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 37}                      // RFC 5280 id-ce-extKeyUsage

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECPublicKey     = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// MaxTokenBytes bounds a token before any parsing happens. Real tokens with a
// full certificate chain stay below 16 KiB; the free verifier reads packages
// from untrusted hands, so the walk gets a ceiling rather than a promise.
const MaxTokenBytes = 64 * 1024

// Token is the verified-as-far-as-parsed content of a TimeStampToken.
type Token struct {
	HashAlgorithm string    // name of the message imprint digest, e.g. "sha256"
	Imprint       []byte    // messageImprint.hashedMessage, raw
	GenTime       time.Time // TSTInfo.genTime, always UTC
	Serial        string    // TSTInfo.serialNumber, lowercase hex
	Policy        string    // TSTInfo.policy, dotted OID
	Accuracy      time.Duration
	Ordering      bool
	Signer        *x509.Certificate   // the certificate that signed this token
	Certs         []*x509.Certificate // every certificate the token carries

	// Raw material for the signature check, kept so Verify needs no reparse.
	signedAttrsDER []byte // re-tagged as SET OF, exactly what was signed
	signature      []byte
	sigAlg         x509.SignatureAlgorithm
}

// ---------------------------------------------------------------------------
// ASN.1 shapes. Only the fields RFC 3161 and RFC 5652 require are named; the
// rest is captured as asn1.RawValue so an unexpected optional field does not
// derail the walk.
// ---------------------------------------------------------------------------

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,tag:0"`
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    algorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
	// Accuracy is a TYPE and not an asn1.RawValue, and that is the difference
	// between reading the token and misreading it: an optional RawValue takes
	// the next element whatever it is. In a token without accuracy it would
	// swallow the ordering BOOLEAN or the nonce INTEGER, and the next field
	// would then fail to parse — a conformant token rejected by this verifier.
	Accuracy   accuracy      `asn1:"optional"`
	Ordering   bool          `asn1:"optional"`
	Nonce      *big.Int      `asn1:"optional"`
	TSA        asn1.RawValue `asn1:"optional,explicit,tag:0"`
	Extensions asn1.RawValue `asn1:"optional,tag:1"`
}

type messageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

type accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

func (a accuracy) dauer() time.Duration {
	return time.Duration(a.Seconds)*time.Second +
		time.Duration(a.Millis)*time.Millisecond +
		time.Duration(a.Micros)*time.Microsecond
}

// ---------------------------------------------------------------------------

// Parse reads a DER-encoded TimeStampToken. It performs NO signature check —
// everything it returns is still only what the token claims about itself.
func Parse(der []byte) (*Token, error) {
	if len(der) == 0 {
		return nil, errors.New("empty token")
	}
	if len(der) > MaxTokenBytes {
		return nil, fmt.Errorf("token is %d bytes, above the %d byte ceiling", len(der), MaxTokenBytes)
	}

	var ci contentInfo
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil {
		return nil, fmt.Errorf("not a DER ContentInfo: %w", err)
	}
	// Trailing bytes are rejected: a token with something appended is not the
	// token that was signed, and accepting it would let two different byte
	// strings carry the same proof.
	if len(rest) != 0 {
		return nil, fmt.Errorf("%d trailing bytes after the ContentInfo", len(rest))
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("content type is %v, expected id-signedData", ci.ContentType)
	}

	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("not a DER SignedData: %w", err)
	}
	// RFC 5652 section 5.1: with certificates present and an eContentType
	// other than id-data the version is 3; 1 and 4 exist for other shapes.
	// Checking it costs nothing and closes a field that would otherwise accept
	// any value at all.
	if sd.Version < 1 || sd.Version > 5 {
		return nil, fmt.Errorf("SignedData version %d is out of range", sd.Version)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidTSTInfo) {
		return nil, fmt.Errorf("encapsulated content is %v, expected id-ct-TSTInfo", sd.EncapContentInfo.EContentType)
	}
	if len(sd.EncapContentInfo.EContent) == 0 {
		return nil, errors.New("SignedData carries no TSTInfo content (detached token)")
	}
	// RFC 3161 tokens are single-signer. More than one signer would mean the
	// question "who attests this time?" has more than one answer, and the
	// caller would have to pick — so it is refused instead.
	if len(sd.SignerInfos) != 1 {
		return nil, fmt.Errorf("token carries %d SignerInfos, expected exactly 1", len(sd.SignerInfos))
	}
	si := sd.SignerInfos[0]
	// RFC 5652 section 5.3: version 1 goes with IssuerAndSerialNumber, 3 with
	// a subjectKeyIdentifier. Anything else is not a shape this parser reads.
	if si.Version != 1 && si.Version != 3 {
		return nil, fmt.Errorf("SignerInfo version %d is neither 1 nor 3", si.Version)
	}
	// RFC 5754: the parameters of a SHA-2 algorithm identifier are absent, and
	// NULL is tolerated for compatibility. Everything else is refused — a
	// parser that ignores a field lets two byte strings carry one statement.
	if err := parameterAbwesendOderNull(si.DigestAlgorithm.Parameters, "digestAlgorithm"); err != nil {
		return nil, err
	}
	if err := parameterAbwesendOderNull(si.SignatureAlgorithm.Parameters, "signatureAlgorithm"); err != nil {
		return nil, err
	}
	// RFC 5652 section 5.1: digestAlgorithms lists the digests the signers use.
	// The field is there for one-pass processing and nothing here depends on
	// it — which is exactly why it gets checked. A field a parser never reads
	// is a field an attacker can rewrite at will, and a token that differs in
	// it is a second byte string carrying one and the same statement.
	if err := digestAlgorithmGelistet(sd.DigestAlgorithms, si.DigestAlgorithm.Algorithm); err != nil {
		return nil, err
	}

	var info tstInfo
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent, &info); err != nil {
		return nil, fmt.Errorf("not a DER TSTInfo: %w", err)
	}
	if info.Version != 1 {
		return nil, fmt.Errorf("TSTInfo version is %d, expected 1", info.Version)
	}

	if err := parameterAbwesendOderNull(info.MessageImprint.HashAlgorithm.Parameters, "messageImprint hashAlgorithm"); err != nil {
		return nil, err
	}
	hashName, err := imprintAlgName(info.MessageImprint.HashAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	if n := expectedImprintLen(hashName); len(info.MessageImprint.HashedMessage) != n {
		return nil, fmt.Errorf("message imprint is %d bytes, %s needs %d",
			len(info.MessageImprint.HashedMessage), hashName, n)
	}

	certs, err := parseCerts(sd.Certificates)
	if err != nil {
		return nil, err
	}
	signer, err := findSigner(certs, si.SID)
	if err != nil {
		return nil, err
	}

	tok := &Token{
		HashAlgorithm: hashName,
		Imprint:       info.MessageImprint.HashedMessage,
		GenTime:       info.GenTime.UTC(),
		Serial:        fmt.Sprintf("%x", info.SerialNumber),
		Policy:        info.Policy.String(),
		Accuracy:      info.Accuracy.dauer(),
		Ordering:      info.Ordering,
		Signer:        signer,
		Certs:         certs,
		signature:     si.Signature,
	}

	// The signed attributes are mandatory here. Without them the signature
	// would cover the TSTInfo directly and the content-type binding of RFC
	// 5652 section 5.3 would be missing — that binding is what stops a
	// signature made over some other CMS content from being replayed as a
	// timestamp.
	if len(si.SignedAttrs.FullBytes) == 0 {
		return nil, errors.New("SignerInfo carries no signed attributes")
	}
	attrs, err := parseAttrs(si.SignedAttrs.Bytes)
	if err != nil {
		return nil, err
	}
	if err := checkSignedAttrs(attrs, sd.EncapContentInfo.EContent, si.DigestAlgorithm.Algorithm); err != nil {
		return nil, err
	}
	tok.signedAttrsDER = retagAsSet(si.SignedAttrs.FullBytes)

	tok.sigAlg, err = signatureAlgorithm(si.SignatureAlgorithm.Algorithm, si.DigestAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	return tok, nil
}

// Verify checks the token's own signature and chains the signer certificate to
// one of the supplied roots. A nil or empty root pool is an error and not a
// silent pass — "I could not check" must never read like "I checked".
//
// The chain is validated AT genTime, not at the verifier's wall clock: a
// timestamp from 2027 stays provable in 2037, when the TSA certificate has
// long expired. That is the whole point of a timestamp.
func (t *Token) Verify(roots *x509.CertPool, intermediates *x509.CertPool) error {
	if t.Signer == nil {
		return errors.New("token carries no signer certificate")
	}
	if roots == nil {
		return errors.New("no trust anchor supplied")
	}
	if err := t.Signer.CheckSignature(t.sigAlg, t.signedAttrsDER, t.signature); err != nil {
		return fmt.Errorf("signature does not verify against the signer certificate: %w", err)
	}
	if err := checkTimeStampingEKU(t.Signer); err != nil {
		return err
	}
	if intermediates == nil {
		intermediates = x509.NewCertPool()
	}
	for _, c := range t.Certs {
		if c != t.Signer {
			intermediates.AddCert(c)
		}
	}
	_, err := t.Signer.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   t.GenTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	})
	if err != nil {
		return fmt.Errorf("signer certificate does not chain to a supplied trust anchor: %w", err)
	}
	return nil
}

// CheckSignatureOnly verifies the token signature against its own enclosed
// signer certificate, without any chain. It answers a narrower question than
// Verify: "is this token internally intact?" — useful to tell a forged or
// corrupted token (evidence of tampering) apart from a merely untrusted one
// (a configuration statement). It is never sufficient on its own.
func (t *Token) CheckSignatureOnly() error {
	if t.Signer == nil {
		return errors.New("token carries no signer certificate")
	}
	if err := t.Signer.CheckSignature(t.sigAlg, t.signedAttrsDER, t.signature); err != nil {
		return fmt.Errorf("signature does not verify against the signer certificate: %w", err)
	}
	return nil
}

// SignerName is a short human-readable name of the attesting authority.
func (t *Token) SignerName() string {
	if t.Signer == nil {
		return ""
	}
	if s := t.Signer.Subject.CommonName; s != "" {
		return s
	}
	return t.Signer.Subject.String()
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// digestAlgorithmGelistet requires the signer's digest to appear in the
// SignedData's digestAlgorithms set.
func digestAlgorithmGelistet(set asn1.RawValue, want asn1.ObjectIdentifier) error {
	// Auch der Behaelter selbst wird geprueft. Ohne das bliebe genau EIN Byte
	// des Tokens frei waehlbar — das SET-Kennzeichen —, weil asn1.RawValue
	// jedes Kennzeichen annimmt und der Inhalt darunter unveraendert bleibt.
	if set.Class != asn1.ClassUniversal || set.Tag != asn1.TagSet || !set.IsCompound {
		return errors.New("digestAlgorithms is not a SET")
	}
	rest := set.Bytes
	for len(rest) > 0 {
		var a algorithmIdentifier
		var err error
		rest, err = asn1.Unmarshal(rest, &a)
		if err != nil {
			return fmt.Errorf("digestAlgorithms do not parse: %w", err)
		}
		if err := parameterAbwesendOderNull(a.Parameters, "digestAlgorithms entry"); err != nil {
			return err
		}
		if a.Algorithm.Equal(want) {
			return nil
		}
	}
	return fmt.Errorf("the signer's digest %v is not listed in digestAlgorithms", want)
}

// parameterAbwesendOderNull enforces RFC 5754 on an AlgorithmIdentifier.
func parameterAbwesendOderNull(p asn1.RawValue, was string) error {
	if len(p.FullBytes) == 0 {
		return nil
	}
	if len(p.FullBytes) == 2 && p.FullBytes[0] == 0x05 && p.FullBytes[1] == 0x00 {
		return nil
	}
	return fmt.Errorf("%s carries parameters that are neither absent nor NULL", was)
}

func imprintAlgName(oid asn1.ObjectIdentifier) (string, error) {
	switch {
	case oid.Equal(oidSHA256):
		return "sha256", nil
	case oid.Equal(oidSHA384):
		return "sha384", nil
	case oid.Equal(oidSHA512):
		return "sha512", nil
	}
	// SHA-1 is deliberately NOT in the list. A collision on the imprint would
	// let one token attest two different checkpoints, which is exactly the
	// property the anchor is supposed to provide — so a SHA-1 token is refused
	// rather than accepted with a note.
	return "", fmt.Errorf("message imprint digest %v is not accepted (sha256, sha384, sha512 only)", oid)
}

func expectedImprintLen(name string) int {
	switch name {
	case "sha256":
		return 32
	case "sha384":
		return 48
	case "sha512":
		return 64
	}
	return 0
}

func newHash(oid asn1.ObjectIdentifier) (hash.Hash, error) {
	switch {
	case oid.Equal(oidSHA256):
		return sha256.New(), nil
	case oid.Equal(oidSHA384):
		return sha512.New384(), nil
	case oid.Equal(oidSHA512):
		return sha512.New(), nil
	}
	return nil, fmt.Errorf("digest algorithm %v is not accepted (sha256, sha384, sha512 only)", oid)
}

func signatureAlgorithm(sigOID, digestOID asn1.ObjectIdentifier) (x509.SignatureAlgorithm, error) {
	switch {
	case sigOID.Equal(oidSHA256WithRSA):
		return x509.SHA256WithRSA, nil
	case sigOID.Equal(oidSHA384WithRSA):
		return x509.SHA384WithRSA, nil
	case sigOID.Equal(oidSHA512WithRSA):
		return x509.SHA512WithRSA, nil
	case sigOID.Equal(oidECDSAWithSHA256):
		return x509.ECDSAWithSHA256, nil
	case sigOID.Equal(oidECDSAWithSHA384):
		return x509.ECDSAWithSHA384, nil
	case sigOID.Equal(oidECDSAWithSHA512):
		return x509.ECDSAWithSHA512, nil
	case sigOID.Equal(oidEd25519):
		return x509.PureEd25519, nil
	case sigOID.Equal(oidRSAEncryption), sigOID.Equal(oidECPublicKey):
		// Some TSAs put the bare key algorithm here and leave the digest to
		// SignerInfo.digestAlgorithm, which RFC 5652 allows.
		switch {
		case digestOID.Equal(oidSHA256):
			if sigOID.Equal(oidRSAEncryption) {
				return x509.SHA256WithRSA, nil
			}
			return x509.ECDSAWithSHA256, nil
		case digestOID.Equal(oidSHA384):
			if sigOID.Equal(oidRSAEncryption) {
				return x509.SHA384WithRSA, nil
			}
			return x509.ECDSAWithSHA384, nil
		case digestOID.Equal(oidSHA512):
			if sigOID.Equal(oidRSAEncryption) {
				return x509.SHA512WithRSA, nil
			}
			return x509.ECDSAWithSHA512, nil
		}
	}
	return x509.UnknownSignatureAlgorithm,
		fmt.Errorf("signature algorithm %v with digest %v is not accepted", sigOID, digestOID)
}

func parseCerts(raw asn1.RawValue) ([]*x509.Certificate, error) {
	if len(raw.Bytes) == 0 {
		return nil, errors.New("token carries no certificates")
	}
	certs, err := x509.ParseCertificates(raw.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certificate set does not parse: %w", err)
	}
	if len(certs) == 0 {
		return nil, errors.New("token carries no certificates")
	}
	return certs, nil
}

// issuerAndSerial is the default SignerIdentifier of RFC 5652.
type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

func findSigner(certs []*x509.Certificate, sid asn1.RawValue) (*x509.Certificate, error) {
	// [0] IMPLICIT SubjectKeyIdentifier
	if sid.Class == asn1.ClassContextSpecific && sid.Tag == 0 {
		for _, c := range certs {
			if len(c.SubjectKeyId) > 0 && string(c.SubjectKeyId) == string(sid.Bytes) {
				return c, nil
			}
		}
		return nil, errors.New("no enclosed certificate matches the signer subject key identifier")
	}
	var ias issuerAndSerial
	if _, err := asn1.Unmarshal(sid.FullBytes, &ias); err != nil {
		return nil, fmt.Errorf("signer identifier does not parse: %w", err)
	}
	for _, c := range certs {
		if c.SerialNumber.Cmp(ias.Serial) == 0 && string(c.RawIssuer) == string(ias.Issuer.FullBytes) {
			return c, nil
		}
	}
	return nil, errors.New("no enclosed certificate matches the signer issuer and serial")
}

func parseAttrs(setContent []byte) ([]attribute, error) {
	var out []attribute
	rest := setContent
	for len(rest) > 0 {
		var a attribute
		var err error
		rest, err = asn1.Unmarshal(rest, &a)
		if err != nil {
			return nil, fmt.Errorf("signed attributes do not parse: %w", err)
		}
		out = append(out, a)
	}
	return out, nil
}

// checkSignedAttrs enforces RFC 5652 section 5.3: contentType must name the
// encapsulated content, and messageDigest must be the digest of it. Without
// the second check a signature over signed attributes would say nothing about
// the TSTInfo the token actually carries.
func checkSignedAttrs(attrs []attribute, eContent []byte, digestOID asn1.ObjectIdentifier) error {
	var sawContentType, sawDigest bool
	for _, a := range attrs {
		switch {
		case a.Type.Equal(oidAttrContentTyp):
			if sawContentType {
				return errors.New("contentType appears more than once in the signed attributes")
			}
			sawContentType = true
			var got asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(a.Values.Bytes, &got); err != nil {
				return fmt.Errorf("contentType attribute does not parse: %w", err)
			}
			if !got.Equal(oidTSTInfo) {
				return fmt.Errorf("signed contentType is %v, expected id-ct-TSTInfo", got)
			}
		case a.Type.Equal(oidAttrMsgDigest):
			if sawDigest {
				return errors.New("messageDigest appears more than once in the signed attributes")
			}
			sawDigest = true
			var want []byte
			if _, err := asn1.Unmarshal(a.Values.Bytes, &want); err != nil {
				return fmt.Errorf("messageDigest attribute does not parse: %w", err)
			}
			h, err := newHash(digestOID)
			if err != nil {
				return err
			}
			h.Write(eContent)
			if got := h.Sum(nil); string(got) != string(want) {
				return errors.New("messageDigest attribute does not match the enclosed TSTInfo")
			}
		}
	}
	if !sawContentType {
		return errors.New("signed attributes carry no contentType")
	}
	if !sawDigest {
		return errors.New("signed attributes carry no messageDigest")
	}
	return nil
}

// checkTimeStampingEKU enforces RFC 3161 section 2.3: the TSA certificate
// carries exactly one extended key usage, id-kp-timeStamping. A certificate
// that is also good for, say, TLS server authentication is a certificate whose
// private key is used elsewhere — and the whole value of a timestamp rests on
// that key doing one thing only.
func checkTimeStampingEKU(c *x509.Certificate) error {
	n := len(c.ExtKeyUsage) + len(c.UnknownExtKeyUsage)
	if n != 1 || len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping {
		return fmt.Errorf("signer certificate %q does not carry exactly one extended key usage id-kp-timeStamping",
			c.Subject.CommonName)
	}
	for _, e := range c.Extensions {
		if e.Id.Equal(oidExtKeyUsage) && !e.Critical {
			return fmt.Errorf("signer certificate %q marks its extended key usage non-critical", c.Subject.CommonName)
		}
	}
	return nil
}

// retagAsSet turns the [0] IMPLICIT encoding of the signed attributes into the
// SET OF encoding that RFC 5652 section 5.4 says is the signed byte string.
// Only the identifier octet changes; every length octet stays as it is.
func retagAsSet(full []byte) []byte {
	out := make([]byte, len(full))
	copy(out, full)
	if len(out) > 0 {
		out[0] = 0x31 // universal, constructed, SET
	}
	return out
}
