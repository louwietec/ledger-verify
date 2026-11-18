// Package tsa implements the time-stamp profile of the LEDGER specification
// (format spec 7.5, from edition 1.10): how a verifier reads and checks an
// RFC 3161 TimeStampToken, byte for byte, for the time witnesses of a chain
// (7.3), the time stamps of the vendor log's day entries (7.4.6) and the
// conditions of the evidence level (10.9).
//
// Spec 7.5 makes the result depend on its rules alone and not on a
// certificate library or its edition: time stamps travel unsigned, and two
// verifiers that read one token differently could be driven apart without a
// signed byte changing. Therefore nothing here parses with encoding/asn1 or
// crypto/x509. der.go reads strict DER (T.6), token.go the envelope (grammar
// T, steps 2 to 5, Z.5, Z.6 and rule QS), cert.go certificates (Z.1), z2.go
// keys and signature algorithms (Z.2) and path.go the path to a root (Z.3,
// Z.4). The standard library contributes only the primitives: SHA-2,
// RSASSA-PKCS1-v1_5, RSASSA-PSS, ECDSA and Ed25519.
//
// The package judges tokens; it reports no finding. Which finding or state a
// result makes is the caller's mapping after spec 7.5.7 (Assess, and the
// time witness check of the verifier).
package tsa

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Limits of format spec 7.3 step 2 and 7.4.6 (registry
// verifier.timestamp_profile).
const (
	MaxTokenDER   = 16384
	MaxTokenB64   = 21848
	oidSignedData = oid("1.2.840.113549.1.7.2")
	oidTSTInfo    = oid("1.2.840.113549.1.9.16.1.4")
	oidAttrCT     = oid("1.2.840.113549.1.9.3")
	oidAttrMD     = oid("1.2.840.113549.1.9.4")
	oidSigCert    = oid("1.2.840.113549.1.9.16.2.12")
	oidSigCertV2  = oid("1.2.840.113549.1.9.16.2.47")
	oidQCStmts    = oid("1.3.6.1.5.5.7.1.3")
	oidQTST       = oid("0.4.0.19422.1.1")
	oidSKI        = oid("2.5.29.14")
)

// Token is a TimeStampToken that follows grammar T (format spec 7.5.2).
// Everything in it is still only what the token claims about itself.
type Token struct {
	DER []byte

	// TSTInfo (T.5).
	Policy        string // dotted OID
	HashAlgorithm string // sha256, sha384 or sha512
	HashedMessage []byte
	Serial        *big.Int
	GenTime       time.Time // full precision, UTC
	GenTimeRaw    string    // the GeneralizedTime as written
	hasExt        bool
	extContent    []byte // the content of extensions [1]
	eContent      []byte // the TSTInfo DER, what messageDigest covers

	// SignedData and SignerInfo (T.2, T.4).
	hasCerts bool
	certTLVs []element
	// certSplitErr is set when the content of certificates does not split
	// into TLVs: step 5 is then not performable (5a), grammar T holds
	// (format spec 7.5.2, T.2).
	certSplitErr error
	sid          element
	digestAlg    algorithm
	signedAttrs  *element // the [0] element, nil when absent
	attrs        []attribute
	sigAlg       algorithm
	signature    []byte

	pathCache map[[2][32]byte]bool
}

// attribute is one signed attribute: SEQUENCE { attrType OID, attrValues
// SET OF } with at least one value.
type attribute struct {
	typ    oid
	values []element
}

// SerialHex is serialNumber in lowercase hexadecimal, the reading tsa_serial
// of a TIME_ANCHOR (format spec 4.22).
//
// Format spec 4.22: the value in hexadecimal without leading zeros, "0" for
// zero and with "-" before a negative value (T.5 admits any INTEGER).
func (t *Token) SerialHex() string { return fmt.Sprintf("%x", t.Serial) }

// GenTimeMillis is genTime truncated (not rounded) to whole milliseconds in
// the form YYYY-MM-DDThh:mm:ss.sssZ (format spec 7.3 step 3).
func (t *Token) GenTimeMillis() string { return FormatMillis(t.GenTime) }

// ErrGrammar marks a token that violates the size limit or grammar T: step 2
// fails (TIME_ANCHOR_INVALID; a day time stamp is defective).
var ErrGrammar = errors.New("grammar T")

func grammar(err error) error { return fmt.Errorf("%w: %v", ErrGrammar, err) }

// ParseToken reads a DER TimeStampToken after the size limit of 16 384
// bytes and grammar T. An error means step 2 fails.
func ParseToken(der []byte) (*Token, error) {
	if len(der) > MaxTokenDER {
		return nil, grammar(fmt.Errorf("token of %d bytes, above %d", len(der), MaxTokenDER))
	}
	t, err := parseT(der)
	if err != nil {
		return nil, grammar(err)
	}
	return t, nil
}

func parseT(der []byte) (*Token, error) {
	t := &Token{DER: der}
	// T.1 ContentInfo, nothing after it, nothing after content inside it.
	ciE, err := single(der)
	if err != nil {
		return nil, fmt.Errorf("T.1: %w", err)
	}
	ci, err := newCursor(ciE, "ContentInfo")
	if err != nil {
		return nil, err
	}
	ctE, err := ci.take(tagOID, "contentType")
	if err != nil {
		return nil, err
	}
	if ct, err := readOID(ctE, "contentType"); err != nil || ct != oidSignedData {
		return nil, derErr("T.1: contentType is not id-signedData")
	}
	wrap, err := ci.take(tagCtx0Cons, "content")
	if err != nil {
		return nil, err
	}
	if err := ci.done(); err != nil {
		return nil, err
	}
	sdE, err := single(wrap.content)
	if err != nil {
		return nil, fmt.Errorf("T.1 content: %w", err)
	}

	// T.2 SignedData.
	sd, err := newCursor(sdE, "SignedData")
	if err != nil {
		return nil, err
	}
	verE, err := sd.take(tagInteger, "version")
	if err != nil {
		return nil, err
	}
	if v, err := smallInt(verE, "SignedData version"); err != nil || v < 1 || v > 5 {
		return nil, derErr("T.2: SignedData version outside 1 to 5")
	}
	daE, err := sd.take(tagSet, "digestAlgorithms")
	if err != nil {
		return nil, err
	}
	daList, err := children(daE, "digestAlgorithms")
	if err != nil {
		return nil, err
	}
	var digestAlgs []algorithm
	for _, d := range daList {
		a, err := readAlgorithm(d, "digestAlgorithms element")
		if err != nil {
			return nil, err
		}
		if !a.paramsAbsentOrNull() {
			return nil, derErr("T.4: an element of digestAlgorithms carries parameters")
		}
		digestAlgs = append(digestAlgs, a)
	}
	eciE, err := sd.take(tagSequence, "encapContentInfo")
	if err != nil {
		return nil, err
	}
	if certsE, ok := sd.optional(tagCtx0Cons); ok {
		// T.2: the content of certificates (zero or more TLVs) is checked in
		// step 5; a content that does not split into TLVs makes step 5 not
		// performable (5a) and does not violate T.
		t.hasCerts = true
		t.certTLVs, t.certSplitErr = elements(certsE.content)
	}
	if crlsE, ok := sd.optional(tagCtx1Cons); ok {
		_ = crlsE // only the TLV is read (T.2)
	}
	sisE, err := sd.take(tagSet, "signerInfos")
	if err != nil {
		return nil, err
	}
	if err := sd.done(); err != nil {
		return nil, err
	}

	// T.3 EncapsulatedContentInfo with exactly one TSTInfo.
	eci, err := newCursor(eciE, "EncapsulatedContentInfo")
	if err != nil {
		return nil, err
	}
	ectE, err := eci.take(tagOID, "eContentType")
	if err != nil {
		return nil, err
	}
	if ect, err := readOID(ectE, "eContentType"); err != nil || ect != oidTSTInfo {
		return nil, derErr("T.3: eContentType is not id-ct-TSTInfo")
	}
	ecW, err := eci.take(tagCtx0Cons, "eContent")
	if err != nil {
		return nil, err
	}
	if err := eci.done(); err != nil {
		return nil, err
	}
	octE, err := single(ecW.content)
	if err != nil || octE.tag() != tagOctetString {
		return nil, derErr("T.3: eContent is not [0] EXPLICIT OCTET STRING")
	}
	t.eContent = octE.content
	if err := t.parseTSTInfo(octE.content); err != nil {
		return nil, err
	}

	// T.4 exactly one SignerInfo.
	sis, err := children(sisE, "signerInfos")
	if err != nil {
		return nil, err
	}
	if len(sis) != 1 {
		return nil, derErr("T.2: %d SignerInfos, exactly one required", len(sis))
	}
	if err := t.parseSignerInfo(sis[0], digestAlgs); err != nil {
		return nil, err
	}
	return t, nil
}

// parseTSTInfo reads T.5.
func (t *Token) parseTSTInfo(b []byte) error {
	e, err := single(b)
	if err != nil {
		return fmt.Errorf("T.3: eContent does not hold exactly one TSTInfo: %w", err)
	}
	c, err := newCursor(e, "TSTInfo")
	if err != nil {
		return err
	}
	verE, err := c.take(tagInteger, "version")
	if err != nil {
		return err
	}
	if v, err := smallInt(verE, "TSTInfo version"); err != nil || v != 1 {
		return derErr("T.5: TSTInfo version is not 1")
	}
	polE, err := c.take(tagOID, "policy")
	if err != nil {
		return err
	}
	pol, err := readOID(polE, "policy")
	if err != nil {
		return err
	}
	t.Policy = string(pol)
	miE, err := c.take(tagSequence, "messageImprint")
	if err != nil {
		return err
	}
	mi, err := newCursor(miE, "messageImprint")
	if err != nil {
		return err
	}
	haE, err := mi.take(tagSequence, "hashAlgorithm")
	if err != nil {
		return err
	}
	ha, err := readAlgorithm(haE, "hashAlgorithm")
	if err != nil {
		return err
	}
	hmE, err := mi.take(tagOctetString, "hashedMessage")
	if err != nil {
		return err
	}
	if err := mi.done(); err != nil {
		return err
	}
	h, ok := sha2(ha.oid)
	if !ok || !ha.paramsAbsentOrNull() {
		return derErr("T.5: the imprint algorithm %s is not sha256, sha384 or sha512 without parameters", ha.oid)
	}
	if len(hmE.content) != h.Size() {
		return derErr("T.5: hashedMessage of %d octets for %s", len(hmE.content), hashName(h))
	}
	t.HashAlgorithm, t.HashedMessage = hashName(h), hmE.content
	snE, err := c.take(tagInteger, "serialNumber")
	if err != nil {
		return err
	}
	if t.Serial, err = bigInt(snE, "serialNumber"); err != nil {
		return err
	}
	gtE, err := c.take(tagGenTime, "genTime")
	if err != nil {
		return err
	}
	if t.GenTime, t.GenTimeRaw, err = readGenTime(gtE); err != nil {
		return err
	}
	if accE, ok := c.optional(tagSequence); ok {
		if err := checkAccuracy(accE); err != nil {
			return err
		}
	}
	if ordE, ok := c.optional(tagBoolean); ok {
		if _, err := boolean(ordE, "ordering"); err != nil {
			return err
		}
	}
	if nonceE, ok := c.optional(tagInteger); ok {
		if err := intContent(nonceE, "nonce"); err != nil {
			return err
		}
	}
	if _, ok := c.optional(tagCtx0Cons); ok {
		// tsa [0] EXPLICIT: a TLV read as constructed [0]; its content is
		// not checked (T.5).
	}
	if extE, ok := c.optional(tagCtx1Cons); ok {
		t.hasExt, t.extContent = true, extE.content
	}
	if err := c.done(); err != nil {
		return fmt.Errorf("T.5: %w", err)
	}
	return nil
}

// checkAccuracy reads accuracy SEQUENCE { seconds INTEGER OPTIONAL, millis
// [0] IMPLICIT INTEGER OPTIONAL, micros [1] IMPLICIT INTEGER OPTIONAL }.
func checkAccuracy(e element) error {
	c, err := newCursor(e, "accuracy")
	if err != nil {
		return err
	}
	for _, tag := range []byte{tagInteger, tagCtx0Prim, tagCtx1Prim} {
		if x, ok := c.optional(tag); ok {
			if err := intContent(x, "accuracy"); err != nil {
				return err
			}
		}
	}
	return c.done()
}

// parseSignerInfo reads T.4.
func (t *Token) parseSignerInfo(e element, digestAlgs []algorithm) error {
	c, err := newCursor(e, "SignerInfo")
	if err != nil {
		return err
	}
	verE, err := c.take(tagInteger, "version")
	if err != nil {
		return err
	}
	if v, err := smallInt(verE, "SignerInfo version"); err != nil || v != 1 && v != 3 {
		return derErr("T.4: SignerInfo version is neither 1 nor 3")
	}
	sid, err := c.next("sid")
	if err != nil {
		return err
	}
	if sid.tag() != tagSequence && sid.tag() != tagCtx0Prim {
		return derErr("T.4: sid is neither IssuerAndSerialNumber nor [0] subjectKeyIdentifier")
	}
	// T.4 checks of sid only that it is a SEQUENCE or a primitive [0]; a
	// content that is not { issuer, serialNumber }, even one that does not
	// split into TLVs, matches no certificate in Z.5 (step 5a) and never
	// violates T.
	t.sid = sid
	daE, err := c.take(tagSequence, "digestAlgorithm")
	if err != nil {
		return err
	}
	if t.digestAlg, err = readAlgorithm(daE, "digestAlgorithm"); err != nil {
		return err
	}
	if !t.digestAlg.paramsAbsentOrNull() {
		return derErr("T.4: digestAlgorithm carries parameters")
	}
	listed := false
	for _, a := range digestAlgs {
		// T.4: compared by the OID; absent parameters and NULL count
		// alike.
		if a.oid == t.digestAlg.oid {
			listed = true
		}
	}
	if !listed {
		return derErr("T.4: digestAlgorithm %s is not in digestAlgorithms", t.digestAlg.oid)
	}
	if sa, ok := c.optional(tagCtx0Cons); ok {
		t.signedAttrs = &sa
		if t.attrs, err = parseAttributes(sa); err != nil {
			return err
		}
	}
	saE, err := c.take(tagSequence, "signatureAlgorithm")
	if err != nil {
		return err
	}
	if t.sigAlg, err = readAlgorithm(saE, "signatureAlgorithm"); err != nil {
		return err
	}
	sigE, err := c.take(tagOctetString, "signature")
	if err != nil {
		return err
	}
	t.signature = sigE.content
	if _, ok := c.optional(tagCtx1Cons); ok {
		// unsignedAttrs: only the TLV is read (T.4).
	}
	return c.done()
}

// parseAttributes reads the signed attributes after T.4: every attribute
// SEQUENCE { attrType OID, attrValues SET OF } with at least one value,
// exactly one contentType with exactly one OID value and exactly one
// messageDigest with exactly one OCTET STRING value.
func parseAttributes(sa element) ([]attribute, error) {
	list, err := children(sa, "signedAttrs")
	if err != nil {
		return nil, err
	}
	var out []attribute
	ct, md := 0, 0
	for _, ae := range list {
		c, err := newCursor(ae, "Attribute")
		if err != nil {
			return nil, err
		}
		typE, err := c.take(tagOID, "attrType")
		if err != nil {
			return nil, err
		}
		typ, err := readOID(typE, "attrType")
		if err != nil {
			return nil, err
		}
		valsE, err := c.take(tagSet, "attrValues")
		if err != nil {
			return nil, err
		}
		if err := c.done(); err != nil {
			return nil, err
		}
		vals, err := children(valsE, "attrValues")
		if err != nil {
			return nil, err
		}
		if len(vals) == 0 {
			return nil, derErr("T.4: attribute %s without a value", typ)
		}
		switch typ {
		case oidAttrCT:
			ct++
			if len(vals) != 1 {
				return nil, derErr("T.4: contentType with %d values", len(vals))
			}
			if _, err := readOID(vals[0], "contentType value"); err != nil {
				return nil, err
			}
		case oidAttrMD:
			md++
			if len(vals) != 1 || vals[0].tag() != tagOctetString {
				return nil, derErr("T.4: messageDigest is not exactly one OCTET STRING")
			}
		}
		out = append(out, attribute{typ: typ, values: vals})
	}
	if ct != 1 || md != 1 {
		return nil, derErr("T.4: %d contentType and %d messageDigest attributes, exactly one each required", ct, md)
	}
	return out, nil
}

func (t *Token) attr(typ oid) []attribute {
	var out []attribute
	for _, a := range t.attrs {
		if a.typ == typ {
			out = append(out, a)
		}
	}
	return out
}

// ---------------------------------------------------------------- step 5

// Signature is the outcome of step 5 of format spec 7.3: 5a whether the CMS
// signature can be checked under the profile at all, 5b whether it holds.
type Signature struct {
	// Performable: 5a holds. Otherwise Reason says why, and the token is
	// not checkable (TIME_ANCHOR_UNVERIFIED, never exit 2).
	Performable bool
	// Valid: 5b holds. With Performable and not Valid, Reason says why
	// (TIME_ANCHOR_INVALID).
	Valid  bool
	Reason string
	// Signer is the one certificate Z.5 finds, Certs the distinct
	// certificates of the token (all of them Z.1); both nil unless the
	// certificates were readable.
	Signer *Certificate
	Certs  []*Certificate
}

// CheckSignature performs step 5 (format spec 7.3, 5a and 5b).
func (t *Token) CheckSignature() Signature {
	not := func(format string, a ...any) Signature {
		return Signature{Reason: fmt.Sprintf(format, a...)}
	}
	if t.signedAttrs == nil {
		return not("the token carries no signed attributes")
	}
	if !t.hasCerts {
		return not("the token carries no certificates")
	}
	if t.certSplitErr != nil {
		return not("the content of certificates does not split into TLVs: %v", t.certSplitErr)
	}
	var certs []*Certificate
	for i, ce := range t.certTLVs {
		if ce.tag() != tagSequence {
			return not("element %d of certificates is no certificate", i+1)
		}
		c, err := readCertificate(ce)
		if err != nil {
			return not("element %d of certificates violates Z.1: %v", i+1, err)
		}
		dup := false
		for _, o := range certs {
			if bytes.Equal(o.DER, c.DER) {
				dup = true
			}
		}
		if !dup {
			certs = append(certs, c)
		}
	}
	var matches []*Certificate
	for _, c := range certs {
		if t.sidMatches(c) {
			matches = append(matches, c)
		}
	}
	switch len(matches) {
	case 0:
		return Signature{Reason: "no certificate of the token matches the signer identifier (Z.5)", Certs: certs}
	case 1:
	default:
		return Signature{Reason: fmt.Sprintf("%d certificates of the token match the signer identifier (Z.5)", len(matches)), Certs: certs}
	}
	signer := matches[0]
	res := Signature{Signer: signer, Certs: certs}
	dh, ok := sha2(t.digestAlg.oid)
	if !ok {
		res.Reason = fmt.Sprintf("the digest algorithm %s of the signer is outside the profile (Z.2)", t.digestAlg.oid)
		return res
	}
	sch, err := signatureScheme(t.sigAlg, true, dh)
	if err != nil {
		res.Reason = err.Error() + " (Z.2)"
		return res
	}
	key, err := signer.profileKey()
	if err != nil {
		res.Reason = "the signer key: " + err.Error() + " (Z.2)"
		return res
	}
	if key.family != sch.family {
		res.Reason = fmt.Sprintf("a %s signature algorithm on a %s key (Z.2)", sch.family, key.family)
		return res
	}
	res.Performable = true

	// 5b.
	ct := t.attr(oidAttrCT)[0]
	if v, _ := readOID(ct.values[0], "contentType"); v != oidTSTInfo {
		res.Reason = "the signed attribute contentType does not name id-ct-TSTInfo"
		return res
	}
	md := t.attr(oidAttrMD)[0].values[0].content
	if !bytes.Equal(md, digest(dh, t.eContent)) {
		res.Reason = "messageDigest is not the hash of eContent"
		return res
	}
	signed := append([]byte{tagSet}, t.signedAttrs.full[1:]...)
	if !key.verify(sch, signed, t.signature) {
		res.Reason = "the signature does not hold under the key of the signer certificate"
		return res
	}
	res.Valid = true
	return res
}

// sidMatches is Z.5: an IssuerAndSerialNumber matches the issuer bytes and
// the serialNumber value of a certificate, a [0] subjectKeyIdentifier the
// content of its subjectKeyIdentifier extension.
func (t *Token) sidMatches(c *Certificate) bool {
	if t.sid.tag() == tagCtx0Prim {
		x, ok := c.extensionByID(oidSKI)
		if !ok {
			return false
		}
		ki, err := single(x.value)
		return err == nil && ki.tag() == tagOctetString && bytes.Equal(ki.content, t.sid.content)
	}
	el, err := children(t.sid, "sid")
	if err != nil || len(el) != 2 || el[1].tag() != tagInteger {
		return false
	}
	n, err := bigInt(el[1], "sid serialNumber")
	return err == nil && bytes.Equal(el[0].full, c.Issuer) && n.Cmp(c.Serial) == 0
}

// ---------------------------------------------------------------- Z.6

// Results of Z.6 (format spec 7.5.6).
const (
	Z6Bound        = "bound"
	Z6Violated     = "violated"
	Z6NotCheckable = "not_checkable"
)

// Z6 judges the binding of the signer certificate in the signed attributes
// for the signer that step 5 found. It never changes the finding of a
// TIME_ANCHOR; a day time stamp and condition 4 of the evidence level read
// it.
func (t *Token) Z6(signer *Certificate) (string, string) {
	if signer == nil {
		return Z6NotCheckable, "no signer"
	}
	v1, v2 := t.attr(oidSigCert), t.attr(oidSigCertV2)
	if len(v1) == 0 && len(v2) == 0 {
		return Z6Violated, "neither signingCertificate nor signingCertificateV2 among the signed attributes"
	}
	if len(v1) > 1 || len(v2) > 1 {
		return Z6Violated, "signingCertificate or signingCertificateV2 more than once"
	}
	uncompared := false
	for _, a := range append(v1, v2...) {
		if len(a.values) != 1 {
			return Z6Violated, "an ESS attribute with more than one value"
		}
		ok, compared, why := essBinds(a.values[0], a.typ == oidSigCertV2, signer)
		if !ok {
			return Z6Violated, why
		}
		if !compared {
			uncompared = true
		}
	}
	if uncompared {
		return Z6NotCheckable, "a signingCertificateV2 with a hash outside sha256, sha384 and sha512"
	}
	return Z6Bound, ""
}

// essBinds reads one SigningCertificate (v2: SigningCertificateV2) in DER
// with at least one element in certs and checks certs[0] against the
// signer: certHash (SHA-1 for v1; for v2 hashAlgorithm, default SHA-256)
// and, if present, issuerSerial. compared is false for a v2 whose hash lies
// outside SHA-256, SHA-384 and SHA-512; its issuerSerial still has to match.
func essBinds(v element, v2 bool, signer *Certificate) (ok, compared bool, why string) {
	c, err := newCursor(v, "SigningCertificate")
	if err != nil {
		return false, false, "the ESS attribute value is not a SEQUENCE"
	}
	certsE, err := c.take(tagSequence, "certs")
	if err != nil {
		return false, false, "the ESS attribute has no certs"
	}
	if pol, ok := c.optional(tagSequence); ok {
		_ = pol // policies: no rule reads them; only the outer TLV is checked (Z.6)
	}
	if c.done() != nil {
		return false, false, "the ESS attribute has further elements"
	}
	ids, err := children(certsE, "certs")
	if err != nil || len(ids) == 0 {
		return false, false, "the ESS attribute has no element in certs"
	}
	// Every element of certs must be DER of its type; only certs[0] is
	// compared.
	var first struct {
		h        crypto.Hash
		known    bool
		hash     []byte
		issuerSN *element
	}
	for i, id := range ids {
		ic, err := newCursor(id, "ESSCertID")
		if err != nil {
			return false, false, "an ESSCertID is not a SEQUENCE"
		}
		h, known := crypto.SHA1, true
		if v2 {
			h = crypto.SHA256
			if haE, ok := ic.optional(tagSequence); ok {
				ha, err := readAlgorithm(haE, "ESSCertIDv2 hashAlgorithm")
				if err != nil {
					return false, false, "the hashAlgorithm of an ESSCertIDv2 is malformed"
				}
				// Z.6: the hash of an ESSCertIDv2 is identified by the OID;
				// absent parameters and NULL count alike.
				h, known = sha2(ha.oid)
			}
		}
		hashE, err := ic.take(tagOctetString, "certHash")
		if err != nil {
			return false, false, "an ESSCertID without certHash"
		}
		var isn *element
		if x, ok := ic.optional(tagSequence); ok {
			if err := checkIssuerSerial(x); err != nil {
				return false, false, "an issuerSerial is malformed"
			}
			isn = &x
		}
		if ic.done() != nil {
			return false, false, "an ESSCertID has further elements"
		}
		if i == 0 {
			first.h, first.known, first.hash, first.issuerSN = h, known, hashE.content, isn
		}
	}
	if first.issuerSN != nil && !issuerSerialMatches(*first.issuerSN, signer) {
		return false, false, "issuerSerial does not name the signer"
	}
	if !first.known {
		return true, false, ""
	}
	var sum []byte
	if first.h == crypto.SHA1 {
		s := sha1.Sum(signer.DER) // an identifier here, not an imprint (Z.6)
		sum = s[:]
	} else {
		sum = digest(first.h, signer.DER)
	}
	if !bytes.Equal(sum, first.hash) {
		return false, false, "certHash does not name the signer certificate"
	}
	return true, true, ""
}

// checkIssuerSerial reads IssuerSerial ::= SEQUENCE { issuer GeneralNames,
// serialNumber INTEGER }, GeneralNames a SEQUENCE of at least one TLV.
//
// Z.6 (format spec 7.5.6): an element of GeneralNames with the identifier
// octet A4 (directoryName) holds exactly one Name after Z.1; of every other
// element T.6 checks only the outer TLV. A [4] elsewhere, in the value of an
// otherName for instance, is no directoryName and is not decomposed.
func checkIssuerSerial(e element) error {
	c, err := newCursor(e, "IssuerSerial")
	if err != nil {
		return err
	}
	gn, err := c.take(tagSequence, "issuer")
	if err != nil {
		return err
	}
	names, err := children(gn, "GeneralNames")
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return derErr("empty GeneralNames")
	}
	for _, g := range names {
		if g.tag() != tagCtx4Cons {
			continue
		}
		n, err := single(g.content)
		if err != nil {
			return fmt.Errorf("directoryName: %w", err)
		}
		if n.tag() != tagSequence {
			return derErr("a directoryName does not hold a Name")
		}
		if err := checkName(n, "directoryName"); err != nil {
			return err
		}
	}
	sn, err := c.take(tagInteger, "serialNumber")
	if err != nil {
		return err
	}
	if err := intContent(sn, "serialNumber"); err != nil {
		return err
	}
	return c.done()
}

// issuerSerialMatches: the serial number is the signer's, and one
// directoryName [4] of GeneralNames holds exactly the issuer Name of the
// signer, byte for byte.
//
// This is the reading Z.6 (format spec 7.5.6) states.
func issuerSerialMatches(e element, signer *Certificate) bool {
	el, _ := children(e, "IssuerSerial")
	names, _ := children(el[0], "GeneralNames")
	n, err := bigInt(el[1], "serialNumber")
	if err != nil || n.Cmp(signer.Serial) != 0 {
		return false
	}
	for _, g := range names {
		if g.tag() != tagCtx4Cons {
			continue
		}
		if inner, err := single(g.content); err == nil && bytes.Equal(inner.full, signer.Issuer) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- QS

// Results of rule QS (format spec 7.5.6).
const (
	QSAbsent    = "absent"
	QSPresent   = "present"
	QSMalformed = "malformed"
	QSUnusable  = "unusable"
)

// QualifiedStatement applies rule QS to the extensions of the TSTInfo. It
// never yields a finding and is never part of steps 1 to 6; no byte search
// is used, for the nonce can carry the nine bytes of the identifier.
func (t *Token) QualifiedStatement() string {
	if !t.hasExt {
		return QSAbsent
	}
	list, err := elements(t.extContent)
	if err != nil || len(list) == 0 {
		return QSUnusable
	}
	exts, err := readExtensions(list)
	if err != nil {
		return QSUnusable
	}
	var qc *extension
	for i, x := range exts {
		if x.critical && x.id != oidQCStmts {
			return QSUnusable
		}
		if x.id == oidQCStmts {
			qc = &exts[i]
		}
	}
	if qc == nil {
		return QSAbsent
	}
	seqE, err := single(qc.value)
	if err != nil || seqE.tag() != tagSequence {
		return QSMalformed
	}
	stmts, err := children(seqE, "QCStatements")
	if err != nil {
		return QSMalformed
	}
	present := false
	for _, s := range stmts {
		c, err := newCursor(s, "QCStatement")
		if err != nil {
			return QSMalformed
		}
		idE, err := c.take(tagOID, "statementId")
		if err != nil {
			return QSMalformed
		}
		id, err := readOID(idE, "statementId")
		if err != nil {
			return QSMalformed
		}
		_, _ = c.next("statementInfo") // ANY OPTIONAL, not evaluated
		if c.done() != nil {
			return QSMalformed
		}
		if id == oidQTST {
			present = true
		}
	}
	if present {
		return QSPresent
	}
	return QSAbsent
}
