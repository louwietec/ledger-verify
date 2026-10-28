package tsa

// Z.1 certificates (format spec 7.5.3): the grammar every element of
// certificates and every certificate the auditor supplies has to follow.
// Names are compared as bytes and never interpreted; extensions are read only
// where Z.3 to Z.5 read them.

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
	"time"
	"unicode/utf8"
)

// Certificate is a certificate read after Z.1.
type Certificate struct {
	DER       []byte    // the whole certificate
	TBS       []byte    // tbsCertificate, the signed bytes
	SigAlg    algorithm // the outer signatureAlgorithm
	Signature []byte    // signatureValue without the unused-bits octet
	Serial    *big.Int
	Issuer    []byte // the issuer Name, whole TLV
	Subject   []byte // the subject Name, whole TLV
	NotBefore time.Time
	NotAfter  time.Time
	SPKI      []byte // subjectPublicKeyInfo, whole TLV
	keyAlg    algorithm
	keyBits   []byte
	ext       []extension
}

// extension is one Extension of a certificate or of the TSTInfo.
type extension struct {
	id       oid
	critical bool
	value    []byte // the content of extnValue: exactly one DER TLV
}

// SPKISHA256 is the SHA-256 value of the DER of subjectPublicKeyInfo, the
// form in which registry published_test_keys names keys of time-stamping
// authorities.
func (c *Certificate) SPKISHA256() [32]byte { return sha256.Sum256(c.SPKI) }

// ParseCertificate reads one certificate after Z.1: DER after T.6, nothing
// after it.
func ParseCertificate(der []byte) (*Certificate, error) {
	e, err := single(der)
	if err != nil {
		return nil, fmt.Errorf("Z.1: %w", err)
	}
	c, err := readCertificate(e)
	if err != nil {
		return nil, fmt.Errorf("Z.1: %w", err)
	}
	return c, nil
}

func readCertificate(e element) (*Certificate, error) {
	outer, err := newCursor(e, "Certificate")
	if err != nil {
		return nil, err
	}
	tbsE, err := outer.take(tagSequence, "tbsCertificate")
	if err != nil {
		return nil, err
	}
	sigAlgE, err := outer.take(tagSequence, "signatureAlgorithm")
	if err != nil {
		return nil, err
	}
	sigE, err := outer.take(tagBitString, "signatureValue")
	if err != nil {
		return nil, err
	}
	if err := outer.done(); err != nil {
		return nil, err
	}
	c := &Certificate{DER: e.full, TBS: tbsE.full}
	if c.SigAlg, err = readAlgorithm(sigAlgE, "signatureAlgorithm"); err != nil {
		return nil, err
	}
	unused, sig, err := bitString(sigE, "signatureValue")
	if err != nil {
		return nil, err
	}
	if unused != 0 {
		return nil, derErr("signatureValue has %d unused bits", unused)
	}
	c.Signature = sig

	tbs, err := newCursor(tbsE, "tbsCertificate")
	if err != nil {
		return nil, err
	}
	verE, err := tbs.take(tagCtx0Cons, "version")
	if err != nil {
		return nil, err
	}
	verInt, err := single(verE.content)
	if err != nil || verInt.tag() != tagInteger {
		return nil, derErr("version is not [0] EXPLICIT INTEGER")
	}
	if v, err := smallInt(verInt, "version"); err != nil || v != 2 {
		return nil, derErr("version is not 2 (v3)")
	}
	serialE, err := tbs.take(tagInteger, "serialNumber")
	if err != nil {
		return nil, err
	}
	if c.Serial, err = bigInt(serialE, "serialNumber"); err != nil {
		return nil, err
	}
	if c.Serial.Sign() <= 0 || len(serialE.content) > 21 {
		return nil, derErr("serialNumber is not positive with at most 21 octets")
	}
	sigInner, err := tbs.take(tagSequence, "signature")
	if err != nil {
		return nil, err
	}
	if _, err := readAlgorithm(sigInner, "signature"); err != nil {
		return nil, err
	}
	if !bytes.Equal(sigInner.full, sigAlgE.full) {
		return nil, derErr("tbsCertificate.signature differs from signatureAlgorithm")
	}
	issuerE, err := tbs.take(tagSequence, "issuer")
	if err != nil {
		return nil, err
	}
	if err := checkName(issuerE, "issuer"); err != nil {
		return nil, err
	}
	c.Issuer = issuerE.full
	valE, err := tbs.take(tagSequence, "validity")
	if err != nil {
		return nil, err
	}
	val, err := newCursor(valE, "validity")
	if err != nil {
		return nil, err
	}
	nb, err := val.next("notBefore")
	if err != nil {
		return nil, err
	}
	na, err := val.next("notAfter")
	if err != nil {
		return nil, err
	}
	if err := val.done(); err != nil {
		return nil, err
	}
	if c.NotBefore, err = readCertTime(nb, "notBefore"); err != nil {
		return nil, err
	}
	if c.NotAfter, err = readCertTime(na, "notAfter"); err != nil {
		return nil, err
	}
	subjE, err := tbs.take(tagSequence, "subject")
	if err != nil {
		return nil, err
	}
	if err := checkName(subjE, "subject"); err != nil {
		return nil, err
	}
	c.Subject = subjE.full
	spkiE, err := tbs.take(tagSequence, "subjectPublicKeyInfo")
	if err != nil {
		return nil, err
	}
	spki, err := newCursor(spkiE, "subjectPublicKeyInfo")
	if err != nil {
		return nil, err
	}
	kaE, err := spki.take(tagSequence, "algorithm")
	if err != nil {
		return nil, err
	}
	if c.keyAlg, err = readAlgorithm(kaE, "subjectPublicKeyInfo.algorithm"); err != nil {
		return nil, err
	}
	kbE, err := spki.take(tagBitString, "subjectPublicKey")
	if err != nil {
		return nil, err
	}
	if err := spki.done(); err != nil {
		return nil, err
	}
	unused, kb, err := bitString(kbE, "subjectPublicKey")
	if err != nil {
		return nil, err
	}
	if unused != 0 {
		return nil, derErr("subjectPublicKey has %d unused bits", unused)
	}
	c.SPKI, c.keyBits = spkiE.full, kb
	if extE, ok := tbs.optional(tagCtx3Cons); ok {
		inner, err := single(extE.content)
		if err != nil || inner.tag() != tagSequence {
			return nil, derErr("extensions are not [3] EXPLICIT SEQUENCE")
		}
		list, err := children(inner, "extensions")
		if err != nil {
			return nil, err
		}
		if len(list) == 0 {
			return nil, derErr("extensions hold no Extension")
		}
		if c.ext, err = readExtensions(list); err != nil {
			return nil, err
		}
		// Z.1 (format spec 7.5.3): the content of extnValue of an extension
		// a rule reads is DER after T.6 throughout; a violation violates Z.1
		// for this certificate. Of every other extension only the outer TLV
		// is checked (readExtensions).
		for _, x := range c.ext {
			if readByRule[x.id] {
				if err := derThroughout(x.value); err != nil {
					return nil, fmt.Errorf("extnValue of %s: %w", x.id, err)
				}
			}
		}
	}
	// No issuerUniqueID [1], no subjectUniqueID [2], nothing else.
	if err := tbs.done(); err != nil {
		return nil, err
	}
	return c, nil
}

// checkName checks Name ::= SEQUENCE OF SET SIZE (1..MAX) OF SEQUENCE { OID,
// one TLV }.
func checkName(e element, what string) error {
	rdns, err := children(e, what)
	if err != nil {
		return err
	}
	for _, rdn := range rdns {
		if rdn.tag() != tagSet {
			return derErr("%s: a RelativeDistinguishedName is not a SET", what)
		}
		atvs, err := children(rdn, what)
		if err != nil {
			return err
		}
		if len(atvs) == 0 {
			return derErr("%s: an empty RelativeDistinguishedName", what)
		}
		for _, atv := range atvs {
			c, err := newCursor(atv, what+" attribute")
			if err != nil {
				return err
			}
			t, err := c.take(tagOID, "type")
			if err != nil {
				return err
			}
			if _, err := readOID(t, what+" attribute type"); err != nil {
				return err
			}
			if _, err := c.next("value"); err != nil {
				return err
			}
			if err := c.done(); err != nil {
				return err
			}
		}
	}
	return nil
}

// readByRule are the extensions of a certificate a rule reads:
// basicConstraints, keyUsage and extKeyUsage (Z.3, Z.4) and
// subjectKeyIdentifier (Z.5). Z.1 (format spec 7.5.3) requires the content
// of their extnValue to be DER after T.6.
var readByRule = map[oid]bool{oidBasicConstraints: true, oidKeyUsage: true, oidExtKeyUsage: true, oidSKI: true}

// readExtensions reads Extension ::= SEQUENCE { extnID OID, critical
// BOOLEAN OPTIONAL, extnValue OCTET STRING }: critical, if encoded, 00 or FF
// (an explicitly encoded FALSE is accepted, T.6); no extnID twice; extnValue
// exactly one DER TLV, of which only the outer TLV is checked here. It serves
// certificates and the extensions of the TSTInfo (rule QS) alike; the
// content checks of Z.1 are readCertificate's.
func readExtensions(list []element) ([]extension, error) {
	var out []extension
	seen := map[oid]bool{}
	for _, xe := range list {
		c, err := newCursor(xe, "Extension")
		if err != nil {
			return nil, err
		}
		idE, err := c.take(tagOID, "extnID")
		if err != nil {
			return nil, err
		}
		id, err := readOID(idE, "extnID")
		if err != nil {
			return nil, err
		}
		x := extension{id: id}
		if b, ok := c.optional(tagBoolean); ok {
			if x.critical, err = boolean(b, "critical"); err != nil {
				return nil, err
			}
		}
		v, err := c.take(tagOctetString, "extnValue")
		if err != nil {
			return nil, err
		}
		if err := c.done(); err != nil {
			return nil, err
		}
		if _, err := single(v.content); err != nil {
			return nil, fmt.Errorf("extnValue of %s: %w", id, err)
		}
		if seen[id] {
			return nil, derErr("extnID %s twice", id)
		}
		seen[id] = true
		x.value = v.content
		out = append(out, x)
	}
	return out, nil
}

// extensionByID returns the extension with the given extnID.
func (c *Certificate) extensionByID(id oid) (extension, bool) {
	for _, x := range c.ext {
		if x.id == id {
			return x, true
		}
	}
	return extension{}, false
}

// SubjectCommonName returns the text of the first commonName (2.5.4.3) of
// the subject held in a UTF8String, PrintableString or IA5String, for display
// only; "" when there is none. Matching never uses it: names are compared as
// bytes (Z.1).
func (c *Certificate) SubjectCommonName() string {
	e, err := single(c.Subject)
	if err != nil {
		return ""
	}
	rdns, _ := children(e, "subject")
	for _, rdn := range rdns {
		atvs, _ := children(rdn, "subject")
		for _, atv := range atvs {
			cur, err := newCursor(atv, "attribute")
			if err != nil {
				continue
			}
			t, err1 := cur.take(tagOID, "type")
			v, err2 := cur.next("value")
			if err1 != nil || err2 != nil {
				continue
			}
			if id, err := readOID(t, "type"); err != nil || id != "2.5.4.3" {
				continue
			}
			switch v.tag() {
			case 0x0c, 0x13, 0x16:
				if utf8.Valid(v.content) {
					return string(v.content)
				}
			}
		}
	}
	return ""
}
