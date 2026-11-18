package tsa

// Z.3 extensions on a path and Z.4 the path to genTime (format spec 7.5.5).

import (
	"bytes"
	"crypto/sha256"
	"time"
)

// Extensions of Z.3.
const (
	oidBasicConstraints oid = "2.5.29.19"
	oidKeyUsage         oid = "2.5.29.15"
	oidExtKeyUsage      oid = "2.5.29.37"
	oidTimeStamping     oid = "1.3.6.1.5.5.7.3.8"
	oidAnyEKU           oid = "2.5.29.37.0"
)

// pathUnusable are the extensions that make a path unusable, critical or not
// (Z.3).
var pathUnusable = map[oid]bool{
	"2.5.29.30": true, // nameConstraints
	"2.5.29.33": true, // policyMappings
	"2.5.29.36": true, // policyConstraints
	"2.5.29.54": true, // inhibitAnyPolicy
}

// MaxPathDepth is k of Z.4: c0 (the signer) to ck (the root), k <= 8.
const MaxPathDepth = 8

// PathExists reports whether a path after Z.4 leads from the signer that
// step 5 found to root at genTime: c0 (signer) ... ck with ck byte-identical
// to root, 0 <= k <= 8, no certificate twice, intermediates only from the
// token's certificates; issuer(ci) byte-identical to subject(ci+1) and the
// signature of ci holding under the key of ci+1 after Z.2; basicConstraints,
// keyUsage, pathLenConstraint and extended key usage after Z.4; validity of
// every certificate at genTime; the extensions after Z.3. Not checked are
// the signature of the root itself, the keyUsage of the signer (beyond its
// grammar of Z.3) and revocation.
//
// It is an existence statement, and it is decided over positions rather
// than by trying paths one by one: the certificates reachable at position j
// are computed level by level up to j = 8. Every rule that depends on the
// position (cA and keyUsage from j = 1, pathLenConstraint >= j - 1) only gets
// easier at a smaller j, so a walk that repeats a certificate can always be
// shortened to one that does not; "no certificate twice" therefore changes
// nothing, and the order of the search cannot change the result. A token
// with many certificates under one key costs at most 9 times n squared
// signature checks, each pair checked once.
func (t *Token) PathExists(sig Signature, root *Certificate) bool {
	if sig.Signer == nil || root == nil {
		return false
	}
	if !usableOnPath(sig.Signer, 0, t.GenTime) || !signerEKU(sig.Signer) {
		return false
	}
	if bytes.Equal(sig.Signer.DER, root.DER) {
		return true // k = 0: the signer is the root
	}
	// Candidates for c1 ... ck: the token's certificates, with the root
	// taking the place of a byte-identical one.
	cands := []*Certificate{root}
	for _, c := range sig.Certs {
		if !bytes.Equal(c.DER, root.DER) && !bytes.Equal(c.DER, sig.Signer.DER) {
			cands = append(cands, c)
		}
	}
	level := []*Certificate{sig.Signer}
	for j := 1; j <= MaxPathDepth && len(level) > 0; j++ {
		var next []*Certificate
		for _, n := range cands {
			if !usableOnPath(n, j, t.GenTime) {
				continue
			}
			for _, c := range level {
				if bytes.Equal(c.Issuer, n.Subject) && t.signedBy(c, n) {
					if n == root {
						return true
					}
					next = append(next, n)
					break
				}
			}
		}
		level = next
	}
	return false
}

// signedBy reports whether the signature of child holds under the key of
// issuer after Z.2 (the certificate forms of the signature algorithms only).
// Results are kept per pair, so that the search stays cheap.
func (t *Token) signedBy(child, issuer *Certificate) bool {
	k := [2][32]byte{sha256.Sum256(child.DER), sha256.Sum256(issuer.DER)}
	if t.pathCache == nil {
		t.pathCache = map[[2][32]byte]bool{}
	}
	if v, ok := t.pathCache[k]; ok {
		return v
	}
	ok := false
	if sch, err := signatureScheme(child.SigAlg, false, 0); err == nil {
		if key, err := issuer.profileKey(); err == nil && key.family == sch.family {
			ok = key.verify(sch, child.TBS, child.Signature)
		}
	}
	t.pathCache[k] = ok
	return ok
}

// usableOnPath applies Z.3 and the rules of Z.4 that hold for the
// certificate at position j: validity at genTime; at every position, c0
// included, a present basicConstraints, keyUsage or extKeyUsage that follows
// its grammar of Z.3; for j >= 1 basicConstraints with cA TRUE,
// pathLenConstraint (if present) >= j - 1, keyUsage (if present) with
// keyCertSign and an extended key usage (if present) with
// id-kp-timeStamping or anyExtendedKeyUsage.
func usableOnPath(c *Certificate, j int, genTime time.Time) bool {
	if genTime.Before(c.NotBefore) || genTime.After(c.NotAfter) {
		return false
	}
	for _, x := range c.ext {
		if pathUnusable[x.id] {
			return false
		}
		if x.critical && x.id != oidBasicConstraints && x.id != oidKeyUsage && x.id != oidExtKeyUsage {
			return false
		}
	}
	// Z.3 (format spec 7.5.5): one of the three extensions that does not
	// follow its grammar makes the path unusable, also where Z.4 does not
	// evaluate it at this position (the keyUsage of the signer c0, for
	// instance).
	var ca, certSign bool
	pathLen := int64(-1)
	var purposes []oid
	bc, hasBC := c.extensionByID(oidBasicConstraints)
	if hasBC {
		var ok bool
		if ca, pathLen, ok = basicConstraints(bc.value); !ok {
			return false
		}
	}
	ku, hasKU := c.extensionByID(oidKeyUsage)
	if hasKU {
		var ok bool
		if certSign, ok = keyCertSign(ku.value); !ok {
			return false
		}
	}
	eku, hasEKU := c.extensionByID(oidExtKeyUsage)
	if hasEKU {
		var ok bool
		if purposes, ok = extKeyUsage(eku.value); !ok {
			return false
		}
	}
	if j == 0 {
		return true
	}
	if !hasBC || !ca || pathLen >= 0 && pathLen < int64(j-1) {
		return false
	}
	if hasKU && !certSign {
		return false
	}
	if hasEKU {
		found := false
		for _, id := range purposes {
			if id == oidTimeStamping || id == oidAnyEKU {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// signerEKU: c0 carries extKeyUsage marked critical with exactly
// id-kp-timeStamping (RFC 3161 section 2.3, Z.4).
func signerEKU(c *Certificate) bool {
	x, ok := c.extensionByID(oidExtKeyUsage)
	if !ok || !x.critical {
		return false
	}
	ids, ok := extKeyUsage(x.value)
	return ok && len(ids) == 1 && ids[0] == oidTimeStamping
}

// basicConstraints reads SEQUENCE { cA BOOLEAN OPTIONAL, pathLenConstraint
// INTEGER (0..MAX) OPTIONAL }; pathLen is -1 when absent.
func basicConstraints(v []byte) (ca bool, pathLen int64, ok bool) {
	e, err := single(v)
	if err != nil {
		return false, 0, false
	}
	c, err := newCursor(e, "basicConstraints")
	if err != nil {
		return false, 0, false
	}
	pathLen = -1
	if b, found := c.optional(tagBoolean); found {
		if ca, err = boolean(b, "cA"); err != nil {
			return false, 0, false
		}
	}
	if n, found := c.optional(tagInteger); found {
		x, err := bigInt(n, "pathLenConstraint")
		if err != nil || x.Sign() < 0 {
			return false, 0, false
		}
		pathLen = 1 << 30
		if x.IsInt64() && x.Int64() < pathLen {
			pathLen = x.Int64()
		}
	}
	if c.done() != nil {
		return false, 0, false
	}
	return ca, pathLen, true
}

// keyCertSign reads keyUsage BIT STRING after Z.3 (ok false when it does
// not follow it) and reports bit 5 (keyCertSign). A bit counts only where
// the BIT STRING has it: bit 5 is set when more than five bits are used and
// it is one; a one among the unused bits is not read as a bit (T.6 does not
// check that they are zero).
func keyCertSign(v []byte) (set, ok bool) {
	e, err := single(v)
	if err != nil {
		return false, false
	}
	unused, bits, err := bitString(e, "keyUsage")
	if err != nil {
		return false, false
	}
	return 8*len(bits)-unused > 5 && bits[0]&0x04 != 0, true
}

// extKeyUsage reads SEQUENCE SIZE (1..MAX) OF OID.
func extKeyUsage(v []byte) ([]oid, bool) {
	e, err := single(v)
	if err != nil || e.tag() != tagSequence {
		return nil, false
	}
	list, err := children(e, "extKeyUsage")
	if err != nil || len(list) == 0 {
		return nil, false
	}
	var out []oid
	for _, x := range list {
		id, err := readOID(x, "KeyPurposeId")
		if err != nil {
			return nil, false
		}
		out = append(out, id)
	}
	return out, true
}
