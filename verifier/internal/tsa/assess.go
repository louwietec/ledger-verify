package tsa

// The mapping of format spec 7.5.7 for one time stamp, independent of a
// chain: the rows of the table in their order, the topmost that applies
// decides, against the roots of the purpose given (log or chain). This is
// the helper mode of spec/testvectors/README 10.4, which says that with
// --purpose chain "die oberste zutreffende Zeile" decides. The verification
// of a package does not use this mapping: there a time witness follows the
// steps of 7.3 and a day time stamp follows 7.4.6.

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

// Purposes of roots for time stamps (format spec 7.5.7).
const (
	PurposeChain     = "chain"
	PurposeQualified = "qualified"
	PurposeLog       = "log"
)

// States of a time stamp (registry verifier.timestamp_profile.day_token_states).
const (
	StateDefective   = "defective"
	StateUnconfirmed = "unconfirmed"
	StateConfirmed   = "confirmed"
)

// Cases of format spec 7.5.7 (registry verifier.timestamp_profile.outcomes).
const (
	CaseGrammar        = "b64_size_or_grammar_t"
	CaseImprint        = "imprint_wrong"
	CaseNotPerformable = "step_5_not_performable"
	CaseFailed         = "step_5_failed"
	CaseZ6Violated     = "z6_failed"
	CaseZ6NotCheckable = "z6_not_checkable"
	CaseNoPath         = "no_path_to_root_of_purpose"
	CaseTestKey        = "published_test_key"
)

// PublishedTestSPKI are the SPKI SHA-256 values of the keys of time-stamping
// authorities in registry verifier.timestamp_profile.published_test_keys
// (format spec 7.5.7): a signer or a root with such a key confirms no time
// stamp and is credited for no condition of the evidence level.
var PublishedTestSPKI = []string{
	"0ee470ade299184118b50cff3ac1d7f671a8eb98b0097a230df0912db863aac1", // test time-stamping authority of the test corpus
	"872128209ec25a77716b9ac3016ea1702bc7ba425358a470dc5feba2542d8f6d", // root of the Ed25519 time-stamping authority of the test corpus
	"547cbb047458edd28eec25389eb560f4a61d2361b22a84c86178489088804738", // signer of the Ed25519 time-stamping authority of the test corpus
	"1e99d749684e30628b78ac24290f52fafc662d604c7b9fc4f05dd96ad32eb953", // signer of the test corpus on brainpoolP256r1
}

// IsPublishedTestKey reports whether the key of c is in PublishedTestSPKI.
func IsPublishedTestKey(c *Certificate) bool {
	if c == nil {
		return false
	}
	h := c.SPKISHA256()
	s := hex.EncodeToString(h[:])
	for _, k := range PublishedTestSPKI {
		if k == s {
			return true
		}
	}
	return false
}

// Assessment is the judgement of one time stamp after format spec 7.5.7.
type Assessment struct {
	Purpose string
	State   string // StateDefective, StateUnconfirmed or StateConfirmed
	Case    string // the topmost row that decides; "" when confirmed
	Detail  string
	// Token is nil when the token violates B64, the size limit or grammar T.
	Token     *Token
	Signature Signature
	Z6        string // Z6Bound, Z6Violated, Z6NotCheckable; "" when not reached
	QS        string // rule QS; "" without a token
	// PathTo has one element per root: whether a path after Z.4 leads to it.
	PathTo []bool
}

// Assess judges a DER token over the stamped bytes against the roots of one
// purpose. For both purposes the rows of 7.5.7 are taken in the order of the
// table and the topmost that applies decides, with the states of the column
// "Tageszeitstempel" (spec/testvectors/README 10.4: "Mit --purpose chain und
// dieser Wurzel folgen die Ergebnisse aus der Tabelle in 7.5.7 (die oberste
// zutreffende Zeile ...)"); the purpose only selects the roots. So the rows
// of Z.6 and of a published test key count for PurposeChain as well. In a
// chain neither changes the finding of a TIME_ANCHOR (7.5.6, 7.5.7, column
// TIME_ANCHOR); this function judges no chain.
func Assess(der, stamped []byte, roots []*Certificate, purpose string) Assessment {
	a := Assessment{Purpose: purpose}
	set := func(state, cs, detail string) Assessment {
		a.State, a.Case, a.Detail = state, cs, detail
		return a
	}
	tok, err := ParseToken(der)
	if err != nil {
		return set(StateDefective, CaseGrammar, err.Error())
	}
	a.Token = tok
	a.QS = tok.QualifiedStatement()
	h, _ := sha2(map[string]oid{"sha256": oidSHA256, "sha384": oidSHA384, "sha512": oidSHA512}[tok.HashAlgorithm])
	if !bytes.Equal(digest(h, stamped), tok.HashedMessage) {
		return set(StateDefective, CaseImprint, fmt.Sprintf("the imprint (%s) is not the hash of the stamped bytes", tok.HashAlgorithm))
	}
	a.Signature = tok.CheckSignature()
	if !a.Signature.Performable {
		return set(StateUnconfirmed, CaseNotPerformable, a.Signature.Reason)
	}
	if !a.Signature.Valid {
		return set(StateDefective, CaseFailed, a.Signature.Reason)
	}
	z6, z6why := tok.Z6(a.Signature.Signer)
	a.Z6 = z6
	a.PathTo = make([]bool, len(roots))
	anyPath, anyUsable := false, false
	for i, r := range roots {
		a.PathTo[i] = tok.PathExists(a.Signature, r)
		if a.PathTo[i] {
			anyPath = true
			if !IsPublishedTestKey(r) {
				anyUsable = true
			}
		}
	}
	switch z6 {
	case Z6Violated:
		return set(StateDefective, CaseZ6Violated, z6why)
	case Z6NotCheckable:
		return set(StateUnconfirmed, CaseZ6NotCheckable, z6why)
	}
	if !anyPath {
		return set(StateUnconfirmed, CaseNoPath, fmt.Sprintf("no path after Z.4 at genTime to a root of the purpose %s", purpose))
	}
	// Format spec 7.5.7: the row applies when the signer's key is listed or
	// when every root with a path after Z.4 is listed; a path to a root that
	// is not listed lets the following rows decide.
	if IsPublishedTestKey(a.Signature.Signer) || !anyUsable {
		return set(StateUnconfirmed, CaseTestKey, "the key of the signer or of the root is a published test key")
	}
	return set(StateConfirmed, "", "")
}
