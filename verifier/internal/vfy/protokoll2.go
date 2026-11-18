package vfy

// The protocol key list ledger-protokollschluessel/2 of the extension of
// edition 1.10 (format spec 7.4.7a) and the rules of step L1 that span the
// lists of both formats (7.4.10, L1 items 2, 3 and 6): the projection onto
// /1 and the merging of a list /1 with the list /2 it projects, the rules
// between counting candidates (carrying keys, hybrid_ab, log_uri), P, P2,
// P_mldsa and H.
//
// The list /2 is the same protocol key list in a second format, not a fourth
// list: it establishes protocol keys of several methods, each with its alg,
// and names the day hybrid_ab from which on the verifier requires an
// ML-DSA-87 signature for every day entry (step L2 (g')). Every violation of
// 7.4.7a other than I-JSON, the number rule, the size and the format makes the
// list ineffective (reason format_violated), never exit 3.

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
	"louwietec.com/ledger-verify/verifier/internal/tsa"
)

// Methods of the protocol keys (format spec 7.4.7a, registry
// protocol_key_list_2.fields.schluessel.items.fields.alg).
const (
	AlgEd25519  = "ed25519"
	AlgMLDSA87  = "ml-dsa-87"
	mldsaPubB64 = 3456 // characters of mldsa87-pub (format spec 2)
	mldsaPubLen = 2592 // bytes of an ML-DSA-87 public key
	mldsaSigLen = 4627 // bytes of an ML-DSA-87 signature
)

var reLogURI = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:[!-"$-~]*$`)

// checkProtocolList2 judges a candidate after format spec 7.4.7a; reason is
// a code of registry vendor_log.no_protocol_key_reasons when it does not
// count. limitJCS applies the limit of 1 048 576 bytes to UTF-8(JCS(list)),
// for a list in protocol_keys of an extract /2.
func checkProtocolList2(v *jcs.Value, roots map[string]vendorRootInfo, limitJCS bool) (*signedList, string) {
	if limitJCS && len(jcs.Canon(v)) > MaxKeyListBytes {
		return nil, PReasonFormat
	}
	if closed(v, "protocol key list /2", []string{"format", "version", "ausgestellt", "log_id", "log_uri", "erster_tag",
		"fuellerbindung", "hybrid_ab", "orte", "schluessel", "signatur"}) != nil {
		return nil, PReasonFormat
	}
	if f, _ := str(v.Get("format")); f != ProtocolKeyList2Format {
		return nil, PReasonFormat
	}
	l := &signedList{v2: true}
	var ok bool
	if l.version, ok = intRange(v.Get("version"), 1, maxSafe); !ok {
		return nil, PReasonFormat
	}
	if l.ausgestellt, ok = str(v.Get("ausgestellt")); !ok {
		return nil, PReasonFormat
	}
	if _, ok = parseUTC(l.ausgestellt); !ok {
		return nil, PReasonFormat
	}
	if l.logID, ok = str(v.Get("log_id")); !ok || !reKeyID.MatchString(l.logID) {
		return nil, PReasonFormat
	}
	if l.logURI, ok = str(v.Get("log_uri")); !ok || len(l.logURI) > 512 || !reLogURI.MatchString(l.logURI) {
		return nil, PReasonFormat
	}
	if l.ersterTag, ok = str(v.Get("erster_tag")); !ok {
		return nil, PReasonFormat
	}
	erster, ok := parseDate(l.ersterTag, true)
	if !ok {
		return nil, PReasonFormat
	}
	if fb := v.Get("fuellerbindung"); fb.Kind != jcs.KindNull {
		if l.fuellerbindung, ok = str(fb); !ok || !reHex64.MatchString(l.fuellerbindung) {
			return nil, PReasonFormat
		}
	}
	if h := v.Get("hybrid_ab"); h.Kind != jcs.KindNull {
		if l.hybridAb, ok = str(h); !ok {
			return nil, PReasonFormat
		}
		t, ok := parseDate(l.hybridAb, true)
		if !ok || t.Before(erster) {
			return nil, PReasonFormat // at least erster_tag
		}
	}
	orte, ok := array(v.Get("orte"), 2, 4)
	if !ok {
		return nil, PReasonFormat
	}
	for _, o := range orte {
		s, ok := str(o)
		if !ok || !rePlace.MatchString(s) {
			return nil, PReasonFormat
		}
		l.orte = append(l.orte, s)
	}
	if l.keys, ok = readListKeys2(v.Get("schluessel")); !ok {
		return nil, PReasonFormat
	}
	hasEd, hasML := false, false
	for i := range l.keys {
		l.keys[i].rolle = RoleProtocol
		switch l.keys[i].alg {
		case AlgEd25519:
			hasEd = true
		case AlgMLDSA87:
			hasML = true
		}
	}
	// At least one key with alg ed25519; hybrid_ab not null only with a key
	// ml-dsa-87.
	if !hasEd || l.hybridAb != "" && !hasML {
		return nil, PReasonFormat
	}
	wid, sg, root, why := listRoot(v.Get("signatur"), roots)
	switch why {
	case ReasonFormat:
		return nil, PReasonFormat
	case ReasonNoRoot:
		return nil, PReasonNoRoot
	}
	if !verifySig(root.pubkey, unsignedJCS(v), sg) {
		return nil, PReasonSignature
	}
	l.wurzelID, l.rootSource = wid, root.source
	l.jcsBytes = string(jcs.Canon(v))
	l.projection = string(projection1(v))
	return l, ""
}

// readListKeys2 reads the entries of a list /2: exactly alg, key_id,
// pubkey, gueltig_ab, optionally gueltig_bis and widerrufen_ab, all strings;
// key_id and pubkey (as strings) unique; pubkey hex64 with ed25519, mldsa87-pub
// with ml-dsa-87 (3456 characters after B64 giving 2592 bytes), 1 to 8192
// characters from [!-~] with any other alg; the times after 10.7.1.
func readListKeys2(arr *jcs.Value) ([]roleKey, bool) {
	list, ok := array(arr, 1, protoListMaxKeys)
	if !ok {
		return nil, false
	}
	ids, pubs := map[string]bool{}, map[string]bool{}
	var out []roleKey
	for _, e := range list {
		if closed(e, "schluessel[]", []string{"alg", "key_id", "pubkey", "gueltig_ab"}, "gueltig_bis", "widerrufen_ab") != nil {
			return nil, false
		}
		for _, m := range e.Members {
			if m.Value.Kind != jcs.KindString {
				return nil, false
			}
		}
		k := roleKey{keyID: e.Get("key_id").Str, alg: e.Get("alg").Str}
		k.pubkey = e.Get("pubkey").Str
		if !reSigAlg.MatchString(k.alg) || !reKeyID.MatchString(k.keyID) || len(k.pubkey) > 8192 || !rePrintable.MatchString(k.pubkey) {
			return nil, false
		}
		switch k.alg {
		case AlgEd25519:
			if !reHex64.MatchString(k.pubkey) {
				return nil, false
			}
		case AlgMLDSA87:
			if len(k.pubkey) != mldsaPubB64 {
				return nil, false
			}
			b, err := tsa.DecodeB64(k.pubkey)
			if err != nil || len(b) != mldsaPubLen {
				return nil, false
			}
			k.mldsaPub = b
		}
		if ids[k.keyID] || pubs[k.pubkey] {
			return nil, false
		}
		ids[k.keyID], pubs[k.pubkey] = true, true
		k.abS = e.Get("gueltig_ab").Str
		if k.ab, ok = parseUTC(k.abS); !ok {
			return nil, false
		}
		if b := e.Get("gueltig_bis"); b != nil {
			k.bisS = b.Str
			if k.bis, ok = parseUTC(k.bisS); !ok || !k.bis.After(k.ab) {
				return nil, false
			}
		}
		if w := e.Get("widerrufen_ab"); w != nil {
			k.widS = w.Str
			if k.widerr, ok = parseUTC(k.widS); !ok {
				return nil, false
			}
		}
		out = append(out, k)
	}
	return out, true
}

// projection1 is the JCS form of the projection of a list /2 onto /1
// (format spec 7.4.7a, "Projektion"): format ledger-protokollschluessel/1,
// the same values of ausgestellt, erster_tag, fuellerbindung, log_id, orte
// and version, without hybrid_ab, log_uri and signatur, and as schluessel
// exactly the entries with alg ed25519 in the same order, each without alg
// and otherwise character for character equal.
func projection1(v *jcs.Value) []byte {
	u := &jcs.Value{Kind: jcs.KindObject}
	for _, m := range v.Members {
		switch m.Key {
		case "signatur", "hybrid_ab", "log_uri":
			continue
		case "format":
			u.Members = append(u.Members, jcs.Member{Key: "format", Value: &jcs.Value{Kind: jcs.KindString, Str: ProtocolKeyListFormat}})
		case "schluessel":
			arr := &jcs.Value{Kind: jcs.KindArray}
			for _, e := range m.Value.Arr {
				if e.Get("alg").Str != AlgEd25519 {
					continue
				}
				x := &jcs.Value{Kind: jcs.KindObject}
				for _, em := range e.Members {
					if em.Key != "alg" {
						x.Members = append(x.Members, em)
					}
				}
				arr.Arr = append(arr.Arr, x)
			}
			u.Members = append(u.Members, jcs.Member{Key: "schluessel", Value: arr})
		default:
			u.Members = append(u.Members, m)
		}
	}
	return jcs.Canon(u)
}

// carries reports whether b names the key k (the same alg, the same key_id
// with the same pubkey).
func carries(b *signedList, k roleKey) bool {
	for _, x := range b.keys {
		if x.alg == k.alg && x.keyID == k.keyID && x.pubkey == k.pubkey {
			return true
		}
	}
	return false
}

// mergeProjections is the first rule of L1 item 2: a counting candidate /1
// and a counting candidate /2 of the same version and the same wurzel_id,
// the /1 the projection of the /2, are one candidate, the /2.
func mergeProjections(counting []*signedList) []*signedList {
	var out []*signedList
	for _, a := range counting {
		merged := false
		if !a.v2 {
			for _, b := range counting {
				if b.v2 && b.version == a.version && b.wurzelID == a.wurzelID && b.projection == a.unsigned {
					merged = true
					break
				}
			}
		}
		if !merged {
			out = append(out, a)
		}
	}
	return out
}

// selectProtocolLists is L1 item 2 over the candidates of both formats after
// merging: P is the counting candidate of the largest version, P2 the
// counting candidate /2 of the largest version; none (lists_contradictory)
// when two have one version and different bytes, name different log_id or
// erster_tag, name different fuellerbindung other than null or null after a
// value, a later one lacks a key of an earlier one it must carry (a /2 every
// key, a /1 every key with alg ed25519), two /2 name different hybrid_ab
// other than null or a /2 names null after a /2 of a smaller version with a
// value, or two /2 name different log_uri; with extracts, log_id_differs when
// one names another log_id than the extracts.
func selectProtocolLists(counting []*signedList, extractLogID string) (p, p2 *signedList, reason string) {
	counting = mergeProjections(counting)
	if len(counting) == 0 {
		return nil, nil, ""
	}
	sort.SliceStable(counting, func(i, j int) bool { return counting[i].version < counting[j].version })
	for i, a := range counting {
		for _, b := range counting[i+1:] {
			// b has the larger version, or the same: then the bytes differ.
			if a.version == b.version || a.logID != b.logID || a.ersterTag != b.ersterTag {
				return nil, nil, PReasonContradictory
			}
			if a.fuellerbindung != "" && a.fuellerbindung != b.fuellerbindung {
				return nil, nil, PReasonContradictory
			}
			for _, k := range a.keys {
				if (b.v2 || k.alg == AlgEd25519) && !carries(b, k) {
					return nil, nil, PReasonContradictory
				}
			}
			if a.v2 && b.v2 {
				if a.hybridAb != "" && a.hybridAb != b.hybridAb {
					// Two values, or a value and then null.
					return nil, nil, PReasonContradictory
				}
				if a.logURI != b.logURI {
					return nil, nil, PReasonContradictory
				}
			}
		}
	}
	if extractLogID != "" {
		for _, c := range counting {
			if c.logID != extractLogID {
				return nil, nil, PReasonLogID
			}
		}
	}
	p = counting[len(counting)-1]
	for _, c := range counting {
		if c.v2 {
			p2 = c
		}
	}
	return p, p2, ""
}

// protoRoleKeys are the entries the role check reads for the protocol key
// list (L1 item 3, 10.7.4): every entry of P and of P2, whatever its alg.
func (kr *keyRoles) protoRoleKeys() []roleKey {
	var out []roleKey
	if kr.p != nil {
		out = append(out, kr.p.keys...)
	}
	if kr.p2 != nil && kr.p2 != kr.p {
		out = append(out, kr.p2.keys...)
	}
	return out
}

func protoHasPub(keys []roleKey, pub string) bool {
	for _, k := range keys {
		if k.pubkey == pub {
			return true
		}
	}
	return false
}

// mldsaKeys are P_mldsa: the keys of P2 with alg ml-dsa-87, by key_id
// (L1 item 6); empty without P2.
func (r *run) mldsaKeys() map[string]roleKey {
	out := map[string]roleKey{}
	if kr := r.roles; kr != nil && kr.p2 != nil {
		for _, k := range kr.p2.keys {
			if k.alg == AlgMLDSA87 {
				out[k.keyID] = k
			}
		}
	}
	return out
}

// hybridFrom is H, hybrid_ab of P2 (L1 item 6); "" for null and without P2.
func (r *run) hybridFrom() string {
	if kr := r.roles; kr != nil && kr.p2 != nil {
		return kr.p2.hybridAb
	}
	return ""
}

// PublishedTestMLDSA87 are the SHA-256 values of the 2592 bytes of the public
// keys of the ML-DSA-87 test keys of the vendor in registry
// verifier.timestamp_profile.published_test_keys (kind ml_dsa_87, format spec
// 7.4.5a, 7.5.7); a condition that rests on one of them gives the note
// published_test_key_credited (10.9.6).
var PublishedTestMLDSA87 = []string{
	"39ce94c0a85b526487591ff462eb68fda1fb8b6d012d650b038c65bfbc4178ff", // vendor-log-mldsa-test-001
	"0139e2e03f9a65d7b1a10e5c94d23c45c8541fe0f35e2ae200d75f9e6cce6695", // vendor-log-mldsa-test-002
	"cccdef8f1dd82502a7992109363cdd65f517e02c8c605c6ae1b7999b520edb02", // signierdienst-hedged-probe
	"6cfb8e368de9051d29f0a77ec9039866b148e8063d1c176f65d5b5f9028a4642", // key of the cross vectors
}

// isPublishedTestMLDSA87 reports whether the public key pk (2592 bytes) is
// one of PublishedTestMLDSA87.
func isPublishedTestMLDSA87(pk []byte) bool {
	h := sha256.Sum256(pk)
	s := hex.EncodeToString(h[:])
	for _, k := range PublishedTestMLDSA87 {
		if k == s {
			return true
		}
	}
	return false
}
