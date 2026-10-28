package vfy

// Key roles of the vendor (format spec 10.7.2 to 10.7.5, from edition 1.10).
//
// Every vendor key has exactly one role: countersigning (receipts),
// statements (statements and anchor history pages), update_manifest, and
// protocol (day entries of the vendor log). The role list
// ledger-schluesselrollen/1 names the first three, the protocol key list
// ledger-protokollschluessel/1 the last, the list of countersigning keys of
// edition 1.9 is the projection onto countersigning. The role check (R1 to
// R4 of 10.7.4) runs with step L1 of 7.4.10 before the receipts (10.5, stage
// 5, step 4). It compares public keys, never key ids, adds no finding class
// and never ends at exit 2: a contradiction of roles is a statement about the
// vendor's lists or the audit environment, not about the chain.

import (
	"regexp"
	"sort"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
)

// Roles, reasons and notes of registry verifier.key_roles.
const (
	RoleCountersigning = "countersigning"
	RoleStatements     = "statements"
	RoleUpdateManifest = "update_manifest"
	RoleProtocol       = "protocol"

	RolesNotSupplied = "not_supplied"
	RolesEffective   = "effective"
	RolesNotEffect   = "not_effective"

	ReasonFormat        = "format"
	ReasonNoRoot        = "no_matching_root"
	ReasonSignature     = "signature"
	ReasonContradictory = "lists_contradictory"
	ReasonTwoRoles      = "key_in_two_roles"

	NoteUnknownRole    = "unknown_role"
	NoteReceiptOther   = "receipt_key_other_role"
	NotePinDropped     = "pin_dropped"
	RootSourceAuditor  = "vendor_root"
	RootSourceBuiltin  = "builtin"
	SourceRoleList     = "role_list"
	SourcePinned       = "pinned"
	keyRoleListMaxKeys = 256
	protoListMaxKeys   = 64
)

// knownRoles are the roles of registry key_role_list.roles.
var knownRoles = map[string]bool{RoleCountersigning: true, RoleStatements: true, RoleUpdateManifest: true}

// Reasons of registry vendor_log.no_protocol_key_reasons (format spec 7.4.10,
// L1 item 4), in their order.
const (
	PReasonNoList        = "no_list"
	PReasonNoRoot        = "no_matching_root"
	PReasonSignature     = "signature_fails"
	PReasonFormat        = "format_violated"
	PReasonContradictory = "lists_contradictory"
	PReasonTwoRoles      = "key_in_two_roles"
	PReasonLogID         = "log_id_differs"
)

var (
	reRole  = regexp.MustCompile(`^[a-z][a-z_]{0,31}$`)
	rePlace = regexp.MustCompile(`^https://[!-~]{1,248}$`)
)

// KeyRolesStat is the report object key_roles (format spec 10.10.2).
type KeyRolesStat struct {
	Status        string            `json:"status"`
	Reason        *string           `json:"reason"`
	Candidates    int               `json:"candidates"`
	List          *KeyRolesListStat `json:"list"`
	StatementKeys []StatementKeyRef `json:"statement_keys"`
	PinsDropped   []PinDropped      `json:"pins_dropped"`
	Notes         []string          `json:"notes"`
}

// KeyRolesListStat names the effective role list Q.
type KeyRolesListStat struct {
	Version           int64   `json:"version"`
	Ausgestellt       string  `json:"ausgestellt"`
	WurzelID          string  `json:"wurzel_id"`
	RootSource        string  `json:"root_source"`
	EndeDoppelbetrieb *string `json:"ende_doppelbetrieb"`
}

// StatementKeyRef is one statements key that can establish pages.
type StatementKeyRef struct {
	KeyID  string `json:"key_id"`
	Source string `json:"source"`
}

// PinDropped is one pin dropped after R3 (d).
type PinDropped struct {
	KeyID    string `json:"key_id"`
	PinnedAs string `json:"pinned_as"`
	ListedAs string `json:"listed_as"`
}

// roleKey is one entry of a role list or a protocol key list.
type roleKey struct {
	vendorListKey
	keyID string
	rolle string
}

// signedList is a role list or a protocol key list that counts (R1, L1).
type signedList struct {
	jcsBytes    string
	version     int64
	ausgestellt string
	ende        string
	hasEnde     bool
	keys        []roleKey
	wurzelID    string
	rootSource  string
	// protocol key lists only; fuellerbindung "" stands for null (format
	// spec 7.4.7: hex64 or null)
	logID, ersterTag, fuellerbindung string
	orte                             []string
}

func (l *signedList) byPubkey(pub string) (roleKey, bool) {
	for _, k := range l.keys {
		if k.pubkey == pub {
			return k, true
		}
	}
	return roleKey{}, false
}

// vendorRootInfo is a vendor root of the auditor or the built-in one.
type vendorRootInfo struct {
	pubkey string
	source string
}

// keyRoles is the result of the role check for one run.
type keyRoles struct {
	stat KeyRolesStat
	q    *signedList // effective role list
	p    *signedList // effective protocol key list
	// pReason is the reason why no protocol key list is effective
	// (registry vendor_log.no_protocol_key_reasons), "" with P.
	pReason string
	// kcsL are the public keys of K_cs^L, kcsLIDs their key ids (format
	// spec 8.8.4, H2 number 1 looks a server_key_id up by key id).
	kcsL    map[string]bool
	kcsLIDs map[string]bool
	// Remaining pins after R3 (d), key_id -> pubkey.
	statementPins map[string]string
	protocolPins  map[string]string
	// otherRole are the public keys of other roles a receipt may name in
	// the manifest (note receipt_key_other_role); receiptOther is set when
	// one did.
	otherRole    map[string]bool
	receiptOther bool
}

// listRoot finds the root of a list by its wurzel_id.
func listRoot(sig *jcs.Value, roots map[string]vendorRootInfo) (wid, sg string, root vendorRootInfo, reason string) {
	if err := closed(sig, "signatur", []string{"wurzel_id", "sig"}); err != nil {
		return "", "", root, ReasonFormat
	}
	var ok1, ok2 bool
	wid, ok1 = str(sig.Get("wurzel_id"))
	sg, ok2 = str(sig.Get("sig"))
	if !ok1 || !reKeyID.MatchString(wid) || !ok2 || !reHex128.MatchString(sg) {
		return "", "", root, ReasonFormat
	}
	r, ok := roots[wid]
	if !ok {
		return wid, sg, root, ReasonNoRoot
	}
	return wid, sg, r, ""
}

// unsignedJCS is the JCS of a list object without its member signatur, the
// bytes the vendor root signs.
func unsignedJCS(v *jcs.Value) []byte {
	u := &jcs.Value{Kind: jcs.KindObject}
	for _, m := range v.Members {
		if m.Key != "signatur" {
			u.Members = append(u.Members, m)
		}
	}
	return jcs.Canon(u)
}

// readListKeys reads the entries of a list after 10.7.1 (and the member
// rolle for a role list): exactly the members, all strings, key_id and
// pubkey unique, gueltig_bis after gueltig_ab.
func readListKeys(arr *jcs.Value, max int, withRole bool) ([]roleKey, bool) {
	list, ok := array(arr, 1, max)
	if !ok {
		return nil, false
	}
	req := []string{"key_id", "pubkey", "gueltig_ab"}
	if withRole {
		req = append(req, "rolle")
	}
	ids, pubs := map[string]bool{}, map[string]bool{}
	var out []roleKey
	for _, e := range list {
		if closed(e, "schluessel[]", req, "gueltig_bis", "widerrufen_ab") != nil {
			return nil, false
		}
		for _, m := range e.Members {
			if m.Value.Kind != jcs.KindString {
				return nil, false
			}
		}
		k := roleKey{keyID: e.Get("key_id").Str}
		k.pubkey = e.Get("pubkey").Str
		if !reKeyID.MatchString(k.keyID) || !reHex64.MatchString(k.pubkey) || ids[k.keyID] || pubs[k.pubkey] {
			return nil, false
		}
		ids[k.keyID], pubs[k.pubkey] = true, true
		if withRole {
			k.rolle = e.Get("rolle").Str
			if !reRole.MatchString(k.rolle) {
				return nil, false
			}
		}
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

// checkRoleList judges a candidate after format spec 10.7.2: the format, the
// signature of a vendor root with its wurzel_id, and that no entry names the
// public key of that root. reason is format, no_matching_root or signature
// when it does not count.
func checkRoleList(v *jcs.Value, roots map[string]vendorRootInfo) (*signedList, string) {
	if closed(v, "role list", []string{"format", "version", "ausgestellt", "schluessel", "signatur"}, "ende_doppelbetrieb") != nil {
		return nil, ReasonFormat
	}
	if f, _ := str(v.Get("format")); f != KeyRoleListFormat {
		return nil, ReasonFormat
	}
	l := &signedList{}
	var ok bool
	if l.version, ok = intRange(v.Get("version"), 1, maxSafe); !ok {
		return nil, ReasonFormat
	}
	if l.ausgestellt, ok = str(v.Get("ausgestellt")); !ok {
		return nil, ReasonFormat
	}
	if _, ok = parseUTC(l.ausgestellt); !ok {
		return nil, ReasonFormat
	}
	if e := v.Get("ende_doppelbetrieb"); e != nil {
		if l.ende, ok = str(e); !ok {
			return nil, ReasonFormat
		}
		if _, ok = parseUTC(l.ende); !ok {
			return nil, ReasonFormat
		}
		l.hasEnde = true
	}
	if l.keys, ok = readListKeys(v.Get("schluessel"), keyRoleListMaxKeys, true); !ok {
		return nil, ReasonFormat
	}
	for _, k := range l.keys {
		if k.rolle == RoleProtocol {
			return nil, ReasonFormat // reserved: protocol keys stand only in their own list
		}
	}
	wid, sg, root, why := listRoot(v.Get("signatur"), roots)
	if why != "" {
		return nil, why
	}
	if _, named := l.byPubkey(root.pubkey); named {
		return nil, ReasonFormat // an entry names the public key of the root (10.7.2)
	}
	if !verifySig(root.pubkey, unsignedJCS(v), sg) {
		return nil, ReasonSignature
	}
	l.wurzelID, l.rootSource = wid, root.source
	l.jcsBytes = string(jcs.Canon(v))
	return l, ""
}

// checkProtocolList judges a candidate after format spec 7.4.7; reason is a
// code of registry vendor_log.no_protocol_key_reasons when it does not count.
func checkProtocolList(v *jcs.Value, roots map[string]vendorRootInfo) (*signedList, string) {
	if closed(v, "protocol key list", []string{"format", "version", "ausgestellt", "log_id", "erster_tag", "fuellerbindung", "orte", "schluessel", "signatur"}) != nil {
		return nil, PReasonFormat
	}
	if f, _ := str(v.Get("format")); f != ProtocolKeyListFormat {
		return nil, PReasonFormat
	}
	l := &signedList{}
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
	if l.ersterTag, ok = str(v.Get("erster_tag")); !ok {
		return nil, PReasonFormat
	}
	if _, ok = parseDate(l.ersterTag, true); !ok {
		return nil, PReasonFormat
	}
	// 7.4.7: fuellerbindung is hex64, or null when the vendor does not
	// derive its fillers (7.4.4).
	if fb := v.Get("fuellerbindung"); fb == nil || fb.Kind != jcs.KindNull {
		if l.fuellerbindung, ok = str(fb); !ok || !reHex64.MatchString(l.fuellerbindung) {
			return nil, PReasonFormat
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
	if l.keys, ok = readListKeys(v.Get("schluessel"), protoListMaxKeys, false); !ok {
		return nil, PReasonFormat
	}
	for i := range l.keys {
		l.keys[i].rolle = RoleProtocol
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
	return l, ""
}

// rank orders the reasons of candidates that do not count: the candidate
// that came furthest decides (10.7.4: format, no_matching_root, signature).
var roleReasonRank = map[string]int{ReasonFormat: 1, ReasonNoRoot: 2, ReasonSignature: 3}
var protoReasonRank = map[string]int{PReasonFormat: 1, PReasonNoRoot: 2, PReasonSignature: 3}

// selectRoleList is R1 and R2: the counting candidate of the largest
// version, or none (lists_contradictory) when two counting candidates have
// one version and different bytes, a later one lacks an entry of an earlier
// one, or ende_doppelbetrieb changes or disappears.
func selectRoleList(counting []*signedList) (*signedList, string) {
	if len(counting) == 0 {
		return nil, ""
	}
	sort.SliceStable(counting, func(i, j int) bool { return counting[i].version < counting[j].version })
	ende := ""
	for i, a := range counting {
		for _, b := range counting[i+1:] {
			// b has the larger version, or the same: then the bytes differ
			// (candidates are distinct by their JCS bytes).
			if a.version == b.version {
				return nil, ReasonContradictory
			}
			for _, k := range a.keys {
				if !hasEntry(b, k) {
					return nil, ReasonContradictory
				}
			}
			if a.hasEnde && !b.hasEnde {
				return nil, ReasonContradictory
			}
		}
		// Values of ende_doppelbetrieb are compared as strings: the vendor
		// copies the value character for character into every later version.
		if a.hasEnde {
			if ende != "" && a.ende != ende {
				return nil, ReasonContradictory
			}
			ende = a.ende
		}
	}
	return counting[len(counting)-1], ""
}

func hasEntry(l *signedList, k roleKey) bool {
	for _, x := range l.keys {
		if x.keyID == k.keyID && x.pubkey == k.pubkey && x.rolle == k.rolle {
			return true
		}
	}
	return false
}

// selectProtocolList is L1 item 2: the counting candidate of the largest
// version, or none when two have one version and different bytes, name
// different log_id or erster_tag, name different fuellerbindung other than
// null, one names fuellerbindung null and one of a smaller version a value
// (once set, it stays the same in every later version, 7.4.7), a later one
// lacks a key of an earlier one (lists_contradictory), or, with extracts,
// one names another log_id than the extracts (log_id_differs).
func selectProtocolList(counting []*signedList, extractLogID string) (*signedList, string) {
	if len(counting) == 0 {
		return nil, ""
	}
	sort.SliceStable(counting, func(i, j int) bool { return counting[i].version < counting[j].version })
	for i, a := range counting {
		for _, b := range counting[i+1:] {
			// b has the larger version, or the same: then the bytes differ.
			if a.version == b.version || a.logID != b.logID || a.ersterTag != b.ersterTag {
				return nil, PReasonContradictory
			}
			if a.fuellerbindung != "" && a.fuellerbindung != b.fuellerbindung {
				// Two different values, or a value and then null.
				return nil, PReasonContradictory
			}
			for _, k := range a.keys {
				found := false
				for _, x := range b.keys {
					if x.keyID == k.keyID && x.pubkey == k.pubkey {
						found = true
					}
				}
				if !found {
					return nil, PReasonContradictory
				}
			}
		}
	}
	if extractLogID != "" {
		for _, c := range counting {
			if c.logID != extractLogID {
				return nil, PReasonLogID
			}
		}
	}
	return counting[len(counting)-1], ""
}

// vendorRoots collects the auditor's vendor roots and the built-in one by
// wurzel_id with their source (CLI and browser refuse two different keys
// under one wurzel_id before the run, 7.1).
func (r *run) vendorRoots() map[string]vendorRootInfo {
	roots := map[string]vendorRootInfo{}
	for _, w := range r.opt.VendorRoots {
		if CheckVendorRoot(w) != nil {
			continue
		}
		src := RootSourceAuditor
		if w.Builtin {
			src = RootSourceBuiltin
		}
		// 10.10.2: a root that is built in and that the auditor also passes
		// counts as vendor_root (AnkerZusammenfuehren merges the two).
		if prev, ok := roots[w.ID]; ok && prev.source == RootSourceAuditor {
			continue
		}
		roots[w.ID] = vendorRootInfo{pubkey: w.Pubkey, source: src}
	}
	return roots
}

// checkKeyRoles runs the role check of format spec 10.7.4 with step L1 of
// 7.4.10 (items 2 and 3): K_cs^L, the role list Q, the protocol key list P,
// R3 (a) to (d), and the report object key_roles.
func (r *run) checkKeyRoles() {
	kr := &keyRoles{kcsL: map[string]bool{}, kcsLIDs: map[string]bool{}, statementPins: map[string]string{}, protocolPins: map[string]string{}, otherRole: map[string]bool{}}
	r.roles = kr
	roots := r.vendorRoots()
	vt := r.vendor

	// K_cs^L: the package's list of countersigning keys if it is effective,
	// and the effective lists of this format the auditor passes.
	for id, k := range vt.list {
		kr.kcsL[k.pubkey] = true
		kr.kcsLIDs[id] = true
	}
	plain := map[string]string{}
	for id, w := range roots {
		plain[id] = w.pubkey
	}
	var roleCands, protoCands []*jcs.Value
	seenRole, seenProto := map[string]bool{}, map[string]bool{}
	for _, l := range r.opt.VendorKeyLists {
		switch l.Format {
		case VendorListFormat:
			if keys, _, _, _, why := parseVendorList(l.Raw, plain); why == "" {
				for id, k := range keys {
					kr.kcsL[k.pubkey] = true
					kr.kcsLIDs[id] = true
				}
			}
		case KeyRoleListFormat:
			if b := string(jcs.Canon(l.Value)); !seenRole[b] {
				seenRole[b] = true
				roleCands = append(roleCands, l.Value)
			}
		case ProtocolKeyListFormat:
			if b := string(jcs.Canon(l.Value)); !seenProto[b] {
				seenProto[b] = true
				protoCands = append(protoCands, l.Value)
			}
		}
	}
	extractLogID := ""
	for _, x := range r.opt.VendorLogs {
		extractLogID = x.LogID
		if pk := x.Value.Get("protocol_keys"); pk != nil && pk.Kind == jcs.KindObject {
			if b := string(jcs.Canon(pk)); !seenProto[b] {
				seenProto[b] = true
				protoCands = append(protoCands, pk)
			}
		}
	}

	// R1, R2.
	st := &kr.stat
	st.Candidates = len(roleCands)
	var counting []*signedList
	furthest := ""
	for _, c := range roleCands {
		l, why := checkRoleList(c, roots)
		if l != nil {
			counting = append(counting, l)
		} else if roleReasonRank[why] > roleReasonRank[furthest] {
			furthest = why
		}
	}
	q, qWhy := selectRoleList(counting)
	if q == nil && qWhy == "" {
		qWhy = furthest
	}

	// L1 item 2.
	var pCounting []*signedList
	pFurthest := ""
	for _, c := range protoCands {
		l, why := checkProtocolList(c, roots)
		if l != nil {
			pCounting = append(pCounting, l)
		} else if protoReasonRank[why] > protoReasonRank[pFurthest] {
			pFurthest = why
		}
	}
	p, pWhy := selectProtocolList(pCounting, extractLogID)
	switch {
	case p != nil:
	case pWhy != "":
	case len(protoCands) == 0:
		pWhy = PReasonNoList
	default:
		pWhy = pFurthest
	}

	// R3 (a): Q gives a key of K_cs^L another role than countersigning.
	if q != nil {
		for _, k := range q.keys {
			if kr.kcsL[k.pubkey] && k.rolle != RoleCountersigning {
				q, qWhy = nil, ReasonTwoRoles
				break
			}
		}
	}
	// R3 (b): Q and P share a key.
	if q != nil && p != nil {
		for _, k := range p.keys {
			if _, shared := q.byPubkey(k.pubkey); shared {
				q, qWhy, p, pWhy = nil, ReasonTwoRoles, nil, PReasonTwoRoles
				break
			}
		}
	}
	// R3 (c): P shares a key with a countersigning pin or K_cs^L.
	if p != nil {
		for _, k := range p.keys {
			if kr.kcsL[k.pubkey] || pinnedPub(r.opt.VendorKeys, k.pubkey) {
				p, pWhy = nil, PReasonTwoRoles
				break
			}
		}
	}
	kr.q, kr.p, kr.pReason = q, p, pWhy

	// R3 (d): pins against the then effective Q and P.
	drop := func(k VendorKey, as, listedAs string) {
		st.PinsDropped = append(st.PinsDropped, PinDropped{KeyID: k.ID, PinnedAs: as, ListedAs: listedAs})
	}
	for _, k := range r.opt.VendorKeys {
		if q != nil {
			if e, ok := q.byPubkey(k.Pubkey); ok && e.rolle != RoleCountersigning {
				drop(k, RoleCountersigning, e.rolle)
				delete(vt.pinned, k.ID)
			}
		}
	}
	for _, k := range r.opt.VendorStatementKeys {
		switch {
		case q != nil && qRoleOther(q, k.Pubkey, RoleStatements) != "":
			drop(k, RoleStatements, qRoleOther(q, k.Pubkey, RoleStatements))
		case kr.kcsL[k.Pubkey]:
			drop(k, RoleStatements, RoleCountersigning)
		case p != nil && hasPub(p, k.Pubkey):
			drop(k, RoleStatements, RoleProtocol)
		default:
			kr.statementPins[k.ID] = k.Pubkey
		}
	}
	for _, k := range r.opt.VendorLogKeys {
		switch {
		case q != nil && hasPub(q, k.Pubkey):
			e, _ := q.byPubkey(k.Pubkey)
			drop(k, RoleProtocol, e.rolle)
		case kr.kcsL[k.Pubkey]:
			drop(k, RoleProtocol, RoleCountersigning)
		default:
			kr.protocolPins[k.ID] = k.Pubkey
		}
	}
	sort.SliceStable(st.PinsDropped, func(i, j int) bool { return st.PinsDropped[i].KeyID < st.PinsDropped[j].KeyID })

	// Keys of other roles a receipt may name in the manifest.
	if q != nil {
		for _, k := range q.keys {
			if k.rolle != RoleCountersigning {
				kr.otherRole[k.pubkey] = true
			}
		}
	}
	if p != nil {
		for _, k := range p.keys {
			kr.otherRole[k.pubkey] = true
		}
	}
	// 10.7.4: for the note receipt_key_other_role every pin the auditor
	// passes counts, also one that R3 drops.
	for _, k := range append(append([]VendorKey{}, r.opt.VendorStatementKeys...), r.opt.VendorLogKeys...) {
		kr.otherRole[k.Pubkey] = true
	}

	// The report object (10.10.2).
	switch {
	case len(roleCands) == 0:
		st.Status = RolesNotSupplied
	case q != nil:
		st.Status = RolesEffective
		st.List = &KeyRolesListStat{Version: q.version, Ausgestellt: q.ausgestellt, WurzelID: q.wurzelID, RootSource: q.rootSource}
		if q.hasEnde {
			e := q.ende
			st.List.EndeDoppelbetrieb = &e
		}
	default:
		st.Status = RolesNotEffect
		why := qWhy
		st.Reason = &why
	}
	// 10.10.2: a key that is pinned and also an entry of Q with the role
	// statements (the same key_id) stands here once, with source pinned, for
	// R4 takes the pins first.
	keys := map[string]string{}
	for id := range kr.statementPins {
		keys[id] = SourcePinned
	}
	if q != nil {
		for _, k := range q.keys {
			if _, pinned := keys[k.keyID]; k.rolle == RoleStatements && !pinned {
				keys[k.keyID] = SourceRoleList
			}
		}
	}
	st.StatementKeys = []StatementKeyRef{}
	for id, src := range keys {
		st.StatementKeys = append(st.StatementKeys, StatementKeyRef{KeyID: id, Source: src})
	}
	sort.Slice(st.StatementKeys, func(i, j int) bool { return st.StatementKeys[i].KeyID < st.StatementKeys[j].KeyID })
	if st.PinsDropped == nil {
		st.PinsDropped = []PinDropped{}
	}
}

func hasPub(l *signedList, pub string) bool { _, ok := l.byPubkey(pub); return ok }

// qRoleOther returns the role Q gives pub when it is not want, else "".
func qRoleOther(q *signedList, pub, want string) string {
	if e, ok := q.byPubkey(pub); ok && e.rolle != want {
		return e.rolle
	}
	return ""
}

func pinnedPub(keys []VendorKey, pub string) bool {
	for _, k := range keys {
		if k.Pubkey == pub {
			return true
		}
	}
	return false
}

// noteReceiptOtherRole records the note receipt_key_other_role for a
// receipt that is not established after 7.1 and whose public key in the
// manifest is a key of another role.
func (r *run) noteReceiptOtherRole(manifestPub string) {
	if r.roles == nil || manifestPub == "" || !r.roles.otherRole[manifestPub] {
		return
	}
	r.roles.receiptOther = true
}

// finishKeyRoles writes the notes of key_roles in the order of the registry.
//
// Format spec 10.10.3: the text report has no block for key_roles in this
// edition; the object stands only in the JSON output.
func (r *run) finishKeyRoles() *KeyRolesStat {
	kr := r.roles
	if kr == nil {
		return nil
	}
	st := kr.stat
	st.Notes = []string{}
	if kr.q != nil {
		for _, k := range kr.q.keys {
			if !knownRoles[k.rolle] {
				st.Notes = append(st.Notes, NoteUnknownRole)
				break
			}
		}
	}
	if kr.receiptOther {
		st.Notes = append(st.Notes, NoteReceiptOther)
	}
	if len(st.PinsDropped) > 0 {
		st.Notes = append(st.Notes, NotePinDropped)
	}
	return &st
}

// StatementKey is how a statements key is established for a page (format
// spec 8.8.3): a pin, or an entry of the effective role list with its
// validity. Later steps of the anchor history read it.
type StatementKey struct {
	Pubkey   string
	Pinned   bool
	Entry    *vendorListKey // the entry of Q, nil for a pin unless Q names the key
	Revoked  bool           // Q names the key with widerrufen_ab
	ListInfo *KeyRolesListStat
}

// statementKey looks up the server_key_id of a page after format spec 8.8.3.
func (r *run) statementKey(keyID string) (StatementKey, bool) {
	kr := r.roles
	if kr == nil {
		return StatementKey{}, false
	}
	if pub, ok := kr.statementPins[keyID]; ok {
		sk := StatementKey{Pubkey: pub, Pinned: true}
		if kr.q != nil {
			if e, ok := kr.q.byPubkey(pub); ok && e.rolle == RoleStatements {
				le := e.vendorListKey
				sk.Entry, sk.Revoked = &le, !e.widerr.IsZero()
			}
		}
		return sk, true
	}
	if kr.q != nil {
		for _, e := range kr.q.keys {
			if e.keyID == keyID && e.rolle == RoleStatements {
				le := e.vendorListKey
				return StatementKey{Pubkey: e.pubkey, Entry: &le, Revoked: !e.widerr.IsZero(), ListInfo: kr.stat.List}, true
			}
		}
	}
	return StatementKey{}, false
}

// keyOfOtherRole is H2 number 1 of format spec 8.8.4 for a server_key_id
// that establishes no page: it names a key of K_cs (K_cs^L and the
// countersigning pins not dropped after R3 (d)) or of the effective protocol
// key list, a protocol pin not dropped, or an entry of the effective role
// list with a role other than statements (reason key_other_role). A dropped
// pin does not count.
func (r *run) keyOfOtherRole(keyID string) bool {
	kr := r.roles
	if kr == nil {
		return false
	}
	if kr.kcsLIDs[keyID] {
		return true
	}
	if vt := r.vendor; vt != nil {
		if _, ok := vt.pinned[keyID]; ok {
			return true
		}
	}
	if _, ok := kr.protocolPins[keyID]; ok {
		return true
	}
	if kr.p != nil {
		for _, k := range kr.p.keys {
			if k.keyID == keyID {
				return true
			}
		}
	}
	if kr.q != nil {
		for _, k := range kr.q.keys {
			if k.keyID == keyID && k.rolle != RoleStatements {
				return true
			}
		}
	}
	return false
}

// protocolKeys returns the established protocol keys (format spec 7.4.10, L1
// items 1 to 3): pins first, they have no end of validity, then the keys of
// P. Later steps of the vendor log read it.
func (r *run) protocolKeys() map[string]vendorListKey {
	out := map[string]vendorListKey{}
	kr := r.roles
	if kr == nil {
		return out
	}
	if kr.p != nil {
		for _, k := range kr.p.keys {
			out[k.keyID] = k.vendorListKey
		}
	}
	for id, pub := range kr.protocolPins {
		out[id] = vendorListKey{pubkey: pub}
	}
	return out
}
