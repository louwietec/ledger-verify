package vfy

// Where a vendor countersigning key comes from (spec 7.1, 10.7).
//
// Until spec 1.3 the verifier took the vendor keys from manifest.vendor_pubkeys
// — written by the very appliance under examination. A receipt therefore only
// proved that SOMEBODY holding SOME key had signed the root; whoever rewrote a
// chain could invent a key pair, sign fresh "receipts" with it, list the public
// key in the manifest and get exit 0 with no finding: a fully anchored chain
// that no vendor had ever countersigned. Measured, not supposed:
// appliance/cmd/vektorgen/faelschung_test.go.
//
// The rule is the one spec 7.3 already set for time witnesses: the trust
// anchor comes from the AUDITOR, never from the package. The auditor brings
//   - the vendor's root key (VendorRoots), published with the licence and
//     compiled into release builds — it vouches for keys through the signed
//     list keys/vendor/schluesselliste.json in the package, each key with its
//     validity window; or
//   - single vendor keys it pinned itself (VendorKeys).
// A key established that way is used for the signature check INSTEAD of the
// manifest's copy. A receipt whose key neither establishes is still checked
// against the manifest key, still counts as an anchor, and is reported once
// per key as RECEIPT_UNVERIFIED (exit 1) — the same split as TIME_ANCHOR_
// UNVERIFIED: a missing anchor is a statement about the audit environment,
// not proof that the chain was forged. Where the vendor's own signed list
// CONTRADICTS a receipt (the key was not valid at server_ts, or the list binds
// the key id to another public key), that is RECEIPT_INVALID (exit 2).

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
)

// VendorListPath is where a package carries the vendor's signed key list.
const VendorListPath = "keys/vendor/schluesselliste.json"

// VendorListFormat names the list format (spec 10.7).
const VendorListFormat = "rekorder-herstellerschluessel/1"

// vendorListMaxKeys bounds the list (spec 10.7).
const vendorListMaxKeys = 64

// VendorRoot is the vendor's offline root key as the auditor supplies it.
// Builtin marks the root compiled into the build (spec 7.1); the report
// names the source of a root as vendor_root or builtin (spec 10.10.2).
type VendorRoot struct {
	ID      string `json:"wurzel_id"`
	Pubkey  string `json:"pubkey"`
	Builtin bool   `json:"-"`
}

// VendorKey is a single vendor countersigning key the auditor pinned.
type VendorKey struct {
	ID     string `json:"key_id"`
	Pubkey string `json:"pubkey"`
}

var (
	reVendorID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	reUTCTime  = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$`)
)

// CheckVendorRoot validates an auditor-supplied root (used by the CLIs).
func CheckVendorRoot(w VendorRoot) error {
	if !reVendorID.MatchString(w.ID) {
		return fmt.Errorf("wurzel_id %q violates the key-id grammar [A-Za-z0-9._-]{1,64}", w.ID)
	}
	if !reHex64.MatchString(w.Pubkey) {
		return fmt.Errorf("pubkey must be 64 lowercase hex characters")
	}
	return nil
}

// CheckVendorKey validates an auditor-pinned key (used by the CLIs).
func CheckVendorKey(k VendorKey) error {
	if !reVendorID.MatchString(k.ID) {
		return fmt.Errorf("key_id %q violates the key-id grammar [A-Za-z0-9._-]{1,64}", k.ID)
	}
	if !reHex64.MatchString(k.Pubkey) {
		return fmt.Errorf("pubkey must be 64 lowercase hex characters")
	}
	return nil
}

// vendorListKey is one key of a verified list.
type vendorListKey struct {
	pubkey          string
	ab, bis, widerr time.Time // bis/widerr zero = open
	abS, bisS, widS string
}

// vendorTrust is the per-run result of establishing vendor keys.
type vendorTrust struct {
	pinned     map[string]string // key_id -> pubkey (auditor pin)
	list       map[string]vendorListKey
	listRoot   string // wurzel_id that vouched for the list
	listVer    int64
	listIssued string // ausgestellt of the list, reported so the auditor can ask the vendor for a newer one
	listNote   string // why no list counts (empty when one does)
	anyAnchor  bool   // the auditor supplied at least one root or key
	verworfen  int    // malformed anchors that reached the library and were ignored
	unverified map[string]bool
}

// parseUTC reads the spec's rfc3339 type as spec 10.7 fixes it for the list
// and for server_ts compared against it: UTC with Z, year 0001-9999,
// fractional seconds of any length, compared at nanoseconds (further digits
// cut off). Both verifiers read it the same way — Go's time package alone
// would take year 0000, Python's datetime would not.
func parseUTC(s string) (time.Time, bool) {
	if !reUTCTime.MatchString(s) || strings.HasPrefix(s, "0000-") {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

// loadVendorTrust assembles the trusted vendor keys once per run.
func (r *run) loadVendorTrust() {
	vt := &vendorTrust{pinned: map[string]string{}, unverified: map[string]bool{}}
	r.vendor = vt
	// The CLIs refuse malformed anchors up front (AnkerZusammenfuehren);
	// a library caller may still pass one. It is ignored — never used — but
	// counted, so the finding does not claim "no anchor was supplied".
	for _, k := range r.opt.VendorKeys {
		if CheckVendorKey(k) == nil {
			vt.pinned[k.ID] = k.Pubkey
			vt.anyAnchor = true
		} else {
			vt.verworfen++
		}
	}
	roots := map[string]string{}
	for _, w := range r.opt.VendorRoots {
		if CheckVendorRoot(w) == nil {
			roots[w.ID] = w.Pubkey
			vt.anyAnchor = true
		} else {
			vt.verworfen++
		}
	}
	if !r.fs.Exists(VendorListPath) {
		vt.listNote = "the package carries no " + VendorListPath
		return
	}
	if len(roots) == 0 {
		vt.listNote = "the package carries " + VendorListPath + ", but no vendor root was supplied to check it against"
		return
	}
	raw, err := r.fs.ReadFile(VendorListPath)
	if err != nil {
		vt.listNote = VendorListPath + " is not readable: " + err.Error()
		return
	}
	list, root, ver, issued, why := parseVendorList(raw, roots)
	if why != "" {
		vt.listNote = VendorListPath + " does not count: " + why
		return
	}
	vt.list, vt.listRoot, vt.listVer, vt.listIssued = list, root, ver, issued
}

// parseVendorList checks a list against the auditor's roots (spec 10.7).
// It returns the keys, the vouching root, version and issue time or, in why,
// the reason the list does not count.
func parseVendorList(raw []byte, roots map[string]string) (map[string]vendorListKey, string, int64, string, string) {
	v, err := jcs.Parse(raw)
	if err != nil {
		return nil, "", 0, "", "not JSON: " + err.Error()
	}
	if v.Kind != jcs.KindObject {
		return nil, "", 0, "", "not a JSON object"
	}
	allowed := map[string]bool{"format": true, "version": true, "ausgestellt": true, "schluessel": true, "signatur": true}
	for _, m := range v.Members {
		if !allowed[m.Key] {
			return nil, "", 0, "", fmt.Sprintf("undefined field %q", m.Key)
		}
	}
	if f := v.Get("format"); f == nil || f.Kind != jcs.KindString || f.Str != VendorListFormat {
		return nil, "", 0, "", "format is not " + VendorListFormat
	}
	ver := v.Get("version")
	if ver == nil || ver.Kind != jcs.KindInt || ver.Int < 1 {
		return nil, "", 0, "", "version must be an integer >= 1"
	}
	issued := v.Get("ausgestellt")
	if issued == nil || issued.Kind != jcs.KindString {
		return nil, "", 0, "", "ausgestellt missing"
	} else if _, ok := parseUTC(issued.Str); !ok {
		return nil, "", 0, "", "ausgestellt is not an RFC 3339 UTC timestamp"
	}
	ks := v.Get("schluessel")
	if ks == nil || ks.Kind != jcs.KindArray || len(ks.Arr) == 0 || len(ks.Arr) > vendorListMaxKeys {
		return nil, "", 0, "", fmt.Sprintf("schluessel must hold 1 to %d keys", vendorListMaxKeys)
	}
	keys := map[string]vendorListKey{}
	pubs := map[string]bool{}
	keyFields := map[string]bool{"key_id": true, "pubkey": true, "gueltig_ab": true, "gueltig_bis": true, "widerrufen_ab": true}
	for _, k := range ks.Arr {
		if k.Kind != jcs.KindObject {
			return nil, "", 0, "", "schluessel[] entry is not an object"
		}
		for _, m := range k.Members {
			if !keyFields[m.Key] {
				return nil, "", 0, "", fmt.Sprintf("undefined field schluessel[].%s", m.Key)
			}
			if m.Value.Kind != jcs.KindString {
				return nil, "", 0, "", fmt.Sprintf("schluessel[].%s is not a string", m.Key)
			}
		}
		id, pub := k.Get("key_id"), k.Get("pubkey")
		if id == nil || !reVendorID.MatchString(id.Str) {
			return nil, "", 0, "", "schluessel[].key_id missing or violates the key-id grammar"
		}
		if _, dup := keys[id.Str]; dup {
			return nil, "", 0, "", fmt.Sprintf("key_id %q listed twice", id.Str)
		}
		if pub == nil || !reHex64.MatchString(pub.Str) {
			return nil, "", 0, "", fmt.Sprintf("%s: pubkey must be 64 lowercase hex characters", id.Str)
		}
		if pubs[pub.Str] {
			return nil, "", 0, "", fmt.Sprintf("%s: the same pubkey is listed under two key ids", id.Str)
		}
		pubs[pub.Str] = true
		lk := vendorListKey{pubkey: pub.Str}
		ab := k.Get("gueltig_ab")
		if ab == nil {
			return nil, "", 0, "", fmt.Sprintf("%s: gueltig_ab missing", id.Str)
		}
		var ok bool
		if lk.ab, ok = parseUTC(ab.Str); !ok {
			return nil, "", 0, "", fmt.Sprintf("%s: gueltig_ab is not an RFC 3339 UTC timestamp", id.Str)
		}
		lk.abS = ab.Str
		if b := k.Get("gueltig_bis"); b != nil {
			if lk.bis, ok = parseUTC(b.Str); !ok {
				return nil, "", 0, "", fmt.Sprintf("%s: gueltig_bis is not an RFC 3339 UTC timestamp", id.Str)
			}
			if !lk.bis.After(lk.ab) {
				return nil, "", 0, "", fmt.Sprintf("%s: gueltig_bis is not after gueltig_ab", id.Str)
			}
			lk.bisS = b.Str
		}
		if w := k.Get("widerrufen_ab"); w != nil {
			if lk.widerr, ok = parseUTC(w.Str); !ok {
				return nil, "", 0, "", fmt.Sprintf("%s: widerrufen_ab is not an RFC 3339 UTC timestamp", id.Str)
			}
			lk.widS = w.Str
		}
		keys[id.Str] = lk
	}
	sig := v.Get("signatur")
	if sig == nil || sig.Kind != jcs.KindObject {
		return nil, "", 0, "", "the list is not signed (signatur missing)"
	}
	for _, m := range sig.Members {
		if m.Key != "wurzel_id" && m.Key != "sig" {
			return nil, "", 0, "", fmt.Sprintf("undefined field signatur.%s", m.Key)
		}
	}
	wid, sg := sig.Get("wurzel_id"), sig.Get("sig")
	if wid == nil || wid.Kind != jcs.KindString || sg == nil || sg.Kind != jcs.KindString || !reHex128.MatchString(sg.Str) {
		return nil, "", 0, "", "signatur needs wurzel_id and a 128-hex sig"
	}
	rootPub, known := roots[wid.Str]
	if !known {
		have := make([]string, 0, len(roots))
		for id := range roots {
			have = append(have, id)
		}
		sort.Strings(have)
		return nil, "", 0, "", fmt.Sprintf("signed by root %q, the auditor supplied %s", wid.Str, strings.Join(have, ", "))
	}
	// Signed bytes: JCS of the list object without its member "signatur".
	unsigned := &jcs.Value{Kind: jcs.KindObject}
	for _, m := range v.Members {
		if m.Key != "signatur" {
			unsigned.Members = append(unsigned.Members, m)
		}
	}
	if !verifySig(rootPub, jcs.Canon(unsigned), sg.Str) {
		return nil, "", 0, "", fmt.Sprintf("the signature of root %q does not verify", wid.Str)
	}
	return keys, wid.Str, ver.Int, issued.Str, ""
}

// vendorKeyFor decides which public key a receipt under keyID must verify
// against, and whether the vendor's list contradicts it at serverTS.
//
//	pub         the key to verify with ("" = none known at all)
//	established true when an auditor anchor vouched for pub
//	contra      non-empty when the vendor's signed list contradicts the receipt
func (r *run) vendorKeyFor(keyID, serverTS string) (pub string, established bool, contra string) {
	vt := r.vendor
	// The manifest copy only matters where no anchor reaches the key: it is
	// not evidence (spec 10.1). Until the review of 25.09. a manifest pubkey
	// differing from the list's was a "contradiction" — one unsigned edit
	// turned genuine vendor receipts into RECEIPT_INVALID + NO_ANCHOR and hid
	// a FORK_DETECTED behind them.
	manPub, inManifest := r.man.vendorKeys[keyID]
	if p, ok := vt.pinned[keyID]; ok {
		return p, true, ""
	}
	if lk, ok := vt.list[keyID]; ok {
		t, tok := parseUTC(serverTS)
		switch {
		case !tok:
			return lk.pubkey, true, fmt.Sprintf("server_ts %q cannot be placed in the validity window of key %q", serverTS, keyID)
		case t.Before(lk.ab):
			return lk.pubkey, true, fmt.Sprintf("the vendor's list (root %s, version %d) makes key %q valid from %s only, the receipt is dated %s",
				vt.listRoot, vt.listVer, keyID, lk.abS, serverTS)
		case !lk.bis.IsZero() && !t.Before(lk.bis):
			return lk.pubkey, true, fmt.Sprintf("the vendor's list (root %s, version %d) makes key %q valid until %s only, the receipt is dated %s",
				vt.listRoot, vt.listVer, keyID, lk.bisS, serverTS)
		case !lk.widerr.IsZero() && !t.Before(lk.widerr):
			return lk.pubkey, true, fmt.Sprintf("the vendor's list (root %s, version %d) REVOKED key %q as of %s, the receipt is dated %s",
				vt.listRoot, vt.listVer, keyID, lk.widS, serverTS)
		}
		return lk.pubkey, true, ""
	}
	if inManifest {
		return manPub, false, ""
	}
	return "", false, ""
}

// vendorKeyVia names where vendorKeyFor took an established key from, in
// its own order: a pin of the auditor first, then the list of the package
// (format spec 10.9.3); a key no anchor establishes comes from the manifest.
func (r *run) vendorKeyVia(keyID string, established bool) string {
	vt := r.vendor
	switch {
	case !established:
		return keyViaManifest
	case vt != nil && vt.pinned[keyID] != "":
		return keyViaPinned
	}
	return keyViaList
}

// noteUnverifiedVendorKey reports RECEIPT_UNVERIFIED once per key id.
func (r *run) noteUnverifiedVendorKey(seq int64, keyID string) {
	vt := r.vendor
	if vt.unverified[keyID] {
		return
	}
	vt.unverified[keyID] = true
	why := "no vendor root and no vendor key was supplied by the auditor"
	if vt.verworfen > 0 && !vt.anyAnchor {
		why = fmt.Sprintf("the auditor's anchors were all malformed and ignored (%d)", vt.verworfen)
	}
	if vt.anyAnchor {
		why = fmt.Sprintf("the key is neither pinned by the auditor nor vouched for by a vendor list the auditor's root verifies (%s)", vt.listNote)
		if vt.list != nil {
			why = fmt.Sprintf("the key is not pinned by the auditor and not in the vendor's list (root %s, version %d)", vt.listRoot, vt.listVer)
		}
	}
	r.add(ClsReceiptUnverified, seq, fmt.Sprintf(
		"receipts under vendor key %q (pubkey %s, from the package manifest) are signed consistently, but the key is not established as the vendor's: %s; "+
			"the package was written by the party the receipt is meant to bind, so its own key proves nothing; look the key up with the vendor outside the package (spec 7.1)",
		keyID, r.man.vendorKeys[keyID], why))
}

// BuiltinVendorRoot is the vendor root compiled into a release build, as
// "wurzel_id=hex64". It is set with
//
//	-ldflags "-X <module>/internal/vfy.BuiltinVendorRoot=<id>=<hex>"
//
// (<module> is the module path, go list -m)
// by verifier/build.sh when the vendor's root is at hand, and it is EMPTY in
// every other build: a developer build and the test harnesses trust nothing
// they were not handed. It counts as a vendor root of the auditor (spec 7.1):
// the auditor chose to trust this binary, whose build is reproducible, and the
// report names its source builtin (spec 10.10.2). No root of a time-stamping
// authority is built in, and the system root store counts for no purpose
// (spec 7.5.7).
var BuiltinVendorRoot = ""

// Builtin returns the compiled-in vendor root, if any.
func Builtin() (VendorRoot, bool, error) {
	if BuiltinVendorRoot == "" {
		return VendorRoot{}, false, nil
	}
	id, pub, ok := strings.Cut(BuiltinVendorRoot, "=")
	w := VendorRoot{ID: id, Pubkey: pub, Builtin: true}
	if !ok {
		return VendorRoot{}, false, fmt.Errorf("compiled-in vendor root %q is not wurzel_id=hex", BuiltinVendorRoot)
	}
	if err := CheckVendorRoot(w); err != nil {
		return VendorRoot{}, false, fmt.Errorf("compiled-in vendor root: %w", err)
	}
	return w, true, nil
}

// ParseVendorRoot reads a vendor root file as the vendor publishes it with
// the licence: {"wurzel_id": "...", "pubkey": "<hex64>"} and nothing else.
func ParseVendorRoot(b []byte) (VendorRoot, error) {
	v, err := jcs.Parse(b)
	if err != nil {
		return VendorRoot{}, fmt.Errorf("not JSON: %w", err)
	}
	if v.Kind != jcs.KindObject {
		return VendorRoot{}, fmt.Errorf("not a JSON object")
	}
	for _, m := range v.Members {
		if m.Key != "wurzel_id" && m.Key != "pubkey" {
			return VendorRoot{}, fmt.Errorf("undefined field %q", m.Key)
		}
		if m.Value.Kind != jcs.KindString {
			return VendorRoot{}, fmt.Errorf("%s is not a string", m.Key)
		}
	}
	w := VendorRoot{}
	if x := v.Get("wurzel_id"); x != nil {
		w.ID = x.Str
	}
	if x := v.Get("pubkey"); x != nil {
		w.Pubkey = x.Str
	}
	return w, CheckVendorRoot(w)
}

// ParseVendorKey reads a pin given as "key_id=hex64".
func ParseVendorKey(s string) (VendorKey, error) {
	id, pub, ok := strings.Cut(s, "=")
	if !ok {
		return VendorKey{}, fmt.Errorf("%q is not key_id=hex64", s)
	}
	k := VendorKey{ID: id, Pubkey: pub}
	return k, CheckVendorKey(k)
}

// AnkerZusammenfuehren checks and merges the auditor's anchors: every one must
// be well-formed, and two anchors of the same name must agree. Two roots
// "w" with different keys, or a pin that contradicts another pin of the same
// key id, leave the audit environment ambiguous — the CLIs refuse that with
// exit 3 instead of silently letting the last one win (spec 7.1). Exact
// duplicates are merged.
func AnkerZusammenfuehren(roots []VendorRoot, keys []VendorKey) ([]VendorRoot, []VendorKey, error) {
	var outR []VendorRoot
	seenR := map[string]string{}
	for _, w := range roots {
		if err := CheckVendorRoot(w); err != nil {
			return nil, nil, fmt.Errorf("vendor root: %w", err)
		}
		if p, ok := seenR[w.ID]; ok {
			if p != w.Pubkey {
				return nil, nil, fmt.Errorf("two vendor roots named %q with different keys: the audit environment is ambiguous", w.ID)
			}
			// The same root built in and passed by the auditor: its source
			// is the auditor's (spec 10.10.2).
			for i := range outR {
				if outR[i].ID == w.ID && !w.Builtin {
					outR[i].Builtin = false
				}
			}
			continue
		}
		seenR[w.ID] = w.Pubkey
		outR = append(outR, w)
	}
	var outK []VendorKey
	seenK := map[string]string{}
	for _, k := range keys {
		if err := CheckVendorKey(k); err != nil {
			return nil, nil, fmt.Errorf("vendor key: %w", err)
		}
		if p, ok := seenK[k.ID]; ok {
			if p != k.Pubkey {
				return nil, nil, fmt.Errorf("vendor key %q pinned twice with different pubkeys: the audit environment is ambiguous", k.ID)
			}
			continue
		}
		seenK[k.ID] = k.Pubkey
		outK = append(outK, k)
	}
	return outR, outK, nil
}
