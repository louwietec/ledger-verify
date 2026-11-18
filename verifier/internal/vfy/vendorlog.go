package vfy

// The vendor log (format spec 7.4, from edition 1.10): steps L2 to L10 of
// 7.4.10 and the report object vendor_log (10.10.2). Step L0, the grammar of
// the extracts and every other unusable invocation (exit 3), lives in
// auditor_inputs.go; step L1, the protocol keys with the role check, in
// keyroles.go.
//
// The steps read only the auditor's inputs, per receipt whether its
// signature holds after 7.1, the prefix roots, GENESIS.appliance_id and the
// check time. They add only the five finding classes of 7.4.11, all of exit
// class 1, and change no other result: NO_ANCHOR, the last countersigned
// checkpoint, the residual window, completeness and expected roots stay as
// they would be without the log. Every case can occur with an honest chain
// (a damaged download, a loss at the vendor, its misconduct), so none of
// them proves a manipulation of the chain.
//
// The verifier never tells a filler from a chain-day leaf, reads no filler
// secret, day secret, salt, opening or day leaves, and does not check the
// size rule (7.4.4, 7.4.9).

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
	"louwietec.com/ledger-verify/verifier/internal/mldsa"
	"louwietec.com/ledger-verify/verifier/internal/tsa"
)

// Statuses, key sources and classes of registry vendor_log.
const (
	VendorLogNotSupplied   = "not_supplied"
	VendorLogNoProtocolKey = "no_protocol_key"
	VendorLogChecked       = "checked"

	KeySourceList          = "list"
	KeySourcePinned        = "pinned"
	KeySourceListAndPinned = "list_and_pinned"

	// Receipt classes of step L8 (registry vendor_log.receipt_classes).
	RcIncluded    = "included"
	RcNotIncluded = "not_included"
	RcUnchecked   = "unchecked"
	RcMissing     = "missing"
	RcPending     = "pending"
	RcBeforeStart = "before_start"
	RcFuture      = "future"

	// Sub-classes of unchecked (registry vendor_log.unchecked_subclasses).
	UcNoRecord              = "no_record"
	UcRecordFailed          = "record_failed"
	UcRecordContradictory   = "record_contradictory"
	UcDayNotWitnessed       = "day_not_witnessed"
	UcDayContradictory      = "day_contradictory"
	UcFirstDayContradictory = "first_day_contradictory"
	UcHybridIncomplete      = "hybrid_incomplete" // from the extension of 1.10, L2 (g')

	// Reasons of day_not_witnessed (registry vendor_log.not_witnessed_reasons).
	NwNoTimestamp    = "no_timestamp"
	NwNoLogRoot      = "no_log_root_supplied"
	NwOutsideProfile = "outside_profile"
	NwNotChained     = "not_chained_to_log_root"
	NwTestKey        = "published_test_key"
	NwLate           = "late"

	// States of the chain-day records of a day (registry
	// vendor_log.record_states).
	recVerified      = "verified"
	recNone          = "none"
	recFailed        = "failed"
	recContradictory = "contradictory"
)

// Object kinds and times (registry object_kinds, vendor_log.time).
const (
	kindDayEntry   = "ledger.vendor_log_day.v1"
	kindGapWitness = "ledger.vendor_log_gap_witness.v1"
	kindPosition   = "ledger.vendor_log_position.v1"
	kindDayLeaf    = "ledger.vendor_log_day_leaf.v1"

	vlDayMS            = 86_400_000
	vlTokenMinOffsetMS = 60_000      // token_min_offset_ms
	vlTokenWindowMS    = 172_800_000 // W, token_window_ms
	vlPublicationMS    = 21_600_000  // P, publication_offset_ms: a day is due from end(d) + P
	vlFutureMS         = 900_000     // receipt_classes.future_tolerance_ms
	vlDaysTo1970       = 719_162     // dn(1970-01-01), format spec 2
)

// nwRank orders the reasons of not witnessed time stamps (L8 case 4): the
// time stamp that came furthest decides.
var nwRank = map[string]int{NwOutsideProfile: 1, NwNotChained: 2, NwTestKey: 3, NwLate: 4}

// emptyRootHex is MTH([]) = SHA-256(""), the root of a day with tree_size 0.
var emptyRootHex = func() string { h := merkleEmptyRoot(); return hex.EncodeToString(h[:]) }()

var reMillisTS = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$`)

// ---------------------------------------------------------------- report

// VendorLogStat is the report object vendor_log (format spec 10.10.2).
type VendorLogStat struct {
	Status        string                `json:"status"`
	LogID         *string               `json:"log_id"`
	FirstDay      *string               `json:"first_day"`
	KeySource     *string               `json:"key_source"`
	KeyList       *VendorLogKeyListStat `json:"key_list"`
	Places        []string              `json:"places"`
	Files         int                   `json:"files"`
	DistinctFiles int                   `json:"distinct_files"`
	Head          *VendorLogHeadStat    `json:"head"`
	Days          VendorLogDaysStat     `json:"days"`
	Seals         VendorLogSealsStat    `json:"seals"`
	// CoseNotChecked counts the elements of day_receipts and cose_receipts
	// of the extracts /2, which a verifier of edition 1.10 keeps in their
	// grammar but does not check (step L3a and step K belong to edition
	// 1.11); never a finding.
	CoseNotChecked      int                    `json:"cose_not_checked"`
	TSA                 VendorLogTSAStat       `json:"tsa"`
	Receipts            *VendorLogReceiptsStat `json:"receipts"`
	LastCountersigned   *string                `json:"last_countersigned"`
	LoggedRoots         *VendorLogRootsStat    `json:"logged_roots"`
	ForeignChainRecords int                    `json:"foreign_chain_records"`
	// NoKeyReason is the reason of step L1 item 4 for the status
	// no_protocol_key, for the text report; not a member of the object.
	NoKeyReason string `json:"-"`
}

// VendorLogKeyListStat names the effective protocol key list.
type VendorLogKeyListStat struct {
	Version     int64  `json:"version"`
	Ausgestellt string `json:"ausgestellt"`
	WurzelID    string `json:"wurzel_id"`
	RootSource  string `json:"root_source"`
	// From the extension of edition 1.10 (format spec 10.10.2): the format
	// of P, the day H, the number of keys in P_mldsa, the version of P2, an
	// entry with an unknown alg in P2 and log_uri of P2.
	Format           string  `json:"format"`
	HybridFrom       *string `json:"hybrid_from"`
	MLDSAKeys        int     `json:"ml_dsa_keys"`
	MLDSAListVersion *int64  `json:"ml_dsa_list_version"`
	UnknownAlg       bool    `json:"unknown_alg"`
	LogURI           *string `json:"log_uri"`
}

// VendorLogSealsStat counts the distinct seals of all day objects after
// pooling (L2 (b'), format spec 10.10.2, from the extension of 1.10).
type VendorLogSealsStat struct {
	MLDSA      VendorLogMLDSAStat `json:"ml_dsa"`
	NotChecked int                `json:"not_checked"`
}

// VendorLogMLDSAStat counts the seals ml-dsa-87.
type VendorLogMLDSAStat struct {
	Carried           int `json:"carried"`
	Defective         int `json:"defective"`
	KeyNotEstablished int `json:"key_not_established"`
}

// VendorLogHeadStat is the head of step L4.
type VendorLogHeadStat struct {
	Day       string `json:"day"`
	DayHash   string `json:"day_hash"`
	TreeSize  int64  `json:"tree_size"`
	Witnessed bool   `json:"witnessed"`
	SeenIn    int    `json:"seen_in"`
}

// VendorLogDaysStat counts the day objects and days (steps L2, L3, L7).
type VendorLogDaysStat struct {
	Supplied             int `json:"supplied"`
	Established          int `json:"established"`
	Witnessed            int `json:"witnessed"`
	Contradictory        int `json:"contradictory"`
	Missing              int `json:"missing"`
	SignaturesNotChecked int `json:"signatures_not_checked"`
	HybridRequired       int `json:"hybrid_required"`
	HybridIncomplete     int `json:"hybrid_incomplete"`
}

// VendorLogTSAStat says whether steps 5 and 6 of the profile run and how
// many roots of the purpose log were supplied.
type VendorLogTSAStat struct {
	CMSChecked    bool `json:"cms_checked"`
	RootsSupplied int  `json:"roots_supplied"`
}

// VendorLogReceiptsStat counts the receipts per class of step L8.
type VendorLogReceiptsStat struct {
	Included             int    `json:"included"`
	NotIncluded          int    `json:"not_included"`
	Unchecked            int    `json:"unchecked"`
	Missing              int    `json:"missing"`
	Pending              int    `json:"pending"`
	BeforeStart          int    `json:"before_start"`
	Future               int    `json:"future"`
	IncludedUpToTreeSize *int64 `json:"included_up_to_tree_size"`
}

// VendorLogRootsStat counts the logged roots of step L9.
type VendorLogRootsStat struct {
	MatchingPrefix         int `json:"matching_prefix"`
	MatchingWithoutReceipt int `json:"matching_without_receipt"`
	ContradictingPrefix    int `json:"contradicting_prefix"`
	BeyondPackage          int `json:"beyond_package"`
	GapWitnesses           int `json:"gap_witnesses"`
}

// ---------------------------------------------------------------- state

// vlRun is the state of the vendor log for one run. Besides the report it
// keeps what the evidence level (10.9.3) and the anchor history (8.8) read:
// the class of every receipt, whether a contradiction without day or on a
// day of [Lo, T] was found, t_m and the logged roots beyond the package.
type vlRun struct {
	stat VendorLogStat

	keys       map[string]vendorListKey // established protocol keys by key_id (L1)
	mldsa      map[string]roleKey       // P_mldsa by key_id (L1 item 6)
	hasH       bool                     // H is not null
	h          int64                    // H as dn
	hybridDays map[int64]bool           // days with a hybrid-incomplete object (L2 (g'))
	listP      *signedList              // the effective protocol key list P, nil without
	logRoots   []*tsa.Certificate       // roots of the purpose log (7.5.7)
	fKnown     bool
	f          int64 // F as dn (format spec 2)
	fContra    bool  // L2 (f) ended the check
	objs       []*vlObject
	byDay      map[int64][]*vlObject // S(d): established entries
	canon      map[int64]*vlObject   // c(d)
	usable     map[int64]bool
	records    map[int64]*vlDayRecords
	headDay    int64
	hasHead    bool
	lo, hi     int64 // [Lo, T] of L7
	hasRange   bool
	missing    map[int64]bool
	classes    map[int64]vlClass // receipt class by seq (L8)
	contraDays map[int64]bool    // days with a VENDOR_LOG_CONTRADICTION
	contraNone bool              // a VENDOR_LOG_CONTRADICTION without day
	tM         int64             // smallest tree_size of LOGGED_ROOT_MISMATCH, 0 without
	beyond     []vlRoot          // logged roots with t > N, for the anchor history (8.8)
	findings   vlFindings
}

// vlClass is the class of one receipt in step L8, with its sub-class.
type vlClass struct {
	class, sub string
	treeSize   int64
	day        int64
}

// vlObject is one day object after pooling (L2): equal statement_jcs are one
// object, its time stamps a set of strings, its signatures a set of pairs.
type vlObject struct {
	jcs    string
	hash   [32]byte // day_hash
	stamps []string
	pairs  []vlPair
	seals  map[string]bool // elements with an alg other than ed25519
	files  map[[32]byte]bool
	// From the extension of 1.10 (7.4.8a): the seals as a set of distinct
	// triples (type, key_id, value).
	seals2 []vlSeal
	// carryingML are the carrying ML-DSA seals of (b'), by key_id.
	carryingML []string

	hasDay bool // dayOf(o) has a day
	day    int64
	dayS   string

	st          *vlStatement
	judged      []vlStamp
	passed      bool // passed (a) to (e)
	established bool
	broken      bool
	witnessed   bool
}

type vlPair struct{ keyID, sig string }

// vlSeal is one seal of a day object /2 (7.4.8a); keyID "" is null.
type vlSeal struct{ typ, keyID, value string }

// vlStatement is the content of a day entry that follows 7.4.5.
type vlStatement struct {
	day, firstDay   int64
	dayS, firstDayS string
	prevHash, root  string
	serverTS        string
	serverMS        int64
	treeSize        int64
}

// vlStamp is one time stamp judged after 7.5.7 (column day time stamp).
type vlStamp struct {
	state  string // tsa.StateDefective, StateUnconfirmed, StateConfirmed
	cs     string // the row that decided
	detail string
	gen    time.Time
	hasGen bool
	// tok and sig keep the token and the result of step 5 for condition (7)
	// of the evidence level, which judges every time stamp of c(d) against
	// each root with the purposes log and qualified alone (format spec
	// 10.9.3); tok is nil when the token violates B64, the size limit or
	// grammar T.
	tok *tsa.Token
	sig tsa.Signature
}

// vlRoot is one element of roots of a present record with its leaf.
type vlRoot struct {
	treeSize   int64
	root       string
	recordedAs string
	serverTS   string
	leaf       []byte
	lh         [32]byte
	day        int64 // the day of the record that carried it
}

// vlDayRecords are the chain-day records of one usable day (L6).
type vlDayRecords struct {
	state string
	m     map[[32]byte]bool // M(d): leaf hashes of the verified record
	roots []vlRoot          // the roots of a verified present record
}

// ---------------------------------------------------------------- findings

// Reasons of registry vendor_log.finding_reasons with their step (ten times
// the step, so that the reasons of the extension of 1.10 stand right after
// the reason they follow: mldsa_signature, L2 (b'), after signature, L2 (b);
// hybrid_incomplete, L2 (g'), after entry_rules, L2 (g)), which orders the
// reasons of one finding (7.4.11: "mit den Gründen in der Reihenfolge der
// Schritte").
var vlReasons = map[string]struct {
	step int
	text string
}{
	"no_protocol_key":          {10, "no protocol key established by an anchor of the auditor"},
	"key_not_established":      {20, "key not established"},
	"signature":                {30, "signature"},
	"mldsa_signature":          {31, "ML-DSA signature"},
	"entry_format":             {40, "signed entry violates the format"},
	"key_validity_ended":       {60, "validity of the protocol key ended, time of the signature not proven"},
	"no_common_first_day":      {70, "day entries under pinned keys name no common first_day"},
	"entry_rules":              {80, "signed entry violates a rule of the log"},
	"hybrid_incomplete":        {81, "ML-DSA signature missing, not established or no longer valid"},
	"timestamp_defective":      {90, "time stamp does not hold"},
	"closed_before_day_end":    {90, "day closed before its end"},
	"two_versions":             {100, "two signed versions"},
	"does_not_link":            {110, "does not link to the previous day"},
	"skips_days":               {110, "skips days"},
	"record_does_not_hold":     {120, "record holds neither as inclusion nor as absence"},
	"leaf_of_other_day":        {120, "leaf of another day"},
	"two_chain_day_records":    {120, "two chain-day records"},
	"days_not_supplied":        {130, "days without an established day entry in the extracts supplied"},
	"no_chain_day_record":      {140, "no chain-day record supplied"},
	"day_not_witnessed":        {140, "day entry not witnessed"},
	"receipt_after_check_time": {140, "receipt with server_ts after the check time"},
	"not_included":             {140, "receipts missing from the witnessed chain day of their day"},
	"root_differs":             {150, "recorded root differs from the package's root"},
}

type vlPart struct {
	code   string
	detail string
}

type vlFinding struct {
	class string
	day   string // "" without day
	seq   int64
	parts []vlPart
	own   string // a finding of its own: a run of missing days, RECEIPT_NOT_LOGGED, LOGGED_ROOT_MISMATCH
}

// vlFindings merges the findings of the vendor log after 7.4.11: per class
// and UTC day at most one finding, with the reasons in step order; per class
// at most one without day; runs of missing days, RECEIPT_NOT_LOGGED per day
// and LOGGED_ROOT_MISMATCH per (tree_size, merkle_root) are findings of their
// own.
type vlFindings struct {
	list []*vlFinding
	idx  map[string]*vlFinding
}

func (fs *vlFindings) note(class, day, code, detail string) {
	if fs.idx == nil {
		fs.idx = map[string]*vlFinding{}
	}
	k := class + "|" + day
	f := fs.idx[k]
	if f == nil {
		f = &vlFinding{class: class, day: day}
		fs.idx[k] = f
		fs.list = append(fs.list, f)
	}
	f.parts = append(f.parts, vlPart{code: code, detail: detail})
}

func (fs *vlFindings) ownFinding(class, day string, seq int64, detail string) {
	fs.list = append(fs.list, &vlFinding{class: class, day: day, seq: seq, own: detail})
}

// emit adds the merged findings to the run.
func (fs *vlFindings) emit(r *run) {
	for _, f := range fs.list {
		if f.own != "" {
			r.add(f.class, f.seq, f.own)
			continue
		}
		sort.SliceStable(f.parts, func(i, j int) bool { return vlReasons[f.parts[i].code].step < vlReasons[f.parts[j].code].step })
		var codes []string
		details := map[string][]string{}
		for _, p := range f.parts {
			if _, ok := details[p.code]; !ok {
				codes = append(codes, p.code)
			}
			if p.detail != "" && !contains(details[p.code], p.detail) {
				details[p.code] = append(details[p.code], p.detail)
			}
			if details[p.code] == nil {
				details[p.code] = []string{}
			}
		}
		var b strings.Builder
		if f.day != "" {
			fmt.Fprintf(&b, "day %s: ", f.day)
		} else {
			b.WriteString("without day: ")
		}
		for i, c := range codes {
			if i > 0 {
				b.WriteString("; ")
			}
			fmt.Fprintf(&b, "%s [%s]", vlReasons[c].text, c)
			if d := details[c]; len(d) > 0 {
				fmt.Fprintf(&b, " (%s)", strings.Join(d, "; "))
			}
		}
		b.WriteString(" (format spec 7.4.10, 7.4.11)")
		r.add(f.class, f.seq, b.String())
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- days

// dayNumber is dn(d) of format spec 2: the days from 0001-01-01 to the UTC
// day of t.
func dayNumber(t time.Time) int64 {
	u := t.Unix()
	d := u / 86400
	if u%86400 < 0 {
		d--
	}
	return d + vlDaysTo1970
}

// dayEndMS is end(d) = (dn(d) + 1) * 86 400 000, in whole milliseconds since
// 0001-01-01T00:00:00Z (format spec 2).
func dayEndMS(dn int64) int64 { return (dn + 1) * vlDayMS }

// msSince0001 is an instant in whole milliseconds since 0001-01-01T00:00:00Z,
// the fraction beyond the third digit cut off (format spec 2).
func msSince0001(t time.Time) int64 { return unixMS(t) + vlDaysTo1970*vlDayMS }

// dayString renders dn as YYYY-MM-DD; only ever called for days between two
// existing dates.
func dayString(dn int64) string {
	return time.Unix((dn-vlDaysTo1970)*86400, 0).UTC().Format("2006-01-02")
}

// dayOfTS is day(ts) of format spec 2: the date part of an rfc3339 value,
// the ten characters before the T.
func dayOfTS(ts string) (int64, bool) {
	if len(ts) < 10 {
		return 0, false
	}
	t, ok := parseDate(ts[:10], false)
	if !ok {
		return 0, false
	}
	return dayNumber(t), true
}

// ---------------------------------------------------------------- leaves

// vlLeaf is the leaf of a root of a chain-day record (format spec 7.4.2,
// "Blatt aus der Aufzeichnung"): countersigned gives the leaf of a
// countersignature, exactly the bytes the receipt signature covers,
// gap_witness the leaf of a gap witness with its kind; server_ts enters as
// the string the record carries.
func vlLeaf(chainID string, treeSize int64, root, recordedAs, serverTS string) []byte {
	m := map[string]any{"chain_id": chainID, "merkle_root": root, "server_ts": serverTS, "tree_size": treeSize}
	if recordedAs == "gap_witness" {
		m["kind"] = kindGapWitness
	}
	b, _ := jcs.CanonGo(m)
	return b
}

// vlPosition is position(C, d) of format spec 7.4.3.
func vlPosition(applianceID, chainID, day string) [32]byte {
	b, _ := jcs.CanonGo(map[string]any{"appliance_id": applianceID, "chain_id": chainID, "day": day, "kind": kindPosition})
	return sha256.Sum256(b)
}

// vlDayLeaf is the chain-day leaf of format spec 7.4.3, the form of every
// leaf of the day tree.
func vlDayLeaf(chainRoot, position string) []byte {
	b, _ := jcs.CanonGo(map[string]any{"chain_root": chainRoot, "kind": kindDayLeaf, "position": position})
	return b
}

// mthOfLeafHashes is MTH (format spec 5, RFC 6962 2.1) over leaves given by
// their leaf hashes; MTH([]) is SHA-256 of the empty string.
func mthOfLeafHashes(hs [][32]byte) [32]byte {
	switch len(hs) {
	case 0:
		return merkleEmptyRoot()
	case 1:
		return hs[0]
	}
	k := 1
	for k*2 < len(hs) {
		k *= 2
	}
	return nodeHash(mthOfLeafHashes(hs[:k]), mthOfLeafHashes(hs[k:]))
}

// vlChainRoot is chain_root(C, d) of format spec 7.4.3: MTH over the leaves,
// ascending by their leaf hash as unsigned 32-byte values, whatever the
// order of roots in the record.
func vlChainRoot(lhs [][32]byte) [32]byte {
	s := append([][32]byte{}, lhs...)
	sort.Slice(s, func(i, j int) bool { return string(s[i][:]) < string(s[j][:]) })
	return mthOfLeafHashes(s)
}

// ---------------------------------------------------------------- the run

// checkVendorLog runs steps L2 to L9 of format spec 7.4.10 after the
// receipts (10.5, stage 5 step 6). Step L1 ran with the role check.
func (r *run) checkVendorLog() {
	vr := &vlRun{
		byDay: map[int64][]*vlObject{}, canon: map[int64]*vlObject{}, usable: map[int64]bool{},
		records: map[int64]*vlDayRecords{}, missing: map[int64]bool{}, classes: map[int64]vlClass{},
		contraDays: map[int64]bool{}, hybridDays: map[int64]bool{}, mldsa: map[string]roleKey{},
	}
	r.vlog = vr
	st := &vr.stat
	st.Status = VendorLogNotSupplied
	st.Places = []string{}
	st.TSA.CMSChecked = true
	if len(r.opt.VendorLogs) == 0 {
		// Without an extract every count is 0 (10.10.2), roots_supplied
		// included.
		return
	}
	logID := r.opt.VendorLogs[0].LogID
	st.LogID = &logID
	st.Files = len(r.opt.VendorLogs)
	distinct := map[[32]byte]bool{}
	for _, x := range r.opt.VendorLogs {
		distinct[extractSum(x)] = true
	}
	st.DistinctFiles = len(distinct)
	st.CoseNotChecked = coseNotChecked(r.opt.VendorLogs)
	for _, x := range r.tsaRootTable() {
		if x.Log {
			vr.logRoots = append(vr.logRoots, x.Cert)
		}
	}
	st.TSA.RootsSupplied = len(vr.logRoots)

	// L1 item 4: no protocol key remains.
	vr.keys = r.protocolKeys()
	kr := r.roles
	if len(vr.keys) == 0 {
		// Steps L2 to L9 are dropped. days.supplied and
		// signatures_not_checked are formed where L2 pools the day objects,
		// so with no_protocol_key they stay 0 (10.10.2), like every member
		// L2 to L9 fill.
		st.Status = VendorLogNoProtocolKey
		why := PReasonNoList
		if kr != nil && kr.pReason != "" {
			why = kr.pReason
		}
		if len(r.opt.VendorLogKeys) > 0 {
			// L1 item 4: no list is effective and every protocol pin was
			// dropped by item 3 (10.7.4, R3 (d)), since a pin that is not
			// dropped would remain as a key. The reason is then "Schlüssel
			// in zwei Rollen", not that of the list.
			why = PReasonTwoRoles
		}
		st.NoKeyReason = why
		vr.findings.note(ClsVendorLogUnverified, "", "no_protocol_key", "reason "+why+": "+vlNoKeyText[why])
		vr.findings.emit(r)
		return
	}
	st.Status = VendorLogChecked
	hasList, hasPins := kr != nil && kr.p != nil, kr != nil && len(kr.protocolPins) > 0
	ks := KeySourceList
	switch {
	case hasList && hasPins:
		ks = KeySourceListAndPinned
	case hasPins:
		ks = KeySourcePinned
	}
	st.KeySource = &ks
	vr.listP = nil
	if hasList {
		p := kr.p
		vr.listP = p
		kl := &VendorLogKeyListStat{Version: p.version, Ausgestellt: p.ausgestellt, WurzelID: p.wurzelID, RootSource: p.rootSource, Format: ProtocolKeyListFormat}
		if p.v2 {
			kl.Format = ProtocolKeyList2Format
		}
		// L1 item 6: P2, P_mldsa and H; without P2 P_mldsa is empty and H
		// null, and unknown_alg is false.
		if p2 := kr.p2; p2 != nil {
			v, u := p2.version, p2.logURI
			kl.MLDSAListVersion, kl.LogURI = &v, &u
			if p2.hybridAb != "" {
				h := p2.hybridAb
				kl.HybridFrom = &h
				t, _ := parseDate(h, true)
				vr.hasH, vr.h = true, dayNumber(t)
			}
			for _, k := range p2.keys {
				switch k.alg {
				case AlgEd25519:
				case AlgMLDSA87:
					vr.mldsa[k.keyID] = k
				default:
					kl.UnknownAlg = true
				}
			}
			kl.MLDSAKeys = len(vr.mldsa)
		}
		st.KeyList = kl
		st.Places = append(st.Places, p.orte...)
	}

	vr.pool(r.opt.VendorLogs)
	vr.stepL2(logID)
	if !vr.fContra {
		vr.stepL3()
		vr.stepL4()
		vr.stepL5()
		vr.stepL6(r)
		vr.stepL7(r)
	}
	vr.stepL8(r)
	if !vr.fContra {
		vr.stepL9(r)
	}
	vr.findings.emit(r)
	vr.finishStat(r)
}

// vlNoKeyText are the texts of registry vendor_log.no_protocol_key_reasons.
var vlNoKeyText = map[string]string{
	PReasonNoList:        "no protocol key list supplied",
	PReasonNoRoot:        "no vendor root of the auditor with the list's wurzel_id",
	PReasonSignature:     "the list's signature does not hold",
	PReasonFormat:        "the list violates the format",
	PReasonContradictory: "contradicting lists",
	PReasonTwoRoles:      "a key in two roles of the vendor",
	PReasonLogID:         "the list's log_id differs from that of the extracts",
}

// extractSum is the SHA-256 of an extract's bytes.
func extractSum(x VendorLogExtract) [32]byte {
	if x.Sum != ([32]byte{}) {
		return x.Sum
	}
	return sha256.Sum256(jcs.Canon(x.Value))
}

// pool is the first part of L2: the day objects of all extracts pooled,
// equal statement_jcs one object; time stamps a set of distinct strings,
// signatures a set of distinct pairs (server_key_id, server_signature) to
// which every element of additional_signatures with alg ed25519 belongs as
// (key_id, signature); elements with another alg counted as a set of
// distinct elements and never checked (7.4.8).
func (vr *vlRun) pool(xs []VendorLogExtract) {
	byJCS := map[string]*vlObject{}
	for _, x := range xs {
		sum := extractSum(x)
		days := x.Value.Get("days")
		if days == nil {
			continue
		}
		for _, d := range days.Arr {
			e := d.Get("entry")
			sj := e.Get("statement_jcs").Str
			o := byJCS[sj]
			if o == nil {
				o = &vlObject{jcs: sj, hash: sha256.Sum256([]byte(sj)), seals: map[string]bool{}, files: map[[32]byte]bool{}}
				byJCS[sj] = o
				vr.objs = append(vr.objs, o)
			}
			o.files[sum] = true
			o.addPair(e.Get("server_key_id").Str, e.Get("server_signature").Str)
			for _, ts := range d.Get("timestamps").Arr {
				if !contains(o.stamps, ts.Str) {
					o.stamps = append(o.stamps, ts.Str)
				}
			}
			for _, s := range d.Get("additional_signatures").Arr {
				if s.Get("alg").Str == "ed25519" {
					o.addPair(s.Get("key_id").Str, s.Get("signature").Str)
				} else {
					o.seals[string(jcs.Canon(s))] = true
				}
			}
			// From 1.10: an object of an extract /1 has no seals and no
			// day_receipts (7.4.8a).
			if x.V2 {
				for _, s := range d.Get("seals").Arr {
					o.addSeal(vlSeal{typ: s.Get("type").Str, keyID: s.Get("key_id").Str, value: s.Get("value").Str})
				}
			}
		}
	}
	// The order of the files never matters (L2): objects in the order of
	// their statement_jcs.
	sort.Slice(vr.objs, func(i, j int) bool { return vr.objs[i].jcs < vr.objs[j].jcs })
	vr.stat.Days.Supplied = len(vr.objs)
	for _, o := range vr.objs {
		vr.stat.Days.SignaturesNotChecked += len(o.seals)
		for _, sl := range o.seals2 {
			if sl.typ != AlgMLDSA87 {
				vr.stat.Seals.NotChecked++
			}
		}
	}
}

// coseNotChecked is vendor_log.cose_not_checked of edition 1.10 (format spec
// 7.4.8a, 10.10.2): the number of distinct elements of day_receipts (per day
// object after pooling, equal statement_jcs one object) and of cose_receipts
// (per extract) of all extracts /2. A verifier 1.10 does not check them;
// they give no finding and never exit 3. It is counted whenever extracts /2
// are supplied, also with the status no_protocol_key: it says what the
// verifier did not check, not what step L2 pooled.
func coseNotChecked(xs []VendorLogExtract) int {
	n := 0
	byJCS := map[string]map[string]bool{}
	for _, x := range xs {
		if !x.V2 {
			continue
		}
		n += len(x.Value.Get("cose_receipts").Arr) // distinct within an extract (grammar)
		for _, d := range x.Value.Get("days").Arr {
			sj := d.Get("entry").Get("statement_jcs").Str
			set := byJCS[sj]
			if set == nil {
				set = map[string]bool{}
				byJCS[sj] = set
			}
			for _, c := range d.Get("day_receipts").Arr {
				set[c.Str] = true
			}
		}
	}
	for _, set := range byJCS {
		n += len(set)
	}
	return n
}

// addSeal adds a seal to the set of distinct triples (type, key_id, value).
func (o *vlObject) addSeal(sl vlSeal) {
	for _, x := range o.seals2 {
		if x == sl {
			return
		}
	}
	o.seals2 = append(o.seals2, sl)
}

// checkMLDSASeals is L2 (b') for one object: every seal ml-dsa-87 whose
// key_id names a key of P_mldsa is checked after 7.4.5a over
// UTF-8(statement_jcs) with Bytes(value) as the signature; a value that
// violates B64, does not give exactly 4627 bytes or whose signature does not
// hold is VENDOR_LOG_DEFECTIVE(dayOf(o)) "ML-DSA signature", without removing
// o; otherwise it is a carrying ML-DSA seal. A seal ml-dsa-87 under another
// key_id is only counted. (b') runs for every object, also before H and with
// H null, and alone never makes an object not established.
func (vr *vlRun) checkMLDSASeals(o *vlObject, day string) {
	for _, sl := range o.seals2 {
		if sl.typ != AlgMLDSA87 {
			continue
		}
		k, ok := vr.mldsa[sl.keyID]
		if !ok {
			vr.stat.Seals.MLDSA.KeyNotEstablished++
			continue
		}
		sig, err := tsa.DecodeB64(sl.value)
		why := ""
		switch {
		case err != nil:
			why = "value violates B64"
		case len(sig) != mldsaSigLen:
			why = fmt.Sprintf("value gives %d bytes, not 4627", len(sig))
		case !mldsa.Verify(mldsa.MLDSA87, k.mldsaPub, []byte(o.jcs), nil, sig):
			why = "signature does not hold"
		}
		if why != "" {
			vr.stat.Seals.MLDSA.Defective++
			vr.findings.note(ClsVendorLogDefective, day, "mldsa_signature", "under "+sl.keyID+", day hash "+hex.EncodeToString(o.hash[:])+": "+why)
			continue
		}
		vr.stat.Seals.MLDSA.Carried++
		o.carryingML = append(o.carryingML, sl.keyID)
	}
}

func (o *vlObject) addPair(keyID, sig string) {
	for _, p := range o.pairs {
		if p.keyID == keyID && p.sig == sig {
			return
		}
	}
	o.pairs = append(o.pairs, vlPair{keyID, sig})
}

// dayOf reads dayOf(o) of L2: the member day when statement_jcs reads as an
// I-JSON object (duplicate member names refused) with a member day that
// follows the grammar of the type date (format spec 2: a calendar date, the
// years 0001 to 9999). The log range 2000-01-01 to 9998-12-31 is no part of
// dayOf: it is a rule of the content, checked in L2 (c), so a signed entry
// with day 1999-12-31 gets its finding on that day.
func (o *vlObject) dayOf() {
	v, err := jcs.Parse([]byte(o.jcs))
	if err != nil || v.Kind != jcs.KindObject {
		return
	}
	s, ok := str(v.Get("day"))
	if !ok {
		return
	}
	t, ok := parseDate(s, false)
	if !ok {
		return
	}
	o.hasDay, o.day, o.dayS = true, dayNumber(t), s
}

// readStatement checks the content of a day entry after 7.4.5 for L2 (c):
// printable ASCII, I-JSON, its own JCS form, exactly the members with their
// types, the kind, log_id equal to that of the extracts, the log range and
// the form of server_ts. It returns the reason of a violation.
func readStatement(sj, logID string) (*vlStatement, string) {
	for i := 0; i < len(sj); i++ {
		if sj[i] < 0x20 || sj[i] > 0x7e {
			return nil, "statement_jcs is not printable ASCII"
		}
	}
	v, err := jcs.Parse([]byte(sj))
	if err != nil {
		return nil, "statement_jcs is not I-JSON: " + err.Error()
	}
	if string(jcs.Canon(v)) != sj {
		return nil, "statement_jcs is not the JCS form of its content"
	}
	if err := closed(v, "statement_jcs", []string{"day", "first_day", "kind", "log_id", "prev_hash", "root", "server_ts", "tree_size"}); err != nil {
		return nil, err.Error()
	}
	s := &vlStatement{}
	var ok bool
	if s.dayS, ok = str(v.Get("day")); !ok {
		return nil, "day is not a string"
	}
	t, ok := parseDate(s.dayS, true)
	if !ok {
		return nil, "day is not a date of the log range"
	}
	s.day = dayNumber(t)
	if s.firstDayS, ok = str(v.Get("first_day")); !ok {
		return nil, "first_day is not a string"
	}
	if t, ok = parseDate(s.firstDayS, true); !ok {
		return nil, "first_day is not a date of the log range"
	}
	s.firstDay = dayNumber(t)
	if k, _ := str(v.Get("kind")); k != kindDayEntry {
		return nil, "kind is not " + kindDayEntry
	}
	lid, ok := str(v.Get("log_id"))
	if !ok || !reKeyID.MatchString(lid) {
		return nil, "log_id is not a key-id"
	}
	if lid != logID {
		return nil, fmt.Sprintf("log_id %q is not that of the extracts (%q)", lid, logID)
	}
	if s.prevHash, ok = str(v.Get("prev_hash")); !ok || !reHex64.MatchString(s.prevHash) {
		return nil, "prev_hash is not hex64"
	}
	if s.root, ok = str(v.Get("root")); !ok || !reHex64.MatchString(s.root) {
		return nil, "root is not hex64"
	}
	if s.serverTS, ok = str(v.Get("server_ts")); !ok || !reMillisTS.MatchString(s.serverTS) {
		return nil, "server_ts is not in the form YYYY-MM-DDThh:mm:ss.sssZ"
	}
	ts, ok := parseUTC(s.serverTS)
	if !ok {
		return nil, "server_ts is not rfc3339"
	}
	s.serverMS = msSince0001(ts)
	if s.treeSize, ok = intRange(v.Get("tree_size"), 0, maxSafe); !ok {
		return nil, "tree_size is not an int from 0 to 2^53-1"
	}
	return s, ""
}

// judgeStamp judges one time stamp of a day entry after 7.5.7 (column day
// time stamp) against the roots of the purpose log: a violation of B64 or of
// the limit of 16 384 bytes makes it defective.
func (vr *vlRun) judgeStamp(b64 string, stmt []byte) vlStamp {
	der, err := tsa.DecodeB64(b64)
	if err != nil {
		return vlStamp{state: tsa.StateDefective, cs: tsa.CaseGrammar, detail: err.Error()}
	}
	a := tsa.Assess(der, stmt, vr.logRoots, tsa.PurposeLog)
	s := vlStamp{state: a.State, cs: a.Case, detail: a.Detail, tok: a.Token, sig: a.Signature}
	if a.Token != nil {
		s.gen, s.hasGen = a.Token.GenTime, true
	}
	return s
}

// timing places a confirmed time stamp of day d: witnessing when end(d) +
// 60 000 <= genTime < end(d) + W, premature before, late from end(d) + W on
// (7.4.6), genTime truncated to whole milliseconds.
func timing(s vlStamp, day int64) string {
	g, end := msSince0001(s.gen), dayEndMS(day)
	switch {
	case g < end+vlTokenMinOffsetMS:
		return "premature"
	case g >= end+vlTokenWindowMS:
		return "late"
	}
	return "witnessing"
}

// stepL2 runs (a) to (e) for every object, then (f), then (g) and (h).
func (vr *vlRun) stepL2(logID string) {
	for _, o := range vr.objs {
		o.dayOf()
		vr.checkObject(o, logID)
		// hybrid_required (10.10.2): every object with dayOf(o) >= H,
		// whatever its result.
		if vr.hasH && o.hasDay && o.day >= vr.h {
			vr.stat.Days.HybridRequired++
		}
	}
	// (f) the beginning F: with an effective list its erster_tag.
	if p := vr.listP; p != nil {
		t, _ := parseDate(p.ersterTag, true)
		vr.fKnown, vr.f = true, dayNumber(t)
	} else {
		firsts := map[int64]bool{}
		for _, o := range vr.objs {
			if o.passed {
				firsts[o.st.firstDay] = true
			}
		}
		switch len(firsts) {
		case 0:
			// F unknown, without a finding; no object reaches (g).
		case 1:
			for f := range firsts {
				vr.fKnown, vr.f = true, f
			}
		default:
			var ds []string
			for f := range firsts {
				ds = append(ds, dayString(f))
			}
			sort.Strings(ds)
			vr.findings.note(ClsVendorLogContradict, "", "no_common_first_day", "first_day "+strings.Join(ds, ", "))
			vr.contraNone = true
			vr.fContra = true
			return
		}
	}
	if vr.fKnown {
		fd := dayString(vr.f)
		vr.stat.FirstDay = &fd
	}
	for _, o := range vr.objs {
		if !o.passed || !vr.fKnown {
			continue
		}
		vr.rulesAndStamps(o)
	}
}

// checkObject is L2 (a) to (e) for one object.
func (vr *vlRun) checkObject(o *vlObject, logID string) {
	day := ""
	if o.hasDay {
		day = o.dayS
	}
	// (a) a pair names an established protocol key.
	named := false
	for _, p := range o.pairs {
		if _, ok := vr.keys[p.keyID]; ok {
			named = true
		}
	}
	if !named {
		var ids []string
		for _, p := range o.pairs {
			if !contains(ids, p.keyID) {
				ids = append(ids, p.keyID)
			}
		}
		vr.findings.note(ClsVendorLogUnverified, day, "key_not_established", "day hash "+hex.EncodeToString(o.hash[:])+" under "+strings.Join(ids, ", "))
		vr.checkMLDSASeals(o, day)
		return
	}
	// (b) every pair under an established key; a failing one never removes
	// the object.
	var carrying []vlPair
	for _, p := range o.pairs {
		k, ok := vr.keys[p.keyID]
		if !ok {
			continue
		}
		if verifySig(k.pubkey, []byte(o.jcs), p.sig) {
			carrying = append(carrying, p)
		} else {
			vr.findings.note(ClsVendorLogDefective, day, "signature", "under "+p.keyID+", day hash "+hex.EncodeToString(o.hash[:]))
		}
	}
	// (b') the seals ml-dsa-87 of o.
	vr.checkMLDSASeals(o, day)
	if len(carrying) == 0 {
		return
	}
	// (c) the content after 7.4.5; the signature holds, so the holder of
	// the protocol key signed it.
	st, why := readStatement(o.jcs, logID)
	if st == nil {
		vr.findings.note(ClsVendorLogContradict, day, "entry_format", why)
		vr.markContra(o.hasDay, o.day)
		return
	}
	o.st = st
	// (d) every time stamp after 7.5.7, with its genTime.
	for _, ts := range o.stamps {
		o.judged = append(o.judged, vr.judgeStamp(ts, []byte(o.jcs)))
	}
	// (e) a carrying pair holds when its key has no end, or a confirmed time
	// stamp of o shows a genTime before that end (nanoseconds, the full
	// genTime). gueltig_ab is not checked against day entries.
	holds := false
	for _, p := range carrying {
		if o.keyHolds(vr.keys[p.keyID]) {
			holds = true
			break
		}
	}
	if !holds {
		vr.findings.note(ClsVendorLogUnverified, st.dayS, "key_validity_ended", "day hash "+hex.EncodeToString(o.hash[:]))
		return
	}
	o.passed = true
}

// keyHolds is the rule of (e) and (e') for a key: it has neither
// gueltig_bis nor widerrufen_ab, or a confirmed time stamp of o shows a
// genTime before its end (the earlier of the two values), compared on
// nanoseconds with the full genTime.
func (o *vlObject) keyHolds(k vendorListKey) bool {
	end := k.bis
	if !k.widerr.IsZero() && (end.IsZero() || k.widerr.Before(end)) {
		end = k.widerr
	}
	if end.IsZero() {
		return true
	}
	for _, s := range o.judged {
		if s.state == tsa.StateConfirmed && s.gen.Before(end) {
			return true
		}
	}
	return false
}

func (vr *vlRun) markContra(hasDay bool, day int64) {
	if hasDay {
		vr.contraDays[day] = true
	} else {
		vr.contraNone = true
	}
}

// rulesAndStamps is L2 (g) and (h) for one object that passed (a) to (e).
func (vr *vlRun) rulesAndStamps(o *vlObject) {
	s := o.st
	var broken []string
	if s.day < vr.f {
		broken = append(broken, "day before first_day of the log")
	}
	if (s.prevHash == zeroHash) != (s.day == vr.f) {
		broken = append(broken, "prev_hash is 64 zeros exactly when day is the first day")
	}
	if s.treeSize == 0 && s.root != emptyRootHex {
		broken = append(broken, "tree_size 0 with a root other than SHA-256 of the empty string")
	}
	if s.serverMS < dayEndMS(s.day) {
		broken = append(broken, "server_ts before the end of the day")
	}
	if s.firstDay != vr.f {
		broken = append(broken, "first_day is not "+dayString(vr.f))
	}
	if len(broken) > 0 {
		vr.findings.note(ClsVendorLogContradict, s.dayS, "entry_rules", strings.Join(broken, ", "))
		vr.contraDays[s.day] = true
		return
	}
	// (g') the hybrid rule, only for an object that passed (g): with H not
	// null and d >= H, o is established only when at least one carrying
	// ML-DSA seal of o holds after (e') for its key of P2; otherwise o is
	// hybrid-incomplete and not established. The conditions of (a), (b) and
	// (e) for Ed25519 hold unchanged: both methods must carry.
	if vr.hasH && s.day >= vr.h {
		holds := false
		for _, id := range o.carryingML {
			if o.keyHolds(vr.mldsa[id].vendorListKey) {
				holds = true
				break
			}
		}
		if !holds {
			vr.findings.note(ClsVendorLogUnverified, s.dayS, "hybrid_incomplete", "day hash "+hex.EncodeToString(o.hash[:]))
			vr.hybridDays[s.day] = true
			vr.stat.Days.HybridIncomplete++
			return
		}
	}
	// (h) established.
	o.established = true
	witnessing := false
	for _, ts := range o.judged {
		switch ts.state {
		case tsa.StateDefective:
			vr.findings.note(ClsVendorLogDefective, s.dayS, "timestamp_defective", ts.detail)
		case tsa.StateConfirmed:
			switch timing(ts, s.day) {
			case "premature":
				vr.findings.note(ClsVendorLogContradict, s.dayS, "closed_before_day_end", "genTime "+tsa.FormatMillis(ts.gen))
				vr.contraDays[s.day] = true
				o.broken = true
			case "witnessing":
				witnessing = true
			}
		}
	}
	o.witnessed = witnessing && !o.broken
}

// stepL3 determines S(d), Wt(d), c(d) and the usable days.
func (vr *vlRun) stepL3() {
	for _, o := range vr.objs {
		if o.established {
			vr.byDay[o.st.day] = append(vr.byDay[o.st.day], o)
			vr.stat.Days.Established++
		}
	}
	for _, d := range sortedDays(vr.byDay) {
		s := vr.byDay[d]
		if len(s) >= 2 {
			var hs []string
			for _, o := range s {
				hs = append(hs, hex.EncodeToString(o.hash[:]))
			}
			sort.Strings(hs)
			vr.findings.note(ClsVendorLogContradict, dayString(d), "two_versions", "day hashes "+strings.Join(hs, ", "))
			vr.contraDays[d] = true
		}
		var wt, unbroken []*vlObject
		for _, o := range s {
			if o.witnessed {
				wt = append(wt, o)
			}
			if !o.broken {
				unbroken = append(unbroken, o)
			}
		}
		switch {
		case len(wt) == 1:
			vr.canon[d] = wt[0]
		case len(wt) == 0 && len(unbroken) == 1:
			vr.canon[d] = unbroken[0]
		}
		if c := vr.canon[d]; c != nil && c.witnessed {
			vr.usable[d] = true
		}
	}
	vr.stat.Days.Witnessed = len(vr.usable)
}

func sortedDays[V any](m map[int64]V) []int64 {
	var out []int64
	for d := range m {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// stepL4 finds the head: the youngest day whose c(d) is determined.
func (vr *vlRun) stepL4() {
	for d := range vr.canon {
		if !vr.hasHead || d > vr.headDay {
			vr.headDay, vr.hasHead = d, true
		}
	}
	if !vr.hasHead {
		return
	}
	c := vr.canon[vr.headDay]
	vr.stat.Head = &VendorLogHeadStat{Day: c.st.dayS, DayHash: hex.EncodeToString(c.hash[:]), TreeSize: c.st.treeSize, Witnessed: c.witnessed, SeenIn: len(c.files)}
}

// stepL5 checks the linking of the canonical entries.
func (vr *vlRun) stepL5() {
	dayOfHash := map[string]int64{}
	for d, s := range vr.byDay {
		for _, o := range s {
			dayOfHash[hex.EncodeToString(o.hash[:])] = d
		}
	}
	for _, d := range sortedDays(vr.canon) {
		c := vr.canon[d]
		if n := vr.canon[d+1]; n != nil && n.st.prevHash != hex.EncodeToString(c.hash[:]) {
			vr.findings.note(ClsVendorLogContradict, n.st.dayS, "does_not_link", "prev_hash "+n.st.prevHash+", day hash of "+c.st.dayS+" "+hex.EncodeToString(c.hash[:]))
			vr.contraDays[d+1] = true
		}
		if d > vr.f && len(vr.byDay[d-1]) == 0 {
			if x, ok := dayOfHash[c.st.prevHash]; ok && x < d-1 {
				vr.findings.note(ClsVendorLogContradict, c.st.dayS, "skips_days", fmt.Sprintf("skips the days %s to %s", dayString(x+1), dayString(d-1)))
				vr.contraDays[d] = true
			}
		}
	}
}

// vlRecordEval is one chain-day record judged against (n, R) of its day.
type vlRecordEval struct {
	present   bool
	chainRoot [32]byte
	roots     []vlRoot
}

// stepL6 checks the chain-day records of the extracts with chain_id = C on
// usable days.
func (vr *vlRun) stepL6(r *run) {
	c := r.man.chainID
	a := ""
	if len(r.entries) > 0 && r.entries[0].eventType == "GENESIS" {
		a = r.entries[0].pStr("appliance_id")
	}
	holding := map[int64][]*vlRecordEval{}
	supplied := map[int64]int{}
	for _, x := range r.opt.VendorLogs {
		cd := x.Value.Get("chain_days")
		if cd == nil || len(cd.Arr) == 0 {
			continue
		}
		if cid, _ := str(x.Value.Get("chain_id")); cid != c {
			// foreign_chain_records (10.10.2): every record of every
			// extract counts, also equal records in several files.
			vr.stat.ForeignChainRecords += len(cd.Arr)
			continue
		}
		for _, rec := range cd.Arr {
			dt, _ := parseDate(rec.Get("day").Str, true)
			d := dayNumber(dt)
			if !vr.usable[d] {
				// Records on days that are not usable are passed over and
				// counted in no member (L6).
				continue
			}
			supplied[d]++
			e, why := vr.evalRecord(rec, c, a, d)
			if e == nil {
				vr.findings.note(ClsVendorLogDefective, dayString(d), "record_does_not_hold", why)
				continue
			}
			holding[d] = append(holding[d], e)
		}
	}
	for _, d := range sortedDays(vr.usable) {
		dr := &vlDayRecords{state: recNone}
		vr.records[d] = dr
		hs := holding[d]
		switch {
		case supplied[d] == 0:
			continue
		case len(hs) == 0:
			dr.state = recFailed
			continue
		}
		contra := false
		for _, e := range hs {
			for _, rt := range e.roots {
				if rd, ok := dayOfTS(rt.serverTS); !ok || rd != d {
					vr.findings.note(ClsVendorLogContradict, dayString(d), "leaf_of_other_day", fmt.Sprintf("tree_size %d, server_ts %s", rt.treeSize, rt.serverTS))
					contra = true
				}
			}
		}
		for _, e := range hs[1:] {
			if e.present != hs[0].present || e.present && e.chainRoot != hs[0].chainRoot {
				vr.findings.note(ClsVendorLogContradict, dayString(d), "two_chain_day_records", "")
				contra = true
				break
			}
		}
		if contra {
			vr.contraDays[d] = true
			dr.state = recContradictory
			continue
		}
		dr.state = recVerified
		dr.m = map[[32]byte]bool{}
		seen := map[string]bool{}
		for _, e := range hs {
			for _, rt := range e.roots {
				dr.m[rt.lh] = true
				if !seen[string(rt.leaf)] {
					seen[string(rt.leaf)] = true
					dr.roots = append(dr.roots, rt)
				}
			}
		}
	}
}

// evalRecord judges one record against n = tree_size and R = root of c(d)
// and p = position(C, d) with A; n and R never come from the record. It
// returns nil and the reason when the record does not hold.
func (vr *vlRun) evalRecord(rec *jcs.Value, c, a string, d int64) (*vlRecordEval, string) {
	cd := vr.canon[d].st
	n := uint64(cd.treeSize)
	rootB, _ := hex.DecodeString(cd.root)
	var root [32]byte
	copy(root[:], rootB)
	pos := vlPosition(a, c, dayString(d))
	posHex := hex.EncodeToString(pos[:])
	if pr := rec.Get("present"); pr != nil && pr.Kind == jcs.KindObject {
		e := &vlRecordEval{present: true}
		var lhs [][32]byte
		for _, x := range pr.Get("roots").Arr {
			rt := vlRoot{treeSize: x.Get("tree_size").Int, root: x.Get("merkle_root").Str, recordedAs: x.Get("recorded_as").Str, serverTS: x.Get("server_ts").Str, day: d}
			rt.leaf = vlLeaf(c, rt.treeSize, rt.root, rt.recordedAs, rt.serverTS)
			rt.lh = leafHash(rt.leaf)
			e.roots = append(e.roots, rt)
			lhs = append(lhs, rt.lh)
		}
		e.chainRoot = vlChainRoot(lhs)
		leaf := vlDayLeaf(hex.EncodeToString(e.chainRoot[:]), posHex)
		if err := verifyInclusion(leafHash(leaf), uint64(pr.Get("leaf_index").Int), n, hexPathOf(pr.Get("path")), root); err != nil {
			return nil, "present: " + err.Error()
		}
		return e, ""
	}
	nb := rec.Get("absent").Get("neighbours").Arr
	incl := func(x *jcs.Value) error {
		leaf := vlDayLeaf(x.Get("chain_root").Str, x.Get("position").Str)
		return verifyInclusion(leafHash(leaf), uint64(x.Get("leaf_index").Int), n, hexPathOf(x.Get("path")), root)
	}
	switch len(nb) {
	case 0:
		if n == 0 {
			return &vlRecordEval{}, ""
		}
		return nil, fmt.Sprintf("absent without a neighbour in a tree of size %d", n)
	case 1:
		if err := incl(nb[0]); err != nil {
			return nil, "absent: the neighbour: " + err.Error()
		}
		i, q := uint64(nb[0].Get("leaf_index").Int), nb[0].Get("position").Str
		if i == 0 && posHex < q || i == n-1 && q < posHex {
			return &vlRecordEval{}, ""
		}
		return nil, "absent: one neighbour that is neither the first leaf above the position nor the last leaf below it"
	default:
		for _, x := range nb {
			if err := incl(x); err != nil {
				return nil, "absent: a neighbour: " + err.Error()
			}
		}
		i0, i1 := nb[0].Get("leaf_index").Int, nb[1].Get("leaf_index").Int
		q0, q1 := nb[0].Get("position").Str, nb[1].Get("position").Str
		if i1 == i0+1 && q0 < posHex && posHex < q1 {
			return &vlRecordEval{}, ""
		}
		return nil, "absent: two neighbours that are not adjacent leaves around the position"
	}
}

func hexPathOf(v *jcs.Value) [][32]byte {
	var out [][32]byte
	for _, h := range v.Arr {
		b, _ := hex.DecodeString(h.Str)
		var x [32]byte
		copy(x[:], b)
		out = append(out, x)
	}
	return out
}

// due reports whether day d is due at the check time: now >= end(d) + P.
func (r *run) due(d int64) bool { return msSince0001(r.now) >= dayEndMS(d)+vlPublicationMS }

// receiptDay is d = day(server_ts) of a receipt.
func receiptDay(ri *receiptInfo) (int64, bool) { return dayOfTS(ri.serverTS) }

// stepL7 determines the required range [Lo, T] and the missing days. RD are
// the days of the receipts of L8: every CHECKPOINT_RECEIPT whose signature
// holds under the key of 7.1 and that has no RECEIPT_INVALID, the same set
// L8 and r5' (10.9.4) use.
func (vr *vlRun) stepL7(r *run) {
	var rdf []int64
	for _, ri := range r.receiptInfos {
		if !ri.sigOK || ri.invalid {
			continue
		}
		d, ok := receiptDay(ri)
		if !ok || vr.fKnown && d < vr.f {
			continue
		}
		rdf = append(rdf, d)
	}
	if len(rdf) == 0 {
		return
	}
	hasT, t := vr.hasHead, vr.headDay
	lo := rdf[0]
	for _, d := range rdf {
		if d < lo {
			lo = d
		}
		if r.due(d) && (!hasT || d > t) {
			hasT, t = true, d
		}
	}
	if !hasT || lo > t {
		return
	}
	vr.lo, vr.hi, vr.hasRange = lo, t, true
	runStart := int64(-1)
	flush := func(end int64) {
		if runStart < 0 {
			return
		}
		vr.findings.ownFinding(ClsVendorLogUnverified, "", 0, fmt.Sprintf("days %s to %s: %s [days_not_supplied] (format spec 7.4.10 L7, 7.4.11)", dayString(runStart), dayString(end), vlReasons["days_not_supplied"].text))
		runStart = -1
	}
	for d := lo; d <= t; d++ {
		// From 1.10: a day with a hybrid-incomplete object counts in no run
		// of missing days; (g') gives its finding.
		if len(vr.byDay[d]) == 0 && !vr.hybridDays[d] {
			vr.missing[d] = true
			if runStart < 0 {
				runStart = d
			}
			continue
		}
		flush(d - 1)
	}
	flush(t)
	vr.stat.Days.Missing = len(vr.missing)
}

// stepL8 classifies every receipt whose signature holds under the key of
// 7.1, established or not, also with a contradiction or fork of the chain; a
// receipt with RECEIPT_INVALID is passed over, also when its signature
// holds.
func (vr *vlRun) stepL8(r *run) {
	nowMS := msSince0001(r.now)
	type notIncl struct {
		n   int
		seq int64
	}
	notIncluded := map[int64]*notIncl{}
	var nlDays []int64
	for _, ri := range r.receiptInfos {
		if !ri.sigOK || ri.invalid {
			continue
		}
		d, okd := receiptDay(ri)
		ts, okt := parseUTC(ri.serverTS)
		if !okd || !okt {
			continue // the schema reads server_ts as rfc3339 (4.21): never here
		}
		cls := vlClass{treeSize: ri.treeSize, day: d}
		set := func(c, sub string) { cls.class, cls.sub = c, sub }
		switch {
		case vr.fContra:
			set(RcUnchecked, UcFirstDayContradictory)
		case vr.fKnown && d < vr.f:
			set(RcBeforeStart, "")
		case msSince0001(ts) > nowMS+vlFutureMS:
			set(RcFuture, "")
			vr.findings.note(ClsVendorLogUnverified, dayString(d), "receipt_after_check_time", fmt.Sprintf("seq %d, server_ts %s", ri.seq, ri.serverTS))
		case vr.usable[d]:
			dr := vr.records[d]
			switch dr.state {
			case recVerified:
				if dr.m[leafHash(ri.subject)] {
					set(RcIncluded, "")
				} else {
					set(RcNotIncluded, "")
					if notIncluded[d] == nil {
						notIncluded[d] = &notIncl{seq: ri.seq}
						nlDays = append(nlDays, d)
					}
					notIncluded[d].n++
				}
			case recNone:
				set(RcUnchecked, UcNoRecord)
				vr.findings.note(ClsVendorLogUnverified, dayString(d), "no_chain_day_record", fmt.Sprintf("seq %d", ri.seq))
			case recFailed:
				set(RcUnchecked, UcRecordFailed)
			default:
				set(RcUnchecked, UcRecordContradictory)
			}
		case vr.canon[d] != nil:
			set(RcUnchecked, UcDayNotWitnessed)
			if why, ok := vr.notWitnessedReason(vr.canon[d]); ok {
				vr.findings.note(ClsVendorLogUnverified, dayString(d), "day_not_witnessed", "reason "+why)
			}
		case len(vr.byDay[d]) > 0:
			set(RcUnchecked, UcDayContradictory)
		case vr.hybridDays[d]:
			// case 6 from 1.10: S(d) is empty and d has a hybrid-incomplete
			// object; (g') gives the finding.
			set(RcUnchecked, UcHybridIncomplete)
		case r.due(d):
			set(RcMissing, "")
		default:
			set(RcPending, "")
		}
		vr.classes[ri.seq] = cls
	}
	for _, d := range nlDays {
		x := notIncluded[d]
		vr.findings.ownFinding(ClsReceiptNotLogged, dayString(d), x.seq, fmt.Sprintf("day %s: %d receipt(s) missing from the witnessed chain day of their day, the first at seq %d [not_included] (format spec 7.4.10 L8, 7.4.11)", dayString(d), x.n, x.seq))
	}
}

// notWitnessedReason is the reason of L8 case 4 (registry
// vendor_log.not_witnessed_reasons); ok is false when every time stamp of
// c(d) is defective, for then VENDOR_LOG_DEFECTIVE already names the day.
//
// A time stamp that is not confirmed because Z.6 cannot be checked (7.5.7)
// gives the reason outside_profile, like a step 5 that is not performable.
func (vr *vlRun) notWitnessedReason(c *vlObject) (string, bool) {
	if len(c.judged) == 0 {
		return NwNoTimestamp, true
	}
	allDefective := true
	for _, s := range c.judged {
		if s.state != tsa.StateDefective {
			allDefective = false
		}
	}
	if allDefective {
		return "", false
	}
	if len(vr.logRoots) == 0 {
		return NwNoLogRoot, true
	}
	best := ""
	for _, s := range c.judged {
		why := ""
		switch {
		case s.state == tsa.StateDefective:
			continue
		case s.state == tsa.StateConfirmed:
			why = NwLate // c(d) is not broken, so a confirmed time stamp that does not witness is late
		case s.cs == tsa.CaseNotPerformable || s.cs == tsa.CaseZ6NotCheckable:
			why = NwOutsideProfile
		case s.cs == tsa.CaseNoPath:
			why = NwNotChained
		case s.cs == tsa.CaseTestKey:
			why = NwTestKey
		}
		if nwRank[why] > nwRank[best] {
			best = why
		}
	}
	return best, true
}

// stepL9 compares the logged roots of every usable day with a verified
// present record with the prefix roots of the package.
func (vr *vlRun) stepL9(r *run) {
	n := int64(len(r.entries))
	receiptLeaf := map[string]bool{}
	for _, ri := range r.receiptInfos {
		if ri.subject != nil {
			receiptLeaf[string(ri.subject)] = true
		}
	}
	type tr struct {
		t int64
		r string
	}
	matching, contradicting, beyond := map[tr]bool{}, map[tr]bool{}, map[tr]bool{}
	// matching_without_receipt counts distinct leaves, and a receipt with
	// RECEIPT_INVALID is still a receipt of its leaf; gap_witnesses counts
	// distinct roots (tree_size, merkle_root) among the rows with
	// recorded_as gap_witness, not distinct leaves (10.10.2).
	withoutReceipt, gapWitnesses := map[string]bool{}, map[tr]bool{}
	rs := &VendorLogRootsStat{}
	for _, d := range sortedDays(vr.records) {
		dr := vr.records[d]
		if dr.state != recVerified {
			continue
		}
		for _, rt := range dr.roots {
			k := tr{rt.treeSize, rt.root}
			if rt.recordedAs == "gap_witness" {
				gapWitnesses[k] = true
			}
			switch got, _ := r.rootAt(rt.treeSize); {
			case rt.treeSize > n:
				if !beyond[k] {
					vr.beyond = append(vr.beyond, rt)
				}
				beyond[k] = true
			case got == rt.root:
				matching[k] = true
				if rt.recordedAs == "countersigned" && !receiptLeaf[string(rt.leaf)] {
					withoutReceipt[string(rt.leaf)] = true
				}
			default:
				if !contradicting[k] {
					vr.findings.ownFinding(ClsLoggedRootMismatch, dayString(d), 0, fmt.Sprintf("day %s, %s: tree_size %d, merkle_root %s, the package's root over the first %d entries is %s [root_differs] (format spec 7.4.10 L9)", dayString(d), rt.recordedAs, rt.treeSize, rt.root, rt.treeSize, got))
					if vr.tM == 0 || rt.treeSize < vr.tM {
						vr.tM = rt.treeSize
					}
				}
				contradicting[k] = true
			}
		}
	}
	rs.MatchingPrefix, rs.ContradictingPrefix, rs.BeyondPackage = len(matching), len(contradicting), len(beyond)
	rs.MatchingWithoutReceipt, rs.GapWitnesses = len(withoutReceipt), len(gapWitnesses)
	vr.stat.LoggedRoots = rs
}

// finishStat fills the counts that depend on the findings and the classes.
func (vr *vlRun) finishStat(r *run) {
	st := &vr.stat
	st.Days.Contradictory = len(vr.contraDays)
	rc := &VendorLogReceiptsStat{}
	minBad := int64(-1)
	var bestGood int64
	for _, ri := range r.receiptInfos {
		c, ok := vr.classes[ri.seq]
		if !ok {
			continue
		}
		switch c.class {
		case RcIncluded:
			rc.Included++
		case RcNotIncluded:
			rc.NotIncluded++
		case RcUnchecked:
			rc.Unchecked++
		case RcMissing:
			rc.Missing++
		case RcPending:
			rc.Pending++
		case RcBeforeStart:
			rc.BeforeStart++
		case RcFuture:
			rc.Future++
		}
		if c.class != RcIncluded && c.class != RcBeforeStart && (minBad < 0 || c.treeSize < minBad) {
			minBad = c.treeSize
		}
	}
	// r5' (10.9.4): the largest tree_size t of a good receipt such that
	// every receipt with tree_size <= t is good or neutral, i.e. t below the
	// smallest tree_size of a bad one.
	for _, c := range vr.classes {
		if c.class == RcIncluded && (minBad < 0 || c.treeSize < minBad) && c.treeSize > bestGood {
			bestGood = c.treeSize
		}
	}
	if bestGood > 0 {
		rc.IncludedUpToTreeSize = &bestGood
	}
	st.Receipts = rc
	if lc := r.lastCountersigned; lc != nil {
		if c, ok := vr.classes[lc.ReceiptSeq]; ok {
			s := c.class
			st.LastCountersigned = &s
		}
	}
	if st.LoggedRoots == nil {
		st.LoggedRoots = &VendorLogRootsStat{}
	}
}

// finishVendorLog returns the report object vendor_log.
func (r *run) finishVendorLog() *VendorLogStat {
	if r.vlog == nil {
		return nil
	}
	st := r.vlog.stat
	return &st
}
