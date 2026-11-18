package vfy

// Anchor history as an input of the auditor (format spec 8.8, from edition
// 1.10): steps H1 to H11 of 8.8.4, the classification of the history roots
// of 8.8.5 and the report object anchor_history of 10.10.2. The affiliation
// (8.8.6, step H12) is in affiliation.go.
//
// Nothing of this comes from the package (format spec 8.8, 10.1): the pages
// are files of the auditor, read at invocation (H0, auditor_inputs.go). A
// page counts only under a statements key (8.8.3), bound to the chain and to
// a device key of the package (H2 numbers 7 and 8). The one way to exit 2 is
// MERKLE_INCONSISTENT from a root the vendor countersigned or recorded as a
// gap witness more than W_h before the request time R (8.8.5); a root that
// is only reported never yields it, and none of the four classes of 8.8.7
// has exit class 2.
//
// Placement in stage 5 (format spec 10.5): checkAnchorHistory runs H1 to H7
// after the vendor log (step 7), classifyHistoryRoots runs H8 with the
// expected roots (step 8), reportHistoryRoots reports its findings with the
// findings of the expected roots (step 13), finishAnchorHistory runs H9 to
// H11 after the time witnesses (step 11), and anchorHistoryStat writes the
// report object after the exit code (step 15).

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
)

// Codes of registry verifier.anchor_history and cloud_statements.
const (
	HistoryKindV2        = "ledger.anchor_history.v2"
	historyOwnerKind     = "ledger.anchor_history.owner.v1"
	historyWhMS          = int64(900_000)             // W_h (w_h_ms)
	historyLegacyBoundTS = "2026-10-04T00:00:00.000Z" // BL (legacy_boundary)

	HistoryNotSupplied = "not_supplied"
	HistoryChecked     = "checked"

	UseFresh    = "used_fresh"
	UseStale    = "used_stale"
	UseUnjudged = "used_unjudged"
	UseLinked   = "used_linked"
)

// Reasons of H2 (registry verifier.anchor_history.page_reasons, in this
// order).
const (
	hrKeyNotEstablished = "key_not_established"
	hrKeyOtherRole      = "key_other_role"
	hrSignature         = "signature"
	hrPageRules         = "page_rules"
	hrNotV2             = "not_v2"
	hrKeyNotValid       = "key_not_valid"
	hrOtherChain        = "other_chain"
	hrOwnerDiffers      = "owner_differs"
	hrSigningTime       = "signing_time_not_proven"
)

var historyPageReasons = []string{hrKeyNotEstablished, hrKeyOtherRole, hrSignature, hrPageRules, hrNotV2, hrKeyNotValid, hrOtherChain, hrOwnerDiffers, hrSigningTime}

// historyReasonsByClass is registry verifier.anchor_history.reasons_by_class:
// the reasons of each class in their order, which orders the members of
// anchor_history.reasons (10.10.1, "Ordnung").
var historyReasonsByClass = map[string][]string{
	ClsHistoryUnverified: {hrKeyNotEstablished, hrKeyOtherRole, hrNotV2, hrKeyNotValid, hrOtherChain, hrOwnerDiffers, hrSigningTime, "issued_before_request", "pages_missing"},
	ClsHistoryDefective:  {hrSignature},
	ClsHistoryContradict: {hrPageRules, "root_time_differs", "root_dropped", "root_withheld", "fork_dropped", "affiliation_narrowed", "affiliation_withheld",
		"known_range_narrowed", "owner_keys_dropped", "succession_changed", "reference_decreases", "succession_mismatch", "log_mismatch", "log_root_missing",
		"gap_witness_time_differs", "receipt_not_in_history"},
	ClsHistoryFork: {"fork_listed", "forks_omitted", "root_beyond_handover", "predecessor_beyond_handover", "history_root_differs", "reported_root_beyond_package"},
}

// historyNotes is registry verifier.anchor_history.notes, in this order.
var historyNotes = []string{"requested_at_unused", "no_request_time", "archive_pages", "recent_roots_not_found", "package_ended_before_request",
	"reported_beyond_handover", "package_beyond_handover", "predecessor_differs_from_genesis", "linked_history_not_supplied",
	"receipt_roots_unverified_not_in_history"}

// historyH5Reasons are the reasons of H5 (a) to (j); every one of them
// between two used pages of the package blocks the completeness (H11 (b)).
var historyH5Reasons = []string{"root_time_differs", "root_dropped", "root_withheld", "fork_dropped", "affiliation_narrowed", "affiliation_withheld",
	"known_range_narrowed", "owner_keys_dropped", "succession_changed", "reference_decreases"}

// recordedAsOrder is the order of recorded_as in page rule 3 (heartbeat spec
// 9.7).
var recordedAsOrder = map[string]int{"countersigned": 0, "gap_witness": 1, "reported": 2}

// affiliationBases are the codes of heartbeat spec 9.10 (registry
// verifier.affiliation.bases.order, code point order).
var affiliationBases = []string{"common_control", "controlled_by_vendor", "controls_vendor", "former_relation", "key_management", "participation", "shared_management", "vendor"}

// ---------------------------------------------------------------- report

// AnchorHistoryStat is the report object anchor_history (format spec
// 10.10.2).
type AnchorHistoryStat struct {
	Status            string               `json:"status"`
	RequestedAt       *string              `json:"requested_at"`
	Files             int                  `json:"files"`
	Pages             HistoryPagesStat     `json:"pages"`
	PageReasons       []string             `json:"page_reasons"`
	Issued            HistoryIssuedStat    `json:"issued"`
	Keys              []HistoryKeyStat     `json:"keys"`
	Owner             *string              `json:"owner"`
	Coverage          HistoryCoverageStat  `json:"coverage"`
	ReferenceTreeSize *int64               `json:"reference_tree_size"`
	Predecessor       *HistorySuccStat     `json:"predecessor"`
	Successor         *HistorySuccStat     `json:"successor"`
	Roots             HistoryRootsStat     `json:"roots"`
	Forks             HistoryForksStat     `json:"forks"`
	Receipts          HistoryReceiptsStat  `json:"receipts"`
	Completeness      HistoryComplStat     `json:"completeness"`
	Reasons           HistoryReasonsStat   `json:"reasons"`
	Notes             []string             `json:"notes"`
	used              int                  // used pages of the package, for the text block
	reasonTexts       []string             // page_reasons in the order of the registry, for the text block
	keyTexts          []historyKeyTextPart // keys with their source, for the text block
}

type historyKeyTextPart struct {
	keyID, source string
	list          *HistoryKeyListStat
}

// HistoryPagesStat counts the pages (H1, H2 number 10).
type HistoryPagesStat struct {
	Supplied     int `json:"supplied"`
	Distinct     int `json:"distinct"`
	UsedFresh    int `json:"used_fresh"`
	UsedStale    int `json:"used_stale"`
	UsedUnjudged int `json:"used_unjudged"`
	UsedLinked   int `json:"used_linked"`
	NotUsed      int `json:"not_used"`
}

// HistoryIssuedStat is the earliest and the latest server_ts of the used
// pages of the package.
type HistoryIssuedStat struct {
	First *string `json:"first"`
	Last  *string `json:"last"`
}

// HistoryKeyStat is one statements key of a used page with its source
// (format spec 8.8.3).
type HistoryKeyStat struct {
	KeyID  string              `json:"key_id"`
	Source string              `json:"source"`
	List   *HistoryKeyListStat `json:"list"`
}

// HistoryKeyListStat names the effective role list.
type HistoryKeyListStat struct {
	Version     int64  `json:"version"`
	Ausgestellt string `json:"ausgestellt"`
	WurzelID    string `json:"wurzel_id"`
	RootSource  string `json:"root_source"`
}

// HistoryGap is a gap [a, b) of H4, with b nil for infinity.
type HistoryGap [2]*int64

// HistoryCoverageStat is the coverage of H4.
type HistoryCoverageStat struct {
	Status string       `json:"status"`
	Gaps   []HistoryGap `json:"gaps"`
}

// HistorySuccStat is a registered change of chain (predecessor, successor).
type HistorySuccStat struct {
	ChainID  string `json:"chain_id"`
	TreeSize int64  `json:"tree_size"`
}

// HistoryRootsStat counts the history roots (H6, H7, 8.8.5).
type HistoryRootsStat struct {
	Distinct                   int `json:"distinct"`
	Found                      int `json:"found"`
	DifferingBeforeRequest     int `json:"differing_before_request"`
	DifferingAfterRequest      int `json:"differing_after_request"`
	BeyondPackageBeforeRequest int `json:"beyond_package_before_request"`
	BeyondPackageRecent        int `json:"beyond_package_recent"`
	BeyondPackageAfterRequest  int `json:"beyond_package_after_request"`
	BeyondPackageUnjudged      int `json:"beyond_package_unjudged"`
	NotUsedVendorLog           int `json:"not_used_vendor_log"`
}

// HistoryForksStat counts the fork findings (H9).
type HistoryForksStat struct {
	Listed  int   `json:"listed"`
	Omitted int64 `json:"omitted"`
}

// HistoryReceiptsStat counts the receipts of H10.
type HistoryReceiptsStat struct {
	Checked                   int `json:"checked"`
	InHistory                 int `json:"in_history"`
	NotInHistory              int `json:"not_in_history"`
	NotInHistoryUnestablished int `json:"not_in_history_unestablished"`
	ServerTSDiffers           int `json:"server_ts_differs"`
	BeforeLegacyBoundary      int `json:"before_legacy_boundary"`
	NotCovered                int `json:"not_covered"`
}

// HistoryComplStat is the completeness from the history (H11).
type HistoryComplStat struct {
	Status       string  `json:"status"`
	Reason       *string `json:"reason"`
	UpToTreeSize *int64  `json:"up_to_tree_size"`
}

// HistoryReasonsStat are the reasons reported per class (8.8.7).
type HistoryReasonsStat struct {
	Unverified    []string `json:"unverified"`
	Defective     []string `json:"defective"`
	Contradiction []string `json:"contradiction"`
	Fork          []string `json:"fork"`
}

// ---------------------------------------------------------------- state

// ahPair is one pair (server_key_id, server_signature) of a page (H1).
type ahPair struct{ keyID, sig string }

// ahPairState is a pair under an established statements key (8.8.3).
type ahPairState struct {
	ahPair
	key StatementKey
}

// ahSucc is a registered change of chain on a page.
type ahSucc struct {
	chainID  string
	treeSize int64
}

// ahRec is one element of roots (a recording).
type ahRec struct {
	t      int64
	root   string
	as     string
	ts     string
	ms     int64
	tsTime time.Time
}

// ahFork is one element of forks.
type ahFork struct {
	t    int64
	root string
	ts   string
	ms   int64
}

// ahPeriod is one period of affiliation.
type ahPeriod struct {
	bases      []string
	from       string
	fromMS     int64
	until      string // "" for null
	untilMS    int64
	recorded   string
	recordedMS int64
	merged     bool
}

// ahContent is the content of a page that follows heartbeat spec 9.7 (H2
// number 5).
type ahContent struct {
	chainID      string
	ownerKeys    []string
	pred, succ   *ahSucc
	reference    int64
	roots        []ahRec
	forks        []ahFork
	forksOmitted int64
	since        int64
	next         int64 // -1 for null (the range reaches to infinity)
	truncated    bool
	knownSince   string // "" for null
	knownMS      int64
	periods      []ahPeriod
	serverTS     string
	serverMS     int64
	serverTime   time.Time
}

// inRange reports whether t lies in I(P).
func (c *ahContent) inRange(t int64) bool {
	return t >= c.since && (c.next < 0 || t < c.next)
}

// hasRoot reports whether the page lists (t, r, recorded_as).
func (c *ahContent) hasRoot(t int64, root, as string) bool {
	for _, x := range c.roots {
		if x.t == t && x.root == root && x.as == as {
			return true
		}
	}
	return false
}

// ahPage is one distinct page after H1 with its judgement after H2.
type ahPage struct {
	jcs    string
	pairs  []ahPair
	pos    string // place of its first occurrence in the input
	order  int
	copies int

	passed   int    // the highest number of H2 passed
	reason   string // the H2 reason of a page that is not used
	use      string // a value of page_uses for a used page
	sigHolds bool   // a pair under an established key passed number 2
	badSig   bool   // a pair under an established key failed number 2
	fresh    bool
	c        *ahContent
	surv     []*ahPairState // pairs that passed numbers 1, 2 and 6
	chosen   *ahPairState   // the pair of the report (smallest server_key_id)
	blocking bool           // page_rules that blocks the completeness (H11 (a))
}

func (p *ahPage) packagePage() bool {
	return p.use == UseFresh || p.use == UseStale || p.use == UseUnjudged
}

// histRoot is a history root (t, r) of H6 with its classification (H8).
type histRoot struct {
	t        int64
	r        string
	recs     []ahRec // distinct recordings on used pages of the package
	kept     []ahRec // the recordings that count after H7
	recorded bool    // kept contains countersigned or gap_witness
	reported bool    // kept contains reported
	e        int64
	eTS      string
	dropped  bool // no recording remains after H7 (not_used_vendor_log)
	auditor  bool // also an expected root of the auditor (format spec 10.8)
	found    bool
	// class is the case of 8.8.5 for a root without the source auditor:
	// found, mi_inside, differs, mi_beyond, reported_beyond, recent, after,
	// unjudged; "" for a root that is dropped or carries the source auditor.
	class string
	// mi: this pair yields MERKLE_INCONSISTENT (under 8.8.5 or, with the
	// source auditor, under 10.8).
	mi bool
}

func (hr *histRoot) key() string { return fmt.Sprintf("%d:%s", hr.t, hr.r) }

// ahFinding is one finding of the anchor history: per class and reason,
// or per (t, r) or day where 8.8.7 says so, with the count and the earliest
// occurrence.
type ahFinding struct {
	class, reason, key string
	count              int
	first              string
}

type ahFindings struct {
	list []*ahFinding
	idx  map[string]*ahFinding
}

func (fs *ahFindings) note(class, reason, key, detail string) {
	if fs.idx == nil {
		fs.idx = map[string]*ahFinding{}
	}
	k := class + "|" + reason + "|" + key
	f := fs.idx[k]
	if f == nil {
		f = &ahFinding{class: class, reason: reason, key: key, first: detail}
		fs.idx[k] = f
		fs.list = append(fs.list, f)
	}
	f.count++
}

// ahRun is the anchor history of one run.
type ahRun struct {
	chainC   string // C = manifest.chain_id
	supplied bool
	hasR     bool
	rMS      int64
	files    int
	supplCnt int
	pages    []*ahPage // distinct, in input order
	pkgUsed  []*ahPage // used pages of the package, ordered after H5
	linked   map[string][]*ahPage
	linkRel  map[string]string // linked chain -> predecessor | successor
	oc       map[string]map[string]bool

	reasonsSeen map[string]map[string]bool // class -> reason -> reported
	notes       map[string]bool
	blockContra bool // a blocking reason under H11 (a), (b) or (c)
	blockFork   bool // a blocking reason under H11 (d)
	affContra   bool // H5 gave affiliation_narrowed, affiliation_withheld or known_range_narrowed
	issuedLast  string

	findings ahFindings // H2 to H7
	late     ahFindings // H9 to H11

	coverStatus string
	gaps        []HistoryGap
	pagesMiss   bool
	h3          bool
	roots       []*histRoot
	rootIdx     map[string]*histRoot
	forks       map[string]ahFork
	forkOrder   []string
	omitted     int64
	receipts    HistoryReceiptsStat
	rootsStat   HistoryRootsStat
	compl       HistoryComplStat
	hstar       *ahPage
}

func (h *ahRun) reported(class, reason string) {
	if h.reasonsSeen == nil {
		h.reasonsSeen = map[string]map[string]bool{}
	}
	if h.reasonsSeen[class] == nil {
		h.reasonsSeen[class] = map[string]bool{}
	}
	h.reasonsSeen[class][reason] = true
}

// add notes a finding of H2 to H7.
func (h *ahRun) add(fs *ahFindings, class, reason, key, detail string) {
	h.reported(class, reason)
	fs.note(class, reason, key, detail)
}

// emit adds the findings to the run, one per class and reason (or per key).
func (fs *ahFindings) emit(r *run) {
	for _, f := range fs.list {
		d := fmt.Sprintf("reason %s", f.reason)
		if f.count > 1 {
			d += fmt.Sprintf(", %d occurrences", f.count)
		}
		if f.first != "" {
			d += "; first: " + f.first
		}
		r.add(f.class, 0, d+" (format spec 8.8.4, 8.8.7)")
	}
	fs.list, fs.idx = nil, nil
}

// further returns the reason of the pair that got further (H2, several
// pairs), measured by the order of the registry.
//
// further picks the reason of the pair that got furthest; of two pairs that
// got equally far, the reason later in registry page_reasons (format spec
// 8.8.4 H2 "Mehrere Paare": at number 1 key_other_role over
// key_not_established).
func further(a, b string) string {
	if a == "" {
		return b
	}
	if indexOf(historyPageReasons, b) > indexOf(historyPageReasons, a) {
		return b
	}
	return a
}

func indexOf(list []string, s string) int {
	for i, x := range list {
		if x == s {
			return i
		}
	}
	return -1
}

// ---------------------------------------------------------------- helpers

// ownerCommitment is an entry of owner_keys (heartbeat spec 9.7):
// Hex(SHA-256(UTF-8(JCS({appliance_id, chain_id, device_pubkey, kind})))).
func ownerCommitment(applianceID, chainID, devicePubkey string) string {
	b, _ := jcs.CanonGo(map[string]any{"appliance_id": applianceID, "chain_id": chainID, "device_pubkey": devicePubkey, "kind": historyOwnerKind})
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// ownerCommitments is OC(c): one commitment per key of PK with A and c.
func (r *run) ownerCommitments(c string) map[string]bool {
	h := r.ah
	if m, ok := h.oc[c]; ok {
		return m
	}
	m := map[string]bool{}
	if len(r.entries) > 0 && r.entries[0].eventType == "GENESIS" {
		a := r.entries[0].pStr("appliance_id")
		for _, k := range r.deviceKeys {
			m[ownerCommitment(a, c, k)] = true
		}
	}
	h.oc[c] = m
	return m
}

// msForm reads an instant exactly in the form YYYY-MM-DDThh:mm:ss.sssZ.
func msForm(v *jcs.Value) (string, int64, time.Time, bool) {
	s, ok := str(v)
	if !ok || !reMillisTS.MatchString(s) {
		return "", 0, time.Time{}, false
	}
	t, ok := parseUTC(s)
	if !ok {
		return "", 0, time.Time{}, false
	}
	return s, unixMS(t), t, true
}

// anyRFC3339 reads an instant of the type rfc3339 of format spec 2.
func anyRFC3339(v *jcs.Value) (string, int64, time.Time, bool) {
	s, ok := str(v)
	if !ok {
		return "", 0, time.Time{}, false
	}
	t, err := parseRFC3339(s)
	if err != nil {
		return "", 0, time.Time{}, false
	}
	return s, unixMS(t), t, true
}

func msString(ms int64) string { return FormatMillisUTC(time.UnixMilli(ms)) }

func readSucc(v *jcs.Value) (*ahSucc, bool) {
	if v == nil {
		return nil, false
	}
	if v.Kind == jcs.KindNull {
		return nil, true
	}
	if closed(v, "succession", []string{"chain_id", "tree_size"}) != nil {
		return nil, false
	}
	c, ok := str(v.Get("chain_id"))
	if !ok || !reUUID.MatchString(c) {
		return nil, false
	}
	t, ok := intRange(v.Get("tree_size"), 1, maxSafe)
	if !ok {
		return nil, false
	}
	return &ahSucc{chainID: c, treeSize: t}, true
}

func boolOf(v *jcs.Value) (bool, bool) {
	if v == nil || v.Kind != jcs.KindBool {
		return false, false
	}
	return v.Bool, true
}

func succEqual(a, b *ahSucc) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// readHistoryContent is H2 number 5: members and types exactly after
// heartbeat spec 9.7 (kind v2) and registry cloud_statements.anchor_history_v2,
// every instant exactly YYYY-MM-DDThh:mm:ss.sssZ except server_ts in roots
// (type rfc3339), and every page rule. It returns what is violated.
func readHistoryContent(v *jcs.Value) (*ahContent, string) {
	if err := closed(v, "statement_jcs", []string{"affiliation", "chain_id", "forks", "forks_omitted", "kind", "next_since_tree_size",
		"owner_keys", "predecessor", "reference_tree_size", "roots", "server_ts", "since_tree_size", "successor", "truncated"}); err != nil {
		return nil, err.Error()
	}
	c := &ahContent{}
	var ok bool
	if c.chainID, ok = str(v.Get("chain_id")); !ok || !reUUID.MatchString(c.chainID) {
		return nil, "chain_id is not a uuid"
	}
	keys, ok := array(v.Get("owner_keys"), 1, 16)
	if !ok {
		return nil, "owner_keys is not an array of 1 to 16 entries"
	}
	for _, k := range keys {
		s, ok := str(k)
		if !ok || !reHex64.MatchString(s) {
			return nil, "owner_keys holds a value that is not hex64"
		}
		c.ownerKeys = append(c.ownerKeys, s)
	}
	if c.pred, ok = readSucc(v.Get("predecessor")); !ok {
		return nil, "predecessor is neither null nor {chain_id, tree_size}"
	}
	if c.succ, ok = readSucc(v.Get("successor")); !ok {
		return nil, "successor is neither null nor {chain_id, tree_size}"
	}
	if c.reference, ok = intRange(v.Get("reference_tree_size"), 0, maxSafe); !ok {
		return nil, "reference_tree_size is not an int from 0"
	}
	roots, ok := array(v.Get("roots"), 0, 500)
	if !ok {
		return nil, "roots is not an array of at most 500 roots"
	}
	for i, x := range roots {
		if closed(x, "roots[]", []string{"tree_size", "merkle_root", "recorded_as", "server_ts"}) != nil {
			return nil, fmt.Sprintf("roots[%d] has not exactly the members tree_size, merkle_root, recorded_as, server_ts", i)
		}
		rec := ahRec{}
		if rec.t, ok = intRange(x.Get("tree_size"), 1, maxSafe); !ok {
			return nil, fmt.Sprintf("roots[%d].tree_size is not an int from 1", i)
		}
		if rec.root, ok = str(x.Get("merkle_root")); !ok || !reHex64.MatchString(rec.root) {
			return nil, fmt.Sprintf("roots[%d].merkle_root is not hex64", i)
		}
		if rec.as, ok = str(x.Get("recorded_as")); !ok {
			return nil, fmt.Sprintf("roots[%d].recorded_as is not a string", i)
		}
		if _, known := recordedAsOrder[rec.as]; !known {
			return nil, fmt.Sprintf("roots[%d].recorded_as %q is not countersigned, gap_witness or reported", i, rec.as)
		}
		if rec.ts, rec.ms, rec.tsTime, ok = anyRFC3339(x.Get("server_ts")); !ok {
			return nil, fmt.Sprintf("roots[%d].server_ts is not rfc3339", i)
		}
		c.roots = append(c.roots, rec)
	}
	forks, ok := array(v.Get("forks"), 0, 500)
	if !ok {
		return nil, "forks is not an array of at most 500 fork findings"
	}
	for i, x := range forks {
		if closed(x, "forks[]", []string{"tree_size", "merkle_root", "detected_ts"}) != nil {
			return nil, fmt.Sprintf("forks[%d] has not exactly the members tree_size, merkle_root, detected_ts", i)
		}
		f := ahFork{}
		if f.t, ok = intRange(x.Get("tree_size"), 1, maxSafe); !ok {
			return nil, fmt.Sprintf("forks[%d].tree_size is not an int from 1", i)
		}
		if f.root, ok = str(x.Get("merkle_root")); !ok || !reHex64.MatchString(f.root) {
			return nil, fmt.Sprintf("forks[%d].merkle_root is not hex64", i)
		}
		if f.ts, f.ms, _, ok = msForm(x.Get("detected_ts")); !ok {
			return nil, fmt.Sprintf("forks[%d].detected_ts is not YYYY-MM-DDThh:mm:ss.sssZ", i)
		}
		c.forks = append(c.forks, f)
	}
	if c.forksOmitted, ok = intRange(v.Get("forks_omitted"), 0, maxSafe); !ok {
		return nil, "forks_omitted is not an int from 0"
	}
	if c.since, ok = intRange(v.Get("since_tree_size"), 0, maxSafe); !ok {
		return nil, "since_tree_size is not an int from 0"
	}
	c.next = -1
	if n := v.Get("next_since_tree_size"); n == nil || n.Kind != jcs.KindNull {
		if c.next, ok = intRange(n, 1, maxSafe); !ok {
			return nil, "next_since_tree_size is neither null nor an int from 1"
		}
	}
	if c.truncated, ok = boolOf(v.Get("truncated")); !ok {
		return nil, "truncated is not a bool"
	}
	aff := v.Get("affiliation")
	if closed(aff, "affiliation", []string{"known_since", "periods"}) != nil {
		return nil, "affiliation has not exactly the members known_since, periods"
	}
	if ks := aff.Get("known_since"); ks.Kind != jcs.KindNull {
		if c.knownSince, c.knownMS, _, ok = msForm(ks); !ok {
			return nil, "affiliation.known_since is neither null nor YYYY-MM-DDThh:mm:ss.sssZ"
		}
	}
	periods, ok := array(aff.Get("periods"), 0, 16)
	if !ok {
		return nil, "affiliation.periods is not an array of at most 16 periods"
	}
	for i, x := range periods {
		if closed(x, "periods[]", []string{"bases", "from", "merged", "recorded_ts", "until"}) != nil {
			return nil, fmt.Sprintf("affiliation.periods[%d] has not exactly the members bases, from, merged, recorded_ts, until", i)
		}
		p := ahPeriod{}
		bases, ok := array(x.Get("bases"), 1, 8)
		if !ok {
			return nil, fmt.Sprintf("affiliation.periods[%d].bases is not an array of 1 to 8 codes", i)
		}
		for _, b := range bases {
			s, ok := str(b)
			if !ok || indexOf(affiliationBases, s) < 0 {
				return nil, fmt.Sprintf("affiliation.periods[%d].bases holds a value that is no code of heartbeat spec 9.10", i)
			}
			p.bases = append(p.bases, s)
		}
		if p.from, p.fromMS, _, ok = msForm(x.Get("from")); !ok {
			return nil, fmt.Sprintf("affiliation.periods[%d].from is not YYYY-MM-DDThh:mm:ss.sssZ", i)
		}
		if p.merged, ok = boolOf(x.Get("merged")); !ok {
			return nil, fmt.Sprintf("affiliation.periods[%d].merged is not a bool", i)
		}
		if p.recorded, p.recordedMS, _, ok = msForm(x.Get("recorded_ts")); !ok {
			return nil, fmt.Sprintf("affiliation.periods[%d].recorded_ts is not YYYY-MM-DDThh:mm:ss.sssZ", i)
		}
		if u := x.Get("until"); u.Kind != jcs.KindNull {
			if p.until, p.untilMS, _, ok = msForm(u); !ok {
				return nil, fmt.Sprintf("affiliation.periods[%d].until is neither null nor YYYY-MM-DDThh:mm:ss.sssZ", i)
			}
		}
		c.periods = append(c.periods, p)
	}
	if c.serverTS, c.serverMS, c.serverTime, ok = msForm(v.Get("server_ts")); !ok {
		return nil, "server_ts is not YYYY-MM-DDThh:mm:ss.sssZ"
	}
	if why := c.pageRules(); why != "" {
		return nil, why
	}
	return c, ""
}

// pageRules checks the ten page rules of heartbeat spec 9.7; instants are
// compared in whole milliseconds (format spec 2).
func (c *ahContent) pageRules() string {
	// 1.
	if (c.next < 0) != !c.truncated {
		return "page rule 1: next_since_tree_size is null exactly when truncated is false"
	}
	if c.next >= 0 {
		if c.next <= c.since {
			return "page rule 1: next_since_tree_size is not greater than since_tree_size"
		}
		for _, x := range c.roots {
			if c.next <= x.t {
				return "page rule 1: next_since_tree_size is not greater than every tree_size of the page"
			}
		}
		for _, x := range c.forks {
			if c.next <= x.t {
				return "page rule 1: next_since_tree_size is not greater than every tree_size of the page"
			}
		}
	}
	// 2.
	for _, x := range c.roots {
		if !c.inRange(x.t) {
			return fmt.Sprintf("page rule 2: root tree_size %d outside the range of the page", x.t)
		}
	}
	for _, x := range c.forks {
		if !c.inRange(x.t) {
			return fmt.Sprintf("page rule 2: fork tree_size %d outside the range of the page", x.t)
		}
	}
	// 3.
	seen := map[string]bool{}
	for i, x := range c.roots {
		k := fmt.Sprintf("%d|%s|%s", x.t, x.root, x.as)
		if seen[k] {
			return fmt.Sprintf("page rule 3: root (%d, %s, %s) listed twice", x.t, x.root, x.as)
		}
		seen[k] = true
		if i > 0 && !rootLess(c.roots[i-1], x) {
			return "page rule 3: roots are not strictly ascending by tree_size, server_ts, recorded_as, merkle_root"
		}
	}
	// 4.
	seenF := map[string]bool{}
	for i, x := range c.forks {
		k := fmt.Sprintf("%d|%s", x.t, x.root)
		if seenF[k] {
			return fmt.Sprintf("page rule 4: fork finding (%d, %s) listed twice", x.t, x.root)
		}
		seenF[k] = true
		if i > 0 {
			a := c.forks[i-1]
			if !(a.t < x.t || a.t == x.t && (a.ms < x.ms || a.ms == x.ms && a.root < x.root)) {
				return "page rule 4: forks are not strictly ascending by tree_size, detected_ts, merkle_root"
			}
		}
	}
	// 5.
	for _, x := range c.roots {
		if x.ms > c.serverMS {
			return "page rule 5: a server_ts of a root lies after the server_ts of the page"
		}
	}
	for _, x := range c.forks {
		if x.ms > c.serverMS {
			return "page rule 5: a detected_ts lies after the server_ts of the page"
		}
	}
	// 6.
	for _, x := range c.roots {
		if x.as != "reported" && x.t > c.reference {
			return fmt.Sprintf("page rule 6: reference_tree_size %d is below the recorded root at tree_size %d", c.reference, x.t)
		}
	}
	// 7.
	if c.pred != nil && c.pred.chainID == c.chainID || c.succ != nil && c.succ.chainID == c.chainID ||
		c.pred != nil && c.succ != nil && c.pred.chainID == c.succ.chainID {
		return "page rule 7: predecessor and successor differ neither from chain_id nor from each other"
	}
	// 8.
	for i := 1; i < len(c.ownerKeys); i++ {
		if c.ownerKeys[i-1] >= c.ownerKeys[i] {
			return "page rule 8: owner_keys are not strictly ascending"
		}
	}
	// 9.
	if c.knownSince != "" && c.knownMS > c.serverMS {
		return "page rule 9: known_since lies after server_ts"
	}
	// 10.
	for i, p := range c.periods {
		for j := 1; j < len(p.bases); j++ {
			if p.bases[j-1] >= p.bases[j] {
				return fmt.Sprintf("page rule 10: bases of period %d are not strictly ascending", i)
			}
		}
		if p.fromMS >= c.serverMS {
			return fmt.Sprintf("page rule 10: from of period %d does not lie before server_ts", i)
		}
		if p.recordedMS > c.serverMS {
			return fmt.Sprintf("page rule 10: recorded_ts of period %d lies after server_ts", i)
		}
		if p.until != "" && (p.untilMS <= p.fromMS || p.untilMS > c.serverMS) {
			return fmt.Sprintf("page rule 10: until of period %d is not after from or lies after server_ts", i)
		}
		if i > 0 {
			q := c.periods[i-1]
			if q.until == "" {
				return fmt.Sprintf("page rule 10: period %d has until null and is not the last", i-1)
			}
			if q.fromMS > p.fromMS || q.untilMS > p.fromMS {
				return fmt.Sprintf("page rule 10: periods %d and %d are not ordered by from or overlap", i-1, i)
			}
			if q.untilMS == p.fromMS && strings.Join(q.bases, ",") == strings.Join(p.bases, ",") {
				return fmt.Sprintf("page rule 10: the adjoining periods %d and %d have the same bases", i-1, i)
			}
		}
	}
	return ""
}

func rootLess(a, b ahRec) bool {
	switch {
	case a.t != b.t:
		return a.t < b.t
	case a.ms != b.ms:
		return a.ms < b.ms
	case a.as != b.as:
		return recordedAsOrder[a.as] < recordedAsOrder[b.as]
	}
	return a.root < b.root
}

// printableASCII is format spec 2: 0x20 to 0x7E.
func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// windowValid is H2 number 6 for an entry of the role list: gueltig_ab <=
// server_ts < gueltig_bis and server_ts < widerrufen_ab, where present, to
// the nanosecond as in format spec 10.7.
func windowValid(e *vendorListKey, t time.Time) bool {
	if e == nil {
		return false
	}
	if t.Before(e.ab) {
		return false
	}
	if !e.bis.IsZero() && !t.Before(e.bis) {
		return false
	}
	if !e.widerr.IsZero() && !t.Before(e.widerr) {
		return false
	}
	return true
}

// ---------------------------------------------------------------- H1 to H7

// checkAnchorHistory runs H1 to H7 of format spec 8.8.4 (10.5 stage 5,
// step 7). Without an anchor history the steps H1 to H11 are dropped (H0).
func (r *run) checkAnchorHistory() {
	h := &ahRun{linked: map[string][]*ahPage{}, linkRel: map[string]string{}, oc: map[string]map[string]bool{}, notes: map[string]bool{}, rootIdx: map[string]*histRoot{}, forks: map[string]ahFork{}}
	r.ah = h
	h.chainC = r.man.chainID
	h.hasR = r.opt.RequestedAtSet
	if h.hasR {
		h.rMS = unixMS(r.opt.RequestedAt)
	}
	h.files = len(r.opt.AnchorHistory)
	if h.files == 0 {
		if h.hasR {
			h.notes["requested_at_unused"] = true // format spec 10.8
		}
		return
	}
	h.supplied = true
	h.pool(r.opt.AnchorHistory)
	h.stepH2(r)
	h.stepH3()
	h.stepH4()
	h.stepH5(r)
	h.stepH6()
	h.stepH7(r)
	h.findings.emit(r)
}

// pool is H1: identical statement_jcs are one page with the set of its
// distinct pairs, whatever the order of the files.
func (h *ahRun) pool(files []AnchorHistoryFile) {
	byJCS := map[string]*ahPage{}
	for fi, f := range files {
		for pi, hp := range f.Pages {
			h.supplCnt++
			p := byJCS[hp.StatementJCS]
			if p == nil {
				pos := fmt.Sprintf("--anchor-history file %d", fi+1)
				if f.Container {
					pos += fmt.Sprintf(", pages[%d]", pi)
				}
				p = &ahPage{jcs: hp.StatementJCS, pos: pos, order: len(h.pages)}
				byJCS[hp.StatementJCS] = p
				h.pages = append(h.pages, p)
			}
			p.copies++
			pr := ahPair{keyID: hp.ServerKeyID, sig: hp.Signature}
			dup := false
			for _, x := range p.pairs {
				if x == pr {
					dup = true
				}
			}
			if !dup {
				p.pairs = append(p.pairs, pr)
			}
		}
	}
}

// fail ends the check of a page with the reason of H2.
func (h *ahRun) fail(p *ahPage, reason, detail string) {
	p.reason = reason
	cls := ClsHistoryUnverified
	switch reason {
	case hrSignature:
		cls = ClsHistoryDefective
	case hrPageRules:
		cls = ClsHistoryContradict
	}
	d := p.pos
	if p.c != nil {
		d += ", server_ts " + p.c.serverTS
	}
	if detail != "" {
		d += ": " + detail
	}
	if reason == hrSignature {
		return // reported once per page with badSig below
	}
	h.add(&h.findings, cls, reason, "", d)
}

// stepH2 judges every page after H2 numbers 1 to 10: first numbers 1 to 6
// for every page, then the pages of the package (numbers 7 to 9), then the
// pages of other chains, which are linked only when a used page of the
// package or GENESIS.predecessor_chain names their chain.
func (h *ahRun) stepH2(r *run) {
	c := r.man.chainID
	for _, p := range h.pages {
		h.upToWindow(r, p)
	}
	for _, p := range h.pages {
		if p.reason == "" && p.c.chainID == c {
			p.passed = 7
			h.deviceAndTime(r, p, false)
		}
	}
	// Linked chains (number 7): named by a used page of the package or by
	// GENESIS.predecessor_chain, which serves only for recognition.
	names := map[string]string{}
	for _, p := range h.pages {
		if !p.packagePage() {
			continue
		}
		if p.c.pred != nil {
			if _, ok := names[p.c.pred.chainID]; !ok {
				names[p.c.pred.chainID] = "predecessor"
			}
		}
		if p.c.succ != nil {
			if _, ok := names[p.c.succ.chainID]; !ok {
				names[p.c.succ.chainID] = "successor"
			}
		}
	}
	if g := r.genesisPredecessor(); g != "" {
		names[g] = "predecessor"
	}
	for _, p := range h.pages {
		if p.reason != "" || p.c.chainID == c {
			continue
		}
		rel, linked := names[p.c.chainID]
		if !linked {
			h.fail(p, hrOtherChain, "chain_id "+p.c.chainID)
			continue
		}
		p.passed = 7
		h.deviceAndTime(r, p, true)
		if p.use == UseLinked {
			h.linked[p.c.chainID] = append(h.linked[p.c.chainID], p)
			h.linkRel[p.c.chainID] = rel
		}
	}
	// Every pair under an established key whose signature does not hold is
	// ANCHOR_HISTORY_DEFECTIVE signature, also on a used page; once per page.
	for _, p := range h.pages {
		if p.badSig {
			d := p.pos
			if p.c != nil {
				d += ", server_ts " + p.c.serverTS
			}
			h.add(&h.findings, ClsHistoryDefective, hrSignature, "", d)
		}
	}
	for _, p := range h.pages {
		if p.packagePage() {
			h.pkgUsed = append(h.pkgUsed, p)
		}
		if h.ofPackage(p) && p.passed >= 8 && (h.issuedLast == "" || p.c.serverTS > h.issuedLast) {
			h.issuedLast = p.c.serverTS
		}
	}
}

// genesisPredecessor is GENESIS.predecessor_chain.chain_id, "" without.
func (r *run) genesisPredecessor() string {
	if len(r.entries) == 0 || r.entries[0].eventType != "GENESIS" {
		return ""
	}
	pc := r.entries[0].payload.Get("predecessor_chain")
	if pc == nil || pc.Kind != jcs.KindObject {
		return ""
	}
	s, _ := str(pc.Get("chain_id"))
	return s
}

// upToWindow runs H2 numbers 1 to 6 on a page.
func (h *ahRun) upToWindow(r *run, p *ahPage) {
	// Numbers 1 and 2 concern the pairs.
	far := ""
	var surv []*ahPairState
	for _, pr := range p.pairs {
		sk, ok := r.statementKey(pr.keyID)
		if !ok {
			why := hrKeyNotEstablished
			if r.keyOfOtherRole(pr.keyID) {
				why = hrKeyOtherRole
			}
			far = further(far, why)
			continue
		}
		if !verifySig(sk.Pubkey, []byte(p.jcs), pr.sig) {
			p.badSig = true
			far = further(far, hrSignature)
			continue
		}
		surv = append(surv, &ahPairState{ahPair: pr, key: sk})
	}
	if len(surv) == 0 {
		if far == hrSignature {
			p.passed = 1
		}
		h.fail(p, far, "server_key_id "+pairIDs(p.pairs))
		return
	}
	p.sigHolds, p.passed = true, 2
	// Number 3.
	v, err := jcs.Parse([]byte(p.jcs))
	switch {
	case !printableASCII(p.jcs):
		h.pageRulesFail(r, p, "statement_jcs is not printable ASCII")
		return
	case err != nil:
		h.pageRulesFail(r, p, "statement_jcs is not I-JSON: "+err.Error())
		return
	case v.Kind != jcs.KindObject:
		h.pageRulesFail(r, p, "statement_jcs is not an object")
		return
	case string(jcs.Canon(v)) != p.jcs:
		h.pageRulesFail(r, p, "statement_jcs is not the JCS form of its content")
		return
	}
	p.passed = 3
	// Number 4.
	if k, ok := str(v.Get("kind")); !ok || k != HistoryKindV2 {
		h.fail(p, hrNotV2, fmt.Sprintf("kind %s", kindText(v.Get("kind"))))
		return
	}
	p.passed = 4
	// Number 5.
	content, why := readHistoryContent(v)
	if content == nil {
		h.pageRulesFail(r, p, why)
		return
	}
	p.c, p.passed = content, 5
	// Number 6 concerns the pairs again.
	var surv6 []*ahPairState
	for _, ps := range surv {
		if ps.key.Pinned || windowValid(ps.key.Entry, content.serverTime) {
			surv6 = append(surv6, ps)
		}
	}
	if len(surv6) == 0 {
		h.fail(p, hrKeyNotValid, "server_key_id "+pairIDs(p.pairs))
		return
	}
	p.surv, p.passed = surv6, 6
}

func pairIDs(ps []ahPair) string {
	var ids []string
	for _, x := range ps {
		ids = append(ids, x.keyID)
	}
	return strings.Join(ids, ", ")
}

func kindText(v *jcs.Value) string {
	if s, ok := str(v); ok {
		return fmt.Sprintf("%q", s)
	}
	if v == nil {
		return "missing"
	}
	return "not a string"
}

// pageRulesFail ends a page with page_rules (numbers 3 and 5) and notes
// whether it blocks the completeness (H11 (a)): its signature holds and its
// statement_jcs reads as an I-JSON object with the member chain_id = C.
func (h *ahRun) pageRulesFail(r *run, p *ahPage, why string) {
	if v, err := jcs.Parse([]byte(p.jcs)); err == nil && v.Kind == jcs.KindObject {
		if c, ok := str(v.Get("chain_id")); ok && c == r.man.chainID {
			p.blocking = true
			h.blockContra = true
		}
	}
	h.fail(p, hrPageRules, why)
}

// deviceAndTime runs H2 numbers 8 and 9 and number 10 on a page of the
// package or a linked page.
func (h *ahRun) deviceAndTime(r *run, p *ahPage, linked bool) {
	oc := r.ownerCommitments(p.c.chainID)
	common := false
	for _, k := range p.c.ownerKeys {
		if oc[k] {
			common = true
		}
	}
	if !common {
		h.fail(p, hrOwnerDiffers, "no commitment of owner_keys matches a device key of the package")
		return
	}
	p.passed = 8
	p.fresh = h.hasR && p.c.serverMS >= h.rMS-historyWhMS
	var surv9 []*ahPairState
	for _, ps := range p.surv {
		if !p.fresh && ps.key.Revoked {
			continue
		}
		surv9 = append(surv9, ps)
	}
	if len(surv9) == 0 {
		h.fail(p, hrSigningTime, "revoked key "+pairIDs(p.pairs))
		return
	}
	p.passed = 9
	sort.SliceStable(surv9, func(i, j int) bool { return surv9[i].keyID < surv9[j].keyID })
	p.surv, p.chosen = surv9, surv9[0]
	switch {
	case linked:
		p.use = UseLinked
	case !h.hasR:
		p.use = UseUnjudged
	case p.fresh:
		p.use = UseFresh
	default:
		p.use = UseStale
	}
}

// stepH3: with R and no fresh page of the package, but a page of the
// package that passed numbers 1 to 8, issued_before_request once.
func (h *ahRun) stepH3() {
	if !h.hasR {
		return
	}
	fresh, stale, passed8 := 0, 0, false
	for _, p := range h.pkgUsed {
		if p.use == UseFresh {
			fresh++
		} else {
			stale++
		}
	}
	for _, p := range h.pages {
		if h.ofPackage(p) && p.passed >= 8 {
			passed8 = true
		}
	}
	if fresh == 0 && passed8 {
		h.h3 = true
		h.add(&h.findings, ClsHistoryUnverified, "issued_before_request", "", "latest server_ts supplied "+h.issuedLast+", request time "+msString(h.rMS))
	}
	if fresh > 0 && stale > 0 {
		h.notes["archive_pages"] = true
	}
}

// ofPackage reports whether a page passed H2 number 7 as a page of the
// package (chain_id = C).
func (h *ahRun) ofPackage(p *ahPage) bool {
	return p.c != nil && p.passed >= 7 && p.c.chainID == h.chainC
}

// coverage is the union of the ranges I(P) of pages (H4): the status and
// the gaps, ascending.
func coverage(pages []*ahPage) (string, []HistoryGap) {
	type iv struct{ a, b int64 } // b = -1 for infinity
	var ivs []iv
	for _, p := range pages {
		ivs = append(ivs, iv{p.c.since, p.c.next})
	}
	sort.Slice(ivs, func(i, j int) bool { return ivs[i].a < ivs[j].a })
	var gaps []HistoryGap
	gap := func(a, b int64) {
		aa := a
		var bp *int64
		if b >= 0 {
			bb := b
			bp = &bb
		}
		gaps = append(gaps, HistoryGap{&aa, bp})
	}
	pos := int64(0) // everything below pos is covered; -1: covered to infinity
	for _, x := range ivs {
		if pos < 0 {
			break
		}
		if x.a > pos {
			gap(pos, x.a)
		}
		if x.b < 0 {
			pos = -1
		} else if x.b > pos {
			pos = x.b
		}
	}
	if pos >= 0 {
		gap(pos, -1)
	}
	switch {
	case len(ivs) == 0:
		return "none", gaps
	case len(gaps) == 0:
		return "complete", []HistoryGap{}
	}
	return "partial", gaps
}

// stepH4: the coverage over the fresh used pages of the package (without R
// over all used pages of the package, only for information); with R and a
// gap pages_missing once, with the gap that starts lowest.
func (h *ahRun) stepH4() {
	var ps []*ahPage
	for _, p := range h.pkgUsed {
		if !h.hasR || p.use == UseFresh {
			ps = append(ps, p)
		}
	}
	h.coverStatus, h.gaps = coverage(ps)
	if h.hasR && len(h.gaps) > 0 {
		h.pagesMiss = true
		g := h.gaps[0]
		end := "infinity"
		if g[1] != nil {
			end = fmt.Sprint(*g[1])
		}
		h.add(&h.findings, ClsHistoryUnverified, "pages_missing", "", fmt.Sprintf("gap [%d, %s)", *g[0], end))
	}
}

// pageOrder is the order of H5: server_ts, then the bytes of statement_jcs.
func pageOrder(ps []*ahPage) {
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].c.serverMS != ps[j].c.serverMS {
			return ps[i].c.serverMS < ps[j].c.serverMS
		}
		return ps[i].jcs < ps[j].jcs
	})
}

// interval is a half-open interval of instants in whole milliseconds; to
// is ignored when open.
type interval struct {
	from, to int64
	open     bool
}

// covered reports whether [iv.from, iv.to) lies in the union of us.
func covered(iv interval, us []interval) bool {
	if iv.to <= iv.from {
		return true
	}
	pos := iv.from
	changed := true
	for changed && pos < iv.to {
		changed = false
		for _, u := range us {
			if u.from <= pos && (u.open || u.to > pos) {
				if u.open {
					return true
				}
				pos = u.to
				changed = true
			}
		}
	}
	return pos >= iv.to
}

// affCover is the affiliation a page states for the instants before cut:
// its periods, a period with until null ending at endOpen (or open when
// endOpen < 0).
func affCover(c *ahContent, endOpen int64) []interval {
	var out []interval
	for _, p := range c.periods {
		switch {
		case p.until != "":
			out = append(out, interval{from: p.fromMS, to: p.untilMS})
		case endOpen >= 0:
			out = append(out, interval{from: p.fromMS, to: endOpen})
		default:
			out = append(out, interval{from: p.fromMS, open: true})
		}
	}
	return out
}

// comparePages is H5 for one pair in which A precedes B; it returns the
// reasons (a) to (j) in their order with a detail each.
func comparePages(a, b *ahContent) []ahReason {
	var out []ahReason
	add := func(code, detail string) { out = append(out, ahReason{code, detail}) }
	// (a)
	for _, x := range a.roots {
		for _, y := range b.roots {
			// format spec 8.8.4 H5 (a): compared in whole milliseconds,
			// like every instant of the section.
			if x.t == y.t && x.root == y.root && x.as == y.as && x.ms != y.ms {
				add("root_time_differs", fmt.Sprintf("tree_size %d %s: %s and %s", x.t, x.as, x.ts, y.ts))
			}
		}
	}
	// (b)
	for _, x := range a.roots {
		if b.inRange(x.t) && !b.hasRoot(x.t, x.root, x.as) {
			add("root_dropped", fmt.Sprintf("tree_size %d %s", x.t, x.as))
		}
	}
	// (c)
	for _, y := range b.roots {
		if a.inRange(y.t) && y.ms < a.serverMS-historyWhMS && !a.hasRoot(y.t, y.root, y.as) {
			add("root_withheld", fmt.Sprintf("tree_size %d %s, server_ts %s", y.t, y.as, y.ts))
		}
	}
	// (d)
	for _, f := range a.forks {
		if !b.inRange(f.t) || b.forksOmitted != 0 {
			continue
		}
		found := false
		for _, g := range b.forks {
			if g.t == f.t && g.root == f.root {
				found = true
			}
		}
		if !found {
			add("fork_dropped", fmt.Sprintf("tree_size %d", f.t))
		}
	}
	// (e): at an instant before A.server_ts A states an affiliation and B
	// does not; an open period of A ends at A.server_ts. B is not older
	// than A, so an open period of B lasts beyond A.server_ts.
	coverA := affCover(a, a.serverMS)
	coverB := affCover(b, -1)
	for _, iv := range coverA {
		iv.to = min64(iv.to, a.serverMS)
		if !covered(iv, coverB) {
			add("affiliation_narrowed", fmt.Sprintf("from %s", msString(iv.from)))
			break
		}
	}
	// (f): at an instant before A.server_ts B states an affiliation over a
	// period recorded before A.server_ts - W_h with merged = false, and A
	// does not. A merged period of B never gives this reason: merging also
	// covers the time between the old periods, which no earlier page had to
	// show (format spec 8.8.4 H5 (f), heartbeat spec 9.10 time reference 4).
	for _, p := range b.periods {
		if p.merged || p.recordedMS >= a.serverMS-historyWhMS {
			continue
		}
		iv := interval{from: p.fromMS, to: a.serverMS}
		if p.until != "" {
			iv.to = min64(p.untilMS, a.serverMS)
		}
		if !covered(iv, coverA) {
			add("affiliation_withheld", fmt.Sprintf("period from %s recorded %s", p.from, p.recorded))
			break
		}
	}
	// (g)
	if a.knownSince != "" && b.knownSince != "" && b.knownMS > a.knownMS && b.knownMS <= a.serverMS {
		add("known_range_narrowed", fmt.Sprintf("known_since %s, then %s", a.knownSince, b.knownSince))
	}
	// (h)
	for _, k := range a.ownerKeys {
		if indexOf(b.ownerKeys, k) < 0 {
			add("owner_keys_dropped", k)
			break
		}
	}
	// (i)
	if !succEqual(a.pred, b.pred) || a.succ != nil && !succEqual(a.succ, b.succ) {
		add("succession_changed", "")
	}
	// (j)
	if b.reference < a.reference {
		add("reference_decreases", fmt.Sprintf("%d, then %d", a.reference, b.reference))
	}
	return out
}

type ahReason struct{ code, detail string }

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// stepH5 compares the used pages of one chain among themselves and checks
// succession_mismatch for a linked pair.
func (h *ahRun) stepH5(r *run) {
	cmp := func(ps []*ahPage, pkg bool) {
		pageOrder(ps)
		for i := range ps {
			for j := i + 1; j < len(ps); j++ {
				for _, x := range comparePages(ps[i].c, ps[j].c) {
					d := fmt.Sprintf("%s (server_ts %s) against %s (server_ts %s)", ps[i].pos, ps[i].c.serverTS, ps[j].pos, ps[j].c.serverTS)
					if x.detail != "" {
						d += ": " + x.detail
					}
					h.add(&h.findings, ClsHistoryContradict, x.code, "", d)
					if pkg {
						h.blockContra = true
					}
					switch x.code {
					case "affiliation_narrowed", "affiliation_withheld", "known_range_narrowed":
						// format spec 8.8.6 number 9: only between two
						// pages of the package; between pages of a linked
						// chain such a reason does not set contradictory.
						if pkg {
							h.affContra = true
						}
					}
				}
			}
		}
	}
	cmp(h.pkgUsed, true)
	for _, c := range sortedChains(h.linked) {
		cmp(h.linked[c], false)
	}
	// succession_mismatch for a linked pair (P of the package, L linked),
	// in both directions (format spec 8.8.4 H5): L as the predecessor of P,
	// every used page of L with a successor names {P, T} with the T of
	// P.predecessor; L as the successor of P, every used page of L with a
	// predecessor names {P, T} with the T of P.successor.
	c := r.man.chainID
	for _, p := range h.pkgUsed {
		if p.c.pred != nil {
			for _, l := range h.linked[p.c.pred.chainID] {
				if l.c.succ == nil {
					continue
				}
				if l.c.succ.chainID != c || l.c.succ.treeSize != p.c.pred.treeSize {
					h.add(&h.findings, ClsHistoryContradict, "succession_mismatch", "", fmt.Sprintf("%s names predecessor %s at tree_size %d, %s names successor %s at tree_size %d",
						p.pos, p.c.pred.chainID, p.c.pred.treeSize, l.pos, l.c.succ.chainID, l.c.succ.treeSize))
					h.blockContra = true
				}
			}
		}
		if p.c.succ != nil {
			for _, l := range h.linked[p.c.succ.chainID] {
				if l.c.pred == nil {
					continue
				}
				if l.c.pred.chainID != c || l.c.pred.treeSize != p.c.succ.treeSize {
					h.add(&h.findings, ClsHistoryContradict, "succession_mismatch", "", fmt.Sprintf("%s names successor %s at tree_size %d, %s names predecessor %s at tree_size %d",
						p.pos, p.c.succ.chainID, p.c.succ.treeSize, l.pos, l.c.pred.chainID, l.c.pred.treeSize))
					h.blockContra = true
				}
			}
		}
	}
}

func sortedChains(m map[string][]*ahPage) []string {
	var out []string
	for c := range m {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// stepH6 forms the history roots over the used pages of the package and the
// fork findings.
func (h *ahRun) stepH6() {
	for _, p := range h.pkgUsed {
		for _, x := range p.c.roots {
			k := fmt.Sprintf("%d:%s", x.t, x.root)
			hr := h.rootIdx[k]
			if hr == nil {
				hr = &histRoot{t: x.t, r: x.root}
				h.rootIdx[k] = hr
				h.roots = append(h.roots, hr)
			}
			dup := false
			for _, y := range hr.recs {
				if y.as == x.as && y.ts == x.ts {
					dup = true
				}
			}
			if !dup {
				hr.recs = append(hr.recs, x)
			}
		}
		for _, f := range p.c.forks {
			k := fmt.Sprintf("%d:%s", f.t, f.root)
			if _, ok := h.forks[k]; !ok {
				h.forks[k] = f
				h.forkOrder = append(h.forkOrder, k)
			}
		}
		if p.c.forksOmitted > h.omitted {
			h.omitted = p.c.forksOmitted
		}
	}
	sort.SliceStable(h.roots, func(i, j int) bool {
		if h.roots[i].t != h.roots[j].t {
			return h.roots[i].t < h.roots[j].t
		}
		return h.roots[i].r < h.roots[j].r
	})
	for _, hr := range h.roots {
		hr.kept = hr.recs
	}
}

// settle computes recorded_as and e of a history root from its kept
// recordings (H6, after H7).
func (hr *histRoot) settle() {
	hr.recorded, hr.reported, hr.dropped = false, false, len(hr.kept) == 0
	for _, x := range hr.kept {
		if x.as == "reported" {
			hr.reported = true
		} else {
			hr.recorded = true
		}
	}
	first := true
	for _, x := range hr.kept {
		if hr.recorded == (x.as == "reported") {
			continue // e from countersigned and gap_witness, or only reported
		}
		if first || x.ms < hr.e {
			hr.e, hr.eTS, first = x.ms, x.ts, false
		}
	}
}

// stepH7 compares the pages of the package with the checked chain-day
// records of the vendor log for C, if the log yielded usable days with one.
func (h *ahRun) stepH7(r *run) {
	vr := r.vlog
	any := false
	if vr != nil {
		for d := range vr.usable {
			if dr := vr.records[d]; dr != nil && dr.state == recVerified {
				any = true
			}
		}
	}
	if !any {
		for _, hr := range h.roots {
			hr.settle()
		}
		return
	}
	c := r.man.chainID
	checked := func(ts string) (*vlDayRecords, int64, bool) {
		d, ok := dayOfTS(ts)
		if !ok || !vr.usable[d] {
			return nil, 0, false
		}
		dr := vr.records[d]
		if dr == nil || dr.state != recVerified {
			return nil, 0, false
		}
		return dr, d, true
	}
	// First bullet: every recording countersigned or gap_witness on a used
	// page of the package whose day is usable and checked must be in the
	// record of that day.
	badDays := map[int64]bool{}
	for _, hr := range h.roots {
		var kept []ahRec
		for _, x := range hr.recs {
			if x.as != "reported" {
				if dr, d, ok := checked(x.ts); ok && !dr.m[leafHash(vlLeaf(c, x.t, x.root, x.as, x.ts))] {
					if !badDays[d] {
						badDays[d] = true
						h.add(&h.findings, ClsHistoryContradict, "log_mismatch", dayString(d), fmt.Sprintf("day %s: tree_size %d %s %s not in the chain-day record", dayString(d), x.t, x.as, x.ts))
						h.blockContra = true
					}
					continue
				}
			}
			kept = append(kept, x)
		}
		hr.kept = kept
		hr.settle()
	}
	// Second bullet: every root of a checked present record must be on every
	// fresh used page of the package that covers it and was issued at least
	// W_h after it.
	gw := map[string]map[string]bool{}
	for _, d := range sortedDays(vr.usable) {
		dr := vr.records[d]
		if dr == nil || dr.state != recVerified {
			continue
		}
		for _, rt := range dr.roots {
			if rt.recordedAs == "gap_witness" {
				k := fmt.Sprintf("%d:%s", rt.treeSize, rt.root)
				if gw[k] == nil {
					gw[k] = map[string]bool{}
				}
				gw[k][rt.serverTS] = true
			}
			t, err := parseRFC3339(rt.serverTS)
			if err != nil {
				continue
			}
			s := unixMS(t)
			for _, p := range h.pkgUsed {
				if p.use != UseFresh || !p.c.inRange(rt.treeSize) || p.c.serverMS < s+historyWhMS {
					continue
				}
				if !p.c.hasRoot(rt.treeSize, rt.root, rt.recordedAs) {
					h.add(&h.findings, ClsHistoryContradict, "log_root_missing", "", fmt.Sprintf("tree_size %d %s %s of day %s missing on %s", rt.treeSize, rt.recordedAs, rt.serverTS, dayString(d), p.pos))
					h.blockContra = true
					continue
				}
				if rt.recordedAs == "gap_witness" {
					for _, x := range p.c.roots {
						if x.t == rt.treeSize && x.root == rt.root && x.as == "gap_witness" && x.ts != rt.serverTS {
							h.add(&h.findings, ClsHistoryContradict, "gap_witness_time_differs", "", fmt.Sprintf("tree_size %d: %s on %s, %s in the log", rt.treeSize, x.ts, p.pos, rt.serverTS))
							h.blockContra = true
						}
					}
				}
			}
		}
	}
	// Third bullet: two gap witnesses of one root with different server_ts
	// in the checked records of C.
	var keys []string
	for k := range gw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if len(gw[k]) > 1 {
			h.add(&h.findings, ClsHistoryContradict, "gap_witness_time_differs", "", fmt.Sprintf("root %s: two gap witnesses with different server_ts in the vendor log", k))
			h.blockContra = true
		}
	}
}

// ---------------------------------------------------------------- H8

// classifyHistoryRoots is H8 (format spec 8.8.5) at 10.5 stage 5, step 8:
// history roots merged with the auditor's expected roots by (t, r); every
// other history root takes the topmost case that applies.
//
// format spec 8.8.5 merges by (t, r), so only with auditor roots given as
// TREE_SIZE:ROOT; a root given without tree_size stays an auditor root of
// its own.
func (r *run) classifyHistoryRoots() {
	h := r.ah
	if h == nil || !h.supplied {
		return
	}
	n := int64(len(r.entries))
	band := h.rMS - historyWhMS
	for _, hr := range h.roots {
		if hr.dropped {
			h.rootsStat.NotUsedVendorLog++
			continue
		}
		for _, x := range r.expected {
			if x.valid && x.root.TreeSize == hr.t && x.root.Root == hr.r {
				hr.auditor = true
			}
		}
		got, inside := r.rootAt(hr.t)
		inside = inside && hr.t <= n
		before := h.hasR && hr.e < band
		// The counts of 10.10.2 follow t, root(t), e and R for every
		// history root.
		//
		// format spec 10.10.2 (roots): a pair that also carries the source
		// auditor is counted by t, root(t), e and R like every history
		// root; its finding follows 10.8.
		switch {
		case inside && got == hr.r:
			hr.found = true
			h.rootsStat.Found++
		case inside && before:
			h.rootsStat.DifferingBeforeRequest++
		case inside:
			h.rootsStat.DifferingAfterRequest++
		case !h.hasR:
			h.rootsStat.BeyondPackageUnjudged++
		case before:
			h.rootsStat.BeyondPackageBeforeRequest++
		case hr.e < h.rMS:
			h.rootsStat.BeyondPackageRecent++
		default:
			h.rootsStat.BeyondPackageAfterRequest++
		}
		if hr.auditor {
			// Format spec 10.8: the finding of the pair follows the rule of
			// the auditor's root; it is MERKLE_INCONSISTENT when not found.
			hr.mi = !hr.found
			continue
		}
		switch {
		case inside && got == hr.r:
			hr.class = "found"
		case inside && hr.recorded && before:
			hr.class, hr.mi = "mi_inside", true
		case inside:
			hr.class = "differs"
			// H11 (step 11) reads the classification of step 8; the finding
			// itself is reported at step 13.
			h.reported(ClsHistoryFork, "history_root_differs")
			h.blockFork = true
		case hr.recorded && before:
			hr.class, hr.mi = "mi_beyond", true
			h.notes["package_ended_before_request"] = true
		case !hr.recorded && before:
			hr.class = "reported_beyond"
			h.reported(ClsHistoryFork, "reported_root_beyond_package")
			h.blockFork = true
		case h.hasR && hr.e < h.rMS:
			hr.class = "recent"
			h.notes["recent_roots_not_found"] = true
		case h.hasR:
			hr.class = "after"
		default:
			hr.class = "unjudged"
			// format spec 8.8.5: the note no_request_time belongs to this
			// case; the text block states a missing request time always
			// (8.8.1).
			h.notes["no_request_time"] = true
		}
	}
	h.rootsStat.Distinct = len(h.roots)
}

// reportHistoryRoots reports the findings of H8 with the findings of the
// expected roots (10.5 stage 5, step 13): once per (t, r).
func (r *run) reportHistoryRoots() {
	h := r.ah
	if h == nil || !h.supplied {
		return
	}
	n := int64(len(r.entries))
	lastReceipt := ""
	for _, ri := range r.receiptInfos {
		if ri.sigOK && !ri.invalid && (lastReceipt == "" || tsAfter(ri.serverTS, lastReceipt)) {
			lastReceipt = ri.serverTS
		}
	}
	rs := "without request time"
	if h.hasR {
		rs = "request time R " + msString(h.rMS) + ", R - W_h " + msString(h.rMS-historyWhMS)
	}
	for _, hr := range h.roots {
		switch hr.class {
		case "mi_inside":
			got, _ := r.rootAt(hr.t)
			r.add(ClsMerkleInconsistent, 0, fmt.Sprintf("anchor history: the vendor recorded root %s for tree_size %d at %s (%s), before the request; the package has %s there (format spec 8.8.5)",
				hr.r, hr.t, hr.eTS, rs, got))
		case "mi_beyond":
			last := "none"
			if lastReceipt != "" {
				last = lastReceipt
			}
			r.add(ClsMerkleInconsistent, 0, fmt.Sprintf("anchor history: the vendor recorded root %s for tree_size %d at %s (%s), before the request; the package ends at %d entries (note package_ended_before_request: latest receipt of the package %s; an export made before the request, or a truncation at an earlier seal) (format spec 8.8.5)",
				hr.r, hr.t, hr.eTS, rs, n, last))
		case "differs":
			got, _ := r.rootAt(hr.t)
			kind := "recorded"
			if !hr.recorded {
				kind = "only reported"
			}
			r.add(ClsHistoryFork, 0, fmt.Sprintf("reason history_root_differs: root %s for tree_size %d (%s, e %s, %s), the package has %s there (format spec 8.8.5)", hr.r, hr.t, kind, hr.eTS, rs, got))
		case "reported_beyond":
			r.add(ClsHistoryFork, 0, fmt.Sprintf("reason reported_root_beyond_package: root %s for tree_size %d, only reported at %s (%s), the package ends at %d entries (format spec 8.8.5)", hr.r, hr.t, hr.eTS, rs, n))
		}
	}
}

// tsAfter compares two rfc3339 instants in whole milliseconds.
func tsAfter(a, b string) bool {
	ta, e1 := parseRFC3339(a)
	tb, e2 := parseRFC3339(b)
	return e1 == nil && e2 == nil && unixMS(ta) > unixMS(tb)
}

// historyFound is the number of history roots found (NO_ANCHOR, 10.5 stage
// 5, step 12).
func (r *run) historyFound() int {
	n := 0
	if h := r.ah; h != nil {
		for _, hr := range h.roots {
			if hr.found {
				n++
			}
		}
	}
	return n
}

// ---------------------------------------------------------------- H9 to H11

// finishAnchorHistory runs H9 to H11 after the time witnesses (10.5 stage
// 5, step 11), with the classification of step 8.
func (r *run) finishAnchorHistory() {
	h := r.ah
	if h == nil || !h.supplied {
		return
	}
	h.stepH9(r)
	h.stepH10(r)
	h.findStar()
	h.late.emit(r)
	h.stepH11()
}

// stepH9 reports fork findings and roots beyond a handover.
func (h *ahRun) stepH9(r *run) {
	n := int64(len(r.entries))
	for _, k := range h.forkOrder {
		f := h.forks[k]
		where := "beyond the package (t > N)"
		if f.t <= n {
			got, _ := r.rootAt(f.t)
			switch {
			case got == f.root:
				where = "equal to root(t) of the package"
			case h.recordedAt(f.t, f.root):
				where = "equal to a recorded root"
			default:
				where = "neither root(t) nor a recorded root"
			}
		}
		h.add(&h.late, ClsHistoryFork, "fork_listed", k, fmt.Sprintf("fork finding tree_size %d merkle_root %s, detected %s: %s", f.t, f.root, f.ts, where))
		h.blockFork = true
	}
	if h.omitted > 0 {
		h.add(&h.late, ClsHistoryFork, "forks_omitted", "", fmt.Sprintf("forks_omitted %d", h.omitted))
		h.blockFork = true
	}
	seenT := map[int64]bool{}
	for _, p := range h.pkgUsed {
		if p.c.succ == nil || seenT[p.c.succ.treeSize] {
			continue
		}
		t := p.c.succ.treeSize
		seenT[t] = true
		for _, hr := range h.roots {
			if hr.dropped || hr.t <= t {
				continue
			}
			if hr.recorded {
				h.add(&h.late, ClsHistoryFork, "root_beyond_handover", "", fmt.Sprintf("root tree_size %d beyond the handover at tree_size %d to %s", hr.t, t, p.c.succ.chainID))
				h.blockFork = true
			} else {
				h.notes["reported_beyond_handover"] = true
			}
		}
		if n > t {
			h.notes["package_beyond_handover"] = true
		}
	}
	c := r.man.chainID
	for _, lc := range sortedChains(h.linked) {
		for _, p := range h.linked[lc] {
			if p.c.succ == nil || p.c.succ.chainID != c {
				continue
			}
			for _, x := range p.c.roots {
				if x.t <= p.c.succ.treeSize {
					continue
				}
				if x.as == "reported" {
					h.notes["reported_beyond_handover"] = true
					continue
				}
				h.add(&h.late, ClsHistoryFork, "predecessor_beyond_handover", "", fmt.Sprintf("root tree_size %d %s of the predecessor chain %s beyond the handover at tree_size %d", x.t, x.as, lc, p.c.succ.treeSize))
				h.blockFork = true
			}
		}
	}
	gp := r.genesisPredecessor()
	for _, p := range h.pkgUsed {
		if p.c.pred == nil {
			continue
		}
		// format spec 8.8.4 H9: predecessor_differs_from_genesis when
		// predecessor names a chain and GENESIS names none or another one.
		if gp != p.c.pred.chainID {
			h.notes["predecessor_differs_from_genesis"] = true
		}
		// format spec 8.8.4 H9: linked_history_not_supplied when no
		// supplied page of that chain passed H2 numbers 1 to 5 (only then
		// is its chain_id read from established bytes).
		supplied := false
		for _, q := range h.pages {
			if q.c != nil && q.c.chainID == p.c.pred.chainID {
				supplied = true
			}
		}
		if !supplied {
			h.notes["linked_history_not_supplied"] = true
		}
	}
}

// recordedAt reports whether (t, r) is a history root recorded as
// countersigned or gap_witness.
func (h *ahRun) recordedAt(t int64, root string) bool {
	hr := h.rootIdx[fmt.Sprintf("%d:%s", t, root)]
	return hr != nil && hr.recorded
}

// stepH10 judges every receipt that counts as anchoring under 7.1 against
// the used pages of the package.
func (h *ahRun) stepH10(r *run) {
	bl, _ := parseUTC(historyLegacyBoundTS)
	blMS := unixMS(bl)
	notIn, notInSeq := 0, int64(0)
	for _, ri := range r.receiptInfos {
		if !ri.sigOK || ri.invalid {
			continue
		}
		t, err := parseRFC3339(ri.serverTS)
		if err != nil {
			continue
		}
		s := unixMS(t)
		h.receipts.Checked++
		if s < blMS {
			h.receipts.BeforeLegacyBoundary++
			continue
		}
		listed, sameTime := false, false
		for _, p := range h.pkgUsed {
			for _, x := range p.c.roots {
				if x.as == "countersigned" && x.t == ri.treeSize && x.root == ri.root {
					listed = true
					if x.ms == s {
						sameTime = true
					}
				}
			}
		}
		if listed {
			h.receipts.InHistory++
			if !sameTime {
				h.receipts.ServerTSDiffers++
			}
			continue
		}
		later := false
		for _, p := range h.pkgUsed {
			if p.c.inRange(ri.treeSize) && p.c.serverMS >= s+historyWhMS {
				later = true
			}
		}
		switch {
		case later && ri.established:
			h.receipts.NotInHistory++
			notIn++
			if notInSeq == 0 || ri.seq < notInSeq {
				notInSeq = ri.seq
			}
		case later:
			h.receipts.NotInHistoryUnestablished++
			h.notes["receipt_roots_unverified_not_in_history"] = true
		default:
			h.receipts.NotCovered++
		}
	}
	if notIn > 0 {
		h.add(&h.late, ClsHistoryContradict, "receipt_not_in_history", "", fmt.Sprintf("%d receipts, smallest seq %d", notIn, notInSeq))
		h.blockContra = true
	}
}

// findStar picks H* (format spec 8.8.6 number 3): the used page of the
// package with the largest (server_ts, bytes of statement_jcs).
func (h *ahRun) findStar() {
	for _, p := range h.pkgUsed {
		if h.hstar == nil || p.c.serverMS > h.hstar.c.serverMS || p.c.serverMS == h.hstar.c.serverMS && p.jcs > h.hstar.jcs {
			h.hstar = p
		}
	}
}

// stepH11 is the completeness from the history.
func (h *ahRun) stepH11() {
	freshUsed := false
	for _, p := range h.pkgUsed {
		if p.use == UseFresh {
			freshUsed = true
		}
	}
	mi := false
	var upTo int64
	foundAny := false
	for _, hr := range h.roots {
		if hr.mi {
			// format spec 8.8.4 H11: a pair that also carries the source
			// auditor and is not found counts as MERKLE_INCONSISTENT from a
			// history root, although its finding arises under 10.8.
			mi = true
		}
		if hr.found {
			foundAny = true
			if hr.t > upTo {
				upTo = hr.t
			}
		}
	}
	if h.hasR && h.coverStatus == "complete" && !h.blockContra && !h.blockFork && !mi && foundAny {
		h.compl = HistoryComplStat{Status: "established", UpToTreeSize: &upTo}
		return
	}
	st := "not_established"
	if h.hasR && freshUsed {
		st = "partial"
	}
	passed7 := false
	owner8 := false
	for _, p := range h.pages {
		if h.ofPackage(p) {
			passed7 = true
			if p.reason == hrOwnerDiffers {
				owner8 = true
			}
		}
	}
	var why string
	switch {
	case !h.hasR:
		why = "no_request_time"
	case !passed7:
		why = "no_usable_page"
	// format spec 8.8.4 H11 owner_differs: at least one page of the package
	// failed only at number 8 and none is used.
	case owner8 && len(h.pkgUsed) == 0:
		why = "owner_differs"
	case h.h3:
		why = "issued_before_request"
	case h.pagesMiss:
		why = "pages_missing"
	case h.blockContra:
		why = "contradiction"
	case h.blockFork:
		why = "fork"
	case mi:
		why = "root_missing"
	default:
		why = "no_root_found"
	}
	h.compl = HistoryComplStat{Status: st, Reason: &why}
}

// ---------------------------------------------------------------- H13

func (h *ahRun) noteList() []string {
	out := []string{}
	for _, n := range historyNotes {
		if h.notes[n] {
			out = append(out, n)
		}
	}
	return out
}

func (h *ahRun) reasonList(class string) []string {
	out := []string{}
	for _, c := range historyReasonsByClass[class] {
		if h.reasonsSeen[class][c] {
			out = append(out, c)
		}
	}
	return out
}

// historyKeyList is the effective role list as anchor_history.keys[].list
// names it.
func (r *run) historyKeyList() *HistoryKeyListStat {
	if r.roles == nil || r.roles.q == nil {
		return nil
	}
	q := r.roles.q
	return &HistoryKeyListStat{Version: q.version, Ausgestellt: q.ausgestellt, WurzelID: q.wurzelID, RootSource: q.rootSource}
}

// anchorHistoryStat writes the report object anchor_history (format spec
// 8.8.4 step H13, 10.10.2); without an anchor history every count is 0,
// every list empty, and requested_at and the note requested_at_unused follow
// 10.8.
func (r *run) anchorHistoryStat() *AnchorHistoryStat {
	h := r.ah
	if h == nil {
		return nil
	}
	st := &AnchorHistoryStat{
		Status:      HistoryNotSupplied,
		Files:       h.files,
		PageReasons: []string{},
		Keys:        []HistoryKeyStat{},
		Coverage:    HistoryCoverageStat{Status: "none", Gaps: []HistoryGap{}},
		Reasons: HistoryReasonsStat{Unverified: h.reasonList(ClsHistoryUnverified), Defective: h.reasonList(ClsHistoryDefective),
			Contradiction: h.reasonList(ClsHistoryContradict), Fork: h.reasonList(ClsHistoryFork)},
		Notes: h.noteList(),
	}
	if h.hasR {
		s := FormatMillisUTC(r.opt.RequestedAt)
		st.RequestedAt = &s
	}
	if !h.supplied {
		why := "not_supplied"
		st.Completeness = HistoryComplStat{Status: "not_established", Reason: &why}
		return st
	}
	st.Status = HistoryChecked
	st.Pages.Supplied, st.Pages.Distinct = h.supplCnt, len(h.pages)
	reasons := map[string]bool{}
	keys := map[string]historyKeyTextPart{}
	reached8, passed8 := false, false
	for _, p := range h.pages {
		switch p.use {
		case UseFresh:
			st.Pages.UsedFresh++
		case UseStale:
			st.Pages.UsedStale++
		case UseUnjudged:
			st.Pages.UsedUnjudged++
		case UseLinked:
			st.Pages.UsedLinked++
		default:
			st.Pages.NotUsed++
			reasons[p.reason] = true
		}
		if p.chosen != nil {
			k := historyKeyTextPart{keyID: p.chosen.keyID, source: SourceRoleList}
			if p.chosen.key.Pinned {
				k.source = SourcePinned
			} else {
				k.list = r.historyKeyList()
			}
			keys[k.keyID] = k
		}
		if h.ofPackage(p) {
			reached8 = true
			if p.passed >= 8 {
				passed8 = true
			}
		}
	}
	for _, c := range historyPageReasons {
		if reasons[c] {
			st.PageReasons = append(st.PageReasons, c)
		}
	}
	var ids []string
	for id := range keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		k := keys[id]
		st.Keys = append(st.Keys, HistoryKeyStat{KeyID: k.keyID, Source: k.source, List: k.list})
		st.keyTexts = append(st.keyTexts, k)
	}
	switch {
	case passed8:
		o := "matches"
		st.Owner = &o
	case reached8:
		o := "differs"
		st.Owner = &o
	}
	for _, p := range h.pkgUsed {
		ts := p.c.serverTS
		if st.Issued.First == nil || p.c.serverMS < msOf(*st.Issued.First) {
			st.Issued.First = &ts
		}
		if st.Issued.Last == nil || p.c.serverMS > msOf(*st.Issued.Last) {
			st.Issued.Last = &ts
		}
	}
	st.used = len(h.pkgUsed)
	st.Coverage = HistoryCoverageStat{Status: h.coverStatus, Gaps: h.gaps}
	if st.Coverage.Gaps == nil {
		st.Coverage.Gaps = []HistoryGap{}
	}
	if hs := h.hstar; hs != nil {
		ref := hs.c.reference
		st.ReferenceTreeSize = &ref
		if hs.c.pred != nil {
			st.Predecessor = &HistorySuccStat{ChainID: hs.c.pred.chainID, TreeSize: hs.c.pred.treeSize}
		}
		if hs.c.succ != nil {
			st.Successor = &HistorySuccStat{ChainID: hs.c.succ.chainID, TreeSize: hs.c.succ.treeSize}
		}
	}
	st.Roots = h.rootsStat
	st.Forks = HistoryForksStat{Listed: len(h.forkOrder), Omitted: h.omitted}
	st.Receipts = h.receipts
	st.Completeness = h.compl
	return st
}

// msOf reads an instant in the form YYYY-MM-DDThh:mm:ss.sssZ as whole
// milliseconds.
func msOf(s string) int64 {
	t, _ := parseUTC(s)
	return unixMS(t)
}
