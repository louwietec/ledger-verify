package vfy

// The evidence level (format spec 10.9, from edition 1.10) and the report
// object evidence_level (10.10.2).
//
// The level is a function of what the run recorded (10.9.3), of the exit
// code and of the finding classes. It is determined after the exit code
// (10.5 stage 5, step 15), adds no finding, removes none and changes no
// other result, and this step reads no clock, no system root store and no
// file. evidenceInputs copies the recorded values of a run into evInputs;
// evaluateEvidence is a function of evInputs alone, so that every rule of
// 10.9.2 to 10.9.6 can be tested on its own.
//
// The level supports statements on how strongly the chain presented is
// evidenced against rewriting by its key holder. It is no legal
// classification, and it says nothing about the content of the calls.

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"louwietec.com/ledger-verify/verifier/internal/tsa"
)

// States of registry verifier.evidence_level.state_order (10.9.2).
const (
	EvRated        = "rated"
	EvChainInvalid = "chain_invalid"
	EvFormatError  = "format_error"
)

// Conditions of registry verifier.evidence_level.condition_order (10.9.1).
const (
	CondTimeWitness          = "time_witness"
	CondExpectedRootFound    = "expected_root_found"
	CondReceiptKeyConfirmed  = "receipt_key_confirmed"
	CondTimeWitnessQualified = "time_witness_qualified"
	CondReceiptsLogged       = "receipts_logged"
	CondCompleteness         = "completeness_from_history"
	CondLogDayQualified      = "log_day_qualified"
)

// evConditionOrder is registry verifier.evidence_level.condition_order.
var evConditionOrder = []string{CondTimeWitness, CondExpectedRootFound, CondReceiptKeyConfirmed,
	CondTimeWitnessQualified, CondReceiptsLogged, CondCompleteness, CondLogDayQualified}

// evRuleItem is one element of the conditions of a level in registry
// verifier.evidence_level.rule: a code, or a group of the form {need: any,
// conditions} that is met when one of its codes is met and reaches as far
// as the larger reach of those met. Level 3 needs (3), (4) or (7), (5) and
// (6): (4) and (7) are the two ways to the qualified time (format spec
// 10.9.1, 10.9.5).
type evRuleItem struct {
	code  string
	group []string
}

// codes are the condition codes of the item.
func (it evRuleItem) codes() []string {
	if it.group != nil {
		return it.group
	}
	return []string{it.code}
}

// met reports whether the item is met: a code when its condition is met, a
// group when one of its conditions is met.
func (it evRuleItem) met(conds map[string]evCond) bool {
	for _, c := range it.codes() {
		if conds[c].met {
			return true
		}
	}
	return false
}

// reach is the reach of the item: of a code its reach, of a group the
// larger reach of the conditions met; 0 when the item is not met.
func (it evRuleItem) reach(conds map[string]evCond) int64 {
	var r int64
	for _, c := range it.codes() {
		if x := conds[c]; x.met && x.reach > r {
			r = x.reach
		}
	}
	return r
}

// evRule is registry verifier.evidence_level.rule: the conditions of each
// level above 0 and whether one of them suffices (10.9.1).
var evRule = map[int]struct {
	need  string
	items []evRuleItem
}{
	1: {"any", []evRuleItem{{code: CondTimeWitness}, {code: CondExpectedRootFound}, {code: CondReceiptKeyConfirmed}}},
	2: {"all", []evRuleItem{{code: CondReceiptKeyConfirmed}}},
	3: {"all", []evRuleItem{{code: CondReceiptKeyConfirmed}, {group: []string{CondTimeWitnessQualified, CondLogDayQualified}},
		{code: CondReceiptsLogged}, {code: CondCompleteness}}},
}

// ruleCodes are the condition codes of the items of a level.
func ruleCodes(level int) map[string]bool {
	out := map[string]bool{}
	for _, it := range evRule[level].items {
		for _, c := range it.codes() {
			out[c] = true
		}
	}
	return out
}

// evQualifiedGapMS is G_q = 129 600 000 ms (36 hours): condition (7)
// credits a receipt only if the genTime of the day stamp, truncated to whole
// milliseconds, lies at most G_q after its server_ts (format spec 10.9.1,
// 10.9.4, reason qualified_day_stamp_gap).
const evQualifiedGapMS = 129_600_000

// evMaterialClasses is registry verifier.evidence_level.material_classes:
// exit 2 only from these classes keeps the state rated (10.9.2).
var evMaterialClasses = map[string]bool{ClsContentMismatch: true, ClsReportMismatch: true}

// Reasons of registry verifier.evidence_level.reasons (10.9.4).
const (
	rsNoTimeAnchor           = "no_time_anchor"
	rsNoTSARoot              = "no_tsa_root_supplied"
	rsSignatureNotCheckable  = "signature_not_checkable"
	rsNotChainedAuditor      = "not_chained_to_auditor_root"
	rsPublishedTestKey       = "published_test_key"
	rsTokenExtUnusable       = "token_extensions_unusable"
	rsNoExpectedRoot         = "no_expected_root_found"
	rsNoReceipt              = "no_receipt"
	rsKeyNotConfirmed        = "key_not_confirmed"
	rsKeyIsDeviceKey         = "key_is_device_key"
	rsNoQualifiedRoot        = "no_qualified_root_supplied"
	rsNotChainedQualified    = "not_chained_to_qualified_root"
	rsQualifiedRootInPackage = "qualified_root_in_package"
	rsOutsideWindow          = "outside_qualified_window"
	rsSigningCertNotBound    = "signing_certificate_not_bound"
	rsQSMalformed            = "qualified_statement_malformed"
	rsNoQS                   = "no_qualified_statement"
	rsVLNotSupplied          = "vendor_log_not_supplied"
	rsVLNotEstablished       = "vendor_log_not_established"
	rsVLContradiction        = "vendor_log_contradiction"
	rsReceiptNotLogged       = "receipt_not_logged"
	rsDayStampNotConfirmed   = "day_timestamp_not_confirmed"
	rsReceiptNotCheckable    = "receipt_not_checkable"
	rsReceiptDayNotClosed    = "receipt_day_not_closed"
	rsReceiptAfterCheckTime  = "receipt_after_check_time"
	rsLogDayNotSupplied      = "log_day_not_supplied"
	rsReceiptsBeforeStart    = "receipts_before_log_start"
	rsLoggedRootMismatch     = "logged_root_mismatch"
	rsHistoryNotSupplied     = "anchor_history_not_supplied"
	rsRequestedAtNotSupplied = "requested_at_not_supplied"
	rsHistoryNotEstablished  = "anchor_history_not_established"
	rsHistoryPartial         = "anchor_history_partial"
	rsHistoryContradiction   = "anchor_history_contradiction"
	rsNoHistoryRoot          = "no_history_root_found"
	rsNoQualifiedLogRoot     = "no_qualified_log_root_supplied"
	rsNoReceiptIncluded      = "no_receipt_included"
	rsNotChainedQualifiedLog = "not_chained_to_qualified_log_root"
	rsDayStampLate           = "qualified_day_stamp_late"
	rsDayStampGap            = "qualified_day_stamp_gap"
)

// evReasonOrder is registry verifier.evidence_level.reason_order.
var evReasonOrder = []string{rsNoTimeAnchor, rsNoTSARoot, rsSignatureNotCheckable, rsNotChainedAuditor,
	rsPublishedTestKey, rsTokenExtUnusable, rsNoExpectedRoot, rsNoReceipt, rsKeyNotConfirmed, rsKeyIsDeviceKey,
	rsNoQualifiedRoot, rsNotChainedQualified, rsQualifiedRootInPackage, rsOutsideWindow, rsSigningCertNotBound,
	rsQSMalformed, rsNoQS, rsVLNotSupplied, rsVLNotEstablished, rsVLContradiction, rsReceiptNotLogged,
	rsDayStampNotConfirmed, rsReceiptNotCheckable, rsReceiptDayNotClosed, rsReceiptAfterCheckTime,
	rsLogDayNotSupplied, rsReceiptsBeforeStart, rsLoggedRootMismatch, rsHistoryNotSupplied,
	rsRequestedAtNotSupplied, rsHistoryNotEstablished, rsHistoryPartial, rsHistoryContradiction,
	rsNoHistoryRoot, rsNoQualifiedLogRoot, rsNoReceiptIncluded, rsNotChainedQualifiedLog, rsDayStampLate, rsDayStampGap}

// stageQS is the stage qualified_statement of conditions (4) and (7); its
// code is rsQSMalformed or rsNoQS (registry stage_codes).
const stageQS = "qualified_statement"

// evGlobal and evStages are the columns "Gründe ohne Gegenstand" and
// "Stufen je Gegenstand" of the table of 10.9.4 (registry
// verifier.evidence_level.conditions.<code>.global and .stages).
var evGlobal = map[string][]string{
	CondTimeWitness:          {rsNoTimeAnchor, rsNoTSARoot},
	CondExpectedRootFound:    {rsNoExpectedRoot},
	CondReceiptKeyConfirmed:  {rsNoReceipt},
	CondTimeWitnessQualified: {rsNoTimeAnchor, rsNoQualifiedRoot},
	CondReceiptsLogged:       {rsVLNotSupplied, rsVLNotEstablished, rsVLContradiction, rsNoReceipt},
	CondCompleteness: {rsHistoryNotSupplied, rsRequestedAtNotSupplied, rsHistoryNotEstablished, rsHistoryPartial,
		rsHistoryContradiction, rsNoHistoryRoot},
	CondLogDayQualified: {rsVLNotSupplied, rsVLNotEstablished, rsVLContradiction, rsNoQualifiedLogRoot, rsNoReceiptIncluded},
}

var evStages = map[string][]string{
	CondTimeWitness:          {rsSignatureNotCheckable, rsNotChainedAuditor, rsPublishedTestKey, rsTokenExtUnusable},
	CondExpectedRootFound:    {},
	CondReceiptKeyConfirmed:  {rsKeyNotConfirmed, rsKeyIsDeviceKey},
	CondTimeWitnessQualified: {rsSignatureNotCheckable, rsNotChainedQualified, rsPublishedTestKey, rsQualifiedRootInPackage, rsOutsideWindow, rsSigningCertNotBound, rsTokenExtUnusable, stageQS},
	CondReceiptsLogged:       {},
	CondCompleteness:         {},
	CondLogDayQualified:      {rsSignatureNotCheckable, rsNotChainedQualifiedLog, rsPublishedTestKey, rsOutsideWindow, rsDayStampLate, rsDayStampGap, rsTokenExtUnusable, stageQS},
}

// evFromCompleteness is registry verifier.evidence_level.conditions.
// completeness_from_history.from_completeness: the reason of condition (6)
// for each reason of anchor_history.completeness (10.9.4). root_missing
// does not occur in the state rated (a MERKLE_INCONSISTENT from a history
// root gives chain_invalid) and has no code.
var evFromCompleteness = map[string]string{
	"not_supplied":          rsHistoryNotSupplied,
	"no_request_time":       rsRequestedAtNotSupplied,
	"no_usable_page":        rsHistoryNotEstablished,
	"owner_differs":         rsHistoryNotEstablished,
	"issued_before_request": rsHistoryNotEstablished,
	"pages_missing":         rsHistoryPartial,
	"contradiction":         rsHistoryContradiction,
	"fork":                  rsHistoryContradiction,
	"no_root_found":         rsNoHistoryRoot,
}

// Notes of registry verifier.evidence_level.note_order (10.9.6).
const (
	ntMaterialContradiction  = "material_contradiction"
	ntUnsealedEnd            = "unsealed_end"
	ntStalePackage           = "stale_package"
	ntPackageNotFullyKnown   = "package_not_fully_known"
	ntVendorRootBuiltinOnly  = "vendor_root_builtin_only"
	ntPublishedTestKey       = "published_test_key_credited"
	ntLastReceiptNotConfirm  = "last_receipt_not_confirmed"
	ntExpectedRootAuditor    = "expected_root_auditor_only"
	ntTSARootInPackage       = "tsa_root_in_package"
	ntHistoryRecentSkipped   = "history_recent_roots_skipped"
	ntReceiptsPendingLog     = "receipts_pending_log"
	ntReceiptNotLogged       = "receipt_not_logged"
	ntLogDayNotSupplied      = "log_day_not_supplied"
	ntLoggedRootMismatch     = "logged_root_mismatch"
	ntCMSNotImplemented      = "cms_not_implemented"
	historyNoteRecentSkipped = "recent_roots_not_found"
)

// evNoteOrder is registry verifier.evidence_level.note_order.
var evNoteOrder = []string{ntMaterialContradiction, ntUnsealedEnd, ntStalePackage, ntPackageNotFullyKnown,
	ntVendorRootBuiltinOnly, ntPublishedTestKey, ntLastReceiptNotConfirm, ntExpectedRootAuditor, ntTSARootInPackage,
	ntHistoryRecentSkipped, ntReceiptsPendingLog, ntReceiptNotLogged, ntLogDayNotSupplied, ntLoggedRootMismatch,
	ntCMSNotImplemented}

// Origins of a root in evidence_level.anchors (10.10.2, "Namen der
// Herkunft"): the same origins as vendor_root and builtin elsewhere.
const (
	rootFromAuditor = "auditor"
	rootFromBuiltin = "builtin"
)

// PublishedTestEd25519 are the public keys (hex64) of the Ed25519 test keys
// of the vendor in registry verifier.timestamp_profile.published_test_keys
// (format spec 7.5.7): they count after the rules under which the auditor
// passes them or a list establishes them, and a condition that rests on one
// of them gives the note published_test_key_credited (10.9.6).
var PublishedTestEd25519 = []string{
	"4943606eee615d5786c459cee74b7157c104453366c97419cd3e4af5ebca8fc8", // vendor root testwurzel-1
	"959c448da9b35ea50abeca1f0a4cac57fc21c5b7ff7216d3e304bb5fc406d36c", // countersigning key vendor-test-001
	"73edaed42d761a1ab4fcc9be71a95b957542e89be13fa185e6ad1264ddc8b816", // countersigning key vendor-test-002
	"cc2edbd00b1893b5ead99b913212db9b733243c0b177dee34f7be1e9fe7cc3b2", // countersigning key vendor-test-003
	"6122df9ab7a7a83ecd7540b4d66cef184bd08aba2cac06123337b8ab3e56c9c2", // statements key vendor-statements-test-001
	"0281ea7e6995a65287fb8b49092636b24cb645eb2a54bd1975a94f1597cc0ef5", // statements key vendor-statements-test-002
	"8796764cebba035507d86bbf2ebf308738417b88f1bdab4f465484569c838f28", // update manifest key vendor-update-manifest-test-001
	"cee49a5a497e248e6be0af06ace16850e8f0eb4c306a212f5430359e8076fdd7", // protocol key vendor-log-test-001
	"8319d7221fdbb1680cb36c8fe33d1507992f14db30ed57c71c46f4ef9313d2a2", // standby protocol key vendor-log-test-002
}

// isPublishedTestEd25519 reports whether pub is one of PublishedTestEd25519.
func isPublishedTestEd25519(pub string) bool {
	pub = strings.ToLower(pub)
	for _, k := range PublishedTestEd25519 {
		if k == pub {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- report

// EvidenceLevelStat is the report object evidence_level (10.10.2). Outside
// the state rated level, entries, up_to_tree_size, conditions, next,
// qualified_time and anchors are null and segments and notes empty;
// qualified_time is null below level 3 at seq 1 as well; affiliation is
// null only in the state format_error.
type EvidenceLevelStat struct {
	State         string                 `json:"state"`
	Level         *int                   `json:"level"`
	Entries       *int64                 `json:"entries"`
	UpToTreeSize  *int64                 `json:"up_to_tree_size"`
	Segments      []EvidenceSegment      `json:"segments"`
	Conditions    *EvidenceConditions    `json:"conditions"`
	Next          *EvidenceNext          `json:"next"`
	QualifiedTime *EvidenceQualifiedTime `json:"qualified_time"`
	Anchors       *EvidenceAnchors       `json:"anchors"`
	Affiliation   *EvidenceAffiliation   `json:"affiliation"`
	Notes         []string               `json:"notes"`
	// text keeps what the text block names beside the object (10.10.3).
	text evText
}

// EvidenceSegment is one run of positions with equal lvl(p) (10.9.5).
type EvidenceSegment struct {
	Level    int      `json:"level"`
	FirstSeq int64    `json:"first_seq"`
	LastSeq  int64    `json:"last_seq"`
	Basis    []string `json:"basis"`
}

// EvidenceConditions are the seven conditions in condition_order
// (10.10.2).
type EvidenceConditions struct {
	TimeWitness             EvidenceCondition `json:"time_witness"`
	ExpectedRootFound       EvidenceCondition `json:"expected_root_found"`
	ReceiptKeyConfirmed     EvidenceCondition `json:"receipt_key_confirmed"`
	TimeWitnessQualified    EvidenceCondition `json:"time_witness_qualified"`
	ReceiptsLogged          EvidenceCondition `json:"receipts_logged"`
	CompletenessFromHistory EvidenceCondition `json:"completeness_from_history"`
	LogDayQualified         EvidenceCondition `json:"log_day_qualified"`
}

// Get returns the condition with the code given, nil for an unknown code.
func (c *EvidenceConditions) Get(code string) *EvidenceCondition {
	switch code {
	case CondTimeWitness:
		return &c.TimeWitness
	case CondExpectedRootFound:
		return &c.ExpectedRootFound
	case CondReceiptKeyConfirmed:
		return &c.ReceiptKeyConfirmed
	case CondTimeWitnessQualified:
		return &c.TimeWitnessQualified
	case CondReceiptsLogged:
		return &c.ReceiptsLogged
	case CondCompleteness:
		return &c.CompletenessFromHistory
	case CondLogDayQualified:
		return &c.LogDayQualified
	}
	return nil
}

// EvidenceCondition is C of 10.10.2: met, the number of credited items,
// the reach (null when not met) and the reason (null exactly when met).
type EvidenceCondition struct {
	Met          bool    `json:"met"`
	Count        int     `json:"count"`
	UpToTreeSize *int64  `json:"up_to_tree_size"`
	Reason       *string `json:"reason"`
}

// EvidenceNext is what the next level needs (10.9.5).
type EvidenceNext struct {
	Level   int      `json:"level"`
	Need    string   `json:"need"`
	Missing []string `json:"missing"`
}

// EvidenceQualifiedTime is qualified_time of 10.10.2: at level 3 at seq 1
// the item that evidences the qualified time for the state up to
// up_to_tree_size, a credited TIME_ANCHOR of (4) or a credited receipt of
// (7). latest is its genTime truncated to whole milliseconds (the state
// existed at the latest then); gap_ms is, for (7), latest minus the
// server_ts of the receipt in whole milliseconds, null for (4).
type EvidenceQualifiedTime struct {
	Via      string `json:"via"`
	TreeSize int64  `json:"tree_size"`
	Latest   string `json:"latest"`
	GapMS    *int64 `json:"gap_ms"`
}

// EvidenceAnchors names the anchors with their fingerprints (10.10.2).
type EvidenceAnchors struct {
	VendorKeys          []EvidenceKeyRef       `json:"vendor_keys"`
	StatementKeys       []EvidenceKeyRef       `json:"statement_keys"`
	TSARoots            []EvidenceTSARoot      `json:"tsa_roots"`
	QualifiedRootsFile  *EvidenceQualifiedFile `json:"qualified_roots_file"`
	ExpectedRootSources []string               `json:"expected_root_sources"`
}

// EvidenceKeyRef is a vendor key or a statements key and how it is
// established: a pin, or a list with version, wurzel_id and the origin of
// the root.
type EvidenceKeyRef struct {
	KeyID       string  `json:"key_id"`
	Via         string  `json:"via"`
	ListVersion *int64  `json:"list_version"`
	RootID      *string `json:"root_id"`
	RootFrom    *string `json:"root_from"`
}

// EvidenceTSARoot is a root for time stamps that credits (1), (4) or (7).
type EvidenceTSARoot struct {
	CertSHA256  string   `json:"cert_sha256"`
	CreditedFor []string `json:"credited_for"`
}

// EvidenceQualifiedFile names the file ledger-tsa-qualifiziert/1.
type EvidenceQualifiedFile struct {
	Stand  string `json:"stand"`
	Quelle string `json:"quelle"`
}

// EvidenceAffiliation is status and vendor_itself of the object
// affiliation (10.10.2).
type EvidenceAffiliation struct {
	Status       string `json:"status"`
	VendorItself bool   `json:"vendor_itself"`
}

// evText is what the text block of 10.10.3 names that the object does not
// carry in this form: whether the head reads "of the chain", the anchors
// per condition and the vendor log and anchor history they rest on.
type evText struct {
	material      bool
	receiptKeys   []EvidenceKeyRef
	historyKeys   []EvidenceKeyRef
	roots         map[string][]string // condition -> crediting fingerprints, ascending
	qualifiedFile *EvidenceQualifiedFile
	sources       []string
	logID         string
	asOf          string
}

// ---------------------------------------------------------------- inputs

// evInputs are the values of 10.9.3 a run recorded, with the exit code and
// the finding classes.
type evInputs struct {
	exit    int
	classes map[string]bool
	entries int64

	// (1) and (4): the TIME_ANCHOR entries of the chain, the witnesses that
	// passed steps 1 to 4 of 7.3, the table of roots for time stamps of
	// 10.8 and the SPKI values of the certificates of keys/tsa/.
	timeAnchors   int64
	witnesses     []evWitness
	roots         []evRoot
	pkgSPKI       map[string]bool
	qualifiedFile *EvidenceQualifiedFile

	// (2): the found expected roots of both sources.
	found []evFound

	// (3): every receipt whose signature holds after 7.1, in chain order,
	// D, and the receipt 8.6 chooses as the last countersigned one (its
	// seq, 0 without).
	receipts             []evReceipt
	deviceKeys           map[string]bool
	lastCountersignedSeq int64

	// (5) and (7): vendor_log.status, a VENDOR_LOG_CONTRADICTION without a
	// day or on a day of [Lo, T], the receipts of step L8 in chain order,
	// t_m (0 without LOGGED_ROOT_MISMATCH), the log_id and whether an
	// established protocol key or the root of the effective protocol key
	// list is a published test key.
	vlStatus        string
	vlContradiction bool
	l8              []evL8
	tM              int64
	logID           string
	protocolTestKey bool

	// (6): anchor_history.completeness, anchor_history.roots.found, the
	// note recent_roots_not_found, as_of of the anchor history, the keys of
	// the used pages of the package that carry a found history root
	// (pagesFound) and of those that enter the completeness of step H11
	// (pagesCompl), and the effective role list.
	compl              HistoryComplStat
	historyFound       int
	recentRootsSkipped bool
	asOf               string
	pagesFound         []evPage
	pagesCompl         []evPage
	roleList           *evList

	affiliation *EvidenceAffiliation
}

// evWitness is one TIME_ANCHOR that passed steps 1 to 4 (10.9.3).
type evWitness struct {
	seq, treeSize int64
	checked       bool // step 5 performable (5a)
	valid         bool // step 5 held (5b)
	genTime       time.Time
	paths         map[string]bool // cert_sha256 of the roots with a path after Z.3 and Z.4 at genTime
	signerTestKey bool
	z6, qs        string
}

// evRoot is one entry of the table of roots for time stamps (10.8).
type evRoot struct {
	certSHA, spki string
	chain, log    bool
	qualified     bool
	from, until   time.Time // the period for the purpose qualified, until zero when open
	testKey       bool      // its SPKI is in published_test_keys
}

// qualifiedAt is qualifiziert_ab <= t < qualifiziert_bis, the upper bound
// only when present, compared as instants on nanoseconds (10.8).
func (x evRoot) qualifiedAt(t time.Time) bool {
	return x.qualified && !t.Before(x.from) && (x.until.IsZero() || t.Before(x.until))
}

// evFound is one found expected root (found_at, merkle_root) with its
// sources.
type evFound struct {
	foundAt          int64
	root             string
	auditor, history bool
}

// evReceipt is one receipt whose signature holds after 7.1 (10.9.3).
type evReceipt struct {
	seq, treeSize   int64
	keyID, pub, via string
	established     bool
	list            *evList // the list of the package for via list
}

// evList is a list of the vendor with its version and its root.
type evList struct {
	version                   int64
	rootID, rootFrom, rootPub string
}

// evL8 is one receipt of step L8 with its class and its server_ts; for the
// class included the time stamps of c(d) that are not defective (10.9.3,
// condition (7)).
type evL8 struct {
	seq, treeSize int64
	class, sub    string
	serverTS      time.Time
	stamps        []evDayStamp
}

// evDayStamp is one time stamp of c(d) that is not defective.
type evDayStamp struct {
	checked       bool // step 5 performable (5a)
	genTime       time.Time
	paths         map[string]bool // cert_sha256 of the roots with the purposes log and qualified with a path
	signerTestKey bool
	late          bool // genTime in whole milliseconds >= end(d) + W
	qs            string
}

// evPage is the statements key of a used page of the package.
type evPage struct {
	keyID, pub string
	pinned     bool
}

// evidenceInputs gathers the values of 10.9.3 that the run recorded.
func (r *run) evidenceInputs(exit int, st *Stats) *evInputs {
	in := &evInputs{exit: exit, classes: map[string]bool{}, entries: int64(len(r.entries)), timeAnchors: r.timeAnchors,
		pkgSPKI: r.pkgTSASPKI, deviceKeys: map[string]bool{}}
	for _, f := range r.findings {
		in.classes[f.Class] = true
	}
	if in.pkgSPKI == nil {
		in.pkgSPKI = map[string]bool{}
	}
	if st.Affiliation != nil {
		in.affiliation = &EvidenceAffiliation{Status: st.Affiliation.Status, VendorItself: st.Affiliation.VendorItself}
	}
	if exit == 3 {
		return in
	}
	roots := r.vendorRoots()
	listOf := func(version int64, rootID, source string) *evList {
		l := &evList{version: version, rootID: rootID, rootFrom: rootFromAuditor, rootPub: roots[rootID].pubkey}
		if source == RootSourceBuiltin {
			l.rootFrom = rootFromBuiltin
		}
		return l
	}

	// (1), (4): the witnesses, the table and the file of qualified roots.
	for _, d := range r.timeAnchorDetails {
		w := evWitness{seq: d.Seq, treeSize: d.TreeSize, checked: d.SignatureChecked, valid: d.SignatureValid, genTime: d.GenTime,
			paths: map[string]bool{}, signerTestKey: d.SignerTestKey, z6: d.Z6, qs: d.QS}
		for _, p := range d.PathRoots {
			w.paths[p] = true
		}
		in.witnesses = append(in.witnesses, w)
	}
	table := r.tsaRootTable()
	for _, x := range table {
		er := evRoot{certSHA: x.CertSHA256, spki: x.SPKISHA256, chain: x.Chain, log: x.Log, testKey: tsa.IsPublishedTestKey(x.Cert)}
		if q := x.Qualified; q != nil {
			er.qualified, er.from, er.until = true, q.From, q.Until
		}
		in.roots = append(in.roots, er)
	}
	if q := r.opt.TSAQualified; q != nil {
		// Format spec 10.10.1: a time point the verifier forms from an
		// input of the auditor stands in the form YYYY-MM-DDThh:mm:ss.sssZ,
		// as requested_at does; only time points from signed objects are
		// taken over character for character.
		// 10.10.2, anchors.qualified_roots_file: stand in the form
		// YYYY-MM-DDThh:mm:ss.sssZ, truncated to whole milliseconds, quelle
		// as written.
		stand := q.Stand
		if t, ok := parseUTC(q.Stand); ok {
			stand = FormatMillisUTC(t)
		}
		in.qualifiedFile = &EvidenceQualifiedFile{Stand: stand, Quelle: q.Quelle}
	}

	// (2): the found expected roots of both sources, by (found_at,
	// merkle_root).
	idx := map[string]int{}
	addFound := func(t int64, root string, auditor bool) {
		k := strconv.FormatInt(t, 10) + ":" + root
		i, ok := idx[k]
		if !ok {
			i = len(in.found)
			idx[k] = i
			in.found = append(in.found, evFound{foundAt: t, root: root})
		}
		if auditor {
			in.found[i].auditor = true
		} else {
			in.found[i].history = true
		}
	}
	for _, x := range r.expected {
		if x.found {
			addFound(x.foundAt, x.root.Root, true)
		}
	}
	if h := r.ah; h != nil {
		for _, hr := range h.roots {
			if hr.found {
				addFound(hr.t, hr.r, false)
			}
		}
	}

	// (3): the receipts, D and the last countersigned receipt.
	var pkgList *evList
	if vt := r.vendor; vt != nil && vt.list != nil {
		pkgList = listOf(vt.listVer, vt.listRoot, roots[vt.listRoot].source)
	}
	for _, ri := range r.receiptInfos {
		if !ri.sigOK {
			continue
		}
		er := evReceipt{seq: ri.seq, treeSize: ri.treeSize, keyID: ri.keyID, pub: ri.pub, via: ri.via, established: ri.established}
		if ri.via == keyViaList {
			er.list = pkgList
		}
		in.receipts = append(in.receipts, er)
	}
	for _, k := range r.deviceKeys {
		in.deviceKeys[strings.ToLower(k)] = true
	}
	if lc := r.lastCountersigned; lc != nil {
		in.lastCountersignedSeq = lc.ReceiptSeq
	}

	// (5), (7): the vendor log.
	if vr := r.vlog; vr != nil {
		in.vlStatus = vr.stat.Status
		if vr.stat.LogID != nil {
			in.logID = *vr.stat.LogID
		}
		in.vlContradiction = vr.contraNone
		if vr.hasRange {
			for d := range vr.contraDays {
				if d >= vr.lo && d <= vr.hi {
					in.vlContradiction = true
				}
			}
		}
		in.tM = vr.tM
		var qlRoots []*TSARoot
		for _, x := range table {
			if x.Log && x.Qualified != nil {
				qlRoots = append(qlRoots, x)
			}
		}
		for _, ri := range r.receiptInfos {
			if !ri.sigOK || ri.invalid {
				continue
			}
			c, ok := vr.classes[ri.seq]
			if !ok {
				continue
			}
			l := evL8{seq: ri.seq, treeSize: ri.treeSize, class: c.class, sub: c.sub}
			if ts, ok := parseUTC(ri.serverTS); ok {
				l.serverTS = ts
			}
			if c.class == RcIncluded {
				if cd := vr.canon[c.day]; cd != nil {
					for _, s := range cd.judged {
						if s.state == tsa.StateDefective || s.tok == nil {
							continue
						}
						ds := evDayStamp{checked: s.sig.Performable, genTime: s.gen, paths: map[string]bool{},
							signerTestKey: tsa.IsPublishedTestKey(s.sig.Signer), qs: s.tok.QualifiedStatement(),
							late: msSince0001(s.gen) >= dayEndMS(c.day)+vlTokenWindowMS}
						for _, x := range qlRoots {
							if s.tok.PathExists(s.sig, x.Cert) {
								ds.paths[x.CertSHA256] = true
							}
						}
						l.stamps = append(l.stamps, ds)
					}
				}
			}
			in.l8 = append(in.l8, l)
		}
		for _, k := range r.protocolKeys() {
			if isPublishedTestEd25519(k.pubkey) {
				in.protocolTestKey = true
			}
		}
		if kr := r.roles; kr != nil && kr.p != nil && isPublishedTestEd25519(roots[kr.p.wurzelID].pubkey) {
			in.protocolTestKey = true
		}
	}

	// (6): the anchor history.
	if ah := st.AnchorHistory; ah != nil {
		in.compl = ah.Completeness
		in.historyFound = ah.Roots.Found
		for _, n := range ah.Notes {
			if n == historyNoteRecentSkipped {
				in.recentRootsSkipped = true
			}
		}
	}
	if af := st.Affiliation; af != nil && af.AsOf != nil {
		in.asOf = *af.AsOf
	}
	if kr := r.roles; kr != nil && kr.q != nil {
		in.roleList = listOf(kr.q.version, kr.q.wurzelID, kr.q.rootSource)
	}
	if h := r.ah; h != nil {
		if in.asOf == "" && h.hstar != nil {
			in.asOf = h.hstar.c.serverTS
		}
		page := func(p *ahPage) evPage {
			return evPage{keyID: p.chosen.keyID, pub: p.chosen.key.Pubkey, pinned: p.chosen.key.Pinned}
		}
		for _, p := range h.pkgUsed {
			if p.chosen == nil {
				continue
			}
			// 10.10.2, anchors.statement_keys: (6) rests on the fresh used
			// pages of the package, the pages that enter the completeness of
			// step H11 (8.8.4, "Ältere Seiten"); its <Anker> in 10.10.3 and
			// the note published_test_key_credited (10.9.6) read the same
			// pages.
			if p.use == UseFresh {
				in.pagesCompl = append(in.pagesCompl, page(p))
			}
			if pageCarriesFoundRoot(p, h.roots) {
				in.pagesFound = append(in.pagesFound, page(p))
			}
		}
	}
	return in
}

// pageCarriesFoundRoot reports whether a used page of the package carries
// the recorded recording of a found history root that counts after H7:
// condition (2) with the source anchor_history rests on such a page (10.10.2,
// anchors.statement_keys: "die verwendeten Seiten, die die festgehaltene
// Aufzeichnung einer gefundenen erwarteten Wurzel tragen (Abschnitt
// 8.8.5)"). "festgehalten" is the term of 8.8.5: recorded_as countersigned
// or gap_witness, so a page that lists a found root only as reported
// carries no such recording. For a page the pair is the one the report
// names for it in anchor_history.keys (the chosen pair, the smallest
// server_key_id).
func pageCarriesFoundRoot(p *ahPage, roots []*histRoot) bool {
	for _, hr := range roots {
		if !hr.found {
			continue
		}
		for _, x := range p.c.roots {
			if x.t != hr.t || x.root != hr.r || x.as == "reported" {
				continue
			}
			for _, k := range hr.kept {
				if k.as == x.as && k.ts == x.ts {
					return true
				}
			}
		}
	}
	return false
}

// ---------------------------------------------------------------- evaluation

// evCond is one condition during the evaluation.
type evCond struct {
	met    bool
	count  int
	reach  int64
	reason string
}

func (c evCond) stat() EvidenceCondition {
	out := EvidenceCondition{Met: c.met, Count: c.count}
	if c.met {
		r := c.reach
		out.UpToTreeSize = &r
	} else {
		why := c.reason
		out.Reason = &why
	}
	return out
}

func notMet(reason string) evCond { return evCond{reason: reason} }

// passedStages is s of 10.9.4: the number of stages a pair or triple passes
// in table order without interruption; fails[i] says whether it fails at
// stage i.
func passedStages(fails []bool) int {
	for i, f := range fails {
		if f {
			return i
		}
	}
	return len(fails)
}

// stageResult collects max(s) over the pairs of one condition and, at the
// stage qualified_statement, whether a pair failed there with malformed.
type stageResult struct {
	best      int
	malformed bool
}

func (sr *stageResult) note(s int, qs string, qsStage int) {
	if s > sr.best {
		sr.best = s
	}
	if s == qsStage && qs == tsa.QSMalformed {
		sr.malformed = true
	}
}

// reason is the code of the stage with index max(s); at the stage
// qualified_statement malformed goes before absent (10.9.4).
func (sr *stageResult) reason(stages []string) string {
	i := sr.best
	if i < 0 {
		i = 0 // no pair at all: does not occur in the state rated
	}
	if stages[i] != stageQS {
		return stages[i]
	}
	if sr.malformed {
		return rsQSMalformed
	}
	return rsNoQS
}

// condTimeWitness is condition (1) (10.9.4): every TIME_ANCHOR, per root of
// the purpose chain. It returns the condition and the crediting roots.
func condTimeWitness(in *evInputs) (evCond, map[string]bool) {
	credited := map[string]bool{}
	if in.timeAnchors == 0 {
		return notMet(rsNoTimeAnchor), credited
	}
	var roots []evRoot
	for _, x := range in.roots {
		if x.chain {
			roots = append(roots, x)
		}
	}
	if len(roots) == 0 {
		return notMet(rsNoTSARoot), credited
	}
	sr := stageResult{best: -1}
	c := evCond{}
	for _, w := range in.witnesses {
		ok := false
		for _, x := range roots {
			s := passedStages([]bool{
				!w.checked || !w.valid,       // signature_not_checkable (5a)
				!w.paths[x.certSHA],          // not_chained_to_auditor_root
				w.signerTestKey || x.testKey, // published_test_key
				w.qs == tsa.QSUnusable,       // token_extensions_unusable
			})
			if s == 4 {
				ok = true
				credited[x.certSHA] = true
			} else {
				sr.note(s, w.qs, -1)
			}
		}
		if ok {
			c.count++
			if w.treeSize > c.reach {
				c.reach = w.treeSize
			}
		}
	}
	if c.count == 0 {
		return notMet(sr.reason(evStages[CondTimeWitness])), credited
	}
	c.met = true
	return c, credited
}

// evQTCand is a candidate for qualified_time (10.10.2): a credited item of
// (4), a TIME_ANCHOR per root, or of (7), a receipt per time stamp and root.
type evQTCand struct {
	via      string
	treeSize int64
	genTime  time.Time
	serverTS time.Time // (7): the server_ts of the receipt
}

// condTimeWitnessQualified is condition (4) (10.9.4): every TIME_ANCHOR, per
// root of the purpose qualified. It returns the condition, the crediting
// roots and the credited pairs as candidates for qualified_time.
func condTimeWitnessQualified(in *evInputs) (evCond, map[string]bool, []evQTCand) {
	credited := map[string]bool{}
	var cands []evQTCand
	if in.timeAnchors == 0 {
		return notMet(rsNoTimeAnchor), credited, cands
	}
	var roots []evRoot
	for _, x := range in.roots {
		if x.qualified {
			roots = append(roots, x)
		}
	}
	if len(roots) == 0 {
		return notMet(rsNoQualifiedRoot), credited, cands
	}
	sr := stageResult{best: -1}
	c := evCond{}
	for _, w := range in.witnesses {
		ok := false
		for _, x := range roots {
			s := passedStages([]bool{
				!w.checked || !w.valid || w.z6 == tsa.Z6NotCheckable, // signature_not_checkable (5a, or Z.6 not checkable)
				!w.paths[x.certSHA],          // not_chained_to_qualified_root
				w.signerTestKey || x.testKey, // published_test_key
				in.pkgSPKI[x.spki],           // qualified_root_in_package
				!x.qualifiedAt(w.genTime),    // outside_qualified_window
				w.z6 == tsa.Z6Violated,       // signing_certificate_not_bound
				w.qs == tsa.QSUnusable,       // token_extensions_unusable
				w.qs != tsa.QSPresent,        // qualified_statement
			})
			if s == 8 {
				ok = true
				credited[x.certSHA] = true
				cands = append(cands, evQTCand{via: CondTimeWitnessQualified, treeSize: w.treeSize, genTime: w.genTime})
			} else {
				sr.note(s, w.qs, 7)
			}
		}
		if ok {
			c.count++
			if w.treeSize > c.reach {
				c.reach = w.treeSize
			}
		}
	}
	if c.count == 0 {
		return notMet(sr.reason(evStages[CondTimeWitnessQualified])), credited, cands
	}
	c.met = true
	return c, credited, cands
}

// condExpectedRootFound is condition (2) (10.9.4): every found expected
// root of the source auditor or anchor_history, counted by (found_at,
// merkle_root). It returns the condition and the sources of the credited
// roots in the order auditor, anchor_history.
func condExpectedRootFound(in *evInputs) (evCond, []string) {
	sources := []string{}
	if len(in.found) == 0 {
		return notMet(rsNoExpectedRoot), sources
	}
	c := evCond{met: true, count: len(in.found)}
	auditor, history := false, false
	for _, f := range in.found {
		if f.foundAt > c.reach {
			c.reach = f.foundAt
		}
		auditor = auditor || f.auditor
		history = history || f.history
	}
	if auditor {
		sources = append(sources, "auditor")
	}
	if history {
		sources = append(sources, "anchor_history")
	}
	return c, sources
}

// condReceiptKeyConfirmed is condition (3) (10.9.4): every receipt whose
// signature holds after 7.1. It returns the condition and the credited
// receipts.
func condReceiptKeyConfirmed(in *evInputs) (evCond, []evReceipt) {
	var credited []evReceipt
	if len(in.receipts) == 0 {
		return notMet(rsNoReceipt), credited
	}
	best := -1
	c := evCond{}
	for _, x := range in.receipts {
		s := passedStages([]bool{
			!x.established,                        // key_not_confirmed
			in.deviceKeys[strings.ToLower(x.pub)], // key_is_device_key
		})
		if s == 2 {
			credited = append(credited, x)
			c.count++
			if x.treeSize > c.reach {
				c.reach = x.treeSize
			}
		} else if s > best {
			best = s
		}
	}
	if c.count == 0 {
		if best < 0 {
			best = 0
		}
		return notMet(evStages[CondReceiptKeyConfirmed][best]), credited
	}
	c.met = true
	return c, credited
}

// vlGlobal is the head of the reasons without item of (5) and (7) (10.9.4).
func vlGlobal(in *evInputs) string {
	switch {
	case in.vlStatus == "" || in.vlStatus == VendorLogNotSupplied:
		return rsVLNotSupplied
	case in.vlStatus == VendorLogNoProtocolKey:
		return rsVLNotEstablished
	case in.vlContradiction:
		return rsVLContradiction
	}
	return ""
}

// badReceiptCode is the code of a bad receipt of (5) (10.9.4, "Zu (5), je
// Quittung"); "" for a good or neutral one.
func badReceiptCode(l evL8) string {
	switch l.class {
	case RcIncluded, RcBeforeStart:
		return ""
	case RcNotIncluded:
		return rsReceiptNotLogged
	case RcUnchecked:
		if l.sub == UcDayNotWitnessed {
			return rsDayStampNotConfirmed
		}
		return rsReceiptNotCheckable
	case RcMissing:
		return rsLogDayNotSupplied
	case RcPending:
		return rsReceiptDayNotClosed
	case RcFuture:
		return rsReceiptAfterCheckTime
	}
	return rsReceiptNotCheckable
}

// condReceiptsLogged is condition (5) (10.9.4).
func condReceiptsLogged(in *evInputs) evCond {
	if why := vlGlobal(in); why != "" {
		return notMet(why)
	}
	if len(in.l8) == 0 {
		return notMet(rsNoReceipt)
	}
	// r5': the largest tree_size t of a good receipt such that every
	// receipt with tree_size <= t is good or neutral.
	minBad := int64(-1)
	allNeutral := true
	firstBad := ""
	for _, l := range in.l8 {
		if l.class != RcBeforeStart {
			allNeutral = false
		}
		if code := badReceiptCode(l); code != "" {
			if firstBad == "" {
				firstBad = code
			}
			if minBad < 0 || l.treeSize < minBad {
				minBad = l.treeSize
			}
		}
	}
	var r5 int64
	for _, l := range in.l8 {
		if l.class == RcIncluded && (minBad < 0 || l.treeSize < minBad) && l.treeSize > r5 {
			r5 = l.treeSize
		}
	}
	reach := r5
	if in.tM > 0 && in.tM-1 < reach {
		reach = in.tM - 1
	}
	if reach >= 1 {
		c := evCond{met: true, reach: reach}
		for _, l := range in.l8 {
			if l.class == RcIncluded && l.treeSize <= reach {
				c.count++
			}
		}
		return c
	}
	switch {
	case allNeutral:
		return notMet(rsReceiptsBeforeStart)
	case r5 == 0 && firstBad != "":
		return notMet(firstBad)
	case r5 >= 1:
		return notMet(rsLoggedRootMismatch)
	}
	return notMet(rsReceiptsBeforeStart)
}

// condCompleteness is condition (6) (10.9.4): met exactly when
// anchor_history.completeness.status is established.
func condCompleteness(in *evInputs) evCond {
	if in.compl.Status == "established" && in.compl.UpToTreeSize != nil {
		return evCond{met: true, reach: *in.compl.UpToTreeSize, count: in.historyFound}
	}
	why := "not_supplied"
	if in.compl.Reason != nil {
		why = *in.compl.Reason
	}
	code, ok := evFromCompleteness[why]
	if !ok {
		// root_missing has no code (format spec 10.9.4, table "Zu (6)";
		// registry from_completeness maps it to null): a MERKLE_INCONSISTENT
		// from a history root gives chain_invalid, so it never reaches
		// this point in the state rated.
		code = rsHistoryNotEstablished
	}
	return notMet(code)
}

// condLogDayQualified is condition (7) (10.9.4), the second way to level 3:
// every receipt of the class included, per time stamp of c(d) that is not
// defective, per root with the purposes log and qualified. It returns the
// condition, the crediting roots and the credited triples as candidates for
// qualified_time.
func condLogDayQualified(in *evInputs) (evCond, map[string]bool, []evQTCand) {
	credited := map[string]bool{}
	var cands []evQTCand
	if why := vlGlobal(in); why != "" {
		return notMet(why), credited, cands
	}
	var roots []evRoot
	for _, x := range in.roots {
		if x.log && x.qualified {
			roots = append(roots, x)
		}
	}
	if len(roots) == 0 {
		return notMet(rsNoQualifiedLogRoot), credited, cands
	}
	included := false
	for _, l := range in.l8 {
		if l.class == RcIncluded {
			included = true
		}
	}
	if !included {
		return notMet(rsNoReceiptIncluded), credited, cands
	}
	sr := stageResult{best: -1}
	c := evCond{}
	for _, l := range in.l8 {
		if l.class != RcIncluded {
			continue
		}
		ok := false
		for _, s := range l.stamps {
			// genTime truncated to whole milliseconds minus the server_ts of
			// the receipt (10.9.4, qualified_day_stamp_gap).
			gap := msSince0001(s.genTime) - msSince0001(l.serverTS)
			for _, x := range roots {
				n := passedStages([]bool{
					!s.checked,                   // signature_not_checkable (5a)
					!s.paths[x.certSHA],          // not_chained_to_qualified_log_root
					s.signerTestKey || x.testKey, // published_test_key
					!x.qualifiedAt(s.genTime),    // outside_qualified_window
					s.late,                       // qualified_day_stamp_late
					gap > evQualifiedGapMS,       // qualified_day_stamp_gap
					s.qs == tsa.QSUnusable,       // token_extensions_unusable
					s.qs != tsa.QSPresent,        // qualified_statement
				})
				if n == 8 {
					ok = true
					credited[x.certSHA] = true
					cands = append(cands, evQTCand{via: CondLogDayQualified, treeSize: l.treeSize, genTime: s.genTime, serverTS: l.serverTS})
				} else {
					sr.note(n, s.qs, 7)
				}
			}
		}
		if ok {
			c.count++
			if l.treeSize > c.reach {
				c.reach = l.treeSize
			}
		}
	}
	if c.count == 0 {
		return notMet(sr.reason(evStages[CondLogDayQualified])), credited, cands
	}
	c.met = true
	return c, credited, cands
}

// chooseQualifiedTime is qualified_time of 10.10.2 at level 3 at seq 1:
// among the candidates with tree_size >= up_to_tree_size the one with the
// earliest genTime, on a tie (4) before (7), then the smaller tree_size,
// then for (7) the earlier server_ts of the receipt. nil without a
// candidate, which does not occur at level 3 (r3 <= max(reach(4),
// reach(7))).
//
// genTime is compared as an instant to the nanosecond, like the periods
// of 10.8, before any cut to whole milliseconds (10.10.2, qualified_time);
// a tie means the same instant.
func chooseQualifiedTime(cands []evQTCand, upTo int64) *EvidenceQualifiedTime {
	var best *evQTCand
	rank := func(via string) int {
		if via == CondTimeWitnessQualified {
			return 0
		}
		return 1
	}
	better := func(a, b evQTCand) bool {
		switch {
		case !a.genTime.Equal(b.genTime):
			return a.genTime.Before(b.genTime)
		case rank(a.via) != rank(b.via):
			return rank(a.via) < rank(b.via)
		case a.treeSize != b.treeSize:
			return a.treeSize < b.treeSize
		}
		return a.via == CondLogDayQualified && a.serverTS.Before(b.serverTS)
	}
	for i := range cands {
		if cands[i].treeSize < upTo {
			continue
		}
		if best == nil || better(cands[i], *best) {
			best = &cands[i]
		}
	}
	if best == nil {
		return nil
	}
	q := &EvidenceQualifiedTime{Via: best.via, TreeSize: best.treeSize, Latest: FormatMillisUTC(best.genTime)}
	if best.via == CondLogDayQualified {
		gap := msSince0001(best.genTime) - msSince0001(best.serverTS)
		q.GapMS = &gap
	}
	return q
}

// evLevels is 10.9.5: from N and the conditions the level, its reach, the
// segments and the next level. r3 = min(reach(3), max(reach(4), reach(7)),
// reach(5), reach(6)) when (3), (5), (6) and at least one of (4) and (7)
// are met, else 0.
func evLevels(n int64, conds map[string]evCond) (int, int64, []EvidenceSegment, *EvidenceNext) {
	reach := func(code string) int64 {
		if c := conds[code]; c.met {
			return c.reach
		}
		return 0
	}
	max64 := func(xs ...int64) int64 {
		m := xs[0]
		for _, x := range xs[1:] {
			if x > m {
				m = x
			}
		}
		return m
	}
	r := [4]int64{n, max64(reach(CondTimeWitness), reach(CondExpectedRootFound), reach(CondReceiptKeyConfirmed)), reach(CondReceiptKeyConfirmed), 0}
	all3 := true
	r3 := int64(-1)
	for _, it := range evRule[3].items {
		if !it.met(conds) {
			all3 = false
			break
		}
		if x := it.reach(conds); r3 < 0 || x < r3 {
			r3 = x
		}
	}
	if all3 {
		r[3] = r3
	}
	segments := []EvidenceSegment{}
	level := 0
	if n < 1 {
		return 0, n, segments, evNext(0, conds)
	}
	for k := 3; k >= 0; k-- {
		if r[k] >= 1 {
			level = k
			break
		}
	}
	clamp := func(x int64) int64 {
		if x > n {
			return n
		}
		return x
	}
	// lvl(p) >= k exactly for p <= r_k, since r1 >= r2 >= r3.
	upper := [4]int64{n, clamp(r[1]), clamp(r[2]), clamp(r[3])}
	prev := int64(0)
	for k := 3; k >= 0; k-- {
		if upper[k] <= prev {
			continue
		}
		segments = append(segments, EvidenceSegment{Level: k, FirstSeq: prev + 1, LastSeq: upper[k], Basis: evBasis(k, r, conds)})
		prev = upper[k]
	}
	up := r[level]
	if level == 0 {
		up = n
	}
	return level, up, segments, evNext(level, conds)
}

// evBasis is basis of a segment at level k (10.9.5), in condition_order: at
// level 3 the met codes among (3) to (7) whose reach equals r3, at level 2
// receipt_key_confirmed, at level 1 the met codes among (1) to (3) whose
// reach equals r1, at level 0 none.
func evBasis(k int, r [4]int64, conds map[string]evCond) []string {
	out := []string{}
	switch k {
	case 3, 1:
		of := ruleCodes(k)
		for _, code := range evConditionOrder {
			if c := conds[code]; of[code] && c.met && c.reach == r[k] {
				out = append(out, code)
			}
		}
	case 2:
		out = append(out, CondReceiptKeyConfirmed)
	}
	return out
}

// evNext is next of 10.9.5 for a level below 3, nil at level 3: the
// conditions of level L + 1 that are not met, in condition_order. For level
// 3, (4) and (7) count as one condition: if neither is met, missing names
// both; if one is met, it names neither.
func evNext(level int, conds map[string]evCond) *EvidenceNext {
	if level >= 3 {
		return nil
	}
	rule := evRule[level+1]
	nx := &EvidenceNext{Level: level + 1, Need: rule.need, Missing: []string{}}
	missing := map[string]bool{}
	for _, it := range rule.items {
		if it.met(conds) {
			continue
		}
		for _, c := range it.codes() {
			missing[c] = true
		}
	}
	for _, code := range evConditionOrder {
		if missing[code] {
			nx.Missing = append(nx.Missing, code)
		}
	}
	return nx
}

// evState is the state of 10.9.2, the topmost row that applies, and
// whether every finding of exit class 2 comes from material_classes.
func evState(exit int, classes map[string]bool) (string, bool) {
	if exit == 3 {
		return EvFormatError, false
	}
	exit2 := false
	for c := range classes {
		if classExit[c] != 2 {
			continue
		}
		if !evMaterialClasses[c] {
			return EvChainInvalid, false
		}
		exit2 = true
	}
	return EvRated, exit2
}

// evaluateEvidence determines the evidence level from the recorded values
// (10.9.2 to 10.9.6) and writes the report object (10.10.2).
func evaluateEvidence(in *evInputs) *EvidenceLevelStat {
	ev := &EvidenceLevelStat{Segments: []EvidenceSegment{}, Notes: []string{}}
	state, material := evState(in.exit, in.classes)
	ev.State = state
	switch state {
	case EvFormatError:
		return ev
	case EvChainInvalid:
		ev.Affiliation = in.affiliation
		return ev
	}
	ev.Affiliation = in.affiliation
	ev.text.material = material

	c1, roots1 := condTimeWitness(in)
	c2, sources := condExpectedRootFound(in)
	c3, receipts := condReceiptKeyConfirmed(in)
	c4, roots4, cands4 := condTimeWitnessQualified(in)
	c5 := condReceiptsLogged(in)
	c6 := condCompleteness(in)
	c7, roots7, cands7 := condLogDayQualified(in)
	conds := map[string]evCond{CondTimeWitness: c1, CondExpectedRootFound: c2, CondReceiptKeyConfirmed: c3,
		CondTimeWitnessQualified: c4, CondReceiptsLogged: c5, CondCompleteness: c6, CondLogDayQualified: c7}
	ec := &EvidenceConditions{}
	for _, code := range evConditionOrder {
		*ec.Get(code) = conds[code].stat()
	}
	ev.Conditions = ec

	level, up, segments, next := evLevels(in.entries, conds)
	n := in.entries
	ev.Level, ev.Entries, ev.UpToTreeSize, ev.Segments, ev.Next = &level, &n, &up, segments, next
	// qualified_time (10.10.2): at level 3 at seq 1, null below.
	if level == 3 {
		ev.QualifiedTime = chooseQualifiedTime(append(cands4, cands7...), up)
	}

	// Anchors (10.10.2).
	an := &EvidenceAnchors{VendorKeys: []EvidenceKeyRef{}, StatementKeys: []EvidenceKeyRef{}, TSARoots: []EvidenceTSARoot{},
		QualifiedRootsFile: in.qualifiedFile, ExpectedRootSources: sources}
	vk := map[string]EvidenceKeyRef{}
	for _, x := range receipts {
		if _, ok := vk[x.keyID]; !ok {
			vk[x.keyID] = receiptKeyRef(x)
		}
	}
	an.VendorKeys = sortedKeyRefs(vk)
	var pages []evPage
	if c2.met && indexOf(sources, "anchor_history") >= 0 {
		pages = append(pages, in.pagesFound...)
	}
	if c6.met {
		pages = append(pages, in.pagesCompl...)
	}
	an.StatementKeys = pageKeyRefs(pages, in.roleList)
	var historyPages []evPage
	if c6.met {
		historyPages = in.pagesCompl
	}
	credited := map[string][]string{}
	for _, x := range []struct {
		code  string
		roots map[string]bool
	}{{CondTimeWitness, roots1}, {CondTimeWitnessQualified, roots4}, {CondLogDayQualified, roots7}} {
		for sha := range x.roots {
			credited[sha] = append(credited[sha], x.code)
		}
	}
	for sha, codes := range credited {
		an.TSARoots = append(an.TSARoots, EvidenceTSARoot{CertSHA256: sha, CreditedFor: codes})
	}
	sort.Slice(an.TSARoots, func(i, j int) bool { return an.TSARoots[i].CertSHA256 < an.TSARoots[j].CertSHA256 })
	ev.Anchors = an

	ev.text.receiptKeys = an.VendorKeys
	ev.text.historyKeys = pageKeyRefs(historyPages, in.roleList)
	ev.text.roots = map[string][]string{CondTimeWitness: sortedSet(roots1), CondTimeWitnessQualified: sortedSet(roots4), CondLogDayQualified: sortedSet(roots7)}
	ev.text.qualifiedFile = in.qualifiedFile
	ev.text.sources = sources
	ev.text.logID = in.logID
	ev.text.asOf = in.asOf

	ev.Notes = evNotes(in, conds, level, material, receipts, roots1, sources)
	return ev
}

// evNotes are the notes of 10.9.6, each once when its occasion applies, in
// note_order.
func evNotes(in *evInputs, conds map[string]evCond, level int, material bool, receipts []evReceipt, roots1 map[string]bool, sources []string) []string {
	on := map[string]bool{}
	on[ntMaterialContradiction] = material
	on[ntUnsealedEnd] = in.classes[ClsUnsealedEnd]
	on[ntStalePackage] = in.classes[ClsTrailingSilence]
	on[ntPackageNotFullyKnown] = in.classes[ClsSpecNewer] || in.classes[ClsUnknownEntryType] || in.classes[ClsUnknownManifestFld]
	if conds[CondReceiptKeyConfirmed].met {
		builtinOnly := true
		credited := map[int64]bool{}
		for _, x := range receipts {
			credited[x.seq] = true
			if x.via != keyViaList || x.list == nil || x.list.rootFrom != rootFromBuiltin {
				builtinOnly = false
			}
			if isPublishedTestEd25519(x.pub) || x.via == keyViaList && x.list != nil && isPublishedTestEd25519(x.list.rootPub) {
				on[ntPublishedTestKey] = true
			}
		}
		on[ntVendorRootBuiltinOnly] = builtinOnly
		on[ntLastReceiptNotConfirm] = in.lastCountersignedSeq > 0 && !credited[in.lastCountersignedSeq]
	}
	if conds[CondReceiptsLogged].met && in.protocolTestKey {
		on[ntPublishedTestKey] = true
	}
	pageTestKey := func(pages []evPage) bool {
		for _, p := range pages {
			if isPublishedTestEd25519(p.pub) || !p.pinned && in.roleList != nil && isPublishedTestEd25519(in.roleList.rootPub) {
				return true
			}
		}
		return false
	}
	if conds[CondExpectedRootFound].met && indexOf(sources, "anchor_history") >= 0 && pageTestKey(in.pagesFound) {
		on[ntPublishedTestKey] = true
	}
	if conds[CondCompleteness].met && pageTestKey(in.pagesCompl) {
		on[ntPublishedTestKey] = true
	}
	on[ntExpectedRootAuditor] = level == 1 && conds[CondExpectedRootFound].met && !conds[CondTimeWitness].met &&
		!conds[CondReceiptKeyConfirmed].met && len(sources) == 1 && sources[0] == "auditor"
	for _, x := range in.roots {
		if roots1[x.certSHA] && in.pkgSPKI[x.spki] {
			on[ntTSARootInPackage] = true
		}
	}
	on[ntHistoryRecentSkipped] = in.recentRootsSkipped
	for _, l := range in.l8 {
		switch l.class {
		case RcPending:
			on[ntReceiptsPendingLog] = true
		case RcMissing:
			on[ntLogDayNotSupplied] = true
		}
	}
	on[ntReceiptNotLogged] = in.classes[ClsReceiptNotLogged]
	on[ntLoggedRootMismatch] = in.classes[ClsLoggedRootMismatch]
	// cms_not_implemented: this verifier performs steps 5 and 6 of 7.3.
	out := []string{}
	for _, n := range evNoteOrder {
		if on[n] {
			out = append(out, n)
		}
	}
	return out
}

// receiptKeyRef is how the key of a credited receipt is established.
func receiptKeyRef(x evReceipt) EvidenceKeyRef {
	k := EvidenceKeyRef{KeyID: x.keyID, Via: keyViaPinned}
	if x.via == keyViaList && x.list != nil {
		k.Via = keyViaList
		v, id, from := x.list.version, x.list.rootID, x.list.rootFrom
		k.ListVersion, k.RootID, k.RootFrom = &v, &id, &from
	}
	return k
}

// pageKeyRef is how the statements key of a page is established.
func pageKeyRef(p evPage, q *evList) EvidenceKeyRef {
	k := EvidenceKeyRef{KeyID: p.keyID, Via: SourcePinned}
	if !p.pinned && q != nil {
		k.Via = SourceRoleList
		v, id, from := q.version, q.rootID, q.rootFrom
		k.ListVersion, k.RootID, k.RootFrom = &v, &id, &from
	}
	return k
}

// pageKeyRefs lists the statements keys of pages without repetition, one per
// distinct (key_id, public key, source) as 10.10.2 writes it, ordered by
// these three in byte order.
func pageKeyRefs(pages []evPage, q *evList) []EvidenceKeyRef {
	type ref struct {
		id, pub, via string
		k            EvidenceKeyRef
	}
	seen := map[[3]string]bool{}
	var refs []ref
	for _, p := range pages {
		k := pageKeyRef(p, q)
		key := [3]string{k.KeyID, p.pub, k.Via}
		if seen[key] {
			continue
		}
		seen[key] = true
		refs = append(refs, ref{k.KeyID, p.pub, k.Via, k})
	}
	sort.Slice(refs, func(i, j int) bool {
		a, b := refs[i], refs[j]
		if a.id != b.id {
			return a.id < b.id
		}
		if a.pub != b.pub {
			return a.pub < b.pub
		}
		return a.via < b.via
	})
	out := []EvidenceKeyRef{}
	for _, r := range refs {
		out = append(out, r.k)
	}
	return out
}

func sortedKeyRefs(m map[string]EvidenceKeyRef) []EvidenceKeyRef {
	out := []EvidenceKeyRef{}
	for _, k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KeyID < out[j].KeyID })
	return out
}

func sortedSet(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// evidenceLevel determines the report object evidence_level after the exit
// code (10.5 stage 5, step 15).
func (r *run) evidenceLevel(exit int, st *Stats) *EvidenceLevelStat {
	return evaluateEvidence(r.evidenceInputs(exit, st))
}
