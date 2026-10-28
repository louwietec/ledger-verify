// Package vfy implements the full offline verification of a LEDGER
// verification package, implemented exclusively from the open specification
// (spec/format.*.md, spec/registry.json).
package vfy

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
)

// Finding classes (registry: verifier.finding_classes).
const (
	ClsSeqBreak            = "SEQ_BREAK"
	ClsHashMismatch        = "HASH_MISMATCH"
	ClsSigInvalid          = "SIG_INVALID"
	ClsMerkleInconsistent  = "MERKLE_INCONSISTENT"
	ClsReceiptInvalid      = "RECEIPT_INVALID"
	ClsTimeAnchorInvalid   = "TIME_ANCHOR_INVALID"
	ClsForkDetected        = "FORK_DETECTED"
	ClsClockAnomaly        = "CLOCK_ANOMALY"
	ClsConcealedSilence    = "CONCEALED_SILENCE"
	ClsHandoverBroken      = "HANDOVER_BROKEN"
	ClsMissingCheckpoint   = "MISSING_CHECKPOINT"
	ClsContentMismatch     = "CONTENT_MISMATCH"
	ClsReportMismatch      = "REPORT_MISMATCH"
	ClsUnsealedEnd         = "UNSEALED_END"
	ClsCoveredGap          = "COVERED_GAP"
	ClsCoveredSourceGap    = "COVERED_SOURCE_GAP"
	ClsReconciliationDelta = "RECONCILIATION_DELTA"
	ClsContentDeleted      = "CONTENT_DELETED"
	ClsHoldViolation       = "HOLD_VIOLATION"
	ClsClockJumpNote       = "CLOCK_JUMP_NOTE"
	ClsTrailingSilence     = "TRAILING_SILENCE"
	ClsNoAnchor            = "NO_ANCHOR"
	ClsTimeAnchorUnverif   = "TIME_ANCHOR_UNVERIFIED"
	ClsReceiptUnverified   = "RECEIPT_UNVERIFIED"
	// Spec 1.10: vendor log (7.4.11, reported by vendorlog.go) and anchor
	// history (8.8.7, reported by anchorhistory.go), all exit class 1.
	ClsVendorLogUnverified = "VENDOR_LOG_UNVERIFIED"
	ClsVendorLogDefective  = "VENDOR_LOG_DEFECTIVE"
	ClsVendorLogContradict = "VENDOR_LOG_CONTRADICTION"
	ClsReceiptNotLogged    = "RECEIPT_NOT_LOGGED"
	ClsLoggedRootMismatch  = "LOGGED_ROOT_MISMATCH"
	ClsHistoryUnverified   = "ANCHOR_HISTORY_UNVERIFIED"
	ClsHistoryDefective    = "ANCHOR_HISTORY_DEFECTIVE"
	ClsHistoryContradict   = "ANCHOR_HISTORY_CONTRADICTION"
	ClsHistoryFork         = "ANCHOR_HISTORY_FORK"
	ClsSpecNewer           = "SPEC_NEWER"
	ClsUnknownEntryType    = "UNKNOWN_ENTRY_TYPE"
	ClsUnknownManifestFld  = "UNKNOWN_MANIFEST_FIELD"
	ClsFormatError         = "FORMAT_ERROR"
)

// classExit maps finding class -> exit class (registry).
var classExit = map[string]int{
	ClsSeqBreak: 2, ClsHashMismatch: 2, ClsSigInvalid: 2, ClsMerkleInconsistent: 2,
	ClsReceiptInvalid: 2, ClsTimeAnchorInvalid: 2, ClsForkDetected: 2, ClsClockAnomaly: 2,
	ClsConcealedSilence: 2,
	ClsHandoverBroken:   2, ClsMissingCheckpoint: 2, ClsContentMismatch: 2, ClsReportMismatch: 2,
	ClsUnsealedEnd: 4,
	ClsCoveredGap:  1, ClsCoveredSourceGap: 1, ClsReconciliationDelta: 1,
	ClsContentDeleted: 1, ClsHoldViolation: 1, ClsClockJumpNote: 1, ClsTrailingSilence: 1, ClsNoAnchor: 1,
	ClsTimeAnchorUnverif: 1, ClsReceiptUnverified: 1,
	ClsVendorLogUnverified: 1, ClsVendorLogDefective: 1, ClsVendorLogContradict: 1,
	ClsReceiptNotLogged: 1, ClsLoggedRootMismatch: 1,
	ClsHistoryUnverified: 1, ClsHistoryDefective: 1, ClsHistoryContradict: 1, ClsHistoryFork: 1,
	ClsSpecNewer: 1, ClsUnknownEntryType: 1, ClsUnknownManifestFld: 1,
	ClsFormatError: 3,
}

// exitPrecedence is the order in which exit classes decide the exit code
// (spec 10.3, registry verifier.exit_precedence): the FIRST class in this list
// that any finding carries wins, and 0 is what remains without findings.
//
// It is a precedence and deliberately not the numeric maximum. Up to spec 1.5
// the two coincided (3 > 2 > 1 > 0) and finish() simply took the largest
// number. Exit 4 (incomplete chain end, spec 8.6) breaks that: an incomplete
// chain with a forged signature must stay 2 ("invalid"), not become 4, and an
// incomplete chain with an informative exit-1 finding is 4, not 1. The numeric
// maximum would get the first case wrong; TestExitPrecedenceMatchesRegistry
// holds this list against the registry.
var exitPrecedence = []int{3, 2, 4, 1, 0}

// statusFor names the verdict of an exit code for the JSON output (Result).
var statusFor = map[int]string{0: "valid", 1: "valid", 2: "invalid", 3: "format_error", 4: "incomplete"}

// Tunable constants from the spec.
const (
	silenceToleranceMS = 450_000 // section 8.2: 7.5 minutes, in whole milliseconds (spec 2)
	clockToleranceMS   = 300_000 // section 9.2: 5 minutes
	defaultFreshnessH  = 24      // section 8.5 default freshness window
	zeroHash           = "0000000000000000000000000000000000000000000000000000000000000000"
)

// unixMS reduces an instant to whole milliseconds (spec 2, "Time arithmetic",
// from edition 1.9): the digits after the third fractional digit are dropped,
// and the tolerance checks of 8.2, 8.5 and 9.2 subtract and compare these
// integers. The epoch does not matter for a difference, so Unix milliseconds
// stand in for "milliseconds since 0001-01-01"; Nanosecond() is never
// negative, so the division truncates the fraction also before 1970.
//
// Why not time.Duration: t.Sub saturates at about ±292 years — 2000 against
// 2300 came out as 2562047h47m16.854775807s — and Duration compared at the
// nanosecond, so 450 s + 100 ns counted as silence here and not in verifier2
// (which truncated to microseconds). Years 0001-9999 in milliseconds stay
// below 3.2e14, far inside int64 and exact in a float64.
func unixMS(t time.Time) int64 {
	return t.Unix()*1000 + int64(t.Nanosecond()/1_000_000)
}

// fmtMS renders a millisecond count for a detail or the report: the exact
// integer, and a readable duration beside it where one fits into a
// time.Duration (about ±292 years).
func fmtMS(ms int64) string {
	const maxDurMS = int64(1<<63-1) / int64(time.Millisecond)
	if ms > -maxDurMS && ms < maxDurMS {
		return fmt.Sprintf("%d ms (%s)", ms, time.Duration(ms)*time.Millisecond)
	}
	return fmt.Sprintf("%d ms", ms)
}

// Finding is one verification finding.
type Finding struct {
	Class  string `json:"class"`
	Seq    int64  `json:"seq,omitempty"`
	Detail string `json:"detail"`
}

// Stats summarizes the verified package.
type Stats struct {
	ChainID     string `json:"chain_id"`
	TreeSize    int64  `json:"tree_size"`
	Entries     int64  `json:"entries"`
	Checkpoints int64  `json:"checkpoints"`
	Receipts    int64  `json:"receipts"`
	// TimeAnchors counts the TIME_ANCHOR entries (spec 7.3); Verified counts
	// those whose authority an anchor OUTSIDE the package vouched for. The
	// two numbers are reported separately on purpose: "3 time witnesses, 0
	// independently established" is a different statement from "3 verified",
	// and only the first one is true without a trust store.
	TimeAnchors         int64 `json:"time_anchors"`
	TimeAnchorsVerified int64 `json:"time_anchors_verified"`
	// TimeAnchorDetails has one element per time witness that binds its
	// checkpoint (spec 7.3 steps 1 to 4), in chain order: whether its
	// signature was checked, whether it was verified, and to which roots of
	// the auditor a path leads (the system root store counts for no purpose,
	// spec 7.5.7).
	// Internal for now: not part of the JSON output, whose shape for it is
	// still open.
	TimeAnchorDetails []TimeAnchorDetail `json:"-"`
	// ReceiptsEstablished counts the receipts whose vendor key an anchor of
	// the AUDITOR established (spec 7.1). Receipts minus this number were
	// checked only against the key the package brought along.
	ReceiptsEstablished int64 `json:"receipts_vendor_established"`
	// VendorList names the signed vendor key list that counted (spec 7.1,
	// 10.7): the verifier cannot tell whether the vendor has issued a newer
	// one, so the auditor gets version and issue time to ask. Nil when no
	// list counted.
	VendorList *VendorListStat `json:"vendor_list,omitempty"`
	Segments   int64           `json:"segments"`
	FirstTS    string          `json:"first_ts,omitempty"`
	LastTS     string          `json:"last_ts,omitempty"`
	Now        string          `json:"now"`
	NowSource  string          `json:"now_source"` // flag | package | system
	// ChainEnd is the status of the chain end (spec 8.6): "sealed" or
	// "incomplete". Nil when the chain end was not judged, which spec 8.6
	// reserves for a package that is a format error (exit 3).
	ChainEnd *ChainEndStat `json:"chain_end,omitempty"`
	// LastCountersigned is the package's last countersigned checkpoint
	// (spec 8.6), nil when the package holds none. Spec 8.6 requires it to be
	// stated with every incomplete chain: offline an export from a running
	// installation, a crash and a truncation look alike, and only the
	// comparison with the vendor's most recent root countersigned before the
	// package was requested tells them apart. It is reported for sealed
	// chains too, for the same comparison.
	LastCountersigned *CountersignStat `json:"last_countersigned,omitempty"`
	// LegalHolds are the deletion holds still active at the chain end
	// (spec 4.24, 9.3), in the order they were set; omitted when none is.
	// Like ChainEnd they are not stated for a format error (exit 3): the
	// material is then not read as a chain.
	LegalHolds []LegalHoldStat `json:"legal_holds,omitempty"`
	// GenesisLicenseNotCommitment: the GENESIS (seq 1) was written under spec
	// 1.7 or earlier and its license_id is not 64 lowercase hex — up to 1.7
	// the standard installation put the licence key there in cleartext
	// (spec 4.1). A notice, not a finding: the result does not change, and
	// the value itself is never printed. Not stated for a format error.
	GenesisLicenseNotCommitment bool `json:"genesis_license_not_commitment,omitempty"`
	// Completeness is what this run can say about whether the package holds
	// the whole chain up to its request (spec 8.6, "What the verifier says
	// about completeness", from 1.9). Stated for every package that is not a
	// format error; for exit 3 null ("nicht bewertet"), never left out
	// (spec 10.10.1).
	Completeness *CompletenessStat `json:"completeness"`
	// ResidualWindow is the measured residual window (spec 11.2, from 1.9):
	// the entries after the last countersigned checkpoint. Not a finding,
	// the exit code does not depend on it. For exit 3 null ("nicht
	// bewertet"), never left out (spec 10.10.1).
	ResidualWindow *ResidualWindowStat `json:"residual_window"`
	// UnanchoredStretches are the covered stretches of spec 11.2 (from
	// 1.10): between two consecutive countersigned checkpoints, more than
	// the anchoring cadence. Not a finding, the exit code does not depend on
	// it. An empty list when there is none; null ("nicht bewertet") only for
	// exit 3, never left out (spec 10.10.1).
	UnanchoredStretches []UnanchoredStretchStat `json:"unanchored_stretches"`
	// KeyRoles is the report object key_roles of the role check (spec
	// 10.7.4, 10.10.2): an object for every package that is not a format
	// error, null for exit 3.
	KeyRoles *KeyRolesStat `json:"key_roles"`
	// VendorLog is the report object vendor_log of the vendor log (spec
	// 7.4.10 step L10, 10.10.2): an object for every package that is not a
	// format error, null for exit 3.
	VendorLog *VendorLogStat `json:"vendor_log"`
	// AnchorHistory and Affiliation are the report objects anchor_history
	// and affiliation of the anchor history (format spec 8.8.4 step H13,
	// 8.8.6, 10.10.2): objects for every package that is not a format error,
	// also without an anchor history (not_supplied, not_checked), null for
	// exit 3.
	AnchorHistory *AnchorHistoryStat `json:"anchor_history"`
	Affiliation   *AffiliationStat   `json:"affiliation"`
	// EvidenceLevel is the report object evidence_level (format spec 10.9,
	// 10.10.2): an object for every report, with the state format_error for
	// exit 3. It is no finding and changes no exit code; an unusable
	// invocation writes no report and so none of it (10.10.1).
	EvidenceLevel *EvidenceLevelStat `json:"evidence_level"`
}

// CompletenessStat (spec 8.6, from 1.9). Without an expected root of the
// auditor that is found in the package, the package alone cannot show that
// it holds the whole chain up to its request — sealed or not: a chain cut
// behind an earlier seal looks sealed, and every export seal is such a point.
//
// Status "established": at least one expected root (--expect-root) was
// passed and found; UpToTreeSize is the largest tree_size among the found
// ones — for a root given without tree_size the prefix size it matched.
// Status "not_established": none was passed or none was found;
// UpToTreeSize is null.
//
// From 1.10 (format spec 8.6, 8.8.5) the found expected roots of both
// sources count, and Sources names the sources of the found roots in the
// order of registry verifier.report_objects.completeness_sources_order
// (auditor, anchor_history); an empty list when none is found.
type CompletenessStat struct {
	Status       string   `json:"status"` // established | not_established
	UpToTreeSize *int64   `json:"up_to_tree_size"`
	Sources      []string `json:"sources"`
}

// ResidualWindowStat is the residual window of spec 11.2, measured.
//
// T (AfterTreeSize) is the tree_size of the last countersigned checkpoint as
// spec 8.6 selects it (Stats.LastCountersigned), 0 if there is none; N is the
// number of entries. The window is the entries at positions T+1 … N:
// FirstSeq = T+1, LastSeq = N, Entries = N − T. FromTS is ts_chained of the
// entry at T and SpanMS the time from it to ToTS (ts_chained of entry N) in
// whole milliseconds (spec 2) — both null when T = 0. UnansweredAnchorMessages
// counts the ADMIN entries with message_type "anchor" after the receipt of
// that checkpoint (all of them when T = 0): anchors the appliance sent whose
// countersignature the package does not hold. BeyondCadence: T = 0 or a span
// above 450,000 ms (the tolerance of 8.2 over the 5-minute anchor cadence).
type ResidualWindowStat struct {
	AfterTreeSize            int64   `json:"after_tree_size"`
	FirstSeq                 int64   `json:"first_seq"`
	LastSeq                  int64   `json:"last_seq"`
	Entries                  int64   `json:"entries"`
	FromTS                   *string `json:"from_ts"`
	ToTS                     string  `json:"to_ts"`
	SpanMS                   *int64  `json:"span_ms"`
	UnansweredAnchorMessages int64   `json:"unanswered_anchor_messages"`
	BeyondCadence            bool    `json:"beyond_cadence"`
}

// UnanchoredStretchStat is one covered stretch of spec 11.2 (from 1.10):
// T1 (AfterTreeSize) and T2 are the tree_sizes of two consecutive
// countersigned checkpoints as spec 8.6 counts them (the receipt's signature
// holds under the key 7.1 chooses, it matches the chain and its own
// checkpoint, the vendor's list does not contradict it), and more than
// 450,000 ms lie between ts_chained of the entries at T1 and T2. The stretch
// is the entries at positions T1+1 … T2: FirstSeq = T1+1, LastSeq = T2,
// FromTS/ToTS are ts_chained at T1 and T2, SpanMS the time between them in
// whole milliseconds (spec 2). UnansweredAnchorMessages counts the ADMIN
// entries with message_type "anchor" in the stretch after the receipt of T1,
// as the residual window counts them after the receipt of its checkpoint.
// ReceiptSeq and ReceiptServerTS name the receipt of T2, the one that covers
// the stretch; on equal tree_size the first in chain order, as in 8.6.
type UnanchoredStretchStat struct {
	AfterTreeSize            int64  `json:"after_tree_size"`
	FirstSeq                 int64  `json:"first_seq"`
	LastSeq                  int64  `json:"last_seq"`
	FromTS                   string `json:"from_ts"`
	ToTS                     string `json:"to_ts"`
	SpanMS                   int64  `json:"span_ms"`
	UnansweredAnchorMessages int64  `json:"unanswered_anchor_messages"`
	ReceiptSeq               int64  `json:"receipt_seq"`
	ReceiptServerTS          string `json:"receipt_server_ts"`
}

// LegalHoldStat names one deletion hold active at the chain end (spec 9.3).
//
// SetSeq is the seq of the LEGAL_HOLD set that made the hold active: 9.3 says
// a hold is active "from its LEGAL_HOLD with action = set", and a further set
// of the same active hold_id does not start a new hold but "replaces its
// scope". ScopeFrom/ScopeTo are therefore the CURRENT scope — that of the
// latest set — and ScopeSeq names that latest set when it is not the
// activating one, so the report never shows a scope the entry at SetSeq does
// not carry without saying where it comes from. Reference stays the one of
// the activating set: 9.3 lets a further set replace the scope, nothing else.
type LegalHoldStat struct {
	HoldID    string `json:"hold_id"`
	ScopeFrom string `json:"scope_from"`
	ScopeTo   string `json:"scope_to"`
	SetSeq    int64  `json:"set_seq"`
	Reference string `json:"reference"`
	ScopeSeq  int64  `json:"scope_seq,omitempty"`
}

// ChainEndStat describes how the chain ends (spec 8.6).
//
// Status "sealed": the last entries are a SEAL, directly its immediate
// checkpoint, then at most receipts naming exactly that checkpoint; the Seal*
// fields name that SEAL (the report states seq, ts_chained and reason of it).
// Status "incomplete": every other end; the finding UNSEALED_END carries it.
type ChainEndStat struct {
	Status   string `json:"status"` // sealed | incomplete
	LastSeq  int64  `json:"last_seq"`
	LastTS   string `json:"last_ts"`
	LastType string `json:"last_type"`
	// LastCriticalWithoutCheckpoint: the last entry is of a critical type and
	// its immediate checkpoint is missing — from spec 1.6 an incomplete end,
	// not MISSING_CHECKPOINT (spec 6.2). Only ever true for "incomplete".
	LastCriticalWithoutCheckpoint bool   `json:"last_critical_without_checkpoint,omitempty"`
	SealSeq                       int64  `json:"seal_seq,omitempty"`
	SealTS                        string `json:"seal_ts,omitempty"`
	SealReason                    string `json:"seal_reason,omitempty"`
	SealCheckpointSeq             int64  `json:"seal_checkpoint_seq,omitempty"`
}

// CountersignStat names one vendor countersignature (CHECKPOINT_RECEIPT).
type CountersignStat struct {
	ReceiptSeq    int64  `json:"receipt_seq"`
	CheckpointSeq int64  `json:"checkpoint_seq"`
	TreeSize      int64  `json:"tree_size"`
	MerkleRoot    string `json:"merkle_root"`
	ServerTS      string `json:"server_ts"`
	ServerKeyID   string `json:"server_key_id"`
	// KeyEstablished: an anchor of the AUDITOR (pinned key or vendor root)
	// established the vendor key (spec 7.1). False means the key came from
	// the package alone and the receipt is RECEIPT_UNVERIFIED — its root is
	// then a statement of whoever wrote the package, not yet of the vendor.
	KeyEstablished bool `json:"key_established"`
}

// VendorListStat identifies the vendor key list a run relied on.
type VendorListStat struct {
	Version int64  `json:"version"`
	Issued  string `json:"ausgestellt"`
	Root    string `json:"wurzel_id"`
}

// Result is the full verification result.
//
// Valid is "cryptographically valid" in the sense of spec 10.3: no
// manipulation was proven — exit 0, 1 and 4. Exit 4 (incomplete chain end,
// spec 8.6) is true here on purpose: 10.3 forbids marking it as invalid in
// machine-readable output, because a tool that reads only this flag would
// otherwise reject every honest export taken during operation. Status carries
// the verdict itself: "valid" (0/1, sealed), "incomplete" (4), "invalid" (2),
// "format_error" (3).
type Result struct {
	Valid    bool      `json:"valid"`
	Status   string    `json:"status"`
	ExitCode int       `json:"exit_code"`
	Findings []Finding `json:"findings"`
	Stats    Stats     `json:"stats"`
}

// Options control a verification run.
type Options struct {
	Now time.Time // zero and NowSet false = system time (or the package's, see NowFromPackage)
	// NowSet says that Now was given (--now, option now). The zero
	// time.Time is 0001-01-01T00:00:00Z, an instant of the grammar of spec
	// 10.8 (year 0001 to 9999); without NowSet it read as "not given", and
	// the system clock took its place. A non-zero Now counts as given as
	// well, so callers that set only Now keep their meaning.
	NowSet bool
	// NowFromPackage lets the package's own verify_args.json set the
	// verification time. OFF by default and only for frozen test vectors:
	// the file is unsigned and written by the very appliance under
	// examination, so honouring it silently made the freshness check
	// (§8.5 TRAILING_SILENCE) a value the prover chooses — a rolled-back
	// chain exported with a fresh "now" passed as current.
	//
	// From spec 1.9 (10.8) the request is binding: if verify_args.json is
	// absent or does not conform (I-JSON, exactly the member "now" in the
	// rfc3339 grammar), the result is FORMAT_ERROR (exit 3) with the reason —
	// never a silent fall back to the system clock.
	NowFromPackage bool
	Freshness      time.Duration // 0 = default 24h
	// ExpectRoots are the auditor's expected roots (spec 7.2, 8.6, 10.8), any
	// number of them: a paper anchor, the vendor's countersigned root from
	// before the package was requested, a gap witness. Each one not found is
	// MERKLE_INCONSISTENT; each one found counts as an anchor and establishes
	// completeness up to its tree_size (Stats.Completeness).
	ExpectRoots []ExpectedRoot
	// ExpectRoot is the single expected root of the options before 1.9, kept
	// for library callers: either form of ParseExpectedRoot ("ROOT" or
	// "TREE_SIZE:ROOT"). It is judged together with ExpectRoots; a value that
	// is neither form is never found (MERKLE_INCONSISTENT).
	ExpectRoot string
	// TSARoots are DER certificates the AUDITOR supplies out of band as roots
	// of the purpose chain for time witnesses (spec 7.3, 7.5.7, --tsa-root).
	// They and the qualified roots are the only thing that can make a
	// TIME_ANCHOR independent of the package; from spec 1.10 the system root
	// store counts for no purpose. AddTSARootPEM reads them in the strict
	// PEM of spec 10.8.
	TSARoots [][]byte
	// Inputs of the auditor from spec 1.10 (format spec 10.8), read by the
	// methods of auditor_inputs.go and checked together by
	// FinishAuditorInputs: the roots named qualified (purposes chain and
	// qualified), the roots for time stamps of the vendor log (purpose log),
	// extracts of the vendor log, pins of protocol and statements keys, key
	// lists, files of the anchor history and the request time.
	TSAQualified        *QualifiedRoots
	VendorLogTSARoots   [][]byte
	VendorLogs          []VendorLogExtract
	VendorLogKeys       []VendorKey
	VendorStatementKeys []VendorKey
	VendorKeyLists      []AuditorKeyList
	AnchorHistory       []AnchorHistoryFile
	RequestedAt         time.Time
	RequestedAtSet      bool
	RequestedAtRaw      string
	// VendorRoots and VendorKeys are the AUDITOR's trust anchors for vendor
	// countersignatures (spec 7.1, 10.7): the vendor's root key, which vouches
	// for keys through the signed list keys/vendor/schluesselliste.json in the
	// package, and single vendor keys pinned directly. Like TSARoots they live
	// in the options and never in the package — the package is written by the
	// party the receipt is meant to bind.
	VendorRoots []VendorRoot
	VendorKeys  []VendorKey
}

// ExpectedRoot is one expected root of the auditor (spec 10.8).
//
// With TreeSize (> 0) it is found if the recomputed root over exactly the
// first TreeSize entries equals Root; a TreeSize beyond the entries of the
// package is not found. Without (TreeSize 0) it is found if the root over the
// first t entries equals Root for some t. Root is 64 lowercase hex.
type ExpectedRoot struct {
	TreeSize int64  `json:"tree_size,omitempty"`
	Root     string `json:"merkle_root"`
}

// String renders the root in the form it was given.
func (x ExpectedRoot) String() string {
	if x.TreeSize > 0 {
		return fmt.Sprintf("%d:%s", x.TreeSize, x.Root)
	}
	return x.Root
}

// reExpectedRoot is the grammar of spec 10.8: "<merkle_root>" or
// "<tree_size>:<merkle_root>". tree_size is a whole number without leading
// zeros from 1 (a checkpoint's tree_size is at least 1, spec 4.20);
// merkle_root is 64 hex characters, upper and lower case equivalent.
var reExpectedRoot = regexp.MustCompile(`^(?:([1-9][0-9]*):)?([0-9a-fA-F]{64})$`)

// ParseExpectedRoot reads an expected root in either form of spec 10.8. Any
// other spelling is an error: the CLIs make it an unusable invocation
// (exit 3), never a silent interpretation.
func ParseExpectedRoot(s string) (ExpectedRoot, error) {
	m := reExpectedRoot.FindStringSubmatch(s)
	if m == nil {
		return ExpectedRoot{}, fmt.Errorf("expected root %q is neither ROOT (64 hex characters) nor TREE_SIZE:ROOT (spec 10.8)", s)
	}
	x := ExpectedRoot{Root: strings.ToLower(m[2])}
	if m[1] != "" {
		n, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil || n > 1<<53-1 {
			return ExpectedRoot{}, fmt.Errorf("expected root %q: tree_size outside 1 … 2^53−1 (spec 2, 10.8)", s)
		}
		x.TreeSize = n
	}
	return x, nil
}

// expectState is one expected root during a run: as given, whether it was
// readable, and where it was found.
type expectState struct {
	raw     string
	root    ExpectedRoot
	valid   bool
	found   bool
	foundAt int64 // tree size of the prefix whose root it equals
}

type entry struct {
	seq        int64
	eventType  string
	origin     string
	chainID    string
	tsCaptured time.Time
	tsChained  time.Time
	tsChainedS string
	monoDelta  int64
	prevHash   string
	storedHash string
	computed   string // recomputed entry_hash (hex)
	payload    *jcs.Value
	raw        *jcs.Value
}

func (e *entry) pStr(key string) string {
	v := e.payload.Get(key)
	if v == nil || v.Kind != jcs.KindString {
		return ""
	}
	return v.Str
}

func (e *entry) pInt(key string) int64 {
	v := e.payload.Get(key)
	if v == nil || v.Kind != jcs.KindInt {
		return 0
	}
	return v.Int
}

type segInfo struct {
	file     string
	sha256   string
	firstSeq int64
	lastSeq  int64
}

type manifest struct {
	chainID    string
	createdTS  string
	treeSize   int64
	segments   []segInfo
	deviceKeys map[string]string // key_id -> pubkey hex
	vendorKeys map[string]string
}

type run struct {
	fs        pkgFS
	opt       Options
	findings  []Finding
	man       *manifest
	entries   []*entry
	roots     [][32]byte // roots[t-1] = computed root over 1..t
	now       time.Time
	nowSource string
	nowKnown  bool // the check time is resolved (the zero time.Time can be one)

	// Forward compatibility (spec 10.6): SPEC_NEWER is reported once per
	// package, UNKNOWN_ENTRY_TYPE once per unknown type name.
	specNewerNoted bool
	unknownTypes   map[string]bool

	// Time witnesses (spec 7.3, 7.5): the table of the auditor's roots for
	// time stamps (spec 10.8) is built once per run.
	timeAnchors         int64
	timeAnchorsVerified int64
	anchorsPresent      int64
	timeAnchorDetails   []TimeAnchorDetail
	tsaRoots            []*TSARoot
	tsaRootsDone        bool
	// pkgTSASPKI are the SPKI SHA-256 values of the certificates of
	// keys/tsa/*.pem (format spec 10.9.3), recorded by checkTimeAnchors.
	pkgTSASPKI map[string]bool

	// Vendor keys (spec 7.1, 10.7), established once per run, and the role
	// check (spec 10.7.4).
	vendor              *vendorTrust
	roles               *keyRoles
	receiptsEstablished int64

	// Chain end (spec 8.6): the last countersigned checkpoint, recorded by
	// checkReceipts, and the chain-end status, recorded by checkChainEnd.
	lastCountersigned *CountersignStat
	chainEnd          *ChainEndStat

	// Deletion holds (spec 9.3) still active at the chain end, recorded by
	// checkLegalHolds in the order they were set.
	legalHolds []LegalHoldStat

	// Expected roots of the auditor (spec 10.8), judged by matchExpectedRoots.
	expected []*expectState

	// The measured residual window (spec 11.2), recorded by
	// measureResidualWindow.
	residual *ResidualWindowStat

	// Every countersigned checkpoint as spec 8.6 counts them, by tree_size,
	// the first receipt in chain order on a tie (recorded by checkReceipts),
	// and the covered stretches measured from them (spec 11.2, from 1.10).
	countersigned map[int64]*CountersignStat
	stretches     []UnanchoredStretchStat

	// Every CHECKPOINT_RECEIPT in chain order with whether its signature
	// holds under the key of spec 7.1 and whether it drew RECEIPT_INVALID
	// (recorded by checkReceipts), and the vendor log (spec 7.4.10, steps L2
	// to L10, recorded by checkVendorLog).
	receiptInfos []*receiptInfo
	vlog         *vlRun

	// The anchor history (format spec 8.8.4, steps H1 to H11, recorded by
	// checkAnchorHistory, matchExpectedRoots and finishAnchorHistory) and
	// the device keys of the package (PK, recorded by checkCheckpoints).
	ah         *ahRun
	deviceKeys []string
}

// receiptInfo is what the vendor log reads about one receipt (spec 7.4.10:
// "je Quittung, ob ihre Signatur nach Abschnitt 7.1 trägt").
type receiptInfo struct {
	seq      int64
	treeSize int64
	root     string
	serverTS string
	// subject is UTF-8(JCS({chain_id, merkle_root, server_ts, tree_size}))
	// with the chain_id of the envelope: the bytes the signature covers and
	// the leaf of a countersignature (spec 7.4.2).
	subject []byte
	sigOK   bool // the signature holds under the key spec 7.1 chooses
	invalid bool // the receipt drew RECEIPT_INVALID
	// established: the key is pinned (not dropped after 10.7.4) or comes
	// from the effective list of countersigning keys of the package; with
	// sigOK and not invalid the receipt is an established receipt of format
	// spec 8.8.4.
	established bool
	// keyID, pub and via record what format spec 10.9.3 keeps per receipt
	// for the evidence level: the server_key_id, the public key the
	// signature was checked under and where it comes from (keyViaPinned,
	// keyViaList for the list of the package, keyViaManifest).
	keyID string
	pub   string
	via   string
}

// Origins of the key of a receipt (format spec 10.9.3, 10.10.2
// evidence_level.anchors.vendor_keys[].via).
const (
	keyViaPinned   = "pinned"
	keyViaList     = "list"
	keyViaManifest = "manifest"
)

func (r *run) add(class string, seq int64, detail string) {
	r.findings = append(r.findings, Finding{Class: class, Seq: seq, Detail: detail})
}

// noteSpecNewer reports SPEC_NEWER exactly once per package (spec 10.6 R1).
// where names the first place it was seen (manifest or entry). The finding
// never stops the run: the rules this verifier knows are applied as usual
// (a later FORMAT_ERROR can still stop it, as for any package).
func (r *run) noteSpecNewer(seq int64, where, ver string) {
	if r.specNewerNoted {
		return
	}
	r.specNewerNoted = true
	r.add(ClsSpecNewer, seq, fmt.Sprintf("%s declares spec_version %s, this verifier implements %d.%d and applies only the rules it knows; rules added after %d.%d are not checked (spec 10.6)",
		where, ver, specMajor, specMinor, specMajor, specMinor))
}

// noteUnknownType reports UNKNOWN_ENTRY_TYPE once per type name, with the seq
// of the first occurrence (spec 10.6 R2). The entry itself stays in the seq,
// reArrayIndex matches the "[7]" of a collected field path.
var reArrayIndex = regexp.MustCompile(`\[[0-9]+\]`)

// unbekanntePfade turns the raw collector of validateObjectOffen into the list
// this verifier reports: array indices dropped, deduplicated, sorted.
//
// All three steps carry weight. Without dropping the index, one extra field in
// a chain with a hundred segments would be a hundred findings and would bury
// every other one — spec 10.6 R5 therefore prescribes "manifest.segments[]".
// Without dedup the same path would repeat per element. Without sorting the
// order would follow Go's map iteration, which is randomized, so two runs over
// the same package would print findings in different orders — and the frozen
// expectations in spec/testvectors/expected/ compare finding sets, which the
// second verifier must reproduce exactly.
// / Index-stripped, deduplicated, sorted: one finding per distinct field path,
// in a deterministic order.
func unbekanntePfade(roh []string) []string {
	gesehen := make(map[string]bool, len(roh))
	var raus []string
	for _, p := range roh {
		p = reArrayIndex.ReplaceAllString(p, "[]")
		if !gesehen[p] {
			gesehen[p] = true
			raus = append(raus, p)
		}
	}
	sort.Strings(raus)
	return raus
}

// hash-chain and Merkle checks; only its payload is not judged, and no
// immediate-checkpoint obligation is assumed for it.
func (r *run) noteUnknownType(seq int64, et string) {
	if r.unknownTypes == nil {
		r.unknownTypes = map[string]bool{}
	}
	if r.unknownTypes[et] {
		return
	}
	r.unknownTypes[et] = true
	r.add(ClsUnknownEntryType, seq, fmt.Sprintf("event_type %q is unknown to this verifier (spec %d.%d), first occurrence at seq %d; entry included in seq, hash-chain and Merkle checks, payload only checked to be an object, no immediate-checkpoint obligation assumed (spec 10.6)",
		et, specMajor, specMinor, seq))
}

// Verify runs the full verification of the package at path (dir or ZIP).
func Verify(path string, opt Options) Result {
	r := &run{opt: opt}
	fs, err := openPackage(path)
	if err != nil {
		r.add(ClsFormatError, 0, fmt.Sprintf("cannot open package: %v", err))
		return r.finish()
	}
	return verifyFS(fs, opt)
}

// VerifyBytes prueft ein Pruefpaket, das als ZIP im Speicher liegt — der
// Einstieg fuer den Browser-Verifier (js/wasm), wo es kein Dateisystem gibt.
//
// Es ist bewusst KEINE zweite Pruefkette, sondern derselbe Ablauf: Verify und
// VerifyBytes unterscheiden sich nur darin, WIE das Paket geoeffnet wird, und
// laufen danach beide durch verifyFS. Ein Verifier, der im Browser anders
// urteilt als auf der Kommandozeile, waere schlimmer als gar keiner — deshalb
// wird die Aequivalenz beider ueber den ganzen Vektorkorpus gemessen, auf
// Exit-Code UND Befundliste.
// / Verifies a package held in memory; same pipeline as Verify, only the way
// the package is opened differs.
func VerifyBytes(data []byte, opt Options) Result {
	r := &run{opt: opt}
	fs, err := openZipBytes(data)
	if err != nil {
		r.add(ClsFormatError, 0, fmt.Sprintf("cannot open package: %v", err))
		return r.finish()
	}
	return verifyFS(fs, opt)
}

// verifyFS ist die eine Pruefkette, die beide Einstiege teilen.
//
// The order is the one of spec 10.5, "Processing stages" (from 1.9): (1) the
// manifest, (2) the segment table, (3) every segment's presence, SHA-256 and
// line count, (4) the lines, (5) the checks of the chain. A failing stage 1
// to 3 drops everything after it; a failing line of stage 4 lets the other
// lines continue and drops stage 5. Before stage 1 stands the check time: a
// requested verify_args.json that does not conform ends the run (10.8).
// Between stage 4 and 5 the number rule of spec 2 is applied to the JSON
// files stages 1-4 do not read (vendor key list, salt files), so that a
// package that is a format error never has its chain end judged (8.6).
func verifyFS(fs pkgFS, opt Options) Result {
	r := &run{opt: opt}
	r.fs = fs
	if err := r.resolveNow(); err != nil {
		r.add(ClsFormatError, 0, err.Error())
		return r.finish() // requested check time unusable (spec 10.8): no fallback
	}

	if !r.loadManifest() || !r.loadEntries() || !r.checkPackageNumbers() {
		return r.finish() // FORMAT_ERROR: package unreadable, stop
	}

	// Stage 5 in the order of spec 10.5 (from 1.10). Step 1: the request
	// time against a check time taken from verify_args.json (spec 10.8);
	// against --now or the system clock the callers compared it at
	// invocation.
	if r.opt.RequestedAtSet && r.nowSource == "package" && unixMS(r.opt.RequestedAt) > unixMS(r.now) {
		r.add(ClsFormatError, 0, fmt.Sprintf("--requested-at %s lies after the check time %s from verify_args.json (spec 10.5, 10.8)",
			r.opt.RequestedAtRaw, FormatMillisUTC(r.now)))
		return r.finish()
	}
	r.checkSeqAndHashChain()
	r.computeRoots()
	r.checkCheckpoints()
	r.loadVendorTrust()
	r.checkKeyRoles()
	r.checkReceipts()
	r.checkVendorLog()
	// Steps 7 and 8: the anchor history H1 to H7, then the expected roots
	// of both sources with the classification H8 (format spec 8.8.5). Up to
	// 1.9 the expected roots were matched before the checkpoints; 10.5 notes
	// that the order changes no result.
	r.checkAnchorHistory()
	r.matchExpectedRoots()
	r.measureResidualWindow()
	r.measureUnanchoredStretches()
	r.checkTimeAnchors()
	// Step 11: the anchor history H9 to H11.
	r.finishAnchorHistory()
	r.checkAnchorPresence()
	r.checkExpectRoot()
	r.checkPerEntryFindings()
	r.checkLegalHolds()
	r.checkSilence()
	r.checkClock()
	r.checkImmediateCheckpoint()
	r.checkHandover()
	r.checkChainEnd()
	r.checkFreshness()
	r.checkContent()
	r.checkReports()

	return r.finish()
}

// resolveNow: --now flag > (only with NowFromPackage) verify_args.json >
// system time. The source is reported in Stats so a reader of the report
// can see whether the freshness verdict rests on the real clock.
//
// Spec 10.8 (from 1.9): when the auditor asks for the package's time, the
// request is binding. An absent or non-conforming verify_args.json is an
// error — the caller makes it FORMAT_ERROR (exit 3) with the reason — and
// never a quiet fall back to the system clock. Up to 1.8 it fell back without
// a word; only stats.now_source said "system". A system clock can only add
// TRAILING_SILENCE, so the fallback was not unsafe, but an explicit request
// silently changed the basis of the freshness verdict, and verifier2 answered
// the same package with exit 3.
func (r *run) resolveNow() error {
	if r.opt.NowSet || !r.opt.Now.IsZero() {
		r.now, r.nowSource, r.nowKnown = r.opt.Now, "flag", true
		return nil
	}
	if r.opt.NowFromPackage {
		r.nowSource = "package"
		t, err := r.readVerifyArgs()
		if err != nil {
			return err
		}
		r.now, r.nowKnown = t, true
		return nil
	}
	r.now, r.nowSource, r.nowKnown = time.Now().UTC(), "system", true
	return nil
}

// readVerifyArgs reads the check time from verify_args.json (spec 10.8): I-JSON
// (spec 2 — no duplicate member, numbers in the integer profile) with exactly
// the member "now", an instant of the rfc3339 grammar of spec 2/10.7.
func (r *run) readVerifyArgs() (time.Time, error) {
	const name = "verify_args.json"
	fail := func(format string, a ...any) (time.Time, error) {
		return time.Time{}, fmt.Errorf("the check time was requested from the package (--now-from-package), but "+name+" "+format+" (spec 10.8); no fallback to the system clock", a...)
	}
	if r.fs == nil || !r.fs.Exists(name) {
		return fail("is absent")
	}
	b, err := r.fs.ReadFile(name)
	if err != nil {
		return fail("cannot be read: %v", err)
	}
	v, err := jcs.Parse(b)
	if err != nil {
		return fail("is not I-JSON: %v", err)
	}
	if v.Kind != jcs.KindObject {
		return fail("is not a JSON object")
	}
	if len(v.Members) != 1 || v.Members[0].Key != "now" {
		keys := make([]string, len(v.Members))
		for i, m := range v.Members {
			keys[i] = strconv.Quote(m.Key)
		}
		return fail("must have exactly the member \"now\", has [%s]", strings.Join(keys, ","))
	}
	nv := v.Members[0].Value
	if nv.Kind != jcs.KindString {
		return fail("carries \"now\" that is not a string")
	}
	t, err := parseRFC3339(nv.Str)
	if err != nil {
		return fail("carries an unusable \"now\": %v", err)
	}
	return t, nil
}

func (r *run) loadManifest() bool {
	b, err := r.fs.ReadFile("manifest.json")
	if err != nil {
		r.add(ClsFormatError, 0, "manifest.json missing or unreadable")
		return false
	}
	v, err := jcs.Parse(b)
	if err != nil {
		r.add(ClsFormatError, 0, fmt.Sprintf("manifest.json: invalid JSON: %v", err))
		return false
	}
	// SPEC_NEWER is noted before the schema verdict so that it is reported
	// alongside a FORMAT_ERROR of the same manifest (spec 10.6 R3).
	if sv := v.Get("spec_version"); sv != nil && sv.Kind == jcs.KindString {
		if newer, err := checkSpecVersion("manifest.spec_version", sv.Str); err == nil && newer {
			r.noteSpecNewer(0, "manifest.json", sv.Str)
		}
	}
	// Spec 10.6 R5: an undefined manifest field is a finding, not a schema
	// error, and it must not stop the run.
	//
	// Until the release of 15.09.2026 (evening) validateObject was strict here
	// and this function returned false — so a future minor version that adds
	// one manifest field made every shipped verifier answer exit 3 and perform
	// ZERO chain checks on a perfectly valid package. Not "a finding too many":
	// no verdict at all, on the one path whose promise is that any third party
	// can check for themselves. The manifest enters no hash, no root and no
	// signature, so accepting the field costs no cryptographic ground.
	//
	// From 1.9 (10.5, stage 1) the R5 signals come BEFORE the schema verdict,
	// like SPEC_NEWER above: they are reported beside a schema error of the
	// same manifest (10.6 R3, last sentence). Up to 1.8 they were collected
	// during the schema walk and dropped when it failed — and the walk over
	// the field table runs in Go's randomized map order, so which of them had
	// been collected before the error was chance.
	for _, pfad := range manifestOffeneFelder(v) {
		r.add(ClsUnknownManifestFld, 0, fmt.Sprintf(
			"manifest carries the field %s, which this verifier (spec %d.%d) does not define; "+
				"accepted and reported per spec 10.6 R5, all checks this version knows still run; "+
				"the field's meaning is NOT judged, so a newer verifier may see more",
			pfad, specMajor, specMinor))
	}
	var offeneFelder []string // collected again by the open walk, already reported
	if err := validateObjectOffen("manifest", manifestFields, v, &offeneFelder); err != nil {
		r.add(ClsFormatError, 0, fmt.Sprintf("manifest schema: %v", err))
		return false
	}
	m := &manifest{
		chainID:    v.Get("chain_id").Str,
		createdTS:  v.Get("created_ts").Str,
		treeSize:   v.Get("tree_size").Int,
		deviceKeys: map[string]string{},
		vendorKeys: map[string]string{},
	}
	for _, s := range v.Get("segments").Arr {
		m.segments = append(m.segments, segInfo{
			file:     s.Get("file").Str,
			sha256:   s.Get("sha256").Str,
			firstSeq: s.Get("first_seq").Int,
			lastSeq:  s.Get("last_seq").Int,
		})
	}
	for _, k := range v.Get("device_pubkeys").Arr {
		m.deviceKeys[k.Get("key_id").Str] = k.Get("pubkey").Str
	}
	for _, k := range v.Get("vendor_pubkeys").Arr {
		m.vendorKeys[k.Get("key_id").Str] = k.Get("pubkey").Str
	}
	r.man = m
	return true
}

// manifestOffeneFelder lists the manifest's field paths spec 10.2 does not
// define (10.6 R5) — in the manifest object and in the objects of its three
// arrays — WITHOUT judging anything else, so the list does not depend on
// whether or where the schema fails. Index-stripped, deduplicated, sorted
// (unbekanntePfade).
func manifestOffeneFelder(v *jcs.Value) []string {
	if v.Kind != jcs.KindObject {
		return nil
	}
	var roh []string
	for _, m := range v.Members {
		spec, ok := manifestFields[m.Key]
		if !ok {
			roh = append(roh, "manifest."+m.Key)
			continue
		}
		if spec.kind != "array" || m.Value.Kind != jcs.KindArray {
			continue
		}
		for i, el := range m.Value.Arr {
			if el.Kind != jcs.KindObject {
				continue
			}
			for _, em := range el.Members {
				if _, ok := spec.fields[em.Key]; !ok {
					roh = append(roh, fmt.Sprintf("manifest.%s[%d].%s", m.Key, i, em.Key))
				}
			}
		}
	}
	return unbekanntePfade(roh)
}

// reSegmentFile is the grammar of a segment's file name (spec 10.1, explicitly
// from 1.9); "." and ".." match it and are excluded separately.
var reSegmentFile = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// loadEntries runs stages 2 to 4 of spec 10.5.
//
// Stage 2, the segment table (spec 10.1, explicitly from 1.9): every file
// follows the grammar and is read ONLY as segments/<file>; the segments are
// taken in first_seq order whatever their order in the list, their declared
// ranges start at 1 without gaps, do not overlap and end at tree_size ≥ 1.
// Stage 3, per segment in that order: file present, SHA-256, exactly
// last_seq − first_seq + 1 lines — for EVERY segment before any line is
// parsed, so a 10.6 signal is never reported from a missing segment or one
// with a wrong SHA-256, wherever it stands in the list. Every violation of
// stage 2 or 3 is FORMAT_ERROR and ends the run there.
//
// Stage 4, per line: JSON, the 10.6 signals, the schema and the chain_id
// (parseEntry). A failing line is FORMAT_ERROR; the other lines continue,
// the chain checks (stage 5) are dropped.
//
// Why the file grammar. Up to 1.8 the file name was only a string of at most
// 128 characters, and a directory package with file "../../x.jsonl" made this
// verifier read a file OUTSIDE the package (the ZIP path refused such names;
// verifier2 read the name raw). The grammar has no "/" and no "\", and the
// directory reader answers only for names it indexed (pkgfs.go), so neither
// a traversal nor a link can reach past the package any more.
func (r *run) loadEntries() bool {
	m := r.man
	for _, s := range m.segments {
		if !reSegmentFile.MatchString(s.file) || s.file == "." || s.file == ".." {
			r.add(ClsFormatError, 0, fmt.Sprintf("segment file name %q violates the grammar [A-Za-z0-9._-]{1,128} (not \".\" or \"..\"); a segment is read only as segments/<file> (spec 10.1)", s.file))
			return false
		}
	}
	segs := make([]segInfo, len(m.segments))
	copy(segs, m.segments)
	sort.SliceStable(segs, func(i, j int) bool { return segs[i].firstSeq < segs[j].firstSeq })

	// segments must cover 1..tree_size without gaps or overlaps
	want := int64(1)
	for _, s := range segs {
		if s.firstSeq != want {
			r.add(ClsFormatError, 0, fmt.Sprintf("segment coverage broken: expected first_seq %d, got %d (%s): the declared ranges must start at 1, without gaps and without overlap (spec 10.1)", want, s.firstSeq, s.file))
			return false
		}
		if s.lastSeq < s.firstSeq {
			r.add(ClsFormatError, 0, fmt.Sprintf("segment %s: last_seq < first_seq", s.file))
			return false
		}
		want = s.lastSeq + 1
	}
	if want != m.treeSize+1 {
		r.add(ClsFormatError, 0, fmt.Sprintf("segments cover seq 1..%d but manifest tree_size is %d", want-1, m.treeSize))
		return false
	}
	if m.treeSize == 0 {
		r.add(ClsFormatError, 0, "empty chain: tree_size 0, no GENESIS entry")
		return false
	}

	// Stage 3 for all segments first.
	segLines := make([][]string, len(segs))
	for k, s := range segs {
		b, err := r.fs.ReadFile("segments/" + s.file)
		if err != nil {
			r.add(ClsFormatError, 0, fmt.Sprintf("segment file segments/%s missing", s.file))
			return false
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != s.sha256 {
			r.add(ClsFormatError, 0, fmt.Sprintf("segment %s: SHA-256 does not match manifest", s.file))
			return false
		}
		lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
		if int64(len(lines)) != s.lastSeq-s.firstSeq+1 {
			r.add(ClsFormatError, 0, fmt.Sprintf("segment %s: %d lines but manifest declares seq %d..%d", s.file, len(lines), s.firstSeq, s.lastSeq))
			return false
		}
		segLines[k] = lines
	}

	// Stage 4.
	ok := true
	for k, s := range segs {
		for i, line := range segLines[k] {
			e, err := r.parseEntry([]byte(line))
			if err != nil {
				r.add(ClsFormatError, s.firstSeq+int64(i), fmt.Sprintf("segment %s line %d: %v", s.file, i+1, err))
				ok = false
				continue
			}
			r.entries = append(r.entries, e)
		}
	}
	return ok
}

// reSaltFile names a salt file of a presented plaintext (spec 10.1).
var reSaltFile = regexp.MustCompile(`^content/[1-9][0-9]*\.salts\.json$`)

// checkPackageNumbers applies the number rule of spec 2 (explicitly from 1.9)
// to the JSON files of the package that stages 1 to 4 do not read: the vendor
// key list and the salt files of presented plaintexts. Every JSON number in
// the package must be an integer within ±(2^53−1) without fraction or
// exponent; any other is FORMAT_ERROR (exit 3) — also in the vendor key list,
// which is otherwise only "ineffective" when it breaks a rule (10.7), and also
// in a salt file, which is otherwise CONTENT_MISMATCH when it does not
// conform (10.1): spec 2 names both explicitly. The scan does not depend on
// whether the file is otherwise valid (jcs.CheckNumbers). Entries and the
// manifest are held to the rule by their parser in stages 1 and 4,
// verify_args.json by resolveNow — and only when it is requested (10.8: the
// verifier reads it only then).
//
// It runs before the chain checks and stops the run on a violation, so the
// package that is a format error never has its chain end judged (8.6).
func (r *run) checkPackageNumbers() bool {
	var names []string
	if r.fs.Exists(VendorListPath) {
		names = append(names, VendorListPath)
	}
	for _, n := range r.fs.List("content") {
		if reSaltFile.MatchString(n) {
			names = append(names, n)
		}
	}
	ok := true
	for _, n := range names {
		b, err := r.fs.ReadFile(n)
		if err != nil {
			continue // unreadable: judged where the file is read (10.7, 10.1)
		}
		if err := jcs.CheckNumbers(b); err != nil {
			r.add(ClsFormatError, 0, fmt.Sprintf("%s: %v (spec 2: every JSON number in the package)", n, err))
			ok = false
		}
	}
	return ok
}

func (r *run) parseEntry(line []byte) (*entry, error) {
	v, err := jcs.Parse(line)
	if err != nil {
		return nil, fmt.Errorf("invalid JSON: %v", err)
	}
	notes, err := validateEntry(v)
	if err != nil {
		// The entry is rejected (FORMAT_ERROR by the caller), but its 10.6
		// signals are still findings (spec 10.6 R3, last sentence).
		var seq int64
		if s := v.Get("seq"); s != nil && s.Kind == jcs.KindInt {
			seq = s.Int
		}
		if notes.specNewer {
			r.noteSpecNewer(seq, fmt.Sprintf("entry seq %d", seq), v.Get("spec_version").Str)
		}
		if notes.unknownType {
			r.noteUnknownType(seq, notes.typeName)
		}
		return nil, err
	}
	e := &entry{
		seq:        v.Get("seq").Int,
		eventType:  v.Get("event_type").Str,
		origin:     v.Get("origin").Str,
		chainID:    v.Get("chain_id").Str,
		monoDelta:  v.Get("mono_delta_ms").Int,
		prevHash:   v.Get("prev_hash").Str,
		storedHash: v.Get("entry_hash").Str,
		tsChainedS: v.Get("ts_chained").Str,
		payload:    v.Get("payload"),
		raw:        v,
	}
	e.tsCaptured, _ = parseRFC3339(v.Get("ts_captured").Str)
	e.tsChained, _ = parseRFC3339(e.tsChainedS)
	// Forward-compatibility signals (spec 10.6) are findings, not errors: the
	// entry is kept and takes part in every chain-level check below. They are
	// noted BEFORE the chain_id verdict (10.5 stage 4, from 1.9): a foreign
	// chain_id is a FORMAT_ERROR of the same object, and R3 keeps the
	// object's signals beside it. Up to 1.8 the chain_id check returned first
	// and the signals of that object were lost (verifier2 kept them).
	if notes.specNewer {
		r.noteSpecNewer(e.seq, fmt.Sprintf("entry seq %d", e.seq), v.Get("spec_version").Str)
	}
	if notes.unknownType {
		r.noteUnknownType(e.seq, notes.typeName)
	}
	if e.chainID != r.man.chainID {
		return nil, fmt.Errorf("chain_id %s differs from manifest chain_id", e.chainID)
	}
	// Recompute entry_hash: JCS over the entry WITHOUT the entry_hash field.
	sub := &jcs.Value{Kind: jcs.KindObject}
	for _, mem := range v.Members {
		if mem.Key != "entry_hash" {
			sub.Members = append(sub.Members, mem)
		}
	}
	sum := sha256.Sum256(jcs.Canon(sub))
	e.computed = hex.EncodeToString(sum[:])
	return e, nil
}

// checkSeqAndHashChain: gapless seq, prev_hash/entry_hash chain, genesis rules.
func (r *run) checkSeqAndHashChain() {
	for i, e := range r.entries {
		wantSeq := int64(i + 1)
		if e.seq != wantSeq {
			r.add(ClsSeqBreak, e.seq, fmt.Sprintf("expected seq %d, found %d", wantSeq, e.seq))
		}
		if e.storedHash != e.computed {
			r.add(ClsHashMismatch, e.seq, "stored entry_hash does not match recomputed hash over the canonical entry")
		}
		if i == 0 {
			if e.prevHash != zeroHash {
				r.add(ClsHashMismatch, e.seq, "genesis prev_hash is not 64 zero characters")
			}
			if e.eventType != "GENESIS" {
				// Spec section 3: seq=1 MUST be GENESIS. No dedicated finding
				// class exists; treated as a schema-level violation.
				r.add(ClsFormatError, e.seq, "first entry is not of type GENESIS")
			}
		} else {
			if e.prevHash != r.entries[i-1].storedHash {
				r.add(ClsHashMismatch, e.seq, "prev_hash does not match entry_hash of the previous entry")
			}
			if e.eventType == "GENESIS" {
				r.add(ClsFormatError, e.seq, "GENESIS entry at seq > 1")
			}
		}
	}
}

func (r *run) computeRoots() {
	// Leaves are the chained entry_hash values (spec section 5). A rewritten
	// entry is reported once as HASH_MISMATCH (computed vs stored); the tree
	// is built over the stored values so anchored roots stay comparable.
	hashes := make([][]byte, len(r.entries))
	for i, e := range r.entries {
		b, _ := hex.DecodeString(e.storedHash)
		hashes[i] = b
	}
	r.roots = merkleRoots(hashes)
}

// rootAt returns the computed root for tree size t (1-based), ok=false if out of range.
func (r *run) rootAt(t int64) (string, bool) {
	if t < 1 || t > int64(len(r.roots)) {
		return "", false
	}
	return hex.EncodeToString(r.roots[t-1][:]), true
}

func verifySig(pubHex string, msg []byte, sigHex string) bool {
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	if !kanonischerPunkt(pub) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// kanonischerPunkt reports whether a 32-byte Ed25519 public key encodes its
// y coordinate canonically, i.e. y < p = 2^255-19 (RFC 8032 5.1.3 step 1).
// Go's crypto/ed25519 reduces a larger y silently; the second verifier, built
// from RFC 8032 alone, rejects it. The two therefore judged the same package
// differently (review of 25.09.: identity point encoded as y = p+1). The
// stricter reading is the RFC's.
func kanonischerPunkt(pub []byte) bool {
	// p little-endian: ed ff .. ff 7f. Compare y (sign bit cleared) from the
	// most significant byte down.
	var p [32]byte
	p[0] = 0xed
	for i := 1; i < 31; i++ {
		p[i] = 0xff
	}
	p[31] = 0x7f
	for i := 31; i >= 0; i-- {
		b := pub[i]
		if i == 31 {
			b &= 0x7f
		}
		if b != p[i] {
			return b < p[i]
		}
	}
	return false // y == p
}

// checkCheckpoints: tree_size = seq-1, recomputed roots, checkpoint sub-chain,
// signatures with the KEY_ROTATION trust chain (spec sections 6.1-6.4).
func (r *run) checkCheckpoints() {
	if len(r.entries) == 0 {
		return
	}
	curKeyID := ""
	curPub := ""
	if g := r.entries[0]; g.eventType == "GENESIS" {
		curKeyID = g.pStr("device_key_id")
		curPub = g.pStr("device_pubkey")
	}
	// PK of format spec 8.8.4 (10.5 stage 5, step 3): GENESIS.device_pubkey
	// and every new_pubkey of a KEY_ROTATION that 6.4 legitimizes. After a
	// rotation that is not legitimate no later key traces back to the
	// GENESIS key, so none of them is in PK.
	legit := curPub != ""
	if legit {
		r.deviceKeys = append(r.deviceKeys, curPub)
	}
	prevCPHash := zeroHash
	for _, e := range r.entries {
		switch e.eventType {
		case "KEY_ROTATION":
			subject, err := jcs.CanonGo(map[string]any{
				"old_key_id": e.pStr("old_key_id"),
				"new_key_id": e.pStr("new_key_id"),
				"new_pubkey": e.pStr("new_pubkey"),
			})
			if err != nil || e.pStr("old_key_id") != curKeyID || !verifySig(curPub, subject, e.pStr("signature_by_old_key")) {
				r.add(ClsSigInvalid, e.seq, "KEY_ROTATION not signed by the previously valid device key")
				legit = false
			}
			// Adopt the new key either way to avoid cascading duplicates;
			// the trust break itself is already reported.
			curKeyID = e.pStr("new_key_id")
			curPub = e.pStr("new_pubkey")
			if legit {
				r.deviceKeys = append(r.deviceKeys, curPub)
			}
		case "CHECKPOINT":
			ts := e.pInt("tree_size")
			if ts != e.seq-1 {
				r.add(ClsMerkleInconsistent, e.seq, fmt.Sprintf("checkpoint tree_size %d does not equal seq-1 (%d)", ts, e.seq-1))
			} else if root, ok := r.rootAt(ts); ok && root != e.pStr("merkle_root") {
				r.add(ClsMerkleInconsistent, e.seq, fmt.Sprintf("checkpoint merkle_root does not match recomputed root for tree_size %d", ts))
			}
			if e.pStr("prev_checkpoint_hash") != prevCPHash {
				r.add(ClsHashMismatch, e.seq, "prev_checkpoint_hash does not match entry_hash of the previous CHECKPOINT")
			}
			prevCPHash = e.storedHash
			subject, err := checkpointSubject(e)
			if err != nil || e.pStr("key_id") != curKeyID || curPub == "" || !verifySig(curPub, subject, e.pStr("signature")) {
				r.add(ClsSigInvalid, e.seq, fmt.Sprintf("checkpoint signature invalid or key %q not legitimized by GENESIS/KEY_ROTATION", e.pStr("key_id")))
			}
		}
	}
}

// checkpointSubject is the canonical signed subject of a CHECKPOINT
// (spec 6.1): JCS({chain_id,key_id,merkle_root,prev_checkpoint_hash,tree_size,ts}).
//
// It has TWO readers, and that is why it is a function rather than an inline
// literal: the device signature (spec 6.1) and the time witness (spec 7.3),
// whose message imprint is the hash of exactly these bytes. If the two ever
// built the subject differently, every time witness would read as forged
// while the chain itself verified — a contradiction the report could not
// explain.
func checkpointSubject(e *entry) ([]byte, error) {
	return jcs.CanonGo(map[string]any{
		"chain_id":             e.chainID,
		"tree_size":            e.pInt("tree_size"),
		"merkle_root":          e.pStr("merkle_root"),
		"prev_checkpoint_hash": e.pStr("prev_checkpoint_hash"),
		"key_id":               e.pStr("key_id"),
		"ts":                   e.tsChainedS,
	})
}

// checkReceipts: vendor countersignature, match with checkpoint, prefix match.
func (r *run) checkReceipts() {
	bySeq := map[int64]*entry{}
	for _, e := range r.entries {
		bySeq[e.seq] = e
	}
	anyReceipt := false
	for _, e := range r.entries {
		if e.eventType != "CHECKPOINT_RECEIPT" {
			continue
		}
		ts := e.pInt("tree_size")
		root := e.pStr("merkle_root")
		sigOK := false
		keyID := e.pStr("server_key_id")
		// The signed subject of spec 7.1, also the leaf of the vendor log
		// (spec 7.4.2) whose leaf hash step L8 looks up.
		subject, subjErr := jcs.CanonGo(map[string]any{
			"chain_id":    e.chainID,
			"tree_size":   ts,
			"merkle_root": root,
			"server_ts":   e.pStr("server_ts"),
		})
		info := &receiptInfo{seq: e.seq, treeSize: ts, root: root, serverTS: e.pStr("server_ts")}
		if subjErr == nil {
			info.subject = subject
		}
		r.receiptInfos = append(r.receiptInfos, info)
		// The key comes from the auditor's anchors where they reach it, and
		// only otherwise from the manifest (spec 7.1, vendortrust.go).
		pub, established, contra := r.vendorKeyFor(keyID, e.pStr("server_ts"))
		info.established = established
		info.keyID, info.pub, info.via = keyID, pub, r.vendorKeyVia(keyID, established)
		if pub == "" {
			r.add(ClsReceiptInvalid, e.seq, fmt.Sprintf("vendor key %q not in manifest vendor_pubkeys", keyID))
			info.invalid = true
		} else {
			sigOK = subjErr == nil && verifySig(pub, subject, e.pStr("server_signature"))
			switch {
			case contra != "":
				// The vendor's own signed statement contradicts the receipt.
				// The signature may still hold, so the prefix check below
				// still runs (a fork stays visible, spec 7.1) — but the
				// receipt does not count as an anchor.
				r.add(ClsReceiptInvalid, e.seq, contra)
				info.invalid = true
			case !sigOK && established:
				r.add(ClsReceiptInvalid, e.seq, fmt.Sprintf("server_signature does not verify against vendor key %q as the auditor's trust anchor establishes it", keyID))
				info.invalid = true
			case !sigOK:
				r.add(ClsReceiptInvalid, e.seq, "server_signature does not verify against the vendor public key")
				info.invalid = true
			case established:
				r.receiptsEstablished++
			default:
				r.noteUnverifiedVendorKey(e.seq, keyID)
			}
			// Spec 10.7.4: a receipt not established after 7.1 whose key in
			// the manifest is a key of another role keeps its finding of
			// edition 1.9; the report gives the note receipt_key_other_role.
			if !established {
				r.noteReceiptOtherRole(pub)
			}
		}
		info.sigOK = sigOK
		// Spec 7.1 (clarified 25.09.): a receipt whose signature does not hold
		// is RECEIPT_INVALID and nothing further is checked on it — its
		// content is no statement of the vendor. This verifier used to run the
		// prefix check on it too (MERKLE_INCONSISTENT), verifier2 did not.
		if !sigOK {
			continue
		}
		cpOK := true
		matched := false // prefix AND referenced checkpoint match
		// Prefix match against the chain at hand. Checked before the
		// checkpoint cross-reference so that a fork/truncation yields its
		// primary class without derivative bookkeeping findings.
		computed, inRange := r.rootAt(ts)
		switch {
		case !inRange:
			// anchored root beyond the end of the presented chain: truncation
			r.add(ClsMerkleInconsistent, e.seq, fmt.Sprintf("receipt anchors tree_size %d but the presented chain has only %d entries (truncation)", ts, len(r.entries)))
		case computed != root:
			r.add(ClsForkDetected, e.seq, fmt.Sprintf("validly signed receipt root for tree_size %d matches no prefix of the presented chain", ts))
		default:
			// receipt must match its referenced checkpoint (7.1: RECEIPT_INVALID)
			cp := bySeq[e.pInt("checkpoint_seq")]
			if cp == nil || cp.eventType != "CHECKPOINT" {
				r.add(ClsReceiptInvalid, e.seq, fmt.Sprintf("checkpoint_seq %d does not reference a CHECKPOINT entry", e.pInt("checkpoint_seq")))
				cpOK = false
				info.invalid = true
			} else if cp.pInt("tree_size") != ts || cp.pStr("merkle_root") != root {
				r.add(ClsReceiptInvalid, e.seq, "receipt tree_size/merkle_root do not match the referenced checkpoint")
				cpOK = false
				info.invalid = true
			} else {
				matched = true
			}
		}
		// The package's last countersigned checkpoint (spec 8.6): among the
		// receipts whose signature holds under the key 7.1 chooses, the one
		// with the largest tree_size. Counted only where the receipt also
		// matches the chain and its own checkpoint and the vendor's signed list
		// does not contradict it — a root the report hands the auditor for the
		// comparison must be one this chain actually has and one the vendor
		// does not disown. Whether an auditor anchor established the key is
		// kept alongside: without it the root is still only the package's word.
		if contra == "" && matched {
			cs := &CountersignStat{
				ReceiptSeq:     e.seq,
				CheckpointSeq:  e.pInt("checkpoint_seq"),
				TreeSize:       ts,
				MerkleRoot:     root,
				ServerTS:       e.pStr("server_ts"),
				ServerKeyID:    keyID,
				KeyEstablished: established,
			}
			// On equal tree_size the first in chain order stays (spec 8.6).
			if r.lastCountersigned == nil || ts > r.lastCountersigned.TreeSize {
				r.lastCountersigned = cs
			}
			if r.countersigned == nil {
				r.countersigned = map[int64]*CountersignStat{}
			}
			if _, ok := r.countersigned[ts]; !ok {
				r.countersigned[ts] = cs
			}
		}
		// Only a receipt that carries its signature anchors (spec 7.1): an
		// unestablished key still does — the finding says so separately, as
		// for a time witness (7.3) — an invalid or contradicted one does not,
		// and neither does one that contradicts its own checkpoint.
		if contra == "" && cpOK {
			anyReceipt = true
		}
	}
	if anyReceipt {
		r.anchorsPresent++
	}
}

// checkAnchorPresence reports NO_ANCHOR, and it runs AFTER the receipts and
// the time witnesses because both can satisfy it (spec 7, 7.3).
//
// A time witness counts here as soon as it binds its checkpoint — even when
// its authority stays unestablished. "No anchoring is present" and "the one
// present is not independently established" are different statements, and
// reporting both for one anchor would count the same shortfall twice. The
// second one is TIME_ANCHOR_UNVERIFIED and it is already in the report.
//
// An expected root of the auditor counts only where it is FOUND (spec 10.8):
// one that is not found is MERKLE_INCONSISTENT and anchors nothing, as a
// receipt with RECEIPT_INVALID anchors nothing (7). Up to 1.8 this verifier
// let any given --expect-root suppress NO_ANCHOR, found or not.
//
// From 1.10 a found history root counts as well (format spec 8.8.5, 10.5
// stage 5, step 12).
func (r *run) checkAnchorPresence() {
	if r.anchorsPresent == 0 && r.expectedFound() == 0 && r.historyFound() == 0 {
		r.add(ClsNoAnchor, 0, "no CHECKPOINT_RECEIPT that counts as an anchor (its signature holding against the vendor key of spec 7.1, not contradicted by the vendor's signed list), no time witness binding its checkpoint and no expected root of the auditor found in the chain")
	}
}

// matchExpectedRoots judges the auditor's expected roots against the
// recomputed prefix roots (spec 10.8): with tree_size against exactly that
// prefix (a tree_size beyond the entries is not found), without it against
// every prefix — the largest matching prefix is kept, since that is how far
// the root establishes completeness (Stats.Completeness). From 1.10 it then
// merges the history roots with them and classifies the others (format spec
// 8.8.5, step H8; 10.5 stage 5, step 8).
func (r *run) matchExpectedRoots() {
	var alle []string
	if r.opt.ExpectRoot != "" {
		alle = append(alle, r.opt.ExpectRoot)
	}
	for _, x := range r.opt.ExpectRoots {
		alle = append(alle, x.String())
	}
	for _, raw := range alle {
		st := &expectState{raw: raw}
		r.expected = append(r.expected, st)
		x, err := ParseExpectedRoot(raw)
		if err != nil {
			continue // a library caller's unreadable value is never found
		}
		st.root, st.valid = x, true
		if x.TreeSize > 0 {
			if got, ok := r.rootAt(x.TreeSize); ok && got == x.Root {
				st.found, st.foundAt = true, x.TreeSize
			}
			continue
		}
		for t := int64(len(r.roots)); t >= 1; t-- {
			if got, _ := r.rootAt(t); got == x.Root {
				st.found, st.foundAt = true, t
				break
			}
		}
	}
	r.classifyHistoryRoots()
}

// expectedFound returns the number of expected roots found.
func (r *run) expectedFound() int {
	n := 0
	for _, x := range r.expected {
		if x.found {
			n++
		}
	}
	return n
}

// checkExpectRoot reports every expected root that is not found as
// MERKLE_INCONSISTENT (spec 7.2, 8.6, 10.8), once per root, naming why, and
// from 1.10 the findings of the classification of the history roots (format
// spec 8.8.5, step H8; 10.5 stage 5, step 13).
func (r *run) checkExpectRoot() {
	for _, x := range r.expected {
		switch {
		case x.found:
		case !x.valid:
			r.add(ClsMerkleInconsistent, 0, fmt.Sprintf("expected root %q is neither ROOT (64 hex) nor TREE_SIZE:ROOT and matches no recomputed prefix root of this chain (spec 10.8)", x.raw))
		case x.root.TreeSize > int64(len(r.roots)):
			r.add(ClsMerkleInconsistent, 0, fmt.Sprintf("expected root %s: tree_size %d exceeds the %d entries of this package: the package lacks entries up to the expected root (spec 8.6, 10.8)", x.root, x.root.TreeSize, len(r.roots)))
		case x.root.TreeSize > 0:
			got, _ := r.rootAt(x.root.TreeSize)
			r.add(ClsMerkleInconsistent, 0, fmt.Sprintf("expected root %s: the recomputed root over the first %d entries is %s (spec 7.2, 10.8)", x.root, x.root.TreeSize, got))
		default:
			r.add(ClsMerkleInconsistent, 0, fmt.Sprintf("expected root %s matches no recomputed prefix root of this chain (spec 7.2, 10.8)", x.root))
		}
	}
	r.reportHistoryRoots()
}

// completeness is the statement of spec 8.6 (from 1.9) for this run, from
// 1.10 over the found expected roots of both sources with their sources.
func (r *run) completeness() *CompletenessStat {
	c := &CompletenessStat{Status: "not_established", Sources: []string{}}
	var bis int64
	fromAuditor := false
	for _, x := range r.expected {
		if x.found {
			fromAuditor = true
			if x.foundAt > bis {
				bis = x.foundAt
			}
		}
	}
	fromHistory := false
	if h := r.ah; h != nil {
		for _, hr := range h.roots {
			if hr.found {
				fromHistory = true
				if hr.t > bis {
					bis = hr.t
				}
			}
		}
	}
	if fromAuditor {
		c.Sources = append(c.Sources, "auditor")
	}
	if fromHistory {
		c.Sources = append(c.Sources, "anchor_history")
	}
	if bis > 0 {
		c.Status, c.UpToTreeSize = "established", &bis
	}
	return c
}

// measureResidualWindow measures the residual window of spec 11.2 (from 1.9)
// — the entries after the last countersigned checkpoint of 8.6 — once
// checkReceipts has chosen that checkpoint. Positions stand for seq: the
// residual window is stated for every package that is not a format error,
// also for one with SEQ_BREAK, and then counts what the package holds.
func (r *run) measureResidualWindow() {
	n := int64(len(r.entries))
	if n == 0 {
		return
	}
	var t, afterReceipt int64
	if lc := r.lastCountersigned; lc != nil && lc.TreeSize <= n {
		t, afterReceipt = lc.TreeSize, lc.ReceiptSeq
	}
	last := r.entries[n-1]
	rw := &ResidualWindowStat{
		AfterTreeSize: t,
		FirstSeq:      t + 1,
		LastSeq:       n,
		Entries:       n - t,
		ToTS:          last.tsChainedS,
	}
	if t > 0 {
		from := r.entries[t-1]
		fromTS := from.tsChainedS
		span := unixMS(last.tsChained) - unixMS(from.tsChained)
		rw.FromTS, rw.SpanMS = &fromTS, &span
		rw.BeyondCadence = span > silenceToleranceMS
	} else {
		rw.BeyondCadence = true
	}
	for _, e := range r.entries {
		if e.eventType == "ADMIN" && e.pStr("message_type") == "anchor" && e.seq > afterReceipt {
			rw.UnansweredAnchorMessages++
		}
	}
	r.residual = rw
}

// measureUnanchoredStretches measures the covered stretches of spec 11.2
// (from 1.10) once checkReceipts has collected the countersigned
// checkpoints: for every two consecutive ones, T1 < T2, whose entries lie
// more than the anchoring cadence apart. This is what a renewal leaves
// behind: the receipt of T2 covers the stretch, yet nothing in it was
// countersigned while it ran. Positions stand for seq, as in the residual
// window. Every countersigned tree_size is at most the number of entries:
// a larger one fails the prefix check and is not counted (spec 7.1).
func (r *run) measureUnanchoredStretches() {
	r.stretches = []UnanchoredStretchStat{}
	sizes := make([]int64, 0, len(r.countersigned))
	for ts := range r.countersigned {
		sizes = append(sizes, ts)
	}
	sort.Slice(sizes, func(i, j int) bool { return sizes[i] < sizes[j] })
	for i := 1; i < len(sizes); i++ {
		t1, t2 := sizes[i-1], sizes[i]
		from, to := r.entries[t1-1], r.entries[t2-1]
		span := unixMS(to.tsChained) - unixMS(from.tsChained)
		if span <= silenceToleranceMS {
			continue
		}
		cover, afterReceipt := r.countersigned[t2], r.countersigned[t1].ReceiptSeq
		st := UnanchoredStretchStat{
			AfterTreeSize:   t1,
			FirstSeq:        t1 + 1,
			LastSeq:         t2,
			FromTS:          from.tsChainedS,
			ToTS:            to.tsChainedS,
			SpanMS:          span,
			ReceiptSeq:      cover.ReceiptSeq,
			ReceiptServerTS: cover.ServerTS,
		}
		for _, e := range r.entries[t1:t2] {
			if e.eventType == "ADMIN" && e.pStr("message_type") == "anchor" && e.seq > afterReceipt {
				st.UnansweredAnchorMessages++
			}
		}
		r.stretches = append(r.stretches, st)
	}
}

// checkPerEntryFindings emits the informative exit-1 findings per entry.
func (r *run) checkPerEntryFindings() {
	for _, e := range r.entries {
		switch e.eventType {
		case "GAP":
			r.add(ClsCoveredGap, e.seq, fmt.Sprintf("reason=%s window=%s..%s lost_count=%d", e.pStr("reason"), e.pStr("started_ts"), e.pStr("ended_ts"), e.pInt("lost_count")))
		case "SOURCE_GAP":
			r.add(ClsCoveredSourceGap, e.seq, fmt.Sprintf("source=%s window=%s..%s", e.pStr("source_id"), e.pStr("window_start"), e.pStr("window_end")))
		case "RECONCILIATION":
			if e.pInt("delta") != 0 {
				r.add(ClsReconciliationDelta, e.seq, fmt.Sprintf("source=%s delta=%d (reported %d vs chained %d)", e.pStr("source_id"), e.pInt("delta"), e.pInt("reported_count"), e.pInt("chained_count")))
			}
		case "CONTENT_DELETED":
			r.add(ClsContentDeleted, e.seq, fmt.Sprintf("target_seq=%d reason=%s", e.pInt("target_seq"), e.pStr("reason")))
		case "CLOCK_JUMP":
			r.add(ClsClockJumpNote, e.seq, fmt.Sprintf("jump_ms=%d (%s -> %s)", e.pInt("jump_ms"), e.pStr("wall_before"), e.pStr("wall_after")))
		}
	}
}

// activeHold is one deletion hold while checkLegalHolds replays the chain.
type activeHold struct {
	id        string
	setSeq    int64 // the set that made the hold active
	scopeSeq  int64 // the set that defined the current scope (== setSeq unless replaced)
	from, to  time.Time
	fromS     string
	toS       string
	reference string
}

// covers reports whether the hold covers an AI_CALL captured at ts: both
// bounds inclusive, compared as points in time (spec 9.3, 2) — not as
// strings, so "…T08:00:00.000Z" and "…T08:00:00Z" are the same instant.
func (h *activeHold) covers(ts time.Time) bool {
	return !ts.Before(h.from) && !ts.After(h.to)
}

// checkLegalHolds implements section 9.3 (retention, deletion and legal hold).
//
// The LEGAL_HOLD entries are replayed in chain order: a set makes its hold_id
// active, a further set of an ACTIVE hold_id replaces its scope, a release
// ends the hold of its hold_id — and a release without an active hold of that
// id has no effect (9.3). The bounds a release carries play no part (9.3:
// "they carry no meaning for verification").
//
// HOLD_VIOLATION (exit 1): a CONTENT_DELETED whose target_seq names an
// AI_CALL whose ts_captured lies inside the scope of a hold active at the
// position of the CONTENT_DELETED. Reported once per CONTENT_DELETED at its
// seq, naming target_seq and EVERY covering hold — two holds on the same
// content are one deletion, not two findings. Exit 1, not 2: the deletion
// stands openly in the chain; the finding proves that the operator broke a
// hold of its own, not that the chain was manipulated (9.3, principle 8.6).
//
// What is deliberately NOT judged here, because 9.3 does not make it a
// finding: a target_seq that names no entry or an entry other than an
// AI_CALL (the verifier does not validate target_seq, as before 1.7), and a
// scope whose scope_from lies after its scope_to — such a hold is active but
// covers nothing, literally read. The target is looked up in the whole chain
// (9.3 says "names an AI_CALL", not "an earlier one"); coverage depends on the
// target's ts_captured, the hold state on the position of the deletion.
//
// The holds still active at the chain end are kept for the report
// (stats.legal_holds), in the order they were set.
// / Deutsch: Die LEGAL_HOLD-Eintraege werden in Kettenreihenfolge
// nachgespielt; ein CONTENT_DELETED auf einen AI_CALL im Umfang einer an
// seiner Stelle aktiven Sperre ist HOLD_VIOLATION (Exit 1), einmal je
// Loeschung, mit allen erfassenden Sperren.
func (r *run) checkLegalHolds() {
	bySeq := map[int64]*entry{}
	for _, e := range r.entries {
		bySeq[e.seq] = e
	}
	active := map[string]*activeHold{}
	for _, e := range r.entries {
		switch e.eventType {
		case "LEGAL_HOLD":
			id := e.pStr("hold_id")
			if e.pStr("action") == "release" {
				delete(active, id) // no active hold of this id: no effect (9.3)
				continue
			}
			// action "set" (the schema admits no third value). The bounds
			// were validated as rfc3339 with the entry, so the parse cannot
			// fail here; if it ever did, that would be a verifier defect and
			// must not pass silently as "covers nothing".
			from, err1 := parseRFC3339(e.pStr("scope_from"))
			to, err2 := parseRFC3339(e.pStr("scope_to"))
			if err1 != nil || err2 != nil {
				r.add(ClsFormatError, e.seq, fmt.Sprintf("LEGAL_HOLD scope not readable: %v %v", err1, err2))
				continue
			}
			h := active[id]
			if h == nil {
				h = &activeHold{id: id, setSeq: e.seq, reference: e.pStr("reference")}
				active[id] = h
			}
			// A further set of an active hold_id replaces its scope (9.3).
			h.scopeSeq, h.from, h.to = e.seq, from, to
			h.fromS, h.toS = e.pStr("scope_from"), e.pStr("scope_to")
		case "CONTENT_DELETED":
			target := bySeq[e.pInt("target_seq")]
			if target == nil || target.eventType != "AI_CALL" {
				continue // 9.3 judges only deletions of an AI_CALL's content
			}
			var covering []*activeHold
			for _, h := range active {
				if h.covers(target.tsCaptured) {
					covering = append(covering, h)
				}
			}
			if len(covering) == 0 {
				continue
			}
			sort.Slice(covering, func(i, j int) bool { return covering[i].setSeq < covering[j].setSeq })
			r.add(ClsHoldViolation, e.seq, holdViolationDetail(target, covering))
		}
	}
	for _, h := range active {
		st := LegalHoldStat{HoldID: h.id, ScopeFrom: h.fromS, ScopeTo: h.toS, SetSeq: h.setSeq, Reference: h.reference}
		if h.scopeSeq != h.setSeq {
			st.ScopeSeq = h.scopeSeq
		}
		r.legalHolds = append(r.legalHolds, st)
	}
	sort.Slice(r.legalHolds, func(i, j int) bool { return r.legalHolds[i].SetSeq < r.legalHolds[j].SetSeq })
}

// holdViolationDetail names target_seq and every covering hold with its
// hold_id (spec 9.3: "with hold_id and target_seq in the report"). The ids
// and the reference are free text and are quoted, so their bounds stay
// visible in the report.
func holdViolationDetail(target *entry, covering []*activeHold) string {
	ids := make([]string, len(covering))
	holds := make([]string, len(covering))
	for i, h := range covering {
		ids[i] = strconv.Quote(h.id)
		d := fmt.Sprintf("%q set at seq %d, scope %s..%s", h.id, h.setSeq, h.fromS, h.toS)
		if h.scopeSeq != h.setSeq {
			d += fmt.Sprintf(" (scope replaced at seq %d)", h.scopeSeq)
		}
		holds[i] = d + fmt.Sprintf(", reference %q", h.reference)
	}
	was := "an active hold"
	if len(covering) > 1 {
		was = fmt.Sprintf("%d active holds", len(covering))
	}
	return fmt.Sprintf("target_seq=%d hold_id=%s: the deleted content belongs to the AI_CALL at seq %d (ts_captured %s), which lies inside the scope of %s: %s; "+
		"the deletion stands openly in the chain, no manipulation of the chain is proven; the operator deleted content under a hold of its own (spec 9.3)",
		target.seq, strings.Join(ids, ","), target.seq, target.raw.Get("ts_captured").Str, was, strings.Join(holds, "; "))
}

// checkSilence implements section 8.2 (TICK coverage).
//
// Δ is computed in whole milliseconds (spec 2, from 1.9, unixMS): a silence
// window exists when Δ > 450,000 ms, and the GAP bounds of conditions 1 and
// 4 are compared as integers the same way.
//
// Entries of a type unknown to this verifier (spec 10.6 R2) are ordinary
// entries of the pair (a, b) — their ts_chained bounds the window like any
// other entry's — but they count neither as a covering GAP nor as a RESTART,
// and they are not critical (condition 4): a silence that ends in an unknown
// type stays CONCEALED_SILENCE.
func (r *run) checkSilence() {
	for i := 0; i+1 < len(r.entries); i++ {
		a, b := r.entries[i], r.entries[i+1]
		delta := unixMS(b.tsChained) - unixMS(a.tsChained)
		if delta <= silenceToleranceMS {
			continue
		}
		if r.silenceCovered(i, delta) {
			continue
		}
		r.add(ClsConcealedSilence, b.seq, fmt.Sprintf("silence of %s before seq %d without covering GAP/RESTART/handover", fmtMS(delta), b.seq))
	}
}

// gapCovers is the window test of 8.2 condition 1, also used by condition 4
// (d): started_ts(gap) ≤ ts_chained(a) + 450,000 ms and ended_ts(gap) ≥
// ts_chained(b) − 450,000 ms, in whole milliseconds.
func gapCovers(gap, a, b *entry) bool {
	started, err1 := parseRFC3339(gap.pStr("started_ts"))
	ended, err2 := parseRFC3339(gap.pStr("ended_ts"))
	return err1 == nil && err2 == nil &&
		unixMS(started) <= unixMS(a.tsChained)+silenceToleranceMS &&
		unixMS(ended) >= unixMS(b.tsChained)-silenceToleranceMS
}

// silenceCovered decides whether the silence window between entries i and
// i+1 (Δ = delta ms) is covered by one of the four conditions of 8.2.
//
// Condition 3, first sentence: a is the immediate CHECKPOINT of a SEAL and b
// the RESUME that continues exactly that SEAL (sealed_entry_hash, 8.4
// clarification 3). The anchor is the checkpoint, not the SEAL itself — a
// SEAL that is directly followed by the RESUME carries no immediate
// checkpoint, so the planned pause is unanchored and this condition does not
// apply (it then draws MISSING_CHECKPOINT from 6.2 and, if the pause exceeds
// the tolerance, CONCEALED_SILENCE from this rule: two independent defects,
// honestly reported as two).
//
// Condition 3, second sentence (from 1.9): a is a SEAL, b its immediate
// checkpoint written late at a restart (mono_delta_ms −1, the trace of a new
// process), and the entry after b is the RESUME that continues this SEAL.
// Up to 1.8 the comment here said that no silence window can arise between a
// SEAL and its immediate checkpoint, "they are adjacent entries". That was
// wrong: a crash between the two leaves exactly that window, and the ledger's
// restart writes the checkpoint late, then RESUME (vector
// gap_late_seal_checkpoint) — reported as CONCEALED_SILENCE although the
// handover declares the pause.
//
// Condition 4 (from 1.9), the immediate checkpoint written late after a
// crash; ALL four parts must hold:
//
//	(a) a is critical and not a SEAL, b is a CHECKPOINT (6.1 binds a into its
//	    signed tree, so nothing can be missing between a and b);
//	(b) mono_delta_ms(b) = −1 — a writer that merely stalled writes ≥ 0 and
//	    stays CONCEALED_SILENCE (vector tamper_late_checkpoint_stalled);
//	(c) the entry after b is a RESTART chained at most 450,000 ms after b
//	    with downtime_ms_estimate −1 or ≥ Δ − 450,000;
//	(d) the entry after that is a GAP whose window covers the silence between
//	    a and b as in condition 1 (it is COVERED_GAP like every GAP).
//
// The narrow shape is the condition of 2026-09-29: a RESTART must not be
// able to conceal a deletion (spec 8.2, "Why condition 4").
func (r *run) silenceCovered(i int, delta int64) bool {
	n := len(r.entries)
	a, b := r.entries[i], r.entries[i+1]
	switch b.eventType {
	case "GAP": // condition 1
		return gapCovers(b, a, b)
	case "RESTART": // condition 2
		return true
	case "RESUME": // condition 3, first sentence
		return a.eventType == "CHECKPOINT" && i >= 1 && r.entries[i-1].eventType == "SEAL" &&
			b.pStr("sealed_entry_hash") == r.entries[i-1].storedHash
	case "CHECKPOINT":
		if b.monoDelta != -1 {
			return false // 3 (second sentence) and 4 (b) need the trace of a new process
		}
		if a.eventType == "SEAL" { // condition 3, second sentence: RESUME follows, or nothing
			return i+2 == n || (r.entries[i+2].eventType == "RESUME" &&
				r.entries[i+2].pStr("sealed_entry_hash") == a.storedHash)
		}
		if !criticalTypes[a.eventType] || i+3 >= n { // condition 4 (a)
			return false
		}
		c, d := r.entries[i+2], r.entries[i+3]
		if c.eventType != "RESTART" || unixMS(c.tsChained)-unixMS(b.tsChained) > silenceToleranceMS { // (c)
			return false
		}
		if dt := c.pInt("downtime_ms_estimate"); dt != -1 && dt < delta-silenceToleranceMS {
			return false
		}
		return d.eventType == "GAP" && gapCovers(d, a, b) // (d)
	}
	return false
}

// checkClock implements section 9.2 (mono_delta_ms plausibility), in whole
// milliseconds (spec 2, from 1.9): the wall-clock delta is the difference of
// the two instants each truncated to the millisecond — not the nanosecond
// difference truncated toward zero, which put 300,000.5 ms on the other side
// of the tolerance than verifier2 did.
func (r *run) checkClock() {
	for i := 1; i < len(r.entries); i++ {
		a, b := r.entries[i-1], r.entries[i]
		if b.monoDelta < 0 {
			continue // -1 = unknown, excluded from this check
		}
		dMS := unixMS(b.tsChained) - unixMS(a.tsChained)
		diff := dMS - b.monoDelta
		abs := diff
		if abs < 0 {
			abs = -abs
		}
		if abs <= clockToleranceMS {
			continue
		}
		if b.eventType == "CLOCK_JUMP" {
			// declared jump: jump_ms must explain the difference (sign and
			// magnitude, tolerance 300,000 ms)
			rem := diff - b.pInt("jump_ms")
			if rem < 0 {
				rem = -rem
			}
			if rem <= clockToleranceMS {
				continue // CLOCK_JUMP_NOTE is emitted separately
			}
		}
		r.add(ClsClockAnomaly, b.seq, fmt.Sprintf("wall-clock delta %d ms contradicts mono_delta_ms %d without a declaring CLOCK_JUMP", dMS, b.monoDelta))
	}
}

// checkImmediateCheckpoint implements section 6.2 trigger 3: after every entry
// of a critical type the immediately following entry MUST be that entry's
// checkpoint. The set of critical types is not invented here — criticalTypes
// mirrors registry event_types with "critical_checkpoint": true, which is the
// same set the spec names in 6.2 (GENESIS, GAP, MODE_CHANGE, SEAL, OVERSIGHT,
// KEY_ROTATION, CONTENT_DELETED, CONTENT_DISCLOSED, LEGAL_HOLD). Violation:
// MISSING_CHECKPOINT (exit 2).
//
// Only adjacency is judged here. Whether that checkpoint is itself sound
// (tree_size, signature, prev_checkpoint_hash) is decided by checkCheckpoints,
// so a broken checkpoint yields its own class instead of being double-counted.
//
// EDGE CASE — a critical entry as the LAST entry of the chain, with no
// following checkpoint at all (a bare terminal SEAL included). From spec 1.6
// this is NOT MISSING_CHECKPOINT. Spec 6.2 (last paragraph) decides it: no
// entry is missing between two present ones, rather the chain END is
// unanchored, and spec 8.6 gives exactly that its own status, "incomplete"
// (UNSEALED_END, exit 4, reported once by checkChainEnd). An honest writer
// that failed between the critical entry and its checkpoint leaves precisely
// this shape, and 8.6 forbids reporting an honest chain as "invalid". A
// critical entry followed by any OTHER entry stays MISSING_CHECKPOINT (exit
// 2): there an entry stands where the checkpoint belongs.
//
// Why this opens no new gap. Up to spec 1.5 this function reported the
// terminal case as MISSING_CHECKPOINT, and its reasoning was: otherwise a
// chain truncated directly after a critical entry would draw at most
// TRAILING_SILENCE (exit 1), and nothing inside the freshness window — a
// missing anchor would pass as an honest chain end. Under 1.6 that premise is
// gone: EVERY chain end that is not a SEAL + immediate checkpoint (+ receipts
// on it) is UNSEALED_END, exit 4, whichever entry it stops at. A truncation
// behind a critical entry is therefore exactly as visible as one behind a
// TICK — neither reads as "valid" (exit 0/1) any more — and the report names
// the last countersigned checkpoint for the comparison that settles it (8.6).
// The only chain end that reads as valid is a sealed one, and a SEAL without
// its checkpoint is by definition not sealed (8.6). checkChainEnd says in its
// detail when the last entry is a critical entry without its checkpoint, so
// the information the old finding carried is re-graded, not dropped.
//
// TRAILING_SILENCE (8.5) stays independent of both: it judges the AGE of the
// chain end, not its structure.
//
// Types unknown to this verifier (spec 10.6 R2) are deliberately NOT treated
// as critical: criticalTypes is the closed set of this version. That is the
// conservative direction — a future critical type is not checked for its
// checkpoint by an older verifier, and the UNKNOWN_ENTRY_TYPE finding says so.
func (r *run) checkImmediateCheckpoint() {
	n := len(r.entries)
	for i, e := range r.entries {
		if !criticalTypes[e.eventType] {
			continue
		}
		if i+1 >= n {
			// Terminal critical entry: the chain end is unanchored, status
			// "incomplete" (spec 6.2, 8.6) — checkChainEnd reports it.
			continue
		}
		nxt := r.entries[i+1]
		if nxt.eventType == "CHECKPOINT" {
			continue
		}
		r.add(ClsMissingCheckpoint, e.seq, fmt.Sprintf(
			"critical entry %s (seq %d) is not immediately followed by its checkpoint but by entry of type %s (seq %d)",
			e.eventType, e.seq, nxt.eventType, nxt.seq))
	}
}

// checkHandover implements section 8.4 (SEAL/RESUME).
func (r *run) checkHandover() {
	n := len(r.entries)
	sealForResume := map[int]bool{} // index of RESUME entries matched to a SEAL
	for i, e := range r.entries {
		if e.eventType != "SEAL" {
			continue
		}
		j := i + 1
		cpSeq := int64(0)
		if j < n && r.entries[j].eventType == "CHECKPOINT" {
			cpSeq = r.entries[j].seq // the SEAL's immediate checkpoint
			j++
		}
		// A SEAL lacking that checkpoint is deliberately NOT reported here:
		// 8.4 assigns the SEAL's missing immediate checkpoint to
		// MISSING_CHECKPOINT (checkImmediateCheckpoint; at the chain end the
		// status "incomplete", spec 6.2, 8.6) and reserves HANDOVER_BROKEN for
		// a missing RESUME although the chain continues, a wrong
		// sealed_entry_hash, and a different or additional entry between SEAL
		// and RESUME.
		//
		// Receipts countersigning the SEAL's immediate checkpoint are anchor
		// confirmations of the sealed state, not substantive entries, and may
		// trail a chain that ends with the SEAL. Between SEAL and RESUME they
		// are NOT tolerated: 8.4 rule 3 admits exactly one entry there and it
		// MUST be the checkpoint, so a receipt in that window is an additional
		// entry and stays HANDOVER_BROKEN.
		k := j
		for k < n && r.entries[k].eventType == "CHECKPOINT_RECEIPT" && r.entries[k].pInt("checkpoint_seq") == cpSeq {
			k++
		}
		if k >= n {
			j = k // receipts trail the end of the chain; no RESUME follows
		}
		if j >= n {
			// The chain ends with this SEAL (+ checkpoint + receipts on it):
			// no RESUME is missing, since nothing continues. From spec 1.6 this
			// is a regular closure WHATEVER the reason (8.4) — up to 1.5 only
			// decommission and key_loss closed a chain, and a chain sealed for
			// update or shutdown was HANDOVER_BROKEN. Whether the end is
			// actually sealed (the checkpoint present) or incomplete (a bare
			// SEAL) is not this function's question: checkChainEnd judges the
			// chain end once, for every kind of end alike (8.6).
			continue
		}
		nxt := r.entries[j]
		if nxt.eventType != "RESUME" {
			r.add(ClsHandoverBroken, nxt.seq, fmt.Sprintf("entry of type %s between SEAL (seq %d) and RESUME", nxt.eventType, e.seq))
			continue
		}
		if nxt.pStr("sealed_entry_hash") != e.storedHash {
			r.add(ClsHandoverBroken, nxt.seq, "RESUME sealed_entry_hash does not match the entry_hash of the SEAL entry")
		}
		sealForResume[j] = true
	}
	for i, e := range r.entries {
		if e.eventType == "RESUME" && !sealForResume[i] {
			r.add(ClsHandoverBroken, e.seq, "RESUME without a directly preceding SEAL (+ immediate checkpoint)")
		}
	}
}

// sealedEnd reports whether the chain end is sealed in the sense of spec 8.6:
// the last entries are a SEAL, directly its immediate checkpoint, then at most
// CHECKPOINT_RECEIPT entries whose checkpoint_seq names exactly that
// checkpoint. It returns the indices of the SEAL and of its checkpoint.
//
// Only the SHAPE is judged, as in checkImmediateCheckpoint: whether that
// checkpoint or those receipts are sound is decided by checkCheckpoints and
// checkReceipts, and a broken one draws its own exit-2 class. The SEAL's
// reason plays no part (8.6).
func (r *run) sealedEnd() (sealIdx, cpIdx int, ok bool) {
	n := len(r.entries)
	k := n - 1
	for k >= 0 && r.entries[k].eventType == "CHECKPOINT_RECEIPT" {
		k--
	}
	if k < 1 || r.entries[k].eventType != "CHECKPOINT" || r.entries[k-1].eventType != "SEAL" {
		return 0, 0, false
	}
	cpSeq := r.entries[k].seq
	for _, e := range r.entries[k+1:] {
		if e.pInt("checkpoint_seq") != cpSeq {
			// A trailing receipt on another checkpoint is not a confirmation
			// of the sealed state; the end is incomplete (and the receipt
			// between SEAL and the end is HANDOVER_BROKEN, checkHandover).
			return 0, 0, false
		}
	}
	return k - 1, k, true
}

// genesisLicenseNotice: spec 4.1 — a GENESIS of spec 1.7 or earlier whose
// license_id is not the licence commitment. From 1.8 such a GENESIS is a
// FORMAT_ERROR (checkGenesisLicense); before, the content was undefined, so
// the verifier can only say that the key MAY stand there.
func (r *run) genesisLicenseNotice() bool {
	if len(r.entries) == 0 || r.entries[0].eventType != "GENESIS" {
		return false
	}
	g := r.entries[0]
	sv := g.raw.Get("spec_version").Str
	if _, minor, _ := strings.Cut(sv, "."); minor == licenseCommitmentMinor || minorNewer(minor, licenseCommitmentMinor) {
		return false
	}
	lic := g.payload.Get("license_id")
	return lic == nil || !reHex64.MatchString(lic.Str)
}

// hasFormatError reports whether a FORMAT_ERROR is among the findings.
func (r *run) hasFormatError() bool {
	for _, f := range r.findings {
		if f.Class == ClsFormatError {
			return true
		}
	}
	return false
}

// checkChainEnd implements section 8.6: a chain is either SEALED or
// INCOMPLETE, and every incomplete chain carries the finding UNSEALED_END
// exactly once, at the seq of its last entry — also alongside findings of
// exit class 2 (the exit code then follows the precedence of 10.3).
//
// It runs after checkImmediateCheckpoint and checkHandover on purpose: those
// two judge the SEAL/RESUME structure INSIDE the chain (MISSING_CHECKPOINT,
// HANDOVER_BROKEN, exit 2) and leave the END to this function, so a terminal
// critical entry and a terminal bare SEAL are judged here once, not twice.
//
// A package that is a format error (exit 3) is not judged (8.6): the chain end
// of material that is not read as a chain says nothing. That includes the
// FORMAT_ERRORs that do not stop the run (first entry not GENESIS).
//
// "Incomplete" is no statement of manipulation: all entries present were
// checked; the package just does not prove that nothing came after its last
// entry. A running installation's export, a crash and a truncation look alike
// offline, which is why the finding names the last countersigned checkpoint
// and the comparison that tells them apart (8.6) — the one thing an auditor
// can do about it.
func (r *run) checkChainEnd() {
	n := len(r.entries)
	if n == 0 || r.hasFormatError() {
		return
	}
	last := r.entries[n-1]
	ce := &ChainEndStat{LastSeq: last.seq, LastTS: last.tsChainedS, LastType: last.eventType}
	r.chainEnd = ce
	if si, ci, ok := r.sealedEnd(); ok {
		seal := r.entries[si]
		ce.Status = "sealed"
		ce.SealSeq = seal.seq
		ce.SealTS = seal.tsChainedS
		ce.SealReason = seal.pStr("reason")
		ce.SealCheckpointSeq = r.entries[ci].seq
		return
	}
	ce.Status = "incomplete"
	ce.LastCriticalWithoutCheckpoint = criticalTypes[last.eventType]

	var b strings.Builder
	fmt.Fprintf(&b, "the chain ends with entry seq %d (%s, ts_chained %s), not with a SEAL + its immediate checkpoint (+ receipts on it): "+
		"the package does not prove that nothing came after it; an export from a running installation, a crash and a truncation look alike offline (spec 8.6)",
		last.seq, last.eventType, last.tsChainedS)
	if ce.LastCriticalWithoutCheckpoint {
		fmt.Fprintf(&b, "; the last entry is a critical entry (%s) without its immediate checkpoint, so the chain end is not anchored (spec 6.2)", last.eventType)
	}
	if lc := r.lastCountersigned; lc != nil {
		herkunft := "vendor key established by the auditor's trust anchor"
		if !lc.KeyEstablished {
			herkunft = "vendor key NOT established by a trust anchor of the auditor (spec 7.1)"
		}
		fmt.Fprintf(&b, "; last countersigned checkpoint in this package: checkpoint_seq %d, tree_size %d, merkle_root %s, server_ts %s (receipt seq %d, server_key_id %s, %s)",
			lc.CheckpointSeq, lc.TreeSize, lc.MerkleRoot, lc.ServerTS, lc.ReceiptSeq, lc.ServerKeyID, herkunft)
	} else {
		b.WriteString("; last countersigned checkpoint: none in this package")
	}
	// No angle brackets in the detail: the JSON output would escape them as unicode sequences.
	// Spec 8.6 (1.9): the root to ask for is the most recent one countersigned
	// BEFORE the package was requested — a later one lies beyond the end of
	// the package and would contradict even an honest one.
	fmt.Fprintf(&b, "; comparison: fetch the vendor's anchor history for chain_id %s (heartbeat spec 9.7) and re-run with every root in it recorded before this package was requested, "+
		"at least the most recent countersigned one (never a later one: it lies beyond the end of the package), as expected root "+
		"(--expect-root TREE_SIZE:ROOT, or --expect-root ROOT to match any prefix); "+
		"a package missing entries the vendor had countersigned by then yields MERKLE_INCONSISTENT", r.man.chainID)
	r.add(ClsUnsealedEnd, last.seq, b.String())
}

// checkFreshness implements section 8.5 (trailing silence), in whole
// milliseconds (spec 2, from 1.9): now − last > window, compared as integers.
// time.Duration's Sub saturated at about ±292 years; unixMS does not.
func (r *run) checkFreshness() {
	if len(r.entries) == 0 {
		return
	}
	window := r.opt.Freshness
	if window == 0 {
		window = defaultFreshnessH * time.Hour
	}
	last := r.entries[len(r.entries)-1]
	if unixMS(r.now)-unixMS(last.tsChained) > window.Milliseconds() {
		r.add(ClsTrailingSilence, last.seq, fmt.Sprintf("last entry at %s is older than the freshness window (%s) at verification time %s", last.tsChainedS, window, r.now.UTC().Format(time.RFC3339)))
	}
}

// contentNameRe is the name grammar of a presentation file (spec 10.1,
// "Presented plaintexts", from 1.9): content/<n>.salts.json,
// content/<n>.request, content/<n>.response with n = [1-9][0-9]*.
var contentNameRe = regexp.MustCompile(`^content/([1-9][0-9]*)\.(salts\.json|request|response)$`)

// contentParts are the two plaintext parts of an AI_CALL, in report order.
var contentParts = []string{"request", "response"}

// praesentation gathers the files of one presentation content/<n>.*.
type praesentation struct {
	n     string            // the digits of the file names
	salts string            // name of the salt file, "" if absent
	plain map[string]string // part -> name of the plaintext file
}

// checkContent verifies deliberately presented plaintexts against the chained
// commitments (spec 9.1) in the layout of spec 10.1 (from 1.9):
//
//   - the presentation for the AI_CALL with seq n is content/<n>.salts.json
//     plus content/<n>.request and/or content/<n>.response;
//   - the salt file is I-JSON with exactly seq (= n), request_salt and
//     response_salt (hex64, present exactly when the matching plaintext
//     is), and optionally vault_ref (a string, not evaluated);
//   - for every presented part entry n is an AI_CALL with a non-null
//     <part>_commitment, and HMAC-SHA-256(salt, plaintext) equals it.
//
// Every other file under content/ — another name (a leading zero included), a
// file in a subdirectory, a plaintext without a salt file, a salt file without
// a plaintext, a non-conforming salt file — is CONTENT_MISMATCH, once per
// file: no presented file goes unchecked (9.1). A plaintext whose salt file
// does not conform cannot be checked either and is CONTENT_MISMATCH as well.
//
// Up to 1.8 the check was driven by the plaintext names alone: a salt file
// without a plaintext, a file of another name and the salt file's seq were
// never looked at, and verifier2 (driven by the salt files) skipped a
// plaintext without a salt silently — the same tampered plaintext passed one
// verifier and failed the other.
func (r *run) checkContent() {
	bySeq := map[int64]*entry{}
	for _, e := range r.entries {
		bySeq[e.seq] = e
	}
	gruppen := map[string]*praesentation{}
	var reihe []*praesentation
	for _, name := range r.fs.List("content") {
		m := contentNameRe.FindStringSubmatch(name)
		if m == nil {
			r.add(ClsContentMismatch, 0, fmt.Sprintf("%s is no presentation file: under content/ only content/N.salts.json, content/N.request and content/N.response are defined, N without leading zeros and no subdirectory (spec 10.1)", name))
			continue
		}
		g := gruppen[m[1]]
		if g == nil {
			g = &praesentation{n: m[1], plain: map[string]string{}}
			gruppen[m[1]] = g
			reihe = append(reihe, g)
		}
		if m[2] == "salts.json" {
			g.salts = name
		} else {
			g.plain[m[2]] = name
		}
	}
	// In seq order: a longer digit string is the larger number (no leading zeros).
	sort.Slice(reihe, func(i, j int) bool {
		if len(reihe[i].n) != len(reihe[j].n) {
			return len(reihe[i].n) < len(reihe[j].n)
		}
		return reihe[i].n < reihe[j].n
	})
	for _, g := range reihe {
		seq, err := strconv.ParseInt(g.n, 10, 64)
		if err != nil {
			seq = 0 // beyond int64: no entry can carry it
		}
		if g.salts == "" {
			for _, part := range contentParts {
				if name, ok := g.plain[part]; ok {
					r.add(ClsContentMismatch, seq, fmt.Sprintf("%s: presented %s plaintext without its salt file content/%s.salts.json, so it cannot be checked (spec 9.1, 10.1)", name, part, g.n))
				}
			}
			continue
		}
		salts, why := r.readSaltFile(g, seq)
		if why != "" {
			r.add(ClsContentMismatch, seq, fmt.Sprintf("%s: %s (spec 10.1)", g.salts, why))
			for _, part := range contentParts {
				if name, ok := g.plain[part]; ok {
					r.add(ClsContentMismatch, seq, fmt.Sprintf("%s: presented %s plaintext cannot be checked: its salt file %s does not conform (spec 9.1, 10.1)", name, part, g.salts))
				}
			}
			continue
		}
		if len(g.plain) == 0 {
			r.add(ClsContentMismatch, seq, fmt.Sprintf("%s: salt file without a presented plaintext (spec 10.1)", g.salts))
			continue
		}
		for _, part := range contentParts {
			name, ok := g.plain[part]
			if !ok {
				continue
			}
			e := bySeq[seq]
			if e == nil || e.eventType != "AI_CALL" {
				r.add(ClsContentMismatch, seq, fmt.Sprintf("%s: presented %s plaintext but seq %s is not an AI_CALL entry", name, part, g.n))
				continue
			}
			commitment := e.pStr(part + "_commitment")
			if commitment == "" {
				r.add(ClsContentMismatch, seq, fmt.Sprintf("%s: presented %s plaintext but the entry carries no %s_commitment", name, part, part))
				continue
			}
			plaintext, err := r.fs.ReadFile(name)
			if err != nil {
				r.add(ClsContentMismatch, seq, fmt.Sprintf("cannot read %s", name))
				continue
			}
			mac := hmac.New(sha256.New, salts[part])
			mac.Write(plaintext)
			if hex.EncodeToString(mac.Sum(nil)) != commitment {
				r.add(ClsContentMismatch, seq, fmt.Sprintf("%s: HMAC-SHA-256 of presented %s plaintext does not match the chained commitment", name, part))
			}
		}
	}
}

// readSaltFile reads and judges the salt file of presentation g (spec 10.1)
// and returns the salt per presented part, or in why the reason it does not
// conform. The number rule of spec 2 is already enforced for salt files
// (checkPackageNumbers: FORMAT_ERROR); what remains here is CONTENT_MISMATCH.
func (r *run) readSaltFile(g *praesentation, seq int64) (map[string][]byte, string) {
	b, err := r.fs.ReadFile(g.salts)
	if err != nil {
		return nil, "cannot be read"
	}
	v, err := jcs.Parse(b)
	if err != nil {
		return nil, fmt.Sprintf("salt file is not I-JSON: %v", err)
	}
	if v.Kind != jcs.KindObject {
		return nil, "salt file is not a JSON object"
	}
	for _, m := range v.Members {
		switch m.Key {
		case "seq", "request_salt", "response_salt", "vault_ref":
		default:
			return nil, fmt.Sprintf("salt file carries the undefined member %q (defined: seq, request_salt, response_salt, vault_ref)", m.Key)
		}
	}
	sv := v.Get("seq")
	if sv == nil || sv.Kind != jcs.KindInt {
		return nil, "salt file lacks the member seq (an integer)"
	}
	if sv.Int != seq || strconv.FormatInt(seq, 10) != g.n {
		return nil, fmt.Sprintf("salt file declares seq %d, its name says %s", sv.Int, g.n)
	}
	if vr := v.Get("vault_ref"); vr != nil && vr.Kind != jcs.KindString {
		return nil, "vault_ref is not a string"
	}
	salts := map[string][]byte{}
	for _, part := range contentParts {
		f := v.Get(part + "_salt")
		_, presented := g.plain[part]
		switch {
		case f == nil && presented:
			return nil, fmt.Sprintf("salt file lacks %s_salt, but content/%s.%s is presented", part, g.n, part)
		case f != nil && !presented:
			return nil, fmt.Sprintf("salt file carries %s_salt, but content/%s.%s is not presented", part, g.n, part)
		case f == nil:
			continue
		}
		if f.Kind != jcs.KindString || !reHex64.MatchString(f.Str) {
			return nil, fmt.Sprintf("%s_salt is not 64 lowercase hex characters (hex64)", part)
		}
		salts[part], _ = hex.DecodeString(f.Str)
	}
	return salts, ""
}

// checkReports verifies presented report files against REPORT_ISSUED hashes.
func (r *run) checkReports() {
	hashes := map[string]bool{}
	for _, e := range r.entries {
		if e.eventType != "REPORT_ISSUED" {
			continue
		}
		hashes[e.pStr("html_hash")] = true
		if h := e.pStr("pdf_hash"); h != "" {
			hashes[h] = true
		}
	}
	for _, name := range r.fs.List("reports") {
		b, err := r.fs.ReadFile(name)
		if err != nil {
			r.add(ClsReportMismatch, 0, fmt.Sprintf("cannot read %s", name))
			continue
		}
		sum := sha256.Sum256(b)
		if !hashes[hex.EncodeToString(sum[:])] {
			r.add(ClsReportMismatch, 0, fmt.Sprintf("SHA-256 of %s appears in no REPORT_ISSUED entry", name))
		}
	}
}

// finish computes exit code and stats.
//
// The exit code follows the precedence of spec 10.3 (exitPrecedence), not the
// numeric maximum: a FORMAT_ERROR decides at once (3); otherwise any exit-2
// finding makes 2, then any exit-4 finding (UNSEALED_END) 4, then any exit-1
// finding 1, else 0.
func (r *run) finish() Result {
	exit := 0
	present := map[int]bool{}
	for _, f := range r.findings {
		c := classExit[f.Class]
		if c == 3 {
			present = map[int]bool{3: true} // package unreadable: nothing else counts
			break
		}
		present[c] = true
	}
	for _, c := range exitPrecedence {
		if present[c] {
			exit = c
			break
		}
	}
	st := Stats{NowSource: r.nowSource}
	if r.nowKnown {
		// Not known only when the requested check time could not be
		// determined (spec 10.8) or the package could not be opened: then
		// "now" stays empty rather than naming a time nothing was checked
		// against. Before 1.1.0 this asked r.now.IsZero(), and a check time
		// of 0001-01-01T00:00:00Z from verify_args.json read as "not
		// determined" in a run without FORMAT_ERROR.
		st.Now = r.now.UTC().Format(time.RFC3339)
	}
	if r.man != nil {
		st.ChainID = r.man.chainID
		st.TreeSize = r.man.treeSize
		st.Segments = int64(len(r.man.segments))
	}
	st.Entries = int64(len(r.entries))
	for _, e := range r.entries {
		switch e.eventType {
		case "CHECKPOINT":
			st.Checkpoints++
		case "CHECKPOINT_RECEIPT":
			st.Receipts++
		}
	}
	st.TimeAnchors = r.timeAnchors
	st.TimeAnchorsVerified = r.timeAnchorsVerified
	st.TimeAnchorDetails = r.timeAnchorDetails
	st.ReceiptsEstablished = r.receiptsEstablished
	if vt := r.vendor; vt != nil && vt.list != nil {
		st.VendorList = &VendorListStat{Version: vt.listVer, Issued: vt.listIssued, Root: vt.listRoot}
	}
	if len(r.entries) > 0 {
		st.FirstTS = r.entries[0].tsChainedS
		st.LastTS = r.entries[len(r.entries)-1].tsChainedS
	}
	// Both only where the chain end was judged: a format error (exit 3) is
	// not (spec 8.6), and a countersignature named next to "not judged"
	// would read as a statement about the chain end all the same.
	if r.chainEnd != nil && exit != 3 {
		st.ChainEnd = r.chainEnd
		st.LastCountersigned = r.lastCountersigned
	}
	if exit != 3 {
		st.LegalHolds = r.legalHolds
		st.GenesisLicenseNotCommitment = r.genesisLicenseNotice()
		// Spec 8.6 and 11.2 (from 1.9): both for every package that is not a
		// format error. A package that is not exit 3 has passed stages 1-4,
		// so it has entries and the window was measured.
		st.Completeness = r.completeness()
		st.ResidualWindow = r.residual
		// Spec 11.2 (from 1.10): stated with the residual window, an empty
		// list when no stretch exceeds the cadence.
		st.UnanchoredStretches = r.stretches
		if st.UnanchoredStretches == nil {
			st.UnanchoredStretches = []UnanchoredStretchStat{}
		}
		st.KeyRoles = r.finishKeyRoles()
		st.VendorLog = r.finishVendorLog()
		// Step 15 of 10.5: after the exit code, the affiliation (H12) and
		// the report objects (H13); neither changes the exit code.
		st.AnchorHistory = r.anchorHistoryStat()
		st.Affiliation = r.affiliationStat()
	}
	// After the exit code and the report objects: the evidence level
	// (10.5 stage 5, step 15; 10.9). It reads the findings and changes none.
	st.EvidenceLevel = r.evidenceLevel(exit, &st)
	if r.findings == nil {
		r.findings = []Finding{}
	}
	return Result{
		Valid:    exit == 0 || exit == 1 || exit == 4,
		Status:   statusFor[exit],
		ExitCode: exit,
		Findings: r.findings,
		Stats:    st,
	}
}
