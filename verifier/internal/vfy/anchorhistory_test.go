package vfy

// The anchor history as an input of the auditor (format spec 8.8, from
// edition 1.10): steps H1 to H13 of 8.8.4, the classification of 8.8.5 and
// the report object anchor_history of 10.10.2, on a generated chain with
// pages built here from the specification (heartbeat spec 9.7) and signed by
// a statements key pinned with --vendor-statement-key. Keys come from fixed
// seeds (keyFromSeed); none is a key of the test corpus.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
)

// The chain of the history tests: validSealedChain, but with times after the
// cut-off date BL (H10) and in the form YYYY-MM-DDThh:mm:ss.sssZ. Receipts:
// tree_size 1 at 08:00:02.000, tree_size 6 at 08:11:04.000; N = 10.
const (
	ahDay      = "2026-10-10"
	ahR        = "2026-10-10T08:30:00.000Z" // request time; R - W_h = 08:15:00.000
	ahPageTS   = "2026-10-10T08:31:00.000Z" // a fresh page
	ahKnown    = "2026-01-01T00:00:00.000Z"
	ahStmtID   = "st-1"
	ahStmtSeed = 0x51
)

func ahTS(clock string) string { return ahDay + "T" + clock + "Z" }

// ahWorld is a run with an anchor history.
type ahWorld struct {
	t      *testing.T
	g      *gen
	files  [][]byte
	r      string // --requested-at; "" none
	now    time.Time
	noPin  bool // without the countersigning pin of the generator
	opts   func(o *Options)
	expect []string
}

func ahChain(t *testing.T) *gen {
	g := newGen(t)
	g.now = time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC)
	g.tsLayout = "2006-01-02T15:04:05.000Z07:00"
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.tick(5 * time.Minute)
	g.tick(5 * time.Minute)
	g.aiCall(time.Minute, nil, nil)
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.seal("shutdown")
	return g
}

func newAHWorld(t *testing.T) *ahWorld {
	return &ahWorld{t: t, g: ahChain(t), r: ahR, now: time.Date(2026, 10, 10, 9, 30, 0, 0, time.UTC)}
}

const ahApp = "1a2b3c4d-5e6f-4a01-9b02-c3d4e5f60718" // GENESIS.appliance_id of the generator

// owner is the owner commitment of the chain's device key (heartbeat spec 9.7).
func (w *ahWorld) owner() string { return ownerCommitment(ahApp, w.g.chainID, w.g.devPub["dev-1"]) }

func (w *ahWorld) root(t int64) string { return w.g.merkleRootAt(t) }

// rt is an element of roots.
func rt(t int64, root, as, ts string) map[string]any {
	return map[string]any{"tree_size": t, "merkle_root": root, "recorded_as": as, "server_ts": ts}
}

func other(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// pg describes a page (heartbeat spec 9.7, kind v2); zero values take the
// defaults of the honest page of the world.
type pg struct {
	chain     string
	owner     []any
	pred      any
	succ      any
	ref       int64 // -1: the largest recorded tree_size
	roots     []map[string]any
	noRoots   bool
	forks     []any
	omitted   int64
	since     int64
	next      any
	truncated bool
	known     any
	periods   []any
	ts        string
	edit      func(m map[string]any)
}

// honestRoots are the chain's two receipts, recorded as countersigned.
func (w *ahWorld) honestRoots() []map[string]any {
	return []map[string]any{rt(1, w.root(1), "countersigned", ahTS("08:00:02.000")), rt(6, w.root(6), "countersigned", ahTS("08:11:04.000"))}
}

// statement builds the content of a page; the roots are put into the order
// of page rule 3.
func (w *ahWorld) statement(p pg) map[string]any {
	if p.chain == "" {
		p.chain = w.g.chainID
	}
	if p.owner == nil {
		p.owner = []any{ownerCommitment(ahApp, p.chain, w.g.devPub["dev-1"])}
	}
	roots := p.roots
	if roots == nil && !p.noRoots {
		roots = w.honestRoots()
	}
	sort.SliceStable(roots, func(i, j int) bool {
		a, b := roots[i], roots[j]
		if a["tree_size"].(int64) != b["tree_size"].(int64) {
			return a["tree_size"].(int64) < b["tree_size"].(int64)
		}
		ta, _ := parseRFC3339(a["server_ts"].(string))
		tb, _ := parseRFC3339(b["server_ts"].(string))
		if !ta.Equal(tb) {
			return ta.Before(tb)
		}
		if a["recorded_as"] != b["recorded_as"] {
			return recordedAsOrder[a["recorded_as"].(string)] < recordedAsOrder[b["recorded_as"].(string)]
		}
		return a["merkle_root"].(string) < b["merkle_root"].(string)
	})
	ref := p.ref
	if ref <= 0 {
		for _, x := range roots {
			if x["recorded_as"] != "reported" && x["tree_size"].(int64) > ref {
				ref = x["tree_size"].(int64)
			}
		}
	}
	if p.ts == "" {
		p.ts = ahPageTS
	}
	var known any = ahKnown
	if p.known != nil {
		known = p.known
		if p.known == "null" {
			known = nil
		}
	}
	rs := []any{}
	for _, x := range roots {
		rs = append(rs, x)
	}
	forks := p.forks
	if forks == nil {
		forks = []any{}
	}
	periods := p.periods
	if periods == nil {
		periods = []any{}
	}
	m := map[string]any{
		"kind": HistoryKindV2, "chain_id": p.chain, "owner_keys": p.owner, "predecessor": p.pred, "successor": p.succ,
		"reference_tree_size": ref, "roots": rs, "forks": forks, "forks_omitted": p.omitted, "since_tree_size": p.since,
		"next_since_tree_size": p.next, "truncated": p.truncated,
		"affiliation": map[string]any{"known_since": known, "periods": periods}, "server_ts": p.ts,
	}
	if p.edit != nil {
		p.edit(m)
	}
	return m
}

func ahStmtKey() (ed25519.PrivateKey, string) { return keyFromSeed(ahStmtSeed) }

// pageFile is the body of a page: statement_jcs, server_key_id,
// server_signature and the unsigned reading copy.
func pageFile(t *testing.T, sj string, pairs ...[2]string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"statement_jcs": sj, "server_key_id": pairs[0][0], "server_signature": pairs[0][1], "statement": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sign(priv ed25519.PrivateKey, sj string) string {
	return hex.EncodeToString(ed25519.Sign(priv, []byte(sj)))
}

// add signs a page with the pinned statements key and adds it as a file.
func (w *ahWorld) add(p pg) string {
	sj := string(canonGo(w.t, w.statement(p)))
	priv, _ := ahStmtKey()
	w.files = append(w.files, pageFile(w.t, sj, [2]string{ahStmtID, sign(priv, sj)}))
	return sj
}

func (w *ahWorld) run() Result {
	w.t.Helper()
	dir := w.g.writePkg()
	opt := Options{Now: w.now}
	if !w.noPin {
		opt = genAnker(opt)
	}
	_, pub := ahStmtKey()
	if err := opt.AddVendorStatementKey(ahStmtID + "=" + pub); err != nil {
		w.t.Fatal(err)
	}
	for _, f := range w.files {
		if err := opt.AddAnchorHistory(f); err != nil {
			w.t.Fatalf("--anchor-history: %v", err)
		}
	}
	if w.r != "" {
		if err := opt.SetRequestedAt(w.r); err != nil {
			w.t.Fatal(err)
		}
	}
	for _, x := range w.expect {
		er, err := ParseExpectedRoot(x)
		if err != nil {
			w.t.Fatal(err)
		}
		opt.ExpectRoots = append(opt.ExpectRoots, er)
	}
	if w.opts != nil {
		w.opts(&opt)
	}
	if err := opt.FinishAuditorInputs(w.now); err != nil {
		w.t.Fatalf("unusable invocation: %v", err)
	}
	return Verify(dir, opt)
}

// TestHistoryReferenceValues recomputes the reference values of heartbeat
// spec 9.7 (owner commitment) and format spec 8.8.2 (the page of the vector
// valid_sealed_export: 776 characters and its SHA-256).
func TestHistoryReferenceValues(t *testing.T) {
	c := "3cef4d7e-4d65-41d6-912d-90d51fda8982"
	oc := ownerCommitment("de431f78-75fd-49ae-b4bf-1cb543b635d1", c, "da78e8f07243904c3669c59bded1b62bc1ad39b520d17d0834f4f77aa892073b")
	if oc != "d0184bb5619fab41289c330c51c12d3353538b46f852fcfb31ef9b2f83a92a28" {
		t.Fatalf("owner commitment %s", oc)
	}
	// The two receipts of the vector, read from its segment.
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "testvectors", "valid_sealed_export", "segments", "chain-000001.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var roots []any
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		v, err := jcs.Parse([]byte(l))
		if err != nil {
			t.Fatal(err)
		}
		if v.Get("event_type").Str == "CHECKPOINT_RECEIPT" {
			p := v.Get("payload")
			roots = append(roots, map[string]any{"tree_size": p.Get("tree_size").Int, "merkle_root": p.Get("merkle_root").Str, "recorded_as": "countersigned", "server_ts": p.Get("server_ts").Str})
		}
	}
	if len(roots) != 2 || roots[0].(map[string]any)["server_ts"] != "2026-01-01T00:30:01.000Z" || roots[1].(map[string]any)["tree_size"] != int64(28) {
		t.Fatalf("receipts of valid_sealed_export: %v", roots)
	}
	m := map[string]any{"kind": HistoryKindV2, "chain_id": c, "owner_keys": []any{oc}, "predecessor": nil, "successor": nil, "reference_tree_size": int64(28),
		"roots": roots, "forks": []any{}, "forks_omitted": int64(0), "since_tree_size": int64(0), "next_since_tree_size": nil, "truncated": false,
		"affiliation": map[string]any{"known_since": "2025-12-01T00:00:00.000Z", "periods": []any{}}, "server_ts": "2026-01-01T01:02:00.000Z"}
	sj := canonGo(t, m)
	sum := sha256.Sum256(sj)
	if len(sj) != 776 || hex.EncodeToString(sum[:]) != "6fe4cc5f74c2539468594843916f9cfa1e528934d3f812202f04969932ca175b" {
		t.Fatalf("statement_jcs %d characters, SHA-256 %x", len(sj), sum)
	}
	v, _ := jcs.Parse(sj)
	if c, why := readHistoryContent(v); c == nil {
		t.Fatalf("the reference page breaks a page rule: %s", why)
	}
}

// TestHistoryHonest: a fresh complete page that lists the chain's receipts
// changes no result (exit 0) and establishes the completeness from the
// history up to the largest found root (8.8.4 H4, H6, H10, H11; 8.6
// sources).
func TestHistoryHonest(t *testing.T) {
	w := newAHWorld(t)
	w.add(pg{})
	res := w.run()
	wantClasses(t, res, 0)
	ah := res.Stats.AnchorHistory
	if ah == nil || ah.Status != HistoryChecked || ah.RequestedAt == nil || *ah.RequestedAt != ahR || ah.Files != 1 {
		t.Fatalf("anchor_history %+v", ah)
	}
	if ah.Pages != (HistoryPagesStat{Supplied: 1, Distinct: 1, UsedFresh: 1}) || len(ah.PageReasons) != 0 {
		t.Errorf("pages %+v %v", ah.Pages, ah.PageReasons)
	}
	if len(ah.Keys) != 1 || ah.Keys[0] != (HistoryKeyStat{KeyID: ahStmtID, Source: SourcePinned}) {
		t.Errorf("keys %+v", ah.Keys)
	}
	if ah.Owner == nil || *ah.Owner != "matches" || ah.Coverage.Status != "complete" || len(ah.Coverage.Gaps) != 0 {
		t.Errorf("owner %v coverage %+v", ah.Owner, ah.Coverage)
	}
	if ah.Issued.First == nil || *ah.Issued.First != ahPageTS || *ah.Issued.Last != ahPageTS || ah.ReferenceTreeSize == nil || *ah.ReferenceTreeSize != 6 {
		t.Errorf("issued %+v reference %v", ah.Issued, ah.ReferenceTreeSize)
	}
	if ah.Roots != (HistoryRootsStat{Distinct: 2, Found: 2}) {
		t.Errorf("roots %+v", ah.Roots)
	}
	if ah.Receipts != (HistoryReceiptsStat{Checked: 2, InHistory: 2}) {
		t.Errorf("receipts %+v", ah.Receipts)
	}
	if ah.Completeness.Status != "established" || ah.Completeness.Reason != nil || ah.Completeness.UpToTreeSize == nil || *ah.Completeness.UpToTreeSize != 6 {
		t.Errorf("completeness %+v", ah.Completeness)
	}
	if len(ah.Notes) != 0 || len(ah.Reasons.Unverified)+len(ah.Reasons.Defective)+len(ah.Reasons.Contradiction)+len(ah.Reasons.Fork) != 0 {
		t.Errorf("notes %v reasons %+v", ah.Notes, ah.Reasons)
	}
	c := res.Stats.Completeness
	if c == nil || c.Status != "established" || *c.UpToTreeSize != 6 || strings.Join(c.Sources, ",") != "anchor_history" {
		t.Errorf("completeness (8.6) %+v", c)
	}
	af := res.Stats.Affiliation
	if af == nil || af.Status != AffNotAffiliated || af.Reason != nil || af.Span == nil || af.Span.From != ahTS("08:00:02.000") || af.Span.To != ahR {
		t.Fatalf("affiliation %+v", af)
	}
	if af.AsOf == nil || *af.AsOf != ahPageTS || af.KnownSince == nil || *af.KnownSince != ahKnown || af.StatedBy == nil || *af.StatedBy != (AffStatedBy{ahStmtID, AffSourcePinned}) {
		t.Errorf("affiliation as_of %v known_since %v stated_by %v", af.AsOf, af.KnownSince, af.StatedBy)
	}
	if *af.ReceiptsTotal != 2 || *af.ReceiptsInPeriods != 0 || *af.ReceiptsAfterStatement != 0 || af.Contradictory {
		t.Errorf("affiliation counts %d %d %d", *af.ReceiptsTotal, *af.ReceiptsInPeriods, *af.ReceiptsAfterStatement)
	}
	// An auditor root and a history root of the same pair are one expected
	// root with both sources (10.8).
	w2 := newAHWorld(t)
	w2.add(pg{})
	w2.expect = []string{fmt.Sprintf("6:%s", w2.root(6))}
	res2 := w2.run()
	wantClasses(t, res2, 0)
	if c := res2.Stats.Completeness; strings.Join(c.Sources, ",") != "auditor,anchor_history" {
		t.Errorf("sources %v", c.Sources)
	}
}

// TestHistoryClassification follows the table of format spec 8.8.5 with its
// band of 15 minutes before R: only a root recorded (countersigned or gap
// witness) before R - W_h that the package contradicts or lacks is
// MERKLE_INCONSISTENT (exit 2); a root that is only reported never is.
func TestHistoryClassification(t *testing.T) {
	differ := other("a second history")
	cases := []struct {
		why     string
		roots   []map[string]any
		noR     bool
		expect  []string
		exit    int
		classes []string
		fork    []string
		notes   []string
		count   func(HistoryRootsStat) bool
		mi      int
	}{
		{why: "t <= N, recorded at R - W_h - 1 ms: MERKLE_INCONSISTENT", roots: []map[string]any{rt(3, differ, "countersigned", ahTS("08:14:59.999"))},
			exit: 2, classes: []string{ClsMerkleInconsistent}, mi: 1, count: func(s HistoryRootsStat) bool { return s.DifferingBeforeRequest == 1 }},
		{why: "t <= N, recorded at R - W_h (the boundary belongs to the band): ANCHOR_HISTORY_FORK", roots: []map[string]any{rt(3, differ, "countersigned", ahTS("08:15:00.000"))},
			exit: 1, classes: []string{ClsHistoryFork}, fork: []string{"history_root_differs"}, count: func(s HistoryRootsStat) bool { return s.DifferingAfterRequest == 1 }},
		{why: "t <= N, gap witness before the band: MERKLE_INCONSISTENT", roots: []map[string]any{rt(3, differ, "gap_witness", ahTS("08:05:00.000"))},
			exit: 2, classes: []string{ClsMerkleInconsistent}, mi: 1},
		{why: "t <= N, only reported before the band: never exit 2", roots: []map[string]any{rt(3, differ, "reported", ahTS("08:05:00.000"))},
			exit: 1, classes: []string{ClsHistoryFork}, fork: []string{"history_root_differs"}, count: func(s HistoryRootsStat) bool { return s.DifferingBeforeRequest == 1 }},
		{why: "a reported recording sets e only for a root that is only reported", roots: []map[string]any{rt(3, differ, "reported", ahTS("08:01:00.000")), rt(3, differ, "countersigned", ahTS("08:20:00.000"))},
			exit: 1, classes: []string{ClsHistoryFork}, fork: []string{"history_root_differs"}},
		{why: "t > N, recorded before the band: MERKLE_INCONSISTENT with note", roots: []map[string]any{rt(11, differ, "countersigned", ahTS("08:14:59.999"))},
			exit: 2, classes: []string{ClsMerkleInconsistent}, mi: 1, notes: []string{"package_ended_before_request"}, count: func(s HistoryRootsStat) bool { return s.BeyondPackageBeforeRequest == 1 }},
		{why: "t > N, only reported before the band: ANCHOR_HISTORY_FORK", roots: []map[string]any{rt(11, differ, "reported", ahTS("08:14:59.999"))},
			exit: 1, classes: []string{ClsHistoryFork}, fork: []string{"reported_root_beyond_package"}, count: func(s HistoryRootsStat) bool { return s.BeyondPackageBeforeRequest == 1 }},
		{why: "t > N in the band: no finding", roots: []map[string]any{rt(11, differ, "countersigned", ahTS("08:15:00.000"))},
			exit: 0, notes: []string{"recent_roots_not_found"}, count: func(s HistoryRootsStat) bool { return s.BeyondPackageRecent == 1 }},
		{why: "t > N at R: no finding", roots: []map[string]any{rt(11, differ, "countersigned", ahTS("08:30:00.000"))},
			exit: 0, count: func(s HistoryRootsStat) bool { return s.BeyondPackageAfterRequest == 1 }},
		{why: "without R, t <= N recorded early: ANCHOR_HISTORY_FORK", noR: true, roots: []map[string]any{rt(3, differ, "countersigned", ahTS("08:01:00.000"))},
			exit: 1, classes: []string{ClsHistoryFork}, fork: []string{"history_root_differs"}, count: func(s HistoryRootsStat) bool { return s.DifferingAfterRequest == 1 }},
		{why: "without R, t > N: counted, not judged", noR: true, roots: []map[string]any{rt(11, differ, "countersigned", ahTS("08:01:00.000"))},
			exit: 0, notes: []string{"no_request_time"}, count: func(s HistoryRootsStat) bool { return s.BeyondPackageUnjudged == 1 }},
		{why: "a pair that also carries the source auditor follows 10.8: one finding", roots: []map[string]any{rt(3, differ, "countersigned", ahTS("08:20:00.000"))},
			expect: []string{"3:" + differ}, exit: 2, classes: []string{ClsMerkleInconsistent}, mi: 1},
	}
	for _, f := range cases {
		t.Run(f.why, func(t *testing.T) {
			w := newAHWorld(t)
			if f.noR {
				w.r = ""
			}
			w.expect = f.expect
			w.add(pg{roots: append(w.honestRoots(), f.roots...)})
			res := w.run()
			wantClasses(t, res, f.exit, f.classes...)
			if got := countClass(res, ClsMerkleInconsistent); got != f.mi {
				t.Errorf("%d MERKLE_INCONSISTENT, want %d", got, f.mi)
			}
			ah := res.Stats.AnchorHistory
			if strings.Join(ah.Reasons.Fork, ",") != strings.Join(f.fork, ",") {
				t.Errorf("reasons.fork %v, want %v", ah.Reasons.Fork, f.fork)
			}
			if strings.Join(ah.Notes, ",") != strings.Join(f.notes, ",") {
				t.Errorf("notes %v, want %v", ah.Notes, f.notes)
			}
			if f.count != nil && !f.count(ah.Roots) {
				t.Errorf("roots %+v", ah.Roots)
			}
			if ah.Roots.Found != 2 {
				t.Errorf("found %d", ah.Roots.Found)
			}
		})
	}
}

// ahCheck is what a case of the history tests expects.
type ahCheck struct {
	exit    int
	classes []string
	reasons map[string][]string // class -> reasons in anchor_history.reasons
	pageRs  []string            // anchor_history.page_reasons
	compl   string              // completeness.status/reason, e.g. "not_established/no_usable_page"
	aff     string              // affiliation.status/reason
	notes   []string
	check   func(t *testing.T, res Result)
}

func (c ahCheck) verify(t *testing.T, res Result) {
	t.Helper()
	wantClasses(t, res, c.exit, c.classes...)
	ah := res.Stats.AnchorHistory
	if ah == nil {
		t.Fatal("anchor_history missing")
	}
	got := map[string][]string{ClsHistoryUnverified: ah.Reasons.Unverified, ClsHistoryDefective: ah.Reasons.Defective,
		ClsHistoryContradict: ah.Reasons.Contradiction, ClsHistoryFork: ah.Reasons.Fork}
	for cls, list := range got {
		if strings.Join(list, ",") != strings.Join(c.reasons[cls], ",") {
			t.Errorf("reasons of %s: %v, want %v", cls, list, c.reasons[cls])
		}
	}
	if c.pageRs != nil && strings.Join(ah.PageReasons, ",") != strings.Join(c.pageRs, ",") {
		t.Errorf("page_reasons %v, want %v", ah.PageReasons, c.pageRs)
	}
	if c.compl != "" {
		g := ah.Completeness.Status + "/" + deref(ah.Completeness.Reason)
		if g != c.compl {
			t.Errorf("completeness %s, want %s", g, c.compl)
		}
	}
	if c.aff != "" {
		af := res.Stats.Affiliation
		if g := af.Status + "/" + deref(af.Reason); g != c.aff {
			t.Errorf("affiliation %s, want %s", g, c.aff)
		}
	}
	if c.notes != nil && strings.Join(ah.Notes, ",") != strings.Join(c.notes, ",") {
		t.Errorf("notes %v, want %v", ah.Notes, c.notes)
	}
	if c.check != nil {
		c.check(t, res)
	}
}

// roleListFor builds an effective role list (format spec 10.7.2) naming one
// statements key and adds it with its root to the options.
func roleListFor(t *testing.T, o *Options, k rolle) {
	t.Helper()
	w, priv := wurzel()
	o.VendorRoots = append(o.VendorRoots, w)
	addList(t, o, rollenliste(t, w.ID, priv, 1, nil, k))
}

// TestHistoryPageReasons runs every reason of H2 (format spec 8.8.4, in the
// order of registry page_reasons). Each page carries a root the package
// contradicts, recorded long before R: had the page been used it would be
// MERKLE_INCONSISTENT; a page that is not used yields exit 1 only.
func TestHistoryPageReasons(t *testing.T) {
	differ := rt(3, other("withheld from use"), "countersigned", ahTS("08:01:00.000"))
	qPriv, qPub := keyFromSeed(0x52)
	unv := ClsHistoryUnverified
	sjOf := func(w *ahWorld, p pg) string {
		if p.roots == nil {
			p.roots = w.honestRoots()
		}
		p.roots = append(p.roots, differ)
		return string(canonGo(t, w.statement(p)))
	}
	cases := []struct {
		why   string
		setup func(w *ahWorld)
		want  ahCheck
	}{
		{"1 key_not_established: a key no anchor of the auditor names", func(w *ahWorld) {
			priv, _ := keyFromSeed(0x60)
			sj := sjOf(w, pg{})
			w.files = append(w.files, pageFile(t, sj, [2]string{"st-unknown", sign(priv, sj)}))
		}, ahCheck{exit: 1, classes: []string{unv}, reasons: map[string][]string{unv: {"key_not_established", "pages_missing"}}, pageRs: []string{"key_not_established"},
			compl: "not_established/no_usable_page", aff: "not_determined/history_key_not_established"}},
		{"1 key_other_role: the countersigning pin establishes no page", func(w *ahWorld) {
			sj := sjOf(w, pg{})
			w.files = append(w.files, pageFile(t, sj, [2]string{"vendor-1", sign(w.g.vendPriv, sj)}))
		}, ahCheck{exit: 1, classes: []string{unv}, reasons: map[string][]string{unv: {"key_other_role", "pages_missing"}}, pageRs: []string{"key_other_role"},
			aff: "not_determined/history_key_not_established"}},
		{"2 signature: the pinned key does not carry the signature", func(w *ahWorld) {
			priv, _ := ahStmtKey()
			sj := sjOf(w, pg{})
			w.files = append(w.files, pageFile(t, sj, [2]string{ahStmtID, sign(priv, sj+" ")}))
		}, ahCheck{exit: 1, classes: []string{ClsHistoryDefective, unv}, reasons: map[string][]string{ClsHistoryDefective: {"signature"}, unv: {"pages_missing"}},
			pageRs: []string{"signature"}, aff: "not_determined/history_defective"}},
		{"3 page_rules: statement_jcs is not its own JCS form", func(w *ahWorld) {
			priv, _ := ahStmtKey()
			sj := strings.Replace(sjOf(w, pg{}), `{"affiliation":`, `{ "affiliation":`, 1)
			w.files = append(w.files, pageFile(t, sj, [2]string{ahStmtID, sign(priv, sj)}))
		}, ahCheck{exit: 1, classes: []string{ClsHistoryContradict, unv}, reasons: map[string][]string{ClsHistoryContradict: {"page_rules"}, unv: {"pages_missing"}},
			pageRs: []string{"page_rules"}, compl: "not_established/no_usable_page", aff: "not_determined/history_contradictory"}},
		{"4 not_v2: a page of kind v1", func(w *ahWorld) {
			priv, _ := ahStmtKey()
			sj := sjOf(w, pg{edit: func(m map[string]any) { m["kind"] = "ledger.anchor_history.v1" }})
			w.files = append(w.files, pageFile(t, sj, [2]string{ahStmtID, sign(priv, sj)}))
		}, ahCheck{exit: 1, classes: []string{unv}, reasons: map[string][]string{unv: {"not_v2", "pages_missing"}}, pageRs: []string{"not_v2"}, aff: "not_determined/history_not_v2"}},
		{"5 page_rules: roots not in the order of page rule 3", func(w *ahWorld) {
			priv, _ := ahStmtKey()
			sj := sjOf(w, pg{edit: func(m map[string]any) {
				rs := m["roots"].([]any)
				rs[0], rs[1] = rs[1], rs[0]
			}})
			w.files = append(w.files, pageFile(t, sj, [2]string{ahStmtID, sign(priv, sj)}))
		}, ahCheck{exit: 1, classes: []string{ClsHistoryContradict, unv}, reasons: map[string][]string{ClsHistoryContradict: {"page_rules"}, unv: {"pages_missing"}},
			pageRs: []string{"page_rules"}, compl: "not_established/no_usable_page"}},
		{"6 key_not_valid: the entry of the role list starts after server_ts", func(w *ahWorld) {
			w.opts = func(o *Options) {
				roleListFor(t, o, rolle{id: "st-q", pub: qPub, rolle: RoleStatements, ab: "2026-10-10T09:00:00Z"})
			}
			sj := sjOf(w, pg{})
			w.files = append(w.files, pageFile(t, sj, [2]string{"st-q", sign(qPriv, sj)}))
		}, ahCheck{exit: 1, classes: []string{unv}, reasons: map[string][]string{unv: {"key_not_valid", "pages_missing"}}, pageRs: []string{"key_not_valid"}, aff: "not_determined/history_key_not_valid"}},
		{"7 other_chain: a page of a chain nobody links", func(w *ahWorld) {
			w.add(pg{chain: "0f0e0d0c-0b0a-4900-8807-0605040302ff", roots: append(w.honestRoots(), differ)})
		}, ahCheck{exit: 1, classes: []string{unv}, reasons: map[string][]string{unv: {"other_chain", "pages_missing"}}, pageRs: []string{"other_chain"},
			compl: "not_established/no_usable_page", aff: "not_determined/history_other_chain"}},
		{"8 owner_differs: owner_keys of another device", func(w *ahWorld) {
			w.add(pg{owner: []any{ownerCommitment(ahApp, w.g.chainID, pubOf(0x61))}, roots: append(w.honestRoots(), differ)})
		}, ahCheck{exit: 1, classes: []string{unv}, reasons: map[string][]string{unv: {"owner_differs", "pages_missing"}}, pageRs: []string{"owner_differs"},
			compl: "not_established/owner_differs", aff: "not_determined/history_owner_differs",
			check: func(t *testing.T, res Result) {
				if o := res.Stats.AnchorHistory.Owner; o == nil || *o != "differs" {
					t.Errorf("owner %v", o)
				}
			}}},
		{"9 signing_time_not_proven: a revoked key on a page that is not fresh", func(w *ahWorld) {
			w.opts = func(o *Options) {
				roleListFor(t, o, rolle{id: "st-q", pub: qPub, rolle: RoleStatements, widerr: "2026-10-10T09:00:00Z"})
			}
			sj := sjOf(w, pg{ts: ahTS("08:10:00.000"), roots: w.honestRoots()[:1]})
			w.files = append(w.files, pageFile(t, sj, [2]string{"st-q", sign(qPriv, sj)}))
		}, ahCheck{exit: 1, classes: []string{unv}, reasons: map[string][]string{unv: {"signing_time_not_proven", "issued_before_request", "pages_missing"}},
			pageRs: []string{"signing_time_not_proven"}, compl: "not_established/issued_before_request", aff: "not_determined/history_signing_time_not_proven"}},
		{"9 a revoked key on a fresh page is used", func(w *ahWorld) {
			w.opts = func(o *Options) {
				roleListFor(t, o, rolle{id: "st-q", pub: qPub, rolle: RoleStatements, widerr: "2026-10-10T09:00:00Z"})
			}
			sj := string(canonGo(t, w.statement(pg{})))
			w.files = append(w.files, pageFile(t, sj, [2]string{"st-q", sign(qPriv, sj)}))
		}, ahCheck{exit: 0, compl: "established/", pageRs: []string{}, check: func(t *testing.T, res Result) {
			k := res.Stats.AnchorHistory.Keys
			if len(k) != 1 || k[0].KeyID != "st-q" || k[0].Source != SourceRoleList || k[0].List == nil || k[0].List.WurzelID != "wurzel-test" {
				t.Errorf("keys %+v", k)
			}
			if sb := res.Stats.Affiliation.StatedBy; sb == nil || sb.KeySource != AffSourceAuditor {
				t.Errorf("stated_by %+v", sb)
			}
		}}},
	}
	for _, f := range cases {
		t.Run(f.why, func(t *testing.T) {
			w := newAHWorld(t)
			f.setup(w)
			res := w.run()
			f.want.verify(t, res)
			if countClass(res, ClsMerkleInconsistent) != 0 {
				t.Errorf("a page that is not used gave MERKLE_INCONSISTENT")
			}
		})
	}
}

// TestHistoryPairs: equal statement_jcs are one page with the set of its
// pairs (H1); the pair numbers 1, 2, 6 and 9 pass while one pair passes,
// a failing pair under an established key is ANCHOR_HISTORY_DEFECTIVE even
// on a used page, and the report names the pair with the smallest
// server_key_id (H2 "Mehrere Paare").
func TestHistoryPairs(t *testing.T) {
	priv2, pub2 := keyFromSeed(0x53)
	priv0, pub0 := keyFromSeed(0x54)
	unknown, _ := keyFromSeed(0x60)
	cases := []struct {
		why   string
		pairs func(sj string) [][2]string
		want  ahCheck
	}{
		{"a failing and a holding pair: used, signature reported", func(sj string) [][2]string {
			p, _ := ahStmtKey()
			return [][2]string{{ahStmtID, sign(p, sj+"x")}, {"st-2", sign(priv2, sj)}}
		}, ahCheck{exit: 1, classes: []string{ClsHistoryDefective}, reasons: map[string][]string{ClsHistoryDefective: {"signature"}}, compl: "established/",
			check: func(t *testing.T, res Result) {
				ah := res.Stats.AnchorHistory
				if ah.Pages.Supplied != 2 || ah.Pages.Distinct != 1 || ah.Pages.UsedFresh != 1 || len(ah.Keys) != 1 || ah.Keys[0].KeyID != "st-2" {
					t.Errorf("pages %+v keys %+v", ah.Pages, ah.Keys)
				}
			}}},
		{"an unknown key and a failing signature: the signature got further", func(sj string) [][2]string {
			p, _ := ahStmtKey()
			return [][2]string{{"st-unknown", sign(unknown, sj)}, {ahStmtID, sign(p, sj+"x")}}
		}, ahCheck{exit: 1, classes: []string{ClsHistoryDefective, ClsHistoryUnverified}, reasons: map[string][]string{ClsHistoryDefective: {"signature"}, ClsHistoryUnverified: {"pages_missing"}},
			pageRs: []string{"signature"}}},
		{"an unknown key and a key of another role", func(sj string) [][2]string {
			return [][2]string{{"st-unknown", sign(unknown, sj)}, {"vendor-1", sign(unknown, sj)}}
		}, ahCheck{exit: 1, classes: []string{ClsHistoryUnverified}, reasons: map[string][]string{ClsHistoryUnverified: {"key_other_role", "pages_missing"}}, pageRs: []string{"key_other_role"}}},
		{"two holding pairs: the smallest server_key_id", func(sj string) [][2]string {
			return [][2]string{{"st-2", sign(priv2, sj)}, {"st-0", sign(priv0, sj)}}
		}, ahCheck{exit: 0, compl: "established/", check: func(t *testing.T, res Result) {
			if k := res.Stats.AnchorHistory.Keys; len(k) != 1 || k[0].KeyID != "st-0" {
				t.Errorf("keys %+v", k)
			}
			if sb := res.Stats.Affiliation.StatedBy; sb == nil || sb.ServerKeyID != "st-0" {
				t.Errorf("stated_by %+v", sb)
			}
		}}},
	}
	for _, f := range cases {
		t.Run(f.why, func(t *testing.T) {
			w := newAHWorld(t)
			sj := string(canonGo(t, w.statement(pg{})))
			for _, p := range f.pairs(sj) {
				w.files = append(w.files, pageFile(t, sj, p))
			}
			w.opts = func(o *Options) {
				for _, k := range []string{"st-2=" + pub2, "st-0=" + pub0} {
					if err := o.AddVendorStatementKey(k); err != nil {
						t.Fatal(err)
					}
				}
			}
			f.want.verify(t, w.run())
		})
	}
}

// TestHistoryCoverage holds coverage (H4) against the reference values of
// format spec 8.8.4.
func TestHistoryCoverage(t *testing.T) {
	pg := func(since, next int64) *ahPage { return &ahPage{c: &ahContent{since: since, next: next}} }
	gapStr := func(gs []HistoryGap) string {
		var out []string
		for _, g := range gs {
			b := "inf"
			if g[1] != nil {
				b = fmt.Sprint(*g[1])
			}
			out = append(out, fmt.Sprintf("[%d,%s)", *g[0], b))
		}
		return strings.Join(out, " ")
	}
	for _, f := range []struct {
		pages  []*ahPage
		status string
		gaps   string
	}{
		{[]*ahPage{pg(0, 501), pg(501, 1001), pg(1001, -1)}, "complete", ""},
		{[]*ahPage{pg(0, 501), pg(1001, -1)}, "partial", "[501,1001)"},
		{[]*ahPage{pg(400, 501), pg(501, -1)}, "partial", "[0,400)"},
		{[]*ahPage{pg(0, 501)}, "partial", "[501,inf)"},
		{[]*ahPage{pg(0, 480), pg(0, 501), pg(501, -1)}, "complete", ""},
		{nil, "none", "[0,inf)"},
	} {
		st, gaps := coverage(f.pages)
		if st != f.status || gapStr(gaps) != f.gaps {
			t.Errorf("coverage %s %s, want %s %s", st, gapStr(gaps), f.status, f.gaps)
		}
	}
}

// TestHistoryIssuedAndCoverage: H3 (issued before the request), H4 (pages
// missing) and the note archive_pages, through the verifier.
func TestHistoryIssuedAndCoverage(t *testing.T) {
	unv := ClsHistoryUnverified
	cases := []struct {
		why   string
		setup func(w *ahWorld)
		want  ahCheck
	}{
		{"H3: only a page issued before R - W_h", func(w *ahWorld) { w.add(pg{ts: ahTS("08:14:00.000")}) },
			ahCheck{exit: 1, classes: []string{unv}, reasons: map[string][]string{unv: {"issued_before_request", "pages_missing"}},
				compl: "not_established/issued_before_request", aff: "not_determined/statement_does_not_cover_package",
				check: func(t *testing.T, res Result) {
					if p := res.Stats.AnchorHistory.Pages; p.UsedStale != 1 || p.UsedFresh != 0 {
						t.Errorf("pages %+v", p)
					}
					// An older page still enters the roots (H6).
					if res.Stats.AnchorHistory.Roots.Found != 2 {
						t.Errorf("roots %+v", res.Stats.AnchorHistory.Roots)
					}
				}}},
		{"H4: a fresh page [0, 5) leaves [5, infinity)", func(w *ahWorld) {
			w.add(pg{roots: w.honestRoots()[:1], next: int64(5), truncated: true})
		}, ahCheck{exit: 1, classes: []string{unv}, reasons: map[string][]string{unv: {"pages_missing"}}, compl: "partial/pages_missing", aff: "not_determined/history_pages_missing",
			check: func(t *testing.T, res Result) {
				cv := res.Stats.AnchorHistory.Coverage
				if cv.Status != "partial" || len(cv.Gaps) != 1 || *cv.Gaps[0][0] != 5 || cv.Gaps[0][1] != nil {
					t.Errorf("coverage %+v", cv)
				}
			}}},
		{"H4: two pages from different fetches cover together", func(w *ahWorld) {
			w.add(pg{roots: w.honestRoots()[:1], next: int64(5), truncated: true})
			w.add(pg{roots: w.honestRoots()[1:], since: 5, ts: ahTS("08:32:00.000")})
		}, ahCheck{exit: 0, compl: "established/", aff: "not_affiliated/"}},
		{"H3: an older page beside a fresh one gives the note archive_pages", func(w *ahWorld) {
			w.add(pg{})
			w.add(pg{ts: ahTS("08:12:00.000"), roots: w.honestRoots()[:1], edit: func(m map[string]any) { m["reference_tree_size"] = int64(6) }})
		}, ahCheck{exit: 0, compl: "established/", notes: []string{"archive_pages"}}},
	}
	for _, f := range cases {
		t.Run(f.why, func(t *testing.T) {
			w := newAHWorld(t)
			f.setup(w)
			f.want.verify(t, w.run())
		})
	}
}

// h5Page builds the content of a page for the comparison of H5 directly.
func h5Page(t *testing.T, w *ahWorld, p pg) *ahContent {
	t.Helper()
	v, err := jcs.Parse(canonGo(t, w.statement(p)))
	if err != nil {
		t.Fatal(err)
	}
	c, why := readHistoryContent(v)
	if c == nil {
		t.Fatalf("page rules: %s", why)
	}
	return c
}

func period(bases []any, from string, until any, recorded string, merged bool) map[string]any {
	return map[string]any{"bases": bases, "from": from, "until": until, "recorded_ts": recorded, "merged": merged}
}

// TestHistoryCompare holds H5 against the reference values of format spec
// 8.8.4 (A with an open period, issued 01:02:00, against B) and against the
// rule of 8.8.4 H5 (g) from edition state ffffeadd: known_range_narrowed only
// when both pages name a value and B.known_since lies after A.known_since and
// not after A.server_ts.
func TestHistoryCompare(t *testing.T) {
	w := newAHWorld(t)
	day := func(c string) string { return "2026-01-01T" + c + "Z" }
	cc := []any{"common_control"}
	open := period(cc, day("00:00:00.000"), nil, day("00:00:00.000"), false)
	base := pg{noRoots: true, ts: day("01:02:00.000"), periods: []any{open}, known: "2025-12-01T00:00:00.000Z"}
	b := func(edit func(p *pg)) pg { p := base; p.ts = day("01:10:00.000"); edit(&p); return p }
	cases := []struct {
		why  string
		a, b pg
		want string
	}{
		{"B ends it after A was issued", base, b(func(p *pg) {
			p.periods = []any{period(cc, day("00:00:00.000"), day("01:05:00.000"), day("01:06:00.000"), false)}
		}), ""},
		{"B ends it before", base, b(func(p *pg) {
			p.periods = []any{period(cc, day("00:00:00.000"), day("01:01:00.000"), day("01:06:00.000"), false)}
		}), "affiliation_narrowed"},
		{"B five seconds later without a period (split view)", base, b(func(p *pg) { p.ts = day("01:02:05.000"); p.periods = []any{} }), "affiliation_narrowed"},
		{"B adds an older period entered after A", base, b(func(p *pg) {
			p.periods = []any{period(cc, "2025-01-01T00:00:00.000Z", "2025-02-01T00:00:00.000Z", day("01:05:00.000"), false), open}
		}), ""},
		{"B adds an older period entered more than W_h before A", base, b(func(p *pg) {
			p.periods = []any{period(cc, "2025-01-01T00:00:00.000Z", "2025-02-01T00:00:00.000Z", day("00:40:00.000"), false), open}
		}), "affiliation_withheld"},
		{"B widens by merging", base, b(func(p *pg) {
			p.periods = []any{period([]any{"common_control", "participation"}, "2025-06-01T00:00:00.000Z", nil, day("01:05:00.000"), true)}
		}), ""},
		// format spec 8.8.4 H5 (f): only a period with merged = false gives
		// affiliation_withheld; a merged period of B never does, even when
		// recorded more than W_h before A (heartbeat spec 9.10 time
		// reference 4).
		{"H5 (f): B shows merged a period recorded more than W_h before A", base, b(func(p *pg) {
			p.periods = []any{period(cc, "2025-01-01T00:00:00.000Z", nil, day("00:40:00.000"), true)}
		}), ""},
		{"H5 (f): B shows the same period not merged", base, b(func(p *pg) {
			p.periods = []any{period(cc, "2025-01-01T00:00:00.000Z", nil, day("00:40:00.000"), false)}
		}), "affiliation_withheld"},
		{"H5 (f): B merges one period and withholds another one not merged", base, b(func(p *pg) {
			p.periods = []any{period(cc, "2024-01-01T00:00:00.000Z", "2024-06-01T00:00:00.000Z", day("00:40:00.000"), false),
				period([]any{"common_control", "participation"}, "2025-01-01T00:00:00.000Z", nil, day("00:40:00.000"), true)}
		}), "affiliation_withheld"},
		{"H5 (f): a merged period of B that narrows A is still affiliation_narrowed", base, b(func(p *pg) {
			p.periods = []any{period(cc, "2025-01-01T00:00:00.000Z", day("01:01:00.000"), day("00:40:00.000"), true)}
		}), "affiliation_narrowed"},
		{"B moves known_since after A.known_since and before A.server_ts", base, b(func(p *pg) { p.known = day("00:30:00.000") }), "known_range_narrowed"},
		{"B moves known_since to A.server_ts (not after it)", base, b(func(p *pg) { p.known = day("01:02:00.000") }), "known_range_narrowed"},
		{"B moves known_since after A.server_ts (a takeover)", base, b(func(p *pg) { p.known = day("01:05:00.000") }), ""},
		{"B names null (a takeover)", base, b(func(p *pg) { p.known = "null" }), ""},
		{"A names null, B a value", func() pg { a := base; a.known = "null"; return a }(), b(func(p *pg) {}), ""},
		{"a root of A in the range of B missing on B", pg{ts: ahTS("08:31:00.000")}, pg{ts: ahTS("08:40:00.000"), roots: w.honestRoots()[:1], edit: func(m map[string]any) { m["reference_tree_size"] = int64(6) }}, "root_dropped"},
		{"a root of B recorded before A - W_h missing on A", pg{ts: ahTS("08:31:00.000"), roots: w.honestRoots()[:1], ref: 6}, pg{ts: ahTS("08:40:00.000")}, "root_withheld"},
		{"a root of B recorded in the band before A is no reason", pg{ts: ahTS("08:20:00.000"), roots: w.honestRoots()[:1], ref: 6}, pg{ts: ahTS("08:40:00.000")}, ""},
		{"the same root with another server_ts", pg{ts: ahTS("08:31:00.000")}, pg{ts: ahTS("08:40:00.000"), roots: []map[string]any{rt(1, w.root(1), "countersigned", ahTS("08:00:03.000")), w.honestRoots()[1]}}, "root_time_differs"},
		{"a fork of A missing on B with forks_omitted 0", pg{forks: []any{map[string]any{"tree_size": int64(6), "merkle_root": other("f"), "detected_ts": ahTS("08:20:00.000")}}}, pg{ts: ahTS("08:40:00.000")}, "fork_dropped"},
		{"a fork of A missing on B with forks_omitted 1", pg{forks: []any{map[string]any{"tree_size": int64(6), "merkle_root": other("f"), "detected_ts": ahTS("08:20:00.000")}}}, pg{ts: ahTS("08:40:00.000"), omitted: 1}, ""},
		{"an owner commitment dropped", pg{owner: []any{w.owner(), strings.Repeat("f", 64)}}, pg{ts: ahTS("08:40:00.000")}, "owner_keys_dropped"},
		{"a successor dropped", pg{succ: map[string]any{"chain_id": "0f0e0d0c-0b0a-4900-8807-0605040302aa", "tree_size": int64(6)}}, pg{ts: ahTS("08:40:00.000")}, "succession_changed"},
		{"a successor added", pg{}, pg{ts: ahTS("08:40:00.000"), succ: map[string]any{"chain_id": "0f0e0d0c-0b0a-4900-8807-0605040302aa", "tree_size": int64(6)}}, ""},
		{"the reference size decreases", pg{ref: 8}, pg{ts: ahTS("08:40:00.000")}, "reference_decreases"},
	}
	for _, f := range cases {
		t.Run(f.why, func(t *testing.T) {
			var got []string
			for _, x := range comparePages(h5Page(t, w, f.a), h5Page(t, w, f.b)) {
				got = append(got, x.code)
			}
			if strings.Join(got, ",") != f.want {
				t.Errorf("reasons %v, want %q", got, f.want)
			}
		})
	}
}

// TestHistoryCompareRun: two pages of the package that contradict each
// other give ANCHOR_HISTORY_CONTRADICTION (exit 1), block the completeness
// (H11 (b)) and mark the affiliation contradictory (8.8.6 number 9), whose
// status still comes from the wider statement.
func TestHistoryCompareRun(t *testing.T) {
	w := newAHWorld(t)
	vend := []any{"vendor"}
	w.add(pg{ts: ahTS("08:20:00.000"), periods: []any{period(vend, "2026-01-01T00:00:00.000Z", nil, "2026-01-01T00:00:00.000Z", false)}})
	w.add(pg{ts: ahTS("08:40:00.000")})
	ahCheck{exit: 1, classes: []string{ClsHistoryContradict}, reasons: map[string][]string{ClsHistoryContradict: {"affiliation_narrowed"}},
		compl: "partial/contradiction", aff: "affiliated/", check: func(t *testing.T, res Result) {
			af := res.Stats.Affiliation
			if !af.Contradictory || !af.VendorItself || strings.Join(af.Bases, ",") != "vendor" {
				t.Errorf("affiliation %+v", af)
			}
			// The period of the older page ends at its server_ts (8.8.6
			// number 4) and still overlaps the period of the package.
			if len(af.Periods) != 1 || af.Periods[0].Until == nil || *af.Periods[0].Until != ahTS("08:20:00.000") || !af.Periods[0].OverlapsPackage {
				t.Errorf("periods %+v", af.Periods)
			}
			if *af.ReceiptsInPeriods != 2 {
				t.Errorf("receipts_in_periods %d", *af.ReceiptsInPeriods)
			}
		}}.verify(t, w.run())
}

// TestHistoryMergedPeriodRun: format spec 8.8.4 H5 (f) between two pages of
// the package. The later page B shows a period recorded more than W_h before
// the earlier page A, which states no affiliation. Merged (merged = true,
// heartbeat spec 9.10 time reference 4), it gives no reason: no finding, the
// completeness stays established (H11 (b)) and contradictory stays false
// (8.8.6 number 9). Not merged, it is affiliation_withheld.
func TestHistoryMergedPeriodRun(t *testing.T) {
	vend := []any{"vendor"}
	cases := []struct {
		why    string
		merged bool
		want   ahCheck
	}{
		{"merged: no reason", true, ahCheck{exit: 0, compl: "established/", aff: "affiliated/"}},
		{"not merged: affiliation_withheld", false, ahCheck{exit: 1, classes: []string{ClsHistoryContradict},
			reasons: map[string][]string{ClsHistoryContradict: {"affiliation_withheld"}}, compl: "partial/contradiction", aff: "affiliated/"}},
	}
	for _, f := range cases {
		t.Run(f.why, func(t *testing.T) {
			w := newAHWorld(t)
			w.add(pg{ts: ahTS("08:20:00.000")})
			w.add(pg{ts: ahTS("08:40:00.000"), periods: []any{period(vend, "2026-01-01T00:00:00.000Z", nil, ahTS("08:00:00.000"), f.merged)}})
			res := w.run()
			f.want.verify(t, res)
			if af := res.Stats.Affiliation; af.Contradictory == f.merged {
				t.Errorf("contradictory %v with merged %v", af.Contradictory, f.merged)
			}
		})
	}
}

// histVL adds an anchor history to the world of the vendor log tests: its
// day 2026-08-01 is witnessed, and the chain-day record of the chain is
// checked (format spec 7.4.10 L3, L6).
func histVL(t *testing.T, w *vlWorld, roots []map[string]any) {
	hw := &ahWorld{t: t, g: w.g}
	sj := string(canonGo(t, hw.statement(pg{roots: roots, ts: "2026-08-01T09:30:00.000Z"})))
	priv, pub := ahStmtKey()
	file := pageFile(t, sj, [2]string{ahStmtID, sign(priv, sj)})
	prev := w.opts
	w.opts = func(o *Options) {
		if prev != nil {
			prev(o)
		}
		if err := o.AddVendorStatementKey(ahStmtID + "=" + pub); err != nil {
			t.Fatal(err)
		}
		if err := o.AddAnchorHistory(file); err != nil {
			t.Fatal(err)
		}
		if err := o.SetRequestedAt("2026-08-01T09:00:00.000Z"); err != nil {
			t.Fatal(err)
		}
	}
}

// TestHistoryVendorLog: H7, the comparison with the checked chain-day
// records of the vendor log; a recording the record lacks does not count
// (not_used_vendor_log), so the vendor log never adds an exit 2.
func TestHistoryVendorLog(t *testing.T) {
	receipts := func(w *vlWorld) []map[string]any {
		var out []map[string]any
		for _, r := range w.receiptRows(vlChainDay) {
			out = append(out, rt(r["tree_size"].(int64), r["merkle_root"].(string), "countersigned", r["server_ts"].(string)))
		}
		return out
	}
	con := ClsHistoryContradict
	cases := []struct {
		why   string
		setup func(w *vlWorld)
		want  ahCheck
	}{
		{"honest: the page and the record agree", func(w *vlWorld) { histVL(t, w, receipts(w)) },
			ahCheck{exit: 0, compl: "established/", check: func(t *testing.T, res Result) {
				if rc := res.Stats.AnchorHistory.Receipts; rc.Checked != 2 || rc.BeforeLegacyBoundary != 2 {
					t.Errorf("receipts %+v (both before the cut-off date)", rc)
				}
			}}},
		{"log_mismatch: a recorded root the record lacks does not count", func(w *vlWorld) {
			histVL(t, w, append(receipts(w), rt(4, other("not logged"), "countersigned", "2026-08-01T08:05:00Z")))
		}, ahCheck{exit: 1, classes: []string{con}, reasons: map[string][]string{con: {"log_mismatch"}}, compl: "partial/contradiction",
			check: func(t *testing.T, res Result) {
				if r := res.Stats.AnchorHistory.Roots; r.NotUsedVendorLog != 1 || r.Distinct != 3 || r.DifferingBeforeRequest != 0 {
					t.Errorf("roots %+v", r)
				}
			}}},
		{"log_root_missing: a logged root missing on a later fresh page", func(w *vlWorld) { histVL(t, w, receipts(w)[:1]) },
			ahCheck{exit: 1, classes: []string{con}, reasons: map[string][]string{con: {"log_root_missing"}}}},
		{"gap_witness_time_differs: the page lists the gap witness with another string", func(w *vlWorld) {
			w.rows = func(rows []map[string]any) []map[string]any {
				return append(rows, map[string]any{"tree_size": int64(6), "merkle_root": w.g.merkleRootAt(6), "recorded_as": "gap_witness", "server_ts": "2026-08-01T08:10:00.000Z"})
			}
			histVL(t, w, append(receipts(w), rt(6, w.g.merkleRootAt(6), "gap_witness", "2026-08-01T08:10:00Z")))
		}, ahCheck{exit: 1, classes: []string{con}, reasons: map[string][]string{con: {"log_mismatch", "gap_witness_time_differs"}}}},
		{"gap_witness_time_differs: two gap witnesses of one root in the records", func(w *vlWorld) {
			w.rows = func(rows []map[string]any) []map[string]any {
				return append(rows,
					map[string]any{"tree_size": int64(6), "merkle_root": w.g.merkleRootAt(6), "recorded_as": "gap_witness", "server_ts": "2026-08-01T08:10:00.000Z"},
					map[string]any{"tree_size": int64(6), "merkle_root": w.g.merkleRootAt(6), "recorded_as": "gap_witness", "server_ts": "2026-08-01T08:10:30.000Z"})
			}
			histVL(t, w, append(receipts(w), rt(6, w.g.merkleRootAt(6), "gap_witness", "2026-08-01T08:10:00.000Z")))
		}, ahCheck{exit: 1, classes: []string{con}, reasons: map[string][]string{con: {"gap_witness_time_differs"}}}},
	}
	for _, f := range cases {
		t.Run(f.why, func(t *testing.T) {
			w := newVLWorld(t)
			f.setup(w)
			res := w.run()
			f.want.verify(t, res)
			if res.Stats.VendorLog.Status != VendorLogChecked {
				t.Fatalf("vendor_log %+v", res.Stats.VendorLog)
			}
		})
	}
}

// TestHistoryForksAndHandover: H9.
func TestHistoryForksAndHandover(t *testing.T) {
	fork := ClsHistoryFork
	succ := map[string]any{"chain_id": "0f0e0d0c-0b0a-4900-8807-0605040302aa", "tree_size": int64(6)}
	cases := []struct {
		why   string
		setup func(w *ahWorld)
		want  ahCheck
	}{
		{"a fork finding is listed", func(w *ahWorld) {
			w.add(pg{forks: []any{map[string]any{"tree_size": int64(6), "merkle_root": other("f"), "detected_ts": ahTS("08:20:00.000")}}})
		}, ahCheck{exit: 1, classes: []string{fork}, reasons: map[string][]string{fork: {"fork_listed"}}, compl: "partial/fork",
			check: func(t *testing.T, res Result) {
				if f := res.Stats.AnchorHistory.Forks; f.Listed != 1 || f.Omitted != 0 {
					t.Errorf("forks %+v", f)
				}
			}}},
		{"fork findings omitted", func(w *ahWorld) { w.add(pg{omitted: 2}) },
			ahCheck{exit: 1, classes: []string{fork}, reasons: map[string][]string{fork: {"forks_omitted"}}, check: func(t *testing.T, res Result) {
				if f := res.Stats.AnchorHistory.Forks; f.Omitted != 2 {
					t.Errorf("forks %+v", f)
				}
			}}},
		{"a countersigned root beyond the handover", func(w *ahWorld) {
			w.add(pg{succ: succ, roots: append(w.honestRoots(), rt(8, w.root(8), "countersigned", ahTS("08:12:30.000")), rt(9, w.root(9), "reported", ahTS("08:12:40.000")))})
		}, ahCheck{exit: 1, classes: []string{fork}, reasons: map[string][]string{fork: {"root_beyond_handover"}},
			notes: []string{"reported_beyond_handover", "package_beyond_handover"}, check: func(t *testing.T, res Result) {
				ah := res.Stats.AnchorHistory
				if ah.Successor == nil || ah.Successor.TreeSize != 6 || ah.Predecessor != nil {
					t.Errorf("successor %+v predecessor %+v", ah.Successor, ah.Predecessor)
				}
			}}},
		{"a predecessor whose pages are not supplied", func(w *ahWorld) {
			w.add(pg{pred: map[string]any{"chain_id": "0f0e0d0c-0b0a-4900-8807-0605040302bb", "tree_size": int64(3)}})
		}, ahCheck{exit: 0, notes: []string{"predecessor_differs_from_genesis", "linked_history_not_supplied"}}},
	}
	for _, f := range cases {
		t.Run(f.why, func(t *testing.T) {
			w := newAHWorld(t)
			f.setup(w)
			f.want.verify(t, w.run())
		})
	}
}

// TestHistoryReceipts: H10, the receipts against the history.
func TestHistoryReceipts(t *testing.T) {
	con := ClsHistoryContradict
	cases := []struct {
		why   string
		setup func(w *ahWorld)
		want  ahCheck
		rc    HistoryReceiptsStat
	}{
		{"an established receipt missing on a later page", func(w *ahWorld) { w.add(pg{roots: w.honestRoots()[:1], ref: 6}) },
			ahCheck{exit: 1, classes: []string{con}, reasons: map[string][]string{con: {"receipt_not_in_history"}}, compl: "partial/contradiction"},
			HistoryReceiptsStat{Checked: 2, InHistory: 1, NotInHistory: 1}},
		{"a receipt whose key is not established: a note", func(w *ahWorld) { w.noPin = true; w.add(pg{roots: w.honestRoots()[:1], ref: 6}) },
			ahCheck{exit: 1, classes: []string{ClsReceiptUnverified}, notes: []string{"receipt_roots_unverified_not_in_history"},
				check: func(t *testing.T, res Result) {
					if af := res.Stats.Affiliation; *af.ReceiptsTotal != 0 {
						t.Errorf("receipts_total %d", *af.ReceiptsTotal)
					}
				}},
			HistoryReceiptsStat{Checked: 2, InHistory: 1, NotInHistoryUnestablished: 1}},
		{"a repetition with another server_ts", func(w *ahWorld) {
			w.add(pg{roots: []map[string]any{w.honestRoots()[0], rt(6, w.root(6), "countersigned", ahTS("08:11:30.000"))}})
		}, ahCheck{exit: 0}, HistoryReceiptsStat{Checked: 2, InHistory: 2, ServerTSDiffers: 1}},
		{"a page issued less than W_h after the receipt does not cover it", func(w *ahWorld) {
			w.add(pg{roots: w.honestRoots()[:1], ref: 6, ts: ahTS("08:20:00.000")})
		}, ahCheck{exit: 0}, HistoryReceiptsStat{Checked: 2, InHistory: 1, NotCovered: 1}},
	}
	for _, f := range cases {
		t.Run(f.why, func(t *testing.T) {
			w := newAHWorld(t)
			f.setup(w)
			res := w.run()
			f.want.verify(t, res)
			if rc := res.Stats.AnchorHistory.Receipts; rc != f.rc {
				t.Errorf("receipts %+v, want %+v", rc, f.rc)
			}
		})
	}
}

// TestHistoryCompleteness: the reasons of H11 in their order (format spec
// 8.8.4, table of H11), and partial against not_established.
func TestHistoryCompleteness(t *testing.T) {
	priv, _ := keyFromSeed(0x60)
	cases := []struct {
		why   string
		setup func(w *ahWorld)
		want  string
	}{
		{"not_supplied", func(w *ahWorld) {}, "not_established/not_supplied"},
		{"no_request_time", func(w *ahWorld) { w.r = ""; w.add(pg{}) }, "not_established/no_request_time"},
		{"no_usable_page", func(w *ahWorld) {
			sj := string(canonGo(t, w.statement(pg{})))
			w.files = append(w.files, pageFile(t, sj, [2]string{"st-unknown", sign(priv, sj)}))
		}, "not_established/no_usable_page"},
		{"owner_differs", func(w *ahWorld) { w.add(pg{owner: []any{strings.Repeat("e", 64)}}) }, "not_established/owner_differs"},
		{"issued_before_request", func(w *ahWorld) { w.add(pg{ts: ahTS("08:14:59.999")}) }, "not_established/issued_before_request"},
		{"pages_missing", func(w *ahWorld) { w.add(pg{since: 1}) }, "partial/pages_missing"},
		{"contradiction", func(w *ahWorld) {
			w.add(pg{})
			w.add(pg{ts: ahTS("08:40:00.000"), ref: 7})
			w.add(pg{ts: ahTS("08:50:00.000")})
		}, "partial/contradiction"},
		{"fork", func(w *ahWorld) { w.add(pg{omitted: 1}) }, "partial/fork"},
		{"root_missing", func(w *ahWorld) {
			w.add(pg{roots: append(w.honestRoots(), rt(11, other("x"), "countersigned", ahTS("08:01:00.000")))})
		}, "partial/root_missing"},
		{"no_root_found", func(w *ahWorld) { w.noPin = true; w.add(pg{noRoots: true}) }, "partial/no_root_found"},
		{"established, up to the largest found root, whenever recorded", func(w *ahWorld) {
			w.add(pg{roots: append(w.honestRoots(), rt(8, w.root(8), "reported", ahTS("08:29:00.000")))})
		}, "established/"},
	}
	for _, f := range cases {
		t.Run(f.why, func(t *testing.T) {
			w := newAHWorld(t)
			f.setup(w)
			res := w.run()
			c := res.Stats.AnchorHistory.Completeness
			if got := c.Status + "/" + deref(c.Reason); got != f.want {
				t.Errorf("completeness %s, want %s; findings %+v", got, f.want, res.Findings)
			}
			if f.want == "established/" && (c.UpToTreeSize == nil || *c.UpToTreeSize != 8) {
				t.Errorf("up_to_tree_size %v", c.UpToTreeSize)
			}
		})
	}
}

// TestAffiliationReference holds 8.8.6 against its reference values: the
// period of the package 00:30:01.000 to 00:58:00.000 (R), two established
// receipts, known_since 2025-12-01, H* fresh unless said otherwise.
func TestAffiliationReference(t *testing.T) {
	ms := func(s string) int64 { t, _ := parseUTC(s); return unixMS(t) }
	day := func(c string) string { return "2026-01-01T" + c + "Z" }
	h := &ahRun{hasR: true, rMS: ms(day("00:58:00.000"))}
	receipts := []int64{ms(day("00:30:01.000")), ms(day("01:00:01.000"))}
	page := func(ts, known string, since int64, fresh bool, ps ...ahPeriod) *ahPage {
		c := &ahContent{serverTS: ts, serverMS: ms(ts), knownSince: known, since: since, next: -1, periods: ps,
			roots: []ahRec{{t: 15, ms: receipts[0]}, {t: 28, ms: receipts[1]}}}
		if known != "" {
			c.knownMS = ms(known)
		}
		return &ahPage{c: c, fresh: fresh, jcs: ts}
	}
	per := func(bases []string, from, until string) ahPeriod {
		p := ahPeriod{bases: bases, from: from, fromMS: ms(from), until: until, recorded: from, recordedMS: ms(from)}
		if until != "" {
			p.untilMS = ms(until)
		}
		return p
	}
	ks := "2025-12-01T00:00:00.000Z"
	cc := []string{"common_control"}
	cases := []struct {
		why      string
		pages    []*ahPage
		complete bool
		status   string
		reason   string
		in       int
		outside  int
	}{
		{"an open period common_control", []*ahPage{page(day("01:02:00.000"), ks, 0, true, per(cc, "2025-06-01T00:00:00.000Z", ""))}, true, AffAffiliated, "", 2, 0},
		{"only a period 2025-06-01 to 2025-12-01", []*ahPage{page(day("01:02:00.000"), ks, 0, true, per(cc, "2025-06-01T00:00:00.000Z", "2025-12-01T00:00:00.000Z"))}, true, AffNotAffiliated, "", 0, 1},
		{"known_since 00:45", []*ahPage{page(day("01:02:00.000"), day("00:45:00.000"), 0, true)}, true, AffNotDetermined, "known_range_too_short", 0, 0},
		{"no fresh page", []*ahPage{page(day("00:40:00.000"), ks, 0, false)}, true, AffNotDetermined, "statement_does_not_cover_package", 0, 0},
		{"no fresh page and known_since 00:45: freshness first", []*ahPage{page(day("00:40:00.000"), day("00:39:00.000"), 0, false)}, true, AffNotDetermined, "statement_does_not_cover_package", 0, 0},
		{"only a page with since_tree_size 20", []*ahPage{page(day("01:02:00.000"), ks, 20, true)}, false, AffNotDetermined, "history_pages_missing", 0, 0},
		{"known_since null with an open period", []*ahPage{page(day("01:02:00.000"), "", 0, true, per(cc, "2025-06-01T00:00:00.000Z", ""))}, true, AffAffiliated, "", 2, 0},
		{"a period from 00:50", []*ahPage{page(day("01:02:00.000"), ks, 0, true, per(cc, day("00:50:00.000"), ""))}, true, AffAffiliated, "", 1, 0},
		{"an open period on an older page from 00:10 beside H* without a period", []*ahPage{
			page(day("00:10:00.000"), ks, 0, false, per(cc, "2025-06-01T00:00:00.000Z", "")), page(day("01:02:00.000"), ks, 0, true)}, true, AffNotAffiliated, "", 0, 1},
	}
	for _, f := range cases {
		t.Run(f.why, func(t *testing.T) {
			// Each page's recordings start at 00:30:01 (span_from).
			ev := h.evalAffiliation(f.pages, receipts, f.complete)
			if ev.status != f.status || ev.reason != f.reason || ev.inPeriods != f.in {
				t.Errorf("status %s reason %q in %d, want %s %q %d", ev.status, ev.reason, ev.inPeriods, f.status, f.reason, f.in)
			}
			out := 0
			for _, p := range ev.periods {
				if !p.OverlapsPackage {
					out++
				}
			}
			if out != f.outside {
				t.Errorf("%d periods outside, want %d: %+v", out, f.outside, ev.periods)
			}
			if msString(ev.spanFrom) != day("00:30:01.000") || msString(ev.spanTo) != day("00:58:00.000") {
				t.Errorf("span %s to %s", msString(ev.spanFrom), msString(ev.spanTo))
			}
		})
	}
	// The last reference value also names the reason of H5 that marks the
	// statement contradictory (8.8.6 number 9).
	a := &ahContent{serverMS: ms(day("00:10:00.000")), periods: []ahPeriod{per(cc, "2025-06-01T00:00:00.000Z", "")}, next: -1}
	b := &ahContent{serverMS: ms(day("01:02:00.000")), next: -1}
	if got := comparePages(a, b); len(got) != 1 || got[0].code != "affiliation_narrowed" {
		t.Errorf("H5 %+v", got)
	}
}

// TestHistoryAffiliationRun: an affiliation stated by the vendor is shown
// and changes neither the exit code nor a finding (8.8.6), and the vendor
// itself as the customer is named (vendor_itself).
func TestHistoryAffiliationRun(t *testing.T) {
	w := newAHWorld(t)
	w.add(pg{periods: []any{
		period([]any{"former_relation"}, "2025-01-01T00:00:00.000Z", "2025-06-01T00:00:00.000Z", "2025-01-02T00:00:00.000Z", false),
		period([]any{"participation", "vendor"}, ahTS("08:05:00.000"), nil, ahTS("08:05:00.000"), true),
	}})
	res := w.run()
	wantClasses(t, res, 0)
	af := res.Stats.Affiliation
	if af.Status != AffAffiliated || !af.VendorItself || strings.Join(af.Bases, ",") != "participation,vendor" || af.Contradictory {
		t.Fatalf("affiliation %+v", af)
	}
	if len(af.Periods) != 2 || af.Periods[0].OverlapsPackage || !af.Periods[1].OverlapsPackage || af.Periods[1].Until != nil || !af.Periods[1].Merged {
		t.Errorf("periods %+v", af.Periods)
	}
	if *af.ReceiptsTotal != 2 || *af.ReceiptsInPeriods != 1 || *af.ReceiptsAfterStatement != 0 {
		t.Errorf("counts %d %d %d", *af.ReceiptsTotal, *af.ReceiptsInPeriods, *af.ReceiptsAfterStatement)
	}
	for _, lang := range []string{"de", "en"} {
		txt := RenderText(res, "pkg", lang)
		want := map[string]string{"de": "Verbundenheit mit dem Hersteller: VERBUNDEN nach Angabe des Herstellers: Kunde ist der Hersteller selbst (ab 2026-10-10T08:05:00.000Z andauernd (zusammengefasst)). 1 von 2 Gegensignaturen",
			"en": "Affiliation with the vendor: AFFILIATED according to the vendor: the customer is the vendor itself (from 2026-10-10T08:05:00.000Z, ongoing (merged)). 1 of 2 countersignatures"}[lang]
		if !strings.Contains(txt, want) {
			t.Errorf("%s text lacks %q:\n%s", lang, want, txt)
		}
	}
}

// TestHistoryLinked: a predecessor chain named by a page of the package
// (H2 number 7), its own device binding (number 8), the handover (H9),
// succession_mismatch (H5) and the linked result of the affiliation (8.8.6
// number 11).
func TestHistoryLinked(t *testing.T) {
	const l = "0f0e0d0c-0b0a-4900-8807-0605040302cc"
	pred := map[string]any{"chain_id": l, "tree_size": int64(4)}
	lRoots := func(w *ahWorld) []map[string]any {
		return []map[string]any{rt(2, other("l2"), "countersigned", ahTS("07:00:00.000")), rt(4, other("l4"), "countersigned", ahTS("07:10:00.000"))}
	}
	cases := []struct {
		why   string
		setup func(w *ahWorld)
		want  ahCheck
	}{
		{"an honest predecessor", func(w *ahWorld) {
			w.add(pg{pred: pred})
			w.add(pg{chain: l, roots: lRoots(w), succ: map[string]any{"chain_id": w.g.chainID, "tree_size": int64(4)}, ts: ahTS("08:32:00.000"),
				periods: []any{period([]any{"vendor"}, "2026-01-01T00:00:00.000Z", nil, "2026-01-01T00:00:00.000Z", false)}})
		}, ahCheck{exit: 0, compl: "established/", notes: []string{"predecessor_differs_from_genesis"}, check: func(t *testing.T, res Result) {
			ah, af := res.Stats.AnchorHistory, res.Stats.Affiliation
			if ah.Pages.UsedLinked != 1 || ah.Predecessor == nil || ah.Predecessor.ChainID != l || ah.Roots.Distinct != 2 {
				t.Errorf("pages %+v predecessor %+v roots %+v", ah.Pages, ah.Predecessor, ah.Roots)
			}
			if len(af.Linked) != 1 || af.Linked[0].ChainID != l || af.Linked[0].Relation != "predecessor" || af.Linked[0].Status != AffAffiliated || af.Status != AffNotAffiliated {
				t.Errorf("affiliation %+v linked %+v", af, af.Linked)
			}
		}}},
		{"a root of the predecessor beyond the handover", func(w *ahWorld) {
			w.add(pg{pred: pred})
			w.add(pg{chain: l, roots: append(lRoots(w), rt(5, other("l5"), "countersigned", ahTS("07:20:00.000")), rt(6, other("l6"), "reported", ahTS("07:21:00.000"))),
				succ: map[string]any{"chain_id": w.g.chainID, "tree_size": int64(4)}})
		}, ahCheck{exit: 1, classes: []string{ClsHistoryFork}, reasons: map[string][]string{ClsHistoryFork: {"predecessor_beyond_handover"}}, compl: "partial/fork",
			notes: []string{"reported_beyond_handover", "predecessor_differs_from_genesis"}}},
		{"succession_mismatch: the predecessor names another tree_size", func(w *ahWorld) {
			w.add(pg{pred: pred})
			w.add(pg{chain: l, roots: lRoots(w), succ: map[string]any{"chain_id": w.g.chainID, "tree_size": int64(3)}, edit: func(m map[string]any) { m["reference_tree_size"] = int64(4) }})
		}, ahCheck{exit: 1, classes: []string{ClsHistoryContradict, ClsHistoryFork}, reasons: map[string][]string{ClsHistoryContradict: {"succession_mismatch"}, ClsHistoryFork: {"predecessor_beyond_handover"}},
			compl: "partial/contradiction"}},
		{"a page of the predecessor bound to the device of the package chain only", func(w *ahWorld) {
			w.add(pg{pred: pred})
			w.add(pg{chain: l, roots: lRoots(w), owner: []any{w.owner()}})
		}, ahCheck{exit: 1, classes: []string{ClsHistoryUnverified}, reasons: map[string][]string{ClsHistoryUnverified: {"owner_differs"}}, compl: "established/",
			check: func(t *testing.T, res Result) {
				// The pages of the package still match their device.
				if o := res.Stats.AnchorHistory.Owner; o == nil || *o != "matches" {
					t.Errorf("owner %v", o)
				}
			}}},
		{"a page of a chain no page of the package names", func(w *ahWorld) {
			w.add(pg{})
			w.add(pg{chain: l, roots: lRoots(w)})
		}, ahCheck{exit: 1, classes: []string{ClsHistoryUnverified}, reasons: map[string][]string{ClsHistoryUnverified: {"other_chain"}}, compl: "established/"}},
	}
	for _, f := range cases {
		t.Run(f.why, func(t *testing.T) {
			w := newAHWorld(t)
			f.setup(w)
			f.want.verify(t, w.run())
		})
	}
}

// TestHistorySuccessorLinked: succession_mismatch in the other direction
// (format spec 8.8.4 H5): L is the successor chain named by a page of the
// package, and every used page of L with a predecessor must name {C, T}.
func TestHistorySuccessorLinked(t *testing.T) {
	const s = "0f0e0d0c-0b0a-4900-8807-0605040302dd"
	succ := map[string]any{"chain_id": s, "tree_size": int64(100)}
	sRoots := []map[string]any{rt(3, other("s3"), "countersigned", ahTS("08:40:00.000"))}
	cases := []struct {
		why   string
		setup func(w *ahWorld)
		want  ahCheck
	}{
		{"an honest successor", func(w *ahWorld) {
			w.add(pg{succ: succ})
			w.add(pg{chain: s, roots: sRoots, pred: map[string]any{"chain_id": w.g.chainID, "tree_size": int64(100)}, ts: ahTS("08:45:00.000")})
		}, ahCheck{exit: 0, compl: "established/", check: func(t *testing.T, res Result) {
			if ah := res.Stats.AnchorHistory; ah.Pages.UsedLinked != 1 {
				t.Errorf("pages %+v", ah.Pages)
			}
		}}},
		{"the successor names another tree_size", func(w *ahWorld) {
			w.add(pg{succ: succ})
			w.add(pg{chain: s, roots: sRoots, pred: map[string]any{"chain_id": w.g.chainID, "tree_size": int64(99)}, ts: ahTS("08:45:00.000")})
		}, ahCheck{exit: 1, classes: []string{ClsHistoryContradict}, reasons: map[string][]string{ClsHistoryContradict: {"succession_mismatch"}},
			compl: "partial/contradiction"}},
		{"a successor page without predecessor is not compared", func(w *ahWorld) {
			w.add(pg{succ: succ})
			w.add(pg{chain: s, roots: sRoots, ts: ahTS("08:45:00.000")})
		}, ahCheck{exit: 0, compl: "established/"}},
	}
	for _, f := range cases {
		t.Run(f.why, func(t *testing.T) {
			w := newAHWorld(t)
			f.setup(w)
			f.want.verify(t, w.run())
		})
	}
}

// TestHistoryContradictoryOnlyPackage: affiliation_narrowed between two
// pages of a linked chain is a finding, but it neither hinders the
// completeness of the package (H11) nor sets contradictory (8.8.6 number 9).
func TestHistoryContradictoryOnlyPackage(t *testing.T) {
	const l = "0f0e0d0c-0b0a-4900-8807-0605040302cc"
	w := newAHWorld(t)
	w.add(pg{pred: map[string]any{"chain_id": l, "tree_size": int64(4)}})
	lRoots := []map[string]any{rt(2, other("l2"), "countersigned", ahTS("07:00:00.000")), rt(4, other("l4"), "countersigned", ahTS("07:10:00.000"))}
	lSucc := map[string]any{"chain_id": w.g.chainID, "tree_size": int64(4)}
	w.add(pg{chain: l, roots: lRoots, succ: lSucc, ts: ahTS("08:20:00.000"),
		periods: []any{period([]any{"vendor"}, "2026-01-01T00:00:00.000Z", nil, "2026-01-01T00:00:00.000Z", false)}})
	w.add(pg{chain: l, roots: lRoots, succ: lSucc, ts: ahTS("08:32:00.000")})
	ahCheck{exit: 1, classes: []string{ClsHistoryContradict}, reasons: map[string][]string{ClsHistoryContradict: {"affiliation_narrowed"}},
		compl: "established/", check: func(t *testing.T, res Result) {
			if af := res.Stats.Affiliation; af.Contradictory {
				t.Errorf("contradictory set by pages of a linked chain: %+v", af)
			}
		}}.verify(t, w.run())
}

// TestAffiliationLinkedOwnSteps holds format spec 8.8.6 number 11: for a
// linked chain the steps run with its own used pages; there are no
// established receipts (numbers 5, 7 (a) and 10), span_from comes from the
// roots of its pages alone, and condition 7 (c) reads the coverage of H4
// over its own used pages, with R over the fresh ones.
func TestAffiliationLinkedOwnSteps(t *testing.T) {
	const l = "0f0e0d0c-0b0a-4900-8807-0605040302cc" // predecessor
	const s = "0f0e0d0c-0b0a-4900-8807-0605040302dd" // successor
	vend := []any{"vendor"}
	lRoots := []map[string]any{rt(2, other("l2"), "countersigned", ahTS("07:00:00.000")), rt(4, other("l4"), "countersigned", ahTS("07:10:00.000"))}
	pred := map[string]any{"chain_id": l, "tree_size": int64(4)}
	cases := []struct {
		why     string
		noR     bool
		setup   func(w *ahWorld)
		status  string // of the one linked chain
		overlap []bool // overlaps_package of its periods, nil: not checked
	}{
		// The period of the successor ends at 08:20, after the first
		// receipt of the package (08:00:02) and before the first root of
		// the successor (08:40): it lies outside the successor's own period.
		{"number 5: span_from from the roots of the linked chain alone", true, func(w *ahWorld) {
			w.add(pg{succ: map[string]any{"chain_id": s, "tree_size": int64(100)}})
			w.add(pg{chain: s, roots: []map[string]any{rt(3, other("s3"), "countersigned", ahTS("08:40:00.000"))},
				pred: map[string]any{"chain_id": w.g.chainID, "tree_size": int64(100)}, ts: ahTS("08:45:00.000"),
				periods: []any{period(vend, "2026-01-01T00:00:00.000Z", ahTS("08:20:00.000"), ahTS("08:20:00.000"), false)}})
		}, AffNotAffiliated, []bool{false}},
		// Without R, H* of the predecessor (08:05) lies before the last
		// receipt of the package (08:11:04); these receipts are not the
		// predecessor's, so condition 7 (a) holds.
		{"number 7 (a): no established receipts without R", true, func(w *ahWorld) {
			w.add(pg{pred: pred})
			w.add(pg{chain: l, roots: lRoots, succ: map[string]any{"chain_id": w.g.chainID, "tree_size": int64(4)}, ts: ahTS("08:05:00.000")})
		}, AffNotAffiliated, nil},
		{"number 7 (c): the coverage of its own pages has a gap", false, func(w *ahWorld) {
			w.add(pg{pred: pred})
			w.add(pg{chain: l, roots: lRoots, succ: map[string]any{"chain_id": w.g.chainID, "tree_size": int64(4)}, ts: ahTS("08:32:00.000"), since: 2})
		}, AffNotDetermined, nil},
		{"number 7 (c): with R only the fresh pages cover", false, func(w *ahWorld) {
			w.add(pg{pred: pred})
			lSucc := map[string]any{"chain_id": w.g.chainID, "tree_size": int64(4)}
			w.add(pg{chain: l, noRoots: true, succ: lSucc, ts: ahTS("08:10:00.000"), next: int64(2), truncated: true})
			w.add(pg{chain: l, roots: lRoots, succ: lSucc, ts: ahTS("08:32:00.000"), since: 2})
		}, AffNotDetermined, nil},
		{"number 7 (c): two fresh pages cover together", false, func(w *ahWorld) {
			w.add(pg{pred: pred})
			lSucc := map[string]any{"chain_id": w.g.chainID, "tree_size": int64(4)}
			w.add(pg{chain: l, noRoots: true, succ: lSucc, ts: ahTS("08:16:00.000"), next: int64(2), truncated: true})
			w.add(pg{chain: l, roots: lRoots, succ: lSucc, ts: ahTS("08:32:00.000"), since: 2})
		}, AffNotAffiliated, nil},
	}
	for _, f := range cases {
		t.Run(f.why, func(t *testing.T) {
			w := newAHWorld(t)
			if f.noR {
				w.r = ""
			}
			f.setup(w)
			res := w.run()
			wantClasses(t, res, 0)
			af := res.Stats.Affiliation
			// The package itself is judged over its own pages and receipts.
			if af.Status != AffNotAffiliated || *af.ReceiptsTotal != 2 {
				t.Errorf("affiliation of the package %+v", af)
			}
			if len(af.Linked) != 1 || af.Linked[0].Status != f.status {
				t.Fatalf("linked %+v, want status %s", af.Linked, f.status)
			}
			if f.overlap != nil {
				var got []bool
				for _, p := range af.Linked[0].Periods {
					got = append(got, p.OverlapsPackage)
				}
				if fmt.Sprint(got) != fmt.Sprint(f.overlap) {
					t.Errorf("overlaps_package %v, want %v", got, f.overlap)
				}
			}
		})
	}
}

// TestHistoryNotSupplied: without an anchor history both objects are
// present with status not_supplied and not_checked (10.10.1, 10.10.2);
// requested_at and the note requested_at_unused follow 10.8; with a format
// error both are null.
func TestHistoryNotSupplied(t *testing.T) {
	w := newAHWorld(t)
	w.r = ""
	res := w.run()
	b, _ := json.Marshal(res.Stats.AnchorHistory)
	want := `{"status":"not_supplied","requested_at":null,"files":0,"pages":{"supplied":0,"distinct":0,"used_fresh":0,"used_stale":0,"used_unjudged":0,"used_linked":0,"not_used":0},"page_reasons":[],"issued":{"first":null,"last":null},"keys":[],"owner":null,"coverage":{"status":"none","gaps":[]},"reference_tree_size":null,"predecessor":null,"successor":null,"roots":{"distinct":0,"found":0,"differing_before_request":0,"differing_after_request":0,"beyond_package_before_request":0,"beyond_package_recent":0,"beyond_package_after_request":0,"beyond_package_unjudged":0,"not_used_vendor_log":0},"forks":{"listed":0,"omitted":0},"receipts":{"checked":0,"in_history":0,"not_in_history":0,"not_in_history_unestablished":0,"server_ts_differs":0,"before_legacy_boundary":0,"not_covered":0},"completeness":{"status":"not_established","reason":"not_supplied","up_to_tree_size":null},"reasons":{"unverified":[],"defective":[],"contradiction":[],"fork":[]},"notes":[]}`
	if string(b) != want {
		t.Errorf("anchor_history\n%s\nwant\n%s", b, want)
	}
	b, _ = json.Marshal(res.Stats.Affiliation)
	if want := `{"status":"not_checked","reason":null,"bases":[],"vendor_itself":false,"span":null,"as_of":null,"known_since":null,"stated_by":null,"periods":[],"receipts_total":null,"receipts_in_periods":null,"receipts_after_statement":null,"contradictory":false,"linked":[]}`; string(b) != want {
		t.Errorf("affiliation\n%s\nwant\n%s", b, want)
	}
	if c := res.Stats.Completeness; c == nil || c.Sources == nil || len(c.Sources) != 0 {
		t.Errorf("completeness.sources %+v", c)
	}
	w = newAHWorld(t)
	res = w.run()
	ah := res.Stats.AnchorHistory
	if ah.RequestedAt == nil || *ah.RequestedAt != ahR || strings.Join(ah.Notes, ",") != "requested_at_unused" {
		t.Errorf("requested_at %v notes %v", ah.RequestedAt, ah.Notes)
	}
	wantClasses(t, res, 0)
	// A format error: both objects are null.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	res = Verify(dir, Options{Now: w.now})
	if res.ExitCode != 3 || res.Stats.AnchorHistory != nil || res.Stats.Affiliation != nil {
		t.Errorf("exit %d anchor_history %v affiliation %v", res.ExitCode, res.Stats.AnchorHistory, res.Stats.Affiliation)
	}
	b, _ = json.Marshal(res.Stats)
	if !strings.Contains(string(b), `"anchor_history":null,"affiliation":null`) {
		t.Errorf("stats %s", b)
	}
}

// TestHistoryTextBlock: the block of the anchor history of 10.10.3 in both
// languages.
func TestHistoryTextBlock(t *testing.T) {
	w := newAHWorld(t)
	w.add(pg{})
	res := w.run()
	for lang, lines := range map[string][]string{
		"de": {"Anker-Historie: 1 von 1 Seiten verwendet (1 nach der Anforderung ausgestellt, 0 ältere Kopien), ausgestellt 2026-10-10T08:31:00.000Z bis 2026-10-10T08:31:00.000Z, Schlüssel st-1 (angeheftet); Gerät der Kette: passt zum Paket.",
			"  Anforderung des Pakets: 2026-10-10T08:30:00.000Z (Angabe des Prüfers).",
			"  Wurzeln: 2 verschieden; bis tree_size 10: 2 gefunden, 0 weichen ab; dahinter: 0 vor der Anforderung festgehalten, 0 in den 15 Minuten davor (Paket neu anfordern), 0 danach.",
			"  Vollständigkeit aus der Anker-Historie: belegt bis tree_size 6.",
			"  Verbundenheit mit dem Hersteller: keine im Zeitraum dieses Pakets (2026-10-10T08:00:02.000Z bis 2026-10-10T08:30:00.000Z, Zeiten des Herstellers) nach Angabe des Herstellers in der Anker-Historie vom 2026-10-10T08:31:00.000Z (Schlüssel st-1, angeheftet). Der Verifier prüft Signatur und Form dieser Angabe, nicht ihre Richtigkeit.",
			"Vollständigkeit:             belegt bis tree_size 6 durch die gefundenen erwarteten Wurzeln (Anker-Historie) (Spezifikation 8.6)"},
		"en": {"Anchor history: 1 of 1 pages used (1 issued after the request, 0 older copies), issued 2026-10-10T08:31:00.000Z to 2026-10-10T08:31:00.000Z, key st-1 (pinned); device of the chain: matches the package.",
			"  Completeness from the anchor history: evidenced up to tree_size 6."},
	} {
		txt := RenderText(res, "pkg", lang)
		for _, l := range lines {
			if !strings.Contains(txt, l+"\n") {
				t.Errorf("%s text lacks %q:\n%s", lang, l, txt)
			}
		}
	}
	// Pages supplied, none used.
	w = newAHWorld(t)
	w.add(pg{chain: "0f0e0d0c-0b0a-4900-8807-0605040302ff"})
	txt := RenderText(w.run(), "pkg", "de")
	// Format spec 10.10.3: the line on affiliation is the last line of the
	// block of the evidence level; with not_determined from level 2 on the
	// sentence open_at_level_2 follows.
	for _, l := range []string{"Anker-Historie: 1 Seiten übergeben, keine für dieses Paket verwendet (Seite einer anderen Kette).",
		"  Vollständigkeit aus der Anker-Historie: nicht belegt (keine Seite für dieses Paket verwendbar).",
		"  Verbundenheit mit dem Hersteller: NICHT FESTGESTELLT (Anker-Historie einer anderen Kette). " + tableDE["aff.open_at_level_2"]} {
		if !strings.Contains(txt, l+"\n") {
			t.Errorf("text lacks %q:\n%s", l, txt)
		}
	}
}

// historyBlockLines are the lines of the block of the anchor history and the
// line on affiliation of a text report: the block from its head line, empty
// lines left out, and the line on affiliation, which format spec 10.10.3
// makes the last line of the block of the evidence level (indented like
// every line of that block after its head).
func historyBlockLines(txt, lang string) []string {
	head := map[string]string{"de": "Anker-Historie:", "en": "Anchor history:"}[lang]
	level := map[string]string{"de": "Beweisstufe", "en": "Evidence level"}[lang]
	aff := map[string]string{"de": "  Verbundenheit mit dem Hersteller:", "en": "  Affiliation with the vendor:"}[lang]
	var out []string
	take := false
	for _, l := range strings.Split(txt, "\n") {
		switch {
		case strings.HasPrefix(l, head):
			take = true
		case strings.HasPrefix(l, level):
			take = false
		case strings.HasPrefix(l, aff):
			return append(out, l)
		}
		if take && l != "" {
			out = append(out, l)
		}
	}
	return out
}

// TestHistoryTextNoneUsedAndNotDetermined holds two phrases of format spec
// 10.10.3: the reason known_range_too_short reads differently when
// known_since is null (table of the reasons for not_determined), and with
// owner differs the text owner_differs_detail (registry
// verifier.anchor_history.texts) is the second line of the block when no
// page of the package is used, followed by the line on completeness.
func TestHistoryTextNoneUsedAndNotDetermined(t *testing.T) {
	detail := map[string]string{"de": "  " + tableDE["ah.owner_differs_detail"], "en": "  " + tableEN["ah.owner_differs_detail"]}
	cases := []struct {
		why   string
		page  pg
		owner string // anchor_history.owner, "" for null
		want  map[string][]string
	}{
		{"known_since null", pg{known: "null"}, "matches", map[string][]string{
			"de": {"  Verbundenheit mit dem Hersteller: NICHT FESTGESTELLT (der Hersteller kann den Kunden dieser Kette derzeit für keinen Zeitraum benennen). " + tableDE["aff.open_at_level_2"]},
			"en": {"  Affiliation with the vendor: NOT DETERMINED (the vendor currently cannot name the customer of this chain for any time). " + tableEN["aff.open_at_level_2"]}}},
		{"known_since after span_from", pg{known: ahTS("08:05:00.000")}, "matches", map[string][]string{
			"de": {"  Verbundenheit mit dem Hersteller: NICHT FESTGESTELLT (der Hersteller kann den Kunden dieser Kette erst ab 2026-10-10T08:05:00.000Z benennen). " + tableDE["aff.open_at_level_2"]},
			"en": {"  Affiliation with the vendor: NOT DETERMINED (the vendor can name the customer of this chain from 2026-10-10T08:05:00.000Z on). " + tableEN["aff.open_at_level_2"]}}},
		{"owner differs: owner_differs_detail as the second line", pg{owner: []any{other("another device")}}, "differs", map[string][]string{
			"de": {"Anker-Historie: 1 Seiten übergeben, keine für dieses Paket verwendet (" + tableDE["ah.reason."+hrOwnerDiffers] + ").",
				detail["de"],
				"  " + fillText(tableDE["ah.completeness_not_established"], "reason", tableDE["ah.compl.owner_differs"]),
				"  Verbundenheit mit dem Hersteller: NICHT FESTGESTELLT (" + tableDE["aff.reason.history_owner_differs"] + "). " + tableDE["aff.open_at_level_2"]},
			"en": {"Anchor history: 1 pages supplied, none used for this package (" + tableEN["ah.reason."+hrOwnerDiffers] + ").",
				detail["en"],
				"  " + fillText(tableEN["ah.completeness_not_established"], "reason", tableEN["ah.compl.owner_differs"]),
				"  Affiliation with the vendor: NOT DETERMINED (" + tableEN["aff.reason.history_owner_differs"] + "). " + tableEN["aff.open_at_level_2"]}}},
		{"another chain: no owner_differs_detail", pg{chain: "0f0e0d0c-0b0a-4900-8807-0605040302ff"}, "", map[string][]string{
			"de": {"Anker-Historie: 1 Seiten übergeben, keine für dieses Paket verwendet (Seite einer anderen Kette).",
				"  Vollständigkeit aus der Anker-Historie: nicht belegt (keine Seite für dieses Paket verwendbar).",
				"  Verbundenheit mit dem Hersteller: NICHT FESTGESTELLT (Anker-Historie einer anderen Kette). " + tableDE["aff.open_at_level_2"]}}},
	}
	for _, f := range cases {
		t.Run(f.why, func(t *testing.T) {
			w := newAHWorld(t)
			w.add(f.page)
			res := w.run()
			if o := res.Stats.AnchorHistory.Owner; deref(o) != f.owner {
				t.Errorf("owner %q, want %q", deref(o), f.owner)
			}
			for lang, want := range f.want {
				got := historyBlockLines(RenderText(res, "pkg", lang), lang)
				if len(want) == 1 {
					// Only the line on affiliation.
					got = got[len(got)-1:]
				}
				if strings.Join(got, "\n") != strings.Join(want, "\n") {
					t.Errorf("%s block\n%s\nwant\n%s", lang, strings.Join(got, "\n"), strings.Join(want, "\n"))
				}
			}
		})
	}
}

// TestHistoryTextsMatchRegistry holds the phrases of the anchor history and
// the affiliation against the registry (10.10.3: every phrase from the
// registry).
func TestHistoryTextsMatchRegistry(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		Verifier struct {
			AnchorHistory struct {
				Texts         map[string]map[string]string `json:"texts"`
				PageReasons   []string                     `json:"page_reasons"`
				PageTexts     map[string]map[string]string `json:"page_reason_texts"`
				ComplTexts    map[string]map[string]string `json:"completeness_reason_texts"`
				NoteTexts     map[string]map[string]string `json:"note_texts"`
				Notes         []string                     `json:"notes"`
				ReasonsBy     map[string][]string          `json:"reasons_by_class"`
				WhMS          int64                        `json:"w_h_ms"`
				Legacy        string                       `json:"legacy_boundary"`
				ComplReasons  []string                     `json:"completeness_reasons"`
				CoverStatuses []string                     `json:"coverage_statuses"`
			} `json:"anchor_history"`
			Affiliation struct {
				Texts       map[string]map[string]string `json:"texts"`
				ReasonTexts map[string]map[string]string `json:"reason_texts"`
				Bases       struct {
					Order []string                     `json:"order"`
					Codes map[string]map[string]string `json:"codes"`
				} `json:"bases"`
				Reasons []string `json:"not_determined_reasons"`
			} `json:"affiliation"`
		} `json:"verifier"`
	}
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatal(err)
	}
	ah, af := reg.Verifier.AnchorHistory, reg.Verifier.Affiliation
	groups := []struct {
		prefix string
		texts  map[string]map[string]string
	}{{"ah.", ah.Texts}, {"ah.reason.", ah.PageTexts}, {"ah.compl.", ah.ComplTexts}, {"ah.note.", ah.NoteTexts},
		{"aff.", af.Texts}, {"aff.reason.", af.ReasonTexts}, {"aff.basis.", af.Bases.Codes}}
	for _, g := range groups {
		for k, v := range g.texts {
			if (tableDE[g.prefix+k] != v["de"] || tableEN[g.prefix+k] != v["en"]) && specAheadText(t, g.prefix+k) {
				// Heartbeat spec 9.10 after the decisions of 26.10.: where
				// the registry lags the specification (former_relation: 24
				// months), the text of the specification decides
				// (speclag_test.go).
				t.Logf("%s%s: the registry %q / %q lags the specification", g.prefix, k, v["de"], v["en"])
				continue
			}
			for lang, tbl := range map[string]i18nTable{"de": tableDE, "en": tableEN} {
				if got := tbl[g.prefix+k]; got != v[lang] {
					t.Errorf("%s%s (%s) = %q, registry %q", g.prefix, k, lang, got, v[lang])
				}
			}
		}
	}
	// Heartbeat spec 9.10: former_relation lasts 24 months, never 730 days.
	for lang, tbl := range map[string]i18nTable{"de": tableDE, "en": tableEN} {
		if x := tbl["aff.basis.former_relation"]; strings.Contains(x, "730") || !strings.Contains(x, "24 ") {
			t.Errorf("aff.basis.former_relation (%s) = %q", lang, x)
		}
	}
	same := func(what string, a, b []string) {
		if strings.Join(a, ",") != strings.Join(b, ",") {
			t.Errorf("%s: %v, registry %v", what, a, b)
		}
	}
	same("page_reasons", historyPageReasons, ah.PageReasons)
	same("notes", historyNotes, ah.Notes)
	same("bases", affiliationBases, af.Bases.Order)
	for cls, list := range ah.ReasonsBy {
		same("reasons_by_class "+cls, historyReasonsByClass[cls], list)
	}
	if ah.WhMS != historyWhMS || ah.Legacy != historyLegacyBoundTS {
		t.Errorf("w_h_ms %d legacy_boundary %s", ah.WhMS, ah.Legacy)
	}
	var mapped []string
	seen := map[string]bool{}
	for _, x := range affReasonFromPage {
		if !seen[x.reason] {
			seen[x.reason] = true
			mapped = append(mapped, x.reason)
		}
	}
	same("not_determined_reasons (from pages)", mapped, af.Reasons[:len(mapped)])
}

// TestHistoryDeviceKeys: PK holds GENESIS.device_pubkey and every key of a
// KEY_ROTATION that 6.4 legitimizes (format spec 8.8.4); a page that names
// only the rotated key is bound to the device, one after a rotation that is
// not legitimate is not.
func TestHistoryDeviceKeys(t *testing.T) {
	for _, legit := range []bool{true, false} {
		t.Run(fmt.Sprintf("legitimate %v", legit), func(t *testing.T) {
			g := newGen(t)
			g.now = time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC)
			g.tsLayout = "2006-01-02T15:04:05.000Z07:00"
			g.genesis()
			g.checkpoint(time.Second)
			g.receiptForLast(time.Second)
			newPriv, newPub := keyFromSeed(3)
			signer := g.devPriv["dev-1"]
			if !legit {
				signer = newPriv
			}
			subject := canonGo(t, map[string]any{"old_key_id": "dev-1", "new_key_id": "dev-2", "new_pubkey": newPub})
			g.add(time.Minute, "KEY_ROTATION", "portal", map[string]any{"old_key_id": "dev-1", "new_key_id": "dev-2", "new_pubkey": newPub,
				"signature_by_old_key": hex.EncodeToString(ed25519.Sign(signer, subject))})
			g.devPriv["dev-2"], g.devPub["dev-2"], g.curKey = newPriv, newPub, "dev-2"
			g.checkpoint(time.Second)
			g.seal("shutdown")
			w := &ahWorld{t: t, g: g, r: ahR, now: time.Date(2026, 10, 10, 9, 30, 0, 0, time.UTC)}
			w.add(pg{owner: []any{ownerCommitment(ahApp, g.chainID, newPub)}, roots: []map[string]any{rt(1, g.merkleRootAt(1), "countersigned", ahTS("08:00:02.000"))}})
			res := w.run()
			o := res.Stats.AnchorHistory.Owner
			if legit && (o == nil || *o != "matches") || !legit && (o == nil || *o != "differs") {
				t.Errorf("owner %v; findings %+v", o, res.Findings)
			}
		})
	}
}

// TestHistoryPageContent: H2 number 5 (format spec 8.8.4) with the members
// and types of heartbeat spec 9.7 and registry cloud_statements.
// anchor_history_v2, and every page rule 1 to 10. Each violation on a
// signed page is ANCHOR_HISTORY_CONTRADICTION page_rules; none panics.
func TestHistoryPageContent(t *testing.T) {
	w := newAHWorld(t)
	setRoot := func(i int, k string, v any) func(m map[string]any) {
		return func(m map[string]any) { m["roots"].([]any)[i].(map[string]any)[k] = v }
	}
	aff := func(k string, v any) func(m map[string]any) {
		return func(m map[string]any) { m["affiliation"].(map[string]any)[k] = v }
	}
	cc := []any{"common_control"}
	withPeriods := func(ps ...any) func(m map[string]any) { return aff("periods", ps) }
	fork := func(t int64, root, ts string) map[string]any {
		return map[string]any{"tree_size": t, "merkle_root": root, "detected_ts": ts}
	}
	cases := []struct {
		why  string
		edit func(m map[string]any)
	}{
		{"an extra member", func(m map[string]any) { m["extra"] = true }},
		{"a member missing", func(m map[string]any) { delete(m, "forks_omitted") }},
		{"chain_id not a uuid", func(m map[string]any) { m["chain_id"] = "0F0E0D0C-0B0A-4900-8807-060504030201" }},
		{"owner_keys empty", func(m map[string]any) { m["owner_keys"] = []any{} }},
		{"owner_keys with 17 entries", func(m map[string]any) {
			var ks []any
			for i := 0; i < 17; i++ {
				ks = append(ks, fmt.Sprintf("%064x", i))
			}
			m["owner_keys"] = ks
		}},
		{"predecessor with an extra member", func(m map[string]any) {
			m["predecessor"] = map[string]any{"chain_id": "0f0e0d0c-0b0a-4900-8807-0605040302bb", "tree_size": int64(1), "x": 1}
		}},
		{"successor tree_size 0", func(m map[string]any) {
			m["successor"] = map[string]any{"chain_id": "0f0e0d0c-0b0a-4900-8807-0605040302bb", "tree_size": int64(0)}
		}},
		{"reference_tree_size negative", func(m map[string]any) { m["reference_tree_size"] = int64(-1) }},
		{"a root tree_size 0", setRoot(0, "tree_size", int64(0))},
		{"a root merkle_root in upper case", setRoot(0, "merkle_root", strings.ToUpper(w.root(1)))},
		{"a root recorded_as unknown", setRoot(0, "recorded_as", "witnessed")},
		{"a root server_ts not rfc3339", setRoot(0, "server_ts", "2026-10-10 08:00:02Z")},
		{"a fork detected_ts not in milliseconds", func(m map[string]any) { m["forks"] = []any{fork(6, other("f"), "2026-10-10T08:20:00Z")} }},
		{"forks_omitted not an int", func(m map[string]any) { m["forks_omitted"] = "0" }},
		{"truncated not a bool", func(m map[string]any) { m["truncated"] = int64(0) }},
		{"server_ts without milliseconds", func(m map[string]any) { m["server_ts"] = "2026-10-10T08:31:00Z" }},
		{"known_since not in milliseconds", aff("known_since", "2026-01-01T00:00:00Z")},
		{"affiliation with an extra member", aff("register", "x")},
		{"a period with an unknown basis", withPeriods(period([]any{"friendship"}, "2026-01-01T00:00:00.000Z", nil, "2026-01-01T00:00:00.000Z", false))},
		{"a period with no bases", withPeriods(period([]any{}, "2026-01-01T00:00:00.000Z", nil, "2026-01-01T00:00:00.000Z", false))},
		{"rule 1: truncated without next_since_tree_size", func(m map[string]any) { m["truncated"] = true }},
		{"rule 1: next_since_tree_size without truncated", func(m map[string]any) { m["next_since_tree_size"] = int64(20) }},
		{"rule 1: next_since_tree_size not above the roots", func(m map[string]any) { m["truncated"], m["next_since_tree_size"] = true, int64(6) }},
		{"rule 2: a root below since_tree_size", func(m map[string]any) { m["since_tree_size"] = int64(2) }},
		{"rule 3: roots out of order", func(m map[string]any) { rs := m["roots"].([]any); rs[0], rs[1] = rs[1], rs[0] }},
		{"rule 3: a root twice", func(m map[string]any) {
			m["roots"] = append(m["roots"].([]any), rt(6, w.root(6), "countersigned", ahTS("08:12:00.000")))
		}},
		{"rule 4: a fork twice", func(m map[string]any) {
			m["forks"] = []any{fork(6, other("f"), ahTS("08:20:00.000")), fork(6, other("f"), ahTS("08:21:00.000"))}
		}},
		{"rule 5: a root after the page", setRoot(1, "server_ts", ahTS("08:31:00.001"))},
		{"rule 5: a fork after the page", func(m map[string]any) { m["forks"] = []any{fork(6, other("f"), ahTS("08:40:00.000"))} }},
		{"rule 6: reference_tree_size below a recorded root", func(m map[string]any) { m["reference_tree_size"] = int64(5) }},
		{"rule 7: predecessor names the chain itself", func(m map[string]any) {
			m["predecessor"] = map[string]any{"chain_id": w.g.chainID, "tree_size": int64(1)}
		}},
		{"rule 7: predecessor and successor name one chain", func(m map[string]any) {
			m["predecessor"] = map[string]any{"chain_id": "0f0e0d0c-0b0a-4900-8807-0605040302bb", "tree_size": int64(1)}
			m["successor"] = map[string]any{"chain_id": "0f0e0d0c-0b0a-4900-8807-0605040302bb", "tree_size": int64(9)}
		}},
		{"rule 8: owner_keys not ascending", func(m map[string]any) { m["owner_keys"] = []any{strings.Repeat("f", 64), w.owner()} }},
		{"rule 9: known_since after server_ts", aff("known_since", ahTS("08:31:00.001"))},
		{"rule 10: bases not ascending", withPeriods(period([]any{"vendor", "participation"}, "2026-01-01T00:00:00.000Z", nil, "2026-01-01T00:00:00.000Z", false))},
		{"rule 10: from not before server_ts", withPeriods(period(cc, ahPageTS, nil, ahPageTS, false))},
		{"rule 10: recorded_ts after server_ts", withPeriods(period(cc, "2026-01-01T00:00:00.000Z", nil, ahTS("08:40:00.000"), false))},
		{"rule 10: until not after from", withPeriods(period(cc, "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z", false))},
		{"rule 10: until after server_ts", withPeriods(period(cc, "2026-01-01T00:00:00.000Z", ahTS("08:40:00.000"), "2026-01-01T00:00:00.000Z", false))},
		{"rule 10: an open period that is not the last", withPeriods(period(cc, "2026-01-01T00:00:00.000Z", nil, "2026-01-01T00:00:00.000Z", false),
			period(cc, "2026-02-01T00:00:00.000Z", nil, "2026-02-01T00:00:00.000Z", false))},
		{"rule 10: overlapping periods", withPeriods(period(cc, "2026-01-01T00:00:00.000Z", "2026-03-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z", false),
			period([]any{"vendor"}, "2026-02-01T00:00:00.000Z", nil, "2026-02-01T00:00:00.000Z", false))},
		{"rule 10: adjoining periods with the same bases", withPeriods(period(cc, "2026-01-01T00:00:00.000Z", "2026-02-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z", false),
			period(cc, "2026-02-01T00:00:00.000Z", nil, "2026-02-01T00:00:00.000Z", false))},
	}
	for _, f := range cases {
		t.Run(f.why, func(t *testing.T) {
			v, err := jcs.Parse(canonGo(t, func() map[string]any { m := w.statement(pg{}); f.edit(m); return m }()))
			if err != nil {
				t.Fatal(err)
			}
			if c, why := readHistoryContent(v); c != nil {
				t.Fatalf("accepted")
			} else if why == "" {
				t.Fatalf("no reason")
			}
		})
	}
	// Through the verifier: page_rules on a page of this chain blocks the
	// completeness (H11 (a)); on a page of another chain it does not.
	for _, f := range []struct {
		chain string
		want  string
	}{{"", "partial/contradiction"}, {"0f0e0d0c-0b0a-4900-8807-0605040302ff", "established/"}} {
		w := newAHWorld(t)
		w.add(pg{})
		w.add(pg{chain: f.chain, ts: ahTS("08:35:00.000"), edit: func(m map[string]any) { m["reference_tree_size"] = int64(5) }})
		res := w.run()
		c := res.Stats.AnchorHistory.Completeness
		if got := c.Status + "/" + deref(c.Reason); got != f.want {
			t.Errorf("chain %q: completeness %s, want %s", f.chain, got, f.want)
		}
		wantClasses(t, res, 1, ClsHistoryContradict)
	}
}

// TestHistoryReferenceVector runs the reference values of format spec 8.8.5
// on the frozen vector valid_sealed_export (its bytes unchanged) with a page
// built here under a pinned statements key: R = 00:58:00.000, so R - W_h =
// 00:43:00.000; differing roots at 20 (e 00:42:59.999) and 21 (e
// 00:43:00.000); 15 and 28 are found.
//
// N is the number of entries (7.4.10): the vector has 32 (28 is the
// tree_size of its last receipt), so the cases beyond the package use 33,
// 34 and 35, as the reference values of 8.8.5 do since 1.10.
func TestHistoryReferenceVector(t *testing.T) {
	const c = "3cef4d7e-4d65-41d6-912d-90d51fda8982"
	dir := filepath.Join(repoRoot(t), "spec", "testvectors", "valid_sealed_export")
	raw, err := os.ReadFile(filepath.Join(dir, "segments", "chain-000001.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var honest []any
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		v, _ := jcs.Parse([]byte(l))
		if v.Get("event_type").Str == "CHECKPOINT_RECEIPT" {
			p := v.Get("payload")
			honest = append(honest, rt(p.Get("tree_size").Int, p.Get("merkle_root").Str, "countersigned", p.Get("server_ts").Str))
		}
	}
	ts := func(clock string) string { return "2026-01-01T" + clock + "Z" }
	run := func(t *testing.T, r string, extra ...map[string]any) Result {
		roots := append([]any{}, honest...)
		for _, x := range extra {
			roots = append(roots, x)
		}
		sort.SliceStable(roots, func(i, j int) bool {
			return roots[i].(map[string]any)["tree_size"].(int64) < roots[j].(map[string]any)["tree_size"].(int64)
		})
		m := map[string]any{"kind": HistoryKindV2, "chain_id": c, "owner_keys": []any{"d0184bb5619fab41289c330c51c12d3353538b46f852fcfb31ef9b2f83a92a28"},
			"predecessor": nil, "successor": nil, "reference_tree_size": int64(35), "roots": roots, "forks": []any{}, "forks_omitted": int64(0),
			"since_tree_size": int64(0), "next_since_tree_size": nil, "truncated": false,
			"affiliation": map[string]any{"known_since": "2025-12-01T00:00:00.000Z", "periods": []any{}}, "server_ts": ts("01:02:00.000")}
		sj := string(canonGo(t, m))
		priv, pub := ahStmtKey()
		opt := Options{Now: time.Date(2026, 1, 1, 1, 3, 0, 1e6, time.UTC),
			VendorKeys: []VendorKey{{ID: "vendor-test-001", Pubkey: "959c448da9b35ea50abeca1f0a4cac57fc21c5b7ff7216d3e304bb5fc406d36c"}}}
		if err := opt.AddVendorStatementKey(ahStmtID + "=" + pub); err != nil {
			t.Fatal(err)
		}
		if err := opt.AddAnchorHistory(pageFile(t, sj, [2]string{ahStmtID, sign(priv, sj)})); err != nil {
			t.Fatal(err)
		}
		if r != "" {
			if err := opt.SetRequestedAt(r); err != nil {
				t.Fatal(err)
			}
		}
		if err := opt.FinishAuditorInputs(opt.Now); err != nil {
			t.Fatal(err)
		}
		return Verify(dir, opt)
	}
	d20, d21 := other("ref 20"), other("ref 21")
	recorded := []map[string]any{
		rt(20, d20, "countersigned", ts("00:42:59.999")), rt(21, d21, "countersigned", ts("00:43:00.000")),
		rt(33, other("ref 33"), "countersigned", ts("00:42:59.999")), rt(34, other("ref 34"), "countersigned", ts("00:43:00.000")),
		rt(35, other("ref 35"), "countersigned", ts("00:58:00.000")),
	}
	t.Run("with R", func(t *testing.T) {
		res := run(t, ts("00:58:00.000"), recorded...)
		wantClasses(t, res, 2, ClsMerkleInconsistent, ClsHistoryFork)
		if n := countClass(res, ClsMerkleInconsistent); n != 2 {
			t.Errorf("%d MERKLE_INCONSISTENT (20 and 33), want 2", n)
		}
		ah := res.Stats.AnchorHistory
		if ah.Roots != (HistoryRootsStat{Distinct: 7, Found: 2, DifferingBeforeRequest: 1, DifferingAfterRequest: 1, BeyondPackageBeforeRequest: 1, BeyondPackageRecent: 1, BeyondPackageAfterRequest: 1}) {
			t.Errorf("roots %+v", ah.Roots)
		}
		if strings.Join(ah.Reasons.Fork, ",") != "history_root_differs" || strings.Join(ah.Notes, ",") != "recent_roots_not_found,package_ended_before_request" {
			t.Errorf("fork %v notes %v", ah.Reasons.Fork, ah.Notes)
		}
		if c := ah.Completeness; c.Status != "partial" || deref(c.Reason) != "fork" {
			t.Errorf("completeness %s %s", c.Status, deref(c.Reason))
		}
	})
	t.Run("without R", func(t *testing.T) {
		res := run(t, "", recorded...)
		wantClasses(t, res, 1, ClsHistoryFork)
		if r := res.Stats.AnchorHistory.Roots; r.DifferingAfterRequest != 2 || r.BeyondPackageUnjudged != 3 || r.Found != 2 {
			t.Errorf("roots %+v", r)
		}
	})
	t.Run("only reported, before the band: never exit 2", func(t *testing.T) {
		res := run(t, ts("00:58:00.000"), rt(20, d20, "reported", ts("00:30:00.000")), rt(33, other("ref 33"), "reported", ts("00:30:00.000")))
		wantClasses(t, res, 1, ClsHistoryFork)
		if f := res.Stats.AnchorHistory.Reasons.Fork; strings.Join(f, ",") != "history_root_differs,reported_root_beyond_package" {
			t.Errorf("fork %v", f)
		}
	})
	t.Run("honest", func(t *testing.T) {
		res := run(t, ts("00:58:00.000"))
		wantClasses(t, res, 0)
		if c := res.Stats.AnchorHistory.Completeness; c.Status != "established" || *c.UpToTreeSize != 28 {
			t.Errorf("completeness %+v", c)
		}
		if rc := res.Stats.AnchorHistory.Receipts; rc.BeforeLegacyBoundary != 2 {
			t.Errorf("receipts %+v", rc)
		}
	})
}
