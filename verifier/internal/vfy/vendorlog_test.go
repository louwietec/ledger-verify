package vfy

// The vendor log (format spec 7.4, from edition 1.10): the reference values
// of 7.4.2 to 7.4.5 and the steps L2 to L10 of 7.4.10 through the whole
// verifier, on a generated chain with extracts built here from the
// specification: day entries signed by a protocol key, time stamps from
// tsa/tsatest, day trees with fillers and chain-day records.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
	"louwietec.com/ledger-verify/verifier/internal/tsa/tsatest"
)

func mustHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("not hex64: %q", s)
	}
	var x [32]byte
	copy(x[:], b)
	return x
}

func vh(b [32]byte) string { return hex.EncodeToString(b[:]) }

// auditPath is the RFC 6962 audit path of leaf m among the leaf hashes hs.
func auditPath(hs [][32]byte, m int) [][32]byte {
	if len(hs) <= 1 {
		return nil
	}
	k := 1
	for k*2 < len(hs) {
		k *= 2
	}
	if m < k {
		return append(auditPath(hs[:k], m), mthOfLeafHashes(hs[k:]))
	}
	return append(auditPath(hs[k:], m-k), mthOfLeafHashes(hs[:k]))
}

// TestVendorLogReferenceValues recomputes the reference values of format
// spec 2 (day arithmetic), 5 (empty tree), 7.4.2 (leaves), 7.4.3 (chain
// root, position, chain-day leaf), 7.4.4 (the day tree of size 5 and its
// path) and 7.4.5 (the example day entry and its day hash).
func TestVendorLogReferenceValues(t *testing.T) {
	// Format spec 2: dn(2026-01-01) = 739 616, end = 63 902 908 800 000.
	d, _ := parseDate("2026-01-01", true)
	if dn := dayNumber(d); dn != 739616 || dayEndMS(dn) != 63902908800000 {
		t.Errorf("dn(2026-01-01) = %d, end = %d", dn, dayEndMS(dn))
	}
	if s := dayString(739616); s != "2026-01-01" {
		t.Errorf("dayString(739616) = %s", s)
	}
	if one, _ := parseDate("0001-01-01", false); dayNumber(one) != 0 {
		t.Errorf("dn(0001-01-01) = %d", dayNumber(one))
	}
	// Format spec 5: MTH([]) = SHA-256("").
	if emptyRootHex != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("empty root %s", emptyRootHex)
	}

	// 7.4.2: the leaves of the record of chain 3cef4d7e (tree_size 42).
	c, a := "3cef4d7e-4d65-41d6-912d-90d51fda8982", "de431f78-75fd-49ae-b4bf-1cb543b635d1"
	rs := sha256.Sum256([]byte("LEDGER-BEISPIEL-WURZEL-42"))
	root := vh(rs)
	if root != "09b2745bcdf71ea82eff8696868a267edd6de0fcb1c82cc3de0020527dc23dae" {
		t.Fatalf("merkle_root %s", root)
	}
	gap := vlLeaf(c, 42, root, "gap_witness", "2026-03-01T23:58:00.000Z")
	cs := vlLeaf(c, 42, root, "countersigned", "2026-03-01T23:59:30.000Z")
	next := vlLeaf(c, 42, root, "countersigned", "2026-03-02T00:03:00.000Z")
	reformatted := vlLeaf(c, 42, root, "gap_witness", "2026-03-01T23:58:00Z")
	for _, f := range []struct {
		why  string
		leaf []byte
		n    int
		want string
	}{
		{"gap witness", gap, 228, "6ae954c9cd400501c3cb2600954f229bd90da369e5f51898f204a46beafb70ce"},
		{"countersignature", cs, 186, "b1a9c17ad92c0112bd915a40e050a26a4ab1da47e34528dba51d81811ca7a6c7"},
		{"countersignature on the following day", next, 186, "733e8945c2dec011786d37ccb6d89a75a92cb2b18ede80b114d339f9c50376c7"},
		{"re-formatted server_ts", reformatted, 0, "212101e4dbf2362aab8909859dbb633662e4aa1a0c098ae9df77a88b96dbfd30"},
	} {
		if got := vh(leafHash(f.leaf)); got != f.want || f.n != 0 && len(f.leaf) != f.n {
			t.Errorf("7.4.2 %s: leaf hash %s (%d bytes), want %s (%d)", f.why, got, len(f.leaf), f.want, f.n)
		}
	}
	// 7.4.3: same day, both leaves; the order of roots does not matter.
	for _, order := range [][][32]byte{{leafHash(gap), leafHash(cs)}, {leafHash(cs), leafHash(gap)}} {
		if got := vh(vlChainRoot(order)); got != "cde717fc82b66d14826268735294060bbf384f0631072c73f46c52056964efd1" {
			t.Errorf("7.4.3 chain root %s", got)
		}
	}
	pos := vlPosition(a, c, "2026-03-01")
	if vh(pos) != "927d08078b4fa065e881fb6f761a660bd2b7afec5be467348492ec1c0ad055a4" {
		t.Errorf("7.4.3 position %s", vh(pos))
	}
	if got := vh(leafHash(vlDayLeaf("cde717fc82b66d14826268735294060bbf384f0631072c73f46c52056964efd1", vh(pos)))); got != "43769b392d798a99f880ea91b7fb6ebb545c9d3f312fb6cfcf59313dba929dd0" {
		t.Errorf("7.4.3 chain-day leaf hash %s", got)
	}
	if got := vh(vlChainRoot([][32]byte{leafHash(next)})); got != "733e8945c2dec011786d37ccb6d89a75a92cb2b18ede80b114d339f9c50376c7" {
		t.Errorf("7.4.3 a chain root of one leaf is its leaf hash: %s", got)
	}
	if p := vlPosition(a, c, "2026-03-02"); vh(p) != "8b0fdc3d4d0ccec032096b89412a3206cf3a51da335c840859d9c7097925ecd8" {
		t.Errorf("7.4.3 position on the following day %s", vh(p))
	}

	// 7.4.4: the day tree of size 5 (one chain and the candidates 0 to 3).
	leaves := [][2]string{
		{"1e5fbe9853522662f2fea962e6ca6893d825da1d8096a69d7237e85e5b498617", "c549809bd9ab5ba2c4c5e70d2052961dfd0ec224e5ae6c7c74d3f3bab23d4a42"},
		{"2d92cc232ee3732c0d395e8cc32f5b1026f396de227190f940e42b453cf88f7c", "606ea38eb4866d33dc28409221cc5131240b31f69333f925507393a4f3bbda5a"},
		{"6a67ff9572b4d663920a2e740361b09ee2cb6acae8ecf613e6a30b16aad350f9", "27f678c7c3c9f763cb99aa6bfb4715d4667faa4b0d6c9f8a2e36e20250b4233c"},
		{"b1ed9cae78dcfafe822b101de7ce470c80f85b3838f7d2701da3de2b588e2c04", "b48375ab1d0a8b4e54d42d8a7c6239eea5ebac215b1b07f45cf8f912030bb2ea"},
		{"b579b898d722778e7776c38f5dc949ad5a516600bf3f6191dc19d156b6b614c9", "422e6e14cdbcb279e6970d8c3116968be422865376c874ede422aa127418da36"},
	}
	var lhs [][32]byte
	for _, l := range leaves {
		lhs = append(lhs, leafHash(vlDayLeaf(l[1], l[0])))
	}
	if vh(lhs[2]) != "294970b630c3526afb9c691702e0e939842253339bb6831386b70502f012f8c5" {
		t.Errorf("7.4.4 leaf hash of candidate 0: %s", vh(lhs[2]))
	}
	dayRoot := mthOfLeafHashes(lhs)
	if vh(dayRoot) != "0adcf8f084c1c9c0e8998f01a0a9a9b57e96b5e9135e2833cbb10c6a9e121871" {
		t.Errorf("7.4.4 root of the day tree %s", vh(dayRoot))
	}
	path := auditPath(lhs, 3)
	want := []string{"294970b630c3526afb9c691702e0e939842253339bb6831386b70502f012f8c5", "eab306e720e2cc96b755b9fc1a8e31f34e448adf0fa615f81ef4f54cfa05b4b0", "3bc3f3d4752763919917958440a1997224c1218d5ef038d09a9ca99d1eb88806"}
	for i := range want {
		if i >= len(path) || vh(path[i]) != want[i] {
			t.Fatalf("7.4.4 chain path %v", path)
		}
	}
	// 5: the inclusion with the size of the signed entry; the same path for
	// another size does not hold here.
	if err := verifyInclusion(lhs[3], 3, 5, path, dayRoot); err != nil {
		t.Errorf("7.4.4 inclusion of the chain at index 3: %v", err)
	}
	if err := verifyInclusion(lhs[3], 3, 9, path, dayRoot); err == nil {
		t.Errorf("7.4.4 the path held for size 9")
	}

	// 7.4.5: the example day entry, its day hash and its content.
	sj := `{"day":"2026-01-01","first_day":"2025-12-31","kind":"ledger.vendor_log_day.v1","log_id":"ledger-testprotokoll-1","prev_hash":"33fd1b2966e2f17af53d478066c97f1da0a181ed1107aaa34341eb4bc3067055","root":"0adcf8f084c1c9c0e8998f01a0a9a9b57e96b5e9135e2833cbb10c6a9e121871","server_ts":"2026-01-02T00:05:00.000Z","tree_size":5}`
	if h := sha256.Sum256([]byte(sj)); vh(h) != "ef330d2049e93b1da0e934a7a0e01e6b1dc26d392ffdac080ff0ec00889e2c1c" || len(sj) != 319 {
		t.Errorf("7.4.5 day hash %s, %d characters", vh(h), len(sj))
	}
	st, why := readStatement(sj, "ledger-testprotokoll-1")
	if st == nil {
		t.Fatalf("7.4.5 example refused: %s", why)
	}
	if st.dayS != "2026-01-01" || st.firstDayS != "2025-12-31" || st.treeSize != 5 || st.root != vh(dayRoot) || st.serverMS < dayEndMS(st.day) {
		t.Errorf("7.4.5 example read as %+v", st)
	}
}

// TestVendorLogStatementFormat is L2 (c): the content of a day entry after
// 7.4.5; a violation is VENDOR_LOG_CONTRADICTION "signed entry violates the
// format".
func TestVendorLogStatementFormat(t *testing.T) {
	base := map[string]any{"day": "2026-08-01", "first_day": "2026-07-31", "kind": kindDayEntry, "log_id": "lg", "prev_hash": strings.Repeat("a", 64), "root": strings.Repeat("b", 64), "server_ts": "2026-08-02T00:05:00.000Z", "tree_size": int64(4)}
	mk := func(edit func(m map[string]any)) string {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		if edit != nil {
			edit(m)
		}
		b, _ := jcs.CanonGo(m)
		return string(b)
	}
	for _, f := range []struct {
		why string
		sj  string
		ok  bool
	}{
		{"the base entry", mk(nil), true},
		{"tree_size 0", mk(func(m map[string]any) { m["tree_size"] = int64(0) }), true},
		{"not printable ASCII", strings.Replace(mk(nil), `"lg"`, `"lé"`, 1), false},
		{"a control character", strings.Replace(mk(nil), `"lg"`, "\"l\tg\"", 1), false},
		{"not its own JCS form (blank)", strings.Replace(mk(nil), `,"first_day"`, `, "first_day"`, 1), false},
		{"not its own JCS form (order)", `{"first_day":"2026-07-31","day":"2026-08-01"}`, false},
		{"duplicate member", `{"day":"2026-08-01","day":"2026-08-01"}`, false},
		{"not JSON", `{"day":`, false},
		{"an array", `[]`, false},
		{"a further member", mk(func(m map[string]any) { m["x"] = "y" }), false},
		{"a member missing", mk(func(m map[string]any) { delete(m, "root") }), false},
		{"kind", mk(func(m map[string]any) { m["kind"] = "ledger.vendor_log_day.v2" }), false},
		{"log_id of another log", mk(func(m map[string]any) { m["log_id"] = "other" }), false},
		{"day outside the log range", mk(func(m map[string]any) { m["day"] = "1999-12-31" }), false},
		{"day 9999-01-01", mk(func(m map[string]any) { m["day"] = "9999-01-01" }), false},
		{"first_day not a date", mk(func(m map[string]any) { m["first_day"] = "2026-02-30" }), false},
		{"prev_hash in upper case", mk(func(m map[string]any) { m["prev_hash"] = strings.Repeat("A", 64) }), false},
		{"root short", mk(func(m map[string]any) { m["root"] = "ab" }), false},
		{"server_ts without milliseconds", mk(func(m map[string]any) { m["server_ts"] = "2026-08-02T00:05:00Z" }), false},
		{"server_ts with microseconds", mk(func(m map[string]any) { m["server_ts"] = "2026-08-02T00:05:00.000000Z" }), false},
		{"server_ts not a date", mk(func(m map[string]any) { m["server_ts"] = "2026-02-30T00:05:00.000Z" }), false},
		{"tree_size negative", mk(func(m map[string]any) { m["tree_size"] = int64(-1) }), false},
		{"tree_size a string", mk(func(m map[string]any) { m["tree_size"] = "4" }), false},
	} {
		st, why := readStatement(f.sj, "lg")
		if (st != nil) != f.ok {
			t.Errorf("7.4.5 %s: accepted=%v (%s), want %v", f.why, st != nil, why, f.ok)
		}
	}
}

// ---------------------------------------------------------------- the world

// vlWorld is a chain with an honest vendor log: validSealedChain (two
// receipts on 2026-08-01), a log that begins 2026-07-31 with an empty day,
// the day 2026-08-01 with the chain-day leaf of the chain and three fillers,
// every entry signed by a protocol key and stamped by the probe time-stamping
// authority, the root of that authority supplied for the purpose log.
// Tests change it through the hooks before build.
type vlWorld struct {
	t        *testing.T
	g        *gen
	now      time.Time
	logID    string
	firstDay string
	days     []string // days with a day object, in order

	keyID   string
	key     ed25519.PrivateKey
	app     string // the appliance_id the vendor bound the chain to
	pin     bool   // pin the protocol key (--vendor-log-key)
	list    bool   // the protocol key list in the extract (protocol_keys)
	listEnd string
	logRoot bool // supply the root of the probe authority for the purpose log

	// Hooks: the members of a statement before it is written, the day
	// object, the chain-day records, the extract.
	entry   func(day string, m map[string]any)
	dayObj  func(day string, o map[string]any)
	stamps  func(day, sj string) []string
	records func(c []any) []any
	extract func(x map[string]any)
	// leaves adds leaves to the day tree of a day (after the chain and the
	// fillers, ordered by position with them).
	leaves func(day string) [][2]string
	// rows edits the roots of the chain's record before the tree is built.
	rows func(rows []map[string]any) []map[string]any
	// opts edits the auditor's inputs before they are finished.
	opts func(o *Options)

	// After build.
	stmts map[string]string // statement_jcs by day
	files [][]byte
}

const vlChainDay = "2026-08-01"

func newVLWorld(t *testing.T) *vlWorld {
	priv, _ := keyFromSeed(0x41)
	return &vlWorld{
		t: t, g: validSealedChain(t), now: time.Date(2026, 8, 2, 8, 0, 0, 0, time.UTC),
		logID: "vl-test-1", firstDay: "2026-07-31", days: []string{"2026-07-31", vlChainDay},
		keyID: "vl-key-1", key: priv, pin: true, logRoot: true, app: vlApp,
	}
}

func vlPub(k ed25519.PrivateKey) string { return hex.EncodeToString(k.Public().(ed25519.PublicKey)) }

// receiptRows are the rows of the chain's receipts with day(server_ts) =
// day, as the vendor recorded them (recorded_as countersigned).
func (w *vlWorld) receiptRows(day string) []map[string]any {
	var out []map[string]any
	for _, l := range w.g.lines {
		v, _ := jcs.Parse(l)
		if v.Get("event_type").Str != "CHECKPOINT_RECEIPT" {
			continue
		}
		p := v.Get("payload")
		if !strings.HasPrefix(p.Get("server_ts").Str, day) {
			continue
		}
		out = append(out, map[string]any{"tree_size": p.Get("tree_size").Int, "merkle_root": p.Get("merkle_root").Str, "recorded_as": "countersigned", "server_ts": p.Get("server_ts").Str})
	}
	return out
}

// fillers are three leaves of the day tree derived from the day; the
// verifier never tells them from chain-day leaves (7.4.4).
func fillers(day string) [][2]string {
	var out [][2]string
	for i := 0; i < 3; i++ {
		p := sha256.Sum256([]byte(fmt.Sprintf("filler position %s %d", day, i)))
		r := sha256.Sum256([]byte(fmt.Sprintf("filler root %s %d", day, i)))
		out = append(out, [2]string{vh(p), vh(r)})
	}
	return out
}

// dayTree orders leaves by position and returns the root, the leaf hashes
// and the index of position p (-1 when absent).
func dayTree(leaves [][2]string, p string) ([32]byte, [][32]byte, int) {
	sort.SliceStable(leaves, func(i, j int) bool { return leaves[i][0] < leaves[j][0] })
	var lhs [][32]byte
	idx := -1
	for i, l := range leaves {
		lhs = append(lhs, leafHash(vlDayLeaf(l[1], l[0])))
		if l[0] == p && idx < 0 {
			idx = i
		}
	}
	return mthOfLeafHashes(lhs), lhs, idx
}

func hexes(hs [][32]byte) []any {
	out := []any{}
	for _, h := range hs {
		out = append(out, vh(h))
	}
	return out
}

func (w *vlWorld) stamp(sj, genTime string) string {
	return base64.StdEncoding.EncodeToString(tsatest.Token(tsatest.TokenSpec{Subject: []byte(sj), Key: tsatest.RSA("tsa test rsa"), Cert: probeStelle(), GenTime: genTime}))
}

// genTimeAfter is a GeneralizedTime offset from the end of day.
func genTimeAfter(day string, d time.Duration) string {
	t, _ := time.Parse("2006-01-02", day)
	return t.Add(24*time.Hour + d).UTC().Format("20060102150405Z")
}

func (w *vlWorld) build() (string, Options) {
	t := w.t
	c := w.g.chainID
	a := w.app
	w.stmts = map[string]string{}
	var days []any
	var records []any
	prev := zeroHash
	for _, day := range w.days {
		pos := vlPosition(a, c, day)
		var leaves [][2]string
		rows := w.receiptRows(day)
		if w.rows != nil && day == vlChainDay {
			rows = w.rows(rows)
		}
		var crHex string
		if len(rows) > 0 {
			var lhs [][32]byte
			for _, r := range rows {
				lhs = append(lhs, leafHash(vlLeaf(c, r["tree_size"].(int64), r["merkle_root"].(string), r["recorded_as"].(string), r["server_ts"].(string))))
			}
			cr := vlChainRoot(lhs)
			crHex = vh(cr)
			leaves = append(leaves, [2]string{vh(pos), crHex})
			leaves = append(leaves, fillers(day)...)
		}
		if w.leaves != nil {
			leaves = append(leaves, w.leaves(day)...)
		}
		root, lhs, idx := dayTree(leaves, vh(pos))
		dt, _ := time.Parse("2006-01-02", day)
		m := map[string]any{"day": day, "first_day": w.firstDay, "kind": kindDayEntry, "log_id": w.logID, "prev_hash": prev,
			"root": vh(root), "server_ts": dt.Add(24*time.Hour + 5*time.Minute).Format("2006-01-02T15:04:05.000Z"), "tree_size": int64(len(leaves))}
		if day == w.firstDay {
			m["prev_hash"] = zeroHash
		}
		if w.entry != nil {
			w.entry(day, m)
		}
		sjB, err := jcs.CanonGo(m)
		if err != nil {
			t.Fatal(err)
		}
		sj := string(sjB)
		w.stmts[day] = sj
		h := sha256.Sum256(sjB)
		prev = vh(h)
		stamps := []any{w.stamp(sj, genTimeAfter(day, 10*time.Minute))}
		if w.stamps != nil {
			stamps = []any{}
			for _, s := range w.stamps(day, sj) {
				stamps = append(stamps, s)
			}
		}
		o := map[string]any{
			"entry":                 map[string]any{"statement_jcs": sj, "server_key_id": w.keyID, "server_signature": hex.EncodeToString(ed25519.Sign(w.key, sjB))},
			"timestamps":            stamps,
			"additional_signatures": []any{},
		}
		if w.dayObj != nil {
			w.dayObj(day, o)
		}
		days = append(days, o)
		if idx >= 0 {
			records = append(records, map[string]any{"day": day, "absent": nil, "present": map[string]any{
				"roots": func() []any {
					out := []any{}
					for _, r := range rows {
						out = append(out, r)
					}
					return out
				}(),
				"leaf_index": int64(idx), "path": hexes(auditPath(lhs, idx)),
			}})
		}
	}
	if w.records != nil {
		records = w.records(records)
	}
	x := map[string]any{"format": ExtractFormat, "log_id": w.logID, "chain_id": c, "protocol_keys": nil, "days": days, "chain_days": records}
	if records == nil {
		x["chain_days"] = []any{}
	}
	opt := Options{Now: w.now}
	if w.list {
		lst, root := w.protocolList()
		x["protocol_keys"] = lst
		opt.VendorRoots = append(opt.VendorRoots, root)
	}
	if w.extract != nil {
		w.extract(x)
	}
	b, err := json.Marshal(x)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.files) == 0 {
		w.files = [][]byte{b}
	}
	for _, f := range w.files {
		if err := opt.AddVendorLog(f); err != nil {
			t.Fatalf("the extract does not follow the grammar: %v", err)
		}
	}
	if w.pin {
		opt.VendorLogKeys = append(opt.VendorLogKeys, VendorKey{ID: w.keyID, Pubkey: vlPub(w.key)})
	}
	if w.logRoot {
		opt.VendorLogTSARoots = append(opt.VendorLogTSARoots, probeStelle())
	}
	opt = genAnker(opt)
	if w.opts != nil {
		w.opts(&opt)
	}
	if err := opt.FinishAuditorInputs(w.now); err != nil {
		t.Fatalf("unusable invocation: %v", err)
	}
	return w.g.writePkg(), opt
}

// protocolList is a protocol key list ledger-protokollschluessel/1 naming
// the protocol key, signed by a vendor root of the auditor.
func (w *vlWorld) protocolList() (map[string]any, VendorRoot) {
	rootKey, rootPub := keyFromSeed(0x42)
	k := map[string]any{"key_id": w.keyID, "pubkey": vlPub(w.key), "gueltig_ab": "2026-01-01T00:00:00Z"}
	if w.listEnd != "" {
		k["gueltig_bis"] = w.listEnd
	}
	l := map[string]any{"format": ProtocolKeyListFormat, "version": int64(1), "ausgestellt": "2026-07-30T10:00:00.000Z", "log_id": w.logID,
		"erster_tag": w.firstDay, "fuellerbindung": strings.Repeat("c", 64),
		"orte": []any{"https://one.example/vl-test-1", "https://two.example/vl-test-1"}, "schluessel": []any{k}}
	unsigned, _ := jcs.CanonGo(l)
	l["signatur"] = map[string]any{"wurzel_id": "vl-root", "sig": hex.EncodeToString(ed25519.Sign(rootKey, unsigned))}
	return l, VendorRoot{ID: "vl-root", Pubkey: rootPub}
}

func (w *vlWorld) run() Result {
	dir, opt := w.build()
	return Verify(dir, opt)
}

// reasonCodes lists the reason codes in the details of the findings of
// class, in the order they stand there.
func reasonCodes(res Result, cls string) []string {
	var out []string
	for _, f := range res.Findings {
		if f.Class != cls {
			continue
		}
		for _, part := range strings.Split(f.Detail, "[")[1:] {
			out = append(out, strings.SplitN(part, "]", 2)[0])
		}
	}
	return out
}

func hasCode(res Result, cls, code string) bool {
	for _, c := range reasonCodes(res, cls) {
		if c == code {
			return true
		}
	}
	return false
}

// TestVendorLogHonest: an honest log with a pinned protocol key or with a
// protocol key list (7.4.7, L1) changes nothing in the result (L10: exit 0
// stays 0) and shows every receipt included (L8).
func TestVendorLogHonest(t *testing.T) {
	for _, f := range []struct {
		why  string
		pin  bool
		list bool
		src  string
	}{
		{"pinned key", true, false, KeySourcePinned},
		{"protocol key list", false, true, KeySourceList},
		{"list and pin", true, true, KeySourceListAndPinned},
	} {
		t.Run(f.why, func(t *testing.T) {
			w := newVLWorld(t)
			w.pin, w.list = f.pin, f.list
			res := w.run()
			wantClasses(t, res, 0)
			vl := res.Stats.VendorLog
			if vl == nil || vl.Status != VendorLogChecked || vl.KeySource == nil || *vl.KeySource != f.src {
				t.Fatalf("vendor_log %+v", vl)
			}
			if vl.FirstDay == nil || *vl.FirstDay != "2026-07-31" || vl.LogID == nil || *vl.LogID != "vl-test-1" {
				t.Errorf("first_day/log_id %v %v", vl.FirstDay, vl.LogID)
			}
			if f.list != (vl.KeyList != nil) || f.list && (len(vl.Places) != 2 || vl.KeyList.Version != 1 || vl.KeyList.WurzelID != "vl-root" || vl.KeyList.RootSource != RootSourceAuditor) {
				t.Errorf("key_list %+v places %v", vl.KeyList, vl.Places)
			}
			if h := vl.Head; h == nil || h.Day != vlChainDay || !h.Witnessed || h.SeenIn != 1 || h.TreeSize != 4 {
				t.Errorf("head %+v", vl.Head)
			} else if sum := sha256.Sum256([]byte(w.stmts[vlChainDay])); h.DayHash != vh(sum) {
				t.Errorf("head day_hash %s", h.DayHash)
			}
			if d := vl.Days; d != (VendorLogDaysStat{Supplied: 2, Established: 2, Witnessed: 2}) {
				t.Errorf("days %+v", d)
			}
			if rc := vl.Receipts; rc == nil || rc.Included != 2 || rc.IncludedUpToTreeSize == nil || *rc.IncludedUpToTreeSize != 6 {
				t.Errorf("receipts %+v", vl.Receipts)
			}
			if vl.LastCountersigned == nil || *vl.LastCountersigned != RcIncluded {
				t.Errorf("last_countersigned %v", vl.LastCountersigned)
			}
			if lr := vl.LoggedRoots; lr == nil || *lr != (VendorLogRootsStat{MatchingPrefix: 2}) {
				t.Errorf("logged_roots %+v", vl.LoggedRoots)
			}
			if vl.TSA != (VendorLogTSAStat{CMSChecked: true, RootsSupplied: 1}) || vl.Files != 1 || vl.DistinctFiles != 1 {
				t.Errorf("tsa %+v files %d/%d", vl.TSA, vl.Files, vl.DistinctFiles)
			}
		})
	}
}

// object signs a statement with the world's protocol key into a day object
// with the given time stamps.
func (w *vlWorld) object(m map[string]any, stamps ...string) map[string]any {
	sj, _ := jcs.CanonGo(m)
	ts := []any{}
	for _, s := range stamps {
		ts = append(ts, s)
	}
	return map[string]any{
		"entry":                 map[string]any{"statement_jcs": string(sj), "server_key_id": w.keyID, "server_signature": hex.EncodeToString(ed25519.Sign(w.key, sj))},
		"timestamps":            ts,
		"additional_signatures": []any{},
	}
}

// statementOf reads back the members of the statement of a day.
func (w *vlWorld) statementOf(day string) map[string]any {
	var m map[string]any
	_ = json.Unmarshal([]byte(w.stmts[day]), &m)
	m["tree_size"] = int64(m["tree_size"].(float64))
	return m
}

const vlApp = "1a2b3c4d-5e6f-4a01-9b02-c3d4e5f60718"

// absentRecord is an absence proof for the chain on day against the day
// tree of leaves (format spec 5, forms (i) to (iv)).
func (w *vlWorld) absentRecord(day string, leaves [][2]string) map[string]any {
	p := vlDayPos(w, day)
	_, lhs, _ := dayTree(leaves, "")
	nb := []any{}
	n := func(i int) map[string]any {
		return map[string]any{"leaf_index": int64(i), "position": leaves[i][0], "chain_root": leaves[i][1], "path": hexes(auditPath(lhs, i))}
	}
	i := sort.Search(len(leaves), func(i int) bool { return leaves[i][0] > p })
	if i > 0 {
		nb = append(nb, n(i-1))
	}
	if i < len(leaves) {
		nb = append(nb, n(i))
	}
	return map[string]any{"day": day, "present": nil, "absent": map[string]any{"neighbours": nb}}
}

func vlDayPos(w *vlWorld, day string) string { p := vlPosition(vlApp, w.g.chainID, day); return vh(p) }

// withoutChain removes the chain from the day tree of vlChainDay and gives
// it the absence proof instead: the vendor left both receipts out.
func withoutChain(w *vlWorld) {
	w.rows = func([]map[string]any) []map[string]any { return nil }
	w.leaves = func(day string) [][2]string {
		if day == vlChainDay {
			return fillers(day)
		}
		return nil
	}
	w.records = func([]any) []any {
		l := fillers(vlChainDay)
		dayTree(l, "")
		return []any{w.absentRecord(vlChainDay, l)}
	}
}

type vlCase struct {
	why     string
	setup   func(w *vlWorld)
	exit    int
	classes []string
	// codes are the reason codes expected in the details, per class, in
	// this order.
	codes map[string][]string
	check func(t *testing.T, vl *VendorLogStat, res Result)
}

func runVLCases(t *testing.T, cases []vlCase) {
	for _, f := range cases {
		t.Run(f.why, func(t *testing.T) {
			w := newVLWorld(t)
			if f.setup != nil {
				f.setup(w)
			}
			res := w.run()
			wantClasses(t, res, f.exit, f.classes...)
			for cls, want := range f.codes {
				if got := reasonCodes(res, cls); strings.Join(got, ",") != strings.Join(want, ",") {
					t.Errorf("%s reasons %v, want %v; findings %+v", cls, got, want, res.Findings)
				}
			}
			if f.check != nil {
				if res.Stats.VendorLog == nil {
					t.Fatal("no vendor_log")
				}
				f.check(t, res.Stats.VendorLog, res)
			}
		})
	}
}

func receiptsAre(t *testing.T, vl *VendorLogStat, want VendorLogReceiptsStat) {
	t.Helper()
	got := vl.Receipts
	if got == nil {
		t.Fatalf("receipts null, want %+v", want)
	}
	g, w := *got, want
	g.IncludedUpToTreeSize, w.IncludedUpToTreeSize = nil, nil
	if g != w {
		t.Errorf("receipts %+v, want %+v", g, w)
	}
	if (got.IncludedUpToTreeSize == nil) != (want.IncludedUpToTreeSize == nil) || got.IncludedUpToTreeSize != nil && *got.IncludedUpToTreeSize != *want.IncludedUpToTreeSize {
		t.Errorf("included_up_to_tree_size %v, want %v", got.IncludedUpToTreeSize, want.IncludedUpToTreeSize)
	}
}

func i64(n int64) *int64 { return &n }

// TestVendorLogL1L2 covers step L1 item 4 (no protocol key) and step L2 (a)
// to (h) of format spec 7.4.10.
func TestVendorLogL1L2(t *testing.T) {
	stranger, _ := keyFromSeed(0x43)
	runVLCases(t, []vlCase{
		{why: "L1 item 4: no protocol key, no list", setup: func(w *vlWorld) { w.pin = false }, exit: 1,
			classes: []string{ClsVendorLogUnverified}, codes: map[string][]string{ClsVendorLogUnverified: {"no_protocol_key"}},
			check: func(t *testing.T, vl *VendorLogStat, res Result) {
				if vl.Status != VendorLogNoProtocolKey || vl.NoKeyReason != PReasonNoList || vl.Receipts != nil || vl.Head != nil || vl.LoggedRoots != nil || vl.KeySource != nil {
					t.Errorf("vendor_log %+v", vl)
				}
				if vl.Days != (VendorLogDaysStat{}) || vl.Files != 1 || vl.LogID == nil || vl.TSA.RootsSupplied != 1 || vl.LastCountersigned != nil {
					t.Errorf("counts %+v", vl)
				}
			}},
		{why: "L1 item 4: a list under a root the auditor did not supply", setup: func(w *vlWorld) {
			w.pin = false
			w.extract = func(x map[string]any) { l, _ := w.protocolList(); x["protocol_keys"] = l }
		}, exit: 1, classes: []string{ClsVendorLogUnverified}, check: func(t *testing.T, vl *VendorLogStat, res Result) {
			if vl.NoKeyReason != PReasonNoRoot {
				t.Errorf("reason %s", vl.NoKeyReason)
			}
		}},
		{why: "L2 (a): the entry under a key that is not established", setup: func(w *vlWorld) {
			w.dayObj = func(day string, o map[string]any) {
				if day == vlChainDay {
					o["entry"].(map[string]any)["server_key_id"] = "unknown-key"
				}
			}
		}, exit: 1, classes: []string{ClsVendorLogUnverified},
			codes: map[string][]string{ClsVendorLogUnverified: {"key_not_established", "days_not_supplied"}},
			check: func(t *testing.T, vl *VendorLogStat, res Result) {
				receiptsAre(t, vl, VendorLogReceiptsStat{Missing: 2})
				if vl.Days.Established != 1 || vl.Days.Missing != 1 || vl.Head.Day != "2026-07-31" {
					t.Errorf("days %+v head %+v", vl.Days, vl.Head)
				}
			}},
		{why: "L2 (a): a pair under an unknown key is passed over", setup: func(w *vlWorld) {
			w.dayObj = func(day string, o map[string]any) {
				o["additional_signatures"] = []any{map[string]any{"alg": "ed25519", "key_id": "unknown-key", "signature": strings.Repeat("0", 128)}}
			}
		}, exit: 0},
		{why: "L2 (a), (b): the entry under an unknown key, an additional signature of the protocol key", setup: func(w *vlWorld) {
			w.dayObj = func(day string, o map[string]any) {
				e := o["entry"].(map[string]any)
				o["additional_signatures"] = []any{map[string]any{"alg": "ed25519", "key_id": w.keyID, "signature": e["server_signature"]}}
				e["server_key_id"] = "unknown-key"
				e["server_signature"] = hex.EncodeToString(ed25519.Sign(stranger, []byte(e["statement_jcs"].(string))))
			}
		}, exit: 0},
		{why: "L2 (b): the signature does not hold", setup: func(w *vlWorld) {
			w.dayObj = func(day string, o map[string]any) {
				if day == vlChainDay {
					e := o["entry"].(map[string]any)
					e["server_signature"] = hex.EncodeToString(ed25519.Sign(w.key, []byte("other bytes")))
				}
			}
		}, exit: 1, classes: []string{ClsVendorLogDefective, ClsVendorLogUnverified},
			codes: map[string][]string{ClsVendorLogDefective: {"signature"}, ClsVendorLogUnverified: {"days_not_supplied"}},
			check: func(t *testing.T, vl *VendorLogStat, res Result) {
				receiptsAre(t, vl, VendorLogReceiptsStat{Missing: 2})
			}},
		{why: "L2 (b): one pair fails, another holds; reasons of one day merged in step order", setup: func(w *vlWorld) {
			w.dayObj = func(day string, o map[string]any) {
				if day == vlChainDay {
					o["additional_signatures"] = []any{map[string]any{"alg": "ed25519", "key_id": w.keyID, "signature": hex.EncodeToString(ed25519.Sign(w.key, []byte("x")))}}
					o["timestamps"] = append(o["timestamps"].([]any), "QQ==")
				}
			}
		}, exit: 1, classes: []string{ClsVendorLogDefective},
			codes: map[string][]string{ClsVendorLogDefective: {"signature", "timestamp_defective"}},
			check: func(t *testing.T, vl *VendorLogStat, res Result) {
				receiptsAre(t, vl, VendorLogReceiptsStat{Included: 2, IncludedUpToTreeSize: i64(6)})
				if n := len(res.Findings); n != 1 {
					t.Errorf("%d findings, want one per class and day", n)
				}
			}},
		{why: "L2: a seal of another alg is counted, never checked", setup: func(w *vlWorld) {
			w.dayObj = func(day string, o map[string]any) {
				o["additional_signatures"] = []any{map[string]any{"alg": "ecdsa-p256", "key_id": w.keyID, "signature": "not-checked"}}
			}
		}, exit: 0, check: func(t *testing.T, vl *VendorLogStat, res Result) {
			if vl.Days.SignaturesNotChecked != 2 {
				t.Errorf("signatures_not_checked %d", vl.Days.SignaturesNotChecked)
			}
		}},
		{why: "L2 (c): server_ts without milliseconds", setup: func(w *vlWorld) {
			w.entry = func(day string, m map[string]any) {
				if day == vlChainDay {
					m["server_ts"] = "2026-08-02T00:05:00Z"
				}
			}
		}, exit: 1, classes: []string{ClsVendorLogContradict, ClsVendorLogUnverified},
			codes: map[string][]string{ClsVendorLogContradict: {"entry_format"}, ClsVendorLogUnverified: {"days_not_supplied"}},
			check: func(t *testing.T, vl *VendorLogStat, res Result) {
				if vl.Days.Contradictory != 1 || vl.Days.Established != 1 {
					t.Errorf("days %+v", vl.Days)
				}
			}},
		{why: "L2 (c): a further member", setup: func(w *vlWorld) {
			w.entry = func(day string, m map[string]any) {
				if day == vlChainDay {
					m["chain_count"] = int64(1)
				}
			}
		}, exit: 1, classes: []string{ClsVendorLogContradict, ClsVendorLogUnverified},
			codes: map[string][]string{ClsVendorLogContradict: {"entry_format"}}},
		{why: "L2 (e): the key's validity ended before the genTime", setup: func(w *vlWorld) {
			w.pin, w.list, w.listEnd = false, true, "2026-08-02T00:00:00Z"
		}, exit: 1, classes: []string{ClsVendorLogUnverified},
			codes: map[string][]string{ClsVendorLogUnverified: {"key_validity_ended", "days_not_supplied"}}},
		{why: "L2 (e): a confirmed time stamp before the end of the key", setup: func(w *vlWorld) {
			w.pin, w.list, w.listEnd = false, true, "2026-08-02T00:10:00.000000001Z"
		}, exit: 0},
		{why: "L2 (e): a pin has no end", setup: func(w *vlWorld) {
			w.pin, w.list, w.listEnd = true, true, "2026-08-01T00:00:00Z"
		}, exit: 0},
		{why: "L2 (f): pins only, two first_day values", setup: func(w *vlWorld) {
			w.entry = func(day string, m map[string]any) {
				if day == vlChainDay {
					m["first_day"] = "2026-07-30"
				}
			}
		}, exit: 1, classes: []string{ClsVendorLogContradict},
			codes: map[string][]string{ClsVendorLogContradict: {"no_common_first_day"}},
			check: func(t *testing.T, vl *VendorLogStat, res Result) {
				receiptsAre(t, vl, VendorLogReceiptsStat{Unchecked: 2})
				if vl.FirstDay != nil || vl.Head != nil || vl.Days.Established != 0 {
					t.Errorf("first_day %v head %v days %+v", vl.FirstDay, vl.Head, vl.Days)
				}
				if c := res.Stats.VendorLog; c.LastCountersigned == nil || *c.LastCountersigned != RcUnchecked {
					t.Errorf("last_countersigned %v", c.LastCountersigned)
				}
			}},
		{why: "L2 (g): prev_hash of zeros on a later day", setup: func(w *vlWorld) {
			w.entry = func(day string, m map[string]any) {
				if day == vlChainDay {
					m["prev_hash"] = zeroHash
				}
			}
		}, exit: 1, classes: []string{ClsVendorLogContradict, ClsVendorLogUnverified},
			codes: map[string][]string{ClsVendorLogContradict: {"entry_rules"}, ClsVendorLogUnverified: {"days_not_supplied"}}},
		{why: "L2 (g): tree_size 0 with another root", setup: func(w *vlWorld) {
			w.entry = func(day string, m map[string]any) {
				if day == "2026-07-31" {
					m["root"] = strings.Repeat("ab", 32)
				}
			}
		}, exit: 1, classes: []string{ClsVendorLogContradict}, codes: map[string][]string{ClsVendorLogContradict: {"entry_rules"}}},
		{why: "L2 (g): server_ts before the end of the day", setup: func(w *vlWorld) {
			w.entry = func(day string, m map[string]any) {
				if day == vlChainDay {
					m["server_ts"] = "2026-08-01T23:59:59.999Z"
				}
			}
		}, exit: 1, classes: []string{ClsVendorLogContradict, ClsVendorLogUnverified}, codes: map[string][]string{ClsVendorLogContradict: {"entry_rules"}}},
		{why: "L2 (g): server_ts at the end of the day", setup: func(w *vlWorld) {
			w.entry = func(day string, m map[string]any) {
				if day == vlChainDay {
					m["server_ts"] = "2026-08-02T00:00:00.000Z"
				}
			}
		}, exit: 0},
		{why: "L2 (g): first_day other than erster_tag of the list", setup: func(w *vlWorld) {
			w.pin, w.list = false, true
			w.entry = func(day string, m map[string]any) {
				if day == vlChainDay {
					m["first_day"] = "2026-07-30"
				}
			}
		}, exit: 1, classes: []string{ClsVendorLogContradict, ClsVendorLogUnverified}, codes: map[string][]string{ClsVendorLogContradict: {"entry_rules"}}},
		{why: "L2 (g): a day before F", setup: func(w *vlWorld) {
			w.pin, w.list, w.firstDay = false, true, vlChainDay
			w.days = []string{"2026-07-31", vlChainDay}
			w.entry = func(day string, m map[string]any) {
				if day == "2026-07-31" {
					m["prev_hash"] = strings.Repeat("1", 64)
				}
			}
		}, exit: 1, classes: []string{ClsVendorLogContradict, ClsVendorLogContradict}, codes: map[string][]string{ClsVendorLogContradict: {"entry_rules"}},
			check: func(t *testing.T, vl *VendorLogStat, res Result) {
				receiptsAre(t, vl, VendorLogReceiptsStat{Included: 2, IncludedUpToTreeSize: i64(6)})
			}},
		{why: "L2 (h): a defective time stamp", setup: func(w *vlWorld) {
			w.stamps = func(day, sj string) []string {
				return []string{w.stamp(sj, genTimeAfter(day, 10*time.Minute)), "QUJD"}
			}
		}, exit: 1, classes: []string{ClsVendorLogDefective}, codes: map[string][]string{ClsVendorLogDefective: {"timestamp_defective", "timestamp_defective"}},
			check: func(t *testing.T, vl *VendorLogStat, res Result) {
				receiptsAre(t, vl, VendorLogReceiptsStat{Included: 2, IncludedUpToTreeSize: i64(6)})
			}},
		{why: "L2 (h): a confirmed premature time stamp breaks the entry", setup: func(w *vlWorld) {
			w.stamps = func(day, sj string) []string {
				if day == vlChainDay {
					return []string{w.stamp(sj, genTimeAfter(day, 59*time.Second)), w.stamp(sj, genTimeAfter(day, 10*time.Minute))}
				}
				return []string{w.stamp(sj, genTimeAfter(day, 10*time.Minute))}
			}
		}, exit: 1, classes: []string{ClsVendorLogContradict}, codes: map[string][]string{ClsVendorLogContradict: {"closed_before_day_end"}},
			check: func(t *testing.T, vl *VendorLogStat, res Result) {
				receiptsAre(t, vl, VendorLogReceiptsStat{Unchecked: 2})
				if vl.Head == nil || vl.Head.Day != "2026-07-31" || vl.Days.Witnessed != 1 || vl.Days.Established != 2 {
					t.Errorf("head %+v days %+v", vl.Head, vl.Days)
				}
			}},
		{why: "L2 (h): genTime at end(d) + 60 000 witnesses", setup: func(w *vlWorld) {
			w.stamps = func(day, sj string) []string { return []string{w.stamp(sj, genTimeAfter(day, time.Minute))} }
		}, exit: 0},
		{why: "L2 (h): genTime just below end(d) + W witnesses", setup: func(w *vlWorld) {
			w.stamps = func(day, sj string) []string {
				return []string{base64.StdEncoding.EncodeToString(tsatest.Token(tsatest.TokenSpec{Subject: []byte(sj), Key: tsatest.RSA("tsa test rsa"), Cert: probeStelle(),
					GenTime: strings.TrimSuffix(genTimeAfter(day, 48*time.Hour-time.Second), "Z") + ".999999999Z"}))}
			}
		}, exit: 0},
	})
}

// protocolListFB is the protocol key list of the world in the given version
// with the member fuellerbindung given (a string, or nil for null), as the
// bytes of a key list of the auditor (format spec 7.4.7).
func (w *vlWorld) protocolListFB(version int64, fb any) []byte {
	l, _ := w.protocolList()
	delete(l, "signatur")
	l["version"], l["fuellerbindung"] = version, fb
	rootKey, _ := keyFromSeed(0x42)
	unsigned, _ := jcs.CanonGo(l)
	l["signatur"] = map[string]any{"wurzel_id": "vl-root", "sig": hex.EncodeToString(ed25519.Sign(rootKey, unsigned))}
	b, err := jcs.CanonGo(l)
	if err != nil {
		w.t.Fatal(err)
	}
	return b
}

// TestVendorLogFillerBinding is step L1 item 2 of format spec 7.4.10 for
// fuellerbindung (7.4.7: hex64 or null, once set the same in every later
// version): the list of the extract (version 1) and a list of the auditor
// (version 2); a contradiction leaves no protocol key, and with an extract
// the run reports VENDOR_LOG_UNVERIFIED with the reason lists_contradictory
// (L1 item 4).
func TestVendorLogFillerBinding(t *testing.T) {
	fb := strings.Repeat("c", 64) // the value of protocolList
	for _, c := range []struct {
		why   string
		first any // fuellerbindung of version 1 in the extract
		later any // fuellerbindung of version 2 of the auditor
		ok    bool
	}{
		{"7.4.7 null in both versions", nil, nil, true},
		{"7.4.4 null, then a value: the vendor begins deriving its fillers", nil, fb, true},
		{"7.4.7 the same value in both versions", fb, fb, true},
		{"7.4.10 L1 a value, then null: lists_contradictory", fb, nil, false},
		{"7.4.10 L1 two different values: lists_contradictory", fb, strings.Repeat("d", 64), false},
	} {
		t.Run(c.why, func(t *testing.T) {
			w := newVLWorld(t)
			w.pin, w.list = false, true
			w.extract = func(x map[string]any) {
				var v any
				if err := json.Unmarshal(w.protocolListFB(1, c.first), &v); err != nil {
					t.Fatal(err)
				}
				x["protocol_keys"] = v
			}
			later := w.protocolListFB(2, c.later)
			w.opts = func(o *Options) { addList(t, o, later) }
			res := w.run()
			vl := res.Stats.VendorLog
			if c.ok {
				if res.ExitCode != 0 || vl.Status != VendorLogChecked || vl.KeyList == nil || vl.KeyList.Version != 2 {
					t.Errorf("exit %d %v, vendor_log %+v", res.ExitCode, res.Findings, vl)
				}
				return
			}
			if res.ExitCode != 1 || !classSet(res)[ClsVendorLogUnverified] || vl.Status != VendorLogNoProtocolKey || vl.NoKeyReason != PReasonContradictory {
				t.Errorf("exit %d %v, vendor_log %+v", res.ExitCode, res.Findings, vl)
			}
		})
	}
}

// TestVendorLogL3toL5 covers the days (L3), the head (L4) and the linking
// (L5) of format spec 7.4.10.
func TestVendorLogL3toL5(t *testing.T) {
	second := func(witnessed bool) func(w *vlWorld) {
		return func(w *vlWorld) {
			w.extract = func(x map[string]any) {
				m := w.statementOf(vlChainDay)
				m["server_ts"] = "2026-08-02T00:35:00.000Z" // a new closing of the same day
				var stamps []string
				if witnessed {
					sj, _ := jcs.CanonGo(m)
					stamps = append(stamps, w.stamp(string(sj), genTimeAfter(vlChainDay, 40*time.Minute)))
				}
				x["days"] = append(x["days"].([]any), w.object(m, stamps...))
			}
		}
	}
	runVLCases(t, []vlCase{
		{why: "L3: two witnessed versions make the day unusable", setup: second(true), exit: 1,
			classes: []string{ClsVendorLogContradict}, codes: map[string][]string{ClsVendorLogContradict: {"two_versions"}},
			check: func(t *testing.T, vl *VendorLogStat, res Result) {
				receiptsAre(t, vl, VendorLogReceiptsStat{Unchecked: 2})
				if vl.Days.Supplied != 3 || vl.Days.Established != 3 || vl.Days.Witnessed != 1 || vl.Days.Contradictory != 1 || vl.Head.Day != "2026-07-31" {
					t.Errorf("days %+v head %+v", vl.Days, vl.Head)
				}
			}},
		{why: "L3: a later unwitnessed version is reported but does not take the day", setup: second(false), exit: 1,
			classes: []string{ClsVendorLogContradict}, codes: map[string][]string{ClsVendorLogContradict: {"two_versions"}},
			check: func(t *testing.T, vl *VendorLogStat, res Result) {
				receiptsAre(t, vl, VendorLogReceiptsStat{Included: 2, IncludedUpToTreeSize: i64(6)})
				if vl.Head.Day != vlChainDay || vl.Head.DayHash != func() string { h := sha256.Sum256([]byte(w0(t))); return vh(h) }() {
					t.Errorf("head %+v", vl.Head)
				}
			}},
		{why: "L4: seen_in counts the distinct files holding c(head)", setup: func(w *vlWorld) {
			w.extract = func(x map[string]any) {
				b1, _ := json.Marshal(x)
				y := map[string]any{}
				for k, v := range x {
					y[k] = v
				}
				y["days"] = x["days"].([]any)[1:]
				b2, _ := json.Marshal(y)
				w.files = [][]byte{b1, b1, b2}
			}
		}, exit: 0, check: func(t *testing.T, vl *VendorLogStat, res Result) {
			if vl.Files != 3 || vl.DistinctFiles != 2 || vl.Head.SeenIn != 2 || vl.Days.Supplied != 2 {
				t.Errorf("files %d distinct %d seen_in %d supplied %d", vl.Files, vl.DistinctFiles, vl.Head.SeenIn, vl.Days.Supplied)
			}
		}},
		{why: "L5: an entry that does not link to the previous day", setup: func(w *vlWorld) {
			w.entry = func(day string, m map[string]any) {
				if day == vlChainDay {
					m["prev_hash"] = strings.Repeat("ab", 32)
				}
			}
		}, exit: 1, classes: []string{ClsVendorLogContradict}, codes: map[string][]string{ClsVendorLogContradict: {"does_not_link"}},
			check: func(t *testing.T, vl *VendorLogStat, res Result) {
				receiptsAre(t, vl, VendorLogReceiptsStat{Included: 2, IncludedUpToTreeSize: i64(6)})
			}},
		{why: "L5: an entry that skips days", setup: func(w *vlWorld) {
			w.firstDay, w.days = "2026-07-29", []string{"2026-07-29", vlChainDay}
		}, exit: 1, classes: []string{ClsVendorLogContradict}, codes: map[string][]string{ClsVendorLogContradict: {"skips_days"}},
			check: func(t *testing.T, vl *VendorLogStat, res Result) {
				if !strings.Contains(detailOf(res, ClsVendorLogContradict), "skips the days 2026-07-30 to 2026-07-31") {
					t.Errorf("detail %s", detailOf(res, ClsVendorLogContradict))
				}
				receiptsAre(t, vl, VendorLogReceiptsStat{Included: 2, IncludedUpToTreeSize: i64(6)})
			}},
	})
}

// w0 is the statement of the canonical entry the honest world writes for
// vlChainDay, rebuilt for a check.
func w0(t *testing.T) string {
	w := newVLWorld(t)
	w.build()
	return w.stmts[vlChainDay]
}

// TestVendorLogL6 covers the chain-day records (L6) of format spec 7.4.10
// and the absence proof of format spec 5.
func TestVendorLogL6(t *testing.T) {
	presentRec := func(c []any) map[string]any { return c[0].(map[string]any)["present"].(map[string]any) }
	runVLCases(t, []vlCase{
		{why: "L6: a path that does not hold", setup: func(w *vlWorld) {
			w.records = func(c []any) []any {
				p := presentRec(c)["path"].([]any)
				p[0] = strings.Repeat("0", 64)
				return c
			}
		}, exit: 1, classes: []string{ClsVendorLogDefective}, codes: map[string][]string{ClsVendorLogDefective: {"record_does_not_hold"}},
			check: func(t *testing.T, vl *VendorLogStat, res Result) {
				receiptsAre(t, vl, VendorLogReceiptsStat{Unchecked: 2})
			}},
		{why: "L6: the leaf index of the record is not that of the chain", setup: func(w *vlWorld) {
			w.records = func(c []any) []any { presentRec(c)["leaf_index"] = int64(0); return c }
		}, exit: 1, classes: []string{ClsVendorLogDefective}},
		{why: "L6: the size comes from c(d), never from the record", setup: func(w *vlWorld) {
			w.entry = func(day string, m map[string]any) {
				if day == vlChainDay {
					m["tree_size"] = int64(5)
				}
			}
		}, exit: 1, classes: []string{ClsVendorLogDefective}, codes: map[string][]string{ClsVendorLogDefective: {"record_does_not_hold"}}},
		{why: "L6: a record whose roots another order names holds", setup: func(w *vlWorld) {
			w.records = func(c []any) []any {
				r := presentRec(c)["roots"].([]any)
				r[0], r[1] = r[1], r[0]
				return c
			}
		}, exit: 0},
		{why: "L8 case 3: no chain-day record", setup: func(w *vlWorld) {
			w.records = func([]any) []any { return []any{} }
		}, exit: 1, classes: []string{ClsVendorLogUnverified}, codes: map[string][]string{ClsVendorLogUnverified: {"no_chain_day_record"}},
			check: func(t *testing.T, vl *VendorLogStat, res Result) {
				receiptsAre(t, vl, VendorLogReceiptsStat{Unchecked: 2})
			}},
		{why: "L6, L8: the chain proven absent", setup: withoutChain, exit: 1, classes: []string{ClsReceiptNotLogged},
			check: func(t *testing.T, vl *VendorLogStat, res Result) {
				receiptsAre(t, vl, VendorLogReceiptsStat{NotIncluded: 2})
				for _, f := range res.Findings {
					if f.Class == ClsReceiptNotLogged && (f.Seq != 3 || !strings.Contains(f.Detail, "2 receipt(s)")) {
						t.Errorf("RECEIPT_NOT_LOGGED %+v", f)
					}
				}
				if vl.LastCountersigned == nil || *vl.LastCountersigned != RcNotIncluded {
					t.Errorf("last_countersigned %v", vl.LastCountersigned)
				}
			}},
		{why: "L6: absent with two neighbours of one leaf_index (grammar accepts)", setup: func(w *vlWorld) {
			withoutChain(w)
			w.records = func([]any) []any {
				l := fillers(vlChainDay)
				dayTree(l, "")
				rec := w.absentRecord(vlChainDay, l)
				nb := rec["absent"].(map[string]any)["neighbours"].([]any)
				if len(nb) == 2 {
					nb[1] = nb[0]
				} else {
					nb = append(nb, nb[0])
				}
				rec["absent"].(map[string]any)["neighbours"] = nb
				return []any{rec}
			}
		}, exit: 1, classes: []string{ClsVendorLogDefective}, codes: map[string][]string{ClsVendorLogDefective: {"record_does_not_hold"}}},
		{why: "L6: absent (i) in an empty day tree", setup: func(w *vlWorld) {
			w.rows = func([]map[string]any) []map[string]any { return nil }
			w.records = func([]any) []any {
				return []any{map[string]any{"day": vlChainDay, "present": nil, "absent": map[string]any{"neighbours": []any{}}}}
			}
		}, exit: 1, classes: []string{ClsReceiptNotLogged}},
		{why: "L6: absent without a neighbour in a tree that is not empty", setup: func(w *vlWorld) {
			withoutChain(w)
			w.records = func([]any) []any {
				return []any{map[string]any{"day": vlChainDay, "present": nil, "absent": map[string]any{"neighbours": []any{}}}}
			}
		}, exit: 1, classes: []string{ClsVendorLogDefective}},
		{why: "L6: absent with one neighbour that is not at the edge", setup: func(w *vlWorld) {
			withoutChain(w)
			w.records = func([]any) []any {
				l := fillers(vlChainDay)
				dayTree(l, "")
				rec := w.absentRecord(vlChainDay, l)
				ab := rec["absent"].(map[string]any)
				ab["neighbours"] = ab["neighbours"].([]any)[:1]
				return []any{rec}
			}
		}, exit: 1, classes: []string{ClsVendorLogDefective}},
		{why: "L6: a leaf of another day", setup: func(w *vlWorld) {
			w.rows = func(rows []map[string]any) []map[string]any {
				return append(rows, map[string]any{"tree_size": rows[0]["tree_size"], "merkle_root": rows[0]["merkle_root"], "recorded_as": "gap_witness", "server_ts": "2026-07-31T23:59:00.000Z"})
			}
		}, exit: 1, classes: []string{ClsVendorLogContradict}, codes: map[string][]string{ClsVendorLogContradict: {"leaf_of_other_day"}},
			check: func(t *testing.T, vl *VendorLogStat, res Result) {
				receiptsAre(t, vl, VendorLogReceiptsStat{Unchecked: 2})
			}},
		{why: "L6: two holding records that differ", setup: func(w *vlWorld) {
			// The day tree carries a second leaf at the chain's position
			// whose chain root holds only the first receipt; a second file
			// names that leaf.
			var one []map[string]any
			w.leaves = func(day string) [][2]string {
				if day != vlChainDay {
					return nil
				}
				one = w.receiptRows(day)[:1]
				r := one[0]
				lh := leafHash(vlLeaf(w.g.chainID, r["tree_size"].(int64), r["merkle_root"].(string), "countersigned", r["server_ts"].(string)))
				return [][2]string{{vlDayPos(w, day), vh(lh)}}
			}
			w.extract = func(x map[string]any) {
				b1, _ := json.Marshal(x)
				rec := x["chain_days"].([]any)[0].(map[string]any)
				p := rec["present"].(map[string]any)
				// Rebuild the tree to find the other leaf and its path.
				rows := w.receiptRows(vlChainDay)
				var lhs [][32]byte
				for _, r := range rows {
					lhs = append(lhs, leafHash(vlLeaf(w.g.chainID, r["tree_size"].(int64), r["merkle_root"].(string), "countersigned", r["server_ts"].(string))))
				}
				leaves := append([][2]string{{vlDayPos(w, vlChainDay), vh(vlChainRoot(lhs))}}, fillers(vlChainDay)...)
				leaves = append(leaves, w.leaves(vlChainDay)...)
				_, tl, _ := dayTree(leaves, "")
				other := -1
				for i, l := range leaves {
					if l[0] == vlDayPos(w, vlChainDay) && int64(i) != p["leaf_index"].(int64) {
						other = i
					}
				}
				rec2 := map[string]any{"day": vlChainDay, "absent": nil, "present": map[string]any{"roots": []any{one[0]}, "leaf_index": int64(other), "path": hexes(auditPath(tl, other))}}
				y := map[string]any{}
				for k, v := range x {
					y[k] = v
				}
				y["chain_days"] = []any{rec2}
				b2, _ := json.Marshal(y)
				w.files = [][]byte{b1, b2}
			}
		}, exit: 1, classes: []string{ClsVendorLogContradict}, codes: map[string][]string{ClsVendorLogContradict: {"two_chain_day_records"}},
			check: func(t *testing.T, vl *VendorLogStat, res Result) {
				receiptsAre(t, vl, VendorLogReceiptsStat{Unchecked: 2})
			}},
		{why: "L6: records of another chain are counted and passed over", setup: func(w *vlWorld) {
			w.extract = func(x map[string]any) {
				b1, _ := json.Marshal(x)
				y := map[string]any{}
				for k, v := range x {
					y[k] = v
				}
				y["chain_id"] = "aaaaaaaa-0b0a-4900-8807-060504030201"
				y["chain_days"] = []any{map[string]any{"day": vlChainDay, "present": nil, "absent": map[string]any{"neighbours": []any{}}}}
				b2, _ := json.Marshal(y)
				w.files = [][]byte{b1, b2}
			}
		}, exit: 0, check: func(t *testing.T, vl *VendorLogStat, res Result) {
			if vl.ForeignChainRecords != 1 || vl.Head.SeenIn != 2 {
				t.Errorf("foreign_chain_records %d seen_in %d", vl.ForeignChainRecords, vl.Head.SeenIn)
			}
		}},
		{why: "7.4.3, L6: a chain taken over under another appliance: the record does not hold under A of the package", setup: func(w *vlWorld) {
			w.app = "99999999-5e6f-4a01-9b02-c3d4e5f60718"
		}, exit: 1, classes: []string{ClsVendorLogDefective}, codes: map[string][]string{ClsVendorLogDefective: {"record_does_not_hold"}}},
	})
}

// TestVendorLogL7L8 covers the required range (L7) and the receipt classes
// (L8) of format spec 7.4.10.
func TestVendorLogL7L8(t *testing.T) {
	stampsFor := func(mk func(w *vlWorld, day, sj string) []string) func(w *vlWorld) {
		return func(w *vlWorld) {
			w.stamps = func(day, sj string) []string {
				if day == vlChainDay {
					return mk(w, day, sj)
				}
				return []string{w.stamp(sj, genTimeAfter(day, 10*time.Minute))}
			}
		}
	}
	notWitnessed := func(reason string) func(t *testing.T, vl *VendorLogStat, res Result) {
		return func(t *testing.T, vl *VendorLogStat, res Result) {
			receiptsAre(t, vl, VendorLogReceiptsStat{Unchecked: 2})
			if !strings.Contains(detailOf(res, ClsVendorLogUnverified), "reason "+reason) {
				t.Errorf("detail %q, want reason %s", detailOf(res, ClsVendorLogUnverified), reason)
			}
			if vl.Head == nil || vl.Head.Day != vlChainDay || vl.Head.Witnessed {
				t.Errorf("head %+v", vl.Head)
			}
		}
	}
	other := tsatest.Ed25519Key("vl other tsa")
	otherCert := tsatest.Cert(tsatest.CertSpec{CN: "Other TSA", Key: other})
	runVLCases(t, []vlCase{
		{why: "L7: a due day without an entry", setup: func(w *vlWorld) { w.days = []string{"2026-07-31"} }, exit: 1,
			classes: []string{ClsVendorLogUnverified}, codes: map[string][]string{ClsVendorLogUnverified: {"days_not_supplied"}},
			check: func(t *testing.T, vl *VendorLogStat, res Result) {
				receiptsAre(t, vl, VendorLogReceiptsStat{Missing: 2})
				if vl.Days.Missing != 1 || !strings.Contains(detailOf(res, ClsVendorLogUnverified), "days 2026-08-01 to 2026-08-01") {
					t.Errorf("missing %d, %s", vl.Days.Missing, detailOf(res, ClsVendorLogUnverified))
				}
			}},
		{why: "L7: a run up to the head is one finding", setup: func(w *vlWorld) {
			w.days = []string{"2026-07-31", "2026-08-03"}
		}, exit: 1, classes: []string{ClsVendorLogUnverified, ClsVendorLogContradict},
			codes: map[string][]string{ClsVendorLogUnverified: {"days_not_supplied"}, ClsVendorLogContradict: {"skips_days"}},
			check: func(t *testing.T, vl *VendorLogStat, res Result) {
				receiptsAre(t, vl, VendorLogReceiptsStat{Missing: 2})
				if vl.Days.Missing != 2 || !strings.Contains(detailOf(res, ClsVendorLogUnverified), "days 2026-08-01 to 2026-08-02") {
					t.Errorf("missing %d, %s", vl.Days.Missing, detailOf(res, ClsVendorLogUnverified))
				}
			}},
		{why: "L8 case 6: a day not yet due is pending, no finding", setup: func(w *vlWorld) {
			w.days, w.now = []string{"2026-07-31"}, time.Date(2026, 8, 2, 5, 59, 59, 0, time.UTC)
		}, exit: 0, check: func(t *testing.T, vl *VendorLogStat, res Result) {
			receiptsAre(t, vl, VendorLogReceiptsStat{Pending: 2})
			if vl.LastCountersigned == nil || *vl.LastCountersigned != RcPending {
				t.Errorf("last_countersigned %v", vl.LastCountersigned)
			}
		}},
		{why: "L8 case 6: due from 06:00Z of the following day", setup: func(w *vlWorld) {
			w.days, w.now = []string{"2026-07-31"}, time.Date(2026, 8, 2, 6, 0, 0, 0, time.UTC)
		}, exit: 1, classes: []string{ClsVendorLogUnverified}, check: func(t *testing.T, vl *VendorLogStat, res Result) {
			receiptsAre(t, vl, VendorLogReceiptsStat{Missing: 2})
		}},
		{why: "L8 case 1: receipts before the start of the log", setup: func(w *vlWorld) {
			w.firstDay, w.days = "2026-08-02", []string{"2026-08-02"}
			w.now = time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
		}, exit: 1, classes: []string{ClsTrailingSilence}, check: func(t *testing.T, vl *VendorLogStat, res Result) {
			receiptsAre(t, vl, VendorLogReceiptsStat{BeforeStart: 2})
			if vl.Days.Missing != 0 || *vl.FirstDay != "2026-08-02" {
				t.Errorf("days %+v", vl.Days)
			}
		}},
		{why: "L8 case 2: receipts after the check time", setup: func(w *vlWorld) {
			w.days, w.now = []string{"2026-07-31"}, time.Date(2026, 8, 1, 7, 45, 0, 0, time.UTC)
		}, exit: 1, classes: []string{ClsVendorLogUnverified}, codes: map[string][]string{ClsVendorLogUnverified: {"receipt_after_check_time"}},
			check: func(t *testing.T, vl *VendorLogStat, res Result) {
				receiptsAre(t, vl, VendorLogReceiptsStat{Future: 2})
			}},
		{why: "L8 case 4: no time stamp", setup: stampsFor(func(w *vlWorld, day, sj string) []string { return nil }), exit: 1,
			classes: []string{ClsVendorLogUnverified}, codes: map[string][]string{ClsVendorLogUnverified: {"day_not_witnessed"}},
			check: notWitnessed(NwNoTimestamp)},
		{why: "L8 case 4: no root for the log", setup: func(w *vlWorld) { w.logRoot = false }, exit: 1,
			classes: []string{ClsVendorLogUnverified}, check: notWitnessed(NwNoLogRoot)},
		{why: "L8 case 4: outside the profile (5a)", setup: stampsFor(func(w *vlWorld, day, sj string) []string {
			return []string{base64.StdEncoding.EncodeToString(tsatest.Token(tsatest.TokenSpec{Subject: []byte(sj), Key: tsatest.RSA("tsa test rsa"), Cert: probeStelle(), GenTime: genTimeAfter(day, time.Hour), NoCerts: true}))}
		}), exit: 1, classes: []string{ClsVendorLogUnverified}, check: notWitnessed(NwOutsideProfile)},
		{why: "L8 case 4: no path to a root of the purpose log", setup: stampsFor(func(w *vlWorld, day, sj string) []string {
			return []string{base64.StdEncoding.EncodeToString(tsatest.Token(tsatest.TokenSpec{Subject: []byte(sj), Key: other, Cert: otherCert, GenTime: genTimeAfter(day, time.Hour)}))}
		}), exit: 1, classes: []string{ClsVendorLogUnverified}, check: notWitnessed(NwNotChained)},
		{why: "L8 case 4: late, and the furthest reason decides", setup: stampsFor(func(w *vlWorld, day, sj string) []string {
			return []string{
				base64.StdEncoding.EncodeToString(tsatest.Token(tsatest.TokenSpec{Subject: []byte(sj), Key: other, Cert: otherCert, GenTime: genTimeAfter(day, time.Hour)})),
				w.stamp(sj, genTimeAfter(day, 48*time.Hour)),
			}
		}), exit: 1, classes: []string{ClsVendorLogUnverified}, check: notWitnessed(NwLate)},
		{why: "L8 case 4: every time stamp defective, no finding of the day not witnessed", setup: stampsFor(func(w *vlWorld, day, sj string) []string {
			return []string{w.stamp("other bytes", genTimeAfter(day, time.Hour))}
		}), exit: 1, classes: []string{ClsVendorLogDefective}, codes: map[string][]string{ClsVendorLogDefective: {"timestamp_defective"}},
			check: func(t *testing.T, vl *VendorLogStat, res Result) {
				receiptsAre(t, vl, VendorLogReceiptsStat{Unchecked: 2})
			}},
		{why: "L8: a receipt with RECEIPT_INVALID is passed over", setup: func(w *vlWorld) {
			w.g.editLine(2, func(v *jcs.Value) {
				p := v.Get("payload")
				setMember(p, "server_signature", jStr(strings.Repeat("0", 128)))
			})
		}, exit: 2, classes: []string{ClsReceiptInvalid, ClsHashMismatch}, check: func(t *testing.T, vl *VendorLogStat, res Result) {
			receiptsAre(t, vl, VendorLogReceiptsStat{Included: 1, IncludedUpToTreeSize: i64(6)})
			// L9: the receipt is still a receipt of its leaf in the package
			// ("ohne Quittung desselben Blatts im Paket"); the leaf does not
			// hold the signature (format spec 7.4.2).
			if lr := vl.LoggedRoots; lr == nil || lr.MatchingWithoutReceipt != 0 {
				t.Errorf("logged_roots %+v, want matching_without_receipt 0", lr)
			}
		}},
	})
}

// TestVendorLogL9 covers the logged roots (L9) of format spec 7.4.10.
func TestVendorLogL9(t *testing.T) {
	addRows := func(extra func(rows []map[string]any) []map[string]any) func(w *vlWorld) {
		return func(w *vlWorld) {
			w.rows = func(rows []map[string]any) []map[string]any { return append(rows, extra(rows)...) }
		}
	}
	runVLCases(t, []vlCase{
		{why: "L9: a logged root that differs from the package", setup: addRows(func(rows []map[string]any) []map[string]any {
			return []map[string]any{{"tree_size": int64(2), "merkle_root": strings.Repeat("ab", 32), "recorded_as": "gap_witness", "server_ts": "2026-08-01T09:00:00.000Z"}}
		}), exit: 1, classes: []string{ClsLoggedRootMismatch}, check: func(t *testing.T, vl *VendorLogStat, res Result) {
			if lr := vl.LoggedRoots; *lr != (VendorLogRootsStat{MatchingPrefix: 2, ContradictingPrefix: 1, GapWitnesses: 1}) {
				t.Errorf("logged_roots %+v", lr)
			}
			receiptsAre(t, vl, VendorLogReceiptsStat{Included: 2, IncludedUpToTreeSize: i64(6)})
		}},
		{why: "L9: a root beyond the package, a matching gap witness and a countersignature without receipt", setup: addRows(func(rows []map[string]any) []map[string]any {
			return []map[string]any{
				{"tree_size": int64(99), "merkle_root": strings.Repeat("cd", 32), "recorded_as": "countersigned", "server_ts": "2026-08-01T09:00:00.000Z"},
				{"tree_size": rows[0]["tree_size"], "merkle_root": rows[0]["merkle_root"], "recorded_as": "gap_witness", "server_ts": "2026-08-01T07:59:00.000Z"},
				{"tree_size": rows[1]["tree_size"], "merkle_root": rows[1]["merkle_root"], "recorded_as": "countersigned", "server_ts": "2026-08-01T10:00:00.000Z"},
			}
		}), exit: 0, check: func(t *testing.T, vl *VendorLogStat, res Result) {
			if lr := vl.LoggedRoots; *lr != (VendorLogRootsStat{MatchingPrefix: 2, MatchingWithoutReceipt: 1, BeyondPackage: 1, GapWitnesses: 1}) {
				t.Errorf("logged_roots %+v", lr)
			}
		}},
	})
}

// TestVendorLogReport covers the report object vendor_log (10.10.1,
// 10.10.2) and the text block (10.10.3).
func TestVendorLogReport(t *testing.T) {
	// Without an extract: not_supplied, null members, every count 0, also
	// with roots for the log and a pinned protocol key (L1 still runs).
	g := validSealedChain(t)
	opt := genAnker(Options{Now: time.Date(2026, 8, 2, 8, 0, 0, 0, time.UTC), VendorLogTSARoots: [][]byte{probeStelle()}})
	priv, _ := keyFromSeed(0x41)
	opt.VendorLogKeys = []VendorKey{{ID: "vl-key-1", Pubkey: vlPub(priv)}}
	res := Verify(g.writePkg(), opt)
	wantClasses(t, res, 0)
	b, _ := json.Marshal(res.Stats.VendorLog)
	if want := `{"status":"not_supplied","log_id":null,"first_day":null,"key_source":null,"key_list":null,"places":[],"files":0,"distinct_files":0,"head":null,"days":{"supplied":0,"established":0,"witnessed":0,"contradictory":0,"missing":0,"signatures_not_checked":0},"tsa":{"cms_checked":true,"roots_supplied":0},"receipts":null,"last_countersigned":null,"logged_roots":null,"foreign_chain_records":0}`; string(b) != want {
		t.Errorf("not_supplied:\n%s\nwant\n%s", b, want)
	}
	for lang, want := range map[string]string{
		"de": "Herstellerprotokoll: nicht übergeben. Ob der Hersteller die Quittungen protokolliert hat, sagt dieser Bericht nicht (Abschnitt 7.4).",
		"en": "Vendor log: not supplied. This report does not say whether the vendor logged the receipts (section 7.4).",
	} {
		if txt := RenderText(res, "pkg", lang); !strings.Contains(txt, want) || strings.Contains(txt, "MISSING:") {
			t.Errorf("%s text lacks %q", lang, want)
		}
	}

	// Checked: the block with head, receipts and the advice.
	w := newVLWorld(t)
	res = w.run()
	h := res.Stats.VendorLog.Head
	for lang, want := range map[string][]string{
		"de": {fmt.Sprintf("Herstellerprotokoll vl-test-1: Kopf 2026-08-01, Tageshash %s, bezeugt: ja, in 1 von 1 Dateien.", h.DayHash),
			"Quittungen: 2 nachgewiesen, 0 fehlen, 0 nicht prüfbar, 0 ohne Tageseintrag, 0 noch nicht fällig, 0 vor Beginn des Protokolls, 0 nach dem Prüfzeitpunkt.",
			"Vergleichen Sie den Tageshash mit dem zweiten Veröffentlichungsort."},
		"en": {fmt.Sprintf("Vendor log vl-test-1: head 2026-08-01, day hash %s, witnessed: yes, in 1 of 1 files.", h.DayHash),
			"Receipts: 2 shown, 0 missing, 0 not checkable, 0 without day entry, 0 not due yet, 0 before the start of the log, 0 after the check time."},
	} {
		txt := RenderText(res, "pkg", lang)
		for _, s := range want {
			if !strings.Contains(txt, s) {
				t.Errorf("%s text lacks %q", lang, s)
			}
		}
	}
	// The JSON output carries the object under stats with the names of the
	// schema report_vendor_log.
	out, _ := RenderJSON(res)
	var parsed struct {
		Stats map[string]json.RawMessage `json:"stats"`
	}
	_ = json.Unmarshal(out, &parsed)
	var obj map[string]any
	_ = json.Unmarshal(parsed.Stats["vendor_log"], &obj)
	for _, m := range []string{"days", "distinct_files", "files", "first_day", "foreign_chain_records", "head", "key_list", "key_source", "last_countersigned", "log_id", "logged_roots", "places", "receipts", "status", "tsa"} {
		if _, ok := obj[m]; !ok {
			t.Errorf("stats.vendor_log lacks %s", m)
		}
	}
	if len(obj) != 15 {
		t.Errorf("stats.vendor_log has %d members", len(obj))
	}

	// no_protocol_key names the reason in the language of the report.
	w = newVLWorld(t)
	w.pin = false
	res = w.run()
	if txt := RenderText(res, "pkg", "de"); !strings.Contains(txt, "Herstellerprotokoll übergeben, aber kein Protokollschlüssel durch einen Anker des Prüfers belegt (keine Protokollschlüsselliste übergeben).") {
		t.Errorf("no_protocol_key text:\n%s", txt)
	}

	// Exit 3: null, and no block.
	w = newVLWorld(t)
	w.g.editLine(1, func(v *jcs.Value) { setMember(v, "seq", jStr("x")) })
	res = w.run()
	if res.ExitCode != 3 || res.Stats.VendorLog != nil {
		t.Errorf("exit %d, vendor_log %+v", res.ExitCode, res.Stats.VendorLog)
	}
	if out, _ := RenderJSON(res); !strings.Contains(string(out), `"vendor_log": null`) {
		t.Errorf("exit 3 JSON without vendor_log null")
	}
	if txt := RenderText(res, "pkg", "en"); strings.Contains(txt, "Vendor log") {
		t.Errorf("exit 3 text names the vendor log")
	}
}

// TestVendorLogExitCode: the vendor log changes the exit code at most from
// 0 to 1 (L10); exit 4 and exit 2 stay.
func TestVendorLogExitCode(t *testing.T) {
	w := newVLWorld(t)
	w.g = validChain(t) // unsealed: exit 4
	w.days = []string{"2026-07-31"}
	res := w.run()
	wantClasses(t, res, 4, ClsUnsealedEnd, ClsVendorLogUnverified)
	w = newVLWorld(t)
	w.g = validChain(t)
	res = w.run()
	wantClasses(t, res, 4, ClsUnsealedEnd)
	if res.Stats.VendorLog.Receipts.Included != 2 {
		t.Errorf("receipts %+v", res.Stats.VendorLog.Receipts)
	}
}

// TestVendorLogAbsenceForms holds the forms (i) to (iv) of the absence proof
// of format spec 5 against (n, R) of the canonical entry (L6): exactly one
// form, every neighbour by inclusion, positions compared as lowercase hex.
func TestVendorLogAbsenceForms(t *testing.T) {
	const c, a, day = "0f0e0d0c-0b0a-4900-8807-060504030201", vlApp, "2026-08-01"
	p := vlPosition(a, c, day)
	ph := vh(p)
	below := func(i int) string { return fmt.Sprintf("%02x", i) + strings.Repeat("0", 62) }
	above := func(i int) string { return "ff" + fmt.Sprintf("%02x", i) + strings.Repeat("0", 60) }
	if !(below(9) < ph && ph < above(0)) {
		t.Fatalf("position %s not between the test positions", ph)
	}
	root := func(i int) string { h := sha256.Sum256([]byte{byte(i)}); return vh(h) }
	type nb struct {
		idx  int
		leaf int // index of the leaf whose position and root it names
	}
	for _, f := range []struct {
		why    string
		pos    []string
		nbs    []nb
		holds  bool
		hidden bool // pass n = 0 with no leaves
	}{
		{why: "(i) n = 0, no neighbour", hidden: true, holds: true},
		{why: "(ii) one neighbour, index 0, p below it", pos: []string{above(1), above(2)}, nbs: []nb{{0, 0}}, holds: true},
		{why: "(ii) the neighbour not at index 0", pos: []string{above(1), above(2)}, nbs: []nb{{1, 1}}},
		{why: "(iii) one neighbour, index n - 1, p above it", pos: []string{below(1), below(2)}, nbs: []nb{{1, 1}}, holds: true},
		{why: "(iii) the neighbour not at index n - 1", pos: []string{below(1), below(2)}, nbs: []nb{{0, 0}}},
		{why: "(iv) two adjacent neighbours around p", pos: []string{below(1), below(2), above(1)}, nbs: []nb{{1, 1}, {2, 2}}, holds: true},
		{why: "(iv) two neighbours not around p", pos: []string{below(1), below(2), above(1)}, nbs: []nb{{0, 0}, {1, 1}}},
		{why: "(iv) two neighbours with one leaf_index", pos: []string{below(1), above(1)}, nbs: []nb{{0, 0}, {0, 0}}},
		{why: "(iv) not adjacent", pos: []string{below(1), below(2), above(1), above(2)}, nbs: []nb{{0, 0}, {2, 2}}},
		{why: "p itself in the tree", pos: []string{ph, above(1)}, nbs: []nb{{0, 0}}},
		{why: "no neighbour in a tree that is not empty", pos: []string{above(1)}},
		{why: "a neighbour naming a leaf it is not", pos: []string{below(1), above(1)}, nbs: []nb{{0, 1}, {1, 1}}},
	} {
		var leaves [][2]string
		for i, q := range f.pos {
			leaves = append(leaves, [2]string{q, root(i)})
		}
		r, lhs, _ := dayTree(leaves, "")
		vr := &vlRun{canon: map[int64]*vlObject{}}
		dt, _ := parseDate(day, true)
		d := dayNumber(dt)
		vr.canon[d] = &vlObject{st: &vlStatement{treeSize: int64(len(leaves)), root: vh(r)}}
		var ns []any
		for _, n := range f.nbs {
			ns = append(ns, map[string]any{"leaf_index": int64(n.idx), "position": leaves[n.leaf][0], "chain_root": leaves[n.leaf][1], "path": hexes(auditPath(lhs, n.leaf))})
		}
		if ns == nil {
			ns = []any{}
		}
		b, _ := json.Marshal(map[string]any{"day": day, "present": nil, "absent": map[string]any{"neighbours": ns}})
		rec, err := jcs.Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		e, why := vr.evalRecord(rec, c, a, d)
		if (e != nil) != f.holds {
			t.Errorf("format spec 5 %s: holds=%v (%s), want %v", f.why, e != nil, why, f.holds)
		}
	}
}

// TestVendorLogBlockLayout is the block of the vendor log of format spec
// 10.10.3 for the status checked: three lines from the registry texts
// checked_head, receipts and compare in this order, the first unindented,
// the other two indented by two spaces; without a head only the first line
// is replaced (checked_no_head).
func TestVendorLogBlockLayout(t *testing.T) {
	id := "ledger-testprotokoll-1"
	vl := &VendorLogStat{Status: VendorLogChecked, LogID: &id, DistinctFiles: 2,
		Head:     &VendorLogHeadStat{Day: "2026-01-02", DayHash: strings.Repeat("ab", 32), TreeSize: 5, Witnessed: true, SeenIn: 1},
		Receipts: &VendorLogReceiptsStat{Included: 1, Pending: 1}}
	got := vendorLogBlock(vl, tableDE)
	want := []string{
		"Herstellerprotokoll ledger-testprotokoll-1: Kopf 2026-01-02, Tageshash " + strings.Repeat("ab", 32) + ", bezeugt: ja, in 1 von 2 Dateien.",
		"  Quittungen: 1 nachgewiesen, 0 fehlen, 0 nicht prüfbar, 0 ohne Tageseintrag, 1 noch nicht fällig, 0 vor Beginn des Protokolls, 0 nach dem Prüfzeitpunkt.",
		"  Vergleichen Sie den Tageshash mit dem zweiten Veröffentlichungsort.",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("status checked:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	vl.Head = nil
	got = vendorLogBlock(vl, tableFor("en"))
	if len(got) != 3 || got[0] != "Vendor log ledger-testprotokoll-1: no day entry established." ||
		!strings.HasPrefix(got[1], "  Receipts: 1 shown, ") || got[2] != "  Compare the day hash with the second place of publication." {
		t.Errorf("status checked without a head:\n%s", strings.Join(got, "\n"))
	}
}
