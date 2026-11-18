package vfy

// The role check of format spec 10.7.4 (R1 to R4) with the role list of
// 10.7.2 and the protocol key list of 7.4.7, and the report object key_roles
// of 10.10.2. The cases follow the reference values of 10.7.4 on a generated
// chain: the receipts of validSealedChain are under vendor-1 (seed 2).

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
)

type rolle struct{ id, pub, rolle, ab, bis, widerr string }

func pubOf(seed byte) string { _, p := keyFromSeed(seed); return p }

// rollenliste builds a role list of version ver, signed by priv as rootID;
// edit changes the object before it is signed.
func rollenliste(t *testing.T, rootID string, priv ed25519.PrivateKey, ver int64, edit func(map[string]any), keys ...rolle) []byte {
	t.Helper()
	var ks []any
	for _, k := range keys {
		ab := k.ab
		if ab == "" {
			ab = "2025-01-01T00:00:00Z"
		}
		m := map[string]any{"key_id": k.id, "pubkey": k.pub, "rolle": k.rolle, "gueltig_ab": ab}
		if k.bis != "" {
			m["gueltig_bis"] = k.bis
		}
		if k.widerr != "" {
			m["widerrufen_ab"] = k.widerr
		}
		ks = append(ks, m)
	}
	l := map[string]any{"format": KeyRoleListFormat, "version": ver, "ausgestellt": "2026-07-01T00:00:00.000Z", "schluessel": ks}
	if edit != nil {
		edit(l)
	}
	sig := hex.EncodeToString(ed25519.Sign(priv, canonGo(t, l)))
	l["signatur"] = map[string]any{"wurzel_id": rootID, "sig": sig}
	return canonGo(t, l)
}

// protokollliste builds a protocol key list (7.4.7).
func protokollliste(t *testing.T, rootID string, priv ed25519.PrivateKey, ver int64, logID string, keys ...rolle) []byte {
	t.Helper()
	return protokolllisteFB(t, rootID, priv, ver, logID, strings.Repeat("ab", 32), keys...)
}

// protokolllisteFB builds a protocol key list (7.4.7) with the member
// fuellerbindung given (a string, or nil for null).
func protokolllisteFB(t *testing.T, rootID string, priv ed25519.PrivateKey, ver int64, logID string, fb any, keys ...rolle) []byte {
	t.Helper()
	var ks []any
	for _, k := range keys {
		ks = append(ks, map[string]any{"key_id": k.id, "pubkey": k.pub, "gueltig_ab": "2025-12-30T00:00:00.000Z"})
	}
	l := map[string]any{"format": ProtocolKeyListFormat, "version": ver, "ausgestellt": "2025-12-30T10:00:00.000Z",
		"log_id": logID, "erster_tag": "2025-12-31", "fuellerbindung": fb,
		"orte": []any{"https://a.example/log", "https://b.example/log"}, "schluessel": ks}
	sig := hex.EncodeToString(ed25519.Sign(priv, canonGo(t, l)))
	l["signatur"] = map[string]any{"wurzel_id": rootID, "sig": sig}
	return canonGo(t, l)
}

// rollenLauf runs validSealedChain with the given auditor inputs; the
// package list, when given, lies at keys/vendor/schluesselliste.json.
func rollenLauf(t *testing.T, paketListe []byte, edit func(*Options)) Result {
	t.Helper()
	g := validSealedChain(t)
	dir := g.writePkg()
	if paketListe != nil {
		legeListe(t, dir, paketListe)
	}
	w, _ := wurzel()
	opt := Options{VendorRoots: []VendorRoot{w}}
	if edit != nil {
		edit(&opt)
	}
	if err := opt.FinishAuditorInputs(g.now.Add(2 * 3600e9)); err != nil {
		t.Fatalf("auditor inputs: %v", err)
	}
	return pruefe(t, g, dir, opt)
}

func addList(t *testing.T, o *Options, b []byte) {
	t.Helper()
	if err := o.AddVendorKeyList(b); err != nil {
		t.Fatalf("--vendor-key-list: %v", err)
	}
}

func notes(st *KeyRolesStat) string { return strings.Join(st.Notes, ",") }

func reason(st *KeyRolesStat) string {
	if st.Reason == nil {
		return ""
	}
	return *st.Reason
}

// TestRollenNichtUebergeben: without a role list the status is
// not_supplied, reason and list null, candidates 0, and statement_keys names
// only pins (10.10.2).
func TestRollenNichtUebergeben(t *testing.T) {
	res := rollenLauf(t, nil, func(o *Options) {
		o.VendorKeys = []VendorKey{{ID: "vendor-1", Pubkey: pubOf(2)}}
		_ = o.AddVendorStatementKey("st-b=" + pubOf(21))
		_ = o.AddVendorStatementKey("st-a=" + pubOf(20))
	})
	erwarte(t, res, 0)
	st := res.Stats.KeyRoles
	if st == nil || st.Status != RolesNotSupplied || st.Reason != nil || st.List != nil || st.Candidates != 0 || notes(st) != "" || len(st.PinsDropped) != 0 {
		t.Fatalf("key_roles %+v", st)
	}
	if len(st.StatementKeys) != 2 || st.StatementKeys[0] != (StatementKeyRef{"st-a", SourcePinned}) || st.StatementKeys[1].KeyID != "st-b" {
		t.Errorf("statement_keys %+v", st.StatementKeys)
	}
}

// TestRollenWirksam: an effective role list (R1, R2), its report, the
// statements keys of Q and of pins (pins first, 8.8.3), an unknown role.
func TestRollenWirksam(t *testing.T) {
	w, priv := wurzel()
	q := rollenliste(t, w.ID, priv, 1, func(l map[string]any) { l["ende_doppelbetrieb"] = "2027-07-01T00:00:00Z" },
		rolle{id: "vendor-1", pub: pubOf(2), rolle: RoleCountersigning},
		rolle{id: "st-2", pub: pubOf(22), rolle: RoleStatements},
		rolle{id: "st-1", pub: pubOf(21), rolle: RoleStatements, widerr: "2026-12-01T00:00:00Z"},
		rolle{id: "um-1", pub: pubOf(23), rolle: RoleUpdateManifest},
		rolle{id: "neu-1", pub: pubOf(24), rolle: "archive"})
	res := rollenLauf(t, nil, func(o *Options) {
		o.VendorKeys = []VendorKey{{ID: "vendor-1", Pubkey: pubOf(2)}}
		addList(t, o, q)
		addList(t, o, q) // the same bytes twice are one candidate
		_ = o.AddVendorStatementKey("st-2=" + pubOf(22))
	})
	erwarte(t, res, 0) // a countersigning pin that Q names countersigning stays
	st := res.Stats.KeyRoles
	if st.Status != RolesEffective || st.Reason != nil || st.Candidates != 1 || st.List == nil {
		t.Fatalf("key_roles %+v", st)
	}
	if *st.List.EndeDoppelbetrieb != "2027-07-01T00:00:00Z" || st.List.Version != 1 || st.List.WurzelID != w.ID ||
		st.List.RootSource != RootSourceAuditor || st.List.Ausgestellt != "2026-07-01T00:00:00.000Z" {
		t.Errorf("list %+v", st.List)
	}
	if got := refs(st.StatementKeys); got != "st-1:role_list,st-2:pinned" {
		t.Errorf("statement_keys %s", got)
	}
	if notes(st) != NoteUnknownRole {
		t.Errorf("notes %v", st.Notes)
	}
}

func refs(r []StatementKeyRef) string {
	var s []string
	for _, x := range r {
		s = append(s, x.KeyID+":"+x.Source)
	}
	return strings.Join(s, ",")
}

// TestRollenGruende: candidates that do not count (10.7.2) and the reason of
// the one that came furthest (format, no_matching_root, signature), and the
// contradictions of R2.
func TestRollenGruende(t *testing.T) {
	w, priv := wurzel()
	fremd, _ := keyFromSeed(9)
	cs := rolle{id: "vendor-1", pub: pubOf(2), rolle: RoleCountersigning}
	st1 := rolle{id: "st-1", pub: pubOf(21), rolle: RoleStatements}
	broken := func(b []byte) []byte {
		v, _ := jcs.Parse(b)
		sig := v.Get("signatur").Get("sig")
		sig.Str = strings.Repeat("0", 128)
		return jcs.Canon(v)
	}
	for _, f := range []struct {
		why   string
		lists [][]byte
		want  string
	}{
		{"rolle protocol is reserved", [][]byte{rollenliste(t, w.ID, priv, 1, nil, cs, rolle{id: "p", pub: pubOf(30), rolle: RoleProtocol})}, ReasonFormat},
		{"an unknown top-level member", [][]byte{rollenliste(t, w.ID, priv, 1, func(l map[string]any) { l["neu"] = "x" }, cs)}, ReasonFormat},
		{"rolle against the grammar", [][]byte{rollenliste(t, w.ID, priv, 1, nil, rolle{id: "x", pub: pubOf(30), rolle: "Statements"})}, ReasonFormat},
		{"a pubkey twice", [][]byte{rollenliste(t, w.ID, priv, 1, nil, cs, rolle{id: "y", pub: pubOf(2), rolle: RoleStatements})}, ReasonFormat},
		{"gueltig_bis before gueltig_ab", [][]byte{rollenliste(t, w.ID, priv, 1, nil, rolle{id: "x", pub: pubOf(30), rolle: RoleStatements, bis: "2024-01-01T00:00:00Z"})}, ReasonFormat},
		{"an entry names the root key", [][]byte{rollenliste(t, w.ID, priv, 1, nil, rolle{id: "r", pub: w.Pubkey, rolle: RoleStatements})}, ReasonFormat},
		{"another wurzel_id", [][]byte{rollenliste(t, "other-root", priv, 1, nil, cs)}, ReasonNoRoot},
		{"a signature that does not hold", [][]byte{broken(rollenliste(t, w.ID, priv, 1, nil, cs))}, ReasonSignature},
		{"signed by another key", [][]byte{rollenliste(t, w.ID, fremd, 1, nil, cs)}, ReasonSignature},
		{"the furthest of three", [][]byte{
			rollenliste(t, w.ID, priv, 1, func(l map[string]any) { l["neu"] = "x" }, cs),
			broken(rollenliste(t, w.ID, priv, 2, nil, cs)),
			rollenliste(t, "other-root", priv, 3, nil, cs)}, ReasonSignature},
		{"one version, different bytes", [][]byte{rollenliste(t, w.ID, priv, 1, nil, cs), rollenliste(t, w.ID, priv, 1, nil, cs, st1)}, ReasonContradictory},
		{"a later version drops an entry", [][]byte{rollenliste(t, w.ID, priv, 1, nil, cs, st1), rollenliste(t, w.ID, priv, 2, nil, cs)}, ReasonContradictory},
		{"a later version changes a role", [][]byte{rollenliste(t, w.ID, priv, 1, nil, cs, st1),
			rollenliste(t, w.ID, priv, 2, nil, cs, rolle{id: "st-1", pub: pubOf(21), rolle: RoleUpdateManifest})}, ReasonContradictory},
		{"ende_doppelbetrieb spelled differently", [][]byte{
			rollenliste(t, w.ID, priv, 1, func(l map[string]any) { l["ende_doppelbetrieb"] = "2026-07-01T00:00:00Z" }, cs),
			rollenliste(t, w.ID, priv, 2, func(l map[string]any) { l["ende_doppelbetrieb"] = "2026-07-01T00:00:00.000Z" }, cs)}, ReasonContradictory},
		{"ende_doppelbetrieb dropped", [][]byte{
			rollenliste(t, w.ID, priv, 1, func(l map[string]any) { l["ende_doppelbetrieb"] = "2026-07-01T00:00:00Z" }, cs),
			rollenliste(t, w.ID, priv, 2, nil, cs)}, ReasonContradictory},
		{"ende_doppelbetrieb added later", [][]byte{rollenliste(t, w.ID, priv, 1, nil, cs),
			rollenliste(t, w.ID, priv, 2, func(l map[string]any) { l["ende_doppelbetrieb"] = "2026-07-01T00:00:00Z" }, cs)}, ""},
		{"a later version adds an entry and shortens validity", [][]byte{rollenliste(t, w.ID, priv, 1, nil, cs, st1),
			rollenliste(t, w.ID, priv, 2, nil, cs, rolle{id: "st-1", pub: pubOf(21), rolle: RoleStatements, bis: "2027-01-01T00:00:00Z"}, rolle{id: "st-9", pub: pubOf(29), rolle: RoleStatements})}, ""},
	} {
		res := rollenLauf(t, nil, func(o *Options) {
			o.VendorKeys = []VendorKey{{ID: "vendor-1", Pubkey: pubOf(2)}}
			for _, l := range f.lists {
				addList(t, o, l)
			}
		})
		erwarte(t, res, 0) // content defects of a list are never a finding
		st := res.Stats.KeyRoles
		want := RolesNotEffect
		if f.want == "" {
			want = RolesEffective
		}
		if st.Status != want || reason(st) != f.want || st.Candidates != len(f.lists) {
			t.Errorf("%s: %s %s (%d candidates), want %s %s", f.why, st.Status, reason(st), st.Candidates, want, f.want)
		}
	}
}

// TestRollenpruefungR3 holds R3 (a) to (d) and the receipts (10.7.4), with
// the reference values of 10.7.4 on the generated chain.
func TestRollenpruefungR3(t *testing.T) {
	w, priv := wurzel()
	liste := signierteListe(t, w.ID, priv, listKey{id: "vendor-1", pub: pubOf(2), ab: "2025-01-01T00:00:00Z"})
	gegen := rolle{id: "vendor-1", pub: pubOf(2), rolle: RoleCountersigning}
	alsBescheid := rolle{id: "vendor-1", pub: pubOf(2), rolle: RoleStatements}

	// (a) Q gives a key of K_cs^L (the package list) the role statements:
	// Q is not effective, the receipts are judged as without it.
	res := rollenLauf(t, liste, func(o *Options) { addList(t, o, rollenliste(t, w.ID, priv, 1, nil, alsBescheid)) })
	erwarte(t, res, 0)
	if st := res.Stats.KeyRoles; st.Status != RolesNotEffect || reason(st) != ReasonTwoRoles || st.List != nil {
		t.Errorf("R3 (a): %+v", st)
	}
	// (a) also for a list of countersigning keys the auditor passes.
	res = rollenLauf(t, nil, func(o *Options) {
		o.VendorKeys = []VendorKey{{ID: "vendor-1", Pubkey: pubOf(2)}}
		addList(t, o, liste)
		addList(t, o, rollenliste(t, w.ID, priv, 1, nil, alsBescheid))
	})
	if st := res.Stats.KeyRoles; reason(st) != ReasonTwoRoles || len(st.PinsDropped) != 0 {
		t.Errorf("R3 (a), auditor list: %+v", st)
	}
	// The same role list without a list of countersigning keys and only the
	// pin: Q is effective, the pin is dropped, the receipts under vendor-1
	// are RECEIPT_UNVERIFIED with receipt_key_other_role.
	res = rollenLauf(t, nil, func(o *Options) {
		o.VendorKeys = []VendorKey{{ID: "vendor-1", Pubkey: pubOf(2)}}
		addList(t, o, rollenliste(t, w.ID, priv, 1, nil, alsBescheid))
	})
	erwarte(t, res, 1, ClsReceiptUnverified)
	st := res.Stats.KeyRoles
	if st.Status != RolesEffective || len(st.PinsDropped) != 1 || st.PinsDropped[0] != (PinDropped{"vendor-1", RoleCountersigning, RoleStatements}) ||
		notes(st) != NoteReceiptOther+","+NotePinDropped {
		t.Errorf("dropped pin: %+v", st)
	}
	if res.Stats.ReceiptsEstablished != 0 {
		t.Errorf("a dropped pin established %d receipts", res.Stats.ReceiptsEstablished)
	}
	// A countersigning pin that Q names countersigning stays.
	res = rollenLauf(t, nil, func(o *Options) {
		o.VendorKeys = []VendorKey{{ID: "vendor-1", Pubkey: pubOf(2)}}
		addList(t, o, rollenliste(t, w.ID, priv, 1, nil, gegen))
	})
	erwarte(t, res, 0)
	// Q of the largest version not effective after (a): no Q, even though a
	// smaller version counts; a protocol key list that shares a key only
	// with that Q stays effective.
	// K_cs^L holds vendor-1 and vendor-2; version 2 keeps every entry of
	// version 1 and gives vendor-2 the role statements.
	liste2 := signierteListe(t, w.ID, priv, listKey{id: "vendor-1", pub: pubOf(2), ab: "2025-01-01T00:00:00Z"},
		listKey{id: "vendor-2", pub: pubOf(3), ab: "2025-01-01T00:00:00Z"})
	v1 := rollenliste(t, w.ID, priv, 1, nil, gegen, rolle{id: "st-1", pub: pubOf(21), rolle: RoleStatements})
	v2 := rollenliste(t, w.ID, priv, 2, nil, gegen, rolle{id: "st-1", pub: pubOf(21), rolle: RoleStatements},
		rolle{id: "st-x", pub: pubOf(3), rolle: RoleStatements}, rolle{id: "log-x", pub: pubOf(41), rolle: RoleStatements})
	p := protokollliste(t, w.ID, priv, 1, "log-1", rolle{id: "log-1", pub: pubOf(41)})
	g := validSealedChain(t)
	dir := g.writePkg()
	legeListe(t, dir, liste2)
	opt := Options{VendorRoots: []VendorRoot{w}}
	addList(t, &opt, v1)
	addList(t, &opt, v2)
	addList(t, &opt, p)
	r := &run{opt: opt}
	r.fs, _ = openPackage(dir)
	r.man = &manifest{vendorKeys: map[string]string{}}
	r.loadVendorTrust()
	r.checkKeyRoles()
	if r.roles.q != nil || r.roles.stat.Status != RolesNotEffect || reason(&r.roles.stat) != ReasonTwoRoles {
		t.Errorf("R3 (a) on the largest version: q %v, %+v", r.roles.q != nil, r.roles.stat)
	}
	if r.roles.p == nil {
		t.Errorf("P lost its effect through a key shared only with an ineffective Q: %s", r.roles.pReason)
	}

	// (b) Q and P share a key: neither is effective.
	kr := roleRun(t, liste, v1, protokollliste(t, w.ID, priv, 1, "log-1", rolle{id: "log-1", pub: pubOf(21)}))
	if kr.q != nil || kr.p != nil || kr.pReason != PReasonTwoRoles || reason(&kr.stat) != ReasonTwoRoles {
		t.Errorf("R3 (b): q %v p %v %s %+v", kr.q != nil, kr.p != nil, kr.pReason, kr.stat)
	}
	// (c) P shares a key with K_cs^L or with a countersigning pin.
	kr = roleRun(t, liste, protokollliste(t, w.ID, priv, 1, "log-1", rolle{id: "log-1", pub: pubOf(2)}))
	if kr.p != nil || kr.pReason != PReasonTwoRoles {
		t.Errorf("R3 (c), K_cs^L: %v %s", kr.p != nil, kr.pReason)
	}
	kr = roleRunOpt(t, nil, func(o *Options) {
		o.VendorKeys = []VendorKey{{ID: "cs-9", Pubkey: pubOf(42)}}
		addList(t, o, protokollliste(t, w.ID, priv, 1, "log-1", rolle{id: "log-1", pub: pubOf(42)}))
	})
	if kr.p != nil || kr.pReason != PReasonTwoRoles {
		t.Errorf("R3 (c), countersigning pin: %v %s", kr.p != nil, kr.pReason)
	}
	// (d) pins against Q and P.
	kr = roleRunOpt(t, liste, func(o *Options) {
		addList(t, o, rollenliste(t, w.ID, priv, 1, nil, gegen, rolle{id: "um-1", pub: pubOf(23), rolle: RoleUpdateManifest}))
		addList(t, o, protokollliste(t, w.ID, priv, 1, "log-1", rolle{id: "log-1", pub: pubOf(41)}))
		for _, s := range []string{"st-a=" + pubOf(2), "st-b=" + pubOf(41), "st-c=" + pubOf(23), "st-d=" + pubOf(50)} {
			_ = o.AddVendorStatementKey(s)
		}
		for _, s := range []string{"lp-a=" + pubOf(2), "lp-b=" + pubOf(23), "lp-c=" + pubOf(51)} {
			_ = o.AddVendorLogKey(s)
		}
	})
	var got []string
	for _, d := range kr.stat.PinsDropped {
		got = append(got, d.KeyID+":"+d.PinnedAs+":"+d.ListedAs)
	}
	want := "lp-a:protocol:countersigning,lp-b:protocol:update_manifest,st-a:statements:countersigning,st-b:statements:protocol,st-c:statements:update_manifest"
	if strings.Join(got, ",") != want {
		t.Errorf("R3 (d): %s\nwant %s", strings.Join(got, ","), want)
	}
	if len(kr.statementPins) != 1 || kr.statementPins["st-d"] == "" || len(kr.protocolPins) != 1 || kr.protocolPins["lp-c"] == "" {
		t.Errorf("remaining pins %v %v", kr.statementPins, kr.protocolPins)
	}
	pk := (&run{roles: kr}).protocolKeys()
	if len(pk) != 2 || pk["log-1"].pubkey != pubOf(41) || pk["lp-c"].pubkey != pubOf(51) {
		t.Errorf("protocol keys %v", pk)
	}
}

func roleRun(t *testing.T, paketListe []byte, lists ...[]byte) *keyRoles {
	t.Helper()
	return roleRunOpt(t, paketListe, func(o *Options) {
		for _, l := range lists {
			addList(t, o, l)
		}
	})
}

func roleRunOpt(t *testing.T, paketListe []byte, edit func(*Options)) *keyRoles {
	t.Helper()
	g := validSealedChain(t)
	dir := g.writePkg()
	if paketListe != nil {
		legeListe(t, dir, paketListe)
	}
	w, _ := wurzel()
	opt := Options{VendorRoots: []VendorRoot{w}}
	edit(&opt)
	r := &run{opt: opt}
	r.fs, _ = openPackage(dir)
	r.man = &manifest{vendorKeys: map[string]string{}}
	r.loadVendorTrust()
	r.checkKeyRoles()
	return r.roles
}

// TestProtokollschluesselliste: step L1 item 2 of 7.4.10 for the lists of
// the auditor and of extracts: the largest counting version, contradictions,
// and the reasons of registry vendor_log.no_protocol_key_reasons.
func TestProtokollschluesselliste(t *testing.T) {
	w, priv := wurzel()
	k1, k2 := rolle{id: "log-1", pub: pubOf(41)}, rolle{id: "log-2", pub: pubOf(42)}
	for _, f := range []struct {
		why   string
		lists [][]byte
		want  string
		ver   int64
	}{
		{"none", nil, PReasonNoList, 0},
		{"one", [][]byte{protokollliste(t, w.ID, priv, 1, "log", k1)}, "", 1},
		{"a later version", [][]byte{protokollliste(t, w.ID, priv, 1, "log", k1), protokollliste(t, w.ID, priv, 2, "log", k1, k2)}, "", 2},
		{"a later version drops a key", [][]byte{protokollliste(t, w.ID, priv, 1, "log", k1, k2), protokollliste(t, w.ID, priv, 2, "log", k1)}, PReasonContradictory, 0},
		{"different log_id", [][]byte{protokollliste(t, w.ID, priv, 1, "log", k1), protokollliste(t, w.ID, priv, 2, "other", k1)}, PReasonContradictory, 0},
		{"one version, different bytes", [][]byte{protokollliste(t, w.ID, priv, 1, "log", k1), protokollliste(t, w.ID, priv, 1, "log", k2)}, PReasonContradictory, 0},
		{"another root", [][]byte{protokollliste(t, "other", priv, 1, "log", k1)}, PReasonNoRoot, 0},
	} {
		kr := roleRun(t, nil, f.lists...)
		if kr.pReason != f.want || (kr.p == nil) != (f.ver == 0) || kr.p != nil && kr.p.version != f.ver {
			t.Errorf("%s: %s, p %v", f.why, kr.pReason, kr.p != nil)
		}
	}
	// 7.4.7, 7.4.10 L1 item 2: fuellerbindung is hex64 or null; once set,
	// it stays the same in every later version.
	fbA, fbB := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	for _, f := range []struct {
		why   string
		lists [][]byte
		want  string
		ver   int64
	}{
		{"7.4.7 fuellerbindung null counts", [][]byte{protokolllisteFB(t, w.ID, priv, 1, "log", nil, k1)}, "", 1},
		{"7.4.7 fuellerbindung null in two versions", [][]byte{protokolllisteFB(t, w.ID, priv, 1, "log", nil, k1), protokolllisteFB(t, w.ID, priv, 2, "log", nil, k1, k2)}, "", 2},
		{"7.4.4 the derived forming begins later: null, then a value", [][]byte{protokolllisteFB(t, w.ID, priv, 1, "log", nil, k1), protokolllisteFB(t, w.ID, priv, 2, "log", fbA, k1)}, "", 2},
		{"7.4.10 L1 null, a value, the same value", [][]byte{protokolllisteFB(t, w.ID, priv, 1, "log", nil, k1), protokolllisteFB(t, w.ID, priv, 2, "log", fbA, k1), protokolllisteFB(t, w.ID, priv, 3, "log", fbA, k1)}, "", 3},
		{"7.4.10 L1 a value, then null: lists_contradictory", [][]byte{protokolllisteFB(t, w.ID, priv, 1, "log", fbA, k1), protokolllisteFB(t, w.ID, priv, 2, "log", nil, k1)}, PReasonContradictory, 0},
		{"7.4.10 L1 two different values: lists_contradictory", [][]byte{protokolllisteFB(t, w.ID, priv, 1, "log", fbA, k1), protokolllisteFB(t, w.ID, priv, 2, "log", fbB, k1)}, PReasonContradictory, 0},
		{"7.4.10 L1 two different values with null between: lists_contradictory", [][]byte{protokolllisteFB(t, w.ID, priv, 1, "log", fbA, k1),
			protokolllisteFB(t, w.ID, priv, 2, "log", nil, k1), protokolllisteFB(t, w.ID, priv, 3, "log", fbB, k1)}, PReasonContradictory, 0},
		{"7.4.10 L1 null, then two different values: lists_contradictory", [][]byte{protokolllisteFB(t, w.ID, priv, 1, "log", nil, k1),
			protokolllisteFB(t, w.ID, priv, 2, "log", fbA, k1), protokolllisteFB(t, w.ID, priv, 3, "log", fbB, k1)}, PReasonContradictory, 0},
		{"7.4.7 fuellerbindung neither hex64 nor null: format", [][]byte{protokolllisteFB(t, w.ID, priv, 1, "log", "AB"+fbA[2:], k1)}, PReasonFormat, 0},
		{"7.4.7 fuellerbindung empty: format", [][]byte{protokolllisteFB(t, w.ID, priv, 1, "log", "", k1)}, PReasonFormat, 0},
		{"7.4.7 fuellerbindung a number: format", [][]byte{protokolllisteFB(t, w.ID, priv, 1, "log", 0, k1)}, PReasonFormat, 0},
	} {
		kr := roleRun(t, nil, f.lists...)
		if kr.pReason != f.want || (kr.p == nil) != (f.ver == 0) || kr.p != nil && kr.p.version != f.ver {
			t.Errorf("%s: %q, p %v", f.why, kr.pReason, kr.p != nil)
		}
	}
	// With an extract, a list of another log_id: log_id_differs; the
	// extract's own protocol_keys are a candidate.
	x := extractWith(t, "log", protokollliste(t, w.ID, priv, 1, "log", k1))
	kr := roleRunOpt(t, nil, func(o *Options) {
		if err := o.AddVendorLog(x); err != nil {
			t.Fatal(err)
		}
	})
	if kr.p == nil || kr.p.version != 1 {
		t.Errorf("protocol_keys of the extract: %s", kr.pReason)
	}
	kr = roleRunOpt(t, nil, func(o *Options) {
		if err := o.AddVendorLog(extractWith(t, "log", nil)); err != nil {
			t.Fatal(err)
		}
		addList(t, o, protokollliste(t, w.ID, priv, 1, "other", k1))
	})
	if kr.p != nil || kr.pReason != PReasonLogID {
		t.Errorf("log_id differs: %s", kr.pReason)
	}
}

func extractWith(t *testing.T, logID string, protocolKeys []byte) []byte {
	t.Helper()
	var pk any
	if protocolKeys != nil {
		v, err := jcs.Parse(protocolKeys)
		if err != nil {
			t.Fatal(err)
		}
		pk = v
	}
	return canonGo(t, map[string]any{"format": ExtractFormat, "log_id": logID, "chain_id": nil, "protocol_keys": pk, "days": []any{}, "chain_days": []any{}})
}

// TestKeyRolesBericht: key_roles in the JSON output follows the generated
// schema spec/schemas/report_key_roles.schema.json (members, enums), is an
// object for every package that is not a format error and null for one
// (10.10.1).
func TestKeyRolesBericht(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "schemas", "report_key_roles.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Required   []string `json:"required"`
		Properties map[string]struct {
			Enum []any `json:"enum"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	w, priv := wurzel()
	res := rollenLauf(t, nil, func(o *Options) {
		o.VendorKeys = []VendorKey{{ID: "vendor-1", Pubkey: pubOf(2)}}
		addList(t, o, rollenliste(t, w.ID, priv, 1, nil, rolle{id: "vendor-1", pub: pubOf(2), rolle: RoleStatements}))
	})
	js, err := RenderJSON(res)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Stats map[string]json.RawMessage `json:"stats"`
	}
	if err := json.Unmarshal(js, &out); err != nil {
		t.Fatal(err)
	}
	var kr map[string]any
	if err := json.Unmarshal(out.Stats["key_roles"], &kr); err != nil {
		t.Fatal(err)
	}
	var have []string
	for k := range kr {
		have = append(have, k)
	}
	sort.Strings(have)
	req := append([]string{}, schema.Required...)
	sort.Strings(req)
	if strings.Join(have, ",") != strings.Join(req, ",") {
		t.Errorf("members %v, schema %v", have, req)
	}
	for _, m := range []string{"status", "reason"} {
		ok := false
		for _, e := range schema.Properties[m].Enum {
			if e == kr[m] {
				ok = true
			}
		}
		if !ok {
			t.Errorf("%s %v outside %v", m, kr[m], schema.Properties[m].Enum)
		}
	}
	// A format error: key_roles is null.
	g := newGen(t)
	g.genesis()
	dir := g.writePkg()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	fe := Verify(dir, Options{})
	js, _ = RenderJSON(fe)
	if fe.ExitCode != 3 || !strings.Contains(string(js), `"key_roles": null`) {
		t.Errorf("format error: exit %d, key_roles not null", fe.ExitCode)
	}
}

// TestBuiltinRootSource: a role list under the built-in root names it
// builtin; the same root passed by the auditor too is the auditor's.
func TestBuiltinRootSource(t *testing.T) {
	w, priv := wurzel()
	q := rollenliste(t, w.ID, priv, 1, nil, rolle{id: "vendor-1", pub: pubOf(2), rolle: RoleCountersigning})
	for _, f := range []struct {
		roots []VendorRoot
		want  string
	}{
		{[]VendorRoot{{ID: w.ID, Pubkey: w.Pubkey, Builtin: true}}, RootSourceBuiltin},
		{[]VendorRoot{{ID: w.ID, Pubkey: w.Pubkey, Builtin: true}, w}, RootSourceAuditor},
	} {
		roots, _, err := AnkerZusammenfuehren(f.roots, nil)
		if err != nil {
			t.Fatal(err)
		}
		kr := roleRunOpt(t, nil, func(o *Options) { o.VendorRoots = roots; addList(t, o, q) })
		if kr.stat.Status != RolesEffective || kr.q.rootSource != f.want {
			t.Errorf("root source %s, want %s", kr.q.rootSource, f.want)
		}
	}
}
