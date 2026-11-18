package vfy

// Inputs of the auditor (format spec 2, 10.8, 7.4.8, 8.8.2): what is an
// unusable invocation (an error, exit 3 without report) and what passes the
// grammar and is left to the content checks.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"louwietec.com/ledger-verify/verifier/internal/tsa/tsatest"
)

// mutate parses a JSON object, applies f and writes it back.
func mutate(t *testing.T, b []byte, f func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func qualifiedFile(t *testing.T, certs ...[]byte) []byte {
	var w []any
	for _, c := range certs {
		w = append(w, map[string]any{"zertifikat": base64.StdEncoding.EncodeToString(c), "qualifiziert_ab": "2025-01-01T00:00:00Z"})
	}
	b, _ := json.Marshal(map[string]any{"format": QualifiedRootsFormat, "stand": "2026-10-01T00:00:00.5Z", "quelle": "EU-Vertrauensliste 2026-10", "wurzeln": w})
	return b
}

func TestQualifiedRootsFile(t *testing.T) {
	c := probeStelle()
	good := qualifiedFile(t, c)
	q, err := ParseQualifiedRoots(good)
	if err != nil || len(q.Roots) != 1 || q.Stand != "2026-10-01T00:00:00.5Z" {
		t.Fatalf("%+v %v", q, err)
	}
	w := func(f func(e map[string]any)) []byte {
		return mutate(t, good, func(m map[string]any) { f(m["wurzeln"].([]any)[0].(map[string]any)) })
	}
	for why, b := range map[string][]byte{
		"a byte order mark":        append([]byte{0xef, 0xbb, 0xbf}, good...),
		"not JSON":                 []byte("{"),
		"a duplicate member":       []byte(`{"format":"ledger-tsa-qualifiziert/1","format":"x"}`),
		"a number with a fraction": mutate(t, good, func(m map[string]any) { m["n"] = 1.5 }),
		"an unknown member":        mutate(t, good, func(m map[string]any) { m["extra"] = "x" }),
		"no quelle":                mutate(t, good, func(m map[string]any) { delete(m, "quelle") }),
		"another format":           mutate(t, good, func(m map[string]any) { m["format"] = "ledger-tsa-qualifiziert/2" }),
		"stand with an offset":     mutate(t, good, func(m map[string]any) { m["stand"] = "2026-10-01T00:00:00+01:00" }),
		"quelle empty":             mutate(t, good, func(m map[string]any) { m["quelle"] = "" }),
		"quelle of 257 characters": mutate(t, good, func(m map[string]any) { m["quelle"] = strings.Repeat("ä", 257) }),
		"quelle with a control":    mutate(t, good, func(m map[string]any) { m["quelle"] = "a\u0007b" }),
		"quelle with U+0085":       mutate(t, good, func(m map[string]any) { m["quelle"] = "a\u0085b" }),
		"wurzeln empty":            mutate(t, good, func(m map[string]any) { m["wurzeln"] = []any{} }),
		"zertifikat not B64": w(func(e map[string]any) {
			e["zertifikat"] = e["zertifikat"].(string)[:10] + "\n" + e["zertifikat"].(string)[10:]
		}),
		"zertifikat no certificate": w(func(e map[string]any) {
			e["zertifikat"] = base64.StdEncoding.EncodeToString(tsatest.Seq(tsatest.Int(1)))
		}),
		"zertifikat a number":          w(func(e map[string]any) { e["zertifikat"] = 5 }),
		"qualifiziert_bis not after":   w(func(e map[string]any) { e["qualifiziert_bis"] = "2025-01-01T00:00:00.000Z" }),
		"qualifiziert_ab not rfc3339":  w(func(e map[string]any) { e["qualifiziert_ab"] = "2025-01-01" }),
		"an unknown member of a root":  w(func(e map[string]any) { e["name"] = "x" }),
		"two byte-equal certificates":  qualifiedFile(t, c, c),
		"above 8 MiB":                  append(good, make([]byte, MaxQualifiedRootsBytes)...),
		"a lone surrogate":             []byte(`{"format":"ledger-tsa-qualifiziert/1","stand":"2026-10-01T00:00:00Z","quelle":"\ud800","wurzeln":[]}`),
		"an invalid UTF-8 byte inside": []byte("{\"format\":\"ledger-tsa-qualifiziert/1\",\"stand\":\"2026-10-01T00:00:00Z\",\"quelle\":\"\xff\",\"wurzeln\":[]}"),
	} {
		if _, err := ParseQualifiedRoots(b); err == nil {
			t.Errorf("ledger-tsa-qualifiziert/1, %s: accepted", why)
		}
	}
	if b := w(func(e map[string]any) { e["qualifiziert_bis"] = "2025-01-01T00:00:00.001Z" }); func() error { _, err := ParseQualifiedRoots(b); return err }() != nil {
		t.Error("qualifiziert_bis one millisecond after refused")
	}
	var o Options
	if err := o.SetTSAQualifiedRoots(good); err != nil {
		t.Fatal(err)
	}
	if err := o.SetTSAQualifiedRoots(good); err == nil {
		t.Error("--tsa-qualified-roots twice accepted")
	}
}

func TestKeyListFile(t *testing.T) {
	for _, f := range []struct {
		why string
		in  string
		ok  bool
	}{
		{"the list of countersigning keys", `{"format":"rekorder-herstellerschluessel/1"}`, true},
		{"a role list", `{"format":"ledger-schluesselrollen/1"}`, true},
		{"a protocol key list", `{"format":"ledger-protokollschluessel/1"}`, true},
		{"content defects are no exit 3", `{"format":"ledger-schluesselrollen/1","version":"x","neu":[1]}`, true},
		{"another format", `{"format":"ledger-schluesselrollen/2"}`, false},
		{"no format", `{"version":1}`, false},
		{"format not a string", `{"format":1}`, false},
		{"an array", `[{"format":"ledger-schluesselrollen/1"}]`, false},
		{"a duplicate member", `{"format":"ledger-schluesselrollen/1","format":"ledger-schluesselrollen/1"}`, false},
		{"a number with a fraction", `{"format":"ledger-schluesselrollen/1","version":1.0}`, false},
		{"a number out of range", `{"format":"ledger-schluesselrollen/1","version":9007199254740992}`, false},
		{"not JSON", `{"format":`, false},
	} {
		var o Options
		if err := o.AddVendorKeyList([]byte(f.in)); (err == nil) != f.ok {
			t.Errorf("--vendor-key-list %s: %v, want ok=%v", f.why, err, f.ok)
		}
	}
	var o Options
	big := `{"format":"ledger-schluesselrollen/1","pad":"` + strings.Repeat("x", MaxKeyListBytes) + `"}`
	if err := o.AddVendorKeyList([]byte(big)); err == nil {
		t.Error("a key list above 1 MiB accepted")
	}
}

// extract is a minimal extract of the vendor log that follows 7.4.8.
func extract() map[string]any {
	return map[string]any{
		"format": ExtractFormat, "log_id": "ledger-testprotokoll-1", "chain_id": "0f0e0d0c-0b0a-4900-8807-060504030201",
		"protocol_keys": nil,
		"days": []any{map[string]any{
			"entry":                 map[string]any{"statement_jcs": "{}", "server_key_id": "vendor-log-1", "server_signature": strings.Repeat("a", 128)},
			"timestamps":            []any{"MIIB"},
			"additional_signatures": []any{map[string]any{"alg": "ed25519", "key_id": "vendor-log-2", "signature": strings.Repeat("b", 128)}},
		}},
		"chain_days": []any{
			map[string]any{"day": "2026-01-01", "absent": nil, "present": map[string]any{
				"roots":      []any{map[string]any{"tree_size": 42, "merkle_root": strings.Repeat("c", 64), "recorded_as": "countersigned", "server_ts": "2026-01-01T23:59:30.000Z"}},
				"leaf_index": 3, "path": []any{strings.Repeat("d", 64)}}},
			map[string]any{"day": "2026-01-02", "present": nil, "absent": map[string]any{"neighbours": []any{
				map[string]any{"leaf_index": 1, "position": strings.Repeat("e", 64), "chain_root": strings.Repeat("f", 64), "path": []any{}},
				map[string]any{"leaf_index": 2, "position": strings.Repeat("e", 64), "chain_root": strings.Repeat("f", 64), "path": []any{}}}}},
		},
	}
}

func jsonOf(t *testing.T, x any) []byte {
	b, err := json.Marshal(x)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestExtractGrammar(t *testing.T) {
	var o Options
	if err := o.AddVendorLog(jsonOf(t, extract())); err != nil {
		t.Fatalf("the minimal extract: %v", err)
	}
	day := func(m map[string]any) map[string]any { return m["days"].([]any)[0].(map[string]any) }
	cd := func(m map[string]any, i int) map[string]any { return m["chain_days"].([]any)[i].(map[string]any) }
	root := func(m map[string]any) map[string]any {
		return cd(m, 0)["present"].(map[string]any)["roots"].([]any)[0].(map[string]any)
	}
	for why, f := range map[string]func(m map[string]any){
		"an unknown member":                func(m map[string]any) { m["x"] = 1 },
		"a missing member":                 func(m map[string]any) { delete(m, "protocol_keys") },
		"another format":                   func(m map[string]any) { m["format"] = "ledger-protokollauszug/2" },
		"log_id against key-id":            func(m map[string]any) { m["log_id"] = "a b" },
		"chain_id null with chain_days":    func(m map[string]any) { m["chain_id"] = nil },
		"chain_id upper case":              func(m map[string]any) { m["chain_id"] = "0F0E0D0C-0B0A-4900-8807-060504030201" },
		"protocol_keys an array":           func(m map[string]any) { m["protocol_keys"] = []any{} },
		"statement_jcs of 2049 characters": func(m map[string]any) { day(m)["entry"].(map[string]any)["statement_jcs"] = strings.Repeat("ü", 2049) },
		"server_signature not hex128":      func(m map[string]any) { day(m)["entry"].(map[string]any)["server_signature"] = "ab" },
		"an unknown member of entry":       func(m map[string]any) { day(m)["entry"].(map[string]any)["statement"] = 1 },
		"five timestamps":                  func(m map[string]any) { day(m)["timestamps"] = []any{"A", "B", "C", "D", "E"} },
		"a timestamp of 21849 characters":  func(m map[string]any) { day(m)["timestamps"] = []any{strings.Repeat("A", 21849)} },
		"ed25519 without hex128": func(m map[string]any) {
			day(m)["additional_signatures"].([]any)[0].(map[string]any)["signature"] = "xyz"
		},
		"two equal additional signatures": func(m map[string]any) {
			s := day(m)["additional_signatures"].([]any)
			day(m)["additional_signatures"] = append(s, s[0])
		},
		"a seal of 1025 characters": func(m map[string]any) {
			day(m)["additional_signatures"] = []any{map[string]any{"alg": "ml-dsa", "key_id": "k", "signature": strings.Repeat("!", 1025)}}
		},
		"alg against its grammar": func(m map[string]any) { day(m)["additional_signatures"].([]any)[0].(map[string]any)["alg"] = "Ed25519" },
		"four additional signatures": func(m map[string]any) {
			a := []any{}
			for i := 0; i < 4; i++ {
				a = append(a, map[string]any{"alg": "x", "key_id": fmt.Sprint(i), "signature": "s"})
			}
			day(m)["additional_signatures"] = a
		},
		"both present and absent":    func(m map[string]any) { cd(m, 0)["absent"] = map[string]any{"neighbours": []any{}} },
		"neither present nor absent": func(m map[string]any) { cd(m, 1)["absent"] = nil },
		"two records of one day":     func(m map[string]any) { cd(m, 1)["day"] = "2026-01-01" },
		"a day before the log range": func(m map[string]any) { cd(m, 0)["day"] = "1999-12-31" },
		"a day that does not exist":  func(m map[string]any) { cd(m, 0)["day"] = "2026-02-30" },
		"two roots with equal leaf bytes": func(m map[string]any) {
			p := cd(m, 0)["present"].(map[string]any)
			p["roots"] = append(p["roots"].([]any), root(m))
		},
		"server_ts not rfc3339":         func(m map[string]any) { root(m)["server_ts"] = "2026-01-01 23:59:30Z" },
		"server_ts that does not exist": func(m map[string]any) { root(m)["server_ts"] = "2026-02-30T00:00:00Z" },
		"tree_size 0":                   func(m map[string]any) { root(m)["tree_size"] = 0 },
		"recorded_as reported":          func(m map[string]any) { root(m)["recorded_as"] = "reported" },
		"no roots":                      func(m map[string]any) { cd(m, 0)["present"].(map[string]any)["roots"] = []any{} },
		"a path of 65 hashes": func(m map[string]any) {
			p := []any{}
			for i := 0; i < 65; i++ {
				p = append(p, strings.Repeat("d", 64))
			}
			cd(m, 0)["present"].(map[string]any)["path"] = p
		},
		"a negative leaf_index": func(m map[string]any) { cd(m, 0)["present"].(map[string]any)["leaf_index"] = -1 },
		"neighbours not ascending": func(m map[string]any) {
			n := cd(m, 1)["absent"].(map[string]any)["neighbours"].([]any)
			n[0], n[1] = n[1], n[0]
		},
		"three neighbours": func(m map[string]any) {
			a := cd(m, 1)["absent"].(map[string]any)
			a["neighbours"] = append(a["neighbours"].([]any), a["neighbours"].([]any)[0])
		},
		"a position not hex64": func(m map[string]any) {
			cd(m, 1)["absent"].(map[string]any)["neighbours"].([]any)[0].(map[string]any)["position"] = "ab"
		},
	} {
		x := extract()
		f(x)
		var o Options
		if err := o.AddVendorLog(jsonOf(t, x)); err == nil {
			t.Errorf("extract, %s: accepted", why)
		}
	}
	// What the grammar leaves to the content checks (7.4.10).
	for why, f := range map[string]func(m map[string]any){
		"a gap witness and a countersignature of one root": func(m map[string]any) {
			p := cd(m, 0)["present"].(map[string]any)
			r2 := map[string]any{}
			for k, v := range root(m) {
				r2[k] = v
			}
			r2["recorded_as"] = "gap_witness"
			p["roots"] = append(p["roots"].([]any), r2)
		},
		"server_ts without milliseconds": func(m map[string]any) { root(m)["server_ts"] = "2026-01-01T23:59:30Z" },
		"another seal is not checked": func(m map[string]any) {
			day(m)["additional_signatures"] = []any{map[string]any{"alg": "ecdsa-p256", "key_id": "k", "signature": "abc!"}}
		},
		"neighbours with an equal index": func(m map[string]any) {
			cd(m, 1)["absent"].(map[string]any)["neighbours"].([]any)[1].(map[string]any)["leaf_index"] = 1
		},
		"protocol_keys any object":         func(m map[string]any) { m["protocol_keys"] = map[string]any{"format": "x"} },
		"a mirror extract without a chain": func(m map[string]any) { m["chain_id"], m["chain_days"] = nil, []any{} },
	} {
		x := extract()
		f(x)
		var o Options
		if err := o.AddVendorLog(jsonOf(t, x)); err != nil {
			t.Errorf("extract, %s: %v", why, err)
		}
	}
}

func page() map[string]any {
	return map[string]any{"statement_jcs": `{"kind":"ledger.anchor_history.v2"}`, "server_key_id": "vendor-statements-test-001",
		"server_signature": strings.Repeat("a", 128), "statement": map[string]any{"any": []any{1, "x", nil}}}
}

func TestAnchorHistoryFile(t *testing.T) {
	cont := map[string]any{"format": HistoryFormat, "pages": []any{page(), page()}, "vendor_log": []any{extract()}}
	var o Options
	if err := o.AddAnchorHistory(jsonOf(t, page())); err != nil {
		t.Fatalf("a page: %v", err)
	}
	if err := o.AddAnchorHistory(jsonOf(t, cont)); err != nil {
		t.Fatalf("a container: %v", err)
	}
	if len(o.AnchorHistory) != 2 || len(o.AnchorHistory[1].Pages) != 2 || len(o.VendorLogs) != 1 || !o.VendorLogs[0].Nested {
		t.Errorf("read %+v, %d extracts", o.AnchorHistory, len(o.VendorLogs))
	}
	if err := o.FinishAuditorInputs(time.Now()); err != nil {
		t.Errorf("finish: %v", err)
	}
	for why, b := range map[string][]byte{
		"a page with another member":     jsonOf(t, func() map[string]any { p := page(); p["x"] = 1; return p }()),
		"a page without statement":       jsonOf(t, func() map[string]any { p := page(); delete(p, "statement"); return p }()),
		"statement_jcs empty":            jsonOf(t, func() map[string]any { p := page(); p["statement_jcs"] = ""; return p }()),
		"statement_jcs of 131073":        jsonOf(t, func() map[string]any { p := page(); p["statement_jcs"] = strings.Repeat("a", 131073); return p }()),
		"server_key_id against key-id":   jsonOf(t, func() map[string]any { p := page(); p["server_key_id"] = "a/b"; return p }()),
		"server_signature upper case":    jsonOf(t, func() map[string]any { p := page(); p["server_signature"] = strings.Repeat("A", 128); return p }()),
		"a number in the reading copy":   []byte(`{"statement_jcs":"x","server_key_id":"k","server_signature":"` + strings.Repeat("a", 128) + `","statement":{"n":1.5}}`),
		"a container of another format":  jsonOf(t, map[string]any{"format": "ledger-ankerhistorie/1", "pages": []any{page()}, "vendor_log": []any{}}),
		"a container without vendor_log": jsonOf(t, map[string]any{"format": HistoryFormat, "pages": []any{page()}}),
		"a container without pages":      jsonOf(t, map[string]any{"format": HistoryFormat, "pages": []any{}, "vendor_log": []any{}}),
		"an extract against 7.4.8":       jsonOf(t, map[string]any{"format": HistoryFormat, "pages": []any{page()}, "vendor_log": []any{map[string]any{"format": ExtractFormat}}}),
		"an array":                       []byte(`[]`),
	} {
		var o Options
		if err := o.AddAnchorHistory(b); err == nil {
			t.Errorf("anchor history, %s: accepted", why)
		}
	}
	// Embedded extracts count as files of --vendor-log (7.4.8, 8.8.2).
	var o2 Options
	logs := []any{}
	for i := 0; i < MaxVendorLogFiles; i++ {
		logs = append(logs, extract())
	}
	if err := o2.AddAnchorHistory(jsonOf(t, map[string]any{"format": HistoryFormat, "pages": []any{page()}, "vendor_log": logs})); err != nil {
		t.Fatal(err)
	}
	if err := o2.AddVendorLog(jsonOf(t, extract())); err != nil {
		t.Fatal(err)
	}
	if err := o2.FinishAuditorInputs(time.Now()); err == nil || !strings.Contains(err.Error(), "129 extracts") {
		t.Errorf("129 extracts: %v", err)
	}
}

func TestFinishAuditorInputs(t *testing.T) {
	pub := func(c string) string { return strings.Repeat(c, 64) }
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	for _, f := range []struct {
		why  string
		edit func(o *Options) error
		ok   bool
	}{
		{"nothing", func(o *Options) error { return nil }, true},
		{"one pin per role", func(o *Options) error {
			o.VendorKeys = []VendorKey{{ID: "cs", Pubkey: pub("1")}}
			if err := o.AddVendorStatementKey("st=" + pub("2")); err != nil {
				return err
			}
			return o.AddVendorLogKey("lp=" + pub("3"))
		}, true},
		{"the same statements pin twice", func(o *Options) error {
			_ = o.AddVendorStatementKey("st=" + pub("2"))
			return o.AddVendorStatementKey("st=" + pub("2"))
		}, true},
		{"two statements pins of one key_id", func(o *Options) error {
			_ = o.AddVendorStatementKey("st=" + pub("2"))
			return o.AddVendorStatementKey("st=" + pub("3"))
		}, false},
		{"two protocol pins of one key_id", func(o *Options) error {
			_ = o.AddVendorLogKey("lp=" + pub("2"))
			return o.AddVendorLogKey("lp=" + pub("3"))
		}, false},
		{"a statements pin equal in key_id to a countersigning pin", func(o *Options) error {
			o.VendorKeys = []VendorKey{{ID: "k", Pubkey: pub("1")}}
			return o.AddVendorStatementKey("k=" + pub("2"))
		}, false},
		{"a protocol pin equal in key to a statements pin", func(o *Options) error {
			_ = o.AddVendorStatementKey("st=" + pub("2"))
			return o.AddVendorLogKey("lp=" + pub("2"))
		}, false},
		{"a protocol pin equal in key_id to a countersigning pin", func(o *Options) error {
			o.VendorKeys = []VendorKey{{ID: "k", Pubkey: pub("1")}}
			return o.AddVendorLogKey("k=" + pub("3"))
		}, false},
		{"requested_at at the check time", func(o *Options) error { return o.SetRequestedAt("2026-10-25T12:00:00.000999Z") }, true},
		{"requested_at one millisecond after", func(o *Options) error { return o.SetRequestedAt("2026-10-25T12:00:00.001Z") }, false},
		{"extracts of two log_id", func(o *Options) error {
			x := extract()
			_ = o.AddVendorLog(jsonOf(t, x))
			x["log_id"] = "other"
			return o.AddVendorLog(jsonOf(t, x))
		}, false},
	} {
		var o Options
		err := f.edit(&o)
		if err == nil {
			err = o.FinishAuditorInputs(now)
		}
		if (err == nil) != f.ok {
			t.Errorf("%s: %v, want ok=%v", f.why, err, f.ok)
		}
	}
	// Grammars of the pins and of the request time.
	for _, s := range []string{"st", "st=" + strings.Repeat("A", 64), "s t=" + pub("1"), "=" + pub("1"), "st=" + pub("1")[:63]} {
		var o Options
		if o.AddVendorStatementKey(s) == nil || o.AddVendorLogKey(s) == nil {
			t.Errorf("pin %q accepted", s)
		}
	}
	for _, s := range []string{"2026-10-25T12:00:00+00:00", "2026-10-25 12:00:00Z", "2026-10-25T12:00Z", "2026-W43-7T12:00:00Z"} {
		var o Options
		if o.SetRequestedAt(s) == nil {
			t.Errorf("--requested-at %q accepted", s)
		}
	}
	var o Options
	_ = o.SetRequestedAt("2026-10-25T12:00:00Z")
	if o.SetRequestedAt("2026-10-25T12:00:00Z") == nil {
		t.Error("--requested-at twice accepted")
	}
}

// TestRequestedAtGegenVerifyArgs: with the check time from verify_args.json
// the request time is compared at the start of stage 5; after it, the
// result is FORMAT_ERROR (format spec 10.5, 10.8).
func TestRequestedAtGegenVerifyArgs(t *testing.T) {
	g := validSealedChain(t)
	dir := g.writePkg()
	putFile(t, dir, "verify_args.json", []byte(`{"now":"2026-08-01T10:00:00Z"}`))
	for at, exit := range map[string]int{"2026-08-01T10:00:00.000Z": 0, "2026-08-01T10:00:00.001Z": 3} {
		opt := genAnker(Options{NowFromPackage: true})
		if err := opt.SetRequestedAt(at); err != nil {
			t.Fatal(err)
		}
		if err := opt.FinishAuditorInputs(time.Time{}); err != nil {
			t.Fatal(err)
		}
		res := Verify(dir, opt)
		if res.ExitCode != exit {
			t.Errorf("requested_at %s: exit %d, want %d (%+v)", at, res.ExitCode, exit, res.Findings)
		}
		if exit == 3 && (len(res.Findings) != 1 || res.Findings[0].Class != ClsFormatError || res.Stats.KeyRoles != nil) {
			t.Errorf("requested_at %s: %+v", at, res.Findings)
		}
	}
}
