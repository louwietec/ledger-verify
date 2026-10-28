package vfy

// Decisions A to E on the vendor log of edition 1.10, each against the
// section of format spec (format.de.md) that states it.

import (
	"encoding/json"
	"strings"
	"testing"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
)

// TestSec10_10_1_FormatErrorMembersNull (decision A; 10.10.1, 8.6, 11.2): a
// package with a report and exit 3 carries completeness, residual_window and
// unanchored_stretches with the value null ("nicht bewertet"), never left
// out.
func TestSec10_10_1_FormatErrorMembersNull(t *testing.T) {
	f := newGen(t)
	f.tick(0)
	res := verifyGen(f, Options{})
	if res.ExitCode != 3 {
		t.Fatalf("exit %d, want 3; findings %v", res.ExitCode, res.Findings)
	}
	b, err := RenderJSON(res)
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Stats map[string]json.RawMessage `json:"stats"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"completeness", "residual_window", "unanchored_stretches", "key_roles", "vendor_log"} {
		v, ok := m.Stats[k]
		if !ok {
			t.Errorf("stats.%s left out at exit 3, want null:\n%s", k, b)
			continue
		}
		if string(v) != "null" {
			t.Errorf("stats.%s = %s at exit 3, want null", k, v)
		}
	}
}

// TestSec7_4_10_L2_DayOfReadsTheTypeDate (decision B; 7.4.10 L2 dayOf,
// section 2 type date): dayOf needs only a calendar date of the type date;
// the log range is a content rule of L2 (c). A signed entry with day
// 1999-12-31 gets its VENDOR_LOG_CONTRADICTION on that day and counts in
// days.contradictory.
func TestSec7_4_10_L2_DayOfReadsTheTypeDate(t *testing.T) {
	w := newVLWorld(t)
	w.entry = func(day string, m map[string]any) {
		if day == vlChainDay {
			m["day"] = "1999-12-31"
		}
	}
	res := w.run()
	wantClasses(t, res, 1, ClsVendorLogContradict, ClsVendorLogUnverified)
	if d := detailOf(res, ClsVendorLogContradict); !strings.HasPrefix(d, "day 1999-12-31: ") || !strings.Contains(d, "[entry_format]") {
		t.Errorf("VENDOR_LOG_CONTRADICTION %q, want it on day 1999-12-31 with entry_format", d)
	}
	vl := res.Stats.VendorLog
	if vl == nil || vl.Days.Contradictory != 1 {
		t.Fatalf("days %+v, want contradictory 1", vl)
	}
	if vl.Days.Supplied != 2 || vl.Days.Established != 1 || vl.Days.Missing != 1 {
		t.Errorf("days %+v", vl.Days)
	}
}

// TestSec7_4_10_L1Item4_AllProtocolPinsDropped (decision C; 7.4.10 L1 item
// 4, 10.7.4 R3 (d)): with no effective list and every protocol pin dropped by
// item 3 the reason is key_in_two_roles, not no_list.
func TestSec7_4_10_L1Item4_AllProtocolPinsDropped(t *testing.T) {
	// The effective role list gives the pinned protocol key the role
	// statements, so R3 (d) drops the pin.
	roleList := func(w *vlWorld) func(o *Options) {
		return func(o *Options) {
			root, priv := wurzel()
			o.VendorRoots = append(o.VendorRoots, root)
			addList(t, o, rollenliste(t, root.ID, priv, 1, nil, rolle{id: "st-x", pub: vlPub(w.key), rolle: RoleStatements}))
		}
	}
	for _, c := range []struct {
		why   string
		setup func(w *vlWorld)
	}{
		{"no list supplied", func(w *vlWorld) {}},
		{"a list under a root the auditor did not supply", func(w *vlWorld) {
			w.extract = func(x map[string]any) { l, _ := w.protocolList(); x["protocol_keys"] = l }
		}},
	} {
		t.Run(c.why, func(t *testing.T) {
			w := newVLWorld(t)
			c.setup(w)
			w.opts = roleList(w)
			res := w.run()
			wantClasses(t, res, 1, ClsVendorLogUnverified)
			kr := res.Stats.KeyRoles
			if kr == nil || len(kr.PinsDropped) != 1 || kr.PinsDropped[0] != (PinDropped{w.keyID, RoleProtocol, RoleStatements}) {
				t.Fatalf("key_roles %+v, want the protocol pin dropped", kr)
			}
			vl := res.Stats.VendorLog
			if vl == nil || vl.Status != VendorLogNoProtocolKey || vl.NoKeyReason != PReasonTwoRoles {
				t.Fatalf("vendor_log %+v, want no_protocol_key with key_in_two_roles", vl)
			}
			if d := detailOf(res, ClsVendorLogUnverified); !strings.Contains(d, "reason "+PReasonTwoRoles+": ") {
				t.Errorf("VENDOR_LOG_UNVERIFIED %q", d)
			}
			for _, lang := range []string{"de", "en"} {
				want := tableFor(lang).get("vlog.reason." + PReasonTwoRoles)
				if txt := RenderText(res, "pkg", lang); !strings.Contains(txt, want) {
					t.Errorf("%s text lacks %q", lang, want)
				}
			}
		})
	}
}

// TestSec7_4_10_L7_ReceiptsOfL8 (decision D; 7.4.10 L7, L8, 10.9.4 r5'): L7
// takes the days of the receipts of L8, whose signature holds and which have
// no RECEIPT_INVALID. Two receipts whose signature holds but whose
// checkpoint_seq names no CHECKPOINT (RECEIPT_INVALID) widen no range: no day
// is missing.
func TestSec7_4_10_L7_ReceiptsOfL8(t *testing.T) {
	w := newVLWorld(t)
	w.days = []string{"2026-07-31"}
	n := 0
	for i, l := range w.g.lines {
		v, _ := jcs.Parse(l)
		if v.Get("event_type").Str != "CHECKPOINT_RECEIPT" {
			continue
		}
		w.g.editLine(i, func(v *jcs.Value) { setMember(v.Get("payload"), "checkpoint_seq", jInt(1)) })
		n++
	}
	if n != 2 {
		t.Fatalf("%d receipts, want 2", n)
	}
	res := w.run()
	if res.ExitCode != 2 || !classSet(res)[ClsReceiptInvalid] {
		t.Fatalf("exit %d, findings %v; want RECEIPT_INVALID", res.ExitCode, res.Findings)
	}
	if strings.Contains(detailOf(res, ClsReceiptInvalid), "server_signature") {
		t.Fatalf("a receipt signature fails: %s", detailOf(res, ClsReceiptInvalid))
	}
	if hasCode(res, ClsVendorLogUnverified, "days_not_supplied") {
		t.Errorf("L7 widened the range by receipts with RECEIPT_INVALID: %s", detailOf(res, ClsVendorLogUnverified))
	}
	vl := res.Stats.VendorLog
	if vl == nil || vl.Status != VendorLogChecked {
		t.Fatalf("vendor_log %+v", vl)
	}
	if vl.Days.Missing != 0 {
		t.Errorf("days.missing %d, want 0", vl.Days.Missing)
	}
	receiptsAre(t, vl, VendorLogReceiptsStat{})
}

// TestSec10_10_2_GapWitnessesCountRoots (decision E; 10.10.2
// logged_roots.gap_witnesses): distinct roots (tree_size, merkle_root) among
// the checked rows with recorded_as gap_witness, not distinct leaves. Two
// gap witnesses of one root at different server_ts are two leaves, one
// root.
func TestSec10_10_2_GapWitnessesCountRoots(t *testing.T) {
	w := newVLWorld(t)
	w.rows = func(rows []map[string]any) []map[string]any {
		for _, ts := range []string{"2026-08-01T07:58:00.000Z", "2026-08-01T07:59:00.000Z"} {
			rows = append(rows, map[string]any{"tree_size": rows[0]["tree_size"], "merkle_root": rows[0]["merkle_root"], "recorded_as": "gap_witness", "server_ts": ts})
		}
		return rows
	}
	res := w.run()
	wantClasses(t, res, 0)
	vl := res.Stats.VendorLog
	if vl == nil || vl.LoggedRoots == nil {
		t.Fatalf("vendor_log %+v", vl)
	}
	if lr := *vl.LoggedRoots; lr != (VendorLogRootsStat{MatchingPrefix: 2, GapWitnesses: 1}) {
		t.Errorf("logged_roots %+v, want matching_prefix 2, gap_witnesses 1", lr)
	}
}
