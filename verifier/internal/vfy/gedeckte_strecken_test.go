package vfy

// Gedeckte Strecken (Spezifikation 11.2, ab Fassung 1.10; Anfrage vom
// 03.10.2026): zwischen zwei aufeinanderfolgenden gegengezeichneten Checkpoints
// mehr als der Verankerungstakt. Kein Befund, kein anderer Exit-Code; der
// Bericht nennt die Strecke, damit nach einer Verlaengerung sichtbar bleibt,
// wie lange die Kette ohne Gegenzeichnung lief.
// / Covered stretches (spec 11.2, from 1.10; request of 2026-10-03).

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// renewalChain is the renewal case: T1 = 1 is countersigned at once (receipt
// at seq 4), then two anchors find no countersignature (seq 5 and 7, a
// licence lapse), and only the checkpoint at seq 8 (T2 = 7) is countersigned
// again (receipt at seq 10). The anchor at seq 3 is the one the receipt at
// seq 4 answers; it lies in the stretch but before that receipt.
func renewalChain(t *testing.T) *gen {
	g := newGen(t)
	g.genesis()                                     // 1
	g.checkpoint(time.Second)                       // 2: tree_size 1
	g.adminAnchor(time.Second)                      // 3: anchor for tree_size 1
	g.receipt(time.Second, 2, 1, g.merkleRootAt(1)) // 4: T1 = 1
	g.adminAnchor(time.Minute)                      // 5: no countersignature
	g.tick(4 * time.Minute)                         // 6
	g.adminAnchor(5 * time.Minute)                  // 7: no countersignature
	g.checkpoint(time.Second)                       // 8: tree_size 7
	g.adminAnchor(time.Second)                      // 9: anchor for tree_size 7
	g.receipt(time.Second, 8, 7, g.merkleRootAt(7)) // 10: T2 = 7
	return g
}

// withinCadence: countersigned checkpoints every five minutes, as in licensed
// operation with a connection to the vendor; no stretch exceeds the cadence.
// (validChain is not this: eleven minutes lie between its two countersigned
// checkpoints, a stretch in the sense of 11.2.)
func withinCadence(t *testing.T) *gen {
	g := newGen(t)
	g.genesis()
	for i := 0; i < 3; i++ {
		g.checkpoint(time.Second)
		g.adminAnchor(time.Second)
		g.receiptForLastBefore(time.Second, 1)
		g.tick(5 * time.Minute)
	}
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	return g
}

// receiptForLastBefore writes a receipt for the checkpoint back entries
// before the last one (the anchor message lies between them).
func (g *gen) receiptForLastBefore(d time.Duration, back int64) string {
	cpSeq := g.seq - back
	treeSize := cpSeq - 1
	return g.receipt(d, cpSeq, treeSize, g.merkleRootAt(treeSize))
}

func serverTSOf(t *testing.T, g *gen, seq int) string {
	t.Helper()
	var e struct {
		Payload struct {
			ServerTS string `json:"server_ts"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(g.lines[seq-1], &e); err != nil || e.Payload.ServerTS == "" {
		t.Fatalf("seq %d carries no server_ts: %v", seq, err)
	}
	return e.Payload.ServerTS
}

func wantStretches(t *testing.T, res Result, want []UnanchoredStretchStat) {
	t.Helper()
	if res.ExitCode == 3 {
		t.Fatalf("exit 3: %+v", res.Findings)
	}
	a, _ := json.Marshal(res.Stats.UnanchoredStretches)
	b, _ := json.Marshal(want)
	if string(a) != string(b) {
		t.Errorf("unanchored_stretches\n got %s\nwant %s", a, b)
	}
}

func TestUnanchoredStretches(t *testing.T) {
	t.Run("renewal after a lapse", func(t *testing.T) {
		g := renewalChain(t)
		res := verifyGen(g, Options{})
		wantStretches(t, res, []UnanchoredStretchStat{{
			AfterTreeSize: 1, FirstSeq: 2, LastSeq: 7,
			FromTS: tsOf(g, 1), ToTS: tsOf(g, 7), SpanMS: 603000,
			UnansweredAnchorMessages: 2,
			ReceiptSeq:               10, ReceiptServerTS: serverTSOf(t, g, 10),
		}})
		// No finding, no other exit code: the stretch is a statement.
		for _, f := range res.Findings {
			if strings.Contains(f.Detail, "stretch") {
				t.Errorf("a finding mentions the stretch: %+v", f)
			}
		}
	})
	t.Run("within the cadence: an empty list, not null", func(t *testing.T) {
		res := verifyGen(withinCadence(t), Options{})
		wantStretches(t, res, []UnanchoredStretchStat{})
		b, _ := RenderJSON(res)
		if !strings.Contains(string(b), `"unanchored_stretches": []`) {
			t.Errorf("JSON lacks an empty unanchored_stretches:\n%s", b)
		}
	})
	for _, c := range []struct {
		name string
		d    time.Duration
		n    int
	}{{"exactly 450,000 ms: no stretch", 448 * time.Second, 0}, {"450,001 ms: a stretch", 448*time.Second + time.Millisecond, 1}} {
		// T1 = 1 (receipt at 3 for the checkpoint at 2), T2 = 4 (receipt at 6
		// for the checkpoint at 5): the span runs from ts_chained of seq 1 to
		// seq 4, 1 s + 1 s + d.
		t.Run(c.name, func(t *testing.T) {
			g := newGen(t)
			g.tsLayout = "2006-01-02T15:04:05.000Z"
			g.genesis()
			g.checkpoint(time.Second)
			g.receiptForLast(time.Second)
			g.tick(c.d)
			g.checkpoint(time.Second)
			g.receiptForLast(time.Second)
			res := verifyGen(g, Options{})
			if got := len(res.Stats.UnanchoredStretches); got != c.n {
				t.Fatalf("%d stretches, want %d: %+v", got, c.n, res.Stats.UnanchoredStretches)
			}
			if c.n == 1 {
				u := res.Stats.UnanchoredStretches[0]
				if u.SpanMS != 450001 || u.AfterTreeSize != 1 || u.LastSeq != 4 || u.ReceiptSeq != 6 || u.UnansweredAnchorMessages != 0 {
					t.Errorf("stretch = %+v", u)
				}
			}
		})
	}
	t.Run("two stretches, each covered by the next receipt", func(t *testing.T) {
		g := newGen(t)
		g.genesis()                   // 1
		g.checkpoint(time.Second)     // 2: tree_size 1
		g.receiptForLast(time.Second) // 3
		g.tick(10 * time.Minute)      // 4
		g.checkpoint(time.Second)     // 5: tree_size 4
		g.receiptForLast(time.Second) // 6
		g.tick(time.Minute)           // 7
		g.checkpoint(time.Second)     // 8: tree_size 7, within the cadence of 4
		g.receiptForLast(time.Second) // 9
		g.adminAnchor(time.Minute)    // 10: no countersignature
		g.tick(20 * time.Minute)      // 11
		g.checkpoint(time.Second)     // 12: tree_size 11
		g.receiptForLast(time.Second) // 13
		res := verifyGen(g, Options{})
		wantStretches(t, res, []UnanchoredStretchStat{
			{AfterTreeSize: 1, FirstSeq: 2, LastSeq: 4, FromTS: tsOf(g, 1), ToTS: tsOf(g, 4), SpanMS: 602000,
				ReceiptSeq: 6, ReceiptServerTS: serverTSOf(t, g, 6)},
			{AfterTreeSize: 7, FirstSeq: 8, LastSeq: 11, FromTS: tsOf(g, 7), ToTS: tsOf(g, 11), SpanMS: 1262000,
				UnansweredAnchorMessages: 1, ReceiptSeq: 13, ReceiptServerTS: serverTSOf(t, g, 13)},
		})
	})
	t.Run("a second receipt for the same tree_size: the first counts", func(t *testing.T) {
		g := newGen(t)
		g.genesis()                                     // 1
		g.checkpoint(time.Second)                       // 2: tree_size 1
		g.receiptForLast(time.Second)                   // 3
		g.tick(10 * time.Minute)                        // 4
		g.checkpoint(time.Second)                       // 5: tree_size 4
		g.receiptForLast(time.Second)                   // 6: covers the stretch
		g.receipt(time.Second, 5, 4, g.merkleRootAt(4)) // 7: the same tree_size again
		res := verifyGen(g, Options{})
		if u := res.Stats.UnanchoredStretches; len(u) != 1 || u[0].ReceiptSeq != 6 {
			t.Errorf("stretches = %+v, want one covered by the receipt at seq 6", u)
		}
	})
	t.Run("an invalid receipt countersigns nothing", func(t *testing.T) {
		g := newGen(t)
		g.genesis()                   // 1
		g.checkpoint(time.Second)     // 2: tree_size 1
		g.receiptForLast(time.Second) // 3
		g.tick(10 * time.Minute)      // 4
		g.checkpoint(time.Second)     // 5: tree_size 4
		// a receipt whose root matches no prefix: FORK_DETECTED, not counted
		g.receipt(time.Second, 5, 4, strings.Repeat("ab", 32))
		res := verifyGen(g, Options{})
		if u := res.Stats.UnanchoredStretches; len(u) != 0 {
			t.Errorf("stretches = %+v, want none: the only later receipt does not count (spec 8.6)", u)
		}
	})
	t.Run("not stated for a format error", func(t *testing.T) {
		g := renewalChain(t)
		g.lines[3] = []byte(`{"not":"an entry"}`)
		res := verifyGen(g, Options{})
		if res.ExitCode != 3 || res.Stats.UnanchoredStretches != nil {
			t.Fatalf("exit %d, stretches %+v, want exit 3 and none", res.ExitCode, res.Stats.UnanchoredStretches)
		}
		b, _ := RenderJSON(res)
		if !strings.Contains(string(b), `"unanchored_stretches": null`) {
			t.Errorf("JSON of a format error does not carry unanchored_stretches null:\n%s", b)
		}
	})
	t.Run("the JSON members of spec 11.2", func(t *testing.T) {
		b, _ := RenderJSON(verifyGen(renewalChain(t), Options{}))
		var m struct {
			Stats struct {
				U []map[string]any `json:"unanchored_stretches"`
			} `json:"stats"`
		}
		if err := json.Unmarshal(b, &m); err != nil || len(m.Stats.U) != 1 {
			t.Fatalf("unanchored_stretches not one object: %v\n%s", err, b)
		}
		want := []string{"after_tree_size", "first_seq", "last_seq", "from_ts", "to_ts", "span_ms", "unanswered_anchor_messages", "receipt_seq", "receipt_server_ts"}
		if len(m.Stats.U[0]) != len(want) {
			t.Errorf("a stretch has %d members, want %d: %v", len(m.Stats.U[0]), len(want), m.Stats.U[0])
		}
		for _, k := range want {
			if _, ok := m.Stats.U[0][k]; !ok {
				t.Errorf("a stretch lacks %s", k)
			}
		}
	})
}

func TestUnanchoredStretchInTextReport(t *testing.T) {
	g := renewalChain(t)
	res := verifyGen(g, Options{})
	for lang, want := range map[string]string{
		"en": "Stretch without countersignature (spec 11.2): seq 2 to 7, from " + tsOf(g, 1) + " to " + tsOf(g, 7) + " (603000 ms (10m3s)), 2 anchor messages without a countersignature of their own; only the receipt at seq 10 (server_ts " + serverTSOf(t, g, 10) + ") covers it.",
		"de": "Strecke ohne Gegenzeichnung (Spezifikation 11.2): seq 2 bis 7, von " + tsOf(g, 1) + " bis " + tsOf(g, 7) + " (603000 ms (10m3s)), 2 Anker-Nachrichten ohne eigene Gegenzeichnung; erst die Quittung an seq 10 (server_ts " + serverTSOf(t, g, 10) + ") deckt sie.",
	} {
		txt := RenderText(res, "pkg", lang)
		if !strings.Contains(txt, want) {
			t.Errorf("%s report lacks %q:\n%s", lang, want, txt)
		}
		if strings.Contains(txt, "MISSING:") || strings.Contains(txt, "%!") {
			t.Errorf("%s report has a missing key or a broken verb:\n%s", lang, txt)
		}
	}
	// Within the cadence there is no such note.
	for _, lang := range []string{"en", "de"} {
		txt := RenderText(verifyGen(withinCadence(t), Options{}), "pkg", lang)
		if strings.Contains(txt, "Stretch without") || strings.Contains(txt, "Strecke ohne") {
			t.Errorf("%s report names a stretch although none exceeds the cadence:\n%s", lang, txt)
		}
	}
}
