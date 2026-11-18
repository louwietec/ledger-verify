package vfy

// The evidence level (format spec 10.9) on whole runs: the examples of
// 10.10.2 and 10.10.3, and the values of 10.9.3 the run records for each
// condition (time witnesses, receipts, vendor log, anchor history).

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"louwietec.com/ledger-verify/verifier/internal/tsa/tsatest"
)

// specExample returns the example of the format spec (DE or EN) that
// follows the line starting with intro: the text between the next two
// lines ```.
func specExample(t *testing.T, lang, intro string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "format."+lang+".md"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	for i, l := range lines {
		if !strings.HasPrefix(l, intro) {
			continue
		}
		var out []string
		open := false
		for _, x := range lines[i+1:] {
			if x == "```" {
				if open {
					return out
				}
				open = true
				continue
			}
			if open {
				out = append(out, x)
			}
		}
	}
	t.Fatalf("format.%s.md: no example after %q", lang, intro)
	return nil
}

// evidenceBlockLines are the lines of the block of the evidence level of a
// text report: from its head line to the line on affiliation.
func evidenceBlockLines(txt, lang string) []string {
	head := map[string]string{"de": "Beweisstufe", "en": "Evidence level"}[lang]
	var out []string
	take := false
	for _, l := range strings.Split(txt, "\n") {
		if strings.HasPrefix(l, head) {
			take = true
		}
		if take && l == "" {
			break
		}
		if take {
			out = append(out, l)
		}
	}
	return out
}

// TestEvidenceSpecExamples: the vector valid_basic in the audit environment
// of the corpus gives exactly the object of 10.10.2 (one line, JCS) and the
// block of 10.10.3, in both languages, and the registry example object.
func TestEvidenceSpecExamples(t *testing.T) {
	res := Verify(filepath.Join(repoRoot(t), "spec", "testvectors", "valid_basic"), mitPruefAnker(t, Options{NowFromPackage: true}))
	b, err := json.Marshal(res.Stats.EvidenceLevel)
	if err != nil {
		t.Fatal(err)
	}
	got := canonJSON(t, b)
	for lang, intro := range map[string]string{"de": "Beispiel (Testvektor `valid_basic` in der Prüfumgebung des Korpus, eine Zeile",
		"en": "Example (test vector `valid_basic` in the audit environment of the corpus, one line"} {
		want := specExample(t, lang, intro)
		if len(want) != 1 || got != canonJSON(t, []byte(want[0])) {
			t.Errorf("10.10.2 example (%s):\n%s\nwant\n%s", lang, got, strings.Join(want, "\n"))
		}
	}
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		Verifier struct {
			EL struct {
				Example struct {
					Object json.RawMessage `json:"object"`
				} `json:"example"`
			} `json:"evidence_level"`
		} `json:"verifier"`
	}
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatal(err)
	}
	if want := canonJSON(t, reg.Verifier.EL.Example.Object); got != want {
		t.Errorf("registry example object:\n%s\nwant\n%s", got, want)
	}
	for lang, intro := range map[string]string{"de": "Beispiel (Testvektor `valid_basic` in der Prüfumgebung des Korpus):",
		"en": "Example (test vector `valid_basic` in the audit environment of the corpus):"} {
		want := specExample(t, lang, intro)
		if gotLines := evidenceBlockLines(RenderText(res, "valid_basic", lang), lang); strings.Join(gotLines, "\n") != strings.Join(want, "\n") {
			t.Errorf("10.10.3 example (%s):\n%s\nwant\n%s", lang, strings.Join(gotLines, "\n"), strings.Join(want, "\n"))
		}
	}
}

// TestEvidenceTextStates: the block of 10.10.3 outside the state rated, at
// level 0 and with exit 2 only from material classes.
func TestEvidenceTextStates(t *testing.T) {
	dis := func(lang string) string { return "  " + tableFor(lang).get("ev.disclaimer") }
	// format_error: the state line and the conclusion, no line on
	// affiliation.
	in := ratedInputs(4)
	in.exit, in.affiliation = 3, nil
	ev := evaluateEvidence(in)
	if got := strings.Join(evidenceBlock(ev, nil, tableDE), "\n"); got != "Beweisstufe: nicht bestimmt (Formatfehler)\n"+dis("de") {
		t.Errorf("format_error:\n%s", got)
	}
	// chain_invalid: the state line, the conclusion and the line on
	// affiliation (without open_at_level_2: there is no level).
	in = ratedInputs(4)
	in.exit = 2
	in.classes[ClsHashMismatch] = true
	af := &AffiliationStat{Status: AffNotChecked}
	got := evidenceBlock(evaluateEvidence(in), af, tableEN)
	if len(got) != 3 || got[0] != "Evidence level: none (chain invalid)" || got[1] != dis("en") || got[2] != "  "+affiliationLine(af, tableEN) {
		t.Errorf("chain_invalid:\n%s", strings.Join(got, "\n"))
	}
	// Level 0: the head without reach and, after the missing conditions,
	// the sentence that a confirmed countersignature leads to level 2.
	in = ratedInputs(16)
	got = evidenceBlock(evaluateEvidence(in), af, tableDE)
	want := []string{
		"Beweisstufe: 0 von 3 (Selbstauskunft), seq 1 bis 16.",
		"  Verlauf: Stufe 0 für seq 1 bis 16.",
		"  " + tableDE["ev.level.0.text"],
		"  für Stufe 1 fehlt eine dieser Bedingungen:",
		"    - " + tableDE["ev.cond.time_witness"] + ": " + tableDE["ev.reason.no_time_anchor"],
		"    - " + tableDE["ev.cond.expected_root_found"] + ": " + tableDE["ev.reason.no_expected_root_found"],
		"    - " + tableDE["ev.cond.receipt_key_confirmed"] + ": " + tableDE["ev.reason.no_receipt"],
		"  Eine bestätigte Gegensignatur führt unmittelbar zu Stufe 2.",
		dis("de"),
		"  " + affiliationLine(af, tableDE),
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("level 0:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Exit 2 only from material classes: the head of the chain and the note.
	in = ratedInputs(16)
	in.exit = 2
	in.classes[ClsContentMismatch] = true
	got = evidenceBlock(evaluateEvidence(in), af, tableEN)
	if !strings.HasPrefix(got[0], "Evidence level of the chain: 0 of 3") {
		t.Errorf("material: %s", got[0])
	}
	if !strings.Contains(strings.Join(got, "\n"), "  Note: "+tableEN["ev.note.material_contradiction"]) {
		t.Errorf("material: no note\n%s", strings.Join(got, "\n"))
	}
	// last_receipt_not_confirmed carries the reach of (3).
	in = ratedInputs(16)
	in.receipts = []evReceipt{{seq: 3, treeSize: 2, keyID: "v", pub: "aa", via: keyViaPinned, established: true}, {seq: 9, treeSize: 8, via: keyViaManifest}}
	in.lastCountersignedSeq = 9
	if txt := strings.Join(evidenceBlock(evaluateEvidence(in), af, tableEN), "\n"); !strings.Contains(txt, "level 2 reaches tree_size 2.") {
		t.Errorf("last_receipt_not_confirmed:\n%s", txt)
	}
}

// evQualifiedFile names the probe authority as qualified from from on.
func evQualifiedFile(t *testing.T, from time.Time) *QualifiedRoots {
	return &QualifiedRoots{Stand: "2026-10-01T00:00:00Z", Quelle: "Liste des Prüfers", Roots: []QualifiedRoot{{Cert: mustCert(t, probeStelle()), From: from}}}
}

// qcPresent writes the qcStatements with esi4-qtstStatement-1 into a token.
func qcPresent(s *tsatest.TokenSpec) { s.Exts = [][]byte{tsatest.QCStatement("", tsatest.QTST)} }

// TestEvidenceTimeWitnessRun: what checkTimeAnchors records for (1) and (4)
// (format spec 10.9.3) through whole runs, with the anchors of 10.10.2.
func TestEvidenceTimeWitnessRun(t *testing.T) {
	early := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		edit      func(*tsatest.TokenSpec)
		opt       func() Options
		inPackage bool
		one, four string // reason, "" when met
		credited  string
		notes     string
	}{
		{"10.9.4 (1) met with --tsa-root, (4) no_qualified_root_supplied", nil, func() Options { return Options{TSARoots: [][]byte{probeStelle()}} }, false,
			"", rsNoQualifiedRoot, "time_witness", ""},
		{"10.9.4 (1) no_tsa_root_supplied", nil, func() Options { return Options{} }, false, rsNoTSARoot, rsNoQualifiedRoot, "", ""},
		{"10.9.4 (1) signature_not_checkable: digest SHA-1", func(s *tsatest.TokenSpec) { s.Digest = tsatest.SHA1 }, func() Options { return Options{TSARoots: [][]byte{probeStelle()}} }, false,
			rsSignatureNotCheckable, rsNoQualifiedRoot, "", ""},
		{"10.9.4 (1) token_extensions_unusable: an unknown critical extension", func(s *tsatest.TokenSpec) {
			s.Exts = [][]byte{tsatest.Seq(tsatest.OID("1.2.3.4"), []byte{0x01, 0x01, 0xff}, tsatest.Octets([]byte{0x05, 0x00}))}
		}, func() Options { return Options{TSARoots: [][]byte{probeStelle()}} }, false, rsTokenExtUnusable, rsNoQualifiedRoot, "", ""},
		{"10.9.4 (4) met with a qualified file and a token that declares itself qualified", qcPresent, func() Options { return Options{TSAQualified: evQualifiedFile(t, early)} }, false,
			"", "", "time_witness,time_witness_qualified", ""},
		{"10.9.4 (4) no_qualified_statement", nil, func() Options { return Options{TSAQualified: evQualifiedFile(t, early)} }, false,
			"", rsNoQS, "time_witness", ""},
		{"10.9.4 (4) outside_qualified_window", qcPresent, func() Options {
			return Options{TSAQualified: evQualifiedFile(t, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))}
		}, false,
			"", rsOutsideWindow, "time_witness", ""},
		{"10.9.4 (4) qualified_root_in_package, note tsa_root_in_package", qcPresent, func() Options { return Options{TSAQualified: evQualifiedFile(t, early)} }, true,
			"", rsQualifiedRootInPackage, "time_witness", ntTSARootInPackage},
		{"10.9.4 (4) signing_certificate_not_bound: no ESS attribute", func(s *tsatest.TokenSpec) { qcPresent(s); s.ESS = "none" }, func() Options { return Options{TSAQualified: evQualifiedFile(t, early)} }, false,
			"", rsSigningCertNotBound, "time_witness", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := zeugenKette(t, c.edit)
			dir := g.writePkg()
			if c.inPackage {
				if err := os.MkdirAll(filepath.Join(dir, "keys", "tsa"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "keys", "tsa", "stelle.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: probeStelle()}), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			opt := c.opt()
			opt.Now = g.now.Add(time.Hour)
			res := Verify(dir, genAnker(opt))
			ev := res.Stats.EvidenceLevel
			if ev == nil || ev.State != EvRated {
				t.Fatalf("evidence_level %+v (exit %d %v)", ev, res.ExitCode, res.Findings)
			}
			for code, want := range map[string]string{CondTimeWitness: c.one, CondTimeWitnessQualified: c.four} {
				cd := ev.Conditions.Get(code)
				if want == "" {
					// The TIME_ANCHOR binds the checkpoint of tree_size 1.
					if !cd.Met || cd.Count != 1 || cd.UpToTreeSize == nil || *cd.UpToTreeSize != 1 {
						t.Errorf("%s: %+v, want met", code, cd)
					}
				} else if cd.Met || deref(cd.Reason) != want {
					t.Errorf("%s: %+v, want %s", code, cd, want)
				}
			}
			var credited []string
			for _, x := range ev.Anchors.TSARoots {
				credited = append(credited, x.CreditedFor...)
			}
			if strings.Join(credited, ",") != c.credited {
				t.Errorf("tsa_roots %+v, want credited_for %s", ev.Anchors.TSARoots, c.credited)
			}
			if strings.Join(ev.Notes, ",") != c.notes {
				t.Errorf("notes %v, want %s", ev.Notes, c.notes)
			}
			// 10.9.7 number 1: from level 1 on there is no NO_ANCHOR; the
			// only anchor of this chain is the time witness.
			if *ev.Level >= 1 && classSet(res)[ClsNoAnchor] {
				t.Error("NO_ANCHOR from level 1 on")
			}
			if c.one == "" && (*ev.Level != 1 || segs(ev.Segments) != "1:1-1[time_witness] 0:2-5[]") {
				t.Errorf("level %d segments %s", *ev.Level, segs(ev.Segments))
			}
			if (opt.TSAQualified != nil) != (ev.Anchors.QualifiedRootsFile != nil) {
				t.Errorf("qualified_roots_file %+v", ev.Anchors.QualifiedRootsFile)
			}
		})
	}
}

// TestEvidenceReceiptRun: the origin of the key of a receipt (format spec
// 10.9.3) for (3), vendor_keys and vendor_root_builtin_only.
func TestEvidenceReceiptRun(t *testing.T) {
	t.Run("10.9.4 (3) via the list of the package under the built-in root", func(t *testing.T) {
		g := validSealedChain(t)
		w, priv := wurzel()
		w.Builtin = true
		dir := g.writePkg()
		legeListe(t, dir, signierteListe(t, w.ID, priv, listKey{id: "vendor-1", pub: g.vendPub, ab: "2026-01-01T00:00:00Z"}))
		res := pruefe(t, g, dir, Options{VendorRoots: []VendorRoot{w}})
		ev := res.Stats.EvidenceLevel
		if c := ev.Conditions.ReceiptKeyConfirmed; !c.Met || c.Count != 2 || *c.UpToTreeSize != 6 {
			t.Fatalf("(3) %+v", c)
		}
		vk := ev.Anchors.VendorKeys
		if len(vk) != 1 || vk[0].Via != keyViaList || deref(vk[0].RootFrom) != rootFromBuiltin || deref(vk[0].RootID) != w.ID || *vk[0].ListVersion != 3 {
			t.Errorf("vendor_keys %+v", vk)
		}
		if strings.Join(ev.Notes, ",") != ntVendorRootBuiltinOnly {
			t.Errorf("notes %v", ev.Notes)
		}
		if txt := RenderText(res, "p", "de"); !strings.Contains(txt, "Schlüssel vendor-1 aus Liste Version 3, im Verifier eingebaute Wurzel wurzel-test)") {
			t.Errorf("text names no list:\n%s", txt)
		}
	})
	t.Run("10.9.4 (3) key_not_confirmed without an anchor of the auditor", func(t *testing.T) {
		g := validSealedChain(t)
		res := pruefe(t, g, g.writePkg(), Options{})
		ev := res.Stats.EvidenceLevel
		if c := ev.Conditions.ReceiptKeyConfirmed; c.Met || deref(c.Reason) != rsKeyNotConfirmed || *ev.Level != 0 {
			t.Errorf("(3) %+v level %d", c, *ev.Level)
		}
		// 10.9.1: RECEIPT_UNVERIFIED keeps level 0; it suppresses NO_ANCHOR.
		if !classSet(res)[ClsReceiptUnverified] || classSet(res)[ClsNoAnchor] {
			t.Errorf("classes %v", classSet(res))
		}
	})
	t.Run("10.9.4 (3) key_is_device_key", func(t *testing.T) {
		g := newGen(t)
		g.vendPriv, g.vendPub = g.devPriv["dev-1"], g.devPub["dev-1"]
		g.genesis()
		g.checkpoint(time.Second)
		g.receiptForLast(time.Second)
		g.seal("shutdown")
		res := pruefe(t, g, g.writePkg(), Options{VendorKeys: []VendorKey{{ID: "vendor-1", Pubkey: g.devPub["dev-1"]}}})
		ev := res.Stats.EvidenceLevel
		if c := ev.Conditions.ReceiptKeyConfirmed; c.Met || deref(c.Reason) != rsKeyIsDeviceKey {
			t.Errorf("(3) %+v (exit %d %v)", c, res.ExitCode, res.Findings)
		}
	})
}

// TestEvidenceVendorLogRun: (5) and (7) from what the vendor log records
// (format spec 10.9.3): the classes of step L8 and the time stamps of c(d)
// per root with the purposes log and qualified.
func TestEvidenceVendorLogRun(t *testing.T) {
	early := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	other := tsatest.Cert(tsatest.CertSpec{CN: "Other TSA", Key: tsatest.Ed25519Key("other tsa")})
	qcStamp := func(sj, genTime string) string {
		return base64.StdEncoding.EncodeToString(tsatest.Token(tsatest.TokenSpec{Subject: []byte(sj), Key: tsatest.RSA("tsa test rsa"), Cert: probeStelle(), GenTime: genTime,
			Exts: [][]byte{tsatest.QCStatement("", tsatest.QTST)}}))
	}
	otherStamp := func(sj, genTime string) string {
		return base64.StdEncoding.EncodeToString(tsatest.Token(tsatest.TokenSpec{Subject: []byte(sj), Key: tsatest.Ed25519Key("other tsa"), Cert: other, GenTime: genTime}))
	}
	cases := []struct {
		name  string
		edit  func(w *vlWorld)
		five  string
		seven string
	}{
		{"10.9.4 (5) met, (7) no_qualified_log_root_supplied", func(w *vlWorld) {}, "", rsNoQualifiedLogRoot},
		{"10.9.4 (7) met: the log root is named qualified and the day stamp declares itself qualified", func(w *vlWorld) {
			w.stamps = func(day, sj string) []string { return []string{qcStamp(sj, genTimeAfter(day, 10*time.Minute))} }
			w.opts = func(o *Options) { o.TSAQualified = evQualifiedFile(t, early) }
		}, "", ""},
		{"10.9.4 (7) no_qualified_statement", func(w *vlWorld) {
			w.opts = func(o *Options) { o.TSAQualified = evQualifiedFile(t, early) }
		}, "", rsNoQS},
		{"10.9.4 (7) qualified_day_stamp_late: a second, late stamp of the qualified authority", func(w *vlWorld) {
			// The day is witnessed by the other authority; the probe
			// authority stamps it after end(d) + W.
			w.logRoot = false
			w.stamps = func(day, sj string) []string {
				return []string{otherStamp(sj, genTimeAfter(day, 10*time.Minute)), qcStamp(sj, genTimeAfter(day, 48*time.Hour))}
			}
			w.opts = func(o *Options) {
				o.TSAQualified = evQualifiedFile(t, early)
				o.VendorLogTSARoots = append(o.VendorLogTSARoots, other, probeStelle())
			}
		}, "", rsDayStampLate},
		{"10.9.4 (7) qualified_day_stamp_gap: the qualified stamp lies more than G_q after both receipts", func(w *vlWorld) {
			// The receipts of the chain stand at about 08:00 and 08:11 of
			// the chain day; a stamp at 21:00 of the following day is
			// witnessing (before end(d) + W) but more than 36 hours later.
			w.now = time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
			w.stamps = func(day, sj string) []string { return []string{qcStamp(sj, genTimeAfter(day, 21*time.Hour))} }
			w.opts = func(o *Options) { o.TSAQualified = evQualifiedFile(t, early) }
		}, "", rsDayStampGap},
		{"10.9.4 (5) day_timestamp_not_confirmed without a root for the log", func(w *vlWorld) { w.logRoot = false }, rsDayStampNotConfirmed, rsNoQualifiedLogRoot},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newVLWorld(t)
			c.edit(w)
			res := w.run()
			ev := res.Stats.EvidenceLevel
			if ev == nil || ev.State != EvRated {
				t.Fatalf("evidence_level %+v %v", ev, res.Findings)
			}
			five, seven := ev.Conditions.ReceiptsLogged, ev.Conditions.LogDayQualified
			if c.five == "" && (!five.Met || five.Count != 2 || *five.UpToTreeSize != 6) || c.five != "" && deref(five.Reason) != c.five {
				t.Errorf("(5) %+v, want %q", five, c.five)
			}
			if c.seven == "" && (!seven.Met || seven.Count != 2 || *seven.UpToTreeSize != 6) || c.seven != "" && deref(seven.Reason) != c.seven {
				t.Errorf("(7) %+v, want %q", seven, c.seven)
			}
			if c.seven == "" {
				if len(ev.Anchors.TSARoots) != 1 || strings.Join(ev.Anchors.TSARoots[0].CreditedFor, ",") != CondLogDayQualified {
					t.Errorf("tsa_roots %+v", ev.Anchors.TSARoots)
				}
				// 10.10.1: stand, an input of the auditor, in the form
				// YYYY-MM-DDThh:mm:ss.sssZ.
				if f := ev.Anchors.QualifiedRootsFile; f == nil || f.Stand != "2026-10-01T00:00:00.000Z" || f.Quelle != "Liste des Prüfers" {
					t.Errorf("qualified_roots_file %+v", f)
				}
				// 10.9.1: (3), (5) and (7) without (6) give no level 3, and
				// qualified_time is null below level 3 (10.10.2).
				if *ev.Level != 2 || segs(ev.Segments) != "2:1-6[receipt_key_confirmed] 0:7-10[]" || ev.QualifiedTime != nil {
					t.Errorf("level %d segments %s qualified_time %+v", *ev.Level, segs(ev.Segments), ev.QualifiedTime)
				}
				// 10.9.5: (7) is met, so missing names (6) alone.
				if ev.Next == nil || strings.Join(ev.Next.Missing, ",") != CondCompleteness {
					t.Errorf("next %+v", ev.Next)
				}
				// 10.10.3: a met (7) stands among the lines "present", with
				// its anchors.
				txt := RenderText(res, "p", "en")
				if !strings.Contains(txt, "\n  present: "+tableEN["ev.cond.log_day_qualified"]+" (2, up to tree_size 6; root with fingerprint ") ||
					!strings.Contains(txt, ", file of qualified roots, as of 2026-10-01T00:00:00.000Z, source Liste des Prüfers, vendor log vl-test-1)") {
					t.Errorf("text of (7):\n%s", txt)
				}
			}
			if c.five == "" && !strings.Contains(RenderText(res, "p", "de"), "liegt vor: "+tableDE["ev.cond.receipts_logged"]+" (2, bis tree_size 6; Herstellerprotokoll vl-test-1)") {
				t.Errorf("text of (5)")
			}
		})
	}
}

// TestEvidenceAnchorHistoryRun: (2) with the source anchor_history and (6)
// from the anchor history (format spec 10.9.3), with the statements keys
// of the pages they rest on (10.10.2).
func TestEvidenceAnchorHistoryRun(t *testing.T) {
	w := newAHWorld(t)
	w.add(pg{})
	res := w.run()
	ev := res.Stats.EvidenceLevel
	if ev == nil || ev.State != EvRated {
		t.Fatalf("evidence_level %+v", ev)
	}
	two, six := ev.Conditions.ExpectedRootFound, ev.Conditions.CompletenessFromHistory
	if !two.Met || two.Count != 2 || *two.UpToTreeSize != 6 || strings.Join(ev.Anchors.ExpectedRootSources, ",") != "anchor_history" {
		t.Errorf("(2) %+v sources %v", two, ev.Anchors.ExpectedRootSources)
	}
	if !six.Met || six.Count != 2 || *six.UpToTreeSize != 6 {
		t.Errorf("(6) %+v", six)
	}
	sk := ev.Anchors.StatementKeys
	if len(sk) != 1 || sk[0].KeyID != ahStmtID || sk[0].Via != SourcePinned || sk[0].ListVersion != nil {
		t.Errorf("statement_keys %+v", sk)
	}
	txt := RenderText(res, "p", "de")
	if !strings.Contains(txt, "  liegt vor: "+tableDE["ev.cond.completeness_from_history"]+" (2, bis tree_size 6; Anker-Historie vom 2026-10-10T08:31:00.000Z, angehefteter Bescheidschlüssel st-1)") {
		t.Errorf("text of (6):\n%s", txt)
	}
	if !strings.Contains(txt, "  liegt vor: "+tableDE["ev.cond.expected_root_found"]+" (2, bis tree_size 6; Quellen: Anker-Historie)") {
		t.Errorf("text of (2):\n%s", txt)
	}
	// Without a request time (6) is requested_at_not_supplied; (2) still
	// counts the found history roots.
	w = newAHWorld(t)
	w.r = ""
	w.add(pg{})
	ev = w.run().Stats.EvidenceLevel
	if c := ev.Conditions.CompletenessFromHistory; c.Met || deref(c.Reason) != rsRequestedAtNotSupplied {
		t.Errorf("(6) without R: %+v", c)
	}
}

// TestEvidenceRegistryMirror holds the hand-copied lists and texts of the
// evidence level against spec/registry.json (format spec 10.9: "Codes,
// Reihenfolgen, Regel und Texte stehen in der Registry"); where the
// registry lags the specification, against the specification
// (speclag_test.go).
func TestEvidenceRegistryMirror(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	type text struct {
		DE string `json:"de"`
		EN string `json:"en"`
	}
	var reg struct {
		Verifier struct {
			EL struct {
				Material   []string `json:"material_classes"`
				States     map[string]text
				StateOrder []string `json:"state_order"`
				Levels     map[string]struct {
					NameDE string `json:"name_de"`
					NameEN string `json:"name_en"`
					DE     string `json:"de"`
					EN     string `json:"en"`
				} `json:"levels"`
				CondOrder   []string        `json:"condition_order"`
				Informative json.RawMessage `json:"informative"`
				Rule        map[string]struct {
					Need       string            `json:"need"`
					Conditions []json.RawMessage `json:"conditions"`
				} `json:"rule"`
				Conditions map[string]struct {
					DE          string          `json:"de"`
					EN          string          `json:"en"`
					Global      []string        `json:"global"`
					Stages      []string        `json:"stages"`
					Informative json.RawMessage `json:"informative"`
					GapMaxMS    *int64          `json:"gap_max_ms"`
				} `json:"conditions"`
				ReasonOrder []string        `json:"reason_order"`
				Reasons     map[string]text `json:"reasons"`
				NoteOrder   []string        `json:"note_order"`
				Notes       map[string]text `json:"notes"`
				Texts       map[string]text `json:"texts"`
			} `json:"evidence_level"`
			TP struct {
				Keys []struct {
					Ed25519 string `json:"ed25519"`
				} `json:"published_test_keys"`
			} `json:"timestamp_profile"`
		} `json:"verifier"`
	}
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatal(err)
	}
	el := reg.Verifier.EL
	same := func(what string, a, b []string) {
		if strings.Join(a, ",") != strings.Join(b, ",") {
			t.Errorf("%s: %v, registry %v", what, a, b)
		}
	}
	same("condition_order", evConditionOrder, el.CondOrder)
	sameOrAhead(t, "reason_order", evReasonOrder, el.ReasonOrder, specReasonOrder(t))
	same("note_order", evNoteOrder, el.NoteOrder)
	same("state_order", []string{EvRated, EvChainInvalid, EvFormatError}, el.StateOrder)
	same("material_classes", sortedKeys(evMaterialClasses), el.Material)
	// 10.9.1: condition (7) is no longer informative; the registry names no
	// informative condition.
	if len(el.Informative) != 0 {
		t.Errorf("registry evidence_level.informative %s", el.Informative)
	}
	// Registry rule: an element of conditions is a code or a group of the
	// same form {need, conditions} (here: any of time_witness_qualified and
	// log_day_qualified).
	for k, r := range el.Rule {
		var n int
		if err := json.Unmarshal([]byte(k), &n); err != nil {
			t.Fatal(err)
		}
		var items []string
		for _, c := range r.Conditions {
			var code string
			if json.Unmarshal(c, &code) == nil {
				items = append(items, code)
				continue
			}
			var g struct {
				Need       string   `json:"need"`
				Conditions []string `json:"conditions"`
			}
			if err := json.Unmarshal(c, &g); err != nil {
				t.Fatalf("rule %s: %s", k, c)
			}
			items = append(items, g.Need+"("+strings.Join(g.Conditions, " ")+")")
		}
		var code []string
		for _, it := range evRule[n].items {
			if it.group != nil {
				code = append(code, "any("+strings.Join(it.group, " ")+")")
			} else {
				code = append(code, it.code)
			}
		}
		same("rule "+k, code, items)
		if evRule[n].need != r.Need {
			t.Errorf("rule %s need %s, registry %s", k, evRule[n].need, r.Need)
		}
	}
	for code, c := range el.Conditions {
		same("global "+code, evGlobal[code], c.Global)
		sameOrAhead(t, "stages "+code, evStages[code], c.Stages, specStages(t, code))
		if len(c.Informative) != 0 {
			t.Errorf("registry condition %s informative %s", code, c.Informative)
		}
	}
	var keys []string
	for _, k := range reg.Verifier.TP.Keys {
		if k.Ed25519 != "" {
			keys = append(keys, k.Ed25519)
		}
	}
	same("published_test_keys (ed25519)", PublishedTestEd25519, keys)
	check := func(key, de, en string) {
		switch {
		case tableDE[key] == de && tableEN[key] == en:
		case specAheadText(t, key):
			t.Logf("%s: the registry %q / %q lags the specification", key, de, en)
		default:
			t.Errorf("%s: %q / %q, registry %q / %q", key, tableDE[key], tableEN[key], de, en)
		}
	}
	for k, v := range el.Texts {
		check("ev."+k, v.DE, v.EN)
	}
	for _, k := range []string{EvChainInvalid, EvFormatError} {
		check("ev.state."+k, el.States[k].DE, el.States[k].EN)
	}
	for n, l := range el.Levels {
		check("ev.level."+n+".name", l.NameDE, l.NameEN)
		check("ev.level."+n+".text", l.DE, l.EN)
	}
	for code, c := range el.Conditions {
		check("ev.cond."+code, c.DE, c.EN)
	}
	for code, r := range el.Reasons {
		check("ev.reason."+code, r.DE, r.EN)
	}
	if _, ok := el.Reasons[rsDayStampGap]; !ok && !specAheadText(t, "ev.reason."+rsDayStampGap) {
		t.Errorf("reason %s neither in the registry nor in the specification", rsDayStampGap)
	}
	// G_q = 129 600 000 ms (10.9.1, 10.9.4): the limit of the registry, or
	// of the specification where the registry lacks it.
	if g := el.Conditions[CondLogDayQualified].GapMaxMS; g != nil && *g != evQualifiedGapMS {
		t.Errorf("G_q %d, registry %d", evQualifiedGapMS, *g)
	} else if g == nil && !strings.Contains(specFile(t, "format.de.md"), "G_q = 129 600 000 ms (36 Stunden)") {
		t.Error("G_q neither in the registry nor in the specification")
	}
	for code, n := range el.Notes {
		check("ev.note."+code, n.DE, n.EN)
	}
}

// specTemplate returns the line of the template of the block of the
// evidence level (format spec 10.10.3) that starts with prefix after its
// indentation, without the indentation.
func specTemplate(t *testing.T, lang, prefix string) string {
	t.Helper()
	head := map[string]string{"de": "#### 10.10.3", "en": "#### 10.10.3"}[lang]
	for _, l := range specSection(t, specFile(t, "format."+lang+".md"), head) {
		if x := strings.TrimLeft(l, " "); strings.HasPrefix(x, prefix) {
			return x
		}
	}
	t.Fatalf("format.%s.md 10.10.3: no template line %q", lang, prefix)
	return ""
}

// TestEvidenceTextTwoWays: the block of format spec 10.10.3 with condition
// (7) as the second way to level 3, in both languages: the line on the
// qualified time directly after the text of the level (time witness of
// the chain, or time stamp of the vendor log with the gap in whole
// minutes, rounded down, as hours and minutes), a met (7) among the lines
// "liegt vor", and (4) and (7) in one line in the place of (4) when both
// are missing; no line for an informative condition.
func TestEvidenceTextTwoWays(t *testing.T) {
	gapWords := map[string][2]string{"de": {" Std. ", " Min."}, "en": {" h ", " min"}}
	for _, lang := range []string{"de", "en"} {
		tb := tableFor(lang)
		qline := map[string]string{"de": "qualifiziert bestätigt:", "en": "qualified confirmation:"}[lang]
		tpl := specTemplate(t, lang, qline)
		alts := strings.Split(strings.TrimPrefix(tpl, qline+" "), " | ")
		if len(alts) != 2 {
			t.Fatalf("%s: template %q", lang, tpl)
		}
		fill := func(s string, kv ...string) string {
			for i := 0; i+1 < len(kv); i += 2 {
				s = strings.ReplaceAll(s, kv[i], kv[i+1])
			}
			return s
		}
		gapName := map[string]string{"de": "<Abstand>", "en": "<gap>"}[lang]
		for _, c := range []struct {
			q    EvidenceQualifiedTime
			want string
		}{
			{EvidenceQualifiedTime{Via: CondTimeWitnessQualified, TreeSize: 300, Latest: "2026-08-02T00:10:00.000Z"},
				qline + " " + fill(alts[0], "<latest>", "2026-08-02T00:10:00.000Z", "<t>", "300")},
			// 30 h 5 min 59.999 s: whole minutes, rounded down.
			{EvidenceQualifiedTime{Via: CondLogDayQualified, TreeSize: 350, Latest: "2026-08-02T06:05:00.000Z", GapMS: ptr64(30*3_600_000 + 5*60_000 + 59_999)},
				qline + " " + fill(alts[1], "<latest>", "2026-08-02T06:05:00.000Z", "<t>", "350", gapName, "30"+gapWords[lang][0]+"5"+gapWords[lang][1])},
			{EvidenceQualifiedTime{Via: CondLogDayQualified, TreeSize: 2, Latest: "2026-08-02T00:00:59.000Z", GapMS: ptr64(59_999)},
				qline + " " + fill(alts[1], "<latest>", "2026-08-02T00:00:59.000Z", "<t>", "2", gapName, "0"+gapWords[lang][0]+"0"+gapWords[lang][1])},
			{EvidenceQualifiedTime{Via: CondLogDayQualified, TreeSize: 2, Latest: "2026-08-03T00:00:00.000Z", GapMS: ptr64(evQualifiedGapMS)},
				qline + " " + fill(alts[1], "<latest>", "2026-08-03T00:00:00.000Z", "<t>", "2", gapName, "36"+gapWords[lang][0]+"0"+gapWords[lang][1])},
		} {
			if got := qualifiedTimeLine(&c.q, tb); got != c.want || strings.ContainsAny(got, "<>{}") {
				t.Errorf("%s: %q, want %q", lang, got, c.want)
			}
		}
		// The block at level 3 through (7): the line directly after the
		// text of the level, (7) among the lines "liegt vor".
		in := ratedInputs(4)
		in.vlStatus, in.logID = VendorLogChecked, "vl-1"
		r := qroot("QL")
		r.log = true
		x := l8(3, 2, RcIncluded)
		x.stamps = []evDayStamp{stamp()}
		in.l8, in.roots = []evL8{x}, []evRoot{r}
		in.receipts = []evReceipt{{seq: 3, treeSize: 2, keyID: "v", pub: strings.Repeat("ab", 32), via: keyViaPinned, established: true}}
		up := int64(2)
		in.compl = HistoryComplStat{Status: "established", UpToTreeSize: &up}
		af := &AffiliationStat{Status: AffNotChecked}
		block := evidenceBlock(evaluateEvidence(in), af, tb)
		i := indexOf(block, "  "+tb.get("ev.level.3.text"))
		if i < 0 || i+1 >= len(block) || block[i+1] != "  "+qline+" "+fill(alts[1], "<latest>", "2026-08-02T00:10:00.000Z", "<t>", "2", gapName, "12"+gapWords[lang][0]+"10"+gapWords[lang][1]) {
			t.Errorf("%s: no line on the qualified time after the text of level 3:\n%s", lang, strings.Join(block, "\n"))
		}
		met := map[string]string{"de": "  liegt vor: ", "en": "  present: "}[lang]
		if !strings.Contains(strings.Join(block, "\n"), "\n"+met+tb.get("ev.cond.log_day_qualified")+" (1, ") {
			t.Errorf("%s: (7) not among the lines present:\n%s", lang, strings.Join(block, "\n"))
		}
		// The block at level 2 with neither (4) nor (7): one line in the
		// place of (4) with both reasons.
		in = ratedInputs(4)
		in.receipts = []evReceipt{{seq: 3, treeSize: 2, keyID: "v", pub: strings.Repeat("ab", 32), via: keyViaPinned, established: true}}
		ev := evaluateEvidence(in)
		block = evidenceBlock(ev, af, tb)
		tplEither := specTemplate(t, lang, map[string]string{"de": "- <Bedingung (4)>", "en": "- <condition (4)>"}[lang])
		want := fill(tplEither, map[string]string{"de": "<Bedingung (4)>", "en": "<condition (4)>"}[lang], tb.get("ev.cond.time_witness_qualified"),
			map[string]string{"de": "<Bedingung (7)>", "en": "<condition (7)>"}[lang], tb.get("ev.cond.log_day_qualified"),
			map[string]string{"de": "<Grund von (4)>", "en": "<reason of (4)>"}[lang], tb.get("ev.reason.no_time_anchor"),
			map[string]string{"de": "<Grund von (7)>", "en": "<reason of (7)>"}[lang], tb.get("ev.reason.vendor_log_not_supplied"))
		var missing []string
		for _, l := range block {
			if strings.HasPrefix(l, "    - ") {
				missing = append(missing, l)
			}
		}
		if len(missing) != 3 || missing[0] != "    "+want ||
			!strings.HasPrefix(missing[1], "    - "+tb.get("ev.cond.receipts_logged")+": ") ||
			!strings.HasPrefix(missing[2], "    - "+tb.get("ev.cond.completeness_from_history")+": ") {
			t.Errorf("%s: missing lines\n%s\nwant first\n    %s", lang, strings.Join(missing, "\n"), want)
		}
		for _, l := range block {
			if strings.Contains(l, qline) {
				t.Errorf("%s: a line on the qualified time below level 3: %s", lang, l)
			}
		}
		for _, k := range []string{"ev.informative_head", "ev.informative_met", "ev.informative_missing"} {
			if _, ok := tb[k]; ok {
				t.Errorf("%s: the text %s of an informative condition is still there", lang, k)
			}
		}
	}
}

func ptr64(n int64) *int64 { return &n }

// TestEvidenceCompletenessPages: (6) rests on the used pages of the
// package that enter the completeness of step H11 (format spec 10.10.2,
// anchors.statement_keys), and an older page never enters it (8.8.4,
// "Ältere Seiten"): a fresh page under st-1 and an older copy under a
// second pinned statements key name st-1 alone for (6), in the text and in
// the note published_test_key_credited, while (2) with the source
// anchor_history rests on both pages, which carry the found roots.
func TestEvidenceCompletenessPages(t *testing.T) {
	w := newAHWorld(t)
	w.add(pg{})
	old := pg{ts: ahTS("08:14:00.000")}
	sj := string(canonGo(t, w.statement(old)))
	priv2, pub2 := keyFromSeed(0x43)
	w.files = append(w.files, pageFile(t, sj, [2]string{"st-2", sign(priv2, sj)}))
	w.opts = func(o *Options) {
		if err := o.AddVendorStatementKey("st-2=" + pub2); err != nil {
			t.Fatal(err)
		}
	}
	res := w.run()
	ev := res.Stats.EvidenceLevel
	ah := res.Stats.AnchorHistory
	if ev == nil || ev.State != EvRated || ah == nil || ah.Pages.UsedFresh != 1 || ah.Pages.UsedStale != 1 {
		t.Fatalf("evidence_level %+v anchor_history pages %+v (%v)", ev, ah.Pages, res.Findings)
	}
	if c := ev.Conditions.CompletenessFromHistory; !c.Met {
		t.Fatalf("(6) %+v (%v)", c, res.Findings)
	}
	var keys []string
	for _, k := range ev.text.historyKeys {
		keys = append(keys, k.KeyID)
	}
	if strings.Join(keys, ",") != ahStmtID {
		t.Errorf("(6) rests on the statements keys %v, want %s", keys, ahStmtID)
	}
	keys = nil
	for _, k := range ev.Anchors.StatementKeys {
		keys = append(keys, k.KeyID)
	}
	if strings.Join(keys, ",") != ahStmtID+",st-2" {
		t.Errorf("statement_keys %v: (2) rests on both pages", keys)
	}
	txt := RenderText(res, "p", "de")
	if !strings.Contains(txt, "Anker-Historie vom 2026-10-10T08:31:00.000Z, angehefteter Bescheidschlüssel st-1)") || strings.Contains(txt, "Bescheidschlüssel st-2") {
		t.Errorf("text of (6):\n%s", txt)
	}
}
