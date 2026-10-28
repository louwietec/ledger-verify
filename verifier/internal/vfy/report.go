package vfy

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// RenderJSON returns the stable machine-readable result.
func RenderJSON(res Result) ([]byte, error) {
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// RenderText renders the human-readable report in the given language
// ("de" or "en"); unknown languages fall back to English.
func RenderText(res Result, pkgPath, lang string) string {
	t := tableFor(lang)
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	line("%s", t.get("report.title"))
	line("%s", strings.Repeat("=", len([]rune(t.get("report.title")))))
	line("%-28s %s", t.get("report.package")+":", pkgPath)
	if res.Stats.ChainID != "" {
		line("%-28s %s", t.get("report.chain")+":", res.Stats.ChainID)
	}
	line("%-28s %d.%d", t.get("report.spec")+":", specMajor, specMinor)
	line("%-28s %d", t.get("report.entries")+":", res.Stats.Entries)
	line("%-28s %d", t.get("report.checkpoints")+":", res.Stats.Checkpoints)
	if res.Stats.Receipts > 0 {
		// Same rule as for time witnesses: both numbers, so that "40
		// Quittungen" never reads as "40 from the vendor" when the key came
		// only from the package (spec 7.1).
		line("%-28s %d (%d %s)", t.get("report.receipts")+":", res.Stats.Receipts,
			res.Stats.ReceiptsEstablished, t.get("report.receipts_established"))
	} else {
		line("%-28s %d", t.get("report.receipts")+":", res.Stats.Receipts)
	}
	if vl := res.Stats.VendorList; vl != nil {
		// Spec 7.1: whether a newer list exists is not visible from the
		// package — the auditor compares version and issue time with the vendor.
		line("%-28s %s %d, %s %s, %s %s", t.get("report.vendor_list")+":",
			t.get("report.vendor_list_version"), vl.Version,
			t.get("report.vendor_list_issued"), vl.Issued,
			t.get("report.vendor_list_root"), vl.Root)
	}
	line("%-28s %d", t.get("report.segments")+":", res.Stats.Segments)
	if res.Stats.TimeAnchors > 0 {
		// Both numbers, always. A line that showed only the count would let
		// "3 Zeitzeugen" read as "3 proven" — which is exactly what an
		// unverified witness is not.
		line("%-28s %d (%d %s)", t.get("report.time_anchors")+":", res.Stats.TimeAnchors,
			res.Stats.TimeAnchorsVerified, t.get("report.time_anchors_verified"))
	}
	if res.Stats.FirstTS != "" {
		line("%-28s %s", t.get("report.first_ts")+":", res.Stats.FirstTS)
		line("%-28s %s", t.get("report.last_ts")+":", res.Stats.LastTS)
	}
	switch {
	case res.Stats.NowSource == "":
		// The package could not be opened, so no check time was resolved
		// (Verify returns before resolveNow): no line, as in verifier2,
		// whose report has none either; spec 10.10.3 prescribes none. Before
		// 1.1.0 the line printed a missing text key and blamed
		// verify_args.json, which nobody had asked for.
	case res.Stats.Now == "":
		// The check time was requested from the package and could not be
		// determined (spec 10.8): the run stopped with FORMAT_ERROR.
		line("%-28s %s (%s)", t.get("report.now")+":", t.get("report.now_not_determined"), t.get("report.now_source."+res.Stats.NowSource))
	default:
		line("%-28s %s (%s)", t.get("report.now")+":", res.Stats.Now, t.get("report.now_source."+res.Stats.NowSource))
	}
	// Chain end (spec 8.6) directly above the result: from spec 1.6 exit 0/1
	// presuppose a sealed end, so the reader must see the one next to the other.
	ce := res.Stats.ChainEnd
	switch {
	case ce == nil:
		line("%-28s %s", t.get("report.chain_end")+":", t.get("report.chain_end_not_judged"))
	case ce.Status == "sealed":
		line("%-28s %s", t.get("report.chain_end")+":",
			fmt.Sprintf(t.get("report.chain_end_sealed"), ce.SealTS, ce.SealReason, ce.SealSeq))
	default:
		v := fmt.Sprintf(t.get("report.chain_end_incomplete"), ce.LastSeq, ce.LastType, ce.LastTS)
		if ce.LastCriticalWithoutCheckpoint {
			v += "; " + t.get("report.chain_end_critical")
		}
		line("%-28s %s", t.get("report.chain_end")+":", v)
	}
	if ce != nil {
		// Spec 8.6: with UNSEALED_END the verifier MUST state the last
		// countersigned checkpoint or that there is none; for a sealed chain it
		// is the reference for the same comparison.
		if lc := res.Stats.LastCountersigned; lc != nil {
			herkunft := t.get("report.last_countersigned_established")
			if !lc.KeyEstablished {
				herkunft = t.get("report.last_countersigned_unverified")
			}
			line("%-28s %s", t.get("report.last_countersigned")+":",
				fmt.Sprintf(t.get("report.last_countersigned_value"), lc.CheckpointSeq, lc.TreeSize, lc.ServerTS))
			line("%-28s merkle_root %s (%s %s, %s)", "", lc.MerkleRoot, t.get("report.last_countersigned_key"), lc.ServerKeyID, herkunft)
		} else {
			line("%-28s %s", t.get("report.last_countersigned")+":", t.get("report.last_countersigned_none"))
		}
	}
	// Spec 8.6 (from 1.9): what this run can say about completeness, and
	// spec 11.2: the residual window, measured. Both for every package that is
	// not a format error.
	if c := res.Stats.Completeness; c != nil {
		v := t.get("report.completeness_not_established")
		switch {
		case c.Status != "established" || c.UpToTreeSize == nil:
		case len(c.Sources) == 1 && c.Sources[0] == "auditor":
			v = fmt.Sprintf(t.get("report.completeness_established"), *c.UpToTreeSize)
		default:
			// From 1.10 the report names the sources of the found roots
			// (spec 8.6).
			v = fmt.Sprintf(t.get("report.completeness_established_sources"), *c.UpToTreeSize, sourcesText(c.Sources, t))
		}
		line("%-28s %s", t.get("report.completeness")+":", v)
	}
	if rw := res.Stats.ResidualWindow; rw != nil {
		var v string
		if rw.AfterTreeSize == 0 || rw.SpanMS == nil {
			v = fmt.Sprintf(t.get("report.residual_window_none"), rw.Entries, rw.LastSeq)
		} else {
			v = fmt.Sprintf(t.get("report.residual_window_value"), rw.Entries, rw.FirstSeq, rw.LastSeq, rw.AfterTreeSize, fmtMS(*rw.SpanMS))
		}
		if rw.BeyondCadence {
			v += "; " + t.get("report.residual_window_beyond")
		}
		line("%-28s %s", t.get("report.residual_window")+":", v)
	}
	// Deletion holds still active at the chain end (spec 9.3), one per line
	// under the label; no line at all when none is active. hold_id and
	// reference are free text and quoted, so their bounds stay visible.
	// / Löschsperren, die am Kettenende aktiv sind; ohne Sperre keine Zeile.
	for i, h := range res.Stats.LegalHolds {
		label := ""
		if i == 0 {
			label = t.get("report.legal_holds") + ":"
		}
		v := fmt.Sprintf(t.get("report.legal_hold_value"), strconv.Quote(h.HoldID), h.ScopeFrom, h.ScopeTo, h.SetSeq, strconv.Quote(h.Reference))
		if h.ScopeSeq != 0 {
			v += " (" + fmt.Sprintf(t.get("report.legal_hold_scope_replaced"), h.ScopeSeq) + ")"
		}
		line("%-28s %s", label, v)
	}
	// The block of the vendor log (spec 10.10.3) after the summary lines,
	// with the phrases of the registry; none for a format error (exit 3).
	if vl := res.Stats.VendorLog; vl != nil {
		line("")
		for _, s := range vendorLogBlock(vl, t) {
			line("%s", s)
		}
	}
	// The block of the anchor history (spec 10.10.3) after the block of the
	// vendor log; none for a format error.
	if ah := res.Stats.AnchorHistory; ah != nil {
		line("")
		for _, s := range anchorHistoryBlock(ah, res.Stats, t) {
			line("%s", s)
		}
	}
	// The block of the evidence level (spec 10.9, 10.10.3), whose last line
	// is the line on affiliation; for a format error the state line and the
	// conclusion only.
	if ev := res.Stats.EvidenceLevel; ev != nil {
		line("")
		for _, s := range evidenceBlock(ev, res.Stats.Affiliation, t) {
			line("%s", s)
		}
	}
	line("")
	line("%s: %s (%s %d)", t.get("report.result"), t.get(fmt.Sprintf("exit.%d", res.ExitCode)), t.get("report.exit"), res.ExitCode)
	line("")
	line("%s (%d):", t.get("report.findings"), len(res.Findings))
	if len(res.Findings) == 0 {
		line("  %s", t.get("report.no_findings"))
	}
	for _, f := range res.Findings {
		loc := ""
		if f.Seq > 0 {
			loc = fmt.Sprintf(" %s=%d:", t.get("report.seq"), f.Seq)
		}
		// "[CLASS] seq=N: text" or "[CLASS] text": a space always follows
		// the bracket, which tools reading the finding headers rely on.
		line("  [%s]%s %s", f.Class, loc, t.get("class."+f.Class))
		if f.Detail != "" {
			line("      %s", f.Detail)
		}
	}
	line("")
	line("%s:", t.get("report.notes"))
	if ce != nil {
		if ce.Status == "sealed" {
			line("  - %s", t.get("note.chain_end_sealed"))
		} else {
			line("  - %s", t.get("note.chain_end_incomplete"))
		}
	}
	// The comparison with the vendor's most recent root countersigned BEFORE
	// the package was requested is the one step that settles an incomplete
	// end (spec 8.6) and the one check against a chain cut off behind an
	// earlier seal (spec 11.2) — so the report says, for every package that
	// is not a format error, that without it no statement about completeness
	// is possible, and how to take it, with the chain_id to ask for (8.6,
	// from 1.9). With a root found it says how far completeness reaches.
	if c := res.Stats.Completeness; c != nil {
		if c.Status == "established" && c.UpToTreeSize != nil && len(c.Sources) == 1 && c.Sources[0] == "auditor" {
			line("  - %s", fmt.Sprintf(t.get("note.completeness_established"), *c.UpToTreeSize, *c.UpToTreeSize))
		} else if c.Status == "established" && c.UpToTreeSize != nil {
			line("  - %s", fmt.Sprintf(t.get("note.completeness_established_sources"), *c.UpToTreeSize, sourcesText(c.Sources, t), *c.UpToTreeSize))
		} else {
			line("  - %s", fmt.Sprintf(t.get("note.completeness_not_established"), res.Stats.ChainID))
		}
	}
	// Spec 11.2 (from 1.9): the residual window measured, not a fixed "~5
	// minutes or 1,000 entries" — the format does not bound it.
	if rw := res.Stats.ResidualWindow; rw != nil {
		if rw.AfterTreeSize == 0 || rw.FromTS == nil || rw.SpanMS == nil {
			line("  - %s", fmt.Sprintf(t.get("note.residual_window_none"), rw.Entries, rw.LastSeq, rw.ToTS, rw.UnansweredAnchorMessages))
		} else {
			line("  - %s", fmt.Sprintf(t.get("note.residual_window_measured"), rw.Entries, rw.AfterTreeSize, rw.FirstSeq, rw.LastSeq, *rw.FromTS, rw.ToTS, fmtMS(*rw.SpanMS), rw.UnansweredAnchorMessages))
		}
		if rw.BeyondCadence {
			line("  - %s", t.get("note.residual_window_beyond"))
		}
	}
	// Spec 11.2 (from 1.10): a stretch a later receipt covers, but in which
	// nothing was countersigned while it ran (a renewal after a lapse, egress
	// off for a while). One note per stretch; no finding.
	for _, u := range res.Stats.UnanchoredStretches {
		line("  - %s", fmt.Sprintf(t.get("note.unanchored_stretch"), u.FirstSeq, u.LastSeq, u.FromTS, u.ToTS, fmtMS(u.SpanMS), u.UnansweredAnchorMessages, u.ReceiptSeq, u.ReceiptServerTS))
	}
	if res.Stats.GenesisLicenseNotCommitment {
		line("  - %s", t.get("note.genesis_license"))
	}
	// The notes of the anchor history (spec 8.8.7), in the registry order.
	if ah := res.Stats.AnchorHistory; ah != nil {
		for _, n := range ah.Notes {
			line("  - %s", t.get("ah.note."+n))
		}
	}
	line("  - %s", t.get("note.purpose"))
	return b.String()
}

// vendorLogBlock renders the block of the vendor log of spec 10.10.3: for
// the status checked three lines from the registry texts checked_head (or,
// without a head, checked_no_head), receipts and compare in this order, the
// first unindented and the other two indented by two spaces, the layout of
// the block of the anchor history; for no_protocol_key the reason of step L1
// item 4; for not_supplied that the report says nothing about the logging.
func vendorLogBlock(vl *VendorLogStat, t i18nTable) []string {
	logID := ""
	if vl.LogID != nil {
		logID = *vl.LogID
	}
	switch vl.Status {
	case VendorLogNotSupplied:
		return []string{t.get("vlog.not_supplied")}
	case VendorLogNoProtocolKey:
		return []string{fmt.Sprintf(t.get("vlog.no_protocol_key"), t.get("vlog.reason."+vl.NoKeyReason))}
	}
	var out []string
	if h := vl.Head; h != nil {
		w := t.get("vlog.no")
		if h.Witnessed {
			w = t.get("vlog.yes")
		}
		out = append(out, fmt.Sprintf(t.get("vlog.checked_head"), logID, h.Day, h.DayHash, w, h.SeenIn, vl.DistinctFiles))
	} else {
		out = append(out, fmt.Sprintf(t.get("vlog.checked_no_head"), logID))
	}
	if rc := vl.Receipts; rc != nil {
		out = append(out, "  "+fmt.Sprintf(t.get("vlog.receipts"), rc.Included, rc.NotIncluded, rc.Unchecked, rc.Missing, rc.Pending, rc.BeforeStart, rc.Future))
	}
	// Without a head 10.10.3 replaces only the first line of the block; the
	// other two, the advice to compare the day hash included, stay.
	return append(out, "  "+t.get("vlog.compare"))
}

// fillText replaces every {name} of a phrase of the registry by its value.
func fillText(s string, kv ...string) string {
	for i := 0; i+1 < len(kv); i += 2 {
		s = strings.ReplaceAll(s, "{"+kv[i]+"}", kv[i+1])
	}
	return s
}

// historySourceText is <Quelle> of spec 10.10.3: pinned, or the role list
// with its version and root and where the root comes from.
func historySourceText(pinned bool, l *HistoryKeyListStat, t i18nTable) string {
	switch {
	case pinned || l == nil:
		return t.get("ah.source_pinned")
	case l.RootSource == RootSourceBuiltin:
		return fillText(t.get("ah.source_role_list_builtin"), "version", strconv.FormatInt(l.Version, 10), "wurzel_id", l.WurzelID)
	}
	return fillText(t.get("ah.source_role_list_auditor"), "version", strconv.FormatInt(l.Version, 10), "wurzel_id", l.WurzelID)
}

// anchorHistoryBlock renders the block of the anchor history of spec
// 10.10.3: with used pages of the package the head line, the request time
// (or that a truncation is not judged), the roots and the completeness;
// with pages but none used, the reasons and the completeness; without an
// anchor history, how to fetch it.
func anchorHistoryBlock(ah *AnchorHistoryStat, st Stats, t i18nTable) []string {
	itoa := strconv.Itoa
	if ah.Status == HistoryNotSupplied {
		return []string{fillText(t.get("ah.not_supplied"), "chain_id", st.ChainID)}
	}
	compl := fillText(t.get("ah.completeness_not_established"), "reason", t.get("ah.compl."+deref(ah.Completeness.Reason)))
	if ah.Completeness.Status == "established" && ah.Completeness.UpToTreeSize != nil {
		compl = fillText(t.get("ah.completeness_established"), "up_to_tree_size", strconv.FormatInt(*ah.Completeness.UpToTreeSize, 10))
	}
	var out []string
	if ah.used == 0 {
		var rs []string
		for _, c := range ah.PageReasons {
			rs = append(rs, t.get("ah.reason."+c))
		}
		out = append(out, fillText(t.get("ah.none_used"), "distinct", itoa(ah.Pages.Distinct), "reasons", strings.Join(rs, "; ")))
		if ah.Owner != nil && *ah.Owner == "differs" {
			out = append(out, "  "+t.get("ah.owner_differs_detail"))
		}
		return append(out, "  "+compl)
	}
	var keys []string
	for _, k := range ah.keyTexts {
		keys = append(keys, fillText(t.get("ah.key_item"), "key_id", k.keyID, "source", historySourceText(k.source == SourcePinned, k.list, t)))
	}
	out = append(out, fillText(t.get("ah.used_head"), "used", itoa(ah.used), "distinct", itoa(ah.Pages.Distinct),
		"fresh", itoa(ah.Pages.UsedFresh), "stale", itoa(ah.Pages.UsedStale), "first", deref(ah.Issued.First), "last", deref(ah.Issued.Last),
		"keys", strings.Join(keys, ", ")))
	if ah.RequestedAt != nil {
		out = append(out, "  "+fillText(t.get("ah.requested_at"), "requested_at", *ah.RequestedAt))
	} else {
		out = append(out, "  "+fillText(t.get("ah.no_request_time"), "unjudged", itoa(ah.Roots.BeyondPackageUnjudged)))
	}
	rt := ah.Roots
	out = append(out, "  "+fillText(t.get("ah.roots"), "distinct", itoa(rt.Distinct), "entries", strconv.FormatInt(st.Entries, 10),
		"found", itoa(rt.Found), "differing", itoa(rt.DifferingBeforeRequest+rt.DifferingAfterRequest),
		"before_request", itoa(rt.BeyondPackageBeforeRequest), "recent", itoa(rt.BeyondPackageRecent), "after_request", itoa(rt.BeyondPackageAfterRequest)))
	return append(out, "  "+compl)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// periodsText renders <Zeiträume> of spec 10.10.3.
func periodsText(ps []AffPeriod, t i18nTable) string {
	var out []string
	for _, p := range ps {
		s := fillText(t.get("aff.period_open"), "from", p.From)
		if p.Until != nil {
			s = fillText(t.get("aff.period_closed"), "from", p.From, "until", *p.Until)
		}
		if p.Merged {
			s += " " + t.get("aff.merged")
		}
		out = append(out, s)
	}
	return strings.Join(out, ", ")
}

// affiliationLine renders the line on affiliation of spec 10.10.3
// (registry verifier.affiliation.texts) without the sentence
// open_at_level_2, which evidenceBlock adds from level 2 on.
func affiliationLine(af *AffiliationStat, t i18nTable) string {
	itoa := func(p *int) string {
		if p == nil {
			return "0"
		}
		return strconv.Itoa(*p)
	}
	key, src := "", ""
	if af.StatedBy != nil {
		key = af.StatedBy.ServerKeyID
		src = historySourceText(af.StatedBy.KeySource == AffSourcePinned, af.statedList, t)
	}
	var in, out []AffPeriod
	for _, p := range af.Periods {
		if p.OverlapsPackage {
			in = append(in, p)
		} else {
			out = append(out, p)
		}
	}
	switch af.Status {
	case AffAffiliated:
		var bs []string
		for _, b := range af.Bases {
			bs = append(bs, t.get("aff.basis."+b))
		}
		phrase := "aff.affiliated"
		if af.VendorItself {
			phrase = "aff.affiliated_vendor_itself"
		}
		return fillText(t.get(phrase), "bases", strings.Join(bs, ", "), "periods", periodsText(in, t), "k", itoa(af.ReceiptsInPeriods),
			"n", itoa(af.ReceiptsTotal), "as_of", deref(af.AsOf), "key_id", key, "source", src)
	case AffNotAffiliated:
		s := ""
		if af.Span != nil {
			s = fillText(t.get("aff.not_affiliated"), "from", af.Span.From, "to", af.Span.To, "as_of", deref(af.AsOf), "key_id", key, "source", src)
		}
		if len(out) > 0 {
			s += " " + fillText(t.get("aff.not_affiliated_outside"), "periods", periodsText(out, t))
		}
		return s
	case AffNotDetermined:
		why := deref(af.Reason)
		reason := fillText(t.get("aff.reason."+why), "known_since", deref(af.KnownSince))
		if why == "known_range_too_short" && af.KnownSince == nil {
			// format spec 10.10.3: with known_since null the reason reads
			// that the vendor currently cannot name the customer for any
			// time.
			reason = t.get("aff.reason." + affKnownRangeNullText)
		}
		return fillText(t.get("aff.not_determined"), "reason", reason)
	}
	if af.receiptHolds {
		return t.get("aff.not_checked") + " " + fillText(t.get("aff.not_checked_fetch"), "chain_id", af.chainID)
	}
	return t.get("aff.not_checked") + " " + t.get("aff.not_checked_never_anchored")
}

// sourcesText names the sources of the found expected roots (spec 8.6).
func sourcesText(src []string, t i18nTable) string {
	var out []string
	for _, x := range src {
		out = append(out, t.get("report.source."+x))
	}
	return strings.Join(out, ", ")
}

// evidenceBlock renders the block of the evidence level of spec 10.10.3:
// the head line, the segments, the text of the level, the line on the
// qualified time when qualified_time is not null, a line per condition that
// is met, what the next level lacks (with (4) and (7) in one line when both
// are missing for level 3), the notes, the conclusion of 10.9.8 and, as its
// last line, the line on affiliation. Every follow-up line is indented by
// two spaces, the lines of the missing conditions by four. Outside the
// state rated: the state line, the conclusion and (for chain_invalid) the
// line on affiliation.
func evidenceBlock(ev *EvidenceLevelStat, af *AffiliationStat, t i18nTable) []string {
	itoa := strconv.Itoa
	i64 := func(n int64) string { return strconv.FormatInt(n, 10) }
	label := t.get("ev.label")
	if ev.text.material {
		label = t.get("ev.label_chain")
	}
	in := func(s string) string { return "  " + s }
	var out []string
	if ev.State != EvRated || ev.Level == nil || ev.Conditions == nil {
		out = append(out, fillText(t.get("ev.state_line"), "label", t.get("ev.label"), "state", t.get("ev.state."+ev.State)))
		out = append(out, in(t.get("ev.disclaimer")))
		if ev.State == EvChainInvalid && af != nil {
			out = append(out, in(affiliationLine(af, t)))
		}
		return out
	}
	level := *ev.Level
	name := t.get("ev.level." + itoa(level) + ".name")
	if level == 0 {
		out = append(out, fillText(t.get("ev.head_level0"), "label", label, "name", name, "entries", i64(*ev.Entries)))
	} else {
		out = append(out, fillText(t.get("ev.head"), "label", label, "level", itoa(level), "name", name,
			"up_to_tree_size", i64(*ev.UpToTreeSize), "entries", i64(*ev.Entries)))
	}
	var segs []string
	for _, sg := range ev.Segments {
		if sg.Level == 0 {
			segs = append(segs, fillText(t.get("ev.segment_level0"), "first_seq", i64(sg.FirstSeq), "last_seq", i64(sg.LastSeq)))
			continue
		}
		var bs []string
		for _, b := range sg.Basis {
			bs = append(bs, t.get("ev.cond."+b))
		}
		segs = append(segs, fillText(t.get("ev.segment"), "level", itoa(sg.Level), "first_seq", i64(sg.FirstSeq), "last_seq", i64(sg.LastSeq),
			"basis", strings.Join(bs, t.get("ev.basis_joiner"))))
	}
	out = append(out, in(fillText(t.get("ev.segments"), "segments", strings.Join(segs, t.get("ev.segment_joiner")))))
	out = append(out, in(t.get("ev.level."+itoa(level)+".text")))
	if q := ev.QualifiedTime; q != nil {
		out = append(out, in(qualifiedTimeLine(q, t)))
	}
	for _, code := range evConditionOrder {
		c := ev.Conditions.Get(code)
		if !c.Met {
			continue
		}
		out = append(out, in(fillText(t.get("ev.met"), "condition", t.get("ev.cond."+code), "count", itoa(c.Count),
			"up_to_tree_size", i64(*c.UpToTreeSize), "anchors", evAnchorsText(ev, code, t))))
	}
	if nx := ev.Next; nx != nil {
		head := "ev.next_all"
		if nx.Need == "any" {
			head = "ev.next_any"
		}
		out = append(out, in(fillText(t.get(head), "n", itoa(nx.Level))))
		// 10.9.5, 10.10.3: when both (4) and (7) are missing for level 3,
		// they stand in one line in the place of (4), with both reasons.
		either := indexOf(nx.Missing, CondTimeWitnessQualified) >= 0 && indexOf(nx.Missing, CondLogDayQualified) >= 0
		for _, code := range nx.Missing {
			switch {
			case either && code == CondLogDayQualified:
				continue
			case either && code == CondTimeWitnessQualified:
				out = append(out, in(in(fillText(t.get("ev.missing_either"),
					"condition_4", t.get("ev.cond."+CondTimeWitnessQualified), "condition_7", t.get("ev.cond."+CondLogDayQualified),
					"reason_4", evReasonText(ev.Conditions.Get(CondTimeWitnessQualified), t),
					"reason_7", evReasonText(ev.Conditions.Get(CondLogDayQualified), t)))))
			default:
				out = append(out, in(in(fillText(t.get("ev.missing_item"), "condition", t.get("ev.cond."+code), "reason", evReasonText(ev.Conditions.Get(code), t)))))
			}
		}
		// 10.9.5, 10.10.3: at level 0 without (3), after the missing
		// conditions, the line that a confirmed countersignature leads
		// directly to level 2, indented by two spaces.
		if level == 0 && !ev.Conditions.ReceiptKeyConfirmed.Met {
			out = append(out, in(t.get("ev.direct_to_2")))
		}
	}
	for _, n := range ev.Notes {
		txt := t.get("ev.note." + n)
		if n == ntLastReceiptNotConfirm && ev.Conditions.ReceiptKeyConfirmed.UpToTreeSize != nil {
			txt = fillText(txt, "t", i64(*ev.Conditions.ReceiptKeyConfirmed.UpToTreeSize))
		}
		out = append(out, in(fillText(t.get("ev.note"), "text", txt)))
	}
	out = append(out, in(t.get("ev.disclaimer")))
	if af != nil {
		s := affiliationLine(af, t)
		// 10.10.3: with not_checked and not_determined, from level 2 on.
		if level >= 2 && (af.Status == AffNotChecked || af.Status == AffNotDetermined) {
			s += " " + t.get("aff.open_at_level_2")
		}
		out = append(out, in(s))
	}
	return out
}

// qualifiedTimeLine is the line "qualifiziert bestätigt" of 10.10.3: latest
// with the tree_size of the item, for (7) with gap_ms in whole minutes,
// rounded down, as hours and minutes.
func qualifiedTimeLine(q *EvidenceQualifiedTime, t i18nTable) string {
	ts := strconv.FormatInt(q.TreeSize, 10)
	if q.Via != CondLogDayQualified || q.GapMS == nil {
		return fillText(t.get("ev.qualified_time_witness"), "latest", q.Latest, "tree_size", ts)
	}
	minutes := *q.GapMS / 60_000
	gap := fillText(t.get("ev.gap"), "h", strconv.FormatInt(minutes/60, 10), "m", strconv.FormatInt(minutes%60, 10))
	return fillText(t.get("ev.qualified_time_log"), "latest", q.Latest, "tree_size", ts, "gap", gap)
}

// evReasonText is the text of the reason of a condition that is not met.
func evReasonText(c *EvidenceCondition, t i18nTable) string {
	if c == nil || c.Reason == nil {
		return ""
	}
	return t.get("ev.reason." + *c.Reason)
}

// evAnchorsText is <Anker> of 10.10.3 for a condition that is met: for (3)
// the keys of the credited receipts as anchors.vendor_keys names them, for
// the other conditions the anchors they name: the fingerprints of the
// crediting roots for time stamps (1), (4), (7), the file of qualified
// roots (4), (7), the sources of the expected roots (2), the log_id (5),
// (7) and as_of of the anchor history with the statements keys of its pages
// (6). Several anchors, and several sources in anchor_expected_sources, are
// joined with ", " (comma and space).
func evAnchorsText(ev *EvidenceLevelStat, code string, t i18nTable) string {
	var parts []string
	keyText := func(k EvidenceKeyRef, pinned, list string) string {
		if k.Via == keyViaPinned || k.ListVersion == nil || k.RootID == nil || k.RootFrom == nil {
			return fillText(t.get(pinned), "key_id", k.KeyID)
		}
		root := fillText(t.get("ev.root_auditor"), "root_id", *k.RootID)
		if *k.RootFrom == rootFromBuiltin {
			root = fillText(t.get("ev.root_builtin"), "root_id", *k.RootID)
		}
		return fillText(t.get(list), "key_id", k.KeyID, "version", strconv.FormatInt(*k.ListVersion, 10), "root", root)
	}
	tx := ev.text
	switch code {
	case CondReceiptKeyConfirmed:
		for _, k := range tx.receiptKeys {
			parts = append(parts, keyText(k, "ev.anchor_pinned", "ev.anchor_list"))
		}
	case CondExpectedRootFound:
		var src []string
		for _, s := range tx.sources {
			src = append(src, t.get("ev.source_"+s))
		}
		parts = append(parts, fillText(t.get("ev.anchor_expected_sources"), "sources", strings.Join(src, ", ")))
	case CondReceiptsLogged:
		parts = append(parts, fillText(t.get("ev.anchor_log"), "log_id", tx.logID))
	case CondCompleteness:
		parts = append(parts, fillText(t.get("ev.anchor_history"), "as_of", tx.asOf))
		for _, k := range tx.historyKeys {
			parts = append(parts, keyText(k, "ev.anchor_statement_pinned", "ev.anchor_statement_role_list"))
		}
	}
	for _, sha := range tx.roots[code] {
		parts = append(parts, fillText(t.get("ev.anchor_tsa_root"), "cert_sha256", sha))
	}
	if (code == CondTimeWitnessQualified || code == CondLogDayQualified) && tx.qualifiedFile != nil {
		parts = append(parts, fillText(t.get("ev.anchor_qualified_file"), "stand", tx.qualifiedFile.Stand, "quelle", tx.qualifiedFile.Quelle))
	}
	if code == CondLogDayQualified {
		parts = append(parts, fillText(t.get("ev.anchor_log"), "log_id", tx.logID))
	}
	return strings.Join(parts, ", ")
}
