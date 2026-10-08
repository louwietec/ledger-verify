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
	if res.Stats.Now == "" {
		// The check time was requested from the package and could not be
		// determined (spec 10.8): the run stopped with FORMAT_ERROR.
		line("%-28s %s (%s)", t.get("report.now")+":", t.get("report.now_not_determined"), t.get("report.now_source."+res.Stats.NowSource))
	} else {
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
			v += " — " + t.get("report.chain_end_critical")
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
		if c.Status == "established" && c.UpToTreeSize != nil {
			v = fmt.Sprintf(t.get("report.completeness_established"), *c.UpToTreeSize)
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
			v += " — " + t.get("report.residual_window_beyond")
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
			loc = fmt.Sprintf(" %s=%d", t.get("report.seq"), f.Seq)
		}
		line("  [%s]%s — %s", f.Class, loc, t.get("class."+f.Class))
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
		if c.Status == "established" && c.UpToTreeSize != nil {
			line("  - %s", fmt.Sprintf(t.get("note.completeness_established"), *c.UpToTreeSize, *c.UpToTreeSize))
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
	if res.Stats.GenesisLicenseNotCommitment {
		line("  - %s", t.get("note.genesis_license"))
	}
	line("  - %s", t.get("note.purpose"))
	return b.String()
}
