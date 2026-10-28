package vfy

// The affiliation of the customer with the vendor over the period of the
// package (format spec 8.8.6, step H12; heartbeat spec 9.10) and the report
// object affiliation (10.10.2).
//
// The statement is the vendor's, signed under a statements key on a page of
// the anchor history. The verifier checks signature, form, binding to chain
// and device, freshness and the comparison with other pages supplied, not
// whether the statement is correct. It never derives an affiliation from the
// package (GENESIS.customer_id, GENESIS.edition, the manifest, the vendor log
// or the evidence level), and the affiliation changes no exit code, no
// finding and not the number of the evidence level. Without a used page the
// report says "not checked" or "not determined", never "not affiliated".

import (
	"sort"
	"strings"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
)

// Statuses and key sources of registry verifier.affiliation.
const (
	AffAffiliated    = "affiliated"
	AffNotAffiliated = "not_affiliated"
	AffNotDetermined = "not_determined"
	AffNotChecked    = "not_checked"

	AffSourcePinned  = "pinned"
	AffSourceAuditor = "role_list_auditor_root"
	AffSourceBuiltin = "role_list_builtin_root"
)

// affKnownRangeNullText is the entry of registry verifier.affiliation.
// reason_texts for the reason known_range_too_short when known_since is
// null (format spec 10.10.3).
const affKnownRangeNullText = "known_range_too_short_null"

// affReasonFromPage is registry verifier.affiliation.not_determined_from_
// page_reason, in the fixed order of format spec 8.8.6 number 2.
var affReasonFromPage = []struct{ page, reason string }{
	{hrOwnerDiffers, "history_owner_differs"},
	{hrKeyNotEstablished, "history_key_not_established"},
	{hrKeyOtherRole, "history_key_not_established"},
	{hrKeyNotValid, "history_key_not_valid"},
	{hrSigningTime, "history_signing_time_not_proven"},
	{hrNotV2, "history_not_v2"},
	{hrSignature, "history_defective"},
	{hrPageRules, "history_contradictory"},
	{hrOtherChain, "history_other_chain"},
}

// AffiliationStat is the report object affiliation (format spec 10.10.2).
type AffiliationStat struct {
	Status                 string              `json:"status"`
	Reason                 *string             `json:"reason"`
	Bases                  []string            `json:"bases"`
	VendorItself           bool                `json:"vendor_itself"`
	Span                   *AffSpan            `json:"span"`
	AsOf                   *string             `json:"as_of"`
	KnownSince             *string             `json:"known_since"`
	StatedBy               *AffStatedBy        `json:"stated_by"`
	Periods                []AffPeriod         `json:"periods"`
	ReceiptsTotal          *int                `json:"receipts_total"`
	ReceiptsInPeriods      *int                `json:"receipts_in_periods"`
	ReceiptsAfterStatement *int                `json:"receipts_after_statement"`
	Contradictory          bool                `json:"contradictory"`
	Linked                 []AffLinked         `json:"linked"`
	chainID                string              // for the text line
	receiptHolds           bool                // the package carries a receipt whose signature holds (10.10.3)
	statedList             *HistoryKeyListStat // the role list of stated_by, nil for a pin
}

// AffSpan is the period of the package (number 5).
type AffSpan struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// AffStatedBy is the key of H* with its source.
type AffStatedBy struct {
	ServerKeyID string `json:"server_key_id"`
	KeySource   string `json:"key_source"`
}

// AffPeriod is one period after number 4 with overlaps_package (number 8).
type AffPeriod struct {
	Bases           []string `json:"bases"`
	From            string   `json:"from"`
	Until           *string  `json:"until"`
	RecordedTS      string   `json:"recorded_ts"`
	Merged          bool     `json:"merged"`
	OverlapsPackage bool     `json:"overlaps_package"`
}

// AffLinked is the result for a linked chain (number 11).
type AffLinked struct {
	ChainID  string      `json:"chain_id"`
	Relation string      `json:"relation"`
	Status   string      `json:"status"`
	Periods  []AffPeriod `json:"periods"`
}

// affEval is numbers 3 to 10 for the used pages of one chain.
type affEval struct {
	status, reason   string
	bases            []string
	hstar            *ahPage
	spanFrom, spanTo int64
	periods          []AffPeriod
	inPeriods, after int
}

// evalAffiliation applies numbers 3 to 10 of format spec 8.8.6 to the used
// pages of one chain; receipts are the server_ts of the established receipts
// in whole milliseconds, coverComplete the coverage of H4 for these pages.
func (h *ahRun) evalAffiliation(pages []*ahPage, receipts []int64, coverComplete bool) affEval {
	ev := affEval{bases: []string{}, periods: []AffPeriod{}}
	// 3. H*: the largest (server_ts, bytes of statement_jcs).
	for _, p := range pages {
		if ev.hstar == nil || p.c.serverMS > ev.hstar.c.serverMS || p.c.serverMS == ev.hstar.c.serverMS && p.jcs > ev.hstar.jcs {
			ev.hstar = p
		}
	}
	hs := ev.hstar
	// 5. The period of the package, only from times the vendor signed.
	ev.spanTo = hs.c.serverMS
	if h.hasR {
		ev.spanTo = h.rMS
	}
	first := true
	for _, s := range receipts {
		if first || s < ev.spanFrom {
			ev.spanFrom, first = s, false
		}
	}
	for _, p := range pages {
		for _, x := range p.c.roots {
			if first || x.ms < ev.spanFrom {
				ev.spanFrom, first = x.ms, false
			}
		}
	}
	if first {
		ev.spanFrom = ev.spanTo
	}
	// format spec 8.8.6 number 11: span_from of a linked chain may lie after
	// span_to (a successor chain whose roots all lie after R); number 6 then
	// applies unchanged by its formula.
	//
	// 4. The periods: an open period ends at the server_ts of its page,
	// except on H*, where it continues.
	type period struct {
		ahPeriod
		end    int64
		endTS  string
		noEnd  bool
		overlp bool
	}
	var ps []period
	for _, p := range pages {
		for _, x := range p.c.periods {
			q := period{ahPeriod: x}
			switch {
			case x.until != "":
				q.end, q.endTS = x.untilMS, x.until
			case p == hs:
				q.noEnd = true
			default:
				q.end, q.endTS = p.c.serverMS, p.c.serverTS
			}
			// 6. A period overlaps the period of the package.
			q.overlp = x.fromMS <= ev.spanTo && (q.noEnd || q.end > ev.spanFrom)
			ps = append(ps, q)
		}
	}
	// 6. affiliated: the union of the bases of the overlapping periods.
	bases := map[string]bool{}
	for _, q := range ps {
		if q.overlp {
			for _, b := range q.bases {
				bases[b] = true
			}
		}
	}
	for _, b := range affiliationBases {
		if bases[b] {
			ev.bases = append(ev.bases, b)
		}
	}
	switch {
	case len(ev.bases) > 0:
		ev.status = AffAffiliated
	default:
		// 7. not_affiliated needs (a), (b) and (c).
		a := h.hasR && hs.fresh
		if !h.hasR {
			a = true
			for _, s := range receipts {
				if hs.c.serverMS < s {
					a = false
				}
			}
		}
		b := hs.c.knownSince != "" && hs.c.knownMS <= ev.spanFrom
		switch {
		case !a:
			ev.status, ev.reason = AffNotDetermined, "statement_does_not_cover_package"
		case !b:
			ev.status, ev.reason = AffNotDetermined, "known_range_too_short"
		case !coverComplete:
			ev.status, ev.reason = AffNotDetermined, "history_pages_missing"
		default:
			ev.status = AffNotAffiliated
		}
	}
	// 10. Receipts in a period and after the statement.
	for _, s := range receipts {
		for _, q := range ps {
			if q.fromMS <= s && (q.noEnd || s < q.end) {
				ev.inPeriods++
				break
			}
		}
		if s > hs.c.serverMS {
			ev.after++
		}
	}
	// 8. Every period with overlaps_package; equal objects once, ordered as
	// 10.10.2 says.
	seen := map[string]bool{}
	for _, q := range ps {
		ap := AffPeriod{Bases: append([]string{}, q.bases...), From: q.from, RecordedTS: q.recorded, Merged: q.merged, OverlapsPackage: q.overlp}
		if !q.noEnd {
			u := q.endTS
			ap.Until = &u
		}
		k := periodKey(ap)
		if !seen[k] {
			seen[k] = true
			ev.periods = append(ev.periods, ap)
		}
	}
	sort.SliceStable(ev.periods, func(i, j int) bool { return periodLess(ev.periods[i], ev.periods[j]) })
	return ev
}

// periodKey identifies a period object by its JCS form (all members have
// fixed types, so equal members mean equal bytes).
func periodKey(p AffPeriod) string {
	u := "null"
	if p.Until != nil {
		u = *p.Until
	}
	return strings.Join([]string{strings.Join(p.Bases, ","), p.From, u, p.RecordedTS, boolStr(p.Merged), boolStr(p.OverlapsPackage)}, "|")
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// periodLess is the order of 10.10.2: from, then until (null last), then
// the bytes of JCS(bases), then recorded_ts, then merged false before true,
// then overlaps_package false before true. The instants have the form
// YYYY-MM-DDThh:mm:ss.sssZ, so their bytes order them in time.
func periodLess(a, b AffPeriod) bool {
	if a.From != b.From {
		return msOf(a.From) < msOf(b.From)
	}
	switch {
	case a.Until == nil && b.Until != nil:
		return false
	case a.Until != nil && b.Until == nil:
		return true
	case a.Until != nil && *a.Until != *b.Until:
		return msOf(*a.Until) < msOf(*b.Until)
	}
	ja, _ := jcsStrings(a.Bases)
	jb, _ := jcsStrings(b.Bases)
	if ja != jb {
		return ja < jb
	}
	if a.RecordedTS != b.RecordedTS {
		return msOf(a.RecordedTS) < msOf(b.RecordedTS)
	}
	if a.Merged != b.Merged {
		return !a.Merged
	}
	return !a.OverlapsPackage && b.OverlapsPackage
}

func jcsStrings(xs []string) (string, error) {
	var arr []any
	for _, x := range xs {
		arr = append(arr, x)
	}
	b, err := jcs.CanonGo(arr)
	return string(b), err
}

// affiliationStat writes the report object affiliation after the exit code
// (format spec 8.8.6, 10.5 stage 5, step 15).
func (r *run) affiliationStat() *AffiliationStat {
	h := r.ah
	if h == nil {
		return nil
	}
	st := &AffiliationStat{Status: AffNotChecked, Bases: []string{}, Periods: []AffPeriod{}, Linked: []AffLinked{}, chainID: r.man.chainID}
	for _, ri := range r.receiptInfos {
		if ri.sigOK {
			st.receiptHolds = true
		}
	}
	// 1. Without anchor history: not_checked.
	if !h.supplied {
		return st
	}
	// 11. Every linked chain with its own used pages and its own
	// recordings; never part of the status of the package.
	//
	// format spec 8.8.6 number 11: no established receipts for a linked
	// chain (the package carries none of its receipts), the coverage of H4
	// over its own used pages (the fresh ones with R).
	for _, lc := range sortedChains(h.linked) {
		pages := h.linked[lc]
		var cov []*ahPage
		for _, p := range pages {
			if !h.hasR || p.fresh {
				cov = append(cov, p)
			}
		}
		cs, _ := coverage(cov)
		ev := h.evalAffiliation(pages, nil, cs == "complete")
		st.Linked = append(st.Linked, AffLinked{ChainID: lc, Relation: h.linkRel[lc], Status: ev.status, Periods: ev.periods})
	}
	// 2. Without a used page of the package: not_determined with the reason
	// a supplied page reached, in the fixed order.
	if len(h.pkgUsed) == 0 {
		st.Status = AffNotDetermined
		reached := map[string]bool{}
		for _, p := range h.pages {
			if p.reason != "" {
				reached[p.reason] = true
			}
		}
		why := "history_no_package_page"
		for _, x := range affReasonFromPage {
			if reached[x.page] {
				why = x.reason
				break
			}
		}
		st.Reason = &why
		return st
	}
	var receipts []int64
	for _, ri := range r.receiptInfos {
		if !ri.sigOK || ri.invalid || !ri.established {
			continue
		}
		if t, err := parseRFC3339(ri.serverTS); err == nil {
			receipts = append(receipts, unixMS(t))
		}
	}
	ev := h.evalAffiliation(h.pkgUsed, receipts, h.coverStatus == "complete")
	st.Status = ev.status
	if ev.reason != "" {
		why := ev.reason
		st.Reason = &why
	}
	st.Bases = ev.bases
	st.VendorItself = st.Status == AffAffiliated && indexOf(ev.bases, "vendor") >= 0
	st.Span = &AffSpan{From: msString(ev.spanFrom), To: msString(ev.spanTo)}
	hs := ev.hstar
	asOf := hs.c.serverTS
	st.AsOf = &asOf
	if hs.c.knownSince != "" {
		ks := hs.c.knownSince
		st.KnownSince = &ks
	}
	src := AffSourcePinned
	if !hs.chosen.key.Pinned {
		st.statedList = r.historyKeyList()
		src = AffSourceAuditor
		if st.statedList != nil && st.statedList.RootSource == RootSourceBuiltin {
			src = AffSourceBuiltin
		}
	}
	st.StatedBy = &AffStatedBy{ServerKeyID: hs.chosen.keyID, KeySource: src}
	st.Periods = ev.periods
	total, in, after := len(receipts), ev.inPeriods, ev.after
	st.ReceiptsTotal, st.ReceiptsInPeriods, st.ReceiptsAfterStatement = &total, &in, &after
	st.Contradictory = h.affContra
	return st
}
