package vfy

// Four places where the two verifiers judged the same package differently
// (found on 29.09.2026). Each test fixes the reading the specification now
// states; a differential run feeds the same inputs through both verifiers
// and compares exit code and finding classes.
//
//  1. Segment files are split on "\n" only (spec 10.1). U+2028, U+2029 and
//     U+0085 stand raw inside JSON strings (RFC 8785 escapes only below
//     U+0020, '"' and '\'); verifier2 split on them (str.splitlines) and
//     called an honest chain a format error. This verifier always split on
//     "\n" — the tests pin that reading and the rest of the line rule.
//  2. Timestamps follow the grammar of spec 2/10.7. time.Parse took a comma
//     as the fraction separator and a one-digit hour; the grammar does not.
//     This one is a fix HERE: red against the previous parseRFC3339.
//  3. A duplicate member name in an entry or in manifest.json is a
//     FORMAT_ERROR (spec 2); verifier2 read it "last wins".
//  4. GENESIS occurs exactly once, at seq 1 (spec 3); anything else is a
//     FORMAT_ERROR that does not stop the run, and the chain end and the
//     active holds are then not judged. verifier2 ignored a later GENESIS.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
)

// rewriteSegment replaces the package's only segment by edit(segment) and
// repairs its SHA-256 in the manifest, so a verdict is about the bytes and
// never about a stale checksum.
func rewriteSegment(t *testing.T, pkg string, edit func([]byte) []byte) {
	t.Helper()
	sp := filepath.Join(pkg, "segments", "000001.jsonl")
	b, err := os.ReadFile(sp)
	if err != nil {
		t.Fatal(err)
	}
	b = edit(b)
	if err := os.WriteFile(sp, b, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	mp := filepath.Join(pkg, "manifest.json")
	mb, err := os.ReadFile(mp)
	if err != nil {
		t.Fatal(err)
	}
	m, err := jcs.Parse(mb)
	if err != nil {
		t.Fatal(err)
	}
	setMember(m.Get("segments").Arr[0], "sha256", jStr(hex.EncodeToString(sum[:])))
	if err := os.WriteFile(mp, jcs.Canon(m), 0o644); err != nil {
		t.Fatal(err)
	}
}

// verifyPkg verifies a written package with the generator's clock and anchor.
func verifyPkg(g *gen, pkg string) Result {
	return Verify(pkg, genAnker(Options{Now: g.now.Add(time.Hour)}))
}

// --- 1. JSON Lines: "\n" and nothing else (spec 10.1) ------------------------

// A raw U+2028, U+2029 or U+0085 inside a payload string is part of the
// string, not a line end: the honest chain verifies without a finding. The
// segment must really carry the character raw — the canonical form does not
// escape it, which is exactly why a reader that splits on it breaks.
func TestRawLineSeparatorsInsideStringsAreNoLineEnd(t *testing.T) {
	for _, c := range []struct{ name, ch string }{
		{"U+2028", " "}, {"U+2029", " "}, {"U+0085", "\u0085"},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := holdBase(t)
			g.legalHold("set", "H-1", scopeJulyLo, scopeJulyHi, "Az. 5 O"+c.ch+"99/26")
			g.seal("shutdown")
			pkg := g.writePkg()
			seg, err := os.ReadFile(filepath.Join(pkg, "segments", "000001.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(seg, []byte(c.ch)) {
				t.Fatalf("the segment does not carry %s raw; the test would prove nothing", c.name)
			}
			res := verifyPkg(g, pkg)
			wantClasses(t, res, 0)
			if len(res.Stats.LegalHolds) != 1 || res.Stats.LegalHolds[0].Reference != "Az. 5 O"+c.ch+"99/26" {
				t.Errorf("reference not read in one piece: %+v", res.Stats.LegalHolds)
			}
		})
	}
}

// The rest of the line rule of spec 10.1: "\n" at the end of the file (one or
// several) is passed over; a "\r" before the "\n" is whitespace of the JSON
// text; every other line — an empty one, one of blanks only — must be an
// entry; neither a lone "\r" nor U+2028 between two entries separates them.
func TestSegmentLineRule(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func([]byte) []byte
		exit int
	}{
		{"one line end at the end (as written)", func(b []byte) []byte { return b }, 0},
		{"several line ends at the end", func(b []byte) []byte { return append(b, "\n\n\n"...) }, 0},
		{"CRLF line ends", func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n")) }, 0},
		{"no line end at the end", func(b []byte) []byte { return bytes.TrimRight(b, "\n") }, 0},
		{"empty line between two entries", func(b []byte) []byte { return bytes.Replace(b, []byte("\n"), []byte("\n\n"), 1) }, 3},
		{"line of blanks between two entries", func(b []byte) []byte { return bytes.Replace(b, []byte("\n"), []byte("\n \n"), 1) }, 3},
		{"empty line at the start", func(b []byte) []byte { return append([]byte("\n"), b...) }, 3},
		{"line of blanks at the end", func(b []byte) []byte { return append(b, " \n"...) }, 3},
		{"lone CR between two entries", func(b []byte) []byte { return bytes.Replace(b, []byte("\n"), []byte("\r"), 1) }, 3},
		{"U+2028 between two entries", func(b []byte) []byte { return bytes.Replace(b, []byte("\n"), []byte(" "), 1) }, 3},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := validSealedChain(t)
			pkg := g.writePkg()
			rewriteSegment(t, pkg, c.edit)
			if c.exit == 0 {
				wantClasses(t, verifyPkg(g, pkg), 0)
			} else {
				wantClasses(t, verifyPkg(g, pkg), 3, ClsFormatError)
			}
		})
	}
}

// --- 2. timestamp grammar (spec 2, 10.7) -------------------------------------

// parseRFC3339 reads exactly the grammar: ASCII digits, two-digit fields, an
// optional period with a fraction of any length, then Z; year 0001-9999; the
// date must exist. Red against the previous version, which took the comma and
// the one-digit hour through time.Parse's general layout parser.
func TestParseRFC3339Grammar(t *testing.T) {
	for _, s := range []string{
		"2026-01-01T00:00:00Z", "2026-01-01T00:00:00.5Z", "2026-01-01T00:00:00.000Z",
		"2026-01-01T00:00:00.1234567891Z", "0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z",
		"2024-02-29T23:59:59.999999999Z",
	} {
		if _, err := parseRFC3339(s); err != nil {
			t.Errorf("%q: %v, want accepted", s, err)
		}
	}
	for _, s := range []string{
		"2026-01-01T00:00:00,5Z",    // comma as fraction separator
		"2026-01-01T1:00:00Z",       // one-digit hour
		"2026-01-01T0:00:00Z",       // one-digit hour
		"2026-01-01T00:00:00.Z",     // period without a digit
		"2026-01-01T00:00:00+00:00", // offset instead of Z
		"2026-01-01t00:00:00z",      // lower case
		"2026-01-01 00:00:00Z",      // blank instead of T
		"2026-01-01T00:00:00Z\n",    // trailing line end
		" 2026-01-01T00:00:00Z",     // leading blank
		"٢٠٢٦-01-01T00:00:00Z",      // Arabic-Indic digits
		"2026-01-01T00:00:0٣Z",      // one Arabic-Indic digit
		"0000-01-01T00:00:00Z",      // year 0000
		"2026-02-30T00:00:00Z",      // no such date
		"2026-01-01T24:00:00Z",      // hour 24
		"2026-01-01T23:59:60Z",      // second 60
		"",
	} {
		if tm, err := parseRFC3339(s); err == nil {
			t.Errorf("%q accepted as %s, want rejected", s, tm.Format(time.RFC3339Nano))
		}
	}
}

// Every rfc3339 field of the package is read by that grammar: the comma
// fraction and the one-digit hour are a FORMAT_ERROR in ts_captured, in the
// LEGAL_HOLD bounds and in the manifest — also where time.Parse would have
// made the verdict (the reviewer's case: a hold .400..600 s around a capture
// written as ",5" gave HOLD_VIOLATION, exit 1).
func TestTimestampGrammarInThePackage(t *testing.T) {
	const comma, oneDigitHour = "2026-07-20T12:00:00,5Z", "2026-07-20T1:00:00Z"
	cases := []struct {
		name  string
		build func(g *gen)
	}{
		{"ts_captured comma fraction", func(g *gen) { g.aiCallCaptured(comma) }},
		{"ts_captured one-digit hour", func(g *gen) { g.aiCallCaptured(oneDigitHour) }},
		{"scope_from comma fraction", func(g *gen) { g.legalHold("set", "H-1", "2026-07-01T00:00:00,5Z", scopeJulyHi, "x") }},
		{"scope_from one-digit hour", func(g *gen) { g.legalHold("set", "H-1", "2026-07-01T1:00:00Z", scopeJulyHi, "x") }},
		{"scope_to comma fraction", func(g *gen) { g.legalHold("set", "H-1", scopeJulyLo, "2026-07-31T23:59:59,5Z", "x") }},
		{"scope_to one-digit hour", func(g *gen) { g.legalHold("set", "H-1", scopeJulyLo, "2026-07-31T1:00:00Z", "x") }},
		{"coverage decided by a comma capture", func(g *gen) {
			call := g.aiCallCaptured(comma)
			g.legalHold("set", "H-1", "2026-07-20T12:00:00.400Z", "2026-07-20T12:00:00.600Z", "x")
			g.contentDeleted(call)
		}},
		{"GAP started_ts one-digit hour", func(g *gen) {
			g.add(time.Minute, "GAP", "system", map[string]any{
				"reason": "manual", "started_ts": "2026-08-01T8:00:00Z", "ended_ts": g.now.Format(time.RFC3339),
				"lost_count": int64(0), "detail": nil,
			})
			g.checkpoint(time.Second)
		}},
		{"manifest created_ts comma fraction", func(g *gen) { g.extraMan = map[string]any{"created_ts": "2026-08-01T08:10:00,5Z"} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := holdBase(t)
			c.build(g)
			wantClasses(t, verifySealed(g), 3, ClsFormatError)
		})
	}
	// Control: the same scenarios written in the grammar verify as before.
	g := holdBase(t)
	call := g.aiCallCaptured("2026-07-20T12:00:00.5Z")
	g.legalHold("set", "H-1", "2026-07-20T12:00:00.400Z", "2026-07-20T12:00:00.600Z", "x")
	g.contentDeleted(call)
	wantClasses(t, verifySealed(g), 1, ClsContentDeleted, ClsHoldViolation)
}

// --- 3. duplicate member names (spec 2) --------------------------------------

// A LEGAL_HOLD whose payload names "action" twice — "release", then "set" —
// with entry_hash computed over the last-wins reading: a first-wins reader
// would see a release. Neither reading is taken: FORMAT_ERROR, exit 3. The
// same for a duplicate member in manifest.json.
func TestDuplicateMemberIsFormatError(t *testing.T) {
	t.Run("segment line", func(t *testing.T) {
		g := holdBase(t)
		call := g.aiCallCaptured(tsCall)
		g.legalHold("set", "H-1", scopeJulyLo, scopeJulyHi, "x")
		g.contentDeleted(call)
		g.seal("shutdown")
		pkg := g.writePkg()
		wantClasses(t, verifyPkg(g, pkg), 1, ClsContentDeleted, ClsHoldViolation) // control, before the edit
		rewriteSegment(t, pkg, func(b []byte) []byte {
			const set = `"payload":{"action":"set"`
			if bytes.Count(b, []byte(set)) != 1 {
				t.Fatalf("want exactly one LEGAL_HOLD set line, segment:\n%s", b)
			}
			return bytes.Replace(b, []byte(set), []byte(`"payload":{"action":"release","action":"set"`), 1)
		})
		res := verifyPkg(g, pkg)
		wantClasses(t, res, 3, ClsFormatError)
		if !strings.Contains(res.Findings[0].Detail, `duplicate object key "action"`) {
			t.Errorf("detail does not name the duplicate: %+v", res.Findings)
		}
	})
	t.Run("manifest.json", func(t *testing.T) {
		g := validSealedChain(t)
		pkg := g.writePkg()
		mp := filepath.Join(pkg, "manifest.json")
		mb, err := os.ReadFile(mp)
		if err != nil {
			t.Fatal(err)
		}
		// The first chain_id is a stranger, the last the real one: last-wins
		// reads a consistent package.
		mb = bytes.Replace(mb, []byte(`{"chain_id":`), []byte(`{"chain_id":"00000000-0000-4000-8000-000000000000","chain_id":`), 1)
		if err := os.WriteFile(mp, mb, 0o644); err != nil {
			t.Fatal(err)
		}
		res := verifyPkg(g, pkg)
		wantClasses(t, res, 3, ClsFormatError)
		if !strings.Contains(res.Findings[0].Detail, `duplicate object key "chain_id"`) {
			t.Errorf("detail does not name the duplicate: %+v", res.Findings)
		}
	})
}

// --- 4. GENESIS exactly once, at seq 1 (spec 3) ------------------------------

// A second GENESIS (with its immediate checkpoint) is a FORMAT_ERROR at its
// seq; the run goes on and reports what else it finds — here CONTENT_DELETED
// and HOLD_VIOLATION — but the chain end and the active holds are not judged:
// no UNSEALED_END although the chain is not sealed, no chain_end, no
// last_countersigned, no legal_holds.
func TestGenesisOnlyAtSeq1(t *testing.T) {
	t.Run("second GENESIS in a sealed chain", func(t *testing.T) {
		g := validChain(t)
		g.genesis()
		second := g.seq
		g.checkpoint(time.Second)
		res := verifySealed(g)
		wantClasses(t, res, 3, ClsFormatError)
		fs := findingsOf(res, ClsFormatError)
		if len(fs) != 1 || fs[0].Seq != second || fs[0].Detail != "GENESIS entry at seq > 1" {
			t.Errorf("want one FORMAT_ERROR at seq %d naming the GENESIS: %+v", second, fs)
		}
		if res.Stats.ChainEnd != nil || res.Stats.LastCountersigned != nil || res.Stats.LegalHolds != nil {
			t.Errorf("judged on a format error: %+v", res.Stats)
		}
	})
	t.Run("second GENESIS after a hold violation, unsealed", func(t *testing.T) {
		g := holdBase(t)
		call := g.aiCallCaptured(tsCall)
		g.legalHold("set", "H-1", scopeJulyLo, scopeJulyHi, "x")
		g.contentDeleted(call)
		g.genesis()
		g.checkpoint(time.Second)
		res := verifyGen(g, Options{})
		wantClasses(t, res, 3, ClsContentDeleted, ClsFormatError, ClsHoldViolation)
		if res.Stats.ChainEnd != nil || res.Stats.LastCountersigned != nil || res.Stats.LegalHolds != nil {
			t.Errorf("judged on a format error: %+v", res.Stats)
		}
	})
}
