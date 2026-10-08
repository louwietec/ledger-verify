package vfy

// Tests for section 10.6 (forward compatibility, spec change S1a):
//
//   R1  spec_version "MAJOR.MINOR": a newer MINOR is SPEC_NEWER (exit 1),
//       reported once per package, all known checks still run; a different
//       MAJOR is FORMAT_ERROR (exit 3).
//   R2  an unknown event_type is UNKNOWN_ENTRY_TYPE (exit 1), once per type
//       name with the seq of its first occurrence; the entry stays in the
//       seq/hash-chain/Merkle checks, its payload is only required to be an
//       object, and it is NOT treated as critical (no MISSING_CHECKPOINT).
//   R3  unknown ENVELOPE fields stay FORMAT_ERROR; payload fields of known
//       types stay strict.
//
// Tests 3 and 4 (major mismatch, unknown envelope field) guard behaviour the
// verifier already had before S1a; they are green without the change and
// exist so that the opening of spec_version/event_type does not leak into
// the envelope contract. Tests 1, 2, 5 (and the silence/dedup tests) are red
// without the change: the old verifier rejected the package as FORMAT_ERROR.
//
// From spec 1.6 an unsealed chain end is its own finding (UNSEALED_END, exit
// 4, spec 8.6). Tests whose point is "exit 1, not worse" therefore end their
// chain with g.seal(...); the others list UNSEALED_END alongside.

import (
	"strings"
	"testing"
	"time"

	"github.com/louwietec/ledger-verify/verifier/internal/jcs"
)

// futureNote appends an entry of a type this verifier does not know
// (not critical, payload = one object), regularly chained.
func (g *gen) futureNote(d time.Duration) string {
	return g.add(d, "FUTURE_NOTE", "system", map[string]any{"note": "reserved for spec 1.1"})
}

// findingsOf returns the findings of one class.
func findingsOf(res Result, cls string) []Finding {
	var out []Finding
	for _, f := range res.Findings {
		if f.Class == cls {
			out = append(out, f)
		}
	}
	return out
}

// --- (1) unknown type: finding, no FORMAT_ERROR, chain still checked -------

func TestUnknownEntryTypeIsFindingNotFormatError(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.futureNote(time.Minute) // seq 4
	g.tick(time.Minute)       // seq 5
	g.checkpoint(time.Second) // checkpoint over 1..5 — includes the unknown entry
	g.receiptForLast(time.Second)
	g.seal("shutdown") // seq 8, 9: sealed end (spec 8.6)
	res := verifyGen(g, Options{})
	// exactly one finding, exit 1, and the chain (incl. Merkle over the
	// unknown entry) is otherwise sound
	wantClasses(t, res, 1, ClsUnknownEntryType)
	if !res.Valid {
		t.Error("chain with an unknown entry type must stay valid (exit 1)")
	}
	fs := findingsOf(res, ClsUnknownEntryType)
	if len(fs) != 1 || fs[0].Seq != 4 || !strings.Contains(fs[0].Detail, `"FUTURE_NOTE"`) {
		t.Errorf("want one UNKNOWN_ENTRY_TYPE at seq 4 naming FUTURE_NOTE, got %+v", fs)
	}
	if res.Stats.Entries != 9 {
		t.Errorf("unknown entry must be counted as an entry: entries=%d, want 9", res.Stats.Entries)
	}
}

// A hash error in a LATER entry is still found: the unknown type does not
// stop the chain checks.
func TestUnknownEntryTypeChainStillChecked(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.futureNote(time.Minute) // seq 4, unknown
	g.tick(time.Minute)       // seq 5
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	// rewrite the TICK (index 4 = seq 5) after the unknown entry
	g.editLine(4, func(v *jcs.Value) {
		setMember(v.Get("payload"), "disk_pct", jInt(99))
	})
	res := verifyGen(g, Options{})
	wantClasses(t, res, 2, ClsUnknownEntryType, ClsHashMismatch, ClsUnsealedEnd) // unsealed end alongside, exit 2 wins
	if fs := findingsOf(res, ClsHashMismatch); len(fs) == 0 || fs[0].Seq != 5 {
		t.Errorf("HASH_MISMATCH at seq 5 expected, got %+v", fs)
	}
}

// The unknown entry itself is part of the hash chain: rewriting IT is found.
func TestUnknownEntryTypeItselfInHashChain(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.futureNote(time.Minute) // seq 4
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.editLine(3, func(v *jcs.Value) {
		setMember(v.Get("payload"), "note", jStr("rewritten"))
	})
	res := verifyGen(g, Options{})
	wantClasses(t, res, 2, ClsUnknownEntryType, ClsHashMismatch, ClsUnsealedEnd) // unsealed end alongside, exit 2 wins
	if fs := findingsOf(res, ClsHashMismatch); len(fs) == 0 || fs[0].Seq != 4 {
		t.Errorf("HASH_MISMATCH at seq 4 expected, got %+v", fs)
	}
}

// Once per type NAME with the seq of the first occurrence; a second unknown
// name yields its own finding.
func TestUnknownEntryTypeOncePerName(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.futureNote(time.Minute)                                                   // seq 4 FUTURE_NOTE
	g.futureNote(time.Minute)                                                   // seq 5 FUTURE_NOTE again
	g.add(time.Minute, "FUTURE_OTHER", "system", map[string]any{"x": int64(1)}) // seq 6
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.seal("shutdown") // sealed end (spec 8.6)
	res := verifyGen(g, Options{})
	wantClasses(t, res, 1, ClsUnknownEntryType)
	fs := findingsOf(res, ClsUnknownEntryType)
	if len(fs) != 2 {
		t.Fatalf("want exactly 2 UNKNOWN_ENTRY_TYPE findings (one per name), got %+v", fs)
	}
	if fs[0].Seq != 4 || !strings.Contains(fs[0].Detail, `"FUTURE_NOTE"`) {
		t.Errorf("first finding must be FUTURE_NOTE at seq 4, got %+v", fs[0])
	}
	if fs[1].Seq != 6 || !strings.Contains(fs[1].Detail, `"FUTURE_OTHER"`) {
		t.Errorf("second finding must be FUTURE_OTHER at seq 6, got %+v", fs[1])
	}
}

// payload of an unknown type must still be an object (envelope rule).
func TestUnknownEntryTypePayloadMustBeObject(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.futureNote(time.Minute) // seq 4
	// a nil Go map would canonicalise to {} (still an object), so the
	// non-object payload is set post-hoc; the schema check comes first
	g.editLine(3, func(v *jcs.Value) { setMember(v, "payload", jStr("not an object")) })
	res := verifyGen(g, Options{})
	// 10.6 R3, last sentence: the finding of rule 2 is reported alongside the
	// FORMAT_ERROR of the same entry (the Python verifier does the same; the
	// equivalence job compares class SETS, so the two must not differ here).
	wantClasses(t, res, 3, ClsFormatError, ClsUnknownEntryType)
}

// --- (2) spec_version 1.1 -> SPEC_NEWER exactly once -----------------------

func TestSpecNewerMinorOnce(t *testing.T) {
	g := newGen(t)
	g.specVersion = newerMinorVersion() // every entry AND the manifest
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.tick(5 * time.Minute)
	g.tick(5 * time.Minute)
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.seal("shutdown") // sealed end (spec 8.6): SPEC_NEWER alone stays exit 1
	res := verifyGen(g, Options{})
	wantClasses(t, res, 1, ClsSpecNewer)
	if fs := findingsOf(res, ClsSpecNewer); len(fs) != 1 {
		t.Errorf("SPEC_NEWER must be reported exactly once per package, got %d: %+v", len(fs), fs)
	}
	if !res.Valid {
		t.Error("a newer minor version must not make the package invalid")
	}
}

// All known checks still run under a newer minor: a hash error is found.
func TestSpecNewerStillChecksChain(t *testing.T) {
	g := newGen(t)
	g.specVersion = newerMinorVersion()
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.tick(time.Minute)
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.editLine(3, func(v *jcs.Value) {
		setMember(v.Get("payload"), "disk_pct", jInt(99))
	})
	res := verifyGen(g, Options{})
	wantClasses(t, res, 2, ClsSpecNewer, ClsHashMismatch, ClsUnsealedEnd) // unsealed end alongside, exit 2 wins
}

// Newer minor only in the manifest: still SPEC_NEWER, still once.
func TestSpecNewerManifestOnly(t *testing.T) {
	g := validSealedChain(t)            // sealed end (spec 8.6): SPEC_NEWER alone stays exit 1
	g.specVersion = newerMinorVersion() // entries were built at the current version; writePkg now writes the newer minor
	res := verifyGen(g, Options{})
	wantClasses(t, res, 1, ClsSpecNewer)
	fs := findingsOf(res, ClsSpecNewer)
	if len(fs) != 1 || fs[0].Seq != 0 || !strings.Contains(fs[0].Detail, "manifest.json") {
		t.Errorf("want one SPEC_NEWER from the manifest (seq 0), got %+v", fs)
	}
}

// --- (3) spec_version 2.0 -> FORMAT_ERROR ----------------------------------

func TestSpecMajorMismatchIsFormatError(t *testing.T) {
	g := newGen(t)
	g.specVersion = "2.0"
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	res := verifyGen(g, Options{})
	wantClasses(t, res, 3, ClsFormatError)
	if res.Valid {
		t.Error("major mismatch must not be valid")
	}
}

// Malformed version strings are FORMAT_ERROR too (not silently "newer").
func TestSpecVersionMalformedIsFormatError(t *testing.T) {
	for _, bad := range []string{"1", "1.x", "v1.0", "1.0.0", ""} {
		g := newGen(t)
		g.specVersion = bad
		g.genesis()
		res := verifyGen(g, Options{})
		if res.ExitCode != 3 || !classSet(res)[ClsFormatError] || classSet(res)[ClsSpecNewer] {
			t.Errorf("spec_version %q: want FORMAT_ERROR exit 3 without SPEC_NEWER, got %d %v", bad, res.ExitCode, res.Findings)
		}
	}
}

// --- (4) unknown ENVELOPE field -> still FORMAT_ERROR (R3) ----------------

func TestUnknownEnvelopeFieldStaysFormatError(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.extraEnv = map[string]any{"future_field": "x"} // hashed in, so only the schema fails
	g.tick(time.Minute)
	res := verifyGen(g, Options{})
	wantClasses(t, res, 3, ClsFormatError)
}

// R3 second half: payload fields of KNOWN types stay strict even under a
// newer minor version.
func TestKnownPayloadStaysStrictUnderNewerMinor(t *testing.T) {
	g := newGen(t)
	g.specVersion = newerMinorVersion()
	g.genesis()
	g.addAt(g.seq+1, "TICK", "system", 1000, map[string]any{
		"uptime_s": int64(1), "spool_backlog": int64(0), "disk_pct": int64(1),
		"future_payload_field": "x",
	})
	res := verifyGen(g, Options{})
	// the manifest's SPEC_NEWER is emitted before the entry is rejected;
	// exit class 3 wins
	wantClasses(t, res, 3, ClsFormatError, ClsSpecNewer)
}

// --- (5) unknown type without checkpoint after -> NO MISSING_CHECKPOINT ---

func TestUnknownEntryTypeNotCritical(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.futureNote(time.Minute) // unknown, NOT followed by a checkpoint
	g.tick(time.Minute)
	g.tick(time.Minute)
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.seal("shutdown") // sealed end (spec 8.6)
	res := verifyGen(g, Options{})
	mustNotHaveClass(t, res, ClsMissingCheckpoint)
	wantClasses(t, res, 1, ClsUnknownEntryType)
}

// Unknown type as the LAST entry of the chain. Up to spec 1.5 the point was
// "no MISSING_CHECKPOINT" (exit 1). From 1.6 no terminal entry draws
// MISSING_CHECKPOINT any more — every unsealed end is UNSEALED_END (exit 4,
// spec 6.2, 8.6) — so the test now pins the remaining difference: the chain
// end does NOT count the unknown type as a critical entry without checkpoint.
func TestUnknownEntryTypeAtChainEndNotCritical(t *testing.T) {
	g := validChain(t)
	g.futureNote(time.Minute)
	res := verifyGen(g, Options{})
	mustNotHaveClass(t, res, ClsMissingCheckpoint)
	wantClasses(t, res, 4, ClsUnknownEntryType, ClsUnsealedEnd)
	if ce := res.Stats.ChainEnd; ce == nil || ce.LastType != "FUTURE_NOTE" || ce.LastCriticalWithoutCheckpoint {
		t.Errorf("unknown type at the end must not count as critical: %+v", ce)
	}
}

// --- silence rules (8.2): unknown types cover nothing ----------------------

func TestUnknownEntryTypeDoesNotCoverSilence(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.futureNote(time.Hour) // one silent hour ends in an unknown type: not GAP/RESTART
	res := verifyGen(g, Options{})
	wantClasses(t, res, 2, ClsUnknownEntryType, ClsConcealedSilence, ClsUnsealedEnd) // unsealed end alongside, exit 2 wins
}

// --- combined vector shape: 1.1 everywhere + one FUTURE_NOTE ---------------

func TestFormatUnknownEventTypeVectorShape(t *testing.T) {
	g := newGen(t)
	g.specVersion = newerMinorVersion()
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.tick(5 * time.Minute)
	g.futureNote(time.Minute)
	g.tick(5 * time.Minute)
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	res := verifyGen(g, Options{})
	// Like every vector frozen up to 1.5 the chain ends unsealed: from spec
	// 1.6 UNSEALED_END joins and the exit is 4 (precedence 4 before 1).
	wantClasses(t, res, 4, ClsSpecNewer, ClsUnknownEntryType, ClsUnsealedEnd)
	// all classes render in both languages without MISSING markers
	for _, lang := range []string{"de", "en"} {
		txt := RenderText(res, "pkg", lang)
		if strings.Contains(txt, "MISSING:") {
			t.Errorf("%s report has missing i18n keys:\n%s", lang, txt)
		}
	}
}

// --- (6) added after the adversarial review of 2026-09-13 ------------------
//
// Each of these was a real divergence between the Go verifier, the Python
// verifier and the generated JSON schema, found by running the three against
// the same inputs. They are red without the corresponding fix.

// An empty event_type is a string outside the known list like any other; with
// "" doubling as the "known" sentinel it produced NO finding and exit 0.
func TestEmptyEventTypeIsUnknownEntryType(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.add(time.Minute, "", "system", map[string]any{"note": "empty type name"})
	g.seal("shutdown") // sealed end (spec 8.6): the unknown type alone stays exit 1
	res := verifyGen(g, Options{})
	wantClasses(t, res, 1, ClsUnknownEntryType)
	if f := findingsOf(res, ClsUnknownEntryType); len(f) != 1 || f[0].Seq != 4 {
		t.Errorf("want one UNKNOWN_ENTRY_TYPE at seq 4, got %+v", f)
	}
}

// Leading zeros are malformed (spec section 2), not aliases: strconv.Atoi had
// accepted "01.0" as 1.0 while schema and Python rejected it.
func TestSpecVersionLeadingZerosAreFormatError(t *testing.T) {
	for _, bad := range []string{"01.0", "1.00", "1.01", "001.0"} {
		g := newGen(t)
		g.specVersion = bad
		g.genesis()
		res := verifyGen(g, Options{})
		if res.ExitCode != 3 || !classSet(res)[ClsFormatError] || classSet(res)[ClsSpecNewer] {
			t.Errorf("spec_version %q: want FORMAT_ERROR exit 3 without SPEC_NEWER, got %d %v", bad, res.ExitCode, res.Findings)
		}
	}
}

// A MINOR of any digit count is judged as a whole number (spec 10.6 R1);
// strconv.Atoi had overflowed into FORMAT_ERROR where Python said SPEC_NEWER.
func TestSpecMinorOfAnyLengthIsSpecNewer(t *testing.T) {
	g := newGen(t)
	g.specVersion = "1." + strings.Repeat("9", 40)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.seal("shutdown") // sealed end (spec 8.6): SPEC_NEWER alone stays exit 1
	res := verifyGen(g, Options{})
	wantClasses(t, res, 1, ClsSpecNewer)
	if n := len(findingsOf(res, ClsSpecNewer)); n != 1 {
		t.Errorf("SPEC_NEWER reported %d times, want exactly once", n)
	}
}

// 10.6 R3, last sentence: a rule-1 finding is reported alongside a
// FORMAT_ERROR of the same entry (an unknown envelope field at 1.1).
func TestSpecNewerReportedAlongsideFormatError(t *testing.T) {
	g := newGen(t)
	g.specVersion = newerMinorVersion()
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.extraEnv = map[string]any{"future_field": "x"}
	g.tick(time.Minute)
	res := verifyGen(g, Options{})
	wantClasses(t, res, 3, ClsFormatError, ClsSpecNewer)
}
