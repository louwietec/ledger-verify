package vfy

// Spec 1.9, the package side: presented plaintexts (10.1), the number rule
// (2), verify_args.json (10.8), the segment table and its stages (10.1,
// 10.5), and the directory rules (10.1: wrapper strip, no symbolic links).
//
// Each rule closes a place where the two reference verifiers judged the same
// package differently or where a package could reach outside itself
// (runde2/map_randfaelle.md, divergences a, b, c, e, g). Every test here is
// red against the 1.8 verifier.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/louwietec/ledger-verify/verifier/internal/jcs"
)

// --- helpers -----------------------------------------------------------------

// praesentChain is a sealed chain with one full-mode AI_CALL at seq 4 whose
// request and response commitments are HMACs of reqText/respText under
// fixed salts. It returns the package directory and the two salts (hex).
func praesentChain(t *testing.T) (g *gen, dir, reqSalt, respSalt string) {
	t.Helper()
	rs, ps := make([]byte, 32), make([]byte, 32)
	for i := range rs {
		rs[i], ps[i] = byte(i), byte(0xa0+i)
	}
	mac := func(salt []byte, msg string) string {
		m := hmac.New(sha256.New, salt)
		m.Write([]byte(msg))
		return hex.EncodeToString(m.Sum(nil))
	}
	g = newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.aiCall(time.Minute, mac(rs, "the request"), mac(ps, "the response"))
	if g.seq != 4 {
		t.Fatalf("AI_CALL at seq %d, want 4", g.seq)
	}
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.seal("shutdown")
	return g, g.writePkg(), hex.EncodeToString(rs), hex.EncodeToString(ps)
}

// putFile writes content at the package-relative path rel.
func putFile(t *testing.T, dir, rel string, content []byte) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

// saltsJSON renders a salt file from members (JCS, as the exporter writes it).
func saltsJSON(t *testing.T, members map[string]any) []byte {
	t.Helper()
	return canonGo(t, members)
}

// verifyDir verifies a written package with the generator's clock and anchor.
func verifyDir(g *gen, dir string) Result {
	return Verify(dir, genAnker(Options{Now: g.now.Add(time.Hour)}))
}

// countClass counts the findings of one class.
func countClass(res Result, cls string) int {
	return len(findingsOf(res, cls))
}

// --- 1. presented plaintexts (spec 10.1, 9.1) ---------------------------------

// The exporter's shape — both parts, exactly seq/request_salt/response_salt/
// vault_ref — verifies without a finding; so does one part alone and a salt
// file without vault_ref.
func TestPresentedPlaintextsConforming(t *testing.T) {
	for _, c := range []struct {
		name  string
		files map[string]string
		salts func(req, resp string) map[string]any
	}{
		{"both parts with vault_ref", map[string]string{"request": "the request", "response": "the response"},
			func(req, resp string) map[string]any {
				return map[string]any{"seq": 4, "request_salt": req, "response_salt": resp, "vault_ref": "vault/1"}
			}},
		{"request only", map[string]string{"request": "the request"},
			func(req, _ string) map[string]any { return map[string]any{"seq": 4, "request_salt": req} }},
		{"response only", map[string]string{"response": "the response"},
			func(_, resp string) map[string]any { return map[string]any{"seq": 4, "response_salt": resp} }},
	} {
		t.Run(c.name, func(t *testing.T) {
			g, dir, req, resp := praesentChain(t)
			for part, text := range c.files {
				putFile(t, dir, "content/4."+part, []byte(text))
			}
			putFile(t, dir, "content/4.salts.json", append(saltsJSON(t, c.salts(req, resp)), '\n'))
			wantClasses(t, verifyDir(g, dir), 0)
		})
	}
}

// Every other file under content/ is CONTENT_MISMATCH, once per file — and a
// plaintext whose salt file does not conform cannot be checked, so it is one
// as well. want is the number of CONTENT_MISMATCH findings.
func TestPresentedPlaintextsEveryOtherFileIsMismatch(t *testing.T) {
	type dateien map[string][]byte
	cases := []struct {
		name  string
		files func(t *testing.T, req, resp string) dateien
		want  int
	}{
		{"salt file without seq (the pre-1.9 test fixture)", func(t *testing.T, req, _ string) dateien {
			return dateien{"content/4.request": []byte("the request"), "content/4.salts.json": saltsJSON(t, map[string]any{"request_salt": req})}
		}, 2},
		{"seq differs from the name", func(t *testing.T, req, _ string) dateien {
			return dateien{"content/4.request": []byte("the request"), "content/4.salts.json": saltsJSON(t, map[string]any{"seq": 5, "request_salt": req})}
		}, 2},
		{"seq as a string", func(t *testing.T, req, _ string) dateien {
			return dateien{"content/4.request": []byte("the request"), "content/4.salts.json": saltsJSON(t, map[string]any{"seq": "4", "request_salt": req})}
		}, 2},
		{"undefined member", func(t *testing.T, req, _ string) dateien {
			return dateien{"content/4.request": []byte("the request"), "content/4.salts.json": saltsJSON(t, map[string]any{"seq": 4, "request_salt": req, "note": "x"})}
		}, 2},
		{"salt in upper case", func(t *testing.T, req, _ string) dateien {
			return dateien{"content/4.request": []byte("the request"), "content/4.salts.json": saltsJSON(t, map[string]any{"seq": 4, "request_salt": strings.ToUpper(req)})}
		}, 2},
		{"salt with a blank", func(t *testing.T, req, _ string) dateien {
			return dateien{"content/4.request": []byte("the request"), "content/4.salts.json": saltsJSON(t, map[string]any{"seq": 4, "request_salt": req[:10] + " " + req[11:]})}
		}, 2},
		{"salt of a part not presented", func(t *testing.T, req, resp string) dateien {
			return dateien{"content/4.response": []byte("the response"), "content/4.salts.json": saltsJSON(t, map[string]any{"seq": 4, "request_salt": req, "response_salt": resp})}
		}, 2},
		{"presented part without its salt", func(t *testing.T, req, _ string) dateien {
			return dateien{"content/4.request": []byte("the request"), "content/4.response": []byte("the response"), "content/4.salts.json": saltsJSON(t, map[string]any{"seq": 4, "request_salt": req})}
		}, 3},
		{"vault_ref not a string", func(t *testing.T, req, _ string) dateien {
			return dateien{"content/4.request": []byte("the request"), "content/4.salts.json": saltsJSON(t, map[string]any{"seq": 4, "request_salt": req, "vault_ref": 7})}
		}, 2},
		{"duplicate member", func(t *testing.T, req, _ string) dateien {
			return dateien{"content/4.request": []byte("the request"), "content/4.salts.json": []byte(`{"request_salt":"` + req + `","request_salt":"` + req + `","seq":4}`)}
		}, 2},
		{"salt file not JSON", func(t *testing.T, _, _ string) dateien {
			return dateien{"content/4.request": []byte("the request"), "content/4.salts.json": []byte("salt=abc")}
		}, 2},
		{"plaintext without a salt file", func(t *testing.T, _, _ string) dateien {
			return dateien{"content/4.request": []byte("the request")}
		}, 1},
		{"salt file without a plaintext", func(t *testing.T, _, _ string) dateien {
			return dateien{"content/4.salts.json": saltsJSON(t, map[string]any{"seq": 4})}
		}, 1},
		{"leading zero in the name", func(t *testing.T, req, _ string) dateien {
			return dateien{"content/04.request": []byte("the request"), "content/04.salts.json": saltsJSON(t, map[string]any{"seq": 4, "request_salt": req})}
		}, 2},
		{"file in a subdirectory", func(t *testing.T, req, _ string) dateien {
			return dateien{"content/sub/4.request": []byte("the request")}
		}, 1},
		{"another name beside a conforming presentation", func(t *testing.T, req, _ string) dateien {
			return dateien{"content/4.request": []byte("the request"), "content/4.salts.json": saltsJSON(t, map[string]any{"seq": 4, "request_salt": req}), "content/notes.txt": []byte("x")}
		}, 1},
		{"tampered plaintext", func(t *testing.T, req, _ string) dateien {
			return dateien{"content/4.request": []byte("the tampered request"), "content/4.salts.json": saltsJSON(t, map[string]any{"seq": 4, "request_salt": req})}
		}, 1},
		{"plaintext for a seq that is no AI_CALL", func(t *testing.T, req, _ string) dateien {
			return dateien{"content/3.request": []byte("the request"), "content/3.salts.json": saltsJSON(t, map[string]any{"seq": 3, "request_salt": req})}
		}, 1},
		{"plaintext for a seq beyond the chain", func(t *testing.T, req, _ string) dateien {
			return dateien{"content/99.request": []byte("the request"), "content/99.salts.json": saltsJSON(t, map[string]any{"seq": 99, "request_salt": req})}
		}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g, dir, req, resp := praesentChain(t)
			for rel, b := range c.files(t, req, resp) {
				putFile(t, dir, rel, b)
			}
			res := verifyDir(g, dir)
			wantClasses(t, res, 2, ClsContentMismatch)
			if got := countClass(res, ClsContentMismatch); got != c.want {
				t.Errorf("CONTENT_MISMATCH %d times, want %d (once per file): %+v", got, c.want, res.Findings)
			}
		})
	}
}

// A null commitment (hash_only) cannot be checked against a presented
// plaintext: CONTENT_MISMATCH, not a silent skip (divergence a11).
func TestPresentedPlaintextForNullCommitment(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.aiCall(time.Minute, nil, nil) // seq 4, no commitments
	g.checkpoint(time.Second)
	g.seal("shutdown")
	dir := g.writePkg()
	putFile(t, dir, "content/4.request", []byte("x"))
	putFile(t, dir, "content/4.salts.json", saltsJSON(t, map[string]any{"seq": 4, "request_salt": strings.Repeat("ab", 32)}))
	res := Verify(dir, genAnker(Options{Now: g.now.Add(time.Hour)}))
	wantClasses(t, res, 2, ClsContentMismatch)
	if countClass(res, ClsContentMismatch) != 1 {
		t.Errorf("want one CONTENT_MISMATCH: %+v", res.Findings)
	}
}

// --- 2. numbers (spec 2) --------------------------------------------------------

// A number outside the integer profile is FORMAT_ERROR wherever it stands in
// the package: in a salt file and in the vendor key list too — there spec 2
// overrides the milder verdicts of 10.1 (CONTENT_MISMATCH) and 10.7
// (ineffective). The chain end of such a package is not judged (8.6).
func TestNumbersOutsideTheProfileAreFormatErrors(t *testing.T) {
	cases := []struct {
		name string
		edit func(t *testing.T, g *gen, dir, req string)
	}{
		{"salt file seq 4.0", func(t *testing.T, _ *gen, dir, req string) {
			putFile(t, dir, "content/4.request", []byte("the request"))
			putFile(t, dir, "content/4.salts.json", []byte(`{"request_salt":"`+req+`","seq":4.0}`))
		}},
		{"salt file seq 2^53", func(t *testing.T, _ *gen, dir, req string) {
			putFile(t, dir, "content/4.request", []byte("the request"))
			putFile(t, dir, "content/4.salts.json", []byte(`{"request_salt":"`+req+`","seq":9007199254740992}`))
		}},
		{"salt file: duplicate member before an exponent", func(t *testing.T, _ *gen, dir, req string) {
			putFile(t, dir, "content/4.request", []byte("the request"))
			putFile(t, dir, "content/4.salts.json", []byte(`{"seq":4,"seq":4e0,"request_salt":"`+req+`"}`))
		}},
		{"vendor key list version 1.0 (no vendor root supplied)", func(t *testing.T, _ *gen, dir, _ string) {
			putFile(t, dir, VendorListPath, []byte(`{"format":"rekorder-herstellerschluessel/1","version":1.0}`))
		}},
		{"vendor key list: fraction inside", func(t *testing.T, _ *gen, dir, _ string) {
			putFile(t, dir, VendorListPath, []byte(`{"format":"rekorder-herstellerschluessel/1","version":1,"schluessel":[{"n":0.5}]}`))
		}},
		{"manifest tree_size N.0", func(t *testing.T, g *gen, dir, _ string) {
			b, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
			alt := fmt.Sprintf(`"tree_size":%d`, g.seq)
			if !strings.Contains(string(b), alt) {
				t.Fatalf("manifest lacks %s", alt)
			}
			putFile(t, dir, "manifest.json", []byte(strings.Replace(string(b), alt, alt+".0", 1)))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g, dir, req, _ := praesentChain(t)
			c.edit(t, g, dir, req)
			res := verifyDir(g, dir)
			wantClasses(t, res, 3, ClsFormatError)
			if res.Stats.ChainEnd != nil || res.Stats.Completeness != nil || res.Stats.ResidualWindow != nil {
				t.Errorf("format error judged the chain end / completeness / residual window: %+v", res.Stats)
			}
		})
	}
}

// Numbers in entries: the payload of an unknown type is held to the profile
// as well, and so is every envelope number; 2^53−1 itself is inside.
func TestNumbersInEntries(t *testing.T) {
	// The unknown type's own line is not read when its number breaks the
	// JSON profile, so it signals nothing; when the TICK's number breaks it,
	// the unknown type was read and its signal stands beside the error.
	for _, c := range []struct {
		name, from, to string
		exit           int
		want           []string
	}{
		{"unknown type, payload 2^60", `"payload":{"note":"n"}`, `"payload":{"n":1152921504606846976,"note":"n"}`, 3, []string{ClsFormatError}},
		{"unknown type, payload 1.0", `"payload":{"note":"n"}`, `"payload":{"n":1.0,"note":"n"}`, 3, []string{ClsFormatError}},
		{"TICK uptime_s 2^53", `"uptime_s":0`, `"uptime_s":9007199254740992`, 3, []string{ClsFormatError, ClsUnknownEntryType}},
		{"TICK uptime_s 2^53-1", `"uptime_s":0`, `"uptime_s":9007199254740991`, -1, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := newGen(t)
			g.genesis()
			g.checkpoint(time.Second)
			g.receiptForLast(time.Second)
			g.add(time.Minute, "FUTURE_NOTE", "system", map[string]any{"note": "n"})
			g.add(0, "TICK", "system", map[string]any{"uptime_s": int64(0), "spool_backlog": int64(0), "disk_pct": int64(1)})
			g.seal("shutdown")
			dir := g.writePkg()
			// Rewrite the raw bytes and repair the hashes that cover them: the
			// verdict must be about the number, never about a stale hash.
			rewriteSegment(t, dir, func(b []byte) []byte {
				return []byte(strings.Replace(string(b), c.from, c.to, 1))
			})
			res := verifyDir(g, dir)
			if c.exit == 3 {
				wantClasses(t, res, 3, c.want...)
				return
			}
			// 2^53-1 parses; the rewritten entry's own hash then no longer
			// matches — the number is accepted, only the tamper is seen.
			if classSet(res)[ClsFormatError] {
				t.Errorf("2^53-1 rejected as a format error: %+v", res.Findings)
			}
		})
	}
}

// --- 3. verify_args.json (spec 10.8) -------------------------------------------

// Requested and absent or not conforming: FORMAT_ERROR with the reason, exit
// 3 — never the system clock. now_source stays "package", "now" is empty, and
// the chain end is not judged.
func TestVerifyArgsRequestedButUnusable(t *testing.T) {
	cases := map[string]string{
		"absent":               "",
		"not JSON":             "now=2026-08-01T10:00:00Z",
		"number":               `{"now":1785578400}`,
		"missing now":          `{"jetzt":"2026-08-01T10:00:00Z"}`,
		"extra member":         `{"now":"2026-08-01T10:00:00Z","by":"x"}`,
		"now twice":            `{"now":"2026-08-01T10:00:00Z","now":"2026-08-01T10:00:00Z"}`,
		"blank instead of T":   `{"now":"2026-08-01 10:00:00Z"}`,
		"offset":               `{"now":"2026-08-01T10:00:00+01:00"}`,
		"without zone":         `{"now":"2026-08-01T10:00:00"}`,
		"empty fraction":       `{"now":"2026-08-01T10:00:00.Z"}`,
		"without seconds":      `{"now":"2026-08-01T10:00Z"}`,
		"not an object":        `["2026-08-01T10:00:00Z"]`,
		"fraction in a number": `{"now":"2026-08-01T10:00:00Z","n":1.5}`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			g := validSealedChain(t)
			dir := g.writePkg()
			if content != "" {
				putFile(t, dir, "verify_args.json", []byte(content))
			}
			res := Verify(dir, genAnker(Options{NowFromPackage: true}))
			wantClasses(t, res, 3, ClsFormatError)
			if res.Stats.NowSource != "package" || res.Stats.Now != "" {
				t.Errorf("now_source=%q now=%q, want package and empty", res.Stats.NowSource, res.Stats.Now)
			}
			if !strings.Contains(res.Findings[0].Detail, "verify_args.json") || !strings.Contains(res.Findings[0].Detail, "no fallback to the system clock") {
				t.Errorf("detail does not give the reason: %s", res.Findings[0].Detail)
			}
			for lang, want := range map[string]string{"de": "nicht bestimmt", "en": "not determined"} {
				if txt := RenderText(res, "pkg", lang); !strings.Contains(txt, want) || strings.Contains(txt, "MISSING:") {
					t.Errorf("%s report does not say the check time was not determined:\n%s", lang, txt)
				}
			}
		})
	}
	// --now wins and the file is not read at all (10.8: only on request).
	t.Run("flag wins, file not read", func(t *testing.T) {
		g := validSealedChain(t)
		dir := g.writePkg()
		putFile(t, dir, "verify_args.json", []byte("garbage"))
		res := Verify(dir, genAnker(Options{Now: g.now.Add(time.Hour), NowFromPackage: true}))
		wantClasses(t, res, 0)
		if res.Stats.NowSource != "flag" {
			t.Errorf("now_source = %q, want flag", res.Stats.NowSource)
		}
	})
	// Not requested: a broken file is not read either.
	t.Run("not requested, file not read", func(t *testing.T) {
		g := validSealedChain(t)
		dir := g.writePkg()
		putFile(t, dir, "verify_args.json", []byte("garbage"))
		res := Verify(dir, genAnker(Options{Now: g.now.Add(time.Hour)}))
		wantClasses(t, res, 0)
	})
	// A conforming file with ten fraction digits: the grammar cuts after nine.
	t.Run("ten fraction digits conform", func(t *testing.T) {
		g := validSealedChain(t)
		dir := g.writePkg()
		putFile(t, dir, "verify_args.json", []byte(`{"now":"`+g.now.Add(time.Hour).Format("2006-01-02T15:04:05")+`.1234567891Z"}`))
		res := Verify(dir, genAnker(Options{NowFromPackage: true}))
		wantClasses(t, res, 0)
		if res.Stats.NowSource != "package" {
			t.Errorf("now_source = %q", res.Stats.NowSource)
		}
	})
}

// ParseTime is the grammar of spec 2/10.7 for the auditor's --now (10.8).
func TestParseTimeAuditorGrammar(t *testing.T) {
	for _, ok := range []string{"2026-01-01T12:02:00Z", "2026-01-01T12:02:00.5Z", "0001-01-01T00:00:00Z", "9999-12-31T23:59:59.999999999Z", "2026-01-01T12:02:00.1234567891Z"} {
		if _, err := ParseTime(ok); err != nil {
			t.Errorf("ParseTime(%q) = %v, want accepted", ok, err)
		}
	}
	for _, bad := range []string{"2026-01-01T12:02:00", "2026-01-01", "2026-01-01 12:02:00Z", "20260101T120200Z", "2026-W01-4T12:02:00Z",
		"2026-01-01T12:02Z", "2026-01-01T12:02:00.Z", "2026-01-01T12:02:00,5Z", "2026-01-01T1:02:00Z", "0000-01-01T00:00:00Z",
		"2026-01-01T12:02:00+01:00", "2026-01-01t12:02:00z", "2026-01-01T12:02:60Z", "2026-02-30T12:02:00Z"} {
		if _, err := ParseTime(bad); err == nil {
			t.Errorf("ParseTime(%q) accepted, want an error (spec 10.8)", bad)
		}
	}
}

// --- 5. processing stages (spec 10.5) ---------------------------------------

// A foreign chain_id is a FORMAT_ERROR of the same object; the object's
// signals stay beside it (10.6 R3) — up to 1.8 the chain_id check came first
// and dropped them (divergences e3, e4).
func TestSignalsSurviveForeignChainID(t *testing.T) {
	for _, c := range []struct {
		name string
		mk   func(g *gen)
		cls  string
	}{
		{"unknown type", func(g *gen) { g.futureNote(time.Minute) }, ClsUnknownEntryType},
		{"newer minor", func(g *gen) {
			g.specVersion = newerMinorVersion()
			g.tick(time.Minute)
			g.specVersion = currentSpecVersion()
		}, ClsSpecNewer},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := newGen(t)
			g.genesis()
			g.checkpoint(time.Second)
			echt := g.chainID
			g.chainID = "11111111-2222-4333-8444-555555555555" // this one entry belongs to another chain
			c.mk(g)
			g.chainID = echt
			res := verifyGen(g, Options{})
			wantClasses(t, res, 3, ClsFormatError, c.cls)
		})
	}
}

// segPart is one segment of a hand-written segment table: the entries
// lines[from-1:to] in file, declared as first..last (0 = as held).
type segPart struct {
	file        string
	from, to    int
	first, last int64
	dir         string // "" = segments
}

// resegment replaces the package's segments by parts, listed in the manifest
// in the order given, with tree_size treeSize (0 = number of lines).
func resegment(t *testing.T, g *gen, dir string, parts []segPart, treeSize int64) {
	t.Helper()
	if err := os.RemoveAll(filepath.Join(dir, "segments")); err != nil {
		t.Fatal(err)
	}
	var segs []any
	for _, p := range parts {
		var body []byte
		for _, l := range g.lines[p.from-1 : p.to] {
			body = append(body, l...)
			body = append(body, '\n')
		}
		sub := p.dir
		if sub == "" {
			sub = "segments"
		}
		putFile(t, dir, sub+"/"+filepath.Base(p.file), body)
		first, last := p.first, p.last
		if first == 0 {
			first, last = int64(p.from), int64(p.to)
		}
		sum := sha256.Sum256(body)
		segs = append(segs, map[string]any{"file": p.file, "sha256": hex.EncodeToString(sum[:]), "first_seq": first, "last_seq": last})
	}
	if treeSize == 0 {
		treeSize = int64(len(g.lines))
	}
	mb, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := jcs.Parse(mb)
	if err != nil {
		t.Fatal(err)
	}
	sv, err := jcs.FromGo(segs)
	if err != nil {
		t.Fatal(err)
	}
	setMember(m, "segments", sv)
	setMember(m, "tree_size", jInt(treeSize))
	putFile(t, dir, "manifest.json", jcs.Canon(m))
}

// Stage 3 runs over EVERY segment before any line is read: a signal in the
// first segment is not reported when the second is missing or fails its
// SHA-256 (10.5: never from a missing segment or one with a wrong SHA, and
// nothing after a failing stage 3). Up to 1.8 the first segment's lines were
// parsed before the second was even opened.
func TestStageThreeBeforeAnyLine(t *testing.T) {
	build := func(t *testing.T) (*gen, string) {
		g := newGen(t)
		g.genesis()
		g.checkpoint(time.Second)
		g.receiptForLast(time.Second)
		g.futureNote(time.Minute) // seq 4, in the first segment
		g.tick(time.Minute)
		g.seal("shutdown") // seq 6, 7
		dir := g.writePkg()
		resegment(t, g, dir, []segPart{{file: "a.jsonl", from: 1, to: 4}, {file: "b.jsonl", from: 5, to: 7}}, 0)
		return g, dir
	}
	t.Run("control: both present", func(t *testing.T) {
		g, dir := build(t)
		wantClasses(t, verifyDir(g, dir), 1, ClsUnknownEntryType)
	})
	t.Run("second segment missing", func(t *testing.T) {
		g, dir := build(t)
		os.Remove(filepath.Join(dir, "segments", "b.jsonl"))
		wantClasses(t, verifyDir(g, dir), 3, ClsFormatError)
	})
	t.Run("second segment SHA-256 wrong", func(t *testing.T) {
		g, dir := build(t)
		putFile(t, dir, "segments/b.jsonl", append(append([]byte{}, g.lines[4]...), '\n'))
		wantClasses(t, verifyDir(g, dir), 3, ClsFormatError)
	})
}

// From 1.9 (10.5 stage 1) the R5 signals of the manifest come before its
// schema verdict and stand beside a schema error of the same manifest.
func TestManifestSignalsBesideSchemaError(t *testing.T) {
	g := validSealedChain(t)
	g.extraMan = map[string]any{"excerpt_of": "x"}
	dir := g.writePkg()
	manifestFeldEntfernen(t, dir, "created_ts")
	res := verifyDir(g, dir)
	wantClasses(t, res, 3, ClsFormatError, ClsUnknownManifestFld)
}

// --- 7. the segment table (spec 10.1) --------------------------------------------

// The file name follows ^[A-Za-z0-9._-]{1,128}$, is not "." or "..", and is
// read only as segments/<file>. A traversal to a file OUTSIDE the package
// is refused before anything is read (map g9: the 1.8 verifier read it).
func TestSegmentFileGrammar(t *testing.T) {
	for _, name := range []string{"../chain.jsonl", "../../OUTSIDE.jsonl", "sub/chain.jsonl", "chain .jsonl", ".", "..", "chain\\x.jsonl", "", "chäin.jsonl"} {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			g := validSealedChain(t)
			base := t.TempDir()
			dir := filepath.Join(base, "pkg", "inner")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			src := g.writePkg()
			copyTree(t, src, dir)
			// The file the name points at exists, next to and outside the package.
			var body []byte
			for _, l := range g.lines {
				body = append(append(body, l...), '\n')
			}
			// segments/../chain.jsonl lies at the package root, and
			// segments/../../OUTSIDE.jsonl next to the package directory.
			for _, p := range []string{filepath.Join(dir, "chain.jsonl"), filepath.Join(base, "pkg", "OUTSIDE.jsonl")} {
				if err := os.WriteFile(p, body, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			sum := sha256.Sum256(body)
			mb, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
			m, _ := jcs.Parse(mb)
			seg := m.Get("segments").Arr[0]
			setMember(seg, "file", jStr(name))
			setMember(seg, "sha256", jStr(hex.EncodeToString(sum[:])))
			putFile(t, dir, "manifest.json", jcs.Canon(m))
			res := Verify(dir, genAnker(Options{Now: g.now.Add(time.Hour)}))
			wantClasses(t, res, 3, ClsFormatError)
		})
	}
}

// copyTree copies the regular files of src below dst.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		putFile(t, dst, filepath.ToSlash(rel), b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Segments are taken in first_seq order whatever the list order; declared
// ranges start at 1 without gap or overlap, end at tree_size ≥ 1, and every
// file holds exactly its declared number of lines. Every violation is
// FORMAT_ERROR.
func TestSegmentTable(t *testing.T) {
	cases := []struct {
		name  string
		parts []segPart
		tree  int64
		exit  int
	}{
		{"two segments listed in reverse order", []segPart{{file: "b.jsonl", from: 6, to: 10}, {file: "a.jsonl", from: 1, to: 5}}, 0, 0},
		{"three segments shuffled", []segPart{{file: "c.jsonl", from: 8, to: 10}, {file: "a.jsonl", from: 1, to: 3}, {file: "b.jsonl", from: 4, to: 7}}, 0, 0},
		{"per-file line count differs from its range", []segPart{{file: "a.jsonl", from: 1, to: 6, first: 1, last: 5}, {file: "b.jsonl", from: 7, to: 10, first: 6, last: 10}}, 0, 3},
		{"gap in the declared ranges", []segPart{{file: "a.jsonl", from: 1, to: 5}, {file: "b.jsonl", from: 6, to: 10, first: 7, last: 11}}, 11, 3},
		{"overlap", []segPart{{file: "a.jsonl", from: 1, to: 6}, {file: "b.jsonl", from: 5, to: 10}}, 0, 3},
		{"not starting at 1", []segPart{{file: "a.jsonl", from: 1, to: 10, first: 2, last: 11}}, 11, 3},
		{"ranges end before tree_size", []segPart{{file: "a.jsonl", from: 1, to: 10}}, 11, 3},
		{"segment outside segments/", []segPart{{file: "a.jsonl", from: 1, to: 10, dir: "."}}, 0, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := validSealedChain(t) // 10 entries
			if len(g.lines) != 10 {
				t.Fatalf("fixture has %d entries, want 10", len(g.lines))
			}
			dir := g.writePkg()
			resegment(t, g, dir, c.parts, c.tree)
			res := verifyDir(g, dir)
			if c.exit == 0 {
				wantClasses(t, res, 0)
			} else {
				wantClasses(t, res, 3, ClsFormatError)
			}
		})
	}
}

// --- 7. directory packages (spec 10.1) ----------------------------------------

// A directory that holds exactly one directory and nothing else is a
// wrapper and is stripped, as for a zipped directory (map g6: exit 3 up to
// 1.8). With anything beside it, it is not.
func TestDirectoryWrapperStripped(t *testing.T) {
	g := validSealedChain(t)
	src := g.writePkg()
	wrap := t.TempDir()
	copyTree(t, src, filepath.Join(wrap, "pruefpaket"))
	wantClasses(t, verifyDir(g, wrap), 0)

	putFile(t, wrap, "README.txt", []byte("beside the wrapper"))
	wantClasses(t, verifyDir(g, wrap), 3, ClsFormatError)
}

// A symbolic link anywhere inside a directory package is FORMAT_ERROR —
// nothing is read through it. Up to 1.8 a link was indexed like a file and
// followed.
func TestDirectorySymlinkIsFormatError(t *testing.T) {
	for _, c := range []struct {
		name string
		mk   func(t *testing.T, dir, outside string)
	}{
		{"segment file is a link", func(t *testing.T, dir, outside string) {
			seg := filepath.Join(dir, "segments", "000001.jsonl")
			b, _ := os.ReadFile(seg)
			os.WriteFile(filepath.Join(outside, "seg.jsonl"), b, 0o644)
			os.Remove(seg)
			if err := os.Symlink(filepath.Join(outside, "seg.jsonl"), seg); err != nil {
				t.Fatalf("cannot create a symbolic link: %v", err)
			}
		}},
		{"a link to a directory", func(t *testing.T, dir, outside string) {
			if err := os.Symlink(outside, filepath.Join(dir, "reports")); err != nil {
				t.Fatalf("cannot create a symbolic link: %v", err)
			}
		}},
		{"a dangling link", func(t *testing.T, dir, _ string) {
			if err := os.Symlink("/nonexistent/x", filepath.Join(dir, "keys", "x.hex")); err != nil {
				t.Fatalf("cannot create a symbolic link: %v", err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := validSealedChain(t)
			dir := g.writePkg()
			outside := t.TempDir()
			c.mk(t, dir, outside)
			res := verifyDir(g, dir)
			wantClasses(t, res, 3, ClsFormatError)
			if !strings.Contains(res.Findings[0].Detail, "symbolic link") {
				t.Errorf("detail does not name the link: %s", res.Findings[0].Detail)
			}
		})
	}
	// The package path the auditor types may itself be a link.
	t.Run("the package root may be a link", func(t *testing.T) {
		g := validSealedChain(t)
		dir := g.writePkg()
		link := filepath.Join(t.TempDir(), "pkg")
		if err := os.Symlink(dir, link); err != nil {
			t.Fatalf("cannot create a symbolic link: %v", err)
		}
		wantClasses(t, verifyDir(g, link), 0)
	})
}

// The directory reader answers only for names it indexed: no "..", no
// absolute path, nothing outside the package.
func TestDirReaderOnlyIndexedNames(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "pkg")
	putFile(t, pkg, "manifest.json", []byte("{}"))
	putFile(t, pkg, "keys/k.hex", []byte("k"))
	putFile(t, root, "secret.txt", []byte("outside"))
	fsys, err := openPackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"../secret.txt", "keys/../../secret.txt", filepath.Join(root, "secret.txt"), "keys", "missing.json"} {
		if _, err := fsys.ReadFile(n); err == nil {
			t.Errorf("ReadFile(%q) succeeded, want refused", n)
		}
		if fsys.Exists(n) {
			t.Errorf("Exists(%q) = true", n)
		}
	}
	if b, err := fsys.ReadFile("keys/k.hex"); err != nil || string(b) != "k" {
		t.Errorf("indexed file: %q %v", b, err)
	}
	if _, err := json.Marshal(fsys.List("")); err != nil {
		t.Fatal(err)
	}
}
