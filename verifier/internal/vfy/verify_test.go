package vfy

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
)

// Spec 1.6 (8.6): the ordinary chain of a running installation — it ends with
// a checkpoint and its receipt — is INCOMPLETE: every entry is intact, but the
// package does not prove that nothing came after the last one (exit 4,
// UNSEALED_END, not "valid"). Up to 1.5 this chain was exit 0. Closed with a
// SEAL and its immediate checkpoint, the same chain is valid without findings.
func TestValidChain(t *testing.T) {
	res := verifyGen(validChain(t), Options{})
	wantClasses(t, res, 4, ClsUnsealedEnd)
	// Spec 10.3: exit 4 is a status of its own and must not be marked
	// invalid in machine-readable output — valid means "no manipulation
	// proven", the verdict is Status.
	if !res.Valid || res.Status != "incomplete" {
		t.Errorf("incomplete chain (exit 4): valid=%v status=%q, want true/incomplete", res.Valid, res.Status)
	}
	res = verifyGen(validSealedChain(t), Options{})
	wantClasses(t, res, 0)
	if !res.Valid || res.Status != "valid" {
		t.Errorf("valid sealed chain: valid=%v status=%q, want true/valid", res.Valid, res.Status)
	}
}

func TestValidChainAsZip(t *testing.T) {
	g := validSealedChain(t) // sealed (spec 8.6): the ZIP path must reach exit 0 like the directory
	dir := g.writePkg()
	zipPath := filepath.Join(t.TempDir(), "pkg.zip")
	zf, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	err = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		w, err := zw.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		_, err = w.Write(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zf.Close()
	res := Verify(zipPath, genAnker(Options{Now: g.now.Add(time.Hour)}))
	wantClasses(t, res, 0)
}

func TestTamperRewriteHashMismatch(t *testing.T) {
	g := validChain(t)
	// rewrite the TICK payload at index 3 without touching stored hashes
	g.editLine(3, func(v *jcs.Value) {
		setMember(v.Get("payload"), "disk_pct", jInt(99))
	})
	res := verifyGen(g, Options{})
	// The chain ends unsealed: UNSEALED_END is reported alongside, and the
	// exit-2 finding decides the exit code (precedence 2 before 4, spec 10.3).
	wantClasses(t, res, 2, ClsHashMismatch, ClsUnsealedEnd)
}

func TestTamperSeqBreak(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	// skip a sequence number: next entry gets seq+2 (hashes stay consistent)
	g.now = g.now.Add(time.Minute)
	g.addAt(g.seq+2, "TICK", "system", int64(60_000), map[string]any{
		"uptime_s": int64(1), "spool_backlog": int64(0), "disk_pct": int64(1),
	})
	// manifest last_seq must match line count: fix by writing seq range 1..n
	dir := g.writePkg()
	// writePkg used g.seq (=5) as tree_size but there are 4 lines -> fix manifest
	fixManifest(t, dir, 4)
	res := Verify(dir, genAnker(Options{Now: g.now.Add(time.Hour)}))
	if res.ExitCode != 2 || !classSet(res)[ClsSeqBreak] {
		t.Errorf("want SEQ_BREAK exit 2, got %d %v", res.ExitCode, res.Findings)
	}
}

// fixManifest rewrites tree_size/last_seq after low-level seq tampering.
func fixManifest(t *testing.T, dir string, n int64) {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := jcs.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	setMember(v, "tree_size", jInt(n))
	setMember(v.Get("segments").Arr[0], "last_seq", jInt(n))
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), jcs.Canon(v), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestTamperSigInvalid(t *testing.T) {
	g := validChain(t)
	// flip the signature of the last checkpoint (index len-2)
	idx := len(g.lines) - 2
	g.editLine(idx, func(v *jcs.Value) {
		sig := v.Get("payload").Get("signature").Str
		flipped := "0"
		if sig[0] == '0' {
			flipped = "1"
		}
		setMember(v.Get("payload"), "signature", jStr(flipped+sig[1:]))
	})
	res := verifyGen(g, Options{})
	// editing the payload also breaks the entry hash; SIG_INVALID must appear
	if res.ExitCode != 2 || !classSet(res)[ClsSigInvalid] {
		t.Errorf("want SIG_INVALID exit 2, got %d %v", res.ExitCode, res.Findings)
	}
}

func TestKeyRotationValid(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	// rotate dev-1 -> dev-2
	newPriv, newPub := keyFromSeed(3)
	subject := canonGo(t, map[string]any{
		"old_key_id": "dev-1", "new_key_id": "dev-2", "new_pubkey": newPub,
	})
	sig := hex.EncodeToString(ed25519.Sign(g.devPriv["dev-1"], subject))
	g.add(time.Minute, "KEY_ROTATION", "portal", map[string]any{
		"old_key_id": "dev-1", "new_key_id": "dev-2",
		"new_pubkey": newPub, "signature_by_old_key": sig,
	})
	g.devPriv["dev-2"] = newPriv
	g.devPub["dev-2"] = newPub
	g.curKey = "dev-2"
	g.checkpoint(time.Second) // immediate checkpoint, signed by the NEW key
	g.receiptForLast(time.Second)
	g.seal("shutdown") // sealed end (spec 8.6); the seal's checkpoint is signed by the new key too
	res := verifyGen(g, Options{})
	wantClasses(t, res, 0)
}

func TestKeyRotationBadSignature(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	newPriv, newPub := keyFromSeed(3)
	// signature by the NEW key instead of the old one: not legitimized
	subject := canonGo(t, map[string]any{
		"old_key_id": "dev-1", "new_key_id": "dev-2", "new_pubkey": newPub,
	})
	sig := hex.EncodeToString(ed25519.Sign(newPriv, subject))
	g.add(time.Minute, "KEY_ROTATION", "portal", map[string]any{
		"old_key_id": "dev-1", "new_key_id": "dev-2",
		"new_pubkey": newPub, "signature_by_old_key": sig,
	})
	g.devPriv["dev-2"] = newPriv
	g.devPub["dev-2"] = newPub
	g.curKey = "dev-2"
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	res := verifyGen(g, Options{})
	wantClasses(t, res, 2, ClsSigInvalid, ClsUnsealedEnd) // unsealed end alongside, exit 2 wins
}

func TestTamperTruncateReceiptBeyondEnd(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	// vendor receipt anchoring a tree size beyond the presented chain
	g.receipt(time.Second, 8, 7, strings.Repeat("ab", 32))
	res := verifyGen(g, Options{})
	wantClasses(t, res, 2, ClsMerkleInconsistent, ClsUnsealedEnd) // unsealed end alongside, exit 2 wins
}

func TestTamperForkReceiptWrongRoot(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	// validly signed receipt for tree_size 1 with a root of a different history
	g.receipt(time.Second, 2, 1, strings.Repeat("cd", 32))
	res := verifyGen(g, Options{})
	wantClasses(t, res, 2, ClsForkDetected, ClsUnsealedEnd) // unsealed end alongside, exit 2 wins
}

func TestTamperReceiptBadSignature(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	idx := len(g.lines) - 1
	g.editLine(idx, func(v *jcs.Value) {
		sig := v.Get("payload").Get("server_signature").Str
		flipped := "0"
		if sig[0] == '0' {
			flipped = "1"
		}
		setMember(v.Get("payload"), "server_signature", jStr(flipped+sig[1:]))
	})
	res := verifyGen(g, Options{})
	if res.ExitCode != 2 || !classSet(res)[ClsReceiptInvalid] {
		t.Errorf("want RECEIPT_INVALID exit 2, got %d %v", res.ExitCode, res.Findings)
	}
}

func TestNoAnchor(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.tick(5 * time.Minute)
	g.seal("shutdown") // sealed without a receipt: NO_ANCHOR alone stays exit 1
	res := verifyGen(g, Options{})
	wantClasses(t, res, 1, ClsNoAnchor)
}

func TestCoveredGap(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	// one hour of silence, immediately terminated by a covering GAP
	start := g.now.Format(time.RFC3339)
	g.now = g.now.Add(time.Hour)
	end := g.now.Format(time.RFC3339)
	g.addAt(g.seq+1, "GAP", "system", -1, map[string]any{
		"reason": "power_loss", "started_ts": start, "ended_ts": end,
		"lost_count": int64(-1), "detail": nil,
	})
	g.checkpoint(time.Second) // immediate checkpoint after critical GAP
	g.receiptForLast(time.Second)
	g.seal("shutdown") // sealed end (spec 8.6): the declared gap alone stays exit 1
	res := verifyGen(g, Options{})
	wantClasses(t, res, 1, ClsCoveredGap)
}

func TestConcealedSilence(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.tick(time.Hour) // one silent hour without any declaration
	res := verifyGen(g, Options{})
	wantClasses(t, res, 2, ClsConcealedSilence, ClsUnsealedEnd) // unsealed end alongside, exit 2 wins
}

func TestSilenceCoveredByRestart(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.addMono(time.Hour, -1, "RESTART", "system", map[string]any{
		"reason": "crash_recovery", "downtime_ms_estimate": int64(3_600_000),
		"version": "1.0.0",
	})
	g.seal("shutdown") // sealed end (spec 8.6)
	res := verifyGen(g, Options{})
	wantClasses(t, res, 0)
}

func TestGapNotCoveringWindow(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	// GAP terminates the silence but its declared window is elsewhere
	g.now = g.now.Add(time.Hour)
	w := g.now.Add(-5 * time.Minute).Format(time.RFC3339)
	g.addAt(g.seq+1, "GAP", "system", -1, map[string]any{
		"reason": "manual", "started_ts": w, "ended_ts": g.ts(),
		"lost_count": int64(0), "detail": nil,
	})
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	res := verifyGen(g, Options{})
	// window starts too late -> silence concealed; GAP itself still noted;
	// the chain ends unsealed (UNSEALED_END), exit 2 wins
	wantClasses(t, res, 2, ClsConcealedSilence, ClsCoveredGap, ClsUnsealedEnd)
}

func TestClockAnomaly(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	// wall clock advances 6 minutes, monotonic clock says 1 second
	g.addMono(6*time.Minute, 1000, "TICK", "system", map[string]any{
		"uptime_s": int64(1), "spool_backlog": int64(0), "disk_pct": int64(1),
	})
	res := verifyGen(g, Options{})
	wantClasses(t, res, 2, ClsClockAnomaly, ClsUnsealedEnd) // unsealed end alongside, exit 2 wins
}

func TestClockJumpDeclared(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	// wall clock set BACK 10 minutes while monotonic clock ran 1 s
	before := g.ts()
	jump := int64(-600_000)
	g.addMono(-10*time.Minute, 1000, "CLOCK_JUMP", "system", map[string]any{
		"wall_before": before, "wall_after": g.ts(),
		"mono_delta_ms": int64(1000), "jump_ms": jump,
	})
	g.seal("shutdown") // sealed end (spec 8.6): the declared jump alone stays exit 1
	res := verifyGen(g, Options{})
	wantClasses(t, res, 1, ClsClockJumpNote)
}

func TestSealResumeHandoverValid(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	sealHash := g.add(time.Minute, "SEAL", "system", map[string]any{
		"version": "1.0.0", "reason": "update",
	})
	g.checkpoint(time.Second)
	g.addMono(30*time.Minute, -1, "RESUME", "system", map[string]any{
		"prev_version": "1.0.0", "new_version": "1.1.0",
		"sealed_entry_hash": sealHash,
	})
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.seal("shutdown") // the chain END sealed too (spec 8.6), so the mid-chain handover is judged alone
	res := verifyGen(g, Options{})
	wantClasses(t, res, 0)
}

func TestHandoverBrokenWrongHash(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.add(time.Minute, "SEAL", "system", map[string]any{
		"version": "1.0.0", "reason": "update",
	})
	g.checkpoint(time.Second)
	// resume within the silence tolerance so that the wrong hash is the
	// only violation (a long pause would additionally be CONCEALED_SILENCE,
	// since a RESUME with a wrong hash is not "the matching RESUME")
	g.addMono(5*time.Minute, -1, "RESUME", "system", map[string]any{
		"prev_version": "1.0.0", "new_version": "1.1.0",
		"sealed_entry_hash": strings.Repeat("ef", 32), // wrong
	})
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	res := verifyGen(g, Options{})
	wantClasses(t, res, 2, ClsHandoverBroken, ClsUnsealedEnd) // unsealed end alongside, exit 2 wins
}

func TestHandoverBrokenInterveningEntry(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	sealHash := g.add(time.Minute, "SEAL", "system", map[string]any{
		"version": "1.0.0", "reason": "update",
	})
	g.checkpoint(time.Second)
	g.tick(time.Minute) // forbidden entry between SEAL(+cp) and RESUME
	g.add(time.Minute, "RESUME", "system", map[string]any{
		"prev_version": "1.0.0", "new_version": "1.1.0",
		"sealed_entry_hash": sealHash,
	})
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	res := verifyGen(g, Options{})
	// the RESUME is also reported as unmatched -> single class HANDOVER_BROKEN;
	// the chain ends unsealed (UNSEALED_END), exit 2 wins
	wantClasses(t, res, 2, ClsHandoverBroken, ClsUnsealedEnd)
}

// Up to spec 1.5 only decommission and key_loss closed a chain; from 1.6 every
// reason does (spec 8.4, 8.6) — TestSealedEndAnyReason in kettenende_test.go
// covers the other three. Decommission stays green.
func TestSealDecommissionClosesChain(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.add(time.Minute, "SEAL", "system", map[string]any{
		"version": "1.0.0", "reason": "decommission",
	})
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	res := verifyGen(g, Options{})
	wantClasses(t, res, 0)
}

// The unsealed stale chain (like the vector valid_stale): TRAILING_SILENCE
// (exit class 1) and UNSEALED_END (exit class 4) together give exit 4 — the
// precedence puts 4 before 1 (spec 10.3). Up to 1.5 this was exit 1. The
// sealed stale chain stays exit 1: TestSealedStaleIsTrailingSilence.
func TestTrailingSilence(t *testing.T) {
	g := validChain(t)
	res := verifyGen(g, Options{Now: g.now.Add(48 * time.Hour)})
	wantClasses(t, res, 4, ClsTrailingSilence, ClsUnsealedEnd)
}

func TestPerEntryInformativeFindings(t *testing.T) {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.add(time.Minute, "SOURCE_GAP", "import", map[string]any{
		"source_id": "src-1", "window_start": g.ts(), "window_end": g.ts(),
		"expected": int64(5), "observed": int64(3), "detail": nil,
	})
	g.add(time.Minute, "RECONCILIATION", "import", map[string]any{
		"source_id": "src-1", "window_start": g.ts(), "window_end": g.ts(),
		"reported_count": int64(10), "chained_count": int64(8), "delta": int64(2),
	})
	g.add(time.Minute, "CONTENT_DELETED", "portal", map[string]any{
		"target_seq": int64(1), "vault_ref": "vault/1",
		"reason": "retention", "actor": "admin",
	})
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.seal("shutdown") // sealed end (spec 8.6): the informative findings alone stay exit 1
	res := verifyGen(g, Options{})
	wantClasses(t, res, 1, ClsCoveredSourceGap, ClsReconciliationDelta, ClsContentDeleted)
}

func TestContentCommitments(t *testing.T) {
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	plaintext := []byte("hello ai")
	mac := hmac.New(sha256.New, salt)
	mac.Write(plaintext)
	commit := hex.EncodeToString(mac.Sum(nil))

	build := func(t *testing.T, content []byte) string {
		g := newGen(t)
		g.genesis()
		g.checkpoint(time.Second)
		g.receiptForLast(time.Second)
		g.aiCall(time.Minute, commit, nil)
		aiSeq := g.seq
		g.checkpoint(time.Second)
		g.receiptForLast(time.Second)
		g.seal("shutdown") // sealed end (spec 8.6): the verdict is the commitment's alone
		dir := g.writePkg()
		cd := filepath.Join(dir, "content")
		if err := os.MkdirAll(cd, 0o755); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(cd, "4.request"), content, 0o644)
		// Spec 10.1 (1.9): the salt file names its AI_CALL — seq equal to the
		// N of the file name — and carries exactly the salts of the parts
		// presented. Up to 1.8 this test wrote no seq; it is now required.
		salts, _ := json.Marshal(map[string]any{"seq": 4, "request_salt": hex.EncodeToString(salt)})
		os.WriteFile(filepath.Join(cd, "4.salts.json"), salts, 0o644)
		if aiSeq != 4 {
			t.Fatalf("expected AI_CALL at seq 4, got %d", aiSeq)
		}
		return dir
	}

	t.Run("match", func(t *testing.T) {
		dir := build(t, plaintext)
		res := Verify(dir, genAnker(Options{Now: time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)}))
		wantClasses(t, res, 0)
	})
	t.Run("mismatch", func(t *testing.T) {
		dir := build(t, []byte("tampered plaintext"))
		res := Verify(dir, genAnker(Options{Now: time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)}))
		wantClasses(t, res, 2, ClsContentMismatch)
	})
}

func TestReportFiles(t *testing.T) {
	reportBytes := []byte("<html>report</html>")
	sum := sha256.Sum256(reportBytes)
	build := func(t *testing.T, fileBytes []byte) string {
		g := newGen(t)
		g.genesis()
		g.checkpoint(time.Second)
		g.receiptForLast(time.Second)
		g.add(time.Minute, "REPORT_ISSUED", "system", map[string]any{
			"report_type": "monthly", "period_start": g.ts(), "period_end": g.ts(),
			"tree_size": int64(3), "html_hash": hex.EncodeToString(sum[:]),
			"pdf_hash": nil, "renderer_version": "r1", "languages": "de,en",
		})
		g.checkpoint(time.Second)
		g.receiptForLast(time.Second)
		g.seal("shutdown") // sealed end (spec 8.6): the verdict is the report file's alone
		dir := g.writePkg()
		rd := filepath.Join(dir, "reports")
		if err := os.MkdirAll(rd, 0o755); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(rd, "monthly.html"), fileBytes, 0o644)
		return dir
	}
	t.Run("match", func(t *testing.T) {
		res := Verify(build(t, reportBytes), genAnker(Options{Now: time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)}))
		wantClasses(t, res, 0)
	})
	t.Run("mismatch", func(t *testing.T) {
		res := Verify(build(t, []byte("forged")), genAnker(Options{Now: time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)}))
		wantClasses(t, res, 2, ClsReportMismatch)
	})
}

func TestExpectRoot(t *testing.T) {
	g := validSealedChain(t) // sealed end (spec 8.6): the verdict is the expected root's alone
	root := g.merkleRootAt(g.seq)
	t.Run("match", func(t *testing.T) {
		res := Verify(g.writePkg(), genAnker(Options{Now: g.now.Add(time.Hour), ExpectRoot: root}))
		wantClasses(t, res, 0)
	})
	t.Run("mismatch", func(t *testing.T) {
		res := Verify(g.writePkg(), genAnker(Options{Now: g.now.Add(time.Hour), ExpectRoot: strings.Repeat("12", 32)}))
		wantClasses(t, res, 2, ClsMerkleInconsistent)
	})
}

func TestFormatBrokenJSON(t *testing.T) {
	g := validChain(t)
	dir := g.writePkg()
	segPath := filepath.Join(dir, "segments", "000001.jsonl")
	b, _ := os.ReadFile(segPath)
	b[10] = '~' // corrupt one byte
	os.WriteFile(segPath, b, 0o644)
	// segment hash now differs from the manifest -> FORMAT_ERROR
	res := Verify(dir, genAnker(Options{Now: g.now.Add(time.Hour)}))
	wantClasses(t, res, 3, ClsFormatError)
	if res.Valid {
		t.Error("format error must not be valid")
	}
}

func TestFormatBadSchema(t *testing.T) {
	g := newGen(t)
	g.genesis()
	// undefined payload field violates the exact-field-set rule
	g.addAt(g.seq+1, "TICK", "system", 1000, map[string]any{
		"uptime_s": int64(1), "spool_backlog": int64(0), "disk_pct": int64(1),
		"bogus_field": "x",
	})
	res := verifyGen(g, Options{})
	wantClasses(t, res, 3, ClsFormatError)
}

func TestFormatFloatRejected(t *testing.T) {
	g := newGen(t)
	g.genesis()
	dir := g.writePkg()
	segPath := filepath.Join(dir, "segments", "000001.jsonl")
	b, _ := os.ReadFile(segPath)
	nb := []byte(strings.Replace(string(b), `"mono_delta_ms":-1`, `"mono_delta_ms":-1.0`, 1))
	os.WriteFile(segPath, nb, 0o644)
	// fix the segment hash so the float itself is what fails
	sum := sha256.Sum256(nb)
	mb, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
	v, _ := jcs.Parse(mb)
	setMember(v.Get("segments").Arr[0], "sha256", jStr(hex.EncodeToString(sum[:])))
	os.WriteFile(filepath.Join(dir, "manifest.json"), jcs.Canon(v), 0o644)
	res := Verify(dir, genAnker(Options{Now: g.now.Add(time.Hour)}))
	wantClasses(t, res, 3, ClsFormatError)
}

// TestVerifyArgsNow pins who controls the verification time. The package's
// own verify_args.json is written by the appliance under examination, so by
// default it must NOT set the clock: a chain that stopped a week ago,
// exported with a "now" from back then, used to pass §8.5 as fresh.
func TestVerifyArgsNow(t *testing.T) {
	g := validSealedChain(t) // sealed end (spec 8.6): only the freshness verdict varies below
	dir := g.writePkg()
	// The chain ends at g.now; the package claims the check happens an hour
	// later, which would make it fresh.
	args, _ := json.Marshal(map[string]string{"now": g.now.Add(time.Hour).Format(time.RFC3339)})
	os.WriteFile(filepath.Join(dir, "verify_args.json"), args, 0o644)

	// Default: the real clock. g.now lies in the past (2026-08), so the
	// chain is stale — TRAILING_SILENCE, whatever the package says.
	res := Verify(dir, genAnker(Options{}))
	wantClasses(t, res, 1, ClsTrailingSilence)
	if res.Stats.NowSource != "system" {
		t.Fatalf("now_source = %q, want system", res.Stats.NowSource)
	}

	// Explicit opt-in: the package's time counts, and the report says so.
	res = Verify(dir, genAnker(Options{NowFromPackage: true}))
	wantClasses(t, res, 0)
	if res.Stats.NowSource != "package" {
		t.Fatalf("now_source = %q, want package", res.Stats.NowSource)
	}
	if txt := RenderText(res, "pkg", "en"); !strings.Contains(txt, "chosen by the prover") {
		t.Fatal("text report does not warn that the check time came from the package")
	}

	// --now wins over both.
	res = Verify(dir, genAnker(Options{Now: g.now.Add(72 * time.Hour), NowFromPackage: true}))
	wantClasses(t, res, 1, ClsTrailingSilence)
	if res.Stats.NowSource != "flag" {
		t.Fatalf("now_source = %q, want flag", res.Stats.NowSource)
	}
}

func TestJSONOutputStructure(t *testing.T) {
	g := validChain(t)
	res := verifyGen(g, Options{})
	b, err := RenderJSON(res)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"valid", "exit_code", "findings", "stats"} {
		if _, ok := m[k]; !ok {
			t.Errorf("JSON output missing key %q", k)
		}
	}
	if _, ok := m["findings"].([]any); !ok {
		t.Error("findings is not an array")
	}
}

func TestTextReportBothLanguages(t *testing.T) {
	g := validChain(t)
	res := verifyGen(g, Options{})
	de := RenderText(res, "pkg", "de")
	en := RenderText(res, "pkg", "en")
	if !strings.Contains(de, "Prüfbericht") || !strings.Contains(en, "verification report") {
		t.Error("language selection broken")
	}
	for _, s := range []string{de, en} {
		if strings.Contains(s, "MISSING:") {
			t.Errorf("report contains missing i18n keys:\n%s", s)
		}
	}
}
