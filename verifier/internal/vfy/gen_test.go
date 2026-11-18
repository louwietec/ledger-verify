package vfy

// Synthetic mini-chain generator for unit tests. It builds cryptographically
// real chains (own JCS, SHA-256, RFC 6962, Ed25519) exclusively from the open
// specification. Test-only code; not part of the shipped verifier binary.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
)

type gen struct {
	t        *testing.T
	chainID  string
	seq      int64
	lines    [][]byte
	hashesRw [][]byte // raw entry hashes in seq order
	lastHash string
	lastCP   string // entry_hash of previous CHECKPOINT
	devPriv  map[string]ed25519.PrivateKey
	devPub   map[string]string
	curKey   string
	vendorID string
	vendPriv ed25519.PrivateKey
	vendPub  string
	now      time.Time
	// specVersion is written into every entry and the manifest (the verifier's
	// own version by default); extraEnv adds envelope fields BEFORE hashing (forward-
	// compatibility tests, spec 10.6).
	specVersion string
	extraEnv    map[string]any
	// extraMan adds fields to the manifest object, extraSeg to every element
	// of manifest.segments — the two places spec 10.6 R5 declares open.
	extraMan map[string]any
	extraSeg map[string]any
	// license is GENESIS.license_id; empty means the licence commitment of
	// "LEDGER-VER1-F1ER-L1ZE-NZ01" — from spec 1.8 the only admissible form (spec 4.1).
	license string
	// tsLayout formats ts_captured/ts_chained; empty means time.RFC3339
	// (whole seconds). The millisecond tests of spec 1.9 (spec 2, "Time
	// arithmetic") set time.RFC3339Nano to write fractions.
	tsLayout string
	// cpSubject is the signed subject (spec 6.1) of every CHECKPOINT by its
	// seq, the bytes a time witness stamps (spec 7.3).
	cpSubject map[int64][]byte
}

// testLicenseCommitment is SHA-256("LEDGER-VER1-F1ER-L1ZE-NZ01") in lowercase hex (spec 4.1).
func testLicenseCommitment() string {
	sum := sha256.Sum256([]byte("LEDGER-VER1-F1ER-L1ZE-NZ01"))
	return hex.EncodeToString(sum[:])
}

// currentSpecVersion is this verifier's own "MAJOR.MINOR"; newerMinorVersion
// is one MINOR ahead of it. The forward-compatibility tests use these instead
// of literals so a release bump (1.0 -> 1.1, S1) cannot silently turn a
// "newer minor" fixture into the current version and the test into a no-op.
func currentSpecVersion() string { return fmt.Sprintf("%d.%d", specMajor, specMinor) }
func newerMinorVersion() string  { return fmt.Sprintf("%d.%d", specMajor, specMinor+1) }

func keyFromSeed(seed byte) (ed25519.PrivateKey, string) {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv, hex.EncodeToString(priv.Public().(ed25519.PublicKey))
}

func newGen(t *testing.T) *gen {
	devPriv, devPub := keyFromSeed(1)
	venPriv, venPub := keyFromSeed(2)
	return &gen{
		t:           t,
		chainID:     "0f0e0d0c-0b0a-4900-8807-060504030201",
		devPriv:     map[string]ed25519.PrivateKey{"dev-1": devPriv},
		devPub:      map[string]string{"dev-1": devPub},
		curKey:      "dev-1",
		vendorID:    "vendor-1",
		vendPriv:    venPriv,
		vendPub:     venPub,
		lastHash:    zeroHash,
		lastCP:      zeroHash,
		now:         time.Date(2026, 8, 1, 8, 0, 0, 0, time.UTC),
		specVersion: currentSpecVersion(),
	}
}

func (g *gen) ts() string { return g.fmtTS(g.now) }

// fmtTS formats an instant the way the generator writes timestamps.
func (g *gen) fmtTS(t time.Time) string {
	if g.tsLayout != "" {
		return t.UTC().Format(g.tsLayout)
	}
	return t.UTC().Format(time.RFC3339)
}

func canonGo(t *testing.T, x any) []byte {
	b, err := jcs.CanonGo(x)
	if err != nil {
		t.Fatalf("canon: %v", err)
	}
	return b
}

// addAt appends an entry with an explicit seq (for SEQ_BREAK crafting).
func (g *gen) addAt(seq int64, eventType, origin string, mono int64, payload map[string]any) string {
	env := map[string]any{
		"spec_version":  g.specVersion,
		"chain_id":      g.chainID,
		"seq":           seq,
		"ts_captured":   g.ts(),
		"ts_chained":    g.ts(),
		"mono_delta_ms": mono,
		"event_type":    eventType,
		"origin":        origin,
		"payload":       payload,
		"prev_hash":     g.lastHash,
	}
	for k, v := range g.extraEnv {
		env[k] = v
	}
	sum := sha256.Sum256(canonGo(g.t, env))
	h := hex.EncodeToString(sum[:])
	env["entry_hash"] = h
	g.lines = append(g.lines, canonGo(g.t, env))
	raw, _ := hex.DecodeString(h)
	g.hashesRw = append(g.hashesRw, raw)
	g.lastHash = h
	g.seq = seq
	return h
}

// add appends the next entry after advancing time by d (mono follows d).
func (g *gen) add(d time.Duration, eventType, origin string, payload map[string]any) string {
	g.now = g.now.Add(d)
	mono := d.Milliseconds()
	if g.seq == 0 {
		mono = -1
	}
	return g.addAt(g.seq+1, eventType, origin, mono, payload)
}

// addMono appends an entry with explicit mono_delta_ms (clock tests).
func (g *gen) addMono(d time.Duration, mono int64, eventType, origin string, payload map[string]any) string {
	g.now = g.now.Add(d)
	return g.addAt(g.seq+1, eventType, origin, mono, payload)
}

func (g *gen) genesis() string {
	return g.add(0, "GENESIS", "system", map[string]any{
		"customer_id":       "cust-1",
		"appliance_id":      "1a2b3c4d-5e6f-4a01-9b02-c3d4e5f60718",
		"device_pubkey":     g.devPub[g.curKey],
		"device_key_id":     g.curKey,
		"license_id":        g.licenseID(),
		"edition":           "pro",
		"purpose_statement": "test chain",
		"language":          "en",
		"timezone":          "Europe/Vienna",
		"predecessor_chain": nil,
	})
}

func (g *gen) licenseID() string {
	if g.license != "" {
		return g.license
	}
	return testLicenseCommitment()
}

func (g *gen) merkleRootAt(treeSize int64) string {
	roots := merkleRoots(g.hashesRw[:treeSize])
	return hex.EncodeToString(roots[treeSize-1][:])
}

// checkpoint writes a CHECKPOINT over all entries so far.
func (g *gen) checkpoint(d time.Duration) string {
	return g.checkpointMono(d, d.Milliseconds())
}

// checkpointMono writes a CHECKPOINT with an explicit mono_delta_ms — −1 for
// the immediate checkpoint the ledger writes late at a restart (spec 8.2
// conditions 3 and 4, from 1.9).
func (g *gen) checkpointMono(d time.Duration, mono int64) string {
	treeSize := g.seq
	root := g.merkleRootAt(treeSize)
	tsChained := g.fmtTS(g.now.Add(d))
	subject := canonGo(g.t, map[string]any{
		"chain_id":             g.chainID,
		"tree_size":            treeSize,
		"merkle_root":          root,
		"prev_checkpoint_hash": g.lastCP,
		"key_id":               g.curKey,
		"ts":                   tsChained,
	})
	sig := hex.EncodeToString(ed25519.Sign(g.devPriv[g.curKey], subject))
	h := g.addMono(d, mono, "CHECKPOINT", "system", map[string]any{
		"tree_size":            treeSize,
		"merkle_root":          root,
		"prev_checkpoint_hash": g.lastCP,
		"key_id":               g.curKey,
		"signature":            sig,
	})
	g.lastCP = h
	if g.cpSubject == nil {
		g.cpSubject = map[int64][]byte{}
	}
	g.cpSubject[g.seq] = subject
	return h
}

// receipt writes a CHECKPOINT_RECEIPT for the checkpoint at cpSeq.
func (g *gen) receipt(d time.Duration, cpSeq, treeSize int64, root string) string {
	g.now = g.now.Add(d)
	serverTS := g.ts()
	subject := canonGo(g.t, map[string]any{
		"chain_id":    g.chainID,
		"tree_size":   treeSize,
		"merkle_root": root,
		"server_ts":   serverTS,
	})
	sig := hex.EncodeToString(ed25519.Sign(g.vendPriv, subject))
	return g.addAt(g.seq+1, "CHECKPOINT_RECEIPT", "system", d.Milliseconds(), map[string]any{
		"checkpoint_seq":   cpSeq,
		"tree_size":        treeSize,
		"merkle_root":      root,
		"server_ts":        serverTS,
		"server_key_id":    g.vendorID,
		"server_signature": sig,
	})
}

// receiptForLast writes a receipt for the most recent checkpoint.
func (g *gen) receiptForLast(d time.Duration) string {
	cpSeq := g.seq
	treeSize := cpSeq - 1
	return g.receipt(d, cpSeq, treeSize, g.merkleRootAt(treeSize))
}

func (g *gen) tick(d time.Duration) string {
	return g.add(d, "TICK", "system", map[string]any{
		"uptime_s":      int64(g.now.Sub(time.Date(2026, 8, 1, 8, 0, 0, 0, time.UTC)) / time.Second),
		"spool_backlog": int64(0),
		"disk_pct":      int64(10),
	})
}

func (g *gen) aiCall(d time.Duration, reqCommit, respCommit any) string {
	return g.add(d, "AI_CALL", "proxy", map[string]any{
		"provider_class": "generic", "route": "default", "model": "m",
		"endpoint": "/v1/x", "http_status": int64(200), "outcome": "ok",
		"duration_ms": int64(120), "request_bytes": int64(10), "response_bytes": int64(20),
		"tokens_in": int64(3), "tokens_out": int64(4), "streamed": false,
		"confidence": "recorded", "source_id": nil, "source_ref": nil,
		"mode": "full", "request_commitment": reqCommit,
		"response_commitment": respCommit, "vault_ref": "vault/1",
	})
}

// writePkg writes the package as a directory and returns its path.
func (g *gen) writePkg() string {
	dir := g.t.TempDir()
	segDir := filepath.Join(dir, "segments")
	if err := os.MkdirAll(segDir, 0o755); err != nil {
		g.t.Fatal(err)
	}
	var seg []byte
	for _, l := range g.lines {
		seg = append(seg, l...)
		seg = append(seg, '\n')
	}
	if err := os.WriteFile(filepath.Join(segDir, "000001.jsonl"), seg, 0o644); err != nil {
		g.t.Fatal(err)
	}
	sum := sha256.Sum256(seg)
	var devKeys, vendKeys []any
	for id, pub := range g.devPub {
		devKeys = append(devKeys, map[string]any{"key_id": id, "pubkey": pub})
		g.writeKey(dir, "device", id, pub)
	}
	vendKeys = append(vendKeys, map[string]any{"key_id": g.vendorID, "pubkey": g.vendPub})
	g.writeKey(dir, "vendor", g.vendorID, g.vendPub)
	man := map[string]any{
		"spec_version": g.specVersion,
		"chain_id":     g.chainID,
		"created_ts":   g.ts(),
		"tree_size":    g.seq,
		"segments": []any{map[string]any{
			"file": "000001.jsonl", "sha256": hex.EncodeToString(sum[:]),
			"first_seq": int64(1), "last_seq": g.seq,
		}},
		"device_pubkeys": devKeys,
		"vendor_pubkeys": vendKeys,
	}
	for k, v := range g.extraMan {
		man[k] = v
	}
	if len(g.extraSeg) > 0 {
		for _, s := range man["segments"].([]any) {
			for k, v := range g.extraSeg {
				s.(map[string]any)[k] = v
			}
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), canonGo(g.t, man), 0o644); err != nil {
		g.t.Fatal(err)
	}
	return dir
}

func (g *gen) writeKey(dir, kind, id, pub string) {
	kd := filepath.Join(dir, "keys", kind)
	if err := os.MkdirAll(kd, 0o755); err != nil {
		g.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(kd, id+".hex"), []byte(pub+"\n"), 0o644); err != nil {
		g.t.Fatal(err)
	}
}

// editLine mutates one already-built line (post-hoc tampering).
func (g *gen) editLine(idx int, mutate func(v *jcs.Value)) {
	v, err := jcs.Parse(g.lines[idx])
	if err != nil {
		g.t.Fatal(err)
	}
	mutate(v)
	g.lines[idx] = jcs.Canon(v)
}

func setMember(v *jcs.Value, key string, nv *jcs.Value) {
	for i := range v.Members {
		if v.Members[i].Key == key {
			v.Members[i].Value = nv
			return
		}
	}
	v.Members = append(v.Members, jcs.Member{Key: key, Value: nv})
}

func jStr(s string) *jcs.Value { return &jcs.Value{Kind: jcs.KindString, Str: s} }
func jInt(n int64) *jcs.Value  { return &jcs.Value{Kind: jcs.KindInt, Int: n} }

// validChain builds: GENESIS, CP, RECEIPT, ticks, CP, RECEIPT. From spec 1.6
// it ends INCOMPLETE — like an export from a running installation, and like
// every vector frozen up to 1.5 — and verifies as exit 4 with UNSEALED_END
// alone; validSealedChain is the same chain properly sealed (exit 0).
func validChain(t *testing.T) *gen {
	g := newGen(t)
	g.genesis()
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	g.tick(5 * time.Minute)
	g.tick(5 * time.Minute)
	g.aiCall(time.Minute, nil, nil)
	g.checkpoint(time.Second)
	g.receiptForLast(time.Second)
	return g
}

// seal closes the chain properly (spec 8.6): a SEAL with the given reason one
// minute later and directly its immediate checkpoint — no receipt, so the
// anchoring of the chain stays what the test built. From spec 1.6 every chain
// that does not end this way is incomplete (UNSEALED_END, exit 4), like an
// export from a running installation. Tests whose verdict concerns something
// other than the chain end seal their chain with this, so their expectation
// stays exactly the one of the case under test (exit 0 and 1 included); the
// chain-end tests (kettenende_test.go) build their ends by hand.
func (g *gen) seal(reason string) string {
	h := g.add(time.Minute, "SEAL", "system", map[string]any{
		"version": "1.0.0", "reason": reason,
	})
	g.checkpoint(time.Second)
	return h
}

// validSealedChain is validChain closed with seal("shutdown"): GENESIS, CP,
// RECEIPT, TICK, TICK, AI_CALL, CP, RECEIPT, SEAL, CP. It verifies with exit 0
// and no findings and carries exactly the two receipts of validChain.
func validSealedChain(t *testing.T) *gen {
	g := validChain(t)
	g.seal("shutdown")
	return g
}

// verifyGen runs the verifier with now = one hour after the last entry.
func verifyGen(g *gen, opt Options) Result {
	if opt.Now.IsZero() {
		opt.Now = g.now.Add(time.Hour)
	}
	return Verify(g.writePkg(), genAnker(opt))
}

// genAnker pins the generator's vendor key as the auditor's anchor (spec
// 7.1). The tests act as the auditor: they know which vendor key is genuine,
// and without saying so every receipt would be RECEIPT_UNVERIFIED by design.
// The trust tests (vendortrust_test.go) build their options by hand.
func genAnker(opt Options) Options {
	_, pub := keyFromSeed(2)
	opt.VendorKeys = append(opt.VendorKeys, VendorKey{ID: "vendor-1", Pubkey: pub})
	return opt
}

func classSet(res Result) map[string]bool {
	m := map[string]bool{}
	for _, f := range res.Findings {
		m[f.Class] = true
	}
	return m
}

func wantClasses(t *testing.T, res Result, exit int, classes ...string) {
	t.Helper()
	got := classSet(res)
	want := map[string]bool{}
	for _, c := range classes {
		want[c] = true
	}
	if res.ExitCode != exit {
		t.Errorf("exit = %d, want %d; findings: %v", res.ExitCode, exit, res.Findings)
	}
	if fmt.Sprint(sortedKeys(got)) != fmt.Sprint(sortedKeys(want)) {
		t.Errorf("finding classes = %v, want %v; findings: %+v", sortedKeys(got), sortedKeys(want), res.Findings)
	}
}

func sortedKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
