package cli

// The vectors of the extension of edition 1.10 (registry testvectors group
// hybrid, spec/testvectors README 16): ML-DSA-87 hybrid with the protocol
// key list ledger-protokollschluessel/2 (format spec 7.4.7a), the extract
// ledger-protokollauszug/2 (7.4.8a), steps L1, L2 (b'), (e'), (g'), L7 and
// L8 of 7.4.10, the members of vendor_log added in 10.10.2 and the rule of
// format spec 2 on keys of small order. The expected file names exit code,
// finding classes and the evidence level; the members of vendor_log and the
// reasons of the findings stand in the member why of each registry entry.
// This test holds the Go verifier to them.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
	"louwietec.com/ledger-verify/verifier/internal/vfy"
)

// hySoll is what a vector of the group hybrid shows in vendor_log: the
// status, the format of P, H, the version of P2, unknown_alg, the counts
// (hybrid_required, hybrid_incomplete), the seals (carried, defective,
// key_not_established, not_checked), cose_not_checked, the receipt classes
// (included, unchecked, missing, pending) and the codes of the findings.
type hySoll struct {
	status     string
	format     string
	h          string
	p2Version  int64
	unknownAlg bool
	hybrid     [2]int
	seals      [4]int
	cose       int
	receipts   [4]int
	codes      []string
}

var hyGeprueft = hySoll{status: "checked", format: "ledger-protokollschluessel/2", p2Version: 1, receipts: [4]int{1, 0, 0, 1}}

func hy(f func(s *hySoll)) hySoll {
	s := hyGeprueft
	f(&s)
	return s
}

var hyKeinSchluessel = hySoll{status: "no_protocol_key", codes: []string{"no_protocol_key"}}

var hySollwerte = map[string]hySoll{
	"log2_hybrid_included": hy(func(s *hySoll) {
		s.h, s.hybrid, s.seals = "2026-01-02", [2]int{1, 0}, [4]int{1, 0, 0, 0}
	}),
	"log2_hybrid_before_hybrid_from": hy(func(s *hySoll) { s.h = "2026-01-03" }),
	"log2_hybrid_mldsa_missing": hy(func(s *hySoll) {
		s.h, s.hybrid, s.receipts, s.codes = "2026-01-02", [2]int{1, 1}, [4]int{0, 1, 0, 1}, []string{"hybrid_incomplete"}
	}),
	"log2_hybrid_mldsa_fails": hy(func(s *hySoll) {
		s.h, s.hybrid, s.seals, s.receipts = "2026-01-02", [2]int{1, 1}, [4]int{0, 1, 0, 0}, [4]int{0, 1, 0, 1}
		s.codes = []string{"mldsa_signature", "hybrid_incomplete"}
	}),
	"log2_hybrid_ed25519_fails_mldsa_ok": hy(func(s *hySoll) {
		s.h, s.hybrid, s.seals, s.receipts = "2026-01-02", [2]int{1, 0}, [4]int{1, 0, 0, 0}, [4]int{0, 0, 1, 1}
		s.codes = []string{"signature", "days_not_supplied"}
	}),
	"log2_hybrid_extract_v1_only": hy(func(s *hySoll) {
		s.h, s.hybrid, s.receipts, s.codes = "2026-01-02", [2]int{1, 1}, [4]int{0, 1, 0, 1}, []string{"hybrid_incomplete"}
	}),
	"log2_mldsa_key_not_listed":            hy(func(s *hySoll) { s.seals = [4]int{0, 0, 1, 0} }),
	"log2_mldsa_wrong_length":              hy(func(s *hySoll) { s.seals, s.codes = [4]int{0, 1, 0, 0}, []string{"mldsa_signature"} }),
	"log2_mldsa_not_b64":                   hy(func(s *hySoll) { s.seals, s.codes = [4]int{0, 1, 0, 0}, []string{"mldsa_signature"} }),
	"log2_mldsa_key_revoked_signed_before": hy(func(s *hySoll) { s.h, s.hybrid, s.seals = "2026-01-02", [2]int{1, 0}, [4]int{1, 0, 0, 0} }),
	"log2_mldsa_key_revoked_signed_after": hy(func(s *hySoll) {
		s.h, s.hybrid, s.seals, s.receipts = "2026-01-02", [2]int{1, 1}, [4]int{1, 0, 0, 0}, [4]int{0, 1, 0, 1}
		s.codes = []string{"hybrid_incomplete"}
	}),
	"log2_list_projection_mismatch": hyKeinSchluessel,
	"log2_list_v1_newer_than_v2": hy(func(s *hySoll) {
		s.format, s.seals = "ledger-protokollschluessel/1", [4]int{1, 0, 0, 0}
	}),
	"log2_list_hybrid_from_differs": hyKeinSchluessel,
	"log2_list_hybrid_from_dropped": hyKeinSchluessel,
	"log2_list_mldsa_key_dropped":   hyKeinSchluessel,
	"log2_list_unknown_alg":         hy(func(s *hySoll) { s.unknownAlg, s.seals = true, [4]int{1, 0, 0, 0} }),
	"log2_list_mldsa_pubkey_length": hyKeinSchluessel,
	"log2_list_log_uri_changed":     hyKeinSchluessel,
	"log2_list_log_uri_relative":    hyKeinSchluessel,
	"log2_extract_v1_v2_merged": hy(func(s *hySoll) {
		s.h, s.hybrid, s.seals = "2026-01-02", [2]int{1, 0}, [4]int{1, 0, 0, 0}
	}),
	"log2_mirror_year": hy(func(s *hySoll) {
		s.h, s.hybrid, s.seals = "2026-01-02", [2]int{1, 0}, [4]int{3, 0, 0, 0}
	}),
	"log2_extract_seal_unknown_type":        hy(func(s *hySoll) { s.seals = [4]int{0, 0, 0, 1} }),
	"log2_extract_seal_cades_not_checked":   hy(func(s *hySoll) { s.seals = [4]int{1, 0, 0, 1} }),
	"log2_extract_cose_members_not_checked": hy(func(s *hySoll) { s.seals, s.cose = [4]int{1, 0, 0, 0}, 5 }),
	"evidence_level_3_hybrid": hy(func(s *hySoll) {
		s.h, s.hybrid, s.seals = "2026-01-02", [2]int{1, 0}, [4]int{1, 0, 0, 0}
	}),
	"evidence_hybrid_incomplete_reach": hy(func(s *hySoll) {
		s.h, s.hybrid, s.receipts, s.codes = "2026-01-02", [2]int{1, 1}, [4]int{0, 1, 0, 1}, []string{"hybrid_incomplete"}
	}),
	"ed25519_small_order_protocol_pin": hy(func(s *hySoll) {
		s.format, s.p2Version, s.codes = "ledger-protokollschluessel/1", 0, []string{"signature"}
	}),
	"ed25519_small_order_list_root": {status: "no_protocol_key", codes: []string{"no_protocol_key"}},
}

// hyLauf runs a vector with its audit environment; extra replaces the
// switches the environment gives.
func hyLauf(t *testing.T, name string, edit func(args []string) []string) (int, string, string) {
	t.Helper()
	dir := vektor("")
	env, err := os.ReadFile(filepath.Join(dir, "pruefer_"+name+".json"))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	args, err := vfy.AuditEnvironmentArgs(env, dir)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if edit != nil {
		args = edit(args)
	}
	return lauf(append(append([]string{"--json", "--now-from-package"}, args...), vektor(name))...)
}

func TestKorpusHybrid(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(vektor(""), "..", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		Testvectors map[string]json.RawMessage `json:"testvectors"`
	}
	if err := json.Unmarshal(b, &reg); err != nil {
		t.Fatal(err)
	}
	var group map[string]struct {
		Auditor struct {
			Exit int `json:"exit_code"`
		} `json:"auditor_inputs"`
	}
	if err := json.Unmarshal(reg.Testvectors["hybrid"], &group); err != nil {
		t.Fatal(err)
	}
	if len(group) == 0 {
		t.Fatal("registry testvectors has no group hybrid")
	}
	for name, e := range group {
		s, ok := hySollwerte[name]
		if !ok {
			if e.Auditor.Exit != 3 {
				t.Errorf("%s: no row in the table", name)
			}
			continue
		}
		_, out, errOut := hyLauf(t, name, nil)
		if out == "" {
			t.Errorf("%s: no report (%s)", name, strings.TrimSpace(errOut))
			continue
		}
		pruefeHybrid(t, name, s, out)
	}
}

func pruefeHybrid(t *testing.T, name string, s hySoll, out string) {
	t.Helper()
	var r struct {
		Findings []struct {
			Class  string `json:"class"`
			Detail string `json:"detail"`
		} `json:"findings"`
		Stats struct {
			VendorLog *vfy.VendorLogStat `json:"vendor_log"`
		} `json:"stats"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	vl := r.Stats.VendorLog
	if vl == nil {
		t.Fatalf("%s: no vendor_log", name)
	}
	errorf := func(what string, got, want any) {
		t.Helper()
		t.Errorf("%s: %s = %v, want %v", name, what, got, want)
	}
	if vl.Status != s.status {
		errorf("status", vl.Status, s.status)
	}
	if s.status == "checked" {
		kl := vl.KeyList
		h := ""
		if kl != nil && kl.HybridFrom != nil {
			h = *kl.HybridFrom
		}
		var p2 int64
		if kl != nil && kl.MLDSAListVersion != nil {
			p2 = *kl.MLDSAListVersion
		}
		switch {
		case kl == nil:
			errorf("key_list", nil, "an object")
		case kl.Format != s.format:
			errorf("key_list.format", kl.Format, s.format)
		case h != s.h:
			errorf("key_list.hybrid_from", h, s.h)
		case p2 != s.p2Version:
			errorf("key_list.ml_dsa_list_version", p2, s.p2Version)
		case kl.UnknownAlg != s.unknownAlg:
			errorf("key_list.unknown_alg", kl.UnknownAlg, s.unknownAlg)
		case p2 > 0 && (kl.MLDSAKeys != 2 || kl.LogURI == nil || *kl.LogURI != "tag:download.example,2025:ledger-testprotokoll-1"):
			errorf("key_list.ml_dsa_keys/log_uri", kl, "2 keys, the log_uri of the test log")
		case p2 == 0 && (kl.MLDSAKeys != 0 || kl.LogURI != nil):
			errorf("key_list without P2", kl, "0 keys, log_uri null")
		}
		if rc := vl.Receipts; rc == nil || [4]int{rc.Included, rc.Unchecked, rc.Missing, rc.Pending} != s.receipts {
			errorf("receipts (included, unchecked, missing, pending)", rc, s.receipts)
		}
	}
	if got := [2]int{vl.Days.HybridRequired, vl.Days.HybridIncomplete}; got != s.hybrid {
		errorf("days (hybrid_required, hybrid_incomplete)", got, s.hybrid)
	}
	sl := vl.Seals
	if got := [4]int{sl.MLDSA.Carried, sl.MLDSA.Defective, sl.MLDSA.KeyNotEstablished, sl.NotChecked}; got != s.seals {
		errorf("seals (carried, defective, key_not_established, not_checked)", got, s.seals)
	}
	if vl.CoseNotChecked != s.cose {
		errorf("cose_not_checked", vl.CoseNotChecked, s.cose)
	}
	var codes []string
	for _, f := range r.Findings {
		for _, m := range reCode.FindAllStringSubmatch(f.Detail, -1) {
			codes = append(codes, m[1])
		}
	}
	if strings.Join(codes, " ") != strings.Join(s.codes, " ") {
		errorf("codes of the findings", codes, s.codes)
	}
}

// ---------------------------------------------------------------- readings

// mitDatei writes b to a file in dir and returns its path.
func mitDatei(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// ersetzeLog replaces the file after --vendor-log by p (the environment of
// the vectors used here names one extract).
func ersetzeLog(p string) func(args []string) []string {
	return func(args []string) []string {
		out := append([]string{}, args...)
		for i := range out {
			if out[i] == "--vendor-log" {
				out[i+1] = p
			}
		}
		return out
	}
}

// liste2Neu returns the list /2 of the extract of log2_hybrid_included
// changed by f and signed again with the published seed of testwurzel-1.
func liste2Neu(t *testing.T, f func(m map[string]any)) (extract map[string]any, list map[string]any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vektor(""), "pruefer_log2_hybrid_included.vendor_log-1.json"))
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.UseNumber()
	var raw any
	if err := d.Decode(&raw); err != nil {
		t.Fatal(err)
	}
	extract = schlicht(raw).(map[string]any)
	list = extract["protocol_keys"].(map[string]any)
	delete(list, "signatur")
	f(list)
	seed := sha256.Sum256([]byte("REKORDER-TESTVECTOR-KEY:vendor-root-1"))
	signed, err := jcs.CanonGo(list)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed[:]), signed)
	list["signatur"] = map[string]any{"wurzel_id": "testwurzel-1", "sig": hex.EncodeToString(sig)}
	return extract, list
}

// schlicht turns the numbers of a decoded JSON value into int64, the form
// jcs.CanonGo takes.
func schlicht(v any) any {
	switch x := v.(type) {
	case json.Number:
		n, err := x.Int64()
		if err != nil {
			panic(err)
		}
		return n
	case map[string]any:
		for k, e := range x {
			x[k] = schlicht(e)
		}
	case []any:
		for i, e := range x {
			x[i] = schlicht(e)
		}
	}
	return v
}

func kanon(t *testing.T, v any) []byte {
	t.Helper()
	b, err := jcs.CanonGo(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var reGrund = regexp.MustCompile(`reason ([a-z_]+)`)

// TestListe2Lesarten holds readings of format spec 7.4.7a, 7.4.8 and
// 7.4.10 L1 that no vector of the corpus records (spec/testvectors README
// 16.3), on the package and the extract of log2_hybrid_included.
func TestListe2Lesarten(t *testing.T) {
	tmp := t.TempDir()
	keinSchluessel := func(t *testing.T, out, why string) {
		t.Helper()
		var r struct {
			Findings []struct{ Class, Detail string } `json:"findings"`
			Stats    struct {
				VendorLog vfy.VendorLogStat `json:"vendor_log"`
			} `json:"stats"`
		}
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatal(err)
		}
		if r.Stats.VendorLog.Status != "no_protocol_key" {
			t.Fatalf("status %s, want no_protocol_key", r.Stats.VendorLog.Status)
		}
		for _, f := range r.Findings {
			if m := reGrund.FindStringSubmatch(f.Detail); m != nil && f.Class == "VENDOR_LOG_UNVERIFIED" {
				if m[1] != why {
					t.Fatalf("reason %s, want %s", m[1], why)
				}
				return
			}
		}
		t.Fatalf("no VENDOR_LOG_UNVERIFIED with a reason: %+v", r.Findings)
	}

	t.Run("7.4.8: a list /2 in an extract /1 is ineffective and no candidate", func(t *testing.T) {
		x, l := liste2Neu(t, func(m map[string]any) {})
		x["format"] = "ledger-protokollauszug/1"
		delete(x, "cose_receipts")
		for _, d := range x["days"].([]any) {
			delete(d.(map[string]any), "seals")
			delete(d.(map[string]any), "day_receipts")
		}
		x["protocol_keys"] = l
		code, out, errOut := hyLauf(t, "log2_hybrid_included", ersetzeLog(mitDatei(t, tmp, "x1.json", kanon(t, x))))
		if code != 1 || out == "" {
			t.Fatalf("exit %d (%s)", code, errOut)
		}
		keinSchluessel(t, out, "format_violated")
	})
	t.Run("7.4.7a: hybrid_ab before erster_tag makes the list ineffective", func(t *testing.T) {
		x, _ := liste2Neu(t, func(m map[string]any) { m["hybrid_ab"] = "2025-12-30" })
		_, out, _ := hyLauf(t, "log2_hybrid_included", ersetzeLog(mitDatei(t, tmp, "x2.json", kanon(t, x))))
		keinSchluessel(t, out, "format_violated")
	})
	t.Run("7.4.7a: hybrid_ab not null without a key ml-dsa-87", func(t *testing.T) {
		x, _ := liste2Neu(t, func(m map[string]any) {
			m["schluessel"] = m["schluessel"].([]any)[:2]
		})
		_, out, _ := hyLauf(t, "log2_hybrid_included", ersetzeLog(mitDatei(t, tmp, "x3.json", kanon(t, x))))
		keinSchluessel(t, out, "format_violated")
	})
	t.Run("7.4.7a: no key with alg ed25519", func(t *testing.T) {
		x, _ := liste2Neu(t, func(m map[string]any) {
			m["schluessel"] = m["schluessel"].([]any)[2:]
		})
		_, out, _ := hyLauf(t, "log2_hybrid_included", ersetzeLog(mitDatei(t, tmp, "x4.json", kanon(t, x))))
		keinSchluessel(t, out, "format_violated")
	})
	t.Run("7.4.7a: the list re-signed unchanged counts", func(t *testing.T) {
		x, _ := liste2Neu(t, func(m map[string]any) {})
		code, out, errOut := hyLauf(t, "log2_hybrid_included", ersetzeLog(mitDatei(t, tmp, "x5.json", kanon(t, x))))
		if code != 0 || !strings.Contains(out, `"status": "checked"`) {
			t.Fatalf("exit %d (%s)", code, errOut)
		}
	})
	t.Run("7.4.10 L1 item 6: a pin with the key_id of a key ml-dsa-87 of P2 is dropped", func(t *testing.T) {
		pin := "vendor-log-mldsa-test-001=" + strings.Repeat("ab", 32)
		code, out, errOut := hyLauf(t, "log2_hybrid_included", func(args []string) []string {
			return append(args, "--vendor-log-key", pin)
		})
		if code != 0 || out == "" {
			t.Fatalf("exit %d (%s)", code, errOut)
		}
		var r struct {
			Stats struct {
				KeyRoles  vfy.KeyRolesStat  `json:"key_roles"`
				VendorLog vfy.VendorLogStat `json:"vendor_log"`
			} `json:"stats"`
		}
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatal(err)
		}
		kr := r.Stats.KeyRoles
		want := vfy.PinDropped{KeyID: "vendor-log-mldsa-test-001", PinnedAs: "protocol", ListedAs: "protocol"}
		if len(kr.PinsDropped) != 1 || kr.PinsDropped[0] != want || len(kr.Notes) != 1 || kr.Notes[0] != "pin_dropped" {
			t.Fatalf("key_roles %+v, want the pin dropped with the note pin_dropped", kr)
		}
		if ks := r.Stats.VendorLog.KeySource; ks == nil || *ks != "list" {
			t.Fatalf("key_source %v, want list", ks)
		}
	})
}
