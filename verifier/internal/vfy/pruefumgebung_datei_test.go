package vfy

// The audit environment of a test vector, ledger-pruefumgebung/1 (format
// spec 10.8): its members in their order become switches.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditEnvironmentArgs(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "spec", "testvectors")
	pin := "k-1=" + strings.Repeat("a", 64)
	full := `{"format":"ledger-pruefumgebung/1","korpus":true,"vendor_root":["pruefer_x.vendor_root-1.json"],` +
		`"vendor_key":["` + pin + `"],"vendor_key_list":["pruefer_x.vendor_key_list-1.json"],"vendor_log_key":["` + pin + `"],` +
		`"vendor_statement_key":["` + pin + `"],"tsa_root":["pruefer_x.tsa_root-1.pem"],"tsa_qualified_roots":"pruefer_x.tsa_qualified_roots-1.json",` +
		`"vendor_log_tsa_root":["pruefer_x.vendor_log_tsa_root-1.pem"],"expect_root":["28:` + strings.Repeat("A", 64) + `"],` +
		`"vendor_log":["pruefer_x.vendor_log-1.json"],"anchor_history":["pruefer_x.anchor_history-1.json"],"requested_at":"2026-01-01T00:00:00.5Z"}`
	args, err := AuditEnvironmentArgs([]byte(full), dir)
	if err != nil {
		t.Fatal(err)
	}
	var flags []string
	for i := 0; i < len(args); i += 2 {
		flags = append(flags, args[i])
	}
	pins, err := os.ReadFile(filepath.Join(dir, "pruefer_herstellerschluessel.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	want = append(want, "--vendor-root")
	for range strings.Fields(string(pins)) {
		want = append(want, "--vendor-key")
	}
	want = append(want, "--vendor-root", "--vendor-key", "--vendor-key-list", "--vendor-log-key", "--vendor-statement-key", "--tsa-root",
		"--tsa-qualified-roots", "--vendor-log-tsa-root", "--expect-root", "--vendor-log", "--anchor-history", "--requested-at")
	if strings.Join(flags, " ") != strings.Join(want, " ") {
		t.Errorf("switches %v\nwant %v", flags, want)
	}
	if args[len(args)-1] != "2026-01-01T00:00:00.5Z" || !strings.HasSuffix(args[1], "pruefer_herstellerwurzel.json") {
		t.Errorf("values %v", args)
	}
	empty := `{"format":"ledger-pruefumgebung/1","korpus":false,"vendor_root":[],"vendor_key":[],"vendor_key_list":[],"vendor_log_key":[],` +
		`"vendor_statement_key":[],"tsa_root":[],"tsa_qualified_roots":null,"vendor_log_tsa_root":[],"expect_root":[],"vendor_log":[],"anchor_history":[],"requested_at":null}`
	if args, err := AuditEnvironmentArgs([]byte(empty), dir); err != nil || len(args) != 0 {
		t.Errorf("empty environment: %v %v", args, err)
	}
	for why, s := range map[string]string{
		"a missing member":           strings.Replace(empty, `,"requested_at":null`, "", 1),
		"another member":             strings.Replace(empty, `"korpus":false`, `"korpus":false,"now":"x"`, 1),
		"another format":             strings.Replace(empty, "pruefumgebung/1", "pruefumgebung/2", 1),
		"korpus not a bool":          strings.Replace(empty, `"korpus":false`, `"korpus":0`, 1),
		"a file of another member":   strings.Replace(empty, `"tsa_root":[]`, `"tsa_root":["pruefer_x.vendor_log-1.json"]`, 1),
		"a file outside the corpus":  strings.Replace(empty, `"tsa_root":[]`, `"tsa_root":["../x.pem"]`, 1),
		"a pin against its grammar":  strings.Replace(empty, `"vendor_key":[]`, `"vendor_key":["k"]`, 1),
		"requested_at not rfc3339":   strings.Replace(empty, `"requested_at":null`, `"requested_at":"2026-01-01"`, 1),
		"tsa_qualified_roots a list": strings.Replace(empty, `"tsa_qualified_roots":null`, `"tsa_qualified_roots":[]`, 1),
		"an expected root with 0:":   strings.Replace(empty, `"expect_root":[]`, `"expect_root":["0:`+strings.Repeat("a", 64)+`"]`, 1),
	} {
		if _, err := AuditEnvironmentArgs([]byte(s), dir); err == nil {
			t.Errorf("%s: accepted", why)
		}
	}
}
