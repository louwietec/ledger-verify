package vfy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pruefAnker reads the audit environment the frozen expectations hold for
// (spec/testvectors/pruefer_*, spec 7.1): the test vendor's root and the
// pinned test key. Every harness that compares against expected/ runs with
// exactly these anchors — without them a receipt is RECEIPT_UNVERIFIED by
// design, and the corpus would say nothing about the other checks.
func pruefAnker(t *testing.T) ([]VendorRoot, []VendorKey) {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "spec", "testvectors")
	wb, err := os.ReadFile(filepath.Join(dir, "pruefer_herstellerwurzel.json"))
	if err != nil {
		t.Fatalf("audit environment missing: %v", err)
	}
	w, err := ParseVendorRoot(wb)
	if err != nil {
		t.Fatalf("pruefer_herstellerwurzel.json: %v", err)
	}
	kb, err := os.ReadFile(filepath.Join(dir, "pruefer_herstellerschluessel.txt"))
	if err != nil {
		t.Fatalf("audit environment missing: %v", err)
	}
	var keys []VendorKey
	for _, z := range strings.Split(strings.TrimSpace(string(kb)), "\n") {
		k, err := ParseVendorKey(strings.TrimSpace(z))
		if err != nil {
			t.Fatalf("pruefer_herstellerschluessel.txt: %v", err)
		}
		keys = append(keys, k)
	}
	return []VendorRoot{w}, keys
}

// mitPruefAnker adds the audit environment to opt.
func mitPruefAnker(t *testing.T, opt Options) Options {
	t.Helper()
	opt.VendorRoots, opt.VendorKeys = pruefAnker(t)
	return opt
}
