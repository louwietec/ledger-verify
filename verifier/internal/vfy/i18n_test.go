package vfy

import (
	"fmt"
	"strings"
	"testing"
)

// Both tables must carry identical key sets.
func TestI18nTablesComplete(t *testing.T) {
	if m := missingKeys(tableEN, tableDE); len(m) > 0 {
		t.Errorf("keys in EN but missing in DE: %v", m)
	}
	if m := missingKeys(tableDE, tableEN); len(m) > 0 {
		t.Errorf("keys in DE but missing in EN: %v", m)
	}
	// every finding class must have a description in both tables
	for cls := range classExit {
		for _, tbl := range []i18nTable{tableEN, tableDE} {
			if _, ok := tbl["class."+cls]; !ok {
				t.Errorf("missing i18n key class.%s", cls)
			}
		}
	}
	// every exit code the precedence can yield must have its result text in
	// both tables — exit 4 (spec 1.6) would otherwise print a MISSING marker
	// on the result line
	for _, c := range exitPrecedence {
		for _, tbl := range []i18nTable{tableEN, tableDE} {
			if _, ok := tbl[fmt.Sprintf("exit.%d", c)]; !ok {
				t.Errorf("missing i18n key exit.%d", c)
			}
		}
	}
}

// Proof by deliberate deletion: removing a key must (a) render a visible
// MISSING marker and (b) turn the completeness check red.
func TestI18nDeletedKeyDetected(t *testing.T) {
	mutilated := i18nTable{}
	for k, v := range tableDE {
		mutilated[k] = v
	}
	delete(mutilated, "report.title")

	got := mutilated.get("report.title")
	if !strings.Contains(got, "MISSING:report.title") {
		t.Errorf("deleted key did not render a MISSING marker, got %q", got)
	}
	if m := missingKeys(tableEN, mutilated); len(m) != 1 || m[0] != "report.title" {
		t.Errorf("completeness check did not flag the deleted key, got %v", m)
	}
}
