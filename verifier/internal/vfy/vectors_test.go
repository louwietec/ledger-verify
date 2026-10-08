package vfy

// Matrix test: run the verifier against every spec test vector listed under
// spec/testvectors/expected/ and compare exit code and finding classes
// exactly. Vector packages that do not exist yet (they are produced in work
// package P02) are honestly counted as SKIP, never as green.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func repoRoot(t *testing.T) string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate source file")
	}
	// file = <repo>/verifier/internal/vfy/vectors_test.go
	return filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(file))))
}

type expected struct {
	ExitCode       int      `json:"exit_code"`
	FindingClasses []string `json:"finding_classes"`
}

func TestVectorMatrix(t *testing.T) {
	root := repoRoot(t)
	expDir := filepath.Join(root, "spec", "testvectors", "expected")
	entries, err := os.ReadDir(expDir)
	if err != nil {
		t.Fatalf("no expected/ directory — the frozen vector corpus belongs to the repository: %v", err)
	}

	var logLines []string
	logf := func(format string, args ...any) {
		logLines = append(logLines, fmt.Sprintf(format, args...))
	}
	logf("ledger-verify vector matrix — %s", time.Now().UTC().Format(time.RFC3339))
	logf("spec dir: %s", filepath.Join(root, "spec", "testvectors"))
	logf("")

	pass, fail, skip := 0, 0, 0
	for _, de := range entries {
		name := strings.TrimSuffix(de.Name(), ".json")
		if name == de.Name() {
			continue
		}
		vecDir := filepath.Join(root, "spec", "testvectors", name)
		if st, err := os.Stat(vecDir); err != nil || !st.IsDir() {
			skip++
			logf("SKIP %-24s vector package not present yet (produced in P02)", name)
			continue
		}
		expBytes, err := os.ReadFile(filepath.Join(expDir, de.Name()))
		if err != nil {
			fail++
			logf("FAIL %-24s cannot read expectation: %v", name, err)
			continue
		}
		var exp expected
		if err := json.Unmarshal(expBytes, &exp); err != nil {
			fail++
			logf("FAIL %-24s cannot parse expectation: %v", name, err)
			continue
		}
		// Frozen vectors carry their own check time in verify_args.json;
		// honouring it is an explicit opt-in, never the default.
		// The audit environment (spec 7.1) is part of the corpus: the
		// expectations hold for the test vendor's root and pinned key.
		res := Verify(vecDir, mitPruefAnker(t, Options{NowFromPackage: true}))
		got := sortedKeys(classSet(res))
		want := append([]string{}, exp.FindingClasses...)
		sort.Strings(want)
		if res.ExitCode == exp.ExitCode && fmt.Sprint(got) == fmt.Sprint(want) {
			pass++
			logf("PASS %-24s exit=%d classes=%v", name, res.ExitCode, got)
		} else {
			fail++
			logf("FAIL %-24s exit=%d (want %d) classes=%v (want %v)", name, res.ExitCode, exp.ExitCode, got, want)
			t.Errorf("vector %s: exit=%d (want %d), classes=%v (want %v)", name, res.ExitCode, exp.ExitCode, got, want)
		}
	}
	logf("")
	logf("summary: %d PASS, %d FAIL, %d SKIP", pass, fail, skip)

	// Nur im Monorepo, wo artefakte/P03 existiert, landet die Matrix auch als
	// Beleg dort; im oeffentlichen Verifier-Repository (ohne artefakte/) legt
	// der Test KEIN Verzeichnis ausserhalb seines Moduls an (Vorschlag A3-V1).
	// / Only where artefakte/P03 exists; never creates a directory outside
	// the module (public verifier repository).
	// Und nur mit BELEGE=1 (Entscheidung 02.10., .ci/belege_auffrischen.sh):
	// ein gewoehnliches "go test" schreibt keinen Beleg; die Matrix steht
	// trotzdem vollstaendig im Testlog. / And only with BELEGE=1.
	logDir := filepath.Join(root, "artefakte", "P03")
	if fi, err := os.Stat(logDir); err == nil && fi.IsDir() && os.Getenv("BELEGE") == "1" {
		_ = os.WriteFile(filepath.Join(logDir, "vektor_matrix.log"), []byte(strings.Join(logLines, "\n")+"\n"), 0o644)
	}
	t.Logf("\n%s", strings.Join(logLines, "\n"))
	if skip > 0 {
		t.Logf("NOTE: %d vectors skipped — packages not yet generated (P02)", skip)
	}
}
