package vfy

// C6.5: a directory of the verification package that cannot be read must never
// disappear silently from the verification scope. These tests pin the loud
// behaviour: opening such a package fails, and Verify reports FORMAT_ERROR
// (exit 3) instead of "valid, no findings" (exit 0).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// unwalkableDir creates a subdirectory of parent that filepath.WalkDir cannot
// read, and returns its name relative to parent.
//
// The realistic case is a directory without read permission. That does not bite
// when the test runs as root (CAP_DAC_READ_SEARCH bypasses the mode bits), so we
// check whether the permission really took hold and otherwise fall back to a
// nesting whose absolute path exceeds PATH_MAX — unreadable for every user,
// root included.
func unwalkableDir(t *testing.T, parent string) string {
	t.Helper()
	const name = "unreadable"
	dir := filepath.Join(parent, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hidden.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	// Always restore the mode: otherwise the t.TempDir cleanup cannot remove it.
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if _, err := os.ReadDir(dir); err != nil {
		return name
	}
	// Running privileged: the mode bits did not block anything. Use path length.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	nestBeyondPathMax(t, dir)
	return name
}

// nestBeyondPathMax creates a chain of directories below base whose absolute
// path grows past PATH_MAX. The directories are created through relative names
// after chdir, so creating them stays legal while walking them from the outside
// fails with ENAMETOOLONG.
// t.Chdir, nicht os.Chdir: das Arbeitsverzeichnis ist prozessweit, und ein
// von Hand zurueckgesetztes bleibt bei einem Fatal im Nest stehen. t.Chdir
// raeumt selbst auf und markiert den Test zugleich als nicht parallelisierbar
// — heute ruft kein Test in diesem Paket t.Parallel(), aber der naechste soll
// nicht in diese Falle laufen. / t.Chdir instead of os.Chdir: the working
// directory is process-wide, a hand-rolled restore is skipped on a Fatal inside
// the nest, and t.Chdir additionally marks the test as not parallelisable.
func nestBeyondPathMax(t *testing.T, base string) {
	t.Helper()
	t.Chdir(base)
	seg := strings.Repeat("d", 200)
	for i := 0; i < 40; i++ {
		if err := os.Mkdir(seg, 0o755); err != nil {
			t.Fatalf("nesting level %d: %v", i, err)
		}
		t.Chdir(seg)
	}
}

func TestUnreadableSubdirectoryIsNotSilentlySkipped(t *testing.T) {
	g := validChain(t)
	dir := g.writePkg()
	blocked := unwalkableDir(t, dir)

	res := Verify(dir, genAnker(Options{Now: g.now.Add(time.Hour)}))

	if res.ExitCode == 0 {
		t.Errorf("package with an unreadable %s/ directory verified as exit 0 — the unread part vanished from the scope", blocked)
	}
	if res.Valid {
		t.Error("package with an unreadable directory reported as valid")
	}
	wantClasses(t, res, 3, ClsFormatError)
	joined := ""
	for _, f := range res.Findings {
		joined += f.Detail + "\n"
	}
	if !strings.Contains(joined, blocked) {
		t.Errorf("the finding does not name the unreadable directory %q; details were:\n%s", blocked, joined)
	}
}

// Guard for the indexing rewrite: an ordinary package must still list every
// nested file below a prefix, and reading it must keep working.
func TestDirListingCoversNestedFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "content", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"manifest.json", "content/4.request", "content/sub/deep.txt"} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(rel)), []byte(rel), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fsys, err := openPackage(root)
	if err != nil {
		t.Fatalf("openPackage: %v", err)
	}
	got := strings.Join(fsys.List("content"), ",")
	if got != "content/4.request,content/sub/deep.txt" {
		t.Errorf("List(content) = %q", got)
	}
	if got := strings.Join(fsys.List(""), ","); got != "content/4.request,content/sub/deep.txt,manifest.json" {
		t.Errorf(`List("") = %q`, got)
	}
	if !fsys.Exists("manifest.json") || fsys.Exists("content") {
		t.Error("Exists must report files, not directories")
	}
	b, err := fsys.ReadFile("content/sub/deep.txt")
	if err != nil || string(b) != "content/sub/deep.txt" {
		t.Errorf("ReadFile = %q, %v", b, err)
	}
}
