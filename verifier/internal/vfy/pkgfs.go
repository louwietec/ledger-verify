package vfy

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// pkgFS abstracts a verification package: a directory or a ZIP archive.
// All names use forward slashes relative to the package root.
type pkgFS interface {
	// ReadFile returns the content of the named file.
	ReadFile(name string) ([]byte, error)
	// List returns all file names under the given prefix (recursive).
	List(prefix string) []string
	// Exists reports whether the named file exists.
	Exists(name string) bool
}

// openPackage opens a package path as directory or ZIP.
func openPackage(p string) (pkgFS, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return openDir(p)
	}
	return openZip(p)
}

type dirFS struct {
	root string
	// names holds every file of the package, relative to root, slash-separated
	// and sorted. It is built once in openDir so that a directory that cannot
	// be read is an error of opening the package, not an invisible hole in a
	// later List.
	names []string
	// index is names as a set. ReadFile and Exists answer ONLY for a name in
	// it: a name the package material spells (a manifest's segment file, a
	// salt file) can never reach a file the index did not see — not one
	// outside the package via "..", not one behind a symbolic link.
	index map[string]bool
}

// openDir indexes the whole package tree up front and fails if any part of it
// cannot be read.
//
// Before, List() walked lazily and dropped every error handed to it by
// filepath.Walk. An unreadable subdirectory therefore vanished from the
// verification scope without a word, and the verifier still reported exit 0 —
// "valid, no findings" — over a package it had only partly seen. For a tool
// whose whole purpose is to be held against the vendor, a silently incomplete
// scope is the worst possible failure.
//
// The error is deliberately raised at open time, so Verify turns it into
// FORMAT_ERROR / exit 3. Exit 3 is the honest code here: exit 2 would assert
// that the chain is broken and exit 1 that the package is valid — both are
// claims about content we could not read. Exit 3 says only what is true: this
// package could not be read as the format requires.
//
// Spec 10.1 (from edition 1.9) adds two rules for a package presented as a
// directory:
//   - a directory that contains exactly one directory and nothing else is a
//     wrapper and is stripped, as for a zipped directory — once, not
//     recursively (the ZIP rule strips one level too);
//   - a symbolic link anywhere inside the package is FORMAT_ERROR. WalkDir
//     does not follow links, so a link is seen as what it is, and nothing is
//     read through it. Before 1.9 a link was indexed like a file and
//     os.ReadFile followed it — a package could make the verifier read any
//     file of the auditor's machine. For the same reason every other entry
//     that is neither a directory nor a regular file (a named pipe, a device)
//     is refused: reading a FIFO would block the verifier for ever.
//
// The package root itself may be a link: it is the path the auditor typed,
// not package material.
func openDir(root string) (*dirFS, error) {
	// The root is the auditor's own path; filepath.WalkDir does not descend
	// into a root that is a link, so it is resolved first.
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	if root, err = stripDirWrapper(root); err != nil {
		return nil, err
	}
	d := &dirFS{root: root, index: map[string]bool{}}
	err = filepath.WalkDir(root, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("cannot read %s: %w", relForMsg(root, p), err)
		}
		if p == root {
			return nil // the root is the auditor's path (links allowed)
		}
		switch t := de.Type(); {
		case t&fs.ModeSymlink != 0:
			return fmt.Errorf("%s is a symbolic link; a package presented as a directory must not contain one (spec 10.1)", relForMsg(root, p))
		case de.IsDir():
			return nil
		case !t.IsRegular():
			return fmt.Errorf("%s is neither a regular file nor a directory (spec 10.1)", relForMsg(root, p))
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return fmt.Errorf("cannot read %s: %w", relForMsg(root, p), err)
		}
		n := filepath.ToSlash(rel)
		d.names = append(d.names, n)
		d.index[n] = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(d.names)
	return d, nil
}

// stripDirWrapper returns the directory to read as the package: root itself,
// or — when root contains exactly one entry and that entry is a directory
// (not a link to one) — that single directory (spec 10.1, from 1.9). A root
// that holds exactly one directory and nothing else cannot carry
// manifest.json at the top, so the condition of the ZIP rule ("manifest.json
// not at the top level") is implied.
func stripDirWrapper(root string) (string, error) {
	des, err := os.ReadDir(root)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", filepath.ToSlash(root), err)
	}
	if len(des) == 1 && des[0].IsDir() && des[0].Type()&fs.ModeSymlink == 0 {
		return filepath.Join(root, des[0].Name()), nil
	}
	return root, nil
}

// relForMsg names a path the way the package sees it, so the message points at
// the package member and not at the operator's directory layout.
//
// Mit einer Ausnahme, und die ist Absicht: ist die PAKETWURZEL selbst unlesbar,
// waere der paketrelative Name "." und wuerde dem Betreiber nichts sagen. Dann
// nennt die Meldung den vollen Pfad — derselbe Grund gilt, wenn filepath.Rel
// scheitert. / One deliberate exception: if the PACKAGE ROOT itself cannot be
// read, the package-relative name would be "." and tell the operator nothing,
// so the message names the full path instead; likewise when filepath.Rel fails.
func relForMsg(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == "." {
		return filepath.ToSlash(p)
	}
	return filepath.ToSlash(rel)
}

// ReadFile reads a file the index holds, and nothing else (see index). The
// Lstat right before the read keeps a file that was swapped for a link after
// indexing from being followed.
func (d *dirFS) ReadFile(name string) ([]byte, error) {
	if !d.index[name] {
		return nil, os.ErrNotExist
	}
	p := filepath.Join(d.root, filepath.FromSlash(name))
	st, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is no longer a regular file", name)
	}
	return os.ReadFile(p)
}

func (d *dirFS) Exists(name string) bool {
	return d.index[name]
}

func (d *dirFS) List(prefix string) []string {
	var out []string
	for _, n := range d.names {
		if prefix == "" || strings.HasPrefix(n, prefix+"/") {
			out = append(out, n)
		}
	}
	return out
}

type zipFS struct {
	files map[string]*zip.File
	// rc haelt die geoeffnete Datei am Leben, solange der zipFS lebt:
	// zip.File.Open() liest verzoegert. Bei einem Paket aus dem Speicher
	// (openZipBytes) ist das Feld nil — dort haelt der Byte-Slice die Daten.
	rc *zip.ReadCloser
}

func openZip(p string) (*zipFS, error) {
	rc, err := zip.OpenReader(p)
	if err != nil {
		return nil, fmt.Errorf("not a directory and not a readable ZIP: %v", err)
	}
	z, err := indexZip(&rc.Reader)
	if err != nil {
		rc.Close()
		return nil, err
	}
	z.rc = rc
	return z, nil
}

// openZipBytes oeffnet ein Pruefpaket, das als ZIP im SPEICHER liegt statt auf
// einer Platte.
//
// WARUM: der freie Verifier ist der Verbreitungsmotor des Produkts — "jeder
// Dritte kann selbst pruefen". Bis zum 15.09. hiess das in der Praxis:
// Hersteller-Binaer herunterladen, Pruefsumme vergleichen, chmod +x, CLI
// bedienen. Fuer die Menschen, die wirklich pruefen, ist das eine Mauer, und
// auf vielen Firmenrechnern ist eine fremde unsignierte Binaerdatei schlicht
// verboten. Mit diesem Einstieg laeuft derselbe Verifier als WebAssembly im
// Browser: das Paket wird lokal geoeffnet, nichts wird hochgeladen, nichts
// installiert. Es ist DIESELBE Quelle — keine dritte Implementierung, die
// auseinanderlaufen koennte, und die Aequivalenz ueber alle eingefrorenen
// Vektoren wird gemessen (artefakte/P03/wasm_aequivalenz.log).
// / Opens a verification package that lives in memory, so the very same
// verifier can run as WebAssembly in a browser: nothing uploaded, nothing
// installed, and no third implementation to drift.
func openZipBytes(data []byte) (*zipFS, error) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("not a readable ZIP: %v", err)
	}
	return indexZip(r)
}

// indexZip baut die Namenstabelle beider Wege — aus der Datei und aus dem
// Speicher. Eine zweite Kopie dieser Schleife waere genau die Handkopie, gegen
// die dieses Repo check_typlisten gebaut hat.
func indexZip(r *zip.Reader) (*zipFS, error) {
	z := &zipFS{files: map[string]*zip.File{}}
	// Spec 10.1: entry names in normal form, no duplicates — otherwise two
	// verifiers can see different files in the same archive. Until 25.09.
	// this verifier cleaned names (path.Clean) and dropped anything with
	// "..", while verifier2 took them raw: a ZIP carrying both
	// "manifest.json" and "./manifest.json" got exit 3 here and exit 0 there.
	var names []string
	seen := map[string]bool{}
	for _, f := range r.File {
		if strings.HasSuffix(f.Name, "/") {
			continue // directory entry
		}
		if why := zipNameFault(f.Name); why != "" {
			return nil, fmt.Errorf("ZIP entry %q is not in normal form: %s (spec 10.1)", f.Name, why)
		}
		if seen[f.Name] {
			return nil, fmt.Errorf("ZIP entry %q occurs twice (spec 10.1)", f.Name)
		}
		seen[f.Name] = true
		names = append(names, f.Name)
	}
	// Tolerate a single top-level wrapper directory (zip of a folder).
	strip := commonTopDir(names)
	for _, f := range r.File {
		if strings.HasSuffix(f.Name, "/") {
			continue
		}
		n := f.Name
		if strip != "" {
			n = strings.TrimPrefix(n, strip+"/")
		}
		z.files[n] = f
	}
	return z, nil
}

// zipNameFault says why a ZIP entry name is not in the normal form of spec
// 10.1, or "" if it is.
func zipNameFault(n string) string {
	switch {
	case n == "":
		return "empty name"
	case strings.HasPrefix(n, "/"):
		return "leading /"
	case strings.Contains(n, "\\"):
		return "backslash"
	}
	for _, teil := range strings.Split(n, "/") {
		switch teil {
		case "":
			return "empty path part"
		case ".", "..":
			return "path part " + teil
		}
	}
	return ""
}

// commonTopDir returns the single shared top-level directory of all names,
// or "" if there is none (e.g. manifest.json at root).
func commonTopDir(names []string) string {
	top := ""
	for _, n := range names {
		i := strings.IndexByte(n, '/')
		if i < 0 {
			return ""
		}
		d := n[:i]
		if top == "" {
			top = d
		} else if top != d {
			return ""
		}
	}
	// Only strip when the root itself has no manifest.json.
	for _, n := range names {
		if n == "manifest.json" {
			return ""
		}
	}
	return top
}

func (z *zipFS) ReadFile(name string) ([]byte, error) {
	f, ok := z.files[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	r, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func (z *zipFS) Exists(name string) bool {
	_, ok := z.files[name]
	return ok
}

func (z *zipFS) List(prefix string) []string {
	var out []string
	for n := range z.files {
		if prefix == "" || strings.HasPrefix(n, prefix+"/") {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}
