// Package cli is the whole command line of the free, offline chain verifier
// ledger-verify. It implements ONLY the open specification in spec/
// (format.*.md, registry.json) and never imports anything from the appliance
// module.
//
// Two binaries call Main and nothing else: verifier/cmd/ledger-verify (the
// name of the product LEDGER) and verifier/cmd/rekorder-verify, the
// compatibility alias under the old product name. Because both are this one
// function, their output is byte-identical and always says ledger-verify /
// LEDGER — an auditor never meets the old name in a text, whichever binary an
// installation still calls.
//
// Usage:
//
//	ledger-verify [flags] <pruefpaket>     (directory or ZIP)
//
// Flags:
//
//	--json               machine-readable output {valid, exit_code, findings, stats}
//	--lang de|en         report language (default en)
//	--now RFC3339        verification time, UTC with Z in the grammar of spec
//	                     2/10.7 (e.g. 2026-01-01T12:00:00Z); anything else is
//	                     an unusable invocation (exit 3); default system time
//	--now-from-package   take the verification time from the package's own
//	                     verify_args.json (test vectors only: the file is
//	                     unsigned and written by the appliance under test);
//	                     absent or not conforming: FORMAT_ERROR, exit 3 (spec 10.8)
//	--expect-root ROOT | TREE_SIZE:ROOT
//	                     expected Merkle root (spec 7.2, 8.6, 10.8), repeatable:
//	                     a paper anchor, or the vendor's most recent root
//	                     countersigned BEFORE the package was requested. With
//	                     TREE_SIZE it must equal the root over exactly the first
//	                     TREE_SIZE entries; without, the root over some prefix.
//	                     Not found: MERKLE_INCONSISTENT; found: an anchor, and
//	                     completeness up to its tree_size is established.
//	--freshness DUR      freshness window (default 24h), e.g. 24h, 90m
//	--tsa-root FILE      PEM trust anchors for time witnesses (spec 7.3);
//	                     without it only the system root store counts as
//	                     independent of the package
//	--vendor-root FILE   the vendor's root key {"wurzel_id","pubkey"} (spec 7.1,
//	                     10.7); vouches for vendor keys through the signed list
//	                     keys/vendor/schluesselliste.json in the package.
//	                     Repeatable. A release build carries it compiled in.
//	--vendor-key ID=HEX  pin a single vendor countersigning key (spec 7.1).
//	                     Repeatable.
//	                     Without either, receipts are checked against the key
//	                     the package brings along and reported RECEIPT_UNVERIFIED.
//	--version            two lines: "ledger-verify <v> (spec X.Y) — LEDGER" and
//	                     the compiled-in vendor root (spec 7.1: a build that
//	                     carries one MUST name it in its version output)
//
// Exit codes (spec/registry.json -> verifier.exit_codes):
//
//	0 = valid, no findings (chain end sealed)
//	1 = valid with findings (chain end sealed)
//	2 = invalid
//	3 = format error (also: unusable invocation)
//	4 = incomplete: chain end not sealed (spec 8.6) — the entries present are
//	    intact, the package does not prove that nothing came after them
//
// The exit code follows the precedence 3 > 2 > 4 > 1 > 0 (spec 10.3,
// registry verifier.exit_precedence), not the numeric maximum.
//
// The JSON output (--json) is machine output and deliberately carries no
// product name: its shape is frozen by spec/schemas and the expected outputs
// in spec/testvectors/expected/.
package cli

import (
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/louwietec/ledger-verify/verifier/internal/vfy"
)

// Name is the verifier's name in every text it prints: version line, usage,
// every error prefix. The compatibility alias rekorder-verify prints it too.
const Name = "ledger-verify"

// Product is the name of the product whose verification packages this tool
// checks. Since the rename it is LEDGER (formerly "Rekorder").
const Product = "LEDGER"

// Version is the verifier's release version. A var, not a const, so that a
// release build can stamp it:
//
//	go build -ldflags "-X github.com/louwietec/ledger-verify/verifier/internal/cli.Version=1.2.0" ./cmd/ledger-verify
var Version = "1.0.0"

// SpecVersion ist die Spezifikationsversion, die dieser Verifier umsetzt —
// gespiegelt aus spec/registry.json und von .ci/check_typlisten.py dagegen
// gehalten. Der Verifier LIEST die Registry bewusst nicht zur Laufzeit: er ist
// ein eigenstaendiges Binaer, das ein Dritter ohne unser Repository benutzt.
//
// Seit dem 29.09. ist das 1.9 (Export-Siegel, Lizenz-Commitment, Zeitarithmetik
// in Millisekunden, Restfenster, Vollstaendigkeitshinweis; Ergaenzung 8.7 vom
// 02.10. ohne Pruefaenderung); davor 1.8 (Lizenz-Commitment in GENESIS), 1.7
// (Eintragstyp LEGAL_HOLD, Befund HOLD_VIOLATION, Spec 4.24/9.3), 1.6 (Kettenende versiegelt oder
// unvollstaendig, UNSEALED_END, Exit 4, Spec 8.6), 1.5 (CAPTURE_TRUNCATED),
// 1.4 (Herkunft des Herstellerschluessels), 1.3 (offenes Manifest) und seit dem
// Release vom 15.09. 1.2 (externer Zeitzeuge, Spec 7.3).
// Bis zum 15.09. stand "spec 1.0" zweimal fest im Text, waehrend der Verifier
// seit dem Release vom 14.09. 1.1 umsetzte (Vorwaertskompatibilitaet,
// CONTENT_DISCLOSED, Konsistenzbeweis). Ausgerechnet hier: der
// Prueferleitfaden laesst den Auditor `--version` als ERSTES ausfuehren, um
// dem Werkzeug zu trauen. Die erste Zeile, die ein Pruefer zu sehen bekommt,
// war also eine falsche Angabe darueber, welche Spezifikation das Werkzeug
// beherrscht. Die spec_version-Regel von check_typlisten hat es nicht
// gefunden, weil sie nach `const NAME = "..."` sucht und die Zahl hier in
// einem Formatstring stand — deshalb steht sie jetzt in einer Konstanten.
// Seit A4 (LEDGER) steht sie hier in verifier/internal/cli statt in
// cmd/rekorder-verify/main.go; beide Binaerdateien rufen diese eine Stelle.
// / The spec version this verifier implements, mirrored from the registry.
const SpecVersion = "1.9"

// VersionLine is the first line of --version, the line the auditor's guide
// has an auditor check first. "(spec X.Y)" stays in exactly this form:
// appliance tests and the WASM equivalence proof read it back.
func VersionLine() string {
	return fmt.Sprintf("%s %s (spec %s) — %s", Name, Version, SpecVersion, Product)
}

// Main runs the verifier with args (the arguments WITHOUT the program name,
// i.e. os.Args[1:]) and returns the exit code. The report goes to stdout,
// usage and every error message to stderr.
func Main(args []string, stdout, stderr io.Writer) int {
	fehler := func(format string, a ...any) int {
		fmt.Fprintf(stderr, Name+": "+format+"\n", a...)
		return 3
	}

	fs := flag.NewFlagSet(Name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	lang := fs.String("lang", "en", "report language: de or en")
	nowStr := fs.String("now", "", "verification time, UTC with Z (e.g. 2026-01-01T12:00:00Z, grammar of spec 2/10.7); default system time")
	nowPkg := fs.Bool("now-from-package", false, "take the verification time from the package's verify_args.json (frozen test vectors only — the file is unsigned and chosen by the prover); absent or not conforming: exit 3")
	var expectRoots vielfach
	fs.Var(&expectRoots, "expect-root", "expected Merkle root, ROOT (64 hex) or TREE_SIZE:ROOT (spec 10.8): a paper anchor or the vendor's most recent root countersigned before the package was requested; repeatable")
	freshness := fs.Duration("freshness", 24*time.Hour, "freshness window for TRAILING_SILENCE")
	tsaRoot := fs.String("tsa-root", "", "PEM file with trust anchors for time witnesses (spec 7.3); without it only the system root store counts as independent")
	var vendorRoots, vendorKeys vielfach
	fs.Var(&vendorRoots, "vendor-root", "file with the vendor's root key {\"wurzel_id\",\"pubkey\"} (spec 7.1, 10.7); repeatable")
	fs.Var(&vendorKeys, "vendor-key", "pin a vendor countersigning key as key_id=hex64 (spec 7.1); repeatable")
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "%s %s — %s offline verifier for %s verification packages (spec %s)\n", Name, Version, Product, Product, SpecVersion)
		fmt.Fprintf(stderr, "usage: %s [flags] <pruefpaket-dir-or-zip>\n", Name)
		fs.PrintDefaults()
		fmt.Fprintln(stderr, "exit codes: 0 valid / 1 valid with findings / 2 invalid / 3 format error / 4 incomplete: chain end not sealed")
		fmt.Fprintln(stderr, "precedence: 3 before 2 before 4 before 1 before 0 (spec 10.3)")
	}
	if err := fs.Parse(args); err != nil {
		return 3
	}
	builtin, hasBuiltin, err := vfy.Builtin()
	if err != nil {
		return fehler("%v", err)
	}
	if *showVersion {
		fmt.Fprintln(stdout, VersionLine())
		// Spec 7.1: a build that carries a vendor root MUST name it in its
		// version output — hence the second line, also when there is none.
		if hasBuiltin {
			fmt.Fprintf(stdout, "vendor root compiled in: %s %s\n", builtin.ID, builtin.Pubkey)
		} else {
			fmt.Fprintln(stdout, "vendor root compiled in: none (pass --vendor-root or --vendor-key)")
		}
		return 0
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 3
	}
	if *lang != "de" && *lang != "en" {
		return fehler("--lang must be de or en")
	}
	opt := vfy.Options{Freshness: *freshness}
	// Spec 10.8 (from 1.9): the auditor's inputs are read with the grammar of
	// the package; anything else is an unusable invocation, never a silent
	// interpretation. time.Parse(RFC3339Nano) took an offset, a comma before
	// the fraction and a one-digit hour — verifier2 took even a value without
	// a zone, in the host's time zone.
	if *nowStr != "" {
		t, err := vfy.ParseTime(*nowStr)
		if err != nil {
			return fehler("--now: %v", err)
		}
		opt.Now = t
	}
	opt.NowFromPackage = *nowPkg
	for _, s := range expectRoots {
		x, err := vfy.ParseExpectedRoot(s)
		if err != nil {
			return fehler("--expect-root must be 64 hex characters (ROOT) or TREE_SIZE:ROOT with TREE_SIZE a whole number from 1 (spec 10.8), got %q", s)
		}
		opt.ExpectRoots = append(opt.ExpectRoots, x)
	}
	if *tsaRoot != "" {
		// Read here and not in the verifier: the verifier gets bytes, never a
		// path. The browser build has no file system at all, and a package
		// must never be able to point the verifier at a file of its choosing.
		pemBytes, err := os.ReadFile(*tsaRoot)
		if err != nil {
			return fehler("--tsa-root: %v", err)
		}
		n := 0
		for rest := pemBytes; len(rest) > 0; {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				break
			}
			if blk.Type == "CERTIFICATE" {
				opt.TSARoots = append(opt.TSARoots, blk.Bytes)
				n++
			}
		}
		if n == 0 {
			return fehler("--tsa-root: no CERTIFICATE block in the file")
		}
	}
	if hasBuiltin {
		opt.VendorRoots = append(opt.VendorRoots, builtin)
	}
	for _, p := range vendorRoots {
		b, err := os.ReadFile(p)
		if err != nil {
			return fehler("--vendor-root: %v", err)
		}
		w, err := vfy.ParseVendorRoot(b)
		if err != nil {
			return fehler("--vendor-root %s: %v", p, err)
		}
		opt.VendorRoots = append(opt.VendorRoots, w)
	}
	for _, s := range vendorKeys {
		k, err := vfy.ParseVendorKey(s)
		if err != nil {
			return fehler("--vendor-key: %v", err)
		}
		opt.VendorKeys = append(opt.VendorKeys, k)
	}
	// Widerspruechliche Anker desselben Namens (auch gegen die eingebaute
	// Wurzel) sind ein Aufruffehler — nicht "der letzte gewinnt" (Spec 7.1).
	if opt.VendorRoots, opt.VendorKeys, err = vfy.AnkerZusammenfuehren(opt.VendorRoots, opt.VendorKeys); err != nil {
		return fehler("%v", err)
	}

	res := vfy.Verify(fs.Arg(0), opt)
	if *jsonOut {
		b, err := vfy.RenderJSON(res)
		if err != nil {
			return fehler("%v", err)
		}
		stdout.Write(b)
	} else {
		fmt.Fprint(stdout, vfy.RenderText(res, fs.Arg(0), *lang))
	}
	return res.ExitCode
}

// vielfach collects a repeatable flag.
type vielfach []string

func (v *vielfach) String() string     { return fmt.Sprint(*v) }
func (v *vielfach) Set(s string) error { *v = append(*v, s); return nil }
