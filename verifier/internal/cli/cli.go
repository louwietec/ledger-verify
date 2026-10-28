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
//	ledger-verify --version
//
// Every switch stands before the package and is written with two dashes;
// "--" ends the switches. A switch without a value (--json,
// --now-from-package) takes none ("--json=true" is refused), a switch with a
// value takes it as "--x v" or "--x=v". --version stands alone. A single
// dash (-json), a switch after the package, an unknown switch and every
// other form is an unusable invocation (exit 3, spec 10.8), and so is a
// request for help (-h, --help): it prints the usage on stderr. verifier2
// reads the same command lines alike (.ci/check_cli_gleich.py).
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
//	--freshness DUR      freshness window (default 24h): a whole number from 1
//	                     to 999999 without a leading zero, directly followed by
//	                     h, m or s, e.g. 24h, 90m (spec 10.8); at most once
//	--tsa-root FILE      roots for time witnesses of the chain (purpose chain,
//	                     spec 7.3, 7.5.7) in the strict PEM of spec 10.8, one or
//	                     more CERTIFICATE blocks; repeatable, every file counts.
//	                     The system root store counts for no purpose.
//	--tsa-qualified-roots FILE
//	                     roots named qualified, ledger-tsa-qualifiziert/1
//	                     (purposes chain and qualified, spec 10.8); at most once
//	--vendor-log-tsa-root FILE
//	                     roots for the time stamps of the vendor log (purpose
//	                     log, strict PEM); repeatable
//	--vendor-log FILE    an extract ledger-protokollauszug/1 of the vendor log
//	                     (spec 7.4.8), checked after spec 7.4.10 (report object
//	                     vendor_log; its findings have exit class 1); repeatable
//	--vendor-log-key ID=HEX
//	                     pin a protocol key of the vendor log; repeatable
//	--vendor-statement-key ID=HEX
//	                     pin a statements key (spec 8.8.3, 10.7.4); repeatable
//	--vendor-key-list FILE
//	                     a key list of the vendor: rekorder-herstellerschluessel/1,
//	                     ledger-schluesselrollen/1 or ledger-protokollschluessel/1
//	                     (spec 10.7, 7.4.7); repeatable
//	--anchor-history FILE
//	                     a page of the anchor history or ledger-ankerhistorie/2
//	                     (spec 8.8.2); repeatable
//	--requested-at RFC3339
//	                     when the auditor requested the package (spec 8.8.1); at
//	                     most once, never after the check time
//	--vendor-root FILE   the vendor's root key {"wurzel_id","pubkey"} (spec 7.1,
//	                     10.7); vouches for vendor keys through the signed list
//	                     keys/vendor/schluesselliste.json in the package.
//	                     Repeatable. A release build carries it compiled in.
//	--vendor-key ID=HEX  pin a single vendor countersigning key (spec 7.1).
//	                     Repeatable.
//	                     Without either, receipts are checked against the key
//	                     the package brings along and reported RECEIPT_UNVERIFIED.
//	--version            two lines: "ledger-verify <v> (spec X.Y) · LEDGER" and
//	                     the compiled-in vendor root (spec 7.1: a build that
//	                     carries one MUST name it in its version output); only
//	                     as the one argument
//
// Every input of the auditor is read at invocation, before the package is
// opened (spec 10.8): a violation of its grammar or limit, an input given
// more often than allowed and every other usage error is an unusable
// invocation, exit 3 with the reason on stderr and no report.
//
// A second mode judges one time stamp on its own, before a chain or a vendor
// log exists (not normative, zeitstempel.go):
//
//	ledger-verify zeitstempel --token FILE (--data FILE | --statement-jcs FILE)
//	              [--tsa-root FILE]... [--purpose chain|log] [--json] [--lang de|en]
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
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"louwietec.com/ledger-verify/verifier/internal/vfy"
)

// Name is the verifier's name in every text it prints: version line, usage,
// every error prefix. The compatibility alias rekorder-verify prints it too.
const Name = "ledger-verify"

// Product is the name of the product whose verification packages this tool
// checks. Since the rename it is LEDGER (formerly "Rekorder").
const Product = "LEDGER"

// Version is the verifier's release version. A var, not a const, so that a
// release build can stamp it (<module> is the module path, go list -m):
//
//	go build -ldflags "-X <module>/internal/cli.Version=1.2.0" ./cmd/ledger-verify
var Version = "1.1.0"

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
// 1.10 since 03.10.2026: covered stretches (spec 11.2).
const SpecVersion = "1.10"

// VersionLine is the first line of --version, the line the auditor's guide
// has an auditor check first. "(spec X.Y)" stays in exactly this form:
// appliance tests and the WASM equivalence proof read it back.
func VersionLine() string {
	return fmt.Sprintf("%s %s (spec %s) · %s", Name, Version, SpecVersion, Product)
}

// Main runs the verifier with args (the arguments WITHOUT the program name,
// i.e. os.Args[1:]) and returns the exit code. The report goes to stdout,
// usage and every error message to stderr.
func Main(args []string, stdout, stderr io.Writer) int {
	fehler := func(format string, a ...any) int {
		fmt.Fprintf(stderr, Name+": "+format+"\n", a...)
		return 3
	}
	if len(args) > 0 && args[0] == "zeitstempel" {
		return zeitstempel(args[1:], stdout, stderr)
	}
	// --version stands alone (spec 10.6: a tool queries it before it passes
	// inputs); with any other argument it is an unusable invocation below.
	if len(args) == 1 && args[0] == "--version" {
		builtin, hasBuiltin, err := vfy.Builtin()
		if err != nil {
			return fehler("%v", err)
		}
		v := VersionLine() + "\n"
		// Spec 7.1: a build that carries a vendor root MUST name it in its
		// version output, hence the second line, also when there is none.
		if hasBuiltin {
			v += fmt.Sprintf("vendor root compiled in: %s %s\n", builtin.ID, builtin.Pubkey)
		} else {
			v += "vendor root compiled in: none (pass --vendor-root or --vendor-key)\n"
		}
		if err := ausgeben(stdout, []byte(v)); err != nil {
			return fehler("%v", err)
		}
		return 0
	}

	fs := flag.NewFlagSet(Name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	lang := einmalFlag(fs, "lang", "report language: de or en (default en)")
	nowStr := einmalFlag(fs, "now", "verification time, UTC with Z (e.g. 2026-01-01T12:00:00Z, grammar of spec 2/10.7); default system time")
	nowPkg := fs.Bool("now-from-package", false, "take the verification time from the package's verify_args.json (frozen test vectors only; the file is unsigned and chosen by the prover); absent or not conforming: exit 3")
	var expectRoots vielfach
	fs.Var(&expectRoots, "expect-root", "expected Merkle root, ROOT (64 hex) or TREE_SIZE:ROOT (spec 10.8): a paper anchor or the vendor's most recent root countersigned before the package was requested; repeatable")
	freshStr := einmalFlag(fs, "freshness", "freshness window for TRAILING_SILENCE: 1 to 999999 directly followed by h, m or s (spec 8.5, 10.8; default 24h)")
	var tsaRoots, vendorRoots, vendorKeys, logTSARoots, vendorLogs, logKeys, statementKeys, keyLists, histories vielfach
	fs.Var(&tsaRoots, "tsa-root", "PEM file with roots for time witnesses of the chain (purpose chain, spec 7.3, 10.8); repeatable; the system root store counts for no purpose")
	qualified := einmalFlag(fs, "tsa-qualified-roots", "file ledger-tsa-qualifiziert/1 with roots named qualified (spec 10.8); at most once")
	fs.Var(&logTSARoots, "vendor-log-tsa-root", "PEM file with roots for time stamps of the vendor log (purpose log, spec 7.4.6, 10.8); repeatable")
	fs.Var(&vendorLogs, "vendor-log", "extract ledger-protokollauszug/1 of the vendor log (spec 7.4.8); repeatable")
	fs.Var(&logKeys, "vendor-log-key", "pin a protocol key of the vendor log as key_id=hex64 (spec 7.4.10); repeatable")
	fs.Var(&statementKeys, "vendor-statement-key", "pin a statements key as key_id=hex64 (spec 8.8.3, 10.7.4); repeatable")
	fs.Var(&keyLists, "vendor-key-list", "key list of the vendor (rekorder-herstellerschluessel/1, ledger-schluesselrollen/1, ledger-protokollschluessel/1; spec 10.7, 7.4.7); repeatable")
	fs.Var(&histories, "anchor-history", "page of the anchor history or ledger-ankerhistorie/2 (spec 8.8.2); repeatable")
	requestedAt := einmalFlag(fs, "requested-at", "when the auditor requested the package, RFC 3339 UTC (spec 8.8.1, 10.8); at most once")
	fs.Var(&vendorRoots, "vendor-root", "file with the vendor's root key {\"wurzel_id\",\"pubkey\"} (spec 7.1, 10.7); repeatable")
	fs.Var(&vendorKeys, "vendor-key", "pin a vendor countersigning key as key_id=hex64 (spec 7.1, 10.7.4); repeatable")
	showVersion := fs.Bool("version", false, "print version and exit; only as the one argument")
	usage := func() {
		fmt.Fprintf(stderr, "%s %s: %s offline verifier for %s verification packages (spec %s)\n", Name, Version, Product, Product, SpecVersion)
		fmt.Fprintf(stderr, "usage: %s [flags] <pruefpaket-dir-or-zip>\n", Name)
		fmt.Fprintf(stderr, "       %s --version\n", Name)
		fmt.Fprintf(stderr, "       %s zeitstempel --token FILE (--data FILE | --statement-jcs FILE) [--tsa-root FILE]... [--purpose chain|log] [--json] [--lang de|en]\n", Name)
		fmt.Fprintln(stderr, "every flag stands before the package and is written with two dashes; \"--\" ends the flags")
		schalterHilfe(fs, stderr)
		fmt.Fprintln(stderr, "exit codes: 0 valid / 1 valid with findings / 2 invalid / 3 format error or unusable invocation / 4 incomplete: chain end not sealed")
		fmt.Fprintln(stderr, "precedence: 3 before 2 before 4 before 1 before 0 (spec 10.3)")
	}
	// The flag package's own messages lack the tool's name and print one
	// dash; the forms it would take beyond the documented ones (-json,
	// --json=true) are refused before it parses (spec 10.8: exit 3 with the
	// reason), so that verifier2 and this verifier read every command line
	// alike.
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	if hilfe, err := vorpruefen(args, schalterArten(fs)); err != nil || hilfe {
		fs.SetOutput(stderr)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v (spec 10.8)\n", Name, err)
		}
		usage()
		return 3
	}
	if err := fs.Parse(args); err != nil {
		fs.SetOutput(stderr)
		if err != flag.ErrHelp {
			fmt.Fprintf(stderr, "%s: %v\n", Name, err)
		}
		usage()
		return 3
	}
	fs.SetOutput(stderr)
	fs.Usage = usage
	// Format spec 10.8: every switch with a value that the table does not
	// name repeatable stands at most once, --now, --lang and the freshness
	// window included; a repeated one is an unusable invocation.
	for _, e := range []*einmal{lang, nowStr, freshStr, qualified, requestedAt} {
		if e.zweimal != "" {
			return fehler("%s is given more than once (spec 10.8)", e.zweimal)
		}
	}
	if *showVersion {
		return fehler("--version stands alone; it takes no other argument")
	}
	if fs.NArg() != 1 {
		fs.Usage()
		if fs.NArg() > 1 {
			fmt.Fprintf(stderr, "%s: exactly one verification package (directory or ZIP) is needed, and every flag stands before it; got %d arguments, the second %q\n", Name, fs.NArg(), fs.Arg(1))
		} else {
			fmt.Fprintf(stderr, "%s: exactly one verification package (directory or ZIP) is needed, got none\n", Name)
		}
		return 3
	}
	builtin, hasBuiltin, err := vfy.Builtin()
	if err != nil {
		return fehler("%v", err)
	}
	langV := "en"
	if lang.set {
		langV = lang.v
	}
	if langV != "de" && langV != "en" {
		return fehler("--lang must be de or en")
	}
	fresh := 24 * time.Hour
	if freshStr.set {
		d, err := frischeFenster(freshStr.v)
		if err != nil {
			return fehler("%v", err)
		}
		fresh = d
	}
	opt := vfy.Options{Freshness: fresh}
	// Spec 10.8 (from 1.9): the auditor's inputs are read with the grammar of
	// the package; anything else is an unusable invocation, never a silent
	// interpretation. time.Parse(RFC3339Nano) took an offset, a comma before
	// the fraction and a one-digit hour; verifier2 took even a value without
	// a zone, in the host's time zone.
	if nowStr.set {
		t, err := vfy.ParseTime(nowStr.v)
		if err != nil {
			return fehler("--now: %v", err)
		}
		// NowSet: the zero time.Time is 0001-01-01T00:00:00Z, a grammatical
		// --now (year 0001 to 9999); before 1.1.0 it read as "not given"
		// and the system clock took its place, while verifier2 honoured it.
		opt.Now, opt.NowSet = t, true
	}
	opt.NowFromPackage = *nowPkg
	for _, s := range expectRoots {
		x, err := vfy.ParseExpectedRoot(s)
		if err != nil {
			return fehler("--expect-root must be 64 hex characters (ROOT) or TREE_SIZE:ROOT with TREE_SIZE a whole number from 1 (spec 10.8), got %q", s)
		}
		opt.ExpectRoots = append(opt.ExpectRoots, x)
	}
	// The inputs are read here and not in the verifier: the verifier gets
	// bytes, never a path. The browser build has no file system at all, and
	// a package must never be able to point the verifier at a file of its
	// choosing.
	files := []struct {
		flag  string
		paths []string
		limit int64
		add   func([]byte) error
	}{
		{"--tsa-root", tsaRoots, 0, opt.AddTSARootPEM},
		{"--tsa-qualified-roots", qualified.list(), vfy.MaxQualifiedRootsBytes, opt.SetTSAQualifiedRoots},
		{"--vendor-log-tsa-root", logTSARoots, 0, opt.AddVendorLogTSARootPEM},
		{"--vendor-log", vendorLogs, vfy.MaxVendorLogFileBytes, opt.AddVendorLog},
		{"--vendor-key-list", keyLists, vfy.MaxKeyListBytes, opt.AddVendorKeyList},
		{"--anchor-history", histories, vfy.MaxHistoryFileBytes, opt.AddAnchorHistory},
	}
	for _, f := range files {
		for _, p := range f.paths {
			b, err := lesen(p, f.limit)
			if err != nil {
				return fehler("%s %s: %v", f.flag, p, err)
			}
			if err := f.add(b); err != nil {
				return fehler("%s %s: %v", f.flag, p, err)
			}
		}
	}
	for _, s := range logKeys {
		if err := opt.AddVendorLogKey(s); err != nil {
			return fehler("%v", err)
		}
	}
	for _, s := range statementKeys {
		if err := opt.AddVendorStatementKey(s); err != nil {
			return fehler("%v", err)
		}
	}
	if requestedAt.set {
		if err := opt.SetRequestedAt(requestedAt.v); err != nil {
			return fehler("%v", err)
		}
	}
	if hasBuiltin {
		opt.VendorRoots = append(opt.VendorRoots, builtin)
	}
	for _, p := range vendorRoots {
		b, err := lesen(p, 0)
		if err != nil {
			return fehler("--vendor-root: %s: %v", p, err)
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
	// Contradicting anchors of the same name (also against the built-in
	// root) are a usage error, not "the last one wins" (spec 7.1).
	if opt.VendorRoots, opt.VendorKeys, err = vfy.AnkerZusammenfuehren(opt.VendorRoots, opt.VendorKeys); err != nil {
		return fehler("%v", err)
	}
	// The rules across inputs (spec 10.8, 7.4.10 L0, 10.7.4). The request
	// time is compared with --now or the system clock here; with the check
	// time from verify_args.json the run compares it at stage 5.
	checkNow := opt.Now
	if !opt.NowSet && !opt.NowFromPackage {
		checkNow = time.Now().UTC()
	}
	if err := opt.FinishAuditorInputs(checkNow); err != nil {
		return fehler("%v", err)
	}

	res := vfy.Verify(fs.Arg(0), opt)
	var out []byte
	if *jsonOut {
		b, err := vfy.RenderJSON(res)
		if err != nil {
			return fehler("%v", err)
		}
		out = b
	} else {
		out = []byte(vfy.RenderText(res, fs.Arg(0), langV))
	}
	if err := ausgeben(stdout, out); err != nil {
		return fehler("%v", err)
	}
	return res.ExitCode
}

// ausgeben writes the output in one piece. An output that cannot be written
// (a full disk, a closed or broken pipe) is an unusable invocation, exit 3
// with the reason on stderr: before 1.1.0 the error was dropped and the
// verdict returned, so exit 0 could stand for a report nobody received;
// verifier2 left with the interpreter's exit 1, "valid with findings".
func ausgeben(w io.Writer, b []byte) error {
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("cannot write the output: %v", err)
	}
	return nil
}

// frischeRe is the grammar of --freshness (spec 8.5, 10.8): a whole number
// from 1 to 999999 without a leading zero, directly followed by the unit.
var frischeRe = regexp.MustCompile(`^([1-9][0-9]{0,5})([hms])$`)

// frischeFenster reads the value of --freshness (spec 10.8). Anything else
// than the grammar, 0, a sign, a fraction, two units ("1h30m"), a missing
// unit or a blank included, is an unusable invocation; before 1.1.0 the
// verifier read it with time.ParseDuration, which took "-1h", "1.5h" and
// "1h30m" and read "0" as the default of 24 hours, while verifier2 took a
// number of hours ("nan" included). 999999h fits a time.Duration.
func frischeFenster(s string) (time.Duration, error) {
	m := frischeRe.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("--freshness must be a whole number from 1 to 999999 directly followed by h, m or s (e.g. 24h, 90m; spec 10.8), got %q", s)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("--freshness %q: %v", s, err)
	}
	einheit := map[string]time.Duration{"h": time.Hour, "m": time.Minute, "s": time.Second}[m[2]]
	return time.Duration(n) * einheit, nil
}

// schalterHilfe lists the switches of fs in the one spelling they are
// accepted in, "--name" (the flag package's PrintDefaults writes one dash).
func schalterHilfe(fs *flag.FlagSet, w io.Writer) {
	arten := schalterArten(fs)
	fs.VisitAll(func(f *flag.Flag) {
		wert := " VALUE"
		if arten[f.Name] {
			wert = ""
		}
		fmt.Fprintf(w, "  --%s%s\n    \t%s\n", f.Name, wert, f.Usage)
	})
}

// schalterArten lists the switches of fs: true for one without a value
// (a bool flag), false for one that takes a value.
func schalterArten(fs *flag.FlagSet) map[string]bool {
	arten := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) {
		b, ok := f.Value.(interface{ IsBoolFlag() bool })
		arten[f.Name] = ok && b.IsBoolFlag()
	})
	return arten
}

// vorpruefen checks the switches in front of the first positional argument
// before the flag package reads them, so that only the documented forms
// pass (spec 10.8): "--name" for a switch without a value, "--name value"
// or "--name=value" for one with a value. Like the flag package it stops at
// "--" and at the first argument that is no switch ("-" is one); everything
// from there on is positional, and Main refuses a second positional, which
// is how a switch after the package is refused. It returns hilfe for -h or
// --help, and an error for a single dash (-json), a value on a switch
// without one (--json=true), an unknown switch and a missing value. The
// flag package took all of the first two, verifier2 none of them.
func vorpruefen(args []string, arten map[string]bool) (hilfe bool, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" || a == "-" || !strings.HasPrefix(a, "-") {
			return false, nil
		}
		if a == "-h" || a == "--help" {
			return true, nil
		}
		if !strings.HasPrefix(a, "--") {
			name, _, _ := strings.Cut(a[1:], "=")
			return false, fmt.Errorf("%q: a flag is written with two dashes (--%s), and stands before the package", a, name)
		}
		name, _, mitWert := strings.Cut(a[2:], "=")
		ohneWert, bekannt := arten[name]
		switch {
		case !bekannt || name == "":
			return false, fmt.Errorf("unknown flag --%s", name)
		case ohneWert && mitWert:
			return false, fmt.Errorf("--%s takes no value, got %q", name, a)
		case !ohneWert && !mitWert:
			if i+1 >= len(args) {
				return false, fmt.Errorf("--%s needs a value", name)
			}
			i++ // the value, whatever it looks like (flag package rule)
		}
	}
	return false, nil
}

// MaxDateiOhneGrenze bounds the files of the auditor for which spec 10.8
// names no limit (--tsa-root, --vendor-log-tsa-root, --vendor-root and the
// files of the helper mode zeitstempel): the largest limit per file of the
// table, 32 MiB. It is a bound of both reference verifiers (verifier2:
// UNBOUNDED_INPUT_BYTES), not of the specification; a root file is a few
// kilobytes, a system's whole root store well below one megabyte.
const MaxDateiOhneGrenze = 33554432

// lesen reads a file of the auditor, at most limit bytes of it (spec 10.8);
// limit 0 stands for MaxDateiOhneGrenze. It reads limit+1 bytes at most and
// refuses a larger file, whatever the file is: os.Stat reports 0 bytes for
// a device, a pipe or a file under /proc, so before 1.1.0 /dev/zero or an
// endless pipe was read until the runtime ran out of memory and died with
// exit 2, the code of "invalid".
func lesen(p string, limit int64) ([]byte, error) {
	bound := limit
	if bound <= 0 {
		bound = MaxDateiOhneGrenze
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, bound+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > bound {
		if limit <= 0 {
			return nil, fmt.Errorf("more than %d bytes; a file without a limit in spec 10.8 is read up to that size", bound)
		}
		return nil, fmt.Errorf("more than %d bytes, above the limit of spec 10.8", bound)
	}
	return b, nil
}

// einmal is a flag that may be given at most once (spec 10.8: an input given
// more often than allowed is an unusable invocation).
type einmal struct {
	v       string
	set     bool
	zweimal string
	name    string
}

// einmalFlag registers a flag that may be given at most once.
func einmalFlag(fs *flag.FlagSet, name, usage string) *einmal {
	e := &einmal{name: "--" + name}
	fs.Var(e, name, usage)
	return e
}

func (e *einmal) String() string {
	if e == nil {
		return ""
	}
	return e.v
}

func (e *einmal) Set(s string) error {
	if e.set {
		e.zweimal = e.name
	}
	e.v, e.set = s, true
	return nil
}

func (e *einmal) list() []string {
	if !e.set {
		return nil
	}
	return []string{e.v}
}

// vielfach collects a repeatable flag.
type vielfach []string

func (v *vielfach) String() string     { return fmt.Sprint(*v) }
func (v *vielfach) Set(s string) error { *v = append(*v, s); return nil }
