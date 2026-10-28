package cli

// The helper mode "zeitstempel": one RFC 3161 time stamp judged after the
// time-stamp profile (format spec 7.5) on its own, without a chain and
// without a vendor log, for instance to check the tokens of a time-stamping
// authority before the first day of the vendor log. It is not normative: it
// is no verification of a package, and its exit code says nothing about one.
//
//	ledger-verify zeitstempel --token FILE (--data FILE | --statement-jcs FILE)
//	              [--tsa-root FILE]... [--purpose chain|log] [--json] [--lang de|en]
//
// --token     the TimeStampToken: DER (a file whose first byte is 0x30) or
//             its Base64 text (any other file; one line end at the end is
//             removed, the rest must follow grammar B64)
// --data      the stamped bytes, exactly as in the file
// --statement-jcs
//             the statement_jcs of a day entry (format spec 7.4.5); one line
//             end at the end is removed, the rest must be printable ASCII
// --tsa-root  roots of the purpose, strict PEM (format spec 10.8); repeatable
// --purpose   log (default) or chain: the purpose of the roots given; for
//             both purposes the rows of 7.5.7 are taken in the order of the
//             table and the topmost that applies decides (spec/testvectors/
//             README 10.4), Z.6 and published test keys included
//
// Output: the state after 7.5.7 (defective, unconfirmed, confirmed), the
// case of 7.5.7 that decides, genTime as written and truncated to
// milliseconds, the imprint algorithm, the name of the signer and the result
// of rule QS. Exit 0 confirmed, 1 unconfirmed or defective, 3 an unusable
// invocation.

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"louwietec.com/ledger-verify/verifier/internal/tsa"
)

// ZeitstempelResult is the JSON output of the helper mode, one object with
// these members in this order.
type ZeitstempelResult struct {
	Purpose            string  `json:"purpose"`
	State              string  `json:"state"`
	Reason             *string `json:"reason"`
	GenTime            *string `json:"gen_time"`
	GenTimeMS          *string `json:"gen_time_ms"`
	ImprintAlgorithm   *string `json:"imprint_algorithm"`
	Signer             *string `json:"signer"`
	QualifiedStatement *string `json:"qualified_statement"`
}

var zeitstempelTexte = map[string]map[string]string{
	"de": {
		"title": "LEDGER: Einzelprüfung eines Zeitstempels (ledger-verify)", "purpose": "Zweck", "state": "Ergebnis",
		"reason": "Grund", "gentime": "genTime", "imprint": "Abdruck", "signer": "Signierer", "qs": "Regel QS",
		"defective": "mangelhaft", "unconfirmed": "nicht bestätigt", "confirmed": "bestätigt",
		"chain": "chain (Zeitzeuge der Kette, Abschnitt 7.3)", "log": "log (Zeitstempel eines Tageseintrags, Abschnitt 7.4.6)",
		"none": "keiner", "note": "Hinweis: Diese Einzelprüfung ist keine Prüfung eines Prüfpakets.",
	},
	"en": {
		"title": "LEDGER: check of a single time stamp (ledger-verify)", "purpose": "Purpose", "state": "Result",
		"reason": "Reason", "gentime": "genTime", "imprint": "Imprint", "signer": "Signer", "qs": "Rule QS",
		"defective": "defective", "unconfirmed": "not confirmed", "confirmed": "confirmed",
		"chain": "chain (time witness of a chain, section 7.3)", "log": "log (time stamp of a day entry, section 7.4.6)",
		"none": "none", "note": "Note: this single check is no verification of a package.",
	},
}

func zeitstempel(args []string, stdout, stderr io.Writer) int {
	fehler := func(format string, a ...any) int {
		fmt.Fprintf(stderr, Name+" zeitstempel: "+format+"\n", a...)
		return 3
	}
	fs := flag.NewFlagSet(Name+" zeitstempel", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tokenF := einmalFlag(fs, "token", "the TimeStampToken, DER or Base64")
	dataF := einmalFlag(fs, "data", "the stamped bytes")
	stmtF := einmalFlag(fs, "statement-jcs", "the statement_jcs of a day entry (format spec 7.4.5)")
	purposeF := einmalFlag(fs, "purpose", "chain or log (default log)")
	langF := einmalFlag(fs, "lang", "de or en (default en)")
	var roots vielfach
	fs.Var(&roots, "tsa-root", "PEM file with roots of the purpose (strict PEM, format spec 10.8); repeatable")
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	// The same forms as in the main mode (cli.go, vorpruefen): two dashes,
	// no value on --json; -h and --help print the switches on stderr and
	// are exit 3 like every other call that judges nothing.
	if hilfe, err := vorpruefen(args, schalterArten(fs)); err != nil || hilfe {
		fs.SetOutput(stderr)
		if err != nil {
			fmt.Fprintf(stderr, "%s zeitstempel: %v\n", Name, err)
		}
		fmt.Fprintf(stderr, "usage: %s zeitstempel --token FILE (--data FILE | --statement-jcs FILE) [--tsa-root FILE]... [--purpose chain|log] [--json] [--lang de|en]\n", Name)
		schalterHilfe(fs, stderr)
		return 3
	}
	if err := fs.Parse(args); err != nil {
		fs.SetOutput(stderr)
		if err != flag.ErrHelp {
			fmt.Fprintf(stderr, "%s zeitstempel: %v\n", Name, err)
		}
		schalterHilfe(fs, stderr)
		return 3
	}
	for _, e := range []*einmal{tokenF, dataF, stmtF, purposeF, langF} {
		if e.zweimal != "" {
			return fehler("%s is given more than once", e.zweimal)
		}
	}
	if fs.NArg() != 0 {
		return fehler("unexpected argument %q", fs.Arg(0))
	}
	if !tokenF.set {
		return fehler("--token is missing")
	}
	if dataF.set == stmtF.set {
		return fehler("exactly one of --data and --statement-jcs is needed")
	}
	purpose := tsa.PurposeLog
	if purposeF.set {
		purpose = purposeF.v
	}
	if purpose != tsa.PurposeLog && purpose != tsa.PurposeChain {
		return fehler("--purpose must be chain or log")
	}
	lang := "en"
	if langF.set {
		lang = langF.v
	}
	if lang != "de" && lang != "en" {
		return fehler("--lang must be de or en")
	}
	var rootCerts []*tsa.Certificate
	for _, p := range roots {
		b, err := lesen(p, 0)
		if err != nil {
			return fehler("--tsa-root %s: %v", p, err)
		}
		c, err := tsa.ParsePEMRoots(b)
		if err != nil {
			return fehler("--tsa-root %s: %v", p, err)
		}
		rootCerts = append(rootCerts, c...)
	}
	var stamped []byte
	if dataF.set {
		b, err := lesen(dataF.v, 0)
		if err != nil {
			return fehler("--data: %v", err)
		}
		stamped = b
	} else {
		b, err := lesen(stmtF.v, 0)
		if err != nil {
			return fehler("--statement-jcs: %v", err)
		}
		b = ohneZeilenende(b)
		for _, c := range b {
			if c < 0x20 || c > 0x7e {
				return fehler("--statement-jcs: a statement_jcs consists of printable ASCII only (format spec 2, 7.4.5)")
			}
		}
		stamped = b
	}
	raw, err := lesen(tokenF.v, 0)
	if err != nil {
		return fehler("--token: %v", err)
	}

	res := ZeitstempelResult{Purpose: purpose}
	var a tsa.Assessment
	der := raw
	if len(raw) == 0 || raw[0] != 0x30 {
		der, err = tsa.DecodeB64(string(ohneZeilenende(raw)))
	}
	if err != nil {
		a = tsa.Assessment{Purpose: purpose, State: tsa.StateDefective, Case: tsa.CaseGrammar, Detail: err.Error()}
	} else {
		a = tsa.Assess(der, stamped, rootCerts, purpose)
	}
	res.State = a.State
	if a.Case != "" {
		res.Reason = ptr(a.Case)
	}
	if t := a.Token; t != nil {
		res.GenTime, res.GenTimeMS = ptr(t.GenTimeRaw), ptr(t.GenTimeMillis())
		res.ImprintAlgorithm = ptr(t.HashAlgorithm)
		res.QualifiedStatement = ptr(a.QS)
	}
	if s := a.Signature.Signer; s != nil && s.SubjectCommonName() != "" {
		res.Signer = ptr(s.SubjectCommonName())
	}

	var b bytes.Buffer
	if *jsonOut {
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			return fehler("%v", err)
		}
	} else {
		tx := zeitstempelTexte[lang]
		opt := func(p *string) string {
			if p == nil || *p == "" {
				return tx["none"]
			}
			return *p
		}
		fmt.Fprintln(&b, tx["title"])
		fmt.Fprintf(&b, "%-12s %s\n", tx["purpose"]+":", tx[purpose])
		fmt.Fprintf(&b, "%-12s %s\n", tx["state"]+":", tx[res.State])
		if res.Reason != nil {
			fmt.Fprintf(&b, "%-12s %s (%s)\n", tx["reason"]+":", *res.Reason, a.Detail)
		}
		if res.GenTime != nil {
			fmt.Fprintf(&b, "%-12s %s (%s)\n", tx["gentime"]+":", *res.GenTime, *res.GenTimeMS)
		}
		fmt.Fprintf(&b, "%-12s %s\n", tx["imprint"]+":", opt(res.ImprintAlgorithm))
		fmt.Fprintf(&b, "%-12s %s\n", tx["signer"]+":", opt(res.Signer))
		fmt.Fprintf(&b, "%-12s %s\n", tx["qs"]+":", opt(res.QualifiedStatement))
		fmt.Fprintln(&b, tx["note"])
	}
	// As in the main mode: an output that cannot be written is exit 3.
	if err := ausgeben(stdout, b.Bytes()); err != nil {
		return fehler("%v", err)
	}
	if res.State == tsa.StateConfirmed {
		return 0
	}
	return 1
}

func ptr(s string) *string { return &s }

// ohneZeilenende removes one line end (\n or \r\n) at the end.
func ohneZeilenende(b []byte) []byte {
	if bytes.HasSuffix(b, []byte("\r\n")) {
		return b[:len(b)-2]
	}
	return bytes.TrimSuffix(b, []byte("\n"))
}
