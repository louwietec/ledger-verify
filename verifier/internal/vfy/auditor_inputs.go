package vfy

// Inputs of the auditor (format spec 2 "Dateien des Prüfers", 10.8, from
// edition 1.10): the roots for time stamps of the three purposes, the file of
// roots named qualified, extracts of the vendor log, pins of protocol and
// statements keys, key lists, anchor history files and the request time.
//
// The verifier reads them as bytes at invocation, before it opens the
// package; the command line and the browser edition call the same methods
// below, so both refuse the same inputs. A violation of a grammar or a limit,
// an input given more often than allowed and every other usage error is an
// unusable invocation: the methods return an error, the callers answer with
// exit 3 and the reason, without a report. What a defect in the content of an
// input that keeps its grammar causes is decided by format spec 7.4, 8.8 and
// 10.7; it is never exit 3.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
	"louwietec.com/ledger-verify/verifier/internal/tsa"
)

// Limits of format spec 10.8 (registry auditor_inputs).
const (
	MaxQualifiedRootsBytes = 8388608
	MaxVendorLogFileBytes  = 33554432
	MaxVendorLogFiles      = 128
	MaxVendorLogRunBytes   = 268435456
	MaxKeyListBytes        = 1048576
	MaxHistoryFileBytes    = 33554432
	MaxHistoryFiles        = 4096
	MaxHistoryPages        = 65536
	MaxHistoryRunBytes     = 268435456
)

// Formats of the auditor's key lists (format spec 10.7, 7.4.7).
const (
	KeyRoleListFormat     = "ledger-schluesselrollen/1"
	ProtocolKeyListFormat = "ledger-protokollschluessel/1"
	QualifiedRootsFormat  = "ledger-tsa-qualifiziert/1"
	ExtractFormat         = "ledger-protokollauszug/1"
	HistoryFormat         = "ledger-ankerhistorie/2"
)

var (
	reKeyID     = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	rePin       = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}=[0-9a-f]{64}$`)
	reSigAlg    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	rePrintable = regexp.MustCompile(`^[!-~]+$`) // and at most 1024 characters
	reDate      = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
)

// QualifiedRoot is one entry of ledger-tsa-qualifiziert/1.
type QualifiedRoot struct {
	Cert     *tsa.Certificate
	From     time.Time // qualifiziert_ab
	Until    time.Time // qualifiziert_bis; zero when absent
	FromRaw  string
	UntilRaw string
}

// QualifiedRoots is the file ledger-tsa-qualifiziert/1 (format spec 10.8).
type QualifiedRoots struct {
	Stand  string
	Quelle string
	Roots  []QualifiedRoot
}

// AuditorKeyList is a file of --vendor-key-list: its format and its value.
// The content is judged by format spec 10.7.1, 10.7.2 and 7.4.7 when the run
// needs it; a list that does not hold is ineffective, never exit 3.
type AuditorKeyList struct {
	Format string
	Value  *jcs.Value
	Raw    []byte
}

// VendorLogExtract is one extract ledger-protokollauszug/1 that follows the
// grammar of format spec 7.4.8, given with --vendor-log or carried in a file
// of the anchor history. Its content is judged by format spec 7.4.10.
type VendorLogExtract struct {
	Value  *jcs.Value
	LogID  string
	Bytes  int  // the file's bytes, or UTF-8(JCS(element)) when embedded
	Nested bool // carried in a file of the anchor history
	// Sum is the SHA-256 of those bytes: files are counted as distinct by
	// their bytes (vendor_log.distinct_files, step L4 seen_in). Zero when a
	// library caller builds the extract itself; then UTF-8(JCS(Value)) counts.
	Sum [32]byte
}

// HistoryPage is one page of the anchor history (format spec 8.8.2); the
// content of statement_jcs is judged only by step H2.
type HistoryPage struct {
	StatementJCS string
	ServerKeyID  string
	Signature    string
	File         int // index of the --anchor-history file
}

// AnchorHistoryFile is one file of --anchor-history.
type AnchorHistoryFile struct {
	Container bool
	Pages     []HistoryPage
	Bytes     int
}

// auditorJSON reads a file of the auditor (format spec 2): at most limit
// bytes, UTF-8 without byte order mark, I-JSON (no member name twice, the
// number rule, no lone surrogates).
func auditorJSON(b []byte, limit int, what string) (*jcs.Value, error) {
	if len(b) > limit {
		return nil, fmt.Errorf("%s: %d bytes, above the limit of %d (format spec 10.8)", what, len(b), limit)
	}
	if bytes.HasPrefix(b, []byte{0xef, 0xbb, 0xbf}) {
		return nil, fmt.Errorf("%s: starts with a byte order mark (format spec 2)", what)
	}
	if !utf8.Valid(b) {
		return nil, fmt.Errorf("%s: not UTF-8 (format spec 2)", what)
	}
	v, err := jcs.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: not I-JSON: %v (format spec 2)", what, err)
	}
	return v, nil
}

// closed checks that v is an object with exactly the required members and at
// most the optional ones (format spec 2: objects of auditor files are
// closed).
func closed(v *jcs.Value, what string, required []string, optional ...string) error {
	if v == nil || v.Kind != jcs.KindObject {
		return fmt.Errorf("%s is not an object", what)
	}
	allowed := map[string]bool{}
	for _, m := range append(append([]string{}, required...), optional...) {
		allowed[m] = true
	}
	for _, m := range v.Members {
		if !allowed[m.Key] {
			return fmt.Errorf("%s: member %q is not defined", what, m.Key)
		}
	}
	for _, m := range required {
		if !v.Has(m) {
			return fmt.Errorf("%s: member %q is missing", what, m)
		}
	}
	return nil
}

func str(v *jcs.Value) (string, bool) {
	if v == nil || v.Kind != jcs.KindString {
		return "", false
	}
	return v.Str, true
}

// strMax checks a string of at most n Unicode characters (format spec 2:
// maxlen counts characters).
func strMax(v *jcs.Value, n int) (string, bool) {
	s, ok := str(v)
	return s, ok && utf8.RuneCountInString(s) <= n
}

func intRange(v *jcs.Value, lo, hi int64) (int64, bool) {
	if v == nil || v.Kind != jcs.KindInt || v.Int < lo || v.Int > hi {
		return 0, false
	}
	return v.Int, true
}

const maxSafe = int64(1)<<53 - 1

func array(v *jcs.Value, lo, hi int) ([]*jcs.Value, bool) {
	if v == nil || v.Kind != jcs.KindArray || len(v.Arr) < lo || len(v.Arr) > hi {
		return nil, false
	}
	return v.Arr, true
}

// parseDate reads the type date of format spec 2 (an existing day, year 0001
// to 9999); logRange additionally requires 2000-01-01 to 9998-12-31.
func parseDate(s string, logRange bool) (time.Time, bool) {
	if !reDate.MatchString(s) || s < "0001-01-01" {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil || t.Format("2006-01-02") != s {
		return time.Time{}, false
	}
	if logRange && (s < "2000-01-01" || s > "9998-12-31") {
		return time.Time{}, false
	}
	return t, true
}

// ---------------------------------------------------------------- roots

// AddTSARootPEM adds a file of --tsa-root (purpose chain): strict PEM.
func (o *Options) AddTSARootPEM(b []byte) error {
	certs, err := tsa.ParsePEMRoots(b)
	if err != nil {
		return err
	}
	for _, c := range certs {
		o.TSARoots = append(o.TSARoots, c.DER)
	}
	return nil
}

// AddVendorLogTSARootPEM adds a file of --vendor-log-tsa-root (purpose log).
func (o *Options) AddVendorLogTSARootPEM(b []byte) error {
	certs, err := tsa.ParsePEMRoots(b)
	if err != nil {
		return err
	}
	for _, c := range certs {
		o.VendorLogTSARoots = append(o.VendorLogTSARoots, c.DER)
	}
	return nil
}

// SetTSAQualifiedRoots reads the file of --tsa-qualified-roots, at most once:
// ledger-tsa-qualifiziert/1 (format spec 10.8).
func (o *Options) SetTSAQualifiedRoots(b []byte) error {
	if o.TSAQualified != nil {
		return errors.New("--tsa-qualified-roots is given more than once (format spec 10.8)")
	}
	q, err := ParseQualifiedRoots(b)
	if err != nil {
		return err
	}
	o.TSAQualified = q
	return nil
}

// ParseQualifiedRoots reads ledger-tsa-qualifiziert/1: format, stand
// (rfc3339), quelle (1 to 256 characters without U+0000 to U+001F and U+007F
// to U+009F) and wurzeln (1 to 256 objects with zertifikat, the B64 form of a
// DER certificate after Z.1 with at most 16 384 bytes, qualifiziert_ab and
// optionally qualifiziert_bis after it). Two entries with a byte-identical
// certificate make the input ambiguous.
func ParseQualifiedRoots(b []byte) (*QualifiedRoots, error) {
	const what = QualifiedRootsFormat
	v, err := auditorJSON(b, MaxQualifiedRootsBytes, what)
	if err != nil {
		return nil, err
	}
	if err := closed(v, what, []string{"format", "stand", "quelle", "wurzeln"}); err != nil {
		return nil, err
	}
	if f, _ := str(v.Get("format")); f != QualifiedRootsFormat {
		return nil, fmt.Errorf("%s: format is not %q", what, QualifiedRootsFormat)
	}
	q := &QualifiedRoots{}
	var ok bool
	if q.Stand, ok = str(v.Get("stand")); !ok {
		return nil, fmt.Errorf("%s: stand is not a string", what)
	}
	if _, ok := parseUTC(q.Stand); !ok {
		return nil, fmt.Errorf("%s: stand %q is not rfc3339 (format spec 10.7)", what, q.Stand)
	}
	if q.Quelle, ok = strMax(v.Get("quelle"), 256); !ok || q.Quelle == "" {
		return nil, fmt.Errorf("%s: quelle is not a string of 1 to 256 characters", what)
	}
	for _, r := range q.Quelle {
		if r <= 0x1f || r >= 0x7f && r <= 0x9f {
			return nil, fmt.Errorf("%s: quelle holds a control character", what)
		}
	}
	list, ok := array(v.Get("wurzeln"), 1, 256)
	if !ok {
		return nil, fmt.Errorf("%s: wurzeln is not an array of 1 to 256 objects", what)
	}
	for i, w := range list {
		at := fmt.Sprintf("%s: wurzeln[%d]", what, i)
		if err := closed(w, at, []string{"zertifikat", "qualifiziert_ab"}, "qualifiziert_bis"); err != nil {
			return nil, err
		}
		z, ok := strMax(w.Get("zertifikat"), tsa.MaxTokenB64)
		if !ok {
			return nil, fmt.Errorf("%s: zertifikat is not a string of at most %d characters", at, tsa.MaxTokenB64)
		}
		der, err := tsa.DecodeB64(z)
		if err != nil {
			return nil, fmt.Errorf("%s: zertifikat: %v", at, err)
		}
		if len(der) > tsa.MaxTokenDER {
			return nil, fmt.Errorf("%s: zertifikat of %d bytes, above %d", at, len(der), tsa.MaxTokenDER)
		}
		c, err := tsa.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%s: zertifikat: %v", at, err)
		}
		e := QualifiedRoot{Cert: c}
		if e.FromRaw, ok = str(w.Get("qualifiziert_ab")); !ok {
			return nil, fmt.Errorf("%s: qualifiziert_ab is not a string", at)
		}
		if e.From, ok = parseUTC(e.FromRaw); !ok {
			return nil, fmt.Errorf("%s: qualifiziert_ab %q is not rfc3339", at, e.FromRaw)
		}
		if bis := w.Get("qualifiziert_bis"); bis != nil {
			if e.UntilRaw, ok = str(bis); !ok {
				return nil, fmt.Errorf("%s: qualifiziert_bis is not a string", at)
			}
			if e.Until, ok = parseUTC(e.UntilRaw); !ok {
				return nil, fmt.Errorf("%s: qualifiziert_bis %q is not rfc3339", at, e.UntilRaw)
			}
			if !e.Until.After(e.From) {
				return nil, fmt.Errorf("%s: qualifiziert_bis is not after qualifiziert_ab", at)
			}
		}
		for j, prev := range q.Roots {
			if bytes.Equal(prev.Cert.DER, c.DER) {
				return nil, fmt.Errorf("%s: the same certificate as wurzeln[%d]: the input is ambiguous (format spec 10.8)", at, j)
			}
		}
		q.Roots = append(q.Roots, e)
	}
	return q, nil
}

// ---------------------------------------------------------------- pins

// ParsePin reads a pin key_id=hex64 of --vendor-statement-key or
// --vendor-log-key (format spec 10.8).
func ParsePin(s string) (VendorKey, error) {
	if !rePin.MatchString(s) {
		return VendorKey{}, fmt.Errorf("%q is not key_id=hex64 (format spec 10.8)", s)
	}
	id, pub, _ := strings.Cut(s, "=")
	return VendorKey{ID: id, Pubkey: pub}, nil
}

// AddVendorStatementKey adds a pin of a statements key.
func (o *Options) AddVendorStatementKey(s string) error {
	k, err := ParsePin(s)
	if err != nil {
		return fmt.Errorf("--vendor-statement-key: %w", err)
	}
	o.VendorStatementKeys = append(o.VendorStatementKeys, k)
	return nil
}

// AddVendorLogKey adds a pin of a protocol key.
func (o *Options) AddVendorLogKey(s string) error {
	k, err := ParsePin(s)
	if err != nil {
		return fmt.Errorf("--vendor-log-key: %w", err)
	}
	o.VendorLogKeys = append(o.VendorLogKeys, k)
	return nil
}

// mergePins merges the pins of one role: two pins with one key_id and
// different keys are an unusable invocation, equal pins are one.
func mergePins(keys []VendorKey, flag string) ([]VendorKey, error) {
	var out []VendorKey
	seen := map[string]string{}
	for _, k := range keys {
		if p, ok := seen[k.ID]; ok {
			if p != k.Pubkey {
				return nil, fmt.Errorf("%s: key_id %q pinned twice with different keys: the audit environment is ambiguous (format spec 7.4.10 L0, 10.7.4)", flag, k.ID)
			}
			continue
		}
		seen[k.ID] = k.Pubkey
		out = append(out, k)
	}
	return out, nil
}

// ---------------------------------------------------------------- key lists

// AddVendorKeyList adds a file of --vendor-key-list: I-JSON of at most
// 1 048 576 bytes whose format is one of the three formats of key lists; an
// unknown or missing format is an unusable invocation (format spec 10.7.4,
// 10.8). The content is judged later and never makes exit 3.
func (o *Options) AddVendorKeyList(b []byte) error {
	v, err := auditorJSON(b, MaxKeyListBytes, "--vendor-key-list")
	if err != nil {
		return err
	}
	if v.Kind != jcs.KindObject {
		return errors.New("--vendor-key-list: not a JSON object")
	}
	f, ok := str(v.Get("format"))
	switch {
	case !ok:
		return errors.New("--vendor-key-list: no format (format spec 10.8)")
	case f != VendorListFormat && f != KeyRoleListFormat && f != ProtocolKeyListFormat:
		return fmt.Errorf("--vendor-key-list: unknown format %q (format spec 10.8)", f)
	}
	o.VendorKeyLists = append(o.VendorKeyLists, AuditorKeyList{Format: f, Value: v, Raw: b})
	return nil
}

// ---------------------------------------------------------------- extracts

// AddVendorLog adds a file of --vendor-log after the grammar of format spec
// 7.4.8.
func (o *Options) AddVendorLog(b []byte) error {
	if len(b) > MaxVendorLogFileBytes {
		return fmt.Errorf("--vendor-log: %d bytes, above %d (format spec 7.4.8)", len(b), MaxVendorLogFileBytes)
	}
	v, err := auditorJSON(b, MaxVendorLogFileBytes, "--vendor-log")
	if err != nil {
		return err
	}
	x, err := parseExtract(v, "--vendor-log")
	if err != nil {
		return err
	}
	x.Bytes, x.Sum = len(b), sha256.Sum256(b)
	o.VendorLogs = append(o.VendorLogs, x)
	return nil
}

// parseExtract checks the grammar of ledger-protokollauszug/1 (format spec
// 7.4.8): exactly these members on every level except inside protocol_keys;
// chain_id null only with empty chain_days; additional signatures with alg
// ed25519 in hex128 and no two equal in one day object; exactly one of
// present and absent; the roots of a record pairwise distinct by their leaf
// bytes; at most one record per day; neighbours ascending by leaf_index.
func parseExtract(v *jcs.Value, what string) (VendorLogExtract, error) {
	bad := func(format string, a ...any) (VendorLogExtract, error) {
		return VendorLogExtract{}, fmt.Errorf(what+": "+format+" (format spec 7.4.8)", a...)
	}
	if err := closed(v, "extract", []string{"format", "log_id", "chain_id", "protocol_keys", "days", "chain_days"}); err != nil {
		return bad("%v", err)
	}
	if f, _ := str(v.Get("format")); f != ExtractFormat {
		return bad("format is not %q", ExtractFormat)
	}
	logID, ok := str(v.Get("log_id"))
	if !ok || !reKeyID.MatchString(logID) {
		return bad("log_id is not a key-id")
	}
	chainID := ""
	if c := v.Get("chain_id"); c.Kind != jcs.KindNull {
		if chainID, ok = str(c); !ok || !reUUID.MatchString(chainID) {
			return bad("chain_id is neither a uuid nor null")
		}
	}
	if pk := v.Get("protocol_keys"); pk.Kind != jcs.KindNull && pk.Kind != jcs.KindObject {
		return bad("protocol_keys is neither an object nor null")
	}
	days, ok := array(v.Get("days"), 0, 4000)
	if !ok {
		return bad("days is not an array of at most 4000 day objects")
	}
	for i, d := range days {
		at := fmt.Sprintf("days[%d]", i)
		if err := closed(d, at, []string{"entry", "timestamps", "additional_signatures"}); err != nil {
			return bad("%v", err)
		}
		e := d.Get("entry")
		if err := closed(e, at+".entry", []string{"statement_jcs", "server_key_id", "server_signature"}); err != nil {
			return bad("%v", err)
		}
		if _, ok := strMax(e.Get("statement_jcs"), 2048); !ok {
			return bad("%s.entry.statement_jcs is not a string of at most 2048 characters", at)
		}
		if s, ok := str(e.Get("server_key_id")); !ok || !reKeyID.MatchString(s) {
			return bad("%s.entry.server_key_id is not a key-id", at)
		}
		if s, ok := str(e.Get("server_signature")); !ok || !reHex128.MatchString(s) {
			return bad("%s.entry.server_signature is not hex128", at)
		}
		ts, ok := array(d.Get("timestamps"), 0, 4)
		if !ok {
			return bad("%s.timestamps is not an array of at most 4 strings", at)
		}
		for j, t := range ts {
			if _, ok := strMax(t, tsa.MaxTokenB64); !ok {
				return bad("%s.timestamps[%d] is not a string of at most %d characters", at, j, tsa.MaxTokenB64)
			}
		}
		sigs, ok := array(d.Get("additional_signatures"), 0, 3)
		if !ok {
			return bad("%s.additional_signatures is not an array of at most 3 objects", at)
		}
		seen := map[string]bool{}
		for j, s := range sigs {
			sat := fmt.Sprintf("%s.additional_signatures[%d]", at, j)
			if err := closed(s, sat, []string{"alg", "key_id", "signature"}); err != nil {
				return bad("%v", err)
			}
			alg, ok1 := str(s.Get("alg"))
			kid, ok2 := str(s.Get("key_id"))
			sv, ok3 := str(s.Get("signature"))
			if !ok1 || !reSigAlg.MatchString(alg) || !ok2 || !reKeyID.MatchString(kid) || !ok3 || !rePrintable.MatchString(sv) || len(sv) > 1024 {
				return bad("%s does not follow the grammar", sat)
			}
			if alg == "ed25519" && !reHex128.MatchString(sv) {
				return bad("%s: alg ed25519 needs a hex128 signature", sat)
			}
			k := string(jcs.Canon(s))
			if seen[k] {
				return bad("%s equals an earlier element", sat)
			}
			seen[k] = true
		}
	}
	cds, ok := array(v.Get("chain_days"), 0, 4000)
	if !ok {
		return bad("chain_days is not an array of at most 4000 records")
	}
	if chainID == "" && len(cds) > 0 {
		return bad("chain_id is null, but chain_days is not empty")
	}
	daySeen := map[string]bool{}
	for i, cd := range cds {
		at := fmt.Sprintf("chain_days[%d]", i)
		if err := closed(cd, at, []string{"day", "present", "absent"}); err != nil {
			return bad("%v", err)
		}
		day, ok := str(cd.Get("day"))
		if _, okd := parseDate(day, true); !ok || !okd {
			return bad("%s.day is not a date of the log range", at)
		}
		if daySeen[day] {
			return bad("two records for the day %s", day)
		}
		daySeen[day] = true
		pr, ab := cd.Get("present"), cd.Get("absent")
		if (pr.Kind == jcs.KindNull) == (ab.Kind == jcs.KindNull) {
			return bad("%s: not exactly one of present and absent", at)
		}
		if pr.Kind != jcs.KindNull {
			if err := closed(pr, at+".present", []string{"roots", "leaf_index", "path"}); err != nil {
				return bad("%v", err)
			}
			roots, ok := array(pr.Get("roots"), 1, 4096)
			if !ok {
				return bad("%s.present.roots is not an array of 1 to 4096 roots", at)
			}
			leaves := map[string]bool{}
			for j, r := range roots {
				rat := fmt.Sprintf("%s.present.roots[%d]", at, j)
				if err := closed(r, rat, []string{"tree_size", "merkle_root", "recorded_as", "server_ts"}); err != nil {
					return bad("%v", err)
				}
				tsz, ok1 := intRange(r.Get("tree_size"), 1, maxSafe)
				mr, ok2 := str(r.Get("merkle_root"))
				ra, ok3 := str(r.Get("recorded_as"))
				st, ok4 := str(r.Get("server_ts"))
				if !ok1 || !ok2 || !reHex64.MatchString(mr) || !ok3 || ra != "countersigned" && ra != "gap_witness" || !ok4 {
					return bad("%s does not follow the grammar", rat)
				}
				if _, ok := parseUTC(st); !ok {
					return bad("%s.server_ts is not rfc3339", rat)
				}
				// The leaf bytes (7.4.2) of one chain differ exactly when
				// the kind or one of the three values differs.
				k := fmt.Sprintf("%s|%d|%s|%s", ra, tsz, mr, st)
				if leaves[k] {
					return bad("%s: two roots with the same leaf bytes", at)
				}
				leaves[k] = true
			}
			if _, ok := intRange(pr.Get("leaf_index"), 0, maxSafe); !ok {
				return bad("%s.present.leaf_index out of range", at)
			}
			if err := hexPath(pr.Get("path")); err != nil {
				return bad("%s.present.path %v", at, err)
			}
		} else {
			if err := closed(ab, at+".absent", []string{"neighbours"}); err != nil {
				return bad("%v", err)
			}
			nb, ok := array(ab.Get("neighbours"), 0, 2)
			if !ok {
				return bad("%s.absent.neighbours is not an array of at most 2 neighbours", at)
			}
			last := int64(-1)
			for j, n := range nb {
				nat := fmt.Sprintf("%s.absent.neighbours[%d]", at, j)
				if err := closed(n, nat, []string{"leaf_index", "position", "chain_root", "path"}); err != nil {
					return bad("%v", err)
				}
				li, ok1 := intRange(n.Get("leaf_index"), 0, maxSafe)
				p, ok2 := str(n.Get("position"))
				c, ok3 := str(n.Get("chain_root"))
				if !ok1 || !ok2 || !reHex64.MatchString(p) || !ok3 || !reHex64.MatchString(c) {
					return bad("%s does not follow the grammar", nat)
				}
				if err := hexPath(n.Get("path")); err != nil {
					return bad("%s.path %v", nat, err)
				}
				// 7.4.8: ascending by leaf_index, not descending; equal
				// values do not violate the grammar.
				if li < last {
					return bad("%s: neighbours not ascending by leaf_index", at)
				}
				last = li
			}
		}
	}
	return VendorLogExtract{Value: v, LogID: logID}, nil
}

func hexPath(v *jcs.Value) error {
	p, ok := array(v, 0, 64)
	if !ok {
		return errors.New("is not an array of at most 64 hex64 values")
	}
	for _, h := range p {
		if s, ok := str(h); !ok || !reHex64.MatchString(s) {
			return errors.New("holds a value that is not hex64")
		}
	}
	return nil
}

// ---------------------------------------------------------------- history

// AddAnchorHistory adds a file of --anchor-history after format spec 8.8.2:
// a page or a container ledger-ankerhistorie/2 whose extracts follow 7.4.8
// and count as files of --vendor-log with the bytes UTF-8(JCS(element)).
func (o *Options) AddAnchorHistory(b []byte) error {
	v, err := auditorJSON(b, MaxHistoryFileBytes, "--anchor-history")
	if err != nil {
		return err
	}
	f := AnchorHistoryFile{Bytes: len(b)}
	idx := len(o.AnchorHistory)
	if v.Kind == jcs.KindObject && v.Has("format") {
		f.Container = true
		if err := closed(v, "--anchor-history container", []string{"format", "pages", "vendor_log"}); err != nil {
			return fmt.Errorf("%v (format spec 8.8.2)", err)
		}
		if s, _ := str(v.Get("format")); s != HistoryFormat {
			return fmt.Errorf("--anchor-history: format is not %q (format spec 8.8.2)", HistoryFormat)
		}
		pages, ok := array(v.Get("pages"), 1, 4096)
		if !ok {
			return errors.New("--anchor-history: pages is not an array of 1 to 4096 pages (format spec 8.8.2)")
		}
		for i, p := range pages {
			hp, err := parsePage(p, fmt.Sprintf("--anchor-history pages[%d]", i))
			if err != nil {
				return err
			}
			hp.File = idx
			f.Pages = append(f.Pages, hp)
		}
		logs, ok := array(v.Get("vendor_log"), 0, 128)
		if !ok {
			return errors.New("--anchor-history: vendor_log is not an array of at most 128 extracts (format spec 8.8.2)")
		}
		for i, x := range logs {
			e, err := parseExtract(x, fmt.Sprintf("--anchor-history vendor_log[%d]", i))
			if err != nil {
				return err
			}
			c := jcs.Canon(x)
			e.Bytes, e.Nested, e.Sum = len(c), true, sha256.Sum256(c)
			if e.Bytes > MaxVendorLogFileBytes {
				return fmt.Errorf("--anchor-history vendor_log[%d]: %d bytes, above %d (format spec 7.4.8)", i, e.Bytes, MaxVendorLogFileBytes)
			}
			o.VendorLogs = append(o.VendorLogs, e)
		}
	} else {
		hp, err := parsePage(v, "--anchor-history page")
		if err != nil {
			return err
		}
		hp.File = idx
		f.Pages = []HistoryPage{hp}
	}
	o.AnchorHistory = append(o.AnchorHistory, f)
	return nil
}

// parsePage checks a page: exactly statement_jcs (1 to 131 072 characters),
// server_key_id (key-id), server_signature (hex128) and statement (any value).
func parsePage(v *jcs.Value, what string) (HistoryPage, error) {
	if err := closed(v, what, []string{"statement_jcs", "server_key_id", "server_signature", "statement"}); err != nil {
		return HistoryPage{}, fmt.Errorf("%v (format spec 8.8.2)", err)
	}
	st, ok := strMax(v.Get("statement_jcs"), 131072)
	if !ok || st == "" {
		return HistoryPage{}, fmt.Errorf("%s: statement_jcs is not a string of 1 to 131072 characters (format spec 8.8.2)", what)
	}
	kid, ok := str(v.Get("server_key_id"))
	if !ok || !reKeyID.MatchString(kid) {
		return HistoryPage{}, fmt.Errorf("%s: server_key_id is not a key-id (format spec 8.8.2)", what)
	}
	sig, ok := str(v.Get("server_signature"))
	if !ok || !reHex128.MatchString(sig) {
		return HistoryPage{}, fmt.Errorf("%s: server_signature is not hex128 (format spec 8.8.2)", what)
	}
	return HistoryPage{StatementJCS: st, ServerKeyID: kid, Signature: sig}, nil
}

// ---------------------------------------------------------------- request time

// SetRequestedAt reads --requested-at, at most once: the rfc3339 grammar of
// the check time with any fraction (format spec 10.8).
func (o *Options) SetRequestedAt(s string) error {
	if o.RequestedAtSet {
		return errors.New("--requested-at is given more than once (format spec 10.8)")
	}
	t, err := ParseTime(s)
	if err != nil {
		return fmt.Errorf("--requested-at: %v", err)
	}
	o.RequestedAt, o.RequestedAtSet, o.RequestedAtRaw = t, true, s
	return nil
}

// ---------------------------------------------------------------- the whole

// FinishAuditorInputs applies the rules that span several inputs, after all
// of them are read and before the package is opened (format spec 10.8, 7.4.10
// L0, 10.7.4): the limits per run, one log_id across all extracts, the pins
// of each role merged, no pin equal in key_id or public key to a pin of
// another role, and the request time not after the check time when that
// comes from --now or the system clock (now is that time; zero when the
// check time comes from verify_args.json, which stage 5 compares; with
// NowSet, now is the given --now, the zero time 0001-01-01T00:00:00Z
// included).
func (o *Options) FinishAuditorInputs(now time.Time) error {
	if n := len(o.VendorLogs); n > MaxVendorLogFiles {
		return fmt.Errorf("%d extracts of the vendor log, above %d per run (format spec 7.4.8, 10.8)", n, MaxVendorLogFiles)
	}
	total := 0
	for _, x := range o.VendorLogs {
		total += x.Bytes
	}
	if total > MaxVendorLogRunBytes {
		return fmt.Errorf("extracts of the vendor log of %d bytes, above %d per run (format spec 7.4.8, 10.8)", total, MaxVendorLogRunBytes)
	}
	logIDs := map[string]bool{}
	for _, x := range o.VendorLogs {
		logIDs[x.LogID] = true
	}
	if len(logIDs) > 1 {
		var ids []string
		for id := range logIDs {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		return fmt.Errorf("the extracts name different log_id values (%s) (format spec 7.4.10 L0)", strings.Join(ids, ", "))
	}
	if n := len(o.AnchorHistory); n > MaxHistoryFiles {
		return fmt.Errorf("%d files of the anchor history, above %d per run (format spec 8.8.2)", n, MaxHistoryFiles)
	}
	pages, hb := 0, 0
	for _, f := range o.AnchorHistory {
		pages += len(f.Pages)
		hb += f.Bytes
	}
	if pages > MaxHistoryPages || hb > MaxHistoryRunBytes {
		return fmt.Errorf("the anchor history holds %d pages and %d bytes, above %d pages or %d bytes per run (format spec 8.8.2)", pages, hb, MaxHistoryPages, MaxHistoryRunBytes)
	}
	var err error
	if o.VendorStatementKeys, err = mergePins(o.VendorStatementKeys, "--vendor-statement-key"); err != nil {
		return err
	}
	if o.VendorLogKeys, err = mergePins(o.VendorLogKeys, "--vendor-log-key"); err != nil {
		return err
	}
	roles := []struct {
		flag string
		keys []VendorKey
	}{{"--vendor-key", o.VendorKeys}, {"--vendor-statement-key", o.VendorStatementKeys}, {"--vendor-log-key", o.VendorLogKeys}}
	for i := range roles {
		for j := i + 1; j < len(roles); j++ {
			for _, a := range roles[i].keys {
				for _, b := range roles[j].keys {
					if a.ID == b.ID || a.Pubkey == b.Pubkey {
						return fmt.Errorf("%s %s=%s and %s %s=%s name one key in two roles: the audit environment is ambiguous (format spec 10.7.4)",
							roles[i].flag, a.ID, a.Pubkey, roles[j].flag, b.ID, b.Pubkey)
					}
				}
			}
		}
	}
	if o.RequestedAtSet && (o.NowSet || !now.IsZero()) && unixMS(o.RequestedAt) > unixMS(now) {
		return fmt.Errorf("--requested-at %s lies after the check time %s (format spec 10.8)", o.RequestedAtRaw, FormatMillisUTC(now))
	}
	return nil
}

// FormatMillisUTC renders an instant the verifier forms itself in the form
// YYYY-MM-DDThh:mm:ss.sssZ, truncated to whole milliseconds (format spec
// 10.10.1).
func FormatMillisUTC(t time.Time) string { return tsa.FormatMillis(t) }
