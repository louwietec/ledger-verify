package cli

// The vectors of the vendor log (registry testvectors group log, format spec
// 7.4.10 steps L0 to L10, report object vendor_log of 10.10.2) with their
// audit environment pruefer_<name>.json. The expected file names exit code
// and finding classes only (spec/testvectors README 11); the values of the
// report object vendor_log and the reasons of the findings stand in the
// description of each row of README 11.3 and in the member why of the
// registry entry. This test holds the Go verifier to them, and it checks the
// object against the generated schema report_vendor_log.schema.json.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"louwietec.com/ledger-verify/verifier/internal/vfy"
)

// jeEinmal returns the sorted classes, each once.
func jeEinmal(k []string) []string {
	sort.Strings(k)
	var out []string
	for i, c := range k {
		if i == 0 || c != k[i-1] {
			out = append(out, c)
		}
	}
	return out
}

// ---------------------------------------------------------------- schema

// The generated report schemas use only these keywords: type (a name or a
// list of names), enum, pattern, maxLength, minimum, maximum, minItems,
// maxItems, items (a schema or false), prefixItems, properties, required
// and additionalProperties false.
type miniSchema struct {
	Type                 any                    `json:"type"`
	Enum                 []any                  `json:"enum"`
	Pattern              string                 `json:"pattern"`
	Minimum              *json.Number           `json:"minimum"`
	Maximum              *json.Number           `json:"maximum"`
	MaxLength            *int                   `json:"maxLength"`
	MinItems             *int                   `json:"minItems"`
	MaxItems             *int                   `json:"maxItems"`
	Items                *miniSchema            `json:"items"`
	PrefixItems          []*miniSchema          `json:"prefixItems"`
	Properties           map[string]*miniSchema `json:"properties"`
	Required             []string               `json:"required"`
	AdditionalProperties *bool                  `json:"additionalProperties"`
	never                bool                   // the schema false: no value holds
}

// UnmarshalJSON reads a schema object or the schemas true and false.
func (s *miniSchema) UnmarshalJSON(b []byte) error {
	switch strings.TrimSpace(string(b)) {
	case "false":
		*s = miniSchema{never: true}
		return nil
	case "true":
		*s = miniSchema{}
		return nil
	}
	type plain miniSchema
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var p plain
	if err := d.Decode(&p); err != nil {
		return err
	}
	*s = miniSchema(p)
	return nil
}

var (
	schemaMu    sync.Mutex
	schemaCache = map[string]*miniSchema{}
)

// reportSchema reads a generated schema spec/schemas/<name> once.
func reportSchema(name string) (*miniSchema, error) {
	schemaMu.Lock()
	defer schemaMu.Unlock()
	if s, ok := schemaCache[name]; ok {
		return s, nil
	}
	b, err := os.ReadFile(filepath.Join(vektor(""), "..", "schemas", name))
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var s miniSchema
	if err := d.Decode(&s); err != nil {
		return nil, err
	}
	schemaCache[name] = &s
	return &s, nil
}

func vendorLogSchema() (*miniSchema, error) { return reportSchema("report_vendor_log.schema.json") }

func jsonTypeOf(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case json.Number:
		if _, err := x.Int64(); err == nil {
			return "integer"
		}
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "unknown"
}

func (s *miniSchema) check(path string, v any) error {
	if s.never {
		return fmt.Errorf("%s: no value allowed here", path)
	}
	if s.Type != nil {
		var names []string
		switch t := s.Type.(type) {
		case string:
			names = []string{t}
		case []any:
			for _, n := range t {
				names = append(names, fmt.Sprint(n))
			}
		}
		got, ok := jsonTypeOf(v), false
		for _, n := range names {
			if n == got || (n == "number" && got == "integer") {
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("%s: type %s, want %v", path, got, names)
		}
	}
	if s.Enum != nil {
		ok := false
		for _, e := range s.Enum {
			if fmt.Sprint(e) == fmt.Sprint(v) && jsonTypeOf(e) == jsonTypeOf(v) {
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("%s: %v not in %v", path, v, s.Enum)
		}
	}
	switch x := v.(type) {
	case string:
		if s.Pattern != "" && !regexp.MustCompile(s.Pattern).MatchString(x) {
			return fmt.Errorf("%s: %q does not match %s", path, x, s.Pattern)
		}
		if s.MaxLength != nil && len([]rune(x)) > *s.MaxLength {
			return fmt.Errorf("%s: %d characters, at most %d", path, len([]rune(x)), *s.MaxLength)
		}
	case json.Number:
		if s.Minimum != nil {
			n, _ := x.Int64()
			m, _ := s.Minimum.Int64()
			if n < m {
				return fmt.Errorf("%s: %d below %d", path, n, m)
			}
		}
		if s.Maximum != nil {
			n, _ := x.Int64()
			m, _ := s.Maximum.Int64()
			if n > m {
				return fmt.Errorf("%s: %d above %d", path, n, m)
			}
		}
	case []any:
		if s.MaxItems != nil && len(x) > *s.MaxItems {
			return fmt.Errorf("%s: %d items, at most %d", path, len(x), *s.MaxItems)
		}
		if s.MinItems != nil && len(x) < *s.MinItems {
			return fmt.Errorf("%s: %d items, at least %d", path, len(x), *s.MinItems)
		}
		for i, e := range x {
			var item *miniSchema
			switch {
			case i < len(s.PrefixItems):
				item = s.PrefixItems[i]
			case s.Items != nil:
				item = s.Items
			}
			if item != nil {
				if err := item.check(fmt.Sprintf("%s[%d]", path, i), e); err != nil {
					return err
				}
			}
		}
	case map[string]any:
		for _, r := range s.Required {
			if _, ok := x[r]; !ok {
				return fmt.Errorf("%s: member %s missing", path, r)
			}
		}
		for k, e := range x {
			p, ok := s.Properties[k]
			if !ok {
				if s.AdditionalProperties != nil && !*s.AdditionalProperties {
					return fmt.Errorf("%s: member %s not in the schema", path, k)
				}
				continue
			}
			if err := p.check(path+"."+k, e); err != nil {
				return err
			}
		}
	}
	return nil
}

// vendorLogNachSchema checks stats.vendor_log of a JSON report: an object
// after the schema, or null with exit 3 (format error, 10.10.1).
func vendorLogNachSchema(t *testing.T, out string) error {
	return reportNachSchema(t, out, "vendor_log", "report_vendor_log.schema.json")
}

// reportNachSchema checks stats.<member> of a JSON report: an object after
// the generated schema, or null with exit 3 (format error, 10.10.1).
func reportNachSchema(t *testing.T, out, member, schema string) error {
	t.Helper()
	s, err := reportSchema(schema)
	if err != nil {
		t.Fatalf("schema %s: %v", schema, err)
	}
	d := json.NewDecoder(strings.NewReader(out))
	d.UseNumber()
	var r struct {
		ExitCode json.Number                `json:"exit_code"`
		Stats    map[string]json.RawMessage `json:"stats"`
	}
	if err := d.Decode(&r); err != nil {
		return err
	}
	raw, ok := r.Stats[member]
	if !ok {
		return fmt.Errorf("member missing")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return err
	}
	if v == nil {
		if r.ExitCode.String() != "3" {
			return fmt.Errorf("null without a format error (exit %s)", r.ExitCode)
		}
		return nil
	}
	return s.check(member, v)
}

// ---------------------------------------------------------------- table

// vlSoll is what README 11.3 and the registry member why say about one
// vector. Strings "" stand for null; -1 in days means "not compared".
type vlSoll struct {
	status    string
	firstDay  string
	keySource string
	receipts  []int // included, not_included, unchecked, missing, pending, before_start, future; nil: receipts null
	last      string
	days      [6]int // supplied, established, witnessed, contradictory, missing, signatures_not_checked
	head      string
	seenIn    int
	roots     int // tsa.roots_supplied
	foreign   int
	files     [2]int // files, distinct_files
	codes     []string
	// From the witnessed days of the corpus authority E1 (README 11.2):
	headW  bool   // head.witnessed
	upTo   int64  // receipts.included_up_to_tree_size; 0: null
	roots5 [5]int // logged_roots: matching_prefix, matching_without_receipt, contradicting_prefix, beyond_package, gap_witnesses
	klVer  int64  // key_list.version; 0: not compared
}

// Reason codes of the findings of 7.4.11: "CLASS code" or, where the step
// names a reason (L1 item 4, L8 case 4), "CLASS code reason".
const (
	uvNotWitnessed = "VENDOR_LOG_UNVERIFIED day_not_witnessed "
	uvRun          = "VENDOR_LOG_UNVERIFIED days_not_supplied"
	uvNoKey        = "VENDOR_LOG_UNVERIFIED no_protocol_key "
)

var (
	// Every package: the first receipt lies on 2026-01-02 (due at the check
	// time), the second on 2026-01-03 (not due); 8.6 chooses the second as
	// the last countersigned (README 11.1).
	rcDayNotWitnessed = []int{0, 0, 1, 0, 1, 0, 0}
	rcFirstMissing    = []int{0, 0, 0, 1, 1, 0, 0}
	oneDay            = [6]int{1, 1, 0, 0, 0, 0}
	notEstablished    = [6]int{1, 0, 0, 0, 1, 0}
	contraNotEst      = [6]int{1, 0, 0, 1, 1, 0}
	noKeyDays         = [6]int{-1, 0, 0, 0, 0, -1}
)

// established day 2026-01-02, not witnessed (log_day_test_authority).
func witnessless(reason string, f func(*vlSoll)) vlSoll {
	s := vlSoll{status: "checked", firstDay: "2025-12-31", keySource: "list", receipts: rcDayNotWitnessed,
		last: "pending", days: oneDay, head: "2026-01-02", seenIn: 1, roots: 1, files: [2]int{1, 1},
		codes: []string{uvNotWitnessed + reason}}
	if f != nil {
		f(&s)
	}
	return s
}

// no protocol key (L1 item 4): receipts null, L2 to L9 dropped.
func noKey(reason string) vlSoll {
	return vlSoll{status: "no_protocol_key", days: noKeyDays, roots: 1, files: [2]int{1, 1},
		codes: []string{uvNoKey + reason}}
}

// the day 2026-01-02 witnessed by the corpus authority E1 (README 11.2,
// format spec 7.5.7) with a present record of the first receipt: included,
// receipts_logged up to tree_size 5, one root matching a prefix (L9).
func witnessed(f func(*vlSoll)) vlSoll {
	s := vlSoll{status: "checked", firstDay: "2025-12-31", keySource: "list", receipts: []int{1, 0, 0, 0, 1, 0, 0},
		upTo: 5, last: "pending", days: [6]int{1, 1, 1, 0, 0, 0}, head: "2026-01-02", headW: true, seenIn: 1, roots: 1,
		files: [2]int{1, 1}, roots5: [5]int{1, 0, 0, 0, 0}}
	if f != nil {
		f(&s)
	}
	return s
}

// the witnessed day does not carry the receipt (L8 case 3): not_included,
// no root checked.
func witnessedNotIncluded(f func(*vlSoll)) vlSoll {
	return witnessed(func(s *vlSoll) {
		s.receipts, s.upTo, s.roots5 = []int{0, 1, 0, 0, 1, 0, 0}, 0, [5]int{}
		s.codes = []string{"RECEIPT_NOT_LOGGED not_included"}
		if f != nil {
			f(s)
		}
	})
}

// the first receipt is unchecked (L8 case 4 to 6); no root is checked.
func witnessedUnchecked(f func(*vlSoll)) vlSoll {
	return witnessed(func(s *vlSoll) {
		s.receipts, s.upTo, s.roots5 = []int{0, 0, 1, 0, 1, 0, 0}, 0, [5]int{}
		f(s)
	})
}

// the day entry of 2026-01-02 is not established; the due day is missing.
func notEst(days [6]int, codes ...string) vlSoll {
	return vlSoll{status: "checked", firstDay: "2025-12-31", keySource: "list", receipts: rcFirstMissing,
		last: "pending", days: days, roots: 1, files: [2]int{1, 1}, codes: codes}
}

var vlSollwerte = map[string]vlSoll{
	// Bezeugung des Tages (L2 (d), (h), L8 case 4).
	"log_day_test_authority":             witnessless("published_test_key", nil),
	"log_reason_no_timestamp":            witnessless("no_timestamp", nil),
	"log_reason_no_log_root":             witnessless("no_log_root_supplied", func(s *vlSoll) { s.roots = 0 }),
	"log_reason_chain_root_only":         witnessless("no_log_root_supplied", func(s *vlSoll) { s.roots = 0 }),
	"log_reason_outside_profile":         witnessless("outside_profile", nil),
	"log_reason_not_chained":             witnessless("not_chained_to_log_root", nil),
	"log_qualified_log_root":             witnessless("published_test_key", nil),
	"log_timestamp_imprint_wrong":        witnessless("", func(s *vlSoll) { s.codes = []string{"VENDOR_LOG_DEFECTIVE timestamp_defective"} }),
	"log_timestamp_z6_violated":          witnessless("", func(s *vlSoll) { s.codes = []string{"VENDOR_LOG_DEFECTIVE timestamp_defective"} }),
	"log_timestamps_early_late_test_key": witnessless("published_test_key", nil),

	// Protokollschluessel und Signaturen (L1, L2 (a), (b), (e), (f)).
	"log_no_list":                        noKey("no_list"),
	"log_list_no_matching_root":          noKey("no_matching_root"),
	"log_list_signature_fails":           noKey("signature_fails"),
	"log_list_format_violated":           noKey("format_violated"),
	"log_lists_same_version_differ":      noKey("lists_contradictory"),
	"log_list_key_dropped":               noKey("lists_contradictory"),
	"log_lists_filler_commitment_differ": noKey("lists_contradictory"),
	"log_list_key_in_two_roles":          noKey("key_in_two_roles"),
	// 7.4.7, L1 item 2: fuellerbindung is hex64 or null; once set, equal in
	// every later version. null alone and a value set from a later version
	// on leave the list effective; a changed or dropped value contradicts.
	"log_list_filler_commitment_null":       witnessed(func(s *vlSoll) { s.klVer = 1 }),
	"log_lists_filler_commitment_set_later": witnessed(func(s *vlSoll) { s.klVer = 2 }),
	"log_lists_filler_commitment_changed":   noKey("lists_contradictory"),
	"log_lists_filler_commitment_dropped":   noKey("lists_contradictory"),
	"log_list_log_id_differs":               noKey("log_id_differs"),
	// L1 item 4: no list and the only pin dropped (R3 (d)): the reason is
	// key_in_two_roles, not no_list.
	"log_pin_dropped": noKey("key_in_two_roles"),
	"log_pin_only":    witnessless("published_test_key", func(s *vlSoll) { s.keySource = "pinned" }),
	"log_pin_first_day_contradictory": {status: "checked", keySource: "pinned", receipts: []int{0, 0, 2, 0, 0, 0, 0},
		last: "unchecked", days: [6]int{2, 0, 0, 0, 0, 0}, roots: 1, files: [2]int{1, 1},
		codes: []string{"VENDOR_LOG_CONTRADICTION no_common_first_day"}},
	"log_key_not_established": notEst(notEstablished, "VENDOR_LOG_UNVERIFIED key_not_established", uvRun),
	"log_signature_fails":     notEst(notEstablished, "VENDOR_LOG_DEFECTIVE signature", uvRun),
	"log_additional_signature_fails": witnessless("published_test_key", func(s *vlSoll) {
		s.codes = append(s.codes, "VENDOR_LOG_DEFECTIVE signature")
	}),
	"log_key_revoked":                      notEst(notEstablished, "VENDOR_LOG_UNVERIFIED key_validity_ended", uvRun),
	"log_resigned_after_revocation":        witnessless("published_test_key", nil),
	"log_additional_signature_unknown_alg": witnessless("published_test_key", func(s *vlSoll) { s.days[5] = 1 }),

	// Signierte Inhalte (L2 (c), (g), L3, L5).
	"log_entry_format_violation": notEst(contraNotEst, "VENDOR_LOG_CONTRADICTION entry_format", uvRun),
	"log_entry_not_json": witnessless("published_test_key", func(s *vlSoll) {
		s.days = [6]int{2, 1, 0, 0, 0, 0}
		s.codes = append(s.codes, "VENDOR_LOG_CONTRADICTION entry_format")
	}),
	"log_rule_server_ts_before_day_end": notEst(contraNotEst, "VENDOR_LOG_CONTRADICTION entry_rules", uvRun),
	"log_rule_prev_hash_zero":           notEst(contraNotEst, "VENDOR_LOG_CONTRADICTION entry_rules", uvRun),
	"log_rule_day_before_start": witnessless("published_test_key", func(s *vlSoll) {
		s.days = [6]int{2, 1, 0, 1, 0, 0}
		s.codes = append(s.codes, "VENDOR_LOG_CONTRADICTION entry_rules")
	}),
	"log_two_versions": witnessless("", func(s *vlSoll) {
		s.days, s.head = [6]int{4, 4, 0, 1, 0, 0}, "2026-01-01"
		s.codes = []string{"VENDOR_LOG_CONTRADICTION two_versions"}
	}),
	"log_prev_hash_broken": witnessless("published_test_key", func(s *vlSoll) {
		s.days = [6]int{3, 3, 0, 1, 0, 0}
		s.codes = append(s.codes, "VENDOR_LOG_CONTRADICTION does_not_link")
	}),
	"log_skips_day": witnessless("published_test_key", func(s *vlSoll) {
		s.days = [6]int{2, 2, 0, 1, 0, 0}
		s.codes = append(s.codes, "VENDOR_LOG_CONTRADICTION skips_days")
	}),

	// Verlangter Bereich und Klassen der Quittungen (L7, L8).
	"log_day_missing": witnessless("", func(s *vlSoll) {
		s.receipts, s.days, s.head = rcFirstMissing, [6]int{1, 1, 0, 0, 1, 0}, "2026-01-01"
		s.codes = []string{uvRun}
	}),
	"log_receipt_future": witnessless("", func(s *vlSoll) {
		s.receipts, s.last, s.days, s.head = []int{0, 0, 0, 0, 1, 0, 1}, "future", [6]int{2, 2, 0, 0, 0, 0}, "2026-01-01"
		s.codes = []string{"VENDOR_LOG_UNVERIFIED receipt_after_check_time"}
	}),
	"log_receipts_pending": witnessless("", func(s *vlSoll) {
		s.receipts, s.days, s.head, s.codes = []int{0, 0, 0, 0, 2, 0, 0}, [6]int{2, 2, 0, 0, 0, 0}, "2026-01-01", nil
	}),
	"log_receipts_before_start": witnessless("", func(s *vlSoll) {
		s.receipts, s.last, s.days, s.head, s.seenIn, s.codes = []int{0, 0, 0, 0, 0, 2, 0}, "before_start", [6]int{}, "", 0, nil
	}),

	// Nachweise und Auszuege (L6, 7.4.8): no day is usable, so the records
	// of chain C are passed over and counted in no member (decision H);
	// foreign_chain_records counts every record of another chain (G).
	"log_record_not_holding":           witnessless("published_test_key", nil),
	"log_two_records":                  witnessless("published_test_key", func(s *vlSoll) { s.files, s.seenIn = [2]int{2, 2}, 2 }),
	"log_padded_day":                   witnessless("published_test_key", nil),
	"log_absence_between_fillers":      witnessless("published_test_key", func(s *vlSoll) { s.days = [6]int{2, 2, 0, 0, 0, 0} }),
	"log_foreign_chain_records":        witnessless("published_test_key", func(s *vlSoll) { s.files, s.seenIn, s.foreign = [2]int{2, 2}, 2, 1 }),
	"log_mirror_extract":               witnessless("published_test_key", func(s *vlSoll) { s.files, s.days = [2]int{2, 2}, [6]int{3, 3, 0, 0, 0, 0} }),
	"log_extract_server_ts_other_form": witnessless("published_test_key", nil),

	// Bezeugte Tage der Zeitstempelstelle E1 (README 11.2, 11.3; L2 to L9).
	"log_witnessed_included":      witnessed(nil),
	"log_witnessed_not_included":  witnessedNotIncluded(func(s *vlSoll) { s.roots5 = [5]int{1, 1, 0, 0, 0} }),
	"log_witnessed_no_record":     witnessedUnchecked(func(s *vlSoll) { s.codes = []string{"VENDOR_LOG_UNVERIFIED no_chain_day_record"} }),
	"log_witnessed_record_failed": witnessedUnchecked(func(s *vlSoll) { s.codes = []string{"VENDOR_LOG_DEFECTIVE record_does_not_hold"} }),
	"log_witnessed_record_contradictory": witnessedUnchecked(func(s *vlSoll) {
		s.days[3] = 1
		s.codes = []string{"VENDOR_LOG_CONTRADICTION leaf_of_other_day"}
	}),
	"log_witnessed_reason_late": witnessedUnchecked(func(s *vlSoll) {
		s.days, s.headW, s.codes = [6]int{1, 1, 0, 0, 0, 0}, false, []string{uvNotWitnessed + "late"}
	}),
	// Decision I: Z.6 not checkable gives the reason outside_profile.
	"log_witnessed_reason_z6_not_checkable": witnessedUnchecked(func(s *vlSoll) {
		s.days, s.headW, s.codes = [6]int{1, 1, 0, 0, 0, 0}, false, []string{uvNotWitnessed + "outside_profile"}
	}),
	"log_witnessed_premature_stamp": witnessedUnchecked(func(s *vlSoll) {
		s.days, s.head, s.seenIn, s.headW = [6]int{1, 1, 0, 1, 0, 0}, "", 0, false
		s.codes = []string{"VENDOR_LOG_CONTRADICTION closed_before_day_end"}
	}),
	"log_witnessed_window_bounds": witnessed(nil),
	"log_witnessed_two_versions_one_witnessed": witnessed(func(s *vlSoll) {
		s.days, s.codes = [6]int{2, 2, 1, 1, 0, 0}, []string{"VENDOR_LOG_CONTRADICTION two_versions"}
	}),
	"log_witnessed_two_versions_both_witnessed": witnessedUnchecked(func(s *vlSoll) {
		s.days, s.head, s.seenIn, s.headW = [6]int{2, 2, 0, 1, 0, 0}, "", 0, false
		s.codes = []string{"VENDOR_LOG_CONTRADICTION two_versions"}
	}),
	"log_witnessed_key_revoked_signed_before": witnessed(func(s *vlSoll) { s.klVer = 2 }),
	"log_witnessed_key_revoked_signed_after": witnessed(func(s *vlSoll) {
		s.receipts, s.upTo, s.roots5, s.klVer = rcFirstMissing, 0, [5]int{}, 2
		s.days, s.head, s.seenIn, s.headW = notEstablished, "", 0, false
		s.codes = []string{"VENDOR_LOG_UNVERIFIED key_validity_ended", uvRun}
	}),
	"log_witnessed_resigned_after_revocation":  witnessed(func(s *vlSoll) { s.klVer = 2 }),
	"log_witnessed_absent_empty_day":           witnessedNotIncluded(nil),
	"log_witnessed_absent_before_first":        witnessedNotIncluded(nil),
	"log_witnessed_absent_after_last_filler":   witnessedNotIncluded(nil),
	"log_witnessed_absent_between_two_fillers": witnessedNotIncluded(nil),
	// Decision E: gap_witnesses counts distinct roots, two rows of root(1) give 1.
	"log_witnessed_logged_roots": witnessed(func(s *vlSoll) {
		s.roots5, s.codes = [5]int{2, 1, 1, 1, 1}, []string{"LOGGED_ROOT_MISMATCH root_differs"}
	}),
	"log_witnessed_logged_root_mismatch": witnessed(func(s *vlSoll) {
		s.roots5, s.codes = [5]int{1, 0, 1, 0, 0}, []string{"LOGGED_ROOT_MISMATCH root_differs"}
	}),
	// Decisions D and K: the RECEIPT_INVALID receipt has no class and widens
	// no range, but it is still a receipt of its leaf.
	"log_witnessed_receipt_invalid": witnessed(func(s *vlSoll) { s.receipts, s.upTo = []int{0, 0, 0, 0, 1, 0, 0}, 0 }),
	"log_receipt_invalid_outside_range": witnessed(func(s *vlSoll) {
		s.receipts, s.upTo, s.roots5 = []int{0, 0, 0, 0, 1, 0, 0}, 0, [5]int{}
		s.days, s.head, s.headW = [6]int{2, 2, 0, 0, 0, 0}, "2026-01-01", false
	}),
	// Decision B: dayOf reads the type date; the day 1999-12-31 counts.
	"log_witnessed_day_1999": witnessed(func(s *vlSoll) {
		s.days, s.codes = [6]int{2, 1, 1, 1, 0, 0}, []string{"VENDOR_LOG_CONTRADICTION entry_format"}
	}),
	"log_witnessed_qualified_stamp":            witnessed(nil),
	"log_witnessed_qualified_root_plain_stamp": witnessed(nil),
	"log_witnessed_time_anchor_qualified":      witnessed(nil),

	// Group auditor: equal leaf_index of two neighbours keeps the grammar.
	"auditor_log_neighbours_equal_index": witnessless("", func(s *vlSoll) {
		s.receipts, s.days, s.head, s.roots, s.codes = []int{0, 0, 0, 0, 2, 0, 0}, oneDay, "2025-12-31", 0, nil
	}),
}

var (
	reCode   = regexp.MustCompile(`\[([a-z_]+)\]`)
	reReason = regexp.MustCompile(`\(reason ([a-z_]+)`)
)

var vlClasses = map[string]bool{"VENDOR_LOG_UNVERIFIED": true, "VENDOR_LOG_DEFECTIVE": true,
	"VENDOR_LOG_CONTRADICTION": true, "RECEIPT_NOT_LOGGED": true, "LOGGED_ROOT_MISMATCH": true}

func TestKorpusHerstellerprotokoll(t *testing.T) {
	dir := vektor("")
	b, err := os.ReadFile(filepath.Join(dir, "..", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		Testvectors map[string]json.RawMessage `json:"testvectors"`
	}
	if err := json.Unmarshal(b, &reg); err != nil {
		t.Fatal(err)
	}
	var group map[string]struct {
		Auditor *struct {
			Exit int `json:"exit_code"`
		} `json:"auditor_inputs"`
	}
	if err := json.Unmarshal(reg.Testvectors["log"], &group); err != nil {
		t.Fatal(err)
	}
	// Every vector of the group is in the table, unless its audit
	// environment is an unusable invocation (exit 3, no report).
	for name, e := range group {
		if _, ok := vlSollwerte[name]; !ok && (e.Auditor == nil || e.Auditor.Exit != 3) {
			t.Errorf("%s: no row in the table", name)
		}
	}
	names := make([]string, 0, len(vlSollwerte))
	for n := range vlSollwerte {
		names = append(names, n)
	}
	sort.Strings(names)
	n := 0
	for _, name := range names {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			continue // the package is not there yet
		}
		env, err := os.ReadFile(filepath.Join(dir, "pruefer_"+name+".json"))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		args, err := vfy.AuditEnvironmentArgs(env, dir)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		n++
		_, out, errOut := lauf(append(append([]string{"--json", "--now-from-package"}, args...), vektor(name))...)
		if out == "" {
			t.Errorf("%s: no report (%s)", name, strings.TrimSpace(errOut))
			continue
		}
		pruefeVendorLog(t, name, vlSollwerte[name], out, args)
	}
	t.Logf("%d vectors of the vendor log", n)
}

func pruefeVendorLog(t *testing.T, name string, s vlSoll, out string, args []string) {
	t.Helper()
	var r struct {
		Findings []struct {
			Class  string `json:"class"`
			Detail string `json:"detail"`
		} `json:"findings"`
		Stats struct {
			VendorLog *vfy.VendorLogStat `json:"vendor_log"`
		} `json:"stats"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	vl := r.Stats.VendorLog
	if vl == nil {
		t.Errorf("%s: stats.vendor_log is null", name)
		return
	}
	errorf := func(what string, got, want any) {
		t.Helper()
		t.Errorf("%s: %s = %v, want %v", name, what, got, want)
	}
	opt := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	if vl.Status != s.status {
		errorf("status", vl.Status, s.status)
	}
	if got := opt(vl.LogID); got != "ledger-testprotokoll-1" {
		errorf("log_id", got, "ledger-testprotokoll-1")
	}
	if got := opt(vl.FirstDay); got != s.firstDay {
		errorf("first_day", got, s.firstDay)
	}
	if got := opt(vl.KeySource); got != s.keySource {
		errorf("key_source", got, s.keySource)
	}
	// key_list and places name the effective list only (10.10.2).
	withList := s.keySource == "list" || s.keySource == "list_and_pinned"
	if (vl.KeyList != nil) != withList || (len(vl.Places) == 2) != withList {
		errorf("key_list/places", fmt.Sprintf("%+v %v", vl.KeyList, vl.Places), withList)
	}
	if withList && (vl.KeyList.WurzelID != "testwurzel-1" || vl.KeyList.RootSource != "vendor_root") {
		errorf("key_list", *vl.KeyList, "testwurzel-1 from vendor_root")
	}
	if withList && s.klVer != 0 && vl.KeyList.Version != s.klVer {
		errorf("key_list.version", vl.KeyList.Version, s.klVer)
	}
	if vl.Files != s.files[0] || vl.DistinctFiles != s.files[1] {
		errorf("files/distinct_files", [2]int{vl.Files, vl.DistinctFiles}, s.files)
	}
	d := vl.Days
	got := [6]int{d.Supplied, d.Established, d.Witnessed, d.Contradictory, d.Missing, d.SignaturesNotChecked}
	for i := range got {
		if s.days[i] >= 0 && got[i] != s.days[i] {
			errorf("days (supplied, established, witnessed, contradictory, missing, signatures_not_checked)", got, s.days)
			break
		}
	}
	if !vl.TSA.CMSChecked || vl.TSA.RootsSupplied != s.roots {
		errorf("tsa", vl.TSA, s.roots)
	}
	if vl.ForeignChainRecords != s.foreign {
		errorf("foreign_chain_records", vl.ForeignChainRecords, s.foreign)
	}
	if s.receipts == nil {
		if vl.Receipts != nil || vl.LoggedRoots != nil || vl.LastCountersigned != nil {
			errorf("receipts/logged_roots/last_countersigned", fmt.Sprintf("%+v %+v %v", vl.Receipts, vl.LoggedRoots, opt(vl.LastCountersigned)), "null")
		}
	} else {
		rc := vl.Receipts
		if rc == nil {
			errorf("receipts", nil, s.receipts)
		} else if g := []int{rc.Included, rc.NotIncluded, rc.Unchecked, rc.Missing, rc.Pending, rc.BeforeStart, rc.Future}; fmt.Sprint(g) != fmt.Sprint(s.receipts) {
			errorf("receipts (included, not_included, unchecked, missing, pending, before_start, future)", g, s.receipts)
		} else if (rc.IncludedUpToTreeSize == nil) != (s.upTo == 0) || rc.IncludedUpToTreeSize != nil && *rc.IncludedUpToTreeSize != s.upTo {
			errorf("receipts.included_up_to_tree_size", rc.IncludedUpToTreeSize, s.upTo)
		}
		// Only a day witnessed by E1 is usable (README 11.2); without one no
		// root is checked.
		want := vfy.VendorLogRootsStat{MatchingPrefix: s.roots5[0], MatchingWithoutReceipt: s.roots5[1],
			ContradictingPrefix: s.roots5[2], BeyondPackage: s.roots5[3], GapWitnesses: s.roots5[4]}
		if lr := vl.LoggedRoots; lr == nil || *lr != want {
			errorf("logged_roots", lr, want)
		}
		if got := opt(vl.LastCountersigned); got != s.last {
			errorf("last_countersigned", got, s.last)
		}
	}
	if s.head == "" {
		if vl.Head != nil {
			errorf("head", *vl.Head, "null")
		}
	} else if vl.Head == nil {
		errorf("head", nil, s.head)
	} else {
		h := vl.Head
		if h.Day != s.head || h.Witnessed != s.headW || h.SeenIn != s.seenIn {
			errorf("head (day, witnessed, seen_in)", fmt.Sprint(h.Day, h.Witnessed, h.SeenIn), fmt.Sprint(s.head, s.headW, s.seenIn))
		}
		// day_hash and tree_size are those of a day object in the
		// extracts (L4: the head with the day hash of c(head)).
		if !headInExtracts(t, args, h) {
			errorf("head", *h, "a day object of the extracts")
		}
	}
	var codes []string
	for _, f := range r.Findings {
		if !vlClasses[f.Class] {
			continue
		}
		c := f.Class
		if m := reCode.FindStringSubmatch(f.Detail); m != nil {
			c += " " + m[1]
		}
		if m := reReason.FindStringSubmatch(f.Detail); m != nil {
			c += " " + m[1]
		}
		codes = append(codes, c)
	}
	want := make([]string, 0, len(s.codes))
	for _, c := range s.codes {
		want = append(want, strings.TrimSpace(c))
	}
	sort.Strings(codes)
	sort.Strings(want)
	if fmt.Sprint(codes) != fmt.Sprint(want) {
		// A code ending in a space leaves the reason open.
		ok := len(codes) == len(want)
		for i := 0; ok && i < len(codes); i++ {
			ok = codes[i] == want[i] || strings.HasPrefix(codes[i], want[i]+" ")
		}
		if !ok {
			errorf("findings of 7.4.11", codes, want)
		}
	}
}

func headInExtracts(t *testing.T, args []string, h *vfy.VendorLogHeadStat) bool {
	t.Helper()
	for i := 0; i+1 < len(args); i++ {
		if args[i] != "--vendor-log" {
			continue
		}
		b, err := os.ReadFile(args[i+1])
		if err != nil {
			t.Fatal(err)
		}
		var x struct {
			Days []struct {
				Entry struct {
					StatementJCS string `json:"statement_jcs"`
				} `json:"entry"`
			} `json:"days"`
		}
		if err := json.Unmarshal(b, &x); err != nil {
			t.Fatal(err)
		}
		for _, o := range x.Days {
			sum := sha256.Sum256([]byte(o.Entry.StatementJCS))
			if hex.EncodeToString(sum[:]) != h.DayHash {
				continue
			}
			var st struct {
				Day      string `json:"day"`
				TreeSize int64  `json:"tree_size"`
			}
			if json.Unmarshal([]byte(o.Entry.StatementJCS), &st) == nil && st.Day == h.Day && st.TreeSize == h.TreeSize {
				return true
			}
		}
	}
	return false
}
