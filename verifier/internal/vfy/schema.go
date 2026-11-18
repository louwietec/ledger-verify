package vfy

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
)

// Minimal schema tables, hand-mirrored from spec/registry.json (which is part
// of the open specification). Field kinds cover exactly the types the
// registry uses.

// Own specification version (registry: spec_version).
const (
	specMajor = 1
	specMinor = 10
)

// specMinor is 10 since 03.10.2026: spec 11.2, covered stretches between two
// countersigned checkpoints are stated (stats.unanchored_stretches, no
// finding); no entry or manifest field changed. It was 9 from the night of
// 29.09.2026 (export seal, edge cases, measured residual window) and 8 from
// the evening of 29.09.2026 (GENESIS.license_id is the licence commitment).
// It was 7 from 29.09.2026: spec 4.24/9.3, the critical entry type
// LEGAL_HOLD sets or releases a deletion hold, and a CONTENT_DELETED whose
// target AI_CALL an active hold covers is the finding HOLD_VIOLATION (exit 1).
// It was 6 from 28.09.2026 (evening): spec 8.6, the chain end is either
// sealed (SEAL + immediate checkpoint + receipts on it, whatever the reason) or
// incomplete (finding UNSEALED_END, exit 4), and the exit code follows the
// precedence 3 > 2 > 4 > 1 > 0 (spec 10.3). No entry or manifest field
// changed. It was 5 from earlier the same day: the entry type
// CAPTURE_TRUNCATED (spec 4.23) names an AI_CALL whose capture the gateway cut
// at max_body_bytes. It was 4 from the release of 25.09.2026: spec 7.1/10.7, vendor keys
// are established by the auditor's trust anchor (RECEIPT_UNVERIFIED). It was 3
// from 15.09.2026 (evening): spec 10.6 R5, the extensible evidence-package
// manifest. It was 2 earlier the same day for the
// external time witness (entry type TIME_ANCHOR, spec 7.3), and 1 since
// 14.09.2026 for spec 10.6 forward compatibility, the entry type
// CONTENT_DISCLOSED and the anchor's consistency_proof. Chains and manifests
// written under an older MINOR are accepted without a finding.

// The two constants above mirror the registry's top-level spec_version
// "MAJOR.MINOR" and are the yardstick of the forward-compatibility rule
// (spec 10.6): same MAJOR and a MINOR <= specMinor is the normal case; a
// newer MINOR is the finding SPEC_NEWER (exit 1) and the run continues with
// the rules this version knows; a different MAJOR is FORMAT_ERROR (exit 3).

type fieldSpec struct {
	kind     string // const | uuid | int | rfc3339 | hex64 | hex128 | enum | open_enum | version | string | bool | object | array
	nullable bool
	constVal string
	values   []string // enum values
	min      int64
	hasMin   bool
	max      int64
	hasMax   bool
	maxLen   int // string: max length in Unicode characters; 0 = unlimited
	fields   map[string]fieldSpec
}

func fInt(min int64) fieldSpec { return fieldSpec{kind: "int", min: min, hasMin: true} }
func fIntN(min int64) fieldSpec {
	return fieldSpec{kind: "int", min: min, hasMin: true, nullable: true}
}
func fIntMM(min, max int64) fieldSpec {
	return fieldSpec{kind: "int", min: min, hasMin: true, max: max, hasMax: true}
}
func fStr(maxLen int) fieldSpec      { return fieldSpec{kind: "string", maxLen: maxLen} }
func fStrN(maxLen int) fieldSpec     { return fieldSpec{kind: "string", maxLen: maxLen, nullable: true} }
func fEnum(vals ...string) fieldSpec { return fieldSpec{kind: "enum", values: vals} }
func fHex64() fieldSpec              { return fieldSpec{kind: "hex64"} }
func fHex64N() fieldSpec             { return fieldSpec{kind: "hex64", nullable: true} }
func fHex128() fieldSpec             { return fieldSpec{kind: "hex128"} }
func fUUID() fieldSpec               { return fieldSpec{kind: "uuid"} }
func fTS() fieldSpec                 { return fieldSpec{kind: "rfc3339"} }
func fBool() fieldSpec               { return fieldSpec{kind: "bool"} }
func fConst(v string) fieldSpec      { return fieldSpec{kind: "const", constVal: v} }

// fVersion: spec_version "MAJOR.MINOR" judged against specMajor/specMinor
// (spec 10.6 R1); the MINOR comparison is reported by the caller, not here.
func fVersion() fieldSpec { return fieldSpec{kind: "version"} }

// fOpenEnum: like fEnum, but a value outside the known list is NOT a schema
// error (spec 10.6 R2); the known values are kept for the mirror check and
// for the caller's membership decision.
func fOpenEnum(vals ...string) fieldSpec { return fieldSpec{kind: "open_enum", values: vals} }
func fObjN(f map[string]fieldSpec) fieldSpec {
	return fieldSpec{kind: "object", nullable: true, fields: f}
}

// Enumerations (registry: provider_classes, gap_classes, alarm_rules).
var providerClasses = []string{"openai", "anthropic", "azure_openai", "google", "aws_bedrock", "mistral", "aleph_alpha", "ionos", "ollama", "vllm", "other_us", "other_eu", "other_local", "generic"}
var gapClasses = []string{"bypass", "proxy_restart", "power_loss", "spool_unwritable", "host_down", "update", "manual"}
var alarmRules = []string{"source_silence", "volume_spike", "error_rate_spike", "new_provider_class", "spool_backlog", "disk_85", "disk_92", "disk_97", "cert_expiry", "anchor_overdue", "report_missing", "report_delivery_failed", "component_silence", "test_alarm"}

// criticalTypes are entry types with the immediate-checkpoint obligation.
var criticalTypes = map[string]bool{
	"GENESIS": true, "GAP": true, "MODE_CHANGE": true, "SEAL": true,
	"OVERSIGHT": true, "KEY_ROTATION": true, "CONTENT_DELETED": true, "CONTENT_DISCLOSED": true,
	"LEGAL_HOLD": true,
}

// envelopeFields per registry envelope_fields (entry_hash checked separately).
// The envelope is the contract: an undefined envelope field stays
// FORMAT_ERROR (spec 10.6 R3) — only spec_version and event_type are open.
var envelopeFields = map[string]fieldSpec{
	"spec_version":  fVersion(),
	"chain_id":      fUUID(),
	"seq":           fInt(1),
	"ts_captured":   fTS(),
	"ts_chained":    fTS(),
	"mono_delta_ms": fInt(-1),
	"event_type":    fOpenEnum(eventTypeNames()...),
	"origin":        fEnum("proxy", "import", "portal", "system"),
	"payload":       {kind: "object"},
	"prev_hash":     fHex64(),
	"entry_hash":    fHex64(),
}

// payloadFields per registry event_types.
var payloadFields = map[string]map[string]fieldSpec{
	"GENESIS": {
		"customer_id":       fStr(128),
		"appliance_id":      fUUID(),
		"device_pubkey":     fHex64(),
		"device_key_id":     fStr(64),
		"license_id":        fStr(64),
		"edition":           fEnum("starter", "pro", "group", "enterprise"),
		"purpose_statement": fStr(2000),
		"language":          fEnum("de", "en"),
		"timezone":          fStr(64),
		"predecessor_chain": fObjN(map[string]fieldSpec{
			"chain_id":        fUUID(),
			"last_entry_hash": fHex64(),
			"reason":          fStr(500),
		}),
	},
	"AI_CALL": {
		"provider_class":      fEnum(providerClasses...),
		"route":               fStr(200),
		"model":               fStrN(200),
		"endpoint":            fStr(400),
		"http_status":         fIntMM(0, 599),
		"outcome":             fEnum("ok", "error", "upstream_error", "aborted"),
		"duration_ms":         fInt(0),
		"request_bytes":       fInt(0),
		"response_bytes":      fInt(0),
		"tokens_in":           fIntN(0),
		"tokens_out":          fIntN(0),
		"streamed":            fBool(),
		"confidence":          fEnum("recorded", "claimed"),
		"source_id":           fStrN(128),
		"source_ref":          fStrN(256),
		"mode":                fEnum("full", "hash_only"),
		"request_commitment":  fHex64N(),
		"response_commitment": fHex64N(),
		"vault_ref":           fStrN(128),
	},
	"TICK": {
		"uptime_s":      fInt(0),
		"spool_backlog": fInt(0),
		"disk_pct":      fIntMM(0, 100),
	},
	"GAP": {
		"reason":     fEnum(gapClasses...),
		"started_ts": fTS(),
		"ended_ts":   fTS(),
		"lost_count": fInt(-1),
		"detail":     fStrN(500),
	},
	"SOURCE_GAP": {
		"source_id":    fStr(128),
		"window_start": fTS(),
		"window_end":   fTS(),
		"expected":     fIntN(0),
		"observed":     fInt(0),
		"detail":       fStrN(500),
	},
	"RECONCILIATION": {
		"source_id":      fStr(128),
		"window_start":   fTS(),
		"window_end":     fTS(),
		"reported_count": fInt(0),
		"chained_count":  fInt(0),
		"delta":          {kind: "int"},
	},
	"CLOCK_JUMP": {
		"wall_before":   fTS(),
		"wall_after":    fTS(),
		"mono_delta_ms": fInt(0),
		"jump_ms":       {kind: "int"},
	},
	"MODE_CHANGE": {
		"from":  fEnum("full", "hash_only"),
		"to":    fEnum("full", "hash_only"),
		"cause": fEnum("manual", "disk_pressure"),
		"actor": fStrN(128),
	},
	"RESTART": {
		"reason":               fEnum("crash_recovery", "self_terminate", "update", "manual", "unknown"),
		"downtime_ms_estimate": fInt(-1),
		"version":              fStr(40),
	},
	"SEAL": {
		"version": fStr(40),
		"reason":  fEnum("update", "shutdown", "key_loss", "decommission", "export"),
	},
	"RESUME": {
		"prev_version":      fStr(40),
		"new_version":       fStr(40),
		"sealed_entry_hash": fHex64(),
	},
	"OVERSIGHT": {
		"action":        fEnum("approval", "rejection", "escalation"),
		"user":          fStr(128),
		"role":          fStr(64),
		"reference":     fStr(256),
		"justification": fStr(4000),
	},
	"ALARM": {
		"rule_id":        fEnum(alarmRules...),
		"severity":       fEnum("info", "warning", "critical"),
		"message_key":    fStr(128),
		"details":        fStrN(1000),
		"delivered_smtp": fBool(),
	},
	"CONFIG_CHANGE": {
		"scope":            fEnum("onboarding", "source", "rule", "alarm", "smtp", "tls", "system", "compliance_signoff"),
		"key":              fStr(128),
		"value_commitment": fHex64N(),
		"summary":          fStrN(500),
		"actor":            fStr(128),
		"step_id":          fStrN(64),
	},
	"KEY_ROTATION": {
		"old_key_id":           fStr(64),
		"new_key_id":           fStr(64),
		"new_pubkey":           fHex64(),
		"signature_by_old_key": fHex128(),
	},
	"REPORT_ISSUED": {
		"report_type":      fEnum("monthly", "quarterly", "audit"),
		"period_start":     fTS(),
		"period_end":       fTS(),
		"tree_size":        fInt(0),
		"html_hash":        fHex64(),
		"pdf_hash":         fHex64N(),
		"renderer_version": fStr(64),
		"languages":        fStr(16),
	},
	"CONTENT_DELETED": {
		"target_seq": fInt(1),
		"vault_ref":  fStr(128),
		"reason":     fEnum("retention", "dsgvo_request", "manual"),
		"actor":      fStr(128),
	},
	"CONTENT_DISCLOSED": {
		"target_seq":     fInt(1),
		"vault_ref":      fStr(128),
		"actor":          fStr(128),
		"role":           fStr(64),
		"reason":         fEnum("audit", "dsgvo_request", "incident", "manual"),
		"request_bytes":  fInt(0),
		"response_bytes": fInt(0),
	},
	"ADMIN": {
		"message_type":      fEnum("activation", "heartbeat", "anchor"),
		"payload_canonical": fStr(16000),
		"payload_hash":      fHex64(),
	},
	"CHECKPOINT": {
		"tree_size":            fInt(1),
		"merkle_root":          fHex64(),
		"prev_checkpoint_hash": fHex64(),
		"key_id":               fStr(64),
		"signature":            fHex128(),
	},
	"CHECKPOINT_RECEIPT": {
		"checkpoint_seq":   fInt(1),
		"tree_size":        fInt(1),
		"merkle_root":      fHex64(),
		"server_ts":        fTS(),
		"server_key_id":    fStr(64),
		"server_signature": fHex128(),
	},
	"TIME_ANCHOR": {
		"checkpoint_seq": fInt(1),
		"tree_size":      fInt(1),
		"merkle_root":    fHex64(),
		"tsa_name":       fStr(256),
		"tsa_policy":     fStr(128),
		"tsa_serial":     fStr(128),
		"tsa_ts":         fTS(),
		"token_base64":   fStr(21848),
	},
	"CAPTURE_TRUNCATED": {
		"target_seq":              fInt(1),
		"request_bytes_captured":  fInt(0),
		"response_bytes_captured": fInt(0),
		"request_truncated":       fBool(),
		"response_truncated":      fBool(),
	},
	// LEGAL_HOLD (spec 4.24, since 1.7): sets or releases a deletion hold.
	// The scope bounds are ordinary rfc3339 values; the unbounded sentinels
	// 0001-01-01T00:00:00Z and 9999-12-31T23:59:59Z lie inside the year range
	// of spec 2, so parseRFC3339 takes them without a special case.
	"LEGAL_HOLD": {
		"action":     fEnum("set", "release"),
		"hold_id":    fStr(64),
		"scope_from": fTS(),
		"scope_to":   fTS(),
		"reference":  fStr(200),
		"actor":      fStr(128),
	},
	// DATA_ACCESS (spec 4.25, since 1.10): a recorded access to customer data
	// of a vendor, written only by the vendor's access chain. Not critical, no
	// finding; only uuid, enum and hex64 fields, so it carries no free text.
	"DATA_ACCESS": {
		"access_id":         fUUID(),
		"actor_kind":        fEnum("person", "service"),
		"actor_id":          fUUID(),
		"purpose":           fEnum("support", "license_admin", "affiliation_upkeep", "fleet_supervision", "incident", "maintenance", "restore", "data_subject_request", "legal_order", "audit", "service", "other"),
		"data_class":        fEnum("license", "registration", "heartbeat", "chain", "journal", "affiliation_register", "alarm_contact", "order_system", "credentials", "access_chain", "operations_log", "backup", "store", "other"),
		"access_mode":       fEnum("read", "change", "export"),
		"scope":             fEnum("one_customer", "several_customers", "all_customers"),
		"record_commitment": fHex64(),
		"capture":           fEnum("gate", "declared", "emergency"),
	},
}

func eventTypeNames() []string {
	return []string{"GENESIS", "AI_CALL", "TICK", "GAP", "SOURCE_GAP", "RECONCILIATION",
		"CLOCK_JUMP", "MODE_CHANGE", "RESTART", "SEAL", "RESUME", "OVERSIGHT", "ALARM",
		"CONFIG_CHANGE", "KEY_ROTATION", "REPORT_ISSUED", "CONTENT_DELETED", "CONTENT_DISCLOSED", "ADMIN",
		"CHECKPOINT", "CHECKPOINT_RECEIPT", "TIME_ANCHOR", "CAPTURE_TRUNCATED", "LEGAL_HOLD", "DATA_ACCESS"}
}

// manifestFields per registry pruefpaket_manifest.
var manifestFields = map[string]fieldSpec{
	"spec_version": fVersion(),
	"chain_id":     fUUID(),
	"created_ts":   fTS(),
	"tree_size":    fInt(0),
	"segments": {kind: "array", fields: map[string]fieldSpec{
		"file":      fStr(128),
		"sha256":    fHex64(),
		"first_seq": fInt(1),
		"last_seq":  fInt(1),
	}},
	"device_pubkeys": {kind: "array", fields: map[string]fieldSpec{
		"key_id": fStr(64),
		"pubkey": fHex64(),
	}},
	"vendor_pubkeys": {kind: "array", fields: map[string]fieldSpec{
		"key_id": fStr(64),
		"pubkey": fHex64(),
	}},
}

var (
	reUUID   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reHex64  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reHex128 = regexp.MustCompile(`^[0-9a-f]{128}$`)
	// MAJOR and MINOR without leading zeros (spec section 2): "01.0" and "1.00"
	// are malformed, not aliases of 1.0 — the Python verifier and the generated
	// JSON schema judge them the same way (measured 2026-09-13: strconv.Atoi
	// had accepted "01.0" as 1.0 and overflowed on a long MINOR).
	reVersion = regexp.MustCompile(`^([1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
)

// checkSpecVersion judges a spec_version string "MAJOR.MINOR" (spec 10.6 R1).
// err != nil: malformed or different MAJOR — a schema error (FORMAT_ERROR).
// newer: same MAJOR, MINOR greater than this verifier's — NOT an error; the
// caller reports SPEC_NEWER once per package and keeps checking.
func checkSpecVersion(path, s string) (newer bool, err error) {
	m := reVersion.FindStringSubmatch(s)
	if m == nil {
		return false, fmt.Errorf("%s: %q is not a version of the form MAJOR.MINOR", path, s)
	}
	if m[1] != strconv.Itoa(specMajor) {
		return false, fmt.Errorf("%s: major version %s differs from this verifier's %d.%d (spec 10.6)", path, m[1], specMajor, specMinor)
	}
	return minorNewer(m[2], strconv.Itoa(specMinor)), nil
}

// minorNewer compares two MINOR strings without leading zeros as whole
// numbers of any length: a longer digit string is the larger number, equal
// lengths compare lexicographically. No integer conversion, so a MINOR of any
// digit count is judged, never overflowed into FORMAT_ERROR (spec 10.6 R1).
func minorNewer(got, own string) bool {
	if len(got) != len(own) {
		return len(got) > len(own)
	}
	return got > own
}

// parseRFC3339 parses a spec timestamp: RFC 3339, UTC, suffix Z required.
//
// The shape is gated by the grammar of spec 2/10.7 (reUTCTime, ASCII digits,
// a period before the fraction, then Z) BEFORE time.Parse sees the string.
// time.Parse alone is not that grammar: when its RFC 3339 fast path fails it
// falls back to the general layout parser, which takes ',' as the fraction
// separator and a one-digit hour — "2026-01-01T00:00:00,5Z" read as .5 s and
// "2026-01-01T1:00:00Z" as 01:00. verifier2 rejects both as FORMAT_ERROR, so
// the two verifiers judged the same LEGAL_HOLD scope and the same ts_captured
// differently (review of 29.09.: exit 1 here, exit 3 there). Every rfc3339
// field of the package goes through this function.
func parseRFC3339(s string) (time.Time, error) {
	if !reUTCTime.MatchString(s) {
		return time.Time{}, fmt.Errorf("timestamp %q is not YYYY-MM-DDThh:mm:ss[.fraction]Z with ASCII digits (spec 2, 10.7)", s)
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, err
	}
	if len(s) == 0 || s[len(s)-1] != 'Z' {
		return time.Time{}, fmt.Errorf("timestamp %q not in UTC with suffix Z", s)
	}
	// Spec 2 (since 25.09.): the year lies in 0001-9999, as in 10.7. Go's
	// time package takes year 0000, Python's datetime does not — the two
	// verifiers judged such a chain differently (exit 0 against exit 3).
	if t.Year() < 1 {
		return time.Time{}, fmt.Errorf("timestamp %q: year before 0001", s)
	}
	return t, nil
}

// ParseTime reads an instant the AUDITOR supplies — the check time --now —
// with exactly the grammar of the package's rfc3339 type (spec 10.8, from
// 1.9): UTC with Z, uppercase T, ASCII digits, year 0001-9999, fractions cut
// after the ninth digit. A value without a zone, with an offset, with a blank
// instead of T, as a week date or without seconds is an error — never read in
// the host's time zone. The CLIs make an error an unusable invocation (exit 3).
func ParseTime(s string) (time.Time, error) {
	t, err := parseRFC3339(s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

// validateField checks one value against its spec; path is used in errors.
func validateField(path string, spec fieldSpec, v *jcs.Value) error {
	return validateFieldOffen(path, spec, v, nil)
}

// validateFieldOffen carries the R5 collector of validateObjectOffen down
// through nested objects and arrays, so the manifest's segments,
// device_pubkeys and vendor_pubkeys are open as well. nil = strict.
func validateFieldOffen(path string, spec fieldSpec, v *jcs.Value, offen *[]string) error {
	if v == nil {
		return fmt.Errorf("%s: field missing", path)
	}
	if v.Kind == jcs.KindNull {
		if spec.nullable {
			return nil
		}
		return fmt.Errorf("%s: null not allowed", path)
	}
	switch spec.kind {
	case "const":
		if v.Kind != jcs.KindString || v.Str != spec.constVal {
			return fmt.Errorf("%s: must be const %q", path, spec.constVal)
		}
	case "uuid":
		if v.Kind != jcs.KindString || !reUUID.MatchString(v.Str) {
			return fmt.Errorf("%s: not a lowercase uuid", path)
		}
	case "int":
		if v.Kind != jcs.KindInt {
			return fmt.Errorf("%s: not an integer", path)
		}
		if spec.hasMin && v.Int < spec.min {
			return fmt.Errorf("%s: %d below min %d", path, v.Int, spec.min)
		}
		if spec.hasMax && v.Int > spec.max {
			return fmt.Errorf("%s: %d above max %d", path, v.Int, spec.max)
		}
	case "rfc3339":
		if v.Kind != jcs.KindString {
			return fmt.Errorf("%s: not a string", path)
		}
		if _, err := parseRFC3339(v.Str); err != nil {
			return fmt.Errorf("%s: %v", path, err)
		}
	case "hex64":
		if v.Kind != jcs.KindString || !reHex64.MatchString(v.Str) {
			return fmt.Errorf("%s: not 64 lowercase hex characters", path)
		}
	case "hex128":
		if v.Kind != jcs.KindString || !reHex128.MatchString(v.Str) {
			return fmt.Errorf("%s: not 128 lowercase hex characters", path)
		}
	case "enum":
		if v.Kind != jcs.KindString {
			return fmt.Errorf("%s: not a string", path)
		}
		for _, ev := range spec.values {
			if v.Str == ev {
				return nil
			}
		}
		return fmt.Errorf("%s: %q not in enum", path, v.Str)
	case "open_enum":
		// Membership is deliberately NOT judged here (spec 10.6 R2): an
		// unknown value is a finding for the caller, not a schema error.
		if v.Kind != jcs.KindString {
			return fmt.Errorf("%s: not a string", path)
		}
	case "version":
		if v.Kind != jcs.KindString {
			return fmt.Errorf("%s: not a string", path)
		}
		if _, err := checkSpecVersion(path, v.Str); err != nil {
			return err
		}
	case "string":
		if v.Kind != jcs.KindString {
			return fmt.Errorf("%s: not a string", path)
		}
		if spec.maxLen > 0 && utf8.RuneCountInString(v.Str) > spec.maxLen {
			return fmt.Errorf("%s: exceeds maxlen %d", path, spec.maxLen)
		}
	case "bool":
		if v.Kind != jcs.KindBool {
			return fmt.Errorf("%s: not a bool", path)
		}
	case "object":
		if v.Kind != jcs.KindObject {
			return fmt.Errorf("%s: not an object", path)
		}
		if spec.fields != nil {
			return validateObjectOffen(path, spec.fields, v, offen)
		}
	case "array":
		if v.Kind != jcs.KindArray {
			return fmt.Errorf("%s: not an array", path)
		}
		for i, el := range v.Arr {
			if err := validateFieldOffen(fmt.Sprintf("%s[%d]", path, i), fieldSpec{kind: "object", fields: spec.fields}, el, offen); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("%s: unknown spec kind %q", path, spec.kind)
	}
	return nil
}

// validateObject enforces the exact field set: every defined field present,
// no undefined fields (spec section 2, completeness rule).
func validateObject(path string, fields map[string]fieldSpec, v *jcs.Value) error {
	return validateObjectOffen(path, fields, v, nil)
}

// validateObjectOffen is validateObject with an optional collector for fields
// the schema does not define (spec 10.6 R5).
//
// offen == nil is the STRICT path and stays exactly as before: an undefined
// field is a schema error. That is deliberate — the envelope and the payloads
// of known entry types must not loosen by accident (R3), so the open behaviour
// is a separate entry point rather than a flag on the common one.
//
// offen != nil is the OPEN path: an undefined field is appended (as
// "path.field") and the walk continues. The caller decides how to report it;
// the collector is deliberately raw and unsorted, because ranging over the
// fields map is not deterministic — whoever reports must sort.
// / offen == nil keeps the strict behaviour; offen != nil collects undefined
// field paths instead of erroring, for the caller to report.
func validateObjectOffen(path string, fields map[string]fieldSpec, v *jcs.Value, offen *[]string) error {
	if v.Kind != jcs.KindObject {
		return fmt.Errorf("%s: not an object", path)
	}
	for _, m := range v.Members {
		if _, ok := fields[m.Key]; !ok {
			if offen == nil {
				return fmt.Errorf("%s: undefined field %q", path, m.Key)
			}
			*offen = append(*offen, path+"."+m.Key)
		}
	}
	for name, spec := range fields {
		mv := v.Get(name)
		if mv == nil {
			return fmt.Errorf("%s: missing field %q", path, name)
		}
		if err := validateFieldOffen(path+"."+name, spec, mv, offen); err != nil {
			return err
		}
	}
	return nil
}

// entryNotes carries the non-error signals of validateEntry to the caller
// (spec 10.6). They are findings of exit class 1, not schema errors; the
// caller decides how often to report them (SPEC_NEWER once per package,
// UNKNOWN_ENTRY_TYPE once per type name).
type entryNotes struct {
	specNewer   bool   // spec_version has a newer MINOR than this verifier (10.6 R1)
	unknownType bool   // event_type unknown to this verifier (10.6 R2)
	typeName    string // the unknown type name; may be "" — an empty event_type is a
	// string outside the known list like any other, so the flag, not the name,
	// carries the signal (measured 2026-09-13: with "" as sentinel an empty
	// event_type produced no finding at all)
}

// validateEntry checks envelope and type-specific payload of one entry.
//
// An unknown event_type is NOT an error (spec 10.6 R2): the envelope has
// already been validated in full (so seq, hashes and timestamps are usable
// for the chain checks) and payload is known to be an object; the payload's
// fields are not judged, and the type name is handed back in entryNotes.
// Payload fields of KNOWN types stay strict (completeness, no undefined
// fields; 10.6 R3).
func validateEntry(v *jcs.Value) (entryNotes, error) {
	var n entryNotes
	// The 10.6 signals are read BEFORE the schema verdict and handed back
	// alongside an error: a finding of rule 1 or 2 is reported even when the
	// same object also carries a FORMAT_ERROR (spec 10.6 R3, last sentence).
	if sv := v.Get("spec_version"); sv != nil && sv.Kind == jcs.KindString {
		if newer, err := checkSpecVersion("entry.spec_version", sv.Str); err == nil {
			n.specNewer = newer
		}
	}
	var pf map[string]fieldSpec
	if et := v.Get("event_type"); et != nil && et.Kind == jcs.KindString {
		var known bool
		if pf, known = payloadFields[et.Str]; !known {
			n.unknownType, n.typeName = true, et.Str
		}
	}
	if err := validateObject("entry", envelopeFields, v); err != nil {
		return n, err
	}
	if n.unknownType {
		return n, nil
	}
	et := v.Get("event_type").Str
	if err := validateObject("payload("+et+")", pf, v.Get("payload")); err != nil {
		return n, err
	}
	if et == "GENESIS" {
		return n, checkGenesisLicense(v.Get("spec_version").Str, v.Get("payload").Get("license_id").Str)
	}
	return n, nil
}

// licenseCommitmentMinor is the MINOR (of MAJOR 1) from which GENESIS.
// license_id MUST be the licence commitment (spec 4.1, 10.6 rule 3).
const licenseCommitmentMinor = "8"

// checkGenesisLicense: from spec 1.8 GENESIS.license_id is the licence
// commitment — 64 lowercase hex, SHA-256 over the key — and anything else is
// FORMAT_ERROR (spec 4.1). What counts is the GENESIS entry's OWN spec_version,
// which its entry_hash covers, not the manifest's: a GENESIS written under 1.7
// keeps whatever it carries and is only pointed out (genesisLicenseNotice).
// The envelope has passed validateObject, so spec_version has the form
// MAJOR.MINOR with this verifier's MAJOR.
func checkGenesisLicense(specVersion, licenseID string) error {
	_, minor, _ := strings.Cut(specVersion, ".")
	if minor != licenseCommitmentMinor && !minorNewer(minor, licenseCommitmentMinor) {
		return nil
	}
	if !reHex64.MatchString(licenseID) {
		return fmt.Errorf("payload(GENESIS): license_id is not the licence commitment (64 lowercase hex), required from spec 1.%s for a GENESIS of spec %s (spec 4.1)", licenseCommitmentMinor, specVersion)
	}
	return nil
}
