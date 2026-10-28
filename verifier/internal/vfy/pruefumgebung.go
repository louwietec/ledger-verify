package vfy

// The audit environment of a test vector, ledger-pruefumgebung/1 (format
// spec 10.8, registry auditor_inputs.pruefumgebung): only in the test corpus,
// a file pruefer_<vector>.json gathers the auditor's inputs for one vector.
// The test tools turn it into switches in the order of its members; this file
// is that conversion, so that every harness of the corpus reads the same
// switches.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
)

// AuditEnvironmentFormat names the file format.
const AuditEnvironmentFormat = "ledger-pruefumgebung/1"

// auditEnvMembers are the members in the order the switches are formed, with
// their switch and the grammar of their values (registry
// auditor_inputs.pruefumgebung).
var auditEnvMembers = []struct {
	name, flag string
	file       bool
	value      *regexp.Regexp
}{
	{"vendor_root", "--vendor-root", true, nil},
	{"vendor_key", "--vendor-key", false, rePin},
	{"vendor_key_list", "--vendor-key-list", true, nil},
	{"vendor_log_key", "--vendor-log-key", false, rePin},
	{"vendor_statement_key", "--vendor-statement-key", false, rePin},
	{"tsa_root", "--tsa-root", true, nil},
	{"tsa_qualified_roots", "--tsa-qualified-roots", true, nil},
	{"vendor_log_tsa_root", "--vendor-log-tsa-root", true, nil},
	{"expect_root", "--expect-root", false, regexp.MustCompile(`^(?:[1-9][0-9]*:)?[0-9A-Fa-f]{64}$`)},
	{"vendor_log", "--vendor-log", true, nil},
	{"anchor_history", "--anchor-history", true, nil},
	{"requested_at", "--requested-at", false, nil},
}

// AuditEnvironmentArgs reads a file ledger-pruefumgebung/1 and returns the
// switches it stands for, with every file named relative to dir (the top
// level of the test vectors). korpus true adds the corpus root
// pruefer_herstellerwurzel.json and the pins of
// pruefer_herstellerschluessel.txt first. The check time stays in the
// verify_args.json of the vector.
func AuditEnvironmentArgs(b []byte, dir string) ([]string, error) {
	v, err := auditorJSON(b, 1<<30, AuditEnvironmentFormat)
	if err != nil {
		return nil, err
	}
	names := []string{"format", "korpus"}
	for _, m := range auditEnvMembers {
		names = append(names, m.name)
	}
	if err := closed(v, AuditEnvironmentFormat, names); err != nil {
		return nil, err
	}
	if f, _ := str(v.Get("format")); f != AuditEnvironmentFormat {
		return nil, fmt.Errorf("format is not %q", AuditEnvironmentFormat)
	}
	k := v.Get("korpus")
	if k.Kind != jcs.KindBool {
		return nil, errors.New("korpus is not a bool")
	}
	var args []string
	if k.Bool {
		args = append(args, "--vendor-root", filepath.Join(dir, "pruefer_herstellerwurzel.json"))
		pins, err := os.ReadFile(filepath.Join(dir, "pruefer_herstellerschluessel.txt"))
		if err != nil {
			return nil, err
		}
		for _, p := range strings.Fields(string(pins)) {
			args = append(args, "--vendor-key", p)
		}
	}
	for _, m := range auditEnvMembers {
		x := v.Get(m.name)
		var vals []*jcs.Value
		switch {
		case m.name == "tsa_qualified_roots" || m.name == "requested_at":
			if x.Kind == jcs.KindNull {
				continue
			}
			vals = []*jcs.Value{x}
		case x.Kind == jcs.KindArray:
			vals = x.Arr
		default:
			return nil, fmt.Errorf("%s is not an array", m.name)
		}
		filePattern := regexp.MustCompile(`^pruefer_[a-z0-9_]+\.` + m.name + `-[0-9]+\.[a-z0-9]+$`)
		for _, e := range vals {
			s, ok := str(e)
			if !ok {
				return nil, fmt.Errorf("%s holds a value that is not a string", m.name)
			}
			switch {
			case m.file:
				if !filePattern.MatchString(s) {
					return nil, fmt.Errorf("%s: %q is not a file name of the corpus", m.name, s)
				}
				s = filepath.Join(dir, s)
			case m.value != nil:
				if !m.value.MatchString(s) {
					return nil, fmt.Errorf("%s: %q does not follow its grammar", m.name, s)
				}
			case m.name == "requested_at":
				if _, ok := parseUTC(s); !ok {
					return nil, fmt.Errorf("requested_at: %q is not rfc3339", s)
				}
			}
			args = append(args, m.flag, s)
		}
	}
	return args, nil
}
