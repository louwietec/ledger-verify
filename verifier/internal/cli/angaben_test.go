package cli

// Inputs of the auditor on the command line (format spec 10.8): every usage
// error is an unusable invocation, exit 3 with the reason on stderr and no
// report; and the helper mode zeitstempel (not normative).

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
)

func TestAngabenUnbrauchbar(t *testing.T) {
	ziel := vektor("valid_basic")
	pin := strings.Repeat("a", 64)
	qual := filepath.Join(t.TempDir(), "q.json")
	if err := os.WriteFile(qual, []byte(`{"format":"ledger-tsa-qualifiziert/1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	liste := datei(t, "liste.json", `{"format":"ledger-schluesselrollen/1"}`)
	fremd := datei(t, "fremd.json", `{"format":"ledger-schluesselrollen/9"}`)
	gross := filepath.Join(t.TempDir(), "gross.json")
	if err := os.WriteFile(gross, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(gross, 33554433); err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct {
		why   string
		args  []string
		grund string
	}{
		{"--now twice", []string{"--now", "2026-01-01T00:00:00Z", "--now", "2026-01-02T00:00:00Z"}, "--now is given more than once"},
		{"--lang twice", []string{"--lang", "de", "--lang", "de"}, "--lang is given more than once"},
		{"--requested-at twice", []string{"--requested-at", "2026-01-01T00:00:00Z", "--requested-at", "2026-01-01T00:00:00Z"}, "--requested-at is given more than once"},
		{"--tsa-qualified-roots twice", []string{"--tsa-qualified-roots", qual, "--tsa-qualified-roots", qual}, "--tsa-qualified-roots is given more than once"},
		{"an unknown switch", []string{"--vendor-log-root", "x"}, "unknown flag --vendor-log-root"},
		{"a missing file", []string{"--vendor-key-list", filepath.Join(t.TempDir(), "fehlt.json")}, "--vendor-key-list"},
		{"an unknown format of a key list", []string{"--vendor-key-list", fremd}, "unknown format"},
		{"a file of the qualified roots against its grammar", []string{"--tsa-qualified-roots", qual}, "--tsa-qualified-roots"},
		{"an extract above 32 MiB", []string{"--vendor-log", gross}, "above the limit"},
		{"a statements pin against its grammar", []string{"--vendor-statement-key", "k=" + pin[:10]}, "--vendor-statement-key"},
		{"a protocol pin equal to a statements pin", []string{"--vendor-statement-key", "k=" + pin, "--vendor-log-key", "l=" + pin}, "two roles"},
		{"a statements pin equal in key_id to a countersigning pin", []string{"--vendor-key", "k=" + strings.Repeat("b", 64), "--vendor-statement-key", "k=" + pin}, "two roles"},
		{"--requested-at after --now", []string{"--now", "2026-01-01T00:00:00Z", "--requested-at", "2026-01-01T00:00:00.001Z"}, "lies after the check time"},
		{"--requested-at with an offset", []string{"--requested-at", "2026-01-01T00:00:00+01:00"}, "--requested-at"},
		{"a PEM file for the log without a block", []string{"--vendor-log-tsa-root", datei(t, "x.pem", "text\n")}, "no CERTIFICATE block"},
		{"an anchor history that is no JSON", []string{"--anchor-history", datei(t, "h.json", "{")}, "not I-JSON"},
	} {
		code, out, errOut := lauf(append(append([]string{"--json"}, f.args...), ziel)...)
		if code != 3 || out != "" || !strings.HasPrefix(errOut, Name+": ") || !strings.Contains(errOut, f.grund) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want exit 3, no report, %q", f.why, code, out, errOut, f.grund)
		}
	}
	// A switch without its value.
	if code, out, errOut := lauf("--json", "--vendor-key-list"); code != 3 || out != "" || !strings.HasPrefix(errOut, Name+": --vendor-key-list needs a value") {
		t.Errorf("a missing value: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	// Inputs that keep their grammar run, whatever their content.
	code, out, errOut := lauf("--json", "--now-from-package", "--vendor-key-list", liste, "--requested-at", "2025-12-31T00:00:00Z", ziel)
	if code == 3 || errOut != "" || !strings.Contains(out, `"key_roles"`) {
		t.Errorf("a role list that does not hold: exit %d, stderr %q", code, errOut)
	}
	var r struct {
		Stats struct {
			KeyRoles struct {
				Status string  `json:"status"`
				Reason *string `json:"reason"`
			} `json:"key_roles"`
		} `json:"stats"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil || r.Stats.KeyRoles.Status != "not_effective" || r.Stats.KeyRoles.Reason == nil || *r.Stats.KeyRoles.Reason != "format" {
		t.Errorf("key_roles %+v, %v", r.Stats.KeyRoles, err)
	}
}

// subjectOf is the signed subject (format spec 6.1) of the checkpoint at seq
// in a vector's first segment, the bytes its time witness stamps.
func subjectOf(t *testing.T, name string, seq int64) []byte {
	t.Helper()
	f, err := os.Open(vektor(filepath.Join(name, "segments", "chain-000001.jsonl")))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var e struct {
			Seq     int64          `json:"seq"`
			ChainID string         `json:"chain_id"`
			TS      string         `json:"ts_chained"`
			Payload map[string]any `json:"payload"`
		}
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		if e.Seq != seq {
			continue
		}
		b, err := jcs.CanonGo(map[string]any{"chain_id": e.ChainID, "tree_size": int64(e.Payload["tree_size"].(float64)),
			"merkle_root": e.Payload["merkle_root"], "prev_checkpoint_hash": e.Payload["prev_checkpoint_hash"],
			"key_id": e.Payload["key_id"], "ts": e.TS})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	t.Fatalf("no seq %d", seq)
	return nil
}

func tokenOf(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(vektor(filepath.Join(name, "segments", "chain-000001.jsonl")))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.Contains(l, `"TIME_ANCHOR"`) {
			var e struct {
				Payload struct {
					Token string `json:"token_base64"`
				} `json:"payload"`
			}
			if err := json.Unmarshal([]byte(l), &e); err != nil {
				t.Fatal(err)
			}
			return e.Payload.Token
		}
	}
	t.Fatal("no TIME_ANCHOR")
	return ""
}

func TestZeitstempel(t *testing.T) {
	fx := func(n string) string { return filepath.Join("..", "tsa", "testdata", n) }
	der, data, root := fx("openssl_token.der"), fx("openssl_data.bin"), fx("openssl_tsa.crt")
	der2, err := os.ReadFile(der)
	if err != nil {
		t.Fatal(err)
	}
	b64 := datei(t, "token.b64", base64.StdEncoding.EncodeToString(der2)+"\r\n")
	b64nl := datei(t, "token2.b64", base64.StdEncoding.EncodeToString(der2)[:40]+"\n"+base64.StdEncoding.EncodeToString(der2)[40:]+"\n")
	corpusTok := datei(t, "corpus.b64", tokenOf(t, "valid_time_anchor"))
	corpusData := datei(t, "corpus.bin", string(subjectOf(t, "valid_time_anchor", 22)))
	corpusRoot := vektor(filepath.Join("valid_time_anchor", "keys", "tsa", "probestelle.pem"))
	stmt := datei(t, "stmt.txt", `{"day":"2026-01-01"}`+"\n")
	for _, f := range []struct {
		why    string
		args   []string
		exit   int
		state  string
		reason any
	}{
		{"DER, log, own root", []string{"--token", der, "--data", data, "--tsa-root", root}, 0, "confirmed", nil},
		{"Base64 with CRLF, chain", []string{"--token", b64, "--data", data, "--tsa-root", root, "--purpose", "chain"}, 0, "confirmed", nil},
		{"no root", []string{"--token", der, "--data", data}, 1, "unconfirmed", "no_path_to_root_of_purpose"},
		{"other data", []string{"--token", der, "--data", root, "--tsa-root", root}, 1, "defective", "imprint_wrong"},
		{"a statement_jcs", []string{"--token", der, "--statement-jcs", stmt, "--tsa-root", root}, 1, "defective", "imprint_wrong"},
		{"Base64 with a line break inside", []string{"--token", b64nl, "--data", data}, 1, "defective", "b64_size_or_grammar_t"},
		{"the corpus authority for the log", []string{"--token", corpusTok, "--data", corpusData, "--tsa-root", corpusRoot}, 1, "unconfirmed", "published_test_key"},
		{"the corpus authority for the chain", []string{"--token", corpusTok, "--data", corpusData, "--tsa-root", corpusRoot, "--purpose", "chain"}, 1, "unconfirmed", "published_test_key"},
	} {
		code, out, errOut := lauf(append([]string{"zeitstempel", "--json"}, f.args...)...)
		if code != f.exit || errOut != "" {
			t.Errorf("%s: exit %d (stderr %q), want %d", f.why, code, errOut, f.exit)
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			t.Fatalf("%s: %v\n%s", f.why, err, out)
		}
		keys := []string{"purpose", "state", "reason", "gen_time", "gen_time_ms", "imprint_algorithm", "signer", "qualified_statement"}
		if len(m) != len(keys) {
			t.Errorf("%s: members %v", f.why, m)
		}
		for _, k := range keys {
			if _, ok := m[k]; !ok {
				t.Errorf("%s: member %s missing", f.why, k)
			}
		}
		if m["state"] != f.state || m["reason"] != f.reason {
			t.Errorf("%s: %v %v, want %s %v", f.why, m["state"], m["reason"], f.state, f.reason)
		}
		if f.state != "defective" || f.reason != "b64_size_or_grammar_t" {
			if m["gen_time"] == nil || m["imprint_algorithm"] != "sha256" || m["qualified_statement"] != "absent" {
				t.Errorf("%s: readings %v", f.why, m)
			}
		} else if m["gen_time"] != nil || m["signer"] != nil || m["qualified_statement"] != nil {
			t.Errorf("%s: readings of a token that is not read %v", f.why, m)
		}
	}
	// The text output names the state in the language of the report.
	code, out, _ := lauf("zeitstempel", "--lang", "de", "--token", der, "--data", data)
	if code != 1 || !strings.Contains(out, "nicht bestätigt") || !strings.Contains(out, "keine Prüfung eines Prüfpakets") {
		t.Errorf("text: exit %d\n%s", code, out)
	}
	// Unusable invocations.
	nonASCII := datei(t, "n.txt", "{\"day\":\"ä\"}")
	for _, args := range [][]string{
		{"--data", data},
		{"--token", der},
		{"--token", der, "--data", data, "--statement-jcs", stmt},
		{"--token", der, "--data", data, "--purpose", "qualified"},
		{"--token", der, "--token", der, "--data", data},
		{"--token", der, "--data", data, "extra"},
		{"--token", der, "--data", data, "--tsa-root", data},
		{"--token", der, "--statement-jcs", nonASCII},
		{"--token", filepath.Join(t.TempDir(), "fehlt"), "--data", data},
		{"--token", der, "--data", data, "--unknown"},
	} {
		code, out, errOut := lauf(append([]string{"zeitstempel"}, args...)...)
		if code != 3 || out != "" || errOut == "" {
			t.Errorf("zeitstempel %v: exit %d, stdout %q, stderr %q", args, code, out, errOut)
		}
	}
}

// TestZeitstempelKorpus: the inputs of the single time-stamp check in the
// test corpus (spec/testvectors/README.*.md, section 10.4), each token as
// DER and as Base64, with --purpose chain and with --purpose log and the
// test root. The results follow the table of format spec 7.5.7, whose rows
// hold alike for both purposes; a signer or a root with a key in
// published_test_keys confirms no time stamp (7.5.7), whatever the purpose,
// and the row on Z.6 stands above that row, so the inputs on Z.6 show its
// result (7.5.6); an arc above 10^4300 in the extnID of an extension next
// to qcStatements leaves rule QS present (7.5.2 T.6, 7.5.6). The signer is named where Z.5 finds it, by its first
// commonName in a primitive UTF8String, PrintableString or IA5String
// (SubjectCommonName): that of timestamp_name_value_constructed is a
// constructed UTF8String and names nobody (null), in both verifiers.
func TestZeitstempelKorpus(t *testing.T) {
	signer := "Testkorpus Zeitstempelstelle (kein Zeuge)"
	sekunde, ms := "20260101004001Z", "2026-01-01T00:40:01.000Z"
	for _, f := range []struct {
		name, genTime, genTimeMS, state, reason, signer, qs string
	}{
		{"timestamp_gentime_fraction", "20260101004001.123999999Z", "2026-01-01T00:40:01.123Z", "unconfirmed", "published_test_key", signer, "absent"},
		{"timestamp_name_value_constructed", sekunde, ms, "unconfirmed", "published_test_key", "<null>", "absent"},
		{"timestamp_sha1_digest_algorithm", sekunde, ms, "unconfirmed", "step_5_not_performable", signer, "absent"},
		{"timestamp_ess_both", sekunde, ms, "unconfirmed", "published_test_key", signer, "absent"},
		{"timestamp_certificates_not_tlv", sekunde, ms, "unconfirmed", "step_5_not_performable", "<null>", "absent"},
		{"timestamp_sid_not_issuer_serial", sekunde, ms, "unconfirmed", "step_5_not_performable", "<null>", "absent"},
		{"timestamp_ess_v2_second_element_broken", sekunde, ms, "defective", "z6_failed", signer, "absent"},
		{"timestamp_ess_issuer_serial_name_broken", sekunde, ms, "defective", "z6_failed", signer, "absent"},
		{"timestamp_ess_policies_not_der", sekunde, ms, "unconfirmed", "published_test_key", signer, "absent"},
		{"timestamp_ess_other_name_a4", sekunde, ms, "unconfirmed", "published_test_key", signer, "absent"},
		{"timestamp_ess_hash_algorithm_parameters_not_der", sekunde, ms, "unconfirmed", "published_test_key", signer, "absent"},
		{"timestamp_qs_extension_oid_arc_large", sekunde, ms, "unconfirmed", "published_test_key", signer, "present"},
	} {
		p := vektor("zeitstempel_" + f.name)
		for _, zweck := range []string{"chain", "log"} {
			for _, form := range []string{".token.der", ".token.b64"} {
				code, out, errOut := lauf("zeitstempel", "--json", "--purpose", zweck, "--token", p+form,
					"--data", p+".daten.json", "--tsa-root", p+".wurzel.pem")
				if code != 1 || errOut != "" {
					t.Errorf("%s%s %s: exit %d (stderr %q), want 1", f.name, form, zweck, code, errOut)
					continue
				}
				var got ZeitstempelResult
				if err := json.Unmarshal([]byte(out), &got); err != nil {
					t.Fatalf("%s%s %s: %v\n%s", f.name, form, zweck, err, out)
				}
				s := func(p *string) string {
					if p == nil {
						return "<null>"
					}
					return *p
				}
				if got.Purpose != zweck || got.State != f.state || s(got.Reason) != f.reason ||
					s(got.GenTime) != f.genTime || s(got.GenTimeMS) != f.genTimeMS || s(got.ImprintAlgorithm) != "sha256" ||
					s(got.Signer) != f.signer || s(got.QualifiedStatement) != f.qs {
					t.Errorf("%s%s %s: %s", f.name, form, zweck, out)
				}
			}
		}
	}
}
