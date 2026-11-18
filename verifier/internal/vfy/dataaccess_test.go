package vfy

// DATA_ACCESS (format spec 4.25, from edition 1.10): the payload table of
// this verifier against registry event_types.DATA_ACCESS, with the data
// class access_chain for accesses to the access chain itself (heartbeat
// spec 12), for instance when an audit reads it.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"louwietec.com/ledger-verify/verifier/internal/jcs"
)

func TestDataAccessSchema(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		EventTypes struct {
			DataAccess struct {
				Payload map[string]struct {
					Type   string   `json:"type"`
					Values []string `json:"values"`
				} `json:"payload"`
				Example string `json:"example_payload_jcs"`
			} `json:"DATA_ACCESS"`
		} `json:"event_types"`
	}
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatal(err)
	}
	da := reg.EventTypes.DataAccess
	fields := payloadFields["DATA_ACCESS"]
	if len(fields) != len(da.Payload) {
		t.Errorf("%d fields, registry %d", len(fields), len(da.Payload))
	}
	for name, f := range da.Payload {
		got, ok := fields[name]
		if !ok || got.kind != f.Type {
			t.Errorf("4.25 %s: kind %q, registry %q", name, got.kind, f.Type)
			continue
		}
		if f.Type == "enum" && strings.Join(got.values, ",") != strings.Join(f.Values, ",") {
			t.Errorf("4.25 %s: %v, registry %v", name, got.values, f.Values)
		}
	}
	if indexOf(fields["data_class"].values, "access_chain") < 0 {
		t.Error("4.25: no data class access_chain")
	}
	payload := func(class string) *jcs.Value {
		var m map[string]any
		if err := json.Unmarshal([]byte(da.Example), &m); err != nil {
			t.Fatal(err)
		}
		m["data_class"] = class
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		v, err := jcs.Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, c := range []struct {
		class string
		ok    bool
	}{
		{"license", true},
		{"access_chain", true},
		{"credentials", true},
		{"access-chain", false},
		{"customer", false},
	} {
		err := validateObject("payload", fields, payload(c.class))
		if (err == nil) != c.ok {
			t.Errorf("4.25 data_class %q: %v, want ok %v", c.class, err, c.ok)
		}
	}
}
