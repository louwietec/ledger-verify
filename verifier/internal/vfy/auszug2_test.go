package vfy

// Format spec 7.4.8a and 10.8 (extension of edition 1.10): the grammar and
// the limits of the extract ledger-protokollauszug/2 at invocation (L0).

import (
	"bytes"
	"strings"
	"testing"
)

// auszug2 is a minimal extract /2: one day object with the given seals and
// day_receipts, chain_id as given (null when ""), cose_receipts as given.
func auszug2Bytes(format, chainID, seals, dayReceipts, cose string) []byte {
	c := "null"
	if chainID != "" {
		c = `"` + chainID + `"`
	}
	day := `{"entry":{"statement_jcs":"x","server_key_id":"k","server_signature":"` + strings.Repeat("ab", 64) + `"},"timestamps":[],"additional_signatures":[]`
	if format == Extract2Format {
		day += `,"seals":` + seals + `,"day_receipts":` + dayReceipts
	}
	day += "}"
	s := `{"format":"` + format + `","log_id":"l","chain_id":` + c + `,"protocol_keys":null,"days":[` + day + `],"chain_days":[]`
	if format == Extract2Format {
		s += `,"cose_receipts":` + cose
	}
	return []byte(s + "}")
}

func TestAuszug2Grammatik(t *testing.T) {
	const uuid = "0f8fad5b-d9cb-469f-a165-70867728950e"
	ml := `{"type":"ml-dsa-87","key_id":"m","value":"AAAA"}`
	cases := []struct {
		name  string
		b     []byte
		valid bool
	}{
		{"minimal", auszug2Bytes(Extract2Format, "", "[]", "[]", "[]"), true},
		{"four seals of different types", auszug2Bytes(Extract2Format, "", "["+ml+`,{"type":"cades-b-t","key_id":null,"value":"AAAA"},{"type":"x","key_id":null,"value":"A"},{"type":"y","key_id":"z","value":"B"}]`, "[]", "[]"), true},
		{"five seals", auszug2Bytes(Extract2Format, "", "["+ml+`,{"type":"a","key_id":null,"value":"A"},{"type":"b","key_id":null,"value":"A"},{"type":"c","key_id":null,"value":"A"},{"type":"d","key_id":null,"value":"A"}]`, "[]", "[]"), false},
		{"seal twice", auszug2Bytes(Extract2Format, "", "["+ml+","+ml+"]", "[]", "[]"), false},
		{"ml-dsa-87 without key_id", auszug2Bytes(Extract2Format, "", `[{"type":"ml-dsa-87","key_id":null,"value":"AAAA"}]`, "[]", "[]"), false},
		{"cades-b-t with key_id", auszug2Bytes(Extract2Format, "", `[{"type":"cades-b-t","key_id":"k","value":"AAAA"}]`, "[]", "[]"), false},
		{"type outside the pattern", auszug2Bytes(Extract2Format, "", `[{"type":"ML","key_id":null,"value":"AAAA"}]`, "[]", "[]"), false},
		{"empty value", auszug2Bytes(Extract2Format, "", `[{"type":"x","key_id":null,"value":""}]`, "[]", "[]"), false},
		{"value of 87384 characters", auszug2Bytes(Extract2Format, "", `[{"type":"x","key_id":null,"value":"`+strings.Repeat("A", 87384)+`"}]`, "[]", "[]"), true},
		{"value of 87385 characters", auszug2Bytes(Extract2Format, "", `[{"type":"x","key_id":null,"value":"`+strings.Repeat("A", 87385)+`"}]`, "[]", "[]"), false},
		{"seal with a further member", auszug2Bytes(Extract2Format, "", `[{"type":"x","key_id":null,"value":"A","z":1}]`, "[]", "[]"), false},
		{"two day_receipts", auszug2Bytes(Extract2Format, "", "[]", `["A","B"]`, "[]"), true},
		{"three day_receipts", auszug2Bytes(Extract2Format, "", "[]", `["A","B","C"]`, "[]"), false},
		{"day_receipts twice", auszug2Bytes(Extract2Format, "", "[]", `["A","A"]`, "[]"), false},
		{"day_receipt of 1369 characters", auszug2Bytes(Extract2Format, "", "[]", `["`+strings.Repeat("A", 1369)+`"]`, "[]"), false},
		{"cose_receipts with chain_id", auszug2Bytes(Extract2Format, uuid, "[]", "[]", `["A","B"]`), true},
		{"cose_receipts without chain_id", auszug2Bytes(Extract2Format, "", "[]", "[]", `["A"]`), false},
		{"cose_receipts twice", auszug2Bytes(Extract2Format, uuid, "[]", "[]", `["A","A"]`), false},
		{"a day object /1 in an extract /2", bytes.Replace(auszug2Bytes(Extract2Format, "", "[]", "[]", "[]"), []byte(`,"seals":[],"day_receipts":[]`), nil, 1), false},
		{"an extract /1 with seals", bytes.Replace(auszug2Bytes(Extract2Format, "", "[]", "[]", "[]"), []byte(Extract2Format), []byte(ExtractFormat), 1), false},
	}
	for _, c := range cases {
		var o Options
		err := o.AddVendorLog(c.b)
		if (err == nil) != c.valid {
			t.Errorf("%s: error %v, want valid %v", c.name, err, c.valid)
		}
		if err == nil && !o.VendorLogs[0].V2 {
			t.Errorf("%s: not read as /2", c.name)
		}
	}
}

// TestAuszug2Grenzen: per file /2 at most 67 108 864 bytes, per file /1 at
// most 33 554 432 (format spec 7.4.8, 7.4.8a, 10.8).
func TestAuszug2Grenzen(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates 64 MiB")
	}
	pad := func(b []byte, n int) []byte { return append(b, bytes.Repeat([]byte(" "), n-len(b))...) }
	var o Options
	if err := o.AddVendorLog(pad(auszug2Bytes(Extract2Format, "", "[]", "[]", "[]"), MaxVendorLog2Bytes)); err != nil {
		t.Errorf("/2 of 67 108 864 bytes: %v", err)
	}
	if err := o.AddVendorLog(pad(auszug2Bytes(Extract2Format, "", "[]", "[]", "[]"), MaxVendorLog2Bytes+1)); err == nil {
		t.Error("/2 of 67 108 865 bytes accepted")
	}
	if err := o.AddVendorLog(pad(auszug2Bytes(ExtractFormat, "", "", "", ""), MaxVendorLogFileBytes+1)); err == nil {
		t.Error("/1 of 33 554 433 bytes accepted")
	}
	if err := o.AddVendorLog(pad(auszug2Bytes(ExtractFormat, "", "", "", ""), MaxVendorLogFileBytes)); err != nil {
		t.Errorf("/1 of 33 554 432 bytes: %v", err)
	}
}

// TestSchluesselliste2AmAufruf: --vendor-key-list takes the format /2; only
// I-JSON, the size and the format are exit 3 (format spec 7.4.7a, 10.8).
func TestSchluesselliste2AmAufruf(t *testing.T) {
	var o Options
	if err := o.AddVendorKeyList([]byte(`{"format":"ledger-protokollschluessel/2","version":"no"}`)); err != nil {
		t.Errorf("a list /2 with a defect in its content: %v", err)
	}
	if err := o.AddVendorKeyList([]byte(`{"format":"ledger-protokollschluessel/3"}`)); err == nil {
		t.Error("an unknown format accepted")
	}
	big := append([]byte(`{"format":"ledger-protokollschluessel/2"}`), bytes.Repeat([]byte(" "), MaxKeyListBytes)...)
	if err := o.AddVendorKeyList(big); err == nil {
		t.Error("a list /2 above 1 048 576 bytes accepted")
	}
}
