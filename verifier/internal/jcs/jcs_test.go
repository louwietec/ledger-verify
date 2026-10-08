package jcs

import (
	"errors"
	"strings"
	"testing"
)

func canon(t *testing.T, in string) string {
	t.Helper()
	v, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("parse %q: %v", in, err)
	}
	return string(Canon(v))
}

func TestCanonBasics(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{}`, `{}`},
		{`[]`, `[]`},
		{`{"b":1, "a":2}`, `{"a":2,"b":1}`},
		{`{"a": [1, 2, true, false, null]}`, `{"a":[1,2,true,false,null]}`},
		{`"häuser"`, `"häuser"`},
		{`"é"`, `"é"`},
		{`"a\/b"`, `"a/b"`},
		{`""`, `""`},
		{`"\u000B"`, `"\u000b"`},
		{`"\n\t\r\b\f\"\\"`, `"\n\t\r\b\f\"\\"`},
		{`-0`, `0`},
		{`{"seq": 42}`, `{"seq":42}`},
	}
	for _, c := range cases {
		if got := canon(t, c.in); got != c.want {
			t.Errorf("canon(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// RFC 8785 sorts keys by UTF-16 code units: a supplementary-plane character
// (surrogate pair, first unit 0xD83D) sorts BELOW U+FB00 despite having the
// larger code point.
func TestCanonKeyOrderUTF16(t *testing.T) {
	got := canon(t, `{"ﬀ":1,"😀":2,"z":3}`)
	want := `{"z":3,"😀":2,"ﬀ":1}`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParseRejects(t *testing.T) {
	bad := []string{
		`{"a":1,"a":2}`,    // duplicate key
		`1.5`,              // float
		`1e3`,              // exponent
		`01`,               // leading zero
		`9007199254740992`, // 2^53, outside safe range
		`{"a":}`,           // syntax
		`"\ud800"`,         // lone surrogate
		"\"\x01\"",         // raw control char
		`{"a":1} {"b":2}`,  // trailing data
	}
	for _, in := range bad {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded", in)
		}
	}
}

func TestParseRoundtripIdempotent(t *testing.T) {
	in := `{"z":[3,-2,"x"],"a":{"c":null,"b":true},"m":"Aß€😀"}`
	first := canon(t, in)
	second := canon(t, first)
	if first != second {
		t.Errorf("canonicalization not idempotent: %q vs %q", first, second)
	}
	if strings.Contains(first, " ") {
		t.Error("canonical form contains whitespace")
	}
}

func TestCanonGo(t *testing.T) {
	b, err := CanonGo(map[string]any{"b": int64(2), "a": "x", "n": nil})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"a":"x","b":2,"n":null}` {
		t.Errorf("got %s", b)
	}
}

// Spec 2 "Numbers" (explicitly from edition 1.9): a number outside the
// integer profile is marked with ErrNumber, every other syntax error is not —
// a reader of the vendor key list tells "not JSON" (ineffective, spec 10.7)
// from "a number outside the profile" (FORMAT_ERROR, spec 2) by it.
func TestParseMarksNumberErrors(t *testing.T) {
	for _, in := range []string{`1.5`, `1.0`, `1e3`, `-2E-1`, `9007199254740992`, `-9007199254740992`, `{"n":99999999999999999999}`, `[1,2.5]`} {
		if _, err := Parse([]byte(in)); !errors.Is(err, ErrNumber) {
			t.Errorf("Parse(%q) = %v, want an error wrapping ErrNumber", in, err)
		}
	}
	for _, in := range []string{`01`, `{"a":1,"a":2}`, `{"a":}`, `-`} {
		if _, err := Parse([]byte(in)); err == nil || errors.Is(err, ErrNumber) {
			t.Errorf("Parse(%q) = %v, want a syntax error that is not ErrNumber", in, err)
		}
	}
	for _, in := range []string{`9007199254740991`, `-9007199254740991`, `0`, `-0`} {
		if _, err := Parse([]byte(in)); err != nil {
			t.Errorf("Parse(%q) = %v, want accepted (inside ±(2^53-1))", in, err)
		}
	}
}

// CheckNumbers judges every number whatever else is wrong with the text: a
// fraction behind a duplicate member name is still found, digits inside
// strings are not numbers, and a text without a bad number passes even when
// it is no JSON.
func TestCheckNumbers(t *testing.T) {
	bad := []string{
		`{"a":1,"a":1.5}`,          // duplicate first, fraction second
		`{"v":1e0}`,                // exponent
		`[1, 2, 9007199254740992]`, // 2^53
		`{"x":{"y":[-0.0]}}`,       // nested fraction
		"{\"a\" :\n 3.25 }",        // blanks around the separator
	}
	for _, in := range bad {
		if err := CheckNumbers([]byte(in)); !errors.Is(err, ErrNumber) {
			t.Errorf("CheckNumbers(%q) = %v, want ErrNumber", in, err)
		}
	}
	good := []string{
		`{"seq":3,"request_salt":"1.5e3"}`, // digits inside a string
		`{"s":"\"1.5\"","n":-9007199254740991}`,
		`{"a":1,"a":2}`, // duplicate: a syntax matter, no number verdict
		`not json 1.5`,  // no value position: not judged
		`{"a":01}`,      // leading zero: syntax, not a number verdict
		``,
	}
	for _, in := range good {
		if err := CheckNumbers([]byte(in)); err != nil {
			t.Errorf("CheckNumbers(%q) = %v, want nil", in, err)
		}
	}
}
