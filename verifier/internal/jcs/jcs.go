// Package jcs implements RFC 8785 (JSON Canonicalization Scheme) for the
// integer-only JSON profile of the LEDGER specification: entries carry no
// fractional or exponent numbers, so canonical number serialization reduces
// to shortest decimal integer form. Implemented from RFC 8785 alone; no
// external dependencies.
package jcs

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Kind enumerates JSON value kinds.
type Kind int

const (
	KindNull Kind = iota
	KindBool
	KindInt
	KindString
	KindArray
	KindObject
)

// Member is one object member (key/value pair).
type Member struct {
	Key   string
	Value *Value
}

// Value is a parsed JSON value. Numbers are restricted to integers.
type Value struct {
	Kind    Kind
	Bool    bool
	Int     int64
	Str     string
	Arr     []*Value
	Members []Member // object members in input order
}

// Get returns the member value for key, or nil.
func (v *Value) Get(key string) *Value {
	if v == nil || v.Kind != KindObject {
		return nil
	}
	for i := range v.Members {
		if v.Members[i].Key == key {
			return v.Members[i].Value
		}
	}
	return nil
}

// Has reports whether an object member with the given key exists.
func (v *Value) Has(key string) bool { return v.Get(key) != nil }

// maxSafeInt is 2^53-1, the largest integer RFC 8785 / I-JSON allows losslessly.
const maxSafeInt = int64(1)<<53 - 1

// Parse parses a single JSON document; trailing data is an error.
func Parse(data []byte) (*Value, error) {
	p := &parser{data: data}
	p.skipWS()
	v, err := p.parseValue(0)
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.pos != len(p.data) {
		return nil, fmt.Errorf("trailing data at offset %d", p.pos)
	}
	return v, nil
}

type parser struct {
	data []byte
	pos  int
}

const maxDepth = 64

func (p *parser) skipWS() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) parseValue(depth int) (*Value, error) {
	if depth > maxDepth {
		return nil, errors.New("nesting too deep")
	}
	if p.pos >= len(p.data) {
		return nil, errors.New("unexpected end of input")
	}
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.parseObject(depth)
	case c == '[':
		return p.parseArray(depth)
	case c == '"':
		s, err := p.parseString()
		if err != nil {
			return nil, err
		}
		return &Value{Kind: KindString, Str: s}, nil
	case c == 't':
		if err := p.expect("true"); err != nil {
			return nil, err
		}
		return &Value{Kind: KindBool, Bool: true}, nil
	case c == 'f':
		if err := p.expect("false"); err != nil {
			return nil, err
		}
		return &Value{Kind: KindBool, Bool: false}, nil
	case c == 'n':
		if err := p.expect("null"); err != nil {
			return nil, err
		}
		return &Value{Kind: KindNull}, nil
	case c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumber()
	default:
		return nil, fmt.Errorf("unexpected character %q at offset %d", c, p.pos)
	}
}

func (p *parser) expect(lit string) error {
	if p.pos+len(lit) > len(p.data) || string(p.data[p.pos:p.pos+len(lit)]) != lit {
		return fmt.Errorf("invalid literal at offset %d", p.pos)
	}
	p.pos += len(lit)
	return nil
}

func (p *parser) parseObject(depth int) (*Value, error) {
	p.pos++ // '{'
	v := &Value{Kind: KindObject}
	p.skipWS()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		return v, nil
	}
	seen := map[string]bool{}
	for {
		p.skipWS()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil, fmt.Errorf("expected object key at offset %d", p.pos)
		}
		key, err := p.parseString()
		if err != nil {
			return nil, err
		}
		if seen[key] {
			return nil, fmt.Errorf("duplicate object key %q", key)
		}
		seen[key] = true
		p.skipWS()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return nil, fmt.Errorf("expected ':' at offset %d", p.pos)
		}
		p.pos++
		p.skipWS()
		val, err := p.parseValue(depth + 1)
		if err != nil {
			return nil, err
		}
		v.Members = append(v.Members, Member{Key: key, Value: val})
		p.skipWS()
		if p.pos >= len(p.data) {
			return nil, errors.New("unterminated object")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return v, nil
		default:
			return nil, fmt.Errorf("expected ',' or '}' at offset %d", p.pos)
		}
	}
}

func (p *parser) parseArray(depth int) (*Value, error) {
	p.pos++ // '['
	v := &Value{Kind: KindArray, Arr: []*Value{}}
	p.skipWS()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return v, nil
	}
	for {
		p.skipWS()
		el, err := p.parseValue(depth + 1)
		if err != nil {
			return nil, err
		}
		v.Arr = append(v.Arr, el)
		p.skipWS()
		if p.pos >= len(p.data) {
			return nil, errors.New("unterminated array")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return v, nil
		default:
			return nil, fmt.Errorf("expected ',' or ']' at offset %d", p.pos)
		}
	}
}

// ErrNumber marks a JSON number outside the integer profile of the
// specification (spec 2, "Numbers", explicitly from edition 1.9): every
// number MUST be an integer from -(2^53-1) to 2^53-1, written without a
// fraction and without an exponent (I-JSON, RFC 7493 2.2). Parse wraps it, so
// a caller can tell such a number from any other syntax error with
// errors.Is — a vendor key list that is not JSON is "ineffective" (spec
// 10.7), a number outside the profile in it is FORMAT_ERROR (spec 2).
var ErrNumber = errors.New("number outside the integer profile of the specification (integer within ±(2^53-1), no fraction, no exponent)")

// parseNumber accepts only JSON integers (spec profile: floats are forbidden).
func (p *parser) parseNumber() (*Value, error) {
	start := p.pos
	if p.data[p.pos] == '-' {
		p.pos++
	}
	digStart := p.pos
	for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
		p.pos++
	}
	if p.pos == digStart {
		return nil, fmt.Errorf("invalid number at offset %d", start)
	}
	if p.data[digStart] == '0' && p.pos-digStart > 1 {
		return nil, fmt.Errorf("leading zero in number at offset %d", start)
	}
	if p.pos < len(p.data) {
		switch p.data[p.pos] {
		case '.', 'e', 'E':
			return nil, fmt.Errorf("non-integer number at offset %d (floats are forbidden by the spec): %w", start, ErrNumber)
		}
	}
	n, err := strconv.ParseInt(string(p.data[start:p.pos]), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("number out of range at offset %d: %w", start, ErrNumber)
	}
	if n > maxSafeInt || n < -maxSafeInt {
		return nil, fmt.Errorf("integer outside RFC 8785 safe range at offset %d: %w", start, ErrNumber)
	}
	if string(p.data[start:p.pos]) == "-0" {
		n = 0
	}
	return &Value{Kind: KindInt, Int: n}, nil
}

// CheckNumbers scans a JSON text for numbers outside the integer profile
// (ErrNumber) WITHOUT parsing it: strings are skipped with their escapes, and
// every token that stands where JSON puts a value — at the start, or after
// '[', ',' or ':' — and begins with '-' or a digit is read as a number and
// judged. It returns an error wrapping ErrNumber for the first such token, and
// nil otherwise, also when the text is not JSON at all.
//
// Why a scan and not Parse: Parse stops at its FIRST error. In a file that
// carries a duplicate member name before a fraction, Parse reports the
// duplicate, and a reader that maps "not JSON" to one verdict and ErrNumber to
// another would decide by the order of the two defects. Spec 2 makes EVERY
// number in the package subject to the profile, so the number verdict must not
// depend on what else is wrong with the file.
func CheckNumbers(data []byte) error {
	valueStart := true // the next non-blank token stands where a value may begin
	for i := 0; i < len(data); {
		c := data[i]
		switch {
		case c == '"':
			i++
			for i < len(data) && data[i] != '"' {
				if data[i] == '\\' {
					i++
				}
				i++
			}
			i++ // closing quote
			valueStart = false
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '[' || c == ',' || c == ':':
			valueStart = true
			i++
		case valueStart && (c == '-' || (c >= '0' && c <= '9')):
			j := i
			for j < len(data) && (data[j] == '-' || data[j] == '+' || data[j] == '.' || data[j] == 'e' || data[j] == 'E' || (data[j] >= '0' && data[j] <= '9')) {
				j++
			}
			if err := checkNumberToken(data[i:j], i); err != nil {
				return err
			}
			i = j
			valueStart = false
		default:
			valueStart = false
			i++
		}
	}
	return nil
}

// checkNumberToken judges one number token for CheckNumbers: a fraction, an
// exponent or a value outside ±(2^53-1) is ErrNumber. A token that is not a
// JSON number at all ("-", "01", "1-2") is a syntax matter for Parse, not a
// number verdict, and passes here.
func checkNumberToken(tok []byte, off int) error {
	s := string(tok)
	digits := strings.TrimPrefix(s, "-")
	intPart := digits
	if k := strings.IndexAny(digits, ".eE"); k >= 0 {
		intPart = digits[:k]
	}
	if intPart == "" || strings.Trim(intPart, "0123456789") != "" || (len(intPart) > 1 && intPart[0] == '0') {
		return nil // not a JSON number: Parse reports the syntax
	}
	if len(intPart) != len(digits) {
		return fmt.Errorf("non-integer number %q at offset %d: %w", s, off, ErrNumber)
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n > maxSafeInt || n < -maxSafeInt {
		return fmt.Errorf("integer %q outside ±(2^53-1) at offset %d: %w", s, off, ErrNumber)
	}
	return nil
}

func (p *parser) parseString() (string, error) {
	p.pos++ // opening quote
	var out []byte
	for {
		if p.pos >= len(p.data) {
			return "", errors.New("unterminated string")
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			p.pos++
			if !utf8.Valid(out) {
				return "", errors.New("invalid UTF-8 in string")
			}
			return string(out), nil
		case c == '\\':
			p.pos++
			if p.pos >= len(p.data) {
				return "", errors.New("unterminated escape")
			}
			e := p.data[p.pos]
			p.pos++
			switch e {
			case '"':
				out = append(out, '"')
			case '\\':
				out = append(out, '\\')
			case '/':
				out = append(out, '/')
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				r, err := p.parseHex4()
				if err != nil {
					return "", err
				}
				if utf16.IsSurrogate(rune(r)) {
					// must be a high surrogate followed by \uXXXX low surrogate
					if p.pos+1 < len(p.data) && p.data[p.pos] == '\\' && p.data[p.pos+1] == 'u' {
						p.pos += 2
						r2, err := p.parseHex4()
						if err != nil {
							return "", err
						}
						dec := utf16.DecodeRune(rune(r), rune(r2))
						if dec == utf8.RuneError {
							return "", errors.New("invalid surrogate pair")
						}
						out = utf8.AppendRune(out, dec)
					} else {
						return "", errors.New("lone surrogate in string")
					}
				} else {
					out = utf8.AppendRune(out, rune(r))
				}
			default:
				return "", fmt.Errorf("invalid escape \\%c", e)
			}
		case c < 0x20:
			return "", errors.New("raw control character in string")
		default:
			out = append(out, c)
			p.pos++
		}
	}
}

func (p *parser) parseHex4() (uint32, error) {
	if p.pos+4 > len(p.data) {
		return 0, errors.New("truncated \\u escape")
	}
	var r uint32
	for i := 0; i < 4; i++ {
		c := p.data[p.pos+i]
		var d uint32
		switch {
		case c >= '0' && c <= '9':
			d = uint32(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint32(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint32(c-'A') + 10
		default:
			return 0, errors.New("invalid \\u escape")
		}
		r = r<<4 | d
	}
	p.pos += 4
	return r, nil
}

// Canon serializes v in RFC 8785 canonical form.
func Canon(v *Value) []byte {
	var out []byte
	return appendCanon(out, v)
}

func appendCanon(out []byte, v *Value) []byte {
	switch v.Kind {
	case KindNull:
		return append(out, "null"...)
	case KindBool:
		if v.Bool {
			return append(out, "true"...)
		}
		return append(out, "false"...)
	case KindInt:
		return strconv.AppendInt(out, v.Int, 10)
	case KindString:
		return appendCanonString(out, v.Str)
	case KindArray:
		out = append(out, '[')
		for i, el := range v.Arr {
			if i > 0 {
				out = append(out, ',')
			}
			out = appendCanon(out, el)
		}
		return append(out, ']')
	case KindObject:
		ms := make([]Member, len(v.Members))
		copy(ms, v.Members)
		sort.SliceStable(ms, func(i, j int) bool { return utf16Less(ms[i].Key, ms[j].Key) })
		out = append(out, '{')
		for i, m := range ms {
			if i > 0 {
				out = append(out, ',')
			}
			out = appendCanonString(out, m.Key)
			out = append(out, ':')
			out = appendCanon(out, m.Value)
		}
		return append(out, '}')
	}
	return out
}

// utf16Less compares strings by their UTF-16 code unit sequences (RFC 8785 §3.2.3).
func utf16Less(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

const hexDigits = "0123456789abcdef"

// appendCanonString serializes a string per RFC 8785 §3.2.2.2.
func appendCanonString(out []byte, s string) []byte {
	out = append(out, '"')
	for _, r := range s {
		switch r {
		case '"':
			out = append(out, '\\', '"')
		case '\\':
			out = append(out, '\\', '\\')
		case '\b':
			out = append(out, '\\', 'b')
		case '\f':
			out = append(out, '\\', 'f')
		case '\n':
			out = append(out, '\\', 'n')
		case '\r':
			out = append(out, '\\', 'r')
		case '\t':
			out = append(out, '\\', 't')
		default:
			if r < 0x20 {
				out = append(out, '\\', 'u', '0', '0', hexDigits[(r>>4)&0xf], hexDigits[r&0xf])
			} else {
				out = utf8.AppendRune(out, r)
			}
		}
	}
	return append(out, '"')
}

// FromGo builds a Value from a limited set of Go types: nil, bool, int,
// int64, string, []any, map[string]any. Used to build signed subjects and
// test fixtures with the same canonicalizer the verifier uses.
func FromGo(x any) (*Value, error) {
	switch t := x.(type) {
	case nil:
		return &Value{Kind: KindNull}, nil
	case bool:
		return &Value{Kind: KindBool, Bool: t}, nil
	case int:
		return &Value{Kind: KindInt, Int: int64(t)}, nil
	case int64:
		return &Value{Kind: KindInt, Int: t}, nil
	case string:
		return &Value{Kind: KindString, Str: t}, nil
	case []any:
		v := &Value{Kind: KindArray}
		for _, el := range t {
			ev, err := FromGo(el)
			if err != nil {
				return nil, err
			}
			v.Arr = append(v.Arr, ev)
		}
		return v, nil
	case map[string]any:
		v := &Value{Kind: KindObject}
		for k, el := range t {
			ev, err := FromGo(el)
			if err != nil {
				return nil, err
			}
			v.Members = append(v.Members, Member{Key: k, Value: ev})
		}
		return v, nil
	case *Value:
		return t, nil
	default:
		return nil, fmt.Errorf("unsupported Go type %T", x)
	}
}

// CanonGo canonicalizes a Go value built from the FromGo type set.
func CanonGo(x any) ([]byte, error) {
	v, err := FromGo(x)
	if err != nil {
		return nil, err
	}
	return Canon(v), nil
}
