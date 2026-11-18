package tsa

// Strict DER (format spec 7.5.2, rule T.6): definite lengths in minimal form,
// INTEGER in minimal two's complement, BOOLEAN with the content 00 or FF,
// minimal OID subidentifiers, primitive or constructed form as the type
// requires. The reader below is the only way the profile looks at bytes;
// nothing in this package uses encoding/asn1 or crypto/x509 for parsing,
// because spec 7.5 makes the result depend on its rules alone and not on a
// library or its edition.

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// Identifier octets of the types the profile reads. All are in the low tag
// number form (X.690 8.1.2.2).
const (
	tagBoolean     = 0x01
	tagInteger     = 0x02
	tagBitString   = 0x03
	tagOctetString = 0x04
	tagNull        = 0x05
	tagOID         = 0x06
	tagUTCTime     = 0x17
	tagGenTime     = 0x18
	tagSequence    = 0x30
	tagSet         = 0x31
	tagCtx0Prim    = 0x80
	tagCtx1Prim    = 0x81
	tagCtx0Cons    = 0xa0
	tagCtx1Cons    = 0xa1
	tagCtx2Cons    = 0xa2
	tagCtx3Cons    = 0xa3
	tagCtx4Cons    = 0xa4
)

// element is one DER TLV: its identifier octets, its content octets and the
// whole encoding (identifier, length and content).
type element struct {
	id      []byte
	content []byte
	full    []byte
}

// tag returns the single identifier octet, or 0 for the high tag number
// form, which never equals any tag the profile expects.
func (e element) tag() byte {
	if len(e.id) != 1 {
		return 0
	}
	return e.id[0]
}

// constructed reports the constructed bit of the identifier.
func (e element) constructed() bool { return len(e.id) > 0 && e.id[0]&0x20 != 0 }

// errDER marks every violation of T.6 or of the grammar around it.
var errDER = errors.New("not DER")

func derErr(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{errDER}, a...)...)
}

// readElement reads one TLV from the front of b. The identifier follows
// X.690 8.1.2 (a tag number above 30 in the high tag number form, its first
// subsequent octet not 0x80); the length is definite and minimal (X.690
// 10.1): the short form below 128, the long form with no leading zero octet
// otherwise, at most four length octets.
//
// T.6 (format spec 7.5.2): where the grammar asks only for "ein TLV" (tsa,
// crls, unsignedAttrs, the value of an attribute in a Name, the parameters
// of signatureAlgorithm, extnValue of an extension no rule reads), only that
// outer TLV is checked: identifier octets after X.690 8.1.2, tag numbers from
// 31 included, and a minimal definite length; its content is not split and
// need not be DER.
func readElement(b []byte) (element, []byte, error) {
	if len(b) == 0 {
		return element{}, nil, derErr("missing element")
	}
	i := 1
	if b[0]&0x1f == 0x1f {
		// High tag number form: base 128, minimal, number at least 31.
		// X.690 sets no upper bound and T.6 none either, so a number of any
		// size is admitted; n saturates instead of overflowing, for only
		// n < 31 is ruled out.
		if len(b) < 2 || b[1] == 0x80 {
			return element{}, nil, derErr("identifier octets not minimal")
		}
		var n uint64
		for {
			if i >= len(b) {
				return element{}, nil, derErr("identifier octets cut off")
			}
			c := b[i]
			i++
			if n < 1<<56 {
				n = n<<7 | uint64(c&0x7f)
			}
			if c&0x80 == 0 {
				break
			}
		}
		if n < 31 {
			return element{}, nil, derErr("tag number %d in the high tag number form", n)
		}
	}
	id := b[:i]
	if i >= len(b) {
		return element{}, nil, derErr("length octets missing")
	}
	l := int(b[i])
	i++
	switch {
	case l < 0x80:
	case l == 0x80:
		return element{}, nil, derErr("indefinite length")
	default:
		n := l & 0x7f
		if n > 4 {
			return element{}, nil, derErr("length of %d octets", n)
		}
		if i+n > len(b) {
			return element{}, nil, derErr("length octets cut off")
		}
		if b[i] == 0 {
			return element{}, nil, derErr("length not in minimal form")
		}
		l = 0
		for _, c := range b[i : i+n] {
			l = l<<8 | int(c)
		}
		i += n
		if l < 0x80 {
			return element{}, nil, derErr("long form for a length below 128")
		}
	}
	if l > len(b)-i {
		return element{}, nil, derErr("content of %d octets, %d present", l, len(b)-i)
	}
	return element{id: id, content: b[i : i+l], full: b[:i+l]}, b[i+l:], nil
}

// single reads exactly one TLV that fills b.
func single(b []byte) (element, error) {
	e, rest, err := readElement(b)
	if err != nil {
		return element{}, err
	}
	if len(rest) != 0 {
		return element{}, derErr("%d octets after the element", len(rest))
	}
	return e, nil
}

// elements splits b into its TLVs.
func elements(b []byte) ([]element, error) {
	var out []element
	for len(b) > 0 {
		e, rest, err := readElement(b)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
		b = rest
	}
	return out, nil
}

// expect reads one TLV with identifier tag from the front of b.
func expect(b []byte, tag byte, what string) (element, []byte, error) {
	e, rest, err := readElement(b)
	if err != nil {
		return element{}, nil, fmt.Errorf("%s: %w", what, err)
	}
	if e.tag() != tag {
		return element{}, nil, derErr("%s: identifier %x, expected %02x", what, e.id, tag)
	}
	return e, rest, nil
}

// children reads the content of a constructed element as TLVs; a primitive
// element, or a content that does not split into TLVs, is not DER.
func children(e element, what string) ([]element, error) {
	if !e.constructed() {
		return nil, derErr("%s is primitive", what)
	}
	el, err := elements(e.content)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	return el, nil
}

// cursor walks the children of a SEQUENCE in order.
type cursor struct {
	el   []element
	what string
}

func newCursor(e element, what string) (*cursor, error) {
	if e.tag() != tagSequence {
		return nil, derErr("%s is not a SEQUENCE", what)
	}
	el, err := children(e, what)
	if err != nil {
		return nil, err
	}
	return &cursor{el: el, what: what}, nil
}

// next returns the next child, whatever its type.
func (c *cursor) next(name string) (element, error) {
	if len(c.el) == 0 {
		return element{}, derErr("%s: %s missing", c.what, name)
	}
	e := c.el[0]
	c.el = c.el[1:]
	return e, nil
}

// take returns the next child with identifier tag.
func (c *cursor) take(tag byte, name string) (element, error) {
	e, err := c.next(name)
	if err != nil {
		return element{}, err
	}
	if e.tag() != tag {
		return element{}, derErr("%s: %s has identifier %x, expected %02x", c.what, name, e.id, tag)
	}
	return e, nil
}

// optional returns the next child if it has identifier tag.
func (c *cursor) optional(tag byte) (element, bool) {
	if len(c.el) == 0 || c.el[0].tag() != tag {
		return element{}, false
	}
	e := c.el[0]
	c.el = c.el[1:]
	return e, true
}

// done requires that no child is left.
func (c *cursor) done() error {
	if len(c.el) != 0 {
		return derErr("%s: %d elements more than the type has", c.what, len(c.el))
	}
	return nil
}

// ---------------------------------------------------------------- primitives

// intContent checks an INTEGER content for minimal two's complement.
func intContent(e element, what string) error {
	if e.tag() != tagInteger && e.tag() != tagCtx0Prim && e.tag() != tagCtx1Prim {
		return derErr("%s is not an INTEGER", what)
	}
	c := e.content
	if len(c) == 0 {
		return derErr("%s: INTEGER without content", what)
	}
	if len(c) > 1 && (c[0] == 0x00 && c[1]&0x80 == 0 || c[0] == 0xff && c[1]&0x80 != 0) {
		return derErr("%s: INTEGER not in minimal form", what)
	}
	return nil
}

// bigInt reads an INTEGER (any identifier already checked by the caller).
func bigInt(e element, what string) (*big.Int, error) {
	if err := intContent(e, what); err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(e.content)
	if e.content[0]&0x80 != 0 {
		n.Sub(n, new(big.Int).Lsh(big.NewInt(1), uint(8*len(e.content))))
	}
	return n, nil
}

// smallInt reads an INTEGER that must fit in an int64.
func smallInt(e element, what string) (int64, error) {
	n, err := bigInt(e, what)
	if err != nil {
		return 0, err
	}
	if !n.IsInt64() {
		return 0, derErr("%s: INTEGER out of range", what)
	}
	return n.Int64(), nil
}

// boolean reads a BOOLEAN: one content octet, 00 or FF.
func boolean(e element, what string) (bool, error) {
	if e.tag() != tagBoolean || len(e.content) != 1 || e.content[0] != 0x00 && e.content[0] != 0xff {
		return false, derErr("%s is no DER BOOLEAN", what)
	}
	return e.content[0] == 0xff, nil
}

// isNull reports whether e is the DER NULL.
func isNull(e element) bool { return e.tag() == tagNull && len(e.content) == 0 }

// oid is an OBJECT IDENTIFIER in dotted form; arcs may exceed 64 bits.
type oid string

// readOID checks the content of an OBJECT IDENTIFIER (minimal
// subidentifiers) and returns it dotted.
func readOID(e element, what string) (oid, error) {
	if e.tag() != tagOID {
		return "", derErr("%s is not an OBJECT IDENTIFIER", what)
	}
	c := e.content
	if len(c) == 0 || c[len(c)-1]&0x80 != 0 {
		return "", derErr("%s: OBJECT IDENTIFIER cut off", what)
	}
	var arcs []string
	start := true
	n := new(big.Int)
	for _, b := range c {
		if start && b == 0x80 {
			return "", derErr("%s: subidentifier not minimal", what)
		}
		start = false
		n.Lsh(n, 7)
		n.Or(n, big.NewInt(int64(b&0x7f)))
		if b&0x80 == 0 {
			if len(arcs) == 0 {
				switch {
				case n.Cmp(big.NewInt(40)) < 0:
					arcs = append(arcs, "0", n.String())
				case n.Cmp(big.NewInt(80)) < 0:
					arcs = append(arcs, "1", new(big.Int).Sub(n, big.NewInt(40)).String())
				default:
					arcs = append(arcs, "2", new(big.Int).Sub(n, big.NewInt(80)).String())
				}
			} else {
				arcs = append(arcs, n.String())
			}
			n = new(big.Int)
			start = true
		}
	}
	return oid(strings.Join(arcs, ".")), nil
}

// bitString reads a primitive BIT STRING: the unused-bits octet (0 to 7, 0
// for an empty string) and the bits.
//
// T.6 (format spec 7.5.2) names it a limit of the profile: whether the unused
// bits are zero (X.690 11.2.1) is not checked.
func bitString(e element, what string) (unused int, bits []byte, err error) {
	if e.tag() != tagBitString || len(e.content) == 0 || e.content[0] > 7 || len(e.content) == 1 && e.content[0] != 0 {
		return 0, nil, derErr("%s is no DER BIT STRING", what)
	}
	return int(e.content[0]), e.content[1:], nil
}

// constructedUniversal are the universal tag numbers whose DER encoding is
// constructed: EXTERNAL, EMBEDDED PDV, SEQUENCE, SET and CHARACTER STRING.
// Every other universal type is primitive.
var constructedUniversal = map[byte]bool{8: true, 11: true, 16: true, 17: true, 29: true}

// derThroughout applies T.6 (format spec 7.5.2) to every element of the one
// TLV b, descending into each constructed encoding of any class: every
// header after readElement; in the universal class no tag number 0 and no
// high tag number form, the constructed form exactly for the types above,
// BOOLEAN 00 or FF, INTEGER minimal, OID subidentifiers minimal; exactly one
// element and nothing after it. As T.6 says, the order of a SET OF, an
// explicitly encoded DEFAULT and the unused bits of a BIT STRING are not
// checked.
//
// Z.1 (format spec 7.5.3) uses it for the content of extnValue of the
// extensions of a certificate a rule reads (readCertificate). Rule QS checks
// only the outer TLV of an extnValue and does not use it. The contents still
// to be read are kept in a list rather than on the call stack, so that a deep
// nesting is read like any other.
func derThroughout(b []byte) error {
	pending := [][]byte{b}
	for top := true; len(pending) > 0; top = false {
		rest := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		n := 0
		for ; len(rest) > 0; n++ {
			e, r, err := readElement(rest)
			if err != nil {
				return err
			}
			rest = r
			if e.id[0]>>6 == 0 { // universal class: the tag number decides the form
				num := e.id[0] & 0x1f
				if num == 0 || num == 0x1f {
					return derErr("universal tag number %d is no DER element here", num)
				}
				if e.constructed() != constructedUniversal[num] {
					return derErr("universal tag number %d in the wrong form", num)
				}
				switch num {
				case 1:
					_, err = boolean(e, "BOOLEAN")
				case 2:
					err = intContent(e, "INTEGER")
				case 6:
					_, err = readOID(e, "OBJECT IDENTIFIER")
				}
				if err != nil {
					return err
				}
			}
			if e.constructed() {
				pending = append(pending, e.content)
			}
		}
		if top && n != 1 {
			return derErr("%d elements where exactly one is expected", n)
		}
	}
	return nil
}

// ---------------------------------------------------------------- algorithms

// algorithm is an AlgorithmIdentifier: SEQUENCE { algorithm OID, parameters
// ANY OPTIONAL }, the parameters one TLV or absent.
type algorithm struct {
	oid    oid
	params *element // nil: absent
	full   []byte
}

func readAlgorithm(e element, what string) (algorithm, error) {
	c, err := newCursor(e, what)
	if err != nil {
		return algorithm{}, err
	}
	o, err := c.take(tagOID, "algorithm")
	if err != nil {
		return algorithm{}, err
	}
	id, err := readOID(o, what)
	if err != nil {
		return algorithm{}, err
	}
	a := algorithm{oid: id, full: e.full}
	if p, err := c.next("parameters"); err == nil {
		a.params = &p
	}
	if err := c.done(); err != nil {
		return algorithm{}, err
	}
	return a, nil
}

// paramsAbsentOrNull is the rule for digest algorithms (T.4, T.5).
func (a algorithm) paramsAbsentOrNull() bool { return a.params == nil || isNull(*a.params) }

// ---------------------------------------------------------------- time

// readGenTime reads genTime after T.5: GeneralizedTime YYYYMMDDhhmmss[.f]Z,
// 1 to 9 digits f, the last one not 0, an existing date, hour 00 to 23,
// minute and second 00 to 59, no offset.
//
// T.5 and Z.1 (format spec 7.5.2, 7.5.3): years 0001 to 9999 as in format
// spec 2; the year 0000 violates the grammar.
func readGenTime(e element) (time.Time, string, error) {
	if e.tag() != tagGenTime {
		return time.Time{}, "", derErr("genTime is not a GeneralizedTime")
	}
	s := string(e.content)
	if len(s) < 15 || s[len(s)-1] != 'Z' {
		return time.Time{}, "", derErr("genTime %q is not YYYYMMDDhhmmss[.f]Z", s)
	}
	frac := s[14 : len(s)-1]
	nanos := 0
	if frac != "" {
		f := frac[1:]
		if frac[0] != '.' || len(f) < 1 || len(f) > 9 || !digits(f) || f[len(f)-1] == '0' {
			return time.Time{}, "", derErr("genTime %q: fraction not 1 to 9 digits without a trailing 0", s)
		}
		v, _ := strconv.Atoi((f + "000000000")[:9])
		nanos = v
	}
	t, ok := civil(s[:4], s[4:6], s[6:8], s[8:10], s[10:12], s[12:14])
	if !ok {
		return time.Time{}, "", derErr("genTime %q is no existing instant", s)
	}
	return t.Add(time.Duration(nanos)), s, nil
}

// readCertTime reads a Time of Z.1: UTCTime YYMMDDhhmmssZ (YY < 50 is 20YY,
// else 19YY) or GeneralizedTime YYYYMMDDhhmmssZ, a valid date and time.
func readCertTime(e element, what string) (time.Time, error) {
	s := string(e.content)
	switch e.tag() {
	case tagUTCTime:
		if len(s) != 13 || s[12] != 'Z' {
			return time.Time{}, derErr("%s: UTCTime %q is not YYMMDDhhmmssZ", what, s)
		}
		century := "20"
		if s[0] >= '5' {
			century = "19"
		}
		if !digits(s[:2]) {
			return time.Time{}, derErr("%s: UTCTime %q", what, s)
		}
		if t, ok := civil(century+s[:2], s[2:4], s[4:6], s[6:8], s[8:10], s[10:12]); ok {
			return t, nil
		}
	case tagGenTime:
		if len(s) != 15 || s[14] != 'Z' {
			return time.Time{}, derErr("%s: GeneralizedTime %q is not YYYYMMDDhhmmssZ", what, s)
		}
		if t, ok := civil(s[:4], s[4:6], s[6:8], s[8:10], s[10:12], s[12:14]); ok {
			return t, nil
		}
	default:
		return time.Time{}, derErr("%s is neither UTCTime nor GeneralizedTime", what)
	}
	return time.Time{}, derErr("%s %q is no valid date and time", what, s)
}

func digits(s string) bool {
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// civil builds an instant from decimal fields and checks that it exists.
func civil(y, mo, d, h, mi, s string) (time.Time, bool) {
	for _, f := range []string{y, mo, d, h, mi, s} {
		if !digits(f) {
			return time.Time{}, false
		}
	}
	yy, _ := strconv.Atoi(y)
	mm, _ := strconv.Atoi(mo)
	dd, _ := strconv.Atoi(d)
	hh, _ := strconv.Atoi(h)
	mn, _ := strconv.Atoi(mi)
	ss, _ := strconv.Atoi(s)
	if yy < 1 || mm < 1 || mm > 12 || dd < 1 || hh > 23 || mn > 59 || ss > 59 {
		return time.Time{}, false
	}
	t := time.Date(yy, time.Month(mm), dd, hh, mn, ss, 0, time.UTC)
	if t.Day() != dd || int(t.Month()) != mm {
		return time.Time{}, false
	}
	return t, true
}

// FormatMillis renders an instant truncated (not rounded) to whole
// milliseconds as YYYY-MM-DDThh:mm:ss.sssZ (format spec 2, 7.3 step 3).
func FormatMillis(t time.Time) string {
	t = t.UTC().Truncate(time.Millisecond)
	return fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", t.Year(), int(t.Month()), t.Day(),
		t.Hour(), t.Minute(), t.Second(), t.Nanosecond()/int(time.Millisecond))
}
