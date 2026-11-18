package tsa

import (
	"bytes"
	"fmt"
	"regexp"
)

const (
	pemBegin = "-----BEGIN CERTIFICATE-----"
	pemEnd   = "-----END CERTIFICATE-----"
)

var pemOtherBegin = regexp.MustCompile(`^-----BEGIN (.*)-----$`)

// ParsePEMRoots reads a PEM file of roots for time stamps in the strict PEM
// of format spec 10.8: lines end with \n or \r\n; blanks and tabs at the end
// of a line do not count; text outside a block is passed over (RFC 7468),
// lines with ":" outside a block included. A block is a line exactly
// -----BEGIN CERTIFICATE-----, content lines and a line exactly
// -----END CERTIFICATE-----; the joined content follows grammar B64 and
// gives exactly one certificate after Z.1. A block with another label after
// BEGIN, a header line inside a block (a line with ":"), a block without its
// end, a block whose content is no certificate and a file without a
// CERTIFICATE block are an unusable invocation; no block is passed over
// silently. Every certificate counts.
//
// A last line without a line end counts as a line (format spec 10.8).
func ParsePEMRoots(text []byte) ([]*Certificate, error) {
	var out []*Certificate
	lines := bytes.Split(text, []byte("\n"))
	open := false
	beginLine := 0
	var body []byte
	for i, l := range lines {
		l = bytes.TrimSuffix(l, []byte("\r"))
		l = bytes.TrimRight(l, " \t")
		s := string(l)
		if !open {
			switch {
			case s == pemBegin:
				open, beginLine, body = true, i+1, nil
			case pemOtherBegin.MatchString(s):
				return nil, fmt.Errorf("line %d: a block %q; only CERTIFICATE blocks are read (format spec 10.8)", i+1, s)
			}
			continue
		}
		if s == pemEnd {
			der, err := DecodeB64(string(body))
			if err != nil {
				return nil, fmt.Errorf("the block of line %d: %v (format spec 10.8)", beginLine, err)
			}
			c, err := ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("the block of line %d is no certificate after %v", beginLine, err)
			}
			out = append(out, c)
			open = false
			continue
		}
		if bytes.IndexByte(l, ':') >= 0 {
			return nil, fmt.Errorf("line %d: a header line inside the block of line %d (format spec 10.8)", i+1, beginLine)
		}
		body = append(body, l...)
	}
	if open {
		return nil, fmt.Errorf("the block of line %d has no END line (format spec 10.8)", beginLine)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE block (format spec 10.8)")
	}
	return out, nil
}
