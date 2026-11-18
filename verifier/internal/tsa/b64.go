package tsa

import (
	"encoding/base64"
	"errors"
)

// DecodeB64 decodes a string of grammar B64 (format spec 2, from 1.10): only
// A-Z, a-z, 0-9, + and /, a length divisible by 4, = only as padding at the
// end and at most twice. Line breaks, blanks and every other character
// violate B64. The unused bits of the last group are not checked: the string
// itself is judged, and a second spelling of the same bytes gives it no second
// meaning. encoding/base64 alone would skip \r and \n.
func DecodeB64(s string) ([]byte, error) {
	if len(s)%4 != 0 {
		return nil, errors.New("B64: length not divisible by 4")
	}
	pad := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
			if pad > 0 {
				return nil, errors.New("B64: character after the padding")
			}
		case c == '=':
			pad++
			if pad > 2 || i < len(s)-2 {
				return nil, errors.New("B64: = other than as padding at the end")
			}
		default:
			return nil, errors.New("B64: character outside the alphabet")
		}
	}
	// Not Strict(): the unused bits of the last group are not judged.
	return base64.StdEncoding.DecodeString(s)
}
