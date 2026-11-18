package mldsa

import "crypto/sha3"

// Pseudorandom sampling (FIPS 204 section 7.3). H is SHAKE256 and G is
// SHAKE128 (section 3.7). The output of a XOF is one byte stream, so reading
// it in larger blocks yields the same bytes as the byte-wise squeezing of the
// algorithms; only the consumption below follows the algorithms exactly.

// shakeH computes H(parts..., outLen) with SHAKE256.
func shakeH(outLen int, parts ...[]byte) []byte {
	h := sha3.NewSHAKE256()
	for _, p := range parts {
		h.Write(p)
	}
	out := make([]byte, outLen)
	h.Read(out)
	return out
}

// byteStream hands out the squeezed bytes of a XOF one at a time.
type byteStream struct {
	xof *sha3.SHAKE
	buf []byte
	pos int
}

func newByteStream(xof *sha3.SHAKE, block int) *byteStream {
	return &byteStream{xof: xof, buf: make([]byte, block), pos: block}
}

func (s *byteStream) next() byte {
	if s.pos == len(s.buf) {
		s.xof.Read(s.buf)
		s.pos = 0
	}
	b := s.buf[s.pos]
	s.pos++
	return b
}

// sampleInBall is Algorithm 29: c in R with exactly tau coefficients in
// {-1, 1} and the others 0, from the whole commitment hash c~.
func sampleInBall(p *Params, ctilde []byte) *poly {
	h := sha3.NewSHAKE256()
	h.Write(ctilde)
	s := newByteStream(h, 136)
	var signs uint64
	for i := 0; i < 8; i++ {
		signs |= uint64(s.next()) << (8 * i)
	}
	c := new(poly)
	for i := n - p.tau; i < n; i++ {
		j := int(s.next())
		for j > i {
			j = int(s.next())
		}
		c[i] = c[j]
		// h[i + tau - 256] selects the sign; bit order of BytesToBits is
		// least significant bit first.
		if signs&1 == 1 {
			c[j] = q - 1
		} else {
			c[j] = 1
		}
		signs >>= 1
	}
	return c
}

// rejNTTPoly is Algorithm 30 with CoeffFromThreeBytes (Algorithm 14): a
// polynomial in the NTT domain sampled from the 34-byte seed rho.
func rejNTTPoly(rho []byte) *poly {
	g := sha3.NewSHAKE128()
	g.Write(rho)
	s := newByteStream(g, 168)
	a := new(poly)
	for j := 0; j < n; {
		b0 := uint32(s.next())
		b1 := uint32(s.next())
		b2 := uint32(s.next()) & 0x7f // b2 - 128 if b2 > 127
		z := b2<<16 | b1<<8 | b0
		if z < q {
			a[j] = z
			j++
		}
	}
	return a
}

// expandA is Algorithm 32: the k x l matrix A^ in the NTT domain.
func expandA(p *Params, rho []byte) [][]*poly {
	a := make([][]*poly, p.k)
	seed := make([]byte, 34)
	copy(seed, rho)
	for r := 0; r < p.k; r++ {
		a[r] = make([]*poly, p.l)
		for s := 0; s < p.l; s++ {
			// rho || IntegerToBytes(s, 1) || IntegerToBytes(r, 1)
			seed[32] = byte(s)
			seed[33] = byte(r)
			a[r][s] = rejNTTPoly(seed)
		}
	}
	return a
}
