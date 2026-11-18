package mldsa

// Decoding of public keys and signatures and encoding of w1 (FIPS 204
// section 7.1 and 7.2). Bit strings are little-endian: bit i of a byte
// string is bit (i mod 8) of byte floor(i/8) (BytesToBits, Algorithm 12).

// unpackBits reads 256 values of the given width from b (the inner part of
// SimpleBitUnpack, Algorithm 18). len(b) must be 32*bits.
func unpackBits(b []byte, bits int, out *[n]uint32) {
	var acc uint64
	accBits := 0
	pos := 0
	mask := uint64(1)<<bits - 1
	for i := 0; i < n; i++ {
		for accBits < bits {
			acc |= uint64(b[pos]) << accBits
			pos++
			accBits += 8
		}
		out[i] = uint32(acc & mask)
		acc >>= bits
		accBits -= bits
	}
}

// packBits writes 256 values of the given width (the inner part of
// SimpleBitPack, Algorithm 16). Every value must be below 2^bits.
func packBits(in *poly, bits int) []byte {
	out := make([]byte, 0, n*bits/8)
	var acc uint64
	accBits := 0
	for i := 0; i < n; i++ {
		acc |= uint64(in[i]) << accBits
		accBits += bits
		for accBits >= 8 {
			out = append(out, byte(acc))
			acc >>= 8
			accBits -= 8
		}
	}
	return out
}

// pkDecode is Algorithm 23. The caller has checked the length.
func pkDecode(p *Params, pk []byte) (rho []byte, t1 []poly) {
	rho = pk[:32]
	t1 = make([]poly, p.k)
	const stride = n * 10 / 8
	for i := 0; i < p.k; i++ {
		// SimpleBitUnpack(z_i, 2^(bitlen(q-1)-d) - 1): every 10-bit value is valid.
		unpackBits(pk[32+i*stride:32+(i+1)*stride], 10, (*[n]uint32)(&t1[i]))
	}
	return rho, t1
}

// sigDecode is Algorithm 27. The caller has checked the length. ok is false
// when HintBitUnpack returns "bottom" (malformed hint).
func sigDecode(p *Params, sig []byte) (ctilde []byte, z []poly, h [][n]bool, ok bool) {
	ctilde = sig[:p.ctildeLen]
	off := p.ctildeLen
	stride := n * p.zBits / 8
	z = make([]poly, p.l)
	var raw [n]uint32
	for i := 0; i < p.l; i++ {
		// BitUnpack(x_i, gamma1 - 1, gamma1), Algorithm 19: z = gamma1 - value.
		// Every value of zBits bits gives z in [-gamma1 + 1, gamma1], so
		// there is nothing to reject here; the norm check follows later.
		unpackBits(sig[off:off+stride], p.zBits, &raw)
		for j, v := range raw {
			z[i][j] = subq(p.gamma1, v)
		}
		off += stride
	}
	h, ok = hintBitUnpack(p, sig[off:])
	return ctilde, z, h, ok
}

// hintBitUnpack is Algorithm 21. y has omega+k bytes: omega positions,
// then for each polynomial i the running count of positions up to and
// including polynomial i. It rejects
//   - a count that decreases or exceeds omega,
//   - positions within one polynomial that are not strictly increasing,
//   - nonzero bytes in the unused part of the position area.
//
// The total number of ones is therefore at most omega.
func hintBitUnpack(p *Params, y []byte) ([][n]bool, bool) {
	h := make([][n]bool, p.k)
	index := 0
	for i := 0; i < p.k; i++ {
		end := int(y[p.omega+i])
		if end < index || end > p.omega {
			return nil, false
		}
		first := index
		for index < end {
			if index > first && y[index-1] >= y[index] {
				return nil, false
			}
			h[i][y[index]] = true
			index++
		}
	}
	for i := index; i < p.omega; i++ {
		if y[i] != 0 {
			return nil, false
		}
	}
	return h, true
}

// w1Encode is Algorithm 28: SimpleBitPack(w1_i, (q-1)/(2*gamma2) - 1) for
// each polynomial, concatenated.
func w1Encode(p *Params, w1 []poly) []byte {
	out := make([]byte, 0, p.k*n*p.w1Bits/8)
	for i := range w1 {
		out = append(out, packBits(&w1[i], p.w1Bits)...)
	}
	return out
}
