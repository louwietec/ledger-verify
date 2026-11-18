package mldsa

// Arithmetic in R_q = Z_q[X]/(X^256 + 1) and the number-theoretic transform
// (FIPS 204 section 7.5, Algorithms 41, 42 and 45). Coefficients are kept as
// representatives in [0, q).

type poly [n]uint32

func addq(a, b uint32) uint32 {
	s := a + b
	if s >= q {
		s -= q
	}
	return s
}

func subq(a, b uint32) uint32 {
	return addq(a, q-b)
}

func mulq(a, b uint32) uint32 {
	return uint32(uint64(a) * uint64(b) % q)
}

func powq(b, e uint32) uint32 {
	r := uint32(1)
	for e > 0 {
		if e&1 == 1 {
			r = mulq(r, b)
		}
		b = mulq(b, b)
		e >>= 1
	}
	return r
}

// zetas[m] = zeta^BitRev8(m) mod q (FIPS 204 Appendix B).
var zetas = func() (z [n]uint32) {
	for m := 0; m < n; m++ {
		br := uint32(0)
		for i := 0; i < 8; i++ {
			br |= uint32((m>>i)&1) << (7 - i)
		}
		z[m] = powq(zeta, br)
	}
	return z
}()

// 256^-1 mod q, the scaling factor of Algorithm 42.
const nInv = 8347681

// ntt is Algorithm 41, in place.
func ntt(w *poly) {
	m := 0
	for length := 128; length >= 1; length /= 2 {
		for start := 0; start < n; start += 2 * length {
			m++
			z := zetas[m]
			for j := start; j < start+length; j++ {
				t := mulq(z, w[j+length])
				w[j+length] = subq(w[j], t)
				w[j] = addq(w[j], t)
			}
		}
	}
}

// invNTT is Algorithm 42, in place.
func invNTT(w *poly) {
	m := n
	for length := 1; length < n; length *= 2 {
		for start := 0; start < n; start += 2 * length {
			m--
			z := q - zetas[m] // -zetas[m] mod q
			for j := start; j < start+length; j++ {
				t := w[j]
				w[j] = addq(t, w[j+length])
				w[j+length] = mulq(z, subq(t, w[j+length]))
			}
		}
	}
	for j := range w {
		w[j] = mulq(nInv, w[j])
	}
}

// mulAddNTT sets acc = acc + a o b (Algorithm 45 followed by AddNTT).
func mulAddNTT(acc, a, b *poly) {
	for i := range acc {
		acc[i] = addq(acc[i], mulq(a[i], b[i]))
	}
}

// infNorm returns ||w||_inf = max |w_i mod+- q| (FIPS 204 section 2.3).
func infNorm(w *poly) uint32 {
	var m uint32
	for _, x := range w {
		if x > (q-1)/2 {
			x = q - x
		}
		if x > m {
			m = x
		}
	}
	return m
}
