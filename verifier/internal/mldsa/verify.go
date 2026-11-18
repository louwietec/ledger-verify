package mldsa

import "crypto/subtle"

// Reasons for a rejection inside verification. They are not exported: the
// API answers only valid or invalid, the tests check which step decided.
type outcome int

const (
	valid outcome = iota
	badParams
	badPKLength
	badSigLength
	badContext
	badHint   // HintBitUnpack returned bottom
	badZNorm  // ||z||_inf >= gamma1 - beta
	badCommit // c~ != c~'
)

// Verify reports whether sig is a valid ML-DSA signature of msg under the
// public key pk with the context string ctx (FIPS 204 Algorithm 3,
// ML-DSA.Verify, pure variant). An empty or nil ctx is the empty context.
// Wrong lengths of pk or sig, a ctx longer than 255 bytes and a nil params
// yield false.
func Verify(params *Params, pk, msg, ctx, sig []byte) bool {
	return verify(params, pk, msg, ctx, sig) == valid
}

func verify(p *Params, pk, msg, ctx, sig []byte) outcome {
	if p == nil {
		return badParams
	}
	if len(ctx) > 255 {
		return badContext
	}
	// M' = IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) || ctx || M
	prefix := make([]byte, 0, 2+len(ctx))
	prefix = append(prefix, 0, byte(len(ctx)))
	prefix = append(prefix, ctx...)
	return verifyInternal(p, pk, sig, nil, prefix, msg)
}

// verifyInternal is Algorithm 8 (ML-DSA.Verify_internal). The formatted
// message M' is the concatenation of mParts. If mu is not nil it is used
// as the message representative directly instead of H(tr || M', 64) (the
// "external mu" interface of the ACVP tests); mParts is then ignored.
func verifyInternal(p *Params, pk, sig, mu []byte, mParts ...[]byte) outcome {
	if p == nil {
		return badParams
	}
	if len(pk) != p.pkLen {
		return badPKLength
	}
	if len(sig) != p.sigLen {
		return badSigLength
	}
	rho, t1 := pkDecode(p, pk)
	ctilde, z, h, ok := sigDecode(p, sig)
	if !ok {
		return badHint
	}
	// The norm check of line 13 does not depend on the rest; doing it first
	// saves work and gives the tests a distinct outcome.
	bound := p.gamma1 - p.beta
	for i := range z {
		if infNorm(&z[i]) >= bound {
			return badZNorm
		}
	}

	if mu == nil {
		tr := shakeH(64, pk)
		mu = shakeH(64, append([][]byte{tr}, mParts...)...)
	} else if len(mu) != 64 {
		return badParams
	}

	aHat := expandA(p, rho)
	c := sampleInBall(p, ctilde)
	ntt(c)

	// NTT(z)
	for i := range z {
		ntt(&z[i])
	}

	// w'_approx = NTT^-1(A^ o NTT(z) - NTT(c) o NTT(t1 * 2^d)), then UseHint.
	w1 := make([]poly, p.k)
	for r := 0; r < p.k; r++ {
		var acc poly
		for s := 0; s < p.l; s++ {
			mulAddNTT(&acc, aHat[r][s], &z[s])
		}
		t := t1[r]
		for j := range t {
			t[j] <<= d // t1 < 2^10, so t1 * 2^d < 2^23 < q
		}
		ntt(&t)
		for j := range acc {
			acc[j] = subq(acc[j], mulq(c[j], t[j]))
		}
		invNTT(&acc)
		for j := range acc {
			w1[r][j] = useHint(p, h[r][j], acc[j])
		}
	}

	ctilde2 := shakeH(p.ctildeLen, mu, w1Encode(p, w1))
	if subtle.ConstantTimeCompare(ctilde, ctilde2) != 1 {
		return badCommit
	}
	return valid
}

// decompose is Algorithm 36 for r in [0, q): r = r1 * 2*gamma2 + r0 with
// r0 in (-gamma2, gamma2], except for the wrap-around case r - r0 = q - 1.
func decompose(p *Params, r uint32) (r1 uint32, r0 int32) {
	a := 2 * p.gamma2
	r0 = int32(r % a)
	if r0 > int32(p.gamma2) {
		r0 -= int32(a)
	}
	if int64(r)-int64(r0) == q-1 {
		return 0, r0 - 1
	}
	return uint32((int64(r) - int64(r0)) / int64(a)), r0
}

// useHint is Algorithm 40.
func useHint(p *Params, h bool, r uint32) uint32 {
	m := (q - 1) / (2 * p.gamma2)
	r1, r0 := decompose(p, r)
	if !h {
		return r1
	}
	if r0 > 0 {
		return (r1 + 1) % m
	}
	return (r1 + m - 1) % m
}
