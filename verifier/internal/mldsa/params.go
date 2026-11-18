// Package mldsa verifies ML-DSA signatures (FIPS 204, August 2024).
//
// Only verification is implemented, for the three parameter sets of
// FIPS 204 Table 1 and the pure variant with a context string
// (Algorithm 3 ML-DSA.Verify on top of Algorithm 8 ML-DSA.Verify_internal).
// The pre-hash variant (HashML-DSA, Algorithm 5) is not supported.
//
// The package is written from the FIPS 204 text alone and uses the
// standard library only (crypto/sha3 for SHAKE128 and SHAKE256). It shares
// no code with any signing implementation.
package mldsa

// Constants of FIPS 204 section 4.
const (
	n    = 256
	q    = 8380417 // 2^23 - 2^13 + 1
	d    = 13      // dropped bits of t
	zeta = 1753    // 512th root of unity mod q
)

// Params is one ML-DSA parameter set (FIPS 204 Table 1 and Table 2).
type Params struct {
	name   string
	k, l   int    // dimensions of A (k rows, l columns)
	tau    int    // number of +-1 in c
	lambda int    // collision strength of c~ in bits
	gamma1 uint32 // coefficient range of y
	gamma2 uint32 // low-order rounding range
	eta    int    // private key range (not needed for verification)
	beta   uint32 // tau * eta
	omega  int    // maximum number of ones in the hint h

	// Derived sizes in bytes.
	ctildeLen int // lambda / 4
	zBits     int // 1 + bitlen(gamma1 - 1)
	w1Bits    int // bitlen((q-1)/(2*gamma2) - 1)
	pkLen     int
	sigLen    int
}

func newParams(name string, k, l, tau, lambda int, gamma1, gamma2 uint32, eta, omega int) *Params {
	p := &Params{
		name: name, k: k, l: l, tau: tau, lambda: lambda,
		gamma1: gamma1, gamma2: gamma2, eta: eta, omega: omega,
		beta: uint32(tau * eta),
	}
	p.ctildeLen = lambda / 4
	p.zBits = 1 + bitlen(gamma1-1)
	p.w1Bits = bitlen((q-1)/(2*gamma2) - 1)
	// pkEncode (Algorithm 22): rho and k polynomials of bitlen(q-1)-d = 10 bits.
	p.pkLen = 32 + k*n*10/8
	// sigEncode (Algorithm 26): c~, l polynomials z, omega+k hint bytes.
	p.sigLen = p.ctildeLen + l*n*p.zBits/8 + omega + k
	return p
}

// The three parameter sets of FIPS 204 Table 1.
var (
	MLDSA44 = newParams("ML-DSA-44", 4, 4, 39, 128, 1<<17, (q-1)/88, 2, 80)
	MLDSA65 = newParams("ML-DSA-65", 6, 5, 49, 192, 1<<19, (q-1)/32, 4, 55)
	MLDSA87 = newParams("ML-DSA-87", 8, 7, 60, 256, 1<<19, (q-1)/32, 2, 75)
)

// Name returns the name of the parameter set as in FIPS 204, e.g. "ML-DSA-65".
func (p *Params) Name() string { return p.name }

// PublicKeySize is the length of an encoded public key in bytes.
func (p *Params) PublicKeySize() int { return p.pkLen }

// SignatureSize is the length of an encoded signature in bytes.
func (p *Params) SignatureSize() int { return p.sigLen }

// bitlen is the number of bits in the binary representation of a positive
// integer (FIPS 204 section 2.3).
func bitlen(x uint32) int {
	b := 0
	for x > 0 {
		b++
		x >>= 1
	}
	return b
}
