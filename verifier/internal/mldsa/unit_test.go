package mldsa

// Tests of the building blocks against their definitions in FIPS 204.

import (
	"math/rand"
	"testing"
)

func TestSizes(t *testing.T) {
	for _, c := range []struct {
		p       *Params
		pk, sig int
	}{
		{MLDSA44, 1312, 2420},
		{MLDSA65, 1952, 3309},
		{MLDSA87, 2592, 4627},
	} {
		if c.p.PublicKeySize() != c.pk || c.p.SignatureSize() != c.sig {
			t.Errorf("%s: pk %d sig %d", c.p.Name(), c.p.PublicKeySize(), c.p.SignatureSize())
		}
	}
	if MLDSA44.w1Bits != 6 || MLDSA65.w1Bits != 4 || MLDSA87.w1Bits != 4 {
		t.Error("w1Encode widths")
	}
	if MLDSA44.zBits != 18 || MLDSA65.zBits != 20 || MLDSA87.zBits != 20 {
		t.Error("z widths")
	}
	if MLDSA44.beta != 78 || MLDSA65.beta != 196 || MLDSA87.beta != 120 {
		t.Error("beta")
	}
}

func TestZetas(t *testing.T) {
	// zeta is a primitive 512th root of unity: zeta^256 = -1.
	if powq(zeta, 256) != q-1 {
		t.Fatal("zeta^256 != -1")
	}
	// zetas[m] = zeta^BitRev8(m): zetas[128] = zeta, zetas[0] = 1, and the
	// first entries listed in FIPS 204 Appendix B.
	want := map[int]uint32{0: 1, 1: 4808194, 2: 3765607, 3: 3761513, 128: zeta}
	for i, w := range want {
		if zetas[i] != w {
			t.Errorf("zetas[%d] = %d, want %d", i, zetas[i], w)
		}
	}
	if mulq(nInv, 256) != 1 {
		t.Error("256^-1 mod q")
	}
}

func randPoly(r *rand.Rand) *poly {
	p := new(poly)
	for i := range p {
		p[i] = uint32(r.Intn(q))
	}
	return p
}

// schoolbook multiplies in Z_q[X]/(X^256 + 1).
func schoolbook(a, b *poly) *poly {
	var acc [2 * n]uint64
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			acc[i+j] = (acc[i+j] + uint64(a[i])*uint64(b[j])) % q
		}
	}
	c := new(poly)
	for i := 0; i < n; i++ {
		c[i] = subq(uint32(acc[i]), uint32(acc[i+n]))
	}
	return c
}

func TestNTT(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for it := 0; it < 5; it++ {
		a, b := randPoly(r), randPoly(r)
		want := schoolbook(a, b)
		x, y := *a, *b
		ntt(&x)
		ntt(&y)
		var prod poly
		mulAddNTT(&prod, &x, &y)
		invNTT(&prod)
		if prod != *want {
			t.Fatal("NTT product differs from schoolbook product")
		}
		invNTT(&x)
		if x != *a {
			t.Fatal("invNTT(NTT(a)) != a")
		}
	}
}

func TestDecompose(t *testing.T) {
	for _, p := range []*Params{MLDSA44, MLDSA87} { // the two values of gamma2
		m := (q - 1) / (2 * p.gamma2)
		for r := uint32(0); r < q; r++ {
			r1, r0 := decompose(p, r)
			if r1 >= m {
				t.Fatalf("r=%d: r1=%d out of range", r, r1)
			}
			if r0 < -int32(p.gamma2) || r0 > int32(p.gamma2) {
				t.Fatalf("r=%d: r0=%d out of range", r, r0)
			}
			back := (int64(r1)*int64(2*p.gamma2) + int64(r0)) % q
			if back < 0 {
				back += q
			}
			if back != int64(r) {
				t.Fatalf("r=%d: r1*2*gamma2 + r0 = %d", r, back)
			}
		}
	}
}

// The property UseHint relies on (FIPS 204 section 7.4): for ||z|| <=
// gamma2, UseHint(MakeHint(z, r), r) = HighBits(r + z), where MakeHint(z, r)
// = [HighBits(r) != HighBits(r + z)] (Algorithm 39, here only for the test).
func TestUseHint(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	for _, p := range []*Params{MLDSA44, MLDSA65} {
		for it := 0; it < 200000; it++ {
			x := uint32(r.Intn(q))
			z := int64(r.Intn(int(2*p.gamma2+1))) - int64(p.gamma2)
			xz := uint32((int64(x) + z + q) % q)
			hx, _ := decompose(p, x)
			hxz, _ := decompose(p, xz)
			h := hx != hxz
			if got := useHint(p, h, x); got != hxz {
				t.Fatalf("%s: UseHint(%v, %d) = %d, HighBits(r+z) = %d", p.Name(), h, x, got, hxz)
			}
		}
		// Boundary values of r.
		for _, x := range []uint32{0, 1, p.gamma2, p.gamma2 + 1, q - p.gamma2 - 1, q - p.gamma2, q - 2, q - 1} {
			m := (q - 1) / (2 * p.gamma2)
			r1, r0 := decompose(p, x)
			up, down := useHint(p, true, x), useHint(p, false, x)
			if down != r1 {
				t.Errorf("%s r=%d: UseHint(0) = %d, want %d", p.Name(), x, down, r1)
			}
			want := (r1 + m - 1) % m
			if r0 > 0 {
				want = (r1 + 1) % m
			}
			if up != want {
				t.Errorf("%s r=%d: UseHint(1) = %d, want %d", p.Name(), x, up, want)
			}
		}
	}
}

func TestHintBitUnpack(t *testing.T) {
	p := MLDSA44 // omega = 80, k = 4
	mk := func(pos []byte, counts ...byte) []byte {
		y := make([]byte, p.omega+p.k)
		copy(y, pos)
		copy(y[p.omega:], counts)
		return y
	}
	full := make([]byte, p.omega)
	for i := range full {
		full[i] = byte(i) // 80 increasing positions in polynomial 0
	}
	for _, c := range []struct {
		name string
		y    []byte
		ok   bool
	}{
		{"empty", mk(nil, 0, 0, 0, 0), true},
		{"one per polynomial, restarting", mk([]byte{5, 3, 3, 0}, 1, 2, 3, 4), true},
		{"exactly omega ones", mk(full, 80, 80, 80, 80), true},
		{"count above omega", mk(full, 80, 80, 80, 81), false},
		{"decreasing count", mk([]byte{1, 2}, 2, 1, 2, 2), false},
		{"equal positions", mk([]byte{7, 7}, 2, 2, 2, 2), false},
		{"decreasing positions", mk([]byte{9, 7}, 2, 2, 2, 2), false},
		{"nonzero unused byte", mk([]byte{1, 2, 0, 0, 9}, 2, 2, 2, 2), false},
		{"nonzero last unused byte", func() []byte { y := mk([]byte{1}, 1, 1, 1, 1); y[p.omega-1] = 1; return y }(), false},
		{"position 255", mk([]byte{255}, 1, 1, 1, 1), true},
	} {
		h, ok := hintBitUnpack(p, c.y)
		if ok != c.ok {
			t.Errorf("%s: ok=%v, want %v", c.name, ok, c.ok)
			continue
		}
		if ok {
			ones := 0
			for i := range h {
				for j := range h[i] {
					if h[i][j] {
						ones++
					}
				}
			}
			if ones != int(c.y[p.omega+p.k-1]) {
				t.Errorf("%s: %d ones, want %d", c.name, ones, c.y[p.omega+p.k-1])
			}
		}
	}
}

func TestBitPacking(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for _, bits := range []int{4, 6, 10, 18, 20} {
		var a poly
		for i := range a {
			a[i] = uint32(r.Intn(1 << bits))
		}
		enc := packBits(&a, bits)
		if len(enc) != 32*bits {
			t.Fatalf("bits=%d: length %d", bits, len(enc))
		}
		var back [n]uint32
		unpackBits(enc, bits, &back)
		if back != a {
			t.Fatalf("bits=%d: round trip", bits)
		}
	}
	// Little-endian bit order: value 1 in coefficient 0, 4 bits -> 0x01.
	var a poly
	a[0], a[1] = 1, 2
	if enc := packBits(&a, 4); enc[0] != 0x21 {
		t.Fatalf("bit order: %02x", enc[0])
	}
}

func TestSampleInBall(t *testing.T) {
	r := rand.New(rand.NewSource(4))
	for _, p := range []*Params{MLDSA44, MLDSA65, MLDSA87} {
		seed := make([]byte, p.ctildeLen)
		r.Read(seed)
		c := sampleInBall(p, seed)
		nz := 0
		for _, x := range c {
			switch x {
			case 0:
			case 1, q - 1:
				nz++
			default:
				t.Fatalf("%s: coefficient %d", p.Name(), x)
			}
		}
		if nz != p.tau {
			t.Errorf("%s: %d nonzero coefficients, want tau=%d", p.Name(), nz, p.tau)
		}
	}
}
