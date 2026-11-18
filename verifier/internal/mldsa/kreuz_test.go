package mldsa

// Cross test: signatures made by the appliance's signing implementation
// (testdata/kreuz_appliance.json, a file and not an import), verified here,
// plus negative tests derived from them: bit flips in signature, public
// key and message, wrong context, wrong lengths and malformed hints.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type kreuzFall struct {
	Name         string `json:"name"`
	ParameterSet string `json:"parameterSet"`
	PK           hexStr `json:"pk"`
	Message      hexStr `json:"message"`
	Context      hexStr `json:"context"`
	Signature    hexStr `json:"signature"`
}

func loadKreuz(t testing.TB) []kreuzFall {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "kreuz_appliance.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Faelle []kreuzFall `json:"faelle"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, c := range f.Faelle {
		if paramsByName(c.ParameterSet) == nil {
			t.Fatalf("unknown parameter set %q", c.ParameterSet)
		}
		seen[c.ParameterSet]++
	}
	for _, p := range []*Params{MLDSA44, MLDSA65, MLDSA87} {
		if seen[p.Name()] == 0 {
			t.Fatalf("no cross vectors for %s", p.Name())
		}
	}
	return f.Faelle
}

func flip(b []byte, bit int) []byte {
	c := append([]byte(nil), b...)
	c[bit/8] ^= 1 << (bit % 8)
	return c
}

func TestKreuzPositiv(t *testing.T) {
	for _, c := range loadKreuz(t) {
		p := paramsByName(c.ParameterSet)
		if got := verify(p, c.PK, c.Message, c.Context, c.Signature); got != valid {
			t.Errorf("%s %s: outcome %d", c.ParameterSet, c.Name, got)
		}
		if !Verify(p, c.PK, c.Message, c.Context, c.Signature) {
			t.Errorf("%s %s: Verify false", c.ParameterSet, c.Name)
		}
	}
}

func TestKreuzBitflips(t *testing.T) {
	for _, c := range loadKreuz(t) {
		if c.Name != "kurz_mit_kontext" {
			continue // one case per parameter set is enough for the sweep
		}
		p := paramsByName(c.ParameterSet)
		// Signature: one bit in every 5th byte, rotating the bit position,
		// covers c~, all z polynomials and the hint area.
		n := 0
		for i := 0; i < len(c.Signature); i += 5 {
			s := flip(c.Signature, 8*i+i%8)
			if Verify(p, c.PK, c.Message, c.Context, s) {
				t.Errorf("%s: signature with bit %d flipped accepted", p.Name(), 8*i+i%8)
			}
			n++
		}
		// Every byte of the hint area and of c~ individually.
		hintStart := p.sigLen - p.omega - p.k
		for i := 0; i < p.ctildeLen; i++ {
			if Verify(p, c.PK, c.Message, c.Context, flip(c.Signature, 8*i+7)) {
				t.Errorf("%s: c~ byte %d flipped accepted", p.Name(), i)
			}
		}
		for i := hintStart; i < p.sigLen; i++ {
			for _, bit := range []int{0, 7} {
				if Verify(p, c.PK, c.Message, c.Context, flip(c.Signature, 8*i+bit)) {
					t.Errorf("%s: hint byte %d bit %d flipped accepted", p.Name(), i, bit)
				}
			}
		}
		// Public key: rho and t1.
		for i := 0; i < len(c.PK); i += 7 {
			if Verify(p, flip(c.PK, 8*i+i%8), c.Message, c.Context, c.Signature) {
				t.Errorf("%s: pk bit %d flipped accepted", p.Name(), 8*i+i%8)
			}
		}
		// Message: every bit.
		for b := 0; b < 8*len(c.Message); b++ {
			if Verify(p, c.PK, flip(c.Message, b), c.Context, c.Signature) {
				t.Errorf("%s: message bit %d flipped accepted", p.Name(), b)
			}
		}
		t.Logf("%s: %d signature flips, %d hint/c~ bytes, %d pk flips, %d message flips rejected",
			p.Name(), n, p.ctildeLen+p.omega+p.k, (len(c.PK)+6)/7, 8*len(c.Message))
	}
}

func TestKreuzMessageAndContext(t *testing.T) {
	for _, c := range loadKreuz(t) {
		p := paramsByName(c.ParameterSet)
		reject := func(what string, pk, msg, ctx, sig []byte) {
			t.Helper()
			if Verify(p, pk, msg, ctx, sig) {
				t.Errorf("%s %s: %s accepted", p.Name(), c.Name, what)
			}
		}
		reject("message with appended byte", c.PK, append(append([]byte(nil), c.Message...), 0), c.Context, c.Signature)
		if len(c.Message) > 0 {
			reject("truncated message", c.PK, c.Message[:len(c.Message)-1], c.Context, c.Signature)
		}
		// Context.
		reject("other context", c.PK, c.Message, []byte("ledger-v2"), c.Signature)
		reject("context with appended byte", c.PK, c.Message, append(append([]byte(nil), c.Context...), 0), c.Signature)
		if len(c.Context) > 0 {
			reject("empty context", c.PK, c.Message, nil, c.Signature)
			reject("context bit flip", c.PK, c.Message, flip(c.Context, 0), c.Signature)
			// Moving bytes between context and message keeps ctx || M but
			// changes the length byte of M'.
			reject("context byte moved to message", c.PK,
				append([]byte{c.Context[len(c.Context)-1]}, c.Message...),
				c.Context[:len(c.Context)-1], c.Signature)
		}
		if got := verify(p, c.PK, c.Message, make([]byte, 256), c.Signature); got != badContext {
			t.Errorf("%s: 256-byte context: outcome %d", p.Name(), got)
		}
		// Empty and nil context are the same.
		if len(c.Context) == 0 && !Verify(p, c.PK, c.Message, []byte{}, c.Signature) {
			t.Errorf("%s: empty non-nil context rejected", p.Name())
		}
		// Pure versus internal interface: the signature is over M', not M.
		if verifyInternal(p, c.PK, c.Signature, nil, c.Message) == valid {
			t.Errorf("%s: signature verified without the M' prefix", p.Name())
		}
	}
}

func TestKreuzLengthsAndParams(t *testing.T) {
	for _, c := range loadKreuz(t) {
		p := paramsByName(c.ParameterSet)
		cases := []struct {
			what    string
			pk, sig []byte
			want    outcome
		}{
			{"short signature", c.PK, c.Signature[:len(c.Signature)-1], badSigLength},
			{"long signature", c.PK, append(append([]byte(nil), c.Signature...), 0), badSigLength},
			{"empty signature", c.PK, nil, badSigLength},
			{"short pk", c.PK[:len(c.PK)-1], c.Signature, badPKLength},
			{"long pk", append(append([]byte(nil), c.PK...), 0), c.Signature, badPKLength},
			{"empty pk", nil, c.Signature, badPKLength},
		}
		for _, k := range cases {
			if got := verify(p, k.pk, c.Message, c.Context, k.sig); got != k.want {
				t.Errorf("%s %s: outcome %d, want %d", p.Name(), k.what, got, k.want)
			}
		}
		for _, other := range []*Params{MLDSA44, MLDSA65, MLDSA87} {
			if other != p && Verify(other, c.PK, c.Message, c.Context, c.Signature) {
				t.Errorf("%s signature accepted under %s", p.Name(), other.Name())
			}
		}
		if Verify(nil, c.PK, c.Message, c.Context, c.Signature) {
			t.Error("nil params accepted")
		}
	}
}

// hintArea returns a copy of sig and the offset of its hint area.
func hintArea(p *Params, sig []byte) ([]byte, int) {
	return append([]byte(nil), sig...), p.sigLen - p.omega - p.k
}

func TestKreuzMalformedHints(t *testing.T) {
	covered := map[string]int{}
	for _, c := range loadKreuz(t) {
		p := paramsByName(c.ParameterSet)
		check := func(what string, sig []byte) {
			t.Helper()
			covered[what]++
			if got := verify(p, c.PK, c.Message, c.Context, sig); got != badHint {
				t.Errorf("%s %s: %s: outcome %d, want badHint", p.Name(), c.Name, what, got)
			}
		}
		_, off := hintArea(p, c.Signature)
		y := c.Signature[off:]
		counts := y[p.omega:]
		total := int(counts[p.k-1])

		// Count above omega in the last polynomial.
		s, o := hintArea(p, c.Signature)
		s[o+p.omega+p.k-1] = byte(p.omega + 1)
		check("count above omega", s)

		// Count of polynomial 0 larger than that of polynomial 1.
		s, o = hintArea(p, c.Signature)
		s[o+p.omega] = counts[1] + 1
		check("decreasing count", s)

		// Nonzero byte in the unused position area.
		if total < p.omega {
			s, o = hintArea(p, c.Signature)
			s[o+p.omega-1] = 1
			check("nonzero unused hint byte", s)
		}

		// Within one polynomial: equal and decreasing positions.
		start := 0
		for i := 0; i < p.k; i++ {
			end := int(counts[i])
			if end-start >= 2 {
				s, o = hintArea(p, c.Signature)
				s[o+start+1] = s[o+start] // duplicate
				check("repeated hint position", s)
				s, o = hintArea(p, c.Signature)
				s[o+start], s[o+start+1] = s[o+start+1], s[o+start] // swap
				check("decreasing hint position", s)
				break
			}
			start = end
		}

		// Positions may start again from a small value in the next
		// polynomial: moving the boundary between two polynomials with the
		// positions unchanged gives a well-formed hint, so decoding passes
		// and the commitment check decides.
		for i := 0; i+1 < p.k; i++ {
			lo := 0
			if i > 0 {
				lo = int(counts[i-1])
			}
			if int(counts[i]) > lo {
				s, o = hintArea(p, c.Signature)
				s[o+p.omega+i]-- // last position of polynomial i moves to i+1
				// Only well-formed if it stays below the first position of
				// polynomial i+1; otherwise it is malformed. Either way the
				// signature is invalid.
				got := verify(p, c.PK, c.Message, c.Context, s)
				if got == valid {
					t.Errorf("%s: moved hint boundary accepted", p.Name())
				}
				break
			}
		}
	}
	for _, what := range []string{"count above omega", "decreasing count", "nonzero unused hint byte",
		"repeated hint position", "decreasing hint position"} {
		if covered[what] == 0 {
			t.Errorf("malformed hint case %q not exercised by any cross vector", what)
		}
	}
}

// setZ overwrites coefficient j of polynomial i of z in an encoded
// signature with the value v in [-gamma1 + 1, gamma1].
func setZ(p *Params, sig []byte, i, j int, v int32) []byte {
	s := append([]byte(nil), sig...)
	enc := uint64(int64(p.gamma1) - int64(v))
	bit := 8*p.ctildeLen + (i*n+j)*p.zBits
	for b := 0; b < p.zBits; b++ {
		pos := bit + b
		s[pos/8] &^= 1 << (pos % 8)
		s[pos/8] |= byte((enc>>b)&1) << (pos % 8)
	}
	return s
}

func TestKreuzZNorm(t *testing.T) {
	for _, c := range loadKreuz(t) {
		p := paramsByName(c.ParameterSet)
		bound := int32(p.gamma1 - p.beta)
		for _, k := range []struct {
			v    int32
			want outcome
		}{
			{bound, badZNorm},
			{-bound, badZNorm},
			{int32(p.gamma1), badZNorm},
			{-int32(p.gamma1) + 1, badZNorm},
			{bound - 1, badCommit},
			{-(bound - 1), badCommit},
		} {
			for _, pos := range [][2]int{{0, 0}, {p.l - 1, n - 1}} {
				s := setZ(p, c.Signature, pos[0], pos[1], k.v)
				if got := verify(p, c.PK, c.Message, c.Context, s); got != k.want {
					t.Errorf("%s: z[%d][%d] = %d: outcome %d, want %d", p.Name(), pos[0], pos[1], k.v, got, k.want)
				}
			}
		}
		// The helper itself must reproduce the original encoding.
		_, z, _, _ := sigDecode(p, c.Signature)
		v := int32(z[0][0])
		if v > int32(q-1)/2 {
			v -= q
		}
		if !bytes.Equal(setZ(p, c.Signature, 0, 0, v), c.Signature) {
			t.Fatalf("%s: setZ does not round-trip", p.Name())
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	faelle := loadKreuz(b)
	for _, p := range []*Params{MLDSA44, MLDSA65, MLDSA87} {
		var c kreuzFall
		for _, f := range faelle {
			if f.ParameterSet == p.Name() && f.Name == "1000_bytes_ohne_kontext" {
				c = f
			}
		}
		b.Run(p.Name(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if !Verify(p, c.PK, c.Message, c.Context, c.Signature) {
					b.Fatal("verify failed")
				}
			}
		})
	}
}

// FuzzVerify: arbitrary signature, key and message bytes must never panic
// and must never verify unless they are the original triple. The seed
// corpus runs with every go test; longer runs with -fuzz=FuzzVerify.
func FuzzVerify(f *testing.F) {
	faelle := loadKreuz(f)
	for _, c := range faelle {
		if c.Name == "kurz_mit_kontext" {
			f.Add(c.ParameterSet, []byte(c.PK), []byte(c.Message), []byte(c.Context), []byte(c.Signature))
		}
	}
	orig := map[string]kreuzFall{}
	for _, c := range faelle {
		orig[c.ParameterSet+string(c.PK)+string(c.Message)+string(c.Context)+string(c.Signature)] = c
	}
	f.Fuzz(func(t *testing.T, set string, pk, msg, ctx, sig []byte) {
		p := paramsByName(set)
		if p == nil {
			p = MLDSA44
		}
		if Verify(p, pk, msg, ctx, sig) {
			if _, ok := orig[p.Name()+string(pk)+string(msg)+string(ctx)+string(sig)]; !ok {
				t.Fatalf("%s: unexpected valid signature", p.Name())
			}
		}
	})
}
