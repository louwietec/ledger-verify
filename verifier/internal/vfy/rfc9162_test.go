package vfy

// Inclusion and consistency proofs (RFC 9162 sections 2.1.3 and 2.1.4)
// against an independent proof generator written here from the recursive
// definitions PATH and SUBPROOF, for every tree size 1 to 64 and every leaf
// index or prefix size. Every proof must verify, and every single-bit
// mutation of path, leaf or root must fail; a changed index or size fails
// exactly when it changes the shape of the proof (refSides, refShape).
//
// The same cases go to verifier2 (verifier2_test.py has its own generator):
// with LEDGER_RFC9162_JSON set, TestRFC9162Kreuzprobe writes the valid proofs
// and a deterministic choice of mutations, each with the verdict Go reached,
// to that file, for a consumer that runs the other verifier on identical
// inputs.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/bits"
	"os"
	"testing"
)

func refLeaf(d []byte) [32]byte { return sha256.Sum256(append([]byte{0x00}, d...)) }

func refNode(l, r [32]byte) [32]byte {
	return sha256.Sum256(append(append([]byte{0x01}, l[:]...), r[:]...))
}

func refSplit(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// refMTH is MTH of RFC 9162 section 2.1.1, recursive as written there.
func refMTH(d [][]byte) [32]byte {
	switch len(d) {
	case 0:
		return sha256.Sum256(nil)
	case 1:
		return refLeaf(d[0])
	}
	k := refSplit(len(d))
	return refNode(refMTH(d[:k]), refMTH(d[k:]))
}

// refPath is PATH(m, D[n]) of RFC 9162 section 2.1.3.1.
func refPath(m int, d [][]byte) [][32]byte {
	if len(d) <= 1 {
		return nil
	}
	k := refSplit(len(d))
	if m < k {
		return append(refPath(m, d[:k]), refMTH(d[k:]))
	}
	return append(refPath(m-k, d[k:]), refMTH(d[:k]))
}

// refProof is PROOF(m, D[n]) = SUBPROOF(m, D[n], true) of RFC 9162 section
// 2.1.4.1.
func refProof(m int, d [][]byte) [][32]byte { return refSubproof(m, d, true) }

func refSubproof(m int, d [][]byte, b bool) [][32]byte {
	if m == len(d) {
		if b {
			return nil
		}
		return [][32]byte{refMTH(d)}
	}
	k := refSplit(len(d))
	if m <= k {
		return append(refSubproof(m, d[:k], b), refMTH(d[k:]))
	}
	return append(refSubproof(m-k, d[k:], false), refMTH(d[:k]))
}

// refSides is the shape of PATH(m, D[n]), read off the recursive definition:
// for each hash of the path from the leaf upwards, whether it is the left
// ("L") or the right ("R") sibling. false: there is no such path.
//
// The shape is all an inclusion proof binds of the tree size. A root of size
// n and its path for leaf m verify for every other size with the same shape
// (leaf 0 of 5 and of 7: d1, MTH(d2,d3), d4 on the right each time): RFC 9162
// takes the size and the root from the same signed tree head, and so must
// every caller. The mutation tests below therefore expect a changed size or
// index to verify exactly when the shape is the same.
func refSides(m, n uint64) (string, bool) {
	if n == 0 || m >= n {
		return "", false
	}
	if n == 1 {
		return "", true
	}
	k := uint64(1) << (bits.Len64(n-1) - 1)
	if m < k {
		s, _ := refSides(m, k)
		return s + "R", true
	}
	s, _ := refSides(m-k, n-k)
	return s + "L", true
}

// refShape is the shape of SUBPROOF(m, D[n], b) in the same sense: "S" for
// the hash of the first tree's own subtree, then "R" or "L" for each sibling.
func refShape(m, n uint64, b bool) (string, bool) {
	if m == 0 || m > n {
		return "", false
	}
	if m == n {
		if b {
			return "", true
		}
		return "S", true
	}
	k := uint64(1) << (bits.Len64(n-1) - 1)
	if m <= k {
		s, ok := refShape(m, k, b)
		return s + "R", ok
	}
	s, ok := refShape(m-k, n-k, false)
	return s + "L", ok
}

func sameSides(m, n, m2, n2 uint64) bool {
	a, ok1 := refSides(m, n)
	b, ok2 := refSides(m2, n2)
	return ok1 && ok2 && a == b
}

func sameShape(m, n, m2, n2 uint64) bool {
	a, ok1 := refShape(m, n, true)
	b, ok2 := refShape(m2, n2, true)
	return ok1 && ok2 && a == b
}

// wie renders a mutation for the failure message, only when one fails: a
// Sprintf per mutation would cost more than the proof check itself.
func wie(what string, arg int) string {
	if arg < 0 {
		return what
	}
	return fmt.Sprintf(what, arg)
}

func refLeaves(n int) [][]byte {
	d := make([][]byte, n)
	for i := range d {
		h := sha256.Sum256([]byte(fmt.Sprintf("rfc9162 leaf %d", i)))
		d[i] = h[:]
	}
	return d
}

func TestMerkleEmptyRoot(t *testing.T) {
	if got := hx(merkleEmptyRoot()); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("MTH({}) = %s", got)
	}
	if merkleEmptyRoot() != refMTH(nil) {
		t.Error("MTH({}) differs from the definition")
	}
}

func TestRFC9162Inclusion(t *testing.T) {
	t.Parallel() // some four million mutations each
	d := refLeaves(64)
	roots := merkleRoots(d)
	var proofs, mutations, shapes int
	for n := 1; n <= 64; n++ {
		root := refMTH(d[:n])
		if roots[n-1] != root {
			t.Fatalf("merkleRoots and MTH differ at size %d", n)
		}
		for m := 0; m < n; m++ {
			leaf, path := refLeaf(d[m]), refPath(m, d[:n])
			if err := verifyInclusion(leaf, uint64(m), uint64(n), path, root); err != nil {
				t.Fatalf("PATH(%d, D[%d]) does not verify: %v", m, n, err)
			}
			proofs++
			fail := func(what string, arg int, leaf [32]byte, idx, size uint64, path [][32]byte, root [32]byte) {
				mutations++
				if verifyInclusion(leaf, idx, size, path, root) == nil {
					t.Errorf("PATH(%d, D[%d]) with %s still verifies", m, n, wie(what, arg))
				}
			}
			for j := range path {
				for bit := 0; bit < 256; bit++ {
					path[j][bit/8] ^= 1 << (bit % 8)
					fail("bit %d of path[j] flipped", bit, leaf, uint64(m), uint64(n), path, root)
					path[j][bit/8] ^= 1 << (bit % 8)
				}
			}
			for bit := 0; bit < 256; bit++ {
				r, l := root, leaf
				r[bit/8] ^= 1 << (bit % 8)
				l[bit/8] ^= 1 << (bit % 8)
				fail("bit %d of the root flipped", bit, leaf, uint64(m), uint64(n), path, r)
				fail("bit %d of the leaf flipped", bit, l, uint64(m), uint64(n), path, root)
			}
			for bit := 0; bit < 64; bit++ {
				for _, v := range [][2]uint64{{uint64(m) ^ 1<<bit, uint64(n)}, {uint64(m), uint64(n) ^ 1<<bit}} {
					mutations++
					want := sameSides(uint64(m), uint64(n), v[0], v[1])
					if got := verifyInclusion(leaf, v[0], v[1], path, root) == nil; got != want {
						t.Errorf("PATH(%d, D[%d]) as index %d, size %d: verifies %v, want %v (same shape: %v)", m, n, v[0], v[1], got, want, want)
					}
					shapes += map[bool]int{true: 1}[want]
				}
			}
			for j := range path {
				short := append(append([][32]byte{}, path[:j]...), path[j+1:]...)
				fail("path[%d] left out", j, leaf, uint64(m), uint64(n), short, root)
			}
			fail("a hash appended to the path", -1, leaf, uint64(m), uint64(n), append(append([][32]byte{}, path...), root), root)
			fail("a hash put before the path", -1, leaf, uint64(m), uint64(n), append([][32]byte{leaf}, path...), root)
		}
	}
	if err := verifyInclusion(refLeaf(d[0]), 0, 0, nil, merkleEmptyRoot()); err == nil {
		t.Error("an inclusion proof in the empty tree verified")
	}
	t.Logf("%d inclusion proofs verified, %d mutations refused except the %d with the size changed to one of the same shape", proofs, mutations-shapes, shapes)
}

func TestRFC9162Consistency(t *testing.T) {
	t.Parallel() // some four million mutations each
	d := refLeaves(64)
	var proofs, mutations, shapes int
	for n := 1; n <= 64; n++ {
		root2 := refMTH(d[:n])
		for m := 1; m <= n; m++ {
			root1, path := refMTH(d[:m]), refProof(m, d[:n])
			if err := verifyConsistency(uint64(m), uint64(n), root1, root2, path); err != nil {
				t.Fatalf("PROOF(%d, D[%d]) does not verify: %v", m, n, err)
			}
			proofs++
			fail := func(what string, arg int, m, n uint64, root1, root2 [32]byte, path [][32]byte) {
				mutations++
				if verifyConsistency(m, n, root1, root2, path) == nil {
					t.Errorf("PROOF(%d, D[%d]) with %s still verifies", m, n, wie(what, arg))
				}
			}
			for j := range path {
				for bit := 0; bit < 256; bit++ {
					path[j][bit/8] ^= 1 << (bit % 8)
					fail("bit %d of path[j] flipped", bit, uint64(m), uint64(n), root1, root2, path)
					path[j][bit/8] ^= 1 << (bit % 8)
				}
			}
			for bit := 0; bit < 256; bit++ {
				r1, r2 := root1, root2
				r1[bit/8] ^= 1 << (bit % 8)
				r2[bit/8] ^= 1 << (bit % 8)
				fail("bit %d of the first root flipped", bit, uint64(m), uint64(n), r1, root2, path)
				fail("bit %d of the second root flipped", bit, uint64(m), uint64(n), root1, r2, path)
			}
			for bit := 0; bit < 64; bit++ {
				for _, v := range [][2]uint64{{uint64(m) ^ 1<<bit, uint64(n)}, {uint64(m), uint64(n) ^ 1<<bit}} {
					mutations++
					want := sameShape(uint64(m), uint64(n), v[0], v[1])
					if got := verifyConsistency(v[0], v[1], root1, root2, path) == nil; got != want {
						t.Errorf("PROOF(%d, D[%d]) as sizes %d, %d: verifies %v, want %v", m, n, v[0], v[1], got, want)
					}
					shapes += map[bool]int{true: 1}[want]
				}
			}
			for j := range path {
				short := append(append([][32]byte{}, path[:j]...), path[j+1:]...)
				fail("path[%d] left out", j, uint64(m), uint64(n), root1, root2, short)
			}
			fail("a hash appended to the path", -1, uint64(m), uint64(n), root1, root2, append(append([][32]byte{}, path...), root2))
		}
		// From the empty tree: an empty path and the root of the empty tree,
		// nothing else (the empty tree is a prefix of every tree).
		if err := verifyConsistency(0, uint64(n), merkleEmptyRoot(), root2, nil); err != nil {
			t.Errorf("from size 0 to %d: %v", n, err)
		}
		if verifyConsistency(0, uint64(n), root2, root2, nil) == nil || verifyConsistency(0, uint64(n), merkleEmptyRoot(), root2, [][32]byte{root2}) == nil {
			t.Errorf("from size 0 to %d with another first root or a path verified", n)
		}
		if verifyConsistency(uint64(n)+1, uint64(n), root2, root2, nil) == nil {
			t.Errorf("from size %d down to %d verified", n+1, n)
		}
	}
	if verifyConsistency(0, 0, merkleEmptyRoot(), merkleEmptyRoot(), nil) != nil || verifyConsistency(0, 0, refMTH(d[:1]), refMTH(d[:1]), nil) == nil {
		t.Error("the empty tree against itself")
	}
	t.Logf("%d consistency proofs verified, %d mutations refused except the %d with a size changed to one of the same shape", proofs, mutations-shapes, shapes)
}

// kreuzFall is one case of the cross-check with the other verifier.
type kreuzFall struct {
	Kind  string   `json:"kind"` // "inclusion" or "consistency"
	What  string   `json:"what"`
	Leaf  string   `json:"leaf,omitempty"`
	Index uint64   `json:"index"`
	Size  uint64   `json:"size"`
	Size1 uint64   `json:"size1"`
	Size2 uint64   `json:"size2"`
	Root  string   `json:"root,omitempty"`
	Root1 string   `json:"root1,omitempty"`
	Root2 string   `json:"root2,omitempty"`
	Path  []string `json:"path"`
	Valid bool     `json:"valid"`
}

func hexAll(p [][32]byte) []string {
	out := make([]string, len(p))
	for i, h := range p {
		out[i] = hex.EncodeToString(h[:])
	}
	return out
}

func hx(h [32]byte) string { return hex.EncodeToString(h[:]) }

func blattHex(d [][]byte) []string {
	out := make([]string, len(d))
	for i, x := range d {
		out[i] = hex.EncodeToString(x)
	}
	return out
}

// TestRFC9162Kreuzprobe builds the cases of the cross-check: every valid
// inclusion and consistency proof for sizes 1 to 64 and, per proof, a fixed
// choice of single-bit, index, size and length mutations. Go's verdict must
// equal the generator's; with LEDGER_RFC9162_JSON set the cases are written
// there for verifier2.
func TestRFC9162Kreuzprobe(t *testing.T) {
	d := refLeaves(64)
	var faelle []kreuzFall
	flip := func(h [32]byte, bit int) [32]byte { h[bit/8] ^= 1 << (bit % 8); return h }
	for n := 1; n <= 64; n++ {
		root := refMTH(d[:n])
		for m := 0; m < n; m++ {
			leaf, path := refLeaf(d[m]), refPath(m, d[:n])
			add := func(what string, leaf [32]byte, idx, size uint64, path [][32]byte, root [32]byte, valid bool) {
				faelle = append(faelle, kreuzFall{Kind: "inclusion", What: what, Leaf: hx(leaf), Index: idx, Size: size, Root: hx(root), Path: hexAll(path), Valid: valid})
			}
			add("valid", leaf, uint64(m), uint64(n), path, root, true)
			for j := range path {
				p := append([][32]byte{}, path...)
				p[j] = flip(p[j], (31*j+7*m+n)%256)
				add(fmt.Sprintf("path[%d] bit flipped", j), leaf, uint64(m), uint64(n), p, root, false)
			}
			add("root bit flipped", leaf, uint64(m), uint64(n), path, flip(root, (13*m+n)%256), false)
			add("leaf bit flipped", flip(leaf, (17*m+3*n)%256), uint64(m), uint64(n), path, root, false)
			for _, v := range []struct {
				what      string
				idx, size uint64
			}{{"index bit 0 flipped", uint64(m) ^ 1, uint64(n)}, {"index bit flipped", uint64(m) ^ 1<<(m%7), uint64(n)},
				{"size bit 0 flipped", uint64(m), uint64(n) ^ 1}, {"size bit flipped", uint64(m), uint64(n) ^ 1<<(n%7)}} {
				add(v.what, leaf, v.idx, v.size, path, root, sameSides(uint64(m), uint64(n), v.idx, v.size))
			}
			if len(path) > 0 {
				add("last hash left out", leaf, uint64(m), uint64(n), path[:len(path)-1], root, false)
			}
			add("a hash appended", leaf, uint64(m), uint64(n), append(append([][32]byte{}, path...), root), root, false)
		}
		for m := 0; m <= n; m++ {
			root1 := refMTH(d[:m])
			var path [][32]byte
			if m > 0 {
				path = refProof(m, d[:n])
			}
			add := func(what string, s1, s2 uint64, r1, r2 [32]byte, path [][32]byte, valid bool) {
				faelle = append(faelle, kreuzFall{Kind: "consistency", What: what, Size1: s1, Size2: s2, Root1: hx(r1), Root2: hx(r2), Path: hexAll(path), Valid: valid})
			}
			add("valid", uint64(m), uint64(n), root1, root, path, true)
			for j := range path {
				p := append([][32]byte{}, path...)
				p[j] = flip(p[j], (29*j+5*m+n)%256)
				add(fmt.Sprintf("path[%d] bit flipped", j), uint64(m), uint64(n), root1, root, p, false)
			}
			add("first root bit flipped", uint64(m), uint64(n), flip(root1, (11*m+n)%256), root, path, false)
			if m > 0 { // from the empty tree any second tree is consistent
				add("second root bit flipped", uint64(m), uint64(n), root1, flip(root, (7*m+n)%256), path, false)
				add("second size bit 0 flipped", uint64(m), uint64(n)^1, root1, root, path, sameShape(uint64(m), uint64(n), uint64(m), uint64(n)^1))
				add("first size bit 0 flipped", uint64(m)^1, uint64(n), root1, root, path, sameShape(uint64(m), uint64(n), uint64(m)^1, uint64(n)))
			}
			if len(path) > 0 {
				add("last hash left out", uint64(m), uint64(n), root1, root, path[:len(path)-1], false)
			}
			add("a hash appended", uint64(m), uint64(n), root1, root, append(append([][32]byte{}, path...), root), false)
		}
	}
	for i, f := range faelle {
		got := kreuzUrteil(t, f)
		if got != f.Valid {
			t.Fatalf("case %d (%s %s): Go says %v, the generator %v", i, f.Kind, f.What, got, f.Valid)
		}
	}
	t.Logf("%d cross-check cases, Go agrees with the generator on all", len(faelle))
	if out := os.Getenv("LEDGER_RFC9162_JSON"); out != "" {
		b, err := json.Marshal(map[string]any{
			"empty_root": hx(merkleEmptyRoot()),
			"leaves":     blattHex(d),
			"cases":      faelle,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, b, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("written to %s", out)
	}
}

func kreuzUrteil(t *testing.T, f kreuzFall) bool {
	t.Helper()
	h := func(s string) [32]byte {
		var out [32]byte
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 {
			t.Fatalf("hash %q", s)
		}
		copy(out[:], b)
		return out
	}
	var path [][32]byte
	for _, p := range f.Path {
		path = append(path, h(p))
	}
	if f.Kind == "inclusion" {
		return verifyInclusion(h(f.Leaf), f.Index, f.Size, path, h(f.Root)) == nil
	}
	return verifyConsistency(f.Size1, f.Size2, h(f.Root1), h(f.Root2), path) == nil
}
