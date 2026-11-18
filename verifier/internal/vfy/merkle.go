package vfy

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// RFC 6962 Merkle tree over entry hashes with domain separation:
// Leaf(n) = SHA-256(0x00 || entryHashBytes), Node(L,R) = SHA-256(0x01 || L || R).

func leafHash(entryHash []byte) [32]byte {
	buf := make([]byte, 0, 33)
	buf = append(buf, 0x00)
	buf = append(buf, entryHash...)
	return sha256.Sum256(buf)
}

func nodeHash(l, r [32]byte) [32]byte {
	buf := make([]byte, 0, 65)
	buf = append(buf, 0x01)
	buf = append(buf, l[:]...)
	buf = append(buf, r[:]...)
	return sha256.Sum256(buf)
}

// merkleRoots computes the root after every prefix size incrementally.
// leaves[i] is the raw 32-byte entry_hash of seq i+1. Returned slice r has
// r[t-1] = root over leaves 1..t. Runs in O(n log n).
func merkleRoots(entryHashes [][]byte) [][32]byte {
	roots := make([][32]byte, len(entryHashes))
	// stack of perfect subtree roots; sizes are implied by binary counter
	var stack [][32]byte
	for i, eh := range entryHashes {
		h := leafHash(eh)
		stack = append(stack, h)
		// merge complete pairs: number of trailing merges = trailing ones of i+1...
		// standard binary counter merge: merge while the two topmost subtrees
		// have equal size, tracked via count of leaves so far.
		n := i + 1
		for m := n; m%2 == 0; m /= 2 {
			a := stack[len(stack)-2]
			b := stack[len(stack)-1]
			stack = stack[:len(stack)-2]
			stack = append(stack, nodeHash(a, b))
		}
		// current root = fold stack right to left
		r := stack[len(stack)-1]
		for j := len(stack) - 2; j >= 0; j-- {
			r = nodeHash(stack[j], r)
		}
		roots[i] = r
	}
	return roots
}

// RFC 9162 (Certificate Transparency 2.0) restates the proofs of RFC 6962
// section 2.1 with verification algorithms written out step by step. The
// three functions below follow that text; nothing in the verdicts uses them
// yet. They are here for an anchor that publishes roots in a log: its proofs
// come from outside the package and have to be checked, not recomputed.

// merkleEmptyRoot is MTH({}), the hash of a tree without leaves (RFC 9162
// section 2.1.1): SHA-256 of the empty string.
func merkleEmptyRoot() [32]byte { return sha256.Sum256(nil) }

// verifyInclusion checks an inclusion proof (RFC 9162 section 2.1.3.2):
// leaf is the leaf hash (leafHash, the 0x00 prefix already applied), index its
// position counted from 0 in a tree of size leaves, path the audit path from
// the leaf upwards, root the expected root. nil means the proof holds. A tree
// of size 0, an index not below the size and a path longer or shorter than
// the tree needs fail.
//
// The proof binds the leaf, its index and the root, the size only through the
// shape of the path: the path of leaf 0 in a tree of 5 leaves (d1, MTH(d2,d3),
// d4, each on the right) is also a well-shaped path for 7 leaves, and verifies
// with the same root. RFC 9162 takes size and root from one signed tree head;
// a caller must do the same and never combine a root with a size from
// elsewhere. The same holds for verifyConsistency and its two sizes.
func verifyInclusion(leaf [32]byte, index, size uint64, path [][32]byte, root [32]byte) error {
	if size == 0 {
		return errors.New("an inclusion proof in a tree of size 0")
	}
	if index >= size {
		return fmt.Errorf("leaf index %d is not below the tree size %d", index, size)
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range path {
		if sn == 0 {
			return fmt.Errorf("an audit path of %d hashes is longer than the tree of size %d needs", len(path), size)
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return fmt.Errorf("an audit path of %d hashes is shorter than the tree of size %d needs", len(path), size)
	}
	if r != root {
		return errors.New("the audit path leads to another root")
	}
	return nil
}

// verifyConsistency checks a consistency proof (RFC 9162 section 2.1.4.2):
// the tree of size1 with root1 is a prefix of the tree of size2 with root2.
// nil means the proof holds. RFC 9162 defines the proof for 0 < size1 <
// size2; the two edges are settled without one, as spec 5 does for equal
// sizes: size1 = size2 holds with an empty path when the roots are equal, and
// size1 = 0 with an empty path when root1 is the root of the empty tree, which
// is a prefix of every tree.
func verifyConsistency(size1, size2 uint64, root1, root2 [32]byte, path [][32]byte) error {
	switch {
	case size1 > size2:
		return fmt.Errorf("the first tree (size %d) is larger than the second (size %d)", size1, size2)
	case size1 == 0 || size1 == size2:
		if len(path) != 0 {
			return fmt.Errorf("a consistency proof from size %d to size %d is empty, this one has %d hashes", size1, size2, len(path))
		}
		if size1 == 0 && root1 != merkleEmptyRoot() {
			return errors.New("the first root is not the root of the empty tree")
		}
		if size1 == size2 && root1 != root2 {
			return errors.New("two trees of the same size with different roots")
		}
		return nil
	}
	if len(path) == 0 {
		return errors.New("an empty consistency proof between different sizes")
	}
	// Step 2: when size1 is a power of two, the first tree is a complete
	// subtree of the second, and its root starts the path.
	if size1&(size1-1) == 0 {
		path = append([][32]byte{root1}, path...)
	}
	fn, sn := size1-1, size2-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := path[0], path[0]
	for _, c := range path[1:] {
		if sn == 0 {
			return fmt.Errorf("a consistency proof of %d hashes is longer than sizes %d and %d need", len(path), size1, size2)
		}
		if fn&1 == 1 || fn == sn {
			fr = nodeHash(c, fr)
			sr = nodeHash(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = nodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return fmt.Errorf("a consistency proof of %d hashes is shorter than sizes %d and %d need", len(path), size1, size2)
	}
	if fr != root1 {
		return errors.New("the consistency proof does not lead to the first root")
	}
	if sr != root2 {
		return errors.New("the consistency proof does not lead to the second root")
	}
	return nil
}
