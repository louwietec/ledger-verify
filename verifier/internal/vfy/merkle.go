package vfy

import "crypto/sha256"

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
