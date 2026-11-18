package vfy

// Format spec 2 ("Signaturen", from edition 1.10): no Ed25519 signature
// holds under a public key of small order, whatever its sign bit.

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

// basisPunkt is the encoding of the base point B (RFC 8032 5.1).
const basisPunkt = "5866666666666666666666666666666666666666666666666666666666666666"

var kleineOrdnungY = []string{
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0100000000000000000000000000000000000000000000000000000000000000",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
}

// TestKleineOrdnungTraegtNicht: under 01 followed by 31 zero bytes the
// signature R = B, S = 1 holds for crypto/ed25519 over any message; the
// verifier refuses it, and every other small-order key with either sign bit.
func TestKleineOrdnungTraegtNicht(t *testing.T) {
	sig := basisPunkt + "01" + strings.Repeat("00", 31)
	id, _ := hex.DecodeString(kleineOrdnungY[1])
	sb, _ := hex.DecodeString(sig)
	if !ed25519.Verify(ed25519.PublicKey(id), []byte("beliebig"), sb) {
		t.Fatal("the reference forgery R = B, S = 1 does not hold for crypto/ed25519; the test proves nothing")
	}
	if verifySig(kleineOrdnungY[1], []byte("beliebig"), sig) {
		t.Fatal("format spec 2: a signature under the identity holds")
	}
	for _, y := range kleineOrdnungY {
		for _, vz := range []bool{false, true} {
			b, _ := hex.DecodeString(y)
			if vz {
				b[31] |= 0x80
			}
			if verifySig(hex.EncodeToString(b), []byte("beliebig"), sig) {
				t.Errorf("format spec 2: a signature holds under %x", b)
			}
		}
	}
	// A key of large order next to them still verifies.
	k := ed25519.NewKeyFromSeed(make([]byte, 32))
	s := ed25519.Sign(k, []byte("m"))
	if !verifySig(hex.EncodeToString(k.Public().(ed25519.PublicKey)), []byte("m"), hex.EncodeToString(s)) {
		t.Fatal("an honest signature no longer holds")
	}
}
