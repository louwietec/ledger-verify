package tsa

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

// TestKleineOrdnungImZeitstempel: format spec 2 and 7.5.4, from edition
// 1.10: an Ed25519 signature in a time stamp does not hold under a public key
// of small order (here the identity, R = B, S = 1), whatever the sign bit.
func TestKleineOrdnungImZeitstempel(t *testing.T) {
	id, _ := hex.DecodeString("01" + strings.Repeat("00", 31))
	sig, _ := hex.DecodeString("5866666666666666666666666666666666666666666666666666666666666666" + "01" + strings.Repeat("00", 31))
	if !ed25519.Verify(ed25519.PublicKey(id), []byte("x"), sig) {
		t.Fatal("reference forgery does not hold for crypto/ed25519")
	}
	k := &publicKey{family: famEd25519, ed: ed25519.PublicKey(id)}
	if k.verify(scheme{family: famEd25519}, []byte("x"), sig) {
		t.Fatal("a signature under the identity holds in a time stamp")
	}
	for _, y := range []string{"00", "01", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"} {
		if len(y) == 2 {
			y += strings.Repeat("00", 31)
		}
		b, _ := hex.DecodeString(y)
		if !SmallOrderEd25519(b) {
			t.Errorf("%s not of small order", y)
		}
		b[31] |= 0x80
		if !SmallOrderEd25519(b) {
			t.Errorf("%x with sign bit not of small order", b)
		}
	}
	h := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	if SmallOrderEd25519(h) {
		t.Error("an ordinary key counts as small order")
	}
}
