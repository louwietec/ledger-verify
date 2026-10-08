package tsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// The fixtures come from OpenSSL (testdata/erzeugen.sh). That is the point of
// them: a parser written by hand from the RFC must be held against a token
// somebody else produced, not against one it produced itself.

func laden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("testdata/%s: %v", name, err)
	}
	return b
}

func zertPool(t *testing.T, name string) *x509.CertPool {
	t.Helper()
	blk, _ := pem.Decode(laden(t, name))
	if blk == nil {
		t.Fatalf("testdata/%s: kein PEM", name)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	p := x509.NewCertPool()
	p.AddCert(c)
	return p
}

func TestParseOpenSSLToken(t *testing.T) {
	tok, err := Parse(laden(t, "openssl_token.der"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if tok.HashAlgorithm != "sha256" {
		t.Errorf("imprint algorithm = %q, want sha256", tok.HashAlgorithm)
	}
	want := sha256.Sum256(laden(t, "openssl_data.bin"))
	if string(tok.Imprint) != string(want[:]) {
		t.Errorf("imprint %x does not bind the stamped data %x", tok.Imprint, want)
	}
	if tok.GenTime.IsZero() || tok.GenTime.Location() != time.UTC {
		t.Errorf("genTime %v is not a UTC time", tok.GenTime)
	}
	if tok.Serial == "" || tok.Policy == "" {
		t.Errorf("serial %q / policy %q empty", tok.Serial, tok.Policy)
	}
	if tok.SignerName() == "" {
		t.Error("signer has no name")
	}
}

func TestVerifyOpenSSLToken(t *testing.T) {
	tok, err := Parse(laden(t, "openssl_token.der"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tok.CheckSignatureOnly(); err != nil {
		t.Fatalf("CheckSignatureOnly: %v", err)
	}
	if err := tok.Verify(zertPool(t, "openssl_tsa.crt"), nil); err != nil {
		t.Fatalf("Verify with the issuing authority as root: %v", err)
	}
}

// Ein Token, das zu einer FREMDEN Stelle kettet, darf nicht durchgehen — sonst
// prueft die Verankerung nur, ob irgendein Zertifikat beiliegt.
func TestVerifyFremdeWurzelScheitert(t *testing.T) {
	tok, err := Parse(laden(t, "openssl_token.der"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tok.Verify(zertPool(t, "fremd_tsa.crt"), nil); err == nil {
		t.Fatal("a token chained to a foreign root")
	}
	// Und die Gegenprobe: derselbe fremde Token kettet zu SEINER Wurzel.
	fremd, err := Parse(laden(t, "fremd_token.der"))
	if err != nil {
		t.Fatal(err)
	}
	if err := fremd.Verify(zertPool(t, "fremd_tsa.crt"), nil); err != nil {
		t.Fatalf("the foreign token does not verify against its own root: %v", err)
	}
}

func TestVerifyOhneWurzelScheitert(t *testing.T) {
	tok, err := Parse(laden(t, "openssl_token.der"))
	if err != nil {
		t.Fatal(err)
	}
	// nil und leer muessen BEIDE scheitern. Ein leerer Pool, der alles annimmt,
	// waere der stille Weg zu "geprueft, weil nichts zu pruefen war".
	if err := tok.Verify(nil, nil); err == nil {
		t.Error("Verify(nil) succeeded")
	}
	if err := tok.Verify(x509.NewCertPool(), nil); err == nil {
		t.Error("Verify(empty pool) succeeded")
	}
}

// Jedes einzelne gekippte Byte muss auffallen — beim Parsen oder bei der
// Signatur. Ein Byte, das beides ueberlebt, waere eine zweite gueltige
// Kodierung derselben Aussage: zwei verschiedene Dateien, ein Beweis.
//
// Der Lauf hat gearbeitet. Anfangs ueberlebten 653 von 2516 Bytes. 610 davon
// lagen in einer ZWEITEN, ungenutzten Kopie des Zertifikats, die OpenSSLs
// `certs`-Einstellung beilegt — ein Messartefakt, das die Vorlage jetzt nicht
// mehr erzeugt. Die restlichen 43 waren echt: die SignedData- und
// SignerInfo-Versionen, die Parameter der Algorithmuskennungen, die
// digestAlgorithms-Menge und sogar deren SET-Kennzeichen wurden vom Parser
// nicht gelesen und waren damit frei waehlbar. Alle vier sind seither
// geprueft; die Zahl unten ist deshalb 0 und darf es bleiben.
func TestGekippteBytesFallenAuf(t *testing.T) {
	der := laden(t, "openssl_token.der")
	pool := zertPool(t, "openssl_tsa.crt")
	ueberlebt := []int{}
	for i := 0; i < len(der); i++ {
		kaputt := append([]byte{}, der...)
		kaputt[i] ^= 0xff
		tok, err := Parse(kaputt)
		if err != nil {
			continue
		}
		if err := tok.Verify(pool, nil); err == nil {
			ueberlebt = append(ueberlebt, i)
		}
	}
	t.Logf("%d Bytes gekippt, %d unentdeckt / %d bytes flipped, %d undetected",
		len(der), len(ueberlebt), len(der), len(ueberlebt))
	if len(ueberlebt) != 0 {
		t.Fatalf("%d Bytes ueberleben Parsen UND Signaturpruefung: %v", len(ueberlebt), ueberlebt)
	}
}

func TestAngehaengteBytesAbgelehnt(t *testing.T) {
	der := append(laden(t, "openssl_token.der"), 0x00)
	if _, err := Parse(der); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("token with an appended byte accepted: %v", err)
	}
}

func TestLeerUndZuGross(t *testing.T) {
	if _, err := Parse(nil); err == nil {
		t.Error("empty token accepted")
	}
	if _, err := Parse(make([]byte, MaxTokenBytes+1)); err == nil {
		t.Error("oversized token accepted")
	}
}

// SHA-1 wird abgelehnt, und zwar am Abdruck. Eine Kollision dort hiesse, dass
// EIN Token zwei verschiedene Checkpoints bezeugt.
func TestSHA1Abgelehnt(t *testing.T) {
	sha1OID := asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	if _, err := imprintAlgName(sha1OID); err == nil {
		t.Fatal("sha1 accepted as an imprint algorithm")
	}
	for _, ok := range []asn1.ObjectIdentifier{oidSHA256, oidSHA384, oidSHA512} {
		if _, err := imprintAlgName(ok); err != nil {
			t.Errorf("%v rejected: %v", ok, err)
		}
	}
}

// RFC 3161 Abschnitt 2.3: genau eine erweiterte Schluesselverwendung, und
// kritisch. OpenSSL stellt solche Zertifikate gar nicht erst aus (`ts -reply`
// bricht ab) — ein Faelscher benutzt OpenSSL aber nicht, also werden die
// Faelle hier direkt gebaut.
func TestEKURegel(t *testing.T) {
	bau := func(t *testing.T, eku []x509.ExtKeyUsage, kritisch bool) *x509.Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		v := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Probe"},
			NotBefore:    time.Unix(0, 0),
			NotAfter:     time.Unix(1<<31, 0),
		}
		if kritisch {
			var oids []asn1.ObjectIdentifier
			for _, u := range eku {
				switch u {
				case x509.ExtKeyUsageTimeStamping:
					oids = append(oids, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8})
				case x509.ExtKeyUsageServerAuth:
					oids = append(oids, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1})
				}
			}
			val, err := asn1.Marshal(oids)
			if err != nil {
				t.Fatal(err)
			}
			v.ExtraExtensions = []pkix.Extension{{Id: oidExtKeyUsage, Critical: true, Value: val}}
		} else {
			v.ExtKeyUsage = eku
		}
		der, err := x509.CreateCertificate(rand.Reader, v, v, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	if err := checkTimeStampingEKU(bau(t, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}, true)); err != nil {
		t.Errorf("conformant certificate rejected: %v", err)
	}
	if err := checkTimeStampingEKU(bau(t, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageServerAuth}, true)); err == nil {
		t.Error("certificate with two extended key usages accepted")
	}
	if err := checkTimeStampingEKU(bau(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, true)); err == nil {
		t.Error("certificate without timeStamping accepted")
	}
	if err := checkTimeStampingEKU(bau(t, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}, false)); err == nil {
		t.Error("certificate with a non-critical extended key usage accepted")
	}
}
