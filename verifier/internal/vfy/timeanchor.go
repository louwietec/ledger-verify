package vfy

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash"
	"sort"
	"strings"

	"github.com/louwietec/ledger-verify/verifier/internal/tsa"
)

// maxTokenDER is the ceiling of spec 4.22 on the decoded token. It is checked
// before parsing: a package from untrusted hands must not be able to steer how
// much work the verifier does.
const maxTokenDER = 16384

// checkTimeAnchors verifies the external time witnesses of spec 7.3.
//
// The two findings it can produce are deliberately NOT one class:
//
//	TIME_ANCHOR_INVALID (exit 2)     the chain claims something the token
//	                                 contradicts, or the token does not carry
//	                                 its own signature — evidence of forgery
//	TIME_ANCHOR_UNVERIFIED (exit 1)  the token is intact and binds the
//	                                 checkpoint, but nothing INDEPENDENT of
//	                                 the package vouches for the authority
//
// Collapsing them would cost one of the two directions: either an auditor
// without a trust store would see honest chains reported as manipulated, or a
// forged token would pass as "merely unverified". The second case is the one
// that matters — it is the whole attack this anchor exists to stop.
func (r *run) checkTimeAnchors() {
	bySeq := map[int64]*entry{}
	for _, e := range r.entries {
		bySeq[e.seq] = e
	}

	var pkgPool *x509.CertPool // certificates the PACKAGE brought along
	pkgLoaded := false

	for _, e := range r.entries {
		if e.eventType != "TIME_ANCHOR" {
			continue
		}
		r.timeAnchors++

		// 1) The anchor must point at a checkpoint it agrees with.
		cp := bySeq[e.pInt("checkpoint_seq")]
		if cp == nil || cp.eventType != "CHECKPOINT" {
			r.add(ClsTimeAnchorInvalid, e.seq,
				fmt.Sprintf("checkpoint_seq %d does not reference a CHECKPOINT entry", e.pInt("checkpoint_seq")))
			continue
		}
		if cp.pInt("tree_size") != e.pInt("tree_size") || cp.pStr("merkle_root") != e.pStr("merkle_root") {
			r.add(ClsTimeAnchorInvalid, e.seq,
				"time anchor tree_size/merkle_root do not match the referenced checkpoint")
			continue
		}

		// 2) Decode and parse the token.
		der, err := base64.StdEncoding.DecodeString(e.pStr("token_base64"))
		if err != nil {
			r.add(ClsTimeAnchorInvalid, e.seq, "token_base64 is not valid base64")
			continue
		}
		if len(der) > maxTokenDER {
			r.add(ClsTimeAnchorInvalid, e.seq,
				fmt.Sprintf("token is %d bytes, above the %d byte ceiling of spec 4.22", len(der), maxTokenDER))
			continue
		}
		tok, err := tsa.Parse(der)
		if err != nil {
			r.add(ClsTimeAnchorInvalid, e.seq, "token does not parse as an RFC 3161 TimeStampToken: "+err.Error())
			continue
		}

		// 3) The readings in the payload must not contradict the token. They
		//    exist so the chain can be read without an ASN.1 parser; a reading
		//    that says something else than the token is the chain lying about
		//    its own evidence, however harmlessly.
		if got, want := e.pStr("tsa_policy"), tok.Policy; got != want {
			r.add(ClsTimeAnchorInvalid, e.seq, fmt.Sprintf("tsa_policy %q contradicts the token (%q)", got, want))
			continue
		}
		if got, want := e.pStr("tsa_serial"), tok.Serial; got != want {
			r.add(ClsTimeAnchorInvalid, e.seq, fmt.Sprintf("tsa_serial %q contradicts the token (%q)", got, want))
			continue
		}
		if got, want := e.pStr("tsa_ts"), tok.GenTime.Format("2006-01-02T15:04:05.000Z"); got != want {
			r.add(ClsTimeAnchorInvalid, e.seq, fmt.Sprintf("tsa_ts %q contradicts the token genTime (%q)", got, want))
			continue
		}

		// 4) The load-bearing binding: the imprint is the hash of exactly the
		//    bytes the checkpoint's own device signature covers.
		subject, err := checkpointSubject(cp)
		if err != nil {
			r.add(ClsTimeAnchorInvalid, e.seq, "checkpoint signed subject not canonicalizable: "+err.Error())
			continue
		}
		h, ok := imprintHash(tok.HashAlgorithm)
		if !ok {
			r.add(ClsTimeAnchorInvalid, e.seq, "token imprint algorithm "+tok.HashAlgorithm+" is not accepted (spec 7.3)")
			continue
		}
		h.Write(subject)
		if want := h.Sum(nil); string(want) != string(tok.Imprint) {
			r.add(ClsTimeAnchorInvalid, e.seq,
				fmt.Sprintf("token attests a different subject: imprint %x, checkpoint %d subject hashes to %x",
					tok.Imprint, cp.seq, want))
			continue
		}

		// Steps 1 to 4 have held: this token really does bind THIS checkpoint.
		// That makes an external anchor present, whatever step 6 decides
		// about the authority (spec 7.3).
		r.anchorsPresent++

		// 5) The token must carry its own signature.
		if err := tok.CheckSignatureOnly(); err != nil {
			r.add(ClsTimeAnchorInvalid, e.seq, "token signature is broken: "+err.Error())
			continue
		}

		// 6) And the authority must be vouched for by someone other than the
		//    package. Independent anchors first; only if none of them accepts
		//    the token do the package's own certificates get a turn, and then
		//    the result is a finding, not a pass.
		indep, indepNote := r.independentTSARoots()
		if err := tok.Verify(indep, nil); err == nil {
			r.timeAnchorsVerified++
			continue
		} else {
			if !pkgLoaded {
				pkgPool = r.packageTSARoots()
				pkgLoaded = true
			}
			note := fmt.Sprintf("time witness %q, genTime %s, serial %s: ",
				tok.SignerName(), tok.GenTime.Format("2006-01-02T15:04:05Z"), tok.Serial)
			if pkgPool != nil && tok.Verify(pkgPool, nil) == nil {
				r.add(ClsTimeAnchorUnverif, e.seq, note+
					"chains only to a certificate the package itself brought along (keys/tsa/) — "+
					"look the authority up outside the package (spec 7.3). "+indepNote)
			} else {
				r.add(ClsTimeAnchorUnverif, e.seq, note+err.Error()+". "+indepNote)
			}
		}
	}
}

// independentTSARoots is the trust set that does NOT come from the package:
// roots the auditor passed on the command line, plus the system root store
// where there is one. The note explains what was available, because "not
// verified" without that context reads like a statement about the chain when
// it is a statement about the machine the check ran on.
func (r *run) independentTSARoots() (*x509.CertPool, string) {
	if r.tsaIndepDone {
		return r.tsaIndep, r.tsaIndepNote
	}
	r.tsaIndepDone = true

	var notes []string
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		// js/wasm has no system store at all — the browser verifier lands here
		// every time, and saying so is the honest half of the finding.
		pool = x509.NewCertPool()
		notes = append(notes, "no system root store available in this build")
	} else {
		notes = append(notes, "system root store consulted")
	}
	n := 0
	for _, der := range r.opt.TSARoots {
		if c, err := x509.ParseCertificate(der); err == nil {
			pool.AddCert(c)
			n++
		}
	}
	if n > 0 {
		notes = append(notes, fmt.Sprintf("%d root(s) supplied by the auditor", n))
	} else {
		notes = append(notes, "no root supplied by the auditor")
	}
	r.tsaIndep, r.tsaIndepNote = pool, "Independent anchors: "+strings.Join(notes, ", ")+"."
	return r.tsaIndep, r.tsaIndepNote
}

// packageTSARoots reads keys/tsa/*.pem out of the package. These certificates
// are NOT evidence (spec 7.3, 10.1) — they only let the report name the
// authority instead of printing an opaque chain error.
func (r *run) packageTSARoots() *x509.CertPool {
	// List haengt den Schraegstrich selbst an — mit "keys/tsa/" suchte die
	// Abfrage nach "keys/tsa//" und fand nie etwas. Der Befund war trotzdem
	// TIME_ANCHOR_UNVERIFIED, nur mit der falschen Begruendung: statt "kettet
	// nur ins Paket" stand da ein nackter Kettenfehler.
	names := r.fs.List("keys/tsa")
	sort.Strings(names)
	pool := x509.NewCertPool()
	any := false
	for _, n := range names {
		b, err := r.fs.ReadFile(n)
		if err != nil {
			continue
		}
		for rest := b; len(rest) > 0; {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				break
			}
			if blk.Type != "CERTIFICATE" {
				continue
			}
			if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
				pool.AddCert(c)
				any = true
			}
		}
	}
	if !any {
		return nil
	}
	return pool
}

func imprintHash(name string) (hash.Hash, bool) {
	switch name {
	case "sha256":
		return sha256.New(), true
	case "sha384":
		return sha512.New384(), true
	case "sha512":
		return sha512.New(), true
	}
	return nil, false
}
