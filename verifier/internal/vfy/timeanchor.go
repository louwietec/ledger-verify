package vfy

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"sort"
	"strings"
	"time"

	"louwietec.com/ledger-verify/verifier/internal/tsa"
)

// TSARoot is one entry of the table of roots for time stamps (format spec
// 10.8): a certificate the auditor passed, with its purposes. Byte-equal
// certificates from several inputs are one entry with the union of their
// purposes; the period for the purpose qualified comes only from the file
// ledger-tsa-qualifiziert/1. The system root store adds nothing, and no
// verifier carries a built-in root of a time-stamping authority (7.5.7).
type TSARoot struct {
	Cert       *tsa.Certificate
	CertSHA256 string // SHA-256 of the DER, the fingerprint of the report
	SPKISHA256 string
	Chain      bool // --tsa-root, or listed in --tsa-qualified-roots
	Log        bool // --vendor-log-tsa-root
	// Qualified is the entry of the file of qualified roots, nil when the
	// certificate is not listed there.
	Qualified *QualifiedRoot
}

// QualifiedAt reports whether the root counts for the purpose qualified for
// a token with genTime t: qualifiziert_ab <= t < qualifiziert_bis (the upper
// bound only if present), compared as instants on nanoseconds (10.8).
func (x *TSARoot) QualifiedAt(t time.Time) bool {
	q := x.Qualified
	return q != nil && !t.Before(q.From) && (q.Until.IsZero() || t.Before(q.Until))
}

// BuildTSARootTable builds the table of roots for time stamps from the
// auditor's inputs, ordered by the fingerprint of the certificate.
func BuildTSARootTable(opt Options) []*TSARoot {
	byDER := map[string]*TSARoot{}
	add := func(der []byte) *TSARoot {
		if x, ok := byDER[string(der)]; ok {
			return x
		}
		c, err := tsa.ParseCertificate(der)
		if err != nil {
			return nil // the command line and the browser refuse these (10.8); a library caller may not
		}
		h, s := sha256.Sum256(der), c.SPKISHA256()
		x := &TSARoot{Cert: c, CertSHA256: hex.EncodeToString(h[:]), SPKISHA256: hex.EncodeToString(s[:])}
		byDER[string(der)] = x
		return x
	}
	for _, d := range opt.TSARoots {
		if x := add(d); x != nil {
			x.Chain = true
		}
	}
	if q := opt.TSAQualified; q != nil {
		for i := range q.Roots {
			if x := add(q.Roots[i].Cert.DER); x != nil {
				x.Chain, x.Qualified = true, &q.Roots[i]
			}
		}
	}
	for _, d := range opt.VendorLogTSARoots {
		if x := add(d); x != nil {
			x.Log = true
		}
	}
	var out []*TSARoot
	for _, x := range byDER {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CertSHA256 < out[j].CertSHA256 })
	return out
}

// TimeAnchorDetail is what the run established about one TIME_ANCHOR that
// binds its checkpoint (spec 7.3 steps 1 to 4), for the report and for the
// conditions of the evidence level that read it (spec 10.9). It is internal
// for now: the JSON output does not carry it (json:"-").
type TimeAnchorDetail struct {
	Seq           int64
	CheckpointSeq int64
	// TreeSize is the tree_size of the TIME_ANCHOR: a credited witness
	// evidences seq 1 to TreeSize (format spec 10.9.1, 10.9.4).
	TreeSize int64
	GenTime  time.Time
	// SignatureChecked: step 5a held, the CMS signature was checked under
	// the profile; SignatureValid: 5b held as well.
	SignatureChecked bool
	SignatureValid   bool
	// Verified: step 6 held, a path after Z.4 to a root of the purpose chain.
	Verified bool
	// PathRoots are the fingerprints (CertSHA256) of the roots of the table,
	// of any purpose, to which a path after Z.4 leads at genTime.
	PathRoots []string
	// SignerTestKey: the signer's key is in published_test_keys (7.5.7).
	SignerTestKey bool
	Z6            string // Z.6 (7.5.6); "" when step 5 did not hold
	QS            string // rule QS (7.5.6)
}

// tsaRootTable returns the table of roots for time stamps, built once.
func (r *run) tsaRootTable() []*TSARoot {
	if !r.tsaRootsDone {
		r.tsaRoots, r.tsaRootsDone = BuildTSARootTable(r.opt), true
	}
	return r.tsaRoots
}

// checkTimeAnchors checks the time witnesses of spec 7.3 after the profile
// of 7.5 (from edition 1.10), step by step:
//
//  1. checkpoint_seq names a CHECKPOINT with the entry's tree_size and
//     merkle_root, else TIME_ANCHOR_INVALID;
//  2. token_base64 follows B64, the DER has at most 16 384 bytes and follows
//     grammar T, else TIME_ANCHOR_INVALID;
//  3. tsa_policy, tsa_serial and tsa_ts equal the token, tsa_ts as genTime
//     truncated to milliseconds, else TIME_ANCHOR_INVALID;
//  4. the imprint is the hash of the checkpoint's signed subject, else
//     TIME_ANCHOR_INVALID; after step 4 the witness counts as an anchor;
//  5. 5a not performable: TIME_ANCHOR_UNVERIFIED with the reason, never
//     exit 2; 5b failed: TIME_ANCHOR_INVALID;
//  6. no path after Z.3 and Z.4 at genTime to a root of the purpose chain:
//     TIME_ANCHOR_UNVERIFIED, naming the authority when a path leads to a
//     certificate of keys/tsa/ of the package.
//
// Z.6, rule QS and published test keys never change the finding of a
// TIME_ANCHOR (7.5.7); the detail keeps them for the evidence level.
//
// The two findings are deliberately NOT one class: TIME_ANCHOR_INVALID
// (exit 2) is a token that contradicts the chain or does not carry its own
// signature, TIME_ANCHOR_UNVERIFIED (exit 1) an intact token that nothing
// independent of the package vouches for, or whose signature the profile
// cannot check. Collapsing them would cost one of the two directions.
func (r *run) checkTimeAnchors() {
	bySeq := map[int64]*entry{}
	for _, e := range r.entries {
		bySeq[e.seq] = e
	}
	var pkgCerts []*tsa.Certificate
	pkgLoaded := false
	table := r.tsaRootTable()
	// Format spec 10.9.3: the SPKI SHA-256 values of the certificates of
	// keys/tsa/*.pem, recorded during the check, for the step after the
	// exit code reads no file (10.9).
	r.pkgTSASPKI = r.packageTSASPKIs()

	for _, e := range r.entries {
		if e.eventType != "TIME_ANCHOR" {
			continue
		}
		r.timeAnchors++

		// 1) The anchor must point at a checkpoint it agrees with.
		cp := bySeq[e.pInt("checkpoint_seq")]
		if cp == nil || cp.eventType != "CHECKPOINT" {
			r.add(ClsTimeAnchorInvalid, e.seq,
				fmt.Sprintf("checkpoint_seq %d does not reference a CHECKPOINT entry (spec 7.3 step 1)", e.pInt("checkpoint_seq")))
			continue
		}
		if cp.pInt("tree_size") != e.pInt("tree_size") || cp.pStr("merkle_root") != e.pStr("merkle_root") {
			r.add(ClsTimeAnchorInvalid, e.seq,
				"time anchor tree_size/merkle_root do not match the referenced checkpoint (spec 7.3 step 1)")
			continue
		}

		// 2) B64, size and grammar T.
		der, err := tsa.DecodeB64(e.pStr("token_base64"))
		if err != nil {
			r.add(ClsTimeAnchorInvalid, e.seq, "token_base64 violates grammar B64: "+err.Error()+" (spec 2, 7.3 step 2)")
			continue
		}
		tok, err := tsa.ParseToken(der)
		if err != nil {
			r.add(ClsTimeAnchorInvalid, e.seq, "the token: "+err.Error()+" (spec 7.3 step 2, 7.5.2)")
			continue
		}

		// 3) The readings must not contradict the token.
		// Step 3 of format spec 7.3 compares the three readings tsa_policy,
		// tsa_serial and tsa_ts; the imprint algorithm has no member in the
		// entry and is used in step 4.
		if got, want := e.pStr("tsa_policy"), tok.Policy; got != want {
			r.add(ClsTimeAnchorInvalid, e.seq, fmt.Sprintf("tsa_policy %q contradicts the token (%q) (spec 7.3 step 3)", got, want))
			continue
		}
		if got, want := e.pStr("tsa_serial"), tok.SerialHex(); got != want {
			r.add(ClsTimeAnchorInvalid, e.seq, fmt.Sprintf("tsa_serial %q contradicts the token (%q) (spec 7.3 step 3)", got, want))
			continue
		}
		if got, want := e.pStr("tsa_ts"), tok.GenTimeMillis(); got != want {
			r.add(ClsTimeAnchorInvalid, e.seq, fmt.Sprintf("tsa_ts %q is not the token's genTime %s truncated to milliseconds (%q) (spec 7.3 step 3)", got, tok.GenTimeRaw, want))
			continue
		}

		// 4) The load-bearing binding: the imprint is the hash of exactly
		//    the bytes the checkpoint's own device signature covers.
		subject, err := checkpointSubject(cp)
		if err != nil {
			r.add(ClsTimeAnchorInvalid, e.seq, "checkpoint signed subject not canonicalizable: "+err.Error())
			continue
		}
		h := imprintHash(tok.HashAlgorithm)
		h.Write(subject)
		if want := h.Sum(nil); !bytes.Equal(want, tok.HashedMessage) {
			r.add(ClsTimeAnchorInvalid, e.seq,
				fmt.Sprintf("token attests a different subject: imprint %x, checkpoint %d subject hashes to %x (spec 7.3 step 4)",
					tok.HashedMessage, cp.seq, want))
			continue
		}

		// Steps 1 to 4 have held: the token binds THIS checkpoint, an
		// external anchor is present, whatever steps 5 and 6 decide.
		r.anchorsPresent++
		detail := TimeAnchorDetail{Seq: e.seq, CheckpointSeq: cp.seq, TreeSize: e.pInt("tree_size"), GenTime: tok.GenTime, QS: tok.QualifiedStatement()}
		note := fmt.Sprintf("time witness genTime %s, serial %s", tok.GenTimeRaw, tok.SerialHex())

		// 5) The CMS signature after the profile.
		sig := tok.CheckSignature()
		if sig.Signer != nil {
			note = fmt.Sprintf("time witness %q, genTime %s, serial %s", signerName(sig.Signer), tok.GenTimeRaw, tok.SerialHex())
			detail.SignerTestKey = tsa.IsPublishedTestKey(sig.Signer)
		}
		if !sig.Performable {
			r.timeAnchorDetails = append(r.timeAnchorDetails, detail)
			r.add(ClsTimeAnchorUnverif, e.seq, note+": the signature cannot be checked under the time-stamp profile, "+sig.Reason+
				" (spec 7.3 step 5a); this verifier did not check the signature, which is no statement that the token is forged")
			continue
		}
		detail.SignatureChecked = true
		if !sig.Valid {
			r.timeAnchorDetails = append(r.timeAnchorDetails, detail)
			r.add(ClsTimeAnchorInvalid, e.seq, note+": "+sig.Reason+" (spec 7.3 step 5b)")
			continue
		}
		detail.SignatureValid = true
		detail.Z6, _ = tok.Z6(sig.Signer)

		// 6) A path to a root of the purpose chain, at genTime.
		for _, x := range table {
			if tok.PathExists(sig, x.Cert) {
				detail.PathRoots = append(detail.PathRoots, x.CertSHA256)
				if x.Chain {
					detail.Verified = true
				}
			}
		}
		r.timeAnchorDetails = append(r.timeAnchorDetails, detail)
		if detail.Verified {
			r.timeAnchorsVerified++
			continue
		}
		if !pkgLoaded {
			pkgCerts, pkgLoaded = r.packageTSACerts(), true
		}
		why := chainRootsNote(table)
		named := false
		for _, c := range pkgCerts {
			if tok.PathExists(sig, c) {
				r.add(ClsTimeAnchorUnverif, e.seq, note+": chains only to a certificate the package itself brought along (keys/tsa/: "+
					signerName(c)+", serial "+c.Serial.Text(16)+"); look the authority up outside the package (spec 7.3). "+why)
				named = true
				break
			}
		}
		if !named {
			r.add(ClsTimeAnchorUnverif, e.seq, note+": no path after Z.4 at genTime to a root the auditor supplied for time witnesses (spec 7.3 step 6). "+why)
		}
	}
}

// chainRootsNote says which roots were available for the purpose chain: "not
// verified" without that context reads like a statement about the chain when
// it is a statement about the audit environment.
func chainRootsNote(table []*TSARoot) string {
	n := 0
	for _, x := range table {
		if x.Chain {
			n++
		}
	}
	if n == 0 {
		return "No root for time witnesses was supplied (--tsa-root, --tsa-qualified-roots); the system root store counts for no purpose (spec 7.5.7)."
	}
	return fmt.Sprintf("%d root(s) for time witnesses supplied by the auditor; the system root store counts for no purpose (spec 7.5.7).", n)
}

// signerName names a certificate for the report: its commonName, else the
// fingerprint of its SPKI.
func signerName(c *tsa.Certificate) string {
	if n := c.SubjectCommonName(); n != "" {
		return n
	}
	h := c.SPKISHA256()
	return "SPKI " + hex.EncodeToString(h[:])
}

// packageTSACerts reads the certificates of keys/tsa/*.pem in the package.
// They are NOT evidence (spec 7.3, 10.1): they only let the report name the
// authority. A block that is no certificate after Z.1 is passed over here;
// these files are no input of the auditor.
func (r *run) packageTSACerts() []*tsa.Certificate {
	names := r.fs.List("keys/tsa")
	sort.Strings(names)
	var out []*tsa.Certificate
	for _, n := range names {
		b, err := r.fs.ReadFile(n)
		if err != nil {
			continue
		}
		out = append(out, pemCertificates(b)...)
	}
	return out
}

// packageTSASPKIs records "Zertifikate des Pakets" of format spec 10.9.3:
// the SPKI SHA-256 value of every certificate in a block CERTIFICATE of a
// file keys/tsa/*.pem that reads under B64 and Z.1; other blocks and files
// are passed over without a finding. Only files directly in keys/tsa/ with
// the ending .pem count, as the pattern keys/tsa/*.pem names them.
func (r *run) packageTSASPKIs() map[string]bool {
	out := map[string]bool{}
	if r.fs == nil {
		return out
	}
	for _, n := range r.fs.List("keys/tsa") {
		rest := strings.TrimPrefix(n, "keys/tsa/")
		if strings.Contains(rest, "/") || !strings.HasSuffix(rest, ".pem") {
			continue
		}
		b, err := r.fs.ReadFile(n)
		if err != nil {
			continue
		}
		for _, c := range pemCertificates(b) {
			h := c.SPKISHA256()
			out[hex.EncodeToString(h[:])] = true
		}
	}
	return out
}

// pemCertificates reads the blocks CERTIFICATE of a file of the package
// (not an input of the auditor, so not the strict PEM of 10.8): a block
// whose content does not read under B64 and Z.1 is passed over.
func pemCertificates(b []byte) []*tsa.Certificate {
	var out []*tsa.Certificate
	var body []string
	open := false
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimRight(l, " \t\r")
		switch {
		case l == "-----BEGIN CERTIFICATE-----":
			open, body = true, nil
		case l == "-----END CERTIFICATE-----" && open:
			open = false
			if der, err := tsa.DecodeB64(strings.Join(body, "")); err == nil {
				if c, err := tsa.ParseCertificate(der); err == nil {
					out = append(out, c)
				}
			}
		case open:
			body = append(body, l)
		}
	}
	return out
}

// ParseTSARoots reads roots for time stamps that the AUDITOR supplies in the
// strict PEM of format spec 10.8 and returns the DER of every certificate.
// An error is an unusable invocation (exit 3) for the command line and the
// browser page, never an anchor silently dropped.
func ParseTSARoots(text []byte) ([][]byte, error) {
	certs, err := tsa.ParsePEMRoots(text)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for _, c := range certs {
		out = append(out, c.DER)
	}
	return out, nil
}

func imprintHash(name string) hash.Hash {
	switch name {
	case "sha384":
		return sha512.New384()
	case "sha512":
		return sha512.New()
	}
	return sha256.New()
}
