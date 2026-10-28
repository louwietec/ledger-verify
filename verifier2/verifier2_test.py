#!/usr/bin/env python3
"""Vorwaertskompatibilitaet (format.de.md 10.6) in verifier2 / forward compatibility in verifier2.

DE: Deckt die fuenf Faelle des Vertrags S1a Teil D fuer den Python-Zweitverifier ab:
  (1) unbekannter event_type -> UNKNOWN_ENTRY_TYPE, kein FORMAT_ERROR, Kette weiter
      geprueft (ein Hash-Fehler in einem SPAETEREN Eintrag wird trotzdem gefunden)
  (2) spec_version 1.1 ueberall -> SPEC_NEWER genau einmal je Paket
  (3) spec_version 2.0 -> FORMAT_ERROR (Exit 3)
  (4) unbekanntes Envelope-Feld -> weiterhin FORMAT_ERROR (auch bei 1.1)
  (5) unbekannter Typ ohne Checkpoint danach -> KEIN MISSING_CHECKPOINT
  dazu: payload eines unbekannten Typs muss ein Objekt sein; UNKNOWN_ENTRY_TYPE
  einmal je Typname mit der seq des ersten Vorkommens; Registry-Vertrag B.
EN: Covers the five cases of contract S1a part D for the Python second verifier
  (see above), plus: payload of an unknown type must be an object; one
  UNKNOWN_ENTRY_TYPE per type name with the seq of its first occurrence; registry
  contract B.
Seit Spezifikation 1.6 dazu die Klasse ChainEnd (Abschnitt 8.6): versiegelt oder
unvollstaendig (UNSEALED_END, Exit 4), Rangfolge 3 > 2 > 4 > 1 > 0 aus der Registry,
Kettenende in Text (DE/EN) und JSON. Die uebrigen Klassen bauen ihre Ketten mit
Siegel (Chain.close), damit ihre Grundlinie weiter ohne Befund ist.
Since spec 1.6 also class ChainEnd (8.6): sealed or incomplete, the registry's exit
precedence, the chain end in text and JSON output.
Seit Spezifikation 1.7 dazu die Klasse LegalHold (Abschnitte 4.24, 9.3): Loeschsperren,
Befund HOLD_VIOLATION (Exit 1), aktive Sperren am Kettenende im JSON (legal_holds).
Since spec 1.7 also class LegalHold (4.24, 9.3): deletion holds, the finding
HOLD_VIOLATION (exit 1), the holds active at the chain end in the JSON output.
Seit Spezifikation 1.9 dazu die Klassen Spec19*: vorgelegte Klartexte (10.1), Zahlenprofil (2),
Angaben des Pruefers und verify_args.json (10.8), Verarbeitungsstufen und Segmenttabelle (10.5,
10.1), Zeitrechnung in ganzen Millisekunden (2), nachgeholter Sofort-Checkpoint (8.2 Bedingungen
3 und 4), Export-Siegel (4.10, 8.4, 8.6), Aussage zur Vollstaendigkeit (8.6) und gemessenes
Restfenster (11.2). verify() nimmt den Pruefzeitpunkt seitdem in ganzen Millisekunden (at_ms).
Since spec 1.9 also the classes Spec19*: presented plaintexts, integer profile, auditor inputs,
processing stages, millisecond arithmetic, the late immediate checkpoint, the export seal, the
completeness statement and the measured residual window; verify() takes the check time in ms.
Seit Spezifikation 1.10 (Grundlagen) dazu die Klassen TimeStampProfile (7.5: B64, Grammatik T, Z.1 bis Z.6, Regel QS,
Zuordnung 7.5.7), TimeWitness110 (7.3 Schritte 1 bis 6, Zwecke der Wurzeln), KeyRoles110 (10.7.2 bis 10.7.5, R1 bis
R4, key_roles), AuditorInputs110 (10.8: Schalter, Grammatiken, Grenzen, Exit 3, Anforderungszeitpunkt,
ledger-pruefumgebung/1), Zeitstempel110 (Einzelpruefung eines Zeitstempels) und Vectors110 (die Vektoren der
Grundlagen mit beiden Pruefumgebungen, ihre Zahl aus Registry und Korpus); die Test-Token entstehen hier aus Schluesseln, die der Code aus Bezeichnern ableitet.
Since spec 1.10 (foundations) also the classes TimeStampProfile (7.5), TimeWitness110 (7.3 steps 1 to 6, purposes of
roots), KeyRoles110 (10.7.2 to 10.7.5, R1 to R4, key_roles), AuditorInputs110 (10.8), Zeitstempel110 (the single check
of a time stamp) and Vectors110 (the vectors of the foundations with both audit environments, their number from the
registry and the corpus); the test tokens are
made here, from keys the code derives from labels.
Dazu die Klasse RFC9162Proofs: Inklusions- und Konsistenzbeweise (RFC 9162 2.1.3.2, 2.1.4.2) gegen einen eigenen
Beweisgenerator, Baumgroessen 1 bis 64.
Seit Spezifikation 1.10 (Herstellerprotokoll) dazu die Klassen VendorLog110 (7.4: Blaetter, Kettentag, Tagesbaum und Fueller
mit den Referenzwerten, Referenzfall spec/testvectors/protokoll/, Abwesenheitsbeweis aus Abschnitt 5, Schritte L1 bis L10,
Befunde 7.4.11, Berichtsobjekt vendor_log und Textblock) mit einer eigenen Zeitstempelstelle ausserhalb von
published_test_keys, und VectorsLog110 (die Vektoren der Gruppe log mit beiden Pruefumgebungen, auch die bezeugten Tage
der Zeitstempelstelle E1 des Korpus).
Also class RFC9162Proofs: inclusion and consistency proofs (RFC 9162 2.1.3.2, 2.1.4.2) against a generator of its own,
tree sizes 1 to 64.
Since spec 1.10 (vendor log) also the classes VendorLog110 (7.4 rule by rule, steps L1 to L10, the report object vendor_log)
with a test authority outside published_test_keys, and VectorsLog110 (the vectors of group log, both environments, also
the witnessed days of the corpus authority E1).
Seit Spezifikation 1.10 (Anker-Historie) dazu die Klassen AnchorHistory110 (8.8 Regel fuer Regel: Referenzseite 8.8.2,
Schluessel 8.8.3, Schritte H1 bis H13, Einordnung 8.8.5 mit der Regel, dass eine nur gemeldete Wurzel nie Exit 2 ergibt,
Verbundenheit 8.8.6, Berichtsobjekte gegen ihre Schemata, Textblock 10.10.3), AnchorHistoryLog110 (Schritt H7 gegen ein
Herstellerprotokoll mit bezeugtem Tag) und VectorsHistory110 (die Vektoren der Gruppe history mit beiden Pruefumgebungen).
Since spec 1.10 (anchor history) also the classes AnchorHistory110 (8.8 rule by rule, the pages built here from heartbeat
spec 9.7 and signed with the test statements keys), AnchorHistoryLog110 (step H7 against a vendor log with a witnessed day)
and VectorsHistory110 (the vectors of group history, both environments, with the explicit check that a root that is only
reported never gives exit 2).

Die Ketten werden synthetisch gebaut (Ed25519-Signierung nur hier); die Registry wird geladen und im Speicher auf
den Vertrag B gebracht (idempotent), die echte Datei bleibt unberuehrt.
The chains are built synthetically; the registry is loaded and brought to
contract B in memory (idempotent) - the real file is never touched.

Umgebung / environment:
  VERIFIER2_PY  Pfad zur zu pruefenden verifier2.py (Rot-Beweis gegen den alten Stand)
  REGISTRY      Pfad zur Registry (Standard: ../spec/registry.json)
"""

import base64, contextlib, datetime, hashlib, hmac, importlib.util, io, itertools, json, os, shutil, sys, tempfile, types, unittest, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
V2_PATH = os.environ.get("VERIFIER2_PY", os.path.join(HERE, "verifier2.py"))
REG_PATH = os.environ.get("REGISTRY", os.path.join(HERE, "..", "spec", "registry.json"))
_spec = importlib.util.spec_from_file_location("verifier2_under_test", V2_PATH)
V = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(V)


def paket_zuletzt(argv):
    """The command line with the package last. From 1.1.0 verifier2, like ledger-verify, takes every switch before the
    package and refuses one after it (release/verifier/check_cli_gleich.py); the tests below name the package first, right after
    "verifier2", and this moves it behind the switches. The helper mode zeitstempel and a call that starts with a switch
    stay as they are."""
    argv = list(argv)
    if len(argv) > 1 and argv[1] != "zeitstempel" and not argv[1].startswith("-"):
        argv = [argv[0]] + argv[2:] + [argv[1]]
    return argv


def vmain(argv):
    """V.main over paket_zuletzt(argv)."""
    return V.main(paket_zuletzt(argv))

CHAIN = "3f1c9a02-1111-4222-8333-444455556666"
T0 = 1767225600          # 2026-01-01T00:00:00Z
DEV_SEED = bytes(range(32))
VENDOR_SEED = bytes(range(32, 64))
def _naechste_minor(v):
    """MAJOR.MINOR -> MAJOR.(MINOR+1)."""
    major, _, minor = v.partition(".")
    return "%s.%d" % (major, int(minor) + 1)


# NEW is the "newer minor" of this test: always one above the registry, never a
# literal. It was "1.2" by hand until the 1.2 release made that the CURRENT
# version: six forward-compatibility tests went red at once, because the
# constant they measure with had quietly become the thing being measured.
with open(REG_PATH, encoding="utf-8") as _fh: NEW = _naechste_minor(json.load(_fh)["spec_version"])


# ---------------------------------------------------------------- registry (contract B)

def contract_registry():
    """Load the registry and apply contract S1a part B in memory (a no-op once part B is in the file)."""
    with open(REG_PATH, encoding="utf-8") as fh: reg = json.load(fh)
    reg["envelope_fields"]["spec_version"] = {"type": "version"}
    reg["pruefpaket_manifest"]["fields"]["spec_version"] = {"type": "version"}
    reg["envelope_fields"]["event_type"] = {"type": "open_enum", "ref": "event_types", "unknown_finding": "UNKNOWN_ENTRY_TYPE"}
    fc = reg["verifier"]["finding_classes"]
    fc.setdefault("SPEC_NEWER", {"exit": 1, "de": "Paket nutzt eine neuere Minor-Version der Spezifikation als der Verifier",
                                 "en": "package uses a newer minor version of the specification than the verifier"})
    fc.setdefault("UNKNOWN_ENTRY_TYPE", {"exit": 1, "de": "Eintragstyp dieser Verifier-Version unbekannt; Eintrag geprueft, Nutzlast nicht",
                                         "en": "entry type unknown to this verifier version; entry checked, payload not"})
    return reg


def file_registry():
    """The registry exactly as it is on disk: no in-memory contract. The S1b tests run against THIS, so they
    are red when spec/registry.json lacks CONTENT_DISCLOSED (verifier2.py has no S1b code: it reads the registry)."""
    with open(REG_PATH, encoding="utf-8") as fh: return json.load(fh)


# contract S1b part D, used only to check the file (test_9): never injected into a registry copy
CONTENT_DISCLOSED_SPEC = {"critical_checkpoint": True, "payload": {
    "target_seq": {"type": "int", "min": 1}, "vault_ref": {"type": "string", "maxlen": 128},
    "actor": {"type": "string", "maxlen": 128}, "role": {"type": "string", "maxlen": 64},
    "reason": {"type": "enum", "values": ["audit", "dsgvo_request", "incident", "manual"]},
    "request_bytes": {"type": "int", "min": 0}, "response_bytes": {"type": "int", "min": 0}}}


REG = contract_registry()
OWN = REG["spec_version"]


# ---------------------------------------------------------------- Ed25519 signing (test only)

def _encode_point(p):
    x, y, z, _t = p
    zi = pow(z, V._Q - 2, V._Q)
    x, y = x * zi % V._Q, y * zi % V._Q
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _scalar(seed):
    h = hashlib.sha512(seed).digest()
    return (int.from_bytes(h[:32], "little") & ((1 << 254) - 8)) | (1 << 254), h[32:]


def pubkey(seed): return _encode_point(V._mul(V._B, _scalar(seed)[0]))


def sign(seed, msg):
    a, prefix = _scalar(seed)
    pub = _encode_point(V._mul(V._B, a))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % V._L
    R = _encode_point(V._mul(V._B, r))
    k = int.from_bytes(hashlib.sha512(R + pub + msg).digest(), "little") % V._L
    return R + ((r + k * a) % V._L).to_bytes(32, "little")


# ---------------------------------------------------------------- chain builder

def iso(t): return "%s.000Z" % __import__("datetime").datetime.utcfromtimestamp(t).strftime("%Y-%m-%dT%H:%M:%S")


def at_ms(t):
    """Seconds since 1970 (the chain builder's clock) -> the check time verify() takes: whole milliseconds (spec 2, 8.5)."""
    return round(t * 1000)


class Chain:
    """Builds a valid chain: GENESIS, CHECKPOINT, then whatever the test appends; close() seals it -
    SEAL, its immediate CHECKPOINT and the vendor CHECKPOINT_RECEIPT on that checkpoint - so the
    baseline has no finding at all. Since spec 1.6 (8.6) that needs the seal: a chain ending with
    anchor() alone (checkpoint + receipt, like an export from a running installation) is incomplete."""

    def __init__(self, version="1.0", extra_env=None, license=None):
        # license: GENESIS.license_id; None = the commitment of "LIC" - from spec 1.8 the only admissible form (4.1)
        self.version, self.extra_env, self.entries, self.prev_cp, self.t = version, extra_env or {}, [], V.ZERO, T0
        self.add("GENESIS", {"customer_id": "TEST", "appliance_id": "49eed9d6-4f02-4aa0-9392-12c117f761a1",
                             "device_pubkey": pubkey(DEV_SEED).hex(), "device_key_id": "dev-1",
                             "license_id": hashlib.sha256(b"LIC").hexdigest() if license is None else license,
                             "edition": "pro", "purpose_statement": "10.6 forward compatibility test.", "language": "de",
                             "timezone": "Europe/Berlin", "predecessor_chain": None}, mono=-1)
        self.checkpoint()

    def add(self, et, payload, origin="system", mono=60000, dt=None):
        """dt: seconds the chain's clock advances before this entry - by default mono_delta_ms, nothing for -1."""
        self.t += (0 if mono < 0 else mono / 1000.0) if dt is None else dt
        e = {"spec_version": self.version, "chain_id": CHAIN, "seq": len(self.entries) + 1, "ts_captured": iso(self.t),
             "ts_chained": iso(self.t), "mono_delta_ms": mono, "event_type": et, "origin": origin, "payload": payload,
             "prev_hash": self.entries[-1]["entry_hash"] if self.entries else V.ZERO, **self.extra_env}
        e["entry_hash"] = V.entry_hash(e)
        self.entries.append(e)
        return e

    def tick(self): return self.add("TICK", {"uptime_s": 1, "spool_backlog": 0, "disk_pct": 10})

    def checkpoint(self, mono=500, dt=0.5):
        """The CHECKPOINT over every entry so far, signed at its own time dt seconds on. mono=-1 with a long dt is
        the immediate checkpoint a restarted writer writes late (6.2; 8.2 conditions 3 and 4)."""
        n = len(self.entries)
        root = V.mth([bytes.fromhex(x["entry_hash"]) for x in self.entries]).hex()
        ts = iso(self.t + dt)
        obj = {"chain_id": CHAIN, "tree_size": n, "merkle_root": root, "prev_checkpoint_hash": self.prev_cp, "key_id": "dev-1", "ts": ts}
        e = self.add("CHECKPOINT", {"tree_size": n, "merkle_root": root, "prev_checkpoint_hash": self.prev_cp, "key_id": "dev-1",
                                    "signature": sign(DEV_SEED, V.jcsb(obj)).hex()}, mono=mono, dt=dt)
        self.prev_cp = e["entry_hash"]
        return e

    def receipt(self, cp):
        """The vendor's countersignature on checkpoint entry cp (7.1)."""
        p = cp["payload"]
        obj = {"chain_id": CHAIN, "tree_size": p["tree_size"], "merkle_root": p["merkle_root"], "server_ts": iso(self.t + 1)}
        return self.add("CHECKPOINT_RECEIPT", {"checkpoint_seq": cp["seq"], "tree_size": p["tree_size"], "merkle_root": p["merkle_root"],
                                               "server_ts": obj["server_ts"], "server_key_id": "vendor-1",
                                               "server_signature": sign(VENDOR_SEED, V.jcsb(obj)).hex()}, mono=1000)

    def anchor(self):
        """A CHECKPOINT and the receipt on it; returns the checkpoint entry."""
        cp = self.checkpoint()
        self.receipt(cp)
        return cp

    def seal(self, reason="shutdown"):
        """SEAL and its immediate CHECKPOINT (6.2, 8.4); returns the SEAL entry."""
        e = self.add("SEAL", {"version": "1.0.0", "reason": reason})
        self.checkpoint()
        return e

    def close(self, reason="shutdown"):
        self.seal(reason)
        self.receipt(self.entries[-1])                  # on exactly the SEAL's immediate checkpoint
        return self

    def write(self, dst, manifest_version=None, patch=None, man_extra=None, seg_extra=None, extra=None, split=()):
        """Write the package; patch(entries) may tamper with the finished entries (bytes as-is, nothing recomputed).
        extra: further files {path: bytes or str} - content/, verify_args.json, ...; split: the seq values after
        which a new segment file begins (chain-000001.jsonl, chain-000002.jsonl, ...; 10.1)."""
        entries = json.loads(json.dumps(self.entries))
        if patch: patch(entries)
        os.makedirs(os.path.join(dst, "segments"))
        segs, bounds = [], [0, *split, len(entries)]
        for k in range(len(bounds) - 1):
            blob = ("\n".join(V.jcs(e) for e in entries[bounds[k]:bounds[k + 1]]) + "\n").encode()
            name = "chain-%06d.jsonl" % (k + 1)
            with open(os.path.join(dst, "segments", name), "wb") as fh: fh.write(blob)
            segs.append({"file": name, "sha256": hashlib.sha256(blob).hexdigest(), "first_seq": bounds[k] + 1, "last_seq": bounds[k + 1]})
        man = {"spec_version": manifest_version or self.version, "chain_id": CHAIN, "created_ts": iso(self.t + 2), "tree_size": len(entries),
               "segments": segs,
               "device_pubkeys": [{"key_id": "dev-1", "pubkey": pubkey(DEV_SEED).hex()}],
               "vendor_pubkeys": [{"key_id": "vendor-1", "pubkey": pubkey(VENDOR_SEED).hex()}]}
        # 10.6 R5: Felder, die die Spezifikation nicht definiert.
        if man_extra: man.update(man_extra)
        if seg_extra:
            for seg in man["segments"]: seg.update(seg_extra)
        with open(os.path.join(dst, "manifest.json"), "w") as fh: json.dump(man, fh, indent=2, sort_keys=True)
        for name, data in (extra or {}).items():
            os.makedirs(os.path.dirname(os.path.join(dst, name)), exist_ok=True)
            with open(os.path.join(dst, name), "wb") as fh: fh.write(data if isinstance(data, bytes) else data.encode())
        return dst


def future_note(c): return c.add("FUTURE_NOTE", {"note": "reserved for spec 1.1"})


def ai_call(c):
    """One full-mode AI_CALL with vault_ref and commitments (the entry a disclosure points at)."""
    return c.add("AI_CALL", {"provider_class": "generic", "route": "default", "model": "m", "endpoint": "/v1/x",
                             "http_status": 200, "outcome": "ok", "duration_ms": 120, "request_bytes": 10, "response_bytes": 20,
                             "tokens_in": 3, "tokens_out": 4, "streamed": False, "confidence": "recorded", "source_id": None,
                             "source_ref": None, "mode": "full", "request_commitment": "a" * 64, "response_commitment": "b" * 64,
                             "vault_ref": "vault/1"}, origin="proxy")


def disclosed(c, target, mutate=None, checkpoint=True):
    """CONTENT_DISCLOSED for target (spec 4.18); mutate edits the payload before chaining."""
    p = {"target_seq": target["seq"], "vault_ref": "vault/1", "actor": "pruefer", "role": "aufsicht", "reason": "audit",
         "request_bytes": 10, "response_bytes": 20}
    if mutate: mutate(p)
    e = c.add("CONTENT_DISCLOSED", p, origin="portal")
    if checkpoint: c.checkpoint()
    return e


# PIN: the vendor key the test auditor knows to be genuine (format.de.md 7.1).
PIN = {"vendor-1": pubkey(VENDOR_SEED).hex()}

# ---------------------------------------------------------------- test cases

class V2Case(unittest.TestCase):
    """Shared harness. self.reg is the registry the verifier runs with: the in-memory contract copy for
    ForwardCompat (S1a), the file as-is for ContentDisclosed (S1b)."""
    reg = REG

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="v2-fwd-")
        self.n = 0

    def tearDown(self): shutil.rmtree(self.tmp, ignore_errors=True)

    def run_v2(self, chain, roots=None, keys=None, now=None, expect=(), **kw):
        """Return (exit_code, findings) of verifier2 over the written package, via verify() + exit_code().
        The test is the auditor (7.1): unless told otherwise it pins the test vendor key it knows.
        now: check time (default 3 s after the last entry); expect: paper anchors [(tree_size, root)] (7.2)."""
        self.n += 1
        pkg = chain.write(os.path.join(self.tmp, "pkg%d" % self.n), **kw)
        self.res = V.verify(pkg, self.reg, at_ms(chain.t + 3 if now is None else now), 24.0, list(expect),
                            vendor_roots=roots or {}, vendor_keys=PIN if keys is None else keys)
        return V.exit_code(self.res, self.reg["verifier"]["finding_classes"]), self.res.findings

    def run_cli(self, chain, args=(), json_out=True, **kw):
        """The command line end to end (exit code through main, own registry copy in the temp dir)."""
        self.n += 1
        pkg = chain.write(os.path.join(self.tmp, "pkg%d" % self.n), **kw)
        regp = os.path.join(self.tmp, "registry.json")
        with open(regp, "w") as fh: json.dump(self.reg, fh)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = vmain(["verifier2", pkg, "--now", iso(chain.t + 3), "--registry", regp,
                           "--vendor-key", "vendor-1=" + pubkey(VENDOR_SEED).hex()] + (["--json"] if json_out else []) + list(args))
        return code, json.loads(out.getvalue()) if json_out else out.getvalue()

    @staticmethod
    def classes(findings): return sorted({f["class"] for f in findings})


class ForwardCompat(V2Case):
    def test_0_signing_helper_matches_verifier(self):
        msg = b"self-check of the test-only signer"
        self.assertTrue(V.ed25519_verify(pubkey(DEV_SEED), sign(DEV_SEED, msg), msg))
        self.assertFalse(V.ed25519_verify(pubkey(DEV_SEED), sign(DEV_SEED, msg), msg + b"x"))

    def test_0_signature_r_in_canonical_encoding_only(self):
        """Format spec 2: the encoding of [S]B - [k]A equals R byte for byte. R = identity with S = k*a holds as
        points; encoded with the sign bit set (x = 0), it is no canonical encoding and never verifies, as in Go's
        crypto/ed25519. R with y >= p does not verify either."""
        msg = b"negative zero"
        a, _prefix = _scalar(DEV_SEED)
        pub = pubkey(DEV_SEED)
        for r_enc, ok in ((b"\x01" + b"\x00" * 31, True), (b"\x01" + b"\x00" * 30 + b"\x80", False)):
            k = int.from_bytes(hashlib.sha512(r_enc + pub + msg).digest(), "little") % V._L
            with self.subTest(r=r_enc.hex()):
                self.assertEqual(V.ed25519_verify(pub, r_enc + (k * a % V._L).to_bytes(32, "little"), msg), ok)
        q1 = (V._Q + 1).to_bytes(32, "little")         # y = p + 1 encodes the identity a second time, not canonically
        k = int.from_bytes(hashlib.sha512(q1 + pub + msg).digest(), "little") % V._L
        self.assertFalse(V.ed25519_verify(pub, q1 + (k * a % V._L).to_bytes(32, "little"), msg))
        sig = sign(DEV_SEED, msg)
        self.assertFalse(V.ed25519_verify(pub, sig[:32] + (int.from_bytes(sig[32:], "little") + V._L).to_bytes(32, "little"), msg))

    def test_0_baseline_is_clean(self):
        c = Chain(); c.tick(); c.tick(); c.close()
        code, f = self.run_v2(c)
        self.assertEqual((code, f), (0, []), f)

    def test_1_unknown_type_is_a_finding_and_the_chain_stays_checked(self):
        c = Chain(NEW); c.tick(); future_note(c); c.tick(); later = c.tick(); c.close()
        # a hash error in a LATER entry must still be found although an unknown type precedes it
        def tamper(entries): entries[later["seq"] - 1]["entry_hash"] = "f" * 64
        code, f = self.run_v2(c, patch=tamper)
        cls = self.classes(f)
        self.assertEqual(code, 2, f)
        self.assertNotIn("FORMAT_ERROR", cls, f)
        for want in ("SPEC_NEWER", "UNKNOWN_ENTRY_TYPE", "HASH_MISMATCH"): self.assertIn(want, cls, f)
        # the broken leaf also breaks the Merkle root and the anchored receipt - the chain checks did run
        self.assertIn("MERKLE_INCONSISTENT", cls, f)
        self.assertTrue(any(f"seq={later['seq']}" in x["detail"] for x in f if x["class"] == "HASH_MISMATCH"), f)

    def test_1b_unknown_type_once_per_name_with_first_seq(self):
        c = Chain(NEW); first = future_note(c); c.tick(); future_note(c); other = c.add("OTHER_FUTURE", {}); c.close()
        code, f = self.run_v2(c)
        unk = [x for x in f if x["class"] == "UNKNOWN_ENTRY_TYPE"]
        self.assertEqual(len(unk), 2, unk)                                  # two names, three occurrences
        self.assertIn(f"seq={first['seq']}", unk[0]["detail"])              # seq of the FIRST occurrence
        self.assertIn("FUTURE_NOTE", unk[0]["detail"])
        self.assertIn(f"seq={other['seq']}", unk[1]["detail"])
        self.assertEqual(code, 1)

    def test_1c_payload_of_unknown_type_must_be_an_object(self):
        c = Chain(NEW); c.add("FUTURE_NOTE", "not an object"); c.close()
        code, f = self.run_v2(c)
        self.assertEqual(code, 3)
        # 10.6 R3 last sentence: the rule-2 finding stands next to the FORMAT_ERROR of the same entry;
        # the chain runs at NEW, so the manifest's SPEC_NEWER is part of the exact set too
        # (pinned on both sides so the equivalence job cannot drift)
        self.assertEqual(self.classes(f), ["FORMAT_ERROR", "SPEC_NEWER", "UNKNOWN_ENTRY_TYPE"], f)
        self.assertTrue(any("payload" in x["detail"] for x in f if x["class"] == "FORMAT_ERROR"), f)

    def test_2_newer_minor_is_spec_newer_exactly_once(self):
        c = Chain(NEW); c.tick(); c.tick(); c.close()                       # every entry AND the manifest carry NEW
        code, f = self.run_v2(c)
        self.assertEqual(self.classes(f), ["SPEC_NEWER"], f)
        self.assertEqual(len(f), 1, f)
        self.assertEqual(code, 1)
        code, j = self.run_cli(c)                                           # and end to end through the CLI
        self.assertEqual((code, j["exit_code"], j["finding_classes"]), (1, 1, ["SPEC_NEWER"]), j)

    def test_2b_newer_minor_in_the_manifest_alone_or_in_one_entry_alone(self):
        c = Chain(); c.tick(); c.close()
        code, f = self.run_v2(c, manifest_version=NEW)
        self.assertEqual((code, self.classes(f), len(f)), (1, ["SPEC_NEWER"], 1), f)
        c = Chain(); c.tick(); c.close()
        def one(entries): entries[2]["spec_version"] = NEW                  # rehash so ONLY the version differs
        def rehash(entries):
            one(entries)
            for i, e in enumerate(entries):
                e["prev_hash"] = entries[i - 1]["entry_hash"] if i else V.ZERO
                e["entry_hash"] = V.entry_hash(e)
        code, f = self.run_v2(c, patch=rehash)
        self.assertIn("SPEC_NEWER", self.classes(f))
        self.assertEqual(sum(x["class"] == "SPEC_NEWER" for x in f), 1, f)
        self.assertNotIn("FORMAT_ERROR", self.classes(f))

    def test_2c_older_or_equal_minor_is_the_normal_case(self):
        c = Chain(OWN); c.tick(); c.close()
        self.assertEqual(self.run_v2(c)[0], 0)

    def test_3_other_major_is_a_format_error(self):
        for ver in ("2.0", "0.9", "1", "1.x", "v1.1", "1.1.0"):
            c = Chain(ver); c.tick(); c.close()
            code, f = self.run_v2(c)
            self.assertEqual((ver, code, self.classes(f)), (ver, 3, ["FORMAT_ERROR"]), f)
            self.assertNotIn("SPEC_NEWER", self.classes(f))
        c = Chain(); c.tick(); c.close()
        code, f = self.run_v2(c, manifest_version="2.0")
        self.assertEqual((code, self.classes(f)), (3, ["FORMAT_ERROR"]), f)

    def test_4_unknown_envelope_field_stays_a_format_error(self):
        for ver in ("1.0", NEW):
            c = Chain(ver, extra_env={"future_field": 1}); c.tick(); c.close()   # hashed in: only the schema objects
            code, f = self.run_v2(c)
            self.assertEqual((ver, code), (ver, 3), f)
            self.assertTrue(any("future_field" in x["detail"] for x in f if x["class"] == "FORMAT_ERROR"), f)
        c = Chain(NEW); c.tick(); c.close()                                 # known type, undefined PAYLOAD field: strict
        def extra(entries):
            entries[2]["payload"]["future_payload_field"] = 1
            for i, e in enumerate(entries):
                e["prev_hash"] = entries[i - 1]["entry_hash"] if i else V.ZERO
                e["entry_hash"] = V.entry_hash(e)
        code, f = self.run_v2(c, patch=extra)
        self.assertEqual(code, 3, f)
        self.assertTrue(any("future_payload_field" in x["detail"] for x in f if x["class"] == "FORMAT_ERROR"), f)

    def test_5_unknown_type_without_checkpoint_is_no_missing_checkpoint(self):
        c = Chain(NEW); future_note(c); c.tick(); c.tick(); c.close()     # FUTURE_NOTE followed by TICK, no checkpoint
        code, f = self.run_v2(c)
        self.assertEqual(self.classes(f), ["SPEC_NEWER", "UNKNOWN_ENTRY_TYPE"], f)
        self.assertEqual(code, 1)
        # control: a KNOWN critical type in the same position IS reported (the rule itself still works)
        c = Chain(NEW); c.add("MODE_CHANGE", {"from": "full", "to": "hash_only", "cause": "manual", "actor": None}, origin="portal"); c.tick(); c.close()
        code, f = self.run_v2(c)
        self.assertIn("MISSING_CHECKPOINT", self.classes(f), f)

    # ---- added after the adversarial review of 2026-09-13: three measured Go/Python divergences

    def test_8_empty_event_type_is_an_unknown_type(self):
        c = Chain(); c.add("", {"note": "empty type name"}); c.close()
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (1, ["UNKNOWN_ENTRY_TYPE"]), f)

    def test_8b_leading_zeros_are_malformed_not_aliases(self):
        for ver in ("01.0", "1.00", "1.01", "001.0"):
            c = Chain(ver); c.tick(); c.close()
            code, f = self.run_v2(c)
            self.assertEqual((ver, code, self.classes(f)), (ver, 3, ["FORMAT_ERROR"]), f)

    # ---- 10.6 R5: das Pruefpaket-Manifest ist erweiterbar (Freigabe 15.09.)

    def test_9_unknown_manifest_field_is_a_finding(self):
        """Ein undefiniertes Manifest-Feld: Befund, kein Formatfehler."""
        c = Chain(); c.tick(); c.close()
        code, f = self.run_v2(c, man_extra={"retention_days": 3650})
        self.assertEqual((code, self.classes(f)), (1, ["UNKNOWN_MANIFEST_FIELD"]), f)
        self.assertIn("manifest.retention_days", f[0]["detail"], f)

    def test_9b_unknown_manifest_field_does_not_stop_the_run(self):
        """Der eigentliche Punkt: die Kettenpruefungen laufen weiter.

        Nachgewiesen an einer Manipulation, die NUR aus der Kette kommen kann.
        Bricht der Lauf nach dem Manifest ab, fehlt HASH_MISMATCH.
        """
        c = Chain(); c.tick(); c.close()
        def kippen(entries): entries[1]["entry_hash"] = "f" * 64
        code, f = self.run_v2(c, man_extra={"partial_export": True}, patch=kippen)
        self.assertEqual(code, 2, f)
        self.assertIn("HASH_MISMATCH", self.classes(f), f)
        self.assertIn("UNKNOWN_MANIFEST_FIELD", self.classes(f), f)

    def test_9c_segment_objects_are_open_and_reported_without_an_index(self):
        c = Chain(); c.tick(); c.close()
        code, f = self.run_v2(c, seg_extra={"first_ts": iso(0)})
        self.assertEqual((code, self.classes(f)), (1, ["UNKNOWN_MANIFEST_FIELD"]), f)
        self.assertIn("manifest.segments[].first_ts", f[0]["detail"], f)

    def test_9d_defined_manifest_fields_stay_strict(self):
        """R5 oeffnet das Manifest, es weicht es nicht auf: ein definiertes Feld
        mit falschem Typ bleibt FORMAT_ERROR."""
        c = Chain(); c.tick(); c.close()
        self.n += 1
        pkg = c.write(os.path.join(self.tmp, "pkg%d" % self.n), man_extra={"neu": 1})
        with open(os.path.join(pkg, "manifest.json")) as fh: man = json.load(fh)
        man["tree_size"] = "nicht eine Zahl"
        with open(os.path.join(pkg, "manifest.json"), "w") as fh: json.dump(man, fh)
        res = V.verify(pkg, self.reg, at_ms(c.t + 3), 24.0, [])
        code = V.exit_code(res, self.reg["verifier"]["finding_classes"])
        # Beide Befunde, und Exit 3 gewinnt: Regel 3 verlangt ausdruecklich, dass
        # ein Befund der offenen Regeln auch neben einem Schemafehler desselben
        # Objekts gemeldet wird. Diese Erwartung war zuerst zu eng: der Code
        # hatte recht, der Test nicht.
        # / Both findings, exit 3 wins: rule 3 requires the open rules' finding
        # to be reported even next to a schema error of the same object.
        self.assertEqual((code, self.classes(res.findings)),
                         (3, ["FORMAT_ERROR", "UNKNOWN_MANIFEST_FIELD"]), res.findings)

    def test_8c_minor_of_any_length_is_spec_newer_once(self):
        c = Chain("1." + "9" * 40); c.tick(); c.close()
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (1, ["SPEC_NEWER"]), f)
        self.assertEqual(sum(1 for x in f if x["class"] == "SPEC_NEWER"), 1)

    def test_8d_spec_newer_reported_alongside_a_format_error(self):
        c = Chain(NEW, extra_env={"future_field": "x"}); c.tick(); c.close()
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (3, ["FORMAT_ERROR", "SPEC_NEWER"]), f)

    def test_7_unknown_registry_type_is_loud_not_silent(self):
        """A registry type this verifier does not implement must not pass silently (the old code accepted "2.0" that way)."""
        reg = json.loads(json.dumps(REG))
        reg["envelope_fields"]["spec_version"] = reg["pruefpaket_manifest"]["fields"]["spec_version"] = {"type": "future_type"}
        c = Chain("2.0"); c.tick(); c.close()
        self.n += 1
        res = V.verify(c.write(os.path.join(self.tmp, "pkg%d" % self.n)), reg, at_ms(c.t + 3), 24.0, [])
        self.assertEqual(V.exit_code(res, reg["verifier"]["finding_classes"]), 3, res.findings)
        self.assertTrue(any("future_type" in f["detail"] for f in res.findings if f["class"] == "FORMAT_ERROR"), res.findings)

    def test_6_registry_file_carries_contract_b(self):
        """The real registry (not the in-memory contract copy): part B of S1a (long landed) plus the
        expectations of the edition this verifier implements. Red whenever the file moves on without it."""
        with open(REG_PATH, encoding="utf-8") as fh: reg = json.load(fh)
        self.assertEqual(reg["envelope_fields"]["spec_version"], {"type": "version"})
        self.assertEqual(reg["pruefpaket_manifest"]["fields"]["spec_version"], {"type": "version"})
        self.assertEqual(reg["envelope_fields"]["event_type"], {"type": "open_enum", "ref": "event_types", "unknown_finding": "UNKNOWN_ENTRY_TYPE"})
        keys = list(reg["verifier"]["finding_classes"])
        self.assertEqual(keys[-4:], ["SPEC_NEWER", "UNKNOWN_ENTRY_TYPE",
                                     "UNKNOWN_MANIFEST_FIELD", "FORMAT_ERROR"], keys)
        for cls in ("SPEC_NEWER", "UNKNOWN_ENTRY_TYPE", "UNKNOWN_MANIFEST_FIELD"):
            self.assertEqual(reg["verifier"]["finding_classes"][cls]["exit"], 1, cls)
        # Since 1.6 (8.6) every frozen vector that is no format error is judged on its chain end as
        # well; the format vectors end without a seal, hence UNSEALED_END and exit 4 beside their finding.
        self.assertEqual(reg["testvectors"]["format"]["format_newer_minor"], {"exit": 4, "findings": ["SPEC_NEWER", "UNSEALED_END"]})
        # Since the 1.1 release the unknown-type vector runs at a version that is not newer
        # than the verifier, so it shows the unknown type alone; only format_newer_minor
        # (one MINOR above) still carries SPEC_NEWER.
        self.assertEqual(reg["testvectors"]["format"]["format_unknown_manifest_field"],
                         {"exit": 4, "findings": ["UNKNOWN_MANIFEST_FIELD", "UNSEALED_END"]})
        # 10.6 R5: das Manifest traegt die Befundklasse fuer unbekannte Felder.
        self.assertEqual(reg["pruefpaket_manifest"]["unknown_field_finding"], "UNKNOWN_MANIFEST_FIELD")
        # A literal on purpose, never read from the file it checks: a version bump must touch this
        # line consciously (together with the verifier), not pass by unnoticed. 1.10 = covered stretches between
        # two countersigned checkpoints (11.2, class Spec110CoveredStretches below). 1.9 = export seal, the late
        # immediate checkpoint (8.2 conditions 3 and 4), content/ layout, integer profile, processing stages,
        # auditor inputs, completeness statement and the measured residual window (classes Spec19* below).
        # Before it: 1.8 = GENESIS.license_id is the licence commitment (4.1; class GenesisLicense below);
        # 1.7 = the contract of 66f0cc0 (LEGAL_HOLD, HOLD_VIOLATION; class LegalHold below); 1.6 = the contract of 6be9d7e.
        self.assertEqual(reg["spec_version"], "1.10")
        self.assertEqual(reg["testvectors"]["format"]["format_unknown_event_type"], {"exit": 4, "findings": ["UNKNOWN_ENTRY_TYPE", "UNSEALED_END"]})


class GenesisLicense(V2Case):
    """Spec 4.1 (1.8): GENESIS.license_id is the licence commitment. From the GENESIS's own spec_version 1.8 on anything
    else is FORMAT_ERROR; a GENESIS of 1.7 or earlier with another value gets a notice - no finding, never the value."""
    KEY = "LEDGER-OFFN-GELG-T17V-ERIF"   # cleartext in a 1.7 GENESIS: disclosed by construction, used nowhere else

    def sealed(self, version, license=None):
        c = Chain(version, license=license); c.tick(); c.close(); return c

    def test_cleartext_from_18_is_a_format_error(self):
        for version in (OWN, NEW):   # the narrowing binds from 1.8 on, so at a newer MINOR too (10.6 R3)
            code, f = self.run_v2(self.sealed(version, self.KEY))
            self.assertEqual(code, 3, f)
            self.assertIn("FORMAT_ERROR", self.classes(f), f)
            self.assertTrue(any("licence commitment" in x["detail"] for x in f), f)
            self.assertFalse(any(self.KEY in x["detail"] for x in f), f)
        code, f = self.run_v2(self.sealed(OWN, hashlib.sha256(b"LIC").hexdigest().upper()))   # uppercase: not the form
        self.assertEqual(code, 3, f)

    def test_commitment_from_18_is_clean(self):
        code, f = self.run_v2(self.sealed(OWN))
        self.assertEqual((code, f), (0, []), f)
        self.assertIs(self.res.glic, False)

    def test_up_to_17_only_a_notice(self):
        code, f = self.run_v2(self.sealed("1.7", self.KEY))
        self.assertEqual((code, f), (0, []), f)
        self.assertIs(self.res.glic, True)
        code, out = self.run_cli(self.sealed("1.7", self.KEY))
        self.assertEqual((code, out["genesis_license_not_commitment"]), (0, True), out)
        for lang, want in (("en", "licence key itself may stand there"), ("de", "Lizenzschlüssel selbst stehen")):
            code, txt = self.run_cli(self.sealed("1.7", self.KEY), args=["--lang", lang], json_out=False)
            self.assertIn(want, txt)
            self.assertNotIn(self.KEY, txt)
        code, f = self.run_v2(self.sealed("1.7"))   # commitment already under 1.7 (the vendor-side mitigation): no notice
        self.assertEqual((code, f), (0, []), f)
        self.assertIs(self.res.glic, False)

    def test_long_minor_is_compared_without_a_digit_limit(self):
        """10.6 R1: MINOR is a whole number without an upper bound on its digits. Python refuses int() beyond 4300
        digits; before the review of 29.09. verifier2 crashed into exit 3 where the Go verifier said SPEC_NEWER."""
        code, f = self.run_v2(self.sealed("1." + "9" * 5000))
        self.assertEqual((code, self.classes(f)), (1, ["SPEC_NEWER"]), f)
        self.assertIs(self.res.glic, False)
        code, f = self.run_v2(self.sealed("1." + "9" * 5000, self.KEY))    # the 1.8 narrowing binds a newer MINOR too
        self.assertEqual(code, 3, f)

    def test_notice_not_stated_for_a_format_error(self):
        code, out = self.run_cli(self.sealed("1.7", self.KEY), patch=lambda es: es[1].__setitem__("event_type", "GENESIS"))
        self.assertEqual(code, 3, out)
        self.assertIsNone(out["genesis_license_not_commitment"], out)


class ContentDisclosed(V2Case):
    """Spec 4.18 (S1b): a chained disclosure is not a finding; the type is critical; its payload is strict.
    Runs against spec/registry.json AS ON DISK (no in-memory contract), so without CONTENT_DISCLOSED in the file
    case 1 draws UNKNOWN_ENTRY_TYPE (exit 1), case 2 no MISSING_CHECKPOINT, cases 3/4 pass unchecked
    (10.6 R2 asks only for an object payload of an unknown type). Case 5 is a control, green in both states."""
    reg = file_registry()

    def test_1_valid_disclosure_is_no_finding(self):
        c = Chain(); t = ai_call(c); disclosed(c, t); c.tick(); c.close()
        self.assertEqual(self.run_v2(c), (0, []))

    def test_2_disclosure_without_checkpoint_is_missing_checkpoint(self):
        c = Chain(); t = ai_call(c); e = disclosed(c, t, checkpoint=False); c.tick(); c.close()
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (2, ["MISSING_CHECKPOINT"]), f)
        self.assertTrue(any(f"seq={e['seq']}" in x["detail"] for x in f), f)

    def test_3_reason_outside_enum_or_missing_field_is_format_error(self):
        for mut in (lambda p: p.__setitem__("reason", "neugier"), lambda p: p.pop("role")):
            c = Chain(); t = ai_call(c); disclosed(c, t, mutate=mut); c.tick(); c.close()
            code, f = self.run_v2(c)
            self.assertEqual((code, self.classes(f)), (3, ["FORMAT_ERROR"]), f)

    def test_4_negative_bytes_is_format_error(self):
        for field in ("request_bytes", "response_bytes"):
            c = Chain(); t = ai_call(c); disclosed(c, t, mutate=lambda p: p.__setitem__(field, -1)); c.tick(); c.close()
            code, f = self.run_v2(c)
            self.assertEqual((code, self.classes(f)), (3, ["FORMAT_ERROR"]), (field, f))

    def test_5_no_content_deleted_note_for_a_disclosure(self):
        c = Chain(); t = ai_call(c); disclosed(c, t); c.close()
        code, f = self.run_v2(c)
        self.assertNotIn("CONTENT_DELETED", self.classes(f), f)

    def test_6_cli_end_to_end(self):
        c = Chain(); t = ai_call(c); disclosed(c, t); c.close()
        code, out = self.run_cli(c)
        self.assertEqual((code, out["findings"]), (0, []), out)

    def test_9_registry_file_carries_contract_d(self):
        """The real registry (not the in-memory contract copy)."""
        with open(REG_PATH, encoding="utf-8") as fh: reg = json.load(fh)
        keys = list(reg["event_types"])
        self.assertEqual(keys[keys.index("CONTENT_DELETED") + 1], "CONTENT_DISCLOSED", keys)
        self.assertEqual(reg["event_types"]["CONTENT_DISCLOSED"], CONTENT_DISCLOSED_SPEC)
        # the frozen vector ends without a seal: since 1.6 (8.6) that is incomplete, its bytes are unchanged
        self.assertEqual(reg["testvectors"]["valid"]["valid_content_disclosed"], {"exit": 4, "findings": ["UNSEALED_END"]})


ROOT_SEED = bytes(range(64, 96))


def vendor_list(keys, root_id="wurzel-test", seed=ROOT_SEED):
    """A signed vendor key list (format.de.md 10.7): JCS of the object without signatur, Ed25519 by the root."""
    body = {"format": "rekorder-herstellerschluessel/1", "version": 2, "ausgestellt": "2025-12-01T00:00:00Z", "schluessel": keys}
    return json.dumps(dict(body, signatur={"wurzel_id": root_id, "sig": sign(seed, V.jcsb(body)).hex()})).encode()


class VendorTrust(V2Case):
    """Spec 7.1/10.7 (1.4): the vendor key comes from the AUDITOR's anchor, never from the package alone."""

    def _pkg(self, liste=None):
        c = Chain(); c.tick(); c.close()
        if liste is not None:
            orig = c.write
            def write(dst, **kw):
                orig(dst, **kw); os.makedirs(os.path.join(dst, "keys", "vendor"), exist_ok=True)
                with open(os.path.join(dst, "keys", "vendor", "schluesselliste.json"), "wb") as fh: fh.write(liste)
                return dst
            c.write = write
        return c

    def root(self): return {"wurzel-test": pubkey(ROOT_SEED).hex()}

    def test_1_without_anchor_the_package_key_proves_nothing(self):
        code, f = self.run_v2(self._pkg(), keys={})
        self.assertEqual((code, self.classes(f)), (1, ["RECEIPT_UNVERIFIED"]), f)
        self.assertIn(pubkey(VENDOR_SEED).hex(), f[0]["detail"])

    def test_2_pinned_key(self):
        self.assertEqual(self.run_v2(self._pkg()), (0, []))

    def test_3_pin_contradicting_the_package(self):
        code, f = self.run_v2(self._pkg(), keys={"vendor-1": pubkey(ROOT_SEED).hex()})
        self.assertEqual((code, self.classes(f)), (2, ["NO_ANCHOR", "RECEIPT_INVALID"]), f)

    def test_4_list_signed_by_the_auditors_root(self):
        liste = vendor_list([{"key_id": "vendor-1", "pubkey": pubkey(VENDOR_SEED).hex(), "gueltig_ab": "2025-01-01T00:00:00Z"}])
        self.assertEqual(self.run_v2(self._pkg(liste), roots=self.root(), keys={}), (0, []))

    def test_4b_report_names_the_list_used(self):
        """7.1: whether a newer list exists is not visible from the package -- output names version, issue time, root."""
        liste = vendor_list([{"key_id": "vendor-1", "pubkey": pubkey(VENDOR_SEED).hex(), "gueltig_ab": "2025-01-01T00:00:00Z"}])
        c = self._pkg(liste)
        pkg = c.write(os.path.join(self.tmp, "pkg_liste"))
        res = V.verify(pkg, self.reg, at_ms(c.t + 3), 24.0, [], vendor_roots=self.root(), vendor_keys={})
        self.assertEqual(res.vendor_list, {"version": 2, "ausgestellt": "2025-12-01T00:00:00Z", "wurzel_id": "wurzel-test"})
        self.assertIn("vendor key list: version 2, issued 2025-12-01T00:00:00Z, root wurzel-test",
                      V.render(res, 0, self.reg["verifier"]["finding_classes"], "en", pkg))
        res = V.verify(pkg, self.reg, at_ms(c.t + 3), 24.0, [], vendor_roots={}, vendor_keys={})
        self.assertIsNone(getattr(res, "vendor_list", None))   # no root: the list counts for nothing, so it is not named

    def test_5_list_revokes_the_key(self):
        liste = vendor_list([{"key_id": "vendor-1", "pubkey": pubkey(VENDOR_SEED).hex(), "gueltig_ab": "2025-01-01T00:00:00Z",
                              "widerrufen_ab": "2025-12-31T00:00:00Z"}])
        code, f = self.run_v2(self._pkg(liste), roots=self.root(), keys={})
        self.assertEqual((code, self.classes(f)), (2, ["NO_ANCHOR", "RECEIPT_INVALID"]), f)

    def test_6_list_of_a_foreign_root_counts_for_nothing(self):
        liste = vendor_list([{"key_id": "vendor-1", "pubkey": pubkey(VENDOR_SEED).hex(), "gueltig_ab": "2025-01-01T00:00:00Z"}],
                            root_id="wurzel-test", seed=DEV_SEED)
        code, f = self.run_v2(self._pkg(liste), roots=self.root(), keys={})
        self.assertEqual((code, self.classes(f)), (1, ["RECEIPT_UNVERIFIED"]), f)

    def test_8_wurzel_id_of_wrong_type_is_an_ineffective_list(self):
        """Review of 25.09. (M1): signatur.wurzel_id as an array crashed verifier2 (exit 3); the Go verifier and
        spec 10.7 say: the list is ineffective, no finding of its own."""
        body = {"format": "rekorder-herstellerschluessel/1", "version": 2, "ausgestellt": "2025-12-01T00:00:00Z",
                "schluessel": [{"key_id": "vendor-1", "pubkey": pubkey(VENDOR_SEED).hex(), "gueltig_ab": "2025-01-01T00:00:00Z"}]}
        for wid in ([], {}, 7):
            liste = json.dumps(dict(body, signatur={"wurzel_id": wid, "sig": "0" * 128})).encode()
            code, f = self.run_v2(self._pkg(liste), roots=self.root(), keys={})
            self.assertEqual((code, self.classes(f)), (1, ["RECEIPT_UNVERIFIED"]), (wid, f))

    def test_9_unknown_root_id(self):
        liste = vendor_list([{"key_id": "vendor-1", "pubkey": pubkey(VENDOR_SEED).hex(), "gueltig_ab": "2025-01-01T00:00:00Z"}],
                            root_id="wurzel-fremd")
        code, f = self.run_v2(self._pkg(liste), roots=self.root(), keys={})
        self.assertEqual((code, self.classes(f)), (1, ["RECEIPT_UNVERIFIED"]), f)
        self.assertIn("wurzel-fremd", f[0]["detail"])

    def test_10_manifest_copy_is_irrelevant_once_the_list_holds(self):
        """Review of 25.09. (H1): an unsigned manifest edit must not turn genuine receipts into RECEIPT_INVALID."""
        liste = vendor_list([{"key_id": "vendor-1", "pubkey": pubkey(VENDOR_SEED).hex(), "gueltig_ab": "2025-01-01T00:00:00Z"}])
        c = self._pkg(liste)
        orig = c.write
        def write(dst, **kw):
            orig(dst, **kw); p = os.path.join(dst, "manifest.json")
            m = json.load(open(p)); m["vendor_pubkeys"][0]["pubkey"] = "11" * 32
            json.dump(m, open(p, "w"))
            return dst
        c.write = write
        self.assertEqual(self.run_v2(c, roots=self.root(), keys={}), (0, []))

    def test_11_list_time_grammar(self):
        self.assertIsNone(V.utc_ns("0000-01-01T00:00:00Z"))
        self.assertIsNone(V.utc_ns("2026-01-01T00:00:0\u0663Z"))           # Arabic-Indic digit
        self.assertEqual(V.utc_ns("2026-01-01T00:00:00.1234567891234Z"), V.utc_ns("2026-01-01T00:00:00.123456789Z"))

    def test_12_conflicting_anchors_are_an_invocation_error(self):
        c = self._pkg()
        pkg = c.write(os.path.join(self.tmp, "konflikt"))
        a, b = "aa" * 32, "bb" * 32
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = vmain(["verifier2", pkg, "--json", "--vendor-key", "k=" + a, "--vendor-key", "k=" + b])
        self.assertEqual(code, 3)

    def test_13_contradicted_receipt_still_shows_the_fork(self):
        """Review of 25.09.: a receipt the vendor's list contradicts still carries its signature, so the prefix check
        runs (7.1) - a second history stays FORK_DETECTED instead of hiding behind RECEIPT_INVALID."""
        c = Chain(); c.tick(); cp = c.checkpoint(); p = cp["payload"]
        obj = {"chain_id": CHAIN, "tree_size": p["tree_size"], "merkle_root": "ab" * 32, "server_ts": iso(c.t + 1)}
        c.add("CHECKPOINT_RECEIPT", {"checkpoint_seq": cp["seq"], "tree_size": p["tree_size"], "merkle_root": "ab" * 32,
                                     "server_ts": obj["server_ts"], "server_key_id": "vendor-1",
                                     "server_signature": sign(VENDOR_SEED, V.jcsb(obj)).hex()}, mono=1000)
        liste = vendor_list([{"key_id": "vendor-1", "pubkey": pubkey(VENDOR_SEED).hex(), "gueltig_ab": "2025-01-01T00:00:00Z",
                              "widerrufen_ab": "2025-12-31T00:00:00Z"}])
        orig = c.write
        def write(dst, **kw):
            orig(dst, **kw); os.makedirs(os.path.join(dst, "keys", "vendor"), exist_ok=True)
            with open(os.path.join(dst, "keys", "vendor", "schluesselliste.json"), "wb") as fh: fh.write(liste)
            return dst
        c.write = write
        code, f = self.run_v2(c, roots=self.root(), keys={})
        self.assertEqual(code, 2, f)
        self.assertIn("FORK_DETECTED", self.classes(f), f)
        self.assertIn("RECEIPT_INVALID", self.classes(f), f)

    def test_7_manifest_with_bom_is_a_format_error(self):
        """Both verifiers read JSON strictly as UTF-8. Until 25.09. json.loads(bytes) stripped a BOM silently here,
        while the Go verifier answered FORMAT_ERROR - two verdicts about one package."""
        c = self._pkg()
        orig = c.write
        def write(dst, **kw):
            orig(dst, **kw); p = os.path.join(dst, "manifest.json")
            with open(p, "rb") as fh: b = fh.read()
            with open(p, "wb") as fh: fh.write(b"\xef\xbb\xbf" + b)
            return dst
        c.write = write
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (3, ["FORMAT_ERROR"]), f)


class Klarstellung(V2Case):
    """Klarstellungen der Spezifikation 1.4 vom 25.09. (freigegeben): Stellen, an denen beide Verifier dasselbe Paket
    verschieden beurteilten, weil die Spezifikation schwieg. Gegen den Stand davor rot (bis auf test_1, den verifier2 schon hielt).
    Bis 28.09. lief diese Klasse im Skriptmodus nie: sie stand hinter dem main-Waechter (unittest.main beendet den Prozess).
    Seit 1.6 (8.6) enden die Ketten von test_1 bis test_3 ohne Siegel und tragen deshalb zusaetzlich UNSEALED_END."""

    def _receipt(self, c, cp_seq, tree_size, root):
        obj = {"chain_id": CHAIN, "tree_size": tree_size, "merkle_root": root, "server_ts": iso(c.t + 1)}
        return c.add("CHECKPOINT_RECEIPT", {"checkpoint_seq": cp_seq, "tree_size": tree_size, "merkle_root": root,
                                            "server_ts": obj["server_ts"], "server_key_id": "vendor-1",
                                            "server_signature": sign(VENDOR_SEED, V.jcsb(obj)).hex()}, mono=1000)

    def _zip(self, c, extra=(), prefix=""):
        d = c.write(os.path.join(self.tmp, "zipquelle%d" % len(os.listdir(self.tmp))))
        z = os.path.join(self.tmp, "paket%d.zip" % len(os.listdir(self.tmp)))
        with zipfile.ZipFile(z, "w") as zf:
            for r, _d, ns in os.walk(d):
                for n in ns: zf.write(os.path.join(r, n), prefix + os.path.relpath(os.path.join(r, n), d).replace(os.sep, "/"))
            for name, data in extra: zf.writestr(name, data)
        res = V.verify(z, self.reg, at_ms(c.t + 3), 24.0, [], vendor_roots={}, vendor_keys=PIN)
        return V.exit_code(res, self.reg["verifier"]["finding_classes"]), self.classes(res.findings)

    def test_1_invalid_signature_gets_no_prefix_finding(self):
        c = Chain(); self._receipt(c, 2, 1, "ab" * 32)
        code, f = self.run_v2(c, keys={"vendor-1": pubkey(ROOT_SEED).hex()})
        self.assertEqual((code, self.classes(f)), (2, ["NO_ANCHOR", "RECEIPT_INVALID", "UNSEALED_END"]), f)

    def test_2_receipt_contradicting_its_checkpoint_is_receipt_invalid_and_anchors_nothing(self):
        c = Chain()
        self._receipt(c, 1, 1, V.mth([bytes.fromhex(c.entries[0]["entry_hash"])]).hex())   # seq 1 is the GENESIS
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (2, ["NO_ANCHOR", "RECEIPT_INVALID", "UNSEALED_END"]), f)
        self.assertIsNone(self.res.last_countersigned)       # it countersigns no checkpoint of the chain (8.6)

    def test_3_fork_stays_its_own_class(self):
        c = Chain(); self._receipt(c, 1, 1, "cd" * 32)
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (2, ["FORK_DETECTED", "UNSEALED_END"]), f)

    def test_4_year_0000_is_a_format_error(self):
        c = Chain(); c.close()
        code, f = self.run_v2(c, patch=lambda es: es[0].update(ts_captured="0000-01-01T00:00:00Z"))
        self.assertEqual(code, 3, f)

    def test_5_zip_names_in_normal_form(self):
        c = Chain(); c.close()
        self.assertEqual(self._zip(c), (0, []))
        self.assertEqual(self._zip(c, prefix="paket/"), (0, []))
        man = open(os.path.join(c.write(os.path.join(self.tmp, "manquelle")), "manifest.json"), "rb").read()
        for name, extra, prefix in [("./manifest.json", [("./manifest.json", man)], ""),
                                    ("a/../manifest.json", [("a/../manifest.json", man)], ""),
                                    ("leading /", [("/x.txt", b"x")], ""), ("backslash", [("keys\\x.hex", b"x")], ""),
                                    ("empty part", [("keys//x.hex", b"x")], ""), ("twice", [("manifest.json", man)], ""),
                                    ("file beside the wrapper", [("paket", b"x")], "paket/")]:
            with self.subTest(name):
                code, cls = self._zip(c, extra, prefix)
                self.assertEqual((code, cls), (3, ["FORMAT_ERROR"]))


class ChainEnd(V2Case):
    """Spezifikation 1.6, Abschnitt 8.6 (mit 6.2, 8.4, 10.3): eine Kette ist versiegelt oder unvollstaendig.
    Laeuft gegen spec/registry.json WIE AUF DER PLATTE: UNSEALED_END, Exit 4 und die Rangfolge kommen von dort.
    Gegen den Stand 1.5 rot: der kennt kein Exit 4, meldet eine mit update/shutdown versiegelte Kette als
    HANDOVER_BROKEN und einen kritischen Eintrag am Kettenende als MISSING_CHECKPOINT.
    / Spec 1.6, 8.6: a chain is sealed or incomplete; runs against the registry file as it is."""
    reg = file_registry()

    @staticmethod
    def mode_change(c): return c.add("MODE_CHANGE", {"from": "full", "to": "hash_only", "cause": "manual", "actor": None}, origin="portal")

    def test_0_registry_file_carries_contract_1_6(self):
        v = self.reg["verifier"]
        self.assertEqual(v["exit_precedence"], [3, 2, 4, 1, 0])
        self.assertEqual(sorted(v["exit_codes"]), ["0", "1", "2", "3", "4"])
        self.assertEqual(v["finding_classes"]["UNSEALED_END"]["exit"], 4)
        self.assertEqual(self.reg["testvectors"]["end"], {                   # the vectors this class models synthetically
            "end_sealed_stale": {"exit": 1, "findings": ["TRAILING_SILENCE"]},
            "end_unsealed_bare_critical": {"exit": 4, "findings": ["UNSEALED_END"]},
            "end_unsealed_bare_seal": {"exit": 4, "findings": ["UNSEALED_END"]},
            "end_truncated_at_seal": {"exit": 0, "findings": []}})

    def test_1_sealed_shutdown_is_valid(self):
        c = Chain(); c.tick(); c.close("shutdown")
        seal = c.entries[-3]
        self.assertEqual(self.run_v2(c), (0, []))
        self.assertEqual(self.res.chain_end, {"status": "sealed", "last_seq": c.entries[-1]["seq"], "seal_seq": seal["seq"],
                                              "seal_reason": "shutdown", "seal_ts": seal["ts_chained"]})

    def test_2_every_reason_seals_with_a_receipt_on_the_seal_checkpoint(self):
        """Up to 1.5 only decommission/key_loss closed a chain; update and shutdown were HANDOVER_BROKEN."""
        for reason in ("update", "shutdown", "key_loss", "decommission"):
            c = Chain(); c.tick(); c.close(reason)
            self.assertEqual(c.entries[-1]["payload"]["checkpoint_seq"], c.entries[-2]["seq"])   # receipt on exactly that checkpoint
            self.assertEqual((reason, self.run_v2(c)), (reason, (0, [])))

    def test_2b_seal_and_checkpoint_alone_are_sealed(self):
        c = Chain(); c.tick(); c.anchor(); c.tick(); c.seal("update")
        self.assertEqual(self.run_v2(c), (0, []))

    def test_3_unsealed_end_is_incomplete_exit_4(self):
        c = Chain(); c.tick(); cp = c.anchor()                                # how an export from a running installation ends
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (4, ["UNSEALED_END"]), f)
        self.assertEqual(len(f), 1, f)                                        # exactly once
        last, p = c.entries[-1], cp["payload"]
        self.assertTrue(f[0]["detail"].startswith(f"seq={last['seq']}: the chain ends with CHECKPOINT_RECEIPT at {last['ts_chained']}"), f)
        for want in (f"checkpoint_seq={cp['seq']}", f"tree_size={p['tree_size']}", f"merkle_root={p['merkle_root']}",
                     f"server_ts={last['payload']['server_ts']}", "--expect-root TREE_SIZE:ROOT", "MERKLE_INCONSISTENT"):
            self.assertIn(want, f[0]["detail"])
        self.assertEqual(self.res.chain_end["status"], "incomplete")
        self.assertEqual(self.res.last_countersigned, {"checkpoint_seq": cp["seq"], "tree_size": p["tree_size"],
                                                       "merkle_root": p["merkle_root"], "server_ts": last["payload"]["server_ts"]})

    def test_3b_last_countersigned_is_the_largest_tree_size_not_the_last_receipt(self):
        c = Chain(); a = c.anchor(); c.tick(); b = c.anchor(); c.receipt(a); c.tick()
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (4, ["UNSEALED_END"]), f)
        self.assertEqual(self.res.last_countersigned["checkpoint_seq"], b["seq"])

    def test_4_precedence_4_over_1_and_no_countersigned_checkpoint(self):
        c = Chain(); c.tick(); c.checkpoint()                                 # no receipt at all: NO_ANCHOR (exit class 1)
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (4, ["NO_ANCHOR", "UNSEALED_END"]), f)
        self.assertIn("Last countersigned checkpoint in the package: none.", [x for x in f if x["class"] == "UNSEALED_END"][0]["detail"])
        self.assertIsNone(self.res.last_countersigned)

    def test_5_bare_critical_entry_at_the_end_is_incomplete_not_missing_checkpoint(self):
        c = Chain(); c.tick(); c.anchor(); e = self.mode_change(c)
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (4, ["UNSEALED_END"]), f)
        self.assertTrue(f[0]["detail"].startswith(f"seq={e['seq']}: the chain ends with MODE_CHANGE (critical"), f)

    def test_6_bare_seal_at_the_end_is_incomplete(self):
        for reason in ("decommission", "update"):                            # no reason closes a chain without the checkpoint
            c = Chain(); c.tick(); c.anchor(); c.add("SEAL", {"version": "1.0.0", "reason": reason})
            code, f = self.run_v2(c)
            self.assertEqual((reason, code, self.classes(f)), (reason, 4, ["UNSEALED_END"]), f)

    def test_7_critical_entry_followed_by_another_entry_stays_missing_checkpoint(self):
        c = Chain(); e = self.mode_change(c); c.tick(); c.close()
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (2, ["MISSING_CHECKPOINT"]), f)
        self.assertTrue(f[0]["detail"].startswith(f"seq={e['seq']}: critical MODE_CHANGE is followed by TICK"), f)

    def test_8_seal_checkpoint_then_another_entry_is_handover_broken_and_incomplete(self):
        c = Chain(); c.anchor(); c.seal("shutdown"); c.tick()
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (2, ["HANDOVER_BROKEN", "UNSEALED_END"]), f)   # 2 before 4 (10.3)

    def test_8b_trailing_receipt_on_another_checkpoint_does_not_seal(self):
        c = Chain(); c.tick(); a = c.checkpoint(); c.seal("shutdown"); c.receipt(a)
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (2, ["HANDOVER_BROKEN", "UNSEALED_END"]), f)

    def test_8c_rewrite_in_a_sealed_chain_is_invalid_but_not_incomplete(self):
        c = Chain(); t = c.tick(); c.close()
        def rewrite(es): es[t["seq"] - 1]["payload"]["disk_pct"] = 11      # bytes changed, entry_hash left as it was
        code, f = self.run_v2(c, patch=rewrite)
        self.assertEqual((code, self.classes(f)), (2, ["HASH_MISMATCH"]), f)

    def test_9_exit_precedence_comes_from_the_registry(self):
        meta = self.reg["verifier"]["finding_classes"]
        def probe(*classes, rules=None):
            res = V.Result(rules or self.reg["verifier"])
            for cls in classes: res.add(cls, "probe")
            return V.exit_code(res, meta)
        self.assertEqual(probe(), 0)
        self.assertEqual(probe("NO_ANCHOR"), 1)
        self.assertEqual(probe("UNSEALED_END", "NO_ANCHOR"), 4)                        # 4 over 1
        self.assertEqual(probe("UNSEALED_END", "HANDOVER_BROKEN"), 2)                  # 2 over 4: max() said 4
        self.assertEqual(probe("UNSEALED_END", "HASH_MISMATCH", "FORMAT_ERROR"), 3)
        turned = dict(self.reg["verifier"], exit_precedence=[3, 4, 2, 1, 0])          # data-driven: the registry decides
        self.assertEqual(probe("UNSEALED_END", "HANDOVER_BROKEN", rules=turned), 4)
        with self.assertRaises(ValueError):                                            # an exit class without a rank is loud
            probe("UNSEALED_END", rules=dict(self.reg["verifier"], exit_precedence=[3, 2, 1, 0]))
        bare = V.Result(); bare.add("UNSEALED_END", "probe"); bare.add("HANDOVER_BROKEN", "probe")
        self.assertEqual(V.exit_code(bare, meta), 2)                                   # without a run: the default registry
        regp = os.path.join(self.tmp, "registry_ohne_rang_4.json")                     # the command line refuses such a registry
        with open(regp, "w") as fh: json.dump(dict(self.reg, verifier=dict(self.reg["verifier"], exit_precedence=[3, 2, 1, 0])), fh)
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            self.assertEqual(vmain(["verifier2", self.tmp, "--registry", regp]), 3)
        self.assertIn("exit_precedence", err.getvalue())

    def test_10_sealed_but_stale_is_trailing_silence(self):
        c = Chain(); c.tick(); c.close()
        code, f = self.run_v2(c, now=c.t + 25 * 3600)
        self.assertEqual((code, self.classes(f)), (1, ["TRAILING_SILENCE"]), f)
        self.assertEqual(self.res.chain_end["status"], "sealed")

    def test_11_truncation_at_an_earlier_seal_shows_only_against_the_vendor_root(self):
        """11.2: cut directly behind an earlier SEAL's checkpoint, a chain looks sealed without any key.
        The comparison with the vendor's most recent countersigned root (--expect-root) exposes it."""
        c = Chain(); c.tick(); c.anchor(); seal = c.seal("update")
        cut = len(c.entries)
        c.add("RESUME", {"prev_version": "1.0.0", "new_version": "1.1.0", "sealed_entry_hash": seal["entry_hash"]})
        c.tick(); later = c.anchor(); c.tick(); c.close()
        def truncate(es): del es[cut:]
        want = (later["payload"]["tree_size"], later["payload"]["merkle_root"])
        self.assertEqual(self.run_v2(c, expect=[want]), (0, []))                       # control: the whole chain holds that root
        self.assertEqual(self.run_v2(c, patch=truncate), (0, []))                      # the limit of proof
        self.assertEqual(self.res.chain_end["seal_seq"], seal["seq"])
        code, f = self.run_v2(c, patch=truncate, expect=[want])
        self.assertEqual((code, self.classes(f)), (2, ["MERKLE_INCONSISTENT"]), f)
        code, j = self.run_cli(c, args=["--expect-root", "%d:%s" % want], patch=truncate)   # the same on the command line
        self.assertEqual((code, j["finding_classes"], j["chain_end"]["status"]), (2, ["MERKLE_INCONSISTENT"], "sealed"), j)

    def test_12_text_output_english_by_default_and_german(self):
        """From 1.1.0 the report language defaults to en, as in ledger-verify (README section 3); --lang de gives German."""
        exits, meta = self.reg["verifier"]["exit_codes"], self.reg["verifier"]["finding_classes"]
        c = Chain(); c.tick(); c.anchor()
        last = c.entries[-1]["seq"]
        code, txt = self.run_cli(c, json_out=False)
        lines = txt.splitlines()
        self.assertEqual((code, lines[0].split(": ")[0]), (4, "LEDGER verifier2 " + V.VERSION), lines)
        self.assertEqual(lines[1:3], ["exit 4: " + exits["4"]["en"], f"chain end: not sealed, last entry seq {last}"])
        self.assertIn("[UNSEALED_END] exit 4: " + meta["UNSEALED_END"]["en"], txt)
        code, txt = self.run_cli(c, args=["--lang", "de"], json_out=False)
        self.assertEqual(txt.splitlines()[1:3], ["Exit 4: " + exits["4"]["de"], f"Kettenende: nicht versiegelt, letzter Eintrag seq {last}"])
        self.assertIn("[UNSEALED_END] Exit 4: " + meta["UNSEALED_END"]["de"], txt)
        c = Chain(); c.tick(); c.close("decommission"); s = c.entries[-3]
        for lang, head, end in (("de", "Exit", f"Kettenende: versiegelt am {s['ts_chained']} (decommission, seq {s['seq']})"),
                                ("en", "exit", f"chain end: sealed at {s['ts_chained']} (decommission, seq {s['seq']})")):
            code, txt = self.run_cli(c, args=["--lang", lang], json_out=False)
            # from 1.9 the completeness statement (8.6) and the residual window (11.2) follow the chain end
            lines = txt.splitlines()
            self.assertEqual((code, lines[1:3]), (0, [f"{head} 0: " + exits["0"][lang], end]))
            self.assertEqual(lines[3].split(":")[0], "Vollständigkeit" if lang == "de" else "completeness")
            self.assertEqual(lines[4].split(" (")[0], "Restfenster" if lang == "de" else "residual window")
            self.assertEqual(lines[5], self.reg["vendor_log"]["texts"]["not_supplied"][lang])        # 10.10.3: the block of the vendor log
            ah, af = self.reg["verifier"]["anchor_history"]["texts"], self.reg["verifier"]["affiliation"]["texts"]
            self.assertEqual(lines[6], ah["not_supplied"][lang].format(chain_id=CHAIN))            # 10.10.3 (1.10): the block of the anchor history
            # 10.10.3 (1.10): then the block of the evidence level (here level 2, a pinned receipt), whose last line is the
            # line on affiliation with the sentence open_at_level_2; then the findings.
            self.assertTrue(lines[7].startswith(self.reg["verifier"]["evidence_level"]["texts"]["label"][lang] + " 2 "), lines[7])
            self.assertEqual(lines[-2], "  " + af["not_checked"][lang] + " " + af["not_checked_fetch"][lang].format(chain_id=CHAIN) + " " + af["open_at_level_2"][lang])
            self.assertEqual(lines[-1], "keine Befunde." if lang == "de" else "no findings.")
        for k in exits:                                                                # every exit code, exit 4 included
            for lang in ("de", "en"):
                self.assertIn(": " + exits[k][lang] + "\n", V.render(V.Result(self.reg["verifier"]), int(k), meta, lang, "p"))
        c = Chain("2.0"); c.anchor()
        code, txt = self.run_cli(c, json_out=False)
        self.assertEqual((code, txt.splitlines()[1:3]), (3, ["exit 3: " + exits["3"]["en"], "chain end: not judged"]))

    def test_13_json_names_chain_end_and_last_countersigned(self):
        c = Chain(); c.tick(); cp = c.anchor()
        code, j = self.run_cli(c)
        self.assertEqual((code, j["chain_end"]), (4, {"status": "incomplete", "last_seq": c.entries[-1]["seq"],
                                                      "seal_seq": None, "seal_reason": None, "seal_ts": None}))
        self.assertEqual(j["last_countersigned"]["checkpoint_seq"], cp["seq"])
        c.close("update"); s = c.entries[-3]
        code, j = self.run_cli(c)
        self.assertEqual((code, j["chain_end"]), (0, {"status": "sealed", "last_seq": c.entries[-1]["seq"], "seal_seq": s["seq"],
                                                      "seal_reason": "update", "seal_ts": s["ts_chained"]}))
        self.assertEqual(j["last_countersigned"]["checkpoint_seq"], c.entries[-2]["seq"])
        c = Chain("2.0"); c.anchor()                                                   # format error: the end is not judged (8.6)
        code, j = self.run_cli(c)
        self.assertEqual((code, j["finding_classes"], j["chain_end"], j["last_countersigned"]), (3, ["FORMAT_ERROR"], None, None))


# contract of spec 1.7 (4.24), used only to check the file (LegalHold.test_0) - never injected into a registry copy
LEGAL_HOLD_PAYLOAD = {"action": {"type": "enum", "values": ["set", "release"]}, "hold_id": {"type": "string", "maxlen": 64},
                      "scope_from": {"type": "rfc3339"}, "scope_to": {"type": "rfc3339"},
                      "reference": {"type": "string", "maxlen": 200}, "actor": {"type": "string", "maxlen": 128}}
UNBOUNDED = ("0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z")     # 4.24: the bounds that stand for "unbounded"
DAY = ("2026-01-01T00:00:00Z", "2026-01-01T23:59:59Z")            # every test chain lies in this day (T0 + minutes)
YEAR_2025 = ("2025-01-01T00:00:00Z", "2025-12-31T23:59:59Z")      # before every test chain


class LegalHold(V2Case):
    """Spezifikation 1.7, Abschnitte 4.24 und 9.3: Eine Sperre ist von ihrem LEGAL_HOLD set bis zum release
    derselben hold_id aktiv; ein weiteres set ersetzt den Umfang, ein release ohne aktive Sperre ist wirkungslos.
    Ein CONTENT_DELETED, dessen target_seq einen AI_CALL nennt, den an dieser Stelle eine aktive Sperre erfasst
    (ts_captured zwischen scope_from und scope_to, Grenzen eingeschlossen, als Zeitpunkte), ist HOLD_VIOLATION
    (Exit 1), einmal je Loeschung, mit allen erfassenden Sperren. LEGAL_HOLD ist kritisch (Sofort-Checkpoint).
    Laeuft gegen spec/registry.json WIE AUF DER PLATTE; alle Ketten sind versiegelt (Chain.close).
    Gegen den Stand 1.6 von verifier2.py rot: der kennt HOLD_VIOLATION und legal_holds nicht.
    / Spec 1.7, 4.24 and 9.3: deletion holds and HOLD_VIOLATION; runs against the registry file as it is."""
    reg = file_registry()

    @staticmethod
    def hold(c, hold_id, scope=DAY, action="set", checkpoint=True, mutate=None):
        """LEGAL_HOLD (4.24) and, unless told otherwise, its immediate checkpoint; mutate edits the payload first."""
        p = {"action": action, "hold_id": hold_id, "scope_from": scope[0], "scope_to": scope[1],
             "reference": "Az. 3 O 17/26", "actor": "rechtsabteilung"}
        if mutate: mutate(p)
        e = c.add("LEGAL_HOLD", p, origin="portal")
        if checkpoint: c.checkpoint()
        return e

    @staticmethod
    def delete(c, target_seq):
        """CONTENT_DELETED (4.17) of target_seq and its immediate checkpoint."""
        e = c.add("CONTENT_DELETED", {"target_seq": target_seq, "vault_ref": "vault/1", "reason": "retention",
                                      "actor": "fristenlauf"}, origin="system")
        c.checkpoint()
        return e

    @staticmethod
    def call_at(c, captured):
        """An AI_CALL whose ts_captured is exactly the string given (rehashed while it is still the last entry)."""
        e = ai_call(c)
        e["ts_captured"] = captured
        e["entry_hash"] = V.entry_hash(e)
        return e

    @staticmethod
    def violations(findings): return [x for x in findings if x["class"] == "HOLD_VIOLATION"]

    def scenario(self, captured, scope):
        """One AI_CALL captured at `captured`, one hold over `scope`, the deletion of that call: the classes seen."""
        c = Chain(OWN); t = self.call_at(c, captured); self.hold(c, "H-1", scope); self.delete(c, t["seq"]); c.close()
        return self.run_v2(c)

    def test_0_registry_file_carries_contract_1_7(self):
        lh = self.reg["event_types"]["LEGAL_HOLD"]
        self.assertIs(lh["critical_checkpoint"], True)
        self.assertEqual({k: {a: b for a, b in d.items() if a != "comment"} for k, d in lh["payload"].items()}, LEGAL_HOLD_PAYLOAD)
        fc = list(self.reg["verifier"]["finding_classes"])
        self.assertEqual(self.reg["verifier"]["finding_classes"]["HOLD_VIOLATION"]["exit"], 1)
        self.assertEqual(fc[fc.index("CONTENT_DELETED") + 1], "HOLD_VIOLATION", fc)          # 10.4 table order
        self.assertEqual(self.reg["testvectors"]["hold"], {                                   # the vectors this class models
            "hold_respected": {"exit": 1, "findings": ["CONTENT_DELETED"]},
            "hold_released": {"exit": 1, "findings": ["CONTENT_DELETED"]},
            "hold_violated": {"exit": 1, "findings": ["CONTENT_DELETED", "HOLD_VIOLATION"]}})

    def test_1_deleting_covered_content_is_hold_violation(self):
        c = Chain(OWN); t = ai_call(c); c.tick(); h = self.hold(c, "H-1"); d = self.delete(c, t["seq"]); c.tick(); c.close()
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (1, ["CONTENT_DELETED", "HOLD_VIOLATION"]), f)
        v = self.violations(f)
        self.assertEqual(len(v), 1, f)
        self.assertTrue(v[0]["detail"].startswith(f"seq={d['seq']}: deletes the content of target_seq={t['seq']} (AI_CALL"), v)
        self.assertIn(f"hold_id=H-1 ({DAY[0]} .. {DAY[1]}, set at seq={h['seq']})", v[0]["detail"])
        self.assertEqual(self.res.legal_holds, [{"hold_id": "H-1", "scope_from": DAY[0], "scope_to": DAY[1], "set_seq": h["seq"]}])

    def test_1b_a_hold_alone_is_no_finding(self):
        c = Chain(OWN); ai_call(c); self.hold(c, "H-1"); c.tick(); c.close()
        self.assertEqual(self.run_v2(c), (0, []))

    def test_2_deleting_content_outside_the_scope_is_no_violation(self):
        for scope in (YEAR_2025, ("2026-01-02T00:00:00Z", UNBOUNDED[1])):              # before and after the call
            c = Chain(OWN); t = ai_call(c); self.hold(c, "H-1", scope); self.delete(c, t["seq"]); c.close()
            code, f = self.run_v2(c)
            self.assertEqual((scope, code, self.classes(f)), (scope, 1, ["CONTENT_DELETED"]), f)
            self.assertEqual(len(self.res.legal_holds), 1)                             # the hold is active, it just does not cover

    def test_3_deleting_after_the_release_is_no_violation(self):
        # 9.3: the bounds a release repeats carry no meaning - a release with other bounds releases just the same
        for release_scope in (DAY, YEAR_2025):
            c = Chain(OWN); t = ai_call(c); self.hold(c, "H-1"); self.hold(c, "H-1", release_scope, action="release")
            self.delete(c, t["seq"]); c.close()
            code, f = self.run_v2(c)
            self.assertEqual((release_scope, code, self.classes(f)), (release_scope, 1, ["CONTENT_DELETED"]), f)
            self.assertEqual(self.res.legal_holds, [])

    def test_4_deleting_before_the_hold_is_set_is_no_violation(self):
        c = Chain(OWN); t = ai_call(c); self.delete(c, t["seq"]); h = self.hold(c, "H-1"); c.close()
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (1, ["CONTENT_DELETED"]), f)          # the position counts, not the chain end
        self.assertEqual([x["set_seq"] for x in self.res.legal_holds], [h["seq"]])      # ... where the hold is active

    def test_5_bounds_are_inclusive_and_compared_as_instants(self):
        lo, hi = "2026-01-01T00:30:00Z", "2026-01-01T00:40:00Z"
        for captured, scope, covered in (
                (lo, (lo, hi), True), (hi, (lo, hi), True),                             # exactly on either bound
                ("2026-01-01T00:29:59.999999999Z", (lo, hi), False),                    # one nanosecond before
                ("2026-01-01T00:40:00.000000001Z", (lo, hi), False),                    # one nanosecond after
                ("2026-01-01T00:30:00.000Z", (lo, hi), True),                           # the same instant, spelt otherwise:
                ("2026-01-01T00:40:00.000Z", (lo, hi), True),                           # as strings ".000Z" < "Z"
                ("2026-01-01T00:40:00Z", (lo, "2026-01-01T00:40:00.000000000Z"), True),
                ("2026-01-01T00:40:00.000000002Z", (lo, "2026-01-01T00:40:00.000000001Z"), False)):   # a float cannot tell
            with self.subTest(captured=captured, scope=scope):
                code, f = self.scenario(captured, scope)
                want = ["CONTENT_DELETED", "HOLD_VIOLATION"] if covered else ["CONTENT_DELETED"]
                self.assertEqual((code, self.classes(f)), (1, want), f)

    def test_6_unbounded_sentinels_cover_the_whole_range(self):
        for captured in (UNBOUNDED[0], "2026-01-01T00:01:00.000Z", UNBOUNDED[1]):       # the extremes themselves included
            with self.subTest(captured=captured):
                code, f = self.scenario(captured, UNBOUNDED)
                self.assertEqual((code, self.classes(f)), (1, ["CONTENT_DELETED", "HOLD_VIOLATION"]), f)
        code, f = self.scenario("2026-01-01T00:01:00.000Z", (UNBOUNDED[0], "2025-12-31T23:59:59Z"))   # open below only
        self.assertEqual((code, self.classes(f)), (1, ["CONTENT_DELETED"]), f)

    def test_7_two_covering_holds_give_one_finding_naming_both(self):
        c = Chain(OWN); t = ai_call(c)
        self.hold(c, "H-A"); self.hold(c, "H-B", UNBOUNDED); self.hold(c, "H-C", YEAR_2025)   # H-C does not cover
        d = self.delete(c, t["seq"]); c.close()
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (1, ["CONTENT_DELETED", "HOLD_VIOLATION"]), f)
        v = self.violations(f)
        self.assertEqual(len(v), 1, f)                                                  # once per CONTENT_DELETED
        self.assertTrue(v[0]["detail"].startswith(f"seq={d['seq']}: "), v)
        self.assertIn("hold_id=H-A (", v[0]["detail"])
        self.assertIn("hold_id=H-B (", v[0]["detail"])
        self.assertNotIn("H-C", v[0]["detail"])
        self.assertEqual([x["hold_id"] for x in self.res.legal_holds], ["H-A", "H-B", "H-C"])

    def test_7b_two_deletions_two_findings(self):
        c = Chain(OWN); a = ai_call(c); b = ai_call(c); self.hold(c, "H-1")
        da = self.delete(c, a["seq"]); db = self.delete(c, b["seq"]); c.close()
        code, f = self.run_v2(c)
        self.assertEqual([x["detail"].split(":")[0] for x in self.violations(f)], [f"seq={da['seq']}", f"seq={db['seq']}"], f)

    def test_8_a_further_set_replaces_the_scope(self):
        c = Chain(OWN); t = ai_call(c); self.hold(c, "H-1", DAY); r = self.hold(c, "H-1", YEAR_2025)   # narrowed away
        self.delete(c, t["seq"]); c.close()
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (1, ["CONTENT_DELETED"]), f)
        self.assertEqual(self.res.legal_holds, [{"hold_id": "H-1", "scope_from": YEAR_2025[0], "scope_to": YEAR_2025[1], "set_seq": r["seq"]}])
        c = Chain(OWN); t = ai_call(c); self.hold(c, "H-1", YEAR_2025); r = self.hold(c, "H-1", DAY)   # widened onto the call
        self.delete(c, t["seq"]); c.close()
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (1, ["CONTENT_DELETED", "HOLD_VIOLATION"]), f)
        self.assertIn(f"hold_id=H-1 ({DAY[0]} .. {DAY[1]}, set at seq={r['seq']})", self.violations(f)[0]["detail"])
        self.assertEqual(len(self.res.legal_holds), 1)                                  # still one hold, not two

    def test_9_release_of_an_unknown_hold_id_is_without_effect(self):
        c = Chain(OWN); t = ai_call(c); self.hold(c, "H-1"); self.hold(c, "H-X", action="release")   # H-1 stays active
        self.delete(c, t["seq"]); c.close()
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (1, ["CONTENT_DELETED", "HOLD_VIOLATION"]), f)
        self.assertEqual([x["hold_id"] for x in self.res.legal_holds], ["H-1"])
        c = Chain(OWN); t = ai_call(c); self.hold(c, "H-X", action="release"); self.delete(c, t["seq"]); c.close()   # no hold at all
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (1, ["CONTENT_DELETED"]), f)
        self.assertEqual(self.res.legal_holds, [])

    def test_10_target_that_is_no_ai_call_or_no_entry_gives_no_violation(self):
        c = Chain(OWN); ai_call(c); k = c.tick(); self.hold(c, "H-1", UNBOUNDED)
        self.delete(c, k["seq"]); self.delete(c, 999); c.close()                        # a TICK; a seq beyond the chain
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (1, ["CONTENT_DELETED"]), f)
        self.assertEqual(sum(x["class"] == "CONTENT_DELETED" for x in f), 2, f)

    def test_11_legal_hold_without_its_checkpoint_mid_chain_is_missing_checkpoint(self):
        for action in ("set", "release"):
            c = Chain(OWN); e = self.hold(c, "H-1", action=action, checkpoint=False); c.tick(); c.close()
            code, f = self.run_v2(c)
            self.assertEqual((action, code, self.classes(f)), (action, 2, ["MISSING_CHECKPOINT"]), f)
            self.assertTrue(f[0]["detail"].startswith(f"seq={e['seq']}: critical LEGAL_HOLD is followed by TICK"), f)
        c = Chain(OWN); c.tick(); c.anchor(); e = self.hold(c, "H-1", checkpoint=False)   # at the chain end: incomplete (8.6)
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (4, ["UNSEALED_END"]), f)
        self.assertTrue(f[0]["detail"].startswith(f"seq={e['seq']}: the chain ends with LEGAL_HOLD (critical"), f)

    def test_12_payload_is_strict(self):
        bad = {"action outside the enum": lambda p: p.__setitem__("action", "suspend"),
               "action missing": lambda p: p.pop("action"),
               "hold_id above maxlen 64": lambda p: p.__setitem__("hold_id", "h" * 65),
               "scope_from without time": lambda p: p.__setitem__("scope_from", "2026-01-01"),
               "scope_to with an offset": lambda p: p.__setitem__("scope_to", "2026-01-01T01:00:00+01:00"),
               "scope_from in year 0000": lambda p: p.__setitem__("scope_from", "0000-01-01T00:00:00Z"),
               "reference above maxlen 200": lambda p: p.__setitem__("reference", "r" * 201),
               "actor above maxlen 128": lambda p: p.__setitem__("actor", "a" * 129),
               "actor null": lambda p: p.__setitem__("actor", None),
               "undefined field": lambda p: p.__setitem__("note", "x")}
        for name, mut in bad.items():
            with self.subTest(name):
                c = Chain(OWN); self.hold(c, "H-1", mutate=mut); c.close()
                code, f = self.run_v2(c)
                self.assertEqual((code, self.classes(f)), (3, ["FORMAT_ERROR"]), f)
        c = Chain(OWN)                                                                   # control: every maxlen exactly
        self.hold(c, "h" * 64, UNBOUNDED, mutate=lambda p: p.update(reference="r" * 200, actor="a" * 128)); c.close()
        self.assertEqual(self.run_v2(c), (0, []))

    def test_13_json_names_the_holds_active_at_the_chain_end(self):
        c = Chain(OWN); t = ai_call(c); a = self.hold(c, "H-A"); self.hold(c, "H-B", YEAR_2025)
        self.hold(c, "H-B", YEAR_2025, action="release"); self.delete(c, t["seq"]); c.close()
        code, j = self.run_cli(c)
        self.assertEqual((code, j["finding_classes"]), (1, ["CONTENT_DELETED", "HOLD_VIOLATION"]), j)
        self.assertEqual(j["legal_holds"], [{"hold_id": "H-A", "scope_from": DAY[0], "scope_to": DAY[1], "set_seq": a["seq"]}])
        c = Chain(OWN); c.tick(); c.close()
        code, j = self.run_cli(c)
        self.assertEqual((code, j["legal_holds"]), (0, []))                             # judged, none active
        c = Chain("2.0"); c.close()
        code, j = self.run_cli(c)
        self.assertEqual((code, j["legal_holds"]), (3, None))                           # format error: not judged, as chain_end


def rewrite_segment(pkg, edit):
    """Replace the package's only segment by edit(bytes) and repair its SHA-256 in the manifest,
    so a verdict is about the bytes and never about a stale checksum."""
    sp = os.path.join(pkg, "segments", "chain-000001.jsonl")
    with open(sp, "rb") as fh: blob = edit(fh.read())
    with open(sp, "wb") as fh: fh.write(blob)
    mp = os.path.join(pkg, "manifest.json")
    with open(mp, encoding="utf-8") as fh: man = json.load(fh)
    man["segments"][0]["sha256"] = hashlib.sha256(blob).hexdigest()
    with open(mp, "w", encoding="utf-8") as fh: json.dump(man, fh, indent=2, sort_keys=True)


class Rohdaten(V2Case):
    """Vier Stellen, an denen die beiden Verifier dasselbe Paket verschieden beurteilten (Review vom 29.09.):
    (1) Segmente werden nur an "\\n" getrennt (10.1) - str.splitlines() brach auch an U+2028, U+2029 und U+0085,
        die die kanonische Form in Strings roh schreibt, und uebersprang Leerzeilen;
    (2) Zeitstempel nach der Grammatik aus 2/10.7 - Komma-Bruchteil und einstellige Stunde sind FORMAT_ERROR;
    (3) ein doppelter Membername in einem Eintrag oder im Manifest ist FORMAT_ERROR (2), nicht "letzter gewinnt";
    (4) GENESIS genau einmal, bei seq 1 (3) - sonst FORMAT_ERROR, Kettenende und Sperren nicht beurteilt.
    Gegen den Stand vor dem 29.09. rot in (1), (3) und (4); (2) sichert, was verifier2 schon richtig las.
    Ein Differenzlauf faehrt dieselben Eingaben durch beide Verifier.
    / Four places where the two verifiers judged the same package differently; runs against the registry file."""
    reg = file_registry()
    SEPARATORS = (("U+2028", " "), ("U+2029", " "), ("U+0085", "\u0085"))
    TENTH = ("2026-01-01T00:01:00.400Z", "2026-01-01T00:01:00.600Z")          # a hold around 00:01:00.5

    def run_edited(self, chain, segment=None, manifest=None):
        """Write the package, edit the segment bytes (SHA-256 repaired) or the manifest text, verify it."""
        self.n += 1
        pkg = chain.write(os.path.join(self.tmp, "pkg%d" % self.n))
        if segment: rewrite_segment(pkg, segment)
        if manifest:
            mp = os.path.join(pkg, "manifest.json")
            with open(mp, encoding="utf-8") as fh: text = manifest(fh.read())
            with open(mp, "w", encoding="utf-8") as fh: fh.write(text)
        self.pkg = pkg
        self.res = V.verify(pkg, self.reg, at_ms(chain.t + 3), 24.0, [], vendor_roots={}, vendor_keys=PIN)
        return V.exit_code(self.res, self.reg["verifier"]["finding_classes"]), self.res.findings

    def deletion_under_hold(self, captured, scope):
        """An AI_CALL captured at `captured`, a hold over `scope`, the deletion of that call, sealed."""
        c = Chain(OWN); t = LegalHold.call_at(c, captured); LegalHold.hold(c, "H-1", scope); LegalHold.delete(c, t["seq"]); c.close()
        return c

    # --- (1) JSON Lines: "\n" and nothing else

    def test_1_raw_line_separators_inside_a_string_are_no_line_end(self):
        for name, ch in self.SEPARATORS:
            with self.subTest(name):
                ref = "Az. 5 O" + ch + "99/26"
                c = Chain(OWN); LegalHold.hold(c, "H-1", mutate=lambda p: p.__setitem__("reference", ref)); c.close()
                code, f = self.run_edited(c)
                self.assertEqual((code, f), (0, []), f)
                with open(os.path.join(self.pkg, "segments", "chain-000001.jsonl"), "rb") as fh:
                    self.assertIn(ch.encode("utf-8"), fh.read())                     # raw in the segment, or the test proves nothing
                self.assertEqual([x["hold_id"] for x in self.res.legal_holds], ["H-1"])

    def test_1b_line_rule(self):
        for name, edit, want in (
                ("several line ends at the end", lambda b: b + b"\n\n\n", 0),
                ("CRLF line ends", lambda b: b.replace(b"\n", b"\r\n"), 0),
                ("no line end at the end", lambda b: b.rstrip(b"\n"), 0),
                ("empty line between two entries", lambda b: b.replace(b"\n", b"\n\n", 1), 3),
                ("line of blanks between two entries", lambda b: b.replace(b"\n", b"\n \n", 1), 3),
                ("empty line at the start", lambda b: b"\n" + b, 3),
                ("line of blanks at the end", lambda b: b + b" \n", 3),
                ("lone CR between two entries", lambda b: b.replace(b"\n", b"\r", 1), 3),
                ("U+2028 between two entries", lambda b: b.replace(b"\n", " ".encode(), 1), 3),
                ("U+0085 between two entries", lambda b: b.replace(b"\n", "\u0085".encode(), 1), 3)):
            with self.subTest(name):
                c = Chain(OWN); c.tick(); c.close()
                code, f = self.run_edited(c, segment=edit)
                self.assertEqual((code, self.classes(f)), (want, ["FORMAT_ERROR"] if want == 3 else []), f)

    # --- (2) timestamp grammar

    def test_2_timestamp_grammar(self):
        comma, hour = "2026-01-01T00:01:00,5Z", "2026-01-01T0:01:00Z"
        cases = {"ts_captured comma fraction": lambda c: LegalHold.call_at(c, comma),
                 "ts_captured one-digit hour": lambda c: LegalHold.call_at(c, hour),
                 "ts_captured Arabic-Indic digit": lambda c: LegalHold.call_at(c, "2026-01-01T00:01:0٣Z"),
                 "ts_captured with a final line end": lambda c: LegalHold.call_at(c, "2026-01-01T00:01:00Z\n"),
                 "scope_from comma fraction": lambda c: LegalHold.hold(c, "H-1", ("2026-01-01T00:00:00,5Z", DAY[1])),
                 "scope_from one-digit hour": lambda c: LegalHold.hold(c, "H-1", ("2026-01-01T0:00:00Z", DAY[1])),
                 "scope_to comma fraction": lambda c: LegalHold.hold(c, "H-1", (DAY[0], "2026-01-01T23:59:59,5Z")),
                 "scope_to one-digit hour": lambda c: LegalHold.hold(c, "H-1", (DAY[0], "2026-01-01T1:00:00Z"))}
        for name, build in cases.items():
            with self.subTest(name):
                c = Chain(OWN); build(c); c.close()
                code, f = self.run_v2(c)
                self.assertEqual((code, self.classes(f)), (3, ["FORMAT_ERROR"]), f)
        # the reviewer's coverage case: a hold .400 .. .600 s around a capture written ",5"; control in the grammar
        code, f = self.run_v2(self.deletion_under_hold(comma, self.TENTH))
        self.assertEqual((code, self.classes(f)), (3, ["FORMAT_ERROR"]), f)
        code, f = self.run_v2(self.deletion_under_hold("2026-01-01T00:01:00.5Z", self.TENTH))
        self.assertEqual((code, self.classes(f)), (1, ["CONTENT_DELETED", "HOLD_VIOLATION"]), f)

    def test_2b_is_ts_is_the_grammar_of_10_7(self):
        for s in ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00.1234567891Z", "0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z"):
            self.assertTrue(V._is_ts(s), s)
        for s in ("2026-01-01T00:00:00,5Z", "2026-01-01T1:00:00Z", "2026-01-01T00:00:00.Z", "2026-01-01T00:00:00+00:00",
                  "2026-01-01T00:00:00Z\n", "٢٠٢٦-01-01T00:00:00Z", "0000-01-01T00:00:00Z",
                  "2026-02-30T00:00:00Z", "2026-01-01T24:00:00Z", "2026-01-01T23:59:60Z", "", None, 20260101):
            self.assertFalse(V._is_ts(s), s)

    def test_2c_uuid_is_the_whole_string(self):
        """Type uuid (2): the whole string is the 8-4-4-4-12 form. A pattern with $ read by match() also admitted a
        final line feed, the Go verifier never did (vector format_uuid_trailing_newline)."""
        def errs(v):
            e = []
            V._check(v, {"type": "uuid"}, self.reg, "x", e, None)
            return e
        self.assertEqual(errs(CHAIN), [])
        for v in (CHAIN + "\n", CHAIN + "\r\n", "\n" + CHAIN, CHAIN + " ", CHAIN.upper(), CHAIN[:-1], CHAIN + "0", "", 1):
            self.assertEqual(errs(v), ["x: not a lowercase uuid"], repr(v))
        c = Chain(OWN); c.tick(); c.close()
        self.assertEqual(self.run_edited(c)[0], 0)                                                     # control
        code, f = self.run_edited(c, manifest=lambda s: s.replace('"chain_id": "%s"' % CHAIN, '"chain_id": "%s\\n"' % CHAIN, 1))
        self.assertEqual((code, self.classes(f)), (3, ["FORMAT_ERROR"]), f)
        self.assertIn("manifest.chain_id: not a lowercase uuid", f[0]["detail"])

        def newline_everywhere(entries):                   # every entry and its hash as the writer would chain them
            for i, e in enumerate(entries):
                e["chain_id"] = CHAIN + "\n"
                e["prev_hash"] = entries[i - 1]["entry_hash"] if i else V.ZERO
                e["entry_hash"] = V.entry_hash(e)
        code, f = self.run_v2(c, patch=newline_everywhere)
        self.assertEqual((code, self.classes(f)), (3, ["FORMAT_ERROR"]), f)
        self.assertIn("entry seq=1.chain_id: not a lowercase uuid", [x["detail"] for x in f])
        code, f = self.run_v2(c, patch=newline_everywhere, man_extra={"chain_id": CHAIN + "\n"})   # the vector: stage 1 ends it
        self.assertEqual((code, [x["detail"] for x in f]), (3, ["manifest.chain_id: not a lowercase uuid"]), f)

    # --- (3) duplicate member names

    def test_3_duplicate_member_in_a_segment_line(self):
        c = Chain(OWN); t = ai_call(c); LegalHold.hold(c, "H-1"); LegalHold.delete(c, t["seq"]); c.close()
        self.assertEqual(self.classes(self.run_edited(c)[1]), ["CONTENT_DELETED", "HOLD_VIOLATION"])   # control

        def dup(b):
            self.assertEqual(b.count(b'"payload":{"action":"set"'), 1, b)
            return b.replace(b'"payload":{"action":"set"', b'"payload":{"action":"release","action":"set"')
        code, f = self.run_edited(c, segment=dup)                                        # entry_hash fits "last wins"
        self.assertEqual((code, self.classes(f)), (3, ["FORMAT_ERROR"]), f)
        self.assertIn("duplicate member", f[0]["detail"])

    def test_3b_duplicate_member_in_the_manifest(self):
        c = Chain(OWN); c.tick(); c.close()
        stranger = '{\n  "chain_id": "00000000-0000-4000-8000-000000000000",\n  "chain_id"'   # last wins would read the real one
        code, f = self.run_edited(c, manifest=lambda s: s.replace('{\n  "chain_id"', stranger, 1))
        self.assertEqual((code, self.classes(f)), (3, ["FORMAT_ERROR"]), f)
        self.assertIn("duplicate member", f[0]["detail"])

    # --- (4) GENESIS exactly once, at seq 1

    @staticmethod
    def second_genesis(c):
        e = c.add("GENESIS", dict(c.entries[0]["payload"]))
        c.checkpoint()
        return e

    def test_4_second_genesis_is_a_format_error(self):
        c = Chain(OWN); c.tick(); g = self.second_genesis(c); c.close()
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (3, ["FORMAT_ERROR"]), f)
        self.assertTrue(f[0]["detail"].startswith(f"seq={g['seq']}: GENESIS after the first entry"), f)
        self.assertEqual((self.res.chain_end, self.res.last_countersigned, self.res.legal_holds), (None, None, None))

    def test_4b_the_run_goes_on_but_chain_end_and_holds_are_not_judged(self):
        c = Chain(OWN); t = ai_call(c); LegalHold.hold(c, "H-1"); LegalHold.delete(c, t["seq"]); self.second_genesis(c)
        c.anchor()                                                                       # not sealed: would be UNSEALED_END
        code, j = self.run_cli(c)
        self.assertEqual((code, j["finding_classes"]), (3, ["CONTENT_DELETED", "FORMAT_ERROR", "HOLD_VIOLATION"]), j)
        self.assertEqual((j["chain_end"], j["last_countersigned"], j["legal_holds"]), (None, None, None), j)

    def test_4c_first_entry_not_genesis_is_a_format_error(self):
        c = Chain(OWN); c.entries, c.prev_cp = [], V.ZERO                               # the chain opens with a TICK
        c.add("TICK", {"uptime_s": 1, "spool_backlog": 0, "disk_pct": 10}, mono=-1); c.checkpoint(); c.tick(); c.close()
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (3, ["FORMAT_ERROR", "SIG_INVALID"]), f)   # no key legitimised
        self.assertIn("seq=1: the chain starts with TICK, not GENESIS", [x["detail"] for x in f if x["class"] == "FORMAT_ERROR"])
        self.assertIsNone(self.res.chain_end)


VEKTOREN = os.path.join(HERE, "..", "spec", "testvectors")
# Identifiers that keep the old name on purpose: signed, normative format ids of the specification.
EINGEFRORENE_KENNUNGEN = ("rekorder-herstellerschluessel/1",)


def alter_name(text):
    """Occurrences of the former product name ("Rekorder", "rekorder-verify", any case), frozen ids excepted."""
    for k in EINGEFRORENE_KENNUNGEN: text = text.replace(k, "")
    return text.lower().count("rekorder")


class Produktname(unittest.TestCase):
    """A4 "Kein Pruefertext ohne LEDGER" / no auditor text without LEDGER: the text report of verifier2 in DE and
    EN for a valid, an invalid and an incomplete frozen vector names LEDGER and never the former product name
    "Rekorder"; so do --help and an error message (the latter must at least not name the old product).
    Measured over main() - the command line an auditor runs - with the audit environment of the frozen
    expectations (spec/testvectors/pruefer_*, 7.1). The package path is masked before the check: the report
    prints the path it was given, and the directory the repository sits in is no text of the verifier."""

    FAELLE = (("valid_sealed_shutdown", 0), ("tamper_rewrite", 2), ("valid_basic", 4))

    def lauf(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try: code = vmain(["verifier2", *argv])
            except SystemExit as e: code = e.code                                      # argparse: --help, bad usage
        return code, out.getvalue(), err.getvalue()

    def anker(self):
        args = ["--vendor-root", os.path.join(VEKTOREN, "pruefer_herstellerwurzel.json")]
        with open(os.path.join(VEKTOREN, "pruefer_herstellerschluessel.txt"), encoding="utf-8") as fh:
            for k in fh.read().split(): args += ["--vendor-key", k]
        return args

    def test_1_report_de_en_names_ledger(self):
        for name, soll in self.FAELLE:
            pkg = os.path.join(VEKTOREN, name)
            for lang in ("de", "en"):
                code, out, err = self.lauf(pkg, "--now-from-package", "--lang", lang, "--registry", REG_PATH, *self.anker())
                text = out.replace(pkg, "<paket>")
                with self.subTest(vektor=name, lang=lang):
                    self.assertEqual(code, soll, out + err)
                    self.assertTrue(text.startswith("LEDGER verifier2 "), text[:200])
                    self.assertIn("LEDGER", text)
                    self.assertEqual(alter_name(text + err), 0, text + err)

    def test_2_help_and_error_without_the_old_name(self):
        code, out, err = self.lauf("--help")                                         # 1.1.0: on stderr, exit 3, like ledger-verify
        self.assertEqual((code, out), (3, ""))
        self.assertIn("LEDGER verification packages", err)
        self.assertEqual(alter_name(out + err), 0, out + err)
        code, out, err = self.lauf("--version")                                      # A4: --version names LEDGER too
        self.assertEqual((code, out, err), (0, f"verifier2 {V.VERSION} (spec {file_registry()['spec_version']}) \u00b7 LEDGER\n", ""))
        code, out, err = self.lauf(os.path.join(VEKTOREN, "valid_basic"), "--vendor-key", "kaputt", "--registry", REG_PATH)
        self.assertEqual(code, 3, out + err)
        self.assertTrue(err.startswith("verifier2: "), err)
        self.assertEqual(alter_name(out + err), 0, out + err)

    def test_3_the_check_can_fail(self):
        """Red check of the check: every spelling that could come back is seen, the frozen format id passes."""
        for s in ("Rekorder: Pruefbericht", "rekorder-verify 1.0.0", "REKORDER", "des Rekorders"):
            self.assertGreater(alter_name(s), 0, s)
        self.assertEqual(alter_name("LEDGER verifier2, format rekorder-herstellerschluessel/1"), 0)


# ---------------------------------------------------------------- specification 1.9

def later(ts, ms, sub=""):
    """ts + ms whole milliseconds (negative: earlier), written with 3 fraction digits plus the extra digits `sub`."""
    t = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ") + datetime.timedelta(milliseconds=ms)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + "%03d" % (t.microsecond // 1000) + sub + "Z"


def retime(c, ts):
    """Give the chain's LAST entry the ts_chained (and ts_captured) `ts` and rehash it - while it is still the last."""
    e = c.entries[-1]
    e["ts_chained"] = e["ts_captured"] = ts
    e["entry_hash"] = V.entry_hash(e)
    if e["event_type"] == "CHECKPOINT": c.prev_cp = e["entry_hash"]
    return e


def span(a, b):
    """Milliseconds between two timestamps of the builder (3 fraction digits), counted without the verifier."""
    p = lambda s: datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ")
    return (p(b) - p(a)) // datetime.timedelta(milliseconds=1)


REQ_SALT, RESP_SALT = bytes(range(100, 132)), bytes(range(132, 164))
SALT = {"request": REQ_SALT, "response": RESP_SALT}
PLAIN = {"request": b'{"prompt":"Wie hoch ist der Zins?"}', "response": b'{"answer":"3 %"}'}


def presented_call(c, commit=("request", "response")):
    """An AI_CALL whose commitments are the real HMACs of PLAIN under the test salts (9.1); a part not in `commit`
    carries a null commitment (hash_only: both)."""
    cm = {p: hmac.new(SALT[p], PLAIN[p], hashlib.sha256).hexdigest() if p in commit else None for p in PLAIN}
    return c.add("AI_CALL", {"provider_class": "generic", "route": "default", "model": "m", "endpoint": "/v1/x",
                             "http_status": 200, "outcome": "ok", "duration_ms": 120, "request_bytes": 10, "response_bytes": 20,
                             "tokens_in": 3, "tokens_out": 4, "streamed": False, "confidence": "recorded", "source_id": None,
                             "source_ref": None, "mode": "full" if commit else "hash_only", "request_commitment": cm["request"],
                             "response_commitment": cm["response"], "vault_ref": "vault/7"}, origin="proxy")


def presentation(n, parts=("request", "response"), plain=None, **members):
    """content/<n>.* as the export writes it (10.1): the plaintexts of `parts` and the salt file for exactly these
    parts; `members` replaces members of the salt file (None drops one)."""
    salts = {"seq": n, "vault_ref": "vault/7", **{p + "_salt": SALT[p].hex() for p in parts}}
    for k, v in members.items():
        if v is None: salts.pop(k, None)
        else: salts[k] = v
    files = {f"content/{n}.{p}": dict(PLAIN, **(plain or {}))[p] for p in parts}
    files[f"content/{n}.salts.json"] = V.jcs(salts)
    return files


def corpus_names(reg, groups):
    """The vectors of these registry groups, sorted, and the expected files <group>_*.json on disk, sorted: the tests
    hold the two against each other instead of a count written here, so a vector the generator adds is run, not missed."""
    names = sorted(n for g in groups for n in reg["testvectors"][g])
    on_disk = sorted(f[:-5] for f in os.listdir(os.path.join(VEKTOREN, "expected")) if f.endswith(".json") and f.startswith(tuple(g + "_" for g in groups)))
    return names, on_disk


def vector_anchors():
    """The audit environment of the frozen expectations (spec/testvectors/pruefer_*, 7.1) as arguments."""
    args = ["--vendor-root", os.path.join(VEKTOREN, "pruefer_herstellerwurzel.json")]
    with open(os.path.join(VEKTOREN, "pruefer_herstellerschluessel.txt"), encoding="utf-8") as fh:
        for k in fh.read().split(): args += ["--vendor-key", k]
    return args


class Spec19(V2Case):
    """Shared harness of the 1.9 classes: runs against spec/registry.json as on disk."""
    reg = file_registry()

    def pkg(self, chain, **kw):
        self.n += 1
        return chain.write(os.path.join(self.tmp, "pkg%d" % self.n), **kw)

    def cli(self, *argv):
        """main() end to end with the test auditor's pinned key: (exit code, JSON or text, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = vmain(["verifier2", *argv, "--registry", REG_PATH, "--vendor-key", "vendor-1=" + pubkey(VENDOR_SEED).hex()])
        text = out.getvalue()
        return code, json.loads(text) if "--json" in argv and text else text, err.getvalue()

    def cm(self, findings): return [x for x in findings if x["class"] == "CONTENT_MISMATCH"]


class Spec19Content(Spec19):
    """Spec 1.9, 9.1 and 10.1 "Presented plaintexts": the presentation for the AI_CALL with seq n is content/<n>.salts.json
    plus content/<n>.request and/or .response; the salt file is I-JSON of exactly seq (= n), a hex64 <part>_salt for
    exactly the presented parts and an optional vault_ref. Every other file under content/ is CONTENT_MISMATCH, once per
    file - no presented file goes unchecked. Red against 1.8: verifier2 then read only the salt files and passed a
    tampered plaintext in five shapes silently (a1b, a2b, a5b, a9, a11 of the divergence map)."""

    def run_content(self, files, commit=("request", "response")):
        """A sealed chain with one presented AI_CALL; files(n, tick_seq) gives the files under content/."""
        c = Chain(OWN); t = presented_call(c, commit); k = c.tick(); c.close()
        code, f = self.run_v2(c, extra=files(t["seq"], k["seq"]))
        return code, f

    def test_1_a_presentation_that_holds_is_no_finding(self):
        for parts in (("request", "response"), ("request",), ("response",)):
            with self.subTest(parts=parts):
                self.assertEqual(self.run_content(lambda n, _k: presentation(n, parts)), (0, []))
        self.assertEqual(self.run_content(lambda n, _k: presentation(n, vault_ref=None)), (0, []))   # vault_ref is optional

    def test_2_tampered_plaintext_is_content_mismatch(self):
        code, f = self.run_content(lambda n, _k: presentation(n, plain={"request": b"anderer Klartext"}))
        self.assertEqual((code, self.classes(f)), (2, ["CONTENT_MISMATCH"]), f)
        self.assertEqual(len(f), 1, f)
        self.assertTrue(f[0]["detail"].startswith("content/3.request: the presented request commits to"), f)

    def test_3_every_shape_is_checked_once_per_file(self):
        tampered = {"request": b"anderer Klartext"}

        def without(files, *names):
            return {k: v for k, v in files.items() if k.split("/")[1] not in names}

        def renamed(files, old, new):
            return {(new if k == old else k): v for k, v in files.items()}
        dup = lambda n: V.jcs({"seq": n, "request_salt": REQ_SALT.hex(), "response_salt": RESP_SALT.hex()})[:-1] + \
            ',"request_salt":"' + "00" * 32 + '"}'
        cases = {   # name: (files(n, tick_seq), commit, the files expected to carry CONTENT_MISMATCH)
            "a1b plaintexts without a salt file": (lambda n, k: without(presentation(n, plain=tampered), f"{n}.salts.json"), None,
                                                   ["content/3.request", "content/3.response"]),
            "a2b salt file names another seq": (lambda n, k: presentation(n, plain=tampered, seq=n + 1), None,
                                                ["content/3.request", "content/3.response", "content/3.salts.json"]),
            "a5b leading zero in the name": (lambda n, k: renamed(presentation(n, plain=tampered), f"content/{n}.request", f"content/0{n}.request"),
                                             None, ["content/03.request", "content/3.response", "content/3.salts.json"]),
            "a9 salt missing for a presented part": (lambda n, k: presentation(n, plain=tampered, request_salt=None), None,
                                                     ["content/3.request", "content/3.response", "content/3.salts.json"]),
            "a11 part without a commitment": (lambda n, k: presentation(n), ("response",), ["content/3.request"]),
            "hash_only call": (lambda n, k: presentation(n), (), ["content/3.request", "content/3.response"]),
            "a3 plaintexts for a TICK": (lambda n, k: presentation(k), None, ["content/4.request", "content/4.response"]),
            "a4 lone salt file": (lambda n, k: presentation(n, parts=()), None, ["content/3.salts.json"]),
            "salt file whose plaintexts are gone": (lambda n, k: without(presentation(n), f"{n}.request", f"{n}.response"), None,
                                                    ["content/3.salts.json"]),
            "another name": (lambda n, k: dict(presentation(n), **{"content/notiz.txt": b"x"}), None, ["content/notiz.txt"]),
            "a subdirectory": (lambda n, k: dict(presentation(n), **{"content/alt/3.request": PLAIN["request"]}), None,
                               ["content/alt/3.request"]),
            "a10 member twice": (lambda n, k: dict(presentation(n), **{f"content/{n}.salts.json": dup(n)}), None,
                                 ["content/3.request", "content/3.response", "content/3.salts.json"]),
        }
        bad_salt_file = {"uppercase salt": {"request_salt": REQ_SALT.hex().upper()}, "salt with a blank": {"request_salt": REQ_SALT.hex()[:62] + " 0"},
                         "short salt": {"request_salt": REQ_SALT.hex()[:62]}, "undefined member": {"note": "x"},
                         "a8 seq as a string": {"seq": "3"}, "seq true": {"seq": True}, "a7 seq missing": {"seq": None},
                         "vault_ref not a string": {"vault_ref": 7}}
        for name, members in bad_salt_file.items():
            cases[name] = (lambda n, k, m=members: presentation(n, **m), None, ["content/3.request", "content/3.response", "content/3.salts.json"])
        for raw_name, raw in (("not an object", b"[]"), ("byte order mark", b"\xef\xbb\xbf{}"), ("not JSON", b"{")):
            cases[raw_name] = (lambda n, k, r=raw: dict(presentation(n), **{f"content/{n}.salts.json": r}), None,
                               ["content/3.request", "content/3.response", "content/3.salts.json"])
        for name, (files, commit, want) in cases.items():
            with self.subTest(name):
                code, f = self.run_content(files, commit if commit is not None else ("request", "response"))
                self.assertEqual((code, self.classes(f)), (2, ["CONTENT_MISMATCH"]), f)
                self.assertEqual(sorted(x["detail"].split(":")[0] for x in f), want, f)   # once per file, every such file

    def test_4_number_outside_the_profile_in_a_salt_file_is_a_format_error(self):
        code, f = self.run_content(lambda n, _k: dict(presentation(n), **{f"content/{n}.salts.json":
                                   presentation(n)[f"content/{n}.salts.json"].replace(f'"seq":{n}', f'"seq":{n}.0')}))
        self.assertEqual(code, 3, f)
        self.assertIn("FORMAT_ERROR", self.classes(f), f)
        self.assertIsNone(self.res.chain_end)                           # a format error leaves the chain end unjudged (8.6)

    def test_5_frozen_presentation_holds(self):
        """Frozen vectors with content/ keep their verdict: valid_basic's presentation holds, tamper_content's does not."""
        for name, want in (("valid_basic", (4, ["UNSEALED_END"])), ("tamper_content", (2, ["CONTENT_MISMATCH", "UNSEALED_END"]))):
            code, j, _ = self.cli(os.path.join(VEKTOREN, name), "--json", "--now-from-package", *vector_anchors())
            self.assertEqual((code, j["finding_classes"]), want, j)


class Spec19Numbers(Spec19):
    """Spec 1.9, Section 2 "Numbers": every JSON number in the package - entries (unknown payloads too), manifest,
    vendor key list, salt files, verify_args.json - is an integer within 2^53-1, without fraction or exponent;
    anything else is FORMAT_ERROR. Red against 1.8: json.loads took 1.0 as 1 and integers of any size."""

    def test_1_the_reader(self):
        self.assertEqual(V.jloads('{"a":[9007199254740991,-9007199254740991,0,-0]}'), {"a": [2**53 - 1, -(2**53 - 1), 0, 0]})
        for bad in ("9007199254740992", "-9007199254740992", "1.0", "1e0", "10E-1", "0.5", "NaN", "Infinity", "-Infinity",
                    '{"a":1,"a":1}', b"\xef\xbb\xbf{}"):
            with self.subTest(bad=bad), self.assertRaises(ValueError): V.jloads(bad)
        with self.assertRaises(V.NumberError): V.jloads("[1.0]")

    def test_2_entries_known_and_unknown_payloads(self):
        for n, want in ((2**53 - 1, (1, ["UNKNOWN_ENTRY_TYPE"])), (-(2**53 - 1), (1, ["UNKNOWN_ENTRY_TYPE"])),
                        (2**53, (3, ["FORMAT_ERROR"])), (-(2**53), (3, ["FORMAT_ERROR"]))):
            with self.subTest(n=n):
                c = Chain(OWN); c.add("FUTURE_NOTE", {"n": n}); c.close()
                code, f = self.run_v2(c)
                self.assertEqual((code, self.classes(f)), want, f)
        c = Chain(OWN); c.tick(); c.close()
        code, f = self.run_v2(c, patch=lambda es: es[2].__setitem__("mono_delta_ms", 2**53))
        self.assertEqual((code, self.classes(f)), (3, ["FORMAT_ERROR"]), f)

    def test_3_fraction_and_exponent_even_where_the_value_is_integral(self):
        for spelling in (b'"n":1.0}', b'"n":1e0}', b'"n":10E-1}', b'"n":1.5}'):
            with self.subTest(spelling=spelling):
                c = Chain(OWN); c.add("FUTURE_NOTE", {"n": 1}); c.close()
                pkg = self.pkg(c)
                rewrite_segment(pkg, lambda b: b.replace(b'"n":1}', spelling))   # the entry_hash still fits the canonical 1
                res = V.verify(pkg, self.reg, at_ms(c.t + 3), 24.0, [], vendor_keys=PIN)
                self.assertEqual(res.classes(), ["FORMAT_ERROR"], res.findings)

    def test_4_manifest(self):
        for name, edit in (("tree_size 3.0", lambda s: s.replace('"tree_size": 5', '"tree_size": 5.0')),
                           ("unknown field with an exponent", lambda s: s.replace('{', '{"retention_days": 1e3, ', 1))):
            with self.subTest(name):
                c = Chain(OWN); c.close()
                pkg = self.pkg(c)
                mp = os.path.join(pkg, "manifest.json")
                with open(mp) as fh: text = fh.read()
                self.assertNotEqual(edit(text), text)
                with open(mp, "w") as fh: fh.write(edit(text))
                res = V.verify(pkg, self.reg, at_ms(c.t + 3), 24.0, [], vendor_keys=PIN)
                self.assertEqual(res.classes(), ["FORMAT_ERROR"], res.findings)

    def test_5_vendor_key_list_with_or_without_a_root(self):
        liste = vendor_list([{"key_id": "vendor-1", "pubkey": pubkey(VENDOR_SEED).hex(), "gueltig_ab": "2025-01-01T00:00:00Z"}])
        root = {"wurzel-test": pubkey(ROOT_SEED).hex()}
        for roots in (root, {}):
            c = Chain(OWN); c.close()
            self.assertEqual(self.run_v2(c, roots=roots, keys={}, extra={"keys/vendor/schluesselliste.json": liste})[0],
                             0 if roots else 1)                         # control: the list as signed
            code, f = self.run_v2(c, roots=roots, keys={}, extra={"keys/vendor/schluesselliste.json": liste.replace(b'"version": 2', b'"version": 2.0')})
            self.assertEqual(code, 3, (roots, f))
            self.assertIn("FORMAT_ERROR", self.classes(f))

    def test_6_stage_4a_drops_the_chain_checks(self):
        """10.5 stage 4a: a number error in the vendor list or a salt file ends the run before stage 5 - exactly
        FORMAT_ERROR, as in the Go verifier (until 29.09. this one went on to CONTENT_MISMATCH/RECEIPT_UNVERIFIED).
        Read lexically: a member twice before the number does not hide it. A misnamed salt file is not scanned."""
        liste = vendor_list([{"key_id": "vendor-1", "pubkey": pubkey(VENDOR_SEED).hex(), "gueltig_ab": "2025-01-01T00:00:00Z"}])
        c = Chain(OWN); c.add("TICK", {"uptime_s": 1, "spool_backlog": 0, "disk_pct": 10}, mono=900000); c.close()
        code, f = self.run_v2(c, keys={})                               # control: stage 5 reports the silence
        self.assertIn("CONCEALED_SILENCE", self.classes(f))
        for extra in ({"keys/vendor/schluesselliste.json": liste.replace(b'"version": 2', b'"version": 2.0')},
                      {"keys/vendor/schluesselliste.json": liste.replace(b'"version": 2', b'"version": 2, "version": 1e0')},
                      {"content/2.salts.json": b'{"seq":2.0}'}, {"content/2.salts.json": b'{"seq":9007199254740992}'}):
            with self.subTest(extra=extra):
                code, f = self.run_v2(c, keys={}, extra=extra)
                self.assertEqual((code, self.classes(f)), (3, ["FORMAT_ERROR"]), f)
        for extra in ({"content/02.salts.json": b'{"seq":2.0}'}, {"content/2.salts.json": b'{"seq":NaN}'}):
            code, f = self.run_v2(c, keys={}, extra=extra)    # misnamed / NaN is no JSON at all (RFC 8259): 10.1, not 2
            self.assertIn("CONTENT_MISMATCH", self.classes(f)); self.assertNotIn("FORMAT_ERROR", self.classes(f))
        self.assertIsNone(V.num_scan(b'{"a":"1.5e9","b":[-0,9007199254740991,01,-],"c":"\\"}'))


class Spec19Inputs(Spec19):
    """Spec 1.9, 10.8: whatever the auditor passes is read by the package's grammar, else exit 3 (unusable invocation).
    The check time is an rfc3339 instant (never host-local time); an expected root is ROOT or TREE_SIZE:ROOT;
    verify_args.json, asked for, is exactly {"now": rfc3339} - absent or not conforming is exit 3, never the system clock."""

    def sealed(self):
        c = Chain(OWN); c.tick(); c.close(); return c

    def test_1_now_grammar(self):
        c = self.sealed(); pkg = self.pkg(c); good = iso(c.t + 3)
        for bad in (good[:19], good[:10], good.replace("T", " "), good[:19].replace("-", "").replace(":", "") + "Z",
                    "2026-W01-4T00:10:00Z", good[:16] + "Z", good[:19] + ".Z", good[:19] + ",5Z", good[:19] + "+01:00",
                    good.lower(), "0000-01-01T00:00:00Z", "2026-02-30T00:00:00Z", ""):
            with self.subTest(now=bad):
                code, out, err = self.cli(pkg, "--json", "--now", bad)
                self.assertEqual((code, out), (3, ""), err)
                self.assertIn("unusable argument: --now", err)
        for ok in (good, good[:19] + "Z", good[:19] + ".123456789123Z"):
            code, j, err = self.cli(pkg, "--json", "--now", ok)
            self.assertEqual((code, j["now_source"]), (0, "flag"), (ok, err))

    def test_2_expect_root_grammar(self):
        c = self.sealed(); pkg = self.pkg(c)
        cp = c.entries[-2]["payload"]; root = cp["merkle_root"]
        for bad in ("abc", root[:63], root + "0", " " + root, root + " ", "0:" + root, "01:" + root, "-1:" + root,
                    "x:" + root, "2:3:" + root, "%d:" % cp["tree_size"], "g" * 64):
            with self.subTest(root=bad):
                code, out, err = self.cli(pkg, "--json", "--expect-root=" + bad)
                self.assertEqual((code, out), (3, ""), err)
                self.assertIn("unusable argument: --expect-root", err)
        for ok in (root, root.upper(), "%d:%s" % (cp["tree_size"], root), "%d:%s" % (cp["tree_size"], root.upper())):
            code, j, err = self.cli(pkg, "--json", "--now", iso(c.t + 3), "--expect-root", ok)
            self.assertEqual((code, j["completeness"]), (0, {"status": "established", "up_to_tree_size": cp["tree_size"], "sources": ["auditor"]}), (ok, err))

    def test_3_verify_args_asked_for(self):
        c = self.sealed(); now = iso(c.t + 3)
        code, j, err = self.cli(self.pkg(c, extra={"verify_args.json": '{"now": "%s"}' % now}), "--json", "--now-from-package")
        self.assertEqual((code, j["now_source"]), (0, "package"), err)
        cases = {"absent": None, "blank instead of T": {"now": now.replace("T", " ")}, "offset": {"now": now[:19] + "+00:00"},
                 "no zone": {"now": now[:19]}, "a number": {"now": 1767268920}, "no now": {"jetzt": now},
                 "another member": {"now": now, "freshness": "24h"}, "empty fraction": {"now": now[:19] + ".Z"},
                 "not JSON": "{now", "now twice": '{"now": "%s", "now": "%s"}' % (now, now),
                 "a fraction": '{"now": "%s", "n": 1.0}' % now, "byte order mark": b'\xef\xbb\xbf{"now": "%s"}' % now.encode()}
        for name, content in cases.items():
            with self.subTest(name):
                extra = {} if content is None else {"verify_args.json": content if isinstance(content, (str, bytes)) else json.dumps(content)}
                code, j, err = self.cli(self.pkg(c, extra=extra), "--json", "--now-from-package")
                self.assertEqual((code, j["finding_classes"], j["now_source"]), (3, ["FORMAT_ERROR"], None), j)
                self.assertIn("verify_args.json", j["findings"][0]["detail"])

    def test_4_the_flag_wins_over_the_package(self):
        c = self.sealed()
        pkg = self.pkg(c, extra={"verify_args.json": '{"now": "2099-01-01T00:00:00Z"}'})
        code, j, _ = self.cli(pkg, "--json", "--now-from-package", "--now", iso(c.t + 3))
        self.assertEqual((code, j["now_source"], j["finding_classes"]), (0, "flag", []), j)
        code, j, _ = self.cli(pkg, "--json")                              # without the request: the system clock, file unread
        self.assertEqual((j["now_source"], j["finding_classes"]), ("system", ["TRAILING_SILENCE"]), j)


class Spec19Stages(Spec19):
    """Spec 1.9, 10.5 processing stages and 10.1 segment rules: manifest; segment table (file grammar, first_seq order,
    contiguous from 1 to tree_size >= 1); per segment present, SHA-256, line count - read only as segments/<file>;
    per line JSON, signals, schema, chain_id. Stages 1-3 end the run; signals come from every object read, never from
    a missing segment or one with a wrong SHA-256. Wrapper directory stripped; no symbolic link in a directory package."""

    def run_pkg(self, pkg, c):
        self.res = V.verify(pkg, self.reg, at_ms(c.t + 3), 24.0, [], vendor_keys=PIN)
        return V.exit_code(self.res, self.reg["verifier"]["finding_classes"]), self.res.classes()

    def edit_manifest(self, pkg, fn):
        mp = os.path.join(pkg, "manifest.json")
        with open(mp) as fh: man = json.load(fh)
        fn(man)
        with open(mp, "w") as fh: json.dump(man, fh)

    def test_1_signals_of_every_object_read_beside_a_broken_line(self):
        for name, build, signal in (("unknown type", future_note, "UNKNOWN_ENTRY_TYPE"),
                                    ("newer minor", lambda c: c.tick().__setitem__("spec_version", NEW), "SPEC_NEWER")):
            with self.subTest(name):
                c = Chain(OWN); c.tick(); build(c); c.close()             # the entry's hash is stale: stage 5 never runs
                pkg = self.pkg(c)
                rewrite_segment(pkg, lambda b: b.replace(b.split(b"\n")[1], b"{kaputt", 1))   # the checkpoint at seq 2 no longer parses
                code, cls = self.run_pkg(pkg, c)
                self.assertEqual((code, cls), (3, ["FORMAT_ERROR", signal]))

    def test_2_signal_beside_the_error_of_the_same_object(self):
        c = Chain(OWN); future_note(c); c.close()
        code, f = self.run_v2(c, patch=lambda es: es[2].__setitem__("chain_id", "00000000-0000-4000-8000-000000000000"))
        self.assertEqual((code, self.classes(f)), (3, ["FORMAT_ERROR", "UNKNOWN_ENTRY_TYPE"]), f)

    def test_3_no_line_is_read_after_a_failed_table_or_segment(self):
        edits = {"tree_size one short": lambda pkg: self.edit_manifest(pkg, lambda m: m.__setitem__("tree_size", m["tree_size"] - 1)),
                 "SHA-256 wrong": lambda pkg: self.edit_manifest(pkg, lambda m: m["segments"][0].__setitem__("sha256", "0" * 64)),
                 "segment missing": lambda pkg: os.remove(os.path.join(pkg, "segments", "chain-000001.jsonl"))}
        for name, edit in edits.items():
            with self.subTest(name):
                c = Chain(NEW); future_note(c); c.close()
                pkg = self.pkg(c, manifest_version=OWN)
                edit(pkg)
                self.assertEqual(self.run_pkg(pkg, c), (3, ["FORMAT_ERROR"]))   # neither UNKNOWN_ENTRY_TYPE nor SPEC_NEWER

    def test_4_segments_are_read_in_first_seq_order(self):
        c = Chain(OWN); c.tick(); c.tick(); c.close()
        pkg = self.pkg(c, split=(2, 4))
        self.edit_manifest(pkg, lambda m: m["segments"].reverse())
        self.assertEqual(self.run_pkg(pkg, c), (0, []))

    def test_5_the_segment_table_must_hold(self):
        def ranges(*r):
            return lambda m: [g.update(first_seq=a, last_seq=b) for g, (a, b) in zip(m["segments"], r)]
        c = Chain(OWN); c.tick(); c.tick(); c.close()
        n = len(c.entries)
        cases = {"a gap between the ranges": ranges((1, 2), (4, n)), "overlapping ranges": ranges((1, 3), (3, n)),
                 "the ranges end before tree_size": ranges((1, 3), (4, n - 1)), "not starting at 1": ranges((2, 3), (4, n)),
                 "last_seq before first_seq": ranges((1, 3), (n, 4)),
                 "line count off by one": ranges((1, 2), (3, n)),              # the files hold 1..3 and 4..n
                 "tree_size 0 without segments": lambda m: m.update(tree_size=0, segments=[]),
                 "the same segment twice": lambda m: m["segments"].insert(1, dict(m["segments"][0]))}
        for name, fn in cases.items():
            with self.subTest(name):
                pkg = self.pkg(c, split=(3,))
                self.edit_manifest(pkg, fn)
                self.assertEqual(self.run_pkg(pkg, c), (3, ["FORMAT_ERROR"]))

    def test_6_file_grammar_and_only_segments_dir(self):
        c = Chain(OWN); c.tick(); c.close()
        for name in ("../chain-000001.jsonl", "sub/chain-000001.jsonl", ".", "..", "chain 1.jsonl", "", "kette-ä.jsonl", "c" * 129):
            with self.subTest(file=name):
                pkg = self.pkg(c)
                self.edit_manifest(pkg, lambda m: m["segments"][0].__setitem__("file", name))
                self.assertEqual(self.run_pkg(pkg, c), (3, ["FORMAT_ERROR"]))
        pkg = self.pkg(c)                                                 # at the package root: no fallback any more
        os.rename(os.path.join(pkg, "segments", "chain-000001.jsonl"), os.path.join(pkg, "chain-000001.jsonl"))
        self.assertEqual(self.run_pkg(pkg, c), (3, ["FORMAT_ERROR"]))
        self.assertIn("segments/chain-000001.jsonl: segment listed in the manifest is missing", [x["detail"] for x in self.res.findings])

    def test_7_wrapper_directory_and_symbolic_links(self):
        c = Chain(OWN); c.tick(); c.close()
        self.n += 1
        outer = os.path.join(self.tmp, "huelle%d" % self.n)
        c.write(os.path.join(outer, "paket"))
        self.assertEqual(self.run_pkg(outer, c), (0, []))                # exactly one directory and nothing else
        os.makedirs(os.path.join(outer, "leer"))
        self.assertEqual(self.run_pkg(outer, c), (3, ["FORMAT_ERROR"]))  # an empty directory beside it: no wrapper
        os.rmdir(os.path.join(outer, "leer"))
        with open(os.path.join(outer, "notiz.txt"), "w") as fh: fh.write("x")
        self.assertEqual(self.run_pkg(outer, c), (3, ["FORMAT_ERROR"]))
        for kind in ("file", "directory", "dangling"):
            with self.subTest(link=kind):
                pkg = self.pkg(c)
                target = {"file": os.path.join(pkg, "manifest.json"), "directory": os.path.join(pkg, "segments"), "dangling": "/nirgends"}[kind]
                os.makedirs(os.path.join(pkg, "keys"))
                os.symlink(target, os.path.join(pkg, "keys", "verweis"))
                self.assertEqual(self.run_pkg(pkg, c), (3, ["FORMAT_ERROR"]))
                self.assertIn("symbolic link", self.res.findings[0]["detail"])

    def test_8_prefix_roots_equal_the_recursive_definition(self):
        leaves = [hashlib.sha256(bytes([i])).digest() for i in range(40)]
        self.assertEqual(list(V.prefix_roots(leaves)), [V.mth(leaves[:t]) for t in range(1, 41)])


class Spec19Time(Spec19):
    """Spec 1.9, Section 2 "Time arithmetic": the tolerance checks of 8.2, 8.5 and 9.2 count whole milliseconds -
    every instant cut after its third fraction digit, then integers compared. Red against 1.8 (float seconds)."""

    def pair(self, delta_ms, sub="", mono=None):
        """TICK a, then TICK b written delta_ms (+ sub-millisecond digits) later; sealed. mono: b's mono_delta_ms."""
        c = Chain(OWN); a = c.tick()
        c.add("TICK", {"uptime_s": 1, "spool_backlog": 0, "disk_pct": 10}, mono=delta_ms if mono is None else mono, dt=delta_ms / 1000.0)
        retime(c, later(a["ts_chained"], delta_ms, sub))
        c.close()
        return self.run_v2(c)

    def test_1_silence_boundary(self):
        self.assertEqual(self.pair(450000), (0, []))
        self.assertEqual(self.pair(450000, "999999"), (0, []))           # 450 000.999999 ms counts as 450 000
        code, f = self.pair(450001)
        self.assertEqual((code, self.classes(f)), (2, ["CONCEALED_SILENCE"]), f)

    def test_2_clock_boundary(self):
        self.assertEqual(self.pair(300000, "5", mono=0), (0, []))        # 300 000.5 ms against 0: diff 300 000
        code, f = self.pair(300001, mono=0)
        self.assertEqual((code, self.classes(f)), (2, ["CLOCK_ANOMALY"]), f)
        code, f = self.pair(-300000, "1", mono=0)                         # every instant is cut, not the difference:
        self.assertEqual((code, self.classes(f)), (0, []), f)             # -300 000 + 0.1 ms is -300 000 ...
        code, f = self.pair(-300001, "9", mono=0)
        self.assertEqual((code, self.classes(f)), (2, ["CLOCK_ANOMALY"]), f)

    def test_3_freshness_boundary(self):
        c = Chain(OWN); c.tick(); c.close()
        pkg, last = self.pkg(c), c.entries[-1]["ts_chained"]
        for now, want in ((later(last, 24 * 3600000), []), (later(last, 24 * 3600000, "999"), []),
                          (later(last, 24 * 3600000 + 1), ["TRAILING_SILENCE"])):
            with self.subTest(now=now):
                code, j, _ = self.cli(pkg, "--json", "--now", now)
                self.assertEqual(j["finding_classes"], want, j)

    def test_4_gap_bounds(self):
        for start_ms, sub, want in ((450000, "999", (1, ["COVERED_GAP"])), (450001, "", (2, ["CONCEALED_SILENCE", "COVERED_GAP"]))):
            with self.subTest(start=start_ms):
                c = Chain(OWN); a = c.tick()
                c.add("GAP", {"reason": "power_loss", "started_ts": later(a["ts_chained"], start_ms, sub),
                              "ended_ts": later(a["ts_chained"], 600000), "lost_count": -1, "detail": None}, mono=600000)
                c.checkpoint(); c.close()
                code, f = self.run_v2(c)
                self.assertEqual((code, self.classes(f)), want, f)


def oversight(c):
    return c.add("OVERSIGHT", {"action": "approval", "user": "pruefer", "role": "aufsicht", "reference": "seq 3",
                               "justification": "freigegeben"}, origin="portal")


class Spec19Silence(Spec19):
    """Spec 1.9, 8.2 condition 3 (second half) and condition 4: a crash between a critical entry and its immediate
    checkpoint. Covered only if all four parts hold: (a) a critical, not SEAL, b its CHECKPOINT; (b) mono_delta_ms(b)
    = -1; (c) then a RESTART at most 450 000 ms after b with downtime -1 or >= silence - 450 000; (d) then a GAP whose
    window covers the silence. SEAL, late checkpoint (mono -1), the RESUME continuing it: covered (condition 3).
    Red against 1.8: both shapes were CONCEALED_SILENCE."""
    SILENCE = 600000

    def scenario(self, first=oversight, mono=-1, restart=True, restart_after=0, downtime=-1, gap=True,
                 gap_start=0, gap_end=0, between=False):
        c = Chain(OWN); c.tick(); c.anchor()
        a = first(c)
        b = c.checkpoint(mono=mono, dt=self.SILENCE / 1000.0)            # written late, at restart
        self.assertEqual(span(a["ts_chained"], b["ts_chained"]), self.SILENCE)
        if restart:
            c.add("RESTART", {"reason": "crash_recovery", "downtime_ms_estimate": downtime, "version": "1.2.3"}, mono=restart_after)
            retime(c, later(b["ts_chained"], restart_after))            # to the millisecond: iso() writes whole seconds
        if between: c.tick()
        if gap:
            c.add("GAP", {"reason": "power_loss", "started_ts": later(a["ts_chained"], gap_start), "ended_ts": later(b["ts_chained"], gap_end),
                          "lost_count": -1, "detail": None}, mono=0)
            c.checkpoint()
        c.close()
        return self.run_v2(c)

    def test_1_covered(self):
        code, f = self.scenario()
        self.assertEqual((code, self.classes(f)), (1, ["COVERED_GAP"]), f)
        for name, kw in (("downtime exactly silence - 450 000", {"downtime": self.SILENCE - 450000}),
                         ("RESTART exactly 450 000 ms after b", {"restart_after": 450000}),
                         ("GAP bounds exactly on the tolerance", {"gap_start": 450000, "gap_end": -450000})):
            with self.subTest(name):
                code, f = self.scenario(**kw)
                self.assertEqual((code, self.classes(f)), (1, ["COVERED_GAP"]), f)
        def deletion(c):
            t = ai_call(c); c.checkpoint()
            return c.add("CONTENT_DELETED", {"target_seq": t["seq"], "vault_ref": "vault/1", "reason": "retention", "actor": "fristenlauf"})
        code, f = self.scenario(first=deletion)                           # the deletion stays in sight
        self.assertEqual((code, self.classes(f)), (1, ["CONTENT_DELETED", "COVERED_GAP"]), f)

    def test_2_each_part_failing_is_concealed_silence(self):
        cases = {"(a) a is no critical entry": {"first": lambda c: c.tick()},
                 "(a) a is a SEAL": {"first": lambda c: c.add("SEAL", {"version": "1.0.0", "reason": "update"})},
                 "(b) stalled writer, mono >= 0": {"mono": self.SILENCE},
                 "(c) no RESTART": {"restart": False},
                 "(c) RESTART 450 001 ms after b": {"restart_after": 450001},
                 "(c) downtime 0, as written before 1.9": {"downtime": 0},
                 "(c) downtime one short": {"downtime": self.SILENCE - 450001},
                 "(d) no GAP": {"gap": False},
                 "(d) GAP not right after the RESTART": {"between": True},
                 "(d) GAP starts 1 ms late": {"gap_start": 450001},
                 "(d) GAP ends 1 ms early": {"gap_end": -450001}}
        for name, kw in cases.items():
            with self.subTest(name):
                code, f = self.scenario(**kw)
                self.assertEqual(code, 2, f)
                self.assertIn("CONCEALED_SILENCE", self.classes(f), f)
                self.assertNotIn("CLOCK_ANOMALY", self.classes(f), f)     # only the silence rule speaks
        code, f = self.scenario(mono=self.SILENCE)
        self.assertEqual(self.classes(f), ["CONCEALED_SILENCE", "COVERED_GAP"], f)

    def seal_scenario(self, mono=-1, resume_hash=None, reason="update"):
        c = Chain(OWN); c.tick(); c.anchor()
        seal = c.add("SEAL", {"version": "1.0.0", "reason": reason})
        c.checkpoint(mono=mono, dt=self.SILENCE / 1000.0)                 # the seal's checkpoint, written late at restart
        c.add("RESUME", {"prev_version": "1.0.0", "new_version": "1.1.0", "sealed_entry_hash": resume_hash or seal["entry_hash"]}, mono=0)
        c.checkpoint(); c.tick(); c.close()
        return self.run_v2(c)

    def test_3_bare_seal_variant(self):
        for reason in ("update", "export"):
            self.assertEqual(self.seal_scenario(reason=reason), (0, []))
        code, f = self.seal_scenario(mono=self.SILENCE)
        self.assertEqual((code, self.classes(f)), (2, ["CONCEALED_SILENCE"]), f)
        code, f = self.seal_scenario(resume_hash="ab" * 32)               # a RESUME that continues another SEAL covers nothing
        self.assertEqual((code, self.classes(f)), (2, ["CONCEALED_SILENCE", "HANDOVER_BROKEN"]), f)

    def test_4_covered_helper_keeps_its_call_shape(self):
        """Callers outside this module call _covered(a, b, entries, i, ta, tb) on stubs without crit; that shape stays."""
        ents = [{"event_type": t, "entry_hash": "%064x" % (k + 1)} for k, t in enumerate(("SEAL", "CHECKPOINT", "RESUME"))]
        ents[2]["payload"] = {"sealed_entry_hash": ents[0]["entry_hash"]}
        self.assertIs(V._covered(ents[1], ents[2], ents, 2, 0, 1000000), True)
        self.assertIs(V._covered(ents[0], ents[2], [ents[0], ents[2]], 1, 0, 1000000), False)


class Spec19ExportSeal(Spec19):
    """Spec 1.9, 4.10, 8.4, 8.6: SEAL reason export. A package ending with SEAL(export), its immediate checkpoint and at
    most receipts on exactly that checkpoint is sealed (exit 0); in the chain the export seal is an ordinary handover."""

    def test_0_registry_carries_the_reason(self):
        self.assertIn("export", self.reg["event_types"]["SEAL"]["payload"]["reason"]["values"])

    def test_1_export_seal_at_the_end_is_sealed(self):
        c = Chain(OWN); c.tick(); c.close("export")
        self.assertEqual(self.run_v2(c), (0, []))
        self.assertEqual((self.res.chain_end["status"], self.res.chain_end["seal_reason"]), ("sealed", "export"))
        c = Chain(OWN); c.tick(); c.anchor(); c.seal("export")          # without a receipt on the seal checkpoint
        self.assertEqual(self.run_v2(c), (0, []))

    def test_2_export_handover_mid_chain_is_regular(self):
        c = Chain(OWN); c.tick(); c.anchor(); seal = c.seal("export")
        cut = len(c.entries)
        c.add("RESUME", {"prev_version": "1.0.0", "new_version": "1.0.0", "sealed_entry_hash": seal["entry_hash"]}, mono=0)
        c.checkpoint(); c.tick(); later_cp = c.anchor(); c.close()
        self.assertEqual(self.run_v2(c), (0, []))
        def the_package(es): del es[cut:]                                 # the verification package of that export
        self.assertEqual(self.run_v2(c, patch=the_package), (0, []))
        want = (later_cp["payload"]["tree_size"], later_cp["payload"]["merkle_root"])
        code, f = self.run_v2(c, patch=the_package, expect=[want])       # a root countersigned after the request
        self.assertEqual((code, self.classes(f)), (2, ["MERKLE_INCONSISTENT"]), f)

    def test_3_seal_then_other_entry_stays_handover_broken(self):
        c = Chain(OWN); c.anchor(); c.seal("export"); c.tick()
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (2, ["HANDOVER_BROKEN", "UNSEALED_END"]), f)


class Spec19Completeness(Spec19):
    """Spec 1.9, 8.6 "What the verifier says about completeness": for every package that is no format error the
    verifier says that without a root countersigned by the vendor no statement about completeness is possible and
    asks for it (chain_id, --expect-root); with an expected root passed and found, up to which tree_size it holds."""

    def test_1_without_a_root_not_established(self):
        for close in (True, False):
            c = Chain(OWN); c.tick(); c.anchor()
            if close: c.close()
            pkg = self.pkg(c)
            code, j, _ = self.cli(pkg, "--json", "--now", iso(c.t + 3))
            self.assertEqual(j["completeness"], {"status": "not_established", "up_to_tree_size": None, "sources": []}, j)   # sources from 1.10
            for lang, words in (("en", ("completeness: not established", "chain_id " + CHAIN, "BEFORE this package was requested",
                                        "--expect-root TREE_SIZE:ROOT")),
                                ("de", ("Vollständigkeit: nicht belegt", "chain_id " + CHAIN, "VOR der Anforderung dieses Pakets",
                                        "--expect-root TREE_SIZE:ROOT"))):
                code, txt, _ = self.cli(pkg, "--lang", lang, "--now", iso(c.t + 3))
                line = [x for x in txt.splitlines() if x.startswith(words[0])]
                self.assertEqual(len(line), 1, txt)
                for w in words: self.assertIn(w, line[0])

    def test_2_found_roots_establish_up_to_the_largest(self):
        c = Chain(OWN); c.tick(); a = c.anchor(); c.tick(); b = c.anchor(); c.close()
        ra, rb = [(x["payload"]["tree_size"], x["payload"]["merkle_root"]) for x in (a, b)]
        self.run_v2(c, expect=[ra])
        self.assertEqual(self.res.completeness, {"status": "established", "up_to_tree_size": ra[0], "sources": ["auditor"]})
        self.run_v2(c, expect=[rb, ra, (None, ra[1])])
        self.assertEqual(self.res.completeness, {"status": "established", "up_to_tree_size": rb[0], "sources": ["auditor"]})
        self.run_v2(c, expect=[(None, rb[1])])                            # without tree_size: the prefix it matched
        self.assertEqual(self.res.completeness, {"status": "established", "up_to_tree_size": rb[0], "sources": ["auditor"]})
        code, txt, _ = self.cli(self.pkg(c), "--lang", "en", "--now", iso(c.t + 3), "--expect-root", rb[1])
        self.assertIn("completeness: established up to tree_size %d by the expected roots found (sources: auditor input) (8.6)" % rb[0], txt.splitlines())

    def test_3_roots_not_found(self):
        c = Chain(OWN); c.tick(); a = c.anchor(); c.close()
        n, root = len(c.entries), a["payload"]["merkle_root"]
        for name, exp in (("beyond the entries", (n + 1, root)), ("other root at that size", (a["payload"]["tree_size"], "ab" * 32)),
                          ("no prefix has that root", (None, "ab" * 32))):
            with self.subTest(name):
                code, f = self.run_v2(c, expect=[exp])
                self.assertEqual((code, self.classes(f)), (2, ["MERKLE_INCONSISTENT"]), f)
                self.assertEqual(self.res.completeness["status"], "not_established")

    def test_4_a_found_root_is_an_anchor(self):
        c = Chain(OWN); c.tick(); c.seal()                                # no receipt at all
        code, f = self.run_v2(c)
        self.assertEqual((code, self.classes(f)), (1, ["NO_ANCHOR"]), f)
        root = c.entries[-1]["payload"]["merkle_root"]
        self.assertEqual(self.run_v2(c, expect=[(None, root)]), (0, []))
        code, f = self.run_v2(c, expect=[(None, "ab" * 32)])              # one not found anchors nothing
        self.assertEqual((code, self.classes(f)), (2, ["MERKLE_INCONSISTENT", "NO_ANCHOR"]), f)

    def test_5_not_stated_for_a_format_error(self):
        c = Chain("2.0"); c.close()
        code, j, _ = self.cli(self.pkg(c), "--json", "--now", iso(c.t + 3))
        self.assertEqual((code, j["completeness"], j["residual_window"]), (3, None, None), j)
        code, txt, _ = self.cli(self.pkg(c), "--lang", "en", "--now", iso(c.t + 3))
        self.assertNotIn("completeness", txt)
        self.assertNotIn("residual window", txt)

    def test_6_unsealed_end_asks_for_the_root_before_the_request(self):
        c = Chain(OWN); c.tick(); c.anchor()
        code, f = self.run_v2(c)
        # decision 1 of 02.10.: a full statement only with the anchor history and --expect-root
        self.assertIn("anchor history for chain_id %s (heartbeat spec 9.7)" % CHAIN, f[0]["detail"])
        self.assertIn("every root in it recorded before this package was requested, at least the most recent countersigned one", f[0]["detail"])


def admin(c, message_type="anchor"):
    body = '{"tree_size":1}'
    return c.add("ADMIN", {"message_type": message_type, "payload_canonical": body,
                           "payload_hash": hashlib.sha256(body.encode()).hexdigest()}, mono=1000)


class Spec19ResidualWindow(Spec19):
    """Spec 1.9, 11.2: the residual window measured and stated for every package that is no format error - T (tree_size
    of the last countersigned checkpoint, 8.6; 0 without one), seq T+1..N, N-T entries, ts_chained of seq T and N, the
    span in whole ms, the ADMIN anchor messages after that checkpoint's receipt, and whether it exceeds the cadence
    (T = 0 or a span above 450 000 ms). No finding, no effect on the exit code."""

    def test_1_measured_after_the_last_countersigned_checkpoint(self):
        c = Chain(OWN); c.tick(); cp = c.anchor(); c.tick(); c.tick()
        code, f = self.run_v2(c)
        T, es = cp["payload"]["tree_size"], c.entries
        self.assertEqual(self.res.residual_window, {"after_tree_size": T, "first_seq": T + 1, "last_seq": len(es), "entries": len(es) - T,
                                                    "from_ts": es[T - 1]["ts_chained"], "to_ts": es[-1]["ts_chained"],
                                                    "span_ms": span(es[T - 1]["ts_chained"], es[-1]["ts_chained"]),
                                                    "unanswered_anchor_messages": 0, "beyond_cadence": False})
        self.assertEqual((code, self.classes(f)), (4, ["UNSEALED_END"]), f)     # no finding of its own

    def test_2_without_a_countersigned_checkpoint(self):
        c = Chain(OWN); c.tick(); admin(c); c.tick(); admin(c, "heartbeat"); admin(c); c.seal()
        self.run_v2(c)
        self.assertEqual(self.res.residual_window, {"after_tree_size": 0, "first_seq": 1, "last_seq": len(c.entries), "entries": len(c.entries),
                                                    "from_ts": None, "to_ts": c.entries[-1]["ts_chained"], "span_ms": None,
                                                    "unanswered_anchor_messages": 2, "beyond_cadence": True})

    def test_3_anchor_messages_after_the_receipt(self):
        c = Chain(OWN); admin(c); cp = c.checkpoint(); admin(c); c.receipt(cp); admin(c); admin(c, "activation"); admin(c)
        self.run_v2(c)
        self.assertEqual(self.res.residual_window["unanswered_anchor_messages"], 2)   # the one before the receipt is answered

    def test_4_cadence_boundary(self):
        for extra, beyond in ((0, False), (1, True)):
            c = Chain(OWN); c.tick(); cp = c.anchor()
            T = cp["payload"]["tree_size"]
            c.add("TICK", {"uptime_s": 1, "spool_backlog": 0, "disk_pct": 10}, mono=449000)
            retime(c, later(c.entries[T - 1]["ts_chained"], 450000 + extra))
            self.run_v2(c)
            self.assertEqual((self.res.residual_window["span_ms"], self.res.residual_window["beyond_cadence"]), (450000 + extra, beyond))

    def test_5_beyond_the_cadence_is_no_finding_and_names_the_causes(self):
        c = Chain(OWN); c.tick(); c.anchor()
        for _ in range(8): c.tick()
        c.seal()
        self.assertEqual(self.run_v2(c), (0, []))
        self.assertIs(self.res.residual_window["beyond_cadence"], True)
        for lang, head, causes in (("en", "residual window (11.2): ", "licence lapse, egress off, vendor unreachable, old export"),
                                   ("de", "Restfenster (11.2): ", "Lizenzablauf, Egress aus, Hersteller nicht erreichbar, alter Export")):
            text = V.render(self.res, 0, self.reg["verifier"]["finding_classes"], lang, "p")
            line = [x for x in text.splitlines() if x.startswith(head)]
            self.assertEqual(len(line), 1, text)
            w = self.res.residual_window
            for part in ("seq %d..%d" % (w["first_seq"], w["last_seq"]), "%d ms" % w["span_ms"], w["from_ts"], w["to_ts"], causes):
                self.assertIn(part, line[0])
        c = Chain(OWN); c.tick(); c.close()                               # within the cadence: no causes named
        self.run_v2(c)
        self.assertNotIn("licence lapse", V.render(self.res, 0, self.reg["verifier"]["finding_classes"], "en", "p"))

    def test_6_frozen_vectors(self):
        for name, want in (("valid_basic", {"after_tree_size": 309, "first_seq": 310, "last_seq": 311, "entries": 2, "span_ms": 1000,
                                            "beyond_cadence": False, "unanswered_anchor_messages": 0}),
                           ("valid_no_anchor", {"after_tree_size": 0, "first_seq": 1, "last_seq": 16, "entries": 16, "from_ts": None,
                                                "span_ms": None, "beyond_cadence": True})):
            code, j, _ = self.cli(os.path.join(VEKTOREN, name), "--json", "--now-from-package", *vector_anchors())
            self.assertEqual({k: j["residual_window"][k] for k in want}, want, j)
        code, j, _ = self.cli(os.path.join(VEKTOREN, "format_broken_json"), "--json", "--now-from-package", *vector_anchors())
        self.assertEqual((code, j["residual_window"], j["completeness"]), (3, None, None))


class Spec110CoveredStretches(Spec19):
    """Spec 1.10, 11.2 (request of 2026-10-03): between two consecutive countersigned checkpoints T1 < T2 more than the
    cadence (ts_chained at T1 and T2 over 450 000 ms) is a covered stretch - seq T1+1..T2, both ts_chained, the span,
    the ADMIN anchor messages in it after the receipt of T1, and the receipt of T2 that covers it. No finding, no effect
    on the exit code; [] without a stretch, None for a format error. The same cases as the Go verifier's
    gedeckte_strecken_test.go."""

    def renewal(self):
        """T1 = 1 countersigned at once (receipt at seq 4; the anchor at seq 3 is the one it answers), a lapse with two
        unanswered anchors (seq 5 and 14) and eight minutes of ticks, then T2 = 14 countersigned again (receipt at 17)."""
        c = Chain(OWN); cp1 = c.entries[1]
        admin(c); c.receipt(cp1); admin(c)
        for _ in range(8): c.tick()
        admin(c); cp2 = c.checkpoint(); admin(c); c.receipt(cp2)
        return c

    def test_1_renewal_after_a_lapse(self):
        c = self.renewal(); es = c.entries
        code, f = self.run_v2(c)
        self.assertEqual(self.res.unanchored_stretches, [{
            "after_tree_size": 1, "first_seq": 2, "last_seq": 14, "from_ts": es[0]["ts_chained"], "to_ts": es[13]["ts_chained"],
            "span_ms": span(es[0]["ts_chained"], es[13]["ts_chained"]), "unanswered_anchor_messages": 2,
            "receipt_seq": 17, "receipt_server_ts": es[16]["payload"]["server_ts"]}])
        self.assertGreater(self.res.unanchored_stretches[0]["span_ms"], 450000)
        self.assertEqual((code, self.classes(f)), (4, ["UNSEALED_END"]), f)     # no finding of its own

    def test_2_within_the_cadence_an_empty_list(self):
        c = Chain(OWN)
        for _ in range(3): c.tick(); c.tick(); c.anchor()
        c.close()
        self.assertEqual(self.run_v2(c), (0, []))
        self.assertEqual(self.res.unanchored_stretches, [])

    def test_3_cadence_boundary(self):
        for extra, n in ((0, 0), (1, 1)):
            c = Chain(OWN); c.tick(); cp1 = c.anchor()
            T1 = cp1["payload"]["tree_size"]
            c.add("TICK", {"uptime_s": 1, "spool_backlog": 0, "disk_pct": 10}, mono=449000)
            retime(c, later(c.entries[T1 - 1]["ts_chained"], 450000 + extra))
            c.anchor()
            self.run_v2(c)
            self.assertEqual(len(self.res.unanchored_stretches), n, self.res.unanchored_stretches)
            if n:
                u = self.res.unanchored_stretches[0]
                self.assertEqual((u["span_ms"], u["after_tree_size"], u["last_seq"], u["unanswered_anchor_messages"]), (450001, T1, T1 + 3, 0))

    def test_4_two_stretches(self):
        c = Chain(OWN); c.receipt(c.entries[1])                      # T = 1
        for _ in range(10): c.tick()
        c.anchor()                                                    # T = 13, ten minutes later
        c.tick(); c.anchor()                                          # T = 16, one minute later: within the cadence
        admin(c)
        for _ in range(20): c.tick()
        c.anchor()                                                    # T = 39
        self.run_v2(c)
        self.assertEqual([(u["after_tree_size"], u["last_seq"], u["unanswered_anchor_messages"]) for u in self.res.unanchored_stretches],
                         [(1, 13, 0), (16, 39, 1)])

    def test_5_second_receipt_for_the_same_tree_size_the_first_counts(self):
        c = Chain(OWN); c.receipt(c.entries[1])
        for _ in range(10): c.tick()
        cp = c.anchor(); c.receipt(cp)
        self.run_v2(c)
        self.assertEqual([u["receipt_seq"] for u in self.res.unanchored_stretches], [cp["seq"] + 1])

    def test_6_an_invalid_receipt_countersigns_nothing(self):
        c = Chain(OWN); c.receipt(c.entries[1])
        for _ in range(10): c.tick()
        cp = c.checkpoint()
        bad = dict(cp, payload=dict(cp["payload"], merkle_root="ab" * 32))   # a root that matches no prefix
        c.receipt(bad)
        code, f = self.run_v2(c)
        self.assertIn("FORK_DETECTED", self.classes(f))
        self.assertEqual(self.res.unanchored_stretches, [])

    def test_7_text_and_json(self):
        c = self.renewal()
        self.run_v2(c)
        u = self.res.unanchored_stretches[0]
        for lang, head in (("en", "stretch without countersignature (11.2): "), ("de", "Strecke ohne Gegenzeichnung (11.2): ")):
            text = V.render(self.res, 4, self.reg["verifier"]["finding_classes"], lang, "p")
            line = [x for x in text.splitlines() if x.startswith(head)]
            self.assertEqual(len(line), 1, text)
            for part in ("seq %d..%d" % (u["first_seq"], u["last_seq"]), "%d ms" % u["span_ms"], u["from_ts"], u["to_ts"],
                         "seq %d (server_ts %s)" % (u["receipt_seq"], u["receipt_server_ts"])):
                self.assertIn(part, line[0])
        code, j, _ = self.cli(self.pkg(c), "--json")
        self.assertEqual(j["unanchored_stretches"], self.res.unanchored_stretches)
        self.assertEqual(sorted(j["unanchored_stretches"][0]), sorted(["after_tree_size", "first_seq", "last_seq", "from_ts", "to_ts", "span_ms",
                                                                         "unanswered_anchor_messages", "receipt_seq", "receipt_server_ts"]))

    def test_8_not_stated_for_a_format_error(self):
        code, j, _ = self.cli(os.path.join(VEKTOREN, "format_broken_json"), "--json", "--now-from-package", *vector_anchors())
        self.assertEqual((code, j["unanchored_stretches"]), (3, None))
        # valid_basic anchors once an hour: every hour between two receipts is a stretch in the sense of 11.2
        code, j, _ = self.cli(os.path.join(VEKTOREN, "valid_basic"), "--json", "--now-from-package", *vector_anchors())
        u = j["unanchored_stretches"]
        self.assertEqual((len(u), {x["span_ms"] for x in u}), (11, {3600000}), u)
        self.assertEqual([x["after_tree_size"] for x in u[1:]], [x["last_seq"] for x in u[:-1]])   # consecutive: T2 of one is T1 of the next


# ---------------------------------------------------------------- time witness: CMS and certificate chain (7.3 steps 5, 6)
# Test tokens are made here, from test keys derived in code (RSA primes found from a label, EC scalars and Ed25519
# seeds hashed from one): no key material lies in the repository. DER is written by hand, so the parser under test
# is held against bytes it did not produce; the frozen vector and its OpenSSL-made token stand beside them.

PROBE = os.path.join(VEKTOREN, "valid_time_anchor", "keys", "tsa", "probestelle.pem")
P256, P384, P521 = "1.2.840.10045.3.1.7", "1.3.132.0.34", "1.3.132.0.35"
SERVER_AUTH = "1.3.6.1.5.5.7.3.1"


def _tl(tag, *parts):
    c = b"".join(parts)
    n = len(c)
    return bytes([tag]) + (bytes([n]) if n < 0x80 else bytes([0x80 | (n.bit_length() + 7) // 8]) + n.to_bytes((n.bit_length() + 7) // 8, "big")) + c


def _seq(*p): return _tl(0x30, *p)
def _set(*p): return _tl(0x31, *p)
def _int(n): return _tl(0x02, n.to_bytes(n.bit_length() // 8 + 1, "big", signed=True))
def _alg(o, par=b""): return _seq(_oid(o), par)
def _time(s): return _tl(0x17, s[2:].encode()) if s < "2050" else _tl(0x18, s.encode())    # YYYYMMDDhhmmssZ (RFC 5280 4.1.2.5)
def _name(cn): return _seq(_set(_seq(_oid("2.5.4.10"), _tl(0x0c, b"Probe"))), _set(_seq(_oid("2.5.4.3"), _tl(0x0c, cn.encode()))))
def _ext(o, value, crit=True): return _seq(_oid(o), _tl(0x01, b"\xff") if crit else b"", _tl(0x04, value))
def pem(*ders): return "".join("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n" % base64.encodebytes(d).decode().strip() for d in ders)


def _oid(s):
    if isinstance(s, bytes): return _tl(0x06, s)                        # the content as written
    a, out = [int(x) for x in s.split(".")], b""
    for v in [40 * a[0] + a[1]] + a[2:]:
        enc = bytes([v & 0x7f]); v >>= 7
        while v: enc, v = bytes([0x80 | v & 0x7f]) + enc, v >> 7
        out += enc
    return _tl(0x06, out)


_SMALL = [p for p in range(3, 3000, 2) if all(p % q for q in range(3, int(p ** 0.5) + 1, 2))]


def _probable_prime(n):
    if any(n % p == 0 for p in _SMALL): return False
    d, s = n - 1, 0
    while not d & 1: d, s = d >> 1, s + 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41):
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1: break
        else: return False
    return True


def _prime(label, bits=1024):
    """The first prime >= a SHAKE-256 value of label with both top bits set and p-1 prime to 65537: deterministic."""
    n = int.from_bytes(hashlib.shake_256(label).digest(bits // 8), "big") | 3 << bits - 2 | 1
    while n % 65537 == 1 or not _probable_prime(n): n += 2
    return n


_HN = {"256": V.H256, "384": V.H384, "512": V.H512}
_RSA_OID = {V.H256: "1.2.840.113549.1.1.11", V.H384: "1.2.840.113549.1.1.12", V.H512: "1.2.840.113549.1.1.13"}
_EC_OID = {V.H256: "1.2.840.10045.4.3.2", V.H384: "1.2.840.10045.4.3.3", V.H512: "1.2.840.10045.4.3.4"}


class TKey:
    """A test signing key from a label: rsa (2048 bits), ec (on curve), ed (Ed25519)."""
    _cache = {}

    def __new__(cls, kind, label, curve=P256):
        k = (kind, label, curve)
        if k not in cls._cache:
            self = cls._cache[k] = super().__new__(cls)
            self.kind, self.curve = kind, curve
            if kind == "rsa":
                p, q = _prime(label + b"/p"), _prime(label + b"/q")
                self.n, self.e, self.pq = p * q, 65537, (p, q)
                self.d = pow(65537, -1, (p - 1) * (q - 1))
            elif kind == "ec":
                P, _b, gx, gy, n = V.CURVES[curve]
                self.d = int.from_bytes(hashlib.sha512(label).digest(), "big") % (n - 1) + 1
                self.Q = V._ec_lin(self.d, (gx, gy), 0, (gx, gy), P)
            else: self.ed = hashlib.sha256(label).digest()
        return cls._cache[k]

    def spki(self):
        if self.kind == "rsa": return _seq(_alg(V.RSA_KEY, b"\x05\x00"), _tl(0x03, b"\x00" + _seq(_int(self.n), _int(self.e))))
        if self.kind == "ec":
            L = (V.CURVES[self.curve][0].bit_length() + 7) // 8
            return _seq(_alg(V.EC_KEY, _oid(self.curve)), _tl(0x03, b"\x00\x04" + self.Q[0].to_bytes(L, "big") + self.Q[1].to_bytes(L, "big")))
        return _seq(_alg(V.ED25519), _tl(0x03, b"\x00" + pubkey(self.ed)))

    def _rsa(self, em):                                                  # m^d mod n by the CRT
        (p, q), m = self.pq, int.from_bytes(em, "big")
        a, b = pow(m, self.d % (p - 1), p), pow(m, self.d % (q - 1), q)
        return (b + q * ((a - b) * pow(q, -1, p) % p)).to_bytes((self.n.bit_length() + 7) // 8, "big")

    def sign(self, msg, alg):
        """(AlgorithmIdentifier, signature) over msg: alg rsa256|384|512 (PKCS#1 v1.5), pss256|384|512 (salt = hash length),
        ec256|384|512 (ECDSA, k derived from the key and msg), ed (Ed25519)."""
        h = _HN.get(alg[-3:])
        if alg.startswith("rsa"):
            t, k = V._DIGEST_INFO[h] + V.SHA2[h](msg).digest(), (self.n.bit_length() + 7) // 8
            return _alg(_RSA_OID[h], b"\x05\x00"), self._rsa(b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t)
        if alg.startswith("pss"):
            H = V.SHA2[h]; hl, bits = H().digest_size, self.n.bit_length() - 1; el = (bits + 7) // 8
            salt = H(b"salt" + msg).digest()
            hh = H(bytes(8) + H(msg).digest() + salt).digest()
            db = bytes(el - 2 * hl - 2) + b"\x01" + salt
            mask = b"".join(H(hh + c.to_bytes(4, "big")).digest() for c in range(len(db) // hl + 1))[:len(db)]
            masked = bytes(a ^ b for a, b in zip(db, mask))
            em = bytes([masked[0] & 0xff >> (8 * el - bits)]) + masked[1:] + hh + b"\xbc"
            return _alg(V.PSS, _seq(_tl(0xa0, _alg(h)), _tl(0xa1, _alg("1.2.840.113549.1.1.8", _alg(h))), _tl(0xa2, _int(hl)))), self._rsa(em)
        if alg.startswith("ec"):
            P, _b, gx, gy, n = V.CURVES[self.curve]
            dg = V.SHA2[h](msg).digest()
            z = int.from_bytes(dg, "big") >> max(0, 8 * len(dg) - n.bit_length())
            k = int.from_bytes(hashlib.sha512(self.d.to_bytes(66, "big") + msg).digest(), "big") % (n - 1) + 1
            r = V._ec_lin(k, (gx, gy), 0, (gx, gy), P)[0] % n
            return _alg(_EC_OID[h]), _seq(_int(r), _int(pow(k, -1, n) * (z + r * self.d) % n))
        return _alg(V.ED25519), sign(self.ed, msg)


def tcert(key, cn, issuer=None, serial=1, nb="20200101000000Z", na="20450101000000Z", ca=False, eku=(V.EKU_TS,), eku_crit=True,
          pathlen=None, alg=None, extra=(), ski=None, sigalg=None, spki=None, bc=True, ku=None, version=2, exts=None, inner_sigalg=None,
          subject=None):
    """A certificate for key under the name cn, signed by issuer = (cn, key), else by itself. bc: basicConstraints
    (cA = ca, pathLenConstraint = pathlen); ku: the content of a keyUsage BIT STRING; eku None: no extKeyUsage; exts:
    the extensions written instead; version None: no [0] (version 1); sigalg: an AlgorithmIdentifier written instead of
    the one signed with (inner_sigalg for tbsCertificate alone); spki: a key written instead of key's; subject: a Name
    written instead of that of cn."""
    icn, ik = issuer or (cn, key)
    alg = alg or {"rsa": "rsa256", "ec": "ec256", "ed": "ed"}[ik.kind]
    if exts is None:
        exts = [_ext("2.5.29.19", _seq(_tl(0x01, b"\xff") if ca else b"", _int(pathlen) if pathlen is not None else b""))] if bc else []
        if ku is not None: exts.append(_ext("2.5.29.15", _tl(0x03, ku)))
        if eku is not None: exts.append(_ext("2.5.29.37", _seq(*map(_oid, eku)), eku_crit))
        if ski is not None: exts.append(_ext("2.5.29.14", _tl(0x04, ski), False))
        exts += list(extra)
    sigalg = sigalg or ik.sign(b"", alg)[0]
    tbs = _seq(b"" if version is None else _tl(0xa0, _int(version)), _int(serial), inner_sigalg or sigalg, _name(icn), _seq(_time(nb), _time(na)),
               subject or _name(cn), spki or key.spki(), _tl(0xa3, _seq(*exts)) if exts else b"")
    return _seq(tbs, sigalg, _tl(0x03, b"\x00" + ik.sign(tbs, alg)[1]))


def _iss_ser(cert):
    """issuer (DER) and serialNumber of a certificate, read without the rules of Z.1 (a test may break them)."""
    f = V.der_seq(V.der_seq(V.der(cert, 0x30))[0])
    i = 1 if f[0][0] == 0xa0 else 0
    return f[i + 2][1], V.der_int(f[i])


_HD = {**V.SHA2, V.SHA1: hashlib.sha1, "2.16.840.1.101.3.4.2.8": hashlib.sha3_256, "2.16.840.1.101.3.4.2.4": hashlib.sha224}


def ess_v2(cert, h=V.H256, issuer_serial=None, alg=None):
    """signingCertificateV2 naming cert by the hash h (RFC 5035); alg: the hashAlgorithm written (None: default, omitted)."""
    ident = _seq(alg if alg is not None else (b"" if h == V.H256 else _alg(h)), _tl(0x04, _HD[h](cert).digest()), issuer_serial or b"")
    return _seq(_oid(V.A_ESS2), _set(_seq(_seq(ident))))


def ess_v1(cert, issuer_serial=None):
    return _seq(_oid(V.A_ESS), _set(_seq(_seq(_seq(_tl(0x04, hashlib.sha1(cert).digest()), issuer_serial or b"")))))


def issuer_serial(cert, serial=None):
    iss, ser = _iss_ser(cert)
    return _seq(_seq(_tl(0xa4, iss)), _int(ser if serial is None else serial))


def ttoken(data, key, cert, carried=None, gentime="20260101004001Z", serial=0x2a, policy="1.3.6.1.4.1.99999.3.161.1", alg=None,
           digest=V.H256, ess="v2", exts=None, imprint=V.H256, sigalg=None, sid=None, signers=1, attrs=True, ct=V.TSTINFO, md=None,
           extra_attrs=(), tst_extra=b"", crls=None, unsigned=None, sd_version=3, si_version=None, das=None, dpar=b""):
    """An RFC 3161 TimeStampToken over data, signed by key whose certificate is cert. carried: the certificates in the
    token (default: cert; () none); ess "v2", "v1", "both", None or a whole attribute; exts: the content parts of the
    TSTInfo extensions [1] (None: absent); attrs False: no signed attributes, the signature over eContent; ct, md: the
    contentType and messageDigest written; sid: a subjectKeyIdentifier to name the signer by; tst_extra: TSTInfo
    elements after genTime; crls, unsigned: contents of [1] in SignedData and SignerInfo; das: digestAlgorithms."""
    tst = _seq(_int(1), _oid(policy), _seq(_alg(imprint), _tl(0x04, _HD[imprint](data).digest())), _int(serial), _tl(0x18, gentime.encode()),
               tst_extra, _tl(0xa1, *exts) if exts is not None else b"")
    a = [_seq(_oid(V.A_CT), _set(_oid(ct))), _seq(_oid(V.A_MD), _set(_tl(0x04, md if md is not None else _HD[digest](tst).digest())))]
    a += {"v2": [ess_v2(cert)], "v1": [ess_v1(cert)], "both": [ess_v1(cert), ess_v2(cert)], None: []}[ess] if ess in ("v2", "v1", "both", None) else [ess]
    a += list(extra_attrs)
    alg_der, sig = key.sign(_set(*a) if attrs else tst, alg or {"rsa": "rsa256", "ec": "ec256", "ed": "ed"}[key.kind])
    iss, ser = _iss_ser(cert)
    si = _seq(_int(si_version or (3 if sid is not None else 1)), _tl(0x80, sid) if sid is not None else _seq(iss, _int(ser)), _alg(digest, dpar),
              _tl(0xa0, *a) if attrs else b"", sigalg or alg_der, _tl(0x04, sig), _tl(0xa1, unsigned) if unsigned is not None else b"")
    sd = _seq(_int(sd_version), _set(*(das if das is not None else [_alg(digest)])), _seq(_oid(V.TSTINFO), _tl(0xa0, _tl(0x04, tst))),
              _tl(0xa0, *(carried or [cert])) if carried != () else b"", _tl(0xa1, crls) if crls is not None else b"", _set(*[si] * signers))
    return _seq(_oid(V.SIGNED_DATA), _tl(0xa0, sd))


def flip_last(der): return der[:-1] + bytes([der[-1] ^ 1])      # the last byte of the token is the last byte of its signature


def vector_token():
    with open(os.path.join(VEKTOREN, "valid_time_anchor", "segments", "chain-000001.jsonl"), encoding="utf-8") as fh:
        return base64.b64decode(next(json.loads(x) for x in fh if '"TIME_ANCHOR"' in x)["payload"]["token_base64"])


def subject_of(cp):
    """The signing subject of checkpoint entry cp (6.1), the bytes a time witness stamps (7.3)."""
    q = cp["payload"]
    return V.jcsb({"chain_id": CHAIN, "tree_size": q["tree_size"], "merkle_root": q["merkle_root"],
                   "prev_checkpoint_hash": q["prev_checkpoint_hash"], "key_id": q["key_id"], "ts": cp["ts_chained"]})


def witness(c, cp, **kw):
    """A TIME_ANCHOR (4.22) on checkpoint entry cp, its token made by ttoken over the checkpoint's signed subject (6.1,
    7.3); the readings follow the token unless tsa_ts, tsa_serial or tsa_policy say otherwise."""
    key, cert = kw.pop("key"), kw.pop("cert")
    g = kw.get("gentime", "20260101004001Z")
    try: ts = V.gen_time((0x18, b"", g.encode()))[2]
    except ValueError: ts = "%s-%s-%sT%s:%s:%s.000Z" % (g[0:4], g[4:6], g[6:8], g[8:10], g[10:12], g[12:14])
    payload = {"checkpoint_seq": cp["seq"], "tree_size": cp["payload"]["tree_size"], "merkle_root": cp["payload"]["merkle_root"], "tsa_name": "Probe",
               "tsa_policy": kw.pop("tsa_policy", kw.get("policy", "1.3.6.1.4.1.99999.3.161.1")), "tsa_serial": kw.pop("tsa_serial", format(kw.get("serial", 0x2a), "x")),
               "tsa_ts": kw.pop("tsa_ts", ts)}
    tamper, b64 = kw.pop("tamper", lambda d: d), kw.pop("b64", None)
    payload["token_base64"] = b64 if b64 is not None else base64.b64encode(tamper(ttoken(subject_of(cp), key, cert, **kw))).decode()
    return c.add("TIME_ANCHOR", payload)


def write_pem(path, *ders, text=None):
    with open(path, "w", newline="") as fh: fh.write(text if text is not None else pem(*ders))
    return path


class TSA:
    """A test time-stamping authority: an RSA root (CA) and an Ed25519 signer under it, keys derived from labels."""
    def __init__(self, label=b"verifier2 1.10 tsa", signer_kind="ed", **signer_kw):
        self.rk, self.sk = TKey("rsa", label + b" root"), TKey(signer_kind, label + b" signer", P384 if signer_kind == "ec" else P256)
        self.root = tcert(self.rk, "Probe Root 1.10", ca=True, eku=None)
        self.signer = tcert(self.sk, "Probe TSA 1.10", issuer=("Probe Root 1.10", self.rk), serial=2,
                            **{"alg": "rsa256", **signer_kw})

    def token(self, data, **kw):
        return ttoken(data, self.sk, self.signer, **{"carried": [self.signer], **kw})


def assess(tok, data=b"s", roots=()):
    return V.ts_assess(tok, data, [V.Cert(r) if isinstance(r, bytes) else r for r in roots])


class TimeStampProfile(Spec19):
    """Format spec 7.5 (1.10), rule by rule over hand-written DER: B64 (2, 7.5.1), grammar T (T.1 to T.6, 7.5.2), Z.1
    certificates (7.5.3), Z.2 algorithms and keys (7.5.4), Z.3 to Z.5 (7.5.5), Z.6 and rule QS (7.5.6) and the mapping
    of results with the purposes of roots (7.5.7). Tokens and certificates are made here from keys derived from labels."""

    @classmethod
    def setUpClass(cls):
        cls.a = TSA()
        cls.rk = TKey("rsa", b"verifier2 test tsa rsa")
        cls.cert = tcert(cls.rk, "Probe TSA RSA")                       # self-signed, CA:FALSE: its own root

    def t_err(self, tok):
        with self.assertRaises(V.TError): V.t_read(tok)

    def test_2_b64_grammar(self):
        """Grammar B64 (format spec 2): alphabet, length divisible by 4, '=' only at the end and at most twice, no line
        break; unused bits of the last group are not checked."""
        self.assertEqual(V.b64_decode("QQ=="), b"A")
        self.assertEqual(V.b64_decode("QR=="), b"A")                     # unused bits: the string is judged, not re-encoded
        self.assertEqual(V.b64_decode(""), b"")
        for bad in ("QQ=", "Q===", "QQ==QQ==", "QQ\n==", "QQ==\n", "QQ ==", "Q-_A", "QUJD\r\nREVG", "QUJDREVG\n"):
            with self.subTest(bad), self.assertRaises(ValueError): V.b64_decode(bad)

    def test_7_5_2_T1_T2_T3_envelope(self):
        """T.1 ContentInfo of id-signedData, nothing after it; T.2 SignedData version 1 to 5, exactly one SignerInfo;
        T.3 eContent of id-ct-TSTInfo holding exactly one TSTInfo; T.6 minimal lengths."""
        tok = self.a.token(b"s")
        self.assertEqual(V.t_read(tok)["policy"], "1.3.6.1.4.1.99999.3.161.1")
        self.t_err(tok + b"\x00")                                        # T.1: a byte after it
        self.assertEqual(tok[1], 0x82)
        self.t_err(tok[:1] + b"\x83\x00" + tok[2:])                         # T.6: a length with a leading 00
        self.t_err(self.a.token(b"s", signers=2))                       # T.2: two SignerInfos
        self.t_err(self.a.token(b"s", sd_version=6))
        for v in (1, 5): V.t_read(self.a.token(b"s", sd_version=v))
        self.t_err(self.a.token(b"s", tst_extra=b"", exts=None, imprint=V.SHA1))           # T.5: sha1 imprint
        self.t_err(_seq(_oid("1.2.840.113549.1.7.1"), tok[tok.index(b"\xa0"):]))          # T.1: id-data

    def test_7_5_2_T4_signer_info(self):
        """T.4: version 1 or 3 (not compared with the form of sid), sid IssuerAndSerialNumber or [0], digestAlgorithm with
        absent or NULL parameters and listed in digestAlgorithms, exactly one contentType and messageDigest each with one
        value, unsignedAttrs read as TLV only, signatureAlgorithm parameters any TLV."""
        a = self.a
        V.t_read(a.token(b"s", si_version=3))                           # version 3 with IssuerAndSerialNumber
        ski_cert = tcert(a.sk, "Probe TSA SKI", issuer=("Probe Root 1.10", a.rk), ski=b"\x07" * 20, alg="rsa256")
        V.t_read(ttoken(b"s", a.sk, ski_cert, sid=b"\x07" * 20, si_version=1))
        self.t_err(a.token(b"s", si_version=2))
        self.t_err(a.token(b"s", dpar=_tl(0x02, b"\x01")))               # digestAlgorithm parameters other than NULL
        V.t_read(a.token(b"s", dpar=b"\x05\x00"))
        self.t_err(a.token(b"s", das=[_alg(V.H384)]))                    # not listed in digestAlgorithms
        self.t_err(a.token(b"s", das=[_alg(V.H256), _alg(V.H384, _tl(0x02, b"\x01"))]))
        self.t_err(a.token(b"s", extra_attrs=[_seq(_oid(V.A_CT), _set(_oid(V.TSTINFO)))]))            # contentType twice
        self.t_err(a.token(b"s", extra_attrs=[_seq(_oid("1.2.3.4"), _set())]))                         # an attribute without value
        self.t_err(a.token(b"s", ess=_seq(_oid(V.A_MD), _set(_tl(0x04, b"x"), _tl(0x04, b"y")))))      # messageDigest twice
        V.t_read(a.token(b"s", unsigned=_tl(0x30, b"\x02\x81\x01")))     # unsignedAttrs: the TLV only, BER inside passes
        V.t_read(a.token(b"s", crls=_tl(0x30, b"\x02\x81\x01")))         # crls likewise (T.2)
        # T.4 (60aa776a): of sid grammar T checks only a SEQUENCE or a primitive [0]; a SEQUENCE whose content is not
        # { issuer, serialNumber } matches no certificate in Z.5 (step 5a) and never violates T
        tok = a.token(b"s")
        iss, ser = _iss_ser(a.signer)
        ias, n = _seq(iss, _int(ser)), len(_int(ser)) - 2
        for why, sid in (("serialNumber as OCTET STRING", _seq(iss, _tl(0x04, _int(ser)[2:]))),
                         ("content does not split into TLV", _tl(0x30, iss + bytes([0x02, 0x7f]) + b"\x00" * n)),
                         ("issuer no SEQUENCE", _seq(b"\x31" + iss[1:], _int(ser)))):
            with self.subTest(why):
                self.assertEqual(len(sid), len(ias))                       # the same length: no other byte of the token changes
                bad = tok.replace(ias, sid, 1)
                self.assertEqual(V.t_read(bad)["sid"], ("none",))
                self.assertEqual(assess(bad, b"s", [a.root])["step5"], "not_performable")
        self.t_err(tok.replace(ias, b"\xa0" + ias[1:], 1))                 # a constructed [0] is neither form

    def test_7_5_2_T5_tstinfo(self):
        """T.5: version 1, imprint sha256/384/512 with 32/48/64 octets, genTime with 1 to 9 fraction digits whose last is
        not 0, existing date, no offset; accuracy, ordering, nonce, tsa, extensions optional and in this order; an
        explicitly encoded ordering FALSE accepted (T.6)."""
        a = self.a
        for g, ok in (("20260101004001Z", True), ("20260101004001.1Z", True), ("20260101004001.123999999Z", True),
                      ("20260101004001.120Z", False), ("20260101004001.1234567891Z", False), ("20260101004001.Z", False),
                      ("20260101004001+0100", False), ("202601010040Z", False), ("20260230004001Z", False), ("20260101244001Z", False),
                      ("20260101006001Z", False), ("20260101004060Z", False), ("00000101000000Z", False), ("20260101004001,5Z", False)):
            with self.subTest(genTime=g):
                if ok: self.assertEqual(V.t_read(a.token(b"s", gentime=g))["gen_time"], g)
                else: self.t_err(a.token(b"s", gentime=g))
        self.assertEqual(V.t_read(a.token(b"s", gentime="20260101004001.123999999Z"))["gen_time_ms"], "2026-01-01T00:40:01.123Z")   # cut, not rounded
        self.assertEqual(V.t_read(a.token(b"s", gentime="20260101004001.9Z"))["gen_time_ms"], "2026-01-01T00:40:01.900Z")
        acc = _seq(_int(1), _tl(0x80, b"\x05"), _tl(0x81, b"\x07"))
        V.t_read(a.token(b"s", tst_extra=acc + _tl(0x01, b"\x00") + _int(12345) + _tl(0xa0, _tl(0xa4, _seq()))))
        self.t_err(a.token(b"s", tst_extra=_int(12345) + _tl(0x01, b"\x00")))                 # nonce before ordering
        self.t_err(a.token(b"s", tst_extra=_tl(0x01, b"\x01")))                               # BOOLEAN content 01 (T.6)
        self.t_err(a.token(b"s", tst_extra=_tl(0x02, b"\x00\x05")))                           # INTEGER not minimal (T.6)
        self.t_err(a.token(b"s", tst_extra=_seq(_tl(0x81, b"\x07"), _tl(0x80, b"\x05"))))    # accuracy out of order
        V.t_read(a.token(b"s", exts=[]))                                                      # an empty [1] is a TLV: T holds (QS: unusable)
        self.t_err(a.token(b"s", exts=None, tst_extra=_tl(0xa2, b"")))                        # an element T.5 does not define
        self.t_err(a.token(b"s", imprint="2.16.840.1.101.3.4.2.4"))                           # sha224
        tok = a.token(b"s", imprint=V.H384)
        self.assertEqual(V.t_read(tok)["imprint_alg"], V.H384)

    def test_7_5_2_size_16384(self):
        """7.3 step 2: the decoded DER has at most 16 384 bytes."""
        base = len(self.a.token(b"s", crls=b""))
        def pad(n): return _tl(0x04, b"\x00" * n)
        for target, ok in ((16384, True), (16385, False)):
            n = target - base - 4
            tok = self.a.token(b"s", crls=pad(n))
            while len(tok) < target: n += 1; tok = self.a.token(b"s", crls=pad(n))
            while len(tok) > target: n -= 1; tok = self.a.token(b"s", crls=pad(n))
            if len(tok) != target: continue
            with self.subTest(size=target):
                if ok: V.t_read(tok)
                else: self.t_err(tok)

    def test_7_5_3_Z1_certificates(self):
        """Z.1: version encoded as 2, serial positive with at most 21 octets, inner signature byte-equal to the outer,
        no unique IDs, SPKI and signature BIT STRINGs with 0 unused bits, Time forms, Extension critical 00 or FF (00
        written out accepted), no extnID twice, extnValue exactly one DER TLV, DER throughout, nothing after it. Where Z.1
        asks for one TLV only (the value of a Name attribute, the parameters of an AlgorithmIdentifier, extnValue of an
        extension no rule reads), only the outer TLV is checked and its content need not be DER (7.5.2 T.6)."""
        k = self.rk
        def signed(tbs): return _seq(tbs, _alg("1.2.840.113549.1.1.11", b"\x05\x00"), _tl(0x03, b"\x00" + k.sign(tbs, "rsa256")[1]))
        head = _tl(0xa0, _int(2)) + _int(1) + _alg("1.2.840.113549.1.1.11", b"\x05\x00") + _name("e") + _seq(_time("20200101000000Z"), _time("20450101000000Z")) + _name("e") + k.spki()
        empty_exts, unique_id = signed(_seq(head, _tl(0xa3, _seq()))), signed(_seq(head, _tl(0x81, b"\x00\x01")))
        V.Cert(signed(_seq(head)))
        V.Cert(tcert(k, "ok"))
        V.Cert(tcert(k, "critical FALSE written out", extra=(_seq(_oid("1.2.3.4"), _tl(0x01, b"\x00"), _tl(0x04, _int(1))),)))
        self.assertEqual(V.Cert(tcert(k, "utc", nb="20491231235959Z")).not_before, V._instant_ns("2049", "12", "31", "23", "59", "59"))
        for why, der in (("version 1", tcert(k, "v1", version=None, exts=[])), ("version encoded 1", tcert(k, "v2", version=1)),
                         ("serial 0", tcert(k, "s0", serial=0)), ("serial negative", tcert(k, "sn", serial=-5)),
                         ("serial 22 octets", tcert(k, "s22", serial=1 << 170)),
                         ("inner signature differs", tcert(k, "inner", inner_sigalg=_alg("1.2.840.113549.1.1.11"))),
                         ("extension twice", tcert(k, "twice", extra=(_ext("2.5.29.19", _seq()),))),
                         ("critical 01", tcert(k, "crit", extra=(_seq(_oid("1.2.3.4"), _tl(0x01, b"\x01"), _tl(0x04, _int(1))),))),
                         ("extnValue two TLV", tcert(k, "two", extra=(_ext("1.2.3.4", _int(1) + _int(2), False),))),
                         ("extnValue a length not minimal", tcert(k, "ber", extra=(_ext("1.2.3.4", b"\x02\x81\x01\x01", False),))),
                         ("basicConstraints not DER inside", tcert(k, "bc", bc=False, extra=(_ext("2.5.29.19", b"\x30\x03\x01\x01\x01"),))),
                         ("extensions [3] with an empty SEQUENCE", empty_exts),
                         ("issuerUniqueID", unique_id),
                         ("a byte after it", tcert(k, "after") + b"\x00")):
            with self.subTest(why), self.assertRaises(ValueError): V.Cert(der)
        good = tcert(k, "gt")
        self.assertRaises(ValueError, V.Cert, good.replace(b"\x17\x0d" + b"200101000000Z", b"\x17\x0d" + b"200230000000Z", 1))   # 30 February
        y0 = _tl(0xa0, _int(2)) + _int(1) + _alg("1.2.840.113549.1.1.11", b"\x05\x00") + _name("e") + _seq(_time("20200101000000Z"), _tl(0x18, b"00000101000000Z")) + _name("e") + k.spki()
        self.assertRaises(ValueError, V.Cert, signed(_seq(y0)))                                          # the year 0000 violates Z.1
        # T.6 (60aa776a): one TLV, its content not parsed: extnValue of an extension no rule reads, a Name attribute value
        # in constructed form, AlgorithmIdentifier parameters with BER inside
        V.Cert(tcert(k, "not der inside", extra=(_ext("1.2.3.4", b"\x02\x02\x00\x01", False), _ext("1.2.3.5", b"\x30\x03\x01\x01\x01", False))))
        cn = _seq(_set(_seq(_oid("2.5.4.3"), _tl(0x2c, _tl(0x0c, b"Probe")))))
        tbs = _seq(_tl(0xa0, _int(2)), _int(1), _alg("1.2.840.113549.1.1.11", b"\x05\x00"), cn, _seq(_time("20200101000000Z"), _time("20450101000000Z")), cn, k.spki())
        self.assertEqual(V.Cert(signed(tbs)).subject, cn)
        tbs = _seq(_tl(0xa0, _int(2)), _int(1), _alg("1.2.840.113549.1.1.11", b"\x02\x02\x00\x01"), _name("e"), _seq(_time("20200101000000Z"), _time("20450101000000Z")), _name("e"), k.spki())
        V.Cert(_seq(tbs, _alg("1.2.840.113549.1.1.11", b"\x02\x02\x00\x01"), _tl(0x03, b"\x00" + k.sign(tbs, "rsa256")[1])))
        self.assertRaises(ValueError, V.Cert, signed(_seq(_tl(0xa0, _int(2)), _int(1), _alg("1.2.840.113549.1.1.11", b"\x05\x00"),
                                                          _seq(_set(_seq(_oid("2.5.4.3"), b"\x0c\x81\x01e"))), _seq(_time("20200101000000Z"), _time("20450101000000Z")), _name("e"), k.spki())))

    def test_7_5_4_Z2_keys_and_algorithms(self):
        """Z.2: RSA 2048 to 8192 bits with 65537 <= e < 2^31 and odd n, e; P-256/384/521 uncompressed on the curve;
        Ed25519 32 octets without parameters, canonical y; signature algorithms with their parameter rules; SHA-1, MD5,
        brainpool and anything else outside; key and algorithm fit by kind only."""
        def key_of(spki): return V.z2_key(V.Cert(tcert(self.rk, "k", spki=spki)))
        self.assertEqual(key_of(self.rk.spki())[0], "rsa")
        small = TKey("rsa", b"small")                                   # the test key: 2048 bits
        self.assertEqual(small.n.bit_length(), 2048)
        rsa = lambda n, e, par=b"\x05\x00": _seq(_alg(V.RSA_KEY, par), _tl(0x03, b"\x00" + _seq(_int(n), _int(e))))
        for why, spki in (("1024 bits", rsa(_prime(b"a", 512) * _prime(b"b", 512), 65537)), ("e = 3", rsa(small.n, 3)),
                          ("e even", rsa(small.n, 65538)), ("e = 2^31", rsa(small.n, 2**31 + 1)), ("parameters absent", rsa(small.n, 65537, b"")),
                          ("brainpoolP256r1", _seq(_alg(V.EC_KEY, _oid("1.3.36.3.3.2.8.1.1.7")), _tl(0x03, b"\x00\x04" + bytes(64)))),
                          ("secp256k1", _seq(_alg(V.EC_KEY, _oid("1.3.132.0.10")), _tl(0x03, b"\x00\x04" + bytes(64)))),
                          ("P-256 compressed", _seq(_alg(V.EC_KEY, _oid(P256)), _tl(0x03, b"\x00\x02" + bytes(32)))),
                          ("P-256 off the curve", _seq(_alg(V.EC_KEY, _oid(P256)), _tl(0x03, b"\x00\x04" + bytes(63) + b"\x01"))),
                          ("Ed25519 with parameters", _seq(_alg(V.ED25519, b"\x05\x00"), _tl(0x03, b"\x00" + bytes(32)))),
                          ("Ed25519 y not canonical", _seq(_alg(V.ED25519), _tl(0x03, b"\x00" + (2**255 - 1).to_bytes(32, "little")))),
                          ("DSA", _seq(_alg("1.2.840.10040.4.1"), _tl(0x03, b"\x00\x02\x01\x01")))):
            with self.subTest(why), self.assertRaises(V.Z2Error): key_of(spki)
        self.assertEqual(key_of(TKey("ec", b"p521", P521).spki())[1][0], P521)
        null = b"\x05\x00"
        self.assertEqual(V.z2_sigalg(("1.2.840.113549.1.1.11", b"")), ("rsa", V.H256, None))
        self.assertEqual(V.z2_sigalg(("1.2.840.113549.1.1.13", null)), ("rsa", V.H512, None))
        self.assertEqual(V.z2_sigalg((V.RSA_KEY, null), True, V.H384), ("rsa", V.H384, None))
        self.assertEqual(V.z2_sigalg((V.EC_KEY, b""), True, V.H256), ("ec", V.H256, None))
        pss = lambda h, mh, salt, tail=b"": _seq(_tl(0xa0, _alg(h)), _tl(0xa1, _alg(V.MGF1, _alg(mh))), _tl(0xa2, _int(salt)), tail)
        self.assertEqual(V.z2_sigalg((V.PSS, pss(V.H256, V.H256, 32))), ("rsa", V.H256, 32))
        self.assertEqual(V.z2_sigalg((V.PSS, pss(V.H384, V.H384, 48, _tl(0xa3, _int(1))))), ("rsa", V.H384, 48))
        for why, a in (("sha1WithRSAEncryption", ("1.2.840.113549.1.1.5", null)), ("md5WithRSA", ("1.2.840.113549.1.1.4", null)),
                       ("sha224WithRSAEncryption", ("1.2.840.113549.1.1.14", null)), ("sha256WithRSA with an INTEGER", ("1.2.840.113549.1.1.11", _int(0))),
                       ("ecdsa-with-SHA256 with NULL", ("1.2.840.10045.4.3.2", null)), ("ecdsa-with-SHA1", ("1.2.840.10045.4.1", b"")),
                       ("Ed25519 with NULL", (V.ED25519, null)), ("bare rsaEncryption in a certificate", (V.RSA_KEY, null)),
                       ("PSS salt 20", (V.PSS, pss(V.H256, V.H256, 20))), ("PSS salt 0", (V.PSS, pss(V.H256, V.H256, 0))),
                       ("PSS MGF1 other hash", (V.PSS, pss(V.H256, V.H384, 32))), ("PSS defaults", (V.PSS, _seq())),
                       ("PSS without parameters", (V.PSS, b"")), ("PSS trailerField 2", (V.PSS, pss(V.H256, V.H256, 32, _tl(0xa3, _int(2))))),
                       ("PSS over SHA-1", (V.PSS, pss(V.SHA1, V.SHA1, 20)))):
            with self.subTest(why), self.assertRaises(V.Z2Error): V.z2_sigalg(a)
        self.assertRaises(V.Z2Error, V.z2_sigalg, (V.RSA_KEY, null), True, V.SHA1)

    def test_7_3_step_5a_and_5b(self):
        """Step 5a (not performable: TIME_ANCHOR_UNVERIFIED, never INVALID) against 5b (performed and failed: INVALID)."""
        a, data = self.a, b"s"
        other = tcert(a.sk, "Probe TSA 1.10", issuer=("Probe Root 1.10", a.rk), serial=2, alg="rsa256", nb="20210101000000Z")   # same issuer and serial
        v1 = tcert(self.rk, "v1", version=None, exts=[])
        bp = _seq(_alg(V.EC_KEY, _oid("1.3.36.3.3.2.8.1.1.7")), _tl(0x03, b"\x00\x04" + bytes(64)))
        cases = (("no signed attributes", a.token(data, attrs=False), "not_performable"),
                 ("no certificates", a.token(data, carried=()), "not_performable"),
                 ("certificates do not split into TLV (T.2)", a.token(data, carried=[a.signer, b"\x30\x05\x01"]), "not_performable"),
                 ("empty certificates", a.token(data, carried=[b""]), "not_performable"),
                 ("a certificate of version 1 beside the signer", a.token(data, carried=[a.signer, v1]), "not_performable"),
                 ("signer not carried", a.token(data, carried=[self.cert]), "not_performable"),
                 ("two certificates match the signer", a.token(data, carried=[a.signer, other]), "not_performable"),
                 ("the signer twice, byte-equal: found once", a.token(data, carried=[a.signer, a.signer]), "holds"),
                 ("SHA-1 digestAlgorithm", a.token(data, digest=V.SHA1), "not_performable"),
                 ("SHA3-256 digestAlgorithm", a.token(data, digest="2.16.840.1.101.3.4.2.8"), "not_performable"),
                 ("key and algorithm do not fit", a.token(data, sigalg=_alg("1.2.840.113549.1.1.11", b"\x05\x00")), "not_performable"),
                 ("contentType id-data", a.token(data, ct="1.2.840.113549.1.7.1"), "failed"),
                 ("messageDigest of other bytes", a.token(data, md=hashlib.sha256(b"x").digest()), "failed"),
                 ("signature flipped", flip_last(a.token(data)), "failed"))
        for why, tok, want in cases:
            with self.subTest(why):
                self.assertEqual(assess(tok, data)["step5"], want, assess(tok, data)["step5_why"])
        bpcert = tcert(a.sk, "Probe TSA BP", issuer=("Probe Root 1.10", a.rk), spki=bp, alg="rsa256")
        self.assertEqual(assess(ttoken(data, TKey("ec", b"bp", P256), bpcert, alg="ec256"), data)["step5"], "not_performable")
        ek = TKey("ec", b"verifier2 1.10 ecdsa", P256)
        ecert = tcert(ek, "Probe TSA EC", alg="ec256")
        tok = ttoken(data, ek, ecert)
        self.assertEqual(assess(tok, data)["step5"], "holds")
        rsa_bare = ttoken(data, self.rk, self.cert, sigalg=_alg(V.RSA_KEY, b"\x05\x00"))
        self.assertEqual(assess(rsa_bare, data)["step5"], "holds")      # rsaEncryption with the SHA-2 digestAlgorithm (SignerInfo only)
        # Z.2 (60aa776a): id-ecPublicKey as the signature algorithm of the SignerInfo with parameters absent, as its SHA-2 forms
        self.assertEqual(assess(ttoken(data, ek, ecert, sigalg=_alg(V.EC_KEY)), data)["step5"], "holds")
        self.assertEqual(assess(ttoken(data, ek, ecert, sigalg=_alg(V.EC_KEY, b"\x05\x00")), data)["step5"], "not_performable")
        self.assertEqual(assess(ttoken(data, self.rk, self.cert, sigalg=_alg(V.RSA_KEY)), data)["step5"], "holds")
        for alg in ("pss256", "pss512", "rsa384", "ec384"):
            k = self.rk if alg[0] in "pr" else TKey("ec", b"p384 " + alg.encode(), P384)
            c = tcert(k, "Probe " + alg, alg=alg)
            with self.subTest(alg=alg):
                self.assertEqual(assess(ttoken(data, k, c, alg=alg), data, [c])["paths"], {V.Cert(c).der: True})

    def test_7_5_5_Z4_paths(self):
        """Z.4: a path c0 ... ck, ck byte-equal to the root, 0 <= k <= 8, intermediates from the token only, issuer and
        subject byte-equal, signatures after Z.2, cA and keyCertSign and pathLen >= j - 1 for j >= 1, validity at genTime
        (bounds inclusive), c0 with exactly id-kp-timeStamping marked critical, others with it or anyExtendedKeyUsage;
        Z.3: nameConstraints, policyMappings, policyConstraints, inhibitAnyPolicy or an unknown critical extension
        make a path unusable. The root's own signature is not checked."""
        rk, ik, lk = self.rk, TKey("ec", b"verifier2 test ca p384", P384), TKey("ec", b"verifier2 test tsa p256", P256)
        def build(i_kw=(), r_kw=(), l_kw=()):
            r = tcert(rk, "Probe Root", **{"ca": True, "eku": None, **dict(r_kw)})
            inter = tcert(ik, "Probe CA", issuer=("Probe Root", rk), **{"ca": True, "eku": None, **dict(i_kw)})
            leaf = tcert(lk, "Probe TSA", issuer=("Probe CA", ik), **{"alg": "ec384", **dict(l_kw)})
            return r, inter, leaf
        r, inter, leaf = build()
        tok = ttoken(b"s", lk, leaf, carried=[leaf, inter])
        self.assertEqual(assess(tok, b"s", [r, inter, leaf])["paths"], {V.Cert(x).der: True for x in (r, inter, leaf)})
        self.assertEqual(assess(ttoken(b"s", lk, leaf, carried=[leaf]), b"s", [r])["paths"], {V.Cert(r).der: False})   # intermediate not carried
        for why, args, want in (
                ("intermediate without cA", ({"ca": False},), False), ("intermediate without basicConstraints", ({"bc": False},), False),
                ("intermediate keyUsage without keyCertSign", ({"ku": b"\x07\x80"},), False), ("intermediate keyUsage keyCertSign", ({"ku": b"\x02\x04"},), True),
                ("intermediate EKU serverAuth", ({"eku": (SERVER_AUTH,), "eku_crit": False},), False),
                ("intermediate EKU timeStamping", ({"eku": (V.EKU_TS,), "eku_crit": False},), True), ("intermediate EKU any", ({"eku": (V.EKU_ANY,)},), True),
                ("intermediate expired at genTime", ({"na": "20260101004000Z"},), False), ("intermediate valid until genTime", ({"na": "20260101004001Z"},), True),
                ("intermediate pathLen 0", ({"pathlen": 0},), True), ("root pathLen 0", ((), {"pathlen": 0}), False), ("root pathLen 1", ((), {"pathlen": 1}), True),
                ("root expired at genTime", ((), {"na": "20251231000000Z"}), False),
                ("root not yet valid at genTime", ((), {"nb": "20260101004002Z"}), False),
                ("root unknown critical extension", ((), {"extra": (_ext("1.2.3.4", _int(0)),)}), False),
                ("root unknown non-critical extension", ((), {"extra": (_ext("1.2.3.4", _int(0), False),)}), True),
                ("intermediate inhibitAnyPolicy, not critical", ({"extra": (_ext("2.5.29.54", _int(0), False),)},), False),
                ("intermediate policyConstraints", ({"extra": (_ext("2.5.29.36", _seq(_tl(0x80, b"\x00"))),)},), False),
                ("intermediate policyMappings", ({"extra": (_ext("2.5.29.33", _seq(), False),)},), False),
                ("intermediate nameConstraints", ({"extra": (_ext("2.5.29.30", _seq(_tl(0xa0, _seq(_tl(0x82, b"x")))), True),)},), False),
                ("leaf signed with ecdsa-with-SHA1", ((), (), {"sigalg": _alg("1.2.840.10045.4.1")}), False),
                ("leaf EKU not critical", ((), (), {"eku_crit": False}), False), ("leaf two EKU", ((), (), {"eku": (V.EKU_TS, SERVER_AUTH)}), False),
                ("leaf EKU any", ((), (), {"eku": (V.EKU_ANY,)}), False), ("leaf without EKU", ((), (), {"eku": None}), False),
                ("leaf keyUsage without keyCertSign", ((), (), {"ku": b"\x07\x80"}), True), ("leaf without basicConstraints", ((), (), {"bc": False}), True)):
            with self.subTest(why):
                r, inter, leaf = build(*args)
                res = assess(ttoken(b"s", lk, leaf, carried=[leaf, inter]), b"s", [r])
                if res["step5"] == "holds": self.assertEqual(res["paths"], {V.Cert(r).der: want}, why)
                else: self.assertFalse(want, res["step5_why"])
        # the root's own signature is never checked: a root whose signature is broken still anchors
        r, inter, leaf = build()
        self.assertTrue(assess(ttoken(b"s", lk, leaf, carried=[leaf, inter]), b"s", [flip_last(r)])["paths"][V.Cert(flip_last(r)).der])
        # depth: k <= 8 - a chain of 8 intermediates reaches its root, one of 9 does not
        keys = [TKey("ed", b"chain %d" % i) for i in range(10)]
        def chain_of(n):
            certs = [tcert(keys[0], "C0", ca=True, eku=None)]
            for i in range(1, n + 1): certs.append(tcert(keys[i], "C%d" % i, issuer=("C%d" % (i - 1), keys[i - 1]), ca=True, eku=None))
            leaf = tcert(lk, "L", issuer=("C%d" % n, keys[n]), alg="ed")
            return certs[0], certs[1:], leaf
        for n, want in ((8, False), (7, True)):
            root, mids, leaf = chain_of(n)
            with self.subTest(intermediates=n):                          # n intermediates + the root: k = n + 1
                self.assertEqual(assess(ttoken(b"s", lk, leaf, carried=[leaf] + mids[::-1]), b"s", [root])["paths"][V.Cert(root).der], want)

    def test_7_5_5_Z5_signer(self):
        """Z.5: sid as IssuerAndSerialNumber or as [0] the content of subjectKeyIdentifier; exactly one certificate."""
        k = TKey("ec", b"verifier2 ski", P256)
        c = tcert(k, "SKI", ski=b"\x01" * 20)
        self.assertEqual(assess(ttoken(b"s", k, c, sid=b"\x01" * 20), b"s", [c])["step5"], "holds")
        self.assertEqual(assess(ttoken(b"s", k, c, sid=b"\x02" * 20), b"s", [c])["step5"], "not_performable")
        c2 = tcert(k, "SKI", ski=b"\x01" * 20, serial=9)
        self.assertEqual(assess(ttoken(b"s", k, c, sid=b"\x01" * 20, carried=[c, c2]), b"s", [c])["step5"], "not_performable")

    def test_7_5_6_Z6(self):
        """Z.6: at least one of signingCertificate (SHA-1 certHash, an identifier) and signingCertificateV2 (SHA-256 by
        default, else SHA-2), each at most once with one value, certs[0] naming the signer, issuerSerial matching if
        present; a V2 with another hash is not compared (not checkable); never grammar T, never step 5b."""
        a = self.a
        a_signer, other = a.signer, a.root
        def z6(**kw): r = assess(a.token(b"s", **kw), b"s", [a.root]); self.assertEqual(r["step5"], "holds"); return r["z6"]
        for why, kw, want in (("v2", {}, "holds"), ("v1", {"ess": "v1"}, "holds"), ("both", {"ess": "both"}, "holds"), ("none", {"ess": None}, "violated"),
                              ("v2 SHA-384", {"ess": ess_v2(a_signer, V.H384)}, "holds"), ("v2 SHA-512", {"ess": ess_v2(a_signer, V.H512)}, "holds"),
                              ("v2 SHA-256 written out", {"ess": ess_v2(a_signer, alg=_alg(V.H256))}, "holds"),
                              ("v2 other certificate", {"ess": ess_v2(other)}, "violated"),
                              ("v1 other certificate beside a good v2", {"ess": "v2", "extra_attrs": [ess_v1(other)]}, "violated"),
                              ("v2 twice", {"ess": "v2", "extra_attrs": [ess_v2(a_signer)]}, "violated"),
                              ("v2 two values", {"ess": _seq(_oid(V.A_ESS2), _set(*[V.der_seq(V.der(ess_v2(a_signer), 0x30))[1][2]] * 2))}, "violated"),
                              ("issuerSerial matching", {"ess": ess_v2(a_signer, issuer_serial=issuer_serial(a_signer))}, "holds"),
                              ("issuerSerial other serial", {"ess": ess_v2(a_signer, issuer_serial=issuer_serial(a_signer, 99))}, "violated"),
                              ("v2 with SHA-1", {"ess": ess_v2(a_signer, V.SHA1, alg=_alg(V.SHA1))}, "not_checkable"),
                              ("v2 with SHA-1 and a v1 naming the signer", {"ess": "v1", "extra_attrs": [ess_v2(a_signer, V.SHA1, alg=_alg(V.SHA1))]}, "not_checkable"),
                              ("v2 with SHA-1 and a v1 naming another", {"ess": ess_v1(other), "extra_attrs": [ess_v2(a_signer, V.SHA1, alg=_alg(V.SHA1))]}, "violated"),
                              ("certs empty", {"ess": _seq(_oid(V.A_ESS2), _set(_seq(_seq())))}, "violated"),
                              ("value not DER", {"ess": _seq(_oid(V.A_ESS2), _set(_tl(0x30, b"\x30\x81\x02\x04\x00")))}, "violated")):
            with self.subTest(why): self.assertEqual(z6(**kw), want)
        # T.6 (60aa776a): the value of a Name attribute is one TLV; an issuerSerial naming an issuer whose attribute value
        # is in constructed form binds the signer like any other
        cn = _seq(_set(_seq(_oid("2.5.4.3"), _tl(0x2c, _tl(0x0c, b"Probe Root")))))
        tbs = _seq(_tl(0xa0, _int(2)), _int(7), _alg("1.2.840.113549.1.1.11", b"\x05\x00"), cn, _seq(_time("20200101000000Z"), _time("20450101000000Z")),
                   _name("Probe TSA 1.10"), a.sk.spki(), _tl(0xa3, _seq(_ext(V.X_EKU, _seq(_oid(V.EKU_TS))))))
        cert = _seq(tbs, _alg("1.2.840.113549.1.1.11", b"\x05\x00"), _tl(0x03, b"\x00" + a.rk.sign(tbs, "rsa256")[1]))
        r = assess(ttoken(b"s", a.sk, cert, carried=[cert], ess=ess_v2(cert, issuer_serial=issuer_serial(cert))), b"s", [a.root])
        self.assertEqual((r["step5"], r["z6"]), ("holds", "holds"))

    def test_7_5_6_Z6_grammar_read_element_by_element(self):
        """Z.6 (7.5.6) reads SigningCertificate(V2) ::= SEQUENCE { certs, policies OPTIONAL } element by element: every
        element of certs is an ESSCertID(v2), also where only certs[0] is compared; of policies only the outer TLV is
        checked (T.6); in GeneralNames an element A4 holds exactly one Name after Z.1, of every other element only the
        outer TLV is read. A [4] inside an otherName value or inside policies is no directoryName."""
        a = self.a
        iss, ser = _iss_ser(a.signer)
        ident = lambda c=a.signer, *tail: _seq(_tl(0x04, hashlib.sha256(c).digest()), *tail)         # ESSCertIDv2, SHA-256 omitted
        isr = lambda *gns: _seq(_seq(*gns), _int(ser))
        v2 = lambda *parts: _seq(_oid(V.A_ESS2), _set(_seq(*parts)))
        v1 = lambda *ids: _seq(_oid(V.A_ESS), _set(_seq(_seq(*ids))))
        v1_ident = _seq(_tl(0x04, hashlib.sha1(a.signer).digest()))
        def z6(ess): r = assess(a.token(b"s", ess=ess), b"s", [a.root]); self.assertEqual(r["step5"], "holds"); return r["z6"]
        for why, ess, want in (
                ("second element of certs not an ESSCertIDv2", v2(_seq(ident(), _seq(_int(1)))), "violated"),
                ("second element of certs naming another certificate (not compared)", v2(_seq(ident(), ident(a.root))), "holds"),
                ("second element of certs with a directoryName that is not a Name", v2(_seq(ident(), ident(a.root, isr(_tl(0xa4, _tl(0x04, b"x")))))), "violated"),
                ("v1: second element of certs not an ESSCertID", v1(v1_ident, _seq(_int(1))), "violated"),
                ("policies with content not DER", v2(_seq(ident()), _seq(_seq(_oid("1.2.3"), _seq(_seq(_oid("1.2.4"), b"\x02\x02\x00\x01"))))), "holds"),
                ("policies with a length in long form below 128 inside", v2(_seq(ident()), _seq(b"\x30\x81\x04\x06\x02\x2a\x03")), "holds"),
                ("policies, its outer length in long form below 128", v2(_seq(ident()), b"\x30\x81\x04\x06\x02\x2a\x03"), "violated"),
                ("policies not a SEQUENCE", v2(_seq(ident()), _set(_oid("1.2.3"))), "violated"),
                ("[4] inside a policy qualifier", v2(_seq(ident()), _seq(_seq(_oid("1.2.3"), _seq(_seq(_oid("1.2.4"), _tl(0xa4, _tl(0x04, b"x"))))))), "holds"),
                ("[4] inside an otherName value", v2(_seq(ident(a.signer, isr(_tl(0xa0, _oid("1.2.3.5"), _tl(0xa0, _tl(0xa4, _tl(0x04, b"x")))), _tl(0xa4, iss))))), "holds"),
                ("an A4 GeneralName whose content is not a Name", v2(_seq(ident(a.signer, isr(_tl(0xa4, _tl(0x04, b"kein Name")), _tl(0xa4, iss))))), "violated"),
                ("an A4 GeneralName whose Name has an empty RDN", v2(_seq(ident(a.signer, isr(_tl(0xa4, _seq(_set())), _tl(0xa4, iss))))), "violated"),
                ("an A4 GeneralName with a byte after its Name", v2(_seq(ident(a.signer, isr(_tl(0xa4, iss + b"\x00"))))), "violated"),
                ("a matching directoryName after a uniformResourceIdentifier", v2(_seq(ident(a.signer, isr(_tl(0x86, b"http://tsa.invalid"), _tl(0xa4, iss))))), "holds"),
                ("a uniformResourceIdentifier only", v2(_seq(ident(a.signer, isr(_tl(0x86, b"http://tsa.invalid"))))), "violated"),
                ("GeneralNames without an element", v2(_seq(ident(a.signer, isr()))), "violated"),
                ("IssuerSerial with a third element", v2(_seq(ident(a.signer, _seq(_seq(_tl(0xa4, iss)), _int(ser), _int(1))))), "violated"),
                ("serialNumber not minimal", v2(_seq(ident(a.signer, _seq(_seq(_tl(0xa4, iss)), b"\x02\x02\x00" + _int(ser)[2:])))), "violated")):
            with self.subTest(why): self.assertEqual(z6(ess), want)

    def test_7_5_6_rule_QS(self):
        """Rule QS: absent, present, malformed or unusable, from the extensions [1] alone; an explicitly written critical
        00 accepted; never a search for bytes (a nonce may carry them); never a finding."""
        qc = lambda crit=b"", stmts=None: _seq(_oid(V.QC_STATEMENTS), crit, _tl(0x04, _seq(*(stmts if stmts is not None else [_seq(_oid(V.QTST))]))))
        for why, exts, tail, want in (("no [1]", None, b"", "absent"), ("qcStatements", [qc()], b"", "present"),
                                      ("critical FF", [qc(_tl(0x01, b"\xff"))], b"", "present"), ("critical 00 written out", [qc(_tl(0x01, b"\x00"))], b"", "present"),
                                      ("another statement only", [qc(stmts=[_seq(_oid("0.4.0.1862.1.1"))])], b"", "absent"),
                                      ("statement with info", [qc(stmts=[_seq(_oid(V.QTST), _seq(_oid("1.2.3")))])], b"", "present"),
                                      ("no statement", [qc(stmts=[])], b"", "absent"),
                                      ("SEQUENCE { INTEGER 1 }", [qc(stmts=[_seq(_int(1))])], b"", "malformed"),
                                      ("three elements", [qc(stmts=[_seq(_oid(V.QTST), _int(1), _int(2))])], b"", "malformed"),
                                      ("unknown critical beside", [qc(), _ext("1.2.3.4", _int(1))], b"", "unusable"),
                                      ("unknown not critical beside", [qc(), _ext("1.2.3.4", _int(1), False)], b"", "present"),
                                      ("not DER inside an extension no rule reads (T.6)", [qc(), _ext("1.2.3.4", b"\x02\x02\x00\x01", False)], b"", "present"),
                                      ("an extension no rule reads, its length not minimal", [qc(), _ext("1.2.3.4", b"\x02\x81\x01\x01", False)], b"", "unusable"),
                                      ("not DER inside qcStatements", [_seq(_oid(V.QC_STATEMENTS), _tl(0x04, _tl(0x30, _tl(0x30, b"\x06\x81\x07" + bytes.fromhex("04008197 5e0101".replace(" ", ""))))))], b"", "malformed"),
                                      ("critical 00 written out elsewhere", [_seq(_oid("1.2.3.4"), _tl(0x01, b"\x00"), _tl(0x04, _int(1))), qc()], b"", "present"),
                                      ("critical 01", [qc(_tl(0x01, b"\x01"))], b"", "unusable"), ("empty [1]", [], b"", "unusable"),
                                      ("qcStatements twice", [qc(), qc()], b"", "unusable"),
                                      ("extnValue with a byte after it", [_seq(_oid(V.QC_STATEMENTS), _tl(0x04, _seq(_seq(_oid(V.QTST))) + b"\x00"))], b"", "unusable"),
                                      ("nonce carrying the identifier", None, _tl(0x02, bytes.fromhex("0607040081975e0101")), "absent")):
            with self.subTest(why):
                t = V.t_read(self.a.token(b"s", exts=exts, tst_extra=tail))
                self.assertEqual(V.qs(t["extensions"]), want)

    def test_7_5_6_QS_item_4_7_5_2_T6_qcStatements_content_not_DER_is_malformed(self):
        """Decision L (7.5.6 rule QS, 7.5.2 T.6): of the extnValue of qcStatements item 2 checks only the outer TLV;
        content inside it that is not DER is "malformed" after item 4, not "unusable" after item 2. A violation of the
        outer TLV stays unusable, and item 3 (an unknown critical extension) is still decided first."""
        qid = _oid(V.QTST)                                                   # 06 07 04 00 81 97 5E 01 01
        qc = lambda value: _seq(_oid(V.QC_STATEMENTS), _tl(0x04, value))
        for why, exts, want in (("a QCStatement with a length in long form below 128", [qc(_tl(0x30, b"\x30\x81\x09" + qid))], "malformed"),
                                ("statementId with a length in long form below 128", [qc(_seq(_seq(b"\x06\x81\x07" + qid[2:])))], "malformed"),
                                ("statementId with a subidentifier not minimal", [qc(_seq(_seq(_tl(0x06, b"\x04\x80\x00\x81\x97\x5e\x01\x01"))))], "malformed"),
                                ("a QCStatement with an indefinite length", [qc(_tl(0x30, b"\x30\x80" + qid + b"\x00\x00"))], "malformed"),
                                ("a QCStatement that is primitive", [qc(_tl(0x30, _tl(0x10, qid)))], "malformed"),
                                ("the same with an unknown critical extension beside it", [qc(_tl(0x30, b"\x30\x81\x09" + qid)), _ext("1.2.3.4", _int(1))], "unusable"),
                                ("the outer TLV of the extnValue with a length in long form below 128", [qc(b"\x30\x81\x0b" + _seq(qid))], "unusable"),
                                ("the outer TLV of the extnValue with a byte after it", [qc(_seq(_seq(qid)) + b"\x00")], "unusable"),
                                ("statementInfo is not evaluated: only its outer TLV is read", [qc(_seq(_seq(qid, _tl(0x30, b"\x02\x02\x00\x01"))))], "present"),
                                ("well formed", [qc(_seq(_seq(qid)))], "present")):
            with self.subTest(why):
                self.assertEqual(V.qs(V.t_read(self.a.token(b"s", exts=exts))["extensions"]), want)

    def test_7_5_7_day_token_column(self):
        """7.5.7, column for day time stamps, in table order: defective, unconfirmed or confirmed with the case of the
        registry; a published test key (SPKI SHA-256) confirms nothing."""
        a, ts = self.a, V.test_spki(self.reg)
        def state(tok, data=b"s", roots=(), spki=ts):
            roots = [V.Cert(r) for r in roots]
            return V.day_token_state(V.ts_assess(tok, data, roots), roots, spki)
        self.assertEqual(state(a.token(b"s") + b"\x00"), ("defective", "b64_size_or_grammar_t"))
        self.assertEqual(state(a.token(b"x"), roots=[a.root]), ("defective", "imprint_wrong"))
        self.assertEqual(state(a.token(b"s", attrs=False), roots=[a.root]), ("unconfirmed", "step_5_not_performable"))
        self.assertEqual(state(flip_last(a.token(b"s")), roots=[a.root]), ("defective", "step_5_failed"))
        self.assertEqual(state(a.token(b"s", ess=None), roots=[a.root]), ("defective", "z6_failed"))
        self.assertEqual(state(a.token(b"s", ess=ess_v2(a.signer, V.SHA1, alg=_alg(V.SHA1))), roots=[a.root]), ("unconfirmed", "z6_not_checkable"))
        self.assertEqual(state(a.token(b"s")), ("unconfirmed", "no_path_to_root_of_purpose"))
        self.assertEqual(state(a.token(b"s"), roots=[self.cert]), ("unconfirmed", "no_path_to_root_of_purpose"))
        self.assertEqual(state(a.token(b"s"), roots=[a.root]), ("confirmed", None))
        self.assertEqual(state(a.token(b"s"), roots=[a.root], spki={V.Cert(a.root).spki_sha256}), ("unconfirmed", "published_test_key"))
        self.assertEqual(state(a.token(b"s"), roots=[a.root], spki={V.Cert(a.signer).spki_sha256}), ("unconfirmed", "published_test_key"))
        self.assertEqual(state(a.token(b"s"), roots=[a.root, a.signer], spki={V.Cert(a.root).spki_sha256}), ("confirmed", None))
        self.assertEqual(state(a.token(b"s", exts=[]), roots=[a.root]), ("confirmed", None))       # rule QS never decides a day token
        with open(os.path.join(VEKTOREN, "zeitstempel_timestamp_ess_both.wurzel.pem"), encoding="latin-1") as fh: corpus_root = V.strict_pem(fh.read())
        with open(os.path.join(VEKTOREN, "zeitstempel_timestamp_ess_both.token.der"), "rb") as fh: tok = fh.read()
        with open(os.path.join(VEKTOREN, "zeitstempel_timestamp_ess_both.daten.json"), "rb") as fh: data = fh.read()
        self.assertEqual(V.day_token_state(V.ts_assess(tok, data, corpus_root), corpus_root, ts), ("unconfirmed", "published_test_key"))
        self.assertEqual({k["spki_sha256"] for k in self.reg["verifier"]["timestamp_profile"]["published_test_keys"] if "spki_sha256" in k}, ts)
        self.assertIn(corpus_root[0].spki_sha256, ts)

    def test_7_5_no_flipped_byte_yields_a_confirmed_stamp(self):
        """Every byte of a token flipped is refused by grammar T or the imprint, breaks the signature, or makes the
        signature not performable or the path fail - no flipped byte passes as confirmed."""
        tok, roots = self.a.token(b"s"), [V.Cert(self.a.root)]
        self.assertEqual(V.day_token_state(V.ts_assess(tok, b"s", roots), roots, set()), ("confirmed", None))
        for i in range(len(tok)):
            b = bytearray(tok); b[i] ^= 0xff
            st = V.day_token_state(V.ts_assess(bytes(b), b"s", roots), roots, set())
            self.assertNotEqual(st[0], "confirmed", f"byte {i} flipped still confirms")


class TimeWitness110(Spec19):
    """Format spec 7.3 as amended for 1.10: steps 1 to 6 of a TIME_ANCHOR after the profile, the findings of the table
    in 7.3, NO_ANCHOR only when steps 1 to 4 fail, and roots of the purpose chain only (7.5.7)."""

    @classmethod
    def setUpClass(cls): cls.a = TSA()

    def run_tsa(self, chain, roots=(), inputs=None, **kw):
        self.n += 1
        pkg = chain.write(os.path.join(self.tmp, "pkg%d" % self.n), **kw)
        self.res = V.verify(pkg, self.reg, at_ms(chain.t + 3), 24.0, [], vendor_keys=PIN, tsa_roots=[V.Cert(r) for r in roots], inputs=inputs)
        return V.exit_code(self.res, self.reg["verifier"]["finding_classes"]), self.classes(self.res.findings)

    def chain(self, **kw):
        c = Chain(OWN); c.tick(); cp = c.anchor()
        witness(c, cp, **{"key": self.a.sk, "cert": self.a.signer, "carried": [self.a.signer], **kw})
        return c.close()

    def detail(self, cls): return " ".join(f["detail"] for f in self.res.findings if f["class"] == cls)

    def test_7_3_steps_1_to_6(self):
        a = self.a
        self.assertEqual(self.run_tsa(self.chain(), [a.root]), (0, []))
        self.assertEqual(self.run_tsa(self.chain(), [a.signer]), (0, []))                       # k = 0: the signer is the root
        self.assertEqual(self.run_tsa(self.chain()), (1, ["TIME_ANCHOR_UNVERIFIED"]))           # step 6: no root
        self.assertIn("7.3 step 6", self.detail("TIME_ANCHOR_UNVERIFIED"))
        # step 1: checkpoint_seq names no checkpoint with these values
        c = Chain(OWN); c.tick(); cp = c.anchor(); e = witness(c, cp, key=a.sk, cert=a.signer)
        c.entries[-1]["payload"]["tree_size"] = 1; c.entries[-1]["entry_hash"] = V.entry_hash(c.entries[-1]); c.close()
        self.assertEqual(self.run_tsa(c, [a.root]), (2, ["TIME_ANCHOR_INVALID"]))
        # step 2: B64, size, grammar T -> INVALID, and the witness binds nothing (NO_ANCHOR without another anchor)
        for why, kw in (("line break", {"b64": base64.encodebytes(a.token(b"x")).decode()}), ("BER length", {"tamper": lambda d: d[:1] + b"\x83\x00" + d[2:]}),
                        ("trailing zero in genTime", {"gentime": "20260101004001.120Z", "tsa_ts": "2026-01-01T00:40:01.120Z"}),
                        ("two SignerInfos", {"signers": 2}), ("SHA-1 imprint", {"imprint": V.SHA1})):
            with self.subTest(why):
                c = Chain(OWN); c.tick(); cp = c.checkpoint(); witness(c, cp, key=a.sk, cert=a.signer, **kw); c.seal()
                self.assertEqual(self.run_tsa(c, [a.root]), (2, ["NO_ANCHOR", "TIME_ANCHOR_INVALID"]))
        # step 3: the readings; tsa_ts is genTime cut, never rounded, in the form YYYY-MM-DDThh:mm:ss.sssZ
        g = "20260101004001.123999999Z"
        self.assertEqual(self.run_tsa(self.chain(gentime=g), [a.root]), (0, []))
        self.assertEqual(self.res.time_anchors[0]["assessment"]["t"]["gen_time_ms"], "2026-01-01T00:40:01.123Z")
        for why, kw in (("rounded", {"tsa_ts": "2026-01-01T00:40:01.124Z"}), ("without milliseconds", {"tsa_ts": "2026-01-01T00:40:01Z"}),
                        ("microseconds", {"tsa_ts": "2026-01-01T00:40:01.123999Z"}), ("serial", {"tsa_serial": "2b"}),
                        ("serial upper case", {"tsa_serial": "2A"}), ("policy", {"tsa_policy": "1.2.3"})):
            with self.subTest(why):
                self.assertEqual(self.run_tsa(self.chain(gentime=g, **kw), [a.root]), (2, ["TIME_ANCHOR_INVALID"]))
                self.assertIn("7.3 step 3", self.detail("TIME_ANCHOR_INVALID"))
        # step 4: the imprint over another subject
        c = Chain(OWN); c.tick(); cp = c.anchor(); witness(c, cp, key=a.sk, cert=a.signer, tamper=lambda d: d.replace(hashlib.sha256(subject_of(cp)).digest(), bytes(32)))
        c.close()
        self.assertEqual(self.run_tsa(c, [a.root]), (2, ["TIME_ANCHOR_INVALID"]))
        # step 5b fails: INVALID, yet the witness is a present anchor (steps 1 to 4 hold): no NO_ANCHOR
        c = Chain(OWN); c.tick(); cp = c.checkpoint(); witness(c, cp, key=a.sk, cert=a.signer, tamper=flip_last); c.seal()
        self.assertEqual(self.run_tsa(c, [a.root]), (2, ["TIME_ANCHOR_INVALID"]))
        self.assertIn("7.3 step 5b", self.detail("TIME_ANCHOR_INVALID"))
        # step 5a: not performable - UNVERIFIED with the reason, never INVALID, and an anchor
        for why, kw in (("SHA-1 digestAlgorithm", {"digest": V.SHA1}), ("no certificates", {"carried": ()}), ("no signed attributes", {"attrs": False}),
                        ("key and algorithm", {"sigalg": _alg("1.2.840.113549.1.1.11", b"\x05\x00")})):
            with self.subTest(why):
                c = Chain(OWN); c.tick(); cp = c.checkpoint(); witness(c, cp, key=a.sk, cert=a.signer, **kw); c.seal()
                self.assertEqual(self.run_tsa(c, [a.root]), (1, ["TIME_ANCHOR_UNVERIFIED"]))
                self.assertIn("7.3 step 5a", self.detail("TIME_ANCHOR_UNVERIFIED"))

    def test_7_5_6_7_5_7_no_effect_on_the_finding(self):
        """Z.6, rule QS and published test keys never change the finding of a TIME_ANCHOR (7.5.6, 7.5.7)."""
        a = self.a
        qc = _seq(_oid(V.QC_STATEMENTS), _tl(0x04, _seq(_seq(_oid(V.QTST)))))
        for why, kw in (("Z.6 violated", {"ess": None}), ("Z.6 not checkable", {"ess": ess_v2(a.signer, V.SHA1, alg=_alg(V.SHA1))}),
                        ("QS present", {"exts": [qc]}), ("QS unusable", {"exts": []})):
            with self.subTest(why): self.assertEqual(self.run_tsa(self.chain(**kw), [a.root]), (0, []))
        corpus = os.path.join(VEKTOREN, "timestamp_chain_root")
        code, j, err = self.cli(corpus, "--json", "--now-from-package", *vector_anchors(), "--tsa-root", os.path.join(VEKTOREN, "pruefer_timestamp_chain_root.tsa_root-1.pem"))
        self.assertEqual((code, j["finding_classes"]), (0, []), err)       # the root is a published test key: still no finding

    def test_7_5_7_purposes_of_roots(self):
        """A root counts only for the purposes the auditor gives it: --vendor-log-tsa-root (log) never confirms a time
        witness; a root of --tsa-qualified-roots carries chain too, also outside its qualified period (10.8)."""
        a = self.a
        pkg = self.pkg(self.chain())
        root_pem = write_pem(os.path.join(self.tmp, "root.pem"), a.root)
        q = os.path.join(self.tmp, "q.json")
        with open(q, "w") as fh: json.dump({"format": "ledger-tsa-qualifiziert/1", "stand": "2026-10-01T00:00:00Z", "quelle": "test",
                                            "wurzeln": [{"zertifikat": base64.b64encode(a.root).decode(), "qualifiziert_ab": "2030-01-01T00:00:00Z"}]}, fh)
        now = iso(T0 + 3600)
        self.assertEqual(self.cli(pkg, "--now", now, "--vendor-log-tsa-root", root_pem)[0], 1)
        self.assertEqual(self.cli(pkg, "--now", now, "--tsa-root", root_pem)[0], 0)
        self.assertEqual(self.cli(pkg, "--now", now, "--tsa-qualified-roots", q)[0], 0)
        self.assertEqual(self.cli(pkg, "--now", now, "--tsa-root", root_pem, "--vendor-log-tsa-root", root_pem)[0], 0)

    def test_7_3_package_certificate_is_no_root(self):
        """keys/tsa/ of the package never anchors; the report names the authority when a path reaches one (7.3)."""
        c = self.chain()
        self.assertEqual(self.run_tsa(c, extra={"keys/tsa/probe.pem": pem(self.a.root)}), (1, ["TIME_ANCHOR_UNVERIFIED"]))
        self.assertIn("keys/tsa/", self.detail("TIME_ANCHOR_UNVERIFIED"))
        self.assertEqual(self.run_tsa(c, extra={"keys/tsa/probe.pem": "no PEM"}), (1, ["TIME_ANCHOR_UNVERIFIED"]))
        self.assertNotIn("keys/tsa/", self.detail("TIME_ANCHOR_UNVERIFIED"))
        self.assertEqual(self.run_tsa(c, [self.a.root], extra={"keys/tsa/probe.pem": pem(self.a.root)}), (0, []))

    def test_7_3_frozen_vectors(self):
        """The two frozen witnesses of 1.3: valid_time_anchor (OpenSSL token, RSA) and tamper_time_anchor."""
        pkg = os.path.join(VEKTOREN, "valid_time_anchor")
        code, j, err = self.cli(pkg, "--json", "--now-from-package", *vector_anchors())
        self.assertEqual((code, j["finding_classes"]), (4, ["TIME_ANCHOR_UNVERIFIED", "UNSEALED_END"]), err)
        self.assertIn("keys/tsa/", " ".join(f["detail"] for f in j["findings"]))
        code, j, err = self.cli(pkg, "--json", "--now-from-package", *vector_anchors(), "--tsa-root", PROBE)
        self.assertEqual((code, j["finding_classes"]), (4, ["UNSEALED_END"]), err)
        code, j, err = self.cli(os.path.join(VEKTOREN, "tamper_time_anchor"), "--json", "--now-from-package", *vector_anchors(), "--tsa-root", PROBE)
        self.assertEqual((code, j["finding_classes"]), (2, ["TIME_ANCHOR_INVALID", "UNSEALED_END"]), err)


def role_entry(kid, seed, rolle, ab="2025-01-01T00:00:00Z", **opt):
    return {"key_id": kid, "pubkey": pubkey(seed).hex(), "rolle": rolle, "gueltig_ab": ab, **opt}


def role_list(entries, version=1, ausgestellt="2025-12-30T10:00:00.000Z", ende=None, root_id="wurzel-test", seed=ROOT_SEED, extra=None, sig_body=None):
    """A role list ledger-schluesselrollen/1 (10.7.2) signed by the test root."""
    body = {"format": "ledger-schluesselrollen/1", "version": version, "ausgestellt": ausgestellt, "schluessel": entries, **(extra or {})}
    if ende is not None: body["ende_doppelbetrieb"] = ende
    return dict(body, signatur={"wurzel_id": root_id, "sig": sign(seed, V.jcsb(sig_body or body)).hex()})


def proto_list(keys, version=1, log_id="ledger-testprotokoll-1", erster_tag="2025-12-31", root_id="wurzel-test", seed=ROOT_SEED, **over):
    """A protocol key list ledger-protokollschluessel/1 (7.4.7) signed by the test root."""
    body = {"format": "ledger-protokollschluessel/1", "version": version, "ausgestellt": "2025-12-30T10:00:00.000Z", "log_id": log_id,
            "erster_tag": erster_tag, "fuellerbindung": "82" * 32, "orte": ["https://a.example/x", "https://b.example/x"],
            "schluessel": [{"key_id": k, "pubkey": pubkey(s).hex(), "gueltig_ab": "2025-12-30T00:00:00.000Z"} for k, s in keys], **over}
    return dict(body, signatur={"wurzel_id": root_id, "sig": sign(seed, V.jcsb(body)).hex()})


STMT_SEED, STMT2_SEED, UPD_SEED, LOG_SEED, CS2_SEED = (bytes([x] * 32) for x in (101, 102, 103, 104, 105))


class KeyRoles110(Spec19):
    """Format spec 10.7.2 to 10.7.5 (1.10): the role list ledger-schluesselrollen/1, the role check R1 to R4 with the
    protocol key list of 7.4.7 (P, step L1), the receipts with dropped pins and the report object key_roles (10.10.2)."""

    def inputs(self, *lists, cs=None, st=None, lg=None, roots=None):
        i = V.AuditorInputs(roots if roots is not None else {"wurzel-test": pubkey(ROOT_SEED).hex()}, PIN if cs is None else cs)
        i.statement_pins, i.log_pins = dict(st or {}), dict(lg or {})
        i.key_lists = [(x["format"], x, json.dumps(x).encode()) for x in lists]
        return i

    def kr(self, *lists, kcs=(), **kw):
        return V.finish_key_roles(V.key_roles(self.inputs(*lists, **kw), set(kcs), self.reg)["report"], False)

    def base(self):
        return [role_entry("vendor-1", VENDOR_SEED, "countersigning"), role_entry("st-1", STMT_SEED, "statements"),
                role_entry("st-2", STMT2_SEED, "statements"), role_entry("upd-1", UPD_SEED, "update_manifest")]

    def test_10_7_2_reference_values(self):
        """The signed bytes of the role list of version 1 (10.7.2): 1221 bytes with SHA-256 0faf73e6..., and the
        signature of testwurzel-1 over them holds against the corpus root."""
        ex = self.reg["key_role_list"]["example"]
        body = json.loads(ex["signed_bytes"])
        self.assertEqual(V.jcs(body), ex["signed_bytes"])
        self.assertEqual((len(V.jcsb(body)), hashlib.sha256(V.jcsb(body)).hexdigest()), (1221, "0faf73e6f479e1c54d1f95933cbe81c18208b2963d007ee51fc6812d02fa6552"))
        with open(os.path.join(VEKTOREN, "pruefer_herstellerwurzel.json")) as fh: w = json.load(fh)
        lst = dict(body, signatur={"wurzel_id": ex["wurzel_id"], "sig": ex["sig"]})
        self.assertEqual((ex["wurzel_id"], V.role_list(lst, {w["wurzel_id"]: w["pubkey"]})), (w["wurzel_id"], ("", "")))
        self.assertEqual(V.role_list(lst, {w["wurzel_id"]: pubkey(ROOT_SEED).hex()})[0], "signature")

    def test_10_7_2_format_rules(self):
        """Each rule of 10.7.2 makes the list ineffective with the reason format, never exit 3; no_matching_root and
        signature for the other failures; the reason of the candidate that came furthest (10.7.4)."""
        ok = role_list(self.base())
        self.assertEqual(self.kr(ok)["status"], "effective")
        bad = {"extra member on top": role_list(self.base(), extra={"kommentar": "x"}), "extra member in an entry": role_list(self.base()[:1] + [dict(self.base()[1], kommentar="x")]),
               "rolle protocol": role_list(self.base() + [role_entry("log-x", LOG_SEED, "protocol")]),
               "rolle grammar": role_list(self.base() + [role_entry("x", LOG_SEED, "Statements")]),
               "key_id twice": role_list(self.base() + [role_entry("st-1", LOG_SEED, "statements")]),
               "pubkey twice": role_list(self.base() + [role_entry("st-9", STMT_SEED, "statements")]),
               "names the root": role_list(self.base() + [role_entry("r", ROOT_SEED, "statements")]),
               "gueltig_bis not after gueltig_ab": role_list([role_entry("st-1", STMT_SEED, "statements", gueltig_bis="2025-01-01T00:00:00Z")]),
               "version 0": role_list(self.base(), version=0), "ausgestellt no rfc3339": role_list(self.base(), ausgestellt="2025-12-30 10:00:00Z"),
               "ende_doppelbetrieb no rfc3339": role_list(self.base(), ende="2026-07-01"), "no entry": role_list([]),
               "a value not a string": role_list([dict(self.base()[0], widerrufen_ab=1)])}
        for why, lst in bad.items():
            with self.subTest(why):
                r = self.kr(lst)
                self.assertEqual((r["status"], r["reason"], r["list"]), ("not_effective", "format", None))
        self.assertEqual(self.kr(role_list(self.base(), root_id="wurzel-x"))["reason"], "no_matching_root")
        self.assertEqual(self.kr(role_list(self.base(), seed=DEV_SEED))["reason"], "signature")
        r = self.kr(bad["rolle protocol"], role_list(self.base(), seed=DEV_SEED))
        self.assertEqual((r["reason"], r["candidates"]), ("signature", 2))
        self.assertEqual(self.kr(ok, ok)["candidates"], 1)                  # distinct by their JCS bytes (R1)

    def test_10_7_4_R2_selection(self):
        """R2: the counting list of the largest version; same version with other bytes, a dropped entry, or a changed
        or dropped ende_doppelbetrieb (compared as strings): lists_contradictory, and no smaller version steps in."""
        v1, v2 = role_list(self.base()), role_list(self.base() + [role_entry("st-3", CS2_SEED, "statements")], version=2)
        r = self.kr(v1, v2)
        self.assertEqual((r["status"], r["list"]["version"]), ("effective", 2))
        for why, lists in (("same version", [v1, role_list(self.base(), ausgestellt="2025-12-31T10:00:00.000Z")]),
                           ("entry dropped", [v1, role_list(self.base()[:2], version=2)]),
                           ("ende differs as a string", [role_list(self.base(), version=2, ende="2026-07-01T00:00:00Z"), role_list(self.base(), version=3, ende="2026-07-01T00:00:00.000Z")]),
                           ("ende dropped", [role_list(self.base(), version=2, ende="2026-07-01T00:00:00Z"), role_list(self.base(), version=3)])):
            with self.subTest(why): self.assertEqual((self.kr(*lists)["status"], self.kr(*lists)["reason"]), ("not_effective", "lists_contradictory"))
        r = self.kr(role_list(self.base(), version=1), role_list(self.base(), version=2, ende="2026-07-01T00:00:00Z"))
        self.assertEqual(r["list"], {"version": 2, "ausgestellt": "2025-12-30T10:00:00.000Z", "wurzel_id": "wurzel-test", "root_source": "vendor_root",
                                     "ende_doppelbetrieb": "2026-07-01T00:00:00Z"})        # 10.7.5: the end of dual operation in the report
        r = self.kr(v1, role_list(self.base(), version=2, seed=DEV_SEED))  # a candidate that does not count is no contradiction
        self.assertEqual((r["status"], r["list"]["version"], r["candidates"]), ("effective", 1, 2))

    def test_10_7_4_R3_by_public_key(self):
        """R3 (a) to (d): a K_cs^L key with another role makes Q ineffective; Q and P sharing a key, neither; P sharing
        with a countersigning pin or K_cs^L, P; pins with a key of another role are dropped (listed_as)."""
        two = role_list([role_entry("vendor-1", VENDOR_SEED, "statements")])
        r = self.kr(two, kcs={pubkey(VENDOR_SEED).hex()})
        self.assertEqual((r["status"], r["reason"], r["pins_dropped"]), ("not_effective", "key_in_two_roles", []))     # (a): the pin stays
        r = self.kr(two, cs={"vendor-1": pubkey(VENDOR_SEED).hex()})
        self.assertEqual((r["status"], r["pins_dropped"], r["notes"]), ("effective", [{"key_id": "vendor-1", "pinned_as": "countersigning", "listed_as": "statements"}], ["pin_dropped"]))
        # (a) with a smaller version that counts: no fallback
        r = self.kr(role_list(self.base()), role_list(self.base() + [role_entry("cs-2", CS2_SEED, "statements")], version=2), kcs={pubkey(CS2_SEED).hex()})
        self.assertEqual((r["status"], r["reason"]), ("not_effective", "key_in_two_roles"))
        # (b) Q and P share a key: neither effective
        roles = V.key_roles(self.inputs(role_list(self.base()), proto_list([("log-1", STMT2_SEED)])), set(), self.reg)
        self.assertEqual((roles["report"]["reason"], roles["P"], roles["p_reason"]), ("key_in_two_roles", None, "key_in_two_roles"))
        # (b) does not read a Q that (a) removed: P stays effective
        roles = V.key_roles(self.inputs(role_list(self.base() + [role_entry("cs-2", CS2_SEED, "statements")]), proto_list([("log-1", STMT2_SEED)])), {pubkey(CS2_SEED).hex()}, self.reg)
        self.assertEqual((roles["report"]["reason"], roles["P"] is not None), ("key_in_two_roles", True))
        # (c) P with the key of a countersigning pin: P not effective, no role list -> not_supplied
        roles = V.key_roles(self.inputs(proto_list([("log-1", VENDOR_SEED)])), set(), self.reg)
        self.assertEqual((roles["report"]["status"], roles["P"], roles["p_reason"]), ("not_supplied", None, "key_in_two_roles"))
        roles = V.key_roles(self.inputs(proto_list([("log-1", LOG_SEED)])), set(), self.reg)
        self.assertEqual(roles["P"]["log_id"], "ledger-testprotokoll-1")
        # (d) pins of the three roles
        r = self.kr(role_list(self.base()), st={"vendor-1x": pubkey(UPD_SEED).hex(), "st-1": pubkey(STMT_SEED).hex(), "kcs": pubkey(CS2_SEED).hex()},
                    lg={"log-x": pubkey(STMT2_SEED).hex()}, kcs={pubkey(CS2_SEED).hex()})
        self.assertEqual(r["pins_dropped"], [{"key_id": "kcs", "pinned_as": "statements", "listed_as": "countersigning"},
                                             {"key_id": "log-x", "pinned_as": "protocol", "listed_as": "statements"},
                                             {"key_id": "vendor-1x", "pinned_as": "statements", "listed_as": "update_manifest"}])
        self.assertEqual(r["statement_keys"], [{"key_id": "st-1", "source": "pinned"}, {"key_id": "st-2", "source": "role_list"}])
        roles = V.key_roles(self.inputs(proto_list([("log-1", LOG_SEED)]), st={"s": pubkey(LOG_SEED).hex()}), set(), self.reg)
        self.assertEqual(roles["report"]["pins_dropped"], [{"key_id": "s", "pinned_as": "statements", "listed_as": "protocol"}])

    def test_10_7_4_unknown_role_and_notes(self):
        r = self.kr(role_list(self.base() + [role_entry("audit", CS2_SEED, "audit_log")]))
        self.assertEqual((r["status"], r["notes"]), ("effective", ["unknown_role"]))
        r = self.kr()
        self.assertEqual(r, {"status": "not_supplied", "reason": None, "candidates": 0, "list": None, "statement_keys": [], "pins_dropped": [], "notes": []})
        r = self.kr(st={"b": pubkey(STMT_SEED).hex(), "a": pubkey(STMT2_SEED).hex()})
        self.assertEqual(r["statement_keys"], [{"key_id": "a", "source": "pinned"}, {"key_id": "b", "source": "pinned"}])

    def test_7_1_10_7_4_receipts(self):
        """Receipts: only a countersigning pin that is not dropped and the package's list establish them; a dropped pin
        counts as not passed (RECEIPT_UNVERIFIED with the note receipt_key_other_role), never RECEIPT_INVALID; the role
        list never establishes a receipt (7.1)."""
        c = Chain(OWN); c.tick(); c.close()
        pkg = self.pkg(c)
        def run(*lists, **kw):
            res = V.verify(pkg, self.reg, at_ms(c.t + 3), 24.0, [], inputs=self.inputs(*lists, **kw))
            return V.exit_code(res, self.reg["verifier"]["finding_classes"]), self.classes(res.findings), res.key_roles
        code, cls, kr = run(role_list(self.base()))
        self.assertEqual((code, cls, kr["status"]), (0, [], "effective"))
        code, cls, kr = run(role_list([role_entry("vendor-1", VENDOR_SEED, "statements")]))
        self.assertEqual((code, cls, kr["notes"]), (1, ["RECEIPT_UNVERIFIED"], ["receipt_key_other_role", "pin_dropped"]))
        code, cls, kr = run(role_list(self.base()), cs={})                # the role list names vendor-1 countersigning, yet establishes nothing
        self.assertEqual((code, cls, kr["notes"]), (1, ["RECEIPT_UNVERIFIED"], []))
        code, cls, kr = run(cs={}, st={"x": pubkey(VENDOR_SEED).hex()})   # the manifest key is a statements pin
        self.assertEqual((code, cls, kr["notes"]), (1, ["RECEIPT_UNVERIFIED"], ["receipt_key_other_role"]))
        code, cls, kr = run(role_list(self.base(), version=1), role_list(self.base(), version=1, ausgestellt="2025-12-31T00:00:00Z"))
        self.assertEqual((code, cls, kr["reason"]), (0, [], "lists_contradictory"))
        # an auditor's list of countersigning keys establishes no receipt, it only joins K_cs^L
        lst = json.loads(vendor_list([{"key_id": "vendor-1", "pubkey": pubkey(VENDOR_SEED).hex(), "gueltig_ab": "2025-01-01T00:00:00Z"}]))
        code, cls, kr = run(lst, cs={})
        self.assertEqual((code, cls), (1, ["RECEIPT_UNVERIFIED"]))
        code, cls, kr = run(lst, role_list([role_entry("vendor-1", VENDOR_SEED, "statements")]))
        self.assertEqual((code, cls, kr["reason"]), (0, [], "key_in_two_roles"))
        # a format error leaves key_roles null (10.10.1)
        code, j, _ = self.cli(os.path.join(VEKTOREN, "format_broken_json"), "--json", "--now-from-package", *vector_anchors())
        self.assertEqual((code, j["key_roles"]), (3, None))
        code, j, _ = self.cli(os.path.join(VEKTOREN, "valid_sealed_shutdown"), "--json", "--now-from-package", *vector_anchors())
        self.assertEqual(j["key_roles"]["status"], "not_supplied")

    def test_7_4_7_protocol_list(self):
        """7.4.7 and L1 item 2: the protocol key list, its format, root and signature, and the selection among several."""
        roots = {"wurzel-test": pubkey(ROOT_SEED).hex()}
        self.assertEqual(V.protocol_list(proto_list([("log-1", LOG_SEED)]), roots), ("", ""))
        for why, lst, want in (("erster_tag out of the log range", proto_list([("l", LOG_SEED)], erster_tag="1999-12-31"), "format_violated"),
                               ("one place", proto_list([("l", LOG_SEED)], orte=["https://a.example/x"]), "format_violated"),
                               ("place without https", proto_list([("l", LOG_SEED)], orte=["http://a.example", "https://b.example"]), "format_violated"),
                               ("foreign root", proto_list([("l", LOG_SEED)], root_id="x"), "no_matching_root"),
                               ("signature", proto_list([("l", LOG_SEED)], seed=DEV_SEED), "signature_fails")):
            with self.subTest(why): self.assertEqual(V.protocol_list(lst, roots)[0], want)
        r = V.key_roles(self.inputs(proto_list([("l", LOG_SEED)]), proto_list([("l", LOG_SEED)], version=2, fuellerbindung="83" * 32)), set(), self.reg)
        self.assertEqual((r["P"], r["p_reason"]), (None, "lists_contradictory"))
        r = V.key_roles(self.inputs(proto_list([("l", LOG_SEED)]), proto_list([("m", LOG_SEED)], version=2)), set(), self.reg)
        self.assertEqual((r["P"], r["p_reason"]), (None, "lists_contradictory"))
        r = V.key_roles(self.inputs(proto_list([("l", LOG_SEED)]), proto_list([("l", LOG_SEED), ("m", CS2_SEED)], version=2)), set(), self.reg)
        self.assertEqual(r["P"]["version"], 2)

    def test_7_4_7_fuellerbindung_null_and_l1_once_set_unchanged(self):
        """7.4.4, 7.4.7: fuellerbindung is hex64 or null (a vendor that does not derive its fillers); 7.4.10 L1 item 2:
        no list is effective ("widerspruechliche Listen", lists_contradictory) when two counting candidates name different
        fuellerbindung other than null, or a counting candidate names null and one of a smaller version a value; a value
        set in a later version after null is no contradiction (once set, unchanged in every later version). Only counting
        candidates count, in any order of the inputs."""
        roots = {"wurzel-test": pubkey(ROOT_SEED).hex()}
        self.assertEqual(V.protocol_list(proto_list([("l", LOG_SEED)], fuellerbindung=None), roots), ("", ""))
        for bad in ("82" * 31, "AB" * 32, 5, "", True):
            with self.subTest(bad): self.assertEqual(V.protocol_list(proto_list([("l", LOG_SEED)], fuellerbindung=bad), roots)[0], "format_violated")
        P = lambda v, fb, **kw: proto_list([("l", LOG_SEED)], version=v, fuellerbindung=fb, **kw)
        A, B = "82" * 32, "83" * 32
        for why, lists, want in (("null then value", [P(1, None), P(2, A)], 2), ("value then null", [P(1, A), P(2, None)], None),
                                 ("two values", [P(1, None), P(2, A), P(3, B)], None), ("null, null", [P(1, None), P(2, None)], 2),
                                 ("same value", [P(1, A), P(2, A)], 2), ("null, value, same value", [P(1, None), P(2, A), P(3, A)], 3),
                                 ("value, null, value", [P(1, A), P(2, None), P(3, A)], None),
                                 ("a value of a list that does not count", [P(1, A, seed=DEV_SEED), P(2, None)], 2)):
            for order in (lists, lists[::-1]):
                with self.subTest(why, order=[x["version"] for x in order]):
                    r = V.key_roles(self.inputs(*order), set(), self.reg)
                    self.assertEqual((r["P"]["version"] if r["P"] else None, r["p_reason"]), (want, None if want else "lists_contradictory"))
        self.assertEqual(self.reg["protocol_key_list"]["fields"]["fuellerbindung"]["type"], "hex64?")

def extract(**over):
    """A minimal extract ledger-protokollauszug/1 (7.4.8)."""
    return {"format": "ledger-protokollauszug/1", "log_id": "ledger-testprotokoll-1", "chain_id": CHAIN, "protocol_keys": None,
            "days": [], "chain_days": [], **over}


def page(**over):
    return {"statement_jcs": "{}", "server_key_id": "st-1", "server_signature": "0" * 128, "statement": None, **over}


class AuditorInputs110(Spec19):
    """Format spec 10.8 (1.10): every auditor input read at invocation with its grammar and limits; a violation and
    every other usage error is an unusable invocation (exit 3, the reason on stderr, no report); a defect in the
    content of an input that keeps its grammar is never exit 3; the request time; ledger-pruefumgebung/1."""

    def setUp(self):
        super().setUp()
        c = Chain(OWN); c.tick(); c.close()
        self.c, self.p = c, self.pkg(c)
        self.now = iso(c.t + 3)

    def f(self, name, data):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as fh: fh.write(data if isinstance(data, bytes) else data.encode() if isinstance(data, str) else json.dumps(data).encode())
        return path

    def cli(self, *argv):
        """main() as the command line runs it: a usage error leaves through SystemExit with code 3 (10.8)."""
        try: return super().cli(*argv)
        except SystemExit as e: return e.code, "", ""

    def run3(self, *args, want=3):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try: code = vmain(["verifier2", self.p, "--now", self.now, "--json", *args, "--registry", REG_PATH, "--vendor-key", "vendor-1=" + pubkey(VENDOR_SEED).hex()])
            except SystemExit as e: code = e.code
        out, err = out.getvalue(), err.getvalue()
        self.assertEqual(code, want, (args, err))
        if want == 3: self.assertEqual((out, err.startswith("verifier2: unusable argument: ")), ("", True), err)
        return err

    def test_10_8_usage_errors(self):
        """Unknown switch, missing value, a switch given more often than allowed, an abbreviation: exit 3, never 2."""
        for args in (("--unknown",), ("--now",), ("--now", self.now), ("--lang", "de", "--lang", "en"), ("--requested-at", self.now, "--requested-at", self.now),
                     ("--tsa-qualified-roots", "a", "--tsa-qualified-roots", "b"), ("--now-from",), ("--freshness", "1h", "--freshness", "2h"), ("--freshness-hours", "24"),
                     ("--lang", "fr")):
            with self.subTest(args=args): self.run3(*args)
        for root in ("0:" + "a" * 64, "01:" + "a" * 64, "9007199254740992:" + "a" * 64, "a" * 63):
            with self.subTest(root=root): self.run3("--expect-root", root)
        self.run3("--expect-root", "9007199254740991:" + "a" * 64, want=2)   # within the grammar: a root not found is MERKLE_INCONSISTENT

    def test_10_8_strict_pem(self):
        """Strict PEM: CRLF, blanks and tabs at a line end, text outside blocks (lines with ':' too) and several blocks
        pass; another label, a header line inside a block, a block without end, no block, content not B64 or not
        exactly one certificate after Z.1 are an unusable invocation - also with --vendor-log-tsa-root."""
        cert = TSA().root
        b = base64.encodebytes(cert).decode().replace("\n", " \t\r\n")
        good = "# bundle\r\nComment: outside\r\n-----BEGIN CERTIFICATE-----\r\n" + b + "-----END CERTIFICATE-----  \r\n" + pem(cert)
        self.assertEqual(len(V.strict_pem(good)), 2)
        self.run3("--tsa-root", self.f("good.pem", good), want=0)
        for why, text in (("other label", pem(cert) + "-----BEGIN X509 CRL-----\nMAA=\n-----END X509 CRL-----\n"),
                          ("header line", pem(cert).replace("-----\n", "-----\nProc-Type: 4,ENCRYPTED\n", 1)),
                          ("no end", "-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(cert).decode()), ("no block", "text\n"), ("empty", ""),
                          ("not B64", "\n".join(x + "==" if i == 1 else x for i, x in enumerate(pem(cert).split("\n")))), ("a byte after the certificate", pem(cert + b"\x00")),
                          ("not Z.1", pem(tcert(TKey("ed", b"v1"), "v1", version=None, exts=[]))), ("leading blank in BEGIN", " " + pem(cert))):
            with self.subTest(why):
                if why == "leading blank in BEGIN": self.assertRaises(ValueError, V.strict_pem, text); continue
                self.run3("--tsa-root", self.f("bad.pem", text))
                self.run3("--vendor-log-tsa-root", self.f("bad.pem", text))
        self.run3("--tsa-root", self.f("good.pem", good), "--tsa-root", self.f("missing.pem", "") + ".nope")

    def test_10_8_qualified_roots_file(self):
        """ledger-tsa-qualifiziert/1: exactly its members, the certificate B64 and Z.1 with at most 16 384 bytes, the
        period with qualifiziert_bis after qualifiziert_ab, no certificate twice, at most 8 388 608 bytes, at most once."""
        cert = TSA().root
        w = {"zertifikat": base64.b64encode(cert).decode(), "qualifiziert_ab": "2025-01-01T00:00:00Z"}
        ok = {"format": "ledger-tsa-qualifiziert/1", "stand": "2026-10-01T00:00:00.5Z", "quelle": "EU-Vertrauensliste", "wurzeln": [w]}
        self.run3("--tsa-qualified-roots", self.f("q.json", ok), want=0)
        self.run3("--tsa-qualified-roots", self.f("q.json", dict(ok, wurzeln=[dict(w, qualifiziert_bis="2025-01-01T00:00:00.000000001Z")])), want=0)
        for why, d in (("format", dict(ok, format="ledger-tsa-qualifiziert/2")), ("member", dict(ok, kommentar="x")), ("member in wurzeln", dict(ok, wurzeln=[dict(w, x=1)])),
                       ("stand", dict(ok, stand="2026-10-01")), ("quelle empty", dict(ok, quelle="")), ("quelle 257", dict(ok, quelle="x" * 257)),
                       ("quelle control", dict(ok, quelle="a\u0085b")), ("no wurzeln", dict(ok, wurzeln=[])),
                       ("twice", dict(ok, wurzeln=[w, dict(w, qualifiziert_ab="2026-01-01T00:00:00Z")])),
                       ("bis equal ab", dict(ok, wurzeln=[dict(w, qualifiziert_bis="2025-01-01T00:00:00Z")])),
                       ("bis before ab", dict(ok, wurzeln=[dict(w, qualifiziert_bis="2024-01-01T00:00:00Z")])),
                       ("not B64", dict(ok, wurzeln=[dict(w, zertifikat=w["zertifikat"] + "\n")])),
                       ("byte after", dict(ok, wurzeln=[dict(w, zertifikat=base64.b64encode(cert + b"\x00").decode())])),
                       ("number 1.0", json.dumps(ok)[:-1] + ', "x": 1.0}')):
            with self.subTest(why): self.run3("--tsa-qualified-roots", self.f("q.json", d))
        self.run3("--tsa-qualified-roots", self.f("big.json", b" " * 8388609))

    def test_10_8_key_lists(self):
        """--vendor-key-list: I-JSON (no BOM, no member twice, the number rule, no lone surrogate), at most 1 048 576
        bytes, one of three formats - else exit 3; a list keeping that grammar never gives exit 3 (10.7.4)."""
        rl = role_list([role_entry("st-1", STMT_SEED, "statements")])
        self.run3("--vendor-key-list", self.f("l.json", rl), want=0)
        self.run3("--vendor-key-list", self.f("l.json", dict(rl, kommentar="x")), want=0)
        self.run3("--vendor-key-list", self.f("l.json", dict(rl, schluessel="x")), want=0)
        for why, data in (("no format", {k: v for k, v in rl.items() if k != "format"}), ("unknown format", dict(rl, format="ledger-schluesselrollen/2")),
                          ("format not a string", dict(rl, format=1)), ("not an object", [rl]),
                          ("member twice", json.dumps(rl)[:-1] + ', "version": 1}'), ("1.0", json.dumps(rl).replace('"version": 1', '"version": 1.0')),
                          ("BOM", b"\xef\xbb\xbf" + json.dumps(rl).encode()), ("lone surrogate", json.dumps(dict(rl, x="\ud800"))),
                          ("not UTF-8", json.dumps(rl).encode()[:-1] + b', "x": "\xff"}'), ("too large", json.dumps(rl) + " " * 1048576)):
            with self.subTest(why): self.run3("--vendor-key-list", self.f("l.json", data))

    def test_10_7_4_pins(self):
        """Pins: key-id=hex64; one key_id twice with different keys; a pin equal in key_id or public key to a pin of
        another role: exit 3. The same pin twice is one pin."""
        a, b = pubkey(STMT_SEED).hex(), pubkey(STMT2_SEED).hex()
        self.run3("--vendor-statement-key", "st=" + a, "--vendor-statement-key", "st=" + a, want=0)
        for args in (("--vendor-statement-key", "st=" + a.upper()), ("--vendor-statement-key", "st"), ("--vendor-log-key", "l=" + a[:-2]),
                     ("--vendor-statement-key", "st=" + a, "--vendor-statement-key", "st=" + b), ("--vendor-log-key", "l=" + a, "--vendor-log-key", "l=" + b),
                     ("--vendor-statement-key", "vendor-1=" + a), ("--vendor-statement-key", "x=" + pubkey(VENDOR_SEED).hex()),
                     ("--vendor-statement-key", "st=" + a, "--vendor-log-key", "st=" + b), ("--vendor-statement-key", "st=" + a, "--vendor-log-key", "l=" + a),
                     ("--vendor-log-key", "vendor-1=" + b), ("--vendor-key", "k=" + a, "--vendor-key", "k=" + b)):
            with self.subTest(args=args): self.run3(*args)

    def test_7_4_8_vendor_log_grammar(self):
        """--vendor-log: the grammar of ledger-protokollauszug/1 and its limits; a violation is exit 3 (L0)."""
        self.run3("--vendor-log", self.f("x.json", extract()), want=1)                # no protocol key: VENDOR_LOG_UNVERIFIED, never exit 3
        day = {"entry": {"statement_jcs": "{}", "server_key_id": "log-1", "server_signature": "0" * 128}, "timestamps": [], "additional_signatures": []}
        rec = {"day": "2026-01-01", "present": {"roots": [{"tree_size": 1, "merkle_root": "a" * 64, "recorded_as": "countersigned", "server_ts": "2026-01-01T00:00:00.000Z"}],
                                                "leaf_index": 0, "path": []}, "absent": None}
        self.run3("--vendor-log", self.f("x.json", extract(days=[day], chain_days=[rec], protocol_keys={"anything": 1})), want=1)
        nb = {"leaf_index": 1, "position": "a" * 64, "chain_root": "b" * 64, "path": []}
        self.run3("--vendor-log", self.f("x.json", extract(chain_days=[dict(rec, present=None, absent={"neighbours": [nb, nb]})])), want=1)  # equal leaf_index: not falling (60aa776a)
        self.run3("--vendor-log", self.f("x.json", extract(chain_days=[dict(rec, present=dict(rec["present"], roots=[dict(rec["present"]["roots"][0], server_ts="2026-01-01T00:00:00Z")]))])), want=1)
        sig = {"alg": "ed25519", "key_id": "log-2", "signature": "1" * 128}
        for why, x in (("not JSON", "{"), ("format", extract(format="ledger-protokollauszug/2")), ("extra member", extract(x=1)),
                       ("chain_id null with records", extract(chain_id=None, chain_days=[rec])), ("protocol_keys a list", extract(protocol_keys=[])),
                       ("statement_jcs 2049", extract(days=[dict(day, entry=dict(day["entry"], statement_jcs="x" * 2049))])),
                       ("five timestamps", extract(days=[dict(day, timestamps=["A"] * 5)])),
                       ("ed25519 signature not hex128", extract(days=[dict(day, additional_signatures=[dict(sig, signature="zz")])])),
                       ("two equal additional signatures", extract(days=[dict(day, additional_signatures=[sig, sig])])),
                       ("alg grammar", extract(days=[dict(day, additional_signatures=[dict(sig, alg="-x")])])),
                       ("present and absent", extract(chain_days=[dict(rec, absent={"neighbours": []})])), ("neither", extract(chain_days=[dict(rec, present=None)])),
                       ("day outside the log range", extract(chain_days=[dict(rec, day="1999-12-31")])), ("two records of one day", extract(chain_days=[rec, rec])),
                       ("two equal roots", extract(chain_days=[dict(rec, present=dict(rec["present"], roots=rec["present"]["roots"] * 2))])),
                       ("server_ts no rfc3339", extract(chain_days=[dict(rec, present=dict(rec["present"], roots=[dict(rec["present"]["roots"][0], server_ts="2026-02-30T00:00:00Z")]))])),
                       ("tree_size 0", extract(chain_days=[dict(rec, present=dict(rec["present"], roots=[dict(rec["present"]["roots"][0], tree_size=0)]))])),
                       ("neighbours descending", extract(chain_days=[dict(rec, present=None, absent={"neighbours": [
                           {"leaf_index": 2, "position": "a" * 64, "chain_root": "b" * 64, "path": []}, {"leaf_index": 1, "position": "a" * 64, "chain_root": "b" * 64, "path": []}]})]))):
            with self.subTest(why): self.run3("--vendor-log", self.f("x.json", x))
        self.run3("--vendor-log", self.f("a.json", extract()), "--vendor-log", self.f("b.json", extract(log_id="other")))     # different log_id
        files = [self.f("e%d.json" % i, extract()) for i in range(129)]
        self.run3(*[x for f in files[:128] for x in ("--vendor-log", f)], want=1)
        self.run3(*[x for f in files for x in ("--vendor-log", f)])

    def test_8_8_2_anchor_history_grammar(self):
        """--anchor-history: a page (exactly four members, statement_jcs of 1 to 131 072 characters) or a container
        ledger-ankerhistorie/2 with 1 to 4096 pages and 0 to 128 extracts, which count as --vendor-log files."""
        self.run3("--anchor-history", self.f("h.json", page()), want=1)          # H2 (8.8.4): key not established, exit 1, never 3
        self.run3("--anchor-history", self.f("h.json", {"format": "ledger-ankerhistorie/2", "pages": [page()], "vendor_log": [extract()]}), want=1)   # an extract: L1 item 4
        self.run3("--anchor-history", self.f("h.json", page(statement_jcs="not even JSON inside")), want=1)    # the content is step H2's
        for why, x in (("not JSON", "x"), ("page member", dict(page(), x=1)), ("statement_jcs empty", page(statement_jcs="")),
                       ("server_key_id", page(server_key_id="a b")), ("container format", {"format": "ledger-ankerhistorie/3", "pages": [page()], "vendor_log": []}),
                       ("no page", {"format": "ledger-ankerhistorie/2", "pages": [], "vendor_log": []}),
                       ("embedded extract", {"format": "ledger-ankerhistorie/2", "pages": [page()], "vendor_log": [extract(x=1)]})):
            with self.subTest(why): self.run3("--anchor-history", self.f("h.json", x))
        self.run3("--anchor-history", self.f("h.json", {"format": "ledger-ankerhistorie/2", "pages": [page()], "vendor_log": [extract(log_id="o")]}),
                  "--vendor-log", self.f("x.json", extract()))

    def test_10_8_requested_at(self):
        """--requested-at: rfc3339, at most once, never after the check time, compared in whole milliseconds: against
        --now at invocation (exit 3 without report), against verify_args.json at the start of stage 5 (FORMAT_ERROR)."""
        self.run3("--requested-at", self.now, want=0)
        self.run3("--requested-at", self.now[:-1] + "999999Z", want=0)       # the fraction cut to milliseconds
        self.run3("--requested-at", later(self.now, 1))
        self.run3("--requested-at", "2026-01-01 00:00:00Z")
        pkg = self.pkg(self.c, extra={"verify_args.json": json.dumps({"now": self.now})})
        code, j, err = self.cli(pkg, "--json", "--now-from-package", "--requested-at", later(self.now, 1))
        self.assertEqual((code, j["finding_classes"], j["key_roles"]), (3, ["FORMAT_ERROR"], None), err)
        code, j, err = self.cli(pkg, "--json", "--now-from-package", "--requested-at", self.now)
        self.assertEqual(code, 0, err)

    def test_10_8_pruefumgebung(self):
        """ledger-pruefumgebung/1: the audit environment of a test vector to switches in the registry's member order."""
        args = V.pruefumgebung(os.path.join(VEKTOREN, "pruefer_roles_statement_pins.json"), self.reg)
        self.assertEqual([a for a in args if a.startswith("--")], ["--vendor-root", "--vendor-key", "--vendor-key-list", "--vendor-statement-key", "--vendor-statement-key"])
        bad = self.f("pruefer_x.json", dict(json.load(open(os.path.join(VEKTOREN, "pruefer_roles_statement_pins.json"))), korpus="ja"))
        self.assertRaises(V.Unusable, V.pruefumgebung, bad, self.reg)


class Zeitstempel110(Spec19):
    """The single check of a time stamp (verifier2.py zeitstempel, a helper outside the specification): the column for
    day time stamps of 7.5.7 against the roots passed for one purpose, the JSON members of the Go helper."""

    def zs(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try: code = vmain(["verifier2", "zeitstempel", *argv])
            except SystemExit as e: code = e.code
        text = out.getvalue()
        return code, json.loads(text) if "--json" in argv and text else text, err.getvalue()

    def test_readme_10_4_inputs(self):
        """The inputs of spec/testvectors README 10.4 with --purpose chain and log and their root: the table values. The rows of
        7.5.7 hold alike for both purposes; the row on Z.6 stands above that on published_test_keys, so the inputs on Z.6 show
        its result (7.5.6); an arc above 10^4300 in the extnID of an extension next to qcStatements leaves rule QS present
        (7.5.2 T.6, 7.5.6). The signer is named where Z.5 finds it, by a commonName as the Go helper reads it: that of
        timestamp_name_value_constructed is a constructed UTF8String, which names nobody (null)."""
        sig, g, gms = "Testkorpus Zeitstempelstelle (kein Zeuge)", "20260101004001Z", "2026-01-01T00:40:01.000Z"
        for name, gt, gtms, want, signer, qs in (
                ("timestamp_gentime_fraction", "20260101004001.123999999Z", "2026-01-01T00:40:01.123Z", ("unconfirmed", "published_test_key"), sig, "absent"),
                ("timestamp_name_value_constructed", g, gms, ("unconfirmed", "published_test_key"), None, "absent"),
                ("timestamp_sha1_digest_algorithm", g, gms, ("unconfirmed", "step_5_not_performable"), sig, "absent"),
                ("timestamp_ess_both", g, gms, ("unconfirmed", "published_test_key"), sig, "absent"),
                ("timestamp_certificates_not_tlv", g, gms, ("unconfirmed", "step_5_not_performable"), None, "absent"),
                ("timestamp_sid_not_issuer_serial", g, gms, ("unconfirmed", "step_5_not_performable"), None, "absent"),
                ("timestamp_ess_v2_second_element_broken", g, gms, ("defective", "z6_failed"), sig, "absent"),
                ("timestamp_ess_issuer_serial_name_broken", g, gms, ("defective", "z6_failed"), sig, "absent"),
                ("timestamp_ess_policies_not_der", g, gms, ("unconfirmed", "published_test_key"), sig, "absent"),
                ("timestamp_ess_other_name_a4", g, gms, ("unconfirmed", "published_test_key"), sig, "absent"),
                ("timestamp_ess_hash_algorithm_parameters_not_der", g, gms, ("unconfirmed", "published_test_key"), sig, "absent"),
                ("timestamp_qs_extension_oid_arc_large", g, gms, ("unconfirmed", "published_test_key"), sig, "present")):
            base = os.path.join(VEKTOREN, "zeitstempel_" + name)
            for purpose in ("chain", "log"):
                for tok, data in ((".token.der", "--data"), (".token.b64", "--statement-jcs")):
                    with self.subTest(name=name, purpose=purpose, token=tok):
                        code, j, err = self.zs("--token", base + tok, data, base + ".daten.json", "--tsa-root", base + ".wurzel.pem", "--purpose", purpose, "--json")
                        self.assertEqual((code, j), (1, {"purpose": purpose, "state": want[0], "reason": want[1], "gen_time": gt, "gen_time_ms": gtms,
                                                         "imprint_algorithm": "sha256", "signer": signer, "qualified_statement": qs}), err)

    def test_signer_is_the_common_name_the_go_helper_shows(self):
        """The member signer, a display value: the first commonName (2.5.4.3) of the signer's subject held in a primitive
        UTF8String, PrintableString or IA5String whose content is UTF-8, in the order of the RDNs and of their attributes;
        null where there is none or where that first one is empty. Never the whole Name, never the content of another
        string type (verifier/internal/tsa/cert.go SubjectCommonName)."""
        CN, O, k, a = "2.5.4.3", "2.5.4.10", TKey("ed", b"verifier2 1.10 common name"), TSA()
        root, data = write_pem(os.path.join(self.tmp, "r.pem"), a.root), self.f("d.bin", b"daten")

        def name(*rdns): return _seq(*(_set(*(_seq(_oid(o), v) for o, v in rdn)) for rdn in rdns))
        for subject, want in (
                (name([(CN, _tl(0x2c, _tl(0x0c, b"Teil")))]), None),                                   # constructed UTF8String
                (name([(O, _tl(0x0c, b"Probe"))]), None),                                              # no commonName: not the Name
                (name([(CN, _tl(0x1e, "Bmp".encode("utf-16-be")))], [(CN, _tl(0x13, b"Druckbar"))]), "Druckbar"),
                (name([(O, _tl(0x0c, b"Probe")), (CN, _tl(0x16, b"ia5"))]), "ia5"),                    # an RDN of two attributes
                (name([(CN, _tl(0x0c, b"\xff"))], [(CN, _tl(0x0c, "Zeit ü".encode()))]), "Zeit ü"),   # not UTF-8: passed over
                (name([(CN, _tl(0x0c, b""))], [(CN, _tl(0x0c, b"zweiter"))]), None),                   # the first is empty
                (name([(CN, _tl(0x13, "Zeitstempel ü".encode()))]), "Zeitstempel ü")):
            with self.subTest(subject=subject.hex()):
                signer = tcert(k, "-", issuer=("Probe Root 1.10", a.rk), serial=2, alg="rsa256", subject=subject)
                tok = self.f("t.der", ttoken(b"daten", k, signer, carried=[signer]))
                code, j, err = self.zs("--token", tok, "--data", data, "--tsa-root", root, "--json")
                self.assertEqual((code, j["state"], j["signer"]), (0, "confirmed", want), err)

    def test_states_exit_codes_and_usage(self):
        a = TSA()
        tok, data, root = self.f("t.der", a.token(b"daten")), self.f("d.bin", b"daten"), write_pem(os.path.join(self.tmp, "r.pem"), a.root)
        code, j, _ = self.zs("--token", tok, "--data", data, "--tsa-root", root, "--json")
        self.assertEqual((code, j["purpose"], j["state"], j["reason"], j["signer"]), (0, "log", "confirmed", None, "Probe TSA 1.10"))
        code, j, _ = self.zs("--token", tok, "--data", data, "--json")
        self.assertEqual((code, j["state"], j["reason"]), (1, "unconfirmed", "no_path_to_root_of_purpose"))
        code, j, _ = self.zs("--token", tok, "--data", self.f("o.bin", b"other"), "--tsa-root", root, "--json")
        self.assertEqual((code, j["state"], j["reason"], j["signer"], j["gen_time"]), (1, "defective", "imprint_wrong", None, "20260101004001Z"))
        code, j, _ = self.zs("--token", self.f("b.b64", base64.b64encode(a.token(b"daten")) + b"\r\n"), "--data", data, "--tsa-root", root, "--json")
        self.assertEqual((code, j["state"]), (0, "confirmed"))
        code, j, _ = self.zs("--token", self.f("b.b64", base64.b64encode(a.token(b"daten")) + b"\n\n"), "--data", data, "--json")
        self.assertEqual((j["state"], j["reason"], j["gen_time"], j["qualified_statement"]), ("defective", "b64_size_or_grammar_t", None, None))
        code, j, _ = self.zs("--token", self.f("f.der", flip_last(a.token(b"daten"))), "--data", data, "--tsa-root", root, "--json")
        self.assertEqual((j["state"], j["reason"]), ("defective", "step_5_failed"))
        code, text, _ = self.zs("--token", tok, "--data", data, "--tsa-root", root)       # 1.1.0: en by default, like ledger-verify
        self.assertIn("\nResult:      confirmed\n", text)
        code, text, _ = self.zs("--token", tok, "--data", data, "--tsa-root", root, "--lang", "de")
        self.assertIn("\nErgebnis:    bestätigt\n", text)
        code, text, _ = self.zs("--token", tok, "--data", data, "--lang", "en")
        self.assertIn("not confirmed", text)
        sj = self.f("s.json", b'{"day":"2026-01-01"}\r\n')
        code, j, _ = self.zs("--token", self.f("s.der", a.token(b'{"day":"2026-01-01"}')), "--statement-jcs", sj, "--tsa-root", root, "--json")
        self.assertEqual(j["state"], "confirmed")
        for args in ((), ("--token", tok), ("--token", tok, "--data", data, "--statement-jcs", data), ("--token", tok, "--token", tok, "--data", data),
                     ("--token", tok, "--data", data, "--purpose", "qualified"), ("--token", tok, "--data", data, "--purpose", "log", "--purpose", "log"),
                     ("--token", tok, "--data", data, "extra"), ("--token", tok, "--statement-jcs", self.f("u.json", "ä".encode())),
                     ("--token", tok, "--data", data, "--tsa-root", data), ("--token", tok + ".nope", "--data", data)):
            with self.subTest(args=args): self.assertEqual(self.zs(*args)[0], 3)

    def f(self, name, data):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as fh: fh.write(data)
        return path


def _dec_ref(v):
    """The decimal digits of v >= 0 by division by 10^9, never str() of the whole number (and its digit limit)."""
    parts = []
    while v >= 10 ** 9: v, r = divmod(v, 10 ** 9); parts.append("%09d" % r)
    return str(v) + "".join(reversed(parts))


class IntegerText110(Spec19):
    """Python converts an int of more than 4300 decimal digits neither to nor from text (sys.get_int_max_str_digits());
    Go's math/big and strconv know no such limit. Where an integer of an input meets decimal text both verifiers judge
    alike: an arc of an OBJECT IDENTIFIER of any size reads as the text big.Int.String() writes (T.6, Z.1, Z.3, rule
    QS, the policy of 7.3 step 3), a JSON number of any length beyond 2^53-1 is the number verdict of section 2 (stage
    4a too), the number of a presentation of any length names no entry (10.1). Red before 26.10.: a ValueError where
    the Go verifier reads on."""

    BIG = b"\x2b" + b"\x81" * 2100 + b"\x01"             # 1.3.N with N = 128^2100 + ... + 128 + 1, 4426 decimal digits
    TEXT = "1.3." + _dec_ref(sum(128 ** k for k in range(2101)))

    def test_1_decimal_text_of_any_size(self):
        self.assertGreater(len(self.TEXT), 4300 + 4)
        self.assertEqual(V.der_oid((0x06, b"", self.BIG)), self.TEXT)
        self.assertEqual(V.der_oid((0x06, b"", b"\x81" * 2200 + b"\x01")), "2." + _dec_ref(sum(128 ** k for k in range(2201)) - 80))
        self.assertEqual([hashlib.sha256(V.der_oid((0x06, b"", c)).encode()).hexdigest() for c in (self.BIG, b"\x81" * 2200 + b"\x01")],
                         ["8e90d728a5b72eb5bf840e6c151aaa3b1e6c27aefc78200a570a4494e68947d7",      # as in Go's TestOIDArcOfAnySize
                          "b547298edafad1c5325f0c86deeb8519b6937d567558efa58587e98440756696"])
        for v in (0, 7, 10 ** 512 - 1, 10 ** 512, 10 ** 512 + 1, 10 ** 1024 - 1, 10 ** 1024, 10 ** 4300, 3 ** 40000 + 10 ** 700):
            with self.subTest(digits=len(_dec_ref(v))):
                self.assertEqual((V._dec(v), V._dec(-v)), (_dec_ref(v), ("-" if v else "") + _dec_ref(v)))
        V.der_check(_seq(_oid(self.BIG)))                                # T.6 throughout
        self.assertEqual(V.z1_name(V.der(_seq(_set(_seq(_oid(self.BIG), _tl(0x0c, b"x")))), 0x30)), [(self.TEXT, "x")])

    def test_2_certificate_and_token(self):
        """The reviewer's case: one more certificate in certificates whose non-critical extKeyUsage holds such an OID (Z.1
        reads it as DER throughout). Go confirmed the token, verifier2 made step 5 not performable. Then the policy of the
        TSTInfo and a non-critical extension of it (rule QS) with such an OID."""
        a, root = TSA(), [V.Cert(TSA().root)]
        extra = tcert(TKey("ed", b"verifier2 1.10 big arc"), "Probe Weitere", eku=None, extra=[_ext(V.X_EKU, _seq(_oid(self.BIG)), False)])
        self.assertEqual(V.Cert(extra).z3(), ("", (False, None), None, ([self.TEXT], False)))
        r = assess(a.token(b"s", carried=[a.signer, extra]), b"s", root)
        self.assertEqual((r["step5"], V.day_token_state(r, root, set())), ("holds", ("confirmed", None)))
        self.assertEqual(V.t_read(a.token(b"s", policy=self.BIG))["policy"], self.TEXT)
        r = assess(a.token(b"s", exts=[_ext(self.BIG, _tl(0x05, b""), False)]), b"s", root)
        self.assertEqual((r["qs"], V.day_token_state(r, root, set())), ("absent", ("confirmed", None)))

    def test_3_json_number_of_any_length(self):
        for tok in ("9" * 17, "1" + "0" * 4300, "-" + "9" * 5000, "2" * 100000):
            with self.subTest(digits=len(tok)):
                with self.assertRaises(V.NumberError): V.jloads("[%s]" % tok)
                with self.assertRaises(V.NumberError): V.num_scan(b'{"a":%s}' % tok.encode())
        with self.assertRaises(V.Unusable) as cm: V.auditor_json(b'{"a":' + b"7" * 5000 + b"}", "--vendor-key-list x")
        self.assertIn("2^53-1", str(cm.exception))
        c = Chain(OWN); c.close()
        for extra in ({"keys/vendor/schluesselliste.json": b'{"version":' + b"1" * 5000 + b"}"}, {"content/2.salts.json": b'{"seq":' + b"2" * 5000 + b"}"}):
            with self.subTest(extra=list(extra)):                       # stage 4a (10.5)
                code, f = self.run_v2(c, keys={}, extra=extra)
                self.assertEqual((code, self.classes(f)), (3, ["FORMAT_ERROR"]), f)
                self.assertIn("2^53-1", f[0]["detail"])
        c = Chain(OWN); c.add("FUTURE_NOTE", {"n": 1}); c.close()
        pkg = self.pkg(c)
        rewrite_segment(pkg, lambda b: b.replace(b'"n":1}', b'"n":' + b"1" * 5000 + b"}"))
        res = V.verify(pkg, self.reg, at_ms(c.t + 3), 24.0, [], vendor_keys=PIN)
        self.assertEqual(res.classes(), ["FORMAT_ERROR"], res.findings)
        self.assertIn("2^53-1", res.findings[0]["detail"])

    def test_4_presentation_number_of_any_length(self):
        """content/<n>.*: a number beyond 2^53-1 names no entry, as the Go verifier reads one beyond int64 as seq 0 that no
        entry carries. A name of 5000 digits fits only into a ZIP archive (10.1)."""
        c = Chain(OWN); presented_call(c); c.close()
        d = c.write(os.path.join(self.tmp, "quelle"))
        for n in ("3" * 20, "3" * 5000):
            with self.subTest(digits=len(n)):
                z = os.path.join(self.tmp, "paket-%d.zip" % len(n))
                with zipfile.ZipFile(z, "w") as zf:
                    for r, _d, ns in os.walk(d):
                        for x in ns: zf.write(os.path.join(r, x), os.path.relpath(os.path.join(r, x), d).replace(os.sep, "/"))
                    zf.writestr(f"content/{n}.request", PLAIN["request"])
                    zf.writestr(f"content/{n}.salts.json", V.jcs({"seq": 3, "request_salt": REQ_SALT.hex()}))
                res = V.verify(z, self.reg, at_ms(c.t + 3), 24.0, [], vendor_keys=PIN)
                self.assertEqual((V.exit_code(res, self.reg["verifier"]["finding_classes"]), res.classes()), (2, ["CONTENT_MISMATCH"]), res.findings)
                self.assertEqual(sorted(x["detail"].split(":")[0] for x in res.findings), [f"content/{n}.request", f"content/{n}.salts.json"])

    def test_5_expected_root_and_rsa_exponent(self):
        """Display: an unusable --expect-root names the rule of 10.8, an RSA exponent outside Z.2 is written in decimal."""
        c = Chain(OWN); c.close()
        code, _j, err = self.cli(self.pkg(c), "--json", "--expect-root", "1" * 5000 + ":" + "ab" * 32)
        self.assertEqual(code, 3)
        self.assertIn("TREE_SIZE 1 to 2^53-1", err)
        k, e = TKey("rsa", b"verifier2 test tsa rsa"), 10 ** 5000 + 1
        cert = V.Cert(tcert(k, "Probe RSA e", spki=_seq(_alg(V.RSA_KEY, b"\x05\x00"), _tl(0x03, b"\x00" + _seq(_int(k.n), _int(e))))))
        with self.assertRaises(V.Z2Error) as cm: V.z2_key(cert)
        self.assertIn("e=" + _dec_ref(e) + ")", str(cm.exception))


class Vectors110(unittest.TestCase):
    """The vectors of the 1.10 foundations (groups roles, auditor, timestamp) with the corpus environment and with
    each vector's own ledger-pruefumgebung/1: exit code and finding classes as expected/<name>.json says, and the
    key_roles values the rows of spec/testvectors README 10.1 name. Which vectors: those the registry lists, held
    against the expected files on disk, never a number written here."""

    KR = {"roles_list_effective": ("effective", None, 1), "roles_pin_without_list": ("not_supplied", None, 0),
          "roles_two_roles_cs_list": ("not_effective", "key_in_two_roles", 1), "roles_two_roles_no_fallback": ("not_effective", "key_in_two_roles", 2),
          "roles_two_roles_protocol_list": ("not_effective", "key_in_two_roles", 1), "roles_protocol_list_cs_pin": ("not_supplied", None, 0),
          "roles_same_version_differ": ("not_effective", "lists_contradictory", 2), "roles_entry_dropped": ("not_effective", "lists_contradictory", 2),
          "roles_dual_end_effective": ("effective", None, 2), "roles_dual_end_differs": ("not_effective", "lists_contradictory", 2),
          "roles_dual_end_dropped": ("not_effective", "lists_contradictory", 2), "roles_list_protocol_role": ("not_effective", "format", 1),
          "roles_list_names_root": ("not_effective", "format", 1), "roles_list_extra_member": ("not_effective", "format", 1),
          "roles_list_no_matching_root": ("not_effective", "no_matching_root", 1), "roles_list_bad_signature": ("not_effective", "signature", 1),
          "roles_list_two_reasons": ("not_effective", "signature", 2), "roles_unknown_role": ("effective", None, 1),
          "roles_statement_pins": ("not_supplied", None, 0), "roles_pins_dropped": ("effective", None, 1),
          "roles_list_revokes_pinned_key": ("effective", None, 1), "roles_list_revokes_receipt_key": ("effective", None, 1),
          "roles_pin_other_role": ("effective", None, 1)}

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try: code = vmain(["verifier2", *argv])
            except SystemExit as e: code = e.code
        return code, json.loads(out.getvalue()) if out.getvalue() else None, err.getvalue()

    def test_both_environments(self):
        reg = file_registry()
        names, on_disk = corpus_names(reg, ("roles", "auditor", "timestamp"))
        self.assertTrue(names)
        self.assertEqual(names, on_disk)
        self.assertEqual([n for n in names if not os.path.isdir(os.path.join(VEKTOREN, n))], [])
        self.assertLessEqual(set(self.KR), set(names))
        for name in names:
            with open(os.path.join(VEKTOREN, "expected", name + ".json")) as fh: exp = json.load(fh)
            pkg = os.path.join(VEKTOREN, name)
            for env, args, want in (("corpus", vector_anchors(), exp), ("vector", V.pruefumgebung(os.path.join(VEKTOREN, exp["auditor_inputs"]["file"]), reg), exp["auditor_inputs"])):
                with self.subTest(name=name, env=env):
                    code, j, err = self.run_main(pkg, "--json", "--now-from-package", "--registry", REG_PATH, *args)
                    self.assertEqual((code, j["finding_classes"] if j else []), (want["exit_code"], sorted(set(want["finding_classes"]))), err)
                    if env == "vector" and name in self.KR:
                        kr = j["key_roles"]
                        self.assertEqual((kr["status"], kr["reason"], kr["candidates"]), self.KR[name], kr)
        code, j, _ = self.run_main(os.path.join(VEKTOREN, "roles_unknown_role"), "--json", "--now-from-package", "--registry", REG_PATH,
                                   *V.pruefumgebung(os.path.join(VEKTOREN, "pruefer_roles_unknown_role.json"), reg))
        self.assertEqual((j["key_roles"]["notes"], j["key_roles"]["pins_dropped"]), (["unknown_role", "receipt_key_other_role", "pin_dropped"],
                                                                                     [{"key_id": "vendor-test-001", "pinned_as": "countersigning", "listed_as": "audit_log"}]))
        code, j, _ = self.run_main(os.path.join(VEKTOREN, "roles_pins_dropped"), "--json", "--now-from-package", "--registry", REG_PATH,
                                   *V.pruefumgebung(os.path.join(VEKTOREN, "pruefer_roles_pins_dropped.json"), reg))
        self.assertEqual(sorted(d["listed_as"] for d in j["key_roles"]["pins_dropped"]), ["countersigning", "statements", "update_manifest"])
        code, j, _ = self.run_main(os.path.join(VEKTOREN, "roles_dual_end_effective"), "--json", "--now-from-package", "--registry", REG_PATH,
                                   *V.pruefumgebung(os.path.join(VEKTOREN, "pruefer_roles_dual_end_effective.json"), reg))
        self.assertEqual((j["key_roles"]["list"]["version"], j["key_roles"]["list"]["ende_doppelbetrieb"]), (2, "2026-07-01T00:00:00Z"))
        code, j, _ = self.run_main(os.path.join(VEKTOREN, "roles_statement_pins"), "--json", "--now-from-package", "--registry", REG_PATH,
                                   *V.pruefumgebung(os.path.join(VEKTOREN, "pruefer_roles_statement_pins.json"), reg))
        self.assertEqual((j["key_roles"]["statement_keys"], j["key_roles"]["notes"]), ([{"key_id": "vendor-statements-test-001", "source": "pinned"}], ["pin_dropped"]))


# ---------------------------------------------------------------- RFC 9162 proofs

def _rleaf(d): return hashlib.sha256(b"\x00" + d).digest()
def _rnode(l, r): return hashlib.sha256(b"\x01" + l + r).digest()
def _rsplit(n): return 1 << (n - 1).bit_length() - 1             # the largest power of two below n


def _rmth(d): return hashlib.sha256(b"").digest() if not d else _rleaf(d[0]) if len(d) == 1 else _rnode(_rmth(d[:_rsplit(len(d))]), _rmth(d[_rsplit(len(d)):]))


def _rpath(m, d):
    """PATH(m, D[n]) of RFC 9162 2.1.3.1, recursive as written there."""
    if len(d) <= 1: return []
    k = _rsplit(len(d))
    return _rpath(m, d[:k]) + [_rmth(d[k:])] if m < k else _rpath(m - k, d[k:]) + [_rmth(d[:k])]


def _rsubproof(m, d, b):
    """SUBPROOF(m, D[n], b) of RFC 9162 2.1.4.1; PROOF(m, D[n]) is SUBPROOF(m, D[n], true)."""
    if m == len(d): return [] if b else [_rmth(d)]
    k = _rsplit(len(d))
    return _rsubproof(m, d[:k], b) + [_rmth(d[k:])] if m <= k else _rsubproof(m - k, d[k:], False) + [_rmth(d[:k])]


def _rsides(m, n):
    """The shape of PATH(m, D[n]): L or R per sibling from the leaf upwards; None: no such path. All an inclusion
    proof binds of the size - leaf 0 of 5 and of 7 leaves have the same path - so a changed index or size must verify
    exactly when the shape stays the same."""
    if not 0 <= m < n: return None
    if n == 1: return ""
    k = _rsplit(n)
    return _rsides(m, k) + "R" if m < k else _rsides(m - k, n - k) + "L"


def _rshape(m, n, b=True):
    """The shape of SUBPROOF(m, D[n], b): S for the first tree's own subtree, then L or R per sibling; None: none."""
    if not 0 < m <= n: return None
    if m == n: return "" if b else "S"
    k = _rsplit(n)
    if m <= k:
        s = _rshape(m, k, b)
        return None if s is None else s + "R"
    s = _rshape(m - k, n - k, False)
    return None if s is None else s + "L"


class RFC9162Proofs(unittest.TestCase):
    """verify_inclusion and verify_consistency (RFC 9162 2.1.3.2, 2.1.4.2) against an independent generator from the
    recursive definitions, for every tree size 1 to 64 and every leaf index or prefix size: every proof verifies; a
    flipped bit of path, leaf or root fails (every bit for the sizes up to 8, one per hash beyond); a changed index or
    size (bits 0 to 9, 31, 52, 63) fails exactly when it changes the shape. The Go verifier runs the full single-bit
    sweep over the same definitions; identical inputs for both come from its TestRFC9162Kreuzprobe."""
    D = [hashlib.sha256(b"rfc9162 leaf %d" % i).digest() for i in range(64)]
    BITS = list(range(10)) + [31, 52, 63]

    @staticmethod
    def flip(h, bit): return h[:bit // 8] + bytes([h[bit // 8] ^ 1 << bit % 8]) + h[bit // 8 + 1:]

    def test_1_the_empty_tree(self):
        self.assertEqual(V.MTH_EMPTY.hex(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(V.mth([]), V.MTH_EMPTY)
        self.assertFalse(V.verify_inclusion(_rleaf(self.D[0]), 0, 0, [], V.MTH_EMPTY))
        self.assertTrue(V.verify_consistency(0, 0, V.MTH_EMPTY, V.MTH_EMPTY, []))
        self.assertFalse(V.verify_consistency(0, 0, _rmth(self.D[:1]), _rmth(self.D[:1]), []))

    def test_2_inclusion(self):
        same_size = 0
        for n in range(1, 65):
            root = _rmth(self.D[:n])
            self.assertEqual(root, V.mth(self.D[:n]))
            for m in range(n):
                leaf, path = _rleaf(self.D[m]), _rpath(m, self.D[:n])
                self.assertTrue(V.verify_inclusion(leaf, m, n, path, root), (m, n))
                bits = range(256) if n <= 8 else [(37 * m + 11 * n) % 256]
                for j in range(len(path)):
                    for b in bits:
                        self.assertFalse(V.verify_inclusion(leaf, m, n, path[:j] + [self.flip(path[j], b)] + path[j + 1:], root), (m, n, j, b))
                for b in bits:
                    self.assertFalse(V.verify_inclusion(leaf, m, n, path, self.flip(root, b)), (m, n, b))
                    self.assertFalse(V.verify_inclusion(self.flip(leaf, b), m, n, path, root), (m, n, b))
                for b in self.BITS:
                    for m2, n2 in ((m ^ 1 << b, n), (m, n ^ 1 << b)):
                        want = _rsides(m2, n2) is not None and _rsides(m2, n2) == _rsides(m, n)
                        self.assertEqual(V.verify_inclusion(leaf, m2, n2, path, root), want, (m, n, m2, n2))
                        same_size += want
                for j in range(len(path)): self.assertFalse(V.verify_inclusion(leaf, m, n, path[:j] + path[j + 1:], root))
                self.assertFalse(V.verify_inclusion(leaf, m, n, path + [root], root))
                self.assertFalse(V.verify_inclusion(leaf, -1, n, path, root))
        self.assertGreater(same_size, 0)                                   # leaf 0 of 5 and of 7, ...

    def test_3_consistency(self):
        for n in range(1, 65):
            root2 = _rmth(self.D[:n])
            self.assertTrue(V.verify_consistency(0, n, V.MTH_EMPTY, root2, []))                 # the empty tree is a prefix of every tree
            self.assertFalse(V.verify_consistency(0, n, root2, root2, []))
            self.assertFalse(V.verify_consistency(0, n, V.MTH_EMPTY, root2, [root2]))
            self.assertFalse(V.verify_consistency(n + 1, n, root2, root2, []))
            for m in range(1, n + 1):
                root1, path = _rmth(self.D[:m]), _rsubproof(m, self.D[:n], True)
                self.assertTrue(V.verify_consistency(m, n, root1, root2, path), (m, n))
                bits = range(256) if n <= 8 else [(29 * m + 7 * n) % 256]
                for j in range(len(path)):
                    for b in bits:
                        self.assertFalse(V.verify_consistency(m, n, root1, root2, path[:j] + [self.flip(path[j], b)] + path[j + 1:]), (m, n, j, b))
                for b in bits:
                    self.assertFalse(V.verify_consistency(m, n, self.flip(root1, b), root2, path), (m, n, b))
                    self.assertFalse(V.verify_consistency(m, n, root1, self.flip(root2, b), path), (m, n, b))
                for b in self.BITS:
                    for m2, n2 in ((m ^ 1 << b, n), (m, n ^ 1 << b)):
                        want = _rshape(m2, n2) is not None and _rshape(m2, n2) == _rshape(m, n)
                        self.assertEqual(V.verify_consistency(m2, n2, root1, root2, path), want, (m, n, m2, n2))
                for j in range(len(path)): self.assertFalse(V.verify_consistency(m, n, root1, root2, path[:j] + path[j + 1:]))
                self.assertFalse(V.verify_consistency(m, n, root1, root2, path + [root2]))


# ---------------------------------------------------------------- vendor log (7.4, from 1.10)

LOG_ID = "ledger-testprotokoll-1"
APPLIANCE = "49eed9d6-4f02-4aa0-9392-12c117f761a1"           # GENESIS.appliance_id of every Chain
FILLER_SECRET = hashlib.sha256(b"LEDGER-TESTVEKTOR-FUELLERGEHEIMNIS").digest()      # the published test filler secret (7.4.4)
LOG2_SEED = bytes([106] * 32)
UTCZ = datetime.timezone.utc


def _j(o):
    """JCS of the ASCII objects of the log: for them RFC 8785 is the JSON text with sorted members and no blanks."""
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


def _sha(b): return hashlib.sha256(b).hexdigest()


def _end_s(day):
    """end(d) in seconds since 1970 (2)."""
    return int(datetime.datetime(int(day[:4]), int(day[5:7]), int(day[8:10]), tzinfo=UTCZ).timestamp()) + 86400


def _gt(day, off_ms):
    """A genTime end(day) + off_ms (T.5: the fraction without trailing zeros)."""
    t = _end_s(day) * 1000 + off_ms
    s = datetime.datetime.fromtimestamp(t // 1000, UTCZ).strftime("%Y%m%d%H%M%S")
    return s + ("." + ("%03d" % (t % 1000)).rstrip("0") if t % 1000 else "") + "Z"


def _ts(day, off_ms):
    """end(day) + off_ms as rfc3339 in the form YYYY-MM-DDThh:mm:ss.sssZ."""
    t = _end_s(day) * 1000 + off_ms
    return datetime.datetime.fromtimestamp(t // 1000, UTCZ).strftime("%Y-%m-%dT%H:%M:%S") + ".%03dZ" % (t % 1000)


def t_row(e, recorded_as="countersigned", **over):
    """The recording row (7.4.2) of a receipt entry e."""
    p = e["payload"]
    return dict({"tree_size": p["tree_size"], "merkle_root": p["merkle_root"], "recorded_as": recorded_as, "server_ts": p["server_ts"]}, **over)


def t_leaf(row, chain=CHAIN):
    o = {"chain_id": chain, "merkle_root": row["merkle_root"], "server_ts": row["server_ts"], "tree_size": row["tree_size"]}
    if row["recorded_as"] == "gap_witness": o["kind"] = "ledger.vendor_log_gap_witness.v1"
    return _j(o)


def t_chain_root(rows, chain=CHAIN): return _rmth(sorted({t_leaf(r, chain) for r in rows}, key=_rleaf)).hex()


def t_position(day, chain=CHAIN, app=APPLIANCE):
    return _sha(_j({"appliance_id": app, "chain_id": chain, "day": day, "kind": "ledger.vendor_log_position.v1"}))


def t_dleaf(pos, root): return _j({"chain_root": root, "kind": "ledger.vendor_log_day_leaf.v1", "position": pos})


def t_fillers(day, m, log_id=LOG_ID, secret=FILLER_SECRET):
    """The day secret g(d) and the candidates 0 .. m - 1 of day d (7.4.4) as (position, chain_root, salt)."""
    g = hmac.new(secret, _j({"day": day, "kind": "ledger.vendor_log_filler_secret.v1", "log_id": log_id}), hashlib.sha256).digest()
    out = []
    for i in range(m):
        salt = hmac.new(g, _j({"index": i, "kind": "ledger.vendor_log_filler_salt.v1"}), hashlib.sha256).hexdigest()
        out.append((_sha(_j({"day": day, "kind": "ledger.vendor_log_filler_position.v1", "log_id": log_id, "salt": salt})),
                    _sha(_j({"day": day, "kind": "ledger.vendor_log_filler_root.v1", "log_id": log_id, "salt": salt})), salt))
    return g.hex(), out


class TLog:
    """The vendor's side of 7.4 for the tests, written from the specification and not from verifier2: day trees of
    chain-day leaves and fillers ordered by position, day entries signed with a protocol key and stamped by a test
    authority, chain-day records and extracts."""

    def __init__(self, tsa, key=("log-1", LOG_SEED), first_day="2025-12-31", log_id=LOG_ID):
        self.tsa, self.key, self.first, self.log_id, self.days, self.prev = tsa, key, first_day, log_id, {}, "0" * 64

    def close(self, day, chains=None, fillers=4, stamps=None, keys=None, token_kw=None, extra_pairs=(), **over):
        """Close day d: chains {(chain_id, appliance_id): rows}, the candidates 0 .. fillers - 1, the entry with the day
        hash of the previous close as prev_hash; stamps: genTimes of tokens (default end(d) + 6 min); keys: the protocol
        keys signing it (default self.key); over: members of the entry written instead."""
        pairs = [(t_position(day, c, a), t_chain_root(rows, c), (c, a, rows)) for (c, a), rows in (chains or {}).items()]
        pairs += [(p, r, None) for p, r, _s in t_fillers(day, fillers, self.log_id)[1]] + [(p, r, None) for p, r in extra_pairs]
        pairs.sort(key=lambda x: x[0])
        leaves = [t_dleaf(p, r) for p, r, _o in pairs]
        st = dict({"day": day, "first_day": self.first, "kind": "ledger.vendor_log_day.v1", "log_id": self.log_id,
                   "prev_hash": "0" * 64 if day == self.first else self.prev, "root": _rmth(leaves).hex(), "server_ts": _ts(day, 300000),
                   "tree_size": len(leaves)}, **over)
        s = over.pop("statement_jcs", None) or _j(st).decode()
        self.prev = _sha(s.encode())
        obj = self.obj(s, stamps=[_gt(day, 360000)] if stamps is None else stamps, keys=keys, token_kw=token_kw)
        self.days[day] = {"stmt": s, "obj": obj, "pairs": pairs, "leaves": leaves}
        return obj

    def obj(self, s, stamps=(), keys=None, token_kw=None, extra=()):
        """A day object for statement_jcs s (7.4.8): the first key in entry, the others as additional ed25519 signatures."""
        keys = list(keys or [self.key])
        sigs = [(k, sign(seed, s.encode()).hex()) for k, seed in keys]
        return {"entry": {"statement_jcs": s, "server_key_id": sigs[0][0], "server_signature": sigs[0][1]},
                "timestamps": [base64.b64encode(self.tsa.token(s.encode(), gentime=g, **(token_kw or {}))).decode() for g in stamps],
                "additional_signatures": [{"alg": "ed25519", "key_id": k, "signature": x} for k, x in sigs[1:]] + list(extra)}

    def present(self, day, chain=CHAIN, app=APPLIANCE, **over):
        """The record present (7.4.8) of the chain on day: its rows, leaf index and audit path (RFC 9162 2.1.3.1)."""
        d = self.days[day]
        i = next(k for k, x in enumerate(d["pairs"]) if x[2] and x[2][:2] == (chain, app))
        return {"day": day, "present": dict({"roots": d["pairs"][i][2][2], "leaf_index": i, "path": [h.hex() for h in _rpath(i, d["leaves"])]}, **over),
                "absent": None}

    def neighbour(self, day, i):
        d = self.days[day]
        return {"leaf_index": i, "position": d["pairs"][i][0], "chain_root": d["pairs"][i][1], "path": [h.hex() for h in _rpath(i, d["leaves"])]}

    def absent(self, day, chain=CHAIN, app=APPLIANCE):
        """The record absent (7.4.8) for the chain on day: the neighbours of its position after the forms of section 5."""
        d, p = self.days[day], t_position(day, chain, app)
        k = sum(1 for x in d["pairs"] if x[0] < p)
        idx = [] if not d["pairs"] else [0] if k == 0 else [k - 1] if k == len(d["pairs"]) else [k - 1, k]
        return {"day": day, "present": None, "absent": {"neighbours": [self.neighbour(day, i) for i in idx]}}

    def extract(self, days=None, records=(), chain_id=CHAIN, protocol_keys=None, objs=None):
        return {"format": "ledger-protokollauszug/1", "log_id": self.log_id, "chain_id": chain_id, "protocol_keys": protocol_keys,
                "days": objs if objs is not None else [self.days[d]["obj"] for d in (days if days is not None else sorted(self.days))],
                "chain_days": list(records)}


def ms_of(ts): return V.ms(ts)


class VendorLog110(Spec19):
    """Format spec 7.4 (1.10), the vendor log, rule by rule: leaves, chain days, day tree and fillers with the reference
    values of 7.4.2 to 7.4.7 and the reference case spec/testvectors/protokoll/, the absence proof of section 5, steps
    L1 to L10 of 7.4.10 with the findings of 7.4.11 (exit class 1, at most from 0 to 1) and the report object vendor_log
    of 10.10.2 with its text block (10.10.3). The test authority is one outside published_test_keys, so its stamps can
    be confirmed and days witnessed, which no frozen vector shows (spec/testvectors README 11.2)."""

    NOW = "2026-01-02T12:00:00Z"             # 2026-01-01 is due from 06:00, 2026-01-02 is not
    ROOTS = {"wurzel-test": pubkey(ROOT_SEED).hex()}

    @classmethod
    def setUpClass(cls):
        cls.tsa = TSA(b"verifier2 1.10 log tsa")
        cls.other_tsa = TSA(b"verifier2 1.10 other log tsa")

    def setUp(self):
        super().setUp()
        c = Chain(OWN); c.tick(); c.anchor(); c.tick(); c.anchor(); c.close()
        self.c, self.p = c, self.pkg(c)
        self.rc = [e for e in c.entries if e["event_type"] == "CHECKPOINT_RECEIPT"]     # seq 5, 8, 11; tree_size 3, 6, 9
        self.rows = [t_row(e) for e in self.rc]
        self.plist = proto_list([("log-1", LOG_SEED), ("log-2", LOG2_SEED)])

    def honest(self, **kw):
        """The test log with 2025-12-31 (no leaf) and 2026-01-01 (the chain and four fillers), both witnessed."""
        log = TLog(self.tsa)
        log.close("2025-12-31", fillers=0)
        log.close("2026-01-01", chains={(CHAIN, APPLIANCE): self.rows}, **kw)
        return log

    def run_vl(self, *extracts, lists=None, pins=None, log_roots=None, now=None, reg=None, raws=None, cs=None):
        """verify() with the auditor's inputs; lists default: the protocol key list with log-1 and log-2."""
        i = V.AuditorInputs(self.ROOTS, PIN if cs is None else cs)
        i.log_pins = dict(pins or {})
        i.key_lists = [(x["format"], x, json.dumps(x).encode()) for x in ([self.plist] if lists is None else lists)]
        i.extracts, i.extract_bytes = list(extracts), raws or [json.dumps(x).encode() for x in extracts]
        for cert in ([self.tsa.root] if log_roots is None else log_roots): i.add_root(V.Cert(cert), "log")
        self.res = V.verify(self.p, reg or self.reg, ms_of(now or self.NOW), 1000.0, [], inputs=i)
        return self.res

    def vl(self, *extracts, **kw):
        """-> (exit code, vendor-log findings [(class, detail)], report object, receipt classes [(class, subclass)])."""
        res = self.run_vl(*extracts, **kw)
        with open(os.path.join(VEKTOREN, "..", "schemas", "report_vendor_log.schema.json"), encoding="utf-8") as fh:
            self.assertEqual(schema_ok(res.vendor_log, json.load(fh)), "")       # 10.10.2: the generated schema
        f = [(x["class"], x["detail"]) for x in res.findings if x["class"] in ("VENDOR_LOG_UNVERIFIED", "VENDOR_LOG_DEFECTIVE", "VENDOR_LOG_CONTRADICTION",
                                                                              "RECEIPT_NOT_LOGGED", "LOGGED_ROOT_MISMATCH")]
        return V.exit_code(res, self.reg["verifier"]["finding_classes"]), f, res.vendor_log, [(x["class"], x["subclass"]) for x in (res.vlog or {}).get("classes", [])]

    @staticmethod
    def cls(f): return sorted({c for c, _d in f})

    # ---------------------------------------------------------------- reference values

    def test_7_4_2_7_4_3_leaves_reference_values(self):
        """7.4.2 and 7.4.3: the leaves of a gap witness and of countersignatures, the chain-day root ordered by leaf hash
        and the position, as the registry's reference values name them; a re-formatted server_ts is another leaf."""
        rv = self.reg["vendor_log"]["leaves"]["reference_values"]
        root = hashlib.sha256(rv["merkle_root_source"].encode()).hexdigest()
        self.assertEqual(root, rv["merkle_root"])
        rows = [{"tree_size": 42, "merkle_root": root, "recorded_as": r["recorded_as"], "server_ts": r["server_ts"]} for r in rv["rows"]]
        for row, want in zip(rows, rv["rows"]):
            leaf = V.vl_leaf(rv["chain_id"], row)
            self.assertEqual((len(leaf), V.lh(leaf).hex(), leaf), (want["leaf_length"], want["leaf_hash"], t_leaf(row, rv["chain_id"])))
            self.assertGreaterEqual(len(leaf), 181)                              # never the 32-byte input of a chain leaf (7.4.2)
        sd = rv["same_day"]
        cr = V.vl_chain_root([V.vl_leaf(rv["chain_id"], rows[i]) for i in sd["rows"][::-1]]).hex()   # whatever the order of the rows
        self.assertEqual((cr, V.vl_position(rv["appliance_id"], rv["chain_id"], sd["day"])), (sd["chain_root"], sd["position"]))
        self.assertEqual((cr, t_chain_root([rows[i] for i in sd["rows"]], rv["chain_id"])), (sd["chain_root"], sd["chain_root"]))
        self.assertEqual(V.lh(V.vl_day_leaf(sd["chain_root"], sd["position"])).hex(), sd["chain_day_leaf_hash"])
        for td in rv["two_days"]:                                                 # one leaf: its chain root is its leaf hash (MTH of one leaf)
            self.assertEqual(V.vl_chain_root([V.vl_leaf(rv["chain_id"], rows[i]) for i in td["rows"]]).hex(), td["chain_root"])
        self.assertEqual(V.vl_position(rv["appliance_id"], rv["chain_id"], "2026-03-02"), rv["two_days"][1]["position"])
        neg = rv["negative"]["reformatted_server_ts"]
        self.assertEqual(V.lh(V.vl_leaf(rv["chain_id"], dict(rows[0], server_ts=neg["server_ts"]))).hex(), neg["leaf_hash"])

    def test_7_4_4_fillers_reference_values(self):
        """7.4.4: filler commitment, day secret, salt, position, root and leaf of candidate 0 of the test filler secret;
        the tree of size 5 (one chain, candidates 0 to 3) with the chain at leaf index 3; the next day's secret; the same
        day under the size rule with 1023 fillers, the chain at index 703 with a path of 10 hashes (7.4.5 example)."""
        self.assertEqual(FILLER_SECRET.hex(), "bcfe9766f065da823b5e2cff936cd8aff9e6c5d59540557ae4fe2d02afa04acf")
        self.assertEqual(_sha(_j({"filler_secret": FILLER_SECRET.hex(), "kind": "ledger.vendor_log_filler_commitment.v1", "log_id": LOG_ID})),
                         "82ba087e5b1b7bee5dbfb6b34620efb2e23e1426ad25fe60a672035fb3a99efe")
        g, cands = t_fillers("2026-01-01", 1023)
        self.assertEqual((g, cands[0][2]), ("cc0a0f17adfa12bc5887b25f7eb2f3745b798db1f94a5cbf0eebb9447006f962", "e49f397932b6e32e2700638a9594ddbd3aeb9784a5129363c925e1bdb3eec14e"))
        self.assertEqual(cands[0][:2], ("6a67ff9572b4d663920a2e740361b09ee2cb6acae8ecf613e6a30b16aad350f9", "27f678c7c3c9f763cb99aa6bfb4715d4667faa4b0d6c9f8a2e36e20250b4233c"))
        self.assertEqual(V.lh(V.vl_day_leaf(cands[0][1], cands[0][0])).hex(), "294970b630c3526afb9c691702e0e939842253339bb6831386b70502f012f8c5")
        self.assertEqual(t_fillers("2026-01-02", 0)[0], "eea894d57696feccaa8c45aee5e4d531924e1cfaa8b82356a36823b0582de9fc")
        chain = ("b1ed9cae78dcfafe822b101de7ce470c80f85b3838f7d2701da3de2b588e2c04", "b48375ab1d0a8b4e54d42d8a7c6239eea5ebac215b1b07f45cf8f912030bb2ea")
        for m, root, idx, plen in ((4, "0adcf8f084c1c9c0e8998f01a0a9a9b57e96b5e9135e2833cbb10c6a9e121871", 3, 3),
                                   (1023, "053bc9260b2e032e8c9691fddb7ab200cf03436717d712e12da1a0b3589d7803", 703, 10)):
            pairs = sorted([chain] + [x[:2] for x in cands[:m]])
            leaves = [V.vl_day_leaf(r, p) for p, r in pairs]
            with self.subTest(fillers=m):
                self.assertEqual((V.mth(leaves).hex(), len(pairs), pairs.index(chain)), (root, m + 1, idx))
                path = _rpath(idx, leaves)
                self.assertEqual(len(path), plen)
                self.assertTrue(V.verify_inclusion(V.lh(leaves[idx]), idx, len(leaves), path, bytes.fromhex(root)))
        self.assertEqual(V.mth([]).hex(), self.reg["vendor_log"]["hashes"]["empty_root"])

    def test_7_4_5_7_4_7_examples(self):
        """7.4.5: the example statement_jcs, 319 characters, day hash ef330d20..., keeps every rule of 7.4.5; 7.4.7: the
        signed bytes of the example protocol key list have the SHA-256 value 21817705..."""
        ex = self.reg["vendor_log"]["day_entry"]["example"]
        v, why = V.vl_content(ex["statement_jcs"], LOG_ID)
        self.assertEqual((why, len(ex["statement_jcs"]), _sha(ex["statement_jcs"].encode())), ("", 319, "ef330d2049e93b1da0e934a7a0e01e6b1dc26d392ffdac080ff0ec00889e2c1c"))
        self.assertEqual((v["root"], V.vl_day_of(ex["statement_jcs"])), ("0adcf8f084c1c9c0e8998f01a0a9a9b57e96b5e9135e2833cbb10c6a9e121871", "2026-01-01"))
        signed = ('{"ausgestellt":"2025-12-30T10:00:00.000Z","erster_tag":"2025-12-31","format":"ledger-protokollschluessel/1",'
                  '"fuellerbindung":"82ba087e5b1b7bee5dbfb6b34620efb2e23e1426ad25fe60a672035fb3a99efe","log_id":"ledger-testprotokoll-1",'
                  '"orte":["https://download.example/ledger-testprotokoll-1","https://mirror.example/ledger-testprotokoll-1"],"schluessel":'
                  '[{"gueltig_ab":"2025-12-30T00:00:00.000Z","key_id":"vendor-log-test-001","pubkey":"1111111111111111111111111111111111111111111111111111111111111111"}],"version":1}')
        self.assertEqual((V.jcs(json.loads(signed)), _sha(signed.encode())), (signed, "21817705e707ffd17c2b4216ec3c654917f3d1b27e413e1fb3b740c9378c60da"))

    def test_reference_case_directory(self):
        """spec/testvectors/protokoll/ (registry vendor_log.reference_case): keys.json is a protocol key list effective
        under testwurzel-1; the day objects of 2025-12-31 and 2026-01-01 carry day hashes 33fd1b29... and ef330d20...,
        keep 7.4.5 and the rules of the log and hold under vendor-log-test-001; their stamps are of the test authority
        (not confirmed, published_test_key); the day leaves pass (a) to (c) of 7.4.9; the mirror extracts and the absent
        extract keep the grammar of 7.4.8, whose record of form (iv) holds against the day of 2026-01-01."""
        base = os.path.join(VEKTOREN, "protokoll")
        def rd(*p):
            with open(os.path.join(base, *p), encoding="utf-8") as fh: return json.load(fh)
        with open(os.path.join(VEKTOREN, "pruefer_herstellerwurzel.json")) as fh: w = json.load(fh)
        keys = rd("keys.json")
        self.assertEqual(V.protocol_list(keys, {w["wurzel_id"]: w["pubkey"]}), ("", ""))
        pub = {k["key_id"]: k["pubkey"] for k in keys["schluessel"]}
        with open(os.path.join(VEKTOREN, "pruefer_log_day_test_authority.vendor_log_tsa_root-1.pem")) as fh: roots = V.strict_pem(fh.read())
        prev = "0" * 64
        for day, want in (("2025-12-31", "33fd1b29"), ("2026-01-01", "ef330d20")):
            obj, leaves = rd("days", day[:4], day + ".json"), rd("leaves", day[:4], day + ".json")
            s = obj["entry"]["statement_jcs"]
            v, why = V.vl_content(s, LOG_ID)
            with self.subTest(day):
                self.assertEqual((why, _sha(s.encode())[:8], v["prev_hash"], v["first_day"]), ("", want, prev, keys["erster_tag"]))
                self.assertTrue(V.ed25519_verify(bytes.fromhex(pub[obj["entry"]["server_key_id"]]), bytes.fromhex(obj["entry"]["server_signature"]), s.encode()))
                self.assertGreaterEqual(V.ms(v["server_ts"]), V.day_end_ms(V.day_ord(day)))
                self.assertEqual([V.vl_judge_stamp(t, s.encode(), roots, V.test_spki(self.reg), {})["reason"] for t in obj["timestamps"]], ["published_test_key"])
                pos = [p for p, _r in leaves["leaves"]]
                self.assertEqual((pos, len(pos), leaves["log_id"], leaves["day"]), (sorted(set(pos)), v["tree_size"], LOG_ID, day))   # (a), (b)
                self.assertEqual(V.mth([V.vl_day_leaf(r, p) for p, r in leaves["leaves"]]).hex(), v["root"])                       # (c)
            prev = _sha(s.encode())
        for name in ("2025.json", "2026.json", "auszug_abwesend_2026-01-01.json"):
            self.assertEqual(V.extract_grammar(rd(name)), LOG_ID)
        self.assertEqual(rd("head.json"), rd("days", "2026", "2026-01-01.json"))
        x = rd("auszug_abwesend_2026-01-01.json")
        v = json.loads(x["days"][0]["entry"]["statement_jcs"])
        nbs = x["chain_days"][0]["absent"]["neighbours"]
        self.assertEqual(([n["leaf_index"] for n in nbs], nbs[0]["position"]), ([2, 3], t_fillers("2026-01-01", 1)[1][0][0]))   # candidate 0 and the chain
        between = nbs[0]["position"][:-1] + ("f" if nbs[0]["position"][-1] != "f" else "e")
        self.assertTrue(nbs[0]["position"] < between < nbs[1]["position"])
        self.assertTrue(V.vl_absent_holds(between, v["tree_size"], bytes.fromhex(v["root"]), nbs))
        self.assertFalse(V.vl_absent_holds(nbs[1]["position"], v["tree_size"], bytes.fromhex(v["root"]), nbs))

    def test_5_absence_proof_forms(self):
        """Section 5, absence proof: exactly one of (i) n = 0 and no neighbour, (ii) a neighbour at index 0 above p, (iii)
        a neighbour at index n - 1 below p, (iv) neighbours at i and i + 1 around p; every neighbour holds by inclusion
        against (n, R); positions compare as unsigned 32-byte values (lowercase hex)."""
        pairs = [("%d0" % (k + 1) * 32, _sha(b"r%d" % k)) for k in range(5)]                    # positions 1010.., 2020.., ..., 5050..
        leaves = [t_dleaf(p, r) for p, r in pairs]
        n, root = len(leaves), _rmth(leaves)
        nb = lambda i, **o: dict({"leaf_index": i, "position": pairs[i][0], "chain_root": pairs[i][1], "path": [h.hex() for h in _rpath(i, leaves)]}, **o)
        lo, mid, hi = "00" * 32, "1f" * 32, "ff" * 32
        for why, p, nbs, want in (("(ii)", lo, [nb(0)], True), ("(iii)", hi, [nb(4)], True), ("(iv)", mid, [nb(0), nb(1)], True),
                                  ("(iv) between 3 and 4", "4f" * 32, [nb(3), nb(4)], True),
                                  ("(ii) with p above the neighbour", mid, [nb(0)], False), ("(iii) with p below", mid, [nb(4)], False),
                                  ("one neighbour inside", mid, [nb(1)], False), ("p equal to a position", pairs[1][0], [nb(0), nb(1)], False),
                                  ("p equal to a position, (ii)", pairs[0][0], [nb(0)], False),
                                  ("not adjacent", "2f" * 32, [nb(0), nb(2)], False), ("p outside the pair", "3f" * 32, [nb(0), nb(1)], False),
                                  ("no neighbour, n > 0", mid, [], False), ("a path that does not hold", lo, [nb(0, chain_root="00" * 32)], False),
                                  ("an index the path does not fit", hi, [nb(4, leaf_index=3)], False),
                                  ("equal leaf_index twice", mid, [nb(0), nb(0)], False)):
            with self.subTest(why): self.assertIs(V.vl_absent_holds(p, n, root, nbs), want)
        self.assertTrue(V.vl_absent_holds(mid, 0, V.MTH_EMPTY, []))                                   # (i)
        self.assertFalse(V.vl_absent_holds(mid, 0, V.MTH_EMPTY, [nb(0)]))
        one = [t_dleaf(*pairs[2])]
        self.assertTrue(V.vl_absent_holds(lo, 1, _rmth(one), [{"leaf_index": 0, "position": pairs[2][0], "chain_root": pairs[2][1], "path": []}]))   # (ii) = (iii) at n = 1
        self.assertTrue(V.vl_absent_holds(hi, 1, _rmth(one), [{"leaf_index": 0, "position": pairs[2][0], "chain_root": pairs[2][1], "path": []}]))

    # ---------------------------------------------------------------- L0, L1

    def test_7_4_10_L0_files_and_embedded_extracts(self):
        """L0, 8.8.2, 10.10.2: every extract counts as a file, an embedded one with the bytes UTF-8(JCS(element));
        distinct_files counts distinct bytes; seen_in counts the distinct files carrying c(head)."""
        log = self.honest()
        x = log.extract(records=[log.present("2026-01-01")])
        f1 = os.path.join(self.tmp, "x.json")
        with open(f1, "w") as fh: json.dump(x, fh, indent=1)
        h = os.path.join(self.tmp, "h.json")
        with open(h, "w") as fh: json.dump({"format": "ledger-ankerhistorie/2", "pages": [page()], "vendor_log": [x]}, fh)
        lst = os.path.join(self.tmp, "l.json")
        with open(lst, "w") as fh: json.dump(self.plist, fh)
        root = write_pem(os.path.join(self.tmp, "r.pem"), self.tsa.root)
        code, j, err = self.cli(self.p, "--json", "--now", self.NOW, "--freshness", "1000h", "--vendor-root", self.f_root(), "--vendor-key-list", lst,
                                "--vendor-log-tsa-root", root, "--vendor-log", f1, "--vendor-log", f1, "--anchor-history", h)
        vl = j["vendor_log"]
        self.assertEqual((vl["files"], vl["distinct_files"], vl["head"]["seen_in"], vl["days"]["supplied"]), (3, 2, 2, 2), err)
        self.assertEqual(vl["receipts"]["included"], 3)

    def f_root(self):
        path = os.path.join(self.tmp, "root.json")
        with open(path, "w") as fh: json.dump({"wurzel_id": "wurzel-test", "pubkey": pubkey(ROOT_SEED).hex()}, fh)
        return path

    def test_7_4_10_L1_no_extract(self):
        """L0, L1, 10.10.2: without an extract the status is not_supplied, every other member null, empty or 0, and no
        finding, also with an effective protocol key list or a pin."""
        for kw in ({}, {"pins": {"log-1": pubkey(LOG_SEED).hex()}}):
            code, f, vl, cls = self.vl(**kw)
            self.assertEqual((code, f, cls), (0, [], []))
            self.assertEqual(vl, {"status": "not_supplied", "log_id": None, "first_day": None, "key_source": None, "key_list": None, "places": [], "files": 0,
                                  "distinct_files": 0, "head": None, "days": {"supplied": 0, "established": 0, "witnessed": 0, "contradictory": 0, "missing": 0,
                                                                              "signatures_not_checked": 0},
                                  "tsa": {"cms_checked": True, "roots_supplied": 0}, "receipts": None, "last_countersigned": None, "logged_roots": None,
                                  "foreign_chain_records": 0})

    def test_7_4_10_L1_no_protocol_key(self):
        """L1 item 4: no protocol key remains and an extract is supplied: VENDOR_LOG_UNVERIFIED once without a day with the
        reason; status no_protocol_key; L2 to L9 dropped, receipt classes undetermined (receipts, last_countersigned and
        logged_roots null)."""
        log = self.honest()
        x = log.extract(records=[log.present("2026-01-01")])
        cs2 = json.loads(vendor_list([{"key_id": "cs-2", "pubkey": pubkey(CS2_SEED).hex(), "gueltig_ab": "2025-01-01T00:00:00Z"}]))
        texts = self.reg["vendor_log"]["no_protocol_key_reasons"]["texts"]
        for reason, kw in (("no_list", {"lists": []}), ("no_matching_root", {"lists": [proto_list([("log-1", LOG_SEED)], root_id="other")]}),
                           ("signature_fails", {"lists": [proto_list([("log-1", LOG_SEED)], seed=DEV_SEED)]}),
                           ("format_violated", {"lists": [proto_list([("log-1", LOG_SEED)], kommentar="x")]}),
                           ("lists_contradictory", {"lists": [self.plist, proto_list([("log-1", LOG_SEED)])]}),
                           ("key_in_two_roles", {"lists": [proto_list([("log-1", VENDOR_SEED)])]}),
                           ("log_id_differs", {"lists": [proto_list([("log-1", LOG_SEED)], log_id="ledger-testprotokoll-2")]}),
                           ("key_in_two_roles", {"lists": [cs2], "pins": {"log-1": pubkey(CS2_SEED).hex()}}),
                           # Decision C: "Ist keine Liste wirksam und ist jede Anheftung eines Protokollschluessels nach
                           # Nummer 3 entfallen": also when a list was passed and is not effective (here no matching root).
                           ("key_in_two_roles", {"lists": [cs2, proto_list([("log-1", LOG_SEED)], root_id="other")],
                                                 "pins": {"log-1": pubkey(CS2_SEED).hex()}})):
            with self.subTest(reason):
                code, f, vl, cls = self.vl(x, **kw)
                self.assertEqual((code, [c for c, _d in f], cls), (1, ["VENDOR_LOG_UNVERIFIED"], []))
                self.assertIn("without day: no protocol key established by an anchor of the auditor (" + texts[reason]["en"] + ")", f[0][1])
                self.assertEqual((vl["status"], vl["log_id"], vl["first_day"], vl["key_source"], vl["receipts"], vl["last_countersigned"], vl["logged_roots"], vl["head"]),
                                 ("no_protocol_key", LOG_ID, None, None, None, None, None, None))
                self.assertEqual(V.vendor_log_text(vl, self.res.vlog, self.reg["vendor_log"], "en"),
                                 self.reg["vendor_log"]["texts"]["no_protocol_key"]["en"].format(reason=texts[reason]["en"]))

    def test_7_4_10_L1_key_sources(self):
        """L1 items 1, 2 and 5, 10.10.2: key_source list, pinned or list_and_pinned; key_list and places of the effective
        list; with pins only F comes from L2 (f); a pin takes precedence for its key_id and has no end."""
        log = self.honest()
        x = log.extract(records=[log.present("2026-01-01")])
        code, f, vl, cls = self.vl(x)
        self.assertEqual((code, f, vl["key_source"], vl["first_day"], vl["places"]), (0, [], "list", "2025-12-31", ["https://a.example/x", "https://b.example/x"]))
        self.assertEqual(vl["key_list"], {"version": 1, "ausgestellt": "2025-12-30T10:00:00.000Z", "wurzel_id": "wurzel-test", "root_source": "vendor_root"})
        code, f, vl, cls = self.vl(x, lists=[], pins={"log-1": pubkey(LOG_SEED).hex()})
        self.assertEqual((code, vl["key_source"], vl["first_day"], vl["key_list"], vl["places"], cls), (0, "pinned", "2025-12-31", None, [], [("included", None)] * 3))
        # a revoked list key: with its pin (no end) the entry counts, without the pin it does not (L2 (e))
        rev = proto_list([("log-1", LOG_SEED)], version=2, schluessel=[{"key_id": "log-1", "pubkey": pubkey(LOG_SEED).hex(), "gueltig_ab": "2025-12-30T00:00:00.000Z",
                                                                          "widerrufen_ab": "2026-01-01T00:00:00Z"}])
        x2 = TLog(self.tsa).extract(objs=[])
        code, f, vl, cls = self.vl(x, lists=[rev], log_roots=[])
        self.assertIn("validity of the protocol key ended", " ".join(d for _c, d in f))
        code, f, vl, cls = self.vl(x, lists=[rev], pins={"log-1": pubkey(LOG_SEED).hex()}, log_roots=[])
        self.assertEqual((vl["key_source"], vl["days"]["established"]), ("list_and_pinned", 2))
        self.assertEqual(self.cls(f), ["VENDOR_LOG_UNVERIFIED"])                 # not witnessed: no root of purpose log
        self.assertEqual(x2["days"], [])

    # ---------------------------------------------------------------- L2

    def test_7_4_10_L2_pooling(self):
        """L2: day objects of all extracts pooled by statement_jcs; time stamps and signature pairs united as sets, an
        ed25519 element of additional_signatures a pair, no pair displacing another whatever the file order; elements of
        another alg counted once each (signatures_not_checked), never checked and never a finding (7.4.8)."""
        log = self.honest()
        d1 = log.days["2026-01-01"]
        seal = {"alg": "ecdsa-p256-sha256", "key_id": "seal-1", "signature": "3045" + "ab" * 20}
        a = log.obj(d1["stmt"], stamps=[], keys=[("log-2", LOG2_SEED)], extra=[seal])                                  # no stamp, another key
        b = log.obj(d1["stmt"], stamps=[_gt("2026-01-01", 400000)], keys=[("log-x", DEV_SEED), ("log-1", LOG_SEED)],
                    extra=[seal, dict(seal, key_id="seal-2")])                                                         # a key not established first
        recs = [log.present("2026-01-01")]
        for order in ((a, b), (b, a)):
            x1 = log.extract(objs=[log.days["2025-12-31"]["obj"], order[0]], records=recs)
            x2 = log.extract(objs=[order[1]], chain_id=None)
            code, f, vl, cls = self.vl(x1, x2)
            with self.subTest(first=order[0]["entry"]["server_key_id"]):
                self.assertEqual((code, f, cls), (0, [], [("included", None)] * 3))
                self.assertEqual((vl["days"]["supplied"], vl["days"]["established"], vl["days"]["signatures_not_checked"], vl["head"]["seen_in"]), (2, 2, 2, 2))

    def test_7_4_10_L2_a_key_not_established(self):
        """L2 (a): no pair names an established protocol key: VENDOR_LOG_UNVERIFIED(dayOf(o)) key not established, the
        object establishes nothing (the due day is then missing, L7); dayOf without a readable day: no day."""
        log = self.honest(keys=[("log-x", DEV_SEED)])
        x = log.extract(objs=[log.days["2025-12-31"]["obj"], log.days["2026-01-01"]["obj"], log.obj("kein JSON", keys=[("log-y", DEV_SEED)])])
        code, f, vl, cls = self.vl(x)
        self.assertEqual((code, cls), (1, [("missing", None)] * 3))
        self.assertEqual(sorted(d.split(": ")[0] for c, d in f), ["2026-01-01", "2026-01-01 to 2026-01-01", "without day"])
        self.assertIn("2026-01-01: key not established (log-x)", " | ".join(d for _c, d in f))
        self.assertEqual((vl["days"]["supplied"], vl["days"]["established"], vl["days"]["missing"]), (3, 1, 1))

    def test_7_4_10_L2_b_signatures(self):
        """L2 (b): every pair under an established key is checked; one that does not hold gives VENDOR_LOG_DEFECTIVE
        signature without removing the object; if none holds the object is not established."""
        log = self.honest(keys=[("log-1", DEV_SEED), ("log-2", LOG2_SEED)])      # entry signed with the wrong key under log-1
        x = log.extract(records=[log.present("2026-01-01")])
        code, f, vl, cls = self.vl(x)
        self.assertEqual((code, self.cls(f), cls), (1, ["VENDOR_LOG_DEFECTIVE"], [("included", None)] * 3))
        self.assertIn("2026-01-01: signature (key log-1)", f[0][1])
        log = self.honest(keys=[("log-1", DEV_SEED)])
        code, f, vl, cls = self.vl(log.extract(records=[log.present("2026-01-01")]))
        self.assertEqual((code, self.cls(f), cls, vl["days"]["established"]), (1, ["VENDOR_LOG_DEFECTIVE", "VENDOR_LOG_UNVERIFIED"], [("missing", None)] * 3, 1))

    def test_7_4_10_L2_c_format(self):
        """L2 (c): a signed content that violates 7.4.5 (printable ASCII, I-JSON, own JCS form, exactly the members with
        their types, kind, log_id of the extracts, log range, form of server_ts) is VENDOR_LOG_CONTRADICTION(dayOf(o))
        signed entry violates the format; it establishes nothing."""
        good = self.honest().days["2026-01-01"]["stmt"]
        v = json.loads(good)
        for why, s, day in (("not printable ASCII", good.replace("ledger-testprotokoll-1", "ledger-testprotokoll-ä1"), "2026-01-01"),
                            ("not its own JCS form", json.dumps(v, sort_keys=True), "2026-01-01"),
                            ("members out of order", _j(v).decode().replace('"day":"2026-01-01",', "")[:-1] + ',"day":"2026-01-01"}', "2026-01-01"),
                            ("a member missing", _j({k: x for k, x in v.items() if k != "root"}).decode(), "2026-01-01"),
                            ("a member more", _j(dict(v, x=1)).decode(), "2026-01-01"), ("kind", _j(dict(v, kind="ledger.vendor_log_day.v2")).decode(), "2026-01-01"),
                            ("log_id of another log", _j(dict(v, log_id="ledger-testprotokoll-2")).decode(), "2026-01-01"),
                            ("day outside the log range", _j(dict(v, day="1999-12-31")).decode(), "1999-12-31"),
                            ("first_day no date", _j(dict(v, first_day="2025-12-32")).decode(), "2026-01-01"),
                            ("server_ts without fraction", _j(dict(v, server_ts="2026-01-02T00:05:00Z")).decode(), "2026-01-01"),
                            ("server_ts with 6 digits", _j(dict(v, server_ts="2026-01-02T00:05:00.000000Z")).decode(), "2026-01-01"),
                            ("tree_size negative", _j(dict(v, tree_size=-1)).decode(), "2026-01-01"), ("tree_size true", _j(dict(v, tree_size=True)).decode(), "2026-01-01"),
                            ("root uppercase", _j(dict(v, root=v["root"].upper())).decode(), "2026-01-01"),
                            ("a member twice: no I-JSON, so no day", good[:-1] + ',"tree_size":5}', None), ("no JSON", "kein JSON", None), ("an array", "[]", None),
                            ("a number with a fraction: no I-JSON (2), so no day", _j(dict(v, tree_size=5)).decode().replace('"tree_size":5', '"tree_size":5.0'), None)):
            log = self.honest(statement_jcs=s)
            code, f, vl, cls = self.vl(log.extract(records=[log.present("2026-01-01")]))
            with self.subTest(why):
                contra = [d for c, d in f if c == "VENDOR_LOG_CONTRADICTION"]
                self.assertEqual((code, len(contra), contra[0].split(": ")[0], cls), (1, 1, day or "without day", [("missing", None)] * 3), f)
                self.assertIn("signed entry violates the format", contra[0])

    def test_7_4_10_L2_e_validity_of_the_key(self):
        """L2 (d), (e): a holding pair counts if its key has no end, or if a confirmed stamp of the object shows a genTime
        before the end (the earlier of gueltig_bis and widerrufen_ab), compared to the nanosecond with the full genTime;
        else VENDOR_LOG_UNVERIFIED(d) and the object is not established; gueltig_ab is not checked (here after server_ts)."""
        def lst(**end): return proto_list([("log-1", LOG_SEED)], schluessel=[dict({"key_id": "log-1", "pubkey": pubkey(LOG_SEED).hex(), "gueltig_ab": "2026-01-02T00:05:30Z"}, **end),
                                                                            {"key_id": "log-2", "pubkey": pubkey(LOG2_SEED).hex(), "gueltig_ab": "2025-12-30T00:00:00Z"}])
        for why, end, gen, kw, ok in (("before the revocation", {"widerrufen_ab": "2026-01-02T00:06:00.000000001Z"}, "20260102000600Z", {}, True),
                                      ("the same millisecond, a nanosecond later", {"widerrufen_ab": "2026-01-02T00:06:00Z"}, "20260102000600.000000001Z", {}, False),
                                      ("at the end", {"gueltig_bis": "2026-01-02T00:06:00Z"}, "20260102000600Z", {}, False),
                                      ("the earlier of the two", {"gueltig_bis": "2026-01-02T00:07:00Z", "widerrufen_ab": "2026-01-02T00:06:00Z"}, "20260102000630Z", {}, False),
                                      ("before, but no root of purpose log", {"widerrufen_ab": "2026-01-02T00:10:00Z"}, "20260102000600Z", {"log_roots": []}, False),
                                      ("before, the stamp of another authority", {"widerrufen_ab": "2026-01-02T00:10:00Z"}, "20260102000600Z", {"log_roots": [self.other_tsa.root]}, False)):
            log = TLog(self.tsa)
            log.close("2025-12-31", fillers=0, stamps=["20260101000600Z"], keys=[("log-2", LOG2_SEED)])
            log.close("2026-01-01", chains={(CHAIN, APPLIANCE): self.rows}, stamps=[gen])
            code, f, vl, cls = self.vl(log.extract(records=[log.present("2026-01-01")]), lists=[lst(**end)], **kw)
            with self.subTest(why):
                ended = [d for c, d in f if "validity of the protocol key ended" in d]
                self.assertEqual((bool(ended), vl["days"]["established"]), (not ok, 2 if ok else 1), f)
                if not ok: self.assertTrue(ended[0].startswith("2026-01-01: "))
        # re-signed under log-2 (no end) in additional_signatures: established (7.4.5 "Die Identitaet ist der Inhalt")
        log = TLog(self.tsa)
        log.close("2025-12-31", fillers=0, keys=[("log-2", LOG2_SEED)])
        log.close("2026-01-01", chains={(CHAIN, APPLIANCE): self.rows}, keys=[("log-1", LOG_SEED), ("log-2", LOG2_SEED)], stamps=["20260102000700Z"])
        code, f, vl, cls = self.vl(log.extract(records=[log.present("2026-01-01")]), lists=[lst(widerrufen_ab="2026-01-02T00:06:00Z")])
        self.assertEqual((code, f, cls), (0, [], [("included", None)] * 3))

    def test_7_4_10_L2_f_start_with_pins(self):
        """L2 (f): with pins only the common first_day of the objects that passed (a) to (e) is F; none passed: F unknown
        without a finding; different values: one VENDOR_LOG_CONTRADICTION without day, F unknown, nothing established,
        every receipt unchecked first_day_contradictory, no further finding (L3 to L7 and L9 dropped)."""
        pins = {"log-1": pubkey(LOG_SEED).hex()}
        log = self.honest()
        code, f, vl, cls = self.vl(log.extract(days=["2026-01-01"], records=[log.present("2026-01-01")]), lists=[], pins=pins)
        self.assertEqual((code, f, vl["first_day"], cls), (0, [], "2025-12-31", [("included", None)] * 3))
        other = TLog(self.tsa, first_day="2026-01-01")
        other.close("2026-01-01", chains={(CHAIN, APPLIANCE): self.rows})
        x = log.extract(objs=[log.days["2025-12-31"]["obj"], other.days["2026-01-01"]["obj"]], records=[other.present("2026-01-01")])
        code, f, vl, cls = self.vl(x, lists=[], pins=pins)
        self.assertEqual((code, f, cls), (1, [("VENDOR_LOG_CONTRADICTION", f[0][1])], [("unchecked", "first_day_contradictory")] * 3))
        self.assertTrue(f[0][1].startswith("without day: day entries under pinned keys name no common first_day (2025-12-31, 2026-01-01)"), f)
        self.assertEqual((vl["first_day"], vl["head"], vl["days"]["established"], vl["days"]["missing"], vl["last_countersigned"], vl["logged_roots"]["matching_prefix"]),
                         (None, None, 0, 0, "unchecked", 0))
        self.assertTrue(self.res.vlog["contradiction_in_range"])
        code, f, vl, cls = self.vl(log.extract(), lists=[], pins={"log-1": pubkey(DEV_SEED).hex()})     # nothing passes (b): F unknown
        self.assertEqual((vl["first_day"], cls), (None, [("missing", None)] * 3))
        self.assertEqual(self.cls(f), ["VENDOR_LOG_DEFECTIVE", "VENDOR_LOG_UNVERIFIED"])

    def test_7_4_10_L2_g_rules(self):
        """L2 (g): d >= F; prev_hash 64 zeros exactly on F; tree_size 0 only with SHA-256(""); server_ts in whole ms at least
        end(d); first_day = F. A violation is VENDOR_LOG_CONTRADICTION(d) a rule of the log; nothing established."""
        for why, kw, day in (("server_ts 1 ms before the end", {"server_ts": "2026-01-01T23:59:59.999Z"}, "2026-01-01"),
                             ("prev_hash zero after F", {"prev_hash": "0" * 64}, "2026-01-01"),
                             ("first_day other than F", {"first_day": "2025-12-30"}, "2026-01-01")):
            log = self.honest(**kw)
            code, f, vl, cls = self.vl(log.extract(records=[log.present("2026-01-01")]))
            with self.subTest(why):
                self.assertEqual((code, cls), (1, [("missing", None)] * 3))
                self.assertIn(f"{day}: signed entry violates a rule of the log", " | ".join(d for c, d in f if c == "VENDOR_LOG_CONTRADICTION"))
        log = TLog(self.tsa)
        log.close("2025-12-31", fillers=0, prev_hash="11" * 32)                 # the start without zeros
        log.close("2025-12-30", fillers=0)                                      # before F
        log.close("2026-01-01", chains={(CHAIN, APPLIANCE): self.rows}, prev_hash=_sha(log.days["2025-12-31"]["stmt"].encode()))
        code, f, vl, cls = self.vl(log.extract(records=[log.present("2026-01-01")]))
        self.assertEqual(sorted(d.split(": ")[0] for c, d in f if c == "VENDOR_LOG_CONTRADICTION"), ["2025-12-30", "2025-12-31"])
        self.assertEqual(cls, [("included", None)] * 3)                          # the effect stays on its day (L3)
        log = TLog(self.tsa)
        log.close("2025-12-31", fillers=0, root="11" * 32)                       # tree_size 0 with another root
        code, f, vl, cls = self.vl(log.extract())
        self.assertIn("2025-12-31: signed entry violates a rule of the log (tree_size 0 with a root", " ".join(d for _c, d in f))
        log = TLog(self.tsa)
        log.close("2025-12-31", fillers=0, server_ts="2026-01-01T00:00:00.000Z")   # exactly end(d) keeps the rule
        code, f, vl, cls = self.vl(log.extract())
        self.assertEqual((vl["days"]["established"], [c for c, _d in f]), (1, ["VENDOR_LOG_UNVERIFIED"]))   # the due day 2026-01-01 is missing

    def test_7_4_10_L2_h_time_stamps(self):
        """L2 (h), 7.4.6: an established object with a defective stamp is VENDOR_LOG_DEFECTIVE(d); a confirmed stamp
        before end(d) + 60 000 ms breaks it (VENDOR_LOG_CONTRADICTION closed before its end); witnessed with a
        confirmed stamp in [end(d) + 60 000, end(d) + W); late from end(d) + W; genTime cut to whole milliseconds."""
        for why, stamps, want_cls, want_f in (
                ("at end + 60 s", [_gt("2026-01-01", 60000)], ("included", None), []),
                ("at end + 60 s - 1 ms", [_gt("2026-01-01", 59999)], ("unchecked", "day_contradictory"), ["VENDOR_LOG_CONTRADICTION"]),
                ("at end + 59.9999 s, cut to ms", ["20260102000059.9999Z"], ("unchecked", "day_contradictory"), ["VENDOR_LOG_CONTRADICTION"]),
                ("at end + W - 1 ms", [_gt("2026-01-01", 172799999)], ("included", None), []),
                ("at end + W", [_gt("2026-01-01", 172800000)], ("unchecked", "day_not_witnessed"), ["VENDOR_LOG_UNVERIFIED"]),
                ("premature beside witnessing", [_gt("2026-01-01", 30000), _gt("2026-01-01", 360000)], ("unchecked", "day_contradictory"), ["VENDOR_LOG_CONTRADICTION"])):
            log = self.honest(stamps=stamps)
            code, f, vl, cls = self.vl(log.extract(records=[log.present("2026-01-01")]))
            with self.subTest(why):
                self.assertEqual((cls[0], self.cls(f)), (want_cls, want_f), f)
                if want_f == ["VENDOR_LOG_CONTRADICTION"]: self.assertIn("2026-01-01: day closed before its end", f[0][1])
                if why == "at end + W": self.assertIn("day entry not witnessed (late)", f[0][1])
        log = self.honest()
        bad = log.obj(log.days["2026-01-01"]["stmt"], stamps=[_gt("2026-01-01", 360000)], keys=[("log-2", LOG2_SEED)])
        bad["timestamps"] = [base64.b64encode(self.tsa.token(b"other bytes", gentime=_gt("2026-01-01", 420000))).decode(), "not base64!"]
        code, f, vl, cls = self.vl(log.extract(records=[log.present("2026-01-01")]), log.extract(objs=[bad], chain_id=None))
        self.assertEqual((code, f, cls), (1, [("VENDOR_LOG_DEFECTIVE", "2026-01-01: time stamp does not hold (7.4.10, 7.4.11)")], [("included", None)] * 3))

    # ---------------------------------------------------------------- L3 to L5

    def test_7_4_10_L3_days_and_canonical_entry(self):
        """L3: two established entries of a day are VENDOR_LOG_CONTRADICTION two signed versions with both day hashes;
        c(d) is the witnessed one, else the only unbroken one when none is witnessed; usable if c(d) is witnessed; a
        contradiction stays on its day."""
        log = self.honest()
        late = TLog(self.tsa); late.prev = _sha(log.days["2025-12-31"]["stmt"].encode())
        late.close("2026-01-01", chains={(CHAIN, APPLIANCE): self.rows}, server_ts=_ts("2026-01-01", 2100000), stamps=[])       # re-closed, not witnessed
        x = log.extract(records=[log.present("2026-01-01")], objs=[log.days["2025-12-31"]["obj"], log.days["2026-01-01"]["obj"], late.days["2026-01-01"]["obj"]])
        code, f, vl, cls = self.vl(x)
        hashes = sorted(_sha(s.encode()) for s in (log.days["2026-01-01"]["stmt"], late.days["2026-01-01"]["stmt"]))
        self.assertEqual((code, f, cls), (1, [("VENDOR_LOG_CONTRADICTION", f"2026-01-01: two signed versions (day hashes {hashes[0]}, {hashes[1]}) (7.4.10, 7.4.11)")],
                                          [("included", None)] * 3))
        self.assertEqual((vl["days"]["contradictory"], vl["days"]["established"], vl["days"]["witnessed"], vl["head"]["day_hash"]), (1, 3, 2, _sha(log.days["2026-01-01"]["stmt"].encode())))
        both = TLog(self.tsa); both.prev = _sha(log.days["2025-12-31"]["stmt"].encode())
        both.close("2026-01-01", chains={(CHAIN, APPLIANCE): self.rows}, server_ts=_ts("2026-01-01", 2100000))                # re-closed and witnessed too
        code, f, vl, cls = self.vl(log.extract(objs=[log.days["2025-12-31"]["obj"], log.days["2026-01-01"]["obj"], both.days["2026-01-01"]["obj"]],
                                               records=[log.present("2026-01-01")]))
        self.assertEqual((cls, vl["head"]["day"]), ([("unchecked", "day_contradictory")] * 3, "2025-12-31"))
        broken = self.honest(stamps=[_gt("2026-01-01", 1000)])                   # broken by a premature confirmed stamp
        code, f, vl, cls = self.vl(log.extract(objs=[log.days["2025-12-31"]["obj"], broken.days["2026-01-01"]["obj"], late.days["2026-01-01"]["obj"]]))
        self.assertEqual((cls, vl["head"]["day_hash"], vl["head"]["witnessed"]), ([("unchecked", "day_not_witnessed")] * 3, _sha(late.days["2026-01-01"]["stmt"].encode()), False))

    def test_7_4_10_L4_head(self):
        """L4: the head is the latest day with c(d) determined, its day hash, tree_size, witnessed and seen_in, the number of
        distinct files carrying its statement_jcs; the text block names it in three lines, the second and third indented by
        two spaces; without a head only the first line is replaced (10.10.3)."""
        log = self.honest()
        x = log.extract(records=[log.present("2026-01-01")])
        y = log.extract(days=["2026-01-01"], chain_id=None)
        code, f, vl, cls = self.vl(x, x, y, log.extract(days=["2025-12-31"], chain_id=None))
        self.assertEqual(vl["head"], {"day": "2026-01-01", "day_hash": log.prev, "tree_size": 5, "witnessed": True, "seen_in": 2})
        self.assertEqual((vl["files"], vl["distinct_files"]), (4, 3))
        de = V.vendor_log_text(vl, self.res.vlog, self.reg["vendor_log"], "de")
        self.assertEqual(de.split("\n"), [f"Herstellerprotokoll {LOG_ID}: Kopf 2026-01-01, Tageshash {log.prev}, bezeugt: ja, in 2 von 3 Dateien.",
                                           "  Quittungen: 3 nachgewiesen, 0 fehlen, 0 nicht prüfbar, 0 ohne Tageseintrag, 0 noch nicht fällig, "
                                           "0 vor Beginn des Protokolls, 0 nach dem Prüfzeitpunkt.",
                                           "  Vergleichen Sie den Tageshash mit dem zweiten Veröffentlichungsort."])
        code, f, vl, cls = self.vl(log.extract(objs=[]))
        en = V.vendor_log_text(vl, self.res.vlog, self.reg["vendor_log"], "en").split("\n")
        self.assertEqual((en[0], len(en), en[2]), (f"Vendor log {LOG_ID}: no day entry established.", 3, "  Compare the day hash with the second place of publication."))
        self.assertTrue(en[1].startswith("  Receipts: "), en[1])

    def test_7_4_10_L5_chaining(self):
        """L5: c(d + 1) whose prev_hash is not the day hash of c(d): VENDOR_LOG_CONTRADICTION(d + 1) does not link; c(d)
        with d > F, S(d - 1) empty and a prev_hash of an established entry of x < d - 1: skips the days x + 1 to d - 1."""
        log = self.honest(prev_hash="22" * 32)
        code, f, vl, cls = self.vl(log.extract(records=[log.present("2026-01-01")]))
        self.assertEqual((code, cls), (1, [("included", None)] * 3))
        self.assertTrue(f[0][1].startswith("2026-01-01: does not link to the previous day (prev_hash " + "22" * 32), f)
        log = TLog(self.tsa)
        log.close("2025-12-31", fillers=0)
        log.close("2026-01-01", chains={(CHAIN, APPLIANCE): self.rows})
        log.close("2026-01-02")
        log.close("2026-01-03", prev_hash=_sha(log.days["2026-01-01"]["stmt"].encode()))
        x = log.extract(days=["2025-12-31", "2026-01-01", "2026-01-03"], records=[log.present("2026-01-01")])
        code, f, vl, cls = self.vl(x, now="2026-01-04T12:00:00Z")
        self.assertEqual(f, [("VENDOR_LOG_CONTRADICTION", "2026-01-03: skips days (the days 2026-01-02 to 2026-01-02) (7.4.10, 7.4.11)"),
                             ("VENDOR_LOG_UNVERIFIED", f[1][1])])                # 2026-01-02 lies in [Lo, T] = [2026-01-01, 2026-01-03]: missing too (L7)
        self.assertTrue(f[1][1].startswith("2026-01-02 to 2026-01-02: days without an established day entry"), f)
        self.assertEqual((cls, vl["days"]["missing"], vl["days"]["contradictory"]), ([("included", None)] * 3, 1, 1))
        # the skipped day before the required range: reported as skipped, never as missing
        log = TLog(self.tsa, first_day="2025-12-30")
        log.close("2025-12-30", fillers=0)
        log.close("2025-12-31", fillers=0)
        log.close("2026-01-01", chains={(CHAIN, APPLIANCE): self.rows}, prev_hash=_sha(log.days["2025-12-30"]["stmt"].encode()))
        x = log.extract(days=["2025-12-30", "2026-01-01"], records=[log.present("2026-01-01")])
        code, f, vl, cls = self.vl(x, lists=[proto_list([("log-1", LOG_SEED)], erster_tag="2025-12-30")])
        self.assertEqual((f, cls, vl["days"]["missing"]), ([("VENDOR_LOG_CONTRADICTION", "2026-01-01: skips days (the days 2025-12-31 to 2025-12-31) (7.4.10, 7.4.11)")],
                                                            [("included", None)] * 3, 0))

    # ---------------------------------------------------------------- L6

    def test_7_4_10_L6_records(self):
        """L6: on a usable day a record present must hold by inclusion of the chain-day leaf (n and R from c(d), the
        position with GENESIS.appliance_id), a record absent as an absence proof of section 5; one that does not hold is
        VENDOR_LOG_DEFECTIVE(d) and the state failed; without a record the state is none (unchecked no_record with
        VENDOR_LOG_UNVERIFIED)."""
        log = self.honest()
        ok = log.present("2026-01-01")
        for why, rec, want_cls, want_f in (
                ("present", ok, ("included", None), []),
                ("roots in another order", dict(ok, present=dict(ok["present"], roots=ok["present"]["roots"][::-1])), ("included", None), []),
                ("leaf_index wrong", dict(ok, present=dict(ok["present"], leaf_index=ok["present"]["leaf_index"] ^ 1)), ("unchecked", "record_failed"), ["VENDOR_LOG_DEFECTIVE"]),
                ("a sibling flipped", dict(ok, present=dict(ok["present"], path=["00" * 32] + ok["present"]["path"][1:])), ("unchecked", "record_failed"), ["VENDOR_LOG_DEFECTIVE"]),
                ("a root missing", dict(ok, present=dict(ok["present"], roots=ok["present"]["roots"][:2])), ("unchecked", "record_failed"), ["VENDOR_LOG_DEFECTIVE"]),
                ("absent for a chain that is present", log.absent("2026-01-01", app="00000000-0000-4000-8000-000000000000"), ("unchecked", "record_failed"), ["VENDOR_LOG_DEFECTIVE"]),
                ("no record", None, ("unchecked", "no_record"), ["VENDOR_LOG_UNVERIFIED"])):
            code, f, vl, cls = self.vl(log.extract(records=[rec] if rec else []))
            with self.subTest(why):
                self.assertEqual((cls[0], self.cls(f)), (want_cls, want_f), f)
                if want_f: self.assertTrue(all(d.startswith("2026-01-01: ") for _c, d in f), f)
        # the same chain_id under another appliance: its records do not hold under the position of the package (7.4.3)
        other = TLog(self.tsa)
        other.close("2025-12-31", fillers=0)
        other.close("2026-01-01", chains={(CHAIN, "00000000-0000-4000-8000-000000000000"): self.rows})
        code, f, vl, cls = self.vl(other.extract(records=[other.present("2026-01-01", app="00000000-0000-4000-8000-000000000000")]))
        self.assertEqual((self.cls(f), cls[0], vl["logged_roots"]["contradicting_prefix"]), (["VENDOR_LOG_DEFECTIVE"], ("unchecked", "record_failed"), 0))

    def test_7_4_10_L6_absent_and_receipt_not_logged(self):
        """L6, L8: a day tree without the chain, proven absent (forms of section 5, a filler as neighbour like any leaf):
        not_included and RECEIPT_NOT_LOGGED(d) once with the number and the smallest seq; a tree of size 0 proves it
        with form (i)."""
        for fillers in (0, 1, 4, 9):
            log = TLog(self.tsa)
            log.close("2025-12-31", fillers=0)
            log.close("2026-01-01", fillers=fillers)
            rec = log.absent("2026-01-01")
            code, f, vl, cls = self.vl(log.extract(records=[rec]))
            with self.subTest(fillers=fillers, neighbours=len(rec["absent"]["neighbours"])):
                self.assertEqual((code, cls), (1, [("not_included", None)] * 3))
                self.assertEqual(f, [("RECEIPT_NOT_LOGGED", "2026-01-01: receipts missing from the witnessed chain day of their day: 3 receipts, smallest seq 5 (7.4.10 L8)")])
                self.assertEqual((vl["receipts"]["not_included"], vl["receipts"]["included_up_to_tree_size"], vl["last_countersigned"]), (3, None, "not_included"))
        # one receipt left out of the leaves: only it is not included
        part = TLog(self.tsa)
        part.close("2025-12-31", fillers=0)
        part.close("2026-01-01", chains={(CHAIN, APPLIANCE): self.rows[:1] + self.rows[2:]})
        code, f, vl, cls = self.vl(part.extract(records=[part.present("2026-01-01")]))
        self.assertEqual((cls, f[0][1]), ([("included", None), ("not_included", None), ("included", None)],
                                          "2026-01-01: receipts missing from the witnessed chain day of their day: 1 receipt, smallest seq 8 (7.4.10 L8)"))
        self.assertEqual(vl["receipts"]["included_up_to_tree_size"], 3)          # r5' (10.9.4): every receipt up to t good or neutral

    def test_7_4_10_L6_records_used_and_counted(self):
        """L6: only records of extracts with chain_id = C are used; others are counted (foreign_chain_records); records on
        a day that is not usable are not used (no finding); among holding records a root of another day or two records
        that differ (chain-day root, present against absent) are VENDOR_LOG_CONTRADICTION(d), the state contradictory."""
        log = self.honest()
        ok, foreign = log.present("2026-01-01"), "d4767e29-b2ab-48f5-9186-37d10dad22c0"
        bad = dict(ok, present=dict(ok["present"], leaf_index=0))
        code, f, vl, cls = self.vl(log.extract(records=[ok]), log.extract(days=[], records=[bad, dict(bad, day="2026-01-02")], chain_id=foreign))
        self.assertEqual((code, f, vl["foreign_chain_records"], cls), (0, [], 2, [("included", None)] * 3))
        nw = self.honest(stamps=[])                                                # the day not witnessed: its records are not used
        code, f, vl, cls = self.vl(nw.extract(records=[bad]))
        self.assertEqual((self.cls(f), cls[0]), (["VENDOR_LOG_UNVERIFIED"], ("unchecked", "day_not_witnessed")))
        # a row of another day inside a record that holds
        rows = self.rows + [dict(self.rows[0], server_ts="2026-01-02T00:00:01.000Z")]
        od = TLog(self.tsa)
        od.close("2025-12-31", fillers=0)
        od.close("2026-01-01", chains={(CHAIN, APPLIANCE): rows})
        code, f, vl, cls = self.vl(od.extract(records=[od.present("2026-01-01")]))
        self.assertEqual((f, cls), ([("VENDOR_LOG_CONTRADICTION", "2026-01-01: leaf of another day (2026-01-02T00:00:01.000Z) (7.4.10, 7.4.11)")],
                                    [("unchecked", "record_contradictory")] * 3))

    def test_7_4_10_L6_two_differing_records(self):
        """L6: two records that hold and differ (here in the chain-day root: a vendor writing two leaves under one
        position, which only the day leaves show, 7.4.3) make the state contradictory, with VENDOR_LOG_CONTRADICTION(d)
        two chain-day records; identical records in two files do not."""
        log = self.honest()
        ok = log.present("2026-01-01")
        code, f, vl, cls = self.vl(log.extract(records=[ok]), log.extract(days=[], records=[ok]))
        self.assertEqual((code, f, cls), (0, [], [("included", None)] * 3))
        # a vendor that writes two leaves under one position (7.4.3: shown only by the day leaves): both records hold
        pos = t_position("2026-01-01")
        dup = TLog(self.tsa)
        dup.close("2025-12-31", fillers=0)
        dup.close("2026-01-01", chains={(CHAIN, APPLIANCE): self.rows}, extra_pairs=[(pos, t_chain_root(self.rows[:1]))])
        d = dup.days["2026-01-01"]
        i = next(k for k, x in enumerate(d["pairs"]) if x[2] is None and x[0] == pos)
        other = {"day": "2026-01-01", "present": {"roots": self.rows[:1], "leaf_index": i, "path": [h.hex() for h in _rpath(i, d["leaves"])]}, "absent": None}
        code, f, vl, cls = self.vl(dup.extract(records=[dup.present("2026-01-01")]), dup.extract(days=[], records=[other]))
        self.assertEqual((f, cls), ([("VENDOR_LOG_CONTRADICTION", "2026-01-01: two chain-day records (7.4.10, 7.4.11)")], [("unchecked", "record_contradictory")] * 3))

    # ---------------------------------------------------------------- L7, L8

    def test_7_4_10_L7_required_range(self):
        """L7: [Lo, T] with Lo the earliest receipt day >= F and T the latest of the head and the due receipt days; every
        day there without an established entry is missing, one VENDOR_LOG_UNVERIFIED per run with start and end; never
        bounded by ts_chained; a day beyond the head that is not due stays pending without a finding."""
        log = TLog(self.tsa)
        for d in ("2025-12-31", "2026-01-01", "2026-01-02", "2026-01-03", "2026-01-04", "2026-01-05"):
            log.close(d, chains={(CHAIN, APPLIANCE): self.rows} if d == "2026-01-01" else None)
        x = log.extract(days=["2025-12-31", "2026-01-02", "2026-01-04", "2026-01-05"])
        code, f, vl, cls = self.vl(x, now="2026-01-06T12:00:00Z")
        runs = [d for c, d in f if c == "VENDOR_LOG_UNVERIFIED"]
        self.assertEqual([r.split(":")[0] for r in runs], ["2026-01-01 to 2026-01-01", "2026-01-03 to 2026-01-03"])
        self.assertTrue(all("days without an established day entry in the extracts supplied" in r for r in runs))
        self.assertEqual((vl["days"]["missing"], cls), (2, [("missing", None)] * 3))
        code, f, vl, cls = self.vl(log.extract(days=["2025-12-31", "2026-01-04"]), now="2026-01-06T12:00:00Z")
        self.assertEqual(([d.split(":")[0] for c, d in f if c == "VENDOR_LOG_UNVERIFIED"], vl["days"]["missing"]), (["2026-01-01 to 2026-01-03"], 3))
        code, f, vl, cls = self.vl(log.extract(days=["2025-12-31"]))                # a due receipt day beyond the head
        self.assertEqual(([d.split(":")[0] for c, d in f], cls), (["2026-01-01 to 2026-01-01"], [("missing", None)] * 3))
        code, f, vl, cls = self.vl(log.extract(days=["2025-12-31"]), now="2026-01-02T05:59:59.999Z")   # not due yet
        self.assertEqual((code, f, cls, vl["days"]["missing"]), (0, [], [("pending", None)] * 3, 0))

    def test_7_4_10_L8_classes(self):
        """L8, in order: before_start (d < F), future (server_ts more than 900 000 ms after now, VENDOR_LOG_UNVERIFIED),
        a usable day (included, not_included, unchecked no_record, record_failed, record_contradictory), c(d) not witnessed
        (unchecked day_not_witnessed), S(d) without c(d) (day_contradictory), S(d) empty (missing when due, else pending)."""
        log = self.honest()
        x = log.extract(records=[log.present("2026-01-01")])
        late = TLog(self.tsa, first_day="2026-01-02")
        late.close("2026-01-02")
        code, f, vl, cls = self.vl(late.extract(), lists=[proto_list([("log-1", LOG_SEED)], erster_tag="2026-01-02")])
        self.assertEqual((code, f, cls, vl["receipts"]["before_start"], vl["receipts"]["included_up_to_tree_size"]), (0, [], [("before_start", None)] * 3, 3, None))
        ts = [r["server_ts"] for r in self.rows]
        for now, want in ((later(ts[2], -900000), [("pending", None)] * 3), (later(ts[2], -900001), [("pending", None)] * 2 + [("future", None)])):
            code, f, vl, cls = self.vl(log.extract(days=["2025-12-31"]), now=now)
            with self.subTest(now=now):
                self.assertEqual(cls, want)
                self.assertEqual([d for _c, d in f], [] if want[2][0] == "pending" else [f"2026-01-01: receipt with server_ts after the check time (seq 11, server_ts {ts[2]}) (7.4.10, 7.4.11)"])
        code, f, vl, cls = self.vl(x)
        self.assertEqual((code, f, cls, vl["last_countersigned"], vl["receipts"]["included_up_to_tree_size"]), (0, [], [("included", None)] * 3, "included", 9))

    def test_7_4_10_L8_reasons_not_witnessed(self):
        """L8 case 4: c(d) determined, not witnessed: unchecked day_not_witnessed and VENDOR_LOG_UNVERIFIED(d) with the
        reason no_timestamp, no_log_root_supplied, or of the stamp that came furthest (outside_profile <
        not_chained_to_log_root < published_test_key < late); defective stamps do not count, and if every stamp is
        defective the finding is left out (VENDOR_LOG_DEFECTIVE reports the day)."""
        test_reg = json.loads(json.dumps(self.reg))
        test_reg["verifier"]["timestamp_profile"]["published_test_keys"].append({"spki_sha256": V.Cert(self.tsa.signer).spki_sha256})
        W = 172800000
        no_certs = lambda log: log.days["2026-01-01"]["obj"]["timestamps"].append(base64.b64encode(self.tsa.token(log.days["2026-01-01"]["stmt"].encode(),
                                                                                                    gentime=_gt("2026-01-01", 400000), carried=())).decode())
        for why, kw, run, want in (("no_timestamp", {"stamps": []}, {}, "no time stamp"),
                                   ("no_log_root_supplied", {}, {"log_roots": []}, "no root of the auditor for the log (--vendor-log-tsa-root)"),
                                   ("outside_profile", {"token_kw": {"carried": ()}}, {}, "outside the time-stamp profile"),
                                   ("not_chained_to_log_root", {}, {"log_roots": [self.other_tsa.root]}, "no path to a root of the auditor for the log"),
                                   ("published_test_key", {}, {"reg": test_reg}, "published test key"),
                                   ("late", {"stamps": [_gt("2026-01-01", W)]}, {}, "late"),
                                   ("late beats outside_profile", {"stamps": [_gt("2026-01-01", W + 5)], "post": no_certs}, {}, "late"),
                                   ("not chained beats outside_profile", {"post": no_certs}, {"log_roots": [self.other_tsa.root]}, "no path to a root of the auditor for the log"),
                                   ("a defective stamp does not count", {"stamps": [_gt("2026-01-01", W), "AAAA"]}, {}, "late"),
                                   ("every stamp defective", {"stamps": ["AAAA"]}, {}, None)):
            post = kw.pop("post", None)
            log = self.honest(**kw)
            if post: post(log)
            code, f, vl, cls = self.vl(log.extract(records=[log.present("2026-01-01")]), **run)
            with self.subTest(why):
                self.assertEqual(cls, [("unchecked", "day_not_witnessed")] * 3)
                nw = [d for c, d in f if c == "VENDOR_LOG_UNVERIFIED"]
                self.assertEqual(nw, [f"2026-01-01: day entry not witnessed ({want}) (7.4.10, 7.4.11)"] if want else [], f)
                if not want: self.assertEqual(self.cls(f), ["VENDOR_LOG_DEFECTIVE"])

    # ---------------------------------------------------------------- L9, L10, 7.4.11

    def test_7_4_10_L9_recorded_roots(self):
        """L9: every root of a checked present record on a usable day: t <= N and root(t) = r matches (a countersignature
        without the same leaf in the package also counts as matching_without_receipt); root(t) != r is
        LOGGED_ROOT_MISMATCH once per (t, r); t > N is beyond_package; gap witnesses counted; no root is an expected root."""
        N = len(self.c.entries)
        wrong = dict(self.rows[1], merkle_root="ab" * 32)
        rows = self.rows + [dict(self.rows[0], server_ts="2026-01-01T23:00:00.000Z"),           # a fresh repetition: no receipt in the package
                            dict(self.rows[0], recorded_as="gap_witness"), wrong, dict(wrong, server_ts="2026-01-01T23:30:00.000Z"),
                            dict(self.rows[0], tree_size=N + 5, merkle_root="cd" * 32)]
        log = TLog(self.tsa)
        log.close("2025-12-31", fillers=0)
        log.close("2026-01-01", chains={(CHAIN, APPLIANCE): rows})
        base_findings = [x for x in self.run_vl().findings]
        code, f, vl, cls = self.vl(log.extract(records=[log.present("2026-01-01")]))
        self.assertEqual((code, cls), (1, [("included", None)] * 3))
        self.assertEqual(f, [("LOGGED_ROOT_MISMATCH", f"2026-01-01: recorded root differs from the package's root: recorded as countersigned, tree_size 6, merkle_root {'ab' * 32}, "
                                                      f"the package's root {self.rows[1]['merkle_root']} (7.4.10 L9)")])
        self.assertEqual(vl["logged_roots"], {"matching_prefix": 3, "matching_without_receipt": 1, "contradicting_prefix": 1, "beyond_package": 1, "gap_witnesses": 1})
        self.assertEqual((self.res.vlog["t_m"], [b["tree_size"] for b in self.res.vlog["beyond"]]), (6, [N + 5]))
        self.assertEqual([x for x in self.res.findings if x["class"] != "LOGGED_ROOT_MISMATCH"], base_findings)   # nothing else changes, no exit 2
        self.assertEqual((self.res.completeness, self.res.last_countersigned["tree_size"]), ({"status": "not_established", "up_to_tree_size": None, "sources": []}, 9))

    def test_7_4_10_L9_receipt_invalid_is_still_a_receipt_of_its_leaf(self):
        """L9: matching_without_receipt counts a countersigned leaf "ohne Quittung desselben Blatts im Paket"; a receipt
        whose signature fails (RECEIPT_INVALID) is still a receipt of that leaf, since the leaf does not hold the
        signature (7.4.2). L8 passes it over, so its class is not counted."""
        def broken(es):
            es[self.rc[0]["seq"] - 1]["payload"]["server_signature"] = "00" * 64
        self.p = self.pkg(self.c, patch=broken)
        log = self.honest()
        code, f, vl, cls = self.vl(log.extract(records=[log.present("2026-01-01")]))
        self.assertEqual((code, cls), (2, [("included", None)] * 2), f)
        self.assertIn("RECEIPT_INVALID", {x["class"] for x in self.res.findings})
        self.assertEqual(vl["logged_roots"], {"matching_prefix": 3, "matching_without_receipt": 0, "contradicting_prefix": 0, "beyond_package": 0, "gap_witnesses": 0})

    def test_7_4_10_L7_L8_10_9_4_r5_receipts_without_receipt_invalid(self):
        """Decision D (7.4.10 L7, L8, 10.9.4 r5'): the three read the same receipts, every CHECKPOINT_RECEIPT whose
        signature holds under 7.1 and that has no RECEIPT_INVALID. A receipt whose signature holds but whose
        checkpoint_seq names a TICK (RECEIPT_INVALID) gets no class, adds no day to [Lo, T] and does not cut r5'.
        "auch bei einem Widerspruch oder Fork" is one of the chain: a receipt with FORK_DETECTED keeps its place in all three."""
        odd_ts, now = "2026-01-03T00:10:00.000Z", "2026-01-04T12:00:00Z"            # 2026-01-03 is due at now
        def signed(c, tree_size, root, checkpoint_seq):
            obj = {"chain_id": CHAIN, "tree_size": tree_size, "merkle_root": root, "server_ts": odd_ts}
            return c.add("CHECKPOINT_RECEIPT", {"checkpoint_seq": checkpoint_seq, "tree_size": tree_size, "merkle_root": root, "server_ts": odd_ts,
                                                "server_key_id": "vendor-1", "server_signature": sign(VENDOR_SEED, V.jcsb(obj)).hex()}, mono=1000)
        for why in ("RECEIPT_INVALID", "FORK_DETECTED"):
            c = Chain(OWN); tk = c.tick(); cp = c.anchor(); c.tick(); c.anchor()
            q = cp["payload"]
            odd = signed(c, q["tree_size"], q["merkle_root"], tk["seq"]) if why == "RECEIPT_INVALID" else signed(c, q["tree_size"], "ab" * 32, cp["seq"])
            c.close()
            self.p = self.pkg(c)
            rc = [e for e in c.entries if e["event_type"] == "CHECKPOINT_RECEIPT" and e["seq"] != odd["seq"]]
            log = TLog(self.tsa)
            log.close("2025-12-31", fillers=0)
            log.close("2026-01-01", chains={(CHAIN, APPLIANCE): [t_row(e) for e in rc]})
            code, f, vl, cls = self.vl(log.extract(records=[log.present("2026-01-01")]), now=now)
            with self.subTest(why):
                self.assertEqual(code, 2)
                self.assertIn(why, {x["class"] for x in self.res.findings})
                if why == "RECEIPT_INVALID":
                    self.assertEqual((f, cls, vl["days"]["missing"]), ([], [("included", None)] * 3, 0))
                    self.assertEqual(vl["receipts"], {"included": 3, "not_included": 0, "unchecked": 0, "missing": 0, "pending": 0, "before_start": 0, "future": 0,
                                                      "included_up_to_tree_size": rc[-1]["payload"]["tree_size"]})
                else:
                    self.assertEqual(cls, [("included", None)] * 2 + [("missing", None), ("included", None)])
                    self.assertEqual(([c_ for c_, _d in f], [d.split(":")[0] for _c, d in f], vl["days"]["missing"]), (["VENDOR_LOG_UNVERIFIED"], ["2026-01-02 to 2026-01-03"], 2))
                    self.assertIsNone(vl["receipts"]["included_up_to_tree_size"])      # the fork receipt has the smallest tree_size of a bad one

    def test_7_4_10_L10_report_exit_and_text(self):
        """L10, 7.4.11, 10.10: an honest witnessed log gives exit 0 without a finding; every finding of the log has exit
        class 1; the report object stands in the JSON output (null on a format error) and the block in the text report
        (left out on exit 3); the log changes no other result."""
        for cls in ("VENDOR_LOG_UNVERIFIED", "VENDOR_LOG_DEFECTIVE", "VENDOR_LOG_CONTRADICTION", "RECEIPT_NOT_LOGGED", "LOGGED_ROOT_MISMATCH"):
            self.assertEqual(self.reg["verifier"]["finding_classes"][cls]["exit"], 1)
        log = self.honest()
        x = os.path.join(self.tmp, "x.json")
        with open(x, "w") as fh: json.dump(log.extract(records=[log.present("2026-01-01")]), fh)
        lst, root = os.path.join(self.tmp, "l.json"), write_pem(os.path.join(self.tmp, "r.pem"), self.tsa.root)
        with open(lst, "w") as fh: json.dump(self.plist, fh)
        args = ["--now", self.NOW, "--freshness", "1000h", "--vendor-root", self.f_root(), "--vendor-key-list", lst, "--vendor-log-tsa-root", root, "--vendor-log", x]
        code, j, err = self.cli(self.p, "--json", *args)
        self.assertEqual((code, j["finding_classes"], j["vendor_log"]["status"], j["vendor_log"]["head"]["witnessed"]), (0, [], "checked", True), err)
        code, txt, err = self.cli(self.p, "--lang", "de", *args)
        self.assertIn(f"Herstellerprotokoll {LOG_ID}: Kopf 2026-01-01", txt)
        code, j0, err = self.cli(self.p, "--json", *args[:4])
        for k in ("completeness", "residual_window", "unanchored_stretches", "last_countersigned", "chain_end", "key_roles"):
            self.assertEqual(j[k], j0[k], k)
        self.assertEqual(j0["vendor_log"]["status"], "not_supplied")
        broken = Chain("2.0"); broken.anchor()
        code, j, err = self.cli(self.pkg(broken), "--json", *args)
        self.assertEqual((code, j["vendor_log"]), (3, None))
        code, txt, err = self.cli(self.pkg(broken), "--lang", "de", *args)
        self.assertNotIn("Herstellerprotokoll", txt)

    def test_7_4_11_one_finding_per_class_and_day(self):
        """7.4.11: per class and UTC day at most one finding with its reasons in step order, at most one without day; the
        runs of missing days, RECEIPT_NOT_LOGGED per day and LOGGED_ROOT_MISMATCH per (tree_size, merkle_root) apart."""
        log = self.honest(keys=[("log-1", DEV_SEED), ("log-2", DEV_SEED), ("log-x", LOG_SEED)], stamps=[_gt("2026-01-01", 360000), "AAAA"])
        bad = log.obj(log.days["2026-01-01"]["stmt"], keys=[("log-1", LOG_SEED)])                     # a further pair: it holds
        y = log.obj("{}", keys=[("log-z", LOG_SEED)])                                                 # no day, key not established
        z = log.obj("[1]", keys=[("log-q", LOG_SEED)])
        code, f, vl, cls = self.vl(log.extract(records=[log.present("2026-01-01")], objs=[log.days["2025-12-31"]["obj"], log.days["2026-01-01"]["obj"], bad, y, z]))
        self.assertEqual((code, cls), (1, [("included", None)] * 3))
        self.assertEqual(f, [("VENDOR_LOG_DEFECTIVE", "2026-01-01: signature (key log-1); signature (key log-2); time stamp does not hold (7.4.10, 7.4.11)"),
                             ("VENDOR_LOG_UNVERIFIED", "without day: key not established (log-z); key not established (log-q) (7.4.10, 7.4.11)")])


def schema_ok(v, sc, path="$"):
    """The subset of JSON Schema (2020-12) the generated report schemas use (type, enum, pattern, minimum, properties,
    required, additionalProperties false, items, prefixItems, minItems, maxItems, boolean schemas) -> the first
    violation, or "" (10.10.2)."""
    if sc is True: return ""
    if sc is False: return f"{path}: {v!r} is not allowed here"
    types = sc.get("type")
    if types is not None:
        kinds = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}
        ok = any((type(v) is int if t == "integer" else isinstance(v, kinds[t])) for t in (types if isinstance(types, list) else [types]))
        if not ok: return f"{path}: {v!r} is not {types}"
    if "enum" in sc and v not in sc["enum"]: return f"{path}: {v!r} not in {sc['enum']}"
    if isinstance(v, str) and "pattern" in sc and not __import__("re").search(sc["pattern"], v): return f"{path}: {v!r} does not match {sc['pattern']}"
    if type(v) is int and "minimum" in sc and v < sc["minimum"]: return f"{path}: {v} below {sc['minimum']}"
    if isinstance(v, dict):
        for k in sc.get("required", []):
            if k not in v: return f"{path}: {k} missing"
        for k, x in v.items():
            if k not in sc.get("properties", {}):
                if sc.get("additionalProperties") is False: return f"{path}: {k} not defined"
                continue
            why = schema_ok(x, sc["properties"][k], f"{path}.{k}")
            if why: return why
    if isinstance(v, list):
        if "maxItems" in sc and len(v) > sc["maxItems"]: return f"{path}: more than {sc['maxItems']} items"
        if "minItems" in sc and len(v) < sc["minItems"]: return f"{path}: fewer than {sc['minItems']} items"
        pre = sc.get("prefixItems", [])
        for i, x in enumerate(v):
            why = schema_ok(x, pre[i] if i < len(pre) else sc.get("items", {}), f"{path}[{i}]")
            if why: return why
    return ""


class VectorsLog110(unittest.TestCase):
    """The vectors of group log (7.4.10, spec/testvectors README 11) with the corpus environment and with each
    vector's own ledger-pruefumgebung/1: exit code and finding classes as expected/<name>.json says, the values of the
    object vendor_log and the reasons the rows of README 11.3 name (also the witnessed days of the corpus authority E1,
    README 11.2), and every vendor_log against the generated schema report_vendor_log.schema.json (10.10.2). Which
    vectors: those the registry lists, held against the expected files on disk, never a number written here."""

    P, PE, U, UC = ("pending", None), ("unchecked", "day_not_witnessed"), ("missing", None), ("unchecked", "day_contradictory")
    I, NI = ("included", None), ("not_included", None)
    LR0 = {"matching_prefix": 0, "matching_without_receipt": 0, "contradicting_prefix": 0, "beyond_package": 0, "gap_witnesses": 0}
    RC0 = {"included": 0, "not_included": 0, "unchecked": 0, "missing": 0, "pending": 0, "before_start": 0, "future": 0, "included_up_to_tree_size": None}
    ROWS = {"log_day_test_authority": {"classes": [PE, P], "reason": "published test key"},
            "log_reason_no_timestamp": {"classes": [PE, P], "reason": "no time stamp"},
            "log_reason_no_log_root": {"classes": [PE, P], "reason": "no root of the auditor for the log (--vendor-log-tsa-root)"},
            "log_reason_chain_root_only": {"classes": [PE, P], "reason": "no root of the auditor for the log (--vendor-log-tsa-root)"},
            "log_reason_outside_profile": {"classes": [PE, P], "reason": "outside the time-stamp profile"},
            "log_reason_not_chained": {"classes": [PE, P], "reason": "no path to a root of the auditor for the log"},
            "log_qualified_log_root": {"classes": [PE, P], "reason": "published test key"},
            "log_timestamp_imprint_wrong": {"classes": [PE, P], "reason": None},
            "log_timestamp_z6_violated": {"classes": [PE, P], "reason": None},
            "log_timestamps_early_late_test_key": {"classes": [PE, P], "reason": "published test key"},
            "log_no_list": {"npk": "no protocol key list supplied"},
            "log_list_no_matching_root": {"npk": "no vendor root of the auditor with the list's wurzel_id"},
            "log_list_signature_fails": {"npk": "the list's signature does not hold"},
            "log_list_format_violated": {"npk": "the list violates the format"},
            "log_lists_same_version_differ": {"npk": "contradicting lists"}, "log_list_key_dropped": {"npk": "contradicting lists"},
            "log_lists_filler_commitment_differ": {"npk": "contradicting lists"}, "log_list_key_in_two_roles": {"npk": "a key in two roles of the vendor"},
            "log_list_log_id_differs": {"npk": "the list's log_id differs from that of the extracts"},
            "log_pin_dropped": {"npk": "a key in two roles of the vendor"},
            "log_pin_only": {"classes": [PE, P], "key_source": "pinned", "first_day": "2025-12-31"},
            "log_pin_first_day_contradictory": {"classes": [("unchecked", "first_day_contradictory")] * 2, "key_source": "pinned", "first_day": None},
            "log_key_not_established": {"classes": [U, P], "missing": 1}, "log_signature_fails": {"classes": [U, P], "missing": 1},
            "log_additional_signature_fails": {"classes": [PE, P]}, "log_key_revoked": {"classes": [U, P], "missing": 1},
            "log_resigned_after_revocation": {"classes": [PE, P]}, "log_additional_signature_unknown_alg": {"classes": [PE, P], "signatures_not_checked": 1},
            "log_entry_format_violation": {"classes": [U, P], "missing": 1}, "log_entry_not_json": {"classes": [PE, P]},
            "log_rule_server_ts_before_day_end": {"classes": [U, P], "missing": 1}, "log_rule_prev_hash_zero": {"classes": [U, P], "missing": 1},
            "log_rule_day_before_start": {"classes": [PE, P], "contradictory": 1}, "log_two_versions": {"classes": [UC, P], "contradictory": 1},
            "log_prev_hash_broken": {"classes": [PE, P], "contradictory": 1}, "log_skips_day": {"classes": [PE, P], "contradictory": 1, "missing": 0},
            "log_day_missing": {"classes": [U, P], "missing": 1}, "log_receipt_future": {"classes": [P, ("future", None)]},
            "log_receipts_pending": {"classes": [P, P]}, "log_receipts_before_start": {"classes": [("before_start", None)] * 2},
            "log_record_not_holding": {"classes": [PE, P]}, "log_two_records": {"classes": [PE, P]}, "log_padded_day": {"classes": [PE, P]},
            "log_absence_between_fillers": {"classes": [PE, P]}, "log_foreign_chain_records": {"classes": [PE, P], "foreign_chain_records": 1},
            "log_mirror_extract": {"classes": [PE, P]}, "log_extract_server_ts_other_form": {"classes": [PE, P]},
            # README 11.2 and 11.3, the witnessed days of E1 (decisions B, D, E, K of the vendor log)
            "log_witnessed_included": {"classes": [I, P], "witnessed": 1, "head_witnessed": True, "receipts": dict(RC0, included=1, pending=1, included_up_to_tree_size=5)},
            "log_witnessed_not_included": {"classes": [NI, P], "logged_roots": dict(LR0, matching_prefix=1, matching_without_receipt=1)},
            "log_witnessed_no_record": {"classes": [("unchecked", "no_record"), P], "logged_roots": LR0},
            "log_witnessed_record_failed": {"classes": [("unchecked", "record_failed"), P]},
            "log_witnessed_record_contradictory": {"classes": [("unchecked", "record_contradictory"), P], "logged_roots": LR0},
            "log_witnessed_reason_late": {"classes": [PE, P], "reason": "late", "witnessed": 0},
            "log_witnessed_premature_stamp": {"classes": [UC, P], "head": None},
            "log_witnessed_window_bounds": {"classes": [I, P], "witnessed": 1},
            "log_witnessed_two_versions_one_witnessed": {"classes": [I, P], "contradictory": 1},
            "log_witnessed_two_versions_both_witnessed": {"classes": [UC, P], "head": None},
            "log_witnessed_key_revoked_signed_before": {"classes": [I, P], "key_list_version": 2},
            "log_witnessed_key_revoked_signed_after": {"classes": [U, P], "missing": 1, "key_list_version": 2},
            "log_witnessed_resigned_after_revocation": {"classes": [I, P]},
            "log_witnessed_absent_empty_day": {"classes": [NI, P], "logged_roots": LR0},
            "log_witnessed_absent_before_first": {"classes": [NI, P]}, "log_witnessed_absent_after_last_filler": {"classes": [NI, P]},
            "log_witnessed_absent_between_two_fillers": {"classes": [NI, P]},
            "log_witnessed_logged_roots": {"classes": [I, P], "logged_roots": {"matching_prefix": 2, "matching_without_receipt": 1, "contradicting_prefix": 1, "beyond_package": 1, "gap_witnesses": 1}},
            "log_witnessed_logged_root_mismatch": {"classes": [I, P], "logged_roots": dict(LR0, matching_prefix=1, contradicting_prefix=1)},
            "log_witnessed_receipt_invalid": {"classes": [P], "receipts": dict(RC0, pending=1), "logged_roots": dict(LR0, matching_prefix=1)},
            "log_receipt_invalid_outside_range": {"classes": [P], "receipts": dict(RC0, pending=1), "missing": 0},
            "log_witnessed_day_1999": {"classes": [I, P], "contradictory": 1, "missing": 0},
            "log_witnessed_reason_z6_not_checkable": {"classes": [PE, P], "reason": "outside the time-stamp profile"},
            "log_witnessed_qualified_stamp": {"classes": [I, P]}, "log_witnessed_qualified_root_plain_stamp": {"classes": [I, P]},
            "log_witnessed_time_anchor_qualified": {"classes": [I, P]},
            # README 14.3, fuellerbindung null and "once set, unchanged in every later version" (7.4.7, 7.4.10 L1 item 2)
            "log_list_filler_commitment_null": {"classes": [I, P], "key_list_version": 1},
            "log_lists_filler_commitment_set_later": {"classes": [I, P], "key_list_version": 2},
            "log_lists_filler_commitment_changed": {"npk": "contradicting lists"},
            "log_lists_filler_commitment_dropped": {"npk": "contradicting lists"}}

    def run_main(self, *argv):
        """main() end to end; self.res: the Result verify() returned inside it (its per-receipt classes, L8)."""
        out, err, orig, self.res = io.StringIO(), io.StringIO(), V.verify, None
        def spy(*a, **k):
            self.res = orig(*a, **k)
            return self.res
        V.verify = spy
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try: code = vmain(["verifier2", *argv])
                except SystemExit as e: code = e.code
        finally: V.verify = orig
        return code, json.loads(out.getvalue()) if out.getvalue() else None, err.getvalue()

    def test_7_4_10_log_vectors(self):
        reg = file_registry()
        with open(os.path.join(VEKTOREN, "..", "schemas", "report_vendor_log.schema.json"), encoding="utf-8") as fh: schema = json.load(fh)
        names, on_disk = corpus_names(reg, ("log",))
        self.assertTrue(names)
        self.assertEqual(names, on_disk)
        self.assertEqual([n for n in names if not os.path.isdir(os.path.join(VEKTOREN, n))], [])
        self.assertLessEqual(set(self.ROWS), set(names))
        for name in names:
            with open(os.path.join(VEKTOREN, "expected", name + ".json")) as fh: exp = json.load(fh)
            pkg = os.path.join(VEKTOREN, name)
            for env, args, want in (("corpus", vector_anchors(), exp), ("vector", V.pruefumgebung(os.path.join(VEKTOREN, exp["auditor_inputs"]["file"]), reg), exp["auditor_inputs"])):
                with self.subTest(name=name, env=env):
                    code, j, err = self.run_main(pkg, "--json", "--now-from-package", "--registry", REG_PATH, *args)
                    self.assertEqual((code, j["finding_classes"] if j else []), (want["exit_code"], sorted(set(want["finding_classes"]))), err)
                    if code == 3: continue
                    vl = j["vendor_log"]
                    self.assertEqual(schema_ok(vl, schema), "")
                    if env == "corpus":
                        self.assertEqual(vl["status"], "not_supplied")
                        continue
                    row = self.ROWS.get(name, {})
                    log_f = [f["detail"] for f in j["findings"] if f["class"] == "VENDOR_LOG_UNVERIFIED"]
                    if "npk" in row:
                        self.assertEqual((vl["status"], vl["receipts"], log_f), ("no_protocol_key", None, [f"without day: no protocol key established by an anchor of the auditor ({row['npk']}) (7.4.10, 7.4.11)"]))
                        continue
                    self.assertEqual(vl["status"], "checked")
                    if "classes" in row:
                        self.assertEqual([(x["class"], x["subclass"]) for x in self.res.vlog["classes"]], row["classes"])
                    if "reason" in row:
                        nw = [d for d in log_f if "day entry not witnessed" in d]
                        self.assertEqual(nw, [f"2026-01-02: day entry not witnessed ({row['reason']}) (7.4.10, 7.4.11)"] if row["reason"] else [])
                    for k in ("key_source", "first_day", "foreign_chain_records"):
                        if k in row: self.assertEqual(vl[k], row[k], k)
                    for k in ("missing", "contradictory", "signatures_not_checked", "witnessed"):
                        if k in row: self.assertEqual(vl["days"][k], row[k], k)
                    for k in ("receipts", "logged_roots", "head"):
                        if k in row: self.assertEqual(vl[k], row[k], k)
                    if "head_witnessed" in row: self.assertEqual(vl["head"]["witnessed"], row["head_witnessed"])
                    if "key_list_version" in row: self.assertEqual(vl["key_list"]["version"], row["key_list_version"])


# ---------------------------------------------------------------- anchor history v2 and affiliation (8.8, 1.10)

H_KIND = "ledger.anchor_history.v2"
H_RANK = {"countersigned": 0, "gap_witness": 1, "reported": 2}
H_KNOWN = "2025-12-01T00:00:00.000Z"
H_ROLES = role_list([role_entry("vendor-1", VENDOR_SEED, "countersigning"), role_entry("st-1", STMT_SEED, "statements"),
                     role_entry("st-2", STMT2_SEED, "statements"), role_entry("upd-1", UPD_SEED, "update_manifest")])
H_BL = 1791072000          # 2026-10-04T00:00:00Z, registry verifier.anchor_history.legacy_boundary (H10)


def h_owner(chain=CHAIN, app=APPLIANCE, key=None):
    """An owner commitment, written from heartbeat spec 9.7: Hex(SHA-256(UTF-8(JCS({appliance_id, chain_id, device_pubkey,
    kind: ledger.anchor_history.owner.v1}))))."""
    return _sha(_j({"appliance_id": app, "chain_id": chain, "device_pubkey": (key or pubkey(DEV_SEED)).hex(), "kind": "ledger.anchor_history.owner.v1"}))


def h_root(t, r, recorded_as, ts): return {"tree_size": t, "merkle_root": r, "recorded_as": recorded_as, "server_ts": ts}


def h_period(bases, frm, until=None, recorded=None, merged=False):
    return {"bases": list(bases), "from": frm, "until": until, "recorded_ts": recorded or frm, "merged": merged}


def h_content(roots, ts, chain=CHAIN, owner=None, since=0, nxt=None, ref=None, forks=(), omitted=0, pred=None, succ=None,
              known_since=H_KNOWN, periods=(), sort=True, **over):
    """The members of a page of kind v2 (heartbeat spec 9.7), all present: roots in the order of page rule 3 (the tests
    write every instant in one form, so the strings order as the instants), reference_tree_size the largest recorded
    root unless given."""
    if sort: roots = sorted(roots, key=lambda x: (x["tree_size"], x["server_ts"], H_RANK[x["recorded_as"]], x["merkle_root"]))
    return dict({"kind": H_KIND, "chain_id": chain, "owner_keys": sorted(owner or [h_owner(chain)]), "predecessor": pred, "successor": succ,
                 "reference_tree_size": max([x["tree_size"] for x in roots if x["recorded_as"] != "reported"], default=0) if ref is None else ref,
                 "roots": list(roots), "forks": list(forks), "forks_omitted": omitted, "since_tree_size": since, "next_since_tree_size": nxt,
                 "truncated": nxt is not None, "affiliation": {"known_since": known_since, "periods": list(periods)}, "server_ts": ts}, **over)


def h_page(content, kid="st-1", seed=STMT_SEED, s=None, sig=None):
    """A page as the body of the HTTP response (8.8.2): statement_jcs (JCS of the content: for these ASCII objects the JSON
    text with sorted members and no blanks), server_key_id, server_signature and the unsigned reading copy statement."""
    s = _j(content).decode() if s is None else s
    return {"statement_jcs": s, "server_key_id": kid, "server_signature": sig or sign(seed, s.encode()).hex(), "statement": None}


def h_pairs(page, *pairs):
    """The same statement_jcs with other pairs (server_key_id, seed or a signature hex)."""
    return [dict(page, server_key_id=k, server_signature=x if isinstance(x, str) else sign(x, page["statement_jcs"].encode()).hex()) for k, x in pairs]


def chain_at(t0):
    """A Chain whose GENESIS stands at t0 (seconds since 1970) instead of 2026-01-01: the builder reads T0 once."""
    global T0
    old, T0 = T0, t0
    try: return Chain(OWN)
    finally: T0 = old


class RotChain(Chain):
    """A Chain whose device key can rotate (6.4): KEY_ROTATION signed by the old key over JCS({old_key_id, new_key_id,
    new_pubkey}), its immediate checkpoint and every later one signed by the new key."""
    def __init__(self, *a, **kw):
        self.kseed, self.kid = DEV_SEED, "dev-1"
        super().__init__(*a, **kw)

    def checkpoint(self, mono=500, dt=0.5):
        n = len(self.entries)
        root = V.mth([bytes.fromhex(x["entry_hash"]) for x in self.entries]).hex()
        obj = {"chain_id": CHAIN, "tree_size": n, "merkle_root": root, "prev_checkpoint_hash": self.prev_cp, "key_id": self.kid, "ts": iso(self.t + dt)}
        e = self.add("CHECKPOINT", {"tree_size": n, "merkle_root": root, "prev_checkpoint_hash": self.prev_cp, "key_id": self.kid,
                                    "signature": sign(self.kseed, V.jcsb(obj)).hex()}, mono=mono, dt=dt)
        self.prev_cp = e["entry_hash"]
        return e

    def rotate(self, seed, kid):
        msg = V.jcsb({"old_key_id": self.kid, "new_key_id": kid, "new_pubkey": pubkey(seed).hex()})
        self.add("KEY_ROTATION", {"old_key_id": self.kid, "new_key_id": kid, "new_pubkey": pubkey(seed).hex(), "signature_by_old_key": sign(self.kseed, msg).hex()})
        self.kseed, self.kid = seed, kid
        self.checkpoint()


class AnchorHistory110(Spec19):
    """Format spec 8.8 (1.10), the anchor history as an auditor input, rule by rule: the reference page of 8.8.2, the keys
    of 8.8.3, the steps H1 to H13 of 8.8.4, the classification of 8.8.5 (a root that is only reported never gives exit 2),
    the affiliation of 8.8.6, the report objects of 10.10.2 against their generated schemas and the text block of 10.10.3.
    The pages are built here from heartbeat spec 9.7 and signed with the test statements keys of KeyRoles110."""

    ROOTS = {"wurzel-test": pubkey(ROOT_SEED).hex()}

    @classmethod
    def setUpClass(cls):
        cls.schemas = {}
        for k in ("anchor_history", "affiliation"):
            with open(os.path.join(VEKTOREN, "..", "schemas", "report_%s.schema.json" % k), encoding="utf-8") as fh: cls.schemas[k] = json.load(fh)

    def setUp(self):
        super().setUp()
        self.use(Chain(OWN))

    def use(self, c, close=True):
        """Package the chain: three receipts (tree_size 3, 6 and 9 of N = 11 for the default chain), R twenty minutes after
        the last entry (every receipt recorded before R - W_h), a fresh page two minutes after R, the check ten minutes after R."""
        if close: c.tick(); c.anchor(); c.tick(); c.anchor(); c.close()
        self.c, self.p = c, self.pkg(c)
        self.rc = [e for e in c.entries if e["event_type"] == "CHECKPOINT_RECEIPT"]
        self.N, self.leaves = len(c.entries), [bytes.fromhex(e["entry_hash"]) for e in c.entries]
        self.R = later(iso(c.t), 20 * 60000)
        self.TS, self.now = later(self.R, 120000), later(self.R, 600000)
        self.band = later(self.R, -900000)                              # R - W_h

    def root(self, t): return _rmth(self.leaves[:t]).hex()

    def rows(self, kind="countersigned"):
        return [h_root(e["payload"]["tree_size"], e["payload"]["merkle_root"], kind, e["payload"]["server_ts"]) for e in self.rc]

    def honest(self, ts=None, roots=None, **kw): return h_content(self.rows() if roots is None else roots, ts or self.TS, **kw)

    def hrun(self, *files, R=True, expect=(), lists=None, st=None, cs=None, lg=None, now=None, extracts=(), log_roots=()):
        """verify() with the auditor's inputs: each file a page (dict) or a container (list of pages); R True: self.R,
        None: no request time; lists default: the role list H_ROLES -> (exit code, anchor_history, affiliation)."""
        i = V.AuditorInputs(self.ROOTS, PIN if cs is None else cs)
        i.statement_pins, i.log_pins = dict(st or {}), dict(lg or {})
        i.key_lists = [(x["format"], x, json.dumps(x).encode()) for x in ([H_ROLES] if lists is None else lists)]
        i.history = [{"file": "h%d.json" % k, "raw": b"", "pages": [x] if isinstance(x, dict) else list(x), "container": not isinstance(x, dict)}
                     for k, x in enumerate(files)]
        i.extracts, i.extract_bytes = list(extracts), [json.dumps(x).encode() for x in extracts]
        for cert in log_roots: i.add_root(V.Cert(cert), "log")
        i.requested_at = self.R if R is True else R
        self.res = V.verify(self.p, self.reg, ms_of(now or self.now), 1000.0, list(expect), inputs=i)
        if self.res.anchor_history is not None:
            for k in ("anchor_history", "affiliation"): self.assertEqual(schema_ok(getattr(self.res, k), self.schemas[k]), "", k)
        return V.exit_code(self.res, self.reg["verifier"]["finding_classes"]), self.res.anchor_history, self.res.affiliation

    def cls(self): return sorted({f["class"] for f in self.res.findings})

    def details(self, cls): return [f["detail"] for f in self.res.findings if f["class"] == cls]

    def ok(self, *files, **kw):
        """A run that must end without finding: exit 0."""
        code, ah, af = self.hrun(*files, **kw)
        self.assertEqual((code, self.cls()), (0, []), self.res.findings)
        return ah, af

    # ---------------------------------------------------------------- 8.8.2, heartbeat spec 9.7: reference values

    def test_8_8_2_reference_page_and_owner_commitment(self):
        """8.8.2 and heartbeat spec 9.7: the page of valid_sealed_export (roots 15 and 28 countersigned, known_since
        2025-12-01, no period, reference_tree_size 28, since 0, issued 01:02:00.000) has 776 characters with SHA-256
        6fe4cc5f...; the owner commitment of its appliance, chain and device key is d0184bb5..."""
        d = os.path.join(VEKTOREN, "valid_sealed_export")
        with open(os.path.join(d, "segments", "chain-000001.jsonl"), encoding="utf-8") as fh: es = [json.loads(x) for x in fh if x.strip()]
        g, rc = es[0], [e for e in es if e["event_type"] == "CHECKPOINT_RECEIPT"]
        own = h_owner(g["chain_id"], g["payload"]["appliance_id"], bytes.fromhex(g["payload"]["device_pubkey"]))
        self.assertEqual(own, "d0184bb5619fab41289c330c51c12d3353538b46f852fcfb31ef9b2f83a92a28")
        self.assertEqual(V.ah_commitment(g["payload"]["appliance_id"], g["chain_id"], g["payload"]["device_pubkey"]), own)
        page = h_content([h_root(e["payload"]["tree_size"], e["payload"]["merkle_root"], "countersigned", e["payload"]["server_ts"]) for e in rc],
                         "2026-01-01T01:02:00.000Z", chain=g["chain_id"], owner=[own])
        s = _j(page).decode()
        self.assertEqual(([e["payload"]["tree_size"] for e in rc], len(s), _sha(s.encode())), ([15, 28], 776, "6fe4cc5f74c2539468594843916f9cfa1e528934d3f812202f04969932ca175b"))
        self.assertEqual(V.jcs(page), s)
        self.assertEqual(list(json.loads(s)), self.reg["cloud_statements"]["anchor_history_v2"]["jcs_order"])
        self.assertEqual(V.ah_content(s, self.reg)[0], page)            # H2 numbers 3 to 5 hold

    # ---------------------------------------------------------------- H0, H1, H13: not supplied, pooled, objects

    def test_8_8_4_h0_h13_not_supplied(self):
        """H0: without an anchor history H1 to H11 are left out; status not_supplied, affiliation not_checked, every count 0
        and the objects exactly as 10.10.2 says; R without a history is taken and noted requested_at_unused (10.8)."""
        code, ah, af = self.hrun(R=None)
        self.assertEqual(code, 0)
        z = lambda *ks: dict.fromkeys(ks, 0)
        want = {"status": "not_supplied", "requested_at": None, "files": 0,
                "pages": z("supplied", "distinct", "used_fresh", "used_stale", "used_unjudged", "used_linked", "not_used"), "page_reasons": [],
                "issued": {"first": None, "last": None}, "keys": [], "owner": None, "coverage": {"status": "none", "gaps": []},
                "reference_tree_size": None, "predecessor": None, "successor": None,
                "roots": z("distinct", "found", "differing_before_request", "differing_after_request", "beyond_package_before_request",
                           "beyond_package_recent", "beyond_package_after_request", "beyond_package_unjudged", "not_used_vendor_log"),
                "forks": {"listed": 0, "omitted": 0},
                "receipts": z("checked", "in_history", "not_in_history", "not_in_history_unestablished", "server_ts_differs", "before_legacy_boundary", "not_covered"),
                "completeness": {"status": "not_established", "reason": "not_supplied", "up_to_tree_size": None},
                "reasons": {"unverified": [], "defective": [], "contradiction": [], "fork": []}, "notes": []}
        self.assertEqual(ah, want)
        self.assertEqual(af, {"status": "not_checked", "reason": None, "bases": [], "vendor_itself": False, "span": None, "as_of": None, "known_since": None,
                              "stated_by": None, "periods": [], "receipts_total": None, "receipts_in_periods": None, "receipts_after_statement": None,
                              "contradictory": False, "linked": []})
        code, ah, af = self.hrun(R=self.R)
        self.assertEqual((code, ah["requested_at"], ah["notes"], ah["status"], af["status"]), (0, self.R, ["requested_at_unused"], "not_supplied", "not_checked"))
        self.assertEqual(self.res.completeness["sources"], [])

    def test_8_8_4_h13_null_on_format_error(self):
        """H13, 10.10.1: on exit 3 both objects are null; for every other exit they are objects (here exit 2 and 4)."""
        c = Chain("2.0"); c.anchor()
        self.p = self.pkg(c)
        code, ah, af = self.hrun(h_page(self.honest()))
        self.assertEqual((code, ah, af), (3, None, None))
        self.use(Chain(OWN))
        code, ah, af = self.hrun(h_page(self.honest()), expect=[(self.N, "ab" * 32)])
        self.assertEqual((code, ah["status"], af["status"]), (2, "checked", "not_affiliated"))
        c = Chain(OWN); c.tick(); c.anchor()
        self.use(c, close=False)
        code, ah, af = self.hrun(h_page(self.honest()))
        self.assertEqual((code, self.cls(), ah["completeness"]["status"]), (4, ["UNSEALED_END"], "established"))

    def test_8_8_4_h1_pooled_pages_and_pairs(self):
        """H1: all pages of all files pooled; equal statement_jcs are one page (supplied 3, distinct 1) with the set of its
        distinct pairs, whatever the order of the files: the good pair of one file and the bad one of another give a used
        page and DEFECTIVE signature for the bad pair under an established key (H2, Mehrere Paare)."""
        p = h_page(self.honest())
        ah, af = self.ok([p, p], p)
        self.assertEqual((ah["files"], ah["pages"]["supplied"], ah["pages"]["distinct"], ah["pages"]["used_fresh"]), (2, 3, 1, 1))
        bad = h_pairs(p, ("st-2", "00" * 64))[0]
        for files in ((p, bad), (bad, p), ([bad, p],)):
            code, ah, _af = self.hrun(*files)
            self.assertEqual((code, self.cls(), ah["pages"]["used_fresh"], ah["reasons"]["defective"], ah["completeness"]["status"]),
                             (1, ["ANCHOR_HISTORY_DEFECTIVE"], 1, ["signature"], "established"), files)

    # ---------------------------------------------------------------- H2 numbers 1 to 10, 8.8.3

    def test_8_8_3_h2_1_keys_of_pages(self):
        """8.8.3 and H2 number 1: a statements pin not dropped, else an entry of the effective role list with rolle
        statements; a countersigning key (K_cs, also by pin), a key of another role in the role list and a protocol pin
        give key_other_role; a key no anchor names, the manifest copy and a dropped pin give key_not_established."""
        c = self.honest()
        cases = (("role list", h_page(c), {}, None, None, ("role_list", 1)),
                 ("pin, no list", h_page(c, kid="st-x"), {"st-x": pubkey(STMT_SEED).hex()}, [], None, ("pinned", None)),
                 ("pin before the list", h_page(c), {"st-1": pubkey(STMT_SEED).hex()}, None, None, ("pinned", None)))
        for why, page, st, lists, _cs, (src, ver) in cases:
            with self.subTest(why):
                ah, af = self.ok(page, st=st, lists=lists)
                k = ah["keys"][0]
                self.assertEqual((k["source"], k["list"] and k["list"]["version"]), (src, ver))
                self.assertEqual(af["stated_by"], {"server_key_id": page["server_key_id"], "key_source": "pinned" if src == "pinned" else "role_list_auditor_root"})
        dropped = {"stp": pubkey(UPD_SEED).hex()}                      # the public key the role list gives update_manifest: dropped (10.7.4 R3 (d))
        for why, page, kw, reason in (("unknown key", h_page(c, kid="zz-9", seed=STMT2_SEED), {}, "key_not_established"),
                                      ("countersigning pin", h_page(c, kid="vendor-1", seed=VENDOR_SEED), {}, "key_other_role"),
                                      ("countersigning, no list", h_page(c, kid="vendor-1", seed=VENDOR_SEED), {"lists": []}, "key_other_role"),
                                      ("manifest copy only", h_page(c, kid="vendor-1", seed=VENDOR_SEED), {"lists": [], "cs": {}}, "key_not_established"),
                                      ("role update_manifest", h_page(c, kid="upd-1", seed=UPD_SEED), {}, "key_other_role"),
                                      ("protocol pin", h_page(c, kid="log-1", seed=LOG_SEED), {"lg": {"log-1": pubkey(LOG_SEED).hex()}}, "key_other_role"),
                                      ("dropped statements pin", h_page(c, kid="stp", seed=UPD_SEED), {"st": dropped}, "key_not_established")):
            with self.subTest(why):
                code, ah, af = self.hrun(page, **kw)
                self.assertEqual((code, ah["page_reasons"], ah["reasons"]["unverified"], ah["pages"]["not_used"]),
                                 (1, [reason], [reason, "pages_missing"], 1), self.res.findings)
                self.assertEqual([x for x in self.cls() if x.startswith("ANCHOR_HISTORY")], ["ANCHOR_HISTORY_UNVERIFIED"])
                self.assertEqual((af["status"], af["reason"]), ("not_determined", "history_key_not_established"))
                self.assertEqual(ah["completeness"], {"status": "not_established", "reason": "no_usable_page", "up_to_tree_size": None})

    def test_8_8_4_h2_several_pairs(self):
        """H2, Mehrere Paare: numbers 1, 2, 6 and 9 pass while one pair passes them; a page fails only when every pair failed,
        with the reason of the pair that came furthest, of equals with the one later in page_reasons (key_other_role before
        key_not_established); the report names the passing pair with the smallest server_key_id."""
        p = h_page(self.honest())
        for pairs in ((("zz-9", STMT2_SEED), ("upd-1", UPD_SEED)), (("upd-1", UPD_SEED), ("zz-9", STMT2_SEED))):
            code, ah, _af = self.hrun(h_pairs(p, *pairs))
            self.assertEqual(ah["page_reasons"], ["key_other_role"])
        code, ah, _af = self.hrun(h_pairs(p, ("upd-1", UPD_SEED), ("st-2", "00" * 64)))          # number 2 is further than number 1
        self.assertEqual((ah["page_reasons"], self.cls()), (["signature"], ["ANCHOR_HISTORY_DEFECTIVE", "ANCHOR_HISTORY_UNVERIFIED"]))
        expired = role_list([role_entry("vendor-1", VENDOR_SEED, "countersigning"), role_entry("st-1", STMT_SEED, "statements", gueltig_bis=self.R)])
        code, ah, _af = self.hrun(h_pairs(p, ("st-1", STMT_SEED), ("zz-9", STMT2_SEED)), lists=[expired])   # number 6 is further
        self.assertEqual(ah["page_reasons"], ["key_not_valid"])
        ah, _af = self.ok(h_pairs(p, ("vendor-1", VENDOR_SEED), ("st-1", STMT_SEED)))   # a pair of another role beside a good one
        self.assertEqual([k["key_id"] for k in ah["keys"]], ["st-1"])
        ah, af = self.ok(h_pairs(p, ("st-2", STMT2_SEED), ("st-1", STMT_SEED)))
        self.assertEqual(([k["key_id"] for k in ah["keys"]], af["stated_by"]["server_key_id"]), (["st-1"], "st-1"))

    def test_8_8_4_h2_2_signature(self):
        """H2 number 2: a signature over UTF-8(statement_jcs) that does not hold is DEFECTIVE signature; the page is not
        used (and with R the coverage leaves [0, infinity): pages_missing)."""
        p = h_page(self.honest())
        code, ah, af = self.hrun(dict(p, server_signature=p["server_signature"][:-1] + ("0" if p["server_signature"][-1] != "0" else "1")))
        self.assertEqual((code, self.cls(), ah["page_reasons"], ah["coverage"]), (1, ["ANCHOR_HISTORY_DEFECTIVE", "ANCHOR_HISTORY_UNVERIFIED"], ["signature"],
                                                                                 {"status": "none", "gaps": [[0, None]]}))
        self.assertEqual(af["reason"], "history_defective")

    def test_8_8_4_h2_3_4_5_form_kind_content(self):
        """H2 numbers 3 (printable ASCII, I-JSON object without duplicate names or lone surrogates, its own JCS form), 4
        (kind ledger.anchor_history.v2, else not_v2) and 5 (members and types of registry cloud_statements.anchor_history_v2,
        every instant .sssZ except server_ts in roots); a defect of the signed content is never exit 3."""
        c = self.honest()
        s = _j(c).decode()
        v1 = {k: c[k] for k in ("chain_id", "predecessor", "successor", "reference_tree_size", "roots", "forks", "since_tree_size", "truncated", "server_ts")}
        for why, text, reason in (("not ASCII", s.replace('"kind"', '"kind","x":"é"'), "page_rules"), ("not JSON", "no JSON at all", "page_rules"),
                                  ("blank", s.replace(",", ", ", 1), "page_rules"), ("member twice", s[:-1] + ',"kind":"%s"}' % H_KIND, "page_rules"),
                                  ("an array", "[" + s + "]", "page_rules"), ("lone surrogate", s[:-1] + ',"zz":"\\ud800"}', "page_rules"),
                                  ("number beyond 2^53-1", s.replace('"forks_omitted":0', '"forks_omitted":9007199254740992'), "page_rules"),
                                  ("kind v1", _j(dict(v1, kind="ledger.anchor_history.v1")).decode(), "not_v2"),
                                  ("licence statement", _j({"kind": "ledger.license_statement.v1", "server_ts": self.TS}).decode(), "not_v2"),
                                  ("no kind", _j({k: x for k, x in c.items() if k != "kind"}).decode(), "not_v2"),
                                  ("extra member", _j(dict(c, comment="x")).decode(), "page_rules"),
                                  ("member missing", _j({k: x for k, x in c.items() if k != "forks_omitted"}).decode(), "page_rules"),
                                  ("server_ts without ms", _j(dict(c, server_ts=self.TS[:19] + "Z")).decode(), "page_rules"),
                                  ("owner key upper case", _j(dict(c, owner_keys=[c["owner_keys"][0].upper()])).decode(), "page_rules"),
                                  ("int as string", _j(dict(c, since_tree_size="0")).decode(), "page_rules"),
                                  ("bool as int", _j(dict(c, truncated=0)).decode(), "page_rules"),
                                  ("unknown basis", _j(dict(c, affiliation={"known_since": None, "periods": [h_period(["friends"], H_KNOWN)]})).decode(), "page_rules")):
            with self.subTest(why):
                code, ah, af = self.hrun(h_page(None, s=text))
                self.assertEqual((code, ah["page_reasons"]), (1, [reason]), self.res.findings)
                self.assertIn("ANCHOR_HISTORY_CONTRADICTION" if reason == "page_rules" else "ANCHOR_HISTORY_UNVERIFIED", self.cls())
                self.assertEqual(af["reason"], "history_contradictory" if reason == "page_rules" else "history_not_v2")
        legacy = h_content([dict(r, server_ts=r["server_ts"][:19] + "Z") if r["tree_size"] == 3 else r for r in self.rows()], self.TS)
        self.ok(h_page(legacy))                                         # a root's server_ts is rfc3339, the stored string

    def test_9_7_page_rules(self):
        """Heartbeat spec 9.7, page rules 1 to 10, each broken once on a page whose members and types hold: H2 number 5,
        page_rules (ANCHOR_HISTORY_CONTRADICTION)."""
        rows, r = self.rows(), self.root(9)
        f = {"tree_size": 4, "merkle_root": "ab" * 32, "detected_ts": self.TS}
        P = lambda frm, until=None, bases=("common_control",), rec=None: h_period(bases, frm, until, rec)
        k0, k1 = h_owner(), h_owner(key=pubkey(STMT2_SEED))
        early, later_ = sorted([k0, k1])
        broken = {"1 next_since null with truncated": dict(truncated=True), "1 next_since not above since": dict(since=9, nxt=9),
                  "1 next_since not above a tree_size": dict(nxt=9),
                  "2 a root below since": dict(since=4), "3 roots descending": dict(roots=rows[::-1], sort=False),
                  "3 a root twice": dict(roots=rows + rows[-1:], sort=False), "4 forks twice": dict(forks=[f, f]),
                  "5 a root after the page": dict(roots=rows + [h_root(9, r, "reported", later(self.TS, 1))]),
                  "5 a fork after the page": dict(forks=[dict(f, detected_ts=later(self.TS, 1))]),
                  "6 reference below a countersigned root": dict(ref=6), "7 predecessor is the chain": dict(pred={"chain_id": CHAIN, "tree_size": 3}),
                  "7 predecessor is the successor": dict(pred={"chain_id": "4f1c9a02-1111-4222-8333-444455556666", "tree_size": 3},
                                                         succ={"chain_id": "4f1c9a02-1111-4222-8333-444455556666", "tree_size": 9}),
                  "8 owner_keys descending": dict(owner=None, owner_keys=[later_, early]), "8 owner_keys twice": dict(owner_keys=[k0, k0]),
                  "9 known_since after the page": dict(known_since=later(self.TS, 1)),
                  "10 bases not ascending": dict(periods=[P(H_KNOWN, bases=("vendor", "participation"))]),
                  "10 from not before the page": dict(periods=[P(self.TS)]), "10 recorded after the page": dict(periods=[P(H_KNOWN, rec=later(self.TS, 1))]),
                  "10 until not after from": dict(periods=[P(H_KNOWN, H_KNOWN)]), "10 until after the page": dict(periods=[P(H_KNOWN, later(self.TS, 1))]),
                  "10 open period not last": dict(periods=[P(H_KNOWN), P(self.R)]),
                  "10 overlapping": dict(periods=[P(H_KNOWN, self.R), P(self.band)]),
                  "10 adjoining with the same bases": dict(periods=[P(H_KNOWN, self.R), P(self.R)])}
        for why, kw in broken.items():
            with self.subTest(why):
                kw = dict(kw)
                c = self.honest(**{k: x for k, x in kw.items() if k != "owner_keys"})
                if "owner_keys" in kw: c["owner_keys"] = kw["owner_keys"]
                self.assertEqual(V._ah_type(c, {"type": "object", "fields": self.reg["cloud_statements"]["anchor_history_v2"]["fields"]}, "page"), "")
                self.assertTrue(V.ah_page_rules(c).startswith("rule " + why.split()[0] + ":"), V.ah_page_rules(c))
                code, ah, _af = self.hrun(h_page(c))
                self.assertEqual((code, ah["page_reasons"]), (1, ["page_rules"]))
        for why, kw in (("adjoining with other bases", dict(periods=[P(H_KNOWN, self.R), P(self.R, bases=("participation",))])),
                        ("an open period last", dict(periods=[P(H_KNOWN, self.band), P(self.R)]))):
            with self.subTest(why): self.assertEqual(V.ah_page_rules(self.honest(**kw)), "")
        self.assertEqual(V.ah_page_rules(h_content(rows[:2], self.TS, nxt=7, ref=9)), "")             # the first page of a split range

    def test_8_8_4_h2_6_window(self):
        """H2 number 6: a key from the role list holds for gueltig_ab <= server_ts < gueltig_bis and server_ts < widerrufen_ab,
        to the nanosecond; else key_not_valid. A pin has no window."""
        p = h_page(self.honest())
        for why, opt, ok in (("gueltig_bis before", {"gueltig_bis": self.TS}, False), ("gueltig_bis 1 ns after", {"gueltig_bis": self.TS[:-1] + "000001Z"}, True),
                             ("revoked at the page", {"widerrufen_ab": self.TS}, False), ("gueltig_ab after", {"ab": later(self.TS, 1)}, False)):
            with self.subTest(why):
                ab = opt.pop("ab", "2025-01-01T00:00:00Z")
                lst = role_list([role_entry("vendor-1", VENDOR_SEED, "countersigning"), role_entry("st-1", STMT_SEED, "statements", ab=ab, **opt)])
                code, ah, af = self.hrun(p, lists=[lst])
                self.assertEqual(ah["page_reasons"], [] if ok else ["key_not_valid"], self.res.findings)
                if not ok: self.assertEqual((af["reason"], self.cls()), ("history_key_not_valid", ["ANCHOR_HISTORY_UNVERIFIED"]))
        lst = role_list([role_entry("vendor-1", VENDOR_SEED, "countersigning"), role_entry("st-1", STMT_SEED, "statements", gueltig_bis=self.R)])
        self.ok(p, lists=[lst], st={"st-1": pubkey(STMT_SEED).hex()})       # the pin: no window

    def test_8_8_4_h2_7_8_chain_and_device(self):
        """H2 numbers 7 (chain_id = C, else a linked page or other_chain) and 8 (owner_keys and OC(chain_id) share an
        element, else owner_differs): one common key suffices; PK holds GENESIS.device_pubkey and every key 6.4 legitimises."""
        other = "4f1c9a02-1111-4222-8333-444455556666"
        code, ah, af = self.hrun(h_page(h_content(self.rows(), self.TS, chain=other)))
        self.assertEqual((code, ah["page_reasons"], af["reason"], ah["owner"]), (1, ["other_chain"], "history_other_chain", None))
        code, ah, af = self.hrun(h_page(self.honest(owner=[h_owner(app="59eed9d6-4f02-4aa0-9392-12c117f761a1")])))
        self.assertEqual((code, self.cls(), ah["page_reasons"], ah["owner"], af["reason"]), (1, ["ANCHOR_HISTORY_UNVERIFIED"], ["owner_differs"], "differs", "history_owner_differs"))
        self.assertEqual(ah["completeness"], {"status": "not_established", "reason": "owner_differs", "up_to_tree_size": None})
        ah, _af = self.ok(h_page(self.honest(owner=[h_owner(), h_owner(key=pubkey(STMT2_SEED))])))   # a key the package does not show
        self.assertEqual(ah["owner"], "matches")
        c = RotChain(OWN); c.tick(); c.anchor(); c.rotate(bytes([7] * 32), "dev-2")
        self.use(c)
        self.ok(h_page(self.honest(owner=[h_owner(key=pubkey(bytes([7] * 32)))])))  # only the rotated key: matches (6.4)
        code, ah, _af = self.hrun(h_page(self.honest(owner=[h_owner(key=bytes([8] * 32))])))
        self.assertEqual(ah["page_reasons"], ["owner_differs"])

    def test_8_8_4_h2_9_10_signing_time_and_use(self):
        """H2 number 9: with R a page is fresh when server_ts >= R - W_h; a page that is not fresh, or any page without R,
        under a key whose role list entry carries widerrufen_ab is not used (signing_time_not_proven), for a pin through an
        entry with rolle statements and the same public key; a key with gueltig_bis only is judged by number 6. Number 10:
        used_fresh, used_stale, used_unjudged."""
        rev = role_list([role_entry("vendor-1", VENDOR_SEED, "countersigning"), role_entry("st-1", STMT_SEED, "statements", widerrufen_ab=self.now)])
        fresh, stale = h_page(self.honest()), h_page(self.honest(ts=later(self.band, -1)))
        ah, _af = self.ok(fresh, lists=[rev])
        self.assertEqual(ah["pages"]["used_fresh"], 1)
        for why, page, kw in (("stale", stale, {}), ("no R", fresh, {"R": None}), ("pinned, stale", stale, {"st": {"st-1": pubkey(STMT_SEED).hex()}})):
            with self.subTest(why):
                code, ah, af = self.hrun(page, lists=[rev], **kw)
                self.assertEqual((ah["page_reasons"], af["reason"]), (["signing_time_not_proven"], "history_signing_time_not_proven"))
        p = h_page(self.honest(ts=self.band))                           # the boundary belongs to the fresh pages
        self.assertEqual(self.ok(p)[0]["pages"]["used_fresh"], 1)
        code, ah, _af = self.hrun(stale, p)
        self.assertEqual((code, ah["pages"]["used_fresh"], ah["pages"]["used_stale"], ah["notes"]), (0, 1, 1, ["archive_pages"]))
        planned = role_list([role_entry("vendor-1", VENDOR_SEED, "countersigning"), role_entry("st-1", STMT_SEED, "statements", gueltig_bis=self.now)])
        code, ah, af = self.hrun(fresh, lists=[planned], R=None)
        self.assertEqual((code, ah["pages"]["used_unjudged"], ah["completeness"]["reason"], af["status"]), (0, 1, "no_request_time", "not_affiliated"))

    # ---------------------------------------------------------------- H3, H4

    def test_8_8_4_h3_h4_issue_and_coverage(self):
        """H3: with R and no fresh page of the package, issued_before_request once with the latest server_ts; H4: the union of
        the ranges of the fresh pages (without R of all used, for information only), its gaps maximal and ascending, with R
        and a gap pages_missing once. Reference values of H4."""
        stale = h_page(self.honest(ts=later(self.band, -1)))
        code, ah, af = self.hrun(stale)
        self.assertEqual((code, ah["reasons"]["unverified"], ah["coverage"], ah["pages"]["used_stale"]),
                         (1, ["issued_before_request", "pages_missing"], {"status": "none", "gaps": [[0, None]]}, 1))
        self.assertEqual((ah["completeness"], af["status"], af["reason"]), ({"status": "not_established", "reason": "issued_before_request", "up_to_tree_size": None},
                                                                            "not_determined", "statement_does_not_cover_package"))
        self.assertIn(later(self.band, -1), self.details("ANCHOR_HISTORY_UNVERIFIED")[0])
        for ranges, want in ((((0, 501), (501, 1001), (1001, None)), ("complete", [])), (((0, 501), (1001, None)), ("partial", [[501, 1001]])),
                             (((400, 501), (501, None)), ("partial", [[0, 400]])), (((0, 501),), ("partial", [[501, None]])),
                             (((0, 480), (0, 501), (501, None)), ("complete", [])), ((), ("none", [[0, None]]))):
            self.assertEqual(V.ah_coverage(list(ranges)), {"status": want[0], "gaps": want[1]}, ranges)
        rows = self.rows()
        a, b = h_page(h_content(rows[:1], self.TS, nxt=4, ref=9)), h_page(h_content(rows[2:], self.TS, since=7, ref=9))
        code, ah, af = self.hrun(a, b)
        self.assertEqual((code, ah["coverage"], ah["reasons"]["unverified"], ah["completeness"]["status"], af["reason"]),
                         (1, {"status": "partial", "gaps": [[4, 7]]}, ["pages_missing"], "partial", "history_pages_missing"))
        code, ah, af = self.hrun(a, b, R=None)                           # without R: for information, no finding
        self.assertEqual((code, ah["coverage"]["status"], ah["reasons"]["unverified"]), (0, "partial", []))
        self.ok(a, b, h_page(h_content(rows[1:2], self.TS, since=4, nxt=7, ref=9)))

    # ---------------------------------------------------------------- H5

    def test_8_8_4_h5_pages_among_each_other(self):
        """H5 (a) to (j) for every pair A before B of used pages of the package, ordered by server_ts and statement_jcs,
        with the reference values; every reason hinders the completeness; contradictory only for the affiliation reasons."""
        rows, r9 = self.rows(), self.root(9)
        A_ts, B_ts = self.TS, later(self.TS, 5000)
        old = later(self.band, -60000)                                  # recorded before A.server_ts - W_h
        open_p = h_period(["common_control"], H_KNOWN)
        cases = (("a root_time_differs", {}, dict(roots=[dict(rows[0], server_ts=later(rows[0]["server_ts"], 1))] + rows[1:]), "root_time_differs"),
                 ("b root_dropped", {}, dict(roots=rows[1:], ref=9), "root_dropped"),
                 ("b root outside I(B)", {}, dict(roots=rows[2:], since=7, ref=9), None),
                 ("c root_withheld", dict(roots=rows[1:], ref=9), {}, "root_withheld"),
                 ("c recorded in the band", {}, dict(roots=rows + [h_root(10, self.root(10), "reported", A_ts)]), None),
                 ("d fork_dropped", dict(forks=[{"tree_size": 4, "merkle_root": "ab" * 32, "detected_ts": old}]), {}, "fork_dropped"),
                 ("d forks_omitted on B", dict(forks=[{"tree_size": 4, "merkle_root": "ab" * 32, "detected_ts": old}]), dict(omitted=1), None),
                 ("e ended before A", dict(periods=[open_p]), dict(periods=[dict(open_p, until=self.R)]), "affiliation_narrowed"),
                 ("e ended after A", dict(periods=[open_p]), dict(periods=[dict(open_p, until=later(A_ts, 1000))]), None),
                 ("e split view", dict(periods=[open_p]), {}, "affiliation_narrowed"),
                 ("f older period entered after A", {}, dict(periods=[h_period(["participation"], "2025-06-01T00:00:00.000Z", "2025-07-01T00:00:00.000Z", later(A_ts, 1000))]), None),
                 ("f entered before A - W_h", {}, dict(periods=[h_period(["participation"], "2025-06-01T00:00:00.000Z", "2025-07-01T00:00:00.000Z", old)]), "affiliation_withheld"),
                 ("f merged adjoining periods", dict(periods=[h_period(["participation"], "2025-06-01T00:00:00.000Z", "2025-06-04T00:00:00.000Z", old),
                                                              h_period(["former_relation"], "2025-06-04T00:00:00.000Z", "2025-06-08T00:00:00.000Z", old)]),
                  dict(periods=[h_period(["former_relation", "participation"], "2025-06-01T00:00:00.000Z", "2025-06-08T00:00:00.000Z", old, True)]), None),
                 # (f) and heartbeat spec 9.10, time reference 4: a merged period of B (merged = true) never gives
                 # affiliation_withheld, also across a gap between the old periods; the same period with merged = false does.
                 ("f merged across a gap", dict(periods=[h_period(["participation"], "2025-06-01T00:00:00.000Z", "2025-06-04T00:00:00.000Z", old),
                                                         h_period(["former_relation"], "2025-06-05T00:00:00.000Z", "2025-06-08T00:00:00.000Z", old)]),
                  dict(periods=[h_period(["former_relation", "participation"], "2025-06-01T00:00:00.000Z", "2025-06-08T00:00:00.000Z", old, True)]), None),
                 ("f across a gap, not merged", dict(periods=[h_period(["participation"], "2025-06-01T00:00:00.000Z", "2025-06-04T00:00:00.000Z", old),
                                                              h_period(["former_relation"], "2025-06-05T00:00:00.000Z", "2025-06-08T00:00:00.000Z", old)]),
                  dict(periods=[h_period(["former_relation", "participation"], "2025-06-01T00:00:00.000Z", "2025-06-08T00:00:00.000Z", old)]), "affiliation_withheld"),
                 ("g known_since later, before A", {}, dict(known_since=self.R), "known_range_narrowed"),
                 ("g known_since after A", {}, dict(known_since=later(A_ts, 1000)), None),
                 ("g known_since null", {}, dict(known_since=None), None),
                 ("h owner_keys_dropped", dict(owner=[h_owner(), h_owner(key=pubkey(STMT2_SEED))]), {}, "owner_keys_dropped"),
                 ("i predecessor differs", dict(pred={"chain_id": "4f1c9a02-1111-4222-8333-444455556666", "tree_size": 3}), {}, "succession_changed"),
                 ("i successor dropped", dict(succ={"chain_id": "4f1c9a02-1111-4222-8333-444455556666", "tree_size": 20}), {}, "succession_changed"),
                 ("i successor added", {}, dict(succ={"chain_id": "4f1c9a02-1111-4222-8333-444455556666", "tree_size": 20}), None),
                 ("j reference_decreases", dict(ref=10), {}, "reference_decreases"))
        for why, ka, kb, reason in cases:
            with self.subTest(why):
                a, b = h_page(self.honest(ts=A_ts, **ka)), h_page(self.honest(ts=B_ts, **kb))
                for files in ((a, b), (b, a)):
                    code, ah, af = self.hrun(*files)
                    got = ah["reasons"]["contradiction"]
                    self.assertEqual(got, [reason] if reason else [], (why, self.res.findings))
                    if reason:
                        self.assertEqual((code, ah["completeness"]["status"], ah["completeness"]["reason"]), (1, "partial", "contradiction"))
                        self.assertEqual(af["contradictory"], reason in ("affiliation_narrowed", "affiliation_withheld", "known_range_narrowed"))
        # 8.8.6 reference value: an open period on an older page of 00:10 beside H* without one ends there: not_affiliated, contradictory
        older = h_page(h_content([], later(self.band, -3600000), periods=[h_period(["common_control"], "2025-06-01T00:00:00.000Z")]))
        code, ah, af = self.hrun(older, h_page(self.honest()))
        self.assertEqual((ah["reasons"]["contradiction"], af["status"], af["contradictory"]), (["affiliation_narrowed"], "not_affiliated", True))
        self.assertEqual([(p["until"], p["overlaps_package"]) for p in af["periods"]], [(later(self.band, -3600000), False)])

    def test_8_8_4_h5_succession_mismatch_both_directions(self):
        """H5, linked pair: L the predecessor (P.predecessor = {L, T}): every used page of L with a successor carries {P, T};
        L the successor (P.successor = {L, T}): every used page of L with a predecessor carries {P, T}; else succession_mismatch,
        which hinders the completeness. H5 between linked pages of another chain does not hinder."""
        L = "4f1c9a02-1111-4222-8333-444455556666"
        pred = lambda T: {"chain_id": L, "tree_size": T}
        back = lambda T, ch=CHAIN: {"chain_id": ch, "tree_size": T}
        lp = lambda roots=(), ts=None, **kw: h_page(h_content(list(roots), ts or self.TS, chain=L, owner=[h_owner(L)], **kw))
        for why, mine, theirs, bad in (("predecessor equal", dict(pred=pred(40)), dict(succ=back(40)), False),
                                       ("predecessor other T", dict(pred=pred(39)), dict(succ=back(40)), True),
                                       ("predecessor other chain", dict(pred=pred(40)), dict(succ=back(40, "5f1c9a02-1111-4222-8333-444455556666")), True),
                                       ("successor equal", dict(succ=pred(20)), dict(pred=back(20)), False),
                                       ("successor other T", dict(succ=pred(20)), dict(pred=back(21)), True),
                                       ("predecessor, L without successor", dict(pred=pred(40)), {}, False)):
            with self.subTest(why):
                code, ah, af = self.hrun(h_page(self.honest(**mine)), lp(**theirs))
                self.assertEqual((ah["pages"]["used_linked"], ah["reasons"]["contradiction"]), (1, ["succession_mismatch"] if bad else []), self.res.findings)
                self.assertEqual(ah["completeness"]["reason"] if bad else ah["completeness"]["status"], "contradiction" if bad else "established")
                self.assertEqual([x["relation"] for x in af["linked"]], ["predecessor" if "pred" in mine else "successor"])
        r = self.root(3)
        code, ah, af = self.hrun(h_page(self.honest(pred=pred(40))), lp(succ=back(40), roots=[h_root(3, r, "countersigned", self.band)], ref=3),
                                lp(succ=back(40), ts=later(self.TS, 1000), ref=3))
        self.assertEqual((code, ah["reasons"]["contradiction"], ah["completeness"]["status"], af["contradictory"]), (1, ["root_dropped"], "established", False))

    def test_8_8_4_h5_f_merged_period_never_withheld(self):
        """H5 (f) and heartbeat spec 9.10, time reference 4: a period of B gives affiliation_withheld only with recorded_ts
        before A.server_ts - W_h (the boundary itself does not) and merged = false. A merged period of B (merged = true)
        never does, also over time between the old periods that A does not show: this pair does not reveal it. (e) is
        unchanged: a merged period of B that ends before A.server_ts still narrows an open period of A. Over the run: no
        reason gives completeness established and contradictory false, the reason gives partial and true (8.8.6 number 9)."""
        A_ts, B_ts = self.TS, later(self.TS, 5000)
        old, edge = later(self.band, -60000), later(A_ts, -900000)       # edge: A.server_ts - W_h
        d = lambda day: "2025-06-%02dT00:00:00.000Z" % day
        two = [h_period(["participation"], d(1), d(4), old), h_period(["former_relation"], d(5), d(8), old)]
        wide = lambda merged, rec=old: [h_period(["former_relation", "participation"], d(1), d(8), rec, merged)]
        for why, pa, pb, reason in (("gap, merged", two, wide(True), None),
                                    ("gap, not merged", two, wide(False), "affiliation_withheld"),
                                    ("A without a period, merged", [], wide(True), None),
                                    ("A without a period, not merged", [], wide(False), "affiliation_withheld"),
                                    ("recorded at A - W_h, not merged", [], wide(False, edge), None),
                                    ("recorded 1 ms before A - W_h, not merged", [], wide(False, later(edge, -1)), "affiliation_withheld"),
                                    ("recorded 1 ms before A - W_h, merged", [], wide(True, later(edge, -1)), None),
                                    ("(e) unchanged: a merged period of B ends before A", [h_period(["participation"], d(1), None, old)],
                                     [h_period(["participation"], d(1), self.R, old, True)], "affiliation_narrowed")):
            with self.subTest(why):
                a, b = h_page(self.honest(ts=A_ts, periods=pa)), h_page(self.honest(ts=B_ts, periods=pb))
                code, ah, af = self.hrun(a, b)
                self.assertEqual(ah["reasons"]["contradiction"], [reason] if reason else [], self.res.findings)
                self.assertEqual((code, ah["completeness"]["status"], af["contradictory"]), (1, "partial", True) if reason else (0, "established", False))

    def test_8_8_4_h5_h2_7_successor_chain(self):
        """H2 number 7 and H5 in both directions, over the run: a chain S that a used page of the package names as successor
        {S, T} is linked (relation successor); every used page of S whose predecessor is not null must carry {C, T}, else
        succession_mismatch, which hinders (H11 (b)) but never sets contradictory; a page of S with predecessor null passes.
        A page of S the package does not name is other_chain. If only GENESIS.predecessor_chain links a predecessor chain L
        and no page of the package names a predecessor, the two statements are not both present: no succession_mismatch."""
        S, X = "4f1c9a02-1111-4222-8333-444455556666", "5f1c9a02-1111-4222-8333-444455556666"
        T = self.N
        sp = lambda pred: h_page(h_content([], self.TS, chain=S, owner=[h_owner(S)], pred=pred, ref=0))
        pkg = h_page(self.honest(succ={"chain_id": S, "tree_size": T}))
        for why, page, bad in (("predecessor {C, T}", sp({"chain_id": CHAIN, "tree_size": T}), False),
                               ("predecessor {C, T - 1}", sp({"chain_id": CHAIN, "tree_size": T - 1}), True),
                               ("predecessor of another chain", sp({"chain_id": X, "tree_size": T}), True),
                               ("predecessor null", sp(None), False)):
            with self.subTest(why):
                code, ah, af = self.hrun(pkg, page)
                self.assertEqual((ah["pages"]["used_linked"], ah["reasons"]["contradiction"]), (1, ["succession_mismatch"] if bad else []), self.res.findings)
                self.assertEqual((code, ah["completeness"]["status"], ah["completeness"]["reason"]),
                                 (1, "partial", "contradiction") if bad else (0, "established", None))
                self.assertEqual([(x["chain_id"], x["relation"], x["status"]) for x in af["linked"]], [(S, "successor", "not_affiliated")])
                self.assertEqual((af["status"], af["contradictory"]), ("not_affiliated", False))
        code, ah, af = self.hrun(h_page(self.honest()), sp({"chain_id": CHAIN, "tree_size": T}))
        self.assertEqual((code, ah["page_reasons"], ah["pages"]["used_linked"], ah["reasons"]["contradiction"], af["linked"]), (1, ["other_chain"], 0, [], []))
        L = S
        g = Chain(OWN)
        g.entries[0]["payload"]["predecessor_chain"] = {"chain_id": L, "last_entry_hash": "11" * 32, "reason": "replacement"}
        g.entries[0]["entry_hash"] = V.entry_hash(g.entries[0])
        g.entries = g.entries[:1]; g.prev_cp = V.ZERO; g.checkpoint()
        self.use(g)
        code, ah, af = self.hrun(h_page(self.honest()), h_page(h_content([], self.TS, chain=L, owner=[h_owner(L)], succ={"chain_id": CHAIN, "tree_size": 99}, ref=0)))
        self.assertEqual((code, ah["pages"]["used_linked"], ah["reasons"]["contradiction"], ah["completeness"]["status"]), (0, 1, [], "established"), self.res.findings)
        self.assertEqual([(x["chain_id"], x["relation"]) for x in af["linked"]], [(L, "predecessor")])

    # ---------------------------------------------------------------- H6, H8 (8.8.5)

    def test_8_8_5_classification_table(self):
        """8.8.5 with R: a recorded root differing at t <= N with e < R - W_h is MERKLE_INCONSISTENT (exit 2), at e = R - W_h
        history_root_differs (the boundary belongs to the band); beyond the package a recorded root with e < R - W_h is
        MERKLE_INCONSISTENT with the note package_ended_before_request, R - W_h <= e < R beyond_package_recent with the note
        recent_roots_not_found, e >= R beyond_package_after_request. Without R: history_root_differs and beyond_package_unjudged
        (note no_request_time). Each counted after 10.10.2."""
        rows, x = self.rows(), "ab" * 32
        mi = h_root(5, x, "countersigned", later(self.band, -1))
        fk = h_root(7, x, "countersigned", self.band)
        b1, b2, b3 = (h_root(self.N + k, x, "countersigned", ts) for k, ts in ((1, later(self.band, -1)), (2, self.band), (3, self.R)))
        for why, extra, code_r, fork_r, notes, counts in (
                ("differing before the band", [mi], 2, [], [], {"differing_before_request": 1}),
                ("differing in the band", [fk], 1, ["history_root_differs"], [], {"differing_after_request": 1}),
                ("beyond before the band", [b1], 2, [], ["package_ended_before_request"], {"beyond_package_before_request": 1}),
                ("beyond in the band", [b2], 0, [], ["recent_roots_not_found"], {"beyond_package_recent": 1}),
                ("beyond after R", [b3], 0, [], [], {"beyond_package_after_request": 1})):
            with self.subTest(why):
                code, ah, _af = self.hrun(h_page(h_content(rows + extra, self.TS)))
                self.assertEqual((code, ah["reasons"]["fork"], ah["notes"]), (code_r, fork_r, notes), self.res.findings)
                want = dict.fromkeys(ah["roots"], 0)
                want.update(distinct=4, found=3, **counts)
                self.assertEqual(ah["roots"], want)
                self.assertEqual(self.cls(), {2: ["MERKLE_INCONSISTENT"], 1: ["ANCHOR_HISTORY_FORK"], 0: []}[code_r])
                if code_r == 2:
                    d = self.details("MERKLE_INCONSISTENT")[0]
                    for w in (str(extra[0]["tree_size"]), x, extra[0]["server_ts"], self.R[:19]): self.assertIn(w, d)
                    self.assertEqual(ah["completeness"]["reason"], "root_missing")
        code, ah, _af = self.hrun(h_page(h_content(rows + [mi, fk, b1, b2, b3], self.TS)), R=None)
        self.assertEqual((code, ah["reasons"]["fork"], ah["notes"], ah["roots"]["beyond_package_unjudged"], ah["roots"]["differing_after_request"]),
                         (1, ["history_root_differs"], ["no_request_time"], 3, 2))
        self.assertEqual((len(self.details("ANCHOR_HISTORY_FORK")), ah["completeness"]["reason"]), (2, "no_request_time"))    # once per (t, r)

    def test_8_8_5_reported_roots_never_exit_2(self):
        """8.8.5 and heartbeat spec 9.2 (Gemeldete Wurzeln): a root that is only reported and contradicts the package is
        ANCHOR_HISTORY_FORK history_root_differs, also with e long before R - W_h; beyond the package before R - W_h it is
        reported_root_beyond_package; never MERKLE_INCONSISTENT. e of a root also recorded is the earliest countersigned or
        gap witness recording: reported early and countersigned in the band is a fork, a gap witness before the band is exit 2."""
        rows, x, early = self.rows(), "ab" * 32, "2025-12-31T00:00:00.000Z"
        for why, extra, code_r, reason, counts in (
                ("reported, differing", [h_root(5, x, "reported", early)], 1, "history_root_differs", {"differing_before_request": 1}),
                ("reported, beyond", [h_root(self.N + 4, x, "reported", early)], 1, "reported_root_beyond_package", {"beyond_package_before_request": 1}),
                ("reported early, countersigned in the band", [h_root(5, x, "reported", early), h_root(5, x, "countersigned", self.band)], 1, "history_root_differs",
                 {"differing_after_request": 1}),
                ("gap witness early, countersigned later", [h_root(5, x, "gap_witness", early), h_root(5, x, "countersigned", self.TS)], 2, None,
                 {"differing_before_request": 1}),
                ("reported, equal to root(t)", [h_root(5, self.root(5), "reported", early)], 0, None, {"found": 1})):
            with self.subTest(why):
                code, ah, _af = self.hrun(h_page(h_content(rows + extra, self.TS)))
                self.assertEqual((code, ah["reasons"]["fork"]), (code_r, [reason] if reason else []), self.res.findings)
                self.assertEqual("MERKLE_INCONSISTENT" in self.cls(), code_r == 2)
                want = dict.fromkeys(ah["roots"], 0)
                want.update(distinct=4, found=3)
                for k, n in counts.items(): want[k] = want[k] + n
                self.assertEqual(ah["roots"], want)
                if reason: self.assertEqual(ah["completeness"], {"status": "partial", "reason": "fork", "up_to_tree_size": None})
        # a package without receipts: a reported history root equal to root(t) is an anchor (no NO_ANCHOR, 10.5 step 12)
        c = Chain(OWN); c.tick(); c.tick(); c.seal()
        self.use(c, close=False)
        code, _ah, _af = self.hrun()
        self.assertEqual(self.cls(), ["NO_ANCHOR"])
        code, ah, _af = self.hrun(h_page(h_content([h_root(3, self.root(3), "reported", self.band)], self.TS)))
        self.assertEqual((code, self.cls(), ah["roots"]["found"], self.res.completeness), (0, [], 1, {"status": "established", "up_to_tree_size": 3, "sources": ["anchor_history"]}))

    def test_8_8_5_merged_with_auditor_roots(self):
        """8.8.5: history roots merge with the auditor's roots of the form TREE_SIZE:ROOT by (t, r), with all sources; for a
        pair that carries the source auditor 10.8 decides its finding (MERKLE_INCONSISTENT when not found, at most one per
        pair), it counts in roots like every history root and for H11 its MERKLE_INCONSISTENT stems from a history root
        (root_missing). A root of the auditor without tree_size stays a root of its own."""
        rows, x, early = self.rows(), "ab" * 32, "2025-12-31T00:00:00.000Z"
        page = h_page(h_content(rows + [h_root(5, x, "reported", early)], self.TS))
        code, ah, _af = self.hrun(page, expect=[(5, x)])
        self.assertEqual((code, self.cls(), len(self.details("MERKLE_INCONSISTENT")), ah["reasons"]["fork"]), (2, ["MERKLE_INCONSISTENT"], 1, []))
        self.assertEqual((ah["roots"]["differing_before_request"], ah["completeness"]["reason"]), (1, "root_missing"))
        code, ah, _af = self.hrun(h_page(self.honest()), expect=[(9, self.root(9)), (None, self.root(6))])
        self.assertEqual((code, ah["roots"]["found"], self.res.completeness["sources"]), (0, 3, ["auditor", "anchor_history"]))
        code, ah, _af = self.hrun(h_page(self.honest()), expect=[(None, x)])
        self.assertEqual((code, self.cls(), ah["completeness"]["status"]), (2, ["MERKLE_INCONSISTENT"], "established"))

    # ---------------------------------------------------------------- H9

    def test_8_8_4_h9_forks_and_handover(self):
        """H9: every fork finding (t, r) on used pages is fork_listed once per (t, r), saying whether root(t) is r, a recorded
        root or t > N; forks_omitted > 0 once with the number; with successor {S, T} a recorded history root beyond T is
        root_beyond_handover, a reported one the note reported_beyond_handover, N > T the note package_beyond_handover."""
        f = lambda t, r: {"tree_size": t, "merkle_root": r, "detected_ts": self.band}
        a = h_page(self.honest(forks=[f(4, "ab" * 32), f(6, self.root(6)), f(self.N + 1, "cd" * 32)]))
        b = h_page(self.honest(ts=later(self.TS, 5000), forks=[f(4, "ab" * 32), f(6, self.root(6)), f(self.N + 1, "cd" * 32)]))
        code, ah, _af = self.hrun(a, b)
        d = self.details("ANCHOR_HISTORY_FORK")
        self.assertEqual((code, ah["reasons"]["fork"], ah["forks"], len(d)), (1, ["fork_listed"], {"listed": 3, "omitted": 0}, 3))
        self.assertTrue(any("root(t) equals it" in x for x in d) and any("beyond the %d entries" % self.N in x for x in d)
                        and any("neither" in x for x in d), d)
        code, ah, _af = self.hrun(h_page(self.honest(forks=[f(9, "ab" * 32)])))
        self.assertIn("root(t) equals a recorded root", self.details("ANCHOR_HISTORY_FORK")[0])
        code, ah, _af = self.hrun(h_page(self.honest(omitted=2)))
        self.assertEqual((code, ah["reasons"]["fork"], ah["forks"]["omitted"], ah["completeness"]["reason"]), (1, ["forks_omitted"], 2, "fork"))
        S = {"chain_id": "4f1c9a02-1111-4222-8333-444455556666", "tree_size": 6}
        code, ah, _af = self.hrun(h_page(self.honest(succ=S)))
        self.assertEqual((code, ah["reasons"]["fork"], ah["notes"], ah["successor"]), (1, ["root_beyond_handover"], ["package_beyond_handover"], S))
        rows = self.rows()[:2] + [dict(self.rows()[2], recorded_as="reported")]
        code, ah, _af = self.hrun(h_page(h_content(rows, self.TS, succ=S)))
        self.assertEqual((code, ah["reasons"]["fork"], ah["notes"]), (0, [], ["reported_beyond_handover", "package_beyond_handover"]))

    def test_8_8_4_h9_predecessor_chain(self):
        """H9 for a linked page of the predecessor chain with successor {C, T}: its recorded roots beyond T are
        predecessor_beyond_handover, reported ones the note reported_beyond_handover; the notes predecessor_differs_from_genesis
        (a used page names a predecessor, GENESIS none or another) and linked_history_not_supplied (no supplied page of that
        chain passed H2 numbers 1 to 5)."""
        L = "4f1c9a02-1111-4222-8333-444455556666"
        mine = h_page(self.honest(pred={"chain_id": L, "tree_size": 40}))
        lroots = [h_root(40, "11" * 32, "countersigned", "2025-12-31T00:00:00.000Z"), h_root(41, "22" * 32, "countersigned", "2025-12-31T00:01:00.000Z"),
                  h_root(42, "33" * 32, "reported", "2025-12-31T00:02:00.000Z")]
        lpage = h_page(h_content(lroots, self.TS, chain=L, owner=[h_owner(L)], succ={"chain_id": CHAIN, "tree_size": 40}, ref=41))
        code, ah, af = self.hrun(mine, lpage)
        self.assertEqual((code, ah["reasons"]["fork"], ah["notes"], ah["roots"]["distinct"]),
                         (1, ["predecessor_beyond_handover"], ["reported_beyond_handover", "predecessor_differs_from_genesis"], 3))
        self.assertEqual([(x["chain_id"], x["relation"]) for x in af["linked"]], [(L, "predecessor")])
        code, ah, _af = self.hrun(mine)
        self.assertEqual((code, ah["notes"]), (0, ["predecessor_differs_from_genesis", "linked_history_not_supplied"]))
        expired = role_list([role_entry("vendor-1", VENDOR_SEED, "countersigning"), role_entry("st-1", STMT_SEED, "statements"),
                             role_entry("st-2", STMT2_SEED, "statements", gueltig_bis=self.R)])
        lp2 = h_page(h_content([], self.TS, chain=L, owner=[h_owner(L)]), kid="st-2", seed=STMT2_SEED)
        code, ah, _af = self.hrun(mine, lp2, lists=[expired])            # numbers 1 to 5 held, number 6 failed: its chain_id is read
        self.assertEqual((ah["page_reasons"], ah["notes"]), (["key_not_valid"], ["predecessor_differs_from_genesis"]))

    # ---------------------------------------------------------------- H10

    def test_8_8_4_h10_receipts_against_the_history(self):
        """H10, the topmost case per receipt that counts as an anchor: before the cut-off date BL; in_history (a countersigned
        root with its tree_size and root, server_ts_differs besides); missing from a used page issued at least W_h after it:
        receipt_not_in_history for an established receipt, the note receipt_roots_unverified_not_in_history otherwise; else
        not_covered."""
        ah, _af = self.ok(h_page(self.honest()))
        self.assertEqual(ah["receipts"], dict(dict.fromkeys(ah["receipts"], 0), checked=3, before_legacy_boundary=3))
        self.use(chain_at(H_BL + 86400))
        rows = self.rows()
        ah, _af = self.ok(h_page(self.honest()))
        self.assertEqual(ah["receipts"], dict(dict.fromkeys(ah["receipts"], 0), checked=3, in_history=3))
        ah, _af = self.ok(h_page(h_content([dict(rows[0], server_ts=later(rows[0]["server_ts"], -100))] + rows[1:], self.TS)))
        self.assertEqual((ah["receipts"]["in_history"], ah["receipts"]["server_ts_differs"]), (3, 1))
        code, ah, _af = self.hrun(h_page(h_content(rows[1:], self.TS, ref=9)))
        self.assertEqual((code, ah["reasons"]["contradiction"], ah["receipts"]["not_in_history"], ah["completeness"]["reason"]),
                         (1, ["receipt_not_in_history"], 1, "contradiction"))
        self.assertIn("smallest seq %d" % self.rc[0]["seq"], self.details("ANCHOR_HISTORY_CONTRADICTION")[0])
        code, ah, _af = self.hrun(h_page(h_content(rows[1:], self.TS, ref=9)), cs={})        # the manifest copy only: not established
        self.assertEqual((ah["reasons"]["contradiction"], ah["receipts"]["not_in_history_unestablished"], ah["notes"]),
                         ([], 1, ["receipt_roots_unverified_not_in_history"]))
        self.assertEqual(self.cls(), ["RECEIPT_UNVERIFIED"])
        soon = later(rows[2]["server_ts"], 899999)                      # less than W_h after the last receipt
        ah, _af = self.ok(h_page(h_content(rows[:2], soon, ref=9)), R=later(soon, -60000))
        self.assertEqual((ah["receipts"]["not_covered"], ah["receipts"]["in_history"]), (1, 2))

    # ---------------------------------------------------------------- H11

    def test_8_8_4_h11_completeness_reasons(self):
        """H11: established only with R, complete coverage, no hindering reason, no MERKLE_INCONSISTENT from a history root and
        a found history root, up to the largest found history root; else partial with R and a fresh used page, else
        not_established, with the first reason of the table that applies."""
        honest = h_page(self.honest())
        ah, _af = self.ok(honest)
        self.assertEqual(ah["completeness"], {"status": "established", "reason": None, "up_to_tree_size": 9})
        bad_sig = dict(honest, server_signature="00" * 64)
        other = h_page(h_content(self.rows(), self.TS, chain="4f1c9a02-1111-4222-8333-444455556666"))
        for why, files, kw, status, reason in (
                ("no R", (honest,), {"R": None}, "not_established", "no_request_time"),
                ("no usable page", (bad_sig, other), {}, "not_established", "no_usable_page"),
                ("owner differs", (h_page(self.honest(owner=[h_owner(app=CHAIN)])), bad_sig), {}, "not_established", "owner_differs"),
                ("stale only", (h_page(self.honest(ts=later(self.band, -1))),), {}, "not_established", "issued_before_request"),
                ("gap", (h_page(self.honest(nxt=10)),), {}, "partial", "pages_missing"),
                ("page rule on a page of C", (honest, h_page(None, s=_j(dict(self.honest(), roots=self.rows()[::-1])).decode())), {}, "partial", "contradiction"),
                ("fork", (h_page(self.honest(omitted=1)),), {}, "partial", "fork"),
                ("no root found", (h_page(h_content([], self.TS)),), {}, "partial", "no_root_found")):
            with self.subTest(why):
                code, ah, _af = self.hrun(*files, **kw)
                self.assertEqual(ah["completeness"], {"status": status, "reason": reason, "up_to_tree_size": None}, self.res.findings)
        code, ah, _af = self.hrun(honest, h_page(h_content(self.rows(), self.TS, chain="4f1c9a02-1111-4222-8333-444455556666", ref=1)))
        self.assertEqual((code, ah["page_reasons"], ah["completeness"]["status"]), (1, ["page_rules"], "established"))  # another chain: not hindering
        code, ah, _af = self.hrun(honest, h_page(self.honest(owner=[h_owner(app=CHAIN)], ts=later(self.TS, 1))))
        self.assertEqual((code, ah["page_reasons"], ah["completeness"]["status"]), (1, ["owner_differs"], "established"))
        code, ah, _af = self.hrun(h_page(h_content(self.rows() + [h_root(self.N + 1, "ab" * 32, "countersigned", later(self.band, 1))], self.TS)))
        self.assertEqual((code, ah["notes"], ah["completeness"]["status"]), (0, ["recent_roots_not_found"], "established"))

    # ---------------------------------------------------------------- H7 against the vendor log

    def test_8_8_4_h7_third_rule_records_only(self):
        """H7, last rule: two gap witnesses with the same t and r and different server_ts in the checked records of chain C,
        on whatever usable days, are gap_witness_time_differs (exercised on the records H7 reads, 7.4.10 L6)."""
        r = "ab" * 32
        recs = {"2026-01-01": [h_root(4, r, "gap_witness", "2026-01-01T00:00:01.000Z")], "2026-01-02": [h_root(4, r, "gap_witness", "2026-01-02T00:00:01.000Z")]}
        res = V.Result(self.reg["verifier"])
        i = V.AuditorInputs()
        i.history = [{"file": "h", "raw": b"", "pages": [], "container": False}]
        h = V.AnchorHistory(res, i, self.reg, {"C": CHAIN, "records": recs})
        h.h6_h7()
        self.assertEqual(list(h.agg), [("ANCHOR_HISTORY_CONTRADICTION", "gap_witness_time_differs")])
        self.assertEqual(h.blocking, {"contradiction"})

    # ---------------------------------------------------------------- H12 (8.8.6)

    def test_8_8_6_affiliation(self):
        """8.8.6: the span of the package from the earliest vendor-signed time (established receipts, roots of the pages of
        P) to R or as_of; affiliated when a period overlaps it (an open period on H* without end, on an older page ending at
        its server_ts), with the union of bases in the order of 9.10 and vendor_itself; else not_affiliated only with (a) R
        and H* fresh, (b) known_since not null and not after span_from, (c) complete coverage, else not_determined with the
        first failing reason; the counts of number 10; the periods ordered and each once."""
        rc_ts = [e["payload"]["server_ts"] for e in self.rc]
        P = lambda bases, frm, until=None: h_period(bases, frm, until, frm if frm < self.TS else self.TS)
        ah, af = self.ok(h_page(self.honest()))
        self.assertEqual((af["status"], af["span"], af["as_of"], af["known_since"], af["receipts_total"], af["receipts_in_periods"], af["receipts_after_statement"]),
                         ("not_affiliated", {"from": rc_ts[0], "to": self.R}, self.TS, H_KNOWN, 3, 0, 0))
        ah, af = self.ok(h_page(self.honest(periods=[P(["common_control", "participation"], "2025-06-01T00:00:00.000Z")])))
        self.assertEqual((af["status"], af["bases"], af["vendor_itself"], af["receipts_in_periods"]), ("affiliated", ["common_control", "participation"], False, 3))
        self.assertEqual(af["periods"], [{"bases": ["common_control", "participation"], "from": "2025-06-01T00:00:00.000Z", "until": None,
                                          "recorded_ts": "2025-06-01T00:00:00.000Z", "merged": False, "overlaps_package": True}])
        ah, af = self.ok(h_page(self.honest(known_since=None, periods=[P(["vendor"], rc_ts[1])])))
        self.assertEqual((af["status"], af["vendor_itself"], af["receipts_in_periods"]), ("affiliated", True, 2))
        ah, af = self.ok(h_page(self.honest(periods=[P(["shared_management"], "2025-06-01T00:00:00.000Z", rc_ts[1])])))
        self.assertEqual((af["status"], af["receipts_in_periods"]), ("affiliated", 1))    # [from, until): the receipt at until is outside
        ah, af = self.ok(h_page(self.honest(periods=[P(["former_relation"], "2025-06-01T00:00:00.000Z", "2025-11-30T00:00:00.000Z")])))
        self.assertEqual((af["status"], [p["overlaps_package"] for p in af["periods"]]), ("not_affiliated", [False]))
        for why, page, kw, reason in (("known_since after span_from", h_page(self.honest(known_since=later(rc_ts[0], 1))), {}, "known_range_too_short"),
                                      ("known_since null", h_page(self.honest(known_since=None)), {}, "known_range_too_short"),
                                      ("no fresh page", h_page(self.honest(ts=later(self.band, -1))), {}, "statement_does_not_cover_package"),
                                      ("no R, a receipt after as_of", h_page(h_content(self.rows()[:2], later(rc_ts[2], -1))), {"R": None}, "statement_does_not_cover_package"),
                                      ("gap", h_page(h_content(self.rows()[1:], self.TS, since=4)), {}, "history_pages_missing")):
            with self.subTest(why):
                _code, _ah, af = self.hrun(page, **kw)
                self.assertEqual((af["status"], af["reason"]), ("not_determined", reason))
        _c, _ah, af = self.hrun(h_page(h_content(self.rows()[:2], later(rc_ts[2], -1))), R=None)
        self.assertEqual((af["span"]["to"], af["receipts_after_statement"]), (later(rc_ts[2], -1), 1))
        _c, _ah, af = self.hrun(h_page(self.honest(ts=later(self.band, -1), periods=[P(["participation"], "2025-06-01T00:00:00.000Z")])))
        self.assertEqual((af["status"], af["periods"][0]["until"]), ("affiliated", None))   # an older page carries affiliated; on H* open
        two = [P(["participation"], "2025-06-01T00:00:00.000Z", "2025-07-01T00:00:00.000Z"), P(["common_control"], "2025-08-01T00:00:00.000Z")]
        _c, _ah, af = self.hrun(h_page(self.honest(periods=two)), h_page(self.honest(ts=later(self.TS, 1000), periods=two)))
        self.assertEqual([(p["bases"], p["until"]) for p in af["periods"]],                              # once each, ordered; the open one of A ends at A
                         [(["participation"], "2025-07-01T00:00:00.000Z"), (["common_control"], self.TS), (["common_control"], None)])

    def test_8_8_6_not_determined_without_package_page(self):
        """8.8.6 number 2: with no used page of the package, not_determined with the first reason in the fixed order that a
        supplied page reached (owner_differs first, key_other_role as key_not_established), history_no_package_page if none
        did, for instance when only pages of a linked chain are used."""
        c = self.honest()
        for why, files, reason in (("owner and key", (h_page(c, kid="zz-9", seed=STMT2_SEED), h_page(self.honest(owner=[h_owner(app=CHAIN)]))), "history_owner_differs"),
                                   ("other role and v1", (h_page(None, s=_j({"kind": "ledger.anchor_history.v1"}).decode()), h_page(c, kid="upd-1", seed=UPD_SEED)), "history_key_not_established"),
                                   ("signature and page rules", (h_page(None, s="x"), dict(h_page(c), server_signature="00" * 64)), "history_defective"),
                                   ("other chain only", (h_page(h_content([], self.TS, chain="4f1c9a02-1111-4222-8333-444455556666")),), "history_other_chain")):
            with self.subTest(why):
                _code, _ah, af = self.hrun(*files)
                self.assertEqual((af["status"], af["reason"], af["span"], af["periods"], af["receipts_total"]), ("not_determined", reason, None, [], None))
        L = "4f1c9a02-1111-4222-8333-444455556666"
        g = Chain(OWN)
        g.entries[0]["payload"]["predecessor_chain"] = {"chain_id": L, "last_entry_hash": "11" * 32, "reason": "replacement"}
        g.entries[0]["entry_hash"] = V.entry_hash(g.entries[0])
        g.entries = g.entries[:1]; g.prev_cp = V.ZERO; g.checkpoint()
        self.use(g)
        _code, ah, af = self.hrun(h_page(h_content([], self.TS, chain=L, owner=[h_owner(L)], succ={"chain_id": CHAIN, "tree_size": 40}, ref=0,
                                                  periods=[h_period(["vendor"], "2025-06-01T00:00:00.000Z")])))
        self.assertEqual((ah["pages"]["used_linked"], af["status"], af["reason"]), (1, "not_determined", "history_no_package_page"))
        self.assertEqual([(x["chain_id"], x["relation"], x["status"]) for x in af["linked"]], [(L, "predecessor", "affiliated")])

    def test_8_8_6_9_contradictory_only_between_pages_of_P(self):
        """8.8.6 number 9: contradictory is true when H5 gave affiliation_narrowed, affiliation_withheld or
        known_range_narrowed between two pages of P. The same reason between pages of a linked chain stays a finding of
        ANCHOR_HISTORY_CONTRADICTION, does not hinder (H11) and does not set contradictory; the package's status comes from
        its own pages, the linked chain's stands under linked (number 11)."""
        L = "4f1c9a02-1111-4222-8333-444455556666"
        B_ts, old = later(self.TS, 5000), later(self.band, -60000)
        openp = h_period(["common_control"], "2025-06-01T00:00:00.000Z")
        lp = lambda ts, **kw: h_page(h_content([], ts, chain=L, owner=[h_owner(L)], succ={"chain_id": CHAIN, "tree_size": 40}, ref=0, **kw))
        pkg = h_page(self.honest(pred={"chain_id": L, "tree_size": 40}, periods=[openp]))
        for why, ka, kb, reason, linked in (("affiliation_narrowed", dict(periods=[openp]), {}, "affiliation_narrowed", "affiliated"),
                                            ("affiliation_withheld", {}, dict(periods=[h_period(["participation"], "2025-06-01T00:00:00.000Z", "2025-07-01T00:00:00.000Z", old)]),
                                             "affiliation_withheld", "not_affiliated"),
                                            ("known_range_narrowed", {}, dict(known_since=self.R), "known_range_narrowed", "not_affiliated")):
            with self.subTest(why):
                code, ah, af = self.hrun(pkg, lp(self.TS, **ka), lp(B_ts, **kb))
                self.assertEqual((code, ah["reasons"]["contradiction"], ah["completeness"]["status"]), (1, [reason], "established"), self.res.findings)
                self.assertEqual((af["status"], af["contradictory"], [x["status"] for x in af["linked"]]), ("affiliated", False, [linked]))
                code, ah, af = self.hrun(h_page(self.honest(**ka)), h_page(self.honest(ts=B_ts, **kb)))    # the same pair as pages of P
                self.assertEqual((code, ah["reasons"]["contradiction"], ah["completeness"]["reason"], af["contradictory"]), (1, [reason], "contradiction", True))

    def test_8_8_6_11_linked_chain_own_receipts_span_and_coverage(self):
        """8.8.6 number 11: a linked chain is judged with its own used pages in place of P. The package carries no receipts
        of it, so it has no established receipts (numbers 5, 7 (a) and 10); span_from comes from the roots of its own pages
        alone (no root: span_from = span_to); condition 7 (c) reads the coverage over its own used pages, with R over the
        fresh ones. The result stands under linked and never enters the status of the package (not_affiliated throughout).
        Its counts under number 10 are 0 and appear nowhere in the report (10.10.2 linked)."""
        L = "4f1c9a02-1111-4222-8333-444455556666"
        rc_ts = [e["payload"]["server_ts"] for e in self.rc]
        tL = later(rc_ts[-1], 1000)                                     # a root of L after every receipt of the package
        lp = lambda ts=None, roots=(), **kw: h_page(h_content(list(roots), ts or self.TS, chain=L, owner=[h_owner(L)], succ={"chain_id": CHAIN, "tree_size": 40}, **kw))
        lroot = lambda ts=tL: [h_root(3, "cd" * 32, "countersigned", ts)]
        ended = [h_period(["common_control"], "2025-06-01T00:00:00.000Z", later(rc_ts[-1], 500), "2025-06-01T00:00:00.000Z")]
        pkg = h_page(self.honest(pred={"chain_id": L, "tree_size": 40}))
        for why, pages, kw, status in (("no established receipts in number 5", (lp(roots=lroot(), known_since=later(rc_ts[0], 1)),), {}, "not_affiliated"),
                                       ("span_from from its own roots", (lp(roots=lroot(), known_since=later(tL, 1)),), {}, "not_determined"),
                                       ("no root: span_from = span_to = R", (lp(known_since=later(self.R, -1)),), {}, "not_affiliated"),
                                       ("a period that ends before its own roots", (lp(roots=lroot(), periods=ended),), {}, "not_affiliated"),
                                       ("a period that ends after its own root", (lp(roots=lroot(later(rc_ts[-1], 400)), periods=ended),), {}, "affiliated"),
                                       ("7 (a) without R: no established receipt", (lp(ts=later(rc_ts[-1], -1)),), {"R": None}, "not_affiliated"),
                                       ("7 (c) with R over its fresh pages", (lp(ts=later(self.band, -1), nxt=5), lp(since=5)), {}, "not_determined"),
                                       ("7 (c) without R over all its pages", (lp(ts=later(self.band, -1), nxt=5), lp(since=5)), {"R": None}, "not_affiliated")):
            with self.subTest(why):
                _code, ah, af = self.hrun(pkg, *pages, **kw)
                self.assertEqual((ah["pages"]["used_linked"], ah["reasons"]["contradiction"]), (len(pages), []), self.res.findings)
                self.assertEqual([(x["chain_id"], x["relation"], x["status"]) for x in af["linked"]], [(L, "predecessor", status)])
                self.assertEqual((af["status"], af["contradictory"], af["receipts_total"]), ("not_affiliated", False, len(self.rc)))

    # ---------------------------------------------------------------- 10.10.3 text

    def test_10_10_3_known_range_too_short_text(self):
        """10.10.3, line on affiliation: not_determined with known_range_too_short names <known_since> of H* (reason text
        known_range_too_short); if known_since is null, the text is known_range_too_short_null (registry
        verifier.affiliation.reason_texts), which names no time, in both languages."""
        rt, a = self.reg["verifier"]["affiliation"]["reason_texts"], self.reg["verifier"]["affiliation"]["texts"]
        ks = later(self.rc[0]["payload"]["server_ts"], 1)
        for why, known, key in (("known_since after span_from", ks, "known_range_too_short"), ("known_since null", None, "known_range_too_short_null")):
            with self.subTest(why):
                code, _ah, af = self.hrun(h_page(self.honest(known_since=known)))
                self.assertEqual((code, af["status"], af["reason"], af["known_since"]), (0, "not_determined", "known_range_too_short", known))
                for lang in ("de", "en"):
                    txt = V.render(self.res, code, self.reg["verifier"]["finding_classes"], lang, "p", self.reg["verifier"]).splitlines()
                    # 10.10.3: the line on affiliation is the last line of the block of the evidence level, at level 2 with open_at_level_2
                    line = [x for x in txt if x.startswith("  " + a["not_determined"][lang].split("(")[0])]
                    tail = " " + a["open_at_level_2"][lang] if self.res.evidence_level["level"] >= 2 else ""
                    self.assertEqual(line, ["  " + a["not_determined"][lang].format(reason=rt[key][lang].format(known_since=known)) + tail])
                    self.assertEqual(ks in line[0], known is not None)
                    self.assertNotIn("null", line[0])

    def test_10_10_3_owner_differs_detail_second_line(self):
        """10.10.3, anchor history passed but no page of the package used: the first line names the texts of the reasons
        from page_reasons; if anchor_history.owner is differs, owner_differs_detail (registry verifier.anchor_history.texts)
        follows as the second line; then the line on completeness. Without owner differs the second line is completeness."""
        ahr = self.reg["verifier"]["anchor_history"]
        t = ahr["texts"]
        for why, page, owner, reason in (("owner differs", h_page(self.honest(owner=[h_owner(app=CHAIN)])), "differs", "owner_differs"),
                                         ("key not established", h_page(self.honest(), kid="zz-9", seed=STMT2_SEED), None, "key_not_established")):
            with self.subTest(why):
                code, ah, _af = self.hrun(page)
                self.assertEqual((ah["owner"], ah["page_reasons"]), (owner, [reason]))
                for lang in ("de", "en"):
                    txt = V.render(self.res, code, self.reg["verifier"]["finding_classes"], lang, "p", self.reg["verifier"]).splitlines()
                    i = txt.index(t["none_used"][lang].format(distinct=1, reasons=ahr["page_reason_texts"][reason][lang]))
                    comp = "  " + t["completeness_not_established"][lang].format(reason=ahr["completeness_reason_texts"][ah["completeness"]["reason"]][lang])
                    want = (["  " + t["owner_differs_detail"][lang]] if owner == "differs" else []) + [comp]
                    self.assertEqual(txt[i + 1:i + 1 + len(want)], want)

    def test_10_10_3_text_blocks(self):
        """10.10.3: the block of the anchor history and the line on affiliation, every phrase from the registry, in the
        language of the report; not supplied, none used (with owner_differs_detail where the device differs) and used."""
        t = {k: x for k, x in self.reg["verifier"]["anchor_history"]["texts"].items()}
        a = {k: x for k, x in self.reg["verifier"]["affiliation"]["texts"].items()}
        self.hrun()
        # 10.10.3: the line on affiliation closes the block of the evidence level, indented like it; at level 2 and above
        # not_checked and not_determined are followed by open_at_level_2.
        tail = lambda lang: " " + a["open_at_level_2"][lang] if self.res.evidence_level["level"] >= 2 else ""
        for lang in ("de", "en"):
            txt = V.render(self.res, 0, self.reg["verifier"]["finding_classes"], lang, "p", self.reg["verifier"])
            self.assertIn(t["not_supplied"][lang].format(chain_id=CHAIN), txt.splitlines())
            self.assertIn("  " + a["not_checked"][lang] + " " + a["not_checked_fetch"][lang].format(chain_id=CHAIN) + tail(lang), txt.splitlines())
        self.hrun(h_page(self.honest(periods=[h_period(["vendor"], "2025-06-01T00:00:00.000Z")])))
        txt = V.render(self.res, 0, self.reg["verifier"]["finding_classes"], "en", "p", self.reg["verifier"]).splitlines()
        i = txt.index(t["used_head"]["en"].format(used=1, distinct=1, fresh=1, stale=0, first=self.TS, last=self.TS,
                                                  keys=t["key_item"]["en"].format(key_id="st-1", source=t["source_role_list_auditor"]["en"].format(version=1, wurzel_id="wurzel-test"))))
        self.assertEqual(txt[i + 1:i + 4], ["  " + t["requested_at"]["en"].format(requested_at=self.R),
                                            "  " + t["roots"]["en"].format(distinct=3, entries=self.N, found=3, differing=0, before_request=0, recent=0, after_request=0),
                                            "  " + t["completeness_established"]["en"].format(up_to_tree_size=9)])
        line = [x for x in txt if x.startswith("  " + a["affiliated_vendor_itself"]["en"].split("{")[0])]
        self.assertEqual(len(line), 1, txt)
        self.assertIn("from 2025-06-01T00:00:00.000Z, ongoing", line[0])
        self.assertFalse(line[0].endswith(a["open_at_level_2"]["en"]))          # only with not_checked and not_determined
        self.hrun(h_page(self.honest(owner=[h_owner(app=CHAIN)])))
        txt = V.render(self.res, 1, self.reg["verifier"]["finding_classes"], "de", "p", self.reg["verifier"]).splitlines()
        i = txt.index(t["none_used"]["de"].format(distinct=1, reasons=self.reg["verifier"]["anchor_history"]["page_reason_texts"]["owner_differs"]["de"]))
        self.assertEqual(txt[i + 1:i + 3], ["  " + t["owner_differs_detail"]["de"], "  " + t["completeness_not_established"]["de"].format(
            reason=self.reg["verifier"]["anchor_history"]["completeness_reason_texts"]["owner_differs"]["de"])])
        self.assertIn("  " + a["not_determined"]["de"].format(reason=self.reg["verifier"]["affiliation"]["reason_texts"]["history_owner_differs"]["de"]) + tail("de"), txt)
        self.hrun(h_page(self.honest()), R=None)
        txt = V.render(self.res, 0, self.reg["verifier"]["finding_classes"], "de", "p", self.reg["verifier"]).splitlines()
        self.assertIn("  " + t["no_request_time"]["de"].format(unjudged=0), txt)


class AnchorHistoryLog110(Spec19):
    """Format spec 8.8.4 step H7 (1.10) end to end: the used pages of the package against the checked chain-day records of
    the vendor log on usable days (7.4.10 L3, L6), with the test log of VendorLog110 and a test authority outside
    published_test_keys, so that the day of the chain is witnessed."""

    NOW = "2026-01-02T12:00:00Z"
    R, TS = "2026-01-02T11:00:00.000Z", "2026-01-02T11:02:00.000Z"
    ROOTS = {"wurzel-test": pubkey(ROOT_SEED).hex()}

    @classmethod
    def setUpClass(cls):
        cls.tsa = TSA(b"verifier2 1.10 history tsa")

    def setUp(self):
        super().setUp()
        c = Chain(OWN); c.tick(); c.anchor(); c.tick(); c.anchor(); c.close()
        self.c, self.p = c, self.pkg(c)
        self.rc = [e for e in c.entries if e["event_type"] == "CHECKPOINT_RECEIPT"]
        self.rows = [t_row(e) for e in self.rc]

    def log(self, rows):
        log = TLog(self.tsa)
        log.close("2025-12-31", fillers=0)
        log.close("2026-01-01", chains={(CHAIN, APPLIANCE): rows})
        return log.extract(records=[log.present("2026-01-01")])

    def hrun(self, page_rows, log_rows):
        i = V.AuditorInputs(self.ROOTS, PIN)
        i.key_lists = [(x["format"], x, json.dumps(x).encode()) for x in (H_ROLES, proto_list([("log-1", LOG_SEED)]))]
        x = self.log(log_rows)
        i.extracts, i.extract_bytes = [x], [json.dumps(x).encode()]
        i.add_root(V.Cert(self.tsa.root), "log")
        i.history = [{"file": "h.json", "raw": b"", "pages": [h_page(h_content(page_rows, self.TS))], "container": False}]
        i.requested_at = self.R
        self.res = V.verify(self.p, self.reg, ms_of(self.NOW), 1000.0, [], inputs=i)
        return V.exit_code(self.res, self.reg["verifier"]["finding_classes"]), self.res.anchor_history

    def test_8_8_4_h7_vendor_log(self):
        """H7: a recording countersigned or gap_witness on a used page whose day is usable and checked must stand in the record
        with the same four values, else it does not count (not_used_vendor_log for a root left without one) and log_mismatch
        once per day; every root of a present record must stand on each fresh page issued W_h after it (log_root_missing),
        a gap witness with the same server_ts as a string (gap_witness_time_differs)."""
        code, ah = self.hrun(self.rows, self.rows)
        self.assertEqual((code, self.res.vendor_log["days"]["witnessed"], ah["reasons"]["contradiction"], ah["completeness"]["status"]),
                         (0, 2, [], "established"))
        moved = [dict(self.rows[0], server_ts=later(self.rows[0]["server_ts"], 1000))] + self.rows[1:]
        code, ah = self.hrun(moved, self.rows)
        self.assertEqual((code, ah["reasons"]["contradiction"], ah["roots"]["not_used_vendor_log"], ah["roots"]["distinct"], ah["roots"]["found"]),
                         (1, ["log_mismatch"], 1, 3, 2))
        self.assertEqual(len([f for f in self.res.findings if f["detail"].startswith("2026-01-01: a recording")]), 1)
        code, ah = self.hrun(self.rows[1:], self.rows)
        self.assertEqual((code, ah["reasons"]["contradiction"], ah["completeness"]["reason"]), (1, ["log_root_missing"], "contradiction"))
        gw = dict(self.rows[0], recorded_as="gap_witness", server_ts=later(self.rows[0]["server_ts"], -1000))   # recorded before its countersignature
        code, ah = self.hrun([gw] + self.rows, [gw] + self.rows)
        self.assertEqual((code, ah["reasons"]["contradiction"]), (0, []))
        code, ah = self.hrun([dict(gw, server_ts=gw["server_ts"][:19] + "Z")] + self.rows, [gw] + self.rows)
        self.assertEqual(ah["reasons"]["contradiction"], ["gap_witness_time_differs"])     # the same instant, another string
        self.assertEqual(ah["roots"]["not_used_vendor_log"], 0)


class VectorsHistory110(unittest.TestCase):
    """The vectors of group history (format spec 8.8, spec/testvectors README 12) with the corpus environment and with each
    vector's own ledger-pruefumgebung/1: exit code and finding classes as expected/<name>.json says, the objects
    anchor_history and affiliation against their generated schemas, evidence_level.affiliation against affiliation.status
    and conditions (2) and (6) against completeness.sources and anchor_history.completeness (10.9.4, registry
    from_completeness), and the values the rows of README 12 name. Which vectors: those the registry lists, held against
    the expected files on disk, never a number written here."""

    # README 12: completeness (status, reason) of the vector's run, affiliation (status, reason), notes, extra checks
    ROWS = {"history_honest_role_list": {"comp": ("established", None), "aff": ("not_affiliated", None)},
            "history_honest_pinned": {"comp": ("established", None), "keys": [("vendor-statements-test-001", "pinned")]},
            "history_pages_duplicate": {"pages": (3, 1)},
            "history_statement_copy_ignored": {"aff": ("not_affiliated", None)},
            "history_pair_bad_signature_beside_good": {"comp": ("established", None), "defective": ["signature"]},
            "history_key_not_established": {"page_reasons": ["key_not_established"], "unverified": ["key_not_established", "pages_missing"]},
            "history_key_countersigning": {"page_reasons": ["key_other_role"]}, "history_key_update_manifest": {"page_reasons": ["key_other_role"]},
            "history_key_pin_dropped": {"page_reasons": ["key_not_established"]}, "history_page_v1_countersigning": {"page_reasons": ["key_other_role"]},
            "history_page_v1": {"page_reasons": ["not_v2"]}, "history_page_other_kind": {"page_reasons": ["not_v2"]},
            "history_page_rules_beside_honest": {"comp": ("partial", "contradiction")},
            "history_page_rules_other_chain": {"comp": ("established", None)},
            "history_key_expired": {"page_reasons": ["key_not_valid"]}, "history_key_revoked_before_issue": {"page_reasons": ["key_not_valid"]},
            "history_key_revoked_no_request_time": {"page_reasons": ["signing_time_not_proven"], "comp": ("not_established", "no_request_time")},
            "history_key_revoked_stale": {"page_reasons": ["signing_time_not_proven"], "unverified": ["signing_time_not_proven", "issued_before_request", "pages_missing"]},
            "history_key_planned_change_no_request_time": {"comp": ("not_established", "no_request_time"), "uses": {"used_unjudged": 1}},
            "history_owner_differs": {"comp": ("not_established", "owner_differs"), "aff": ("not_determined", "history_owner_differs")},
            "history_owner_differs_beside_honest": {"comp": ("established", None)},
            "history_issued_before_request": {"aff": ("not_determined", "statement_does_not_cover_package"), "found": 1},
            "history_stale_known_since_late": {"aff": ("not_determined", "statement_does_not_cover_package")},
            "history_archive_pages": {"notes": ["archive_pages"]},
            "history_coverage_gap": {"comp": ("partial", "pages_missing"), "aff": ("not_determined", "history_pages_missing")},
            "history_coverage_gap_no_request_time": {"aff": ("not_determined", "history_pages_missing")},
            "history_affiliation_narrowed": {"aff": ("affiliated", None), "contradictory": True},
            "history_affiliation_older_page": {"aff": ("not_affiliated", None), "contradictory": True},
            "history_known_since_narrowed": {"contradiction": ["known_range_narrowed"]},
            "history_root_differs_before_band": {"merkle": True}, "history_root_beyond_before_band": {"merkle": True, "notes": ["package_ended_before_request"]},
            "history_gap_witness_then_countersigned": {"merkle": True}, "history_reported_root_also_auditor": {"merkle": True},
            "history_root_differs_in_band": {"fork": ["history_root_differs"]},
            "history_band_no_request_time": {"fork": ["history_root_differs"], "roots": {"beyond_package_unjudged": 3}},
            "history_root_beyond_in_band": {"notes": ["recent_roots_not_found"], "roots": {"beyond_package_recent": 1, "beyond_package_after_request": 1}},
            "history_reported_root_differs": {"fork": ["history_root_differs"], "roots": {"differing_before_request": 1}},
            "history_reported_root_beyond": {"fork": ["reported_root_beyond_package"], "roots": {"beyond_package_before_request": 1}},
            "history_reported_then_countersigned": {"fork": ["history_root_differs"]},
            "history_fork_listed": {"fork": ["fork_listed"]}, "history_forks_omitted": {"fork": ["forks_omitted"]},
            "history_root_beyond_handover": {"fork": ["root_beyond_handover"], "notes": ["package_beyond_handover"]},
            "history_reported_beyond_handover": {"notes": ["reported_beyond_handover", "package_beyond_handover"]},
            "history_succession_linked": {"aff": ("not_affiliated", None), "linked": ["affiliated"]},
            "history_succession_mismatch": {"contradiction": ["succession_mismatch"]},
            "history_predecessor_beyond_handover": {"fork": ["predecessor_beyond_handover"], "notes_in": ["reported_beyond_handover"]},
            "history_linked_history_not_supplied": {"notes_in": ["linked_history_not_supplied"]},
            "history_predecessor_differs_from_genesis": {"notes_in": ["predecessor_differs_from_genesis", "linked_history_not_supplied"]},
            "history_linked_contradiction_not_blocking": {"contradiction": ["root_dropped"], "comp": ("established", None)},
            "history_log_mismatch": {"contradiction": ["log_mismatch"]}, "history_log_root_missing": {"contradiction": ["log_root_missing"]},
            "history_log_gap_witness_times": {"contradiction": ["log_root_missing", "gap_witness_time_differs"]},
            "history_receipts_in_history": {"receipts": {"in_history": 2}},
            "history_receipt_server_ts_differs": {"receipts": {"in_history": 2, "server_ts_differs": 1}},
            "history_receipt_not_in_history": {"contradiction": ["receipt_not_in_history"]},
            "history_receipt_not_covered": {"receipts": {"not_covered": 1}},
            "history_receipt_unverified_not_in_history": {"notes_in": ["receipt_roots_unverified_not_in_history"]},
            "history_no_root_found": {"comp": ("partial", "no_root_found")},
            "history_affiliated_open": {"aff": ("affiliated", None), "in_periods": (2, 2)},
            "history_not_affiliated_period_before": {"aff": ("not_affiliated", None)},
            "history_known_since_after_span": {"aff": ("not_determined", "known_range_too_short")},
            "history_known_since_null_open_period": {"aff": ("affiliated", None)},
            "history_affiliated_from_0050": {"aff": ("affiliated", None), "in_periods": (1, 2)},
            "history_vendor_itself": {"aff": ("affiliated", None), "vendor_itself": True},
            "history_affiliated_no_request_time": {"aff": ("affiliated", None)},
            "history_affiliated_stale_page": {"aff": ("affiliated", None)},
            "history_affiliation_ends_in_span": {"aff": ("affiliated", None), "in_periods": (1, 2)},
            # H5 (f) with merged, 8.8.6 numbers 9 and 11, H5 succession_mismatch with a successor chain, 10.10.3 known_since null
            "history_affiliation_merged_gap": {"comp": ("established", None), "aff": ("affiliated", None), "contradictory": False, "contradiction": []},
            "history_affiliation_gap_not_merged": {"comp": ("partial", "contradiction"), "aff": ("affiliated", None), "contradictory": True,
                                                   "contradiction": ["affiliation_withheld"]},
            "history_linked_affiliation_narrowed": {"comp": ("established", None), "aff": ("affiliated", None), "contradictory": False,
                                                    "contradiction": ["affiliation_narrowed"], "linked": ["affiliated"]},
            "history_successor_linked": {"comp": ("established", None), "aff": ("not_affiliated", None), "linked": ["not_affiliated"],
                                         "relations": ["successor"], "uses": {"used_linked": 1}, "contradiction": []},
            "history_successor_mismatch": {"comp": ("partial", "contradiction"), "aff": ("not_affiliated", None), "contradiction": ["succession_mismatch"],
                                           "relations": ["successor"], "contradictory": False},
            "history_known_since_null_after_takeover": {"aff": ("not_determined", "known_range_too_short"), "contradictory": False, "known_since_null": True}}
    # A root that is only reported never gives exit 2 (8.8.5); a recorded one before R - W_h does, and so does the auditor's root (10.8).
    REPORTED = ("history_reported_root_differs", "history_reported_root_beyond", "history_reported_then_countersigned")
    RECORDED = ("history_root_differs_before_band", "history_root_beyond_before_band", "history_gap_witness_then_countersigned")

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try: code = vmain(["verifier2", *argv])
            except SystemExit as e: code = e.code
        return code, json.loads(out.getvalue()) if out.getvalue() else None, err.getvalue()

    def run_text(self, *argv):
        """The text report (10.10.3) of a run: (exit code, stdout, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try: code = vmain(["verifier2", *argv])
            except SystemExit as e: code = e.code
        return code, out.getvalue(), err.getvalue()

    def test_8_8_history_vectors(self):
        reg = file_registry()
        schemas = {}
        for k in ("anchor_history", "affiliation"):
            with open(os.path.join(VEKTOREN, "..", "schemas", "report_%s.schema.json" % k), encoding="utf-8") as fh: schemas[k] = json.load(fh)
        fromc = reg["verifier"]["evidence_level"]["conditions"]["completeness_from_history"]["from_completeness"]
        names, on_disk = corpus_names(reg, ("history",))
        self.assertTrue(names)
        self.assertEqual(names, on_disk)
        self.assertLessEqual(set(self.ROWS) | set(self.REPORTED) | set(self.RECORDED), set(names))
        for name in names:
            with open(os.path.join(VEKTOREN, "expected", name + ".json")) as fh: exp = json.load(fh)
            pkg = os.path.join(VEKTOREN, name)
            for env, args, want in (("corpus", vector_anchors(), exp), ("vector", V.pruefumgebung(os.path.join(VEKTOREN, exp["auditor_inputs"]["file"]), reg), exp["auditor_inputs"])):
                with self.subTest(name=name, env=env):
                    code, j, err = self.run_main(pkg, "--json", "--now-from-package", "--registry", REG_PATH, *args)
                    self.assertEqual((code, j["finding_classes"] if j else []), (want["exit_code"], sorted(set(want["finding_classes"]))), err)
                    if code == 3: continue
                    ah, af = j["anchor_history"], j["affiliation"]
                    for k in schemas: self.assertEqual(schema_ok(j[k], schemas[k]), "", k)
                    el = want.get("evidence_level") or {}
                    if "affiliation" in el: self.assertEqual(af["status"], el["affiliation"])
                    if el.get("conditions"):
                        self.assertEqual(el["conditions"]["expected_root_found"], None if j["completeness"]["sources"] else "no_expected_root_found")
                        hc = ah["completeness"]
                        self.assertEqual(el["conditions"]["completeness_from_history"], None if hc["status"] == "established" else fromc[hc["reason"]])
                    if env == "corpus":
                        self.assertEqual((ah["status"], af["status"]), ("not_supplied", "not_checked"))
                        continue
                    if name in self.REPORTED:
                        self.assertEqual((code, j["finding_classes"]), (1, ["ANCHOR_HISTORY_FORK"]))
                    if name in self.RECORDED:
                        self.assertEqual((code, j["finding_classes"]), (2, ["MERKLE_INCONSISTENT"]))
                        self.assertEqual(ah["reasons"]["fork"], [])
                    row = self.ROWS.get(name, {})
                    if "comp" in row: self.assertEqual((ah["completeness"]["status"], ah["completeness"]["reason"]), row["comp"])
                    if "aff" in row: self.assertEqual((af["status"], af["reason"]), row["aff"])
                    for k in ("page_reasons", "notes"):
                        if k in row: self.assertEqual(ah[k], row[k], k)
                    for k in row.get("notes_in", ()): self.assertIn(k, ah["notes"])
                    for k in ("unverified", "defective", "contradiction", "fork"):
                        if k in row: self.assertEqual(ah["reasons"][k], [r for r in reg["verifier"]["anchor_history"]["reasons_by_class"][
                            reg["verifier"]["anchor_history"]["report_reason_keys"][k]] if r in row[k]], k)
                    if row.get("merkle"): self.assertEqual(ah["completeness"]["reason"], "root_missing")
                    for k, n in row.get("roots", {}).items(): self.assertEqual(ah["roots"][k], n, k)
                    for k, n in row.get("receipts", {}).items(): self.assertEqual(ah["receipts"][k], n, k)
                    for k, n in row.get("uses", {}).items(): self.assertEqual(ah["pages"][k], n, k)
                    if "found" in row: self.assertEqual(ah["roots"]["found"], row["found"])
                    if "pages" in row: self.assertEqual((ah["pages"]["supplied"], ah["pages"]["distinct"]), row["pages"])
                    if "keys" in row: self.assertEqual([(k["key_id"], k["source"]) for k in ah["keys"]], row["keys"])
                    if "contradictory" in row: self.assertEqual(af["contradictory"], row["contradictory"])
                    if "vendor_itself" in row: self.assertEqual(af["vendor_itself"], row["vendor_itself"])
                    if "in_periods" in row: self.assertEqual((af["receipts_in_periods"], af["receipts_total"]), row["in_periods"])
                    if "linked" in row: self.assertEqual([x["status"] for x in af["linked"]], row["linked"])
                    if "relations" in row: self.assertEqual([x["relation"] for x in af["linked"]], row["relations"])
                    if row.get("known_since_null"):                    # 10.10.3: the text known_range_too_short_null, in both languages
                        self.assertIsNone(af["known_since"])
                        for lang in ("de", "en"):
                            tcode, text, terr = self.run_text(pkg, "--lang", lang, "--now-from-package", "--registry", REG_PATH, *args)
                            self.assertEqual(tcode, code, terr)
                            line = reg["verifier"]["affiliation"]["texts"]["not_determined"][lang].format(
                                reason=reg["verifier"]["affiliation"]["reason_texts"]["known_range_too_short_null"][lang])
                            # 10.10.3: the last line of the block of the evidence level, at level 2 with open_at_level_2
                            if j["evidence_level"]["level"] >= 2: line += " " + reg["verifier"]["affiliation"]["texts"]["open_at_level_2"][lang]
                            self.assertIn("  " + line, text.splitlines())


# ---------------------------------------------------------------- evidence level (format spec 10.9, 10.10, from 1.10)

def ev_cert(tag, spki=None):
    """A stand-in for a certificate of the root table (10.8, 7.5.7): its DER bytes and its SPKI SHA-256 value."""
    return types.SimpleNamespace(der=("cert-" + tag).encode(), spki_sha256=spki or hashlib.sha256(("spki-" + tag).encode()).hexdigest())


def ev_root(tag, purposes, ab="2025-01-01T00:00:00Z", bis=None, spki=None):
    """(DER, entry of the root table): a root of the purpose qualified also carries the purpose chain (7.5.7)."""
    c = ev_cert(tag, spki)
    purposes = set(purposes) | ({"chain"} if "qualified" in purposes else set())
    return c.der, {"cert": c, "purposes": purposes, "qualified": (V.utc_ns(ab), V.utc_ns(bis) if bis else None) if "qualified" in purposes else None}


def ev_assess(paths=(), step5="holds", z6="holds", qs="present", signer=None, gen="2026-01-02T23:55:01Z"):
    """A stand-in for ts_assess (7.5): step 5, Z.6, rule QS, genTime, the signer's SPKI and a path per root DER."""
    holds = step5 == "holds"
    return {"step5": step5, "z6": z6 if holds else None, "qs": qs, "signer": types.SimpleNamespace(spki_sha256=signer or "5" * 64) if holds else None,
            "paths": {d: True for d in paths} if holds else {}, "t": {"gen_ns": V.utc_ns(gen)}}


def ev_ta(seq, t, a): return {"seq": seq, "tree_size": t, "assessment": a}


def ev_rc(seq, t, via="pinned", key="vendor-1", pub=None, version=None, root_id=None):
    """A receipt whose signature holds after 7.1, with the origin of its key (10.9.3)."""
    return {"seq": seq, "tree_size": t, "key_id": key, "pubkey": pub or pubkey(VENDOR_SEED).hex(), "via": via,
            "list_version": version if via == "list" else None, "root_id": root_id if via == "list" else None}


EV_DAY = "2026-01-02"


EV_SERVER_TS = EV_DAY + "T23:55:01.000Z"


def ev_vlog(classes=(), status="checked", t_m=None, contra=False, stamps=(), proto=(), p_root=None):
    """The state of the vendor log the evidence level reads (7.4.10 L3, L7, L8, L9): classes [(seq, tree_size, class[,
    subclass[, server_ts]])] in chain order, all on EV_DAY (server_ts EV_SERVER_TS unless given); stamps the judged time
    stamps of c(EV_DAY) [(state, assessment)]."""
    cls = [{"seq": x[0], "tree_size": x[1], "class": x[2], "subclass": x[3] if len(x) > 3 else None, "day": EV_DAY,
            "server_ts": x[4] if len(x) > 4 else EV_SERVER_TS} for x in classes]
    canon = {EV_DAY: {"end": V.day_end_ms(V.day_ord(EV_DAY)), "stamps": [{"state": s, "r": a} for s, a in stamps]}}
    return {"status": status, "classes": cls, "contradiction_in_range": contra, "t_m": t_m, "canon": canon, "proto_pubs": set(proto), "p_root": p_root}


def ev_page(kid="st-1", src="role_list", seed=STMT_SEED, roots=((15, "aa" * 32, "countersigned", EV_SERVER_TS),), pub=None, use="used_fresh"):
    """A used page of the package as AnchorHistory keeps it: its report pair (key_id, signature, source, public key, entry),
    its use (8.8.4 H2 number 10) and the recordings of its roots [(tree_size, merkle_root, recorded_as, server_ts)] (8.8.4 H6)."""
    return {"pair": (kid, "00" * 64, src, pub or pubkey(seed).hex(), None), "use": use,
            "v": {"roots": [{"tree_size": t, "merkle_root": r, "recorded_as": ra, "server_ts": st} for t, r, ra, st in roots]}}


def ev_hroots(pages):
    """The history roots of H6 over the given used pages, every recording kept (no H7 drop): (t, r) -> [(recorded_as, server_ts)]."""
    out = {}
    for o in pages:
        for x in o["v"]["roots"]:
            rec = out.setdefault((x["tree_size"], x["merkle_root"]), [])
            if (x["recorded_as"], x["server_ts"]) not in rec: rec.append((x["recorded_as"], x["server_ts"]))
    return out


Q_TEST = {"version": 1, "signatur": {"wurzel_id": "wurzel-test"}}


def condensed(ev):
    """An object evidence_level (10.10.2) in the short form of the expected files (registry expected_files.evidence_level)."""
    if not isinstance(ev, dict): return ev
    cond, af = ev["conditions"], ev["affiliation"]
    return {"state": ev["state"], "level": ev["level"], "up_to_tree_size": ev["up_to_tree_size"],
            "segments": [[g["level"], g["first_seq"], g["last_seq"]] for g in ev["segments"]],
            "conditions": None if cond is None else {k: None if v["met"] else v["reason"] for k, v in cond.items()},
            "notes": ev["notes"], "affiliation": af["status"] if af else None}


class EvidenceLevel110(unittest.TestCase):
    """Format spec 10.9 and 10.10 rule by rule over what a run holds (10.9.3), built here: the state (10.9.2), each
    condition with its reasons without an item, its stages, reach and count (10.9.4), level, reach, segments and next
    with the reference values KAT1 to KAT7 (10.9.5), the notes (10.9.6), the anchors and the object against its
    generated schema (10.10.2), the text block (10.10.3) and the rule that the level never changes the exit code (10.3)."""
    reg = file_registry()

    def setUp(self):
        self.rules = self.reg["verifier"]
        self.el = self.rules["evidence_level"]
        ptk = self.rules["timestamp_profile"]["published_test_keys"]
        self.tspki = next(k["spki_sha256"] for k in ptk if "spki_sha256" in k)
        self.ed = [k["ed25519"] for k in ptk if "ed25519" in k]
        with open(os.path.join(VEKTOREN, "..", "schemas", "report_evidence_level.schema.json"), encoding="utf-8") as fh: self.schema = json.load(fh)

    def mk(self, classes=(), N=32, receipts=(), tas=(), ta_entries=None, roots=(), qualified=None, vroots=None, pkg_spki=(), found=(),
           pages=(), Q=None, vlog=None, completeness=None, hist_found=0, ah_notes=(), aff="not_checked", lc_seq=None, D=(), hroots=None):
        """A Result after verify() with what the evidence level reads (10.9.3), each member as given; hroots the history
        roots of H6 after H7, by default those of the pages with every recording kept."""
        res = V.Result(self.rules)
        for c in classes: res.add(c, "test")
        res.ev = {"N": N, "D": set(D), "receipts": list(receipts), "lc_seq": max((x["seq"] for x in receipts), default=0) if lc_seq is None else lc_seq,
                  "time_anchors": list(tas), "time_anchor_entries": len(tas) if ta_entries is None else ta_entries, "roots": dict(roots),
                  "qualified": qualified, "vendor_roots": dict(vroots or {}), "pkg_spki": set(pkg_spki), "found": list(found),
                  "hist": types.SimpleNamespace(used_pkg=list(pages), hroots=ev_hroots(pages) if hroots is None else hroots)}
        res.vlog = vlog or ev_vlog(status="not_supplied")
        res.vl_reg, res.roles, res.chain_id, res.sig_receipt = self.reg["vendor_log"], {"Q": Q}, CHAIN, bool(receipts)
        res.vendor_log = {"log_id": None if res.vlog["status"] == "not_supplied" else LOG_ID}
        res.anchor_history = {"completeness": completeness or {"status": "not_established", "reason": "not_supplied", "up_to_tree_size": None},
                              "roots": {"found": hist_found}, "notes": list(ah_notes)}
        res.affiliation = {"status": aff, "reason": None, "vendor_itself": False, "known_since": None, "as_of": "2026-01-03T06:10:00.000Z" if pages else None}
        res.af_reg, res.ah_reg = self.rules["affiliation"], self.rules["anchor_history"]
        return res

    def ev(self, res, code=None):
        code = V.exit_code(res, self.rules["finding_classes"], self.rules) if code is None else code
        out = V.evidence_level(res, code, self.rules)
        if out is not None: self.assertEqual(schema_ok(out, self.schema), "", out)   # 10.10.2: the generated schema
        res.evidence_level = out
        return out

    def c(self, res, name): return self.ev(res)["conditions"][name]

    def no(self, reason): return {"met": False, "count": 0, "up_to_tree_size": None, "reason": reason}

    def yes(self, count, t): return {"met": True, "count": count, "up_to_tree_size": t, "reason": None}

    # ---------------------------------------------------------------- 10.9.2 state
    def test_10_9_2_state_format_error_chain_invalid_rated(self):
        """10.9.2: the topmost row that applies. Exit 3: format_error, everything null or empty, affiliation null as well;
        an exit-2 finding of a class outside material_classes: chain_invalid without level, conditions, segments and notes,
        affiliation present; otherwise rated, also exit 2 only from CONTENT_MISMATCH or REPORT_MISMATCH (note
        material_contradiction) and exit 4 (note unsealed_end)."""
        empty = {"state": "format_error", "level": None, "entries": None, "up_to_tree_size": None, "segments": [], "conditions": None,
                 "next": None, "qualified_time": None, "anchors": None, "affiliation": None, "notes": []}
        self.assertEqual(self.ev(self.mk(classes=["FORMAT_ERROR", "UNSEALED_END"], receipts=[ev_rc(16, 15)]), 3), empty)
        self.assertEqual(self.el["material_classes"], ["CONTENT_MISMATCH", "REPORT_MISMATCH"])
        for cls in ("RECEIPT_INVALID", "HASH_MISMATCH", "TIME_ANCHOR_INVALID", "MERKLE_INCONSISTENT"):
            with self.subTest(cls):
                ev = self.ev(self.mk(classes=[cls, "CONTENT_MISMATCH", "UNSEALED_END"], receipts=[ev_rc(16, 15)], aff="not_affiliated"))
                self.assertEqual(ev, dict(empty, state="chain_invalid", affiliation={"status": "not_affiliated", "vendor_itself": False}))
        for cls in self.el["material_classes"]:
            with self.subTest(cls):
                res = self.mk(classes=[cls], receipts=[ev_rc(16, 15)])
                self.assertEqual(V.exit_code(res, self.rules["finding_classes"], self.rules), 2)
                ev = self.ev(res)
                self.assertEqual((ev["state"], ev["level"], ev["up_to_tree_size"], ev["notes"][0]), ("rated", 2, 15, "material_contradiction"))
        ev = self.ev(self.mk(classes=["UNSEALED_END"], receipts=[ev_rc(16, 15)]))
        self.assertEqual((ev["state"], ev["level"], ev["entries"], ev["notes"]), ("rated", 2, 32, ["unsealed_end"]))

    def test_10_9_7_property_5_format_error_exactly_on_exit_3(self):
        """10.9.7 property 5: state is format_error exactly when the exit code is 3, whatever the findings."""
        for code in (0, 1, 2, 3, 4):
            res = self.mk(classes={0: [], 1: ["COVERED_GAP"], 2: ["CONTENT_MISMATCH"], 3: ["FORMAT_ERROR"], 4: ["UNSEALED_END"]}[code])
            self.assertEqual(self.ev(res, code)["state"] == "format_error", code == 3, code)

    # ---------------------------------------------------------------- 10.9.5 level, reach, segments, next
    def test_10_9_5_reference_values_kat1_to_kat10(self):
        """10.9.5, Referenzwerte (registry verifier.evidence_level.kat): level, up_to_tree_size, segments with basis and
        next from the reaches of the conditions that are met; KAT8 to KAT10 with (7) as the second way to level 3 (KAT10:
        next names (4) and (7), one of them suffices)."""
        order = self.el["condition_order"]
        self.assertEqual([k["case"] for k in self.el["kat"]], ["KAT%d" % i for i in range(1, 11)])
        for k in self.el["kat"]:
            with self.subTest(k["case"]):
                cond = {c: {"met": c in k["reaches"], "up_to_tree_size": k["reaches"].get(c)} for c in order}
                level, up, segs, nxt, _r = V.ev_level(cond, k["entries"], self.el)
                self.assertEqual((level, up), (k["level"], k["up_to_tree_size"]))
                self.assertEqual([[g["level"], g["first_seq"], g["last_seq"], g["basis"]] for g in segs], k["segments"])
                if "next" in k: self.assertEqual(nxt, k["next"])

    def test_10_9_5_segments_cover_the_chain_and_fall_strictly(self):
        """10.9.5 and 10.9.7 property 4 over every combination of small reaches of the seven conditions: r1 = max(reach(1),
        reach(2), reach(3)), r2 = reach(3), r3 = min(reach(3), max(reach(4), reach(7)), reach(5), reach(6)) when (3), (5),
        (6) and one of (4) and (7) are met, else 0; the segments cover seq 1 to N without gap, their levels fall strictly,
        the first has the level; up_to_tree_size is r_level (N at level 0); basis names the met codes of the level whose
        reach equals r_level, at level 3 among (3) to (7); next names the conditions of level L + 1 that are not met,
        for level 3 (4) and (7) both or neither (one condition), need any at L = 0, else all; null at level 3."""
        order = self.el["condition_order"]
        k1 = ["time_witness", "expected_root_found", "receipt_key_confirmed"]
        k3 = ["receipt_key_confirmed", "time_witness_qualified", "receipts_logged", "completeness_from_history", "log_day_qualified"]
        N = 6
        for reaches in itertools.product((0, 3, 6), repeat=7):
            cond = {c: {"met": t > 0, "up_to_tree_size": t or None} for c, t in zip(order, reaches)}
            R = dict(zip(order, reaches))
            way = max(R["time_witness_qualified"], R["log_day_qualified"])
            want = [N, max(R[c] for c in k1), R["receipt_key_confirmed"],
                    min(R["receipt_key_confirmed"], way, R["receipts_logged"], R["completeness_from_history"])
                    if R["receipt_key_confirmed"] and R["receipts_logged"] and R["completeness_from_history"] and way else 0]
            level, up, segs, nxt, r = V.ev_level(cond, N, self.el)
            self.assertEqual(r, want, reaches)
            self.assertEqual((segs[0]["first_seq"], segs[-1]["last_seq"], segs[0]["level"]), (1, N, level), reaches)
            for a, b in zip(segs, segs[1:]): self.assertEqual((b["first_seq"], a["level"] > b["level"]), (a["last_seq"] + 1, True), reaches)
            for g in segs:
                codes = {0: [], 1: k1, 2: ["receipt_key_confirmed"], 3: k3}[g["level"]]
                self.assertEqual(g["basis"], [c for c in order if c in codes and R[c] and R[c] == r[g["level"]]], reaches)
            self.assertEqual(up, r[level] if level else N)
            self.assertTrue(r[0] >= r[1] >= r[2] >= r[3], r)
            if level == 3: self.assertIsNone(nxt)
            elif level == 2:
                miss = [c for c in ("receipts_logged", "completeness_from_history") if not R[c]] + ([] if way else ["time_witness_qualified", "log_day_qualified"])
                self.assertEqual(nxt, {"level": 3, "need": "all", "missing": [c for c in order if c in miss]}, reaches)
            else: self.assertEqual(nxt, {"level": level + 1, "need": "any" if level == 0 else "all",
                                         "missing": [c for c in (k1 if level == 0 else ["receipt_key_confirmed"]) if not R[c]]}, reaches)

    def test_10_9_1_condition_7_second_way_to_level_3(self):
        """10.9.1, 10.9.5: level 3 needs (3), (4) or (7), (5) and (6). (7) alone with (3), (5), (6) reaches level 3; (7)
        without (3) gives no level; with (4) and (7) both the larger reach counts; the basis names (7) when its reach is r3;
        with neither, next names both (one of them suffices); with one of them, next names neither."""
        d, R = ev_root("q", {"log", "qualified"})
        est = {"status": "established", "reason": None, "up_to_tree_size": 28}
        stamp = [("confirmed", ev_assess(paths=(d,), gen="2026-01-03T00:05:01Z"))]
        res = self.mk(roots=[(d, R)], vlog=ev_vlog([(16, 15, "included")], stamps=stamp))
        ev = self.ev(res)
        self.assertEqual(ev["conditions"]["log_day_qualified"], self.yes(1, 15))
        self.assertEqual((ev["level"], ev["up_to_tree_size"], condensed(ev)["segments"]), (0, 32, [[0, 1, 32]]))
        self.assertEqual(ev["next"], {"level": 1, "need": "any", "missing": ["time_witness", "expected_root_found", "receipt_key_confirmed"]})
        rc = [ev_rc(16, 15), ev_rc(30, 28)]
        res = self.mk(roots=[(d, R)], receipts=rc, completeness=est, hist_found=1, pages=[ev_page()], Q=Q_TEST,
                      vlog=ev_vlog([(16, 15, "included"), (30, 28, "pending")], stamps=stamp))
        ev = self.ev(res)
        self.assertEqual((ev["level"], ev["up_to_tree_size"], ev["next"]), (3, 15, None))
        self.assertEqual([(g["level"], g["first_seq"], g["last_seq"], g["basis"]) for g in ev["segments"]],
                         [(3, 1, 15, ["receipts_logged", "log_day_qualified"]), (2, 16, 28, ["receipt_key_confirmed"]), (0, 29, 32, [])])
        self.assertEqual(ev["conditions"]["time_witness_qualified"], self.no("no_time_anchor"))
        # (4) up to 8 and (7) up to 15: the larger reach counts
        res = self.mk(roots=[(d, R)], receipts=rc, completeness=est, hist_found=1, pages=[ev_page()], Q=Q_TEST, tas=[ev_ta(9, 8, ev_assess(paths=(d,)))],
                      vlog=ev_vlog([(16, 15, "included"), (30, 28, "pending")], stamps=stamp))
        ev = self.ev(res)
        self.assertEqual((ev["level"], ev["up_to_tree_size"], ev["segments"][0]["basis"]), (3, 15, ["receipts_logged", "log_day_qualified"]))
        # neither (4) nor (7): next names both; one of them met but (6) missing: next names neither
        res = self.mk(roots=[(d, R)], receipts=rc, completeness=est, hist_found=1, pages=[ev_page()], Q=Q_TEST,
                      vlog=ev_vlog([(16, 15, "included"), (30, 28, "pending")], stamps=[("confirmed", ev_assess(gen="2026-01-03T00:05:01Z"))]))
        self.assertEqual(self.ev(res)["next"], {"level": 3, "need": "all", "missing": ["time_witness_qualified", "log_day_qualified"]})
        res = self.mk(roots=[(d, R)], receipts=rc, hist_found=1, pages=[ev_page()], Q=Q_TEST,
                      vlog=ev_vlog([(16, 15, "included"), (30, 28, "pending")], stamps=stamp))
        self.assertEqual(self.ev(res)["next"], {"level": 3, "need": "all", "missing": ["completeness_from_history"]})

    # ---------------------------------------------------------------- 10.9.4 conditions
    def test_10_9_4_condition_1_time_witness(self):
        """10.9.4 (1): reasons without an item first (no_time_anchor, then no_tsa_root_supplied); then every pair of
        TIME_ANCHOR and root of the purpose chain through the stages signature_not_checkable, not_chained_to_auditor_root,
        published_test_key, token_extensions_unusable; the reason is the stage of the pair that came furthest; stages of
        different roots are never combined; reach the largest tree_size, count the credited TIME_ANCHOR. Rule QS absent or
        malformed does not matter for (1); a root of the purpose log never counts."""
        d1, R1 = ev_root("r1", {"chain"})
        d2, R2 = ev_root("r2", {"chain"}, spki=self.tspki)
        dl, RL = ev_root("l", {"log"})
        self.assertEqual(self.c(self.mk(), "time_witness"), self.no("no_time_anchor"))
        self.assertEqual(self.c(self.mk(roots=[(d1, R1)]), "time_witness"), self.no("no_time_anchor"))
        self.assertEqual(self.c(self.mk(tas=[ev_ta(9, 8, ev_assess(paths=(dl,)))], roots=[(dl, RL)]), "time_witness"), self.no("no_tsa_root_supplied"))
        for want, a, roots in (("signature_not_checkable", ev_assess(step5="not_performable"), [(d1, R1)]),
                               ("not_chained_to_auditor_root", ev_assess(paths=(dl,)), [(d1, R1), (dl, RL)]),
                               ("published_test_key", ev_assess(paths=(d1,), signer=self.tspki), [(d1, R1)]),
                               ("published_test_key", ev_assess(paths=(d2,)), [(d2, R2)]),
                               ("token_extensions_unusable", ev_assess(paths=(d1,), qs="unusable"), [(d1, R1)]),
                               ("published_test_key", ev_assess(paths=(d2,), qs="unusable"), [(d1, R1), (d2, R2)])):   # never combined
            with self.subTest(want):
                self.assertEqual(self.c(self.mk(tas=[ev_ta(9, 8, a)], roots=roots), "time_witness"), self.no(want))
        res = self.mk(tas=[ev_ta(9, 8, ev_assess(paths=(d1,), qs="absent")), ev_ta(21, 20, ev_assess(paths=(d1,), qs="malformed")),
                           ev_ta(24, 23, ev_assess(paths=()))], roots=[(d1, R1)])
        self.assertEqual(self.c(res, "time_witness"), self.yes(2, 20))
        self.assertEqual(res.evidence_level["anchors"]["tsa_roots"], [{"cert_sha256": hashlib.sha256(d1).hexdigest(), "credited_for": ["time_witness"]}])
        res = self.mk(tas=[ev_ta(9, 8, ev_assess(paths=())), ev_ta(21, 20, ev_assess(paths=(d1,), qs="unusable"))], roots=[(d1, R1)])
        self.assertEqual(self.c(res, "time_witness"), self.no("token_extensions_unusable"))           # max(s) over all pairs

    def test_10_9_4_condition_2_expected_root_found(self):
        """10.9.4 (2): every found expected root of the sources auditor and anchor_history; count the distinct
        (found_at, merkle_root), reach the largest found_at; anchors.expected_root_sources in the order auditor,
        anchor_history; none found: no_expected_root_found."""
        self.assertEqual(self.c(self.mk(), "expected_root_found"), self.no("no_expected_root_found"))
        res = self.mk(found=[(20, "aa" * 32, {"anchor_history"}), (20, "aa" * 32, {"auditor"}), (14, "bb" * 32, {"anchor_history"})])
        self.assertEqual(self.c(res, "expected_root_found"), self.yes(2, 20))
        self.assertEqual(res.evidence_level["anchors"]["expected_root_sources"], ["auditor", "anchor_history"])
        ev = self.ev(self.mk(found=[(14, "bb" * 32, {"auditor"})]))
        self.assertEqual((ev["level"], ev["up_to_tree_size"], ev["segments"][0]["basis"]), (1, 14, ["expected_root_found"]))

    def test_10_9_4_condition_3_receipt_key_confirmed(self):
        """10.9.4 (3): no_receipt without a receipt whose signature holds; stages key_not_confirmed (key only from the
        manifest) and key_is_device_key (the confirmed public key is one of D); reach the largest tree_size of a credited
        receipt, count the credited receipts. It reads no finding of the vendor log and none of the anchor history."""
        dev = pubkey(DEV_SEED).hex()
        self.assertEqual(self.c(self.mk(), "receipt_key_confirmed"), self.no("no_receipt"))
        self.assertEqual(self.c(self.mk(receipts=[ev_rc(16, 15, via=None)]), "receipt_key_confirmed"), self.no("key_not_confirmed"))
        self.assertEqual(self.c(self.mk(receipts=[ev_rc(16, 15, via=None), ev_rc(30, 28, pub=dev)], D=[dev]), "receipt_key_confirmed"),
                         self.no("key_is_device_key"))
        res = self.mk(classes=["VENDOR_LOG_CONTRADICTION", "RECEIPT_NOT_LOGGED", "ANCHOR_HISTORY_CONTRADICTION", "ANCHOR_HISTORY_FORK"],
                      receipts=[ev_rc(16, 15), ev_rc(30, 28, via="list", key="vendor-2", version=3, root_id="wurzel-test"), ev_rc(31, 30, via=None)])
        self.assertEqual(self.c(res, "receipt_key_confirmed"), self.yes(2, 28))
        self.assertEqual(res.evidence_level["anchors"]["vendor_keys"],
                         [{"key_id": "vendor-1", "via": "pinned", "list_version": None, "root_id": None, "root_from": None},
                          {"key_id": "vendor-2", "via": "list", "list_version": 3, "root_id": "wurzel-test", "root_from": "auditor"}])

    def test_10_9_4_condition_4_time_witness_qualified(self):
        """10.9.4 (4): no_time_anchor, then no_qualified_root_supplied (a root of the purpose chain alone does not count);
        then every pair of TIME_ANCHOR and root of the purpose qualified through the eight stages in order:
        signature_not_checkable (5a, or Z.6 not checkable), not_chained_to_qualified_root, published_test_key,
        qualified_root_in_package, outside_qualified_window (qualifiziert_ab <= genTime < qualifiziert_bis, to the
        nanosecond), signing_certificate_not_bound (Z.6 violated), token_extensions_unusable, qualified_statement
        (malformed before absent where pairs fail there with both results). A credited item of (4) is one of (1)."""
        d, R = ev_root("q", {"qualified"}, bis="2026-01-02T23:55:01Z")
        dc, RC = ev_root("c", {"chain"})
        ok = dict(paths=(d,), gen="2026-01-02T23:55:00.999999999Z")
        self.assertEqual(self.c(self.mk(roots=[(d, R)]), "time_witness_qualified"), self.no("no_time_anchor"))
        self.assertEqual(self.c(self.mk(tas=[ev_ta(9, 8, ev_assess(paths=(dc,)))], roots=[(dc, RC)]), "time_witness_qualified"), self.no("no_qualified_root_supplied"))
        for want, a, pkg in (("signature_not_checkable", ev_assess(step5="not_performable"), ()),
                             ("signature_not_checkable", ev_assess(z6="not_checkable", **ok), ()),
                             ("not_chained_to_qualified_root", ev_assess(paths=()), ()),
                             ("published_test_key", ev_assess(signer=self.tspki, **ok), ()),
                             ("qualified_root_in_package", ev_assess(**ok), (R["cert"].spki_sha256,)),
                             ("outside_qualified_window", ev_assess(paths=(d,), gen="2026-01-02T23:55:01Z"), ()),
                             ("outside_qualified_window", ev_assess(paths=(d,), gen="2024-12-31T23:59:59.999999999Z"), ()),
                             ("signing_certificate_not_bound", ev_assess(z6="violated", **ok), ()),
                             ("token_extensions_unusable", ev_assess(qs="unusable", **ok), ()),
                             ("qualified_statement_malformed", ev_assess(qs="malformed", **ok), ()),
                             ("no_qualified_statement", ev_assess(qs="absent", **ok), ())):
            with self.subTest(want, a=a):
                self.assertEqual(self.c(self.mk(tas=[ev_ta(9, 8, a)], roots=[(d, R)], pkg_spki=pkg), "time_witness_qualified"), self.no(want))
        res = self.mk(tas=[ev_ta(9, 8, ev_assess(qs="absent", **ok)), ev_ta(21, 20, ev_assess(qs="malformed", **ok))], roots=[(d, R)])
        self.assertEqual(self.c(res, "time_witness_qualified"), self.no("qualified_statement_malformed"))
        res = self.mk(tas=[ev_ta(9, 8, ev_assess(**ok)), ev_ta(21, 20, ev_assess(paths=(d, dc), gen="2026-01-03T00:00:00Z"))], roots=[(d, R), (dc, RC)])
        ev = self.ev(res)
        self.assertEqual((ev["conditions"]["time_witness_qualified"], ev["conditions"]["time_witness"]), (self.yes(1, 8), self.yes(2, 20)))
        self.assertEqual(sorted((x["cert_sha256"], x["credited_for"]) for x in ev["anchors"]["tsa_roots"]),
                         sorted([(hashlib.sha256(d).hexdigest(), ["time_witness", "time_witness_qualified"]), (hashlib.sha256(dc).hexdigest(), ["time_witness"])]))
        self.assertEqual([x["cert_sha256"] for x in ev["anchors"]["tsa_roots"]], sorted(x["cert_sha256"] for x in ev["anchors"]["tsa_roots"]))

    def test_10_9_4_condition_5_receipts_logged(self):
        """10.9.4 (5): reasons without an item vendor_log_not_supplied, vendor_log_not_established,
        vendor_log_contradiction, no_receipt in this order; per receipt good (included), neutral (before_start) or bad
        with the code of the table; r5' the largest good t with every receipt up to t good or neutral; reach min(r5',
        t_m - 1) with LOGGED_ROOT_MISMATCH; met with a reach of at least 1; else receipts_before_log_start, the code of the
        foremost bad receipt in chain order, or logged_root_mismatch; count the good receipts up to the reach."""
        cond = lambda **kw: self.c(self.mk(vlog=ev_vlog(**kw)), "receipts_logged")
        self.assertEqual(self.c(self.mk(), "receipts_logged"), self.no("vendor_log_not_supplied"))
        self.assertEqual(cond(status="no_protocol_key", contra=True), self.no("vendor_log_not_established"))
        self.assertEqual(cond(contra=True), self.no("vendor_log_contradiction"))
        self.assertEqual(cond(), self.no("no_receipt"))
        for m in self.el["conditions"]["receipts_logged"]["per_receipt"]:
            with self.subTest(m):
                self.assertEqual(cond(classes=[(16, 15, m["class"], m.get("subclass", "no_record"))]), self.no(m["code"]))
        self.assertEqual(cond(classes=[(16, 15, "unchecked", "day_not_witnessed")]), self.no("day_timestamp_not_confirmed"))
        self.assertEqual(cond(classes=[(16, 15, "included"), (22, 21, "pending"), (30, 28, "included")]), self.yes(1, 15))
        self.assertEqual(cond(classes=[(6, 5, "before_start"), (16, 15, "included")]), self.yes(1, 15))
        self.assertEqual(cond(classes=[(6, 5, "before_start"), (16, 15, "before_start")]), self.no("receipts_before_log_start"))
        self.assertEqual(cond(classes=[(30, 28, "missing"), (31, 15, "not_included")]), self.no("log_day_not_supplied"))     # chain order, not tree_size
        self.assertEqual(cond(classes=[(16, 15, "included"), (30, 28, "included")], t_m=20), self.yes(1, 19))
        self.assertEqual(cond(classes=[(16, 15, "included"), (30, 28, "included")], t_m=1), self.no("logged_root_mismatch"))

    def test_10_9_4_condition_6_completeness_from_history(self):
        """10.9.4 (6): met exactly when anchor_history.completeness.status is established, reach its up_to_tree_size and
        count anchor_history.roots.found; otherwise count 0 and the reason after the table from the reason of the
        completeness (registry from_completeness); root_missing does not occur in the state rated."""
        res = self.mk(completeness={"status": "established", "reason": None, "up_to_tree_size": 28}, hist_found=3)
        self.assertEqual(self.c(res, "completeness_from_history"), self.yes(3, 28))
        for reason, want in self.el["conditions"]["completeness_from_history"]["from_completeness"].items():
            if want is None: continue
            for status in ("partial", "not_established"):
                with self.subTest(reason=reason, status=status):
                    res = self.mk(completeness={"status": status, "reason": reason, "up_to_tree_size": None}, hist_found=2)
                    self.assertEqual(self.c(res, "completeness_from_history"), self.no(want))

    def test_10_9_4_condition_7_log_day_qualified(self):
        """10.9.4 (7), the second way to level 3: vendor_log_not_supplied, vendor_log_not_established,
        vendor_log_contradiction, no_qualified_log_root_supplied (no root with both purposes log and qualified),
        no_receipt_included; then every triple of included receipt, time stamp of c(d) that is not defective, and such a
        root through the stages signature_not_checkable, not_chained_to_qualified_log_root, published_test_key,
        outside_qualified_window, qualified_day_stamp_late (genTime cut to ms not below end(d) + W),
        qualified_day_stamp_gap (genTime cut to ms minus server_ts greater than G_q), token_extensions_unusable,
        qualified_statement. A defective time stamp forms no triple; Z.6 not checkable concerns (4) only (7.5.7)."""
        W = self.reg["vendor_log"]["time"]["token_window_ms"]
        end = V.day_end_ms(V.day_ord(EV_DAY))
        iso_ms = lambda m: datetime.datetime.fromtimestamp(m / 1000, UTCZ).strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (m % 1000)
        d, R = ev_root("lq", {"log", "qualified"}, ab="2026-01-03T00:00:00Z")
        dl, RL = ev_root("l", {"log"})
        dq, RQ = ev_root("q", {"qualified"})
        inc = [(16, 15, "included"), (30, 28, "pending")]
        good = dict(paths=(d,), gen="2026-01-03T00:05:01Z")
        cond = lambda roots, stamps=(), **kw: self.c(self.mk(roots=roots, vlog=ev_vlog(stamps=stamps, **kw)), "log_day_qualified")
        self.assertEqual(self.c(self.mk(roots=[(d, R)]), "log_day_qualified"), self.no("vendor_log_not_supplied"))
        self.assertEqual(cond([(d, R)], status="no_protocol_key"), self.no("vendor_log_not_established"))
        self.assertEqual(cond([(d, R)], contra=True, classes=inc), self.no("vendor_log_contradiction"))
        self.assertEqual(cond([(dl, RL), (dq, RQ)], classes=inc), self.no("no_qualified_log_root_supplied"))
        self.assertEqual(cond([(d, R)], classes=[(30, 28, "pending")]), self.no("no_receipt_included"))
        for want, a in (("signature_not_checkable", ev_assess(step5="not_performable")),
                        ("not_chained_to_qualified_log_root", ev_assess(paths=(dl,))),
                        ("published_test_key", ev_assess(signer=self.tspki, **good)),
                        ("outside_qualified_window", ev_assess(paths=(d,), gen="2026-01-02T23:59:59.999999999Z")),
                        ("qualified_day_stamp_late", ev_assess(paths=(d,), gen=iso_ms(end + W))),
                        ("token_extensions_unusable", ev_assess(qs="unusable", **good)),
                        ("qualified_statement_malformed", ev_assess(qs="malformed", **good)),
                        ("no_qualified_statement", ev_assess(qs="absent", **good))):
            with self.subTest(want):
                self.assertEqual(cond([(d, R), (dl, RL)], [("confirmed", a)], classes=inc), self.no(want))
        # the last instant before end(d) + W is not late, but lies more than G_q after every receipt of day d (G_q < W)
        self.assertEqual(cond([(d, R)], [("unconfirmed", ev_assess(paths=(d,), gen=iso_ms(end + W - 1)))], classes=inc), self.no("qualified_day_stamp_gap"))
        self.assertEqual(cond([(d, R)], [("unconfirmed", ev_assess(paths=(d,), gen="2026-01-04T11:55:01Z"))], classes=inc), self.yes(1, 15))
        self.assertEqual(cond([(d, R)], [("unconfirmed", ev_assess(z6="not_checkable", **good))], classes=inc), self.yes(1, 15))
        self.assertEqual(cond([(d, R)], [("defective", ev_assess(**good)), ("confirmed", ev_assess(paths=(dl,)))], classes=inc),
                         self.no("not_chained_to_qualified_log_root"))
        res = self.mk(roots=[(d, R), (dl, RL)], vlog=ev_vlog(stamps=[("confirmed", ev_assess(**good))], classes=[(16, 15, "included"), (30, 28, "included")]))
        ev = self.ev(res)
        self.assertEqual(ev["conditions"]["log_day_qualified"], self.yes(2, 28))
        self.assertEqual(ev["anchors"]["tsa_roots"], [{"cert_sha256": hashlib.sha256(d).hexdigest(), "credited_for": ["log_day_qualified"]}])

    # ---------------------------------------------------------------- 10.9.6 notes
    def test_10_9_6_notes_each_on_its_occasion_in_note_order(self):
        """10.9.6: every note stands exactly when its occasion applies, once, in note_order, only in the state rated;
        vendor_root_builtin_only (no vendor root is built in) and cms_not_implemented (steps 5 and 6 of 7.3 run) never."""
        cases = {"unsealed_end": dict(classes=["UNSEALED_END"]), "stale_package": dict(classes=["TRAILING_SILENCE"]),
                 "package_not_fully_known": dict(classes=["UNKNOWN_MANIFEST_FIELD"]),
                 "history_recent_roots_skipped": dict(ah_notes=["recent_roots_not_found"]),
                 "receipts_pending_log": dict(vlog=ev_vlog([(16, 15, "included"), (30, 28, "pending")])),
                 "log_day_not_supplied": dict(vlog=ev_vlog([(16, 15, "missing")])),
                 "receipt_not_logged": dict(classes=["RECEIPT_NOT_LOGGED"]), "logged_root_mismatch": dict(classes=["LOGGED_ROOT_MISMATCH"])}
        for note, kw in cases.items():
            with self.subTest(note):
                self.assertEqual(self.ev(self.mk(**kw))["notes"], [note])
        for cls in ("SPEC_NEWER", "UNKNOWN_ENTRY_TYPE"):
            self.assertEqual(self.ev(self.mk(classes=[cls]))["notes"], ["package_not_fully_known"])
        res = self.mk(classes=["CONTENT_MISMATCH", "UNKNOWN_ENTRY_TYPE", "UNSEALED_END", "TRAILING_SILENCE", "LOGGED_ROOT_MISMATCH", "RECEIPT_NOT_LOGGED"],
                      ah_notes=["recent_roots_not_found"], vlog=ev_vlog([(16, 15, "missing"), (30, 28, "pending")]))
        self.assertEqual(self.ev(res)["notes"], [n for n in self.el["note_order"] if n not in ("vendor_root_builtin_only", "published_test_key_credited",
                                                                                              "last_receipt_not_confirmed", "expected_root_auditor_only",
                                                                                              "tsa_root_in_package", "cms_not_implemented")])
        self.assertEqual(self.ev(self.mk(classes=["RECEIPT_INVALID", "UNSEALED_END", "TRAILING_SILENCE"]))["notes"], [])

    def test_10_9_6_published_test_key_credited(self):
        """10.9.6, published_test_key_credited: a condition that is met rests on an Ed25519 test key of published_test_keys:
        for (3) the key of a credited receipt or the vendor root of its list, for (5) an established protocol key or the
        root of the effective protocol key list, for (2) with the source anchor_history and for (6) the key of a used page
        of the package or the root of the role list that establishes it. Never from a condition that is not met."""
        pub, root = self.ed[1], self.ed[0]
        note = "published_test_key_credited"
        has = lambda **kw: note in self.ev(self.mk(**kw))["notes"]
        self.assertTrue(has(receipts=[ev_rc(16, 15, pub=pub)]))
        self.assertFalse(has(receipts=[ev_rc(16, 15, pub=pub, via=None)]))
        self.assertTrue(has(receipts=[ev_rc(16, 15, via="list", version=1, root_id="w")], vroots={"w": root}))
        self.assertFalse(has(receipts=[ev_rc(16, 15)], vroots={"w": root}))
        logged = ev_vlog([(16, 15, "included")], proto=[pub])
        self.assertTrue(has(receipts=[ev_rc(16, 15)], vlog=logged))
        self.assertTrue(has(receipts=[ev_rc(16, 15)], vlog=ev_vlog([(16, 15, "included")], p_root="w"), vroots={"w": root}))
        self.assertFalse(has(receipts=[ev_rc(16, 15)], vlog=ev_vlog([(16, 15, "pending")], proto=[pub])))
        test_page = ev_page("st-t", "pinned", pub=self.ed[5])
        est = {"status": "established", "reason": None, "up_to_tree_size": 15}
        self.assertTrue(has(pages=[test_page], completeness=est, hist_found=1))
        self.assertTrue(has(pages=[ev_page()], Q=Q_TEST, vroots={"wurzel-test": root}, completeness=est, hist_found=1))
        self.assertTrue(has(pages=[test_page], found=[(15, "aa" * 32, {"anchor_history"})]))
        self.assertFalse(has(pages=[test_page], found=[(15, "aa" * 32, {"auditor"})]))
        # (2) rests only on the used pages that carry the recorded recording of a found history root (10.10.2)
        self.assertFalse(has(pages=[ev_page("st-t", "pinned", pub=self.ed[5], roots=[(15, "aa" * 32, "reported", EV_SERVER_TS)])],
                             found=[(15, "aa" * 32, {"anchor_history"})]))
        self.assertFalse(has(pages=[ev_page("st-t", "pinned", pub=self.ed[5], roots=[(14, "bb" * 32, "countersigned", EV_SERVER_TS)]), ev_page("st-2", "pinned")],
                             found=[(15, "aa" * 32, {"anchor_history"})]))
        self.assertFalse(has(pages=[ev_page(src="pinned")], Q=Q_TEST, vroots={"wurzel-test": root}, completeness=est, hist_found=1))

    def test_10_9_6_last_receipt_not_confirmed(self):
        """10.9.6: (3) is met and the receipt 8.6 chooses as the last countersigned one is not credited; the text names the
        reach of (3) as <t>."""
        rc = [ev_rc(16, 15), ev_rc(30, 28, via=None, key="vendor-2")]
        res = self.mk(receipts=rc, lc_seq=30)
        ev = self.ev(res)
        self.assertEqual((ev["notes"], ev["up_to_tree_size"]), (["last_receipt_not_confirmed"], 15))
        for lang in ("de", "en"):
            self.assertIn("  " + self.el["texts"]["note"][lang].format(text=self.el["notes"]["last_receipt_not_confirmed"][lang].format(t=15)),
                          V.evidence_level_text(res, lang, self.rules).splitlines())
        self.assertEqual(self.ev(self.mk(receipts=rc, lc_seq=16))["notes"], [])
        self.assertEqual(self.ev(self.mk(receipts=[ev_rc(30, 28, via=None)], lc_seq=30))["notes"], [])           # (3) not met

    def test_10_9_6_expected_root_auditor_only(self):
        """10.9.6: level 1 at seq 1 rests only on (2), and every root credited for it carries only the source auditor."""
        aud, hist = (20, "aa" * 32, {"auditor"}), (20, "aa" * 32, {"anchor_history"})
        d, R = ev_root("r", {"chain"})
        note = lambda **kw: self.ev(self.mk(**kw))["notes"]
        self.assertEqual(note(found=[aud]), ["expected_root_auditor_only"])
        self.assertEqual(note(found=[aud, hist]), [])
        self.assertEqual(note(found=[aud], tas=[ev_ta(9, 8, ev_assess(paths=(d,)))], roots=[(d, R)]), [])
        self.assertEqual(note(found=[aud], receipts=[ev_rc(16, 15)]), [])

    def test_10_9_6_tsa_root_in_package_note_for_1_exclusion_for_4(self):
        """10.9.6 and 10.9.4: a root credited by (1) with the SPKI of a certificate from keys/tsa/ gives the note
        tsa_root_in_package and still counts for (1); for (4) the same root is excluded (qualified_root_in_package)."""
        d, R = ev_root("q", {"qualified"})
        ev = self.ev(self.mk(tas=[ev_ta(9, 8, ev_assess(paths=(d,)))], roots=[(d, R)], pkg_spki=[R["cert"].spki_sha256]))
        self.assertEqual((ev["conditions"]["time_witness"], ev["conditions"]["time_witness_qualified"], ev["notes"]),
                         (self.yes(1, 8), self.no("qualified_root_in_package"), ["tsa_root_in_package"]))

    # ---------------------------------------------------------------- 10.10.2 anchors and the object
    def test_10_10_2_anchors(self):
        """10.10.2: anchors.vendor_keys per key of a credited receipt ascending by key_id; statement_keys the pairs of the
        used pages on which (2) with the source anchor_history or (6) rests (pin or role list with version, wurzel_id and
        origin auditor), without repetition, in the order of anchor_history.keys, empty without such a page;
        qualified_roots_file stand (YYYY-MM-DDThh:mm:ss.sssZ, cut to whole milliseconds, 10.10.1) and quelle as written,
        null without the file; null anchors outside the state rated."""
        est = {"status": "established", "reason": None, "up_to_tree_size": 15}
        res = self.mk(receipts=[ev_rc(30, 28, key="vendor-b"), ev_rc(16, 15, key="vendor-a")], pages=[ev_page("st-2", "pinned"), ev_page("st-1")], Q=Q_TEST,
                      completeness=est, hist_found=1, qualified={"stand": "2026-01-01T00:00:00.98765Z", "quelle": "Test"})
        an = self.ev(res)["anchors"]
        self.assertEqual([k["key_id"] for k in an["vendor_keys"]], ["vendor-a", "vendor-b"])
        self.assertEqual(an["statement_keys"], [{"key_id": "st-1", "via": "role_list", "list_version": 1, "root_id": "wurzel-test", "root_from": "auditor"},
                                                {"key_id": "st-2", "via": "pinned", "list_version": None, "root_id": None, "root_from": None}])
        # 10.10.1, Zeitpunkte: an instant from an input of the auditor in the form YYYY-MM-DDThh:mm:ss.sssZ, whole milliseconds
        self.assertEqual(an["qualified_roots_file"], {"stand": "2026-01-01T00:00:00.987Z", "quelle": "Test"})
        an = self.ev(self.mk(receipts=[ev_rc(16, 15)], pages=[ev_page()], Q=Q_TEST))["anchors"]
        self.assertEqual((an["statement_keys"], an["qualified_roots_file"], an["tsa_roots"], an["expected_root_sources"]), ([], None, [], []))
        self.assertIsNone(self.ev(self.mk(classes=["SIG_INVALID"]))["anchors"])

    def test_10_10_2_registry_example_valid_basic(self):
        """10.10.2, Beispiel: valid_basic in the audit environment of the corpus gives exactly the object of the registry
        example (verifier.evidence_level.example: qualified_time null below level 3, next.missing after 10.9.5 with (4)
        and (7) both), and the one-line example in the text of 10.10.2 (DE and EN) is its JCS form."""
        code, j, err = VectorsEvidence110.run_vector(os.path.join(VEKTOREN, "valid_basic"), vector_anchors())
        self.assertEqual((code, j["evidence_level"]), (4, self.el["example"]["object"]), err)
        for fn in ("format.de.md", "format.en.md"):
            with open(os.path.join(HERE, "..", "spec", fn), encoding="utf-8") as fh: text = fh.read()
            self.assertIn("\n" + V.jcs(j["evidence_level"]) + "\n", text, fn)
        self.assertEqual(schema_ok(j["evidence_level"], self.schema), "")

    # ---------------------------------------------------------------- 10.10.3 text
    def text(self, res, lang="de"):
        self.ev(res)
        return V.evidence_level_text(res, lang, self.rules).splitlines()

    def test_10_10_3_states_without_level(self):
        """10.10.3: state chain_invalid: the line "Beweisstufe: keine (Kette ungueltig)", the closing text and the line on
        affiliation; state format_error: the line "Beweisstufe: nicht bestimmt (Formatfehler)" and the closing text, no
        line on affiliation."""
        t, st = self.el["texts"], self.el["states"]
        a = self.rules["affiliation"]["texts"]
        for lang in ("de", "en"):
            res = self.mk(classes=["SIG_INVALID"], receipts=[ev_rc(16, 15)])
            self.assertEqual(self.text(res, lang), [t["state_line"][lang].format(label=t["label"][lang], state=st["chain_invalid"][lang]),
                                                    "  " + t["disclaimer"][lang],
                                                    "  " + a["not_checked"][lang] + " " + a["not_checked_fetch"][lang].format(chain_id=CHAIN)])
            res = self.mk(classes=["FORMAT_ERROR"])
            res.evidence_level = V.evidence_level(res, 3, self.rules)
            self.assertEqual(V.evidence_level_text(res, lang, self.rules).splitlines(),
                             [t["state_line"][lang].format(label=t["label"][lang], state=st["format_error"][lang]), "  " + t["disclaimer"][lang]])
        self.assertEqual(self.text(self.mk(classes=["SIG_INVALID"]))[0], "Beweisstufe: keine (Kette ungültig)")

    def test_10_10_3_level_0_block(self):
        """10.10.3 at level 0: the head line "<label> 0 von 3 (<Name>), seq 1 bis <N>.", the segment without "Ende durch",
        the text of the level, the lines "fehlt" with need any and the sentence that a confirmed countersignature leads
        directly to level 2 as a line of the block indented by two spaces, the closing text and the line on affiliation
        (no open_at_level_2 below level 2); (7) stands among the missing conditions of level 3 only (10.9.1, 10.9.5)."""
        t, el, a = self.el["texts"], self.el, self.rules["affiliation"]["texts"]
        for lang in ("de", "en"):
            lines = self.text(self.mk(), lang)
            cl = lambda c: el["conditions"][c][lang]
            self.assertEqual(lines, [t["head_level0"][lang].format(label=t["label"][lang], name=el["levels"]["0"]["name_" + lang], entries=32),
                                     "  " + t["segments"][lang].format(segments=t["segment_level0"][lang].format(first_seq=1, last_seq=32)),
                                     "  " + el["levels"]["0"][lang], "  " + t["next_any"][lang].format(n=1)]
                             + ["    " + t["missing_item"][lang].format(condition=cl(c), reason=el["reasons"][r][lang])
                                for c, r in (("time_witness", "no_time_anchor"), ("expected_root_found", "no_expected_root_found"), ("receipt_key_confirmed", "no_receipt"))]
                             + ["  " + t["direct_to_2"][lang],
                                "  " + t["disclaimer"][lang], "  " + a["not_checked"][lang] + " " + a["not_checked_never_anchored"][lang]])
        self.assertEqual(self.text(self.mk())[0], "Beweisstufe: 0 von 3 (Selbstauskunft), seq 1 bis 32.")

    def test_10_10_3_level_2_block_anchors_and_open_at_level_2(self):
        """10.10.3: head with reach, segments joined by "; " with "Ende durch" naming the labels of basis, "liegt vor" per
        condition that is met with count, reach and anchors (keys of the credited receipts: pinned or from a list with
        the root of the auditor); "Beweisstufe der Kette:" with findings of material_classes only; at level 2 the line on
        affiliation of not_checked and not_determined ends with open_at_level_2, of the other statuses not."""
        t, el, a = self.el["texts"], self.el, self.rules["affiliation"]["texts"]
        rc = [ev_rc(16, 15), ev_rc(30, 28, via="list", key="vendor-2", version=2, root_id="wurzel-test")]
        lines = self.text(self.mk(receipts=rc))
        self.assertEqual(lines[0], "Beweisstufe: 2 von 3 (gegengezeichnet), belegt für seq 1 bis 28 von 32.")
        self.assertEqual(lines[1], "  Verlauf: Stufe 2 für seq 1 bis 28 (Ende durch: " + el["conditions"]["receipt_key_confirmed"]["de"] + "); Stufe 0 für seq 29 bis 32.")
        # 10.10.3, <Anker>: several anchors are joined by ", " (comma and space).
        self.assertEqual(lines[3], "  " + t["met"]["de"].format(condition=el["conditions"]["receipt_key_confirmed"]["de"], count=2, up_to_tree_size=28,
                                                                anchors="angehefteter Schlüssel vendor-1, Schlüssel vendor-2 aus Liste Version 2, Wurzel wurzel-test des Prüfers"))
        self.assertEqual(lines[-1], "  " + a["not_checked"]["de"] + " " + a["not_checked_fetch"]["de"].format(chain_id=CHAIN) + " " + a["open_at_level_2"]["de"])
        self.assertTrue(self.text(self.mk(classes=["REPORT_MISMATCH"], receipts=rc))[0].startswith("Beweisstufe der Kette: 2 von 3"))
        self.assertTrue(self.text(self.mk(classes=["REPORT_MISMATCH"], receipts=rc), "en")[0].startswith("Evidence level of the chain: 2 of 3"))
        res = self.mk(receipts=rc, aff="not_determined")
        res.affiliation["reason"] = "history_no_package_page"
        self.assertTrue(self.text(res)[-1].endswith(". " + a["open_at_level_2"]["de"]), self.text(res)[-1])
        lines = self.text(self.mk(found=[(20, "aa" * 32, {"auditor"})]))
        self.assertFalse(lines[-1].endswith(a["open_at_level_2"]["de"]))             # level 1

    def test_10_10_3_level_3_anchor_texts(self):
        """10.10.3, <Anker>: fingerprints of the crediting roots for time stamps, for (4) and (7) stand and quelle of the
        file of qualified roots, the sources of the expected roots, for (5) and (7) the log_id, for (6) as_of of the anchor
        history and the statements keys of its pages; (7) stands among the lines "liegt vor" like every condition; level 3
        reaches as far as the larger reach of (4) and (7) (10.9.5), its segment ends by the codes whose reach equals r3;
        the line "qualifiziert bestaetigt" stands directly after the text of the level."""
        t, el = self.el["texts"], self.el
        d, R = ev_root("q", {"log", "qualified"})
        fp = hashlib.sha256(d).hexdigest()
        res = self.mk(tas=[ev_ta(9, 8, ev_assess(paths=(d,)))], roots=[(d, R)], receipts=[ev_rc(16, 15)], found=[(15, "aa" * 32, {"anchor_history"})],
                      pages=[ev_page()], Q=Q_TEST, completeness={"status": "established", "reason": None, "up_to_tree_size": 15}, hist_found=1,
                      qualified={"stand": "2026-01-01T00:00:00Z", "quelle": "Test"},
                      vlog=ev_vlog([(16, 15, "included")], stamps=[("confirmed", ev_assess(paths=(d,), gen="2026-01-03T00:05:01Z"))]))
        lines = self.text(res, "en")
        self.assertEqual(lines[0], "Evidence level: 3 of 3 (anchored and reconciled), evidenced for seq 1 to 15 of 32.")
        lab = lambda c: el["conditions"][c]["en"]
        self.assertEqual(lines[1], "  Course: level 3 for seq 1 to 15 (ended by: " + " and ".join(lab(c) for c in (
            "receipt_key_confirmed", "receipts_logged", "completeness_from_history", "log_day_qualified"))
                         + "); level 0 for seq 16 to 32.")
        self.assertEqual(lines[2], "  " + el["levels"]["3"]["en"])
        self.assertEqual(lines[3], "  qualified confirmation: at the latest 2026-01-03T00:05:01.000Z (time stamp of the vendor log, tree_size 15, "
                                   "0 h 10 min after the countersignature)")
        root = "root with fingerprint " + fp
        qf = "file of qualified roots, as of 2026-01-01T00:00:00.000Z, source Test"
        met = lambda c, n, tt, an: "  " + t["met"]["en"].format(condition=lab(c), count=n, up_to_tree_size=tt, anchors=an)
        self.assertEqual(lines[4:11], [met("time_witness", 1, 8, root), met("expected_root_found", 1, 15, "sources: anchor history"),
                                       met("receipt_key_confirmed", 1, 15, "pinned key vendor-1"), met("time_witness_qualified", 1, 8, root + ", " + qf),
                                       met("receipts_logged", 1, 15, "vendor log " + LOG_ID),
                                       met("completeness_from_history", 1, 15, "anchor history of 2026-01-03T06:10:00.000Z, statements key st-1 from role list version 1, auditor's root wurzel-test"),
                                       met("log_day_qualified", 1, 15, root + ", " + qf + ", vendor log " + LOG_ID)])
        self.assertEqual(lines[11:], ["  " + t["disclaimer"]["en"], "  " + V.affiliation_text(res, "en") + " " + self.rules["affiliation"]["texts"]["open_at_level_2"]["en"]])
        self.assertIsNone(res.evidence_level["next"])
        self.assertEqual(res.evidence_level["qualified_time"], {"via": "log_day_qualified", "tree_size": 15, "latest": "2026-01-03T00:05:01.000Z", "gap_ms": 600000})

    # ---------------------------------------------------------------- 10.9.4 (7): G_q, 10.10.2 qualified_time, 10.10.3 lines
    def test_10_9_4_condition_7_gap_g_q(self):
        """10.9.1, 10.9.4 (7), stage qualified_day_stamp_gap: a triple fails when genTime, cut to whole milliseconds, minus
        server_ts of the receipt is greater than G_q = 129 600 000 ms (registry gap_max_ms); exactly G_q holds, and so
        does a genTime that is cut to exactly G_q. The stage stands after qualified_day_stamp_late and before
        token_extensions_unusable; each receipt is judged against its own server_ts."""
        spec = self.el["conditions"]["log_day_qualified"]
        self.assertEqual(spec["gap_max_ms"], 129600000)
        self.assertEqual(spec["stages"][spec["stages"].index("qualified_day_stamp_late") + 1:spec["stages"].index("token_extensions_unusable")],
                         ["qualified_day_stamp_gap"])
        self.assertIn("qualified_day_stamp_gap", self.el["reason_order"])
        self.assertIn("36", self.el["reasons"]["qualified_day_stamp_gap"]["de"])
        d, R = ev_root("lq", {"log", "qualified"})
        inc = [(16, 15, "included")]
        cond = lambda gen, classes=inc, **kw: self.c(self.mk(roots=[(d, R)], vlog=ev_vlog(classes, stamps=[("confirmed", ev_assess(paths=(d,), gen=gen, **kw))])),
                                                     "log_day_qualified")
        self.assertEqual(cond("2026-01-04T11:55:01Z"), self.yes(1, 15))                      # exactly G_q after 23:55:01.000
        self.assertEqual(cond("2026-01-04T11:55:01.001Z"), self.no("qualified_day_stamp_gap"))
        self.assertEqual(cond("2026-01-04T11:55:01.0009Z"), self.yes(1, 15))                 # cut to 11:55:01.000
        self.assertEqual(cond("2026-01-04T11:55:01.001Z", qs="unusable"), self.no("qualified_day_stamp_gap"))
        self.assertEqual(cond("2026-01-05T00:00:00Z"), self.no("qualified_day_stamp_late"))  # end(d) + W: late before gap
        # two receipts of the same day: the later one is still within G_q, the earlier one is not
        two = [(10, 9, "included", None, "2026-01-02T10:00:00.000Z"), (16, 15, "included")]
        self.assertEqual(cond("2026-01-04T11:55:01Z", classes=two), self.yes(1, 15))
        self.assertEqual(cond("2026-01-03T22:00:00Z", classes=two), self.yes(2, 15))

    def level3(self, tas=(), classes=((16, 15, "included"), (30, 28, "pending")), stamps=(), up=28, roots=None):
        """A run at level 3 through (3) and (6) up to 28 and (5) as the classes give, with (4) from tas and (7) from stamps
        of c(EV_DAY), both against the root q with the purposes log and qualified."""
        d, R = ev_root("q", {"log", "qualified"})
        est = {"status": "established", "reason": None, "up_to_tree_size": up}
        return self.mk(roots=roots or [(d, R)], receipts=[ev_rc(16, 15), ev_rc(30, 28)], completeness=est, hist_found=1, pages=[ev_page()], Q=Q_TEST,
                       tas=[ev_ta(s, t, ev_assess(paths=(d,), gen=g)) for s, t, g in tas],
                       vlog=ev_vlog(list(classes), stamps=[("confirmed", ev_assess(paths=(d,), gen=g)) for g in stamps]))

    def test_10_10_2_qualified_time(self):
        """10.10.2 qualified_time: at level 3 at seq 1 the credited item of (4) (TIME_ANCHOR per root) or (7) (receipt per
        time stamp and root) with tree_size >= up_to_tree_size and the earliest genTime; on a tie (4) before (7), then the
        smaller tree_size, then for (7) the earlier server_ts of the receipt. latest is its genTime cut to whole
        milliseconds as YYYY-MM-DDThh:mm:ss.sssZ, gap_ms latest minus server_ts for (7), null for (4); null below level 3
        and outside the state rated."""
        qt = lambda res: self.ev(res)["qualified_time"]
        q7 = lambda t, latest, gap: {"via": "log_day_qualified", "tree_size": t, "latest": latest, "gap_ms": gap}
        q4 = lambda t, latest: {"via": "time_witness_qualified", "tree_size": t, "latest": latest, "gap_ms": None}
        self.assertIsNone(qt(self.mk(receipts=[ev_rc(16, 15)])))                                                # level 2
        # (4) at 8 is below up_to_tree_size 15 and no candidate, though earlier
        self.assertEqual(qt(self.level3(tas=[(9, 8, "2026-01-02T20:00:00Z")], stamps=["2026-01-03T00:05:01Z"])),
                         q7(15, "2026-01-03T00:05:01.000Z", 600000))
        # (4) at 15 later than (7) at 15: (7); earlier: (4); same genTime: (4) before (7)
        self.assertEqual(qt(self.level3(tas=[(17, 15, "2026-01-03T00:10:00Z")], stamps=["2026-01-03T00:05:01Z"])), q7(15, "2026-01-03T00:05:01.000Z", 600000))
        self.assertEqual(qt(self.level3(tas=[(17, 15, "2026-01-03T00:01:00Z")], stamps=["2026-01-03T00:05:01Z"])), q4(15, "2026-01-03T00:01:00.000Z"))
        self.assertEqual(qt(self.level3(tas=[(17, 15, "2026-01-03T00:05:01Z")], stamps=["2026-01-03T00:05:01Z"])), q4(15, "2026-01-03T00:05:01.000Z"))
        # the smaller tree_size among items with the same genTime: (6) up to 15 caps r3 below the receipt at 20
        res = self.level3(classes=[(16, 15, "included"), (21, 20, "included"), (30, 28, "pending")], stamps=["2026-01-03T00:05:01Z"], up=15)
        self.assertEqual((self.ev(res)["up_to_tree_size"], qt(res)), (15, q7(15, "2026-01-03T00:05:01.000Z", 600000)))
        # the earlier server_ts among receipts with the same tree_size
        res = self.level3(classes=[(16, 15, "included", None, "2026-01-02T23:58:00.000Z"), (17, 15, "included"), (30, 28, "pending")],
                          stamps=["2026-01-03T00:05:01Z"])
        self.assertEqual(qt(res), q7(15, "2026-01-03T00:05:01.000Z", 600000))
        # latest is genTime cut to whole milliseconds
        self.assertEqual(qt(self.level3(stamps=["2026-01-03T00:05:01.0009Z"])), q7(15, "2026-01-03T00:05:01.000Z", 600000))
        # 10.10.2: "der mit dem fruehesten genTime" compares genTime as an instant to the nanosecond, before any cut to whole
        # milliseconds; (7) at 00:05:01.0001 comes before (4) at 00:05:01.0009 although both cut to the same millisecond.
        self.assertEqual(qt(self.level3(tas=[(17, 15, "2026-01-03T00:05:01.0009Z")], stamps=["2026-01-03T00:05:01.0001Z"])),
                         q7(15, "2026-01-03T00:05:01.000Z", 600000))
        self.assertIsNone(qt(self.mk(classes=["SIG_INVALID"], receipts=[ev_rc(16, 15)])))
        self.assertIsNone(V.evidence_level(self.mk(classes=["FORMAT_ERROR"]), 3, self.rules)["qualified_time"])

    def test_10_10_3_qualified_time_line(self):
        """10.10.3: the line "qualifiziert bestaetigt" stands exactly when qualified_time is not null, directly after the
        text of the level; for (4) it names the time witness of the chain, for (7) the time stamp of the vendor log with
        gap_ms in whole minutes, rounded down, as "<h> Std. <m> Min." (registry texts qualified_time_witness,
        qualified_time_log, gap)."""
        t = self.el["texts"]
        res = self.level3(tas=[(17, 15, "2026-01-03T00:01:00Z")], stamps=["2026-01-03T00:05:01Z"])
        lines = self.text(res)
        self.assertEqual(lines[2:4], ["  " + self.el["levels"]["3"]["de"],
                                      "  qualifiziert bestätigt: spätestens 2026-01-03T00:01:00.000Z (Zeitzeuge der Kette, tree_size 15)"])
        self.assertEqual(self.text(res, "en")[3], "  qualified confirmation: at the latest 2026-01-03T00:01:00.000Z (time witness of the chain, tree_size 15)")
        res = self.level3(stamps=["2026-01-03T00:05:01Z"])
        self.assertEqual(self.text(res)[3], "  qualifiziert bestätigt: spätestens 2026-01-03T00:05:01.000Z (Zeitstempel des Herstellerprotokolls, "
                                            "tree_size 15, 0 Std. 10 Min. nach der Gegensignatur)")
        self.assertEqual(self.text(res, "en")[3], "  qualified confirmation: at the latest 2026-01-03T00:05:01.000Z (time stamp of the vendor log, "
                                                  "tree_size 15, 0 h 10 min after the countersignature)")
        for gap, de in ((129600000, "36 Std. 0 Min."), (659999, "0 Std. 10 Min."), (59999, "0 Std. 0 Min."), (25 * 3600000 + 61000, "25 Std. 1 Min.")):
            with self.subTest(gap):
                res.evidence_level = dict(res.evidence_level, qualified_time=dict(res.evidence_level["qualified_time"], gap_ms=gap))
                self.assertEqual(V.evidence_level_text(res, "de", self.rules).splitlines()[3],
                                 "  " + t["qualified_time_log"]["de"].format(latest="2026-01-03T00:05:01.000Z", tree_size=15, gap=de))
        lines = self.text(self.mk(receipts=[ev_rc(16, 15)]))
        self.assertFalse(any("qualifiziert bestätigt" in x for x in lines))

    def test_10_10_3_missing_either_line(self):
        """10.9.5, 10.10.3: when neither (4) nor (7) is met, next names both, and the text gives one line "<Bedingung (4)>
        oder <Bedingung (7)>: <Grund von (4)>; <Grund von (7)>" at the place of (4) (registry missing_either); when one of
        them is met, no line names either of them."""
        t, el = self.el["texts"], self.el
        res = self.mk(receipts=[ev_rc(16, 15)])
        for lang in ("de", "en"):
            lines = self.text(res, lang)
            i = lines.index("  " + t["next_all"][lang].format(n=3))
            lab, why = (lambda c: el["conditions"][c][lang]), (lambda c: el["reasons"][c][lang])
            self.assertEqual(lines[i + 1:i + 4], [
                "    " + t["missing_either"][lang].format(condition_4=lab("time_witness_qualified"), condition_7=lab("log_day_qualified"),
                                                          reason_4=why("no_time_anchor"), reason_7=why("vendor_log_not_supplied")),
                "    " + t["missing_item"][lang].format(condition=lab("receipts_logged"), reason=why("vendor_log_not_supplied")),
                "    " + t["missing_item"][lang].format(condition=lab("completeness_from_history"), reason=why("anchor_history_not_supplied"))])
        self.assertEqual(self.text(res)[5], "    - " + el["conditions"]["time_witness_qualified"]["de"] + " oder " + el["conditions"]["log_day_qualified"]["de"]
                         + ": kein Zeitzeuge in der Kette; kein Auszug des Herstellerprotokolls übergeben (--vendor-log)")
        d, R = ev_root("q", {"log", "qualified"})
        res = self.mk(roots=[(d, R)], receipts=[ev_rc(16, 15)], vlog=ev_vlog([(16, 15, "included")], stamps=[("confirmed", ev_assess(paths=(d,), gen="2026-01-03T00:05:01Z"))]))
        lines = self.text(res)
        self.assertEqual(res.evidence_level["next"]["missing"], ["completeness_from_history"])
        self.assertEqual([x for x in lines if x.startswith("    - ")],
                         ["    " + t["missing_item"]["de"].format(condition=el["conditions"]["completeness_from_history"]["de"], reason=el["reasons"]["anchor_history_not_supplied"]["de"])])

    def test_10_10_3_spec_example_valid_basic(self):
        """10.10.3, Beispiel: valid_basic in the audit environment of the corpus gives the block of the evidence level of the
        specification line by line, in German (format.de.md) and English (format.en.md), with (4) and (7) in one line and
        the line on affiliation as its last, indented line."""
        heads = {"de": "Beispiel (Testvektor `valid_basic` in der Prüfumgebung des Korpus):", "en": "Example (test vector `valid_basic` in the audit environment of the corpus):"}
        for lang, fn in (("de", "format.de.md"), ("en", "format.en.md")):
            with self.subTest(lang):
                with open(os.path.join(HERE, "..", "spec", fn), encoding="utf-8") as fh: text = fh.read()
                block = text.split("\n" + heads[lang] + "\n\n```\n", 1)[1].split("\n```", 1)[0].splitlines()
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    try: vmain(["verifier2", os.path.join(VEKTOREN, "valid_basic"), "--lang", lang, "--now-from-package", "--registry", REG_PATH, *vector_anchors()])
                    except SystemExit: pass
                lines = out.getvalue().splitlines()
                i = lines.index(block[0])
                self.assertEqual(lines[i:i + len(block)], block)
                self.assertFalse(lines[i + len(block)].startswith("  "))

    def test_10_10_2_statement_keys_pages(self):
        """10.10.2 anchors.statement_keys: for (2) with the source anchor_history the used pages that carry the recorded
        recording (8.8.5: countersigned or gap_witness) of a found expected root, as it counts for its history root after H7;
        for (6), when met, every used page that enters the completeness of H11, that is every fresh used page of the
        package (8.8.4, "Aeltere Seiten": an older page never enters it); per page its report pair, without repetition, in
        the order of anchor_history.keys (by key_id); for (2) with the source auditor only, none."""
        r, ts = "aa" * 32, EV_SERVER_TS
        A = ev_page("st-1", "pinned", roots=[(15, r, "countersigned", ts)])
        B = ev_page("st-2", "pinned", seed=STMT2_SEED, roots=[(15, r, "reported", ts)])
        C = ev_page("st-3", "pinned", seed=UPD_SEED, roots=[(15, r, "gap_witness", "2026-01-02T23:50:00.000Z")])
        D = ev_page("st-4", "pinned", seed=CS2_SEED, roots=[(14, "bb" * 32, "countersigned", ts)])
        A2 = ev_page("st-1", "pinned", roots=[(15, r, "countersigned", ts), (16, "cc" * 32, "reported", ts)])
        keys = lambda **kw: [k["key_id"] for k in self.ev(self.mk(**kw))["anchors"]["statement_keys"]]
        hist = [(15, r, {"anchor_history"})]
        self.assertEqual(keys(pages=[D, C, B, A, A2], found=hist), ["st-1", "st-3"])
        self.assertEqual(keys(pages=[A, C], found=[(15, r, {"auditor"})]), [])
        # H7: the countersigned recording of A does not count for its history root, the gap witness of C does
        self.assertEqual(keys(pages=[A, C], found=hist, hroots={(15, r): [("gap_witness", "2026-01-02T23:50:00.000Z")]}), ["st-3"])
        est = {"status": "established", "reason": None, "up_to_tree_size": 15}
        self.assertEqual(keys(pages=[D, B, A], completeness=est, hist_found=1), ["st-1", "st-2", "st-4"])
        self.assertEqual(keys(pages=[D, B], found=hist), [])
        # (6) rests on the fresh used pages only: an older page D enters neither (6) nor, without a found root, (2);
        # an older page that carries the recording of a found root still counts for (2)
        Ds = dict(D, use="used_stale")
        As = dict(A, use="used_stale")
        self.assertEqual(keys(pages=[Ds, B], completeness=est, hist_found=1), ["st-2"])
        self.assertEqual(keys(pages=[Ds, As, B], completeness=est, hist_found=1, found=hist), ["st-1", "st-2"])

    def test_10_10_3_anchors_of_completeness(self):
        """10.10.3 <Anker> of (6): as_of and the statements keys of the pages (6) rests on, the fresh used pages of the
        package that enter the completeness (8.8.4 H11), not every pair of anchors.statement_keys: an older page under
        another key that carries the recording of a found root stands in statement_keys for (2), not among the anchors of
        (6)."""
        r, ts = "aa" * 32, EV_SERVER_TS
        A = ev_page("st-1", "pinned", roots=[(15, r, "countersigned", ts)])
        Cs = dict(ev_page("st-3", "pinned", seed=UPD_SEED, roots=[(15, r, "countersigned", ts)]), use="used_stale")
        est = {"status": "established", "reason": None, "up_to_tree_size": 15}
        res = self.mk(pages=[A, Cs], completeness=est, hist_found=1, found=[(15, r, {"anchor_history"})])
        self.assertEqual([k["key_id"] for k in self.ev(res)["anchors"]["statement_keys"]], ["st-1", "st-3"])
        self.assertEqual(res.ev_history_keys, [{"key_id": "st-1", "via": "pinned", "list_version": None, "root_id": None, "root_from": None}])
        for lang in ("de", "en"):
            label = self.el["conditions"]["completeness_from_history"][lang]
            lines = [x for x in V.evidence_level_text(res, lang, self.rules).splitlines() if label in x]
            self.assertEqual(len(lines), 1, lines)
            self.assertIn(self.el["texts"]["anchor_statement_pinned"][lang].format(key_id="st-1"), lines[0])
            self.assertNotIn("st-3", lines[0])

    # ---------------------------------------------------------------- 10.9.3 and the run end to end
    def test_10_9_3_certificates_of_the_package(self):
        """10.9.3, Zertifikate des Pakets: the SPKI SHA-256 value of every certificate in a block CERTIFICATE of a file
        keys/tsa/*.pem that reads after B64 and Z.1; another block, a block that does not read, a block without end and
        another file (other ending, subdirectory) are passed over without a finding."""
        with open(PROBE, encoding="latin-1") as fh: good = fh.read()
        spki = {c.spki_sha256 for c in V.strict_pem(good)}
        bad = "x: y\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n-----BEGIN " + "PRIVATE KEY-----\nAAAA\n-----END " + "PRIVATE KEY-----\n"
        files = {"keys/tsa/a.pem": (bad + good).encode("latin-1"), "keys/tsa/b.crt": good.encode(), "keys/tsa/sub/c.pem": good.encode(),
                 "keys/tsa/d.pem": b"-----BEGIN CERTIFICATE-----\n" + good.split("\n", 2)[1].encode()}
        self.assertEqual(V.package_tsa_spki(files), spki)
        self.assertEqual(V.package_tsa_spki({k: v for k, v in files.items() if k != "keys/tsa/a.pem"}), set())


class EvidenceLevelRun110(Spec19):
    """Format spec 10.9 and 10.10 over runs of verify() and main(): the object in the JSON output at the top level
    (10.10.1), a format error with a report (state format_error), an unusable invocation without one, and the rule that
    the evidence level is formed after the exit code and changes neither it nor a finding (10.3, 10.9, 10.9.7 property 6)."""

    def test_10_9_level_2_from_a_pinned_receipt_and_exit_code_unchanged(self):
        c = Chain(); c.tick(); c.anchor(); c.tick(); c.close()
        code, j, err = self.cli(self.pkg(c), "--json", "--now", iso(c.t + 3))
        ev = j["evidence_level"]
        self.assertEqual((code, ev["state"], ev["level"], ev["entries"]), (0, "rated", 2, len(c.entries)), err)
        self.assertEqual(ev["conditions"]["receipt_key_confirmed"], {"met": True, "count": 2, "up_to_tree_size": c.entries[-2]["payload"]["tree_size"], "reason": None})
        res = V.verify(self.pkg(c), self.reg, at_ms(c.t + 3), 24.0, [], vendor_keys=PIN)
        before = (V.exit_code(res, self.reg["verifier"]["finding_classes"]), json.dumps(res.findings))
        res.evidence_level = V.evidence_level(res, before[0], self.reg["verifier"])
        V.render(res, before[0], self.reg["verifier"]["finding_classes"], "de", "p", self.reg["verifier"])
        self.assertEqual((V.exit_code(res, self.reg["verifier"]["finding_classes"]), json.dumps(res.findings)), before)
        self.assertEqual(condensed(res.evidence_level), condensed(ev))

    def test_10_9_device_key_as_vendor_key(self):
        """10.9.4 (3), key_is_device_key: a receipt under a pinned key equal to GENESIS.device_pubkey holds (no finding) and
        is not credited."""
        c = Chain(); c.tick()
        cp = c.checkpoint(); p = cp["payload"]
        obj = {"chain_id": CHAIN, "tree_size": p["tree_size"], "merkle_root": p["merkle_root"], "server_ts": iso(c.t + 1)}
        c.add("CHECKPOINT_RECEIPT", {"checkpoint_seq": cp["seq"], "tree_size": p["tree_size"], "merkle_root": p["merkle_root"], "server_ts": obj["server_ts"],
                                     "server_key_id": "dev-as-vendor", "server_signature": sign(DEV_SEED, V.jcsb(obj)).hex()}, mono=1000)
        c.seal()
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = vmain(["verifier2", self.pkg(c), "--json", "--now", iso(c.t + 3), "--registry", REG_PATH, "--vendor-key", "dev-as-vendor=" + pubkey(DEV_SEED).hex()])
        j = json.loads(out.getvalue())
        self.assertEqual((code, j["finding_classes"]), (0, []), err.getvalue())
        self.assertEqual((j["evidence_level"]["level"], j["evidence_level"]["conditions"]["receipt_key_confirmed"]["reason"]), (0, "key_is_device_key"))

    def test_10_10_1_exit_3_with_and_without_report(self):
        """10.10.1: a format error writes a report with evidence_level of state format_error and the other objects null;
        an unusable invocation (10.8) writes no report at all."""
        c = Chain("2.0"); c.anchor()
        code, j, _err = self.cli(self.pkg(c), "--json", "--now", iso(c.t + 3))
        self.assertEqual((code, j["evidence_level"]["state"], j["evidence_level"]["affiliation"], j["key_roles"], j["affiliation"]), (3, "format_error", None, None, None))
        code, text, _err = self.cli(self.pkg(c), "--lang", "de", "--now", iso(c.t + 3))
        self.assertIn("Beweisstufe: nicht bestimmt (Formatfehler)", text.splitlines())
        self.assertFalse(any(x.startswith("  Verbundenheit") for x in text.splitlines()))
        code, out, err = self.cli(self.pkg(Chain().close()), "--json", "--now", "2026-01-01 00:00:00Z")
        self.assertEqual((code, out), (3, ""), err)

    def test_10_10_3_block_order(self):
        """10.10.3: the summary lines, the block of the vendor log, the block of the anchor history, the block of the
        evidence level whose last line is the line on affiliation, then the findings."""
        c = Chain(); c.tick(); c.anchor()
        code, text, _err = self.cli(self.pkg(c), "--lang", "de", "--now", iso(c.t + 3))
        lines = text.splitlines()
        vl = lines.index(self.reg["vendor_log"]["texts"]["not_supplied"]["de"])
        ah = lines.index(self.reg["verifier"]["anchor_history"]["texts"]["not_supplied"]["de"].format(chain_id=CHAIN))
        ev = next(i for i, x in enumerate(lines) if x.startswith("Beweisstufe: "))
        af = next(i for i, x in enumerate(lines) if x.startswith("  Verbundenheit mit dem Hersteller: "))
        fi = lines.index("[UNSEALED_END] Exit 4: " + self.reg["verifier"]["finding_classes"]["UNSEALED_END"]["de"])
        self.assertEqual((code, vl + 1, ah + 1, ev < af, af + 2), (4, ah, ev, True, fi))


class VectorsEvidence110(unittest.TestCase):
    """Every vector with the corpus environment and, where its expected file names one, with its own
    ledger-pruefumgebung/1 (10.8): exit code and finding classes, and where the expected file carries evidence_level or
    auditor_inputs.evidence_level every member of it (registry expected_files.evidence_level; null for an unusable
    invocation, 10.9.2, 10.10.1); on every run with a report the object evidence_level against its generated schema and
    properties 1 to 5 of 10.9.7; the monotonicity of 10.9.7 between both environments of a vector whose environment
    contains the corpus's; the neutrality of 10.9.7; and the values the rows of README 13 name."""

    # README 13 and 14.3: conditions with (count, reach) of the vector's run, segments with basis, next, expected root
    # sources, qualified_time (qt)
    LDQ = ["receipts_logged", "log_day_qualified"]
    BOTH = {"level": 3, "need": "all", "missing": ["time_witness_qualified", "log_day_qualified"]}
    ROWS = {"evidence_level_3": {"reach": {"time_witness": 5, "expected_root_found": 11, "receipt_key_confirmed": 11, "time_witness_qualified": 5,
                                           "receipts_logged": 5, "completeness_from_history": 11, "log_day_qualified": 5},
                                 "basis": [["time_witness_qualified", "receipts_logged", "log_day_qualified"], ["receipt_key_confirmed"], []], "next": None,
                                 "qt": {"via": "time_witness_qualified", "tree_size": 5, "latest": "2026-01-02T23:55:01.000Z", "gap_ms": None}},
            "evidence_level_3_log_day_qualified": {"reach": {"log_day_qualified": 5, "receipts_logged": 5, "receipt_key_confirmed": 10},
                                                   "basis": [LDQ, ["receipt_key_confirmed"], []], "next": None,
                                                   "qt": {"via": "log_day_qualified", "tree_size": 5, "latest": "2026-01-03T00:05:01.000Z", "gap_ms": 600000}},
            "evidence_level_3_both_ways": {"reach": {"time_witness": 1, "time_witness_qualified": 1, "receipts_logged": 6, "log_day_qualified": 6,
                                                     "expected_root_found": 11, "receipt_key_confirmed": 11, "completeness_from_history": 11},
                                           "basis": [LDQ, ["receipt_key_confirmed"], []], "next": None,
                                           "qt": {"via": "log_day_qualified", "tree_size": 6, "latest": "2026-01-03T00:05:01.000Z", "gap_ms": 600000}},
            "evidence_qualified_time_tie": {"reach": {"time_witness_qualified": 10, "log_day_qualified": 5}, "basis": [LDQ, ["receipt_key_confirmed"], []],
                                            "qt": {"via": "time_witness_qualified", "tree_size": 10, "latest": "2026-01-03T00:05:01.000Z", "gap_ms": None}},
            "evidence_log_stamp_gap_exact": {"basis": [LDQ, ["receipt_key_confirmed"], []],
                                             "qt": {"via": "log_day_qualified", "tree_size": 5, "latest": "2026-01-04T11:55:01.000Z", "gap_ms": 129600000}},
            "evidence_log_stamp_gap_exceeded": {"reach": {"receipts_logged": 5}, "next": BOTH, "qt": None},
            "evidence_log_stamp_gap_truncated": {"qt": {"via": "log_day_qualified", "tree_size": 5, "latest": "2026-01-04T11:55:01.000Z", "gap_ms": 129600000}},
            "evidence_qualified_log_root_log_only": {"reach": {"receipts_logged": 5}, "next": BOTH, "qt": None},
            "evidence_qualified_log_root_qualified_only": {"next": {"level": 3, "need": "all", "missing": ["time_witness_qualified", "receipts_logged", "log_day_qualified"]}},
            "evidence_qualified_root_in_package": {"basis": [LDQ, ["receipt_key_confirmed"], []], "next": None},
            "evidence_level_3_four_segments": {"reach": {"expected_root_found": 13, "completeness_from_history": 11},
                                               "sources": ["auditor", "anchor_history"], "basis": [None, None, ["expected_root_found"], []]},
            "evidence_level_2_without_log": {"next": {"level": 3, "need": "all", "missing": ["receipts_logged"]}},
            "evidence_qualified_window_from": {"next": None, "basis": [LDQ, ["receipt_key_confirmed"], []],
                                               "qt": {"via": "log_day_qualified", "tree_size": 5, "latest": "2026-01-03T00:05:01.000Z", "gap_ms": 600000}},
            "evidence_witness_certificate_not_bound": {"reach": {"time_witness": 20}},
            "evidence_witness_statement_malformed": {"reach": {"time_witness": 23}},
            "evidence_level_1_time_witness": {"reach": {"time_witness": 20}, "basis": [["time_witness"], []],
                                              "next": {"level": 2, "need": "all", "missing": ["receipt_key_confirmed"]}},
            "evidence_level_1_auditor_root": {"reach": {"expected_root_found": 20}, "sources": ["auditor"], "basis": [["expected_root_found"], []]},
            "evidence_last_receipt_unconfirmed": {"reach": {"receipt_key_confirmed": 28}},
            "evidence_package_not_fully_known": {"reach": {"expected_root_found": 28, "completeness_from_history": 28}}}
    CORPUS_ROWS = {"evidence_level_1_time_witness": {"next": {"level": 1, "need": "any", "missing": ["time_witness", "expected_root_found", "receipt_key_confirmed"]}},
                   "evidence_level_0_no_receipt": {"next": {"level": 1, "need": "any", "missing": ["time_witness", "expected_root_found", "receipt_key_confirmed"]}},
                   "evidence_last_receipt_unconfirmed": {"reach": {"receipt_key_confirmed": 15}}}

    @staticmethod
    def run_vector(pkg, args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try: code = vmain(["verifier2", pkg, "--json", "--now-from-package", "--registry", REG_PATH, *args])
            except SystemExit as e: code = e.code
        return code, json.loads(out.getvalue()) if out.getvalue() else None, err.getvalue()

    def properties(self, code, j, el):
        """10.9.7 properties 1 to 5 on one run with a report."""
        ev = j["evidence_level"]
        self.assertEqual(ev["state"] == "format_error", code == 3)                                           # 5
        if ev["state"] != "rated": return
        if "NO_ANCHOR" in j["finding_classes"]: self.assertEqual(ev["level"], 0)                             # 1
        if ev["level"] >= 1: self.assertNotIn("NO_ANCHOR", j["finding_classes"])
        if ev["level"] >= 2: self.assertTrue(ev["conditions"]["receipt_key_confirmed"]["met"] and ev["anchors"]["vendor_keys"])   # 2
        if ev["level"] == 3: self.assertEqual(j["anchor_history"]["completeness"]["status"], "established")  # 3
        qt = ev["qualified_time"]                                                                            # 10.10.2
        self.assertEqual(qt is not None, ev["level"] == 3)
        if qt is not None:
            self.assertTrue(qt["tree_size"] >= ev["up_to_tree_size"] and ev["conditions"][qt["via"]]["met"], qt)
            self.assertEqual(qt["gap_ms"] is None, qt["via"] == "time_witness_qualified")
            if qt["gap_ms"] is not None: self.assertTrue(0 <= qt["gap_ms"] <= el["conditions"]["log_day_qualified"]["gap_max_ms"], qt)
        g = ev["segments"]                                                                                   # 4
        self.assertEqual((g[0]["first_seq"], g[-1]["last_seq"], g[0]["level"]), (1, ev["entries"], ev["level"]))
        for a, b in zip(g, g[1:]): self.assertEqual((b["first_seq"], a["level"] > b["level"]), (a["last_seq"] + 1, True))

    def reaches(self, ev, el):
        return V.ev_level(ev["conditions"], ev["entries"], el)[4]

    def breaks_monotonicity(self, corpus, vec, reg):
        """The exceptions of 10.9.7 (Monotonie), read conservatively: what the run with the vector's inputs has and the run
        of the corpus has not."""
        el = reg["verifier"]["evidence_level"]
        if vec["evidence_level"]["state"] == "chain_invalid": return True
        new = set(vec["finding_classes"]) - set(corpus["finding_classes"])
        if new & set(el["monotonicity_breakers"]) or new & {"RECEIPT_UNVERIFIED", "VENDOR_LOG_UNVERIFIED"}: return True
        kr = vec["key_roles"]
        if kr["pins_dropped"] or kr["status"] == "not_effective" and kr["reason"] in el["monotonicity_breakers_key_roles"]["status_not_effective_reasons"]: return True
        why = set(vec["anchor_history"]["reasons"]["unverified"])
        return "ANCHOR_HISTORY_UNVERIFIED" in new and bool(why & {"key_not_valid", "signing_time_not_proven", "key_not_established", "key_other_role"})

    def test_10_9_every_vector_both_environments(self):
        reg = file_registry()
        el = reg["verifier"]["evidence_level"]
        with open(os.path.join(VEKTOREN, "..", "schemas", "report_evidence_level.schema.json"), encoding="utf-8") as fh: schema = json.load(fh)
        names = sorted(f[:-5] for f in os.listdir(os.path.join(VEKTOREN, "expected")) if f.endswith(".json"))
        self.assertEqual(sorted(n for g, xs in reg["testvectors"].items() if g != "comment" for n in xs), names)
        self.assertLessEqual(set(self.ROWS) | set(self.CORPUS_ROWS), set(names))
        with_level = 0
        for name in names:
            with open(os.path.join(VEKTOREN, "expected", name + ".json"), encoding="utf-8") as fh: exp = json.load(fh)
            pkg = os.path.join(VEKTOREN, name)
            envs = [("corpus", vector_anchors(), exp)]
            if exp.get("auditor_inputs"): envs.append(("vector", V.pruefumgebung(os.path.join(VEKTOREN, exp["auditor_inputs"]["file"]), reg), exp["auditor_inputs"]))
            runs = {}
            for env, args, want in envs:
                with self.subTest(name=name, env=env):
                    code, j, err = self.run_vector(pkg, args)
                    runs[env] = j
                    self.assertEqual((code, sorted(j["finding_classes"]) if j else []), (want["exit_code"], sorted(set(want["finding_classes"]))), err)
                    if j is None:                                       # an unusable invocation: no report, no evidence level (10.8, 10.10.1)
                        self.assertEqual((code, want.get("evidence_level", None)), (3, None))
                        continue
                    self.assertEqual(schema_ok(j["evidence_level"], schema), "")
                    self.properties(code, j, el)
                    if "evidence_level" in want:
                        with_level += 1
                        self.assertEqual(condensed(j["evidence_level"]), want["evidence_level"])
                    row = (self.ROWS if env == "vector" else self.CORPUS_ROWS).get(name, {})
                    ev = j["evidence_level"]
                    for c, t in row.get("reach", {}).items(): self.assertEqual(ev["conditions"][c]["up_to_tree_size"], t, c)
                    if "sources" in row: self.assertEqual(ev["anchors"]["expected_root_sources"], row["sources"])
                    if "next" in row: self.assertEqual(ev["next"], row["next"])
                    if "qt" in row: self.assertEqual(ev["qualified_time"], row["qt"])
                    for g, b in zip(ev["segments"], row.get("basis", ())):
                        if b is not None: self.assertEqual(g["basis"], b)
            c, v = runs.get("corpus"), runs.get("vector")
            if c and v and c["evidence_level"]["state"] == "rated" and v["evidence_level"]["state"] != "format_error":
                with open(os.path.join(VEKTOREN, exp["auditor_inputs"]["file"]), encoding="utf-8") as fh: korpus = json.load(fh)["korpus"]
                if korpus and not self.breaks_monotonicity(c, v, reg):
                    with self.subTest(name=name, check="monotonicity"):
                        rc, rv = self.reaches(c["evidence_level"], el), self.reaches(v["evidence_level"], el)
                        self.assertTrue(all(b >= a for a, b in zip(rc, rv)), (rc, rv))
        self.assertGreater(with_level, 0)

    def test_10_9_7_neutrality(self):
        """10.9.7, Neutralitaet: the same package with the affiliation affiliated and not_affiliated gives the same level,
        up_to_tree_size and segments (evidence_level_3 and evidence_level_3_affiliated, README 13)."""
        reg = file_registry()
        got = {}
        for name in ("evidence_level_3", "evidence_level_3_affiliated"):
            code, j, err = self.run_vector(os.path.join(VEKTOREN, name), V.pruefumgebung(os.path.join(VEKTOREN, "pruefer_%s.json" % name), reg))
            ev = j["evidence_level"]
            got[name] = (ev["affiliation"]["status"], ev["level"], ev["up_to_tree_size"], ev["segments"])
        self.assertEqual((got["evidence_level_3"][0], got["evidence_level_3_affiliated"][0]), ("not_affiliated", "affiliated"))
        self.assertEqual(got["evidence_level_3"][1:], got["evidence_level_3_affiliated"][1:])


class Decisions2610(unittest.TestCase):
    """The decisions of 26.10. outside the evidence level: the data class access_chain of DATA_ACCESS (format spec 4.25)
    and the 24 months of former_relation (heartbeat spec 9.10), which the verifier reads from a page and never computes."""

    def run_vector(self, name, env):
        reg = file_registry()
        with open(os.path.join(VEKTOREN, "expected", name + ".json"), encoding="utf-8") as fh: exp = json.load(fh)
        args = vector_anchors() if env == "corpus" else V.pruefumgebung(os.path.join(VEKTOREN, exp["auditor_inputs"]["file"]), reg)
        out = {}
        for mode in ("--json", "de", "en"):
            o, e = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
                try: code = vmain(["verifier2", os.path.join(VEKTOREN, name), *(["--json"] if mode == "--json" else ["--lang", mode]),
                                    "--now-from-package", "--registry", REG_PATH, *args])
                except SystemExit as x: code = x.code
            out[mode] = (code, o.getvalue())
        return out

    def test_4_25_data_access_class_access_chain(self):
        """4.25: data_class access_chain (the access chain itself, read for example by an audit) is a value of the
        enumeration in the registry the verifier reads; another value is a format error of the payload. The vector
        valid_data_access_access_chain gives exit 0 without a finding and level 2 up to 30; the evidence level does not
        read DATA_ACCESS."""
        reg = file_registry()
        spec = reg["event_types"]["DATA_ACCESS"]["payload"]
        self.assertIn("access_chain", spec["data_class"]["values"])
        with open(os.path.join(VEKTOREN, "valid_data_access_access_chain", "segments", "chain-000001.jsonl"), encoding="utf-8") as fh:
            entries = [json.loads(x) for x in fh if x.strip()]
        da = [e["payload"] for e in entries if e["event_type"] == "DATA_ACCESS"]
        self.assertEqual([p["data_class"] for p in da], ["credentials", "access_chain"])
        for p, want in ((da[1], []), (dict(da[1], data_class="access_chains"), ["$.payload.data_class: 'access_chains' is not in the enumeration"])):
            errs = []
            V._fields(p, spec, reg, "$.payload", errs, V.Result())
            self.assertEqual(errs, want)
        (code, j), _de, _en = self.run_vector("valid_data_access_access_chain", "corpus").values()
        j = json.loads(j)
        self.assertEqual((code, j["finding_classes"], j["evidence_level"]["level"], j["evidence_level"]["up_to_tree_size"]), (0, [], 2, 30))

    def test_heartbeat_9_10_former_relation_24_months(self):
        """Heartbeat spec 9.10: former_relation lasts 24 months after the end of a relation (the same day and time two
        calendar years later; 29 February goes to 1 March, 00:00:00.000Z). The registry carries the months, no constant in
        milliseconds or days, and the texts say 24 months; the verifier reads until of the page and computes no end, so
        history_affiliated_former_relation_leap_day is affiliated up to 2026-03-01T00:00:00.000Z (an end after 730 days
        would lie before the package) and history_not_affiliated_period_before_24_months not affiliated."""
        reg = file_registry()
        af = reg["verifier"]["affiliation"]
        self.assertEqual(af["bases"]["former_relation_months"], 24)
        self.assertNotIn("former_relation_ms", af["bases"])
        self.assertIn("24 Monate", af["bases"]["codes"]["former_relation"]["de"])
        self.assertIn("24 months", af["bases"]["codes"]["former_relation"]["en"])
        with open(V2_PATH, encoding="utf-8") as fh: src = fh.read()
        for const in ("63072000000", "63 072 000 000", "730"):
            self.assertNotIn(const, src)
        r = self.run_vector("history_affiliated_former_relation_leap_day", "vector")
        code, j = r["--json"][0], json.loads(r["--json"][1])
        a = j["affiliation"]
        self.assertEqual((code, a["status"], a["bases"], a["receipts_in_periods"], a["receipts_total"]), (0, "affiliated", ["former_relation"], 2, 2))
        self.assertEqual([(p["from"], p["until"]) for p in a["periods"]], [("2025-06-01T00:00:00.000Z", "2026-03-01T00:00:00.000Z")])
        self.assertIn(af["bases"]["codes"]["former_relation"]["de"], r["de"][1])
        self.assertIn(af["bases"]["codes"]["former_relation"]["en"], r["en"][1])
        j = json.loads(self.run_vector("history_not_affiliated_period_before_24_months", "vector")["--json"][1])
        a = j["affiliation"]
        self.assertEqual((a["status"], [(p["until"], p["overlaps_package"]) for p in a["periods"]]), ("not_affiliated", [("2025-12-01T00:00:00.000Z", False)]))


class Aufruf110(unittest.TestCase):
    """The command line of verifier 1.1.0: both reference verifiers read every command line alike (release/verifier/check_cli_gleich.py
    runs ledger-verify and verifier2 over the same command lines; verifier/internal/cli/aufruf_test.go holds the same
    cases for ledger-verify). Every switch stands before the package and is written with two dashes, "--" ends them; a
    switch without a value takes none; --version stands alone; -h and --help print the help on the error output with
    exit 3; --freshness DUR (10.8) replaces --freshness-hours; the report language defaults to en. Any other form is an
    unusable invocation: exit 3, nothing on the standard output, the reason on the error output (10.8)."""

    PKG = os.path.join(VEKTOREN, "valid_sealed_shutdown")      # exit 0 in the audit environment of the corpus
    NOW = "2026-01-01T03:01:00.500Z"                            # 7 200 000 ms after its last entry (01:01:00.500Z)

    def lauf(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try: code = V.main(["verifier2", *argv])
            except SystemExit as e: code = e.code
        return code, out.getvalue(), err.getvalue()

    def unusable(self, *argv, prefix="verifier2: "):
        code, out, err = self.lauf(*argv)
        self.assertEqual((code, out), (3, ""), (argv, err))
        self.assertTrue(err.startswith(prefix), (argv, err))
        return err

    def base(self):
        return ["--now", self.NOW, *vector_anchors()]

    def test_switch_after_the_package_is_refused(self):
        p = self.PKG
        for after in (["--json"], ["--lang", "de"], ["--", "--json"], [p], ["--help"], ["--version"], ["--bogus"]):
            with self.subTest(after=after):
                err = self.unusable(*self.base(), p, *after)
                self.assertIn("every switch stands before the package", err)
        code, out, err = self.lauf(*self.base(), "--", p)                          # "--" ends the switches
        self.assertEqual((code, err), (0, ""), err)
        code, out, err = self.lauf("--json", "--", "--json")                       # after "--" even "--json" is the package
        self.assertEqual((code, json.loads(out)["finding_classes"]), (3, ["FORMAT_ERROR"]), err)

    def test_help_is_exit_3_on_the_error_output(self):
        for argv in (["--help"], ["-h"], ["--help", self.PKG], ["zeitstempel", "--help"], ["zeitstempel", "-h"]):
            with self.subTest(argv=argv):
                code, out, err = self.lauf(*argv)
                self.assertEqual((code, out), (3, ""), err)
                self.assertIn("usage: verifier2", err)
        code, out, err = self.lauf("--help")
        self.assertIn("--registry FILE", err)
        self.assertIn("no auditor input", err)
        self.assertIn("two dashes", self.unusable("-help"))                       # a single dash, refused as such (ledger-verify too)

    def test_version_stands_alone(self):
        code, out, err = self.lauf("--version")
        self.assertEqual((code, out, err), (0, f"verifier2 {V.VERSION} (spec {file_registry()['spec_version']}) \u00b7 LEDGER\n", ""))
        self.assertEqual(V.VERSION, "1.1.0")
        for argv in (["--version", "--json"], ["--lang", "xx", "--version"], ["--lang", "de", "--version"], ["--version", "--bogus"],
                     ["--bogus", "--version"], ["--version", self.PKG], [self.PKG, "--version"], ["--version=1"], ["-version"]):
            with self.subTest(argv=argv): self.unusable(*argv)
        self.unusable("zeitstempel", "--version", prefix="verifier2 zeitstempel: ")

    def test_spellings_outside_the_documented_one_are_refused(self):
        for sw in (["-json"], ["-lang", "de"], ["-now", self.NOW], ["--json=true"], ["--json=false"], ["--json=1"], ["--now-from-package=true"],
                   ["--JSON"], ["---json"], ["--js"], ["-j"], ["--format", "json"], ["--freshness-hours", "24"], ["-help"], ["--help=1"]):
            with self.subTest(sw=sw): self.unusable(*sw, *self.base(), self.PKG)
        for sw in (["--json", "--json"], ["--now-from-package", "--now-from-package"], ["--lang=de"], ["--now=" + self.NOW]):
            with self.subTest(sw=sw):
                code, out, err = self.lauf(*sw, *vector_anchors(), "--now", self.NOW, self.PKG) if not sw[0].startswith("--now=") else \
                                 self.lauf(*sw, *vector_anchors(), self.PKG)
                self.assertEqual((code, err), (0, ""), (sw, err))

    def test_freshness_grammar_and_window(self):
        """--freshness DUR (8.5, 10.8): 1 to 999999 without a leading zero, then h, m or s; at most once. The window is
        compared in whole milliseconds: an age of exactly the window is no TRAILING_SILENCE, a window one second shorter
        gives it. The finding names the window exactly: "24.0 h" for the default, as up to 1.0, "7199 s" for 7199s."""
        for good, exit_ in (("2h", 0), ("120m", 0), ("7200s", 0), ("7199s", 1), ("1h", 1), ("999999h", 0), ("24h", 0), ("1s", 1)):
            with self.subTest(good=good):
                code, out, err = self.lauf("--json", "--freshness", good, *self.base(), self.PKG)
                self.assertEqual((code, json.loads(out)["finding_classes"]), (exit_, ["TRAILING_SILENCE"] if exit_ else []), err)
        for bad in ("0", "0h", "01h", "-1h", "+1h", "1.5h", "1h30m", "24", " 24h", "24h ", "24H", "1d", "1000000h", "nan", "inf",
                    "1_0h", "\u0661h", "", "1e3s", "0x10h"):
            with self.subTest(bad=bad):
                err = self.unusable("--freshness", bad, *self.base(), self.PKG)
        self.unusable("--freshness", "1h", "--freshness", "1h", *self.base(), self.PKG)
        fw = file_registry()["auditor_inputs"]["freshness_window"]                 # the grammar as the registry states it
        self.assertEqual(("^" + V.FRESHNESS.pattern.replace("(", "").replace(")", "") + "$", V.FRESHNESS_UNIT_MS, fw["flag"], fw["max_count"], fw["default"]),
                         (fw["pattern"], fw["unit_ms"], "--freshness", 1, "24h"))
        self.assertEqual(V.freshness_ms(fw["default"]), V.DEFAULT_FRESHNESS_H * 3600000)
        for given, shown in (("7199s", "freshness window 7199 s"), ("1h", "freshness window 1.0 h"), ("119m", "freshness window 7140 s")):
            code, out, err = self.lauf("--json", "--freshness", given, *self.base(), self.PKG)
            self.assertTrue(json.loads(out)["findings"][0]["detail"].endswith(shown), (given, out))
        code, out, err = self.lauf("--json", "--now", "2026-01-02T03:01:00.500Z", *vector_anchors(), self.PKG)
        self.assertTrue(json.loads(out)["findings"][0]["detail"].endswith("freshness window 24.0 h"), out)

    def test_report_language_defaults_to_en(self):
        code, out, err = self.lauf(*self.base(), self.PKG)
        self.assertEqual(out.splitlines()[1:3][0], "exit 0: " + file_registry()["verifier"]["exit_codes"]["0"]["en"], out)
        code, out, err = self.lauf("--lang", "de", *self.base(), self.PKG)
        self.assertEqual(out.splitlines()[1], "Exit 0: " + file_registry()["verifier"]["exit_codes"]["0"]["de"], out)

    def test_unopenable_package_report(self):
        """A package that cannot be opened: exit 3 with a report (FORMAT_ERROR), no check-time line and no missing text
        (ledger-verify prints none either, 10.10.3)."""
        exits = file_registry()["verifier"]["exit_codes"]
        for lang, head, end in (("de", "Exit", "Kettenende: nicht bewertet"), ("en", "exit", "chain end: not judged")):
            code, out, err = self.lauf("--lang", lang, *self.base(), os.path.join(VEKTOREN, "does-not-exist"))
            self.assertEqual(code, 3, err)
            self.assertEqual(out.splitlines()[1:3], [f"{head} 3: " + exits["3"][lang], end])
            self.assertIn("[FORMAT_ERROR]", out)
            self.assertNotIn("MISSING", out + err)

    def test_registry_is_the_one_switch_of_verifier2_alone(self):
        code, out, err = self.lauf("--registry", REG_PATH, *self.base(), self.PKG)
        self.assertEqual((code, err), (0, ""), err)
        self.unusable("--registry", REG_PATH, "--registry", REG_PATH, *self.base(), self.PKG)

    def test_arguments_around_the_switches(self):
        """read_command_line, as ledger-verify reads the command line: a "--" after the package is a second argument; the
        value of a switch is the next argument also when it begins with a dash; a package named "-1" or "-x y" is a
        single-dash switch unless "--" stands before it; in zeitstempel a final "--" ends the switches and nothing may
        follow it. Up to the first 1.1.0 draft argparse decided: it judged "<package> --", "-1" and "-x y" and refused
        "--tsa-root -roots.pem" ("expected one argument"), each time where ledger-verify did the opposite."""
        p = os.path.abspath(self.PKG)
        base = [os.path.abspath(a) if a.startswith(VEKTOREN) else a for a in self.base()]
        for argv in ([*base, p, "--"], ["--json", *base, p, "--"], [*base, "--", p, "--"]):
            with self.subTest(argv=argv[-2:]): self.assertIn("every switch stands before the package", self.unusable(*argv))
        with open(os.path.join(VEKTOREN, "zeitstempel_timestamp_ess_both.wurzel.pem"), "rb") as fh: pem = fh.read()
        with open(os.path.join(VEKTOREN, "pruefer_herstellerwurzel.json"), "rb") as fh: root = fh.read()
        zs = ["zeitstempel", "--token", os.path.join(VEKTOREN, "zeitstempel_timestamp_ess_both.token.der"),
              "--data", os.path.join(VEKTOREN, "zeitstempel_timestamp_ess_both.daten.json"), "--purpose", "chain"]
        zs = [os.path.abspath(a) if a.startswith(VEKTOREN) else a for a in zs]
        here, tmp = os.getcwd(), tempfile.mkdtemp(prefix="v2-aufruf-")
        try:
            os.chdir(tmp)
            for name, data in (("-roots.pem", pem), ("--", pem), ("-root.json", root)):
                with open(name, "wb") as fh: fh.write(data)
            for name in ("-1", "-x y"): os.symlink(p, name)
            for argv in (["--tsa-root", "-roots.pem", *base, p], ["--tsa-root", "--", *base, p], ["--vendor-root", "-root.json", *base, p],
                         ["--vendor-statement-key", "-=" + "ab" * 32, *base, p], [*base, "--", "-1"], [*base, "--", "-x y"]):
                with self.subTest(argv=argv[:2]):
                    code, out, err = self.lauf(*argv)
                    self.assertEqual((code, err), (0, ""), err)
            for name in ("-1", "-x y"):
                with self.subTest(package=name): self.unusable(*base, name)
            with_end = self.lauf(*zs, "--tsa-root", "-roots.pem", "--")
            self.assertEqual(self.lauf(*zs, "--tsa-root", "-roots.pem"), with_end)
            self.assertNotEqual(with_end[0], 3, with_end)
            self.unusable(*zs, "--", "x", prefix="verifier2 zeitstempel: ")
        finally:
            os.chdir(here)
            shutil.rmtree(tmp, ignore_errors=True)

    def test_zero_time_is_a_check_time(self):
        """--now 0001-01-01T00:00:00Z is grammatical (10.8) and is honoured, as by ledger-verify since it stopped reading
        Go's zero time as "not given"; --requested-at after it is unusable."""
        code, out, err = self.lauf("--json", "--now", "0001-01-01T00:00:00Z", *vector_anchors(), self.PKG)
        self.assertEqual((code, json.loads(out)["now_source"], json.loads(out)["finding_classes"]), (0, "flag", []), err)
        self.assertIn("after the check time", self.unusable("--now", "0001-01-01T00:00:00Z", "--requested-at", "2025-01-01T00:00:00Z",
                                                            *vector_anchors(), self.PKG))

    def test_files_are_read_up_to_their_bound(self):
        """Every auditor file is read up to its limit plus one byte, /dev/zero included; a file without a limit in 10.8 up to
        UNBOUNDED_INPUT_BYTES, the bound ledger-verify has (MaxDateiOhneGrenze)."""
        if not os.path.exists("/dev/zero"): self.skipTest("no /dev/zero")
        for sw in ("--vendor-key-list", "--tsa-qualified-roots", "--vendor-log", "--anchor-history", "--tsa-root", "--vendor-log-tsa-root", "--vendor-root"):
            with self.subTest(sw=sw): self.assertIn("more than", self.unusable(sw, "/dev/zero", *self.base(), self.PKG))
        self.unusable("zeitstempel", "--token", "/dev/zero", "--data", os.path.join(VEKTOREN, "zeitstempel_timestamp_ess_both.daten.json"),
                      prefix="verifier2 zeitstempel: ")
        self.assertEqual(V.UNBOUNDED_INPUT_BYTES, 33554432)
        with tempfile.NamedTemporaryFile(suffix=".pem") as fh:
            fh.truncate(V.UNBOUNDED_INPUT_BYTES + 1); fh.flush()
            self.assertIn("more than 33554432 bytes", self.unusable("--tsa-root", fh.name, *self.base(), self.PKG))

    def test_output_that_cannot_be_written_is_exit_3(self):
        """A full disk or a broken pipe on the standard output: exit 3 with the reason, as ledger-verify; up to the first 1.1.0
        draft the interpreter left with exit 1 ("valid with findings") and a traceback."""
        class Broken(io.RawIOBase):                                              # full once, so that the final flush stays quiet
            failed = False
            def writable(self): return True
            def write(self, b):
                if not self.failed:
                    self.failed = True
                    raise OSError(28, "No space left on device")
                return len(b)
        for argv in ([*self.base(), self.PKG], ["--json", *self.base(), self.PKG], ["--version"],
                     ["zeitstempel", "--token", os.path.join(VEKTOREN, "zeitstempel_timestamp_ess_both.token.der"),
                      "--data", os.path.join(VEKTOREN, "zeitstempel_timestamp_ess_both.daten.json")]):
            with self.subTest(argv=argv[:1]):
                out, err = io.TextIOWrapper(io.BufferedWriter(Broken()), encoding="utf-8"), io.StringIO()
                saved = sys.stdout
                try:
                    sys.stdout = out
                    with contextlib.redirect_stderr(err): code = V.main(["verifier2", *argv])
                finally: sys.stdout = saved
                self.assertEqual(code, 3, err.getvalue())
                self.assertIn("cannot write the output", err.getvalue())

    def test_output_bytes_as_ledger_verify_writes_them(self):
        """The output is UTF-8 whatever the locale (--version with an ASCII standard output gave a traceback and exit 1); a
        package path that is not UTF-8 stands in the text report as its bytes and in the JSON output as U+FFFD, so the JSON
        stays UTF-8 (it held a raw 0xFF), and a strict UTF-8 locale no longer ends the run with exit 1."""
        import subprocess
        env = dict(os.environ, PYTHONIOENCODING="ascii")
        r = subprocess.run([sys.executable, "-B", V2_PATH, "--version"], capture_output=True, env=env)
        self.assertEqual((r.returncode, r.stdout), (0, f"verifier2 {V.VERSION} (spec {file_registry()['spec_version']}) · LEDGER\n".encode()), r.stderr)
        tmp = tempfile.mkdtemp(prefix="v2-bytes-")
        try:
            link = os.path.join(os.fsencode(tmp), b"pkg\xff")
            os.symlink(os.path.abspath(self.PKG), link)
            for loc in ("C", "C.UTF-8"):
                env = dict(os.environ, LC_ALL=loc, PYTHONIOENCODING="utf-8:strict")
                argv = [os.fsencode(sys.executable), b"-B", os.fsencode(V2_PATH), b"--now", self.NOW.encode()] + [os.fsencode(a) for a in vector_anchors()]
                r = subprocess.run(argv + [link], capture_output=True, env=env)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn(b"pkg\xff\n", r.stdout)
                r = subprocess.run(argv[:3] + [b"--json"] + argv[3:] + [link], capture_output=True, env=env)
                self.assertEqual((r.returncode, json.loads(r.stdout.decode("utf-8"))["package"][-4:]), (0, "pkg\ufffd"), r.stderr)
        finally: shutil.rmtree(tmp, ignore_errors=True)
        self.assertEqual(V._valid_utf8(b"a\xe2\x82b\xffc\xc3\xa4"), "a\ufffd\ufffdb\ufffdc\u00e4")      # one U+FFFD per byte, as Go

    def test_paket_zuletzt_helper(self):
        """The helper of this file moves the package behind the switches; it touches zeitstempel and switch-first calls not."""
        self.assertEqual(paket_zuletzt(["verifier2", "p", "--json"]), ["verifier2", "--json", "p"])
        self.assertEqual(paket_zuletzt(["verifier2", "--json", "p"]), ["verifier2", "--json", "p"])
        self.assertEqual(paket_zuletzt(["verifier2", "zeitstempel", "--json"]), ["verifier2", "zeitstempel", "--json"])

# The guard stands at the very end: unittest.main() ends the process, so a class defined after it
# never runs in script mode (python3 verifier2_test.py - how CI and the red proofs call this file).
# Until 28.09. that was the fate of Klarstellung: five tests, run only by "python3 -m unittest".
if __name__ == "__main__":
    print(f"verifier2 under test: {V2_PATH}\nregistry: {REG_PATH} (own spec_version {OWN})", file=sys.stderr)
    unittest.main(verbosity=2)
