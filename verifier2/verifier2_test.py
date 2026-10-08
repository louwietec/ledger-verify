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

Die Ketten werden synthetisch gebaut (Ed25519-Signierung nur hier, wie in
artefakte/P04/keyrotation_test.py); die Registry wird geladen und im Speicher auf
den Vertrag B gebracht (idempotent), die echte Datei bleibt unberuehrt.
The chains are built synthetically; the registry is loaded and brought to
contract B in memory (idempotent) - the real file is never touched.

Umgebung / environment:
  VERIFIER2_PY  Pfad zur zu pruefenden verifier2.py (Rot-Beweis gegen den alten Stand)
  REGISTRY      Pfad zur Registry (Standard: ../spec/registry.json)
"""

import contextlib, datetime, hashlib, hmac, importlib.util, io, json, os, shutil, sys, tempfile, unittest, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
V2_PATH = os.environ.get("VERIFIER2_PY", os.path.join(HERE, "verifier2.py"))
REG_PATH = os.environ.get("REGISTRY", os.path.join(HERE, "..", "spec", "registry.json"))
_spec = importlib.util.spec_from_file_location("verifier2_under_test", V2_PATH)
V = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(V)

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
# version — six forward-compatibility tests went red at once, because the
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
    """The registry exactly as it is on disk — no in-memory contract. The S1b tests run against THIS, so they
    are red when spec/registry.json lacks CONTENT_DISCLOSED (verifier2.py has no S1b code: it reads the registry)."""
    with open(REG_PATH, encoding="utf-8") as fh: return json.load(fh)


# contract S1b part D, used only to check the file (test_9) — never injected into a registry copy
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
            code = V.main(["verifier2", pkg, "--now", iso(chain.t + 3), "--registry", regp,
                           "--vendor-key", "vendor-1=" + pubkey(VENDOR_SEED).hex()] + (["--json"] if json_out else []) + list(args))
        return code, json.loads(out.getvalue()) if json_out else out.getvalue()

    @staticmethod
    def classes(findings): return sorted({f["class"] for f in findings})


class ForwardCompat(V2Case):
    def test_0_signing_helper_matches_verifier(self):
        msg = b"self-check of the test-only signer"
        self.assertTrue(V.ed25519_verify(pubkey(DEV_SEED), sign(DEV_SEED, msg), msg))
        self.assertFalse(V.ed25519_verify(pubkey(DEV_SEED), sign(DEV_SEED, msg), msg + b"x"))

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
        # Objekts gemeldet wird. Diese Erwartung war zuerst zu eng — der Code
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
        # line consciously (together with the verifier), not pass by unnoticed. 1.9 = export seal, the late
        # immediate checkpoint (8.2 conditions 3 and 4), content/ layout, integer profile, processing stages,
        # auditor inputs, completeness statement and the measured residual window (classes Spec19* below).
        # Before it: 1.8 = GENESIS.license_id is the licence commitment (4.1; class GenesisLicense below);
        # 1.7 = the contract of 66f0cc0 (LEGAL_HOLD, HOLD_VIOLATION; class LegalHold below); 1.6 = the contract of 6be9d7e.
        self.assertEqual(reg["spec_version"], "1.9")
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
        code, f = self.run_v2(self.sealed("1.7"))   # commitment already under 1.7 (lane B's mitigation): no notice
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
            code = V.main(["verifier2", pkg, "--json", "--vendor-key", "k=" + a, "--vendor-key", "k=" + b])
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
            self.assertEqual(V.main(["verifier2", self.tmp, "--registry", regp]), 3)
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

    def test_12_text_output_german_by_default_and_english(self):
        exits, meta = self.reg["verifier"]["exit_codes"], self.reg["verifier"]["finding_classes"]
        c = Chain(); c.tick(); c.anchor()
        last = c.entries[-1]["seq"]
        code, txt = self.run_cli(c, json_out=False)
        lines = txt.splitlines()
        self.assertEqual((code, lines[0].split(" - ")[0]), (4, "LEDGER verifier2 " + V.VERSION), lines)
        self.assertEqual(lines[1:3], ["Exit 4: " + exits["4"]["de"], f"Kettenende: nicht versiegelt, letzter Eintrag seq {last}"])
        self.assertIn("[UNSEALED_END] Exit 4 - " + meta["UNSEALED_END"]["de"], txt)
        code, txt = self.run_cli(c, args=["--lang", "en"], json_out=False)
        self.assertEqual(txt.splitlines()[1:3], ["exit 4: " + exits["4"]["en"], f"chain end: not sealed, last entry seq {last}"])
        c = Chain(); c.tick(); c.close("decommission"); s = c.entries[-3]
        for lang, head, end in (("de", "Exit", f"Kettenende: versiegelt am {s['ts_chained']} (decommission, seq {s['seq']})"),
                                ("en", "exit", f"chain end: sealed at {s['ts_chained']} (decommission, seq {s['seq']})")):
            code, txt = self.run_cli(c, args=["--lang", lang], json_out=False)
            # from 1.9 the completeness statement (8.6) and the residual window (11.2) follow the chain end
            lines = txt.splitlines()
            self.assertEqual((code, lines[1:3]), (0, [f"{head} 0: " + exits["0"][lang], end]))
            self.assertEqual(lines[3].split(":")[0], "Vollständigkeit" if lang == "de" else "completeness")
            self.assertEqual(lines[4].split(" (")[0], "Restfenster" if lang == "de" else "residual window")
            self.assertEqual(lines[5], "keine Befunde." if lang == "de" else "no findings.")
        for k in exits:                                                                # every exit code, exit 4 included
            for lang in ("de", "en"):
                self.assertIn(": " + exits[k][lang] + "\n", V.render(V.Result(self.reg["verifier"]), int(k), meta, lang, "p"))
        c = Chain("2.0"); c.anchor()
        code, txt = self.run_cli(c, json_out=False)
        self.assertEqual((code, txt.splitlines()[1:3]), (3, ["Exit 3: " + exits["3"]["de"], "Kettenende: nicht bewertet"]))

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
    artefakte/P04/rohdaten_differenz.py faehrt dieselben Eingaben durch beide Verifier.
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
            try: code = V.main(["verifier2", *argv])
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
        code, out, err = self.lauf("--help")
        self.assertEqual(code, 0)
        self.assertIn("LEDGER verification packages", out)
        self.assertEqual(alter_name(out + err), 0, out + err)
        code, out, err = self.lauf(os.path.join(VEKTOREN, "valid_basic"), "--vendor-key", "kaputt", "--registry", REG_PATH)
        self.assertEqual(code, 3, out + err)
        self.assertTrue(err.startswith("verifier2: "), err)
        self.assertEqual(alter_name(out + err), 0, out + err)

    def test_3_the_check_can_fail(self):
        """Red check of the check: every spelling that could come back is seen, the frozen format id passes."""
        for s in ("Rekorder — Pruefbericht", "rekorder-verify 1.0.0", "REKORDER", "des Rekorders"):
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
            code = V.main(["verifier2", *argv, "--registry", REG_PATH, "--vendor-key", "vendor-1=" + pubkey(VENDOR_SEED).hex()])
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
            self.assertEqual((code, j["completeness"]), (0, {"status": "established", "up_to_tree_size": cp["tree_size"]}), (ok, err))

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
            self.assertEqual(j["completeness"], {"status": "not_established", "up_to_tree_size": None}, j)
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
        self.assertEqual(self.res.completeness, {"status": "established", "up_to_tree_size": ra[0]})
        self.run_v2(c, expect=[rb, ra, (None, ra[1])])
        self.assertEqual(self.res.completeness, {"status": "established", "up_to_tree_size": rb[0]})
        self.run_v2(c, expect=[(None, rb[1])])                            # without tree_size: the prefix it matched
        self.assertEqual(self.res.completeness, {"status": "established", "up_to_tree_size": rb[0]})
        code, txt, _ = self.cli(self.pkg(c), "--lang", "en", "--now", iso(c.t + 3), "--expect-root", rb[1])
        self.assertIn("completeness: established up to tree_size %d by the expected root passed (8.6)" % rb[0], txt.splitlines())

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


# The guard stands at the very end: unittest.main() ends the process, so a class defined after it
# never runs in script mode (python3 verifier2_test.py - how CI and the red proofs call this file).
# Until 28.09. that was the fate of Klarstellung: five tests, run only by "python3 -m unittest".
if __name__ == "__main__":
    print(f"verifier2 under test: {V2_PATH}\nregistry: {REG_PATH} (own spec_version {OWN})", file=sys.stderr)
    unittest.main(verbosity=2)
