#!/usr/bin/env python3
# verifier2 - independent second verifier for LEDGER verification packages
# (the product was called "Rekorder"; frozen, signed format identifiers such as
# "rekorder-herstellerschluessel/1" keep that name - they are no product name).
#
# Built solely from the open specification (spec/format.de.md + spec/registry.json).
# It must never import from, read, or otherwise depend on the Go implementation or
# the appliance code: its whole point is to show that the specification alone is
# enough to build an independent verifier. Python 3.10 or later, standard library only -
# Ed25519, RSA and ECDSA verification and the CMS of RFC 3161 time-stamp tokens
# included, since the stdlib offers none.
#
# Exit codes (registry verifier.exit_codes):
#   0 valid, no findings / 1 valid with findings / 2 invalid / 3 format error /
#   4 incomplete: chain end not sealed (format.de.md 8.6)
#   (3 also covers an unusable invocation, e.g. a missing registry)
# Several findings: the precedence 3 > 2 > 4 > 1 > 0 of 10.3 decides (registry
# verifier.exit_precedence), not the numeric maximum - 2 beats 4.
#
# Forward compatibility (format.de.md 10.6): the verifier's own spec version is the
# registry's top-level spec_version. A package of the same MAJOR with a newer MINOR
# is the finding SPEC_NEWER (once per package, exit 1) and every known check still
# runs; a different MAJOR is FORMAT_ERROR. An event_type unknown to this version is
# the finding UNKNOWN_ENTRY_TYPE (once per type name, seq of the first occurrence),
# not a schema error: the entry stays in the seq/hash/Merkle checks, its payload is
# only required to be an object, and it is never treated as critical (no immediate
# checkpoint demanded - the conservative direction). Unknown ENVELOPE fields and the
# payload fields of KNOWN types stay strict (FORMAT_ERROR).
#
# Processing stages (format.de.md 10.5, from 1.9): (1) manifest, (2) segment table,
# (3) per segment: present, SHA-256, number of lines, (4) per line: JSON, signals,
# schema, chain_id, (5) the checks of the chain. A failure in stages 1-3 ends the run;
# one in stage 4 lets the other lines run on and drops stage 5.
#
# The command line (1.1.0): verifier2 [switches] [--] <package>, every switch before the package and written with two
# dashes, "--" ends the switches; a switch without a value takes none, one with a value takes the next argument as it is
# (also when it begins with a dash), --version stands alone, and -h/--help print the help on the error output with
# exit 3. read_command_line reads it as ledger-verify does, before argparse sees it. Any other form is an unusable
# invocation (exit 3), exactly where ledger-verify refuses it too (release/verifier/check_cli_gleich.py runs both over the same
# command lines); so is an output that cannot be written (emit). --registry is the one switch of verifier2 alone: which
# registry it reads, no auditor input. The report language defaults to en, as in ledger-verify.
#
# From 1.10 (the foundations): the auditor's inputs of 10.8 are read at invocation, before the package is
# opened, and an unusable invocation is exit 3 without a report; the role check of 10.7.4 runs before the
# receipts and gives the report object key_roles (10.10.2); time witnesses follow the time-stamp profile of
# 7.5. "verifier2.py zeitstempel" checks one time stamp on its own, a helper outside the specification.
#
# From 1.10 (the vendor log): the extracts the auditor passes (7.4.8) are checked after the receipts in steps L1 to L10
# of 7.4.10; they add only the five classes of 7.4.11, all of exit class 1, and the report object vendor_log (10.10.2)
# with its block in the text report (10.10.3), and change no other result.
#
# From 1.10 (the anchor history): the pages of kind ledger.anchor_history.v2 the auditor passes (8.8.2) and the request
# time R go through steps H1 to H13 of 8.8.4; their roots become expected roots of the source anchor_history (8.8.5),
# the affiliation is read from them alone (8.8.6), never from the package. The four classes of 8.8.7 have exit class 1;
# the one way to exit 2 is MERKLE_INCONSISTENT from a root the vendor countersigned or recorded as a gap witness before
# R - W_h. A root that is only reported never gives exit 2.
#
# From 1.10 (the evidence level): after the exit code the verifier forms the evidence level of 10.9 from what the run
# holds (10.9.3), the exit code and the finding classes, and writes it as the report object evidence_level (10.10.2)
# with its block in the text report (10.10.3), whose last line is the line on affiliation. It is no finding, adds,
# removes and changes none, and never changes the exit code.

import argparse, base64, datetime, hashlib, hmac, json, os, re, sys, zipfile

VERSION = "1.1.0"
ZERO = "0" * 64
TICK_TOLERANCE_MS = 450000     # format.de.md 8.2: 1.5 x the 5 min TICK interval, in whole milliseconds (2)
CLOCK_TOLERANCE_MS = 300000    # format.de.md 9.2
DEFAULT_FRESHNESS_H = 24.0     # format.de.md 8.5
FRESHNESS = re.compile(r"([1-9][0-9]{0,5})([hms])")   # --freshness (10.8): 1 to 999999, then h, m or s
FRESHNESS_UNIT_MS = {"h": 3600000, "m": 60000, "s": 1000}
MAX_INT = 2 ** 53 - 1          # format.de.md 2: every JSON number of the package lies in -MAX_INT .. MAX_INT
UNBOUNDED_INPUT_BYTES = 33554432   # an auditor file without a limit in 10.8 (PEM roots, vendor root, zeitstempel files) is
                                   # read up to this size, the largest limit per file of the table, like ledger-verify
                                   # (MaxDateiOhneGrenze): a bound of both reference verifiers, not of the specification
DEFAULT_REGISTRY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "spec", "registry.json")

# ------------------------------------------------------------ RFC 8785 (JCS)

_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _jstr(s):
    return '"' + "".join(_ESC.get(c, c if c >= "\x20" else "\\u%04x" % ord(c)) for c in s) + '"'


def jcs(v):
    """RFC 8785 canonicalisation, integer profile: the package holds no other number (2), jloads admits none."""
    if v is None or isinstance(v, bool): return "null" if v is None else str(v).lower()
    if isinstance(v, int): return str(v)
    if isinstance(v, str): return _jstr(v)
    if isinstance(v, list): return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        # RFC 8785 sorts member names by their UTF-16 code units.
        ks = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_jstr(k) + ":" + jcs(v[k]) for k in ks) + "}"
    raise ValueError("unserialisable type " + type(v).__name__)


def jcsb(v): return jcs(v).encode("utf-8")


def entry_hash(e):
    """format.de.md 3: SHA-256 over the JCS of the entry without entry_hash."""
    return hashlib.sha256(jcsb({k: x for k, x in e.items() if k != "entry_hash"})).hexdigest()


# --------------------------------------------- Ed25519 verification (RFC 8032)
# The standard library has no Ed25519, so verification is implemented here.

_Q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _Q - 2, _Q) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _xrecover(y):
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q)
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0: x = x * _I % _Q
    return _Q - x if x % 2 else x


_BY = 4 * pow(5, _Q - 2, _Q) % _Q
_B = (_xrecover(_BY), _BY, 1, _xrecover(_BY) * _BY % _Q)


def _add(p, q):
    a, b, c, d = p
    e, f, g, h = q
    r, s = (b - a) * (f - e) % _Q, (b + a) * (f + e) % _Q
    t, u = 2 * d * h * _D % _Q, 2 * c * g % _Q
    return ((s - r) * (u - t) % _Q, (u + t) * (s + r) % _Q, (u - t) * (u + t) % _Q, (s - r) * (s + r) % _Q)


def _mul(p, e):
    r = (0, 1, 1, 0)
    while e:
        if e & 1: r = _add(r, p)
        p, e = _add(p, p), e >> 1
    return r


def _point(b):
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    if y >= _Q: return None
    x = _xrecover(y)
    if x & 1 != b[31] >> 7: x = _Q - x
    if (-x * x + y * y - 1 - _D * x * x % _Q * (y * y)) % _Q != 0: return None
    return (x, y, 1, x * y % _Q)


def _encode(p):
    x, y, z, _t = p
    zi = pow(z, _Q - 2, _Q)
    x, y = x * zi % _Q, y * zi % _Q
    return (y | (x & 1) << 255).to_bytes(32, "little")


def ed25519_verify(pubkey, sig, msg):
    """RFC 8032 5.1.7 without the cofactor: S < L, and the encoding of [S]B - [k]A equals R byte for byte (format
    spec 2). An R that is not the canonical encoding of its point (x = 0 with the sign bit set) therefore never
    verifies; the public key is decoded as before (x = 0 with the sign bit set reads as x = 0)."""
    if len(pubkey) != 32 or len(sig) != 64: return False
    a = _point(pubkey)
    s = int.from_bytes(sig[32:], "little")
    if a is None or s >= _L: return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pubkey + msg).digest(), "little") % _L
    x, y, z, t = _mul(a, h)
    return _encode(_add(_mul(_B, s), ((-x) % _Q, y, z, (-t) % _Q))) == sig[:32]


# -------------------------------------------------- Merkle tree (RFC 6962, §5)

MTH_EMPTY = hashlib.sha256(b"").digest()           # MTH({}) (RFC 9162 2.1.1): the root of a tree without leaves


def mth(leaves):
    """Merkle Tree Hash: leaf = SHA256(0x00||hash), node = SHA256(0x01||L||R)."""
    n = len(leaves)
    if n == 0: return MTH_EMPTY
    if n == 1: return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = 1 << ((n - 1).bit_length() - 1)      # largest power of two smaller than n
    return hashlib.sha256(b"\x01" + mth(leaves[:k]) + mth(leaves[k:])).digest()


def prefix_roots(leaves):
    """The MTH of every prefix 1..n in one pass, equal to mth(leaves[:t]) for each t: the perfect subtrees of
    the prefix lie on a stack, largest first, and its root folds them from the right (RFC 6962, 2.1). Needed
    for an expected root without tree_size (10.8), which may be the root of any prefix."""
    stack = []                                   # (height, hash) of the perfect subtrees
    for leaf in leaves:
        h, height = hashlib.sha256(b"\x00" + leaf).digest(), 0
        while stack and stack[-1][0] == height:
            h, height = hashlib.sha256(b"\x01" + stack.pop()[1] + h).digest(), height + 1
        stack.append((height, h))
        r = h
        for _height, left in reversed(stack[:-1]): r = hashlib.sha256(b"\x01" + left + r).digest()
        yield r


# Proofs of RFC 6962 2.1 as RFC 9162 writes their verification out (2.1.3.2, 2.1.4.2). No verdict uses them yet:
# they are for an anchor that publishes roots in a log, whose proofs come from outside the package.

def _node(left, right): return hashlib.sha256(b"\x01" + left + right).digest()


def verify_inclusion(leaf, index, size, path, root):
    """An inclusion proof (RFC 9162 2.1.3.2): leaf the leaf hash (0x00 prefix applied), index its position from 0 in a
    tree of size leaves, path the audit path upwards -> True if it leads to root. A tree of size 0, an index not below
    the size and a path longer or shorter than the tree needs fail. The size is bound only through the shape of the path
    (leaf 0 of 5 and of 7 leaves: d1, MTH(d2,d3), d4, each on the right), so size and root must come from one signed
    statement, as RFC 9162 takes both from one tree head; the same holds for the two sizes of verify_consistency."""
    if not 0 <= index < size: return False
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0: return False                      # longer than the tree is deep
        if fn & 1 or fn == sn:
            r = _node(p, r)
            while not fn & 1 and fn: fn, sn = fn >> 1, sn >> 1
        else: r = _node(r, p)
        fn, sn = fn >> 1, sn >> 1
    return sn == 0 and r == root                      # sn > 0: shorter than the tree is deep


def verify_consistency(size1, size2, root1, root2, path):
    """A consistency proof (RFC 9162 2.1.4.2): the tree of size1 with root1 is a prefix of the tree of size2 with root2
    -> True if path proves it. RFC 9162 defines the proof for 0 < size1 < size2; the edges hold with an empty path, as
    spec 5 settles equal sizes: size1 = size2 with equal roots, size1 = 0 with root1 the root of the empty tree."""
    if not 0 <= size1 <= size2: return False
    if size1 == 0 or size1 == size2:
        return not path and (size1 > 0 or root1 == MTH_EMPTY) and (size1 < size2 or root1 == root2)
    if not path: return False
    if size1 & (size1 - 1) == 0: path = [root1] + list(path)    # a complete subtree: its root starts the path
    fn, sn = size1 - 1, size2 - 1
    while fn & 1: fn, sn = fn >> 1, sn >> 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0: return False
        if fn & 1 or fn == sn:
            fr, sr = _node(c, fr), _node(c, sr)
            while not fn & 1 and fn: fn, sn = fn >> 1, sn >> 1
        else: sr = _node(sr, c)
        fn, sn = fn >> 1, sn >> 1
    return sn == 0 and fr == root1 and sr == root2


# ------------------------------------------------- schema checks (registry.json)

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_HEXLEN = {"hex64": 64, "hex128": 128}


def _is_ts(v):
    """rfc3339 (format.de.md 2) read by the one grammar of 10.7 - the same function the hold
    comparison (9.3) and the vendor list use. It replaced a \\d/$ regex plus fromisoformat: \\d is
    Unicode, $ matches before a final line end, and only fromisoformat's own strictness kept
    both out; the comma fraction and the one-digit hour the grammar forbids stay out as before."""
    return utc_ns(v) is not None


def _check(v, spec, reg, path, errs, res, offen=None):
    """Schema errors go to errs (FORMAT_ERROR); the two open types of 10.6 report findings via res.once."""
    t = spec["type"].rstrip("?")            # "object?" etc.: nullable
    if v is None:
        return None if spec["type"].endswith("?") else errs.append(f"{path}: null in a non-nullable field")
    if t not in ("const", "uuid", "rfc3339", "bool", "hex64", "hex128", "enum", "version", "open_enum", "int", "string", "object", "array"): errs.append(f"{path}: registry type {t!r} is unknown to this verifier version: loud, not silent")
    elif t == "const" and v != spec["value"]:
        errs.append(f"{path}: expected {spec['value']!r}, got {v!r}")
    elif t == "uuid" and not (isinstance(v, str) and _UUID.fullmatch(v)):   # fullmatch: $ alone matches before a final line end
        errs.append(f"{path}: not a lowercase uuid")
    elif t == "rfc3339" and not _is_ts(v):
        errs.append(f"{path}: not an RFC 3339 UTC timestamp")
    elif t == "bool" and not isinstance(v, bool):
        errs.append(f"{path}: not a boolean")
    elif t in _HEXLEN and not (isinstance(v, str) and re.fullmatch("[0-9a-f]{%d}" % _HEXLEN[t], v)):
        errs.append(f"{path}: not {t}")
    elif t == "enum" and v not in (spec.get("values") or reg[spec["ref"]]):
        errs.append(f"{path}: {v!r} is not in the enumeration")
    elif t == "version":     # 10.6 R1: same MAJOR required; a newer MINOR is the finding SPEC_NEWER, once per package
        own, got = reg["spec_version"].split("."), v.split(".") if isinstance(v, str) and re.fullmatch("[1-9][0-9]*\\.(0|[1-9][0-9]*)", v) else None
        if got is None or got[0] != own[0]: errs.append(f"{path}: {v!r} is not a version {own[0]}.MINOR (this verifier: {reg['spec_version']})")
        elif (len(got[1]), got[1]) > (len(own[1]), own[1]): res.once("SPEC_NEWER", "", f"{path}: {v} is newer than this verifier's {reg['spec_version']}; only the rules of {reg['spec_version']} are applied")
    elif t == "open_enum":   # 10.6 R2: an unknown value is a finding (once per value, first occurrence), not a schema error
        if not isinstance(v, str): errs.append(f"{path}: not a string")
        elif v not in reg[spec["ref"]]: res.once(spec["unknown_finding"], v, f"{path}: {v!r} is unknown to this verifier ({reg['spec_version']}); entry checked, payload only as an object")
    elif t == "int":
        if not isinstance(v, int) or isinstance(v, bool): errs.append(f"{path}: not an integer")
        elif "min" in spec and v < spec["min"]: errs.append(f"{path}: {v} is below min {spec['min']}")
        elif "max" in spec and v > spec["max"]: errs.append(f"{path}: {v} is above max {spec['max']}")
    elif t == "string":
        if not isinstance(v, str): errs.append(f"{path}: not a string")
        elif len(v) > spec.get("maxlen", 1 << 30): errs.append(f"{path}: exceeds maxlen")
    elif t == "object":
        if not isinstance(v, dict): errs.append(f"{path}: not an object")
        elif spec.get("fields"): _fields(v, spec["fields"], reg, path, errs, res, offen)
    elif t == "array" and not isinstance(v, list): errs.append(f"{path}: not an array")
    elif t == "array":
        for i, x in enumerate(v): _check(x, spec["items"], reg, f"{path}[{i}]", errs, res, offen)


def _fields(obj, specs, reg, path, errs, res, offen=None):
    """Every defined field must be present; undefined fields must not occur.

    offen is not None -> the open path of 10.6 R5: an undefined field is
    collected for the caller instead of being an error. The strict path stays
    unchanged, so the envelope and the payloads of known types (R3) cannot
    loosen by accident.
    """
    for k in sorted(set(obj) - set(specs)):
        if offen is None:
            errs.append(f"{path}.{k}: field not defined by the specification")
        else:
            offen.add(re.sub(r"\[[0-9]+\]", "[]", f"{path}.{k}"))
    for k, spec in specs.items():
        if k not in obj: errs.append(f"{path}.{k}: required field missing")
        else: _check(obj[k], spec, reg, f"{path}.{k}", errs, res, offen)


# ------------------------------------------------------------------ package

# --- Time-stamp profile (format spec 7.5, from 1.10) ---------------------------
# One profile for the time witnesses of the chain (7.3), the time stamps of the vendor log's day entries (7.4.6) and
# the evidence level (10.9), written out from the rules alone: B64 (2, 7.5.1), grammar T (7.5.2), Z.1 certificates
# (7.5.3), Z.2 algorithms and keys (7.5.4), Z.3 to Z.5 extensions, path and signer (7.5.5), Z.6 and rule QS (7.5.6)
# and the mapping of results (7.5.7). Nothing here asks a certificate library; the standard library has none, and
# 7.5 wants the result to rest on these rules only. RSA PKCS#1 v1.5 and RSASSA-PSS (RFC 8017), ECDSA on P-256,
# P-384 and P-521 (FIPS 186-5) and the Ed25519 above are implemented here.
# Roots for time stamps are exactly the certificates the auditor passes, each with its purposes (7.5.7, 10.8): the
# system root store counts for no purpose, no root is built in, and a certificate of the package's keys/tsa/ only
# lets the report name the authority (7.3).

class TError(ValueError):
    """Grammar T (7.5.2) or B64 or the size of the DER violated: step 2 of 7.3 (TIME_ANCHOR_INVALID); a day time
    stamp is defective (7.5.7)."""


def der_tlv(b, i=0, end=None):
    """The DER header at b[i] (T.6): (first tag byte, start of the content, end of the content). Definite lengths in
    minimal form; a tag number from 31 on in minimal base-128 form (its first byte then never equals a low tag)."""
    end = len(b) if end is None else end
    if i + 2 > end: raise ValueError("truncated")
    t, j = b[i], i + 1
    if t & 0x1f == 0x1f:
        if b[j] == 0x80: raise ValueError("tag number not in minimal form")
        num = 0
        while True:
            if j >= end: raise ValueError("truncated")
            num, j = num << 7 | b[j] & 0x7f, j + 1
            if not b[j - 1] & 0x80: break
        if num < 31: raise ValueError("high tag number form for a low tag number")
    if j >= end: raise ValueError("truncated")
    n, j = b[j], j + 1
    if n & 0x80:
        k = n & 0x7f
        if k == 0: raise ValueError("indefinite length")
        if k > 8 or j + k > end or b[j] == 0: raise ValueError("length not in minimal form")
        n, j = int.from_bytes(b[j:j + k], "big"), j + k
        if n < 0x80: raise ValueError("length not in minimal form")
    if j + n > end: raise ValueError("truncated")
    return t, j, j + n


def der(b, tag=None):
    """b as exactly one DER element (tag, encoding, content): nothing after it (T.1, Z.1)."""
    t, s, e = der_tlv(b)
    if e != len(b): raise ValueError("bytes after the element")
    if tag is not None and t != tag: raise ValueError("tag 0x%02x, expected 0x%02x" % (t, tag))
    return t, b, b[s:]


def der_seq(node, tag=0x30):
    """The elements [(tag, encoding, content)] inside a constructed element of that tag."""
    if node[0] != tag: raise ValueError("tag 0x%02x, expected 0x%02x" % (node[0], tag))
    out, b, i = [], node[2], 0
    while i < len(b):
        t, s, e = der_tlv(b, i)
        out.append((t, b[i:e], b[s:e])); i = e
    return out


def _int_ok(c):
    return bool(c) and not (len(c) > 1 and (c[0] == 0 and c[1] < 0x80 or c[0] == 0xff and c[1] >= 0x80))


_DEC_PART = 10 ** 512


def _dec(v):
    """The decimal text of an integer of any size, without leading zeros. str() refuses more digits than
    sys.get_int_max_str_digits() (4300 by default, never fewer than 640), and an arc of an OBJECT IDENTIFIER or an
    INTEGER in DER can have more, which T.6 and Z.1 admit: such a value is split by the powers 10^(512 * 2^i) into
    parts str() writes, every part after the first padded with zeros. The limit itself stays as it is, for the JSON
    reader too."""
    if v < 0: return "-" + _dec(-v)
    if v < _DEC_PART: return str(v)
    pw = [_DEC_PART]
    while pw[-1] <= v: pw.append(pw[-1] * pw[-1])

    def part(x, i, pad):                        # x < pw[i]; pad: with all 512 * 2^i digits
        if i == 0: return str(x).zfill(512) if pad else str(x)
        hi, lo = divmod(x, pw[i - 1])
        return (part(hi, i - 1, pad) if pad or hi else "") + part(lo, i - 1, pad or hi > 0)
    return part(v, len(pw) - 1, False)


def der_oid(node):
    """OBJECT IDENTIFIER with minimal subidentifiers (T.6) -> dotted text, every arc in decimal whatever its size."""
    c = node[2]
    if node[0] != 0x06 or not c or c[-1] & 0x80 or any(x == 0x80 and (j == 0 or c[j - 1] < 0x80) for j, x in enumerate(c)):
        raise ValueError("not a DER OBJECT IDENTIFIER")
    arcs, v = [], 0
    for x in c:
        v = v << 7 | x & 0x7f
        if x < 0x80: arcs.append(v); v = 0
    f = min(arcs[0] // 40, 2)
    return ".".join(map(_dec, [f, arcs[0] - 40 * f] + arcs[1:]))


def der_int(node, tag=0x02):
    """INTEGER in minimal two's complement (T.6); tag: the tag of an IMPLICIT INTEGER."""
    if node[0] != tag or not _int_ok(node[2]): raise ValueError("not a DER INTEGER")
    return int.from_bytes(node[2], "big", signed=True)


def der_bool(node):
    if node[0] != 0x01 or node[2] not in (b"\x00", b"\xff"): raise ValueError("not a DER BOOLEAN (content 00 or FF)")
    return node[2] == b"\xff"


def der_octets(node):
    if node[0] != 0x04: raise ValueError("not an OCTET STRING")
    return node[2]


def der_bits(node):
    """A BIT STRING with 0 unused bits (Z.1: signatureValue, subjectPublicKey)."""
    if node[0] != 0x03 or node[2][:1] != b"\x00": raise ValueError("not a BIT STRING with 0 unused bits")
    return node[2][1:]


def der_alg(node):
    """AlgorithmIdentifier SEQUENCE { OID, parameters as one TLV or absent } -> (OID, the parameters' DER or b"")."""
    k = der_seq(node)
    if not 1 <= len(k) <= 2: raise ValueError("not an AlgorithmIdentifier")
    return der_oid(k[0]), k[1][1] if len(k) == 2 else b""


_CONSTRUCTED_UNIVERSAL = {8, 11, 16, 17, 29}      # EXTERNAL, EMBEDDED PDV, SEQUENCE, SET, CHARACTER STRING


def der_check(b):
    """T.6 for every element of one DER TLV b, descending into each constructed encoding: definite lengths in minimal
    form, INTEGER minimal, BOOLEAN 00 or FF, OID subidentifiers minimal, primitive or constructed form as a universal
    type demands; nothing after the element. The order of a SET OF and an explicitly written DEFAULT are not checked.
    Used where a rule reads a content as DER throughout (Z.1, rule QS); Z.6 reads its grammar element by element (7.5.6).
    Iterative, so a deep nesting is read like any other. ValueError on a deviation."""
    b, ranges, top = bytes(b), [(0, len(b))], True
    while ranges:
        i, end = ranges.pop()
        n = 0
        while i < end:
            t, s, e = der_tlv(b, i, end)
            if t >> 6 == 0:                            # universal class: the tag number decides the form
                num, cons = t & 0x1f, bool(t & 0x20)
                if num == 0 or num == 0x1f: raise ValueError("universal tag %d is no DER element here" % num)
                if cons != (num in _CONSTRUCTED_UNIVERSAL): raise ValueError("universal tag %d in the wrong form" % num)
                if num == 1: der_bool((0x01, b"", b[s:e]))
                elif num == 2: der_int((0x02, b"", b[s:e]))
                elif num == 6: der_oid((0x06, b"", b[s:e]))
            if t & 0x20: ranges.append((s, e))
            i, n = e, n + 1
        if top and n != 1: raise ValueError("not exactly one element")
        top = False


B64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")   # grammar B64 (2), registry types.b64


def b64_decode(s):
    """Grammar B64 (2): the alphabet of RFC 4648 section 4, a length divisible by 4, "=" only as padding at the end, at
    most twice; no line break, no blank. Unused bits of the last group are not checked. ValueError otherwise."""
    if not isinstance(s, str) or not B64.fullmatch(s): raise ValueError("violates grammar B64 (2)")
    return base64.b64decode(s)


EPOCH_ORDINAL = datetime.date(1970, 1, 1).toordinal()


def _instant_ns(y, mo, d, h, mi, s, frac=""):
    """Nanoseconds since 1970 of a calendar instant in UTC; ValueError for a date that does not exist, an hour beyond
    23, a minute or second beyond 59 (no leap second), and the year 0000."""
    day = datetime.date(int(y), int(mo), int(d)).toordinal() - EPOCH_ORDINAL
    if int(h) > 23 or int(mi) > 59 or int(s) > 59: raise ValueError("no valid time of day")
    return ((day * 24 + int(h)) * 60 + int(mi)) * 60 * 10**9 + int(s) * 10**9 + int((frac or "0")[:9].ljust(9, "0"))


_GENTIME = re.compile(rb"([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})(?:\.([0-9]{0,8}[1-9]))?Z")
_Z1_UTC = re.compile(rb"([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z")
_Z1_GEN = re.compile(rb"([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z")


def gen_time(node):
    """genTime (T.5): GeneralizedTime YYYYMMDDhhmmss[.f]Z, 1 to 9 digits f whose last is not 0, an existing date, hour
    00 to 23, minute and second 00 to 59, no offset -> (text as written, ns since 1970, the same cut to milliseconds
    in the form YYYY-MM-DDThh:mm:ss.sssZ). Cut, never rounded (7.3 step 3)."""
    m = _GENTIME.fullmatch(node[2]) if node[0] == 0x18 else None
    if not m: raise ValueError("genTime is no GeneralizedTime of grammar T.5")
    g = [x.decode() for x in m.groups(default=b"")]
    ns = _instant_ns(*g)
    return node[2].decode(), ns, "%s-%s-%sT%s:%s:%s.%sZ" % (*g[:6], (g[6] + "000")[:3])


def z1_time(node):
    """Time of Z.1: UTCTime YYMMDDhhmmssZ (YY < 50 is 20YY, else 19YY) or GeneralizedTime YYYYMMDDhhmmssZ -> ns."""
    m = _Z1_UTC.fullmatch(node[2]) if node[0] == 0x17 else _Z1_GEN.fullmatch(node[2]) if node[0] == 0x18 else None
    if not m: raise ValueError("not a Time of Z.1")
    g = [x.decode() for x in m.groups()]
    if node[0] == 0x17: g[0] = ("20" if int(g[0]) < 50 else "19") + g[0]
    return _instant_ns(*g)


def _utc(ns):   # an instant for the report, to the second
    return (datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=ns // 10**9)).strftime("%Y-%m-%dT%H:%M:%SZ")


H256, H384, H512, SHA1 = "2.16.840.1.101.3.4.2.1", "2.16.840.1.101.3.4.2.2", "2.16.840.1.101.3.4.2.3", "1.3.14.3.2.26"
SHA2 = {H256: hashlib.sha256, H384: hashlib.sha384, H512: hashlib.sha512}            # the only digests of Z.2 and T.5
HASH_NAMES = {H256: "sha256", H384: "sha384", H512: "sha512"}
NULL_OR_ABSENT = (b"", b"\x05\x00")
RSA_KEY, EC_KEY, ED25519, PSS, MGF1 = "1.2.840.113549.1.1.1", "1.2.840.10045.2.1", "1.3.101.112", "1.2.840.113549.1.1.10", "1.2.840.113549.1.1.8"
RSA_SIGS = {"1.2.840.113549.1.1.11": H256, "1.2.840.113549.1.1.12": H384, "1.2.840.113549.1.1.13": H512}
EC_SIGS = {"1.2.840.10045.4.3.2": H256, "1.2.840.10045.4.3.3": H384, "1.2.840.10045.4.3.4": H512}
_DIGEST_INFO = {h: bytes([0x30, 17 + L, 0x30, 0x0d, 0x06, 0x09]) + bytes.fromhex("6086480165030402") + bytes([i, 5, 0, 4, L])
                for i, h, L in ((1, H256, 32), (2, H384, 48), (3, H512, 64))}   # RFC 8017 9.2 note 1


def rsa_verify(n, e, sig, msg, h, salt=None):
    """RSASSA-PKCS1-v1_5 (Z.2: the complete encoded message compared, signature length the octet length of n) or, with
    a salt length, RSASSA-PSS with MGF1 over the same hash (RFC 8017 8.2.2, 9.1.2)."""
    k = (n.bit_length() + 7) // 8
    if len(sig) != k or int.from_bytes(sig, "big") >= n: return False
    m = pow(int.from_bytes(sig, "big"), e, n)
    if salt is None:
        t = _DIGEST_INFO[h] + SHA2[h](msg).digest()
        return k >= len(t) + 11 and m.to_bytes(k, "big") == b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    H, bits = SHA2[h], n.bit_length() - 1
    hl, el = H().digest_size, (bits + 7) // 8
    if m.bit_length() > bits or el < hl + salt + 2 or m & 0xff != 0xbc: return False
    em = m.to_bytes(el, "big")
    masked, hh, mask, c = em[:el - hl - 1], em[el - hl - 1:-1], b"", 0
    while len(mask) < len(masked): mask += H(hh + c.to_bytes(4, "big")).digest(); c += 1
    db = ((int.from_bytes(masked, "big") ^ int.from_bytes(mask[:len(masked)], "big")) & ((1 << (bits - 8 * hl - 8)) - 1)).to_bytes(len(masked), "big")
    z = el - hl - salt - 2
    return db[:z] == bytes(z) and db[z] == 1 and H(bytes(8) + H(msg).digest() + db[z + 1:]).digest() == hh


# NIST curves, a = -3 on all three: OID -> (p, b, Gx, Gy, n) (FIPS 186-5, SP 800-186)
CURVES = {"1.2.840.10045.3.1.7": (2**256 - 2**224 + 2**192 + 2**96 - 1, 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
                                  0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
                                  0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
                                  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551),
          "1.3.132.0.34": (2**384 - 2**128 - 2**96 + 2**32 - 1,
                           0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
                           0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
                           0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
                           0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973),
          "1.3.132.0.35": (2**521 - 1,
                           0x51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
                           0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
                           0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650,
                           0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409)}


def _jadd(P, Q, p):
    """P + Q on y^2 = x^3 - 3x + b in Jacobian coordinates (X, Y, Z), None the point at infinity; doubling included."""
    if P is None or Q is None: return P or Q
    (X1, Y1, Z1), (X2, Y2, Z2) = P, Q
    z1, z2 = Z1 * Z1 % p, Z2 * Z2 % p
    u1, u2, s1, s2 = X1 * z2 % p, X2 * z1 % p, Y1 * z2 * Z2 % p, Y2 * z1 * Z1 % p
    h, r = (u2 - u1) % p, (s2 - s1) % p
    if h == 0:
        if r or not Y1: return None
        g = Y1 * Y1 % p
        b4, a = 4 * X1 * g % p, 3 * (X1 - z1) * (X1 + z1) % p
        X3 = (a * a - 2 * b4) % p
        return X3, (a * (b4 - X3) - 8 * g * g) % p, 2 * Y1 * Z1 % p
    hh = h * h % p
    hhh, v = h * hh % p, u1 * hh % p
    X3 = (r * r - hhh - 2 * v) % p
    return X3, (r * (v - X3) - s1 * hhh) % p, h * Z1 * Z2 % p


def _ec_lin(a, P, b, Q, p):
    """a*P + b*Q for affine points (None: infinity), one pass of doublings for both (Shamir's trick)."""
    J = [None, (*P, 1), (*Q, 1)]
    J.append(_jadd(J[1], J[2], p))
    R = None
    for i in range(max(a.bit_length(), b.bit_length()) - 1, -1, -1):
        R = _jadd(R, R, p)
        k = (a >> i & 1) | (b >> i & 1) << 1
        if k: R = _jadd(R, J[k], p)
    if R is None: return None
    zi = pow(R[2], -1, p)
    return R[0] * zi * zi % p, R[1] * zi * zi * zi % p


def ec_point(curve, b):
    """An uncompressed point 04 || X || Y on the curve (Z.2), else ValueError."""
    p, cb = CURVES[curve][:2]
    L = (p.bit_length() + 7) // 8
    if len(b) != 2 * L + 1 or b[0] != 4: raise ValueError("the EC point is not uncompressed")
    x, y = int.from_bytes(b[1:L + 1], "big"), int.from_bytes(b[L + 1:], "big")
    if x >= p or y >= p or (y * y - x * x * x + 3 * x - cb) % p: raise ValueError("the EC point is not on the curve")
    return x, y


def ecdsa_verify(curve, Q, sig, msg, h):
    """ECDSA (FIPS 186-5 6.4.2): the signature SEQUENCE { r, s } of minimal positive INTEGERs with 1 <= r, s < n (Z.2),
    the hash cut to the bit length of n."""
    p, _b, gx, gy, n = CURVES[curve]
    try:
        rs = der_seq(der(sig, 0x30))
        if len(rs) != 2: return False
        r, s = map(der_int, rs)
    except ValueError: return False
    if not (0 < r < n and 0 < s < n): return False
    d = SHA2[h](msg).digest()
    w, z = pow(s, -1, n), int.from_bytes(d, "big") >> max(0, 8 * len(d) - n.bit_length())
    X = _ec_lin(z * w % n, (gx, gy), r * w % n, Q, p)
    return X is not None and X[0] % n == r


class Z2Error(ValueError):
    """An algorithm or key outside Z.2 (7.5.4): for the signer step 5a (not checkable), on a path no path."""


def _hash_alg(node):
    """A SHA-2 AlgorithmIdentifier (parameters absent or NULL) -> OID, else Z2Error."""
    o, par = der_alg(node)
    if o not in SHA2 or par not in NULL_OR_ABSENT: raise Z2Error(f"hash {o} outside Z.2")
    return o


def _pss(par):
    """RSASSA-PSS-params of Z.2: exactly [0] hashAlgorithm SHA-2, [1] maskGenAlgorithm MGF1 with the same hash, [2]
    saltLength = the hash length, [3] trailerField absent or 1 -> (hash, salt length); Z2Error otherwise."""
    try:
        p = der_seq(der(par, 0x30)) if par else []
        if [x[0] for x in p] not in ([0xa0, 0xa1, 0xa2], [0xa0, 0xa1, 0xa2, 0xa3]): raise Z2Error("RSASSA-PSS parameters not of Z.2")
        h = _hash_alg(der(p[0][2], 0x30))
        m, mp = der_alg(der(p[1][2], 0x30))
        if m != MGF1 or _hash_alg(der(mp, 0x30)) != h: raise Z2Error("RSASSA-PSS mask generation not MGF1 with the same hash")
        if der_int(der(p[2][2])) != SHA2[h]().digest_size: raise Z2Error("RSASSA-PSS saltLength is not the hash length")
        if len(p) == 4 and der_int(der(p[3][2])) != 1: raise Z2Error("RSASSA-PSS trailerField is not 1")
        return h, SHA2[h]().digest_size
    except Z2Error: raise
    except (ValueError, IndexError) as exc: raise Z2Error(f"RSASSA-PSS parameters not of Z.2: {exc}") from None


def z2_sigalg(alg, signer_info=False, digest=None):
    """A signature algorithm (OID, parameters) of Z.2 -> (key kind, hash, PSS salt length or None); Z2Error outside the
    profile. signer_info admits rsaEncryption and id-ecPublicKey with the SHA-2 digestAlgorithm digest (7.5.4)."""
    o, par = alg
    if o in RSA_SIGS and par in NULL_OR_ABSENT: return "rsa", RSA_SIGS[o], None
    if o == PSS: return ("rsa", *_pss(par))
    if o in EC_SIGS and par == b"": return "ec", EC_SIGS[o], None
    if o == ED25519 and par == b"": return "ed", None, None
    # Z.2, in the SignerInfo only: rsaEncryption with parameters absent or NULL and id-ecPublicKey with parameters absent,
    # as their SHA-2 forms, together with a SHA-2 digestAlgorithm (7.5.4).
    if signer_info and digest in SHA2 and (o == RSA_KEY and par in NULL_OR_ABSENT or o == EC_KEY and par == b""): return ("rsa" if o == RSA_KEY else "ec"), digest, None
    raise Z2Error(f"signature algorithm {o} outside Z.2" + (" with these parameters" if o in RSA_SIGS or o in EC_SIGS or o == ED25519 else ""))


def z2_key(cert):
    """The key of a certificate in Z.2 -> ("rsa", (n, e)) | ("ec", (curve, point)) | ("ed", 32 bytes); Z2Error outside."""
    (o, par), bits = cert.key_alg, cert.key_bits
    try:
        if o == RSA_KEY:
            ne = der_seq(der(bits, 0x30))
            if par != b"\x05\x00" or len(ne) != 2: raise Z2Error("rsaEncryption key not RSAPublicKey { n, e } with NULL parameters")
            n, e = map(der_int, ne)
            if not (n > 0 and n & 1 and 2048 <= n.bit_length() <= 8192 and e & 1 and 65537 <= e <= 2**31 - 1):
                raise Z2Error(f"RSA key outside Z.2 ({n.bit_length()} bits, e={_dec(e)})")
            return "rsa", (n, e)
        if o == EC_KEY:
            c = der_oid(der(par)) if par else ""
            if c not in CURVES: raise Z2Error(f"id-ecPublicKey on the curve {c or '(none)'}, outside Z.2 (P-256, P-384, P-521)")
            return "ec", (c, ec_point(c, bits))
        if o == ED25519:
            if par or len(bits) != 32 or int.from_bytes(bits, "little") & ((1 << 255) - 1) >= _Q:
                raise Z2Error("id-Ed25519 key not 32 octets without parameters with a canonical y")
            return "ed", bits
    except Z2Error: raise
    except ValueError as exc: raise Z2Error(f"key outside Z.2: {exc}") from None
    raise Z2Error(f"key algorithm {o} outside Z.2")


def z2_verify(key, kind_hash_salt, sig, msg):
    """The signature check of Z.2 with a key and a signature algorithm already in Z.2 that fit -> bool."""
    kind, h, salt = kind_hash_salt
    if kind == "rsa": return rsa_verify(*key[1], sig, msg, h, salt)
    if kind == "ec": return ecdsa_verify(*key[1], sig, msg, h)
    return ed25519_verify(key[1], sig, msg)


_DN = {"2.5.4.3": "CN", "2.5.4.5": "serialNumber", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
       "2.5.4.97": "organizationIdentifier"}


def z1_name(node):
    """Name of Z.1: SEQUENCE OF SET SIZE (1..MAX) OF SEQUENCE { OID, one TLV } -> [(attribute, text)], the strings
    decoded for the report only; names are compared as bytes, never interpreted."""
    out = []
    for rdn in der_seq(node):
        atvs = der_seq(rdn, 0x31)
        if not atvs: raise ValueError("an empty RelativeDistinguishedName")
        for a in atvs:
            k = der_seq(a)
            if len(k) != 2: raise ValueError("an AttributeTypeAndValue is not OID and one TLV")
            o = der_oid(k[0])
            out.append((_DN.get(o, o), k[1][2].decode({0x0c: "utf-8", 0x1e: "utf-16-be", 0x1c: "utf-32-be"}.get(k[1][0], "latin-1"), "replace")))
    return out


EKU_TS, EKU_ANY, KU_CERT_SIGN = "1.3.6.1.5.5.7.3.8", "2.5.29.37.0", 1 << 5
X_BC, X_KU, X_EKU, X_SKI = "2.5.29.19", "2.5.29.15", "2.5.29.37", "2.5.29.14"
PATH_UNUSABLE = {"2.5.29.30": "nameConstraints", "2.5.29.33": "policyMappings", "2.5.29.36": "policyConstraints", "2.5.29.54": "inhibitAnyPolicy"}


READ_EXTENSIONS = (X_BC, X_KU, X_EKU, X_SKI)        # the extensions of a certificate a rule reads (Z.3, Z.4, Z.5)


class Cert:
    """A certificate after Z.1 (7.5.3): ValueError on a deviation. The key is not read here (Z.2 reads it where it
    signs), and no extension is interpreted (Z.3 does that on a path). T.6 holds for every element the grammar of Z.1
    names, each checked where it is read below; where Z.1 asks for one TLV only (the value of a Name attribute, the
    parameters of an AlgorithmIdentifier, extnValue of an extension no rule reads) only its outer header is checked,
    and its content need not be DER (7.5.2 T.6)."""

    def __init__(self, b):
        b = bytes(b)
        try:
            top = der_seq(der(b, 0x30))
            if len(top) != 3 or top[0][0] != 0x30: raise ValueError("not SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }")
            self.der, self.tbs, self.sigalg, self.sig = b, top[0][1], der_alg(top[1]), der_bits(top[2])
            f = der_seq(top[0])
            if len(f) < 7 or f[0][0] != 0xa0 or der_int(der(f[0][2])) != 2: raise ValueError("version is not encoded as 2 (v3)")
            if not 0 < (serial := der_int(f[1])) or len(f[1][2]) > 21: raise ValueError("serialNumber not positive with at most 21 octets")
            if f[2][1] != top[1][1]: raise ValueError("signature differs from the outer signatureAlgorithm")
            der_alg(f[2])
            self.serial, self.issuer, self.subject = serial, f[3][1], f[5][1]
            z1_name(f[3]); dn = z1_name(f[5])
            validity = der_seq(f[4])
            if len(validity) != 2: raise ValueError("validity is not notBefore, notAfter")
            self.not_before, self.not_after = z1_time(validity[0]), z1_time(validity[1])
            k = der_seq(f[6])
            if len(k) != 2: raise ValueError("subjectPublicKeyInfo is not AlgorithmIdentifier, BIT STRING")
            self.spki, self.key_alg, self.key_bits = f[6][1], der_alg(k[0]), der_bits(k[1])
            self.spki_sha256 = hashlib.sha256(self.spki).hexdigest()
            self.exts = {}                                     # extnID -> (critical, extnValue content)
            if len(f) > 8 or len(f) == 8 and f[7][0] != 0xa3: raise ValueError("fields after subjectPublicKeyInfo other than extensions [3]")
            if len(f) == 8:
                xs = der_seq(der(f[7][2], 0x30))
                if not xs: raise ValueError("extensions without an Extension")
                for x in xs:
                    e = der_seq(x)
                    if len(e) not in (2, 3): raise ValueError("an Extension is not extnID, critical, extnValue")
                    o, crit, val = der_oid(e[0]), der_bool(e[1]) if len(e) == 3 else False, der_octets(e[-1])
                    # Z.1: extnValue is exactly one DER TLV; of an extension no rule reads only the outer TLV is
                    # checked (T.6). The four a rule reads are DER throughout, as Z.1 asks for them.
                    der_check(val) if o in READ_EXTENSIONS else der(val)
                    if o in self.exts: raise ValueError(f"extension {o} twice")
                    self.exts[o] = (crit, val)
        except (IndexError, TypeError) as exc: raise ValueError(f"malformed ({type(exc).__name__})") from None
        self.dn = ", ".join(f"{a}={v}" for a, v in dn)
        self.name = next((v for a, v in dn if a == "CN"), self.dn)
        self._z3 = None

    def ski(self):
        """The content of the subjectKeyIdentifier extension (Z.5), None without one that is an OCTET STRING."""
        v = self.exts.get(X_SKI)
        try: return der_octets(der(v[1])) if v else None
        except ValueError: return None

    def common_name(self):
        """The signer for display only (the helper zeitstempel; no rule of 7.5 reads it): the first commonName (2.5.4.3)
        of the subject, in the order of the RDNs and of their attributes, held in a primitive UTF8String, PrintableString
        or IA5String whose content is UTF-8; "" when there is none or that one is empty. Any other value, a constructed
        string too, is passed over, and never the whole Name."""
        for rdn in der_seq(der(self.subject, 0x30)):                     # read by z1_name in __init__: one TLV per value
            for a in der_seq(rdn, 0x31):
                o, v = der_seq(a)
                if v[0] in (0x0c, 0x13, 0x16) and der_oid(o) == "2.5.4.3":
                    try: return v[2].decode("utf-8")
                    except UnicodeDecodeError: pass
        return ""

    def z3(self):
        """Z.3 on a path -> (None, basicConstraints (cA, pathLen or None) or None, keyUsage bits or None, extKeyUsage
        (OIDs, critical) or None), or (why, ...) when no path through this certificate is usable."""
        if self._z3 is None:
            bc = ku = eku = None
            why = ""
            for o, (crit, val) in self.exts.items():
                try:
                    if o in PATH_UNUSABLE: why = f"{self.name!r} carries {PATH_UNUSABLE[o]}, which makes a path unusable (Z.3)"
                    elif o == X_BC:
                        s = der_seq(der(val, 0x30)); ca, pl = False, None
                        if s and s[0][0] == 0x01: ca = der_bool(s.pop(0))
                        if s and s[0][0] == 0x02: pl = der_int(s.pop(0))
                        if s or pl is not None and pl < 0: raise ValueError("basicConstraints")
                        bc = (ca, pl)
                    elif o == X_KU:
                        c = der(val, 0x03)[2]
                        if not c or c[0] > 7 or len(c) == 1 and c[0]: raise ValueError("keyUsage")
                        ku = sum(1 << j for j in range(8 * (len(c) - 1) - c[0]) if c[1 + j // 8] >> (7 - j % 8) & 1)
                    elif o == X_EKU:
                        ids = [der_oid(y) for y in der_seq(der(val, 0x30))]
                        if not ids: raise ValueError("extKeyUsage without a purpose")
                        eku = (ids, crit)
                    elif crit: why = f"{self.name!r} carries the critical extension {o}, which Z.3 does not understand"
                except ValueError as exc: why = f"{self.name!r}: {exc} not readable after Z.3"
                if why: break
            self._z3 = (why, bc, ku, eku)
        return self._z3


def strict_pem(text):
    """Strict PEM (10.8) -> [Cert]: lines end on \\n or \\r\\n, blanks and tabs at a line end do not count, text outside a
    block is passed over (RFC 7468), a line with ':' there too. A block is the line -----BEGIN CERTIFICATE-----, content
    lines and the line -----END CERTIFICATE-----; its joined content follows B64 and gives exactly one certificate after
    Z.1. ValueError (an unusable invocation, exit 3): a block with another label, a header line inside a block, a block
    without end, a file without a CERTIFICATE block. No block is passed over silently."""
    out, body = [], None
    for n, line in enumerate(text.split("\n"), 1):
        line = (line[:-1] if line.endswith("\r") else line).rstrip(" \t")
        if body is None:
            m = re.fullmatch(r"-----BEGIN (.*)-----", line)
            if m and m[1] != "CERTIFICATE": raise ValueError(f"line {n}: a block {m[1]!r}; only CERTIFICATE blocks are admitted (10.8)")
            if m: body = []
        elif line == "-----END CERTIFICATE-----":
            try: out.append(Cert(b64_decode("".join(body))))
            except ValueError as exc: raise ValueError(f"the block ending in line {n} is no certificate after Z.1: {exc}") from None
            body = None
        elif ":" in line: raise ValueError(f"line {n}: a header line inside a block (10.8)")
        else: body.append(line)
    if body is not None: raise ValueError("a CERTIFICATE block without its END line")
    if not out: raise ValueError("no CERTIFICATE block")
    return out


TSTINFO, SIGNED_DATA, QC_STATEMENTS, QTST = "1.2.840.113549.1.9.16.1.4", "1.2.840.113549.1.7.2", "1.3.6.1.5.5.7.1.3", "0.4.0.19422.1.1"
A_CT, A_MD, A_ESS, A_ESS2 = "1.2.840.113549.1.9.3", "1.2.840.113549.1.9.4", "1.2.840.113549.1.9.16.2.12", "1.2.840.113549.1.9.16.2.47"
TOKEN_MAX_DER = 16384


def t_read(b):
    """Grammar T (7.5.2) over the decoded bytes of a token -> dict of what steps 3 to 6 read; TError otherwise. Only the
    TLV is read of crls, unsignedAttrs, tsa and of the values of signed attributes other than contentType and
    messageDigest; the content of certificates is checked in step 5, that of extensions only by rule QS."""
    if len(b) > TOKEN_MAX_DER: raise TError(f"the DER has {len(b)} bytes, more than {TOKEN_MAX_DER} (7.3 step 2)")
    try:
        ci = der_seq(der(bytes(b), 0x30))                                                         # T.1
        if len(ci) != 2 or der_oid(ci[0]) != SIGNED_DATA or ci[1][0] != 0xa0: raise TError("T.1: not a ContentInfo of id-signedData")
        sd = der_seq(der(ci[1][2], 0x30))                                                         # T.2
        if len(sd) < 4 or not 1 <= der_int(sd[0]) <= 5: raise TError("T.2: SignedData version not 1 to 5")
        das = [der_alg(x) for x in der_seq(sd[1], 0x31)]
        eci, i = der_seq(sd[2]), 3                                                                # T.3
        if len(eci) != 2 or der_oid(eci[0]) != TSTINFO or eci[1][0] != 0xa0: raise TError("T.3: no eContent of id-ct-TSTInfo")
        econtent = der_octets(der(eci[1][2]))
        certs = None
        if i < len(sd) and sd[i][0] == 0xa0: certs, i = sd[i], i + 1
        if i < len(sd) and sd[i][0] == 0xa1: i += 1                                             # crls: the TLV only
        if len(sd) != i + 1: raise TError("T.2: elements of SignedData out of order or after signerInfos")
        sis = der_seq(sd[i], 0x31)
        if len(sis) != 1: raise TError(f"T.2: {len(sis)} SignerInfos, exactly one is admitted")
        si = der_seq(sis[0])                                                                      # T.4
        if len(si) < 5 or der_int(si[0]) not in (1, 3): raise TError("T.4: SignerInfo version not 1 or 3")
        # T.4 checks of sid only that it is a SEQUENCE or a primitive [0]; a SEQUENCE whose content is not { issuer,
        # serialNumber } matches no certificate in Z.5 (step 5a) and never violates T.
        if si[1][0] == 0x80: sid = ("ski", si[1][2])
        elif si[1][0] == 0x30:
            try:
                ias = der_seq(si[1])
                sid = ("ias", ias[0][1], der_int(ias[1])) if len(ias) == 2 and ias[0][0] == 0x30 else ("none",)
            except ValueError: sid = ("none",)
        else: raise TError("T.4: sid is neither IssuerAndSerialNumber nor [0] subjectKeyIdentifier")
        dig, dpar = der_alg(si[2])
        j = 3
        attrs_node = None
        if si[j][0] == 0xa0: attrs_node, j = si[j], j + 1
        sigalg, sig = der_alg(si[j]), der_octets(si[j + 1])
        if len(si) > j + 3 or len(si) == j + 3 and si[j + 2][0] != 0xa1: raise TError("T.4: elements of SignerInfo out of order")
        if dpar not in NULL_OR_ABSENT or any(p not in NULL_OR_ABSENT for _, p in das):
            raise TError("T.4: digestAlgorithm or an element of digestAlgorithms carries parameters other than NULL")
        # T.4: digestAlgorithm stands in digestAlgorithms compared by its OID; absent parameters and NULL count as equal.
        if dig not in [o for o, _ in das]: raise TError("T.4: digestAlgorithm is not listed in digestAlgorithms")
        attrs = None
        if attrs_node is not None:
            attrs = []
            for a in der_seq(attrs_node, 0xa0):
                k = der_seq(a)
                if len(k) != 2: raise TError("T.4: an attribute is not attrType, attrValues")
                vals = der_seq(k[1], 0x31)
                if not vals: raise TError("T.4: an attribute without a value")
                attrs.append((der_oid(k[0]), vals))
            ct, md = [v for o, v in attrs if o == A_CT], [v for o, v in attrs if o == A_MD]
            if len(ct) != 1 or len(ct[0]) != 1 or len(md) != 1 or len(md[0]) != 1:
                raise TError("T.4: not exactly one contentType and one messageDigest, each with exactly one value")
            ct_value, md_value = der_oid(ct[0][0]), der_octets(md[0][0])
        tst = der_seq(der(econtent, 0x30))                                                        # T.5
        if len(tst) < 5 or der_int(tst[0]) != 1: raise TError("T.5: TSTInfo version is not 1")
        policy, mi = der_oid(tst[1]), der_seq(tst[2])
        if len(mi) != 2: raise TError("T.5: messageImprint is not hashAlgorithm, hashedMessage")
        halg, hpar = der_alg(mi[0])
        hashed = der_octets(mi[1])
        if halg not in SHA2 or hpar not in NULL_OR_ABSENT: raise TError(f"T.5: imprint algorithm {halg} is not sha256, sha384 or sha512")
        if len(hashed) != SHA2[halg]().digest_size: raise TError("T.5: hashedMessage of the wrong length")
        serial = der_int(tst[3])
        text, ns, ms_text = gen_time(tst[4])
        order, exts = [0x30, 0x01, 0x02, 0xa0, 0xa1], None
        for x in tst[5:]:
            if x[0] not in order: raise TError("T.5: TSTInfo element out of order or not defined")
            order = order[order.index(x[0]) + 1:]
            if x[0] == 0x30:
                acc, tags = der_seq(x), [0x02, 0x80, 0x81]
                for y in acc:
                    if y[0] not in tags: raise TError("T.5: accuracy element out of order")
                    tags = tags[tags.index(y[0]) + 1:]; der_int(y, y[0])
            elif x[0] == 0x01: der_bool(x)
            elif x[0] == 0x02: der_int(x)
            elif x[0] == 0xa1: exts = x                                                          # read by rule QS only
    except TError: raise
    except (ValueError, IndexError, UnicodeDecodeError) as exc: raise TError(f"grammar T: {exc}") from None
    return {"policy": policy, "imprint_alg": halg, "imprint": hashed, "serial": serial, "gen_time": text, "gen_ns": ns,
            "gen_time_ms": ms_text, "extensions": exts, "certificates": certs, "sid": sid, "digest": dig, "attrs": attrs,
            "signed": b"\x31" + attrs_node[1][1:] if attrs_node else None, "sigalg": sigalg, "sig": sig, "econtent": econtent,
            "content_type": ct_value if attrs is not None else None, "message_digest": md_value if attrs is not None else None}


def step5(t):
    """Step 5 of 7.3 over a token t (t_read) -> (state, why, signer): state "not_performable" (5a, TIME_ANCHOR_UNVERIFIED),
    "failed" (5b, TIME_ANCHOR_INVALID) or "holds". signer: the certificate Z.5 found, None where it found none."""
    if t["attrs"] is None: return "not_performable", "the token carries no signed attributes", None
    if t["certificates"] is None: return "not_performable", "the token carries no certificates", None
    # T.2: a content of certificates that does not split into TLVs makes step 5 not performable (5a); T holds.
    try: elems = der_seq(t["certificates"], 0xa0)
    except ValueError as exc: return "not_performable", f"certificates is no sequence of TLV: {exc}", None
    certs = []
    for n, x in enumerate(elems, 1):
        try: certs.append(Cert(x[1]))
        except ValueError as exc: return "not_performable", f"element {n} of certificates is no certificate after Z.1: {exc}", None
    sid = t["sid"]
    match = {c.der: c for c in certs if (c.ski() == sid[1] if sid[0] == "ski" else sid[0] == "ias" and c.issuer == sid[1] and c.serial == sid[2])}
    if len(match) != 1: return "not_performable", f"{'no' if not match else len(match)} certificates match the signer identifier (Z.5)", None
    signer = next(iter(match.values()))
    try:
        if t["digest"] not in SHA2: raise Z2Error(f"digestAlgorithm {t['digest']} outside Z.2 (sha256, sha384, sha512)")
        key, alg = z2_key(signer), z2_sigalg(t["sigalg"], True, t["digest"])
        if key[0] != alg[0]: raise Z2Error(f"a {alg[0]} signature algorithm on a {key[0]} key: key and algorithm do not fit (Z.2)")
    except Z2Error as exc: return "not_performable", str(exc), signer
    if t["content_type"] != TSTINFO: return "failed", f"the signed contentType is {t['content_type']}, not id-ct-TSTInfo", signer
    if t["message_digest"] != SHA2[t["digest"]](t["econtent"]).digest(): return "failed", "messageDigest is not the hash of eContent", signer
    if not z2_verify(key, alg, t["sig"], t["signed"]): return "failed", "the signature does not hold under the key of the signer certificate", signer
    return "holds", "", signer


def _z6_issuer_serial(node):
    """IssuerSerial of Z.6 (7.5.6): SEQUENCE { issuer GeneralNames, serialNumber INTEGER } and nothing else -> (the
    Names of its directoryNames as DER, serialNumber); ValueError otherwise. GeneralNames is a SEQUENCE of at least one
    TLV: an element with the identifier octet A4 (directoryName) holds exactly one Name after Z.1, its attribute values
    one TLV each; of every other element only the outer TLV is read (T.6), so a [4] inside an otherName value is no
    directoryName."""
    isr = der_seq(node)
    if len(isr) != 2: raise ValueError("IssuerSerial is not issuer, serialNumber")
    gns = der_seq(isr[0])
    if not gns: raise ValueError("GeneralNames without an element")
    names = []
    for g in gns:
        if g[0] == 0xa4:
            n = der(g[2], 0x30); z1_name(n); names.append(n[1])
    return names, der_int(isr[1])


def _z6_cert_id(node, v2):
    """ESSCertID of Z.6 (7.5.6): SEQUENCE { certHash OCTET STRING, issuerSerial IssuerSerial OPTIONAL }, for v2 the
    ESSCertIDv2 with hashAlgorithm AlgorithmIdentifier OPTIONAL before certHash, and nothing else -> (hash OID, certHash,
    (Names, serialNumber) or None); ValueError otherwise. The hashAlgorithm is known by its OID (absent: SHA-256), its
    parameters are one TLV; v1 names the certificate by SHA-1."""
    e = der_seq(node)
    h = SHA1
    if v2: h = der_alg(e.pop(0))[0] if e and e[0][0] == 0x30 else H256
    if not e: raise ValueError("an ESSCertID without certHash")
    cert_hash = der_octets(e.pop(0))
    isr = _z6_issuer_serial(e.pop(0)) if e and e[0][0] == 0x30 else None
    if e: raise ValueError("an ESSCertID with further elements")
    return h, cert_hash, isr


def z6(t, signer):
    """Z.6 (7.5.6): the signed attributes bind the signer certificate -> "holds", "violated" or "not_checkable" (a
    signingCertificateV2 with a hash outside SHA-2 and no violation otherwise). Never grammar T, never step 5b."""
    present, unchecked = [(o, v) for o, v in t["attrs"] if o in (A_ESS, A_ESS2)], False
    if not present or [o for o, _ in present].count(A_ESS) > 1 or [o for o, _ in present].count(A_ESS2) > 1: return "violated"
    for o, vals in present:
        try:
            if len(vals) != 1: return "violated"
            # SigningCertificate(V2) ::= SEQUENCE { certs SEQUENCE OF, policies SEQUENCE OPTIONAL } and nothing else; no
            # rule reads policies, T.6 checks only its outer TLV (7.5.6), so a [4] inside it is no directoryName.
            sc = der_seq(vals[0])
            if not 1 <= len(sc) <= 2 or len(sc) == 2 and sc[1][0] != 0x30: return "violated"
            # Every element of certs follows the grammar of Z.6, also where only certs[0] is compared.
            ids = [_z6_cert_id(x, o == A_ESS2) for x in der_seq(sc[0])]
            if not ids: return "violated"
            h, cert_hash, isr = ids[0]
            # issuerSerial names the signer: its serialNumber, and the Name of one directoryName [4] byte-equal to the issuer
            if isr is not None and (signer.issuer not in isr[0] or isr[1] != signer.serial): return "violated"
            if o == A_ESS: ok = hashlib.sha1(signer.der).digest() == cert_hash
            elif h in SHA2: ok = SHA2[h](signer.der).digest() == cert_hash
            else: unchecked = True; continue              # not compared: makes Z.6 not checkable, never violated
            if not ok: return "violated"
        except (ValueError, IndexError): return "violated"
    return "not_checkable" if unchecked else "holds"


def qs(node):
    """Rule QS (7.5.6) over the extensions [1] of the TSTInfo -> "absent", "present", "malformed" or "unusable". It
    reads the extensions only, never searches bytes (a nonce may carry the identifier), and yields no finding."""
    if node is None: return "absent"
    exts = {}
    try:
        if not node[2]: return "unusable"
        for x in der_seq(node, 0xa1):
            der_check(x[1])
            e = der_seq(x)
            if len(e) not in (2, 3): return "unusable"
            o, crit, val = der_oid(e[0]), der_bool(e[1]) if len(e) == 3 else False, der_octets(e[-1])
            # Z.1, T.6, QS item 2: of every extnValue only the outer TLV is checked here, also for qcStatements; content of
            # qcStatements that is not DER is "malformed" after item 4, not unusable (7.5.6, decision L).
            der(val)
            if o in exts: return "unusable"
            exts[o] = (crit, val)
    except ValueError: return "unusable"
    if any(crit and o != QC_STATEMENTS for o, (crit, _v) in exts.items()): return "unusable"
    if QC_STATEMENTS not in exts: return "absent"
    try:                                               # item 4: a deviation from DER here is malformed (decision L)
        sts = der_seq(der(exts[QC_STATEMENTS][1], 0x30))
        ids = []                                       # statementInfo is not evaluated: of it only its outer TLV is read
        for st in sts:
            k = der_seq(st)
            if len(k) not in (1, 2): return "malformed"
            ids.append(der_oid(k[0]))
    except ValueError: return "malformed"
    return "present" if QTST in ids else "absent"


def z4_path(signer, pool, root, at, memo=None):
    """Z.4 (7.5.5): a path c0 = signer, ..., ck byte-equal to root with 0 <= k <= 8, intermediates only from pool (the
    token's certificates), at genTime `at` -> True or False. Existence over every candidate: a walk that repeats a
    certificate shortens to one that does not, with every position no later than before, so the search keeps the
    reachable (certificate, position) pairs and is independent of its order. memo caches signature checks."""
    memo = {} if memo is None else memo

    def fits(c, j):                                   # the conditions on c at position j (Z.3, Z.4)
        why, bc, ku, eku = c.z3()
        if why or not c.not_before <= at <= c.not_after: return False
        if j == 0: return eku is not None and eku[0] == [EKU_TS] and eku[1]
        return (bc is not None and bc[0] and (ku is None or ku & KU_CERT_SIGN) and (bc[1] is None or bc[1] >= j - 1)
                and (eku is None or EKU_TS in eku[0] or EKU_ANY in eku[0]))

    def signs(parent, child):                         # the signature of child holds with the key of parent after Z.2
        k = (parent.der, child.der)
        if k not in memo:
            try:
                key, alg = z2_key(parent), z2_sigalg(child.sigalg)
                memo[k] = key[0] == alg[0] and z2_verify(key, alg, child.sig, child.tbs)
            except Z2Error: memo[k] = False
        return memo[k]

    if not fits(signer, 0): return False
    if signer.der == root.der: return True
    cands = {c.der: c for c in pool if c.der != root.der}
    frontier, seen = [signer], {(signer.der, 0)}
    for j in range(1, 9):
        nxt = []
        for c in frontier:
            if c.issuer == root.subject and fits(root, j) and signs(root, c): return True
            for p in cands.values():
                if p.subject == c.issuer and (p.der, j) not in seen and fits(p, j) and signs(p, c):
                    seen.add((p.der, j)); nxt.append(p)
        frontier = nxt
    return False


def ts_assess(der_bytes, subject, roots):
    """A time stamp after the profile (7.5) -> dict: der_bytes the decoded token, subject the bytes its imprint must
    cover, roots [Cert] to try for Z.4. Members: grammar (why grammar T or the size fails, else ""), t (t_read),
    imprint_ok, step5 ("not_performable", "failed", "holds") with step5_why, signer, z6, qs, paths {root DER: bool}.
    The mapping to findings and states is the caller's (7.3, 7.5.7)."""
    r = {"grammar": "", "t": None, "imprint_ok": None, "step5": None, "step5_why": "", "signer": None, "z6": None, "qs": None, "paths": {}}
    try: r["t"] = t = t_read(der_bytes)
    except TError as exc:
        r["grammar"] = str(exc)
        return r
    r["qs"] = qs(t["extensions"])
    r["imprint_ok"] = SHA2[t["imprint_alg"]](subject).digest() == t["imprint"]
    if not r["imprint_ok"]: return r
    r["step5"], r["step5_why"], r["signer"] = step5(t)
    if r["step5"] != "holds": return r
    r["z6"] = z6(t, r["signer"])
    pool, memo = [Cert(x[1]) for x in der_seq(t["certificates"], 0xa0)], {}
    r["paths"] = {c.der: z4_path(r["signer"], pool, c, t["gen_ns"], memo) for c in roots}
    return r


def day_token_state(r, roots, test_spki):
    """The column "Tageszeitstempel" of 7.5.7 for an assessment r (ts_assess) against roots of one purpose -> (state,
    reason): "defective", "unconfirmed" or "confirmed" with the case of registry verifier.timestamp_profile.outcomes,
    the topmost row that applies deciding; None when confirmed. test_spki: the SPKI SHA-256 values of published_test_keys.
    The row of published_test_keys applies when the signer's SPKI stands there or every root with a path after Z.4
    does; a path to a root outside it lets the following rows decide (7.5.7)."""
    if r["grammar"]: return "defective", "b64_size_or_grammar_t"
    if not r["imprint_ok"]: return "defective", "imprint_wrong"
    if r["step5"] == "not_performable": return "unconfirmed", "step_5_not_performable"
    if r["step5"] == "failed": return "defective", "step_5_failed"
    if r["z6"] == "violated": return "defective", "z6_failed"
    if r["z6"] == "not_checkable": return "unconfirmed", "z6_not_checkable"
    chained = [c for c in roots if r["paths"].get(c.der)]
    if not chained: return "unconfirmed", "no_path_to_root_of_purpose"
    if r["signer"].spki_sha256 in test_spki or all(c.spki_sha256 in test_spki for c in chained): return "unconfirmed", "published_test_key"
    return "confirmed", None


def test_spki(reg):
    """The SPKI SHA-256 values of the time-stamping keys in published_test_keys (7.5.7)."""
    return {k["spki_sha256"] for k in reg["verifier"]["timestamp_profile"]["published_test_keys"] if "spki_sha256" in k}


def _package_tsa(files):
    """keys/tsa/ of the package (7.3, 10.1): never a root and no evidence; only to tell in the report that the token
    chains to nothing but what the package brings along. A file that does not read names nothing."""
    out = []
    for n in sorted(x for x in files if x.startswith("keys/tsa/")):
        try: out += strict_pem(files[n].decode("latin-1"))
        except ValueError: pass
    return out


def load_package(path):
    """Read a verification package from a directory or a ZIP archive (10.1)."""
    files, is_dir = {}, os.path.isdir(path)
    if is_dir:
        for r, dirs, names in os.walk(path):             # followlinks=False: a link is listed, never followed
            for n in dirs + names:                       # 10.1: no symbolic link, nothing but files and directories
                if os.path.islink(os.path.join(r, n)) or (n in names and not os.path.isfile(os.path.join(r, n))):
                    raise ValueError(f"{os.path.relpath(os.path.join(r, n), path)!r} is a symbolic link or no regular file (10.1)")
            for n in names:
                with open(os.path.join(r, n), "rb") as fh:
                    files[os.path.relpath(os.path.join(r, n), path).replace(os.sep, "/")] = fh.read()
    else:
        with zipfile.ZipFile(path) as z:
            for i in z.infolist():                       # 10.1: names in normal form, none twice
                n = i.filename
                if n.endswith("/"): continue
                if n.startswith("/") or "\\" in n or any(t in ("", ".", "..") for t in n.split("/")) or n in files:
                    raise ValueError(f"ZIP entry {n!r} is not in normal form or occurs twice (10.1)")
                files[n] = z.read(i)
    if "manifest.json" not in files:
        # one wrapping directory is stripped (10.1): every entry inside it - and a directory package that
        # holds exactly that one directory and nothing else (from 1.9), not even an empty directory beside it
        tops = {n.split("/", 1)[0] for n in files}
        if len(tops) == 1 and all("/" in n for n in files) and (not is_dir or len(os.listdir(path)) == 1):
            pre = tops.pop() + "/"
            files = {n[len(pre):]: b for n, b in files.items()}
    return files


# ------------------------------------------------ vendor trust (format.de.md 7.1, 10.7)

KEY_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
SEGMENT_FILE = re.compile(r"[A-Za-z0-9._-]{1,128}")                                # 10.1, besides "." and ".."
PRESENTED = re.compile(r"content/([1-9][0-9]*)\.(salts\.json|request|response)")    # 10.1: presented plaintexts
EXPECT_ROOT = re.compile(r"(?:([1-9][0-9]*):)?([0-9a-fA-F]{64})")                  # 10.8: ROOT or TREE_SIZE:ROOT
HEX64, HEX128 = re.compile(r"[0-9a-f]{64}"), re.compile(r"[0-9a-f]{128}")
UTC = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?Z")  # [0-9]: \d is Unicode


def utc_ns(s):
    """RFC 3339 in UTC with suffix Z, year 0001-9999, any fraction length cut to nanoseconds (10.7), or None."""
    m = UTC.fullmatch(s) if isinstance(s, str) else None
    if not m: return None
    try: d = datetime.datetime(*map(int, m.groups()[:6]), tzinfo=datetime.timezone.utc)
    except ValueError: return None
    return int(d.timestamp()) * 10**9 + int((m.group(7) or "0")[:9].ljust(9, "0"))


def ms(s):
    """The tolerance checks of 8.2, 8.5 and 9.2 count whole milliseconds (2): the fraction is cut after its third
    digit. Floor division of the nanoseconds does exactly that, before 1970 too - the epochs lie whole seconds apart."""
    return utc_ns(s) // 10**6


class NumberError(ValueError):
    """A JSON number outside the integer profile of Section 2: FORMAT_ERROR wherever it stands in the package."""


def _int53(s):
    # 2^53-1 has 16 digits: a longer integer lies outside before int() reads it, which refuses more than 4300 digits
    # (sys.get_int_max_str_digits()) with a ValueError that is no number verdict. The rule of 2 knows no length.
    if len(s.lstrip("-").lstrip("0")) > 16 or abs(int(s)) > MAX_INT: raise NumberError(f"number {s} lies outside -(2^53-1) .. 2^53-1 (2)")
    return int(s)


def _no_int(s): raise NumberError(f"number {s} is no integer without fraction and exponent (2)")


def _no_json(s): raise ValueError(f"{s} is no JSON (RFC 8259): a syntax error, not a number verdict")


def _no_dups(pairs):
    d = dict(pairs)
    if len(d) != len(pairs): raise ValueError("duplicate member")
    return d


def jloads(raw):
    """Every JSON text of the package and of the auditor (2, 10.8), read as I-JSON: strict UTF-8 - a byte order mark
    is no JSON -, no member name twice, every number an integer within 2^53-1 without fraction and exponent."""
    return json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw, object_pairs_hook=_no_dups,
                      parse_int=_int53, parse_float=_no_int, parse_constant=_no_json)


def num_scan(b):
    """Every number token where a JSON value may begin, strings skipped (2): a fraction, an exponent or a value beyond
    2^53-1 is NumberError. A token that is no JSON number at all ("-", "01") is a syntax matter, not a number verdict."""
    i, value = 0, True
    while i < len(b):
        c = b[i:i + 1]
        if c == b'"':
            i += 1
            while i < len(b) and b[i:i + 1] != b'"': i += 2 if b[i:i + 1] == b"\\" else 1
            i, value = i + 1, False
        elif c in (b" ", b"\t", b"\n", b"\r"): i += 1
        elif c in (b"[", b",", b":"): i, value = i + 1, True
        elif value and (c == b"-" or c.isdigit()):
            j = i
            while j < len(b) and (b[j:j + 1] in (b"-", b"+", b".", b"e", b"E") or b[j:j + 1].isdigit()): j += 1
            tok = b[i:j].decode(); digits = tok[1:] if tok[:1] == "-" else tok; ip = re.split(r"[.eE]", digits)[0]
            if ip.isdigit() and not (len(ip) > 1 and ip[0] == "0"):
                if ip != digits: _no_int(tok)
                _int53(tok)
            i, value = j, False
        else: i, value = i + 1, False


def _verify_args(raw):
    """10.8: verify_args.json is exactly {"now": rfc3339}; the check time in whole milliseconds."""
    if raw is None: raise ValueError("the package carries none")
    a = jloads(raw)
    if not isinstance(a, dict) or set(a) != {"now"} or utc_ns(a["now"]) is None:
        raise ValueError('it is not exactly {"now": <RFC 3339 UTC instant>}')
    return ms(a["now"])


def vendor_list(raw, roots):
    """The signed key list (10.7), checked against the AUDITOR's roots: (keys, root_id, version, why). Its numbers
    were read in stage 4a (10.5): what is left here makes the list ineffective, never a FORMAT_ERROR."""
    try: v = jloads(raw)
    except Exception as exc: return None, "", 0, f"not JSON: {exc}"
    if not isinstance(v, dict) or set(v) - {"format", "version", "ausgestellt", "schluessel", "signatur"}:
        return None, "", 0, "not an object of the fields format, version, ausgestellt, schluessel, signatur"
    ver, ks, sig = v.get("version"), v.get("schluessel"), v.get("signatur")
    if v.get("format") != "rekorder-herstellerschluessel/1" or type(ver) is not int or not 1 <= ver <= 2**53 - 1:
        return None, "", 0, "format or version invalid"
    if utc_ns(v.get("ausgestellt")) is None or not isinstance(ks, list) or not 1 <= len(ks) <= 64:
        return None, "", 0, "ausgestellt or schluessel (1 to 64 keys) invalid"
    keys, pubs = {}, set()
    for k in ks:
        if not isinstance(k, dict) or set(k) - {"key_id", "pubkey", "gueltig_ab", "gueltig_bis", "widerrufen_ab"} \
                or not all(isinstance(x, str) for x in k.values()):
            return None, "", 0, "schluessel[] entry with undefined or non-string fields"
        kid, pub = k.get("key_id", ""), k.get("pubkey", "")
        if not KEY_ID.fullmatch(kid) or kid in keys or not HEX64.fullmatch(pub) or pub in pubs:
            return None, "", 0, f"key {kid!r}: key_id or pubkey invalid or listed twice"
        ab, bis, wid = (utc_ns(k[f]) if f in k else None for f in ("gueltig_ab", "gueltig_bis", "widerrufen_ab"))
        if ab is None or ("gueltig_bis" in k and (bis is None or bis <= ab)) or ("widerrufen_ab" in k and wid is None):
            return None, "", 0, f"key {kid}: validity timestamps invalid (RFC 3339 UTC, gueltig_bis after gueltig_ab)"
        keys[kid] = (pub, ab, bis, wid, k)
        pubs.add(pub)
    if not isinstance(sig, dict) or set(sig) != {"wurzel_id", "sig"} or not isinstance(sig["sig"], str) \
            or not isinstance(sig["wurzel_id"], str) or not HEX128.fullmatch(sig["sig"]):
        return None, "", 0, "the list is not signed (signatur with wurzel_id and a 128-hex sig)"
    if sig["wurzel_id"] not in roots:
        return None, "", 0, f"signed by root {sig['wurzel_id']!r}, the auditor supplied {', '.join(sorted(roots))}"
    body = {n: x for n, x in v.items() if n != "signatur"}
    if not ed25519_verify(bytes.fromhex(roots[sig["wurzel_id"]]), bytes.fromhex(sig["sig"]), jcsb(body)):
        return None, "", 0, f"the signature of root {sig['wurzel_id']!r} does not verify"
    return keys, sig["wurzel_id"], ver, ""


# ------------------------------------------------ auditor inputs (format.de.md 2, 10.8, from 1.10)
# Everything the auditor passes is read as bytes at invocation, before the package is opened (10.5, 7.4.10 L0). A
# violation of a grammar or limit, an input given more often than allowed and every other usage error is an
# unusable invocation: exit 3 with the reason on stderr and no report. A defect in the content of an input that keeps
# its grammar is never exit 3 (7.4, 8.8, 10.7). Nothing of this is ever read from a package (10.1).

class Unusable(ValueError):
    """An unusable invocation (10.8): exit 3, the reason on the error output, no report."""


PIN = re.compile(r"([A-Za-z0-9._-]{1,64})=([0-9a-f]{64})")         # key-id, "=", hex64 (registry auditor_inputs.inputs)
DATE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})")
LOG_DAY_MIN, LOG_DAY_MAX = "2000-01-01", "9998-12-31"                # date, log range (2)
KEY_LIST_FORMATS = ("rekorder-herstellerschluessel/1", "ledger-schluesselrollen/1", "ledger-protokollschluessel/1")


def is_date(v, log_range=False):
    """Type date (2): YYYY-MM-DD with ASCII digits, an existing date, year 0001 to 9999; log_range: 2000-01-01 to 9998-12-31."""
    m = DATE.fullmatch(v) if isinstance(v, str) else None
    try: datetime.date(*map(int, m.groups())) if m else None
    except ValueError: return False
    return bool(m) and (not log_range or LOG_DAY_MIN <= v <= LOG_DAY_MAX)


def _lone_surrogate(v):
    if isinstance(v, str): return any(0xd800 <= ord(c) <= 0xdfff for c in v)
    if isinstance(v, list): return any(_lone_surrogate(x) for x in v)
    if isinstance(v, dict): return any(_lone_surrogate(k) or _lone_surrogate(x) for k, x in v.items())
    return False


def auditor_json(raw, what):
    """An auditor file (2): I-JSON (no member twice, the number rule, no lone surrogates), UTF-8 without a byte order
    mark -> the value; Unusable otherwise. That its objects are closed is the rule of each file."""
    if raw[:3] == b"\xef\xbb\xbf": raise Unusable(f"{what}: starts with a byte order mark (2)")
    try: v = jloads(raw)
    except Exception as exc: raise Unusable(f"{what}: not I-JSON in UTF-8 (2): {exc}") from None
    if _lone_surrogate(v): raise Unusable(f"{what}: a lone surrogate (2)")
    return v


def read_input(path, what, limit=None):
    """The bytes of an auditor file, at most limit of them (10.8); Unusable when unreadable or larger. Without a limit in
    10.8 (limit None) the file is read up to UNBOUNDED_INPUT_BYTES, as ledger-verify reads it: a device or an endless pipe
    (/dev/zero, <(yes)) is refused with exit 3 in both, never read until the memory runs out."""
    bound = UNBOUNDED_INPUT_BYTES if limit is None else limit
    try:
        with open(path, "rb") as fh: raw = fh.read(bound + 1)
    except (OSError, MemoryError) as exc: raise Unusable(f"{what} {path}: {exc or type(exc).__name__}") from None
    if len(raw) > bound:
        raise Unusable(f"{what} {path}: more than {bound} bytes" + (" (10.8)" if limit is not None else "; a file without a limit in 10.8 is read up to that size"))
    return raw


def _closed(obj, required, optional=(), what="object"):
    """The members of an auditor object: exactly required plus any of optional (2: objects are closed)."""
    if not isinstance(obj, dict) or not set(required) <= set(obj) <= set(required) | set(optional):
        raise ValueError(f"{what} is not an object of exactly {', '.join(sorted(required))}" + (f" and optionally {', '.join(optional)}" if optional else ""))
    return obj


def _s(v, maxlen=None, minlen=0, pattern=None):
    return isinstance(v, str) and minlen <= len(v) <= (maxlen or len(v)) and (pattern is None or re.fullmatch(pattern, v) is not None)


def _i(v, lo=0, hi=MAX_INT): return type(v) is int and lo <= v <= hi


def _arr(v, lo, hi): return isinstance(v, list) and lo <= len(v) <= hi


def extract_grammar(x):
    """The grammar of ledger-protokollauszug/1 (7.4.8) over one extract -> its log_id; ValueError on a violation. Not the
    content of protocol_keys (7.4.7) and not of statement_jcs (7.4.10 L2)."""
    _closed(x, ("format", "log_id", "chain_id", "protocol_keys", "days", "chain_days"), what="the extract")
    if x["format"] != "ledger-protokollauszug/1": raise ValueError("format is not ledger-protokollauszug/1")
    if not _s(x["log_id"], pattern=KEY_ID.pattern): raise ValueError("log_id is no key-id")
    if not (x["chain_id"] is None or _s(x["chain_id"], pattern=_UUID.pattern[1:-1])): raise ValueError("chain_id is neither a uuid nor null")
    if x["protocol_keys"] is not None and not isinstance(x["protocol_keys"], dict): raise ValueError("protocol_keys is neither an object nor null")
    if not _arr(x["days"], 0, 4000) or not _arr(x["chain_days"], 0, 4000): raise ValueError("days or chain_days not an array of 0 to 4000")
    if x["chain_id"] is None and x["chain_days"]: raise ValueError("chain_id is null, chain_days is not empty")
    for d in x["days"]:
        _closed(d, ("entry", "timestamps", "additional_signatures"), what="a day object")
        en = _closed(d["entry"], ("statement_jcs", "server_key_id", "server_signature"), what="entry")
        if not (_s(en["statement_jcs"], 2048) and _s(en["server_key_id"], pattern=KEY_ID.pattern) and _s(en["server_signature"], pattern=HEX128.pattern)):
            raise ValueError("entry: statement_jcs (at most 2048), server_key_id (key-id) or server_signature (hex128) violated")
        if not _arr(d["timestamps"], 0, 4) or not all(_s(t, 21848) for t in d["timestamps"]): raise ValueError("timestamps: 0 to 4 strings of at most 21 848")
        if not _arr(d["additional_signatures"], 0, 3): raise ValueError("additional_signatures: 0 to 3 elements")
        seen = []
        for a in d["additional_signatures"]:
            _closed(a, ("alg", "key_id", "signature"), what="an additional signature")
            if not (_s(a["alg"], pattern=r"[a-z0-9][a-z0-9-]{0,31}") and _s(a["key_id"], pattern=KEY_ID.pattern) and _s(a["signature"], 1024, 1, r"[!-~]+")):
                raise ValueError("an additional signature violates alg, key_id or signature")
            if a["alg"] == "ed25519" and not HEX128.fullmatch(a["signature"]): raise ValueError("an additional ed25519 signature is no hex128")
            if a in seen: raise ValueError("two equal additional signatures in one day object")
            seen.append(a)
    days = set()
    for c in x["chain_days"]:
        _closed(c, ("day", "present", "absent"), what="a chain-day record")
        if not is_date(c["day"], True): raise ValueError("chain_days: day is no date of the log range")
        if c["day"] in days: raise ValueError(f"two chain-day records for {c['day']} in one file")
        days.add(c["day"])
        if (c["present"] is None) == (c["absent"] is None): raise ValueError("not exactly one of present and absent")
        if c["present"] is not None:
            p = _closed(c["present"], ("roots", "leaf_index", "path"), what="present")
            if not _arr(p["roots"], 1, 4096) or not _i(p["leaf_index"]) or not _arr(p["path"], 0, 64) or not all(_s(h, pattern=HEX64.pattern) for h in p["path"]):
                raise ValueError("present: roots (1 to 4096), leaf_index or path (0 to 64 hex64) violated")
            leaves = set()
            for r in p["roots"]:
                _closed(r, ("tree_size", "merkle_root", "recorded_as", "server_ts"), what="a root")
                if not (_i(r["tree_size"], 1) and _s(r["merkle_root"], pattern=HEX64.pattern) and r["recorded_as"] in ("countersigned", "gap_witness")
                        and utc_ns(r["server_ts"]) is not None):
                    raise ValueError("a root violates tree_size, merkle_root, recorded_as or server_ts")
                leaf = (r["recorded_as"], r["tree_size"], r["merkle_root"], r["server_ts"])     # the leaf bytes of 7.4.2 under one chain_id
                if leaf in leaves: raise ValueError("two roots of one record with the same leaf bytes")
                leaves.add(leaf)
        else:
            a = _closed(c["absent"], ("neighbours",), what="absent")
            if not _arr(a["neighbours"], 0, 2): raise ValueError("absent: 0 to 2 neighbours")
            for nb in a["neighbours"]:
                _closed(nb, ("leaf_index", "position", "chain_root", "path"), what="a neighbour")
                if not (_i(nb["leaf_index"]) and _s(nb["position"], pattern=HEX64.pattern) and _s(nb["chain_root"], pattern=HEX64.pattern)
                        and _arr(nb["path"], 0, 64) and all(_s(h, pattern=HEX64.pattern) for h in nb["path"])):
                    raise ValueError("a neighbour violates leaf_index, position, chain_root or path")
            # 7.4.8: neighbours ascend by leaf_index, not falling: equal values keep the grammar.
            if [nb["leaf_index"] for nb in a["neighbours"]] != sorted(nb["leaf_index"] for nb in a["neighbours"]):
                raise ValueError("neighbours are not ascending by leaf_index")
    return x["log_id"]


def history_page_grammar(p):
    """A page of the anchor history (8.8.2): exactly statement_jcs (1 to 131 072 characters), server_key_id (key-id),
    server_signature (hex128) and statement (any value). The content of statement_jcs is step H2's."""
    _closed(p, ("statement_jcs", "server_key_id", "server_signature", "statement"), what="a page")
    if not (_s(p["statement_jcs"], 131072, 1) and _s(p["server_key_id"], pattern=KEY_ID.pattern) and _s(p["server_signature"], pattern=HEX128.pattern)):
        raise ValueError("a page violates statement_jcs, server_key_id or server_signature")


def qualified_file(obj):
    """ledger-tsa-qualifiziert/1 (10.8) -> (stand, quelle, [(Cert, qualifiziert_ab ns, qualifiziert_bis ns or None)]);
    ValueError on every violation, a byte-equal certificate twice included."""
    _closed(obj, ("format", "stand", "quelle", "wurzeln"), what="the file")
    if obj["format"] != "ledger-tsa-qualifiziert/1": raise ValueError("format is not ledger-tsa-qualifiziert/1")
    if utc_ns(obj["stand"]) is None: raise ValueError("stand is no rfc3339 instant")
    if not _s(obj["quelle"], 256, 1, "[^\u0000-\u001f\u007f-\u009f]+"): raise ValueError("quelle: 1 to 256 characters without control characters")
    if not _arr(obj["wurzeln"], 1, 256): raise ValueError("wurzeln: 1 to 256 objects")
    out, seen = [], set()
    for w in obj["wurzeln"]:
        _closed(w, ("zertifikat", "qualifiziert_ab"), ("qualifiziert_bis",), what="an element of wurzeln")
        if not _s(w["zertifikat"], 21848): raise ValueError("zertifikat is no string of at most 21 848 characters")
        raw = b64_decode(w["zertifikat"])
        if len(raw) > 16384: raise ValueError("zertifikat has more than 16 384 bytes")
        cert = Cert(raw)
        ab, bis = utc_ns(w["qualifiziert_ab"]), utc_ns(w["qualifiziert_bis"]) if "qualifiziert_bis" in w else None
        if ab is None or "qualifiziert_bis" in w and (bis is None or bis <= ab):
            raise ValueError("qualifiziert_ab or qualifiziert_bis is no rfc3339 instant, or qualifiziert_bis does not lie after qualifiziert_ab")
        if cert.der in seen: raise ValueError("the same certificate twice: the input is ambiguous")
        seen.add(cert.der)
        out.append((cert, ab, bis))
    return obj["stand"], obj["quelle"], out


class AuditorInputs:
    """What the auditor passes (7.1, 10.7, 10.8), read and checked at invocation by load(); the package is not touched.
    roots: the table of roots for time stamps (7.5.7, 10.8), DER -> {"cert", "purposes", "qualified"}."""

    def __init__(self, vendor_roots=None, vendor_keys=None, tsa_roots=()):
        self.vendor_roots, self.cs_pins, self.statement_pins, self.log_pins = dict(vendor_roots or {}), dict(vendor_keys or {}), {}, {}
        self.key_lists, self.roots, self.qualified, self.extracts, self.history, self.requested_at = [], {}, None, [], [], None
        self.extract_bytes = []          # per extract its bytes as a file: as passed, an embedded one UTF-8(JCS(element)) (8.8.2)
        for c in tsa_roots: self.add_root(c, "chain")

    def add_root(self, cert, purpose, window=None):
        e = self.roots.setdefault(cert.der, {"cert": cert, "purposes": set(), "qualified": None})
        e["purposes"].add(purpose)
        if window is not None: e["qualified"] = window
        if purpose == "qualified": e["purposes"].add("chain")

    def roots_for(self, purpose):
        return [e["cert"] for e in self.roots.values() if purpose in e["purposes"]]

    @classmethod
    def load(cls, args, reg):
        """From the parsed command line -> AuditorInputs; Unusable on every violation (10.8, 7.1, 10.7.4, 7.4.10 L0)."""
        lim = reg["auditor_inputs"]["inputs"]
        self = cls()
        for f in args.vendor_root:                                     # {"wurzel_id", "pubkey"}, nothing else (7.1, 10.7)
            w = auditor_json(read_input(f, "--vendor-root"), f"--vendor-root {f}")
            if not isinstance(w, dict) or set(w) != {"wurzel_id", "pubkey"} or not _s(w["wurzel_id"], pattern=KEY_ID.pattern) or not _s(w["pubkey"], pattern=HEX64.pattern):
                raise Unusable(f"--vendor-root {f}: not exactly {{wurzel_id, pubkey}} with a key-id and 64 lowercase hex (10.7)")
            if self.vendor_roots.get(w["wurzel_id"], w["pubkey"]) != w["pubkey"]: raise Unusable(f"two vendor roots named {w['wurzel_id']!r} with different keys (7.1)")
            self.vendor_roots[w["wurzel_id"]] = w["pubkey"]
        for flag, pins, given in (("--vendor-key", self.cs_pins, args.vendor_key), ("--vendor-statement-key", self.statement_pins, args.vendor_statement_key),
                                  ("--vendor-log-key", self.log_pins, args.vendor_log_key)):
            for k in given:
                m = PIN.fullmatch(k)
                if not m: raise Unusable(f"{flag} {k!r} is not key_id=hex64 (10.8)")
                if pins.get(m[1], m[2]) != m[2]: raise Unusable(f"{flag}: key_id {m[1]!r} pinned twice with different public keys")
                pins[m[1]] = m[2]
        roles = (("--vendor-key", self.cs_pins), ("--vendor-statement-key", self.statement_pins), ("--vendor-log-key", self.log_pins))
        for i, (fa, a) in enumerate(roles):                            # a key in two roles (10.7.4, 7.4.10 L0)
            for fb, b in roles[i + 1:]:
                same = sorted(set(a) & set(b)) or sorted(k for k, v in a.items() if v in b.values())
                if same: raise Unusable(f"{fa} and {fb} name the same key_id or public key ({same[0]}): a key in two roles (10.7.4)")
        for f in args.vendor_key_list:                                 # I-JSON, size, format; the content is 10.7.1, 10.7.2, 7.4.7
            raw = read_input(f, "--vendor-key-list", lim["vendor_key_list"]["max_bytes"])
            v = auditor_json(raw, f"--vendor-key-list {f}")
            if not isinstance(v, dict) or v.get("format") not in KEY_LIST_FORMATS:
                raise Unusable(f"--vendor-key-list {f}: format is missing or none of {', '.join(KEY_LIST_FORMATS)} (10.8)")
            self.key_lists.append((v["format"], v, raw))
        for flag, purpose in (("--tsa-root", "chain"), ("--vendor-log-tsa-root", "log")):
            for f in getattr(args, flag[2:].replace("-", "_")):
                try: certs = strict_pem(read_input(f, flag).decode("latin-1"))
                except ValueError as exc: raise Unusable(f"{flag} {f}: {exc} (10.8)") from None
                for c in certs: self.add_root(c, purpose)
        if args.tsa_qualified_roots is not None:
            f = args.tsa_qualified_roots
            obj = auditor_json(read_input(f, "--tsa-qualified-roots", lim["tsa_qualified_roots"]["max_bytes"]), f"--tsa-qualified-roots {f}")
            try: stand, quelle, roots = qualified_file(obj)
            except ValueError as exc: raise Unusable(f"--tsa-qualified-roots {f}: {exc} (10.8)") from None
            self.qualified = {"stand": stand, "quelle": quelle}
            for c, ab, bis in roots: self.add_root(c, "qualified", (ab, bis))
        vl, ah = lim["vendor_log"], lim["anchor_history"]
        log_bytes, hist_bytes, pages = 0, 0, 0

        def extract(x, raw, where):                                     # one extract, embedded ones counted alike (8.8.2)
            nonlocal log_bytes
            if len(raw) > vl["max_file_bytes"]: raise Unusable(f"{where}: an extract of more than {vl['max_file_bytes']} bytes (7.4.8)")
            log_bytes += len(raw)
            if len(self.extracts) + 1 > vl["max_files"] or log_bytes > vl["max_run_bytes"]:
                raise Unusable(f"{where}: more than {vl['max_files']} extracts or {vl['max_run_bytes']} bytes of extracts in one invocation (7.4.8)")
            try: extract_grammar(x)
            except ValueError as exc: raise Unusable(f"{where}: {exc} (7.4.8)") from None
            self.extracts.append(x)
            self.extract_bytes.append(raw)

        for f in args.vendor_log:
            raw = read_input(f, "--vendor-log", vl["max_file_bytes"])
            extract(auditor_json(raw, f"--vendor-log {f}"), raw, f"--vendor-log {f}")
        if len(args.anchor_history) > ah["max_files"]: raise Unusable(f"more than {ah['max_files']} files of the anchor history (8.8.2)")
        for f in args.anchor_history:
            raw = read_input(f, "--anchor-history", ah["max_file_bytes"])
            hist_bytes += len(raw)
            if hist_bytes > ah["max_run_bytes"]: raise Unusable(f"more than {ah['max_run_bytes']} bytes of the anchor history in one invocation (8.8.2)")
            v = auditor_json(raw, f"--anchor-history {f}")
            try:
                if isinstance(v, dict) and "format" in v:              # a container ledger-ankerhistorie/2
                    _closed(v, ("format", "pages", "vendor_log"), what="the container")
                    if v["format"] != "ledger-ankerhistorie/2" or not _arr(v["pages"], 1, 4096) or not _arr(v["vendor_log"], 0, 128):
                        raise ValueError("format, pages (1 to 4096) or vendor_log (0 to 128) violated")
                    for p in v["pages"]: history_page_grammar(p)
                    found = v["pages"]
                else: history_page_grammar(v); found = [v]
            except ValueError as exc: raise Unusable(f"--anchor-history {f}: {exc} (8.8.2)") from None
            pages += len(found)
            if pages > ah["max_pages"]: raise Unusable(f"more than {ah['max_pages']} pages of the anchor history in one invocation (8.8.2)")
            self.history.append({"file": f, "raw": raw, "pages": found, "container": "format" in v})
            for x in v.get("vendor_log", []) if "format" in v else []:
                extract(x, jcsb(x), f"--anchor-history {f}: an embedded extract")
        if len({x["log_id"] for x in self.extracts}) > 1: raise Unusable("the extracts name different log_id (7.4.10 L0)")
        if args.requested_at is not None:
            if utc_ns(args.requested_at) is None: raise Unusable(f"--requested-at {args.requested_at!r} is no rfc3339 instant in UTC (10.8)")
            self.requested_at = args.requested_at
        return self


def pruefumgebung(path, reg):
    """The audit environment of a test vector, ledger-pruefumgebung/1 (10.8; only in the test corpus) -> the switches
    in the member order of the registry, the files it names resolved beside it; korpus true adds the vendor root and
    the pinned key of the corpus. The check time stays in the vector's verify_args.json. Unusable on a violation of
    its schema (an auditor file, 2: every member present, nothing else)."""
    spec = reg["auditor_inputs"]["pruefumgebung"]
    d, order = auditor_json(read_input(path, "ledger-pruefumgebung/1"), path), spec["member_order"]
    try:
        _closed(d, order, what="ledger-pruefumgebung/1")
        for m, f in spec["fields"].items():
            v, t = d[m], f["type"]
            ok = (v == f["value"] if t == "const" else type(v) is bool if t == "bool" else
                  v is None or _s(v, pattern=f["pattern"][1:-1]) if t == "string?" else v is None or utc_ns(v) is not None if t == "rfc3339?" else
                  isinstance(v, list) and all(_s(x, pattern=f["items"]["pattern"][1:-1]) for x in v))
            if not ok: raise ValueError(f"member {m} violates its type")
    except ValueError as exc: raise Unusable(f"{path}: {exc} (10.8)") from None
    base, out = os.path.dirname(os.path.abspath(path)), []
    for m in order[1:]:
        v = d[m]
        if m == "korpus":
            if v:
                out += ["--vendor-root", os.path.join(base, "pruefer_herstellerwurzel.json")]
                with open(os.path.join(base, "pruefer_herstellerschluessel.txt"), encoding="utf-8") as fh: out += [x for k in fh.read().split() for x in ("--vendor-key", k)]
            continue
        files = spec["fields"][m].get("type") in ("string?",) or "pruefer_" in spec["fields"][m].get("items", {}).get("pattern", "")
        for x in [] if v is None else v if isinstance(v, list) else [v]:
            out += [spec["member_flags"][m], os.path.join(base, x) if files else x]
    return out


# ------------------------------------------------ key roles (format.de.md 10.7.2 to 10.7.4, 7.4.7, 7.4.10 L1)

def _list_keys(ks, max_keys, with_role):
    """The schluessel of a list of 10.7 (with rolle for the role list) -> [entry]; ValueError on a violation."""
    if not _arr(ks, 1, max_keys): raise ValueError(f"schluessel is not an array of 1 to {max_keys} objects")
    ids, pubs = set(), set()
    for k in ks:
        _closed(k, ("key_id", "pubkey", "gueltig_ab") + (("rolle",) if with_role else ()), ("gueltig_bis", "widerrufen_ab"), what="an element of schluessel")
        if not all(isinstance(x, str) for x in k.values()): raise ValueError("a value of schluessel[] is no string")
        if not KEY_ID.fullmatch(k["key_id"]) or not HEX64.fullmatch(k["pubkey"]) or k["key_id"] in ids or k["pubkey"] in pubs:
            raise ValueError(f"key {k['key_id']!r}: key_id or pubkey invalid or listed twice")
        if with_role and not re.fullmatch(r"[a-z][a-z_]{0,31}", k["rolle"]): raise ValueError(f"key {k['key_id']}: rolle violates its grammar")
        if with_role and k["rolle"] == "protocol": raise ValueError(f"key {k['key_id']}: the reserved rolle protocol")
        ab, bis = utc_ns(k["gueltig_ab"]), utc_ns(k["gueltig_bis"]) if "gueltig_bis" in k else None
        if ab is None or "gueltig_bis" in k and (bis is None or bis <= ab) or "widerrufen_ab" in k and utc_ns(k["widerrufen_ab"]) is None:
            raise ValueError(f"key {k['key_id']}: validity instants invalid (rfc3339, gueltig_bis after gueltig_ab)")
        ids.add(k["key_id"]); pubs.add(k["pubkey"])
    return ks


def _signed_by_root(v, roots, extra_check=None):
    """The signature of a root-signed list (10.7) -> (stage, why): "no_matching_root", "format" (extra_check with the
    root's public key), "signature" or "" when it holds."""
    sig = v.get("signatur")
    if not isinstance(sig, dict) or set(sig) != {"wurzel_id", "sig"} or not _s(sig["wurzel_id"], pattern=KEY_ID.pattern) or not _s(sig["sig"], pattern=HEX128.pattern):
        return "format", "signatur is not exactly wurzel_id (key-id) and sig (hex128)"
    if sig["wurzel_id"] not in roots: return "no_matching_root", f"no vendor root of the auditor named {sig['wurzel_id']!r}"
    if extra_check and extra_check(roots[sig["wurzel_id"]]): return "format", extra_check(roots[sig["wurzel_id"]])
    body = {n: x for n, x in v.items() if n != "signatur"}
    if not ed25519_verify(bytes.fromhex(roots[sig["wurzel_id"]]), bytes.fromhex(sig["sig"]), jcsb(body)):
        return "signature", f"the signature of root {sig['wurzel_id']!r} does not hold"
    return "", ""


def role_list(v, roots):
    """A role list ledger-schluesselrollen/1 (10.7.2) -> (reason, why): reason "" when it counts (R1), else "format",
    "no_matching_root" or "signature"."""
    try:
        _closed(v, ("format", "version", "ausgestellt", "schluessel", "signatur"), ("ende_doppelbetrieb",), what="the role list")
        if v["format"] != "ledger-schluesselrollen/1" or not _i(v["version"], 1): raise ValueError("format or version invalid")
        if utc_ns(v["ausgestellt"]) is None or "ende_doppelbetrieb" in v and utc_ns(v["ende_doppelbetrieb"]) is None:
            raise ValueError("ausgestellt or ende_doppelbetrieb is no rfc3339 instant")
        _list_keys(v["schluessel"], 256, True)
    except ValueError as exc: return "format", str(exc)
    return _signed_by_root(v, roots, lambda pub: "an entry names the public key of the root" if any(k["pubkey"] == pub for k in v["schluessel"]) else "")


def protocol_list(v, roots):
    """A protocol key list ledger-protokollschluessel/1 (7.4.7) -> (reason, why) as role_list, the reasons in the
    words of registry vendor_log.no_protocol_key_reasons: format_violated, no_matching_root, signature_fails."""
    try:
        _closed(v, ("format", "version", "ausgestellt", "log_id", "erster_tag", "fuellerbindung", "orte", "schluessel", "signatur"), what="the protocol key list")
        if v["format"] != "ledger-protokollschluessel/1" or not _i(v["version"], 1) or utc_ns(v["ausgestellt"]) is None:
            raise ValueError("format, version or ausgestellt invalid")
        # 7.4.7: fuellerbindung is hex64, or null for a vendor that does not derive its fillers (7.4.4).
        if not _s(v["log_id"], pattern=KEY_ID.pattern) or not is_date(v["erster_tag"], True) or not (v["fuellerbindung"] is None or _s(v["fuellerbindung"], pattern=HEX64.pattern)):
            raise ValueError("log_id, erster_tag or fuellerbindung invalid")
        if not _arr(v["orte"], 2, 4) or not all(_s(o, pattern=r"https://[!-~]{1,248}") for o in v["orte"]): raise ValueError("orte invalid")
        _list_keys(v["schluessel"], 64, False)
    except ValueError as exc: return "format_violated", str(exc)
    reason, why = _signed_by_root(v, roots)
    return {"format": "format_violated", "signature": "signature_fails"}.get(reason, reason), why


def _effective(cands, judge, keys_of, same):
    """R1/R2 and L1 item 2 over distinct candidates (JCS bytes) -> (effective list or None, reason, counting, reasons):
    the counting candidate of the largest version; none if two counting candidates share a version, one lacks an entry
    of a smaller version or same() finds a contradiction (reason "lists_contradictory")."""
    counting, reasons = [], []
    for v in cands:
        r, _why = judge(v)
        (reasons.append(r) if r else counting.append(v))
    if not counting: return None, None, counting, reasons
    by_v = sorted(counting, key=lambda v: v["version"])
    if len({v["version"] for v in counting}) != len(counting) or same(by_v): return None, "lists_contradictory", counting, reasons
    for i, small in enumerate(by_v):
        if any(not keys_of(small) <= keys_of(big) for big in by_v[i + 1:]): return None, "lists_contradictory", counting, reasons
    return by_v[-1], None, counting, reasons


def _distinct(lists):
    out, seen = [], set()
    for v in lists:
        b = jcsb(v)
        if b not in seen: seen.add(b); out.append(v)
    return out


def key_roles(inputs, package_list_keys, reg, package_list_ids=()):
    """The role check (10.7.4, R1 to R4) with step L1 items 2 and 3 (7.4.10) -> dict: report (the object key_roles of
    10.10.2 without the note receipt_key_other_role, which the receipts add), Q (effective role list or None), P
    (effective protocol key list or None) with p_reason, cs_pins / statement_pins / log_pins (those not dropped), kcs_l
    (K_cs^L, public keys) and kcs_l_ids (their key_id, read by H2 number 1 of 8.8.4), auditor_cs_lists (judged
    auditor lists of countersigning keys)."""
    roots = inputs.vendor_roots
    kcs_l, kcs_ids, aud_cs = set(package_list_keys), set(package_list_ids), []
    for fmt, v, raw in inputs.key_lists:                               # auditor lists of countersigning keys: K_cs^L only (10.7.1)
        if fmt != KEY_LIST_FORMATS[0]: continue
        keys, root_id, ver, why = vendor_list(raw, roots)
        aud_cs.append({"version": ver, "wurzel_id": root_id, "effective": keys is not None, "why": why})
        if keys is not None: kcs_l |= {k[0] for k in keys.values()}; kcs_ids |= set(keys)
    rl = _distinct([v for fmt, v, _raw in inputs.key_lists if fmt == KEY_LIST_FORMATS[1]])
    # R2: ende_doppelbetrieb compared as strings; a larger version must carry it once a smaller one does.
    def dual_end(by_v):
        vals = {v["ende_doppelbetrieb"] for v in by_v if "ende_doppelbetrieb" in v}
        return len(vals) > 1 or any("ende_doppelbetrieb" in s and "ende_doppelbetrieb" not in b for i, s in enumerate(by_v) for b in by_v[i + 1:])
    q, q_reason, _c, q_reasons = _effective(rl, lambda v: role_list(v, roots), lambda v: {(k["key_id"], k["pubkey"], k["rolle"]) for k in v["schluessel"]}, dual_end)
    if q is None and q_reason is None and q_reasons:                   # the candidate that came furthest (10.7.4, Bericht)
        q_reason = max(q_reasons, key=["format", "no_matching_root", "signature"].index)
    pl = _distinct([v for fmt, v, _raw in inputs.key_lists if fmt == KEY_LIST_FORMATS[2]] + [x["protocol_keys"] for x in inputs.extracts if x["protocol_keys"] is not None])
    log_ids = {x["log_id"] for x in inputs.extracts}
    def proto_same(by_v):
        """L1 item 2 over the counting candidates, ascending by version: different log_id or erster_tag; two different
        fuellerbindung other than null; or null in a candidate while one of a smaller version names a value (once set,
        unchanged in every later version, 7.4.7)."""
        fb = [v["fuellerbindung"] for v in by_v]
        return (len({(v["log_id"], v["erster_tag"]) for v in by_v}) > 1 or len({x for x in fb if x is not None}) > 1
                or any(fb[j] is None and fb[i] is not None for i in range(len(fb)) for j in range(i + 1, len(fb))))
    p, p_reason, p_counting, p_reasons = _effective(pl, lambda v: protocol_list(v, roots), lambda v: {(k["key_id"], k["pubkey"]) for k in v["schluessel"]}, proto_same)
    if p is not None and log_ids and any(v["log_id"] not in log_ids for v in p_counting): p, p_reason = None, "log_id_differs"
    if p is None and p_reason is None: p_reason = max(p_reasons, key=["format_violated", "no_matching_root", "signature_fails"].index) if p_reasons else "no_list"
    role_of = lambda lst: {k["pubkey"]: k["rolle"] for k in lst["schluessel"]} if lst else {}
    if q is not None and any(r != "countersigning" for pub, r in role_of(q).items() if pub in kcs_l): q, q_reason = None, "key_in_two_roles"    # R3 (a)
    p_pubs = {k["pubkey"] for k in p["schluessel"]} if p else set()
    if q is not None and p is not None and p_pubs & set(role_of(q)): q, q_reason, p, p_reason = None, "key_in_two_roles", None, "key_in_two_roles"  # (b)
    if p is not None and p_pubs & (kcs_l | set(inputs.cs_pins.values())): p, p_reason = None, "key_in_two_roles"                                # (c)
    p_pubs, q_roles = ({k["pubkey"] for k in p["schluessel"]} if p else set()), role_of(q)
    dropped, keep = [], {"countersigning": {}, "statements": {}, "protocol": {}}
    for role, pins in (("countersigning", inputs.cs_pins), ("statements", inputs.statement_pins), ("protocol", inputs.log_pins)):     # (d)
        for kid, pub in pins.items():
            listed = ("countersigning" if role != "countersigning" and pub in kcs_l else
                      "protocol" if role == "statements" and pub in p_pubs else
                      q_roles[pub] if pub in q_roles and (q_roles[pub] != role or role == "protocol") else None)
            if listed: dropped.append({"key_id": kid, "pinned_as": role, "listed_as": listed})
            else: keep[role][kid] = pub
    st = {kid: "pinned" for kid in keep["statements"]}
    for k in q["schluessel"] if q else ():
        if k["rolle"] == "statements": st.setdefault(k["key_id"], "role_list")
    known = reg["key_role_list"]["roles"]
    report = {"status": "not_supplied" if not rl else "effective" if q else "not_effective", "reason": None if q or not rl else q_reason,
              "candidates": len(rl), "list": None if q is None else {"version": q["version"], "ausgestellt": q["ausgestellt"], "wurzel_id": q["signatur"]["wurzel_id"],
                                                                      "root_source": "vendor_root", "ende_doppelbetrieb": q.get("ende_doppelbetrieb")},
              "statement_keys": [{"key_id": k, "source": st[k]} for k in sorted(st)], "pins_dropped": sorted(dropped, key=lambda d: d["key_id"]),
              "notes": ["unknown_role"] if q and any(k["rolle"] not in known for k in q["schluessel"]) else []}
    return {"report": report, "Q": q, "P": p, "p_reason": None if p else p_reason, "cs_pins": keep["countersigning"], "statement_pins": keep["statements"],
            "log_pins": keep["protocol"], "kcs_l": kcs_l, "kcs_l_ids": kcs_ids, "auditor_cs_lists": aud_cs,
            "other_role": {pub for pub, r in q_roles.items() if r != "countersigning"} | p_pubs | set(inputs.statement_pins.values()) | set(inputs.log_pins.values())}


def finish_key_roles(report, other_role_note):
    """The notes of key_roles in the registry order: unknown_role, receipt_key_other_role, pin_dropped (10.7.4)."""
    notes = set(report["notes"]) | ({"receipt_key_other_role"} if other_role_note else set()) | ({"pin_dropped"} if report["pins_dropped"] else set())
    report["notes"] = [n for n in ("unknown_role", "receipt_key_other_role", "pin_dropped") if n in notes]
    return report


# ------------------------------------------------ vendor log (format.de.md 7.4, from 1.10)
# The auditor passes the log as extracts (7.4.8, read at invocation in L0); nothing of it is ever read from the package
# (7.4.1). Step L1 ran with the role check (key_roles, 7.4.10 L1 items 2 and 3); vendor_log() below takes the protocol
# keys from it and runs L1 item 4 and steps L2 to L10 after the receipts (10.5 stage 5, step 6). It adds only the five
# classes of 7.4.11, all of exit class 1, and the report object vendor_log (10.10.2); it changes no other result.

VL_DAY_LEAF, VL_POSITION, VL_GAP_WITNESS = "ledger.vendor_log_day_leaf.v1", "ledger.vendor_log_position.v1", "ledger.vendor_log_gap_witness.v1"
VL_DAY_KIND = "ledger.vendor_log_day.v1"
VL_DAY_MEMBERS = ("day", "first_day", "kind", "log_id", "prev_hash", "root", "server_ts", "tree_size")    # 7.4.5
SERVER_TS_MS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z")             # 7.4.5: exactly YYYY-MM-DDThh:mm:ss.sssZ
VL_UNVERIFIED, VL_DEFECTIVE, VL_CONTRADICTION = "VENDOR_LOG_UNVERIFIED", "VENDOR_LOG_DEFECTIVE", "VENDOR_LOG_CONTRADICTION"


def day_ord(d):
    """A day of type date (2) -> its ordinal (0001-01-01 is 1), so dn(d) = day_ord(d) - 1. Previous and next days are
    computed on these integers, never as calendar dates (2, Tagesarithmetik)."""
    return datetime.date(int(d[0:4]), int(d[5:7]), int(d[8:10])).toordinal()


def day_text(o): return datetime.date.fromordinal(o).isoformat()


def day_end_ms(o):
    """end(d) (2): (dn(d) + 1) * 86 400 000 ms since 0001-01-01, here in ms since 1970 like every other instant of this
    verifier; both epochs lie whole days apart, so every comparison and difference is the same."""
    return (o - EPOCH_ORDINAL + 1) * 86400000


def lh(x): return hashlib.sha256(b"\x00" + x).digest()       # LH(x) = SHA-256(0x00 || x) (7.4.10)


def vl_leaf(chain_id, row):
    """The leaf of a recording row (7.4.2, Blatt aus der Aufzeichnung): countersigned gives the countersignature, gap_witness
    the gap witness, each with exactly these values; server_ts enters as the string the row carries."""
    o = {"chain_id": chain_id, "merkle_root": row["merkle_root"], "server_ts": row["server_ts"], "tree_size": row["tree_size"]}
    if row["recorded_as"] == "gap_witness": o["kind"] = VL_GAP_WITNESS
    return jcsb(o)


def vl_chain_root(leaves):
    """chain_root(C, d) (7.4.3): MTH (5) over the leaves of a chain day, ascending by their leaf hash LH as unsigned
    32-byte values, whatever the order they are named in."""
    return mth(sorted(set(leaves), key=lh))


def vl_position(appliance_id, chain_id, day):
    """position(C, d) (7.4.3) with A = GENESIS.appliance_id of the package."""
    return hashlib.sha256(jcsb({"appliance_id": appliance_id, "chain_id": chain_id, "day": day, "kind": VL_POSITION})).hexdigest()


def vl_day_leaf(chain_root_hex, position_hex):
    """The leaf of the day tree (7.4.3, 7.4.4): a chain-day leaf or a filler, the same form and kind."""
    return jcsb({"chain_root": chain_root_hex, "kind": VL_DAY_LEAF, "position": position_hex})


def vl_absent_holds(p, n, root, neighbours):
    """The absence proof of 5 for position p in the tree (n, root): exactly one of the forms (i) to (iv), every neighbour
    leaf holding by inclusion against (n, root). Positions compare as their lowercase hex text (= unsigned 32 bytes)."""
    for nb in neighbours:
        if not verify_inclusion(lh(vl_day_leaf(nb["chain_root"], nb["position"])), nb["leaf_index"], n, [bytes.fromhex(h) for h in nb["path"]], root):
            return False
    if not neighbours: return n == 0                                                                   # (i)
    if len(neighbours) == 1:
        nb = neighbours[0]
        return (nb["leaf_index"] == 0 and p < nb["position"]) or (nb["leaf_index"] == n - 1 and nb["position"] < p)   # (ii), (iii)
    a, b = neighbours
    return b["leaf_index"] == a["leaf_index"] + 1 and a["position"] < p < b["position"]                 # (iv)


def vl_record(rec, chain_id, n, root, p):
    """A chain-day record (7.4.10 L6) against n and root of c(d) and the position p -> None when it does not hold, else
    ("present", chain_root hex, {LH of its leaves}, roots) or ("absent", None, set(), [])."""
    if rec["present"] is not None:
        pr = rec["present"]
        leaves = [vl_leaf(chain_id, r) for r in pr["roots"]]
        cr = vl_chain_root(leaves).hex()
        if not verify_inclusion(lh(vl_day_leaf(cr, p)), pr["leaf_index"], n, [bytes.fromhex(h) for h in pr["path"]], root): return None
        return "present", cr, {lh(x) for x in leaves}, pr["roots"]
    return ("absent", None, set(), []) if vl_absent_holds(p, n, root, rec["absent"]["neighbours"]) else None


def vl_content(s, log_id):
    """The content of a statement_jcs after 7.4.5 (7.4.10 L2 (c)) -> (object, "") or (None, why): printable ASCII, I-JSON
    without a member twice, its own JCS form, exactly the members with their types, kind, log_id equal to that of the
    extracts, the log range of day and first_day, server_ts exactly YYYY-MM-DDThh:mm:ss.sssZ."""
    if not all(" " <= ch <= "~" for ch in s): return None, "statement_jcs is not printable ASCII (2)"
    try: v = jloads(s)
    except Exception as exc: return None, f"statement_jcs is not I-JSON: {exc}"
    if not isinstance(v, dict): return None, "statement_jcs is no object"
    if jcs(v) != s: return None, "statement_jcs is not the JCS form of its own content"
    if set(v) != set(VL_DAY_MEMBERS): return None, "not exactly the members " + ", ".join(VL_DAY_MEMBERS)
    if not (is_date(v["day"], True) and is_date(v["first_day"], True)): return None, "day or first_day is no date of the log range"
    if v["kind"] != VL_DAY_KIND: return None, f"kind is not {VL_DAY_KIND}"
    if not _s(v["log_id"], pattern=KEY_ID.pattern) or v["log_id"] != log_id: return None, f"log_id is not {log_id}, that of the extracts"
    if not (_s(v["prev_hash"], pattern=HEX64.pattern) and _s(v["root"], pattern=HEX64.pattern)): return None, "prev_hash or root is no hex64"
    if not (isinstance(v["server_ts"], str) and SERVER_TS_MS.fullmatch(v["server_ts"]) and utc_ns(v["server_ts"]) is not None):
        return None, f"server_ts {v['server_ts']!r} is not exactly of the form YYYY-MM-DDThh:mm:ss.sssZ"
    if not _i(v["tree_size"]): return None, "tree_size is no int 0 to 2^53-1"
    return v, ""


def vl_day_of(s):
    """dayOf(o) (7.4.10 L2): the member day when statement_jcs reads as an I-JSON object (2, a member twice refused) with a
    member day of type date; else None, and the finding has no day."""
    try: v = jloads(s)
    except Exception: return None
    if not isinstance(v, dict) or _lone_surrogate(v) or not is_date(v.get("day")): return None
    return v["day"]


_VL_STEP = re.compile(r"L([0-9]+)(?: \(([a-z])\))?")


class _VlFindings:
    """The findings of the vendor log after "Mehrfachmeldungen" (7.4.11): per class and UTC day at most one finding with
    its reasons in the order of the steps, at most one per class without a day; the runs of missing days, RECEIPT_NOT_LOGGED
    per day and LOGGED_ROOT_MISMATCH per (tree_size, merkle_root) are findings of their own."""

    def __init__(self, reg):
        self.reasons, self.items = reg["vendor_log"]["finding_reasons"], {}
        self.rank = {}
        for cls, codes in self.reasons.items():
            if cls == "comment": continue
            for i, (code, r) in enumerate(codes.items()):
                m = _VL_STEP.fullmatch(r["step"])
                self.rank[(cls, code)] = (int(m[1]), m[2] or "", i)

    def note(self, cls, day, code, extra=""):
        """day: the day as YYYY-MM-DD or None; extra: what the finding names besides the reason (key, day hashes, ...)."""
        lst = self.items.setdefault((cls, day), [])
        if (code, extra) not in lst: lst.append((code, extra))

    def own(self, cls, key, detail):
        self.items[(cls, key)] = detail

    def days_with(self, cls): return {day for (c, day), v in self.items.items() if c == cls and isinstance(day, str) and isinstance(v, list)}

    def emit(self, res):
        for (cls, day), v in self.items.items():
            if isinstance(v, str): res.add(cls, v); continue
            parts = [self.reasons[cls][code]["en"] + (f" ({extra})" if extra else "") for code, extra in sorted(v, key=lambda x: self.rank[(cls, x[0])])]
            res.add(cls, f"{day or 'without day'}: " + "; ".join(parts) + " (7.4.10, 7.4.11)")


def vl_judge_stamp(text, subject, roots, tspki, memo):
    """A day time stamp (7.4.6) after 7.5.7, column Tageszeitstempel -> {"state", "reason", "gen_ns", "r"}: a violation of
    B64 or of the 16 384 bytes of the DER makes it defective, like grammar T. r is the assessment (ts_assess) with a path
    per root of the purpose log, which condition (7) of the evidence level reads (10.9.3)."""
    k = (text, subject)
    if k not in memo:
        try: r = ts_assess(b64_decode(text), subject, roots)
        except ValueError as exc: r = {"grammar": f"violates grammar B64: {exc}", "t": None}
        state, reason = day_token_state(r, roots, tspki)
        memo[k] = {"state": state, "reason": reason, "gen_ns": r["t"]["gen_ns"] if r["t"] else None, "r": r}
    return memo[k]


def vendor_log(res, inputs, reg, entries, root, held, now, lc_seq):
    """The vendor log after 7.4.10 L1 item 4 and L2 to L10 -> (the report object vendor_log of 10.10.2, what later steps
    read: per receipt its class, whether a VENDOR_LOG_CONTRADICTION lies without a day or in [Lo, T], t_m, the recorded
    roots beyond the package and the checked records). held: the CHECKPOINT_RECEIPT entries whose signature holds under
    the key of 7.1 and that have no RECEIPT_INVALID (L8), in chain order; lc_seq: the seq of the receipt 8.6 chooses as the last countersigned one, or 0."""
    vl, tm = reg["vendor_log"], reg["vendor_log"]["time"]
    W, MIN, DUE, FUT = tm["token_window_ms"], tm["token_min_offset_ms"], tm["publication_offset_ms"], vl["receipt_classes"]["future_tolerance_ms"]
    ex, log_roots, tspki = inputs.extracts, inputs.roots_for("log"), test_spki(reg)
    rep = {"status": "not_supplied", "log_id": None, "first_day": None, "key_source": None, "key_list": None, "places": [], "files": 0,
           "distinct_files": 0, "head": None, "days": {"supplied": 0, "established": 0, "witnessed": 0, "contradictory": 0, "missing": 0,
                                                       "signatures_not_checked": 0},
           "tsa": {"cms_checked": True, "roots_supplied": 0}, "receipts": None, "last_countersigned": None, "logged_roots": None,
           "foreign_chain_records": 0}
    # canon: per usable day its end(d) and the judged time stamps of c(d), for condition (7) of the evidence level (10.9.3);
    # proto_pubs and p_root: the established protocol keys and the root of the effective protocol key list (10.9.6).
    state = {"status": "not_supplied", "classes": [], "contradiction_in_range": False, "t_m": None, "beyond": [], "records": {},
             "canon": {}, "proto_pubs": set(), "p_root": None}
    if not ex: return rep, state                                       # L0: without an extract not_supplied, L2 to L9 dropped
    out = _VlFindings(reg)
    raws = list(inputs.extract_bytes) + [jcsb(x) for x in ex[len(inputs.extract_bytes):]]
    distinct = {}
    file_no = [distinct.setdefault(b, len(distinct)) for b in raws]    # files counted by distinct bytes (L4, 10.10.2)
    log_id = ex[0]["log_id"]                                           # L0: every extract names the same
    rep.update(log_id=log_id, files=len(ex), distinct_files=len(distinct))
    rep["tsa"]["roots_supplied"] = len(log_roots)

    # L1 items 1, 4 and 5: the established protocol keys -> (public key, end of validity in ns or None); a pin that is not
    # dropped takes precedence for its key_id and has no end (item 1).
    P, pins = res.roles["P"], res.roles["log_pins"]
    keys = {}
    for k in P["schluessel"] if P else ():
        ends = [utc_ns(k[f]) for f in ("gueltig_bis", "widerrufen_ab") if f in k]
        keys[k["key_id"]] = (k["pubkey"], min(ends) if ends else None)
    for kid, pub in pins.items(): keys[kid] = (pub, None)
    state["proto_pubs"], state["p_root"] = {pub for pub, _end in keys.values()}, (P["signatur"]["wurzel_id"] if P else None)
    if not keys:                                                       # item 4: once without a day, L2 to L9 dropped
        reason = res.roles["p_reason"] or "no_list"
        # 7.4.10 L1 item 4 (decision C): with no list effective and every protocol pin dropped by item 3 (R3 (d)) the
        # reason is "Schluessel in zwei Rollen" (key_in_two_roles), since that is why no key remains. No key remains,
        # so a pin passed was dropped; this holds whatever the reason no list is effective, not only without a list.
        if inputs.log_pins: reason = "key_in_two_roles"
        out.note(VL_UNVERIFIED, None, "no_protocol_key", vl["no_protocol_key_reasons"]["texts"][reason]["en"])
        out.emit(res)
        # 10.10.2, days (decision F): with status no_protocol_key step L2 does not run; supplied and
        # signatures_not_checked stay 0.
        rep["status"] = state["status"] = "no_protocol_key"
        state["reason"] = reason
        return rep, state
    rep.update(status="checked", key_source="list_and_pinned" if P and pins else "list" if P else "pinned")
    state["status"] = "checked"
    if P:
        rep["key_list"] = {"version": P["version"], "ausgestellt": P["ausgestellt"], "wurzel_id": P["signatur"]["wurzel_id"], "root_source": "vendor_root"}
        rep["places"] = list(P["orte"])

    # L2: the day objects of all extracts pooled; equal statement_jcs are one object, its time stamps a set of distinct
    # strings, its signatures a set of distinct pairs (an ed25519 element of additional_signatures included); elements of
    # another alg a set of distinct elements, counted and never checked (7.4.8).
    pool = {}
    for i, x in enumerate(ex):
        for d in x["days"]:
            s = d["entry"]["statement_jcs"]
            o = pool.setdefault(s, {"stmt": s, "ts": {}, "pairs": {}, "other": set(), "files": set()})
            for t in d["timestamps"]: o["ts"].setdefault(t, None)
            o["pairs"].setdefault((d["entry"]["server_key_id"], d["entry"]["server_signature"]), None)
            for a in d["additional_signatures"]:
                if a["alg"] == "ed25519": o["pairs"].setdefault((a["key_id"], a["signature"]), None)
                else: o["other"].add((a["alg"], a["key_id"], a["signature"]))
            o["files"].add(file_no[i])
    objs = list(pool.values())
    rep["days"].update(supplied=len(objs), signatures_not_checked=sum(len(o["other"]) for o in objs))
    memo, passed = {}, []
    for o in objs:                                                     # (a) to (e) for every object
        s, dof = o["stmt"], vl_day_of(o["stmt"])
        mine = [(k, sig) for k, sig in o["pairs"] if k in keys]
        if not mine:                                                   # (a)
            out.note(VL_UNVERIFIED, dof, "key_not_established", ", ".join(sorted({k for k, _ in o["pairs"]})))
            continue
        holding = []
        for k, sig in mine:                                            # (b)
            if ed25519_verify(bytes.fromhex(keys[k][0]), bytes.fromhex(sig), s.encode()): holding.append(k)
            else: out.note(VL_DEFECTIVE, dof, "signature", f"key {k}")
        if not holding: continue
        v, why = vl_content(s, log_id)                                 # (c)
        if v is None:
            out.note(VL_CONTRADICTION, dof, "entry_format", why)
            continue
        o.update(content=v, day=v["day"], ord=day_ord(v["day"]), hash=hashlib.sha256(s.encode()).hexdigest())
        o["judged"] = [vl_judge_stamp(t, s.encode(), log_roots, tspki, memo) for t in o["ts"]]   # (d)
        # (e): a holding pair counts with a key without an end, or with a confirmed stamp whose full genTime lies before
        # the end of its key, compared to the nanosecond (2).
        if not any(keys[k][1] is None or any(j["state"] == "confirmed" and j["gen_ns"] < keys[k][1] for j in o["judged"]) for k in holding):
            out.note(VL_UNVERIFIED, v["day"], "key_validity_ended", ", ".join(sorted(set(holding))))
            continue
        passed.append(o)
    # (f) the start F: the list's erster_tag; with pins only the common first_day of the objects that passed (a) to (e).
    F, contradictory_start = (P["erster_tag"] if P else None), False
    if not P:
        starts = {o["content"]["first_day"] for o in passed}
        if len(starts) == 1: F = starts.pop()
        elif starts:
            contradictory_start = True
            out.note(VL_CONTRADICTION, None, "no_common_first_day", ", ".join(sorted(starts)))
    rep["first_day"] = F
    established = []
    for o in passed if not contradictory_start else ():
        v, d = o["content"], o["ord"]
        end = day_end_ms(d)
        broken = []                                                    # (g) the rules of the log
        if v["day"] < F: broken.append(f"day {v['day']} lies before the start {F}")
        if (v["prev_hash"] == ZERO) != (v["day"] == F):
            broken.append("prev_hash is 64 zeros on a day other than the start" if v["day"] != F else "prev_hash is not 64 zeros on the start")
        if v["tree_size"] == 0 and v["root"] != MTH_EMPTY.hex(): broken.append("tree_size 0 with a root other than SHA-256 of the empty string")
        if ms(v["server_ts"]) < end: broken.append(f"server_ts {v['server_ts']} lies before the end of the day")
        if v["first_day"] != F: broken.append(f"first_day {v['first_day']} is not the start {F}")
        if broken:
            out.note(VL_CONTRADICTION, v["day"], "entry_rules", "; ".join(broken))
            continue
        established.append(o)                                          # (h)
        if any(j["state"] == "defective" for j in o["judged"]): out.note(VL_DEFECTIVE, v["day"], "timestamp_defective")
        conf = [j["gen_ns"] // 10**6 for j in o["judged"] if j["state"] == "confirmed"]          # genTime cut to whole ms (2)
        o["broken"] = any(g < end + MIN for g in conf)
        if o["broken"]: out.note(VL_CONTRADICTION, v["day"], "closed_before_day_end")
        o["witnessed"] = not o["broken"] and any(end + MIN <= g < end + W for g in conf)
    rep["days"]["established"] = len(established)

    # L3 days: S(d), Wt(d) and the canonical entry c(d); a day is usable if c(d) is determined and witnessed.
    S, c = {}, {}
    for o in established: S.setdefault(o["ord"], []).append(o)
    for d, lst in S.items():
        if len(lst) >= 2: out.note(VL_CONTRADICTION, day_text(d), "two_versions", "day hashes " + ", ".join(sorted(o["hash"] for o in lst)))
        wt = [o for o in lst if o["witnessed"]]
        whole = [o for o in lst if not o["broken"]]
        if len(wt) == 1: c[d] = wt[0]
        elif not wt and len(whole) == 1: c[d] = whole[0]
    usable = {d for d, o in c.items() if o["witnessed"]}
    rep["days"]["witnessed"] = len(usable)
    # 10.9.3, for condition (7): per usable day the time stamps of c(d) itself, never those of a later day (7.4.6).
    state["canon"] = {day_text(d): {"end": day_end_ms(d), "stamps": list(c[d]["judged"])} for d in usable}
    # L4 head: the latest day with c(d) determined; seen_in counts the distinct files that carry its statement_jcs.
    head = max(c) if c else None
    if head is not None:
        h = c[head]
        rep["head"] = {"day": h["day"], "day_hash": h["hash"], "tree_size": h["content"]["tree_size"], "witnessed": h["witnessed"], "seen_in": len(h["files"])}
    # L5 chaining
    for d in sorted(c):
        if d + 1 in c and c[d + 1]["content"]["prev_hash"] != c[d]["hash"]:
            out.note(VL_CONTRADICTION, day_text(d + 1), "does_not_link", f"prev_hash {c[d + 1]['content']['prev_hash']}, day hash of {day_text(d)} {c[d]['hash']}")
        if F is not None and d > day_ord(F) and not S.get(d - 1):
            x = max((o["ord"] for o in established if o["hash"] == c[d]["content"]["prev_hash"] and o["ord"] < d - 1), default=None)
            if x is not None: out.note(VL_CONTRADICTION, day_text(d), "skips_days", f"the days {day_text(x + 1)} to {day_text(d - 1)}")

    # L6 chain-day records: only those of extracts with chain_id = C; those of other chains are counted and passed over,
    # those on days that are not usable are not used. n and R always come from c(d), never from the record.
    C, A, N = res.chain_id, entries[0]["payload"]["appliance_id"], len(entries)
    recs = {}
    for x in ex:
        if x["chain_id"] != C:
            # 7.4.10 L6, 10.10.2 foreign_chain_records (decision G): every record of every extract counts, also an equal
            # record in several files, like files.
            rep["foreign_chain_records"] += len(x["chain_days"])
            continue
        for r in x["chain_days"]: recs.setdefault(day_ord(r["day"]), []).append(r)
    rstate = {}                                                        # usable day -> (state, M(d), roots of a present record)
    for d in sorted(usable):
        v, p = c[d]["content"], vl_position(A, C, day_text(d))
        holding = []
        for r in recs.get(d, []):
            got = vl_record(r, C, v["tree_size"], bytes.fromhex(v["root"]), p)
            if got is None: out.note(VL_DEFECTIVE, day_text(d), "record_does_not_hold")
            else: holding.append(got)
        if not recs.get(d): rstate[d] = ("none", set(), [])
        elif not holding: rstate[d] = ("failed", set(), [])
        else:
            other_day = sorted({r["server_ts"] for h in holding for r in h[3] if r["server_ts"][:10] != day_text(d)})
            if other_day: out.note(VL_CONTRADICTION, day_text(d), "leaf_of_other_day", ", ".join(other_day))
            if len({(h[0], h[1]) for h in holding}) > 1: out.note(VL_CONTRADICTION, day_text(d), "two_chain_day_records")
            rstate[d] = ("contradictory", set(), []) if other_day or len({(h[0], h[1]) for h in holding}) > 1 else ("verified", holding[0][2], holding[0][3])
            if rstate[d][0] == "verified": state["records"][day_text(d)] = holding[0][3]

    # L7 the required range [Lo, T]: every day there without an established entry is missing, one finding per run.
    due = lambda d: now >= day_end_ms(d) + DUE
    rdays = [day_ord(r["payload"]["server_ts"][:10]) for r in held]
    rdf = [d for d in rdays if F is None or d >= day_ord(F)]
    tops = ([head] if head is not None else []) + [d for d in rdf if due(d)]
    lo_t = (min(rdf), max(tops)) if rdf and tops and not contradictory_start else None
    missing = [d for d in range(lo_t[0], lo_t[1] + 1) if not S.get(d)] if lo_t and lo_t[0] <= lo_t[1] else []
    rep["days"]["missing"] = len(missing)
    run = []
    for d in missing + [None]:
        if run and (d is None or d != run[-1] + 1):
            a, b = day_text(run[0]), day_text(run[-1])
            out.own(VL_UNVERIFIED, ("run", a), f"{a} to {b}: " + vl["finding_reasons"][VL_UNVERIFIED]["days_not_supplied"]["en"]
                    + f" ({len(run)} day{'s' if len(run) > 1 else ''} of the required range {day_text(lo_t[0])} to {day_text(lo_t[1])}) (7.4.10 L7)")
            run = []
        if d is not None: run.append(d)

    # L8 receipts, in chain order; the topmost case that applies holds.
    def nw_reason(o):                                                  # case 4: the reason of day_not_witnessed, None if every stamp is defective
        if not o["ts"]: return "no_timestamp"
        if all(j["state"] == "defective" for j in o["judged"]): return None
        if not log_roots: return "no_log_root_supplied"
        rank = ("outside_profile", "not_chained_to_log_root", "published_test_key", "late")
        # 7.4.10 L8 case 4 (decision I): a stamp unconfirmed because Z.6 is not checkable (7.5.7) gives outside_profile.
        got = [{"step_5_not_performable": "outside_profile", "z6_not_checkable": "outside_profile", "no_path_to_root_of_purpose": "not_chained_to_log_root",
                "published_test_key": "published_test_key"}[j["reason"]] if j["state"] == "unconfirmed" else "late"
               for j in o["judged"] if j["state"] != "defective"]
        return max(got, key=rank.index)
    counts = {k: 0 for k in vl["receipt_classes"]["order"]}
    not_logged, cls_of = {}, {}
    for e in held:
        p, s = e["payload"], e["payload"]["server_ts"]
        d = day_ord(s[:10])
        leaf = lh(jcsb({"chain_id": e["chain_id"], "merkle_root": p["merkle_root"], "server_ts": s, "tree_size": p["tree_size"]}))
        sub = None
        if contradictory_start: cls, sub = "unchecked", "first_day_contradictory"
        elif F is not None and d < day_ord(F): cls = "before_start"
        elif ms(s) > now + FUT:
            cls = "future"
            out.note(VL_UNVERIFIED, s[:10], "receipt_after_check_time", f"seq {e['seq']}, server_ts {s}")
        elif d in usable:
            st, M, _roots = rstate[d]
            if st == "verified": cls = "included" if leaf in M else "not_included"
            else:
                cls, sub = "unchecked", {"none": "no_record", "failed": "record_failed", "contradictory": "record_contradictory"}[st]
                if st == "none": out.note(VL_UNVERIFIED, s[:10], "no_chain_day_record")
        elif d in c:
            cls, sub = "unchecked", "day_not_witnessed"
            why = nw_reason(c[d])
            if why: out.note(VL_UNVERIFIED, s[:10], "day_not_witnessed", vl["not_witnessed_reasons"]["texts"][why]["en"])
        elif S.get(d): cls, sub = "unchecked", "day_contradictory"
        else: cls = "missing" if due(d) else "pending"
        counts[cls] += 1
        cls_of[e["seq"]] = cls
        state["classes"].append({"seq": e["seq"], "tree_size": p["tree_size"], "class": cls, "subclass": sub, "day": s[:10], "server_ts": s})
        if cls == "not_included": not_logged.setdefault(s[:10], []).append(e["seq"])
    for d, seqs in not_logged.items():
        out.own("RECEIPT_NOT_LOGGED", d, f"{d}: " + vl["finding_reasons"]["RECEIPT_NOT_LOGGED"]["not_included"]["en"]
                + f": {len(seqs)} receipt{'s' if len(seqs) > 1 else ''}, smallest seq {min(seqs)} (7.4.10 L8)")
    # r5' of 10.9.4: the largest tree_size t of a good receipt such that every receipt with tree_size <= t is good or neutral
    good = [x["tree_size"] for x in state["classes"] if x["class"] == "included"]
    r5 = max((t for t in good if all(y["class"] in ("included", "before_start") for y in state["classes"] if y["tree_size"] <= t)), default=0)
    rep["receipts"] = dict(counts, included_up_to_tree_size=r5 or None)
    rep["last_countersigned"] = cls_of.get(lc_seq)

    # L9 recorded roots of the checked present records: they match the package, contradict it or lie beyond it; they are
    # no expected roots and anchor nothing.
    # "ein Blatt countersigned ohne Quittung desselben Blatts im Paket" (7.4.10 L9): every CHECKPOINT_RECEIPT of the package
    # counts, also one with RECEIPT_INVALID; the leaf does not hold the signature (7.4.2).
    receipt_leaves = {jcsb({"chain_id": e["chain_id"], "merkle_root": e["payload"]["merkle_root"], "server_ts": e["payload"]["server_ts"],
                            "tree_size": e["payload"]["tree_size"]}) for e in entries if e["event_type"] == "CHECKPOINT_RECEIPT"}
    # 10.10.2, logged_roots (decisions E and K): matching_prefix, contradicting_prefix, beyond_package and gap_witnesses
    # count distinct roots (tree_size, merkle_root), gap_witnesses among the checked rows recorded as gap_witness;
    # matching_without_receipt counts distinct leaves.
    lr = {k: set() for k in ("matching_prefix", "matching_without_receipt", "contradicting_prefix", "beyond_package", "gap_witnesses")}
    for d in sorted(rstate) if not contradictory_start else ():
        if rstate[d][0] != "verified": continue
        for row in rstate[d][2]:
            t, r = row["tree_size"], row["merkle_root"]
            if row["recorded_as"] == "gap_witness": lr["gap_witnesses"].add((t, r))
            if t > N:
                lr["beyond_package"].add((t, r))
                state["beyond"].append({"day": day_text(d), "tree_size": t, "merkle_root": r, "recorded_as": row["recorded_as"], "server_ts": row["server_ts"]})
            elif root[t] == r:
                lr["matching_prefix"].add((t, r))
                if row["recorded_as"] == "countersigned" and vl_leaf(C, row) not in receipt_leaves: lr["matching_without_receipt"].add(vl_leaf(C, row))
            else:
                if (t, r) not in lr["contradicting_prefix"]:
                    out.own("LOGGED_ROOT_MISMATCH", ("root", t, r), f"{day_text(d)}: " + vl["finding_reasons"]["LOGGED_ROOT_MISMATCH"]["root_differs"]["en"]
                            + f": recorded as {row['recorded_as']}, tree_size {t}, merkle_root {r}, the package's root {root[t]} (7.4.10 L9)")
                lr["contradicting_prefix"].add((t, r))
    rep["logged_roots"] = {k: len(x) for k, x in lr.items()}
    state["t_m"] = min((t for t, _r in lr["contradicting_prefix"]), default=None)
    contra_days = out.days_with(VL_CONTRADICTION)
    rep["days"]["contradictory"] = len(contra_days)
    state["contradiction_in_range"] = (VL_CONTRADICTION, None) in out.items or bool(lo_t and any(lo_t[0] <= day_ord(x) <= lo_t[1] for x in contra_days))
    out.emit(res)
    return rep, state


def vendor_log_text(rep, state, vl, lang):
    """The block of the vendor log in the text report (10.10.3), each phrase from registry vendor_log.texts; for the
    status checked three lines from checked_head (or checked_no_head), receipts and compare in this order, the first
    unindented, the other two indented by two spaces, the layout of the block of the anchor history."""
    t = {k: x[lang] for k, x in vl["texts"].items()}
    if rep["status"] == "not_supplied": return t["not_supplied"]
    if rep["status"] == "no_protocol_key": return t["no_protocol_key"].format(reason=vl["no_protocol_key_reasons"]["texts"][state["reason"]][lang])
    h = rep["head"]
    start = t["checked_head"].format(log_id=rep["log_id"], day=h["day"], day_hash=h["day_hash"], witnessed=t["yes" if h["witnessed"] else "no"],
                                     seen_in=h["seen_in"], distinct_files=rep["distinct_files"]) if h else t["checked_no_head"].format(log_id=rep["log_id"])
    # Without a head only the first line is replaced; the other two, the advice to compare the day hash included, stay.
    return "\n".join((start, "  " + t["receipts"].format(**rep["receipts"]), "  " + t["compare"]))


# ------------------------------------------------ anchor history and affiliation (format.de.md 8.8, from 1.10)
# The auditor passes the pages of the anchor history (8.8.2, read at invocation in H0) and optionally the request time
# R; nothing of it is ever read from the package, and the affiliation is never derived from GENESIS, the manifest, the
# vendor log or the evidence level (8.8). Steps H1 to H7 run after the vendor log (10.5 stage 5, step 7), the
# classification H8 at the comparison of the expected roots (step 8), H9 to H11 after the time witnesses (step 11),
# the affiliation H12 and the report objects H13 after the exit code (step 15). The four classes of 8.8.7 all have
# exit class 1; the one way to exit 2 is MERKLE_INCONSISTENT from a root the vendor countersigned or recorded as a gap
# witness before R - W_h (8.8.5). A root that is only reported never gives exit 2 on its own.

AH_KIND, AH_OWNER_KIND = "ledger.anchor_history.v2", "ledger.anchor_history.owner.v1"
AH_U, AH_D, AH_C, AH_F = "ANCHOR_HISTORY_UNVERIFIED", "ANCHOR_HISTORY_DEFECTIVE", "ANCHOR_HISTORY_CONTRADICTION", "ANCHOR_HISTORY_FORK"
AH_RECORDED = ("countersigned", "gap_witness")                       # "festgehalten" (8.8.5); reported is "nur gemeldet"
AH_REC_RANK = {"countersigned": 0, "gap_witness": 1, "reported": 2}  # page rule 3 (heartbeat spec 9.7)
AH_PKG_USES = ("used_fresh", "used_stale", "used_unjudged")
AH_AFFILIATION_REASONS = ("affiliation_narrowed", "affiliation_withheld", "known_range_narrowed")      # 8.8.6 number 9


def ah_commitment(appliance_id, chain_id, device_pubkey):
    """An owner commitment (heartbeat spec 9.7): Hex(SHA-256(UTF-8(JCS({appliance_id, chain_id, device_pubkey, kind}))))."""
    return hashlib.sha256(jcsb({"appliance_id": appliance_id, "chain_id": chain_id, "device_pubkey": device_pubkey, "kind": AH_OWNER_KIND})).hexdigest()


def ms_text(m):
    """An instant the verifier forms itself, from whole milliseconds, as YYYY-MM-DDThh:mm:ss.sssZ (10.10.1)."""
    d = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(milliseconds=m)
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (m % 1000)


def _ah_type(v, spec, path):
    """A value against a field of registry cloud_statements.anchor_history_v2 (heartbeat spec 9.7) -> "" or why. Every
    instant is exactly YYYY-MM-DDThh:mm:ss.sssZ unless the field admits any fraction (server_ts in roots, 8.8.4 H2 5)."""
    t = spec["type"]
    if t.endswith("?"):
        if v is None: return ""
        t = t[:-1]
    if t == "object":
        if not isinstance(v, dict) or set(v) != set(spec["fields"]): return f"{path} is not an object of exactly the members {', '.join(sorted(spec['fields']))}"
        return next((w for w in (_ah_type(v[k], s, f"{path}.{k}") for k, s in spec["fields"].items()) if w), "")
    if t == "array":
        if not isinstance(v, list) or not spec.get("min_items", 0) <= len(v) <= spec.get("max_items", MAX_INT):
            return f"{path} is not an array of {spec.get('min_items', 0)} to {spec.get('max_items', 'any number of')} elements"
        return next((w for w in (_ah_type(x, spec["items"], f"{path}[{i}]") for i, x in enumerate(v)) if w), "")
    if t == "const": ok = isinstance(v, str) and v == spec["value"]
    elif t == "uuid": ok = isinstance(v, str) and _UUID.fullmatch(v) is not None
    elif t == "hex64": ok = isinstance(v, str) and HEX64.fullmatch(v) is not None
    elif t == "int": ok = type(v) is int and v >= spec.get("min", -MAX_INT)
    elif t == "bool": ok = isinstance(v, bool)
    elif t == "enum": ok = isinstance(v, str) and v in spec["values"]
    elif t == "rfc3339": ok = isinstance(v, str) and utc_ns(v) is not None and (spec.get("fraction") == "any" or SERVER_TS_MS.fullmatch(v) is not None)
    else: return f"{path}: registry type {t!r} is unknown to this verifier version: loud, not silent"
    return "" if ok else f"{path} is not of type {spec['type']}" + ("" if t != "rfc3339" else " (exactly YYYY-MM-DDThh:mm:ss.sssZ)" * (spec.get("fraction") != "any"))


def ah_in_range(t, v):
    """t lies in the range I(P) = [since_tree_size, next_since_tree_size) of page content v (8.8.4)."""
    return v["since_tree_size"] <= t and (v["next_since_tree_size"] is None or t < v["next_since_tree_size"])


def ah_page_rules(v):
    """The page rules 1 to 10 of heartbeat spec 9.7 over a page whose members and types hold -> "" or the first rule
    broken. Instants compare in whole milliseconds (9.7, format spec 2)."""
    since, nxt, ts = v["since_tree_size"], v["next_since_tree_size"], ms(v["server_ts"])
    roots, forks = v["roots"], v["forks"]
    sizes = [x["tree_size"] for x in roots] + [x["tree_size"] for x in forks]
    if (nxt is None) != (v["truncated"] is False): return "rule 1: next_since_tree_size is not null exactly when truncated is true"
    if nxt is not None and (nxt <= since or any(nxt <= t for t in sizes)): return "rule 1: next_since_tree_size is not above since_tree_size and every tree_size of the page"
    if any(not ah_in_range(t, v) for t in sizes): return "rule 2: a tree_size of roots or forks lies outside the range of the page"
    rk = [(x["tree_size"], ms(x["server_ts"]), AH_REC_RANK[x["recorded_as"]], x["merkle_root"]) for x in roots]
    if any(a >= b for a, b in zip(rk, rk[1:])) or len({(x["tree_size"], x["merkle_root"], x["recorded_as"]) for x in roots}) != len(roots):
        return "rule 3: roots do not ascend strictly by tree_size, server_ts, recorded_as and merkle_root, or a root stands twice"
    fk = [(x["tree_size"], ms(x["detected_ts"]), x["merkle_root"]) for x in forks]
    if any(a >= b for a, b in zip(fk, fk[1:])) or len({(x["tree_size"], x["merkle_root"]) for x in forks}) != len(forks):
        return "rule 4: forks do not ascend strictly by tree_size, detected_ts and merkle_root, or a fork stands twice"
    if any(ms(x["server_ts"]) > ts for x in roots) or any(ms(x["detected_ts"]) > ts for x in forks):
        return "rule 5: a server_ts of a root or a detected_ts lies after the server_ts of the page"
    if any(x["tree_size"] > v["reference_tree_size"] for x in roots if x["recorded_as"] in AH_RECORDED):
        return "rule 6: reference_tree_size is below the tree_size of a countersigned or gap witness root"
    ids = [x["chain_id"] for x in (v["predecessor"], v["successor"]) if x is not None]
    if v["chain_id"] in ids or len(set(ids)) != len(ids): return "rule 7: predecessor and successor do not differ from chain_id and from each other"
    ok = v["owner_keys"]
    if not 1 <= len(ok) <= 16 or any(a >= b for a, b in zip(ok, ok[1:])): return "rule 8: owner_keys do not ascend strictly or have not 1 to 16 entries"
    ks = v["affiliation"]["known_since"]
    if ks is not None and ms(ks) > ts: return "rule 9: known_since lies after server_ts"
    ps = v["affiliation"]["periods"]
    for i, p in enumerate(ps):
        b, f, u = p["bases"], ms(p["from"]), p["until"]
        if not b or any(x >= y for x, y in zip(b, b[1:])): return "rule 10: bases are empty or do not ascend strictly"
        if not f < ts or ms(p["recorded_ts"]) > ts: return "rule 10: from does not lie before server_ts, or recorded_ts lies after it"
        if u is not None and not f < ms(u) <= ts: return "rule 10: until does not lie after from and not after server_ts"
        if i + 1 < len(ps):
            if u is None: return "rule 10: a period other than the last has until null"
            if ms(u) > ms(ps[i + 1]["from"]): return "rule 10: the periods are not ordered by from or overlap"
            if ms(u) == ms(ps[i + 1]["from"]) and b == ps[i + 1]["bases"]: return "rule 10: two adjoining periods have the same bases"
    return ""


def ah_content(s, reg):
    """H2 numbers 3 to 5 (8.8.4) over a statement_jcs whose signature holds -> (page object, None, None, "") or (None,
    number, reason, why): page_rules at number 3 (form) or 5 (content), not_v2 at number 4 (kind)."""
    if not all(" " <= ch <= "~" for ch in s): return None, 3, "page_rules", "statement_jcs is not printable ASCII (2)"
    try: v = jloads(s)
    except Exception as exc: return None, 3, "page_rules", f"statement_jcs is not I-JSON: {exc}"
    if not isinstance(v, dict) or _lone_surrogate(v): return None, 3, "page_rules", "statement_jcs is no I-JSON object"
    if jcs(v) != s: return None, 3, "page_rules", "statement_jcs is not the JCS form of its own content"
    if v.get("kind") != AH_KIND: return None, 4, "not_v2", f"kind is {str(v.get('kind'))[:80]!r}, not {AH_KIND}"
    why = _ah_type(v, {"type": "object", "fields": reg["cloud_statements"]["anchor_history_v2"]["fields"]}, "page") or ah_page_rules(v)
    return (None, 5, "page_rules", why) if why else (v, None, None, "")


def ah_coverage(ranges):
    """H4: the union of the ranges [a, b) (b None: infinity) -> {"status", "gaps"}; a gap is a maximal contiguous range
    not covered, [a, b) with None for infinity, ascending by a."""
    gaps, pos = [], 0
    for a, b in sorted(ranges, key=lambda r: r[0]):
        if a > pos: gaps.append([pos, a])
        if b is None: pos = None; break
        pos = max(pos, b)
    if pos is not None: gaps.append([pos, None])
    return {"status": "none" if not ranges else "complete" if not gaps else "partial", "gaps": gaps}


def _uncovered(a, b, cover):
    """Whether some instant t with a <= t < b (b None: infinity) lies in no interval [c, d) of cover (d None: infinity)."""
    pos = a
    for c, d in sorted(cover, key=lambda x: x[0]):
        if b is not None and pos >= b: return False
        if c > pos: return True
        if d is None: return False
        pos = max(pos, d)
    return b is None or pos < b


class AnchorHistory:
    """The anchor history as an auditor input (8.8.4 steps H1 to H13, 8.8.5, 8.8.6). ctx: what the run of the chain
    knows before step 7 of stage 5: C, A, N, root (root[t]), PK (the device keys of the package after 6.4), gen_pred
    (GENESIS.predecessor_chain.chain_id or None), held (the receipts that count as an anchor after 7.1), est (the seq
    of those whose key is pinned or from the package's effective list: belegte Quittungen), kcs_ids (key_id of K_cs)
    and records (the checked chain-day records of C on usable days of the vendor log, 7.4.10 L6)."""

    def __init__(self, res, inputs, reg, ctx):
        self.res, self.inputs, self.reg, self.ctx = res, inputs, reg, ctx
        self.ah, self.af = reg["verifier"]["anchor_history"], reg["verifier"]["affiliation"]
        self.W = self.ah["w_h_ms"]
        self.R = ms(inputs.requested_at) if inputs.requested_at is not None else None
        self.supplied = bool(inputs.history)
        self.page_f = {}         # (class, reason) -> pages, H2 (one finding per class and reason)
        self.agg = {}            # (class, reason) -> [count, detail of the earliest occurrence]
        self.own = []            # findings of their own: per (t, r) or per day, (class, reason, detail)
        self.notes, self.blocking, self.contradictory = set(), set(), False
        self.pages, self.plist, self.n_supplied = {}, [], 0
        self.used_pkg, self.linked, self.rel = [], {}, {}
        self.coverage = {"status": "none", "gaps": []}
        self.hroots, self.hforks, self.distinct_roots, self.not_used_log = {}, {}, 0, 0
        self.found_history, self.merkle_from_history, self.own_reasons_f, self.roots_h = [], False, set(), {}
        self.counts = dict.fromkeys(("distinct", "found", "differing_before_request", "differing_after_request", "beyond_package_before_request",
                                     "beyond_package_recent", "beyond_package_after_request", "beyond_package_unjudged", "not_used_vendor_log"), 0)
        self.rcounts = dict.fromkeys(("checked", "in_history", "not_in_history", "not_in_history_unestablished", "server_ts_differs",
                                      "before_legacy_boundary", "not_covered"), 0)
        self.completeness = {"status": "not_established", "reason": "not_supplied", "up_to_tree_size": None}

    # -- finding helpers
    def note(self, cls, reason, detail, blocking=None):
        """One finding per class and reason (8.8.7, Mehrfachmeldungen): the count and the earliest occurrence."""
        x = self.agg.setdefault((cls, reason), [0, detail])
        x[0] += 1
        if blocking: self.blocking.add(blocking)

    def reason_text(self, reason): return self.ah["page_reason_texts"].get(reason, {}).get("en", reason.replace("_", " "))

    def key_of(self, kid):
        """8.8.3 -> (source, public key, entry of Q or None): a statements pin not dropped first, without a window; else
        the entry of the effective role list Q with rolle statements; else (None, reason of H2 number 1, None)."""
        roles, q = self.res.roles, self.res.roles["Q"]
        if kid in roles["statement_pins"]: return "pinned", roles["statement_pins"][kid], None
        qk = q["schluessel"] if q else []
        k = next((k for k in qk if k["key_id"] == kid and k["rolle"] == "statements"), None)
        if k is not None: return "role_list", k["pubkey"], k
        # H2 number 1: a key of K_cs, of the effective protocol key list, a protocol pin not dropped, or an entry of Q
        # with another role; a dropped pin counts for nothing.
        other = kid in self.ctx["kcs_ids"] or kid in roles["log_pins"] or any(k["key_id"] == kid for k in (roles["P"]["schluessel"] if roles["P"] else ())) \
            or any(k["key_id"] == kid for k in qk)
        return None, "key_other_role" if other else "key_not_established", None

    def revoked(self, src, pub, entry):
        """H2 number 9: the entry of the key in the role list carries widerrufen_ab; for a pin, an entry of Q with rolle
        statements and the same public key (8.8.3 item 1)."""
        if src == "role_list": return "widerrufen_ab" in entry
        q = self.res.roles["Q"]
        return any(k["rolle"] == "statements" and k["pubkey"] == pub and "widerrufen_ab" in k for k in (q["schluessel"] if q else ()))

    @staticmethod
    def in_window(entry, ts_ns):
        """H2 number 6 for a key from the role list (a pin has no window): gueltig_ab <= server_ts < gueltig_bis and
        server_ts < widerrufen_ab, as far as present, to the nanosecond (10.7)."""
        if entry is None: return True
        ab, bis, wid = (utc_ns(entry[f]) if f in entry else None for f in ("gueltig_ab", "gueltig_bis", "widerrufen_ab"))
        return ab <= ts_ns and (bis is None or ts_ns < bis) and (wid is None or ts_ns < wid)

    def fail(self, o, number, reason, why=""):
        o["fail"], o["why"] = (number, reason), why

    def fail_pairs(self, o, reached):
        """Every pair failed at number 1, 2 or 6: the page fails with the reason of the pair that came furthest; of
        several that came equally far, with the reason that stands later in registry page_reasons (8.8.4, Mehrere Paare:
        at number 1 key_other_role before key_not_established)."""
        top = max(n for n, _k, _r in reached)
        self.fail(o, top, max((r for n, _k, r in reached if n == top), key=self.ah["page_reasons"].index))

    # -- H1 and H2
    def h1(self):
        """H1: all pages of all files pooled; equal statement_jcs are one page with the set of its distinct pairs."""
        for h in self.inputs.history:
            for i, p in enumerate(h["pages"]):
                self.n_supplied += 1
                o = self.pages.get(p["statement_jcs"])
                if o is None:
                    where = f"--anchor-history {h['file']}" + (f", page {i + 1} of the container" if h.get("container") else "")
                    o = self.pages[p["statement_jcs"]] = {"s": p["statement_jcs"], "pairs": {}, "where": where, "order": len(self.pages),
                                                         "v": None, "fail": None, "use": None, "bad_pairs": 0, "passed8": False, "chain5": None}
                o["pairs"].setdefault((p["server_key_id"], p["server_signature"]), None)
        self.plist = list(self.pages.values())

    def h2_1_to_6(self, o):
        """H2 numbers 1 to 6. Numbers 1, 2, 6 (and 9) concern the pairs: a page passes while one pair passes the number and
        every earlier one of them. Every pair under an established key whose signature fails is DEFECTIVE signature."""
        reached, alive = [], []
        for kid, sig in sorted(o["pairs"]):
            src, pub, entry = self.key_of(kid)
            if src is None: reached.append((1, kid, pub)); continue
            if not ed25519_verify(bytes.fromhex(pub), bytes.fromhex(sig), o["s"].encode()):
                o["bad_pairs"] += 1
                reached.append((2, kid, "signature")); continue
            alive.append((kid, sig, src, pub, entry))
        if o["bad_pairs"]: self.page_f.setdefault((AH_D, "signature"), []).append(o)
        if not alive: return self.fail_pairs(o, reached)
        v, number, reason, why = ah_content(o["s"], self.reg)
        if v is None: return self.fail(o, number, reason, why)
        o["chain5"] = v["chain_id"]        # numbers 1 to 5 hold: the chain_id is read from established bytes (H9)
        ts = utc_ns(v["server_ts"])
        good = [p for p in alive if self.in_window(p[4], ts)]
        reached += [(6, p[0], "key_not_valid") for p in alive if p not in good]
        if not good: return self.fail_pairs(o, reached)
        o["v"], o["alive"] = v, good

    def h2_8_to_10(self, o, linked):
        """H2 numbers 8 to 10 for a package page (linked False) or a linked page."""
        v, ctx = o["v"], self.ctx
        oc = {ah_commitment(ctx["A"], v["chain_id"], k) for k in ctx["PK"]}
        if not oc & set(v["owner_keys"]): return self.fail(o, 8, "owner_differs")
        o["passed8"] = True
        o["fresh"] = self.R is not None and ms(v["server_ts"]) >= self.R - self.W
        good = [p for p in o["alive"] if o["fresh"] or not self.revoked(p[2], p[3], p[4])]
        if not good: return self.fail(o, 9, "signing_time_not_proven")
        o["pair"] = min(good, key=lambda p: p[0].encode())          # the report pair: the smallest server_key_id (bytes)
        o["use"] = "used_linked" if linked else "used_fresh" if o["fresh"] else "used_stale" if self.R is not None else "used_unjudged"

    def h2(self):
        C = self.ctx["C"]
        for o in self.plist: self.h2_1_to_6(o)
        for o in self.plist:                                           # number 7: pages of the package first
            if o["v"] is not None and o["v"]["chain_id"] == C: self.h2_8_to_10(o, False)
        self.used_pkg = [o for o in self.plist if o["use"] in AH_PKG_USES]
        rel = {}
        if self.ctx["gen_pred"]: rel[self.ctx["gen_pred"]] = "predecessor"    # GENESIS only recognises, never establishes
        for o in self.used_pkg:
            if o["v"]["predecessor"]: rel.setdefault(o["v"]["predecessor"]["chain_id"], "predecessor")
        for o in self.used_pkg:
            if o["v"]["successor"]: rel.setdefault(o["v"]["successor"]["chain_id"], "successor")
        self.rel = rel
        for o in self.plist:
            if o["v"] is None or o["v"]["chain_id"] == C: continue
            if o["v"]["chain_id"] in rel: self.h2_8_to_10(o, True)
            else: self.fail(o, 7, "other_chain")
        for o in self.plist:
            if o["use"] == "used_linked": self.linked.setdefault(o["v"]["chain_id"], []).append(o)
        for o in self.plist:
            if o["fail"] is not None:
                r = o["fail"][1]
                self.page_f.setdefault((self.ah["page_reason_class"][r], r), [])
                if o not in self.page_f[(self.ah["page_reason_class"][r], r)]: self.page_f[(self.ah["page_reason_class"][r], r)].append(o)
                if r == "page_rules":                                  # H11 (a): blocking on a page that reads with chain_id = C
                    try: x = jloads(o["s"])
                    except Exception: x = None
                    if isinstance(x, dict) and x.get("chain_id") == C: self.blocking.add("contradiction")

    def pkg_reached_7(self):
        return [o for o in self.plist if o["v"] is not None and o["v"]["chain_id"] == self.ctx["C"]]

    # -- H3 to H7
    def h3_h4(self):
        R, pkg = self.R, self.pkg_reached_7()
        fresh = [o for o in self.used_pkg if o["use"] == "used_fresh"]
        passed8 = [o for o in pkg if o["passed8"]]
        if R is not None and not fresh and passed8:                    # H3
            last = max(passed8, key=lambda o: (ms(o["v"]["server_ts"]), o["s"].encode()))
            self.note(AH_U, "issued_before_request", f"no page of the package issued at or after R - W_h = {ms_text(R - self.W)}; the latest is of "
                                                     f"{last['v']['server_ts']} ({last['where']}) (8.8.4 H3)")
        if fresh and any(o["use"] == "used_stale" for o in self.used_pkg): self.notes.add("archive_pages")
        cov = fresh if R is not None else self.used_pkg                # H4; without R only for information
        self.coverage = ah_coverage([(o["v"]["since_tree_size"], o["v"]["next_since_tree_size"]) for o in cov])
        if R is not None and self.coverage["gaps"]:
            a, b = self.coverage["gaps"][0]
            self.note(AH_U, "pages_missing", f"the fresh pages of the package leave tree sizes [{a}, {'infinity' if b is None else b}) uncovered "
                                             f"({len(self.coverage['gaps'])} gap{'s' if len(self.coverage['gaps']) > 1 else ''}) (8.8.4 H4)")

    def h5_pair(self, A, B):
        """H5 (a) to (j) for the pair A before B -> the reasons that apply."""
        a, b, W = A["v"], B["v"], self.W
        ats = ms(a["server_ts"])
        out = []
        ra = {(x["tree_size"], x["merkle_root"], x["recorded_as"]): x for x in a["roots"]}
        rb = {(x["tree_size"], x["merkle_root"], x["recorded_as"]): x for x in b["roots"]}
        if any(k in rb and ms(x["server_ts"]) != ms(rb[k]["server_ts"]) for k, x in ra.items()): out.append("root_time_differs")
        if any(k not in rb and ah_in_range(k[0], b) for k in ra): out.append("root_dropped")
        if any(k not in ra and ah_in_range(k[0], a) and ms(x["server_ts"]) < ats - W for k, x in rb.items()): out.append("root_withheld")
        fb = {(x["tree_size"], x["merkle_root"]) for x in b["forks"]}
        if b["forks_omitted"] == 0 and any((x["tree_size"], x["merkle_root"]) not in fb and ah_in_range(x["tree_size"], b) for x in a["forks"]):
            out.append("fork_dropped")
        pa, pb = a["affiliation"]["periods"], b["affiliation"]["periods"]
        # (e): an open period of A ends at A.server_ts; B, issued after A, states its open period up to its own server_ts at least.
        a_iv = [(ms(p["from"]), min(ats, ms(p["until"])) if p["until"] is not None else ats) for p in pa]
        b_cover = [(ms(p["from"]), ms(p["until"]) if p["until"] is not None else None) for p in pb]
        if any(f < u and _uncovered(f, u, b_cover) for f, u in a_iv): out.append("affiliation_narrowed")
        # (f): only a period of B with recorded_ts before A.server_ts - W_h and merged = false. A merged period of B never
        # gives this reason, not even across a gap between the old periods: merging covers that time too, and no earlier
        # page had to show it (8.8.4 H5 (f), heartbeat spec 9.10, time reference 4). (e) is unchanged by merged.
        b_iv = [(ms(p["from"]), min(ats, ms(p["until"])) if p["until"] is not None else ats) for p in pb
                if ms(p["recorded_ts"]) < ats - W and p["merged"] is False]
        a_cover = [(ms(p["from"]), ms(p["until"]) if p["until"] is not None else ats) for p in pa]
        if any(f < u and _uncovered(f, u, a_cover) for f, u in b_iv): out.append("affiliation_withheld")
        ka, kb = a["affiliation"]["known_since"], b["affiliation"]["known_since"]
        if ka is not None and kb is not None and ms(ka) < ms(kb) <= ats: out.append("known_range_narrowed")      # (g) since ffffeadd
        if set(a["owner_keys"]) - set(b["owner_keys"]): out.append("owner_keys_dropped")
        if a["predecessor"] != b["predecessor"] or (a["successor"] is not None and a["successor"] != b["successor"]): out.append("succession_changed")
        if b["reference_tree_size"] < a["reference_tree_size"]: out.append("reference_decreases")
        return out

    def h5(self):
        groups = [(self.ctx["C"], self.used_pkg)] + sorted(self.linked.items())
        for chain, lst in groups:
            lst = sorted(lst, key=lambda o: (ms(o["v"]["server_ts"]), o["s"].encode()))
            for i, A in enumerate(lst):
                for B in lst[i + 1:]:
                    for r in self.h5_pair(A, B):
                        pkg = chain == self.ctx["C"]
                        self.note(AH_C, r, f"{'pages of the package' if pkg else 'linked pages of chain ' + chain}: page of {A['v']['server_ts']} "
                                           f"({A['where']}) before page of {B['v']['server_ts']} ({B['where']}) (8.8.4 H5)",
                                  "contradiction" if pkg else None)
                        if pkg and r in AH_AFFILIATION_REASONS: self.contradictory = True
        # succession_mismatch: both statements on the change between P and a linked chain L name the same T. L the
        # predecessor (P.predecessor = {L, T} on a used page of the package): every used page of L whose successor is not
        # null carries successor = {P, T}; L the successor (P.successor = {L, T}): every used page of L whose
        # predecessor is not null carries predecessor = {P, T}.
        C = self.ctx["C"]
        for o in self.used_pkg:
            for mine, theirs in (("predecessor", "successor"), ("successor", "predecessor")):
                m = o["v"][mine]
                if m is None: continue
                want = {"chain_id": C, "tree_size": m["tree_size"]}
                for x in self.linked.get(m["chain_id"], ()):
                    y = x["v"][theirs]
                    if y is not None and y != want:
                        self.note(AH_C, "succession_mismatch", f"the package's page of {o['v']['server_ts']} names the {mine} {{{m['chain_id']}, {m['tree_size']}}}, "
                                                               f"the page of {x['v']['server_ts']} of that chain the {theirs} {{{y['chain_id']}, {y['tree_size']}}} "
                                                               f"(8.8.4 H5)", "contradiction")

    def h6_h7(self):
        """H6 history roots and fork findings from the used pages of the package; H7 against the vendor log."""
        for o in self.used_pkg:
            for x in o["v"]["roots"]:
                rec = self.hroots.setdefault((x["tree_size"], x["merkle_root"]), [])
                if (x["recorded_as"], x["server_ts"]) not in rec: rec.append((x["recorded_as"], x["server_ts"]))
            for f in o["v"]["forks"]: self.hforks.setdefault((f["tree_size"], f["merkle_root"]), f)
        self.distinct_roots = len(self.hroots)
        recs, W = self.ctx["records"], self.W
        if recs:
            days = set()
            for (t, r), rl in self.hroots.items():
                keep = []
                for ra, s in rl:
                    d = s[:10]
                    # "dieselben vier Werte": server_ts compared as an instant in whole milliseconds (8.8.4, Bezeichnungen);
                    # only gap_witness_time_differs below compares strings, as the text says.
                    if ra in AH_RECORDED and d in recs and not any((x["tree_size"], x["merkle_root"], x["recorded_as"], ms(x["server_ts"])) == (t, r, ra, ms(s)) for x in recs[d]):
                        days.add(d); continue
                    keep.append((ra, s))
                rl[:] = keep
            for d in sorted(days):
                self.own.append((AH_C, "log_mismatch", f"{d}: a recording of a used page of the package with recorded_as countersigned or gap_witness "
                                                       f"is missing from the checked chain-day record of the vendor log; it does not count for its history root (8.8.4 H7)"))
                self.blocking.add("contradiction")
            fresh = [o for o in self.used_pkg if o["use"] == "used_fresh"]
            for d in sorted(recs):
                for x in recs[d]:
                    t, r, ra, s = x["tree_size"], x["merkle_root"], x["recorded_as"], x["server_ts"]
                    for o in fresh:
                        v = o["v"]
                        if not ah_in_range(t, v) or ms(v["server_ts"]) < ms(s) + W: continue
                        listed = [y for y in v["roots"] if (y["tree_size"], y["merkle_root"], y["recorded_as"]) == (t, r, ra)]
                        if not listed:
                            self.note(AH_C, "log_root_missing", f"the page of {v['server_ts']} ({o['where']}) lacks the root {ra} tree_size {t} of {s} of the "
                                                                f"vendor log's day {d} (8.8.4 H7)", "contradiction")
                        elif ra == "gap_witness" and any(y["server_ts"] != s for y in listed):
                            self.note(AH_C, "gap_witness_time_differs", f"the page of {v['server_ts']} names the gap witness tree_size {t} with another server_ts "
                                                                        f"than {s} of the vendor log (8.8.4 H7)", "contradiction")
            gw = {}
            for rows in recs.values():
                for x in rows:
                    if x["recorded_as"] == "gap_witness": gw.setdefault((x["tree_size"], x["merkle_root"]), set()).add(ms(x["server_ts"]))
            for (t, r), ss in sorted(gw.items()):
                if len(ss) > 1:
                    self.note(AH_C, "gap_witness_time_differs", f"the checked records of the vendor log name the gap witness tree_size {t} with "
                                                                f"{len(ss)} different server_ts (8.8.4 H7)", "contradiction")
        self.not_used_log = sum(1 for rl in self.hroots.values() if not rl)
        self.roots_h = {}                                              # (t, r) -> (recorded_as set, e in ms, e text, recorded)
        for k, rl in self.hroots.items():
            if not rl: continue
            kinds = {ra for ra, _s in rl}
            recorded = bool(kinds & set(AH_RECORDED))
            e_s = min((s for ra, s in rl if (ra in AH_RECORDED) == recorded), key=ms)
            self.roots_h[k] = (kinds, ms(e_s), e_s, recorded)

    def run_h1_h7(self):
        if not self.supplied: return
        self.h1(); self.h2(); self.h3_h4(); self.h5(); self.h6_h7()

    # -- H8: the classification of 8.8.5, computed at step 8 of 10.5 (the expected roots), reported at step 13
    def classify(self, expect_roots, root, N):
        """The expected roots of both sources (10.8, 8.8.5) -> (found: [(found_at, sources)], findings to report at step
        13: [(class, detail)]). Equal pairs (tree_size, merkle_root) from both sources are one expected root."""
        R, W, found, pend = self.R, self.W, [], []
        exp = {}
        for size, r in expect_roots:
            if size is None:
                ts = [k for k in range(1, len(root)) if root[k] == r]
                if ts: found.append((max(ts), {"auditor"}))            # 10.8 (1.10): found at the largest matching t
                else: pend.append(("MERKLE_INCONSISTENT", f"expected root {r} is the root of no prefix 1..{N} of this chain"))
            else: exp.setdefault((size, r), set()).add("auditor")
        for k in self.roots_h: exp.setdefault(k, set()).add("anchor_history")
        notes, c = self.notes, self.counts
        c["distinct"], c["not_used_vendor_log"] = self.distinct_roots, self.not_used_log
        for (t, r), src in sorted(exp.items()):
            hist = (t, r) in self.roots_h
            ok = t <= N and root[t] == r
            if hist:
                kinds, e, e_s, recorded = self.roots_h[(t, r)]
                # 10.10.2 roots: a pair that also carries the source auditor counts like every history root, by t, root(t),
                # e and R; its finding follows 10.8.
                if ok: c["found"] += 1
                elif t <= N: c["differing_before_request" if R is not None and e < R - W else "differing_after_request"] += 1
                elif R is None: c["beyond_package_unjudged"] += 1
                elif e < R - W: c["beyond_package_before_request"] += 1
                elif e < R: c["beyond_package_recent"] += 1
                else: c["beyond_package_after_request"] += 1
            if ok:
                found.append((t, src))
                if hist: self.found_history.append(t)
                continue
            if "auditor" in src:                                       # 10.8: not found is MERKLE_INCONSISTENT, one finding per pair
                pend.append(("MERKLE_INCONSISTENT", f"expected root for tree_size={t} lies beyond the {N} entries present" if t > N else
                             f"expected root for tree_size={t} is {r}, recomputed {root[t]}"))
                if hist: self.merkle_from_history = True               # H11: it stems from a history root all the same
                continue
            kinds, e, e_s, recorded = self.roots_h[(t, r)]
            rt = f", root(t) {root[t]}" if t <= N else ""
            what = f"tree_size {t}, merkle_root {r}, recorded as {', '.join(sorted(kinds, key=AH_REC_RANK.get))}, first recorded {e_s}"
            if recorded and R is not None and e < R - W:
                pend.append(("MERKLE_INCONSISTENT", f"the vendor recorded at {what}, before the request at {ms_text(R)} minus 15 minutes, "
                             + (f"and the package contradicts it{rt}" if t <= N else f"and the package ends before it ({N} entries)") + " (8.8.5)"))
                self.merkle_from_history = True
                if t > N: notes.add("package_ended_before_request")
            elif t <= N:
                pend.append((AH_F, f"history_root_differs: {what}{rt}; " + ("recorded within 15 minutes before the request or after it" if recorded and R is not None
                             else "without a request time" if recorded else "only reported, never exit 2") + " (8.8.5)"))
                self.blocking.add("fork")
                self.own_reasons_f.add("history_root_differs")
            elif R is None: notes.add("no_request_time")
            elif e < R - W:
                pend.append((AH_F, f"reported_root_beyond_package: {what}, only reported, before the request at {ms_text(R)} minus 15 minutes, beyond "
                             f"the {N} entries of the package (8.8.5)"))
                self.blocking.add("fork")
                self.own_reasons_f.add("reported_root_beyond_package")
            elif e < R: notes.add("recent_roots_not_found")
        return found, pend

    # -- H9 to H11
    def h9(self, root, N):
        C, gen_pred = self.ctx["C"], self.ctx["gen_pred"]
        rec_roots = {k for k, x in self.roots_h.items() if x[3]}
        for (t, r), f in sorted(self.hforks.items()):
            how = f"tree_size {t} lies beyond the {N} entries" if t > N else "root(t) equals it" if root[t] == r else \
                "root(t) equals a recorded root of the history" if (t, root[t]) in rec_roots else f"root(t) is {root[t]}, neither it nor a recorded root"
            self.own.append((AH_F, "fork_listed", f"fork_listed: fork finding tree_size {t}, merkle_root {r}, detected {f['detected_ts']}; {how} (8.8.4 H9)"))
            self.blocking.add("fork")
        om = max((o["v"]["forks_omitted"] for o in self.used_pkg), default=0)
        if om > 0: self.note(AH_F, "forks_omitted", f"a used page of the package omits {om} fork findings (forks_omitted) (8.8.4 H9)", "fork")
        beyond = {}
        for o in self.used_pkg:
            s = o["v"]["successor"]
            if s is None: continue
            T = s["tree_size"]
            for (t, r), x in sorted(self.roots_h.items()):
                if t <= T: continue
                if x[3]: beyond.setdefault((t, r), (x, s))
                else: self.notes.add("reported_beyond_handover")
            if N > T: self.notes.add("package_beyond_handover")
        for (t, r), (x, s) in sorted(beyond.items()):
            self.note(AH_F, "root_beyond_handover", f"history root tree_size {t} recorded as {', '.join(sorted(x[0], key=AH_REC_RANK.get))} lies "
                                                    f"beyond the handover to {s['chain_id']} at {s['tree_size']} (8.8.4 H9)", "fork")
        for L, lp in self.linked.items():
            for o in lp:
                s = o["v"]["successor"]
                if s is None or s["chain_id"] != C: continue
                for x in o["v"]["roots"]:
                    if x["tree_size"] <= s["tree_size"]: continue
                    if x["recorded_as"] in AH_RECORDED:
                        self.note(AH_F, "predecessor_beyond_handover", f"the predecessor chain {L} records tree_size {x['tree_size']} as {x['recorded_as']}, "
                                                                       f"beyond its handover to this chain at {s['tree_size']} (8.8.4 H9)", "fork")
                    else: self.notes.add("reported_beyond_handover")
        # The notes on a predecessor: a used page of the package names one, and GENESIS.predecessor_chain names none or
        # another; no supplied page with its chain_id passed numbers 1 to 5 of H2 (only then is its chain_id read from
        # established bytes).
        passed5 = {o["chain5"] for o in self.plist if o["chain5"] is not None}
        for o in self.used_pkg:
            p = o["v"]["predecessor"]
            if p is None: continue
            if p["chain_id"] != gen_pred: self.notes.add("predecessor_differs_from_genesis")
            if p["chain_id"] not in passed5: self.notes.add("linked_history_not_supplied")

    def h10(self):
        held, est, W = self.ctx["held"], self.ctx["est"], self.W
        BL = ms(self.ah["legacy_boundary"])
        cs = {}
        for o in self.used_pkg:
            for x in o["v"]["roots"]:
                if x["recorded_as"] == "countersigned": cs.setdefault((x["tree_size"], x["merkle_root"]), set()).add(ms(x["server_ts"]))
        missing, rc = [], self.rcounts
        rc["checked"] = len(held)
        for e in held:
            p = e["payload"]
            s, k = ms(p["server_ts"]), (p["tree_size"], p["merkle_root"])
            if s < BL: rc["before_legacy_boundary"] += 1
            elif k in cs:
                rc["in_history"] += 1
                if s not in cs[k]: rc["server_ts_differs"] += 1
            elif any(ah_in_range(p["tree_size"], o["v"]) and ms(o["v"]["server_ts"]) >= s + W for o in self.used_pkg):
                if e["seq"] in est: rc["not_in_history"] += 1; missing.append(e["seq"])
                else: rc["not_in_history_unestablished"] += 1; self.notes.add("receipt_roots_unverified_not_in_history")
            else: rc["not_covered"] += 1
        if missing:
            self.note(AH_C, "receipt_not_in_history", f"{len(missing)} established receipt{'s' if len(missing) > 1 else ''}, smallest seq {min(missing)}, "
                                                      f"missing from a used page of the package issued at least 15 minutes after them (8.8.4 H10)", "contradiction")

    def h11(self):
        R, ctx = self.R, self.ctx
        pkg7 = self.pkg_reached_7()
        fresh = any(o["use"] == "used_fresh" for o in self.used_pkg)
        if R is not None and self.coverage["status"] == "complete" and not self.blocking and not self.merkle_from_history and self.found_history:
            self.completeness = {"status": "established", "reason": None, "up_to_tree_size": max(self.found_history)}
            return
        if R is None: reason = "no_request_time"
        elif not pkg7: reason = "no_usable_page"
        elif any(o["fail"] == (8, "owner_differs") for o in pkg7) and not self.used_pkg: reason = "owner_differs"
        elif (AH_U, "issued_before_request") in self.agg: reason = "issued_before_request"
        elif (AH_U, "pages_missing") in self.agg: reason = "pages_missing"
        elif "contradiction" in self.blocking: reason = "contradiction"
        elif "fork" in self.blocking: reason = "fork"
        elif self.merkle_from_history: reason = "root_missing"
        else: reason = "no_root_found"
        self.completeness = {"status": "partial" if R is not None and fresh else "not_established", "reason": reason, "up_to_tree_size": None}

    def run_h9_h11(self, root, N):
        if not self.supplied: return
        self.h9(root, N); self.h10(); self.h11()

    def emit(self, res):
        """The findings of H2 to H10 (8.8.7, Mehrfachmeldungen): one per class and reason with the number of pages and
        the place and server_ts of the foremost in input order; fork_listed per (t, r), log_mismatch per day."""
        for r in self.ah["page_reasons"]:
            for cls in (AH_U, AH_D, AH_C):
                pages = self.page_f.get((cls, r))
                if not pages: continue
                first = min(pages, key=lambda o: o["order"])
                ts = first["v"]["server_ts"] if first["v"] else (ah_page_ts(first["s"]) or "not readable")
                why = f"; {first['why']}" if first.get("why") and first["fail"] and first["fail"][1] == r else ""
                n = len(pages)
                res.add(cls, f"{r}: {self.reason_text(r)}: {n} page{'s' if n > 1 else ''}; first {first['where']}, server_ts {ts}{why} (8.8.4 H2)")
        for (cls, r), (n, detail) in self.agg.items():
            res.add(cls, f"{r}: {detail}" + (f" ({n} occurrences)" if n > 1 else ""))
        for cls, r, detail in self.own: res.add(cls, detail)

    def reasons(self):
        """anchor_history.reasons (10.10.2): per class the reasons reported, in the order of the registry."""
        got = {(c, r) for c, r in self.page_f if self.page_f[(c, r)]} | set(self.agg) | {(c, r) for c, r, _d in self.own} | {(AH_F, r) for r in self.own_reasons_f}
        return {key: [r for r in self.ah["reasons_by_class"][cls] if (cls, r) in got] for key, cls in self.ah["report_reason_keys"].items()}

    # -- H12: the affiliation (8.8.6)
    def key_source(self, o):
        """(anchor_history.keys[].source, its list, affiliation.stated_by.key_source) of the report pair of page o."""
        src = o["pair"][2]
        if src == "pinned": return "pinned", None, "pinned"
        q = self.res.roles["Q"]
        return "role_list", {"version": q["version"], "ausgestellt": q["ausgestellt"], "wurzel_id": q["signatur"]["wurzel_id"], "root_source": "vendor_root"}, "role_list_auditor_root"

    def affiliation_of(self, P, receipts, coverage):
        """8.8.6 numbers 3 to 10 over the used pages P (not empty) of one chain; receipts: server_ts of the established
        receipts that count for it (none for a linked chain); coverage: its status after H4."""
        R = self.R
        H = max(P, key=lambda o: (ms(o["v"]["server_ts"]), o["s"].encode()))
        as_of = H["v"]["server_ts"]
        periods = []
        for o in P:
            for p in o["v"]["affiliation"]["periods"]:
                end = p["until"] if p["until"] is not None else (None if o is H else o["v"]["server_ts"])
                periods.append({"bases": p["bases"], "from": p["from"], "until": end, "recorded_ts": p["recorded_ts"], "merged": p["merged"]})
        times = [ms(s) for s in receipts] + [ms(x["server_ts"]) for o in P for x in o["v"]["roots"]]
        span_to = R if R is not None else ms(as_of)
        span_from = min(times) if times else span_to
        for p in periods: p["overlaps_package"] = ms(p["from"]) <= span_to and (p["until"] is None or ms(p["until"]) > span_from)
        over = [p for p in periods if p["overlaps_package"]]
        ks = H["v"]["affiliation"]["known_since"]
        reason = None
        if over: status = "affiliated"
        else:
            cover_ok = (R is not None and H["fresh"]) or (R is None and all(ms(as_of) >= ms(s) for s in receipts))
            if not cover_ok: reason = "statement_does_not_cover_package"
            elif ks is None or ms(ks) > span_from: reason = "known_range_too_short"
            elif coverage != "complete": reason = "history_pages_missing"
            status = "not_determined" if reason else "not_affiliated"
        bases = [b for b in self.af["bases"]["order"] if any(b in p["bases"] for p in over)]
        uniq = {jcs(p): p for p in periods}
        ordered = sorted(uniq.values(), key=lambda p: (ms(p["from"]), (1, 0) if p["until"] is None else (0, ms(p["until"])), jcsb(p["bases"]),
                                                       ms(p["recorded_ts"]), p["merged"], p["overlaps_package"]))
        def inside(s): return any(ms(p["from"]) <= ms(s) and (p["until"] is None or ms(s) < ms(p["until"])) for p in periods)
        return {"status": status, "reason": reason, "bases": bases if status == "affiliated" else [], "vendor_itself": status == "affiliated" and "vendor" in bases,
                "span": {"from": ms_text(span_from), "to": ms_text(span_to)}, "as_of": as_of, "known_since": ks, "H": H, "periods": ordered,
                "receipts_total": len(receipts), "receipts_in_periods": sum(1 for s in receipts if inside(s)),
                "receipts_after_statement": sum(1 for s in receipts if ms(s) > ms(as_of))}

    def affiliation(self):
        """The object affiliation of 10.10.2 (8.8.6)."""
        empty = {"status": "not_checked", "reason": None, "bases": [], "vendor_itself": False, "span": None, "as_of": None, "known_since": None,
                 "stated_by": None, "periods": [], "receipts_total": None, "receipts_in_periods": None, "receipts_after_statement": None,
                 "contradictory": False, "linked": []}
        if not self.supplied: return empty
        linked = []
        for L, lp in sorted(self.linked.items()):                      # number 11: their own pages and recordings, never the package's status
            cov = ah_coverage([(o["v"]["since_tree_size"], o["v"]["next_since_tree_size"]) for o in lp if self.R is None or o["fresh"]])["status"]
            x = self.affiliation_of(lp, [], cov)
            linked.append({"chain_id": L, "relation": self.rel.get(L, "predecessor"), "status": x["status"], "periods": x["periods"]})
        if not self.used_pkg:
            reached = {o["fail"][1] for o in self.plist if o["fail"] is not None}
            m = self.af["not_determined_from_page_reason"]
            order = ("owner_differs", "key_not_established", "key_other_role", "key_not_valid", "signing_time_not_proven", "not_v2", "signature", "page_rules", "other_chain")
            r = next((m[x] for x in order if x in reached), "history_no_package_page")
            return dict(empty, status="not_determined", reason=r, linked=linked)
        held = self.ctx["held"]
        receipts = [e["payload"]["server_ts"] for e in held if e["seq"] in self.ctx["est"]]
        x = self.affiliation_of(self.used_pkg, receipts, self.coverage["status"])
        H = x.pop("H")
        _s, _l, ks = self.key_source(H)
        x.update(stated_by={"server_key_id": H["pair"][0], "key_source": ks}, contradictory=self.contradictory, linked=linked)
        return x

    def report(self):
        """The object anchor_history of 10.10.2 (H13)."""
        notes = set(self.notes)
        if self.inputs.requested_at is not None and not self.supplied: notes.add("requested_at_unused")
        out = {"status": "checked" if self.supplied else "not_supplied", "requested_at": ms_text(self.R) if self.R is not None else None,
               "files": len(self.inputs.history),
               "pages": {"supplied": self.n_supplied, "distinct": len(self.plist), **{u: sum(1 for o in self.plist if o["use"] == u) for u in self.ah["page_uses"]},
                         "not_used": sum(1 for o in self.plist if o["use"] is None)},
               "page_reasons": [r for r in self.ah["page_reasons"] if any(o["fail"] and o["fail"][1] == r for o in self.plist)],
               "issued": {"first": None, "last": None}, "keys": [], "owner": None, "coverage": self.coverage,
               "reference_tree_size": None, "predecessor": None, "successor": None, "roots": dict(self.counts),
               "forks": {"listed": len(self.hforks), "omitted": max((o["v"]["forks_omitted"] for o in self.used_pkg), default=0)},
               "receipts": dict(self.rcounts), "completeness": self.completeness, "reasons": self.reasons(),
               "notes": [n for n in self.ah["notes"] if n in notes]}
        if self.used_pkg:
            by = sorted(self.used_pkg, key=lambda o: (ms(o["v"]["server_ts"]), o["s"].encode()))
            out["issued"] = {"first": by[0]["v"]["server_ts"], "last": by[-1]["v"]["server_ts"]}
            H = by[-1]["v"]
            out.update(reference_tree_size=H["reference_tree_size"], predecessor=H["predecessor"], successor=H["successor"])
        keys = {}
        for o in self.plist:
            if o["use"] is not None:
                src, lst, _ks = self.key_source(o)
                keys.setdefault(o["pair"][0], {"key_id": o["pair"][0], "source": src, "list": lst})
        out["keys"] = [keys[k] for k in sorted(keys, key=str.encode)]
        pkg7 = self.pkg_reached_7()
        if any(o["passed8"] for o in pkg7): out["owner"] = "matches"
        elif any(o["fail"] == (8, "owner_differs") for o in pkg7): out["owner"] = "differs"
        return out


def ah_page_ts(s):
    """The member server_ts of a statement_jcs that reads as an I-JSON object, for the place of a finding only ("soweit
    lesbar", 8.8.4); it decides nothing."""
    try: v = jloads(s)
    except Exception: return None
    return v.get("server_ts") if isinstance(v, dict) and isinstance(v.get("server_ts"), str) and utc_ns(v["server_ts"]) is not None else None


def anchor_history_text(res, lang):
    """The block of the anchor history (10.10.3), every phrase from registry verifier.anchor_history.texts."""
    ah, rep, reg = res.ah_reg, res.anchor_history, res.ah_reg["texts"]
    t = {k: x[lang] for k, x in reg.items()}
    if rep["status"] == "not_supplied": return t["not_supplied"].format(chain_id=res.chain_id)
    comp = rep["completeness"]
    why = ah["completeness_reason_texts"][comp["reason"]][lang] if comp["reason"] else ""
    last = t["completeness_established"].format(**comp) if comp["status"] == "established" else t["completeness_not_established"].format(reason=why)
    p = rep["pages"]
    used = p["used_fresh"] + p["used_stale"] + p["used_unjudged"]
    if not used:
        reasons = "; ".join(ah["page_reason_texts"][r][lang] for r in rep["page_reasons"])
        # 10.10.3: if owner is differs, the text owner_differs_detail (registry verifier.anchor_history.texts) follows as
        # the second line; then the line on completeness.
        detail = ["  " + t["owner_differs_detail"]] if rep["owner"] == "differs" else []
        return "\n".join([t["none_used"].format(distinct=p["distinct"], reasons=reasons)] + detail + ["  " + last])
    keys = ", ".join(t["key_item"].format(key_id=k["key_id"], source=source_text(k["list"], t)) for k in rep["keys"])
    r = rep["roots"]
    lines = [t["used_head"].format(used=used, distinct=p["distinct"], fresh=p["used_fresh"], stale=p["used_stale"], first=rep["issued"]["first"],
                                   last=rep["issued"]["last"], keys=keys),
             "  " + (t["requested_at"].format(requested_at=rep["requested_at"]) if rep["requested_at"] else t["no_request_time"].format(unjudged=r["beyond_package_unjudged"])),
             "  " + t["roots"].format(distinct=r["distinct"], entries=res.n_entries, found=r["found"], differing=r["differing_before_request"] + r["differing_after_request"],
                                      before_request=r["beyond_package_before_request"], recent=r["beyond_package_recent"], after_request=r["beyond_package_after_request"]),
             "  " + last]
    return "\n".join(lines)


def source_text(lst, t):
    """<Quelle> (10.10.3): pinned, or the role list with its version and the auditor's root (this verifier builds no root in)."""
    return t["source_pinned"] if lst is None else t["source_role_list_auditor"].format(version=lst["version"], wurzel_id=lst["wurzel_id"])


def affiliation_text(res, lang):
    """The line on affiliation (10.10.3, registry verifier.affiliation.texts), without the sentence open_at_level_2, which
    the block of the evidence level appends at level 2 and above (evidence_level_text)."""
    af, a = res.af_reg, res.affiliation
    t = {k: x[lang] for k, x in af["texts"].items()}
    ah_t = {k: x[lang] for k, x in res.ah_reg["texts"].items()}
    def periods(ps):
        return ", ".join((t["period_open"].format(**p) if p["until"] is None else t["period_closed"].format(**p)) + (" " + t["merged"] if p["merged"] else "") for p in ps)
    if a["status"] == "not_checked":
        return t["not_checked"] + " " + (t["not_checked_fetch"].format(chain_id=res.chain_id) if res.sig_receipt else t["not_checked_never_anchored"])
    if a["status"] == "not_determined":
        # 10.10.3: known_range_too_short names <known_since>; if known_since of H* is null (8.8.6 number 7 (b)), the text
        # is reason_texts.known_range_too_short_null, which names no time (registry verifier.affiliation.texts_comment).
        key = "known_range_too_short_null" if a["reason"] == "known_range_too_short" and a["known_since"] is None else a["reason"]
        why = af["reason_texts"][key][lang].format(known_since=a["known_since"])
        return t["not_determined"].format(reason=why)
    lst = next((k["list"] for k in res.anchor_history["keys"] if k["key_id"] == a["stated_by"]["server_key_id"]), None)
    src = source_text(lst, ah_t)
    if a["status"] == "not_affiliated":
        out = t["not_affiliated"].format(**{"from": a["span"]["from"], "to": a["span"]["to"]}, as_of=a["as_of"], key_id=a["stated_by"]["server_key_id"], source=src)
        outside = [p for p in a["periods"] if not p["overlaps_package"]]
        return out + (" " + t["not_affiliated_outside"].format(periods=periods(outside)) if outside else "")
    over = [p for p in a["periods"] if p["overlaps_package"]]
    names = ", ".join(af["bases"]["codes"][b][lang] for b in a["bases"])
    key = "affiliated_vendor_itself" if a["vendor_itself"] else "affiliated"
    return t[key].format(bases=names, periods=periods(over), k=a["receipts_in_periods"], n=a["receipts_total"], as_of=a["as_of"],
                         key_id=a["stated_by"]["server_key_id"], source=src)


# ------------------------------------------------ evidence level (format.de.md 10.9, 10.10, from 1.10)
# The evidence level is a function of what the run holds (10.9.3), the exit code and the finding classes. It is formed
# after the exit code (10.5 stage 5, step 15) from what verify() kept in Result.ev: it adds, removes and changes no
# finding, reads no clock, no root store of the system and no file, and never changes the exit code (10.3, 10.9). It
# applies to every package whatever spec_version it declares. Codes, orders, rule and texts come from the registry
# (verifier.evidence_level); this verifier builds no vendor root in, so the note vendor_root_builtin_only never applies,
# and it performs steps 5 and 6 of 7.3, so cms_not_implemented never does.

def package_tsa_spki(files):
    """10.9.3, Zertifikate des Pakets: the SPKI SHA-256 value of every certificate in a block CERTIFICATE of a file
    keys/tsa/*.pem that reads after B64 and Z.1; every other block and file is passed over, without a finding. Lines as
    in strict PEM (10.8): they end on \\n or \\r\\n, blanks and tabs at a line end do not count."""
    out = set()
    for name in sorted(files):
        if not re.fullmatch(r"keys/tsa/[^/]+\.pem", name): continue
        body = None
        for line in files[name].decode("latin-1").split("\n"):
            line = (line[:-1] if line.endswith("\r") else line).rstrip(" \t")
            if body is None:
                if line == "-----BEGIN CERTIFICATE-----": body = []
            elif line == "-----END CERTIFICATE-----":
                try: out.add(Cert(b64_decode("".join(body))).spki_sha256)
                except ValueError: pass
                body = None
            else: body.append(line)
    return out


def ev_stages(checks):
    """s of 10.9.4: the number of stages a pair or triple passes in table order without interruption; checks are the
    tests of the stages in that order, each a callable, so a later one is only read once the earlier ones hold."""
    for i, ok in enumerate(checks):
        if not ok(): return i
    return len(checks)


def ev_stage_reason(stages, results):
    """The reason when no item is credited (10.9.4): the code of the stage with the index max(s) over all pairs or
    triples; at the stage qualified_statement, qualified_statement_malformed before no_qualified_statement. results:
    [(s, result of rule QS)]. Every condition with stages has a pair or triple once no reason without an item applies."""
    top = max(s for s, _q in results)
    if stages[top] != "qualified_statement": return stages[top]
    return "qualified_statement_malformed" if any(s == top and q == "malformed" for s, q in results) else "no_qualified_statement"


def ev_in_window(entry, gen_ns):
    """qualifiziert_ab <= genTime < qualifiziert_bis, the upper bound only when present, as instants to the nanosecond (10.8)."""
    ab, bis = entry["qualified"]
    return ab <= gen_ns and (bis is None or gen_ns < bis)


def ev_codes(x):
    """The codes of an element of verifier.evidence_level.rule[k].conditions: a code, or a group {need, conditions}."""
    return [x] if isinstance(x, str) else [c for y in x["conditions"] for c in ev_codes(y)]


def ev_level(cond, N, el):
    """10.9.5 over the conditions (met, up_to_tree_size) and N -> (level, up_to_tree_size, segments, next, [r0, r1, r2, r3]):
    reach(c) is up_to_tree_size when c is met, else 0; r_k after registry verifier.evidence_level.rule, whose elements
    are codes or groups of the same form (max for need any, min when all are met for need all, else 0), so that
    r3 = min(reach(3), max(reach(4), reach(7)), reach(5), reach(6)) when (3), (5), (6) and one of (4) and (7) are met;
    lvl(p) = max{k : r_k >= p}; the segments are the maximal runs of equal lvl(p) with their basis in condition_order."""
    order, rule = el["condition_order"], el["rule"]
    reach = {c: cond[c]["up_to_tree_size"] if cond[c]["met"] else 0 for c in order}

    def met(x):
        if isinstance(x, str): return cond[x]["met"]
        return (any if x["need"] == "any" else all)(met(y) for y in x["conditions"])

    def rch(x):
        if isinstance(x, str): return reach[x]
        xs = [rch(y) for y in x["conditions"]]
        return max(xs) if x["need"] == "any" else min(xs) if met(x) else 0

    r = [N] + [rch(rule[k]) for k in ("1", "2", "3")]
    lvl = lambda p: max(k for k in range(4) if r[k] >= p)
    level = lvl(1)
    segs, start = [], 1
    for cut in sorted({x for x in r if 1 <= x <= N} | {N}):        # lvl is constant between two of these positions
        if cut < start: continue
        L = lvl(start)
        if segs and segs[-1]["level"] == L: segs[-1]["last_seq"] = cut
        else: segs.append({"level": L, "first_seq": start, "last_seq": cut})
        start = cut + 1
    # basis: the met codes of level k whose reach equals r_k, at level 3 among (3) to (7), by the literal rule of 10.9.5:
    # with (4) 5, (7) 10 and (5) 5, r3 is 5 and (4) stands in basis, although the larger reach of (7) carries the group
    # of (4) and (7) on.
    for g in segs:
        k = g["level"]
        g["basis"] = [] if k == 0 else [c for c in order if c in ev_codes(rule[str(k)]) and cond[c]["met"] and reach[c] == r[k]]
    nxt = None
    if level < 3:
        # missing: the conditions of level L + 1 that are not met; a group that is met names none of its codes, a group
        # that is not met names every code of it (for level 3: (4) and (7) count as one condition, 10.9.5).
        nr = rule[str(level + 1)]
        miss = {c for x in nr["conditions"] if not met(x) for c in ev_codes(x) if not cond[c]["met"]}
        nxt = {"level": level + 1, "need": nr["need"], "missing": [c for c in order if c in miss]}
    return level, r[level] if level else N, segs, nxt, r


def evidence_level(res, code, rules):
    """The object evidence_level of 10.10.2 for a run with a report (10.9): state after 10.9.2, the conditions after
    10.9.4, level, reach, segments and next after 10.9.5, the notes after 10.9.6 and the anchors after 10.10.2."""
    el, meta = rules["evidence_level"], rules["finding_classes"]
    classes = set(res.classes())
    exit2 = {c for c in classes if meta[c]["exit"] == 2}
    # 10.9.2: the topmost row that applies.
    state = "format_error" if code == 3 else "chain_invalid" if exit2 - set(el["material_classes"]) else "rated"
    af = res.affiliation if state != "format_error" else None
    out = {"state": state, "level": None, "entries": None, "up_to_tree_size": None, "segments": [], "conditions": None, "next": None,
           "qualified_time": None, "anchors": None, "affiliation": None if af is None else {"status": af["status"], "vendor_itself": af["vendor_itself"]}, "notes": []}
    if state != "rated": return out
    if res.ev is None: return None       # a Result whose checks of the chain did not run; verify() gives that only with FORMAT_ERROR
    E, order, spec = res.ev, el["condition_order"], el["conditions"]
    ptk = rules["timestamp_profile"]["published_test_keys"]
    tspki, ted = {k["spki_sha256"] for k in ptk if "spki_sha256" in k}, {k["ed25519"] for k in ptk if "ed25519" in k}
    table, vroots = E["roots"], E["vendor_roots"]
    cond, credit = {}, {c: set() for c in ("time_witness", "time_witness_qualified", "log_day_qualified")}   # root DER per condition

    def C(name, items=None, reason=None):
        """items: {item: tree_size} of the credited items; met exactly when one is credited and no reason is given."""
        if reason is None and items:
            cond[name] = {"met": True, "up_to_tree_size": max(items.values()), "count": len(items), "reason": None}
        else: cond[name] = {"met": False, "up_to_tree_size": None, "count": 0, "reason": reason}

    def published(r, R): return r["signer"].spki_sha256 in tspki or R.spki_sha256 in tspki

    # (1) time_witness: every TIME_ANCHOR, per root of the purpose chain (7.5.7).
    tas = E["time_anchors"] or []
    chain = [e for e in table.values() if "chain" in e["purposes"]]
    if not E["time_anchor_entries"]: C("time_witness", reason="no_time_anchor")
    elif not chain: C("time_witness", reason="no_tsa_root_supplied")
    else:
        results, got = [], {}
        for a in tas:
            r = a["assessment"]
            for e in chain:
                R = e["cert"]
                s = ev_stages([lambda: r["step5"] == "holds", lambda: bool(r["paths"].get(R.der)), lambda: not published(r, R),
                               lambda: r["qs"] != "unusable"])
                results.append((s, r["qs"]))
                if s == len(spec["time_witness"]["stages"]): got[a["seq"]] = a["tree_size"]; credit["time_witness"].add(R.der)
        C("time_witness", got, None if got else ev_stage_reason(spec["time_witness"]["stages"], results))

    # (2) expected_root_found: the found expected roots of both sources, distinct by (found_at, merkle_root) (10.8).
    found = {}
    for t, r, src in E["found"]: found.setdefault((t, r), set()).update(src)
    C("expected_root_found", {k: k[0] for k in found}, None if found else "no_expected_root_found")

    # (3) receipt_key_confirmed: every receipt whose signature holds after 7.1; it reads no finding of the vendor log or
    # the anchor history (10.9.4, Zu (3)).
    rc, got3 = E["receipts"], {}
    if not rc: C("receipt_key_confirmed", reason="no_receipt")
    else:
        results = []
        for x in rc:
            s = ev_stages([lambda: x["via"] is not None, lambda: x["pubkey"] not in E["D"]])
            results.append((s, None))
            if s == 2: got3[x["seq"]] = x["tree_size"]
        C("receipt_key_confirmed", got3, None if got3 else ev_stage_reason(spec["receipt_key_confirmed"]["stages"], results))

    # (4) time_witness_qualified: every TIME_ANCHOR, per root of the purpose qualified (10.8, 7.5.6, 7.5.7). Every credited
    # pair is a candidate for qualified_time (10.10.2): (genTime in ns, 0 for (4), tree_size, 0).
    qual = [e for e in table.values() if "qualified" in e["purposes"]]
    qt_items = []
    if not E["time_anchor_entries"]: C("time_witness_qualified", reason="no_time_anchor")
    elif not qual: C("time_witness_qualified", reason="no_qualified_root_supplied")
    else:
        results, got = [], {}
        for a in tas:
            r = a["assessment"]
            for e in qual:
                R = e["cert"]
                s = ev_stages([lambda: r["step5"] == "holds" and r["z6"] != "not_checkable", lambda: bool(r["paths"].get(R.der)),
                               lambda: not published(r, R), lambda: R.spki_sha256 not in E["pkg_spki"],
                               lambda: ev_in_window(e, r["t"]["gen_ns"]), lambda: r["z6"] != "violated", lambda: r["qs"] != "unusable",
                               lambda: r["qs"] == "present"])
                results.append((s, r["qs"]))
                if s == len(spec["time_witness_qualified"]["stages"]):
                    got[a["seq"]] = a["tree_size"]; credit["time_witness_qualified"].add(R.der)
                    qt_items.append((r["t"]["gen_ns"], 0, a["tree_size"], 0))
        C("time_witness_qualified", got, None if got else ev_stage_reason(spec["time_witness_qualified"]["stages"], results))

    # (5) receipts_logged: the receipts of 7.4.10 L8 in chain order with their class; reach min(r5', t_m - 1).
    vs = res.vlog or {"status": "not_supplied", "classes": [], "contradiction_in_range": False, "t_m": None, "canon": {}, "proto_pubs": set(), "p_root": None}
    rl = spec["receipts_logged"]
    glob = ("vendor_log_not_supplied" if vs["status"] == "not_supplied" else "vendor_log_not_established" if vs["status"] == "no_protocol_key"
            else "vendor_log_contradiction" if vs["contradiction_in_range"] else None)
    cls = vs["classes"]
    good = lambda x: x["class"] in rl["good"]
    neutral = lambda x: x["class"] in rl["neutral"]
    if glob: C("receipts_logged", reason=glob)
    elif not cls: C("receipts_logged", reason="no_receipt")
    else:
        r5 = max((x["tree_size"] for x in cls if good(x) and all(good(y) or neutral(y) for y in cls if y["tree_size"] <= x["tree_size"])), default=0)
        reach = min(r5, vs["t_m"] - 1) if vs["t_m"] is not None else r5
        if reach >= 1:
            cond["receipts_logged"] = {"met": True, "up_to_tree_size": reach, "count": sum(1 for x in cls if good(x) and x["tree_size"] <= reach), "reason": None}
        elif all(neutral(x) for x in cls): C("receipts_logged", reason="receipts_before_log_start")
        elif r5 == 0:
            bad = next(x for x in cls if not good(x) and not neutral(x))
            C("receipts_logged", reason=next(m["code"] for m in rl["per_receipt"] if m["class"] == bad["class"] and m.get("subclass", bad["subclass"]) == bad["subclass"]))
        else: C("receipts_logged", reason="logged_root_mismatch")

    # (6) completeness_from_history: anchor_history.completeness (8.8.4 H11).
    hc = res.anchor_history["completeness"]
    if hc["status"] == "established":
        cond["completeness_from_history"] = {"met": True, "up_to_tree_size": hc["up_to_tree_size"], "count": res.anchor_history["roots"]["found"], "reason": None}
    else:
        # root_missing does not occur in the state rated: a MERKLE_INCONSISTENT from a history root gives chain_invalid (10.9.4).
        C("completeness_from_history", reason=spec["completeness_from_history"]["from_completeness"][hc["reason"]])

    # (7) log_day_qualified, the second way to level 3 (10.9.1): every receipt of class included, per time stamp of c(d)
    # that is not defective, per root with the purposes log and qualified. Of Z.6 only a violation counts here, through
    # the defective stamp; signature_not_checkable is step 5 after 5a alone (7.5.7: "nur Bedingung 4" for Z.6 not
    # checkable). The stage qualified_day_stamp_gap: genTime cut to whole milliseconds minus server_ts of the receipt
    # greater than G_q (registry gap_max_ms, 10.9.4). Every credited triple is a candidate for qualified_time (10.10.2):
    # (genTime in ns, 1 for (7), tree_size, server_ts of the receipt in ms).
    loq = [e for e in table.values() if {"log", "qualified"} <= e["purposes"]]
    W = res.vl_reg["time"]["token_window_ms"] if res.vl_reg else None    # W of 7.4.6 (registry vendor_log.time)
    G_q = spec["log_day_qualified"]["gap_max_ms"]
    if glob: C("log_day_qualified", reason=glob)
    elif not loq: C("log_day_qualified", reason="no_qualified_log_root_supplied")
    elif not any(x["class"] == "included" for x in cls): C("log_day_qualified", reason="no_receipt_included")
    else:
        results, got = [], {}
        for x in cls:
            if x["class"] != "included": continue
            day, sts = vs["canon"][x["day"]], ms(x["server_ts"])
            for j in day["stamps"]:
                if j["state"] == "defective": continue                 # a defective time stamp forms no triple
                r = j["r"]
                for e in loq:
                    R = e["cert"]
                    s = ev_stages([lambda: r["step5"] == "holds", lambda: bool(r["paths"].get(R.der)), lambda: not published(r, R),
                                   lambda: ev_in_window(e, r["t"]["gen_ns"]), lambda: r["t"]["gen_ns"] // 10**6 < day["end"] + W,
                                   lambda: r["t"]["gen_ns"] // 10**6 - sts <= G_q, lambda: r["qs"] != "unusable", lambda: r["qs"] == "present"])
                    results.append((s, r["qs"]))
                    if s == len(spec["log_day_qualified"]["stages"]):
                        got[x["seq"]] = x["tree_size"]; credit["log_day_qualified"].add(R.der)
                        qt_items.append((r["t"]["gen_ns"], 1, x["tree_size"], sts))
        C("log_day_qualified", got, None if got else ev_stage_reason(spec["log_day_qualified"]["stages"], results))

    N = E["N"]
    level, up_to, segs, nxt, _r = ev_level(cond, N, el)

    # 10.10.2 qualified_time: at level 3 at seq 1 the credited item of (4) or (7) with tree_size >= up_to_tree_size and
    # the earliest genTime; on a tie (4) before (7), then the smaller tree_size, then for (7) the earlier server_ts of
    # the receipt. At level 3 there is always one: up_to_tree_size is at most the larger reach of (4) and (7).
    # 10.10.2: "der mit dem fruehesten genTime" compares genTime as an instant to the nanosecond, like the periods of
    # 10.8, before any cut to whole milliseconds; only latest and gap_ms are cut (to whole ms).
    qt = None
    if level == 3:
        g, way, t, sts = min(x for x in qt_items if x[2] >= up_to)
        latest = g // 10**6
        qt = {"via": "time_witness_qualified" if way == 0 else "log_day_qualified", "tree_size": t, "latest": ms_text(latest),
              "gap_ms": None if way == 0 else latest - sts}

    # 10.10.2 anchors.
    cred3 = {x["seq"] for x in rc if x["seq"] in got3}
    vkeys = {}
    for x in rc:
        if x["seq"] in cred3:
            vkeys.setdefault(x["key_id"], {"key_id": x["key_id"], "via": x["via"], "list_version": x["list_version"], "root_id": x["root_id"],
                                           "root_from": "auditor" if x["via"] == "list" else None})
    # anchors.statement_keys: the used pages of the package on which a condition that is met rests. For (2) with the
    # source anchor_history the used pages that carry the "festgehaltene" recording of a found expected root (8.8.5:
    # recorded_as countersigned or gap_witness), a recording that still counts for its history root after H7; for (6),
    # when it is met, every used page that enters the completeness (8.8.4 H11): the fresh used pages of the package,
    # since an older page never enters the completeness (8.8.4, "Aeltere Seiten"), and (6) needs R, so every used page
    # of the package is fresh or older. Per page its report pair (8.8.4 H2 number 10), without repetition of (key_id,
    # public key, origin), in the order of anchor_history.keys (by key_id). "festgehalten" is the term of 8.8.5, so a
    # page that lists a found history root only as reported carries no such recording.
    hist = E["hist"]
    hfound = {k for k, s in found.items() if "anchor_history" in s}
    def carries(o):
        return any((x["tree_size"], x["merkle_root"]) in hfound and x["recorded_as"] in AH_RECORDED
                   and (x["recorded_as"], x["server_ts"]) in hist.hroots.get((x["tree_size"], x["merkle_root"]), ()) for x in o["v"]["roots"])
    in6 = lambda o: cond["completeness_from_history"]["met"] and o["use"] == "used_fresh"
    pages6 = [o for o in hist.used_pkg if in6(o)]
    pages = [o for o in hist.used_pkg if in6(o) or hfound and carries(o)]
    q = res.roles["Q"] if res.roles else None

    def key_refs(ps):
        refs = {}
        for o in ps:
            kid, _sig, src, pub, _entry = o["pair"]
            refs.setdefault((kid, pub, src), {"key_id": kid, "via": src, "list_version": q["version"] if src == "role_list" else None,
                                              "root_id": q["signatur"]["wurzel_id"] if src == "role_list" else None,
                                              "root_from": "auditor" if src == "role_list" else None, "pubkey": pub})
        return [refs[x] for x in sorted(refs, key=lambda x: tuple(map(str.encode, x)))]
    skeys = key_refs(pages)
    # <Anker> of (6) in the text block (10.10.3): the statements keys of the pages (6) rests on, not every pair of
    # anchors.statement_keys.
    res.ev_history_keys = [{k: v for k, v in x.items() if k != "pubkey"} for x in key_refs(pages6)]
    tsa = {}
    for c in ("time_witness", "time_witness_qualified", "log_day_qualified"):
        for d in credit[c]: tsa.setdefault(d, []).append(c)
    sources = [s for s in rules["report_objects"]["completeness_sources_order"] if any(s in x for x in found.values())]
    out["anchors"] = {"vendor_keys": [vkeys[k] for k in sorted(vkeys, key=str.encode)],
                      "statement_keys": [{k: v for k, v in x.items() if k != "pubkey"} for x in skeys],
                      "tsa_roots": sorted(({"cert_sha256": hashlib.sha256(d).hexdigest(), "credited_for": [c for c in order if c in cs]} for d, cs in tsa.items()),
                                          key=lambda x: x["cert_sha256"]),
                      # 10.10.2: stand as YYYY-MM-DDThh:mm:ss.sssZ, cut to whole milliseconds, like every instant from an
                      # input of the auditor (10.10.1, Zeitpunkte); quelle as written in the file.
                      "qualified_roots_file": {"stand": ms_text(ms(E["qualified"]["stand"])), "quelle": E["qualified"]["quelle"]} if E["qualified"] else None,
                      "expected_root_sources": sources}

    # 10.9.6 notes, each once, in note_order, only in the state rated.
    m = cond["receipt_key_confirmed"]["met"]
    test3 = any(x["pubkey"] in ted or x["via"] == "list" and vroots.get(x["root_id"]) in ted for x in rc if x["seq"] in cred3)
    test5 = cond["receipts_logged"]["met"] and (bool(vs["proto_pubs"] & ted) or vs["p_root"] is not None and vroots.get(vs["p_root"]) in ted)
    # (2) with the source anchor_history and (6): the key of a used page of the package on which (2) or (6) rests (the pages
    # of anchors.statement_keys) or the vendor root of the role list that establishes it (8.8.3); a pinned statements key
    # rests on no role list (10.9.6). The occasion keeps its list of conditions without (7): level 3 needs (5), which rests
    # on the same established protocol keys as (7), so the note fires whenever (7) would.
    test26 = any(x["pubkey"] in ted or x["via"] == "role_list" and vroots.get(x["root_id"]) in ted for x in skeys)
    occ = {"material_contradiction": bool(exit2),
           "unsealed_end": "UNSEALED_END" in classes,
           "stale_package": "TRAILING_SILENCE" in classes,
           "package_not_fully_known": bool(classes & {"SPEC_NEWER", "UNKNOWN_ENTRY_TYPE", "UNKNOWN_MANIFEST_FIELD"}),
           # every credited receipt established only through a list the built-in vendor root carries: none is built in here
           "vendor_root_builtin_only": m and all(x["via"] == "list" and x["root_from"] == "builtin" for x in vkeys.values()),
           "published_test_key_credited": m and test3 or test5 or test26,
           "last_receipt_not_confirmed": m and E["lc_seq"] not in cred3,
           # 10.9.6: "beruht nur auf (2)" means the level at seq 1 is 1 and of the conditions of level 1 only (2) is met
           # ((3) is never met at level 1); the basis of the first segment is not the criterion.
           "expected_root_auditor_only": level == 1 and not cond["time_witness"]["met"] and cond["expected_root_found"]["met"]
                                         and all(s == {"auditor"} for s in found.values()),
           "tsa_root_in_package": any(table[d]["cert"].spki_sha256 in E["pkg_spki"] for d in credit["time_witness"]),
           "history_recent_roots_skipped": "recent_roots_not_found" in res.anchor_history["notes"],
           "receipts_pending_log": any(x["class"] == "pending" for x in cls),
           "receipt_not_logged": "RECEIPT_NOT_LOGGED" in classes,
           "log_day_not_supplied": any(x["class"] == "missing" for x in cls),
           "logged_root_mismatch": "LOGGED_ROOT_MISMATCH" in classes,
           "cms_not_implemented": False}                # this verifier performs steps 5 and 6 of 7.3
    out.update(level=level, entries=N, up_to_tree_size=up_to, segments=segs, conditions={c: cond[c] for c in order}, next=nxt,
               qualified_time=qt, notes=[n for n in el["note_order"] if occ[n]])
    return out


def evidence_level_text(res, lang, rules):
    """The block of the evidence level in the text report (10.10.3), every phrase from registry verifier.evidence_level;
    its last line is the line on affiliation (registry verifier.affiliation.texts), which exit 3 leaves out."""
    el, ev = rules["evidence_level"], res.evidence_level
    t = {k: x[lang] for k, x in el["texts"].items()}
    label = lambda c: el["conditions"][c][lang]
    why = lambda code: el["reasons"][code][lang]
    aff = []
    if ev["state"] != "format_error" and res.affiliation is not None and res.af_reg is not None:
        line = affiliation_text(res, lang)
        if ev["level"] is not None and ev["level"] >= 2 and res.affiliation["status"] in ("not_checked", "not_determined"):
            line += " " + res.af_reg["texts"]["open_at_level_2"][lang]
        aff = ["  " + line]
    # 10.10.3: every line of the block after the first is indented by two spaces, the lines of the missing conditions by
    # four; so are the lines after the state line in the states chain_invalid and format_error and the line direct_to_2.
    if ev["state"] != "rated":
        return "\n".join([t["state_line"].format(label=t["label"], state=el["states"][ev["state"]][lang]), "  " + t["disclaimer"]] + aff)
    L, cond, an = ev["level"], ev["conditions"], ev["anchors"]
    head = t["label_chain" if "material_contradiction" in ev["notes"] else "label"]
    name = el["levels"][str(L)]["name_" + lang]
    lines = [t["head_level0"].format(label=head, name=name, entries=ev["entries"]) if L == 0 else
             t["head"].format(label=head, level=L, name=name, up_to_tree_size=ev["up_to_tree_size"], entries=ev["entries"])]
    segs = [t["segment_level0"].format(**g) if g["level"] == 0 else
            t["segment"].format(level=g["level"], first_seq=g["first_seq"], last_seq=g["last_seq"], basis=t["basis_joiner"].join(label(c) for c in g["basis"]))
            for g in ev["segments"]]
    lines += ["  " + t["segments"].format(segments=t["segment_joiner"].join(segs)), "  " + el["levels"][str(L)][lang]]
    # The line "qualifiziert bestaetigt" stands exactly when qualified_time is not null, directly after the text of the
    # level; <Abstand> is gap_ms in whole minutes, rounded down, as <h> and <m> (10.10.3).
    qt = ev.get("qualified_time")
    if qt is not None:
        if qt["via"] == "time_witness_qualified": lines.append("  " + t["qualified_time_witness"].format(latest=qt["latest"], tree_size=qt["tree_size"]))
        else:
            h, m = divmod(qt["gap_ms"] // 60000, 60)
            lines.append("  " + t["qualified_time_log"].format(latest=qt["latest"], tree_size=qt["tree_size"], gap=t["gap"].format(h=h, m=m)))
    # <Anker> (10.10.3): for (3) the keys of the credited receipts as anchors.vendor_keys; for the other conditions the
    # anchors they name: the fingerprints of the crediting roots for time stamps, for (4) and (7) stand and quelle of the
    # file of qualified roots, the sources of the expected roots, for (5) and (7) the log_id, for (6) as_of of the anchor
    # history and the statements keys of its pages. Several anchors and several sources are joined by ", ".
    root = lambda rid, frm: t["root_auditor" if frm == "auditor" else "root_builtin"].format(root_id=rid)
    fps = lambda c: [t["anchor_tsa_root"].format(cert_sha256=x["cert_sha256"]) for x in an["tsa_roots"] if c in x["credited_for"]]
    qf = [t["anchor_qualified_file"].format(**an["qualified_roots_file"])] if an["qualified_roots_file"] else []
    log = [t["anchor_log"].format(log_id=res.vendor_log["log_id"])] if res.vendor_log and res.vendor_log["log_id"] else []
    keys = [t["anchor_pinned"].format(key_id=k["key_id"]) if k["via"] == "pinned" else
            t["anchor_list"].format(key_id=k["key_id"], version=k["list_version"], root=root(k["root_id"], k["root_from"])) for k in an["vendor_keys"]]
    # (6): the statements keys of the pages (6) rests on, the fresh used pages of the package (10.10.3, 8.8.4 H11).
    skeys = [t["anchor_statement_pinned"].format(key_id=k["key_id"]) if k["via"] == "pinned" else
             t["anchor_statement_role_list"].format(key_id=k["key_id"], version=k["list_version"], root=root(k["root_id"], k["root_from"]))
             for k in res.ev_history_keys]
    as_of = (res.affiliation or {}).get("as_of")
    anchors = {"time_witness": fps("time_witness"),
               "expected_root_found": [t["anchor_expected_sources"].format(sources=", ".join(t["source_" + s] for s in an["expected_root_sources"]))],
               "receipt_key_confirmed": keys, "time_witness_qualified": fps("time_witness_qualified") + qf, "receipts_logged": log,
               "completeness_from_history": ([t["anchor_history"].format(as_of=as_of)] if as_of else []) + skeys,
               "log_day_qualified": fps("log_day_qualified") + qf + log}
    for c in el["condition_order"]:
        if cond[c]["met"]:
            lines.append("  " + t["met"].format(condition=label(c), count=cond[c]["count"], up_to_tree_size=cond[c]["up_to_tree_size"], anchors=", ".join(anchors[c])))
    if ev["next"]:
        n = ev["next"]
        lines.append("  " + t["next_any" if n["need"] == "any" else "next_all"].format(n=n["level"]))
        # A group of the rule of the next level (for level 3 (4) and (7), 10.9.5) whose codes are all missing stands in one
        # line missing_either with both reasons, at the place of its first code in condition_order (10.10.3).
        either = {}
        for x in el["rule"][str(n["level"])]["conditions"]:
            g = [c for c in el["condition_order"] if c in ev_codes(x)]
            if not isinstance(x, str) and all(c in n["missing"] for c in g): either.update({c: g for c in g})
        for c in n["missing"]:
            if c not in either: lines.append("    " + t["missing_item"].format(condition=label(c), reason=why(cond[c]["reason"])))
            elif either[c][0] == c:
                a, b = either[c][:2]
                lines.append("    " + t["missing_either"].format(condition_4=label(a), condition_7=label(b), reason_4=why(cond[a]["reason"]),
                                                                 reason_7=why(cond[b]["reason"])))
        if L == 0 and "receipt_key_confirmed" in n["missing"]: lines.append("  " + t["direct_to_2"])
    for nt in ev["notes"]:
        lines.append("  " + t["note"].format(text=el["notes"][nt][lang].format(t=cond["receipt_key_confirmed"]["up_to_tree_size"])))
    lines.append("  " + t["disclaimer"])
    return "\n".join(lines + aff)


class Result:
    def __init__(self, rules=None):   # rules: the registry's "verifier" section the run was made with
        self.findings, self.seen, self.rules, self.chain_end, self.last_countersigned = [], set(), rules, None, None
        self.now_source = self.chain_id = self.completeness = self.residual_window = self.unanchored_stretches = None   # None: not resolved / not judged
        self.time_anchors = None             # 7.3, 7.5: per time witness that binds its checkpoint (steps 1-4) its assessment, with seq
        self.key_roles = self.roles = None   # 10.7.4: the report object key_roles and the role check behind it; None: not judged
        self.vendor_log = self.vlog = None   # 7.4.10 L10: the report object vendor_log and what later steps read of it; None: not judged
        self.vl_reg = None                   # registry vendor_log, for the texts of the report (10.10.3)
        self.anchor_history = self.affiliation = None   # 8.8.4 H13, 8.8.6, 10.10.2: the report objects; None: not judged
        self.ah_reg = self.af_reg = None     # registry verifier.anchor_history and verifier.affiliation, for the texts (10.10.3)
        self.sig_receipt, self.n_entries = False, 0
        self.ev = None                       # 10.9.3: what the run holds for the evidence level; None: the checks of the chain did not end
        self.evidence_level = None           # 10.9, 10.10.2: the report object, formed after the exit code (evidence_level())
        self.ev_history_keys = []            # 10.10.3: the statements keys of the pages (6) rests on, for its <Anker>
    def add(self, cls, detail): self.findings.append({"class": cls, "detail": detail})
    def once(self, cls, key, detail):      # 10.6: SPEC_NEWER once per package, UNKNOWN_ENTRY_TYPE once per type name
        if (cls, key) not in self.seen: self.seen.add((cls, key)); self.add(cls, detail)
    def classes(self): return sorted({f["class"] for f in self.findings})


def _fmt_err(res, errs):
    for e in errs[:50]: res.add("FORMAT_ERROR", e)
    return res


# -------------------------------------------------------------- verification

def verify(path, reg, now, freshness_h, expect_roots, now_from_package=False, vendor_roots=None, vendor_keys=None, tsa_roots=None,
           inputs=None, now_source=None):
    """now: the check time in whole milliseconds since 1970 (None: verify_args.json on request, else the system
    clock), now_source naming where a given one came from (default "flag"); expect_roots: the auditor's expected roots
    [(tree_size or None, lowercase root)] (10.8); inputs: the auditor's inputs (AuditorInputs, 10.8), else built from
    vendor_roots, vendor_keys and tsa_roots (Cert, purpose chain). Roots for time stamps are the auditor's only."""
    res, errs = Result(reg["verifier"]), []
    inputs = inputs or AuditorInputs(vendor_roots, vendor_keys, tsa_roots or ())
    try: files = load_package(path)
    except Exception as exc: return _fmt_err(res, [f"package not readable: {exc}"])
    # Check time (8.5, 10.8): --now > (only on explicit request) the package's own verify_args.json > the
    # system clock. The package file is unsigned and written by the appliance under examination, so it never
    # sets the clock by default. Asked for and absent or not conforming it is exit 3 - a fallback to the
    # system clock would silently change the basis of the freshness check.
    if now is not None: res.now_source = now_source or "flag"
    elif now_from_package:
        try: now = _verify_args(files.get("verify_args.json"))
        except Exception as exc: return _fmt_err(res, [f"--now-from-package: verify_args.json unusable: {exc} (10.8)"])
        res.now_source = "package"
    else: now, res.now_source = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000), "system"

    # Stage 1: manifest.json as I-JSON, its signals (10.6 rules 1 and 5), then its schema.
    if "manifest.json" not in files:
        return _fmt_err(res, ["manifest.json is missing from the package"])
    try: man = jloads(files["manifest.json"])
    except Exception as exc: return _fmt_err(res, [f"manifest.json is not valid I-JSON: {exc}"])
    if not isinstance(man, dict): return _fmt_err(res, ["manifest.json is not a JSON object"])
    # 10.6 R5: das Manifest ist erweiterbar. Ein undefiniertes Feld ist ein
    # Befund, kein Schemafehler, und bricht den Lauf nicht ab: das Manifest
    # geht in keinen Hash, keine Wurzel und keine Signatur ein. Pfade ohne
    # Index, sortiert, je Pfad einmal.
    offen = set()
    _fields(man, reg["pruefpaket_manifest"]["fields"], reg, "manifest", errs, res, offen)
    for pfad in sorted(offen):
        res.add("UNKNOWN_MANIFEST_FIELD",
                f"manifest carries the field {pfad}, which this verifier "
                f"(spec {reg['spec_version']}) does not define; accepted and reported "
                f"per spec 10.6 R5, all checks this version knows still run")
    if errs: return _fmt_err(res, errs)
    res.chain_id = man["chain_id"]

    # Stage 2: the segment table (10.1), in first_seq order whatever the order of the list: every file named by
    # the grammar, the declared ranges contiguous from 1 without overlap up to tree_size >= 1. The manifest is
    # unsigned packaging - a table that does not hold is a format error and the check ends here (10.5).
    segs, start = sorted(man["segments"], key=lambda g: g["first_seq"]), 1
    for g in segs:
        if not SEGMENT_FILE.fullmatch(g["file"]) or g["file"] in (".", ".."):
            errs.append(f"manifest.segments: file {g['file']!r} is not a name of the grammar ^[A-Za-z0-9._-]{{1,128}}$ other than . and ..")
        if g["first_seq"] != start or g["last_seq"] < g["first_seq"]:
            errs.append(f"manifest.segments: {g['file']!r} declares seq {g['first_seq']}..{g['last_seq']}, where a range from seq "
                        f"{start} on is due (the ranges run from seq 1 without gap or overlap)")
        start = g["last_seq"] + 1
    if man["tree_size"] < 1 or start - 1 != man["tree_size"]:
        errs.append(f"manifest: the segments cover seq 1..{start - 1}, tree_size is {man['tree_size']} (both equal and at least 1)")
    if errs: return _fmt_err(res, errs)

    # Stage 3: per segment, read only as segments/<file>: present, SHA-256, number of lines - a segment that fails
    # is not read at all, so none of its lines yields a signal. Split on "\n" and on nothing else: str.splitlines()
    # also broke at U+2028, U+2029 and U+0085, which the canonical form writes raw inside a string (RFC 8785
    # escapes only below U+0020, '"' and '\'), and turned an honest entry into FORMAT_ERROR fragments. "\n" at the
    # end of the file is passed over; every other line - an empty one, one of blanks only - must be an entry.
    blobs = []
    for g in segs:
        name = "segments/" + g["file"]
        if name not in files: errs.append(f"{name}: segment listed in the manifest is missing"); continue
        if hashlib.sha256(files[name]).hexdigest() != g["sha256"]: errs.append(f"{name}: SHA-256 does not match the manifest"); continue
        lines = files[name].rstrip(b"\n").split(b"\n")
        if len(lines) != g["last_seq"] - g["first_seq"] + 1:
            errs.append(f"{name}: {len(lines)} lines, the manifest declares seq {g['first_seq']}..{g['last_seq']}"); continue
        blobs.append((name, lines))
    if errs: return _fmt_err(res, errs)

    # Stage 4: per line I-JSON; an object gets its schema - the signals of 10.6 rules 1 and 2 come out of it, also
    # beside a schema error of the same object (rule 3) - and its chain_id. A broken line does not stop the others.
    # A member name twice is a FORMAT_ERROR (2), not "last wins": one LEGAL_HOLD could read as set or release.
    entries = []
    for name, lines in blobs:
        for ln, line in enumerate(lines, 1):
            try: e = jloads(line)
            except Exception as exc: errs.append(f"{name}:{ln}: not valid I-JSON: {exc}"); continue
            if not isinstance(e, dict): errs.append(f"{name}:{ln}: entry is not a JSON object"); continue
            entries.append(e)
            at = f"entry seq={e.get('seq')!r}"
            _fields(e, reg["envelope_fields"], reg, at, errs, res)
            et = e.get("event_type")   # unknown type (10.6 R2): envelope strict, payload only "is an object" (checked above)
            if et in reg["event_types"] and isinstance(e.get("payload"), dict):
                _fields(e["payload"], reg["event_types"][et]["payload"], reg, at + ".payload", errs, res)
                if et == "GENESIS" and _minor_at_least(e.get("spec_version"), "8") and not HEX64.fullmatch(str(e["payload"].get("license_id"))):
                    errs.append(f"{at}: GENESIS license_id is not the licence commitment (64 lowercase hex), required from spec 1.8 (4.1)")
            if e.get("chain_id") != man["chain_id"]: errs.append(f"{at}: chain_id differs from the manifest")
    if errs: return _fmt_err(res, errs)

    # Stage 4a (10.5): the vendor list and the salt files of presented plaintexts against the number rule (2), read
    # lexically - a member twice or a broken text is judged where the file is read (10.7, 10.1), a number never there.
    for name in sorted(n for n in files if n == "keys/vendor/schluesselliste.json" or re.fullmatch(r"content/[1-9][0-9]*\.salts\.json", n)):
        try: num_scan(files[name])
        except NumberError as exc: errs.append(f"{name}: {exc}")
    if errs: return _fmt_err(res, errs)

    # Stage 5: the checks of the chain. Step 1 (10.5, from 1.10): the request time against the check time of
    # verify_args.json, which only now is known; after it, FORMAT_ERROR and nothing more of stage 5 (10.8). Against
    # --now or the system clock the invocation already checked it.
    if inputs.requested_at is not None and res.now_source == "package" and ms(inputs.requested_at) > now:
        return _fmt_err(res, [f"--requested-at {inputs.requested_at} lies after the check time of verify_args.json (10.8)"])
    # (2) seq contiguity and hash chain (format.de.md 3)
    bad = next((i for i, e in enumerate(entries) if e["seq"] != i + 1), None)
    seq_ok = bad is None
    if not seq_ok:
        res.add("SEQ_BREAK", f"position {bad + 1} carries seq={entries[bad]['seq']}, expected {bad + 1}")
    # GENESIS exactly once, at seq 1 (3): a first entry of another type and a GENESIS anywhere
    # else are FORMAT_ERROR (until 29.09. the first was SEQ_BREAK and a later GENESIS passed
    # unseen - the Go verifier said exit 3 to what this one called valid). The run goes on and
    # reports every other finding; chain end and active holds are then not judged (below).
    if entries[0]["event_type"] != "GENESIS":
        res.add("FORMAT_ERROR", f"seq={entries[0]['seq']}: the chain starts with {entries[0]['event_type']}, not GENESIS")
    for e in entries[1:]:
        if e["event_type"] == "GENESIS": res.add("FORMAT_ERROR", f"seq={e['seq']}: GENESIS after the first entry: only seq 1 is GENESIS")
    for i, e in enumerate(entries):
        got = entry_hash(e)
        if got != e["entry_hash"]: res.add("HASH_MISMATCH", f"seq={e['seq']}: entry_hash {e['entry_hash']} != {got}")
        want = ZERO if i == 0 else entries[i - 1]["entry_hash"]
        if e["prev_hash"] != want: res.add("HASH_MISMATCH", f"seq={e['seq']}: prev_hash {e['prev_hash']} != {want}")

    leaves = [bytes.fromhex(e["entry_hash"]) for e in entries]
    root = [mth([]).hex()] + [r.hex() for r in prefix_roots(leaves)]   # root[t]: MTH of the first t entries (5)

    # (3)+(4) device key trust chain IN CHAIN ORDER (format.de.md 6.4): exactly one
    # key is valid at any seq - the GENESIS key until a KEY_ROTATION, the new key
    # from that entry on. A checkpoint signed by a key that is not the one valid
    # at its position (old key after the rotation, new key before it) is
    # SIG_INVALID; a set of "ever trusted" keys would let both pass.
    vendor = {k["key_id"]: k["pubkey"] for k in man["vendor_pubkeys"]}
    cur_id, cur_pk, legit, dev_keys = "", "", False, []  # dev_keys: PK of 8.8.4, GENESIS.device_pubkey and every key 6.4 legitimises
    if entries[0]["event_type"] == "GENESIS":
        cur_id, cur_pk, legit = entries[0]["payload"]["device_key_id"], entries[0]["payload"]["device_pubkey"], True
        dev_keys.append(cur_pk)
    prev_cp = ZERO
    for e in entries:
        p, s = e["payload"], e["seq"]
        if e["event_type"] == "KEY_ROTATION":
            msg = jcsb({"old_key_id": p["old_key_id"], "new_key_id": p["new_key_id"], "new_pubkey": p["new_pubkey"]})
            if not (p["old_key_id"] == cur_id and cur_pk
                    and ed25519_verify(bytes.fromhex(cur_pk), bytes.fromhex(p["signature_by_old_key"]), msg)):
                res.add("SIG_INVALID", f"seq={s}: KEY_ROTATION not certified by the key valid at this point ({cur_id})")
                legit = False                                # 6.4: the unbroken sequence back to GENESIS ends here
            elif legit: dev_keys.append(p["new_pubkey"])
            cur_id, cur_pk = p["new_key_id"], p["new_pubkey"]  # adopt either way, like the Go verifier
            continue
        if e["event_type"] != "CHECKPOINT": continue
        obj = {"chain_id": e["chain_id"], "tree_size": p["tree_size"], "merkle_root": p["merkle_root"],
               "prev_checkpoint_hash": p["prev_checkpoint_hash"], "key_id": p["key_id"], "ts": e["ts_chained"]}
        if p["key_id"] != cur_id or not cur_pk:
            res.add("SIG_INVALID", f"seq={s}: key_id {p['key_id']} is not the device key valid at this seq ({cur_id})")
        elif not ed25519_verify(bytes.fromhex(cur_pk), bytes.fromhex(p["signature"]), jcsb(obj)):
            res.add("SIG_INVALID", f"seq={s}: the checkpoint signature does not verify")
        if p["prev_checkpoint_hash"] != prev_cp:
            res.add("HASH_MISMATCH", f"seq={s}: prev_checkpoint_hash {p['prev_checkpoint_hash']}, want {prev_cp}")
        prev_cp = e["entry_hash"]
        if p["tree_size"] > len(leaves):
            res.add("MERKLE_INCONSISTENT", f"seq={s}: tree_size={p['tree_size']} exceeds the {len(leaves)} entries present (truncation)")
        elif seq_ok and p["tree_size"] != s - 1:
            res.add("MERKLE_INCONSISTENT", f"seq={s}: tree_size={p['tree_size']}, expected seq-1={s - 1}")
        elif root[p["tree_size"]] != p["merkle_root"]:
            res.add("MERKLE_INCONSISTENT", f"seq={s}: merkle_root {p['merkle_root']}, recomputed {root[p['tree_size']]}")

    # (5) receipts and anchoring (format.de.md 7). The vendor key comes from the
    # AUDITOR's anchors (7.1): a pinned key, or the vendor root vouching through the
    # signed list in the package (10.7); the manifest's copy only where neither reaches.
    roots = inputs.vendor_roots
    raw = files.get("keys/vendor/schluesselliste.json")
    lst, lroot, lver, note = None, "", 0, "the package carries no keys/vendor/schluesselliste.json"
    if raw is not None:       # its numbers were read in stage 4a, with or without a root (2)
        lst, lroot, lver, note = vendor_list(raw, roots)
        note = f"the list does not count: {note}" if roots else "no vendor root was supplied to check the package's list against"
        if lst is not None:   # 7.1: a newer list is not visible from the package -- name the one used
            res.vendor_list = {"version": lver, "ausgestellt": jloads(raw)["ausgestellt"], "wurzel_id": lroot}
    # Step 4 of stage 5 (10.5): the role check (10.7.4) with step L1 (7.4.10), before the receipts. Only a
    # countersigning pin that is not dropped and the package's own list establish a receipt (7.1); the auditor's
    # lists and the role list never do.
    res.roles = key_roles(inputs, {k[0] for k in (lst or {}).values()}, reg, set(lst or ()))
    pinned, other_role_note = res.roles["cs_pins"], False
    anchors, lc_receipt = 0, 0                       # lc_receipt: seq of the receipt behind last_countersigned (11.2)
    countersigned = {}                               # 8.6: every countersigned tree_size -> (receipt seq, server_ts), first on a tie (11.2, 1.10)
    held = []                                        # 7.4.10 L7, L8, 10.9.4 r5': every receipt whose signature holds under the key of 7.1, without RECEIPT_INVALID
    est = set()                                      # 8.8.4: the seq of the held receipts whose key is pinned or from the package's list (belegte Quittungen)
    ev_receipts = []                                 # 10.9.3: per receipt whose signature holds after 7.1 its tree_size, key and the origin of the key
    res.sig_receipt = False                          # 10.10.3, line on affiliation: the package carries a receipt whose signature holds
    for e in entries:
        if e["event_type"] != "CHECKPOINT_RECEIPT": continue
        p, s = e["payload"], e["seq"]
        obj = {"chain_id": e["chain_id"], "tree_size": p["tree_size"], "merkle_root": p["merkle_root"], "server_ts": p["server_ts"]}
        kid, contra = p["server_key_id"], ""
        pk, known = pinned.get(kid), kid in pinned
        if not known and lst and kid in lst:
            pk, ab, bis, wid, raw_k = lst[kid]; known, t = True, utc_ns(p["server_ts"])
            if t is None or t < ab or (bis is not None and t >= bis) or (wid is not None and t >= wid):
                contra = f"the vendor's list (root {lroot}, version {lver}) does not make key {kid} valid at {p['server_ts']}: {raw_k}"
        if not known: pk = vendor.get(kid)            # the manifest copy counts only where no anchor reaches (10.1)
        # 10.7.4: a receipt not established whose manifest key is a key of another role is judged as in 1.9 and
        # gives the note receipt_key_other_role; for it every pin as a statements or protocol key counts, also one
        # dropped after R3 (10.7.4, Quittungen).
        if not known and pk in res.roles["other_role"]: other_role_note = True
        if pk is None or not ed25519_verify(bytes.fromhex(pk), bytes.fromhex(p["server_signature"]), jcsb(obj)):
            res.add("RECEIPT_INVALID", f"seq={s}: vendor countersignature invalid for key {kid}")
            continue
        res.sig_receipt = True
        # 10.9.3: the origin of the key as in evidence_level.anchors.vendor_keys (10.10.2): a pin not dropped, the package's
        # list under a vendor root of the auditor (this verifier builds no root in), or the manifest copy (via None).
        ev_receipts.append({"seq": s, "tree_size": p["tree_size"], "key_id": kid, "pubkey": pk,
                            "via": "pinned" if kid in pinned else "list" if known else None,
                            "list_version": lver if known and kid not in pinned else None,
                            "root_id": lroot if known and kid not in pinned else None})
        # 7.4.10 L8 (decision D): L7, L8 and r5' (10.9.4) read the same receipts, those whose signature holds and that have
        # no RECEIPT_INVALID (the vendor's list contradicts the key, or the checkpoint disagrees: both are passed over, also
        # where the signature holds). "auch bei einem Widerspruch oder Fork" is one of the chain: a receipt with
        # FORK_DETECTED or MERKLE_INCONSISTENT stays in. Appended after the checkpoint check below.
        if contra: res.add("RECEIPT_INVALID", f"seq={s}: {contra}")   # signature holds: prefix check below still runs
        if not known:
            why = f"neither pinned by the auditor nor vouched for by a list its root verifies ({note})"
            if not (roots or pinned): why = "no vendor root and no vendor key was supplied by the auditor"
            elif lst: why = f"not pinned and not in the vendor's list (root {lroot}, version {lver})"
            if kid in inputs.cs_pins and kid not in pinned: why += "; the auditor's pin of this key_id was dropped, a list names its public key with another role (10.7.4 R3 (d))"
            res.once("RECEIPT_UNVERIFIED", kid, f"seq={s}: receipts under vendor key {kid} (pubkey {pk}, from the package manifest) "
                                                f"are consistent, but the key is not established as the vendor's: {why} (7.1)")
        cp_ok = True                                 # 7.1: prefix first; checkpoint only when the prefix matches
        if p["tree_size"] > len(leaves):
            res.add("MERKLE_INCONSISTENT", f"seq={s}: receipt anchors tree_size={p['tree_size']}, only {len(leaves)} entries present (truncation)")
        elif root[p["tree_size"]] != p["merkle_root"]:
            res.add("FORK_DETECTED", f"seq={s}: anchored root for tree_size={p['tree_size']} matches no prefix of this chain")
        else:
            cp = next((c for c in entries if c["seq"] == p["checkpoint_seq"] and c["event_type"] == "CHECKPOINT"), None)
            if cp is None or (cp["payload"]["tree_size"], cp["payload"]["merkle_root"]) != (p["tree_size"], p["merkle_root"]):
                res.add("RECEIPT_INVALID", f"seq={s}: checkpoint_seq={p['checkpoint_seq']} is no CHECKPOINT of this chain or disagrees with the receipt")
                cp_ok = False
            elif not contra:
                countersigned.setdefault(p["tree_size"], (s, p["server_ts"]))
                if res.last_countersigned is None or p["tree_size"] > res.last_countersigned["tree_size"]:   # 8.6: anchor per 7.1, first on a tie
                    res.last_countersigned = {k: p[k] for k in ("checkpoint_seq", "tree_size", "merkle_root", "server_ts")}
                    lc_receipt = s
        anchors += 1 if cp_ok and not contra else 0  # contradicted or checkpoint-less receipts anchor nothing (7.1)
        if cp_ok and not contra:
            held.append(e)
            if known: est.add(s)
    res.key_roles = finish_key_roles(res.roles["report"], other_role_note)

    # Step 6 of stage 5 (10.5): the vendor log, 7.4.10 L2 to L10, after the receipts. It reads the auditor's inputs, which
    # receipts hold, the prefix roots, A and now, and adds only its five classes (exit class 1) and the object vendor_log.
    if entries[0]["event_type"] == "GENESIS":
        res.vendor_log, res.vlog = vendor_log(res, inputs, reg, entries, root, held, now, lc_receipt)
        res.vl_reg = reg["vendor_log"]

    # Step 7 of stage 5 (10.5): the anchor history, steps H1 to H7 (8.8.4), after the vendor log. It reads the auditor's
    # pages and R, the device keys of the package (PK), the receipts of 7.1, K_cs and the checked records of the vendor log.
    g = entries[0]["payload"] if entries[0]["event_type"] == "GENESIS" else None
    hist = AnchorHistory(res, inputs, reg, {"C": res.chain_id, "A": g and g["appliance_id"], "N": len(entries), "PK": dev_keys,
                                            "gen_pred": ((g or {}).get("predecessor_chain") or {}).get("chain_id"), "held": held, "est": est,
                                            "kcs_ids": set(res.roles["kcs_l_ids"]) | set(pinned),
                                            "records": res.vlog["records"] if res.vlog else {}})
    if g is None: hist.supplied = False                # a format error (GENESIS not at seq 1): not judged, the objects are null
    hist.run_h1_h7()
    # Step 8: the expected roots of both sources with their sources; the classification H8 of 8.8.5 is computed here
    # and its findings are reported at step 13 (8.8.4, Stellung im Pruefablauf).
    found, pending = hist.classify(expect_roots, root, len(leaves))

    # Time witnesses (7.3), steps 1-6 in order, after the time-stamp profile (7.5). Steps 1 to 4 need no certificate:
    # what fails them binds nothing and is no anchor. Step 5a (not performable) is TIME_ANCHOR_UNVERIFIED with the
    # reason, never INVALID; 5b (performed and failed) is TIME_ANCHOR_INVALID. Step 6 counts only roots of the purpose
    # chain the auditor passes (7.5.7): no system root store, no root built in; keys/tsa/ of the package is tried
    # afterwards for the report alone. Z.6, rule QS and published test keys never change the finding (7.5.7).
    chain_roots, all_roots, pkg_tsa, res.time_anchors = inputs.roots_for("chain"), [e["cert"] for e in inputs.roots.values()], None, []
    for e in entries:
        if e["event_type"] != "TIME_ANCHOR": continue
        p, s = e["payload"], e["seq"]
        cp = next((c for c in entries if c["seq"] == p["checkpoint_seq"] and c["event_type"] == "CHECKPOINT"), None)
        if cp is None or (cp["payload"]["tree_size"], cp["payload"]["merkle_root"]) != (p["tree_size"], p["merkle_root"]):
            res.add("TIME_ANCHOR_INVALID", f"seq={s}: checkpoint_seq={p['checkpoint_seq']} is no CHECKPOINT of this chain or disagrees with it (7.3 step 1)")
            continue
        q = cp["payload"]
        subject = jcsb({"chain_id": cp["chain_id"], "tree_size": q["tree_size"], "merkle_root": q["merkle_root"],
                        "prev_checkpoint_hash": q["prev_checkpoint_hash"], "key_id": q["key_id"], "ts": cp["ts_chained"]})
        try: r = ts_assess(b64_decode(p["token_base64"]), subject, all_roots)
        except ValueError as exc:
            res.add("TIME_ANCHOR_INVALID", f"seq={s}: token_base64 {exc} (7.3 step 2)")
            continue
        if r["grammar"]:
            res.add("TIME_ANCHOR_INVALID", f"seq={s}: the token is no TimeStampToken of the profile: {r['grammar']} (7.3 step 2, 7.5.2)")
            continue
        t = r["t"]
        # Step 3: the three readings tsa_policy, tsa_serial and tsa_ts; the imprint algorithm has no field and serves step 4.
        got = (t["policy"], format(t["serial"], "x"), t["gen_time_ms"])
        if (p["tsa_policy"], p["tsa_serial"], p["tsa_ts"]) != got:
            res.add("TIME_ANCHOR_INVALID", f"seq={s}: the readings tsa_policy, tsa_serial, tsa_ts {(p['tsa_policy'], p['tsa_serial'], p['tsa_ts'])} "
                                           f"contradict the token {got}; tsa_ts is genTime {t['gen_time']} cut to milliseconds (7.3 step 3)")
            continue
        if not r["imprint_ok"]:
            res.add("TIME_ANCHOR_INVALID", f"seq={s}: the token's imprint ({HASH_NAMES[t['imprint_alg']]}) attests a subject other than checkpoint seq={cp['seq']} (7.3 step 4)")
            continue
        anchors += 1                                 # bound, so an anchor IS present, whatever steps 5 and 6 say (7.3)
        signer = r["signer"]
        res.time_anchors.append({"seq": s, "checkpoint_seq": cp["seq"], "tree_size": p["tree_size"], "assessment": r})
        who = (f"time witness {signer.name!r} (certificate serial {format(signer.serial, 'x')})" if signer else "time witness (no signer certificate found)") + \
              f", token serial {format(t['serial'], 'x')}, genTime {t['gen_time']}"
        if r["step5"] == "failed":
            res.add("TIME_ANCHOR_INVALID", f"seq={s}: the token does not carry its own signature: {r['step5_why']}; {who} (7.3 step 5b)")
            continue
        if r["step5"] == "not_performable":
            res.add("TIME_ANCHOR_UNVERIFIED", f"seq={s}: the token binds checkpoint seq={cp['seq']}, but its signature is not checkable after the "
                                              f"profile: {r['step5_why']}; {who} (7.3 step 5a, 7.5.4)")
            continue
        if any(r["paths"].get(c.der) for c in chain_roots): continue      # step 6 holds against a root of the auditor
        why = "no path after Z.3 and Z.4 at genTime to a root the auditor passes for time witnesses of the chain"
        pkg_tsa = _package_tsa(files) if pkg_tsa is None else pkg_tsa
        pool = [Cert(x[1]) for x in der_seq(t["certificates"], 0xa0)]
        if any(z4_path(signer, pool, c, t["gen_ns"]) for c in pkg_tsa):
            why = f"it chains only to a certificate the package itself brings along (keys/tsa/), which is no root; look the authority up outside the package. Against the auditor's roots: {why}"
        res.add("TIME_ANCHOR_UNVERIFIED", f"seq={s}: the token binds checkpoint seq={cp['seq']} and carries its signature, but its authority is not "
                                          f"established: {who}: {why}; roots of the purpose chain: {len(chain_roots)} (--tsa-root, --tsa-qualified-roots); "
                                          f"the system root store counts for no purpose (7.3 step 6, 7.5.7)")

    # Step 11 (10.5): the anchor history, steps H9 to H11 (8.8.4), with the classification of step 8.
    hist.run_h9_h11(root, len(leaves))
    hist.emit(res)
    # Step 12: an anchor is present (7, 10.8): a receipt, a bound time witness or a found expected root of either source.
    anchors += len(found)
    if anchors == 0: res.add("NO_ANCHOR", "no receipt counts as an anchor (signature holding, not contradicted by the vendor's list), "
                                          "no time witness binds its checkpoint and no expected root of the auditor or the anchor history was found")
    # Step 13: the findings of the expected roots (10.8) with those of the classification (8.8.5): with a tree_size an
    # expected root is found if the root over that many entries equals it, never beyond the entries present; without one
    # at the largest t whose prefix root equals it. A root of the auditor not found is MERKLE_INCONSISTENT; a history
    # root without the source auditor follows 8.8.5, and one only reported never gives exit 2 there.
    for cls, detail in pending: res.add(cls, detail)
    # 8.6: completeness up to the largest tree_size of a found expected root of either source, with their sources (1.10).
    res.completeness = {"status": "established" if found else "not_established", "up_to_tree_size": max((t for t, _s in found), default=None),
                        "sources": [x for x in reg["verifier"]["report_objects"]["completeness_sources_order"] if any(x in src for _t, src in found)]}

    # (6) declared gaps and notes (format.de.md 8.3, 9.1, 9.2) and deletion holds (9.3), in chain
    # order: a hold is active from its LEGAL_HOLD set until a release of the same hold_id; a further
    # set replaces its scope (holds[id] then names that entry: set_seq and scope come from it); a
    # release without an active hold is without effect. A CONTENT_DELETED whose target_seq names an
    # AI_CALL whose ts_captured an active hold covers (bounds inclusive, as instants to the
    # nanosecond - utc_ns, not strings) is HOLD_VIOLATION: once per deletion, naming every such hold.
    by_seq, holds = {e["seq"]: e for e in entries}, {}
    for e in entries:
        t, p, s = e["event_type"], e["payload"], e["seq"]
        if t == "GAP":
            res.add("COVERED_GAP", f"seq={s}: declared gap {p['reason']}, {p['started_ts']} .. {p['ended_ts']}, lost={p['lost_count']}")
        elif t == "SOURCE_GAP":
            res.add("COVERED_SOURCE_GAP", f"seq={s}: declared source gap {p['source_id']}, {p['window_start']} .. {p['window_end']}")
        elif t == "RECONCILIATION" and p["delta"] != 0:
            res.add("RECONCILIATION_DELTA", f"seq={s}: {p['source_id']} reports {p['reported_count']}, chain holds {p['chained_count']} (delta {p['delta']})")
        elif t == "CONTENT_DELETED":
            res.add("CONTENT_DELETED", f"seq={s}: vault object {p['vault_ref']} of seq={p['target_seq']} deleted ({p['reason']})")
            x = by_seq.get(p["target_seq"], {})       # names no entry or no AI_CALL: no hold applies (9.3)
            hit = [h["payload"] | {"seq": h["seq"]} for h in holds.values() if x.get("event_type") == "AI_CALL"
                   and utc_ns(h["payload"]["scope_from"]) <= utc_ns(x["ts_captured"]) <= utc_ns(h["payload"]["scope_to"])]
            if hit: res.add("HOLD_VIOLATION", f"seq={s}: deletes the content of target_seq={p['target_seq']} (AI_CALL, ts_captured "
                                              f"{x['ts_captured']}), covered by active hold(s) " + ", ".join(
                                              f"hold_id={h['hold_id']} ({h['scope_from']} .. {h['scope_to']}, set at seq={h['seq']})" for h in hit))
        elif t == "LEGAL_HOLD" and p["action"] == "set": holds[p["hold_id"]] = e
        elif t == "LEGAL_HOLD": holds.pop(p["hold_id"], None)
        elif t == "CLOCK_JUMP":
            res.add("CLOCK_JUMP_NOTE", f"seq={s}: declared clock jump {p['jump_ms']} ms ({p['wall_before']} -> {p['wall_after']})")
    res.legal_holds = [{"hold_id": h, "scope_from": x["payload"]["scope_from"], "scope_to": x["payload"]["scope_to"],
                        "set_seq": x["seq"]} for h, x in holds.items()]   # active at the chain end, in the order they became active

    # (7) silence coverage and clock plausibility (format.de.md 8.2, 9.2), in whole milliseconds (2). The
    # critical types (nine since 1.7) are not hardcoded here: the registry marks them itself.
    crit = {t for t, d in reg["event_types"].items() if d.get("critical_checkpoint")}
    for i in range(1, len(entries)):
        a, b = entries[i - 1], entries[i]
        ta, tb = ms(a["ts_chained"]), ms(b["ts_chained"])
        if tb - ta > TICK_TOLERANCE_MS and not _covered(a, b, entries, i, ta, tb, crit):
            res.add("CONCEALED_SILENCE", f"seq={a['seq']} -> {b['seq']}: {tb - ta} ms silence, no covering GAP/RESTART/handover")
        md = b["mono_delta_ms"]
        if md < 0: continue
        diff = (tb - ta) - md
        if abs(diff) <= CLOCK_TOLERANCE_MS: continue
        if b["event_type"] == "CLOCK_JUMP" and abs(diff - b["payload"]["jump_ms"]) <= CLOCK_TOLERANCE_MS: continue
        res.add("CLOCK_ANOMALY", f"seq={b['seq']}: wall {tb - ta} ms vs monotonic {md} ms, undeclared diff {diff} ms")

    # (8) immediate checkpoint of every critical type (format.de.md 6.2 rule 3, without
    # exception and expressly including SEAL) and the SEAL/RESUME handover (8.4).
    # A critical entry that is the LAST entry lacks no entry between two present ones: from
    # 1.6 that is no MISSING_CHECKPOINT but an unanchored chain end (UNSEALED_END below).
    n, resumed, seal = len(entries), set(), None
    for i, e in enumerate(entries):
        nxt = entries[i + 1]["event_type"] if i + 1 < n else None
        if e["event_type"] in crit and nxt not in ("CHECKPOINT", None):
            res.add("MISSING_CHECKPOINT", f"seq={e['seq']}: critical {e['event_type']} is followed by {nxt}, not by its immediate CHECKPOINT")
        if e["event_type"] != "SEAL": continue
        j = i + 2 if nxt == "CHECKPOINT" else i + 1     # 8.4: only that checkpoint may stand between
        cp = entries[i + 1]["seq"] if nxt == "CHECKPOINT" else 0
        k = j                                           # receipts on that checkpoint may trail the chain END only
        while k < n and entries[k]["event_type"] == "CHECKPOINT_RECEIPT" and entries[k]["payload"]["checkpoint_seq"] == cp: k += 1
        if k >= n: j = k
        if j >= n: seal = e if cp else None             # 8.6: SEAL + its checkpoint close the chain, whatever the reason
        elif entries[j]["event_type"] != "RESUME":
            res.add("HANDOVER_BROKEN", f"seq={e['seq']}: SEAL followed by {entries[j]['event_type']} at seq={entries[j]['seq']}, not RESUME")
        elif resumed.add(j) or entries[j]["payload"]["sealed_entry_hash"] != e["entry_hash"]:
            res.add("HANDOVER_BROKEN", f"seq={entries[j]['seq']}: RESUME sealed_entry_hash {entries[j]['payload']['sealed_entry_hash']} != SEAL entry_hash {e['entry_hash']}")
    for i, e in enumerate(entries):                     # 8.4: every RESUME continues exactly one SEAL
        if e["event_type"] == "RESUME" and i not in resumed:
            res.add("HANDOVER_BROKEN", f"seq={e['seq']}: RESUME without a directly preceding SEAL (+ immediate checkpoint)")

    # (9) presented plaintexts and reports (9.1, 10.1) - before the chain end: a number outside the integer
    # profile in a salt file is a format error (2), and a format error leaves the chain end unjudged.
    _content(res, files, entries)
    _reports(res, files, entries)

    # Chain end (8.6): sealed = SEAL, its immediate CHECKPOINT, then at most receipts on exactly
    # that checkpoint - whatever the reason, the export seal of 1.9 included. Every other end is
    # incomplete: UNSEALED_END exactly once, at the last seq, also beside exit-2 findings (10.3 ranks
    # them). Offline a live export, a crash and a truncation look alike, so the finding names the last
    # countersigned checkpoint and the comparison. A format error (exit 3; a misplaced GENESIS, a
    # number outside the profile in the vendor list or a salt file) is not judged (8.6): no chain end,
    # no UNSEALED_END, and at the end of verify() no holds, countersigned checkpoint, completeness or residual window.
    last, s = entries[-1], seal or {}
    unjudged = any(f["class"] == "FORMAT_ERROR" for f in res.findings)
    res.chain_end = None if unjudged else {"status": "sealed" if seal else "incomplete", "last_seq": last["seq"], "seal_seq": s.get("seq"),
                                           "seal_reason": s.get("payload", {}).get("reason"), "seal_ts": s.get("ts_chained")}
    if not seal and not unjudged:
        lc = ", ".join(f"{k}={v}" for k, v in res.last_countersigned.items()) if res.last_countersigned else "none"
        why = " (critical: its immediate CHECKPOINT is missing, 6.2)" if last["event_type"] in crit else ""
        res.add("UNSEALED_END", f"seq={last['seq']}: the chain ends with {last['event_type']}{why} at {last['ts_chained']}, not with SEAL + "
                                f"its immediate CHECKPOINT: nothing in the package shows that no entry followed. Last countersigned checkpoint "
                                f"in the package: {lc}. Compare: fetch the vendor's anchor history for chain_id {man['chain_id']} (heartbeat spec 9.7) and "
                                f"re-run with --expect-root TREE_SIZE:ROOT for every root in it recorded before this package was requested, at least "
                                f"the most recent countersigned one; entries the vendor countersigned "
                                f"and the package lacks then show as MERKLE_INCONSISTENT (8.6)")

    # (10) freshness (format.de.md 8.5) - always, against the resolved check time, in whole milliseconds (2)
    age = now - ms(entries[-1]["ts_chained"])
    window = round(freshness_h * 3600000)
    if age > window:                                                    # the window as given, exactly: 24.0 h, 1.5 h, 7199 s
        shown = f"{freshness_h:.1f} h" if window % 360000 == 0 else f"{window // 1000} s" if window % 1000 == 0 else f"{window} ms"
        res.add("TRAILING_SILENCE", f"chain ends {age / 3600000:.1f} h before the check time ({res.now_source}), freshness window {shown}")

    # (12) the residual window (11.2), measured - no finding: the entries after the last countersigned checkpoint
    # (T = its tree_size, 0 if there is none) up to the chain end, and the anchor messages chained after that
    # checkpoint's receipt (all of them for T = 0) for which the package holds no countersignature.
    T, N = res.last_countersigned["tree_size"] if res.last_countersigned else 0, len(entries)
    span = ms(entries[-1]["ts_chained"]) - ms(entries[T - 1]["ts_chained"]) if T else None
    res.residual_window = {"after_tree_size": T, "first_seq": T + 1, "last_seq": N, "entries": N - T,
                           "from_ts": entries[T - 1]["ts_chained"] if T else None, "to_ts": entries[-1]["ts_chained"], "span_ms": span,
                           "unanswered_anchor_messages": sum(1 for e in entries if e["event_type"] == "ADMIN" and e["seq"] > lc_receipt
                                                             and e["payload"]["message_type"] == "anchor"),
                           "beyond_cadence": T == 0 or span > TICK_TOLERANCE_MS}
    # (12a) covered stretches (11.2, from 1.10) - no finding: between two consecutive countersigned checkpoints
    # T1 < T2 more than the cadence (ts_chained at T1 and T2), the anchor messages in the stretch after the receipt
    # of T1, and the receipt of T2 that covers it. Every countersigned tree_size passed the prefix check, so <= N.
    sizes, res.unanchored_stretches = sorted(countersigned), []
    for t1, t2 in zip(sizes, sizes[1:]):
        span = ms(entries[t2 - 1]["ts_chained"]) - ms(entries[t1 - 1]["ts_chained"])
        if span <= TICK_TOLERANCE_MS: continue
        r1, (r2, r2_ts) = countersigned[t1][0], countersigned[t2]
        res.unanchored_stretches.append({"after_tree_size": t1, "first_seq": t1 + 1, "last_seq": t2,
                                         "from_ts": entries[t1 - 1]["ts_chained"], "to_ts": entries[t2 - 1]["ts_chained"], "span_ms": span,
                                         "unanswered_anchor_messages": sum(1 for e in entries[t1:t2] if e["event_type"] == "ADMIN" and e["seq"] > r1
                                                                           and e["payload"]["message_type"] == "anchor"),
                                         "receipt_seq": r2, "receipt_server_ts": r2_ts})
    # Step 15 (10.5): the affiliation (8.8.6, H12) and the report objects anchor_history and affiliation (10.10.2, H13). They
    # add no finding, so the exit code is the same whether it is formed before or after them.
    res.anchor_history, res.affiliation = hist.report(), hist.affiliation()
    res.ah_reg, res.af_reg, res.n_entries = reg["verifier"]["anchor_history"], reg["verifier"]["affiliation"], len(entries)
    # 10.9.3: what the run holds for the evidence level, formed after the exit code (10.5 stage 5, step 15). A found
    # expected root has root(found_at) as its merkle_root (10.8).
    res.ev = {"N": len(entries), "D": set(dev_keys), "receipts": ev_receipts, "lc_seq": lc_receipt, "time_anchors": res.time_anchors,
              "time_anchor_entries": sum(1 for e in entries if e["event_type"] == "TIME_ANCHOR"), "roots": inputs.roots,
              "qualified": inputs.qualified, "vendor_roots": inputs.vendor_roots, "pkg_spki": package_tsa_spki(files),
              "found": [(t, root[t], set(src)) for t, src in found], "hist": hist}
    if unjudged:              # 8.6, 11.2, 10.10.1: not judged, so not named either
        res.last_countersigned = res.legal_holds = res.completeness = res.residual_window = res.unanchored_stretches = res.key_roles = None
        res.vendor_log = res.anchor_history = res.affiliation = None
    g = entries[0]   # 4.1: up to 1.7 license_id was undefined and the installation wrote the key there - a notice, never the value
    res.glic = None if unjudged else g["event_type"] == "GENESIS" and not _minor_at_least(g["spec_version"], "8") and not HEX64.fullmatch(str(g["payload"].get("license_id")))
    return res


def _minor_at_least(v, n):   # v is a well-formed "1.m" (10.6 R1) with m >= n, compared as decimals of any length
    m = re.fullmatch(r"1\.(0|[1-9][0-9]*)", v) if isinstance(v, str) else None
    return m is not None and (len(m[1]), m[1]) >= (len(n), n)


def _covered(a, b, entries, i, ta, tb, crit=()):
    """format.de.md 8.2: is the silence between a and b (ta, tb: whole milliseconds) declared by the chain itself?
    crit: the registry's critical types, for condition 4. Only the fields each entry type promises are read."""
    def after(k): return entries[i + k] if i + k < len(entries) else {"event_type": None}

    def gap_covers(g):        # condition 1, and part (d) of condition 4: the GAP's window encloses the silence
        return g["event_type"] == "GAP" and ms(g["payload"]["started_ts"]) <= ta + TICK_TOLERANCE_MS \
            and ms(g["payload"]["ended_ts"]) >= tb - TICK_TOLERANCE_MS

    def resumes(r, seal):     # 8.4 clarification 3: only the handover the RESUME really continues covers
        return r["event_type"] == "RESUME" and r["payload"]["sealed_entry_hash"] == seal["entry_hash"]

    if b["event_type"] == "GAP": return gap_covers(b)
    if b["event_type"] == "RESTART": return True
    # Condition 3 runs from the SEAL's immediate checkpoint to the RESUME - the SEAL
    # itself no longer covers the planned silence, its checkpoint does.
    if b["event_type"] == "RESUME":
        return a["event_type"] == "CHECKPOINT" and i >= 2 and entries[i - 2]["event_type"] == "SEAL" and resumes(b, entries[i - 2])
    # From 1.9 a late immediate checkpoint: b is written at restart - mono_delta_ms -1, the trace of a new
    # process; a writer that merely stalled writes mono >= 0 and stays concealed.
    if b["event_type"] != "CHECKPOINT" or b["mono_delta_ms"] != -1: return False
    # Condition 3, second half: a crash between a SEAL and its checkpoint, declared by the RESUME that follows -
    # or by nothing: the chain ends sealed there (the restart's RESUME never landed).
    if a["event_type"] == "SEAL": return after(1)["event_type"] is None or resumes(after(1), a)
    # Condition 4: a critical entry other than SEAL, its checkpoint written late, then at once a RESTART (at
    # most 450 000 ms after b, its downtime unknown or long enough) and a GAP whose window covers the silence.
    r = after(1)
    if a["event_type"] not in crit or r["event_type"] != "RESTART" or ms(r["ts_chained"]) - tb > TICK_TOLERANCE_MS: return False
    down = r["payload"]["downtime_ms_estimate"]
    return (down == -1 or down >= tb - ta - TICK_TOLERANCE_MS) and gap_covers(after(2))


def _content(res, files, entries):
    """format.de.md 9.1, 10.1: presented plaintexts. The presentation for the AI_CALL with seq n is content/<n>.salts.json
    with content/<n>.request and/or content/<n>.response; each presented part must match the commitment in the chain.
    Every file under content/ is checked: one that is no part of a presentation that holds is CONTENT_MISMATCH, once.
    n stays the decimal text of the name, of any length and without a leading zero: it names the entry whose seq reads
    the same, one beyond 2^53-1 names none (int() would refuse more than 4300 digits)."""
    by_seq, shown = {str(e["seq"]): e for e in entries}, {}
    for name in sorted(n for n in files if n.startswith("content/")):
        m = PRESENTED.fullmatch(name)
        if m: shown.setdefault(m[1], {})[m[2]] = files[name]
        else: res.add("CONTENT_MISMATCH", f"{name}: no file of a presentation (content/<n>.salts.json, <n>.request, <n>.response, 10.1)")
    for n, group in sorted(shown.items(), key=lambda x: (len(x[0]), x[0])):       # in seq order
        parts = [p for p in ("request", "response") if p in group]
        salts, why = None, f"content/{n}.salts.json is missing"
        if "salts.json" in group:
            try: salts = _salt_file(group["salts.json"], n, parts)
            except Exception as exc: res.add("CONTENT_MISMATCH", f"content/{n}.salts.json: {exc} (10.1)"); why = "its salt file does not conform"
        e = by_seq.get(n, {})
        for part in parts:
            name, want = f"content/{n}.{part}", e["payload"].get(part + "_commitment") if e.get("event_type") == "AI_CALL" else None
            got = hmac.new(salts[part], group[part], hashlib.sha256).hexdigest() if salts else None
            if salts is None:
                res.add("CONTENT_MISMATCH", f"{name}: cannot be checked, {why} (10.1)")
            elif want is None:
                res.add("CONTENT_MISMATCH", f"{name}: seq={n} is no AI_CALL of this chain with a {part}_commitment (10.1)")
            elif got != want:
                res.add("CONTENT_MISMATCH", f"{name}: the presented {part} commits to {got}, the chain holds {want}")


def _salt_file(raw, n, parts):
    """The salt file of presentation n (10.1, n its decimal text): I-JSON of exactly seq (= n), a hex64 <part>_salt for
    each presented part and none for a part not presented, and optionally vault_ref (a string, not evaluated). Returns
    {part: salt}."""
    s = jloads(raw)
    if not parts: raise ValueError("a salt file without a plaintext")
    want = {"seq"} | {p + "_salt" for p in parts}
    if not isinstance(s, dict) or not want <= set(s) <= want | {"vault_ref"}:
        raise ValueError(f"not an object of exactly {', '.join(sorted(want))} and an optional vault_ref")
    if type(s["seq"]) is not int or str(s["seq"]) != n: raise ValueError(f"seq {s['seq']!r} is not {n}")
    if not isinstance(s.get("vault_ref", ""), str): raise ValueError("vault_ref is not a string")
    bad = [p + "_salt" for p in parts if not (isinstance(s[p + "_salt"], str) and HEX64.fullmatch(s[p + "_salt"]))]
    if bad: raise ValueError(f"{', '.join(bad)}: not 64 lowercase hex characters")
    return {p: bytes.fromhex(s[p + "_salt"]) for p in parts}


def _reports(res, files, entries):
    """format.de.md 10.1: a presented report must be bound into the chain."""
    known = set()
    for e in entries:
        if e["event_type"] == "REPORT_ISSUED":
            known.add(e["payload"]["html_hash"])
            if e["payload"]["pdf_hash"]: known.add(e["payload"]["pdf_hash"])
    for name in sorted(files):
        if not name.startswith("reports/"): continue
        digest = hashlib.sha256(files[name]).hexdigest()
        if digest not in known:
            res.add("REPORT_MISMATCH", f"{name}: SHA-256 {digest} appears in no REPORT_ISSUED entry")


# ---------------------------------------------------------------- reporting

def load_registry(path=DEFAULT_REGISTRY):
    with open(path, encoding="utf-8") as fh: return json.load(fh)


def _rules(res, rules):
    """The registry's "verifier" section: as passed, else the one verify() ran with, else the default registry's."""
    return rules or res.rules or load_registry()["verifier"]


def exit_code(res, meta, rules=None):
    """10.3: the first exit class of verifier.exit_precedence that occurs - 3 > 2 > 4 > 1 > 0, not max()."""
    order, got = _rules(res, rules)["exit_precedence"], {meta[f["class"]]["exit"] for f in res.findings} | {0}
    if got - set(order): raise ValueError(f"exit classes {sorted(got - set(order))} are missing from verifier.exit_precedence")
    return next(c for c in order if c in got)


_UI = {"de": {"exit": "Exit", "end": "Kettenende", "sealed": "versiegelt am {seal_ts} ({seal_reason}, seq {seal_seq})",
              "incomplete": "nicht versiegelt, letzter Eintrag seq {last_seq}", "none": "nicht bewertet", "clean": "keine Befunde.",
              "list": "Herstellerschlüsselliste: Version {version}, ausgestellt {ausgestellt}, Wurzel {wurzel_id}",
              "glic": "Hinweis: GENESIS stammt aus Spezifikation 1.7 oder älter, seine license_id ist kein Lizenz-Commitment, dort kann der Lizenzschlüssel selbst stehen; vom Hersteller ersetzen lassen (4.1). Ohne Einfluss auf das Ergebnis.",
              "established": "Vollständigkeit: bis tree_size {up_to_tree_size} belegt durch die gefundenen erwarteten Wurzeln (Quellen: {sources}) (8.6)",
              "not_established": "Vollständigkeit: nicht belegt, ohne eine vom Hersteller gegengezeichnete Wurzel ist keine Aussage möglich, ob dieses Paket die ganze Kette bis zu seiner Anforderung enthält (8.6, 11.2). Eine volle Aussage braucht die Anker-Historie des Herstellers: die Seiten der Form v2 für chain_id {chain_id} selbst abholen (GET /v1/anchors?chain_id={chain_id}&kind=ledger.anchor_history.v2, Heartbeat-Spezifikation 9.7) und erneut prüfen mit --anchor-history und dem Zeitpunkt der Anforderung dieses Pakets als --requested-at (8.8.1, 10.8). Nur bei einem Hersteller ohne veröffentlichte Rollenliste bleibt der Abgleich von Hand: jede Wurzel daraus, die VOR der Anforderung dieses Pakets festgehalten wurde (mindestens die jüngste gegengezeichnete, nie eine spätere), als --expect-root TREE_SIZE:ROOT.",
              "sources": {"auditor": "Angabe des Prüfers", "anchor_history": "Anker-Historie"},
              "window": "Restfenster (11.2): {entries} Einträge, seq {first_seq}..{last_seq}, nach dem letzten gegengezeichneten Checkpoint (tree_size {after_tree_size}), {from_ts} .. {to_ts} = {span_ms} ms; Ankermeldungen ohne Gegenzeichnung im Paket: {unanswered_anchor_messages}",
              "window0": "Restfenster (11.2): alle {entries} Einträge, seq {first_seq}..{last_seq}, bis {to_ts}, das Paket enthält keinen gegengezeichneten Checkpoint; Ankermeldungen ohne Gegenzeichnung im Paket: {unanswered_anchor_messages}",
              "beyond": "; über dem Ankertakt, mögliche Ursachen: Lizenzablauf, Egress aus, Hersteller nicht erreichbar, alter Export; Abgleich mit der Wurzel des Herstellers (8.6)",
              "stretch": "Strecke ohne Gegenzeichnung (11.2): seq {first_seq}..{last_seq}, {from_ts} .. {to_ts} = {span_ms} ms, {unanswered_anchor_messages} Ankermeldungen ohne eigene Gegenzeichnung; erst die Quittung an seq {receipt_seq} (server_ts {receipt_server_ts}) deckt sie"},
       "en": {"exit": "exit", "end": "chain end", "sealed": "sealed at {seal_ts} ({seal_reason}, seq {seal_seq})",
              "incomplete": "not sealed, last entry seq {last_seq}", "none": "not judged", "clean": "no findings.",
              "list": "vendor key list: version {version}, issued {ausgestellt}, root {wurzel_id}",
              "glic": "notice: GENESIS was written under spec 1.7 or earlier and its license_id is not a licence commitment, so the licence key itself may stand there; have the vendor replace it (4.1). No effect on the result.",
              "established": "completeness: established up to tree_size {up_to_tree_size} by the expected roots found (sources: {sources}) (8.6)",
              "not_established": "completeness: not established; without a root countersigned by the vendor no statement is possible on whether this package holds the whole chain up to its request (8.6, 11.2). A full statement needs the vendor's anchor history: fetch its pages of kind v2 for chain_id {chain_id} yourself (GET /v1/anchors?chain_id={chain_id}&kind=ledger.anchor_history.v2, heartbeat spec 9.7) and re-run with --anchor-history and the time this package was requested as --requested-at (8.8.1, 10.8). Only for a vendor without a published role list the manual comparison stays: every root in it recorded BEFORE this package was requested (at least the most recent countersigned one, never a later one) as --expect-root TREE_SIZE:ROOT.",
              "sources": {"auditor": "auditor input", "anchor_history": "anchor history"},
              "window": "residual window (11.2): {entries} entries, seq {first_seq}..{last_seq}, after the last countersigned checkpoint (tree_size {after_tree_size}), {from_ts} .. {to_ts} = {span_ms} ms; anchor messages without a countersignature in the package: {unanswered_anchor_messages}",
              "window0": "residual window (11.2): all {entries} entries, seq {first_seq}..{last_seq}, up to {to_ts}; the package holds no countersigned checkpoint; anchor messages without a countersignature in the package: {unanswered_anchor_messages}",
              "beyond": "; beyond the anchor cadence, possible causes: licence lapse, egress off, vendor unreachable, old export; compare with the vendor's root (8.6)",
              "stretch": "stretch without countersignature (11.2): seq {first_seq}..{last_seq}, {from_ts} .. {to_ts} = {span_ms} ms, {unanswered_anchor_messages} anchor messages without a countersignature of their own; only the receipt at seq {receipt_seq} (server_ts {receipt_server_ts}) covers it"}}


def render(res, code, meta, lang, package, rules=None):
    ui, end = _UI[lang], res.chain_end or {"status": "none"}   # a format error leaves the chain end unjudged (8.6)
    out = [f"LEDGER verifier2 {VERSION}: {package}", f"{ui['exit']} {code}: {_rules(res, rules)['exit_codes'][str(code)][lang]}",
           f"{ui['end']}: {ui[end['status']].format(**end)}"]
    if res.completeness:                                                                                                # 8.6, with sources from 1.10
        cm = res.completeness
        out.append(ui[cm["status"]].format(chain_id=res.chain_id, up_to_tree_size=cm["up_to_tree_size"],
                                           sources=", ".join(ui["sources"][x] for x in cm.get("sources", []))))
    w = res.residual_window                                                                                             # 11.2
    if w: out.append(ui["window" if w["after_tree_size"] else "window0"].format(**w) + (ui["beyond"] if w["beyond_cadence"] else ""))
    out += [ui["stretch"].format(**u) for u in res.unanchored_stretches or []]                                          # 11.2 (1.10)
    if getattr(res, "vendor_list", None): out.append(ui["list"].format(**res.vendor_list))
    if getattr(res, "glic", None): out.append(ui["glic"])
    # 10.10.3: key_roles has no block in the text report of this edition, the object stands in the JSON output only.
    if res.vendor_log is not None and res.vl_reg is not None: out.append(vendor_log_text(res.vendor_log, res.vlog, res.vl_reg, lang))  # 7.4.10 L10
    if res.anchor_history is not None and res.ah_reg is not None: out.append(anchor_history_text(res, lang))                       # 8.8.4 H13
    # 10.10.3: the block of the evidence level, whose last line is the line on affiliation (left out with exit 3), then the findings.
    if res.evidence_level is None: res.evidence_level = evidence_level(res, code, _rules(res, rules))
    if res.evidence_level is not None: out.append(evidence_level_text(res, lang, _rules(res, rules)))
    if not res.findings: out.append(ui["clean"])
    for cls in res.classes():
        out += ["", f"[{cls}] {ui['exit']} {meta[cls]['exit']}: {meta[cls].get(lang, meta[cls]['en'])}"]
        out += [f"    - {f['detail']}" for f in res.findings if f["class"] == cls]
    return "\n".join(out)


class _Once(argparse.Action):
    """A switch allowed at most once (10.8): a second occurrence is an unusable invocation, never "last wins"."""
    def __call__(self, parser, ns, value, option=None):
        if getattr(ns, self.dest) is not None: parser.error(f"{option} is given more than once (10.8)")
        setattr(ns, self.dest, value)


def version_line():
    """--version (10.6): the version of verifier2, the edition of the specification of its default registry and the
    product name, like the first line of ledger-verify --version."""
    try: edition = load_registry()["spec_version"]
    except Exception: edition = "unknown"
    return f"verifier2 {VERSION} (spec {edition}) \u00b7 LEDGER"


class _Help(argparse.Action):
    """-h and --help: the help on the error output and exit 3, a usage error after 10.8, like ledger-verify; exit 0 would
    read as "valid, no findings" (10.3). Normally answered by read_command_line before argparse sees the switch."""
    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings=option_strings, dest=dest, default=default, nargs=0, help=help)

    def __call__(self, parser, ns, value, option=None):
        parser.print_help(sys.stderr)
        sys.exit(3)


class _Parser(argparse.ArgumentParser):
    """Every usage error (an unknown switch, a missing value, a switch given too often) is an unusable invocation:
    exit 3 with the reason on the error output (10.6, 10.8), never argparse's own code 2."""
    def error(self, message):
        print(f"{self.prog}: unusable argument: {message}", file=sys.stderr)
        sys.exit(3)


def _parser(prog, description):
    ap = _Parser(prog=prog, allow_abbrev=False, add_help=False, description=description,
                 epilog="Every switch stands before the package and is written with two dashes; \"--\" ends the switches. "
                        "Exit codes: 0 valid / 1 valid with findings / 2 invalid / 3 format error or unusable invocation / "
                        "4 incomplete: chain end not sealed.")
    ap.add_argument("-h", "--help", action=_Help, help="show this help on the error output and exit with 3")
    return ap


def read_command_line(ap, argv):
    """10.8, the command line as ledger-verify reads it (cli.go vorpruefen, then Go's flag package): the switches stand in
    front, each written "--name" (a switch without a value) or "--name VALUE" / "--name=VALUE" (VALUE is the next argument
    as it is, also when it begins with a dash); "--" ends them and is consumed; the first argument that is "-" or does not
    begin with a dash ends them too. -h and --help print the help on the error output with exit 3. A single dash (-json,
    -1, "-x y"), an unknown switch, a value on a switch without one and a missing value are unusable (exit 3).
    -> (the switches for argparse, each "--name" or "--name=VALUE", and the arguments after them). argparse alone guessed:
    it took "-1" and "-x y" for a package, refused a value beginning with a dash and swallowed a trailing "--"."""
    takes = {o[2:]: act.nargs != 0 for act in ap._actions for o in act.option_strings if o.startswith("--")}
    out, i = [], 0
    while i < len(argv):
        a = argv[i]
        if a == "--": i += 1; break
        if a == "-" or not a.startswith("-"): break
        if a in ("-h", "--help"):
            ap.print_help(sys.stderr)
            sys.exit(3)
        if not a.startswith("--"): ap.error(f"{a!r}: a switch is written with two dashes (--{a[1:].partition('=')[0]}) and stands before the package")
        name, eq, value = a[2:].partition("=")
        if name not in takes: ap.error(f"unknown switch --{name}")
        if not takes[name]:
            if eq: ap.error(f"--{name} takes no value, got {a!r}")
            out.append(a)
        else:
            if not eq:
                if i + 1 >= len(argv): ap.error(f"--{name} needs a value")
                i += 1
                value = argv[i]
            out.append(f"--{name}={value}")
        i += 1
    return out, argv[i:]


def _wire(text):
    """str -> the bytes ledger-verify writes for it: UTF-8 whatever the locale, and a byte of an argument that is no UTF-8
    (which the interpreter holds as a surrogate, PEP 383) as that byte, as Go writes the string it was given."""
    try: return text.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        return "".join("\ufffd" if "\ud800" <= c <= "\udfff" and not "\udc80" <= c <= "\udcff" else c for c in text).encode("utf-8", "surrogateescape")


def _valid_utf8(raw):
    """bytes -> str, every byte that is no UTF-8 replaced by U+FFFD, one per byte, as Go's encoding/json does: the JSON
    output stays UTF-8 also for a package path that is not."""
    try: return raw.decode("utf-8")
    except UnicodeDecodeError: pass
    out, i = [], 0
    while i < len(raw):
        for n in (1, 2, 3, 4):
            try:
                out.append(raw[i:i + n].decode("utf-8")); i += n
                break
            except UnicodeDecodeError: pass
        else: out.append("\ufffd"); i += 1
    return "".join(out)


def emit(text, prog="verifier2", json_out=False):
    """The output and a line end on the standard output, as ledger-verify writes it (_wire; JSON in valid UTF-8). True when
    written; an output that cannot be written (a full disk, a broken pipe) is named on the error output and the caller
    leaves with exit 3, never with the verdict or the interpreter's exit 1. A standard output closed at the start counts
    as /dev/null, as in ledger-verify, whose runtime opens /dev/null on a closed descriptor 1."""
    data = _wire(text + "\n")
    if json_out: data = _valid_utf8(data).encode("utf-8")
    if sys.stdout is None: return True
    try:
        buf = getattr(sys.stdout, "buffer", None)
        if buf is None: sys.stdout.write(data.decode("utf-8", "surrogateescape")); sys.stdout.flush()
        else: sys.stdout.flush(); buf.write(data); buf.flush()
        return True
    except (OSError, ValueError) as exc:
        try: print(f"{prog}: cannot write the output: {exc}", file=sys.stderr)
        except Exception: pass
        try: os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())   # the flush at exit goes nowhere, not to a 120
        except Exception: pass
        return False


def freshness_ms(value):
    """--freshness (8.5, 10.8): a whole number from 1 to 999999 without a leading zero, directly followed by h, m or s ->
    the window in whole milliseconds. Anything else (0, a sign, a fraction, "1h30m", no unit, a blank) is unusable.
    Up to 1.0 the switch was --freshness-hours with a float, which took "nan", "inf" and "-1"."""
    m = FRESHNESS.fullmatch(value)
    if not m: raise Unusable(f"--freshness {value!r} is no whole number from 1 to 999999 directly followed by h, m or s (e.g. 24h, 90m; 10.8)")
    return int(m[1]) * FRESHNESS_UNIT_MS[m[2]]


_TS_TEXT = {"de": {"head": "LEDGER: Einzelprüfung eines Zeitstempels (verifier2)", "purpose": "Zweck", "result": "Ergebnis", "reason": "Grund",
                   "imprint": "Abdruck", "signer": "Signierer", "qs": "Regel QS", "none": "keiner",
                   "chain": "chain (Zeitzeuge der Kette, Abschnitt 7.3)", "log": "log (Zeitstempel eines Tageseintrags, Abschnitt 7.4.6)",
                   "defective": "mangelhaft", "unconfirmed": "nicht bestätigt", "confirmed": "bestätigt",
                   "note": "Hinweis: Diese Einzelprüfung ist keine Prüfung eines Prüfpakets."},
            "en": {"head": "LEDGER: check of a single time stamp (verifier2)", "purpose": "Purpose", "result": "Result", "reason": "Reason",
                   "imprint": "Imprint", "signer": "Signer", "qs": "Rule QS", "none": "none",
                   "chain": "chain (time witness of the chain, section 7.3)", "log": "log (time stamp of a day entry, section 7.4.6)",
                   "defective": "defective", "unconfirmed": "not confirmed", "confirmed": "confirmed",
                   "note": "Note: this single check is no verification of a package."}}


def zeitstempel(argv):
    """verifier2.py zeitstempel: one time stamp after the profile (7.5), judged by the column for day time stamps of
    7.5.7 against the roots passed for one purpose. A helper, not part of the specification: it checks no package.
    Exit 0 confirmed, 1 not confirmed or defective, 3 unusable invocation.
    SPEC-FRAGE (spec/testvectors/README.de.md 10.4): for --purpose chain "die oberste zutreffende Zeile" of 7.5.7 is
    read as the rule of the day time stamp column for both purposes, Z.6 included; the TIME_ANCHOR column knows no
    states defective, unconfirmed or confirmed."""
    ap = _parser("verifier2 zeitstempel", "check of a single RFC 3161 time stamp after the time-stamp profile (format spec 7.5)")
    ap.add_argument("--token", action=_Once, metavar="FILE", help="the TimeStampToken, DER or Base64 (grammar B64, one line end allowed)")
    ap.add_argument("--data", action=_Once, metavar="FILE", help="the stamped bytes")
    ap.add_argument("--statement-jcs", action=_Once, metavar="FILE", help="the statement_jcs of a day entry (format spec 7.4.5), one line end allowed")
    ap.add_argument("--tsa-root", action="append", default=[], metavar="FILE", help="PEM file with roots of the purpose (strict PEM, format spec 10.8); repeatable")
    ap.add_argument("--purpose", action=_Once, choices=("chain", "log"), help="chain or log (default log)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--lang", action=_Once, choices=("de", "en"), help="language of the text output (default en)")
    ap.add_argument("--registry", action=_Once, metavar="FILE", help="the registry to read (default: spec/registry.json beside verifier2); verifier2 only, no auditor input")
    switches, rest = read_command_line(ap, argv)                       # the same rules as the main mode; "--" may end them
    a = ap.parse_args(switches)
    if rest: ap.error(f"unexpected argument {rest[0]!r}")
    purpose, lang = a.purpose or "log", a.lang or "en"
    try:
        reg = load_registry(a.registry or DEFAULT_REGISTRY)
        if a.token is None: raise Unusable("--token is needed")
        if (a.data is None) == (a.statement_jcs is None): raise Unusable("exactly one of --data and --statement-jcs is needed")
        tok = read_input(a.token, "--token")
        if a.data is not None: data = read_input(a.data, "--data")
        else:
            data = read_input(a.statement_jcs, "--statement-jcs")
            data = data[:-2] if data.endswith(b"\r\n") else data[:-1] if data.endswith(b"\n") else data
            if any(not 0x20 <= x <= 0x7e for x in data): raise Unusable("--statement-jcs: a statement_jcs consists of printable ASCII only (format spec 2, 7.4.5)")
        roots = []
        for f in a.tsa_root:
            try: roots += strict_pem(read_input(f, "--tsa-root").decode("latin-1"))
            except ValueError as exc: raise Unusable(f"--tsa-root {f}: {exc}") from None
    except Exception as exc:
        print(f"verifier2 zeitstempel: unusable argument: {exc}", file=sys.stderr); return 3
    try:
        if tok[:1] == b"\x30": der_bytes = tok                       # DER; else Base64 after B64 with one line end
        else: der_bytes = b64_decode((tok[:-2] if tok.endswith(b"\r\n") else tok[:-1] if tok.endswith(b"\n") else tok).decode("latin-1"))
        r = ts_assess(der_bytes, data, roots)
    except ValueError as exc:
        r = {"grammar": f"the token violates grammar B64: {exc}", "t": None, "signer": None, "qs": None}
    state, reason = day_token_state(r, roots, test_spki(reg))
    t = r["t"]
    out = {"purpose": purpose, "state": state, "reason": reason, "gen_time": t and t["gen_time"], "gen_time_ms": t and t["gen_time_ms"],
           "imprint_algorithm": t and HASH_NAMES[t["imprint_alg"]], "signer": r["signer"] and r["signer"].common_name() or None,
           "qualified_statement": r["qs"]}
    if a.json: text = json.dumps(out, indent=2, ensure_ascii=False)
    else:
        x = _TS_TEXT[lang]
        why = r["grammar"] or ("" if r["imprint_ok"] is not False else "the imprint does not cover the given bytes") or r.get("step5_why", "")
        text = "\n".join([x["head"], f"{x['purpose'] + ':':<13}{x[purpose]}", f"{x['result'] + ':':<13}{x[state]}",
                          f"{x['reason'] + ':':<13}{reason or x['none']}" + (f" ({why})" if reason and why else ""),
                          f"{'genTime:':<13}{out['gen_time'] or '-'}" + (f" ({out['gen_time_ms']})" if t else ""),
                          f"{x['imprint'] + ':':<13}{out['imprint_algorithm'] or '-'}", f"{x['signer'] + ':':<13}{out['signer'] or '-'}",
                          f"{x['qs'] + ':':<13}{out['qualified_statement'] or '-'}", x["note"]])
    if not emit(text, "verifier2 zeitstempel", a.json): return 3
    return 0 if state == "confirmed" else 1


def main(argv):
    if argv[1:2] == ["zeitstempel"]: return zeitstempel(argv[2:])
    if argv[1:] == ["--version"]:                                     # 10.6: only as the one argument, like ledger-verify
        return 0 if emit(version_line()) else 3
    ap = _parser("verifier2", "independent second verifier for LEDGER verification packages")
    ap.usage = "verifier2 [switches] [--] <package>    (package: directory or ZIP archive; every switch stands before it)"
    ap.add_argument("--version", action="store_true", help="print the version and the edition of the specification; only as the one argument")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--now", action=_Once, help="check time for the freshness window, RFC 3339 in UTC: YYYY-MM-DDThh:mm:ss[.fraction]Z (10.8); default: system clock")
    ap.add_argument("--now-from-package", action="store_true", help="take the check time from the package's verify_args.json (frozen test vectors only; the file is chosen by the prover)")
    ap.add_argument("--freshness", action=_Once, metavar="DUR", help="freshness window for TRAILING_SILENCE (8.5, 10.8): 1 to 999999 directly followed by h, m or s, e.g. 24h, 90m; default 24h; at most once")
    ap.add_argument("--expect-root", action="append", default=[], metavar="[TREE_SIZE:]ROOT",
                    help="expected Merkle root (paper anchor, the vendor's countersigned root; 10.8): at that tree size, or at any; repeatable")
    ap.add_argument("--vendor-root", action="append", default=[], metavar="FILE", help="the vendor's root key {wurzel_id, pubkey} (7.1, 10.7); repeatable")
    ap.add_argument("--vendor-key", action="append", default=[], metavar="ID=HEX", help="pin a countersigning key of the vendor (7.1, 10.7.4); repeatable")
    ap.add_argument("--vendor-statement-key", action="append", default=[], metavar="ID=HEX", help="pin a statements key of the vendor (8.8.3, 10.7.4); repeatable")
    ap.add_argument("--vendor-log-key", action="append", default=[], metavar="ID=HEX", help="pin a protocol key of the vendor log (7.4.10); repeatable")
    ap.add_argument("--vendor-key-list", action="append", default=[], metavar="FILE",
                    help="key list of the vendor: a list of countersigning keys, a role list or a protocol key list (10.7, 7.4.7, 10.8); repeatable")
    ap.add_argument("--tsa-root", action="append", default=[], metavar="FILE",
                    help="strict PEM file of roots for time witnesses of the chain (purpose chain, 7.3, 10.8); repeatable, every file counts; "
                         "the system root store counts for no purpose, and a certificate in the package (keys/tsa/) never does")
    ap.add_argument("--tsa-qualified-roots", action=_Once, metavar="FILE", help="file ledger-tsa-qualifiziert/1 of roots named qualified (purposes chain and qualified, 10.8); at most once")
    ap.add_argument("--vendor-log-tsa-root", action="append", default=[], metavar="FILE", help="strict PEM file of roots for time stamps of the vendor log (purpose log, 7.4.6, 10.8); repeatable")
    ap.add_argument("--vendor-log", action="append", default=[], metavar="FILE", help="extract ledger-protokollauszug/1 of the vendor log (7.4.8); repeatable")
    ap.add_argument("--anchor-history", action="append", default=[], metavar="FILE", help="page of the anchor history or ledger-ankerhistorie/2 (8.8.2); repeatable")
    ap.add_argument("--requested-at", action=_Once, metavar="RFC3339", help="when the auditor requested the package (8.8.1, 10.8); at most once")
    ap.add_argument("--lang", action=_Once, choices=("de", "en"), help="report language (default en)")
    ap.add_argument("--registry", action=_Once, metavar="FILE", help="the registry to read (default: spec/registry.json beside verifier2); verifier2 only, no auditor input")
    # The package is read here and not by argparse, which took "-1" or "-x y" for a package and swallowed a "--" after it:
    # exactly one argument after the switches, as in ledger-verify, so a switch after the package is a second argument.
    switches, rest = read_command_line(ap, argv[1:])
    args = ap.parse_args(switches)
    if args.version: ap.error("--version stands alone; it takes no other argument")
    if len(rest) != 1:
        ap.error(f"every switch stands before the package; found {rest[1]!r} after it" if rest else "the package (directory or ZIP) is missing")
    args.package = rest[0]
    lang = args.lang or "en"
    reg_path = args.registry or DEFAULT_REGISTRY
    try:
        reg = load_registry(reg_path)
        rules = reg["verifier"]
        meta, ranked = rules["finding_classes"], {str(c) for c in rules["exit_precedence"]}
        if set(rules["exit_codes"]) != ranked or not ranked >= {str(m["exit"]) for m in meta.values()} | {"0", "3"}:
            raise ValueError("verifier.exit_codes and exit_precedence must name the same exit codes, every one a finding can yield (10.3)")
    except Exception as exc:
        print(f"verifier2: cannot load the registry ({reg_path}): {exc}", file=sys.stderr); return 3
    try:
        # 10.8: the auditor's inputs follow the package's grammar - never read in the host's time zone, never guessed
        freshness = DEFAULT_FRESHNESS_H if args.freshness is None else freshness_ms(args.freshness) / 3600000
        if args.now is not None and utc_ns(args.now) is None:
            raise ValueError(f"--now {args.now!r} is no RFC 3339 instant in UTC (YYYY-MM-DDThh:mm:ss[.fraction]Z, 10.8)")
        now, now_source = (ms(args.now), "flag") if args.now is not None else (None, None)
        roots = []
        for s in args.expect_root:                                         # ROOT or TREE_SIZE:ROOT, the root case-insensitive
            m = EXPECT_ROOT.fullmatch(s)
            if not m or m[1] and (len(m[1]) > 16 or int(m[1]) > MAX_INT):        # 16 digits first: int() reads 4300 at most
                raise ValueError(f"--expect-root {s!r} is neither ROOT nor TREE_SIZE:ROOT with TREE_SIZE 1 to 2^53-1 and a root of 64 hex characters (10.8)")
            roots.append((int(m[1]) if m[1] else None, m[2].lower()))
        inputs = AuditorInputs.load(args, reg)                            # L0 (7.4.10), 10.7.4, 10.8: before the package is opened
        if now is None and not args.now_from_package:                      # the system clock, read once, at invocation
            now, now_source = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000), "system"
        if inputs.requested_at is not None and now is not None and ms(inputs.requested_at) > now:
            raise ValueError(f"--requested-at {inputs.requested_at} lies after the check time ({now_source}) (10.8)")
    except Exception as exc:
        print(f"verifier2: unusable argument: {exc}", file=sys.stderr); return 3
    # Whatever the package throws at the checks, the answer is never the interpreter's
    # default exit 1 - that code means "valid with findings" (registry verifier.exit_codes).
    # An input the verifier cannot process is a format error: exit 3, reason on stderr.
    try:
        res = verify(args.package, reg, now, freshness, roots, args.now_from_package, inputs=inputs, now_source=now_source)
        code = exit_code(res, meta, rules)
    except Exception as exc:
        res, code = _fmt_err(Result(rules), [f"cannot process the package: {type(exc).__name__}: {exc}"]), 3
    # 10.5 stage 5, step 15: the evidence level after the exit code, which it never changes (10.3, 10.9): a fault in forming
    # it leaves the exit code as it is and is named on the error output.
    try: res.evidence_level = evidence_level(res, code, rules)
    except Exception as exc:
        print(f"verifier2: the evidence level could not be formed: {type(exc).__name__}: {exc}", file=sys.stderr)
        res.evidence_level, res.ev = None, None
    if args.json:
        text = (json.dumps({"verifier": "verifier2", "version": VERSION, "spec_version": reg["spec_version"],
                          "package": args.package, "exit_code": code, "now_source": res.now_source,
                          "status": {0: "valid", 1: "valid", 2: "invalid", 3: "format_error", 4: "incomplete"}[code],   # 10.3: 4 is no "invalid"
                          "finding_classes": res.classes(), "findings": res.findings,
                          "vendor_list": getattr(res, "vendor_list", None),
                          "chain_end": res.chain_end, "last_countersigned": res.last_countersigned,   # 8.6; null: not judged / none
                          "legal_holds": getattr(res, "legal_holds", None),   # 9.3: active at the chain end, []: none; null: not judged
                          "genesis_license_not_commitment": getattr(res, "glic", None),   # 4.1 notice; null: not judged
                          "completeness": res.completeness,          # 8.6 (1.9): {status, up_to_tree_size}; null: not judged
                          "residual_window": res.residual_window,    # 11.2 (1.9): measured, no finding; null: not judged
                          "unanchored_stretches": res.unanchored_stretches,   # 11.2 (1.10): covered stretches, []: none; null: not judged
                          "key_roles": res.key_roles,                # 10.7.4, 10.10.2 (1.10): an object; null on exit 3
                          "vendor_log": res.vendor_log,              # 7.4.10 L10, 10.10.2 (1.10): an object; null on exit 3
                          "anchor_history": res.anchor_history,      # 8.8.4 H13, 10.10.2 (1.10): an object; null on exit 3
                          "affiliation": res.affiliation,            # 8.8.6, 10.10.2 (1.10): an object; null on exit 3
                          "evidence_level": res.evidence_level},     # 10.9, 10.10.2 (1.10): an object, state format_error on exit 3
                         indent=2, sort_keys=True, ensure_ascii=False))
    else:
        text = render(res, code, meta, lang, args.package, rules)
    return code if emit(text, json_out=args.json) else 3


if __name__ == "__main__":
    sys.exit(main(sys.argv))
