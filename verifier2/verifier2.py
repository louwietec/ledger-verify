#!/usr/bin/env python3
# verifier2 - independent second verifier for LEDGER verification packages
# (the product was called "Rekorder"; frozen, signed format identifiers such as
# "rekorder-herstellerschluessel/1" keep that name - they are no product name).
#
# Built solely from the open specification (spec/format.de.md + spec/registry.json).
# It must never import from, read, or otherwise depend on the Go implementation or
# the appliance code: its whole point is to show that the specification alone is
# enough to build an independent verifier. Python 3.11 standard library only -
# Ed25519 verification included, since the stdlib offers none.
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

import argparse, base64, datetime, hashlib, hmac, json, os, re, sys, zipfile

VERSION = "1.0.0"
ZERO = "0" * 64
TICK_TOLERANCE_MS = 450000     # format.de.md 8.2: 1.5 x the 5 min TICK interval, in whole milliseconds (2)
CLOCK_TOLERANCE_MS = 300000    # format.de.md 9.2
DEFAULT_FRESHNESS_H = 24.0     # format.de.md 8.5
MAX_INT = 2 ** 53 - 1          # format.de.md 2: every JSON number of the package lies in -MAX_INT .. MAX_INT
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


def ed25519_verify(pubkey, sig, msg):
    if len(pubkey) != 32 or len(sig) != 64: return False
    a, r = _point(pubkey), _point(sig[:32])
    s = int.from_bytes(sig[32:], "little")
    if a is None or r is None or s >= _L: return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pubkey + msg).digest(), "little") % _L
    x1, y1, z1, _u = _mul(_B, s)
    x2, y2, z2, _v = _add(r, _mul(a, h))
    return (x1 * z2 - x2 * z1) % _Q == 0 and (y1 * z2 - y2 * z1) % _Q == 0


# -------------------------------------------------- Merkle tree (RFC 6962, §5)

def mth(leaves):
    """Merkle Tree Hash: leaf = SHA256(0x00||hash), node = SHA256(0x01||L||R)."""
    n = len(leaves)
    if n == 0: return hashlib.sha256(b"").digest()
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
    if t not in ("const", "uuid", "rfc3339", "bool", "hex64", "hex128", "enum", "version", "open_enum", "int", "string", "object", "array"): errs.append(f"{path}: registry type {t!r} is unknown to this verifier version - loud, not silent")
    elif t == "const" and v != spec["value"]:
        errs.append(f"{path}: expected {spec['value']!r}, got {v!r}")
    elif t == "uuid" and not (isinstance(v, str) and _UUID.match(v)):
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

# --- RFC 3161 time witness (format.de.md 7.3) --------------------------------
# Only the structural half. Steps 1-4 of 7.3 are mandatory for every verifier
# and need no CMS: decode, walk to the TSTInfo, compare imprint and readings.
# Steps 5-6 (CMS signature, certificate chain) are not implementable in the
# Python standard library, so this verifier reports TIME_ANCHOR_UNVERIFIED and
# says so — which 7.3 requires of a verifier that cannot check the signature.

def der_items(b):
    """Flache DER-Liste [(tag, inhalt)] / flat DER list."""
    out, i = [], 0
    while i < len(b):
        t = b[i]; i += 1
        if t & 0x1f == 0x1f: raise ValueError("high tag number")
        if i >= len(b): raise ValueError("truncated")
        n = b[i]; i += 1
        if n & 0x80:
            k = n & 0x7f
            if k == 0 or k > 4: raise ValueError("bad length")
            n = int.from_bytes(b[i:i + k], "big"); i += k
        if i + n > len(b): raise ValueError("truncated")
        out.append((t, b[i:i + n])); i += n
    return out


def der_oid(b):
    if not b: raise ValueError("empty oid")
    out, v = [str(b[0] // 40), str(b[0] % 40)], 0
    for c in b[1:]:
        v = v * 128 + (c & 0x7f)
        if not c & 0x80: out.append(str(v)); v = 0
    return ".".join(out)


def der_sub(items, idx, tag):
    if idx >= len(items) or items[idx][0] != tag:
        raise ValueError("expected tag 0x%02x at %d" % (tag, idx))
    return items[idx][1]


def tst_info(der):
    """ContentInfo -> SignedData -> encapContentInfo -> TSTInfo (RFC 3161/5652)."""
    f = der_items(der_sub(der_items(der), 0, 0x30))
    if der_oid(der_sub(f, 0, 0x06)) != "1.2.840.113549.1.7.2": raise ValueError("not signedData")
    sd = der_items(der_sub(der_items(der_sub(f, 1, 0xa0)), 0, 0x30))
    eci = der_items(der_sub(sd, 2, 0x30))
    if der_oid(der_sub(eci, 0, 0x06)) != "1.2.840.113549.1.9.16.1.4": raise ValueError("not a TSTInfo")
    t = der_items(der_sub(der_items(der_sub(der_items(der_sub(eci, 1, 0xa0)), 0, 0x04)), 0, 0x30))
    mi = der_items(der_sub(t, 2, 0x30))
    g = der_sub(t, 4, 0x18).decode("ascii")            # GeneralizedTime YYYYMMDDHHMMSSZ
    if len(g) != 15 or g[14] != "Z": raise ValueError("genTime is not a plain UTC second")
    return {"policy": der_oid(der_sub(t, 1, 0x06)),
            "alg": der_oid(der_sub(der_items(der_sub(mi, 0, 0x30)), 0, 0x06)),
            "imprint": der_sub(mi, 1, 0x04),
            "serial": format(int.from_bytes(der_sub(t, 3, 0x02), "big", signed=True), "x"),
            "ts": "%s-%s-%sT%s:%s:%s.000Z" % (g[0:4], g[4:6], g[6:8], g[8:10], g[10:12], g[12:14])}


IMPRINT_HASHES = {"2.16.840.1.101.3.4.2.1": hashlib.sha256,
                  "2.16.840.1.101.3.4.2.2": hashlib.sha384,
                  "2.16.840.1.101.3.4.2.3": hashlib.sha512}


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
    if abs(int(s)) > MAX_INT: raise NumberError(f"number {s} lies outside -(2^53-1) .. 2^53-1 (2)")
    return int(s)


def _no_int(s): raise NumberError(f"number {s} is no integer without fraction and exponent (2)")


def _no_json(s): raise ValueError(f"{s} is no JSON (RFC 8259) - a syntax error, not a number verdict")


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


class Result:
    def __init__(self, rules=None):   # rules: the registry's "verifier" section the run was made with
        self.findings, self.seen, self.rules, self.chain_end, self.last_countersigned = [], set(), rules, None, None
        self.now_source = self.chain_id = self.completeness = self.residual_window = None   # None: not resolved / not judged
    def add(self, cls, detail): self.findings.append({"class": cls, "detail": detail})
    def once(self, cls, key, detail):      # 10.6: SPEC_NEWER once per package, UNKNOWN_ENTRY_TYPE once per type name
        if (cls, key) not in self.seen: self.seen.add((cls, key)); self.add(cls, detail)
    def classes(self): return sorted({f["class"] for f in self.findings})


def _fmt_err(res, errs):
    for e in errs[:50]: res.add("FORMAT_ERROR", e)
    return res


# -------------------------------------------------------------- verification

def verify(path, reg, now, freshness_h, expect_roots, now_from_package=False, vendor_roots=None, vendor_keys=None):
    """now: the check time in whole milliseconds since 1970 (None: verify_args.json on request, else the system
    clock); expect_roots: the auditor's expected roots [(tree_size or None, lowercase root)] (10.8)."""
    res, errs = Result(reg["verifier"]), []
    try: files = load_package(path)
    except Exception as exc: return _fmt_err(res, [f"package not readable: {exc}"])
    # Check time (8.5, 10.8): --now > (only on explicit request) the package's own verify_args.json > the
    # system clock. The package file is unsigned and written by the appliance under examination, so it never
    # sets the clock by default. Asked for and absent or not conforming it is exit 3 - a fallback to the
    # system clock would silently change the basis of the freshness check.
    if now is not None: res.now_source = "flag"
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
    # Befund, kein Schemafehler, und bricht den Lauf nicht ab — das Manifest
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
                    errs.append(f"{at}: GENESIS license_id is not the licence commitment (64 lowercase hex) - required from spec 1.8 (4.1)")
            if e.get("chain_id") != man["chain_id"]: errs.append(f"{at}: chain_id differs from the manifest")
    if errs: return _fmt_err(res, errs)

    # Stage 4a (10.5): the vendor list and the salt files of presented plaintexts against the number rule (2), read
    # lexically - a member twice or a broken text is judged where the file is read (10.7, 10.1), a number never there.
    for name in sorted(n for n in files if n == "keys/vendor/schluesselliste.json" or re.fullmatch(r"content/[1-9][0-9]*\.salts\.json", n)):
        try: num_scan(files[name])
        except NumberError as exc: errs.append(f"{name}: {exc}")
    if errs: return _fmt_err(res, errs)

    # Stage 5: the checks of the chain.
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
        if e["event_type"] == "GENESIS": res.add("FORMAT_ERROR", f"seq={e['seq']}: GENESIS after the first entry - only seq 1 is GENESIS")
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
    cur_id, cur_pk = "", ""
    if entries[0]["event_type"] == "GENESIS":
        cur_id, cur_pk = entries[0]["payload"]["device_key_id"], entries[0]["payload"]["device_pubkey"]
    prev_cp = ZERO
    for e in entries:
        p, s = e["payload"], e["seq"]
        if e["event_type"] == "KEY_ROTATION":
            msg = jcsb({"old_key_id": p["old_key_id"], "new_key_id": p["new_key_id"], "new_pubkey": p["new_pubkey"]})
            if not (p["old_key_id"] == cur_id and cur_pk
                    and ed25519_verify(bytes.fromhex(cur_pk), bytes.fromhex(p["signature_by_old_key"]), msg)):
                res.add("SIG_INVALID", f"seq={s}: KEY_ROTATION not certified by the key valid at this point ({cur_id})")
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
    roots, pinned = dict(vendor_roots or {}), dict(vendor_keys or {})
    raw = files.get("keys/vendor/schluesselliste.json")
    lst, lroot, lver, note = None, "", 0, "the package carries no keys/vendor/schluesselliste.json"
    if raw is not None:       # its numbers were read in stage 4a, with or without a root (2)
        lst, lroot, lver, note = vendor_list(raw, roots)
        note = f"the list does not count: {note}" if roots else "no vendor root was supplied to check the package's list against"
        if lst is not None:   # 7.1: a newer list is not visible from the package -- name the one used
            res.vendor_list = {"version": lver, "ausgestellt": jloads(raw)["ausgestellt"], "wurzel_id": lroot}
    anchors, lc_receipt = 0, 0                       # lc_receipt: seq of the receipt behind last_countersigned (11.2)
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
        if pk is None or not ed25519_verify(bytes.fromhex(pk), bytes.fromhex(p["server_signature"]), jcsb(obj)):
            res.add("RECEIPT_INVALID", f"seq={s}: vendor countersignature invalid for key {kid}")
            continue
        if contra: res.add("RECEIPT_INVALID", f"seq={s}: {contra}")   # signature holds: prefix check below still runs
        if not known:
            why = f"neither pinned by the auditor nor vouched for by a list its root verifies ({note})"
            if not (roots or pinned): why = "no vendor root and no vendor key was supplied by the auditor"
            elif lst: why = f"not pinned and not in the vendor's list (root {lroot}, version {lver})"
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
            elif not contra and (res.last_countersigned is None or p["tree_size"] > res.last_countersigned["tree_size"]):   # 8.6: anchor per 7.1, first on a tie
                res.last_countersigned = {k: p[k] for k in ("checkpoint_seq", "tree_size", "merkle_root", "server_ts")}
                lc_receipt = s
        anchors += 1 if cp_ok and not contra else 0  # contradicted or checkpoint-less receipts anchor nothing (7.1)

    for e in entries:                                # time witnesses, format.de.md 7.3
        if e["event_type"] != "TIME_ANCHOR": continue
        p, s = e["payload"], e["seq"]
        cp = next((c for c in entries if c["seq"] == p["checkpoint_seq"] and c["event_type"] == "CHECKPOINT"), None)
        if cp is None or (cp["payload"]["tree_size"], cp["payload"]["merkle_root"]) != (p["tree_size"], p["merkle_root"]):
            res.add("TIME_ANCHOR_INVALID", f"seq={s}: checkpoint_seq={p['checkpoint_seq']} is no CHECKPOINT of this chain or disagrees with it")
            continue
        try:
            der = base64.b64decode(p["token_base64"], validate=True)
            if len(der) > 16384: raise ValueError("token above the 16384 byte ceiling")
            t = tst_info(der)
        except Exception as ex:
            res.add("TIME_ANCHOR_INVALID", f"seq={s}: token is not a readable RFC 3161 TimeStampToken: {ex}")
            continue
        if (p["tsa_policy"], p["tsa_serial"], p["tsa_ts"]) != (t["policy"], t["serial"], t["ts"]):
            res.add("TIME_ANCHOR_INVALID", f"seq={s}: the tsa_* readings contradict the token")
            continue
        h = IMPRINT_HASHES.get(t["alg"])
        if h is None:
            res.add("TIME_ANCHOR_INVALID", f"seq={s}: imprint algorithm {t['alg']} is not accepted (7.3)")
            continue
        q = cp["payload"]
        subject = jcsb({"chain_id": cp["chain_id"], "tree_size": q["tree_size"], "merkle_root": q["merkle_root"],
                        "prev_checkpoint_hash": q["prev_checkpoint_hash"], "key_id": q["key_id"], "ts": cp["ts_chained"]})
        if h(subject).digest() != t["imprint"]:
            res.add("TIME_ANCHOR_INVALID", f"seq={s}: the token attests a subject other than checkpoint seq={cp['seq']}")
            continue
        anchors += 1                                 # bound, so an anchor IS present (7.3)
        res.add("TIME_ANCHOR_UNVERIFIED", f"seq={s}: the token binds checkpoint seq={cp['seq']} at {t['ts']}, "
                                          f"but this verifier implements no CMS and did not check the signature or the certificate chain (7.3)")

    # The auditor's expected roots (paper anchor 7.2, comparison 8.6, gap witnesses 11.2; forms of 10.8): with a
    # tree_size it is found if the root over that many entries equals it - never beyond the entries present -,
    # without one if the root of some prefix does. Every one not found is MERKLE_INCONSISTENT, every one found an anchor.
    found = []
    for size, r in expect_roots:
        if size is None:
            t = next((k for k in range(1, len(root)) if root[k] == r), None)
            why = f"expected root {r} is the root of no prefix 1..{len(leaves)} of this chain"
        else:
            t = size if size <= len(leaves) and root[size] == r else None
            why = (f"expected root for tree_size={size} lies beyond the {len(leaves)} entries present" if size > len(leaves)
                   else f"expected root for tree_size={size} is {r}, recomputed {root[size]}")
        if t is None: res.add("MERKLE_INCONSISTENT", why)
        else: found.append(t)
    anchors += len(found)
    if anchors == 0: res.add("NO_ANCHOR", "no receipt counts as an anchor (signature holding, not contradicted by the vendor's list), "
                                          "no time witness binds its checkpoint and no expected root of the auditor was found")
    # 8.6 (1.9): only a root the vendor countersigned - passed as an expected root and found - establishes completeness
    res.completeness = {"status": "established" if found else "not_established", "up_to_tree_size": max(found, default=None)}

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
    if age > round(freshness_h * 3600000):
        res.add("TRAILING_SILENCE", f"chain ends {age / 3600000:.1f} h before the check time ({res.now_source}), freshness window {freshness_h:.1f} h")

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
    if unjudged:              # 8.6, 11.2: not judged, so not named either
        res.last_countersigned = res.legal_holds = res.completeness = res.residual_window = None
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
    Every file under content/ is checked: one that is no part of a presentation that holds is CONTENT_MISMATCH, once."""
    by_seq, shown = {e["seq"]: e for e in entries}, {}
    for name in sorted(n for n in files if n.startswith("content/")):
        m = PRESENTED.fullmatch(name)
        if m: shown.setdefault(int(m[1]), {})[m[2]] = files[name]
        else: res.add("CONTENT_MISMATCH", f"{name}: no file of a presentation - content/<n>.salts.json, <n>.request, <n>.response (10.1)")
    for n, group in sorted(shown.items()):
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
    """The salt file of presentation n (10.1): I-JSON of exactly seq (= n), a hex64 <part>_salt for each presented part
    and none for a part not presented, and optionally vault_ref (a string, not evaluated). Returns {part: salt}."""
    s = jloads(raw)
    if not parts: raise ValueError("a salt file without a plaintext")
    want = {"seq"} | {p + "_salt" for p in parts}
    if not isinstance(s, dict) or not want <= set(s) <= want | {"vault_ref"}:
        raise ValueError(f"not an object of exactly {', '.join(sorted(want))} and an optional vault_ref")
    if type(s["seq"]) is not int or s["seq"] != n: raise ValueError(f"seq {s['seq']!r} is not {n}")
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
              "glic": "Hinweis: GENESIS stammt aus Spezifikation 1.7 oder älter, seine license_id ist kein Lizenz-Commitment - dort kann der Lizenzschlüssel selbst stehen; vom Hersteller ersetzen lassen (4.1). Ohne Einfluss auf das Ergebnis.",
              "established": "Vollständigkeit: bis tree_size {up_to_tree_size} belegt durch die übergebene erwartete Wurzel (8.6)",
              "not_established": "Vollständigkeit: nicht belegt - ohne eine vom Hersteller gegengezeichnete Wurzel ist keine Aussage möglich, ob dieses Paket die ganze Kette bis zu seiner Anforderung enthält (8.6, 11.2). Eine volle Aussage braucht die Anker-Historie des Herstellers: für chain_id {chain_id} selbst abholen (Heartbeat-Spezifikation 9.7) und erneut prüfen mit jeder Wurzel daraus, die VOR der Anforderung dieses Pakets festgehalten wurde (mindestens der jüngsten gegengezeichneten, nie einer späteren), als --expect-root TREE_SIZE:ROOT.",
              "window": "Restfenster (11.2): {entries} Einträge, seq {first_seq}..{last_seq}, nach dem letzten gegengezeichneten Checkpoint (tree_size {after_tree_size}), {from_ts} .. {to_ts} = {span_ms} ms; Ankermeldungen ohne Gegenzeichnung im Paket: {unanswered_anchor_messages}",
              "window0": "Restfenster (11.2): alle {entries} Einträge, seq {first_seq}..{last_seq}, bis {to_ts} - das Paket enthält keinen gegengezeichneten Checkpoint; Ankermeldungen ohne Gegenzeichnung im Paket: {unanswered_anchor_messages}",
              "beyond": "; über dem Ankertakt - mögliche Ursachen: Lizenzablauf, Egress aus, Hersteller nicht erreichbar, alter Export; Abgleich mit der Wurzel des Herstellers (8.6)"},
       "en": {"exit": "exit", "end": "chain end", "sealed": "sealed at {seal_ts} ({seal_reason}, seq {seal_seq})",
              "incomplete": "not sealed, last entry seq {last_seq}", "none": "not judged", "clean": "no findings.",
              "list": "vendor key list: version {version}, issued {ausgestellt}, root {wurzel_id}",
              "glic": "notice: GENESIS was written under spec 1.7 or earlier and its license_id is not a licence commitment - the licence key itself may stand there; have the vendor replace it (4.1). No effect on the result.",
              "established": "completeness: established up to tree_size {up_to_tree_size} by the expected root passed (8.6)",
              "not_established": "completeness: not established - without a root countersigned by the vendor no statement is possible on whether this package holds the whole chain up to its request (8.6, 11.2). A full statement needs the vendor's anchor history: fetch it for chain_id {chain_id} yourself (heartbeat spec 9.7) and re-run with every root in it recorded BEFORE this package was requested (at least the most recent countersigned one, never a later one) as --expect-root TREE_SIZE:ROOT.",
              "window": "residual window (11.2): {entries} entries, seq {first_seq}..{last_seq}, after the last countersigned checkpoint (tree_size {after_tree_size}), {from_ts} .. {to_ts} = {span_ms} ms; anchor messages without a countersignature in the package: {unanswered_anchor_messages}",
              "window0": "residual window (11.2): all {entries} entries, seq {first_seq}..{last_seq}, up to {to_ts} - the package holds no countersigned checkpoint; anchor messages without a countersignature in the package: {unanswered_anchor_messages}",
              "beyond": "; beyond the anchor cadence - possible causes: licence lapse, egress off, vendor unreachable, old export; compare with the vendor's root (8.6)"}}


def render(res, code, meta, lang, package, rules=None):
    ui, end = _UI[lang], res.chain_end or {"status": "none"}   # a format error leaves the chain end unjudged (8.6)
    out = [f"LEDGER verifier2 {VERSION} - {package}", f"{ui['exit']} {code}: {_rules(res, rules)['exit_codes'][str(code)][lang]}",
           f"{ui['end']}: {ui[end['status']].format(**end)}"]
    if res.completeness: out.append(ui[res.completeness["status"]].format(chain_id=res.chain_id, **res.completeness))   # 8.6
    w = res.residual_window                                                                                             # 11.2
    if w: out.append(ui["window" if w["after_tree_size"] else "window0"].format(**w) + (ui["beyond"] if w["beyond_cadence"] else ""))
    if getattr(res, "vendor_list", None): out.append(ui["list"].format(**res.vendor_list))
    if getattr(res, "glic", None): out.append(ui["glic"])
    if not res.findings: out.append(ui["clean"])
    for cls in res.classes():
        out += ["", f"[{cls}] {ui['exit']} {meta[cls]['exit']} - {meta[cls].get(lang, meta[cls]['en'])}"]
        out += [f"    - {f['detail']}" for f in res.findings if f["class"] == cls]
    return "\n".join(out)


def main(argv):
    ap = argparse.ArgumentParser(prog="verifier2", description="independent second verifier for LEDGER verification packages")
    ap.add_argument("package", help="verification package: directory or ZIP archive")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--now", help="check time for the freshness window, RFC 3339 in UTC: YYYY-MM-DDThh:mm:ss[.fraction]Z (10.8); default: system clock")
    ap.add_argument("--now-from-package", action="store_true", help="take the check time from the package's verify_args.json (frozen test vectors only; the file is chosen by the prover)")
    ap.add_argument("--freshness-hours", type=float, default=DEFAULT_FRESHNESS_H)
    ap.add_argument("--expect-root", action="append", default=[], metavar="[TREE_SIZE:]ROOT",
                    help="expected Merkle root (paper anchor, the vendor's countersigned root; 10.8): at that tree size, or at any; repeatable")
    ap.add_argument("--vendor-root", action="append", default=[], metavar="FILE", help="the vendor's root key {wurzel_id, pubkey} (7.1, 10.7); repeatable")
    ap.add_argument("--vendor-key", action="append", default=[], metavar="ID=HEX", help="pin a vendor countersigning key (7.1); repeatable")
    ap.add_argument("--lang", choices=("de", "en"), default="de")
    ap.add_argument("--registry", default=DEFAULT_REGISTRY)
    args = ap.parse_args(argv[1:])
    try:
        reg = load_registry(args.registry)
        rules = reg["verifier"]
        meta, ranked = rules["finding_classes"], {str(c) for c in rules["exit_precedence"]}
        if set(rules["exit_codes"]) != ranked or not ranked >= {str(m["exit"]) for m in meta.values()} | {"0", "3"}:
            raise ValueError("verifier.exit_codes and exit_precedence must name the same exit codes, every one a finding can yield (10.3)")
    except Exception as exc:
        print(f"verifier2: cannot load the registry ({args.registry}): {exc}", file=sys.stderr); return 3
    try:
        # 10.8: the auditor's inputs follow the package's grammar - never read in the host's time zone, never guessed
        if args.now is not None and utc_ns(args.now) is None:
            raise ValueError(f"--now {args.now!r} is no RFC 3339 instant in UTC (YYYY-MM-DDThh:mm:ss[.fraction]Z, 10.8)")
        now = ms(args.now) if args.now is not None else None
        roots = []
        for s in args.expect_root:                                         # ROOT or TREE_SIZE:ROOT, the root case-insensitive
            m = EXPECT_ROOT.fullmatch(s)
            if not m: raise ValueError(f"--expect-root {s!r} is neither ROOT nor TREE_SIZE:ROOT with a root of 64 hex characters (10.8)")
            roots.append((int(m[1]) if m[1] else None, m[2].lower()))
        vroots, vkeys = {}, {}                                             # same name, different key: ambiguous -> exit 3 (7.1)
        for f in args.vendor_root:                                         # {"wurzel_id","pubkey"}, nothing else
            with open(f, "rb") as fh: w = jloads(fh.read())
            if not isinstance(w, dict) or set(w) != {"wurzel_id", "pubkey"} or not isinstance(w["wurzel_id"], str) \
                    or not KEY_ID.fullmatch(w["wurzel_id"]) or not isinstance(w["pubkey"], str) or not HEX64.fullmatch(w["pubkey"]):
                raise ValueError(f"--vendor-root {f}: not {{wurzel_id, pubkey}} with a key-id and 64 lowercase hex")
            if vroots.get(w["wurzel_id"], w["pubkey"]) != w["pubkey"]: raise ValueError(f"two vendor roots named {w['wurzel_id']!r} with different keys")
            vroots[w["wurzel_id"]] = w["pubkey"]
        for k in args.vendor_key:
            kid, _, pub = k.partition("=")
            if not KEY_ID.fullmatch(kid) or not HEX64.fullmatch(pub): raise ValueError(f"--vendor-key {k!r} is not key_id=hex64")
            if vkeys.get(kid, pub) != pub: raise ValueError(f"vendor key {kid!r} pinned twice with different pubkeys")
            vkeys[kid] = pub
    except Exception as exc:
        print(f"verifier2: unusable argument: {exc}", file=sys.stderr); return 3
    # Whatever the package throws at the checks, the answer is never the interpreter's
    # default exit 1 - that code means "valid with findings" (registry verifier.exit_codes).
    # An input the verifier cannot process is a format error: exit 3, reason on stderr.
    try:
        res = verify(args.package, reg, now, args.freshness_hours, roots, args.now_from_package, vroots, vkeys)
        code = exit_code(res, meta, rules)
    except Exception as exc:
        res, code = _fmt_err(Result(rules), [f"cannot process the package: {type(exc).__name__}: {exc}"]), 3
    if args.json:
        print(json.dumps({"verifier": "verifier2", "version": VERSION, "spec_version": reg["spec_version"],
                          "package": args.package, "exit_code": code, "now_source": res.now_source,
                          "status": {0: "valid", 1: "valid", 2: "invalid", 3: "format_error", 4: "incomplete"}[code],   # 10.3: 4 is no "invalid"
                          "finding_classes": res.classes(), "findings": res.findings,
                          "vendor_list": getattr(res, "vendor_list", None),
                          "chain_end": res.chain_end, "last_countersigned": res.last_countersigned,   # 8.6; null: not judged / none
                          "legal_holds": getattr(res, "legal_holds", None),   # 9.3: active at the chain end, []: none; null: not judged
                          "genesis_license_not_commitment": getattr(res, "glic", None),   # 4.1 notice; null: not judged
                          "completeness": res.completeness,          # 8.6 (1.9): {status, up_to_tree_size}; null: not judged
                          "residual_window": res.residual_window},   # 11.2 (1.9): measured, no finding; null: not judged
                         indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(render(res, code, meta, args.lang, args.package, rules))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
