#!/usr/bin/env python3
"""Reduziert die NIST-ACVP-Dateien fuer ML-DSA (FIPS 204) auf die Testdaten
von appliance/internal/mldsa und verifier/internal/mldsa.

Aufruf:
  python3 -I acvp_auswahl.py <acvp> <appliance-testdata> <verifier-testdata>
<acvp> enthaelt keyGen/, sigGen/ und sigVer/ mit je der internalProjection.json
aus gen-val/json-files/ML-DSA-{keyGen,sigGen,sigVer}-FIPS204/ des ACVP-Servers.

Auswahl (Herkunft und Commit in README.md):
  keyGen: alle drei Gruppen, je die ersten 10 Faelle (tcId-Reihenfolge der Datei).
  sigGen: deterministische Gruppen ohne Pre-Hash (external/pure, internal,
          internal mit externalMu), je die ersten 10 Faelle; pk entfaellt.
  sigVer: Gruppen ohne Pre-Hash, je 10 Faelle: alle gueltigen (3) und
          ungueltige reihum nach reason (alphabetisch), aufsteigend nach tcId;
          sk entfaellt.
Alle uebrigen Felder bleiben unveraendert, tcId und tgId sind die originalen.
"""
import collections
import json
import sys

src, appl, verf = sys.argv[1], sys.argv[2], sys.argv[3]


def load(mode):
    with open(f"{src}/{mode}/internalProjection.json") as f:
        return json.load(f)


def header(j):
    return {k: j[k] for k in ("vsId", "algorithm", "mode", "revision", "isSample")}


def pick(d, names):
    return {k: d[k] for k in names if k in d}


def write(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f, indent=1)
        f.write("\n")


j = load("keyGen")
out = header(j)
out["testGroups"] = []
for g in j["testGroups"]:
    tg = pick(g, ("tgId", "testType", "parameterSet"))
    tg["tests"] = [pick(t, ("tcId", "seed", "pk", "sk")) for t in g["tests"][:10]]
    out["testGroups"].append(tg)
write(f"{appl}/acvp_keygen.json", out)

j = load("sigGen")
out = header(j)
out["testGroups"] = []
for g in j["testGroups"]:
    if not g["deterministic"] or g["preHash"] == "preHash":
        continue
    tg = pick(g, ("tgId", "testType", "parameterSet", "deterministic", "signatureInterface",
                  "preHash", "externalMu", "cornerCase"))
    tg["tests"] = [pick(t, ("tcId", "message", "mu", "context", "sk", "signature"))
                   for t in g["tests"][:10]]
    out["testGroups"].append(tg)
write(f"{appl}/acvp_siggen.json", out)

j = load("sigVer")
out = header(j)
out["testGroups"] = []
for g in j["testGroups"]:
    if g["preHash"] == "preHash":
        continue
    tg = pick(g, ("tgId", "testType", "parameterSet", "signatureInterface", "preHash", "externalMu"))
    chosen = [t for t in g["tests"] if t["testPassed"]]
    by_reason = collections.defaultdict(list)
    for t in g["tests"]:
        if not t["testPassed"]:
            by_reason[t["reason"]].append(t)
    reasons = sorted(by_reason)
    i = 0
    while len(chosen) < 10:
        r = reasons[i % len(reasons)]
        if by_reason[r]:
            chosen.append(by_reason[r].pop(0))
        i += 1
    chosen.sort(key=lambda t: t["tcId"])
    tg["tests"] = [pick(t, ("tcId", "testPassed", "reason", "pk", "message", "mu", "context", "signature"))
                   for t in chosen]
    out["testGroups"].append(tg)
write(f"{verf}/acvp_sigver.json", out)
