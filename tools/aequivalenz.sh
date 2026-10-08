#!/usr/bin/env bash
# aequivalenz.sh — beide Verifier ueber ALLE Testvektoren, gegen expected/.
#
# Zwei unabhaengige Implementierungen derselben offenen Spezifikation — der
# Go-Verifier (verifier/) und der Python-Zweitverifier (verifier2/) — muessen
# fuer jeden eingefrorenen Testvektor unter spec/testvectors/ genau das Urteil
# aus spec/testvectors/expected/<name>.json fallen: denselben Exit-Code und
# dieselbe Menge an Befundklassen. Dazu muessen sie untereinander im Status
# und im Kettenende uebereinstimmen. Jede Abweichung ist rot und nennt den
# Vektor, die Erwartung und das Gesehene.
#
# UNABHAENGIGKEIT WIRD ERZWUNGEN, NICHT VERSPROCHEN: verifier2 laeuft in einem
# frischen Verzeichnis, das nur spec/ und verifier2/ enthaelt — kein verifier/,
# kein Repository. Haette verifier2 eine versteckte Abhaengigkeit vom
# Go-Verifier, fiele er hier auf.
#
# Vorher: jede Vektordatei gegen spec/testvectors/PINS.sha256 — ein
# veraenderter Vektor ist rot, bevor er ein Urteil beeinflussen kann.
#
# Pruefumgebung (Spezifikation 7.1): die Erwartungen gelten fuer die Wurzel
# des Testherstellers und seinen angehefteten Schluessel, beide in
# spec/testvectors/ (pruefer_herstellerwurzel.json,
# pruefer_herstellerschluessel.txt); die Pruefzeit steht in verify_args.json.
#
# / Both verifiers over ALL test vectors against expected/: same exit code and
# same finding classes as expected, same status and chain end as each other.
# verifier2 runs in a sandbox holding only spec/ and verifier2/. Pins first.
#
# Aufruf / usage:  bash tools/aequivalenz.sh      (braucht / needs: go, python3)
set -euo pipefail

BAUM="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARBEIT="$(mktemp -d "${TMPDIR:-/tmp}/ledger-aequivalenz.XXXXXX")"
trap 'rm -rf "$ARBEIT"' EXIT

pruefsummen_c() { # Pruefsummendatei im aktuellen Verzeichnis pruefen / check a sums file
  if command -v sha256sum >/dev/null 2>&1; then sha256sum -c --quiet "$1"; else shasum -a 256 -c --quiet "$1"; fi
}

echo "== 0) Testvektoren gegen PINS.sha256 / vectors against their pins"
(cd "$BAUM/spec/testvectors" && pruefsummen_c PINS.sha256)
echo "   GRUEN: $(grep -c . "$BAUM/spec/testvectors/PINS.sha256") Dateien unveraendert / files unchanged"

echo "== 1) Go-Verifier bauen / build the Go verifier"
# Neuer Name, wenn vorhanden, sonst der fruehere / new name if present, else the former
if [ -d "$BAUM/verifier/cmd/ledger-verify" ]; then CMD=ledger-verify; else CMD=rekorder-verify; fi
(cd "$BAUM/verifier" && CGO_ENABLED=0 GOFLAGS= go build -trimpath -buildvcs=false -o "$ARBEIT/go-verifier" "./cmd/$CMD")
echo "   ./cmd/$CMD -> $ARBEIT/go-verifier"

echo "== 2) Sandbox fuer verifier2: nur spec/ + verifier2/"
SANDBOX="$ARBEIT/sandbox"
mkdir -p "$SANDBOX"
cp -R "$BAUM/spec" "$SANDBOX/spec"
cp -R "$BAUM/verifier2" "$SANDBOX/verifier2"
FREMD="$(cd "$SANDBOX" && ls -A | grep -vx -e spec -e verifier2 || true)"
[ -z "$FREMD" ] || { echo "ROT: Sandbox nicht isoliert: $FREMD"; exit 1; }
for verboten in verifier .git; do
  if find "$SANDBOX" -maxdepth 3 -name "$verboten" | grep -q .; then
    echo "ROT: Sandbox enthaelt $verboten — Unabhaengigkeit verletzt / independence violated"; exit 1
  fi
done
echo "   $SANDBOX: $(cd "$SANDBOX" && ls -A | tr '\n' ' ')"

VEC="$BAUM/spec/testvectors"
SVEC="$SANDBOX/spec/testvectors"
ANKER=(--vendor-root "$VEC/pruefer_herstellerwurzel.json")
SANKER=(--vendor-root "$SVEC/pruefer_herstellerwurzel.json")
while IFS= read -r k; do
  [ -n "$k" ] && ANKER+=(--vendor-key "$k") && SANKER+=(--vendor-key "$k")
done < "$VEC/pruefer_herstellerschluessel.txt"

echo "== 3) Beide Verifier ueber alle Vektoren / both verifiers over all vectors"
GUT=0; SCHLECHT=0
for erw in "$VEC"/expected/*.json; do
  name="$(basename "$erw" .json)"
  if [ ! -d "$VEC/$name" ]; then
    echo "ROT        $name: Vektorverzeichnis fehlt / vector directory missing"; SCHLECHT=$((SCHLECHT + 1)); continue
  fi
  soll="$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["exit_code"], ",".join(sorted(set(d["finding_classes"]))))' "$erw")"
  set +e
  go_json="$("$ARBEIT/go-verifier" --json --now-from-package "${ANKER[@]}" "$VEC/$name" 2>"$ARBEIT/go.err")"; go_exit=$?
  py_json="$(python3 "$SANDBOX/verifier2/verifier2.py" --json --now-from-package "${SANKER[@]}" "$SVEC/$name" 2>"$ARBEIT/py.err")"; py_exit=$?
  set -e
  go="$(printf '%s' "$go_json" | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin); print(d["exit_code"], ",".join(sorted({f["class"] for f in d["findings"]})), d["status"], (d["stats"].get("chain_end") or {}).get("status","-"))
except Exception: print("? UNLESBAR - -")')"
  py="$(printf '%s' "$py_json" | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin); print(d["exit_code"], ",".join(sorted(set(d["finding_classes"]))), d["status"], (d.get("chain_end") or {}).get("status","-"))
except Exception: print("? UNLESBAR - -")')"
  g2="$(echo "$go" | cut -d' ' -f1-2)"; p2="$(echo "$py" | cut -d' ' -f1-2)"
  urteil=GLEICH
  if [ "$g2" != "$soll" ] || [ "$p2" != "$soll" ] || [ "$go_exit" != "${soll%% *}" ] || [ "$py_exit" != "${soll%% *}" ] \
     || [ "$(echo "$go" | cut -d' ' -f3-)" != "$(echo "$py" | cut -d' ' -f3-)" ]; then
    urteil=ABWEICHUNG
  fi
  printf '%-10s %-30s soll=%-34s go=%-46s verifier2=%s\n' "$urteil" "$name" "[$soll]" "[$go]" "[$py]"
  if [ "$urteil" = GLEICH ]; then GUT=$((GUT + 1)); else
    SCHLECHT=$((SCHLECHT + 1))
    [ -s "$ARBEIT/go.err" ] && sed 's/^/           go stderr: /' "$ARBEIT/go.err"
    [ -s "$ARBEIT/py.err" ] && sed 's/^/           verifier2 stderr: /' "$ARBEIT/py.err"
  fi
done

GESAMT=$((GUT + SCHLECHT))
echo
if [ "$SCHLECHT" -eq 0 ] && [ "$GESAMT" -gt 0 ]; then
  echo "ERGEBNIS: GRUEN — $GUT/$GESAMT Vektoren: beide Verifier exakt wie erwartet und untereinander gleich (Exit, Befundklassen, Status, Kettenende)"
  echo "RESULT: GREEN — $GUT/$GESAMT vectors: both verifiers exactly as expected and equal to each other"
  exit 0
fi
echo "ERGEBNIS: ROT — $SCHLECHT von $GESAMT Vektoren weichen ab / RESULT: RED — $SCHLECHT of $GESAMT vectors deviate"
exit 1
