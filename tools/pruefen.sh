#!/usr/bin/env bash
# pruefen.sh — genau das, was ein Dritter mit einem LEDGER-Verifier-Release tut.
#
# Abnahme von Paket A3: "Ein Dritter laedt herunter, prueft Signatur, prueft
# Beispielkette offline." Dieses Skript ist dieser Dritte, Schritt fuer
# Schritt, ohne etwas vom Hersteller ausser den Release-Dateien:
#
#   1. Schluessel: Fingerabdruck des Schluessels in allowed_signers — gegen den
#      veroeffentlichten verglichen, wenn Sie ihn als drittes Argument angeben
#      (louwietec.com, Prueferleitfaden). OHNE diesen Abgleich beweist die
#      Signatur nur, dass SHA256SUMS zu irgendeinem Schluessel passt.
#   2. Signatur: ssh-keygen -Y verify (Namensraum "file") ueber SHA256SUMS.
#   3. Pruefsummen: sha256sum -c SHA256SUMS ueber alle Release-Dateien.
#   4. Offline: das Binaer fuer DIESEN Rechner prueft die zwei Beispielketten
#      aus dem Quellarchiv — mit den Vertrauensankern aus dem Quellarchiv —
#      in einem Netz-Namensraum ohne Netz (unshare -rn), wo es den gibt:
#        valid_sealed_export      -> Exit 0, "ordnungsgemaess versiegelt"
#        tamper_content_unpaired  -> Exit 2, CONTENT_MISMATCH
#      Beide sind Ketten der Fassung 1.9: Ketten vor 1.8 trugen den
#      Lizenzschluessel im Klartext und werden fuer die Abnahme nicht mehr
#      verwendet (Entscheidung vom 02.10.2026).
#
# Ein einziges geaendertes Byte in SHA256SUMS, in der Signatur oder in einer
# Release-Datei macht das Ergebnis ROT.
#
# Braucht nur, was auf Linux und macOS ohnehin da ist: bash, ssh-keygen
# (OpenSSH 8.1 oder neuer), sha256sum oder shasum, tar, gzip. Unter Windows
# dieselben Schritte in PowerShell: siehe README.
#
# / Exactly what a third party does with a release: key fingerprint (compared
# with the published one if given as third argument), signature, checksums,
# then the binary for THIS machine on the two example chains, offline, with
# the trust anchors from the source archive. One changed byte in SHA256SUMS,
# the signature or any release file turns the result RED.
#
# Aufruf / usage:
#   bash pruefen.sh DIST ALLOWED_SIGNERS [FINGERABDRUCK]
#     DIST             Verzeichnis mit den Release-Dateien / release files
#     ALLOWED_SIGNERS  allowed_signers des Herstellers / the vendor's file
#     FINGERABDRUCK    veroeffentlichter Fingerabdruck, z. B. SHA256:abc...
#   LEDGER_IDENTITAET  Signatur-Identitaet (Vorgabe release@louwietec.com)
set -euo pipefail

IDENTITAET="${LEDGER_IDENTITAET:-release@louwietec.com}"

sha256_c() { # Pruefsummendatei im aktuellen Verzeichnis / sums file in cwd
  if command -v sha256sum >/dev/null 2>&1; then sha256sum -c "$@"; else shasum -a 256 -c "$@"; fi
}
sha256_von() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# offline_teil BIN TESTVEKTOREN AUSGABE NETZNACHWEIS — laeuft, wo moeglich, in
# einem Netz-Namensraum ohne Netz; NETZNACHWEIS=1 zeigt dort die
# Schnittstellen und einen gescheiterten Verbindungsversuch. Ohne Namensraum
# wird KEINE Verbindung versucht — ein Pruefer soll von diesem Skript keinen
# Netzverkehr bekommen.
# / Runs, where possible, in a network namespace without network; only there
# does it show the interfaces and a failing connection attempt.
offline_teil() {
  local bin="$1" tv="$2" aus="$3" nachweis="$4" ok=0 e
  if [ "$nachweis" = 1 ]; then
    local ifs n
    ifs="$(tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | tr '\n' ' ' | sed 's/ $//')"
    n="$(tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | grep -vcx lo || true)"
    echo "   Netzschnittstellen ausser lo / interfaces besides lo: $n   (sichtbar / visible: ${ifs:-keine})"
    [ "$n" = 0 ] || { echo "   ROT: der Namensraum hat Netz / the namespace has network"; ok=1; }
    if (exec 3<>/dev/tcp/1.1.1.1/443) 2>"$aus/netz.err"; then
      echo "   Verbindungsversuch 1.1.1.1:443: ERFOLGREICH — dieser Lauf ist NICHT offline / NOT offline"
      ok=1
    else
      echo "   Verbindungsversuch / connection attempt 1.1.1.1:443: $(tail -1 "$aus/netz.err" | sed 's/^.*: //')"
    fi
  fi
  echo "   $("$bin" --version | head -1)"
  echo "   $("$bin" --version | sed -n 2p)"
  local anker_w="$tv/pruefer_herstellerwurzel.json" anker_k
  anker_k="$(head -1 "$tv/pruefer_herstellerschluessel.txt")"

  echo
  echo "   -- Beispielkette 1 / example chain 1: valid_sealed_export (Soll / expected: Exit 0, ordnungsgemäß versiegelt)"
  echo "   \$ $(basename "$bin") --lang de --now-from-package --vendor-root .../pruefer_herstellerwurzel.json --vendor-key $anker_k .../valid_sealed_export"
  set +e
  "$bin" --lang de --now-from-package --vendor-root "$anker_w" --vendor-key "$anker_k" "$tv/valid_sealed_export" > "$aus/gueltig.txt" 2>&1
  e=$?
  set -e
  sed 's/^/     | /' "$aus/gueltig.txt"
  if [ "$e" -eq 0 ] && grep -q 'ordnungsgemäß versiegelt' "$aus/gueltig.txt"; then
    echo "   GRUEN: Exit $e, Kettenende ordnungsgemäß versiegelt / sealed"
  else
    echo "   ROT: Exit $e (Soll 0) oder 'ordnungsgemäß versiegelt' fehlt / RED"; ok=1
  fi

  echo
  echo "   -- Beispielkette 2 / example chain 2: tamper_content_unpaired (Soll / expected: Exit 2, CONTENT_MISMATCH)"
  echo "   \$ $(basename "$bin") --lang de --now-from-package --vendor-root .../pruefer_herstellerwurzel.json --vendor-key $anker_k .../tamper_content_unpaired"
  set +e
  "$bin" --lang de --now-from-package --vendor-root "$anker_w" --vendor-key "$anker_k" "$tv/tamper_content_unpaired" > "$aus/manipuliert.txt" 2>&1
  e=$?
  set -e
  sed 's/^/     | /' "$aus/manipuliert.txt"
  if [ "$e" -eq 2 ] && grep -q 'CONTENT_MISMATCH' "$aus/manipuliert.txt"; then
    echo "   GRUEN: Exit $e mit CONTENT_MISMATCH — die Manipulation ist erkannt / tampering detected"
  else
    echo "   ROT: Exit $e (Soll 2) oder CONTENT_MISMATCH fehlt / RED"; ok=1
  fi
  return "$ok"
}

if [ "${1:-}" = "--offline-teil" ]; then
  offline_teil "$2" "$3" "$4" "$5"
  exit $?
fi

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
  echo "Aufruf / usage: bash pruefen.sh DIST ALLOWED_SIGNERS [FINGERABDRUCK]" >&2
  exit 2
fi
DIST="$(cd "$1" && pwd)"
ALLOWED="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
FP_SOLL="${3:-}"
SELBST="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
ARBEIT="$(mktemp -d "${TMPDIR:-/tmp}/ledger-pruefen.XXXXXX")"
trap 'rm -rf "$ARBEIT"' EXIT

rot() { echo; echo "ERGEBNIS: ROT — $*"; exit 1; }

echo "== LEDGER-Verifier: Release pruefen / verify a release"
echo "   Release-Dateien / files : $DIST"
echo "   allowed_signers         : $ALLOWED"
echo "   Identitaet / identity   : $IDENTITAET"
command -v ssh-keygen >/dev/null 2>&1 || rot "ssh-keygen fehlt (OpenSSH-Client) / missing"
echo "   OpenSSH                 : $(ssh -V 2>&1 || echo 'ssh -V nicht verfuegbar')"
[ -f "$DIST/SHA256SUMS" ] || rot "SHA256SUMS fehlt in $DIST / missing"
[ -f "$DIST/SHA256SUMS.sig" ] || rot "SHA256SUMS.sig fehlt in $DIST / missing"
[ -f "$ALLOWED" ] || rot "allowed_signers fehlt / missing: $ALLOWED"

echo
echo "== 1) Schluessel / signing key"
# allowed_signers: <identitaet> [optionen] <schluesseltyp> <base64> [kommentar]
ZEILE="$(awk -v id="$IDENTITAET" '{ n = split($1, p, ","); for (i = 1; i <= n; i++) if (p[i] == id) { print; exit } }' "$ALLOWED")"
[ -n "$ZEILE" ] || rot "allowed_signers nennt $IDENTITAET nicht / does not name the identity"
echo "$ZEILE" | awk '{for (i = 2; i < NF; i++) if ($i ~ /^(ssh-|ecdsa-|sk-)/) { print $i, $(i+1); exit }}' > "$ARBEIT/signierer.pub"
[ -s "$ARBEIT/signierer.pub" ] || rot "kein Schluessel in der allowed_signers-Zeile / no key in the line"
FP_IST="$(ssh-keygen -lf "$ARBEIT/signierer.pub" | awk '{print $2}')"
echo "   $(ssh-keygen -lf "$ARBEIT/signierer.pub")"
if [ -n "$FP_SOLL" ]; then
  if [ "$FP_IST" = "$FP_SOLL" ]; then
    echo "   GRUEN: Fingerabdruck = veroeffentlichter / fingerprint matches the published one ($FP_SOLL)"
  else
    rot "Fingerabdruck $FP_IST ist NICHT der veroeffentlichte $FP_SOLL — allowed_signers stammt nicht vom Hersteller / not the vendor's key"
  fi
else
  echo "   ACHTUNG / ATTENTION: kein veroeffentlichter Fingerabdruck angegeben. Vergleichen Sie $FP_IST"
  echo "   selbst mit dem auf louwietec.com und im Prueferleitfaden — sonst beweist die Signatur nur,"
  echo "   dass SHA256SUMS zu IRGENDEINEM Schluessel passt. / Compare it yourself with the published one."
fi

echo
echo "== 2) Signatur / signature (ssh-keygen -Y verify -n file)"
if ! ssh-keygen -Y verify -f "$ALLOWED" -I "$IDENTITAET" -n file -s "$DIST/SHA256SUMS.sig" \
     < "$DIST/SHA256SUMS" > "$ARBEIT/sig.txt" 2>&1; then
  sed 's/^/   /' "$ARBEIT/sig.txt"
  rot "Signatur ueber SHA256SUMS ungueltig / signature over SHA256SUMS invalid"
fi
sed 's/^/   /' "$ARBEIT/sig.txt"
echo "   GRUEN: SHA256SUMS ist vom Schluessel $FP_IST signiert / signed by that key"

echo
echo "== 3) Pruefsummen / checksums (sha256sum -c SHA256SUMS)"
if ! (cd "$DIST" && sha256_c SHA256SUMS) > "$ARBEIT/summen.txt" 2>&1; then
  sed 's/^/   /' "$ARBEIT/summen.txt"
  rot "mindestens eine Release-Datei weicht von SHA256SUMS ab oder fehlt / a release file differs or is missing"
fi
sed 's/^/   /' "$ARBEIT/summen.txt"
N_SUMMEN="$(grep -c . "$DIST/SHA256SUMS")"
echo "   GRUEN: $N_SUMMEN/$N_SUMMEN Dateien stimmen / files match"
for f in "$DIST"/*; do
  b="$(basename "$f")"
  case "$b" in SHA256SUMS|SHA256SUMS.sig|allowed_signers) continue ;; esac
  grep -q "  $b\$" "$DIST/SHA256SUMS" || echo "   HINWEIS: $b liegt in DIST, steht aber nicht in SHA256SUMS — wird nicht benutzt / not listed, not used"
done

echo
echo "== 4) Offline: Beispielketten mit dem Binaer dieses Rechners / example chains offline"
case "$(uname -s)" in Linux) OS=linux ;; Darwin) OS=darwin ;; MINGW*|MSYS*|CYGWIN*) OS=windows ;; *) rot "unbekanntes Betriebssystem $(uname -s)" ;; esac
case "$(uname -m)" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) rot "unbekannte Architektur $(uname -m)" ;; esac
BIN_NAME="$(sed -n "s/^[0-9a-f]\{64\}  \(.*_${OS}_${ARCH}\(\.exe\)\{0,1\}\)\$/\1/p" "$DIST/SHA256SUMS")"
[ "$(printf '%s\n' "$BIN_NAME" | grep -c .)" -eq 1 ] || rot "kein eindeutiges Binaer fuer ${OS}_${ARCH} in SHA256SUMS / no unique binary"
QUELL_NAME="$(sed -n 's/^[0-9a-f]\{64\}  \(.*_source\.tar\.gz\)$/\1/p' "$DIST/SHA256SUMS")"
[ "$(printf '%s\n' "$QUELL_NAME" | grep -c .)" -eq 1 ] || rot "kein eindeutiges Quellarchiv in SHA256SUMS / no unique source archive"
echo "   Plattform / platform : ${OS}_${ARCH} -> $BIN_NAME"
echo "   Quellarchiv / source : $QUELL_NAME"

# Kopien, gegen SHA256SUMS nachgeprueft: DIST bleibt unberuehrt, und zwischen
# Pruefung und Ausfuehrung kann niemand die Datei tauschen.
# / Copies, re-checked against SHA256SUMS: DIST stays untouched.
cp "$DIST/$BIN_NAME" "$ARBEIT/$BIN_NAME"
cp "$DIST/$QUELL_NAME" "$ARBEIT/$QUELL_NAME"
for f in "$BIN_NAME" "$QUELL_NAME"; do
  soll="$(grep "  $f\$" "$DIST/SHA256SUMS" | cut -d' ' -f1)"
  [ "$(sha256_von "$ARBEIT/$f")" = "$soll" ] || rot "Kopie von $f weicht ab / copy differs"
done
chmod +x "$ARBEIT/$BIN_NAME"
mkdir -p "$ARBEIT/quelle"
tar -xzf "$ARBEIT/$QUELL_NAME" -C "$ARBEIT/quelle"
TV="$(find "$ARBEIT/quelle" -maxdepth 3 -type d -path '*/spec/testvectors' | head -1)"
[ -n "$TV" ] || rot "spec/testvectors fehlt im Quellarchiv / missing in the source archive"
for n in pruefer_herstellerwurzel.json pruefer_herstellerschluessel.txt valid_sealed_export tamper_content_unpaired PINS.sha256; do
  [ -e "$TV/$n" ] || rot "$n fehlt im Quellarchiv / missing"
done
if ! (cd "$TV" && sha256_c --quiet PINS.sha256) > "$ARBEIT/pins.txt" 2>&1; then
  sed 's/^/   /' "$ARBEIT/pins.txt"; rot "Testvektoren weichen von PINS.sha256 ab / vectors differ from their pins"
fi
echo "   Testvektoren gegen PINS.sha256 / vectors vs pins: $(grep -c . "$TV/PINS.sha256") Dateien unveraendert"
echo "   Vertrauensanker aus dem Quellarchiv / trust anchors from the source archive:"
echo "     --vendor-root spec/testvectors/pruefer_herstellerwurzel.json  $(tr -d '\n' < "$TV/pruefer_herstellerwurzel.json")"
echo "     --vendor-key  $(head -1 "$TV/pruefer_herstellerschluessel.txt")"
echo
mkdir -p "$ARBEIT/offline"

if command -v unshare >/dev/null 2>&1 && unshare -rn true 2>/dev/null; then
  echo "   Netz-Namensraum ohne Netz / network namespace without network: unshare -rn"
  if unshare -rn bash "$SELBST" --offline-teil "$ARBEIT/$BIN_NAME" "$TV" "$ARBEIT/offline" 1; then OFFLINE=0; else OFFLINE=1; fi
  WIE="in einem Netz-Namensraum ohne Netz (unshare -rn)"
else
  echo "   HINWEIS: kein Netz-Namensraum verfuegbar (macOS, Windows, eingeschraenkter Container)."
  echo "   Der Verifier oeffnet keine Verbindung; wer es sehen will, trennt das Netz vor diesem Schritt."
  echo "   / No network namespace here; the verifier opens no connection — disconnect to see it."
  if offline_teil "$ARBEIT/$BIN_NAME" "$TV" "$ARBEIT/offline" 0; then OFFLINE=0; else OFFLINE=1; fi
  WIE="ohne Netz-Namensraum (Netz nicht technisch getrennt)"
fi
[ "$OFFLINE" -eq 0 ] || rot "die Beispielketten ergaben nicht das erwartete Urteil / example chains did not yield the expected verdict"

echo
if [ -n "$FP_SOLL" ]; then
  echo "ERGEBNIS: GRUEN — Schluessel = veroeffentlichter Fingerabdruck, Signatur gueltig, $N_SUMMEN/$N_SUMMEN Pruefsummen, Beispielketten $WIE: gueltig+versiegelt Exit 0, manipuliert Exit 2 CONTENT_MISMATCH"
else
  echo "ERGEBNIS: GRUEN — Signatur gueltig, $N_SUMMEN/$N_SUMMEN Pruefsummen, Beispielketten $WIE: gueltig+versiegelt Exit 0, manipuliert Exit 2 CONTENT_MISMATCH; ACHTUNG: Fingerabdruck $FP_IST NICHT mit dem veroeffentlichten abgeglichen"
fi
