#!/usr/bin/env bash
# bauen.sh — baut den Browser-Verifier (ledger-verify, LEDGER) zu EINER Datei.
#
# Ergebnis: verifier/web/dist/ledger-verify.html — eine einzige HTML-Datei,
# die ein LEDGER-Pruefpaket vollstaendig lokal prueft. Kein Server, kein
# Nachladen, kein Upload. Ein Pruefer speichert sie einmal und benutzt sie
# danach offline.
#
# ALTER NAME / old name: daneben entsteht verifier/web/dist/rekorder-verify.html
# als BYTEGLEICHE Kopie (cmp am Ende dieses Skripts). Das Portal
# (--verifier-web), deploy/images/Dockerfile und der CI-Upload erwarten noch
# diesen Pfad (Spuren B/C); stellen sie um, kann die Kopie entfallen. Die
# Kopie ist dieselbe Seite: auch sie nennt LEDGER und ledger-verify.
#
# WARUM EINE DATEI: die Alternative waere HTML + verifier.wasm + wasm_exec.js
# nebeneinander. Das laedt der Browser von file:// nicht zuverlaessig nach
# (CORS), und drei Dateien, von denen eine fehlen kann, sind fuer ein
# Beweiswerkzeug die falsche Bauart. Deshalb liegt das WebAssembly-Modul
# gepackt und base64-kodiert IN der Seite.
#
# WARUM DIE ARBEIT IN GO STECKT (web/einbetten): dieser Bau laeuft auch IM
# Appliance-Abbild, damit das Portal die Seite dem Pruefpaket beilegen kann.
# Dort gibt es kein python3 und kein verlaessliches gzip/base64. Go ist an
# beiden Orten da — also macht Go das Packen, das Kodieren und das Einsetzen,
# und dieses Skript ist nur noch die Reihenfolge.
#
# REPRODUZIERBAR: -trimpath, eine feste Go-Fassung und ein gzip-Kopf ohne
# Zeitstempel ergeben eine byte-gleiche Seite. Die ausgegebene SHA-256 ist die,
# die ein Pruefer gegen die veroeffentlichte haelt.
#
# Aufruf / usage:  bash verifier/web/bauen.sh
set -euo pipefail

WURZEL="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST="$WURZEL/verifier/web/dist"
mkdir -p "$DIST"

WASM="$(mktemp -t rv-XXXXXX.wasm)"
trap 'rm -f "$WASM"' EXIT

echo "== 1) WebAssembly bauen / build the module"
(cd "$WURZEL/verifier" && GOOS=js GOARCH=wasm go build -trimpath -o "$WASM" ./cmd/ledger-verify-wasm)

echo "== 2) wasm_exec.js der benutzten Go-Fassung suchen / locate Go's loader"
LADER="$(go env GOROOT)/lib/wasm/wasm_exec.js"
[ -f "$LADER" ] || LADER="$(go env GOROOT)/misc/wasm/wasm_exec.js"
if [ ! -f "$LADER" ]; then
  echo "FEHLT: wasm_exec.js der Go-Installation nicht gefunden / not found" >&2
  exit 1
fi

echo "== 3) packen, kodieren, einsetzen / compress, encode, inject"
(cd "$WURZEL/verifier" && go run ./web/einbetten \
   -vorlage web/verifier.html -wasm "$WASM" -lader "$LADER" \
   -aus web/dist/ledger-verify.html)

echo "== 4) bytegleiche Kopie unter dem alten Namen / byte-identical copy under the old name"
cp "$DIST/ledger-verify.html" "$DIST/rekorder-verify.html"
cmp "$DIST/ledger-verify.html" "$DIST/rekorder-verify.html"
echo "   rekorder-verify.html = ledger-verify.html (cmp: gleich / identical)"

echo "   Go           : $(go version | awk '{print $3}')"
