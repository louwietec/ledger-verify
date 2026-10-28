#!/usr/bin/env bash
# bauen.sh: baut den LEDGER-Verifier reproduzierbar aus diesem Baum.
#
# Ergebnis in AUSGABE:
#   <name>_<version>_linux_amd64, _linux_arm64, _darwin_amd64, _darwin_arm64,
#   _windows_amd64.exe      die Kommandozeilen-Verifier
#   <name>_<version>.html   der Browser-Verifier als EINE Datei (WebAssembly
#                           gepackt in der Seite, siehe verifier/web/bauen.sh)
#
# REPRODUZIERBAR: CGO_ENABLED=0, -trimpath, -buildvcs=false,
# -ldflags "-s -w -buildid=", feste GOAMD64/GOARM64, GOTOOLCHAIN=local und ein
# leeres GOFLAGS. Mit derselben Go-Fassung (go1.24.7) ergibt jeder Rechner
# dieselben Bytes wie das Release; vergleichen Sie mit SHA256SUMS.
# -buildvcs=false, weil ein Bau aus einem git-Klon sonst andere Bytes ergaebe
# als einer aus dem Quellarchiv (Go stempelt den VCS-Stand ins Binaer).
#
# Dieses Skript ist DIE Bauvorschrift: das Release, die CI dieses
# Repositorys und jeder Dritte, der nachbaut, rufen genau diese Datei.
#
# / Reproducible build of the LEDGER verifier from this tree: five CLI
# binaries and the single-file browser page. With the same Go release
# (go1.24.7) every machine yields the release's bytes; compare them with
# SHA256SUMS. This script is THE build recipe; the release, this
# repository's CI and anyone rebuilding call exactly this file.
#
# Aufruf / usage:  bash tools/bauen.sh AUSGABE VERSION [NAME]
#                  NAME default: ledger-verify
# Optional: LEDGER_VERIFY_HERSTELLER_WURZEL=<datei {"wurzel_id","pubkey"}>
#           baut die Herstellerwurzel ein (Spezifikation 7.1); ohne sie traegt
#           das Binaer keine, und der Pruefer uebergibt --vendor-root.
#           / compiles the vendor root in; without it the auditor passes it.
set -euo pipefail

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
  echo "Aufruf / usage: bash tools/bauen.sh AUSGABE VERSION [NAME]" >&2
  exit 2
fi
AUSGABE="$1"; VERSION="$2"; NAME="${3:-ledger-verify}"
GO_FASSUNG_RELEASE="go1.24.7"
BAUM="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
V="$BAUM/verifier"

case "$VERSION" in
  *[!0-9A-Za-z.-]*|"") echo "VERSION darf nur 0-9 A-Z a-z . - enthalten / invalid VERSION: $VERSION" >&2; exit 2 ;;
esac
case "$NAME" in
  *[!0-9a-z-]*|"") echo "NAME darf nur a-z 0-9 - enthalten / invalid NAME: $NAME" >&2; exit 2 ;;
esac

mkdir -p "$AUSGABE"
AUSGABE="$(cd "$AUSGABE" && pwd)"
ARBEIT="$(mktemp -d "${TMPDIR:-/tmp}/ledger-bau.XXXXXX")"
trap 'rm -rf "$ARBEIT"' EXIT

echo "== Bau / build: $NAME $VERSION"
GOVER="$(GOTOOLCHAIN=local go env GOVERSION)"
echo "   Go            : $GOVER"
if [ "$GOVER" != "$GO_FASSUNG_RELEASE" ]; then
  echo "   WARNUNG / WARNING: das Release wurde mit $GO_FASSUNG_RELEASE gebaut; mit $GOVER weichen die Bytes ab"
  echo "                      the release was built with $GO_FASSUNG_RELEASE; $GOVER yields different bytes"
fi

# Kommandos: ./cmd/<name> (Kommandozeile) und ./cmd/<name>-wasm (Browser).
# Beide rufen nur internal/cli bzw. internal/wasmapi; dort steht die Version
# als Variable, die -X setzt.
# / Commands ./cmd/<name> and ./cmd/<name>-wasm; the version is a variable in
# internal/cli and internal/wasmapi, stamped with -X.
CMD="$NAME"; WCMD="$NAME-wasm"
for k in "$CMD" "$WCMD"; do
  [ -d "$V/cmd/$k" ] || { echo "verifier/cmd/$k fehlt / missing" >&2; exit 1; }
done
echo "   Kommando      : ./cmd/$CMD"
echo "   Browser-Modul : ./cmd/$WCMD"
for q in internal/cli/cli.go internal/wasmapi/wasmapi.go; do
  grep -q '^var Version = "' "$V/$q" \
    || { echo "$q: keine Variable Version; -X wuerde nichts setzen / no Version variable" >&2; exit 1; }
done
echo "   Version       : -X internal/cli.Version=$VERSION, -X internal/wasmapi.Version=$VERSION"

MODUL="$(sed -n 's/^module \(.*\)$/\1/p' "$V/go.mod" | head -1)"
WURZEL_LDFLAG=""
if [ -n "${LEDGER_VERIFY_HERSTELLER_WURZEL:-}" ]; then
  WURZEL_WERT="$(python3 -c 'import json,re,sys; w=json.load(open(sys.argv[1])); assert set(w)=={"wurzel_id","pubkey"}, "genau wurzel_id und pubkey / exactly wurzel_id and pubkey"; assert re.fullmatch("[0-9a-f]{64}", w["pubkey"]), "pubkey ist kein 64-stelliger Hexwert / pubkey is not 64 hex digits"; assert re.fullmatch("[A-Za-z0-9._-]{1,64}", w["wurzel_id"]), "wurzel_id ungueltig / invalid"; print(w["wurzel_id"]+"="+w["pubkey"])' "$LEDGER_VERIFY_HERSTELLER_WURZEL")"
  WURZEL_LDFLAG=" -X $MODUL/internal/vfy.BuiltinVendorRoot=$WURZEL_WERT"
  echo "   Herstellerwurzel eingebaut / vendor root compiled in: $WURZEL_WERT"
else
  echo "   Herstellerwurzel: keine eingebaut, Pruefer uebergibt --vendor-root / none compiled in"
fi

# Feste Bauumgebung: nichts aus der Shell des Bauenden darf die Bytes aendern.
# / Fixed build environment: nothing from the builder's shell changes bytes.
goenv() {
  env CGO_ENABLED=0 GOFLAGS= GOEXPERIMENT= GOAMD64=v1 GOARM64=v8.0 GOTOOLCHAIN=local GOPROXY=off "$@"
}

echo "== 1) Kommandozeilen-Verifier / CLI verifiers"
for ziel in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
  goos="${ziel%/*}"; goarch="${ziel#*/}"; ext=""
  [ "$goos" = windows ] && ext=".exe"
  aus="$AUSGABE/${NAME}_${VERSION}_${goos}_${goarch}${ext}"
  (cd "$V" && goenv GOOS="$goos" GOARCH="$goarch" \
     go build -trimpath -buildvcs=false -ldflags "-s -w -buildid= -X $MODUL/internal/cli.Version=$VERSION$WURZEL_LDFLAG" \
     -o "$aus" "./cmd/$CMD")
done

echo "== 2) Browser-Verifier / browser page (wie / as verifier/web/bauen.sh)"
WASM="$ARBEIT/verifier.wasm"
(cd "$V" && goenv GOOS=js GOARCH=wasm \
   go build -trimpath -buildvcs=false -ldflags "-X $MODUL/internal/wasmapi.Version=$VERSION$WURZEL_LDFLAG" -o "$WASM" "./cmd/$WCMD")
LADER="$(GOTOOLCHAIN=local go env GOROOT)/lib/wasm/wasm_exec.js"
[ -f "$LADER" ] || LADER="$(GOTOOLCHAIN=local go env GOROOT)/misc/wasm/wasm_exec.js"
[ -f "$LADER" ] || { echo "wasm_exec.js der Go-Installation nicht gefunden / not found" >&2; exit 1; }
(cd "$V" && goenv GOOS="$(go env GOHOSTOS)" GOARCH="$(go env GOHOSTARCH)" \
   go build -trimpath -buildvcs=false -o "$ARBEIT/einbetten" ./web/einbetten)
"$ARBEIT/einbetten" -vorlage "$V/web/verifier.html" -wasm "$WASM" -lader "$LADER" \
   -aus "$AUSGABE/${NAME}_${VERSION}.html" >/dev/null

echo "== Ergebnis / result ($AUSGABE)"
(cd "$AUSGABE" && for f in "${NAME}_${VERSION}"_* "${NAME}_${VERSION}.html"; do
   if command -v sha256sum >/dev/null 2>&1; then sha256sum "$f"; else shasum -a 256 "$f"; fi
 done)
