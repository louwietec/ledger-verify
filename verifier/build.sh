#!/bin/sh
# Reproducible cross-platform builds of ledger-verify, the free offline
# verifier of LEDGER (formerly "Rekorder"; the compatibility alias
# ./cmd/rekorder-verify is the same program and is not shipped from here).
# Builds linux/amd64, darwin/arm64, windows/amd64 into verifier/dist/,
# then builds everything a second time in a separate directory and compares
# SHA-256 sums to prove byte-identical (reproducible) output.
# Where an evidence directory artefakte/ exists next to verifier/, the log is
# also written there; otherwise (the public verifier repository has no
# artefakte/) the log goes to stdout only; the script never creates
# directories outside verifier/.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=$(dirname -- "$HERE")
DIST="$HERE/dist"
LOG_DIR="$REPO/artefakte/P03"
if [ -d "$LOG_DIR" ]; then LOG="$LOG_DIR/repro_build.log"; else LOG=$(mktemp); trap 'rm -f "$LOG"' EXIT; fi
mkdir -p "$DIST"

TARGETS="linux/amd64 darwin/arm64 windows/amd64"

# Vendor root compiled into a release build (spec 7.1): REKORDER_VERIFY_HERSTELLER_WURZEL
# names the vendor's root file {"wurzel_id","pubkey"}. Deliberately NOT the
# appliance's REKORDER_HERSTELLER_WURZEL from rekorder.env: a build shell that
# sourced an appliance configuration must not silently bake that root into
# the auditor's tool. Without it the build
# carries no root — the auditor passes --vendor-root or --vendor-key. The
# value is part of the build input, so both reproducibility runs use it.
WURZEL_LDFLAG=""
if [ -n "${REKORDER_VERIFY_HERSTELLER_WURZEL:-}" ]; then
    WURZEL_WERT=$(python3 -c 'import json,sys; w=json.load(open(sys.argv[1])); assert set(w)=={"wurzel_id","pubkey"}; print(w["wurzel_id"]+"="+w["pubkey"])' "$REKORDER_VERIFY_HERSTELLER_WURZEL")
    MODUL=$(cd "$HERE" && go list -m)
    WURZEL_LDFLAG="-X $MODUL/internal/vfy.BuiltinVendorRoot=$WURZEL_WERT"
fi

build_all() {
    outdir=$1
    for t in $TARGETS; do
        goos=${t%/*}
        goarch=${t#*/}
        ext=""
        [ "$goos" = "windows" ] && ext=".exe"
        out="$outdir/ledger-verify_${goos}_${goarch}${ext}"
        (cd "$HERE" && CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOFLAGS=-mod=mod \
            go build -trimpath -ldflags "-s -w -buildid= $WURZEL_LDFLAG" \
            -o "$out" ./cmd/ledger-verify)
    done
}

{
    echo "ledger-verify (LEDGER) reproducible build — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "go: $(go version)"
    echo "targets: $TARGETS"
    echo "vendor root compiled in: ${WURZEL_WERT:-none (auditor passes --vendor-root / --vendor-key)}"
    echo

    B1=$(mktemp -d)
    B2=$(mktemp -d)
    trap 'rm -rf "$B1" "$B2"' EXIT

    echo "build 1 -> $B1"
    build_all "$B1"
    echo "build 2 -> $B2"
    build_all "$B2"
    echo

    ok=1
    for f in "$B1"/*; do
        base=$(basename "$f")
        s1=$(sha256sum "$f" | cut -d' ' -f1)
        s2=$(sha256sum "$B2/$base" | cut -d' ' -f1)
        if [ "$s1" = "$s2" ]; then
            echo "REPRODUCIBLE  $base  $s1"
            cp "$f" "$DIST/$base"
        else
            echo "MISMATCH      $base  build1=$s1 build2=$s2"
            ok=0
        fi
    done
    echo
    if [ "$ok" = 1 ]; then
        echo "result: all targets byte-identical across two independent builds"
    else
        echo "result: REPRODUCIBILITY FAILURE (see mismatches above)"
    fi
    [ "$ok" = 1 ]
} 2>&1 | tee "$LOG"

# preserve failure exit status through the pipe
grep -q "REPRODUCIBILITY FAILURE" "$LOG" && exit 1 || exit 0
