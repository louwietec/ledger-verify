# LEDGER verifier

[Deutsch](README.de.md)

The open specification, test vectors and two independent verifiers for
LEDGER evidence chains (LEDGER was formerly named "Rekorder"; the vendor is
LOUWIETEC). With the files in this repository, anyone can check a LEDGER
verification package ("Prüfpaket") by themselves. It works offline, without the
vendor's involvement, without an account and without any secret.

| Path | Content |
|---|---|
| `spec/` | the normative specification (`format.en.md`, `format.de.md`, spec_version 1.9), the machine-readable registry `registry.json`, JSON schemas and the test vectors |
| `verifier/` | the free verifier in Go (nothing but the standard library), as a command-line tool and as a single-file browser page |
| `verifier2/` | an independent second verifier in Python 3 (nothing but the standard library), written from the specification alone |
| `tools/` | `bauen.sh` (the reproducible build), `aequivalenz.sh` (both verifiers over all test vectors), `pruefen.sh` (checks a release the way a third party would) |

## 1. Download and check the signature

Each release on this repository's release page contains:

- `ledger-verify_<version>_<os>_<arch>`: the command-line verifier for `linux_amd64`, `linux_arm64`, `darwin_amd64`, `darwin_arm64` and `windows_amd64` (`.exe`);
- `ledger-verify_<version>.html`: the browser page (section 5);
- `ledger-verify_<version>_source.tar.gz`: this repository at the release tag, including the test vectors;
- `SHA256SUMS`: the SHA-256 checksums of all of the above;
- `SHA256SUMS.sig`: the vendor's OpenSSH signature over `SHA256SUMS` (namespace `file`);
- `allowed_signers`: the vendor's release key in OpenSSH format.

The signature is checked with `ssh-keygen`. It comes with the OpenSSH client
that Linux, macOS and Windows 10/11 already include. The client must be
OpenSSH 8.1 or newer (`ssh -V`).

**Above all, the fingerprint.** The key in `allowed_signers` must be the vendor's
release key. Compare its fingerprint with the one LOUWIETEC publishes on
louwietec.com and in the auditor's guide. Without this comparison, a valid
signature proves no more than that `SHA256SUMS` fits *some* key. The comparison is
what shows that it is the vendor's key.

### Linux and macOS

```sh
V=1.0.0            # the release version
P=linux_amd64      # or linux_arm64, darwin_amd64, darwin_arm64
R=https://github.com/louwietec/ledger-verify/releases/download/v$V
for f in SHA256SUMS SHA256SUMS.sig allowed_signers ledger-verify_${V}_$P ledger-verify_${V}_source.tar.gz; do
  curl -fsSLO "$R/$f"
done

# 1) fingerprint of the signing key: compare it with the published one
awk '{print $3, $4}' allowed_signers > release.pub && ssh-keygen -lf release.pub

# 2) signature over SHA256SUMS; expected: Good "file" signature for release@louwietec.com ...
ssh-keygen -Y verify -f allowed_signers -I release@louwietec.com -n file -s SHA256SUMS.sig < SHA256SUMS

# 3) checksums of the downloaded files (macOS: shasum -a 256 -c --ignore-missing SHA256SUMS)
sha256sum -c --ignore-missing SHA256SUMS

chmod +x ledger-verify_${V}_$P && ./ledger-verify_${V}_$P --version
```

On macOS, a file downloaded with `curl` carries no quarantine flag. A file
downloaded in a browser does, and it is removed with
`xattr -d com.apple.quarantine <file>`.

**All in one step.** Put all release files in one directory, and
`tools/pruefen.sh` runs steps 1 to 3 over every file. It then runs the
example chains of section 2 offline with the binary for your machine:

```sh
bash tools/pruefen.sh <directory> <directory>/allowed_signers SHA256:<published fingerprint>
```

`tools/pruefen.sh` is in this repository and in the source archive, and it is
short enough to read before you run it. Its last line is
`ERGEBNIS: GRUEN` or `ERGEBNIS: ROT`, followed by the details. Even one changed byte in
`SHA256SUMS`, in the signature or in any release file makes it RED.

### Windows (PowerShell)

```powershell
$V = "1.0.0"
$R = "https://github.com/louwietec/ledger-verify/releases/download/v$V"
foreach ($f in "SHA256SUMS", "SHA256SUMS.sig", "allowed_signers",
               "ledger-verify_${V}_windows_amd64.exe", "ledger-verify_${V}_source.tar.gz") {
  Invoke-WebRequest -Uri "$R/$f" -OutFile $f
}

# 1) fingerprint of the signing key: compare it with the published one
$k = (Get-Content allowed_signers -TotalCount 1).Split(" ")
"$($k[2]) $($k[3])" | Set-Content -Encoding ascii release.pub
ssh-keygen -lf release.pub

# 2) signature; run through cmd so that SHA256SUMS reaches ssh-keygen byte for byte
cmd /c "ssh-keygen -Y verify -f allowed_signers -I release@louwietec.com -n file -s SHA256SUMS.sig < SHA256SUMS"

# 3) checksums of the downloaded files
Get-Content SHA256SUMS | ForEach-Object {
  $h, $f = $_ -split "  ", 2
  if (Test-Path $f) {
    if ((Get-FileHash -Algorithm SHA256 $f).Hash -eq $h) { "OK      $f" } else { "FAILED  $f" }
  }
}

.\ledger-verify_${V}_windows_amd64.exe --version
```

## 2. Check the example chains offline

The source archive contains the test vectors and the trust anchors of the
**test** vendor. They are test keys and never a production vendor's keys. Two
example chains show both outcomes:

```sh
tar -xzf ledger-verify_${V}_source.tar.gz
TV=ledger-verify-$V/spec/testvectors
A="--vendor-root $TV/pruefer_herstellerwurzel.json --vendor-key $(cat $TV/pruefer_herstellerschluessel.txt)"
./ledger-verify_${V}_$P --now-from-package $A $TV/valid_sealed_export   # exit 0: valid, properly sealed
./ledger-verify_${V}_$P --now-from-package $A $TV/tamper_content_unpaired   # exit 2: CONTENT_MISMATCH
```

```powershell
tar -xzf "ledger-verify_${V}_source.tar.gz"
$TV = "ledger-verify-$V\spec\testvectors"
$K = Get-Content "$TV\pruefer_herstellerschluessel.txt" -TotalCount 1
.\ledger-verify_${V}_windows_amd64.exe --now-from-package --vendor-root "$TV\pruefer_herstellerwurzel.json" --vendor-key $K "$TV\valid_sealed_export"; $LASTEXITCODE
.\ledger-verify_${V}_windows_amd64.exe --now-from-package --vendor-root "$TV\pruefer_herstellerwurzel.json" --vendor-key $K "$TV\tamper_content_unpaired"; $LASTEXITCODE
```

`--now-from-package` is meant for the frozen test vectors alone. It takes the check
time from the package's own `verify_args.json`, a file that whoever presents
the package chooses. For a real package, leave it out (the system clock
applies) or pass `--now <RFC 3339>`.

**Offline.** The verifier needs no network and opens no connection. It reads
a package (a directory or a ZIP file) and prints a report. Copy the binary and
the package to a machine without a network, or disconnect before you start. On Linux,
`unshare -rn ./ledger-verify_${V}_$P …` runs it in a network namespace without a
network, and `tools/pruefen.sh` does exactly that where it can.

## 3. Running the verifier

```
ledger-verify [flags] <verification package: directory or ZIP>
```

| Flag | Effect |
|---|---|
| `--lang de\|en` | report language (default `en`) |
| `--json` | machine-readable output `{valid, status, exit_code, findings, stats}` |
| `--vendor-root FILE` | the vendor's root key `{"wurzel_id", "pubkey"}` (spec 7.1, 10.7); repeatable |
| `--vendor-key ID=HEX` | pins a single vendor countersigning key (spec 7.1); repeatable |
| `--expect-root HEX` | a 64-hex Merkle root that MUST occur in this chain (spec 7.2, 8.6) |
| `--tsa-root FILE` | PEM trust anchors for time witnesses (spec 7.3) |
| `--now RFC3339` | the check time; default is the system clock |
| `--freshness DUR` | the freshness window for `TRAILING_SILENCE` (default `24h`) |

`--help` lists every flag. `--version` names the version and the
specification the verifier implements. Its second line states whether a
vendor root is compiled into the binary.

### Trust anchors: `--vendor-root` and `--vendor-key` (spec 7.1, 10.7)

A verification package is written by the very party that the vendor's
countersignatures are meant to bind. A vendor key taken from the package
therefore proves nothing on its own, and the trust anchor has to come from
**you**:

- `--vendor-root FILE` is the vendor's root key, published with the licence.
  Through the signed list `keys/vendor/schluesselliste.json` in the package,
  it vouches for the vendor's countersigning keys.
- `--vendor-key ID=HEX` pins a single countersigning key that you obtained
  from the vendor yourself.

Without either, receipts are reported as `RECEIPT_UNVERIFIED` (exit 1). Their
signatures are consistent, but their key comes from the package.

**The release binaries carry LOUWIETEC's vendor root compiled in**; `--version`
names it on its second line. Check it independently of the binary: download
the root file and its fingerprint from louwietec.com (HTTPS) and pass the file
with `--vendor-root`. If it matches the compiled-in root, the verdict does not
change. If it differs, the verifier refuses to check (exit 3) instead of
picking one of the two (spec 7.1). A swapped binary therefore cannot slip its
compiled-in root past you.

### Comparison with the vendor's most recent countersigned root: `--expect-root` (spec 8.6)

On its own, a package cannot prove that nothing came after its last entry.
Offline, an incomplete chain (exit 4) and a chain cut off directly after an
earlier seal look alike. The comparison is what gives certainty. Ask the
vendor for the most recent root it has countersigned for the `chain_id` in
the report, then check again with `--expect-root <merkle_root>`. If the
package lacks entries that the vendor has already countersigned, the verifier
reports `MERKLE_INCONSISTENT` (exit 2). Run the comparison for sealed chains
too. The same flag takes a root printed in a monthly report (paper anchor,
spec 7.2). verifier2 takes it as `--expect-root TREE_SIZE:ROOT`.

## 4. Exit codes (spec 10.3)

| Exit | Meaning |
|---|---|
| 0 | valid, no findings |
| 1 | valid with findings |
| 2 | invalid |
| 3 | format error (also: an unusable invocation) |
| 4 | incomplete: chain end not sealed (spec 8.6) |

When several findings apply, the order of precedence decides: 3 before 2
before 4 before 1 before 0. The size of the number does not. Exit 0 and exit
1 require a sealed chain end. Exit 4 is not a failure: the entries present
are intact, and the package just does not prove that nothing came after them.
Exit 1 is a good result, because an honestly declared gap does not invalidate
a chain. A concealed gap does.

## 5. The browser page

`ledger-verify_<version>.html` is the same Go verifier compiled to WebAssembly, in a
single file. It is not a second implementation. Compare its checksum with
`SHA256SUMS`, open it by double-clicking (it works without a network) and drag
the verification package onto the page. Under "Weitere Prüfangaben" you
choose the vendor root and, if needed, the root certificate of a time-stamping
authority. The package never leaves your computer, and the page loads nothing
and sends nothing. You can check this yourself; every line should print 0:

```sh
for m in 'fetch(' XMLHttpRequest WebSocket sendBeacon EventSource importScripts; do
  printf '%-16s %s\n' "$m" "$(grep -c -F "$m" ledger-verify_${V}.html)"
done
```

## 6. verifier2: the independent second implementation

`verifier2/verifier2.py` is written in Python 3 with nothing but the standard
library. It was written from the specification alone and shares no code with the
Go verifier. `tools/aequivalenz.sh` runs both verifiers over every test
vector. It requires the expected verdict from each of them, with the same exit
code, finding classes, status and chain end, and it runs verifier2 in a
directory that contains nothing but `spec/` and `verifier2/`. This
repository's CI runs it on every change.

```sh
python3 verifier2/verifier2.py --now-from-package \
  --vendor-root spec/testvectors/pruefer_herstellerwurzel.json \
  --vendor-key "$(cat spec/testvectors/pruefer_herstellerschluessel.txt)" \
  spec/testvectors/valid_sealed_export
```

## 7. Specification and test vectors

- `spec/format.en.md` / `spec/format.de.md`: the chain format, the
  verification procedure, the exit codes, the finding classes, the attacker
  model and the limits of proof. `spec/registry.json` is the machine-readable
  reference and prevails if the two diverge.
- `spec/heartbeat.*.md`: the messages between the appliance and the vendor's
  server (activation, heartbeat, anchor).
- `spec/pflichten.*.md`: the duty coverage table, which states which operator
  duties the chain supports with evidence. It is not legal advice.
- `spec/testvectors/`: the frozen test vectors, each with its expected
  verdict under `expected/<name>.json`. Every file is pinned in `PINS.sha256`,
  and `spec/testvectors/README.en.md` explains the corpus.

## 8. Rebuilding a release

```sh
tar -xzf ledger-verify_${V}_source.tar.gz && cd ledger-verify-$V
bash tools/bauen.sh ../rebuild $V ledger-verify
cd ../rebuild && sha256sum -c --ignore-missing ../SHA256SUMS
```

The build is reproducible with the same Go release (go1.24.7). A different
Go release yields different bytes, and `tools/bauen.sh` warns about that.

## 9. Licence

Apache License 2.0; see `LICENSE` and `NOTICE`. The LEDGER appliance and the
vendor's services are not part of this repository.

## 10. Reporting a vulnerability

See [SECURITY.md](SECURITY.md). Please do not open a public issue.
