# LEDGER verifier

[Deutsch](README.de.md)

The open specification, test vectors and two independent verifiers for
LEDGER evidence chains (LEDGER was formerly named "Rekorder"; the vendor is
LOUWIETEC). With the files in this repository, anyone can check a LEDGER
verification package ("Prüfpaket") by themselves. It works offline, without the
vendor's involvement, without an account and without any secret.

| Path | Content |
|---|---|
| `spec/` | the normative specification (`format.en.md`, `format.de.md`, spec_version 1.10), the machine-readable registry `registry.json`, JSON schemas and the test vectors |
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
V=1.1.0-entwurf        # the release version
P=linux_amd64      # or linux_arm64, darwin_amd64, darwin_arm64
R=https://github.com/louwietec/ledger-verify/releases/download/v$V
for f in SHA256SUMS SHA256SUMS.sig allowed_signers ledger-verify_${V}_$P ledger-verify_${V}_source.tar.gz; do
  curl -fsSLO "$R/$f"
done

# 1) fingerprint of the signing key: compare it with the published one
awk 'NR==1{print $3, $4}' allowed_signers > release.pub && ssh-keygen -lf release.pub

# 2) signature over SHA256SUMS, checked against the key from step 1 and never against
#    the shipped allowed_signers (a line there can show one key and have another checked);
#    expected: Good "file" signature for release@louwietec.com with ED25519 key <fingerprint from step 1>
printf '%s namespaces="file" %s\n' release@louwietec.com "$(cat release.pub)" > checked_allowed_signers
ssh-keygen -Y verify -f checked_allowed_signers -I release@louwietec.com -n file -s SHA256SUMS.sig < SHA256SUMS

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
bash tools/pruefen.sh <directory> <allowed_signers line published by the vendor, saved as a file> SHA256:<published fingerprint>
```

`tools/pruefen.sh` is in this repository and in the source archive, and it is
short enough to read before you run it. Its last line is
`ERGEBNIS: GRUEN` or `ERGEBNIS: ROT`, followed by the details. Even one changed byte in
`SHA256SUMS`, in the signature or in any release file makes it RED.

### Windows (PowerShell)

```powershell
$V = "1.1.0-entwurf"
$R = "https://github.com/louwietec/ledger-verify/releases/download/v$V"
foreach ($f in "SHA256SUMS", "SHA256SUMS.sig", "allowed_signers",
               "ledger-verify_${V}_windows_amd64.exe", "ledger-verify_${V}_source.tar.gz") {
  Invoke-WebRequest -Uri "$R/$f" -OutFile $f
}

# 1) fingerprint of the signing key: compare it with the published one
$k = (Get-Content allowed_signers -TotalCount 1).Split(" ")
"$($k[2]) $($k[3])" | Set-Content -Encoding ascii release.pub
ssh-keygen -lf release.pub

# 2) signature, checked against the key from step 1 (never against the shipped
#    allowed_signers); run through cmd so that SHA256SUMS reaches ssh-keygen byte for byte
[IO.File]::WriteAllText("$PWD\checked_allowed_signers", "release@louwietec.com namespaces=`"file`" $($k[2]) $($k[3])`n")
cmd /c "ssh-keygen -Y verify -f checked_allowed_signers -I release@louwietec.com -n file -s SHA256SUMS.sig < SHA256SUMS"

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

After its summary lines the report on `valid_sealed_export` shows three
blocks: the vendor log and the anchor history ("not supplied", since the
example passes neither) and the evidence level, here "2 of 3
(countersigned)" with the note that it rests on a published test key.
Section 3 explains these blocks.

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
| `--now RFC3339` | the check time, UTC with `Z` (e.g. `2026-01-01T12:00:00Z`); default is the system clock |
| `--freshness DUR` | the freshness window for `TRAILING_SILENCE` (spec 8.5, 10.8): a whole number from 1 to 999999 directly followed by `h`, `m` or `s`, e.g. `24h` or `90m`; default `24h`; at most once |
| `--vendor-root FILE` | the vendor's root key `{"wurzel_id", "pubkey"}` (spec 7.1, 10.7); repeatable |
| `--vendor-key ID=HEX` | pins a vendor countersigning key (spec 7.1, 10.7.4); repeatable |
| `--vendor-key-list FILE` | a key list of the vendor: role list, protocol key list or list of countersigning keys (spec 10.7, 7.4.7); repeatable |
| `--vendor-statement-key ID=HEX` | pins a statements key, the key of the anchor history pages (spec 8.8.3, 10.7.4); repeatable |
| `--vendor-log-key ID=HEX` | pins a protocol key of the vendor log (spec 7.4.10); repeatable |
| `--vendor-log FILE` | an extract `ledger-protokollauszug/1` of the vendor log (spec 7.4.8); repeatable |
| `--anchor-history FILE` | pages `ledger.anchor_history.v2` or a file `ledger-ankerhistorie/2` (spec 8.8.2); repeatable |
| `--requested-at RFC3339` | when you requested the package (spec 8.8.1, 10.8); at most once |
| `--expect-root [TREE_SIZE:]ROOT` | an expected Merkle root, 64 hex characters, optionally with its `tree_size` (spec 7.2, 8.6, 10.8); repeatable |
| `--tsa-root FILE` | PEM roots for time witnesses of the chain (spec 7.3, 10.8); repeatable; the system root store counts for no purpose |
| `--vendor-log-tsa-root FILE` | PEM roots for the time stamps of the vendor log (spec 7.4.6, 10.8); repeatable |
| `--tsa-qualified-roots FILE` | your file `ledger-tsa-qualifiziert/1` of roots you name as qualified (spec 10.8); at most once |

**How a call is written** (from verifier 1.1.0). Every flag stands before
the package and is written with two dashes; `--` ends the flags. A flag
without a value (`--json`, `--now-from-package`) takes none; a flag with a
value takes it as `--lang de` or `--lang=de`, and the value is the next
argument even if it begins with a dash. A package whose name begins with a
dash stands after `--`. Any other form, such as `-json`, `--json=true`, a
flag or a `--` after the package, an abbreviation or an unknown flag, is an
unusable invocation: exit 3, the reason on the error output, no report
(spec 10.8). It is exit 3 as well when the output cannot be written, for
instance to a full disk. A file for which the specification names no limit
(PEM roots, the vendor root) is read up to 33,554,432 bytes; a larger one
is exit 3 too. verifier2 (section 6) reads every call the same way, and the
report language is `en` in both unless you pass `--lang de`.

`--help` (or `-h`) lists every flag on the error output and ends with exit 3,
a usage error under spec 10.8. `--version`, as the one argument,
names the version and the specification the verifier implements; its second
line states whether a vendor root is compiled into the binary. `ledger-verify
zeitstempel --token FILE (--data FILE | --statement-jcs FILE) [--tsa-root
FILE]...` checks a single RFC 3161 time-stamp token against roots you pass
(spec 7.5); it follows the same rules for its flags.

### What the verifier checks from specification 1.10

Besides the chain itself (hash chaining, Merkle tree, signatures, gaps,
chain end), the verifier checks what you hand to it from outside the package:

- **Key roles** (spec 10.7.2 to 10.7.4). The vendor signs with keys of three
  roles: countersigning keys for receipts, statements keys for the pages of
  the anchor history, protocol keys for the vendor log. The signed role list
  `ledger-schluesselrollen/1` names them. A key of one role never establishes
  an object of another, and the report lists the roles under `key_roles`.
- **Vendor log** (spec 7.4). For every closed UTC day the vendor commits with
  a signed day entry to all its countersignatures and gap witnesses, and
  time-stamping authorities witness that entry. With your extracts the
  verifier shows whether each receipt of the package stands in a witnessed
  day (`RECEIPT_NOT_LOGGED` if not) and whether a root recorded there
  contradicts the package (`LOGGED_ROOT_MISMATCH`).
- **Anchor history and affiliation** (spec 8.8). The vendor's signed pages
  name every root of the chain it countersigned, recorded as a gap witness or
  received in a report from the appliance. With the request time you pass,
  every root recorded more than 15 minutes before your request becomes an
  expected root: if the package lacks it or contradicts it, the verifier
  reports `MERKLE_INCONSISTENT` (exit 2), for a root the vendor merely
  received in a report `ANCHOR_HISTORY_FORK` (exit 1). The same pages carry
  the vendor's signed statement whether a customer of the chain is
  affiliated with it (heartbeat specification §9.10). The verifier checks
  signature, form, binding to chain and device and freshness of that
  statement, not whether it is true (no evidence produced by LEDGER).
- **Evidence level 0 to 3** (spec 10.9). It summarises which anchors the
  verifier could confirm with your inputs and up to which `seq` they reach:
  0 self-statement, 1 externally bound (a time witness or an expected root),
  2 countersigned (a receipt under a key your anchor confirms), 3 anchored and
  reconciled (in addition a time stamp of an authority you named as qualified,
  receipts shown in witnessed days of the vendor log, and completeness from an
  anchor history issued after your request). The report names what is
  missing for the next level and the switch that would pass it. The evidence
  level is not a finding, never changes the exit code and is not a legal
  classification.

Without these inputs each of the blocks reads "not supplied" or "not
checked" and adds no finding.

### Passing the auditor inputs (spec 10.8)

None of these inputs comes from the package, and you take none of them from
the audited site: fetch them yourself from the vendor's two places of
publication, from its metadata server or from the operator of each
time-stamping authority, and note when you requested the package. The
auditor's guide, section 10, names where each one comes from. The verifier
reads every input before it opens the package; an input that violates its
grammar is an unusable invocation (exit 3 with the reason, no report).

```sh
./ledger-verify_${V}_$P --json \
  --vendor-root herstellerwurzel.json \
  --vendor-key-list rollenliste.json --vendor-key-list keys.json \
  --anchor-history seite-0.json --anchor-history seite-1.json \
  --vendor-log auszug.json \
  --vendor-log-tsa-root log-tsa.pem --tsa-root chain-tsa.pem \
  --tsa-qualified-roots qualifiziert.json \
  --requested-at 2026-11-02T09:30:00Z \
  pruefpaket.zip > findings.json
```

Leave out what you do not have; the report names every missing input. In
the JSON output the results are under `stats.key_roles`, `stats.vendor_log`,
`stats.anchor_history`, `stats.affiliation` and `stats.evidence_level`.

### Trust anchors: `--vendor-root` and `--vendor-key` (spec 7.1, 10.7)

A verification package is written by the very party that the vendor's
countersignatures are meant to bind. A vendor key taken from the package
therefore proves nothing on its own, and the trust anchor has to come from
**you**:

- `--vendor-root FILE` is the vendor's root key, published with the licence.
  Through the signed list `keys/vendor/schluesselliste.json` in the package,
  or through the key lists you pass, it vouches for the vendor's keys.
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

### Expected roots: `--expect-root` (spec 7.2, 8.6)

On its own, a package cannot prove that nothing came after its last entry.
Offline, an incomplete chain (exit 4) and a chain cut off directly after an
earlier seal look alike. The comparison is what gives certainty. From
specification 1.10 the anchor history with `--requested-at` does this for
every root the vendor recorded more than 15 minutes before your request. A root you know by
another route, such as one printed in a monthly report (paper anchor, spec
7.2), you pass with `--expect-root <merkle_root>` or
`--expect-root <tree_size>:<merkle_root>`. If the package lacks entries that
belong to it, the verifier reports `MERKLE_INCONSISTENT` (exit 2). Run the
comparison for sealed chains too. verifier2 takes both forms as well.

### Honest limits

The verifier proves no more than its inputs carry. Entries after the last
countersigned checkpoint (the residual window) are not yet anchored and
never reach level 3. Whether a vendor root, a pinned key or a root of a
time-stamping authority really comes from outside the audited site, the
verifier cannot tell; the report names the fingerprints the level rests on.
If vendor and customer act together, they can issue an anchor history to
match a truncated chain. The statement on affiliation is the vendor's own,
and fetching history and log tells the vendor which chain is checked when.
The chain shows existence, time, order and integrity, not that the content
of a call was right. Specification section 11.2 states every limit in full.

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
the verification package onto the page.

Under "Further inputs" ("Weitere Prüfangaben" on the German page) you choose
the auditor inputs of section 3 as files or fields, with the same rules as on
the command line: the vendor root, key lists including the role list, pinned
keys, anchor history files, vendor log extracts, PEM roots for time witnesses
and for the time stamps of the vendor log, your file of roots named qualified,
expected roots, the check time and the request time. An input that violates
its grammar yields an error message instead of a verdict. Below the verdict
the page then shows two lines: the evidence level with its reach (for example
"Evidence level: 2 of 3, evidenced up to seq 309 of 311") and the status of
the affiliation with the vendor. The colour of the verdict stays bound to the
exit code; the evidence level colours nothing (spec 10.10.3). Whoever embeds
the page passes the same inputs as options (spec 10.8).

The package and the inputs never leave your computer, and the page loads
nothing and sends nothing; it does not fetch the inputs either, you download
them beforehand. You can check this yourself; every line should print 0:

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
repository's CI runs it on every change. verifier2 takes the auditor inputs of
section 3 under the same switch names and reads every call as `ledger-verify` does
(section 3). It has one switch of its own, `--registry FILE`: the
registry it reads, by default `spec/registry.json` beside it. That switch
is no auditor input and changes no rule of the specification;
`ledger-verify` carries the registry built in and refuses the switch.

```sh
python3 verifier2/verifier2.py --now-from-package \
  --vendor-root spec/testvectors/pruefer_herstellerwurzel.json \
  --vendor-key "$(cat spec/testvectors/pruefer_herstellerschluessel.txt)" \
  spec/testvectors/valid_sealed_export
```

## 7. Specification and test vectors

- `spec/format.en.md` / `spec/format.de.md`: the chain format, the
  verification procedure, the exit codes, the finding classes, the attacker
  model and the limits of proof (section 11.2). `spec/registry.json` is the
  machine-readable reference and prevails if the two diverge.
- `spec/heartbeat.*.md`: the messages between the appliance and the vendor's
  server (activation, heartbeat, anchor) and, from specification 1.10, what
  the vendor publishes for auditors: the anchor history with the statement on
  affiliation, the vendor log and its two places of publication.
- `spec/pflichten.*.md`: the duty coverage table, which states which operator
  duties the chain supports with evidence. It is not legal advice.
- `spec/testvectors/`: the frozen test vectors, each with its expected
  verdict under `expected/<name>.json`. Every file is pinned in `PINS.sha256`,
  and `spec/testvectors/README.en.md` explains the corpus. The verdicts hold
  for the audit environment of the corpus (the test vendor's root and key,
  as in section 2). From specification 1.10 a vector can also carry an audit
  environment of its own, `pruefer_<name>.json` (`ledger-pruefumgebung/1`),
  with auditor inputs such as a vendor log extract or an anchor history; its
  expected file then also names exit code, finding classes and evidence level
  for that environment (member `auditor_inputs`). `tools/aequivalenz.sh`
  checks the verdicts of the corpus environment.

## 8. Rebuilding a release

```sh
tar -xzf ledger-verify_${V}_source.tar.gz && cd ledger-verify-$V
# The compiled-in vendor root as a file: wurzel_id and pubkey as on
# louwietec.com and on line 2 of --version of a release binary
printf '%s\n' '{"wurzel_id":"<wurzel_id>","pubkey":"<pubkey>"}' > ../herstellerwurzel.json
LEDGER_VERIFY_HERSTELLER_WURZEL=../herstellerwurzel.json bash tools/bauen.sh ../rebuild $V ledger-verify
cd ../rebuild && sha256sum -c --ignore-missing ../SHA256SUMS
```

The release binaries carry the vendor root compiled in. Without the root file
the binaries carry no compiled-in root and so have other checksums.

The build is reproducible with the same Go release (go1.24.7). A different
Go release yields different bytes, and `tools/bauen.sh` warns about that.

## 9. Licence

Apache License 2.0; see `LICENSE` and `NOTICE`. The LEDGER appliance and the
vendor's services are not part of this repository.

## 10. Reporting a vulnerability

See [SECURITY.md](SECURITY.md). Please do not open a public issue.
