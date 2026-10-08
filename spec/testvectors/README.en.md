# Test Vectors

**Rekorder Specification · spec_version 1.9 · Language: English (German version: `README.de.md`, identical structure)**

The canonical list of all vectors and their expectations is `spec/registry.json`, section `testvectors`. CI checks registry × existing files as a complete matrix; the yardstick is the registry, not whatever files happen to exist.

## 1. Purpose

The test vectors are the **shared contract** between the chain writer (appliance) and all verifiers: the free Go verifier and the independent Python second verifier share no code; they share only the specification and these vectors. Each vector is a complete verification package with a fixed expected output; a verifier conforms to the specification exactly when it produces exactly the expected exit codes and finding classes across the whole corpus. The corpus covers:

- **valid chains** (including honestly declared findings: covered gaps, clock jump, deletion, reconciliation delta, missing anchor, stale end) and the **sealed chain end** (`valid_sealed_shutdown`, `valid_sealed_update_receipt`),
- **one manipulation class per negative vector** (rewriting, truncating, fork, clock, concealed silence; plus signature, receipt, handover, commitment and report breaks),
- **one gap class each** (`bypass`, `proxy_restart`, `power_loss`, `spool_unwritable`, `host_down`, `update`, `manual`),
- **the chain end** (group `end`, since specification 1.6, format specification Section 8.6): sealed but stale; incomplete because the last critical entry or the last `SEAL` lacks its immediate checkpoint; and the declared limit of proof of a truncation at an earlier seal (§5, §6),
- **the deletion hold** (group `hold`, since specification 1.7, format specification Sections 4.24 and 9.3): a deletion outside the scope of an active hold, a deletion after the hold was released and a deletion despite an active hold (`HOLD_VIOLATION`, §7),
- **the licence commitment** (group `license`, since specification 1.8, format specification Section 4.1): `GENESIS` with the commitment, the `GENESIS` of an updated 1.7 appliance with the key in cleartext (notice, no finding) and a `GENESIS` of edition 1.8 with the key in cleartext (`FORMAT_ERROR`, §8),
- **format errors** (broken JSON, schema-violating package),
- **forward compatibility** (format specification Section 10.6): a package with a newer minor version (`format_newer_minor`, finding `SPEC_NEWER`), a package with an entry type unknown to this version (`format_unknown_event_type`, finding `UNKNOWN_ENTRY_TYPE`) and a package with an unknown manifest field (`format_unknown_manifest_field`, finding `UNKNOWN_MANIFEST_FIELD`); not exit 3: the verifier keeps checking what it knows. All three end unsealed and carry `UNSEALED_END` alongside (exit 4).

This also nails down the exit semantics: an honestly declared gap does not invalidate the chain (exit 1, with an unsealed end exit 4), a concealed one does (exit 2). An unsealed end is not a manipulation finding but a status of its own (exit 4); "invalid" (exit 2) remains reserved for proven manipulation.

## 2. Directory layout

One directory per vector containing the files of a verification package; the expectation lives next to it under `expected/<name>.json`:

```
spec/testvectors/
├── README.de.md · README.en.md     # this document
├── PINS.sha256                     # SHA-256 pin per frozen vector file (§4)
├── pruefer_herstellerwurzel.json   # audit environment: the test vendor's root (§3)
├── pruefer_herstellerschluessel.txt  # audit environment: the pinned test key (§3)
├── expected/
│   └── <name>.json                 # expected output per vector (§3)
└── <name>/                         # one directory per vector = one complete verification package
    ├── manifest.json               # package manifest (registry: pruefpaket_manifest)
    ├── segments/*.jsonl            # chain segments (canonical JSON, one entry per line)
    ├── verify_args.json            # the vector's check time (`now`), only with --now-from-package
    └── …                           # per vector: receipts, public keys, presented plaintexts/salts, report hashes
```

Vector names (`valid_*`, `gap_*`, `end_*`, `hold_*`, `tamper_*`, `format_*`) and their expected values are exhaustively defined in the registry; this README deliberately does not enumerate them again. The exception are the eight vectors of specification 1.6 (§5), the three of specification 1.7 (§7), the three of specification 1.8 (§8) and the nine of specification 1.9 (§9): what they show does not follow from the name alone. Their tables state the registry's expected values, and `TestKettenendeTabelleFolgtDerErwartung`, `TestHoldTabelleFolgtDerErwartung` `TestLizenzTabelleFolgtDerErwartung` and `TestV19TabelleFolgtDerErwartung` (`appliance/cmd/vektorgen`) hold them against `expected/`.

## 3. Expected results (`expected/`)

Exactly one file `expected/<name>.json` per vector, for example `expected/end_sealed_stale.json`:

```json
{
  "exit_code": 1,
  "finding_classes": ["TRAILING_SILENCE"]
}
```

- `exit_code`: expected verifier exit code: `0` valid without findings, `1` valid with findings, `2` invalid, `3` format error, `4` incomplete: chain end not sealed (registry: `verifier.exit_codes`). What counts is the order of precedence 3 before 2 before 4 before 1 before 0 (registry: `verifier.exit_precedence`), not the size of the number.
- `finding_classes`: exact list of expected finding classes (registry: `verifier.finding_classes`); empty list for `exit_code` 0.

The expectation is **exact**, not "at least": both verifiers must produce exactly this exit code and exactly these finding classes.

**Audit environment (since specification 1.4).** The expectations hold for an auditor who brings two trust anchors (specification 7.1): the test vendor's root in `pruefer_herstellerwurzel.json` (`--vendor-root`) and its pinned key in `pruefer_herstellerschluessel.txt` (one `key_id=hex` per line, `--vendor-key`). Both files lie beside the vectors, not inside them, and are pinned too. Whoever checks without anchors additionally gets `RECEIPT_UNVERIFIED` on every vector with a receipt; that is the intended behaviour, not a fault of the corpus. One exception: `tamper_vendor_revoked` needs the root to see the list's contradiction at all; without anchors it yields only exit 4 `[RECEIPT_UNVERIFIED, UNSEALED_END]` instead of exit 2 `[NO_ANCHOR, RECEIPT_INVALID, UNSEALED_END]`. The three vendor vectors of 1.4 (`valid_vendor_list`, `tamper_vendor_key`, `tamper_vendor_revoked`) receipt under keys only the signed list in the package vouches for, or does not; every other vector with a receipt, the eight of 1.6 and the three of 1.7 included, receipts under `vendor-test-001` (pinned).

## 4. Freezing (`PINS.sha256`)

The cryptographically valid bytes of the vectors (real hash chains, Merkle roots, Ed25519 signatures and countersignatures with published test keys) are **produced by the ledger vector generator (work package P02)**; they cannot be crafted by hand. After generation, every vector file is pinned by SHA-256 in `PINS.sha256` and **never changed again**: CI compares the files against the pins on every run; any deviation is red. Until then only the target definitions under `expected/` exist; a vector counts as frozen and referenceable only once pinned. New requirements lead to **new** vectors (registry entry + new pin), never to changing frozen ones.

Every vector declares the `spec_version` it was frozen under as a literal, forever (`TestEingefroreneVersionenBleibenStehen`). Only `format_newer_minor` derives its version: by definition it must lie one minor version above the current one, so it is regenerated and re-pinned at every version bump, with specification 1.9 to `1.10`.

**One exception, written down rather than passed over.** The rule "never changed again" assumes the yardstick itself holds still. With the release of Section 6.2 rule 3 (the immediate checkpoint admits no exception and includes `SEAL`) that ceased to be true: the vectors `valid_update_handover` and `tamper_handover` chained `SEAL → RESUME` without the mandatory immediate checkpoint and thereby violated the very specification they are meant to be the yardstick for, and `valid_update_handover` was declared *valid* on top of that. Both were therefore regenerated and re-pinned; their target values under `expected/` stayed unchanged, because the expectation was never wrong, only the chain. That **only** these two vectors changed while the remaining 27 stayed byte-for-byte identical is proven by hash in `artefakte/P03/vektor_gegenprobe.log`, section [1]. A frozen vector is regenerated only when the released specification demonstrably refutes it; never to make a verifier go green.

**Second exception: specification 1.6 (chain end).** With the release of Section 8.6 every chain is also judged by how it ends, and all vectors frozen up to 1.5 end unsealed, like an export from a running installation. The expectations of the 38 frozen vectors that are not format errors therefore changed with the released specification 1.6: each additionally carries `UNSEALED_END`, exit 4 instead of 0 or 1; where a finding of exit class 2 already stood, it stays exit 2. Their **bytes** are unchanged, except `format_newer_minor`, which is regenerated at every version bump anyway (see above): the chains were never wrong, only the yardstick moved. This is the situation of the precedent of specification 1.1: there `format_unknown_event_type` lost the finding `SPEC_NEWER` in `expected/` because the verifier had reached the version the vector declares; the expectation followed the released edition, the bytes did not. With 1.6 only `format_newer_minor` was regenerated (then to `1.7`, see above); the eight vectors of §5 were added. Recomputable: `git show 6be9d7e:spec/testvectors/PINS.sha256 | grep -v ' format_newer_minor/' > /tmp/pins_1_5` and then `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_5`: 225 files (39 vector directories and the two files of the audit environment), no deviation.

**Specification 1.7 (deletion hold): no exception.** Edition 1.7 adds the finding `HOLD_VIOLATION`, and it arises only at a `LEGAL_HOLD`; none of the 48 older vectors carries one. Their expectations and their bytes therefore stay unchanged. Only `format_newer_minor` was regenerated (then to `1.8`, see above); the three vectors of §7 were added. Recomputable: `git show 66f0cc0:spec/testvectors/PINS.sha256 | grep -v ' format_newer_minor/' > /tmp/pins_1_6` and then `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_6`: 265 files (47 vector directories and the two files of the audit environment), no deviation.

**Specification 1.8 (licence commitment): no exception.** From 1.8 `GENESIS.license_id` must be the licence commitment, but only in a `GENESIS` whose own `spec_version` is 1.8 or newer (format specification 4.1). Every older vector declares an older edition and carries `LIC-TEST-0001` in cleartext; the verifiers print a notice for it, not a finding. Their expectations and their bytes therefore stay unchanged. Only `format_newer_minor` was regenerated (then to `1.9`, see above; its `GENESIS` carries the commitment since); the three vectors of §8 were added. Recomputable: `git show a3a0147:spec/testvectors/PINS.sha256 | grep -v '^#' | grep -v ' format_newer_minor/' > /tmp/pins_1_7` and then `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_7`: 280 files (50 vector directories and the two files of the audit environment), no deviation.

**Specification 1.9 (export seal, late checkpoint, clarifications): no exception.** The new rules apply only at places no older vector contains: no export seal, no late immediate checkpoint more than 450 s away, no segment outside `segments/`, no file under `content/` other than complete presentations, no number outside ±(2^53−1). Their expectations and their bytes therefore stay unchanged. Only `format_newer_minor` was regenerated (now `1.10`); the nine vectors of §9 were added. Recomputable: `git show 2ff96ba:spec/testvectors/PINS.sha256 | grep -v '^#' | grep -v ' format_newer_minor/' > /tmp/pins_1_8` and then `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_8`: 295 files (53 vector directories and the two files of the audit environment), no deviation.

Section 8.7 of the format specification (capture commitment and gap start after a crash) binds the appliance, not the verifier: it produces no finding and changes no vector.

**Test keys from chains before 1.8 (decision of 2026-10-02): no exception for the bytes.** Every test key that a test or demo chain before 1.8 carried in cleartext has been replaced by a new one in tests, contract vectors, demo and example configuration. Every new one contains at least one of the characters I, L, O or U and so never has the form the LOUWIETEC Cloud issues (`LEDGER-` and four times four characters of Crockford base32). `LIC-TEST-0001` stays in the frozen corpus. It is not a license key and cannot become one: the grammar `^[A-Z0-9-]{19,29}$` (heartbeat specification 4.1) does not admit 13 characters, so an activation with it already fails on the form. The vectors before 1.8 are also the yardstick for chains of older versions staying readable (format specification 4.1). They are used for that alone, not as a demo and not as a template for new chains.

**Addendum on the vector `tamper_missing_checkpoint` (14 Sep).** The negative vector for `MISSING_CHECKPOINT` (exit 2) was pinned and exercised by both check jobs, because those enumerate `expected/`, but it was not listed in `spec/registry.json`; `.ci/check_registry_matrix.py` therefore counted 29 vectors instead of 30 and checked only the direction registry → files. Both are fixed: the entry is in the registry, and the matrix check runs in both directions; a vector directory or an `expected/` file without a registry entry has been red ever since (red proof: `artefakte/P01/redproof_registry_beidseitig.log`).

## 5. Chain end (specification 1.6)

A chain is sealed if its last entries are a `SEAL`, directly its immediate checkpoint and after that at most receipts on exactly that checkpoint, whatever the `reason` (format specification 8.6). Every other chain is incomplete: finding `UNSEALED_END`, exactly once, at the `seq` of the last entry, exit 4; also alongside findings of exit class 2. The eight vectors of edition 1.6 declare `spec_version` `1.6` and build on the corpus's one-hour standard chain (GENESIS, two AI calls, 5-minute cadence, half-hourly receipts under `vendor-test-001`; `end_truncated_at_seal` see §6). They carry no defect other than the one they are named after, that is, no silence beyond the tolerance, no missing immediate checkpoint before the end, no receipt whose signature does not hold (`TestKettenendeVektoren`):

| Vector | Chain end | Exit | Findings |
|---|---|---|---|
| `valid_sealed_shutdown` | `SEAL(shutdown)` + immediate checkpoint; checked 2 min after the last entry | 0 | - |
| `valid_sealed_update_receipt` | `SEAL(update)` + immediate checkpoint + a receipt on exactly that checkpoint | 0 | - |
| `end_sealed_stale` | sealed like `valid_sealed_shutdown`, but checked 25 h after the last entry: the seal does not prove it is the most recent one (8.5) | 1 | `TRAILING_SILENCE` |
| `end_unsealed_bare_critical` | last entry an `OVERSIGHT` (critical) without its immediate checkpoint: the writer died before it; no longer `MISSING_CHECKPOINT` (6.2) | 4 | `UNSEALED_END` |
| `end_unsealed_bare_seal` | last entry a `SEAL(shutdown)` without its immediate checkpoint: no seal | 4 | `UNSEALED_END` |
| `end_truncated_at_seal` | honest chain with a mid-chain handover, cut directly behind the `SEAL`'s immediate checkpoint: the limit of proof (§6) | 0 | - |
| `tamper_seal_then_entry` | `SEAL(shutdown)` + immediate checkpoint, then a `TICK` without `RESUME` (within the silence tolerance) | 2 | `HANDOVER_BROKEN`, `UNSEALED_END` |
| `tamper_sealed_rewrite` | sealed chain, one `AI_CALL` rewritten after hashing (technique of `tamper_rewrite`); the end is sealed, so no `UNSEALED_END` | 2 | `HASH_MISMATCH` |

A verifier of edition 1.5 or older does not know exit 4 and reports a chain sealed with `update` or `shutdown` as `HANDOVER_BROKEN` (up to 1.5 only `decommission` and `key_loss` closed a chain regularly), and a critical end without checkpoint as `MISSING_CHECKPOINT`; on these eight vectors it is thus stricter than 1.6 throughout. On an incomplete chain, however (any of the 38 older vectors, for instance), it is milder: it reports exit 0 or 1 where 1.6 reports exit 4 (8.6, "Older verifiers"). In addition it reports `SPEC_NEWER`, since the vectors declare `1.6`.

## 6. Limit of proof: `end_truncated_at_seal`

The honest chain behind the vector: GENESIS, two AI calls, cadence up to 00:30 with a receipt at 00:30:01; at 00:32 `SEAL(shutdown)` and 500 ms later its immediate checkpoint; after a 90 s pause `RESUME` with the `SEAL`'s `entry_hash`, its checkpoint, cadence on to 01:30 with receipts at 01:00:01 and 01:30:01, 47 entries in total. The package ends after entry 19, the `SEAL`'s immediate checkpoint; `manifest.json` (`tree_size` 19) and the segment hash match the cut chain, no key was needed. The check time is 2 min after the end of the **uncut** chain (`verify_args.json`: `2026-01-01T01:32:01.000Z`), i.e. when an auditor actually checks. The package then lies an hour back, inside the freshness window.

**Expectation without the comparison: exit 0, no findings.** The package alone cannot refute the truncation (format specification 8.6, 11.2). This is not a fault of the verifier but the declared limit: the immediate checkpoint of a `SEAL` that a `RESUME` follows carries no receipt before the `RESUME` (8.4, clarification 2), so every earlier handover is a point at which a truncated chain appears sealed without any key.

**The comparison that reveals the truncation with certainty.** The most recent root the vendor countersigned for this chain is that of the last receipt of the uncut chain: `tree_size` = 45, `merkle_root` = `89495c09e4fff767882017bfb73e5b26ef17637111bbad7e09034445e0807cd5`, `server_ts` = `2026-01-01T01:30:01.000Z` (receipt on the checkpoint with `seq` 46). If the auditor passes it as expected root, the package lacks entries the vendor has already countersigned: `MERKLE_INCONSISTENT`, exit 2.

Go verifier (expects the root only; it must occur as a prefix root of the chain):

```
cd verifier && go build -o /tmp/ledger-verify ./cmd/ledger-verify && cd ..
/tmp/ledger-verify --now-from-package \
  --vendor-root spec/testvectors/pruefer_herstellerwurzel.json \
  --vendor-key "$(head -1 spec/testvectors/pruefer_herstellerschluessel.txt)" \
  --expect-root 89495c09e4fff767882017bfb73e5b26ef17637111bbad7e09034445e0807cd5 \
  spec/testvectors/end_truncated_at_seal
```

Second verifier (expects `tree_size:merkle_root`):

```
python3 verifier2/verifier2.py --now-from-package \
  --vendor-root spec/testvectors/pruefer_herstellerwurzel.json \
  --vendor-key "$(head -1 spec/testvectors/pruefer_herstellerschluessel.txt)" \
  --expect-root 45:89495c09e4fff767882017bfb73e5b26ef17637111bbad7e09034445e0807cd5 \
  spec/testvectors/end_truncated_at_seal
```

Both report `MERKLE_INCONSISTENT`, exit 2: the Go verifier because the root matches no prefix root of the 19 entries, the second verifier because `tree_size` 45 exceeds the 19 entries present. The values are not a transcript: `TestKuerzungAmSiegel` recomputes them from the generator's uncut chain and holds this README against them; `TestKuerzungAmSiegelImVerifier` runs the comparison through the Go verifier, with a control (the package's own receipted root yields no `MERKLE_INCONSISTENT`).

## 7. Deletion hold (specification 1.7)

Only vault content is deleted, never chain entries; every deletion stands in the chain as `CONTENT_DELETED` (format specification 9.3). A hold (`LEGAL_HOLD`, 4.24) is active from its `set` until a `release` with the same `hold_id`. It covers an `AI_CALL` whose `ts_captured` lies between `scope_from` and `scope_to`, both bounds inclusive, compared as points in time. A `CONTENT_DELETED` whose `target_seq` names an `AI_CALL` that an active hold covers at its position is the finding `HOLD_VIOLATION`, at the `seq` of the `CONTENT_DELETED`, with `hold_id` and `target_seq`. Exit class 1, not 2: the deletion stands openly in the chain, nothing is concealed (8.6).

The three vectors of edition 1.7 declare `spec_version` `1.7` and are **sealed** (ending like `valid_sealed_shutdown`: `SEAL(shutdown)` at 01:01 and its immediate checkpoint, checked 2 min later) so that their verdict shows the hold rule alone and no `UNSEALED_END` stands beside it. Common start: GENESIS, three AI calls with content (`mode` `full`, `vault_ref`) at 00:01, 00:02 and 00:03 (`seq` 3, 4, 5), at 00:04 `LEGAL_HOLD` `set` with `hold_id` `LH-2026-001` (`seq` 6) and its immediate checkpoint. At 00:42 the retention job (`reason` `retention`, `actor` `system:aufbewahrung`) deletes one call, followed 500 ms later by the immediate checkpoint. Cadence and half-hourly receipts under `vendor-test-001` as in §5; no other defect (`TestHoldVektoren`, which recomputes each vector's hold situation with its own reading of 9.3 and holds it against `expected/`):

| Vector | Hold and deletion | Exit | Findings |
|---|---|---|---|
| `hold_respected` | scope `2026-01-01T00:00:00.000Z` to `2026-01-01T00:02:59.999Z`, covering the calls `seq` 3 and 4. Deleted is `target_seq` 5 (`seq` 25), captured at 00:03:00.000, 1 ms outside; the hold stays active. The call was chained before the `set`: whoever reads the hold by `seq` instead of by `ts_captured` reports a false `HOLD_VIOLATION` here | 1 | `CONTENT_DELETED` |
| `hold_released` | scope as in `hold_respected`, `2026-01-01T00:00:00.000Z` to `2026-01-01T00:02:59.999Z`; at 00:22 `release` (`seq` 16) of the same `hold_id` with the same bounds; then deleted `target_seq` 3 (`seq` 27): covered, but no longer held | 1 | `CONTENT_DELETED` |
| `hold_violated` | scope from exactly the capture time of `seq` 3, `2026-01-01T00:01:00.000Z` (lower bound inclusive), to unbounded, `9999-12-31T23:59:59.000Z` (the "unbounded" value of 4.24); deleted `target_seq` 3 (`seq` 25) while the hold is active | 1 | `CONTENT_DELETED`, `HOLD_VIOLATION` |

The bounds are tight on purpose: `hold_respected` turns red for a verifier that ignores the scope or holds by `seq`; `hold_released` for one that ignores the release; `hold_violated` for one that excludes the lower bound or fails on the year 9999.

A verifier of edition 1.6 does not know `LEGAL_HOLD` (4.24): it reports `UNKNOWN_ENTRY_TYPE` (10.6 rule 2), plus `SPEC_NEWER` because the vectors declare `1.7`, and otherwise checks the chain in full (exit 1 with `CONTENT_DELETED`, `SPEC_NEWER`, `UNKNOWN_ENTRY_TYPE` on all three vectors). On `hold_violated` it is thus milder than 1.7: it does not see the broken hold. It does not demand the immediate checkpoint after `LEGAL_HOLD` (an unknown type is not critical for it); it is present all the same. Run with the Go verifier of state `66f0cc0` (edition 1.6) and the audit environment of §3.

## 8. Licence commitment (specification 1.8)

From edition 1.8 `GENESIS.license_id` carries the licence commitment (SHA-256 over the UTF-8 bytes of the licence key, lowercase hex), never the key (format specification 4.1). What counts is the `spec_version` of the `GENESIS` entry itself: a `GENESIS` of 1.8 or newer with another value is `FORMAT_ERROR`; an older one keeps what it carries and gets a notice (`genesis_license_not_commitment` in the JSON output of both verifiers), not a finding. The commitment of `LIC-TEST-0001` is `8d3ba2f4ded263ed0f5e27324951d2277063cf3ddc58f81e989b1cfbdb7a71d5`.

The three vectors of edition 1.8 are the corpus's one-hour standard chain (GENESIS, two AI calls, 5-minute cadence, half-hourly receipts under `vendor-test-001`), **sealed** at 01:01 with `SEAL(shutdown)` and its immediate checkpoint, checked 2 min later; their verdict shows the licence rule alone (`TestLizenzVektoren`, `TestKeinSchluesselAbFassung18`):

| Vector | GENESIS; other entries and manifest | Exit | Findings |
|---|---|---|---|
| `valid_genesis_commitment` | GENESIS `1.8` with the commitment; others `1.8` | 0 | - |
| `valid_genesis_upgraded` | GENESIS `1.7` with `LIC-TEST-0001` in cleartext, an appliance updated from 1.7 to 1.8; others `1.8`; the notice only | 0 | - |
| `format_genesis_license_cleartext` | GENESIS `1.8` with `LIC-TEST-0001` in cleartext; others `1.8` | 3 | `FORMAT_ERROR` |

`valid_genesis_upgraded` turns red for a verifier that applies the rule by the version of the manifest or of the latest entry instead of that of the `GENESIS`; the chain of every updated appliance would then be a format error. `format_genesis_license_cleartext` turns red for a verifier that does not apply the narrowing at all.

A verifier of edition 1.7 accepts all three: exit 1 with `SPEC_NEWER` alone, also on `format_genesis_license_cleartext` (milder than 1.8 there, it does not see the cleartext). This is intended: because the field name stays, 1.8 is no fleet break (format specification 10.6, rule 3). Run with both verifiers of state `154ef14` (edition 1.7) and the audit environment of §3.

The reference values for the vendor side of the licence (`license_proof`, licence statement, bound refusal, gap witnesses) are not verification packages and therefore do not live here but in `spec/contract/` (see its `README.en.md`).

## 9. Export seal, late checkpoint and clarifications (specification 1.9)

Ten vectors of edition 1.9 declare `spec_version` `1.9`. They build on the one-hour standard chain (GENESIS, two AI calls, the first with content, 5-minute cadence, half-hourly receipts under `vendor-test-001`) and end, where the seal is not itself the subject, with `SEAL(shutdown)` at 01:01 and its immediate checkpoint (`TestV19Vektoren`):

| Vector | Shape | Exit | Findings |
|---|---|---|---|
| `valid_sealed_export` | the package ends at 01:01 with `SEAL(export)` and its immediate checkpoint: an orderly export from running operation (format specification 8.6) | 0 | - |
| `valid_export_handover` | at 00:30:30 `SEAL(export)`, immediate checkpoint, `RESUME`, checkpoint a millisecond apart, as the writer writes them in one go on an export (8.4) | 0 | - |
| `gap_late_checkpoint_restart` | `OVERSIGHT` at 00:21, crash before its immediate checkpoint; the restart at 00:31 writes the checkpoint late (`mono_delta_ms` −1), then `RESTART` (outage 600,000 ms) and `GAP` from the critical entry on (8.2 condition 4) | 1 | `COVERED_GAP` |
| `gap_late_seal_checkpoint` | `SEAL(update)` at 00:30:30, crash before its immediate checkpoint; the restart ten minutes later writes it late (`mono_delta_ms` −1), then `RESUME` (8.2 condition 3) | 0 | - |
| `gap_late_seal_checkpoint_end` | `SEAL(shutdown)` at 01:01, crash before its immediate checkpoint; the restart at 01:11 writes it late (`mono_delta_ms` −1), nothing after that: the restart's `RESUME` was never written (8.2 condition 3: an honest chain is never invalid) | 0 | - |
| `tamper_late_checkpoint_stalled` | the same silence after `OVERSIGHT` at 00:21, but without a restart: the checkpoint comes ten minutes later with `mono_delta_ms` ≥ 0, no `RESTART`, no `GAP` | 2 | `CONCEALED_SILENCE` |
| `tamper_content_unpaired` | under `content/` a presented plaintext for the first AI call that contradicts its commitment, without a salt file (10.1) | 2 | `CONTENT_MISMATCH` |
| `format_segment_path` | the manifest names the segment `../chain-000001.jsonl`; the file lies next to `manifest.json` instead of under `segments/` (10.1) | 3 | `FORMAT_ERROR` |
| `format_int_range` | a `TICK` with `uptime_s` = 2^53 (Section 2) | 3 | `FORMAT_ERROR` |
| `format_unknown_type_broken_line` | the first `TICK` is not valid JSON (closing brace missing), a `FUTURE_NOTE` follows (10.5, 10.6 rule 2) | 3 | `FORMAT_ERROR`, `UNKNOWN_ENTRY_TYPE` |

`valid_sealed_export` also shows the accepted limit of proof: a package that ends at an export seal looks exactly like a chain truncated behind that seal. The verifier therefore says for every package that without a countersigned root no statement about completeness is possible (format specification 8.6); with a root the vendor countersigned after 01:01 that the package does not contain, this becomes `MERKLE_INCONSISTENT`, as for `end_truncated_at_seal` (§6).

A verifier of edition 1.8 does not know the sealing reason `export` and reports `valid_sealed_export` and `valid_export_handover` as `FORMAT_ERROR` (exit 3), plus `SPEC_NEWER` (format specification 8.6, "Older verifiers"). On `gap_late_checkpoint_restart`, `gap_late_seal_checkpoint` and `gap_late_seal_checkpoint_end` it reports `CONCEALED_SILENCE` (exit 2), stricter than 1.9. `tamper_content_unpaired`, `format_segment_path`, `format_int_range` and `format_unknown_type_broken_line` were judged differently by the two verifiers up to 1.8 (verifier2 let the unpaired plaintext pass and knew no number bound, the Go verifier read the segment outside `segments/`, verifier2 lost the unknown-type signal beside the broken line).
