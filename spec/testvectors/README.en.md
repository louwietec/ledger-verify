# Test Vectors

**Rekorder Specification · spec_version 1.10 · Language: English (German version: `README.de.md`, identical structure)**

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
├── pruefer_<name>.json             # audit environment of a vector from 1.10 (ledger-pruefumgebung/1, §10)
├── pruefer_<name>.<member>-<n>.*   # the files it names (§10)
├── zeitstempel_<name>.*            # inputs of the single time-stamp check (§10.4)
├── zeitstempelstelle_e1.json       # certificates and tokens of the time-stamping authority E1 with discarded keys (§11.2)
├── zeitstempelstelle_e2.json       # certificates and tokens of the time-stamping authority E2 with discarded keys (§13.2)
├── zeitstempelstelle_e3.json       # certificates and tokens of the time-stamping authority E3 with discarded keys (§14.2)
├── protokoll/                      # reference case of a published vendor log (§11.4)
├── expected/
│   └── <name>.json                 # expected output per vector (§3)
└── <name>/                         # one directory per vector = one complete verification package
    ├── manifest.json               # package manifest (registry: pruefpaket_manifest)
    ├── segments/*.jsonl            # chain segments (canonical JSON, one entry per line)
    ├── verify_args.json            # the vector's check time (`now`), only with --now-from-package
    └── …                           # per vector: receipts, public keys, presented plaintexts/salts, report hashes
```

Vector names (`valid_*`, `gap_*`, `end_*`, `hold_*`, `tamper_*`, `format_*`, from 1.10 `roles_*`, `auditor_*`, `timestamp_*`, `log_*`, `history_*`, `evidence_*`) and their expected values are exhaustively defined in the registry; this README deliberately does not enumerate them again. The exception are the eight vectors of specification 1.6 (§5), the three of specification 1.7 (§7), the three of specification 1.8 (§8), the nine of specification 1.9 (§9), the 130 of the foundations of 1.10 (§10), the 89 of the vendor log (§11), the 115 of the anchor history (§12), the 26 of the evidence level (§13), the 16 on the decisions of 26.10. (§14) and the three packages from the alignment of both verifiers (§15): what they show does not follow from the name alone. Their tables state the registry's expected values, and `TestKettenendeTabelleFolgtDerErwartung`, `TestHoldTabelleFolgtDerErwartung` `TestLizenzTabelleFolgtDerErwartung` and `TestV19TabelleFolgtDerErwartung` (`appliance/cmd/vektorgen`) hold them against `expected/`.

## 3. Expected results (`expected/`)

Exactly one file `expected/<name>.json` per vector, for example `expected/end_sealed_stale.json`:

```json
{
  "exit_code": 1,
  "finding_classes": ["TRAILING_SILENCE"]
}
```

- `exit_code`: expected verifier exit code: `0` valid without findings, `1` valid with findings, `2` invalid, `3` format error, `4` incomplete: chain end not sealed (registry: `verifier.exit_codes`). What counts is the order of precedence 3 before 2 before 4 before 1 before 0 (registry: `verifier.exit_precedence`), not the size of the number.
- `finding_classes`: exact list of expected finding classes (registry: `verifier.finding_classes`); empty list for `exit_code` 0. The list is the set of the classes reported: a class that a verifier reports twice (for instance a finding on a day next to a run of missing days of the same class, as format specification 7.4.11 requires) appears in it once.

The expectation is **exact**, not "at least": both verifiers must produce exactly this exit code and exactly these finding classes.

**From specification 1.10** an expected file may also carry `evidence_level` (the evidence level with the audit environment of the corpus) and `auditor_inputs` (`null`, or file, exit code, finding classes and evidence level with the vector's audit environment `pruefer_<name>.json`) (registry `expected_files`); `evidence_level` names `state`, `level`, `up_to_tree_size`, the course as `[level, first_seq, last_seq]`, per condition the reason or `null`, the notes and the status of the affiliation. For an unusable invocation (exit 3 without a report, format specification 10.8) `auditor_inputs.evidence_level` is `null`: without a report there is no evidence level (10.9.2, 10.10.1); the object of state `format_error` stands only where a format error writes a report (`FORMAT_ERROR`). A vector without these members stays as it is.

**Audit environment (since specification 1.4).** The expectations hold for an auditor who brings two trust anchors (specification 7.1): the test vendor's root in `pruefer_herstellerwurzel.json` (`--vendor-root`) and its pinned key in `pruefer_herstellerschluessel.txt` (one `key_id=hex` per line, `--vendor-key`). Both files lie beside the vectors, not inside them, and are pinned too. Whoever checks without anchors additionally gets `RECEIPT_UNVERIFIED` on every vector with a receipt; that is the intended behaviour, not a fault of the corpus. One exception: `tamper_vendor_revoked` needs the root to see the list's contradiction at all; without anchors it yields only exit 4 `[RECEIPT_UNVERIFIED, UNSEALED_END]` instead of exit 2 `[NO_ANCHOR, RECEIPT_INVALID, UNSEALED_END]`. The three vendor vectors of 1.4 (`valid_vendor_list`, `tamper_vendor_key`, `tamper_vendor_revoked`) receipt under keys only the signed list in the package vouches for, or does not; every other vector with a receipt, the eight of 1.6 and the three of 1.7 included, receipts under `vendor-test-001` (pinned).

## 4. Freezing (`PINS.sha256`)

The cryptographically valid bytes of the vectors (real hash chains, Merkle roots, Ed25519 signatures and countersignatures with published test keys) are **produced by the ledger vector generator**; they cannot be crafted by hand. After generation, every vector file is pinned by SHA-256 in `PINS.sha256` and **never changed again**: CI compares the files against the pins on every run; any deviation is red. Until then only the target definitions under `expected/` exist; a vector counts as frozen and referenceable only once pinned. New requirements lead to **new** vectors (registry entry + new pin), never to changing frozen ones.

Every vector declares the `spec_version` it was frozen under as a literal, forever (`TestEingefroreneVersionenBleibenStehen`). Only `format_newer_minor` derives its version: by definition it must lie one minor version above the current one, so it is regenerated and re-pinned at every version bump, with specification 1.10 to `1.11`.

**One exception, written down rather than passed over.** The rule "never changed again" assumes the yardstick itself holds still. With the release of Section 6.2 rule 3 (the immediate checkpoint admits no exception and includes `SEAL`) that ceased to be true: the vectors `valid_update_handover` and `tamper_handover` chained `SEAL → RESUME` without the mandatory immediate checkpoint and thereby violated the very specification they are meant to be the yardstick for, and `valid_update_handover` was declared *valid* on top of that. Both were therefore regenerated and re-pinned; their target values under `expected/` stayed unchanged, because the expectation was never wrong, only the chain. That **only** these two vectors changed while the remaining 27 stayed byte-for-byte identical is proven by hash. A frozen vector is regenerated only when the released specification demonstrably refutes it; never to make a verifier go green.

**Second exception: specification 1.6 (chain end).** With the release of Section 8.6 every chain is also judged by how it ends, and all vectors frozen up to 1.5 end unsealed, like an export from a running installation. The expectations of the 38 frozen vectors that are not format errors therefore changed with the released specification 1.6: each additionally carries `UNSEALED_END`, exit 4 instead of 0 or 1; where a finding of exit class 2 already stood, it stays exit 2. Their **bytes** are unchanged, except `format_newer_minor`, which is regenerated at every version bump anyway (see above): the chains were never wrong, only the yardstick moved. This is the situation of the precedent of specification 1.1: there `format_unknown_event_type` lost the finding `SPEC_NEWER` in `expected/` because the verifier had reached the version the vector declares; the expectation followed the released edition, the bytes did not. With 1.6 only `format_newer_minor` was regenerated (then to `1.7`, see above); the eight vectors of §5 were added. Recomputable: `git show 6be9d7e:spec/testvectors/PINS.sha256 | grep -v ' format_newer_minor/' > /tmp/pins_1_5` and then `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_5`: 225 files (39 vector directories and the two files of the audit environment), no deviation.

**Specification 1.7 (deletion hold): no exception.** Edition 1.7 adds the finding `HOLD_VIOLATION`, and it arises only at a `LEGAL_HOLD`; none of the 48 older vectors carries one. Their expectations and their bytes therefore stay unchanged. Only `format_newer_minor` was regenerated (then to `1.8`, see above); the three vectors of §7 were added. Recomputable: `git show 66f0cc0:spec/testvectors/PINS.sha256 | grep -v ' format_newer_minor/' > /tmp/pins_1_6` and then `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_6`: 265 files (47 vector directories and the two files of the audit environment), no deviation.

**Specification 1.8 (licence commitment): no exception.** From 1.8 `GENESIS.license_id` must be the licence commitment, but only in a `GENESIS` whose own `spec_version` is 1.8 or newer (format specification 4.1). Every older vector declares an older edition and carries `LIC-TEST-0001` in cleartext; the verifiers print a notice for it, not a finding. Their expectations and their bytes therefore stay unchanged. Only `format_newer_minor` was regenerated (then to `1.9`, see above; its `GENESIS` carries the commitment since); the three vectors of §8 were added. Recomputable: `git show a3a0147:spec/testvectors/PINS.sha256 | grep -v '^#' | grep -v ' format_newer_minor/' > /tmp/pins_1_7` and then `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_7`: 280 files (50 vector directories and the two files of the audit environment), no deviation.

**Specification 1.9 (export seal, late checkpoint, clarifications): no exception.** The new rules apply only at places no older vector contains: no export seal, no late immediate checkpoint more than 450 s away, no segment outside `segments/`, no file under `content/` other than complete presentations, no number outside ±(2^53−1). Their expectations and their bytes therefore stay unchanged. Only `format_newer_minor` was regenerated (then to `1.10`); the nine vectors of §9 were added. Recomputable: `git show 2ff96ba:spec/testvectors/PINS.sha256 | grep -v '^#' | grep -v ' format_newer_minor/' > /tmp/pins_1_8` and then `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_8`: 295 files (53 vector directories and the two files of the audit environment), no deviation.

**Specification 1.10 (covered stretches, mail language): no exception.** What is new is a statement in the verifiers' report, not a finding: stretches between two countersigned checkpoints beyond the anchoring cadence (format specification 11.2). Added to it is the language of the vendor's mails (heartbeat specification). `expected/` names only the exit code and the finding classes; neither changes for any vector. Their expectations and their bytes therefore stay unchanged. Only `format_newer_minor` was regenerated (now `1.11`); no vector was added. Recomputable: `git show 6963364:spec/testvectors/PINS.sha256 | grep -v '^#' | grep -v ' format_newer_minor/' > /tmp/pins_1_9` and then `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_9`: 346 files (63 vector directories and the two files of the audit environment), no deviation.

**Specification 1.10 (foundations: key roles, auditor inputs, time-stamp profile): no exception.** Added are the 101 vectors of §10 with their audit environments `pruefer_<name>.json` and the inputs of the single time-stamp check (§10.4), all pinned; the generator writes them too. No frozen vector changed, neither in its bytes nor in its expectation. The new expected files also carry `evidence_level` and `auditor_inputs` (registry `expected_files`), and `published_test_keys` names three more keys of a time-stamping authority. Recomputable: `git show f37ad01b:spec/testvectors/PINS.sha256 > /tmp/pins_1_10` and then `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_10`: 355 files (64 vector directories and the two files of the audit environment), no deviation.

**Specification 1.10 (vendor log): no exception.** Added are the 63 vectors of the group `log` (§11) with their audit environments, six vectors of the groups `auditor` and `timestamp` (§10.2, §10.3) on readings of the time-stamp profile and of the grammar of the extract that the specification wrote down after the foundations, the inputs of the single time-stamp check for three of them (§10.4) and the reference case `protokoll/` (§11.4), all pinned. No frozen vector changed, neither in its bytes nor in its expectation. `published_test_keys` additionally names the two protocol keys of the test corpus. Recomputable: `git show 5e4e70bb:spec/testvectors/PINS.sha256 > /tmp/pins_1_10_grundlagen` and then `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_10_grundlagen`: 1075 files (165 vector directories and 217 files at the top level), no deviation.

**Specification 1.10 (witnessed days of the vendor log): no exception.** Added are the 26 vectors of the group `log` of the table "Witnessed days" (§11.3) with their audit environments, the certificates and tokens of the time-stamping authority E1 with discarded keys in `zeitstempelstelle_e1.json` (§11.2) and the second reference day `protokoll/zweiter_referenztag/` (§11.4), all pinned. No frozen vector has changed, neither in its bytes nor in its expectation. Unlike every other byte of the corpus, the tokens of E1 cannot be generated again: the generator reads them as a frozen input and stops if a regenerated statement no longer matches its token (§11.2). Recomputable: `git show 3605ad7d:spec/testvectors/PINS.sha256 > /tmp/pins_1_10_protokoll` and then `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_10_protokoll`: 1653 files (234 vector directories with 1203 files, 440 files at the top level and 10 files of the reference case), no deviation.

**Specification 1.10 (anchor history v2 and affiliation): no exception.** Added are the 110 vectors of the group `history` (§12) with their audit environments, all pinned. Five of them carry the package of another vector byte for byte under their own name (`history_reference_page` that of `valid_sealed_export`, the four vectors of step H7 those of `log_witnessed_included` and `log_witnessed_logged_roots`); the day objects of their extracts carry frozen tokens of E1, no new token was added. No frozen vector has changed, neither in its bytes nor in its expectation, and `published_test_keys` stays unchanged: every key of a page is a test key of the corpus. Recomputable: `git show ffffeadd:spec/testvectors/PINS.sha256 > /tmp/pins_1_10_bezeugt` and then `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_10_bezeugt`: 1872 files (260 vector directories with 1333 files, 525 files at the top level and 14 files of the reference case), no deviation.

**Specification 1.10 (anchor history: follow-ups from the comparison): no exception.** Added are five vectors of the group `history` (§12.4, §12.6) with their audit environments, all pinned: a merge across a gap with and without the mark `merged` (format specification 8.8.4 H5 (f)), a reason of H5 between pages of a linked predecessor chain (8.8.6 item 9) and a successor chain named by the page of the package, honest and with `succession_mismatch` (H5 in both directions). No frozen vector has changed, neither in its bytes nor in its expectation, and `published_test_keys` stays unchanged: every key of a page is a test key of the corpus. Recomputable: `git show 4d101f28:spec/testvectors/PINS.sha256 > /tmp/pins_1_10_ankerhistorie` and then `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_10_ankerhistorie`: 2790 files (370 vector directories with 1883 files, 893 files at the top level and 14 files of the reference case), no deviation.

**Specification 1.10 (evidence level and report members): no exception for the bytes.** Added are the 26 vectors of the group `evidence` (§13) with their audit environments and the certificates and tokens of the time-stamping authority E2 with discarded keys in `zeitstempelstelle_e2.json` (§13.2), all pinned. Twelve of them carry the package of a vector of the group `log` byte for byte under their own name (`evidence_qualified_root_in_package` with `keys/tsa/zeitstempelwurzel_e1.pem` in addition). No frozen vector has changed in its bytes, its exit code or its finding classes. Two expectations that are no findings have changed: the 52 expected files of an unusable invocation (exit 3 without findings with `pruefer_<name>.json`) now name `null` in `auditor_inputs.evidence_level` instead of the object of state `format_error`, since without a report there is no evidence level (format specification 10.9.2, 10.10.1, registry `expected_files`); and `valid_basic` also carries `evidence_level`, the example of format specification 10.10.2. `published_test_keys` stays unchanged: the keys of E2 are not published, every other key of the new vectors is a test key of the corpus. Recomputable: `git show b653130e:spec/testvectors/PINS.sha256 > /tmp/pins_1_10_beweisstufe` and then `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_10_beweisstufe`: 2836 files (375 vector directories with 1908 files, 914 files at the top level and 14 files of the reference case), no deviation.

**Specification 1.10 (condition (7) as the second way to level 3 and the other decisions of 26.10.): no exception for the bytes.** Added are the 15 vectors of §14 with their audit environments and the certificates and tokens of the time-stamping authority E3 with discarded keys in `zeitstempelstelle_e3.json` (§14.2), all pinned; they stand in the groups `valid`, `log`, `history` and `evidence`, each after the vectors that stood there before. Ten of them carry the package of a vector of the group `log` byte for byte under their own name. No frozen vector has changed in its bytes, its exit code or its finding classes. One expectation that is no finding has changed: with condition (7) as the second way to level 3 (format specification 10.9.1, 10.9.5), `evidence_qualified_window_from` and `evidence_qualified_root_in_package` reach level 3 up to 5 instead of level 2 up to 11 with their audit environment (`auditor_inputs.evidence_level`); their exit code and finding classes stay. `published_test_keys` stays unchanged: the keys of E3 are not published, every other key of the new vectors is a test key of the corpus. Recomputable: `git show 76a6b84e:spec/testvectors/PINS.sha256 > /tmp/pins_1_10_bedingung7` and then `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_10_bedingung7`: 3063 files (401 vector directories with 2042 files, 1007 files at the top level and 14 files of the reference case), no deviation.

**Specification 1.10 (alignment of both verifiers): no exception.** Added are 25 vectors on readings the specification wrote down so that both reference verifiers judge every input alike: 23 of the group `timestamp` (§10.3) with their audit environments and the inputs of the single check for six of them (§10.4), and `valid_receipt_r_identity` and `tamper_receipt_r_identity_sign_bit` (§15), all pinned; each stands after the vectors that stood in its group before. No frozen vector has changed, neither in its bytes nor in its expectation. `published_test_keys` stays unchanged: every new certificate carries the key of the root or of the signer of the generator's time-stamping authority, the certificate on no path in `timestamp_extra_certificate_key_parameters_tag_zero` the 32 octets of the signer's key under a private algorithm outside Z.2; every receipt is signed with `vendor-test-001`. Recomputable: `git show 8020dcf7:spec/testvectors/PINS.sha256 > /tmp/pins_1_10_abgleich` and then `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_10_abgleich`: 3216 files (417 vector directories with 2122 files, 1080 files at the top level and 14 files of the reference case), no deviation.

**Specification 1.10 (alignment of both verifiers: a uuid is the whole string): no exception.** Added is `format_uuid_trailing_newline` (§15), pinned; it closes the group `format`. No frozen vector has changed, neither in its bytes nor in its expectation. `published_test_keys` stays unchanged: its chain is signed with `dev-test-001` and `vendor-test-001`. Recomputable: `git show f920c34e:spec/testvectors/PINS.sha256 > /tmp/pins_1_10_uuid` and then `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_10_uuid`: 3411 files (442 vector directories with 2247 files, 1150 files at the top level and 14 files of the reference case), no deviation.

Section 8.7 of the format specification (capture commitment and gap start after a crash) binds the appliance, not the verifier: it produces no finding and changes no vector.

**Test keys from chains before 1.8 (decision of 2026-10-02): no exception for the bytes.** Every test key that a test or demo chain before 1.8 carried in cleartext has been replaced by a new one in tests, contract vectors, demo and example configuration. Every new one contains at least one of the characters I, L, O or U and so never has the form the LOUWIETEC Cloud issues (`LEDGER-` and four times four characters of Crockford base32). `LIC-TEST-0001` stays in the frozen corpus. It is not a license key and cannot become one: the grammar `^[A-Z0-9-]{19,29}$` (heartbeat specification 4.1) does not admit 13 characters, so an activation with it already fails on the form. The vectors before 1.8 are also the yardstick for chains of older versions staying readable (format specification 4.1). They are used for that alone, not as a demo and not as a template for new chains.

**Addendum on the vector `tamper_missing_checkpoint` (14 Sep).** The negative vector for `MISSING_CHECKPOINT` (exit 2) was pinned and exercised by both check jobs, because those enumerate `expected/`, but it was not listed in `spec/registry.json`; `.ci/check_registry_matrix.py` therefore counted 29 vectors instead of 30 and checked only the direction registry → files. Both are fixed: the entry is in the registry, and the matrix check runs in both directions; a vector directory or an `expected/` file without a registry entry has been red ever since; a red proof shows it.

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

## 10. Foundations of specification 1.10: key roles, auditor inputs, time-stamp profile

130 vectors declare `spec_version` `1.10`, in the groups `roles`, `auditor` and `timestamp`; 29 of them (`auditor_log_neighbours_equal_index` and the last 28 of the table in §10.3, the last 23 from the alignment of both verifiers, §15) show readings the specification wrote down after the foundations. They build on the one-hour standard chain (GENESIS, two AI calls, 5-minute cadence, half-hourly receipts), **sealed** at 01:01 with `SEAL(shutdown)` and its immediate checkpoint, checked 2 min later: 32 entries, receipts at `tree_size` 15 and 28, the case KAT1 of format specification 10.9.5. The vectors of the group `timestamp` additionally carry at 00:40:01.200 a `TIME_ANCHOR` over the checkpoint of 00:40:00.500 (`checkpoint_seq` 21, `tree_size` 20; 33 entries, receipts at 15 and 29). No package carries `keys/tsa/` or a list of countersigning keys.

**Two audit environments.** Besides the audit environment of the corpus (§3) each of these vectors has its own: the file `pruefer_<name>.json` (`ledger-pruefumgebung/1`, format specification 10.8) and the files `pruefer_<name>.<member>-<n>.<ext>` it names, all at the top level and pinned in `PINS.sha256`. The checking tools turn the members into switches in the order of the registry (`auditor_inputs.pruefumgebung.member_order`); `korpus` `true` adds the root and the pin of the corpus, the check time stays in `verify_args.json`. The expected file names both expectations: `exit_code`, `finding_classes` and `evidence_level` for the audit environment of the corpus, `auditor_inputs` for that of the vector. The tables state first exit and findings with the audit environment of the corpus, then with `pruefer_<name>.json`. Exit 3 without findings (`-`) means: unusable invocation, no report (10.8); the expected file then names `evidence_level` `null`, since without a report there is no evidence level (10.9.2, 10.10.1). Every registry entry names in member `why` the reason and the section the expectation rests on. The report object `key_roles` (10.10.2) and the results per token (Z.6, rule QS) are not in the expected file; their expected values stand in the description of the row, and both reference verifiers print them alike (format specification 10.10). `TestGrundlagenTabellenFolgenDerErwartung` (`appliance/cmd/vektorgen`) holds the tables against `expected/`.

### 10.1 Key roles (group `roles`)

The receipts are under `vendor-test-001`, which the audit environment of the corpus pins; in `roles_pin_other_role` and `roles_pin_without_list` under `vendor-statements-test-001`, a statements key, in `roles_list_revokes_receipt_key` under `vendor-test-002`, which no pin confirms. Every audit environment of a vector contains that of the corpus (`korpus` `true`), so it can check the monotonicity of format specification 10.9.7. `testwurzel-1` signs every list, every key is a test key of the corpus (format specification 10.7.2, reference values). **Counter-check:** every role list of the vectors that are to show that no role list is effective gives the public key of `vendor-test-001` the rolle `statements`. Were it effective, the corpus pin would be dropped (10.7.4, R3 (d)) and the receipts would give `RECEIPT_UNVERIFIED`; exit 0 with the vector's audit environment is the proof. The expected values of `key_roles` stand in the description.

| Vector | Structure and the vector's audit environment | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `roles_list_effective` | role list of version 1 from 10.7.2 (byte for byte the reference values); `key_roles`: `effective`, statements keys `vendor-statements-test-001` and `-002` from the role list; the pin of `vendor-test-001` stays | 0 | - | 0 | - |
| `roles_pin_other_role` | receipts under `vendor-statements-test-001`; `--vendor-key` pins this key as countersigning key, the role list of version 1 names it with rolle `statements`: the pin is dropped (`pins_dropped`, notes `receipt_key_other_role`, `pin_dropped`) | 1 | `RECEIPT_UNVERIFIED` | 1 | `RECEIPT_UNVERIFIED` |
| `roles_pin_without_list` | the same package as `roles_pin_other_role`, the same pin, no role list: the pin confirms the receipts; `key_roles`: `not_supplied` | 1 | `RECEIPT_UNVERIFIED` | 0 | - |
| `roles_list_revokes_pinned_key` | role list names `vendor-test-001` as countersigning key with `widerrufen_ab` `2025-12-31T00:00:00Z`, before every receipt; the corpus pin stays and confirms them; `key_roles`: `effective` | 0 | - | 0 | - |
| `roles_list_revokes_receipt_key` | receipts under `vendor-test-002`, which is neither pinned nor in a list of the package; the role list names it as countersigning key with `widerrufen_ab` `2025-12-31T00:00:00Z`: `RECEIPT_UNVERIFIED`, never `RECEIPT_INVALID`; `key_roles`: `effective` | 1 | `RECEIPT_UNVERIFIED` | 1 | `RECEIPT_UNVERIFIED` |
| `roles_two_roles_cs_list` | list of countersigning keys of the corpus (version 1, as in `valid_vendor_list`) through `--vendor-key-list` and a role list that gives `vendor-test-001` the rolle `statements`: `key_roles` `not_effective`, reason `key_in_two_roles`; the pin stays | 0 | - | 0 | - |
| `roles_two_roles_no_fallback` | list of countersigning keys with `vendor-test-002` alone; role list version 1 gives `vendor-test-001` the rolle `statements`, version 2 also `vendor-test-002`: version 2 fails R3 (a), version 1 does not take its place; `not_effective`, `key_in_two_roles` | 0 | - | 0 | - |
| `roles_two_roles_protocol_list` | role list (gives `vendor-test-001` the rolle `statements`) and a protocol key list whose key carries the public key of `vendor-statements-test-002`: neither is effective; `not_effective`, `key_in_two_roles` | 0 | - | 0 | - |
| `roles_protocol_list_cs_pin` | protocol key list with the public key of `vendor-test-001`, no role list, no extract: the list is ineffective, the pin stays; `key_roles`: `not_supplied` | 0 | - | 0 | - |
| `roles_same_version_differ` | two role lists of version 1 that differ only in `ausgestellt`: `not_effective`, `lists_contradictory` | 0 | - | 0 | - |
| `roles_entry_dropped` | role list version 2 without the entry `vendor-statements-test-002` of version 1: `not_effective`, `lists_contradictory` | 0 | - | 0 | - |
| `roles_dual_end_effective` | role list version 1 and version 2 with the same entries and `ende_doppelbetrieb` `2026-07-01T00:00:00Z`: `effective`, `list.version` 2, `list.ende_doppelbetrieb` `2026-07-01T00:00:00Z` | 0 | - | 0 | - |
| `roles_dual_end_differs` | role lists version 2 and 3 with `ende_doppelbetrieb` `2026-07-01T00:00:00Z` and `2026-07-01T00:00:00.000Z`: `not_effective`, `lists_contradictory` | 0 | - | 0 | - |
| `roles_dual_end_dropped` | role list version 2 with `ende_doppelbetrieb`, version 3 without: `not_effective`, `lists_contradictory` | 0 | - | 0 | - |
| `roles_list_protocol_role` | role list with an entry of rolle `protocol`: `not_effective`, reason `format` | 0 | - | 0 | - |
| `roles_list_names_root` | role list with an entry that names the public key of `testwurzel-1`: `not_effective`, reason `format` | 0 | - | 0 | - |
| `roles_list_extra_member` | role list with a member `kommentar` in one entry: `not_effective`, reason `format`, no exit 3 | 0 | - | 0 | - |
| `roles_list_no_matching_root` | role list with `signatur.wurzel_id` `testwurzel-2`, signed with the key of `testwurzel-1`: `not_effective`, reason `no_matching_root` | 0 | - | 0 | - |
| `roles_list_bad_signature` | role list under `testwurzel-1`, signed with the key of `vendor-test-002`: `not_effective`, reason `signature` | 0 | - | 0 | - |
| `roles_list_two_reasons` | the role lists of `roles_list_protocol_role` and `roles_list_bad_signature` together: `not_effective`, reason `signature`, `candidates` 2 | 0 | - | 0 | - |
| `roles_unknown_role` | role list of version 1 with rolle `audit_log` for `vendor-test-001`: `effective`, notes `unknown_role`, `receipt_key_other_role`, `pin_dropped`; the pin is dropped (`listed_as` `audit_log`) | 0 | - | 1 | `RECEIPT_UNVERIFIED` |
| `roles_statement_pins` | list of countersigning keys of the corpus through `--vendor-key-list`, statements pins: `vendor-statements-test-001` (stays, `statement_keys` with `pinned`) and `vendor-test-003` (public key in K_cs^L, dropped); `key_roles`: `not_supplied`, note `pin_dropped` | 0 | - | 0 | - |
| `roles_pins_dropped` | role list of version 1; pinned as statements keys `vendor-test-002` and `vendor-update-manifest-test-001`, as protocol key `vendor-log-test-001` with the public key of `vendor-statements-test-002`: all three are dropped (`listed_as` `countersigning`, `update_manifest`, `statements`) | 0 | - | 0 | - |

The verifier does not read `statement_signatures` (heartbeat specification §9.3); the reference cases for receivers of editions 1.9 and 1.10 are in `spec/contract/statement_signatures.json`. The verifier's side of the transition from single-key operation (10.7.5) is shown by `roles_dual_end_effective`, `roles_dual_end_differs` and `roles_dual_end_dropped`: `ende_doppelbetrieb` in the role list and the rules of R2.

### 10.2 Auditor inputs (group `auditor`)

One unusable invocation per rule of format specification 10.8 (with 7.1, 10.7.4 and 7.4.10, step L0), plus three cases at a boundary that are accepted. The package is the standard chain; with the audit environment of the corpus it gives exit 0. Without a vector remain inputs that `ledger-pruefumgebung/1` cannot express (a switch allowed at most once given twice; a pin not of the form `key_id=hex64`; an expected root with `0:` or a leading zero; an unknown switch) and the size limits from 1 048 576 bytes up.

| Vector | Structure and the vector's audit environment | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `auditor_root_conflict` | a second vendor root `testwurzel-1` with another public key next to the corpus root | 0 | - | 3 | - |
| `auditor_root_extra_member` | vendor root with a third member `kommentar` | 0 | - | 3 | - |
| `auditor_vendor_key_conflict` | `--vendor-key vendor-test-001` with the public key of `vendor-test-002` next to the corpus pin | 0 | - | 3 | - |
| `auditor_statement_pin_equals_cs_pin` | `--vendor-statement-key` with exactly the corpus pin `vendor-test-001=...` | 0 | - | 3 | - |
| `auditor_statement_pin_conflict` | two statements pins `vendor-statements-test-001` with different public keys | 0 | - | 3 | - |
| `auditor_statement_pin_id_equals_log_pin` | statements pin and protocol pin with the same `key_id` `vendor-statements-test-001`, different public keys | 0 | - | 3 | - |
| `auditor_log_pin_conflict` | two protocol pins `vendor-log-test-001` with different public keys | 0 | - | 3 | - |
| `auditor_log_pin_equals_cs_pin` | protocol pin `vendor-log-test-001` with the public key of the pin `vendor-test-001` | 0 | - | 3 | - |
| `auditor_key_list_unknown_format` | role list of version 1 with `format` `ledger-schluesselrollen/2` | 0 | - | 3 | - |
| `auditor_key_list_no_format` | role list of version 1 without member `format` | 0 | - | 3 | - |
| `auditor_key_list_duplicate_member` | role list of version 1 with the member `version` twice | 0 | - | 3 | - |
| `auditor_key_list_number_form` | role list of version 1 with `"version":1.0` | 0 | - | 3 | - |
| `auditor_expect_root_too_large` | `--expect-root 9007199254740992:<root>` | 0 | - | 3 | - |
| `auditor_vendor_log_not_json` | `--vendor-log` with a file that is no JSON | 0 | - | 3 | - |
| `auditor_anchor_history_not_json` | `--anchor-history` with a file that is no JSON | 0 | - | 3 | - |
| `auditor_requested_at_after_now` | `--requested-at 2026-01-01T01:03:00.501Z`, check time `2026-01-01T01:03:00.500Z` from `verify_args.json` | 0 | - | 3 | `FORMAT_ERROR` |
| `auditor_requested_at_unused` | `--requested-at 2026-01-01T01:03:00.500999999Z` without an anchor history: accepted, note `requested_at_unused` | 0 | - | 0 | - |
| `auditor_tsa_pem_other_label` | `--tsa-root` with a block `CERTIFICATE` and a block `X509 CRL` | 0 | - | 3 | - |
| `auditor_tsa_pem_header` | `--tsa-root` with a line `Comment: ...` between `BEGIN` and the content | 0 | - | 3 | - |
| `auditor_tsa_pem_no_end` | `--tsa-root` with a block without `END` | 0 | - | 3 | - |
| `auditor_tsa_pem_no_block` | `--tsa-root` with a file without a block | 0 | - | 3 | - |
| `auditor_tsa_pem_not_b64` | `--tsa-root`, the first content line ends in `==` | 0 | - | 3 | - |
| `auditor_tsa_pem_not_certificate` | `--tsa-root`, certificate followed by one byte `00` | 0 | - | 3 | - |
| `auditor_log_tsa_pem_no_block` | `--vendor-log-tsa-root` with a file without a block | 0 | - | 3 | - |
| `auditor_qualified_duplicate` | `--tsa-qualified-roots` with the same root twice | 0 | - | 3 | - |
| `auditor_qualified_window_inverted` | `qualifiziert_bis` before `qualifiziert_ab` | 0 | - | 3 | - |
| `auditor_qualified_unknown_member` | `--tsa-qualified-roots` with a member `kommentar` | 0 | - | 3 | - |
| `auditor_qualified_format` | `format` `ledger-tsa-qualifiziert/2` | 0 | - | 3 | - |
| `auditor_qualified_not_certificate` | `zertifikat` with one byte `00` after the certificate | 0 | - | 3 | - |
| `auditor_log_neighbours_equal_index` | `--vendor-log` with an extract of the test log (§11.1): the day 2025-12-31 and an `absent` record whose two neighbours carry the same `leaf_index`: the grammar holds (not falling), no exit 3; both receipts `pending` | 0 | - | 0 | - |

### 10.3 Time-stamp profile (group `timestamp`)

The tokens are issued by a time-stamping authority of the generator (`appliance/cmd/vektorgen/zeitstempelprofil.go`): a root and a signer with Ed25519 keys from published seeds, `digestAlgorithm` SHA-512 (RFC 8419), `genTime` `20260101004001Z`, imprint SHA-256 over the checkpoint's signing subject, `signingCertificateV2` on the signer, no `extensions`. Each vector changes exactly what it is named after; the audit environment of most of them is the test root in `--tsa-qualified-roots` (purposes `chain` and `qualified`, qualified from `2025-01-01T00:00:00Z`). Without a root, that is with the audit environment of the corpus, every token that passes steps 1 to 4 and, where performable, 5b gives `TIME_ANCHOR_UNVERIFIED`.

**Published test keys.** The SPKI SHA-256 values of the root, of the signer and of the Brainpool signer are listed in `published_test_keys` (format specification 7.5.7), like that of the source's test authority which `timestamp_published_test_key` uses. Therefore no vector credits conditions (1) and (4) of the evidence level: with a root of the auditor, `time_witness` and `time_witness_qualified` end at `published_test_key`, except where step 5 is not performable after 5a or Z.6 cannot be checked (`signature_not_checkable`) or no path exists. The stages behind `published_test_key` (`qualified_root_in_package`, period, Z.6, rule QS) are therefore shown by no expected file; the vectors pin that these results change neither the exit code nor the findings.

| Vector | Structure and the vector's audit environment | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `timestamp_chain_root` | token that keeps the whole profile (Ed25519, ESS v2); `--tsa-root` with the test root | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_qualified_root` | the same token; the test root only in `--tsa-qualified-roots` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_signer_as_root` | the same token; `--tsa-root` with the signer certificate | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_signer_expired_after_gentime` | signer certificate valid until `2026-01-01T00:50:00Z`, `genTime` 00:40:01, check time 01:03:00.5 | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_published_test_key` | token of the source's test authority (RSA, SPKI SHA-256 `0ee470ad…`); its certificate in `--tsa-qualified-roots` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_root_other` | `--tsa-root` with the certificate of another authority (the source's test authority) | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_qualified_root_other` | `--tsa-qualified-roots` with the certificate of another authority | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_log_root_only` | the test root only in `--vendor-log-tsa-root` (purpose `log`) | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_signer_eku_not_critical` | signer certificate with `extKeyUsage` `id-kp-timeStamping`, not critical | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_signer_not_yet_valid` | signer certificate valid from `2026-01-01T00:45:00Z`, `genTime` 00:40:01 | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_root_repeated` | two `--tsa-root`: the test root, then another authority | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_pem_bundle` | one PEM file with a comment line, CRLF, blanks at line ends and two roots (another authority first) | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_checkpoint_mismatch` | `tree_size` of the entry 18 instead of 20 | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_b64_newline` | `token_base64` with `\n` after 76 characters | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_der_too_large` | DER 16 385 bytes (padding in `crls`), Base64 21 848 characters | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_imprint_wrong` | imprint over a signing subject with another tree root, otherwise a token that keeps the profile | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_gentime_trailing_zero` | `genTime` `20260101004001.120Z` | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_imprint_sha1` | `messageImprint` with SHA-1 | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_two_signer_infos` | two equal `SignerInfo` | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_ber_length` | outer length of the `ContentInfo` with a leading octet `00` | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_tsa_ts_rounded` | `genTime` `20260101004001.123999999Z`, `tsa_ts` `2026-01-01T00:40:01.124Z` (rounded) | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_gentime_fraction` | `genTime` `20260101004001.123999999Z`, `tsa_ts` `2026-01-01T00:40:01.123Z`; `qualifiziert_ab` equal to `genTime`; input of the single check | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_imprint_sha384` | `messageImprint` with SHA-384 | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_sha1_digest_algorithm` | `digestAlgorithm` SHA-1 (also in `digestAlgorithms`), `messageDigest` and signature hold; input of the single check | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_no_certificates` | `certificates` absent | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_no_signed_attrs` | `signedAttrs` absent, signature over `eContent` | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_signer_not_found` | `sid` with a serial number no certificate carries | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_certificate_not_z1` | `certificates` with the signer and a version 1 certificate | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_signer_brainpool` | signer with a key on brainpoolP256r1, `ecdsa-with-SHA256` | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_key_algorithm_mismatch` | Ed25519 key, `signatureAlgorithm` `sha256WithRSAEncryption` | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_message_digest_wrong` | `messageDigest` changed in one bit, the signature over it holds | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_signature_wrong` | signature changed in one bit | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_content_type_attr_wrong` | `contentType` `id-data` | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_ess_none` | neither ESS attribute | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_ess_v1` | `signingCertificate` alone | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_ess_both` | `signingCertificate` and `signingCertificateV2`, both on the signer; input of the single check | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_ess_v2_other_cert` | `signingCertificateV2` with the hash of the root | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_ess_v1_mismatch` | both attributes, `signingCertificate` with the hash of the root | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_ess_two_values` | `signingCertificateV2` with two values | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_ess_issuer_serial_mismatch` | `signingCertificateV2` with `issuerSerial` of another serial number | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_ess_v2_sha1` | `signingCertificateV2` with `hashAlgorithm` SHA-1 | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_qs_present` | `extensions` with `qcStatements` and `0.4.0.19422.1.1` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_qs_other_statement` | `qcStatements` with `0.4.0.1862.1.1` alone | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_qs_malformed` | `qcStatements` with `SEQUENCE { INTEGER 1 }` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_qs_unknown_critical` | `qcStatements` with the identifier and an unknown critical extension | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_qs_critical_false_encoded` | `qcStatements` with explicitly encoded `critical` `00` and the identifier | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_qs_nonce_bytes` | `nonce` with the bytes `06 07 04 00 81 97 5E 01 01`, no `extensions` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_qs_empty` | empty `extensions` `[1]` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_qualified_outside_window` | `qualifiziert_bis` `2026-01-01T00:40:01Z` equal to `genTime` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_extension_value_not_der` | signer with a non-critical extension no rule reads; its `extnValue` is one TLV of minimal length with content outside DER (`30 03 01 01 01`): only the outer TLV is checked | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_certificates_not_tlv` | the content of `certificates` does not split into TLV (signer, then `30 05 01`): step 5 not performable (5a), never grammar T; input of the single check | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_gentime_year_zero` | `genTime` `00000101004001Z`, `tsa_ts` `2026-01-01T00:40:01.000Z`: the year `0000` violates grammar T (T.5), step 2 | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_sid_not_issuer_serial` | `sid` is a SEQUENCE whose serial carries the tag OCTET STRING: grammar T holds, no signer after Z.5 (5a); input of the single check | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_name_value_constructed` | the CN in the signer's `subject` as a UTF8String in constructed form: the value of an attribute of a Name is one TLV, Z.1 holds; input of the single check | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_ess_v2_second_element_broken` | `signingCertificateV2` with `certs[0]` on the signer and `certs[1]` = `SEQUENCE { INTEGER 1 }`, no ESSCertIDv2: every element of `certs` follows the grammar of Z.6, also where only `certs[0]` is compared; Z.6 violated (7.5.6); input of the single check | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_ess_issuer_serial_name_broken` | `issuerSerial` in `certs[0]` with the serial number of the signer and two `directoryName` `[4]`: the first with the signer's `issuer`, the second with `SEQUENCE { INTEGER 1 }`, no Name; an element with the identifier octet `A4` holds exactly one Name per Z.1: Z.6 violated although a matching `directoryName` stands beside it; input of the single check | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_ess_policies_not_der` | `signingCertificateV2` with `policies` whose qualifier holds an INTEGER with the content `00 01` (not minimal) and a `[4]` around it: no rule reads `policies`, T.6 checks only its outer TLV, a `[4]` in it is no `directoryName`; Z.6 holds; input of the single check | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_ess_other_name_a4` | GeneralNames in `issuerSerial`: an otherName `[0]` whose value holds a `[4]` with `SEQUENCE { INTEGER 1 }`, then the `directoryName` `[4]` with the signer's `issuer`: of the otherName T.6 checks only the outer TLV, a `[4]` in its value is no `directoryName`; Z.6 holds; input of the single check | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_signer_basic_constraints_not_der` | signer with basicConstraints, critical, content `SEQUENCE { BOOLEAN 01 }`: Z.1 checks the content of basicConstraints under T.6, BOOLEAN `01` is not DER; Z.1 violated, step 5 not performable (5a), not "no path" | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_extra_certificate_path_len_not_minimal` | `certificates` with the signer and a certificate of the root for an intermediate authority on no path, whose `pathLenConstraint` 0 stands as the INTEGER content `00 00`: Z.1 holds for every certificate from `certificates`, here it does not; 5a | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_signer_eku_oid_not_minimal` | the signer's `extKeyUsage` with `id-kp-timeStamping`, last subidentifier 8 as `80 08`, not minimal: Z.1 violated, 5a, not "no path" under Z.4 | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_signer_basic_constraints_tag_zero` | the signer's basicConstraints with the content `30 02 00 00`, an element of the universal class with tag number 0: where T.6 checks every element, it does not satisfy T.6; Z.1 violated, 5a | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_signer_basic_constraints_tag_31` | the signer's basicConstraints with the content `30 03 1F 1F 00`, an element of the universal class with tag number 31: does not satisfy T.6; Z.1 violated, 5a | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_signer_key_usage_unreadable` | the signer's keyUsage is the BIT STRING `03 02 08 80` with eight unused bits: T.6 does not check the unused-bits octet, Z.1 holds and step 5 holds; keyUsage does not follow the grammar of Z.3, which makes the path unusable also at c0: no path | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_signer_basic_constraints_unreadable` | the signer's basicConstraints with the content `SEQUENCE { OCTET STRING 00 }`: DER, Z.1 holds; does not follow the grammar of Z.3, also at c0, where Z.4 does not evaluate basicConstraints: no path | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_signer_basic_constraints_null_content` | the signer's basicConstraints with the content `SEQUENCE { NULL }`, the NULL with the content `00`: T.6 does not check the content of NULL, Z.1 holds; Z.3 not kept: no path, never 5a | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_root_key_cert_sign_unused_bit` | in `--tsa-qualified-roots` the test root with the same key and keyUsage `03 02 03 06`: keyCertSign (bit 5) stands among the three unused bits and does not count; Z.4 asks keyCertSign of the root: no path | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_sid_key_identifier` | `sid` as `[0]` with the key identifier from the signer's subjectKeyIdentifier (content of the OCTET STRING in `extnValue`, SHA-1 of its public key), version 1: Z.5 finds the signer | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_signature_r_identity` | signature of the token with R = `01 00…00 00`, the canonical encoding of the neutral element, and S = k·a mod L: the encoding of [S]B - [k]A equals R, the signature holds (Section 2) | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_signature_r_identity_sign_bit` | the same signature with R = `01 00…00 80`, the neutral element with the sign bit set: as points [S]B = R + [k]A holds, but the encoding of [S]B - [k]A is `01 00…00 00`; step 5b (Section 2) | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_signer_cert_r_identity` | the root's signature over the signer certificate with R = `01 00…00 00`: holds, the path exists | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_signer_cert_r_identity_sign_bit` | the root's signature over the signer certificate with R = `01 00…00 80`: does not hold, no path (Z.4), never 5b | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_ess_hash_algorithm_parameters_not_der` | `signingCertificateV2` with `hashAlgorithm` SHA-256 and the parameters `02 02 00 01` in `certs[0]`, an INTEGER 1 with the content `00 01`, not minimal: the verifier recognises the `hashAlgorithm` by its OID alone, of the parameters T.6 checks only the outer TLV; Z.6 holds (7.5.6); input of the single check | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_signed_attribute_value_not_der` | one more signed attribute of a private type with the value `30 04 02 02 00 01`, a SEQUENCE around an INTEGER with the content `00 01`: the value of a signed attribute that no rule reads is one TLV, and T.6 checks only that; grammar T holds, step 5 performed (7.5.2) | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_extra_certificate_key_parameters_tag_zero` | `certificates` with the signer and a certificate of the root on no path whose `subjectPublicKeyInfo` names a private algorithm outside Z.2 with the parameters `00 00`, a TLV of the universal class with tag number 0: of parameters no rule reads T.6 checks only the outer TLV, where tag number 0 is admitted; Z.1 holds, Z.2 applies only to keys on a path | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_extra_certificate_oid_arc_large` | `certificates` with the signer and a certificate of the root on no path whose non-critical `extKeyUsage` holds an OID with the arc N = 128^2100 + … + 128 + 1 (4426 decimal digits, above 10^4300), minimally encoded: T.6 sets no bound on an arc, Z.1 holds, step 5 performable (7.5.3) | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_qs_extension_oid_arc_large` | `extensions` of the TSTInfo with a non-critical extension whose `extnID` carries the same arc N, value NULL, next to `qcStatements` with the identifier: every Extension is DER under T.6, the unknown one is not critical; rule QS `present` (7.5.6); input of the single check | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |

### 10.4 Inputs of the single time-stamp check

For the check of a single time stamp (`ledger-verify zeitstempel`, `verifier2.py zeitstempel`; it checks no package and is not part of the specification) the inputs of twelve vectors lie at the top level, pinned: `zeitstempel_<name>.token.der` and `zeitstempel_<name>.token.b64` (the token as DER and as Base64 after B64, without line end), `zeitstempel_<name>.daten.json` (the bytes the imprint covers, the checkpoint's signing subject, for `--data`) and `zeitstempel_<name>.wurzel.pem` (the test root, for `--tsa-root`). With `--purpose chain` and this root the results follow from the table in 7.5.7 (the topmost row that applies, cases as in registry `verifier.timestamp_profile.outcomes`); the signer is `Testkorpus Zeitstempelstelle (kein Zeuge)` throughout, where Z.5 finds it. The rows of 7.5.7 hold alike for both purposes: with `--purpose log` and the same root the result is the same. The inputs on Z.6 show what the expected file does not show: there a token of a published test key ends at `published_test_key`, while in 7.5.7 the row on Z.6 stands above it. Likewise only the single check shows the result of rule QS (column "Rule QS").

| Input | genTime, cut to milliseconds | Imprint | Rule QS | Result |
|---|---|---|---|---|
| `zeitstempel_timestamp_gentime_fraction` | `20260101004001.123999999Z`, `2026-01-01T00:40:01.123Z` | sha256 | `absent` | not confirmed, `published_test_key` |
| `zeitstempel_timestamp_sha1_digest_algorithm` | `20260101004001Z`, `2026-01-01T00:40:01.000Z` | sha256 | `absent` | not confirmed, `step_5_not_performable` (`digestAlgorithm` SHA-1 outside Z.2) |
| `zeitstempel_timestamp_ess_both` | `20260101004001Z`, `2026-01-01T00:40:01.000Z` | sha256 | `absent` | not confirmed, `published_test_key` (Z.6 holds with both attributes) |
| `zeitstempel_timestamp_certificates_not_tlv` | `20260101004001Z`, `2026-01-01T00:40:01.000Z` | sha256 | `absent` | not confirmed, `step_5_not_performable` (the content of `certificates` does not split into TLV) |
| `zeitstempel_timestamp_sid_not_issuer_serial` | `20260101004001Z`, `2026-01-01T00:40:01.000Z` | sha256 | `absent` | not confirmed, `step_5_not_performable` (no signer after Z.5) |
| `zeitstempel_timestamp_name_value_constructed` | `20260101004001Z`, `2026-01-01T00:40:01.000Z` | sha256 | `absent` | not confirmed, `published_test_key` (Z.1 holds) |
| `zeitstempel_timestamp_ess_v2_second_element_broken` | `20260101004001Z`, `2026-01-01T00:40:01.000Z` | sha256 | `absent` | defective, `z6_failed` (`certs[1]` is no ESSCertIDv2) |
| `zeitstempel_timestamp_ess_issuer_serial_name_broken` | `20260101004001Z`, `2026-01-01T00:40:01.000Z` | sha256 | `absent` | defective, `z6_failed` (a `directoryName` without a Name) |
| `zeitstempel_timestamp_ess_policies_not_der` | `20260101004001Z`, `2026-01-01T00:40:01.000Z` | sha256 | `absent` | not confirmed, `published_test_key` (Z.6 holds, `policies` only as an outer TLV) |
| `zeitstempel_timestamp_ess_other_name_a4` | `20260101004001Z`, `2026-01-01T00:40:01.000Z` | sha256 | `absent` | not confirmed, `published_test_key` (Z.6 holds, the `[4]` in the otherName is no `directoryName`) |
| `zeitstempel_timestamp_ess_hash_algorithm_parameters_not_der` | `20260101004001Z`, `2026-01-01T00:40:01.000Z` | sha256 | `absent` | not confirmed, `published_test_key` (Z.6 holds, the parameters of `hashAlgorithm` only as an outer TLV) |
| `zeitstempel_timestamp_qs_extension_oid_arc_large` | `20260101004001Z`, `2026-01-01T00:40:01.000Z` | sha256 | `present` | not confirmed, `published_test_key` (the arc above 10^4300 keeps T.6) |

## 11. Vendor log of specification 1.10 (group `log`)

89 vectors of the group `log` check the steps L0 to L10 of format specification 7.4.10 and the report object `vendor_log` (10.10.2). They declare `spec_version` `1.10`. Their expectations stand in the registry, each with its reason and section in the member `why`, derived from the text of the specification; the expected file does not name the report object `vendor_log`, its values stand in the row's description where a vector is about them. 26 of them (§11.3, table "Witnessed days") show, with the time-stamping authority E1 (§11.2), the cases that need a usable day.

### 11.1 Package and log

**Package.** Every vector has its own chain, with its own `chain_id` and `appliance_id`, after the same script: `GENESIS` at 23:50 on 2026-01-02, two AI calls, 5-minute cadence, receipts under `vendor-test-001` at 23:55:01 (`tree_size` 5, day 2026-01-02) and at 00:05:01 the next day (`tree_size` 10, day 2026-01-03), sealed at 00:06 with `SEAL(shutdown)` and its immediate checkpoint (14 entries), checked at 06:30 on 2026-01-03. The day of the first receipt is then due, that of the second is not (format specification 7.4.6, due days). With the audit environment of the corpus every package gives exit 0 and level 2 up to `tree_size` 10. `log_receipt_future` is checked at 23:49 on 2026-01-02, `log_receipts_pending` at 00:10 on 2026-01-03; the chain of `log_receipts_before_start` starts at 23:30 on 2025-12-30 and is checked at 23:50 the same day. In `log_witnessed_receipt_invalid` and `log_receipt_invalid_outside_range` the receipt of `tree_size` 5 names as `checkpoint_seq` the `TICK` before its checkpoint: its signature holds and it fits a prefix, but it is `RECEIPT_INVALID` (exit 2, format specification 7.1). `log_witnessed_time_anchor_qualified` carries a `TIME_ANCHOR` over the checkpoint of `tree_size` 5, 700 ms after the first receipt (15 entries, receipts at `tree_size` 5 and 11); with the audit environment of the corpus it gives `TIME_ANCHOR_UNVERIFIED`.

**Log.** The test log `ledger-testprotokoll-1` is that of the examples of format specification 7.4.4, 7.4.5 and 7.4.7: first day 2025-12-31, the published test filler secret and the protocol key list of version 1 with `vendor-log-test-001` and the standby key `vendor-log-test-002` (seeds `vendor-log-1` and `vendor-log-2`, both in `published_test_keys`), signed by `testwurzel-1`. Its days 2025-12-31 (no leaves, `tree_size` 0, day hash `33fd1b29…`) and 2026-01-01 (the tree of size 5, root `0adcf8f0…`, day hash `ef330d20…`) are those of the reference values and equal in every vector. The day 2026-01-02 carries the chain-day leaf of the vector's chain and the candidates 0 to 3 of the day as fillers, closed at 00:05 on 2026-01-03. Every day entry is signed with `vendor-log-test-001` and stamped by the time-stamping authority of the test corpus (§10.3) over `UTF-8(statement_jcs)` with sha256, `genTime` one second after `server_ts`. The extract is the one the server gives without `from` and `to`: the days from the chain's first leaf to the head, here the day 2026-01-02 with its chain-day record, and the protocol key list in `protocol_keys`. In the vectors of the table "Witnessed days" the time-stamping authority E1 (§11.2) stamps the day 2026-01-02; chain-day leaf, fillers and record follow what the vector is about.

**Audit environment.** `pruefer_<name>.json` passes the anchors of the corpus (`korpus` `true`), the extracts with `--vendor-log` and the root of the test corpus's time-stamping authority with `--vendor-log-tsa-root`, unless the vector is about these inputs. `TestProtokollVektoren`, `TestProtokollNachweise`, `TestProtokollReferenzfall` and `TestProtokollTabellenFolgenDerErwartung` (`appliance/cmd/vektorgen`) hold packages, records, reference case and the table of §11.3 against the bytes and against `expected/`; `TestBlaetterReferenzwerte`, `TestFuellerReferenzwerte`, `TestTageseintragReferenzwerte` and `TestProtokolllisteReferenzwerte` recompute the reference values of 7.4.2, 7.4.4, 7.4.5 and 7.4.7, `TestInklusionUndAbwesenheit` the proofs after section 5. The vectors of the table "Witnessed days" pass, in place of the test authority's root, the root of E1 with `--vendor-log-tsa-root` and, where they are about condition (4) or (7), also in `--tsa-qualified-roots` (named from 2025-01-01). `TestEinmaligeStelleEingefroren`, `TestEinmaligeStelleWeistAbweichungAb`, `TestBezeugtVektoren`, `TestBezeugtNachweise`, `TestBezeugtStempel`, `TestZweiterReferenztag` and `TestBezeugtTabellenFolgenDerErwartung` (`appliance/cmd/vektorgen`) hold the frozen input, the packages, every record, every time stamp of E1 with its window class, the second reference day and the table against the bytes and against `expected/`.

### 11.2 Witnessed days and the time-stamping authority with discarded keys

Every key of a time-stamping authority from a published seed stands in `published_test_keys`; a day time stamp of such an authority is never confirmed after format specification 7.5.7. With such authorities no day is therefore witnessed or usable (7.4.10, steps L2 (h) and L3). No vector whose days only such authorities stamp shows the classes `included` and `not_included`, the sub-classes `no_record`, `record_failed` and `record_contradictory`, the findings `RECEIPT_NOT_LOGGED` and `LOGGED_ROOT_MISMATCH`, the reason `late`, a confirmed premature time stamp, two witnessed versions of a day, the checks of steps L6 and L9 and the validity of a protocol key through the `genTime` of a confirmed time stamp (L2 (e)); the conditions (5) and (7) of the evidence level are not met in such a vector. The records of the vectors are built correctly nevertheless (`TestProtokollNachweise` checks each after `verify_inclusion` and the forms of the absence proof of section 5), and the vectors pin that a record on a day that is not usable is passed over and counted in no member of the report. The vectors of the table "Witnessed days" show these cases with the time-stamping authority E1.

**Time-stamping authority with discarded keys** (format specification 7.5.7). The corpus MAY contain a time-stamping authority whose keys are created in one run of the generator from a cryptographically secure random source, issue the tokens of the corpus only in that run, and are written nowhere. Its root and its certificates are in the corpus; its keys are not in `published_test_keys`. It counts only where the audit environment of a vector passes its root (`pruefer_<name>.json`); no auditor outside the corpus has a reason to pass it. It serves to show the cases that need a usable day. Its tokens cannot be issued again: the generator keeps them as frozen inputs and refuses to run if a regenerated statement no longer matches a frozen token. A new set of such tokens needs a new authority with a new root and new pins in `PINS.sha256`. Whoever ran the generator could have kept the key; that is why its root is never an auditor's root.

**The authority E1 of the corpus.** The corpus contains two such authorities, E1 and E2 (§13.2). Its input `appliance/cmd/vektorgen/eingefroren/zeitstempelstelle_e1.json` (format `ledger-testkorpus-zeitstempelstelle/1`) names exactly three certificates and the tokens, no key; the generator copies it unchanged to `zeitstempelstelle_e1.json`:

- `wurzel`: "Testkorpus Zeitstempelwurzel E1 (Schluessel verworfen)", Ed25519, self-signed, serial number 1, valid from 2025-01-01 to 2036-01-01, basicConstraints cA and keyUsage keyCertSign, both critical; SHA-256 of the certificate `8cc6b26e7d6c5e9d643d44b7cb6219a18131e45eae54dba715d9770801ee709c`, SPKI SHA-256 `596a543ec10239b2d08e7230b38b4e5bac7531758c9b83a3d75c59acc7c604ac`.
- `signierer`: "Testkorpus Zeitstempelstelle E1 (Schluessel verworfen)", serial number 2, valid from 2025-06-01 to 2031-01-01, keyUsage digitalSignature and extKeyUsage exactly `id-kp-timeStamping`, both critical; SPKI SHA-256 `5babaa3dda6221b13273c3843e98a07ec07dd61dca3e9c165c083860dd555429`.
- `signierer_qs`: "Testkorpus Zeitstempelstelle E1 qcStatements (Schluessel verworfen)", serial number 3, otherwise as `signierer`; SPKI SHA-256 `5ebf2a484ceecb25d5f1e8ee7c0022b5957b8e681a8bfe63f6465e2bff0a73a2`. Its tokens carry in the TSTInfo the extension `qcStatements` with `esi4-qtstStatement-1` (rule QS: `present`, format specification 7.5.6), for the conditions (4) and (7) of the evidence level.
- `token`: 31 tokens, each under the name `<vector>/<label>` or `protokoll/2026-03-01`, serial numbers `0x3001` to `0x301e` and `0x3100`.

Every token follows profile Z (format specification 7.5): Ed25519, the imprint with sha256 over `UTF-8(statement_jcs)` or, for the `TIME_ANCHOR`, over the checkpoint's signing subject, `digestAlgorithm` id-sha512 next to Ed25519 (RFC 8419), signingCertificateV2 with SHA-256 over the signer certificate (Z.6) and the signer certificate in `certificates` (`certReq`). A token of E1 is therefore confirmed for the purpose `log` and for the purpose `chain` wherever the audit environment passes the root of E1 for that purpose; the exception is the token of `log_witnessed_reason_z6_not_checkable`, whose signingCertificateV2 names SHA-1. The tokens show the three window classes of format specification 7.4.6: witnessing (`genTime` one second after `server_ts`), premature (`log_witnessed_premature_stamp`) and late (`log_witnessed_reason_late`, `log_witnessed_window_bounds`, `log_witnessed_qualified_stamp`).

The keys of E1 were created in a single run of `vektorgen -einmalige-stelle appliance/cmd/vektorgen/eingefroren` from `crypto/rand` in memory; the root certified the signers, the signers issued every token the corpus needs, and the run wrote only certificates and tokens and cleared the keys before it ended. This mode never overwrites the file. Every other run of the generator holds each token to the request from which it would build it again: apart from the signature the token must be equal byte for byte, and the signature must hold under the frozen signer certificate. A missing token, a deviating one and one no vector asks for end the run.

### 11.3 Vectors

The tables first state exit and findings with the audit environment of the corpus (without vendor log), then with `pruefer_<name>.json`.

**Witnessing of the day** (steps L2 (d) and (h), L8 case 4). Each vector shows a reason of `day_not_witnessed` where the specification names one; the finding names the reason, not the expected file.

| Vector | Construction and the vector's audit environment | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `log_day_test_authority` | honest extract, the test authority's root with `--vendor-log-tsa-root`: the day 2026-01-02 is established but not witnessed (reason `published_test_key`); first receipt `unchecked` with `day_not_witnessed`, second `pending` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_reason_no_timestamp` | the day object carries no time stamp: reason `no_timestamp` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_reason_no_log_root` | without `--vendor-log-tsa-root`: reason `no_log_root_supplied` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_reason_chain_root_only` | the test root only with `--tsa-root` (purpose `chain`): reason `no_log_root_supplied` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_reason_outside_profile` | time stamp without `certificates`: step 5 not performable, reason `outside_profile` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_reason_not_chained` | root of the probe authority with `--vendor-log-tsa-root`: no path, reason `not_chained_to_log_root` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_qualified_log_root` | the test root also in `--tsa-qualified-roots`: `log_day_qualified` ends at `no_receipt_included` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_timestamp_imprint_wrong` | the only time stamp covers other bytes: defective; no finding on `day_not_witnessed`, since every time stamp of c(d) is defective | 0 | - | 1 | `VENDOR_LOG_DEFECTIVE` |
| `log_timestamp_z6_violated` | the only time stamp without an ESS attribute: Z.6 violated, defective for day entries | 0 | - | 1 | `VENDOR_LOG_DEFECTIVE` |
| `log_timestamps_early_late_test_key` | `server_ts` 00:00:20; time stamps with `genTime` 00:00:30 (premature) and `20260105000000Z` (late) of the test authority: not confirmed, no contradiction, reason `published_test_key` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |

**Protocol keys and signatures** (steps L1, L2 (a), (b), (e), (f); additional signatures of 7.4.8). Without an effective protocol key L2 to L9 are dropped and the receipt classes stay undetermined; the finding names the reason.

| Vector | Construction and the vector's audit environment | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `log_no_list` | `protocol_keys` `null`, no pin: status `no_protocol_key` (`no_list`), receipt classes undetermined | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_list_no_matching_root` | list with `wurzel_id` `testwurzel-2`: `no_matching_root` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_list_signature_fails` | list under `testwurzel-1` signed with the key of `vendor-test-002`: `signature_fails` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_list_format_violated` | list with a member `kommentar` in a key: `format_violated` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_lists_same_version_differ` | a second list of version 1 with another `ausgestellt` via `--vendor-key-list`: `lists_contradictory` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_list_key_dropped` | version 2 without `vendor-log-test-002`: `lists_contradictory` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_lists_filler_commitment_differ` | version 2 with another `fuellerbindung`: `lists_contradictory` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_list_key_in_two_roles` | list with `vendor-log-test-003` and the public key of `vendor-test-001`: `key_in_two_roles`, the corpus pin stays | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_list_log_id_differs` | list with `log_id` `ledger-testprotokoll-2`: `log_id_differs` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_pin_only` | no list, `--vendor-log-key` `vendor-log-test-001`: F from the entries' `first_day`, otherwise as `log_day_test_authority` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_pin_first_day_contradictory` | the pin alone; entries for 2026-01-01 (`first_day` 2025-12-31) and 2026-01-02 (`first_day` 2026-01-02): contradiction without day, every receipt `unchecked` with `first_day_contradictory` | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION` |
| `log_pin_dropped` | pin `vendor-log-test-001` with the public key of `vendor-test-002`, the corpus list of countersigning keys via `--vendor-key-list`: the pin is dropped, `no_protocol_key` with the reason `key_in_two_roles` (7.4.10 L1 item 4) | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_key_not_established` | day entry under `vendor-test-002`: key not established; the due day has no established entry, first receipt `missing` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_signature_fails` | the day entry's signature does not hold: not established, first receipt `missing` | 0 | - | 1 | `VENDOR_LOG_DEFECTIVE`, `VENDOR_LOG_UNVERIFIED` |
| `log_additional_signature_fails` | an additional `ed25519` signature of `vendor-log-test-002` that does not hold: the entry stays established | 0 | - | 1 | `VENDOR_LOG_DEFECTIVE`, `VENDOR_LOG_UNVERIFIED` |
| `log_key_revoked` | version 2 revokes `vendor-log-test-001` from 2026-01-03T03:00; the day carries only its signature: validity ended, first receipt `missing` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_resigned_after_revocation` | the same revocation; the day carries the re-signature of `vendor-log-test-002` in `additional_signatures`: established | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_additional_signature_unknown_alg` | an additional signature with `alg` `ecdsa-p256-sha256`: counted (`signatures_not_checked` 1), never checked | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |

**Signed contents** (steps L2 (c) and (g), L3, L5).

| Vector | Construction and the vector's audit environment | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `log_entry_format_violation` | signed entry with `server_ts` `2026-01-03T00:05:00Z`: violates the format, first receipt `missing` | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION`, `VENDOR_LOG_UNVERIFIED` |
| `log_entry_not_json` | a second day object with the signed `statement_jcs` `kein JSON`: contradiction without day | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION`, `VENDOR_LOG_UNVERIFIED` |
| `log_rule_server_ts_before_day_end` | `server_ts` `2026-01-02T23:59:59.999Z`: violates a rule, first receipt `missing` | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION`, `VENDOR_LOG_UNVERIFIED` |
| `log_rule_prev_hash_zero` | `prev_hash` of 64 zeros: violates a rule, first receipt `missing` | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION`, `VENDOR_LOG_UNVERIFIED` |
| `log_rule_day_before_start` | a further signed entry for 2025-12-30: contradiction on a day outside [Lo, T], `receipts_logged` stays at `day_timestamp_not_confirmed` | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION`, `VENDOR_LOG_UNVERIFIED` |
| `log_two_versions` | the day 2026-01-02 closed twice (00:05 and 00:35, the same root): two versions, first receipt `unchecked` with `day_contradictory` | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION` |
| `log_prev_hash_broken` | `prev_hash` of 2026-01-02 is the day hash of a new closing of 2026-01-01 at 00:35 that is not supplied | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION`, `VENDOR_LOG_UNVERIFIED` |
| `log_skips_day` | extract with 2025-12-31 and 2026-01-02, which links to 2025-12-31: skips 2026-01-01 | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION`, `VENDOR_LOG_UNVERIFIED` |

**Requested range and receipt classes** (steps L7 and L8).

| Vector | Construction and the vector's audit environment | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `log_day_missing` | extract up to 2026-01-01 (chain absent): the due day 2026-01-02 is missing, first receipt `missing` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_receipt_future` | checked at 23:49 on 2026-01-02, extract up to 2026-01-01: second receipt `future`, first `pending` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_receipts_pending` | checked at 00:10 on 2026-01-03, extract up to 2026-01-01: both receipts `pending` | 0 | - | 0 | - |
| `log_receipts_before_start` | chain on 2025-12-30 (receipts 23:35:01 and 23:45:01), checked at 23:50, extract without days: both `before_start`, reason `receipts_before_log_start` | 0 | - | 0 | - |

**Records and extracts** (step L6, section 7.4.8). No day of these vectors is usable (§11.2): records are passed over and counted in no member of the report.

| Vector | Construction and the vector's audit environment | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `log_record_not_holding` | record with a wrong `leaf_index` on a day that is not usable: passed over, counted in no member | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_two_records` | a second extract of the same chain with an `absent` record for the same day: not used, no contradiction | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_padded_day` | the day 2026-01-02 under the size rule: 1023 fillers, a path of 10 hashes | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_absence_between_fillers` | extract from 2026-01-01: `absent` record with two fillers as neighbours (leaf indices 1 and 2) | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_foreign_chain_records` | a second extract of another chain with a record on the same day: `foreign_chain_records` 1 | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_mirror_extract` | mirror extracts `2025.json` and `2026.json` (`chain_id` `null`, no records) | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_extract_server_ts_other_form` | `server_ts` of a root without fraction: the grammar holds, the record is not used | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |

**Witnessed days** (time-stamping authority E1, §11.2; steps L2 (d), (e), (h), L3, L6, L8 cases 3 to 5, L9; decisions B and D on L2 and on L7, L8 and r5′). The audit environment passes the root of E1 with `--vendor-log-tsa-root`. Unless stated otherwise the day 2026-01-02 is witnessed with its `present` chain-day record, the first receipt is `included`, the second `pending`, `logged_roots.matching_prefix` is 1 and `receipts_logged` holds up to `tree_size` 5.

| Vector | Construction and the vector's audit environment | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `log_witnessed_included` | honest extract, the day stamped by E1 (`genTime` `20260103000501Z`, witnessing), `present` record: first receipt `included`, `days.witnessed` 1, head witnessed | 0 | - | 0 | - |
| `log_witnessed_not_included` | the chain-day leaf of the witnessed day carries a fresh repeat of the countersignature of `tree_size` 5 (`server_ts` 23:58:00.000Z), not the package's receipt: `not_included`; `matching_prefix` 1, `matching_without_receipt` 1 | 0 | - | 1 | `RECEIPT_NOT_LOGGED` |
| `log_witnessed_no_record` | witnessed day without a chain-day record: first receipt `unchecked` with `no_record`, `logged_roots` all 0 | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_witnessed_record_failed` | the only record names a wrong `leaf_index`: state failed, `unchecked` with `record_failed` | 0 | - | 1 | `VENDOR_LOG_DEFECTIVE` |
| `log_witnessed_record_contradictory` | the holding `present` record carries, next to the receipt, a gap witness with `server_ts` on 2026-01-03: leaf of another day, state contradictory, `unchecked` with `record_contradictory`, L9 checks no root | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION` |
| `log_witnessed_reason_late` | the only time stamp confirmed, `genTime` `20260105000000Z`, exactly end(d) + W: late, day not witnessed, `unchecked` with `day_not_witnessed`, reason `late` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_witnessed_premature_stamp` | `server_ts` 00:00:20; confirmed time stamps with `genTime` `20260103000059.9999Z` (cut to milliseconds 00:00:59.999, premature) and `20260103000501Z` (witnessing): day closed before its end, entry broken, c(d) undetermined, no head, `unchecked` with `day_contradictory` | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION` |
| `log_witnessed_window_bounds` | `server_ts` 00:00:30; time stamps with `genTime` exactly end(d) + 60 000 (`20260103000100Z`, witnessing) and exactly end(d) + W (`20260105000000Z`, late): witnessed, `included` | 0 | - | 0 | - |
| `log_witnessed_two_versions_one_witnessed` | a second signed version of the day (00:35) without time stamp: two versions, the witnessed one stays c(d), first receipt `included`; the contradiction lies in [Lo, T], `receipts_logged` ends at `vendor_log_contradiction` | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION` |
| `log_witnessed_two_versions_both_witnessed` | both versions witnessed: c(d) undetermined, no head, `unchecked` with `day_contradictory` | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION` |
| `log_witnessed_key_revoked_signed_before` | version 2 via `--vendor-key-list` revokes `vendor-log-test-001` from `2026-01-03T00:05:01.0000005Z`; confirmed time stamp with `genTime` `20260103000501.0000001Z`, before it to the nanosecond: the pair holds, `included`; `key_list.version` 2 | 0 | - | 0 | - |
| `log_witnessed_key_revoked_signed_after` | the same revocation, `genTime` `20260103000501.0000009Z`, after it to the nanosecond (cut to milliseconds it would lie before it): validity ended, the due day is missing, first receipt `missing` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_witnessed_resigned_after_revocation` | version 2 revokes `vendor-log-test-001` from 00:03:00, the time stamp (00:05:01) lies after it; the additional `ed25519` signature of `vendor-log-test-002` holds: established, witnessed, `included` | 0 | - | 0 | - |
| `log_witnessed_absent_empty_day` | witnessed day without leaves (`tree_size` 0): `absent` record of form (i) without neighbours, `not_included`, `logged_roots` all 0 | 0 | - | 1 | `RECEIPT_NOT_LOGGED` |
| `log_witnessed_absent_before_first` | witnessed day of the fillers 0 to 3 without the chain: `absent` record of form (ii), the neighbour a filler at leaf index 0, `not_included` | 0 | - | 1 | `RECEIPT_NOT_LOGGED` |
| `log_witnessed_absent_after_last_filler` | witnessed day of the fillers 0 and 1: form (iii), the neighbour a filler at leaf index 1 = n − 1, `not_included` | 0 | - | 1 | `RECEIPT_NOT_LOGGED` |
| `log_witnessed_absent_between_two_fillers` | witnessed day of the fillers 0 to 3: form (iv), the neighbours two fillers at leaf indices 2 and 3, `not_included` | 0 | - | 1 | `RECEIPT_NOT_LOGGED` |
| `log_witnessed_logged_roots` | `present` record with the receipt, its repeat (23:58:00), two gap witnesses of root(1) (23:50:01 and 23:50:02), a countersignature (3, r) with r ≠ root(3) and one with `tree_size` 20 > N: `matching_prefix` 2, `matching_without_receipt` 1, `contradicting_prefix` 1, `beyond_package` 1, `gap_witnesses` 1; `receipts_logged` up to `tree_size` 2 | 0 | - | 1 | `LOGGED_ROOT_MISMATCH` |
| `log_witnessed_logged_root_mismatch` | `present` record with the receipt and a countersignature (1, r) with r ≠ root(1): t_m = 1 sets the reach of `receipts_logged` to 0, reason `logged_root_mismatch` | 0 | - | 1 | `LOGGED_ROOT_MISMATCH` |
| `log_witnessed_receipt_invalid` | the receipt of `tree_size` 5 names the `TICK` before its checkpoint (signature holds, `RECEIPT_INVALID`), the witnessed record carries its leaf: it has no class (`receipts`: `pending` 1, otherwise 0), `matching_prefix` 1, `matching_without_receipt` 0 | 2 | `RECEIPT_INVALID` | 2 | `RECEIPT_INVALID` |
| `log_receipt_invalid_outside_range` | the same receipt, extract up to 2026-01-01: without it L7 requires no day, no `VENDOR_LOG_UNVERIFIED`, `receipts`: `pending` 1 | 2 | `RECEIPT_INVALID` | 2 | `RECEIPT_INVALID` |
| `log_witnessed_day_1999` | next to the witnessed day a signed entry with `day` `1999-12-31`: contradiction on that day (`days.contradictory` 1), outside [Lo, T]; `receipts_logged` holds | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION` |
| `log_witnessed_reason_z6_not_checkable` | the only time stamp with signingCertificateV2 over SHA-1: Z.6 not checkable, not confirmed, reason `outside_profile` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_witnessed_qualified_stamp` | a witnessing and a late time stamp of the signer of E1 with `qcStatements`, the root of E1 also in `--tsa-qualified-roots`: `log_day_qualified` holds up to `tree_size` 5 | 0 | - | 0 | - |
| `log_witnessed_qualified_root_plain_stamp` | the same audit environment, the time stamp without `qcStatements`: `log_day_qualified` ends at `no_qualified_statement` | 0 | - | 0 | - |
| `log_witnessed_time_anchor_qualified` | `TIME_ANCHOR` of the signer with `qcStatements` over the checkpoint of `tree_size` 5, the day stamped by the same signer, the root of E1 for `log` and named qualified: `time_witness`, `time_witness_qualified`, `receipts_logged` and `log_day_qualified` hold up to `tree_size` 5, level 2 up to 11; with the audit environment of the corpus `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |

**Grammar of the extract** (step L0): unusable invocation, exit 3 without report.

| Vector | Construction and the vector's audit environment | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `log_extract_unknown_member` | a member `kommentar` at the top level of the extract | 0 | - | 3 | - |
| `log_extract_mirror_with_records` | `chain_id` `null` with a record | 0 | - | 3 | - |
| `log_extract_present_and_absent` | record with `present` and `absent` | 0 | - | 3 | - |
| `log_extract_record_empty` | record with `present` and `absent` both `null` | 0 | - | 3 | - |
| `log_extract_roots_duplicate` | the same root twice in `roots` | 0 | - | 3 | - |
| `log_extract_two_records_one_day` | two records for the same day in one file | 0 | - | 3 | - |
| `log_extract_neighbours_descending` | two neighbours with falling `leaf_index` | 0 | - | 3 | - |
| `log_extracts_log_id_differ` | two extracts with `ledger-testprotokoll-1` and `ledger-testprotokoll-2` | 0 | - | 3 | - |
| `log_extract_ed25519_not_hex128` | an additional `ed25519` signature of 127 hex characters | 0 | - | 3 | - |
| `log_extract_additional_signature_twice` | two equal elements of `additional_signatures` | 0 | - | 3 | - |
| `log_extract_alg_pattern` | `alg` `Ed25519` | 0 | - | 3 | - |
| `log_extract_signature_too_long` | an additional signature of 1025 characters | 0 | - | 3 | - |
| `log_extract_timestamp_too_long` | a time stamp of 21 849 characters | 0 | - | 3 | - |
| `log_extract_five_timestamps` | five time stamps in one day object | 0 | - | 3 | - |
| `log_extract_server_ts_not_rfc3339` | `server_ts` `2026-01-02 23:55:01.000Z` (blank instead of `T`) | 0 | - | 3 | - |
| `log_extract_format_other` | `format` `ledger-protokollauszug/2` | 0 | - | 3 | - |

### 11.4 Reference case `spec/testvectors/protokoll/`

The directory shows the test log as a place of publication carries it (heartbeat specification 9.9, file form), for whoever writes or reads a log: `keys.json` (the protocol key list of version 1), `days/2025/2025-12-31.json` and `days/2026/2026-01-01.json` (the day objects with entry, one time stamp and an empty `additional_signatures`), `leaves/2025/2025-12-31.json` and `leaves/2026/2026-01-01.json` (the day leaves, empty and with five pairs), `2025.json` and `2026.json` (the mirror extracts of the years), `head.json` (the day 2026-01-01), `verluste.json` (`[]`) and `auszug_abwesend_2026-01-01.json`, the extract of a chain without a leaf on that day as `GET /v1/log/extract?chain_id=…&from=2026-01-01&to=2026-01-01` gives it: an `absent` record of form (iv) with candidate 0, a filler, and the chain-day leaf of the reference values as neighbours. The values are byte-identical with the reference values of format specification 7.4.2, 7.4.4 and 7.4.5 (day hash `ef330d20…`, root `0adcf8f0…`); the day leaves pass the checks (a) to (c) of 7.4.9, check (d) does not apply to a test log. A vendor stamps every day at two or more authorities of different operators (heartbeat specification 9.9); the reference case carries one time stamp per day, and the verifier does not check the number of authorities. The reference case is no vector and has no expected file; the generator writes its files, `PINS.sha256` holds them, and the registry names it under `vendor_log.reference_case`. The subdirectory `zweiter_referenztag/` shows the second reference day (below).

**Second reference day** (`zweiter_referenztag/`, format specification 7.4.4). The chain-day root `b48375ab…` of the day 2026-01-01 is an arbitrary value for the computation of the tree; it comes from no rows, and no `present` record can be built for it. The second reference day is therefore a day whose chain-day leaf is that of format specification 7.4.2, so that a `present` record exists for it:

- **Chain and rows:** chain `3cef4d7e-4d65-41d6-912d-90d51fda8982` with `appliance_id` `de431f78-75fd-49ae-b4bf-1cb543b635d1` (the chain of the vector `valid_sealed_export`), `tree_size` 42, `merkle_root` `09b2745bcdf71ea82eff8696868a267edd6de0fcb1c82cc3de0020527dc23dae` (SHA-256 of `LEDGER-BEISPIEL-WURZEL-42`), recorded as gap witness with `server_ts` `2026-03-01T23:58:00.000Z` (leaf hash `6ae954c9cd400501c3cb2600954f229bd90da369e5f51898f204a46beafb70ce`) and countersigned with `2026-03-01T23:59:30.000Z` (leaf hash `b1a9c17ad92c0112bd915a40e050a26a4ab1da47e34528dba51d81811ca7a6c7`).
- **Chain-day leaf:** chain-day root `cde717fc82b66d14826268735294060bbf384f0631072c73f46c52056964efd1`, position `927d08078b4fa065e881fb6f761a660bd2b7afec5be467348492ec1c0ad055a4`, hash of the leaf `43769b392d798a99f880ea91b7fb6ebb545c9d3f312fb6cfcf59313dba929dd0`.
- **Fillers:** the candidates 0 to 3 of the day 2026-03-01 (g(d) = `634cc011ed834c015ef269b3b8d2e9e218ad8c7cbd3216cfe2b3a3e5a8106fb4`) with the positions `93028b66207660e2b221edd4de86b513e48f3463e7b08081569013811a5fbb59`, `c8d352a6c4ba66f7fcabf9654efd9de40dc923b07f206ec205b655d07c07da6d`, `1b37c8dd298c6721d3ba25317209118e53552b899cf54bac84767fc1d223ca2f` and `3824b90f571613ceb94cc09c90ce8587f7402ba1d00b600dc6c0d2156aa00f70`.
- **Day tree:** size 5, root `bc178f7cabe3389335e08cd51dfb33f5edb4ea7749db5fea329e7c7a059bb55b`; the chain stands at leaf index 2, its path is `32c2f3257389ab53dcdc456ed3203edcd6c9ebac86c0a0070c4ed925880dced1`, `1c3377bf07b5b6e6fbe0bf143ffa968fb1e65ac0c7245586e965d1d65a4b0b93`, `a11b9e4b6bf4ac3056df539f224894a012a5e1b27d29b3e2a1427f0931e11212`.
- **Linking:** in the reference log the day 2026-01-01 is followed by the days 2026-01-02 to 2026-02-28 without leaves (`tree_size` 0, `root` SHA-256 of the empty byte string, `server_ts` 00:05:00.000Z of the next day, like 2025-12-31), each with the day hash of the day before as `prev_hash`; the reference case does not show them as files, their entries follow from format specification 7.4.5 (the first has the day hash `21d47c425ce6651f1d6453c8c1390daf31ee50def0f1afe2d9fde97c0bcbdced`). This is the reference log, not that of a vector: the vectors carry leaves of their own on 2026-01-02 (§11.1). The day hash of 2026-02-28 is `ca88598631a4e9200c0756a960e2b9b48daff57dc92f03975eca0176b62fac0b` and thus the `prev_hash` of 2026-03-01.
- **Day entry:** `server_ts` `2026-03-02T00:05:00.000Z`, 319 characters, day hash `343e886a3cd81c44e063747f2cf5a96ecf779541f256a0e96102e994e7614c60`, signed with `vendor-log-test-001`, one time stamp of the signer of E1 (§11.2, serial number `0x3100`, `genTime` `20260302000501Z`, witnessing).
- **Files:** `days/2026/2026-03-01.json` (the day object), `leaves/2026/2026-03-01.json` (five pairs), `auszug_vorhanden_2026-03-01.json`, the extract as `GET /v1/log/extract?chain_id=3cef4d7e-4d65-41d6-912d-90d51fda8982&from=2026-03-01&to=2026-03-01` gives it, with the `present` record of both rows (leaf index 2, the path above), which holds after `verify_inclusion`, and `zeitstempelwurzel_e1.pem`, the root of E1 (SPKI SHA-256 `596a543ec10239b2d08e7230b38b4e5bac7531758c9b83a3d75c59acc7c604ac`).

The day leaves pass the checks (a) to (c) of 7.4.9. With the root of E1 for the purpose `log` the day is witnessed; no auditor outside the corpus has a reason to pass it (format specification 7.5.7). The rows are the example values of 7.4.2, not receipts of a package of the corpus; the reference day shows the construction and the record, and `TestZweiterReferenztag` recomputes both.





## 12. Anchor history v2 and affiliation of specification 1.10 (group `history`)

115 vectors of the group `history` check the auditor input of format specification 8.8: the files of the anchor history (8.8.2), the keys of the pages (8.8.3), the steps H0 to H13 (8.8.4), the classification of the history roots (8.8.5) and the affiliation over the span of the package (8.8.6), with pages of kind v2 after heartbeat specification §9.7 and the statement on affiliation after §9.10. They declare `spec_version` `1.10`, except `history_reference_page` with the package of `valid_sealed_export` (`1.9`). Their expectations stand in the registry, each with its reason and section in the member `why`, derived from the text of the specification. The expected file does not name the report objects `anchor_history` and `affiliation` (10.10.2); the status of the affiliation stands in `evidence_level.affiliation`, the other values stand in the row's description where a vector is about them.

### 12.1 Package, pages and audit environment

**Package.** Most vectors carry the one-hour standard chain of the corpus with their own `chain_id` and `appliance_id`: `GENESIS` at 00:00 on 2026-01-01, two AI calls, 5-minute cadence, receipts under `vendor-test-001` at 00:30:01 (`tree_size` 15) and 01:00:01 (`tree_size` 28), sealed at 01:01 with `SEAL(shutdown)` and its immediate checkpoint (N = 32), checked at 01:03:00.500. With the audit environment of the corpus such a package gives exit 0, level 2 up to `tree_size` 28 and the affiliation `not_checked`. Differing from that, the vectors of step H10 (§12.7) carry the same chain on 2026-10-05, after the cut-off date `legacy_boundary` 2026-10-04 of the registry; there `history_receipt_unverified_not_in_history` receipts under `vendor-test-002`, which no pin establishes (`RECEIPT_UNVERIFIED`, level 0). The vectors of a chain succession (§12.6) name a predecessor chain L of the same appliance, handed over at `tree_size` 40, in `GENESIS.predecessor_chain`; the two vectors of a successor chain (`history_successor_linked`, `history_successor_mismatch`) carry the standard package, and its page names the successor chain S of the same appliance with `successor` {S, 32}, handed over at the end of the package. `history_reference_page` carries the package of `valid_sealed_export` byte for byte, the vectors of step H7 (§12.7) the package and the extract of `log_witnessed_included` or `log_witnessed_logged_roots` (§11.3), so that the day 2026-01-02 of the test log is usable with the frozen tokens of E1 (with the audit environment of the corpus exit 0, level 2 up to `tree_size` 10, §11.1).

**Pages.** The generator builds every page after heartbeat specification §9.7 (kind v2, JCS, printable ASCII) and signs it with `vendor-statements-test-001` unless the row says otherwise; `owner_keys` names the owner commitment of `appliance_id`, `chain_id` and device key of the package. The honest page names every receipt of the package as a countersigned root with its `server_ts`, `reference_tree_size` 28, `since_tree_size` 0 without continuation, no fork finding, `known_since` `2025-12-01T00:00:00.000Z` and no period, and it is issued at 01:02:00.000; with the package of `valid_sealed_export` it is the reference page of format specification 8.8.2 (776 characters, SHA-256 `6fe4cc5f…`). Each page file is the response body with `statement_jcs`, `server_key_id`, `server_signature` and the reading copy `statement`; a container `ledger-ankerhistorie/2` carries pages and extracts. A second page of the same chain is issued at 01:02:05.000 (A and B in §12.4).

**Audit environment.** `pruefer_<name>.json` passes the anchors of the corpus (`korpus` `true`), the role list of version 1 of format specification 10.7.2 with `--vendor-key-list` (or a pin with `--vendor-statement-key` where the row says so), the files of the anchor history with `--anchor-history` and the request time R = `2026-01-01T00:58:00.000Z` with `--requested-at`, the value of the reference values of 8.8.5 and 8.8.6 (R − W_h = 00:43:00.000). For the chain of 2026-10-05 R is `2026-10-05T01:02:00.000Z` with pages of 01:02:30, for the vectors of step H7 R is `2026-01-03T06:00:00.000Z` with pages of 06:10 and the root of E1 with `--vendor-log-tsa-root`. If, with R, no page of the package is used fresh, the union of step H4 covers nothing, the gap is [0, ∞), and `pages_missing` is added; the rows say so.

**Three reference values.** The reference values of 8.8.5 name N = 32 for `valid_sealed_export` with its receipts at 15 and 28; the roots beyond the package lie at `tree_size` 33 to 35. The reference value of 8.8.6 "no fresh page, issued 00:42:30 with `known_since` 00:42:00" is shown by `history_stale_known_since_late`, the reference value "only one period `former_relation` from 2025-06-01 to 2025-12-01" (a relation that ended on 2023-12-01, 24 months later, clipped to the activation; the server derives no further period from it, heartbeat specification §9.10) by `history_not_affiliated_period_before_24_months` (§14.3). The frozen vector `history_not_affiliated_period_before` carries the same case with the end 2025-11-30 after 730 days, as the reference value read before the decisions of 26.10.; the verifier reads `until` and computes no end, so its expectation stands unchanged.

`TestAnkerhistorieVektoren`, `TestAnkerhistorieReferenzseite`, `TestAnkerhistorieSeiten`, `TestAnkerhistoriePruefumgebungen` and `TestAnkerhistorieTabellenFolgenDerErwartung` (`appliance/cmd/vektorgen`) hold packages, pages, signatures, page rules, audit environments and the tables against the bytes and against `expected/`. The tables first state exit and findings with the audit environment of the corpus (without anchor history), then with `pruefer_<name>.json`.

### 12.2 Files, keys and pages (steps H0 to H2)

Exit 3 without findings (`-`) means: unusable invocation, no report (8.8.2, 10.8).

| Vector | Construction and the vector's audit environment | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `history_honest_role_list` | honest page under `vendor-statements-test-001` from the role list of version 1, issued 01:02:00, R = 00:58:00: fresh, coverage complete, roots 15 and 28 found; completeness `established` up to 28, affiliation `not_affiliated` | 0 | - | 0 | - |
| `history_honest_pinned` | the same page, key pinned with `--vendor-statement-key`, no role list: the pin establishes the page without a validity window | 0 | - | 0 | - |
| `history_reference_page` | the package of `valid_sealed_export` byte for byte with the reference page of 8.8.2 (776 characters, SHA-256 `6fe4cc5f…`, owner commitment `d0184bb5…`) | 0 | - | 0 | - |
| `history_container` | the honest page in a container `ledger-ankerhistorie/2` with an empty `vendor_log` | 0 | - | 0 | - |
| `history_pages_duplicate` | the same page twice in a container and once as a file: one page (H1, `supplied` 3, `distinct` 1) | 0 | - | 0 | - |
| `history_statement_copy_ignored` | the unsigned copy `statement` names `known_since` `null` and an open period `vendor`; only `statement_jcs` is read: `not_affiliated` | 0 | - | 0 | - |
| `history_pair_bad_signature_beside_good` | one page with two pairs: `vendor-statements-test-001` holds, `vendor-statements-test-002` does not: the page is used, the pair under the established key gives `signature`; completeness `established` | 0 | - | 1 | `ANCHOR_HISTORY_DEFECTIVE` |
| `history_pair_other_role_beside_good` | one page with the pairs under `vendor-statements-test-001` and under the countersigning key `vendor-test-001`, both holding: used, no finding | 0 | - | 0 | - |
| `history_key_not_established` | page under `vendor-statements-test-002`, only `vendor-statements-test-001` pinned, no role list: `key_not_established`; without a fresh used page also `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_key_countersigning` | page under the countersigning key `vendor-test-001` (pinned, in the role list with `countersigning`): `key_other_role`, also `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_key_update_manifest` | page under `vendor-update-manifest-test-001` (rolle `update_manifest`): `key_other_role`, also `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_key_pin_dropped` | statements pin `vendor-statements-pin-1` with the public key of `vendor-update-manifest-test-001`: the pin is dropped; the page names its `key_id`: `key_not_established`, also `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_signature_defective` | the honest page with one hex digit of the signature changed: `signature`, also `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_DEFECTIVE`, `ANCHOR_HISTORY_UNVERIFIED` |
| `history_page_v1` | page of kind v1 with the roots of the package under `vendor-statements-test-001`: `not_v2`, also `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_page_v1_countersigning` | the same page of kind v1 under `vendor-test-001`, as in dual operation: `key_other_role` (item 1 before item 4), also `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_page_other_kind` | a licence statement `ledger.license_statement.v1` under `vendor-statements-test-001` as an anchor history file: `not_v2`, also `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_page_not_json` | `statement_jcs` is text, no JSON, signed under an established key: no exit 3, `page_rules`, also `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION`, `ANCHOR_HISTORY_UNVERIFIED` |
| `history_page_not_jcs` | `statement_jcs` with a blank after the first comma: not its own JCS form, `page_rules`, also `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION`, `ANCHOR_HISTORY_UNVERIFIED` |
| `history_page_extra_member` | page with a member `comment`: `page_rules`, also `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION`, `ANCHOR_HISTORY_UNVERIFIED` |
| `history_page_time_form` | `server_ts` of the page `2026-01-01T01:02:00Z` without milliseconds: `page_rules`, also `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION`, `ANCHOR_HISTORY_UNVERIFIED` |
| `history_page_rules_known_since` | `known_since` 01:02:01 after `server_ts` 01:02:00 (page rule 9): `page_rules`, also `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION`, `ANCHOR_HISTORY_UNVERIFIED` |
| `history_page_rules_periods_adjoining` | two adjoining periods with the same `bases` (page rule 10): `page_rules`, also `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION`, `ANCHOR_HISTORY_UNVERIFIED` |
| `history_page_rules_reference` | `reference_tree_size` 15 beside a countersigned root at 28 (page rule 6): `page_rules`, also `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION`, `ANCHOR_HISTORY_UNVERIFIED` |
| `history_page_rules_beside_honest` | honest page and a second page of chain C whose roots descend (page rule 3): `page_rules`, hindering: completeness `partial` (`contradiction`) | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_page_rules_other_chain` | honest page and a page of another chain breaking a page rule: `page_rules`, not hindering: completeness `established` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_root_ts_legacy_form` | root 15 with `server_ts` `2026-01-01T00:30:01Z`, the stored string of a root recorded earlier: allowed | 0 | - | 0 | - |
| `history_key_expired` | role list with `gueltig_bis` 01:00:00 for `vendor-statements-test-001`, page 01:02:00: `key_not_valid`, also `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_key_revoked_before_issue` | role list version 2 revokes `vendor-statements-test-001` from 00:00, before the page of 01:02:00: `key_not_valid`, also `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_key_revoked_fresh` | role list version 2 revokes `vendor-statements-test-001` from 01:02:30, after the page; the page is fresh: used | 0 | - | 0 | - |
| `history_key_revoked_no_request_time` | the same revocation without `--requested-at`: `signing_time_not_proven`; completeness `no_request_time` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_key_revoked_stale` | the same revocation, page of 00:40:00 before R − W_h: `signing_time_not_proven`, also `issued_before_request` and `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_key_revoked_pinned_fresh` | `vendor-statements-test-001` pinned, the role list revokes it from 00:00 before the page: the pin has no window, the page is fresh: used | 0 | - | 0 | - |
| `history_key_planned_change_no_request_time` | role list with `gueltig_bis` 02:00 (planned change), without R: used (`used_unjudged`); completeness `no_request_time` | 0 | - | 0 | - |
| `history_other_chain` | page of another `chain_id`, linked to nothing: `other_chain`, also `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_owner_differs` | page of chain C with the owner commitment of another `appliance_id`: `owner_differs`, also `pages_missing`; completeness `owner_differs` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_owner_differs_beside_honest` | honest page and a page of another device: `owner_differs`, not hindering: completeness `established` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_owner_keys_superset` | `owner_keys` with the commitment of the package's device key and that of a further key: one common element suffices | 0 | - | 0 | - |
| `history_container_extra_member` | container with a member `kommentar` | 0 | - | 3 | - |
| `history_container_format_other` | object with `format` `ledger-ankerhistorie/1` | 0 | - | 3 | - |
| `history_container_no_pages` | container with `pages` `[]` | 0 | - | 3 | - |
| `history_container_extract_grammar` | container with an embedded extract that carries a member `kommentar` | 0 | - | 3 | - |
| `history_page_member_missing` | page file without the member `statement` | 0 | - | 3 | - |
| `history_page_key_id_grammar` | `server_key_id` `vendor statements test 001` (blanks) | 0 | - | 3 | - |
| `history_page_signature_form` | `server_signature` of 126 hex digits | 0 | - | 3 | - |
| `history_page_jcs_empty` | `statement_jcs` is the empty string | 0 | - | 3 | - |
| `history_page_duplicate_member` | page file with the member `server_key_id` twice (same value): no I-JSON | 0 | - | 3 | - |

### 12.3 Issue and coverage (steps H3, H4)

| Vector | Construction and the vector's audit environment | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `history_issued_before_request` | one page of 00:40:00 with the root 15, before R − W_h: `issued_before_request` and `pages_missing`; root 15 found, affiliation `not_determined` (`statement_does_not_cover_package`) | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_stale_known_since_late` | one page of 00:42:30 with `known_since` 00:42:00: `statement_does_not_cover_package` before `known_range_too_short`; also `issued_before_request` and `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_archive_pages` | older page of 00:40:00 beside the fresh one: note `archive_pages`, no finding | 0 | - | 0 | - |
| `history_coverage_split` | two fresh pages [0, 16) and [16, ∞): coverage `complete` | 0 | - | 0 | - |
| `history_coverage_overlap` | three fresh pages [0, 16), [0, 20) and [20, ∞) with shifted boundaries: coverage `complete` | 0 | - | 0 | - |
| `history_coverage_gap` | only a page with `since_tree_size` 20: gap [0, 20), `pages_missing`; completeness `partial`, affiliation `not_determined` (`history_pages_missing`) | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_coverage_gap_no_request_time` | the same page without R: coverage only as information, no finding; affiliation `not_determined` | 0 | - | 0 | - |

### 12.4 Pages among each other (step H5)

A is the page of 01:02:00, B the one of 01:02:05, both fresh, unless the row says otherwise.

| Vector | Construction and the vector's audit environment | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `history_root_time_differs` | B names root 15 with `server_ts` 00:30:02 instead of 00:30:01: `root_time_differs` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_root_dropped` | root 15 of A is missing on B: `root_dropped` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_root_withheld` | A names only root 28, B also root 15 of 00:30:01, before A.`server_ts` − W_h: `root_withheld` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_root_recorded_in_band` | B also names the reported root 24 of 00:50:01, after A.`server_ts` − W_h: no reason | 0 | - | 0 | - |
| `history_fork_dropped` | fork finding at 20 on A, B without it and with `forks_omitted` 0: `fork_dropped` and `fork_listed` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION`, `ANCHOR_HISTORY_FORK` |
| `history_affiliation_narrowed` | A with an open period `common_control`, B ends it at 01:00:00, before A: `affiliation_narrowed`; `affiliated`, `contradictory` `true` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_affiliation_ended_after_issue` | B ends the open period of A at 01:02:03, after A: no reason; `affiliated` | 0 | - | 0 | - |
| `history_affiliation_split_view` | A with an open period, B five seconds later without a period: `affiliation_narrowed` (shared view); `affiliated` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_affiliation_older_page` | older page of 00:10:00 with an open period, H* of 01:02:00 without: `affiliation_narrowed`; the period ends at 00:10:00: `not_affiliated`, `contradictory` `true` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_affiliation_withheld` | B names a period `former_relation` 2025-06-01 to 2025-11-30, entered long before A, which A does not show: `affiliation_withheld` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_affiliation_added_late` | B names an open period `participation` from 00:50:00, entered at 01:02:02 after A: no reason; `affiliated` | 0 | - | 0 | - |
| `history_affiliation_merged` | A with 16 periods, B merges the earliest ones after a 17th (`merged` `true`): an extension, no reason; `affiliated` | 0 | - | 0 | - |
| `history_affiliation_merged_gap` | A with 16 periods `participation`, three days of every week from 2025-06-01 with gaps between them, all entered on 2025-06-01; after a 17th, B merges the two earliest across the gap (`merged` `true`, `recorded_ts` more than W_h before A): a merged period never gives `affiliation_withheld`, no reason; `affiliated`, `contradictory` `false` | 0 | - | 0 | - |
| `history_affiliation_gap_not_merged` | the same pages, the first period of B with `merged` `false`: in the gap B names an affiliation, entered more than W_h before A, and A does not: `affiliation_withheld`, hindering; `affiliated`, `contradictory` `true` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_known_since_narrowed` | B moves `known_since` to 00:45:00, before A.`server_ts`: `known_range_narrowed`; `not_determined` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_known_since_null_after_takeover` | B names `known_since` `null`, as after a takeover: no reason; `not_determined` | 0 | - | 0 | - |
| `history_known_since_after_issue` | B moves `known_since` to 01:02:01, after A.`server_ts`: no reason; `not_determined` | 0 | - | 0 | - |
| `history_owner_keys_dropped` | A with two owner commitments, B with one: `owner_keys_dropped` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_succession_changed` | A names a successor at 32, B none: `succession_changed` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_reference_decreases` | B with `reference_tree_size` 15 after the 28 of A: `reference_decreases` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |

### 12.5 Classification of the history roots (steps H6, H8, format specification 8.8.5)

A differing root is a root of the page whose `merkle_root` is not `root(t)` of the package. Only a countersigned root or one recorded as gap witness, recorded before R − W_h, gives `MERKLE_INCONSISTENT`; a root that is only reported never does.

| Vector | Construction and the vector's audit environment | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `history_root_differs_before_band` | countersigned differing root at 20 with e = 00:42:59.999: `MERKLE_INCONSISTENT` | 0 | - | 2 | `MERKLE_INCONSISTENT` |
| `history_root_differs_in_band` | countersigned differing root at 21 with e = 00:43:00.000 (boundary in the band): `history_root_differs` | 0 | - | 1 | `ANCHOR_HISTORY_FORK` |
| `history_root_beyond_before_band` | countersigned root at 33 beyond the package with e = 00:42:59.999: `MERKLE_INCONSISTENT`, note `package_ended_before_request` | 0 | - | 2 | `MERKLE_INCONSISTENT` |
| `history_root_beyond_in_band` | countersigned roots at 34 (e = 00:43:00.000) and 35 (e = R) beyond the package: no finding, note `recent_roots_not_found` | 0 | - | 0 | - |
| `history_band_no_request_time` | the roots 20, 21, 33, 34 and 35 without R: 20 and 21 `history_root_differs`, 33 to 35 `beyond_package_unjudged` | 0 | - | 1 | `ANCHOR_HISTORY_FORK` |
| `history_reported_root_differs` | differing root at 20, only reported, e = 00:42:59.999: `history_root_differs`, never exit 2 | 0 | - | 1 | `ANCHOR_HISTORY_FORK` |
| `history_reported_root_beyond` | root at 33, only reported, beyond the package, e = 00:42:59.999: `reported_root_beyond_package` | 0 | - | 1 | `ANCHOR_HISTORY_FORK` |
| `history_gap_witness_then_countersigned` | differing root at 20, gap witness at 00:42:59.999, countersigned at 00:50:00: e = 00:42:59.999, `MERKLE_INCONSISTENT` | 0 | - | 2 | `MERKLE_INCONSISTENT` |
| `history_reported_then_countersigned` | differing root at 20, reported at 00:40:00, countersigned at 00:43:00: e = 00:43:00.000, `history_root_differs` | 0 | - | 1 | `ANCHOR_HISTORY_FORK` |
| `history_reported_root_also_auditor` | differing root at 20, only reported, the same root also with `--expect-root`: rule of 10.8, `MERKLE_INCONSISTENT` | 0 | - | 2 | `MERKLE_INCONSISTENT` |

### 12.6 Fork findings, handover and chain succession (step H9)

| Vector | Construction and the vector's audit environment | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `history_fork_listed` | fork finding at 20 on the page: `fork_listed` | 0 | - | 1 | `ANCHOR_HISTORY_FORK` |
| `history_forks_omitted` | `forks_omitted` 2: `forks_omitted` | 0 | - | 1 | `ANCHOR_HISTORY_FORK` |
| `history_root_beyond_handover` | successor at 20, countersigned root 28 beyond it: `root_beyond_handover`, note `package_beyond_handover` | 0 | - | 1 | `ANCHOR_HISTORY_FORK` |
| `history_reported_beyond_handover` | successor at 28, reported root 31 = root(31): notes `reported_beyond_handover` and `package_beyond_handover`, no finding | 0 | - | 0 | - |
| `history_succession_linked` | chain succession L → C at 40, pages of both chains, the same affiliation: linked page used; package `not_affiliated`, L under `linked` `affiliated` | 0 | - | 0 | - |
| `history_succession_mismatch` | C names `predecessor` {L, 39}, L `successor` {C, 40}: `succession_mismatch` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_predecessor_beyond_handover` | page of L with a countersigned root 41 beyond the handover at 40: `predecessor_beyond_handover`, note `reported_beyond_handover` | 0 | - | 1 | `ANCHOR_HISTORY_FORK` |
| `history_linked_history_not_supplied` | only the page of C with `predecessor` {L, 40}: note `linked_history_not_supplied` | 0 | - | 0 | - |
| `history_predecessor_differs_from_genesis` | the page of C names another predecessor chain than `GENESIS`: notes `predecessor_differs_from_genesis` and `linked_history_not_supplied` | 0 | - | 0 | - |
| `history_linked_contradiction_not_blocking` | two pages of L, the later one without the root 20: `root_dropped` between linked pages, not hindering | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_linked_affiliation_narrowed` | the page of C and a page of L with an open period `common_control`, a later page of L without it: `affiliation_narrowed` between linked pages, not hindering: completeness `established`; package `affiliated` with `contradictory` `false`, L under `linked` `affiliated` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_successor_linked` | standard package; its page names `successor` {S, 32}, the page of S `predecessor` {C, 32}, the owner commitment for S and no root: linked page used, `relation` `successor`, no reason; package and S `not_affiliated` | 0 | - | 0 | - |
| `history_successor_mismatch` | the page of the package names `successor` {S, 32}, the page of S `predecessor` {C, 31}: `succession_mismatch` (S as the successor chain), hindering | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |

### 12.7 Vendor log, receipts and completeness (steps H7, H10, H11)

| Vector | Construction and the vector's audit environment | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `history_log_container` | page and extract of `log_witnessed_included` in one container, page and record agree: no finding | 0 | - | 0 | - |
| `history_log_mismatch` | page names root 5 with `server_ts` 23:55:02, the record 23:55:01: `log_mismatch` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_log_root_missing` | page without the root 5 of the record: `log_root_missing` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_log_gap_witness_times` | package and extract of `log_witnessed_logged_roots`, page with the gap witness 1 of 23:50:01: `gap_witness_time_differs` and `log_root_missing` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION`, `LOGGED_ROOT_MISMATCH` |
| `history_receipts_in_history` | chain of 2026-10-05 after the cut-off date: both receipts `in_history` | 0 | - | 0 | - |
| `history_receipt_server_ts_differs` | page names root 15 at 00:30:00.900, the receipt 00:30:01.000: `in_history` and `server_ts_differs`, no finding | 0 | - | 0 | - |
| `history_receipt_not_in_history` | page without the root of the established receipt of 00:30:01: `receipt_not_in_history` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_receipt_not_covered` | page without root 28, issued less than W_h after its receipt: `not_covered`, no finding | 0 | - | 0 | - |
| `history_receipt_unverified_not_in_history` | receipts under `vendor-test-002`, which no pin establishes; page without root 15: note `receipt_roots_unverified_not_in_history`, level 1 through the anchor history | 1 | `RECEIPT_UNVERIFIED` | 1 | `RECEIPT_UNVERIFIED` |
| `history_no_root_found` | fresh complete page without roots: completeness `partial` (`no_root_found`) | 0 | - | 0 | - |

### 12.8 Affiliation (step H12, format specification 8.8.6)

Span of the package from 00:30:01 to R = 00:58:00, two established receipts, H* fresh, unless the row says otherwise (reference values of 8.8.6).

| Vector | Construction and the vector's audit environment | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `history_affiliated_open` | open period `common_control` from 2025-06-01: `affiliated`, 2 of 2 receipts in the period | 0 | - | 0 | - |
| `history_not_affiliated_period_before` | only a period `former_relation` 2025-06-01 to 2025-11-30 (end after 730 days, before the decisions of 26.10.; with 24 months §14.3): `not_affiliated`, period outside | 0 | - | 0 | - |
| `history_known_since_after_span` | `known_since` 00:45:00: `not_determined` (`known_range_too_short`) | 0 | - | 0 | - |
| `history_known_since_null_open_period` | `known_since` `null` with an open period: `affiliated` | 0 | - | 0 | - |
| `history_affiliated_from_0050` | open period `participation` from 00:50:00: `affiliated`, 1 of 2 receipts in the period | 0 | - | 0 | - |
| `history_vendor_itself` | open period `vendor`: `affiliated`, `vendor_itself` `true` | 0 | - | 0 | - |
| `history_affiliated_no_request_time` | open period without R: `span_to` = `as_of`, `affiliated` | 0 | - | 0 | - |
| `history_affiliated_stale_page` | only an older page of 00:40:00 with an open period: `affiliated` (an older page carries `affiliated`, never `not_affiliated`), also `issued_before_request` and `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_affiliation_ends_in_span` | period `shared_management` until 00:40:00, within the span of the package: `affiliated`, 1 of 2 receipts | 0 | - | 0 | - |

## 13. Evidence level and report members of specification 1.10 (group `evidence`)

26 vectors of the group `evidence` check the evidence level of format specification 10.9 and the report object `evidence_level` (10.10.2): the levels 0 to 3 with reach, segments and the conditions missing for the next level, the reasons of the table of 10.9.4 and the notes of 10.9.6 that no earlier vector shows, the states `chain_invalid` and `format_error` (10.9.2) and condition (7), the second way to level 3, credited and not credited. They declare `spec_version` `1.10`. Their expectations stand in the registry, each with reason and section in member `why`, derived from the text of the specification. The expected file names the evidence level in the short form of §3; reach and count per condition, `basis` and the anchors stand, where a vector is about them, in the description of the row. `next` follows from level and reasons (10.9.5): at a level L below 3 `missing` names the conditions of level L + 1 whose reason is not `null`, in the order of the registry; for level 3, (4) and (7) count as one condition: if neither is met, `missing` names both, if one is met, neither.

### 13.1 Packages and audit environments

**Packages.** Twelve vectors carry the package of a vector of the group `log` byte for byte under their own name, so that the frozen tokens of E1 apply (§11.2): that of `log_witnessed_time_anchor_qualified` (15 entries, receipts at `tree_size` 5 and 11, a `TIME_ANCHOR` of the signer of E1 with qcStatements over the checkpoint of `tree_size` 5, `genTime` 23:55:01 on 2026-01-02; its day 2026-01-02 carries a witnessing stamp of the same signer of 00:05:01 on 2026-01-03), that of `log_witnessed_included` and that of `log_witnessed_qualified_stamp` (14 entries each, receipts at 5 and 10, §11.1). With the audit environment of the corpus the first gives exit 1 with `TIME_ANCHOR_UNVERIFIED` and level 2 up to 11, the two others exit 0 and level 2 up to 10. The other vectors carry the one-hour standard chain of the corpus with their own `chain_id` (N = 32, receipts at 15 and 28, sealed at 01:01, checked two minutes later; level 2 up to 28), changed where the row says so; the vectors with a time witness of E2 carry it 700 ms after the checkpoint of 00:40 (`tree_size` 20; N = 33, receipts at 15 and 29) like the group `timestamp`. `evidence_receipts_after_check_time` carries the script of the group `log` (§11.1), checked at 23:35 on 2026-01-02.

**Audit environment.** Every audit environment contains that of the corpus (`korpus` `true`), so that the monotonicity of 10.9.7 can be checked against the run with the audit environment of the corpus. The vectors on the package of `log_witnessed_time_anchor_qualified` pass, where the row says nothing else, its extract, the root of E1 with `--vendor-log-tsa-root` and in `--tsa-qualified-roots` (named from 2025-01-01), the role list of version 1, the request time R = `2026-01-03T06:00:00.000Z` and the honest page of the anchor history of 06:10 with both receipts (§12.1). `TestBeweisstufeVektoren`, `TestEinmaligeStelleE2Eingefroren`, `TestBeweisstufeEigenschaften`, `TestBeweisstufeMonotonie`, `TestBeweisstufeAbdeckung` and `TestBeweisstufeTabellenFolgenDerErwartung` (`appliance/cmd/vektorgen`) hold packages, the frozen input of E2, the properties 1 to 5 of 10.9.7 at every expected file, the monotonicity between both audit environments, the coverage of reasons, notes, levels and states and the tables against the bytes and against `expected/`.

### 13.2 The time-stamping authority E2

A time witness over the checkpoint of a new chain and a day stamp whose extensions a vector is about need tokens that no frozen token of E1 covers. They come from a second time-stamping authority with discarded keys, E2, created like E1 (§11.2) in a single run of `vektorgen -einmalige-stelle appliance/cmd/vektorgen/eingefroren -stelle E2`. Its input `appliance/cmd/vektorgen/eingefroren/zeitstempelstelle_e2.json` (format `ledger-testkorpus-zeitstempelstelle/1`) names exactly three certificates and the tokens, no key; the generator copies it unchanged to `zeitstempelstelle_e2.json`:

- `wurzel`: "Testkorpus Zeitstempelwurzel E2 (Schluessel verworfen)", Ed25519, self-signed, serial number 1, valid from 2025-01-01 to 2036-01-01, basicConstraints cA and keyUsage keyCertSign, both critical; SHA-256 of the certificate `0ab126bd732ce17cf18945a9fda9afa37c82e22e0b838cb61a6ca2cc08585f63`, SPKI SHA-256 `9c80d27b8fab6d67528271f45a739e58d68876bc1ab88f2fd7cca181a3198a15`.
- `signierer`: "Testkorpus Zeitstempelstelle E2 (Schluessel verworfen)", serial number 2, valid from 2025-06-01 to 2031-01-01, keyUsage digitalSignature and extKeyUsage exactly `id-kp-timeStamping`, both critical; SPKI SHA-256 `3bb8df0932f16a6a2b736ebb42d16d30799ea8ffbe1bc35290ce76c7f1e1318c`.
- `signierer_qs`: "Testkorpus Zeitstempelstelle E2 qcStatements (Schluessel verworfen)", serial number 3, otherwise like `signierer`; SPKI SHA-256 `b0289719598844828b4cb418feee9700a3b7bd9a503710796a3818bc14a1801e`.
- `token`: seven tokens, each under the name `<vector>/<label>`, serial numbers `0x4001` to `0x4007`: the day stamps of `evidence_log_stamp_extensions_unusable` (qcStatements with `esi4-qtstStatement-1` and an unknown critical extension) and `evidence_log_stamp_statement_malformed` (qcStatements with `SEQUENCE { INTEGER 1 }`) over the day entry of `log_witnessed_included`, the time witnesses of `evidence_witness_extensions_unusable` (like the first day stamp), `evidence_witness_certificate_not_bound` (qcStatements, signingCertificateV2 with the hash of the root of the test authority), `evidence_witness_statement_malformed` (two: qcStatements unreadable, no extensions) and `evidence_level_1_time_witness` (no extensions).

Everything §11.2 says of E1 holds for E2: its keys are in no file and not in `published_test_keys`, its tokens cannot be issued again, every other run of the generator holds each token to its request and stops at a missing, deviating or unrequested token, and its root is never an auditor's root; it counts only where `pruefer_<name>.json` passes it.

### 13.3 Vectors

The tables state first exit and findings with the audit environment of the corpus, then with `pruefer_<name>.json`. The description states the segments as "level for `first_seq` to `last_seq`" and `basis` in square brackets; (1) to (7) are the conditions of 10.9.1.

**Level 3, segments and neutrality** (10.9.1, 10.9.5, 10.9.7)

| Vector | Structure and audit environment of the vector | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `evidence_level_3` | package and audit environment of §13.1: (1), (4), (5) and (7) up to 5, (2), (3) and (6) up to 11; r1 = r2 = 11, r3 = 5: level 3 up to 5; 3 for 1 to 5 [`time_witness_qualified`, `receipts_logged`, `log_day_qualified`], 2 for 6 to 11, 0 for 12 to 15; `next` `null`; `qualified_time` via (4) at `tree_size` 5, `latest` `2026-01-02T23:55:01.000Z` (the time witness is earlier than the day stamp); notes `published_test_key_credited`, `receipts_pending_log` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `evidence_level_3_four_segments` | plus the expected root `13:<root(13)>` of the auditor: (2) up to 13 with the sources `auditor` and `anchor_history`, (6) stays at 11; 3 for 1 to 5, 2 for 6 to 11, 1 for 12 to 13 [`expected_root_found`], 0 for 14 to 15 | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `evidence_level_3_affiliated` | the page with an open period `common_control` from 2025-06-01: `affiliated`; level, reach and segments as in `evidence_level_3` (neutrality) | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `evidence_level_2_without_log` | the same anchors and page without extract and without a root for the log: (5) and (7) `vendor_log_not_supplied`, no note `receipts_pending_log`; level 2 up to 11, `next` `{3, all, [receipts_logged]}` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |

**Condition (4): period and root from the package** (10.8, 10.9.1, 10.9.4)

| Vector | Structure and audit environment of the vector | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `evidence_qualified_window_from` | E1 named as qualified only from `2026-01-03T00:00:00Z`: the time witness lies before, (4) `outside_qualified_window`; (1) holds, since for the purpose `chain` the root counts at every time; the day stamp of 00:05:01 lies within the period, (7) holds, the second way to level 3: level 3 up to 5; 3 for 1 to 5 [`receipts_logged`, `log_day_qualified`], 2 for 6 to 11, 0 for 12 to 15; `qualified_time` via (7) at `tree_size` 5 | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `evidence_qualified_window_until` | qualified from 2025-01-01 with `qualifiziert_bis` `2026-01-02T23:55:01Z`, equal to the `genTime` of the time witness (upper bound excluded): (4) and (7) `outside_qualified_window`, (1) holds; level 2 up to 11 | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `evidence_qualified_root_in_package` | the package with the root of E1 in `keys/tsa/zeitstempelwurzel_e1.pem`: (1) holds, note `tsa_root_in_package`; (4) `qualified_root_in_package`; (7) has no such stage and holds, the second way to level 3: level 3 up to 5; 3 for 1 to 5 [`receipts_logged`, `log_day_qualified`], 2 for 6 to 11, 0 for 12 to 15 | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |

**Condition (7): day stamps** (7.4.6, 7.5.7, 10.9.4)

| Vector | Structure and audit environment of the vector | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `evidence_log_stamp_late` | package and extract of `log_witnessed_qualified_stamp` (a witnessing and a late stamp of `2026-01-05T00:00:00Z`, both with qcStatements), E1 for the log and named as qualified only from `2026-01-04T00:00:00Z`: the triple with the witnessing stamp ends at `outside_qualified_window`, that with the late stamp at `qualified_day_stamp_late`, the stage at which the triple that came furthest fails; (5) up to 5 | 0 | - | 0 | - |
| `evidence_log_root_not_chained` | package and extract of `log_witnessed_included`, E1 for the log, the root of the test authority for the log and named as qualified: the day is witnessed by E1, the only root with both purposes is the test root: (7) `not_chained_to_qualified_log_root` | 0 | - | 0 | - |
| `evidence_log_stamp_published_key` | the same day with the stamp of E1 and one of the test authority (`genTime` 00:05:02, not confirmed, no finding), roots as before: (7) `published_test_key` | 0 | - | 0 | - |
| `evidence_log_stamp_extensions_unusable` | the same day only with a stamp of E2 with qcStatements and an unknown critical extension (rule QS: unusable), E2 for the log and named as qualified: the stamp is confirmed and witnesses the day, (5) up to 5; (7) `token_extensions_unusable` | 0 | - | 0 | - |
| `evidence_log_stamp_statement_malformed` | the same day with the stamp of E1 without qcStatements and one of E2 with unreadable qcStatements, both roots for the log and named as qualified: both triples fail at the stage `qualified_statement`, with both results: (7) `qualified_statement_malformed` | 0 | - | 0 | - |

**Conditions (1) and (4): time witnesses of E2** (7.3, 7.5.6, 10.9.4)

| Vector | Structure and audit environment of the vector | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `evidence_witness_extensions_unusable` | time witness at `tree_size` 20 with a token of E2 with qcStatements and an unknown critical extension, E2 named as qualified: step 6 holds; (1) and (4) `token_extensions_unusable`; level 2 up to 29 | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `evidence_witness_certificate_not_bound` | token of E2 with qcStatements whose signingCertificateV2 names another certificate (Z.6 violated, no finding): (1) up to 20, (4) `signing_certificate_not_bound`; level 2 up to 29 | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `evidence_witness_statement_malformed` | two time witnesses of E2 at `tree_size` 20 (qcStatements unreadable) and 23 (no extensions), N = 34, receipts at 15 and 30: (1) up to 23; both pairs fail at `qualified_statement`, with both results: (4) `qualified_statement_malformed`; level 2 up to 30 | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |

**Levels 1 and 0** (10.9.1, 10.9.5)

| Vector | Structure and audit environment of the vector | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `evidence_level_1_time_witness` | receipts under `vendor-test-002` (no pin, no list), time witness of E2 without extensions at `tree_size` 20: with the audit environment of the corpus level 0, `next` `{1, any, [time_witness, expected_root_found, receipt_key_confirmed]}`; with E2 named as qualified (1) up to 20, (4) `no_qualified_statement`, (3) `key_not_confirmed`: level 1 up to 20 [`time_witness`], 0 for 21 to 33, `next` `{2, all, [receipt_key_confirmed]}`, no note | 1 | `RECEIPT_UNVERIFIED`, `TIME_ANCHOR_UNVERIFIED` | 1 | `RECEIPT_UNVERIFIED` |
| `evidence_level_1_auditor_root` | receipts under `vendor-test-002`; the expected root root(20) of the auditor without `tree_size`, found at t = 20: (2) up to 20 with the source `auditor` only: level 1 up to 20 [`expected_root_found`], note `expected_root_auditor_only` | 1 | `RECEIPT_UNVERIFIED` | 1 | `RECEIPT_UNVERIFIED` |
| `evidence_level_0_no_receipt` | standard chain without receipts (N = 30): `NO_ANCHOR`, level 0 (property 1), (3) `no_receipt`, `next` `{1, any, [time_witness, expected_root_found, receipt_key_confirmed]}`; with an established extract (reference day 2025-12-31) and E1 for the log and named as qualified: (5) `no_receipt`, (7) `no_receipt_included` | 1 | `NO_ANCHOR` | 1 | `NO_ANCHOR` |
| `evidence_level_0_device_key` | receipts under `vendor-test-geraet` with the public key of `GENESIS.device_pubkey`; `--vendor-key` pins it: the signatures hold (no finding), (3) `key_is_device_key`, level 0 | 1 | `RECEIPT_UNVERIFIED` | 0 | - |

**Notes** (10.9.6)

| Vector | Structure and audit environment of the vector | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `evidence_last_receipt_unconfirmed` | receipt at 15 under `vendor-test-001`, at 28, the last countersigned checkpoint of 8.6, under `vendor-test-002`: (3) up to 15, level 2 up to 15, note `last_receipt_not_confirmed`; with the pin of `vendor-test-002` level 2 up to 28 without that note | 1 | `RECEIPT_UNVERIFIED` | 0 | - |
| `evidence_material_contradiction` | a presented plaintext contradicts the commitment of the first AI call: `CONTENT_MISMATCH` from `material_classes`, state `rated`, level 2 up to 28, note `material_contradiction`; with the expected root `28:<root(28)>` (2) holds | 2 | `CONTENT_MISMATCH` | 2 | `CONTENT_MISMATCH` |
| `evidence_stale_package` | checked 25 hours after the last entry: `TRAILING_SILENCE`, note `stale_package`; level 2 up to 28 | 1 | `TRAILING_SILENCE` | 1 | `TRAILING_SILENCE` |
| `evidence_package_not_fully_known` | manifest with the member `affiliation` = `affiliated`: `UNKNOWN_MANIFEST_FIELD`, note `package_not_fully_known`; with the honest page of 01:02, R = 00:58 and the role list `not_affiliated`, since no condition and no affiliation reads the manifest; (2) and (6) up to 28 | 1 | `UNKNOWN_MANIFEST_FIELD` | 1 | `UNKNOWN_MANIFEST_FIELD` |
| `evidence_receipts_after_check_time` | package of the group `log`, checked at 23:35 on 2026-01-02, extract up to the reference day 2026-01-01: both receipts `future`, the foremost bad receipt gives (5) `receipt_after_check_time` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |

**States** (10.9.2, 10.10.1, 10.10.2)

| Vector | Structure and audit environment of the vector | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `evidence_chain_invalid` | signature of the receipt at 28 altered: `RECEIPT_INVALID`, no class of `material_classes`: state `chain_invalid` without level, conditions, segments and notes; `affiliation` stands here too: `not_checked`, with the honest page `not_affiliated` | 2 | `RECEIPT_INVALID` | 2 | `RECEIPT_INVALID` |
| `evidence_format_error` | the line of the second AI call is no JSON: `FORMAT_ERROR` with a report, state `format_error`, `affiliation` `null`; the anchor history of the audit environment changes nothing | 3 | `FORMAT_ERROR` | 3 | `FORMAT_ERROR` |

### 13.4 Coverage and limits

Together with the vectors of the groups `roles` to `history` the corpus shows every level from 0 to 3, the three states, every reason of the table of 10.9.4 at every condition where it can stand, and every note of 10.9.6 with three exceptions no vector can show:

- `signature_not_checkable` at condition (7): a receipt of class `included` lies on a usable day whose canonical entry carries a confirmed witnessing stamp (7.4.10, steps L2 (h), L3). Its signature is checked, so every triple with it passes the first stage, whatever the root; the triple that came furthest therefore never fails at the first stage.
- `vendor_root_builtin_only`: no run of the corpus carries a built-in vendor root.
- `cms_not_implemented`: the reference verifiers perform steps 5 and 6 of 7.3.

`valid_basic` also carries `evidence_level`, the example of format specification 10.10.2: level 2 up to 309, 0 for 310 to 311, notes `unsealed_end` and `published_test_key_credited`.

## 14. Condition (7) as the second way to level 3 and the other decisions of 26.10. (specification 1.10)

16 vectors check what the specification lays down after the decisions of 26.10.: condition (7) as the second way to level 3 next to (4), with the bound G_q = 129 600 000 ms, the reason `qualified_day_stamp_gap` and the report object `qualified_time` (format specification 10.9.1, 10.9.4, 10.9.5, 10.10.2, 10.10.3); the filler commitment `null` and the rule that, once set, it stays the same in every later version (7.4.4, 7.4.7, 7.4.10 step L1); the end of a period `former_relation` 24 months after the end of a relation (heartbeat specification §9.10); an entry `DATA_ACCESS` of the data class `access_chain` (4.25); and the anchors of condition (6) in the block of the evidence level, the statements keys of the fresh used pages instead of every pair of `anchors.statement_keys` (10.10.2, 10.10.3). They stand in the registry in the group of their subject (`valid`, `log`, `history`, `evidence`), each after the vectors that stood there before, and declare `spec_version` `1.10`. Their expectations stand in the registry, each with reason and section in member `why`, derived from the text of the specification. The expected file names the evidence level in the short form of §3; `qualified_time`, `basis` and `next` stand in the description of the row. The reference values KAT8 to KAT10 of 10.9.5 stand in the registry (`verifier.evidence_level.kat`), with `next` for KAT10; they are no vectors.

### 14.1 Packages and audit environments

**Packages.** Ten vectors carry the package of a vector of the group `log` byte for byte under their own name (§11.1, §11.3): that of `log_witnessed_included` (14 entries, receipts at `tree_size` 5 with `server_ts` `2026-01-02T23:55:01.000Z` and at 10, checked at 06:30 on 2026-01-03; the day of the second receipt is not yet due) and that of `log_witnessed_qualified_stamp` (the same script; its day 2026-01-02 carries a witnessing stamp of 00:05:01 and a late one of `2026-01-05T00:00:00Z`, both of the signer of E1 with qcStatements). Two vectors carry the script of the group `log` with a chain of their own and a `TIME_ANCHOR` of the signer of E3 with qcStatements: `evidence_level_3_both_ways` 700 ms after the checkpoint of `GENESIS` (`tree_size` 1, `genTime` 23:50:01; receipts at 6 and 11), `evidence_qualified_time_tie` 700 ms after the second receipt over the checkpoint of `tree_size` 10 (`genTime` 00:05:01 on 2026-01-03; receipts at 5 and 10), both with N = 15; their day 2026-01-02 carries only a stamp of the same signer of 00:05:01. The vectors of the group `history` carry the one-hour standard chain of the corpus (§12.1), `history_affiliated_former_relation_leap_day` from 22:00 on 2026-02-28, checked at 00:10 on 2026-03-01. `valid_data_access_access_chain` carries the one-hour standard chain with two entries `DATA_ACCESS` at 00:03 and 00:04 (N = 34, receipts at 17 and 30).

**Audit environment.** Every audit environment contains that of the corpus (`korpus` `true`). The vectors of the group `evidence` pass, where the row says nothing else, the extract of their package, the root of their authority (E1 or E3) with `--vendor-log-tsa-root` and in `--tsa-qualified-roots` (named from 2025-01-01), the role list of version 1, R = `2026-01-03T06:00:00.000Z` and the honest page of the anchor history of 06:10 with both receipts (§13.1). The vectors of the group `log` pass the extract with the witnessed day of `log_witnessed_included` and the root of E1 with `--vendor-log-tsa-root` (§11.2); the list in the extract and the lists the row names as files of the auditor differ only in `version`, `ausgestellt` and `fuellerbindung`. The vectors of the group `history` pass the role list of version 1, R and the pages the row names (§12.1). `valid_data_access_access_chain` has no audit environment of its own. `TestEntscheidungenVektoren`, `TestEinmaligeStelleE3Eingefroren`, `TestNach24Monaten`, `TestBeweisstufeReferenzwerte`, `TestEntscheidungenInRegistryGruppen` and `TestEntscheidungenTabellenFolgenDerErwartung` (`appliance/cmd/vektorgen`) hold packages, the frozen input of E3, the month arithmetic, the reference values KAT1 to KAT10, the position in the registry and the tables against the bytes and against `expected/`; `TestBeweisstufeEigenschaften`, `TestBeweisstufeMonotonie` and `TestBeweisstufeAbdeckung` (§13.1) hold for these vectors too.

### 14.2 The time-stamping authority E3

A day stamp at a given distance from the countersignature (the bound G_q) and a time witness over the checkpoint of a new chain need tokens that no frozen token of E1 or E2 covers. They come from a third time-stamping authority with discarded keys, E3, created like E1 (§11.2) in a single run of `vektorgen -einmalige-stelle appliance/cmd/vektorgen/eingefroren -stelle E3`. Its input `appliance/cmd/vektorgen/eingefroren/zeitstempelstelle_e3.json` (format `ledger-testkorpus-zeitstempelstelle/1`) names exactly three certificates and the tokens, no key; the generator copies it unchanged to `zeitstempelstelle_e3.json`:

- `wurzel`: "Testkorpus Zeitstempelwurzel E3 (Schluessel verworfen)", Ed25519, self-signed, serial number 1, valid from 2025-01-01 to 2036-01-01, basicConstraints cA and keyUsage keyCertSign, both critical; SHA-256 of the certificate `bf7bd6f96548b2c78965f7a54f0698cfdda12902fca98553b11ba0fa84e97c31`, SPKI SHA-256 `c030cacc09261f8c3f37b931a38732d217e8791d4345afc9b94f2f071bd3c4d7`.
- `signierer`: "Testkorpus Zeitstempelstelle E3 (Schluessel verworfen)", serial number 2, valid from 2025-06-01 to 2031-01-01, keyUsage digitalSignature and extKeyUsage exactly `id-kp-timeStamping`, both critical; SPKI SHA-256 `730012141817ed53bfa605da40de43535372ebe05d34fda69cc450cf0aa86ea6`.
- `signierer_qs`: "Testkorpus Zeitstempelstelle E3 qcStatements (Schluessel verworfen)", serial number 3, otherwise like `signierer`; SPKI SHA-256 `2fb922d638c2973efa426787d5834d9ac407fafe7262fa9b9c45d0d280054858`.
- `token`: seven tokens of the signer with qcStatements (`esi4-qtstStatement-1`), each under the name `<vector>/<label>`, serial numbers `0x5001` to `0x5007`: the time witnesses and the day stamps of `evidence_level_3_both_ways` and `evidence_qualified_time_tie` and the day stamps of `evidence_log_stamp_gap_exact`, `evidence_log_stamp_gap_exceeded` and `evidence_log_stamp_gap_truncated` over the day entry of `log_witnessed_included`.

Everything §11.2 says of E1 holds for E3: its keys are in no file and not in `published_test_keys`, its tokens cannot be issued again, every other run of the generator holds each token to its request and stops at a missing, deviating or unrequested token, and its root is never an auditor's root; it counts only where `pruefer_<name>.json` passes it.

### 14.3 Vectors

The tables state first exit and findings with the audit environment of the corpus, then with `pruefer_<name>.json`. In the description the segments stand as "level for `first_seq` to `last_seq`" and `basis` in square brackets; (1) to (7) are the conditions of 10.9.1, `qualified_time` stands as `{via, tree_size, latest, gap_ms}`. With the audit environment of the corpus the vectors of the groups `log` and `evidence` have level 2 up to 10 (those with a time witness of E3 level 2 up to 11 and 10 with `TIME_ANCHOR_UNVERIFIED`), those of the group `history` level 2 up to 28.

**Condition (7), the second way to level 3** (10.9.1, 10.9.5, 10.10.2, 10.10.3)

| Vector | Structure and audit environment of the vector | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `evidence_level_3_log_day_qualified` | package and extract of `log_witnessed_qualified_stamp`, E1 for the log and named as qualified: no time witness, (4) `no_time_anchor`; (7) with the witnessing stamp, 10 minutes after the receipt, up to 5, (5) up to 5, (2), (3) and (6) up to 10; r3 = min(10, max(0, 5), 5, 10) = 5: level 3 up to 5 through (7) alone; 3 for 1 to 5 [`receipts_logged`, `log_day_qualified`], 2 for 6 to 10, 0 for 11 to 14; `qualified_time` `{log_day_qualified, 5, 2026-01-03T00:05:01.000Z, 600000}`, line "qualified confirmation: at the latest 2026-01-03T00:05:01.000Z (time stamp of the vendor log, tree_size 5, 0 h 10 min after the countersignature)" | 0 | - | 0 | - |
| `evidence_level_3_both_ways` | time witness of E3 at `tree_size` 1, day stamped by E3, E3 for the log and named as qualified: (1) and (4) up to 1, (5) and (7) up to 6, (2), (3) and (6) up to 11; r3 = min(11, max(1, 6), 6, 11) = 6, the larger reach of (4) and (7) counts: level 3 up to 6; 3 for 1 to 6 [`receipts_logged`, `log_day_qualified`], 2 for 7 to 11, 0 for 12 to 15; `qualified_time` `{log_day_qualified, 6, 2026-01-03T00:05:01.000Z, 600000}`, the time witness at 1 is no candidate, its `tree_size` lies below `up_to_tree_size` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `evidence_qualified_time_tie` | time witness of E3 at `tree_size` 10 with `genTime` 00:05:01, day of E3 with the same `genTime`: (1) and (4) up to 10, (5) and (7) up to 5: level 3 up to 5; 3 for 1 to 5 [`receipts_logged`, `log_day_qualified`], 2 for 6 to 10, 0 for 11 to 15; at an equal `genTime` (4) comes before (7): `qualified_time` `{time_witness_qualified, 10, 2026-01-03T00:05:01.000Z, null}`, line "qualified confirmation: at the latest 2026-01-03T00:05:01.000Z (time witness of the chain, tree_size 10)" | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |

**The bound G_q** (10.9.1, 10.9.4)

| Vector | Structure and audit environment of the vector | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `evidence_log_stamp_gap_exact` | package of `log_witnessed_included`, its day only with a stamp of E3 with qcStatements, `genTime` `2026-01-04T11:55:01Z`, exactly G_q after the receipt of 23:55:01.000 and witnessing (before end(d) + W): (7) holds, only a distance greater than G_q fails; level 3 up to 5 [`receipts_logged`, `log_day_qualified`]; `qualified_time` `{log_day_qualified, 5, 2026-01-04T11:55:01.000Z, 129600000}`, in the line "36 h 0 min" | 0 | - | 0 | - |
| `evidence_log_stamp_gap_exceeded` | the same with `genTime` `2026-01-04T11:55:01.001Z`: distance 129 600 001 ms, every earlier stage holds: (7) `qualified_day_stamp_gap`; the day stays witnessed, (5) up to 5; level 2 up to 10, `next` `{3, all, [time_witness_qualified, log_day_qualified]}`, in the text one line for (4) or (7) with both reasons | 0 | - | 0 | - |
| `evidence_log_stamp_gap_truncated` | the same with `genTime` `2026-01-04T11:55:01.0009Z`: truncated to whole milliseconds exactly G_q, (7) holds; level 3 up to 5; `qualified_time.latest` `2026-01-04T11:55:01.000Z`, `gap_ms` 129600000 | 0 | - | 0 | - |

**Roots with only one of the purposes** (7.5.7, 10.8, 10.9.4)

| Vector | Structure and audit environment of the vector | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `evidence_qualified_log_root_log_only` | package and extract of `log_witnessed_qualified_stamp`, E1 only for the log: the day is witnessed, (5) up to 5; no root carries both purposes: (7) `no_qualified_log_root_supplied`, (4) `no_time_anchor`; level 2 up to 10, `next` `{3, all, [time_witness_qualified, log_day_qualified]}` | 0 | - | 0 | - |
| `evidence_qualified_log_root_qualified_only` | E1 only in the file of qualified roots, not for the log: no day stamp is confirmed, the first receipt is `unchecked` with `day_not_witnessed`, reason `no_log_root_supplied`; (5) `day_timestamp_not_confirmed`, (7) `no_qualified_log_root_supplied`; level 2 up to 10, `next` `{3, all, [time_witness_qualified, receipts_logged, log_day_qualified]}` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |

**Filler commitment** (7.4.4, 7.4.7, 7.4.10 step L1)

| Vector | Structure and audit environment of the vector | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `log_list_filler_commitment_null` | extract with the list of version 1 with `fuellerbindung` `null`: effective, no finding; (5) up to 5 | 0 | - | 0 | - |
| `log_lists_filler_commitment_set_later` | version 1 with `null` in the extract, version 2 with the filler commitment of the test filler secret as a file of the auditor: set from version 2 on, no contradiction; version 2 effective | 0 | - | 0 | - |
| `log_lists_filler_commitment_changed` | in addition version 3 with the filler commitment of another secret: two counting lists name different values other than `null`, "contradicting lists"; no protocol key, (5) and (7) `vendor_log_not_established` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_lists_filler_commitment_dropped` | version 1 with the filler commitment in the extract, version 2 with `null`: "contradicting lists" | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |

**Affiliation: 24 months** (heartbeat specification §9.10, format specification 8.8.6)

| Vector | Structure and audit environment of the vector | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `history_not_affiliated_period_before_24_months` | the reference value of 8.8.6: only a period `former_relation` 2025-06-01 to 2025-12-01, 24 months after the end of the relation on 2023-12-01: `not_affiliated`, period outside | 0 | - | 0 | - |
| `history_affiliated_former_relation_leap_day` | standard chain from 22:00 on 2026-02-28, R = 23:58, fresh page of 00:02 on 2026-03-01: a period `former_relation` from 2025-06-01 to `2026-03-01T00:00:00.000Z` for a relation that ended at 12:00 on 2024-02-29 (24 months after a 29 February is 1 March two years later, 00:00:00.000Z); the span of the package lies before it, after 730 days (12:00 on 2026-02-28) it would lie after it: `affiliated` with `former_relation`, 2 of 2 receipts in the period | 0 | - | 0 | - |

**Anchors of condition (6)** (10.10.2, 10.10.3; 8.8.4, "Older pages")

| Vector | Structure and audit environment of the vector | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `history_archive_page_other_key` | the older page of 00:40:00 of `history_archive_pages` (root at 15), signed with `vendor-statements-test-002` of the role list, beside the fresh page under `vendor-statements-test-001`: no finding, note `archive_pages`; (2), (3) and (6) up to 28, level 2 up to 28; (2) with the source `anchor_history` rests on both pages, `anchors.statement_keys` names both keys; (6) rests on the fresh page alone (8.8.4, "Older pages"), the line "present" of (6) names "anchor history of 2026-01-01T01:02:00.000Z, statements key vendor-statements-test-001 from role list version 1, auditor's root testwurzel-1" and not `vendor-statements-test-002` | 0 | - | 0 | - |

**`DATA_ACCESS`** (4.25)

| Vector | Structure and audit environment of the vector | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `valid_data_access_access_chain` | standard chain of edition 1.10 with two entries `DATA_ACCESS`: at 00:03 the addition of an account (`credentials`, `change`, `maintenance`, `all_customers`, `declared`, `origin` `portal`), at 00:04 the read of the access chain itself by that account for the audit (`access_chain`, `read`, `audit`, `all_customers`, `gate`, `origin` `import`): the schema holds, no finding; level 2 up to 30 | 0 | - | - | - |

### 14.4 Coverage and limits

With these vectors the corpus also shows the reason `qualified_day_stamp_gap` and condition (7) as the only way to level 3; `TestBeweisstufeAbdeckung` holds that. Limits, stated openly:

- The day stamps of `evidence_log_stamp_gap_exact`, `evidence_log_stamp_gap_exceeded` and `evidence_log_stamp_gap_truncated` carry a `genTime` after the check time of their package (06:30 on 2026-01-03), like the late stamps of §11.3; no step of the specification compares the `genTime` of a day stamp with the check time.
- The frozen vector `history_not_affiliated_period_before` carries the end of a period `former_relation` after 730 days (§12.8); its bytes and its expectation stay, since the verifier computes no end.

## 15. Alignment of both verifiers (specification 1.10)

26 vectors pin readings the specification wrote down so that both reference verifiers judge every input alike (format specification Section 2, 7.5.2 to 7.5.6). 23 of them belong to the group `timestamp` and stand with their audit environments in the table of §10.3, six of them with the inputs of the single check in §10.4; the generator builds them like the others there (`grundlagen.go`, `zeitstempelprofil.go`). Here stand the three package vectors: the two with a countersignature, `valid_receipt_r_identity` in the group `valid` and `tamper_receipt_r_identity_sign_bit` in the group `tamper`, and `format_uuid_trailing_newline` in the group `format`, each after the vectors that stood there before (`abgleich.go`). All three declare `spec_version` `1.10`, carry the standard chain of §10 (32 entries, receipts at `tree_size` 15 and 28 under `vendor-test-001`, sealed at 01:01, checked 2 min later) and have no audit environment of their own; their expected file names `evidence_level`. Every expectation stands with its reason and section in the member `why` of the registry, derived from the text of the specification.

**The neutral element as R.** Ed25519 is verified without the cofactor (format specification Section 2): S < L, and the encoding of [S]B - [k]A equals R byte for byte. The neutral element (0, 1) has two encodings with a valid y: `01 00…00 00`, the canonical one, and `01 00…00 80` with the sign bit set although x = 0. With R either of them and S = k·a mod L (k = SHA-512(R, A, M) mod L, a the secret scalar of the key), [S]B = R + [k]A holds as an equation between points; the comparison of encodings admits only the canonical one. Anyone who knows the private key writes such a signature; it needs no break of Ed25519, and every key here is a test key of the corpus. The same two encodings carry, in the group `timestamp`, the signature of a token (`timestamp_signature_r_identity`, `timestamp_signature_r_identity_sign_bit`) and the root's signature over the signer certificate (`timestamp_signer_cert_r_identity`, `timestamp_signer_cert_r_identity_sign_bit`).

| Vector | Structure and the vector's audit environment | Exit | Findings | Exit with `pruefer_<name>.json` | Findings with `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `valid_receipt_r_identity` | the receipt of 01:00 (`tree_size` 28) with R = `01 00…00 00` and S = k·a mod L: `server_signature` validates under the pinned key (7.1); no finding, level 2 up to 28 | 0 | - | - | - |
| `tamper_receipt_r_identity_sign_bit` | the same chain with R = `01 00…00 80`: the encoding of [S]B - [k]A is `01 00…00 00` and does not equal R, `server_signature` does not validate (7.1); state `chain_invalid` (10.9.2). Whoever checks the equation between points would accept the receipt | 2 | `RECEIPT_INVALID` | - | - |
| `format_uuid_trailing_newline` | the chain under its own `chain_id`, every receipt signed after RFC 8032, with a line feed (U+000A) after the 36 characters of the uuid, in the manifest and in every entry: `manifest.chain_id` violates the type `uuid` (2), the manifest its schema, the later stages are dropped (10.5); state `format_error` with a report (10.9.2). Whoever reads the type with a pattern whose `$` admits a final line end finds a valid chain | 3 | `FORMAT_ERROR` | - | - |

**Which rule which vector pins.**

- Z.6 element by element (7.5.6): `timestamp_ess_v2_second_element_broken`, `timestamp_ess_issuer_serial_name_broken` (violated), `timestamp_ess_policies_not_der`, `timestamp_ess_other_name_a4`, `timestamp_ess_hash_algorithm_parameters_not_der` (holds).
- Z.1, the content of `extnValue` of the extensions a rule reads, in DER under T.6, in every certificate from `certificates` (7.5.2, 7.5.3): `timestamp_signer_basic_constraints_not_der`, `timestamp_extra_certificate_path_len_not_minimal`, `timestamp_signer_eku_oid_not_minimal`; there an element of the universal class with tag number 0 or from 31 on does not satisfy T.6: `timestamp_signer_basic_constraints_tag_zero`, `timestamp_signer_basic_constraints_tag_31`. Each of these vectors ends at 5a, not at "no path".
- Limits of T.6 (7.5.2): T.6 checks neither the content of NULL nor the unused-bits octet nor the unused bits of a BIT STRING: `timestamp_signer_basic_constraints_null_content`, `timestamp_signer_key_usage_unreadable`, `timestamp_root_key_cert_sign_unused_bit`.
- Z.3 at every position of the path, c0 included (7.5.5), and keyCertSign only among the used bits: `timestamp_signer_key_usage_unreadable`, `timestamp_signer_basic_constraints_unreadable`, `timestamp_signer_basic_constraints_null_content`, `timestamp_root_key_cert_sign_unused_bit`.
- Z.5, `sid` as `[0]` against the key identifier (7.5.5): `timestamp_sid_key_identifier`.
- Where the grammar asks only for one TLV, T.6 checks only the outer TLV (7.5.2): the parameters of `hashAlgorithm` of an ESSCertIDv2 (Z.6, 7.5.6): `timestamp_ess_hash_algorithm_parameters_not_der`; the value of a signed attribute that no rule reads (T.4): `timestamp_signed_attribute_value_not_der`; the parameters of the key algorithm of a certificate on no path, also with tag number 0 (Z.1, 7.5.3): `timestamp_extra_certificate_key_parameters_tag_zero`. Each of these tokens is judged like that of `timestamp_qualified_root`.
- An arc of an OID above 10^4300 keeps T.6 (7.5.2): in `extKeyUsage` of a certificate on no path, Z.1 holds (7.5.3): `timestamp_extra_certificate_oid_arc_large`; as the `extnID` of a TSTInfo extension next to `qcStatements`, rule QS `present` (7.5.6): `timestamp_qs_extension_oid_arc_large`.
- Ed25519 without the cofactor (Section 2): the two vectors of this section with a countersignature and the four of the group `timestamp` named above.
- A uuid is the whole string of the form 8-4-4-4-12 (Section 2): `format_uuid_trailing_newline`. A pattern anchored with `^` and `$` admits, in more than one regular-expression dialect, a line feed after the last character as well, since `$` also matches before a final line end; the type does not. The package is a correct chain over the bytes with the line feed, so the line feed is its only defect.

**Limits.** Whether Z.6 holds is shown by no expected file: a token of the generator's time-stamping authority that has a path to the auditor's root ends at `published_test_key` for conditions (1) and (4), before the stage on Z.6 (§10.3). Only the single check shows it (§10.4), in whose table from 7.5.7 the row on Z.6 stands above the one on `published_test_keys`; `TestZeitstempelKorpus` (`verifier/internal/cli`) and `test_readme_10_4_inputs` (`verifier2`) hold the five inputs on Z.6 and the one on rule QS with both purposes. `TestAbgleichTabelleFolgtDerErwartung` (`appliance/cmd/vektorgen`) holds the table of this section against `expected/`, `TestGrundlagenTabellenFolgenDerErwartung` the rows of the group `timestamp`.
