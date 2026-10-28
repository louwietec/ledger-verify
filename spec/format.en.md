# LEDGER Chain Format: Specification (EN)

**spec_version: 1.10** · This specification is normative. It describes LEDGER's evidence format completely enough that an independent third party can implement a verifier from this document alone. The machine-readable field and class reference is `spec/registry.json`; in case of divergence the registry prevails.

**Draft of edition 1.10, as of 2026-10-26: not released.** New in this edition are the vendor log with fillers, the timestamp profile, the anchor history as auditor input, the key roles with `statement_signatures`, the evidence level, the report members and the access chain with the entry type `DATA_ACCESS`. Both reference verifiers implement this edition as a draft; until it is released, verification follows the edition named by `--version` of the verifier in use.

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as described in RFC 2119.

## 1. Overview and Design Goals

LEDGER captures the use of AI services as an **append-only event chain**: canonical JSON, SHA-256 hash chaining, an RFC 6962 Merkle tree, Ed25519-signed checkpoints and external countersignatures. Three design goals drive every format decision:

1. **Proof instead of claim.** Every statement the chain makes is cryptographically verifiable: offline, without the vendor's cooperation, without secrets. Verification requires neither customer keys nor content.
2. **A gap is a finding.** No failure path ends in nothingness: outages, bypasses, clock jumps and deletions are chained as dedicated entry types. An honestly declared gap does not invalidate the chain; a concealed one does (Sections 8, 11). For the single call this is a commitment of the appliance: every call it has answered is in the chain or lies inside the window of a chained `GAP` (Section 8.7); whether it was kept, the package alone cannot show (Section 11.2).
3. **Sovereignty.** The chain carries no plaintext, only salted commitments (Section 9). The vendor knows no customer keys and sees no content. Its roles in the proof model are countersigning 32-byte roots (Section 7.1), the signed anchor history with the statement on affiliation (Section 8.8, heartbeat specification §9.7, §9.10) and the vendor log (Section 7.4). For each of these roles it keeps keys of its own (Section 10.7.3). None of these roles gives it a key of the customer or insight into content.

The chain serves as technical evidence and supports the fulfilment of an operator's documentation and record-keeping duties; which duties apply in a given case is not determined by this specification. It contains no legal advice.

## 2. Conventions and Basic Types

All field types used in this specification:

| Type | Meaning |
|---|---|
| `string` | UTF-8 string; `maxlen` = maximum length in Unicode characters |
| `int` | integer (JSON number without fraction); `min`/`max` inclusive |
| `bool` | `true` or `false` |
| `uuid` | UUID as a lowercase string, format 8-4-4-4-12 |
| `rfc3339` | RFC 3339 timestamp, MUST be given in UTC with suffix `Z`; read by the grammar of Section 10.7: `YYYY-MM-DDThh:mm:ss` with the ASCII digits `0` to `9`, optionally a period with fractional seconds, then `Z`; a comma before the fraction, a one-digit hour or second `60` do not satisfy the type; the year lies between `0001` and `9999`, the date must exist |
| `date` | calendar day `YYYY-MM-DD` (from edition 1.10) with the ASCII digits `0` to `9`; the date must exist in the proleptic Gregorian calendar, the year lies between `0001` and `9999`; members of the vendor log of type `date` (Section 7.4) additionally lie between `2000-01-01` and `9998-12-31` (log range); `dayOf` (Section 7.4.10, step L2) reads only the grammar of the type, and step L2 (c) checks the log range of a day entry as a content rule |
| `hex64` | 64 lowercase hexadecimal characters (32 bytes), e.g. a SHA-256 value or an Ed25519 public key |
| `hex128` | 128 lowercase hexadecimal characters (64 bytes), an Ed25519 signature |
| `key-id` | key identifier (a type of its own from edition 1.10): a string of the grammar `^[A-Za-z0-9._-]{1,64}$` of Section 10.7 |
| `enum` | exactly one of the enumerated string values |
| `object` | JSON object with the stated fields |
| `const` | fixed value, MUST match exactly |
| `version` | specification version `"MAJOR.MINOR"` (two decimal numbers separated by `.`); acceptance rule per Section 10.6 |
| `open_enum` | one of the enumerated string values OR a value unknown to this version; unknown values are not a schema error but the finding named in the registry (`unknown_finding`), Section 10.6 |
| Suffix `?` | nullable: the field MUST be present, its value MAY be `null` |

Binding rules:

- **Completeness:** Every field defined for an entry type MUST be present in the entry. Undefined fields MUST NOT occur. Nullable fields (`?`) carry `null` when no value is available.
- **Canonicalization:** "JCS(x)" denotes canonicalization of the JSON value `x` per RFC 8785 (JSON Canonicalization Scheme): keys sorted by UTF-16 code units, shortest number representation, no unnecessary escapes, no whitespace. The result is UTF-8 bytes.
- **Member names:** A JSON object MUST NOT contain a member name twice (I-JSON, RFC 7493, as RFC 8785 presupposes; names are compared after resolving escapes). An entry or a `manifest.json` with a duplicate member name is `FORMAT_ERROR` (exit 3). It is read neither as "last wins" nor as "first wins"; for the vendor key list Section 10.7 applies.
- **Hex:** All hex values MUST use lowercase. "Bytes(h)" denotes decoding a hex string `h` into raw bytes.
- **Hash:** For its own objects (entries, Merkle trees, commitments, signing inputs, vendor log and anchor history) this specification uses SHA-256 and no other hash function. Other hash functions occur only in RFC 3161 time stamps that a time-stamping authority forms (Sections 7.3, 7.5): imprints with SHA-384 or SHA-512, the hashes of the signature algorithms and of the attributes `messageDigest` and signingCertificateV2, and SHA-1 as the identifier of the signer certificate in signingCertificate (from edition 1.10 Z.6, Section 7.5.6). "Hex(x)" is the lowercase hex encoding of bytes `x`.
- **Signatures:** Ed25519 (RFC 8032). What is signed is always the UTF-8 bytes of a JCS-canonicalized object; signatures are encoded as `hex128`, public keys as `hex64`. Verification is without the cofactor, as RFC 8032 Section 5.1.7 permits: S < L; k is SHA-512 over R, the 32 octets of the public key as they stand, and the message, read as a little-endian number and reduced modulo L; the encoding of [S]B − [k]A equals R, the first 32 octets of the signature, byte for byte. An R that is not the canonical encoding of its point (y ≥ p, or x = 0 with the sign bit set) therefore never verifies. Under a public key with y ≥ p no signature verifies (in time stamps it lies outside Z.2, Section 7.5.4); x = 0 with the sign bit set is read by the verifier as x = 0 for a public key, departing from RFC 8032 Section 5.1.3, step 4. This holds for every Ed25519 signature of this specification, also in time stamps (Section 7.5.4).
- **Numbers (explicitly from edition 1.9):** Every JSON number in the verification package (in entries including the payload of unknown types, in the manifest, in the vendor key list, in the salt files of presented plaintexts (Section 10.1) and in `verify_args.json` (Section 10.8)) MUST be an integer from −(2^53−1) to 2^53−1, written without a fraction and without an exponent (I-JSON, RFC 7493 section 2.2; RFC 8785 presupposes it). Any other number is `FORMAT_ERROR` (exit 3); `1.0` is not `1`. The writing path cannot write anything else. This holds in the vendor key list and in the salt files too, whose other defects only make the list ineffective (Section 10.7) or are `CONTENT_MISMATCH` (Section 10.1), and whether or not the auditor passes a vendor root. These two kinds of file are read lexically (every number token where a JSON value may begin, strings do not count), hence independently of other defects of the same file (stage 4a, Section 10.5). `NaN` and `Infinity` are not JSON (RFC 8259): a syntax error of the file, not a number violation. `-0` is the number 0.
- **Time arithmetic (from edition 1.9):** The tolerance checks of Sections 8.2, 8.5 and 9.2 and the window conditions of Section 8.7 compute in whole milliseconds: every instant is truncated to whole milliseconds since `0001-01-01T00:00:00Z` (digits after the third fractional digit are dropped); integers are compared and subtracted. All other time comparisons (Sections 7.1, 9.3, 10.7) are made to the nanosecond. The writing path writes milliseconds; an honest chain never touches the difference. From edition 1.10 the following also compute in whole milliseconds: the time windows of the day time stamps, the due time of a day and the rules on `server_ts` of the vendor log (Sections 7.4.6, 7.4.10), the check of the anchor history with the request time, freshness, the page rules and affiliation (Sections 8.8, 10.8), and the instants the verifier forms itself (Section 10.10.1). To the nanosecond, with the full `genTime`, from edition 1.10: the comparison with the end of validity of a protocol key (Section 7.4.10, step L2 (e)), the validity window of a list entry for pages of the anchor history (Section 8.8.4, step H2), the period of a root named as qualified (Section 10.8) and the validity of the certificates of a path (Section 7.5.5).
- **Day arithmetic (from edition 1.10):** For a day d of type `date`, `dn(d)` is the number of days from `0001-01-01` to d (`dn(0001-01-01) = 0`), and `end(d) = (dn(d) + 1) · 86,400,000` is the end of the UTC day d in whole milliseconds since `0001-01-01T00:00:00Z`, as in the time arithmetic above. Previous days, following days and day ends MUST be computed on these integers; no calendar date is formed for d + 1 or d + 2, since at the edge of the value range there is none. `day(ts)` is the date part of a value of type `rfc3339`, the ten characters before the `T`; fractional seconds never change it (truncated, not rounded). Example: `dn(2026-01-01) = 739,616`, `end(2026-01-01) = 63,902,908,800,000`.
- **Base64, grammar B64 (from edition 1.10):** A base64 string (RFC 4648 Section 4) consists only of the characters `A` to `Z`, `a` to `z`, `0` to `9`, `+` and `/`, has a length divisible by 4 and carries `=` only as padding at the end, at most twice. Line breaks, blanks and other characters violate B64. Unused bits of the last group are not checked: what is judged is the string itself, and a second spelling of the same bytes gives it no second meaning. A decoder that skips line breaks MUST reject `\r` and `\n` beforehand. B64 applies to `token_base64` (Section 7.3; a violation is `TIME_ANCHOR_INVALID`, not a format error, since the registry type of the field remains `string`), to the time stamps of the day entries (Section 7.4.6), to the content of a PEM block after joining its lines and to certificates in auditor files (Section 10.8).
- **Auditor files (from edition 1.10):** JSON files the auditor passes to the verifier (Sections 7.4, 8.8, 10.8) are I-JSON under the rules above (member names, numbers, no lone surrogates), UTF-8 without a byte order mark, and their objects are closed: members other than those defined MUST NOT occur. The size limits are given in Section 10.8 (registry `auditor_inputs`). What a violation causes is decided by the section of the respective file; where it says nothing else, it is an unusable invocation (exit 3, Section 10.8).
- **Signed statements in printable ASCII (from edition 1.10):** The `statement_jcs` of a day entry (Section 7.4.5) and of an anchor history page of kind v2 (heartbeat specification §9.7) consists only of the bytes `0x20` to `0x7E`; its length limit in characters is therefore also one in bytes.

## 3. Entry Envelope

Every entry is a JSON object with exactly these eleven fields (source: registry `envelope_fields`):

| Field | Type | Description |
|---|---|---|
| `spec_version` | version `"MAJOR.MINOR"` | version of the specification the entry was written under; `MAJOR` and `MINOR` are decimal numbers without leading zeros (`"1.0"`, not `"01.0"` or `"1.00"`); this edition writes `"1.10"` and accepts older minor versions of the same MAJOR; acceptance of other versions: Section 10.6 |
| `chain_id` | uuid | chain identity; MUST be identical across all entries of a chain |
| `seq` | int, min 1 | sequence number; strictly monotonic, gapless, starting at 1 |
| `ts_captured` | rfc3339 | wall-clock time of event capture |
| `ts_chained` | rfc3339 | wall-clock time of chaining (writing the entry) |
| `mono_delta_ms` | int, min −1 | monotonic milliseconds since the previous entry; `-1` = unknown (first entry after process start) |
| `event_type` | open_enum | one of the entry types of Section 4; unknown types: Section 10.6 |
| `origin` | enum | `proxy` \| `import` \| `portal` \| `system` |
| `payload` | object | type-specific payload, see Section 4 |
| `prev_hash` | hex64 | `entry_hash` of the previous entry; for `seq=1`: 64 zero characters (`000…0`) |
| `entry_hash` | hex64 | see below |

**Hash computation (normative):**

```
entry_hash = Hex( SHA-256( JCS( entry WITHOUT the entry_hash field ) ) )
```

That is: remove the `entry_hash` field from the complete entry object, canonicalize the remaining object (ten fields, including `prev_hash`) per RFC 8785, and hash the resulting UTF-8 bytes with SHA-256.

**Chaining rules:**

- `prev_hash` of the entry with `seq = n` (n > 1) MUST equal `entry_hash` of the entry with `seq = n − 1`.
- The genesis entry (`seq = 1`) MUST carry `prev_hash = "000…0"` (64 zero characters) and MUST be of type `GENESIS`. `GENESIS` occurs exactly once in a chain, as its first entry: a first entry of another type, or a `GENESIS` anywhere else, is `FORMAT_ERROR` (exit 3). The other checks still run and report their findings; the chain end is, as for every format error, not judged (Section 8.6).
- `seq` MUST be gapless: any deviation (gap, jump, duplicate) is the finding `SEQ_BREAK`; any hash break is `HASH_MISMATCH` (both exit 2, Section 11).
- Storage is JSON Lines (one entry per line) in segment files (Section 10.1). The verifier MUST canonicalize itself before hash checking; the stored byte order carries no evidentiary weight.

## 4. Entry Types

This version defines 25 entry types (an entry type not defined here is handled per Section 10.6). Nine of them are **critical types** (registry attribute `critical_checkpoint`): `GENESIS`, `GAP`, `MODE_CHANGE`, `SEAL`, `OVERSIGHT`, `KEY_ROTATION`, `CONTENT_DELETED`, `CONTENT_DISCLOSED`, `LEGAL_HOLD`. After every entry of a critical type, the immediately following entry MUST be a `CHECKPOINT` (immediate-checkpoint obligation, Section 6).

### 4.1 GENESIS *(critical)*

First entry of every chain (`seq = 1`) and the only one of its type; anywhere else it is `FORMAT_ERROR` (Section 3). Binds customer identity, device key, licence and declared system purpose to the chain.

| Field | Type | Description |
|---|---|---|
| `customer_id` | string, maxlen 128 | customer identifier |
| `appliance_id` | uuid | appliance identifier |
| `device_pubkey` | hex64 | Ed25519 public key of the device key |
| `device_key_id` | string, maxlen 64 | device key identifier |
| `license_id` | string, maxlen 64 | licence commitment: from edition 1.8 `Hex(SHA-256(UTF-8(licence key)))`, exactly 64 characters `[0-9a-f]` (below) |
| `edition` | enum: `starter` \| `pro` \| `group` \| `enterprise` | product edition |
| `purpose_statement` | string, maxlen 2000 | system purpose declared during onboarding; descriptive evidence |
| `language` | enum: `de` \| `en` | system language |
| `timezone` | string, maxlen 64 | time zone (IANA name) |
| `predecessor_chain` | object? | emergency chain succession; `null` for a first chain. Fields: `chain_id` (uuid), `last_entry_hash` (hex64), `reason` (string, maxlen 500) |

**`license_id` is the commitment, never the key (from edition 1.8).** A `GENESIS` MUST NOT contain the licence key: the entry is in every verification package, and a chain can never shed it. `license_id` MUST therefore be the commitment of the licence key: SHA-256 over its UTF-8 bytes, lowercase hex, the same value as the activation's `license_commitment` (heartbeat specification §4). It is the commitment at the time the chain was created; after a replacement of the key (heartbeat specification §4.1) the current one differs from it, without the chain being faulty. The field name stays so that older verifiers keep accepting these chains (Section 10.6, rule 3). A `GENESIS` whose own `spec_version` is 1.8 or newer and whose `license_id` does not consist of exactly 64 characters `[0-9a-f]` is `FORMAT_ERROR`. What counts is the `spec_version` of the `GENESIS` entry itself, which is bound in its `entry_hash`, not that of the manifest.

Up to edition 1.7 this specification did not define the content of `license_id`, and the standard installation wrote the licence key into it in cleartext. If a `GENESIS` with `spec_version` up to 1.7 carries in `license_id` a value that is not exactly 64 characters `[0-9a-f]`, the verifier MUST point out that the licence key may stand there and that every holder of the package then knows it. The notice is not a finding and does not change the result; the verifier does not print the value itself. If the package is a format error (exit 3), the notice is dropped like every further statement about the chain (Section 8.6); the auditor requests a clean package. In the JSON output it stands, for the Go verifier, as `stats.genesis_license_not_commitment` (only when it applies) and, for the second verifier, as a top-level `genesis_license_not_commitment` (`true`, `false`, or `null` at exit 3). An appliance that moves from 1.7 to 1.8 keeps its `GENESIS` and with it the notice; the vendor replaces the key (heartbeat specification §4.1).

### 4.2 AI_CALL

One recorded AI call (proxy capture or passive import). Content never appears in plaintext, only as commitments (Section 9).

| Field | Type | Description |
|---|---|---|
| `provider_class` | enum, see 4.26 | provider class |
| `route` | string, maxlen 200 | configured route |
| `model` | string?, maxlen 200 | model identifier as reported by the traffic |
| `endpoint` | string, maxlen 400 | endpoint addressed |
| `http_status` | int, 0 to 599 | HTTP status; 0 = no status |
| `outcome` | enum: `ok` \| `error` \| `upstream_error` \| `aborted` | outcome |
| `duration_ms` | int, min 0 | duration |
| `request_bytes` | int, min 0 | request size |
| `response_bytes` | int, min 0 | response size |
| `tokens_in` | int?, min 0 | input tokens, if known |
| `tokens_out` | int?, min 0 | output tokens, if known |
| `streamed` | bool | streaming response |
| `confidence` | enum: `recorded` \| `claimed` | `recorded` = captured by the proxy; `claimed` = asserted by provider/import source |
| `source_id` | string?, maxlen 128 | import source identifier; `null` for proxy |
| `source_ref` | string?, maxlen 256 | identifier inside the source (idempotency) |
| `mode` | enum: `full` \| `hash_only` | capture mode |
| `request_commitment` | hex64? | HMAC-SHA-256(salt, request plaintext); salt stored with the vault object |
| `response_commitment` | hex64? | HMAC-SHA-256(salt, response plaintext) |
| `vault_ref` | string?, maxlen 128 | reference to the vault object |

### 4.3 TICK

Liveness signal of the write path, every 5 minutes (Section 8.1).

| Field | Type | Description |
|---|---|---|
| `uptime_s` | int, min 0 | process uptime |
| `spool_backlog` | int, min 0 | spool backlog (entries) |
| `disk_pct` | int, 0 to 100 | disk usage |

### 4.4 GAP *(critical)*

Honestly declared capture gap: a time window in which events may be missing. Covers a silence window (Section 8.2) and holds answered calls that are not in the chain (Section 8.7).

| Field | Type | Description |
|---|---|---|
| `reason` | enum, see 4.26 | gap class |
| `started_ts` | rfc3339 | window start (inclusive) |
| `ended_ts` | rfc3339 | window end (inclusive) |
| `lost_count` | int, min −1 | lost events; `-1` = unknown |
| `detail` | string?, maxlen 500 | free-text detail |

**Window (from edition 1.9, addition of 2026-10-02).** `started_ts` and `ended_ts` are times on the appliance's wall clock, the one that writes `ts_chained`. A call lies inside the window if the time from its intake to its end of answer touches the window (Section 8.7). The window can therefore begin before the last entry preceding the silence it covers. It does not necessarily contain the `ts_captured` of every call that may be missing: that lies at most the call's duration before `started_ts`; a reconciliation under Section 4.6 over such a window widens it backwards by the longest call duration. The verifier checks the window only under Section 8.2.

### 4.5 SOURCE_GAP

Declared gap of an import source (source sequence gap, missing fetch window).

| Field | Type | Description |
|---|---|---|
| `source_id` | string, maxlen 128 | source identifier |
| `window_start` | rfc3339 | window start |
| `window_end` | rfc3339 | window end |
| `expected` | int?, min 0 | expected events, if known |
| `observed` | int, min 0 | observed events |
| `detail` | string?, maxlen 500 | free-text detail |

### 4.6 RECONCILIATION

Reconciliation of chained counts against provider figures (usage API). The answer to gateway bypass / shadow usage.

| Field | Type | Description |
|---|---|---|
| `source_id` | string, maxlen 128 | source identifier |
| `window_start` | rfc3339 | window start |
| `window_end` | rfc3339 | window end |
| `reported_count` | int, min 0 | reported by the provider |
| `chained_count` | int, min 0 | present in the chain |
| `delta` | int | difference (`reported_count − chained_count`) |

### 4.7 CLOCK_JUMP

Declared jump of the wall clock (Sections 8.5, 9.2).

| Field | Type | Description |
|---|---|---|
| `wall_before` | rfc3339 | wall clock before the jump |
| `wall_after` | rfc3339 | wall clock after the jump |
| `mono_delta_ms` | int, min 0 | monotonic duration across the jump |
| `jump_ms` | int | jump size (negative = set back) |

### 4.8 MODE_CHANGE *(critical)*

Change of capture mode (`full` ↔ `hash_only`).

| Field | Type | Description |
|---|---|---|
| `from` | enum: `full` \| `hash_only` | previous mode |
| `to` | enum: `full` \| `hash_only` | new mode |
| `cause` | enum: `manual` \| `disk_pressure` | trigger |
| `actor` | string?, maxlen 128 | acting person, if manual |

### 4.9 RESTART

Restart of the write path.

| Field | Type | Description |
|---|---|---|
| `reason` | enum: `crash_recovery` \| `self_terminate` \| `update` \| `manual` \| `unknown` | restart reason |
| `downtime_ms_estimate` | int, min −1 | estimated downtime: from `ts_chained` of the last surviving entry of the previous process to this `RESTART`, not from the start of a following `GAP` window (Section 8.7); `-1` = unknown |
| `version` | string, maxlen 40 | software version after restart |

### 4.10 SEAL *(critical)*

Planned sealing of the chain (update, shutdown, decommission, export). Start of a handover (Section 8.4) or, if no `RESUME` follows, regular closure of the chain (Section 8.6).

| Field | Type | Description |
|---|---|---|
| `version` | string, maxlen 40 | sealing software version |
| `reason` | enum: `update` \| `shutdown` \| `key_loss` \| `decommission` \| `export` | sealing reason |

`export` (from edition 1.9) is the **export seal**: the running installation seals the chain for a verification package, and the same writer continues it immediately with `RESUME` (Section 8.4). A package that ends at the immediate checkpoint of this seal is sealed (Section 8.6). A verifier up to edition 1.8 does not know the value (Section 8.6, "Older verifiers").

### 4.11 RESUME

Resumption after a SEAL. Closes the handover.

| Field | Type | Description |
|---|---|---|
| `prev_version` | string, maxlen 40 | version before the SEAL |
| `new_version` | string, maxlen 40 | version after resumption |
| `sealed_entry_hash` | hex64 | MUST equal `entry_hash` of the SEAL entry being continued from |

### 4.12 OVERSIGHT *(critical)*

Human oversight event (approval, rejection, escalation), submitted through the portal.

| Field | Type | Description |
|---|---|---|
| `action` | enum: `approval` \| `rejection` \| `escalation` | oversight action |
| `user` | string, maxlen 128 | acting person (taken from the session, never from the form) |
| `role` | string, maxlen 64 | role of the acting person (taken from the session, never from the form) |
| `reference` | string, maxlen 256 | what is being decided (e.g. chain `seq`, case id) |
| `justification` | string, maxlen 4000 | justification |

### 4.13 ALARM

Rule-based alarm (no AI in the product).

| Field | Type | Description |
|---|---|---|
| `rule_id` | enum, see 4.26 | alarm rule |
| `severity` | enum: `info` \| `warning` \| `critical` | severity |
| `message_key` | string, maxlen 128 | i18n key |
| `details` | string?, maxlen 1000 | details |
| `delivered_smtp` | bool | delivered via SMTP |

### 4.14 CONFIG_CHANGE

Configuration change, including onboarding steps.

| Field | Type | Description |
|---|---|---|
| `scope` | enum: `onboarding` \| `source` \| `rule` \| `alarm` \| `smtp` \| `tls` \| `system` \| `compliance_signoff` | scope |
| `key` | string, maxlen 128 | configuration key |
| `value_commitment` | hex64? | commitment of the new value where the value itself is sensitive |
| `summary` | string?, maxlen 500 | summary |
| `actor` | string, maxlen 128 | acting person |
| `step_id` | string?, maxlen 64 | onboarding step id (duration measurement) |

### 4.15 KEY_ROTATION *(critical)*

Rotation of the device key; the old key attests the new one (trust chain, Section 6.4).

| Field | Type | Description |
|---|---|---|
| `old_key_id` | string, maxlen 64 | old key |
| `new_key_id` | string, maxlen 64 | new key |
| `new_pubkey` | hex64 | public key of the new key |
| `signature_by_old_key` | hex128 | Ed25519 by the OLD key over `JCS({old_key_id, new_key_id, new_pubkey})` |

### 4.16 REPORT_ISSUED

Issued report, bound to the chain via file hashes and data state.

| Field | Type | Description |
|---|---|---|
| `report_type` | enum: `monthly` \| `quarterly` \| `audit` | report type |
| `period_start` | rfc3339 | reporting period start |
| `period_end` | rfc3339 | reporting period end |
| `tree_size` | int, min 0 | data state of the report |
| `html_hash` | hex64 | SHA-256 of the HTML rendition |
| `pdf_hash` | hex64? | SHA-256 of the PDF rendition; `null` when only HTML was produced |
| `renderer_version` | string, maxlen 64 | renderer version |
| `languages` | string, maxlen 16 | produced languages (e.g. `de,en`) |

### 4.17 CONTENT_DELETED *(critical)*

Retention-driven or ordered deletion of a vault content while the chain stays intact: proves THAT and WHEN deletion happened.

| Field | Type | Description |
|---|---|---|
| `target_seq` | int, min 1 | `seq` of the affected entry |
| `vault_ref` | string, maxlen 128 | deleted vault object |
| `reason` | enum: `retention` \| `dsgvo_request` \| `manual` | deletion reason |
| `actor` | string, maxlen 128 | acting person |

### 4.18 CONTENT_DISCLOSED *(critical)*

Handing out the plaintext of a vault content to a person (audit, access request, incident, manual inspection) while the chain stays intact: records WHEN, to WHOM and WHY a hand-out of a stored content was initiated. The entry carries NO plaintext and NO commitment material, only the attribution and the sizes of the parts handed out.

| Field | Type | Description |
|---|---|---|
| `target_seq` | int, min 1 | `seq` of the disclosed entry |
| `vault_ref` | string, maxlen 128 | disclosed vault object |
| `actor` | string, maxlen 128 | acting person (taken from the session, never from the form) |
| `role` | string, maxlen 64 | role of the acting person at the time of disclosure |
| `reason` | enum: `audit` \| `dsgvo_request` \| `incident` \| `manual` | disclosure reason |
| `request_bytes` | int, min 0 | size of the request plaintext handed out, in bytes |
| `response_bytes` | int, min 0 | size of the response plaintext handed out, in bytes |

**Proof before disclosure.** LEDGER MUST chain the `CONTENT_DISCLOSED` entry (including the immediate checkpoint per Section 6.2) BEFORE it hands out the plaintext. If chaining fails, the plaintext MUST NOT be handed out. Hence there is no disclosure the chain does not know about. The converse does NOT hold: a `CONTENT_DISCLOSED` entry does not prove that the plaintext reached the recipient (immediate checkpoint failed, response not delivered, crash in between); it proves that a hand-out with this attribution was initiated.

A disclosure is not a verifier finding: a valid `CONTENT_DISCLOSED` entry with its immediate checkpoint yields no finding class (exit 0). If the immediate checkpoint is missing, `MISSING_CHECKPOINT` (exit 2) applies as for every critical type.

### 4.19 ADMIN

Verbatim self-recording of every message sent to the vendor.

| Field | Type | Description |
|---|---|---|
| `message_type` | enum: `activation` \| `heartbeat` \| `anchor` | message type |
| `payload_canonical` | string, maxlen 16000 | the exact JCS bytes sent, verbatim as a string |
| `payload_hash` | hex64 | SHA-256 over `payload_canonical` |

### 4.20 CHECKPOINT

Signed tree head; details in Section 6.

| Field | Type | Description |
|---|---|---|
| `tree_size` | int, min 1 | number of leaves covered = all entries with `seq` smaller than this entry's `seq` |
| `merkle_root` | hex64 | Merkle root over leaves 1…`tree_size` (Section 5) |
| `prev_checkpoint_hash` | hex64 | `entry_hash` of the previous CHECKPOINT entry; 64 zero characters for the first |
| `key_id` | string, maxlen 64 | signing device key |
| `signature` | hex128 | Ed25519 by the device key, signed subject see Section 6.1 |

### 4.21 CHECKPOINT_RECEIPT

Countersignature (receipt) by the vendor server over an anchored checkpoint; details in Section 7.1.

| Field | Type | Description |
|---|---|---|
| `checkpoint_seq` | int, min 1 | `seq` of the receipted CHECKPOINT entry |
| `tree_size` | int, min 1 | receipted tree size; MUST match the checkpoint |
| `merkle_root` | hex64 | receipted root; MUST match the checkpoint |
| `server_ts` | rfc3339 | server time of the receipt |
| `server_key_id` | string, maxlen 64 | vendor key identifier |
| `server_signature` | hex128 | Ed25519 by the vendor key, signed subject see Section 7.1 |

### 4.22 TIME_ANCHOR

Time stamp by an independent time-stamping authority (RFC 3161) over a checkpoint; details and verification rules in Section 7.3.

| Field | Type | Description |
|---|---|---|
| `checkpoint_seq` | int, min 1 | `seq` of the attested CHECKPOINT entry |
| `tree_size` | int, min 1 | attested tree size; MUST match the checkpoint |
| `merkle_root` | hex64 | attested root; MUST match the checkpoint |
| `tsa_name` | string, maxlen 256 | the authority as configured or confirmed by the customer (Section 7.3); descriptive, not evidentiary |
| `tsa_policy` | string, maxlen 128 | `policy` OID from the token; MUST match the token |
| `tsa_serial` | string, maxlen 128 | `serialNumber` from the token, lowercase hex: the value in hexadecimal without leading zeros, `0` for zero, with a leading `-` for a negative value (T.5 admits any INTEGER); MUST match the token |
| `tsa_ts` | rfc3339 | `genTime` from the token in the time format of Section 2; MUST match the token |
| `token_base64` | string, maxlen 21848 | the DER-encoded TimeStampToken (RFC 3161), base64; the DER MUST be ≤ 16384 bytes |

The three fields `tsa_policy`, `tsa_serial` and `tsa_ts` are **readings from the token**, not a second source: they make the chain legible without an ASN.1 parser. Only `token_base64` is evidentiary. A reading that contradicts the token is the finding `TIME_ANCHOR_INVALID`, not a reason to adopt one value over the other.

TIME_ANCHOR is **not a critical type**: it follows a checkpoint, it does not trigger one.

### 4.23 CAPTURE_TRUNCATED

The gateway forwards every body completely but captures only its first `max_body_bytes` bytes (capture limit). If a body was cut in the process, this entry follows the `AI_CALL`. `request_bytes` and `response_bytes` of the AI_CALL stay the real sizes; `request_commitment`, `response_commitment` and the vault content cover the captured bytes.

| Field | Type | Description |
|---|---|---|
| `target_seq` | int, min 1 | `seq` of the AI_CALL entry whose capture was cut |
| `request_bytes_captured` | int, min 0 | captured bytes of the request; commitment and vault content cover this many |
| `response_bytes_captured` | int, min 0 | captured bytes of the response; likewise |
| `request_truncated` | bool | the request was cut |
| `response_truncated` | bool | the response was cut |

The producer SHOULD chain the entry immediately after the AI_CALL. If that fails, it is missing: an AI_CALL without this entry is therefore no proof that nothing was cut; if `request_bytes` or `response_bytes` exceeds the capture limit, the cut stays recognisable. CAPTURE_TRUNCATED is **not a critical type** and **not a finding**: the call itself is fully chained, only the capture is cut. Verifiers check the schema. Introduced with edition 1.5; a verifier of edition 1.4 reports the type as `UNKNOWN_ENTRY_TYPE` (Section 10.6, rule 2) and otherwise checks the chain completely.

### 4.24 LEGAL_HOLD *(critical)*

Setting or releasing a deletion block (legal hold) over stored content. Proves THAT, WHEN, FOR WHAT and BY WHOM a hold existed (Section 9.3). Introduced with edition 1.7; a verifier of edition 1.6 reports the type as `UNKNOWN_ENTRY_TYPE` (Section 10.6, rule 2) and otherwise checks the chain in full.

| Field | Type | Description |
|---|---|---|
| `action` | enum: `set` \| `release` | set or release the hold |
| `hold_id` | string, maxlen 64 | identifier of the hold; a `release` names the `hold_id` of a hold that was set |
| `scope_from` | rfc3339 | earliest capture time covered (`ts_captured`); unbounded: `0001-01-01T00:00:00.000Z` |
| `scope_to` | rfc3339 | latest capture time covered; unbounded: `9999-12-31T23:59:59.000Z` |
| `reference` | string, maxlen 200 | occasion or case reference |
| `actor` | string, maxlen 128 | acting person |

### 4.25 DATA_ACCESS

From edition 1.10. A recorded access by a person or a service to customer data of a vendor within the meaning of heartbeat specification §12 (access chain). The entry carries no free text, no identifier of a customer, no name and no content of the data; what justifies the access stands in a case record kept by the operator of the chain, to which the entry is bound by a commitment. Only an access chain (heartbeat specification §12) writes this type; the chain of a customer's appliance does not carry it.

| Field | Type | Description |
|---|---|---|
| `access_id` | uuid | identifier of the access; if an access concerns several data classes, each of its entries carries the same one |
| `actor_kind` | enum: `person` \| `service` | who accesses |
| `actor_id` | uuid | identifier of the account in the operator's account directory; every addition to the directory stands beforehand as an entry of its own in the chain (heartbeat specification §12, access chain, item 4) |
| `purpose` | enum: `support` \| `license_admin` \| `affiliation_upkeep` \| `fleet_supervision` \| `incident` \| `maintenance` \| `restore` \| `data_subject_request` \| `legal_order` \| `audit` \| `service` \| `other` | purpose (below) |
| `data_class` | enum: `license` \| `registration` \| `heartbeat` \| `chain` \| `journal` \| `affiliation_register` \| `alarm_contact` \| `order_system` \| `credentials` \| `access_chain` \| `operations_log` \| `backup` \| `store` \| `other` | data class (below) |
| `access_mode` | enum: `read` \| `change` \| `export` | kind of access |
| `scope` | enum: `one_customer` \| `several_customers` \| `all_customers` | scope |
| `record_commitment` | hex64 | commitment of the case record kept by the operator (below) |
| `capture` | enum: `gate` \| `declared` \| `emergency` | how the access was recorded (below) |

- **Times.** `ts_captured` is the time of the access: for `gate` the arrival of the request at the access path, for the entry of a service per start that start, for a collective entry of a service `end(d)` of its day `d` as a point in time (heartbeat specification §12, access chain, item 1), for `declared` and `emergency` the start of the access as stated by the person. `ts_chained` is the chaining; the distance between the two shows how late an access was entered.
- **`capture`.** `gate`: the access path wrote the entry through an import interface (`origin = import`) and released data only after the interface had confirmed it (Section 8.7, Import). A service writes its entry per start and its collective entries with `gate` through the import interface in the same way, but does not wait for the confirmation (heartbeat specification §12, access chain, item 2). `declared`: a person entered the access himself (`origin = portal`), for instance after an access that no access path mediates. `emergency`: an access path released data without confirmation because the access chain was not reachable, and the person entered the access afterwards (`origin = portal`).
- **`record_commitment`** = `Hex(HMAC-SHA-256(key = salt, message = case record))`. The case record is the bytes the operator keeps on this access (occasion, justification, customers concerned, for `gate` the request); `salt` is a 32-byte random value per case record. Case record and salt stay with the operator, never in the chain (as in Section 9.1) and never on the installation that runs the access chain: for `declared` and `emergency` the person enters `access_id` and `record_commitment` as the operator formed them for case record and salt. An access chain carries at most one entry per (`access_id`, `data_class`), whichever route it came by; an access whose data were released without confirmation stands in it only as `emergency`, never additionally as `gate`. Whoever is given both recomputes the commitment; the verifier does not (no evidence produced by LEDGER for the content of the case record).
- **Data classes** follow the list "What the vendor holds" in heartbeat specification §12: `license` licenses; `registration` registrations and device keys; `heartbeat` heartbeats; `chain` bindings, roots, changes of chain, fork findings and data of the vendor log, including openings of fillers (Section 7.4.13); `journal` issuance and binding journal and the declarations of the licensees (heartbeat specification §9.10, obligation 2); `affiliation_register` affiliation register; `alarm_contact` alarm addresses and alarm mailbox; `order_system` order system; `credentials` administrative access, keys and access tokens, the account directory of the access chain included; `access_chain` the access chain itself with its case records and salts (heartbeat specification §12), for instance when the audit reads it; `operations_log` operation logs; `backup` backups; `store` the whole data store, for instance the file of a database or access to a machine; `other` another class that the case record names.
- **Purposes.** `service` is the standing purpose of a service, recorded once per start of the service and per data class; only a part whose output no person reads directly counts as a service, every other part is an access path (heartbeat specification §12, access chain, item 1). A collective entry with which a service records administrative actions on licenses carries `license_admin` (ibid.). `other` refers to the case record.
- DATA_ACCESS is **not a critical type** and **not a finding**; verifiers check the schema. For the silence rules (Section 8.2) it covers nothing; like every entry it merely bounds a silence window. It does not enter residual windows and covered stretches (Section 11.2), and the evidence level (Section 10.9) does not read it. A verifier of edition 1.9 reports the type as `UNKNOWN_ENTRY_TYPE` (Section 10.6, rule 2) and otherwise checks the chain completely.

### 4.26 Referenced Enumerations

**Provider classes (`provider_classes`):** `openai`, `anthropic`, `azure_openai`, `google`, `aws_bedrock`, `mistral`, `aleph_alpha`, `ionos`, `ollama`, `vllm`, `other_us`, `other_eu`, `other_local`, `generic`. (Classes of providers/deployment forms, not model identifiers.)

**Gap classes (`gap_classes`):** `bypass`, `proxy_restart`, `power_loss`, `spool_unwritable`, `host_down`, `update`, `manual`.

**Alarm rules (`alarm_rules`):** `source_silence`, `volume_spike`, `error_rate_spike`, `new_provider_class`, `spool_backlog`, `disk_85`, `disk_92`, `disk_97`, `cert_expiry`, `anchor_overdue`, `report_missing`, `report_delivery_failed`, `component_silence`, `test_alarm`.

## 5. Merkle Tree (RFC 6962)

All entries of a chain, in `seq` order, are the leaves of a continuously growing Merkle tree per RFC 6962 with domain separation:

```
Leaf(n)          = SHA-256( 0x00 || Bytes(entry_hash of the entry with seq = n) )
Node(L, R)       = SHA-256( 0x01 || L || R )
```

`0x00` and `0x01` are single prefix bytes; `Bytes(…)` is the 32 raw bytes of the decoded `entry_hash`. The leaf input is therefore always 33 bytes, the node input 65 bytes.

**Root computation (Merkle Tree Hash, RFC 6962 § 2.1):** For a leaf list `D[0..n)` (leaf `D[i]` belongs to `seq = i + 1`):

- `MTH({d}) = SHA-256(0x00 || d)` for n = 1,
- `MTH(D[0..n)) = SHA-256(0x01 || MTH(D[0..k)) || MTH(D[k..n)))` for n > 1, where `k` is the largest power of two smaller than `n`.

**tree_size semantics:** A tree of size `t` covers exactly the entries `seq = 1 … t`, including earlier CHECKPOINT, CHECKPOINT_RECEIPT and all other entries. The `merkle_root` of a checkpoint with `tree_size = t` is `Hex(MTH over leaves 1…t)`.

**Inclusion proofs** (RFC 6962 § 2.1.1) show that an entry is a leaf of a tree with a given root. **Consistency proofs** (RFC 6962 § 2.1.2) show that a tree of size `t1` is a prefix of a tree of size `t2 ≥ t1`. The verifier MUST check for **every pair** of anchored roots `(t1, r1)`, `(t2, r2)` with `t1 ≤ t2` that `r1` is consistent with `r2` (for `t1 = t2`: equality). Since the verifier holds the complete package, it MAY compute the proofs itself from the leaves; a violation is the finding `MERKLE_INCONSISTENT` (exit 2).

**Trees of the vendor log (from edition 1.10).** The trees of Section 7.4 follow the same construction with domain separation. Their leaf data are the bytes of a leaf under Section 7.4, of any length; the leaf input is `0x00` followed by these bytes, the leaf hash `SHA-256(0x00 || leaf data)`. For the chain itself n ≥ 1 still applies. For these trees the following holds in addition:

- **Empty tree:** `MTH([]) = SHA-256("")` = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, the SHA-256 value of the empty byte string.
- **Inclusion proof** under RFC 9162 Section 2.1.3.2. A verifier MUST check it exactly by this procedure (`H` = SHA-256, `leaf_hash` = leaf hash, `path` = the sibling values from the leaf to the root):

```
verify_inclusion(index, size, leaf_hash, path, root):
  if index >= size: return false
  fn = index; sn = size - 1; r = leaf_hash
  for p in path:
    if sn == 0: return false
    if (fn & 1) == 1 or fn == sn:
      r = H(0x01 || p || r)
      if (fn & 1) == 0:
        while (fn & 1) == 0 and fn != 0: fn >>= 1; sn >>= 1
    else:
      r = H(0x01 || r || p)
    fn >>= 1; sn >>= 1
  return sn == 0 and r == root
```

  The tree size `size` MUST come from the signed day entry (Section 7.4.5), never from the proof material: the same path can also hold for a wrong size (example: the path to the leaf with index 2 of a tree of size 5 also holds for size 6).
- **Absence proof:** In a tree of size n with root R whose leaves are ordered strictly ascending by their position (Section 7.4.4), exactly one of the following forms proves that the position p does not occur in it: (i) n = 0 and no neighbour; (ii) one neighbour with index 0, and p is smaller than its position; (iii) one neighbour with index n − 1, and its position is smaller than p; (iv) two neighbours with the indices i and i + 1, and pos_i < p < pos_{i+1}. Every neighbour leaf MUST hold by an inclusion proof against (n, R). Positions are compared as unsigned 32-byte values; this is equivalent to comparing their lowercase hex form.

## 6. Checkpoints

### 6.1 Signed Subject

A `CHECKPOINT` entry (Section 4.20) carries an Ed25519 signature by the customer's device key. The signed subject is **exactly**:

```
JCS({ "chain_id": …, "tree_size": …, "merkle_root": …,
      "prev_checkpoint_hash": …, "key_id": …, "ts": … })
```

with:

- `chain_id` = `chain_id` of the envelope,
- `tree_size`, `merkle_root`, `prev_checkpoint_hash`, `key_id` = the payload fields of the same name,
- `ts` = **`ts_chained` of the CHECKPOINT entry** (string, unchanged).

Per RFC 8785, the canonical key order is `chain_id, key_id, merkle_root, prev_checkpoint_hash, tree_size, ts`. Example of the canonical signed subject (one line):

```
{"chain_id":"6f0f…","key_id":"dev-2026-01","merkle_root":"ab12…","prev_checkpoint_hash":"0000…","tree_size":41,"ts":"2026-08-28T09:05:00.000Z"}
```

`tree_size` MUST equal `seq − 1` of the CHECKPOINT entry (the checkpoint covers all preceding entries; it is itself covered only by the next checkpoint). An invalid signature is the finding `SIG_INVALID` (exit 2).

### 6.2 Triggers

The chain writer MUST write a checkpoint:

1. at latest every **5 minutes** (provided at least one entry was added since the last checkpoint), OR
2. at latest every **1,000 entries**, OR
3. **immediately** after every entry of a critical type (`GENESIS`, `GAP`, `MODE_CHANGE`, `SEAL`, `OVERSIGHT`, `KEY_ROTATION`, `CONTENT_DELETED`, `CONTENT_DISCLOSED`, `LEGAL_HOLD`): the immediately following entry MUST be the checkpoint.

Rule 3 admits no exception and expressly includes `SEAL`: after a `SEAL` too, the immediately following entry MUST be its immediate checkpoint. That checkpoint is at the same time the only entry permitted between `SEAL` and `RESUME` (Section 8.4); the two rules therefore interlock without contradiction. If a critical entry is followed by an entry other than its checkpoint, this is the finding `MISSING_CHECKPOINT` (exit 2, Section 10.4). If the critical entry is instead the last entry of the chain, no entry is missing between two present ones; rather, the chain end is unanchored: from edition 1.6 this is not `MISSING_CHECKPOINT` but the status "incomplete" (`UNSEALED_END`, Section 8.6). An honest chain whose writer failed between the critical entry and its checkpoint ends this way too.

### 6.3 Checkpoint Chaining

Checkpoints form their own sub-chain via `prev_checkpoint_hash`: `prev_checkpoint_hash` MUST equal `entry_hash` of the previous CHECKPOINT entry; the first checkpoint of the chain carries 64 zero characters. The checkpoint history is thus gaplessly verifiable, independently of the main hash chain.

### 6.4 KEY_ROTATION Trust Chain

The signing key of a checkpoint (`key_id`) MUST either be the device key registered in `GENESIS` or be traceable back to it through a gapless sequence of `KEY_ROTATION` entries: each `KEY_ROTATION` carries `signature_by_old_key` = the Ed25519 signature of the **old** key over

```
JCS({ "old_key_id": …, "new_key_id": …, "new_pubkey": … })
```

(canonical order: `new_key_id, new_pubkey, old_key_id`). The verifier MUST check this signature against the public key valid up to that point and use the new public key from the KEY_ROTATION entry onward (including its immediate checkpoint). Before the KEY_ROTATION entry only the previous public key is valid: at every position of the chain exactly one device key is valid, and a checkpoint signed with the new key before the rotation or with the old key after it is `SIG_INVALID` (clarification 2026-09-03). Checkpoints signed with a key not legitimized this way are `SIG_INVALID`.

## 7. Anchoring

Anchoring binds tree roots to parties outside the key holder's control. If no anchor exists at all, the verifier reports `NO_ANCHOR` (exit 1); a receipt counts only if its signature holds (Section 7.1). The chain remains internally valid, but is more weakly evidenced against rewriting by the key holder (Section 11).

**Inputs outside the package (from edition 1.10).** Besides the three anchor types of the chain (countersignature, Section 7.1; paper anchor, Section 7.2; time witness, Section 7.3) there are two inputs that only the auditor supplies, never the package: the vendor log (Section 7.4) and the anchor history (Section 8.8). The verifier checks both against anchors of the auditor; the package remains unchanged. Countersignature and time witness stand as entries in the chain; the paper anchor is passed by the auditor as an expected root (Section 10.8). The same time-stamp profile (Section 7.5) applies to the time stamps of the time witnesses and of the vendor log.

### 7.1 Cloud Countersignature (CHECKPOINT_RECEIPT)

The appliance sends `{chain_id, tree_size, merkle_root}` to the vendor server; the server answers with an Ed25519 countersignature under server time. The signed subject is **exactly**:

```
JCS({ "chain_id": …, "tree_size": …, "merkle_root": …, "server_ts": … })
```

(canonical order: `chain_id, merkle_root, server_ts, tree_size`). The receipt is written back into the chain as a `CHECKPOINT_RECEIPT` entry (Section 4.21). Verification rules:

- `server_signature` MUST validate against the vendor public key for `server_key_id`, otherwise `RECEIPT_INVALID` (exit 2). Which public key that is, is decided by the following rule on the key's origin, not by the verification package alone.
- Every receipt whose signature holds MUST match a prefix of the chain at hand: the root for the receipted `tree_size`, recomputed from the leaves, MUST equal the receipt's `merkle_root`. If it matches no prefix history, that is `FORK_DETECTED` (exit 2), the strongest indication of a second history. A receipt whose signature does not hold is already `RECEIPT_INVALID`; nothing further is checked on it, since its content is no statement of the vendor.
- If the receipt matches a prefix, `tree_size` and `merkle_root` MUST also match the referenced checkpoint (`checkpoint_seq`); if `checkpoint_seq` references no CHECKPOINT or it differs, that is `RECEIPT_INVALID` (exit 2). With a fork this check is skipped, so the fork appears as its own class and not with derivative findings.
- `server_ts` provides an external upper time bound: the receipted tree state existed no later than `server_ts`.

**Origin of the vendor key (verifiers from edition 1.4).** The rule applies to **every** package, whatever `spec_version` it declares (like rule 5 in Section 10.6): a forger who declares an older version does not escape it. The verification package is written by exactly the party the receipt is meant to bind. A key from `manifest.vendor_pubkeys` or `keys/vendor/` therefore only proves that *somebody* signed the root: whoever rewrites a chain can invent a key pair, sign "receipts" with it and write the public key into the manifest. The trust anchor MUST therefore come from the AUDITOR, the same rule as for the time witness (Section 7.3). A verifier MUST offer the auditor two ways and MUST NOT derive a third from the package:

1. **Vendor root.** The vendor's offline root key as `{"wurzel_id", "pubkey"}` (Section 10.7), published with the licence; a vendor build of the verifier MAY carry it compiled in and MUST name it in its version output. The root vouches for countersigning keys through the signed list of countersigning keys `keys/vendor/schluesselliste.json` in the package (Section 10.7.1).
2. **Pinned key.** A single pair `key_id` = public key that the auditor obtained itself.

If the auditor names two roots with the same `wurzel_id` or two pins of the same `key_id` with different public keys (also against a compiled-in root), the audit environment is ambiguous; the verifier MUST reject the invocation (exit 3) and MUST NOT silently choose one of them.

For each receipt the verifier determines the key in this order:

- If `server_key_id` is pinned, the pinned public key applies. The signature is checked against **it**, not against the manifest's copy; if that fails, it is `RECEIPT_INVALID` (exit 2). The pin takes precedence over the list, including its validity window: whoever pins makes the statement about the key themselves.
- Otherwise: if the package carries a list whose signature holds against one of the auditor's roots (Section 10.7) and the list names `server_key_id`, the list's public key applies; the manifest's copy is then irrelevant. It is `RECEIPT_INVALID` (exit 2) if the signature fails against it or if `server_ts` lies outside the key's validity window (`gueltig_ab` ≤ `server_ts`; `server_ts` < `gueltig_bis` if present; `server_ts` < `widerrufen_ab` if present). In the second case the vendor's signed statement contradicts the receipt. `server_ts` is read with the grammar of Section 10.7; a `server_ts` that cannot be read that way lies in no window.
- Otherwise the manifest's public key applies. If the signature holds, the verifier reports `RECEIPT_UNVERIFIED` (exit 1), **once per `server_key_id`**, with `key_id` and public key in the report so the auditor can look the key up outside the package. If it fails, or the key is missing from the manifest, it remains `RECEIPT_INVALID` (exit 2).

A list that does not hold (no root supplied, another `wurzel_id`, failing signature, format violated) makes no key credible; but it is **not a forgery finding** either, since the list is part of no hash chain. The receipts concerned are then `RECEIPT_UNVERIFIED`, and the report names the reason. Likewise a key missing from a list that holds: the list may be older than the key.

The split between `RECEIPT_INVALID` and `RECEIPT_UNVERIFIED` follows Section 7.3: a signature that does not hold, or a signed statement of the vendor that contradicts the receipt, is a finding about the **chain**. A missing anchor is a statement about the **audit environment**. The best a forgery with an invented key can therefore reach is a named finding with exit 1, never exit 0.

**What counts as anchoring.** A receipt whose signature holds against the key determined by this rule counts as an external anchor present, also under `RECEIPT_UNVERIFIED`, as a time witness does under `TIME_ANCHOR_UNVERIFIED` (Section 7.3); `NO_ANCHOR` then adds nothing. A receipt with `RECEIPT_INVALID` does not count: if all receipts are invalid and no other anchor is present, the verifier reports `NO_ANCHOR` alongside. The prefix check (`FORK_DETECTED`) applies to every receipt whose signature holds, whether or not its key is established, and also when the list contradicts it: a contradiction must not hide a fork.

**Keys and lists beside this rule (from edition 1.10).** A key still establishes a receipt only by the two ways above, and only a key of the role `countersigning` (Section 10.7.3). Four clarifications:

- A key of another role never establishes a receipt: no statements key, no update manifest key and no protocol key of the vendor log (Section 7.4.7). The role list (Section 10.7.2) never establishes a receipt, not even with its entries of the role `countersigning`. A receipt that is not established by the two ways above and whose public key in the manifest is a key of another role (an entry of the effective role list with another role, a key of the effective protocol key list, or a pin as a statements or protocol key) is judged as in edition 1.9 (`RECEIPT_UNVERIFIED` if `manifest.vendor_pubkeys` names the key); the report gives the note `receipt_key_other_role` (Section 10.7.4), and for condition (3) of the evidence level the receipt has the origin `manifest` (Section 10.9.4).
- A pin as a countersigning key (`--vendor-key`) whose public key the effective role list names with another role is dropped (Section 10.7.4, step R3 (d)); it then counts as not passed. Without a role list the verifier does not see the role of a pin (Section 11.2).
- A list of countersigning keys the auditor passes himself (Section 10.8) establishes, in this edition, neither a receipt nor a page of the anchor history; it counts only in the role check (Section 10.7.4; Section 7.4.10, step L1). If a list of the auditor established receipts, a newer list whose `widerrufen_ab` lies before genuine, already issued receipts could turn archived honest packages into `RECEIPT_INVALID` (exit 2), targeted at one customer if his anchors carried a key of their own. For the same reason the role list establishes no receipt.
- That the vendor log contains a receipt does not establish its key; inclusion in a day tree is no third way. The report shows the inclusion beside the origin of the key.

**What this rule does not achieve.** The validity window is checked against `server_ts`, and `server_ts` sits in the receipt itself. Whoever holds a revoked key (exactly the case revocation exists for) can sign receipts with a `server_ts` before the revocation; the verifier compares `server_ts` with no other time of the chain, and the chain's key holder could backdate the chain's times as well. Only anchors the forger cannot create after the fact work against such backdating: the paper anchor (7.2), the time witness (7.3) and the freshness window (8.5). From edition 1.10 the vendor log works against it as well (Section 7.4): a receipt signed after the fact with a revoked or stolen key stands in no witnessed day tree of the day of its `server_ts`; if the auditor passes the log, the verifier reports `RECEIPT_NOT_LOGGED`. This holds for days whose entry is witnessed, not for days whose entry is not yet due, and not for days before the start of the log (`before_start`). A receipt whose `server_ts` lies after the check time stands in no closed day; the verifier reports it as `VENDOR_LOG_UNVERIFIED` (class `future`, Section 7.4.10, step L8), never as not yet due. Nor can the verifier tell whether a newer list exists than the one in the package: `version` is only comparable among lists. The report therefore names the version and issue time of the list used, so the auditor can check them with the vendor.

From `spec_version` 1.1 the appliance additionally attaches to the anchor the RFC 6962 consistency proof from the chain's reference size (the `tree_size` last receipted or recorded as a gap witness) to the new one (heartbeat specification §6 and §9.2); the vendor server countersigns a grown chain only when that proof holds. Nothing changes for the verifier: the receipt remains the object of proof, and the prefix check of this section remains its own.

### 7.2 Paper Anchor

The monthly report prints the Merkle roots (and `tree_size`) of the month's checkpoints. An auditor MAY pass a printed root to the verifier as the expected root (e.g. `--expect-root`); if the recomputed root differs, the chain is not consistent with the paper state (`MERKLE_INCONSISTENT`). Paper anchors are vendor-independent.

### 7.3 Time Witness (TIME_ANCHOR)

A time-stamping authority per RFC 3161 (TSA) attests that a checkpoint **already existed** at a given point in time. Unlike the vendor countersignature, that statement comes from a source controlled by neither the customer nor the vendor; the authority is set up by the customer or, upon a proposal, confirmed by him (below).

The time stamp is taken over the **canonical checkpoint signed subject** of Section 6.1, that is, over exactly the bytes the checkpoint's device signature covers as well. It therefore attests not only the root but `chain_id`, `tree_size`, `prev_checkpoint_hash`, `key_id` and the checkpoint time along with it.

The token's `messageImprint` MUST be `H(JCS(checkpoint signed subject))`, where `H` is the imprint algorithm named in the token itself. Permitted are `sha256`, `sha384`, `sha512`; `sha1` is NOT: a collision on the imprint would let one token attest two different checkpoints, which is precisely what the anchor is meant to rule out.

The token is written into the chain as a `TIME_ANCHOR` entry (Section 4.22). A time witness is **optional**: a chain without a TIME_ANCHOR is not deficient for that reason, and its absence is not a finding.

**Proposed authority (from edition 1.10).** An appliance MAY propose a time-stamping authority to the customer during setup. For a proposed authority the same applies as for any other, and in addition:

1. It is operated neither by the vendor nor by a party affiliated with it (heartbeat specification §12).
2. The appliance connects to it only once the customer has confirmed it; until then not a single byte goes to it. The customer can deselect it at any time or replace it by another authority.
3. The appliance queries the authority directly, never through the vendor. The request carries nothing about the installation or the customer and no entitlement that the vendor grants or pays for; it SHOULD carry a nonce and `certReq = true`.
4. The vendor does not deliver the authority's root, neither in the verification package (`keys/tsa/`) nor as a file for the auditor, and no verifier carries it built in. The vendor's documentation names the authority and the place where the authority itself publishes its root; the auditor obtains the root there or from a trusted list (Section 10.8).
5. It SHOULD be run by a different operator than the authorities the vendor uses for the day entries of its log (heartbeat specification §9.9), so that time witnesses of the chain and time stamps of the log do not rest on the same authority.

Which authority is proposed, at what interval the appliance queries it and how setup proceeds is not fixed by this specification. For the verifier there is no proposed authority: it checks every TIME_ANCHOR by the same steps, and an authority counts only through a root the auditor passes. Whether an authority is attributable to the customer or to the vendor the verifier does not check (Section 11.2).

**Verification rules.** For every TIME_ANCHOR the verifier MUST check, in this order. From edition 1.10 the rules of the time-stamp profile (Section 7.5) apply, so that every verifier judges the same token alike:

1. `checkpoint_seq` references a CHECKPOINT whose `tree_size` and `merkle_root` match the entry's fields. Otherwise `TIME_ANCHOR_INVALID` (exit 2).
2. `token_base64` follows the grammar B64 (Section 2), the decoded DER comprises at most 16,384 bytes, and the token follows the grammar T (Section 7.5.2): a TimeStampToken with exactly one signer and exactly one TSTInfo in strict DER. Otherwise `TIME_ANCHOR_INVALID` (exit 2).
3. The three readings `tsa_policy`, `tsa_serial` and `tsa_ts` agree with the token. The imprint algorithm has no field in the entry; it is used in step 4. From edition 1.10 `tsa_ts` MUST equal `genTime`, truncated to milliseconds (not rounded), in the form `YYYY-MM-DDThh:mm:ss.sssZ`; a `genTime` with fractional seconds is permitted. The form of `tsa_ts` is already checked by the schema of the payload (another form is `FORMAT_ERROR`); what counts in this step is whether a value of this form equals `genTime` truncated to milliseconds. Otherwise `TIME_ANCHOR_INVALID` (exit 2).
4. The token's `messageImprint` equals the imprint named above over the signed subject of the referenced checkpoint. Otherwise `TIME_ANCHOR_INVALID` (exit 2). **This is the load-bearing binding**, and it is checkable without any signature check: compute the imprint, compare it with `hashedMessage` in the TSTInfo.
5. The token's CMS signature, from edition 1.10 in two parts:
   - **5a Performability.** The token carries signed attributes and `certificates`; every element of `certificates` satisfies Z.1 (Section 7.5.3); the signer is found exactly once under Z.5 (Section 7.5.5); the signer's digest and signature algorithms and its key lie within Z.2 (Section 7.5.4) and fit each other under Z.2. Otherwise the signature cannot be checked: `TIME_ANCHOR_UNVERIFIED` (exit 1) with the reason, never exit 2.
   - **5b Check.** The attribute `contentType` names id-ct-TSTInfo, `messageDigest` is the hash of `eContent` under the signer's `digestAlgorithm`, and the signature holds under the key of the signer certificate over the DER encoding of the signed attributes with the tag `0x31` instead of `0xA0` (RFC 5652 Section 5.4). If that fails, it is `TIME_ANCHOR_INVALID` (exit 2); a token that does not carry its own signature is forged or damaged.
6. The signer certificate chains under Z.3 and Z.4 (Section 7.5.5) to a trust anchor the AUDITOR supplies for time witnesses of the chain (an explicitly passed root; from edition 1.10 the system root store counts for no purpose) and carries exactly the extended key usage `id-kp-timeStamping`, marked critical (RFC 3161 Section 2.3). Only roots of purpose `chain` may count (Section 7.5.7). The chain is validated **at the token's `genTime`**, not at the time of verification; otherwise the proof would expire with the authority's certificate. If that does not succeed, the finding is `TIME_ANCHOR_UNVERIFIED` (exit 1); if a path leads to a certificate from `keys/tsa/`, the report names the authority as described below.

The steps divide the possible results as follows (from edition 1.10, alike for every verifier):

| Result | Cases | Finding |
|---|---|---|
| step 2 fails | `token_base64` violates B64; DER larger than 16,384 bytes; the token violates grammar T | `TIME_ANCHOR_INVALID` (exit 2) |
| step 1, 3 or 4 fails | as described in the steps, with the rule for `tsa_ts` of step 3 | `TIME_ANCHOR_INVALID` (exit 2) |
| step 5 performed and failed (5b) | `contentType` is not id-ct-TSTInfo; `messageDigest` differs from the hash of `eContent`; the signature does not hold under the signer's key | `TIME_ANCHOR_INVALID` (exit 2) |
| step 5 not performable (5a) | no signed attributes; no `certificates`; the content of `certificates` does not split into TLVs; an element of `certificates` is no certificate or violates Z.1; signer not found or found more than once (Z.5); digest or signature algorithm or key of the signer outside Z.2; key and algorithm do not fit each other | `TIME_ANCHOR_UNVERIFIED` (exit 1) with the reason |
| step 6 fails | no path under Z.3 and Z.4 at `genTime` to a root of the auditor for time witnesses | `TIME_ANCHOR_UNVERIFIED` (exit 1) |
| step 6 holds | a path to a root of the auditor for time witnesses | no finding |

The binding of the signer certificate in the signed attributes (Z.6, Section 7.5.6) does not change the finding of a TIME_ANCHOR; it counts for the evidence level (Section 10.9).

**Steps 1 through 4 are mandatory for every verifier.** They need no signature check and no certificates: decode base64 under B64, read the token's wrapper under grammar T, compute the imprint over the signed subject and compare it with `hashedMessage`, compare the three readings. They MUST complete independently of reading the certificates: a peculiarity of a certificate never leads to exit 2, at most to step 5a. A verifier that CANNOT perform steps 5 and 6 (because no CMS implementation is available to it) MUST NOT turn that into `TIME_ANCHOR_INVALID`. It MUST report `TIME_ANCHOR_UNVERIFIED` (exit 1) and state in the report that it did not check the signature. This rule is not a convenience but the condition for the specification remaining implementable with ordinary means (Section 1): everyone can check the load-bearing binding, not everyone can check the signature chain.

The split between 5 and 6 is deliberate. A broken signature is a forgery finding. A missing or unreachable trust anchor is a **statement about the verification environment**, not about the chain, and a verifier that treated both alike would either declare honest chains manipulated or wave forged ones through. For the same reason step 5 separates performability (5a) from the check (5b): a token whose signature a verifier cannot check under the profile is not checkable for it, not forged.

**Why the trust anchor must not come from the package.** The verification package is written by exactly the party the time witness is meant to constrain. A certificate from `keys/tsa/` therefore establishes self-consistency only. A verifier MAY use such certificates for chain building, but in that case it MUST report `TIME_ANCHOR_UNVERIFIED` (exit 1) and name the authority in the report (name, serial number, `genTime`) so the auditor can look it up outside the package. Only an anchor the auditor supplies makes the witness independent.

A TIME_ANCHOR that passes steps 1 through 4 counts as an external anchor being present: `NO_ANCHOR` (Section 7) is then NOT reported, even if step 6 fails. The two findings say different things ("no anchoring is present" and "the one present is not independently established"), and only the second applies here. The split also keeps verifiers that cannot perform step 6 at all in agreement.

**What the time witness does not do.** It proves that a checkpoint existed at a point in time, not that the chain is complete. It works against the residual window of Section 11.2, because a history rewritten later cannot produce a token with an earlier `genTime`; against the omission of entries BEFORE the time stamp, only the hash chain, Merkle consistency and the remaining anchors continue to work.

### 7.4 Vendor Log

From edition 1.10. With the vendor log the vendor commits publicly, for every closed UTC day, to the set of countersignatures (Section 7.1) and gap witnesses (heartbeat specification §9.2) it issued or recorded on that day; time-stamping authorities witness the commitment. If the auditor passes the log, the verifier shows whether the receipts of the package stand in it and whether roots recorded there contradict the package. This section fixes formats and checks; how the vendor closes and publishes a day is governed by heartbeat specification §9.9.

#### 7.4.1 Position and Keys

The vendor log is an auditor input (Section 10.8). None of it stands in the verification package, in the chain, in a receipt, in the manifest, in the list of countersigning keys or the role list (Sections 10.7.1, 10.7.2), in a message of the appliance or in the anchor history of kind v1 (heartbeat specification §9.7); the appliance never fetches it (heartbeat specification §1). A verifier MUST NOT read material of the log from the package.

The vendor closes exactly one day entry per UTC day, without gaps from the day `erster_tag` of its protocol key list (Section 7.4.7), also for a day without leaves. The day entry commits the vendor to all countersignatures and gap witnesses of the day (Section 7.4.2), carries the signature of a protocol key of its own (Section 7.4.5) and RFC 3161 time stamps (Section 7.4.6), and appears at the places of publication of the protocol key list. It carries no customer data, no `appliance_id`, no commitment and no `chain_id` in clear.

| Key | confirmed by | signs | never signs |
|---|---|---|---|
| vendor root | the auditor or a vendor build of the verifier that carries it built in and names it (Section 7.1) | the three key lists: list of countersigning keys (Section 10.7.1), role list (Section 10.7.2) and protocol key list (Section 7.4.7) | data of running operation |
| countersigning key (role `countersigning`) | pin or list of countersigning keys (Section 7.1) | receipts; until the end of dual operation also the wrapper of license statements, refusal statements and activation receipts and pages of the anchor history of kind v1 (Section 10.7.5) | pages of kind v2, update manifest, day entries |
| statements key (role `statements`) | role list or pin as a statements key (Section 10.7.4) | license statements, refusal statements, activation receipts and pages of the anchor history (heartbeat specification §9) | receipts, update manifest, day entries |
| update manifest key (role `update_manifest`) | role list; the verifier does not use it | the update manifest (heartbeat specification §9.4) | anything else |
| protocol key (role `protocol`, active and standby) | protocol key list or pin as a protocol key (Section 7.4.10, step L1) | day entries the vendor built itself | anything else |
| key of a time-stamping authority | roots of the auditor for the respective purpose (Section 7.5.7) | time stamps | |

Every key of the vendor has exactly one role (Section 10.7.3). The same public key in two roles makes a list ineffective or causes a pin to be dropped (Section 10.7.4); if a protocol key also stands in another role, the protocol key list is ineffective (Section 7.4.10, step L1). The vendor chooses the time-stamping authorities of the log; the customer chooses the authorities of a chain's time witnesses (Section 7.3); a root the auditor passes for one side never confirms the other (Section 7.5.7).

#### 7.4.2 Leaves

Leaves are only hashed, never published. There are two kinds:

- **Countersignature:** `UTF-8(JCS({"chain_id": …, "merkle_root": …, "server_ts": …, "tree_size": …}))`, exactly the bytes the signature of the receipt covers (Section 7.1). `server_ts` is byte-identical with that of the receipt. From edition 1.10 the server writes it exactly in the form `YYYY-MM-DDThh:mm:ss.sssZ` (heartbeat specification §9.1); so receipt and leaf are equal character for character, and for the earliest countersignature of a root also the row of the anchor history (heartbeat specification §9.7).
- **Gap witness** (heartbeat specification §9.2): `UTF-8(JCS({"chain_id": …, "kind": "ledger.vendor_log_gap_witness.v1", "merkle_root": …, "server_ts": …, "tree_size": …}))`. `server_ts` is the time at which the server recorded the gap witness, from edition 1.10 in the same form (heartbeat specification §9.2), and it stays so when the same root is presented again. The member `kind` distinguishes the leaf from every countersignature with the same values. The leaf is not signed by itself (the day entry commits to it); it carries no `appliance_id`, no commitment and never the refusal statement.

**Leaf from the recording (from edition 1.10).** Every leaf is a function of the chain and of a recording of the vendor in the form of a row of the anchor history (heartbeat specification §9.7): from `chain_id` C and a row (`tree_size`, `merkle_root`, `recorded_as`, `server_ts`) arises, for `recorded_as` = `countersigned`, the leaf of a countersignature, for `gap_witness` the leaf of a gap witness, each with exactly these values; a row `reported` yields no leaf. `server_ts` enters as the string that the recording, row, extract or receipt carries; vendor and verifier read it only for `day(server_ts)` and for comparisons and never rewrite it. For the same root of a chain (`chain_id`, `tree_size`, `merkle_root`) there is at most one gap witness and therefore at most one leaf of a gap witness (heartbeat specification §9.2). A refusal statement (heartbeat specification §9.5) is never the input of a leaf. Every leaf comprises at least 181 bytes and therefore never equals the input of a leaf of a chain's Merkle tree, which comprises 32 bytes (Section 5).

Reference values (chain `3cef4d7e-4d65-41d6-912d-90d51fda8982` with `appliance_id` `de431f78-75fd-49ae-b4bf-1cb543b635d1`, `tree_size` 42, `merkle_root` = SHA-256 of the ASCII bytes `LEDGER-BEISPIEL-WURZEL-42`): the gap witness with `server_ts` `2026-03-01T23:58:00.000Z` has the leaf hash `6ae954c9cd400501c3cb2600954f229bd90da369e5f51898f204a46beafb70ce`, the countersignature of the same root with `2026-03-01T23:59:30.000Z` the leaf hash `b1a9c17ad92c0112bd915a40e050a26a4ab1da47e34528dba51d81811ca7a6c7`, and both yield the chain-day root `cde717fc82b66d14826268735294060bbf384f0631072c73f46c52056964efd1` at the position `927d08078b4fa065e881fb6f761a660bd2b7afec5be467348492ec1c0ad055a4`. Countersigned only on the following day with `2026-03-02T00:03:00.000Z`, the countersignature has the leaf hash `733e8945c2dec011786d37ccb6d89a75a92cb2b18ede80b114d339f9c50376c7` and stands at the position `8b0fdc3d4d0ccec032096b89412a3206cf3a51da335c840859d9c7097925ecd8`. The same gap witness with the reformatted `server_ts` `2026-03-01T23:58:00Z` yields a different leaf, which does not stand in the record.

**Leaves of chain C on day d** are every countersignature for C that left the server with `day(server_ts) = d`, and every gap witness for C with `day(server_ts) = d`. They form a set: identical bytes count once. Delivering a stored original again is the same leaf; a freshly issued repetition of a countersignature is a further leaf. A root that was recorded as a gap witness and later countersigned yields two leaves, possibly on different days. Not logged are reported roots, refusals, fork findings, statements and activation receipts.

**Why the whole object with `server_ts`.** The day of a leaf is the day of its `server_ts`, and the leaf binds exactly the receipt the customer holds. A receipt signed later with a stolen or revoked key carries its own `server_ts` and stands in no witnessed day. A leaf of `chain_id`, `tree_size` and `merkle_root` alone would let one logged root cover every backdated receipt over this root.

#### 7.4.3 Chain Day: Root, Position and Leaf

The log of a day is a tree in two tiers: per chain a chain-day tree over its leaves of the day, above it the day tree over the chain-day leaves and the fillers (Section 7.4.4), whose positions are strictly ordered and public in the day leaves (Section 7.4.9).

- **Chain-day root:** `chain_root(C, d)` is MTH (Section 5) over the leaves of chain C on day d, ordered ascending by their leaf hash as an unsigned 32-byte value; n ≥ 1.
- **Position:** `position(C, d) = SHA-256(UTF-8(JCS({"appliance_id": A, "chain_id": C, "day": d, "kind": "ledger.vendor_log_position.v1"})))`. For A the server inserts the appliance to which it bound the chain, the verifier the package's `GENESIS.appliance_id`.
- **Chain-day leaf:** `UTF-8(JCS({"chain_root": Hex(chain_root(C, d)), "kind": "ledger.vendor_log_day_leaf.v1", "position": Hex(position(C, d))}))`. It carries no `chain_id`, no size and no time; the day is contained in the position. The kind `ledger.vendor_log_day_leaf.v1` is that of every leaf of the day tree, a filler included (Section 7.4.4); it says nothing about the leaf's origin.

**Why positions, and why with the `appliance_id`.** Positions differ per chain and day, and the day tree is strictly ordered by them. Two chain-day leaves for the same chain and the same day therefore need a duplicate position or a broken order; the published day leaves show both, if someone checks them (Section 7.4.9). The absence proof (Section 5) and the property that a chain has at most one chain-day leaf per day rest on this order. The verifier does not check the order, because it does not read the day leaves. Both are therefore proven only together with a check of the published day leaves of the day; without it a vendor can keep two chain-day leaves of one chain under the same day root and give different auditors different records (Section 11.2). Because the `appliance_id` enters the position, only the vendor and holders of a verification package of the chain can read the chain's active days from the day leaves; the `chain_id` alone does not suffice for that. The exception is the vendor's access chain, whose `chain_id` and `appliance_id` are public (heartbeat specification §12, access chain, item 9); anyone can read its active days. If someone takes over a `chain_id` under another appliance, his proofs do not hold under the position of the honest chain (`VENDOR_LOG_DEFECTIVE`); they never yield `LOGGED_ROOT_MISMATCH`.

#### 7.4.4 Day Tree, Tree Size and Fillers

- **Leaves of the day tree:** `D(d)` are the chain-day leaves of all chains with leaves on day d and the fillers of day d, ordered strictly ascending by `position` (comparison as in Section 5); no position occurs twice. Every leaf has the form and the kind `ledger.vendor_log_day_leaf.v1` of a chain-day leaf (Section 7.4.3).
- **Root and size:** `root(d)` is MTH over `D(d)` in this order (Section 5), `tree_size(d)` the number of leaves of `D(d)`. `tree_size = 0` goes with `root = SHA-256("")`; under the size rule such a day does not occur, but the verifier accepts it (Section 7.4.10, step L2 (g)).
- **Size rule:** if n(d) is the number of chains with leaves on day d, then `tree_size(d)` is the smallest power of two that is at least 1024 and at least n(d). The remaining m(d) = `tree_size(d)` − n(d) leaves are fillers; a day without leaves has 1024 fillers. The rule applies to every day entry of kind `ledger.vendor_log_day.v1` and is thus fixed before the first day of every log. The only exception is a log whose protocol key list is signed by a vendor root from `published_test_keys` (Section 7.5.7), for instance in test vectors; such a log hides nothing. The verifier does not check the rule; it checks the size only against the signed day entry (Section 7.4.10). That `tree_size` is a power of two and at least 1024 anyone can check (Section 7.4.9, check (d)); whether it is the smallest permitted one is shown only by the opening of the day together with proof of origin for every other leaf (Section 7.4.13).
- **Filler:** a filler is a leaf of the day tree in the form and kind of a chain-day leaf that belongs to no chain. Fillers MUST be publicly indistinguishable from chain-day leaves: without a secret of the vendor their `position` and `chain_root` cannot be told apart from random 32-byte values, and a day that is closed anew (heartbeat specification §9.9) carries the same fillers. How the vendor forms its fillers is **not part of the check**: no verifier reads, computes or checks a filler, and no check of this specification depends on how they are formed. This edition specifies a construction with which the vendor can prove the origin of its fillers to an examining body or a supervisory authority (the derived construction below, with the opening under Section 7.4.13); the vendor MAY use it. If it does not, the signing service forms the fillers from a cryptographically secure random number generator (heartbeat specification §9.9). If it does, the protocol key list names its filler commitment (Section 7.4.7), otherwise it carries `null` there. The vendor can also begin the derived construction later, with the first version of the list that names the filler commitment; format and verifier do not change for that. For days before that version the origin of its fillers cannot be proven (no evidence produced by LEDGER).
- **Derived construction:** with L = `log_id`, d in the form `YYYY-MM-DD` and HMAC-SHA-256 per RFC 2104 with SHA-256:

| Value | Construction |
|---|---|
| filler secret G | 32 bytes from a cryptographically secure random generator, a separate one for every log, generated before the first version of the protocol key list that names its filler commitment, and unchanged afterwards (heartbeat specification §9.9); never published |
| filler commitment | `SHA-256(UTF-8(JCS({"filler_secret": Hex(G), "kind": "ledger.vendor_log_filler_commitment.v1", "log_id": L})))`; stands as `fuellerbindung` in every version of the protocol key list from the first one that names it (Section 7.4.7) and is public |
| day secret g(d) | `HMAC-SHA-256(G, UTF-8(JCS({"day": d, "kind": "ledger.vendor_log_filler_secret.v1", "log_id": L})))` |
| salt s(d, i) for i = 0, 1, 2, … | `HMAC-SHA-256(g(d), UTF-8(JCS({"index": i, "kind": "ledger.vendor_log_filler_salt.v1"})))` |
| position of candidate i | `SHA-256(UTF-8(JCS({"day": d, "kind": "ledger.vendor_log_filler_position.v1", "log_id": L, "salt": Hex(s(d, i))})))` |
| root of candidate i | `SHA-256(UTF-8(JCS({"day": d, "kind": "ledger.vendor_log_filler_root.v1", "log_id": L, "salt": Hex(s(d, i))})))` |
| leaf of candidate i | `UTF-8(JCS({"chain_root": Hex(root), "kind": "ledger.vendor_log_day_leaf.v1", "position": Hex(position)}))` |

- **Selection:** the fillers of day d are exactly the candidates i = 0 to m(d) − 1; no candidate is skipped. If the position of a candidate hits the position of a chain-day leaf or of another candidate (which happens only with a collision of SHA-256), the closing does not close the day and raises an alarm (heartbeat specification §9.9); it forms no other fillers instead. In the tree the fillers stand between the chain-day leaves according to their position; the index i has nothing to do with the leaf index. Because the index enters no preimage of position and root, the opening of a single filler shows neither its index nor the number of fillers.
- **Binding to the day:** the day secret depends only on `log_id` and day, not on `server_ts`. A day that is closed anew after a destroyed entry (heartbeat specification §9.9) receives a new `server_ts`, but the same candidates; two trees of the same day share their fillers and, side by side, show only the leaves in which they differ. If the day secret depended on `server_ts`, two trees of one day would have only their chain-day leaves in common and together would show which leaves are fillers. If the same `statement_jcs` is signed anew under another protocol key (Section 7.4.5), all fillers stay the same anyway.
- **Not public:** filler secret, day secrets, salts, indices, m(d), n(d) and the information which leaves are fillers stand in no day entry, in no day leaves, in no extract, in no record and in no output of the vendor (status, statistics, operation logs). The filler commitment is public; G cannot be computed from it. The secured day leaves suffice to rebuild every record (heartbeat specification §9.9); the filler secret is needed only for an opening (Section 7.4.13).
- **What the size shows:** only whether more than 1024 chains had leaves on that day, and then the power of two that bounds their number from above; if the number crosses a power of two, the size shows growth on that day. The day leaves (Section 7.4.9) comprise 64 bytes per leaf, so at least 64 KiB per day.
- **Test vectors** use the published filler secret G = SHA-256 of the ASCII bytes `LEDGER-TESTVEKTOR-FUELLERGEHEIMNIS` (`bcfe9766f065da823b5e2cff936cd8aff9e6c5d59540557ae4fe2d02afa04acf`) and smaller trees than the size rule requires; their protocol key lists are signed by a root from `published_test_keys`.

Reference values (log `ledger-testprotokoll-1`, day `2026-01-01`, test filler secret): the filler commitment is `82ba087e5b1b7bee5dbfb6b34620efb2e23e1426ad25fe60a672035fb3a99efe`; g(d) = `cc0a0f17adfa12bc5887b25f7eb2f3745b798db1f94a5cbf0eebb9447006f962`; s(d, 0) = `e49f397932b6e32e2700638a9594ddbd3aeb9784a5129363c925e1bdb3eec14e`; position of candidate 0 `6a67ff9572b4d663920a2e740361b09ee2cb6acae8ecf613e6a30b16aad350f9`, its root `27f678c7c3c9f763cb99aa6bfb4715d4667faa4b0d6c9f8a2e36e20250b4233c`, the hash of its leaf `294970b630c3526afb9c691702e0e939842253339bb6831386b70502f012f8c5`. A day tree of one chain (chain-day leaf with the position `b1ed9cae78dcfafe822b101de7ce470c80f85b3838f7d2701da3de2b588e2c04` and the chain-day root `b48375ab1d0a8b4e54d42d8a7c6239eea5ebac215b1b07f45cf8f912030bb2ea`) and the candidates 0 to 3 has size 5 and the root `0adcf8f084c1c9c0e8998f01a0a9a9b57e96b5e9135e2833cbb10c6a9e121871` (example in Section 7.4.5, with `server_ts` `2026-01-02T00:05:00.000Z`); the chain stands at leaf index 3. A new closing of the same day with `server_ts` `2026-01-02T00:35:00.000Z` has the same fillers and the same root; the following day has g(d) = `eea894d57696feccaa8c45aee5e4d531924e1cfaa8b82356a36823b0582de9fc`. Under the size rule the same day with the same chain has 1023 fillers and the root `053bc9260b2e032e8c9691fddb7ab200cf03436717d712e12da1a0b3589d7803`; the chain stands there at leaf index 703, and its path comprises 10 hashes. The chain-day root `b48375ab1d0a8b4e54d42d8a7c6239eea5ebac215b1b07f45cf8f912030bb2ea` of this example is an arbitrary value for the computation of the tree; it comes from no rows, and no `present` record can be built for it. A second reference day, whose chain-day leaf is the one of Section 7.4.2 (chain-day root `cde717fc82b66d14826268735294060bbf384f0631072c73f46c52056964efd1` at the position `927d08078b4fa065e881fb6f761a660bd2b7afec5be467348492ec1c0ad055a4`), so that a `present` record exists for it, is shown by the reference case in `spec/testvectors/protokoll/`.

**Why the kind stands in the preimage and not in the leaf.** If a filler carried its kind in the leaf, the day leaves would show the number of fillers and thus the number of chains. Therefore every leaf of the day tree has the same kind `ledger.vendor_log_day_leaf.v1`, which says nothing about its origin, and the kind of a filler stands in the preimages of its position and its root: fillers are a leaf kind of their own, identifiable by their opening (Section 7.4.13), not by public data. Both preimages contain the salt; without the salt neither value can be computed from the other or from public data. A filler therefore cannot be told apart from a chain whose `appliance_id` and `chain_id` one does not know, not even as a neighbour in an absence proof.

**Why a filler cannot belong to any chain.** The position of a chain is the hash of an object of kind `ledger.vendor_log_position.v1`, that of a filler the hash of an object of kind `ledger.vendor_log_filler_position.v1`. The root of a chain is the hash of an input that begins with the byte 0x00 or 0x01 (Section 5), the root of a filler the hash of a JSON object that begins with `{`. Equal values would require a collision of SHA-256. Nobody can therefore pass off a filler as a day of his chain, and the vendor cannot open a chain-day leaf as a filler (Section 7.4.13).

**Why derived and not random.** With derived fillers every leaf of the day tree has an origin the vendor can prove to an examining body: a chain-day leaf by the leaves of its chain and their binding to the appliance, a filler by its opening. A filler from a random generator would have no provable origin and could not be told apart from a leaf of unknown provenance. With the filler commitment the vendor commits to the filler secret before the first day; whoever receives G recomputes the derivation of every day (Section 7.4.13). The day secret is a separate HMAC value for every day, from which no other can be computed; the salt is a separate value for every filler, so that the vendor can open single fillers without showing their index or the number of fillers of the day.

#### 7.4.5 Day Entry `ledger.vendor_log_day.v1`

A day entry is an object with exactly the members `statement_jcs`, `server_key_id` and `server_signature`, the wrapper of heartbeat specification §9.4 without the reading copy. `statement_jcs` is the JCS form of an object with exactly these members:

| Member | Type | Rule |
|---|---|---|
| `day` | date (log range) | the UTC day the entry closes |
| `first_day` | date (log range) | start of the log; equal to `erster_tag` of the protocol key list |
| `kind` | const `"ledger.vendor_log_day.v1"` | kind of entry |
| `log_id` | key-id | equal to `log_id` of the protocol key list; a log for trials starts with `staging-` |
| `prev_hash` | hex64 | `Hex(SHA-256(UTF-8(statement_jcs)))` of the entry for the previous day; 64 zero characters exactly when `day = first_day` |
| `root` | hex64 | `Hex(root(day))` (Section 7.4.4); for `tree_size = 0` the SHA-256 value of the empty byte string (Section 5) |
| `server_ts` | rfc3339, exactly in the form `YYYY-MM-DDThh:mm:ss.sssZ` | time the vendor's signing service fixes before it forms the entry (heartbeat specification §9.9); MUST be at least `end(day)` (Section 2). The fillers do not depend on it (Section 7.4.4) |
| `tree_size` | int, 0 … 2^53−1 | number of leaves of the day tree |

The canonical member order is `day, first_day, kind, log_id, prev_hash, root, server_ts, tree_size`. `statement_jcs` consists of printable ASCII (Section 2), is I-JSON without duplicate member names, exactly the JCS form of its own content and at most 2,048 characters long; an entry comprises about 319 characters. `server_key_id` has the type key-id. `server_signature` (hex128) is the Ed25519 signature (RFC 8032, without prehash and without context) of a protocol key over `UTF-8(statement_jcs)`; it is checked like the signature of a receipt (Section 7.1).

Example of a `statement_jcs` (one line; day tree of a test log of one chain and four fillers per Section 7.4.4; day hash `ef330d2049e93b1da0e934a7a0e01e6b1dc26d392ffdac080ff0ec00889e2c1c`):

```
{"day":"2026-01-01","first_day":"2025-12-31","kind":"ledger.vendor_log_day.v1","log_id":"ledger-testprotokoll-1","prev_hash":"33fd1b2966e2f17af53d478066c97f1da0a181ed1107aaa34341eb4bc3067055","root":"0adcf8f084c1c9c0e8998f01a0a9a9b57e96b5e9135e2833cbb10c6a9e121871","server_ts":"2026-01-02T00:05:00.000Z","tree_size":5}
```

- **Day hash:** `day_hash = SHA-256(UTF-8(statement_jcs))`. Auditors compare it at the head of the log; it is the input of the next `prev_hash` and, for sha256, the imprint of the time stamps.
- **The identity is the content.** The same `statement_jcs` under two protocol keys is one entry; signing it anew after a key change is no contradiction; the new signature stands as an additional signature in the day object (Section 7.4.8). Two different `statement_jcs` for the same day of one log are a contradiction (`VENDOR_LOG_CONTRADICTION`).
- **What `prev_hash` covers:** the content, not signature or time stamp. A time stamp arises only after the entry, and a later or additional time stamp does not change the chaining.
- **Without gaps:** exactly one entry per day from `first_day`, also for a day without leaves. `first_day` stands in the list the vendor root signs; the vendor cannot claim a later start afterwards.
- **No running tree:** this edition keeps no tree over the day entries; the days are chained by `prev_hash` alone.
- The entry carries no customer data, no `appliance_id`, no commitment, no `chain_id` and no number of receipts.

#### 7.4.6 Time Stamps of the Day Entries

- A day object carries 0 to 4 time stamps (Section 7.4.8), each an RFC 3161 TimeStampToken in base64 (at most 21,848 characters, DER at most 16,384 bytes). Its `messageImprint` is `H(UTF-8(statement_jcs))` with the algorithm `sha256`, `sha384` or `sha512` named in the token. The vendor MUST have every day stamped by at least two time-stamping authorities of different operators, none of which is operated by the vendor itself or by a party affiliated with it; every request SHOULD carry `certReq = true` and a nonce (heartbeat specification §9.9). The verifier does not check this: it does not see who operates an authority.
- Every time stamp is, under Section 7.5.7 (column day time stamp), **defective**, **unconfirmed** or **confirmed**; a violation of B64 or of the limit of 16 384 bytes for the DER makes it defective. A string of more than 21 848 characters already violates the grammar of the extract and is an unusable invocation (Section 7.4.8). It is confirmed only against a root of purpose `log`. A verifier that cannot perform step 5 of the profile confirms no day time stamp.
- For a confirmed time stamp of an entry for day d, with `genTime` truncated to whole milliseconds (Section 2): **witnessing** if `end(d) + 60,000 ≤ genTime < end(d) + W`; **premature** if `genTime < end(d) + 60,000`; **late** if `genTime ≥ end(d) + W`.
- **Time window:** W = 172,800,000 ms (48 hours).
- **Due:** a day d is due when `now ≥ end(d) + 21,600,000` holds, that is from 06:00Z of the following day; `now` is the check time (Section 10.8). By then the vendor publishes the entry at both places (heartbeat specification §9.9).
- **Authority whose token declares itself qualified (from edition 1.10).** One of the authorities MAY be such an authority (rule QS, Section 7.5.6; heartbeat specification §9.9). Its time stamp is judged like any other and can witness the day. Whether it chains to a root that the auditor passes for the log and names as qualified is read only by condition (7) of the evidence level (Section 10.9.1), the second path to level 3.

**Why the time stamp covers the content and not the signature.** The time stamp proves that the content existed at `genTime`; the signature binds the content to the key. Since every entry carries `prev_hash`, a timely time stamp of a later day indirectly proves earlier contents as well. The verifier does not use this indirect bound: a day counts only by a witnessing time stamp of its own, also for condition (7) (Section 10.9.4).

#### 7.4.7 Protocol Key List `ledger-protokollschluessel/1`

The protocol keys are confirmed by a list of their own that the vendor root signs; neither the list of countersigning keys (Section 10.7.1) nor the role list (Section 10.7.2) names them. The format of the list is its role: every key in it has the role `protocol` (Section 10.7.3) and stands in no other list. The list is a JSON object under the rules for auditor files (Section 2) with exactly these members:

| Member | Type | Rule |
|---|---|---|
| `format` | const `"ledger-protokollschluessel/1"` | format identifier; any other makes the list ineffective |
| `version` | int, 1 … 2^53−1 | assigned by the vendor, strictly increasing; a new version carries every key ever listed forward, with its end of validity |
| `ausgestellt` | rfc3339 | time of issue, read with the grammar of Section 10.7 |
| `log_id` | key-id | identifier of the log |
| `erster_tag` | date (log range) | start of the log; equal in every version |
| `fuellerbindung` | hex64 or `null` | filler commitment `Hex(SHA-256(UTF-8(JCS({"filler_secret": Hex(G), "kind": "ledger.vendor_log_filler_commitment.v1", "log_id": log_id}))))` to the filler secret G of this log (Section 7.4.4) if the vendor derives its fillers, otherwise `null`; once set, equal in every later version |
| `orte` | array, 2 … 4 strings `^https://[!-~]{1,248}$` | places of publication, each the base address of the file form (heartbeat specification §9.9); at least one lies outside the vendor's operation, except for a log under trial (below, "Places") |
| `schluessel` | array, 1 … 64 objects | per key exactly as in Section 10.7: `key_id`, `pubkey` (hex64), `gueltig_ab`, optionally `gueltig_bis` and `widerrufen_ab`; all values strings; a `key_id` and a `pubkey` may each occur only once |
| `signatur` | object | exactly `wurzel_id` (key-id) and `sig` (hex128) |

- **Places:** the places of publication stand in the signed list, so that an auditor cannot be referred to a mirror operated by the vendor alone. Every place is the base address of the same file form (heartbeat specification §9.9, "Publication"): an auditor forms an address by appending `/` and the path of a file to the place, for instance `<place>/days/2026/2026-01-01.json`; a place therefore MUST NOT end with `/` nor contain `?` or `#`, which the signing procedure of the list checks (heartbeat specification §9.11 item 10), the verifier does not. If a place nevertheless ends with `/`, the auditor drops that character before appending. The routes of the metadata server under `/v1/` are not a place. This specification names no place; what a reader can expect from a place outside the vendor's operation and how he checks it is given in heartbeat specification §9.9. For a log under trial (`log_id` begins with `staging-`) both places MAY lie within the vendor's operation; its list is never signed by the vendor root of the operation (heartbeat specification §9.9).
- For `key_id`, `pubkey` and the time values the rules of Section 10.7.1 apply (grammar, validity at an instant, comparison as instants).
- **Unique across all lists:** `key_id` and `pubkey` of a protocol key occur in no version of the list of countersigning keys and of the role list (heartbeat specification §9.9, §9.11). The role check compares the effective list with the countersigning keys and with the effective role list (Section 10.7.4, step R3; Section 7.4.10, step L1).
- **Signature:** what is signed is the JCS form of the list object **without** the member `signatur`, with the canonical member order `ausgestellt, erster_tag, format, fuellerbindung, log_id, orte, schluessel, version`, with Ed25519 by the vendor root named in `signatur.wurzel_id`. This root comes from the auditor or is built in and named (Section 7.1), never from a package or an extract.
- The number rule of Section 2 applies; there are no other members at any level.
- **Effective** is the list only if every rule holds and the signature holds against a root with this `wurzel_id`; which list applies among several is decided by step L1 (Section 7.4.10). An ineffective list establishes no key and is not a finding itself; the report names the reason.
- **Filler commitment:** with `fuellerbindung` the vendor commits to the filler secret before the first day whose fillers it derives (Section 7.4.4); if it derives no fillers, it is `null`. The verifier reads it only for the rule that, once set, it is equal in every later version (Section 7.4.10, step L1); whoever receives the filler secret can check it (Section 7.4.13).
- **Standby key:** the list SHOULD name a second protocol key whose private part is kept offline. After a compromise the vendor switches to it and publishes a new version with `widerrufen_ab` for the old key, without a previously unlisted key appearing.
- **Publication:** in every extract (`protocol_keys`), at `GET /v1/log/keys` and as `keys.json` at both places of publication (heartbeat specification §9.9), never in a verification package and never as `keys/vendor/schluesselliste.json`. A reader of the list of countersigning keys never accepts it: `format` and the members `log_id`, `erster_tag`, `fuellerbindung` and `orte` make it ineffective there. It therefore never confirms a countersigning key.

Example of the signed bytes (one line; SHA-256 `21817705e707ffd17c2b4216ec3c654917f3d1b27e413e1fb3b740c9378c60da`):

```
{"ausgestellt":"2025-12-30T10:00:00.000Z","erster_tag":"2025-12-31","format":"ledger-protokollschluessel/1","fuellerbindung":"82ba087e5b1b7bee5dbfb6b34620efb2e23e1426ad25fe60a672035fb3a99efe","log_id":"ledger-testprotokoll-1","orte":["https://download.example/ledger-testprotokoll-1","https://mirror.example/ledger-testprotokoll-1"],"schluessel":[{"gueltig_ab":"2025-12-30T00:00:00.000Z","key_id":"vendor-log-test-001","pubkey":"1111111111111111111111111111111111111111111111111111111111111111"}],"version":1}
```

#### 7.4.8 Log Extract `ledger-protokollauszug/1`

The auditor passes the log as one or more extracts (Section 10.8). An extract is an auditor file (Section 2) with this structure; `x?` means `x` or `null`:

```
{"format":        "ledger-protokollauszug/1",
 "log_id":        key-id,
 "chain_id":      uuid?,
 "protocol_keys": object?,       protocol key list, judged under 7.4.7
 "days":          [0 … 4000 day objects:
                   {"entry":      {"statement_jcs": string (maxlen 2048),
                                   "server_key_id": key-id,
                                   "server_signature": hex128},
                    "timestamps": [0 … 4 × string (maxlen 21848)],
                    "additional_signatures": [0 … 3 × {"alg": string (^[a-z0-9][a-z0-9-]{0,31}$),
                                                       "key_id": key-id,
                                                       "signature": string (1 … 1024 × [!-~])}]}],
 "chain_days":    [0 … 4000 chain-day records:
                   {"day":     date (log range),
                    "present": {"roots": [1 … 4096 × {"tree_size": int (1 … 2^53−1),
                                                     "merkle_root": hex64,
                                                     "recorded_as": "countersigned" | "gap_witness",
                                                     "server_ts": rfc3339}],
                                "leaf_index": int (0 … 2^53−1),
                                "path": [0 … 64 × hex64]}?,
                    "absent":  {"neighbours": [0 … 2 × {"leaf_index": int (0 … 2^53−1),
                                                        "position": hex64,
                                                        "chain_root": hex64,
                                                        "path": [0 … 64 × hex64]}]}?}]}
```

**Grammar.** A violation is an unusable invocation (exit 3, Section 10.8):

- At every level exactly these members stand, except within the content of `protocol_keys`; `format` is the constant.
- `chain_id` is `null` only with an empty `chain_days`.
- An element of `additional_signatures` with `alg` = `ed25519` carries a value of type hex128 in `signature`. Two equal elements in one day object violate the grammar.
- In every chain-day record exactly one of `present` and `absent` is not `null`.
- The `roots` of a record are pairwise distinct by their leaf bytes (Section 7.4.2). A file carries at most one record per `day`. `neighbours` are ordered ascending by `leaf_index`, non-decreasing: equal values do not violate the grammar.
- `server_ts` in `roots` is a value of type rfc3339, taken over byte-identically from the receipt or the recording. From edition 1.10 the server writes it in the form `YYYY-MM-DDThh:mm:ss.sssZ` (heartbeat specification §9.1, §9.2); another form does not violate this grammar.
- All extracts of an invocation name the same `log_id`.
- Limits: per file at most 33,554,432 bytes; per invocation at most 128 files and 268,435,456 bytes.

**What the extract is.** An unsigned container of parts that prove themselves: day entries by protocol keys and time stamps, chain-day records by inclusion under a witnessed day tree. It is no statement of the vendor. Every row `countersigned` or `gap_witness` of the anchor history whose `server_ts` falls on a day from `first_day` stands byte-identical among the `roots` of the record for that day, since both come from the recordings of the vendor (heartbeat specification §9.1, §9.2). A freshly issued repetition of a countersignature stands there in addition with its own `server_ts`; for that root the anchor history names only the earliest countersignature. Rows of earlier days have no record in the log. Section 8.8 reconciles the two and compares in the reverse direction without `server_ts` (step H7). The mirror extract `<YYYY>.json` at the places of publication is an extract with `chain_id = null`. An anchor history file (Section 8.8.2) MAY contain extracts unchanged; the verifier treats them like extracts passed by the auditor.

**Additional signatures (from edition 1.10).** A day object MAY carry further signatures over `UTF-8(statement_jcs)` under `additional_signatures`. With `alg` = `ed25519` it is the signature of a further protocol key, for instance after a key change (Section 7.4.5); step L2 treats it like the pair from `entry` (Section 7.4.10). With another `alg` it is a seal under a method this edition does not define, for instance for a later service that demands a method other than Ed25519. A verifier of this edition does not check such a seal: it counts for no step, never yields a finding, and the report gives the number of such seals (`vendor_log.days.signatures_not_checked`, Section 10.10). So a later edition can add methods whose seal fits into 1024 printable characters (for instance ECDSA, or RSA up to 4096 bits in hex) without an extract becoming unusable for a verifier of this edition. A longer seal, for instance under ML-DSA or with a certificate, violates the grammar of this edition and needs a new format of the extract.

#### 7.4.9 Day Leaves `ledger-tagesblaetter/1`

`{"format": "ledger-tagesblaetter/1", "log_id": key-id, "day": date, "leaves": [[position, chain_root], …]}`: per leaf of the day tree a pair of two hex64 values, in the order of the tree. The vendor publishes the day leaves of every day at both places (heartbeat specification §9.9). They serve observation of the log; the verifier does not read them. Anyone can check against them:

- (a) The positions increase strictly.
- (b) The number of pairs is `tree_size` of the day entry.
- (c) MTH (Section 5) over the leaves `UTF-8(JCS({"chain_root": …, "kind": "ledger.vendor_log_day_leaf.v1", "position": …}))` in this order is `root` of the witnessed day entry.
- (d) `tree_size` of the day entry is a power of two and at least 1024 (size rule, Section 7.4.4), for every log whose protocol key list is not signed with a root from `published_test_keys`.

A violation of (a) to (d) under a witnessed entry is a rule violation anyone can attribute to the vendor. Beyond the tree size the day leaves reveal nothing: positions depend on the `appliance_id` (Section 7.4.3), chain-day roots are hash values, and without their opening fillers cannot be told apart from chains (Sections 7.4.4, 7.4.13).

#### 7.4.10 Checks by the Verifier

Notation: N = number of entries of the package; C = `manifest.chain_id`; A = `GENESIS.appliance_id`; `now` = check time (Section 10.8); `root(t)` = the root over the entries 1 … t recomputed from the leaves (Section 5); `LH(x) = SHA-256(0x00 || x)`. A **day object** is an element of `days` of an extract. Both reference verifiers perform the steps alike.

**L0 Invocation** (before the package is opened). The verifier reads every extract, including those contained in anchor history files, every key list of the auditor, every pin of a protocol or statements key and every root for time stamps of the log (Section 10.8). An unusable invocation (exit 3 without a report) is: a violation of the grammar or of a limit (Sections 7.4.8, 10.8); different `log_id` values in the extracts; a pin not of the form `key_id=hex64`; two pins of protocol keys with the same `key_id` and different public keys; a pin of one role equal in `key_id` or public key to a pin of another role (`--vendor-key`, `--vendor-log-key`, `--vendor-statement-key`; one key in two roles); the other cases of Section 10.7.4; a malformed PEM block. Without an extract the status is `not_supplied`, and steps L2 to L9 are dropped. Step L1 runs as soon as a protocol key list (in an extract or as a key list of the auditor) or a pin of a protocol key is supplied, with or without an extract; without an extract it only determines the protocol keys for Sections 7.1, 8.8.3 and 10.7.4 and reports no finding.

**Place in the verification procedure.** Step L1 runs with the other keys of the vendor before the check of the receipts (Section 10.5, step 4), steps L2 to L9 after the check of the receipts (Section 7.1) and before the anchor history (Section 8.8). They read only the auditor inputs, per receipt whether its signature holds under Section 7.1, the set K_cs, the prefix roots, A and `now`. They add only the five finding classes of Section 7.4.11 and the report object `vendor_log` (Section 10.10) and change no other result: `NO_ANCHOR`, the last countersigned checkpoint (Section 8.6), residual window, completeness and expected roots remain as they would be without the log.

**K_cs** are the countersigning keys established by anchors of the auditor (Section 10.7.4): K_cs^L, that is the keys of the package's list of countersigning keys if it is effective against a vendor root of the auditor or the built-in root, and likewise the keys of effective lists of this format that the auditor passes; in addition the pinned countersigning keys (Section 7.1) that are not dropped under Section 10.7.4, step R3 (d). `manifest.vendor_pubkeys` and `keys/vendor/*.hex` never enter K_cs.

**L1 Protocol keys.**

1. Pinned protocol keys take precedence for their `key_id`; they have no end of validity.
2. Candidates are the distinct protocol key lists (distinct by their JCS bytes) from the members `protocol_keys` of the extracts and from the auditor's key lists in the format `ledger-protokollschluessel/1`. A candidate counts if it satisfies Section 7.4.7 and its signature holds against a vendor root of the auditor or the built-in root with this `wurzel_id`; the report names the source of the root. Effective is the counting candidate with the greatest `version`. No list is effective if two counting candidates have the same `version` and different bytes, if two counting candidates name different `log_id` or `erster_tag`, if two counting candidates name different `fuellerbindung` other than `null`, if a counting candidate names `fuellerbindung` `null` and one of a smaller `version` a value, if a counting candidate lacks a key (the same `key_id` with the same `pubkey`) of a counting candidate of a smaller `version` (Section 7.4.7: a new version carries every key forward), or if, with an extract, a counting candidate names a `log_id` other than that of the extracts; the reason is then "contradicting lists", in the last case "differing `log_id`".
3. **Role check** (Section 10.7.4, step R3): if the effective list shares a public key with a pin of a countersigning key, with K_cs^L or with the effective role list, no list is effective. A pin of a protocol key whose public key equals that of a key from K_cs^L or from the effective role list is dropped. The public key is compared, not the `key_id`: if only the `key_id` is equal, no key stands in two roles, because every key is looked up only in the list of its role; that the vendor assigns the `key_id` values of all roles separately is required by heartbeat specification §9.9. Otherwise whoever writes a package could add an older, genuinely signed list of countersigning keys with a coincidentally equal `key_id` and switch the log off. `manifest.vendor_pubkeys` and `keys/vendor/*.hex` never count for this; otherwise a forger could switch the log off by entering the protocol key there.
4. If no protocol key remains and an extract is supplied, the verifier reports `VENDOR_LOG_UNVERIFIED` once without a day, with the reason (no list supplied, no matching root, signature fails, format violated, contradicting lists, key in two roles, differing `log_id`). If no list is effective and every protocol key pin was dropped under item 3 (Section 10.7.4, step R3 (d)), the reason is "key in two roles", not "no list supplied". The status is then `no_protocol_key`, the classes of the receipts remain undetermined (Section 10.10), and steps L2 to L9 are dropped.
5. F is `erster_tag` of the effective list. If there are only pins, step L2 (f) determines the start F.

**L2 Day objects.** The day objects of all extracts are pooled: identical `statement_jcs` are one object. Its time stamps are united as a set of distinct strings, its signatures as a set of distinct pairs (`server_key_id`, `server_signature`), to which every element of `additional_signatures` with `alg` = `ed25519` belongs as the pair (`key_id`, `signature`); no pair displaces another, whatever the order in which the files are passed. Elements with another `alg` are counted as a set of distinct elements and not checked (Section 7.4.8). `dayOf(o)` is the member `day` if `statement_jcs` can be read as an I-JSON object (Section 2, duplicate member names refused) with a member `day` that satisfies the grammar of type `date` (an existing calendar day with a year from `0001` to `9999`, Section 2); otherwise the finding has no day. The log range is not part of `dayOf`; it is a content rule that (c) checks. A signed entry with `day` `1999-12-31` therefore gets its finding `VENDOR_LOG_CONTRADICTION` on that day and counts in `days.contradictory` (Section 10.10.2). First steps (a) to (e) apply to every object o; then (f) determines the start F; then (g) and (h) apply to every object that passed (a) to (e):

- (a) No pair of o names as its key (`server_key_id` from `entry` or `key_id` of an element of `additional_signatures` with `alg` = `ed25519`) an established protocol key: `VENDOR_LOG_UNVERIFIED(dayOf(o))` "key not established"; o is not established.
- (b) For every pair under an established protocol key the Ed25519 signature over `UTF-8(statement_jcs)` is checked. Every pair whose signature does not hold yields `VENDOR_LOG_DEFECTIVE(dayOf(o))` "signature", without removing o. If none holds, o is not established; otherwise the pairs whose signature holds are the **holding pairs** of o.
- (c) The content violates Section 7.4.5 (printable ASCII, I-JSON, own JCS form, exactly the members with their types, `kind`, `log_id` equal to that of the extracts, log range, form of `server_ts`): `VENDOR_LOG_CONTRADICTION(dayOf(o))` "signed entry violates the format". The signature holds, so the holder of the protocol key signed the content.
- (d) Every time stamp of o is judged under Section 7.5.7: defective, unconfirmed or confirmed, with its `genTime`.
- (e) A holding pair **counts** if its key carries neither `gueltig_bis` nor `widerrufen_ab`, or if a confirmed time stamp of o shows a `genTime` before the end of this key (end = the earlier of the two values, read under Section 10.7; compared to the nanosecond with the full `genTime`, not truncated to milliseconds, Section 2). If no holding pair counts: `VENDOR_LOG_UNVERIFIED(d)` "validity of the protocol key ended, time of the signature not proven"; o is not established. `gueltig_ab` is not checked against day entries: otherwise signing anew after a key change would be excluded, and no time stamp proves a lower bound of the signing time.
- (f) **Start F.** With an effective list F is its `erster_tag` (step L1). If there are only pins, the objects that passed (a) to (e) decide: if they all name the same `first_day`, F is that value. If none passed (a) to (e), F is unknown, without a finding; then no object reaches (g) either. If they name different `first_day` values, the verifier reports `VENDOR_LOG_CONTRADICTION` once without a day, "day entries under pinned keys name no common first_day"; F is unknown, no object is established, (g) and (h) and steps L3 to L7 and L9 are dropped, and in step L8 every receipt is `unchecked` with the sub-class `first_day_contradictory`. If F is unknown, `first_day` in the report is `null`.
- (g) Rules of the log: d ≥ F; `prev_hash` consists of 64 zero characters exactly when d = F; `tree_size = 0` implies `root = SHA-256("")`; `server_ts` (in whole milliseconds) ≥ `end(d)`; `first_day = F`. A violation: `VENDOR_LOG_CONTRADICTION(d)` "signed entry violates a rule of the log"; o is not established.
- (h) Otherwise o is **established**. If one of its time stamps is defective: `VENDOR_LOG_DEFECTIVE(d)` "time stamp does not hold". If one of its confirmed time stamps is premature: `VENDOR_LOG_CONTRADICTION(d)` "day closed before its end", and o is **broken**. o is **witnessed** if at least one of its confirmed time stamps is witnessing and o is not broken.

**L3 Days.** S(d) are the established entries of day d, Wt(d) the witnessed ones. If S(d) has two or more elements: `VENDOR_LOG_CONTRADICTION(d)` "two signed versions", with both day hashes. The canonical entry c(d) is the element of Wt(d) if Wt(d) has exactly one; otherwise, if Wt(d) is empty and S(d) has exactly one entry that is not broken, that one; otherwise c(d) is undetermined. Day d is **usable** if c(d) is determined and witnessed. A later unwitnessed version is thus reported, but it does not take the day from the witnessed one; two witnessed versions make the day unusable. The effect of a contradiction on a day stays confined to that day. For condition (5) of the evidence level only contradictions without a day and on days of the required range of this package count (step L7, Section 10.9.4); a contradiction on another day, for example in a yearly mirror, does not take level 3 from a package.

**L4 Head.** The head is the latest day d for which c(d) is determined, or none. `seen_in` is the number of files passed (counted by distinct bytes) that contain the `statement_jcs` of c(head). `seen_in` is no measure of independence: whoever passes files on can put the same day objects into differently written files, and the verifier cannot tell whether two files come from two places.

**L5 Chaining.** If c(d) and c(d + 1) are determined and `prev_hash` of c(d + 1) is not the day hash of c(d): `VENDOR_LOG_CONTRADICTION(d + 1)` "does not link to the previous day". If c(d) is determined, d > F and S(d − 1) is empty, and `prev_hash` of c(d) equals the day hash of an established entry of a day x < d − 1: `VENDOR_LOG_CONTRADICTION(d)` "skips the days x + 1 to d − 1".

**L6 Chain-day records.** Only records from extracts with `chain_id = C` are used. Records of other chains are counted (`foreign_chain_records`: every record of every extract, also an equal record in several files) and passed over, so that runs across a chain succession remain possible; records of chain C on days that are not usable are passed over and counted in no member of the report. For a usable day d, n = `tree_size` of c(d), R = `root` of c(d) and p = position(C, d) with A:

- `present`: from every element of `roots` the leaf under Section 7.4.2 is formed (`countersigned` as a countersignature, `gap_witness` as a gap witness, each with `chain_id` C; `server_ts` enters as the string the extract carries, Section 7.4.2, leaf from the recording), from them the chain-day root under Section 7.4.3 (ordered ascending by leaf hash, whatever the order in which `roots` names the roots) and the chain-day leaf with p. Required is `verify_inclusion(leaf_index, n, LH(chain-day leaf), path, R)` (Section 5).
- `absent`: exactly one of the forms of the absence proof of Section 5 for p against (n, R); every neighbour leaf `UTF-8(JCS({"chain_root": …, "kind": "ledger.vendor_log_day_leaf.v1", "position": …}))` holds by inclusion against (n, R). A neighbour can be a filler; the verifier does not distinguish fillers from chain-day leaves (Section 7.4.4).
- n and R always come from c(d), never from the record (Section 5).
- A record that does not hold: `VENDOR_LOG_DEFECTIVE(d)`.
- Among the records that hold for (C, d): a root in `present` with `day(server_ts) ≠ d` yields `VENDOR_LOG_CONTRADICTION(d)` "leaf of another day"; two records that hold and differ (in the chain-day root or as `present` against `absent`) yield `VENDOR_LOG_CONTRADICTION(d)` "two chain-day records". In both cases the record state of the day is **contradictory**.
- Otherwise the state is **checked**, with the proven leaf set M(d), empty for `absent`. Without a record the state is **none**; with records none of which holds, **failed**.

**L7 Required range.** RD are the days of the receipts of step L8 (every `CHECKPOINT_RECEIPT` whose signature holds under Section 7.1 and that has no finding `RECEIPT_INVALID`); RDF the days from RD that are ≥ F (all of RD if F is unknown). T is the maximum of the head and the due days from RDF, Lo the minimum of RDF. If both exist and Lo ≤ T, every day d in [Lo, T] for which no entry is established (S(d) empty, step L3) is missing; an object under a key that is not established, with a signature that does not hold, or with a violation of format or rules establishes no day. Per run of consecutive missing days the verifier reports `VENDOR_LOG_UNVERIFIED` once, "days without an established day entry in the extracts supplied", with the start and the end of the run. A due day of a receipt beyond the head is thus a finding, never a silent counter. The range is bounded by the days of the receipts and the head, never by `ts_chained`.

**L8 Receipts.** The step checks, in chain order, every `CHECKPOINT_RECEIPT` whose signature holds under the key of Section 7.1, whether that key is established or not, and that has no finding `RECEIPT_INVALID`. This holds also with a contradiction or a fork of the chain (for instance `FORK_DETECTED`); a receipt with `RECEIPT_INVALID` is passed over, even if its signature holds. Step L7 and the pre-reach r5′ (Section 10.9.4) use the same set of receipts. Per receipt, ℓ = LH of the signed subject of Section 7.1, formed from the `chain_id` of the envelope and the payload, with `server_ts` as the string of the payload, and d = day(`server_ts`). The cases are checked in order; the first that applies holds:

1. F is known and d < F: `before_start`.
2. `server_ts` (in whole milliseconds) lies after `now` + 900 000: `future` and `VENDOR_LOG_UNVERIFIED(d)` "receipt with server_ts after the check time". No closed day can contain such a receipt; it is never `pending`.
3. d is usable: state checked yields `included` if ℓ lies in M(d), otherwise `not_included`; state none yields `unchecked` with `no_record` and `VENDOR_LOG_UNVERIFIED(d)` "no chain-day record supplied"; state failed yields `unchecked` with `record_failed`; state contradictory yields `unchecked` with `record_contradictory`.
4. c(d) is determined but not witnessed: `unchecked` with `day_not_witnessed` and `VENDOR_LOG_UNVERIFIED(d)` "day entry not witnessed", with a reason from registry `vendor_log.not_witnessed_reasons`: `no_timestamp` if c(d) carries no time stamp; otherwise `no_log_root_supplied` if the auditor passed no root of purpose `log`; otherwise the reason of the time stamp of c(d) that got furthest, in this ranking from bottom to top: `outside_profile` (step 5 not performable under 5a, or Z.6 not checkable, Section 7.5.6), `not_chained_to_log_root` (no path to a root of purpose `log`), `published_test_key` (a path exists, key in `published_test_keys`), `late` (confirmed but late). Defective time stamps do not count for the reason. The finding is dropped if every time stamp of c(d) is defective; then `VENDOR_LOG_DEFECTIVE` already reports the day.
5. S(d) is not empty, but c(d) is undetermined: `unchecked` with `day_contradictory`.
6. S(d) is empty (no entry is established for d): `missing` if d is due (L7 reports the finding), otherwise `pending`. An object that establishes no entry (step L7) does not change this class.

If step L2 (f) ended the check, every one of these receipts is `unchecked` with the sub-class `first_day_contradictory`, without a further finding.

Per day with receipts of class `not_included` the verifier reports `RECEIPT_NOT_LOGGED(d)` once, with their number and the smallest `seq` among them. Only a witnessed day can testify against a receipt: whoever has stolen a protocol key but cannot produce a timely time stamp cannot incriminate an honest receipt.

| Class | Meaning |
|---|---|
| `included` | shown in the witnessed chain day of its day |
| `not_included` | day witnessed and record checked, its leaf is missing from it or the chain is proven absent (`RECEIPT_NOT_LOGGED`) |
| `unchecked` | not checkable, with sub-class `no_record`, `record_failed`, `record_contradictory`, `day_not_witnessed`, `day_contradictory` or `first_day_contradictory` |
| `missing` | no established day entry for its day although the day is due |
| `pending` | no established day entry for its day; the day is not due yet |
| `before_start` | its day lies before the start of the log |
| `future` | its `server_ts` lies more than 15 minutes after the check time |

**L9 Recorded roots.** For every usable day d with a checked record `present` and every element (t, r, `recorded_as`) of its `roots`: if t ≤ N and `root(t) = r`, the root matches the package (a leaf `countersigned` without a receipt of the same leaf in the package additionally counts as `matching_without_receipt`, once per distinct leaf; a receipt with `RECEIPT_INVALID` is a receipt of its leaf for this count). If t ≤ N and `root(t) ≠ r`: `LOGGED_ROOT_MISMATCH`, once per (t, r), with day and kind. If t > N, the root counts as `beyond_package` and goes with its `server_ts` to the check of the anchor history (Section 8.8). Recorded roots are no expected roots: they anchor nothing, do not lift `NO_ANCHOR` and establish no completeness; they serve reconciliation, here and in Section 8.8.

**L10 Output.** The result stands in the report object `vendor_log` (Section 10.10), among it the status, the head with day hash and `seen_in`, the number of receipts per class and the class of the receipt that Section 8.6 chooses as the last countersigned one. The exit code changes only through the five classes of Section 7.4.11, that is at most from 0 to 1; exit 3 arises only in L0.

#### 7.4.11 Findings

All five classes have exit class 1 (Section 10.4).

| Finding class | Meaning (registry) | Cases |
|---|---|---|
| `VENDOR_LOG_UNVERIFIED` | vendor log supplied but not established by the auditor's anchors, or not supplied completely | no effective protocol key (no list, foreign root, key in two roles, contradicting lists); entry under a key that is no established protocol key; validity ended without a proven signing time; day of a receipt not witnessed; days without an established entry in the required range; no chain-day record for a usable day of a receipt; a receipt with `server_ts` after the check time |
| `VENDOR_LOG_DEFECTIVE` | supplied vendor log material does not hold (signature, time stamp or proof) | the signature of an entry does not hold; a time stamp is defective; a record holds neither as inclusion nor as absence |
| `VENDOR_LOG_CONTRADICTION` | the vendor signed contradicting or rule-breaking log statements | two established entries for one day; broken chaining or skipped days; signed violation of format or rules; confirmed premature time stamp; two different records that hold; a leaf of another day |
| `RECEIPT_NOT_LOGGED` | receipt missing from the witnessed vendor log of its day | a receipt whose signature holds, on a usable day whose checked record does not contain its leaf or proves the chain absent |
| `LOGGED_ROOT_MISMATCH` | root recorded in the vendor log does not match the package | a checked recorded root with t ≤ N differs from `root(t)` |

**Multiple reports.** Per class and UTC day at most one finding, with the reasons in the order of the steps, except `LOGGED_ROOT_MISMATCH` (per (`tree_size`, `merkle_root`)) and the runs of missing days; per class at most one without a day; missing days combined per run, next to a finding of the same class on a day of the run; `RECEIPT_NOT_LOGGED` once per day with the number and the smallest `seq`; `LOGGED_ROOT_MISMATCH` once per (`tree_size`, `merkle_root`).

**Why none of them is exit 2.** Every case can occur with an honest chain: a damaged fetch, an outage or data loss at the vendor, its misconduct, an invented root, the takeover of a `chain_id`. "Invalid" is reserved for proven manipulation of the chain (Section 8.6); with exit 2 from the vendor's behaviour, a vendor could make an honest chain invalid without any involvement of the auditor. `LOGGED_ROOT_MISMATCH` can mean a rewrite by the key holder or a root the vendor invented; the verifier cannot tell the two apart. The route to exit 2 remains the anchor history as a source of expected roots (Sections 8.6, 8.8).

#### 7.4.12 Data Protection and Neutrality

| Published or delivered | Content | Recipient | What it reveals |
|---|---|---|---|
| day entry | day, size, root, hash of the previous day, time | anyone | the size step under the size rule (Section 7.4.4) |
| day leaves | positions, chain-day roots | anyone | the same as the size; whoever had a verification package of a chain recognises its later active days |
| extract with chain-day records | roots and times of the chain, sibling values, neighbours | whoever names the `chain_id` | the same as the anchor history (heartbeat specification §9.7) |
| protocol key list, role list, list of countersigning keys | public keys, roles, validity, places, filler commitment | anyone | nothing beyond that |
| opening of fillers (Section 7.4.13) | salts or a day secret | an examining body to which the vendor gives it; never public | singly: that these leaves are fillers; for a whole day: the number of its chains |

- No object of the log carries customer data or a commitment; public material carries neither `chain_id` nor `appliance_id` in clear. Only `chain_id` and `appliance_id` of the vendor's access chain, a chain without customer data, the vendor publishes itself (heartbeat specification §12).
- Whoever once had a verification package knows the `chain_id` and `appliance_id` of the chain. He can fetch extracts and pages of the anchor history of this chain later as well and so learns later roots, tree sizes, times of the countersignatures and changes of the statement on affiliation. Through `successor` of a page (heartbeat specification §9.7) he learns the `chain_id` of the successor chain; because both chains belong to the same appliance, he can compute its positions with the same `appliance_id` and recognise its active days in the day leaves (Section 11.2).
- Every chain is logged under the same rule, without exception and without a variant per customer, including the vendor's own chains and the chains of affiliated customers (heartbeat specification §9.10). Building the log reads only the leaves and the binding of the chain to its appliance, no licence, customer or affiliation data; the affiliation never stands in the log.
- Every vendor can keep a log under these rules, with its own root, its own `log_id`, its own protocol keys, its own filler secret and its own time-stamping authorities; no criterion names a vendor.
- What the vendor records about fetches of the log is governed by heartbeat specification §12. Whether it keeps to that, no verification package and no extract shows (no evidence produced by LEDGER).

#### 7.4.13 Opening of Fillers `ledger-fuelleroeffnung/1`

With an opening the vendor shows an examining body that certain leaves of a day tree are fillers (Section 7.4.4). An opening exists only for fillers of the derived construction, on days from the first version of the protocol key list that names the filler commitment. An opening is a file under the rules for auditor files (Section 2) with exactly these members; `x?` means `x` or `null`:

```
{"format":       "ledger-fuelleroeffnung/1",
 "log_id":       key-id,
 "day":          date (log range),
 "day_secret":   hex64?,                 day secret g(day); opens the whole day
 "filler_count": int (0 … 2^53−1)?,      m(day); not null exactly when day_secret is not null
 "fillers":      [0 … 4096 × {"salt": hex64}]}
```

`fillers` names individually opened fillers, pairwise distinct; if `day_secret` is `null`, it names at least one. An opening is unsigned and proves itself; no verifier reads it, and it is not an auditor input under Section 10.8. Anyone who has the day entry and the day leaves of the day can check it. The derivation and checks F2 to F4 need nothing but HMAC-SHA-256 and SHA-256; F1 additionally requires the timestamp profile (Section 7.5).

- **F1** `log_id` and `day` equal those of the day entry; the entry is witnessed (Section 7.4.6), and the day leaves pass checks (a) to (c) of Section 7.4.9 against it.
- **F2** For every element of `fillers`, position and root, formed under Section 7.4.4 from `day`, `log_id` and `salt`, stand as a pair in the day leaves.
- **F3** With `day_secret`: the candidates are formed from `day_secret` (Section 7.4.4). The candidates 0 to `filler_count` − 1 stand with their pair in the day leaves, and their positions are pairwise distinct; the position of the candidate `filler_count` stands nowhere in the day leaves; every salt from `fillers` is that of one of the candidates 0 to `filler_count` − 1. Otherwise the opening fails. If, under a witnessed entry, a leaf with a different root stands at the position of a candidate, this leaf has no provable origin; that is attributable to the vendor.
- **F4** With `day_secret`: `tree_size` is the smallest power of two that is at least 1024 and at least `tree_size` − `filler_count`. If F4 fails, the opening still passes, and the vendor violated the size rule on that day.
- **Filler outside the selection.** If a leaf that F2 shows to be a filler stands at a position that none of the candidates 0 to `filler_count` − 1 of an opening of the same day passing F3 occupies, the vendor violated the selection on that day (Section 7.4.4); that is attributable to the vendor.
- **Filler secret.** If the vendor gives an examining body the filler secret G itself, the body first checks that the filler commitment from G (Section 7.4.4) equals `fuellerbindung` of the protocol key list. It then forms every day secret itself, for every day `filler_count` as the smallest index of a candidate whose position does not stand in the day leaves, and performs F3 and F4. It thereby learns, for every day of the log, what the opening of the whole day shows.

What an opening proves if F1 to F3 pass:

| Part | proves | does not prove |
|---|---|---|
| F2 | Every opened leaf is a filler and not a chain-day leaf of a chain (Section 7.4.4). It was formed from this salt when the witnessed tree arose; finding a matching salt only later would require a preimage of SHA-256. | the index of the filler; the number of fillers of the day |
| F3 | The candidates 0 to `filler_count` − 1 are fillers, and the candidate `filler_count` is not in the tree. For the number of chains this gives only the upper bound n(d) ≤ `tree_size` − `filler_count`. | that the remaining `tree_size` − `filler_count` leaves are not fillers: further candidates beyond `filler_count` or leaves from arbitrary salts in the tree go unnoticed by F3. That these leaves belong to chains with honest leaves the vendor shows per leaf with the leaves of the chain and its binding to the appliance (Sections 7.4.2, 7.4.3); these are customer data (heartbeat specification §12), and this edition fixes no format for it. |
| F4 | If F4 fails, the vendor violated the size rule on that day. | that the size rule is kept when F4 passes; only proof of origin for every leaf that is none of the candidates 0 to `filler_count` − 1 shows that |
| every opening | nothing about other days: from a day secret and from salts neither the filler secret nor the day secret or a salt of another day can be computed. | that the day secret comes from the filler secret; only the filler secret itself, checked against the filler commitment (above), shows that. Whether the vendor uses derived fillers on days it does not open (no evidence produced by LEDGER) |

The size rule and the number of chains of a day are therefore shown only by the opening of the whole day together with proof of origin for every leaf that is not a filler of the selection. The opening of a whole day alone shows the recipient, for a vendor that keeps to the selection, the number of chains of that day, otherwise an upper bound; the opening of single fillers shows only that there are at least as many fillers as it opens. An opening is bound to no recipient; whoever receives it can pass it on. To whom the vendor gives openings and how it records them is governed by heartbeat specification §9.9.

Reference values (day tree of size 5 from Section 7.4.4, F1 presupposed): the opening of candidate 1 with the salt `beb59a39221d53bf16f62d42d66bfe2ac7bdcf26661432e5a8489b1c626adb46` passes F2. The opening of the whole day with g(d) and `filler_count` 4 passes F3, and F4 fails, as expected for a test tree below the size rule. With `filler_count` 5, F3 fails (candidate 4 is missing), and likewise with `filler_count` 3 (candidate 3 stands in the day leaves). A foreign salt fails F2, a foreign root at the position of candidate 1 fails F3. The opening of the day with 1023 fillers (Section 7.4.4) passes F2 to F4.

### 7.5 Time-Stamp Profile

From edition 1.10. The profile fixes byte by byte how a verifier reads and checks an RFC 3161 time stamp: for the time witnesses of the chain (Section 7.3), for the time stamps of the day entries (Section 7.4.6) and for the conditions of the evidence level (Section 10.9). A verifier MUST apply exactly these rules; its result depends on them alone, not on a certificate library or its version. Because time stamps travel unsigned, someone could otherwise drive two verifiers apart without changing a single signed byte. One profile applies to time witnesses and log alike, with RSASSA-PSS, P-521 and Ed25519. Both reference verifiers implement the profile completely, including the CMS signature (step 5) and the path (step 6).

#### 7.5.1 Base64

The grammar B64 of Section 2 applies. A token whose string violates it fails at step 2 (Section 7.5.7).

#### 7.5.2 Grammar T

The token's wrapper; it concerns steps 2 to 4 of Section 7.3.

- **T.1** `ContentInfo ::= SEQUENCE { contentType OID = 1.2.840.113549.1.7.2, content [0] EXPLICIT SignedData }`. After it the decoded bytes contain nothing further, and inside it nothing follows `content`.
- **T.2** `SignedData ::= SEQUENCE { version INTEGER (1..5), digestAlgorithms SET OF AlgorithmIdentifier, encapContentInfo, certificates [0] IMPLICIT OPTIONAL, crls [1] IMPLICIT OPTIONAL, signerInfos SET OF SignerInfo }` with exactly one SignerInfo. The content of `certificates` (zero or more TLV) is checked in step 5: if it does not split into TLVs, step 5 is not performable (5a), and T is not violated. Of `crls` only the TLV is read.
- **T.3** `EncapsulatedContentInfo ::= SEQUENCE { eContentType OID = 1.2.840.113549.1.9.16.1.4, eContent [0] EXPLICIT OCTET STRING }`; `eContent` is present and contains exactly one TSTInfo without trailing bytes.
- **T.4** `SignerInfo ::= SEQUENCE { version INTEGER (1 | 3), sid, digestAlgorithm AlgorithmIdentifier, signedAttrs [0] IMPLICIT OPTIONAL, signatureAlgorithm AlgorithmIdentifier, signature OCTET STRING, unsignedAttrs [1] IMPLICIT OPTIONAL }`. `sid` is an IssuerAndSerialNumber (SEQUENCE) or `[0] IMPLICIT OCTET STRING` (subjectKeyIdentifier). Grammar T checks of `sid` only that it is a SEQUENCE or a primitive `[0]`; content that is not `{ issuer, serialNumber }` with a `serialNumber` per T.6 (for instance an INTEGER not in minimal form) matches no certificate in Z.5 (step 5a) and is never a violation of T. The version is not compared with the form of `sid`: version 1 with subjectKeyIdentifier and version 3 with IssuerAndSerialNumber do not violate T. The parameters of `digestAlgorithm` are absent or NULL, and `digestAlgorithm` stands in `digestAlgorithms`, whose elements likewise carry no parameters or NULL; this is compared by the OID, absent parameters and NULL counting as equal. The parameters of `signatureAlgorithm` are one TLV or absent; they are checked in step 5. Of `unsignedAttrs` only the TLV is read. If `signedAttrs` are present, every attribute is `SEQUENCE { attrType OID, attrValues SET OF }` with at least one value, and there is exactly one attribute `contentType` with exactly one OID value and exactly one attribute `messageDigest` with exactly one OCTET STRING value.
- **T.5** `TSTInfo ::= SEQUENCE { version INTEGER = 1, policy OID, messageImprint SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }, serialNumber INTEGER, genTime GeneralizedTime, accuracy SEQUENCE { seconds INTEGER OPTIONAL, millis [0] IMPLICIT INTEGER OPTIONAL, micros [1] IMPLICIT INTEGER OPTIONAL } OPTIONAL, ordering BOOLEAN OPTIONAL, nonce INTEGER OPTIONAL, tsa [0] EXPLICIT OPTIONAL, extensions [1] IMPLICIT OPTIONAL }` in this order and nothing else. `hashAlgorithm` is sha256, sha384 or sha512 (parameters absent or NULL), and `hashedMessage` has correspondingly 32, 48 or 64 octets; sha1 and every other algorithm violate T. `genTime` has the form `YYYYMMDDhhmmss[.f]Z` with 1 to 9 digits f, the last of which is not 0, an existing date (year `0001` to `9999` as in Section 2; the year `0000` violates T), hour 00 to 23, minute and second 00 to 59 and no offset. `tsa` is one TLV, read as a constructed `[0]`; its content is not checked. The content of `extensions` is read only by rule QS (Section 7.5.6).
- **T.6** DER for every element: definite lengths in minimal form; INTEGER with at least one content octet in minimal two's complement; BOOLEAN with the content `00` or `FF`; OID with at least one content octet, every subidentifier minimal and complete (its last octet has bit 8 equal to 0); primitive or constructed form as the type requires. The order within a SET OF is not checked, and an explicitly encoded DEFAULT value (for instance `ordering` FALSE, `trailerField` 1) is accepted. Where the grammar asks only for "one TLV" (`tsa`, `crls`, `unsignedAttrs`, the value of a signed attribute that no rule reads, the value of an attribute in a Name, the parameters of `signatureAlgorithm` and of every other AlgorithmIdentifier as far as no rule reads them, for instance in the `hashAlgorithm` of an ESSCertIDv2, `extnValue` of an extension that no rule reads, and the parts of `issuerSerial` and `policies` that Z.6 names), only this outer TLV is checked: identifier octets per X.690 Section 8.1.2, tag numbers from 31 included, and a definite length in minimal form; its content is not parsed and need not be DER. Content that a rule reads is checked by that rule under T.6 where it reads it: the content of basicConstraints, keyUsage, extKeyUsage and subjectKeyIdentifier of a certificate by Z.1 (Section 7.5.3), that of qcStatements by rule QS, item 4, under which a violation gives `malformed` (Section 7.5.6). Where T.6 checks a content without a grammar (for instance that of one of the four extensions under Z.1), it checks every element in it and descends into every constructed element, whatever its class; in the universal class it requires there the constructed form exactly for tag numbers 8, 11, 16, 17 and 29 and the primitive form for every other from 1 to 30, and an element of the universal class with tag number 0 or one from 31 on does not satisfy T.6 there; in the other classes every tag number in either form is admitted there. A limit of the profile: whether the unused bits of a BIT STRING are zero (X.690 Section 11.2.1) is not checked, nor are content rules of X.690 other than those named here, for instance that NULL has no content or that a BIT STRING carries the unused-bits octet; where a rule reads such a value, it checks it itself (for instance keyUsage under Z.3).

#### 7.5.3 Z.1 Certificates

Applies to every element of `certificates` and to every certificate the auditor passes.

- `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }` with 0 unused bits, DER under T.6, without trailing bytes.
- `tbsCertificate ::= SEQUENCE { [0] EXPLICIT version INTEGER = 2, serialNumber INTEGER, signature AlgorithmIdentifier, issuer Name, validity SEQUENCE { notBefore Time, notAfter Time }, subject Name, subjectPublicKeyInfo SEQUENCE { AlgorithmIdentifier, BIT STRING }, extensions [3] EXPLICIT SEQUENCE SIZE (1..MAX) OF Extension OPTIONAL }`, without `issuerUniqueID` and `subjectUniqueID`. `serialNumber` is positive with at most 21 octets of content; `signature` is byte-identical with the outer `signatureAlgorithm`; the BIT STRING in `subjectPublicKeyInfo` has 0 unused bits.
- `Name ::= SEQUENCE OF SET SIZE (1..MAX) OF SEQUENCE { OID, one TLV }`; names are compared as bytes and never interpreted.
- `Time` is UTCTime `YYMMDDhhmmssZ` (YY < 50 stands for 20YY, otherwise for 19YY) or GeneralizedTime `YYYYMMDDhhmmssZ`, with a valid date (year `0001` to `9999` as in Section 2; the year `0000` violates Z.1) and a valid time of day.
- `Extension ::= SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }`; `critical`, if encoded, has the content `00` or `FF`; no `extnID` occurs twice; `extnValue` is exactly one DER TLV; for an extension that no rule reads, T.6 checks only the outer TLV. For basicConstraints (2.5.29.19), keyUsage (2.5.29.15), extKeyUsage (2.5.29.37) and subjectKeyIdentifier (2.5.29.14) the content of `extnValue` is read and MUST be DER under T.6; a violation makes the certificate violate Z.1.

#### 7.5.4 Z.2 Algorithms and Keys

Applies to the signer's key and to every key that checks a signature on a path.

- **Keys:** `rsaEncryption` (parameters NULL) with `RSAPublicKey { n, e }`, n positive and odd with 2048 ≤ bitlength(n) ≤ 8192, e odd with 65537 ≤ e ≤ 2^31 − 1; `id-ecPublicKey` with namedCurve P-256, P-384 or P-521 and an uncompressed point `04 || X || Y` on the curve; `id-Ed25519` without parameters, 32 octets, with canonical y (Section 2).
- **RSA signatures:** sha256/384/512WithRSAEncryption (parameters absent or NULL) and, only in the SignerInfo, `rsaEncryption` (parameters absent or NULL, as with the SHA-2 forms) together with a SHA-2 `digestAlgorithm`, each RSASSA-PKCS1-v1_5 with comparison of the complete encoded message and a signature length equal to the octet length of n; RSASSA-PSS with exactly the parameters `{ [0] hashAlgorithm SHA-2, [1] maskGenAlgorithm MGF1 with the same hash, [2] saltLength = hash length, [3] trailerField absent or 1 }` on an `rsaEncryption` key.
- **ECDSA signatures:** ecdsa-with-SHA256/384/512 (parameters absent) and, only in the SignerInfo, `id-ecPublicKey` (parameters absent, as with the SHA-2 forms) together with a SHA-2 `digestAlgorithm`; the signature is `SEQUENCE { r, s }` of minimal positive INTEGERs with 1 ≤ r, s < the group order of the curve.
- **Ed25519 signatures:** Ed25519 (parameters absent).
- SHA-1, MD5 and everything else lie outside the profile, the Brainpool curves (RFC 5639) included. A token whose signer uses such a curve cannot be checked under step 5a (`TIME_ANCHOR_UNVERIFIED`; a day time stamp is not confirmed); a certificate of a path with such a curve yields no path under Z.4. The curve alone never makes a time stamp defective.
- **Key and algorithm fit each other** if an RSA algorithm stands on an `rsaEncryption` key, an ECDSA algorithm on an `id-ecPublicKey` key and Ed25519 on an `id-Ed25519` key. Nothing more is compared: a signature algorithm with its own hash (sha256/384/512WithRSAEncryption, RSASSA-PSS, ecdsa-with-SHA256/384/512) need not name the same hash in the SignerInfo as `digestAlgorithm`, and the curve does not bound the hash. The check uses the hash of the signature algorithm; only with `rsaEncryption` or `id-ecPublicKey` as the signature algorithm of the SignerInfo does the hash of `digestAlgorithm` apply.

#### 7.5.5 Z.3 to Z.5: Extensions, Path and Signer

- **Z.3 Extensions on a path.** Understood, also when marked critical: basicConstraints `SEQUENCE { cA BOOLEAN OPTIONAL, pathLenConstraint INTEGER (0..MAX) OPTIONAL }`, keyUsage `BIT STRING` with at least one content octet, the first of which (the number of unused bits) is 0 to 7, and 0 if no further octet follows; a bit such as keyCertSign (bit 5) is set if it lies among the used bits and is 1, a 1 among the unused bits does not count; extKeyUsage `SEQUENCE SIZE (1..MAX) OF OID`. If a certificate of the path carries nameConstraints (2.5.29.30), policyMappings (2.5.29.33), policyConstraints (2.5.29.36) or inhibitAnyPolicy (2.5.29.54), critical or not, this path is not usable; likewise with every other critical extension. Every other non-critical extension is passed over. If basicConstraints, keyUsage or extKeyUsage of a certificate of the path does not follow this grammar, this path is not usable, even where Z.4 does not evaluate the extension at its position (for instance keyUsage of the signer c0).
- **Z.4 Path at `genTime`.** A path c0 (signer) … ck with ck byte-identical (DER) to the root R, k ≥ 0 (the signer can itself be the root), k ≤ 8, no certificate twice, intermediate certificates only from the token's `certificates`. For i < k, `issuer(ci)` is byte-identical with `subject(ci+1)`, and the signature of ci holds with the key of ci+1 under Z.2. Every cj with j ≥ 1 carries basicConstraints with cA TRUE, keyUsage (if present) with keyCertSign and pathLenConstraint (if present) ≥ j − 1. For every certificate of the path notBefore ≤ genTime ≤ notAfter holds, compared as instants. c0 carries extKeyUsage marked critical with exactly `id-kp-timeStamping` (RFC 3161 Section 2.3); every cj with j ≥ 1 that carries extKeyUsage contains `id-kp-timeStamping` or `anyExtendedKeyUsage`. Not checked are the signature of the root itself, the signer's keyUsage beyond its grammar under Z.3, and revocations. The path is a statement of existence: an implementation MUST search every candidate up to depth 8, so that the order of the search cannot change the result.
- **Z.5 Signer.** `sid` as an IssuerAndSerialNumber matches the bytes of `issuer` and the value of `serialNumber` of a certificate, as `[0]` the key identifier of its subjectKeyIdentifier extension (the content of the OCTET STRING in its `extnValue`); exactly one certificate from `certificates` matches (identical bytes count once). What is signed are the DER bytes of `signedAttrs` with the tag `0x31` instead of `0xA0` (RFC 5652 Section 5.4).

#### 7.5.6 Z.6 ESS Binding and Rule QS

- **Z.6 Binding of the signer certificate.** The signed attributes contain at least one of signingCertificate (1.2.840.113549.1.9.16.2.12; in `certs[0]`, `certHash` is the SHA-1 value of the DER of the signer certificate) and signingCertificateV2 (1.2.840.113549.1.9.16.2.47; in `certs[0]`, `hashAlgorithm` is SHA-256 if absent, otherwise SHA-256, SHA-384 or SHA-512, and `certHash` is this hash of the DER of the signer certificate); each of the two that is present meets this rule, and `issuerSerial` in `certs[0]`, if present, matches the signer. The verifier recognises the `hashAlgorithm` of an ESSCertIDv2 by its OID alone; its parameters are one TLV or absent, T.6 checks only their outer TLV, and whether they are absent, NULL or any other value changes nothing. `issuerSerial` matches the signer if its `serialNumber` equals the signer's and the Name in one `directoryName` `[4]` among its GeneralNames is byte-identical with the signer's `issuer`. A token with both attributes is admissible. Each of the two attributes appears at most once among the signed attributes and has at most one value (T.4 already requires at least one), a SigningCertificate or SigningCertificateV2 respectively in DER per T.6 with at least one element in `certs`; otherwise Z.6 is violated (never grammar T, never step 5b). What is read is `SigningCertificate ::= SEQUENCE { certs SEQUENCE OF ESSCertID, policies SEQUENCE OPTIONAL }` with `ESSCertID ::= SEQUENCE { certHash OCTET STRING, issuerSerial IssuerSerial OPTIONAL }`, for signingCertificateV2 the same with `ESSCertIDv2 ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier OPTIONAL, certHash OCTET STRING, issuerSerial IssuerSerial OPTIONAL }`, and `IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber INTEGER }`. Every element of `certs` follows this grammar, also where only `certs[0]` is compared; an `issuerSerial` in a later element is not compared with the signer. `GeneralNames` is a SEQUENCE of at least one TLV: an element with the identifier octet `A4` (directoryName) holds exactly one Name per Z.1; of every other element T.6 checks only the outer TLV. No rule reads `policies`; T.6 checks only its outer TLV. A `[4]` elsewhere, for instance in the value of an otherName or in `policies`, is no directoryName. If a present attribute deviates from this structure, even only in an element of `certs` after the first, Z.6 is violated. A present signingCertificateV2 whose `hashAlgorithm` is other than SHA-256, SHA-384 or SHA-512 is not compared and does not by this violate Z.6. If the token does not violate Z.6 otherwise (count, DER and structure as above, in every element of `certs`; every other present attribute names the signer, and `issuerSerial` in `certs[0]` matches in every present attribute), Z.6 cannot be checked: a day time stamp is then unconfirmed, condition (4) gets `signature_not_checkable`; it is never defective because of this. SHA-1 serves here as an identifier, not as an imprint: a forgery would need a second preimage for a certificate the authority itself issued, and RFC 3161 Section 2.4.1 requires the attribute. Z.6 is a condition for a confirmed day time stamp (Section 7.4.6) and for condition (4) of the evidence level (Section 10.9); it does not change the finding of a TIME_ANCHOR.
- **Rule QS (statement "qualified" in the TSTInfo).** The input is the component `extensions` `[1]` of the TSTInfo (T.5), or none. The rule never yields a finding and is never part of steps 1 to 6.
  1. No `[1]`: `absent` (usable).
  2. The content of `[1]` is one or more `Extension` under Z.1, each DER under T.6 without trailing bytes. `critical`, if encoded, has exactly one content octet `00` or `FF`; an explicitly encoded `00` is accepted (it violates X.690 Section 11.5 but occurs in qualified time stamps). Any other content octet, an empty `[1]`, a duplicate `extnID` or any other deviation: the extensions are **unusable**. Of the `extnValue` of an extension this item checks only the outer TLV under T.6; content of the `extnValue` of `1.3.6.1.5.5.7.1.3` that is not DER is `malformed` under item 4, not unusable.
  3. An extension with `critical` = `FF` whose `extnID` is not `1.3.6.1.5.5.7.1.3`: unusable, since its meaning is unknown.
  4. No extension `1.3.6.1.5.5.7.1.3`: `absent`. Otherwise its `extnValue` MUST be exactly one DER `SEQUENCE OF QCStatement`, every `QCStatement ::= SEQUENCE { statementId OID, statementInfo ANY OPTIONAL }` with one or two elements, without trailing bytes; otherwise `malformed`. `present` exactly when a `statementId` is `0.4.0.19422.1.1` (DER `06 07 04 00 81 97 5E 01 01`), otherwise `absent`. The identifier is `esi4-qtstStatement-1` from ETSI EN 319 422; Implementing Regulation (EU) 2025/1929 applies this standard in version V1.1.1, with adaptations, to qualified time stamps. The legal basis beside ETSI EN 319 422 is Implementing Regulation (EU) 2025/1929, Annex (adaptation to EN 319 422, No. 9.1): qcStatements with esi4-qtstStatement-1, not critical. The identifier does not say whether an authority is qualified; only the trusted list shows that, from which the auditor derives the file `ledger-tsa-qualifiziert/1` (Section 10.8). `statementInfo` is not evaluated; of it only the outer TLV is read (identifier per X.690, minimal definite length), its content need not be DER.

  A search for bytes in the TSTInfo MUST NOT be used: the nonce is an INTEGER chosen by the requester and can carry these nine bytes.

#### 7.5.7 Mapping of Results and Purposes of the Roots

| Result | TIME_ANCHOR (7.3) | Day time stamp (7.4.6) | Evidence level (10.9) |
|---|---|---|---|
| B64, size or grammar T violated | `TIME_ANCHOR_INVALID` (step 2) | defective | no credit |
| imprint wrong | `TIME_ANCHOR_INVALID` (step 4) | defective (imprint ≠ `H(UTF-8(statement_jcs))`) | no credit |
| step 5 not performable (5a) | `TIME_ANCHOR_UNVERIFIED` | unconfirmed | `signature_not_checkable` |
| step 5 performed and failed (5b) | `TIME_ANCHOR_INVALID` | defective | no credit |
| Z.6 violated | no effect on the exit code | defective | `signing_certificate_not_bound` (condition 4 only); for condition 7 a defective day time stamp forms no triple |
| Z.6 cannot be checked (hash of a signingCertificateV2 outside SHA-256, SHA-384, SHA-512) | no effect on the exit code | unconfirmed | `signature_not_checkable` (condition 4 only) |
| no path under Z.3 and Z.4 to a root of the purpose | `TIME_ANCHOR_UNVERIFIED` | unconfirmed | `not_chained_to_auditor_root`, `not_chained_to_qualified_root` or `not_chained_to_qualified_log_root` |
| SPKI of the signer or of the root in `published_test_keys` | no effect on the exit code | unconfirmed | `published_test_key` |
| extensions under rule QS unusable, `malformed` or `absent` | no effect | no effect | condition 1: `token_extensions_unusable` if unusable; conditions 4 and 7: `token_extensions_unusable`, `qualified_statement_malformed` or `no_qualified_statement` |

For a day time stamp the rows are checked in the order of the table; the first that applies decides. If none applies, it is **confirmed**. The row on `published_test_keys` applies if the signer's SPKI is listed there or if every root to which a path under Z.3 and Z.4 exists is listed there; if a path leads to a root that is not listed there, the time stamp is judged by the following rows. For a TIME_ANCHOR the order of the steps of Section 7.3 applies.

**Purposes of the roots.** Every certificate the auditor passes as a root for time stamps stands with its SPKI SHA-256 value and its purposes in a table (Section 10.8):

- `chain`: time witnesses of the chain (step 6 in Section 7.3) and condition (1) of the evidence level;
- `qualified`: condition (4) of the evidence level, only within the period for which the auditor names the root as qualified; such a root also carries the purpose `chain`; if the same certificate also carries the purpose `log`, it counts within the same period for condition (7);
- `log`: time stamps of the day entries (Section 7.4.6) and, together with the purpose `qualified` on the same root, condition (7) of the evidence level.

The file of qualified roots never gives the purpose `log`; for condition (7) the auditor passes the same certificate also as a root for time stamps of the log (Section 10.8).

A root counts only for the purposes for which the auditor passes it; a root for the log never confirms a time witness of the chain, and vice versa. The system root store counts for no purpose, and no verifier carries a root of a time-stamping authority built in.

**Published test keys.** The registry lists under `published_test_keys` keys whose private part is published or can be derived from published values; the list changes only with an edition of the specification. It has two kinds of entries:

- the SPKI SHA-256 values of keys of a time-stamping authority, for example of the test time-stamping authority of the test corpus, `0ee470ade299184118b50cff3ac1d7f671a8eb98b0097a230df0912db863aac1`. A signer or root with such a key confirms no time stamp and is credited for no condition of the evidence level (row above);
- from edition 1.10 the public keys (hex64) of the Ed25519 test keys of the vendor in the test corpus: vendor root, countersigning keys, statements keys and the update manifest key (reference values in Section 10.7.2), and the protocol keys of the test log `ledger-testprotokoll-1`, `vendor-log-test-001` and the standby key `vendor-log-test-002` (Section 7.4.7). Such a key counts under the rules under which the auditor passes it or a list establishes it, so that the test corpus can show the conditions that rest on keys of the vendor; if a condition of the evidence level rests on it, the report gives the note `published_test_key_credited` (Section 10.9.6).

**Time-stamping authority of the test corpus with discarded keys.** The test corpus MAY contain a time-stamping authority whose keys cannot be derived from published values: its keys are created in one run of the vector generator from a cryptographically secure random source, serve only in that run to issue the tokens of the corpus, and are written nowhere. The root and the certificates of this authority are in the corpus; its keys are not in `published_test_keys`. It counts only where the audit environment of a vector passes its root (`pruefer_<name>.json`); no auditor outside the test corpus has a reason to pass it. Its tokens cannot be issued again: the generator keeps them as frozen inputs and refuses to run if a regenerated statement no longer matches a frozen token. A new set of such tokens needs a new authority with a new root and new pins. Whoever ran the generator could have kept the key; that is why such a root is never an auditor's root.

### 7.6 Future Anchor Types

Further anchor types are conceivable. From edition 1.10 the following applies to them: an anchor type in the chain is a new entry type and falls under rule 2 of Section 10.6; an anchor type outside the chain is an auditor input (Section 10.8) that an older verifier does not offer. A verifier from edition 1.10 that does not know it answers it as an unusable invocation, in the browser edition as well, and never assesses the package differently. How verifiers of edition 1.9 treat unknown inputs is stated in Section 10.6.

## 8. Gap Semantics

Principle: **No events is an event, too.** Silence is only unobjectionable when the chain itself declares it.

### 8.1 TICK Obligation

While operating, the write path MUST write an entry at latest every **5 minutes**; absent any other event, that entry is a `TICK`. Every silence window of the write path is thereby bounded and verifiable.

### 8.2 Concealed vs. Covered Silence

For every pair of consecutive entries `a` (seq n) and `b` (seq n+1) let `Δ = ts_chained(b) − ts_chained(a)`, computed in whole milliseconds (Section 2). Tolerance: **7.5 minutes** (450,000 ms = 1.5 × TICK interval). If `Δ > 450,000 ms`, there is a silence window. It counts as **covered** if at least one of the following conditions holds:

1. `b` is a `GAP` entry whose window covers the silence: `started_ts(b) ≤ ts_chained(a) + 450,000 ms` AND `ended_ts(b) ≥ ts_chained(b) − 450,000 ms`. Finding: `COVERED_GAP` (exit 1).
2. `b` is a `RESTART` entry (the downtime is declared via `downtime_ms_estimate`). An additional covering `GAP` SHOULD follow if events were lost. Independently, Section 8.7 requires after a crash that every answered call not in the chain lies inside a `GAP` window, and sets where that window begins; whether the silence is covered does not depend on it.
3. `a` is the immediate checkpoint of a `SEAL`, and `b` is the matching `RESUME` (Section 8.4): planned silence, declared by the handover itself. From edition 1.9 likewise: `a` is a `SEAL`, `b` its immediate checkpoint written late at restart with `mono_delta_ms(b) = −1`, and after `b` follows either the `RESUME` that continues this `SEAL` or no entry at all: a crash between `SEAL` and its immediate checkpoint, declared by the handover; if the package ends with `b` (the restart's `RESUME` was never written), the `SEAL` itself declares the silence. No entry can be missing between `a` and `b` (`seq`, the Merkle tree of `b`); an honest chain thus never becomes invalid.
4. **Immediate checkpoint written late after a crash (from edition 1.9).** All four parts MUST hold: (a) `a` is a critical entry other than `SEAL`, and `b` is a `CHECKPOINT` (per Section 6.1 it binds `a` into its signed tree); (b) `mono_delta_ms(b) = −1`, the trace of a new process (Section 9.2): a writer that merely stalled writes `mono_delta_ms ≥ 0`; (c) the entry after `b` is a `RESTART` with `ts_chained(RESTART) − ts_chained(b) ≤ 450,000 ms` (a negative difference satisfies this; clock jumps are checked by Section 9.2), with `downtime_ms_estimate = −1` or `downtime_ms_estimate ≥ Δ − 450,000`; (d) the entry after that is a `GAP` whose window covers the silence between `a` and `b` as in condition 1: `started_ts ≤ ts_chained(a) + 450,000 ms` and `ended_ts ≥ ts_chained(b) − 450,000 ms`. Like every other `GAP` it is the finding `COVERED_GAP` (exit 1).

If no condition holds, the silence window is **concealed**: finding `CONCEALED_SILENCE` (exit 2). A covering `GAP` outside these positions does NOT cover the silence: the declaration must close the silence immediately.

**Why condition 4, and why so narrow.** If the writing path crashes between a critical entry and its immediate checkpoint, the restart writes the checkpoint late (Section 6.2), then `RESTART` and `GAP`. Up to edition 1.8 the silence before the late checkpoint stayed concealed although the chain declares it right after (deliberate decision of 2026-09-03, changed on 2026-09-29 in favour of coverage by the following `RESTART`, on the condition that a `RESTART` must not be able to conceal a deletion). Condition 4 therefore demands the trace of the restart, the declaration that follows immediately and a `GAP` window that encloses the whole silence. It touches no other check: no entry can be missing between `a` and `b` (`seq`, the checkpoint's Merkle tree), a `CONTENT_DELETED` as `a` remains the finding `CONTENT_DELETED`, and the deletion hold (Section 9.3) is checked as everywhere. The time of `a` is then bounded only by the signature of `b` at `ts_chained(b)`, not by the tolerance before it.

**Limit: "a RESTART must not be able to conceal a deletion" cannot be ensured offline in general, not even with condition 2, which has applied since edition 1.0.** Whoever has write access to the chain files can cut off the end of the chain including a `CONTENT_DELETED` and restart the installation; `RESTART` and `GAP` then cover the silence up to the last remaining entry, and nothing in the package refutes that. Likewise a restart signs any hash-consistent entry someone appended to the end before it. This is the same limit as the residual window (Section 11.2): the key is with the operator. Anchoring exposes it: the vendor no longer accepts a truncated chain (heartbeat specification §9.2), an expected root of the auditor contradicts it (Sections 7.2, 8.6), a time witness (Section 7.3). Condition 4 does not widen this possibility; what it covers could already be reached with fabricated `TICK` entries.

### 8.3 Gap Classes

`GAP.reason` carries exactly one of the classes of 4.26: `bypass` (gatekeeper direct forwarding without capture), `proxy_restart`, `power_loss`, `spool_unwritable`, `host_down`, `update`, `manual`. For import sources, `SOURCE_GAP` covers source windows (finding `COVERED_SOURCE_GAP`, exit 1); a `RECONCILIATION` with `delta ≠ 0` is the finding `RECONCILIATION_DELTA` (exit 1).

### 8.4 SEAL/RESUME Handover

Planned interruptions (update, shutdown, decommission) MUST be sealed; an export from running operation MAY be sealed (export seal, `reason = export`, from edition 1.9):

1. The old instance writes `SEAL`; as a critical type its immediate checkpoint MUST follow directly (Section 6.2).
2. The continuing instance (a new one after `update` or `shutdown`, the same one after `export` or, after a crash in between, the restarted one) writes `RESUME` as its first substantive entry, with `sealed_entry_hash` = **the `entry_hash` of the SEAL entry** (not of the immediate checkpoint; MUST match exactly) plus `prev_version`/`new_version`.
3. Between `SEAL` and `RESUME` there lies **exactly one** entry, and it MUST be the SEAL's immediate checkpoint.

Rationale for both halves of rule 3: A `SEAL` without an immediate checkpoint would remain **unanchored**: should the machine die between SEAL and RESUME, the chain state would be signed only up to the last older checkpoint; that is the weaker evidentiary position, and the moment of a planned interruption is precisely where the stronger one is needed. Conversely, **only this one anchor** may lie in between, so that the handover stays provably tight: any further entry inside the planned silence would no longer be covered by the handover itself.

Violations (a missing RESUME after a SEAL (although the chain continues), a wrong `sealed_entry_hash`, a different or an additional entry between SEAL and RESUME) are the finding `HANDOVER_BROKEN` (exit 2); the SEAL's missing immediate checkpoint itself is `MISSING_CHECKPOINT` (exit 2), except at the chain end (Section 6.2). If the chain ends with a SEAL + immediate checkpoint, this is a regular chain closure, not a finding, whatever its `reason` (from edition 1.6; up to edition 1.5 only with `decommission` or `key_loss`) and even when `CHECKPOINT_RECEIPT` entries on exactly this immediate checkpoint still follow: they confirm the sealed state and are not substantive entries. How the chain end is judged is governed by Section 8.6.

**Export seal (from edition 1.9).** The writer writes `SEAL` with `reason = export`, its immediate checkpoint, `RESUME` and the checkpoint after it without any entry in between and continues the chain immediately; in the chain this is an ordinary handover under rules 1 to 3. The verification package holds the entries up to and including the immediate checkpoint of this seal and is therefore sealed (Section 8.6). The handover takes milliseconds; a longer silence between checkpoint and `RESUME` (a crash during the export) is covered by condition 3 of Section 8.2 as for every handover.

Three clarifications (decision of 2026-09-03; both reference verifiers read the rule this way): (1) Every `RESUME` continues exactly one `SEAL`: a `RESUME` not immediately preceded by a `SEAL` with its immediate checkpoint is `HANDOVER_BROKEN`. (2) `CHECKPOINT_RECEIPT` entries on the immediate checkpoint of a `SEAL` may trail only at the chain end; between `SEAL` and `RESUME` they are an additional entry in the sense of rule 3. (3) The silence coverage of Section 8.2 condition 3 applies only to the handover the `RESUME` actually continues with a matching `sealed_entry_hash`.

### 8.5 Silence at the Chain End (Freshness)

No subsequent entry can cover the end of the chain. If `ts_chained` of the last entry lies further in the past than the **freshness window** at verification time, the verifier reports `TRAILING_SILENCE` (exit 1). The window is configurable (verifier option `--freshness`, grammar in Section 10.8); default: **24 hours**. This finding protects against presenting a stale (e.g. rolled-back) state; together with receipt `server_ts` and cloud-side `tree_size` monotonicity it bounds fork/rollback attacks (Section 11). The finding applies to a sealed chain as well (Section 8.6): the seal declares the silence after it, but it does not prove that it is the chain's most recent seal; a chain truncated at an earlier seal would look exactly the same (Section 11.2). `TRAILING_SILENCE` remains exit class 1; the chain remains valid.

### 8.6 Chain End: Sealed or Incomplete

Principle (from edition 1.6): **An honest chain is never reported as "invalid". "Invalid" (exit 2) is reserved for proven manipulation.** How a chain ends is therefore not a manipulation finding but a status of its own.

A chain is **sealed** if its last entries are, in this order: a `SEAL`, directly followed by its immediate checkpoint (Section 6.2), followed by at most `CHECKPOINT_RECEIPT` entries whose `checkpoint_seq` names exactly this immediate checkpoint. The `reason` of the `SEAL` plays no part in this. Every other chain is **incomplete**; this includes a chain whose last entry is a `SEAL` or another critical entry without its checkpoint (Section 6.2).

| Chain end | Result | Exit |
|---|---|---|
| sealed, no findings of exit class 2 | valid, properly sealed; the report states `seq`, `ts_chained` and `reason` of the `SEAL` | 0, with findings of exit class 1: 1 |
| incomplete, no findings of exit class 2 | incomplete: finding `UNSEALED_END` | 4 |
| `SEAL`, followed by other entries without `RESUME` | invalid: `HANDOVER_BROKEN` (Section 8.4) | 2 |
| hash chain broken, signature wrong or any other finding of exit class 2 | invalid | 2 |

The finding `UNSEALED_END` is reported exactly once for every incomplete chain, with the `seq` of its last entry, also alongside findings of exit class 2; the exit code then follows Section 10.3. If the package is a format error (exit 3), the chain end is not judged. From edition 1.6, exit 0 and exit 1 therefore presuppose a sealed chain end.

**What "incomplete" means.** All entries present are checked as for any chain. Incomplete only means: the package does not prove that nothing came after its last entry. Every export from a running installation without an export seal ends this way, every chain after a crash or power loss, and a truncated chain just as well. Offline these cases cannot be told apart. The verifier MUST therefore state, with the finding, the package's last countersigned checkpoint (`checkpoint_seq`, `tree_size`, `merkle_root` and `server_ts` of the receipt with the largest `tree_size` among those that count as an anchor per Section 7.1 (signature holds, no contradicting vendor list) and match their checkpoint; on equal `tree_size` the first in chain order) or that there is none, and point to the comparison.

**Export seal.** A package the installation produces with an export seal (Section 8.4) ends with `SEAL(export)` and its immediate checkpoint and is sealed: an orderly export from running operation is valid, not incomplete (decision of 2026-09-29).

**Comparison with the last countersigned checkpoint.** The vendor keeps, per `chain_id`, the roots it has countersigned, and from edition 1.9 hands them out together with gap witnesses and reported roots as a signed anchor history, which the auditor fetches himself by the `chain_id` (heartbeat specification §9.7); he then passes every root from it that was recorded or reported before the package was requested. At the least the auditor passes the most recent countersigned root countersigned **before the package was requested** as an expected root, like a paper anchor (`tree_size` and `merkle_root`, Sections 7.2, 10.8), not the most recent overall: a root countersigned after that lies beyond the end of the package and cannot occur in it; it would appear as a contradiction even for an honest package. If the package does not contain the root passed as a prefix root, it lacks entries the vendor had already countersigned: `MERKLE_INCONSISTENT` (exit 2). The comparison applies to sealed chains alike.

**Comparison by the verifier (from edition 1.10).** If the auditor passes the anchor history (Section 8.8), the verifier reads its pages itself and takes over every root from it, countersigned, recorded as a gap witness or reported, as an expected root with the source `anchor_history`. Roots the auditor passes himself as expected roots (Section 10.8) carry the source `auditor`. The boundary "before the request" is then drawn by the verifier, no longer by the auditor by hand: it compares the time at which the vendor recorded a root (with several recordings the earliest) with the request time R the auditor states (Section 10.8). A countersigned root or one recorded as a gap witness, recorded more than 15 minutes before R, that the package lacks or contradicts is `MERKLE_INCONSISTENT` (exit 2), as with the comparison by hand since edition 1.9; if the package lacks only a root from the 15 minutes before R, that is a note, not a finding, and the auditor requests the package again. A root that is only reported, in contrast, never leads to exit 2, but to `ANCHOR_HISTORY_FORK` (exit 1): the verifier cannot check its device signature, and no log confirms it. Section 8.8.5 gives the cases in detail. Added to this is the binding to the device: the verifier uses only pages whose owner commitments match a device key of the package (Section 8.8.4, step H2). Without R it judges no truncation. Roots from the vendor log are no expected roots (Section 7.4.10, step L9); pages of kind v1 the verifier does not evaluate; for them the comparison by hand under heartbeat specification §9.7 remains, as long as the vendor has published no role list.

**What the verifier says about completeness (from edition 1.9).** Without a root countersigned by the vendor, no statement is possible about whether the package holds the whole chain up to its request, neither for an incomplete nor for a sealed chain (limit of proof below, Section 11.2; decision of 2026-09-29: accepted as a property of the model). The verifier MUST say so explicitly for every package that is not a format error and ask for the root: with the `chain_id` and the invocation by which the auditor passes it. If an expected root was passed and found in the package, it says instead up to which `tree_size` completeness is established by it. With a format error completeness is not assessed: the member `completeness` then has the value `null` and is never left out (Section 10.10.1).

From edition 1.10 this applies to found expected roots of both sources, and the report names where the found roots come from: the object `completeness` gains the member `sources`, the sources of the found roots in the order `auditor`, `anchor_history` (registry `verifier.report_objects.completeness_sources_order`; the same order applies to `evidence_level.anchors.expected_root_sources`, Section 10.10.2). When asking for the root, the verifier then names the anchor history of kind v2 and the request time (Sections 8.8.1, 10.8). Besides this, the anchor history itself judges completeness (`anchor_history.completeness`, Section 8.8.4, step H11): there it is established only with a request time, with fresh pages that together cover all tree sizes, without a contradiction of the history and with at least one found root from it. The evidence level reads this statement (Section 10.9); roots of the source `auditor` alone do not suffice for it.

**Limit of proof of the seal.** The seal carries the signature of the device key, not the vendor's: the immediate checkpoint of a `SEAL` that a `RESUME` follows carries no receipt before the `RESUME` (Section 8.4, clarification 2). Every earlier handover (`SEAL`, checkpoint, `RESUME`) is therefore a point at which a truncated chain appears sealed without any key; the key holder can truncate at any point anyway and sign a new seal (Section 11.1). What works against this is the time of the seal in the report, `TRAILING_SILENCE` (Section 8.5) and, with certainty, only the comparison above (Section 11.2, test vector `end_truncated_at_seal`).

**Older verifiers.** The rule applies to every package, whatever `spec_version` it declares: the manifest is not signed, and a declared older edition must not change the status of the chain end (as in Section 7.1). A verifier of edition 1.5 or older does not know exit 4: it reports an incomplete chain as valid (exit 0 or 1; milder than this edition), but one whose last entry is a critical entry without its checkpoint as `MISSING_CHECKPOINT` and a chain sealed with `update` or `shutdown` as `HANDOVER_BROKEN` (exit 2 each; stricter). It recognises a package of edition 1.6 or later by the finding `SPEC_NEWER` (Section 10.6); packages from 1.6 SHOULD be checked with a verifier from 1.6. A verifier up to edition 1.8 does not know the sealing reason `export`: the payloads of known types stay strict (Section 10.6, rule 3), so it reports every package containing an export seal as `FORMAT_ERROR` (exit 3), permanently for that chain, including every later package, because the seal stays in the chain. Packages from 1.9 SHOULD be checked with a verifier from 1.9.

### 8.7 Capture commitment and gap start after a crash

From edition 1.9 (addition of 2026-10-02). Principle: no answered AI call may be lost silently. It is either in the chain, or it lies visibly inside a gap.

**Terms.** An **answered call** is an AI call that the appliance's capture took in and for which the appliance delivered response bytes of the provider to the client, whatever the status, and even if the response broke off afterwards. An error response the appliance produces itself without having passed the call on to a provider is not an answer. Its **intake** is the time the capture took it in, before forwarding (for `origin = proxy`, its `ts_captured`); its **end of answer** is the last time the appliance delivered response bytes for it. A **crash** is any end of a capture or write-path process without an orderly shutdown, and any host failure. All times in this section come from the appliance's wall clock (Section 4.4) and are compared in whole milliseconds (Section 2).

**Commitment.** Every answered call MUST be chained (after a crash also later, with its original `ts_captured`) or lie inside a `GAP`: `started_ts` ≤ end of answer and `ended_ts` ≥ intake. If its capture evidence survives a crash, the appliance SHOULD chain it rather than only placing it inside a window; it MUST NOT chain it a second time. A `GAP` meant to hold a possibly lost answered call MUST NOT carry `lost_count = 0`; if the number is unknown, it carries `−1`.

**Safe point.** The capture MUST keep durably recording up to where it vouches for its calls: a time S such that every answered call whose last delivery of response bytes began before S is durably secured, or its loss is durably counted with a window it lies in. With it, the safe point names the start of the capture process. It is recorded anew at least every second, and at least every 100 ms while calls are running; an older safe point is never wrong, it only makes a window wider.

**Where the window begins after a crash.** After a crash the appliance no longer knows the lost calls one by one; the start therefore follows from what was durably stored before the crash. For each of the three groups, at least one `GAP` chained after the crash MUST meet the condition; different `GAP`s may serve different groups:

1. Calls whose capture evidence was not yet durable: `started_ts` ≤ the last durably recorded safe point of the crashed capture process; if none is readable, `started_ts` ≤ the start of that process. `ended_ts` ≥ the time the appliance detects the crash.
2. Answered calls whose entry the write path had written but not made durable before the crash, and that it does not chain again under the commitment above: `started_ts` ≤ their `ts_captured`. Once a flush to the medium has failed, no entry written before it counts as durable through a later successful flush.
3. The silence itself: the `GAP` after the `RESTART` covers it as before under Section 8.2; for that its window begins no later than the `ts_chained` of the last surviving entry.

**Without a crash.** If the capture cannot secure an answered call, or the write path cannot chain a secured one, the `GAP` declaring this loss (class `spool_unwritable`) MUST begin no later than the call's intake. If the capture ends in order while a call is still running, group 1 applies accordingly.

**Import.** Events from an import interface (`origin = import`) carry their source's time in `ts_captured`; no appliance window can hold them. If an import interface confirms to the submitter that it took an event in, the event MUST be durably chained at that moment.

**Precondition.** If the wall clock steps back between intake and crash, a window can miss the call; Section 4.7 declares the step.

**Not a verifier finding.** A commitment not kept is not a verifier finding: the package contains only what was chained and cannot show a missing call (Section 11.2). A `GAP` whose window begins before the last entry preceding the silence is covered under Section 8.2 like any other (`COVERED_GAP`, exit 1); this section changes no finding and no exit code. The commitment is evidenced by tests with known ground truth at the appliance. Chains written before this addition may carry windows that begin only at the last entry.

### 8.8 Anchor History as an Auditor Input

From edition 1.10. The anchor history is the vendor's signed account of the recorded and reported roots of a chain, its fork findings and its change of chain (heartbeat specification §9.7). From this edition the auditor passes its pages of kind v2 to the verifier instead of copying roots from it by hand as expected roots. The verifier checks every page against anchors of the auditor, binds it to the chain and the device of the package, takes over its roots as expected roots with a source (Sections 8.6, 10.8), reconciles them with receipts and vendor log, and evaluates the statement on the affiliation of the customer with the vendor (heartbeat specification §9.10) over the period of the package.

None of this stands in the verification package. A verifier MUST NOT read anchor history pages, a statement on affiliation or a request time from the package (Section 10.1). It never derives the affiliation from `GENESIS.customer_id`, `GENESIS.edition`, the manifest, another file of the package, the vendor log or the evidence level. Both reference verifiers perform the steps of this section alike; every rule needs only I-JSON, JCS, SHA-256, Ed25519 and integer arithmetic.

#### 8.8.1 Inputs

| Input | Flag (Section 10.8) | Purpose |
|---|---|---|
| anchor history | `--anchor-history FILE`, repeatable | pages and embedded extracts (Section 8.8.2) |
| request time R | `--requested-at RFC3339`, at most once, optional | when the auditor requested the package |
| role list | `--vendor-key-list FILE`, repeatable | establishes statements keys of pages (Sections 8.8.3, 10.7.4); lists of the two other formats count here only for the role check |
| vendor root | `--vendor-root` (Section 7.1) | confirms the role list (Section 10.7.2) |
| pinned statements keys | `--vendor-statement-key ID=HEX`, repeatable | establish keys of pages (Section 8.8.3) |

A pin as a countersigning key (`--vendor-key`) establishes no page.

Grammar and limits are given in Section 10.8. The verifier reads only pages of kind `ledger.anchor_history.v2`. A page of kind v1 it does not use (step H2, reason `not_v2`): it binds the chain to no device and can omit fork findings without a marker. For pages of kind v1 the procedure by hand under heartbeat specification §9.7 remains, and only for a vendor without a published role list: if the vendor has published a role list, an auditor following edition 1.10 never passes roots from pages of kind v1 as expected roots.

The request time is optional. Without it the verifier judges no truncation: it counts roots beyond the package end without judging them, a differing root in the package is `ANCHOR_HISTORY_FORK` instead of `MERKLE_INCONSISTENT` (Section 8.8.5), completeness from the history counts as not established (reason `no_request_time`), and the report says so explicitly. The verifier never fills in R from `manifest.created_ts`, from `verify_args.json`, from the check time or from a clock. When the package was requested is known to the auditor, not to the package; an earlier `created_ts` can be chosen by the producer of the package and could thereby hide a truncation, and the check time would turn roots recorded only after the request into a contradiction against an honest package. If the auditor states a later time than the actual one, an honest package appears truncated; if he states an earlier one, the verifier checks less.

#### 8.8.2 Anchor History File `ledger-ankerhistorie/2`

An anchor history file is an auditor file (Section 2) in one of two forms:

- **One page:** the body of the HTTP response unchanged (heartbeat specification §9.7), an object with exactly the members `statement_jcs` (string, 1 to 131,072 characters), `server_key_id` (key-id), `server_signature` (hex128) and `statement` (any JSON value; the unsigned reading copy is not evaluated).
- **A container:** an object with exactly the members `format` (const `"ledger-ankerhistorie/2"`), `pages` (array, 1 to 4,096 pages as above) and `vendor_log` (array, 0 to 128 extracts under Section 7.4.8).

Extracts in `vendor_log` stand there unchanged; there is no shortened form. The verifier checks them under the grammar of Section 7.4.8 and treats them like extracts the auditor passes individually (Section 7.4.10, step L0); for the counting of files and the limits there each counts as one file with the bytes `UTF-8(JCS(element))`. So pages and extract of one audit travel in one file, without the two formats depending on each other.

Limits: per file at most 33,554,432 bytes; per invocation at most 4,096 anchor history files, 65,536 pages and 268,435,456 bytes. A violation of this grammar or of a limit is an unusable invocation (exit 3 without a report, Section 10.8). The content of `statement_jcs` is checked only by step H2; a defect there never leads to exit 3.

Reference value: the page for the test vector `valid_sealed_export` with its two countersigned roots (`tree_size` 15 with `server_ts` `2026-01-01T00:30:01.000Z` and 28 with `2026-01-01T01:00:01.000Z`), the owner commitment of heartbeat specification §9.7, `known_since` `2025-12-01T00:00:00.000Z`, without periods, with `reference_tree_size` 28, `since_tree_size` 0, without continuation and with `server_ts` `2026-01-01T01:02:00.000Z` has a `statement_jcs` of 776 characters with the SHA-256 value `6fe4cc5f74c2539468594843916f9cfa1e528934d3f812202f04969932ca175b`.

#### 8.8.3 Keys of the Pages

A page of kind v2 carries the signature of a statements key (role `statements`, Section 10.7.3). For the `server_key_id` of a page, the following applies in this order:

1. If it is pinned as a statements key (`--vendor-statement-key`) and not dropped under Section 10.7.4, the pinned public key applies, without a validity window. If the effective role list names the same public key with the role `statements` and `widerrufen_ab`, step H2, number 9 (Section 8.8.4) still applies to the signing time.
2. Otherwise the entry of the effective role list (Section 10.7.4) with the role `statements` applies.

Otherwise the key is not established. A countersigning key, a protocol key and a key of another role never establish a page, not even through a pin under Section 7.1 or a list of countersigning keys. The copy in the manifest (`manifest.vendor_pubkeys`, `keys/vendor/<key_id>.hex`) never establishes a page.

**Why only statements keys.** A route to exit 2 leads through pages (`MERKLE_INCONSISTENT`, Section 8.8.5). If a countersigning key established pages, whoever holds only such a key could make an honest package appear invalid with a page he signs himself. Because pages count only under statements keys, he produces no page a verifier uses (Section 11.2, key roles). A page under a key of another role is no forgery finding: it yields `ANCHOR_HISTORY_UNVERIFIED` with the reason `key_other_role` (Section 8.8.4, step H2).

Reference values (role list of version 1 from Section 10.7.2, instant `2026-01-01T01:02:00.000Z`): `vendor-statements-test-001` and `vendor-statements-test-002` are established and valid; a page under `vendor-test-001` yields `key_other_role`; a key the role list does not name is not established (`key_not_established`); a pin as a statements key takes precedence over the role list; two role lists of version 1 with different bytes: none is effective (`lists_contradictory`, Section 10.7.4), and no page is established through a role list.

#### 8.8.4 Checks by the Verifier

Notation: N, C, A and `root(t)` as in Section 7.4.10, likewise K_cs. PK are the device keys of the package: `GENESIS.device_pubkey` and every `new_pubkey` of a `KEY_ROTATION` that Section 6.4 legitimizes. `OC(c)` is the set of owner commitments (heartbeat specification §9.7) with the `appliance_id` A, the `chain_id` c and one key each from PK. R is the request time or absent; W_h = 900,000 ms (15 minutes). The **range** I(P) of a page P is `[since_tree_size, next_since_tree_size)`, for `next_since_tree_size = null` `[since_tree_size, ∞)`. BL is the cut-off date `legacy_boundary` of the registry (`verifier.anchor_history`). **Established receipts** are the `CHECKPOINT_RECEIPT` entries that count as anchoring under Section 7.1 and whose key is pinned (without being dropped under Section 10.7.4) or comes from the effective list of countersigning keys of the package. This section compares instants in whole milliseconds (Section 2, time arithmetic), R included; only the validity window of an entry of the role list (step H2, number 6) is checked to the nanosecond as in Section 7.1.

**Place in the verification procedure.** H0 runs at invocation, before the package is opened. H1 to H7 run after the vendor log (Section 7.4.10) and before the comparison of the expected roots. The classification H8 (Section 8.8.5) is computed by the verifier at the comparison of the expected roots (Section 10.5, step 8); its findings are reported only with the findings of the expected roots (step 13). H9 to H11 run after the time witnesses and read the classification computed in step 8; H12 and H13 run after the exit code is determined (Section 10.5).

**H0 Invocation.** The verifier reads every anchor history file under Section 8.8.2 and the request time under Section 10.8; R must not lie after the check time from `--now` or the system clock. A violation is an unusable invocation (exit 3 without a report) with the position in the file and the path of the member. Without an anchor history steps H1 to H11 are dropped; the status is `not_supplied`, the affiliation `not_checked`.

**H1 Pooling.** All pages of all files are pooled; identical `statement_jcs` are one page (counted as passed twice), with the set of its distinct pairs (`server_key_id`, `server_signature`). No pair displaces another, whatever the order in which the files are passed. Extracts from containers have already gone to the check of the vendor log in H0.

**H2 Every page.** The steps are checked in order. If one fails, the check of the page ends there, with exactly this reason (registry `verifier.anchor_history.page_reasons`, in this order):

1. **Key.** `server_key_id` is established under Section 8.8.3. Otherwise `ANCHOR_HISTORY_UNVERIFIED`: reason `key_other_role` if `server_key_id` names a key from K_cs or from the effective protocol key list, a pin as a countersigning or protocol key that is not dropped under Section 10.7.4, step R3 (d), or an entry of the effective role list with a role other than `statements`; otherwise reason `key_not_established`. A dropped pin does not count for this.
2. **Signature.** The Ed25519 signature over `UTF-8(statement_jcs)` holds, checked like the signature of a receipt (Section 7.1). Otherwise `ANCHOR_HISTORY_DEFECTIVE`, reason `signature`.
3. **Form.** `statement_jcs` consists of printable ASCII (Section 2), is an I-JSON object without duplicate member names and without lone surrogates and equals its own JCS form. Otherwise `ANCHOR_HISTORY_CONTRADICTION`, reason `page_rules`.
4. **Kind.** The member `kind` is the string `ledger.anchor_history.v2`. Otherwise `ANCHOR_HISTORY_UNVERIFIED`, reason `not_v2`: a page of kind v1, a statement or another signed object is a statement of the vendor, but not one this section reads.
5. **Content.** Members and types exactly under heartbeat specification §9.7 (kind v2) and registry `cloud_statements.anchor_history_v2`, all instants exactly in the form `YYYY-MM-DDThh:mm:ss.sssZ` except `server_ts` in `roots`, which is of type `rfc3339` (Section 2; the stored character string, heartbeat specification §9.7), every page rule of heartbeat specification §9.7. Otherwise `ANCHOR_HISTORY_CONTRADICTION`, reason `page_rules`: the established key has signed a rule-breaking page.
6. **Window.** If the key comes from the role list (not from a pin), `gueltig_ab` ≤ `server_ts`, `server_ts` < `gueltig_bis` and `server_ts` < `widerrufen_ab` hold for its entry, where present, by the grammar and to the nanosecond as in Section 10.7. Otherwise `ANCHOR_HISTORY_UNVERIFIED`, reason `key_not_valid`.
7. **Chain.** If `chain_id = C`, the page is a **page of the package**. Otherwise, after all pages of the package are checked, it is a **linked page** if a used page of the package names its `chain_id` as `predecessor` or `successor` or if `GENESIS.predecessor_chain.chain_id` names it; `GENESIS` serves only for recognition here, never as evidence. Otherwise `ANCHOR_HISTORY_UNVERIFIED`, reason `other_chain`.
8. **Device.** `owner_keys` of the page and `OC(chain_id)` with the `chain_id` of the page have at least one element in common. Otherwise `ANCHOR_HISTORY_UNVERIFIED`, reason `owner_differs`. A common key is required, not equality: the server may know keys the package does not show (a rotation after the export), and from the time before edition 1.10 only the key that was registered at the changeover (heartbeat specification §9.7).
9. **Signing time.** With R the page is **fresh** if `server_ts` ≥ R − W_h holds. If it is not fresh or R is absent, and the entry of its key in the role list carries `widerrufen_ab` (for a pinned key: an entry of the effective role list with the role `statements` and the same public key, Section 8.8.3), then `ANCHOR_HISTORY_UNVERIFIED`, reason `signing_time_not_proven`: the `server_ts` of such a page is determined by the signer, and whoever holds the revoked key could backdate it. A key that carries only `gueltig_bis` (planned change) is judged under number 6 as in Section 7.1.
10. Otherwise the page is **used**: `used_fresh` (page of the package, fresh), `used_stale` (page of the package, with R, not fresh), `used_unjudged` (page of the package, without R) or `used_linked` (linked page).

**Several pairs.** Numbers 1, 2, 6 and 9 concern the pair of key and signature, the others the content. If a page has several pairs, it passes each of these four numbers as long as one pair passes it and every earlier one of these numbers; it fails at one of them only when every pair has failed at it or at an earlier one, and then with the reason of the pair that got furthest; if several got equally far, with the reason that comes later in the registry order `page_reasons` (at number 1 therefore `key_other_role` over `key_not_established`). Every pair under an established key whose signature does not hold yields `ANCHOR_HISTORY_DEFECTIVE`, reason `signature`, even if the page is used. If several pairs of a used page pass all four numbers, the report (`keys`, `stated_by`, Section 10.10.2) uses the one with the smallest `server_key_id` (byte comparison).

Per class and reason the verifier reports one finding, with the number of pages and, for the foremost in input order, its position and its `server_ts` where readable. Key and signature come first because `server_key_id` and the signature lie outside `statement_jcs`: the verifier never interprets unestablished bytes, and an interpretation of damaged bytes can never decide the exit code. `page_rules` is a contradiction and not a defect, because the signature holds. `other_chain` has exit 1 because the auditor fetches the pages of both chains of a change of chain (heartbeat specification §9.7), and a mixed-up file is a statement about the audit environment, not about the package.

**Older pages.** A used page of the package that is not fresh (for instance from an archive) enters the roots (H6), the reconciliation (H5, H7, H10) and a statement `affiliated` (H12), never the coverage (H4), the completeness (H11) or a statement `not_affiliated` (H12). If the entry of its key carries `widerrufen_ab`, it is not used under number 9.

**H3 Issued after the request.** With R: if no page of the package is `used_fresh` and at least one page of the package has passed numbers 1 to 8, the verifier reports `ANCHOR_HISTORY_UNVERIFIED` once, reason `issued_before_request`, with the latest `server_ts` passed. Used older pages beside a fresh one yield no finding (note `archive_pages`).

**H4 Coverage.** Over the fresh used pages of the package (without R over all used pages of the package, then only for information) the union of the ranges I(P) is formed. It is `complete` if it contains all tree sizes from 0, `partial` if it is not empty and not `complete`, otherwise `none`. A gap is a contiguous range not covered, taken as wide as possible. With R and a gap the verifier reports `ANCHOR_HISTORY_UNVERIFIED` once, reason `pages_missing`, with the gap that starts at the smallest tree size. A union is required, not a path from page to page: pages from different fetches with shifted boundaries cover together. Reference values: [0, 501), [501, 1001) and [1001, ∞) are `complete`; [0, 501) and [1001, ∞) leave the gap [501, 1001); [400, 501) and [501, ∞) leave [0, 400); [0, 501) alone leaves [501, ∞); [0, 480), [0, 501) and [501, ∞) are `complete`.

**H5 Pages among themselves.** Compared are the used pages of one chain (the pages of the package among themselves, the linked pages of one chain among themselves), ordered by `server_ts` and then by the bytes of `statement_jcs`. For every pair in which A precedes B, every violation is a reason of `ANCHOR_HISTORY_CONTRADICTION`:

- (a) `root_time_differs`: the same root (`tree_size`, `merkle_root`, `recorded_as`) with a different `server_ts`, compared in whole milliseconds like every instant of this section; the server keeps the time at which it first recorded it.
- (b) `root_dropped`: a root of A whose `tree_size` lies in I(B) is missing from B.
- (c) `root_withheld`: a root of B whose `tree_size` lies in I(A) and whose `server_ts` lies before A.`server_ts` − W_h is missing from A.
- (d) `fork_dropped`: a fork finding of A whose `tree_size` lies in I(B) is missing from B, and B carries `forks_omitted = 0`.
- (e) `affiliation_narrowed`: at an instant t before A.`server_ts`, A states an affiliation and B does not. A period of A with `until = null` ends at A.`server_ts` for this comparison.
- (f) `affiliation_withheld`: at an instant t before A.`server_ts`, B states an affiliation, over a period with `recorded_ts` before A.`server_ts` − W_h and `merged = false`, and A does not. A merged period of B (`merged = true`) never gives this reason: merging also covers the time between the old periods, which no earlier page had to show (heartbeat specification §9.10, time reference 4). If A withheld a period that B shows only merged, this pair therefore does not reveal it.
- (g) `known_range_narrowed`: A and B name a value, and B.`known_since` lies after A.`known_since` and not after A.`server_ts`. If B names `null` or a time after A.`server_ts`, that is no reason: after a takeover the operator is not determined until its declaration, and while a declaration is open the binding journal does not determine the customers (heartbeat specification §9.10, time reference 2); B then withdraws no statement of A about the time up to A.`server_ts`.
- (h) `owner_keys_dropped`: a commitment from A.`owner_keys` is missing from B.`owner_keys`.
- (i) `succession_changed`: `predecessor` differs, or A names a `successor` and B another one or none.
- (j) `reference_decreases`: B.`reference_tree_size` is smaller than A.`reference_tree_size`.

For a linked pair (chain P of the package, linked chain L), both statements about the succession between P and L MUST name the same T if both are present: if L is the predecessor chain (`P.predecessor = {L, T}` on a used page of the package), every used page of L whose `successor` is not `null` must carry `successor = {P, T}`; if L is the successor chain (`P.successor = {L, T}`), every used page of L whose `predecessor` is not `null` must carry `predecessor = {P, T}`. Otherwise reason `succession_mismatch`. The comparison is per instant: so every honest change passes (a period that ended after the older page, a late entry after it, a widening merge under heartbeat specification §9.10), and every narrowing and every split view shows as soon as both pages reach the same run. If the vendor shows two auditors different pages and nobody brings both together, nothing shows: pages of the anchor history stand in no log and at no second place (Section 11.2). The verifier does not compare the bases of a period; another basis for the past removes no statement. Reference values (A with an open period, issued `01:02:00`, against B): B ends it after A was issued: no reason; B ends it before: `affiliation_narrowed`; B five seconds later without a period: `affiliation_narrowed` (split view); B adds an older period, entered after A: no reason; entered more than W_h before A: `affiliation_withheld`; B widens by merging: no reason; B moves `known_since` to a time after A.`known_since` and before A.`server_ts`: `known_range_narrowed`; to a time after A.`server_ts` or to `null`, for instance after a takeover: no reason.

**H6 History roots.** Over the used pages of the package the verifier forms, per pair (t, r) from `roots`, a **history root** with the set of its `recorded_as` and with e, the earliest `server_ts` of its recordings `countersigned` and `gap_witness`, or, if it is only reported, of its recordings `reported`; per pair (t, r) from `forks` it forms a fork finding. e is the earliest time because a root first recorded as a gap witness and later countersigned (heartbeat specification §9.2) has existed since its earliest recording. A reported recording sets e only for a root that is only reported, because the server did not accept its device signature as an anchor (heartbeat specification §9.2) and the verifier cannot check it. Linked pages supply no history roots of this package.

**H7 Reconciliation with the vendor log.** Only if the check of the log yielded usable days with a checked chain-day record for C (Section 7.4.10, steps L3 and L6):

- For every recording (t, r, `recorded_as`, s) on a used page of the package with `recorded_as` `countersigned` or `gap_witness` whose day d = day(s) is usable and whose record for (C, d) is checked, the record MUST contain a root with the same four values; a record `absent` contains none. Otherwise this recording does not count for its history root, neither for e nor for `recorded_as`; a history root with no remaining recording is no expected root (counted as `not_used_vendor_log`). The verifier then reports `ANCHOR_HISTORY_CONTRADICTION` once per day, reason `log_mismatch`.
- For every root (t, r, `recorded_as`, s) of a checked record `present` on a usable day and every fresh used page P of the package for which t lies in I(P) and P.`server_ts` ≥ s + W_h holds, P MUST list a root with the same t, r and `recorded_as`. Otherwise `ANCHOR_HISTORY_CONTRADICTION`, reason `log_root_missing`. For `countersigned` the comparison is without `server_ts`: a freshly issued repetition of a countersignature has a leaf of its own with its own `server_ts` in the log (Section 7.4.2), while the history keeps the time of the earliest recording. For `gap_witness` there is no repetition, since the server records at most one gap witness per root (heartbeat specification §9.2): if P lists the root as `gap_witness` with a `server_ts` other than s (compared as strings), that is a reason `gap_witness_time_differs`.
- If the checked records of chain C contain, on whichever usable days, two roots `gap_witness` with the same t and r and different `server_ts`, that is `ANCHOR_HISTORY_CONTRADICTION`, reason `gap_witness_time_differs`.

So it shows when a page and a supplied chain-day record contradict each other. Against vendor and customer acting together this works only if the auditor already holds the record of the witnessed day himself, for example archived from an earlier check. The vendor delivers the extract, and the verifier requires chain-day records only for the days of the receipts in the package (steps L7, L8 in Section 7.4.10). If a colluding vendor leaves out the records of the days after the last receipt of a truncated package, the verifier reports nothing (Section 11.2).

**H8 Classification** of the history roots: Section 8.8.5.

**H9 Fork findings and handover.**

- Every fork finding (t, r) on used pages of the package is `ANCHOR_HISTORY_FORK`, reason `fork_listed`, once per (t, r); the report says whether `root(t)` equals r, whether it equals a recorded root or whether t > N holds.
- If a used page of the package carries `forks_omitted` > 0: once `ANCHOR_HISTORY_FORK`, reason `forks_omitted`, with the number.
- If a used page of the package names `successor = {S, T}`: a history root with t > T whose `recorded_as` contains `countersigned` or `gap_witness` is `ANCHOR_HISTORY_FORK`, reason `root_beyond_handover` (heartbeat specification §9.7). A merely reported root beyond it yields the note `reported_beyond_handover`, N > T the note `package_beyond_handover`. Only these two kinds are a finding, because when entering a change the server checks only the reference size against T; reported roots beyond T occur with honest chains too.
- A linked page of the predecessor chain with `successor = {C, T}`: its roots with t > T and `recorded_as` `countersigned` or `gap_witness` are `ANCHOR_HISTORY_FORK`, reason `predecessor_beyond_handover`; reported ones yield the note `reported_beyond_handover`.
- Notes: `predecessor_differs_from_genesis` if `predecessor` of a used page of the package names a chain and `GENESIS.predecessor_chain` names none or another one (if the page names no `predecessor`, there is no note); `linked_history_not_supplied` if a used page of the package names a predecessor chain and no passed page with its `chain_id` has passed numbers 1 to 5 of H2 (only then is the `chain_id` of a page read from established bytes).

**H10 Receipts against the history.** For every `CHECKPOINT_RECEIPT` that counts as anchoring under Section 7.1, with `server_ts` s, the first case that applies holds:

1. s < BL: counted as `before_legacy_boundary`, no finding.
2. A used page of the package lists a root `countersigned` with the `tree_size` and `merkle_root` of the receipt: counted as `in_history`; if its `server_ts` differs from s (freshly issued repetition, heartbeat specification §9.1), additionally as `server_ts_differs`, no finding.
3. A used page P of the package for which the `tree_size` of the receipt lies in I(P) has P.`server_ts` ≥ s + W_h: the root is missing from a page issued after the receipt. If the receipt is established (above), the verifier reports `ANCHOR_HISTORY_CONTRADICTION` once, reason `receipt_not_in_history`, with the number and the smallest `seq`; otherwise it gives the note `receipt_roots_unverified_not_in_history` and counts them as `not_in_history_unestablished`.
4. Otherwise: counted as `not_covered`.

The finding has exit 1 because a restore at the vendor can lose countersignatures from its records; the chain remains honest. **Cut-off date.** Up to edition 1.9 this specification did not require the vendor to keep recorded roots durably; roots that a metadata server recorded before BL may therefore be missing from the history. BL is one value for all vendors in the registry (`2026-10-04T00:00:00.000Z`), never a member of the page, so that no vendor can choose it per chain.

**H11 Completeness from the history** (`anchor_history.completeness`). **Blocking reasons** are exactly these:

- (a) `page_rules` (H2, number 3 or 5) on a page whose signature holds and whose `statement_jcs` can be read as an I-JSON object (Section 2, duplicate member names refused) with the member `chain_id` = C. On a page whose `chain_id` cannot be read so or names another chain, `page_rules` does not block;
- (b) every reason from H5 between two used pages of the package, and `succession_mismatch`;
- (c) `log_mismatch`, `log_root_missing` and `gap_witness_time_differs` (H7) and `receipt_not_in_history` (H10);
- (d) every reason of `ANCHOR_HISTORY_FORK`: `fork_listed`, `forks_omitted`, `root_beyond_handover`, `predecessor_beyond_handover` (H9), `history_root_differs` and `reported_root_beyond_package` (Section 8.8.5).

Not blocking are the reasons from H5 between linked pages of another chain, `page_rules` on other pages, the reasons of `ANCHOR_HISTORY_UNVERIFIED` and `ANCHOR_HISTORY_DEFECTIVE` (they act through the coverage and through the used pages) and every note. The status is `established` exactly when all of the following hold: R is passed; the coverage (H4) is `complete`; no blocking reason exists; no `MERKLE_INCONSISTENT` comes from a history root (a pair that also carries the source `auditor` and whose finding arises under Section 10.8 counts for this too); at least one history root is found under the classification of Section 10.5, step 8 (Section 8.8.5). Then `up_to_tree_size` is the largest `tree_size` of a found history root, whenever it was recorded. Otherwise the status is `partial` if R is passed and a fresh used page of the package exists, else `not_established`; `up_to_tree_size` is then `null`, and the reason is the first in this order that applies:

| Reason | applies when |
|---|---|
| `not_supplied` | no anchor history is passed |
| `no_request_time` | R is absent |
| `no_usable_page` | no page has passed numbers 1 to 7 of H2 as a page of the package |
| `owner_differs` | at least one page of the package failed only at number 8 and no page of the package is used |
| `issued_before_request` | H3 reports the finding |
| `pages_missing` | H4 reports the finding |
| `contradiction` | a blocking reason under (a), (b) or (c) exists |
| `fork` | a blocking reason under (d) exists |
| `root_missing` | a `MERKLE_INCONSISTENT` comes from a history root |
| `no_root_found` | no history root is found |

Roots from the 15 minutes before R that the package lacks do not prevent the status (note `recent_roots_not_found`).

**H12 Affiliation:** Section 8.8.6.

**H13 Output.** The result stands in the report objects `anchor_history` and `affiliation` (Section 10.10), the found history roots additionally in `completeness.sources` (Section 8.6). For every package that is not a format error both objects are present, also without an anchor history (`not_supplied`, `not_checked`); with exit 3 they are `null`. The exit code follows Section 10.3 unchanged.

#### 8.8.5 Classification of the History Roots

Roots the auditor passes themselves (source `auditor`) keep the rules of Section 10.8. History roots (source `anchor_history`) are merged with them by (t, r), with all sources, so only with auditor roots of the form `<tree_size>:<merkle_root>`; an auditor root without `tree_size` stays an auditor root of its own; if a pair also carries the source `auditor`, Section 10.8 applies to its finding. Per (t, r) there is at most one finding. For every other history root (t, r) with e (step H6) the topmost case that applies holds; "recorded" means that its `recorded_as` contain `countersigned` or `gap_witness`, "only reported" that they contain only `reported`:

| Case | Result |
|---|---|
| t ≤ N, `root(t)` = r | found: counts as anchoring (no `NO_ANCHOR`, Section 10.8) and establishes completeness up to t (Section 8.6) |
| t ≤ N, `root(t)` ≠ r, recorded, R passed, e < R − W_h | `MERKLE_INCONSISTENT` (exit 2) |
| t ≤ N, `root(t)` ≠ r, otherwise (e ≥ R − W_h, without R or only reported) | `ANCHOR_HISTORY_FORK`, reason `history_root_differs` (exit 1) |
| t > N, recorded, R passed, e < R − W_h | `MERKLE_INCONSISTENT` (exit 2), note `package_ended_before_request` |
| t > N, only reported, R passed, e < R − W_h | `ANCHOR_HISTORY_FORK`, reason `reported_root_beyond_package` (exit 1) |
| t > N, R − W_h ≤ e < R | no finding; counted as `beyond_package_recent`, note `recent_roots_not_found` |
| t > N, e ≥ R | no finding; counted as `beyond_package_after_request` |
| t > N, without R | no finding; counted as `beyond_package_unjudged`, note `no_request_time` (independently of this note the report always states that R is absent, Section 8.8.1) |

With `MERKLE_INCONSISTENT` the report names t, r, e, R and, for t ≤ N, `root(t)`: the vendor recorded the root r for `tree_size` t at e, before the request at R, and the package contradicts it or ends before it. That is the finding the comparison by hand has given for exactly these roots since edition 1.9 (Section 8.6); the verifier adds the binding to the device (Section 8.8.4, step H2), the band of 15 minutes also within the package and the signed omission marker `forks_omitted`, and is thus stricter than the procedure by hand. A root that a dishonest vendor invents or that someone places on a page with a statements key would appear the same way; it is attributable to this key, and the verifier cannot recognise it as invented (Section 11.2).

The band also applies within the package: R is a time of the auditor, e one of the vendor, and within 15 minutes the verifier cannot tell before from after. A differing root that was recorded only after R − W_h is the vendor's record that the device signed another history for a size this package covers: an honest export before a later reset, or a rewrite in the residual window. The verifier reports it with exit 1 and never omits it.

The note `package_ended_before_request` names the latest `server_ts` of a receipt of the package (a time signed by the vendor) and the two explanations: an export made before the request, or a truncation at an earlier seal (Section 8.6, limit of proof of the seal). The finding remains exit 2 as in edition 1.9.

**Why roots that are only reported never yield exit 2.** The server records a reported root from the `last_checkpoint` of a heartbeat or from an anchor it does not accept (heartbeat specification §9.2). Its device signature stands on no page, and no day of the vendor log names it. Had a server taken it over from the message of another appliance that knows the `chain_id`, it would otherwise yield exit 2 against an honest package. From edition 1.10 the server records a reported root only from messages of the appliance the chain belongs to (heartbeat specification §9.2); the verifier cannot check that and therefore reports a contradiction from a root that is only reported with exit 1, never not at all.

Reference values (package `valid_sealed_export`, N = 32, its receipts at 15 and 28, R = `2026-01-01T00:58:00.000Z`, hence R − W_h = `2026-01-01T00:43:00.000Z`): a differing root at `tree_size` 20 with e = `00:42:59.999` is `MERKLE_INCONSISTENT`, at 21 with e = `00:43:00.000` `ANCHOR_HISTORY_FORK` (the boundary belongs to the band); beyond the package, 33 with e = `00:42:59.999` is `MERKLE_INCONSISTENT`, 34 with e = `00:43:00.000` `beyond_package_recent`, 35 with e = `00:58:00.000` `beyond_package_after_request`; 15 and 28 are found. Without R, 20 and 21 are `ANCHOR_HISTORY_FORK` and 33 to 35 `beyond_package_unjudged`.

#### 8.8.6 Affiliation over the Period of the Package

The verifier evaluates the vendor's statement on affiliation (heartbeat specification §9.10) as follows:

1. Without an anchor history: `not_checked`.
2. P is the set of used pages of the package (fresh, older or without R). If P is empty: `not_determined`, with the reason, first applicable in this fixed order, that a passed page reached: `history_owner_differs`, `history_key_not_established`, `history_key_not_valid`, `history_signing_time_not_proven`, `history_not_v2`, `history_defective`, `history_contradictory`, `history_other_chain` (in turn for the reasons `owner_differs`, `key_not_established` and `key_other_role`, `key_not_valid`, `signing_time_not_proven`, `not_v2`, `signature`, `page_rules` and `other_chain` of H2). If no passed page reached one of these reasons, for example because only pages of a linked chain are used, the reason is `history_no_package_page`.
3. H* is the page from P with the greatest (`server_ts`, bytes of `statement_jcs`); `as_of` is H*.`server_ts`.
4. **Periods** are all periods of all pages from P. The **end** of a period is its `until`; a period with `until = null` ends at the `server_ts` of its page, except on H*, where it continues and has no end. A period covers the instants t with `from` ≤ t < end (half-open).
5. **Period of the package**, only from times the vendor signed: `span_from` is the earliest `server_ts` among the established receipts (Section 8.8.4) and the recordings in `roots` of the pages from P; `span_to` is R if passed, otherwise `as_of`. If there is no such time, `span_from = span_to`. `ts_chained` or any other time the customer writes never counts.
6. `affiliated` exactly when a period overlaps the period of the package, that is `from` ≤ `span_to` holds and the period has no end under number 4 or its end lies after `span_from`. Output are the union of the bases of the overlapping periods and `vendor_itself` if `vendor` is among them.
7. Otherwise `not_affiliated` exactly when all three conditions hold: (a) either R is passed and H* is fresh, or R is absent and `as_of` is at least as late as the `server_ts` of every established receipt; (b) H*.`known_since` is not `null` and does not lie after `span_from`; (c) the coverage under H4 is `complete`. Otherwise `not_determined`, with the reason of the first condition that fails: `statement_does_not_cover_package` (a), `known_range_too_short` (b), `history_pages_missing` (c). Condition (c) prevents withholding early pages from pushing `span_from` past an affiliation that has ended.
8. Periods that do not overlap the period of the package the verifier outputs with `overlaps_package = false` ("outside the period of this package"). An affiliation that ended years before the chain thus never yields `affiliated` for this package.
9. `contradictory` is `true` if H5 yielded, between two pages of P, one of the reasons `affiliation_narrowed`, `affiliation_withheld` or `known_range_narrowed`; such a reason between pages of a linked chain does not set `contradictory` (number 11). The status then still comes from the union, that is from the wider statement.
10. Counted are `receipts_total` (established receipts), `receipts_in_periods` (those whose `server_ts` lies in a period, that is `from` ≤ `server_ts` < end under number 4, for a period without an end `from` ≤ `server_ts`) and `receipts_after_statement` (those whose `server_ts` lies after `as_of`).
11. For every linked chain the same steps apply with its used pages in place of P and the period from its own recordings: the package carries no receipts of this chain, so there are no established receipts for it (in numbers 5, 7 (a) and 10); `span_from` comes from the `roots` of its pages alone; condition 7 (c) reads the coverage under H4 over its own used pages (with R over the fresh ones); its counts under number 10 are 0. If `span_from` then lies after `span_to` (for instance for a successor chain whose recordings all lie after R), number 6 applies unchanged by its formula. The result stands under `linked` and never enters the status of the package.

The affiliation changes no exit code, no finding and not the number of the evidence level (Section 10.9); the report shows it. The verifier checks signature, form, binding to chain and device, freshness and the comparison with other pages passed, not the correctness of the statement (Section 11.2). If the history is missing or no page is used, the report says "not checked" or "not determined", never "not affiliated".

Reference values (period of the package `2026-01-01T00:30:01.000Z` to `00:58:00.000Z`, two established receipts, `known_since` `2025-12-01T00:00:00.000Z`, H* fresh where not stated otherwise): one open period `common_control`: `affiliated`, 2 of 2 receipts in the period; only one period `former_relation` from `2025-06-01` to `2025-12-01` (a relation that ended on `2023-12-01`, 24 months after it, clipped to the activation on `2025-06-01`; the server derives no further period from it, heartbeat specification §9.10): `not_affiliated`, one period outside; `known_since` `00:45`: `not_determined` (`known_range_too_short`); no fresh page: `not_determined` (`statement_does_not_cover_package`); no fresh page, issued `00:42:30` with `known_since` `00:42:00`: `not_determined` (`statement_does_not_cover_package`, freshness takes precedence; a later `known_since` would violate page rule 9); only one page with `since_tree_size` 20: `not_determined` (`history_pages_missing`); `known_since` `null` with an open period: `affiliated`; a period from `00:50`: `affiliated`, 1 of 2 receipts in the period; an open period from `2025-06-01` on an older page of `00:10`, next to H* of `01:02` without a period: the period ends at `00:10` and does not overlap the period of the package; `not_affiliated` with `contradictory` `true` (reason `affiliation_narrowed` from H5).

#### 8.8.7 Findings

All four classes have exit class 1 (Section 10.4).

| Finding class | Meaning (registry) | Reasons |
|---|---|---|
| `ANCHOR_HISTORY_UNVERIFIED` | anchor history supplied but not established for this package (key not established by an anchor of the auditor or not valid, other kind, other chain, other device, issued before the request or supplied incompletely) | `key_not_established`, `key_other_role`, `not_v2`, `key_not_valid`, `other_chain`, `owner_differs`, `signing_time_not_proven` (H2); `issued_before_request` (H3); `pages_missing` (H4) |
| `ANCHOR_HISTORY_DEFECTIVE` | the signature of a supplied anchor history page does not hold | `signature` (H2) |
| `ANCHOR_HISTORY_CONTRADICTION` | the vendor signed rule-breaking or contradicting statements on the anchor history of this chain (pages among themselves, receipts, vendor log) | `page_rules` (H2); `root_time_differs`, `root_dropped`, `root_withheld`, `fork_dropped`, `affiliation_narrowed`, `affiliation_withheld`, `known_range_narrowed`, `owner_keys_dropped`, `succession_changed`, `reference_decreases`, `succession_mismatch` (H5); `log_mismatch`, `log_root_missing`, `gap_witness_time_differs` (H7); `receipt_not_in_history` (H10) |
| `ANCHOR_HISTORY_FORK` | anchor history shows a second version of this chain or of its succession (fork finding, differing root, root beyond the handover) | `fork_listed`, `forks_omitted`, `root_beyond_handover`, `predecessor_beyond_handover` (H9); `history_root_differs`, `reported_root_beyond_package` (Section 8.8.5) |

| Situation | Class | Exit |
|---|---|---|
| grammar or limit of a file violated; `--requested-at` malformed, repeated or after `--now` or the system clock; `--vendor-key-list` not I-JSON or with an unknown `format`; a pin as a statements key malformed, contradictory or in two roles (Section 10.7.4); an embedded extract violates its grammar | none (unusable invocation, no report) | 3 |
| `--requested-at` after the check time from `verify_args.json` | `FORMAT_ERROR` | 3 |
| key not established or key of another role; other kind; key outside its window; other chain; other device; revoked key without a proven signing time; no fresh page; gap in the pages | `ANCHOR_HISTORY_UNVERIFIED` | 1 |
| signature does not hold | `ANCHOR_HISTORY_DEFECTIVE` | 1 |
| signed page violates the format; pages contradict each other (roots, fork findings, affiliation, known range, owner commitments, change of chain, reference size); receipt missing from a later page; history and log contradict each other | `ANCHOR_HISTORY_CONTRADICTION` | 1 |
| fork finding listed or omitted; differing root in the package, recorded in the band, after it or without R; root that is only reported and contradicts the package or lies beyond it before R − W_h; countersigned root or root recorded as a gap witness beyond the handover | `ANCHOR_HISTORY_FORK` | 1 |
| countersigned root or root recorded as a gap witness that contradicts the package or lies beyond it, recorded before R − W_h | `MERKLE_INCONSISTENT` | 2 |
| root beyond the package in the band; older pages; reported root beyond the handover; package beyond the handover; affiliation of any status | none (counted, note or status) | none |
| manifest field that claims an affiliation | `UNKNOWN_MANIFEST_FIELD` (Section 10.6, rule 5) | 1 |

**Multiple reports.** One finding per class and reason, with the number and the earliest occurrence; `MERKLE_INCONSISTENT`, `fork_listed`, `history_root_differs` and `reported_root_beyond_package` once per (t, r); `log_mismatch` once per day.

**Notes** (no finding, registry `verifier.anchor_history.notes`, in this order): `requested_at_unused` (R passed without an anchor history), `no_request_time`, `archive_pages`, `recent_roots_not_found`, `package_ended_before_request`, `reported_beyond_handover`, `package_beyond_handover`, `predecessor_differs_from_genesis`, `linked_history_not_supplied`, `receipt_roots_unverified_not_in_history`.

**Why none of the four classes has exit 2.** Every case can occur with an honest chain: a damaged fetch, an outage or data loss at the vendor, its misconduct, an error in the auditor's inputs, the takeover of a `chain_id`. "Invalid" is reserved for proven manipulation (Section 8.6). `ANCHOR_HISTORY_CONTRADICTION` and `ANCHOR_HISTORY_FORK` presuppose the signature of an established key; whoever controls only the transport path cannot produce them. Four classes instead of one, because the auditor's next step differs: correct the inputs or fetch missing pages; fetch again; confront the vendor; investigate the key holder's second history. From edition 1.10 a route to exit 2 leads from the anchor history, and it leads to an existing class: `MERKLE_INCONSISTENT` from a root the vendor countersigned or recorded as a gap witness more than 15 minutes before the request (Section 8.8.5). This route presupposes a page under a statements key (Section 8.8.3); a countersigning key alone does not open it. How vendor and customer can act together and what works against it is stated in Section 11.1 (class `collusion`).

## 9. Content Commitments and Time Plausibility

### 9.1 Content Commitments

The chain never carries request/response plaintext, only commitments:

```
commitment = Hex( HMAC-SHA-256( key = salt, message = plaintext bytes ) )
```

- `salt` is a **32-byte random value per object**, stored with the encrypted vault object (not in the chain).
- Purpose of the salt: protection against dictionary attacks. An unsalted hash of short, guessable prompts could be inverted by trial; with the salt, the commitment remains unusable to an attacker.
- Checking presented plaintexts: if the customer deliberately presents plaintext **and** salt to an auditor (layout: Section 10.1, "Presented plaintexts"), the verifier recomputes the HMAC and compares it with the chained commitment (`request_commitment`/`response_commitment`). A mismatch is the finding `CONTENT_MISMATCH` (exit 2). Without such presentation, no content check takes place; the chain remains content-tight. A presented file the verifier cannot check is `CONTENT_MISMATCH` as well: no presented file goes unchecked.
- After a `CONTENT_DELETED`, the vault object is gone; the commitment stays chained. The verifier reports `CONTENT_DELETED` (exit 1): chain intact, deletion declared.

### 9.2 mono_delta_ms Plausibility

`mono_delta_ms` comes from the monotonic clock and is immune to wall-clock manipulation. For every pair of consecutive entries `a`, `b` with `mono_delta_ms(b) ≥ 0`, let:

```
contradiction_ms = | ( ts_chained(b) − ts_chained(a) ) − mono_delta_ms(b) |
```

If `contradiction_ms > 300,000` (5 minutes) and `b` is not a `CLOCK_JUMP` entry declaring the jump (`jump_ms` explains the difference in sign and magnitude, tolerance 300,000 ms), this is the finding `CLOCK_ANOMALY` (exit 2). A declared jump is the finding `CLOCK_JUMP_NOTE` (exit 1). `mono_delta_ms = −1` (first entry after process start) does not take part in this check; there, RESTART/GAP coverage (Section 8) and the server time of receipts as an external time bracket apply instead.

### 9.3 Retention, Deletion and Legal Hold

Under this specification only **vault content** is deleted, never entries of the chain: a truncated or thinned-out chain would break the hash chain, `seq` and Merkle roots (`SEQ_BREAK`, `HASH_MISMATCH`, `MERKLE_INCONSISTENT`). Every deletion of content is chained as `CONTENT_DELETED` (Sections 4.17, 9.1); the commitment stays.

A **hold** (Section 4.24) is active from its `LEGAL_HOLD` with `action = set` until a `LEGAL_HOLD` with `action = release` and the same `hold_id` follows. A further `set` of an active `hold_id` replaces its scope; a `release` without an active hold of that `hold_id` has no effect. A hold covers an `AI_CALL` if its `ts_captured` lies between `scope_from` and `scope_to` (both bounds inclusive; compared as points in time, Section 2; the point in time counts, not the spelling: `…00Z` and `…00.000Z` are the same bound). A `release` SHOULD repeat the bounds of the hold it releases; they carry no meaning for verification.

Finding `HOLD_VIOLATION` (exit 1): a `CONTENT_DELETED` whose `target_seq` names an `AI_CALL` that, at the position of the `CONTENT_DELETED`, is covered by an active hold. Reported once per `CONTENT_DELETED` at its `seq`, with `target_seq` and every `hold_id` that covers the entry in the report. The exit class is deliberately 1, not 2: the deletion stands openly in the chain, nothing is concealed or falsified; there is no proof of manipulation of the chain (principle of Section 8.6). The finding proves that the operator broke a hold of its own; an auditor reads it like a hard finding about the operation.

## 10. Verification Package and Verifier

### 10.1 ZIP Layout

A verification package is a ZIP archive:

```
pruefpaket.zip
├── manifest.json           # mandatory, see 10.2
├── segments/               # mandatory: chain segments as JSON Lines
│   ├── 000001.jsonl
│   ├── 000002.jsonl
│   └── …
└── keys/                   # mandatory: public keys as hex text files
    ├── device/<key_id>.hex # 64 hex characters + optional trailing newline
    ├── vendor/<key_id>.hex
    ├── vendor/schluesselliste.json  # optional: signed list of countersigning keys (10.7.1)
    └── tsa/*.pem           # optional: time-stamping authority certificates (7.3)
```

- Each segment file contains entries as JSON Lines (one entry per line, `\n`-separated), in ascending `seq` order; segments do not overlap and together cover `seq = 1 … tree_size` of the manifest without gaps. Lines are split at `\n` (U+000A) only: `\r`, U+0085, U+2028 and U+2029 do not separate entries; the last three stand raw inside a JSON string (RFC 8785), and a `\r` before the `\n` is whitespace of the JSON text. `\n` at the end of the file (one or several) is passed over; every other line (an empty one or one of whitespace only included) MUST be an entry, otherwise `FORMAT_ERROR` (exit 3).
- The names of the entries in the ZIP are in normal form: path parts separated by `/`, no leading `/`, no empty path part, no path part `.` or `..`, no `\`, and no name occurs twice. Directory entries (name ends in `/`) are skipped. If `manifest.json` is not at the top level and all entries share exactly one top-level directory, that directory is stripped (a zipped directory); from edition 1.9 the same applies to a package presented as a directory that contains exactly one directory and nothing else. A package presented as a directory may contain only files and directories; a symbolic link or anything else (a named pipe, a device) is `FORMAT_ERROR`. A package violating these rules is a format error (`FORMAT_ERROR`, exit 3): two verifiers must not see different files in the same archive.
- Segment file names carry no evidentiary weight; the manifest's segment list (file, SHA-256, `first_seq`, `last_seq`) is authoritative. Explicitly from edition 1.9: `file` follows the grammar `^[A-Za-z0-9._-]{1,128}$`, is neither `.` nor `..` and is read only as `segments/<file>`, never elsewhere in the package and never outside it. The segments are read ordered by `first_seq`, whatever their order in the list; their declared ranges MUST start at 1 without gaps, must not overlap and MUST end at `tree_size` ≥ 1, and every file MUST hold exactly `last_seq − first_seq + 1` entries. Every violation is `FORMAT_ERROR` (exit 3), and the check ends there (Section 10.5). Whether the entries themselves are numbered without gaps is checked by Section 3 (`SEQ_BREAK`).
- `keys/` mirrors the manifest's keys (one file per `key_id`); in case of divergence the manifest prevails. The vendor keys from the manifest and `keys/vendor/` are **not evidentiary** (Section 7.1): they lead to `RECEIPT_UNVERIFIED` as long as no anchor of the auditor establishes them. `keys/vendor/schluesselliste.json` is optional and counts only if its signature holds against a vendor root of the auditor (Section 10.7.1); a role list never stands there (Section 10.7.2). `keys/tsa/` is optional and **not evidentiary** (Section 7.3): certificates from there lead to the finding `TIME_ANCHOR_UNVERIFIED`, because they come from the same hand as the chain. From edition 1.10 a verification package SHOULD NOT carry a certificate that an auditor would pass as a trust anchor; `keys/tsa/` remains a reading aid (Section 7.3).
- **Auditor inputs do not belong in the package (from edition 1.10).** Day entries, extracts and protocol key lists of the vendor log (Section 7.4), anchor history pages (Section 8.8), role lists (Section 10.7.2) and other key lists the auditor passes, a statement on affiliation, a naming of roots as qualified and a request time (Section 10.8) never stand in a verification package, and a verifier never reads them from it. Such a file outside `content/` remains disregarded as before (no finding); under `content/` it is `CONTENT_MISMATCH` like any other file not defined there. The package and its layout do not change with edition 1.10.
- Optionally, the package MAY contain presented reports (HTML/PDF) and deliberately disclosed plaintexts with salts; the verifier then additionally checks `REPORT_MISMATCH` and `CONTENT_MISMATCH`.
- **Presented plaintexts (defined from edition 1.9)** live under `content/`. The presentation for the `AI_CALL` with `seq` n consists of `content/<n>.salts.json` and `content/<n>.request` and/or `content/<n>.response`; `<n>` has the form `[1-9][0-9]*`. The plaintext files hold exactly the bytes of the HMAC message (Section 9.1). The salt file is I-JSON (Section 2) with exactly these members: `seq` (int, equal to n), `request_salt` and `response_salt` (hex64 each, present exactly when the matching plaintext file is present) and optionally `vault_ref` (string, not evaluated). For every presented part, entry n MUST be an `AI_CALL` with a non-null `<part>_commitment`, and the HMAC MUST match. Every other file under `content/` (another name, a file in a subdirectory, a plaintext without a salt, a salt without a plaintext, a non-conforming salt file) is `CONTENT_MISMATCH`, once per file. Beside a non-conforming salt file, every plaintext of the same n is `CONTENT_MISMATCH` as well: it cannot be checked. If a presented part does not meet the condition on entry n, its plaintext file is `CONTENT_MISMATCH`, the conforming salt file beside it is not. An empty directory yields nothing.

### 10.2 manifest.json

Fields (registry `pruefpaket_manifest`):

| Field | Type | Description |
|---|---|---|
| `spec_version` | version `"MAJOR.MINOR"` | specification version of the package; `MAJOR` and `MINOR` are decimal numbers without leading zeros; this edition writes `"1.10"` and accepts older minor versions of the same MAJOR; acceptance of other versions: Section 10.6 |
| `chain_id` | uuid | chain of this package |
| `created_ts` | rfc3339 | package creation time |
| `tree_size` | int, min 0 | number of entries contained |
| `segments` | array of object | per segment: `file` (string, maxlen 128), `sha256` (hex64), `first_seq` (int, min 1), `last_seq` (int, min 1) |
| `device_pubkeys` | array of object | per key: `key_id` (string, maxlen 64), `pubkey` (hex64) |
| `vendor_pubkeys` | array of object | per key: `key_id` (string, maxlen 64), `pubkey` (hex64) |

The verifier MUST check the SHA-256 sums of the segment files against the manifest; any deviation, as well as unreadable or schema-violating material, is `FORMAT_ERROR` (exit 3).

Edition 1.10 adds no field. A field that claims, for instance, an affiliation, a request time or a result of Sections 7.4 and 8.8 is an unknown field under Section 10.6, rule 5 (`UNKNOWN_MANIFEST_FIELD`); the verifier reads nothing from it.

### 10.3 Exit Codes

| Exit | Meaning |
|---|---|
| 0 | valid, no findings |
| 1 | valid with findings |
| 2 | invalid |
| 3 | format error |
| 4 | incomplete: chain end not sealed (Section 8.6) |

Determination: if the package is unreadable or schema-violating → **3**. Otherwise: at least one finding of exit class 2 → **2**; otherwise at least one finding of exit class 4 → **4**; otherwise at least one finding of exit class 1 → **1**; otherwise → **0**. What counts is this order of precedence (3 before 2 before 4 before 1 before 0, registry `verifier.exit_precedence`), not the size of the number. The semantics are strictly separated: "cryptographically valid yes/no" (0/1/4 vs. 2/3), the status of the chain end (0/1 sealed, 4 incomplete) and the list of findings. Exit 4 is not a failure: the checked entries are intact; only their completeness is not proven by the package. If a verifier also emits its verdict in machine-readable form, it MUST report exit 4 as a status of its own and MUST NOT mark it as "invalid"; a tool that reads only a yes/no flag would otherwise reject every honest chain taken during operation. An honestly declared gap does not invalidate the chain; a concealed one does.

The evidence level (Section 10.9) and the other report data (Section 10.10) are no part of the verdict and do not change the exit code.

### 10.4 Finding Classes

Complete list (registry `verifier.finding_classes`); a verifier MUST be able to report every class:

| Finding class | Exit | Meaning |
|---|---|---|
| `SEQ_BREAK` | 2 | sequence gap or jump |
| `HASH_MISMATCH` | 2 | hash chain broken |
| `SIG_INVALID` | 2 | checkpoint signature invalid |
| `MERKLE_INCONSISTENT` | 2 | Merkle consistency between anchored roots violated |
| `RECEIPT_INVALID` | 2 | vendor countersignature invalid |
| `TIME_ANCHOR_INVALID` | 2 | time witness contradicts the checkpoint or is forged |
| `FORK_DETECTED` | 2 | receipt matches no prefix history |
| `CLOCK_ANOMALY` | 2 | time contradiction without a chained CLOCK_JUMP |
| `CONCEALED_SILENCE` | 2 | mid-chain silence without covering GAP/RESTART |
| `HANDOVER_BROKEN` | 2 | SEAL/RESUME handover broken |
| `MISSING_CHECKPOINT` | 2 | critical entry without an immediately following checkpoint |
| `CONTENT_MISMATCH` | 2 | presented plaintext contradicts commitment |
| `REPORT_MISMATCH` | 2 | presented report not in the chain |
| `UNSEALED_END` | 4 | chain ends without a seal: incomplete (Section 8.6) |
| `COVERED_GAP` | 1 | declared gap (GAP) |
| `COVERED_SOURCE_GAP` | 1 | declared source gap |
| `RECONCILIATION_DELTA` | 1 | reconciliation delta against provider figures |
| `CONTENT_DELETED` | 1 | content deleted per retention, chain intact |
| `HOLD_VIOLATION` | 1 | content deleted despite an active deletion hold (Section 9.3) |
| `CLOCK_JUMP_NOTE` | 1 | declared clock jump |
| `TRAILING_SILENCE` | 1 | chain ends before the freshness window |
| `NO_ANCHOR` | 1 | no external anchor present |
| `TIME_ANCHOR_UNVERIFIED` | 1 | time witness present, its authority not independently established |
| `RECEIPT_UNVERIFIED` | 1 | vendor countersignature consistent, but its key is not established by a trust anchor of the auditor |
| `VENDOR_LOG_UNVERIFIED` | 1 | vendor log supplied but not established by the auditor's anchors, or not supplied completely |
| `VENDOR_LOG_DEFECTIVE` | 1 | supplied vendor log material does not hold (signature, time stamp or proof) |
| `VENDOR_LOG_CONTRADICTION` | 1 | the vendor signed contradicting or rule-breaking log statements |
| `RECEIPT_NOT_LOGGED` | 1 | receipt missing from the witnessed vendor log of its day |
| `LOGGED_ROOT_MISMATCH` | 1 | root recorded in the vendor log does not match the package |
| `ANCHOR_HISTORY_UNVERIFIED` | 1 | anchor history supplied but not established for this package (key not established by an anchor of the auditor or not valid, other kind, other chain, other device, issued before the request or supplied incompletely) |
| `ANCHOR_HISTORY_DEFECTIVE` | 1 | the signature of a supplied anchor history page does not hold |
| `ANCHOR_HISTORY_CONTRADICTION` | 1 | the vendor signed rule-breaking or contradicting statements on the anchor history of this chain (pages among themselves, receipts, vendor log) |
| `ANCHOR_HISTORY_FORK` | 1 | anchor history shows a second version of this chain or of its succession (fork finding, differing root, root beyond the handover) |
| `SPEC_NEWER` | 1 | package uses a newer minor version of the specification than the verifier |
| `UNKNOWN_ENTRY_TYPE` | 1 | entry type unknown to this verifier version; entry checked, payload not |
| `UNKNOWN_MANIFEST_FIELD` | 1 | manifest field unknown to this verifier version; accepted and reported, all known checks still run |
| `FORMAT_ERROR` | 3 | package unreadable / violates schema |

Edition 1.10 adds nine classes, five of the vendor log (Section 7.4.11) and four of the anchor history (Section 8.8.7); the list thus comprises 37 classes. All nine have exit class 1, because each of their cases can occur with an honest chain; no name ends in `_INVALID`, since every class with this ending has exit class 2. A case that leads to exit 2 through an auditor input from edition 1.10 belongs to an existing class: `MERKLE_INCONSISTENT` from a root of the anchor history (Section 8.8.5). The key roles (Section 10.7.4), the fillers (Section 7.4.4), condition (7) of the evidence level (Section 10.9.1) and the entry type `DATA_ACCESS` (Section 4.25) add no class.

### 10.5 Verification Procedure (Normative Minimum Checks)

A conformant verifier performs at least: (1) package/schema checks including segment hashes, applying the forward-compatibility acceptance rules (Section 10.6); (2) `seq` gaplessness and hash chain (`prev_hash`/`entry_hash` with its own JCS canonicalization); (3) checkpoint signatures including the KEY_ROTATION trust chain and checkpoint chaining; (4) recomputation of all checkpoint Merkle roots; pairwise consistency of all anchored roots; (5) receipts: origin of the vendor key and countersignature per Section 7.1, from edition 1.10 with the role check per Section 10.7.4, match against the checkpoint, prefix match (fork); (6) gap semantics per Section 8; (7) time plausibility per Section 9.2; (8) SEAL/RESUME handover and chain end (Sections 8.4, 8.6); (9) optionally presented plaintexts and reports; deletion holds (Section 9.3); (10) freshness window; (11) time witnesses per Section 7.3, where present, from edition 1.10 under the time-stamp profile (Section 7.5); (12) measure and state the residual window (Section 11.2); from edition 1.10 in addition (13) measure and state covered stretches (Section 11.2); (14) the vendor log per Section 7.4, where supplied; (15) the anchor history and the affiliation per Section 8.8, where supplied; (16) determine and state the evidence level (Section 10.9).

**Processing stages (from edition 1.9).** The package is read in this order: (1) `manifest.json` as I-JSON, signals under rules 1 and 5 (Section 10.6), then its schema; (2) the segment table (Section 10.1); (3) per segment in `first_seq` order: file present, SHA-256, number of lines (for all segments before stage 4 reads a line); (4) per line: JSON; if it is an object, the signals under rules 1 and 2 from `spec_version` and `event_type` (where they are strings), then its schema and its `chain_id`, continuing with the remaining lines; (4a) the vendor key list and the salt files `content/<n>.salts.json` (only names of this form) against the number rule of Section 2, at most one `FORMAT_ERROR` per file; (5) the checks of the chain, the presented plaintexts among them. If one of stages 1 to 3 fails, all later ones are dropped. Signals are reported for every object read up to then, also beside its schema error (rule 3), but never from a missing segment or one with a wrong SHA-256. If stage 4 fails on a line, the remaining lines continue; stage 5 is dropped; if stage 4a fails, stage 5 is dropped as well.

**Order within stage 5 (from edition 1.10).** The verifier reads the auditor inputs of Section 10.8 at invocation, before stage 1 (Sections 7.4.10, step L0; 8.8.4, step H0). Both reference verifiers perform stage 5 in this order, since later steps read results of earlier ones:

1. request time against the check time from `verify_args.json`, if the auditor asked for it (Section 10.8); if R lies after it, that is `FORMAT_ERROR` (exit 3), and the remaining steps of stage 5 are dropped (against a check time from `--now` or the system clock the same case is an unusable invocation, Section 10.8);
2. `seq`, hash chain and the roots of all prefixes (Sections 3, 5);
3. checkpoints (Section 6); in doing so the verifier records the device keys of the chain (`GENESIS.device_pubkey` and every key from `KEY_ROTATION` legitimized under Section 6.4);
4. keys of the vendor: the list of the package, the lists of the auditor, role check, K_cs and protocol keys (Sections 7.1, 7.4.10 step L1, 8.8.3, 10.7.4); role check and step L1 run only here, with or without an extract, step L1 as soon as a protocol key list or a pin of a protocol key is supplied;
5. receipts (Section 7.1), per receipt with the origin of its key, the origin of the list and the comparison with the device keys;
6. vendor log (Section 7.4.10, steps L2 to L9);
7. anchor history, steps H1 to H7 (Section 8.8.4);
8. comparison of the expected roots: roots of the auditor and history roots with their sources; here the verifier computes the classification under Section 8.8.5 (step H8) that step 11 reads (Sections 8.8.5, 10.8);
9. residual window and covered stretches (Section 11.2);
10. time witnesses (Sections 7.3, 7.5), per token and per root with the data the evidence level reads (Section 10.9);
11. anchor history, steps H9 to H11, with the classification from step 8;
12. presence of an anchor (`NO_ANCHOR`, Section 7; found history roots count too);
13. findings of the expected roots, with the findings of the classification under Section 8.8.5 (step H8) computed in step 8;
14. the remaining checks in the previous order, from the findings on single entries through deletion holds, silence, clock, immediate checkpoints, handover, chain end and freshness to presented plaintexts and reports;
15. conclusion: first the exit code under Section 10.3, then the affiliation (Section 8.8.6), the report objects (Section 10.10) and the evidence level (Section 10.9), which no longer change the exit code.

The comparison of the expected roots (step 8) thus stands after the checkpoints and receipts, no longer before them. This changes no result: the expected roots are read only for the completeness from the anchor history (step 11), for the presence of an anchor (step 12), for their findings (step 13) and for the statement on completeness (Section 8.6), and all four come after step 8.

### 10.6 Forward compatibility

The model is the rule for unknown anchor types (from edition 1.10 Section 7.6): what a verifier does not know is a finding, not an error (with a deliberately drawn boundary at the envelope).

**Rule 1: Version acceptance.** `spec_version` has the form `"MAJOR.MINOR"` (type `version`, Section 2). A verifier implementing version `1.m` MUST accept entries and manifests with `spec_version = "1.n"`. For `n ≤ m` the normal case applies, without a special finding. For `n > m` it MUST report the finding `SPEC_NEWER` (exit class 1) exactly ONCE per verification package and MUST continue to perform ALL checks it knows, in particular the minimum checks of Section 10.5. A `spec_version` whose `MAJOR` differs from the verifier's is `FORMAT_ERROR` (exit 3); so is a `spec_version` that does not have the form of Section 2 (for instance with leading zeros). `MINOR` is compared as a whole number, with no upper bound on its number of digits.

**Rule 2: Unknown entry types.** An `event_type` the verifier does not know (type `open_enum`, Section 2) is NOT a schema error. The verifier MUST report the finding `UNKNOWN_ENTRY_TYPE` (exit class 1), once per unknown type name, with the `seq` of its first occurrence. It MUST include the entry in the `seq`, hash-chain and Merkle checks (these do not depend on the type), MUST check `payload` only for being a JSON object, and MUST NOT treat the type as critical (immediate-checkpoint obligation, Sections 4 and 6). This is the conservative direction, and it is to be understood as such: a future critical type is NOT checked for its immediate checkpoint by an older verifier; a missing checkpoint after an unknown type is no `MISSING_CHECKPOINT` for that verifier. For the silence rules (Sections 8.1, 8.2) an unknown type is not a covering `GAP` or `RESTART`; like every entry it merely bounds the silence window per Section 8.2.

**Rule 3: The envelope stays closed.** An envelope field that Section 3 does not define remains `FORMAT_ERROR` (exit 3): the envelope is the contract; a new envelope field is a `MAJOR` change. The `payload` fields of KNOWN entry types remain strict per Section 2 (completeness, no undefined fields); the evidence-package manifest, by contrast, is governed by rule 5. Findings under rules 1, 2 and 5 are reported even when the same object also carries a schema error (`FORMAT_ERROR`); the exit code follows Section 10.3. A MINOR version MAY narrow the value range of an existing `payload` field if every value of the narrower range is also valid under the older schema; the narrowing applies to entries whose own `spec_version` is that MINOR version or a newer one, and an older verifier accepts them without the narrowing (from edition 1.8: `GENESIS.license_id`, Section 4.1).

**Rule 4: Anchor types.** For unknown anchor types, Section 7.6 applies from edition 1.10.

**Rule 5: The evidence-package manifest is extensible.** A field in `manifest.json` that Section 10.2 does not define is NOT a schema error. The verifier MUST report the finding `UNKNOWN_MANIFEST_FIELD` (exit class 1), once per unknown field path, with the path in `detail`, and MUST continue to run ALL checks it knows, in particular the minimum checks of Section 10.5. This holds for the manifest object itself AND for the objects inside its `segments`, `device_pubkeys` and `vendor_pubkeys` fields; field paths are reported without an index (`manifest.segments[].field`), so one extra field across a hundred segments yields one finding, not a hundred. The DEFINED fields remain mandatory and strict as before: a defined field that is missing, of the wrong type, or outside its value range remains `FORMAT_ERROR` (exit 3). The finding applies independently of `spec_version`: a manifest that declares the verifier's own version but carries a field unknown to it is likewise accepted and reported; a producer adding a field without a version bump violates this specification, and the verifier does not rely on it refraining.

The difference from rule 3 is not convenience but burden of proof. The manifest enters **no** hash chain, no Merkle root and no signature; an extra field there cannot change any cryptographic check. An extra envelope field, by contrast, changes the JCS bytes and therefore `entry_hash`, which is why the envelope stays closed and is a `MAJOR` question. And the finding is the price of acceptance: a verifier that does not know a manifest field cannot know whether it narrows its own check; a future field might mark a package as an excerpt. The field is therefore not passed over silently: the auditor learns that the package carries a statement this tool does not read, and can fetch a newer build. Without the finding, the rule would be an invitation to false green.

**Auditor inputs (from edition 1.10).** From edition 1.10 new subjects of verification come as auditor inputs (Section 10.8), not in the package. A verifier from edition 1.10 that does not know an input rejects the invocation, on the command line as in the browser edition; it never assesses the package differently (Section 10.8). Package, manifest and list of countersigning keys have the same formats as in edition 1.9 (Sections 10.1, 10.2, 10.7.1), and the chain knows one more entry type, `DATA_ACCESS` (Section 4.25), which only an access chain of a vendor writes: a verifier of edition 1.9 assesses every package of edition 1.10 as before, an entry `DATA_ACCESS` yields `UNKNOWN_ENTRY_TYPE` once with it (rule 2), and a package that declares `spec_version` `"1.10"` receives `SPEC_NEWER` from it (rule 1). It does not know the inputs of Sections 7.4 and 8.8, the role list, pins as statements keys or the new roots for time stamps. The Go verifier of edition 1.9 rejects an unknown flag as an unusable invocation (exit 3); the second verifier of edition 1.9 then exits with code 2 of its command-line parsing, which looks like "invalid" but says nothing about the package, and this can no longer be changed in the published version. The Go verifier of edition 1.9 knows the flag `--tsa-root` only once: if an invocation repeats it, it accepts it without a word and reads only the last file, and it passes over blocks that are not a certificate; a time witness under a root from an earlier file then yields `TIME_ANCHOR_UNVERIFIED` instead of no finding. The browser edition 1.9 passes over options it does not know without a word and judges the package without them, with verdict and report; `tsaRootsPem` as a list instead of a single `Uint8Array` aborts it. For verifiers of edition 1.9 the sentence on rejecting unknown inputs therefore does not hold. From edition 1.10 a verifier MUST answer every usage error with exit 3, the browser edition with an error message instead of a verdict, also an unknown option name (Section 10.8). Whoever passes one of the new inputs or repeats `--tsa-root` MUST use a verifier from edition 1.10; a tool or a page that passes them MUST query its version first (command line: `--version`; browser edition: `ledgerVerifyVersion`).

A later kind of anchor history is, for a verifier of edition 1.10, a page with the reason `not_v2` (Section 8.8.4), and a later format of an auditor file is an unusable invocation: it reads none of them other than as intended. What can change from edition 1.10 in the assessment of an unchanged package comes from the time-stamp profile (Section 7.5), not from the new inputs: peculiarities of a certificate and a token without certificates lead at most to `TIME_ANCHOR_UNVERIFIED` (Section 7.3, step 5a), a `token_base64` with a line break, an envelope that does not follow strict DER (for example BER lengths or a `genTime` with a trailing zero, grammar T in Section 7.5.2) and a CMS signature that does not hold lead to `TIME_ANCHOR_INVALID`, and a time witness that only the system root store confirmed leads to `TIME_ANCHOR_UNVERIFIED` (Section 7.5.7). Two verifiers that could so far judge the same token differently judge it alike from edition 1.10.

The registry mirrors these rules: `envelope_fields.spec_version` and `pruefpaket_manifest.spec_version` carry the type `version`; `envelope_fields.event_type` carries the type `open_enum` with `unknown_finding = "UNKNOWN_ENTRY_TYPE"`; `pruefpaket_manifest` carries `unknown_field_finding = "UNKNOWN_MANIFEST_FIELD"`. The test vectors `format_newer_minor`, `format_unknown_event_type` and `format_unknown_manifest_field` (registry `testvectors.format`) fix the expected behaviour.

### 10.7 Vendor Key Lists

The vendor keeps three key lists that its root signs: the list of countersigning keys (Section 10.7.1), the role list (Section 10.7.2) and the protocol key list (Section 7.4.7). Each carries its own `format`, and a reader checks `format` first; the root signs nothing else. That no entry of these lists names the public key of the root is a rule for the vendor (heartbeat specification §9.11 item 1); the verifier checks it only on the role list (Section 10.7.2), not on the list of countersigning keys and not on the protocol key list. Which role signs which object is given in Section 10.7.3, how the verifier checks the roles in Section 10.7.4, and how a vendor passes from operation with one key to separate roles in Section 10.7.5.

The vendor root the auditor supplies has the form `{"wurzel_id": …, "pubkey": …}` with exactly these two fields. It NEVER comes from the verification package: a root from the same hand as the list would only prove that the list agrees with itself.

#### 10.7.1 List of Countersigning Keys

The list of the vendor's countersigning keys (up to edition 1.9 "vendor key list"; that name remains valid), where present, lies at `keys/vendor/schluesselliste.json` (registry `vendor_key_list`). It is a JSON object in UTF-8 without a byte order mark, without duplicate member names and with no fields other than these:

| Field | Type | Description |
|---|---|---|
| `format` | const `"rekorder-herstellerschluessel/1"` | format identifier; any other makes the list ineffective |
| `version` | int, 1 … 2^53−1 | assigned by the vendor, strictly increasing; whether a newer one exists, the verifier cannot tell (7.1) |
| `ausgestellt` | rfc3339 | time of issue |
| `schluessel` | array, 1 … 64 objects | per key: `key_id`, `pubkey`, `gueltig_ab`, optionally `gueltig_bis` and `widerrufen_ab`; all values strings |
| `signatur` | object | exactly `wurzel_id` and `sig` (hex128) |

- `key_id` and `wurzel_id` follow the grammar `^[A-Za-z0-9._-]{1,64}$`; `pubkey` is hex64 (lower case). A `key_id` and a `pubkey` may each occur only once.
- `gueltig_ab`, `gueltig_bis`, `widerrufen_ab` and `ausgestellt` are of type `rfc3339` (Section 2) and are read, like `server_ts` when compared with them, with this grammar: `YYYY-MM-DDThh:mm:ss` with the ASCII digits `0` to `9`, optionally a dot with fractional seconds of any length, then `Z`; year `0001` to `9999`; the date must exist, second `60` does not. Fractions beyond the ninth digit are truncated; comparison is to the nanosecond. `gueltig_bis` MUST lie after `gueltig_ab`. Times are compared as instants, not as strings.
- A key is valid at a time `t` if `gueltig_ab` ≤ `t`, and `t` < `gueltig_bis` and `t` < `widerrufen_ab` where present. Several keys may be valid at the same time: that is how a rotation overlaps.
- The signature is Ed25519 by the root key named in `signatur.wurzel_id` over the JCS canonicalization (Section 2) of the list object **without** the member `signatur`. Formatting and member order of the file do not matter.
- A list that violates any of these rules, or whose signature does not hold against a root of the auditor with the same `wurzel_id`, is **ineffective**: it establishes no key and is not a finding itself (Section 7.1).

From edition 1.10 the list names only keys of the role `countersigning` (Section 10.7.3); the vendor never includes a key of another role. Format and reading rules remain, so that verifiers and appliances of edition 1.9 keep reading it: they reject every other member, and a list with a member for roles would be ineffective for them, so that every receipt whose key the auditor does not pin would yield `RECEIPT_UNVERIFIED`. The list is the projection of the role list onto the role `countersigning` (Section 10.7.2).

**Passing by the auditor (from edition 1.10).** Format and reading rules of the list remain unchanged, as does its place in the package. The auditor MAY also pass a list of this format himself (Section 10.8), for instance the current one he fetched from the vendor. Such a list establishes neither a receipt (Section 7.1) nor a page of the anchor history (Section 8.8.3); its keys belong to K_cs^L, the set against which the verifier checks the roles (Section 10.7.4; Section 7.4.10, step L1). Whether it is effective is decided by this section as for the list in the package; a list that does not hold is ineffective and no finding, and the report names the reason.

**Roles.** The keys of the list sign receipts and, until the end of dual operation (Section 10.7.5), the wrapper of license statements, refusal statements and activation receipts and anchor history pages of kind v1 (heartbeat specification §9, §9.11); never a page of kind v2, never the update manifest and never a day entry of the vendor log. Sections 7.4.1 and 10.7.3 show the roles of all keys of the vendor. The protocol keys stand in the protocol key list (Section 7.4.7), which a reader of this list never accepts. The same public key in two roles makes the list concerned ineffective (Section 10.7.4; Section 7.4.10, step L1); a pin of one role that equals a pin of another role in `key_id` or public key is an unusable invocation (Section 10.7.4). Day entries under a protocol key with an end of validity count only with a confirmed time stamp before this end (Section 7.4.10, step L2).

#### 10.7.2 Role List `ledger-schluesselrollen/1`

The role list names every key with which the vendor signs in running operation, with exactly one role (Section 10.7.3), except the protocol keys; those are named by the protocol key list (Section 7.4.7). The vendor root signs it. It never establishes a receipt (Section 7.1). It is an auditor file (Section 2) with exactly these members:

| Member | Type | Rule |
|---|---|---|
| `format` | const `"ledger-schluesselrollen/1"` | format identifier; any other makes the list ineffective |
| `version` | int, 1 … 2^53−1 | assigned by the vendor, strictly increasing; a new version carries forward every entry of earlier versions with the same `key_id`, the same `pubkey` and the same `rolle`; it may add to or shorten its validity data |
| `ausgestellt` | rfc3339 | time of issue, read with the grammar of Section 10.7.1 |
| `ende_doppelbetrieb` | rfc3339, optional | end of dual operation (Section 10.7.5): from this instant keys of the role `countersigning` sign only receipts; once present, every later version carries the same value |
| `schluessel` | array, 1 … 256 objects | per key exactly `key_id`, `pubkey` (hex64), `rolle`, `gueltig_ab` and optionally `gueltig_bis` and `widerrufen_ab`; all values strings; a `key_id` and a `pubkey` may each occur only once; `gueltig_bis` lies after `gueltig_ab` |
| `signatur` | object | exactly `wurzel_id` (key-id) and `sig` (hex128) |

- **`rolle`** follows the grammar `^[a-z][a-z_]{0,31}$`. Known roles are `countersigning`, `statements` and `update_manifest`. `protocol` is reserved: an entry with this role makes the list ineffective, since protocol keys stand only in the protocol key list. An entry with another, unknown role establishes nothing, but counts for uniqueness and in the role check (note `unknown_role`, Section 10.7.4). New members at the top level require a new `format`.
- For `key_id`, `pubkey`, the time values and validity at an instant the rules of Section 10.7.1 apply. The number rule of Section 2 applies; there are no other members at any level.
- **Signature:** what is signed is the JCS form of the list object **without** the member `signatur`, with the canonical member order `ausgestellt, ende_doppelbetrieb, format, schluessel, version` and in every entry `gueltig_ab, gueltig_bis, key_id, pubkey, rolle, widerrufen_ab`, with Ed25519 by the vendor root named in `signatur.wurzel_id`. This root comes from the auditor or is built in and named (Section 7.1), never from a package or an extract. If an entry names the public key of the root against which the signature is checked, the list is ineffective (reason `format`, Section 10.7.4).
- **Effective** is the list only if every rule holds and the signature holds against a root with this `wurzel_id`; which list applies among several and whether a role contradicts is decided by Section 10.7.4. An ineffective list establishes no key and is not a finding itself; the report names the reason (`key_roles`, Section 10.10.2).
- **Never in the package:** the role list never stands in a verification package and never at `keys/vendor/schluesselliste.json`; there it would make the list of countersigning keys ineffective, and every receipt whose key the auditor does not pin would yield `RECEIPT_UNVERIFIED`. The auditor passes it with `--vendor-key-list` (Section 10.8).
- **Projection:** the list of countersigning keys of the same signing procedure names exactly the entries of the role `countersigning`, with `key_id`, `pubkey`, `gueltig_ab`, `gueltig_bis` and `widerrufen_ab` equal character for character. This is a rule for the vendor (heartbeat specification §9.11); the verifier does not check it.
- **Standby:** in every role list the vendor MUST name, beside the active statements key, a standby statements key whose private part is kept offline (heartbeat specification §9.11); the verifier does not check this.
- **Publication:** at the places of publication of the protocol key list (Section 7.4.7, heartbeat specification §9.9) and with every installation and every update bundle.

Reference values (test keys of the corpus, seed in each case SHA-256 of the ASCII bytes `REKORDER-TESTVECTOR-KEY:` followed by the name): statements key `vendor-statements-test-001` (name `vendor-statements-1`) `6122df9ab7a7a83ecd7540b4d66cef184bd08aba2cac06123337b8ab3e56c9c2`; standby statements key `vendor-statements-test-002` (name `vendor-statements-2`) `0281ea7e6995a65287fb8b49092636b24cb645eb2a54bd1975a94f1597cc0ef5`; update manifest key `vendor-update-manifest-test-001` (name `vendor-update-manifest-1`) `8796764cebba035507d86bbf2ebf308738417b88f1bdab4f465484569c838f28`. The entries of the role `countersigning` of version 1 are the projection of the list of version 1 of the test corpus (test vector `valid_vendor_list`). Signed bytes of version 1 (one line, 1221 bytes, SHA-256 `0faf73e6f479e1c54d1f95933cbe81c18208b2963d007ee51fc6812d02fa6552`; signature of the root `testwurzel-1`: `9d478d23691ef3ab633d278292a52acf0b2ab8b1c69be6c826825cc824d6b630e079afab31c6afb4f5a5cb5063e1754347842429ab4c80123583c2912387940e`):

```
{"ausgestellt":"2025-12-30T10:00:00.000Z","format":"ledger-schluesselrollen/1","schluessel":[{"gueltig_ab":"2025-01-01T00:00:00Z","key_id":"vendor-test-001","pubkey":"959c448da9b35ea50abeca1f0a4cac57fc21c5b7ff7216d3e304bb5fc406d36c","rolle":"countersigning"},{"gueltig_ab":"2025-06-01T00:00:00Z","gueltig_bis":"2027-01-01T00:00:00Z","key_id":"vendor-test-002","pubkey":"73edaed42d761a1ab4fcc9be71a95b957542e89be13fa185e6ad1264ddc8b816","rolle":"countersigning"},{"gueltig_ab":"2025-01-01T00:00:00Z","key_id":"vendor-test-003","pubkey":"cc2edbd00b1893b5ead99b913212db9b733243c0b177dee34f7be1e9fe7cc3b2","rolle":"countersigning","widerrufen_ab":"2025-12-15T00:00:00Z"},{"gueltig_ab":"2025-12-30T00:00:00.000Z","key_id":"vendor-statements-test-001","pubkey":"6122df9ab7a7a83ecd7540b4d66cef184bd08aba2cac06123337b8ab3e56c9c2","rolle":"statements"},{"gueltig_ab":"2025-12-30T00:00:00.000Z","key_id":"vendor-statements-test-002","pubkey":"0281ea7e6995a65287fb8b49092636b24cb645eb2a54bd1975a94f1597cc0ef5","rolle":"statements"},{"gueltig_ab":"2025-12-30T00:00:00.000Z","key_id":"vendor-update-manifest-test-001","pubkey":"8796764cebba035507d86bbf2ebf308738417b88f1bdab4f465484569c838f28","rolle":"update_manifest"}],"version":1}
```

#### 10.7.3 Roles and Signed Subjects

Every key of the vendor has exactly one role, for its whole lifetime; `key_id` and `pubkey` occur, across all versions of all three lists, in exactly one role (heartbeat specification §9.11). Signing is always with Ed25519 (RFC 8032, without prehash and without context):

| Object | Signed subject | Role | until the end of dual operation (Section 10.7.5) |
|---|---|---|---|
| receipt (Section 7.1, heartbeat specification §9.1) | `UTF-8(JCS({chain_id, merkle_root, server_ts, tree_size}))`, exactly these four members, without `kind` | `countersigning` | `countersigning` |
| license statement `ledger.license_statement.v1`, refusal statement `ledger.anchor_refusal.v1`, activation receipt `ledger.activation_receipt.v1` | `UTF-8(statement_jcs)` | `statements` | pair of the wrapper: `countersigning`; pair in `statement_signatures`: `statements` (heartbeat specification §9.3, §9.4) |
| anchor history page `ledger.anchor_history.v1` | `UTF-8(statement_jcs)` | `statements` | `countersigning`, bytes as in edition 1.9 |
| anchor history page `ledger.anchor_history.v2` | `UTF-8(statement_jcs)` | `statements` | `statements` only |
| update manifest | `UTF-8(JCS({"kind": "ledger.update_manifest.v1", "manifest": <object>}))` | `update_manifest` | `update_manifest` only |
| day entry `ledger.vendor_log_day.v1` | `UTF-8(statement_jcs)` | `protocol` | `protocol` |
| list of countersigning keys, role list, protocol key list | `UTF-8(JCS(list without "signatur"))`, each with its own `format` | vendor root | vendor root |

1. A key signs only objects of its role. Between the roles, different keys and the role check (Section 10.7.4) separate the objects; within a role, the member `kind` does (registry `object_kinds`). Within the role `countersigning` the rule of edition 1.9 applies during dual operation: a receipt has exactly the four members and no `kind`, every other object carries a `kind`.
2. No context and no prefix are added: both signatures of a statement during dual operation cover the same bytes, and the signed subjects of edition 1.9 remain valid.
3. A reader of a list signed by the root checks `format` first. The root signs nothing else, and no entry of a list names its public key; the verifier checks this only on the role list (Section 10.7.2).
4. The key of the update bundles (heartbeat specification §1) does not belong to these roles and stays as it is.

#### 10.7.4 Role Check by the Verifier

The role check runs with step L1 before the check of the receipts (Section 10.5, stage 5, step 4). It reads the list of countersigning keys of the package and the lists and pins the auditor passes.

**Unusable invocation** (exit 3 without a report; supplements step L0 of Section 7.4.10): a pin of a statements key not of the form `key_id=hex64`; two pins of statements keys with the same `key_id` and different public keys; a pin of one role equal in `key_id` or public key to a pin of another role (`--vendor-key` for `countersigning`, `--vendor-log-key` for `protocol`, `--vendor-statement-key` for `statements`); a violation of the grammar or of the size of a file from `--vendor-key-list`, including an unknown or missing `format` (Section 10.8). A defect in the content of a list that keeps its grammar is never exit 3.

**Notation.** K_cs^L are the keys of the package's list of countersigning keys if it is effective (Section 10.7.1), and the keys of the effective lists of this format that the auditor passes. P is the effective protocol key list under Section 7.4.10, step L1, number 2.

- **R1 Candidates.** Candidates are the distinct role lists (distinct by their JCS bytes) from `--vendor-key-list`. A candidate counts if it satisfies Section 10.7.2 and its signature holds against a vendor root of the auditor or the built-in root with this `wurzel_id`; the report names the source of the root.
- **R2 Effective role list Q.** Q is the counting candidate with the greatest `version`. There is no effective role list (reason `lists_contradictory`) if two counting candidates have the same `version` and different bytes, if a counting candidate lacks an entry (the same `key_id` with the same `pubkey` and the same `rolle`) of a counting candidate of smaller `version`, or if counting candidates carry different values of `ende_doppelbetrieb` or a candidate of greater `version` lacks the member that a candidate of smaller `version` carries. Values of `ende_doppelbetrieb` are compared here as strings, since the vendor copies the value character for character into every later version; `…T00:00:00Z` and `…T00:00:00.000Z` are different values. If there is no effective role list, no candidate of smaller `version` takes its place.
- **R3 Role check by public key**, in this order:
  - (a) If Q gives a public key from K_cs^L a role other than `countersigning`, Q is not effective (reason `key_in_two_roles`). Then there is no effective role list, and no candidate of smaller `version` takes its place. (b) to (d) do not read such a Q: a public key named only by this Q does not make P ineffective and drops no pin.
  - (b) If Q and P share a public key, neither of the two is effective (reason `key_in_two_roles`; for P the reason "key in two roles" of Section 7.4.10, step L1, number 4).
  - (c) If P shares a public key with a pin of a countersigning key or with K_cs^L, P is not effective (Section 7.4.10, step L1, number 3).
  - (d) Pins, checked against the Q and P that are effective after that: a pin of a countersigning key whose public key Q names with another role is dropped. A pin of a statements key whose public key stands in K_cs^L or in P, or which Q names with another role, is dropped. A pin of a protocol key whose public key stands in K_cs^L or which Q names is dropped. A dropped pin establishes nothing (report `pins_dropped`, note `pin_dropped`).

  The public key is compared, not the `key_id`: every key is looked up only in its role. K_cs (Section 7.4.10) is K_cs^L together with the pinned countersigning keys that are not dropped.
- **R4 Use per role.** `countersigning`: Section 7.1 with the remaining pins; Q never establishes a receipt. `statements`: first the pins as statements keys, then the entries of Q with the role `statements` (Section 8.8.3); a page under an entry with `widerrufen_ab` counts only if it is fresh (Section 8.8.4, step H2), also under a pin whose public key Q names that way (Section 8.8.3). `protocol`: Section 7.4.10, step L1. The role `update_manifest` and unknown roles the verifier does not use.

**Receipts.** The findings under Section 7.1 do not change. A receipt that is not established under Section 7.1 and whose public key in the manifest is an entry of Q with another role, a key of P or a pin as a statements or protocol key is judged as in edition 1.9 (`RECEIPT_UNVERIFIED` if the manifest names the key); the report gives the note `receipt_key_other_role`. For this note every pin the auditor passes counts, also one that step R3 drops. A dropped pin of a countersigning key counts as not passed.

**Report.** The result stands in the report object `key_roles` (Section 10.10.2): status `not_supplied` without candidates; `effective` with Q; `not_effective` if there are candidates but no Q, with the reason `lists_contradictory` or `key_in_two_roles` where they apply, otherwise with the reason of the candidate that came furthest: the reasons are ordered `format` < `no_matching_root` < `signature`, and the highest reason among the candidates is named. Notes stand in the order of the registry: `unknown_role`, `receipt_key_other_role`, `pin_dropped`.

**Findings.** The role check adds no finding class. Exit 3 arises only with the unusable invocation above. A contradiction of the roles ends at exit 1 through existing classes, never at exit 2: `ANCHOR_HISTORY_UNVERIFIED` with the reason `key_not_established` or `key_other_role` (Section 8.8.4), `VENDOR_LOG_UNVERIFIED` with the reason "key in two roles" (Section 7.4.10) and `RECEIPT_UNVERIFIED` (Section 7.1). `RECEIPT_INVALID` (exit 2) remains where the list of countersigning keys of the package contradicts a receipt (Section 7.1). A contradiction of the roles is a statement about the vendor's lists or about the verification environment, not about the chain.

Reference values (role list from Section 10.7.2): a pin as a countersigning key with the public key of `vendor-test-001` is effective with the role list of version 1; a pin as a countersigning key with the public key of `vendor-statements-test-001` is dropped and establishes no receipt. A role list that gives the public key of `vendor-test-001` the role `statements` is, in the package `valid_vendor_list` under `testwurzel-1` (list of countersigning keys of the package effective, `vendor-test-001` in K_cs^L), not effective (`key_in_two_roles`), and the receipts are judged as without it; without an effective list of countersigning keys, with only `--vendor-key` for `vendor-test-001`, the same role list is effective, the pin is dropped (`pins_dropped`), and the receipts under `vendor-test-001` yield `RECEIPT_UNVERIFIED` with the note `receipt_key_other_role`. A role list with an unknown role is effective, with the note `unknown_role`; a pin as a statements key that equals a pin as a countersigning key is an unusable invocation. Two counting role lists whose `ende_doppelbetrieb` read `2026-07-01T00:00:00Z` and `2026-07-01T00:00:00.000Z` yield `lists_contradictory`. If the role list of the highest `version` is not effective after R3 (a), none is effective, even if a role list of smaller `version` counts; a protocol key list that shares a public key only with this role list stays effective. If a page names in `server_key_id` the `key_id` of a dropped pin, its reason is `key_not_established`, not `key_other_role` (Section 8.8.4, step H2).

#### 10.7.5 Transition from Operation with One Key

Up to edition 1.9 the same key of the vendor signs receipts, statements, anchor history pages and the update manifest. Verifiers and appliances of edition 1.9 know no roles: they check receipts and statements against the list of countersigning keys or a pinned key and reject every unknown member of this list. The transition to separate roles therefore proceeds in three steps after which they keep working (heartbeat specification §9.11):

1. **Signing procedure.** Before the server works under edition 1.10 and before the first day of the vendor log, the vendor collects the public parts of the keys in one signing procedure: the active statements key is generated in the service that signs statements, the active protocol key in the service that signs day entries; the standby keys, the update manifest key and the filler secret (Section 7.4.4) are generated offline (heartbeat specification §9.11). It signs the role list of version 1 and the protocol key list of version 1; if it includes a standby for countersigning keys, also a new version of the list of countersigning keys.
2. **Dual operation.** After that the previous countersigning key continues to sign receipts, pages of kind v1 and the wrapper of the three statements that appliances receive (license statement, refusal statement, activation receipt). The same `statement_jcs` of these statements is signed by a statements key in the member `statement_signatures` of the response (heartbeat specification §9.3). The service that holds the countersigning key reads every `statement_jcs` handed to it itself before signing and signs only an object of the form of Section 2 with a `kind` of these three statements or of the page of form v1, never an object without `kind` (heartbeat specification §9.11 item 3). Pages of kind v2 are signed only by a statements key, the update manifest only by its own key, day entries only by a protocol key.
3. **End of dual operation.** From the instant `ende_doppelbetrieb` of the role list, countersigning keys sign only receipts; the wrapper of the statements and pages of kind v1 are then signed by a statements key. The vendor sets this instant in a new version of the role list at least 180 days in advance and only once it no longer supports any appliance that checks statements solely against the list of countersigning keys.

Recipients and auditors who proceed under edition 1.9 accept, until the end of dual operation, receipts under the countersigning keys of their list and statements in the wrapper under a countersigning key; they pass over the member `statement_signatures`, and their list never names a key of another role. After the end of dual operation a statement the vendor issues is no longer effective for an appliance of edition 1.9, since it knows no statements key; recording, chain and receipts continue (heartbeat specification §9.4). A statement in the wrapper under a countersigning key it would still accept (Section 11.2, key roles). A verifier from edition 1.10 establishes pages only through statements keys (Section 8.8.3); because the server issues pages of kind v2 only under statements keys from the start, no page loses its effect through this.

### 10.8 Auditor Inputs and `verify_args.json`

Whatever the auditor hands to the verifier is read by the same grammar as the package (from edition 1.9); an input that violates it is an unusable invocation: exit 3 with the reason, never a silent interpretation.

- **Check time** (freshness, Section 8.5): an instant of the `rfc3339` grammar of Sections 2 and 10.7 (UTC with `Z`, uppercase `T`, ASCII digits, year `0001` to `9999`). A value without a zone, with an offset, with a blank instead of `T`, as a week date or without seconds is unusable; it is not read in the host's time zone. Without a value the system clock applies. A check time given takes precedence over `verify_args.json`; the file is then not read.
- **Expected roots** (paper anchor, Section 7.2; comparison, Section 8.6; gap witnesses, Section 11.2), any number of them, each in one of two forms: `<merkle_root>` or `<tree_size>:<merkle_root>`; `merkle_root` is 64 hex characters, upper and lower case equivalent; `tree_size` has the form `[1-9][0-9]*` and is at most 2^53−1 (`0:` and leading zeros are unusable). With `tree_size` it is found if the recomputed root over the first `tree_size` entries equals it; if `tree_size` exceeds the number of entries, it is not found. Without `tree_size` it is found if it equals the root over the first t entries for some t from 1 to the number of entries. Every expected root not found is `MERKLE_INCONSISTENT` (exit 2) and anchors nothing; every one found counts as an anchor (no `NO_ANCHOR`). Completeness (Section 8.6) holds up to the largest `tree_size` of a root found, even if another one is not found. From edition 1.10 every expected root carries a source: `auditor` for a root under this item, `anchor_history` for a history root (Section 8.8.5); for history roots without the source `auditor` the classification of Section 8.8.5 applies instead of the sentence on `MERKLE_INCONSISTENT`. A root without `tree_size` that matches several prefixes counts as found at the largest matching t. Identical pairs (`tree_size`, `merkle_root`) from both sources are one expected root with both sources and yield at most one finding.
- **`verify_args.json`** is optional and unsigned; the producer of the package chooses its content. It is I-JSON (Section 2) and has exactly the member `now` (rfc3339 as above). The verifier reads it only when the auditor explicitly asks for it (for frozen test vectors) and names the source of the check time in the report. Asked for and absent or not conforming: exit 3 with the reason, the package is not read any further (the only finding `FORMAT_ERROR`); no fallback to the system clock, so that an explicit request never silently changes the basis of the freshness check.
- **Freshness window** (Section 8.5; flag and grammar from edition 1.10): `--freshness DUR`, at most once. DUR is a whole number from 1 to 999 999 without a leading zero, directly followed by the unit `h`, `m` or `s` (e.g. `24h` or `90m`); without it, `24h` applies. Any other form, such as `0`, a sign, a fraction, two units or a missing unit, is unusable. The window is compared in whole milliseconds (Section 2).

**Further inputs (from edition 1.10).** The existing inputs (check time, expected roots, vendor root and pinned keys under Section 7.1, `verify_args.json`) keep their rules; from edition 1.10 `--vendor-key` pins only a countersigning key (Section 10.7.4). The following are added, with the same flags in the Go verifier and in the second verifier and the same options in the browser version:

| Input | Flag | Browser option | Grammar, limits and rules | read in |
|---|---|---|---|---|
| roots for time witnesses of the chain (purpose `chain`) | `--tsa-root FILE`, repeatable from edition 1.10 | `tsaRootsPem` (`Uint8Array` or `Uint8Array[]`) | strict PEM (below) | 7.3 step 6; 10.9 condition 1 |
| roots named as qualified (purposes `chain` and `qualified`) | `--tsa-qualified-roots FILE`, at most once | `tsaQualifiedRootsJson` (`Uint8Array`) | `ledger-tsa-qualifiziert/1` (below), at most 8,388,608 bytes | 7.3 step 6; 10.9 conditions 1, 4 and 7 |
| roots for time stamps of the vendor log (purpose `log`) | `--vendor-log-tsa-root FILE`, repeatable | `vendorLogTsaRootsPem` (`Uint8Array[]`) | strict PEM | 7.4.6; 10.9 condition 7 |
| extracts of the vendor log | `--vendor-log FILE`, repeatable | `vendorLogJson` (`Uint8Array[]`) | `ledger-protokollauszug/1` (7.4.8); per file at most 33,554,432 bytes, per invocation at most 128 files and 268,435,456 bytes, embedded extracts included | 7.4 |
| pinned protocol keys | `--vendor-log-key ID=HEX`, repeatable | `vendorLogKeys` (`string[]`) | `key-id`, `=`, hex64; contradictions and double roles under 7.4.10, step L0 | 7.4 |
| pinned statements keys | `--vendor-statement-key ID=HEX`, repeatable | `vendorStatementKeys` (`string[]`) | `key-id`, `=`, hex64; contradictions and double roles under 10.7.4 | 8.8.3; 10.7.4 |
| key lists | `--vendor-key-list FILE`, repeatable | `vendorKeyListJson` (`Uint8Array[]`) | I-JSON, at most 1,048,576 bytes; `format` is `rekorder-herstellerschluessel/1`, `ledger-schluesselrollen/1` or `ledger-protokollschluessel/1`, another or a missing `format` is an unusable invocation; the content is judged by Sections 10.7.1, 10.7.2 and 7.4.7: a list that does not hold is ineffective (named in the report), never exit 3 | 10.7.4; 8.8.3; 7.4.10 step L1 |
| anchor history | `--anchor-history FILE`, repeatable | `anchorHistoryJson` (`Uint8Array[]`) | one page or `ledger-ankerhistorie/2` (8.8.2); per file at most 33,554,432 bytes, per invocation at most 4,096 files, 65,536 pages and 268,435,456 bytes | 8.8 |
| request time | `--requested-at RFC3339`, at most once | `requestedAt` (`string`) | grammar `rfc3339` as for the check time, any fractional seconds, compared in whole milliseconds (fraction truncated); rules below | 8.8 |

The verifier reads the inputs of the table as bytes at invocation, before it opens the package; in the browser the same holds for the options. For the individual inputs:

- **Strict PEM** (both PEM inputs): lines end in `\n` or `\r\n`, and a last line without a line end counts as a line; blanks and tabs at the end of a line do not count; text outside a block is passed over (RFC 7468). A block is a line exactly `-----BEGIN CERTIFICATE-----`, lines of content and a line exactly `-----END CERTIFICATE-----`; the joined content follows the grammar B64 (Section 2) and yields exactly one certificate under Z.1 (Section 7.5.3). Unusable are a block with another label after `BEGIN`, a header line inside a block (a line with `:` between `BEGIN` and `END`), a block without an end and a file without a `CERTIFICATE` block; a line with `:` outside a block, for example a comment of a bundle file, is text outside a block and is passed over, and so is an END line outside a block. No block is passed over silently, and every repeated input counts; so far a verifier could pass over malformed blocks or read only the last file. Every certificate of such a file counts as a root of the purpose; if the auditor passes a bundle file with many roots, for example the root store of a system, every one of them counts, and a token of any of these authorities can suffice for condition (1) of the evidence level (Section 11.2).
- **`ledger-tsa-qualifiziert/1`:** an auditor file (Section 2) with exactly the members `format` (const `"ledger-tsa-qualifiziert/1"`), `stand` (rfc3339, grammar of Section 10.7: when the auditor compiled the file), `quelle` (string, 1 to 256 characters without U+0000 to U+001F and U+007F to U+009F: where he took it from) and `wurzeln` (array, 1 to 256 objects with exactly `zertifikat`, the base64 form under B64 of a DER certificate under Z.1 of at most 16,384 bytes, `qualifiziert_ab` (rfc3339) and optionally `qualifiziert_bis` (rfc3339, after `qualifiziert_ab`)). Two entries with a byte-identical certificate make the input ambiguous: exit 3. A root of the file counts for the purpose `qualified` only for tokens with `qualifiziert_ab` ≤ `genTime` < `qualifiziert_bis` (the upper bound only where present), compared as instants to the nanosecond; for the purpose `chain` it always counts. The report outputs `stand` and `quelle`. Deriving the file from a trusted list is a step of the auditor; the verifier reads no signed XML lists.
- **Table of roots for time stamps.** Every certificate from the three root inputs is one entry with its SPKI SHA-256 value and its purposes (Section 7.5.7). Byte-identical certificates (DER) from different inputs are one entry with the union of their purposes; the period for the purpose `qualified` is named solely by the file `ledger-tsa-qualifiziert/1`, which never gives the purpose `log`. For condition (7) the auditor therefore passes the same certificate with `--vendor-log-tsa-root` and in `--tsa-qualified-roots`. The system root store adds nothing for any purpose, and a verifier carries no root of a time-stamping authority built in.
- **Key lists** (`--vendor-key-list`): every file is an auditor file (Section 2). A violation of I-JSON, for instance a duplicate member name or a number outside the number rule of Section 2, is an unusable invocation (exit 3 without a report). The list in the package is different: Sections 10.7.1 and 10.7.2 decide whether it is effective; only a violation of the number rule is `FORMAT_ERROR` there (Section 2).
- **Request time R** (Section 8.8.1): optional, at most once. R MUST NOT lie after the check time. Against a check time from `--now` or the system clock the verifier checks this at invocation (exit 3 without a report). If the auditor asks for the check time from `verify_args.json`, the verifier checks R against it at the start of stage 5 (Section 10.5); if R lies after it, that is `FORMAT_ERROR` (exit 3 with a report). This difference is intended: from `--now` or the system clock the check time is known at invocation, from `verify_args.json` only once the package is opened. The verifier never fills in R from `manifest.created_ts`, `verify_args.json`, the check time or a clock. If R is passed without an anchor history, the verifier accepts it and gives the note `requested_at_unused`.
- **Unusable invocation.** A violation of a grammar or limit of this table, an input that occurs more often than permitted and every other usage error (an unknown flag, a missing value) is an unusable invocation: exit 3 with a reason on the error output, without a report; in the browser an error message instead of a verdict, from edition 1.10 also for an option name the browser edition does not know (Section 10.6). Only the flags the table calls repeatable and the flags for expected roots, vendor roots and pinned countersigning keys (above, Section 7.1) may occur more than once; every other flag with a value occurs at most once, `--now`, `--lang` and the flag of the freshness window (Section 8.5) included, and a repeated one is an unusable invocation. On the command line the flags stand before the package and begin with two dashes, `--` ends them; a flag without a value (`--json`, `--now-from-package`) takes none, a flag with a value takes it as `--name VALUE` or `--name=VALUE`, VALUE being the next argument even if it begins with a dash, and `--version` stands alone (from edition 1.10). An argument before `--` that begins with a dash is a flag; a package with such a name stands after `--`. Any other form, a flag or a further argument after the package included, is a usage error, and so is a request for help (`--help`, `-h`), which names the flags on the error output. Excepted is the comparison of R with `verify_args.json` (above), which is possible only after reading the package. What a defect in the content of an input that keeps its grammar causes is decided by Sections 7.4, 8.8 and 10.7; it is never exit 3.

**Audit environment of a test vector `ledger-pruefumgebung/1`.** Only in the test corpus, a file `pruefer_<vector>.json` combines the auditor inputs for one vector. It is an auditor file (Section 2), all members are present, and the test tools turn it into flags in this order: `format` (const `"ledger-pruefumgebung/1"`), `korpus` (bool; `true`: in addition the vendor root and the pinned key of the corpus, `pruefer_herstellerwurzel.json` and `pruefer_herstellerschluessel.txt`), `vendor_root` (array of files), `vendor_key` (array of `key_id=hex64`), `vendor_key_list` (array of files), `vendor_log_key` (array of `key_id=hex64`), `vendor_statement_key` (array of `key_id=hex64`), `tsa_root` (array of files), `tsa_qualified_roots` (file or `null`), `vendor_log_tsa_root` (array of files), `expect_root` (array of strings as for the expected roots), `vendor_log` (array of files), `anchor_history` (array of files) and `requested_at` (rfc3339 or `null`). The files named are called `pruefer_<vector>.<member>-<n>.<extension>`, lie at the top level of the test vectors and are recorded with their SHA-256 value like the vectors. The check time stays in the `verify_args.json` of the vector.

### 10.9 Evidence Level

From edition 1.10. The verifier MUST determine and output an evidence level for every package for which it outputs a report. It summarises which of the anchors checked under Sections 7, 8.6, 8.8 and 10.8 are confirmed by auditor inputs and up to which `seq` they reach. It is no finding, does not change the exit code and is no part of the verdict (Section 10.3). It applies to every package, whatever `spec_version` it declares. The evidence level supports statements on how strongly the chain presented is evidenced against rewriting by its key holder. It guarantees nothing, it is no legal classification, and it says nothing about the content of the calls.

The level is a function of the data the verifier records during the check (Section 10.9.3), of the exit code and of the finding classes. Determining it adds no finding, removes none and changes no other result; the step that determines it after the exit code (Section 10.5) reads neither a clock nor the system root store nor a file. Both reference verifiers determine it under this section and output the same object `evidence_level` for equal inputs (Section 10.10). Codes, orders, rule and texts are in the registry under `verifier.evidence_level`.

#### 10.9.1 Conditions and Levels

**Conditions.** Every condition has a fixed code; this section uses the numbers in parentheses.

1. `time_witness`: a time witness passes steps 1 to 6 of Section 7.3, and step 6 succeeds with a single root on its own that the auditor passed for time witnesses of the chain (purpose `chain`, Sections 7.5.7, 10.9.4).
2. `expected_root_found`: an expected root that the auditor passed (source `auditor`, for instance a paper anchor under Section 7.2) or that comes from a checked anchor history (source `anchor_history`, Section 8.8.5) is found in the package (Section 10.8).
3. `receipt_key_confirmed`: a countersignature holds under a key that an anchor of the auditor confirms under Section 7.1, and this key is no device key of the chain.
4. `time_witness_qualified`: a time witness under (1) chains to a root the auditor named as qualified for the time of the token (purpose `qualified`, Section 10.8); its token declares itself a qualified time stamp (rule QS, Section 7.5.6), and its signed attributes name the signer certificate (Z.6, Section 7.5.6).
5. `receipts_logged`: the countersignatures are shown in witnessed days of the vendor log (Section 7.4).
6. `completeness_from_history`: completeness is established by a checked, complete anchor history issued after the request of the package (Section 8.8.4, step H11).

7. `log_day_qualified`: countersignatures are shown in days of the vendor log (as for (5)) whose canonical entry carries the time stamp of an authority that the auditor passes for the log and names as qualified for the time of the token; this token declares itself a qualified time stamp (Sections 7.4.6, 7.5.6), and its `genTime` lies at most G_q = 129 600 000 ms (36 hours) after the `server_ts` of the countersignature (Section 10.9.4).

**Two paths to the qualified time (from edition 1.10).** (4) and (7) evidence the same thing: that the state of the chain at a `tree_size` existed at the latest at a time carried by the token of an authority the auditor names as qualified. (4) binds the chain directly, through a time witness on it; (7) indirectly, through the countersignature whose inclusion in the day tree the extract proves, and the time stamp of the day entry (Sections 7.4.2 to 7.4.6). For level 3 one of the two paths suffices. (7) presupposes only a log under Section 7.4 and an authority the auditor names as qualified: every vendor whose log follows these rules opens this path to its customers alike, without a contract per customer. Which time is evidenced, and at what distance from the countersignature, stands in `qualified_time` (Section 10.10.2); the limit of this path is named in Section 11.2.

**Levels.** The levels build on each other; a level is present at a position if its conditions reach this position (Section 10.9.5).

| Level | Name | Conditions |
|---|---|---|
| 0 | self-statement | none of levels 1 to 3 is present |
| 1 | externally bound | (1), (2) or (3) |
| 2 | countersigned | (3) |
| 3 | anchored and reconciled | (3), (4) or (7), (5) and (6) |

The headline of the report names the level of `seq` 1 with its name from the table, never without its reach and the course over the chain.

Every condition reaches up to a `tree_size` t: an anchor for t evidences the entries `seq` 1 to t. The level of a position `seq` p is the highest level whose conditions reach p. The report MUST always name the level with its reach and the course, together with every condition with its reason, what is missing for the next level, the anchors with fingerprint and the affiliation (Section 8.8.6, heartbeat specification §9.10). The presentation MUST NOT change colour and form of the verdict.

**Level 0.** Level 0 at a position means: no evidence of a party outside the key holder's control that an anchor of the auditor confirms reaches up to it. Level 0 is no statement about a manipulation; the entries are checked like all others. Receipts under a key that no anchor of the auditor confirms (`RECEIPT_UNVERIFIED`) and time witnesses whose authority only a certificate from the package confirms (`TIME_ANCHOR_UNVERIFIED`) do not raise the level above 0: they suppress `NO_ANCHOR` (Sections 7.1, 7.3), but establish self-consistency only.

**Origin of the anchors.** Only anchors the auditor supplies count (Sections 7.1, 7.3, 8.8, 10.7, 10.8), and the vendor root built into the verifier that the report names as the source (Section 7.1). Never counted are: the system root store; certificates and keys from the package (`keys/tsa/`, `keys/vendor/`, `manifest.vendor_pubkeys`); certificates from a token as trust anchors (they serve only as intermediate certificates, Section 7.5.5); a key of a signer or of a root of a time-stamping authority whose private part is published (entries with an SPKI SHA-256 value in `published_test_keys`, Section 7.5.7); this rule applies to keys of time-stamping authorities, not to the Ed25519 test keys of the vendor in the same list, to which the note `published_test_key_credited` draws attention (Section 10.9.6); a vendor key that equals a device key of the chain; a pin that is dropped under Section 10.7.4; a key of a role other than that of the object it is to establish (Section 10.7.3); and, for condition (4), a root with the same key as a certificate from `keys/tsa/`. Keys of certificates are compared by the SHA-256 value of their SubjectPublicKeyInfo (SPKI SHA-256 value), not by the certificate: a key whose private part is known can be put into a new certificate.

**Affiliation.** The report shows the affiliation of the customer with the vendor (Section 8.8.6) beside the level. It enters no condition and changes neither the number of the level nor its reach nor the course; no note depends on it. No condition reads `GENESIS.customer_id`, the edition, licence data or a list of customers. The list `published_test_keys` names keys, never customers or vendors, and changes only with an edition of the specification. The criteria name formats, not a vendor: every vendor whose root, key lists, anchor history and log follow the formats of this specification reaches the same levels with the inputs the auditor passes. A vendor root built into the verifier replaces such an input only for the vendor whose root is built in; for its customers a check without any action of the auditor reaches level 2, for the customers of other vendors it does not. The report names the built-in root as the source and then gives the note `vendor_root_builtin_only` (Section 10.9.6).

#### 10.9.2 State

The state `state` follows from the exit code (Section 10.3) and the findings; the first row that applies holds:

| Situation | `state` | `level` |
|---|---|---|
| exit 3 (format error) | `format_error` | `null` |
| a finding of exit class 2 whose class is not in `verifier.evidence_level.material_classes`; the list names `CONTENT_MISMATCH` and `REPORT_MISMATCH` | `chain_invalid` | `null` |
| otherwise: exit 0, 1 or 4, or exit 2 only from classes of the list `material_classes` | `rated` | 0 to 3 |

An unusable invocation (Section 10.8) writes no report; there is then no level. In the states `format_error` and `chain_invalid` there is no level, there are no conditions and there is no course (Section 10.10.2); the texts read "not determined (format error)" and "none (chain invalid)".

**Only presented material contradicts.** If all findings of exit class 2 come from the list `material_classes`, presented plaintexts or reports contradict the chain (Sections 9.1, 10.1), while every check of the chain ran and held. The level is then determined and applies to the chain, not to this material; the report gives the note `material_contradiction`, and its headline reads "Evidence level of the chain: …" (Section 10.10.3). The more strongly the chain is anchored, the more weight the contradiction of the material carries; without a level this would be lost.

**Incomplete chain end.** Exit 4 (Section 8.6) yields the state `rated` like exit 0 and 1. The level applies to the entries present, `seq` 1 to N; it says nothing about entries after N, and the report gives the note `unsealed_end`. Entries that no condition reaches, for instance in the residual window (Section 11.2), stand in the course with level 0.

**Later exit classes.** The nine classes of Sections 7.4.11 and 8.8.7 have exit class 1 and never change the state. If one of them receives exit class 2 in a later edition, it MUST be added to a list that acts like `material_classes`: a behaviour of the vendor is no proof against the customer's chain.

#### 10.9.3 Recorded Data

During the check the verifier records these data. Each is a function of the package and of the auditor inputs and yields no finding by itself.

- **Per receipt** whose signature holds under Section 7.1: `tree_size`, `server_key_id`, the origin of the key (`pinned`; `list` with `version` and `wurzel_id` of the list and the origin of the root, `auditor` or `builtin`; `manifest`, as in `evidence_level.anchors.vendor_keys`, Section 10.10.2), whether the public key equals a key from D, and its class in the vendor log with sub-class (Section 7.4.10, step L8).
- **D:** every device key under which a checkpoint signature of this chain was accepted, that is `GENESIS.device_pubkey` and every key from `KEY_ROTATION` legitimized under Section 6.4.
- **Per TIME_ANCHOR:** `tree_size`, `genTime`, whether steps 1 to 4 of Section 7.3 are passed, the result of step 5 (holds, or not performable under 5a with the reason), for every root R of the table of Section 10.8 individually whether a path under Z.3 and Z.4 at `genTime` to R alone exists, the SPKI SHA-256 values of the signer and of R, the result of rule QS and whether Z.6 holds, is violated or cannot be checked.
- **Roots for time stamps:** per entry of the table (Section 10.8) the certificate, its SHA-256 value, its SPKI SHA-256 value, its purposes and, for the purpose `qualified`, the period with `qualifiziert_ab` and, where given, `qualifiziert_bis`.
- **Certificates of the package:** the SPKI SHA-256 value of every certificate in a `CERTIFICATE` block of a file `keys/tsa/*.pem` that can be read under B64 and Z.1; others are passed over, without a finding.
- **Per expected root:** its sources (`auditor`, `anchor_history`), whether it is found, and `found_at`, the `tree_size` at which it is found (for a root without `tree_size` the largest matching t, Section 10.8).
- **From Section 8.8:** `anchor_history.completeness`, the notes of the anchor history and, from the affiliation, `status` and `vendor_itself`.
- **From Section 7.4:** `vendor_log.status`, whether a finding `VENDOR_LOG_CONTRADICTION` exists without a day or on a day of the required range [Lo, T] of this package (Section 7.4.10, step L7), and the smallest `tree_size` t_m of a finding `LOGGED_ROOT_MISMATCH`.
- **From Section 7.4 for condition (7):** per usable day d on which a receipt has the class `included`, per time stamp of c(d) that is not defective: its `genTime`, the result of step 5 (performable under 5a or not), for every root R of the table of Section 10.8 with the purposes `log` and `qualified` singly whether a path under Z.3 and Z.4 at `genTime` to R alone exists, the SPKI SHA-256 values of the signer and of R, and the result of rule QS.

#### 10.9.4 Conditions in Detail

Every condition yields an object with four members: `met` (bool) says whether it is present; `up_to_tree_size` is its reach, `null` if it is not present; `count` is the number of credited items, 0 if none is credited; `reason` is `null` exactly when it is present, otherwise a reason from the table below.

**Evaluation.** First the reasons without an item are checked in the order of the table: if one applies, the condition is not present, and the foremost one that applies is its reason. Otherwise every item is checked against the stages, for (1) and (4) every pair of item and root, for (7) every triple of receipt, time stamp and root; s is the number of stages the pair or triple passes without interruption in the order of the table. An item is credited if it passes every stage for one and the same root (for (7): the same time stamp and the same root); stages of different roots are never combined. If no item is credited, the reason is the code of the stage with the index max(s) over all pairs, that is the stage at which the pair that got furthest failed. If pairs fail there at the stage `qualified_statement` with both results, `qualified_statement_malformed` takes precedence over `no_qualified_statement`. Because only the code is output, no further rule is needed.

| Condition | Items, roots | Reasons without an item, in this order | Stages per item, in this order | Reach | `count` |
|---|---|---|---|---|---|
| (1) `time_witness` | every TIME_ANCHOR, per root of purpose `chain` | `no_time_anchor` (no TIME_ANCHOR in the chain); `no_tsa_root_supplied` (no root of purpose `chain`) | `signature_not_checkable` (step 5 not performable under 5a); `not_chained_to_auditor_root` (no path under Z.3 and Z.4 at `genTime` to this root alone); `published_test_key` (SPKI of the signer or of the root in `published_test_keys`); `token_extensions_unusable` (rule QS yields "unusable" under numbers 1 to 3) | largest `tree_size` of a credited TIME_ANCHOR | credited TIME_ANCHOR entries |
| (2) `expected_root_found` | every found expected root of the source `auditor` or `anchor_history` | `no_expected_root_found` (no such root found) | none | largest `found_at` | distinct found roots, per (`found_at`, `merkle_root`) |
| (3) `receipt_key_confirmed` | every `CHECKPOINT_RECEIPT` whose signature holds under Section 7.1 | `no_receipt` (no such receipt) | `key_not_confirmed` (key only from the manifest, that is `RECEIPT_UNVERIFIED`); `key_is_device_key` (the confirmed public key equals a key from D) | largest `tree_size` of a credited receipt | credited receipts |
| (4) `time_witness_qualified` | every TIME_ANCHOR, per root of purpose `qualified` | `no_time_anchor`; `no_qualified_root_supplied` (no root of purpose `qualified`) | `signature_not_checkable` (step 5 not performable under 5a, or Z.6 cannot be checked, Section 7.5.6); `not_chained_to_qualified_root`; `published_test_key`; `qualified_root_in_package` (SPKI of the root equals that of a certificate from `keys/tsa/`); `outside_qualified_window` (not `qualifiziert_ab` ≤ `genTime` < `qualifiziert_bis`, the upper bound only where present, compared as instants to the nanosecond); `signing_certificate_not_bound` (Z.6 violated); `token_extensions_unusable`; `qualified_statement` (rule QS, number 4: `malformed` yields `qualified_statement_malformed`, `absent` yields `no_qualified_statement`) | largest `tree_size` of a credited TIME_ANCHOR | credited TIME_ANCHOR entries |
| (5) `receipts_logged` | the receipts of Section 7.4.10, step L8 (signature holds under Section 7.1, no finding `RECEIPT_INVALID`), in chain order, each with its class from step L8 | `vendor_log_not_supplied` (status `not_supplied`); `vendor_log_not_established` (status `no_protocol_key`); `vendor_log_contradiction` (a finding `VENDOR_LOG_CONTRADICTION` without a day or on a day from [Lo, T], Section 10.9.3); `no_receipt` | per receipt (below) | below | good receipts up to the reach |
| (6) `completeness_from_history` | `anchor_history.completeness` (Section 8.8.4, step H11) | by the mapping below | none | `completeness.up_to_tree_size` | found history roots (`anchor_history.roots.found`) |
| (7) `log_day_qualified` | every receipt of the class `included` (Section 7.4.10, step L8), per time stamp s of the canonical entry c(d) of its day d = day(`server_ts`) that is not defective under Section 7.5.7, and per root with the purposes `log` and `qualified` | `vendor_log_not_supplied`; `vendor_log_not_established`; `vendor_log_contradiction` (as for (5)); `no_qualified_log_root_supplied` (no root of the table carries both purposes); `no_receipt_included` (no receipt has the class `included`) | `signature_not_checkable`; `not_chained_to_qualified_log_root` (no path under Z.3 and Z.4 at `genTime` to this root alone); `published_test_key`; `outside_qualified_window`; `qualified_day_stamp_late` (`genTime`, truncated to whole milliseconds, is not less than end(d) + W, Section 7.4.6); `qualified_day_stamp_gap` (`genTime`, truncated to whole milliseconds, minus `server_ts` of the receipt is greater than G_q); `token_extensions_unusable`; `qualified_statement` (as for (4)) | largest `tree_size` of a credited receipt | credited receipts |

**In the state `rated`** all time witnesses have passed steps 1 to 4, and where step 5 was performed, it holds; otherwise `TIME_ANCHOR_INVALID` would exist. Likewise every expected root of the source `auditor` is found; otherwise `MERKLE_INCONSISTENT` would exist. A credited item of (4) is at the same time a credited item of (1), since a root of purpose `qualified` also carries the purpose `chain` (Section 7.5.7).

**On (2).** History roots count if Section 8.8.5 classifies them as found; roots beyond the package end are not found. Roots from the vendor log are no expected roots (Section 7.4.10, step L9) and never count.

**On (3).** Condition (3) reads no finding of the vendor log and none of the anchor history. A behaviour of the vendor under another key or a data loss at the vendor thus never lowers the level 2 of a customer. A receipt under a key of another role (Section 10.7.4) and a receipt whose key only a list of the auditor names have the origin `manifest` (Section 7.1).

**On (5), per receipt.** A receipt of class `included` is good, one of class `before_start` neutral. Every other one is bad, with this code:

| Class (Section 7.4.10, step L8) | Code |
|---|---|
| `not_included` | `receipt_not_logged` |
| `unchecked` with sub-class `day_not_witnessed` | `day_timestamp_not_confirmed` |
| `unchecked` with another sub-class | `receipt_not_checkable` |
| `missing` | `log_day_not_supplied` |
| `pending` | `receipt_day_not_closed` |
| `future` | `receipt_after_check_time` |

Receipts here are those of Section 7.4.10, step L8: every `CHECKPOINT_RECEIPT` whose signature holds under Section 7.1 and that has no finding `RECEIPT_INVALID`. The pre-reach r5′ is the largest `tree_size` t of a good receipt for which every receipt with `tree_size` ≤ t is good or neutral; if there is none, r5′ = 0. The reach is min(r5′, t_m − 1) if a finding `LOGGED_ROOT_MISMATCH` exists (t_m as in Section 10.9.3), otherwise r5′. A day counts only by its own witnessing time stamp (Section 7.4.6). Condition (5) is present if no reason without an item applies and the reach is at least 1. Otherwise the reason is, in this order: `receipts_before_log_start` if every receipt is neutral; the code of the foremost bad receipt in chain order if r5′ = 0; `logged_root_mismatch` if r5′ ≥ 1 and the cap sets the reach to 0. If the reach ends before the last receipt, (5) is present, and the notes (Section 10.9.6) name what limits the reach.

So a day not yet due, a stale extract and an omitted leaf shorten the reach of level 3 instead of lifting it; level 2 remains untouched, and with an omitted leaf the vendor faces a finding against itself.

**On (6).** Condition (6) is present exactly when `anchor_history.completeness.status` is `established`; its reach is then `completeness.up_to_tree_size` and `count` the number of found history roots (`anchor_history.roots.found`). Otherwise `count` is 0, and its reason follows from the reason of the completeness:

| Reason in `anchor_history.completeness` (Section 8.8.4, step H11) | Reason of (6) |
|---|---|
| `not_supplied` | `anchor_history_not_supplied` |
| `no_request_time` | `requested_at_not_supplied` |
| `no_usable_page`, `owner_differs`, `issued_before_request` | `anchor_history_not_established` |
| `pages_missing` | `anchor_history_partial` |
| `contradiction`, `fork` | `anchor_history_contradiction` |
| `no_root_found` | `no_history_root_found` |
| `root_missing` | does not occur in the state `rated`: a `MERKLE_INCONSISTENT` from a history root yields `chain_invalid` |

Expected roots of the source `auditor` never suffice for (6): when they were recorded relative to the request is known only to the auditor.

Pages count for (2) with the source `anchor_history` and for (6) only under statements keys (Section 8.8.3). Level 3 therefore requires a role list or a pin as a statements key.

**On (7).** Condition (7) binds the state of the chain at the `tree_size` of a countersignature to the time stamp of the day on which the vendor log shows this countersignature: the receipt is a leaf of its chain day, the chain day a leaf of the day tree whose root the day entry carries, and the time stamp covers the day entry (Sections 7.4.2 to 7.4.6). For a receipt of the class `included` with d = day(`server_ts`), the day d is usable and c(d) is determined and witnessed. A receipt is credited if a triple with it passes every stage. Only time stamps of c(d) itself count, never a later day through `prev_hash` (Section 7.4.6). A defective time stamp forms no triple; a time stamp that violates Z.6 is defective for day entries (Section 7.5.7). Premature time stamps do not occur: a confirmed premature time stamp makes its day unusable (Section 7.4.10, step L2 (h)), and a receipt of such a day is never `included`. Condition (7) has no stage for roots from `keys/tsa/`, since the tokens come from the vendor log, not from the package. A time stamp of c(d) witnesses the state at most W after the end of the day, that is less than 72 hours after `server_ts` of the receipt; a time witness under (4) witnesses it at the interval of its requests. (7) credits a receipt only if at most G_q lies between its `server_ts` and the `genTime` of the time stamp. **Why 36 hours:** an honest vendor closes a day shortly after its end, at the latest by its due time of 06:00 UTC of the following day (heartbeat specification §9.9); a countersignature shortly after midnight then lies up to 30 hours before the stamp, and six hours remain for an outage of the authority. So the evidenced time lies not much further from the countersignature than with a daily time witness on the chain, and a vendor acting together with the customer can backdate a countersignature by at most this span before the stamp fixes its day (Section 11.2). A receipt counts for (7) whatever establishes its key, as for (5). Condition (7) reads neither the affiliation nor the time witnesses of the chain.

**Reasons** (registry `verifier.evidence_level.reasons`; the report outputs the text, the DE version is in the registry):

| Code | Condition | Text in the report |
|---|---|---|
| `no_time_anchor` | (1), (4) | no time witness in the chain |
| `no_tsa_root_supplied` | (1) | no root for time witnesses of the chain supplied (--tsa-root, --tsa-qualified-roots) |
| `signature_not_checkable` | (1), (4), (7) | neither the signature nor, for (4), the binding of the signer certificate of any of these time stamps can be checked under the time-stamp profile (7.5, Z.6) |
| `not_chained_to_auditor_root` | (1) | no time witness chains, at its genTime, to a root supplied |
| `published_test_key` | (1), (4), (7) | the authority uses a key whose private part is published (no witness) |
| `token_extensions_unusable` | (1), (4), (7) | the token carries an unknown critical or unreadable TSTInfo extension |
| `no_expected_root_found` | (2) | no expected root found in the package (none supplied, or the anchor history names only roots beyond the package end) |
| `no_receipt` | (3), (5) | no countersignature in the chain |
| `key_not_confirmed` | (3) | countersignatures consistent, but no anchor of the auditor confirms their key (--vendor-root, --vendor-key) |
| `key_is_device_key` | (3) | the key confirmed as the vendor's is a device key of this chain |
| `no_qualified_root_supplied` | (4) | no root named as qualified supplied (--tsa-qualified-roots) |
| `not_chained_to_qualified_root` | (4) | no time witness chains, at its genTime, to a root named as qualified |
| `qualified_root_in_package` | (4) | the root named as qualified has the same key as a certificate in the package's keys/tsa/ and does not count for this |
| `outside_qualified_window` | (4), (7) | genTime lies outside the period for which the auditor named the root as qualified |
| `signing_certificate_not_bound` | (4) | the token's signed attributes do not name the signer certificate, one of signingCertificate and signingCertificateV2 names another one, or one of them is not formed per Z.6 (RFC 3161 2.4.1, RFC 5816) |
| `qualified_statement_malformed` | (4), (7) | the token's qcStatements extension is unreadable |
| `no_qualified_statement` | (4), (7) | the token does not declare itself a qualified time stamp (qcStatements with esi4-qtstStatement-1, ETSI EN 319 422) |
| `vendor_log_not_supplied` | (5), (7) | no vendor log extract supplied (--vendor-log) |
| `vendor_log_not_established` | (5), (7) | extract supplied, but no protocol key established by an anchor of the auditor |
| `vendor_log_contradiction` | (5), (7) | the vendor log contradicts itself (VENDOR_LOG_CONTRADICTION) |
| `receipt_not_logged` | (5) | a countersignature is missing from the witnessed day of its vendor log (RECEIPT_NOT_LOGGED) |
| `day_timestamp_not_confirmed` | (5) | the day entry for the day of a countersignature is witnessed by no time stamp that a root of the auditor for the log confirms (--vendor-log-tsa-root) |
| `receipt_not_checkable` | (5) | for the day of a countersignature a chain-day record that holds is missing, or records or day entries contradict each other |
| `receipt_day_not_closed` | (5) | the day of a countersignature is not due yet; check again from 06:00 UTC of the following day |
| `receipt_after_check_time` | (5) | a countersignature carries a server_ts after the check time; no closed day can contain it |
| `log_day_not_supplied` | (5) | there is no day entry for the day of a countersignature; fetch a complete, current extract |
| `receipts_before_log_start` | (5) | all countersignatures lie before the start of the vendor log |
| `logged_root_mismatch` | (5) | a root recorded in the vendor log contradicts the package (LOGGED_ROOT_MISMATCH); level 3 ends before it |
| `anchor_history_not_supplied` | (6) | no anchor history supplied (--anchor-history) |
| `requested_at_not_supplied` | (6) | without a request time (--requested-at) completeness is not judged |
| `anchor_history_not_established` | (6) | anchor history supplied, but not established for this package (ANCHOR_HISTORY_UNVERIFIED) |
| `anchor_history_partial` | (6) | pages of the anchor history are missing (ANCHOR_HISTORY_UNVERIFIED) |
| `anchor_history_contradiction` | (6) | the anchor history contradicts itself, the receipts or the vendor log, or shows a second version (ANCHOR_HISTORY_CONTRADICTION, ANCHOR_HISTORY_FORK) |
| `no_history_root_found` | (6) | no root of the anchor history found in the package |
| `no_qualified_log_root_supplied` | (7) | no root supplied both for time stamps of the vendor log and as named qualified (--vendor-log-tsa-root and --tsa-qualified-roots) |
| `no_receipt_included` | (7) | no countersignature shown in the witnessed day of its vendor log |
| `not_chained_to_qualified_log_root` | (7) | no time stamp of a day with a countersignature shown chains, at its genTime, to a root supplied for the log and named as qualified |
| `qualified_day_stamp_late` | (7) | the time stamp of the authority named as qualified lies after the window of 48 hours after the end of the day (7.4.6) |
| `qualified_day_stamp_gap` | (7) | the time stamp of the authority named as qualified lies more than 36 hours after the countersignature (10.9.4) |

#### 10.9.5 Level, Reach, Course and Next Level

With N = number of entries of the package and reach(c) = `up_to_tree_size` of condition c if it is present, otherwise 0:

```
r0 = N
r1 = max(reach(1), reach(2), reach(3))
r2 = reach(3)
r3 = min(reach(3), max(reach(4), reach(7)), reach(5), reach(6)) if (3), (5), (6) and at least one of (4) and (7) are present, otherwise 0
lvl(p) = max{ k in 0..3 : r_k >= p }            for every position seq p with 1 <= p <= N
level = lvl(1)
up_to_tree_size = r_level, at level 0 equal to N
```

By construction r1 ≥ r2 ≥ r3; the level therefore never rises again along the chain. If (4) and (7) are both present, the larger reach counts.

**Course** (`segments`): the largest possible runs of consecutive positions with equal lvl(p), ascending by `seq`, each with `level`, `first_seq`, `last_seq` and `basis`. Their levels fall strictly, and they cover `seq` 1 to N without gaps. `basis` names what the run ends with, in the order of the registry (`condition_order`): at level 3 the present codes among (3) to (7) whose reach equals r3; at level 2 `receipt_key_confirmed`; at level 1 the present codes among (1) to (3) whose reach equals r1; at level 0 none.

**Next level** (`next`): in the state `rated` and at a level L below 3, `next` = `{level: L + 1, need: "any" for L = 0, otherwise "all", missing: [...]}`; `missing` names the conditions of level L + 1 that are not present, in the order of the registry. For level 3, (4) and (7) count as one condition: if neither is present, `missing` names both, and the report says that one of them suffices; if one is present, `missing` names neither. At level 0 one of conditions (1) to (3) suffices; from level 1 all conditions of the next level are needed. If condition (3) is missing at level 0, the report adds the sentence "A confirmed countersignature leads directly to level 2." At level 3 and outside the state `rated`, `next` is `null`; at level 3 the course names what the run of level 3 ends with.

Why the reach: an anchor for the `tree_size` t commits to the whole prefix 1 to t; every condition therefore holds for every shorter prefix. Without the reach, a confirmed receipt at `seq` 5 of a chain with 100,000 entries would read as level 2 of the whole chain. Why the headline names the level of `seq` 1: the level of the whole package would always be 0 because of the residual window, and the level at the last countersigned checkpoint would never show level 3 for a freshly exported package.

Reference values (course as level, `first_seq` to `last_seq`, `basis`):

| Case | N | Reaches of the present conditions | Result |
|---|---|---|---|
| KAT1 | 32 | (3) 28 | level 2 up to 28; 2 for 1 to 28 [`receipt_key_confirmed`]; 0 for 29 to 32 |
| KAT2 | 5050 | (1) 5000, (3) 1000, (4) 10, (5) 900, (6) 4990 | level 3 up to 10; 3 for 1 to 10 [`time_witness_qualified`]; 2 for 11 to 1000; 1 for 1001 to 5000 [`time_witness`]; 0 for 5001 to 5050 |
| KAT3 | 400 | (1) 398, (2) 390, (3) 396, (4) 398, (5) 300, (6) 390 | level 3 up to 300; 3 for 1 to 300 [`receipts_logged`]; 2 for 301 to 396; 1 for 397 to 398 [`time_witness`]; 0 for 399 to 400 |
| KAT4 | 16 | none | level 0; 0 for 1 to 16; `next` `{1, any, [time_witness, expected_root_found, receipt_key_confirmed]}` |
| KAT5 | 32 | (2) 14 | level 1 up to 14; 1 for 1 to 14 [`expected_root_found`]; 0 for 15 to 32 |
| KAT6 | 30 | (1) 20, (4) 20, (6) 28 | level 1 up to 20; 1 for 1 to 20 [`time_witness`]; 0 for 21 to 30; `next` `{2, all, [receipt_key_confirmed]}` |
| KAT7 | 320 | (1) 310, (3) 309, (4) 300, (5) 300, (6) 309 | level 3 up to 300; 3 for 1 to 300 [`time_witness_qualified`, `receipts_logged`]; 2 for 301 to 309; 1 for 310 to 310 [`time_witness`]; 0 for 311 to 320 |
| KAT8 | 400 | (3) 396, (5) 300, (6) 390, (7) 350 | level 3 up to 300; 3 for 1 to 300 [`receipts_logged`]; 2 for 301 to 396 [`receipt_key_confirmed`]; 0 for 397 to 400 |
| KAT9 | 400 | (1) 10, (3) 396, (4) 10, (5) 300, (6) 390, (7) 200 | level 3 up to 200; 3 for 1 to 200 [`log_day_qualified`]; 2 for 201 to 396 [`receipt_key_confirmed`]; 0 for 397 to 400 |
| KAT10 | 32 | (3) 28, (5) 28, (6) 28 | level 2 up to 28; 2 for 1 to 28 [`receipt_key_confirmed`]; 0 for 29 to 32; `next` `{3, all, [time_witness_qualified, log_day_qualified]}` (one of the two suffices) |

#### 10.9.6 Notes

Notes never change the level. Each stands in the report exactly when its occasion applies, once, in this order (registry `verifier.evidence_level.note_order`), only in the state `rated`:

| Code | Occasion | Text in the report |
|---|---|---|
| `material_contradiction` | findings of exit class 2 exist, all from `material_classes` | Presented plaintexts or reports contradict the chain (CONTENT_MISMATCH, REPORT_MISMATCH); the level applies to the chain, not to this material. |
| `unsealed_end` | `UNSEALED_END` exists | Chain end not sealed; the level applies to the entries present. |
| `stale_package` | `TRAILING_SILENCE` exists | The chain ends before the freshness window (TRAILING_SILENCE); the level says nothing about the time after it. |
| `package_not_fully_known` | `SPEC_NEWER`, `UNKNOWN_ENTRY_TYPE` or `UNKNOWN_MANIFEST_FIELD` exists | The package carries data this verifier version does not know; the level rests only on what it reads. |
| `vendor_root_builtin_only` | (3) is present, and the key of every credited receipt is established only through a list that the built-in vendor root carries | The vendor key is confirmed only through the vendor root built into this verifier; the level is only as independent as this build. |
| `published_test_key_credited` | a condition that is present rests on a key whose public key stands as an Ed25519 test key in `published_test_keys` (Section 7.5.7): for (3) the key of a credited receipt or the vendor root of its list, for (5) an established protocol key or the root of the effective protocol key list, for (2) with the source `anchor_history` and for (6) the key of a used page of the package on which (2) or (6) rests, or the vendor root of the role list that establishes this key (Section 8.8.3); a pinned statements key rests on no role list | The level rests on a published test key (published_test_keys); anyone can sign with it. The level thus proves nothing against a forgery. |
| `last_receipt_not_confirmed` | (3) is present, and the receipt that Section 8.6 chooses as the last countersigned one is not credited; `<t>` is the reach of (3) | The countersignature of the last countersigned checkpoint is confirmed through no anchor of the auditor; level 2 reaches tree_size `<t>`. |
| `expected_root_auditor_only` | level 1 at `seq` 1 rests only on (2), and every root credited for it carries only the source `auditor`; "rests only on (2)" means: the level at `seq` 1 is 1, and of the conditions of level 1 only (2) is present. The criterion is not `basis` of the first segment | Level 1 rests only on expected roots the auditor supplied; it holds as far as the auditor received them before the audit and from outside the audited organisation. |
| `tsa_root_in_package` | a root that (1) credits has the SPKI SHA-256 value of a certificate from `keys/tsa/` | A root for time-stamping authorities on which the level rests has the same key as a certificate in the package's keys/tsa/. This is no defect of the package; the auditor should have obtained it outside the package. |
| `history_recent_roots_skipped` | the anchor history gives the note `recent_roots_not_found` (Section 8.8.7) | Roots from the 15 minutes before the request lie beyond the package end; request the package again (heartbeat specification 9.7). |
| `receipts_pending_log` | a receipt has the class `pending` | Countersignatures of days whose entry is not due yet; check again from 06:00 UTC of the following day. |
| `receipt_not_logged` | `RECEIPT_NOT_LOGGED` exists | At least one countersignature is not shown in the vendor log (RECEIPT_NOT_LOGGED); level 3 ends before it, level 2 remains. |
| `log_day_not_supplied` | a receipt has the class `missing` | For days with countersignatures whose entry should already exist no day entry was supplied; fetch a complete, current extract. |
| `logged_root_mismatch` | `LOGGED_ROOT_MISMATCH` exists | A root recorded in the vendor log contradicts the package (LOGGED_ROOT_MISMATCH); level 3 ends before it, level 2 remains. |
| `cms_not_implemented` | the verifier does not perform steps 5 and 6 of Section 7.3 (never the case for the reference verifiers) | This verifier does not check signature and signature chain of time stamps (7.3); through time witnesses it reaches no level, and not level 3. |

Why `tsa_root_in_package` is only a note for level 1 and an exclusion for condition (4): `keys/tsa/` is a reading aid (Section 10.1), and an honest package of a third party that ships the root of its authority would otherwise lose level 1 although the auditor passed the genuine root; a forger would escape the exclusion by leaving the root out. For condition (4) the exclusion stays, because that condition is the binding to an authority attributable neither to the customer nor to the vendor, and a root copied from the package would let a self-built "qualified" witness be credited.

#### 10.9.7 Properties

Every property is a test of both reference verifiers:

1. If `NO_ANCHOR` exists and the state is `rated`, the level is 0; from level 1, `NO_ANCHOR` does not exist.
2. From level 2, at least one receipt holds under a key that an anchor of the auditor confirms.
3. At level 3, `anchor_history.completeness.status` is `established`.
4. The course covers `seq` 1 to N without gaps, with strictly falling levels; its foremost run has the level `level`.
5. `state` is `format_error` exactly when the exit code is 3.
6. Without the determination of the level, every run yields the same exit code and the same findings.
7. Both reference verifiers output identical objects `evidence_level` for the same inputs.

**Monotonicity.** The property is stated for runs in the state `rated`. For a package P and auditor inputs I ⊆ I′ (more roots for time stamps, pins, roots named as qualified, expected roots, anchor history pages, extracts, roots for the log) for which the run with I has the state `rated`, r_k(P, I′) ≥ r_k(P, I) holds for every k, unless the run with I′ has something the run with I does not have: the state `chain_invalid`; the state `format_error` (for instance an added `--requested-at` after the check time gives exit 3, Section 10.8); a finding `RECEIPT_NOT_LOGGED`, `LOGGED_ROOT_MISMATCH`, `VENDOR_LOG_CONTRADICTION`, `ANCHOR_HISTORY_CONTRADICTION` or `ANCHOR_HISTORY_FORK`; a finding `VENDOR_LOG_UNVERIFIED` with the reason "key in two roles" or "contradicting lists" (Section 7.4.10, step L1); a finding `ANCHOR_HISTORY_UNVERIFIED` with the reason `key_not_valid` or `signing_time_not_proven`; the status `not_effective` of `key_roles` with the reason `lists_contradictory` or `key_in_two_roles`, or an entry in `key_roles.pins_dropped` (Section 10.7.4); a finding `ANCHOR_HISTORY_UNVERIFIED` with the reason `key_not_established` or `key_other_role` where an additional input made the role list ineffective or caused a pin as a statements key to be dropped; or a finding `RECEIPT_UNVERIFIED` where an additional role list caused a pin as a countersigning key to be dropped. These exceptions arise when an additional input states the revocation, validity or role of a key: a newer key list with `widerrufen_ab`, a pin that equals a protocol key, a role list that gives a pinned key another role, or a second list of the same version with other content rightly takes the effect from a key. A changed input (another request time, another check time) does not fall under this. This is checked on every test vector with an audit environment `ledger-pruefumgebung/1` (Section 10.8): the audit environment of the corpus against that of the vector.

**Neutrality.** The same package with the affiliation `affiliated`, `not_affiliated`, `not_determined` and `not_checked` yields the same `level`, `up_to_tree_size` and `segments`.

#### 10.9.8 Texts

The texts are in the registry (`verifier.evidence_level`, DE and EN); the report outputs them unchanged. Names and texts of the levels:

| Level | Name | Text |
|---|---|---|
| 0 | self-statement | The chain is checked in itself. There is no evidence from a party independent of the key holder that the auditor has confirmed. |
| 1 | externally bound | At least one state of the chain is bound to a time witness whose authority a root of the auditor confirms, or to an expected root that the auditor supplies or that comes from a checked anchor history. |
| 2 | countersigned | At least one countersignature holds under a key an anchor of the auditor confirms. This level says nothing about completeness. |
| 3 | anchored and reconciled | In addition there are: a time stamp of an authority the auditor named as qualified whose token declares itself qualified, as a time witness on the chain or on the day entry of the vendor log in which the countersignature is shown; the proof of the countersignatures in witnessed days of the vendor log; completeness according to a checked anchor history issued after the request of the package. Entries after the latest anchored root remain in the residual window (section 11.2). |

Labels of the conditions in the report: (1) "time witness whose authority a root supplied by the auditor confirms (7.3)"; (2) "expected root of the auditor or from the anchor history found in the package (10.8)"; (3) "countersignature whose key an anchor of the auditor confirms (7.1)"; (4) "time witness of an authority the auditor named as qualified, whose token declares itself qualified"; (5) "countersignatures shown in witnessed days of the vendor log (7.4)"; (6) "completeness according to a checked anchor history issued after the request of the package (8.8)"; (7) "countersignatures shown in days of the vendor log whose entry carries a time stamp of an authority the auditor named as qualified, which declares itself qualified, at most 36 hours after the countersignature (7.4.6)".

Conclusion of every block of the evidence level (Section 10.10.3): "The evidence level supports statements on how strongly the chain presented is evidenced against rewriting by its key holder. It guarantees nothing and says nothing about the content of the calls. It is only as independent as this verifier and the inputs the auditor gave it."

For the texts: of a condition they say "present" or "missing" (DE "liegt vor" or "fehlt"). No name of a level contains "independent" (DE "unabhängig"). "Qualified" stands only as "named as qualified by the auditor" or "declares itself qualified", never as a statement on the status of an authority. No text says that the chain, the operator or LEDGER keeps to a regulation; as for every piece of evidence, the language rule of the duty coverage table applies (`spec/pflichten.en.md`, §4). No text names a particular vendor.

### 10.10 Report Data

From edition 1.10. This section fixes the data of the report that are not findings, alike for both reference verifiers: their place in the JSON output, their members and the text blocks. They are no part of the verdict and do not change the exit code (Section 10.3).

#### 10.10.1 Path and `null`

- **Path.** Report data that are not findings stand in the JSON output of the Go verifier under `stats`, in that of the second verifier at the top level, each with the same names and the same form: `completeness` (Section 8.6, from edition 1.10 with `sources`), `residual_window` and `unanchored_stretches` (Section 11.2), `key_roles` (Section 10.7.4), `vendor_log` (Section 7.4), `anchor_history` and `affiliation` (Section 8.8), `evidence_level` (Section 10.9) and every future datum of this kind. The member names are normative for both reference verifiers.
- **Always an object.** For every package that is not a format error, `key_roles`, `vendor_log`, `anchor_history`, `affiliation` and `evidence_level` are objects, also without the corresponding auditor input (`status` `not_supplied` or `not_checked`, respectively). A missing input is never a missing member.
- **Exit 3.** With a format error, `key_roles`, `vendor_log`, `anchor_history` and `affiliation` are `null`; `evidence_level` is present, with `state` `format_error` (Section 10.9.2). For `completeness`, `residual_window` and `unanchored_stretches` Sections 8.6 and 11.2 continue to apply: with a format error they are not assessed. The three members are then present with the value `null` ("not assessed") and are never left out.
- **No report.** An unusable invocation (Section 10.8) writes no report and none of these objects.
- **Instants.** Instants the verifier forms itself, from whole milliseconds or from an auditor input (for instance `requested_at` and `span`), it writes in the form `YYYY-MM-DDThh:mm:ss.sssZ`. Instants from signed objects it takes over character by character.
- **Order.** Lists of codes stand in the order of the registry; other lists in the order stated at their member.
- **Browser version.** Its result additionally carries `evidenceLevel` (number or `null`), `evidenceState` (string) and `affiliationStatus` (string or `null`); the complete objects stand in its member `json`. It MAY also carry the two lines under the verdict (Section 10.10.3) as `evidenceLine` and `affiliationLine` (string or `null`); they are text for the reader, not data for machines.

#### 10.10.2 Objects

Notation as in Section 7.4.8: `x?` means `x` or `null`.

**`key_roles`** (Section 10.7.4):

```
{"status":         "not_supplied" | "effective" | "not_effective",
 "reason":         "format" | "no_matching_root" | "signature" | "lists_contradictory"
                   | "key_in_two_roles" | null,
 "candidates":     int,
 "list":           {"version": int, "ausgestellt": rfc3339, "wurzel_id": key-id,
                    "root_source": "vendor_root" | "builtin", "ende_doppelbetrieb": rfc3339?}?,
 "statement_keys": [{"key_id": key-id, "source": "role_list" | "pinned"}],
 "pins_dropped":   [{"key_id": key-id, "pinned_as": "countersigning" | "statements" | "protocol",
                     "listed_as": code}],
 "notes":          [code]}
```

- `status` and `reason` under Section 10.7.4; `reason` is `null` for `not_supplied` and `effective`.
- `candidates`: the number of distinct role lists (step R1).
- `list`: the effective role list Q with the origin of its root (root of the auditor or built in), `null` without Q. A root that is built in and that the auditor also passes counts as `vendor_root`.
- `statement_keys`: the statements keys that can establish pages (pins that are not dropped, and entries of Q with the role `statements`), ascending by `key_id`. A key that is pinned and is also an entry of Q with the role `statements` (the same `key_id`) stands here once, with `source` `pinned`, since step R4 takes the pins first.
- `pins_dropped`: the dropped pins (step R3 (d)), ascending by `key_id`; `listed_as` is the role with which a list names the public key (a role from Q, `countersigning` for K_cs^L, `protocol` for the protocol key list).
- `notes`: the notes `unknown_role`, `receipt_key_other_role` and `pin_dropped`, where they apply, in this order.

Without a role list, `status` is `not_supplied`, `reason` and `list` are `null`, `candidates` is 0, and `statement_keys` names only pins.

**`vendor_log`** (Section 7.4.10, step L10):

```
{"status":             "not_supplied" | "no_protocol_key" | "checked",
 "log_id":             key-id?,
 "first_day":          date?,
 "key_source":         "list" | "pinned" | "list_and_pinned" | null,
 "key_list":           {"version": int, "ausgestellt": rfc3339, "wurzel_id": key-id,
                        "root_source": "vendor_root" | "builtin"}?,
 "places":             [string],
 "files":              int,
 "distinct_files":     int,
 "head":               {"day": date, "day_hash": hex64, "tree_size": int,
                        "witnessed": bool, "seen_in": int}?,
 "days":               {"supplied": int, "established": int, "witnessed": int,
                        "contradictory": int, "missing": int,
                        "signatures_not_checked": int},
 "tsa":                {"cms_checked": bool, "roots_supplied": int},
 "receipts":           {"included": int, "not_included": int, "unchecked": int,
                        "missing": int, "pending": int, "before_start": int,
                        "future": int, "included_up_to_tree_size": int?}?,
 "last_countersigned": "included" | "not_included" | "unchecked" | "missing"
                       | "pending" | "before_start" | "future" | null,
 "logged_roots":       {"matching_prefix": int, "matching_without_receipt": int,
                        "contradicting_prefix": int, "beyond_package": int,
                        "gap_witnesses": int}?,
 "foreign_chain_records": int}
```

- `status` under steps L0 and L1; `log_id` the `log_id` of the extracts; `first_day` the start F (step L2 (f)), `null` if F is unknown.
- `key_source`: how the protocol keys are established, by the effective list, by pins or by both; `key_list` names the effective list with the origin of its root (root of the auditor or built in); `places` its `orte` in the order of the list, empty without an effective list.
- `files` the number of extracts passed, embedded ones included (Section 8.8.2), `distinct_files` the number of those distinct by their bytes.
- `head` the head under step L4 with the day hash of c(head); `witnessed` says whether c(head) is witnessed.
- `days`: `supplied` the day objects after pooling (step L2), `established` the established ones, `witnessed` the usable days (step L3), `contradictory` the days with a finding `VENDOR_LOG_CONTRADICTION`, `missing` the missing days of the required range (step L7), `signatures_not_checked` the sum over all day objects after pooling (step L2), established or not, of the number of distinct elements of `additional_signatures` whose `alg` is not `ed25519` (distinct by `alg`, `key_id` and `signature`); elements with `alg` = `ed25519` never count here, not even under a key that is not established. `signatures_not_checked` is formed in the same cases as `supplied`. With status `no_protocol_key` step L2 does not run; `supplied` and `signatures_not_checked` are then 0.
- `tsa`: `cms_checked` says whether the verifier performs steps 5 and 6 of the profile (`true` for the reference verifiers); `roots_supplied` the number of roots of purpose `log`.
- `receipts`: the number of receipts per class (step L8); `included_up_to_tree_size` is the pre-reach r5′ of Section 10.9.4, `null` if it is 0. `receipts` is `null` if the status is not `checked`, since the classes are then undetermined.
- `last_countersigned`: the class of the receipt that Section 8.6 chooses as the last countersigned one; `null` without it or without the status `checked`.
- `logged_roots` (step L9): `matching_prefix` and `contradicting_prefix` count the distinct (`tree_size`, `merkle_root`) with t ≤ N that match or contradict the package, `matching_without_receipt` the distinct matching `countersigned` leaves without a receipt of the same leaf in the package (a receipt with `RECEIPT_INVALID` is a receipt of its leaf for this count), `beyond_package` those with t > N, `gap_witnesses` the distinct roots (`tree_size`, `merkle_root`) among the checked rows with `recorded_as` `gap_witness`, not the distinct leaves, including those that contradict the package or lie beyond it; `null` if the status is not `checked`.
- `foreign_chain_records`: the chain-day records of other chains (step L6); every record of every extract counts, also an equal record in several files.

Without an extract, `status` is `not_supplied`; `log_id`, `first_day`, `key_source`, `key_list`, `head`, `receipts`, `last_countersigned` and `logged_roots` are `null`, `places` is empty, and every counter is 0, `tsa.roots_supplied` included, also when the auditor passes roots of purpose `log`.

**`anchor_history`** (Section 8.8.4, step H13):

```
{"status":       "not_supplied" | "checked",
 "requested_at": rfc3339?,
 "files":        int,
 "pages":        {"supplied": int, "distinct": int, "used_fresh": int, "used_stale": int,
                  "used_unjudged": int, "used_linked": int, "not_used": int},
 "page_reasons": [code],
 "issued":       {"first": rfc3339?, "last": rfc3339?},
 "keys":         [{"key_id": key-id, "source": "pinned" | "role_list",
                   "list": {"version": int, "ausgestellt": string, "wurzel_id": key-id,
                            "root_source": "vendor_root" | "builtin"}?}],
 "owner":        "matches" | "differs" | null,
 "coverage":     {"status": "complete" | "partial" | "none", "gaps": [[int, int?]]},
 "reference_tree_size": int?,
 "predecessor":  {"chain_id": uuid, "tree_size": int}?,
 "successor":    {"chain_id": uuid, "tree_size": int}?,
 "roots":        {"distinct": int, "found": int, "differing_before_request": int,
                  "differing_after_request": int, "beyond_package_before_request": int,
                  "beyond_package_recent": int, "beyond_package_after_request": int,
                  "beyond_package_unjudged": int, "not_used_vendor_log": int},
 "forks":        {"listed": int, "omitted": int},
 "receipts":     {"checked": int, "in_history": int, "not_in_history": int,
                  "not_in_history_unestablished": int, "server_ts_differs": int,
                  "before_legacy_boundary": int, "not_covered": int},
 "completeness": {"status": "established" | "partial" | "not_established",
                  "reason": code?, "up_to_tree_size": int?},
 "reasons":      {"unverified": [code], "defective": [code],
                  "contradiction": [code], "fork": [code]},
 "notes":        [code]}
```

- `status` is `checked` as soon as an anchor history file is passed; `requested_at` is R or `null`; `files` the number of files.
- `pages`: `supplied` all pages of all files, `distinct` the distinct ones after step H1, the four kinds of used pages under step H2, number 10, and `not_used` the remaining distinct pages; `page_reasons` the reasons of step H2 at which pages not used failed, each once.
- `issued`: the earliest and the latest `server_ts` of the used pages of the package.
- `keys`: per `server_key_id` of a used page the origin under Section 8.8.3, ascending by `key_id`; `list` names the effective role list, `null` for a pin.
- `owner`: `matches` if a page of the package passed step H2, number 8; `differs` if pages of the package reached number 8 and none passed it; otherwise `null`.
- `coverage` under step H4; `gaps` are the gaps as ranges [a, b), with `null` for b = ∞, ascending by a.
- `reference_tree_size`, `predecessor` and `successor` are the values of the page H* (Section 8.8.6, number 3), `null` without it.
- `roots`: `distinct` the history roots (step H6), `found` the found ones (Section 8.8.5); `differing_before_request` the roots with t ≤ N that contradict the package and, with R passed, have an e before R − W_h (step H6), whether they yield `MERKLE_INCONSISTENT` or, only reported, `ANCHOR_HISTORY_FORK`, `differing_after_request` the other contradicting ones; `beyond_package_before_request` the roots with t > N and e < R − W_h, whether they yield `MERKLE_INCONSISTENT` or, only reported, `ANCHOR_HISTORY_FORK`; the three further counters under Section 8.8.5 and `not_used_vendor_log` under step H7. A pair that also carries the source `auditor` is counted here like every history root, by t, `root(t)`, e and R; its finding follows Section 10.8.
- `forks`: `listed` the distinct fork findings (t, r) under step H9, `omitted` the largest value of `forks_omitted` on used pages of the package.
- `receipts`: the counters of step H10, `checked` the number of receipts that step H10 checks.
- `completeness`: the result of step H11; `reasons`: per finding class the reasons reported (Section 8.8.7); `notes`: the notes of Section 8.8.7.

Without an anchor history, `status` is `not_supplied`, every counter is 0, every list empty, `issued.first`, `issued.last`, `owner`, `reference_tree_size`, `predecessor` and `successor` are `null`, `coverage` is `{"status": "none", "gaps": []}` and `completeness` is `{"status": "not_established", "reason": "not_supplied", "up_to_tree_size": null}`; `requested_at` and the note `requested_at_unused` follow Section 10.8.

**`affiliation`** (Section 8.8.6):

```
{"status":        "affiliated" | "not_affiliated" | "not_determined" | "not_checked",
 "reason":        code?,
 "bases":         [code],
 "vendor_itself": bool,
 "span":          {"from": rfc3339, "to": rfc3339}?,
 "as_of":         rfc3339?,
 "known_since":   rfc3339?,
 "stated_by":     {"server_key_id": key-id,
                   "key_source": "pinned" | "role_list_auditor_root" | "role_list_builtin_root"}?,
 "periods":       [{"bases": [code], "from": rfc3339, "until": rfc3339?,
                    "recorded_ts": rfc3339, "merged": bool, "overlaps_package": bool}],
 "receipts_total": int?, "receipts_in_periods": int?, "receipts_after_statement": int?,
 "contradictory": bool,
 "linked":        [{"chain_id": uuid, "relation": "predecessor" | "successor",
                    "status": "affiliated" | "not_affiliated" | "not_determined",
                    "periods": [...]}]}
```

- `reason`: for `not_determined` the reason (Section 8.8.6, numbers 2 and 7), otherwise `null`.
- `bases`: for `affiliated` the union of the bases of the periods that overlap the period of the package, in the order of the codes of heartbeat specification §9.10, otherwise empty; `vendor_itself` is `true` if `vendor` is among them.
- `span` the period of the package (number 5), `as_of` and `known_since` the values of the page H*, `stated_by` its key with the key's origin.
- `periods`: all periods under number 4, each with `overlaps_package` (number 8). `until` is the end under number 4, `null` only for a period that continues on H*. Equal objects (equal by the bytes of their JCS form) stand once; they are ordered ascending by `from`, then by `until` (`null` last), then by the bytes of JCS(`bases`), then by `recorded_ts`, then `merged` `false` before `true`, then `overlaps_package` `false` before `true`; the three counters under number 10; `contradictory` under number 9; `linked` per linked chain under number 11, ascending by `chain_id`.

Without a used page of the package (status `not_checked`, or `not_determined` under number 2), `span`, `as_of`, `known_since`, `stated_by` and the three counters are `null`, `bases` and `periods` are empty, and `vendor_itself` and `contradictory` are `false`.

**`evidence_level`** (Section 10.9):

```
{"state":           "rated" | "chain_invalid" | "format_error",
 "level":           int (0 … 3)?,
 "entries":         int?,
 "up_to_tree_size": int?,
 "segments":        [{"level": int, "first_seq": int, "last_seq": int, "basis": [code]}],
 "conditions":      {"time_witness": C, "expected_root_found": C, "receipt_key_confirmed": C,
                     "time_witness_qualified": C, "receipts_logged": C,
                     "completeness_from_history": C, "log_day_qualified": C}?,
 "next":            {"level": int (1 … 3), "need": "any" | "all", "missing": [code]}?,
 "qualified_time":  {"via": "time_witness_qualified" | "log_day_qualified", "tree_size": int,
                     "latest": rfc3339, "gap_ms": int?}?,
 "anchors":         {"vendor_keys": [{"key_id": key-id, "via": "pinned" | "list",
                                      "list_version": int?, "root_id": key-id?,
                                      "root_from": "auditor" | "builtin" | null}],
                     "statement_keys": [{"key_id": key-id, "via": "pinned" | "role_list",
                                         "list_version": int?, "root_id": key-id?,
                                         "root_from": "auditor" | "builtin" | null}],
                     "tsa_roots": [{"cert_sha256": hex64, "credited_for": [code]}],
                     "qualified_roots_file": {"stand": rfc3339, "quelle": string}?,
                     "expected_root_sources": ["auditor" | "anchor_history"]}?,
 "affiliation":     {"status": string, "vendor_itself": bool}?,
 "notes":           [code]}
C = {"met": bool, "count": int, "up_to_tree_size": int?, "reason": code?}
```

- `level`, `entries` (N), `up_to_tree_size`, `conditions`, `next`, `qualified_time` and `anchors` are `null`, and `segments` and `notes` empty, if the state is not `rated`.
- `qualified_time`: at level 3 at `seq` 1, the item that evidences the qualified time for the state up to `up_to_tree_size`. Candidates are the credited items of (4) (TIME_ANCHOR per root) and of (7) (receipt per time stamp and root) with `tree_size` ≥ `up_to_tree_size`; chosen is the one with the earliest `genTime`, on a tie (4) before (7), then the smaller `tree_size`, then for (7) the earlier `server_ts` of the receipt. "The one with the earliest `genTime`" compares `genTime` as an instant to the nanosecond, like the periods of Section 10.8, before any truncation to whole milliseconds; a tie means the same instant. `via` names the condition, `tree_size` that of the item, `latest` its `genTime`, truncated to whole milliseconds, in the form `YYYY-MM-DDThh:mm:ss.sssZ`: the state existed at the latest at this time. `gap_ms` is for (7) `latest` minus `server_ts` of the receipt in whole milliseconds, for (4) `null`. Below level 3 at `seq` 1, `qualified_time` is `null`.
- `anchors.vendor_keys`: per key of a credited receipt, ascending by `key_id`, how it is established (pin, or list with version, `wurzel_id` and origin of the root).
- `anchors.statement_keys`: without repetition, the pairs of statements key and origin (`key_id`, public key, origin) of the used pages of the package on which a condition that is present rests: for (2) with the source `anchor_history`, the used pages that carry a recording of a found expected root that is recorded (`recorded_as` contains `countersigned` or `gap_witness`, Section 8.8.5); for (6), when it is present, every used page that enters the completeness (Section 8.8.4, step H11). (6) thus rests on the fresh used pages of the package: only they enter the completeness, an older page never does (Section 8.8.4, "Older pages"), and (6) requires R. The note `published_test_key_credited` (Section 10.9.6) and `<anchors>` in the block of the evidence level (Section 10.10.3) refer to the same pages where they name the pages on which (6) rests. For a page, the pair is the one the report names for that page in `anchor_history`; if it names several, each of them. Each pair states how the key is established (pin or role list with version, `wurzel_id` and origin of the root), in the order of `anchor_history.keys`; empty without such a page.
- **Names of the origin.** A pin is called `pinned` in every object. The origin of a root is called `vendor_root` or `builtin` in `key_roles.list.root_source`, `vendor_log.key_list.root_source` and `anchor_history.keys[].list.root_source`, `auditor` or `builtin` in `evidence_level.anchors.vendor_keys[].root_from` and `evidence_level.anchors.statement_keys[].root_from` and `role_list_auditor_root` or `role_list_builtin_root` in `affiliation.stated_by.key_source`. `vendor_root`, `auditor` and `role_list_auditor_root` denote the same origin: a vendor root the auditor passed.
- `anchors.tsa_roots`: per root that (1), (4) or (7) credits, ascending by `cert_sha256`, the SHA-256 value of its certificate (DER) as fingerprint; `credited_for` names these conditions in the order of the registry, for instance `["time_witness"]`, `["time_witness", "time_witness_qualified"]` or `["log_day_qualified"]`.
- `anchors.qualified_roots_file`: `stand` and `quelle` of the file `ledger-tsa-qualifiziert/1` (Section 10.8), `null` without it. The verifier writes `stand` in the form `YYYY-MM-DDThh:mm:ss.sssZ`, truncated to whole milliseconds, like every instant from an auditor input (Section 10.10.1, Instants); it copies `quelle` as written; `anchors.expected_root_sources`: the sources of the roots that (2) credits, in the order `auditor`, `anchor_history` as in `completeness.sources` (Section 8.6).
- `affiliation`: `status` and `vendor_itself` of the object `affiliation`, also in the state `chain_invalid`; `null` only in the state `format_error`.

Example (test vector `valid_basic` in the audit environment of the corpus, one line, members in JCS order):

```
{"affiliation":{"status":"not_checked","vendor_itself":false},"anchors":{"expected_root_sources":[],"qualified_roots_file":null,"statement_keys":[],"tsa_roots":[],"vendor_keys":[{"key_id":"vendor-test-001","list_version":null,"root_from":null,"root_id":null,"via":"pinned"}]},"conditions":{"completeness_from_history":{"count":0,"met":false,"reason":"anchor_history_not_supplied","up_to_tree_size":null},"expected_root_found":{"count":0,"met":false,"reason":"no_expected_root_found","up_to_tree_size":null},"log_day_qualified":{"count":0,"met":false,"reason":"vendor_log_not_supplied","up_to_tree_size":null},"receipt_key_confirmed":{"count":12,"met":true,"reason":null,"up_to_tree_size":309},"receipts_logged":{"count":0,"met":false,"reason":"vendor_log_not_supplied","up_to_tree_size":null},"time_witness":{"count":0,"met":false,"reason":"no_time_anchor","up_to_tree_size":null},"time_witness_qualified":{"count":0,"met":false,"reason":"no_time_anchor","up_to_tree_size":null}},"entries":311,"level":2,"next":{"level":3,"missing":["time_witness_qualified","receipts_logged","completeness_from_history","log_day_qualified"],"need":"all"},"notes":["unsealed_end","published_test_key_credited"],"qualified_time":null,"segments":[{"basis":["receipt_key_confirmed"],"first_seq":1,"last_seq":309,"level":2},{"basis":[],"first_seq":310,"last_seq":311,"level":0}],"state":"rated","up_to_tree_size":309}
```

The schemas `spec/schemas/report_key_roles.schema.json`, `report_vendor_log.schema.json`, `report_anchor_history.schema.json`, `report_affiliation.schema.json` and `report_evidence_level.schema.json` are generated from the registry; every run over the test corpus checks the output of both reference verifiers against them.

#### 10.10.3 Text Blocks

Both reference verifiers output the same blocks in the text report, in this order, every phrase from the registry, in the language of the report, with `<…>` replaced: the existing summary lines (chain end, completeness, residual window, covered stretches, vendor key list, note on the licence); the block of the vendor log; the block of the anchor history; the block of the evidence level, whose last line is the line on affiliation; then "No findings." or the findings. With exit 3 the blocks of the vendor log and of the anchor history and the line on affiliation are dropped. The text report has no block for `key_roles` in this edition; the object appears only in the JSON output (Section 10.10.2).

**Vendor log.**

- Status `checked`: three lines from the texts `checked_head`, `receipts` and `compare` of the registry (`vendor_log.texts`), in this order; the first stands unindented, the other two are indented by two spaces, as in the block of the anchor history:

```
Vendor log <log_id>: head <day>, day hash <day_hash>, witnessed: <yes|no>, in <seen_in> of <distinct_files> files.
  Receipts: <included> shown, <not_included> missing, <unchecked> not checkable, <missing> without day entry, <pending> not due yet, <before_start> before the start of the log, <future> after the check time.
  Compare the day hash with the second place of publication.
```

  If no head is determined (Section 7.4.10, step L4), the first line reads "Vendor log `<log_id>`: no day entry established." (text `checked_no_head`). Only this line is replaced; the other two stay, including the line on comparing the day hash.
- Status `no_protocol_key`: "Vendor log supplied, but no protocol key established by an anchor of the auditor (`<reason>`)." with the reason of step L1, number 4.
- Status `not_supplied`: "Vendor log: not supplied. This report does not say whether the vendor logged the receipts (section 7.4)."

**Anchor history.**

- With used pages of the package:

```
Anchor history: <u> of <d> pages used (<f> issued after the request, <s> older copies), issued <first> to <last>, key <key_id> (<source>); device of the chain: matches the package.
  Request of the package: <R> (auditor input).
  Roots: <n> distinct; up to tree_size <N>: <found> found, <diff> differ; beyond: <b> recorded before the request, <r> in the 15 minutes before it (request the package again), <a> after it.
  Completeness from the anchor history: evidenced up to tree_size <T>. | not evidenced (<reason>).
```

  Here `<u>` is the number of used pages of the package, `<d>` `pages.distinct`, `<f>` `used_fresh`, `<s>` `used_stale`, `<diff>` the sum of `differing_before_request` and `differing_after_request`, and `<b>`, `<r>` and `<a>` the counters `beyond_package_before_request`, `beyond_package_recent` and `beyond_package_after_request`; with several keys "`<key_id>` (`<source>`)" stands once per key. `<source>` is "pinned", "role list version `<v>`, auditor's root `<w>`" or "role list version `<v>`, root `<w>` built into this verifier". Without a request time the second line reads "Without a request time (--requested-at) a truncation of the package is not judged; `<n>` roots beyond the package end are counted, not judged." with `<n>` = `beyond_package_unjudged`.
- Passed, but no page of the package used: "Anchor history: `<d>` pages supplied, none used for this package (`<reasons>`)." with the texts of the reasons from `page_reasons`; if `owner` is `differs`, the text `owner_differs_detail` (registry `verifier.anchor_history.texts`) follows as the second line; then the line on completeness.
- Not passed: "Anchor history: not supplied. Whether the package holds everything the vendor recorded before the request is therefore not checked. Fetch the history with the chain_id `<id>` from the vendor yourself (GET /v1/anchors?chain_id=`<id>`&kind=ledger.anchor_history.v2) and pass it with --anchor-history and --requested-at."

**Evidence level.**

```
Evidence level: <level> of 3 (<name>), evidenced for seq 1 to <up_to_tree_size> of <N>.
  Course: level <l> for seq <first_seq> to <last_seq> (ended by: <conditions>); …
  <text of the level>
  qualified confirmation: at the latest <latest> (time witness of the chain, tree_size <t>) | at the latest <latest> (time stamp of the vendor log, tree_size <t>, <gap> after the countersignature)
  present: <condition> (<count>, up to tree_size <t>; <anchors>)
  for level <n> one of these conditions is missing: | for level <n> missing, all needed:
    - <condition>: <reason>
    - <condition (4)> or <condition (7)>: <reason of (4)>; <reason of (7)>
  Note: <text>
  <conclusion under Section 10.9.8>
  <line on affiliation>
```

- Headline at level 0: "Evidence level: 0 of 3 (self-statement), seq 1 to `<N>`." If findings of exit class 2 exist only from `material_classes`, the headline begins with "Evidence level of the chain:".
- "Course" names every run; "ended by" names the labels from `basis` and is dropped at level 0. "present" stands per present condition; `<anchors>` names, for (3), the keys of the credited receipts as `anchors.vendor_keys` does ("pinned key `<key_id>`" or "key `<key_id>` from list version `<v>`, `<source of the root>`") and, for the other conditions, the anchors those conditions name: the fingerprints of the crediting roots for time stamps and, for (4) and (7), `stand` and `quelle` of the file of qualified roots, the sources of the expected roots, for (5) and (7) the `log_id` and for (6) `as_of` of the anchor history and the statements keys of the pages on which (6) rests: the fresh used pages of the package that enter the completeness (Section 8.8.4, step H11), not every pair of `anchors.statement_keys`; each pair once, in the order of `anchor_history.keys`. Several anchors in `<anchors>` and several sources in the text `anchor_expected_sources` are joined with ", " (comma and space).
- Every follow-up line of the block is indented by two spaces, the lines of the missing conditions by four.
- The "missing" lines stand, at a level below 3, under `next`, one per missing condition with the text of its reason; at level 0, if (3) is missing, the line "A confirmed countersignature leads directly to level 2." follows after the missing conditions, a line of the block indented by two spaces.
- The line "qualified confirmation" stands exactly when `qualified_time` is not `null`, directly after the text of the level; `<latest>` is `qualified_time.latest`, `<gap>` `gap_ms` in whole minutes, rounded down, as "`<h>` h `<m>` min": with M = `gap_ms` in whole minutes, rounded down, `<h>` = M div 60 and `<m>` = M mod 60, both without leading zeros (for instance "0 h 10 min" for 600 000 ms and "36 h 0 min" for 129 600 000 ms). If both (4) and (7) are missing for level 3, they stand in one line "`<condition (4)>` or `<condition (7)>`" with both reasons; the line stands in the place of (4).
- State `chain_invalid`: the line "Evidence level: none (chain invalid)", then the conclusion and the line on affiliation. State `format_error`: the line "Evidence level: not determined (format error)", then the conclusion. These follow-up lines are lines of the block, indented by two spaces.

Example (test vector `valid_basic` in the audit environment of the corpus):

```
Evidence level: 2 of 3 (countersigned), evidenced for seq 1 to 309 of 311.
  Course: level 2 for seq 1 to 309 (ended by: countersignature whose key an anchor of the auditor confirms (7.1)); level 0 for seq 310 to 311.
  At least one countersignature holds under a key an anchor of the auditor confirms. This level says nothing about completeness.
  present: countersignature whose key an anchor of the auditor confirms (7.1) (12, up to tree_size 309; pinned key vendor-test-001)
  for level 3 missing, all needed:
    - time witness of an authority the auditor named as qualified, whose token declares itself qualified or countersignatures shown in days of the vendor log whose entry carries a time stamp of an authority the auditor named as qualified, which declares itself qualified, at most 36 hours after the countersignature (7.4.6): no time witness in the chain; no vendor log extract supplied (--vendor-log)
    - countersignatures shown in witnessed days of the vendor log (7.4): no vendor log extract supplied (--vendor-log)
    - completeness according to a checked anchor history issued after the request of the package (8.8): no anchor history supplied (--anchor-history)
  Note: Chain end not sealed; the level applies to the entries present.
  Note: The level rests on a published test key (published_test_keys); anyone can sign with it. The level thus proves nothing against a forgery.
  The evidence level supports statements on how strongly the chain presented is evidenced against rewriting by its key holder. It guarantees nothing and says nothing about the content of the calls. It is only as independent as this verifier and the inputs the auditor gave it.
  Affiliation with the vendor: NOT CHECKED. This statement comes from the vendor's anchor history, not from the verification package. Fetch the anchor history with the chain_id 18b0ad26-30f2-40b4-88fd-b5dc2926666d from the vendor yourself and pass it with --anchor-history. Whether the countersigner is affiliated with the customer is therefore open; level 2 says nothing about it.
```

**Line on affiliation** (registry `verifier.affiliation.texts`; for every report with an exit code other than 3, also in the state `chain_invalid`):

| Status | Line |
|---|---|
| `affiliated` | Affiliation with the vendor: AFFILIATED according to the vendor (`<bases>`; `<periods>`). `<k>` of `<n>` countersignatures of this package fall into this time. For this time a countersignature of the vendor evidences no party independent of the customer. A time witness binds the time to a third party only if the time-stamping authority is attributable neither to the customer nor to the vendor; the verifier does not check this. The statement comes from the anchor history of `<as_of>` (key `<key_id>`, `<source>`); the verifier checks signature, form, binding to chain and device and the comparison with other pages supplied, not its correctness. |
| `affiliated` with `vendor_itself` | as above; the sentence at the beginning reads "Affiliation with the vendor: AFFILIATED according to the vendor: the customer is the vendor itself (`<periods>`)." |
| `not_affiliated` | Affiliation with the vendor: none in the period of this package (`<from>` to `<to>`, vendor times) according to the vendor in the anchor history of `<as_of>` (key `<key_id>`, `<source>`). The verifier checks signature and form of this statement, not its correctness. If there are periods outside it, "Outside the period of this package the vendor states an affiliation: `<periods>`." follows. |
| `not_determined` | Affiliation with the vendor: NOT DETERMINED (`<reason>`). |
| `not_checked` | Affiliation with the vendor: NOT CHECKED. This statement comes from the vendor's anchor history, not from the verification package. If the package carries a receipt whose signature holds, "Fetch the anchor history with the chain_id `<id>` from the vendor yourself and pass it with --anchor-history." follows, otherwise "For a chain from which the vendor never accepted an anchor it keeps no anchor history; then this source gives no statement, not even for an affiliated customer (section 11.2)." |

With `not_checked` and `not_determined`, from level 2 the sentence "Whether the countersigner is affiliated with the customer is therefore open; level 2 says nothing about it." follows. `<k>` is `receipts_in_periods`, `<n>` `receipts_total`. `<bases>` are the labels of the codes of heartbeat specification §9.10; `<periods>` read, per period, "from `<from>`, ongoing" or "`<from>` to `<until>`", with "(merged)" for `merged`. `<source>` as in the block of the anchor history. No text calls a time witness independent.

| Reason for `not_determined` | Text |
|---|---|
| `history_owner_differs` | the anchor history belongs to another device than this package |
| `history_key_not_established` | key of the anchor history not established by a trust anchor of the auditor |
| `history_key_not_valid` | key of the anchor history not valid at the issue time |
| `history_signing_time_not_proven` | page under a revoked key without proof of its issue time |
| `history_not_v2` | pages supplied are not of kind ledger.anchor_history.v2 |
| `history_defective` | signature of the anchor history does not hold |
| `history_contradictory` | anchor history violates its own format |
| `history_other_chain` | anchor history of another chain |
| `known_range_too_short` | the vendor can name the customer of this chain from `<known_since>` on; if `known_since` is `null`: the vendor currently cannot name the customer of this chain for any time |
| `statement_does_not_cover_package` | the anchor history is older than the request of the package or than its latest countersignature |
| `history_pages_missing` | pages of the anchor history are missing; without all pages "not affiliated" is not established |
| `history_no_package_page` | no page of the anchor history of this chain supplied |

**Browser version.** Under the verdict stand two lines: the level with its reach (for instance "Evidence level: 2 of 3, evidenced up to seq 309 of 311", registry `verifier.evidence_level.texts.browser`) and the status of the affiliation as the last line of the evidence level block states it. At level 0 the first line reads like the head line of level 0 (`head_level0`), in the states `chain_invalid` and `format_error` like the line of the state (`state_line`), because "evidenced up to seq N" would read as evidence where there is none. If only classes from `material_classes` give exit 2, it begins with the label of the chain like the text block. A call that is unusable has neither line. The colour of the verdict stays bound to the exit code. The page offers inputs for several anchor history files, extracts, key lists (including the role list) and PEM files for time stamps, for the file of qualified roots, for pins as statements keys and a field for the request time (Section 10.8).

## 11. Attacker Model and Limits of Proof

### 11.1 Manipulation Classes and Detection

| Class | Attack | Detection |
|---|---|---|
| `rewrite` | rewriting an entry | hash chain (`HASH_MISMATCH`), signatures (`SIG_INVALID`), Merkle roots, time witnesses (Section 7.3) |
| `truncate` | truncating the chain against anchored roots | consistency proofs against anchors and expected roots (`MERKLE_INCONSISTENT`), handover (`HANDOVER_BROKEN`), chain end (`UNSEALED_END`, Section 8.6) |
| `fork` | second history against receipts/consistency proofs, also with self-signed "receipts" under an invented vendor key | receipt prefix check (`FORK_DETECTED`, `RECEIPT_INVALID`), origin of the vendor key (`RECEIPT_UNVERIFIED`, Section 7.1), cloud-side `tree_size` monotonicity, freshness |
| `clock` | backdating against mono_delta/server time | `CLOCK_ANOMALY`, time-witness `genTime` (`TIME_ANCHOR_INVALID`); the receipts' `server_ts` is a time signed by the vendor, but the verifier compares it with no other time of the chain; it reports nothing on it |
| `silent_gap` | concealed silence without a covering GAP | TICK coverage (`CONCEALED_SILENCE`) |
| `vendor_omission` (from edition 1.10) | the vendor omits a countersignature it issued from the vendor log or the anchor history | `RECEIPT_NOT_LOGGED` (Section 7.4.10, step L8) and `ANCHOR_HISTORY_CONTRADICTION` with reason `receipt_not_in_history` (Section 8.8.4, step H10), both only for a receipt that stands in the presented package; a data loss at the vendor looks the same |
| `vendor_split_view` (from edition 1.10) | the vendor shows different auditors different versions of the vendor log or the anchor history | `VENDOR_LOG_CONTRADICTION` and `ANCHOR_HISTORY_CONTRADICTION` when both versions are before the same verifier; comparison of the day hash with the second place of publication and among auditors; check of the day leaves (Section 7.4.9), which the verifier does not perform |
| `collusion` (from edition 1.10) | vendor and customer act together, for instance with an affiliated customer: they truncate or rewrite the chain and issue countersignature and anchor history to match | against a rewrite only time witnesses of an authority attributable to neither of them whose root the auditor supplies (Section 7.3); against a truncation only a chain-day record of a witnessed day that the auditor already holds, or a comparison of the public day leaves by hand, which the verifier does not perform (Section 11.2); condition (7) does not help here, since the vendor chooses the authority of the day entry, and a newly issued countersignature stands with its own `server_ts` in a later day (Section 10.9.4); the statement on affiliation (Section 8.8.6) shows where this risk exists |

Roles: **An external attacker without keys** fails against the hash chain and signatures. **The key holder** (the customer) can produce formally valid entries anew, but fails against already anchored roots: any history that is not prefix-consistent with every anchored root fails the consistency check. New "receipts" for its rewrite it can only sign under a key it holds itself; no anchor of the auditor has established that key, and the verifier reports `RECEIPT_UNVERIFIED` (Section 7.1). **The vendor** never holds the customer key and therefore cannot produce valid entries; it sees no content. It can refuse a countersignature, fail to record a root, issue a countersignature without logging it, or deliver an anchor history incompletely. What it has logged for a witnessed day of the vendor log (from edition 1.10, Section 7.4) it cannot take back afterwards; different versions of a day for different auditors show on comparison of the day hashes, different records under the same day root only on a check of the day leaves (Section 7.4.3). Its statement on affiliation with the customer is a statement of its own (Section 11.2); if the customer is affiliated with it, the role analysis of the key holder applies to both together.

### 11.2 Honest Limits of Proof

- **Residual window:** entries between the last countersigned checkpoint and the end of the chain are not yet externally anchored. The key holder could rewrite this **residual window** without trace before the next receipt arrives. The format does not bound its size: in licensed operation with a connection to the vendor it usually spans a few minutes (one anchor every 5 minutes), after a licence lapse, with egress switched off or in an old export any amount. The verifier MUST therefore **measure and state** it for every package that is not a format error (from edition 1.9): T is the `tree_size` of the last countersigned checkpoint per Section 8.6 (0 if there is none), N the number of entries. The residual window is the entries `seq` T+1 to N; to be stated are T, T+1, N, the count N − T, `ts_chained` of `seq` T (not for T = 0) and of `seq` N, the duration between them in milliseconds (Section 2; not for T = 0), the number of `ADMIN` entries with `message_type = anchor` after the receipt of that checkpoint (anchors sent without a countersignature in the package) and whether the window exceeds the cadence (T = 0 or a duration above 450,000 ms). In the JSON output of both reference verifiers the object is called `residual_window` with the members `after_tree_size`, `first_seq`, `last_seq`, `entries`, `from_ts`, `to_ts`, `span_ms`, `unanswered_anchor_messages` and `beyond_cadence`. With a format error the residual window is not assessed; `residual_window` then has the value `null` and is never left out. The residual window is not a finding and does not change the exit code; if it exceeds the cadence, the report names the possible causes (licence lapse, egress off, vendor unreachable, old export) and the comparison of Section 8.6. A time witness per Section 7.3 does not shrink the window, but it changes who can exploit it: it moves the statement to an authority controlled by neither customer nor vendor; whoever rewrites the history would have to produce a token with an earlier `genTime`, which they do not have. Without a trust anchor of the auditor's own, that too remains self-reported (`TIME_ANCHOR_UNVERIFIED`).
- **Covered stretches (from edition 1.10):** if more than the anchoring cadence lies between two consecutive countersigned checkpoints (`tree_size` T1 and T2, T1 < T2), that is more than 450,000 ms between `ts_chained` of `seq` T1 and of `seq` T2, the verifier MUST state this stretch for every package that is not a format error: `seq` T1+1 to T2, `ts_chained` of `seq` T1 and of `seq` T2, the duration between them in milliseconds (Section 2), the number of `ADMIN` entries with `message_type = anchor` in the stretch after the receipt of T1 (anchor messages without a countersignature of their own, counted as for the residual window), and `seq` and `server_ts` of the receipt of T2 that covers the stretch. A checkpoint is countersigned when Section 8.6 admits its receipt for choosing the last countersigned checkpoint; on equal `tree_size` the first receipt in chain order counts. In the JSON output of both reference verifiers the list is called `unanchored_stretches`, each stretch with the members `after_tree_size` (T1), `first_seq`, `last_seq`, `from_ts`, `to_ts`, `span_ms`, `unanswered_anchor_messages`, `receipt_seq` and `receipt_server_ts`; without such a stretch it is empty; with a format error it has the value `null` (not assessed) and is never left out. A stretch is not a finding and does not change the exit code; an honest chain never becomes invalid through it. So even after a renewal the report shows how long the chain ran without a countersignature (after a licence lapse, say, or with egress switched off for a while). The entries before the first countersigned checkpoint are no covered stretch in this sense; they stand in the package like any other entry.
- **Without a trust anchor of the auditor** a receipt only proves self-consistency: signature, checkpoint and prefix are checked in full, but the key comes from the package (`RECEIPT_UNVERIFIED`, Section 7.1). The statement "countersigned by the vendor" holds only with the vendor root or a pinned key.
- **Without any anchor** (air-gap, egress off), evidentiary strength against the key holder drops to the freshness/paper-anchor level; the verifier reports this as `NO_ANCHOR`. Against external manipulation, the chain remains fully evidential.
- **Fork detection needs reference points:** a rollback is only detected when at least one newer receipt, a newer paper anchor or the freshness window contradicts it.
- **Licence lapse (from edition 1.8):** once term and grace period have ended, the vendor no longer countersigns anchors. It does, however, keep checking them for consistency and records their roots as gap witnesses (heartbeat specification §9.2). The verification package holds no receipt for this period; every entry since the last receipt lies in the residual window, which, judged from the package alone, the key holder could rewrite. At the vendor, however, a rewrite reaches back only to the latest gap witness. An auditor assessing such a package SHOULD fetch the chain's signed anchor history from the vendor himself (heartbeat specification §9.7), not through the audited organisation, and check every root from it that was recorded before the package was requested (countersigned, gap witness or reported) as an expected root (Sections 7.2, 10.8): if the package contradicts one of them or lacks it, that is `MERKLE_INCONSISTENT`. A root recorded only after the request says nothing about this package; passed as an expected root, it would appear as a contradiction even for an honest package. From edition 1.10 the auditor passes the anchor history itself to the verifier for this (Section 8.8); the boundary before the request is then drawn by the verifier.
- **Licence key in older chains:** up to edition 1.7, `GENESIS.license_id` could carry the licence key in cleartext (Section 4.1). This does not reduce the chain's evidentiary value, but it discloses the key to every holder of the package; the verifier points this out.
- **Truncation at an earlier seal (from edition 1.6):** a chain cut off directly behind the immediate checkpoint of an earlier `SEAL` appears properly sealed; no key is needed for this. The package alone cannot refute it. It shows in the time of the seal in the report, in `TRAILING_SILENCE` outside the freshness window and, with certainty, in the comparison with the vendor's most recent countersigned root (Section 8.6). The test vector `end_truncated_at_seal` exposes this limit. Every export seal (from edition 1.9) is such a point; this limit has been fixed as a property of the model since 2026-09-29. The verifier therefore says for every package that without a countersigned root no statement about completeness is possible, and asks for it (Section 8.6).
- **Wall-clock time:** the chain proves order (seq, monotonic clock) hard; absolute wall-clock time is evidenced only up to the bracket of receipt `server_ts` (≤ 5-minute granularity) and declared clock jumps.
- **Single lost calls (from edition 1.9, 2026-10-02):** The package contains only what was chained. If a call the appliance answered is missing and no `GAP` window holds it, this cannot be detected offline; the chain stays valid. Section 8.7 obliges the appliance to prevent it. The commitment can be evidenced only outside the package: against logs of the calling applications, against the provider's counts (Section 4.6), or by test runs with known ground truth. A `GAP` window says that calls may be missing in that time, not that any are; `lost_count = −1` means their number is unknown.
- **Content:** commitments prove the integrity of presented plaintexts, not their existence or completeness; deleted content (`CONTENT_DELETED`) can permanently no longer be presented (declared, not disguised).
- **Sovereignty as subject of proof:** the vendor knows no customer keys and sees no content; everything the appliance sends is chained verbatim as an `ADMIN` entry and is thus itself subject to verification.
- **Key roles (from edition 1.10):** Every role has keys of its own, and with the verifier a key of one role never establishes an object of another (Sections 10.7.3, 10.7.4). Whoever holds only a statements key produces no receipt that an anchor of the auditor confirms, unless the auditor himself pins it as a countersigning key; if he passes the role list, the verifier discards such a pin. Whoever holds only a countersigning key produces no page a verifier uses and no statement whose root an auditor following edition 1.10 passes as an expected root (heartbeat specification §9.5, §9.7). During dual operation the countersigning key continues to sign the wrapper of license statements, refusal statements and activation receipts and pages of kind v1; recipients and auditors who proceed under edition 1.9 know no roles and accept such statements and pages even after the end of dual operation. The service that holds the countersigning key therefore reads every `statement_jcs` handed to it itself and signs on this path only objects with the `kind` of one of these statements or of a page of kind v1 (heartbeat specification §9.11 item 3); if it did not, whoever controls the statements service could have arbitrary bytes signed under the countersigning key, the signed object of a receipt included. How the vendor keeps its keys and whether this service reads that way no verification package shows (no evidence produced by LEDGER). The role check sees only the lists the auditor passes. Without a role list and without a pin as a statements key the verifier uses no page of kind v2 (`ANCHOR_HISTORY_UNVERIFIED`), even with an honest chain, and level 3 is not present. Whoever holds the vendor root can give any key any role; the roles do not protect against that.
- **Vendor log (from edition 1.10):** With the signed day entry (Section 7.4) the vendor commits, for every closed UTC day, to the set of its countersignatures and gap witnesses. A time stamp of an authority whose root the auditor supplies himself witnesses this commitment at most 48 hours after the end of the day (Section 7.4.6). If the auditor passes the log, the verifier reports every presented receipt of a witnessed day that is missing from it (`RECEIPT_NOT_LOGGED`) and every root recorded there that the package contradicts (`LOGGED_ROOT_MISMATCH`). This supports two statements. For one, the vendor cannot make a countersignature that a customer presents disappear from the log after its day was witnessed without the verifier reporting it. For another, it shows when the vendor shows two auditors different versions of a day, as soon as the auditors compare the day hash with each other or with the second place of publication, or pass both versions to the same verifier (`VENDOR_LOG_CONTRADICTION`); different day lists of a chain under the same day root show when someone checks the published day leaves for order and duplicate positions (Section 7.4.9). The verifier does not check the day leaves. An absence proof and the property that a chain has at most one chain-day leaf per day are therefore proven only together with this check (Section 7.4.3): if a vendor keeps two chain-day leaves of one chain under a day root, it can give an auditor a record without an honest receipt, and the verifier then reports `RECEIPT_NOT_LOGGED` against the customer, a finding that the day leaves attribute to the vendor. Without such a comparison a split view does not show; whether two files passed come from two places the verifier cannot tell. The log does not establish that a customer chain is complete; the expected roots remain responsible for that (Sections 8.6, 8.8). A countersignature that the vendor does not log at the close of the day and that stands in no presented package stays invisible. Receipts of a day whose entry is not yet due and receipts before the start of the log are not checkable. If the vendor obtains no witnessing time stamp for a day within 48 hours, this day remains unwitnessed for every chain active on it, and their receipts of this day remain not checkable. A data loss at the vendor appears like an omission; the chain remains valid. A root that a dishonest vendor invents and logs is attributable to it; the verifier cannot recognise it as invented. The tree size of a day follows the size rule (Section 7.4.4): it shows only whether more than 1024 chains had leaves on that day, and then the power of two that bounds their number from above; on the day on which the number crosses a power of two, it shows growth. Exempt is a log whose protocol key list is signed by a root from `published_test_keys`; it hides nothing. That the size is a power of two and at least 1024 anyone can check on the day entries; whether it is the smallest permitted one and how many chains the day had is shown only by the opening of the whole day together with proof of origin for every leaf that is not a filler of the selection, and whether the fillers come from the filler secret only by the filler secret itself, checked against the filler commitment of the protocol key list; only the vendor can give either (Section 7.4.13), and no verification package shows it (no evidence produced by LEDGER). The verifier does not check the size rule. The opening of a whole day shows which leaves are fillers of the selection and bounds the number of chains from above, but does not vouch that the other leaves are not fillers; their origin the vendor shows only with customer data, and this edition fixes no format for that. An opening is bound to no recipient and cannot be withdrawn. Whoever receives the filler secret or the opening of a whole day knows the number of chains of the days concerned; if the filler secret is lost, these days can no longer be opened. Neither changes anything about the check of a chain. The verifier does not check revocations of certificates of the time-stamping authorities. Whoever once had a verification package can also later recognise from the published day leaves on which days this chain was active, and fetch later extracts and pages of the anchor history with its `chain_id`; through `successor` he learns the successor chain and can recognise its active days as well (Section 7.4.12). If the vendor discontinues the log, no days are added; fetched extracts remain checkable offline. Whoever holds the vendor root can confirm keys of all roles; the log does not protect against misuse of the root itself.
- **Evidence level (from edition 1.10):** The evidence level (Section 10.9) summarises which anchors the verifier could confirm with the auditor inputs and up to which `seq` they reach; it holds as far as these inputs hold. Whether a vendor root, a pinned key, a root for time-stamping authorities, its naming as qualified or an expected root actually comes from outside the package and not from the hand of the key holder, the verifier cannot tell; it therefore names the fingerprints of the anchors on which the level rests. "Qualified" here means: the auditor named the root so for the time of the token, and the token declares itself so. The verifier does not check the trusted list, the status of the authority or revocations; with the stolen key of an authority, backdated tokens can be issued. Level 2 rests on the countersigning key: whoever holds it, a thief or a vendor acting together with the customer, reaches it also for a rewritten chain; only the conditions of level 3 work against that, the vendor log only for days already witnessed. Level 2 says nothing about completeness. Level 3 establishes it up to the largest `tree_size` of a found root of the anchor history; the time of the request is stated by the auditor, the verifier cannot check it, and for the entries after it the residual window remains (above). Level 3 presupposes services and signed material of the vendor: the anchor history, the vendor log and a role list or a statements key the auditor pins. The vendor can deny it to a single chain by withholding these services for it or by not logging one of its countersignatures; the omission appears as a finding against the vendor (`RECEIPT_NOT_LOGGED`), the withholding does not. If the vendor discontinues the services, a new check ends at most at level 2, and without the vendor at most at level 1; documents fetched earlier remain checkable offline. For a freshly exported package level 3 reaches at most up to the countersignatures of the last witnessed day. If the auditor passes as roots for time witnesses a bundle file of many authorities, for example the root store of a system, every one of them counts (Section 10.8); a time stamp the key holder buys from one of these authorities then suffices for condition (1). The report shows the affiliation; the number of the level does not change with it. A verifier supplied by the audited party can display any level. A verifier that does not perform steps 5 and 6 of Section 7.3 reaches no level through time witnesses, and not level 3.
- **Time binding through the vendor log (from edition 1.10):** Condition (7) is the second path to level 3 beside (4): a countersignature stands in a day whose entry an authority named as qualified has stamped. One time stamp thus covers all chains of a day and binds the state at the `tree_size` of the countersignature at most 36 hours after its `server_ts`, not at the interval of a time witness. Only "at the latest" is evidenced: that the state existed at the `genTime` of the stamp (`qualified_time`, Section 10.10.2). The stamp covers the vendor's day entry, not the chain; the chain is bound only indirectly, through the countersignature and its inclusion in the day tree. Within these 36 hours a vendor acting together with the customer can backdate a countersignature as long as its day is not yet stamped; a time witness under (4) on the chain narrows this no further than its interval allows. The authority is chosen by the vendor, not by the customer, and the proof runs through the vendor's extract and its day tree. Whether this indirect binding has the legal effect of a time stamp over the receipt or the chain is not determined by this specification; it is no legal classification (no evidence produced by LEDGER). One authority thus covers all chains: if it is no longer listed as qualified or its key is stolen, that concerns every chain, and the crediting is limited only by the period for which the auditor names the root as qualified (Section 10.8). Whether a state already existed at the time the chain itself states is shown neither by (4) nor by (7): no condition compares `genTime` with `ts_chained`. Who operates a time-stamping authority the verifier does not see; that no authority of the log is operated by the vendor or by a party affiliated with it is a duty of the vendor (heartbeat specification §9.9) that no verification package shows (no evidence produced by LEDGER).
- **Proposed time-stamping authority (from edition 1.10):** If the appliance proposes an authority (Section 7.3), the customer chooses it by his confirmation; whether it is independent of the vendor the verifier does not check. The auditor obtains its root himself. A time witness depends on the availability and the terms of the authority, and every request shows the authority the network address of the installation and the interval of its requests.
- **Affiliation with the vendor (from edition 1.10):** Whether a customer of a chain is affiliated with the vendor (heartbeat specification §9.10) is a signed statement of the vendor in the anchor history. It covers the licensee and the declared operator, as far as the vendor knows them. The verifier checks its signature against a trust anchor of the auditor, its form, its binding to the chain and to the chain's device, its freshness relative to the request of the package and its agreement with other passed pages of the same chain, but not whether it is true (no evidence produced by LEDGER). A statement that is false from the start it does not recognise; such a statement is attributable to the vendor's statements key. A statement that is later withdrawn or shortened shows if an earlier page with it is before the verifier. Whoever puts forward another licensee and does not declare the operator escapes the statement, as far as the vendor does not know the connection. The customer cannot suppress the statement if the auditor fetches the history himself; the vendor or whoever sits in the transport path can withhold it. The verifier then reports "not checked" or "not determined", never "not affiliated". For a chain from which the vendor never accepted an anchor there is no anchor history and thus no statement; a customer who never anchors gives the vendor no source for a statement. For the time of an affiliation a countersignature evidences no party independent of the customer. A time witness binds the time to a third party only if the time-stamping authority is attributable neither to the customer nor to the vendor; the verifier does not check this. Whether the vendor separates the data of its customers from affiliated parties, and how far the exception for a person acting for both sides reaches, is governed by heartbeat specification §12 (below, fetching and information barrier).
- **Vendor and customer acting together (from edition 1.10):** If vendor and customer act together, for instance with an affiliated customer, they can truncate or rewrite a chain and issue the anchor history to match, without package and history contradicting each other. Against a rewrite, time witnesses of an authority attributable to neither of them whose trust anchor the auditor supplies himself work (Section 7.3): a rewritten checkpoint has no token with an earlier `genTime`. Against a truncation they do not work, because the `TIME_ANCHOR` entries of the cut-off end go with it, and a time-stamping authority publishes nothing the auditor could compare. Witnessed days of the vendor log work against a truncation only if the auditor already holds the chain-day record of such a day himself, for example archived from an earlier check: the vendor delivers the extract, and the verifier requires records only for the days of the receipts in the package (Section 7.4.10, steps L7 and L8). If a colluding vendor leaves out the records of the days after the last receipt of the truncated package, the verifier reports nothing; then the completeness from the anchor history can also count as established and level 3 can be reached. A comparison of the public day leaves by hand for `position(C, d)` on days before the request can show the truncation; the verifier does not perform it. Before a day of the vendor log is witnessed, the log shows what both have agreed. The evidence level shows the affiliation but does not change its number.
- **Anchor history as an auditor input (from edition 1.10):** Roots that the vendor countersigned or recorded as a gap witness more than 15 minutes before the request of the package and that the package lacks or contradicts are reported by the verifier as `MERKLE_INCONSISTENT` (Section 8.8.5); a root that is only reported then yields `ANCHOR_HISTORY_FORK` (exit 1). A root that a dishonest vendor invents or that someone places on a page with a statements key would appear the same way; it is attributable to this key, and the verifier cannot recognise it as invented. The same root can yield `LOGGED_ROOT_MISMATCH` (exit 1) from the vendor log and `MERKLE_INCONSISTENT` (exit 2) from the anchor history; the report names both, since only the comparison with the history knows a request time and a binding to the device. A page whose device does not match the package the verifier does not use; this protects an honest package if another installation presented the `chain_id` of a never-anchored chain earlier. A package that was re-signed under another device key and carries no receipt thereby receives a named finding with exit 1 instead of exit 2. Without a request time the verifier judges no truncation; if the auditor states a later time than the actual one, an honest package appears truncated, and if he states an earlier one, the verifier checks less. Roots from the 15 minutes before the request that the package lacks are a note, not a finding; whether the package lacks roots from these 15 minutes, the verifier does not judge. Roots that a metadata server recorded before the cut-off date `legacy_boundary` of the registry (Section 8.8.4, step H10) may be missing from the history. The history depends on the vendor delivering it; fetched pages remain checkable offline. Whether two passed pages come from two places the verifier cannot know. Different pages for different auditors show only if both reach the same run; pages of the anchor history stand in no log and at no second place. If the vendor refuses a fetch, for example because of the rate limit (HTTP 429), that says nothing about the package; if the auditor thereby gets no fresh page, the verifier reports `ANCHOR_HISTORY_UNVERIFIED` with the reason `issued_before_request`, or there is no page to pass; the auditor then fetches again later (heartbeat specification §9.7). The vendor root built into the verifier vouches like a root of the auditor; the report names which one was used. A verifier enclosed with the package comes from the same hand as the package; its statement on affiliation is then also a statement of the audited party.
- **Fetching history and log, information barrier (from edition 1.10):** Whoever fetches the anchor history or an extract of the vendor log for a chain tells the vendor which chain is checked when; that the vendor does not record this is a duty of its operation (heartbeat specification §12) that no verification package shows (no evidence produced by LEDGER). The same holds for the separation of customer data from affiliated parties. If a person acts both for the vendor and for an affiliated party, that person may keep operational access as long as the vendor cannot set up the separation for them, at most until a fixed day that the vendor states publicly with the scope and period of the exception; heartbeats, telemetry and summaries about other customers remain closed to that person even then, every access is recorded immutably, and an independent review is then mandatory (heartbeat specification §12). No verification package shows this either (no evidence produced by LEDGER). From the first day of its vendor log at the latest, the vendor records accesses to customer data in an access chain (entry type `DATA_ACCESS`, Section 4.25; heartbeat specification §12). The access chain shows which accesses were recorded, when, through which account, for which purpose and in which scope, and that an anchored entry was afterwards neither removed nor changed; whether every access was recorded it does not show (no evidence produced by LEDGER). Whoever has access to the machine can access data without an entry, an emergency access releases data before the confirmed entry, and the content of a case record is checked only by whoever receives case record and salt. The vendor countersigns its access chain itself and issues its anchor history; for it the vendor is customer and countersigner at once. It is bound independently only by time witnesses of an authority operated neither by the vendor nor by a party affiliated with it, by roots the auditor kept himself, by the vendor log and by the daily heads of the access chain at both places of publication. Whether the chain was truncated is shown by comparing these heads and the day leaves with the verification package in the yearly audit (heartbeat specification §12, access chain, item 8), not by the verifier. A customer does not find his own entries in it, since no entry names him. Day entries, day leaves and the mirror at the second place of publication the auditor can fetch without naming a chain; the chain-day records and the pages of his chain he receives only with its `chain_id`. The length of a page also depends on the number of periods, and identical entry times on the pages of two chains reveal that both belong to the same affiliated customer.
