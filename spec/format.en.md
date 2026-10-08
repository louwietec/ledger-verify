# LEDGER Chain Format: Specification (EN)

**spec_version: 1.9** · This specification is normative. It describes LEDGER's evidence format completely enough that an independent third party can implement a verifier from this document alone. The machine-readable field and class reference is `spec/registry.json`; in case of divergence the registry prevails.

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as described in RFC 2119.

## 1. Overview and Design Goals

LEDGER captures the use of AI services as an **append-only event chain**: canonical JSON, SHA-256 hash chaining, an RFC 6962 Merkle tree, Ed25519-signed checkpoints and external countersignatures. Three design goals drive every format decision:

1. **Proof instead of claim.** Every statement the chain makes is cryptographically verifiable: offline, without the vendor's cooperation, without secrets. Verification requires neither customer keys nor content.
2. **A gap is a finding.** No failure path ends in nothingness: outages, bypasses, clock jumps and deletions are chained as dedicated entry types. An honestly declared gap does not invalidate the chain; a concealed one does (Sections 8, 11). For the single call this is a commitment of the appliance: every call it has answered is in the chain or lies inside the window of a chained `GAP` (Section 8.7); whether it was kept, the package alone cannot show (Section 11.2).
3. **Sovereignty.** The chain carries no plaintext, only salted commitments (Section 9). The vendor knows no customer keys and sees no content; its only role in the proof model is countersigning 32-byte roots (Sections 6, 7, 11).

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
| `hex64` | 64 lowercase hexadecimal characters (32 bytes), e.g. a SHA-256 value or an Ed25519 public key |
| `hex128` | 128 lowercase hexadecimal characters (64 bytes), an Ed25519 signature |
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
- **Hash:** SHA-256 is the only hash function in this specification. "Hex(x)" is the lowercase hex encoding of bytes `x`.
- **Signatures:** Ed25519 (RFC 8032). What is signed is always the UTF-8 bytes of a JCS-canonicalized object; signatures are encoded as `hex128`, public keys as `hex64`.
- **Numbers (explicitly from edition 1.9):** Every JSON number in the verification package (in entries including the payload of unknown types, in the manifest, in the vendor key list, in the salt files of presented plaintexts (Section 10.1) and in `verify_args.json` (Section 10.8)) MUST be an integer from −(2^53−1) to 2^53−1, written without a fraction and without an exponent (I-JSON, RFC 7493 section 2.2; RFC 8785 presupposes it). Any other number is `FORMAT_ERROR` (exit 3); `1.0` is not `1`. The writing path cannot write anything else. This holds in the vendor key list and in the salt files too, whose other defects only make the list ineffective (Section 10.7) or are `CONTENT_MISMATCH` (Section 10.1), and whether or not the auditor passes a vendor root. These two kinds of file are read lexically (every number token where a JSON value may begin, strings do not count), hence independently of other defects of the same file (stage 4a, Section 10.5). `NaN` and `Infinity` are not JSON (RFC 8259): a syntax error of the file, not a number violation. `-0` is the number 0.
- **Time arithmetic (from edition 1.9):** The tolerance checks of Sections 8.2, 8.5 and 9.2 and the window conditions of Section 8.7 compute in whole milliseconds: every instant is truncated to whole milliseconds since `0001-01-01T00:00:00Z` (digits after the third fractional digit are dropped); integers are compared and subtracted. All other time comparisons (Sections 7.1, 9.3, 10.7) are made to the nanosecond. The writing path writes milliseconds; an honest chain never touches the difference.

## 3. Entry Envelope

Every entry is a JSON object with exactly these eleven fields (source: registry `envelope_fields`):

| Field | Type | Description |
|---|---|---|
| `spec_version` | version `"MAJOR.MINOR"` | version of the specification the entry was written under; `MAJOR` and `MINOR` are decimal numbers without leading zeros (`"1.0"`, not `"01.0"` or `"1.00"`); this edition writes `"1.9"` and accepts older minor versions of the same MAJOR; acceptance of other versions: Section 10.6 |
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

This version defines 24 entry types (an entry type not defined here is handled per Section 10.6). Nine of them are **critical types** (registry attribute `critical_checkpoint`): `GENESIS`, `GAP`, `MODE_CHANGE`, `SEAL`, `OVERSIGHT`, `KEY_ROTATION`, `CONTENT_DELETED`, `CONTENT_DISCLOSED`, `LEGAL_HOLD`. After every entry of a critical type, the immediately following entry MUST be a `CHECKPOINT` (immediate-checkpoint obligation, Section 6).

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
| `provider_class` | enum, see 4.25 | provider class |
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
| `reason` | enum, see 4.25 | gap class |
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
| `user` | string, maxlen 128 | acting person |
| `role` | string, maxlen 64 | role |
| `reference` | string, maxlen 256 | what is being decided (e.g. chain `seq`, case id) |
| `justification` | string, maxlen 4000 | justification |

### 4.13 ALARM

Rule-based alarm (no AI in the product).

| Field | Type | Description |
|---|---|---|
| `rule_id` | enum, see 4.25 | alarm rule |
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
| `tsa_name` | string, maxlen 256 | the authority as configured by the customer; descriptive, not evidentiary |
| `tsa_policy` | string, maxlen 128 | `policy` OID from the token; MUST match the token |
| `tsa_serial` | string, maxlen 128 | `serialNumber` from the token, lowercase hex; MUST match the token |
| `tsa_ts` | rfc3339 | `genTime` from the token in the time format of Section 2; MUST match the token |
| `token_base64` | string, maxlen 21848 | the DER-encoded TimeStampToken (RFC 3161), base64; the DER MUST be ≤ 16384 bytes |

The four `tsa_*` fields are **readings from the token**, not a second source: they make the chain legible without an ASN.1 parser. Only `token_base64` is evidentiary. A reading that contradicts the token is the finding `TIME_ANCHOR_INVALID`, not a reason to adopt one value over the other.

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

### 4.25 Referenced Enumerations

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

1. **Vendor root.** The vendor's offline root key as `{"wurzel_id", "pubkey"}` (Section 10.7), published with the licence; a vendor build of the verifier MAY carry it compiled in and MUST name it in its version output. The root vouches for countersigning keys through the signed list `keys/vendor/schluesselliste.json` in the package (Section 10.7).
2. **Pinned key.** A single pair `key_id` = public key that the auditor obtained itself.

If the auditor names two roots with the same `wurzel_id` or two pins of the same `key_id` with different public keys (also against a compiled-in root), the audit environment is ambiguous; the verifier MUST reject the invocation (exit 3) and MUST NOT silently choose one of them.

For each receipt the verifier determines the key in this order:

- If `server_key_id` is pinned, the pinned public key applies. The signature is checked against **it**, not against the manifest's copy; if that fails, it is `RECEIPT_INVALID` (exit 2). The pin takes precedence over the list, including its validity window: whoever pins makes the statement about the key themselves.
- Otherwise: if the package carries a list whose signature holds against one of the auditor's roots (Section 10.7) and the list names `server_key_id`, the list's public key applies; the manifest's copy is then irrelevant. It is `RECEIPT_INVALID` (exit 2) if the signature fails against it or if `server_ts` lies outside the key's validity window (`gueltig_ab` ≤ `server_ts`; `server_ts` < `gueltig_bis` if present; `server_ts` < `widerrufen_ab` if present). In the second case the vendor's signed statement contradicts the receipt. `server_ts` is read with the grammar of Section 10.7; a `server_ts` that cannot be read that way lies in no window.
- Otherwise the manifest's public key applies. If the signature holds, the verifier reports `RECEIPT_UNVERIFIED` (exit 1), **once per `server_key_id`**, with `key_id` and public key in the report so the auditor can look the key up outside the package. If it fails, or the key is missing from the manifest, it remains `RECEIPT_INVALID` (exit 2).

A list that does not hold (no root supplied, another `wurzel_id`, failing signature, format violated) makes no key credible; but it is **not a forgery finding** either, since the list is part of no hash chain. The receipts concerned are then `RECEIPT_UNVERIFIED`, and the report names the reason. Likewise a key missing from a list that holds: the list may be older than the key.

The split between `RECEIPT_INVALID` and `RECEIPT_UNVERIFIED` follows Section 7.3: a signature that does not hold, or a signed statement of the vendor that contradicts the receipt, is a finding about the **chain**. A missing anchor is a statement about the **audit environment**. The best a forgery with an invented key can therefore reach is a named finding with exit 1, never exit 0.

**What counts as anchoring.** A receipt whose signature holds against the key determined by this rule counts as an external anchor present, also under `RECEIPT_UNVERIFIED`, as a time witness does under `TIME_ANCHOR_UNVERIFIED` (Section 7.3); `NO_ANCHOR` then adds nothing. A receipt with `RECEIPT_INVALID` does not count: if all receipts are invalid and no other anchor is present, the verifier reports `NO_ANCHOR` alongside. The prefix check (`FORK_DETECTED`) applies to every receipt whose signature holds, whether or not its key is established, and also when the list contradicts it: a contradiction must not hide a fork.

**What this rule does not achieve.** The validity window is checked against `server_ts`, and `server_ts` sits in the receipt itself. Whoever holds a revoked key (exactly the case revocation exists for) can sign receipts with a `server_ts` before the revocation; the verifier compares `server_ts` with no other time of the chain, and the chain's key holder could backdate the chain's times as well. Only anchors the forger cannot create after the fact work against such backdating: the paper anchor (7.2), the time witness (7.3) and the freshness window (8.5). Nor can the verifier tell whether a newer list exists than the one in the package: `version` is only comparable among lists. The report therefore names the version and issue time of the list used, so the auditor can check them with the vendor.

From `spec_version` 1.1 the appliance additionally attaches to the anchor the RFC 6962 consistency proof from the chain's reference size (the `tree_size` last receipted or recorded as a gap witness) to the new one (heartbeat specification §6 and §9.2); the vendor server countersigns a grown chain only when that proof holds. Nothing changes for the verifier: the receipt remains the object of proof, and the prefix check of this section remains its own.

### 7.2 Paper Anchor

The monthly report prints the Merkle roots (and `tree_size`) of the month's checkpoints. An auditor MAY pass a printed root to the verifier as the expected root (e.g. `--expect-root`); if the recomputed root differs, the chain is not consistent with the paper state (`MERKLE_INCONSISTENT`). Paper anchors are vendor-independent.

### 7.3 Time Witness (TIME_ANCHOR)

A time-stamping authority per RFC 3161 (TSA) attests that a checkpoint **already existed** at a given point in time. Unlike the vendor countersignature, that statement comes from a source controlled by neither the customer nor the vendor; the authority is set up by the customer.

The time stamp is taken over the **canonical checkpoint signed subject** of Section 6.1, that is, over exactly the bytes the checkpoint's device signature covers as well. It therefore attests not only the root but `chain_id`, `tree_size`, `prev_checkpoint_hash`, `key_id` and the checkpoint time along with it.

The token's `messageImprint` MUST be `H(JCS(checkpoint signed subject))`, where `H` is the imprint algorithm named in the token itself. Permitted are `sha256`, `sha384`, `sha512`; `sha1` is NOT: a collision on the imprint would let one token attest two different checkpoints, which is precisely what the anchor is meant to rule out.

The token is written into the chain as a `TIME_ANCHOR` entry (Section 4.22). A time witness is **optional**: a chain without a TIME_ANCHOR is not deficient for that reason, and its absence is not a finding.

**Verification rules.** For every TIME_ANCHOR the verifier MUST check, in this order:

1. `checkpoint_seq` references a CHECKPOINT whose `tree_size` and `merkle_root` match the entry's fields. Otherwise `TIME_ANCHOR_INVALID` (exit 2).
2. `token_base64` decodes to a DER-encoded TimeStampToken with exactly one signer and one TSTInfo. Otherwise `TIME_ANCHOR_INVALID` (exit 2).
3. The four readings `tsa_policy`, `tsa_serial`, `tsa_ts` and the imprint algorithm agree with the token. Otherwise `TIME_ANCHOR_INVALID` (exit 2).
4. The token's `messageImprint` equals the imprint named above over the signed subject of the referenced checkpoint. Otherwise `TIME_ANCHOR_INVALID` (exit 2). **This is the load-bearing binding**, and it is checkable without any knowledge of CMS: compute the imprint, locate the `messageImprint` octet string in the DER, compare.
5. The token's CMS signature verifies against the signer certificate carried inside the token. If it does not, that is `TIME_ANCHOR_INVALID` (exit 2); a token that does not carry its own signature is forged or damaged.
6. The signer certificate chains to a trust anchor supplied by the AUDITOR (the system root store, an explicitly passed root) and carries exactly the extended key usage `id-kp-timeStamping` (RFC 3161 Section 2.3). The chain is validated **at the token's `genTime`**, not at the time of verification; otherwise the proof would expire with the authority's certificate. If that does not succeed, the finding is `TIME_ANCHOR_UNVERIFIED` (exit 1).

**Steps 1 through 4 are mandatory for every verifier.** They need no CMS: decode base64, compute the imprint over the signed subject, find it at the `messageImprint` position in the DER, compare the three readings. A verifier that CANNOT perform steps 5 and 6 (because no CMS implementation is available to it) MUST NOT turn that into `TIME_ANCHOR_INVALID`. It MUST report `TIME_ANCHOR_UNVERIFIED` (exit 1) and state in the report that it did not check the signature. This rule is not a convenience but the condition for the specification remaining implementable with ordinary means (Section 1): everyone can check the load-bearing binding, not everyone can check the signature chain.

The split between 5 and 6 is deliberate. A broken signature is a forgery finding. A missing or unreachable trust anchor is a **statement about the verification environment**, not about the chain, and a verifier that treated both alike would either declare honest chains manipulated or wave forged ones through.

**Why the trust anchor must not come from the package.** The verification package is written by exactly the party the time witness is meant to constrain. A certificate from `keys/tsa/` therefore establishes self-consistency only. A verifier MAY use such certificates for chain building, but in that case it MUST report `TIME_ANCHOR_UNVERIFIED` (exit 1) and name the authority in the report (name, serial number, `genTime`) so the auditor can look it up outside the package. Only an anchor the auditor supplies makes the witness independent.

A TIME_ANCHOR that passes steps 1 through 4 counts as an external anchor being present: `NO_ANCHOR` (Section 7) is then NOT reported, even if step 6 fails. The two findings say different things ("no anchoring is present" and "the one present is not independently established"), and only the second applies here. The split also keeps verifiers that cannot perform step 6 at all in agreement.

**What the time witness does not do.** It proves that a checkpoint existed at a point in time, not that the chain is complete. It works against the residual window of Section 11.2, because a history rewritten later cannot produce a token with an earlier `genTime`; against the omission of entries BEFORE the time stamp, only the hash chain, Merkle consistency and the remaining anchors continue to work.

### 7.4 Future Anchor Types (Outlook, Non-Normative)

Further anchor types are conceivable (for instance publication in a public transparency log). Verifiers of this version MUST ignore unknown anchor types and MUST NOT treat them as errors.

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

**Why condition 4, and why so narrow.** If the writing path crashes between a critical entry and its immediate checkpoint, the restart writes the checkpoint late (Section 6.2), then `RESTART` and `GAP`. Up to edition 1.8 the silence before the late checkpoint stayed concealed although the chain declares it right after (deliberate decision of 2026-09-03, changed by the client on 2026-09-29 in favour of coverage by the following `RESTART`, on the condition that a `RESTART` must not be able to conceal a deletion). Condition 4 therefore demands the trace of the restart, the declaration that follows immediately and a `GAP` window that encloses the whole silence. It touches no other check: no entry can be missing between `a` and `b` (`seq`, the checkpoint's Merkle tree), a `CONTENT_DELETED` as `a` remains the finding `CONTENT_DELETED`, and the deletion hold (Section 9.3) is checked as everywhere. The time of `a` is then bounded only by the signature of `b` at `ts_chained(b)`, not by the tolerance before it.

**Limit, reported to the client: "a RESTART must not be able to conceal a deletion" cannot be ensured offline in general, not even with condition 2, which has applied since edition 1.0.** Whoever has write access to the chain files can cut off the end of the chain including a `CONTENT_DELETED` and restart the installation; `RESTART` and `GAP` then cover the silence up to the last remaining entry, and nothing in the package refutes that. Likewise a restart signs any hash-consistent entry someone appended to the end before it. This is the same limit as the residual window (Section 11.2): the key is with the operator. Anchoring exposes it: the vendor no longer accepts a truncated chain (heartbeat specification §9.2), an expected root of the auditor contradicts it (Sections 7.2, 8.6), a time witness (Section 7.3). Condition 4 does not widen this possibility; what it covers could already be reached with fabricated `TICK` entries.

### 8.3 Gap Classes

`GAP.reason` carries exactly one of the classes of 4.25: `bypass` (gatekeeper direct forwarding without capture), `proxy_restart`, `power_loss`, `spool_unwritable`, `host_down`, `update`, `manual`. For import sources, `SOURCE_GAP` covers source windows (finding `COVERED_SOURCE_GAP`, exit 1); a `RECONCILIATION` with `delta ≠ 0` is the finding `RECONCILIATION_DELTA` (exit 1).

### 8.4 SEAL/RESUME Handover

Planned interruptions (update, shutdown, decommission) MUST be sealed; an export from running operation MAY be sealed (export seal, `reason = export`, from edition 1.9):

1. The old instance writes `SEAL`; as a critical type its immediate checkpoint MUST follow directly (Section 6.2).
2. The continuing instance (a new one after `update` or `shutdown`, the same one after `export` or, after a crash in between, the restarted one) writes `RESUME` as its first substantive entry, with `sealed_entry_hash` = **the `entry_hash` of the SEAL entry** (not of the immediate checkpoint; MUST match exactly) plus `prev_version`/`new_version`.
3. Between `SEAL` and `RESUME` there lies **exactly one** entry, and it MUST be the SEAL's immediate checkpoint.

Rationale for both halves of rule 3: A `SEAL` without an immediate checkpoint would remain **unanchored**: should the machine die between SEAL and RESUME, the chain state would be signed only up to the last older checkpoint; that is the weaker evidentiary position, and the moment of a planned interruption is precisely where the stronger one is needed. Conversely, **only this one anchor** may lie in between, so that the handover stays provably tight: any further entry inside the planned silence would no longer be covered by the handover itself.

Violations (a missing RESUME after a SEAL (although the chain continues), a wrong `sealed_entry_hash`, a different or an additional entry between SEAL and RESUME) are the finding `HANDOVER_BROKEN` (exit 2); the SEAL's missing immediate checkpoint itself is `MISSING_CHECKPOINT` (exit 2), except at the chain end (Section 6.2). If the chain ends with a SEAL + immediate checkpoint, this is a regular chain closure, not a finding, whatever its `reason` (from edition 1.6; up to edition 1.5 only with `decommission` or `key_loss`) and even when `CHECKPOINT_RECEIPT` entries on exactly this immediate checkpoint still follow: they confirm the sealed state and are not substantive entries. How the chain end is judged is governed by Section 8.6.

**Export seal (from edition 1.9).** The writer writes `SEAL` with `reason = export`, its immediate checkpoint, `RESUME` and the checkpoint after it without any entry in between and continues the chain immediately; in the chain this is an ordinary handover under rules 1 to 3. The verification package holds the entries up to and including the immediate checkpoint of this seal and is therefore sealed (Section 8.6). The handover takes milliseconds; a longer silence between checkpoint and `RESUME` (a crash during the export) is covered by condition 3 of Section 8.2 as for every handover.

Three clarifications (client release 2026-09-03; both reference verifiers read the rule this way): (1) Every `RESUME` continues exactly one `SEAL`: a `RESUME` not immediately preceded by a `SEAL` with its immediate checkpoint is `HANDOVER_BROKEN`. (2) `CHECKPOINT_RECEIPT` entries on the immediate checkpoint of a `SEAL` may trail only at the chain end; between `SEAL` and `RESUME` they are an additional entry in the sense of rule 3. (3) The silence coverage of Section 8.2 condition 3 applies only to the handover the `RESUME` actually continues with a matching `sealed_entry_hash`.

### 8.5 Silence at the Chain End (Freshness)

No subsequent entry can cover the end of the chain. If `ts_chained` of the last entry lies further in the past than the **freshness window** at verification time, the verifier reports `TRAILING_SILENCE` (exit 1). The window is configurable (verifier option); default: **24 hours**. This finding protects against presenting a stale (e.g. rolled-back) state; together with receipt `server_ts` and cloud-side `tree_size` monotonicity it bounds fork/rollback attacks (Section 11). The finding applies to a sealed chain as well (Section 8.6): the seal declares the silence after it, but it does not prove that it is the chain's most recent seal; a chain truncated at an earlier seal would look exactly the same (Section 11.2). `TRAILING_SILENCE` remains exit class 1; the chain remains valid.

### 8.6 Chain End: Sealed or Incomplete

Principle (product decision of the client, from edition 1.6): **An honest chain is never reported as "invalid". "Invalid" (exit 2) is reserved for proven manipulation.** How a chain ends is therefore not a manipulation finding but a status of its own.

A chain is **sealed** if its last entries are, in this order: a `SEAL`, directly followed by its immediate checkpoint (Section 6.2), followed by at most `CHECKPOINT_RECEIPT` entries whose `checkpoint_seq` names exactly this immediate checkpoint. The `reason` of the `SEAL` plays no part in this. Every other chain is **incomplete**; this includes a chain whose last entry is a `SEAL` or another critical entry without its checkpoint (Section 6.2).

| Chain end | Result | Exit |
|---|---|---|
| sealed, no findings of exit class 2 | valid, properly sealed; the report states `seq`, `ts_chained` and `reason` of the `SEAL` | 0, with findings of exit class 1: 1 |
| incomplete, no findings of exit class 2 | incomplete: finding `UNSEALED_END` | 4 |
| `SEAL`, followed by other entries without `RESUME` | invalid: `HANDOVER_BROKEN` (Section 8.4) | 2 |
| hash chain broken, signature wrong or any other finding of exit class 2 | invalid | 2 |

The finding `UNSEALED_END` is reported exactly once for every incomplete chain, with the `seq` of its last entry, also alongside findings of exit class 2; the exit code then follows Section 10.3. If the package is a format error (exit 3), the chain end is not judged. From edition 1.6, exit 0 and exit 1 therefore presuppose a sealed chain end.

**What "incomplete" means.** All entries present are checked as for any chain. Incomplete only means: the package does not prove that nothing came after its last entry. Every export from a running installation without an export seal ends this way, every chain after a crash or power loss, and a truncated chain just as well. Offline these cases cannot be told apart. The verifier MUST therefore state, with the finding, the package's last countersigned checkpoint (`checkpoint_seq`, `tree_size`, `merkle_root` and `server_ts` of the receipt with the largest `tree_size` among those that count as an anchor per Section 7.1 (signature holds, no contradicting vendor list) and match their checkpoint; on equal `tree_size` the first in chain order) or that there is none, and point to the comparison.

**Export seal.** A package the installation produces with an export seal (Section 8.4) ends with `SEAL(export)` and its immediate checkpoint and is sealed: an orderly export from running operation is valid, not incomplete (client decision of 2026-09-29).

**Comparison with the last countersigned checkpoint.** The vendor keeps, per `chain_id`, the roots it has countersigned, and from edition 1.9 hands them out together with gap witnesses and reported roots as a signed anchor history, which the auditor fetches himself by the `chain_id` (heartbeat specification §9.7); he then passes every root from it that was recorded before the package was requested. At the least the auditor passes the most recent countersigned root countersigned **before the package was requested** as an expected root, like a paper anchor (`tree_size` and `merkle_root`, Sections 7.2, 10.8), not the most recent overall: a root countersigned after that lies beyond the end of the package and cannot occur in it; it would appear as a contradiction even for an honest package. If the package does not contain the root passed as a prefix root, it lacks entries the vendor had already countersigned: `MERKLE_INCONSISTENT` (exit 2). The comparison applies to sealed chains alike.

**What the verifier says about completeness (from edition 1.9).** Without a root countersigned by the vendor, no statement is possible about whether the package holds the whole chain up to its request, neither for an incomplete nor for a sealed chain (limit of proof below, Section 11.2; client decision of 2026-09-29: accepted as a property of the model). The verifier MUST say so explicitly for every package that is not a format error and ask for the root: with the `chain_id` and the invocation by which the auditor passes it. If an expected root was passed and found in the package, it says instead up to which `tree_size` completeness is established by it.

**Limit of proof of the seal.** The seal carries the signature of the device key, not the vendor's: the immediate checkpoint of a `SEAL` that a `RESUME` follows carries no receipt before the `RESUME` (Section 8.4, clarification 2). Every earlier handover (`SEAL`, checkpoint, `RESUME`) is therefore a point at which a truncated chain appears sealed without any key; the key holder can truncate at any point anyway and sign a new seal (Section 11.1). What works against this is the time of the seal in the report, `TRAILING_SILENCE` (Section 8.5) and, with certainty, only the comparison above (Section 11.2, test vector `end_truncated_at_seal`).

**Older verifiers.** The rule applies to every package, whatever `spec_version` it declares: the manifest is not signed, and a declared older edition must not change the status of the chain end (as in Section 7.1). A verifier of edition 1.5 or older does not know exit 4: it reports an incomplete chain as valid (exit 0 or 1; milder than this edition), but one whose last entry is a critical entry without its checkpoint as `MISSING_CHECKPOINT` and a chain sealed with `update` or `shutdown` as `HANDOVER_BROKEN` (exit 2 each; stricter). It recognises a package of edition 1.6 or later by the finding `SPEC_NEWER` (Section 10.6); packages from 1.6 SHOULD be checked with a verifier from 1.6. A verifier up to edition 1.8 does not know the sealing reason `export`: the payloads of known types stay strict (Section 10.6, rule 3), so it reports every package containing an export seal as `FORMAT_ERROR` (exit 3), permanently for that chain, including every later package, because the seal stays in the chain. Packages from 1.9 SHOULD be checked with a verifier from 1.9.

### 8.7 Capture commitment and gap start after a crash

From edition 1.9 (addition of 2026-10-02). The client's principle: no answered AI call may be lost silently. It is either in the chain, or it lies visibly inside a gap.

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
    ├── vendor/schluesselliste.json  # optional: signed vendor key list (10.7)
    └── tsa/*.pem           # optional: time-stamping authority certificates (7.3)
```

- Each segment file contains entries as JSON Lines (one entry per line, `\n`-separated), in ascending `seq` order; segments do not overlap and together cover `seq = 1 … tree_size` of the manifest without gaps. Lines are split at `\n` (U+000A) only: `\r`, U+0085, U+2028 and U+2029 do not separate entries; the last three stand raw inside a JSON string (RFC 8785), and a `\r` before the `\n` is whitespace of the JSON text. `\n` at the end of the file (one or several) is passed over; every other line (an empty one or one of whitespace only included) MUST be an entry, otherwise `FORMAT_ERROR` (exit 3).
- The names of the entries in the ZIP are in normal form: path parts separated by `/`, no leading `/`, no empty path part, no path part `.` or `..`, no `\`, and no name occurs twice. Directory entries (name ends in `/`) are skipped. If `manifest.json` is not at the top level and all entries share exactly one top-level directory, that directory is stripped (a zipped directory); from edition 1.9 the same applies to a package presented as a directory that contains exactly one directory and nothing else. A package presented as a directory may contain only files and directories; a symbolic link or anything else (a named pipe, a device) is `FORMAT_ERROR`. A package violating these rules is a format error (`FORMAT_ERROR`, exit 3): two verifiers must not see different files in the same archive.
- Segment file names carry no evidentiary weight; the manifest's segment list (file, SHA-256, `first_seq`, `last_seq`) is authoritative. Explicitly from edition 1.9: `file` follows the grammar `^[A-Za-z0-9._-]{1,128}$`, is neither `.` nor `..` and is read only as `segments/<file>`, never elsewhere in the package and never outside it. The segments are read ordered by `first_seq`, whatever their order in the list; their declared ranges MUST start at 1 without gaps, must not overlap and MUST end at `tree_size` ≥ 1, and every file MUST hold exactly `last_seq − first_seq + 1` entries. Every violation is `FORMAT_ERROR` (exit 3), and the check ends there (Section 10.5). Whether the entries themselves are numbered without gaps is checked by Section 3 (`SEQ_BREAK`).
- `keys/` mirrors the manifest's keys (one file per `key_id`); in case of divergence the manifest prevails. The vendor keys from the manifest and `keys/vendor/` are **not evidentiary** (Section 7.1): they lead to `RECEIPT_UNVERIFIED` as long as no anchor of the auditor establishes them. `keys/vendor/schluesselliste.json` is optional and counts only if its signature holds against a vendor root of the auditor (Section 10.7). `keys/tsa/` is optional and **not evidentiary** (Section 7.3): certificates from there lead to the finding `TIME_ANCHOR_UNVERIFIED`, because they come from the same hand as the chain.
- Optionally, the package MAY contain presented reports (HTML/PDF) and deliberately disclosed plaintexts with salts; the verifier then additionally checks `REPORT_MISMATCH` and `CONTENT_MISMATCH`.
- **Presented plaintexts (defined from edition 1.9)** live under `content/`. The presentation for the `AI_CALL` with `seq` n consists of `content/<n>.salts.json` and `content/<n>.request` and/or `content/<n>.response`; `<n>` has the form `[1-9][0-9]*`. The plaintext files hold exactly the bytes of the HMAC message (Section 9.1). The salt file is I-JSON (Section 2) with exactly these members: `seq` (int, equal to n), `request_salt` and `response_salt` (hex64 each, present exactly when the matching plaintext file is present) and optionally `vault_ref` (string, not evaluated). For every presented part, entry n MUST be an `AI_CALL` with a non-null `<part>_commitment`, and the HMAC MUST match. Every other file under `content/` (another name, a file in a subdirectory, a plaintext without a salt, a salt without a plaintext, a non-conforming salt file) is `CONTENT_MISMATCH`, once per file. Beside a non-conforming salt file, every plaintext of the same n is `CONTENT_MISMATCH` as well: it cannot be checked. If a presented part does not meet the condition on entry n, its plaintext file is `CONTENT_MISMATCH`, the conforming salt file beside it is not. An empty directory yields nothing.

### 10.2 manifest.json

Fields (registry `pruefpaket_manifest`):

| Field | Type | Description |
|---|---|---|
| `spec_version` | version `"MAJOR.MINOR"` | specification version of the package; `MAJOR` and `MINOR` are decimal numbers without leading zeros; this edition writes `"1.9"` and accepts older minor versions of the same MAJOR; acceptance of other versions: Section 10.6 |
| `chain_id` | uuid | chain of this package |
| `created_ts` | rfc3339 | package creation time |
| `tree_size` | int, min 0 | number of entries contained |
| `segments` | array of object | per segment: `file` (string, maxlen 128), `sha256` (hex64), `first_seq` (int, min 1), `last_seq` (int, min 1) |
| `device_pubkeys` | array of object | per key: `key_id` (string, maxlen 64), `pubkey` (hex64) |
| `vendor_pubkeys` | array of object | per key: `key_id` (string, maxlen 64), `pubkey` (hex64) |

The verifier MUST check the SHA-256 sums of the segment files against the manifest; any deviation, as well as unreadable or schema-violating material, is `FORMAT_ERROR` (exit 3).

### 10.3 Exit Codes

| Exit | Meaning |
|---|---|
| 0 | valid, no findings |
| 1 | valid with findings |
| 2 | invalid |
| 3 | format error |
| 4 | incomplete: chain end not sealed (Section 8.6) |

Determination: if the package is unreadable or schema-violating → **3**. Otherwise: at least one finding of exit class 2 → **2**; otherwise at least one finding of exit class 4 → **4**; otherwise at least one finding of exit class 1 → **1**; otherwise → **0**. What counts is this order of precedence (3 before 2 before 4 before 1 before 0, registry `verifier.exit_precedence`), not the size of the number. The semantics are strictly separated: "cryptographically valid yes/no" (0/1/4 vs. 2/3), the status of the chain end (0/1 sealed, 4 incomplete) and the list of findings. Exit 4 is not a failure: the checked entries are intact; only their completeness is not proven by the package. If a verifier also emits its verdict in machine-readable form, it MUST report exit 4 as a status of its own and MUST NOT mark it as "invalid"; a tool that reads only a yes/no flag would otherwise reject every honest chain taken during operation. An honestly declared gap does not invalidate the chain; a concealed one does.

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
| `SPEC_NEWER` | 1 | package uses a newer minor version of the specification than the verifier |
| `UNKNOWN_ENTRY_TYPE` | 1 | entry type unknown to this verifier version; entry checked, payload not |
| `UNKNOWN_MANIFEST_FIELD` | 1 | manifest field unknown to this verifier version; accepted and reported, all known checks still run |
| `FORMAT_ERROR` | 3 | package unreadable / violates schema |

### 10.5 Verification Procedure (Normative Minimum Checks)

A conformant verifier performs at least: (1) package/schema checks including segment hashes, applying the forward-compatibility acceptance rules (Section 10.6); (2) `seq` gaplessness and hash chain (`prev_hash`/`entry_hash` with its own JCS canonicalization); (3) checkpoint signatures including the KEY_ROTATION trust chain and checkpoint chaining; (4) recomputation of all checkpoint Merkle roots; pairwise consistency of all anchored roots; (5) receipts: origin of the vendor key and countersignature per Section 7.1, match against the checkpoint, prefix match (fork); (6) gap semantics per Section 8; (7) time plausibility per Section 9.2; (8) SEAL/RESUME handover and chain end (Sections 8.4, 8.6); (9) optionally presented plaintexts and reports; deletion holds (Section 9.3); (10) freshness window; (11) time witnesses per Section 7.3, where present; (12) measure and state the residual window (Section 11.2).

**Processing stages (from edition 1.9).** The package is read in this order: (1) `manifest.json` as I-JSON, signals under rules 1 and 5 (Section 10.6), then its schema; (2) the segment table (Section 10.1); (3) per segment in `first_seq` order: file present, SHA-256, number of lines (for all segments before stage 4 reads a line); (4) per line: JSON; if it is an object, the signals under rules 1 and 2 from `spec_version` and `event_type` (where they are strings), then its schema and its `chain_id`, continuing with the remaining lines; (4a) the vendor key list and the salt files `content/<n>.salts.json` (only names of this form) against the number rule of Section 2, at most one `FORMAT_ERROR` per file; (5) the checks of the chain, the presented plaintexts among them. If one of stages 1 to 3 fails, all later ones are dropped. Signals are reported for every object read up to then, also beside its schema error (rule 3), but never from a missing segment or one with a wrong SHA-256. If stage 4 fails on a line, the remaining lines continue; stage 5 is dropped; if stage 4a fails, stage 5 is dropped as well.

### 10.6 Forward compatibility

The model is the rule for unknown anchor types (Section 7.4), which continues to apply unchanged: what a verifier does not know is a finding, not an error (with a deliberately drawn boundary at the envelope).

**Rule 1: Version acceptance.** `spec_version` has the form `"MAJOR.MINOR"` (type `version`, Section 2). A verifier implementing version `1.m` MUST accept entries and manifests with `spec_version = "1.n"`. For `n ≤ m` the normal case applies, without a special finding. For `n > m` it MUST report the finding `SPEC_NEWER` (exit class 1) exactly ONCE per verification package and MUST continue to perform ALL checks it knows, in particular the minimum checks of Section 10.5. A `spec_version` whose `MAJOR` differs from the verifier's is `FORMAT_ERROR` (exit 3); so is a `spec_version` that does not have the form of Section 2 (for instance with leading zeros). `MINOR` is compared as a whole number, with no upper bound on its number of digits.

**Rule 2: Unknown entry types.** An `event_type` the verifier does not know (type `open_enum`, Section 2) is NOT a schema error. The verifier MUST report the finding `UNKNOWN_ENTRY_TYPE` (exit class 1), once per unknown type name, with the `seq` of its first occurrence. It MUST include the entry in the `seq`, hash-chain and Merkle checks (these do not depend on the type), MUST check `payload` only for being a JSON object, and MUST NOT treat the type as critical (immediate-checkpoint obligation, Sections 4 and 6). This is the conservative direction, and it is to be understood as such: a future critical type is NOT checked for its immediate checkpoint by an older verifier; a missing checkpoint after an unknown type is no `MISSING_CHECKPOINT` for that verifier. For the silence rules (Sections 8.1, 8.2) an unknown type is not a covering `GAP` or `RESTART`; like every entry it merely bounds the silence window per Section 8.2.

**Rule 3: The envelope stays closed.** An envelope field that Section 3 does not define remains `FORMAT_ERROR` (exit 3): the envelope is the contract; a new envelope field is a `MAJOR` change. The `payload` fields of KNOWN entry types remain strict per Section 2 (completeness, no undefined fields); the evidence-package manifest, by contrast, is governed by rule 5. Findings under rules 1, 2 and 5 are reported even when the same object also carries a schema error (`FORMAT_ERROR`); the exit code follows Section 10.3. A MINOR version MAY narrow the value range of an existing `payload` field if every value of the narrower range is also valid under the older schema; the narrowing applies to entries whose own `spec_version` is that MINOR version or a newer one, and an older verifier accepts them without the narrowing (from edition 1.8: `GENESIS.license_id`, Section 4.1).

**Rule 4: Anchor types.** The rule for unknown anchor types (Section 7.4) remains unchanged.

**Rule 5: The evidence-package manifest is extensible.** A field in `manifest.json` that Section 10.2 does not define is NOT a schema error. The verifier MUST report the finding `UNKNOWN_MANIFEST_FIELD` (exit class 1), once per unknown field path, with the path in `detail`, and MUST continue to run ALL checks it knows, in particular the minimum checks of Section 10.5. This holds for the manifest object itself AND for the objects inside its `segments`, `device_pubkeys` and `vendor_pubkeys` fields; field paths are reported without an index (`manifest.segments[].field`), so one extra field across a hundred segments yields one finding, not a hundred. The DEFINED fields remain mandatory and strict as before: a defined field that is missing, of the wrong type, or outside its value range remains `FORMAT_ERROR` (exit 3). The finding applies independently of `spec_version`: a manifest that declares the verifier's own version but carries a field unknown to it is likewise accepted and reported; a producer adding a field without a version bump violates this specification, and the verifier does not rely on it refraining.

The difference from rule 3 is not convenience but burden of proof. The manifest enters **no** hash chain, no Merkle root and no signature; an extra field there cannot change any cryptographic check. An extra envelope field, by contrast, changes the JCS bytes and therefore `entry_hash`, which is why the envelope stays closed and is a `MAJOR` question. And the finding is the price of acceptance: a verifier that does not know a manifest field cannot know whether it narrows its own check; a future field might mark a package as an excerpt. The field is therefore not passed over silently: the auditor learns that the package carries a statement this tool does not read, and can fetch a newer build. Without the finding, the rule would be an invitation to false green.

The registry mirrors these rules: `envelope_fields.spec_version` and `pruefpaket_manifest.spec_version` carry the type `version`; `envelope_fields.event_type` carries the type `open_enum` with `unknown_finding = "UNKNOWN_ENTRY_TYPE"`; `pruefpaket_manifest` carries `unknown_field_finding = "UNKNOWN_MANIFEST_FIELD"`. The test vectors `format_newer_minor`, `format_unknown_event_type` and `format_unknown_manifest_field` (registry `testvectors.format`) fix the expected behaviour.

### 10.7 Vendor key list

The list of the vendor's countersigning keys, where present, lies at `keys/vendor/schluesselliste.json` (registry `vendor_key_list`). It is a JSON object in UTF-8 without a byte order mark, without duplicate member names and with no fields other than these:

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

The vendor root the auditor supplies has the form `{"wurzel_id": …, "pubkey": …}` with exactly these two fields. It NEVER comes from the verification package: a root from the same hand as the list would only prove that the list agrees with itself.

### 10.8 Auditor Inputs and `verify_args.json`

Whatever the auditor hands to the verifier is read by the same grammar as the package (from edition 1.9); an input that violates it is an unusable invocation: exit 3 with the reason, never a silent interpretation.

- **Check time** (freshness, Section 8.5): an instant of the `rfc3339` grammar of Sections 2 and 10.7 (UTC with `Z`, uppercase `T`, ASCII digits, year `0001` to `9999`). A value without a zone, with an offset, with a blank instead of `T`, as a week date or without seconds is unusable; it is not read in the host's time zone. Without a value the system clock applies. A check time given takes precedence over `verify_args.json`; the file is then not read.
- **Expected roots** (paper anchor, Section 7.2; comparison, Section 8.6; gap witnesses, Section 11.2), any number of them, each in one of two forms: `<merkle_root>` or `<tree_size>:<merkle_root>`; `merkle_root` is 64 hex characters, upper and lower case equivalent; `tree_size` has the form `[1-9][0-9]*` and is at most 2^53−1 (`0:` and leading zeros are unusable). With `tree_size` it is found if the recomputed root over the first `tree_size` entries equals it; if `tree_size` exceeds the number of entries, it is not found. Without `tree_size` it is found if it equals the root over the first t entries for some t from 1 to the number of entries. Every expected root not found is `MERKLE_INCONSISTENT` (exit 2) and anchors nothing; every one found counts as an anchor (no `NO_ANCHOR`). Completeness (Section 8.6) holds up to the largest `tree_size` of a root found, even if another one is not found.
- **`verify_args.json`** is optional and unsigned; the producer of the package chooses its content. It is I-JSON (Section 2) and has exactly the member `now` (rfc3339 as above). The verifier reads it only when the auditor explicitly asks for it (for frozen test vectors) and names the source of the check time in the report. Asked for and absent or not conforming: exit 3 with the reason, the package is not read any further (the only finding `FORMAT_ERROR`); no fallback to the system clock, so that an explicit request never silently changes the basis of the freshness check.

## 11. Attacker Model and Limits of Proof

### 11.1 Manipulation Classes and Detection

| Class | Attack | Detection |
|---|---|---|
| `rewrite` | rewriting an entry | hash chain (`HASH_MISMATCH`), signatures (`SIG_INVALID`), Merkle roots, time witnesses (Section 7.3) |
| `truncate` | truncating the chain against anchored roots | consistency proofs against anchors and expected roots (`MERKLE_INCONSISTENT`), handover (`HANDOVER_BROKEN`), chain end (`UNSEALED_END`, Section 8.6) |
| `fork` | second history against receipts/consistency proofs, also with self-signed "receipts" under an invented vendor key | receipt prefix check (`FORK_DETECTED`, `RECEIPT_INVALID`), origin of the vendor key (`RECEIPT_UNVERIFIED`, Section 7.1), cloud-side `tree_size` monotonicity, freshness |
| `clock` | backdating against mono_delta/server time | `CLOCK_ANOMALY`, time-witness `genTime` (`TIME_ANCHOR_INVALID`); the receipts' `server_ts` is a time signed by the vendor, but the verifier compares it with no other time of the chain; it reports nothing on it |
| `silent_gap` | concealed silence without a covering GAP | TICK coverage (`CONCEALED_SILENCE`) |

Roles: **An external attacker without keys** fails against the hash chain and signatures. **The key holder** (the customer) can produce formally valid entries anew, but fails against already anchored roots: any history that is not prefix-consistent with every anchored root fails the consistency check. New "receipts" for its rewrite it can only sign under a key it holds itself; no anchor of the auditor has established that key, and the verifier reports `RECEIPT_UNVERIFIED` (Section 7.1). **The vendor** never holds the customer key and therefore cannot produce valid entries; it sees no content and cannot selectively suppress anything; its countersignatures are verifiable by any third party who supplies the vendor root published with the licence or a pinned key (Sections 7.1, 10.7); the paper anchor additionally anchors independently of the vendor.

### 11.2 Honest Limits of Proof

- **Residual window:** entries between the last countersigned checkpoint and the end of the chain are not yet externally anchored. The key holder could rewrite this **residual window** without trace before the next receipt arrives. The format does not bound its size: in licensed operation with a connection to the vendor it usually spans a few minutes (one anchor every 5 minutes), after a licence lapse, with egress switched off or in an old export any amount. The verifier MUST therefore **measure and state** it for every package that is not a format error (from edition 1.9; request of lane C of 2026-09-29): T is the `tree_size` of the last countersigned checkpoint per Section 8.6 (0 if there is none), N the number of entries. The residual window is the entries `seq` T+1 to N; to be stated are T, T+1, N, the count N − T, `ts_chained` of `seq` T (not for T = 0) and of `seq` N, the duration between them in milliseconds (Section 2; not for T = 0), the number of `ADMIN` entries with `message_type = anchor` after the receipt of that checkpoint (anchors sent without a countersignature in the package) and whether the window exceeds the cadence (T = 0 or a duration above 450,000 ms). In the JSON output of both reference verifiers the object is called `residual_window` with the members `after_tree_size`, `first_seq`, `last_seq`, `entries`, `from_ts`, `to_ts`, `span_ms`, `unanswered_anchor_messages` and `beyond_cadence`. The residual window is not a finding and does not change the exit code; if it exceeds the cadence, the report names the possible causes (licence lapse, egress off, vendor unreachable, old export) and the comparison of Section 8.6. A time witness per Section 7.3 does not shrink the window, but it changes who can exploit it: it moves the statement to an authority controlled by neither customer nor vendor; whoever rewrites the history would have to produce a token with an earlier `genTime`, which they do not have. Without a trust anchor of the auditor's own, that too remains self-reported (`TIME_ANCHOR_UNVERIFIED`).
- **Without a trust anchor of the auditor** a receipt only proves self-consistency: signature, checkpoint and prefix are checked in full, but the key comes from the package (`RECEIPT_UNVERIFIED`, Section 7.1). The statement "countersigned by the vendor" holds only with the vendor root or a pinned key.
- **Without any anchor** (air-gap, egress off), evidentiary strength against the key holder drops to the freshness/paper-anchor level; the verifier reports this as `NO_ANCHOR`. Against external manipulation, the chain remains fully evidential.
- **Fork detection needs reference points:** a rollback is only detected when at least one newer receipt, a newer paper anchor or the freshness window contradicts it.
- **Licence lapse (from edition 1.8):** once term and grace period have ended, the vendor no longer countersigns anchors. It does, however, keep checking them for consistency and records their roots as gap witnesses (heartbeat specification §9.2). The verification package holds no receipt for this period; every entry since the last receipt lies in the residual window, which, judged from the package alone, the key holder could rewrite. At the vendor, however, a rewrite reaches back only to the latest gap witness. An auditor assessing such a package SHOULD fetch the chain's signed anchor history from the vendor himself (heartbeat specification §9.7), not through the audited organisation, and check every root from it that was recorded before the package was requested (countersigned, gap witness or reported) as an expected root (Sections 7.2, 10.8): if the package contradicts one of them or lacks it, that is `MERKLE_INCONSISTENT`. A root recorded only after the request says nothing about this package; passed as an expected root, it would appear as a contradiction even for an honest package.
- **Licence key in older chains:** up to edition 1.7, `GENESIS.license_id` could carry the licence key in cleartext (Section 4.1). This does not reduce the chain's evidentiary value, but it discloses the key to every holder of the package; the verifier points this out.
- **Truncation at an earlier seal (from edition 1.6):** a chain cut off directly behind the immediate checkpoint of an earlier `SEAL` appears properly sealed; no key is needed for this. The package alone cannot refute it. It shows in the time of the seal in the report, in `TRAILING_SILENCE` outside the freshness window and, with certainty, in the comparison with the vendor's most recent countersigned root (Section 8.6). The test vector `end_truncated_at_seal` exposes this limit. Every export seal (from edition 1.9) is such a point; the client accepted this limit on 2026-09-29 as a property of the model. The verifier therefore says for every package that without a countersigned root no statement about completeness is possible, and asks for it (Section 8.6).
- **Wall-clock time:** the chain proves order (seq, monotonic clock) hard; absolute wall-clock time is evidenced only up to the bracket of receipt `server_ts` (≤ 5-minute granularity) and declared clock jumps.
- **Single lost calls (from edition 1.9, 2026-10-02):** The package contains only what was chained. If a call the appliance answered is missing and no `GAP` window holds it, this cannot be detected offline; the chain stays valid. Section 8.7 obliges the appliance to prevent it. The commitment can be evidenced only outside the package: against logs of the calling applications, against the provider's counts (Section 4.6), or by test runs with known ground truth. A `GAP` window says that calls may be missing in that time, not that any are; `lost_count = −1` means their number is unknown.
- **Content:** commitments prove the integrity of presented plaintexts, not their existence or completeness; deleted content (`CONTENT_DELETED`) can permanently no longer be presented (declared, not disguised).
- **Sovereignty as subject of proof:** the vendor knows no customer keys and sees no content; everything the appliance sends is chained verbatim as an `ADMIN` entry and is thus itself subject to verification.
