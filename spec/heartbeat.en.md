# Cloud Messages: Activation, Heartbeat, Anchor

**LEDGER Specification · spec_version 1.9 · Language: English (German version: `heartbeat.de.md`, identical structure)**

The canonical field source is `spec/registry.json`, section `cloud_messages`. If this document and the registry ever diverge, the registry prevails.

## 1. Purpose and scope

This document exhaustively specifies all message traffic from the LEDGER appliance to the vendor metadata server. There are **exactly three message types**:

| Message type | Direction | Frequency |
|---|---|---|
| `activation` | appliance → vendor | at commissioning; again only in the cases of §4 |
| `heartbeat` | appliance → vendor | hourly |
| `anchor` | appliance → vendor | every 5 minutes |

No further message type and no further channel to the vendor exists. What the vendor answers is governed by §9. Every sent message is chained verbatim (exact JCS bytes) by the appliance as an `ADMIN` entry in its own ledger and can be inspected in the portal under "What we send". An auditor can compare actual network traffic captures against this published schema.

**Update bundles (from edition 1.9).** Outside these three messages the updater fetches update bundles over HTTPS from the source configured at installation: the metadata server or the vendor's download area, a second address. It only asks for a bundle with `GET` and sends nothing about the installation beyond what any HTTPS request discloses (address, time, the bundle's path; the path names the version and, from the addition of 2026-10-07, the installation's architecture, `amd64` or `arm64`, §9.3); in particular never the licence key, the commitment, `license_proof` or a device identifier. The source is not a trust anchor: every bundle MUST be signature-checked against the update key pinned at installation before any use, wherever it comes from, and is discarded without a valid signature; the checksum from the update notice (§9.3) protects the transport only. If a source requires an authorisation, its form is defined in this specification before it is built; sending the licence key for it is excluded. The updater's requests are not messages in the sense of this document and are not chained; an installed update evidences itself in the chain through its handover (`SEAL` with `reason = update`, `RESUME`).

## 2. Principle: no free text, by construction

> **Integers, enums and fixed-length hex only; no free-text field exists by construction.**

The recurring messages `heartbeat` and `anchor` consist exclusively of integers, enum values from fixed published value lists, fixed-length hex strings and values with a fixed grammar (UUID, RFC 3339 timestamp, SemVer). A field into which free text (such as prompts, responses, user names, source names, internal addresses or configuration content) could be written is not present in the schema and therefore cannot be filled even by misoperation or a software defect. The `activation` (at commissioning, again only in the cases of §4) additionally carries length-bounded technical identifiers (the SHA-256 commitment of the license key, the proof of possession `license_proof`, key id, IANA timezone name); it too contains no field for free content.

This property is construction, not configuration: telemetry serializes only typed structs whose schema is frozen in CI (any new field turns CI red), and the server discards everything not in the schema (§8).

## 3. Field types

| Type | Meaning |
|---|---|
| `int` | integer; per-field range (`min`/`max`) |
| `enum` | exactly one value from the stated fixed value list |
| `const` | fixed mandatory value; any other value is invalid |
| `hex64` | fixed-length hex string: 64 characters `[0-9a-f]` (32 bytes) |
| `hex128` | fixed-length hex string: 128 characters `[0-9a-f]` (64 bytes) |
| `uuid` | UUID in canonical lowercase form (36 characters) |
| `rfc3339` | RFC 3339 timestamp in UTC |
| `semver` | version per Semantic Versioning 2.0.0 |
| `version` | specification version `MAJOR.MINOR` without leading zeros (format specification §10.6); the server accepts every minor version of its own major version and rejects another major version |
| `string` | technical identifier, length-bounded (`maxlen`) or pattern-bound (`pattern`); only in `activation` |
| `intmap` | object: keys exclusively from the referenced enum → `int ≥ 0`; a missing key means 0; any key not in the enum is free text in an enum position and thus invalid (§8) |
| `enummap` | object: fixed enumerated keys → exactly one value from a fixed value list |
| `object` | object with fixed enumerated subfields; no further fields permitted |
| `array` | list of values of one fixed type, length-bounded (`max_items`); only in `anchor` (consistency proof) |

## 4. Message type `activation`

At commissioning. Registers the Ed25519 device public key against which the server verifies all later signatures.

**Renewed activation (from version 1.9).** An appliance activates again in two cases only: after the server answered `heartbeat` or `anchor` with HTTP 403 `unknown_appliance`, and after a key replacement (§4.1). A chain succession (§9.2 step 1) is a procedure at the vendor and no occasion; the activation carries no `chain_id`. Every renewed activation carries the same `appliance_id` and the same device key and is chained before sending like every message (§1). Between two activations, whatever their occasion, at least 30 seconds pass; the spacing doubles with each activation up to at most 15 minutes and starts again at 30 seconds only after an hour without an activation. That makes at most eight activations in any hour. The appliance measures the spacing with a monotonic clock; it SHOULD keep it across a restart. If it does not keep it, the first renewed activation after a restart waits the largest spacing of 15 minutes, so that a restart loop does not lift the bound.

| Field | Type | Constraint |
|---|---|---|
| `license_commitment` | hex64 | SHA-256 over the UTF-8 bytes of the license key. The key itself is never sent, never chained and never exported; the server finds the license through the commitment. The commitment is public (every verification package carries it) and proves nothing by itself |
| `license_proof` | hex64 | proof of possession of the license key (§4.1); from `spec_version` 1.8, required by the server regardless of the declared version |
| `appliance_id` | uuid | - |
| `device_pubkey` | hex64 | Ed25519 public key of the device key |
| `device_key_id` | string | maxlen 64 |
| `version` | semver | appliance software version |
| `spec_version` | version | specification version the appliance implements (`1.0`, `1.1`, …); steers the message contract of `anchor` (§6, §9) |
| `edition` | enum | `starter` \| `pro` \| `group` \| `enterprise` |
| `language` | enum | `de` \| `en` |
| `timezone` | string | maxlen 64 (IANA timezone name) |
| `sig` | hex128 | Ed25519 signature (§7) |

The server's response is governed by §9.3.

### 4.1 Proof of possession `license_proof`

The `license_commitment` is not secret: every verification package carries it, in the chained activation and from version 1.8 also in `GENESIS` (format specification 4.1). Presenting the commitment alone therefore proves nothing. The appliance proves possession of the license key with

`license_proof = HEX( HMAC-SHA256( K, M ) )`

- `K` is the UTF-8 bytes of the license key exactly as issued (without trimming and without case folding), i.e. the same bytes `license_commitment` is computed over.
- `M` is the ASCII bytes of the field value `device_pubkey` (64 characters) immediately followed by those of the field value `appliance_id` (36 characters), exactly as both appear in the same message: 100 bytes without a separator. Both fields have a fixed length; the concatenation is unambiguous.
- HMAC per RFC 2104 with SHA-256; `HEX` is lowercase hex encoding (64 characters).
- Reference values: `spec/contract/license_proof.json`.

The server checks an activation in this order: signature (§7) and schema (§8); the license via `license_commitment` (unknown: HTTP 403 `unknown_license`); `license_proof`, recomputed with the stored license key and compared in constant time (different: HTTP 403 `license_proof_invalid`, nothing is registered; if it is missing, the schema already fails: HTTP 400 `invalid_field`, field `license_proof`, before any license check; this is also what an appliance before version 1.8 gets); only then edition, appliance limit and registration. A request without a valid proof MUST NOT be counted against the license's request quota: otherwise anyone holding a verification package could use the public commitment to drive the customer's heartbeats and anchors into throttling. The server requires `license_proof` regardless of the declared `spec_version`. An older declared version is no way around the proof. Appliances already registered stay registered; the server keeps checking their heartbeats and anchors against the registered device key.

**What the proof binds.** It binds the license key to exactly one pair of device key and `appliance_id`. Whoever holds a verification package knows the commitment and the chained activation including `license_proof`, but not the key: they cannot register a device key of their own. They can only repeat the chained message verbatim. The server MUST treat a verbatim repetition (same `appliance_id`, same `device_pubkey`, same license) as already done: no new appliance, nothing counted against the appliance limit. An activation that was chained but never reached the vendor or was refused (egress off, send failure, `appliance_limit_reached`) can be submitted first by a package holder. Therefore a registered appliance counts against the appliance limit, and silence monitoring (§10) starts, only once the first valid heartbeat signed with the registered device key has arrived (from version 1.9); until then the registration is only pending. A package holder cannot sign a heartbeat. An activation for a registered `appliance_id` with a different device key stays HTTP 409 `already_registered`, even with a valid proof; replacing the device key is a procedure at the vendor, not a self-service path.

**Key form and key strength.** A license key follows the grammar `^[A-Z0-9-]{19,29}$` (registry `cloud_messages.activation.license_key_grammar`): at most 29 bytes and only uppercase letters, digits and hyphen. Both matter for security: a key over 64 bytes would, per RFC 2104, be shortened with SHA-256 before the HMAC, and the result would be exactly the public commitment, from which every `license_proof` could then be computed; and a key of 64 lowercase hex characters would look like a commitment and end up in cleartext in `GENESIS` (format specification 4.1). The commitment is an unsalted SHA-256. A license key MUST therefore also carry at least 80 bits from a cryptographically secure random generator, and the vendor MUST NOT issue freely chosen keys: a weaker key can be recovered from the public commitment by trial, and with it every `license_proof`. In this version the license key serves only this proof; any future further HMAC use MUST include its own identifier in the message, so that the proofs cannot be swapped.

**Disclosed keys.** Up to version 1.7 the standard installation wrote the license key in cleartext into `GENESIS` (format specification 4.1), and a chain can never shed it. Every key that ever stood in a `GENESIS` counts as disclosed and MUST be replaced by the vendor; for a disclosed key `license_proof` proves nothing. **Replacement (specified from version 1.9):** the license stays the same (term, registrations and anchor history remain); from then on the vendor keeps the new commitment for it, and every statement (§9.4) carries it. The operator installs the new key on the appliance; the appliance activates again with it (same `appliance_id`, same device key, valid proof under the new key), and the server rebinds the registration: HTTP 200, no `already_registered`. It no longer accepts a proof under the replaced key afterwards. `GENESIS.license_id` remains the commitment at the time the chain was created (format specification 4.1).

**Acceptance of the rebinding (from version 1.9).** The appliance counts a rebinding as accepted only once the 200 answer to its activation carries both:

1. in the member `license` a license statement effective per §9.4 with the commitment of the configured, that is the new, key, whose `server_ts` deviates from the appliance's own clock by at most 15 minutes, in either direction. It shows that the vendor holds the license under the new commitment; it is not bound to any appliance;
2. in the member `activation_receipt` an activation receipt effective per §9.8 with the appliance's own `appliance_id`, its own `device_pubkey` and the same commitment, whose `server_ts` likewise deviates by at most 15 minutes. Only the receipt binds the answer to this registration: a statement alone could be taken by someone in the transport path from the answer to another appliance of the same license.

If either is missing or not effective, the rebinding has failed. The appliance repeats it with the spacing of §4 and reports the failure. Recording and anchoring do not depend on it.

**Appliance side of the replacement (from version 1.9).** An appliance considers itself registered when it has recorded an accepted activation (a rebinding only once it is accepted per the previous paragraph) or its chain carries a `CHECKPOINT_RECEIPT`; a merely chained activation does not suffice. A registered appliance keeps sending heartbeat and anchor whatever becomes of a renewed activation. With neither, the next activation is the first: if SHA-256 of the configured key differs from the commitment in `GENESIS`, it does not activate and reports the mismatch; if it cannot read the commitment from `GENESIS`, it does not activate either and reports that. If a registered appliance does not hold under which commitment its activation was accepted (activation state from a version before 1.9, or lost), `GENESIS` decides: if it names another commitment than that of the configured key, this is a key replacement; if it names the same one or cannot be read, the appliance does not activate again. While the server holds the registration only as pending (above, "What the proof binds") and the license's appliance limit is reached, it may answer heartbeats and anchors with HTTP 403 `appliance_limit_reached` (§9.5, §9.6); it then countersigns none of their anchors. The appliance then keeps sending, reports it and does not activate again because of it.

## 5. Message type `heartbeat`

Hourly. Counters, enums and the last checkpoint only. No content, no URLs, no names.

| Field | Type | Constraint |
|---|---|---|
| `appliance_id` | uuid | - |
| `ts` | rfc3339 | send time (appliance clock) |
| `version` | semver | appliance software version |
| `spec_version` | version | specification version the appliance implements (`1.0`, `1.1`, …); steers the message contract of `anchor` (§6, §9) |
| `uptime_s` | int | min 0 |
| `mode` | enum | `full` \| `hash_only` |
| `disk_pct` | int | min 0, max 100 |
| `spool_backlog` | int | min 0 |
| `loss_counter` | int | min 0 (fsync-persistent loss counter of the doorman) |
| `gap_count_24h` | int | min 0 |
| `gap_seconds_24h` | int | min 0; from version 1.9 the length of the union of all chained `GAP` windows, clipped to the last 24 hours: overlapping windows count once (format specification 8.7) |
| `oversight_count_24h` | int | min 0 |
| `events_total` | int | min 0 |
| `events_24h` | int | min 0 |
| `events_24h_by_type` | intmap | keys from `event_types` (§5.1) |
| `calls_24h_by_provider_class` | intmap | keys from `provider_classes` (§5.1) |
| `alarms_24h_by_rule` | intmap | keys from `alarm_rules` (§5.1) |
| `health` | enummap | keys `schleuse` \| `kern` \| `portal` \| `telemetrie`; values `green` \| `yellow` \| `red` |
| `last_checkpoint` | object | `{chain_id: uuid, tree_size: int ≥ 0, merkle_root: hex64}` |
| `sig` | hex128 | Ed25519 signature (§7) |

The server's response carries the current license statement (§9.3, §9.4).

### 5.1 Permitted map keys (fixed enums from the registry)

- `event_types`: `GENESIS`, `AI_CALL`, `TICK`, `GAP`, `SOURCE_GAP`, `RECONCILIATION`, `CLOCK_JUMP`, `MODE_CHANGE`, `RESTART`, `SEAL`, `RESUME`, `OVERSIGHT`, `ALARM`, `CONFIG_CHANGE`, `KEY_ROTATION`, `REPORT_ISSUED`, `CONTENT_DELETED`, `CONTENT_DISCLOSED`, `ADMIN`, `CHECKPOINT`, `CHECKPOINT_RECEIPT`, `TIME_ANCHOR`, `CAPTURE_TRUNCATED`, `LEGAL_HOLD`
- `provider_classes`: `openai`, `anthropic`, `azure_openai`, `google`, `aws_bedrock`, `mistral`, `aleph_alpha`, `ionos`, `ollama`, `vllm`, `other_us`, `other_eu`, `other_local`, `generic` (provider **classes** from a fixed enum; never free text, never endpoint URLs)
- `alarm_rules`: `source_silence`, `volume_spike`, `error_rate_spike`, `new_provider_class`, `spool_backlog`, `disk_85`, `disk_92`, `disk_97`, `cert_expiry`, `anchor_overdue`, `report_missing`, `report_delivery_failed`, `component_silence`, `test_alarm`

## 6. Message type `anchor`

Every 5 minutes. Carries only the Merkle root (32 bytes), the tree size and, from `spec_version` 1.1, the RFC 6962 consistency proof (node hashes of the Merkle tree). No content can be reconstructed from any of it.

| Field | Type | Constraint |
|---|---|---|
| `appliance_id` | uuid | - |
| `chain_id` | uuid | - |
| `tree_size` | int | min 1 |
| `merkle_root` | hex64 | RFC 6962 Merkle root over `tree_size` leaves |
| `consistency_proof` | object | mandatory from `spec_version` 1.1 (§9); absent from the message contract for `spec_version` 1.0 |
| `consistency_proof.from_tree_size` | int | min 0; the reference size of this chain (§9.2): the largest `tree_size` the server countersigned or recorded as a gap witness (0 = none yet) |
| `consistency_proof.hashes` | array (hex64) | RFC 6962 consistency proof from `from_tree_size` to `tree_size`; empty for `from_tree_size` 0; max 64 entries |
| `sig` | hex128 | Ed25519 signature (§7) |

## 7. Signature subject

Identical for all three message types:

1. Form the message object **without** the `sig` field.
2. Canonicalize it per RFC 8785 (JCS).
3. `sig` = Ed25519 signature over these UTF-8 JCS bytes, hex-encoded (128 characters), created with the private device key belonging to `device_pubkey`/`device_key_id` from activation (for `activation` itself: the key registered inside the message; possession of the device key is shown by the self-signature, possession of the license key by `license_proof` (§4.1), which is computed over `device_pubkey` and `appliance_id` and is therefore bound to exactly this device key).

The transport channel (plain TLS, corporate-proxy compatible) is **not** evidence-bearing; the Ed25519 signatures are. The server discards any message with an invalid signature before any further processing.

## 8. Server behaviour: strict validation

The metadata server strictly validates every incoming message against the published schema:

- **Excess fields** (top-level fields not present in the schema): the message is accepted, the excess fields are **discarded and logged** (protection also against defective future appliance versions). Discarded fields are never stored.
- **Free text in an enum position** (invalid enum value, unknown map key, pattern/grammar violation for `uuid`/`rfc3339`/`semver`/`version`/`hex`/`const`/`pattern`, over-long `array` lists): **HTTP 400**, the message is rejected in full and not stored.
- **Message contract per `spec_version`:** the server validates `anchor` against the contract of the highest `spec_version` the appliance has ever declared (activation, then every heartbeat). From 1.1 `consistency_proof` is a mandatory field; for 1.0 it does not exist in the contract and would be discarded as an excess field (§9). A **lower** `spec_version` than the one on record is not adopted; the heartbeat is accepted, the downgrade is logged and counted (`spec_version_downgrades_refused_total`): whoever holds the device key cannot reopen the contract without proof by declaring backwards.
- Range violations for `int` (`min`/`max`), missing mandatory fields, invalid signature (§7): HTTP 400 or rejection.
- **Request quota (from edition 1.9).** The server limits requests per licence. A request is counted only once it has passed every check that recognises a repetition, because every sent message stands verbatim in the verification package (§1), and whoever holds one could otherwise use genuine, validly signed messages to exhaust the customer's quota and drive its heartbeats and anchors into throttling. Not counted are: an activation without a valid `license_proof` (§4.1), a verbatim repetition of an activation, a heartbeat whose `ts` is not newer than the last one accepted from this appliance or lies outside the time window, and an anchor that §9.2 step 2 or 3 answers as a repetition or as stale. Such requests are answered without effect and limited per source at most.
- **`spec_version` 1.0** is no longer accepted by the server from edition 1.9 (§9.2, "Message contract 1.0").

Hence: even a compromised or defective appliance cannot deposit free content with the vendor over this channel; the server does not accept it.

## 9. Vendor responses

The server answers with a JSON object. Only the signed objects in it carry evidence: the countersignature (§9.1), the license statements (§9.4, §9.5) and the activation receipt (§9.8). The appliance MUST ignore response members this document does not name, and it MUST NOT derive from unsigned members any decision that concerns recording, the chain or anchoring. A narrowly bounded exception is the appliance limit at the anchor (§9.5): it decides only whether an anchor is overdue and what the status shows. No vendor statement locks, deletes or alters customer data: recording continues in every license state.

### 9.1 Countersignature

The response to a valid `anchor` message under a valid license or one in its grace period is the vendor's **countersignature** (HTTP 200):

| Field | Type | Constraint |
|---|---|---|
| `chain_id` | uuid | from the request |
| `tree_size` | int | from the request |
| `merkle_root` | hex64 | from the request |
| `server_ts` | rfc3339 | server time |
| `server_key_id` | string | maxlen 64 |
| `server_signature` | hex128 | Ed25519 with the vendor key over JCS(`{chain_id, tree_size, merkle_root, server_ts}`) |

The appliance chains the response as a `CHECKPOINT_RECEIPT` entry. Any third party can verify the countersignature offline; it establishes the vendor public key through the vendor root published with the licence and the signed key list in the verification package, not through the package alone (format specification 7.1, 10.7). The server additionally enforces per-`chain_id` **tree_size monotonicity** against the reference size (§9.2): an `anchor` with a smaller `tree_size` is not accepted; a different root at a recorded size is a fork finding, a merely stale anchor is not (§9.2 step 2).

### 9.2 Consistency proof and gap witness

**Consistency proof (from `spec_version` 1.1).** Monotonicity alone does not prove that the new root extends the old one: a rewritten chain that merely *grew* would pass it. Therefore the server accepts a larger `tree_size` only when `consistency_proof` proves the extension (RFC 6962 consistency proof between `from_tree_size` and `tree_size`).

**Recorded roots and reference size.** For each chain the server records every root it has checked and accepted, countersigned (§9.1) or as a gap witness (below), with `tree_size`, `merkle_root` and server time; from edition 1.9 it MUST keep all of them (anchor history, §9.7). The largest of them is the reference size `B` with its root; while there is none, `B = 0`. An anchor is checked in this order:

1. Signature (§7), schema (§8) and whether the chain belongs to the sending appliance. From edition 1.9 additionally: if the server already keeps another chain with `B > 0` for this appliance, it records nothing for a new `chain_id` until a chain succession has been registered at the vendor (a procedure at the vendor like replacing the device key, §4.1; registered are the predecessor and the `tree_size` handed over): HTTP 409 `chain_succession_required`. Otherwise whoever holds the device key could let a rewritten history begin as a new chain at `B = 0` without any proof.
2. `tree_size < B`: if a root is recorded for exactly this `tree_size` and equals the one presented, the anchor is a repetition: for a countersigned one the server answers with the original countersignature, for a gap witness with HTTP 409 `stale_anchor`; no finding. If a different root is recorded, the device key has signed two roots of the same size: HTTP 409 `fork_detected`, fork finding. If none is recorded for this size: HTTP 409 `stale_anchor`, no finding, nothing is recorded. A stale anchor (one chained during a network outage and never delivered, one that overtakes the resend of a newer one, or one from a verification package, where every sent anchor stands verbatim) proves no fork without a consistency proof to the reference size. The server counts such anchors (`anchors_stale_total`).
3. `tree_size = B`: with the same root the anchor is a repetition: for a countersigned `B` the server answers with the original countersignature, for a witnessed `B` it continues with step 5 (after a renewal the gap witness is countersigned there); with a different root it is a fork (HTTP 409 `fork_detected`, fork finding).
4. `tree_size > B`: `from_tree_size` MUST equal `B`, otherwise the server answers HTTP 409 `consistency_required` with `expected_from_tree_size = B`; the appliance fetches the matching proof from its chain and resends the anchor once. If the proof does not hold against the root at `B` and the new root, it answers HTTP 409 `consistency_failed`, accepts nothing and records a fork finding (alarm via the sweep, history in the anchor history). With `B = 0`, `hashes` is empty: the first recorded root of a chain needs no proof.
5. Only now the license: valid or in grace → countersignature (§9.1); expired → gap witness and refusal (§9.5).

The license check comes after the consistency check. So even an anchor the server does not countersign has been checked, and a fork during a license lapse is detected like any other.

**Gap witness.** If the server refuses to countersign an anchor that passed steps 1 to 4 because the license has expired, it MUST durably record that anchor's `tree_size` and `merkle_root` as a **gap witness** of this chain before it answers; from then on they are the reference size `B`. Every later anchor of the chain, during the lapse and after a renewal, must therefore prove that it extends exactly this root. A gap witness is not a countersignature and is never delivered as one; the anchor history (§9.7) names it as what it is.

**Reported roots (from edition 1.9).** In addition the server MUST record every device-signed root that reaches it without being accepted: the `last_checkpoint` of every valid heartbeat (§5) and the root of every anchor it answers with `consistency_required`. They are not a reference size (unchecked, they prove no extension), but they stand in the anchor history as reported roots: the appliance itself declared at that time that its chain had this root.

What this closes: without gap witnesses the first anchor after a renewal only had to prove that it extends the last root BEFORE the lapse. Whoever holds the device key and the chain files could until then rewrite every entry from the lapse, rebuild the Merkle tree and have the rewritten version countersigned. With gap witnesses this reaches back, as in licensed operation, only to the latest recorded root (residual window, format specification 11.2); a rewrite before it fails the consistency proof and is reported as a fork, and in a verification package it shows in the comparison with the anchor history (§9.7). **Limit:** whoever keeps the anchors from reaching the vendor during the lapse prevents gap witnesses; he loses no receipts by it, since there are none during a lapse. As long as the heartbeats get through, their reported roots are recorded, and the anchor history shows heartbeats without an accepted anchor. If he blocks the heartbeats too, the vendor reports the silence (§10), and the anchor history ends before the lapse; the verification package shows the residual window over the whole period (format specification 11.2).

**Choice of `from_tree_size`.** The appliance SHOULD use as `from_tree_size` the latest `tree_size` the vendor countersigned for this chain (§9.1) or confirmed in an effective refusal statement (§9.5); the resend after `consistency_required` remains the fallback.

**Message contract 1.0 (ended from edition 1.9).** Up to edition 1.8 appliances with `spec_version` 1.0 had a message contract without `consistency_proof`. It has ended: whoever activates a new appliance declaring 1.0 could have its anchors recorded without any proof. From edition 1.9 the server accepts no activation and no heartbeat with `spec_version` 1.0 (HTTP 400 `invalid_field`, field `spec_version`) and no anchor without `consistency_proof`.

### 9.3 Responses at a glance

| Request | HTTP | Response |
|---|---|---|
| `activation` | 200 | `{"status": "activated", "customer_id": <string>, "license": <license statement §9.4>, "activation_receipt": <activation receipt §9.8>}`, also for an expired license; the statement then says `expired` |
| `heartbeat` | 200 | `{"status": "ok", "license": <license statement §9.4>, "update": <update notice, below>, "update_arch": <checksums per architecture, below>}`; `license` is absent when the server cannot issue a statement, `update` when no update is announced; `update_arch` is present exactly when `update` is |
| `anchor` | 200 | countersignature (§9.1) |
| `anchor` | 403 | refusal because the license expired (§9.5) |
| any | 4xx | error response (§9.6) |

**Update notice (from edition 1.9).** The member `update` of the heartbeat response announces an update (registry `cloud_response_members.update`):

| Member | Type | Meaning |
|---|---|---|
| `version` | string, `^[0-9]+\.[0-9]+\.[0-9]+$` | announced software version |
| `channel` | string, `^[a-z]{1,16}$` | delivery channel |
| `min_version` | string, `^[0-9]+\.[0-9]+\.[0-9]+$` | lowest version the bundle can be installed from |
| `release_ts` | rfc3339 | release time, form as in §9.4 item 2 (three fractional digits, `Z`) |
| `sha256` | hex64 | SHA-256 over the whole bundle |

The notice is **unsigned** and only a notice. It is neither a trust anchor nor an order: on its account the appliance MUST NOT install anything without checking the bundle against the pinned update key (§1), obtaining the customer's consent and refusing a downgrade. A forged or altered notice can therefore only name a version that does not exist or one that is validly signed anyway, or withdraw an announcement. If `update` is absent, nothing is announced; a notice that does not match the table is discarded and the previous state kept. Which updates the vendor announces and delivers depends on the licence: security fixes always, feature updates only with an active licence (decision of 29.09.2026); the vendor decides this, not the appliance. A notice changes nothing about recording.

**Checksums per architecture (from edition 1.9, addition of 2026-10-07).** Each version has one bundle per architecture. The member `update_arch` of the heartbeat response names their checksums (registry `cloud_response_members.update_arch`):

| Member | Type | Meaning |
|---|---|---|
| `amd64` | hex64 | SHA-256 over the whole bundle for amd64 (x86_64) |
| `arm64` | hex64 | SHA-256 over the whole bundle for arm64 (aarch64) |

`update_arch` has exactly these two members and is present in the response exactly when `update` is. `update` keeps its five members; its `sha256` names the amd64 bundle. The appliance takes `update_arch` only together with `update`. If `update_arch` is present without `update` or does not match the table, it discards the whole notice like a malformed `update` and keeps the previous state. The updater fetches the bundle of its own architecture, `<source>/<version>/ledger-<version>-<architecture>.rbundle`, and checks it against that architecture's checksum. If `update_arch` or its own architecture in it is missing, it fetches nothing. Everything said above about the notice applies to `update_arch`: unsigned, not a trust anchor, the checksum protects the transport only, the signature against the pinned update key stays mandatory (§1). The bundle's signed manifest does not change. Someone who alters both the notice and the source can slip an appliance a validly signed bundle of the other architecture; the signature alone does not rule that out.

### 9.4 License statement

A statement travels in the response member `license`, as an object with exactly these four members (registry `cloud_statements`):

| Member | Type | Meaning |
|---|---|---|
| `statement_jcs` | string | the statement in JCS form (RFC 8785); only these bytes are signed |
| `server_key_id` | string, `^[A-Za-z0-9._-]{1,64}$` | identifier of the vendor key, the same countersigning key as in §9.1 (format specification 10.7) |
| `server_signature` | hex128 | Ed25519 over the UTF-8 bytes of `statement_jcs` |
| `statement` | object | unsigned reading copy of `statement_jcs`; the recipient MUST ignore it |

The statement `ledger.license_statement.v1` has exactly these members:

| Member | Type | Meaning |
|---|---|---|
| `kind` | const `"ledger.license_statement.v1"` | kind of statement |
| `license_commitment` | hex64 | commitment of the license (§4) |
| `state` | enum `valid` \| `grace` \| `expired` | license state at `server_ts` |
| `countersigning` | bool | whether the vendor countersigns anchors under this license; `true` exactly when `state` is not `expired` |
| `updates` | bool | whether the license entitles to feature updates; in this version equal to `countersigning`. Security fixes do not depend on it (decision of 29.09.2026) |
| `server_ts` | rfc3339 | time of issue by the server clock |
| `valid_until` | rfc3339 or `null` | end of the term; `null` for a license without a term |
| `grace_until` | rfc3339 or `null` | end of the grace period; `null` for a license without a term |

A statement is effective only if the recipient (appliance, portal) confirms ALL of the following:

1. `statement_jcs` is I-JSON without duplicate member names and exactly the JCS form of its own content: canonicalized again, it yields the same bytes.
2. The members are exactly those of the table, with the stated types; instants have exactly the form `YYYY-MM-DDThh:mm:ss.sssZ`: UTC, three fractional digits, `Z`, as in format specification 10.7 (stricter than §3, which allows any RFC 3339 UTC time for requests); `kind` is the expected kind.
3. The key `server_key_id` is valid at `server_ts`, per the signed vendor key list (format specification 10.7) or as a key pinned at installation, and `server_signature` holds over the UTF-8 bytes of `statement_jcs`.
4. `license_commitment` is the recipient's own commitment: that of the license key installed on the appliance, not `GENESIS.license_id`, which differs after a key replacement (§4.1).
5. For `ledger.license_statement.v1` only: `countersigning` is `true` exactly when `state` is not `expired`; a contradiction makes the statement ineffective.
6. `server_ts` lies at most 15 minutes after the recipient's own clock.

The recipient never replaces an effective statement it holds by one with an older `server_ts`; so nobody can replay an old, more favourable statement, not even with a meanwhile revoked key that was valid at its time. If the latest effective statement is more than three hours (three heartbeats) old, the recipient shows it as stale.

An ineffective statement is no information; it changes nothing. An effective statement is for display (portal, telemetry status) and does not change recording either. Countersignatures and statements are signed by the same key; they cannot be confused: the signature subject of a countersignature is JCS over exactly four members without `kind`, and every statement and every activation receipt (§9.8) carries `kind`. A verifier does not evaluate statements. Reference values with a test key: `spec/contract/license_statement.json`.

### 9.5 Refusal because the license expired

If the license has expired (after its term and grace period), the server answers an anchor that passed §9.2 steps 1 to 4, after storing the gap witness, with HTTP 403:

| Member | Type | Meaning |
|---|---|---|
| `error` | const `"license_expired"` | error code (§9.6) |
| `detail` | string | explanation; not evaluated |
| `valid_until`, `grace_until` | rfc3339 or `null` | unsigned copies; not evaluated |
| `license` | object | object per §9.4 with a refusal statement `ledger.anchor_refusal.v1` |

The refusal statement has exactly these members:

| Member | Type | Meaning |
|---|---|---|
| `kind` | const `"ledger.anchor_refusal.v1"` | kind of statement |
| `license_commitment` | hex64 | commitment of the license (§4) |
| `appliance_id` | uuid | from the request |
| `chain_id` | uuid | from the request |
| `tree_size` | int, min 1 | from the request |
| `merkle_root` | hex64 | from the request |
| `server_ts` | rfc3339 | time of issue by the server clock |
| `valid_until` | rfc3339 or `null` | end of the term |
| `grace_until` | rfc3339 or `null` | end of the grace period |

It states: the vendor checked the anchor (`chain_id`, `tree_size`, `merkle_root`) of appliance `appliance_id` at `server_ts` and recorded it as a gap witness (§9.2), and it does not countersign it because the license has expired. It is not a countersignature: the appliance MUST NOT chain it as a `CHECKPOINT_RECEIPT`, and a verifier does not count it as an anchor. It is, however, a vendor-signed statement about this root at `server_ts`: whoever keeps it can present it to an auditor, who can check the root like a gap witness as an expected root (format specification 11.2). That such a transferable statement arises after the licence has expired is intended: it is the gap witness in the customer's hands.

The appliance MUST treat a 403 response to an anchor as a license lock only if ALL of the following hold:

1. `error` is `license_expired`, and `license` is present.
2. The statement is effective per §9.4 items 1 to 4, with `kind` = `ledger.anchor_refusal.v1`.
3. `appliance_id` is its own; `chain_id`, `tree_size` and `merkle_root` are exactly those of the anchor this request sent.
4. `server_ts` deviates from its own clock by at most 15 minutes.

Then the anchor counts as answered (it is not overdue), the telemetry status shows the lock, and the appliance MAY use `tree_size` as the next `from_tree_size` (§9.2). If anything does not hold, the response is an ordinary failure: the anchor stays due and is reported as missing under the telemetry's rules.

**Exception: appliance limit at the anchor (from version 1.9, addition of 2026-10-05).** A 403 `appliance_limit_reached` to an anchor is not a failure while the appliance's registration can still be only pending, that is while the server answers its heartbeat itself with `appliance_limit_reached` or has not taken any of its heartbeats since the telemetry started (§4.1). The anchor is then not overdue, the appliance chains nothing as `CHECKPOINT_RECEIPT`, keeps sending at its usual cadence and reports the state. Once the server has taken a heartbeat since the start and did not refuse the last one it answered with `appliance_limit_reached`, the registration is confirmed; the same answer to an anchor is then an ordinary failure. The state ends with any other answer of the server, including a 200 whose countersignature does not hold, but not with a transport error. The 403 is not signed. It therefore decides only whether the anchor is overdue and what the status shows, never anything about the chain or a receipt. In this state the appliance never reports `green` for `telemetrie`. Someone on the transport path can fake the state and hold it as long as the server takes no heartbeat; it stays visible while they do.

What the binding closes: a captured statement fits only the anchor it answered. Whoever sits in the transport path (for instance a TLS-intercepting corporate proxy) cannot produce a statement for a new root, and can replay an old one only for exactly the anchor it already fitted. An unbound statement, however fresh, would have made every anchor of a 15-minute window appear "answered" while no root reached the vendor (precisely the roots §9.2 needs as gap witnesses). The freshness check in item 4 additionally limits replaying the same anchor. Reference cases: `spec/contract/anchor_refusal.json`, sequence with gap witnesses: `spec/contract/lueckenzeuge.json`.

### 9.6 Error responses

An error response is `{"error": <code>, "detail": <text>}`, for some codes with additional members. `detail` is explanation and is not evaluated. The appliance treats a code not named here like any other failure.

| HTTP | `error` | Meaning | Additional members |
|---|---|---|---|
| 400 | `invalid_field` | schema violation (§8) | `field` |
| 400 | `stale_heartbeat` \| `future_heartbeat` | a heartbeat's `ts` outside the server's time window | - |
| 403 | `bad_signature` | invalid signature (§7) | - |
| 403 | `unknown_license` | no license for the commitment | - |
| 403 | `license_proof_invalid` | `license_proof` does not hold (§4.1); a missing one is HTTP 400 `invalid_field` | - |
| 403 | `edition_mismatch` | edition does not match the license | - |
| 403 | `appliance_limit_reached` | the license's appliance limit is reached: to an activation; from version 1.9 also to the heartbeat and (addition of 2026-10-05) to the anchor of a registration that is only pending (§4.1, §9.5) | - |
| 403 | `unknown_appliance` | no activation for `appliance_id` | - |
| 403 | `chain_owner_mismatch` | the chain belongs to another appliance | - |
| 403 | `license_expired` | refusal because the license expired (§9.5) | `valid_until`, `grace_until`, `license` |
| 409 | `already_registered` | `appliance_id` is registered with another device key (§4.1) | - |
| 409 | `fork_detected` | a different root at a recorded size (§9.2 steps 2 and 3) | `chain_id`, `tree_size`, `countersigned_maximum` |
| 409 | `stale_anchor` | stale or repeated anchor below the reference size, no finding (§9.2 step 2) | `chain_id`, `tree_size`, `countersigned_maximum` |
| 409 | `chain_succession_required` | new chain of an appliance that already has a chain with `B > 0`, without a registered chain succession (§9.2 step 1) | `chain_id` |
| 409 | `consistency_required` | `from_tree_size` is not the reference size (§9.2) | `chain_id`, `tree_size`, `presented_from_tree_size`, `expected_from_tree_size` |
| 409 | `consistency_failed` | the consistency proof does not hold (§9.2) | `chain_id`, `tree_size`, `countersigned_maximum` |
| 429 | `rate_limited` | request quota exhausted | - |

`countersigned_maximum` carries the reference size `B`; the name dates from version 1.1 and from version 1.8 includes gap witnesses.

### 9.7 Anchor history

The server hands out the **anchor history** of every chain (normative from edition 1.9): all recorded and reported roots (§9.2), signed like a statement (§9.4) with `kind` = `ledger.anchor_history.v1` (registry `cloud_statements.anchor_history`). It is fetched without login by the `chain_id` (`GET /v1/anchors?chain_id=<uuid>`, optionally `&since_tree_size=<n>`); the `chain_id` stands in every verification package and cannot be guessed. The history holds no personal data, no `appliance_id` and no commitment.

| Member | Type | Meaning |
|---|---|---|
| `kind` | const `"ledger.anchor_history.v1"` | kind of statement |
| `chain_id` | uuid | the chain |
| `predecessor` | object or `null` | registered chain succession (§9.2 step 1): `chain_id` of the predecessor chain and the `tree_size` handed over there |
| `successor` | object or `null` | registered successor: its `chain_id` and the `tree_size` handed over from this chain |
| `reference_tree_size` | int, min 0 | the reference size `B` |
| `roots` | array | per root: `tree_size`, `merkle_root`, `recorded_as` (`countersigned` \| `gap_witness` \| `reported`), `server_ts`; ascending by `tree_size`, for equal sizes by time |
| `forks` | array | per fork finding: `tree_size`, `merkle_root`, `detected_ts` |
| `since_tree_size` | int, min 0 | from the request; only roots from this size on |
| `truncated` | bool | `true`: more roots follow; the next request sets `since_tree_size` higher |
| `server_ts` | rfc3339 | time of issue by the server clock |

An auditor who wants to establish the completeness of a package (format specification 8.6, 11.2)

1. fetches the history from the vendor himself, not through the audited organisation (it can withhold the history but not alter it, and its absence is then information in itself);
2. checks it per §9.4 items 1 to 3 (JCS form, members, signature against the vendor root or a pinned key; it carries no commitment);
3. requires `server_ts` to lie after the package was requested, and reads all pages;
4. passes every root of the history whose `server_ts` lies before the package was requested as an expected root `<tree_size>:<merkle_root>` (format specification 10.8), countersigned ones, gap witnesses and reported ones alike. If the package does not contain one of them, it lacks entries the appliance already had before the package was requested, or it contradicts them: `MERKLE_INCONSISTENT`. If this concerns only roots from the last 15 minutes before the request (clocks, anchors in transit), the auditor requests the package anew instead of treating it as truncated;
5. on a registered chain succession also fetches the history of the other chain; likewise when a `GENESIS` names a predecessor chain (format specification 4.1). For a predecessor chain the `tree_size` handed over is its end; a root recorded there beyond it is a contradiction.

The history is neither a countersignature nor an anchor in the sense of the format specification; a verifier does not evaluate it. It supplies the auditor with the expected roots, which the verifier then checks.

### 9.8 Activation receipt

From version 1.9 every 200 answer to an activation (the first one, a verbatim repetition and a rebinding) carries an activation receipt in the member `activation_receipt`. It travels as an object per §9.4 (`statement_jcs`, `server_key_id`, `server_signature`, `statement`) with `kind` = `ledger.activation_receipt.v1` (registry `cloud_statements.activation_receipt`) and has exactly these members:

| Member | Type | Meaning |
|---|---|---|
| `kind` | const `"ledger.activation_receipt.v1"` | kind of the receipt |
| `appliance_id` | uuid | from the activation |
| `device_pubkey` | hex64 | from the activation |
| `license_commitment` | hex64 | commitment under which the vendor holds this registration at `server_ts` |
| `server_ts` | rfc3339 | time of issue by the server clock, form as in §9.4 item 2 |

It says: at `server_ts` the vendor holds the registration of `appliance_id` with this device key under this commitment. This is a statement of state, not an answer to exactly one request: an activation carries neither a time nor a nonce, and a verbatim repetition receives a receipt of the same statement. The receipt therefore proves neither possession of the license key nor that the appliance is alive; whoever holds a verification package can obtain a new one by repeating the chained activation.

It is effective when the recipient confirms §9.4 items 1 to 4: JCS form, exactly these members with these types and `kind` as above, key and signature, and `license_commitment` is that of the configured key. For accepting a rebinding, §4.1 additionally requires the appliance's own `appliance_id`, its own `device_pubkey` and freshness. A receipt is not held like a statement; the rule against older statements (§9.4) does not apply to it. It is not chained, and a verifier does not evaluate it. Reference cases: `spec/contract/activation_receipt.json`.

## 10. Silence alarm: expectation table

If the hourly heartbeat of an activated appliance stops, the cloud alarms according to a fixed table. The reference is the time since the last valid (signature-verified) heartbeat for this `appliance_id`:

| Silence duration | Mail behaviour | Recipients |
|---|---|---|
| < 3 h | **exactly 0** mails | - |
| ≥ 3 h | **exactly 1** silence mail (no repetition) | [customer contact from the license record, vendor] |
| ≥ 24 h | **exactly 1** additional escalation mail (no repetition) | [customer contact from the license record, vendor escalation list] |

At most two mails are therefore sent per silence episode. A valid heartbeat arriving again ends the episode; a later new silence starts a new episode. The test expectation (Mailhog assert) checks exactly against this table.

### 10.1 Subject patterns

Subject lines are fixed, language-neutral and machine-checkable; the mail body is localized in the license language (`language`).

| Stage | Subject (exact) |
|---|---|
| 3 h | `[LEDGER] HEARTBEAT-STILLE 3H <appliance_id>` |
| 24 h | `[LEDGER] HEARTBEAT-STILLE 24H-ESKALATION <appliance_id>` |

Check regex: `^\[LEDGER\] HEARTBEAT-STILLE (3H|24H-ESKALATION) [0-9a-f-]{36}$`

## 11. Alarm contact address: origin and display

The recipient address for silence mails comes from the **license record** at the vendor (created at purchase, updatable by the customer). It is the **only piece of personal data in the cloud**: beyond it the metadata server stores only counters, enums and 32-byte roots, and no customer login exists in the cloud. The appliance portal displays this address as the "alarm address held by the cloud", so the customer can always see where alarms would go in a silence case. In air-gap / egress-off mode the cloud silence alarm is not active; the portal states this explicitly.
