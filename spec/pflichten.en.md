# Duty Coverage Table: Operator Duties and Evidence

**LEDGER Specification · spec_version 1.9 · Language: English (German version: `pflichten.de.md`, identical structure)**

The canonical source is `spec/registry.json`, section `duty_mapping`. If this document and the registry ever diverge, the registry prevails.

## 1. Purpose and normative status

This document **normatively** defines which operator duty is evidenced by which chained entry types, which evidence kind (`evidence_kind`) that evidence belongs to, and where the honest limits of the evidence lie. Portal (coverage table), reports and the auditor guide must reproduce exactly this mapping, no more and no less.

Binding, verbatim from the registry:

> "Binding language rule: every tile says 'supports fulfilment', never 'fulfils'. Where LEDGER produces no evidence, the tile honestly says 'no evidence produced by LEDGER'."

The two evidence kinds:

| `evidence_kind` | Meaning |
|---|---|
| `chain` | cryptographically verifiable evidence: the named entry types are hash-chained, checkpoint-signed and externally anchored; a free verifier confirms existence, order and integrity |
| `descriptive` | descriptive evidence: the chain verifiably evidences THAT and WHEN something was declared, produced or changed, not its substantive correctness or adequacy |

## 2. Duty coverage table (normative)

| Duty (id) | Name | Evidencing entry types | `evidence_kind` | Honest limit |
|---|---|---|---|---|
| `protokollaufbewahrung` | Log retention | `GENESIS`, `AI_CALL`, `CHECKPOINT`, `CHECKPOINT_RECEIPT` | `chain` | - (see §3.1) |
| `aufsichts_nachweis` | Human oversight evidence | `OVERSIGHT` | `chain` | - (see §3.1) |
| `betriebsueberwachung` | Operational monitoring | `TICK`, `ALARM`, `CONFIG_CHANGE` | `chain` | - (see §3.1) |
| `transparenzbelege` | Transparency evidence | `REPORT_ISSUED` | `descriptive` | §3.2, verbatim |
| `zweckbindung` | Purpose limitation | `GENESIS`, `CONFIG_CHANGE` | `descriptive` | §3.3, verbatim |

Normative reading of each row: the chained entries of the named types **support fulfilment** of the named operator duty. Any stronger claim is impermissible (§4). Every tile of the portal table links to existing chain entries; where no evidence exists, the tile honestly shows "no evidence produced by LEDGER".

## 3. Honest limits

### 3.1 General limit of `chain` evidence

`chain` evidence proves existence, time, order and integrity of the recorded events, not their substantive quality. Example: `OVERSIGHT` entries verifiably evidence that a named person with a role and a justification approved, rejected or escalated; whether that oversight was professionally adequate is something the recorder cannot and does not judge. The registry defines no per-field `honest_limit` for the `chain` duties; this general limit applies normatively to all three.

### 3.2 Limit for `transparenzbelege` (verbatim from the registry)

> "LEDGER evidences issued reports and call metadata; it does not produce end-user transparency (labelling) itself."

### 3.3 Limit for `zweckbindung` (verbatim from the registry)

> "Evidenced are the declared system purpose (genesis), its changes, and provider/model constancy; no substantive purpose assessment takes place."

## 4. Language rule (binding)

For every duty-related text in the specification, portal, reports, alarms and documentation:

1. **Binding phrasing:** LEDGER or a piece of evidence "**supports fulfilment**" of a duty; this form of statement is the only permissible one.
2. **Impermissible** is any phrasing that ascribes to the product or to a piece of evidence that it itself observes, guarantees or conclusively proves a regulation, standard or duty (conformity/compliance promises of any kind).
3. **No-evidence case:** where LEDGER produces no evidence, the text honestly reads "**no evidence produced by LEDGER**".
4. **Machine check:** the versioned forbidden-pattern list lives in `spec/sprachregel_verbote.txt` and is checked in CI against all duty-related texts (central i18n namespace `compliance.*`). The evidence honestly states that exactly the N patterns listed there are checked. The list does not replace editorial sign-off; its one-time manual approval is documented as a chained event.

German equivalent of the binding phrasing: "unterstützt die Erfüllung"; no-evidence case: "kein Beleg durch LEDGER".
