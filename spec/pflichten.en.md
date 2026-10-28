# Duty Coverage Table: Duties and Evidence

**LEDGER Specification · spec_version 1.10 · Language: English (German version: `pflichten.de.md`, identical structure)**

The canonical source is `spec/registry.json`, section `duty_mapping`. If this document and the registry ever diverge, the registry prevails.

## 1. Purpose and normative status

This document **normatively** defines which duty is evidenced by which chained entry types, whom it concerns (addressee), which evidence kind (`evidence_kind`) that evidence belongs to, and where the honest limits of the evidence lie. Duties for which LEDGER produces no evidence are listed with the evidence kind `none`, so that no reader takes their absence for coverage. Portal (coverage table), reports and the auditor guide must reproduce exactly this mapping, no more and no less.

Binding, verbatim from the registry:

> "Binding language rule: every tile says 'supports fulfilment', never 'fulfils'. Where LEDGER produces no evidence, the tile honestly says 'no evidence produced by LEDGER'."

The three evidence kinds:

| `evidence_kind` | Meaning |
|---|---|
| `chain` | cryptographically verifiable evidence: the named entry types are hash-chained, checkpoint-signed and externally anchored; a free verifier confirms existence, order and integrity |
| `descriptive` | descriptive evidence: the chain verifiably evidences THAT and WHEN something was declared, produced or changed, not its substantive correctness or adequacy |
| `none` | no evidence produced by LEDGER: no entry type evidences the duty; the row names it with its honest limit so the table does not feign coverage |

## 2. Duty coverage table (normative)

| Duty (id) | Name | Evidencing entry types | `evidence_kind` | Addressee | Reference (Regulation (EU) 2024/1689) | Honest limit |
|---|---|---|---|---|---|---|
| `protokollaufbewahrung` | Log retention | `GENESIS`, `AI_CALL`, `CHECKPOINT`, `CHECKPOINT_RECEIPT` | `chain` | provider, deployer | Art. 12(1) and Art. 19(1) (provider); Art. 26(6) (deployer) | §3.4, verbatim, and §3.1 |
| `aufsichts_nachweis` | Human oversight evidence | `OVERSIGHT` | `chain` | provider, deployer | Art. 12(3)(d) (provider); Art. 26(5) (deployer, monitoring) | - (see §3.1) |
| `betriebsueberwachung` | Operational monitoring | `TICK`, `ALARM`, `CONFIG_CHANGE` | `chain` | provider, deployer | Art. 12(2)(c) (provider); Art. 26(5) (deployer, monitoring) | - (see §3.1) |
| `transparenzbelege` | Transparency evidence | `REPORT_ISSUED` | `descriptive` | deployer | Art. 50(3) and (4), Art. 26(7) and (11), Art. 86 (deployer) | §3.2, verbatim |
| `zweckbindung` | Purpose limitation | `GENESIS`, `CONFIG_CHANGE` | `descriptive` | provider | Art. 12(2)(a) (provider, changes only) | §3.3, verbatim |
| `meldung_aussetzung` | Reporting and suspension | none | `none` | deployer | Art. 26(5) (deployer, informing and suspending) | §3.5, verbatim |
| `beobachtungsdaten` | Monitoring data (post-market monitoring) | `AI_CALL`, `REPORT_ISSUED` | `descriptive` | provider | Art. 12(2)(b) and Art. 72 (provider) | §3.6, verbatim |
| `biometrie_abgleich` | Remote biometric identification log (reference database, input data with a match) | none | `none` | provider | Art. 12(3)(b) and (c), Annex III point 1(a) (provider) | §3.7, verbatim |

Normative reading of each row: the chained entries of the named types **support fulfilment** of the named duty; a row of evidence kind `none` says "no evidence produced by LEDGER". Any stronger claim is impermissible (§4). Every tile of the portal table links to existing chain entries; where no evidence exists, the tile honestly shows "no evidence produced by LEDGER".

## 3. Honest limits

### 3.1 General limit of `chain` evidence

`chain` evidence proves existence, time, order and integrity of the recorded events, not their substantive quality. Example: `OVERSIGHT` entries verifiably evidence that a named person with a role and a justification approved, rejected or escalated; whether that oversight was professionally adequate is something the recorder cannot and does not judge. The registry defines no per-field `honest_limit` for `aufsichts_nachweis` and `betriebsueberwachung`, and the one of §3.4 for `protokollaufbewahrung`; this general limit applies normatively to all three.

### 3.2 Limit for `transparenzbelege` (verbatim from the registry)

> "LEDGER evidences issued reports and call metadata; it does not produce end-user transparency (labelling) itself. For the transparency duties of the provider (Art. 13, Art. 50(1) and (2)): no evidence produced by LEDGER."

### 3.3 Limit for `zweckbindung` (verbatim from the registry)

> "Evidenced are the declared system purpose (genesis), its changes, and provider/model constancy; no substantive purpose assessment takes place."

### 3.4 Limit for `protokollaufbewahrung` (verbatim from the registry, from edition 1.10)

> "The format sets no retention period and checks none; only vault contents are deleted (CONTENT_DELETED), never chain entries; a single lost call cannot be recognised offline in the verification package (format specification 11.2)."

### 3.5 Limit `meldung_aussetzung` (verbatim from the registry, from version 1.10)

> "No evidence produced by LEDGER: there is no entry type for informing the provider or distributor and the market surveillance authority or for suspending use. Monitoring of operation is evidenced by the row operational monitoring."

### 3.6 Limit `beobachtungsdaten` (verbatim from the registry, from version 1.10)

> "Evidenced are the metadata of every call (time, model, outcome, duration, sizes and token counts) and issued reports; LEDGER does not produce a post-market monitoring system, its analysis or the transfer to the provider."

### 3.7 Limit `biometrie_abgleich` (verbatim from the registry, from version 1.10)

> "No evidence produced by LEDGER: LEDGER records neither the reference database against which input data was checked nor the input data that led to a match."

### 3.8 Addressee (from version 1.10)

The column "Addressee" names whom the duty concerns under Regulation (EU) 2024/1689: the **provider** of the AI system (for example Art. 12, Art. 19, Art. 72) or its **deployer** (Art. 26). LEDGER runs at the deployer and records at the interface of the calls. For a duty of the provider this means: if the deployer is not itself the provider of the system, the duty has "**no evidence produced by LEDGER**"; if it is, the evidence supports fulfilment only for what is visible at that interface. A row with "not yet assigned" has no fixed addressee yet; its tile names none.

## 4. Language rule (binding)

For every duty-related text in the specification, portal, reports, alarms and documentation:

1. **Binding phrasing:** LEDGER or a piece of evidence "**supports fulfilment**" of a duty; this form of statement is the only permissible one.
2. **Impermissible** is any phrasing that ascribes to the product or to a piece of evidence that it itself observes, guarantees or conclusively proves a regulation, standard or duty (conformity/compliance promises of any kind).
3. **No-evidence case:** where LEDGER produces no evidence, the text honestly reads "**no evidence produced by LEDGER**".
4. **Forbidden-pattern list:** the versioned list of impermissible phrasings lives in `spec/sprachregel_verbote.txt` and applies to all duty-related texts (central i18n namespace `compliance.*`). A text that matches a pattern of the list is impermissible. The list covers only the patterns it names; a text that matches none does not thereby already satisfy item 2. It does not replace an editorial sign-off of the texts; the sign-off on the appliance is recorded as a chained `CONFIG_CHANGE` event with `scope` = `compliance_signoff`.

German equivalent of the binding phrasing: "unterstützt die Erfüllung"; no-evidence case: "kein Beleg durch LEDGER".
