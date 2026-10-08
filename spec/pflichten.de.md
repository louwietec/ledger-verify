# Pflicht-Deckungs-Tafel: Betreiberpflichten und Belege

**Spezifikation LEDGER · spec_version 1.9 · Sprache: Deutsch (englische Fassung: `pflichten.en.md`, identische Struktur)**

Kanonische Quelle ist `spec/registry.json`, Abschnitt `duty_mapping`. Bei Abweichung zwischen diesem Dokument und der Registry gilt die Registry.

## 1. Zweck und normative Geltung

Dieses Dokument legt **normativ** fest, welche Betreiberpflicht durch welche verketteten Eintragstypen belegt wird, welcher Beleg-Art (`evidence_kind`) dieser Beleg angehört und wo die ehrlichen Grenzen des Belegs liegen. Portal (Deckungs-Tafel), Berichte und Prüferleitfaden müssen exakt diese Zuordnung wiedergeben, nicht mehr und nicht weniger.

Verbindlich aus der Registry (wörtlich):

> „Sprachregel verbindlich: jede Kachel sagt ‚unterstützt die Erfüllung', nie ‚erfüllt'. Wo LEDGER keinen Beleg erzeugt, sagt die Kachel ehrlich ‚kein Beleg durch LEDGER'."

Die zwei Beleg-Arten:

| `evidence_kind` | Bedeutung |
|---|---|
| `chain` | kryptographisch prüfbarer Beleg: die genannten Eintragstypen sind hash-verkettet, checkpoint-signiert und extern verankert; ein freier Verifier bestätigt Existenz, Reihenfolge und Unversehrtheit |
| `descriptive` | deskriptiver Beleg: die Kette belegt prüfbar, DASS und WANN etwas erklärt, erzeugt oder geändert wurde, nicht dessen inhaltliche Richtigkeit oder Angemessenheit |

## 2. Pflicht-Deckungs-Tafel (normativ)

| Pflicht (ID) | Bezeichnung | Belegende Eintragstypen | `evidence_kind` | Ehrliche Grenze |
|---|---|---|---|---|
| `protokollaufbewahrung` | Protokollaufbewahrung | `GENESIS`, `AI_CALL`, `CHECKPOINT`, `CHECKPOINT_RECEIPT` | `chain` | - (siehe §3.1) |
| `aufsichts_nachweis` | Aufsichts-Nachweis (menschliche Aufsicht) | `OVERSIGHT` | `chain` | - (siehe §3.1) |
| `betriebsueberwachung` | Betriebsüberwachung | `TICK`, `ALARM`, `CONFIG_CHANGE` | `chain` | - (siehe §3.1) |
| `transparenzbelege` | Transparenzbelege | `REPORT_ISSUED` | `descriptive` | §3.2, wörtlich |
| `zweckbindung` | Zweckbindung | `GENESIS`, `CONFIG_CHANGE` | `descriptive` | §3.3, wörtlich |

Normative Lesart je Zeile: Die verketteten Einträge der genannten Typen **unterstützen die Erfüllung** der genannten Betreiberpflicht. Eine weitergehende Aussage ist unzulässig (§4). Jede Kachel der Portal-Tafel verlinkt auf existierende Ketteneinträge; existiert kein Beleg, zeigt die Kachel ehrlich „kein Beleg durch LEDGER".

## 3. Ehrliche Grenzen

### 3.1 Allgemeine Grenze der `chain`-Belege

Ein `chain`-Beleg beweist Existenz, Zeitpunkt, Reihenfolge und Unversehrtheit der aufgezeichneten Ereignisse, nicht deren inhaltliche Qualität. Beispiel: `OVERSIGHT`-Einträge belegen prüfbar, dass eine benannte Person mit Rolle und Begründung freigegeben, abgelehnt oder eskaliert hat; ob diese Aufsicht fachlich angemessen war, kann und will der Rekorder nicht beurteilen. Die Registry definiert für die `chain`-Pflichten kein feldweises `honest_limit`; diese allgemeine Grenze gilt normativ für alle drei.

### 3.2 Grenze `transparenzbelege` (wörtlich aus der Registry)

> „LEDGER belegt erzeugte Berichte und Aufruf-Metadaten; Endnutzer-Transparenz (Kennzeichnungspflichten) erzeugt LEDGER nicht."

### 3.3 Grenze `zweckbindung` (wörtlich aus der Registry)

> „Belegt sind deklarierter Systemzweck (Genesis) und dessen Änderungen sowie Anbieter-/Modell-Konstanz; eine inhaltliche Zweckprüfung findet nicht statt."

## 4. Sprachregel (verbindlich)

Für jeden pflichtbezogenen Text in Spezifikation, Portal, Berichten, Alarmen und Dokumentation gilt:

1. **Verbindliche Formulierung:** LEDGER bzw. ein Beleg „**unterstützt die Erfüllung**" einer Pflicht; ausschließlich diese Aussageform ist zulässig.
2. **Unzulässig** ist jede Formulierung, die dem Produkt oder einem Beleg zuschreibt, eine Vorschrift, Norm oder Pflicht selbst einzuhalten, zu garantieren oder abschließend nachzuweisen (Konformitäts-/Compliance-Zusagen jeder Art).
3. **Kein-Beleg-Fall:** Wo LEDGER keinen Beleg erzeugt, lautet der Text ehrlich „**kein Beleg durch LEDGER**".
4. **Maschinenprüfung:** Die versionierte Verbotsmusterliste steht in `spec/sprachregel_verbote.txt` und wird in der CI gegen alle pflichtbezogenen Texte (zentraler i18n-Namensraum `compliance.*`) geprüft. Der Beleg benennt ehrlich, dass exakt die dort gelisteten N Muster geprüft werden. Die Liste ersetzt keine redaktionelle Abnahme; deren einmalige manuelle Freigabe wird als verkettetes Ereignis dokumentiert.

Englische Entsprechung der verbindlichen Formulierung: „supports fulfilment"; Kein-Beleg-Fall: „no evidence produced by LEDGER".
