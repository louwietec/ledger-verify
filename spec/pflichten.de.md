# Pflicht-Deckungs-Tafel: Pflichten und Belege

**Spezifikation LEDGER · spec_version 1.10 · Sprache: Deutsch (englische Fassung: `pflichten.en.md`, identische Struktur)**

Kanonische Quelle ist `spec/registry.json`, Abschnitt `duty_mapping`. Bei Abweichung zwischen diesem Dokument und der Registry gilt die Registry.

## 1. Zweck und normative Geltung

Dieses Dokument legt **normativ** fest, welche Pflicht durch welche verketteten Eintragstypen belegt wird, wen sie trifft (Adressat), welcher Beleg-Art (`evidence_kind`) dieser Beleg angehört und wo die ehrlichen Grenzen des Belegs liegen. Pflichten, für die LEDGER keinen Beleg erzeugt, stehen mit der Beleg-Art `none` in der Tafel, damit kein Leser ihr Fehlen für eine Deckung hält. Portal (Deckungs-Tafel), Berichte und Prüferleitfaden müssen exakt diese Zuordnung wiedergeben, nicht mehr und nicht weniger.

Verbindlich aus der Registry (wörtlich):

> „Sprachregel verbindlich: jede Kachel sagt ‚unterstützt die Erfüllung', nie ‚erfüllt'. Wo LEDGER keinen Beleg erzeugt, sagt die Kachel ehrlich ‚kein Beleg durch LEDGER'."

Die drei Beleg-Arten:

| `evidence_kind` | Bedeutung |
|---|---|
| `chain` | kryptographisch prüfbarer Beleg: die genannten Eintragstypen sind hash-verkettet, checkpoint-signiert und extern verankert; ein freier Verifier bestätigt Existenz, Reihenfolge und Unversehrtheit |
| `descriptive` | deskriptiver Beleg: die Kette belegt prüfbar, DASS und WANN etwas erklärt, erzeugt oder geändert wurde, nicht dessen inhaltliche Richtigkeit oder Angemessenheit |
| `none` | kein Beleg durch LEDGER: kein Eintragstyp belegt die Pflicht; die Zeile nennt sie mit ihrer ehrlichen Grenze, damit die Tafel keine Deckung vortäuscht |

## 2. Pflicht-Deckungs-Tafel (normativ)

| Pflicht (ID) | Bezeichnung | Belegende Eintragstypen | `evidence_kind` | Adressat | Fundstelle (VO (EU) 2024/1689) | Ehrliche Grenze |
|---|---|---|---|---|---|---|
| `protokollaufbewahrung` | Protokollaufbewahrung | `GENESIS`, `AI_CALL`, `CHECKPOINT`, `CHECKPOINT_RECEIPT` | `chain` | Anbieter, Betreiber | Art. 12 Abs. 1 und Art. 19 Abs. 1 (Anbieter); Art. 26 Abs. 6 (Betreiber) | §3.4, wörtlich, und §3.1 |
| `aufsichts_nachweis` | Aufsichts-Nachweis (menschliche Aufsicht) | `OVERSIGHT` | `chain` | Anbieter, Betreiber | Art. 12 Abs. 3 lit. d (Anbieter); Art. 26 Abs. 5 (Betreiber, Überwachen) | - (siehe §3.1) |
| `betriebsueberwachung` | Betriebsüberwachung | `TICK`, `ALARM`, `CONFIG_CHANGE` | `chain` | Anbieter, Betreiber | Art. 12 Abs. 2 lit. c (Anbieter); Art. 26 Abs. 5 (Betreiber, Überwachen) | - (siehe §3.1) |
| `transparenzbelege` | Transparenzbelege | `REPORT_ISSUED` | `descriptive` | Betreiber | Art. 50 Abs. 3 und 4, Art. 26 Abs. 7 und 11, Art. 86 (Betreiber) | §3.2, wörtlich |
| `zweckbindung` | Zweckbindung | `GENESIS`, `CONFIG_CHANGE` | `descriptive` | Anbieter | Art. 12 Abs. 2 lit. a (Anbieter, nur Änderungen) | §3.3, wörtlich |
| `meldung_aussetzung` | Meldung und Aussetzung | keine | `none` | Betreiber | Art. 26 Abs. 5 (Betreiber, Informieren und Aussetzen) | §3.5, wörtlich |
| `beobachtungsdaten` | Beobachtungsdaten (Beobachtung nach dem Inverkehrbringen) | `AI_CALL`, `REPORT_ISSUED` | `descriptive` | Anbieter | Art. 12 Abs. 2 lit. b und Art. 72 (Anbieter) | §3.6, wörtlich |
| `biometrie_abgleich` | Protokoll biometrischer Fernidentifizierung (Referenzdatenbank, Eingaben mit Treffer) | keine | `none` | Anbieter | Art. 12 Abs. 3 lit. b und c, Anhang III Nr. 1 lit. a (Anbieter) | §3.7, wörtlich |

Normative Lesart je Zeile: Die verketteten Einträge der genannten Typen **unterstützen die Erfüllung** der genannten Pflicht; eine Zeile der Beleg-Art `none` sagt „kein Beleg durch LEDGER“. Eine weitergehende Aussage ist unzulässig (§4). Jede Kachel der Portal-Tafel verlinkt auf existierende Ketteneinträge; existiert kein Beleg, zeigt die Kachel ehrlich „kein Beleg durch LEDGER".

## 3. Ehrliche Grenzen

### 3.1 Allgemeine Grenze der `chain`-Belege

Ein `chain`-Beleg beweist Existenz, Zeitpunkt, Reihenfolge und Unversehrtheit der aufgezeichneten Ereignisse, nicht deren inhaltliche Qualität. Beispiel: `OVERSIGHT`-Einträge belegen prüfbar, dass eine benannte Person mit Rolle und Begründung freigegeben, abgelehnt oder eskaliert hat; ob diese Aufsicht fachlich angemessen war, kann und will der Rekorder nicht beurteilen. Die Registry definiert für `aufsichts_nachweis` und `betriebsueberwachung` kein feldweises `honest_limit`, für `protokollaufbewahrung` das aus §3.4; diese allgemeine Grenze gilt normativ für alle drei.

### 3.2 Grenze `transparenzbelege` (wörtlich aus der Registry)

> „LEDGER belegt erzeugte Berichte und Aufruf-Metadaten; Endnutzer-Transparenz (Kennzeichnungspflichten) erzeugt LEDGER nicht. Für die Transparenzpflichten des Anbieters (Art. 13, Art. 50 Abs. 1 und 2): kein Beleg durch LEDGER."

### 3.3 Grenze `zweckbindung` (wörtlich aus der Registry)

> „Belegt sind deklarierter Systemzweck (Genesis) und dessen Änderungen sowie Anbieter-/Modell-Konstanz; eine inhaltliche Zweckprüfung findet nicht statt."

### 3.4 Grenze `protokollaufbewahrung` (wörtlich aus der Registry, ab Fassung 1.10)

> „Das Format legt keine Aufbewahrungsfrist fest und prüft keine; gelöscht werden nur Inhalte im Tresor (CONTENT_DELETED), nie Einträge der Kette; ein einzelner verlorener Aufruf ist im Prüfpaket offline nicht zu erkennen (Format-Spezifikation 11.2)."

### 3.5 Grenze `meldung_aussetzung` (wörtlich aus der Registry, ab Fassung 1.10)

> „Kein Beleg durch LEDGER: Für die Information von Anbieter oder Händler und Marktüberwachungsbehörde und für das Aussetzen der Nutzung gibt es keinen Eintragstyp. Das Überwachen des Betriebs belegt die Zeile Betriebsüberwachung.“

### 3.6 Grenze `beobachtungsdaten` (wörtlich aus der Registry, ab Fassung 1.10)

> „Belegt sind Metadaten jedes Aufrufs (Zeit, Modell, Ergebnis, Dauer, Größen und Token-Zahlen) und erzeugte Berichte; ein System zur Beobachtung nach dem Inverkehrbringen, seine Auswertung und die Weitergabe an den Anbieter erzeugt LEDGER nicht.“

### 3.7 Grenze `biometrie_abgleich` (wörtlich aus der Registry, ab Fassung 1.10)

> „Kein Beleg durch LEDGER: LEDGER hält weder die Referenzdatenbank fest, gegen die Eingaben abgeglichen wurden, noch die Eingabedaten, die zu einem Treffer führten.“

### 3.8 Adressat (ab Fassung 1.10)

Die Spalte „Adressat“ nennt, wen die Pflicht nach der VO (EU) 2024/1689 trifft: den **Anbieter** des KI-Systems (etwa Art. 12, Art. 19, Art. 72) oder seinen **Betreiber** (Art. 26). LEDGER läuft beim Betreiber und zeichnet an der Schnittstelle der Aufrufe auf. Für eine Pflicht des Anbieters gilt deshalb: Ist der Betreiber nicht selbst Anbieter des Systems, gilt für diese Pflicht „**kein Beleg durch LEDGER**“; ist er es, unterstützt der Beleg die Erfüllung nur für das, was an dieser Schnittstelle sichtbar ist. Eine Zeile mit „noch nicht zugeordnet“ hat noch keinen festgelegten Adressaten; ihre Kachel nennt keinen.

## 4. Sprachregel (verbindlich)

Für jeden pflichtbezogenen Text in Spezifikation, Portal, Berichten, Alarmen und Dokumentation gilt:

1. **Verbindliche Formulierung:** LEDGER bzw. ein Beleg „**unterstützt die Erfüllung**" einer Pflicht; ausschließlich diese Aussageform ist zulässig.
2. **Unzulässig** ist jede Formulierung, die dem Produkt oder einem Beleg zuschreibt, eine Vorschrift, Norm oder Pflicht selbst einzuhalten, zu garantieren oder abschließend nachzuweisen (Konformitäts-/Compliance-Zusagen jeder Art).
3. **Kein-Beleg-Fall:** Wo LEDGER keinen Beleg erzeugt, lautet der Text ehrlich „**kein Beleg durch LEDGER**".
4. **Verbotsmusterliste:** Die versionierte Liste unzulässiger Formulierungen steht in `spec/sprachregel_verbote.txt` und gilt für alle pflichtbezogenen Texte (zentraler i18n-Namensraum `compliance.*`). Ein Text, der ein Muster der Liste trifft, ist unzulässig. Die Liste erfasst nur die Muster, die sie nennt; ein Text, der keines trifft, erfüllt damit nicht schon Punkt 2. Sie ersetzt keine redaktionelle Abnahme der Texte; die Abnahme an der Appliance wird als verkettetes Ereignis `CONFIG_CHANGE` mit `scope` = `compliance_signoff` festgehalten.

Englische Entsprechung der verbindlichen Formulierung: „supports fulfilment"; Kein-Beleg-Fall: „no evidence produced by LEDGER".
