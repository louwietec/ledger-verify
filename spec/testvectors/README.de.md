# Testvektoren

**Spezifikation Rekorder · spec_version 1.10 · Sprache: Deutsch (englische Fassung: `README.en.md`, identische Struktur)**

Kanonische Liste aller Vektoren und ihrer Erwartungen ist `spec/registry.json`, Abschnitt `testvectors`. Die CI prüft Registry × vorhandene Dateien als vollständige Matrix; Maßstab ist die Registry, nicht der zufällige Dateibestand.

## 1. Zweck

Die Testvektoren sind der **gemeinsame Vertrag** zwischen Kettenschreiber (Appliance) und allen Prüfern: Der freie Go-Verifier und der unabhängige Python-Zweitverifier teilen keinen Code; sie teilen ausschließlich die Spezifikation und diese Vektoren. Jeder Vektor ist ein vollständiges Prüfpaket mit fest definierter Soll-Ausgabe; ein Verifier ist genau dann spezifikationskonform, wenn er über den gesamten Korpus exakt die erwarteten Exit-Codes und Befundklassen liefert. Der Korpus deckt ab:

- **gültige Ketten** (auch mit ehrlich ausgewiesenen Befunden: gedeckte Lücken, Uhrensprung, Löschung, Abgleich-Differenz, fehlender Anker, Stale-Ende) und das **versiegelte Kettenende** (`valid_sealed_shutdown`, `valid_sealed_update_receipt`),
- **je eine Manipulationsklasse pro Negativvektor** (Umschreiben, Kürzen, Fork, Uhr, verschwiegene Stille; plus Signatur-, Quittungs-, Handover-, Commitment- und Berichtsbrüche),
- **je eine Lückenklasse** (`bypass`, `proxy_restart`, `power_loss`, `spool_unwritable`, `host_down`, `update`, `manual`),
- **das Kettenende** (Gruppe `end`, seit Spezifikation 1.6, Formatspezifikation Abschnitt 8.6): versiegelt, aber veraltet; unvollständig, weil dem letzten kritischen Eintrag oder dem letzten `SEAL` der Sofort-Checkpoint fehlt; und die ausgewiesene Nachweisgrenze einer Kürzung an einem früheren Siegel (§5, §6),
- **die Löschsperre** (Gruppe `hold`, seit Spezifikation 1.7, Formatspezifikation Abschnitte 4.24 und 9.3): eine Löschung außerhalb des Umfangs einer aktiven Sperre, eine Löschung nach Aufhebung der Sperre und eine Löschung trotz aktiver Sperre (`HOLD_VIOLATION`, §7),
- **das Lizenz-Commitment** (Gruppe `license`, seit Spezifikation 1.8, Formatspezifikation Abschnitt 4.1): `GENESIS` mit dem Commitment, `GENESIS` einer aktualisierten 1.7-Appliance mit dem Schlüssel im Klartext (Hinweis, kein Befund) und `GENESIS` der Fassung 1.8 mit dem Schlüssel im Klartext (`FORMAT_ERROR`, §8),
- **Formatfehler** (kaputtes JSON, schema-widriges Paket),
- **Vorwärtskompatibilität** (Formatspezifikation Abschnitt 10.6): ein Paket mit neuerer Minor-Version (`format_newer_minor`, Befund `SPEC_NEWER`), ein Paket mit einem dieser Version unbekannten Eintragstyp (`format_unknown_event_type`, Befund `UNKNOWN_ENTRY_TYPE`) und ein Paket mit einem unbekannten Manifestfeld (`format_unknown_manifest_field`, Befund `UNKNOWN_MANIFEST_FIELD`); nicht Exit 3: der Verifier prüft weiter, was er kennt. Alle drei enden unversiegelt und tragen daneben `UNSEALED_END` (Exit 4).

Damit ist auch die Exit-Semantik festgenagelt: Eine ehrlich ausgewiesene Lücke macht die Kette nicht ungültig (Exit 1, bei unversiegeltem Ende Exit 4), eine verschwiegene schon (Exit 2). Ein unversiegeltes Ende ist kein Manipulationsbefund, sondern ein eigener Status (Exit 4); „ungültig" (Exit 2) bleibt nachgewiesener Manipulation vorbehalten.

## 2. Verzeichnis-Layout

Je Vektor ein Ordner mit den Dateien eines Prüfpakets; die Erwartung liegt daneben unter `expected/<name>.json`:

```
spec/testvectors/
├── README.de.md · README.en.md     # dieses Dokument
├── PINS.sha256                     # SHA-256-Pin je eingefrorener Vektor-Datei (§4)
├── pruefer_herstellerwurzel.json   # Prüfumgebung: Wurzel des Testherstellers (§3)
├── pruefer_herstellerschluessel.txt  # Prüfumgebung: angehefteter Testschlüssel (§3)
├── pruefer_<name>.json             # Prüfumgebung eines Vektors ab 1.10 (ledger-pruefumgebung/1, §10)
├── pruefer_<name>.<Member>-<n>.*   # die Dateien, die sie nennt (§10)
├── zeitstempel_<name>.*            # Eingaben der Einzelprüfung von Zeitstempeln (§10.4)
├── zeitstempelstelle_e1.json       # Zertifikate und Token der Zeitstempelstelle E1 mit verworfenen Schlüsseln (§11.2)
├── zeitstempelstelle_e2.json       # Zertifikate und Token der Zeitstempelstelle E2 mit verworfenen Schlüsseln (§13.2)
├── zeitstempelstelle_e3.json       # Zertifikate und Token der Zeitstempelstelle E3 mit verworfenen Schlüsseln (§14.2)
├── protokoll/                      # Referenzfall eines veröffentlichten Herstellerprotokolls (§11.4)
├── expected/
│   └── <name>.json                 # Soll-Ausgabe je Vektor (§3)
└── <name>/                         # ein Ordner je Vektor = ein vollständiges Prüfpaket
    ├── manifest.json               # Prüfpaket-Manifest (Registry: pruefpaket_manifest)
    ├── segments/*.jsonl            # Ketten-Segmente (kanonisches JSON, ein Eintrag je Zeile)
    ├── verify_args.json            # Prüfzeit des Vektors (`now`), nur mit --now-from-package
    └── …                           # je nach Vektor: Quittungen, Publikeys, vorgelegte Klartexte/Salts, Berichts-Hashes
```

Vektor-Namen (`valid_*`, `gap_*`, `end_*`, `hold_*`, `tamper_*`, `format_*`, ab 1.10 `roles_*`, `auditor_*`, `timestamp_*`, `log_*`, `history_*`, `evidence_*`) und ihre Sollwerte sind abschließend in der Registry definiert; dieses README zählt sie bewusst nicht erneut auf. Ausgenommen sind die acht Vektoren der Spezifikation 1.6 (§5), die drei der Spezifikation 1.7 (§7), die drei der Spezifikation 1.8 (§8), die neun der Spezifikation 1.9 (§9), die 130 der Grundlagen von 1.10 (§10), die 89 des Herstellerprotokolls (§11), die 115 der Anker-Historie (§12), die 26 der Beweisstufe (§13), die 16 zu den Entscheidungen vom 26.10. (§14) und die drei Pakete aus dem Abgleich beider Verifier (§15): Was sie zeigen, geht aus dem Namen allein nicht hervor. Ihre Tabellen nennen die Sollwerte der Registry, und `TestKettenendeTabelleFolgtDerErwartung`, `TestHoldTabelleFolgtDerErwartung` `TestLizenzTabelleFolgtDerErwartung` und `TestV19TabelleFolgtDerErwartung` (`appliance/cmd/vektorgen`) halten sie gegen `expected/`.

## 3. Erwartete Ergebnisse (`expected/`)

Je Vektor genau eine Datei `expected/<name>.json`, zum Beispiel `expected/end_sealed_stale.json`:

```json
{
  "exit_code": 1,
  "finding_classes": ["TRAILING_SILENCE"]
}
```

- `exit_code`: erwarteter Verifier-Exit-Code: `0` gültig ohne Befunde, `1` gültig mit Befunden, `2` ungültig, `3` Formatfehler, `4` unvollständig: Kettenende nicht versiegelt (Registry: `verifier.exit_codes`). Maßgeblich ist die Rangfolge 3 vor 2 vor 4 vor 1 vor 0 (Registry: `verifier.exit_precedence`), nicht die Größe der Zahl.
- `finding_classes`: exakte Liste der erwarteten Befundklassen (Registry: `verifier.finding_classes`); leere Liste bei `exit_code` 0. Die Liste ist die Menge der gemeldeten Klassen: Eine Klasse, die ein Verifier zweimal meldet (etwa einen Befund an einem Tag neben einem Lauf fehlender Tage derselben Klasse, wie Formatspezifikation 7.4.11 verlangt), steht einmal darin.

Die Erwartung ist **exakt**, nicht „mindestens": beide Verifier müssen genau diesen Exit-Code und genau diese Befundklassen liefern.

**Ab Spezifikation 1.10** kann eine Solldatei zusätzlich `evidence_level` (die Beweisstufe mit der Prüfumgebung des Korpus) und `auditor_inputs` (`null`, oder Datei, Exit-Code, Befundklassen und Beweisstufe mit der Prüfumgebung `pruefer_<name>.json` des Vektors) tragen (Registry `expected_files`); `evidence_level` nennt `state`, `level`, `up_to_tree_size`, den Verlauf als `[level, first_seq, last_seq]`, je Bedingung den Grund oder `null`, die Hinweise und den Status der Verbundenheit. Für einen unbrauchbaren Aufruf (Exit 3 ohne Bericht, Formatspezifikation 10.8) ist `auditor_inputs.evidence_level` `null`: Ohne Bericht gibt es keine Beweisstufe (10.9.2, 10.10.1); das Objekt des Zustands `format_error` steht nur, wo ein Formatfehler einen Bericht schreibt (`FORMAT_ERROR`). Ein Vektor ohne diese Member bleibt, wie er ist.

**Prüfumgebung (seit Spezifikation 1.4).** Die Erwartungen gelten für einen Prüfer, der zwei Vertrauensanker mitbringt (Spezifikation 7.1): die Wurzel des Testherstellers in `pruefer_herstellerwurzel.json` (`--vendor-root`) und dessen angehefteten Schlüssel in `pruefer_herstellerschluessel.txt` (je Zeile `key_id=hex`, `--vendor-key`). Beide Dateien liegen neben den Vektoren, nicht in ihnen, und sind mitgepinnt. Wer ohne Anker prüft, bekommt bei jedem Vektor mit Quittung zusätzlich `RECEIPT_UNVERIFIED`; das ist das vorgesehene Verhalten, kein Fehler des Korpus. Eine Ausnahme: `tamper_vendor_revoked` braucht die Wurzel, um den Widerspruch der Liste überhaupt zu sehen; ohne Anker ergibt es statt Exit 2 `[NO_ANCHOR, RECEIPT_INVALID, UNSEALED_END]` nur Exit 4 `[RECEIPT_UNVERIFIED, UNSEALED_END]`. Die drei Hersteller-Vektoren von 1.4 (`valid_vendor_list`, `tamper_vendor_key`, `tamper_vendor_revoked`) quittieren unter Schlüsseln, für die nur die signierte Liste im Paket bürgt, oder eben nicht; alle anderen Vektoren mit Quittung, auch die acht von 1.6 und die drei von 1.7, quittieren unter `vendor-test-001` (angeheftet).

## 4. Einfrieren (`PINS.sha256`)

Die kryptogültigen Bytes der Vektoren (echte Hash-Ketten, Merkle-Roots, Ed25519-Signaturen und Gegensignaturen mit publizierten Testschlüsseln) werden **vom Ledger-Vektor-Generator erzeugt**; sie sind von Hand nicht herstellbar. Nach der Erzeugung wird jede Vektor-Datei per SHA-256 in `PINS.sha256` gepinnt und **nie mehr geändert**: Die CI vergleicht die Dateien bei jedem Lauf gegen die Pins; jede Abweichung ist rot. Bis dahin existieren nur die Soll-Definitionen unter `expected/`; ein Vektor gilt erst mit Pin als eingefroren und referenzierbar. Neue Anforderungen führen zu **neuen** Vektoren (Registry-Eintrag + neuer Pin), niemals zur Änderung eingefrorener.

Jeder Vektor erklärt die `spec_version`, unter der er eingefroren wurde, als Literal, für immer (`TestEingefroreneVersionenBleibenStehen`). Nur `format_newer_minor` leitet seine Version ab: er muss per Definition eine Minor-Version über der aktuellen liegen und wird deshalb bei jedem Versionssprung neu erzeugt und neu gepinnt, mit Spezifikation 1.10 auf `1.11`.

**Eine Ausnahme, aufgeschrieben statt verschwiegen.** Die Regel „nie mehr geändert" setzt voraus, dass der Maßstab selbst stillsteht. Mit der Freigabe von Abschnitt 6.2 Regel 3 (der Sofort-Checkpoint gilt ausnahmslos und schließt `SEAL` ein) traf das nicht mehr zu: Die Vektoren `valid_update_handover` und `tamper_handover` schrieben `SEAL → RESUME` ohne den vorgeschriebenen Sofort-Checkpoint und verletzten damit genau die Spezifikation, für die sie der Maßstab sein sollen; `valid_update_handover` war zudem als *gültig* ausgewiesen. Beide wurden deshalb neu erzeugt und neu gepinnt; ihre Sollwerte in `expected/` blieben unverändert, weil die Erwartung nie falsch war, nur die Kette. Dass sich **ausschließlich** diese beiden Vektoren geändert haben und die übrigen 27 Byte für Byte gleich geblieben sind, ist per Hash nachgewiesen. Ein eingefrorener Vektor wird nur dann neu erzeugt, wenn die freigegebene Spezifikation ihn nachweislich widerlegt; nie, um einen Verifier grün zu bekommen.

**Zweite Ausnahme: Spezifikation 1.6 (Kettenende).** Mit der Freigabe von Abschnitt 8.6 wird jede Kette auch nach ihrem Ende beurteilt, und alle bis 1.5 eingefrorenen Vektoren enden unversiegelt, wie ein Export aus laufendem Betrieb. Die Erwartungen der 38 eingefrorenen Vektoren, die kein Formatfehler sind, haben sich deshalb mit der freigegebenen Spezifikation 1.6 geändert: Jeder trägt zusätzlich `UNSEALED_END`, Exit 4 statt 0 oder 1; wo schon ein Befund der Exit-Klasse 2 stand, bleibt es Exit 2. Ihre **Bytes** sind unverändert, bis auf `format_newer_minor`, der ohnehin bei jedem Versionssprung neu erzeugt wird (siehe oben): Die Ketten waren nie falsch, nur der Maßstab hat sich bewegt. Das ist dieselbe Lage wie beim Präzedenzfall von Spezifikation 1.1: Dort verlor `format_unknown_event_type` in `expected/` den Befund `SPEC_NEWER`, weil der Verifier die Version erreicht hatte, die der Vektor erklärt; die Erwartung folgte der freigegebenen Fassung, die Bytes nicht. Neu erzeugt wurde mit 1.6 nur `format_newer_minor` (damals auf `1.7`, siehe oben); hinzugekommen sind die acht Vektoren aus §5. Nachrechenbar: `git show 6be9d7e:spec/testvectors/PINS.sha256 | grep -v ' format_newer_minor/' > /tmp/pins_1_5` und dann `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_5`: 225 Dateien (39 Vektorverzeichnisse und die zwei Dateien der Prüfumgebung), keine Abweichung.

**Spezifikation 1.7 (Löschsperre): keine Ausnahme.** Mit 1.7 kommt der Befund `HOLD_VIOLATION` hinzu, und er entsteht nur an einem `LEGAL_HOLD`; keiner der 48 älteren Vektoren trägt einen. Ihre Erwartungen und ihre Bytes bleiben deshalb unverändert. Neu erzeugt wurde nur `format_newer_minor` (damals auf `1.8`, siehe oben); hinzugekommen sind die drei Vektoren aus §7. Nachrechenbar: `git show 66f0cc0:spec/testvectors/PINS.sha256 | grep -v ' format_newer_minor/' > /tmp/pins_1_6` und dann `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_6`: 265 Dateien (47 Vektorverzeichnisse und die zwei Dateien der Prüfumgebung), keine Abweichung.

**Spezifikation 1.8 (Lizenz-Commitment): keine Ausnahme.** Mit 1.8 muss `GENESIS.license_id` das Lizenz-Commitment sein, aber nur in einem `GENESIS`, dessen eigene `spec_version` 1.8 oder neuer ist (Formatspezifikation 4.1). Alle älteren Vektoren erklären eine ältere Fassung und tragen `LIC-TEST-0001` im Klartext; die Verifier geben dazu einen Hinweis aus, keinen Befund. Ihre Erwartungen und ihre Bytes bleiben deshalb unverändert. Neu erzeugt wurde nur `format_newer_minor` (damals auf `1.9`, siehe oben; sein `GENESIS` trägt seither das Commitment); hinzugekommen sind die drei Vektoren aus §8. Nachrechenbar: `git show a3a0147:spec/testvectors/PINS.sha256 | grep -v '^#' | grep -v ' format_newer_minor/' > /tmp/pins_1_7` und dann `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_7`: 280 Dateien (50 Vektorverzeichnisse und die zwei Dateien der Prüfumgebung), keine Abweichung.

**Spezifikation 1.9 (Export-Siegel, nachgeholter Checkpoint, Klarstellungen): keine Ausnahme.** Die neuen Regeln greifen nur an Stellen, die kein älterer Vektor enthält: kein Export-Siegel, kein nachgeholter Sofort-Checkpoint mit mehr als 450 s Abstand, kein Segment außerhalb von `segments/`, keine Datei unter `content/` außer vollständigen Vorlagen, keine Zahl außerhalb von ±(2^53−1). Ihre Erwartungen und ihre Bytes bleiben deshalb unverändert. Neu erzeugt wurde nur `format_newer_minor` (damals auf `1.10`); hinzugekommen sind die neun Vektoren aus §9. Nachrechenbar: `git show 2ff96ba:spec/testvectors/PINS.sha256 | grep -v '^#' | grep -v ' format_newer_minor/' > /tmp/pins_1_8` und dann `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_8`: 295 Dateien (53 Vektorverzeichnisse und die zwei Dateien der Prüfumgebung), keine Abweichung.

**Spezifikation 1.10 (gedeckte Strecken, Mailsprache): keine Ausnahme.** Neu ist eine Angabe im Bericht der Verifier, kein Befund: Strecken zwischen zwei gegengezeichneten Checkpoints über dem Verankerungstakt (Formatspezifikation 11.2). Dazu kommt die Sprache der Hersteller-Mails (Heartbeat-Spezifikation). `expected/` nennt nur Exit-Code und Befundklassen; beides ändert sich bei keinem Vektor. Ihre Erwartungen und ihre Bytes bleiben deshalb unverändert. Neu erzeugt wurde nur `format_newer_minor` (jetzt `1.11`); kein Vektor ist hinzugekommen. Nachrechenbar: `git show 6963364:spec/testvectors/PINS.sha256 | grep -v '^#' | grep -v ' format_newer_minor/' > /tmp/pins_1_9` und dann `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_9`: 346 Dateien (63 Vektorverzeichnisse und die zwei Dateien der Prüfumgebung), keine Abweichung.

**Spezifikation 1.10 (Grundlagen: Schlüsselrollen, Angaben des Prüfers, Zeitstempelprofil): keine Ausnahme.** Hinzugekommen sind die 101 Vektoren aus §10 mit ihren Prüfumgebungen `pruefer_<name>.json` und die Eingaben der Einzelprüfung von Zeitstempeln (§10.4), alle mit Pin; der Generator schreibt sie mit. Kein eingefrorener Vektor hat sich geändert, weder in den Bytes noch in der Erwartung. Die neuen Solldateien tragen zusätzlich `evidence_level` und `auditor_inputs` (Registry `expected_files`), und `published_test_keys` nennt drei Schlüssel einer Zeitstempelstelle mehr. Nachrechenbar: `git show f37ad01b:spec/testvectors/PINS.sha256 > /tmp/pins_1_10` und dann `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_10`: 355 Dateien (64 Vektorverzeichnisse und die zwei Dateien der Prüfumgebung), keine Abweichung.

**Spezifikation 1.10 (Herstellerprotokoll): keine Ausnahme.** Hinzugekommen sind die 63 Vektoren der Gruppe `log` (§11) mit ihren Prüfumgebungen, sechs Vektoren der Gruppen `auditor` und `timestamp` (§10.2, §10.3) zu Lesarten des Zeitstempelprofils und der Grammatik des Auszugs, die die Spezifikation nach den Grundlagen festgehalten hat, die Eingaben der Einzelprüfung zu drei von ihnen (§10.4) und der Referenzfall `protokoll/` (§11.4), alle mit Pin. Kein eingefrorener Vektor hat sich geändert, weder in den Bytes noch in der Erwartung. `published_test_keys` nennt zusätzlich die beiden Protokollschlüssel des Testkorpus. Nachrechenbar: `git show 5e4e70bb:spec/testvectors/PINS.sha256 > /tmp/pins_1_10_grundlagen` und dann `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_10_grundlagen`: 1075 Dateien (165 Vektorverzeichnisse und 217 Dateien auf oberster Ebene), keine Abweichung.

**Spezifikation 1.10 (bezeugte Tage des Herstellerprotokolls): keine Ausnahme.** Hinzugekommen sind die 26 Vektoren der Gruppe `log` aus der Tabelle „Bezeugte Tage“ (§11.3) mit ihren Prüfumgebungen, die Zertifikate und Token der Zeitstempelstelle E1 mit verworfenen Schlüsseln in `zeitstempelstelle_e1.json` (§11.2) und der zweite Referenztag `protokoll/zweiter_referenztag/` (§11.4), alle mit Pin. Kein eingefrorener Vektor hat sich geändert, weder in den Bytes noch in der Erwartung. Anders als jedes andere Byte des Korpus lassen sich die Token von E1 nicht neu erzeugen: Der Generator liest sie als eingefrorene Eingabe und bricht ab, wenn eine neu erzeugte Aussage nicht mehr zu ihrem Token passt (§11.2). Nachrechenbar: `git show 3605ad7d:spec/testvectors/PINS.sha256 > /tmp/pins_1_10_protokoll` und dann `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_10_protokoll`: 1653 Dateien (234 Vektorverzeichnisse mit 1203 Dateien, 440 Dateien auf oberster Ebene und 10 Dateien des Referenzfalls), keine Abweichung.

**Spezifikation 1.10 (Anker-Historie v2 und Verbundenheit): keine Ausnahme.** Hinzugekommen sind die 110 Vektoren der Gruppe `history` (§12) mit ihren Prüfumgebungen, alle mit Pin. Fünf von ihnen tragen das Paket eines anderen Vektors Byte für Byte unter eigenem Namen (`history_reference_page` das von `valid_sealed_export`, die vier Vektoren zu Schritt H7 die von `log_witnessed_included` und `log_witnessed_logged_roots`); die Tagesobjekte ihrer Auszüge tragen eingefrorene Token von E1, kein neues Token ist hinzugekommen. Kein eingefrorener Vektor hat sich geändert, weder in den Bytes noch in der Erwartung, und `published_test_keys` bleibt unverändert: Jeder Schlüssel einer Seite ist ein Testschlüssel des Korpus. Nachrechenbar: `git show ffffeadd:spec/testvectors/PINS.sha256 > /tmp/pins_1_10_bezeugt` und dann `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_10_bezeugt`: 1872 Dateien (260 Vektorverzeichnisse mit 1333 Dateien, 525 Dateien auf oberster Ebene und 14 Dateien des Referenzfalls), keine Abweichung.

**Spezifikation 1.10 (Anker-Historie: Nacharbeiten aus dem Abgleich): keine Ausnahme.** Hinzugekommen sind fünf Vektoren der Gruppe `history` (§12.4, §12.6) mit ihren Prüfumgebungen, alle mit Pin: eine Zusammenfassung über eine Lücke mit und ohne Kennzeichen `merged` (Formatspezifikation 8.8.4 H5 (f)), ein Grund aus H5 zwischen Seiten einer verknüpften Vorgängerkette (8.8.6 Nummer 9) und eine Nachfolgekette, die die Seite des Pakets nennt, ehrlich und mit `succession_mismatch` (H5 in beiden Richtungen). Kein eingefrorener Vektor hat sich geändert, weder in den Bytes noch in der Erwartung, und `published_test_keys` bleibt unverändert: Jeder Schlüssel einer Seite ist ein Testschlüssel des Korpus. Nachrechenbar: `git show 4d101f28:spec/testvectors/PINS.sha256 > /tmp/pins_1_10_ankerhistorie` und dann `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_10_ankerhistorie`: 2790 Dateien (370 Vektorverzeichnisse mit 1883 Dateien, 893 Dateien auf oberster Ebene und 14 Dateien des Referenzfalls), keine Abweichung.

**Spezifikation 1.10 (Beweisstufe und Berichtsangaben): keine Ausnahme für die Bytes.** Hinzugekommen sind die 26 Vektoren der Gruppe `evidence` (§13) mit ihren Prüfumgebungen und die Zertifikate und Token der Zeitstempelstelle E2 mit verworfenen Schlüsseln in `zeitstempelstelle_e2.json` (§13.2), alle mit Pin. Zwölf von ihnen tragen das Paket eines Vektors der Gruppe `log` Byte für Byte unter eigenem Namen (`evidence_qualified_root_in_package` zusätzlich mit `keys/tsa/zeitstempelwurzel_e1.pem`). Kein eingefrorener Vektor hat sich in den Bytes, im Exit-Code oder in den Befundklassen geändert. Geändert haben sich zwei Erwartungen, die keine Befunde sind: Die 52 Solldateien eines unbrauchbaren Aufrufs (Exit 3 ohne Befunde mit `pruefer_<name>.json`) nennen in `auditor_inputs.evidence_level` jetzt `null` statt des Objekts des Zustands `format_error`, denn ohne Bericht gibt es keine Beweisstufe (Formatspezifikation 10.9.2, 10.10.1, Registry `expected_files`); und `valid_basic` trägt zusätzlich `evidence_level`, das Beispiel aus Formatspezifikation 10.10.2. `published_test_keys` bleibt unverändert: Die Schlüssel von E2 sind nicht veröffentlicht, jeder andere Schlüssel der neuen Vektoren ist ein Testschlüssel des Korpus. Nachrechenbar: `git show b653130e:spec/testvectors/PINS.sha256 > /tmp/pins_1_10_beweisstufe` und dann `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_10_beweisstufe`: 2836 Dateien (375 Vektorverzeichnisse mit 1908 Dateien, 914 Dateien auf oberster Ebene und 14 Dateien des Referenzfalls), keine Abweichung.

**Spezifikation 1.10 (Bedingung (7) als zweiter Weg zu Stufe 3 und die übrigen Entscheidungen vom 26.10.): keine Ausnahme für die Bytes.** Hinzugekommen sind die 15 Vektoren aus §14 mit ihren Prüfumgebungen und die Zertifikate und Token der Zeitstempelstelle E3 mit verworfenen Schlüsseln in `zeitstempelstelle_e3.json` (§14.2), alle mit Pin; sie stehen in den Gruppen `valid`, `log`, `history` und `evidence`, jeweils nach den Vektoren, die dort schon standen. Zehn von ihnen tragen das Paket eines Vektors der Gruppe `log` Byte für Byte unter eigenem Namen. Kein eingefrorener Vektor hat sich in den Bytes, im Exit-Code oder in den Befundklassen geändert. Geändert hat sich eine Erwartung, die kein Befund ist: Mit Bedingung (7) als zweitem Weg zu Stufe 3 (Formatspezifikation 10.9.1, 10.9.5) erreichen `evidence_qualified_window_from` und `evidence_qualified_root_in_package` mit ihrer Prüfumgebung Stufe 3 bis 5 statt Stufe 2 bis 11 (`auditor_inputs.evidence_level`); ihr Exit-Code und ihre Befundklassen bleiben. `published_test_keys` bleibt unverändert: Die Schlüssel von E3 sind nicht veröffentlicht, jeder andere Schlüssel der neuen Vektoren ist ein Testschlüssel des Korpus. Nachrechenbar: `git show 76a6b84e:spec/testvectors/PINS.sha256 > /tmp/pins_1_10_bedingung7` und dann `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_10_bedingung7`: 3063 Dateien (401 Vektorverzeichnisse mit 2042 Dateien, 1007 Dateien auf oberster Ebene und 14 Dateien des Referenzfalls), keine Abweichung.

**Spezifikation 1.10 (Abgleich beider Verifier): keine Ausnahme.** Hinzugekommen sind 25 Vektoren zu Lesarten, die die Spezifikation festgehalten hat, damit beide Referenz-Verifier jede Eingabe gleich beurteilen: 23 der Gruppe `timestamp` (§10.3) mit ihren Prüfumgebungen und den Eingaben der Einzelprüfung zu sechs von ihnen (§10.4), dazu `valid_receipt_r_identity` und `tamper_receipt_r_identity_sign_bit` (§15), alle mit Pin; sie stehen jeweils nach den Vektoren, die dort schon standen. Kein eingefrorener Vektor hat sich geändert, weder in den Bytes noch in der Erwartung. `published_test_keys` bleibt unverändert: Jedes neue Zertifikat trägt den Schlüssel der Wurzel oder des Signierers der Zeitstempelstelle des Generators, das Zertifikat auf keinem Pfad in `timestamp_extra_certificate_key_parameters_tag_zero` die 32 Oktette des Signiererschlüssels unter einem privaten Algorithmus außerhalb von Z.2; jede Quittung ist mit `vendor-test-001` signiert. Nachrechenbar: `git show 8020dcf7:spec/testvectors/PINS.sha256 > /tmp/pins_1_10_abgleich` und dann `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_10_abgleich`: 3216 Dateien (417 Vektorverzeichnisse mit 2122 Dateien, 1080 Dateien auf oberster Ebene und 14 Dateien des Referenzfalls), keine Abweichung.

**Spezifikation 1.10 (Abgleich beider Verifier: eine uuid ist die ganze Zeichenkette): keine Ausnahme.** Hinzugekommen ist `format_uuid_trailing_newline` (§15), mit Pin; er schließt die Gruppe `format`. Kein eingefrorener Vektor hat sich geändert, weder in den Bytes noch in der Erwartung. `published_test_keys` bleibt unverändert: Seine Kette ist mit `dev-test-001` und `vendor-test-001` signiert. Nachrechenbar: `git show f920c34e:spec/testvectors/PINS.sha256 > /tmp/pins_1_10_uuid` und dann `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_10_uuid`: 3411 Dateien (442 Vektorverzeichnisse mit 2247 Dateien, 1150 Dateien auf oberster Ebene und 14 Dateien des Referenzfalls), keine Abweichung.

Abschnitt 8.7 der Formatspezifikation (Erfassungszusage und Lückenbeginn nach einem Absturz) verpflichtet die Appliance, nicht den Verifier: Er erzeugt keinen Befund und ändert keinen Vektor.

**Testschlüssel aus Ketten vor 1.8 (Entscheidung vom 02.10.2026): keine Ausnahme für die Bytes.** Jeder Testschlüssel, den eine Test- oder Demokette vor 1.8 im Klartext trug, ist in Tests, Vertragsvektoren, Demo und Beispielkonfiguration durch einen neuen ersetzt. Jeder neue enthält mindestens eines der Zeichen I, L, O oder U und hat damit nie die Form, die die LOUWIETEC-Cloud ausgibt (`LEDGER-` und viermal vier Zeichen Crockford-Base32). `LIC-TEST-0001` bleibt im eingefrorenen Korpus. Er ist kein Lizenzschlüssel und kann keiner werden: Die Grammatik `^[A-Z0-9-]{19,29}$` (Heartbeat-Spezifikation 4.1) lässt 13 Zeichen nicht zu, eine Aktivierung mit ihm scheitert also schon an der Form. Die Vektoren vor 1.8 sind außerdem der Maßstab dafür, dass Ketten älterer Fassungen lesbar bleiben (Formatspezifikation 4.1). Sie werden nur dafür verwendet, nicht als Demo und nicht als Vorlage für neue Ketten.

**Nachtrag zum Vektor `tamper_missing_checkpoint` (14.09.).** Der Negativvektor zu `MISSING_CHECKPOINT` (Exit 2) war gepinnt und wurde von beiden Prüf-Jobs gefahren, weil diese `expected/` aufzählen, stand aber nicht in `spec/registry.json`; `.ci/check_registry_matrix.py` zählte deshalb 29 statt 30 Vektoren und prüfte nur die Richtung Registry → Dateien. Beides ist behoben: der Eintrag steht in der Registry, und die Matrixprüfung läuft in beide Richtungen; ein Vektorverzeichnis oder eine `expected/`-Datei ohne Registry-Eintrag ist seither rot; ein Rot-Beweis belegt es.

## 5. Kettenende (Spezifikation 1.6)

Versiegelt ist eine Kette, deren letzte Einträge ein `SEAL`, direkt dessen Sofort-Checkpoint und danach höchstens Quittungen genau auf diesen Checkpoint sind, gleich mit welchem `reason` (Formatspezifikation 8.6). Jede andere Kette ist unvollständig: Befund `UNSEALED_END`, genau einmal, an der `seq` des letzten Eintrags, Exit 4; auch neben Befunden der Exit-Klasse 2. Die acht Vektoren der Fassung 1.6 erklären `spec_version` `1.6` und bauen auf der einstündigen Standardkette des Korpus auf (GENESIS, zwei KI-Aufrufe, 5-Minuten-Takt, halbstündliche Quittungen unter `vendor-test-001`; `end_truncated_at_seal` siehe §6). Sie tragen keinen anderen Mangel als den, nach dem sie heißen, also keine Stille über der Toleranz, keinen fehlenden Sofort-Checkpoint vor dem Ende, keine Quittung ohne tragende Signatur (`TestKettenendeVektoren`):

| Vektor | Kettenende | Exit | Befunde |
|---|---|---|---|
| `valid_sealed_shutdown` | `SEAL(shutdown)` + Sofort-Checkpoint; geprüft 2 min nach dem letzten Eintrag | 0 | - |
| `valid_sealed_update_receipt` | `SEAL(update)` + Sofort-Checkpoint + Quittung genau auf diesen Checkpoint | 0 | - |
| `end_sealed_stale` | versiegelt wie `valid_sealed_shutdown`, aber 25 h nach dem letzten Eintrag geprüft: das Siegel beweist nicht, dass es das jüngste ist (8.5) | 1 | `TRAILING_SILENCE` |
| `end_unsealed_bare_critical` | letzter Eintrag ein `OVERSIGHT` (kritisch) ohne Sofort-Checkpoint: der Schreiber starb davor; kein `MISSING_CHECKPOINT` mehr (6.2) | 4 | `UNSEALED_END` |
| `end_unsealed_bare_seal` | letzter Eintrag ein `SEAL(shutdown)` ohne Sofort-Checkpoint: kein Siegel | 4 | `UNSEALED_END` |
| `end_truncated_at_seal` | ehrliche Kette mit Übergabe mitten im Lauf, gekürzt direkt hinter dem Sofort-Checkpoint des `SEAL`: die Nachweisgrenze (§6) | 0 | - |
| `tamper_seal_then_entry` | `SEAL(shutdown)` + Sofort-Checkpoint, danach ein `TICK` ohne `RESUME` (innerhalb der Stilletoleranz) | 2 | `HANDOVER_BROKEN`, `UNSEALED_END` |
| `tamper_sealed_rewrite` | versiegelte Kette, ein `AI_CALL` nach dem Hashen umgeschrieben (Technik von `tamper_rewrite`); das Ende ist versiegelt, also kein `UNSEALED_END` | 2 | `HASH_MISMATCH` |

Ein Verifier der Fassung 1.5 oder älter kennt Exit 4 nicht und meldet eine mit `update` oder `shutdown` versiegelte Kette als `HANDOVER_BROKEN` (bis 1.5 schlossen nur `decommission` und `key_loss` regulär ab), ein kritisches Ende ohne Checkpoint als `MISSING_CHECKPOINT`; auf diesen acht Vektoren ist er damit durchweg strenger als 1.6. Auf einer unvollständigen Kette (etwa jedem der 38 älteren Vektoren) ist er dagegen milder: Er meldet Exit 0 oder 1, wo 1.6 Exit 4 meldet (8.6, „Ältere Verifier"). Zusätzlich meldet er `SPEC_NEWER`, weil die Vektoren `1.6` erklären.

## 6. Nachweisgrenze: `end_truncated_at_seal`

Die ehrliche Kette hinter dem Vektor: GENESIS, zwei KI-Aufrufe, Takt bis 00:30 mit Quittung um 00:30:01; um 00:32 `SEAL(shutdown)` und 500 ms später sein Sofort-Checkpoint; nach 90 s Pause `RESUME` mit dem `entry_hash` des `SEAL`, sein Checkpoint, weiter im Takt bis 01:30 mit Quittungen um 01:00:01 und 01:30:01, insgesamt 47 Einträge. Das Paket endet nach Eintrag 19, dem Sofort-Checkpoint des `SEAL`; `manifest.json` (`tree_size` 19) und der Segment-Hash passen zur gekürzten Kette, kein Schlüssel war nötig. Geprüft wird 2 min nach dem Ende der **ungekürzten** Kette (`verify_args.json`: `2026-01-01T01:32:01.000Z`), also dann, wenn ein Prüfer tatsächlich prüft. Das Paket liegt dann eine Stunde zurück, innerhalb des Frischefensters.

**Erwartung ohne Abgleich: Exit 0, keine Befunde.** Das Paket allein kann die Kürzung nicht widerlegen (Formatspezifikation 8.6, 11.2). Das ist kein Fehler des Verifiers, sondern die ausgewiesene Grenze: Der Sofort-Checkpoint eines `SEAL`, dem ein `RESUME` folgt, trägt vor dem `RESUME` keine Quittung (8.4, Klarstellung 2), jede frühere Übergabe ist also eine Stelle, an der eine gekürzte Kette ohne Schlüssel versiegelt aussieht.

**Der Abgleich, der die Kürzung sicher aufdeckt.** Die jüngste Wurzel, die der Hersteller für diese Kette gegengezeichnet hat, ist die der letzten Quittung der ungekürzten Kette: `tree_size` = 45, `merkle_root` = `89495c09e4fff767882017bfb73e5b26ef17637111bbad7e09034445e0807cd5`, `server_ts` = `2026-01-01T01:30:01.000Z` (Quittung auf den Checkpoint mit `seq` 46). Übergibt der Prüfer sie als erwartete Wurzel, fehlen dem Paket Einträge, die der Hersteller schon gegengezeichnet hat: `MERKLE_INCONSISTENT`, Exit 2.

Go-Verifier (erwartet nur die Wurzel; sie muss als Präfix-Wurzel der Kette vorkommen):

```
cd verifier && go build -o /tmp/ledger-verify ./cmd/ledger-verify && cd ..
/tmp/ledger-verify --now-from-package \
  --vendor-root spec/testvectors/pruefer_herstellerwurzel.json \
  --vendor-key "$(head -1 spec/testvectors/pruefer_herstellerschluessel.txt)" \
  --expect-root 89495c09e4fff767882017bfb73e5b26ef17637111bbad7e09034445e0807cd5 \
  spec/testvectors/end_truncated_at_seal
```

Zweitverifier (erwartet `tree_size:merkle_root`):

```
python3 verifier2/verifier2.py --now-from-package \
  --vendor-root spec/testvectors/pruefer_herstellerwurzel.json \
  --vendor-key "$(head -1 spec/testvectors/pruefer_herstellerschluessel.txt)" \
  --expect-root 45:89495c09e4fff767882017bfb73e5b26ef17637111bbad7e09034445e0807cd5 \
  spec/testvectors/end_truncated_at_seal
```

Beide melden `MERKLE_INCONSISTENT`, Exit 2: der Go-Verifier, weil die Wurzel keiner Präfix-Wurzel der 19 Einträge entspricht, der Zweitverifier, weil `tree_size` 45 die 19 vorhandenen Einträge übersteigt. Die Werte sind keine Abschrift: `TestKuerzungAmSiegel` rechnet sie aus der ungekürzten Kette des Generators nach und hält dieses README dagegen; `TestKuerzungAmSiegelImVerifier` fährt den Abgleich durch den Go-Verifier samt Kontrolle (die eigene quittierte Wurzel des Pakets ergibt kein `MERKLE_INCONSISTENT`).

## 7. Löschsperre (Spezifikation 1.7)

Gelöscht werden nur Tresor-Inhalte, nie Ketteneinträge; jede Löschung steht als `CONTENT_DELETED` in der Kette (Formatspezifikation 9.3). Eine Sperre (`LEGAL_HOLD`, 4.24) ist aktiv von ihrem `set` bis zu einem `release` mit derselben `hold_id`. Sie erfasst einen `AI_CALL`, dessen `ts_captured` zwischen `scope_from` und `scope_to` liegt, beide Grenzen eingeschlossen, verglichen als Zeitpunkte. Ein `CONTENT_DELETED`, dessen `target_seq` einen `AI_CALL` nennt, den an seiner Stelle eine aktive Sperre erfasst, ist der Befund `HOLD_VIOLATION`, an der `seq` des `CONTENT_DELETED`, mit `hold_id` und `target_seq`. Exit-Klasse 1, nicht 2: Die Löschung steht offen in der Kette, nichts ist verschwiegen (8.6).

Die drei Vektoren der Fassung 1.7 erklären `spec_version` `1.7` und sind **versiegelt** (Ende wie `valid_sealed_shutdown`: `SEAL(shutdown)` um 01:01 und sein Sofort-Checkpoint, geprüft 2 min danach), damit ihr Ergebnis die Sperrregel allein zeigt und kein `UNSEALED_END` daneben steht. Gemeinsamer Anfang: GENESIS, drei KI-Aufrufe mit Inhalt (`mode` `full`, `vault_ref`) um 00:01, 00:02 und 00:03 (`seq` 3, 4, 5), um 00:04 `LEGAL_HOLD` `set` mit `hold_id` `LH-2026-001` (`seq` 6) und sein Sofort-Checkpoint. Um 00:42 löscht der Aufbewahrungslauf (`reason` `retention`, `actor` `system:aufbewahrung`) einen Aufruf, 500 ms später folgt der Sofort-Checkpoint. Takt und halbstündliche Quittungen unter `vendor-test-001` wie in §5; kein anderer Mangel (`TestHoldVektoren`, der die Sperrlage jedes Vektors mit einer eigenen Lesart von 9.3 nachrechnet und gegen `expected/` hält):

| Vektor | Sperre und Löschung | Exit | Befunde |
|---|---|---|---|
| `hold_respected` | Umfang `2026-01-01T00:00:00.000Z` bis `2026-01-01T00:02:59.999Z`, erfasst die Aufrufe `seq` 3 und 4. Gelöscht wird `target_seq` 5 (`seq` 25), erfasst um 00:03:00.000, 1 ms außerhalb; die Sperre bleibt aktiv. Der Aufruf ist vor dem `set` verkettet: Wer die Sperre nach `seq` statt nach `ts_captured` liest, meldet hier fälschlich `HOLD_VIOLATION` | 1 | `CONTENT_DELETED` |
| `hold_released` | Umfang wie bei `hold_respected`, `2026-01-01T00:00:00.000Z` bis `2026-01-01T00:02:59.999Z`; um 00:22 `release` (`seq` 16) derselben `hold_id` mit denselben Grenzen; danach gelöscht `target_seq` 3 (`seq` 27): erfasst, aber nicht mehr gesperrt | 1 | `CONTENT_DELETED` |
| `hold_violated` | Umfang ab genau der Erfassungszeit von `seq` 3, `2026-01-01T00:01:00.000Z` (untere Grenze eingeschlossen), bis unbegrenzt, `9999-12-31T23:59:59.000Z` (der Wert „unbegrenzt“ aus 4.24); gelöscht `target_seq` 3 (`seq` 25) bei aktiver Sperre | 1 | `CONTENT_DELETED`, `HOLD_VIOLATION` |

Die Grenzen sind mit Absicht knapp gewählt: `hold_respected` wird rot bei einem Verifier, der den Umfang übergeht oder nach `seq` sperrt; `hold_released` bei einem, der die Aufhebung übergeht; `hold_violated` bei einem, der die untere Grenze ausschließt oder am Jahr 9999 scheitert.

Ein Verifier der Fassung 1.6 kennt `LEGAL_HOLD` nicht (4.24): Er meldet `UNKNOWN_ENTRY_TYPE` (10.6 Regel 2), dazu `SPEC_NEWER`, weil die Vektoren `1.7` erklären, und prüft die Kette sonst vollständig (auf allen drei Vektoren Exit 1 mit `CONTENT_DELETED`, `SPEC_NEWER`, `UNKNOWN_ENTRY_TYPE`). Auf `hold_violated` ist er damit milder als 1.7: Den Bruch der Sperre sieht er nicht. Den Sofort-Checkpoint nach `LEGAL_HOLD` verlangt er nicht (ein unbekannter Typ ist für ihn nicht kritisch); vorhanden ist er trotzdem. Nachgefahren mit dem Go-Verifier des Stands `66f0cc0` (Fassung 1.6) und der Prüfumgebung aus §3.

## 8. Lizenz-Commitment (Spezifikation 1.8)

Ab Fassung 1.8 trägt `GENESIS.license_id` das Lizenz-Commitment (SHA-256 über die UTF-8-Bytes des Lizenzschlüssels, hex in Kleinbuchstaben), nie den Schlüssel (Formatspezifikation 4.1). Maßgeblich ist die `spec_version` des `GENESIS`-Eintrags selbst: Ein `GENESIS` ab 1.8 mit anderem Wert ist `FORMAT_ERROR`; ein älterer behält, was er trägt, und bekommt einen Hinweis (`genesis_license_not_commitment` in der JSON-Ausgabe beider Verifier), keinen Befund. Das Commitment von `LIC-TEST-0001` ist `8d3ba2f4ded263ed0f5e27324951d2277063cf3ddc58f81e989b1cfbdb7a71d5`.

Die drei Vektoren der Fassung 1.8 sind die einstündige Standardkette des Korpus (GENESIS, zwei KI-Aufrufe, 5-Minuten-Takt, halbstündliche Quittungen unter `vendor-test-001`), **versiegelt** um 01:01 mit `SEAL(shutdown)` und Sofort-Checkpoint, geprüft 2 min danach; ihr Ergebnis zeigt die Lizenzregel allein (`TestLizenzVektoren`, `TestKeinSchluesselAbFassung18`):

| Vektor | GENESIS; übrige Einträge und Manifest | Exit | Befunde |
|---|---|---|---|
| `valid_genesis_commitment` | GENESIS `1.8` mit dem Commitment; übrige `1.8` | 0 | - |
| `valid_genesis_upgraded` | GENESIS `1.7` mit `LIC-TEST-0001` im Klartext, eine von 1.7 auf 1.8 aktualisierte Appliance; übrige `1.8`; nur der Hinweis | 0 | - |
| `format_genesis_license_cleartext` | GENESIS `1.8` mit `LIC-TEST-0001` im Klartext; übrige `1.8` | 3 | `FORMAT_ERROR` |

`valid_genesis_upgraded` wird rot bei einem Verifier, der die Regel nach der Version des Manifests oder des jüngsten Eintrags statt nach der des `GENESIS` anwendet; die Kette jeder aktualisierten Appliance wäre dann ein Formatfehler. `format_genesis_license_cleartext` wird rot bei einem Verifier, der die Verengung gar nicht anwendet.

Ein Verifier der Fassung 1.7 nimmt alle drei an: Exit 1 mit `SPEC_NEWER` allein, auch auf `format_genesis_license_cleartext` (dort milder als 1.8, den Klartext sieht er nicht). Das ist gewollt: Weil der Feldname bleibt, ist 1.8 kein Flottenbruch (Formatspezifikation 10.6, Regel 3). Nachgefahren mit beiden Verifiern des Stands `154ef14` (Fassung 1.7) und der Prüfumgebung aus §3.

Die Referenzwerte für die Hersteller-Seite der Lizenz (`license_proof`, Lizenzbescheid, gebundene Verweigerung, Lückenzeugen) sind keine Prüfpakete und liegen deshalb nicht hier, sondern in `spec/contract/` (dort `README.de.md`).

## 9. Export-Siegel, nachgeholter Checkpoint und Klarstellungen (Spezifikation 1.9)

Zehn Vektoren der Fassung 1.9 erklären `spec_version` `1.9`. Sie bauen auf der einstündigen Standardkette auf (GENESIS, zwei KI-Aufrufe, der erste mit Inhalt, 5-Minuten-Takt, halbstündliche Quittungen unter `vendor-test-001`) und enden, wo das Siegel nicht selbst Gegenstand ist, mit `SEAL(shutdown)` um 01:01 und Sofort-Checkpoint (`TestV19Vektoren`):

| Vektor | Aufbau | Exit | Befunde |
|---|---|---|---|
| `valid_sealed_export` | das Paket endet um 01:01 mit `SEAL(export)` und dessen Sofort-Checkpoint: ein ordentlicher Export aus laufendem Betrieb (Formatspezifikation 8.6) | 0 | - |
| `valid_export_handover` | um 00:30:30 `SEAL(export)`, Sofort-Checkpoint, `RESUME`, Checkpoint im Millisekundenabstand, so, wie der Schreiber es beim Export in einem Zug schreibt (8.4) | 0 | - |
| `gap_late_checkpoint_restart` | `OVERSIGHT` um 00:21, Absturz vor dem Sofort-Checkpoint; der Neustart um 00:31 schreibt den Checkpoint nach (`mono_delta_ms` −1), dann `RESTART` (Ausfall 600 000 ms) und `GAP` ab dem kritischen Eintrag (8.2 Bedingung 4) | 1 | `COVERED_GAP` |
| `gap_late_seal_checkpoint` | `SEAL(update)` um 00:30:30, Absturz vor dem Sofort-Checkpoint; der Neustart zehn Minuten später schreibt ihn nach (`mono_delta_ms` −1), dann `RESUME` (8.2 Bedingung 3) | 0 | - |
| `gap_late_seal_checkpoint_end` | `SEAL(shutdown)` um 01:01, Absturz vor dem Sofort-Checkpoint; der Neustart um 01:11 schreibt ihn nach (`mono_delta_ms` −1), danach nichts mehr: der `RESUME` des Neustarts ist nie geschrieben worden (8.2 Bedingung 3: eine ehrliche Kette ist nie ungültig) | 0 | - |
| `tamper_late_checkpoint_stalled` | dieselbe Stille nach `OVERSIGHT` um 00:21, aber ohne Neustart: Der Checkpoint kommt zehn Minuten später mit `mono_delta_ms` ≥ 0, kein `RESTART`, kein `GAP` | 2 | `CONCEALED_SILENCE` |
| `tamper_content_unpaired` | unter `content/` ein vorgelegter Klartext zum ersten KI-Aufruf, der dem Commitment widerspricht, ohne Salt-Datei (10.1) | 2 | `CONTENT_MISMATCH` |
| `format_segment_path` | das Manifest nennt das Segment `../chain-000001.jsonl`; die Datei liegt neben `manifest.json` statt unter `segments/` (10.1) | 3 | `FORMAT_ERROR` |
| `format_int_range` | ein `TICK` mit `uptime_s` = 2^53 (Abschnitt 2) | 3 | `FORMAT_ERROR` |
| `format_unknown_type_broken_line` | der erste `TICK` ist kein gültiges JSON (schließende Klammer fehlt), danach ein `FUTURE_NOTE` (10.5, 10.6 Regel 2) | 3 | `FORMAT_ERROR`, `UNKNOWN_ENTRY_TYPE` |

`valid_sealed_export` zeigt zugleich die angenommene Beweisgrenze: Ein Paket, das an einem Export-Siegel endet, sieht genauso aus wie eine hinter diesem Siegel gekürzte Kette. Der Verifier sagt deshalb bei jedem Paket, dass ohne gegengezeichnete Wurzel keine Aussage über die Vollständigkeit möglich ist (Formatspezifikation 8.6); mit einer Wurzel, die der Hersteller nach 01:01 gegengezeichnet hat und die das Paket nicht enthält, wird daraus `MERKLE_INCONSISTENT`, wie bei `end_truncated_at_seal` (§6).

Ein Verifier der Fassung 1.8 kennt den Versiegelungsgrund `export` nicht und meldet `valid_sealed_export` und `valid_export_handover` als `FORMAT_ERROR` (Exit 3), dazu `SPEC_NEWER` (Formatspezifikation 8.6, „Ältere Verifier“). Auf `gap_late_checkpoint_restart`, `gap_late_seal_checkpoint` und `gap_late_seal_checkpoint_end` meldet er `CONCEALED_SILENCE` (Exit 2), strenger als 1.9. `tamper_content_unpaired`, `format_segment_path`, `format_int_range` und `format_unknown_type_broken_line` beurteilten die beiden Verifier bis 1.8 verschieden (verifier2 ließ den ungepaarten Klartext durch und kannte keine Zahlengrenze, der Go-Verifier las das Segment außerhalb von `segments/`, verifier2 verlor das Signal des unbekannten Typs neben der kaputten Zeile).

## 10. Grundlagen der Spezifikation 1.10: Schlüsselrollen, Angaben des Prüfers, Zeitstempelprofil

130 Vektoren erklären `spec_version` `1.10`, in den Gruppen `roles`, `auditor` und `timestamp`; 29 davon (`auditor_log_neighbours_equal_index` und die letzten 28 der Tabelle in §10.3, die letzten 23 aus dem Abgleich beider Verifier, §15) zeigen Lesarten, die die Spezifikation nach den Grundlagen festgehalten hat. Sie bauen auf der einstündigen Standardkette auf (GENESIS, zwei KI-Aufrufe, 5-Minuten-Takt, halbstündliche Quittungen), **versiegelt** um 01:01 mit `SEAL(shutdown)` und Sofort-Checkpoint, geprüft 2 min danach: 32 Einträge, Quittungen bei `tree_size` 15 und 28, der Fall KAT1 aus Formatspezifikation 10.9.5. Die Vektoren der Gruppe `timestamp` tragen zusätzlich um 00:40:01.200 einen `TIME_ANCHOR` über den Checkpoint von 00:40:00.500 (`checkpoint_seq` 21, `tree_size` 20; 33 Einträge, Quittungen bei 15 und 29). Kein Paket trägt `keys/tsa/` oder eine Liste der Gegenzeichnungsschlüssel.

**Zwei Prüfumgebungen.** Neben der Prüfumgebung des Korpus (§3) hat jeder dieser Vektoren seine eigene: die Datei `pruefer_<name>.json` (`ledger-pruefumgebung/1`, Formatspezifikation 10.8) und die Dateien `pruefer_<name>.<Member>-<n>.<Endung>`, die sie nennt, alle auf oberster Ebene und in `PINS.sha256` festgehalten. Die Prüfwerkzeuge setzen die Member in der Reihenfolge der Registry (`auditor_inputs.pruefumgebung.member_order`) in Schalter um; `korpus` `true` fügt die Wurzel und die Anheftung des Korpus hinzu, der Prüfzeitpunkt bleibt in `verify_args.json`. Die Solldatei nennt beide Erwartungen: `exit_code`, `finding_classes` und `evidence_level` für die Prüfumgebung des Korpus, `auditor_inputs` für die des Vektors. Die Tabellen nennen zuerst Exit und Befunde mit der Prüfumgebung des Korpus, dann mit `pruefer_<name>.json`. Exit 3 ohne Befunde (`-`) heißt: unbrauchbarer Aufruf, kein Bericht (10.8); die Solldatei nennt dann `evidence_level` `null`, denn ohne Bericht gibt es keine Beweisstufe (10.9.2, 10.10.1). Jeder Registry-Eintrag nennt im Member `why` den Grund und den Abschnitt, der die Erwartung trägt. Das Berichtsobjekt `key_roles` (10.10.2) und die Ergebnisse je Token (Z.6, Regel QS) nennt die Solldatei nicht; ihre Sollwerte stehen in der Beschreibung der Zeile, und beide Referenz-Verifier geben sie gleich aus (Formatspezifikation 10.10). `TestGrundlagenTabellenFolgenDerErwartung` (`appliance/cmd/vektorgen`) hält die Tabellen gegen `expected/`.

### 10.1 Schlüsselrollen (Gruppe `roles`)

Die Quittungen stehen unter `vendor-test-001`, das die Prüfumgebung des Korpus anheftet; bei `roles_pin_other_role` und `roles_pin_without_list` unter `vendor-statements-test-001`, einem Bescheidschlüssel, bei `roles_list_revokes_receipt_key` unter `vendor-test-002`, das keine Anheftung belegt. Jede Prüfumgebung eines Vektors enthält die des Korpus (`korpus` `true`), sodass sie die Monotonie aus Formatspezifikation 10.9.7 prüfen kann. Jede Liste signiert `testwurzel-1`, jeder Schlüssel ist ein Testschlüssel des Korpus (Formatspezifikation 10.7.2, Referenzwerte). **Gegenprobe:** Jede Rollenliste der Vektoren, die zeigen sollen, dass keine Rollenliste wirksam ist, gibt dem Publikey von `vendor-test-001` die Rolle `statements`. Wäre sie wirksam, entfiele die Anheftung des Korpus (10.7.4, R3 (d)), und die Quittungen ergäben `RECEIPT_UNVERIFIED`; Exit 0 mit der Prüfumgebung des Vektors ist der Beleg. Die Sollwerte von `key_roles` stehen in der Beschreibung.

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `roles_list_effective` | Rollenliste der Version 1 aus 10.7.2 (Byte für Byte die Referenzwerte); `key_roles`: `effective`, Bescheidschlüssel `vendor-statements-test-001` und `-002` aus der Rollenliste; die Anheftung von `vendor-test-001` bleibt | 0 | - | 0 | - |
| `roles_pin_other_role` | Quittungen unter `vendor-statements-test-001`; `--vendor-key` heftet diesen Schlüssel als Gegenzeichnungsschlüssel an, die Rollenliste der Version 1 nennt ihn mit der Rolle `statements`: die Anheftung entfällt (`pins_dropped`, Hinweise `receipt_key_other_role`, `pin_dropped`) | 1 | `RECEIPT_UNVERIFIED` | 1 | `RECEIPT_UNVERIFIED` |
| `roles_pin_without_list` | dasselbe Paket wie `roles_pin_other_role`, dieselbe Anheftung, keine Rollenliste: die Anheftung belegt die Quittungen; `key_roles`: `not_supplied` | 1 | `RECEIPT_UNVERIFIED` | 0 | - |
| `roles_list_revokes_pinned_key` | Rollenliste nennt `vendor-test-001` als Gegenzeichnungsschlüssel mit `widerrufen_ab` `2025-12-31T00:00:00Z`, vor allen Quittungen; die Anheftung des Korpus bleibt und belegt sie; `key_roles`: `effective` | 0 | - | 0 | - |
| `roles_list_revokes_receipt_key` | Quittungen unter `vendor-test-002`, das weder angeheftet ist noch in einer Liste des Pakets steht; die Rollenliste nennt es als Gegenzeichnungsschlüssel mit `widerrufen_ab` `2025-12-31T00:00:00Z`: `RECEIPT_UNVERIFIED`, nie `RECEIPT_INVALID`; `key_roles`: `effective` | 1 | `RECEIPT_UNVERIFIED` | 1 | `RECEIPT_UNVERIFIED` |
| `roles_two_roles_cs_list` | Liste der Gegenzeichnungsschlüssel des Korpus (Version 1, wie in `valid_vendor_list`) über `--vendor-key-list` und eine Rollenliste, die `vendor-test-001` die Rolle `statements` gibt: `key_roles` `not_effective`, Grund `key_in_two_roles`; die Anheftung bleibt | 0 | - | 0 | - |
| `roles_two_roles_no_fallback` | Liste der Gegenzeichnungsschlüssel nur mit `vendor-test-002`; Rollenliste Version 1 gibt `vendor-test-001` die Rolle `statements`, Version 2 zusätzlich `vendor-test-002`: Version 2 scheitert an R3 (a), Version 1 tritt nicht an ihre Stelle; `not_effective`, `key_in_two_roles` | 0 | - | 0 | - |
| `roles_two_roles_protocol_list` | Rollenliste (gibt `vendor-test-001` die Rolle `statements`) und eine Protokollschlüsselliste, deren Schlüssel den Publikey von `vendor-statements-test-002` trägt: keine der beiden wirksam; `not_effective`, `key_in_two_roles` | 0 | - | 0 | - |
| `roles_protocol_list_cs_pin` | Protokollschlüsselliste mit dem Publikey von `vendor-test-001`, keine Rollenliste, kein Auszug: die Liste ist unwirksam, die Anheftung bleibt; `key_roles`: `not_supplied` | 0 | - | 0 | - |
| `roles_same_version_differ` | zwei Rollenlisten der Version 1, verschieden nur in `ausgestellt`: `not_effective`, `lists_contradictory` | 0 | - | 0 | - |
| `roles_entry_dropped` | Rollenliste Version 2 ohne den Eintrag `vendor-statements-test-002` der Version 1: `not_effective`, `lists_contradictory` | 0 | - | 0 | - |
| `roles_dual_end_effective` | Rollenliste Version 1 und Version 2 mit denselben Einträgen und `ende_doppelbetrieb` `2026-07-01T00:00:00Z`: `effective`, `list.version` 2, `list.ende_doppelbetrieb` `2026-07-01T00:00:00Z` | 0 | - | 0 | - |
| `roles_dual_end_differs` | Rollenlisten Version 2 und 3 mit `ende_doppelbetrieb` `2026-07-01T00:00:00Z` und `2026-07-01T00:00:00.000Z`: `not_effective`, `lists_contradictory` | 0 | - | 0 | - |
| `roles_dual_end_dropped` | Rollenliste Version 2 mit `ende_doppelbetrieb`, Version 3 ohne: `not_effective`, `lists_contradictory` | 0 | - | 0 | - |
| `roles_list_protocol_role` | Rollenliste mit einem Eintrag der Rolle `protocol`: `not_effective`, Grund `format` | 0 | - | 0 | - |
| `roles_list_names_root` | Rollenliste mit einem Eintrag, der den Publikey von `testwurzel-1` nennt: `not_effective`, Grund `format` | 0 | - | 0 | - |
| `roles_list_extra_member` | Rollenliste mit einem Member `kommentar` in einem Eintrag: `not_effective`, Grund `format`, kein Exit 3 | 0 | - | 0 | - |
| `roles_list_no_matching_root` | Rollenliste mit `signatur.wurzel_id` `testwurzel-2`, signiert mit dem Schlüssel von `testwurzel-1`: `not_effective`, Grund `no_matching_root` | 0 | - | 0 | - |
| `roles_list_bad_signature` | Rollenliste unter `testwurzel-1`, signiert mit dem Schlüssel von `vendor-test-002`: `not_effective`, Grund `signature` | 0 | - | 0 | - |
| `roles_list_two_reasons` | die Rollenlisten von `roles_list_protocol_role` und `roles_list_bad_signature` zusammen: `not_effective`, Grund `signature`, `candidates` 2 | 0 | - | 0 | - |
| `roles_unknown_role` | Rollenliste der Version 1 mit der Rolle `audit_log` für `vendor-test-001`: `effective`, Hinweise `unknown_role`, `receipt_key_other_role`, `pin_dropped`; die Anheftung entfällt (`listed_as` `audit_log`) | 0 | - | 1 | `RECEIPT_UNVERIFIED` |
| `roles_statement_pins` | Liste der Gegenzeichnungsschlüssel des Korpus über `--vendor-key-list`, Bescheidschlüssel angeheftet: `vendor-statements-test-001` (bleibt, `statement_keys` mit `pinned`) und `vendor-test-003` (Publikey in K_cs^L, entfällt); `key_roles`: `not_supplied`, Hinweis `pin_dropped` | 0 | - | 0 | - |
| `roles_pins_dropped` | Rollenliste der Version 1; angeheftet als Bescheidschlüssel `vendor-test-002` und `vendor-update-manifest-test-001`, als Protokollschlüssel `vendor-log-test-001` mit dem Publikey von `vendor-statements-test-002`: alle drei entfallen (`listed_as` `countersigning`, `update_manifest`, `statements`) | 0 | - | 0 | - |

`statement_signatures` (Heartbeat-Spezifikation §9.3) liest der Verifier nicht; die Referenzfälle für Empfänger der Fassungen 1.9 und 1.10 stehen in `spec/contract/statement_signatures.json`. Die Seite des Verifiers am Übergang vom Betrieb mit einem Schlüssel (10.7.5) zeigen `roles_dual_end_effective`, `roles_dual_end_differs` und `roles_dual_end_dropped`: `ende_doppelbetrieb` in der Rollenliste und die Regeln aus R2.

### 10.2 Angaben des Prüfers (Gruppe `auditor`)

Je Regel aus Formatspezifikation 10.8 (mit 7.1, 10.7.4 und 7.4.10, Schritt L0) ein unbrauchbarer Aufruf, dazu drei Fälle an einer Grenze, die angenommen werden. Das Paket ist die Standardkette; mit der Prüfumgebung des Korpus ergibt sie Exit 0. Ohne Vektor bleiben Angaben, die `ledger-pruefumgebung/1` nicht ausdrücken kann (ein Schalter, der höchstens einmal erlaubt ist, zweimal; eine Anheftung ohne die Form `key_id=hex64`; eine erwartete Wurzel mit `0:` oder führender Null; ein unbekannter Schalter) und die Größengrenzen ab 1 048 576 Bytes.

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `auditor_root_conflict` | zweite Herstellerwurzel `testwurzel-1` mit anderem Publikey neben der des Korpus | 0 | - | 3 | - |
| `auditor_root_extra_member` | Herstellerwurzel mit einem dritten Member `kommentar` | 0 | - | 3 | - |
| `auditor_vendor_key_conflict` | `--vendor-key vendor-test-001` mit dem Publikey von `vendor-test-002` neben der Anheftung des Korpus | 0 | - | 3 | - |
| `auditor_statement_pin_equals_cs_pin` | `--vendor-statement-key` mit genau der Anheftung des Korpus `vendor-test-001=...` | 0 | - | 3 | - |
| `auditor_statement_pin_conflict` | zwei Bescheidschlüssel `vendor-statements-test-001` mit verschiedenen Publikeys | 0 | - | 3 | - |
| `auditor_statement_pin_id_equals_log_pin` | Bescheidschlüssel und Protokollschlüssel mit derselben `key_id` `vendor-statements-test-001`, verschiedene Publikeys | 0 | - | 3 | - |
| `auditor_log_pin_conflict` | zwei Protokollschlüssel `vendor-log-test-001` mit verschiedenen Publikeys | 0 | - | 3 | - |
| `auditor_log_pin_equals_cs_pin` | Protokollschlüssel `vendor-log-test-001` mit dem Publikey der Anheftung `vendor-test-001` | 0 | - | 3 | - |
| `auditor_key_list_unknown_format` | Rollenliste der Version 1 mit `format` `ledger-schluesselrollen/2` | 0 | - | 3 | - |
| `auditor_key_list_no_format` | Rollenliste der Version 1 ohne Member `format` | 0 | - | 3 | - |
| `auditor_key_list_duplicate_member` | Rollenliste der Version 1 mit dem Member `version` zweimal | 0 | - | 3 | - |
| `auditor_key_list_number_form` | Rollenliste der Version 1 mit `"version":1.0` | 0 | - | 3 | - |
| `auditor_expect_root_too_large` | `--expect-root 9007199254740992:<Wurzel>` | 0 | - | 3 | - |
| `auditor_vendor_log_not_json` | `--vendor-log` mit einer Datei, die kein JSON ist | 0 | - | 3 | - |
| `auditor_anchor_history_not_json` | `--anchor-history` mit einer Datei, die kein JSON ist | 0 | - | 3 | - |
| `auditor_requested_at_after_now` | `--requested-at 2026-01-01T01:03:00.501Z`, Prüfzeitpunkt `2026-01-01T01:03:00.500Z` aus `verify_args.json` | 0 | - | 3 | `FORMAT_ERROR` |
| `auditor_requested_at_unused` | `--requested-at 2026-01-01T01:03:00.500999999Z` ohne Anker-Historie: angenommen, Hinweis `requested_at_unused` | 0 | - | 0 | - |
| `auditor_tsa_pem_other_label` | `--tsa-root` mit einem Block `CERTIFICATE` und einem Block `X509 CRL` | 0 | - | 3 | - |
| `auditor_tsa_pem_header` | `--tsa-root` mit einer Zeile `Comment: ...` zwischen `BEGIN` und dem Inhalt | 0 | - | 3 | - |
| `auditor_tsa_pem_no_end` | `--tsa-root` mit einem Block ohne `END` | 0 | - | 3 | - |
| `auditor_tsa_pem_no_block` | `--tsa-root` mit einer Datei ohne Block | 0 | - | 3 | - |
| `auditor_tsa_pem_not_b64` | `--tsa-root`, erste Inhaltszeile endet auf `==` | 0 | - | 3 | - |
| `auditor_tsa_pem_not_certificate` | `--tsa-root`, Zertifikat mit einem Byte `00` dahinter | 0 | - | 3 | - |
| `auditor_log_tsa_pem_no_block` | `--vendor-log-tsa-root` mit einer Datei ohne Block | 0 | - | 3 | - |
| `auditor_qualified_duplicate` | `--tsa-qualified-roots` mit derselben Wurzel zweimal | 0 | - | 3 | - |
| `auditor_qualified_window_inverted` | `qualifiziert_bis` vor `qualifiziert_ab` | 0 | - | 3 | - |
| `auditor_qualified_unknown_member` | `--tsa-qualified-roots` mit einem Member `kommentar` | 0 | - | 3 | - |
| `auditor_qualified_format` | `format` `ledger-tsa-qualifiziert/2` | 0 | - | 3 | - |
| `auditor_qualified_not_certificate` | `zertifikat` mit einem Byte `00` hinter dem Zertifikat | 0 | - | 3 | - |
| `auditor_log_neighbours_equal_index` | `--vendor-log` mit einem Auszug des Testprotokolls (§11.1): Tag 2025-12-31 und ein Nachweis `absent`, dessen zwei Nachbarn denselben `leaf_index` tragen: Grammatik eingehalten (nicht fallend), kein Exit 3; beide Quittungen `pending` | 0 | - | 0 | - |

### 10.3 Zeitstempelprofil (Gruppe `timestamp`)

Die Token stellt eine Zeitstempelstelle des Generators aus (`appliance/cmd/vektorgen/zeitstempelprofil.go`): eine Wurzel und ein Signierer mit Ed25519-Schlüsseln aus veröffentlichten Startwerten, `digestAlgorithm` SHA-512 (RFC 8419), `genTime` `20260101004001Z`, Abdruck SHA-256 über den Signaturgegenstand des Checkpoints, `signingCertificateV2` auf den Signierer, keine `extensions`. Jeder Vektor ändert genau das, wonach er heißt; die Prüfumgebung der meisten ist die Testwurzel in `--tsa-qualified-roots` (Zwecke `chain` und `qualified`, qualifiziert ab `2025-01-01T00:00:00Z`). Ohne Wurzel, also mit der Prüfumgebung des Korpus, ergibt jedes Token, das die Schritte 1 bis 4 und, wo ausführbar, 5b besteht, `TIME_ANCHOR_UNVERIFIED`.

**Veröffentlichte Testschlüssel.** Die SPKI-SHA-256-Werte der Wurzel, des Signierers und des Brainpool-Signierers stehen in `published_test_keys` (Formatspezifikation 7.5.7), wie der der Probestelle, die `timestamp_published_test_key` verwendet. Darum rechnet kein Vektor die Bedingungen (1) und (4) der Beweisstufe an: Mit einer Wurzel des Prüfers enden `time_witness` und `time_witness_qualified` bei `published_test_key`, außer wo Schritt 5 nach 5a nicht ausführbar oder Z.6 nicht prüfbar ist (`signature_not_checkable`) oder kein Pfad besteht. Die Stufen hinter `published_test_key` (`qualified_root_in_package`, Zeitraum, Z.6, Regel QS) zeigt deshalb keine Solldatei; die Vektoren legen fest, dass diese Ergebnisse weder den Exit-Code noch die Befunde ändern.

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `timestamp_chain_root` | Token, das das ganze Profil einhält (Ed25519, ESS v2); `--tsa-root` mit der Testwurzel | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_qualified_root` | dasselbe Token; die Testwurzel nur in `--tsa-qualified-roots` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_signer_as_root` | dasselbe Token; `--tsa-root` mit dem Zertifikat des Signierers | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_signer_expired_after_gentime` | Signiererzertifikat gültig bis `2026-01-01T00:50:00Z`, `genTime` 00:40:01, Prüfzeitpunkt 01:03:00.5 | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_published_test_key` | Token der Probestelle (RSA, SPKI-SHA-256 `0ee470ad…`); ihr Zertifikat in `--tsa-qualified-roots` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_root_other` | `--tsa-root` mit dem Zertifikat einer anderen Stelle (Probestelle) | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_qualified_root_other` | `--tsa-qualified-roots` mit dem Zertifikat einer anderen Stelle | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_log_root_only` | die Testwurzel nur in `--vendor-log-tsa-root` (Zweck `log`) | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_signer_eku_not_critical` | Signiererzertifikat mit `extKeyUsage` `id-kp-timeStamping`, nicht kritisch | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_signer_not_yet_valid` | Signiererzertifikat gültig ab `2026-01-01T00:45:00Z`, `genTime` 00:40:01 | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_root_repeated` | zwei `--tsa-root`: die Testwurzel, danach eine andere Stelle | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_pem_bundle` | eine PEM-Datei mit Kommentarzeile, CRLF, Leerraum am Zeilenende und zwei Wurzeln (andere Stelle zuerst) | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_checkpoint_mismatch` | `tree_size` des Eintrags 18 statt 20 | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_b64_newline` | `token_base64` mit `\n` nach 76 Zeichen | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_der_too_large` | DER 16 385 Bytes (Füllung in `crls`), Base64 21 848 Zeichen | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_imprint_wrong` | Abdruck über einen Signaturgegenstand mit anderer Baumwurzel, sonst ein Token, das das Profil einhält | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_gentime_trailing_zero` | `genTime` `20260101004001.120Z` | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_imprint_sha1` | `messageImprint` mit SHA-1 | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_two_signer_infos` | zwei gleiche `SignerInfo` | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_ber_length` | äußere Länge des `ContentInfo` mit einem führenden Oktett `00` | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_tsa_ts_rounded` | `genTime` `20260101004001.123999999Z`, `tsa_ts` `2026-01-01T00:40:01.124Z` (gerundet) | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_gentime_fraction` | `genTime` `20260101004001.123999999Z`, `tsa_ts` `2026-01-01T00:40:01.123Z`; `qualifiziert_ab` gleich `genTime`; Eingabe der Einzelprüfung | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_imprint_sha384` | `messageImprint` mit SHA-384 | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_sha1_digest_algorithm` | `digestAlgorithm` SHA-1 (auch in `digestAlgorithms`), `messageDigest` und Signatur stimmen; Eingabe der Einzelprüfung | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_no_certificates` | `certificates` fehlt | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_no_signed_attrs` | `signedAttrs` fehlen, Signatur über `eContent` | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_signer_not_found` | `sid` mit einer Seriennummer, die kein Zertifikat trägt | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_certificate_not_z1` | `certificates` mit dem Signierer und einem Zertifikat der Version 1 | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_signer_brainpool` | Signierer mit einem Schlüssel auf brainpoolP256r1, `ecdsa-with-SHA256` | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_key_algorithm_mismatch` | Ed25519-Schlüssel, `signatureAlgorithm` `sha256WithRSAEncryption` | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_message_digest_wrong` | `messageDigest` um ein Bit verändert, Signatur darüber trägt | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_signature_wrong` | Signatur um ein Bit verändert | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_content_type_attr_wrong` | `contentType` `id-data` | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_ess_none` | keines der beiden ESS-Attribute | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_ess_v1` | nur `signingCertificate` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_ess_both` | `signingCertificate` und `signingCertificateV2`, beide auf den Signierer; Eingabe der Einzelprüfung | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_ess_v2_other_cert` | `signingCertificateV2` mit dem Hash der Wurzel | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_ess_v1_mismatch` | beide Attribute, `signingCertificate` mit dem Hash der Wurzel | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_ess_two_values` | `signingCertificateV2` mit zwei Werten | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_ess_issuer_serial_mismatch` | `signingCertificateV2` mit `issuerSerial` einer anderen Seriennummer | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_ess_v2_sha1` | `signingCertificateV2` mit `hashAlgorithm` SHA-1 | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_qs_present` | `extensions` mit `qcStatements` und `0.4.0.19422.1.1` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_qs_other_statement` | `qcStatements` nur mit `0.4.0.1862.1.1` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_qs_malformed` | `qcStatements` mit `SEQUENCE { INTEGER 1 }` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_qs_unknown_critical` | `qcStatements` mit Kennung und eine unbekannte kritische Erweiterung | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_qs_critical_false_encoded` | `qcStatements` mit ausdrücklich kodiertem `critical` `00` und Kennung | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_qs_nonce_bytes` | `nonce` mit den Bytes `06 07 04 00 81 97 5E 01 01`, keine `extensions` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_qs_empty` | leeres `extensions` `[1]` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_qualified_outside_window` | `qualifiziert_bis` `2026-01-01T00:40:01Z` gleich `genTime` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_extension_value_not_der` | Signierer mit einer nicht kritischen Erweiterung, die keine Regel liest; ihr `extnValue` ist ein TLV minimaler Länge mit einem Inhalt außerhalb von DER (`30 03 01 01 01`): nur das äußere TLV wird geprüft | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_certificates_not_tlv` | Inhalt von `certificates` zerfällt nicht in TLV (Signierer, dann `30 05 01`): Schritt 5 nicht ausführbar (5a), nie Grammatik T; Eingabe der Einzelprüfung | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_gentime_year_zero` | `genTime` `00000101004001Z`, `tsa_ts` `2026-01-01T00:40:01.000Z`: das Jahr `0000` verletzt Grammatik T (T.5), Schritt 2 | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_sid_not_issuer_serial` | `sid` ist eine SEQUENCE, deren Seriennummer das Tag OCTET STRING trägt: Grammatik T eingehalten, kein Signierer nach Z.5 (5a); Eingabe der Einzelprüfung | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_name_value_constructed` | CN im `subject` des Signierers als UTF8String in zusammengesetzter Form: der Wert eines Attributs eines Name ist ein TLV, Z.1 gilt; Eingabe der Einzelprüfung | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_ess_v2_second_element_broken` | `signingCertificateV2` mit `certs[0]` auf den Signierer und `certs[1]` = `SEQUENCE { INTEGER 1 }`, kein ESSCertIDv2: Jedes Element von `certs` folgt der Grammatik von Z.6, auch wo nur `certs[0]` verglichen wird; Z.6 verletzt (7.5.6); Eingabe der Einzelprüfung | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_ess_issuer_serial_name_broken` | `issuerSerial` in `certs[0]` mit der Seriennummer des Signierers und zwei `directoryName` `[4]`: der erste mit dem `issuer` des Signierers, der zweite mit `SEQUENCE { INTEGER 1 }`, kein Name; ein Element mit dem Identifier-Oktett `A4` enthält genau einen Name nach Z.1: Z.6 verletzt, obwohl ein passender `directoryName` daneben steht; Eingabe der Einzelprüfung | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_ess_policies_not_der` | `signingCertificateV2` mit `policies`, in dessen Qualifier ein INTEGER mit dem Inhalt `00 01` (nicht minimal) und ein `[4]` darum stehen: `policies` liest keine Regel, T.6 prüft nur das äußere TLV, ein `[4]` darin ist kein `directoryName`; Z.6 gilt; Eingabe der Einzelprüfung | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_ess_other_name_a4` | GeneralNames in `issuerSerial`: ein otherName `[0]`, dessen Wert ein `[4]` mit `SEQUENCE { INTEGER 1 }` enthält, dann der `directoryName` `[4]` mit dem `issuer` des Signierers: Vom otherName prüft T.6 nur das äußere TLV, ein `[4]` in seinem Wert ist kein `directoryName`; Z.6 gilt; Eingabe der Einzelprüfung | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_signer_basic_constraints_not_der` | Signierer mit basicConstraints, kritisch, Inhalt `SEQUENCE { BOOLEAN 01 }`: Den Inhalt von basicConstraints prüft Z.1 nach T.6, BOOLEAN `01` ist kein DER; Z.1 verletzt, Schritt 5 nicht ausführbar (5a), nicht „kein Pfad“ | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_extra_certificate_path_len_not_minimal` | `certificates` mit dem Signierer und einem Zertifikat der Wurzel für eine Zwischenstelle auf keinem Pfad, dessen `pathLenConstraint` 0 als INTEGER-Inhalt `00 00` steht: Z.1 gilt für jedes Zertifikat aus `certificates`, hier nicht; 5a | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_signer_eku_oid_not_minimal` | `extKeyUsage` des Signierers mit `id-kp-timeStamping`, letzte Teilkennung 8 als `80 08`, nicht minimal: Z.1 verletzt, 5a, nicht „kein Pfad“ nach Z.4 | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_signer_basic_constraints_tag_zero` | basicConstraints des Signierers mit dem Inhalt `30 02 00 00`, ein Element der Klasse universal mit der Tag-Nummer 0: Wo T.6 jedes Element prüft, genügt es T.6 nicht; Z.1 verletzt, 5a | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_signer_basic_constraints_tag_31` | basicConstraints des Signierers mit dem Inhalt `30 03 1F 1F 00`, ein Element der Klasse universal mit der Tag-Nummer 31: genügt T.6 nicht; Z.1 verletzt, 5a | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_signer_key_usage_unreadable` | keyUsage des Signierers ist der BIT STRING `03 02 08 80` mit acht ungenutzten Bits: Das Oktett der ungenutzten Bits prüft T.6 nicht, Z.1 gilt und Schritt 5 hält; keyUsage folgt der Grammatik von Z.3 nicht, das macht den Pfad auch an c0 unbrauchbar: kein Pfad | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_signer_basic_constraints_unreadable` | basicConstraints des Signierers mit dem Inhalt `SEQUENCE { OCTET STRING 00 }`: DER, Z.1 gilt; folgt der Grammatik von Z.3 nicht, auch an c0, wo Z.4 basicConstraints nicht auswertet: kein Pfad | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_signer_basic_constraints_null_content` | basicConstraints des Signierers mit dem Inhalt `SEQUENCE { NULL }`, das NULL mit dem Inhalt `00`: Den Inhalt von NULL prüft T.6 nicht, Z.1 gilt; Z.3 nicht eingehalten: kein Pfad, nie 5a | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_root_key_cert_sign_unused_bit` | in `--tsa-qualified-roots` die Testwurzel mit demselben Schlüssel und keyUsage `03 02 03 06`: keyCertSign (Bit 5) steht unter den drei ungenutzten Bits und zählt nicht; Z.4 verlangt keyCertSign an der Wurzel: kein Pfad | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_sid_key_identifier` | `sid` als `[0]` mit dem Schlüsselbezeichner aus subjectKeyIdentifier des Signierers (Inhalt des OCTET STRING in `extnValue`, SHA-1 seines Publikeys), Version 1: Z.5 findet den Signierer | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_signature_r_identity` | Signatur des Tokens mit R = `01 00…00 00`, der kanonischen Kodierung des neutralen Elements, und S = k·a mod L: Die Kodierung von [S]B - [k]A gleicht R, die Signatur besteht (Abschnitt 2) | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_signature_r_identity_sign_bit` | dieselbe Signatur mit R = `01 00…00 80`, dem neutralen Element mit gesetztem Vorzeichenbit: als Punkte gilt [S]B = R + [k]A, die Kodierung von [S]B - [k]A ist aber `01 00…00 00`; Schritt 5b (Abschnitt 2) | 2 | `TIME_ANCHOR_INVALID` | 2 | `TIME_ANCHOR_INVALID` |
| `timestamp_signer_cert_r_identity` | Signatur der Wurzel über das Signiererzertifikat mit R = `01 00…00 00`: besteht, der Pfad besteht | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_signer_cert_r_identity_sign_bit` | Signatur der Wurzel über das Signiererzertifikat mit R = `01 00…00 80`: besteht nicht, kein Pfad (Z.4), nie 5b | 1 | `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` |
| `timestamp_ess_hash_algorithm_parameters_not_der` | `signingCertificateV2` mit `hashAlgorithm` SHA-256 und den Parametern `02 02 00 01` in `certs[0]`, ein INTEGER 1 mit dem Inhalt `00 01`, nicht minimal: Den `hashAlgorithm` erkennt der Verifier allein an der OID, von den Parametern prüft T.6 nur das äußere TLV; Z.6 gilt (7.5.6); Eingabe der Einzelprüfung | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_signed_attribute_value_not_der` | ein weiteres signiertes Attribut eines privaten Typs mit dem Wert `30 04 02 02 00 01`, eine SEQUENCE um einen INTEGER mit dem Inhalt `00 01`: Der Wert eines signierten Attributs, das keine Regel liest, ist ein TLV, nur dieses prüft T.6; Grammatik T eingehalten, Schritt 5 ausgeführt (7.5.2) | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_extra_certificate_key_parameters_tag_zero` | `certificates` mit dem Signierer und einem Zertifikat der Wurzel auf keinem Pfad, dessen `subjectPublicKeyInfo` einen privaten Algorithmus außerhalb von Z.2 mit den Parametern `00 00` nennt, einem TLV der Klasse universal mit der Tag-Nummer 0: Von Parametern, die keine Regel liest, prüft T.6 nur das äußere TLV, die Tag-Nummer 0 ist dort zugelassen; Z.1 gilt, Z.2 gilt nur für Schlüssel auf einem Pfad | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_extra_certificate_oid_arc_large` | `certificates` mit dem Signierer und einem Zertifikat der Wurzel auf keinem Pfad, dessen nicht kritisches `extKeyUsage` eine OID mit der Teilkennung N = 128^2100 + … + 128 + 1 enthält (4426 Dezimalstellen, über 10^4300), minimal kodiert: T.6 setzt einer Teilkennung keine Grenze, Z.1 gilt, Schritt 5 ausführbar (7.5.3) | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `timestamp_qs_extension_oid_arc_large` | `extensions` des TSTInfo mit einer nicht kritischen Erweiterung, deren `extnID` dieselbe Teilkennung N trägt, Wert NULL, daneben `qcStatements` mit der Kennung: Jede Extension ist DER nach T.6, die unbekannte nicht kritisch; Regel QS `present` (7.5.6); Eingabe der Einzelprüfung | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |

### 10.4 Eingaben der Einzelprüfung von Zeitstempeln

Für die Einzelprüfung eines Zeitstempels (`ledger-verify zeitstempel`, `verifier2.py zeitstempel`; sie prüft kein Paket und ist nicht Teil der Spezifikation) liegen zu zwölf Vektoren die Eingaben auf oberster Ebene, mit Pin: `zeitstempel_<name>.token.der` und `zeitstempel_<name>.token.b64` (der Token als DER und als Base64 nach B64, ohne Zeilenende), `zeitstempel_<name>.daten.json` (die Bytes, die der Abdruck deckt, der Signaturgegenstand des Checkpoints, für `--data`) und `zeitstempel_<name>.wurzel.pem` (die Testwurzel, für `--tsa-root`). Mit `--purpose chain` und dieser Wurzel folgen die Ergebnisse aus der Tabelle in 7.5.7 (die oberste zutreffende Zeile, Fälle wie in Registry `verifier.timestamp_profile.outcomes`); Signierer ist jeweils `Testkorpus Zeitstempelstelle (kein Zeuge)`, soweit Z.5 ihn findet. Die Zeilen von 7.5.7 gelten für beide Zwecke gleich: Mit `--purpose log` und derselben Wurzel ist das Ergebnis dasselbe. Die Eingaben zu Z.6 zeigen, was die Solldatei nicht zeigt: Ein Token eines veröffentlichten Testschlüssels endet dort bei `published_test_key`, die Zeile zu Z.6 steht in 7.5.7 darüber. Ebenso zeigt nur die Einzelprüfung das Ergebnis der Regel QS (Spalte „Regel QS“).

| Eingabe | genTime, auf Millisekunden abgeschnitten | Abdruck | Regel QS | Ergebnis |
|---|---|---|---|---|
| `zeitstempel_timestamp_gentime_fraction` | `20260101004001.123999999Z`, `2026-01-01T00:40:01.123Z` | sha256 | `absent` | nicht bestätigt, `published_test_key` |
| `zeitstempel_timestamp_sha1_digest_algorithm` | `20260101004001Z`, `2026-01-01T00:40:01.000Z` | sha256 | `absent` | nicht bestätigt, `step_5_not_performable` (`digestAlgorithm` SHA-1 außerhalb von Z.2) |
| `zeitstempel_timestamp_ess_both` | `20260101004001Z`, `2026-01-01T00:40:01.000Z` | sha256 | `absent` | nicht bestätigt, `published_test_key` (Z.6 gilt mit beiden Attributen) |
| `zeitstempel_timestamp_certificates_not_tlv` | `20260101004001Z`, `2026-01-01T00:40:01.000Z` | sha256 | `absent` | nicht bestätigt, `step_5_not_performable` (der Inhalt von `certificates` zerfällt nicht in TLV) |
| `zeitstempel_timestamp_sid_not_issuer_serial` | `20260101004001Z`, `2026-01-01T00:40:01.000Z` | sha256 | `absent` | nicht bestätigt, `step_5_not_performable` (kein Signierer nach Z.5) |
| `zeitstempel_timestamp_name_value_constructed` | `20260101004001Z`, `2026-01-01T00:40:01.000Z` | sha256 | `absent` | nicht bestätigt, `published_test_key` (Z.1 gilt) |
| `zeitstempel_timestamp_ess_v2_second_element_broken` | `20260101004001Z`, `2026-01-01T00:40:01.000Z` | sha256 | `absent` | mangelhaft, `z6_failed` (`certs[1]` ist kein ESSCertIDv2) |
| `zeitstempel_timestamp_ess_issuer_serial_name_broken` | `20260101004001Z`, `2026-01-01T00:40:01.000Z` | sha256 | `absent` | mangelhaft, `z6_failed` (ein `directoryName` ohne Name) |
| `zeitstempel_timestamp_ess_policies_not_der` | `20260101004001Z`, `2026-01-01T00:40:01.000Z` | sha256 | `absent` | nicht bestätigt, `published_test_key` (Z.6 gilt, `policies` nur als äußeres TLV) |
| `zeitstempel_timestamp_ess_other_name_a4` | `20260101004001Z`, `2026-01-01T00:40:01.000Z` | sha256 | `absent` | nicht bestätigt, `published_test_key` (Z.6 gilt, das `[4]` im otherName ist kein `directoryName`) |
| `zeitstempel_timestamp_ess_hash_algorithm_parameters_not_der` | `20260101004001Z`, `2026-01-01T00:40:01.000Z` | sha256 | `absent` | nicht bestätigt, `published_test_key` (Z.6 gilt, die Parameter von `hashAlgorithm` nur als äußeres TLV) |
| `zeitstempel_timestamp_qs_extension_oid_arc_large` | `20260101004001Z`, `2026-01-01T00:40:01.000Z` | sha256 | `present` | nicht bestätigt, `published_test_key` (die Teilkennung über 10^4300 hält T.6 ein) |

## 11. Herstellerprotokoll der Spezifikation 1.10 (Gruppe `log`)

89 Vektoren der Gruppe `log` prüfen die Schritte L0 bis L10 aus Formatspezifikation 7.4.10 und das Berichtsobjekt `vendor_log` (10.10.2). Sie erklären `spec_version` `1.10`. Ihre Erwartungen stehen in der Registry, jede mit Grund und Abschnitt im Member `why`, abgeleitet aus dem Text der Spezifikation; das Berichtsobjekt `vendor_log` nennt die Solldatei nicht, seine Werte stehen, wo ein Vektor von ihnen handelt, in der Beschreibung der Zeile. 26 von ihnen (§11.3, Tabelle „Bezeugte Tage“) zeigen mit der Zeitstempelstelle E1 (§11.2) die Fälle, die einen nutzbaren Tag brauchen.

### 11.1 Paket und Protokoll

**Paket.** Jeder Vektor hat seine eigene Kette, mit eigener `chain_id` und `appliance_id`, nach demselben Ablauf: `GENESIS` um 23:50 am 2026-01-02, zwei KI-Aufrufe, 5-Minuten-Takt, Quittungen unter `vendor-test-001` um 23:55:01 (`tree_size` 5, Tag 2026-01-02) und um 00:05:01 am Folgetag (`tree_size` 10, Tag 2026-01-03), versiegelt um 00:06 mit `SEAL(shutdown)` und Sofort-Checkpoint (14 Einträge), geprüft um 06:30 am 2026-01-03. Der Tag der ersten Quittung ist dann fällig, der der zweiten nicht (Formatspezifikation 7.4.6, Fälligkeit). Mit der Prüfumgebung des Korpus ergibt jedes Paket Exit 0 und Stufe 2 bis `tree_size` 10. `log_receipt_future` wird um 23:49 am 2026-01-02 geprüft, `log_receipts_pending` um 00:10 am 2026-01-03; die Kette von `log_receipts_before_start` beginnt um 23:30 am 2025-12-30 und wird um 23:50 desselben Tages geprüft. In `log_witnessed_receipt_invalid` und `log_receipt_invalid_outside_range` nennt die Quittung von `tree_size` 5 als `checkpoint_seq` den `TICK` vor ihrem Checkpoint: Ihre Signatur trägt, sie passt zu einem Präfix, ist aber `RECEIPT_INVALID` (Exit 2, Formatspezifikation 7.1). `log_witnessed_time_anchor_qualified` trägt 700 ms nach der ersten Quittung einen `TIME_ANCHOR` über den Checkpoint von `tree_size` 5 (15 Einträge, Quittungen bei `tree_size` 5 und 11); mit der Prüfumgebung des Korpus ergibt er `TIME_ANCHOR_UNVERIFIED`.

**Protokoll.** Das Testprotokoll `ledger-testprotokoll-1` ist das der Beispiele aus Formatspezifikation 7.4.4, 7.4.5 und 7.4.7: Beginn 2025-12-31, das veröffentlichte Test-Füllergeheimnis und die Protokollschlüsselliste der Version 1 mit `vendor-log-test-001` und dem Reserveschlüssel `vendor-log-test-002` (Startwerte `vendor-log-1` und `vendor-log-2`, beide in `published_test_keys`), signiert von `testwurzel-1`. Seine Tage 2025-12-31 (ohne Blätter, `tree_size` 0, Tageshash `33fd1b29…`) und 2026-01-01 (der Baum der Größe 5, Wurzel `0adcf8f0…`, Tageshash `ef330d20…`) sind die der Referenzwerte und in jedem Vektor gleich. Der Tag 2026-01-02 trägt das Kettentag-Blatt der Kette des Vektors und die Kandidaten 0 bis 3 des Tages als Füller, abgeschlossen um 00:05 am 2026-01-03. Jeder Tageseintrag ist mit `vendor-log-test-001` signiert und von der Zeitstempelstelle des Testkorpus (§10.3) über `UTF-8(statement_jcs)` mit sha256 gestempelt, `genTime` eine Sekunde nach `server_ts`. Der Auszug ist der, den der Server ohne `from` und `to` gibt: die Tage ab dem ersten Blatt der Kette bis zum Kopf, hier der Tag 2026-01-02 mit seinem Kettentag-Nachweis, und die Protokollschlüsselliste in `protocol_keys`. In den Vektoren der Tabelle „Bezeugte Tage“ stempelt die Zeitstempelstelle E1 (§11.2) den Tag 2026-01-02; Kettentag-Blatt, Füller und Nachweis folgen dem, wovon der Vektor handelt.

**Prüfumgebung.** `pruefer_<name>.json` übergibt die Anker des Korpus (`korpus` `true`), die Auszüge mit `--vendor-log` und die Wurzel der Zeitstempelstelle des Testkorpus mit `--vendor-log-tsa-root`, soweit der Vektor nicht von diesen Angaben handelt. `TestProtokollVektoren`, `TestProtokollNachweise`, `TestProtokollReferenzfall` und `TestProtokollTabellenFolgenDerErwartung` (`appliance/cmd/vektorgen`) halten Pakete, Nachweise, Referenzfall und die Tabelle in §11.3 gegen die Bytes und gegen `expected/`; `TestBlaetterReferenzwerte`, `TestFuellerReferenzwerte`, `TestTageseintragReferenzwerte` und `TestProtokolllisteReferenzwerte` rechnen die Referenzwerte aus 7.4.2, 7.4.4, 7.4.5 und 7.4.7 nach, `TestInklusionUndAbwesenheit` die Beweise nach Abschnitt 5. Die Vektoren der Tabelle „Bezeugte Tage“ übergeben statt der Wurzel der Teststelle die Wurzel von E1 mit `--vendor-log-tsa-root`, wo sie von Bedingung (4) oder (7) handeln, auch in `--tsa-qualified-roots` (benannt ab 2025-01-01). `TestEinmaligeStelleEingefroren`, `TestEinmaligeStelleWeistAbweichungAb`, `TestBezeugtVektoren`, `TestBezeugtNachweise`, `TestBezeugtStempel`, `TestZweiterReferenztag` und `TestBezeugtTabellenFolgenDerErwartung` (`appliance/cmd/vektorgen`) halten die eingefrorene Eingabe, die Pakete, jeden Nachweis, jeden Zeitstempel von E1 mit seiner Fensterklasse, den zweiten Referenztag und die Tabelle gegen die Bytes und gegen `expected/`.

### 11.2 Bezeugte Tage und die Zeitstempelstelle mit verworfenen Schlüsseln

Jeder Schlüssel einer Zeitstempelstelle aus einem veröffentlichten Startwert steht in `published_test_keys`; ein Tageszeitstempel einer solchen Stelle ist nach Formatspezifikation 7.5.7 nie bestätigt. Mit solchen Stellen ist deshalb kein Tag bezeugt oder nutzbar (7.4.10, Schritte L2 (h) und L3). Kein Vektor, dessen Tage nur solche Stellen stempeln, zeigt die Klassen `included` und `not_included`, die Unterklassen `no_record`, `record_failed` und `record_contradictory`, die Befunde `RECEIPT_NOT_LOGGED` und `LOGGED_ROOT_MISMATCH`, den Grund `late`, einen bestätigten verfrühten Zeitstempel, zwei bezeugte Fassungen eines Tages, die Prüfungen der Schritte L6 und L9 und die Gültigkeit eines Protokollschlüssels über das `genTime` eines bestätigten Zeitstempels (L2 (e)); die Bedingungen (5) und (7) der Beweisstufe liegen in einem solchen Vektor nicht vor. Die Nachweise der Vektoren sind trotzdem richtig gebildet (`TestProtokollNachweise` prüft jeden nach `verify_inclusion` und den Formen des Abwesenheitsbeweises aus Abschnitt 5), und die Vektoren legen fest, dass ein Nachweis an einem Tag, der nicht nutzbar ist, übergangen und in keinem Member des Berichts gezählt wird. Die Vektoren der Tabelle „Bezeugte Tage“ zeigen diese Fälle mit der Zeitstempelstelle E1.

**Zeitstempelstelle mit verworfenen Schlüsseln** (Formatspezifikation 7.5.7). Das Korpus DARF eine Zeitstempelstelle enthalten, deren Schlüssel in einem Lauf des Generators aus einem kryptographisch sicheren Zufallsgenerator entstehen, nur in diesem Lauf die Token des Korpus ausstellen und nirgends geschrieben werden. Ihre Wurzel und ihre Zertifikate stehen im Korpus; ihre Schlüssel stehen nicht in `published_test_keys`. Sie zählt nur, wo die Prüfumgebung eines Vektors ihre Wurzel übergibt (`pruefer_<name>.json`); ein Prüfer außerhalb des Korpus hat keinen Grund, sie zu übergeben. Sie dient dazu, die Fälle zu zeigen, die einen nutzbaren Tag brauchen. Ihre Token lassen sich nicht erneut ausstellen: Der Generator führt sie als eingefrorene Eingaben und bricht ab, wenn eine neu erzeugte Aussage nicht mehr zu einem eingefrorenen Token passt. Neue Token dieser Art verlangen eine neue Stelle mit neuer Wurzel und neuen Pins in `PINS.sha256`. Wer den Generator ausgeführt hat, hätte den Schlüssel behalten können; deshalb ist ihre Wurzel nie die Wurzel eines Prüfers.

**Die Stelle E1 des Korpus.** Das Korpus enthält zwei solche Stellen, E1 und E2 (§13.2). Ihre Eingabe `appliance/cmd/vektorgen/eingefroren/zeitstempelstelle_e1.json` (Format `ledger-testkorpus-zeitstempelstelle/1`) nennt genau drei Zertifikate und die Token, keinen Schlüssel; der Generator kopiert sie unverändert nach `zeitstempelstelle_e1.json`:

- `wurzel`: „Testkorpus Zeitstempelwurzel E1 (Schluessel verworfen)“, Ed25519, selbst signiert, Seriennummer 1, gültig von 2025-01-01 bis 2036-01-01, basicConstraints cA und keyUsage keyCertSign, beide kritisch; SHA-256 des Zertifikats `8cc6b26e7d6c5e9d643d44b7cb6219a18131e45eae54dba715d9770801ee709c`, SPKI-SHA-256 `596a543ec10239b2d08e7230b38b4e5bac7531758c9b83a3d75c59acc7c604ac`.
- `signierer`: „Testkorpus Zeitstempelstelle E1 (Schluessel verworfen)“, Seriennummer 2, gültig von 2025-06-01 bis 2031-01-01, keyUsage digitalSignature und extKeyUsage genau `id-kp-timeStamping`, beide kritisch; SPKI-SHA-256 `5babaa3dda6221b13273c3843e98a07ec07dd61dca3e9c165c083860dd555429`.
- `signierer_qs`: „Testkorpus Zeitstempelstelle E1 qcStatements (Schluessel verworfen)“, Seriennummer 3, sonst wie `signierer`; SPKI-SHA-256 `5ebf2a484ceecb25d5f1e8ee7c0022b5957b8e681a8bfe63f6465e2bff0a73a2`. Seine Token tragen im TSTInfo die Erweiterung `qcStatements` mit `esi4-qtstStatement-1` (Regel QS: `present`, Formatspezifikation 7.5.6), für die Bedingungen (4) und (7) der Beweisstufe.
- `token`: 31 Token, je unter dem Namen `<Vektor>/<Bezeichnung>` oder `protokoll/2026-03-01`, Seriennummern `0x3001` bis `0x301e` und `0x3100`.

Jedes Token folgt Profil Z (Formatspezifikation 7.5): Ed25519, Abdruck mit sha256 über `UTF-8(statement_jcs)` oder, beim `TIME_ANCHOR`, über den Signaturgegenstand des Checkpoints, `digestAlgorithm` id-sha512 neben Ed25519 (RFC 8419), signingCertificateV2 mit SHA-256 über das Signiererzertifikat (Z.6) und das Signiererzertifikat in `certificates` (`certReq`). Ein Token von E1 ist deshalb für den Zweck `log` und für den Zweck `chain` bestätigt, wo die Prüfumgebung die Wurzel von E1 für diesen Zweck übergibt; Ausnahme ist das Token von `log_witnessed_reason_z6_not_checkable`, dessen signingCertificateV2 SHA-1 nennt. Die Token zeigen die drei Fensterklassen aus Formatspezifikation 7.4.6: bezeugend (`genTime` eine Sekunde nach `server_ts`), verfrüht (`log_witnessed_premature_stamp`) und verspätet (`log_witnessed_reason_late`, `log_witnessed_window_bounds`, `log_witnessed_qualified_stamp`).

Die Schlüssel von E1 sind in einem einzigen Lauf von `vektorgen -einmalige-stelle appliance/cmd/vektorgen/eingefroren` aus `crypto/rand` im Speicher entstanden; die Wurzel hat die Signierer zertifiziert, die Signierer haben jedes Token ausgestellt, das das Korpus braucht, und der Lauf hat nur Zertifikate und Token geschrieben und die Schlüssel vor seinem Ende gelöscht. Dieser Modus überschreibt die Datei nie. Jeder andere Lauf des Generators hält jedes Token gegen die Anforderung, aus der er es neu bilden würde: Bis auf die Signatur muss das Token Byte für Byte gleich sein, und die Signatur muss unter dem eingefrorenen Signiererzertifikat tragen. Ein fehlendes, ein abweichendes und ein von keinem Vektor verlangtes Token beenden den Lauf.

### 11.3 Vektoren

Die Tabellen nennen zuerst Exit und Befunde mit der Prüfumgebung des Korpus (ohne Herstellerprotokoll), dann mit `pruefer_<name>.json`.

**Bezeugung des Tages** (Schritte L2 (d) und (h), L8 Fall 4). Jeder Vektor zeigt einen Grund von `day_not_witnessed`, wo die Spezifikation einen nennt; den Grund nennt der Befund, nicht die Solldatei.

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `log_day_test_authority` | ehrlicher Auszug, Wurzel der Teststelle mit `--vendor-log-tsa-root`: der Tag 2026-01-02 ist festgestellt, aber nicht bezeugt (Grund `published_test_key`); erste Quittung `unchecked` mit `day_not_witnessed`, zweite `pending` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_reason_no_timestamp` | das Tagesobjekt trägt keinen Zeitstempel: Grund `no_timestamp` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_reason_no_log_root` | ohne `--vendor-log-tsa-root`: Grund `no_log_root_supplied` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_reason_chain_root_only` | die Testwurzel nur mit `--tsa-root` (Zweck `chain`): Grund `no_log_root_supplied` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_reason_outside_profile` | Zeitstempel ohne `certificates`: Schritt 5 nicht ausführbar, Grund `outside_profile` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_reason_not_chained` | Wurzel der Probestelle mit `--vendor-log-tsa-root`: kein Pfad, Grund `not_chained_to_log_root` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_qualified_log_root` | die Testwurzel zusätzlich in `--tsa-qualified-roots`: `log_day_qualified` endet bei `no_receipt_included` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_timestamp_imprint_wrong` | einziger Zeitstempel über andere Bytes: mangelhaft; kein Befund zu `day_not_witnessed`, weil jeder Zeitstempel von c(d) mangelhaft ist | 0 | - | 1 | `VENDOR_LOG_DEFECTIVE` |
| `log_timestamp_z6_violated` | einziger Zeitstempel ohne ESS-Attribut: Z.6 verletzt, für Tageseinträge mangelhaft | 0 | - | 1 | `VENDOR_LOG_DEFECTIVE` |
| `log_timestamps_early_late_test_key` | `server_ts` 00:00:20; Zeitstempel mit `genTime` 00:00:30 (verfrüht) und `20260105000000Z` (verspätet) der Teststelle: nicht bestätigt, kein Widerspruch, Grund `published_test_key` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |

**Protokollschlüssel und Signaturen** (Schritte L1, L2 (a), (b), (e), (f); weitere Signaturen aus 7.4.8). Ohne wirksamen Protokollschlüssel entfallen L2 bis L9, und die Klassen der Quittungen bleiben unbestimmt; der Grund steht im Befund.

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `log_no_list` | `protocol_keys` `null`, keine Anheftung: Status `no_protocol_key` (`no_list`), Klassen der Quittungen unbestimmt | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_list_no_matching_root` | Liste mit `wurzel_id` `testwurzel-2`: `no_matching_root` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_list_signature_fails` | Liste unter `testwurzel-1`, signiert mit dem Schlüssel von `vendor-test-002`: `signature_fails` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_list_format_violated` | Liste mit einem Member `kommentar` in einem Schlüssel: `format_violated` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_lists_same_version_differ` | zweite Liste der Version 1 mit anderem `ausgestellt` über `--vendor-key-list`: `lists_contradictory` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_list_key_dropped` | Version 2 ohne `vendor-log-test-002`: `lists_contradictory` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_lists_filler_commitment_differ` | Version 2 mit anderer `fuellerbindung`: `lists_contradictory` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_list_key_in_two_roles` | Liste mit `vendor-log-test-003` und dem Publikey von `vendor-test-001`: `key_in_two_roles`, die Anheftung des Korpus bleibt | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_list_log_id_differs` | Liste mit `log_id` `ledger-testprotokoll-2`: `log_id_differs` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_pin_only` | keine Liste, `--vendor-log-key` `vendor-log-test-001`: F aus `first_day` der Einträge, sonst wie `log_day_test_authority` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_pin_first_day_contradictory` | nur die Anheftung; Einträge für 2026-01-01 (`first_day` 2025-12-31) und 2026-01-02 (`first_day` 2026-01-02): Widerspruch ohne Tag, jede Quittung `unchecked` mit `first_day_contradictory` | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION` |
| `log_pin_dropped` | Anheftung `vendor-log-test-001` mit dem Publikey von `vendor-test-002`, die Liste der Gegenzeichnungsschlüssel des Korpus über `--vendor-key-list`: die Anheftung entfällt, `no_protocol_key` mit dem Grund `key_in_two_roles` (7.4.10 L1 Nummer 4) | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_key_not_established` | Tageseintrag unter `vendor-test-002`: Schlüssel nicht belegt; der fällige Tag hat keinen festgestellten Eintrag, erste Quittung `missing` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_signature_fails` | Signatur des Tageseintrags trägt nicht: nicht festgestellt, erste Quittung `missing` | 0 | - | 1 | `VENDOR_LOG_DEFECTIVE`, `VENDOR_LOG_UNVERIFIED` |
| `log_additional_signature_fails` | weitere Signatur `ed25519` von `vendor-log-test-002`, die nicht trägt: der Eintrag bleibt festgestellt | 0 | - | 1 | `VENDOR_LOG_DEFECTIVE`, `VENDOR_LOG_UNVERIFIED` |
| `log_key_revoked` | Version 2 widerruft `vendor-log-test-001` ab 2026-01-03T03:00; der Tag trägt nur dessen Signatur: Gültigkeit beendet, erste Quittung `missing` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_resigned_after_revocation` | derselbe Widerruf; der Tag trägt die Neusignatur von `vendor-log-test-002` in `additional_signatures`: festgestellt | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_additional_signature_unknown_alg` | weitere Signatur mit `alg` `ecdsa-p256-sha256`: gezählt (`signatures_not_checked` 1), nie geprüft | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |

**Signierte Inhalte** (Schritte L2 (c) und (g), L3, L5).

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `log_entry_format_violation` | signierter Eintrag mit `server_ts` `2026-01-03T00:05:00Z`: verletzt das Format, erste Quittung `missing` | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION`, `VENDOR_LOG_UNVERIFIED` |
| `log_entry_not_json` | zweites Tagesobjekt mit dem signierten `statement_jcs` `kein JSON`: Widerspruch ohne Tag | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION`, `VENDOR_LOG_UNVERIFIED` |
| `log_rule_server_ts_before_day_end` | `server_ts` `2026-01-02T23:59:59.999Z`: verletzt eine Regel, erste Quittung `missing` | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION`, `VENDOR_LOG_UNVERIFIED` |
| `log_rule_prev_hash_zero` | `prev_hash` aus 64 Nullzeichen: verletzt eine Regel, erste Quittung `missing` | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION`, `VENDOR_LOG_UNVERIFIED` |
| `log_rule_day_before_start` | weiterer signierter Eintrag für 2025-12-30: Widerspruch an einem Tag außerhalb von [Lo, T], `receipts_logged` bleibt bei `day_timestamp_not_confirmed` | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION`, `VENDOR_LOG_UNVERIFIED` |
| `log_two_versions` | der Tag 2026-01-02 zweimal abgeschlossen (00:05 und 00:35, dieselbe Wurzel): zwei Fassungen, erste Quittung `unchecked` mit `day_contradictory` | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION` |
| `log_prev_hash_broken` | `prev_hash` von 2026-01-02 ist der Tageshash eines neuen Abschlusses von 2026-01-01 um 00:35, der nicht übergeben ist | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION`, `VENDOR_LOG_UNVERIFIED` |
| `log_skips_day` | Auszug mit 2025-12-31 und 2026-01-02, das an 2025-12-31 anknüpft: überspringt 2026-01-01 | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION`, `VENDOR_LOG_UNVERIFIED` |

**Verlangter Bereich und Klassen der Quittungen** (Schritte L7 und L8).

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `log_day_missing` | Auszug bis 2026-01-01 (Kette abwesend): der fällige Tag 2026-01-02 fehlt, erste Quittung `missing` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_receipt_future` | geprüft um 23:49 am 2026-01-02, Auszug bis 2026-01-01: zweite Quittung `future`, erste `pending` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_receipts_pending` | geprüft um 00:10 am 2026-01-03, Auszug bis 2026-01-01: beide Quittungen `pending` | 0 | - | 0 | - |
| `log_receipts_before_start` | Kette am 2025-12-30 (Quittungen 23:35:01 und 23:45:01), geprüft um 23:50, Auszug ohne Tage: beide `before_start`, Grund `receipts_before_log_start` | 0 | - | 0 | - |

**Nachweise und Auszüge** (Schritt L6, Abschnitt 7.4.8). Kein Tag dieser Vektoren ist nutzbar (§11.2): Nachweise werden übergangen und in keinem Member des Berichts gezählt.

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `log_record_not_holding` | Nachweis mit falschem `leaf_index` an einem Tag, der nicht nutzbar ist: übergangen, in keinem Member gezählt | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_two_records` | zweiter Auszug derselben Kette mit einem Nachweis `absent` für denselben Tag: nicht verwendet, kein Widerspruch | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_padded_day` | der Tag 2026-01-02 nach der Größenregel: 1023 Füller, Pfad aus 10 Hashes | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_absence_between_fillers` | Auszug ab 2026-01-01: Nachweis `absent` mit zwei Füllern als Nachbarn (Blattindizes 1 und 2) | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_foreign_chain_records` | zweiter Auszug einer anderen Kette mit einem Nachweis am selben Tag: `foreign_chain_records` 1 | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_mirror_extract` | Spiegelauszüge `2025.json` und `2026.json` (`chain_id` `null`, ohne Nachweise) | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_extract_server_ts_other_form` | `server_ts` einer Wurzel ohne Bruchteil: Grammatik eingehalten, der Nachweis wird nicht verwendet | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |

**Bezeugte Tage** (Zeitstempelstelle E1, §11.2; Schritte L2 (d), (e), (h), L3, L6, L8 Fälle 3 bis 5, L9; Entscheidungen B und D zu L2 und zu L7, L8 und r5′). Die Prüfumgebung übergibt die Wurzel von E1 mit `--vendor-log-tsa-root`. Wo nichts anderes steht, ist der Tag 2026-01-02 mit seinem Kettentag-Nachweis `present` bezeugt, die erste Quittung `included`, die zweite `pending`, `logged_roots.matching_prefix` 1 und `receipts_logged` liegt bis `tree_size` 5 vor.

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `log_witnessed_included` | ehrlicher Auszug, der Tag von E1 gestempelt (`genTime` `20260103000501Z`, bezeugend), Nachweis `present`: erste Quittung `included`, `days.witnessed` 1, Kopf bezeugt | 0 | - | 0 | - |
| `log_witnessed_not_included` | das Kettentag-Blatt des bezeugten Tages trägt eine frisch ausgestellte Wiederholung der Gegensignatur von `tree_size` 5 (`server_ts` 23:58:00.000Z), nicht die Quittung des Pakets: `not_included`; `matching_prefix` 1, `matching_without_receipt` 1 | 0 | - | 1 | `RECEIPT_NOT_LOGGED` |
| `log_witnessed_no_record` | bezeugter Tag ohne Kettentag-Nachweis: erste Quittung `unchecked` mit `no_record`, `logged_roots` alle 0 | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_witnessed_record_failed` | der einzige Nachweis nennt einen falschen `leaf_index`: Stand gescheitert, `unchecked` mit `record_failed` | 0 | - | 1 | `VENDOR_LOG_DEFECTIVE` |
| `log_witnessed_record_contradictory` | der tragende Nachweis `present` enthält neben der Quittung einen Lückenzeugen mit `server_ts` am 2026-01-03: Blatt eines anderen Tages, Stand widersprüchlich, `unchecked` mit `record_contradictory`, L9 prüft keine Wurzel | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION` |
| `log_witnessed_reason_late` | einziger Zeitstempel bestätigt, `genTime` `20260105000000Z`, genau end(d) + W: verspätet, Tag nicht bezeugt, `unchecked` mit `day_not_witnessed`, Grund `late` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_witnessed_premature_stamp` | `server_ts` 00:00:20; bestätigte Zeitstempel mit `genTime` `20260103000059.9999Z` (auf Millisekunden abgeschnitten 00:00:59.999, verfrüht) und `20260103000501Z` (bezeugend): Tag vor seinem Ende abgeschlossen, Eintrag gebrochen, c(d) nicht bestimmt, kein Kopf, `unchecked` mit `day_contradictory` | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION` |
| `log_witnessed_window_bounds` | `server_ts` 00:00:30; Zeitstempel mit `genTime` genau end(d) + 60 000 (`20260103000100Z`, bezeugend) und genau end(d) + W (`20260105000000Z`, verspätet): bezeugt, `included` | 0 | - | 0 | - |
| `log_witnessed_two_versions_one_witnessed` | zweite signierte Fassung des Tages (00:35) ohne Zeitstempel: zwei Fassungen, die bezeugte bleibt c(d), erste Quittung `included`; der Widerspruch liegt in [Lo, T], `receipts_logged` endet bei `vendor_log_contradiction` | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION` |
| `log_witnessed_two_versions_both_witnessed` | beide Fassungen bezeugt: c(d) nicht bestimmt, kein Kopf, `unchecked` mit `day_contradictory` | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION` |
| `log_witnessed_key_revoked_signed_before` | Version 2 über `--vendor-key-list` widerruft `vendor-log-test-001` ab `2026-01-03T00:05:01.0000005Z`; bestätigter Zeitstempel mit `genTime` `20260103000501.0000001Z`, auf Nanosekunden davor: das Paar gilt, `included`; `key_list.version` 2 | 0 | - | 0 | - |
| `log_witnessed_key_revoked_signed_after` | derselbe Widerruf, `genTime` `20260103000501.0000009Z`, auf Nanosekunden danach (auf Millisekunden abgeschnitten läge es davor): Gültigkeit beendet, der fällige Tag fehlt, erste Quittung `missing` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_witnessed_resigned_after_revocation` | Version 2 widerruft `vendor-log-test-001` ab 00:03:00, der Zeitstempel (00:05:01) liegt danach; die weitere Signatur `ed25519` von `vendor-log-test-002` trägt: festgestellt, bezeugt, `included` | 0 | - | 0 | - |
| `log_witnessed_absent_empty_day` | bezeugter Tag ohne Blätter (`tree_size` 0): Nachweis `absent` der Form (i) ohne Nachbarn, `not_included`, `logged_roots` alle 0 | 0 | - | 1 | `RECEIPT_NOT_LOGGED` |
| `log_witnessed_absent_before_first` | bezeugter Tag aus den Füllern 0 bis 3 ohne die Kette: Nachweis `absent` der Form (ii), Nachbar ein Füller am Blattindex 0, `not_included` | 0 | - | 1 | `RECEIPT_NOT_LOGGED` |
| `log_witnessed_absent_after_last_filler` | bezeugter Tag aus den Füllern 0 und 1: Form (iii), Nachbar ein Füller am Blattindex 1 = n − 1, `not_included` | 0 | - | 1 | `RECEIPT_NOT_LOGGED` |
| `log_witnessed_absent_between_two_fillers` | bezeugter Tag aus den Füllern 0 bis 3: Form (iv), Nachbarn zwei Füller an den Blattindizes 2 und 3, `not_included` | 0 | - | 1 | `RECEIPT_NOT_LOGGED` |
| `log_witnessed_logged_roots` | Nachweis `present` mit der Quittung, ihrer Wiederholung (23:58:00), zwei Lückenzeugen von root(1) (23:50:01 und 23:50:02), einer Gegensignatur (3, r) mit r ≠ root(3) und einer mit `tree_size` 20 > N: `matching_prefix` 2, `matching_without_receipt` 1, `contradicting_prefix` 1, `beyond_package` 1, `gap_witnesses` 1; `receipts_logged` bis `tree_size` 2 | 0 | - | 1 | `LOGGED_ROOT_MISMATCH` |
| `log_witnessed_logged_root_mismatch` | Nachweis `present` mit der Quittung und einer Gegensignatur (1, r) mit r ≠ root(1): t_m = 1 setzt die Reichweite von `receipts_logged` auf 0, Grund `logged_root_mismatch` | 0 | - | 1 | `LOGGED_ROOT_MISMATCH` |
| `log_witnessed_receipt_invalid` | die Quittung von `tree_size` 5 nennt den `TICK` vor ihrem Checkpoint (Signatur trägt, `RECEIPT_INVALID`), der bezeugte Nachweis trägt ihr Blatt: Sie hat keine Klasse (`receipts`: `pending` 1, sonst 0), `matching_prefix` 1, `matching_without_receipt` 0 | 2 | `RECEIPT_INVALID` | 2 | `RECEIPT_INVALID` |
| `log_receipt_invalid_outside_range` | dieselbe Quittung, Auszug bis 2026-01-01: Ohne sie verlangt L7 keinen Tag, kein `VENDOR_LOG_UNVERIFIED`, `receipts`: `pending` 1 | 2 | `RECEIPT_INVALID` | 2 | `RECEIPT_INVALID` |
| `log_witnessed_day_1999` | neben dem bezeugten Tag ein signierter Eintrag mit `day` `1999-12-31`: Widerspruch an diesem Tag (`days.contradictory` 1), außerhalb von [Lo, T]; `receipts_logged` liegt vor | 0 | - | 1 | `VENDOR_LOG_CONTRADICTION` |
| `log_witnessed_reason_z6_not_checkable` | einziger Zeitstempel mit signingCertificateV2 über SHA-1: Z.6 nicht prüfbar, nicht bestätigt, Grund `outside_profile` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_witnessed_qualified_stamp` | ein bezeugender und ein verspäteter Zeitstempel des Signierers von E1 mit `qcStatements`, die Wurzel von E1 auch in `--tsa-qualified-roots`: `log_day_qualified` liegt bis `tree_size` 5 vor | 0 | - | 0 | - |
| `log_witnessed_qualified_root_plain_stamp` | dieselbe Prüfumgebung, der Zeitstempel ohne `qcStatements`: `log_day_qualified` endet bei `no_qualified_statement` | 0 | - | 0 | - |
| `log_witnessed_time_anchor_qualified` | `TIME_ANCHOR` des Signierers mit `qcStatements` über den Checkpoint von `tree_size` 5, der Tag von demselben Signierer gestempelt, die Wurzel von E1 für `log` und als qualifiziert benannt: `time_witness`, `time_witness_qualified`, `receipts_logged` und `log_day_qualified` liegen bis `tree_size` 5 vor, Stufe 2 bis 11; mit der Prüfumgebung des Korpus `TIME_ANCHOR_UNVERIFIED` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |

**Grammatik des Auszugs** (Schritt L0): unbrauchbarer Aufruf, Exit 3 ohne Bericht.

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `log_extract_unknown_member` | Member `kommentar` auf oberster Ebene des Auszugs | 0 | - | 3 | - |
| `log_extract_mirror_with_records` | `chain_id` `null` mit einem Nachweis | 0 | - | 3 | - |
| `log_extract_present_and_absent` | Nachweis mit `present` und `absent` | 0 | - | 3 | - |
| `log_extract_record_empty` | Nachweis mit `present` und `absent` beide `null` | 0 | - | 3 | - |
| `log_extract_roots_duplicate` | dieselbe Wurzel zweimal in `roots` | 0 | - | 3 | - |
| `log_extract_two_records_one_day` | zwei Nachweise für denselben Tag in einer Datei | 0 | - | 3 | - |
| `log_extract_neighbours_descending` | zwei Nachbarn mit fallendem `leaf_index` | 0 | - | 3 | - |
| `log_extracts_log_id_differ` | zwei Auszüge mit `ledger-testprotokoll-1` und `ledger-testprotokoll-2` | 0 | - | 3 | - |
| `log_extract_ed25519_not_hex128` | weitere Signatur `ed25519` mit 127 Hex-Zeichen | 0 | - | 3 | - |
| `log_extract_additional_signature_twice` | zwei gleiche Elemente von `additional_signatures` | 0 | - | 3 | - |
| `log_extract_alg_pattern` | `alg` `Ed25519` | 0 | - | 3 | - |
| `log_extract_signature_too_long` | weitere Signatur aus 1025 Zeichen | 0 | - | 3 | - |
| `log_extract_timestamp_too_long` | Zeitstempel aus 21 849 Zeichen | 0 | - | 3 | - |
| `log_extract_five_timestamps` | fünf Zeitstempel in einem Tagesobjekt | 0 | - | 3 | - |
| `log_extract_server_ts_not_rfc3339` | `server_ts` `2026-01-02 23:55:01.000Z` (Leerzeichen statt `T`) | 0 | - | 3 | - |
| `log_extract_format_other` | `format` `ledger-protokollauszug/2` | 0 | - | 3 | - |

### 11.4 Referenzfall `spec/testvectors/protokoll/`

Das Verzeichnis zeigt das Testprotokoll so, wie ein Veröffentlichungsort es trägt (Heartbeat-Spezifikation §9.9, Dateiform), für jeden, der ein Protokoll schreibt oder liest: `keys.json` (die Protokollschlüsselliste der Version 1), `days/2025/2025-12-31.json` und `days/2026/2026-01-01.json` (die Tagesobjekte mit Eintrag, einem Zeitstempel und leerem `additional_signatures`), `leaves/2025/2025-12-31.json` und `leaves/2026/2026-01-01.json` (die Tagesblätter, leer und mit fünf Paaren), `2025.json` und `2026.json` (die Spiegelauszüge der Jahre), `head.json` (der Tag 2026-01-01), `verluste.json` (`[]`) und `auszug_abwesend_2026-01-01.json`, den Auszug zu einer Kette ohne Blatt an diesem Tag, wie ihn `GET /v1/log/extract?chain_id=…&from=2026-01-01&to=2026-01-01` gibt: ein Nachweis `absent` der Form (iv) mit dem Kandidaten 0, einem Füller, und dem Kettentag-Blatt der Referenzwerte als Nachbarn. Die Werte sind byte-gleich mit den Referenzwerten aus Formatspezifikation 7.4.2, 7.4.4 und 7.4.5 (Tageshash `ef330d20…`, Wurzel `0adcf8f0…`); die Tagesblätter bestehen die Prüfungen (a) bis (c) aus 7.4.9, Prüfung (d) gilt für ein Testprotokoll nicht. Ein Hersteller stempelt jeden Tag bei mindestens zwei Stellen verschiedener Betreiber (Heartbeat-Spezifikation §9.9); der Referenzfall trägt einen Zeitstempel je Tag, der Verifier prüft die Zahl der Stellen nicht. Der Referenzfall ist kein Vektor und hat keine Solldatei; seine Dateien schreibt der Generator, `PINS.sha256` hält sie fest, und die Registry nennt ihn unter `vendor_log.reference_case`. Den zweiten Referenztag zeigt das Unterverzeichnis `zweiter_referenztag/` (unten).

**Zweiter Referenztag** (`zweiter_referenztag/`, Formatspezifikation 7.4.4). Die Kettentag-Wurzel `b48375ab…` des Tages 2026-01-01 ist ein beliebig gewählter Wert für die Berechnung des Baums; sie stammt aus keinen Zeilen, und zu ihr lässt sich kein Nachweis `present` bilden. Der zweite Referenztag ist deshalb ein Tag, dessen Kettentag-Blatt das aus Formatspezifikation 7.4.2 ist, sodass zu ihm ein Nachweis `present` besteht:

- **Kette und Zeilen:** Kette `3cef4d7e-4d65-41d6-912d-90d51fda8982` mit `appliance_id` `de431f78-75fd-49ae-b4bf-1cb543b635d1` (die Kette des Vektors `valid_sealed_export`), `tree_size` 42, `merkle_root` `09b2745bcdf71ea82eff8696868a267edd6de0fcb1c82cc3de0020527dc23dae` (SHA-256 von `LEDGER-BEISPIEL-WURZEL-42`), festgehalten als Lückenzeuge mit `server_ts` `2026-03-01T23:58:00.000Z` (Blatt-Hash `6ae954c9cd400501c3cb2600954f229bd90da369e5f51898f204a46beafb70ce`) und gegengezeichnet mit `2026-03-01T23:59:30.000Z` (Blatt-Hash `b1a9c17ad92c0112bd915a40e050a26a4ab1da47e34528dba51d81811ca7a6c7`).
- **Kettentag-Blatt:** Kettentag-Wurzel `cde717fc82b66d14826268735294060bbf384f0631072c73f46c52056964efd1`, Position `927d08078b4fa065e881fb6f761a660bd2b7afec5be467348492ec1c0ad055a4`, Hash des Blatts `43769b392d798a99f880ea91b7fb6ebb545c9d3f312fb6cfcf59313dba929dd0`.
- **Füller:** die Kandidaten 0 bis 3 des Tages 2026-03-01 (g(d) = `634cc011ed834c015ef269b3b8d2e9e218ad8c7cbd3216cfe2b3a3e5a8106fb4`) mit den Positionen `93028b66207660e2b221edd4de86b513e48f3463e7b08081569013811a5fbb59`, `c8d352a6c4ba66f7fcabf9654efd9de40dc923b07f206ec205b655d07c07da6d`, `1b37c8dd298c6721d3ba25317209118e53552b899cf54bac84767fc1d223ca2f` und `3824b90f571613ceb94cc09c90ce8587f7402ba1d00b600dc6c0d2156aa00f70`.
- **Tagesbaum:** Größe 5, Wurzel `bc178f7cabe3389335e08cd51dfb33f5edb4ea7749db5fea329e7c7a059bb55b`; die Kette steht am Blattindex 2, ihr Pfad ist `32c2f3257389ab53dcdc456ed3203edcd6c9ebac86c0a0070c4ed925880dced1`, `1c3377bf07b5b6e6fbe0bf143ffa968fb1e65ac0c7245586e965d1d65a4b0b93`, `a11b9e4b6bf4ac3056df539f224894a012a5e1b27d29b3e2a1427f0931e11212`.
- **Verkettung:** Auf den Tag 2026-01-01 folgen im Referenzprotokoll die Tage 2026-01-02 bis 2026-02-28 ohne Blätter (`tree_size` 0, `root` SHA-256 der leeren Bytefolge, `server_ts` 00:05:00.000Z des Folgetags, wie 2025-12-31), je mit dem Tageshash des Vortags als `prev_hash`; der Referenzfall zeigt sie nicht als Dateien, ihre Einträge folgen aus Formatspezifikation 7.4.5 (der erste hat den Tageshash `21d47c425ce6651f1d6453c8c1390daf31ee50def0f1afe2d9fde97c0bcbdced`). Das ist das Referenzprotokoll, nicht das eines Vektors: Die Vektoren tragen am 2026-01-02 je eigene Blätter (§11.1). Der Tageshash des 2026-02-28 ist `ca88598631a4e9200c0756a960e2b9b48daff57dc92f03975eca0176b62fac0b` und damit `prev_hash` des 2026-03-01.
- **Tageseintrag:** `server_ts` `2026-03-02T00:05:00.000Z`, 319 Zeichen, Tageshash `343e886a3cd81c44e063747f2cf5a96ecf779541f256a0e96102e994e7614c60`, signiert mit `vendor-log-test-001`, ein Zeitstempel des Signierers von E1 (§11.2, Seriennummer `0x3100`, `genTime` `20260302000501Z`, bezeugend).
- **Dateien:** `days/2026/2026-03-01.json` (das Tagesobjekt), `leaves/2026/2026-03-01.json` (fünf Paare), `auszug_vorhanden_2026-03-01.json`, der Auszug, wie ihn `GET /v1/log/extract?chain_id=3cef4d7e-4d65-41d6-912d-90d51fda8982&from=2026-03-01&to=2026-03-01` gibt, mit dem Nachweis `present` aus beiden Zeilen (Blattindex 2, der Pfad oben), der nach `verify_inclusion` trägt, und `zeitstempelwurzel_e1.pem`, die Wurzel von E1 (SPKI-SHA-256 `596a543ec10239b2d08e7230b38b4e5bac7531758c9b83a3d75c59acc7c604ac`).

Die Tagesblätter bestehen die Prüfungen (a) bis (c) aus 7.4.9. Mit der Wurzel von E1 für den Zweck `log` ist der Tag bezeugt; ein Prüfer außerhalb des Korpus hat keinen Grund, sie zu übergeben (Formatspezifikation 7.5.7). Die Zeilen sind die Beispielwerte aus 7.4.2, keine Quittungen eines Pakets des Korpus; der Referenztag zeigt Bildung und Nachweis, `TestZweiterReferenztag` rechnet beides nach.





## 12. Anker-Historie v2 und Verbundenheit der Spezifikation 1.10 (Gruppe `history`)

115 Vektoren der Gruppe `history` prüfen die Angabe des Prüfers aus Formatspezifikation 8.8: die Dateien der Anker-Historie (8.8.2), die Schlüssel der Seiten (8.8.3), die Schritte H0 bis H13 (8.8.4), die Einordnung der Historienwurzeln (8.8.5) und die Verbundenheit über den Zeitraum des Pakets (8.8.6), mit Seiten der Form v2 nach Heartbeat-Spezifikation §9.7 und der Angabe zur Verbundenheit nach §9.10. Sie erklären `spec_version` `1.10`, ausgenommen `history_reference_page` mit dem Paket von `valid_sealed_export` (`1.9`). Ihre Erwartungen stehen in der Registry, jede mit Grund und Abschnitt im Member `why`, abgeleitet aus dem Text der Spezifikation. Die Berichtsobjekte `anchor_history` und `affiliation` (10.10.2) nennt die Solldatei nicht; der Status der Verbundenheit steht in `evidence_level.affiliation`, die übrigen Werte stehen, wo ein Vektor von ihnen handelt, in der Beschreibung der Zeile.

### 12.1 Paket, Seiten und Prüfumgebung

**Paket.** Die meisten Vektoren tragen die einstündige Standardkette des Korpus mit eigener `chain_id` und `appliance_id`: `GENESIS` um 00:00 am 2026-01-01, zwei KI-Aufrufe, 5-Minuten-Takt, Quittungen unter `vendor-test-001` um 00:30:01 (`tree_size` 15) und 01:00:01 (`tree_size` 28), versiegelt um 01:01 mit `SEAL(shutdown)` und Sofort-Checkpoint (N = 32), geprüft um 01:03:00.500. Mit der Prüfumgebung des Korpus ergibt ein solches Paket Exit 0, Stufe 2 bis `tree_size` 28 und die Verbundenheit `not_checked`. Abweichend davon tragen die Vektoren zu Schritt H10 (§12.7) dieselbe Kette am 2026-10-05, nach dem Stichtag `legacy_boundary` 2026-10-04 der Registry; `history_receipt_unverified_not_in_history` quittiert dort unter `vendor-test-002`, das keine Anheftung belegt (`RECEIPT_UNVERIFIED`, Stufe 0). Die Vektoren eines Kettenwechsels (§12.6) nennen in `GENESIS.predecessor_chain` eine Vorgängerkette L derselben Appliance, übergeben bei `tree_size` 40; die beiden Vektoren einer Nachfolgekette (`history_successor_linked`, `history_successor_mismatch`) tragen das Standardpaket, und dessen Seite nennt die Nachfolgekette S derselben Appliance mit `successor` {S, 32}, übergeben am Ende des Pakets. `history_reference_page` trägt das Paket von `valid_sealed_export` Byte für Byte, die Vektoren zu Schritt H7 (§12.7) das Paket und den Auszug von `log_witnessed_included` oder `log_witnessed_logged_roots` (§11.3), damit der Tag 2026-01-02 des Testprotokolls mit den eingefrorenen Token von E1 nutzbar ist (mit der Prüfumgebung des Korpus Exit 0, Stufe 2 bis `tree_size` 10, §11.1).

**Seiten.** Der Generator bildet jede Seite nach Heartbeat-Spezifikation §9.7 (Form v2, JCS, druckbares ASCII) und signiert sie mit `vendor-statements-test-001`, wo die Zeile nichts anderes sagt; `owner_keys` nennt das Eigentümer-Commitment aus `appliance_id`, `chain_id` und Geräteschlüssel des Pakets. Die ehrliche Seite nennt jede Quittung des Pakets als gegengezeichnete Wurzel mit deren `server_ts`, `reference_tree_size` 28, `since_tree_size` 0 ohne Fortsetzung, keinen Fork-Befund, `known_since` `2025-12-01T00:00:00.000Z` und keinen Zeitraum, und sie ist um 01:02:00.000 ausgestellt; mit dem Paket von `valid_sealed_export` ist sie die Referenzseite aus Formatspezifikation 8.8.2 (776 Zeichen, SHA-256 `6fe4cc5f…`). Jede Datei einer Seite ist der Rumpf der Antwort mit `statement_jcs`, `server_key_id`, `server_signature` und der Lesekopie `statement`; ein Behälter `ledger-ankerhistorie/2` trägt Seiten und Auszüge. Eine zweite Seite derselben Kette ist um 01:02:05.000 ausgestellt (A und B in §12.4).

**Prüfumgebung.** `pruefer_<name>.json` übergibt die Anker des Korpus (`korpus` `true`), die Rollenliste der Version 1 aus Formatspezifikation 10.7.2 mit `--vendor-key-list` (oder eine Anheftung mit `--vendor-statement-key`, wo die Zeile es sagt), die Dateien der Anker-Historie mit `--anchor-history` und den Anforderungszeitpunkt R = `2026-01-01T00:58:00.000Z` mit `--requested-at`, den Wert der Referenzwerte aus 8.8.5 und 8.8.6 (R − W_h = 00:43:00.000). Für die Kette vom 2026-10-05 ist R = `2026-10-05T01:02:00.000Z` mit Seiten von 01:02:30, für die Vektoren zu Schritt H7 R = `2026-01-03T06:00:00.000Z` mit Seiten von 06:10 und der Wurzel von E1 mit `--vendor-log-tsa-root`. Ist mit R keine Seite des Pakets frisch verwendet, deckt die Vereinigung nach Schritt H4 nichts ab, die Lücke ist [0, ∞), und es kommt `pages_missing` hinzu; die Zeilen nennen das.

**Drei Referenzwerte.** Die Referenzwerte aus 8.8.5 nennen für `valid_sealed_export` N = 32 mit den Quittungen bei 15 und 28; die Wurzeln hinter dem Paket liegen auf `tree_size` 33 bis 35. Den Referenzwert aus 8.8.6 „keine frische Seite, ausgestellt 00:42:30 mit `known_since` 00:42:00“ zeigt `history_stale_known_since_late`, den Referenzwert „nur ein Zeitraum `former_relation` von 2025-06-01 bis 2025-12-01“ (eine Beziehung, die am 2023-12-01 endete, 24 Monate danach, beschnitten auf die Aktivierung; daraus leitet der Server keinen weiteren Zeitraum ab, Heartbeat-Spezifikation §9.10) `history_not_affiliated_period_before_24_months` (§14.3). Der eingefrorene Vektor `history_not_affiliated_period_before` trägt denselben Fall mit dem Ende 2025-11-30 nach 730 Tagen, wie der Referenzwert vor den Entscheidungen vom 26.10. lautete; der Verifier liest `until` und berechnet kein Ende, seine Erwartung gilt unverändert.

`TestAnkerhistorieVektoren`, `TestAnkerhistorieReferenzseite`, `TestAnkerhistorieSeiten`, `TestAnkerhistoriePruefumgebungen` und `TestAnkerhistorieTabellenFolgenDerErwartung` (`appliance/cmd/vektorgen`) halten Pakete, Seiten, Signaturen, Seitenregeln, Prüfumgebungen und die Tabellen gegen die Bytes und gegen `expected/`. Die Tabellen nennen zuerst Exit und Befunde mit der Prüfumgebung des Korpus (ohne Anker-Historie), dann mit `pruefer_<name>.json`.

### 12.2 Dateien, Schlüssel und Seiten (Schritte H0 bis H2)

Exit 3 ohne Befunde (`-`) heißt: unbrauchbarer Aufruf, kein Bericht (8.8.2, 10.8).

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `history_honest_role_list` | ehrliche Seite unter `vendor-statements-test-001` aus der Rollenliste der Version 1, ausgestellt 01:02:00, R = 00:58:00: frisch, Abdeckung vollständig, Wurzeln 15 und 28 gefunden; Vollständigkeit `established` bis 28, Verbundenheit `not_affiliated` | 0 | - | 0 | - |
| `history_honest_pinned` | dieselbe Seite, Schlüssel mit `--vendor-statement-key` angeheftet, keine Rollenliste: die Anheftung belegt die Seite ohne Gültigkeitsfenster | 0 | - | 0 | - |
| `history_reference_page` | das Paket von `valid_sealed_export` Byte für Byte mit der Referenzseite aus 8.8.2 (776 Zeichen, SHA-256 `6fe4cc5f…`, Eigentümer-Commitment `d0184bb5…`) | 0 | - | 0 | - |
| `history_container` | die ehrliche Seite in einem Behälter `ledger-ankerhistorie/2` mit leerem `vendor_log` | 0 | - | 0 | - |
| `history_pages_duplicate` | dieselbe Seite zweimal in einem Behälter und einmal als Datei: eine Seite (H1, `supplied` 3, `distinct` 1) | 0 | - | 0 | - |
| `history_statement_copy_ignored` | die unsignierte Lesekopie `statement` nennt `known_since` `null` und einen offenen Zeitraum `vendor`; gelesen wird nur `statement_jcs`: `not_affiliated` | 0 | - | 0 | - |
| `history_pair_bad_signature_beside_good` | eine Seite mit zwei Paaren: `vendor-statements-test-001` trägt, `vendor-statements-test-002` nicht: die Seite ist verwendet, das Paar unter dem belegten Schlüssel ergibt `signature`; Vollständigkeit `established` | 0 | - | 1 | `ANCHOR_HISTORY_DEFECTIVE` |
| `history_pair_other_role_beside_good` | eine Seite mit den Paaren unter `vendor-statements-test-001` und unter dem Gegenzeichnungsschlüssel `vendor-test-001`, beide tragen: verwendet, kein Befund | 0 | - | 0 | - |
| `history_key_not_established` | Seite unter `vendor-statements-test-002`, angeheftet ist nur `vendor-statements-test-001`, keine Rollenliste: `key_not_established`; ohne frische verwendete Seite dazu `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_key_countersigning` | Seite unter dem Gegenzeichnungsschlüssel `vendor-test-001` (angeheftet, in der Rollenliste mit `countersigning`): `key_other_role`, dazu `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_key_update_manifest` | Seite unter `vendor-update-manifest-test-001` (Rolle `update_manifest`): `key_other_role`, dazu `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_key_pin_dropped` | Bescheidschlüssel `vendor-statements-pin-1` mit dem Publikey von `vendor-update-manifest-test-001` angeheftet: die Anheftung entfällt; die Seite nennt ihre `key_id`: `key_not_established`, dazu `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_signature_defective` | die ehrliche Seite, eine Hex-Ziffer der Signatur geändert: `signature`, dazu `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_DEFECTIVE`, `ANCHOR_HISTORY_UNVERIFIED` |
| `history_page_v1` | Seite der Form v1 mit den Wurzeln des Pakets unter `vendor-statements-test-001`: `not_v2`, dazu `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_page_v1_countersigning` | dieselbe Seite der Form v1 unter `vendor-test-001`, wie im Doppelbetrieb: `key_other_role` (Nummer 1 vor Nummer 4), dazu `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_page_other_kind` | ein Lizenzbescheid `ledger.license_statement.v1` unter `vendor-statements-test-001` als Datei der Anker-Historie: `not_v2`, dazu `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_page_not_json` | `statement_jcs` ist Text, kein JSON, signiert unter einem belegten Schlüssel: kein Exit 3, `page_rules`, dazu `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION`, `ANCHOR_HISTORY_UNVERIFIED` |
| `history_page_not_jcs` | `statement_jcs` mit einem Leerzeichen nach dem ersten Komma: nicht die eigene JCS-Form, `page_rules`, dazu `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION`, `ANCHOR_HISTORY_UNVERIFIED` |
| `history_page_extra_member` | Seite mit einem Member `comment`: `page_rules`, dazu `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION`, `ANCHOR_HISTORY_UNVERIFIED` |
| `history_page_time_form` | `server_ts` der Seite `2026-01-01T01:02:00Z` ohne Millisekunden: `page_rules`, dazu `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION`, `ANCHOR_HISTORY_UNVERIFIED` |
| `history_page_rules_known_since` | `known_since` 01:02:01 nach `server_ts` 01:02:00 (Seitenregel 9): `page_rules`, dazu `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION`, `ANCHOR_HISTORY_UNVERIFIED` |
| `history_page_rules_periods_adjoining` | zwei aneinanderstoßende Zeiträume mit denselben `bases` (Seitenregel 10): `page_rules`, dazu `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION`, `ANCHOR_HISTORY_UNVERIFIED` |
| `history_page_rules_reference` | `reference_tree_size` 15 neben einer gegengezeichneten Wurzel bei 28 (Seitenregel 6): `page_rules`, dazu `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION`, `ANCHOR_HISTORY_UNVERIFIED` |
| `history_page_rules_beside_honest` | ehrliche Seite und eine zweite Seite der Kette C, deren Wurzeln fallen (Seitenregel 3): `page_rules`, hindernd: Vollständigkeit `partial` (`contradiction`) | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_page_rules_other_chain` | ehrliche Seite und eine regelwidrige Seite einer anderen Kette: `page_rules`, nicht hindernd: Vollständigkeit `established` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_root_ts_legacy_form` | Wurzel 15 mit `server_ts` `2026-01-01T00:30:01Z`, der gespeicherten Zeichenfolge einer früher festgehaltenen Wurzel: zulässig | 0 | - | 0 | - |
| `history_key_expired` | Rollenliste mit `gueltig_bis` 01:00:00 für `vendor-statements-test-001`, Seite 01:02:00: `key_not_valid`, dazu `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_key_revoked_before_issue` | Rollenliste Version 2 widerruft `vendor-statements-test-001` ab 00:00, vor der Seite von 01:02:00: `key_not_valid`, dazu `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_key_revoked_fresh` | Rollenliste Version 2 widerruft `vendor-statements-test-001` ab 01:02:30, nach der Seite; die Seite ist frisch: verwendet | 0 | - | 0 | - |
| `history_key_revoked_no_request_time` | derselbe Widerruf ohne `--requested-at`: `signing_time_not_proven`; Vollständigkeit `no_request_time` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_key_revoked_stale` | derselbe Widerruf, Seite von 00:40:00 vor R − W_h: `signing_time_not_proven`, dazu `issued_before_request` und `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_key_revoked_pinned_fresh` | `vendor-statements-test-001` angeheftet, die Rollenliste widerruft ihn ab 00:00 vor der Seite: die Anheftung gilt ohne Fenster, die Seite ist frisch: verwendet | 0 | - | 0 | - |
| `history_key_planned_change_no_request_time` | Rollenliste mit `gueltig_bis` 02:00 (geplanter Wechsel), ohne R: verwendet (`used_unjudged`); Vollständigkeit `no_request_time` | 0 | - | 0 | - |
| `history_other_chain` | Seite einer anderen `chain_id`, mit nichts verknüpft: `other_chain`, dazu `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_owner_differs` | Seite der Kette C mit dem Eigentümer-Commitment einer anderen `appliance_id`: `owner_differs`, dazu `pages_missing`; Vollständigkeit `owner_differs` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_owner_differs_beside_honest` | ehrliche Seite und eine Seite eines anderen Geräts: `owner_differs`, nicht hindernd: Vollständigkeit `established` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_owner_keys_superset` | `owner_keys` mit dem Commitment des Geräteschlüssels des Pakets und dem eines weiteren Schlüssels: ein gemeinsames Element genügt | 0 | - | 0 | - |
| `history_container_extra_member` | Behälter mit einem Member `kommentar` | 0 | - | 3 | - |
| `history_container_format_other` | Objekt mit `format` `ledger-ankerhistorie/1` | 0 | - | 3 | - |
| `history_container_no_pages` | Behälter mit `pages` `[]` | 0 | - | 3 | - |
| `history_container_extract_grammar` | Behälter mit einem eingebetteten Auszug, der ein Member `kommentar` trägt | 0 | - | 3 | - |
| `history_page_member_missing` | Datei einer Seite ohne das Member `statement` | 0 | - | 3 | - |
| `history_page_key_id_grammar` | `server_key_id` `vendor statements test 001` (Leerzeichen) | 0 | - | 3 | - |
| `history_page_signature_form` | `server_signature` mit 126 Hex-Ziffern | 0 | - | 3 | - |
| `history_page_jcs_empty` | `statement_jcs` ist die leere Zeichenkette | 0 | - | 3 | - |
| `history_page_duplicate_member` | Datei einer Seite mit dem Member `server_key_id` zweimal (gleicher Wert): kein I-JSON | 0 | - | 3 | - |

### 12.3 Ausstellung und Abdeckung (Schritte H3, H4)

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `history_issued_before_request` | eine Seite von 00:40:00 mit der Wurzel 15, vor R − W_h: `issued_before_request` und `pages_missing`; Wurzel 15 gefunden, Verbundenheit `not_determined` (`statement_does_not_cover_package`) | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_stale_known_since_late` | eine Seite von 00:42:30 mit `known_since` 00:42:00: `statement_does_not_cover_package` vor `known_range_too_short`; dazu `issued_before_request` und `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_archive_pages` | ältere Seite von 00:40:00 neben der frischen: Hinweis `archive_pages`, kein Befund | 0 | - | 0 | - |
| `history_coverage_split` | zwei frische Seiten [0, 16) und [16, ∞): Abdeckung `complete` | 0 | - | 0 | - |
| `history_coverage_overlap` | drei frische Seiten [0, 16), [0, 20) und [20, ∞) mit verschobenen Schnittstellen: Abdeckung `complete` | 0 | - | 0 | - |
| `history_coverage_gap` | nur eine Seite mit `since_tree_size` 20: Lücke [0, 20), `pages_missing`; Vollständigkeit `partial`, Verbundenheit `not_determined` (`history_pages_missing`) | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_coverage_gap_no_request_time` | dieselbe Seite ohne R: Abdeckung nur zur Auskunft, kein Befund; Verbundenheit `not_determined` | 0 | - | 0 | - |

### 12.4 Seiten untereinander (Schritt H5)

A ist die Seite von 01:02:00, B die von 01:02:05, beide frisch, wo die Zeile nichts anderes sagt.

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `history_root_time_differs` | B nennt Wurzel 15 mit `server_ts` 00:30:02 statt 00:30:01: `root_time_differs` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_root_dropped` | Wurzel 15 von A fehlt auf B: `root_dropped` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_root_withheld` | A nennt nur Wurzel 28, B auch Wurzel 15 von 00:30:01, vor A.`server_ts` − W_h: `root_withheld` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_root_recorded_in_band` | B nennt zusätzlich die gemeldete Wurzel 24 von 00:50:01, nach A.`server_ts` − W_h: kein Grund | 0 | - | 0 | - |
| `history_fork_dropped` | Fork-Befund bei 20 auf A, B ohne ihn und mit `forks_omitted` 0: `fork_dropped` und `fork_listed` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION`, `ANCHOR_HISTORY_FORK` |
| `history_affiliation_narrowed` | A mit offenem Zeitraum `common_control`, B beendet ihn um 01:00:00, vor A: `affiliation_narrowed`; `affiliated`, `contradictory` `true` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_affiliation_ended_after_issue` | B beendet den offenen Zeitraum von A um 01:02:03, nach A: kein Grund; `affiliated` | 0 | - | 0 | - |
| `history_affiliation_split_view` | A mit offenem Zeitraum, B fünf Sekunden später ohne Zeitraum: `affiliation_narrowed` (geteilte Sicht); `affiliated` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_affiliation_older_page` | ältere Seite von 00:10:00 mit offenem Zeitraum, H* von 01:02:00 ohne: `affiliation_narrowed`; der Zeitraum endet um 00:10:00: `not_affiliated`, `contradictory` `true` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_affiliation_withheld` | B nennt einen Zeitraum `former_relation` 2025-06-01 bis 2025-11-30, eingetragen lange vor A, den A nicht zeigt: `affiliation_withheld` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_affiliation_added_late` | B nennt einen offenen Zeitraum `participation` ab 00:50:00, eingetragen um 01:02:02 nach A: kein Grund; `affiliated` | 0 | - | 0 | - |
| `history_affiliation_merged` | A mit 16 Zeiträumen, B fasst nach einem 17. die frühesten zusammen (`merged` `true`): Erweiterung, kein Grund; `affiliated` | 0 | - | 0 | - |
| `history_affiliation_merged_gap` | A mit 16 Zeiträumen `participation`, je drei Tage jeder Woche ab 2025-06-01 mit Lücken dazwischen, alle eingetragen am 2025-06-01; B fasst nach einem 17. die beiden frühesten über die Lücke zusammen (`merged` `true`, `recorded_ts` mehr als W_h vor A): ein zusammengefasster Zeitraum ergibt `affiliation_withheld` nie, kein Grund; `affiliated`, `contradictory` `false` | 0 | - | 0 | - |
| `history_affiliation_gap_not_merged` | dieselben Seiten, der erste Zeitraum von B mit `merged` `false`: in der Lücke nennt B eine Verbundenheit, eingetragen mehr als W_h vor A, A nicht: `affiliation_withheld`, hindernd; `affiliated`, `contradictory` `true` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_known_since_narrowed` | B verlegt `known_since` auf 00:45:00, vor A.`server_ts`: `known_range_narrowed`; `not_determined` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_known_since_null_after_takeover` | B nennt `known_since` `null`, etwa nach einer Übernahme: kein Grund; `not_determined` | 0 | - | 0 | - |
| `history_known_since_after_issue` | B verlegt `known_since` auf 01:02:01, nach A.`server_ts`: kein Grund; `not_determined` | 0 | - | 0 | - |
| `history_owner_keys_dropped` | A mit zwei Eigentümer-Commitments, B mit einem: `owner_keys_dropped` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_succession_changed` | A nennt einen Nachfolger bei 32, B keinen: `succession_changed` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_reference_decreases` | B mit `reference_tree_size` 15 nach den 28 von A: `reference_decreases` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |

### 12.5 Einordnung der Historienwurzeln (Schritte H6, H8, Formatspezifikation 8.8.5)

Eine abweichende Wurzel ist eine Wurzel der Seite, deren `merkle_root` nicht `root(t)` des Pakets ist. Nur eine gegengezeichnete oder als Lückenzeuge festgehaltene Wurzel, die vor R − W_h festgehalten ist, ergibt `MERKLE_INCONSISTENT`; eine nur gemeldete nie.

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `history_root_differs_before_band` | gegengezeichnete abweichende Wurzel bei 20 mit e = 00:42:59.999: `MERKLE_INCONSISTENT` | 0 | - | 2 | `MERKLE_INCONSISTENT` |
| `history_root_differs_in_band` | gegengezeichnete abweichende Wurzel bei 21 mit e = 00:43:00.000 (Grenze im Band): `history_root_differs` | 0 | - | 1 | `ANCHOR_HISTORY_FORK` |
| `history_root_beyond_before_band` | gegengezeichnete Wurzel bei 33 hinter dem Paket mit e = 00:42:59.999: `MERKLE_INCONSISTENT`, Hinweis `package_ended_before_request` | 0 | - | 2 | `MERKLE_INCONSISTENT` |
| `history_root_beyond_in_band` | gegengezeichnete Wurzeln bei 34 (e = 00:43:00.000) und 35 (e = R) hinter dem Paket: kein Befund, Hinweis `recent_roots_not_found` | 0 | - | 0 | - |
| `history_band_no_request_time` | die Wurzeln 20, 21, 33, 34 und 35 ohne R: 20 und 21 `history_root_differs`, 33 bis 35 `beyond_package_unjudged` | 0 | - | 1 | `ANCHOR_HISTORY_FORK` |
| `history_reported_root_differs` | nur gemeldete abweichende Wurzel bei 20 mit e = 00:42:59.999: `history_root_differs`, nie Exit 2 | 0 | - | 1 | `ANCHOR_HISTORY_FORK` |
| `history_reported_root_beyond` | nur gemeldete Wurzel bei 33 hinter dem Paket mit e = 00:42:59.999: `reported_root_beyond_package` | 0 | - | 1 | `ANCHOR_HISTORY_FORK` |
| `history_gap_witness_then_countersigned` | abweichende Wurzel bei 20, Lückenzeuge um 00:42:59.999, gegengezeichnet um 00:50:00: e = 00:42:59.999, `MERKLE_INCONSISTENT` | 0 | - | 2 | `MERKLE_INCONSISTENT` |
| `history_reported_then_countersigned` | abweichende Wurzel bei 20, gemeldet um 00:40:00, gegengezeichnet um 00:43:00: e = 00:43:00.000, `history_root_differs` | 0 | - | 1 | `ANCHOR_HISTORY_FORK` |
| `history_reported_root_also_auditor` | nur gemeldete abweichende Wurzel bei 20, dieselbe Wurzel auch mit `--expect-root`: Regel aus 10.8, `MERKLE_INCONSISTENT` | 0 | - | 2 | `MERKLE_INCONSISTENT` |

### 12.6 Fork-Befunde, Übergabe und Kettenwechsel (Schritt H9)

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `history_fork_listed` | Fork-Befund bei 20 auf der Seite: `fork_listed` | 0 | - | 1 | `ANCHOR_HISTORY_FORK` |
| `history_forks_omitted` | `forks_omitted` 2: `forks_omitted` | 0 | - | 1 | `ANCHOR_HISTORY_FORK` |
| `history_root_beyond_handover` | Nachfolger bei 20, gegengezeichnete Wurzel 28 dahinter: `root_beyond_handover`, Hinweis `package_beyond_handover` | 0 | - | 1 | `ANCHOR_HISTORY_FORK` |
| `history_reported_beyond_handover` | Nachfolger bei 28, gemeldete Wurzel 31 = root(31): Hinweise `reported_beyond_handover` und `package_beyond_handover`, kein Befund | 0 | - | 0 | - |
| `history_succession_linked` | Kettenwechsel L → C bei 40, Seiten beider Ketten, dieselbe Verbundenheit: verknüpfte Seite verwendet; Paket `not_affiliated`, L unter `linked` `affiliated` | 0 | - | 0 | - |
| `history_succession_mismatch` | C nennt `predecessor` {L, 39}, L `successor` {C, 40}: `succession_mismatch` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_predecessor_beyond_handover` | Seite von L mit gegengezeichneter Wurzel 41 hinter der Übergabe bei 40: `predecessor_beyond_handover`, Hinweis `reported_beyond_handover` | 0 | - | 1 | `ANCHOR_HISTORY_FORK` |
| `history_linked_history_not_supplied` | nur die Seite von C mit `predecessor` {L, 40}: Hinweis `linked_history_not_supplied` | 0 | - | 0 | - |
| `history_predecessor_differs_from_genesis` | die Seite von C nennt eine andere Vorgängerkette als `GENESIS`: Hinweise `predecessor_differs_from_genesis` und `linked_history_not_supplied` | 0 | - | 0 | - |
| `history_linked_contradiction_not_blocking` | zwei Seiten von L, die spätere ohne die Wurzel 20: `root_dropped` zwischen verknüpften Seiten, nicht hindernd | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_linked_affiliation_narrowed` | die Seite von C und eine Seite von L mit offenem Zeitraum `common_control`, eine spätere Seite von L ohne ihn: `affiliation_narrowed` zwischen verknüpften Seiten, nicht hindernd: Vollständigkeit `established`; Paket `affiliated` mit `contradictory` `false`, L unter `linked` `affiliated` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_successor_linked` | Standardpaket; seine Seite nennt `successor` {S, 32}, die Seite von S `predecessor` {C, 32}, das Eigentümer-Commitment für S und keine Wurzel: verknüpfte Seite verwendet, `relation` `successor`, kein Grund; Paket und S `not_affiliated` | 0 | - | 0 | - |
| `history_successor_mismatch` | die Seite des Pakets nennt `successor` {S, 32}, die Seite von S `predecessor` {C, 31}: `succession_mismatch` (S als Nachfolgekette), hindernd | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |

### 12.7 Herstellerprotokoll, Quittungen und Vollständigkeit (Schritte H7, H10, H11)

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `history_log_container` | Seite und Auszug von `log_witnessed_included` in einem Behälter, Seite und Nachweis stimmen überein: kein Befund | 0 | - | 0 | - |
| `history_log_mismatch` | Seite nennt Wurzel 5 mit `server_ts` 23:55:02, der Nachweis 23:55:01: `log_mismatch` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_log_root_missing` | Seite ohne die Wurzel 5 des Nachweises: `log_root_missing` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_log_gap_witness_times` | Paket und Auszug von `log_witnessed_logged_roots`, Seite mit dem Lückenzeugen 1 von 23:50:01: `gap_witness_time_differs` und `log_root_missing` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION`, `LOGGED_ROOT_MISMATCH` |
| `history_receipts_in_history` | Kette vom 2026-10-05 nach dem Stichtag: beide Quittungen `in_history` | 0 | - | 0 | - |
| `history_receipt_server_ts_differs` | Seite nennt Wurzel 15 mit 00:30:00.900, die Quittung 00:30:01.000: `in_history` und `server_ts_differs`, kein Befund | 0 | - | 0 | - |
| `history_receipt_not_in_history` | Seite ohne die Wurzel der belegten Quittung von 00:30:01: `receipt_not_in_history` | 0 | - | 1 | `ANCHOR_HISTORY_CONTRADICTION` |
| `history_receipt_not_covered` | Seite ohne Wurzel 28, ausgestellt weniger als W_h nach deren Quittung: `not_covered`, kein Befund | 0 | - | 0 | - |
| `history_receipt_unverified_not_in_history` | Quittungen unter `vendor-test-002`, das keine Anheftung belegt; Seite ohne Wurzel 15: Hinweis `receipt_roots_unverified_not_in_history`, Stufe 1 über die Anker-Historie | 1 | `RECEIPT_UNVERIFIED` | 1 | `RECEIPT_UNVERIFIED` |
| `history_no_root_found` | frische vollständige Seite ohne Wurzeln: Vollständigkeit `partial` (`no_root_found`) | 0 | - | 0 | - |

### 12.8 Verbundenheit (Schritt H12, Formatspezifikation 8.8.6)

Zeitraum des Pakets von 00:30:01 bis R = 00:58:00, zwei belegte Quittungen, H* frisch, wo die Zeile nichts anderes sagt (Referenzwerte aus 8.8.6).

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `history_affiliated_open` | offener Zeitraum `common_control` ab 2025-06-01: `affiliated`, 2 von 2 Quittungen im Zeitraum | 0 | - | 0 | - |
| `history_not_affiliated_period_before` | nur ein Zeitraum `former_relation` 2025-06-01 bis 2025-11-30 (Ende nach 730 Tagen, vor den Entscheidungen vom 26.10.; mit 24 Monaten §14.3): `not_affiliated`, Zeitraum außerhalb | 0 | - | 0 | - |
| `history_known_since_after_span` | `known_since` 00:45:00: `not_determined` (`known_range_too_short`) | 0 | - | 0 | - |
| `history_known_since_null_open_period` | `known_since` `null` mit offenem Zeitraum: `affiliated` | 0 | - | 0 | - |
| `history_affiliated_from_0050` | offener Zeitraum `participation` ab 00:50:00: `affiliated`, 1 von 2 Quittungen im Zeitraum | 0 | - | 0 | - |
| `history_vendor_itself` | offener Zeitraum `vendor`: `affiliated`, `vendor_itself` `true` | 0 | - | 0 | - |
| `history_affiliated_no_request_time` | offener Zeitraum ohne R: `span_to` = `as_of`, `affiliated` | 0 | - | 0 | - |
| `history_affiliated_stale_page` | nur eine ältere Seite von 00:40:00 mit offenem Zeitraum: `affiliated` (eine ältere Seite trägt `affiliated`, nie `not_affiliated`), dazu `issued_before_request` und `pages_missing` | 0 | - | 1 | `ANCHOR_HISTORY_UNVERIFIED` |
| `history_affiliation_ends_in_span` | Zeitraum `shared_management` bis 00:40:00, innerhalb des Zeitraums des Pakets: `affiliated`, 1 von 2 Quittungen | 0 | - | 0 | - |

## 13. Beweisstufe und Berichtsangaben der Spezifikation 1.10 (Gruppe `evidence`)

26 Vektoren der Gruppe `evidence` prüfen die Beweisstufe aus Formatspezifikation 10.9 und das Berichtsobjekt `evidence_level` (10.10.2): die Stufen 0 bis 3 mit Reichweite, Verlauf und den Bedingungen, die für die nächste Stufe fehlen, die Gründe der Tabelle aus 10.9.4 und die Hinweise aus 10.9.6, die kein früherer Vektor zeigt, die Zustände `chain_invalid` und `format_error` (10.9.2) und die Bedingung (7), den zweiten Weg zu Stufe 3, mit und ohne Anrechnung. Sie erklären `spec_version` `1.10`. Ihre Erwartungen stehen in der Registry, jede mit Grund und Abschnitt im Member `why`, abgeleitet aus dem Text der Spezifikation. Die Solldatei nennt die Beweisstufe in der Kurzform aus §3; Reichweite und Zählwert je Bedingung, `basis` und die Anker stehen, wo ein Vektor von ihnen handelt, in der Beschreibung der Zeile. `next` folgt aus Stufe und Gründen (10.9.5): Bei einer Stufe L unter 3 nennt `missing` die Bedingungen der Stufe L + 1, deren Grund nicht `null` ist, in der Reihenfolge der Registry; für Stufe 3 gelten (4) und (7) als eine Bedingung: Liegt keine von beiden vor, nennt `missing` beide, liegt eine vor, keine von beiden.

### 13.1 Pakete und Prüfumgebungen

**Pakete.** Zwölf Vektoren tragen das Paket eines Vektors der Gruppe `log` Byte für Byte unter eigenem Namen, damit die eingefrorenen Token von E1 gelten (§11.2): das von `log_witnessed_time_anchor_qualified` (15 Einträge, Quittungen bei `tree_size` 5 und 11, ein `TIME_ANCHOR` des Signierers von E1 mit qcStatements über den Checkpoint von `tree_size` 5, `genTime` 23:55:01 am 2026-01-02; sein Tag 2026-01-02 trägt einen bezeugenden Zeitstempel desselben Signierers von 00:05:01 am 2026-01-03), das von `log_witnessed_included` und das von `log_witnessed_qualified_stamp` (je 14 Einträge, Quittungen bei 5 und 10, §11.1). Mit der Prüfumgebung des Korpus ergibt das erste Exit 1 mit `TIME_ANCHOR_UNVERIFIED` und Stufe 2 bis 11, die beiden anderen Exit 0 und Stufe 2 bis 10. Die übrigen Vektoren tragen die einstündige Standardkette des Korpus mit eigener `chain_id` (N = 32, Quittungen bei 15 und 28, versiegelt um 01:01, geprüft zwei Minuten danach; Stufe 2 bis 28), geändert, wo die Zeile es sagt; die Vektoren mit einem Zeitzeugen von E2 tragen ihn 700 ms nach dem Checkpoint von 00:40 (`tree_size` 20; N = 33, Quittungen bei 15 und 29) wie die Gruppe `timestamp`. `evidence_receipts_after_check_time` trägt das Skript der Gruppe `log` (§11.1), geprüft um 23:35 am 2026-01-02.

**Prüfumgebung.** Jede Prüfumgebung enthält die des Korpus (`korpus` `true`), damit die Monotonie aus 10.9.7 gegen den Lauf mit der Prüfumgebung des Korpus geprüft werden kann. Die Vektoren auf dem Paket von `log_witnessed_time_anchor_qualified` übergeben, wo die Zeile nichts anderes sagt, dessen Auszug, die Wurzel von E1 mit `--vendor-log-tsa-root` und in `--tsa-qualified-roots` (benannt ab 2025-01-01), die Rollenliste der Version 1, den Anforderungszeitpunkt R = `2026-01-03T06:00:00.000Z` und die ehrliche Seite der Anker-Historie von 06:10 mit beiden Quittungen (§12.1). `TestBeweisstufeVektoren`, `TestEinmaligeStelleE2Eingefroren`, `TestBeweisstufeEigenschaften`, `TestBeweisstufeMonotonie`, `TestBeweisstufeAbdeckung` und `TestBeweisstufeTabellenFolgenDerErwartung` (`appliance/cmd/vektorgen`) halten Pakete, die eingefrorene Eingabe von E2, die Eigenschaften 1 bis 5 aus 10.9.7 an jeder Solldatei, die Monotonie zwischen beiden Prüfumgebungen, die Abdeckung der Gründe, Hinweise, Stufen und Zustände und die Tabellen gegen die Bytes und gegen `expected/`.

### 13.2 Die Zeitstempelstelle E2

Ein Zeitzeuge über den Checkpoint einer neuen Kette und ein Tageszeitstempel, um dessen Erweiterungen es einem Vektor geht, brauchen Token, die kein eingefrorenes Token von E1 deckt. Sie stammen von einer zweiten Zeitstempelstelle mit verworfenen Schlüsseln, E2, entstanden wie E1 (§11.2) in einem einzigen Lauf von `vektorgen -einmalige-stelle appliance/cmd/vektorgen/eingefroren -stelle E2`. Ihre Eingabe `appliance/cmd/vektorgen/eingefroren/zeitstempelstelle_e2.json` (Format `ledger-testkorpus-zeitstempelstelle/1`) nennt genau drei Zertifikate und die Token, keinen Schlüssel; der Generator kopiert sie unverändert nach `zeitstempelstelle_e2.json`:

- `wurzel`: „Testkorpus Zeitstempelwurzel E2 (Schluessel verworfen)“, Ed25519, selbst signiert, Seriennummer 1, gültig von 2025-01-01 bis 2036-01-01, basicConstraints cA und keyUsage keyCertSign, beide kritisch; SHA-256 des Zertifikats `0ab126bd732ce17cf18945a9fda9afa37c82e22e0b838cb61a6ca2cc08585f63`, SPKI-SHA-256 `9c80d27b8fab6d67528271f45a739e58d68876bc1ab88f2fd7cca181a3198a15`.
- `signierer`: „Testkorpus Zeitstempelstelle E2 (Schluessel verworfen)“, Seriennummer 2, gültig von 2025-06-01 bis 2031-01-01, keyUsage digitalSignature und extKeyUsage genau `id-kp-timeStamping`, beide kritisch; SPKI-SHA-256 `3bb8df0932f16a6a2b736ebb42d16d30799ea8ffbe1bc35290ce76c7f1e1318c`.
- `signierer_qs`: „Testkorpus Zeitstempelstelle E2 qcStatements (Schluessel verworfen)“, Seriennummer 3, sonst wie `signierer`; SPKI-SHA-256 `b0289719598844828b4cb418feee9700a3b7bd9a503710796a3818bc14a1801e`.
- `token`: sieben Token, je unter dem Namen `<Vektor>/<Bezeichnung>`, Seriennummern `0x4001` bis `0x4007`: die Tageszeitstempel von `evidence_log_stamp_extensions_unusable` (qcStatements mit `esi4-qtstStatement-1` und eine unbekannte kritische Erweiterung) und `evidence_log_stamp_statement_malformed` (qcStatements mit `SEQUENCE { INTEGER 1 }`) über den Tageseintrag von `log_witnessed_included`, die Zeitzeugen von `evidence_witness_extensions_unusable` (wie der erste Tageszeitstempel), `evidence_witness_certificate_not_bound` (qcStatements, signingCertificateV2 mit dem Hash der Wurzel der Teststelle), `evidence_witness_statement_malformed` (zwei: qcStatements nicht lesbar, ohne Erweiterungen) und `evidence_level_1_time_witness` (ohne Erweiterungen).

Für E2 gilt alles, was §11.2 für E1 sagt: Ihre Schlüssel stehen in keiner Datei und nicht in `published_test_keys`, ihre Token lassen sich nicht erneut ausstellen, jeder andere Lauf des Generators hält jedes Token gegen seine Anforderung und bricht bei einem fehlenden, abweichenden oder von keinem Vektor verlangten Token ab, und ihre Wurzel ist nie die Wurzel eines Prüfers; sie zählt nur, wo `pruefer_<name>.json` sie übergibt.

### 13.3 Vektoren

Die Tabellen nennen zuerst Exit und Befunde mit der Prüfumgebung des Korpus, dann mit `pruefer_<name>.json`. In der Beschreibung steht der Verlauf als „Stufe für `first_seq` bis `last_seq`“ und `basis` in eckigen Klammern; (1) bis (7) sind die Bedingungen aus 10.9.1.

**Stufe 3, Verlauf und Neutralität** (10.9.1, 10.9.5, 10.9.7)

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `evidence_level_3` | Paket und Prüfumgebung aus §13.1: (1), (4), (5) und (7) bis 5, (2), (3) und (6) bis 11; r1 = r2 = 11, r3 = 5: Stufe 3 bis 5; 3 für 1 bis 5 [`time_witness_qualified`, `receipts_logged`, `log_day_qualified`], 2 für 6 bis 11, 0 für 12 bis 15; `next` `null`; `qualified_time` über (4) bei `tree_size` 5, `latest` `2026-01-02T23:55:01.000Z` (der Zeitzeuge ist früher als der Tageszeitstempel); Hinweise `published_test_key_credited`, `receipts_pending_log` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `evidence_level_3_four_segments` | dazu die erwartete Wurzel `13:<root(13)>` des Prüfers: (2) bis 13 mit den Quellen `auditor` und `anchor_history`, (6) bleibt bei 11; 3 für 1 bis 5, 2 für 6 bis 11, 1 für 12 bis 13 [`expected_root_found`], 0 für 14 bis 15 | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `evidence_level_3_affiliated` | die Seite mit einem offenen Zeitraum `common_control` ab 2025-06-01: `affiliated`; Stufe, Reichweite und Verlauf wie bei `evidence_level_3` (Neutralität) | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `evidence_level_2_without_log` | dieselben Anker und dieselbe Seite ohne Auszug und ohne Wurzel für das Protokoll: (5) und (7) `vendor_log_not_supplied`, kein Hinweis `receipts_pending_log`; Stufe 2 bis 11, `next` `{3, all, [receipts_logged]}` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |

**Bedingung (4): Zeitraum und Wurzel aus dem Paket** (10.8, 10.9.1, 10.9.4)

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `evidence_qualified_window_from` | E1 als qualifiziert benannt erst ab `2026-01-03T00:00:00Z`: Der Zeitzeuge liegt davor, (4) `outside_qualified_window`; (1) liegt vor, denn für den Zweck `chain` zählt die Wurzel immer; der Tageszeitstempel von 00:05:01 liegt im Zeitraum, (7) liegt vor, der zweite Weg zu Stufe 3: Stufe 3 bis 5; 3 für 1 bis 5 [`receipts_logged`, `log_day_qualified`], 2 für 6 bis 11, 0 für 12 bis 15; `qualified_time` über (7) bei `tree_size` 5 | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `evidence_qualified_window_until` | qualifiziert ab 2025-01-01 mit `qualifiziert_bis` `2026-01-02T23:55:01Z`, gleich dem `genTime` des Zeitzeugen (obere Grenze ausgeschlossen): (4) und (7) `outside_qualified_window`, (1) liegt vor; Stufe 2 bis 11 | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `evidence_qualified_root_in_package` | das Paket mit der Wurzel von E1 in `keys/tsa/zeitstempelwurzel_e1.pem`: (1) liegt vor, Hinweis `tsa_root_in_package`; (4) `qualified_root_in_package`; (7) kennt diese Stufe nicht und liegt vor, der zweite Weg zu Stufe 3: Stufe 3 bis 5; 3 für 1 bis 5 [`receipts_logged`, `log_day_qualified`], 2 für 6 bis 11, 0 für 12 bis 15 | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |

**Bedingung (7): Tageszeitstempel** (7.4.6, 7.5.7, 10.9.4)

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `evidence_log_stamp_late` | Paket und Auszug von `log_witnessed_qualified_stamp` (ein bezeugender und ein verspäteter Zeitstempel von `2026-01-05T00:00:00Z`, beide mit qcStatements), E1 für das Protokoll und als qualifiziert benannt erst ab `2026-01-04T00:00:00Z`: Das Tripel mit dem bezeugenden Zeitstempel endet bei `outside_qualified_window`, das mit dem verspäteten bei `qualified_day_stamp_late`, der Stufe, an der das am weitesten gekommene Tripel scheitert; (5) bis 5 | 0 | - | 0 | - |
| `evidence_log_root_not_chained` | Paket und Auszug von `log_witnessed_included`, E1 für das Protokoll, die Wurzel der Teststelle für das Protokoll und als qualifiziert benannt: Der Tag ist durch E1 bezeugt, die einzige Wurzel mit beiden Zwecken ist die Testwurzel: (7) `not_chained_to_qualified_log_root` | 0 | - | 0 | - |
| `evidence_log_stamp_published_key` | derselbe Tag mit dem Zeitstempel von E1 und einem der Teststelle (`genTime` 00:05:02, nicht bestätigt, kein Befund), Wurzeln wie zuvor: (7) `published_test_key` | 0 | - | 0 | - |
| `evidence_log_stamp_extensions_unusable` | derselbe Tag nur mit einem Zeitstempel von E2 mit qcStatements und einer unbekannten kritischen Erweiterung (Regel QS: unbrauchbar), E2 für das Protokoll und als qualifiziert benannt: Der Zeitstempel ist bestätigt und bezeugt den Tag, (5) bis 5; (7) `token_extensions_unusable` | 0 | - | 0 | - |
| `evidence_log_stamp_statement_malformed` | derselbe Tag mit dem Zeitstempel von E1 ohne qcStatements und einem von E2 mit nicht lesbarem qcStatements, beide Wurzeln für das Protokoll und als qualifiziert benannt: beide Tripel scheitern an der Stufe `qualified_statement`, mit beiden Ergebnissen: (7) `qualified_statement_malformed` | 0 | - | 0 | - |

**Bedingungen (1) und (4): Zeitzeugen von E2** (7.3, 7.5.6, 10.9.4)

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `evidence_witness_extensions_unusable` | Zeitzeuge bei `tree_size` 20 mit einem Token von E2 mit qcStatements und einer unbekannten kritischen Erweiterung, E2 als qualifiziert benannt: Schritt 6 trägt; (1) und (4) `token_extensions_unusable`; Stufe 2 bis 29 | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `evidence_witness_certificate_not_bound` | Token von E2 mit qcStatements, dessen signingCertificateV2 ein anderes Zertifikat nennt (Z.6 verletzt, kein Befund): (1) bis 20, (4) `signing_certificate_not_bound`; Stufe 2 bis 29 | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `evidence_witness_statement_malformed` | zwei Zeitzeugen von E2 bei `tree_size` 20 (qcStatements nicht lesbar) und 23 (ohne Erweiterungen), N = 34, Quittungen bei 15 und 30: (1) bis 23; beide Paare scheitern an `qualified_statement`, mit beiden Ergebnissen: (4) `qualified_statement_malformed`; Stufe 2 bis 30 | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |

**Stufen 1 und 0** (10.9.1, 10.9.5)

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `evidence_level_1_time_witness` | Quittungen unter `vendor-test-002` (keine Anheftung, keine Liste), Zeitzeuge von E2 ohne Erweiterungen bei `tree_size` 20: mit der Prüfumgebung des Korpus Stufe 0, `next` `{1, any, [time_witness, expected_root_found, receipt_key_confirmed]}`; mit E2 als qualifiziert benannt (1) bis 20, (4) `no_qualified_statement`, (3) `key_not_confirmed`: Stufe 1 bis 20 [`time_witness`], 0 für 21 bis 33, `next` `{2, all, [receipt_key_confirmed]}`, kein Hinweis | 1 | `RECEIPT_UNVERIFIED`, `TIME_ANCHOR_UNVERIFIED` | 1 | `RECEIPT_UNVERIFIED` |
| `evidence_level_1_auditor_root` | Quittungen unter `vendor-test-002`; die erwartete Wurzel root(20) des Prüfers ohne `tree_size`, gefunden bei t = 20: (2) bis 20 nur mit der Quelle `auditor`: Stufe 1 bis 20 [`expected_root_found`], Hinweis `expected_root_auditor_only` | 1 | `RECEIPT_UNVERIFIED` | 1 | `RECEIPT_UNVERIFIED` |
| `evidence_level_0_no_receipt` | Standardkette ohne Quittungen (N = 30): `NO_ANCHOR`, Stufe 0 (Eigenschaft 1), (3) `no_receipt`, `next` `{1, any, [time_witness, expected_root_found, receipt_key_confirmed]}`; mit einem wirksamen Auszug (Referenztag 2025-12-31) und E1 für das Protokoll und als qualifiziert benannt: (5) `no_receipt`, (7) `no_receipt_included` | 1 | `NO_ANCHOR` | 1 | `NO_ANCHOR` |
| `evidence_level_0_device_key` | Quittungen unter `vendor-test-geraet` mit dem Publikey aus `GENESIS.device_pubkey`; `--vendor-key` heftet ihn an: Die Signaturen tragen (kein Befund), (3) `key_is_device_key`, Stufe 0 | 1 | `RECEIPT_UNVERIFIED` | 0 | - |

**Hinweise** (10.9.6)

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `evidence_last_receipt_unconfirmed` | Quittung bei 15 unter `vendor-test-001`, bei 28, dem letzten gegengezeichneten Checkpoint aus 8.6, unter `vendor-test-002`: (3) bis 15, Stufe 2 bis 15, Hinweis `last_receipt_not_confirmed`; mit der Anheftung von `vendor-test-002` Stufe 2 bis 28 ohne diesen Hinweis | 1 | `RECEIPT_UNVERIFIED` | 0 | - |
| `evidence_material_contradiction` | ein vorgelegter Klartext widerspricht dem Commitment des ersten KI-Aufrufs: `CONTENT_MISMATCH` aus `material_classes`, Zustand `rated`, Stufe 2 bis 28, Hinweis `material_contradiction`; mit der erwarteten Wurzel `28:<root(28)>` liegt (2) vor | 2 | `CONTENT_MISMATCH` | 2 | `CONTENT_MISMATCH` |
| `evidence_stale_package` | geprüft 25 Stunden nach dem letzten Eintrag: `TRAILING_SILENCE`, Hinweis `stale_package`; Stufe 2 bis 28 | 1 | `TRAILING_SILENCE` | 1 | `TRAILING_SILENCE` |
| `evidence_package_not_fully_known` | Manifest mit dem Member `affiliation` = `affiliated`: `UNKNOWN_MANIFEST_FIELD`, Hinweis `package_not_fully_known`; mit der ehrlichen Seite von 01:02, R = 00:58 und der Rollenliste `not_affiliated`, denn keine Bedingung und keine Verbundenheit liest das Manifest; (2) und (6) bis 28 | 1 | `UNKNOWN_MANIFEST_FIELD` | 1 | `UNKNOWN_MANIFEST_FIELD` |
| `evidence_receipts_after_check_time` | Paket der Gruppe `log`, geprüft um 23:35 am 2026-01-02, Auszug bis zum Referenztag 2026-01-01: beide Quittungen `future`, die vorderste schlechte Quittung ergibt (5) `receipt_after_check_time` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |

**Zustände** (10.9.2, 10.10.1, 10.10.2)

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `evidence_chain_invalid` | Signatur der Quittung bei 28 verändert: `RECEIPT_INVALID`, keine Klasse aus `material_classes`: Zustand `chain_invalid` ohne Stufe, Bedingungen, Verlauf und Hinweise; `affiliation` steht auch hier: `not_checked`, mit der ehrlichen Seite `not_affiliated` | 2 | `RECEIPT_INVALID` | 2 | `RECEIPT_INVALID` |
| `evidence_format_error` | die Zeile des zweiten KI-Aufrufs ist kein JSON: `FORMAT_ERROR` mit Bericht, Zustand `format_error`, `affiliation` `null`; die Anker-Historie der Prüfumgebung ändert nichts | 3 | `FORMAT_ERROR` | 3 | `FORMAT_ERROR` |

### 13.4 Abdeckung und Grenzen

Zusammen mit den Vektoren der Gruppen `roles` bis `history` zeigt das Korpus jede Stufe von 0 bis 3, die drei Zustände, jeden Grund der Tabelle aus 10.9.4 an jeder Bedingung, an der er stehen kann, und jeden Hinweis aus 10.9.6 mit drei Ausnahmen, die kein Vektor zeigen kann:

- `signature_not_checkable` an Bedingung (7): Eine Quittung der Klasse `included` liegt an einem nutzbaren Tag, dessen kanonischer Eintrag einen bestätigten bezeugenden Zeitstempel trägt (7.4.10, Schritte L2 (h), L3). Dessen Signatur ist geprüft, also besteht jedes Tripel mit ihm die erste Stufe, gleich mit welcher Wurzel; das am weitesten gekommene Tripel scheitert deshalb nie an der ersten Stufe.
- `vendor_root_builtin_only`: Keiner der Läufe des Korpus trägt eine eingebaute Herstellerwurzel.
- `cms_not_implemented`: Die Referenz-Verifier führen die Schritte 5 und 6 aus 7.3 aus.

`valid_basic` trägt zusätzlich `evidence_level`, das Beispiel aus Formatspezifikation 10.10.2: Stufe 2 bis 309, 0 für 310 bis 311, Hinweise `unsealed_end` und `published_test_key_credited`.

## 14. Bedingung (7) als zweiter Weg zu Stufe 3 und die übrigen Entscheidungen vom 26.10. (Spezifikation 1.10)

16 Vektoren prüfen, was die Spezifikation nach den Entscheidungen vom 26.10. festlegt: Bedingung (7) als zweiten Weg zu Stufe 3 neben (4), mit der Grenze G_q = 129 600 000 ms, dem Grund `qualified_day_stamp_gap` und dem Berichtsobjekt `qualified_time` (Formatspezifikation 10.9.1, 10.9.4, 10.9.5, 10.10.2, 10.10.3); die Füllerbindung `null` und die Regel, dass sie, einmal gesetzt, in jeder späteren Version gleich bleibt (7.4.4, 7.4.7, 7.4.10 Schritt L1); das Ende eines Zeitraums `former_relation` 24 Monate nach dem Ende einer Beziehung (Heartbeat-Spezifikation §9.10); einen Eintrag `DATA_ACCESS` der Datenklasse `access_chain` (4.25); und die Anker der Bedingung (6) im Block der Beweisstufe, die Bescheidschlüssel der frischen verwendeten Seiten statt jedes Paars aus `anchors.statement_keys` (10.10.2, 10.10.3). Sie stehen in der Registry in der Gruppe ihres Gegenstands (`valid`, `log`, `history`, `evidence`), jeweils nach den Vektoren, die dort schon standen, und erklären `spec_version` `1.10`. Ihre Erwartungen stehen in der Registry, jede mit Grund und Abschnitt im Member `why`, abgeleitet aus dem Text der Spezifikation. Die Solldatei nennt die Beweisstufe in der Kurzform aus §3; `qualified_time`, `basis` und `next` stehen in der Beschreibung der Zeile. Die Referenzwerte KAT8 bis KAT10 aus 10.9.5 stehen in der Registry (`verifier.evidence_level.kat`), mit `next` für KAT10; sie sind keine Vektoren.

### 14.1 Pakete und Prüfumgebungen

**Pakete.** Zehn Vektoren tragen das Paket eines Vektors der Gruppe `log` Byte für Byte unter eigenem Namen (§11.1, §11.3): das von `log_witnessed_included` (14 Einträge, Quittungen bei `tree_size` 5 mit `server_ts` `2026-01-02T23:55:01.000Z` und bei 10, geprüft um 06:30 am 2026-01-03; der Tag der zweiten Quittung ist noch nicht fällig) und das von `log_witnessed_qualified_stamp` (dasselbe Skript; sein Tag 2026-01-02 trägt einen bezeugenden Zeitstempel von 00:05:01 und einen verspäteten von `2026-01-05T00:00:00Z`, beide vom Signierer von E1 mit qcStatements). Zwei Vektoren tragen das Skript der Gruppe `log` mit eigener Kette und einem `TIME_ANCHOR` des Signierers von E3 mit qcStatements: `evidence_level_3_both_ways` 700 ms nach dem Checkpoint von `GENESIS` (`tree_size` 1, `genTime` 23:50:01; Quittungen bei 6 und 11), `evidence_qualified_time_tie` 700 ms nach der zweiten Quittung über den Checkpoint von `tree_size` 10 (`genTime` 00:05:01 am 2026-01-03; Quittungen bei 5 und 10), beide mit N = 15; ihr Tag 2026-01-02 trägt nur einen Zeitstempel desselben Signierers von 00:05:01. Die Vektoren der Gruppe `history` tragen die einstündige Standardkette des Korpus (§12.1), `history_affiliated_former_relation_leap_day` ab 22:00 am 2026-02-28, geprüft um 00:10 am 2026-03-01. `valid_data_access_access_chain` trägt die einstündige Standardkette mit zwei Einträgen `DATA_ACCESS` um 00:03 und 00:04 (N = 34, Quittungen bei 17 und 30).

**Prüfumgebung.** Jede Prüfumgebung enthält die des Korpus (`korpus` `true`). Die Vektoren der Gruppe `evidence` übergeben, wo die Zeile nichts anderes sagt, den Auszug ihres Pakets, die Wurzel ihrer Stelle (E1 oder E3) mit `--vendor-log-tsa-root` und in `--tsa-qualified-roots` (benannt ab 2025-01-01), die Rollenliste der Version 1, R = `2026-01-03T06:00:00.000Z` und die ehrliche Seite der Anker-Historie von 06:10 mit beiden Quittungen (§13.1). Die Vektoren der Gruppe `log` übergeben den Auszug mit dem bezeugten Tag von `log_witnessed_included` und die Wurzel von E1 mit `--vendor-log-tsa-root` (§11.2); die Liste im Auszug und die Listen, die die Zeile als Dateien des Prüfers nennt, unterscheiden sich nur in `version`, `ausgestellt` und `fuellerbindung`. Die Vektoren der Gruppe `history` übergeben die Rollenliste der Version 1, R und die Seiten, die die Zeile nennt (§12.1). `valid_data_access_access_chain` hat keine eigene Prüfumgebung. `TestEntscheidungenVektoren`, `TestEinmaligeStelleE3Eingefroren`, `TestNach24Monaten`, `TestBeweisstufeReferenzwerte`, `TestEntscheidungenInRegistryGruppen` und `TestEntscheidungenTabellenFolgenDerErwartung` (`appliance/cmd/vektorgen`) halten Pakete, die eingefrorene Eingabe von E3, die Monatsrechnung, die Referenzwerte KAT1 bis KAT10, die Stellung in der Registry und die Tabellen gegen die Bytes und gegen `expected/`; `TestBeweisstufeEigenschaften`, `TestBeweisstufeMonotonie` und `TestBeweisstufeAbdeckung` (§13.1) gelten auch für diese Vektoren.

### 14.2 Die Zeitstempelstelle E3

Ein Tageszeitstempel in einem bestimmten Abstand zur Gegensignatur (die Grenze G_q) und ein Zeitzeuge über den Checkpoint einer neuen Kette brauchen Token, die kein eingefrorenes Token von E1 oder E2 deckt. Sie stammen von einer dritten Zeitstempelstelle mit verworfenen Schlüsseln, E3, entstanden wie E1 (§11.2) in einem einzigen Lauf von `vektorgen -einmalige-stelle appliance/cmd/vektorgen/eingefroren -stelle E3`. Ihre Eingabe `appliance/cmd/vektorgen/eingefroren/zeitstempelstelle_e3.json` (Format `ledger-testkorpus-zeitstempelstelle/1`) nennt genau drei Zertifikate und die Token, keinen Schlüssel; der Generator kopiert sie unverändert nach `zeitstempelstelle_e3.json`:

- `wurzel`: „Testkorpus Zeitstempelwurzel E3 (Schluessel verworfen)“, Ed25519, selbst signiert, Seriennummer 1, gültig von 2025-01-01 bis 2036-01-01, basicConstraints cA und keyUsage keyCertSign, beide kritisch; SHA-256 des Zertifikats `bf7bd6f96548b2c78965f7a54f0698cfdda12902fca98553b11ba0fa84e97c31`, SPKI-SHA-256 `c030cacc09261f8c3f37b931a38732d217e8791d4345afc9b94f2f071bd3c4d7`.
- `signierer`: „Testkorpus Zeitstempelstelle E3 (Schluessel verworfen)“, Seriennummer 2, gültig von 2025-06-01 bis 2031-01-01, keyUsage digitalSignature und extKeyUsage genau `id-kp-timeStamping`, beide kritisch; SPKI-SHA-256 `730012141817ed53bfa605da40de43535372ebe05d34fda69cc450cf0aa86ea6`.
- `signierer_qs`: „Testkorpus Zeitstempelstelle E3 qcStatements (Schluessel verworfen)“, Seriennummer 3, sonst wie `signierer`; SPKI-SHA-256 `2fb922d638c2973efa426787d5834d9ac407fafe7262fa9b9c45d0d280054858`.
- `token`: sieben Token des Signierers mit qcStatements (`esi4-qtstStatement-1`), je unter dem Namen `<Vektor>/<Bezeichnung>`, Seriennummern `0x5001` bis `0x5007`: die Zeitzeugen und die Tageszeitstempel von `evidence_level_3_both_ways` und `evidence_qualified_time_tie` und die Tageszeitstempel von `evidence_log_stamp_gap_exact`, `evidence_log_stamp_gap_exceeded` und `evidence_log_stamp_gap_truncated` über den Tageseintrag von `log_witnessed_included`.

Für E3 gilt alles, was §11.2 für E1 sagt: Ihre Schlüssel stehen in keiner Datei und nicht in `published_test_keys`, ihre Token lassen sich nicht erneut ausstellen, jeder andere Lauf des Generators hält jedes Token gegen seine Anforderung und bricht bei einem fehlenden, abweichenden oder von keinem Vektor verlangten Token ab, und ihre Wurzel ist nie die Wurzel eines Prüfers; sie zählt nur, wo `pruefer_<name>.json` sie übergibt.

### 14.3 Vektoren

Die Tabellen nennen zuerst Exit und Befunde mit der Prüfumgebung des Korpus, dann mit `pruefer_<name>.json`. In der Beschreibung steht der Verlauf als „Stufe für `first_seq` bis `last_seq`“ und `basis` in eckigen Klammern; (1) bis (7) sind die Bedingungen aus 10.9.1, `qualified_time` steht als `{via, tree_size, latest, gap_ms}`. Mit der Prüfumgebung des Korpus haben die Vektoren der Gruppen `log` und `evidence` Stufe 2 bis 10 (die mit einem Zeitzeugen von E3 Stufe 2 bis 11 und 10 mit `TIME_ANCHOR_UNVERIFIED`), die der Gruppe `history` Stufe 2 bis 28.

**Bedingung (7), der zweite Weg zu Stufe 3** (10.9.1, 10.9.5, 10.10.2, 10.10.3)

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `evidence_level_3_log_day_qualified` | Paket und Auszug von `log_witnessed_qualified_stamp`, E1 für das Protokoll und als qualifiziert benannt: kein Zeitzeuge, (4) `no_time_anchor`; (7) mit dem bezeugenden Zeitstempel, 10 Minuten nach der Quittung, bis 5, (5) bis 5, (2), (3) und (6) bis 10; r3 = min(10, max(0, 5), 5, 10) = 5: Stufe 3 bis 5 allein über (7); 3 für 1 bis 5 [`receipts_logged`, `log_day_qualified`], 2 für 6 bis 10, 0 für 11 bis 14; `qualified_time` `{log_day_qualified, 5, 2026-01-03T00:05:01.000Z, 600000}`, Zeile „qualifiziert bestätigt: spätestens 2026-01-03T00:05:01.000Z (Zeitstempel des Herstellerprotokolls, tree_size 5, 0 Std. 10 Min. nach der Gegensignatur)“ | 0 | - | 0 | - |
| `evidence_level_3_both_ways` | Zeitzeuge von E3 bei `tree_size` 1, Tag von E3 gestempelt, E3 für das Protokoll und als qualifiziert benannt: (1) und (4) bis 1, (5) und (7) bis 6, (2), (3) und (6) bis 11; r3 = min(11, max(1, 6), 6, 11) = 6, es zählt die größere Reichweite von (4) und (7): Stufe 3 bis 6; 3 für 1 bis 6 [`receipts_logged`, `log_day_qualified`], 2 für 7 bis 11, 0 für 12 bis 15; `qualified_time` `{log_day_qualified, 6, 2026-01-03T00:05:01.000Z, 600000}`, der Zeitzeuge bei 1 ist kein Kandidat, seine `tree_size` liegt unter `up_to_tree_size` | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |
| `evidence_qualified_time_tie` | Zeitzeuge von E3 bei `tree_size` 10 mit `genTime` 00:05:01, Tag von E3 mit demselben `genTime`: (1) und (4) bis 10, (5) und (7) bis 5: Stufe 3 bis 5; 3 für 1 bis 5 [`receipts_logged`, `log_day_qualified`], 2 für 6 bis 10, 0 für 11 bis 15; bei gleichem `genTime` geht (4) vor (7): `qualified_time` `{time_witness_qualified, 10, 2026-01-03T00:05:01.000Z, null}`, Zeile „qualifiziert bestätigt: spätestens 2026-01-03T00:05:01.000Z (Zeitzeuge der Kette, tree_size 10)“ | 1 | `TIME_ANCHOR_UNVERIFIED` | 0 | - |

**Die Grenze G_q** (10.9.1, 10.9.4)

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `evidence_log_stamp_gap_exact` | Paket von `log_witnessed_included`, sein Tag nur mit einem Zeitstempel von E3 mit qcStatements, `genTime` `2026-01-04T11:55:01Z`, genau G_q nach der Quittung von 23:55:01.000 und bezeugend (vor end(d) + W): (7) liegt vor, nur ein Abstand größer als G_q scheitert; Stufe 3 bis 5 [`receipts_logged`, `log_day_qualified`]; `qualified_time` `{log_day_qualified, 5, 2026-01-04T11:55:01.000Z, 129600000}`, in der Zeile „36 Std. 0 Min.“ | 0 | - | 0 | - |
| `evidence_log_stamp_gap_exceeded` | dasselbe mit `genTime` `2026-01-04T11:55:01.001Z`: Abstand 129 600 001 ms, jede frühere Stufe besteht: (7) `qualified_day_stamp_gap`; der Tag bleibt bezeugt, (5) bis 5; Stufe 2 bis 10, `next` `{3, all, [time_witness_qualified, log_day_qualified]}`, im Text eine Zeile für (4) oder (7) mit beiden Gründen | 0 | - | 0 | - |
| `evidence_log_stamp_gap_truncated` | dasselbe mit `genTime` `2026-01-04T11:55:01.0009Z`: auf ganze Millisekunden abgeschnitten genau G_q, (7) liegt vor; Stufe 3 bis 5; `qualified_time.latest` `2026-01-04T11:55:01.000Z`, `gap_ms` 129600000 | 0 | - | 0 | - |

**Wurzeln mit nur einem der Zwecke** (7.5.7, 10.8, 10.9.4)

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `evidence_qualified_log_root_log_only` | Paket und Auszug von `log_witnessed_qualified_stamp`, E1 nur für das Protokoll: Der Tag ist bezeugt, (5) bis 5; keine Wurzel trägt beide Zwecke: (7) `no_qualified_log_root_supplied`, (4) `no_time_anchor`; Stufe 2 bis 10, `next` `{3, all, [time_witness_qualified, log_day_qualified]}` | 0 | - | 0 | - |
| `evidence_qualified_log_root_qualified_only` | E1 nur in der Datei der qualifizierten Wurzeln, nicht für das Protokoll: kein Tageszeitstempel ist bestätigt, die erste Quittung `unchecked` mit `day_not_witnessed`, Grund `no_log_root_supplied`; (5) `day_timestamp_not_confirmed`, (7) `no_qualified_log_root_supplied`; Stufe 2 bis 10, `next` `{3, all, [time_witness_qualified, receipts_logged, log_day_qualified]}` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |

**Füllerbindung** (7.4.4, 7.4.7, 7.4.10 Schritt L1)

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `log_list_filler_commitment_null` | Auszug mit der Liste der Version 1 mit `fuellerbindung` `null`: wirksam, kein Befund; (5) bis 5 | 0 | - | 0 | - |
| `log_lists_filler_commitment_set_later` | Version 1 mit `null` im Auszug, Version 2 mit der Füllerbindung des Test-Füllergeheimnisses als Datei des Prüfers: ab Version 2 gesetzt, kein Widerspruch; Version 2 wirksam | 0 | - | 0 | - |
| `log_lists_filler_commitment_changed` | dazu Version 3 mit der Füllerbindung eines anderen Geheimnisses: zwei zählende Listen nennen verschiedene Werte ungleich `null`, „widersprüchliche Listen“; kein Protokollschlüssel, (5) und (7) `vendor_log_not_established` | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |
| `log_lists_filler_commitment_dropped` | Version 1 mit der Füllerbindung im Auszug, Version 2 mit `null`: „widersprüchliche Listen“ | 0 | - | 1 | `VENDOR_LOG_UNVERIFIED` |

**Verbundenheit: 24 Monate** (Heartbeat-Spezifikation §9.10, Formatspezifikation 8.8.6)

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `history_not_affiliated_period_before_24_months` | der Referenzwert aus 8.8.6: nur ein Zeitraum `former_relation` 2025-06-01 bis 2025-12-01, 24 Monate nach dem Ende der Beziehung am 2023-12-01: `not_affiliated`, Zeitraum außerhalb | 0 | - | 0 | - |
| `history_affiliated_former_relation_leap_day` | Standardkette ab 22:00 am 2026-02-28, R = 23:58, frische Seite von 00:02 am 2026-03-01: ein Zeitraum `former_relation` von 2025-06-01 bis `2026-03-01T00:00:00.000Z` für eine Beziehung, die um 12:00 am 2024-02-29 endete (24 Monate nach einem 29. Februar sind der 1. März zwei Jahre später, 00:00:00.000Z); der Zeitraum des Pakets liegt davor, nach 730 Tagen (12:00 am 2026-02-28) läge er dahinter: `affiliated` mit `former_relation`, 2 von 2 Quittungen im Zeitraum | 0 | - | 0 | - |

**Anker der Bedingung (6)** (10.10.2, 10.10.3; 8.8.4, „Ältere Seiten“)

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `history_archive_page_other_key` | die ältere Seite von 00:40:00 aus `history_archive_pages` (Wurzel bei 15), signiert mit `vendor-statements-test-002` der Rollenliste, neben der frischen Seite unter `vendor-statements-test-001`: kein Befund, Hinweis `archive_pages`; (2), (3) und (6) bis 28, Stufe 2 bis 28; (2) mit der Quelle `anchor_history` beruht auf beiden Seiten, `anchors.statement_keys` nennt beide Schlüssel; (6) beruht nur auf der frischen Seite (8.8.4, „Ältere Seiten“), die Zeile „liegt vor“ von (6) nennt „Anker-Historie vom 2026-01-01T01:02:00.000Z, Bescheidschlüssel vendor-statements-test-001 aus Rollenliste Version 1, Wurzel testwurzel-1 des Prüfers“ und nicht `vendor-statements-test-002` | 0 | - | 0 | - |

**`DATA_ACCESS`** (4.25)

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `valid_data_access_access_chain` | Standardkette der Fassung 1.10 mit zwei Einträgen `DATA_ACCESS`: um 00:03 die Ergänzung eines Kontos (`credentials`, `change`, `maintenance`, `all_customers`, `declared`, `origin` `portal`), um 00:04 das Lesen der Zugriffskette selbst durch dieses Konto für die Prüfung (`access_chain`, `read`, `audit`, `all_customers`, `gate`, `origin` `import`): Das Schema hält, kein Befund; Stufe 2 bis 30 | 0 | - | - | - |

### 14.4 Abdeckung und Grenzen

Mit diesen Vektoren zeigt das Korpus auch den Grund `qualified_day_stamp_gap` und Bedingung (7) als einzigen Weg zu Stufe 3; `TestBeweisstufeAbdeckung` hält das fest. Grenzen, offen ausgewiesen:

- Die Tageszeitstempel von `evidence_log_stamp_gap_exact`, `evidence_log_stamp_gap_exceeded` und `evidence_log_stamp_gap_truncated` tragen einen `genTime` nach dem Prüfzeitpunkt ihres Pakets (06:30 am 2026-01-03), wie die verspäteten Zeitstempel aus §11.3; kein Schritt der Spezifikation vergleicht den `genTime` eines Tageszeitstempels mit dem Prüfzeitpunkt.
- Der eingefrorene Vektor `history_not_affiliated_period_before` trägt das Ende eines Zeitraums `former_relation` nach 730 Tagen (§12.8); seine Bytes und seine Erwartung bleiben, denn der Verifier berechnet kein Ende.

## 15. Abgleich beider Verifier (Spezifikation 1.10)

26 Vektoren legen Lesarten fest, die die Spezifikation festgehalten hat, damit beide Referenz-Verifier jede Eingabe gleich beurteilen (Formatspezifikation Abschnitt 2, 7.5.2 bis 7.5.6). 23 von ihnen gehören zur Gruppe `timestamp` und stehen mit ihren Prüfumgebungen in der Tabelle von §10.3, sechs davon mit den Eingaben der Einzelprüfung in §10.4; der Generator baut sie wie die übrigen dort (`grundlagen.go`, `zeitstempelprofil.go`). Hier stehen die drei Paketvektoren: die zwei mit einer Gegenzeichnung, `valid_receipt_r_identity` in der Gruppe `valid` und `tamper_receipt_r_identity_sign_bit` in der Gruppe `tamper`, und `format_uuid_trailing_newline` in der Gruppe `format`, jeweils nach den Vektoren, die dort schon standen (`abgleich.go`). Alle drei erklären `spec_version` `1.10`, tragen die Standardkette aus §10 (32 Einträge, Quittungen bei `tree_size` 15 und 28 unter `vendor-test-001`, versiegelt um 01:01, geprüft 2 min danach) und haben keine eigene Prüfumgebung; ihre Solldatei nennt `evidence_level`. Jede Erwartung steht mit Grund und Abschnitt im Member `why` der Registry, abgeleitet aus dem Text der Spezifikation.

**Das neutrale Element als R.** Ed25519 wird ohne Kofaktor geprüft (Formatspezifikation Abschnitt 2): S < L, und die Kodierung von [S]B - [k]A gleicht R Byte für Byte. Das neutrale Element (0, 1) hat zwei Kodierungen mit gültigem y: `01 00…00 00`, die kanonische, und `01 00…00 80` mit gesetztem Vorzeichenbit, obwohl x = 0 ist. Mit R gleich einer der beiden und S = k·a mod L (k = SHA-512(R, A, M) mod L, a der geheime Skalar des Schlüssels) gilt [S]B = R + [k]A als Gleichung zwischen Punkten; der Vergleich der Kodierungen lässt nur die kanonische zu. Eine solche Signatur schreibt jeder, der den privaten Schlüssel kennt; sie braucht keinen Bruch von Ed25519, und jeder Schlüssel hier ist ein Testschlüssel des Korpus. Dieselben zwei Kodierungen tragen in der Gruppe `timestamp` die Signatur eines Tokens (`timestamp_signature_r_identity`, `timestamp_signature_r_identity_sign_bit`) und die Signatur der Wurzel über das Signiererzertifikat (`timestamp_signer_cert_r_identity`, `timestamp_signer_cert_r_identity_sign_bit`).

| Vektor | Aufbau und Prüfumgebung des Vektors | Exit | Befunde | Exit mit `pruefer_<name>.json` | Befunde mit `pruefer_<name>.json` |
|---|---|---|---|---|---|
| `valid_receipt_r_identity` | die Quittung von 01:00 (`tree_size` 28) mit R = `01 00…00 00` und S = k·a mod L: `server_signature` besteht unter dem angehefteten Schlüssel (7.1); kein Befund, Stufe 2 bis 28 | 0 | - | - | - |
| `tamper_receipt_r_identity_sign_bit` | dieselbe Kette mit R = `01 00…00 80`: Die Kodierung von [S]B - [k]A ist `01 00…00 00` und gleicht R nicht, `server_signature` besteht nicht (7.1); Zustand `chain_invalid` (10.9.2). Wer die Gleichung zwischen Punkten prüft, nähme die Quittung an | 2 | `RECEIPT_INVALID` | - | - |
| `format_uuid_trailing_newline` | die Kette unter eigener `chain_id`, jede Quittung nach RFC 8032 signiert, mit einem Zeilenvorschub (U+000A) nach den 36 Zeichen der uuid, im Manifest und in jedem Eintrag: `manifest.chain_id` verletzt den Typ `uuid` (2), das Manifest sein Schema, die späteren Stufen entfallen (10.5); Zustand `format_error` mit Bericht (10.9.2). Wer den Typ mit einem Muster liest, dessen `$` ein Zeilenende am Schluss zulässt, findet eine gültige Kette | 3 | `FORMAT_ERROR` | - | - |

**Welche Regel welcher Vektor festlegt.**

- Z.6 Element für Element (7.5.6): `timestamp_ess_v2_second_element_broken`, `timestamp_ess_issuer_serial_name_broken` (verletzt), `timestamp_ess_policies_not_der`, `timestamp_ess_other_name_a4`, `timestamp_ess_hash_algorithm_parameters_not_der` (gilt).
- Z.1, der Inhalt von `extnValue` der Erweiterungen, die eine Regel liest, in DER nach T.6, in jedem Zertifikat aus `certificates` (7.5.2, 7.5.3): `timestamp_signer_basic_constraints_not_der`, `timestamp_extra_certificate_path_len_not_minimal`, `timestamp_signer_eku_oid_not_minimal`; dort genügt ein Element der Klasse universal mit der Tag-Nummer 0 oder ab 31 T.6 nicht: `timestamp_signer_basic_constraints_tag_zero`, `timestamp_signer_basic_constraints_tag_31`. Jeder dieser Vektoren endet bei 5a, nicht bei „kein Pfad“.
- Grenzen von T.6 (7.5.2): den Inhalt von NULL, das Oktett der ungenutzten Bits und die ungenutzten Bits eines BIT STRING prüft T.6 nicht: `timestamp_signer_basic_constraints_null_content`, `timestamp_signer_key_usage_unreadable`, `timestamp_root_key_cert_sign_unused_bit`.
- Z.3 an jeder Stelle des Pfads, auch an c0 (7.5.5), und keyCertSign nur unter den genutzten Bits: `timestamp_signer_key_usage_unreadable`, `timestamp_signer_basic_constraints_unreadable`, `timestamp_signer_basic_constraints_null_content`, `timestamp_root_key_cert_sign_unused_bit`.
- Z.5, `sid` als `[0]` gegen den Schlüsselbezeichner (7.5.5): `timestamp_sid_key_identifier`.
- Wo die Grammatik nur ein TLV verlangt, prüft T.6 nur das äußere TLV (7.5.2): die Parameter von `hashAlgorithm` eines ESSCertIDv2 (Z.6, 7.5.6): `timestamp_ess_hash_algorithm_parameters_not_der`; der Wert eines signierten Attributs, das keine Regel liest (T.4): `timestamp_signed_attribute_value_not_der`; die Parameter des Schlüsselalgorithmus eines Zertifikats auf keinem Pfad, auch mit der Tag-Nummer 0 (Z.1, 7.5.3): `timestamp_extra_certificate_key_parameters_tag_zero`. Jedes dieser Token wird beurteilt wie das von `timestamp_qualified_root`.
- Eine Teilkennung einer OID über 10^4300 hält T.6 ein (7.5.2): in `extKeyUsage` eines Zertifikats auf keinem Pfad, Z.1 gilt (7.5.3): `timestamp_extra_certificate_oid_arc_large`; als `extnID` einer Erweiterung des TSTInfo neben `qcStatements`, Regel QS `present` (7.5.6): `timestamp_qs_extension_oid_arc_large`.
- Ed25519 ohne Kofaktor (Abschnitt 2): die zwei Vektoren dieses Abschnitts mit einer Gegenzeichnung und die vier oben genannten der Gruppe `timestamp`.
- Eine uuid ist die ganze Zeichenkette der Form 8-4-4-4-12 (Abschnitt 2): `format_uuid_trailing_newline`. Ein mit `^` und `$` verankertes Muster lässt in mehr als einem Dialekt regulärer Ausdrücke auch einen Zeilenvorschub nach dem letzten Zeichen zu, weil `$` auch vor einem Zeilenende am Schluss passt; der Typ lässt ihn nicht zu. Das Paket ist eine korrekte Kette über die Bytes mit dem Zeilenvorschub, der Zeilenvorschub ist also sein einziger Mangel.

**Grenzen.** Ob Z.6 gilt, zeigt keine Solldatei: Ein Token der Zeitstempelstelle des Generators, das einen Pfad zur Wurzel des Prüfers hat, endet bei den Bedingungen (1) und (4) bei `published_test_key`, vor der Stufe zu Z.6 (§10.3). Es zeigt nur die Einzelprüfung (§10.4), in deren Tabelle aus 7.5.7 die Zeile zu Z.6 über der zu `published_test_keys` steht; `TestZeitstempelKorpus` (`verifier/internal/cli`) und `test_readme_10_4_inputs` (`verifier2`) halten die fünf Eingaben zu Z.6 und die zur Regel QS mit beiden Zwecken fest. `TestAbgleichTabelleFolgtDerErwartung` (`appliance/cmd/vektorgen`) hält die Tabelle dieses Abschnitts gegen `expected/`, `TestGrundlagenTabellenFolgenDerErwartung` die Zeilen der Gruppe `timestamp`.
