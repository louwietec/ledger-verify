# Testvektoren

**Spezifikation Rekorder · spec_version 1.9 · Sprache: Deutsch (englische Fassung: `README.en.md`, identische Struktur)**

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
├── expected/
│   └── <name>.json                 # Soll-Ausgabe je Vektor (§3)
└── <name>/                         # ein Ordner je Vektor = ein vollständiges Prüfpaket
    ├── manifest.json               # Prüfpaket-Manifest (Registry: pruefpaket_manifest)
    ├── segments/*.jsonl            # Ketten-Segmente (kanonisches JSON, ein Eintrag je Zeile)
    ├── verify_args.json            # Prüfzeit des Vektors (`now`), nur mit --now-from-package
    └── …                           # je nach Vektor: Quittungen, Publikeys, vorgelegte Klartexte/Salts, Berichts-Hashes
```

Vektor-Namen (`valid_*`, `gap_*`, `end_*`, `hold_*`, `tamper_*`, `format_*`) und ihre Sollwerte sind abschließend in der Registry definiert; dieses README zählt sie bewusst nicht erneut auf. Ausgenommen sind die acht Vektoren der Spezifikation 1.6 (§5), die drei der Spezifikation 1.7 (§7), die drei der Spezifikation 1.8 (§8) und die neun der Spezifikation 1.9 (§9): Was sie zeigen, geht aus dem Namen allein nicht hervor. Ihre Tabellen nennen die Sollwerte der Registry, und `TestKettenendeTabelleFolgtDerErwartung`, `TestHoldTabelleFolgtDerErwartung` `TestLizenzTabelleFolgtDerErwartung` und `TestV19TabelleFolgtDerErwartung` (`appliance/cmd/vektorgen`) halten sie gegen `expected/`.

## 3. Erwartete Ergebnisse (`expected/`)

Je Vektor genau eine Datei `expected/<name>.json`, zum Beispiel `expected/end_sealed_stale.json`:

```json
{
  "exit_code": 1,
  "finding_classes": ["TRAILING_SILENCE"]
}
```

- `exit_code`: erwarteter Verifier-Exit-Code: `0` gültig ohne Befunde, `1` gültig mit Befunden, `2` ungültig, `3` Formatfehler, `4` unvollständig: Kettenende nicht versiegelt (Registry: `verifier.exit_codes`). Maßgeblich ist die Rangfolge 3 vor 2 vor 4 vor 1 vor 0 (Registry: `verifier.exit_precedence`), nicht die Größe der Zahl.
- `finding_classes`: exakte Liste der erwarteten Befundklassen (Registry: `verifier.finding_classes`); leere Liste bei `exit_code` 0.

Die Erwartung ist **exakt**, nicht „mindestens": beide Verifier müssen genau diesen Exit-Code und genau diese Befundklassen liefern.

**Prüfumgebung (seit Spezifikation 1.4).** Die Erwartungen gelten für einen Prüfer, der zwei Vertrauensanker mitbringt (Spezifikation 7.1): die Wurzel des Testherstellers in `pruefer_herstellerwurzel.json` (`--vendor-root`) und dessen angehefteten Schlüssel in `pruefer_herstellerschluessel.txt` (je Zeile `key_id=hex`, `--vendor-key`). Beide Dateien liegen neben den Vektoren, nicht in ihnen, und sind mitgepinnt. Wer ohne Anker prüft, bekommt bei jedem Vektor mit Quittung zusätzlich `RECEIPT_UNVERIFIED`; das ist das vorgesehene Verhalten, kein Fehler des Korpus. Eine Ausnahme: `tamper_vendor_revoked` braucht die Wurzel, um den Widerspruch der Liste überhaupt zu sehen; ohne Anker ergibt es statt Exit 2 `[NO_ANCHOR, RECEIPT_INVALID, UNSEALED_END]` nur Exit 4 `[RECEIPT_UNVERIFIED, UNSEALED_END]`. Die drei Hersteller-Vektoren von 1.4 (`valid_vendor_list`, `tamper_vendor_key`, `tamper_vendor_revoked`) quittieren unter Schlüsseln, für die nur die signierte Liste im Paket bürgt, oder eben nicht; alle anderen Vektoren mit Quittung, auch die acht von 1.6 und die drei von 1.7, quittieren unter `vendor-test-001` (angeheftet).

## 4. Einfrieren (`PINS.sha256`)

Die kryptogültigen Bytes der Vektoren (echte Hash-Ketten, Merkle-Roots, Ed25519-Signaturen und Gegensignaturen mit publizierten Testschlüsseln) werden **vom Ledger-Vektor-Generator erzeugt (Arbeitspaket P02)**; sie sind von Hand nicht herstellbar. Nach der Erzeugung wird jede Vektor-Datei per SHA-256 in `PINS.sha256` gepinnt und **nie mehr geändert**: Die CI vergleicht die Dateien bei jedem Lauf gegen die Pins; jede Abweichung ist rot. Bis dahin existieren nur die Soll-Definitionen unter `expected/`; ein Vektor gilt erst mit Pin als eingefroren und referenzierbar. Neue Anforderungen führen zu **neuen** Vektoren (Registry-Eintrag + neuer Pin), niemals zur Änderung eingefrorener.

Jeder Vektor erklärt die `spec_version`, unter der er eingefroren wurde, als Literal, für immer (`TestEingefroreneVersionenBleibenStehen`). Nur `format_newer_minor` leitet seine Version ab: er muss per Definition eine Minor-Version über der aktuellen liegen und wird deshalb bei jedem Versionssprung neu erzeugt und neu gepinnt, mit Spezifikation 1.9 auf `1.10`.

**Eine Ausnahme, aufgeschrieben statt verschwiegen.** Die Regel „nie mehr geändert" setzt voraus, dass der Maßstab selbst stillsteht. Mit der Freigabe von Abschnitt 6.2 Regel 3 (der Sofort-Checkpoint gilt ausnahmslos und schließt `SEAL` ein) traf das nicht mehr zu: Die Vektoren `valid_update_handover` und `tamper_handover` schrieben `SEAL → RESUME` ohne den vorgeschriebenen Sofort-Checkpoint und verletzten damit genau die Spezifikation, für die sie der Maßstab sein sollen; `valid_update_handover` war zudem als *gültig* ausgewiesen. Beide wurden deshalb neu erzeugt und neu gepinnt; ihre Sollwerte in `expected/` blieben unverändert, weil die Erwartung nie falsch war, nur die Kette. Dass sich **ausschließlich** diese beiden Vektoren geändert haben und die übrigen 27 Byte für Byte gleich geblieben sind, ist per Hash nachgewiesen in `artefakte/P03/vektor_gegenprobe.log`, Abschnitt [1]. Ein eingefrorener Vektor wird nur dann neu erzeugt, wenn die freigegebene Spezifikation ihn nachweislich widerlegt; nie, um einen Verifier grün zu bekommen.

**Zweite Ausnahme: Spezifikation 1.6 (Kettenende).** Mit der Freigabe von Abschnitt 8.6 wird jede Kette auch nach ihrem Ende beurteilt, und alle bis 1.5 eingefrorenen Vektoren enden unversiegelt, wie ein Export aus laufendem Betrieb. Die Erwartungen der 38 eingefrorenen Vektoren, die kein Formatfehler sind, haben sich deshalb mit der freigegebenen Spezifikation 1.6 geändert: Jeder trägt zusätzlich `UNSEALED_END`, Exit 4 statt 0 oder 1; wo schon ein Befund der Exit-Klasse 2 stand, bleibt es Exit 2. Ihre **Bytes** sind unverändert, bis auf `format_newer_minor`, der ohnehin bei jedem Versionssprung neu erzeugt wird (siehe oben): Die Ketten waren nie falsch, nur der Maßstab hat sich bewegt. Das ist dieselbe Lage wie beim Präzedenzfall von Spezifikation 1.1: Dort verlor `format_unknown_event_type` in `expected/` den Befund `SPEC_NEWER`, weil der Verifier die Version erreicht hatte, die der Vektor erklärt; die Erwartung folgte der freigegebenen Fassung, die Bytes nicht. Neu erzeugt wurde mit 1.6 nur `format_newer_minor` (damals auf `1.7`, siehe oben); hinzugekommen sind die acht Vektoren aus §5. Nachrechenbar: `git show 6be9d7e:spec/testvectors/PINS.sha256 | grep -v ' format_newer_minor/' > /tmp/pins_1_5` und dann `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_5`: 225 Dateien (39 Vektorverzeichnisse und die zwei Dateien der Prüfumgebung), keine Abweichung.

**Spezifikation 1.7 (Löschsperre): keine Ausnahme.** Mit 1.7 kommt der Befund `HOLD_VIOLATION` hinzu, und er entsteht nur an einem `LEGAL_HOLD`; keiner der 48 älteren Vektoren trägt einen. Ihre Erwartungen und ihre Bytes bleiben deshalb unverändert. Neu erzeugt wurde nur `format_newer_minor` (damals auf `1.8`, siehe oben); hinzugekommen sind die drei Vektoren aus §7. Nachrechenbar: `git show 66f0cc0:spec/testvectors/PINS.sha256 | grep -v ' format_newer_minor/' > /tmp/pins_1_6` und dann `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_6`: 265 Dateien (47 Vektorverzeichnisse und die zwei Dateien der Prüfumgebung), keine Abweichung.

**Spezifikation 1.8 (Lizenz-Commitment): keine Ausnahme.** Mit 1.8 muss `GENESIS.license_id` das Lizenz-Commitment sein, aber nur in einem `GENESIS`, dessen eigene `spec_version` 1.8 oder neuer ist (Formatspezifikation 4.1). Alle älteren Vektoren erklären eine ältere Fassung und tragen `LIC-TEST-0001` im Klartext; die Verifier geben dazu einen Hinweis aus, keinen Befund. Ihre Erwartungen und ihre Bytes bleiben deshalb unverändert. Neu erzeugt wurde nur `format_newer_minor` (damals auf `1.9`, siehe oben; sein `GENESIS` trägt seither das Commitment); hinzugekommen sind die drei Vektoren aus §8. Nachrechenbar: `git show a3a0147:spec/testvectors/PINS.sha256 | grep -v '^#' | grep -v ' format_newer_minor/' > /tmp/pins_1_7` und dann `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_7`: 280 Dateien (50 Vektorverzeichnisse und die zwei Dateien der Prüfumgebung), keine Abweichung.

**Spezifikation 1.9 (Export-Siegel, nachgeholter Checkpoint, Klarstellungen): keine Ausnahme.** Die neuen Regeln greifen nur an Stellen, die kein älterer Vektor enthält: kein Export-Siegel, kein nachgeholter Sofort-Checkpoint mit mehr als 450 s Abstand, kein Segment außerhalb von `segments/`, keine Datei unter `content/` außer vollständigen Vorlagen, keine Zahl außerhalb von ±(2^53−1). Ihre Erwartungen und ihre Bytes bleiben deshalb unverändert. Neu erzeugt wurde nur `format_newer_minor` (jetzt `1.10`); hinzugekommen sind die neun Vektoren aus §9. Nachrechenbar: `git show 2ff96ba:spec/testvectors/PINS.sha256 | grep -v '^#' | grep -v ' format_newer_minor/' > /tmp/pins_1_8` und dann `cd spec/testvectors && sha256sum -c --quiet /tmp/pins_1_8`: 295 Dateien (53 Vektorverzeichnisse und die zwei Dateien der Prüfumgebung), keine Abweichung.

Abschnitt 8.7 der Formatspezifikation (Erfassungszusage und Lückenbeginn nach einem Absturz) verpflichtet die Appliance, nicht den Verifier: Er erzeugt keinen Befund und ändert keinen Vektor.

**Testschlüssel aus Ketten vor 1.8 (Entscheidung vom 02.10.2026): keine Ausnahme für die Bytes.** Jeder Testschlüssel, den eine Test- oder Demokette vor 1.8 im Klartext trug, ist in Tests, Vertragsvektoren, Demo und Beispielkonfiguration durch einen neuen ersetzt. Jeder neue enthält mindestens eines der Zeichen I, L, O oder U und hat damit nie die Form, die die LOUWIETEC-Cloud ausgibt (`LEDGER-` und viermal vier Zeichen Crockford-Base32). `LIC-TEST-0001` bleibt im eingefrorenen Korpus. Er ist kein Lizenzschlüssel und kann keiner werden: Die Grammatik `^[A-Z0-9-]{19,29}$` (Heartbeat-Spezifikation 4.1) lässt 13 Zeichen nicht zu, eine Aktivierung mit ihm scheitert also schon an der Form. Die Vektoren vor 1.8 sind außerdem der Maßstab dafür, dass Ketten älterer Fassungen lesbar bleiben (Formatspezifikation 4.1). Sie werden nur dafür verwendet, nicht als Demo und nicht als Vorlage für neue Ketten.

**Nachtrag zum Vektor `tamper_missing_checkpoint` (14.09.).** Der Negativvektor zu `MISSING_CHECKPOINT` (Exit 2) war gepinnt und wurde von beiden Prüf-Jobs gefahren, weil diese `expected/` aufzählen, stand aber nicht in `spec/registry.json`; `.ci/check_registry_matrix.py` zählte deshalb 29 statt 30 Vektoren und prüfte nur die Richtung Registry → Dateien. Beides ist behoben: der Eintrag steht in der Registry, und die Matrixprüfung läuft in beide Richtungen; ein Vektorverzeichnis oder eine `expected/`-Datei ohne Registry-Eintrag ist seither rot (Rot-Beweis: `artefakte/P01/redproof_registry_beidseitig.log`).

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
