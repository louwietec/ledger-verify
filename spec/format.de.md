# LEDGER-Kettenformat: Spezifikation (DE)

**spec_version: 1.9** · Diese Spezifikation ist normativ. Sie beschreibt das Aufzeichnungsformat von LEDGER vollständig genug, dass ein unabhängiger Dritter allein hieraus einen Verifier implementieren kann. Die maschinenlesbare Feld- und Klassenreferenz ist `spec/registry.json`; bei Abweichungen gilt die Registry.

Die Schlüsselwörter MUSS, DARF NICHT, SOLLTE und KANN sind im Sinne von RFC 2119 („MUST", „MUST NOT", „SHOULD", „MAY") zu verstehen.

## 1. Überblick und Designziele

LEDGER zeichnet die Nutzung von KI-Diensten als **append-only Ereigniskette** auf: kanonisches JSON, SHA-256-Hash-Verkettung, Merkle-Baum nach RFC 6962, Ed25519-signierte Checkpoints und externe Gegensignaturen. Drei Designziele bestimmen jede Formatentscheidung:

1. **Beweis statt Behauptung.** Jede Aussage der Kette ist kryptographisch prüfbar: offline, ohne Mitwirkung des Herstellers, ohne Geheimnisse. Die Prüfung benötigt weder Kundenschlüssel noch Inhalte.
2. **Lücke = Befund.** Es gibt keinen Fehlerpfad, der „im Nichts" endet: Ausfälle, Umgehungen, Uhrensprünge und Löschungen werden als eigene Eintragstypen verkettet. Eine ehrlich ausgewiesene Lücke macht die Kette nicht ungültig; eine verschwiegene schon (Abschnitt 8, 11). Für den einzelnen Aufruf ist das eine Zusage der Appliance: Jeder Aufruf, den sie beantwortet hat, steht in der Kette oder liegt im Fenster eines verketteten `GAP` (Abschnitt 8.7); ob sie eingehalten ist, kann das Paket allein nicht zeigen (Abschnitt 11.2).
3. **Souveränität.** Die Kette trägt keine Klartexte, sondern gesalzene Commitments (Abschnitt 9). Der Hersteller kennt keine Kundenschlüssel und sieht keine Inhalte; seine einzige Rolle im Beweismodell ist die Gegensignatur über 32-Byte-Wurzeln (Abschnitt 6, 7, 11).

Die Kette dient als technisches Beweismittel und unterstützt die Erfüllung von Dokumentations- und Nachweispflichten des Betreibers; welche Pflichten im Einzelfall bestehen, bestimmt diese Spezifikation nicht. Sie enthält keine Rechtsberatung.

## 2. Konventionen und Grundtypen

Alle Feldtypen dieser Spezifikation:

| Typ | Bedeutung |
|---|---|
| `string` | UTF-8-Zeichenkette; `maxlen` = maximale Länge in Unicode-Zeichen |
| `int` | ganze Zahl (JSON number ohne Bruchteil); `min`/`max` inklusive |
| `bool` | `true` oder `false` |
| `uuid` | UUID als Kleinbuchstaben-String, Format 8-4-4-4-12 |
| `rfc3339` | Zeitstempel nach RFC 3339, MUSS in UTC mit Suffix `Z` angegeben werden; gelesen nach der Grammatik aus Abschnitt 10.7: `JJJJ-MM-TTThh:mm:ss` mit den ASCII-Ziffern `0` bis `9`, optional ein Punkt mit Sekundenbruchteilen, dann `Z`; ein Komma vor dem Bruchteil, eine einstellige Stunde oder die Sekunde `60` erfüllen den Typ nicht; das Jahr liegt zwischen `0001` und `9999`, das Datum muss existieren |
| `hex64` | 64 hexadezimale Kleinbuchstaben-Zeichen (32 Bytes), z. B. SHA-256-Wert oder Ed25519-Publikey |
| `hex128` | 128 hexadezimale Kleinbuchstaben-Zeichen (64 Bytes), Ed25519-Signatur |
| `enum` | genau einer der aufgezählten String-Werte |
| `object` | JSON-Objekt mit den angegebenen Feldern |
| `const` | fester Wert, MUSS exakt übereinstimmen |
| `version` | Spezifikationsversion `"MAJOR.MINOR"` (zwei Dezimalzahlen, durch `.` getrennt); Annahmeregel nach Abschnitt 10.6 |
| `open_enum` | einer der aufgezählten String-Werte ODER ein dieser Version unbekannter Wert; unbekannte Werte sind kein Schemafehler, sondern der in der Registry benannte Befund (`unknown_finding`), Abschnitt 10.6 |
| Suffix `?` | nullable: das Feld MUSS vorhanden sein, sein Wert DARF `null` sein |

Verbindliche Regeln:

- **Vollständigkeit:** Jedes für einen Eintragstyp definierte Feld MUSS im Eintrag vorhanden sein. Nicht definierte Felder DÜRFEN NICHT vorkommen. Nullable-Felder (`?`) tragen `null`, wenn kein Wert vorliegt.
- **Kanonisierung:** „JCS(x)" bezeichnet die Kanonisierung des JSON-Werts `x` nach RFC 8785 (JSON Canonicalization Scheme): Schlüssel sortiert nach UTF-16-Codeeinheiten, kürzeste Zahlendarstellung, keine unnötigen Escapes, keine Leerzeichen. Das Ergebnis sind UTF-8-Bytes.
- **Membernamen:** Ein JSON-Objekt DARF keinen Membernamen zweimal enthalten (I-JSON, RFC 7493, wie RFC 8785 es voraussetzt; verglichen werden die Namen nach Auflösung der Escapes). Ein Eintrag oder ein `manifest.json` mit doppeltem Membernamen ist `FORMAT_ERROR` (Exit 3). Er wird weder nach „letzter gewinnt“ noch nach „erster gewinnt“ gelesen; für die Hersteller-Schlüsselliste gilt Abschnitt 10.7.
- **Hex:** Alle Hex-Werte MÜSSEN Kleinbuchstaben verwenden. „Bytes(h)" bezeichnet die Dekodierung eines Hex-Strings `h` in Rohbytes.
- **Hash:** SHA-256 ist die einzige Hash-Funktion dieser Spezifikation. „Hex(x)" ist die Kleinbuchstaben-Hex-Kodierung von Bytes `x`.
- **Signaturen:** Ed25519 (RFC 8032). Signiert werden stets die UTF-8-Bytes eines JCS-kanonisierten Objekts; Signaturen werden als `hex128` kodiert, Publikeys als `hex64`.
- **Zahlen (ab Fassung 1.9 ausdrücklich):** Jede JSON-Zahl im Prüfpaket (in Einträgen einschließlich der Nutzlast unbekannter Typen, im Manifest, in der Hersteller-Schlüsselliste, in den Salt-Dateien vorgelegter Klartexte (Abschnitt 10.1) und in `verify_args.json` (Abschnitt 10.8)) MUSS eine ganze Zahl von −(2^53−1) bis 2^53−1 sein, geschrieben ohne Bruchteil und ohne Exponent (I-JSON, RFC 7493 Abschnitt 2.2; RFC 8785 setzt es voraus). Jede andere Zahl ist `FORMAT_ERROR` (Exit 3); `1.0` ist nicht `1`. Die Schreibstrecke kann nichts anderes schreiben. Das gilt auch in der Hersteller-Schlüsselliste und in den Salt-Dateien, deren übrige Mängel nur die Liste unwirksam machen (Abschnitt 10.7) oder `CONTENT_MISMATCH` sind (Abschnitt 10.1), und gleich, ob der Prüfer eine Herstellerwurzel übergibt. Diese beiden Dateiarten werden lexikalisch gelesen (jedes Zahl-Token dort, wo ein JSON-Wert beginnen kann, Zeichenketten zählen nicht), also unabhängig von anderen Mängeln derselben Datei (Stufe 4a, Abschnitt 10.5). `NaN` und `Infinity` sind kein JSON (RFC 8259): ein Syntaxfehler der Datei, kein Zahlverstoß. `-0` ist die Zahl 0.
- **Zeitarithmetik (ab Fassung 1.9):** Die Toleranzprüfungen der Abschnitte 8.2, 8.5 und 9.2 und die Fensterbedingungen des Abschnitts 8.7 rechnen in ganzen Millisekunden: Jeder Zeitpunkt wird auf ganze Millisekunden seit `0001-01-01T00:00:00Z` abgeschnitten (Stellen nach der dritten Nachkommastelle entfallen); verglichen und subtrahiert werden ganze Zahlen. Alle übrigen Zeitvergleiche (Abschnitte 7.1, 9.3, 10.7) erfolgen auf Nanosekunden. Die Schreibstrecke schreibt Millisekunden; eine ehrliche Kette berührt den Unterschied nie.

## 3. Eintrags-Envelope

Jeder Eintrag ist ein JSON-Objekt mit exakt diesen elf Feldern (Quelle: Registry `envelope_fields`):

| Feld | Typ | Beschreibung |
|---|---|---|
| `spec_version` | version `"MAJOR.MINOR"` | Version der Spezifikation, nach der der Eintrag geschrieben wurde; `MAJOR` und `MINOR` sind Dezimalzahlen ohne führende Nullen (`"1.0"`, nicht `"01.0"` oder `"1.00"`); diese Fassung schreibt `"1.9"` und nimmt ältere Minor-Versionen derselben MAJOR-Version an; Annahme anderer Versionen: Abschnitt 10.6 |
| `chain_id` | uuid | Identität der Kette; MUSS über alle Einträge einer Kette identisch sein |
| `seq` | int, min 1 | Sequenznummer; streng monoton steigend, lückenlos, beginnend bei 1 |
| `ts_captured` | rfc3339 | Wanduhrzeit der Erfassung des Ereignisses |
| `ts_chained` | rfc3339 | Wanduhrzeit der Verkettung (Schreiben des Eintrags) |
| `mono_delta_ms` | int, min −1 | monotone Millisekunden seit dem vorherigen Eintrag; `-1` = unbekannt (erster Eintrag nach Prozessstart) |
| `event_type` | open_enum | einer der Eintragstypen aus Abschnitt 4; unbekannte Typen: Abschnitt 10.6 |
| `origin` | enum | `proxy` \| `import` \| `portal` \| `system` |
| `payload` | object | typspezifische Nutzdaten, siehe Abschnitt 4 |
| `prev_hash` | hex64 | `entry_hash` des vorherigen Eintrags; bei `seq=1`: 64 Nullzeichen (`000…0`) |
| `entry_hash` | hex64 | siehe unten |

**Hash-Berechnung (normativ):**

```
entry_hash = Hex( SHA-256( JCS( Eintrag OHNE das Feld entry_hash ) ) )
```

Das heißt: Aus dem vollständigen Eintragsobjekt wird das Feld `entry_hash` entfernt, das verbleibende Objekt (zehn Felder, einschließlich `prev_hash`) wird nach RFC 8785 kanonisiert, die resultierenden UTF-8-Bytes werden mit SHA-256 gehasht.

**Verkettungsregeln:**

- `prev_hash` des Eintrags mit `seq = n` (n > 1) MUSS gleich `entry_hash` des Eintrags mit `seq = n − 1` sein.
- Der Genesis-Eintrag (`seq = 1`) MUSS `prev_hash = "000…0"` (64 Nullzeichen) tragen und MUSS vom Typ `GENESIS` sein. `GENESIS` kommt in einer Kette genau einmal vor, als erster Eintrag: Ist der erste Eintrag von anderem Typ oder steht ein `GENESIS` an anderer Stelle, ist das `FORMAT_ERROR` (Exit 3). Die übrigen Prüfungen laufen weiter und melden ihre Befunde; das Kettenende wird, wie bei jedem Formatfehler, nicht bewertet (Abschnitt 8.6).
- `seq` MUSS lückenlos sein: jede Abweichung (Lücke, Sprung, Duplikat) ist der Befund `SEQ_BREAK`; jeder Hash-Bruch ist `HASH_MISMATCH` (beide Exit 2, Abschnitt 11).
- Die Speicherung erfolgt als JSON Lines (ein Eintrag je Zeile) in Segmentdateien (Abschnitt 10.1). Der Verifier MUSS vor der Hash-Prüfung selbst kanonisieren; die abgespeicherte Byte-Reihenfolge ist nicht beweistragend.

## 4. Eintragstypen

Diese Version definiert 24 Eintragstypen (ein Eintragstyp, der hier nicht definiert ist, wird nach Abschnitt 10.6 behandelt). Neun davon sind **kritische Typen** (Registry-Attribut `critical_checkpoint`): `GENESIS`, `GAP`, `MODE_CHANGE`, `SEAL`, `OVERSIGHT`, `KEY_ROTATION`, `CONTENT_DELETED`, `CONTENT_DISCLOSED`, `LEGAL_HOLD`. Nach jedem Eintrag eines kritischen Typs MUSS der unmittelbar folgende Eintrag ein `CHECKPOINT` sein (Sofort-Checkpoint-Pflicht, Abschnitt 6).

### 4.1 GENESIS *(kritisch)*

Erster Eintrag jeder Kette (`seq = 1`) und einziger dieses Typs; an anderer Stelle ist er `FORMAT_ERROR` (Abschnitt 3). Bindet Kundenidentität, Geräteschlüssel, Lizenz und deklarierten Systemzweck an die Kette.

| Feld | Typ | Beschreibung |
|---|---|---|
| `customer_id` | string, maxlen 128 | Kundenkennung |
| `appliance_id` | uuid | Gerätekennung |
| `device_pubkey` | hex64 | Ed25519-Publikey des Geräteschlüssels |
| `device_key_id` | string, maxlen 64 | Kennung des Geräteschlüssels |
| `license_id` | string, maxlen 64 | Lizenz-Commitment: ab Fassung 1.8 `Hex(SHA-256(UTF-8(Lizenzschlüssel)))`, genau 64 Zeichen `[0-9a-f]` (unten) |
| `edition` | enum: `starter` \| `pro` \| `group` \| `enterprise` | Produktedition |
| `purpose_statement` | string, maxlen 2000 | im Onboarding deklarierter Systemzweck; deskriptiver Beleg |
| `language` | enum: `de` \| `en` | Systemsprache |
| `timezone` | string, maxlen 64 | Zeitzone (IANA-Name) |
| `predecessor_chain` | object? | Notfall-Kettennachfolge; `null` bei Erstkette. Felder: `chain_id` (uuid), `last_entry_hash` (hex64), `reason` (string, maxlen 500) |

**`license_id` ist das Commitment, nie der Schlüssel (ab Fassung 1.8).** Ein `GENESIS` DARF den Lizenzschlüssel NICHT enthalten: Der Eintrag steht in jedem Prüfpaket, und eine Kette kann ihn nie mehr ablegen. `license_id` MUSS deshalb das Commitment des Lizenzschlüssels sein: SHA-256 über seine UTF-8-Bytes, hex in Kleinbuchstaben, derselbe Wert wie `license_commitment` der Aktivierung (Heartbeat-Spezifikation §4). Er ist das Commitment zur Zeit der Kettenerzeugung; nach einem Ersatz des Schlüssels (Heartbeat-Spezifikation §4.1) weicht das aktuelle davon ab, ohne dass die Kette dadurch fehlerhaft wäre. Der Feldname bleibt, damit ältere Verifier diese Ketten weiter annehmen (Abschnitt 10.6, Regel 3). Ein `GENESIS`, dessen eigene `spec_version` 1.8 oder neuer ist und dessen `license_id` nicht aus genau 64 Zeichen `[0-9a-f]` besteht, ist `FORMAT_ERROR`. Maßgeblich ist die `spec_version` des `GENESIS`-Eintrags selbst, die im `entry_hash` gebunden ist, nicht die des Manifests.

Bis Fassung 1.7 legte diese Spezifikation den Inhalt von `license_id` nicht fest, und die Standardinstallation schrieb dort den Lizenzschlüssel im Klartext hinein. Trägt ein `GENESIS` mit `spec_version` bis 1.7 in `license_id` keinen Wert aus genau 64 Zeichen `[0-9a-f]`, MUSS der Verifier darauf hinweisen, dass dort der Lizenzschlüssel stehen kann und ihn dann jeder Inhaber des Pakets kennt. Der Hinweis ist kein Befund und ändert das Ergebnis nicht; den Wert selbst gibt der Verifier nicht aus. Ist das Paket ein Formatfehler (Exit 3), entfällt der Hinweis wie jede weitere Aussage über die Kette (Abschnitt 8.6); der Prüfer fordert ein sauberes Paket an. In der JSON-Ausgabe steht er beim Go-Verifier als `stats.genesis_license_not_commitment` (nur wenn zutreffend), beim Zweitverifier als `genesis_license_not_commitment` auf oberster Ebene (`true`, `false` oder bei Exit 3 `null`). Eine Appliance, die von 1.7 auf 1.8 wechselt, behält ihren `GENESIS` und damit den Hinweis; der Hersteller ersetzt den Schlüssel (Heartbeat-Spezifikation §4.1).

### 4.2 AI_CALL

Ein aufgezeichneter KI-Aufruf (Proxy-Erfassung oder passiver Import). Inhalte erscheinen nie im Klartext, nur als Commitments (Abschnitt 9).

| Feld | Typ | Beschreibung |
|---|---|---|
| `provider_class` | enum, siehe 4.25 | Anbieter-Klasse |
| `route` | string, maxlen 200 | konfigurierte Route |
| `model` | string?, maxlen 200 | vom Verkehr gemeldete Modellkennung |
| `endpoint` | string, maxlen 400 | angesprochener Endpunkt |
| `http_status` | int, 0 bis 599 | HTTP-Status; 0 = kein Status |
| `outcome` | enum: `ok` \| `error` \| `upstream_error` \| `aborted` | Ergebnis |
| `duration_ms` | int, min 0 | Dauer |
| `request_bytes` | int, min 0 | Anfragegröße |
| `response_bytes` | int, min 0 | Antwortgröße |
| `tokens_in` | int?, min 0 | Eingabe-Token, falls bekannt |
| `tokens_out` | int?, min 0 | Ausgabe-Token, falls bekannt |
| `streamed` | bool | Streaming-Antwort |
| `confidence` | enum: `recorded` \| `claimed` | `recorded` = vom Proxy erfasst; `claimed` = von Anbieter/Importquelle behauptet |
| `source_id` | string?, maxlen 128 | Importquellen-Kennung; `null` bei Proxy |
| `source_ref` | string?, maxlen 256 | Kennung innerhalb der Quelle (Idempotenz) |
| `mode` | enum: `full` \| `hash_only` | Erfassungsmodus |
| `request_commitment` | hex64? | HMAC-SHA-256(salt, Anfrage-Klartext); Salt beim Tresor-Objekt |
| `response_commitment` | hex64? | HMAC-SHA-256(salt, Antwort-Klartext) |
| `vault_ref` | string?, maxlen 128 | Referenz auf das Tresor-Objekt |

### 4.3 TICK

Lebenszeichen der Schreibstrecke, alle 5 Minuten (Abschnitt 8.1).

| Feld | Typ | Beschreibung |
|---|---|---|
| `uptime_s` | int, min 0 | Prozess-Uptime |
| `spool_backlog` | int, min 0 | Spool-Rückstau (Einträge) |
| `disk_pct` | int, 0 bis 100 | Plattenfüllstand |

### 4.4 GAP *(kritisch)*

Ehrlich ausgewiesene Erfassungslücke: ein Zeitfenster, in dem Ereignisse fehlen können. Deckt ein Stillefenster (Abschnitt 8.2) und nimmt beantwortete Aufrufe auf, die nicht in der Kette stehen (Abschnitt 8.7).

| Feld | Typ | Beschreibung |
|---|---|---|
| `reason` | enum, siehe 4.25 | Lückenklasse |
| `started_ts` | rfc3339 | Beginn des Fensters (einschließlich) |
| `ended_ts` | rfc3339 | Ende des Fensters (einschließlich) |
| `lost_count` | int, min −1 | verlorene Ereignisse; `-1` = unbekannt |
| `detail` | string?, maxlen 500 | Freitext-Detail |

**Fenster (ab Fassung 1.9, Ergänzung vom 02.10.2026).** `started_ts` und `ended_ts` sind Zeitpunkte der Wanduhr der Appliance, derselben, die `ts_chained` schreibt. Ein Aufruf liegt im Fenster, wenn die Zeit von seiner Entgegennahme bis zu seinem Antwortende das Fenster berührt (Abschnitt 8.7). Das Fenster kann deshalb vor dem letzten Eintrag vor der Stille beginnen, die es deckt. Es enthält nicht notwendig den `ts_captured` jedes Aufrufs, der fehlen kann: Dieser liegt höchstens um die Dauer des Aufrufs vor `started_ts`; ein Abgleich nach Abschnitt 4.6 über ein solches Fenster erweitert es um die längste Aufrufdauer nach vorn. Der Verifier prüft das Fenster nur nach Abschnitt 8.2.

### 4.5 SOURCE_GAP

Ausgewiesene Lücke einer Importquelle (Quell-Sequenzlücke, fehlender Abrufzeitraum).

| Feld | Typ | Beschreibung |
|---|---|---|
| `source_id` | string, maxlen 128 | Quellkennung |
| `window_start` | rfc3339 | Fensterbeginn |
| `window_end` | rfc3339 | Fensterende |
| `expected` | int?, min 0 | erwartete Ereignisse, falls bekannt |
| `observed` | int, min 0 | beobachtete Ereignisse |
| `detail` | string?, maxlen 500 | Freitext-Detail |

### 4.6 RECONCILIATION

Abgleich verketteter Zählwerte gegen Anbieter-Angaben (Usage-API). Antwort auf Schleusen-Umgehung/Schatten-Nutzung.

| Feld | Typ | Beschreibung |
|---|---|---|
| `source_id` | string, maxlen 128 | Quellkennung |
| `window_start` | rfc3339 | Fensterbeginn |
| `window_end` | rfc3339 | Fensterende |
| `reported_count` | int, min 0 | vom Anbieter gemeldet |
| `chained_count` | int, min 0 | in der Kette vorhanden |
| `delta` | int | Differenz (`reported_count − chained_count`) |

### 4.7 CLOCK_JUMP

Deklarierter Sprung der Wanduhr (Abschnitt 8.5, 9.2).

| Feld | Typ | Beschreibung |
|---|---|---|
| `wall_before` | rfc3339 | Wanduhr vor dem Sprung |
| `wall_after` | rfc3339 | Wanduhr nach dem Sprung |
| `mono_delta_ms` | int, min 0 | monotone Dauer über den Sprung |
| `jump_ms` | int | Sprungweite (negativ = Rückstellung) |

### 4.8 MODE_CHANGE *(kritisch)*

Wechsel des Erfassungsmodus (`full` ↔ `hash_only`).

| Feld | Typ | Beschreibung |
|---|---|---|
| `from` | enum: `full` \| `hash_only` | vorheriger Modus |
| `to` | enum: `full` \| `hash_only` | neuer Modus |
| `cause` | enum: `manual` \| `disk_pressure` | Auslöser |
| `actor` | string?, maxlen 128 | handelnde Person, falls manuell |

### 4.9 RESTART

Neustart der Schreibstrecke.

| Feld | Typ | Beschreibung |
|---|---|---|
| `reason` | enum: `crash_recovery` \| `self_terminate` \| `update` \| `manual` \| `unknown` | Neustartgrund |
| `downtime_ms_estimate` | int, min −1 | geschätzte Ausfallzeit: von `ts_chained` des letzten erhaltenen Eintrags des vorigen Prozesses bis zu diesem `RESTART`, nicht ab dem Beginn eines folgenden `GAP`-Fensters (Abschnitt 8.7); `-1` = unbekannt |
| `version` | string, maxlen 40 | Softwareversion nach Neustart |

### 4.10 SEAL *(kritisch)*

Geplante Versiegelung der Kette (Update, Shutdown, Stilllegung, Export). Beginn eines Handovers (Abschnitt 8.4) oder, wenn kein `RESUME` folgt, regulärer Abschluss der Kette (Abschnitt 8.6).

| Feld | Typ | Beschreibung |
|---|---|---|
| `version` | string, maxlen 40 | versiegelnde Softwareversion |
| `reason` | enum: `update` \| `shutdown` \| `key_loss` \| `decommission` \| `export` | Versiegelungsgrund |

`export` (ab Fassung 1.9) ist das **Export-Siegel**: Die laufende Anlage versiegelt die Kette für ein Prüfpaket, und derselbe Schreiber setzt sie unmittelbar mit `RESUME` fort (Abschnitt 8.4). Ein Paket, das am Sofort-Checkpoint dieses Siegels endet, ist versiegelt (Abschnitt 8.6). Ein Verifier bis Fassung 1.8 kennt den Wert nicht (Abschnitt 8.6, „Ältere Verifier“).

### 4.11 RESUME

Wiederaufnahme nach einem SEAL. Schließt den Handover.

| Feld | Typ | Beschreibung |
|---|---|---|
| `prev_version` | string, maxlen 40 | Version vor dem SEAL |
| `new_version` | string, maxlen 40 | Version nach Wiederaufnahme |
| `sealed_entry_hash` | hex64 | MUSS gleich `entry_hash` des SEAL-Eintrags sein, an den angeknüpft wird |

### 4.12 OVERSIGHT *(kritisch)*

Menschliches Aufsichts-Ereignis (Freigabe, Ablehnung, Eskalation), eingereicht über das Portal.

| Feld | Typ | Beschreibung |
|---|---|---|
| `action` | enum: `approval` \| `rejection` \| `escalation` | Aufsichts-Handlung |
| `user` | string, maxlen 128 | handelnde Person |
| `role` | string, maxlen 64 | Rolle |
| `reference` | string, maxlen 256 | Gegenstand der Entscheidung (z. B. Ketten-`seq`, Fallkennung) |
| `justification` | string, maxlen 4000 | Begründung |

### 4.13 ALARM

Regelbasierter Alarm (keine KI im Produkt).

| Feld | Typ | Beschreibung |
|---|---|---|
| `rule_id` | enum, siehe 4.25 | Alarmregel |
| `severity` | enum: `info` \| `warning` \| `critical` | Schweregrad |
| `message_key` | string, maxlen 128 | i18n-Schlüssel |
| `details` | string?, maxlen 1000 | Details |
| `delivered_smtp` | bool | per SMTP zugestellt |

### 4.14 CONFIG_CHANGE

Konfigurationsänderung einschließlich Onboarding-Schritten.

| Feld | Typ | Beschreibung |
|---|---|---|
| `scope` | enum: `onboarding` \| `source` \| `rule` \| `alarm` \| `smtp` \| `tls` \| `system` \| `compliance_signoff` | Bereich |
| `key` | string, maxlen 128 | Konfigurationsschlüssel |
| `value_commitment` | hex64? | Commitment des neuen Werts, wenn der Wert selbst sensibel ist |
| `summary` | string?, maxlen 500 | Zusammenfassung |
| `actor` | string, maxlen 128 | handelnde Person |
| `step_id` | string?, maxlen 64 | Onboarding-Schrittkennung (Dauermessung) |

### 4.15 KEY_ROTATION *(kritisch)*

Rotation des Geräteschlüssels; der alte Schlüssel beglaubigt den neuen (Vertrauenskette, Abschnitt 6.4).

| Feld | Typ | Beschreibung |
|---|---|---|
| `old_key_id` | string, maxlen 64 | alter Schlüssel |
| `new_key_id` | string, maxlen 64 | neuer Schlüssel |
| `new_pubkey` | hex64 | Publikey des neuen Schlüssels |
| `signature_by_old_key` | hex128 | Ed25519 des ALTEN Schlüssels über `JCS({old_key_id, new_key_id, new_pubkey})` |

### 4.16 REPORT_ISSUED

Erzeugter Bericht, an die Kette gebunden über Datei-Hashes und Datenstand.

| Feld | Typ | Beschreibung |
|---|---|---|
| `report_type` | enum: `monthly` \| `quarterly` \| `audit` | Berichtstyp |
| `period_start` | rfc3339 | Berichtszeitraum Beginn |
| `period_end` | rfc3339 | Berichtszeitraum Ende |
| `tree_size` | int, min 0 | Datenstand des Berichts |
| `html_hash` | hex64 | SHA-256 der HTML-Fassung |
| `pdf_hash` | hex64? | SHA-256 der PDF-Fassung; `null`, wenn nur HTML erzeugt wurde |
| `renderer_version` | string, maxlen 64 | Renderer-Version |
| `languages` | string, maxlen 16 | erzeugte Sprachen (z. B. `de,en`) |

### 4.17 CONTENT_DELETED *(kritisch)*

Fristgerechte oder angeordnete Löschung eines Tresor-Inhalts bei intakter Kette: beweist, DASS und WANN gelöscht wurde.

| Feld | Typ | Beschreibung |
|---|---|---|
| `target_seq` | int, min 1 | `seq` des betroffenen Eintrags |
| `vault_ref` | string, maxlen 128 | gelöschtes Tresor-Objekt |
| `reason` | enum: `retention` \| `dsgvo_request` \| `manual` | Löschgrund |
| `actor` | string, maxlen 128 | handelnde Person |

### 4.18 CONTENT_DISCLOSED *(kritisch)*

Herausgabe des Klartexts eines Tresor-Inhalts an eine Person (Audit, Auskunftsersuchen, Vorfall, manuelle Einsicht) bei intakter Kette: hält fest, WANN, an WEN und WARUM eine Herausgabe eines gespeicherten Inhalts eingeleitet wurde. Der Eintrag trägt KEINEN Klartext und KEIN Commitment-Material, nur die Zurechnung und die Größen der herausgegebenen Teile.

| Feld | Typ | Beschreibung |
|---|---|---|
| `target_seq` | int, min 1 | `seq` des offengelegten Eintrags |
| `vault_ref` | string, maxlen 128 | offengelegtes Tresor-Objekt |
| `actor` | string, maxlen 128 | handelnde Person (aus der Sitzung, nie aus dem Formular) |
| `role` | string, maxlen 64 | Rolle der handelnden Person zum Zeitpunkt der Offenlegung |
| `reason` | enum: `audit` \| `dsgvo_request` \| `incident` \| `manual` | Offenlegungsgrund |
| `request_bytes` | int, min 0 | Größe des herausgegebenen Anfrage-Klartexts in Bytes |
| `response_bytes` | int, min 0 | Größe des herausgegebenen Antwort-Klartexts in Bytes |

**Beweis vor Offenlegung.** LEDGER MUSS den `CONTENT_DISCLOSED`-Eintrag verketten (einschließlich des Sofort-Checkpoints nach Abschnitt 6.2), BEVOR es den Klartext herausgibt. Scheitert das Verketten, DARF der Klartext NICHT herausgegeben werden. Damit gibt es keine Offenlegung, die die Kette nicht kennt. Die Umkehrung gilt NICHT: ein `CONTENT_DISCLOSED`-Eintrag beweist nicht, dass der Klartext den Empfänger erreicht hat (Sofort-Checkpoint gescheitert, Antwort nicht zugestellt, Absturz dazwischen); er beweist, dass eine Herausgabe mit dieser Zurechnung eingeleitet wurde.

Eine Offenlegung ist kein Befund des Verifiers: ein gültiger `CONTENT_DISCLOSED`-Eintrag mit Sofort-Checkpoint erzeugt keine Befundklasse (Exit 0). Fehlt der Sofort-Checkpoint, gilt `MISSING_CHECKPOINT` (Exit 2) wie bei jedem kritischen Typ.

### 4.19 ADMIN

Wörtliche Selbstprotokollierung jeder an den Hersteller gesendeten Nachricht.

| Feld | Typ | Beschreibung |
|---|---|---|
| `message_type` | enum: `activation` \| `heartbeat` \| `anchor` | Nachrichtentyp |
| `payload_canonical` | string, maxlen 16000 | die exakt gesendeten JCS-Bytes, wörtlich als String |
| `payload_hash` | hex64 | SHA-256 über `payload_canonical` |

### 4.20 CHECKPOINT

Signierter Baumkopf (Signed Tree Head); Details in Abschnitt 6.

| Feld | Typ | Beschreibung |
|---|---|---|
| `tree_size` | int, min 1 | Zahl der abgedeckten Blätter = alle Einträge mit `seq` kleiner als `seq` dieses Eintrags |
| `merkle_root` | hex64 | Merkle-Wurzel über die Blätter 1…`tree_size` (Abschnitt 5) |
| `prev_checkpoint_hash` | hex64 | `entry_hash` des vorherigen CHECKPOINT-Eintrags; 64 Nullzeichen beim ersten |
| `key_id` | string, maxlen 64 | signierender Geräteschlüssel |
| `signature` | hex128 | Ed25519 des Geräteschlüssels, Signaturgegenstand siehe Abschnitt 6.1 |

### 4.21 CHECKPOINT_RECEIPT

Gegensignatur (Quittung) des Hersteller-Servers über einen verankerten Checkpoint; Details in Abschnitt 7.1.

| Feld | Typ | Beschreibung |
|---|---|---|
| `checkpoint_seq` | int, min 1 | `seq` des quittierten CHECKPOINT-Eintrags |
| `tree_size` | int, min 1 | quittierte Baumgröße; MUSS dem Checkpoint entsprechen |
| `merkle_root` | hex64 | quittierte Wurzel; MUSS dem Checkpoint entsprechen |
| `server_ts` | rfc3339 | Serverzeit der Quittung |
| `server_key_id` | string, maxlen 64 | Hersteller-Schlüsselkennung |
| `server_signature` | hex128 | Ed25519 des Hersteller-Schlüssels, Signaturgegenstand siehe Abschnitt 7.1 |

### 4.22 TIME_ANCHOR

Zeitstempel einer unabhängigen Zeitstempelstelle (RFC 3161) über einen Checkpoint; Details und Prüfregeln in Abschnitt 7.3.

| Feld | Typ | Beschreibung |
|---|---|---|
| `checkpoint_seq` | int, min 1 | `seq` des bezeugten CHECKPOINT-Eintrags |
| `tree_size` | int, min 1 | bezeugte Baumgröße; MUSS dem Checkpoint entsprechen |
| `merkle_root` | hex64 | bezeugte Wurzel; MUSS dem Checkpoint entsprechen |
| `tsa_name` | string, maxlen 256 | die vom Kunden eingerichtete Stelle; beschreibend, nicht beweistragend |
| `tsa_policy` | string, maxlen 128 | `policy`-OID aus dem Token; MUSS dem Token entsprechen |
| `tsa_serial` | string, maxlen 128 | `serialNumber` aus dem Token, Kleinbuchstaben-Hex; MUSS dem Token entsprechen |
| `tsa_ts` | rfc3339 | `genTime` aus dem Token im Zeitformat aus Abschnitt 2; MUSS dem Token entsprechen |
| `token_base64` | string, maxlen 21848 | der DER-kodierte TimeStampToken (RFC 3161), base64; das DER MUSS ≤ 16384 Bytes sein |

Die vier `tsa_*`-Felder sind **Ablesungen aus dem Token**, keine zweite Quelle: sie machen die Kette ohne ASN.1-Parser lesbar. Beweistragend ist allein `token_base64`. Widerspricht eine Ablesung dem Token, ist das der Befund `TIME_ANCHOR_INVALID`, nicht die Übernahme des einen oder des anderen Wertes.

TIME_ANCHOR ist **kein kritischer Typ**: er folgt einem Checkpoint, er löst keinen aus.

### 4.23 CAPTURE_TRUNCATED

Die Schleuse reicht jeden Body vollständig weiter, schneidet aber nur dessen erste `max_body_bytes` Bytes mit (Mitschnittgrenze). Wurde ein Body dabei gekürzt, folgt dem `AI_CALL` dieser Eintrag. `request_bytes` und `response_bytes` des AI_CALL bleiben die echten Größen; `request_commitment`, `response_commitment` und der Tresor-Inhalt beziehen sich auf die mitgeschnittenen Bytes.

| Feld | Typ | Beschreibung |
|---|---|---|
| `target_seq` | int, min 1 | `seq` des AI_CALL-Eintrags, dessen Mitschnitt gekürzt wurde |
| `request_bytes_captured` | int, min 0 | mitgeschnittene Bytes der Anfrage; so viele decken Commitment und Tresor-Inhalt ab |
| `response_bytes_captured` | int, min 0 | mitgeschnittene Bytes der Antwort; ebenso |
| `request_truncated` | bool | die Anfrage wurde gekürzt |
| `response_truncated` | bool | die Antwort wurde gekürzt |

Der Erzeuger SOLL den Eintrag unmittelbar nach dem AI_CALL verketten. Gelingt das nicht, fehlt er: Ein AI_CALL ohne diesen Eintrag ist deshalb kein Beweis, dass nicht gekürzt wurde; ist `request_bytes` oder `response_bytes` größer als die Mitschnittgrenze, bleibt die Kürzung erkennbar. CAPTURE_TRUNCATED ist **kein kritischer Typ** und **kein Befund**: Der Aufruf selbst ist vollständig verkettet, gekürzt ist nur der Mitschnitt. Verifier prüfen das Schema. Eingeführt mit Fassung 1.5; ein Verifier der Fassung 1.4 meldet den Typ als `UNKNOWN_ENTRY_TYPE` (Abschnitt 10.6, Regel 2) und prüft die Kette sonst vollständig.

### 4.24 LEGAL_HOLD *(kritisch)*

Setzen oder Aufheben einer Löschsperre (Legal Hold) über gespeicherte Inhalte. Beweist, DASS, WANN, WOFÜR und durch WEN eine Sperre bestand (Abschnitt 9.3). Eingeführt mit Fassung 1.7; ein Verifier der Fassung 1.6 meldet den Typ als `UNKNOWN_ENTRY_TYPE` (Abschnitt 10.6, Regel 2) und prüft die Kette sonst vollständig.

| Feld | Typ | Beschreibung |
|---|---|---|
| `action` | enum: `set` \| `release` | Sperre setzen oder aufheben |
| `hold_id` | string, maxlen 64 | Kennung der Sperre; ein `release` nennt die `hold_id` einer gesetzten Sperre |
| `scope_from` | rfc3339 | frühester erfasster Erfassungszeitpunkt (`ts_captured`); unbegrenzt: `0001-01-01T00:00:00.000Z` |
| `scope_to` | rfc3339 | spätester erfasster Erfassungszeitpunkt; unbegrenzt: `9999-12-31T23:59:59.000Z` |
| `reference` | string, maxlen 200 | Anlass oder Aktenzeichen |
| `actor` | string, maxlen 128 | handelnde Person |

### 4.25 Referenzierte Enumerationen

**Anbieter-Klassen (`provider_classes`):** `openai`, `anthropic`, `azure_openai`, `google`, `aws_bedrock`, `mistral`, `aleph_alpha`, `ionos`, `ollama`, `vllm`, `other_us`, `other_eu`, `other_local`, `generic`. (Klassen von Anbietern/Betriebsformen, keine Modellkennungen.)

**Lückenklassen (`gap_classes`):** `bypass`, `proxy_restart`, `power_loss`, `spool_unwritable`, `host_down`, `update`, `manual`.

**Alarmregeln (`alarm_rules`):** `source_silence`, `volume_spike`, `error_rate_spike`, `new_provider_class`, `spool_backlog`, `disk_85`, `disk_92`, `disk_97`, `cert_expiry`, `anchor_overdue`, `report_missing`, `report_delivery_failed`, `component_silence`, `test_alarm`.

## 5. Merkle-Baum (RFC 6962)

Alle Einträge einer Kette sind, in `seq`-Reihenfolge, die Blätter eines fortlaufenden Merkle-Baums nach RFC 6962 mit Domain-Separation:

```
Blatt(n)          = SHA-256( 0x00 || Bytes(entry_hash des Eintrags mit seq = n) )
Knoten(L, R)      = SHA-256( 0x01 || L || R )
```

`0x00` und `0x01` sind einzelne Präfix-Bytes; `Bytes(…)` sind die 32 Rohbytes des dekodierten `entry_hash`. Das Blatt-Input ist also stets 33 Bytes, das Knoten-Input 65 Bytes.

**Wurzelberechnung (Merkle Tree Hash, RFC 6962 § 2.1):** Für eine Blattliste `D[0..n)` (Blatt `D[i]` gehört zu `seq = i + 1`):

- `MTH({d}) = SHA-256(0x00 || d)` für n = 1,
- `MTH(D[0..n)) = SHA-256(0x01 || MTH(D[0..k)) || MTH(D[k..n)))` für n > 1, wobei `k` die größte Zweierpotenz kleiner als `n` ist.

**tree_size-Semantik:** Ein Baum der Größe `t` umfasst exakt die Einträge `seq = 1 … t`, einschließlich früherer CHECKPOINT-, CHECKPOINT_RECEIPT- und aller übrigen Einträge. `merkle_root` eines Checkpoints mit `tree_size = t` ist `Hex(MTH über die Blätter 1…t))`.

**Inklusionsbeweise** (RFC 6962 § 2.1.1) belegen, dass ein Eintrag Blatt eines Baums gegebener Wurzel ist. **Konsistenzbeweise** (RFC 6962 § 2.1.2) belegen, dass ein Baum der Größe `t1` ein Präfix eines Baums der Größe `t2 ≥ t1` ist. Der Verifier MUSS für **jedes Paar** verankerter Wurzeln `(t1, r1)`, `(t2, r2)` mit `t1 ≤ t2` prüfen, dass `r1` konsistent zu `r2` ist (bei `t1 = t2`: Gleichheit). Da der Verifier das Prüfpaket vollständig vorliegen hat, KANN er die Beweise selbst aus den Blättern berechnen; eine Verletzung ist der Befund `MERKLE_INCONSISTENT` (Exit 2).

## 6. Checkpoints

### 6.1 Signaturgegenstand

Ein `CHECKPOINT`-Eintrag (Abschnitt 4.20) trägt eine Ed25519-Signatur des Kunden-Geräteschlüssels. Der Signaturgegenstand ist **exakt**:

```
JCS({ "chain_id": …, "tree_size": …, "merkle_root": …,
      "prev_checkpoint_hash": …, "key_id": …, "ts": … })
```

mit:

- `chain_id` = `chain_id` des Envelopes,
- `tree_size`, `merkle_root`, `prev_checkpoint_hash`, `key_id` = gleichnamige Payload-Felder,
- `ts` = **`ts_chained` des CHECKPOINT-Eintrags** (String, unverändert).

Nach RFC 8785 ergibt sich die kanonische Schlüsselreihenfolge `chain_id, key_id, merkle_root, prev_checkpoint_hash, tree_size, ts`. Beispiel des kanonischen Signaturgegenstands (eine Zeile):

```
{"chain_id":"6f0f…","key_id":"dev-2026-01","merkle_root":"ab12…","prev_checkpoint_hash":"0000…","tree_size":41,"ts":"2026-08-28T09:05:00.000Z"}
```

`tree_size` MUSS gleich `seq − 1` des CHECKPOINT-Eintrags sein (der Checkpoint deckt alle vorangehenden Einträge ab; er selbst wird erst vom nächsten Checkpoint abgedeckt). Eine ungültige Signatur ist der Befund `SIG_INVALID` (Exit 2).

### 6.2 Auslöser

Der Kettenschreiber MUSS einen Checkpoint schreiben:

1. spätestens alle **5 Minuten** (sofern seit dem letzten Checkpoint mindestens ein Eintrag hinzukam), ODER
2. spätestens alle **1.000 Einträge**, ODER
3. **sofort** nach jedem Eintrag eines kritischen Typs (`GENESIS`, `GAP`, `MODE_CHANGE`, `SEAL`, `OVERSIGHT`, `KEY_ROTATION`, `CONTENT_DELETED`, `CONTENT_DISCLOSED`, `LEGAL_HOLD`): der unmittelbar folgende Eintrag MUSS der Checkpoint sein.

Regel 3 gilt ausnahmslos und schließt `SEAL` ausdrücklich ein: auch nach einem `SEAL` MUSS der unmittelbar folgende Eintrag dessen Sofort-Checkpoint sein. Dieser Checkpoint ist zugleich der einzige Eintrag, der zwischen `SEAL` und `RESUME` stehen darf (Abschnitt 8.4); beide Regeln greifen damit widerspruchsfrei ineinander. Folgt auf einen kritischen Eintrag ein anderer Eintrag als sein Checkpoint, ist das der Befund `MISSING_CHECKPOINT` (Exit 2, Abschnitt 10.4). Ist der kritische Eintrag dagegen der letzte Eintrag der Kette, fehlt kein Eintrag zwischen zwei vorhandenen, sondern das Kettenende ist nicht verankert: Das ist ab Fassung 1.6 kein `MISSING_CHECKPOINT`, sondern der Status „unvollständig“ (`UNSEALED_END`, Abschnitt 8.6). So endet auch eine ehrliche Kette, deren Schreiber zwischen dem kritischen Eintrag und seinem Checkpoint ausfiel.

### 6.3 Checkpoint-Verkettung

Checkpoints bilden über `prev_checkpoint_hash` eine eigene Unterkette: `prev_checkpoint_hash` MUSS gleich `entry_hash` des vorherigen CHECKPOINT-Eintrags sein; der erste Checkpoint der Kette trägt 64 Nullzeichen. Damit ist auch die Checkpoint-Historie lückenlos prüfbar, unabhängig von der Haupt-Hash-Kette.

### 6.4 KEY_ROTATION-Vertrauenskette

Der signierende Schlüssel eines Checkpoints (`key_id`) MUSS entweder der im `GENESIS` registrierte Geräteschlüssel sein oder über eine lückenlose Folge von `KEY_ROTATION`-Einträgen auf ihn zurückführbar sein: Jede `KEY_ROTATION` trägt `signature_by_old_key` = Ed25519-Signatur des **alten** Schlüssels über

```
JCS({ "old_key_id": …, "new_key_id": …, "new_pubkey": … })
```

(kanonische Reihenfolge: `new_key_id, new_pubkey, old_key_id`). Der Verifier MUSS diese Signatur gegen den bis dahin gültigen Publikey prüfen und ab dem KEY_ROTATION-Eintrag (einschließlich dessen Sofort-Checkpoint) den neuen Publikey verwenden. Vor dem KEY_ROTATION-Eintrag gilt ausschließlich der bisherige Publikey: je Position der Kette ist genau ein Geräteschlüssel gültig, und ein Checkpoint, der vor der Rotation schon mit dem neuen oder nach ihr noch mit dem alten Schlüssel signiert ist, ist `SIG_INVALID` (Klarstellung 2026-09-03). Checkpoints, die mit einem nicht derart legitimierten Schlüssel signiert sind, sind `SIG_INVALID`.

## 7. Verankerung

Verankerung bindet Baumwurzeln an Instanzen außerhalb der Kontrolle des Schlüsselinhabers. Fehlt jede Verankerung, meldet der Verifier `NO_ANCHOR` (Exit 1); eine Quittung zählt dabei nur, wenn ihre Signatur trägt (Abschnitt 7.1). Die Kette bleibt in sich gültig, aber gegen Neuschreiben durch den Schlüsselinhaber schwächer belegt (Abschnitt 11).

### 7.1 Cloud-Gegensignatur (CHECKPOINT_RECEIPT)

Die Appliance sendet `{chain_id, tree_size, merkle_root}` an den Hersteller-Server; dieser antwortet mit einer Ed25519-Gegensignatur unter Serverzeit. Der Signaturgegenstand ist **exakt**:

```
JCS({ "chain_id": …, "tree_size": …, "merkle_root": …, "server_ts": … })
```

(kanonische Reihenfolge: `chain_id, merkle_root, server_ts, tree_size`). Die Quittung wird als `CHECKPOINT_RECEIPT`-Eintrag (Abschnitt 4.21) zurück in die Kette geschrieben. Prüfregeln:

- `server_signature` MUSS gegen den Hersteller-Publikey zu `server_key_id` validieren, sonst `RECEIPT_INVALID` (Exit 2). Welcher Publikey das ist, bestimmt die folgende Regel zur Herkunft des Schlüssels, nicht das Prüfpaket allein.
- Jede Quittung, deren Signatur trägt, MUSS zu einem Präfix der vorliegenden Kette passen: die Wurzel zur quittierten `tree_size`, aus den Blättern neu berechnet, MUSS gleich `merkle_root` der Quittung sein. Passt sie zu keiner Präfix-Historie, ist das `FORK_DETECTED` (Exit 2), der stärkste Hinweis auf eine Zweitgeschichte. Eine Quittung, deren Signatur nicht trägt, ist bereits `RECEIPT_INVALID`; an ihr wird nichts weiter geprüft, denn ihr Inhalt ist keine Aussage des Herstellers.
- Passt die Quittung zu einem Präfix, MÜSSEN `tree_size` und `merkle_root` außerdem mit dem referenzierten Checkpoint (`checkpoint_seq`) übereinstimmen; verweist `checkpoint_seq` auf keinen CHECKPOINT oder weicht er ab, ist das `RECEIPT_INVALID` (Exit 2). Bei einem Fork unterbleibt diese Prüfung, damit der Fork als seine eigene Klasse erscheint und nicht mit Folgebefunden.
- `server_ts` liefert eine externe Zeitobergrenze: der quittierte Baumzustand existierte spätestens zu `server_ts`.

**Herkunft des Hersteller-Schlüssels (Verifier ab Fassung 1.4).** Die Regel gilt für **jedes** Paket, gleich welche `spec_version` es erklärt (wie Regel 5 in Abschnitt 10.6): Ein Fälscher, der eine ältere Version erklärt, entgeht ihr nicht. Das Prüfpaket wird von genau der Partei geschrieben, die die Quittung binden soll. Ein Schlüssel aus `manifest.vendor_pubkeys` oder `keys/vendor/` belegt daher nur, dass *irgendjemand* die Wurzel signiert hat: Wer eine Kette neu schreibt, kann ein Schlüsselpaar erfinden, damit „Quittungen" signieren und den Publikey ins Manifest schreiben. Der Vertrauensanker MUSS deshalb vom PRÜFER kommen, dieselbe Regel wie beim Zeitzeugen (Abschnitt 7.3). Ein Verifier MUSS dem Prüfer zwei Wege anbieten und DARF keinen dritten aus dem Paket ableiten:

1. **Herstellerwurzel.** Der Offline-Wurzelschlüssel des Herstellers als `{"wurzel_id", "pubkey"}` (Abschnitt 10.7), veröffentlicht mit der Lizenz; ein Verifier-Build des Herstellers KANN ihn eingebaut tragen und MUSS das bei der Versionsausgabe nennen. Die Wurzel bürgt für Gegenzeichnungsschlüssel über die signierte Liste `keys/vendor/schluesselliste.json` im Paket (Abschnitt 10.7).
2. **Angehefteter Schlüssel.** Ein einzelnes Paar `key_id` = Publikey, das der Prüfer selbst beschafft hat.

Nennt der Prüfer zwei Wurzeln derselben `wurzel_id` oder zwei Anheftungen derselben `key_id` mit verschiedenen Publikeys (auch gegenüber einer eingebauten Wurzel), ist die Prüfumgebung mehrdeutig; der Verifier MUSS den Aufruf ablehnen (Exit 3) und DARF NICHT stillschweigend einen der beiden wählen.

Für jede Quittung bestimmt der Verifier den Schlüssel in dieser Reihenfolge:

- Ist `server_key_id` angeheftet, gilt der angeheftete Publikey. Die Signatur wird gegen **ihn** geprüft, nicht gegen die Kopie im Manifest; scheitert sie, ist das `RECEIPT_INVALID` (Exit 2). Die Anheftung hat Vorrang vor der Liste, auch vor deren Gültigkeitsfenster: Wer anheftet, trifft die Aussage über den Schlüssel selbst.
- Sonst: Führt das Paket eine Liste, deren Signatur gegen eine Wurzel des Prüfers trägt (Abschnitt 10.7), und nennt sie `server_key_id`, gilt der Publikey der Liste; die Kopie im Manifest ist dann ohne Belang. `RECEIPT_INVALID` (Exit 2) ist es, wenn die Signatur gegen ihn scheitert oder wenn `server_ts` außerhalb des Gültigkeitsfensters des Schlüssels liegt (`gueltig_ab` ≤ `server_ts`; `server_ts` < `gueltig_bis`, falls vorhanden; `server_ts` < `widerrufen_ab`, falls vorhanden). Im zweiten Fall widerspricht die signierte Aussage des Herstellers der Quittung. `server_ts` wird dabei nach der Grammatik von Abschnitt 10.7 gelesen; ein `server_ts`, der sich so nicht lesen lässt, liegt in keinem Fenster.
- Sonst gilt der Publikey aus dem Manifest. Trägt die Signatur, meldet der Verifier `RECEIPT_UNVERIFIED` (Exit 1), **einmal je `server_key_id`**, mit `key_id` und Publikey im Bericht, damit der Prüfer den Schlüssel außerhalb des Pakets nachschlagen kann. Scheitert sie oder fehlt der Schlüssel im Manifest, bleibt es `RECEIPT_INVALID` (Exit 2).

Eine Liste, die nicht trägt (keine Wurzel beigebracht, andere `wurzel_id`, Signatur scheitert, Format verletzt), macht keinen Schlüssel glaubwürdig; sie ist aber auch **kein Fälschungsbefund**, denn die Liste steht in keiner Hash-Kette. Die betroffenen Quittungen sind dann `RECEIPT_UNVERIFIED`, und der Bericht nennt den Grund. Ebenso ein Schlüssel, der in einer tragenden Liste fehlt: Die Liste kann älter sein als der Schlüssel.

Die Trennung zwischen `RECEIPT_INVALID` und `RECEIPT_UNVERIFIED` folgt Abschnitt 7.3: Eine Signatur, die nicht trägt, oder eine signierte Aussage des Herstellers, die der Quittung widerspricht, ist ein Befund über die **Kette**. Ein fehlender Anker ist eine Aussage über die **Prüfumgebung**. Das Beste, was eine Fälschung mit erfundenem Schlüssel erreicht, ist damit ein benannter Befund mit Exit 1, nie Exit 0.

**Was als Verankerung zählt.** Eine Quittung, deren Signatur gegen den nach dieser Regel bestimmten Schlüssel trägt, zählt als vorhandene externe Verankerung, auch unter `RECEIPT_UNVERIFIED`, so wie ein Zeitzeuge unter `TIME_ANCHOR_UNVERIFIED` (Abschnitt 7.3); `NO_ANCHOR` sagt dann nichts Zusätzliches. Eine Quittung mit `RECEIPT_INVALID` zählt nicht: Sind alle Quittungen ungültig und liegt kein anderer Anker vor, meldet der Verifier `NO_ANCHOR` daneben. Die Präfix-Prüfung (`FORK_DETECTED`) gilt für jede Quittung, deren Signatur trägt, unabhängig davon, ob ihr Schlüssel belegt ist, und auch dann, wenn die Liste ihr widerspricht: Ein Widerspruch darf einen Fork nicht verdecken.

**Was diese Regel nicht leistet.** Das Gültigkeitsfenster wird gegen `server_ts` geprüft, und `server_ts` steht in der Quittung selbst. Wer einen widerrufenen Schlüssel besitzt (genau der Fall, für den es den Widerruf gibt), kann Quittungen mit einem `server_ts` vor dem Widerruf signieren; der Verifier vergleicht `server_ts` mit keiner anderen Zeit der Kette, und der Schlüsselinhaber der Kette könnte deren Zeiten ohnehin mit zurückdatieren. Gegen eine solche Rückdatierung wirken nur Anker, die der Fälscher nicht nachträglich erzeugen kann: der Papier-Anker (7.2), der Zeitzeuge (7.3) und das Freshness-Fenster (8.5). Ebenso kann der Verifier nicht erkennen, ob es eine neuere Liste gibt als die im Paket: `version` ist nur untereinander vergleichbar. Der Bericht nennt deshalb Version und Ausstellzeit der verwendeten Liste, damit der Prüfer sie beim Hersteller abgleichen kann.

Ab `spec_version` 1.1 legt die Appliance dem Anker zusätzlich den RFC-6962-Konsistenzbeweis von der Bezugsgröße der Kette (der zuletzt quittierten oder als Lückenzeuge festgehaltenen `tree_size`) zur neuen bei (Heartbeat-Spezifikation §6 und §9.2); der Hersteller-Server gegenzeichnet eine gewachsene Kette nur, wenn dieser Beweis trägt. Für den Verifier ändert sich dadurch nichts: Beweisgegenstand bleibt die Quittung, und die Präfix-Prüfung dieses Abschnitts bleibt seine eigene.

### 7.2 Papier-Anker

Der Monatsbericht druckt die Merkle-Wurzeln (und `tree_size`) der Monats-Checkpoints ab. Ein Prüfer KANN eine abgedruckte Wurzel als erwartete Wurzel an den Verifier übergeben (z. B. `--expect-root`); weicht die neu berechnete Wurzel ab, ist die Kette gegenüber dem Papierstand nicht konsistent (`MERKLE_INCONSISTENT`). Papier-Anker sind herstellerunabhängig.

### 7.3 Zeitzeuge (TIME_ANCHOR)

Eine Zeitstempelstelle nach RFC 3161 (TSA) bezeugt, dass ein Checkpoint zu einem bestimmten Zeitpunkt **bereits existierte**. Anders als die Gegensignatur des Herstellers stammt diese Aussage aus einer Quelle, die weder der Kunde noch der Hersteller kontrolliert; die Stelle wird vom Kunden eingerichtet.

Der Zeitstempel wird über den **kanonischen Checkpoint-Signaturgegenstand** aus Abschnitt 6.1 gebildet, also über genau die Bytes, die auch die Geräte-Signatur des Checkpoints deckt. Damit bezeugt er nicht nur die Wurzel, sondern `chain_id`, `tree_size`, `prev_checkpoint_hash`, `key_id` und die Checkpoint-Zeit mit.

Der `messageImprint` des Tokens MUSS sein: `H(JCS(Signaturgegenstand des Checkpoints))`, wobei `H` der im Token selbst genannte Abdruck-Algorithmus ist. Zulässig sind `sha256`, `sha384`, `sha512`; `sha1` ist es NICHT: eine Kollision auf dem Abdruck würde ein Token zwei verschiedene Checkpoints bezeugen lassen, und genau das soll der Anker ausschließen.

Der Token wird als `TIME_ANCHOR`-Eintrag (Abschnitt 4.22) in die Kette geschrieben. Ein Zeitzeuge ist **optional**: eine Kette ohne TIME_ANCHOR ist deswegen nicht mangelhaft, und sein Fehlen ist kein Befund.

**Prüfregeln.** Der Verifier MUSS für jeden TIME_ANCHOR in dieser Reihenfolge prüfen:

1. `checkpoint_seq` verweist auf einen CHECKPOINT, dessen `tree_size` und `merkle_root` den Feldern des Eintrags entsprechen. Sonst `TIME_ANCHOR_INVALID` (Exit 2).
2. `token_base64` dekodiert zu einem DER-kodierten TimeStampToken mit genau einem Signierer und einem TSTInfo. Sonst `TIME_ANCHOR_INVALID` (Exit 2).
3. Die vier Ablesungen `tsa_policy`, `tsa_serial`, `tsa_ts` und der Abdruck-Algorithmus stimmen mit dem Token überein. Sonst `TIME_ANCHOR_INVALID` (Exit 2).
4. Der `messageImprint` des Tokens entspricht dem oben genannten Abdruck über den Signaturgegenstand des referenzierten Checkpoints. Sonst `TIME_ANCHOR_INVALID` (Exit 2). **Dies ist die tragende Bindung**, und sie ist ohne Kenntnis von CMS prüfbar: Abdruck berechnen, im DER die `messageImprint`-Oktettfolge finden, vergleichen.
5. Die CMS-Signatur des Tokens verifiziert gegen das im Token mitgeführte Signiererzertifikat. Schlägt das fehl, ist das `TIME_ANCHOR_INVALID` (Exit 2); ein Token, das seine eigene Signatur nicht trägt, ist gefälscht oder beschädigt.
6. Das Signiererzertifikat kettet zu einem Vertrauensanker, den der PRÜFER beibringt (Wurzelspeicher des Systems, ausdrücklich übergebene Wurzel), und trägt genau die erweiterte Schlüsselverwendung `id-kp-timeStamping` (RFC 3161 Abschnitt 2.3). Die Kettenprüfung erfolgt **zum `genTime` des Tokens**, nicht zur Uhrzeit der Prüfung; sonst verfiele der Beweis mit dem Zertifikat der Stelle. Gelingt das nicht, ist das `TIME_ANCHOR_UNVERIFIED` (Exit 1).

**Schritte 1 bis 4 sind für jeden Verifier Pflicht.** Sie kommen ohne CMS aus: Base64 dekodieren, den Abdruck über den Signaturgegenstand berechnen, ihn im DER an der `messageImprint`-Stelle wiederfinden, die drei Ablesungen vergleichen. Ein Verifier, der die Schritte 5 und 6 nicht ausführen KANN (weil ihm keine CMS-Implementierung zur Verfügung steht), DARF daraus NICHT `TIME_ANCHOR_INVALID` machen. Er MUSS `TIME_ANCHOR_UNVERIFIED` (Exit 1) melden und im Bericht sagen, dass er die Signatur nicht geprüft hat. Diese Regel ist keine Bequemlichkeit, sondern die Bedingung dafür, dass die Spezifikation mit Bordmitteln umsetzbar bleibt (Abschnitt 1): die tragende Bindung kann jeder prüfen, die Signaturkette nicht jeder.

Die Trennung zwischen 5 und 6 ist Absicht: Eine gebrochene Signatur ist ein Fälschungsbefund. Ein fehlender oder nicht erreichbarer Vertrauensanker ist eine **Aussage über die Prüfumgebung**, nicht über die Kette, und ein Verifier, der beides gleich behandelte, würde entweder ehrliche Ketten für manipuliert erklären oder gefälschte durchwinken.

**Warum der Vertrauensanker nicht aus dem Paket kommen darf.** Das Prüfpaket wird von genau der Partei geschrieben, gegen die der Zeitzeuge schützen soll. Ein Zertifikat aus `keys/tsa/` belegt daher nur Selbstkonsistenz. Ein Verifier DARF solche Zertifikate zur Kettenbildung heranziehen, MUSS in diesem Fall aber `TIME_ANCHOR_UNVERIFIED` (Exit 1) melden und im Bericht die Stelle benennen (Name, Seriennummer, `genTime`), damit der Prüfer sie außerhalb des Pakets nachschlagen kann. Nur ein Anker, den der Prüfer selbst beibringt, macht den Zeugen unabhängig.

Ein TIME_ANCHOR, der die Schritte 1 bis 4 besteht, zählt als vorhandene externe Verankerung: `NO_ANCHOR` (Abschnitt 7) wird dann NICHT gemeldet, auch wenn Schritt 6 scheitert. Die beiden Befunde sagen Verschiedenes („es liegt keine Verankerung vor" und „die vorliegende ist nicht unabhängig belegt"), und nur der zweite trifft hier zu. Diese Trennung hält auch Verifier gleich, die Schritt 6 gar nicht ausführen können.

**Was der Zeitzeuge nicht leistet.** Er beweist, dass ein Checkpoint zu einem Zeitpunkt existierte, nicht, dass die Kette vollständig ist. Gegen das Restfenster aus Abschnitt 11.2 wirkt er, weil eine später neu geschriebene Historie keinen Token mit früherem `genTime` beibringen kann; gegen das Weglassen von Einträgen VOR dem Zeitstempel wirken weiterhin nur Hash-Kette, Merkle-Konsistenz und die übrigen Anker.

### 7.4 Künftige Ankertypen (Ausblick, nicht normativ)

Weitere Ankertypen sind denkbar (etwa Veröffentlichung in einem öffentlichen Transparenzprotokoll). Verifier dieser Version MÜSSEN unbekannte Ankertypen ignorieren, DÜRFEN sie aber NICHT als Fehler werten.

## 8. Lücken-Semantik

Grundsatz: **Keine Ereignisse sind auch ein Ereignis.** Stille ist nur dann unbedenklich, wenn die Kette sie selbst ausweist.

### 8.1 TICK-Pflicht

Die Schreibstrecke MUSS im Betrieb spätestens alle **5 Minuten** einen Eintrag schreiben; ohne anderes Ereignis ist das ein `TICK`. Damit ist jedes Stillefenster der Schreibstrecke nach oben begrenzt und prüfbar.

### 8.2 Verschwiegene vs. gedeckte Stille

Für jedes Paar aufeinanderfolgender Einträge `a` (seq n) und `b` (seq n+1) sei `Δ = ts_chained(b) − ts_chained(a)`, gerechnet in ganzen Millisekunden (Abschnitt 2). Toleranz: **7,5 Minuten** (450 000 ms = 1,5 × TICK-Intervall). Ist `Δ > 450 000 ms`, liegt ein Stillefenster vor. Es gilt als **gedeckt**, wenn mindestens eine der folgenden Bedingungen zutrifft:

1. `b` ist ein `GAP`-Eintrag, dessen Fenster die Stille abdeckt: `started_ts(b) ≤ ts_chained(a) + 450 000 ms` UND `ended_ts(b) ≥ ts_chained(b) − 450 000 ms`. Befund: `COVERED_GAP` (Exit 1).
2. `b` ist ein `RESTART`-Eintrag (die Ausfallzeit ist per `downtime_ms_estimate` deklariert). Ein zusätzlicher deckender `GAP` SOLLTE folgen, wenn Ereignisse verloren gingen. Unabhängig davon verlangt Abschnitt 8.7 nach einem Absturz, dass jeder beantwortete Aufruf, der nicht in der Kette steht, im Fenster eines `GAP` liegt, und legt fest, wo dieses Fenster beginnt; ob die Stille gedeckt ist, hängt davon nicht ab.
3. `a` ist der Sofort-Checkpoint eines `SEAL`, und `b` ist der zugehörige `RESUME` (Abschnitt 8.4): geplante Stille, durch den Handover selbst deklariert. Ab Fassung 1.9 ebenso: `a` ist ein `SEAL`, `b` sein beim Neustart nachgeholter Sofort-Checkpoint mit `mono_delta_ms(b) = −1`, und nach `b` folgt entweder der `RESUME`, der diesen `SEAL` fortsetzt, oder kein Eintrag mehr: ein Absturz zwischen `SEAL` und Sofort-Checkpoint, den der Handover deklariert; endet das Paket mit `b` (der `RESUME` des Neustarts ist nie geschrieben worden), deklariert das `SEAL` selbst die Stille. Zwischen `a` und `b` kann kein Eintrag fehlen (`seq`, Merkle-Baum von `b`); eine ehrliche Kette wird so nie ungültig.
4. **Nachgeholter Sofort-Checkpoint nach einem Absturz (ab Fassung 1.9).** Alle vier Teile MÜSSEN zutreffen: (a) `a` ist ein kritischer Eintrag außer `SEAL`, und `b` ist ein `CHECKPOINT` (nach Abschnitt 6.1 bindet er `a` in seinen signierten Baum); (b) `mono_delta_ms(b) = −1`, die Spur eines neuen Prozesses (Abschnitt 9.2): ein Schreiber, der nur stockte, schreibt `mono_delta_ms ≥ 0`; (c) der Eintrag nach `b` ist ein `RESTART` mit `ts_chained(RESTART) − ts_chained(b) ≤ 450 000 ms` (ein negativer Unterschied erfüllt das; Uhrensprünge prüft Abschnitt 9.2), mit `downtime_ms_estimate = −1` oder `downtime_ms_estimate ≥ Δ − 450 000`; (d) der Eintrag danach ist ein `GAP`, dessen Fenster die Stille zwischen `a` und `b` nach Bedingung 1 abdeckt: `started_ts ≤ ts_chained(a) + 450 000 ms` und `ended_ts ≥ ts_chained(b) − 450 000 ms`. Der `GAP` ist wie jeder andere der Befund `COVERED_GAP` (Exit 1).

Trifft keine Bedingung zu, ist das Stillefenster **verschwiegen**: Befund `CONCEALED_SILENCE` (Exit 2). Ein deckender `GAP` außerhalb dieser Positionen deckt die Stille NICHT: die Deklaration muss die Stille unmittelbar abschließen.

**Warum Bedingung 4, und warum so eng.** Stürzt die Schreibstrecke zwischen einem kritischen Eintrag und seinem Sofort-Checkpoint ab, schreibt der Neustart den Checkpoint nach (Abschnitt 6.2), danach `RESTART` und `GAP`. Bis Fassung 1.8 blieb die Stille vor dem nachgeholten Checkpoint verschwiegen, obwohl die Kette sie unmittelbar danach deklariert (bewusste Entscheidung vom 03.09.2026, am 29.09.2026 vom Auftraggeber zugunsten der Deckung durch den folgenden `RESTART` geändert, mit der Bedingung: ein `RESTART` darf keine Löschung verdecken können). Bedingung 4 verlangt deshalb die Spur des Neustarts, die unmittelbar folgende Deklaration und ein `GAP`-Fenster, das die ganze Stille umfasst. Sie berührt keine andere Prüfung: Zwischen `a` und `b` kann kein Eintrag fehlen (`seq`, Merkle-Baum des Checkpoints), ein `CONTENT_DELETED` als `a` bleibt der Befund `CONTENT_DELETED`, und die Löschsperre (Abschnitt 9.3) wird geprüft wie überall. Die Zeit von `a` ist dann nur durch die Signatur von `b` zum Zeitpunkt `ts_chained(b)` begrenzt, nicht durch die Toleranz davor.

**Grenze, dem Auftraggeber gemeldet: „Ein RESTART darf keine Löschung verdecken“ lässt sich offline nicht allgemein sicherstellen, schon nicht mit Bedingung 2, die seit Fassung 1.0 gilt.** Wer Schreibzugriff auf die Kettendateien hat, kann das Ende der Kette samt eines `CONTENT_DELETED` abschneiden und die Anlage neu starten; `RESTART` und `GAP` decken dann die Stille bis zum letzten verbliebenen Eintrag, und nichts im Paket widerlegt das. Ebenso signiert ein Neustart jeden hash-konsistenten Eintrag, den jemand vorher ans Ende gehängt hat. Das ist dieselbe Grenze wie das Restfenster (Abschnitt 11.2): Der Schlüssel liegt beim Betreiber. Aufgedeckt wird es durch Verankerung: der Hersteller nimmt eine gekürzte Kette nicht mehr an (Heartbeat-Spezifikation §9.2), eine erwartete Wurzel des Prüfers widerspricht ihr (Abschnitte 7.2, 8.6), ein Zeitzeuge (Abschnitt 7.3). Bedingung 4 erweitert diese Möglichkeit nicht; was sie deckt, ließ sich schon zuvor mit vorgetäuschten `TICK`-Einträgen erreichen.

### 8.3 Lückenklassen

`GAP.reason` trägt genau eine der Klassen aus 4.25: `bypass` (Pförtner-Direktweiterleitung ohne Erfassung), `proxy_restart`, `power_loss`, `spool_unwritable`, `host_down`, `update`, `manual`. Für Importquellen deckt `SOURCE_GAP` Quellfenster (Befund `COVERED_SOURCE_GAP`, Exit 1); `RECONCILIATION` mit `delta ≠ 0` ist der Befund `RECONCILIATION_DELTA` (Exit 1).

### 8.4 SEAL/RESUME-Handover

Geplante Unterbrechungen (Update, Shutdown, Stilllegung) MÜSSEN versiegelt werden; ein Export aus laufendem Betrieb KANN versiegelt werden (Export-Siegel, `reason = export`, ab Fassung 1.9):

1. Die alte Instanz schreibt `SEAL`; als kritischer Typ MUSS unmittelbar danach dessen Sofort-Checkpoint folgen (Abschnitt 6.2).
2. Die fortsetzende Instanz (nach `update` oder `shutdown` eine neue, nach `export` dieselbe oder, nach einem Absturz dazwischen, die neu gestartete) schreibt als ersten inhaltlichen Eintrag `RESUME` mit `sealed_entry_hash` = **`entry_hash` des SEAL-Eintrags** (nicht des Sofort-Checkpoints; MUSS exakt übereinstimmen) sowie `prev_version`/`new_version`.
3. Zwischen `SEAL` und `RESUME` liegt **genau ein** Eintrag, und dieser MUSS der Sofort-Checkpoint des SEAL sein.

Begründung beider Hälften von Regel 3: Ein `SEAL` ohne sofortigen Checkpoint bliebe **unverankert**: stirbt die Maschine zwischen SEAL und RESUME, wäre der Kettenstand nur bis zum letzten älteren Checkpoint signiert abgedeckt; das ist die schwächere Beweislage, und genau der Moment der geplanten Unterbrechung braucht die stärkere. Umgekehrt darf **nur dieser eine Anker** dazwischenliegen, damit der Handover beweisbar dicht bleibt: jeder weitere Eintrag in der geplanten Stille wäre nicht mehr vom Handover selbst gedeckt.

Verletzungen (fehlender RESUME nach SEAL (obwohl die Kette weiterläuft), falscher `sealed_entry_hash`, ein anderer oder ein zusätzlicher Eintrag zwischen SEAL und RESUME) sind der Befund `HANDOVER_BROKEN` (Exit 2); der fehlende Sofort-Checkpoint des SEAL selbst ist `MISSING_CHECKPOINT` (Exit 2), außer am Kettenende (Abschnitt 6.2). Endet die Kette mit einem SEAL + Sofort-Checkpoint, ist das ein regulärer Kettenabschluss, kein Befund, gleich mit welchem `reason` (ab Fassung 1.6; bis Fassung 1.5 nur mit `decommission` oder `key_loss`) und auch dann, wenn danach noch `CHECKPOINT_RECEIPT`-Einträge auf genau diesen Sofort-Checkpoint folgen: sie bestätigen den versiegelten Stand und sind kein inhaltlicher Eintrag. Wie das Kettenende bewertet wird, regelt Abschnitt 8.6.

**Export-Siegel (ab Fassung 1.9).** Der Schreiber schreibt `SEAL` mit `reason = export`, dessen Sofort-Checkpoint, `RESUME` und den Checkpoint danach ohne einen Eintrag dazwischen und setzt die Kette unmittelbar fort; in der Kette ist das ein gewöhnlicher Handover nach den Regeln 1 bis 3. Das Prüfpaket umfasst die Einträge bis einschließlich des Sofort-Checkpoints dieses Siegels und ist damit versiegelt (Abschnitt 8.6). Der Handover dauert Millisekunden; eine längere Stille zwischen Checkpoint und `RESUME` (ein Absturz im Export) deckt Bedingung 3 von Abschnitt 8.2 wie bei jedem Handover.

Drei Klarstellungen (Freigabe des Auftraggebers 2026-09-03; beide Referenz-Verifier lesen die Regel so): (1) Jeder `RESUME` setzt genau einen `SEAL` fort: ein `RESUME`, dem nicht unmittelbar ein `SEAL` mit dessen Sofort-Checkpoint vorausgeht, ist `HANDOVER_BROKEN`. (2) `CHECKPOINT_RECEIPT`-Einträge auf den Sofort-Checkpoint eines `SEAL` dürfen nur am Kettenende nachlaufen; zwischen `SEAL` und `RESUME` sind sie ein zusätzlicher Eintrag im Sinne von Regel 3. (3) Die Stille-Deckung nach Abschnitt 8.2 Bedingung 3 gilt nur für den Handover, den der `RESUME` mit passendem `sealed_entry_hash` tatsächlich fortsetzt.

### 8.5 Stille am Kettenende (Freshness)

Das Ende der Kette kann kein nachfolgender Eintrag decken. Liegt `ts_chained` des letzten Eintrags weiter als das **Freshness-Fenster** vor dem Prüfzeitpunkt, meldet der Verifier `TRAILING_SILENCE` (Exit 1). Das Fenster ist konfigurierbar (Verifier-Option); Default: **24 Stunden**. Dieser Befund schützt vor der Vorlage eines veralteten (z. B. zurückgerollten) Standes; zusammen mit Quittungs-`server_ts` und cloudseitiger `tree_size`-Monotonie begrenzt er Fork-/Rollback-Angriffe (Abschnitt 11). Der Befund gilt auch für eine versiegelte Kette (Abschnitt 8.6): Das Siegel erklärt die Stille nach ihm, es belegt aber nicht, dass es das jüngste Siegel der Kette ist; eine an einem früheren Siegel gekürzte Kette sähe genauso aus (Abschnitt 11.2). `TRAILING_SILENCE` bleibt Exit-Klasse 1; die Kette bleibt gültig.

### 8.6 Kettenende: versiegelt oder unvollständig

Grundsatz (Produktentscheidung des Auftraggebers, ab Fassung 1.6): **Eine ehrliche Kette wird nie als „ungültig“ gemeldet. „Ungültig“ (Exit 2) ist nachgewiesener Manipulation vorbehalten.** Wie eine Kette endet, ist deshalb kein Manipulationsbefund, sondern ein eigener Status.

Eine Kette ist **versiegelt**, wenn ihre letzten Einträge in dieser Reihenfolge sind: ein `SEAL`, unmittelbar danach dessen Sofort-Checkpoint (Abschnitt 6.2), danach höchstens `CHECKPOINT_RECEIPT`-Einträge, deren `checkpoint_seq` genau diesen Sofort-Checkpoint nennt. Der `reason` des `SEAL` spielt dafür keine Rolle. Jede andere Kette ist **unvollständig**; das schließt eine Kette ein, deren letzter Eintrag ein `SEAL` oder ein anderer kritischer Eintrag ohne seinen Checkpoint ist (Abschnitt 6.2).

| Kettenende | Ergebnis | Exit |
|---|---|---|
| versiegelt, keine Befunde der Exit-Klasse 2 | gültig, ordnungsgemäß versiegelt; der Bericht nennt `seq`, `ts_chained` und `reason` des `SEAL` | 0, bei Befunden der Exit-Klasse 1: 1 |
| unvollständig, keine Befunde der Exit-Klasse 2 | unvollständig: Befund `UNSEALED_END` | 4 |
| `SEAL`, danach andere Einträge ohne `RESUME` | ungültig: `HANDOVER_BROKEN` (Abschnitt 8.4) | 2 |
| Hash-Kette gebrochen, Signatur falsch oder ein anderer Befund der Exit-Klasse 2 | ungültig | 2 |

Der Befund `UNSEALED_END` wird für jede unvollständige Kette genau einmal gemeldet, mit der `seq` ihres letzten Eintrags, auch neben Befunden der Exit-Klasse 2; der Exit-Code folgt dann Abschnitt 10.3. Ist das Paket ein Formatfehler (Exit 3), wird das Kettenende nicht bewertet. Seit Fassung 1.6 setzen Exit 0 und Exit 1 damit ein versiegeltes Kettenende voraus.

**Was „unvollständig“ heißt.** Alle vorhandenen Einträge sind geprüft wie bei jeder Kette. Unvollständig heißt nur: Das Paket belegt nicht, dass nach seinem letzten Eintrag nichts mehr kam. So endet jeder Export aus einer laufenden Anlage ohne Export-Siegel, jede Kette nach einem Absturz oder Stromausfall, und ebenso eine gekürzte Kette. Offline lassen sich diese Fälle nicht unterscheiden. Der Verifier MUSS deshalb mit dem Befund den letzten gegengezeichneten Checkpoint des Pakets nennen (`checkpoint_seq`, `tree_size`, `merkle_root` und `server_ts` der Quittung mit der größten `tree_size` unter denen, die nach Abschnitt 7.1 als Verankerung zählen (Signatur trägt, keine widersprechende Herstellerliste) und mit ihrem Checkpoint übereinstimmen; bei gleicher `tree_size` die erste in Kettenfolge) oder dass es keinen gibt, und auf den Abgleich hinweisen.

**Export-Siegel.** Ein Paket, das die Anlage mit Export-Siegel erzeugt (Abschnitt 8.4), endet mit `SEAL(export)` und dessen Sofort-Checkpoint und ist versiegelt: Ein ordentlicher Export aus laufendem Betrieb ist gültig, nicht unvollständig (Entscheidung des Auftraggebers vom 29.09.2026).

**Abgleich mit dem letzten gegengezeichneten Checkpoint.** Der Hersteller führt je `chain_id` die Wurzeln, die er gegengezeichnet hat, und gibt sie ab Fassung 1.9 zusammen mit Lückenzeugen und gemeldeten Wurzeln als signierte Anker-Historie heraus, die der Prüfer mit der `chain_id` selbst abholt (Heartbeat-Spezifikation §9.7); er übergibt dann jede Wurzel daraus, die vor der Anforderung des Pakets festgehalten wurde. Mindestens übergibt der Prüfer die jüngste gegengezeichnete Wurzel, die **vor der Anforderung des Pakets** gegengezeichnet wurde, wie einen Papier-Anker als erwartete Wurzel (`tree_size` und `merkle_root`, Abschnitt 7.2, 10.8), nicht die jüngste überhaupt: Eine danach gegengezeichnete Wurzel liegt hinter dem Paketende und kann darin nicht vorkommen; sie erschiene auch bei einem ehrlichen Paket als Widerspruch. Enthält das Paket die übergebene Wurzel nicht als Präfix-Wurzel, fehlen ihm Einträge, die der Hersteller bereits gegengezeichnet hatte: `MERKLE_INCONSISTENT` (Exit 2). Der Abgleich gilt für versiegelte Ketten ebenso.

**Was der Verifier zur Vollständigkeit sagt (ab Fassung 1.9).** Ohne eine vom Hersteller gegengezeichnete Wurzel ist keine Aussage darüber möglich, ob das Paket die ganze Kette bis zu seiner Anforderung enthält, weder bei einer unvollständigen noch bei einer versiegelten Kette (Beweisgrenze unten, Abschnitt 11.2; Entscheidung des Auftraggebers vom 29.09.2026: als Eigenschaft des Modells angenommen). Der Verifier MUSS das für jedes Paket, das kein Formatfehler ist, ausdrücklich sagen und die Wurzel anfordern: mit der `chain_id` und dem Aufruf, mit dem der Prüfer sie übergibt. Wurde eine erwartete Wurzel übergeben und im Paket gefunden, sagt er stattdessen, bis zu welcher `tree_size` die Vollständigkeit durch sie belegt ist.

**Beweisgrenze der Versiegelung.** Das Siegel trägt die Signatur des Geräteschlüssels, nicht die des Herstellers: Der Sofort-Checkpoint eines `SEAL`, auf den ein `RESUME` folgt, trägt vor dem `RESUME` keine Quittung (Abschnitt 8.4, Klarstellung 2). Jede frühere Übergabe (`SEAL`, Checkpoint, `RESUME`) ist deshalb eine Stelle, an der eine gekürzte Kette ohne jeden Schlüssel als versiegelt erscheint; der Schlüsselinhaber kann ohnehin an jeder Stelle kürzen und ein neues Siegel signieren (Abschnitt 11.1). Dagegen wirken der Zeitpunkt des Siegels im Bericht, `TRAILING_SILENCE` (Abschnitt 8.5) und sicher nur der Abgleich oben (Abschnitt 11.2, Testvektor `end_truncated_at_seal`).

**Ältere Verifier.** Die Regel gilt für jedes Paket, gleich welche `spec_version` es erklärt: Das Manifest ist nicht signiert, eine erklärte ältere Fassung darf den Status des Kettenendes nicht ändern (wie in Abschnitt 7.1). Ein Verifier der Fassung 1.5 oder älter kennt Exit 4 nicht: Er meldet eine unvollständige Kette als gültig (Exit 0 oder 1; milder als diese Fassung), eine, deren letzter Eintrag ein kritischer Eintrag ohne Checkpoint ist, dagegen als `MISSING_CHECKPOINT` und eine mit `update` oder `shutdown` versiegelte als `HANDOVER_BROKEN` (je Exit 2; strenger). Er erkennt ein Paket ab 1.6 am Befund `SPEC_NEWER` (Abschnitt 10.6); Pakete ab 1.6 SOLLEN mit einem Verifier ab 1.6 geprüft werden. Ein Verifier bis Fassung 1.8 kennt den Versiegelungsgrund `export` nicht: Die Nutzlasten bekannter Typen bleiben streng (Abschnitt 10.6, Regel 3), er meldet deshalb jedes Paket, das ein Export-Siegel enthält, als `FORMAT_ERROR` (Exit 3), für diese Kette dauerhaft, auch für jedes spätere Paket, weil das Siegel in der Kette bleibt. Pakete ab 1.9 SOLLEN mit einem Verifier ab 1.9 geprüft werden.

### 8.7 Erfassungszusage und Lückenbeginn nach einem Absturz

Ab Fassung 1.9 (Ergänzung vom 02.10.2026). Grundsatz des Auftraggebers: Kein beantworteter KI-Aufruf darf still verloren gehen. Entweder steht er in der Kette, oder er liegt sichtbar in einer Lücke.

**Begriffe.** Ein **beantworteter Aufruf** ist ein KI-Aufruf, den die Erfassung der Appliance entgegengenommen und zu dem die Appliance dem Client Antwortbytes des Anbieters ausgeliefert hat, gleich mit welchem Status und auch dann, wenn die Antwort danach abbrach. Eine Fehlerantwort, die die Appliance selbst erzeugt, ohne den Aufruf an einen Anbieter weitergegeben zu haben, ist keine Beantwortung. Seine **Entgegennahme** ist der Zeitpunkt, zu dem die Erfassung ihn vor der Weiterleitung entgegennahm (bei `origin = proxy` sein `ts_captured`); sein **Antwortende** ist der Zeitpunkt, zu dem die Appliance ihm zuletzt Antwortbytes auslieferte. Ein **Absturz** ist jedes Ende eines Prozesses der Erfassung oder der Schreibstrecke ohne geordnetes Herunterfahren und jeder Ausfall des Hosts. Alle Zeitpunkte dieses Abschnitts stammen von der Wanduhr der Appliance (Abschnitt 4.4) und werden in ganzen Millisekunden verglichen (Abschnitt 2).

**Zusage.** Jeder beantwortete Aufruf MUSS verkettet werden (nach einem Absturz auch nachträglich, mit seinem ursprünglichen `ts_captured`) oder in einem `GAP` liegen: `started_ts` ≤ Antwortende und `ended_ts` ≥ Entgegennahme. Ist sein Erfassungsnachweis nach einem Absturz erhalten, SOLLTE die Appliance ihn verketten, statt ihn nur in ein Fenster zu legen; sie DARF ihn dabei nicht ein zweites Mal verketten. Ein `GAP`, in dem ein möglicherweise verlorener beantworteter Aufruf liegen soll, DARF NICHT `lost_count = 0` tragen; ist die Zahl unbekannt, trägt er `−1`.

**Sicherungsstand.** Die Erfassung MUSS laufend dauerhaft festhalten, bis wohin sie für ihre Aufrufe einsteht: einen Zeitpunkt S, für den gilt: Jeder beantwortete Aufruf, dessen letzte Auslieferung von Antwortbytes vor S begann, ist dauerhaft gesichert, oder sein Verlust ist dauerhaft gezählt, mit einem Fenster, in dem er liegt. Dazu nennt der Sicherungsstand den Start des Erfassungsprozesses. Er wird höchstens alle Sekunde neu festgehalten, solange Aufrufe laufen höchstens alle 100 ms; ein älterer Sicherungsstand ist nie falsch, er macht ein Fenster nur breiter.

**Wo das Fenster nach einem Absturz beginnt.** Nach einem Absturz kennt die Appliance die verlorenen Aufrufe nicht mehr einzeln; der Beginn folgt deshalb aus dem, was vor dem Absturz dauerhaft gespeichert war. Für jede der drei Gruppen MUSS mindestens ein nach dem Absturz verketteter `GAP` die Bedingung erfüllen; verschiedene `GAP` dürfen verschiedene Gruppen abdecken:

1. Aufrufe, deren Erfassungsnachweis noch nicht dauerhaft gesichert war: `started_ts` ≤ dem zuletzt dauerhaft festgehaltenen Sicherungsstand des abgestürzten Erfassungsprozesses; ist keiner lesbar, `started_ts` ≤ Start dieses Prozesses. `ended_ts` ≥ dem Zeitpunkt, zu dem die Appliance den Absturz feststellt.
2. Beantwortete Aufrufe, deren Eintrag die Schreibstrecke vor dem Absturz geschrieben, aber nicht dauerhaft gesichert hatte, und die sie nicht nach der Zusage oben erneut verkettet: `started_ts` ≤ ihr `ts_captured`. Ist ein Sichern auf das Medium gescheitert, gilt keiner der davor geschriebenen Einträge durch ein späteres gelungenes Sichern als dauerhaft gesichert.
3. Die Stille selbst: Der `GAP` nach dem `RESTART` deckt sie wie bisher nach Abschnitt 8.2; sein Fenster beginnt dafür höchstens beim `ts_chained` des letzten erhaltenen Eintrags.

**Ohne Absturz.** Kann die Erfassung einen beantworteten Aufruf nicht sichern oder die Schreibstrecke einen gesicherten nicht verketten, MUSS der `GAP`, der diesen Verlust ausweist (Klasse `spool_unwritable`), höchstens bei dessen Entgegennahme beginnen. Endet die Erfassung geordnet, während ein Aufruf noch läuft, gilt Gruppe 1 entsprechend.

**Import.** Ereignisse einer Import-Schnittstelle (`origin = import`) tragen in `ts_captured` die Zeit ihrer Quelle; ein Fenster der Appliance kann sie nicht aufnehmen. Bestätigt eine Import-Schnittstelle dem Einreicher, ein Ereignis entgegengenommen zu haben, MUSS es in diesem Augenblick dauerhaft verkettet sein.

**Voraussetzung.** Springt die Wanduhr zwischen Entgegennahme und Absturz zurück, kann ein Fenster den Aufruf verfehlen; den Sprung weist Abschnitt 4.7 aus.

**Kein Befund des Verifiers.** Eine nicht eingehaltene Zusage ist kein Befund des Verifiers: Das Paket enthält nur, was verkettet wurde, und kann einen fehlenden Aufruf nicht zeigen (Abschnitt 11.2). Ein `GAP`, dessen Fenster vor dem letzten Eintrag vor der Stille beginnt, ist nach Abschnitt 8.2 gedeckt wie jeder andere (`COVERED_GAP`, Exit 1); dieser Abschnitt ändert keinen Befund und keinen Exit-Code. Belegt wird die Zusage durch Prüfungen mit bekannter Grundwahrheit an der Appliance. Ketten, die vor dieser Ergänzung geschrieben wurden, können Fenster tragen, die erst beim letzten Eintrag beginnen.

## 9. Inhalts-Commitments und Zeitplausibilität

### 9.1 Inhalts-Commitments

Die Kette trägt niemals Klartexte von Anfragen/Antworten, sondern Commitments:

```
commitment = Hex( HMAC-SHA-256( key = salt, message = Klartext-Bytes ) )
```

- `salt` ist ein **32-Byte-Zufallswert je Objekt**, gespeichert beim verschlüsselten Tresor-Objekt (nicht in der Kette).
- Zweck des Salts: Schutz vor Wörterbuchangriffen. Ein ungesalzener Hash kurzer, ratbarer Prompts wäre durch Ausprobieren umkehrbar; ohne Salt bleibt das Commitment unverwertbar.
- Prüfung vorgelegter Klartexte: Legt der Kunde einem Prüfer Klartext **und** Salt bewusst vor (Ablage: Abschnitt 10.1, „Vorgelegte Klartexte“), berechnet der Verifier das HMAC neu und vergleicht mit dem verketteten Commitment (`request_commitment`/`response_commitment`). Abweichung = Befund `CONTENT_MISMATCH` (Exit 2). Ohne Vorlage findet keine Inhaltsprüfung statt; die Kette bleibt inhaltsdicht. Eine vorgelegte Datei, die der Verifier nicht prüfen kann, ist ebenfalls `CONTENT_MISMATCH`: Keine vorgelegte Datei bleibt ungeprüft.
- Nach einem `CONTENT_DELETED` ist das Tresor-Objekt weg; das Commitment bleibt verkettet. Der Verifier meldet `CONTENT_DELETED` (Exit 1): Kette intakt, Löschung ausgewiesen.

### 9.2 mono_delta_ms-Plausibilität

`mono_delta_ms` stammt von der monotonen Uhr und ist gegen Wanduhr-Manipulation immun. Für jedes Paar aufeinanderfolgender Einträge `a`, `b` mit `mono_delta_ms(b) ≥ 0` sei:

```
widerspruch_ms = | ( ts_chained(b) − ts_chained(a) ) − mono_delta_ms(b) |
```

Ist `widerspruch_ms > 300 000` (5 Minuten) und ist `b` kein `CLOCK_JUMP`-Eintrag, der den Sprung deklariert (`jump_ms` erklärt die Differenz in Vorzeichen und Größenordnung, Toleranz 300 000 ms), dann ist das der Befund `CLOCK_ANOMALY` (Exit 2). Ein deklarierter Sprung ist der Befund `CLOCK_JUMP_NOTE` (Exit 1). `mono_delta_ms = −1` (erster Eintrag nach Prozessstart) nimmt an dieser Prüfung nicht teil; dort greifen stattdessen RESTART/GAP-Deckung (Abschnitt 8) und die Serverzeit der Quittungen als äußere Zeitklammer.

### 9.3 Aufbewahrung, Löschung und Legal Hold

Gelöscht werden nach dieser Spezifikation nur **Tresor-Inhalte**, nie Einträge der Kette: Eine gekürzte oder ausgedünnte Kette bräche Hash-Kette, `seq` und Merkle-Wurzeln (`SEQ_BREAK`, `HASH_MISMATCH`, `MERKLE_INCONSISTENT`). Jede Löschung eines Inhalts wird als `CONTENT_DELETED` verkettet (Abschnitt 4.17, 9.1); das Commitment bleibt stehen.

Eine **Sperre** (Abschnitt 4.24) ist ab ihrem `LEGAL_HOLD` mit `action = set` aktiv, bis ein `LEGAL_HOLD` mit `action = release` und derselben `hold_id` folgt. Ein weiteres `set` einer aktiven `hold_id` ersetzt deren Umfang; ein `release` ohne aktive Sperre dieser `hold_id` ist wirkungslos. Eine Sperre erfasst einen `AI_CALL`, wenn dessen `ts_captured` zwischen `scope_from` und `scope_to` liegt (beide Grenzen eingeschlossen; verglichen als Zeitpunkte, Abschnitt 2; maßgeblich ist der Zeitpunkt, nicht die Schreibweise: `…00Z` und `…00.000Z` sind dieselbe Grenze). Ein `release` SOLL die Grenzen der aufgehobenen Sperre wiederholen; für die Prüfung haben sie keine Bedeutung.

Befund `HOLD_VIOLATION` (Exit 1): ein `CONTENT_DELETED`, dessen `target_seq` einen `AI_CALL` nennt, der an der Stelle des `CONTENT_DELETED` von einer aktiven Sperre erfasst ist. Gemeldet einmal je `CONTENT_DELETED` an dessen `seq`, mit `target_seq` und jeder `hold_id`, die den Eintrag erfasst, im Bericht. Die Exit-Klasse ist bewusst 1, nicht 2: Die Löschung steht offen in der Kette, nichts ist verschwiegen oder verfälscht; es gibt keinen Manipulationsnachweis an der Kette (Grundsatz von Abschnitt 8.6). Der Befund weist nach, dass der Betreiber eine eigene Sperre gebrochen hat; ein Prüfer liest ihn wie einen harten Befund über den Betrieb.

## 10. Prüfpaket und Verifier

### 10.1 ZIP-Layout

Ein Prüfpaket ist ein ZIP-Archiv:

```
pruefpaket.zip
├── manifest.json           # Pflicht, siehe 10.2
├── segments/               # Pflicht: Ketten-Segmente als JSON Lines
│   ├── 000001.jsonl
│   ├── 000002.jsonl
│   └── …
└── keys/                   # Pflicht: Publikeys als Hex-Textdateien
    ├── device/<key_id>.hex # 64 Hex-Zeichen + optionales Zeilenende
    ├── vendor/<key_id>.hex
    ├── vendor/schluesselliste.json  # optional: signierte Hersteller-Schlüsselliste (10.7)
    └── tsa/*.pem           # optional: Zertifikate der Zeitstempelstelle (7.3)
```

- Jede Segmentdatei enthält Einträge als JSON Lines (ein Eintrag je Zeile, `\n`-getrennt), in aufsteigender `seq`-Reihenfolge; Segmente überlappen nicht und decken zusammen lückenlos `seq = 1 … tree_size` des Manifests ab. Getrennt wird ausschließlich an `\n` (U+000A): `\r`, U+0085, U+2028 und U+2029 trennen keine Einträge; die letzten drei stehen in einem JSON-String roh (RFC 8785), ein `\r` vor dem `\n` ist Leerraum des JSON-Texts. `\n` am Dateiende (eines oder mehrere) wird übergangen; jede andere Zeile (auch eine leere oder eine nur aus Leerraum bestehende) MUSS ein Eintrag sein, sonst `FORMAT_ERROR` (Exit 3).
- Die Namen der Einträge im ZIP stehen in Normalform: Pfadteile getrennt durch `/`, kein führendes `/`, kein leerer Pfadteil, kein Pfadteil `.` oder `..`, kein `\`, und kein Name kommt zweimal vor. Verzeichniseinträge (Name endet auf `/`) werden übergangen. Liegt `manifest.json` nicht auf oberster Ebene und teilen alle Einträge genau ein oberstes Verzeichnis, wird dieses abgelöst (ein gezipptes Verzeichnis); dasselbe gilt ab Fassung 1.9 für ein als Verzeichnis vorgelegtes Paket, das genau ein Verzeichnis und sonst nichts enthält. Ein als Verzeichnis vorgelegtes Paket darf nur Dateien und Verzeichnisse enthalten; eine symbolische Verknüpfung oder etwas anderes (eine benannte Pipe, ein Gerät) ist `FORMAT_ERROR`. Ein Paket, das diese Regeln verletzt, ist ein Formatfehler (`FORMAT_ERROR`, Exit 3): Zwei Verifier dürfen im selben Archiv nicht verschiedene Dateien sehen.
- Dateinamen der Segmente sind nicht beweistragend; maßgeblich ist die Segmentliste des Manifests (Datei, SHA-256, `first_seq`, `last_seq`). Ab Fassung 1.9 ausdrücklich: `file` folgt der Grammatik `^[A-Za-z0-9._-]{1,128}$`, ist weder `.` noch `..` und wird ausschließlich als `segments/<file>` gelesen, nie an anderer Stelle des Pakets und nie außerhalb davon. Die Segmente werden nach `first_seq` geordnet gelesen, unabhängig von ihrer Reihenfolge in der Liste; ihre deklarierten Bereiche MÜSSEN lückenlos bei 1 beginnen, dürfen sich nicht überlappen und MÜSSEN bei `tree_size` ≥ 1 enden, und jede Datei MUSS genau `last_seq − first_seq + 1` Einträge enthalten. Jede Verletzung ist `FORMAT_ERROR` (Exit 3), und die Prüfung endet dort (Abschnitt 10.5). Ob die Einträge selbst lückenlos nummeriert sind, prüft Abschnitt 3 (`SEQ_BREAK`).
- `keys/` spiegelt die Schlüssel des Manifests wider (eine Datei je `key_id`); bei Abweichung gilt das Manifest. Die Hersteller-Schlüssel aus Manifest und `keys/vendor/` sind **nicht beweistragend** (Abschnitt 7.1): Sie führen zu `RECEIPT_UNVERIFIED`, solange kein Anker des Prüfers sie belegt. `keys/vendor/schluesselliste.json` ist optional und zählt nur, wenn ihre Signatur gegen eine Herstellerwurzel des Prüfers trägt (Abschnitt 10.7). `keys/tsa/` ist optional und **nicht beweistragend** (Abschnitt 7.3): Zertifikate von dort führen zum Befund `TIME_ANCHOR_UNVERIFIED`, weil sie aus derselben Hand stammen wie die Kette.
- Optional KANN das Paket vorgelegte Berichte (HTML/PDF) und bewusst offengelegte Klartexte mit Salts enthalten; dann prüft der Verifier zusätzlich `REPORT_MISMATCH` bzw. `CONTENT_MISMATCH`.
- **Vorgelegte Klartexte (ab Fassung 1.9 festgelegt)** liegen unter `content/`. Die Vorlage für den `AI_CALL` mit `seq` n besteht aus `content/<n>.salts.json` und `content/<n>.request` und/oder `content/<n>.response`; `<n>` hat die Form `[1-9][0-9]*`. Die Klartextdateien enthalten genau die Bytes der HMAC-Nachricht (Abschnitt 9.1). Die Salt-Datei ist I-JSON (Abschnitt 2) mit genau diesen Membern: `seq` (int, gleich n), `request_salt` und `response_salt` (je hex64, vorhanden genau dann, wenn die zugehörige Klartextdatei vorliegt) und optional `vault_ref` (string, wird nicht ausgewertet). Für jeden vorgelegten Teil MUSS der Eintrag n ein `AI_CALL` mit nicht-leerem `<teil>_commitment` sein, und das HMAC MUSS übereinstimmen. Jede andere Datei unter `content/` (ein anderer Name, eine Datei in einem Unterverzeichnis, ein Klartext ohne Salt, ein Salt ohne Klartext, eine nicht konforme Salt-Datei) ist `CONTENT_MISMATCH`, einmal je Datei. Neben einer nicht konformen Salt-Datei ist auch jeder Klartext desselben n `CONTENT_MISMATCH`: Er ist nicht prüfbar. Erfüllt ein vorgelegter Teil die Bedingung an Eintrag n nicht, ist seine Klartextdatei `CONTENT_MISMATCH`, die konforme Salt-Datei daneben nicht. Ein leeres Verzeichnis ergibt nichts.

### 10.2 manifest.json

Felder (Registry `pruefpaket_manifest`):

| Feld | Typ | Beschreibung |
|---|---|---|
| `spec_version` | version `"MAJOR.MINOR"` | Spezifikationsversion des Pakets; `MAJOR` und `MINOR` sind Dezimalzahlen ohne führende Nullen; diese Fassung schreibt `"1.9"` und nimmt ältere Minor-Versionen derselben MAJOR-Version an; Annahme anderer Versionen: Abschnitt 10.6 |
| `chain_id` | uuid | Kette dieses Pakets |
| `created_ts` | rfc3339 | Erzeugungszeit des Pakets |
| `tree_size` | int, min 0 | Zahl der enthaltenen Einträge |
| `segments` | array of object | je Segment: `file` (string, maxlen 128), `sha256` (hex64), `first_seq` (int, min 1), `last_seq` (int, min 1) |
| `device_pubkeys` | array of object | je Schlüssel: `key_id` (string, maxlen 64), `pubkey` (hex64) |
| `vendor_pubkeys` | array of object | je Schlüssel: `key_id` (string, maxlen 64), `pubkey` (hex64) |

Der Verifier MUSS die SHA-256-Summen der Segmentdateien gegen das Manifest prüfen; jede Abweichung sowie unlesbares/schema-widriges Material ist `FORMAT_ERROR` (Exit 3).

### 10.3 Exit-Codes

| Exit | Bedeutung |
|---|---|
| 0 | gültig ohne Befunde |
| 1 | gültig mit Befunden |
| 2 | ungültig |
| 3 | Formatfehler |
| 4 | unvollständig: Kettenende nicht versiegelt (Abschnitt 8.6) |

Bestimmung: Ist das Paket nicht lesbar oder schema-widrig → **3**. Sonst: mindestens ein Befund der Exit-Klasse 2 → **2**; sonst mindestens ein Befund der Exit-Klasse 4 → **4**; sonst mindestens ein Befund der Exit-Klasse 1 → **1**; sonst → **0**. Maßgeblich ist diese Rangfolge (3 vor 2 vor 4 vor 1 vor 0, Registry `verifier.exit_precedence`), nicht die Größe der Zahl. Die Semantik ist strikt getrennt: „kryptographisch gültig ja/nein" (0/1/4 vs. 2/3), der Status des Kettenendes (0/1 versiegelt, 4 unvollständig) und die Befundliste. Exit 4 ist kein Fehlschlag: Die geprüften Einträge sind intakt, nur ihre Vollständigkeit belegt das Paket nicht. Gibt ein Verifier sein Urteil zusätzlich maschinenlesbar aus, MUSS er Exit 4 als eigenen Status ausweisen und DARF ihn nicht als „ungültig“ kennzeichnen; ein Werkzeug, das nur ein Ja/Nein-Merkmal ausliest, würde sonst jede ehrliche Kette aus dem laufenden Betrieb verwerfen. Eine ehrlich ausgewiesene Lücke macht die Kette nicht ungültig; eine verschwiegene schon.

### 10.4 Befundklassen

Vollständige Liste (Registry `verifier.finding_classes`); ein Verifier MUSS jede Klasse melden können:

| Befundklasse | Exit | Bedeutung |
|---|---|---|
| `SEQ_BREAK` | 2 | Sequenzlücke oder -sprung |
| `HASH_MISMATCH` | 2 | Hash-Kette gebrochen |
| `SIG_INVALID` | 2 | Checkpoint-Signatur ungültig |
| `MERKLE_INCONSISTENT` | 2 | Merkle-Konsistenz zwischen verankerten Wurzeln verletzt |
| `RECEIPT_INVALID` | 2 | Hersteller-Gegensignatur ungültig |
| `TIME_ANCHOR_INVALID` | 2 | Zeitzeuge widerspricht dem Checkpoint oder ist gefälscht |
| `FORK_DETECTED` | 2 | Quittung passt zu keiner Präfix-Historie |
| `CLOCK_ANOMALY` | 2 | Zeitwiderspruch ohne verketteten CLOCK_JUMP |
| `CONCEALED_SILENCE` | 2 | Stille im Kettenverlauf ohne deckenden GAP/RESTART |
| `HANDOVER_BROKEN` | 2 | SEAL/RESUME-Handover gebrochen |
| `MISSING_CHECKPOINT` | 2 | kritischer Eintrag ohne unmittelbar folgenden Checkpoint |
| `CONTENT_MISMATCH` | 2 | vorgelegter Klartext widerspricht Commitment |
| `REPORT_MISMATCH` | 2 | vorgelegter Bericht nicht in der Kette |
| `UNSEALED_END` | 4 | Kette endet ohne Siegel: unvollständig (Abschnitt 8.6) |
| `COVERED_GAP` | 1 | ausgewiesene Lücke (GAP) |
| `COVERED_SOURCE_GAP` | 1 | ausgewiesene Quell-Lücke |
| `RECONCILIATION_DELTA` | 1 | Abgleich-Differenz zur Anbieter-Angabe |
| `CONTENT_DELETED` | 1 | Inhalt fristgerecht gelöscht, Kette intakt |
| `HOLD_VIOLATION` | 1 | Inhalt trotz aktiver Löschsperre gelöscht (Abschnitt 9.3) |
| `CLOCK_JUMP_NOTE` | 1 | ausgewiesener Uhrensprung |
| `TRAILING_SILENCE` | 1 | Kette endet vor dem Freshness-Fenster |
| `NO_ANCHOR` | 1 | keine externe Verankerung vorhanden |
| `TIME_ANCHOR_UNVERIFIED` | 1 | Zeitzeuge vorhanden, seine Stelle aber nicht unabhängig belegt |
| `RECEIPT_UNVERIFIED` | 1 | Hersteller-Gegensignatur stimmig, ihr Schlüssel aber nicht durch einen Vertrauensanker des Prüfers belegt |
| `SPEC_NEWER` | 1 | Paket nutzt eine neuere Minor-Version der Spezifikation als der Verifier |
| `UNKNOWN_ENTRY_TYPE` | 1 | Eintragstyp dieser Verifier-Version unbekannt; Eintrag geprüft, Nutzlast nicht |
| `UNKNOWN_MANIFEST_FIELD` | 1 | Manifest-Feld dieser Verifier-Version unbekannt; angenommen und gemeldet, alle bekannten Prüfungen laufen weiter |
| `FORMAT_ERROR` | 3 | Prüfpaket nicht lesbar/schema-widrig |

### 10.5 Prüfablauf (normative Mindestprüfungen)

Ein konformer Verifier führt mindestens aus: (1) Paket-/Schema-Prüfung inkl. Segment-Hashes, mit den Annahmeregeln der Vorwärtskompatibilität (Abschnitt 10.6); (2) `seq`-Lückenlosigkeit und Hash-Kette (`prev_hash`/`entry_hash` mit eigener JCS-Kanonisierung); (3) Checkpoint-Signaturen inkl. KEY_ROTATION-Vertrauenskette und Checkpoint-Verkettung; (4) Merkle-Wurzeln aller Checkpoints neu berechnen; Konsistenz aller verankerten Wurzeln paarweise; (5) Quittungen: Herkunft des Hersteller-Schlüssels und Gegensignatur nach Abschnitt 7.1, Übereinstimmung mit Checkpoint, Präfix-Passung (Fork); (6) Lücken-Semantik nach Abschnitt 8; (7) Zeitplausibilität nach Abschnitt 9.2; (8) SEAL/RESUME-Handover und Kettenende (Abschnitt 8.4, 8.6); (9) optional vorgelegte Klartexte und Berichte; Löschsperren (Abschnitt 9.3); (10) Freshness-Fenster; (11) Zeitzeugen nach Abschnitt 7.3, soweit vorhanden; (12) Restfenster messen und ausgeben (Abschnitt 11.2).

**Verarbeitungsstufen (ab Fassung 1.9).** Das Paket wird in dieser Reihenfolge gelesen: (1) `manifest.json` als I-JSON, Signale nach den Regeln 1 und 5 (Abschnitt 10.6), dann sein Schema; (2) die Segmenttabelle (Abschnitt 10.1); (3) je Segment in `first_seq`-Reihenfolge: Datei vorhanden, SHA-256, Zahl der Zeilen (für alle Segmente, bevor Stufe 4 eine Zeile liest); (4) je Zeile: JSON; ist sie ein Objekt, die Signale nach den Regeln 1 und 2 aus `spec_version` und `event_type` (soweit Zeichenketten), dann ihr Schema und ihre `chain_id`, weiter mit den übrigen Zeilen; (4a) die Hersteller-Schlüsselliste und die Salt-Dateien `content/<n>.salts.json` (nur Namen dieser Form) nach der Zahlregel aus Abschnitt 2, je Datei höchstens ein `FORMAT_ERROR`; (5) die Prüfungen der Kette, darunter die vorgelegten Klartexte. Scheitert eine der Stufen 1 bis 3, entfallen alle späteren. Signale werden für jedes bis dahin gelesene Objekt gemeldet, auch neben seinem Schemafehler (Regel 3), nie aber aus einem fehlenden Segment oder einem mit falscher SHA-256. Scheitert Stufe 4 an einer Zeile, laufen die übrigen Zeilen weiter, Stufe 5 entfällt; scheitert Stufe 4a, entfällt Stufe 5 ebenso.

### 10.6 Vorwärtskompatibilität

Vorbild ist die Regel für unbekannte Ankertypen (Abschnitt 7.4), die unverändert gilt: Was ein Verifier nicht kennt, ist ein Befund, kein Fehler (mit einer bewusst gezogenen Grenze am Envelope).

**Regel 1: Versionsannahme.** `spec_version` hat die Form `"MAJOR.MINOR"` (Typ `version`, Abschnitt 2). Ein Verifier, der die Version `1.m` implementiert, MUSS Einträge und Manifeste mit `spec_version = "1.n"` annehmen. Für `n ≤ m` gilt der Normalfall ohne besonderen Befund. Für `n > m` MUSS er genau EINMAL je Prüfpaket den Befund `SPEC_NEWER` (Exit-Klasse 1) melden und ALLE Prüfungen, die er kennt, weiter ausführen, insbesondere die Mindestprüfungen aus Abschnitt 10.5. Eine `spec_version` mit anderem `MAJOR` als dem des Verifiers ist `FORMAT_ERROR` (Exit 3); ebenso eine `spec_version`, die nicht die Form aus Abschnitt 2 hat (etwa mit führenden Nullen). `MINOR` wird als ganze Zahl verglichen, ohne Obergrenze der Stellenzahl.

**Regel 2: Unbekannte Eintragstypen.** Ein `event_type`, den der Verifier nicht kennt (Typ `open_enum`, Abschnitt 2), ist KEIN Schemafehler. Der Verifier MUSS den Befund `UNKNOWN_ENTRY_TYPE` (Exit-Klasse 1) melden, einmal je unbekanntem Typnamen, mit der `seq` des ersten Vorkommens. Er MUSS den Eintrag in die `seq`-, Hash-Ketten- und Merkle-Prüfung einbeziehen (diese hängen nicht am Typ), MUSS für `payload` nur prüfen, dass es ein JSON-Objekt ist, und DARF den Typ NICHT als kritisch (Sofort-Checkpoint-Pflicht, Abschnitt 4 und 6) behandeln. Das ist die konservative Richtung, und sie ist als solche zu verstehen: Ein künftiger kritischer Typ wird von einem älteren Verifier NICHT auf seinen Sofort-Checkpoint geprüft; ein fehlender Checkpoint nach einem unbekannten Typ ist für diesen Verifier kein `MISSING_CHECKPOINT`. Für die Stille-Regeln (Abschnitt 8.1, 8.2) ist ein unbekannter Typ kein deckender `GAP` oder `RESTART`; wie jeder Eintrag begrenzt er lediglich das Stillefenster nach Abschnitt 8.2.

**Regel 3: Envelope bleibt geschlossen.** Ein Envelope-Feld, das Abschnitt 3 nicht definiert, bleibt `FORMAT_ERROR` (Exit 3): Das Envelope ist der Vertrag; ein neues Envelope-Feld ist eine `MAJOR`-Änderung. Die `payload`-Felder BEKANNTER Eintragstypen bleiben strikt nach Abschnitt 2 (Vollständigkeit, keine undefinierten Felder); für das Prüfpaket-Manifest gilt dagegen Regel 5. Befunde nach den Regeln 1, 2 und 5 werden auch dann gemeldet, wenn dasselbe Objekt daneben einen Schemafehler (`FORMAT_ERROR`) trägt; der Exit-Code folgt Abschnitt 10.3. Eine MINOR-Version DARF den Wertebereich eines bestehenden `payload`-Feldes verengen, wenn jeder Wert des engeren Bereichs auch im älteren Schema gültig ist; die Verengung gilt für Einträge, deren eigene `spec_version` diese MINOR-Version oder eine neuere ist, und ein älterer Verifier nimmt sie ohne die Verengung an (ab Fassung 1.8: `GENESIS.license_id`, Abschnitt 4.1).

**Regel 4: Ankertypen.** Die Regel für unbekannte Ankertypen (Abschnitt 7.4) bleibt unverändert.

**Regel 5: Das Prüfpaket-Manifest ist erweiterbar.** Ein Feld in `manifest.json`, das Abschnitt 10.2 nicht definiert, ist KEIN Schemafehler. Der Verifier MUSS den Befund `UNKNOWN_MANIFEST_FIELD` (Exit-Klasse 1) melden, einmal je unbekanntem Feldpfad, mit dem Pfad im `detail`, und ALLE Prüfungen, die er kennt, weiter ausführen, insbesondere die Mindestprüfungen aus Abschnitt 10.5. Das gilt für das Manifest-Objekt selbst UND für die Objekte in seinen Feldern `segments`, `device_pubkeys` und `vendor_pubkeys`; Feldpfade werden ohne Index gemeldet (`manifest.segments[].feld`), damit ein zusätzliches Feld in hundert Segmenten einen Befund ergibt und nicht hundert. Die DEFINIERTEN Felder bleiben unverändert pflichtig und streng: ein fehlendes, falsch getyptes oder außerhalb seines Wertebereichs liegendes definiertes Feld bleibt `FORMAT_ERROR` (Exit 3). Der Befund gilt unabhängig von `spec_version`: auch ein Manifest, das die Version des Verifiers erklärt, aber ein ihm unbekanntes Feld trägt, wird angenommen und gemeldet; ein Erzeuger, der ein Feld ohne Versionssprung hinzufügt, verletzt diese Spezifikation, und der Verifier verlässt sich nicht darauf, dass er es nicht tut.

Der Unterschied zu Regel 3 ist nicht Bequemlichkeit, sondern Beweislast. Das Manifest geht in **keine** Hash-Kette, keine Merkle-Wurzel und keine Signatur ein; ein zusätzliches Feld dort kann keine kryptographische Prüfung verändern. Ein zusätzliches Envelope-Feld verändert dagegen die JCS-Bytes und damit `entry_hash`; deshalb bleibt das Envelope geschlossen und ist eine `MAJOR`-Frage. Und der Befund ist der Preis für die Annahme: Ein Verifier, der ein Manifest-Feld nicht kennt, kann nicht wissen, ob es seine Prüfung einschränkt; ein künftiges Feld könnte ein Paket als Auszug kennzeichnen. Deshalb wird das Feld nicht still übergangen: Der Prüfer erfährt, dass das Paket eine Aussage trägt, die dieses Werkzeug nicht liest, und kann eine neuere Fassung holen. Ohne den Befund wäre die Regel eine Einladung zum falschen Grün.

Die Registry bildet diese Regeln ab: `envelope_fields.spec_version` und `pruefpaket_manifest.spec_version` tragen den Typ `version`; `envelope_fields.event_type` trägt den Typ `open_enum` mit `unknown_finding = "UNKNOWN_ENTRY_TYPE"`; `pruefpaket_manifest` trägt `unknown_field_finding = "UNKNOWN_MANIFEST_FIELD"`. Die Testvektoren `format_newer_minor`, `format_unknown_event_type` und `format_unknown_manifest_field` (Registry `testvectors.format`) legen das Sollverhalten fest.

### 10.7 Hersteller-Schlüsselliste

Die Liste der Gegenzeichnungsschlüssel des Herstellers liegt, wenn vorhanden, unter `keys/vendor/schluesselliste.json` (Registry `vendor_key_list`). Sie ist ein JSON-Objekt in UTF-8 ohne Byte-Order-Mark, ohne doppelte Membernamen und ohne andere Felder als diese:

| Feld | Typ | Beschreibung |
|---|---|---|
| `format` | const `"rekorder-herstellerschluessel/1"` | Formatkennung; eine andere macht die Liste unwirksam |
| `version` | int, 1 … 2^53−1 | vom Hersteller streng steigend vergeben; ob eine neuere existiert, kann der Verifier nicht erkennen (7.1) |
| `ausgestellt` | rfc3339 | Ausstellungszeit |
| `schluessel` | array, 1 … 64 Objekte | je Schlüssel: `key_id`, `pubkey`, `gueltig_ab`, optional `gueltig_bis` und `widerrufen_ab`; alle Werte Zeichenketten |
| `signatur` | object | genau `wurzel_id` und `sig` (hex128) |

- `key_id` und `wurzel_id` folgen der Grammatik `^[A-Za-z0-9._-]{1,64}$`; `pubkey` ist hex64 (Kleinbuchstaben). Eine `key_id` und ein `pubkey` dürfen je nur einmal vorkommen.
- `gueltig_ab`, `gueltig_bis`, `widerrufen_ab` und `ausgestellt` sind vom Typ `rfc3339` (Abschnitt 2) und werden, wie `server_ts` beim Vergleich mit ihnen, nach dieser Grammatik gelesen: `JJJJ-MM-TTThh:mm:ss` mit den ASCII-Ziffern `0` bis `9`, optional ein Punkt mit Sekundenbruchteilen beliebiger Länge, dann `Z`; Jahr `0001` bis `9999`; das Datum muss existieren, Sekunde `60` gibt es nicht. Bruchteile jenseits der neunten Stelle werden abgeschnitten, verglichen wird auf Nanosekunden. `gueltig_bis` MUSS nach `gueltig_ab` liegen. Zeitpunkte werden als Zeitpunkte verglichen, nicht als Zeichenketten.
- Gültig zu einem Zeitpunkt `t` ist ein Schlüssel, wenn `gueltig_ab` ≤ `t`, und `t` < `gueltig_bis` sowie `t` < `widerrufen_ab`, soweit vorhanden. Mehrere Schlüssel dürfen gleichzeitig gültig sein: so überlappt eine Rotation.
- Signiert wird die JCS-Kanonisierung (Abschnitt 2) des Listenobjekts **ohne** das Member `signatur`, mit Ed25519 durch den Wurzelschlüssel, den `signatur.wurzel_id` nennt. Formatierung und Memberreihenfolge der Datei spielen keine Rolle.
- Eine Liste, die eine dieser Regeln verletzt oder deren Signatur nicht gegen eine Wurzel des Prüfers mit derselben `wurzel_id` trägt, ist **unwirksam**: Sie belegt keinen Schlüssel und ist selbst kein Befund (Abschnitt 7.1).

Die Herstellerwurzel, die der Prüfer beibringt, hat die Form `{"wurzel_id": …, "pubkey": …}` mit genau diesen zwei Feldern. Sie kommt NIE aus dem Prüfpaket: Eine Wurzel aus derselben Hand wie die Liste würde nur beweisen, dass die Liste zu sich selbst passt.

### 10.8 Angaben des Prüfers und `verify_args.json`

Was der Prüfer dem Verifier übergibt, liest er nach derselben Grammatik wie das Paket (ab Fassung 1.9); eine Angabe, die sie verletzt, ist ein unbrauchbarer Aufruf: Exit 3 mit Begründung, nie eine stille Auslegung.

- **Prüfzeitpunkt** (Freshness, Abschnitt 8.5): ein Zeitpunkt der Grammatik `rfc3339` aus Abschnitt 2 und 10.7 (UTC mit `Z`, großes `T`, ASCII-Ziffern, Jahr `0001` bis `9999`). Eine Angabe ohne Zone, mit Versatz, mit Leerzeichen statt `T`, als Wochendatum oder ohne Sekunden ist unbrauchbar; sie wird nicht nach der Zeitzone des Rechners gelesen. Ohne Angabe gilt die Systemuhr. Ein angegebener Prüfzeitpunkt geht `verify_args.json` vor; die Datei wird dann nicht gelesen.
- **Erwartete Wurzeln** (Papier-Anker, Abschnitt 7.2; Abgleich, Abschnitt 8.6; Lückenzeugen, Abschnitt 11.2), beliebig viele, je in einer von zwei Formen: `<merkle_root>` oder `<tree_size>:<merkle_root>`; `merkle_root` ist 64 Hex-Zeichen, Groß- und Kleinschreibung gleichwertig; `tree_size` hat die Form `[1-9][0-9]*` und ist höchstens 2^53−1 (`0:` und führende Nullen sind unbrauchbar). Mit `tree_size` ist sie gefunden, wenn die neu berechnete Wurzel über die ersten `tree_size` Einträge gleich ist; ist `tree_size` größer als die Zahl der Einträge, ist sie nicht gefunden. Ohne `tree_size` ist sie gefunden, wenn sie der Wurzel über die ersten t Einträge für irgendein t von 1 bis zur Zahl der Einträge gleicht. Jede nicht gefundene erwartete Wurzel ist `MERKLE_INCONSISTENT` (Exit 2) und verankert nichts; jede gefundene zählt als Verankerung (kein `NO_ANCHOR`). Die Vollständigkeit (Abschnitt 8.6) gilt bis zur größten `tree_size` einer gefundenen Wurzel, auch wenn eine andere nicht gefunden ist.
- **`verify_args.json`** ist optional und unsigniert; der Erzeuger des Pakets wählt ihren Inhalt. Sie ist I-JSON (Abschnitt 2) und hat genau das Member `now` (rfc3339 wie oben). Der Verifier liest sie nur, wenn der Prüfer es ausdrücklich verlangt (für eingefrorene Testvektoren), und nennt im Bericht die Quelle des Prüfzeitpunkts. Verlangt und fehlend oder nicht konform: Exit 3 mit Begründung, das Paket wird nicht weiter gelesen (einziger Befund `FORMAT_ERROR`); kein Rückfall auf die Systemuhr, damit eine ausdrückliche Anforderung nie still die Grundlage der Freshness-Prüfung wechselt.

## 11. Angreifermodell und Beweisgrenzen

### 11.1 Manipulationsklassen und Erkennung

| Klasse | Angriff | Erkennung |
|---|---|---|
| `rewrite` | Umschreiben eines Eintrags | Hash-Kette (`HASH_MISMATCH`), Signaturen (`SIG_INVALID`), Merkle-Wurzeln, Zeitzeugen (Abschnitt 7.3) |
| `truncate` | Kürzen der Kette gegen verankerte Wurzeln | Konsistenzbeweise gegen Anker und erwartete Wurzeln (`MERKLE_INCONSISTENT`), Handover (`HANDOVER_BROKEN`), Kettenende (`UNSEALED_END`, Abschnitt 8.6) |
| `fork` | Zweitgeschichte gegen Quittungen/Konsistenzbeweise, auch mit selbst signierten „Quittungen" unter einem erfundenen Hersteller-Schlüssel | Quittungs-Präfix-Prüfung (`FORK_DETECTED`, `RECEIPT_INVALID`), Herkunft des Hersteller-Schlüssels (`RECEIPT_UNVERIFIED`, Abschnitt 7.1), cloudseitige `tree_size`-Monotonie, Freshness |
| `clock` | Rückdatierung gegen mono_delta/Serverzeit | `CLOCK_ANOMALY`, `genTime` der Zeitzeugen (`TIME_ANCHOR_INVALID`); `server_ts` der Quittungen ist eine vom Hersteller signierte Zeitangabe, die der Verifier aber mit keiner anderen Zeit der Kette vergleicht; er meldet daran nichts |
| `silent_gap` | verschwiegene Stille ohne deckenden GAP | TICK-Abdeckung (`CONCEALED_SILENCE`) |

Rollenbetrachtung: **Ein Externer ohne Schlüssel** scheitert an Hash-Kette und Signaturen. **Der Schlüsselinhaber selbst** (der Kunde) kann formal gültige Einträge neu erzeugen, scheitert aber an bereits verankerten Wurzeln: jede Historie, die nicht Präfix-konsistent zu jeder verankerten Wurzel ist, fällt durch. Neue „Quittungen" für seine Neufassung kann er nur unter einem Schlüssel signieren, den er selbst besitzt; den hat kein Anker des Prüfers belegt, und der Verifier meldet `RECEIPT_UNVERIFIED` (Abschnitt 7.1). **Der Hersteller** besitzt den Kundenschlüssel nie und kann daher keine gültigen Einträge erzeugen; er sieht keine Inhalte und kann nichts selektiv unterdrücken; seine Gegensignaturen sind von jedem Dritten prüfbar, der die mit der Lizenz veröffentlichte Herstellerwurzel oder einen angehefteten Schlüssel beibringt (Abschnitt 7.1, 10.7); der Papier-Anker verankert zusätzlich herstellerunabhängig.

### 11.2 Ehrliche Beweisgrenzen

- **Restfenster:** Einträge zwischen dem letzten gegengezeichneten Checkpoint und dem Kettenende sind noch nicht extern verankert. Der Schlüsselinhaber könnte dieses **Restfenster** verlustfrei neu schreiben, bevor die nächste Quittung eintrifft. Das Format begrenzt seine Größe nicht: Im lizenzierten Betrieb mit Verbindung zum Hersteller umfasst es meist wenige Minuten (ein Anker alle 5 Minuten), nach einem Lizenzablauf, bei abgeschaltetem Egress oder in einem alten Export beliebig viel. Der Verifier MUSS es deshalb für jedes Paket, das kein Formatfehler ist, **messen und ausgeben** (ab Fassung 1.9; Anfrage von Spur C vom 29.09.2026): T ist die `tree_size` des letzten gegengezeichneten Checkpoints nach Abschnitt 8.6 (0, wenn es keinen gibt), N die Zahl der Einträge. Das Restfenster sind die Einträge `seq` T+1 bis N; auszugeben sind T, T+1, N, die Zahl N − T, `ts_chained` von `seq` T (nicht bei T = 0) und von `seq` N, die Dauer dazwischen in Millisekunden (Abschnitt 2; nicht bei T = 0), die Zahl der `ADMIN`-Einträge mit `message_type = anchor` nach der Quittung jenes Checkpoints (gesendete Anker ohne Gegenzeichnung im Paket) und ob das Fenster die Taktung überschreitet (T = 0 oder Dauer über 450 000 ms). In der JSON-Ausgabe beider Referenz-Verifier heißt das Objekt `residual_window` mit den Membern `after_tree_size`, `first_seq`, `last_seq`, `entries`, `from_ts`, `to_ts`, `span_ms`, `unanswered_anchor_messages` und `beyond_cadence`. Das Restfenster ist kein Befund und ändert den Exit-Code nicht; überschreitet es die Taktung, nennt der Bericht die möglichen Ursachen (Lizenzablauf, Egress aus, Hersteller nicht erreichbar, alter Export) und den Abgleich nach Abschnitt 8.6. Ein Zeitzeuge nach Abschnitt 7.3 verkleinert das Fenster nicht, verändert aber, wer es ausnutzen kann: Er verlagert die Aussage auf eine Stelle, die weder Kunde noch Hersteller kontrolliert; wer die Historie neu schreibt, müsste einen Token mit früherem `genTime` beibringen, den er nicht hat. Ohne eigenen Vertrauensanker des Prüfers bleibt auch das nur eine Selbstauskunft (`TIME_ANCHOR_UNVERIFIED`).
- **Ohne Vertrauensanker des Prüfers** belegt eine Quittung nur Selbstkonsistenz: Signatur, Checkpoint und Präfix werden voll geprüft, der Schlüssel aber stammt aus dem Paket (`RECEIPT_UNVERIFIED`, Abschnitt 7.1). Die Aussage „vom Hersteller gegengezeichnet" trägt erst mit der Herstellerwurzel oder einem angehefteten Schlüssel.
- **Ohne jede Verankerung** (Air-Gap, Egress aus) sinkt die Beweiskraft gegen den Schlüsselinhaber auf das Freshness-/Papier-Anker-Niveau; der Verifier weist das als `NO_ANCHOR` aus. Die Kette bleibt gegen externe Manipulation voll beweiskräftig.
- **Fork-Erkennung braucht Vergleichspunkte:** Ein Rollback fällt nur auf, wenn dem Prüfer mindestens eine jüngere Quittung, ein jüngerer Papier-Anker oder das Freshness-Fenster widerspricht.
- **Lizenzablauf (ab Fassung 1.8):** Nach Ablauf von Laufzeit und Kulanz zeichnet der Hersteller keine Anker mehr gegen. Er prüft sie aber weiter auf Konsistenz und hält ihre Wurzeln als Lückenzeugen fest (Heartbeat-Spezifikation §9.2). Das Prüfpaket enthält für diese Zeit keine Quittung; alle Einträge seit der letzten Quittung liegen im Restfenster, das der Schlüsselinhaber aus Sicht des Pakets allein neu schreiben könnte. Beim Hersteller reicht die Neufassung dagegen nur bis zum jüngsten Lückenzeugen zurück. Ein Prüfer, der ein solches Paket bewertet, SOLL die signierte Anker-Historie der Kette selbst beim Hersteller abholen (Heartbeat-Spezifikation §9.7), nicht über das geprüfte Haus, und jede Wurzel daraus, die vor der Anforderung des Pakets festgehalten wurde (gegengezeichnet, Lückenzeuge oder gemeldet), als erwartete Wurzel prüfen (Abschnitte 7.2, 10.8): Widerspricht das Paket einer davon oder fehlt sie ihm, ist das `MERKLE_INCONSISTENT`. Eine Wurzel, die erst nach der Anforderung festgehalten wurde, sagt über dieses Paket nichts; als erwartete Wurzel übergeben, erschiene sie auch bei einem ehrlichen Paket als Widerspruch.
- **Lizenzschlüssel in älteren Ketten:** Bis Fassung 1.7 konnte `GENESIS.license_id` den Lizenzschlüssel im Klartext tragen (Abschnitt 4.1). Das mindert die Beweiskraft der Kette nicht, legt aber den Schlüssel jedem Inhaber des Pakets offen; der Verifier weist darauf hin.
- **Kürzung an einem früheren Siegel (ab Fassung 1.6):** Eine Kette, die unmittelbar hinter dem Sofort-Checkpoint eines früheren `SEAL` abgeschnitten wird, erscheint als ordnungsgemäß versiegelt; dafür ist kein Schlüssel nötig. Das Paket allein kann das nicht widerlegen. Es fällt auf am Zeitpunkt des Siegels im Bericht, an `TRAILING_SILENCE` außerhalb des Freshness-Fensters und sicher am Abgleich mit der jüngsten gegengezeichneten Wurzel des Herstellers (Abschnitt 8.6). Der Testvektor `end_truncated_at_seal` legt diese Grenze offen. Jedes Export-Siegel (ab Fassung 1.9) ist eine solche Stelle; der Auftraggeber hat diese Grenze am 29.09.2026 als Eigenschaft des Modells angenommen. Der Verifier sagt deshalb bei jedem Paket, dass ohne gegengezeichnete Wurzel keine Aussage über die Vollständigkeit möglich ist, und fordert sie an (Abschnitt 8.6).
- **Uhrzeit:** Die Kette beweist Reihenfolge (seq, monotone Uhr) hart; absolute Wanduhrzeit ist nur bis zur Klammer aus `server_ts` der Quittungen (≤ 5 Minuten Raster) und deklarierten Uhrensprüngen belegt.
- **Einzelne verlorene Aufrufe (ab Fassung 1.9, 02.10.2026):** Das Paket enthält nur, was verkettet wurde. Fehlt ein Aufruf, den die Appliance beantwortet hat, ohne dass ein `GAP`-Fenster ihn aufnimmt, ist das offline nicht zu erkennen; die Kette bleibt gültig. Abschnitt 8.7 verpflichtet die Appliance, das zu verhindern. Belegen lässt sich die Zusage nur außerhalb des Pakets: gegen Protokolle der aufrufenden Anwendungen, gegen Zählwerte des Anbieters (Abschnitt 4.6) oder durch Prüfläufe mit bekannter Grundwahrheit. Ein `GAP`-Fenster sagt, dass in dieser Zeit Aufrufe fehlen können, nicht, dass welche fehlen; `lost_count = −1` heißt, ihre Zahl ist unbekannt.
- **Inhalte:** Commitments beweisen Integrität vorgelegter Klartexte, nicht deren Existenz oder Vollständigkeit; gelöschte Inhalte (`CONTENT_DELETED`) sind endgültig nicht mehr vorlegbar (ausgewiesen, nicht verschleiert).
- **Souveränität als Beweisgegenstand:** Der Hersteller kennt keine Kundenschlüssel und sieht keine Inhalte; alles, was die Appliance sendet, ist als `ADMIN`-Eintrag wörtlich verkettet und damit selbst Prüfgegenstand.
