# LEDGER-Kettenformat: Spezifikation (DE)

**spec_version: 1.10** · Diese Spezifikation ist normativ. Sie beschreibt das Aufzeichnungsformat von LEDGER vollständig genug, dass ein unabhängiger Dritter allein hieraus einen Verifier implementieren kann. Die maschinenlesbare Feld- und Klassenreferenz ist `spec/registry.json`; bei Abweichungen gilt die Registry.

**Fassung 1.10, Stand 2026-11-18.** Neu in dieser Fassung sind das Herstellerprotokoll mit Füllern, das Zeitstempelprofil, die Anker-Historie als Angabe des Prüfers, die Schlüsselrollen mit `statement_signatures`, die Beweisstufe, die Berichtsangaben und die Zugriffskette mit dem Eintragstyp `DATA_ACCESS`, dazu die Protokollschlüsselliste und der Protokollauszug im Format `/2` mit einer zweiten Signatur nach ML-DSA-87 (Abschnitte 7.4.5a, 7.4.7a, 7.4.8a). COSE Receipts (Abschnitt 7.7) beschreibt diese Fassung als Entwurf; ein Verifier der Fassung 1.10 zählt sie nur und prüft sie nicht, geprüft werden sie ab Fassung 1.11. Beide Referenz-Verifier setzen diese Fassung ab der Fassung 1.1.0 um; `--version` nennt die Fassung der Spezifikation.

Die Schlüsselwörter MUSS, DARF NICHT, SOLLTE und KANN sind im Sinne von RFC 2119 („MUST", „MUST NOT", „SHOULD", „MAY") zu verstehen.

## 1. Überblick und Designziele

LEDGER zeichnet die Nutzung von KI-Diensten als **append-only Ereigniskette** auf: kanonisches JSON, SHA-256-Hash-Verkettung, Merkle-Baum nach RFC 6962, Ed25519-signierte Checkpoints und externe Gegensignaturen. Drei Designziele bestimmen jede Formatentscheidung:

1. **Beweis statt Behauptung.** Jede Aussage der Kette ist kryptographisch prüfbar: offline, ohne Mitwirkung des Herstellers, ohne Geheimnisse. Die Prüfung benötigt weder Kundenschlüssel noch Inhalte.
2. **Lücke = Befund.** Es gibt keinen Fehlerpfad, der „im Nichts" endet: Ausfälle, Umgehungen, Uhrensprünge und Löschungen werden als eigene Eintragstypen verkettet. Eine ehrlich ausgewiesene Lücke macht die Kette nicht ungültig; eine verschwiegene schon (Abschnitt 8, 11). Für den einzelnen Aufruf ist das eine Zusage der Appliance: Jeder Aufruf, den sie beantwortet hat, steht in der Kette oder liegt im Fenster eines verketteten `GAP` (Abschnitt 8.7); ob sie eingehalten ist, kann das Paket allein nicht zeigen (Abschnitt 11.2).
3. **Souveränität.** Die Kette trägt keine Klartexte, sondern gesalzene Commitments (Abschnitt 9). Der Hersteller kennt keine Kundenschlüssel und sieht keine Inhalte. Seine Rollen im Beweismodell sind die Gegensignatur über 32-Byte-Wurzeln (Abschnitt 7.1), die signierte Anker-Historie mit der Angabe zur Verbundenheit (Abschnitt 8.8, Heartbeat-Spezifikation §9.7, §9.10) und das Herstellerprotokoll (Abschnitt 7.4). Für jede dieser Rollen führt er eigene Schlüssel (Abschnitt 10.7.3). Keine dieser Rollen gibt ihm einen Schlüssel des Kunden oder Einblick in Inhalte.

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
| `date` | Kalendertag `JJJJ-MM-TT` (ab Fassung 1.10) mit den ASCII-Ziffern `0` bis `9`; das Datum muss im proleptischen gregorianischen Kalender existieren, das Jahr liegt zwischen `0001` und `9999`; Member des Herstellerprotokolls vom Typ `date` (Abschnitt 7.4) liegen zusätzlich zwischen `2000-01-01` und `9998-12-31` (Protokollbereich); `dayOf` (Abschnitt 7.4.10, Schritt L2) liest nur die Grammatik des Typs, den Protokollbereich eines Tageseintrags prüft Schritt L2 (c) als Regel des Inhalts |
| `hex64` | 64 hexadezimale Kleinbuchstaben-Zeichen (32 Bytes), z. B. SHA-256-Wert oder Ed25519-Publikey |
| `hex128` | 128 hexadezimale Kleinbuchstaben-Zeichen (64 Bytes), Ed25519-Signatur |
| `b64` | Zeichenkette nach der Grammatik B64 (unten; ab Fassung 1.10 eigener Typ); `Bytes(x)` bezeichnet bei einem Wert `x` dieses Typs seine Dekodierung nach RFC 4648 Abschnitt 4 |
| `mldsa87-pub` | `b64` mit genau 3456 Zeichen, dekodiert genau 2592 Bytes (ab Fassung 1.10): ein Publikey nach ML-DSA-87 (FIPS 204, Tabelle 2, `pk`; Abschnitt 7.4.5a) |
| `mldsa87-sig` | `b64` mit genau 6172 Zeichen, die auf `==` enden, dekodiert genau 4627 Bytes (ab Fassung 1.10): eine Signatur nach ML-DSA-87 (FIPS 204, Tabelle 2, `σ`; Abschnitt 7.4.5a) |
| `key-id` | Schlüsselkennung (ab Fassung 1.10 eigener Typ): eine Zeichenkette nach der Grammatik `^[A-Za-z0-9._-]{1,64}$` aus Abschnitt 10.7 |
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
- **Hash:** Für ihre eigenen Objekte (Einträge, Merkle-Bäume, Commitments, Signaturgegenstände, Herstellerprotokoll und Anker-Historie) verwendet diese Spezifikation SHA-256 und keine andere Hash-Funktion. Andere Hash-Funktionen kommen nur in Zeitstempeln nach RFC 3161 vor, die eine Zeitstempelstelle bildet (Abschnitte 7.3, 7.5): Abdrücke mit SHA-384 oder SHA-512, die Hashes der Signaturalgorithmen und der Attribute `messageDigest` und signingCertificateV2 und SHA-1 als Kennung des Signiererzertifikats in signingCertificate (ab Fassung 1.10 Z.6, Abschnitt 7.5.6). „Hex(x)" ist die Kleinbuchstaben-Hex-Kodierung von Bytes `x`.
- **Signaturen:** Ed25519 (RFC 8032), außer wo ein Abschnitt ausdrücklich ein anderes Verfahren nennt; ab Fassung 1.10 nennt Abschnitt 7.4.5a ML-DSA-87 für eine zweite Signatur des Tageseintrags, und Abschnitt 7.7 nennt für COSE-Objekte als signierte Bytes die Sig_structure nach RFC 9052, signiert mit Ed25519. Signiert werden die UTF-8-Bytes eines JCS-kanonisierten Objekts, außer wo ein Abschnitt ausdrücklich andere Bytes nennt; Ed25519-Signaturen werden als `hex128` kodiert, Ed25519-Publikeys als `hex64`, außer wo ein Abschnitt ausdrücklich eine andere Kodierung nennt. Geprüft wird ohne Kofaktor, wie RFC 8032 Abschnitt 5.1.7 es zulässt: S < L; k ist SHA-512 über R, die 32 Oktette des Publikeys, wie sie stehen, und die Nachricht, gelesen als Zahl in Little-Endian und modulo L reduziert; die Kodierung von [S]B − [k]A gleicht R, den ersten 32 Oktetten der Signatur, Byte für Byte. Ein R, das nicht die kanonische Kodierung seines Punkts ist (y ≥ p, oder x = 0 mit gesetztem Vorzeichenbit), besteht deshalb nie. Unter einem Publikey mit y ≥ p besteht keine Signatur (in Zeitstempeln liegt er außerhalb von Z.2, Abschnitt 7.5.4); x = 0 mit gesetztem Vorzeichenbit liest der Verifier beim Publikey als x = 0, abweichend von RFC 8032 Abschnitt 5.1.3, Schritt 4. Ab Fassung 1.10 besteht außerdem keine Signatur unter einem Publikey, der einen Punkt kleiner Ordnung kodiert, also wenn sein y (Little-Endian, Bit 255 gelöscht) einer dieser fünf Werte ist: 0, 1, p − 1, `26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05` oder `c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a` (die beiden y-Werte der Punkte der Ordnung 8, als 32 Oktette in Hex), gleich mit welchem Vorzeichenbit. Unter einem solchen Schlüssel ließen sich Signaturen ohne geheimen Schlüssel bilden, unter `01` gefolgt von 31 Nullbytes etwa R = B, S = 1 über jede Nachricht; er belegt nichts über den, der signiert hat. Das gilt für jede Ed25519-Signatur dieser Spezifikation, auch in Zeitstempeln (Abschnitt 7.5.4).
- **Zahlen (ab Fassung 1.9 ausdrücklich):** Jede JSON-Zahl im Prüfpaket (in Einträgen einschließlich der Nutzlast unbekannter Typen, im Manifest, in der Hersteller-Schlüsselliste, in den Salt-Dateien vorgelegter Klartexte (Abschnitt 10.1) und in `verify_args.json` (Abschnitt 10.8)) MUSS eine ganze Zahl von −(2^53−1) bis 2^53−1 sein, geschrieben ohne Bruchteil und ohne Exponent (I-JSON, RFC 7493 Abschnitt 2.2; RFC 8785 setzt es voraus). Jede andere Zahl ist `FORMAT_ERROR` (Exit 3); `1.0` ist nicht `1`. Die Schreibstrecke kann nichts anderes schreiben. Das gilt auch in der Hersteller-Schlüsselliste und in den Salt-Dateien, deren übrige Mängel nur die Liste unwirksam machen (Abschnitt 10.7) oder `CONTENT_MISMATCH` sind (Abschnitt 10.1), und gleich, ob der Prüfer eine Herstellerwurzel übergibt. Diese beiden Dateiarten werden lexikalisch gelesen (jedes Zahl-Token dort, wo ein JSON-Wert beginnen kann, Zeichenketten zählen nicht), also unabhängig von anderen Mängeln derselben Datei (Stufe 4a, Abschnitt 10.5). `NaN` und `Infinity` sind kein JSON (RFC 8259): ein Syntaxfehler der Datei, kein Zahlverstoß. `-0` ist die Zahl 0.
- **Zeitarithmetik (ab Fassung 1.9):** Die Toleranzprüfungen der Abschnitte 8.2, 8.5 und 9.2 und die Fensterbedingungen des Abschnitts 8.7 rechnen in ganzen Millisekunden: Jeder Zeitpunkt wird auf ganze Millisekunden seit `0001-01-01T00:00:00Z` abgeschnitten (Stellen nach der dritten Nachkommastelle entfallen); verglichen und subtrahiert werden ganze Zahlen. Alle übrigen Zeitvergleiche (Abschnitte 7.1, 9.3, 10.7) erfolgen auf Nanosekunden. Die Schreibstrecke schreibt Millisekunden; eine ehrliche Kette berührt den Unterschied nie. Ab Fassung 1.10 rechnen außerdem in ganzen Millisekunden: die Zeitfenster der Tageszeitstempel, die Fälligkeit eines Tages und die Regeln an `server_ts` des Herstellerprotokolls (Abschnitte 7.4.6, 7.4.10), die Prüfung der Anker-Historie mit dem Anforderungszeitpunkt, der Frische, den Seitenregeln und der Verbundenheit (Abschnitte 8.8, 10.8) und die Zeitpunkte, die der Verifier selbst bildet (Abschnitt 10.10.1). Auf Nanosekunden, mit dem vollen `genTime`, erfolgen ab Fassung 1.10: der Vergleich mit dem Ende der Gültigkeit eines Protokollschlüssels (Abschnitt 7.4.10, Schritt L2 (e)), das Gültigkeitsfenster eines Listeneintrags für Seiten der Anker-Historie (Abschnitt 8.8.4, Schritt H2), der Zeitraum einer als qualifiziert benannten Wurzel (Abschnitt 10.8) und die Gültigkeit der Zertifikate eines Pfads (Abschnitt 7.5.5).
- **Tagesarithmetik (ab Fassung 1.10):** Für einen Tag d vom Typ `date` ist `dn(d)` die Zahl der Tage von `0001-01-01` bis d (`dn(0001-01-01) = 0`), und `end(d) = (dn(d) + 1) · 86 400 000` ist das Ende des UTC-Tages d in ganzen Millisekunden seit `0001-01-01T00:00:00Z`, wie in der Zeitarithmetik oben. Vortage, Folgetage und Tagesenden MÜSSEN auf diesen ganzen Zahlen berechnet werden; für d + 1 oder d + 2 wird kein Kalenderdatum gebildet, denn am Rand des Wertebereichs gibt es keines. `day(ts)` ist der Datumsteil eines Werts vom Typ `rfc3339`, die zehn Zeichen vor dem `T`; Sekundenbruchteile ändern ihn nie (abgeschnitten, nicht gerundet). Beispiel: `dn(2026-01-01) = 739 616`, `end(2026-01-01) = 63 902 908 800 000`.
- **Base64, Grammatik B64 (ab Fassung 1.10):** Eine Base64-Zeichenkette (RFC 4648 Abschnitt 4) besteht nur aus den Zeichen `A` bis `Z`, `a` bis `z`, `0` bis `9`, `+` und `/`, hat eine durch 4 teilbare Länge und trägt `=` nur als Auffüllung am Ende, höchstens zweimal. Zeilenumbrüche, Leerzeichen und andere Zeichen verletzen B64. Ungenutzte Bits der letzten Gruppe werden nicht geprüft: Beurteilt wird die Zeichenkette selbst, und eine zweite Schreibweise derselben Bytes gibt ihr keine zweite Bedeutung. Ein Decoder, der Zeilenumbrüche überspringt, MUSS `\r` und `\n` vorher abweisen. B64 gilt für `token_base64` (Abschnitt 7.3; ein Verstoß ist `TIME_ANCHOR_INVALID`, kein Formatfehler, denn der Registry-Typ des Feldes bleibt `string`), für die Zeitstempel der Tageseinträge (Abschnitt 7.4.6), für den Inhalt eines PEM-Blocks nach dem Zusammenfügen seiner Zeilen und für Zertifikate in Dateien des Prüfers (Abschnitt 10.8). Ab Fassung 1.10 gilt B64 außerdem für die Werte der Typen `b64`, `mldsa87-pub` und `mldsa87-sig`. In einer Datei des Prüfers prüft deren Grammatik an einem solchen Wert nur, dass er eine Zeichenkette mit der Zahl von Zeichen ist, die die Grammatik der Datei für dieses Member nennt (für `pubkey` einer Protokollschlüsselliste `/2` 1 bis 8192 Zeichen; dort ist jeder Verstoß ein Mangel des Inhalts, Abschnitt 7.4.7a); B64 und die Zahl der dekodierten Bytes prüft der Schritt, der den Wert liest, und was ein Verstoß dort bewirkt, bestimmt der Abschnitt dieses Schritts (Abschnitte 7.4.7a, 7.4.10), wie bei den Zeitstempeln der Tageseinträge (Abschnitt 7.4.6).
- **Dateien des Prüfers (ab Fassung 1.10):** JSON-Dateien, die der Prüfer dem Verifier übergibt (Abschnitte 7.4, 8.8, 10.8), sind I-JSON nach den Regeln oben (Membernamen, Zahlen, keine einzeln stehenden Ersatzzeichen), UTF-8 ohne Byte-Order-Mark, und ihre Objekte sind geschlossen: Andere als die definierten Member DÜRFEN NICHT vorkommen. Die Größengrenzen nennt Abschnitt 10.8 (Registry `auditor_inputs`). Was ein Verstoß bewirkt, bestimmt der Abschnitt der jeweiligen Datei; wo er nichts anderes sagt, ist es ein unbrauchbarer Aufruf (Exit 3, Abschnitt 10.8).
- **Signierte Aussagen in druckbarem ASCII (ab Fassung 1.10):** Der `statement_jcs` eines Tageseintrags (Abschnitt 7.4.5) und einer Seite der Anker-Historie der Form v2 (Heartbeat-Spezifikation §9.7) besteht nur aus den Bytes `0x20` bis `0x7E`; seine Längengrenze in Zeichen ist damit zugleich eine in Bytes.

## 3. Eintrags-Envelope

Jeder Eintrag ist ein JSON-Objekt mit exakt diesen elf Feldern (Quelle: Registry `envelope_fields`):

| Feld | Typ | Beschreibung |
|---|---|---|
| `spec_version` | version `"MAJOR.MINOR"` | Version der Spezifikation, nach der der Eintrag geschrieben wurde; `MAJOR` und `MINOR` sind Dezimalzahlen ohne führende Nullen (`"1.0"`, nicht `"01.0"` oder `"1.00"`); diese Fassung schreibt `"1.10"` und nimmt ältere Minor-Versionen derselben MAJOR-Version an; Annahme anderer Versionen: Abschnitt 10.6 |
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

Diese Version definiert 25 Eintragstypen (ein Eintragstyp, der hier nicht definiert ist, wird nach Abschnitt 10.6 behandelt). Neun davon sind **kritische Typen** (Registry-Attribut `critical_checkpoint`): `GENESIS`, `GAP`, `MODE_CHANGE`, `SEAL`, `OVERSIGHT`, `KEY_ROTATION`, `CONTENT_DELETED`, `CONTENT_DISCLOSED`, `LEGAL_HOLD`. Nach jedem Eintrag eines kritischen Typs MUSS der unmittelbar folgende Eintrag ein `CHECKPOINT` sein (Sofort-Checkpoint-Pflicht, Abschnitt 6).

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
| `provider_class` | enum, siehe 4.26 | Anbieter-Klasse |
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
| `reason` | enum, siehe 4.26 | Lückenklasse |
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
| `user` | string, maxlen 128 | handelnde Person (aus der Sitzung, nie aus dem Formular) |
| `role` | string, maxlen 64 | Rolle der handelnden Person (aus der Sitzung, nie aus dem Formular) |
| `reference` | string, maxlen 256 | Gegenstand der Entscheidung (z. B. Ketten-`seq`, Fallkennung) |
| `justification` | string, maxlen 4000 | Begründung |

### 4.13 ALARM

Regelbasierter Alarm (keine KI im Produkt).

| Feld | Typ | Beschreibung |
|---|---|---|
| `rule_id` | enum, siehe 4.26 | Alarmregel |
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
| `tsa_name` | string, maxlen 256 | die vom Kunden eingerichtete oder bestätigte Stelle (Abschnitt 7.3); beschreibend, nicht beweistragend |
| `tsa_policy` | string, maxlen 128 | `policy`-OID aus dem Token; MUSS dem Token entsprechen |
| `tsa_serial` | string, maxlen 128 | `serialNumber` aus dem Token, Kleinbuchstaben-Hex: der Wert hexadezimal ohne führende Nullen, `0` für null, mit vorangestelltem `-` für einen negativen Wert (T.5 lässt jeden INTEGER zu); MUSS dem Token entsprechen |
| `tsa_ts` | rfc3339 | `genTime` aus dem Token im Zeitformat aus Abschnitt 2; MUSS dem Token entsprechen |
| `token_base64` | string, maxlen 21848 | der DER-kodierte TimeStampToken (RFC 3161), base64; das DER MUSS ≤ 16384 Bytes sein |

Die drei Felder `tsa_policy`, `tsa_serial` und `tsa_ts` sind **Ablesungen aus dem Token**, keine zweite Quelle: sie machen die Kette ohne ASN.1-Parser lesbar. Beweistragend ist allein `token_base64`. Widerspricht eine Ablesung dem Token, ist das der Befund `TIME_ANCHOR_INVALID`, nicht die Übernahme des einen oder des anderen Wertes.

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

### 4.25 DATA_ACCESS

Ab Fassung 1.10. Ein festgehaltener Zugriff einer Person oder eines Dienstes auf Kundendaten eines Herstellers im Sinn von Heartbeat-Spezifikation §12 (Zugriffskette). Der Eintrag trägt keinen Freitext, keine Kennung eines Kunden, keinen Namen und keinen Inhalt der Daten; was den Zugriff begründet, steht in einem Vorgang beim Betreiber der Kette, an den der Eintrag über ein Commitment gebunden ist. Den Typ schreibt nur eine Zugriffskette (Heartbeat-Spezifikation §12); die Kette einer Appliance eines Kunden trägt ihn nicht.

| Feld | Typ | Beschreibung |
|---|---|---|
| `access_id` | uuid | Kennung des Zugriffs; betrifft ein Zugriff mehrere Datenklassen, trägt jeder seiner Einträge dieselbe |
| `actor_kind` | enum: `person` \| `service` | wer zugreift |
| `actor_id` | uuid | Kennung des Kontos im Kontenverzeichnis des Betreibers; jede Ergänzung des Verzeichnisses steht vorher als eigener Eintrag in der Kette (Heartbeat-Spezifikation §12, Zugriffskette, Punkt 4) |
| `purpose` | enum: `support` \| `license_admin` \| `affiliation_upkeep` \| `fleet_supervision` \| `incident` \| `maintenance` \| `restore` \| `data_subject_request` \| `legal_order` \| `audit` \| `service` \| `other` | Zweck (unten) |
| `data_class` | enum: `license` \| `registration` \| `heartbeat` \| `chain` \| `journal` \| `affiliation_register` \| `alarm_contact` \| `order_system` \| `credentials` \| `access_chain` \| `operations_log` \| `backup` \| `store` \| `other` | Datenklasse (unten) |
| `access_mode` | enum: `read` \| `change` \| `export` | Art des Zugriffs |
| `scope` | enum: `one_customer` \| `several_customers` \| `all_customers` | Umfang |
| `record_commitment` | hex64 | Commitment des Vorgangs beim Betreiber (unten) |
| `capture` | enum: `gate` \| `declared` \| `emergency` | wie der Zugriff festgehalten wurde (unten) |

- **Zeiten.** `ts_captured` ist der Zeitpunkt des Zugriffs: bei `gate` der Eingang der Anfrage am Zugangsweg, beim Eintrag eines Dienstes je Start dieser Start, bei einem Sammeleintrag eines Dienstes `end(d)` seines Tages `d` als Zeitpunkt (Heartbeat-Spezifikation §12, Zugriffskette, Punkt 1), bei `declared` und `emergency` der Beginn des Zugriffs nach Angabe der Person. `ts_chained` ist die Verkettung; der Abstand zeigt, wie spät ein Zugriff eingetragen wurde.
- **`capture`.** `gate`: Der Zugangsweg hat den Eintrag über eine Import-Schnittstelle (`origin = import`) geschrieben und Daten erst ausgegeben, nachdem sie ihn bestätigt hat (Abschnitt 8.7, Import). Ein Dienst schreibt seinen Eintrag je Start und seine Sammeleinträge ebenso mit `gate` über die Import-Schnittstelle, wartet dafür aber nicht auf die Bestätigung (Heartbeat-Spezifikation §12, Zugriffskette, Punkt 2). `declared`: Eine Person hat den Zugriff selbst eingetragen (`origin = portal`), etwa nach einem Zugang, den kein Zugangsweg vermittelt. `emergency`: Ein Zugangsweg hat Daten ohne Bestätigung ausgegeben, weil die Zugriffskette nicht erreichbar war, und die Person hat den Zugriff danach eingetragen (`origin = portal`).
- **`record_commitment`** = `Hex(HMAC-SHA-256(key = salt, message = Vorgang))`. Der Vorgang sind die Bytes, die der Betreiber zu diesem Zugriff festhält (Anlass, Begründung, betroffene Kunden, bei `gate` die Anfrage); `salt` ist ein 32-Byte-Zufallswert je Vorgang. Vorgang und Salz bleiben beim Betreiber, nie in der Kette (wie in Abschnitt 9.1) und nie auf der Anlage, die die Zugriffskette führt: Bei `declared` und `emergency` gibt die Person `access_id` und `record_commitment` so ein, wie der Betreiber sie zu Vorgang und Salz gebildet hat. Je (`access_id`, `data_class`) trägt eine Zugriffskette höchstens einen Eintrag, gleich über welchen Weg er kam; ein Zugriff, dessen Daten ohne Bestätigung ausgegeben wurden, steht darin nur als `emergency`, nie zusätzlich als `gate`. Wer beide vorgelegt bekommt, rechnet das Commitment nach; der Verifier tut das nicht (kein Beleg durch LEDGER für den Inhalt des Vorgangs).
- **Datenklassen** folgen der Aufstellung „Was der Hersteller hält“ in Heartbeat-Spezifikation §12: `license` Lizenzen; `registration` Registrierungen und Geräteschlüssel; `heartbeat` Heartbeats; `chain` Bindungen, Wurzeln, Kettenwechsel, Fork-Befunde und Daten des Herstellerprotokolls, auch Öffnungen von Füllern (Abschnitt 7.4.13); `journal` Ausstellungs- und Bindungsjournal und die Erklärungen der Lizenznehmer (Heartbeat-Spezifikation §9.10, Pflicht 2); `affiliation_register` Verbundenheitsregister; `alarm_contact` Alarmadressen und Alarmpostfach; `order_system` Bestellsystem; `credentials` Verwaltungszugänge, Schlüssel und Zugangsmarken, auch das Kontenverzeichnis der Zugriffskette; `access_chain` die Zugriffskette selbst mit ihren Vorgängen und Salzen (Heartbeat-Spezifikation §12), etwa wenn die Prüfung sie liest; `operations_log` Betriebsprotokolle; `backup` Sicherungen; `store` der ganze Datenbestand, etwa die Datei einer Datenbank oder der Zugang zu einem Rechner; `other` eine andere Klasse, die der Vorgang nennt.
- **Zwecke.** `service` ist der Dauerzweck eines Dienstes, festgehalten einmal je Start des Dienstes und je Datenklasse; als Dienst gilt nur ein Teil, dessen Ausgabe keine Person unmittelbar liest, jeder andere ist ein Zugangsweg (Heartbeat-Spezifikation §12, Zugriffskette, Punkt 1). Ein Sammeleintrag, mit dem ein Dienst Verwaltungshandlungen an Lizenzen festhält, trägt `license_admin` (ebenda). `other` verweist auf den Vorgang.
- DATA_ACCESS ist **kein kritischer Typ** und **kein Befund**; Verifier prüfen das Schema. Für die Stille-Regeln (Abschnitt 8.2) deckt er nichts; wie jeder Eintrag begrenzt er lediglich ein Stillefenster. In Restfenster und gedeckte Strecken (Abschnitt 11.2) geht er nicht ein, und die Beweisstufe (Abschnitt 10.9) liest ihn nicht. Ein Verifier der Fassung 1.9 meldet den Typ als `UNKNOWN_ENTRY_TYPE` (Abschnitt 10.6, Regel 2) und prüft die Kette sonst vollständig.

### 4.26 Referenzierte Enumerationen

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

**Bäume des Herstellerprotokolls (ab Fassung 1.10).** Die Bäume aus Abschnitt 7.4 folgen derselben Konstruktion mit Domain-Separation. Ihre Blattdaten sind die Bytes eines Blatts nach Abschnitt 7.4, beliebig lang; das Blatt-Input ist `0x00` gefolgt von diesen Bytes, der Blatt-Hash `SHA-256(0x00 || Blattdaten)`. Für die Kette selbst bleibt es bei n ≥ 1. Die Konstruktion ist die von RFC 9162 Abschnitt 2.1 mit SHA-256, im Sinn von RFC 9942 die Datenstruktur `RFC9162_SHA256` (Wert 1); auf ihr beruhen die COSE Receipts für die Kette (Profil C1) und für die Tage des Herstellerprotokolls (Profil C2, Abschnitt 7.7). Für diese Bäume gilt zusätzlich:

- **Leerer Baum:** `MTH([]) = SHA-256("")` = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, der SHA-256-Wert der leeren Bytefolge.
- **Inklusionsbeweis** nach RFC 9162 Abschnitt 2.1.3.2. Ein Verifier MUSS ihn genau nach diesem Ablauf prüfen (`H` = SHA-256, `leaf_hash` = Blatt-Hash, `path` = die Geschwisterwerte vom Blatt zur Wurzel):

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

  Die Baumgröße `size` MUSS aus dem signierten Tageseintrag stammen (Abschnitt 7.4.5), nie aus dem Beweismaterial: Derselbe Pfad kann auch für eine falsche Größe tragen (Beispiel: Der Pfad zum Blatt mit Index 2 eines Baums der Größe 5 trägt auch für die Größe 6).
- **Abwesenheitsbeweis:** In einem Baum der Größe n mit Wurzel R, dessen Blätter streng aufsteigend nach ihrer Position geordnet sind (Abschnitt 7.4.4), belegt genau eine der folgenden Formen, dass die Position p darin nicht vorkommt: (i) n = 0 und kein Nachbar; (ii) ein Nachbar mit Index 0, und p ist kleiner als seine Position; (iii) ein Nachbar mit Index n − 1, und seine Position ist kleiner als p; (iv) zwei Nachbarn mit den Indizes i und i + 1, und pos_i < p < pos_{i+1}. Jedes Nachbarblatt MUSS durch einen Inklusionsbeweis gegen (n, R) tragen. Positionen werden als 32-Byte-Werte ohne Vorzeichen verglichen; das ist gleichbedeutend mit dem Vergleich ihrer Kleinbuchstaben-Hex-Form.

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

**Angaben außerhalb des Pakets (ab Fassung 1.10).** Neben den drei Ankertypen der Kette (Gegensignatur, Abschnitt 7.1; Papier-Anker, Abschnitt 7.2; Zeitzeuge, Abschnitt 7.3) gibt es zwei Angaben, die nur der Prüfer beibringt, nie das Paket: das Herstellerprotokoll (Abschnitt 7.4) und die Anker-Historie (Abschnitt 8.8). Beide prüft der Verifier gegen Anker des Prüfers; das Paket bleibt unverändert. Gegensignatur und Zeitzeuge stehen als Einträge in der Kette, den Papier-Anker übergibt der Prüfer als erwartete Wurzel (Abschnitt 10.8). Für die Zeitstempel der Zeitzeugen und des Herstellerprotokolls gilt dasselbe Zeitstempelprofil (Abschnitt 7.5).

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

1. **Herstellerwurzel.** Der Offline-Wurzelschlüssel des Herstellers als `{"wurzel_id", "pubkey"}` (Abschnitt 10.7), veröffentlicht mit der Lizenz; ein Verifier-Build des Herstellers KANN ihn eingebaut tragen und MUSS das bei der Versionsausgabe nennen. Die Wurzel bürgt für Gegenzeichnungsschlüssel über die signierte Liste der Gegenzeichnungsschlüssel `keys/vendor/schluesselliste.json` im Paket (Abschnitt 10.7.1).
2. **Angehefteter Schlüssel.** Ein einzelnes Paar `key_id` = Publikey, das der Prüfer selbst beschafft hat.

Nennt der Prüfer zwei Wurzeln derselben `wurzel_id` oder zwei Anheftungen derselben `key_id` mit verschiedenen Publikeys (auch gegenüber einer eingebauten Wurzel), ist die Prüfumgebung mehrdeutig; der Verifier MUSS den Aufruf ablehnen (Exit 3) und DARF NICHT stillschweigend einen der beiden wählen.

Für jede Quittung bestimmt der Verifier den Schlüssel in dieser Reihenfolge:

- Ist `server_key_id` angeheftet, gilt der angeheftete Publikey. Die Signatur wird gegen **ihn** geprüft, nicht gegen die Kopie im Manifest; scheitert sie, ist das `RECEIPT_INVALID` (Exit 2). Die Anheftung hat Vorrang vor der Liste, auch vor deren Gültigkeitsfenster: Wer anheftet, trifft die Aussage über den Schlüssel selbst.
- Sonst: Führt das Paket eine Liste, deren Signatur gegen eine Wurzel des Prüfers trägt (Abschnitt 10.7), und nennt sie `server_key_id`, gilt der Publikey der Liste; die Kopie im Manifest ist dann ohne Belang. `RECEIPT_INVALID` (Exit 2) ist es, wenn die Signatur gegen ihn scheitert oder wenn `server_ts` außerhalb des Gültigkeitsfensters des Schlüssels liegt (`gueltig_ab` ≤ `server_ts`; `server_ts` < `gueltig_bis`, falls vorhanden; `server_ts` < `widerrufen_ab`, falls vorhanden). Im zweiten Fall widerspricht die signierte Aussage des Herstellers der Quittung. `server_ts` wird dabei nach der Grammatik von Abschnitt 10.7 gelesen; ein `server_ts`, der sich so nicht lesen lässt, liegt in keinem Fenster.
- Sonst gilt der Publikey aus dem Manifest. Trägt die Signatur, meldet der Verifier `RECEIPT_UNVERIFIED` (Exit 1), **einmal je `server_key_id`**, mit `key_id` und Publikey im Bericht, damit der Prüfer den Schlüssel außerhalb des Pakets nachschlagen kann. Scheitert sie oder fehlt der Schlüssel im Manifest, bleibt es `RECEIPT_INVALID` (Exit 2).

Eine Liste, die nicht trägt (keine Wurzel beigebracht, andere `wurzel_id`, Signatur scheitert, Format verletzt), macht keinen Schlüssel glaubwürdig; sie ist aber auch **kein Fälschungsbefund**, denn die Liste steht in keiner Hash-Kette. Die betroffenen Quittungen sind dann `RECEIPT_UNVERIFIED`, und der Bericht nennt den Grund. Ebenso ein Schlüssel, der in einer tragenden Liste fehlt: Die Liste kann älter sein als der Schlüssel.

Die Trennung zwischen `RECEIPT_INVALID` und `RECEIPT_UNVERIFIED` folgt Abschnitt 7.3: Eine Signatur, die nicht trägt, oder eine signierte Aussage des Herstellers, die der Quittung widerspricht, ist ein Befund über die **Kette**. Ein fehlender Anker ist eine Aussage über die **Prüfumgebung**. Das Beste, was eine Fälschung mit erfundenem Schlüssel erreicht, ist damit ein benannter Befund mit Exit 1, nie Exit 0.

**Was als Verankerung zählt.** Eine Quittung, deren Signatur gegen den nach dieser Regel bestimmten Schlüssel trägt, zählt als vorhandene externe Verankerung, auch unter `RECEIPT_UNVERIFIED`, so wie ein Zeitzeuge unter `TIME_ANCHOR_UNVERIFIED` (Abschnitt 7.3); `NO_ANCHOR` sagt dann nichts Zusätzliches. Eine Quittung mit `RECEIPT_INVALID` zählt nicht: Sind alle Quittungen ungültig und liegt kein anderer Anker vor, meldet der Verifier `NO_ANCHOR` daneben. Die Präfix-Prüfung (`FORK_DETECTED`) gilt für jede Quittung, deren Signatur trägt, unabhängig davon, ob ihr Schlüssel belegt ist, und auch dann, wenn die Liste ihr widerspricht: Ein Widerspruch darf einen Fork nicht verdecken.

**Schlüssel und Listen neben dieser Regel (ab Fassung 1.10).** Ein Schlüssel belegt eine Quittung weiterhin nur auf den beiden Wegen oben, und nur ein Schlüssel der Rolle `countersigning` (Abschnitt 10.7.3). Dazu vier Klarstellungen:

- Ein Schlüssel einer anderen Rolle belegt nie eine Quittung: kein Bescheidschlüssel, kein Schlüssel des Update-Manifests, kein Protokollschlüssel des Herstellerprotokolls (Abschnitt 7.4.7) und, ab Fassung 1.10, kein Transparenzschlüssel (Abschnitt 7.7). Die Rollenliste (Abschnitt 10.7.2) belegt nie eine Quittung, auch nicht mit ihren Einträgen der Rolle `countersigning`. Eine Quittung, die nach den beiden Wegen oben nicht belegt ist und deren Publikey im Manifest ein Schlüssel einer anderen Rolle ist (ein Eintrag der wirksamen Rollenliste mit einer anderen Rolle, ein Schlüssel der wirksamen Protokollschlüsselliste oder eine Anheftung als Bescheid-, Protokoll- oder Transparenzschlüssel), wird beurteilt wie in Fassung 1.9 (`RECEIPT_UNVERIFIED`, wenn `manifest.vendor_pubkeys` den Schlüssel nennt); der Bericht gibt den Hinweis `receipt_key_other_role` (Abschnitt 10.7.4), und für Bedingung (3) der Beweisstufe hat sie die Herkunft `manifest` (Abschnitt 10.9.4).
- Eine Anheftung als Gegenzeichnungsschlüssel (`--vendor-key`), deren Publikey die wirksame Rollenliste mit einer anderen Rolle nennt, entfällt (Abschnitt 10.7.4, Schritt R3 (d)); sie gilt dann als nicht übergeben. Ohne Rollenliste sieht der Verifier die Rolle einer Anheftung nicht (Abschnitt 11.2).
- Eine Liste der Gegenzeichnungsschlüssel, die der Prüfer selbst übergibt (Abschnitt 10.8), belegt in dieser Fassung weder eine Quittung noch eine Seite der Anker-Historie; sie zählt nur bei der Rollenprüfung mit (Abschnitt 10.7.4; Abschnitt 7.4.10, Schritt L1). Belegte eine Liste des Prüfers Quittungen, könnte eine neuere Liste, deren `widerrufen_ab` vor echten, schon ausgestellten Quittungen liegt, archivierte ehrliche Pakete zu `RECEIPT_INVALID` (Exit 2) machen, gezielt gegen einen Kunden, wenn seine Anker einen eigenen Schlüssel trugen. Aus demselben Grund belegt die Rollenliste keine Quittung.
- Dass das Herstellerprotokoll eine Quittung enthält, belegt ihren Schlüssel nicht; die Aufnahme in einen Tagesbaum ist kein dritter Weg. Der Bericht zeigt die Aufnahme neben der Herkunft des Schlüssels. Ebenso wenig belegt eine COSE-Gegensignatur (Profil C1, Abschnitt 7.7.3) eine Quittung oder ihren Schlüssel: Sie ist eine weitere Aussage des Herstellers über dieselbe Wurzel unter einem Transparenzschlüssel, keine Verankerung, und sie steht nie in der Kette.

**Was diese Regel nicht leistet.** Das Gültigkeitsfenster wird gegen `server_ts` geprüft, und `server_ts` steht in der Quittung selbst. Wer einen widerrufenen Schlüssel besitzt (genau der Fall, für den es den Widerruf gibt), kann Quittungen mit einem `server_ts` vor dem Widerruf signieren; der Verifier vergleicht `server_ts` mit keiner anderen Zeit der Kette, und der Schlüsselinhaber der Kette könnte deren Zeiten ohnehin mit zurückdatieren. Gegen eine solche Rückdatierung wirken nur Anker, die der Fälscher nicht nachträglich erzeugen kann: der Papier-Anker (7.2), der Zeitzeuge (7.3) und das Freshness-Fenster (8.5). Ab Fassung 1.10 wirkt dagegen das Herstellerprotokoll (Abschnitt 7.4): Eine Quittung, die nachträglich mit einem widerrufenen oder entwendeten Schlüssel signiert wurde, steht in keinem bezeugten Tagesbaum des Tages ihres `server_ts`; übergibt der Prüfer das Protokoll, meldet der Verifier `RECEIPT_NOT_LOGGED`. Das gilt für Tage, deren Eintrag bezeugt ist, nicht für Tage, deren Eintrag noch nicht fällig ist, und nicht für Tage vor dem Beginn des Protokolls (`before_start`). Eine Quittung, deren `server_ts` nach dem Prüfzeitpunkt liegt, steht in keinem abgeschlossenen Tag; der Verifier meldet sie als `VENDOR_LOG_UNVERIFIED` (Klasse `future`, Abschnitt 7.4.10, Schritt L8), nie als noch nicht fällig. Ebenso kann der Verifier nicht erkennen, ob es eine neuere Liste gibt als die im Paket: `version` ist nur untereinander vergleichbar. Der Bericht nennt deshalb Version und Ausstellzeit der verwendeten Liste, damit der Prüfer sie beim Hersteller abgleichen kann.

Ab `spec_version` 1.1 legt die Appliance dem Anker zusätzlich den RFC-6962-Konsistenzbeweis von der Bezugsgröße der Kette (der zuletzt quittierten oder als Lückenzeuge festgehaltenen `tree_size`) zur neuen bei (Heartbeat-Spezifikation §6 und §9.2); der Hersteller-Server gegenzeichnet eine gewachsene Kette nur, wenn dieser Beweis trägt. Für den Verifier ändert sich dadurch nichts: Beweisgegenstand bleibt die Quittung, und die Präfix-Prüfung dieses Abschnitts bleibt seine eigene.

### 7.2 Papier-Anker

Der Monatsbericht druckt die Merkle-Wurzeln (und `tree_size`) der Monats-Checkpoints ab. Ein Prüfer KANN eine abgedruckte Wurzel als erwartete Wurzel an den Verifier übergeben (z. B. `--expect-root`); weicht die neu berechnete Wurzel ab, ist die Kette gegenüber dem Papierstand nicht konsistent (`MERKLE_INCONSISTENT`). Papier-Anker sind herstellerunabhängig.

### 7.3 Zeitzeuge (TIME_ANCHOR)

Eine Zeitstempelstelle nach RFC 3161 (TSA) bezeugt, dass ein Checkpoint zu einem bestimmten Zeitpunkt **bereits existierte**. Anders als die Gegensignatur des Herstellers stammt diese Aussage aus einer Quelle, die weder der Kunde noch der Hersteller kontrolliert; die Stelle wird vom Kunden eingerichtet oder, auf einen Vorschlag hin, von ihm bestätigt (unten).

Der Zeitstempel wird über den **kanonischen Checkpoint-Signaturgegenstand** aus Abschnitt 6.1 gebildet, also über genau die Bytes, die auch die Geräte-Signatur des Checkpoints deckt. Damit bezeugt er nicht nur die Wurzel, sondern `chain_id`, `tree_size`, `prev_checkpoint_hash`, `key_id` und die Checkpoint-Zeit mit.

Der `messageImprint` des Tokens MUSS sein: `H(JCS(Signaturgegenstand des Checkpoints))`, wobei `H` der im Token selbst genannte Abdruck-Algorithmus ist. Zulässig sind `sha256`, `sha384`, `sha512`; `sha1` ist es NICHT: eine Kollision auf dem Abdruck würde ein Token zwei verschiedene Checkpoints bezeugen lassen, und genau das soll der Anker ausschließen.

Der Token wird als `TIME_ANCHOR`-Eintrag (Abschnitt 4.22) in die Kette geschrieben. Ein Zeitzeuge ist **optional**: eine Kette ohne TIME_ANCHOR ist deswegen nicht mangelhaft, und sein Fehlen ist kein Befund.

**Vorgeschlagene Stelle (ab Fassung 1.10).** Eine Appliance KANN dem Kunden bei der Einrichtung eine Zeitstempelstelle vorschlagen. Für eine vorgeschlagene Stelle gilt dasselbe wie für jede andere und zusätzlich:

1. Sie wird weder vom Hersteller noch von einer mit ihm verbundenen Stelle betrieben (Heartbeat-Spezifikation §12).
2. Die Appliance verbindet sich mit ihr erst, wenn der Kunde sie bestätigt hat; bis dahin geht kein Byte zu ihr. Der Kunde kann sie jederzeit abwählen oder durch eine andere Stelle ersetzen.
3. Die Appliance fragt die Stelle unmittelbar an, nie über den Hersteller. Die Anfrage trägt nichts über die Anlage oder den Kunden und keine Berechtigung, die der Hersteller vergibt oder bezahlt; sie SOLL eine Nonce und `certReq = true` tragen.
4. Der Hersteller liefert die Wurzel der Stelle nicht aus, weder im Prüfpaket (`keys/tsa/`) noch als Datei für den Prüfer, und kein Verifier trägt sie eingebaut. Seine Dokumentation nennt die Stelle und den Ort, an dem die Stelle selbst ihre Wurzel veröffentlicht; der Prüfer beschafft die Wurzel dort oder aus einer Vertrauensliste (Abschnitt 10.8).
5. Sie SOLL von einem anderen Betreiber geführt werden als die Stellen, die der Hersteller für die Tageseinträge seines Protokolls nutzt (Heartbeat-Spezifikation §9.9), damit Zeitzeugen der Kette und Zeitstempel des Protokolls nicht auf derselben Stelle beruhen.

Welche Stelle vorgeschlagen wird, in welchem Takt die Appliance anfragt und wie die Einrichtung abläuft, legt diese Spezifikation nicht fest. Für den Verifier gibt es keine vorgeschlagene Stelle: Er prüft jeden TIME_ANCHOR nach denselben Schritten, und eine Stelle zählt nur über eine Wurzel, die der Prüfer übergibt. Ob eine Stelle dem Kunden oder dem Hersteller zuzurechnen ist, prüft der Verifier nicht (Abschnitt 11.2).

**Prüfregeln.** Der Verifier MUSS für jeden TIME_ANCHOR in dieser Reihenfolge prüfen. Ab Fassung 1.10 gelten dabei die Regeln des Zeitstempelprofils (Abschnitt 7.5), damit jeder Verifier über dasselbe Token gleich urteilt:

1. `checkpoint_seq` verweist auf einen CHECKPOINT, dessen `tree_size` und `merkle_root` den Feldern des Eintrags entsprechen. Sonst `TIME_ANCHOR_INVALID` (Exit 2).
2. `token_base64` folgt der Grammatik B64 (Abschnitt 2), das dekodierte DER umfasst höchstens 16 384 Bytes, und das Token folgt der Grammatik T (Abschnitt 7.5.2): ein TimeStampToken mit genau einem Signierer und genau einem TSTInfo in striktem DER. Sonst `TIME_ANCHOR_INVALID` (Exit 2).
3. Die drei Ablesungen `tsa_policy`, `tsa_serial` und `tsa_ts` stimmen mit dem Token überein. Der Abdruck-Algorithmus hat im Eintrag kein Feld; er wird in Schritt 4 verwendet. Ab Fassung 1.10 MUSS `tsa_ts` gleich `genTime` sein, auf Millisekunden abgeschnitten (nicht gerundet), in der Form `JJJJ-MM-TTThh:mm:ss.sssZ`; ein `genTime` mit Sekundenbruchteilen ist zulässig. Die Form von `tsa_ts` prüft schon das Schema der Nutzlast (eine andere Form ist `FORMAT_ERROR`); in diesem Schritt zählt, ob ein Wert dieser Form gleich `genTime` ist, auf Millisekunden abgeschnitten. Sonst `TIME_ANCHOR_INVALID` (Exit 2).
4. Der `messageImprint` des Tokens entspricht dem oben genannten Abdruck über den Signaturgegenstand des referenzierten Checkpoints. Sonst `TIME_ANCHOR_INVALID` (Exit 2). **Dies ist die tragende Bindung**, und sie ist ohne Signaturprüfung prüfbar: Abdruck berechnen, mit `hashedMessage` im TSTInfo vergleichen.
5. Die CMS-Signatur des Tokens, ab Fassung 1.10 in zwei Teilen:
   - **5a Ausführbarkeit.** Das Token trägt signierte Attribute und `certificates`; jedes Element von `certificates` genügt Z.1 (Abschnitt 7.5.3); der Signierer ist nach Z.5 genau einmal gefunden (Abschnitt 7.5.5); Abdruck- und Signaturalgorithmus des Signierers und sein Schlüssel liegen in Z.2 (Abschnitt 7.5.4) und passen nach Z.2 zueinander. Sonst ist die Signatur nicht prüfbar: `TIME_ANCHOR_UNVERIFIED` (Exit 1) mit dem Grund, nie Exit 2.
   - **5b Prüfung.** Das Attribut `contentType` nennt id-ct-TSTInfo, `messageDigest` ist der Hash von `eContent` nach dem `digestAlgorithm` des Signierers, und die Signatur trägt unter dem Schlüssel des Signiererzertifikats über die DER-Kodierung der signierten Attribute mit dem Tag `0x31` statt `0xA0` (RFC 5652 Abschnitt 5.4). Schlägt das fehl, ist das `TIME_ANCHOR_INVALID` (Exit 2); ein Token, das seine eigene Signatur nicht trägt, ist gefälscht oder beschädigt.
6. Das Signiererzertifikat kettet nach Z.3 und Z.4 (Abschnitt 7.5.5) zu einem Vertrauensanker, den der PRÜFER für Zeitzeugen der Kette beibringt (ausdrücklich übergebene Wurzel; der Wurzelspeicher des Systems zählt ab Fassung 1.10 für keinen Zweck), und trägt genau die erweiterte Schlüsselverwendung `id-kp-timeStamping`, als kritisch markiert (RFC 3161 Abschnitt 2.3). Zählen dürfen nur Wurzeln des Zwecks `chain` (Abschnitt 7.5.7). Die Kettenprüfung erfolgt **zum `genTime` des Tokens**, nicht zur Uhrzeit der Prüfung; sonst verfiele der Beweis mit dem Zertifikat der Stelle. Gelingt das nicht, ist das `TIME_ANCHOR_UNVERIFIED` (Exit 1); führt ein Pfad zu einem Zertifikat aus `keys/tsa/`, benennt der Bericht die Stelle wie unten beschrieben.

Die Schritte teilen die möglichen Ergebnisse so auf (ab Fassung 1.10, für jeden Verifier gleich):

| Ergebnis | Fälle | Befund |
|---|---|---|
| Schritt 2 scheitert | `token_base64` verletzt B64; DER größer als 16 384 Bytes; das Token verletzt Grammatik T | `TIME_ANCHOR_INVALID` (Exit 2) |
| Schritt 1, 3 oder 4 scheitert | wie in den Schritten beschrieben, mit der Regel für `tsa_ts` aus Schritt 3 | `TIME_ANCHOR_INVALID` (Exit 2) |
| Schritt 5 ausgeführt und gescheitert (5b) | `contentType` ist nicht id-ct-TSTInfo; `messageDigest` weicht vom Hash von `eContent` ab; die Signatur trägt nicht unter dem Schlüssel des Signierers | `TIME_ANCHOR_INVALID` (Exit 2) |
| Schritt 5 nicht ausführbar (5a) | keine signierten Attribute; keine `certificates`; der Inhalt von `certificates` zerfällt nicht in TLV; ein Element von `certificates` ist kein Zertifikat oder verletzt Z.1; Signierer nicht oder mehrfach gefunden (Z.5); Abdruck- oder Signaturalgorithmus oder Schlüssel des Signierers außerhalb von Z.2; Schlüssel und Algorithmus passen nicht zueinander | `TIME_ANCHOR_UNVERIFIED` (Exit 1) mit dem Grund |
| Schritt 6 scheitert | kein Pfad nach Z.3 und Z.4 zum `genTime` zu einer Wurzel des Prüfers für Zeitzeugen | `TIME_ANCHOR_UNVERIFIED` (Exit 1) |
| Schritt 6 trägt | ein Pfad zu einer Wurzel des Prüfers für Zeitzeugen | kein Befund |

Die Bindung des Signiererzertifikats in den signierten Attributen (Z.6, Abschnitt 7.5.6) ändert den Befund eines TIME_ANCHOR nicht; sie zählt für die Beweisstufe (Abschnitt 10.9).

**Schritte 1 bis 4 sind für jeden Verifier Pflicht.** Sie kommen ohne Signaturprüfung und ohne Zertifikate aus: Base64 nach B64 dekodieren, die Hülle nach Grammatik T lesen, den Abdruck über den Signaturgegenstand berechnen und mit `hashedMessage` vergleichen, die drei Ablesungen vergleichen. Sie MÜSSEN unabhängig vom Lesen der Zertifikate abschließen: Eine Eigenheit eines Zertifikats führt nie zu Exit 2, sondern höchstens zu Schritt 5a. Ein Verifier, der die Schritte 5 und 6 nicht ausführen KANN (weil ihm keine CMS-Implementierung zur Verfügung steht), DARF daraus NICHT `TIME_ANCHOR_INVALID` machen. Er MUSS `TIME_ANCHOR_UNVERIFIED` (Exit 1) melden und im Bericht sagen, dass er die Signatur nicht geprüft hat. Diese Regel ist keine Bequemlichkeit, sondern die Bedingung dafür, dass die Spezifikation mit Bordmitteln umsetzbar bleibt (Abschnitt 1): die tragende Bindung kann jeder prüfen, die Signaturkette nicht jeder.

Die Trennung zwischen 5 und 6 ist Absicht: Eine gebrochene Signatur ist ein Fälschungsbefund. Ein fehlender oder nicht erreichbarer Vertrauensanker ist eine **Aussage über die Prüfumgebung**, nicht über die Kette, und ein Verifier, der beides gleich behandelte, würde entweder ehrliche Ketten für manipuliert erklären oder gefälschte durchwinken. Aus demselben Grund trennt Schritt 5 die Ausführbarkeit (5a) von der Prüfung (5b): Ein Token, dessen Signatur ein Verifier nach dem Profil nicht prüfen kann, ist für ihn nicht prüfbar, nicht gefälscht.

**Warum der Vertrauensanker nicht aus dem Paket kommen darf.** Das Prüfpaket wird von genau der Partei geschrieben, gegen die der Zeitzeuge schützen soll. Ein Zertifikat aus `keys/tsa/` belegt daher nur Selbstkonsistenz. Ein Verifier DARF solche Zertifikate zur Kettenbildung heranziehen, MUSS in diesem Fall aber `TIME_ANCHOR_UNVERIFIED` (Exit 1) melden und im Bericht die Stelle benennen (Name, Seriennummer, `genTime`), damit der Prüfer sie außerhalb des Pakets nachschlagen kann. Nur ein Anker, den der Prüfer selbst beibringt, macht den Zeugen unabhängig.

Ein TIME_ANCHOR, der die Schritte 1 bis 4 besteht, zählt als vorhandene externe Verankerung: `NO_ANCHOR` (Abschnitt 7) wird dann NICHT gemeldet, auch wenn Schritt 6 scheitert. Die beiden Befunde sagen Verschiedenes („es liegt keine Verankerung vor" und „die vorliegende ist nicht unabhängig belegt"), und nur der zweite trifft hier zu. Diese Trennung hält auch Verifier gleich, die Schritt 6 gar nicht ausführen können.

**Was der Zeitzeuge nicht leistet.** Er beweist, dass ein Checkpoint zu einem Zeitpunkt existierte, nicht, dass die Kette vollständig ist. Gegen das Restfenster aus Abschnitt 11.2 wirkt er, weil eine später neu geschriebene Historie keinen Token mit früherem `genTime` beibringen kann; gegen das Weglassen von Einträgen VOR dem Zeitstempel wirken weiterhin nur Hash-Kette, Merkle-Konsistenz und die übrigen Anker.

### 7.4 Herstellerprotokoll

Ab Fassung 1.10. Mit dem Herstellerprotokoll legt sich der Hersteller für jeden abgeschlossenen UTC-Tag öffentlich auf die Menge der Gegensignaturen (Abschnitt 7.1) und Lückenzeugen (Heartbeat-Spezifikation §9.2) fest, die er an diesem Tag erteilt oder festgehalten hat; Zeitstempelstellen bezeugen die Festlegung. Übergibt der Prüfer das Protokoll, zeigt der Verifier, ob die Quittungen des Pakets darin stehen und ob dort festgehaltene Wurzeln dem Paket widersprechen. Dieser Abschnitt legt Formate und Prüfung fest; wie der Hersteller einen Tag abschließt und veröffentlicht, regelt Heartbeat-Spezifikation §9.9.

#### 7.4.1 Stellung und Schlüssel

Das Herstellerprotokoll ist eine Angabe des Prüfers (Abschnitt 10.8). Nichts davon steht im Prüfpaket, in der Kette, in einer Quittung, im Manifest, in der Liste der Gegenzeichnungsschlüssel oder der Rollenliste (Abschnitte 10.7.1, 10.7.2), in einer Nachricht der Appliance oder in der Anker-Historie der Form v1 (Heartbeat-Spezifikation §9.7); die Appliance ruft es nie ab (Heartbeat-Spezifikation §1). Ein Verifier DARF Material des Protokolls NICHT aus dem Paket lesen.

Der Hersteller schließt je UTC-Tag genau einen Tageseintrag ab, lückenlos ab dem Tag `erster_tag` seiner Protokollschlüsselliste (Abschnitt 7.4.7), auch für einen Tag ohne Blätter. Der Tageseintrag legt ihn auf alle Gegensignaturen und Lückenzeugen des Tages fest (Abschnitt 7.4.2), trägt die Signatur eines eigenen Protokollschlüssels (Abschnitt 7.4.5) und Zeitstempel nach RFC 3161 (Abschnitt 7.4.6) und erscheint an den Veröffentlichungsorten der Protokollschlüsselliste. Er trägt keine Kundendaten, keine `appliance_id`, kein Commitment und keine `chain_id` im Klartext.

| Schlüssel | bestätigt durch | signiert | signiert nie |
|---|---|---|---|
| Herstellerwurzel | den Prüfer oder einen Verifier-Build des Herstellers, der sie eingebaut trägt und nennt (Abschnitt 7.1) | die drei Schlüssellisten: Liste der Gegenzeichnungsschlüssel (Abschnitt 10.7.1), Rollenliste (Abschnitt 10.7.2) und Protokollschlüsselliste (Abschnitt 7.4.7) | Daten des laufenden Betriebs |
| Gegenzeichnungsschlüssel (Rolle `countersigning`) | Anheftung oder Liste der Gegenzeichnungsschlüssel (Abschnitt 7.1) | Quittungen; bis zum Ende des Doppelbetriebs auch die Hülle von Lizenzbescheiden, Verweigerungsbescheiden und Aktivierungsquittungen und Seiten der Anker-Historie der Form v1 (Abschnitt 10.7.5) | Seiten der Form v2, Update-Manifest, Tageseinträge |
| Bescheidschlüssel (Rolle `statements`) | Rollenliste oder Anheftung als Bescheidschlüssel (Abschnitt 10.7.4) | Lizenzbescheide, Verweigerungsbescheide, Aktivierungsquittungen und Seiten der Anker-Historie (Heartbeat-Spezifikation §9) | Quittungen, Update-Manifest, Tageseinträge |
| Schlüssel des Update-Manifests (Rolle `update_manifest`) | Rollenliste; der Verifier verwendet ihn nicht | das Update-Manifest (Heartbeat-Spezifikation §9.4) | alles andere |
| Protokollschlüssel (Rolle `protocol`, aktiv und in Reserve) | Protokollschlüsselliste oder Anheftung als Protokollschlüssel (Abschnitt 7.4.10, Schritt L1); ein Schlüssel nach ML-DSA-87 nur durch die Liste `ledger-protokollschluessel/2` (Abschnitt 7.4.7a) | Tageseinträge, die der Hersteller selbst gebaut hat | alles andere |
| Transparenzschlüssel (Rolle `transparency`, ab Fassung 1.10, aktiv und in Reserve) | Rollenliste oder Anheftung als Transparenzschlüssel (Abschnitt 7.7.5) | COSE-Objekte der Profile C1 und C2 über ihre Sig_structure (Abschnitt 7.7) | alles andere |
| Schlüssel einer Zeitstempelstelle | Wurzeln des Prüfers für den jeweiligen Zweck (Abschnitt 7.5.7) | Zeitstempel | |

Jeder Schlüssel des Herstellers hat genau eine Rolle (Abschnitt 10.7.3). Derselbe Publikey in zwei Rollen macht eine Liste unwirksam oder lässt eine Anheftung entfallen (Abschnitt 10.7.4); steht ein Protokollschlüssel zugleich in einer anderen Rolle, ist die Protokollschlüsselliste unwirksam (Abschnitt 7.4.10, Schritt L1). Ein Transparenzschlüssel belegt nie einen Tageseintrag, eine Quittung oder eine Seite der Anker-Historie, und kein Schlüssel einer anderen Rolle belegt ein COSE-Objekt (Abschnitt 7.7.5). Die Zeitstempelstellen des Protokolls wählt der Hersteller, die Stellen der Zeitzeugen einer Kette wählt der Kunde (Abschnitt 7.3); eine Wurzel, die der Prüfer für die eine Seite übergibt, bestätigt nie die andere (Abschnitt 7.5.7).

#### 7.4.2 Blätter

Blätter werden nur gehasht, nie veröffentlicht. Es gibt zwei Arten:

- **Gegensignatur:** `UTF-8(JCS({"chain_id": …, "merkle_root": …, "server_ts": …, "tree_size": …}))`, genau die Bytes, die die Signatur der Quittung deckt (Abschnitt 7.1). `server_ts` ist byte-gleich mit dem der Quittung. Ab Fassung 1.10 schreibt der Server ihn genau in der Form `JJJJ-MM-TTThh:mm:ss.sssZ` (Heartbeat-Spezifikation §9.1); so sind Quittung und Blatt Zeichen für Zeichen gleich, für die früheste Gegensignatur einer Wurzel auch die Zeile der Anker-Historie (Heartbeat-Spezifikation §9.7).
- **Lückenzeuge** (Heartbeat-Spezifikation §9.2): `UTF-8(JCS({"chain_id": …, "kind": "ledger.vendor_log_gap_witness.v1", "merkle_root": …, "server_ts": …, "tree_size": …}))`. `server_ts` ist der Zeitpunkt, zu dem der Server den Lückenzeugen festhielt, ab Fassung 1.10 in derselben Form (Heartbeat-Spezifikation §9.2), und bleibt es, wenn dieselbe Wurzel erneut vorgelegt wird. Das Member `kind` unterscheidet das Blatt von jeder Gegensignatur mit denselben Werten. Für sich ist das Blatt nicht signiert (der Tageseintrag legt es fest); es trägt keine `appliance_id`, kein Commitment und nie den Verweigerungsbescheid.

**Blatt aus der Aufzeichnung (ab Fassung 1.10).** Jedes Blatt ist eine Funktion der Kette und einer Aufzeichnung des Herstellers in der Form einer Zeile der Anker-Historie (Heartbeat-Spezifikation §9.7): Aus `chain_id` C und einer Zeile (`tree_size`, `merkle_root`, `recorded_as`, `server_ts`) entsteht bei `recorded_as` = `countersigned` das Blatt einer Gegensignatur, bei `gap_witness` das Blatt eines Lückenzeugen, jeweils mit genau diesen Werten; eine Zeile `reported` ergibt kein Blatt. `server_ts` geht als die Zeichenkette ein, die Aufzeichnung, Zeile, Auszug oder Quittung trägt; Hersteller und Verifier lesen ihn nur für `day(server_ts)` und für Vergleiche und schreiben ihn nie neu. Für dieselbe Wurzel einer Kette (`chain_id`, `tree_size`, `merkle_root`) gibt es höchstens einen Lückenzeugen und damit höchstens ein Blatt eines Lückenzeugen (Heartbeat-Spezifikation §9.2). Ein Verweigerungsbescheid (Heartbeat-Spezifikation §9.5) ist nie Eingabe eines Blatts. Jedes Blatt umfasst mindestens 181 Bytes und gleicht deshalb nie der Eingabe eines Blatts des Merkle-Baums einer Kette, die 32 Bytes umfasst (Abschnitt 5).

Referenzwerte (Kette `3cef4d7e-4d65-41d6-912d-90d51fda8982` mit `appliance_id` `de431f78-75fd-49ae-b4bf-1cb543b635d1`, `tree_size` 42, `merkle_root` = SHA-256 der ASCII-Bytes `LEDGER-BEISPIEL-WURZEL-42`): Der Lückenzeuge mit `server_ts` `2026-03-01T23:58:00.000Z` hat den Blatt-Hash `6ae954c9cd400501c3cb2600954f229bd90da369e5f51898f204a46beafb70ce`, die Gegensignatur derselben Wurzel mit `2026-03-01T23:59:30.000Z` den Blatt-Hash `b1a9c17ad92c0112bd915a40e050a26a4ab1da47e34528dba51d81811ca7a6c7`, und beide ergeben die Kettentag-Wurzel `cde717fc82b66d14826268735294060bbf384f0631072c73f46c52056964efd1` an der Position `927d08078b4fa065e881fb6f761a660bd2b7afec5be467348492ec1c0ad055a4`. Gegengezeichnet erst am Folgetag mit `2026-03-02T00:03:00.000Z`, hat die Gegensignatur den Blatt-Hash `733e8945c2dec011786d37ccb6d89a75a92cb2b18ede80b114d339f9c50376c7` und steht an der Position `8b0fdc3d4d0ccec032096b89412a3206cf3a51da335c840859d9c7097925ecd8`. Derselbe Lückenzeuge mit dem neu formatierten `server_ts` `2026-03-01T23:58:00Z` ergibt ein anderes Blatt, das im Nachweis nicht steht.

**Blätter der Kette C am Tag d** sind jede Gegensignatur für C, die den Server mit `day(server_ts) = d` verlassen hat, und jeder Lückenzeuge für C mit `day(server_ts) = d`. Sie bilden eine Menge: Gleiche Bytes zählen einmal. Die erneute Auslieferung eines gespeicherten Originals ist dasselbe Blatt; eine frisch ausgestellte Wiederholung einer Gegensignatur ist ein weiteres Blatt. Eine Wurzel, die als Lückenzeuge festgehalten und später gegengezeichnet wurde, ergibt zwei Blätter, unter Umständen an verschiedenen Tagen. Nicht protokolliert werden gemeldete Wurzeln, Verweigerungen, Fork-Befunde, Bescheide und Aktivierungsquittungen.

**Warum das ganze Objekt mit `server_ts`.** Der Tag eines Blatts ist der Tag seines `server_ts`, und das Blatt bindet genau die Quittung, die der Kunde hält. Eine Quittung, die später mit einem entwendeten oder widerrufenen Schlüssel signiert wird, trägt ihren eigenen `server_ts` und steht in keinem bezeugten Tag. Ein Blatt nur aus `chain_id`, `tree_size` und `merkle_root` ließe eine protokollierte Wurzel jede zurückdatierte Quittung über diese Wurzel decken.

#### 7.4.3 Kettentag: Wurzel, Position und Blatt

Das Protokoll eines Tages ist ein Baum in zwei Ebenen: je Kette ein Kettentag-Baum über ihre Blätter des Tages, darüber der Tagesbaum über die Kettentag-Blätter und die Füller (Abschnitt 7.4.4), deren Positionen streng geordnet und in den Tagesblättern öffentlich sind (Abschnitt 7.4.9).

- **Kettentag-Wurzel:** `chain_root(C, d)` ist MTH (Abschnitt 5) über die Blätter der Kette C am Tag d, aufsteigend geordnet nach ihrem Blatt-Hash als 32-Byte-Wert ohne Vorzeichen; n ≥ 1.
- **Position:** `position(C, d) = SHA-256(UTF-8(JCS({"appliance_id": A, "chain_id": C, "day": d, "kind": "ledger.vendor_log_position.v1"})))`. Der Server setzt für A die Appliance ein, an die er die Kette gebunden hat, der Verifier `GENESIS.appliance_id` des Pakets.
- **Kettentag-Blatt:** `UTF-8(JCS({"chain_root": Hex(chain_root(C, d)), "kind": "ledger.vendor_log_day_leaf.v1", "position": Hex(position(C, d))}))`. Es trägt keine `chain_id`, keine Größe und keine Zeit; der Tag steckt in der Position. Die Art `ledger.vendor_log_day_leaf.v1` ist die jedes Blatts des Tagesbaums, auch eines Füllers (Abschnitt 7.4.4); sie sagt nichts über den Ursprung des Blatts.

**Warum Positionen, und warum mit der `appliance_id`.** Positionen sind je Kette und Tag verschieden, und der Tagesbaum ist streng nach ihnen geordnet. Zwei Kettentag-Blätter für dieselbe Kette und denselben Tag brauchen daher eine doppelte Position oder eine verletzte Ordnung; beides zeigen die veröffentlichten Tagesblätter, wenn jemand sie prüft (Abschnitt 7.4.9). Auf dieser Ordnung beruhen der Abwesenheitsbeweis (Abschnitt 5) und die Eigenschaft, dass eine Kette je Tag höchstens ein Kettentag-Blatt hat. Der Verifier prüft die Ordnung nicht, denn er liest die Tagesblätter nicht. Belegt sind beide deshalb nur zusammen mit einer Prüfung der veröffentlichten Tagesblätter des Tages; ohne sie kann ein Hersteller unter derselben Tageswurzel zwei Kettentag-Blätter einer Kette führen und verschiedenen Prüfern verschiedene Nachweise geben (Abschnitt 11.2). Weil die `appliance_id` in die Position eingeht, können aus den Tagesblättern nur der Hersteller und Inhaber eines Prüfpakets der Kette deren aktive Tage ablesen; die `chain_id` allein reicht dazu nicht. Ausgenommen ist die Zugriffskette des Herstellers, deren `chain_id` und `appliance_id` öffentlich sind (Heartbeat-Spezifikation §12, Zugriffskette, Punkt 9); ihre aktiven Tage kann jeder ablesen. Übernimmt jemand eine `chain_id` unter einer anderen Appliance, tragen seine Nachweise unter der Position der ehrlichen Kette nicht (`VENDOR_LOG_DEFECTIVE`); sie ergeben nie `LOGGED_ROOT_MISMATCH`.

#### 7.4.4 Tagesbaum, Baumgröße und Füller

- **Blätter des Tagesbaums:** `D(d)` sind die Kettentag-Blätter aller Ketten mit Blättern am Tag d und die Füller des Tages d, streng aufsteigend nach `position` geordnet (Vergleich wie in Abschnitt 5); keine Position kommt zweimal vor. Jedes Blatt hat die Form und die Art `ledger.vendor_log_day_leaf.v1` eines Kettentag-Blatts (Abschnitt 7.4.3).
- **Wurzel und Größe:** `root(d)` ist MTH über `D(d)` in dieser Reihenfolge (Abschnitt 5), `tree_size(d)` die Zahl der Blätter von `D(d)`. Zu `tree_size = 0` gehört `root = SHA-256("")`; nach der Größenregel kommt ein solcher Tag nicht vor, der Verifier nimmt ihn aber an (Abschnitt 7.4.10, Schritt L2 (g)).
- **Größenregel:** Ist n(d) die Zahl der Ketten mit Blättern am Tag d, so ist `tree_size(d)` die kleinste Zweierpotenz, die mindestens 1024 und mindestens n(d) ist. Die übrigen m(d) = `tree_size(d)` − n(d) Blätter sind Füller; ein Tag ohne Blätter hat 1024 Füller. Die Regel gilt für jeden Tageseintrag der Art `ledger.vendor_log_day.v1` und steht damit vor dem ersten Tag jedes Protokolls fest. Ausgenommen ist nur ein Protokoll, dessen Protokollschlüsselliste eine Herstellerwurzel aus `published_test_keys` signiert (Abschnitt 7.5.7), etwa in Testvektoren; ein solches Protokoll verbirgt nichts. Der Verifier prüft die Regel nicht; er prüft die Größe nur gegen den signierten Tageseintrag (Abschnitt 7.4.10). Dass `tree_size` eine Zweierpotenz und mindestens 1024 ist, kann jeder prüfen (Abschnitt 7.4.9, Prüfung (d)); ob es die kleinste zulässige ist, zeigt erst die Öffnung des Tages zusammen mit dem Nachweis des Ursprungs jedes übrigen Blatts (Abschnitt 7.4.13).
- **Füller:** Ein Füller ist ein Blatt des Tagesbaums in Form und Art eines Kettentag-Blatts, das zu keiner Kette gehört. Füller MÜSSEN öffentlich von Kettentag-Blättern nicht zu unterscheiden sein: Ihre `position` und ihre `chain_root` lassen sich ohne ein Geheimnis des Herstellers von zufälligen 32-Byte-Werten nicht unterscheiden, und ein Tag, der neu abgeschlossen wird (Heartbeat-Spezifikation §9.9), trägt dieselben Füller. Wie der Hersteller seine Füller bildet, ist **nicht Teil der Prüfung**: Kein Verifier liest, berechnet oder prüft einen Füller, und keine Prüfung dieser Spezifikation hängt von ihrer Bildung ab. Diese Fassung legt eine Bildung fest, mit der der Hersteller den Ursprung seiner Füller einer prüfenden Stelle oder einer Aufsicht nachweisen kann (die abgeleitete Bildung unten, mit der Öffnung nach Abschnitt 7.4.13); er KANN sie verwenden. Verwendet er sie nicht, bildet der Signierdienst die Füller aus einem kryptographisch sicheren Zufallsgenerator (Heartbeat-Spezifikation §9.9). Verwendet er sie, nennt die Protokollschlüsselliste ihre Füllerbindung (Abschnitt 7.4.7), sonst steht dort `null`. Er kann die abgeleitete Bildung auch später beginnen, mit der ersten Version der Liste, die die Füllerbindung nennt; Format und Verifier ändern sich dadurch nicht. Für Tage vor dieser Version ist der Ursprung seiner Füller nicht nachweisbar (kein Beleg durch LEDGER).
- **Abgeleitete Bildung:** Mit L = `log_id`, d in der Form `JJJJ-MM-TT` und HMAC-SHA-256 nach RFC 2104 mit SHA-256 gilt:

| Wert | Bildung |
|---|---|
| Füllergeheimnis G | 32 Bytes aus einem kryptographisch sicheren Zufallsgenerator, für jedes Protokoll ein eigenes, erzeugt vor der ersten Version der Protokollschlüsselliste, die seine Füllerbindung nennt, und danach unverändert (Heartbeat-Spezifikation §9.9); nie veröffentlicht |
| Füllerbindung | `SHA-256(UTF-8(JCS({"filler_secret": Hex(G), "kind": "ledger.vendor_log_filler_commitment.v1", "log_id": L})))`; steht als `fuellerbindung` in jeder Version der Protokollschlüsselliste ab der ersten, die sie nennt (Abschnitt 7.4.7), und ist öffentlich |
| Tagesgeheimnis g(d) | `HMAC-SHA-256(G, UTF-8(JCS({"day": d, "kind": "ledger.vendor_log_filler_secret.v1", "log_id": L})))` |
| Salz s(d, i) für i = 0, 1, 2, … | `HMAC-SHA-256(g(d), UTF-8(JCS({"index": i, "kind": "ledger.vendor_log_filler_salt.v1"})))` |
| Position des Kandidaten i | `SHA-256(UTF-8(JCS({"day": d, "kind": "ledger.vendor_log_filler_position.v1", "log_id": L, "salt": Hex(s(d, i))})))` |
| Wurzel des Kandidaten i | `SHA-256(UTF-8(JCS({"day": d, "kind": "ledger.vendor_log_filler_root.v1", "log_id": L, "salt": Hex(s(d, i))})))` |
| Blatt des Kandidaten i | `UTF-8(JCS({"chain_root": Hex(Wurzel), "kind": "ledger.vendor_log_day_leaf.v1", "position": Hex(Position)}))` |

- **Auswahl:** Die Füller des Tages d sind genau die Kandidaten i = 0 bis m(d) − 1; übersprungen wird kein Kandidat. Trifft die Position eines Kandidaten die Position eines Kettentag-Blatts oder eines anderen Kandidaten (das geschieht nur bei einer Kollision von SHA-256), schließt der Abschluss den Tag nicht ab und löst einen Alarm aus (Heartbeat-Spezifikation §9.9); andere Füller bildet er dafür nicht. Im Baum stehen die Füller nach ihrer Position zwischen den Kettentag-Blättern; der Index i hat mit dem Blattindex nichts zu tun. Weil der Index in kein Urbild von Position und Wurzel eingeht, zeigt die Öffnung eines einzelnen Füllers weder seinen Index noch die Zahl der Füller.
- **Bindung an den Tag:** Das Tagesgeheimnis hängt nur an `log_id` und Tag, nicht an `server_ts`. Ein Tag, der nach einem vernichteten Eintrag neu abgeschlossen wird (Heartbeat-Spezifikation §9.9), erhält einen neuen `server_ts`, aber dieselben Kandidaten; zwei Bäume desselben Tages teilen ihre Füller und zeigen nebeneinander nur die Blätter, in denen sie sich unterscheiden. Hinge das Tagesgeheimnis an `server_ts`, hätten zwei Bäume eines Tages nur ihre Kettentag-Blätter gemeinsam und zeigten zusammen, welche Blätter Füller sind. Wird derselbe `statement_jcs` unter einem anderen Protokollschlüssel neu signiert (Abschnitt 7.4.5), bleiben alle Füller ohnehin gleich.
- **Nicht öffentlich:** Füllergeheimnis, Tagesgeheimnisse, Salze, Indizes, m(d), n(d) und die Angabe, welche Blätter Füller sind, stehen in keinem Tageseintrag, in keinen Tagesblättern, in keinem Auszug, in keinem Nachweis und in keiner Ausgabe des Herstellers (Status, Statistik, Betriebsprotokolle). Die Füllerbindung ist öffentlich; aus ihr lässt sich G nicht berechnen. Zum Nachbau jedes Nachweises genügen die gesicherten Tagesblätter (Heartbeat-Spezifikation §9.9); das Füllergeheimnis braucht nur eine Öffnung (Abschnitt 7.4.13).
- **Was die Größe zeigt:** nur, ob an dem Tag mehr als 1024 Ketten Blätter hatten, und dann die Zweierpotenz, die ihre Zahl nach oben begrenzt; überschreitet die Zahl eine Zweierpotenz, zeigt die Größe an diesem Tag Wachstum. Die Tagesblätter (Abschnitt 7.4.9) umfassen 64 Bytes je Blatt, also mindestens 64 KiB je Tag.
- **Testvektoren** verwenden das veröffentlichte Füllergeheimnis G = SHA-256 der ASCII-Bytes `LEDGER-TESTVEKTOR-FUELLERGEHEIMNIS` (`bcfe9766f065da823b5e2cff936cd8aff9e6c5d59540557ae4fe2d02afa04acf`) und kleinere Bäume, als die Größenregel verlangt; ihre Protokollschlüssellisten signiert eine Wurzel aus `published_test_keys`.

Referenzwerte (Protokoll `ledger-testprotokoll-1`, Tag `2026-01-01`, Test-Füllergeheimnis): Die Füllerbindung ist `82ba087e5b1b7bee5dbfb6b34620efb2e23e1426ad25fe60a672035fb3a99efe`; g(d) = `cc0a0f17adfa12bc5887b25f7eb2f3745b798db1f94a5cbf0eebb9447006f962`; s(d, 0) = `e49f397932b6e32e2700638a9594ddbd3aeb9784a5129363c925e1bdb3eec14e`; Position des Kandidaten 0 `6a67ff9572b4d663920a2e740361b09ee2cb6acae8ecf613e6a30b16aad350f9`, seine Wurzel `27f678c7c3c9f763cb99aa6bfb4715d4667faa4b0d6c9f8a2e36e20250b4233c`, der Hash seines Blatts `294970b630c3526afb9c691702e0e939842253339bb6831386b70502f012f8c5`. Ein Tagesbaum aus einer Kette (Kettentag-Blatt mit der Position `b1ed9cae78dcfafe822b101de7ce470c80f85b3838f7d2701da3de2b588e2c04` und der Kettentag-Wurzel `b48375ab1d0a8b4e54d42d8a7c6239eea5ebac215b1b07f45cf8f912030bb2ea`) und den Kandidaten 0 bis 3 hat die Größe 5 und die Wurzel `0adcf8f084c1c9c0e8998f01a0a9a9b57e96b5e9135e2833cbb10c6a9e121871` (Beispiel in Abschnitt 7.4.5, mit `server_ts` `2026-01-02T00:05:00.000Z`); die Kette steht am Blattindex 3. Ein neuer Abschluss desselben Tages mit `server_ts` `2026-01-02T00:35:00.000Z` hat dieselben Füller und dieselbe Wurzel; der Folgetag hat g(d) = `eea894d57696feccaa8c45aee5e4d531924e1cfaa8b82356a36823b0582de9fc`. Nach der Größenregel hat derselbe Tag mit derselben Kette 1023 Füller und die Wurzel `053bc9260b2e032e8c9691fddb7ab200cf03436717d712e12da1a0b3589d7803`; die Kette steht dort am Blattindex 703, ihr Pfad umfasst 10 Hashes. Die Kettentag-Wurzel `b48375ab1d0a8b4e54d42d8a7c6239eea5ebac215b1b07f45cf8f912030bb2ea` dieses Beispiels ist ein beliebig gewählter Wert für die Berechnung des Baums; sie stammt aus keinen Zeilen, und zu ihr lässt sich kein Nachweis `present` bilden. Einen zweiten Referenztag, dessen Kettentag-Blatt das aus Abschnitt 7.4.2 ist (Kettentag-Wurzel `cde717fc82b66d14826268735294060bbf384f0631072c73f46c52056964efd1` an der Position `927d08078b4fa065e881fb6f761a660bd2b7afec5be467348492ec1c0ad055a4`), sodass zu ihm ein Nachweis `present` besteht, zeigt der Referenzfall in `spec/testvectors/protokoll/`.

**Warum die Art im Urbild steht und nicht im Blatt.** Trüge ein Füller seine Art im Blatt, zeigten die Tagesblätter die Zahl der Füller und damit die Zahl der Ketten. Deshalb hat jedes Blatt des Tagesbaums dieselbe Art `ledger.vendor_log_day_leaf.v1`, die nichts über seinen Ursprung sagt, und die Art eines Füllers steht in den Urbildern seiner Position und seiner Wurzel: Füller sind eine eigene Art von Blatt, erkennbar an ihrer Öffnung (Abschnitt 7.4.13), nicht an öffentlichen Daten. Beide Urbilder enthalten das Salz; ohne das Salz lässt sich keiner der beiden Werte aus dem anderen oder aus öffentlichen Daten berechnen. Ein Füller ist deshalb von einer Kette, deren `appliance_id` und `chain_id` man nicht kennt, nicht zu unterscheiden, auch nicht als Nachbar in einem Abwesenheitsbeweis.

**Warum ein Füller keiner Kette gehören kann.** Die Position einer Kette ist der Hashwert eines Objekts der Art `ledger.vendor_log_position.v1`, die eines Füllers der Hashwert eines Objekts der Art `ledger.vendor_log_filler_position.v1`. Die Wurzel einer Kette ist der Hashwert einer Eingabe, die mit dem Byte 0x00 oder 0x01 beginnt (Abschnitt 5), die Wurzel eines Füllers der Hashwert eines JSON-Objekts, das mit `{` beginnt. Gleiche Werte verlangten eine Kollision von SHA-256. Niemand kann daher einen Füller als Tag seiner Kette ausgeben, und der Hersteller kann kein Kettentag-Blatt als Füller öffnen (Abschnitt 7.4.13).

**Warum abgeleitet und nicht zufällig.** Mit abgeleiteten Füllern hat jedes Blatt des Tagesbaums einen Ursprung, den der Hersteller einer prüfenden Stelle nachweisen kann: ein Kettentag-Blatt durch die Blätter seiner Kette und ihre Bindung an die Appliance, ein Füller durch seine Öffnung. Ein Füller aus einem Zufallsgenerator hätte keinen nachweisbaren Ursprung und wäre von einem Blatt unbekannter Herkunft nicht zu unterscheiden. Mit der Füllerbindung legt sich der Hersteller schon vor dem ersten Tag auf das Füllergeheimnis fest; wer G erhält, rechnet die Ableitung jedes Tages nach (Abschnitt 7.4.13). Das Tagesgeheimnis ist für jeden Tag ein eigener HMAC-Wert, aus dem sich kein anderes berechnen lässt; das Salz ist für jeden Füller ein eigener Wert, sodass der Hersteller einzelne Füller öffnen kann, ohne ihren Index oder die Zahl der Füller des Tages zu zeigen.

#### 7.4.5 Tageseintrag `ledger.vendor_log_day.v1`

Ein Tageseintrag ist ein Objekt mit genau den Membern `statement_jcs`, `server_key_id` und `server_signature`, der Hülle aus Heartbeat-Spezifikation §9.4 ohne Lesekopie. `statement_jcs` ist die JCS-Form eines Objekts mit genau diesen Membern:

| Member | Typ | Regel |
|---|---|---|
| `day` | date (Protokollbereich) | der UTC-Tag, den der Eintrag abschließt |
| `first_day` | date (Protokollbereich) | Beginn des Protokolls; gleich `erster_tag` der Protokollschlüsselliste |
| `kind` | const `"ledger.vendor_log_day.v1"` | Art des Eintrags |
| `log_id` | key-id | gleich `log_id` der Protokollschlüsselliste; ein Protokoll zur Erprobung beginnt mit `staging-` |
| `prev_hash` | hex64 | `Hex(SHA-256(UTF-8(statement_jcs)))` des Eintrags für den Vortag; 64 Nullzeichen genau dann, wenn `day = first_day` |
| `root` | hex64 | `Hex(root(day))` (Abschnitt 7.4.4); bei `tree_size = 0` der SHA-256-Wert der leeren Bytefolge (Abschnitt 5) |
| `server_ts` | rfc3339, genau in der Form `JJJJ-MM-TTThh:mm:ss.sssZ` | Zeitpunkt, den der Signierdienst des Herstellers festlegt, bevor er den Eintrag bildet (Heartbeat-Spezifikation §9.9); MUSS mindestens `end(day)` sein (Abschnitt 2). Die Füller hängen nicht daran (Abschnitt 7.4.4) |
| `tree_size` | int, 0 … 2^53−1 | Zahl der Blätter des Tagesbaums |

Die kanonische Memberreihenfolge ist `day, first_day, kind, log_id, prev_hash, root, server_ts, tree_size`. `statement_jcs` besteht aus druckbarem ASCII (Abschnitt 2), ist I-JSON ohne doppelte Membernamen, genau die JCS-Form seines eigenen Inhalts und höchstens 2048 Zeichen lang; ein Eintrag umfasst etwa 319 Zeichen. `server_key_id` hat den Typ key-id. `server_signature` (hex128) ist die Ed25519-Signatur (RFC 8032, ohne Prehash und ohne Kontext) eines Protokollschlüssels über `UTF-8(statement_jcs)`; sie wird geprüft wie die Signatur einer Quittung (Abschnitt 7.1). Ab Fassung 1.10 KANN ein Tageseintrag zusätzlich eine Signatur nach ML-DSA-87 über dieselben Bytes tragen, als Siegel im Auszug `ledger-protokollauszug/2` (Abschnitte 7.4.5a, 7.4.8a); `statement_jcs` und die Art `ledger.vendor_log_day.v1` ändern sich dadurch nicht.

Beispiel eines `statement_jcs` (eine Zeile; Tagesbaum eines Testprotokolls aus einer Kette und vier Füllern nach Abschnitt 7.4.4; Tageshash `ef330d2049e93b1da0e934a7a0e01e6b1dc26d392ffdac080ff0ec00889e2c1c`):

```
{"day":"2026-01-01","first_day":"2025-12-31","kind":"ledger.vendor_log_day.v1","log_id":"ledger-testprotokoll-1","prev_hash":"33fd1b2966e2f17af53d478066c97f1da0a181ed1107aaa34341eb4bc3067055","root":"0adcf8f084c1c9c0e8998f01a0a9a9b57e96b5e9135e2833cbb10c6a9e121871","server_ts":"2026-01-02T00:05:00.000Z","tree_size":5}
```

- **Tageshash:** `day_hash = SHA-256(UTF-8(statement_jcs))`. Ihn vergleichen Prüfer am Kopf des Protokolls; er ist die Eingabe des nächsten `prev_hash` und, für sha256, der Abdruck der Zeitstempel.
- **Die Identität ist der Inhalt.** Derselbe `statement_jcs` unter zwei Protokollschlüsseln ist ein Eintrag; ihn nach einem Schlüsselwechsel neu zu signieren, ist kein Widerspruch; die neue Signatur steht als weitere Signatur im Tagesobjekt (Abschnitt 7.4.8). Zwei verschiedene `statement_jcs` für denselben Tag eines Protokolls sind ein Widerspruch (`VENDOR_LOG_CONTRADICTION`).
- **Was `prev_hash` deckt:** den Inhalt, nicht Signatur oder Zeitstempel. Ein Zeitstempel entsteht erst nach dem Eintrag, und ein späterer oder zusätzlicher Zeitstempel ändert die Verkettung nicht.
- **Lückenlos:** genau ein Eintrag je Tag ab `first_day`, auch für einen Tag ohne Blätter. `first_day` steht in der Liste, die die Herstellerwurzel signiert; einen späteren Beginn kann der Hersteller danach nicht behaupten.
- **Kein laufender Baum:** Einen Baum über die Tageseinträge führt diese Fassung nicht; die Tage sind allein über `prev_hash` verkettet.
- Der Eintrag trägt keine Kundendaten, keine `appliance_id`, kein Commitment, keine `chain_id` und keine Zahl von Quittungen.

#### 7.4.5a Zweite Signatur nach ML-DSA-87

Ab Fassung 1.10. Ein Tageseintrag KANN neben der Ed25519-Signatur eines Protokollschlüssels (Abschnitt 7.4.5) eine Signatur nach ML-DSA-87 (FIPS 204) über dieselben Bytes tragen. Ab dem Tag `hybrid_ab` der Protokollschlüsselliste `ledger-protokollschluessel/2` (Abschnitt 7.4.7a) verlangt der Verifier beide (Abschnitt 7.4.10, Schritt L2 (g′)).

| Signatur | signierte Bytes | Schlüssel | Ort |
|---|---|---|---|
| Ed25519 (unverändert) | `UTF-8(statement_jcs)` | Protokollschlüssel mit `alg` = `ed25519` | `entry.server_signature` und Elemente von `additional_signatures` mit `alg` = `ed25519` (Abschnitt 7.4.8) |
| ML-DSA-87 | `UTF-8(statement_jcs)`, dieselben Bytes | Protokollschlüssel mit `alg` = `ml-dsa-87` | Siegel `{"type": "ml-dsa-87", "key_id": …, "value": …}` unter `seals` eines Tagesobjekts im Auszug `ledger-protokollauszug/2` (Abschnitt 7.4.8a) |

- **Rolle.** Ein Schlüssel nach ML-DSA-87 hat die Rolle `protocol` wie jeder Protokollschlüssel (Abschnitt 10.7.3). Er signiert nur Tageseinträge, die der Signierdienst selbst gebildet hat (Heartbeat-Spezifikation §9.9), und wird nur durch eine Liste `ledger-protokollschluessel/2` belegt, nie durch eine Anheftung (Abschnitt 7.4.10, Schritt L1).
- **Prüfregel.** Geprüft wird nach FIPS 204, Algorithmus 3 (ML-DSA.Verify), mit dem Parametersatz ML-DSA-87 und leerem Kontext, also über `M′ = 0x00 || 0x00 || M` mit Algorithmus 8 (ML-DSA.Verify_internal); `M` sind die signierten Bytes, hier `UTF-8(statement_jcs)`. Die Variante mit Vorab-Hash (HashML-DSA) und ein von außen übergebenes μ kommen nicht vor.
- **Trägt nicht.** Ein Publikey mit einer anderen Länge als 2592 Bytes oder eine Signatur mit einer anderen Länge als 4627 Bytes ergibt „trägt nicht“ (FIPS 204, Abschnitt 3.6.2), ebenso ein Hinweisvektor, den HintBitUnpack (FIPS 204, Algorithmus 21) abweist (unter anderem: Zähler fallend oder größer als ω = 75, Indizes nicht streng steigend, Füllbytes ungleich null). Weitere Regeln über FIPS 204 hinaus gibt es nicht.
- **Einheitstests.** Beide Referenz-Verifier MÜSSEN die 241 Fälle der Wycheproof-Vektoren `mldsa_87_verify_test.json` (C2SP) in ihren Einheitstests bestehen, mit gleichem Ergebnis je Fall. Diese Vektoren sind keine Solldateien des Testkorpus.
- **Signieren.** Im Betrieb signiert der Hersteller mit zufälligem `rnd` (Variante „hedged“ nach FIPS 204, Abschnitt 3.4); im Testkorpus wird deterministisch signiert, mit `rnd` gleich 32 Nullbytes. Der Verifier sieht keinen Unterschied.
- **Testschlüssel.** Ein Testschlüssel nach ML-DSA-87 des Testkorpus entsteht mit ML-DSA.KeyGen_internal (FIPS 204, Algorithmus 6) aus dem Startwert `ξ = SHA-256("REKORDER-TESTVECTOR-KEY:" || Name)` über die ASCII-Bytes, wie die Ed25519-Testschlüssel (Abschnitt 10.7.2). Seine Publikeys stehen in `published_test_keys` (Abschnitt 7.5.7).

#### 7.4.6 Zeitstempel der Tageseinträge

- Ein Tagesobjekt trägt 0 bis 4 Zeitstempel (Abschnitt 7.4.8), je ein TimeStampToken nach RFC 3161 als Base64 (höchstens 21 848 Zeichen, DER höchstens 16 384 Bytes). Sein `messageImprint` ist `H(UTF-8(statement_jcs))` mit dem im Token genannten Algorithmus `sha256`, `sha384` oder `sha512`. Der Hersteller MUSS jeden Tag bei mindestens zwei Zeitstempelstellen verschiedener Betreiber stempeln lassen, von denen keine er selbst oder eine mit ihm verbundene Stelle betreibt; jede Anforderung SOLL `certReq = true` und eine Nonce tragen (Heartbeat-Spezifikation §9.9). Der Verifier prüft das nicht: Wer eine Stelle betreibt, sieht er nicht.
- Jeder Zeitstempel ist nach Abschnitt 7.5.7 (Spalte Tageszeitstempel) **mangelhaft**, **nicht bestätigt** oder **bestätigt**; ein Verstoß gegen B64 oder gegen die Grenze von 16 384 Bytes für das DER macht ihn mangelhaft. Eine Zeichenkette mit mehr als 21 848 Zeichen verletzt schon die Grammatik des Auszugs und ist ein unbrauchbarer Aufruf (Abschnitt 7.4.8). Bestätigt ist er nur gegen eine Wurzel des Zwecks `log`. Ein Verifier, der Schritt 5 des Profils nicht ausführen kann, bestätigt keinen Tageszeitstempel.
- Für einen bestätigten Zeitstempel eines Eintrags zum Tag d, mit `genTime` auf ganze Millisekunden abgeschnitten (Abschnitt 2), gilt: **bezeugend**, wenn `end(d) + 60 000 ≤ genTime < end(d) + W`; **verfrüht**, wenn `genTime < end(d) + 60 000`; **verspätet**, wenn `genTime ≥ end(d) + W`.
- **Zeitfenster:** W = 172 800 000 ms (48 Stunden).
- **Fälligkeit:** Ein Tag d ist fällig, wenn `now ≥ end(d) + 21 600 000` gilt, also ab 06:00Z des Folgetags; `now` ist der Prüfzeitpunkt (Abschnitt 10.8). Bis dahin veröffentlicht der Hersteller den Eintrag an beiden Orten (Heartbeat-Spezifikation §9.9).
- **Stelle, deren Token sich als qualifiziert ausweist (ab Fassung 1.10).** Eine der Stellen KANN eine solche sein (Regel QS, Abschnitt 7.5.6; Heartbeat-Spezifikation §9.9). Ihr Zeitstempel wird beurteilt wie jeder andere und kann den Tag bezeugen. Ob er zu einer Wurzel kettet, die der Prüfer für das Protokoll übergibt und als qualifiziert benennt, liest nur Bedingung (7) der Beweisstufe (Abschnitt 10.9.1), der zweite Weg zu Stufe 3.

**Warum der Zeitstempel den Inhalt deckt und nicht die Signatur.** Der Zeitstempel belegt, dass der Inhalt zu `genTime` existierte; die Signatur bindet den Inhalt an den Schlüssel. Weil jeder Eintrag `prev_hash` trägt, belegt ein rechtzeitiger Zeitstempel eines späteren Tages mittelbar auch frühere Inhalte. Der Verifier nutzt diese mittelbare Schranke nicht: Ein Tag zählt nur durch einen eigenen bezeugenden Zeitstempel, auch für Bedingung (7) (Abschnitt 10.9.4).

#### 7.4.7 Protokollschlüsselliste `ledger-protokollschluessel/1`

Die Protokollschlüssel bestätigt eine eigene Liste, die die Herstellerwurzel signiert; weder die Liste der Gegenzeichnungsschlüssel (Abschnitt 10.7.1) noch die Rollenliste (Abschnitt 10.7.2) nennt sie. Das Format der Liste ist ihre Rolle: Jeder ihrer Schlüssel hat die Rolle `protocol` (Abschnitt 10.7.3) und steht in keiner anderen Liste. Die Liste ist ein JSON-Objekt nach den Regeln für Dateien des Prüfers (Abschnitt 2) mit genau diesen Membern:

| Member | Typ | Regel |
|---|---|---|
| `format` | const `"ledger-protokollschluessel/1"` | Formatkennung; eine andere macht die Liste unwirksam |
| `version` | int, 1 … 2^53−1 | vom Hersteller streng steigend vergeben; eine neue Version führt jeden je gelisteten Schlüssel weiter, mit seinem Ende der Gültigkeit |
| `ausgestellt` | rfc3339 | Ausstellungszeit, gelesen nach der Grammatik aus Abschnitt 10.7 |
| `log_id` | key-id | Kennung des Protokolls |
| `erster_tag` | date (Protokollbereich) | Beginn des Protokolls; in jeder Version gleich |
| `fuellerbindung` | hex64 oder `null` | Füllerbindung `Hex(SHA-256(UTF-8(JCS({"filler_secret": Hex(G), "kind": "ledger.vendor_log_filler_commitment.v1", "log_id": log_id}))))` des Füllergeheimnisses G dieses Protokolls (Abschnitt 7.4.4), wenn der Hersteller seine Füller ableitet, sonst `null`; einmal gesetzt, in jeder späteren Version gleich |
| `orte` | array, 2 … 4 Zeichenketten `^https://[!-~]{1,248}$` | Veröffentlichungsorte, je die Basisadresse der Dateiform (Heartbeat-Spezifikation §9.9); mindestens einer liegt außerhalb des Betriebs des Herstellers, außer bei einem Protokoll zur Erprobung (unten, „Orte“) |
| `schluessel` | array, 1 … 64 Objekte | je Schlüssel genau wie in Abschnitt 10.7: `key_id`, `pubkey` (hex64), `gueltig_ab`, optional `gueltig_bis` und `widerrufen_ab`; alle Werte Zeichenketten; eine `key_id` und ein `pubkey` dürfen je nur einmal vorkommen |
| `signatur` | object | genau `wurzel_id` (key-id) und `sig` (hex128) |

- **Orte:** Die Veröffentlichungsorte stehen in der signierten Liste, damit ein Prüfer nicht auf einen Spiegel verwiesen werden kann, den allein der Hersteller betreibt. Jeder Ort ist die Basisadresse derselben Dateiform (Heartbeat-Spezifikation §9.9, „Veröffentlichung“): Ein Prüfer bildet eine Adresse, indem er an den Ort `/` und den Pfad einer Datei hängt, etwa `<ort>/days/2026/2026-01-01.json`; ein Ort DARF deshalb nicht mit `/` enden und weder `?` noch `#` enthalten, das prüft das Signierverfahren der Liste (Heartbeat-Spezifikation §9.11 Punkt 10), der Verifier nicht. Endet ein Ort dennoch mit `/`, lässt der Prüfer dieses Zeichen vor dem Anhängen weg. Die Routen des Metadatenservers unter `/v1/` sind kein Ort. Diese Spezifikation nennt keinen Ort; was ein Leser von einem Ort außerhalb des Betriebs des Herstellers erwarten kann und wie er es prüft, nennt Heartbeat-Spezifikation §9.9. Für ein Protokoll zur Erprobung (`log_id` beginnt mit `staging-`) DÜRFEN beide Orte im Betrieb des Herstellers liegen; seine Liste signiert nie die Herstellerwurzel des Betriebs (Heartbeat-Spezifikation §9.9).
- Für `key_id`, `pubkey` und die Zeitangaben gelten die Regeln aus Abschnitt 10.7.1 (Grammatik, Gültigkeit zu einem Zeitpunkt, Vergleich als Zeitpunkte).
- **Eindeutigkeit über alle Listen:** `key_id` und `pubkey` eines Protokollschlüssels kommen in keiner Version der Liste der Gegenzeichnungsschlüssel und der Rollenliste vor (Heartbeat-Spezifikation §9.9, §9.11). Die Rollenprüfung vergleicht die wirksame Liste mit den Gegenzeichnungsschlüsseln und mit der wirksamen Rollenliste (Abschnitt 10.7.4, Schritt R3; Abschnitt 7.4.10, Schritt L1).
- **Signatur:** Signiert wird die JCS-Form des Listenobjekts **ohne** das Member `signatur`, mit der kanonischen Memberreihenfolge `ausgestellt, erster_tag, format, fuellerbindung, log_id, orte, schluessel, version`, mit Ed25519 durch die Herstellerwurzel, die `signatur.wurzel_id` nennt. Diese Wurzel kommt vom Prüfer oder ist eingebaut und genannt (Abschnitt 7.1), nie aus einem Paket oder einem Auszug.
- Die Zahlregel aus Abschnitt 2 gilt; andere Member gibt es auf keiner Ebene.
- **Wirksam** ist die Liste nur, wenn jede Regel gilt und die Signatur gegen eine Wurzel mit dieser `wurzel_id` trägt; welche Liste unter mehreren gilt, bestimmt Schritt L1 (Abschnitt 7.4.10). Die Regeln, die mehrere Versionen verbinden (eine neue Version führt jeden Schlüssel weiter; `log_id`, `erster_tag` und, einmal gesetzt, `fuellerbindung` bleiben gleich), sind Pflichten des Herstellers; einen Verstoß zwischen zählenden Listen beurteilt allein Schritt L1: Dann ist keine Liste wirksam, nie nur eine von ihnen unwirksam. Eine unwirksame Liste belegt keinen Schlüssel und ist selbst kein Befund; der Bericht nennt den Grund.
- **Füllerbindung:** Mit `fuellerbindung` legt sich der Hersteller vor dem ersten Tag, dessen Füller er ableitet, auf das Füllergeheimnis fest (Abschnitt 7.4.4); leitet er keine Füller ab, ist sie `null`. Der Verifier liest sie nur für die Regel, dass sie, einmal gesetzt, in jeder späteren Version gleich ist (Abschnitt 7.4.10, Schritt L1); prüfen kann sie, wer das Füllergeheimnis erhält (Abschnitt 7.4.13).
- **Reserveschlüssel:** Die Liste SOLL einen zweiten Protokollschlüssel nennen, dessen privater Teil offline liegt. Nach einer Kompromittierung wechselt der Hersteller auf ihn und veröffentlicht eine neue Version mit `widerrufen_ab` für den alten Schlüssel, ohne dass ein bisher ungelisteter Schlüssel erscheint.
- **Veröffentlichung:** in jedem Auszug (`protocol_keys`), unter `GET /v1/log/keys` und als `keys.json` an beiden Veröffentlichungsorten (Heartbeat-Spezifikation §9.9), nie in einem Prüfpaket und nie als `keys/vendor/schluesselliste.json`. Ein Leser der Liste der Gegenzeichnungsschlüssel nimmt sie nie an: `format` und die Member `log_id`, `erster_tag`, `fuellerbindung` und `orte` machen sie dort unwirksam. Darum bestätigt sie nie einen Gegenzeichnungsschlüssel.

Beispiel der signierten Bytes (eine Zeile; SHA-256 `21817705e707ffd17c2b4216ec3c654917f3d1b27e413e1fb3b740c9378c60da`):

```
{"ausgestellt":"2025-12-30T10:00:00.000Z","erster_tag":"2025-12-31","format":"ledger-protokollschluessel/1","fuellerbindung":"82ba087e5b1b7bee5dbfb6b34620efb2e23e1426ad25fe60a672035fb3a99efe","log_id":"ledger-testprotokoll-1","orte":["https://download.example/ledger-testprotokoll-1","https://mirror.example/ledger-testprotokoll-1"],"schluessel":[{"gueltig_ab":"2025-12-30T00:00:00.000Z","key_id":"vendor-log-test-001","pubkey":"1111111111111111111111111111111111111111111111111111111111111111"}],"version":1}
```

#### 7.4.7a Protokollschlüsselliste `ledger-protokollschluessel/2`

Ab Fassung 1.10. Die Liste `/2` ist dieselbe Protokollschlüsselliste in einem zweiten Format, keine vierte Liste (Abschnitt 10.7): Sie bestätigt Protokollschlüssel mehrerer Verfahren, jeden mit seinem Verfahren `alg`, und legt fest, ab welchem Tag der Verifier zu jedem Tageseintrag eine Signatur nach ML-DSA-87 verlangt (Abschnitt 7.4.5a). Sie ist ein JSON-Objekt nach den Regeln für Dateien des Prüfers (Abschnitt 2), höchstens 1 048 576 Bytes, mit genau diesen Membern; für eine Liste in `protocol_keys` eines Auszugs `/2` gilt die Grenze für `UTF-8(JCS(Liste))`, und darüber ist die Liste unwirksam (Grund „Format verletzt“):

| Member | Typ | Regel |
|---|---|---|
| `format` | const `"ledger-protokollschluessel/2"` | Formatkennung |
| `version` | int, 1 … 2^53−1 | wie in Abschnitt 7.4.7; Listen `/1` und `/2` eines Protokolls zählen ihre Versionen gemeinsam (Projektion, unten) |
| `ausgestellt` | rfc3339 | wie in Abschnitt 7.4.7 |
| `log_id` | key-id | wie in Abschnitt 7.4.7 |
| `log_uri` | string, 1 … 512 Zeichen aus `[!-~]` | absolute URI nach RFC 3986 (Schema nach RFC 3986 Abschnitt 3.1, dann `:`, dann der Rest), ohne Fragment, also ohne `#`, genau nach dem Muster `^[A-Za-z][A-Za-z0-9+.-]*:[!-"$-~]*$` (der Rest darf leer sein); einmal gesetzt, in jeder späteren Version `/2` gleich; steht nicht in der Projektion `/1` |
| `erster_tag` | date (Protokollbereich) | wie in Abschnitt 7.4.7 |
| `fuellerbindung` | hex64 oder `null` | wie in Abschnitt 7.4.7; einmal gesetzt, in jeder späteren Version beider Formate gleich |
| `hybrid_ab` | date (Protokollbereich) oder `null` | ab diesem Tag verlangt der Verifier zu jedem Tageseintrag zusätzlich eine geltende Signatur nach ML-DSA-87 (Abschnitt 7.4.10, Schritt L2 (g′)); mindestens `erster_tag`; nicht `null` nur, wenn die Liste mindestens einen Schlüssel mit `alg` = `ml-dsa-87` nennt; einmal gesetzt, in jeder späteren Version `/2` gleich; erstmals gesetzt, liegt der Tag nach dem Tag von `ausgestellt` dieser Version (Heartbeat-Spezifikation §9.11 Punkt 10) |
| `orte` | array, 2 … 4 Zeichenketten `^https://[!-~]{1,248}$` | wie in Abschnitt 7.4.7 |
| `schluessel` | array, 1 … 64 Objekte | je Schlüssel genau `alg` (Zeichenkette `^[a-z0-9][a-z0-9-]{0,31}$`), `key_id`, `pubkey` (Zeichenkette aus 1 bis 8192 Zeichen aus `[!-~]`), `gueltig_ab`, optional `gueltig_bis` und `widerrufen_ab`; alle Werte Zeichenketten |
| `signatur` | object | genau `wurzel_id` (key-id) und `sig` (hex128) |

- **Grenze zu Exit 3.** Wie bei der Liste `/1`: Für eine Liste, die der Prüfer mit `--vendor-key-list` übergibt, ist nur ein Verstoß gegen I-JSON und die Zahlregel (Abschnitt 2), eine Größe über 1 048 576 Bytes oder ein unbekanntes oder fehlendes `format` ein unbrauchbarer Aufruf (Exit 3, Abschnitt 10.8). Jeder andere Verstoß gegen diesen Abschnitt, auch ein fehlendes oder zusätzliches Member, ein Wert außerhalb seines Typs in der Tabelle, eine `log_uri` außerhalb ihres Musters oder ein `pubkey` mit falscher Länge, macht die Liste unwirksam (Grund „Format verletzt“) und ist nie Exit 3; ebenso für eine Liste in `protocol_keys` eines Auszugs `/2`. Die Regeln, die mehrere Versionen verbinden (eine neue Version führt jeden Schlüssel weiter; `log_id`, `erster_tag`, `log_uri`, `fuellerbindung` und `hybrid_ab` bleiben, einmal gesetzt, gleich), sind Pflichten des Herstellers (Heartbeat-Spezifikation §9.11 Punkt 10); einen Verstoß zwischen zählenden Listen beurteilt allein Schritt L1 (Abschnitt 7.4.10): Dann ist keine Liste wirksam, nie nur eine von ihnen unwirksam.
- **`alg` und `pubkey`.** Bekannt sind `ed25519` (dann ist `pubkey` vom Typ hex64) und `ml-dsa-87` (dann ist `pubkey` vom Typ `mldsa87-pub`: genau 3456 Zeichen nach B64, die genau 2592 Bytes ergeben). Ein `pubkey`, der nicht zu seinem bekannten `alg` passt, ist ein Mangel des Inhalts. Ein Eintrag mit einem anderen `alg` belegt keinen Schlüssel, zählt aber für die Eindeutigkeit, und der Bericht gibt dazu `unknown_alg` an (Abschnitt 10.10.2). So nimmt das Format `/2` ein weiteres Verfahren auf, ohne ein neues Format. Die Liste nennt mindestens einen Schlüssel mit `alg` = `ed25519`.
- Für `key_id`, die Zeitangaben und die Gültigkeit gelten die Regeln aus Abschnitt 10.7.1, für jeden Schlüssel gleich welches `alg`. `key_id` und `pubkey` (verglichen als Zeichenketten) kommen in der Liste je höchstens einmal vor; die Eindeutigkeit über alle Listen (Abschnitt 7.4.7) gilt für jeden Schlüssel.
- **`log_uri`.** COSE-Objekte dieses Protokolls tragen diesen Wert als `iss` in den CWT-Claims (Label 15), weil RFC 9943 für `iss` eine URI verlangt; ihre Prüfung legt Abschnitt 7.7 fest. Der Verifier prüft an `log_uri` nur die Grammatik oben und die Regel, dass der Wert, einmal gesetzt, gleich bleibt (Abschnitt 7.4.10, Schritt L1); dass er im Übrigen RFC 3986 folgt, prüft das Signierverfahren der Liste (Heartbeat-Spezifikation §9.11 Punkt 10).
- **Signatur:** Signiert wird die JCS-Form des Listenobjekts **ohne** das Member `signatur`, mit der kanonischen Memberreihenfolge `ausgestellt, erster_tag, format, fuellerbindung, hybrid_ab, log_id, log_uri, orte, schluessel, version` und in jedem Objekt von `schluessel` der Reihenfolge `alg, gueltig_ab, gueltig_bis, key_id, pubkey, widerrufen_ab` (fehlende optionale Member entfallen), mit Ed25519 durch die Herstellerwurzel, die `signatur.wurzel_id` nennt; `hybrid_ab` und `fuellerbindung` stehen auch mit dem Wert `null` in den signierten Bytes. Für die Wurzel gilt Abschnitt 7.4.7.
- Die Zahlregel aus Abschnitt 2 gilt; andere Member gibt es auf keiner Ebene. **Wirksam** ist die Liste nur, wenn jede Regel dieses Abschnitts für die einzelne Liste gilt und die Signatur gegen eine Wurzel mit dieser `wurzel_id` trägt; welche Liste unter mehreren gilt, bestimmt Schritt L1 (Abschnitt 7.4.10). Eine unwirksame Liste belegt keinen Schlüssel und ist selbst kein Befund; der Bericht nennt den Grund.
- **Projektion.** Die Projektion einer Liste `/2` ist das Objekt mit `format` = `"ledger-protokollschluessel/1"`, denselben Werten von `ausgestellt`, `erster_tag`, `fuellerbindung`, `log_id`, `orte` und `version`, ohne `hybrid_ab` und ohne `log_uri`, und als `schluessel` genau den Einträgen mit `alg` = `ed25519` in derselben Reihenfolge, je ohne das Member `alg` und sonst Zeichen für Zeichen gleich. Eine Liste `/1` ist die Projektion einer Liste `/2`, wenn ihre JCS-Form ohne `signatur` byte-gleich mit der JCS-Form der Projektion ist; `signatur` wird nicht verglichen. Zu jeder Version einer Liste `/2` signiert der Hersteller im selben Signierverfahren die Liste `/1` derselben `version`, die ihre Projektion ist, und veröffentlicht beide zusammen (Heartbeat-Spezifikation §9.9, §9.11 Punkt 10). Eine Liste `/1` ohne Gegenstück `/2` ist zulässig, etwa eine Version vor der ersten Liste `/2`.
- **`hybrid_ab`.** Der Tag bezieht sich auf `day` des Tageseintrags, nicht auf dessen `server_ts` und nicht auf `gueltig_ab`, das gegen Tageseinträge nicht geprüft wird (Abschnitt 7.4.10, Schritt L2 (e)). Einmal gesetzt, kann der Hersteller die Pflicht nicht zurücknehmen: Fehlt einem Tag ab `hybrid_ab` eine geltende Signatur nach ML-DSA-87, ist der Tag für jeden Verifier, der Schritt L2 (g′) umsetzt, nicht festgestellt.
- **Veröffentlichung:** als `keys-2.json` an beiden Veröffentlichungsorten, unter `GET /v1/log/keys?format=2` und, ab der ersten Liste `/2`, in `protocol_keys` jedes Auszugs `ledger-protokollauszug/2`; davor trägt ein Auszug `/2` die Liste `/1` (Heartbeat-Spezifikation §9.9); in einem Auszug `/1` und als `keys.json` steht die Projektion `/1`. Eine Liste mit 64 Schlüsseln nach ML-DSA-87 umfasst etwa 230 KB.

#### 7.4.8 Protokollauszug `ledger-protokollauszug/1`

Der Prüfer übergibt das Protokoll als einen oder mehrere Auszüge (Abschnitt 10.8). Ein Auszug ist eine Datei des Prüfers (Abschnitt 2) mit dieser Struktur; `x?` heißt `x` oder `null`:

```
{"format":        "ledger-protokollauszug/1",
 "log_id":        key-id,
 "chain_id":      uuid?,
 "protocol_keys": object?,       Protokollschlüsselliste /1, beurteilt nach 7.4.7
 "days":          [0 … 4000 Tagesobjekte:
                   {"entry":      {"statement_jcs": string (maxlen 2048),
                                   "server_key_id": key-id,
                                   "server_signature": hex128},
                    "timestamps": [0 … 4 × string (maxlen 21848)],
                    "additional_signatures": [0 … 3 × {"alg": string (^[a-z0-9][a-z0-9-]{0,31}$),
                                                       "key_id": key-id,
                                                       "signature": string (1 … 1024 × [!-~])}]}],
 "chain_days":    [0 … 4000 Kettentag-Nachweise:
                   {"day":     date (Protokollbereich),
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

**Grammatik.** Ein Verstoß ist ein unbrauchbarer Aufruf (Exit 3, Abschnitt 10.8):

- Auf jeder Ebene stehen genau diese Member, außer im Inhalt von `protocol_keys`; `format` ist die Konstante.
- `chain_id` ist `null` nur mit leerem `chain_days`.
- Ein Element von `additional_signatures` mit `alg` = `ed25519` trägt in `signature` einen Wert vom Typ hex128. Zwei gleiche Elemente in einem Tagesobjekt verletzen die Grammatik.
- In jedem Kettentag-Nachweis ist genau eines von `present` und `absent` nicht `null`.
- Die `roots` eines Nachweises sind paarweise verschieden nach ihren Blatt-Bytes (Abschnitt 7.4.2). Eine Datei trägt höchstens einen Nachweis je `day`. `neighbours` sind aufsteigend nach `leaf_index` geordnet, nicht fallend: Gleiche Werte verletzen die Grammatik nicht.
- `server_ts` in `roots` ist ein Wert vom Typ rfc3339, byte-gleich aus der Quittung oder der Aufzeichnung übernommen. Ab Fassung 1.10 schreibt der Server ihn in der Form `JJJJ-MM-TTThh:mm:ss.sssZ` (Heartbeat-Spezifikation §9.1, §9.2); eine andere Form verletzt diese Grammatik nicht.
- Alle Auszüge eines Aufrufs, auch solche im Format `ledger-protokollauszug/2` (Abschnitt 7.4.8a), nennen dieselbe `log_id`.
- Ab Fassung 1.10: Nennt `protocol_keys` eines Auszugs `/1` ein anderes `format` als `ledger-protokollschluessel/1`, auch `ledger-protokollschluessel/2`, ist diese Liste unwirksam (Grund „Format verletzt“, Abschnitt 7.4.7); sie ist in Schritt L1 kein Kandidat. Das verletzt die Grammatik des Auszugs nicht.
- Grenzen: je Datei höchstens 33 554 432 Bytes; je Aufruf höchstens 128 Dateien und 268 435 456 Bytes, Auszüge `/2` eingerechnet (Abschnitt 7.4.8a).

**Was der Auszug ist.** Ein unsignierter Behälter aus Teilen, die sich selbst belegen: Tageseinträge durch Protokollschlüssel und Zeitstempel, Kettentag-Nachweise durch Inklusion unter einem bezeugten Tagesbaum. Er ist keine Aussage des Herstellers. Jede Zeile `countersigned` oder `gap_witness` der Anker-Historie, deren `server_ts` auf einen Tag ab `first_day` fällt, steht byte-gleich unter den `roots` des Nachweises für diesen Tag, denn beide stammen aus den Aufzeichnungen des Herstellers (Heartbeat-Spezifikation §9.1, §9.2). Eine frisch ausgestellte Wiederholung einer Gegensignatur steht dort zusätzlich mit ihrem eigenen `server_ts`; die Anker-Historie nennt für diese Wurzel nur die früheste Gegensignatur. Zeilen früherer Tage haben im Protokoll keinen Nachweis. Abschnitt 8.8 gleicht beide ab und vergleicht in der Gegenrichtung ohne `server_ts` (Schritt H7). Der Spiegelauszug `<YYYY>.json` an den Veröffentlichungsorten ist ein Auszug mit `chain_id = null`; überschritte er die Grenze je Datei, teilt der Hersteller ihn (Heartbeat-Spezifikation §9.9, Teilung der Spiegelauszüge); eine höhere Grenze gibt es nicht. Eine Datei der Anker-Historie (Abschnitt 8.8.2) DARF Auszüge unverändert enthalten; der Verifier behandelt sie wie übergebene Auszüge.

**Weitere Signaturen (ab Fassung 1.10).** Ein Tagesobjekt KANN unter `additional_signatures` weitere Signaturen über `UTF-8(statement_jcs)` tragen. Mit `alg` = `ed25519` ist es die Signatur eines weiteren Protokollschlüssels, etwa nach einem Schlüsselwechsel (Abschnitt 7.4.5); Schritt L2 behandelt sie wie das Paar aus `entry` (Abschnitt 7.4.10). Mit einem anderen `alg` ist es ein Siegel nach einem Verfahren, das diese Fassung nicht festlegt, etwa für einen späteren Dienst, der ein Verfahren außerhalb von Ed25519 verlangt. Ein solches Siegel prüft ein Verifier dieser Fassung nicht: Es zählt für keinen Schritt, ergibt nie einen Befund, und der Bericht nennt die Zahl solcher Siegel (`vendor_log.days.signatures_not_checked`, Abschnitt 10.10). So kann eine spätere Fassung Verfahren hinzufügen, deren Siegel in 1024 druckbare Zeichen passt (etwa ECDSA oder RSA bis 4096 Bit in Hex), ohne dass ein Auszug für einen Verifier dieser Fassung unbrauchbar wird. Ein längeres Siegel, etwa nach ML-DSA oder mit Zertifikat, verletzt diese Grammatik; es steht im Auszug `ledger-protokollauszug/2` unter `seals` (Abschnitt 7.4.8a).

#### 7.4.8a Protokollauszug `ledger-protokollauszug/2`

Ab Fassung 1.10. Der Auszug `/2` trägt dieselben Teile wie der Auszug `/1` (Abschnitt 7.4.8) und dazu je Tagesobjekt Siegel und COSE Receipts des Tages und je Auszug COSE Receipts zu Gegensignaturen der Kette `chain_id`. Er ist eine Datei des Prüfers (Abschnitt 2) mit dieser Struktur; `x?` heißt `x` oder `null`:

```
{"format":        "ledger-protokollauszug/2",
 "log_id":        key-id,
 "chain_id":      uuid?,
 "protocol_keys": object?,       Protokollschlüsselliste /1 oder /2, beurteilt nach 7.4.7 bzw. 7.4.7a
 "days":          [0 … 4000 Tagesobjekte:
                   {"entry":                 wie in /1,
                    "timestamps":            wie in /1,
                    "additional_signatures": wie in /1,
                    "seals":        [0 … 4 × {"type":   string (^[a-z0-9][a-z0-9-]{0,31}$),
                                              "key_id": key-id?,
                                              "value":  string (1 … 87384)}],
                    "day_receipts": [0 … 2 × string (1 … 1368)]}],
 "chain_days":    wie in /1,
 "cose_receipts": [0 … 131072 × string (1 … 1368)]}
```

**Grammatik.** Ein Verstoß ist ein unbrauchbarer Aufruf (Exit 3, Abschnitt 10.8):

- Auf jeder Ebene stehen genau diese Member, außer im Inhalt von `protocol_keys`; `format` ist die Konstante. Jede Regel der Grammatik des Auszugs `/1` (Abschnitt 7.4.8) gilt auch hier, mit denselben Typen und Grenzen für `entry`, `timestamps`, `additional_signatures` und `chain_days`.
- Ein Siegel mit `type` = `ml-dsa-87` trägt eine `key_id` ungleich `null`; ein Siegel mit `type` = `cades-b-t` trägt `key_id` = `null`. Zwei Siegel eines Tagesobjekts, die in `type`, `key_id` und `value` gleichen, zwei gleiche Elemente in `day_receipts` eines Tagesobjekts und zwei gleiche Elemente in `cose_receipts` verletzen die Grammatik.
- `cose_receipts` ist nur mit `chain_id` ungleich `null` nicht leer.
- Alle Auszüge eines Aufrufs, im Format `/1` wie `/2`, nennen dieselbe `log_id`.
- Grenzen: je Datei `/2` höchstens 67 108 864 Bytes; je Aufruf weiter höchstens 128 Dateien und 268 435 456 Bytes, Auszüge beider Formate zusammengezählt.

**Binärwerte.** Neu hinzukommende Binärwerte stehen in Base64 nach B64 (Abschnitt 2): `value` eines Siegels, die Elemente von `day_receipts` und `cose_receipts` und `pubkey` eines Schlüssels mit `alg` = `ml-dsa-87` (Abschnitt 7.4.7a). Die Member aus `/1` behalten ihre Hex-Form, sodass ein Tagesobjekt `/1` durch Hinzufügen von `seals` und `day_receipts` verlustfrei zu einem Tagesobjekt `/2` wird. Die Grammatik prüft an diesen Werten nur Zeichenkette und Zahl der Zeichen; B64 und die Zahl der dekodierten Bytes prüft der Schritt, der sie liest (Abschnitt 2).

**Siegel.** Ein Siegel ist eine weitere Signatur über `UTF-8(statement_jcs)` des Tagesobjekts nach dem Verfahren, das `type` nennt:

| `type` | `key_id` | `value` | Prüfung in dieser Fassung |
|---|---|---|---|
| `ml-dsa-87` | `key_id` eines Protokollschlüssels mit `alg` = `ml-dsa-87` (Abschnitt 7.4.7a) | Signatur vom Typ `mldsa87-sig` (Abschnitt 7.4.5a) | Abschnitt 7.4.10, Schritt L2 (b′), (e′) und (g′) |
| `cades-b-t` | `null` | abgetrennte Signatur nach ETSI EN 319 122-1 (CAdES-B-T) über `UTF-8(statement_jcs)` mit Zertifikatskette, in B64 | keine: gezählt in `vendor_log.seals.not_checked` (Abschnitt 10.10.2), nie ein Befund |
| jeder andere Wert | nach der Grammatik | nach der Grammatik | keine: gezählt in `vendor_log.seals.not_checked`, nie ein Befund |

Ein Siegel, das diese Fassung nicht prüft, zählt für keinen Schritt, ergibt nie einen Befund und macht den Auszug nie unbrauchbar; so braucht ein weiteres Verfahren kein neues Format des Auszugs. Ein Siegel `cades-b-t` belegt in dieser Fassung nichts, auch nicht, dass der Inhaber eines Siegelzertifikats den Inhalt gesiegelt hat (kein Beleg durch LEDGER).

**COSE Receipts.** Die Elemente von `day_receipts` und `cose_receipts` sind COSE-Objekte in Ablageform (Abschnitt 7.7.2) als B64: in `day_receipts` höchstens zwei Objekte des Profils C2 zum Tag des Tagesobjekts (Abschnitt 7.7.4), etwa unter dem bisherigen und dem neuen Transparenzschlüssel, in `cose_receipts` Objekte des Profils C1 zu Gegensignaturen der Kette `chain_id` (Abschnitt 7.7.3). Dieser Abschnitt legt für sie nur Grammatik und Grenzen fest. Geprüft werden sie in Abschnitt 7.4.10, Schritt L3a (`day_receipts`), und in Abschnitt 7.7.6, Schritt K (`cose_receipts`): B64, die Zahl der Bytes und das Profil prüft erst dieser Schritt, und ein Verstoß dort macht das Objekt mangelhaft, nie den Aufruf unbrauchbar. Elemente von `cose_receipts` eines Auszugs zu einer anderen Kette zählt Schritt K als `foreign_chain`. **In Fassung 1.10** laufen Schritt L3a und Schritt K nicht (Abschnitt 7.7, „Fassung 1.10“): Ein Verifier 1.10 prüft die Elemente von `day_receipts` und `cose_receipts` nicht und zählt ihre Zahl über alle Auszüge im Berichtsmember `vendor_log.cose_not_checked` (Abschnitt 10.10.2); das ergibt nie einen Befund und nie Exit 3.

**Zusammenlegen und Spiegel.** Tagesobjekte aus Auszügen `/1` und `/2` legt Schritt L2 zusammen (Abschnitt 7.4.10). Der Spiegelauszug `<YYYY>-2.json` an den Veröffentlichungsorten ist ein Auszug `/2` mit `chain_id` = `null`, leerem `chain_days` und leerem `cose_receipts` (Heartbeat-Spezifikation §9.9). Überschritte er 67 108 864 Bytes, teilt ihn der Hersteller nach Halbjahren oder Quartalen (Heartbeat-Spezifikation §9.9, Teilung der Spiegelauszüge); eine höhere Grenze gibt es nicht.

#### 7.4.9 Tagesblätter `ledger-tagesblaetter/1`

`{"format": "ledger-tagesblaetter/1", "log_id": key-id, "day": date, "leaves": [[position, chain_root], …]}`: je Blatt des Tagesbaums ein Paar aus zwei hex64-Werten, in der Reihenfolge des Baums. Der Hersteller veröffentlicht die Tagesblätter jedes Tages an beiden Orten (Heartbeat-Spezifikation §9.9). Sie dienen der Beobachtung des Protokolls; der Verifier liest sie nicht. Jeder kann an ihnen prüfen:

- (a) Die Positionen steigen streng.
- (b) Die Zahl der Paare ist `tree_size` des Tageseintrags.
- (c) MTH (Abschnitt 5) über die Blätter `UTF-8(JCS({"chain_root": …, "kind": "ledger.vendor_log_day_leaf.v1", "position": …}))` in dieser Reihenfolge ist `root` des bezeugten Tageseintrags.
- (d) `tree_size` des Tageseintrags ist eine Zweierpotenz und mindestens 1024 (Größenregel, Abschnitt 7.4.4), für jedes Protokoll, dessen Protokollschlüsselliste nicht mit einer Wurzel aus `published_test_keys` signiert ist.

Ein Verstoß gegen (a) bis (d) unter einem bezeugten Eintrag ist ein Regelverstoß, den jeder dem Hersteller zurechnen kann. Über die Baumgröße hinaus verraten die Tagesblätter nichts: Positionen hängen an der `appliance_id` (Abschnitt 7.4.3), Kettentag-Wurzeln sind Hashwerte, und Füller sind ohne ihre Öffnung von Ketten nicht zu unterscheiden (Abschnitte 7.4.4, 7.4.13).

#### 7.4.10 Prüfung durch den Verifier

Bezeichnungen: N = Zahl der Einträge des Pakets; C = `manifest.chain_id`; A = `GENESIS.appliance_id`; `now` = Prüfzeitpunkt (Abschnitt 10.8); `root(t)` = die aus den Blättern neu berechnete Wurzel über die Einträge 1 … t (Abschnitt 5); `LH(x) = SHA-256(0x00 || x)`. Ein **Tagesobjekt** ist ein Element von `days` eines Auszugs. Beide Referenz-Verifier führen die Schritte gleich aus.

**L0 Aufruf** (vor dem Öffnen des Pakets). Der Verifier liest jeden Auszug, auch die in Dateien der Anker-Historie enthaltenen, jede Schlüsselliste des Prüfers, jede Anheftung eines Protokoll-, Bescheid- oder Transparenzschlüssels und jede Wurzel für Zeitstempel des Protokolls (Abschnitt 10.8). Ein unbrauchbarer Aufruf (Exit 3 ohne Bericht) ist: eine Verletzung der Grammatik oder einer Grenze (Abschnitte 7.4.8, 10.8); verschiedene `log_id` in den Auszügen; eine Anheftung, die nicht die Form `key_id=hex64` hat; zwei Anheftungen von Protokollschlüsseln mit derselben `key_id` und verschiedenen Publikeys; eine Anheftung einer Rolle, die in `key_id` oder Publikey einer Anheftung einer anderen Rolle gleicht (`--vendor-key`, `--vendor-log-key`, `--vendor-statement-key` und, ab Fassung 1.10, `--vendor-transparency-key`; ein Schlüssel in zwei Rollen); die übrigen Fälle aus Abschnitt 10.7.4; ein fehlerhafter PEM-Block. Ohne Auszug ist der Status `not_supplied`, und die Schritte L2 bis L9 entfallen. Schritt L1 läuft, sobald eine Protokollschlüsselliste (in einem Auszug oder als Schlüsselliste des Prüfers) oder eine Anheftung eines Protokollschlüssels übergeben ist, mit oder ohne Auszug; ohne Auszug bestimmt er nur die Protokollschlüssel für die Abschnitte 7.1, 8.8.3 und 10.7.4 und meldet keinen Befund. Ab Fassung 1.10 ist ein unbrauchbarer Aufruf außerdem: eine Verletzung der Grammatik oder einer Grenze des Auszugs `ledger-protokollauszug/2` (Abschnitt 7.4.8a), auch eine Datei `/2` mit mehr als 67 108 864 Bytes und verschiedene `log_id` in Auszügen `/1` und `/2` eines Aufrufs; eine Liste `ledger-protokollschluessel/2` aus `--vendor-key-list` mit mehr als 1 048 576 Bytes oder ohne I-JSON (Abschnitt 7.4.7a, Grenze zu Exit 3); zwei Anheftungen von Transparenzschlüsseln mit derselben `key_id` und verschiedenen Publikeys. Jeder andere Verstoß einer Liste `/2` gegen Abschnitt 7.4.7a ist nie Exit 3, ebenso wenig ein Mangel eines COSE-Objekts (Abschnitt 7.7).

**Stellung im Prüfablauf.** Schritt L1 läuft mit den übrigen Schlüsseln des Herstellers vor der Prüfung der Quittungen (Abschnitt 10.5, Schritt 4), die Schritte L2 bis L9 nach der Prüfung der Quittungen (Abschnitt 7.1) und vor der Anker-Historie (Abschnitt 8.8). Sie lesen nur die Angaben des Prüfers, je Quittung, ob ihre Signatur nach Abschnitt 7.1 trägt, die Menge K_cs, die Präfix-Wurzeln, A und `now`. Sie fügen nur die fünf Befundklassen aus Abschnitt 7.4.11 und das Berichtsobjekt `vendor_log` (Abschnitt 10.10) hinzu und ändern kein anderes Ergebnis: `NO_ANCHOR`, der letzte gegengezeichnete Checkpoint (Abschnitt 8.6), Restfenster, Vollständigkeit und erwartete Wurzeln bleiben, wie sie ohne Protokoll wären. Schritt L3a (ab Fassung 1.10) liest außerdem die Transparenzschlüssel T und `log_uri` U (Abschnitt 7.7.5). Die COSE-Gegensignaturen der Kette prüft danach Schritt K (Abschnitt 7.7.6, Abschnitt 10.5, Schritt 6a).

**K_cs** sind die Gegenzeichnungsschlüssel, die Anker des Prüfers belegen (Abschnitt 10.7.4): K_cs^L, also die Schlüssel der Liste der Gegenzeichnungsschlüssel des Pakets, wenn sie gegen eine Herstellerwurzel des Prüfers oder die eingebaute Wurzel wirksam ist, und ebenso die Schlüssel wirksamer Listen dieses Formats, die der Prüfer übergibt; dazu die angehefteten Gegenzeichnungsschlüssel (Abschnitt 7.1), die nach Abschnitt 10.7.4, Schritt R3 (d) nicht entfallen. `manifest.vendor_pubkeys` und `keys/vendor/*.hex` gehen nie in K_cs ein.

**L1 Protokollschlüssel.**

1. Angeheftete Protokollschlüssel haben für ihre `key_id` Vorrang; sie haben kein Ende der Gültigkeit.
2. Kandidaten sind die verschiedenen Protokollschlüssellisten (verschieden nach ihren JCS-Bytes) aus den Membern `protocol_keys` der Auszüge und aus den Schlüssellisten des Prüfers im Format `ledger-protokollschluessel/1` und, ab Fassung 1.10, `ledger-protokollschluessel/2`; Kandidaten `/2` kommen nur aus Auszügen `/2` und aus `--vendor-key-list`, eine Liste `/2` in einem Auszug `/1` ist unwirksam und kein Kandidat (Abschnitt 7.4.8). Ein Kandidat `/1` wird gelesen wie eine Liste `/2` mit `alg` = `ed25519` an jedem Schlüssel, `hybrid_ab` = `null` und ohne `log_uri`. Ein Kandidat zählt, wenn er Abschnitt 7.4.7 beziehungsweise 7.4.7a genügt und seine Signatur gegen eine Herstellerwurzel des Prüfers oder die eingebaute Wurzel mit dieser `wurzel_id` trägt; der Bericht nennt die Quelle der Wurzel. Zählen ein Kandidat `/1` und ein Kandidat `/2` derselben `version` und derselben `signatur.wurzel_id` und ist der Kandidat `/1` die Projektion des Kandidaten `/2` (Abschnitt 7.4.7a), sind beide ein Kandidat, der Kandidat `/2`; dieses Zusammenlegen geschieht zuerst, und die folgenden Regeln gelten danach zwischen den übrigen zählenden Kandidaten. Ein Kandidat `/1` mit einer anderen `wurzel_id` zählt wie jeder andere Kandidat. Wirksam ist der zählende Kandidat mit der größten `version`. Keine Liste ist wirksam, wenn zwei zählende Kandidaten dieselbe `version` und verschiedene Bytes haben, wenn zwei zählende Kandidaten verschiedene `log_id` oder `erster_tag` nennen, wenn zwei zählende Kandidaten verschiedene `fuellerbindung` ungleich `null` nennen, wenn ein zählender Kandidat `fuellerbindung` `null` nennt und einer kleinerer `version` einen Wert, wenn einem zählenden Kandidaten ein Schlüssel (dasselbe `alg`, dieselbe `key_id` mit demselben `pubkey`) eines zählenden Kandidaten kleinerer `version` fehlt, den er weiterführen muss (Abschnitt 7.4.7: eine neue Version führt jeden Schlüssel weiter; ein Kandidat `/2` führt jeden Schlüssel weiter, ein Kandidat `/1` jeden Schlüssel mit `alg` = `ed25519`), wenn zwei zählende Kandidaten `/2` verschiedene `hybrid_ab` ungleich `null` nennen, wenn ein zählender Kandidat `/2` `hybrid_ab` `null` nennt und einer `/2` kleinerer `version` einen Wert, wenn zwei zählende Kandidaten `/2` verschiedene `log_uri` nennen oder wenn, mit Auszug, ein zählender Kandidat eine andere `log_id` nennt als die Auszüge; der Grund ist dann „widersprüchliche Listen“, im letzten Fall „abweichende `log_id`“. Diese Regeln über mehrere Versionen machen nie nur einen Kandidaten unwirksam (Abschnitte 7.4.7, 7.4.7a).
3. **Rollenprüfung** (Abschnitt 10.7.4, Schritt R3): Teilt die wirksame Liste einen Publikey mit einer Anheftung eines Gegenzeichnungsschlüssels, mit K_cs^L oder mit der wirksamen Rollenliste, ist keine Liste wirksam. Eine Anheftung eines Protokollschlüssels, deren Publikey dem eines Schlüssels aus K_cs^L oder der wirksamen Rollenliste gleicht, entfällt. Verglichen wird der Publikey, nicht die `key_id`: Gleicht nur die `key_id`, steht kein Schlüssel in zwei Rollen, denn jeder Schlüssel wird nur in der Liste seiner Rolle nachgeschlagen; dass der Hersteller die `key_id` aller Rollen getrennt vergibt, verlangt Heartbeat-Spezifikation §9.9. Sonst könnte, wer ein Paket schreibt, eine ältere, echt signierte Liste der Gegenzeichnungsschlüssel mit einer zufällig gleichen `key_id` beilegen und das Protokoll abschalten. `manifest.vendor_pubkeys` und `keys/vendor/*.hex` zählen dafür nie; sonst könnte ein Fälscher das Protokoll abschalten, indem er den Protokollschlüssel dort einträgt. Ab Fassung 1.10 zählen für diese Rollenprüfung alle Einträge der Liste, die nach Nummer 2 wirksam ist, und des zählenden Kandidaten `/2` mit der größten `version` (der nach Nummer 6 P2 wird, wenn eine Liste wirksam bleibt), gleich welches `alg`; jeder `pubkey` wird als Zeichenkette, wie er geschrieben ist, mit dem hex64 des anderen Schlüssels verglichen. So hängt Nummer 3 nicht von Nummer 6 ab.
4. Bleibt kein Protokollschlüssel und ist ein Auszug übergeben, meldet der Verifier einmal `VENDOR_LOG_UNVERIFIED` ohne Tag mit dem Grund (keine Liste übergeben, keine passende Wurzel, Signatur scheitert, Format verletzt, widersprüchliche Listen, Schlüssel in zwei Rollen, abweichende `log_id`). Ist keine Liste wirksam und ist jede Anheftung eines Protokollschlüssels nach Nummer 3 entfallen (Abschnitt 10.7.4, Schritt R3 (d)), ist der Grund „Schlüssel in zwei Rollen“, nicht „keine Liste übergeben“. Der Status ist dann `no_protocol_key`, die Klassen der Quittungen bleiben unbestimmt (Abschnitt 10.10), und die Schritte L2 bis L9 entfallen.
5. F ist `erster_tag` der wirksamen Liste. Gibt es nur Anheftungen, bestimmt Schritt L2 (f) den Beginn F.
6. **Listen `/2` (ab Fassung 1.10).** P ist die wirksame Liste (Nummer 2); belegte Protokollschlüssel für die Schritte L2 (a), (b) und (e) sind die nicht entfallenen Anheftungen und die Schlüssel von P mit `alg` = `ed25519`. P2 ist der zählende Kandidat `/2` mit der größten `version`, wenn eine Liste wirksam ist. P_mldsa sind die Schlüssel aus P2 mit `alg` = `ml-dsa-87`, H ist `hybrid_ab` aus P2; ohne P2 ist P_mldsa leer und H = `null`. Ist P ein Kandidat `/1` mit größerer `version` als P2, gilt das ebenso, und der Bericht nennt beide Versionen (Abschnitt 10.10.2). Ohne wirksame Liste, also nur mit Anheftungen, ist P_mldsa leer und H = `null`: Ein Schlüssel nach ML-DSA-87 wird nie angeheftet. Eine Anheftung ist immer ein Schlüssel mit `alg` = `ed25519` und hat nur gegenüber solchen Schlüsseln Vorrang (Nummer 1). Nennt P2 einen Schlüssel mit einem anderen `alg` und derselben `key_id` wie eine Anheftung, entfällt die Anheftung (Bericht `key_roles.pins_dropped` mit `pinned_as` und `listed_as` `protocol`, Hinweis `pin_dropped`, Abschnitt 10.10.2), und für diese `key_id` gilt nur der Schlüssel aus P2. Ein Eintrag mit einem unbekannten `alg` (Abschnitt 7.4.7a) belegt nichts.

**L2 Tagesobjekte.** Die Tagesobjekte aller Auszüge werden zusammengelegt: Gleiche `statement_jcs` sind ein Objekt. Seine Zeitstempel werden als Menge verschiedener Zeichenketten vereinigt, seine Signaturen als Menge verschiedener Paare (`server_key_id`, `server_signature`), zu denen jedes Element von `additional_signatures` mit `alg` = `ed25519` als Paar (`key_id`, `signature`) gehört; kein Paar verdrängt ein anderes, gleich in welcher Reihenfolge die Dateien übergeben sind. Elemente mit einem anderen `alg` werden als Menge verschiedener Elemente gezählt und nicht geprüft (Abschnitt 7.4.8). Ab Fassung 1.10 werden außerdem die Siegel als Menge verschiedener Tripel (`type`, `key_id`, `value`) vereinigt und die Elemente von `day_receipts` als Menge verschiedener Zeichenketten; ein Objekt aus einem Auszug `/1` hat keine Siegel und keine `day_receipts` (Abschnitt 7.4.8a). `dayOf(o)` ist das Member `day`, wenn sich `statement_jcs` als I-JSON-Objekt (Abschnitt 2, doppelte Membernamen abgewiesen) mit einem Member `day` lesen lässt, das der Grammatik des Typs `date` genügt (ein existierender Kalendertag mit einem Jahr von `0001` bis `9999`, Abschnitt 2); sonst hat der Befund keinen Tag. Der Protokollbereich gehört nicht zu `dayOf`; er ist eine Regel des Inhalts, die (c) prüft. Ein signierter Eintrag mit `day` `1999-12-31` erhält daher seinen Befund `VENDOR_LOG_CONTRADICTION` an diesem Tag und zählt in `days.contradictory` (Abschnitt 10.10.2). Zuerst gelten die Schritte (a) bis (e), mit (b′) und (e′), für jedes Objekt o; danach bestimmt (f) den Beginn F; danach gilt (g) für jedes Objekt, das (a) bis (e) bestanden hat, (g′) für jedes Objekt, das zudem (g) bestanden hat und damit nach (a) bis (g) festgestellt wäre, und (h) für jedes Objekt, das zudem (g′) bestanden hat:

- (a) Kein Paar von o nennt als Schlüssel (`server_key_id` aus `entry` oder `key_id` eines Elements von `additional_signatures` mit `alg` = `ed25519`) einen belegten Protokollschlüssel: `VENDOR_LOG_UNVERIFIED(dayOf(o))` „Schlüssel nicht belegt“; o ist nicht festgestellt.
- (b) Für jedes Paar unter einem belegten Protokollschlüssel wird die Ed25519-Signatur über `UTF-8(statement_jcs)` geprüft. Jedes Paar, dessen Signatur nicht trägt, ergibt `VENDOR_LOG_DEFECTIVE(dayOf(o))` „Signatur“, ohne o zu entfernen. Trägt keine, ist o nicht festgestellt; sonst heißen die Paare, deren Signatur trägt, die **tragenden Paare** von o.
- (b′) **Siegel nach ML-DSA-87** (ab Fassung 1.10). Für jedes Siegel von o mit `type` = `ml-dsa-87`, dessen `key_id` einen Schlüssel aus P_mldsa nennt, wird die Signatur nach Abschnitt 7.4.5a über `UTF-8(statement_jcs)` geprüft, mit `Bytes(value)` als Signatur. Verletzt `value` B64, ergibt es nicht genau 4627 Bytes oder trägt die Signatur nicht: `VENDOR_LOG_DEFECTIVE(dayOf(o))` „ML-DSA-Signatur“, ohne o zu entfernen; sonst ist es ein **tragendes ML-DSA-Siegel** von o. Ein Siegel mit `type` = `ml-dsa-87`, dessen `key_id` keinen Schlüssel aus P_mldsa nennt, wird nur gezählt (`seals.ml_dsa.key_not_established`, Abschnitt 10.10.2). (b′) läuft für jedes Objekt, auch für Tage vor H und mit H = `null`; allein macht es kein Objekt zu einem nicht festgestellten.
- (c) Der Inhalt verletzt Abschnitt 7.4.5 (druckbares ASCII, I-JSON, eigene JCS-Form, genau die Member mit ihren Typen, `kind`, `log_id` gleich der der Auszüge, Protokollbereich, Form von `server_ts`): `VENDOR_LOG_CONTRADICTION(dayOf(o))` „signierter Eintrag verletzt das Format“. Die Signatur trägt, also hat der Inhaber des Protokollschlüssels den Inhalt signiert.
- (d) Jeder Zeitstempel von o wird nach Abschnitt 7.5.7 beurteilt: mangelhaft, nicht bestätigt oder bestätigt, mit seinem `genTime`.
- (e) Ein tragendes Paar **gilt**, wenn sein Schlüssel weder `gueltig_bis` noch `widerrufen_ab` trägt oder wenn ein bestätigter Zeitstempel von o ein `genTime` vor dem Ende dieses Schlüssels zeigt (Ende = der frühere der beiden Werte, gelesen nach Abschnitt 10.7; verglichen auf Nanosekunden mit dem vollen `genTime`, nicht auf Millisekunden abgeschnitten, Abschnitt 2). Gilt kein tragendes Paar: `VENDOR_LOG_UNVERIFIED(d)` „Gültigkeit des Protokollschlüssels beendet, Zeit der Signatur nicht belegt“; o ist nicht festgestellt. `gueltig_ab` wird gegen Tageseinträge nicht geprüft: Sonst wäre das Neusignieren nach einem Schlüsselwechsel ausgeschlossen, und eine untere Schranke der Signaturzeit belegt kein Zeitstempel.
- (e′) Ein tragendes ML-DSA-Siegel **gilt** nach der Regel aus (e) für seinen Schlüssel aus P2: wenn dieser weder `gueltig_bis` noch `widerrufen_ab` trägt oder wenn ein bestätigter Zeitstempel von o ein `genTime` vor dem Ende dieses Schlüssels zeigt (verglichen auf Nanosekunden). (e′) ergibt keinen Befund; ob o ein geltendes ML-DSA-Siegel braucht, entscheidet (g′).
- (f) **Beginn F.** Mit wirksamer Liste ist F deren `erster_tag` (Schritt L1). Gibt es nur Anheftungen, entscheiden die Objekte, die (a) bis (e) bestanden haben: Nennen sie alle denselben `first_day`, ist F dieser Wert. Hat keines (a) bis (e) bestanden, ist F unbekannt, ohne Befund; dann erreicht auch kein Objekt (g). Nennen sie verschiedene `first_day`, meldet der Verifier einmal `VENDOR_LOG_CONTRADICTION` ohne Tag „Tageseinträge unter angehefteten Schlüsseln nennen keinen gemeinsamen first_day“; F ist unbekannt, kein Objekt ist festgestellt, (g) und (h) und die Schritte L3 bis L7 und L9 entfallen, und in Schritt L8 ist jede Quittung `unchecked` mit der Unterklasse `first_day_contradictory`. Ist F unbekannt, ist `first_day` im Bericht `null`.
- (g) Regeln des Protokolls: d ≥ F; `prev_hash` besteht genau dann aus 64 Nullzeichen, wenn d = F; aus `tree_size = 0` folgt `root = SHA-256("")`; `server_ts` (in ganzen Millisekunden) ≥ `end(d)`; `first_day = F`. Ein Verstoß: `VENDOR_LOG_CONTRADICTION(d)` „signierter Eintrag verletzt eine Regel des Protokolls“; o ist nicht festgestellt.
- (g′) **Hybridregel** (ab Fassung 1.10), nur für ein Objekt, das (g) bestanden hat; ein Objekt, das schon vorher scheitert, behält seine Wirkung aus (a) bis (g) und wird nie hybrid-unvollständig. Ist H ≠ `null` und d ≥ H, ist o nur festgestellt, wenn mindestens ein tragendes ML-DSA-Siegel von o gilt. Sonst ist o **hybrid-unvollständig** und nicht festgestellt: `VENDOR_LOG_UNVERIFIED(d)` „ML-DSA-Signatur fehlt, ist nicht belegt oder nicht mehr gültig“. Hat ein Siegel unter einem Schlüssel aus P_mldsa nicht getragen, steht daneben schon der Befund aus (b′). Die Bedingungen aus (a), (b) und (e) für die Ed25519-Signatur gelten unverändert: Beide Verfahren müssen tragen.
- (h) Sonst ist o **festgestellt**. Ist einer seiner Zeitstempel mangelhaft: `VENDOR_LOG_DEFECTIVE(d)` „Zeitstempel trägt nicht“. Ist einer seiner bestätigten Zeitstempel verfrüht: `VENDOR_LOG_CONTRADICTION(d)` „Tag vor seinem Ende abgeschlossen“, und o ist **gebrochen**. o ist **bezeugt**, wenn mindestens einer seiner bestätigten Zeitstempel bezeugend ist und o nicht gebrochen ist.

**L3 Tage.** S(d) sind die festgestellten Einträge des Tages d, Wt(d) die bezeugten. Hat S(d) zwei oder mehr Elemente: `VENDOR_LOG_CONTRADICTION(d)` „zwei signierte Fassungen“, mit beiden Tageshashes. Der kanonische Eintrag c(d) ist das Element von Wt(d), wenn Wt(d) genau eines hat; sonst, wenn Wt(d) leer ist und S(d) genau einen nicht gebrochenen Eintrag hat, dieser; sonst ist c(d) nicht bestimmt. Der Tag d ist **nutzbar**, wenn c(d) bestimmt und bezeugt ist. Eine spätere unbezeugte Fassung wird also gemeldet, nimmt der bezeugten aber den Tag nicht; zwei bezeugte Fassungen machen den Tag unbrauchbar. Die Wirkung eines Widerspruchs an einem Tag bleibt auf diesen Tag beschränkt. Für Bedingung (5) der Beweisstufe zählen nur Widersprüche ohne Tag und an Tagen des verlangten Bereichs dieses Pakets (Schritt L7, Abschnitt 10.9.4); ein Widerspruch an einem anderen Tag, etwa in einem Jahresspiegel, nimmt einem Paket nicht die Stufe 3.

**L3a COSE Receipts der Tage** (ab Fassung 1.11; in Fassung 1.10 läuft der Schritt nicht, Abschnitt 7.7). Für jedes Tagesobjekt o nach dem Zusammenlegen (Schritt L2) und jedes verschiedene Element y seiner `day_receipts` gilt der erste zutreffende der folgenden Schritte; T und U nach Abschnitt 7.7.5:

- **D1 Profil.** y verletzt B64 (Abschnitt 2), Bytes(y) umfasst mehr als 1024 Bytes, oder Bytes(y) verletzt Grammatik C (Abschnitt 7.7.1), das Profil in Ablageform (Abschnitt 7.7.2) oder Profil C2 (Abschnitt 7.7.4): `defective`, `VENDOR_LOG_DEFECTIVE(dayOf(o))` „COSE-Receipt verletzt das Profil“.
- **D2 Schlüssel.** `kid` nennt keinen Schlüssel aus T: `key_not_established`.
- **D3 Protokoll.** `iss` ist nicht U, oder es gibt kein U: `other_log`.
- **D4 Tag.** o hat keinen Tag, oder `sub` ist nicht dayOf(o): `defective`, `VENDOR_LOG_DEFECTIVE(dayOf(o))` „COSE-Receipt eines anderen Tages“. Sonst sei e = `sub`. Ist c(e) nicht bestimmt (Schritt L3): `day_not_determined`.
- **D5 Signatur.** Vergleich nach Wert: R(e) sind die verschiedenen Werte `Bytes(root)` der Einträge aus S(e), zuerst der von c(e), danach die übrigen aufsteigend nach ihren Bytes. Trägt die Signatur von y unter dem Publikey aus D2 über die Sig_structure (Abschnitt 7.7.2) mit R gleich einem Wert r aus R(e), in dieser Reihenfolge geprüft, ist r die **Wurzel von y**; ein Eintrag wird dabei nicht ausgewählt. Trägt sie über keinen: `defective`, `VENDOR_LOG_DEFECTIVE(e)` „Signatur des COSE-Receipts trägt nicht“.
- **D6 Gültigkeit.** Der Schlüssel aus D2 gilt nicht für C2 zum Tag e (Abschnitt 7.7.5): `key_not_valid`.
- **D7 Vergleich.** Ist r = `Bytes(root)` von c(e) und gleicht der Wert von −65537 `tree_size` von c(e): `matching`; ein neuer Abschluss desselben Tages mit derselben Wurzel und Größe ist also nie ein Widerspruch. Sonst: `contradicting`, `VENDOR_LOG_CONTRADICTION(e)` „COSE-Receipt weicht vom Tageseintrag ab“, denn der Hersteller hat über denselben Tag zwei verschiedene Aussagen signiert.

Jedes Element zählt in genau einer der Klassen `matching`, `contradicting`, `defective`, `key_not_established`, `key_not_valid`, `other_log` und `day_not_determined` (Abschnitt 10.10.2, `vendor_log.day_receipts`). Entfällt Schritt L3 (Schritt L2 (f)), zählt jedes Element als `day_not_determined`. L3a ändert weder S(d) noch c(d) noch die Klassen aus Schritt L8, und ein fehlendes COSE Receipt ergibt nie einen Befund. Ein Widerspruch aus D7 zählt wie jeder andere für `days.contradictory` und für Bedingung (5) der Beweisstufe (Schritt L3; Abschnitt 10.9.4).

**L4 Kopf.** Der Kopf ist der jüngste Tag d, für den c(d) bestimmt ist, oder keiner. `seen_in` ist die Zahl der übergebenen Dateien (gezählt nach verschiedenen Bytes), die den `statement_jcs` von c(Kopf) enthalten. `seen_in` ist kein Maß der Unabhängigkeit: Wer Dateien weitergibt, kann dieselben Tagesobjekte in verschieden geschriebene Dateien setzen, und ob zwei Dateien von zwei Orten stammen, erkennt der Verifier nicht.

**L5 Verkettung.** Sind c(d) und c(d + 1) bestimmt und ist `prev_hash` von c(d + 1) nicht der Tageshash von c(d): `VENDOR_LOG_CONTRADICTION(d + 1)` „knüpft nicht an den Vortag an“. Ist c(d) bestimmt, d > F und S(d − 1) leer, und gleicht `prev_hash` von c(d) dem Tageshash eines festgestellten Eintrags eines Tages x < d − 1: `VENDOR_LOG_CONTRADICTION(d)` „überspringt die Tage x + 1 bis d − 1“.

**L6 Kettentag-Nachweise.** Verwendet werden nur Nachweise aus Auszügen mit `chain_id = C`. Nachweise anderer Ketten werden gezählt (`foreign_chain_records`: jeder Nachweis jedes Auszugs, auch ein gleicher Nachweis in mehreren Dateien) und übergangen, damit Läufe über eine Kettennachfolge möglich bleiben; Nachweise der Kette C an Tagen, die nicht nutzbar sind, werden übergangen und in keinem Member des Berichts gezählt. Für einen nutzbaren Tag d sind n = `tree_size` von c(d), R = `root` von c(d) und p = position(C, d) mit A:

- `present`: Aus jedem Element von `roots` entsteht das Blatt nach Abschnitt 7.4.2 (`countersigned` als Gegensignatur, `gap_witness` als Lückenzeuge, je mit `chain_id` C; `server_ts` geht als die Zeichenkette ein, die der Auszug trägt, Abschnitt 7.4.2, Blatt aus der Aufzeichnung), daraus die Kettentag-Wurzel nach Abschnitt 7.4.3 (aufsteigend nach Blatt-Hash geordnet, gleich in welcher Reihenfolge `roots` die Wurzeln nennt) und das Kettentag-Blatt mit p. Verlangt ist `verify_inclusion(leaf_index, n, LH(Kettentag-Blatt), path, R)` (Abschnitt 5).
- `absent`: genau eine der Formen des Abwesenheitsbeweises aus Abschnitt 5 für p gegen (n, R); jedes Nachbarblatt `UTF-8(JCS({"chain_root": …, "kind": "ledger.vendor_log_day_leaf.v1", "position": …}))` trägt durch Inklusion gegen (n, R). Ein Nachbar kann ein Füller sein; der Verifier unterscheidet Füller nicht von Kettentag-Blättern (Abschnitt 7.4.4).
- n und R kommen immer aus c(d), nie aus dem Nachweis (Abschnitt 5).
- Ein Nachweis, der nicht trägt: `VENDOR_LOG_DEFECTIVE(d)`.
- Unter den tragenden Nachweisen für (C, d): eine Wurzel in `present` mit `day(server_ts) ≠ d` ergibt `VENDOR_LOG_CONTRADICTION(d)` „Blatt eines anderen Tages“; zwei tragende Nachweise, die sich unterscheiden (in der Kettentag-Wurzel oder als `present` gegen `absent`), ergeben `VENDOR_LOG_CONTRADICTION(d)` „zwei Kettentag-Nachweise“. In beiden Fällen ist der Nachweisstand des Tages **widersprüchlich**.
- Sonst ist der Stand **geprüft**, mit der belegten Blattmenge M(d), leer bei `absent`. Ohne Nachweis ist der Stand **keiner**; mit Nachweisen, von denen keiner trägt, **gescheitert**.

**L7 Verlangter Bereich.** RD sind die Tage der Quittungen aus Schritt L8 (jeder `CHECKPOINT_RECEIPT`, dessen Signatur nach Abschnitt 7.1 trägt und der keinen Befund `RECEIPT_INVALID` hat); RDF die Tage aus RD, die ≥ F sind (alle aus RD, wenn F unbekannt ist). T ist das Maximum aus dem Kopf und den fälligen Tagen aus RDF, Lo das Minimum von RDF. Gibt es beide und ist Lo ≤ T, fehlt jeder Tag d in [Lo, T], für den kein Eintrag festgestellt ist (S(d) leer, Schritt L3); ein Objekt unter einem nicht belegten Schlüssel, mit einer Signatur, die nicht trägt, oder mit einem Verstoß gegen Format oder Regeln stellt keinen Tag fest. Je Lauf aufeinanderfolgender fehlender Tage meldet der Verifier einmal `VENDOR_LOG_UNVERIFIED` „Tage ohne festgestellten Tageseintrag in den übergebenen Auszügen“, mit Anfang und Ende des Laufs. Ein fälliger Tag einer Quittung jenseits des Kopfes ist damit ein Befund, nie ein stiller Zähler. Begrenzt wird der Bereich durch die Tage der Quittungen und den Kopf, nie durch `ts_chained`. Ab Fassung 1.10 fehlt ein Tag d mit leerem S(d) nicht, wenn für d ein hybrid-unvollständiges Objekt vorliegt (Schritt L2 (g′)): Er zählt in keinem Lauf fehlender Tage, und seinen Befund gibt (g′).

**L8 Quittungen.** Geprüft wird in Kettenreihenfolge jeder `CHECKPOINT_RECEIPT`, dessen Signatur unter dem Schlüssel nach Abschnitt 7.1 trägt, ob dieser belegt ist oder nicht, und der keinen Befund `RECEIPT_INVALID` hat. Das gilt auch bei einem Widerspruch oder Fork der Kette (etwa `FORK_DETECTED`); eine Quittung mit `RECEIPT_INVALID` wird übergangen, auch wenn ihre Signatur trägt. Dieselbe Menge von Quittungen verwenden Schritt L7 und die Vorreichweite r5′ (Abschnitt 10.9.4). Je Quittung ist ℓ = LH des Signaturgegenstands aus Abschnitt 7.1, gebildet aus der `chain_id` des Envelopes und der Nutzlast, mit `server_ts` als Zeichenkette der Nutzlast, und d = day(`server_ts`). Die Fälle werden der Reihe nach geprüft; es gilt der oberste, der zutrifft:

1. F ist bekannt und d < F: `before_start`.
2. `server_ts` (in ganzen Millisekunden) liegt nach `now` + 900 000: `future` und `VENDOR_LOG_UNVERIFIED(d)` „Quittung mit server_ts nach dem Prüfzeitpunkt“. Kein abgeschlossener Tag kann eine solche Quittung enthalten; sie ist nie `pending`.
3. d ist nutzbar: Stand geprüft ergibt `included`, wenn ℓ in M(d) liegt, sonst `not_included`; Stand keiner ergibt `unchecked` mit `no_record` und `VENDOR_LOG_UNVERIFIED(d)` „kein Kettentag-Nachweis übergeben“; Stand gescheitert ergibt `unchecked` mit `record_failed`; Stand widersprüchlich ergibt `unchecked` mit `record_contradictory`.
4. c(d) ist bestimmt, aber nicht bezeugt: `unchecked` mit `day_not_witnessed` und `VENDOR_LOG_UNVERIFIED(d)` „Tageseintrag nicht bezeugt“, mit einem Grund aus Registry `vendor_log.not_witnessed_reasons`: `no_timestamp`, wenn c(d) keinen Zeitstempel trägt; sonst `no_log_root_supplied`, wenn der Prüfer keine Wurzel des Zwecks `log` übergeben hat; sonst der Grund des Zeitstempels von c(d), der am weitesten kam, in dieser Rangfolge von unten nach oben: `outside_profile` (Schritt 5 nach 5a nicht ausführbar oder Z.6 nicht prüfbar, Abschnitt 7.5.6), `not_chained_to_log_root` (kein Pfad zu einer Wurzel des Zwecks `log`), `published_test_key` (Pfad besteht, Schlüssel in `published_test_keys`), `late` (bestätigt, aber verspätet). Mangelhafte Zeitstempel zählen für den Grund nicht. Der Befund entfällt, wenn jeder Zeitstempel von c(d) mangelhaft ist; dann meldet schon `VENDOR_LOG_DEFECTIVE` den Tag.
5. S(d) ist nicht leer, c(d) ist aber nicht bestimmt: `unchecked` mit `day_contradictory`.
6. S(d) ist leer (für d ist kein Eintrag festgestellt): `unchecked` mit `hybrid_incomplete`, wenn für d ein hybrid-unvollständiges Objekt vorliegt (Schritt L2 (g′), ab Fassung 1.10; den Befund meldet (g′)); sonst `missing`, wenn d fällig ist (den Befund meldet L7), sonst `pending`. Ein anderes Objekt, das keinen Eintrag feststellt (Schritt L7), ändert diese Klasse nicht.

Hat Schritt L2 (f) die Prüfung beendet, ist jede dieser Quittungen `unchecked` mit der Unterklasse `first_day_contradictory`, ohne weiteren Befund.

Je Tag mit Quittungen der Klasse `not_included` meldet der Verifier einmal `RECEIPT_NOT_LOGGED(d)`, mit ihrer Zahl und der kleinsten `seq` unter ihnen. Nur ein bezeugter Tag kann gegen eine Quittung zeugen: Wer einen Protokollschlüssel entwendet hat, aber keinen rechtzeitigen Zeitstempel beibringt, kann keine ehrliche Quittung belasten.

| Klasse | Bedeutung |
|---|---|
| `included` | im bezeugten Kettentag ihres Tages nachgewiesen |
| `not_included` | Tag bezeugt und Nachweis geprüft, ihr Blatt fehlt darin oder die Kette ist als abwesend belegt (`RECEIPT_NOT_LOGGED`) |
| `unchecked` | nicht prüfbar, mit Unterklasse `no_record`, `record_failed`, `record_contradictory`, `day_not_witnessed`, `day_contradictory`, `first_day_contradictory` oder, ab Fassung 1.10, `hybrid_incomplete` |
| `missing` | kein festgestellter Tageseintrag für ihren Tag, obwohl er fällig ist |
| `pending` | kein festgestellter Tageseintrag für ihren Tag; der Tag ist noch nicht fällig |
| `before_start` | ihr Tag liegt vor dem Beginn des Protokolls |
| `future` | ihr `server_ts` liegt mehr als 15 Minuten nach dem Prüfzeitpunkt |

**L9 Festgehaltene Wurzeln.** Für jeden nutzbaren Tag d mit geprüftem Nachweis `present` und jedes Element (t, r, `recorded_as`) seiner `roots`: Ist t ≤ N und `root(t) = r`, passt die Wurzel zum Paket (ein Blatt `countersigned` ohne Quittung desselben Blatts im Paket zählt zusätzlich als `matching_without_receipt`, je verschiedenes Blatt einmal; eine Quittung mit `RECEIPT_INVALID` ist dafür eine Quittung ihres Blatts). Ist t ≤ N und `root(t) ≠ r`: `LOGGED_ROOT_MISMATCH`, einmal je (t, r), mit Tag und Art. Ist t > N, zählt die Wurzel als `beyond_package` und geht mit ihrem `server_ts` an die Prüfung der Anker-Historie (Abschnitt 8.8). Festgehaltene Wurzeln sind keine erwarteten Wurzeln: Sie verankern nichts, heben `NO_ANCHOR` nicht auf und belegen keine Vollständigkeit; sie dienen dem Abgleich, hier und in Abschnitt 8.8.

**L10 Ausgabe.** Das Ergebnis steht im Berichtsobjekt `vendor_log` (Abschnitt 10.10), darunter der Status, der Kopf mit Tageshash und `seen_in`, die Zahl der Quittungen je Klasse und die Klasse der Quittung, die Abschnitt 8.6 als letzte gegengezeichnete wählt. Ab Fassung 1.10 nennt `vendor_log` außerdem `day_receipts` (Schritt L3a) und `key_list.log_uri`. Der Exit-Code ändert sich nur über die fünf Klassen aus Abschnitt 7.4.11, also höchstens von 0 zu 1; Exit 3 entsteht nur in L0.

#### 7.4.11 Befunde

Alle fünf Klassen haben die Exit-Klasse 1 (Abschnitt 10.4). Die Liste `/2`, der Auszug `/2`, die Signatur nach ML-DSA-87 und die COSE Receipts der Tage (ab Fassung 1.10) fügen keine Klasse hinzu; ihre Fälle stehen unten bei `VENDOR_LOG_UNVERIFIED`, `VENDOR_LOG_DEFECTIVE` und `VENDOR_LOG_CONTRADICTION`; die COSE-Gegensignaturen haben eigene Klassen (Abschnitt 7.7.7), und Exit 3 entsteht auch für sie nur in Schritt L0. Siegel, die diese Fassung nicht prüft, und Siegel unter einem Schlüssel außerhalb von P_mldsa ergeben keinen Befund.

| Befundklasse | Bedeutung (Registry) | Fälle |
|---|---|---|
| `VENDOR_LOG_UNVERIFIED` | Herstellerprotokoll übergeben, aber nicht durch Anker des Prüfers belegt oder nicht vollständig übergeben | kein wirksamer Protokollschlüssel (keine Liste, fremde Wurzel, Schlüssel in zwei Rollen, widersprüchliche Listen); Eintrag unter einem Schlüssel, der kein belegter Protokollschlüssel ist; Gültigkeit beendet ohne belegte Signaturzeit; Tag einer Quittung nicht bezeugt; Tage ohne festgestellten Eintrag im verlangten Bereich; kein Kettentag-Nachweis für einen nutzbaren Tag einer Quittung; eine Quittung mit `server_ts` nach dem Prüfzeitpunkt; ab Fassung 1.10 ein Tageseintrag ab `hybrid_ab` ohne geltende Signatur nach ML-DSA-87 (hybrid-unvollständig, Schritt L2 (g′)) |
| `VENDOR_LOG_DEFECTIVE` | übergebenes Herstellerprotokoll trägt nicht (Signatur, Zeitstempel oder Nachweis) | die Signatur eines Eintrags trägt nicht; ein Zeitstempel ist mangelhaft; ein Nachweis trägt weder als Inklusion noch als Abwesenheit; ab Fassung 1.10 ein Siegel `ml-dsa-87` unter einem Schlüssel aus P_mldsa, dessen `value` B64 verletzt, nicht genau 4627 Bytes ergibt oder dessen Signatur nicht trägt (Schritt L2 (b′)); ab Fassung 1.10 ein COSE Receipt eines Tages, das Profil C2 verletzt, einen anderen Tag nennt oder dessen Signatur über keinen festgestellten Eintrag seines Tages trägt (Schritt L3a, D1, D4, D5) |
| `VENDOR_LOG_CONTRADICTION` | Hersteller hat einander widersprechende oder regelwidrige Protokollaussagen signiert | zwei festgestellte Einträge für einen Tag; gebrochene Verkettung oder übersprungene Tage; signierter Verstoß gegen Format oder Regeln; bestätigter verfrühter Zeitstempel; zwei verschiedene tragende Nachweise; ein Blatt eines anderen Tages; ab Fassung 1.10 ein COSE Receipt eines Tages unter einem geltenden Transparenzschlüssel, das einen anderen Eintrag oder eine andere Baumgröße nennt als c(d) (Schritt L3a, D7) |
| `RECEIPT_NOT_LOGGED` | Quittung fehlt im bezeugten Herstellerprotokoll ihres Tages | eine Quittung, deren Signatur trägt, an einem nutzbaren Tag, dessen geprüfter Nachweis ihr Blatt nicht enthält oder die Kette als abwesend belegt |
| `LOGGED_ROOT_MISMATCH` | im Herstellerprotokoll festgehaltene Wurzel passt nicht zum Paket | eine geprüfte festgehaltene Wurzel mit t ≤ N weicht von `root(t)` ab |

**Mehrfachmeldungen.** Je Klasse und UTC-Tag höchstens ein Befund, mit den Gründen in der Reihenfolge der Schritte, außer `LOGGED_ROOT_MISMATCH` (je (`tree_size`, `merkle_root`)) und den Läufen fehlender Tage; je Klasse höchstens einer ohne Tag; fehlende Tage zusammengefasst je Lauf, neben einem Befund derselben Klasse an einem Tag des Laufs; `RECEIPT_NOT_LOGGED` einmal je Tag mit Zahl und kleinster `seq`; `LOGGED_ROOT_MISMATCH` einmal je (`tree_size`, `merkle_root`).

**Warum keiner davon Exit 2.** Jeder Fall kann bei einer ehrlichen Kette eintreten: ein beschädigter Abruf, ein Ausfall oder Datenverlust beim Hersteller, sein Fehlverhalten, eine erfundene Wurzel, die Übernahme einer `chain_id`. „Ungültig“ ist nachgewiesener Manipulation der Kette vorbehalten (Abschnitt 8.6); mit Exit 2 aus dem Verhalten des Herstellers könnte ein Hersteller eine ehrliche Kette ohne Zutun des Prüfers ungültig machen. `LOGGED_ROOT_MISMATCH` kann ein Umschreiben durch den Schlüsselinhaber bedeuten oder eine Wurzel, die der Hersteller erfunden hat; der Verifier kann beides nicht unterscheiden. Der Weg zu Exit 2 bleibt die Anker-Historie als Quelle erwarteter Wurzeln (Abschnitte 8.6, 8.8).

#### 7.4.12 Datenschutz und Neutralität

| Veröffentlicht oder ausgeliefert | Inhalt | Empfänger | Was es verrät |
|---|---|---|---|
| Tageseintrag | Tag, Größe, Wurzel, Hash des Vortags, Zeit | jeder | die Größenstufe nach der Größenregel (Abschnitt 7.4.4) |
| Tagesblätter | Positionen, Kettentag-Wurzeln | jeder | dasselbe wie die Größe; wer ein Prüfpaket einer Kette hatte, erkennt deren spätere aktive Tage |
| Auszug mit Kettentag-Nachweisen | Wurzeln und Zeiten der Kette, Geschwisterwerte, Nachbarn | wer die `chain_id` nennt | dasselbe wie die Anker-Historie (Heartbeat-Spezifikation §9.7) |
| Protokollschlüsselliste, Rollenliste, Liste der Gegenzeichnungsschlüssel | öffentliche Schlüssel, Rollen, Gültigkeit, Orte, Füllerbindung | jeder | nichts darüber hinaus |
| COSE Receipt eines Tages (C2, ab Fassung 1.10, Abschnitt 7.7.4) | Tag, Größe, Wurzel, `log_uri`, `kid`; in Vorlageform ein Einschlussbeweis für Index 0 | jeder | nichts über Tageseintrag und Tagesblätter hinaus |
| COSE-Gegensignatur (C1) und C2 in Vorlageform zu einer Kette (Abschnitte 7.7.3, 7.7.4) | `chain_id`, Größe, Zeit der Gegensignatur; Einschlussbeweis des Kettentag-Blatts | wer die `chain_id` nennt | dasselbe wie der Auszug mit Kettentag-Nachweisen (Abschnitt 7.7.9) |
| Öffnung von Füllern (Abschnitt 7.4.13) | Salze oder ein Tagesgeheimnis | eine prüfende Stelle, der der Hersteller sie gibt; nie öffentlich | einzeln: dass diese Blätter Füller sind; für einen ganzen Tag: die Zahl seiner Ketten |

- Kein Objekt des Protokolls trägt Kundendaten oder ein Commitment; öffentliches Material trägt weder `chain_id` noch `appliance_id` im Klartext. Nur `chain_id` und `appliance_id` der Zugriffskette des Herstellers, einer Kette ohne Kundendaten, veröffentlicht der Hersteller selbst (Heartbeat-Spezifikation §12).
- Wer einmal ein Prüfpaket hatte, kennt `chain_id` und `appliance_id` der Kette. Er kann Auszüge und Seiten der Anker-Historie dieser Kette auch später abrufen und erfährt so spätere Wurzeln, Baumgrößen, Zeiten der Gegensignaturen und Änderungen der Angabe zur Verbundenheit. Über `successor` einer Seite (Heartbeat-Spezifikation §9.7) erfährt er die `chain_id` der Nachfolgekette; weil beide Ketten derselben Appliance gehören, kann er mit derselben `appliance_id` deren Positionen berechnen und ihre aktiven Tage in den Tagesblättern erkennen (Abschnitt 11.2).
- Jede Kette wird nach derselben Regel protokolliert, ohne Ausnahme und ohne Variante je Kunde, auch die eigenen Ketten des Herstellers und die Ketten verbundener Kunden (Heartbeat-Spezifikation §9.10). Der Aufbau des Protokolls liest nur die Blätter und die Bindung der Kette an ihre Appliance, keine Lizenz-, Kunden- oder Verbundenheitsdaten; die Verbundenheit steht nie im Protokoll.
- Jeder Hersteller kann ein Protokoll nach diesen Regeln führen, mit eigener Wurzel, eigener `log_id`, eigenen Protokollschlüsseln, eigenem Füllergeheimnis und eigenen Zeitstempelstellen; kein Kriterium nennt einen Hersteller.
- Was der Hersteller über Abrufe des Protokolls festhält, regelt Heartbeat-Spezifikation §12. Ob er sich daran hält, zeigt kein Prüfpaket und kein Auszug (kein Beleg durch LEDGER).

#### 7.4.13 Öffnung von Füllern `ledger-fuelleroeffnung/1`

Mit einer Öffnung zeigt der Hersteller einer prüfenden Stelle, dass bestimmte Blätter eines Tagesbaums Füller sind (Abschnitt 7.4.4). Eine Öffnung gibt es nur für Füller nach der abgeleiteten Bildung, an Tagen ab der ersten Version der Protokollschlüsselliste, die die Füllerbindung nennt. Eine Öffnung ist eine Datei nach den Regeln für Dateien des Prüfers (Abschnitt 2) mit genau diesen Membern; `x?` heißt `x` oder `null`:

```
{"format":       "ledger-fuelleroeffnung/1",
 "log_id":       key-id,
 "day":          date (Protokollbereich),
 "day_secret":   hex64?,                 Tagesgeheimnis g(day); öffnet den ganzen Tag
 "filler_count": int (0 … 2^53−1)?,      m(day); genau dann nicht null, wenn day_secret nicht null ist
 "fillers":      [0 … 4096 × {"salt": hex64}]}
```

`fillers` nennt einzeln geöffnete Füller, paarweise verschieden; ist `day_secret` `null`, nennt es mindestens einen. Eine Öffnung ist unsigniert und belegt sich selbst; kein Verifier liest sie, und sie ist keine Angabe des Prüfers nach Abschnitt 10.8. Prüfen kann sie jeder, der den Tageseintrag und die Tagesblätter des Tages hat. Die Ableitung und die Prüfungen F2 bis F4 kommen mit HMAC-SHA-256 und SHA-256 aus; F1 verlangt zusätzlich das Zeitstempelprofil (Abschnitt 7.5).

- **F1** `log_id` und `day` gleichen denen des Tageseintrags; der Eintrag ist bezeugt (Abschnitt 7.4.6), und die Tagesblätter bestehen gegen ihn die Prüfungen (a) bis (c) aus Abschnitt 7.4.9.
- **F2** Für jedes Element von `fillers` stehen Position und Wurzel, gebildet nach Abschnitt 7.4.4 aus `day`, `log_id` und `salt`, als Paar in den Tagesblättern.
- **F3** Mit `day_secret`: Die Kandidaten werden aus `day_secret` gebildet (Abschnitt 7.4.4). Die Kandidaten 0 bis `filler_count` − 1 stehen mit ihrem Paar in den Tagesblättern, und ihre Positionen sind paarweise verschieden; die Position des Kandidaten `filler_count` steht nirgends in den Tagesblättern; jedes Salz aus `fillers` ist das eines der Kandidaten 0 bis `filler_count` − 1. Sonst besteht die Öffnung nicht. Steht unter einem bezeugten Eintrag an der Position eines Kandidaten ein Blatt mit einer anderen Wurzel, hat dieses Blatt keinen nachweisbaren Ursprung; das ist dem Hersteller zuzurechnen.
- **F4** Mit `day_secret`: `tree_size` ist die kleinste Zweierpotenz, die mindestens 1024 und mindestens `tree_size` − `filler_count` ist. Scheitert F4, besteht die Öffnung trotzdem, und der Hersteller hat an diesem Tag die Größenregel verletzt.
- **Füller außerhalb der Auswahl.** Steht ein Blatt, das sich nach F2 als Füller zeigt, an einer Position, die keiner der Kandidaten 0 bis `filler_count` − 1 einer Öffnung desselben Tages einnimmt, die F3 besteht, hat der Hersteller an diesem Tag gegen die Auswahl verstoßen (Abschnitt 7.4.4); das ist ihm zuzurechnen.
- **Füllergeheimnis.** Gibt der Hersteller einer prüfenden Stelle das Füllergeheimnis G selbst, prüft sie zuerst, dass die Füllerbindung aus G (Abschnitt 7.4.4) gleich `fuellerbindung` der Protokollschlüsselliste ist. Dann bildet sie jedes Tagesgeheimnis selbst, für jeden Tag `filler_count` als den kleinsten Index eines Kandidaten, dessen Position nicht in den Tagesblättern steht, und führt F3 und F4 aus. Sie erfährt damit für jeden Tag des Protokolls, was die Öffnung des ganzen Tages zeigt.

Was eine Öffnung belegt, wenn F1 bis F3 bestehen:

| Teil | belegt | belegt nicht |
|---|---|---|
| F2 | Jedes geöffnete Blatt ist ein Füller und kein Kettentag-Blatt einer Kette (Abschnitt 7.4.4). Es wurde aus diesem Salz gebildet, als der bezeugte Baum entstand; ein passendes Salz erst später zu finden, verlangte ein Urbild von SHA-256. | den Index des Füllers; die Zahl der Füller des Tages |
| F3 | Die Kandidaten 0 bis `filler_count` − 1 sind Füller, und der Kandidat `filler_count` steht nicht im Baum. Für die Zahl der Ketten folgt daraus nur die obere Schranke n(d) ≤ `tree_size` − `filler_count`. | dass die übrigen `tree_size` − `filler_count` Blätter keine Füller sind: Weitere Kandidaten jenseits von `filler_count` oder Blätter aus beliebigen Salzen im Baum bemerkt F3 nicht. Dass diese Blätter zu Ketten mit ehrlichen Blättern gehören, zeigt der Hersteller je Blatt mit den Blättern der Kette und ihrer Bindung an die Appliance (Abschnitte 7.4.2, 7.4.3); das sind Kundendaten (Heartbeat-Spezifikation §12), und diese Fassung legt dafür kein Format fest. |
| F4 | Scheitert F4, hat der Hersteller an diesem Tag die Größenregel verletzt. | dass die Größenregel eingehalten ist, wenn F4 besteht; das zeigt erst der Nachweis des Ursprungs jedes Blatts, das keiner der Kandidaten 0 bis `filler_count` − 1 ist |
| jede Öffnung | nichts über andere Tage: Aus einem Tagesgeheimnis und aus Salzen lässt sich weder das Füllergeheimnis noch das Tagesgeheimnis oder ein Salz eines anderen Tages berechnen. | dass das Tagesgeheimnis aus dem Füllergeheimnis stammt; das zeigt nur das Füllergeheimnis selbst, geprüft gegen die Füllerbindung (oben). Ob der Hersteller an Tagen, die er nicht öffnet, abgeleitete Füller verwendet (kein Beleg durch LEDGER) |

Die Größenregel und die Zahl der Ketten eines Tages zeigt also nur die Öffnung des ganzen Tages zusammen mit dem Nachweis des Ursprungs jedes Blatts, das kein Füller der Auswahl ist. Die Öffnung eines ganzen Tages allein zeigt dem Empfänger bei einem Hersteller, der die Auswahl einhält, die Zahl der Ketten dieses Tages, sonst eine obere Schranke; die Öffnung einzelner Füller zeigt nur, dass es mindestens so viele Füller gibt, wie sie öffnet. Eine Öffnung ist an keinen Empfänger gebunden; wer sie erhält, kann sie weitergeben. Wem der Hersteller Öffnungen gibt und wie er sie festhält, regelt Heartbeat-Spezifikation §9.9.

Referenzwerte (Tagesbaum der Größe 5 aus Abschnitt 7.4.4, F1 vorausgesetzt): Die Öffnung des Kandidaten 1 mit dem Salz `beb59a39221d53bf16f62d42d66bfe2ac7bdcf26661432e5a8489b1c626adb46` besteht F2. Die Öffnung des ganzen Tages mit g(d) und `filler_count` 4 besteht F3, und F4 scheitert, wie bei einem Testbaum unterhalb der Größenregel erwartet. Mit `filler_count` 5 scheitert F3 (Kandidat 4 fehlt), mit `filler_count` 3 ebenso (Kandidat 3 steht in den Tagesblättern). Ein fremdes Salz scheitert an F2, eine fremde Wurzel an der Position des Kandidaten 1 an F3. Die Öffnung des Tages mit 1023 Füllern (Abschnitt 7.4.4) besteht F2 bis F4.

### 7.5 Zeitstempelprofil

Ab Fassung 1.10. Das Profil legt Byte für Byte fest, wie ein Verifier einen Zeitstempel nach RFC 3161 liest und prüft: für die Zeitzeugen der Kette (Abschnitt 7.3), für die Zeitstempel der Tageseinträge (Abschnitt 7.4.6) und für die Bedingungen der Beweisstufe (Abschnitt 10.9). Ein Verifier MUSS genau diese Regeln anwenden; sein Ergebnis hängt allein von ihnen ab, nicht von einer Zertifikatsbibliothek oder deren Fassung. Weil Zeitstempel unsigniert reisen, könnte sonst jemand zwei Verifier auseinanderbringen, ohne ein signiertes Byte zu ändern. Ein Profil gilt für Zeitzeugen und Protokoll gemeinsam, mit RSASSA-PSS, P-521 und Ed25519. Beide Referenz-Verifier setzen das Profil vollständig um, einschließlich der CMS-Signatur (Schritt 5) und des Pfads (Schritt 6).

#### 7.5.1 Base64

Es gilt die Grammatik B64 aus Abschnitt 2. Ein Token, dessen Zeichenkette sie verletzt, scheitert an Schritt 2 (Abschnitt 7.5.7).

#### 7.5.2 Grammatik T

Die Hülle des Tokens; sie betrifft die Schritte 2 bis 4 aus Abschnitt 7.3.

- **T.1** `ContentInfo ::= SEQUENCE { contentType OID = 1.2.840.113549.1.7.2, content [0] EXPLICIT SignedData }`. Nach ihm stehen in den dekodierten Bytes keine weiteren, und in ihm steht nach `content` nichts.
- **T.2** `SignedData ::= SEQUENCE { version INTEGER (1..5), digestAlgorithms SET OF AlgorithmIdentifier, encapContentInfo, certificates [0] IMPLICIT OPTIONAL, crls [1] IMPLICIT OPTIONAL, signerInfos SET OF SignerInfo }` mit genau einer SignerInfo. Der Inhalt von `certificates` (null oder mehr TLV) wird in Schritt 5 geprüft: Zerfällt er nicht in TLV, ist Schritt 5 nicht ausführbar (5a), und T ist nicht verletzt. Von `crls` wird nur das TLV gelesen.
- **T.3** `EncapsulatedContentInfo ::= SEQUENCE { eContentType OID = 1.2.840.113549.1.9.16.1.4, eContent [0] EXPLICIT OCTET STRING }`; `eContent` ist vorhanden und enthält genau ein TSTInfo ohne nachfolgende Bytes.
- **T.4** `SignerInfo ::= SEQUENCE { version INTEGER (1 | 3), sid, digestAlgorithm AlgorithmIdentifier, signedAttrs [0] IMPLICIT OPTIONAL, signatureAlgorithm AlgorithmIdentifier, signature OCTET STRING, unsignedAttrs [1] IMPLICIT OPTIONAL }`. `sid` ist eine IssuerAndSerialNumber (SEQUENCE) oder `[0] IMPLICIT OCTET STRING` (subjectKeyIdentifier). Grammatik T prüft an `sid` nur, dass es eine SEQUENCE oder ein primitives `[0]` ist; ein Inhalt, der nicht `{ issuer, serialNumber }` mit einem `serialNumber` nach T.6 ist (etwa ein INTEGER nicht in minimaler Form), passt in Z.5 auf kein Zertifikat (Schritt 5a) und ist nie eine Verletzung von T. Die Version wird nicht mit der Form von `sid` verglichen: Version 1 mit subjectKeyIdentifier und Version 3 mit IssuerAndSerialNumber verletzen T nicht. Die Parameter von `digestAlgorithm` fehlen oder sind NULL, und `digestAlgorithm` steht in `digestAlgorithms`, deren Elemente ebenfalls keine Parameter oder NULL tragen; verglichen wird dabei die OID, fehlende Parameter und NULL gelten als gleich. Die Parameter von `signatureAlgorithm` sind ein TLV oder fehlen; geprüft werden sie in Schritt 5. Von `unsignedAttrs` wird nur das TLV gelesen. Sind `signedAttrs` vorhanden, ist jedes Attribut `SEQUENCE { attrType OID, attrValues SET OF }` mit mindestens einem Wert, und es gibt genau ein Attribut `contentType` mit genau einem OID-Wert und genau ein Attribut `messageDigest` mit genau einem OCTET-STRING-Wert.
- **T.5** `TSTInfo ::= SEQUENCE { version INTEGER = 1, policy OID, messageImprint SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }, serialNumber INTEGER, genTime GeneralizedTime, accuracy SEQUENCE { seconds INTEGER OPTIONAL, millis [0] IMPLICIT INTEGER OPTIONAL, micros [1] IMPLICIT INTEGER OPTIONAL } OPTIONAL, ordering BOOLEAN OPTIONAL, nonce INTEGER OPTIONAL, tsa [0] EXPLICIT OPTIONAL, extensions [1] IMPLICIT OPTIONAL }` in dieser Reihenfolge und sonst nichts. `hashAlgorithm` ist sha256, sha384 oder sha512 (Parameter fehlen oder NULL), `hashedMessage` hat dazu passend 32, 48 oder 64 Oktette; sha1 und jeder andere Algorithmus verletzen T. `genTime` hat die Form `JJJJMMTThhmmss[.f]Z` mit 1 bis 9 Ziffern f, deren letzte nicht 0 ist, einem existierenden Datum (Jahr `0001` bis `9999` wie in Abschnitt 2; das Jahr `0000` verletzt T), Stunde 00 bis 23, Minute und Sekunde 00 bis 59 und ohne Versatz. `tsa` ist ein TLV, gelesen als zusammengesetztes `[0]`; sein Inhalt wird nicht geprüft. Den Inhalt von `extensions` liest nur die Regel QS (Abschnitt 7.5.6).
- **T.6** DER für jedes Element: bestimmte Längen in minimaler Form; INTEGER mit mindestens einem Inhaltsoktett in minimalem Zweierkomplement; BOOLEAN mit dem Inhalt `00` oder `FF`; OID mit mindestens einem Inhaltsoktett, jede Teilkennung minimal und abgeschlossen (ihr letztes Oktett hat Bit 8 gleich 0); primitive oder zusammengesetzte Form, wie der Typ es verlangt. Die Reihenfolge in einem SET OF wird nicht geprüft, und ein ausdrücklich kodierter DEFAULT-Wert (etwa `ordering` FALSE, `trailerField` 1) wird angenommen. Wo die Grammatik nur „ein TLV“ verlangt (`tsa`, `crls`, `unsignedAttrs`, der Wert eines signierten Attributs, das keine Regel liest, der Wert eines Attributs in einem Name, die Parameter von `signatureAlgorithm` und jedes anderen AlgorithmIdentifier, soweit keine Regel sie liest, etwa im `hashAlgorithm` eines ESSCertIDv2, `extnValue` einer Erweiterung, die keine Regel liest, und die Teile von `issuerSerial` und `policies`, die Z.6 nennt), wird nur dieses äußere TLV geprüft: Identifier-Oktette nach X.690 Abschnitt 8.1.2, auch für Tag-Nummern ab 31, und eine bestimmte Länge in minimaler Form; sein Inhalt wird nicht zerlegt und muss nicht DER sein. Einen Inhalt, den eine Regel liest, prüft diese Regel nach T.6, dort, wo sie ihn liest: den Inhalt von basicConstraints, keyUsage, extKeyUsage und subjectKeyIdentifier eines Zertifikats Z.1 (Abschnitt 7.5.3), den von qcStatements die Regel QS, Nummer 4, nach der ein Verstoß `malformed` ergibt (Abschnitt 7.5.6). Wo T.6 einen Inhalt ohne Grammatik prüft (etwa den einer der vier Erweiterungen nach Z.1), prüft es jedes Element darin und steigt in jedes zusammengesetzte Element ab, gleich welcher Klasse; in der Klasse universal verlangt es dort die zusammengesetzte Form genau bei den Tag-Nummern 8, 11, 16, 17 und 29 und die primitive bei jeder anderen von 1 bis 30, und ein Element der Klasse universal mit der Tag-Nummer 0 oder einer ab 31 genügt T.6 dort nicht; in den übrigen Klassen ist dort jede Tag-Nummer in beiden Formen zulässig. Eine Grenze des Profils: Ob die ungenutzten Bits eines BIT STRING null sind (X.690 Abschnitt 11.2.1), wird nicht geprüft, ebenso wenig andere Inhaltsregeln von X.690 als die hier genannten, etwa dass NULL keinen Inhalt hat oder ein BIT STRING das Oktett der ungenutzten Bits trägt; wo eine Regel einen solchen Wert liest, prüft sie ihn selbst (etwa keyUsage nach Z.3).

#### 7.5.3 Z.1 Zertifikate

Gilt für jedes Element von `certificates` und für jedes Zertifikat, das der Prüfer übergibt.

- `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }` mit 0 ungenutzten Bits, DER nach T.6, ohne nachfolgende Bytes.
- `tbsCertificate ::= SEQUENCE { [0] EXPLICIT version INTEGER = 2, serialNumber INTEGER, signature AlgorithmIdentifier, issuer Name, validity SEQUENCE { notBefore Time, notAfter Time }, subject Name, subjectPublicKeyInfo SEQUENCE { AlgorithmIdentifier, BIT STRING }, extensions [3] EXPLICIT SEQUENCE SIZE (1..MAX) OF Extension OPTIONAL }`, ohne `issuerUniqueID` und `subjectUniqueID`. `serialNumber` ist positiv mit höchstens 21 Oktetten Inhalt; `signature` ist byte-gleich mit dem äußeren `signatureAlgorithm`; der BIT STRING in `subjectPublicKeyInfo` hat 0 ungenutzte Bits.
- `Name ::= SEQUENCE OF SET SIZE (1..MAX) OF SEQUENCE { OID, ein TLV }`; Namen werden als Bytes verglichen und nie ausgelegt.
- `Time` ist UTCTime `JJMMTThhmmssZ` (JJ < 50 steht für 20JJ, sonst für 19JJ) oder GeneralizedTime `JJJJMMTThhmmssZ`, mit gültigem Datum (Jahr `0001` bis `9999` wie in Abschnitt 2; das Jahr `0000` verletzt Z.1) und gültiger Uhrzeit.
- `Extension ::= SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }`; `critical` hat, wenn kodiert, den Inhalt `00` oder `FF`; keine `extnID` kommt zweimal vor; `extnValue` ist genau ein DER-TLV; bei einer Erweiterung, die keine Regel liest, prüft T.6 nur das äußere TLV. Bei basicConstraints (2.5.29.19), keyUsage (2.5.29.15), extKeyUsage (2.5.29.37) und subjectKeyIdentifier (2.5.29.14) wird der Inhalt von `extnValue` gelesen und MUSS DER nach T.6 sein; ein Verstoß verletzt Z.1 für dieses Zertifikat.

#### 7.5.4 Z.2 Algorithmen und Schlüssel

Gilt für den Schlüssel des Signierers und für jeden Schlüssel, der auf einem Pfad eine Signatur prüft.

- **Schlüssel:** `rsaEncryption` (Parameter NULL) mit `RSAPublicKey { n, e }`, n positiv und ungerade mit 2048 ≤ Bitlänge(n) ≤ 8192, e ungerade mit 65537 ≤ e ≤ 2^31 − 1; `id-ecPublicKey` mit namedCurve P-256, P-384 oder P-521 und unkomprimiertem Punkt `04 || X || Y` auf der Kurve; `id-Ed25519` ohne Parameter, 32 Oktette, mit kanonischem y (Abschnitt 2).
- **RSA-Signaturen:** sha256/384/512WithRSAEncryption (Parameter fehlen oder NULL) und, nur in der SignerInfo, `rsaEncryption` (Parameter fehlen oder NULL, wie bei den SHA-2-Formen) zusammen mit einem SHA-2-`digestAlgorithm`, jeweils RSASSA-PKCS1-v1_5 mit Vergleich der vollständigen kodierten Nachricht und einer Signaturlänge gleich der Oktettlänge von n; RSASSA-PSS mit genau den Parametern `{ [0] hashAlgorithm SHA-2, [1] maskGenAlgorithm MGF1 mit demselben Hash, [2] saltLength = Hashlänge, [3] trailerField fehlt oder 1 }` auf einem `rsaEncryption`-Schlüssel.
- **ECDSA-Signaturen:** ecdsa-with-SHA256/384/512 (Parameter fehlen) und, nur in der SignerInfo, `id-ecPublicKey` (Parameter fehlen, wie bei den SHA-2-Formen) zusammen mit einem SHA-2-`digestAlgorithm`; die Signatur ist `SEQUENCE { r, s }` aus minimalen positiven INTEGER mit 1 ≤ r, s < Gruppenordnung der Kurve.
- **Ed25519-Signaturen:** Ed25519 (Parameter fehlen).
- SHA-1, MD5 und alles andere liegen außerhalb des Profils, auch die Brainpool-Kurven (RFC 5639). Ein Token, dessen Signierer eine solche Kurve verwendet, ist nach Schritt 5a nicht prüfbar (`TIME_ANCHOR_UNVERIFIED`; ein Tageszeitstempel ist nicht bestätigt); ein Zertifikat eines Pfads mit einer solchen Kurve ergibt keinen Pfad nach Z.4. Die Kurve allein macht einen Zeitstempel nie mangelhaft.
- **Schlüssel und Algorithmus passen zueinander,** wenn ein RSA-Algorithmus auf einem `rsaEncryption`-Schlüssel steht, ein ECDSA-Algorithmus auf einem `id-ecPublicKey`-Schlüssel und Ed25519 auf einem `id-Ed25519`-Schlüssel. Mehr wird nicht verglichen: Ein Signaturalgorithmus mit eigenem Hash (sha256/384/512WithRSAEncryption, RSASSA-PSS, ecdsa-with-SHA256/384/512) muss in der SignerInfo nicht denselben Hash nennen wie `digestAlgorithm`, und die Kurve begrenzt den Hash nicht. Geprüft wird mit dem Hash des Signaturalgorithmus; nur bei `rsaEncryption` oder `id-ecPublicKey` als Signaturalgorithmus der SignerInfo gilt der Hash von `digestAlgorithm`.

#### 7.5.5 Z.3 bis Z.5: Erweiterungen, Pfad und Signierer

- **Z.3 Erweiterungen auf einem Pfad.** Verstanden werden, auch als kritisch markiert: basicConstraints `SEQUENCE { cA BOOLEAN OPTIONAL, pathLenConstraint INTEGER (0..MAX) OPTIONAL }`, keyUsage `BIT STRING` mit mindestens einem Inhaltsoktett, dessen erstes (die Zahl der ungenutzten Bits) 0 bis 7 ist und 0, wenn ihm kein weiteres folgt; ein Bit wie keyCertSign (Bit 5) ist gesetzt, wenn es unter den genutzten Bits liegt und 1 ist, eine 1 unter den ungenutzten Bits zählt nicht; extKeyUsage `SEQUENCE SIZE (1..MAX) OF OID`. Trägt ein Zertifikat des Pfads nameConstraints (2.5.29.30), policyMappings (2.5.29.33), policyConstraints (2.5.29.36) oder inhibitAnyPolicy (2.5.29.54), kritisch oder nicht, ist dieser Pfad nicht nutzbar; ebenso bei jeder anderen kritischen Erweiterung. Jede andere nicht kritische Erweiterung wird übergangen. Folgt basicConstraints, keyUsage oder extKeyUsage eines Zertifikats des Pfads dieser Grammatik nicht, ist dieser Pfad nicht nutzbar, auch wenn Z.4 die Erweiterung an seiner Stelle nicht auswertet (etwa keyUsage des Signierers c0).
- **Z.4 Pfad zum `genTime`.** Ein Pfad c0 (Signierer) … ck mit ck byte-gleich (DER) zur Wurzel R, k ≥ 0 (der Signierer kann selbst die Wurzel sein), k ≤ 8, kein Zertifikat zweimal, Zwischenzertifikate nur aus `certificates` des Tokens. Für i < k ist `issuer(ci)` byte-gleich mit `subject(ci+1)`, und die Signatur von ci trägt mit dem Schlüssel von ci+1 nach Z.2. Jedes cj mit j ≥ 1 trägt basicConstraints mit cA TRUE, keyUsage (falls vorhanden) mit keyCertSign und pathLenConstraint (falls vorhanden) ≥ j − 1. Für jedes Zertifikat des Pfads gilt notBefore ≤ genTime ≤ notAfter, verglichen als Zeitpunkte. c0 trägt extKeyUsage als kritisch markiert mit genau `id-kp-timeStamping` (RFC 3161 Abschnitt 2.3); jedes cj mit j ≥ 1, das extKeyUsage trägt, enthält `id-kp-timeStamping` oder `anyExtendedKeyUsage`. Nicht geprüft werden die Signatur der Wurzel selbst, keyUsage des Signierers über seine Grammatik nach Z.3 hinaus und Sperrungen. Der Pfad ist eine Existenzaussage: Eine Implementierung MUSS jeden Kandidaten bis zur Tiefe 8 durchsuchen, damit die Reihenfolge der Suche das Ergebnis nicht ändern kann.
- **Z.5 Signierer.** `sid` als IssuerAndSerialNumber passt auf die Bytes von `issuer` und den Wert von `serialNumber` eines Zertifikats, als `[0]` auf den Schlüsselbezeichner seiner Erweiterung subjectKeyIdentifier (den Inhalt des OCTET STRING in ihrem `extnValue`); genau ein Zertifikat aus `certificates` passt (gleiche Bytes zählen einmal). Signiert sind die DER-Bytes von `signedAttrs` mit dem Tag `0x31` statt `0xA0` (RFC 5652 Abschnitt 5.4).

#### 7.5.6 Z.6 ESS-Bindung und Regel QS

- **Z.6 Bindung des Signiererzertifikats.** Die signierten Attribute enthalten mindestens eines von signingCertificate (1.2.840.113549.1.9.16.2.12; in `certs[0]` ist `certHash` der SHA-1-Wert des DER des Signiererzertifikats) und signingCertificateV2 (1.2.840.113549.1.9.16.2.47; in `certs[0]` ist `hashAlgorithm` SHA-256, wenn es fehlt, sonst SHA-256, SHA-384 oder SHA-512, und `certHash` dieser Hash des DER des Signiererzertifikats); jedes vorhandene der beiden erfüllt diese Regel, und `issuerSerial` in `certs[0]` passt, falls vorhanden, auf den Signierer. Den `hashAlgorithm` eines ESSCertIDv2 erkennt der Verifier allein an der OID; seine Parameter sind ein TLV oder fehlen, T.6 prüft von ihnen nur das äußere TLV, und ob sie fehlen, NULL oder ein anderer Wert sind, ändert nichts. `issuerSerial` passt auf den Signierer, wenn sein `serialNumber` gleich dem des Signierers ist und der Name in einem `directoryName` `[4]` unter seinen GeneralNames byte-gleich mit dem `issuer` des Signierers ist. Ein Token mit beiden Attributen ist zulässig. Jedes der beiden Attribute steht höchstens einmal in den signierten Attributen und hat höchstens einen Wert (mindestens einen verlangt schon T.4), ein SigningCertificate beziehungsweise SigningCertificateV2 in DER nach T.6 mit mindestens einem Element in `certs`; sonst ist Z.6 verletzt (nie Grammatik T, nie Schritt 5b). Gelesen wird `SigningCertificate ::= SEQUENCE { certs SEQUENCE OF ESSCertID, policies SEQUENCE OPTIONAL }` mit `ESSCertID ::= SEQUENCE { certHash OCTET STRING, issuerSerial IssuerSerial OPTIONAL }`, bei signingCertificateV2 dasselbe mit `ESSCertIDv2 ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier OPTIONAL, certHash OCTET STRING, issuerSerial IssuerSerial OPTIONAL }`, und `IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber INTEGER }`. Jedes Element von `certs` folgt dieser Grammatik, auch wo nur `certs[0]` verglichen wird; ein `issuerSerial` in einem späteren Element wird nicht mit dem Signierer verglichen. `GeneralNames` ist eine SEQUENCE aus mindestens einem TLV: Ein Element mit dem Identifier-Oktett `A4` (directoryName) enthält genau einen Name nach Z.1, von jedem anderen Element prüft T.6 nur das äußere TLV. `policies` liest keine Regel; T.6 prüft davon nur das äußere TLV. Ein `[4]` an anderer Stelle, etwa im Wert eines otherName oder in `policies`, ist kein directoryName. Weicht ein vorhandenes Attribut von diesem Aufbau ab, auch nur in einem Element von `certs` nach dem ersten, ist Z.6 verletzt. Ein vorhandenes signingCertificateV2, dessen `hashAlgorithm` ein anderer als SHA-256, SHA-384 oder SHA-512 ist, wird nicht verglichen und verletzt Z.6 dadurch nicht. Verletzt das Token Z.6 sonst nicht (Anzahl, DER und Aufbau wie oben, in jedem Element von `certs`; jedes übrige vorhandene Attribut nennt den Signierer, und `issuerSerial` in `certs[0]` passt in jedem vorhandenen Attribut), ist Z.6 nicht prüfbar: Ein Tageszeitstempel ist dann nicht bestätigt, Bedingung (4) erhält `signature_not_checkable`; mangelhaft ist er dadurch nie. SHA-1 dient hier als Kennung, nicht als Abdruck: Eine Fälschung bräuchte ein zweites Urbild zu einem Zertifikat, das die Stelle selbst ausgestellt hat, und RFC 3161 Abschnitt 2.4.1 verlangt das Attribut. Z.6 ist Bedingung für einen bestätigten Tageszeitstempel (Abschnitt 7.4.6) und für Bedingung (4) der Beweisstufe (Abschnitt 10.9); den Befund eines TIME_ANCHOR ändert sie nicht.
- **Regel QS (Angabe „qualifiziert“ im TSTInfo).** Eingabe ist der Bestandteil `extensions` `[1]` des TSTInfo (T.5) oder keiner. Die Regel ergibt nie einen Befund und ist nie Teil der Schritte 1 bis 6.
  1. Kein `[1]`: `absent` (nutzbar).
  2. Der Inhalt von `[1]` ist eine oder mehrere `Extension` nach Z.1, je DER nach T.6 ohne nachfolgende Bytes. `critical` hat, wenn kodiert, genau ein Inhaltsoktett `00` oder `FF`; ein ausdrücklich kodiertes `00` wird angenommen (es verletzt X.690 Abschnitt 11.5, kommt aber in qualifizierten Zeitstempeln vor). Jedes andere Inhaltsoktett, ein leeres `[1]`, eine doppelte `extnID` oder jede andere Abweichung: Die Erweiterungen sind **unbrauchbar**. Vom `extnValue` einer Erweiterung prüft diese Nummer nur das äußere TLV nach T.6; ein Inhalt des `extnValue` von `1.3.6.1.5.5.7.1.3`, der nicht DER ist, ist nach Nummer 4 `malformed`, nicht unbrauchbar.
  3. Eine Erweiterung mit `critical` = `FF`, deren `extnID` nicht `1.3.6.1.5.5.7.1.3` ist: unbrauchbar, denn ihre Bedeutung ist unbekannt.
  4. Keine Erweiterung `1.3.6.1.5.5.7.1.3`: `absent`. Sonst MUSS ihr `extnValue` genau ein DER-`SEQUENCE OF QCStatement` sein, jedes `QCStatement ::= SEQUENCE { statementId OID, statementInfo ANY OPTIONAL }` mit einem oder zwei Elementen, ohne nachfolgende Bytes; sonst `malformed`. `present` genau dann, wenn eine `statementId` `0.4.0.19422.1.1` ist (DER `06 07 04 00 81 97 5E 01 01`), sonst `absent`. Die Kennung ist `esi4-qtstStatement-1` aus ETSI EN 319 422; die Durchführungsverordnung (EU) 2025/1929 wendet diese Norm in der Fassung V1.1.1 mit Anpassungen auf qualifizierte Zeitstempel an. Rechtsgrundlage neben ETSI EN 319 422 ist die Durchführungsverordnung (EU) 2025/1929, Anhang (Anpassung zu EN 319 422, Nr. 9.1): qcStatements mit esi4-qtstStatement-1, nicht kritisch. Ob eine Stelle qualifiziert ist, sagt die Kennung nicht; das zeigt nur die Vertrauensliste, aus der der Prüfer die Datei `ledger-tsa-qualifiziert/1` ableitet (Abschnitt 10.8). `statementInfo` wird nicht ausgewertet; von ihm wird nur das äußere TLV gelesen (Bezeichner nach X.690, kürzeste bestimmte Länge), sein Inhalt muss kein DER sein.

  Eine Suche nach Bytes im TSTInfo DARF NICHT verwendet werden: Die Nonce ist ein INTEGER, den der Anfragende wählt, und kann diese neun Bytes tragen.

#### 7.5.7 Zuordnung der Ergebnisse und Zwecke der Wurzeln

| Ergebnis | TIME_ANCHOR (7.3) | Tageszeitstempel (7.4.6) | Beweisstufe (10.9) |
|---|---|---|---|
| B64, Größe oder Grammatik T verletzt | `TIME_ANCHOR_INVALID` (Schritt 2) | mangelhaft | keine Anrechnung |
| Abdruck falsch | `TIME_ANCHOR_INVALID` (Schritt 4) | mangelhaft (Abdruck ≠ `H(UTF-8(statement_jcs))`) | keine Anrechnung |
| Schritt 5 nicht ausführbar (5a) | `TIME_ANCHOR_UNVERIFIED` | nicht bestätigt | `signature_not_checkable` |
| Schritt 5 ausgeführt und gescheitert (5b) | `TIME_ANCHOR_INVALID` | mangelhaft | keine Anrechnung |
| Z.6 verletzt | keine Wirkung auf den Exit-Code | mangelhaft | `signing_certificate_not_bound` (nur Bedingung 4); für Bedingung 7 bildet ein mangelhafter Tageszeitstempel kein Tripel |
| Z.6 nicht prüfbar (Hash eines signingCertificateV2 außerhalb von SHA-256, SHA-384, SHA-512) | keine Wirkung auf den Exit-Code | nicht bestätigt | `signature_not_checkable` (nur Bedingung 4) |
| kein Pfad nach Z.3 und Z.4 zu einer Wurzel des Zwecks | `TIME_ANCHOR_UNVERIFIED` | nicht bestätigt | `not_chained_to_auditor_root`, `not_chained_to_qualified_root` oder `not_chained_to_qualified_log_root` |
| SPKI des Signierers oder der Wurzel in `published_test_keys` | keine Wirkung auf den Exit-Code | nicht bestätigt | `published_test_key` |
| Erweiterungen nach Regel QS unbrauchbar, `malformed` oder `absent` | keine Wirkung | keine Wirkung | Bedingung 1: `token_extensions_unusable`, wenn unbrauchbar; Bedingungen 4 und 7: `token_extensions_unusable`, `qualified_statement_malformed` oder `no_qualified_statement` |

Für einen Tageszeitstempel werden die Zeilen in der Reihenfolge der Tabelle geprüft; die oberste zutreffende entscheidet. Trifft keine zu, ist er **bestätigt**. Die Zeile zu `published_test_keys` trifft zu, wenn der SPKI des Signierers dort steht oder wenn jede Wurzel dort steht, zu der ein Pfad nach Z.3 und Z.4 besteht; führt ein Pfad zu einer Wurzel, die dort nicht steht, wird der Zeitstempel nach den folgenden Zeilen beurteilt. Für einen TIME_ANCHOR gilt die Reihenfolge der Schritte aus Abschnitt 7.3.

**Zwecke der Wurzeln.** Jedes Zertifikat, das der Prüfer als Wurzel für Zeitstempel übergibt, steht mit seinem SPKI-SHA-256-Wert und seinen Zwecken in einer Tabelle (Abschnitt 10.8):

- `chain`: Zeitzeugen der Kette (Schritt 6 in Abschnitt 7.3) und Bedingung (1) der Beweisstufe;
- `qualified`: Bedingung (4) der Beweisstufe, nur innerhalb des Zeitraums, für den der Prüfer die Wurzel als qualifiziert benennt; eine solche Wurzel trägt zugleich den Zweck `chain`; trägt dasselbe Zertifikat auch den Zweck `log`, zählt es im selben Zeitraum für Bedingung (7);
- `log`: Zeitstempel der Tageseinträge (Abschnitt 7.4.6) und, zusammen mit dem Zweck `qualified` an derselben Wurzel, Bedingung (7) der Beweisstufe.

Die Datei der qualifizierten Wurzeln gibt den Zweck `log` nie; für Bedingung (7) übergibt der Prüfer dasselbe Zertifikat auch als Wurzel für Zeitstempel des Protokolls (Abschnitt 10.8).

Eine Wurzel zählt nur für die Zwecke, für die der Prüfer sie übergibt; eine Wurzel für das Protokoll bestätigt nie einen Zeitzeugen der Kette und umgekehrt. Der Wurzelspeicher des Systems zählt für keinen Zweck, und kein Verifier trägt eine Wurzel einer Zeitstempelstelle eingebaut.

**Veröffentlichte Testschlüssel.** Die Registry führt unter `published_test_keys` Schlüssel, deren privater Teil veröffentlicht ist oder sich aus veröffentlichten Werten ableiten lässt; die Liste ändert sich nur mit einer Fassung der Spezifikation. Sie hat drei Arten von Einträgen:

- die SPKI-SHA-256-Werte von Schlüsseln einer Zeitstempelstelle, etwa der Test-Zeitstempelstelle des Testkorpus, `0ee470ade299184118b50cff3ac1d7f671a8eb98b0097a230df0912db863aac1`. Ein Signierer oder eine Wurzel mit einem solchen Schlüssel bestätigt keinen Zeitstempel und wird für keine Bedingung der Beweisstufe angerechnet (Zeile oben);
- ab Fassung 1.10 die Publikeys (hex64) der Ed25519-Testschlüssel des Herstellers im Testkorpus: Herstellerwurzel, Gegenzeichnungsschlüssel, Bescheidschlüssel und der Schlüssel des Update-Manifests (Referenzwerte in Abschnitt 10.7.2) sowie die Protokollschlüssel des Testprotokolls `ledger-testprotokoll-1`, `vendor-log-test-001` und der Reserveschlüssel `vendor-log-test-002` (Abschnitt 7.4.7), und ab der Erweiterung der Fassung 1.10 der Transparenzschlüssel `vendor-transparency-test-001` (Abschnitt 7.7.10). Ein solcher Schlüssel zählt nach den Regeln, nach denen der Prüfer ihn übergibt oder eine Liste ihn belegt, damit das Testkorpus die Bedingungen zeigen kann, die auf Schlüsseln des Herstellers beruhen; beruht eine Bedingung der Beweisstufe auf ihm, gibt der Bericht den Hinweis `published_test_key_credited` (Abschnitt 10.9.6).
- ab Fassung 1.10 die Art `ml_dsa_87`: der SHA-256-Wert der 2592 Bytes des Publikeys jedes Testschlüssels nach ML-DSA-87 des Herstellers im Testkorpus (Abschnitt 7.4.5a), als hex64. Für einen solchen Schlüssel gilt dasselbe wie für die Ed25519-Testschlüssel des Herstellers, auch der Hinweis `published_test_key_credited`.

**Zeitstempelstelle des Testkorpus mit verworfenen Schlüsseln.** Das Testkorpus DARF eine Zeitstempelstelle enthalten, deren Schlüssel sich nicht aus veröffentlichten Werten ableiten lassen: Ihre Schlüssel entstehen in einem Lauf des Vektor-Generators aus einem kryptographisch sicheren Zufallsgenerator, dienen nur in diesem Lauf dazu, die Token des Korpus auszustellen, und werden nirgends geschrieben. Wurzel und Zertifikate dieser Stelle stehen im Korpus; ihre Schlüssel stehen nicht in `published_test_keys`. Sie zählt nur, wo die Prüfumgebung eines Vektors ihre Wurzel übergibt (`pruefer_<name>.json`); ein Prüfer außerhalb des Testkorpus hat keinen Grund, sie zu übergeben. Ihre Token lassen sich nicht erneut ausstellen: Der Generator führt sie als eingefrorene Eingaben und bricht ab, wenn eine neu erzeugte Aussage nicht mehr zu einem eingefrorenen Token passt. Neue Token dieser Art verlangen eine neue Stelle mit neuer Wurzel und neuen Pins. Wer den Generator ausgeführt hat, hätte den Schlüssel behalten können; deshalb ist eine solche Wurzel nie eine Wurzel eines Prüfers.

### 7.6 Künftige Ankertypen

Weitere Ankertypen sind denkbar. Ab Fassung 1.10 gilt für sie: Ein Ankertyp in der Kette ist ein neuer Eintragstyp und fällt unter Regel 2 von Abschnitt 10.6; ein Ankertyp außerhalb der Kette ist eine Angabe des Prüfers (Abschnitt 10.8), die ein älterer Verifier nicht anbietet. Ein Verifier ab Fassung 1.10, dem sie unbekannt ist, beantwortet sie als unbrauchbaren Aufruf, auch in der Browser-Fassung, und bewertet das Paket nie anders. Wie Verifier der Fassung 1.9 unbekannte Angaben behandeln, nennt Abschnitt 10.6.

### 7.7 COSE Receipts

Ab Fassung 1.11.

**Fassung 1.10.** Dieser Abschnitt, Schritt L3a (Abschnitt 7.4.10), Schritt K (Abschnitt 7.7.6), die Rolle `transparency` (Abschnitt 10.7), die Angabe `--vendor-transparency-key` (Abschnitt 10.8), die Klassen `COSE_RECEIPT_DEFECTIVE` und `COSE_RECEIPT_MISMATCH`, das Berichtsobjekt `cose_receipts` und `vendor_log.day_receipts` (Abschnitt 10.10.2) und die Route der Receipts (Heartbeat-Spezifikation §9.9) gelten ab Fassung 1.11; sie stehen hier als Entwurf. Ein Verifier 1.10 führt diese Schritte nicht aus, kennt die Rolle `transparency` nicht (Hinweis `unknown_role` wie bei jeder unbekannten Rolle) und nimmt `--vendor-transparency-key` nicht an (unbekannter Schalter, Exit 3). Was er mit `day_receipts` und `cose_receipts` eines Auszugs `/2` tut, sagt Abschnitt 7.4.8a: zählen, nicht prüfen. In Fassung 1.10 bleiben `log_uri` (Abschnitt 7.4.7a) und die Grammatik des Auszugs `/2`.

Der Hersteller KANN seine Gegensignaturen (Abschnitt 7.1) und die Tage seines Herstellerprotokolls (Abschnitt 7.4) zusätzlich als COSE Receipts nach RFC 9942 ausgeben: als COSE_Sign1 nach RFC 9052 in deterministischem CBOR nach RFC 8949, Profil C1 je Gegensignatur und Profil C2 je Tag. Beide signiert ein Schlüssel der Rolle `transparency` (Transparenzschlüssel, Abschnitt 10.7.3), der nichts anderes signiert. Ein COSE-Objekt ist eine Angabe des Prüfers in einem Auszug `ledger-protokollauszug/2` (Abschnitt 7.4.8a); es steht nie im Paket, in der Kette, in einer Quittung oder in einem Tageseintrag, und es ändert keine Bytes, die eine bestehende Signatur oder ein bestehender Hash deckt. COSE-Objekte ändern die Beweisstufe nicht, außer über einen Widerspruch nach Schritt L3a: Ein C2, das vom Tageseintrag abweicht (Abschnitt 7.4.10, Schritt L3a, D7), ist ein Befund `VENDOR_LOG_CONTRADICTION` und zählt wie jeder andere für die Bedingungen (5) und (7) (Abschnitt 10.9.4); ein C1 wirkt nie auf die Beweisstufe, und durch kein COSE-Objekt liegt eine Bedingung vor. In Auszügen und an den Orten stehen die Objekte in Ablageform ohne Beweis (Abschnitt 7.7.2). Nach außen heißen die Objekte „COSE Receipts nach RFC 9942“; ob sie allen Regeln der Architektur nach RFC 9943 folgen, sagt diese Spezifikation nicht (kein Beleg durch LEDGER).

#### 7.7.1 CBOR-Grammatik C

Jedes COSE-Objekt dieses Abschnitts und der Inhalt seines geschützten Kopfs folgen der Grammatik C. Ein Verstoß macht das Objekt mangelhaft (Schritt K1; Abschnitt 7.4.10, Schritt L3a, D1); er ist nie Exit 3.

- **C.1 Typen.** Erlaubt sind nur: Major Type 0 (ganze Zahl von 0 bis 2^53−1), Major Type 1 (ganze Zahl von −2^53 bis −1), Major Type 2 (Bytefolge), Major Type 3 (Zeichenkette in gültigem UTF-8), Major Type 4 (Array), Major Type 5 (Map), Tag 18 (Major Type 6) nur als äußerstes Element eines COSE-Objekts und nie im Inhalt des geschützten Kopfs, und der einfache Wert `null` (0xF6). Nicht erlaubt sind Gleitkommazahlen, unbestimmte Längen, andere Tags, andere einfache Werte (auch `false` und `true`), eine Schachtelungstiefe über 8 (das äußerste Element hat die Tiefe 1, jedes Datenelement in einem Array oder einer Map, auch eine Zahl, eine Bytefolge, eine Zeichenkette oder `null`, hat die Tiefe des Arrays oder der Map plus 1; acht geschachtelte Arrays mit einer Zahl darin haben die Tiefe 9) und Bytes nach dem äußersten Element.
- **C.2 Deterministische Kodierung** nach RFC 8949 Abschnitt 4.2.1: jedes Argument (Wert, Länge, Zahl der Elemente) in der kürzesten Form; Schlüssel einer Map nur vom Typ `int` (Major Type 0 oder 1) oder `tstr`, paarweise verschieden und streng aufsteigend geordnet nach den Bytes ihrer Kodierung (bytewise lexikographisch).
- **C.3 Prüfregel.** Ein Verifier liest das Objekt nach C.1 und kodiert es nach C.2 neu; weichen die Bytes ab, ist C.2 verletzt. Dasselbe gilt für den Inhalt des geschützten Kopfs (`bstr .cbor`), der selbst ein vollständiges Objekt nach C.1 ist. Ebenso für jeden Beweis `bstr .cbor einschluss` der Vorlageform (Abschnitt 7.7.4). Tag 18 zählt für die Schachtelungstiefe nicht; das Array darin hat die Tiefe 1. Doppelte Schlüssel einer Map verletzen C.2 auch dann, wenn ein Leser sie zusammenfasst.

Für die Labels der Profile ergibt C.2 die kodierte Reihenfolge 1, 4, 15, 16, 395, −65537, −65538 (Kodierungen `01`, `04`, `0F`, `10`, `19 01 8B`, `3A 00 01 00 00`, `3A 00 01 00 01`) und in den CWT-Claims die Reihenfolge 1, 2.

#### 7.7.2 COSE_Sign1-Profil

Ein COSE-Objekt hat diese Form (CDDL nach RFC 8610; die Map des geschützten Kopfs legt das Profil fest, Abschnitte 7.7.3 und 7.7.4):

```
ledger-cose = #6.18([
  protected:   bstr .cbor ledger-protected,   ; Map des Profils C1 oder C2, geschlossen
  unprotected: {} / vorlage-kopf,             ; Ablageform: genau die leere Map 0xA0
  payload:     nil,                           ; abgetrennt: die 32 Bytes R des Profils
  signature:   bstr .size 64                  ; Ed25519
])
```

- **`alg` (Label 1)** ist `-19` (Ed25519, RFC 9864). Jeder andere Wert, auch `-8` (EdDSA, nach RFC 9864 abgekündigt), verletzt das Profil. Ein weiteres Verfahren kann eine spätere Fassung über `alg` zulassen, ohne neues Profil.
- **`kid` (Label 4)** ist eine Bytefolge mit `UTF-8(key_id)` eines Transparenzschlüssels; `key_id` folgt dem Typ key-id (Abschnitt 2). `kid` steht im geschützten Kopf und ist Pflicht.
- **CWT-Claims (Label 15, RFC 9597)** sind eine Map mit genau den Claims `iss` (1) und `sub` (2), beide Zeichenketten: `iss` ist `log_uri` der Protokollschlüsselliste `/2` (Abschnitt 7.4.7a), `sub` nennt den Gegenstand nach dem Profil. `iat`, `exp`, `nbf` und jeder andere Claim verletzen das Profil.
- **`typ` (Label 16, RFC 9596)** ist die Zeichenkette des Medientyps des Profils: `application/ledger-countersignature+cose` (C1) oder `application/ledger-day-receipt+cose` (C2). Die Medientypen sind nicht registriert.
- **`vds` (Label 395, RFC 9942)** ist `1` (`RFC9162_SHA256`): Der Baum ist ein Merkle-Baum nach Abschnitt 5, also nach RFC 9162 Abschnitt 2.1 mit SHA-256.
- **Private Labels** (RFC 9052 Abschnitt 3.1, Werte unter −65536): `-65537` ist `tree_size`, eine ganze Zahl ohne Vorzeichen (Major Type 0); `-65538` ist `server_ts`, eine Zeichenkette, nur in C1. Beide stehen nicht in `crit`: Ein allgemeiner COSE-Prüfer, der sie nicht kennt, liest das Objekt und übergeht sie (Abschnitt 7.7.8).
- **Nicht vorhanden** sind `crit` (2), `content type` (3), `x5chain` (33), `receipts` (394), `vdp` (396) und jedes andere Label im geschützten Kopf. Ein Label im ungeschützten Kopf der Ablageform verletzt das Profil.
- **Nutzlast** ist `nil` (0xF6): Die 32 Bytes R, die die Signatur deckt, stehen nicht im Objekt; der Prüfer bildet sie selbst (Schritt K4; Abschnitt 7.4.10, Schritt L3a, D5). Eine angehängte Nutzlast verletzt das Profil.
- **Größe:** Ein Objekt in Ablageform umfasst höchstens 1024 Bytes, in B64 höchstens 1368 Zeichen; ein Objekt in Vorlageform höchstens 4096 Bytes. Ein C1 mit `kid` aus 64 Zeichen, `tree_size` 2^53−1 und einer `iss` aus L ≥ 256 Zeichen umfasst 280 + L Bytes; mit `log_uri` aus höchstens 512 Zeichen (Abschnitt 7.4.7a) passt jedes Objekt in 1024 Bytes.
- **Werte, die zum Profil gehören** (Verstoß: Profil verletzt, Schritt K1 beziehungsweise Abschnitt 7.4.10, Schritt L3a, D1): `kid` umfasst 1 bis 64 Bytes, die eine Zeichenkette nach key-id ergeben; `iss` ist eine absolute URI nach dem Muster und der Länge von `log_uri` (Abschnitt 7.4.7a); `sub` ist bei C1 eine uuid in Kleinbuchstaben, bei C2 ein Wert vom Typ date im Protokollbereich; −65537 liegt im Bereich des Profils; −65538 hat genau die Form `JJJJ-MM-TTThh:mm:ss.sssZ` mit existierendem Datum (Typ rfc3339, Abschnitt 2). Ob `kid` einen Schlüssel aus T nennt, ob `iss` gleich U ist und ob `sub` gleich C oder dem Tag des Tagesobjekts ist, gehört nicht zum Profil; das prüfen erst die Schritte K2 und K3 beziehungsweise D2 bis D4 und zählen es eigens.

**Signierte Bytes** (RFC 9052 Abschnitt 4.4: Sig_structure mit dem Kontext `Signature1`, leerem `external_aad` und der abgetrennten Nutzlast R). Mit P = Inhalt der Bytefolge `protected`, so wie empfangen, ist

```
Sig_structure = 0x84 || 0x6A || "Signature1" || bstr(P) || 0x40 || 0x58 0x20 || R
```

`0x84` beginnt ein Array aus vier Elementen, `0x6A "Signature1"` ist die Zeichenkette aus 10 Bytes, `bstr(P)` ist P mit dem Kopf der Bytefolge in kürzester Form (`0x58 n` für 24 ≤ n ≤ 255, `0x59` und zwei Bytes für 256 ≤ n ≤ 65 535), `0x40` ist die leere Bytefolge `external_aad`, und `0x58 0x20 || R` ist die Bytefolge der 32 Bytes R. Die Ed25519-Signatur über die Sig_structure wird nach Abschnitt 2 geprüft (ohne Kofaktor, ohne Prehash, ohne Kontext). Eine Sig_structure beginnt mit dem Byte 0x84, jeder JCS-Signaturgegenstand dieser Spezifikation mit `{` (0x7B); so gleicht keine Sig_structure dem Signaturgegenstand eines anderen Objekts (Abschnitt 10.7.3).

**Ablageform und Vorlageform.** Die **Ablageform** hat den leeren ungeschützten Kopf (0xA0); in ihr stehen die Objekte in Auszügen `/2` und in Tagesobjekten `/2` an den Veröffentlichungsorten (Heartbeat-Spezifikation §9.9). Die **Vorlageform** trägt im ungeschützten Kopf genau einen Einschlussbeweis nach RFC 9942 Abschnitt 5.2 (`vorlage-kopf`, Abschnitt 7.7.4) und gleicht sonst der Ablageform, mit demselben geschützten Kopf und derselben Signatur, denn der ungeschützte Kopf steht nicht in der Sig_structure. Der Hersteller gibt eine Vorlageform nur für C2 und nur über den Metadatenserver aus (Heartbeat-Spezifikation §9.9). Kein Verifier liest eine Vorlageform; ein Objekt mit nicht leerem ungeschütztem Kopf in einem Auszug verletzt das Profil. Erst die Vorlageform ist ein Receipt nach RFC 9942 Abschnitt 5.2; die Ablageform ist dessen signierter Teil ohne Beweis, denn RFC 9942 verlangt `vdp` (396). Jeder bildet aus ihr ein Receipt, indem er einen Beweis in den ungeschützten Kopf setzt. Die Bezeichnung „COSE Receipts nach RFC 9942“ bezieht sich auf die Vorlageform.

#### 7.7.3 Profil C1: Gegensignatur

C1 ist die Aussage einer Quittung (Abschnitt 7.1) in COSE unter einem Transparenzschlüssel: `chain_id`, `tree_size`, `merkle_root` und `server_ts` derselben Gegensignatur.

```
c1-protected = {
  1      => -19,                                     ; alg Ed25519
  4      => bstr,                                    ; kid = UTF-8(key_id), Rolle transparency
  15     => { 1 => tstr,                             ; iss = log_uri der Liste /2
              2 => tstr },                           ; sub = chain_id (uuid, Kleinbuchstaben)
  16     => "application/ledger-countersignature+cose",
  395    => 1,                                       ; vds RFC9162_SHA256
  -65537 => uint,                                    ; tree_size, 1 … 2^53−1
  -65538 => tstr                                     ; server_ts, JJJJ-MM-TTThh:mm:ss.sssZ
}
R = Bytes(merkle_root), 32 Bytes: die Wurzel der Kette zur Größe tree_size (Abschnitt 5)
```

- `sub` ist `chain_id` der Gegensignatur, eine Zeichenkette vom Typ uuid (Abschnitt 2). `tree_size` (−65537) und `server_ts` (−65538) sind die Werte der Quittung; `server_ts` steht Zeichen für Zeichen wie in der Quittung, genau in der Form `JJJJ-MM-TTThh:mm:ss.sssZ` (24 Zeichen, Typ rfc3339).
- Kodierte Reihenfolge der Schlüssel: 1, 4, 15, 16, 395, −65537, −65538.
- **Kandidat nach RFC 9942** ist ein Eintrag der Kette: die 32 Bytes seines `entry_hash`, mit dem Blatt-Hash `SHA-256(0x00 || Bytes(entry_hash))` wie in Abschnitt 5. Der Hersteller gibt für C1 keine Vorlageform aus, denn er kennt die Einträge nicht. Wer das Paket hält, KANN eine bilden, indem er einen Einschlussbeweis für einen Eintrag nach der Form `vorlage-kopf` (Abschnitt 7.7.4) in den ungeschützten Kopf setzt, mit `tree_size` gleich dem Wert von −65537; die Signatur bleibt dieselbe.
- C1 ist keine Verankerung: Es hebt `NO_ANCHOR` nicht auf, belegt weder eine Quittung noch einen Gegenzeichnungsschlüssel (Abschnitt 7.1), ist keine erwartete Wurzel (Abschnitt 10.8) und zählt für keine Bedingung der Beweisstufe (Abschnitt 10.9).

#### 7.7.4 Profil C2: Tag des Herstellerprotokolls

C2 ist die Aussage eines Tageseintrags über seinen Tagesbaum (Abschnitte 7.4.4, 7.4.5) in COSE unter einem Transparenzschlüssel: Tag, Baumgröße und Wurzel.

```
c2-protected = {
  1      => -19,
  4      => bstr,                                    ; kid, Rolle transparency
  15     => { 1 => tstr,                             ; iss = log_uri der Liste /2
              2 => tstr },                           ; sub = Tag d, JJJJ-MM-TT
  16     => "application/ledger-day-receipt+cose",
  395    => 1,
  -65537 => uint                                     ; tree_size, 0 … 2^53−1, gleich tree_size des Tageseintrags
}
R = Bytes(root) des Tageseintrags zum Tag d, 32 Bytes: root(d) (Abschnitt 7.4.4)
```

- `sub` ist der Tag d, eine Zeichenkette vom Typ date im Protokollbereich (Abschnitt 2). Ein Label −65538 verletzt das Profil.
- Kodierte Reihenfolge der Schlüssel: 1, 4, 15, 16, 395, −65537.
- Tag und Baumgröße stehen im geschützten Kopf, weil RFC 9942 die Baumgröße nur im ungeschützten Beweis führt und Abschnitt 5 die Größe aus einer signierten Aussage verlangt. `prev_hash`, `first_day` und `server_ts` des Tageseintrags stehen nicht in C2: Ein neuer Abschluss desselben Tages (Heartbeat-Spezifikation §9.9, Abschluss eines Tages, Punkt 3) hat dieselbe Wurzel und dieselbe Größe und damit dasselbe C2.
- **Kandidat nach RFC 9942** ist ein Blatt des Tagesbaums, die Bytes eines Kettentag-Blatts oder eines Füllers (Abschnitte 7.4.3, 7.4.4), mit dem Blatt-Hash `SHA-256(0x00 || Blattdaten)` (Abschnitt 5). C2 trägt kein Blatt; wer prüft, bildet es selbst, ein Kettentag-Blatt aus den Blättern seiner Kette am Tag d und ihrer Position (Abschnitte 7.4.2, 7.4.3), wie beim Nachweis `present` eines Auszugs.
- Ein Tag mit `tree_size` = 0 hat ein C2 mit R = `SHA-256("")`; ein Tag mit `tree_size` 0 oder 1 hat keine Vorlageform, denn RFC 9942 verlangt mindestens einen Eintrag im Pfad. Nach der Größenregel (Abschnitt 7.4.4) kommt keiner dieser Tage vor.

**Vorlageform von C2** (RFC 9942 Abschnitt 5.2, Inklusion; nur vom Metadatenserver, Heartbeat-Spezifikation §9.9):

```
vorlage-kopf = { 396 => { -1 => [ bstr .cbor einschluss ] } }   ; vdp, genau ein Beweis
einschluss   = [ tree_size: uint,                               ; gleich dem Wert von −65537
                 leaf_index: uint,                              ; 0 … tree_size − 1
                 inclusion_path: [ 1*64 bstr .size 32 ] ]       ; Pfad nach RFC 9162 Abschnitt 2.1.3
```

- Genau ein Beweis, kein Konsistenzbeweis (Label −2): Die Tage sind über `prev_hash` verkettet und bilden keinen wachsenden Baum. `tree_size` im Beweis gleicht dem Wert von −65537; die Größe für die Prüfung kommt aus dem geschützten Kopf, nie aus dem Beweis (Abschnitt 5). Der Pfad umfasst 1 bis 64 Einträge, das Objekt höchstens 4096 Bytes, und es folgt Grammatik C.
- Ohne Angabe einer Kette trägt die Vorlageform den Beweis für das Blatt mit Index 0; er verrät nicht, ob dieses Blatt ein Kettentag-Blatt oder ein Füller ist, denn das Blatt mit Index 0 steht in den öffentlichen Tagesblättern (Abschnitt 7.4.9) wie jedes andere. Mit der Angabe einer `chain_id` trägt sie den Beweis für das Kettentag-Blatt dieser Kette am Tag d. Wer ein anderes Blatt prüft, ersetzt den ungeschützten Kopf durch einen Beweis aus den Tagesblättern; die Signatur bleibt gültig.
- Der Beweis entspricht dem Nachweis `present` eines Auszugs (Abschnitt 7.4.8) ohne die Wurzeln der Kette; einen Abwesenheitsbeweis kennt RFC 9942 nicht.

#### 7.7.5 Transparenzschlüssel und Gültigkeit

**T** sind die belegten Transparenzschlüssel: die Anheftungen als Transparenzschlüssel (`--vendor-transparency-key`, Abschnitt 10.8), die nach Abschnitt 10.7.4, Schritt R3 (d) nicht entfallen, und die Einträge der wirksamen Rollenliste Q mit der Rolle `transparency` (Abschnitt 10.7.4, Schritt R4); eine Anheftung hat für ihre `key_id` Vorrang, und ein Eintrag von Q mit derselben `key_id` gehört dann nicht zu T. **U** ist `log_uri` der Liste P2 (Abschnitt 7.4.10, Schritt L1, Nummer 6); ohne P2 gibt es kein U.

- Ein Objekt nennt mit `kid` einen Schlüssel aus T, wenn `kid` die UTF-8-Bytes seiner `key_id` sind; geprüft wird gegen den Publikey der Anheftung oder des Eintrags von Q.
- **Gültigkeit für C1:** Ein angehefteter Schlüssel gilt immer. Ein Eintrag von Q gilt, wenn `gueltig_ab` ≤ `server_ts` < Ende, mit Ende gleich dem früheren der Werte `gueltig_bis` und `widerrufen_ab`, soweit vorhanden; `server_ts` ist der Wert von −65538, gelesen und verglichen nach Abschnitt 10.7.1 (Zeitpunkte, Nanosekunden).
- **Gültigkeit für C2 zum Tag d:** Ein angehefteter Schlüssel gilt immer. Ein Eintrag von Q gilt, wenn er kein Ende hat oder sein Ende, gelesen nach Abschnitt 10.7.1, streng nach end(d) + W liegt, verglichen auf Nanosekunden (W = 172 800 000 ms, Abschnitte 2, 7.4.6); ein Ende gleich end(d) + W gilt nicht. `gueltig_ab` wird gegen C2 nicht geprüft, wie bei Tageseinträgen (Abschnitt 7.4.10, Schritt L2 (e)). Der Hersteller stellt C2 innerhalb von W nach end(d) aus (Heartbeat-Spezifikation §9.9).
- Ein Objekt unter einem Schlüssel, der nicht gilt, zählt als `key_not_valid` und ergibt keinen Befund.
- **`iss`.** Ein Objekt, dessen `iss` nicht Zeichen für Zeichen U ist, und jedes Objekt, wenn es kein U gibt, zählt als `other_log` und ergibt keinen Befund: Es ist keine Aussage über dieses Protokoll, oder der Verifier kann es keinem Protokoll zuordnen.

#### 7.7.6 Schritt K: COSE-Gegensignaturen

Schritt K läuft in Stufe 5 nach dem Herstellerprotokoll (Abschnitt 10.5, Schritt 6a), mit oder ohne Protokollschlüssel; ohne Element in `cose_receipts` eines Auszugs `/2` ist der Status `not_supplied`, und K prüft nichts. Bezeichnungen wie in Abschnitt 7.4.10 (C, N, `root(t)`), dazu T und U (Abschnitt 7.7.5).

- **Elemente.** X_C sind die verschiedenen Zeichenketten aus `cose_receipts` der Auszüge `/2` mit `chain_id` = C, X_F die verschiedenen Zeichenketten aus `cose_receipts` der übrigen Auszüge, die nicht in X_C stehen. Jedes Element von X_F zählt als `foreign_chain` und wird nicht weiter geprüft, damit Läufe über eine Kettennachfolge möglich bleiben.
- **Vergleichswurzeln** V(t) zu einer Größe t: zuerst `root(t)`, wenn 1 ≤ t ≤ N; danach höchstens 8 weitere Werte, nämlich die kleinsten nach ihren Bytes (aufsteigend) unter den verschiedenen 32-Byte-Werten ungleich `root(t)` aus `Bytes(merkle_root)` jedes `CHECKPOINT_RECEIPT` des Pakets mit `tree_size` = t und aus `Bytes(merkle_root)` jedes Elements von `roots` mit `tree_size` = t in einem Nachweis `present` eines Auszugs, den der Prüfer mit `chain_id` = C übergibt, gleich ob sein Tag nutzbar ist und ob der Nachweis nach Schritt L6 trägt. Auszüge in Dateien der Anker-Historie tragen keine Vergleichswurzeln bei (Abschnitt 8.8.2). Je Element prüft der Verifier also höchstens 9 Signaturen, beide Referenz-Verifier in derselben Reihenfolge. Woher ein Wert stammt, ist für K4 ohne Belang: Er zählt nur, wenn die Signatur über ihn trägt, und dann hat der Inhaber des Transparenzschlüssels genau ihn signiert.
- **Dem Paket zugeordnet** ist eine Wurzel r zur Größe t, wenn das Paket einen `CHECKPOINT_RECEIPT` mit `tree_size` t und `merkle_root` gleich `Hex(r)` trägt oder wenn r unter den `roots` eines geprüften Nachweises `present` für (C, A) eines nutzbaren Tages steht (Abschnitt 7.4.10, Schritt L6), also nach demselben Maßstab wie in Abschnitt 7.4.3 über die Position mit der `appliance_id` des Pakets.

Für jedes Element x von X_C gilt der erste zutreffende Schritt:

- **K1 Profil.** x verletzt B64 (Abschnitt 2), Bytes(x) umfasst mehr als 1024 Bytes, oder Bytes(x) verletzt Grammatik C (Abschnitt 7.7.1), das Profil in Ablageform (Abschnitt 7.7.2) oder Profil C1 (Abschnitt 7.7.3): `defective`, Befund `COSE_RECEIPT_DEFECTIVE` „Profil“.
- **K2 Schlüssel.** `kid` nennt keinen Schlüssel aus T: `key_not_established`.
- **K3 Kette und Protokoll.** `sub` ist nicht C: `foreign_chain`. Sonst, wenn `iss` nicht U ist oder es kein U gibt: `other_log`. K3 steht vor K4, denn die Vergleichswurzeln stammen aus der Kette C.
- **K4 Signatur.** Mit t = Wert von −65537: Trägt die Signatur von x unter dem Publikey aus K2 über die Sig_structure (Abschnitt 7.7.2) mit R gleich einem Wert r aus V(t), ist r die **Wurzel von x**. Geprüft wird in der Reihenfolge von V(t); die erste Wurzel, über die sie trägt, ist r. Trägt sie über keinen Wert aus V(t), auch wenn V(t) leer ist: `defective`, Befund `COSE_RECEIPT_DEFECTIVE` „Signatur trägt über keine Wurzel, die der Verifier zu tree_size t kennt“.
- **K5 Gültigkeit.** Der Schlüssel aus K2 gilt nicht zu `server_ts` (Abschnitt 7.7.5): `key_not_valid`.
- **K6 Vergleich.** t ≤ N und r = `root(t)`: `matching_prefix`. t ≤ N, r ≠ `root(t)` und r dem Paket zugeordnet: `contradicting_prefix`, Befund `COSE_RECEIPT_MISMATCH`, einmal je (t, r). t ≤ N, r ≠ `root(t)` und r nicht dem Paket zugeordnet: `root_not_attributed`, ohne Befund, denn C1 bindet die Kette nur über `chain_id`, nicht über die Appliance (Abschnitt 7.7.8). t > N: `beyond_package`.
- **K7 Quittung.** Ein Element `matching_prefix` zählt zusätzlich als `with_chain_receipt`, wenn das Paket einen `CHECKPOINT_RECEIPT` mit `chain_id` C trägt, dessen Signatur unter dem Schlüssel nach Abschnitt 7.1 trägt, ob dieser belegt ist oder nicht (wie Abschnitt 7.4.10, Schritt L8), und der keinen Befund `RECEIPT_INVALID` hat, mit `tree_size` t, `merkle_root` gleich `Hex(r)` und `server_ts` Zeichen für Zeichen gleich dem Wert von −65538.

Jedes Element von X_C und X_F zählt in genau einer der Klassen `foreign_chain`, `other_log`, `defective`, `key_not_established`, `key_not_valid`, `matching_prefix`, `contradicting_prefix`, `root_not_attributed` und `beyond_package`; `with_chain_receipt` ist ein Teil von `matching_prefix`.

**Warum die Wurzel nicht im Objekt steht.** Die Nutzlast ist abgetrennt (RFC 9942 Abschnitt 4.4); wer prüft, bildet die Wurzel selbst. Ein echtes C1 aus einem Auszug, der auch den Kettentag-Nachweis seines Tages trägt, findet seine Wurzel unter den Vergleichswurzeln (Heartbeat-Spezifikation §9.9), solange der Auszug zu (t) nicht mehr als 8 weitere Wurzeln nennt, die nach ihren Bytes vor ihr liegen; ein ehrlicher Auszug nennt je Gegensignatur eine Wurzel. Die Grenze von 9 Prüfungen je Element hält den Aufwand linear in der Eingabe. Trägt die Signatur über keine bekannte Wurzel, kann das Objekt beschädigt sein oder eine Wurzel nennen, die der Verifier nicht kennt; beides unterscheidet er nicht, und er meldet es als mangelhaft.

**Wirkung.** Schritt K liest nur die Wurzeln der Präfixe, die Quittungen des Pakets und ob ihre Signatur trägt, die Auszüge, die geprüften Nachweise aus Schritt L6, T und U. Er ändert kein anderes Ergebnis: `NO_ANCHOR`, erwartete Wurzeln, Vollständigkeit, Herstellerprotokoll, Anker-Historie und Beweisstufe bleiben, wie sie ohne ihn wären. Der Exit-Code ändert sich nur über die Klassen aus Abschnitt 7.7.7, also höchstens von 0 zu 1. Das Ergebnis steht im Berichtsobjekt `cose_receipts` (Abschnitt 10.10.2).

#### 7.7.7 Befunde

| Befundklasse | Bedeutung | Fälle |
|---|---|---|
| `COSE_RECEIPT_DEFECTIVE` | übergebene COSE-Gegensignatur trägt nicht (Profil oder Signatur) | ein Element von `cose_receipts` der Kette des Pakets verletzt B64, die Größe, Grammatik C oder Profil C1 (Schritt K1), oder seine Signatur unter einem Schlüssel aus T trägt über keine Vergleichswurzel (Schritt K4) |
| `COSE_RECEIPT_MISMATCH` | COSE-Gegensignatur nennt eine Wurzel, die zum Paket nicht passt | eine COSE-Gegensignatur unter einem geltenden Schlüssel aus T, deren Signatur über eine dem Paket zugeordnete Wurzel r zu einer Größe t ≤ N trägt, mit r ≠ `root(t)` (Schritt K6) |

Beide haben die Exit-Klasse 1 (Abschnitt 10.4). COSE Receipts der Tage (C2) fügen keine Klasse hinzu; ihre Fälle stehen bei `VENDOR_LOG_DEFECTIVE` und `VENDOR_LOG_CONTRADICTION` (Abschnitt 7.4.11). Exit 3 entsteht nur in Schritt L0 (Abschnitte 7.4.10, 10.8). Ein Element, das als `foreign_chain`, `other_log`, `key_not_established`, `key_not_valid`, `root_not_attributed` oder `beyond_package` zählt, ergibt keinen Befund. Kein Element von `cose_receipts` wirkt auf die Beweisstufe (Abschnitt 7.7).

**Mehrfachmeldungen.** `COSE_RECEIPT_DEFECTIVE` höchstens einmal je Lauf, mit der Zahl der Elemente und ihren Gründen in der Reihenfolge der Schritte; `COSE_RECEIPT_MISMATCH` einmal je (`tree_size`, `merkle_root`), mit beiden Werten.

**Warum keiner davon Exit 2.** Wie in Abschnitt 7.4.11: Das Material steht außerhalb der Kette und stammt vom Hersteller. Ein beschädigter Abruf, ein Fehler oder ein Fehlverhalten des Herstellers kann jeden Fall auslösen; mit Exit 2 könnte ein Hersteller eine ehrliche Kette ohne Zutun des Prüfers ungültig machen. `COSE_RECEIPT_MISMATCH` kann ein Umschreiben der Kette durch den Schlüsselinhaber bedeuten oder eine Wurzel, die der Hersteller erfunden hat; der Verifier unterscheidet beides nicht. Eine Wurzel derselben `chain_id` unter einer anderen Appliance ergibt den Befund nicht, denn sie ist dem Paket nicht zugeordnet (Schritt K6, Abschnitt 7.4.3).

#### 7.7.8 Was ein COSE Receipt nicht zeigt

- **C2** zeigt nur: Ein Blatt steht in einem Baum mit der Wurzel R und der Größe t, und der Inhaber des Transparenzschlüssels hat R und t für den Tag d signiert. Es zeigt nicht, dass der Tag rechtzeitig bezeugt ist (Zeitstempel, Abschnitt 7.4.6), dass die Tage lückenlos über `prev_hash` verkettet sind (Abschnitt 7.4.5), dass die Größe der Größenregel folgt (Abschnitt 7.4.4), dass die Positionen streng geordnet sind und eine Kette je Tag höchstens ein Kettentag-Blatt hat (Abschnitt 7.4.3; das zeigt nur die Prüfung der Tagesblätter, Abschnitt 7.4.9), und keine Abwesenheit (Abschnitt 5). Es ersetzt den Tageseintrag nicht: Ohne ihn weiß ein Prüfer nicht, ob der Tag bezeugt ist, und der Verifier stellt ohne Tageseintrag keinen Tag fest. C2 belegt das Kettentag-Blatt, nicht die einzelne Gegensignatur; deren Aufnahme zeigt erst die Kettentag-Wurzel aus allen Blättern der Kette am Tag (Abschnitt 7.4.3).
- **C1** zeigt nur, was der Hersteller unter dem Transparenzschlüssel über eine Wurzel der Kette sagt. Es verankert nichts, ersetzt die Quittung nicht und belegt keinen Gegenzeichnungsschlüssel (Abschnitt 7.7.3). Ob die Kette vollständig ist, ob die Gegensignatur protokolliert ist und wann sie ausgestellt wurde, zeigt es nicht; `server_ts` ist eine Zeitangabe des Herstellers wie in der Quittung (Abschnitt 7.1). Es bindet die Kette nur über `chain_id`, nicht über die Appliance. In die Kette kann es nicht: `CHECKPOINT_RECEIPT` ist streng (Abschnitt 10.6, Regel 3), und ein neuer Eintragstyp ergäbe bei Verifiern der Fassung 1.9 `UNKNOWN_ENTRY_TYPE`.
- **Tage ohne C2.** Tage vor dem ersten C2 des Herstellers haben keines, ebenso ein Tag, dessen Eintrag nicht unter der wirksamen Protokollschlüsselliste trägt oder erst nach end(d) + W veröffentlicht wird, etwa durch eine Person ohne Zeitstempel (Heartbeat-Spezifikation §9.9). Ebenso hat eine Gegensignatur kein C1, wenn der Transparenzdienst es nicht innerhalb von 15 Minuten ausgestellt hat. Ein fehlendes C1 oder C2 ist nie ein Befund; Tage und Quittungen beurteilt der Verifier wie ohne COSE-Objekte.
- **Allgemeine COSE-Prüfer.** Die Labels −65537 und −65538 stehen nicht in `crit`. Ein Prüfer, der sie nicht kennt, übergeht sie; für ihn ist die Baumgröße nicht gebunden, und derselbe Pfad kann für mehrere Größen tragen (Abschnitt 5). Er MUSS die Größe deshalb aus dem geschützten Kopf oder aus dem Tageseintrag nehmen, nie aus dem Beweis. Den Schlüssel zu `kid` belegt ein solcher Prüfer nur mit einer Rollenliste, die er gegen die Herstellerwurzel prüft.
- **Transparenzschlüssel.** Den aktiven Transparenzschlüssel hält ein laufender Dienst (Heartbeat-Spezifikation §9.11 Punkt 4). Wer ihn entwendet, kann C1 und C2 über beliebige Wurzeln signieren. Gegen den Tageseintrag und das Paket fallen solche Objekte auf: als Widerspruch (`VENDOR_LOG_CONTRADICTION`, `COSE_RECEIPT_MISMATCH`), wenn ihre Wurzel einem anderen Eintrag des Tages oder einer dem Paket zugeordneten Vergleichswurzel gleicht oder nur die Baumgröße abweicht, sonst als mangelhaft (`VENDOR_LOG_DEFECTIVE`, `COSE_RECEIPT_DEFECTIVE`), denn der Verifier kennt die signierte Wurzel nicht; `COSE_RECEIPT_DEFECTIVE` geht in keine Bedingung der Beweisstufe ein. Der Transparenzschlüssel ist ein Schlüssel nach Ed25519; gegen einen Bruch dieses Verfahrens hilft das COSE-Objekt nicht.
- **Unbekannte Wurzel.** Trägt die Signatur eines C1 über keine Wurzel, die der Verifier kennt, meldet er es als mangelhaft (Schritt K4), auch wenn der Hersteller es echt über eine andere Wurzel signiert hat, etwa nach einem Verlust von Blättern (Heartbeat-Spezifikation §9.9, Wiederherstellung, Punkt 2) oder wenn ein Auszug mehr als 8 andere Wurzeln derselben Größe nennt, die nach ihren Bytes vor der echten liegen.

#### 7.7.9 Datenschutz

RFC 9942 Abschnitt 6.2 verlangt vom Aussteller eine Analyse der Pflichtfelder eines Profils auf ihre Wirkung für den Datenschutz. Für die Profile C1 und C2:

| Feld | C2 (Tag) | C1 (Gegensignatur) |
|---|---|---|
| `alg`, `vds`, `typ` | feste Werte; verraten nichts | feste Werte; verraten nichts |
| `kid` | `key_id` eines Transparenzschlüssels, öffentlich in der Rollenliste | wie C2 |
| `iss` | `log_uri` der Liste `/2`, öffentlich | wie C2 |
| `sub` | der Tag d, öffentlich im Tageseintrag | `chain_id` der Kette; nicht öffentlich |
| −65537 `tree_size` | Größe des Tagesbaums, öffentlich im Tageseintrag; zeigt die Größenstufe (Abschnitt 7.4.4) | Größe der Kette, wie in der Quittung |
| −65538 `server_ts` | steht nicht in C2 | Zeit der Gegensignatur, wie in der Quittung |
| R (abgetrennt) | `root(d)`, öffentlich im Tageseintrag | `merkle_root`, wie in der Quittung |
| Signatur | nichts über die Felder hinaus | wie C2 |
| Beweis der Vorlageform | `tree_size`, `leaf_index` und Pfad, aus den öffentlichen Tagesblättern ablesbar; für Index 0 kein Hinweis auf eine Kette; für das Kettentag-Blatt einer Kette wie der Nachweis `present` eines Auszugs | keine Vorlageform vom Hersteller |

- Kein COSE-Objekt trägt Kundendaten, ein Commitment, eine `appliance_id`, eine Kettentag-Wurzel oder die Zahl der Ketten oder Füller eines Tages. Was ohne `chain_id` abrufbar ist (C2 in Ablageform an den Orten und in Vorlageform für Index 0), zeigt nichts, was Tageseintrag und Tagesblätter nicht schon zeigen.
- C2 entsteht für jeden veröffentlichten Tag, gleich wie viele Ketten er hat (Heartbeat-Spezifikation §9.9); Zahl und Zeit der C2 verraten deshalb nichts über die Ketten.
- Eine Vorlageform je Blatt zeigte, welche Blätter Kettentag-Blätter sind, und damit die Zahl der Ketten (Abschnitt 7.4.4, „Nicht öffentlich“). Deshalb gibt der Hersteller ohne `chain_id` nur den Beweis für Index 0 aus und mit `chain_id` nur den für das Kettentag-Blatt dieser Kette; jeder Prüfer bildet andere Beweise selbst aus den Tagesblättern, ohne dem Hersteller zu zeigen, welches Blatt er prüft.
- C1 trägt die `chain_id` im Klartext. Der Hersteller gibt C1 deshalb nur in einem Auszug zu einer Kette heraus, wenn die Anfrage deren `chain_id` nennt, wie Auszüge und Seiten der Anker-Historie; nie an den Veröffentlichungsorten, nie in einem Spiegelauszug und nie in `days2/…` (Abschnitt 7.4.12; Heartbeat-Spezifikation §9.9, §12). Wer die `chain_id` nennt, erfährt aus C1 nichts, was der Auszug mit seinen Kettentag-Nachweisen nicht schon zeigt.
- Ein Abruf eines Auszugs oder eines C2 mit `chain_id` teilt dem Hersteller mit, welche Kette geprüft wird; dass er das nicht festhält, ist eine Pflicht seines Betriebs (Heartbeat-Spezifikation §12 Punkt 7; kein Beleg durch LEDGER).

#### 7.7.10 Beispiele

Beide Beispiele verwenden den Transparenzschlüssel `vendor-transparency-test-001` des Testkorpus, einen Testschlüssel mit dem Namen `vendor-transparency-1` (Startwert SHA-256 der ASCII-Bytes `REKORDER-TESTVECTOR-KEY:vendor-transparency-1` = `55a183d4704c343cf9ed817e384e0e6b294be27649f8a48a730f758eaba1b6d4`, Publikey `66e422bf73c6eb8db0ac17ee7e775e5f1570cd09734f23afb1c7333a26c9f973`, Abschnitt 10.7.2), und `log_uri` `https://download.example/ledger-testprotokoll-1`. Ed25519 ist deterministisch; jede Signatur lässt sich nachrechnen.

- **C1** zur Gegensignatur aus Abschnitt 7.4.2 (`chain_id` `3cef4d7e-4d65-41d6-912d-90d51fda8982`, `tree_size` 42, `merkle_root` `09b2745bcdf71ea82eff8696868a267edd6de0fcb1c82cc3de0020527dc23dae`, `server_ts` `2026-03-01T23:59:30.000Z`): Der geschützte Kopf umfasst 210 Bytes, die Sig_structure 259 Bytes mit dem SHA-256-Wert `9f52aabc6a9cc788e2906c6d911f79d4d5bd378ee177c2710700c78030b7992f`, die Ablageform 282 Bytes (376 Zeichen in B64) mit dem SHA-256-Wert `67c126cd0829fbc93fa41896a8facd4042f85c4a6a6fd9daa824a4c65397a8cf`:

```
d28458d2a7013204581c76656e646f722d7472616e73706172656e63792d746573742d3030310fa201782f68747470733a2f2f646f776e6c6f61642e6578616d706c652f6c65646765722d7465737470726f746f6b6f6c6c2d3102782433636566346437652d346436352d343164362d393132642d3930643531666461383938321078286170706c69636174696f6e2f6c65646765722d636f756e7465727369676e61747572652b636f736519018b013a00010000182a3a000100017818323032362d30332d30315432333a35393a33302e3030305aa0f658405b7fa331f27a5fcc356fccc40fbfd3d952a6c33bfa4f10524c31fed29403471443b1cf5d67ac9b500d5d601e8b11bdd4074e3ca69154735d6b85cd763f936c04
```

- **C2** zum Referenztag aus Abschnitt 7.4.4 (Protokoll `ledger-testprotokoll-1`, Tag `2026-01-01`, `tree_size` 5, `root` `0adcf8f084c1c9c0e8998f01a0a9a9b57e96b5e9135e2833cbb10c6a9e121871`): Der geschützte Kopf umfasst 146 Bytes, die Sig_structure 195 Bytes mit dem SHA-256-Wert `3cfba65d3722d38c391700a1a4dddae204ade131d0c535402fc8b7804e8bdabb`, die Ablageform 218 Bytes (292 Zeichen in B64) mit dem SHA-256-Wert `3d42e54618152a9524e51e20e6979f6f378612e5d92b148878b8c6757b8cf6e2`:

```
d2845892a6013204581c76656e646f722d7472616e73706172656e63792d746573742d3030310fa201782f68747470733a2f2f646f776e6c6f61642e6578616d706c652f6c65646765722d7465737470726f746f6b6f6c6c2d31026a323032362d30312d30311078236170706c69636174696f6e2f6c65646765722d6461792d726563656970742b636f736519018b013a0001000005a0f6584087d2c08b6f74e3c4b24d53263e478befaecf0d6c9a170fdb2d13bd6750f13c135bfb7776b2fe099c857d6ffb21b836ed1e7b9d12873c9ecee1dfad1ae2872b05
```

  Die Vorlageform für das Blatt mit Index 0 umfasst 332 Bytes mit dem SHA-256-Wert `42ceed4126edc02255c73fe75faec3ff02d5cc10dfe3bf1c41d0da7f0739a999`; ihr Pfad lautet `f98a7536bad9d202f57590429f3e4c2523f79f82c87c254e9c6c1c00893845f2`, `cb3741c57d198a3c3b2800967939346d4d0380ddcc1fb85347ef2cdef3a904b3`, `3bc3f3d4752763919917958440a1997224c1218d5ef038d09a9ca99d1eb88806`. Die Vorlageform für das Kettentag-Blatt dieses Tages (Index 3, Abschnitt 7.4.4) hat ebenfalls 332 Bytes und den SHA-256-Wert `6423d050b2fef46cbc6e8176e7d6bc5bf31f2c71bb1744e92aa8631fa1a8d4d7`; ihr Beweis ist `[5, 3, [<Pfad>]]` mit dem Pfad `294970b630c3526afb9c691702e0e939842253339bb6831386b70502f012f8c5`, `eab306e720e2cc96b755b9fc1a8e31f34e448adf0fa615f81ef4f54cfa05b4b0`, `3bc3f3d4752763919917958440a1997224c1218d5ef038d09a9ca99d1eb88806`, kodiert `830503835820294970b630c3526afb9c691702e0e939842253339bb6831386b70502f012f8c55820eab306e720e2cc96b755b9fc1a8e31f34e448adf0fa615f81ef4f54cfa05b4b058203bc3f3d4752763919917958440a1997224c1218d5ef038d09a9ca99d1eb88806`, und ihr ungeschützter Kopf `{396: {-1: [h'<diese 106 Bytes>']}}`.

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

**Warum Bedingung 4, und warum so eng.** Stürzt die Schreibstrecke zwischen einem kritischen Eintrag und seinem Sofort-Checkpoint ab, schreibt der Neustart den Checkpoint nach (Abschnitt 6.2), danach `RESTART` und `GAP`. Bis Fassung 1.8 blieb die Stille vor dem nachgeholten Checkpoint verschwiegen, obwohl die Kette sie unmittelbar danach deklariert (bewusste Entscheidung vom 03.09.2026, am 29.09.2026 zugunsten der Deckung durch den folgenden `RESTART` geändert, mit der Bedingung: ein `RESTART` darf keine Löschung verdecken können). Bedingung 4 verlangt deshalb die Spur des Neustarts, die unmittelbar folgende Deklaration und ein `GAP`-Fenster, das die ganze Stille umfasst. Sie berührt keine andere Prüfung: Zwischen `a` und `b` kann kein Eintrag fehlen (`seq`, Merkle-Baum des Checkpoints), ein `CONTENT_DELETED` als `a` bleibt der Befund `CONTENT_DELETED`, und die Löschsperre (Abschnitt 9.3) wird geprüft wie überall. Die Zeit von `a` ist dann nur durch die Signatur von `b` zum Zeitpunkt `ts_chained(b)` begrenzt, nicht durch die Toleranz davor.

**Grenze: „Ein RESTART darf keine Löschung verdecken“ lässt sich offline nicht allgemein sicherstellen, schon nicht mit Bedingung 2, die seit Fassung 1.0 gilt.** Wer Schreibzugriff auf die Kettendateien hat, kann das Ende der Kette samt eines `CONTENT_DELETED` abschneiden und die Anlage neu starten; `RESTART` und `GAP` decken dann die Stille bis zum letzten verbliebenen Eintrag, und nichts im Paket widerlegt das. Ebenso signiert ein Neustart jeden hash-konsistenten Eintrag, den jemand vorher ans Ende gehängt hat. Das ist dieselbe Grenze wie das Restfenster (Abschnitt 11.2): Der Schlüssel liegt beim Betreiber. Aufgedeckt wird es durch Verankerung: der Hersteller nimmt eine gekürzte Kette nicht mehr an (Heartbeat-Spezifikation §9.2), eine erwartete Wurzel des Prüfers widerspricht ihr (Abschnitte 7.2, 8.6), ein Zeitzeuge (Abschnitt 7.3). Bedingung 4 erweitert diese Möglichkeit nicht; was sie deckt, ließ sich schon zuvor mit vorgetäuschten `TICK`-Einträgen erreichen.

### 8.3 Lückenklassen

`GAP.reason` trägt genau eine der Klassen aus 4.26: `bypass` (Pförtner-Direktweiterleitung ohne Erfassung), `proxy_restart`, `power_loss`, `spool_unwritable`, `host_down`, `update`, `manual`. Für Importquellen deckt `SOURCE_GAP` Quellfenster (Befund `COVERED_SOURCE_GAP`, Exit 1); `RECONCILIATION` mit `delta ≠ 0` ist der Befund `RECONCILIATION_DELTA` (Exit 1).

### 8.4 SEAL/RESUME-Handover

Geplante Unterbrechungen (Update, Shutdown, Stilllegung) MÜSSEN versiegelt werden; ein Export aus laufendem Betrieb KANN versiegelt werden (Export-Siegel, `reason = export`, ab Fassung 1.9):

1. Die alte Instanz schreibt `SEAL`; als kritischer Typ MUSS unmittelbar danach dessen Sofort-Checkpoint folgen (Abschnitt 6.2).
2. Die fortsetzende Instanz (nach `update` oder `shutdown` eine neue, nach `export` dieselbe oder, nach einem Absturz dazwischen, die neu gestartete) schreibt als ersten inhaltlichen Eintrag `RESUME` mit `sealed_entry_hash` = **`entry_hash` des SEAL-Eintrags** (nicht des Sofort-Checkpoints; MUSS exakt übereinstimmen) sowie `prev_version`/`new_version`.
3. Zwischen `SEAL` und `RESUME` liegt **genau ein** Eintrag, und dieser MUSS der Sofort-Checkpoint des SEAL sein.

Begründung beider Hälften von Regel 3: Ein `SEAL` ohne sofortigen Checkpoint bliebe **unverankert**: stirbt die Maschine zwischen SEAL und RESUME, wäre der Kettenstand nur bis zum letzten älteren Checkpoint signiert abgedeckt; das ist die schwächere Beweislage, und genau der Moment der geplanten Unterbrechung braucht die stärkere. Umgekehrt darf **nur dieser eine Anker** dazwischenliegen, damit der Handover beweisbar dicht bleibt: jeder weitere Eintrag in der geplanten Stille wäre nicht mehr vom Handover selbst gedeckt.

Verletzungen (fehlender RESUME nach SEAL (obwohl die Kette weiterläuft), falscher `sealed_entry_hash`, ein anderer oder ein zusätzlicher Eintrag zwischen SEAL und RESUME) sind der Befund `HANDOVER_BROKEN` (Exit 2); der fehlende Sofort-Checkpoint des SEAL selbst ist `MISSING_CHECKPOINT` (Exit 2), außer am Kettenende (Abschnitt 6.2). Endet die Kette mit einem SEAL + Sofort-Checkpoint, ist das ein regulärer Kettenabschluss, kein Befund, gleich mit welchem `reason` (ab Fassung 1.6; bis Fassung 1.5 nur mit `decommission` oder `key_loss`) und auch dann, wenn danach noch `CHECKPOINT_RECEIPT`-Einträge auf genau diesen Sofort-Checkpoint folgen: sie bestätigen den versiegelten Stand und sind kein inhaltlicher Eintrag. Wie das Kettenende bewertet wird, regelt Abschnitt 8.6.

**Export-Siegel (ab Fassung 1.9).** Der Schreiber schreibt `SEAL` mit `reason = export`, dessen Sofort-Checkpoint, `RESUME` und den Checkpoint danach ohne einen Eintrag dazwischen und setzt die Kette unmittelbar fort; in der Kette ist das ein gewöhnlicher Handover nach den Regeln 1 bis 3. Das Prüfpaket umfasst die Einträge bis einschließlich des Sofort-Checkpoints dieses Siegels und ist damit versiegelt (Abschnitt 8.6). Der Handover dauert Millisekunden; eine längere Stille zwischen Checkpoint und `RESUME` (ein Absturz im Export) deckt Bedingung 3 von Abschnitt 8.2 wie bei jedem Handover.

Drei Klarstellungen (Entscheidung vom 03.09.2026; beide Referenz-Verifier lesen die Regel so): (1) Jeder `RESUME` setzt genau einen `SEAL` fort: ein `RESUME`, dem nicht unmittelbar ein `SEAL` mit dessen Sofort-Checkpoint vorausgeht, ist `HANDOVER_BROKEN`. (2) `CHECKPOINT_RECEIPT`-Einträge auf den Sofort-Checkpoint eines `SEAL` dürfen nur am Kettenende nachlaufen; zwischen `SEAL` und `RESUME` sind sie ein zusätzlicher Eintrag im Sinne von Regel 3. (3) Die Stille-Deckung nach Abschnitt 8.2 Bedingung 3 gilt nur für den Handover, den der `RESUME` mit passendem `sealed_entry_hash` tatsächlich fortsetzt.

### 8.5 Stille am Kettenende (Freshness)

Das Ende der Kette kann kein nachfolgender Eintrag decken. Liegt `ts_chained` des letzten Eintrags weiter als das **Freshness-Fenster** vor dem Prüfzeitpunkt, meldet der Verifier `TRAILING_SILENCE` (Exit 1). Das Fenster ist konfigurierbar (Verifier-Option `--freshness`, Grammatik in Abschnitt 10.8); Default: **24 Stunden**. Dieser Befund schützt vor der Vorlage eines veralteten (z. B. zurückgerollten) Standes; zusammen mit Quittungs-`server_ts` und cloudseitiger `tree_size`-Monotonie begrenzt er Fork-/Rollback-Angriffe (Abschnitt 11). Der Befund gilt auch für eine versiegelte Kette (Abschnitt 8.6): Das Siegel erklärt die Stille nach ihm, es belegt aber nicht, dass es das jüngste Siegel der Kette ist; eine an einem früheren Siegel gekürzte Kette sähe genauso aus (Abschnitt 11.2). `TRAILING_SILENCE` bleibt Exit-Klasse 1; die Kette bleibt gültig.

### 8.6 Kettenende: versiegelt oder unvollständig

Grundsatz (ab Fassung 1.6): **Eine ehrliche Kette wird nie als „ungültig“ gemeldet. „Ungültig“ (Exit 2) ist nachgewiesener Manipulation vorbehalten.** Wie eine Kette endet, ist deshalb kein Manipulationsbefund, sondern ein eigener Status.

Eine Kette ist **versiegelt**, wenn ihre letzten Einträge in dieser Reihenfolge sind: ein `SEAL`, unmittelbar danach dessen Sofort-Checkpoint (Abschnitt 6.2), danach höchstens `CHECKPOINT_RECEIPT`-Einträge, deren `checkpoint_seq` genau diesen Sofort-Checkpoint nennt. Der `reason` des `SEAL` spielt dafür keine Rolle. Jede andere Kette ist **unvollständig**; das schließt eine Kette ein, deren letzter Eintrag ein `SEAL` oder ein anderer kritischer Eintrag ohne seinen Checkpoint ist (Abschnitt 6.2).

| Kettenende | Ergebnis | Exit |
|---|---|---|
| versiegelt, keine Befunde der Exit-Klasse 2 | gültig, ordnungsgemäß versiegelt; der Bericht nennt `seq`, `ts_chained` und `reason` des `SEAL` | 0, bei Befunden der Exit-Klasse 1: 1 |
| unvollständig, keine Befunde der Exit-Klasse 2 | unvollständig: Befund `UNSEALED_END` | 4 |
| `SEAL`, danach andere Einträge ohne `RESUME` | ungültig: `HANDOVER_BROKEN` (Abschnitt 8.4) | 2 |
| Hash-Kette gebrochen, Signatur falsch oder ein anderer Befund der Exit-Klasse 2 | ungültig | 2 |

Der Befund `UNSEALED_END` wird für jede unvollständige Kette genau einmal gemeldet, mit der `seq` ihres letzten Eintrags, auch neben Befunden der Exit-Klasse 2; der Exit-Code folgt dann Abschnitt 10.3. Ist das Paket ein Formatfehler (Exit 3), wird das Kettenende nicht bewertet. Seit Fassung 1.6 setzen Exit 0 und Exit 1 damit ein versiegeltes Kettenende voraus.

**Was „unvollständig“ heißt.** Alle vorhandenen Einträge sind geprüft wie bei jeder Kette. Unvollständig heißt nur: Das Paket belegt nicht, dass nach seinem letzten Eintrag nichts mehr kam. So endet jeder Export aus einer laufenden Anlage ohne Export-Siegel, jede Kette nach einem Absturz oder Stromausfall, und ebenso eine gekürzte Kette. Offline lassen sich diese Fälle nicht unterscheiden. Der Verifier MUSS deshalb mit dem Befund den letzten gegengezeichneten Checkpoint des Pakets nennen (`checkpoint_seq`, `tree_size`, `merkle_root` und `server_ts` der Quittung mit der größten `tree_size` unter denen, die nach Abschnitt 7.1 als Verankerung zählen (Signatur trägt, keine widersprechende Herstellerliste) und mit ihrem Checkpoint übereinstimmen; bei gleicher `tree_size` die erste in Kettenfolge) oder dass es keinen gibt, und auf den Abgleich hinweisen.

**Export-Siegel.** Ein Paket, das die Anlage mit Export-Siegel erzeugt (Abschnitt 8.4), endet mit `SEAL(export)` und dessen Sofort-Checkpoint und ist versiegelt: Ein ordentlicher Export aus laufendem Betrieb ist gültig, nicht unvollständig (Entscheidung vom 29.09.2026).

**Abgleich mit dem letzten gegengezeichneten Checkpoint.** Der Hersteller führt je `chain_id` die Wurzeln, die er gegengezeichnet hat, und gibt sie ab Fassung 1.9 zusammen mit Lückenzeugen und gemeldeten Wurzeln als signierte Anker-Historie heraus, die der Prüfer mit der `chain_id` selbst abholt (Heartbeat-Spezifikation §9.7); er übergibt dann jede Wurzel daraus, die vor der Anforderung des Pakets festgehalten oder gemeldet wurde. Mindestens übergibt der Prüfer die jüngste gegengezeichnete Wurzel, die **vor der Anforderung des Pakets** gegengezeichnet wurde, wie einen Papier-Anker als erwartete Wurzel (`tree_size` und `merkle_root`, Abschnitt 7.2, 10.8), nicht die jüngste überhaupt: Eine danach gegengezeichnete Wurzel liegt hinter dem Paketende und kann darin nicht vorkommen; sie erschiene auch bei einem ehrlichen Paket als Widerspruch. Enthält das Paket die übergebene Wurzel nicht als Präfix-Wurzel, fehlen ihm Einträge, die der Hersteller bereits gegengezeichnet hatte: `MERKLE_INCONSISTENT` (Exit 2). Der Abgleich gilt für versiegelte Ketten ebenso.

**Abgleich durch den Verifier (ab Fassung 1.10).** Übergibt der Prüfer die Anker-Historie (Abschnitt 8.8), liest der Verifier ihre Seiten selbst und übernimmt jede Wurzel daraus, gegengezeichnet, als Lückenzeuge festgehalten oder gemeldet, als erwartete Wurzel mit der Quelle `anchor_history`. Wurzeln, die der Prüfer selbst als erwartete Wurzel übergibt (Abschnitt 10.8), tragen die Quelle `auditor`. Die Grenze „vor der Anforderung“ zieht dann der Verifier, nicht mehr der Prüfer von Hand: Er vergleicht den Zeitpunkt, zu dem der Hersteller eine Wurzel festgehalten hat (bei mehreren Aufzeichnungen der früheste), mit dem Anforderungszeitpunkt R, den der Prüfer angibt (Abschnitt 10.8). Eine gegengezeichnete oder als Lückenzeuge festgehaltene Wurzel, die mehr als 15 Minuten vor R festgehalten wurde und die dem Paket fehlt oder ihm widerspricht, ist `MERKLE_INCONSISTENT` (Exit 2), wie beim Abgleich von Hand seit Fassung 1.9; fehlt dem Paket nur eine Wurzel aus den 15 Minuten vor R, ist das ein Hinweis, kein Befund, und der Prüfer fordert das Paket neu an. Eine nur gemeldete Wurzel führt dagegen nie zu Exit 2, sondern zu `ANCHOR_HISTORY_FORK` (Exit 1): Ihre Geräte-Signatur kann der Verifier nicht prüfen, und kein Protokoll bestätigt sie. Die Fälle im Einzelnen nennt Abschnitt 8.8.5. Hinzu kommt die Bindung an das Gerät: Der Verifier verwendet nur Seiten, deren Eigentümer-Commitments zu einem Geräteschlüssel des Pakets passen (Abschnitt 8.8.4, Schritt H2). Ohne R beurteilt er keine Kürzung. Wurzeln aus dem Herstellerprotokoll sind keine erwarteten Wurzeln (Abschnitt 7.4.10, Schritt L9); Seiten der Form v1 wertet der Verifier nicht aus; für sie bleibt der Abgleich von Hand nach Heartbeat-Spezifikation §9.7, solange der Hersteller keine Rollenliste veröffentlicht hat.

**Was der Verifier zur Vollständigkeit sagt (ab Fassung 1.9).** Ohne eine vom Hersteller gegengezeichnete Wurzel ist keine Aussage darüber möglich, ob das Paket die ganze Kette bis zu seiner Anforderung enthält, weder bei einer unvollständigen noch bei einer versiegelten Kette (Beweisgrenze unten, Abschnitt 11.2; Entscheidung vom 29.09.2026: als Eigenschaft des Modells angenommen). Der Verifier MUSS das für jedes Paket, das kein Formatfehler ist, ausdrücklich sagen und die Wurzel anfordern: mit der `chain_id` und dem Aufruf, mit dem der Prüfer sie übergibt. Wurde eine erwartete Wurzel übergeben und im Paket gefunden, sagt er stattdessen, bis zu welcher `tree_size` die Vollständigkeit durch sie belegt ist. Bei einem Formatfehler ist die Vollständigkeit nicht bewertet: Das Member `completeness` hat dann den Wert `null` und fehlt nie (Abschnitt 10.10.1).

Ab Fassung 1.10 gilt das für gefundene erwartete Wurzeln beider Quellen, und der Bericht nennt, woher die gefundenen Wurzeln stammen: Das Objekt `completeness` erhält das Member `sources`, die Quellen der gefundenen Wurzeln in der Reihenfolge `auditor`, `anchor_history` (Registry `verifier.report_objects.completeness_sources_order`; dieselbe Reihenfolge gilt für `evidence_level.anchors.expected_root_sources`, Abschnitt 10.10.2). Zur Anforderung nennt der Verifier dann die Anker-Historie der Form v2 und den Anforderungszeitpunkt (Abschnitte 8.8.1, 10.8). Daneben urteilt die Anker-Historie selbst über die Vollständigkeit (`anchor_history.completeness`, Abschnitt 8.8.4, Schritt H11): Belegt ist sie dort nur mit Anforderungszeitpunkt, mit frischen Seiten, die zusammen alle Baumgrößen abdecken, ohne Widerspruch der Historie und mit mindestens einer gefundenen Wurzel aus ihr. Diese Aussage liest die Beweisstufe (Abschnitt 10.9); Wurzeln der Quelle `auditor` allein genügen ihr nicht.

**Beweisgrenze der Versiegelung.** Das Siegel trägt die Signatur des Geräteschlüssels, nicht die des Herstellers: Der Sofort-Checkpoint eines `SEAL`, auf den ein `RESUME` folgt, trägt vor dem `RESUME` keine Quittung (Abschnitt 8.4, Klarstellung 2). Jede frühere Übergabe (`SEAL`, Checkpoint, `RESUME`) ist deshalb eine Stelle, an der eine gekürzte Kette ohne jeden Schlüssel als versiegelt erscheint; der Schlüsselinhaber kann ohnehin an jeder Stelle kürzen und ein neues Siegel signieren (Abschnitt 11.1). Dagegen wirken der Zeitpunkt des Siegels im Bericht, `TRAILING_SILENCE` (Abschnitt 8.5) und sicher nur der Abgleich oben (Abschnitt 11.2, Testvektor `end_truncated_at_seal`).

**Ältere Verifier.** Die Regel gilt für jedes Paket, gleich welche `spec_version` es erklärt: Das Manifest ist nicht signiert, eine erklärte ältere Fassung darf den Status des Kettenendes nicht ändern (wie in Abschnitt 7.1). Ein Verifier der Fassung 1.5 oder älter kennt Exit 4 nicht: Er meldet eine unvollständige Kette als gültig (Exit 0 oder 1; milder als diese Fassung), eine, deren letzter Eintrag ein kritischer Eintrag ohne Checkpoint ist, dagegen als `MISSING_CHECKPOINT` und eine mit `update` oder `shutdown` versiegelte als `HANDOVER_BROKEN` (je Exit 2; strenger). Er erkennt ein Paket ab 1.6 am Befund `SPEC_NEWER` (Abschnitt 10.6); Pakete ab 1.6 SOLLEN mit einem Verifier ab 1.6 geprüft werden. Ein Verifier bis Fassung 1.8 kennt den Versiegelungsgrund `export` nicht: Die Nutzlasten bekannter Typen bleiben streng (Abschnitt 10.6, Regel 3), er meldet deshalb jedes Paket, das ein Export-Siegel enthält, als `FORMAT_ERROR` (Exit 3), für diese Kette dauerhaft, auch für jedes spätere Paket, weil das Siegel in der Kette bleibt. Pakete ab 1.9 SOLLEN mit einem Verifier ab 1.9 geprüft werden.

### 8.7 Erfassungszusage und Lückenbeginn nach einem Absturz

Ab Fassung 1.9 (Ergänzung vom 02.10.2026). Grundsatz: Kein beantworteter KI-Aufruf darf still verloren gehen. Entweder steht er in der Kette, oder er liegt sichtbar in einer Lücke.

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

### 8.8 Anker-Historie als Angabe des Prüfers

Ab Fassung 1.10. Die Anker-Historie ist die signierte Aufstellung des Herstellers über die festgehaltenen und gemeldeten Wurzeln einer Kette, ihre Fork-Befunde und ihren Kettenwechsel (Heartbeat-Spezifikation §9.7). Ab dieser Fassung übergibt der Prüfer ihre Seiten der Form v2 dem Verifier, statt Wurzeln daraus von Hand als erwartete Wurzeln abzuschreiben. Der Verifier prüft jede Seite gegen Anker des Prüfers, bindet sie an Kette und Gerät des Pakets, übernimmt ihre Wurzeln als erwartete Wurzeln mit Quelle (Abschnitte 8.6, 10.8), gleicht sie mit Quittungen und Herstellerprotokoll ab und wertet die Angabe zur Verbundenheit des Kunden mit dem Hersteller (Heartbeat-Spezifikation §9.10) über den Zeitraum des Pakets aus.

Nichts davon steht im Prüfpaket. Ein Verifier DARF Seiten der Anker-Historie, eine Angabe zur Verbundenheit und einen Anforderungszeitpunkt NICHT aus dem Paket lesen (Abschnitt 10.1). Die Verbundenheit leitet er nie aus `GENESIS.customer_id`, `GENESIS.edition`, dem Manifest, einer anderen Datei des Pakets, dem Herstellerprotokoll oder der Beweisstufe ab. Beide Referenz-Verifier führen die Schritte dieses Abschnitts gleich aus; jede Regel kommt mit I-JSON, JCS, SHA-256, Ed25519 und ganzzahliger Arithmetik aus.

#### 8.8.1 Eingaben

| Angabe | Schalter (Abschnitt 10.8) | Zweck |
|---|---|---|
| Anker-Historie | `--anchor-history FILE`, wiederholbar | Seiten und eingebettete Auszüge (Abschnitt 8.8.2) |
| Anforderungszeitpunkt R | `--requested-at RFC3339`, höchstens einmal, freiwillig | wann der Prüfer das Paket angefordert hat |
| Rollenliste | `--vendor-key-list FILE`, wiederholbar | belegt Bescheidschlüssel von Seiten (Abschnitte 8.8.3, 10.7.4); Listen der beiden anderen Formate zählen hier nur für die Rollenprüfung |
| Herstellerwurzel | `--vendor-root` (Abschnitt 7.1) | bestätigt die Rollenliste (Abschnitt 10.7.2) |
| angeheftete Bescheidschlüssel | `--vendor-statement-key ID=HEX`, wiederholbar | belegen Schlüssel von Seiten (Abschnitt 8.8.3) |

Eine Anheftung als Gegenzeichnungsschlüssel (`--vendor-key`) belegt keine Seite.

Grammatik und Grenzen nennt Abschnitt 10.8. Der Verifier liest nur Seiten der Form `ledger.anchor_history.v2`. Eine Seite der Form v1 verwendet er nicht (Schritt H2, Grund `not_v2`): Sie bindet die Kette an kein Gerät und kann Fork-Befunde ohne Marke weglassen. Für Seiten der Form v1 bleibt das Verfahren von Hand nach Heartbeat-Spezifikation §9.7, und nur für einen Hersteller ohne veröffentlichte Rollenliste: Hat der Hersteller eine Rollenliste veröffentlicht, übergibt ein Prüfer nach Fassung 1.10 Wurzeln aus Seiten der Form v1 nie als erwartete Wurzeln.

Der Anforderungszeitpunkt ist freiwillig. Ohne ihn beurteilt der Verifier keine Kürzung: Wurzeln hinter dem Paketende zählt er, ohne sie zu bewerten, eine abweichende Wurzel im Paket ist `ANCHOR_HISTORY_FORK` statt `MERKLE_INCONSISTENT` (Abschnitt 8.8.5), die Vollständigkeit aus der Historie gilt als nicht belegt (Grund `no_request_time`), und der Bericht sagt das ausdrücklich. Der Verifier ergänzt R nie aus `manifest.created_ts`, aus `verify_args.json`, aus dem Prüfzeitpunkt oder aus einer Uhr. Wann das Paket angefordert wurde, weiß der Prüfer, nicht das Paket; einen früheren `created_ts` kann der Erzeuger des Pakets wählen und damit eine Kürzung verdecken, und der Prüfzeitpunkt machte Wurzeln, die erst nach der Anforderung festgehalten wurden, zu einem Widerspruch gegen ein ehrliches Paket. Nennt der Prüfer einen späteren Zeitpunkt als den tatsächlichen, erscheint ein ehrliches Paket als gekürzt; nennt er einen früheren, prüft der Verifier weniger.

#### 8.8.2 Datei der Anker-Historie `ledger-ankerhistorie/2`

Eine Datei der Anker-Historie ist eine Datei des Prüfers (Abschnitt 2) in einer von zwei Formen:

- **Eine Seite:** der Rumpf der HTTP-Antwort unverändert (Heartbeat-Spezifikation §9.7), ein Objekt mit genau den Membern `statement_jcs` (Zeichenkette, 1 bis 131 072 Zeichen), `server_key_id` (key-id), `server_signature` (hex128) und `statement` (beliebiger JSON-Wert; die unsignierte Lesekopie wird nicht ausgewertet).
- **Ein Behälter:** ein Objekt mit genau den Membern `format` (const `"ledger-ankerhistorie/2"`), `pages` (array, 1 bis 4 096 Seiten wie oben) und `vendor_log` (array, 0 bis 128 Auszüge nach Abschnitt 7.4.8).

Auszüge in `vendor_log` stehen dort unverändert; eine verkürzte Form gibt es nicht. Der Verifier prüft sie nach der Grammatik aus Abschnitt 7.4.8 und behandelt sie wie Auszüge, die der Prüfer einzeln übergibt (Abschnitt 7.4.10, Schritt L0); für die Zählung der Dateien und die Grenzen dort gilt jeder als eine Datei mit den Bytes `UTF-8(JCS(Element))`. So reisen Seiten und Auszug einer Prüfung in einer Datei, ohne dass die beiden Formate voneinander abhängen. In Fassung 1.10 trägt ein Behälter nur Auszüge `ledger-protokollauszug/1`; ein Auszug `ledger-protokollauszug/2` (Abschnitt 7.4.8a) darin verletzt diese Grammatik (Exit 3). Auszüge `/2` übergibt der Prüfer einzeln (Abschnitt 10.8).

Grenzen: je Datei höchstens 33 554 432 Bytes; je Aufruf höchstens 4 096 Dateien der Anker-Historie, 65 536 Seiten und 268 435 456 Bytes. Ein Verstoß gegen diese Grammatik oder eine Grenze ist ein unbrauchbarer Aufruf (Exit 3 ohne Bericht, Abschnitt 10.8). Den Inhalt von `statement_jcs` prüft erst Schritt H2; ein Mangel dort führt nie zu Exit 3.

Referenzwert: Die Seite zum Testvektor `valid_sealed_export` mit seinen beiden gegengezeichneten Wurzeln (`tree_size` 15 mit `server_ts` `2026-01-01T00:30:01.000Z` und 28 mit `2026-01-01T01:00:01.000Z`), dem Eigentümer-Commitment aus Heartbeat-Spezifikation §9.7, `known_since` `2025-12-01T00:00:00.000Z`, ohne Zeiträume, mit `reference_tree_size` 28, `since_tree_size` 0, ohne Fortsetzung und mit `server_ts` `2026-01-01T01:02:00.000Z` hat einen `statement_jcs` von 776 Zeichen mit dem SHA-256-Wert `6fe4cc5f74c2539468594843916f9cfa1e528934d3f812202f04969932ca175b`.

#### 8.8.3 Schlüssel der Seiten

Eine Seite der Form v2 trägt die Signatur eines Bescheidschlüssels (Rolle `statements`, Abschnitt 10.7.3). Für den `server_key_id` einer Seite gilt in dieser Reihenfolge:

1. Ist er als Bescheidschlüssel angeheftet (`--vendor-statement-key`) und nicht nach Abschnitt 10.7.4 weggefallen, gilt der angeheftete Publikey, ohne Gültigkeitsfenster. Nennt die wirksame Rollenliste denselben Publikey mit der Rolle `statements` und `widerrufen_ab`, gilt für die Signaturzeit trotzdem Schritt H2, Nummer 9 (Abschnitt 8.8.4).
2. Sonst gilt der Eintrag der wirksamen Rollenliste (Abschnitt 10.7.4) mit der Rolle `statements`.

Sonst ist der Schlüssel nicht belegt. Ein Gegenzeichnungsschlüssel, ein Protokollschlüssel und ein Schlüssel einer anderen Rolle belegen nie eine Seite, auch nicht über eine Anheftung nach Abschnitt 7.1 oder eine Liste der Gegenzeichnungsschlüssel. Die Kopie im Manifest (`manifest.vendor_pubkeys`, `keys/vendor/<key_id>.hex`) belegt nie eine Seite.

**Warum nur Bescheidschlüssel.** Über Seiten führt ein Weg zu Exit 2 (`MERKLE_INCONSISTENT`, Abschnitt 8.8.5). Belegte ein Gegenzeichnungsschlüssel Seiten, könnte, wer nur einen solchen Schlüssel hält, mit einer Seite, die er selbst signiert, ein ehrliches Paket ungültig erscheinen lassen. Weil Seiten nur unter Bescheidschlüsseln zählen, erzeugt er keine Seite, die ein Verifier verwendet (Abschnitt 11.2, Schlüsselrollen). Eine Seite unter einem Schlüssel einer anderen Rolle ist kein Fälschungsbefund: Sie ergibt `ANCHOR_HISTORY_UNVERIFIED` mit dem Grund `key_other_role` (Abschnitt 8.8.4, Schritt H2).

Referenzwerte (Rollenliste der Version 1 aus Abschnitt 10.7.2, Zeitpunkt `2026-01-01T01:02:00.000Z`): `vendor-statements-test-001` und `vendor-statements-test-002` sind belegt und gültig; eine Seite unter `vendor-test-001` ergibt `key_other_role`; ein Schlüssel, den die Rollenliste nicht nennt, ist nicht belegt (`key_not_established`); eine Anheftung als Bescheidschlüssel hat Vorrang vor der Rollenliste; zwei Rollenlisten der Version 1 mit verschiedenen Bytes: keine ist wirksam (`lists_contradictory`, Abschnitt 10.7.4), und keine Seite ist über eine Rollenliste belegt.

#### 8.8.4 Prüfung durch den Verifier

Bezeichnungen: N, C, A und `root(t)` wie in Abschnitt 7.4.10, ebenso K_cs. PK sind die Geräteschlüssel des Pakets: `GENESIS.device_pubkey` und jeder `new_pubkey` eines `KEY_ROTATION`, den Abschnitt 6.4 legitimiert. `OC(c)` ist die Menge der Eigentümer-Commitments (Heartbeat-Spezifikation §9.7) mit der `appliance_id` A, der `chain_id` c und je einem Schlüssel aus PK. R ist der Anforderungszeitpunkt oder fehlt; W_h = 900 000 ms (15 Minuten). Der **Bereich** I(P) einer Seite P ist `[since_tree_size, next_since_tree_size)`, bei `next_since_tree_size = null` `[since_tree_size, ∞)`. BL ist der Stichtag `legacy_boundary` der Registry (`verifier.anchor_history`). **Belegte Quittungen** sind die `CHECKPOINT_RECEIPT`, die nach Abschnitt 7.1 als Verankerung zählen und deren Schlüssel angeheftet ist (ohne nach Abschnitt 10.7.4 zu entfallen) oder aus der wirksamen Liste der Gegenzeichnungsschlüssel des Pakets stammt. Zeitpunkte vergleicht dieser Abschnitt in ganzen Millisekunden (Abschnitt 2, Zeitarithmetik), auch R; nur das Gültigkeitsfenster eines Eintrags der Rollenliste (Schritt H2, Nummer 6) wird wie in Abschnitt 7.1 auf Nanosekunden geprüft.

**Stellung im Prüfablauf.** H0 läuft beim Aufruf, vor dem Öffnen des Pakets. H1 bis H7 laufen nach dem Herstellerprotokoll (Abschnitt 7.4.10) und vor dem Abgleich der erwarteten Wurzeln. Die Einordnung H8 (Abschnitt 8.8.5) berechnet der Verifier beim Abgleich der erwarteten Wurzeln (Abschnitt 10.5, Schritt 8); ihre Befunde meldet er erst mit den Befunden der erwarteten Wurzeln (Schritt 13). H9 bis H11 laufen nach den Zeitzeugen und lesen die in Schritt 8 berechnete Einordnung; H12 und H13 laufen nach der Bestimmung des Exit-Codes (Abschnitt 10.5).

**H0 Aufruf.** Der Verifier liest jede Datei der Anker-Historie nach Abschnitt 8.8.2 und den Anforderungszeitpunkt nach Abschnitt 10.8; R darf nicht nach dem Prüfzeitpunkt aus `--now` oder der Systemuhr liegen. Ein Verstoß ist ein unbrauchbarer Aufruf (Exit 3 ohne Bericht) mit der Stelle der Datei und dem Pfad des Members. Ohne Anker-Historie entfallen die Schritte H1 bis H11; der Status ist `not_supplied`, die Verbundenheit `not_checked`.

**H1 Sammeln.** Alle Seiten aller Dateien werden zusammengelegt; gleiche `statement_jcs` sind eine Seite (gezählt als doppelt übergeben), mit der Menge ihrer verschiedenen Paare (`server_key_id`, `server_signature`). Kein Paar verdrängt ein anderes, gleich in welcher Reihenfolge die Dateien übergeben sind. Auszüge aus Behältern sind schon in H0 an die Prüfung des Herstellerprotokolls gegangen.

**H2 Jede Seite.** Die Schritte werden der Reihe nach geprüft. Scheitert einer, endet die Prüfung der Seite dort, mit genau diesem Grund (Registry `verifier.anchor_history.page_reasons`, in dieser Reihenfolge):

1. **Schlüssel.** `server_key_id` ist nach Abschnitt 8.8.3 belegt. Sonst `ANCHOR_HISTORY_UNVERIFIED`: Grund `key_other_role`, wenn `server_key_id` einen Schlüssel aus K_cs oder aus der wirksamen Protokollschlüsselliste, eine Anheftung als Gegenzeichnungs- oder Protokollschlüssel, die nach Abschnitt 10.7.4, Schritt R3 (d) nicht entfallen ist, oder einen Eintrag der wirksamen Rollenliste mit einer anderen Rolle als `statements` nennt; sonst Grund `key_not_established`. Eine entfallene Anheftung zählt dafür nicht.
2. **Signatur.** Die Ed25519-Signatur über `UTF-8(statement_jcs)` trägt, geprüft wie die Signatur einer Quittung (Abschnitt 7.1). Sonst `ANCHOR_HISTORY_DEFECTIVE`, Grund `signature`.
3. **Form.** `statement_jcs` besteht aus druckbarem ASCII (Abschnitt 2), ist ein I-JSON-Objekt ohne doppelte Membernamen und ohne einzeln stehende Ersatzzeichen und gleich seiner eigenen JCS-Form. Sonst `ANCHOR_HISTORY_CONTRADICTION`, Grund `page_rules`.
4. **Art.** Das Member `kind` ist die Zeichenkette `ledger.anchor_history.v2`. Sonst `ANCHOR_HISTORY_UNVERIFIED`, Grund `not_v2`: eine Seite der Form v1, ein Bescheid oder ein anderes signiertes Objekt ist eine Aussage des Herstellers, aber keine, die dieser Abschnitt liest.
5. **Inhalt.** Member und Typen genau nach Heartbeat-Spezifikation §9.7 (Form v2) und Registry `cloud_statements.anchor_history_v2`, alle Zeitpunkte genau in der Form `JJJJ-MM-TTThh:mm:ss.sssZ` außer `server_ts` in `roots`, der vom Typ `rfc3339` ist (Abschnitt 2; die gespeicherte Zeichenfolge, Heartbeat-Spezifikation §9.7), jede Seitenregel aus Heartbeat-Spezifikation §9.7. Sonst `ANCHOR_HISTORY_CONTRADICTION`, Grund `page_rules`: Der belegte Schlüssel hat eine regelwidrige Seite signiert.
6. **Fenster.** Stammt der Schlüssel aus der Rollenliste (nicht aus einer Anheftung), gilt für seinen Eintrag `gueltig_ab` ≤ `server_ts`, `server_ts` < `gueltig_bis` und `server_ts` < `widerrufen_ab`, soweit vorhanden, nach der Grammatik und auf Nanosekunden wie in Abschnitt 10.7. Sonst `ANCHOR_HISTORY_UNVERIFIED`, Grund `key_not_valid`.
7. **Kette.** Ist `chain_id = C`, ist die Seite eine **Seite des Pakets**. Sonst ist sie, nachdem alle Seiten des Pakets geprüft sind, eine **verknüpfte Seite**, wenn eine verwendete Seite des Pakets ihre `chain_id` als `predecessor` oder `successor` nennt oder wenn `GENESIS.predecessor_chain.chain_id` sie nennt; `GENESIS` dient dabei nur dem Erkennen, nie als Beleg. Sonst `ANCHOR_HISTORY_UNVERIFIED`, Grund `other_chain`.
8. **Gerät.** `owner_keys` der Seite und `OC(chain_id)` mit der `chain_id` der Seite haben mindestens ein gemeinsames Element. Sonst `ANCHOR_HISTORY_UNVERIFIED`, Grund `owner_differs`. Verlangt ist ein gemeinsamer Schlüssel, keine Gleichheit: Der Server kann Schlüssel kennen, die das Paket nicht zeigt (eine Rotation nach dem Export), und aus der Zeit vor Fassung 1.10 nur den Schlüssel, der bei der Umstellung registriert war (Heartbeat-Spezifikation §9.7).
9. **Signaturzeit.** Mit R ist die Seite **frisch**, wenn `server_ts` ≥ R − W_h gilt. Ist sie nicht frisch oder fehlt R, und trägt der Eintrag ihres Schlüssels in der Rollenliste `widerrufen_ab` (bei einem angehefteten Schlüssel: ein Eintrag der wirksamen Rollenliste mit der Rolle `statements` und demselben Publikey, Abschnitt 8.8.3), dann `ANCHOR_HISTORY_UNVERIFIED`, Grund `signing_time_not_proven`: Den `server_ts` einer solchen Seite bestimmt der Signierer, und wer den widerrufenen Schlüssel hält, könnte ihn zurückdatieren. Ein Schlüssel, der nur `gueltig_bis` trägt (geplanter Wechsel), wird nach Nummer 6 beurteilt wie in Abschnitt 7.1.
10. Sonst ist die Seite **verwendet**: `used_fresh` (Seite des Pakets, frisch), `used_stale` (Seite des Pakets, mit R, nicht frisch), `used_unjudged` (Seite des Pakets, ohne R) oder `used_linked` (verknüpfte Seite).

**Mehrere Paare.** Die Nummern 1, 2, 6 und 9 betreffen das Paar aus Schlüssel und Signatur, die übrigen den Inhalt. Hat eine Seite mehrere Paare, besteht sie jede dieser vier Nummern, solange ein Paar sie und jede frühere dieser Nummern besteht; sie scheitert an einer von ihnen erst, wenn jedes Paar an ihr oder an einer früheren gescheitert ist, und dann mit dem Grund des Paars, das am weitesten kam; kamen mehrere gleich weit, mit dem Grund, der in der Registry-Reihenfolge `page_reasons` später steht (an Nummer 1 also `key_other_role` vor `key_not_established`). Jedes Paar unter einem belegten Schlüssel, dessen Signatur nicht trägt, ergibt `ANCHOR_HISTORY_DEFECTIVE`, Grund `signature`, auch wenn die Seite verwendet wird. Bestehen bei einer verwendeten Seite mehrere Paare alle vier Nummern, gilt für den Bericht (`keys`, `stated_by`, Abschnitt 10.10.2) das mit der kleinsten `server_key_id` (Vergleich der Bytes).

Je Klasse und Grund meldet der Verifier einen Befund, mit der Zahl der Seiten und, für die in Eingabereihenfolge vorderste, ihrer Stelle und ihrem `server_ts`, soweit lesbar. Schlüssel und Signatur kommen zuerst, weil `server_key_id` und die Signatur außerhalb von `statement_jcs` liegen: Unbelegte Bytes legt der Verifier nie aus, und eine Auslegung beschädigter Bytes kann den Exit-Code nie bestimmen. `page_rules` ist ein Widerspruch und kein Mangel, weil die Signatur trägt. `other_chain` hat Exit 1, weil der Prüfer die Seiten beider Ketten eines Kettenwechsels holt (Heartbeat-Spezifikation §9.7) und eine verwechselte Datei eine Aussage über die Prüfumgebung ist, nicht über das Paket.

**Ältere Seiten.** Eine verwendete Seite des Pakets, die nicht frisch ist (etwa aus einem Archiv), geht in die Wurzeln (H6), den Abgleich (H5, H7, H10) und eine Angabe `affiliated` (H12) ein, nie in die Abdeckung (H4), die Vollständigkeit (H11) oder eine Angabe `not_affiliated` (H12). Trägt der Eintrag ihres Schlüssels `widerrufen_ab`, ist sie nach Nummer 9 nicht verwendet.

**H3 Ausstellung nach der Anforderung.** Mit R: Ist keine Seite des Pakets `used_fresh` und hat mindestens eine Seite des Pakets die Nummern 1 bis 8 bestanden, meldet der Verifier einmal `ANCHOR_HISTORY_UNVERIFIED`, Grund `issued_before_request`, mit dem jüngsten übergebenen `server_ts`. Verwendete ältere Seiten neben einer frischen ergeben keinen Befund (Hinweis `archive_pages`).

**H4 Abdeckung.** Über die frischen verwendeten Seiten des Pakets (ohne R über alle verwendeten Seiten des Pakets, dann nur zur Auskunft) wird die Vereinigung der Bereiche I(P) gebildet. Sie ist `complete`, wenn sie alle Baumgrößen ab 0 enthält, `partial`, wenn sie nicht leer und nicht `complete` ist, sonst `none`. Eine Lücke ist ein zusammenhängender nicht abgedeckter Bereich, so weit gefasst wie möglich. Mit R und einer Lücke meldet der Verifier einmal `ANCHOR_HISTORY_UNVERIFIED`, Grund `pages_missing`, mit der Lücke, die bei der kleinsten Baumgröße beginnt. Verlangt ist eine Vereinigung, kein Weg von Seite zu Seite: Seiten aus verschiedenen Abrufen mit verschobenen Schnittstellen decken zusammen ab. Referenzwerte: [0, 501), [501, 1001) und [1001, ∞) sind `complete`; [0, 501) und [1001, ∞) lassen die Lücke [501, 1001); [400, 501) und [501, ∞) lassen [0, 400); [0, 501) allein lässt [501, ∞); [0, 480), [0, 501) und [501, ∞) sind `complete`.

**H5 Seiten untereinander.** Verglichen werden die verwendeten Seiten einer Kette (die Seiten des Pakets untereinander, die verknüpften Seiten einer Kette untereinander), geordnet nach `server_ts` und dann nach den Bytes von `statement_jcs`. Für jedes Paar, in dem A vor B steht, ist jeder Verstoß ein Grund von `ANCHOR_HISTORY_CONTRADICTION`:

- (a) `root_time_differs`: dieselbe Wurzel (`tree_size`, `merkle_root`, `recorded_as`) mit verschiedenem `server_ts`, verglichen in ganzen Millisekunden wie jeder Zeitpunkt dieses Abschnitts; der Server behält den Zeitpunkt, zu dem er sie zuerst festhielt.
- (b) `root_dropped`: Eine Wurzel von A, deren `tree_size` in I(B) liegt, fehlt auf B.
- (c) `root_withheld`: Eine Wurzel von B, deren `tree_size` in I(A) liegt und deren `server_ts` vor A.`server_ts` − W_h liegt, fehlt auf A.
- (d) `fork_dropped`: Ein Fork-Befund von A, dessen `tree_size` in I(B) liegt, fehlt auf B, und B trägt `forks_omitted = 0`.
- (e) `affiliation_narrowed`: Zu einem Zeitpunkt t vor A.`server_ts` gibt A eine Verbundenheit an und B nicht. Ein Zeitraum von A mit `until = null` endet für diesen Vergleich bei A.`server_ts`.
- (f) `affiliation_withheld`: Zu einem Zeitpunkt t vor A.`server_ts` gibt B eine Verbundenheit an, über einen Zeitraum mit `recorded_ts` vor A.`server_ts` − W_h und `merged = false`, und A nicht. Ein zusammengefasster Zeitraum von B (`merged = true`) ergibt diesen Grund nie: Zusammenfassen deckt auch die Zeit zwischen den alten Zeiträumen, die keine frühere Seite zeigen musste (Heartbeat-Spezifikation §9.10, Zeitbezug 4). Hat A einen Zeitraum zurückgehalten, den B nur zusammengefasst zeigt, fällt das an diesem Paar deshalb nicht auf.
- (g) `known_range_narrowed`: A und B nennen einen Wert, und B.`known_since` liegt nach A.`known_since` und nicht nach A.`server_ts`. Nennt B `null` oder einen Zeitpunkt nach A.`server_ts`, ist das kein Grund: Nach einer Übernahme ist der Betreiber bis zu seiner Erklärung nicht bestimmt, und solange eine Erklärung offen ist, bestimmt das Bindungsjournal die Kunden nicht (Heartbeat-Spezifikation §9.10, Zeitbezug 2); B nimmt dann keine Angabe von A über die Zeit bis A.`server_ts` zurück.
- (h) `owner_keys_dropped`: Ein Commitment aus A.`owner_keys` fehlt in B.`owner_keys`.
- (i) `succession_changed`: `predecessor` unterscheidet sich, oder A nennt einen `successor` und B einen anderen oder keinen.
- (j) `reference_decreases`: B.`reference_tree_size` ist kleiner als A.`reference_tree_size`.

Für ein verknüpftes Paar (Kette P des Pakets, verknüpfte Kette L) MÜSSEN beide Angaben zum Wechsel zwischen P und L dasselbe T nennen, wenn beide vorliegen: Ist L die Vorgängerkette (`P.predecessor = {L, T}` auf einer verwendeten Seite des Pakets), muss jede verwendete Seite von L, deren `successor` nicht `null` ist, `successor = {P, T}` tragen; ist L die Nachfolgekette (`P.successor = {L, T}`), muss jede verwendete Seite von L, deren `predecessor` nicht `null` ist, `predecessor = {P, T}` tragen. Sonst Grund `succession_mismatch`. Verglichen wird je Zeitpunkt: So besteht jede ehrliche Änderung (ein Zeitraum, der nach der älteren Seite endete, eine späte Eintragung nach ihr, eine erweiternde Zusammenfassung nach Heartbeat-Spezifikation §9.10), und jedes Verkürzen und jede geteilte Sicht fällt auf, sobald beide Seiten in denselben Lauf gelangen. Zeigt der Hersteller zwei Prüfern verschiedene Seiten und bringt niemand beide zusammen, fällt nichts auf: Seiten der Anker-Historie stehen in keinem Protokoll und an keinem zweiten Ort (Abschnitt 11.2). Die Grundlagen eines Zeitraums vergleicht der Verifier nicht; eine andere Grundlage für die Vergangenheit entfernt keine Angabe. Referenzwerte (A mit einem offenen Zeitraum, ausgestellt `01:02:00`, gegen B): B beendet ihn nach der Ausstellung von A: kein Grund; B beendet ihn davor: `affiliation_narrowed`; B fünf Sekunden später ohne Zeitraum: `affiliation_narrowed` (geteilte Sicht); B fügt einen älteren Zeitraum hinzu, eingetragen nach A: kein Grund; eingetragen mehr als W_h vor A: `affiliation_withheld`; B erweitert durch Zusammenfassen: kein Grund; B verlegt `known_since` auf einen Zeitpunkt nach A.`known_since` und vor A.`server_ts`: `known_range_narrowed`; auf einen Zeitpunkt nach A.`server_ts` oder auf `null`, etwa nach einer Übernahme: kein Grund.

**H6 Historienwurzeln.** Über die verwendeten Seiten des Pakets bildet der Verifier je Paar (t, r) aus `roots` eine **Historienwurzel** mit der Menge ihrer `recorded_as` und mit e, dem frühesten `server_ts` ihrer Aufzeichnungen `countersigned` und `gap_witness`, oder, wenn sie nur gemeldet ist, ihrer Aufzeichnungen `reported`; je Paar (t, r) aus `forks` bildet er einen Fork-Befund. e ist die früheste Zeit, weil eine Wurzel, die zuerst als Lückenzeuge festgehalten und später gegengezeichnet wurde (Heartbeat-Spezifikation §9.2), seit ihrer frühesten Aufzeichnung bestand. Eine gemeldete Aufzeichnung setzt e nur bei einer nur gemeldeten Wurzel, weil der Server ihre Geräte-Signatur nicht als Anker angenommen hat (Heartbeat-Spezifikation §9.2) und der Verifier sie nicht prüfen kann. Verknüpfte Seiten liefern keine Historienwurzeln dieses Pakets.

**H7 Abgleich mit dem Herstellerprotokoll.** Nur, wenn die Prüfung des Protokolls nutzbare Tage mit geprüftem Kettentag-Nachweis für C ergeben hat (Abschnitt 7.4.10, Schritte L3 und L6):

- Für jede Aufzeichnung (t, r, `recorded_as`, s) auf einer verwendeten Seite des Pakets mit `recorded_as` `countersigned` oder `gap_witness`, deren Tag d = day(s) nutzbar ist und deren Nachweis für (C, d) geprüft ist, MUSS der Nachweis eine Wurzel mit denselben vier Werten enthalten; ein Nachweis `absent` enthält keine. Sonst zählt diese Aufzeichnung nicht für ihre Historienwurzel, weder für e noch für `recorded_as`; eine Historienwurzel ohne verbleibende Aufzeichnung ist keine erwartete Wurzel (gezählt als `not_used_vendor_log`). Der Verifier meldet dann je Tag einmal `ANCHOR_HISTORY_CONTRADICTION`, Grund `log_mismatch`.
- Für jede Wurzel (t, r, `recorded_as`, s) eines geprüften Nachweises `present` an einem nutzbaren Tag und jede frische verwendete Seite P des Pakets, bei der t in I(P) liegt und P.`server_ts` ≥ s + W_h gilt, MUSS P eine Wurzel mit denselben t, r und `recorded_as` aufführen. Sonst `ANCHOR_HISTORY_CONTRADICTION`, Grund `log_root_missing`. Bei `countersigned` wird ohne `server_ts` verglichen: Eine frisch ausgestellte Wiederholung einer Gegensignatur hat im Protokoll ein eigenes Blatt mit eigenem `server_ts` (Abschnitt 7.4.2), die Historie führt die Zeit der frühesten Aufzeichnung. Bei `gap_witness` gibt es keine Wiederholung, denn je Wurzel hält der Server höchstens einen Lückenzeugen fest (Heartbeat-Spezifikation §9.2): Führt P die Wurzel als `gap_witness` mit einem anderen `server_ts` als s (verglichen als Zeichenketten), ist das ein Grund `gap_witness_time_differs`.
- Enthalten die geprüften Nachweise der Kette C, gleich an welchen nutzbaren Tagen, zwei Wurzeln `gap_witness` mit denselben t und r und verschiedenem `server_ts`, ist das `ANCHOR_HISTORY_CONTRADICTION`, Grund `gap_witness_time_differs`.

So fällt auf, wenn eine Seite und ein übergebener Kettentag-Nachweis einander widersprechen. Gegen ein Zusammenwirken von Hersteller und Kunde wirkt das nur, wenn der Prüfer den Nachweis des bezeugten Tages selbst schon hält, etwa aus einer früheren Prüfung archiviert. Den Auszug liefert der Hersteller, und der Verifier verlangt Kettentag-Nachweise nur für die Tage der Quittungen im Paket (Schritte L7, L8 in Abschnitt 7.4.10). Lässt ein zusammenwirkender Hersteller die Nachweise der Tage nach der letzten Quittung eines gekürzten Pakets weg, meldet der Verifier nichts (Abschnitt 11.2).

**H8 Einordnung** der Historienwurzeln: Abschnitt 8.8.5.

**H9 Fork-Befunde und Übergabe.**

- Jeder Fork-Befund (t, r) auf verwendeten Seiten des Pakets ist `ANCHOR_HISTORY_FORK`, Grund `fork_listed`, einmal je (t, r); der Bericht sagt, ob `root(t)` gleich r ist, gleich einer festgehaltenen Wurzel oder ob t > N gilt.
- Trägt eine verwendete Seite des Pakets `forks_omitted` > 0: einmal `ANCHOR_HISTORY_FORK`, Grund `forks_omitted`, mit der Zahl.
- Nennt eine verwendete Seite des Pakets `successor = {S, T}`: Eine Historienwurzel mit t > T, deren `recorded_as` `countersigned` oder `gap_witness` enthält, ist `ANCHOR_HISTORY_FORK`, Grund `root_beyond_handover` (Heartbeat-Spezifikation §9.7). Eine nur gemeldete Wurzel dahinter ergibt den Hinweis `reported_beyond_handover`, N > T den Hinweis `package_beyond_handover`. Nur diese beiden Arten sind ein Befund, weil der Server beim Eintragen eines Wechsels allein die Bezugsgröße gegen T prüft; gemeldete Wurzeln hinter T gibt es auch bei ehrlichen Ketten.
- Eine verknüpfte Seite der Vorgängerkette mit `successor = {C, T}`: Ihre Wurzeln mit t > T und `recorded_as` `countersigned` oder `gap_witness` sind `ANCHOR_HISTORY_FORK`, Grund `predecessor_beyond_handover`; gemeldete ergeben den Hinweis `reported_beyond_handover`.
- Hinweise: `predecessor_differs_from_genesis`, wenn `predecessor` einer verwendeten Seite des Pakets eine Kette nennt und `GENESIS.predecessor_chain` keine oder eine andere nennt (nennt die Seite keinen `predecessor`, gibt es den Hinweis nicht); `linked_history_not_supplied`, wenn eine verwendete Seite des Pakets eine Vorgängerkette nennt und keine übergebene Seite mit deren `chain_id` die Nummern 1 bis 5 aus H2 bestanden hat (erst dann ist die `chain_id` einer Seite aus belegten Bytes gelesen).

**H10 Quittungen gegen die Historie.** Für jeden `CHECKPOINT_RECEIPT`, der nach Abschnitt 7.1 als Verankerung zählt, mit `server_ts` s gilt der oberste zutreffende Fall:

1. s < BL: gezählt als `before_legacy_boundary`, kein Befund.
2. Eine verwendete Seite des Pakets führt eine Wurzel `countersigned` mit `tree_size` und `merkle_root` der Quittung: gezählt als `in_history`; weicht deren `server_ts` von s ab (frisch ausgestellte Wiederholung, Heartbeat-Spezifikation §9.1), zusätzlich als `server_ts_differs`, kein Befund.
3. Eine verwendete Seite P des Pakets, bei der die `tree_size` der Quittung in I(P) liegt, hat P.`server_ts` ≥ s + W_h: Die Wurzel fehlt auf einer Seite, die nach der Quittung ausgestellt ist. Ist die Quittung belegt (oben), meldet der Verifier einmal `ANCHOR_HISTORY_CONTRADICTION`, Grund `receipt_not_in_history`, mit der Zahl und der kleinsten `seq`; sonst gibt er den Hinweis `receipt_roots_unverified_not_in_history` und zählt sie als `not_in_history_unestablished`.
4. Sonst: gezählt als `not_covered`.

Der Befund hat Exit 1, weil eine Wiederherstellung beim Hersteller Gegensignaturen aus seinem Bestand verlieren kann; die Kette bleibt ehrlich. **Stichtag.** Bis Fassung 1.9 verlangte diese Spezifikation nicht, dass der Hersteller festgehaltene Wurzeln dauerhaft führt; Wurzeln, die ein Metadatenserver vor BL festgehalten hat, können deshalb in der Historie fehlen. BL ist ein Wert für alle Hersteller in der Registry (`2026-10-04T00:00:00.000Z`), nie ein Member der Seite, damit kein Hersteller ihn je Kette wählen kann.

**H11 Vollständigkeit aus der Historie** (`anchor_history.completeness`). **Hindernde Gründe** sind genau diese:

- (a) `page_rules` (H2, Nummer 3 oder 5) an einer Seite, deren Signatur trägt und deren `statement_jcs` sich als I-JSON-Objekt (Abschnitt 2, doppelte Membernamen abgewiesen) mit dem Member `chain_id` = C lesen lässt. An einer Seite, deren `chain_id` sich so nicht lesen lässt oder eine andere Kette nennt, hindert `page_rules` nicht;
- (b) jeder Grund aus H5 zwischen zwei verwendeten Seiten des Pakets und `succession_mismatch`;
- (c) `log_mismatch`, `log_root_missing` und `gap_witness_time_differs` (H7) und `receipt_not_in_history` (H10);
- (d) jeder Grund von `ANCHOR_HISTORY_FORK`: `fork_listed`, `forks_omitted`, `root_beyond_handover`, `predecessor_beyond_handover` (H9), `history_root_differs` und `reported_root_beyond_package` (Abschnitt 8.8.5).

Nicht hindernd sind die Gründe aus H5 zwischen verknüpften Seiten einer anderen Kette, `page_rules` an anderen Seiten, die Gründe von `ANCHOR_HISTORY_UNVERIFIED` und `ANCHOR_HISTORY_DEFECTIVE` (sie wirken über die Abdeckung und über die verwendeten Seiten) und jeder Hinweis. Der Status ist `established` genau dann, wenn alles gilt: R ist übergeben; die Abdeckung (H4) ist `complete`; kein hindernder Grund liegt vor; kein `MERKLE_INCONSISTENT` stammt aus einer Historienwurzel (dafür zählt auch ein Paar, das zugleich die Quelle `auditor` trägt und dessen Befund nach Abschnitt 10.8 entsteht); mindestens eine Historienwurzel ist nach der Einordnung aus Abschnitt 10.5, Schritt 8 gefunden (Abschnitt 8.8.5). Dann ist `up_to_tree_size` die größte `tree_size` einer gefundenen Historienwurzel, gleich wann sie festgehalten wurde. Sonst ist der Status `partial`, wenn R übergeben ist und eine frische verwendete Seite des Pakets vorliegt, andernfalls `not_established`; `up_to_tree_size` ist dann `null`, und der Grund ist der in dieser Reihenfolge zuerst zutreffende:

| Grund | trifft zu, wenn |
|---|---|
| `not_supplied` | keine Anker-Historie übergeben ist |
| `no_request_time` | R fehlt |
| `no_usable_page` | keine Seite die Nummern 1 bis 7 aus H2 als Seite des Pakets bestanden hat |
| `owner_differs` | mindestens eine Seite des Pakets erst an Nummer 8 gescheitert ist und keine Seite des Pakets verwendet ist |
| `issued_before_request` | H3 den Befund meldet |
| `pages_missing` | H4 den Befund meldet |
| `contradiction` | ein hindernder Grund nach (a), (b) oder (c) vorliegt |
| `fork` | ein hindernder Grund nach (d) vorliegt |
| `root_missing` | ein `MERKLE_INCONSISTENT` aus einer Historienwurzel stammt |
| `no_root_found` | keine Historienwurzel gefunden ist |

Wurzeln aus den 15 Minuten vor R, die dem Paket fehlen, hindern den Status nicht (Hinweis `recent_roots_not_found`).

**H12 Verbundenheit:** Abschnitt 8.8.6.

**H13 Ausgabe.** Das Ergebnis steht in den Berichtsobjekten `anchor_history` und `affiliation` (Abschnitt 10.10), die gefundenen Historienwurzeln zusätzlich in `completeness.sources` (Abschnitt 8.6). Für jedes Paket, das kein Formatfehler ist, sind beide Objekte vorhanden, auch ohne Anker-Historie (`not_supplied`, `not_checked`); bei Exit 3 sind sie `null`. Der Exit-Code folgt Abschnitt 10.3 unverändert.

#### 8.8.5 Einordnung der Historienwurzeln

Wurzeln, die der Prüfer selbst übergibt (Quelle `auditor`), behalten die Regeln aus Abschnitt 10.8. Historienwurzeln (Quelle `anchor_history`) werden mit ihnen nach (t, r) zusammengeführt, mit allen Quellen, also nur mit Wurzeln des Prüfers in der Form `<tree_size>:<merkle_root>`; eine Wurzel des Prüfers ohne `tree_size` bleibt eine eigene Wurzel des Prüfers; trägt ein Paar auch die Quelle `auditor`, gilt für seinen Befund Abschnitt 10.8. Je (t, r) gibt es höchstens einen Befund. Für jede übrige Historienwurzel (t, r) mit e (Schritt H6) gilt der oberste zutreffende Fall; „festgehalten“ heißt, dass ihre `recorded_as` `countersigned` oder `gap_witness` enthalten, „nur gemeldet“, dass sie nur `reported` enthalten:

| Fall | Ergebnis |
|---|---|
| t ≤ N, `root(t)` = r | gefunden: zählt als Verankerung (kein `NO_ANCHOR`, Abschnitt 10.8) und belegt die Vollständigkeit bis t (Abschnitt 8.6) |
| t ≤ N, `root(t)` ≠ r, festgehalten, R übergeben, e < R − W_h | `MERKLE_INCONSISTENT` (Exit 2) |
| t ≤ N, `root(t)` ≠ r, sonst (e ≥ R − W_h, ohne R oder nur gemeldet) | `ANCHOR_HISTORY_FORK`, Grund `history_root_differs` (Exit 1) |
| t > N, festgehalten, R übergeben, e < R − W_h | `MERKLE_INCONSISTENT` (Exit 2), Hinweis `package_ended_before_request` |
| t > N, nur gemeldet, R übergeben, e < R − W_h | `ANCHOR_HISTORY_FORK`, Grund `reported_root_beyond_package` (Exit 1) |
| t > N, R − W_h ≤ e < R | kein Befund; gezählt als `beyond_package_recent`, Hinweis `recent_roots_not_found` |
| t > N, e ≥ R | kein Befund; gezählt als `beyond_package_after_request` |
| t > N, ohne R | kein Befund; gezählt als `beyond_package_unjudged`, Hinweis `no_request_time` (unabhängig von diesem Hinweis nennt der Bericht das Fehlen von R stets, Abschnitt 8.8.1) |

Zu `MERKLE_INCONSISTENT` nennt der Bericht t, r, e, R und für t ≤ N `root(t)`: Der Hersteller hat zu `tree_size` t die Wurzel r am e festgehalten, vor der Anforderung am R, und das Paket widerspricht ihr oder endet davor. Das ist der Befund, den der Abgleich von Hand seit Fassung 1.9 für genau diese Wurzeln ergibt (Abschnitt 8.6); der Verifier fügt die Bindung an das Gerät (Abschnitt 8.8.4, Schritt H2), das Band von 15 Minuten auch innerhalb des Pakets und die signierte Auslassungsmarke `forks_omitted` hinzu und ist damit strenger als das Verfahren von Hand. Eine Wurzel, die ein unredlicher Hersteller erfindet oder die jemand mit einem Bescheidschlüssel auf eine Seite setzt, erschiene ebenso; sie ist diesem Schlüssel zuzurechnen, als erfunden erkennen kann der Verifier sie nicht (Abschnitt 11.2).

Das Band gilt auch innerhalb des Pakets: R ist eine Zeit des Prüfers, e eine des Herstellers, und innerhalb von 15 Minuten kann der Verifier vorher und nachher nicht unterscheiden. Eine abweichende Wurzel, die erst nach R − W_h festgehalten wurde, ist die Aufzeichnung des Herstellers, dass das Gerät zu einer Größe, die dieses Paket abdeckt, eine andere Geschichte signiert hat: ein ehrlicher Export vor einem späteren Zurücksetzen oder ein Umschreiben im Restfenster. Der Verifier meldet sie mit Exit 1 und lässt sie nie weg.

Der Hinweis `package_ended_before_request` nennt den jüngsten `server_ts` einer Quittung des Pakets (eine vom Hersteller signierte Zeit) und die beiden Erklärungen: ein Export, der vor der Anforderung entstand, oder eine Kürzung an einem früheren Siegel (Abschnitt 8.6, Beweisgrenze der Versiegelung). Der Befund bleibt Exit 2 wie in Fassung 1.9.

**Warum nur gemeldete Wurzeln nie Exit 2 ergeben.** Eine gemeldete Wurzel hält der Server aus dem `last_checkpoint` eines Heartbeats oder aus einem Anker fest, den er nicht annimmt (Heartbeat-Spezifikation §9.2). Ihre Geräte-Signatur steht auf keiner Seite, und kein Tag des Herstellerprotokolls nennt sie. Hätte ein Server sie aus der Nachricht einer anderen Appliance übernommen, die die `chain_id` kennt, ergäbe sie sonst gegen ein ehrliches Paket Exit 2. Ab Fassung 1.10 hält der Server eine gemeldete Wurzel nur aus Nachrichten der Appliance fest, der die Kette gehört (Heartbeat-Spezifikation §9.2); der Verifier kann das nicht prüfen und meldet einen Widerspruch aus einer nur gemeldeten Wurzel deshalb mit Exit 1, nie gar nicht.

Referenzwerte (Paket `valid_sealed_export`, N = 32, seine Quittungen bei 15 und 28, R = `2026-01-01T00:58:00.000Z`, also R − W_h = `2026-01-01T00:43:00.000Z`): eine abweichende Wurzel bei `tree_size` 20 mit e = `00:42:59.999` ist `MERKLE_INCONSISTENT`, bei 21 mit e = `00:43:00.000` `ANCHOR_HISTORY_FORK` (die Grenze gehört zum Band); hinter dem Paket ist 33 mit e = `00:42:59.999` `MERKLE_INCONSISTENT`, 34 mit e = `00:43:00.000` `beyond_package_recent`, 35 mit e = `00:58:00.000` `beyond_package_after_request`; 15 und 28 sind gefunden. Ohne R sind 20 und 21 `ANCHOR_HISTORY_FORK` und 33 bis 35 `beyond_package_unjudged`.

#### 8.8.6 Verbundenheit über den Zeitraum des Pakets

Die Angabe des Herstellers zur Verbundenheit (Heartbeat-Spezifikation §9.10) wertet der Verifier so aus:

1. Ohne Anker-Historie: `not_checked`.
2. P ist die Menge der verwendeten Seiten des Pakets (frisch, älter oder ohne R). Ist P leer: `not_determined`, mit dem in dieser festen Reihenfolge zuerst zutreffenden Grund, den eine übergebene Seite erreicht hat: `history_owner_differs`, `history_key_not_established`, `history_key_not_valid`, `history_signing_time_not_proven`, `history_not_v2`, `history_defective`, `history_contradictory`, `history_other_chain` (der Reihe nach zu den Gründen `owner_differs`, `key_not_established` und `key_other_role`, `key_not_valid`, `signing_time_not_proven`, `not_v2`, `signature`, `page_rules` und `other_chain` aus H2). Hat keine übergebene Seite einen dieser Gründe erreicht, etwa weil nur Seiten einer verknüpften Kette verwendet sind, ist der Grund `history_no_package_page`.
3. H* ist die Seite aus P mit dem größten (`server_ts`, Bytes von `statement_jcs`); `as_of` ist H*.`server_ts`.
4. **Zeiträume** sind alle Zeiträume aller Seiten aus P. Das **Ende** eines Zeitraums ist sein `until`; ein Zeitraum mit `until = null` endet beim `server_ts` seiner Seite, außer auf H*, wo er andauert und kein Ende hat. Ein Zeitraum umfasst die Zeitpunkte t mit `from` ≤ t < Ende (halboffen).
5. **Zeitraum des Pakets**, nur aus Zeiten, die der Hersteller signiert hat: `span_from` ist der früheste `server_ts` unter den belegten Quittungen (Abschnitt 8.8.4) und den Aufzeichnungen in `roots` der Seiten aus P; `span_to` ist R, wenn übergeben, sonst `as_of`. Gibt es keine solche Zeit, ist `span_from = span_to`. Nie zählt `ts_chained` oder eine andere Zeit, die der Kunde schreibt.
6. `affiliated` genau dann, wenn sich ein Zeitraum mit dem Zeitraum des Pakets überschneidet, also `from` ≤ `span_to` gilt und der Zeitraum nach Nummer 4 kein Ende hat oder sein Ende nach `span_from` liegt. Ausgegeben werden die Vereinigung der Grundlagen der sich überschneidenden Zeiträume und `vendor_itself`, wenn `vendor` darunter ist.
7. Sonst `not_affiliated` genau dann, wenn alle drei Bedingungen gelten: (a) entweder ist R übergeben und H* frisch, oder R fehlt und `as_of` ist mindestens so spät wie der `server_ts` jeder belegten Quittung; (b) H*.`known_since` ist nicht `null` und liegt nicht nach `span_from`; (c) die Abdeckung nach H4 ist `complete`. Sonst `not_determined`, mit dem Grund der ersten Bedingung, die scheitert: `statement_does_not_cover_package` (a), `known_range_too_short` (b), `history_pages_missing` (c). Bedingung (c) verhindert, dass ein Zurückhalten früher Seiten `span_from` hinter eine beendete Verbundenheit schiebt.
8. Zeiträume, die sich mit dem Zeitraum des Pakets nicht überschneiden, gibt der Verifier mit `overlaps_package = false` aus („außerhalb des Zeitraums dieses Pakets“). Eine Verbundenheit, die Jahre vor der Kette endete, ergibt so für dieses Paket nie `affiliated`.
9. `contradictory` ist `true`, wenn H5 zwischen zwei Seiten aus P einen der Gründe `affiliation_narrowed`, `affiliation_withheld` oder `known_range_narrowed` ergab; ein solcher Grund zwischen Seiten einer verknüpften Kette setzt `contradictory` nicht (Nummer 11). Der Status kommt dann trotzdem aus der Vereinigung, also aus der weiteren Angabe.
10. Gezählt werden `receipts_total` (belegte Quittungen), `receipts_in_periods` (deren `server_ts` in einem Zeitraum liegt, also `from` ≤ `server_ts` < Ende nach Nummer 4, bei einem Zeitraum ohne Ende `from` ≤ `server_ts`) und `receipts_after_statement` (deren `server_ts` nach `as_of` liegt).
11. Für jede verknüpfte Kette gelten dieselben Schritte mit ihren verwendeten Seiten an Stelle von P und dem Zeitraum aus ihren eigenen Aufzeichnungen: Das Paket trägt keine Quittungen dieser Kette, also gibt es für sie keine belegten Quittungen (in Nummer 5, 7 (a) und 10); `span_from` kommt allein aus den `roots` ihrer Seiten; Bedingung 7 (c) liest die Abdeckung nach H4 über ihre eigenen verwendeten Seiten (mit R über die frischen); ihre Zählwerte nach Nummer 10 sind 0. Liegt `span_from` dabei nach `span_to` (etwa bei einer Nachfolgekette, deren Aufzeichnungen alle nach R liegen), gilt Nummer 6 unverändert nach ihrer Formel. Das Ergebnis steht unter `linked` und geht nie in den Status des Pakets ein.

Die Verbundenheit ändert keinen Exit-Code, keinen Befund und nicht die Zahl der Beweisstufe (Abschnitt 10.9); der Bericht zeigt sie an. Der Verifier prüft Signatur, Form, Bindung an Kette und Gerät, Frische und den Abgleich mit anderen übergebenen Seiten, nicht die Richtigkeit der Angabe (Abschnitt 11.2). Fehlt die Historie oder ist keine Seite verwendet, sagt der Bericht „nicht geprüft“ oder „nicht festgestellt“, nie „nicht verbunden“.

Referenzwerte (Zeitraum des Pakets `2026-01-01T00:30:01.000Z` bis `00:58:00.000Z`, zwei belegte Quittungen, `known_since` `2025-12-01T00:00:00.000Z`, H* frisch, wo nicht anders gesagt): ein offener Zeitraum `common_control`: `affiliated`, 2 von 2 Quittungen im Zeitraum; nur ein Zeitraum `former_relation` von `2025-06-01` bis `2025-12-01` (eine Beziehung, die am `2023-12-01` endete, 24 Monate danach, beschnitten auf die Aktivierung am `2025-06-01`; daraus leitet der Server keinen weiteren Zeitraum ab, Heartbeat-Spezifikation §9.10): `not_affiliated`, ein Zeitraum außerhalb; `known_since` `00:45`: `not_determined` (`known_range_too_short`); keine frische Seite: `not_determined` (`statement_does_not_cover_package`); keine frische Seite, ausgestellt `00:42:30` mit `known_since` `00:42:00`: `not_determined` (`statement_does_not_cover_package`, die Frische geht vor; ein späteres `known_since` verböte Seitenregel 9); nur eine Seite mit `since_tree_size` 20: `not_determined` (`history_pages_missing`); `known_since` `null` mit einem offenen Zeitraum: `affiliated`; ein Zeitraum ab `00:50`: `affiliated`, 1 von 2 Quittungen im Zeitraum; ein offener Zeitraum ab `2025-06-01` auf einer älteren Seite vom `00:10`, neben H* vom `01:02` ohne Zeitraum: Der Zeitraum endet um `00:10` und überschneidet sich nicht mit dem Zeitraum des Pakets; `not_affiliated` mit `contradictory` `true` (Grund `affiliation_narrowed` aus H5).

#### 8.8.7 Befunde

Alle vier Klassen haben die Exit-Klasse 1 (Abschnitt 10.4).

| Befundklasse | Bedeutung (Registry) | Gründe |
|---|---|---|
| `ANCHOR_HISTORY_UNVERIFIED` | Anker-Historie übergeben, für dieses Paket aber nicht belegt (Schlüssel nicht durch einen Anker des Prüfers belegt oder nicht gültig, andere Art, andere Kette, anderes Gerät, vor der Anforderung ausgestellt oder unvollständig übergeben) | `key_not_established`, `key_other_role`, `not_v2`, `key_not_valid`, `other_chain`, `owner_differs`, `signing_time_not_proven` (H2); `issued_before_request` (H3); `pages_missing` (H4) |
| `ANCHOR_HISTORY_DEFECTIVE` | Signatur einer übergebenen Seite der Anker-Historie trägt nicht | `signature` (H2) |
| `ANCHOR_HISTORY_CONTRADICTION` | Hersteller hat regelwidrige oder einander widersprechende Aussagen zur Anker-Historie dieser Kette signiert (Seiten untereinander, Quittungen, Herstellerprotokoll) | `page_rules` (H2); `root_time_differs`, `root_dropped`, `root_withheld`, `fork_dropped`, `affiliation_narrowed`, `affiliation_withheld`, `known_range_narrowed`, `owner_keys_dropped`, `succession_changed`, `reference_decreases`, `succession_mismatch` (H5); `log_mismatch`, `log_root_missing`, `gap_witness_time_differs` (H7); `receipt_not_in_history` (H10) |
| `ANCHOR_HISTORY_FORK` | Anker-Historie zeigt eine zweite Fassung dieser Kette oder ihrer Nachfolge (Fork-Befund, abweichende Wurzel, Wurzel hinter der Übergabe) | `fork_listed`, `forks_omitted`, `root_beyond_handover`, `predecessor_beyond_handover` (H9); `history_root_differs`, `reported_root_beyond_package` (Abschnitt 8.8.5) |

| Lage | Klasse | Exit |
|---|---|---|
| Grammatik oder Grenze einer Datei verletzt; `--requested-at` fehlerhaft, mehrfach oder nach `--now` oder der Systemuhr; `--vendor-key-list` kein I-JSON oder mit unbekanntem `format`; eine Anheftung als Bescheidschlüssel fehlerhaft, widersprüchlich oder in zwei Rollen (Abschnitt 10.7.4); ein eingebetteter Auszug verletzt seine Grammatik | keine (unbrauchbarer Aufruf, kein Bericht) | 3 |
| `--requested-at` nach dem Prüfzeitpunkt aus `verify_args.json` | `FORMAT_ERROR` | 3 |
| Schlüssel nicht belegt oder Schlüssel einer anderen Rolle; andere Art; Schlüssel außerhalb seines Fensters; andere Kette; anderes Gerät; widerrufener Schlüssel ohne belegte Signaturzeit; keine frische Seite; Lücke in den Seiten | `ANCHOR_HISTORY_UNVERIFIED` | 1 |
| Signatur trägt nicht | `ANCHOR_HISTORY_DEFECTIVE` | 1 |
| signierte Seite verletzt das Format; Seiten widersprechen einander (Wurzeln, Fork-Befunde, Verbundenheit, bekannter Zeitraum, Eigentümer-Commitments, Kettenwechsel, Bezugsgröße); Quittung fehlt auf einer späteren Seite; Historie und Protokoll widersprechen einander | `ANCHOR_HISTORY_CONTRADICTION` | 1 |
| Fork-Befund aufgeführt oder ausgelassen; abweichende Wurzel im Paket, festgehalten im Band, danach oder ohne R; nur gemeldete Wurzel, die dem Paket widerspricht oder vor R − W_h hinter dem Paket liegt; gegengezeichnete oder als Lückenzeuge festgehaltene Wurzel hinter der Übergabe | `ANCHOR_HISTORY_FORK` | 1 |
| gegengezeichnete oder als Lückenzeuge festgehaltene Wurzel, die dem Paket widerspricht oder hinter ihm liegt, festgehalten vor R − W_h | `MERKLE_INCONSISTENT` | 2 |
| Wurzel hinter dem Paket im Band; ältere Seiten; gemeldete Wurzel hinter der Übergabe; Paket hinter der Übergabe; Verbundenheit jedes Status | keine (gezählt, Hinweis oder Status) | keiner |
| Manifest-Feld, das eine Verbundenheit behauptet | `UNKNOWN_MANIFEST_FIELD` (Abschnitt 10.6, Regel 5) | 1 |

**Mehrfachmeldungen.** Je Klasse und Grund ein Befund, mit der Zahl und dem frühesten Vorkommen; `MERKLE_INCONSISTENT`, `fork_listed`, `history_root_differs` und `reported_root_beyond_package` einmal je (t, r); `log_mismatch` einmal je Tag.

**Hinweise** (kein Befund, Registry `verifier.anchor_history.notes`, in dieser Reihenfolge): `requested_at_unused` (R ohne Anker-Historie übergeben), `no_request_time`, `archive_pages`, `recent_roots_not_found`, `package_ended_before_request`, `reported_beyond_handover`, `package_beyond_handover`, `predecessor_differs_from_genesis`, `linked_history_not_supplied`, `receipt_roots_unverified_not_in_history`.

**Warum keine der vier Klassen Exit 2 hat.** Jeder Fall kann bei einer ehrlichen Kette eintreten: ein beschädigter Abruf, ein Ausfall oder Datenverlust beim Hersteller, sein Fehlverhalten, ein Fehler in den Angaben des Prüfers, die Übernahme einer `chain_id`. „Ungültig“ ist nachgewiesener Manipulation vorbehalten (Abschnitt 8.6). `ANCHOR_HISTORY_CONTRADICTION` und `ANCHOR_HISTORY_FORK` setzen die Signatur eines belegten Schlüssels voraus; wer nur den Transportweg kontrolliert, kann sie nicht erzeugen. Vier Klassen statt einer, weil der nächste Schritt des Prüfers verschieden ist: Angaben berichtigen oder Seiten nachholen; neu abrufen; den Hersteller zur Rede stellen; die zweite Geschichte des Schlüsselinhabers untersuchen. Ab Fassung 1.10 führt aus der Anker-Historie ein Weg zu Exit 2, und er führt zu einer bestehenden Klasse: `MERKLE_INCONSISTENT` aus einer Wurzel, die der Hersteller mehr als 15 Minuten vor der Anforderung gegengezeichnet oder als Lückenzeuge festgehalten hat (Abschnitt 8.8.5). Dieser Weg setzt eine Seite unter einem Bescheidschlüssel voraus (Abschnitt 8.8.3); ein Gegenzeichnungsschlüssel allein eröffnet ihn nicht. Wie Hersteller und Kunde zusammenwirken können und was dagegen wirkt, nennt Abschnitt 11.1 (Klasse `collusion`).

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
    ├── vendor/schluesselliste.json  # optional: signierte Liste der Gegenzeichnungsschlüssel (10.7.1)
    └── tsa/*.pem           # optional: Zertifikate der Zeitstempelstelle (7.3)
```

- Jede Segmentdatei enthält Einträge als JSON Lines (ein Eintrag je Zeile, `\n`-getrennt), in aufsteigender `seq`-Reihenfolge; Segmente überlappen nicht und decken zusammen lückenlos `seq = 1 … tree_size` des Manifests ab. Getrennt wird ausschließlich an `\n` (U+000A): `\r`, U+0085, U+2028 und U+2029 trennen keine Einträge; die letzten drei stehen in einem JSON-String roh (RFC 8785), ein `\r` vor dem `\n` ist Leerraum des JSON-Texts. `\n` am Dateiende (eines oder mehrere) wird übergangen; jede andere Zeile (auch eine leere oder eine nur aus Leerraum bestehende) MUSS ein Eintrag sein, sonst `FORMAT_ERROR` (Exit 3).
- Die Namen der Einträge im ZIP stehen in Normalform: Pfadteile getrennt durch `/`, kein führendes `/`, kein leerer Pfadteil, kein Pfadteil `.` oder `..`, kein `\`, und kein Name kommt zweimal vor. Verzeichniseinträge (Name endet auf `/`) werden übergangen. Liegt `manifest.json` nicht auf oberster Ebene und teilen alle Einträge genau ein oberstes Verzeichnis, wird dieses abgelöst (ein gezipptes Verzeichnis); dasselbe gilt ab Fassung 1.9 für ein als Verzeichnis vorgelegtes Paket, das genau ein Verzeichnis und sonst nichts enthält. Ein als Verzeichnis vorgelegtes Paket darf nur Dateien und Verzeichnisse enthalten; eine symbolische Verknüpfung oder etwas anderes (eine benannte Pipe, ein Gerät) ist `FORMAT_ERROR`. Ein Paket, das diese Regeln verletzt, ist ein Formatfehler (`FORMAT_ERROR`, Exit 3): Zwei Verifier dürfen im selben Archiv nicht verschiedene Dateien sehen.
- Dateinamen der Segmente sind nicht beweistragend; maßgeblich ist die Segmentliste des Manifests (Datei, SHA-256, `first_seq`, `last_seq`). Ab Fassung 1.9 ausdrücklich: `file` folgt der Grammatik `^[A-Za-z0-9._-]{1,128}$`, ist weder `.` noch `..` und wird ausschließlich als `segments/<file>` gelesen, nie an anderer Stelle des Pakets und nie außerhalb davon. Die Segmente werden nach `first_seq` geordnet gelesen, unabhängig von ihrer Reihenfolge in der Liste; ihre deklarierten Bereiche MÜSSEN lückenlos bei 1 beginnen, dürfen sich nicht überlappen und MÜSSEN bei `tree_size` ≥ 1 enden, und jede Datei MUSS genau `last_seq − first_seq + 1` Einträge enthalten. Jede Verletzung ist `FORMAT_ERROR` (Exit 3), und die Prüfung endet dort (Abschnitt 10.5). Ob die Einträge selbst lückenlos nummeriert sind, prüft Abschnitt 3 (`SEQ_BREAK`).
- `keys/` spiegelt die Schlüssel des Manifests wider (eine Datei je `key_id`); bei Abweichung gilt das Manifest. Die Hersteller-Schlüssel aus Manifest und `keys/vendor/` sind **nicht beweistragend** (Abschnitt 7.1): Sie führen zu `RECEIPT_UNVERIFIED`, solange kein Anker des Prüfers sie belegt. `keys/vendor/schluesselliste.json` ist optional und zählt nur, wenn ihre Signatur gegen eine Herstellerwurzel des Prüfers trägt (Abschnitt 10.7.1); dort steht nie eine Rollenliste (Abschnitt 10.7.2). `keys/tsa/` ist optional und **nicht beweistragend** (Abschnitt 7.3): Zertifikate von dort führen zum Befund `TIME_ANCHOR_UNVERIFIED`, weil sie aus derselben Hand stammen wie die Kette. Ab Fassung 1.10 SOLL ein Prüfpaket kein Zertifikat tragen, das ein Prüfer als Vertrauensanker übergeben würde; `keys/tsa/` bleibt eine Lesehilfe (Abschnitt 7.3).
- **Angaben des Prüfers gehören nicht ins Paket (ab Fassung 1.10).** Tageseinträge, Auszüge und Protokollschlüssellisten des Herstellerprotokolls (Abschnitt 7.4), Seiten der Anker-Historie (Abschnitt 8.8), Rollenlisten (Abschnitt 10.7.2) und andere Schlüssellisten, die der Prüfer übergibt, eine Angabe zur Verbundenheit, eine Benennung von Wurzeln als qualifiziert und ein Anforderungszeitpunkt (Abschnitt 10.8) stehen nie in einem Prüfpaket, und ein Verifier liest sie nie daraus. Eine solche Datei außerhalb von `content/` bleibt wie bisher unbeachtet (kein Befund); unter `content/` ist sie `CONTENT_MISMATCH` wie jede andere dort nicht definierte Datei. Das Paket und sein Layout ändern sich mit Fassung 1.10 nicht.
- Optional KANN das Paket vorgelegte Berichte (HTML/PDF) und bewusst offengelegte Klartexte mit Salts enthalten; dann prüft der Verifier zusätzlich `REPORT_MISMATCH` bzw. `CONTENT_MISMATCH`.
- **Vorgelegte Klartexte (ab Fassung 1.9 festgelegt)** liegen unter `content/`. Die Vorlage für den `AI_CALL` mit `seq` n besteht aus `content/<n>.salts.json` und `content/<n>.request` und/oder `content/<n>.response`; `<n>` hat die Form `[1-9][0-9]*`. Die Klartextdateien enthalten genau die Bytes der HMAC-Nachricht (Abschnitt 9.1). Die Salt-Datei ist I-JSON (Abschnitt 2) mit genau diesen Membern: `seq` (int, gleich n), `request_salt` und `response_salt` (je hex64, vorhanden genau dann, wenn die zugehörige Klartextdatei vorliegt) und optional `vault_ref` (string, wird nicht ausgewertet). Für jeden vorgelegten Teil MUSS der Eintrag n ein `AI_CALL` mit nicht-leerem `<teil>_commitment` sein, und das HMAC MUSS übereinstimmen. Jede andere Datei unter `content/` (ein anderer Name, eine Datei in einem Unterverzeichnis, ein Klartext ohne Salt, ein Salt ohne Klartext, eine nicht konforme Salt-Datei) ist `CONTENT_MISMATCH`, einmal je Datei. Neben einer nicht konformen Salt-Datei ist auch jeder Klartext desselben n `CONTENT_MISMATCH`: Er ist nicht prüfbar. Erfüllt ein vorgelegter Teil die Bedingung an Eintrag n nicht, ist seine Klartextdatei `CONTENT_MISMATCH`, die konforme Salt-Datei daneben nicht. Ein leeres Verzeichnis ergibt nichts.

### 10.2 manifest.json

Felder (Registry `pruefpaket_manifest`):

| Feld | Typ | Beschreibung |
|---|---|---|
| `spec_version` | version `"MAJOR.MINOR"` | Spezifikationsversion des Pakets; `MAJOR` und `MINOR` sind Dezimalzahlen ohne führende Nullen; diese Fassung schreibt `"1.10"` und nimmt ältere Minor-Versionen derselben MAJOR-Version an; Annahme anderer Versionen: Abschnitt 10.6 |
| `chain_id` | uuid | Kette dieses Pakets |
| `created_ts` | rfc3339 | Erzeugungszeit des Pakets |
| `tree_size` | int, min 0 | Zahl der enthaltenen Einträge |
| `segments` | array of object | je Segment: `file` (string, maxlen 128), `sha256` (hex64), `first_seq` (int, min 1), `last_seq` (int, min 1) |
| `device_pubkeys` | array of object | je Schlüssel: `key_id` (string, maxlen 64), `pubkey` (hex64) |
| `vendor_pubkeys` | array of object | je Schlüssel: `key_id` (string, maxlen 64), `pubkey` (hex64) |

Der Verifier MUSS die SHA-256-Summen der Segmentdateien gegen das Manifest prüfen; jede Abweichung sowie unlesbares/schema-widriges Material ist `FORMAT_ERROR` (Exit 3).

Mit Fassung 1.10 kommt kein Feld hinzu. Ein Feld, das etwa eine Verbundenheit, einen Anforderungszeitpunkt oder ein Ergebnis der Abschnitte 7.4 und 8.8 behauptet, ist ein unbekanntes Feld nach Abschnitt 10.6, Regel 5 (`UNKNOWN_MANIFEST_FIELD`); der Verifier liest daraus nichts.

### 10.3 Exit-Codes

| Exit | Bedeutung |
|---|---|
| 0 | gültig ohne Befunde |
| 1 | gültig mit Befunden |
| 2 | ungültig |
| 3 | Formatfehler |
| 4 | unvollständig: Kettenende nicht versiegelt (Abschnitt 8.6) |

Bestimmung: Ist das Paket nicht lesbar oder schema-widrig → **3**. Sonst: mindestens ein Befund der Exit-Klasse 2 → **2**; sonst mindestens ein Befund der Exit-Klasse 4 → **4**; sonst mindestens ein Befund der Exit-Klasse 1 → **1**; sonst → **0**. Maßgeblich ist diese Rangfolge (3 vor 2 vor 4 vor 1 vor 0, Registry `verifier.exit_precedence`), nicht die Größe der Zahl. Die Semantik ist strikt getrennt: „kryptographisch gültig ja/nein" (0/1/4 vs. 2/3), der Status des Kettenendes (0/1 versiegelt, 4 unvollständig) und die Befundliste. Exit 4 ist kein Fehlschlag: Die geprüften Einträge sind intakt, nur ihre Vollständigkeit belegt das Paket nicht. Gibt ein Verifier sein Urteil zusätzlich maschinenlesbar aus, MUSS er Exit 4 als eigenen Status ausweisen und DARF ihn nicht als „ungültig“ kennzeichnen; ein Werkzeug, das nur ein Ja/Nein-Merkmal ausliest, würde sonst jede ehrliche Kette aus dem laufenden Betrieb verwerfen. Eine ehrlich ausgewiesene Lücke macht die Kette nicht ungültig; eine verschwiegene schon.

Die Beweisstufe (Abschnitt 10.9) und die übrigen Berichtsangaben (Abschnitt 10.10) sind kein Teil des Urteils und ändern den Exit-Code nicht.

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
| `VENDOR_LOG_UNVERIFIED` | 1 | Herstellerprotokoll übergeben, aber nicht durch Anker des Prüfers belegt oder nicht vollständig übergeben |
| `VENDOR_LOG_DEFECTIVE` | 1 | übergebenes Herstellerprotokoll trägt nicht (Signatur, Zeitstempel oder Nachweis) |
| `VENDOR_LOG_CONTRADICTION` | 1 | Hersteller hat einander widersprechende oder regelwidrige Protokollaussagen signiert |
| `RECEIPT_NOT_LOGGED` | 1 | Quittung fehlt im bezeugten Herstellerprotokoll ihres Tages |
| `LOGGED_ROOT_MISMATCH` | 1 | im Herstellerprotokoll festgehaltene Wurzel passt nicht zum Paket |
| `ANCHOR_HISTORY_UNVERIFIED` | 1 | Anker-Historie übergeben, für dieses Paket aber nicht belegt (Schlüssel nicht durch einen Anker des Prüfers belegt oder nicht gültig, andere Art, andere Kette, anderes Gerät, vor der Anforderung ausgestellt oder unvollständig übergeben) |
| `ANCHOR_HISTORY_DEFECTIVE` | 1 | Signatur einer übergebenen Seite der Anker-Historie trägt nicht |
| `ANCHOR_HISTORY_CONTRADICTION` | 1 | Hersteller hat regelwidrige oder einander widersprechende Aussagen zur Anker-Historie dieser Kette signiert (Seiten untereinander, Quittungen, Herstellerprotokoll) |
| `ANCHOR_HISTORY_FORK` | 1 | Anker-Historie zeigt eine zweite Fassung dieser Kette oder ihrer Nachfolge (Fork-Befund, abweichende Wurzel, Wurzel hinter der Übergabe) |
| `SPEC_NEWER` | 1 | Paket nutzt eine neuere Minor-Version der Spezifikation als der Verifier |
| `UNKNOWN_ENTRY_TYPE` | 1 | Eintragstyp dieser Verifier-Version unbekannt; Eintrag geprüft, Nutzlast nicht |
| `UNKNOWN_MANIFEST_FIELD` | 1 | Manifest-Feld dieser Verifier-Version unbekannt; angenommen und gemeldet, alle bekannten Prüfungen laufen weiter |
| `FORMAT_ERROR` | 3 | Prüfpaket nicht lesbar/schema-widrig |

**COSE Receipts (ab Fassung 1.11, Abschnitt 7.7).** Abschnitt 7.7.7 fügt zwei Klassen der Exit-Klasse 1 hinzu: `COSE_RECEIPT_DEFECTIVE` (übergebene COSE-Gegensignatur trägt nicht: Profil oder Signatur) und `COSE_RECEIPT_MISMATCH` (COSE-Gegensignatur nennt eine Wurzel, die zum Paket nicht passt). Sie stehen in diesem Entwurf noch nicht in der Tabelle oben und nicht in der Registry `verifier.finding_classes`; beide kommen dorthin, sobald beide Referenz-Verifier Abschnitt 7.7 umsetzen. Bis dahin gilt der Kopf dieser Spezifikation: Bei Abweichungen gilt die Registry, und ein Verifier meldet diese Klassen nicht.

Mit Fassung 1.10 kommen elf Klassen hinzu, fünf des Herstellerprotokolls (Abschnitt 7.4.11), vier der Anker-Historie (Abschnitt 8.8.7) und zwei der COSE Receipts (Abschnitt 7.7.7); die Liste umfasst damit 39 Klassen, 37 in der Tabelle oben und die zwei der COSE Receipts. Alle elf haben die Exit-Klasse 1, weil jeder ihrer Fälle bei einer ehrlichen Kette eintreten kann; kein Name endet auf `_INVALID`, denn jede Klasse mit dieser Endung hat die Exit-Klasse 2. Ein Fall, der ab Fassung 1.10 über eine Angabe des Prüfers zu Exit 2 führt, gehört zu einer bestehenden Klasse: `MERKLE_INCONSISTENT` aus einer Wurzel der Anker-Historie (Abschnitt 8.8.5). Die Schlüsselrollen (Abschnitt 10.7.4), die Füller (Abschnitt 7.4.4), Bedingung (7) der Beweisstufe (Abschnitt 10.9.1), der Eintragstyp `DATA_ACCESS` (Abschnitt 4.25), die Formate `/2` mit der Signatur nach ML-DSA-87 (Abschnitte 7.4.5a, 7.4.7a, 7.4.8a) und die COSE Receipts der Tage (Abschnitt 7.4.10, Schritt L3a) bringen keine Klasse hinzu.

### 10.5 Prüfablauf (normative Mindestprüfungen)

Ein konformer Verifier führt mindestens aus: (1) Paket-/Schema-Prüfung inkl. Segment-Hashes, mit den Annahmeregeln der Vorwärtskompatibilität (Abschnitt 10.6); (2) `seq`-Lückenlosigkeit und Hash-Kette (`prev_hash`/`entry_hash` mit eigener JCS-Kanonisierung); (3) Checkpoint-Signaturen inkl. KEY_ROTATION-Vertrauenskette und Checkpoint-Verkettung; (4) Merkle-Wurzeln aller Checkpoints neu berechnen; Konsistenz aller verankerten Wurzeln paarweise; (5) Quittungen: Herkunft des Hersteller-Schlüssels und Gegensignatur nach Abschnitt 7.1, ab Fassung 1.10 mit der Rollenprüfung nach Abschnitt 10.7.4, Übereinstimmung mit Checkpoint, Präfix-Passung (Fork); (6) Lücken-Semantik nach Abschnitt 8; (7) Zeitplausibilität nach Abschnitt 9.2; (8) SEAL/RESUME-Handover und Kettenende (Abschnitt 8.4, 8.6); (9) optional vorgelegte Klartexte und Berichte; Löschsperren (Abschnitt 9.3); (10) Freshness-Fenster; (11) Zeitzeugen nach Abschnitt 7.3, soweit vorhanden, ab Fassung 1.10 nach dem Zeitstempelprofil (Abschnitt 7.5); (12) Restfenster messen und ausgeben (Abschnitt 11.2); ab Fassung 1.10 außerdem (13) gedeckte Strecken messen und ausgeben (Abschnitt 11.2); (14) das Herstellerprotokoll nach Abschnitt 7.4, soweit übergeben, ab Fassung 1.10 mit den Formaten `/2` und den COSE Receipts der Tage (Schritt L3a); (14a) ab Fassung 1.10 die COSE-Gegensignaturen nach Abschnitt 7.7.6 (Schritt K), soweit übergeben; (15) die Anker-Historie und die Verbundenheit nach Abschnitt 8.8, soweit übergeben; (16) die Beweisstufe bestimmen und ausgeben (Abschnitt 10.9).

**Verarbeitungsstufen (ab Fassung 1.9).** Das Paket wird in dieser Reihenfolge gelesen: (1) `manifest.json` als I-JSON, Signale nach den Regeln 1 und 5 (Abschnitt 10.6), dann sein Schema; (2) die Segmenttabelle (Abschnitt 10.1); (3) je Segment in `first_seq`-Reihenfolge: Datei vorhanden, SHA-256, Zahl der Zeilen (für alle Segmente, bevor Stufe 4 eine Zeile liest); (4) je Zeile: JSON; ist sie ein Objekt, die Signale nach den Regeln 1 und 2 aus `spec_version` und `event_type` (soweit Zeichenketten), dann ihr Schema und ihre `chain_id`, weiter mit den übrigen Zeilen; (4a) die Hersteller-Schlüsselliste und die Salt-Dateien `content/<n>.salts.json` (nur Namen dieser Form) nach der Zahlregel aus Abschnitt 2, je Datei höchstens ein `FORMAT_ERROR`; (5) die Prüfungen der Kette, darunter die vorgelegten Klartexte. Scheitert eine der Stufen 1 bis 3, entfallen alle späteren. Signale werden für jedes bis dahin gelesene Objekt gemeldet, auch neben seinem Schemafehler (Regel 3), nie aber aus einem fehlenden Segment oder einem mit falscher SHA-256. Scheitert Stufe 4 an einer Zeile, laufen die übrigen Zeilen weiter, Stufe 5 entfällt; scheitert Stufe 4a, entfällt Stufe 5 ebenso.

**Reihenfolge in Stufe 5 (ab Fassung 1.10).** Die Angaben des Prüfers aus Abschnitt 10.8 liest der Verifier beim Aufruf, vor Stufe 1 (Abschnitte 7.4.10, Schritt L0; 8.8.4, Schritt H0). Stufe 5 führen beide Referenz-Verifier in dieser Reihenfolge aus, denn spätere Schritte lesen Ergebnisse früherer:

1. Anforderungszeitpunkt gegen den Prüfzeitpunkt aus `verify_args.json`, wenn der Prüfer diesen verlangt hat (Abschnitt 10.8); liegt R danach, ist das `FORMAT_ERROR` (Exit 3), und die übrigen Schritte der Stufe 5 entfallen (gegen einen Prüfzeitpunkt aus `--now` oder der Systemuhr ist derselbe Fall ein unbrauchbarer Aufruf, Abschnitt 10.8);
2. `seq`, Hash-Kette und die Wurzeln aller Präfixe (Abschnitte 3, 5);
3. Checkpoints (Abschnitt 6); dabei hält der Verifier die Geräteschlüssel der Kette fest (`GENESIS.device_pubkey` und jeder nach Abschnitt 6.4 legitimierte Schlüssel aus `KEY_ROTATION`);
4. Schlüssel des Herstellers: Liste des Pakets, Listen des Prüfers, Rollenprüfung, K_cs, Protokollschlüssel aus Listen der Formate `/1` und `/2` und, ab Fassung 1.10, die Transparenzschlüssel T (Abschnitte 7.1, 7.4.10 Schritt L1, 7.7.5, 8.8.3, 10.7.4); Rollenprüfung und Schritt L1 laufen nur hier, mit oder ohne Auszug, Schritt L1 sobald eine Protokollschlüsselliste oder eine Anheftung eines Protokollschlüssels übergeben ist;
5. Quittungen (Abschnitt 7.1), je Quittung mit der Herkunft ihres Schlüssels, der Herkunft der Liste und dem Vergleich mit den Geräteschlüsseln;
6. Herstellerprotokoll (Abschnitt 7.4.10, Schritte L2 bis L9, ab Fassung 1.11 mit Schritt L3a); ab Fassung 1.11 danach, als Schritt 6a, die COSE-Gegensignaturen (Schritt K, Abschnitt 7.7.6);
7. Anker-Historie, Schritte H1 bis H7 (Abschnitt 8.8.4);
8. Abgleich der erwarteten Wurzeln: Wurzeln des Prüfers und Historienwurzeln mit ihren Quellen; hier berechnet der Verifier die Einordnung nach Abschnitt 8.8.5 (Schritt H8), die Schritt 11 liest (Abschnitte 8.8.5, 10.8);
9. Restfenster und gedeckte Strecken (Abschnitt 11.2);
10. Zeitzeugen (Abschnitte 7.3, 7.5), je Token und je Wurzel mit den Angaben, die die Beweisstufe liest (Abschnitt 10.9);
11. Anker-Historie, Schritte H9 bis H11, mit der Einordnung aus Schritt 8;
12. Vorhandensein einer Verankerung (`NO_ANCHOR`, Abschnitt 7; gefundene Historienwurzeln zählen mit);
13. Befunde der erwarteten Wurzeln, mit den Befunden der in Schritt 8 berechneten Einordnung nach Abschnitt 8.8.5 (Schritt H8);
14. die übrigen Prüfungen in der bisherigen Reihenfolge, von den Befunden einzelner Einträge über Löschsperren, Stille, Uhrzeit, Sofort-Checkpoints, Handover, Kettenende und Freshness bis zu vorgelegten Klartexten und Berichten;
15. Abschluss: zuerst der Exit-Code nach Abschnitt 10.3, danach die Verbundenheit (Abschnitt 8.8.6), die Berichtsobjekte (Abschnitt 10.10, ab Fassung 1.10 mit `cose_receipts`) und die Beweisstufe (Abschnitt 10.9), die den Exit-Code nicht mehr ändern.

Der Abgleich der erwarteten Wurzeln (Schritt 8) steht damit nach den Checkpoints und Quittungen, nicht mehr davor. Das ändert kein Ergebnis: Gelesen werden die erwarteten Wurzeln nur bei der Vollständigkeit aus der Anker-Historie (Schritt 11), beim Vorhandensein einer Verankerung (Schritt 12), bei ihren Befunden (Schritt 13) und bei der Aussage zur Vollständigkeit (Abschnitt 8.6), und alle vier kommen nach Schritt 8.

### 10.6 Vorwärtskompatibilität

Vorbild ist die Regel für unbekannte Ankertypen (ab Fassung 1.10 Abschnitt 7.6): Was ein Verifier nicht kennt, ist ein Befund, kein Fehler (mit einer bewusst gezogenen Grenze am Envelope).

**Regel 1: Versionsannahme.** `spec_version` hat die Form `"MAJOR.MINOR"` (Typ `version`, Abschnitt 2). Ein Verifier, der die Version `1.m` implementiert, MUSS Einträge und Manifeste mit `spec_version = "1.n"` annehmen. Für `n ≤ m` gilt der Normalfall ohne besonderen Befund. Für `n > m` MUSS er genau EINMAL je Prüfpaket den Befund `SPEC_NEWER` (Exit-Klasse 1) melden und ALLE Prüfungen, die er kennt, weiter ausführen, insbesondere die Mindestprüfungen aus Abschnitt 10.5. Eine `spec_version` mit anderem `MAJOR` als dem des Verifiers ist `FORMAT_ERROR` (Exit 3); ebenso eine `spec_version`, die nicht die Form aus Abschnitt 2 hat (etwa mit führenden Nullen). `MINOR` wird als ganze Zahl verglichen, ohne Obergrenze der Stellenzahl.

**Regel 2: Unbekannte Eintragstypen.** Ein `event_type`, den der Verifier nicht kennt (Typ `open_enum`, Abschnitt 2), ist KEIN Schemafehler. Der Verifier MUSS den Befund `UNKNOWN_ENTRY_TYPE` (Exit-Klasse 1) melden, einmal je unbekanntem Typnamen, mit der `seq` des ersten Vorkommens. Er MUSS den Eintrag in die `seq`-, Hash-Ketten- und Merkle-Prüfung einbeziehen (diese hängen nicht am Typ), MUSS für `payload` nur prüfen, dass es ein JSON-Objekt ist, und DARF den Typ NICHT als kritisch (Sofort-Checkpoint-Pflicht, Abschnitt 4 und 6) behandeln. Das ist die konservative Richtung, und sie ist als solche zu verstehen: Ein künftiger kritischer Typ wird von einem älteren Verifier NICHT auf seinen Sofort-Checkpoint geprüft; ein fehlender Checkpoint nach einem unbekannten Typ ist für diesen Verifier kein `MISSING_CHECKPOINT`. Für die Stille-Regeln (Abschnitt 8.1, 8.2) ist ein unbekannter Typ kein deckender `GAP` oder `RESTART`; wie jeder Eintrag begrenzt er lediglich das Stillefenster nach Abschnitt 8.2.

**Regel 3: Envelope bleibt geschlossen.** Ein Envelope-Feld, das Abschnitt 3 nicht definiert, bleibt `FORMAT_ERROR` (Exit 3): Das Envelope ist der Vertrag; ein neues Envelope-Feld ist eine `MAJOR`-Änderung. Die `payload`-Felder BEKANNTER Eintragstypen bleiben strikt nach Abschnitt 2 (Vollständigkeit, keine undefinierten Felder); für das Prüfpaket-Manifest gilt dagegen Regel 5. Befunde nach den Regeln 1, 2 und 5 werden auch dann gemeldet, wenn dasselbe Objekt daneben einen Schemafehler (`FORMAT_ERROR`) trägt; der Exit-Code folgt Abschnitt 10.3. Eine MINOR-Version DARF den Wertebereich eines bestehenden `payload`-Feldes verengen, wenn jeder Wert des engeren Bereichs auch im älteren Schema gültig ist; die Verengung gilt für Einträge, deren eigene `spec_version` diese MINOR-Version oder eine neuere ist, und ein älterer Verifier nimmt sie ohne die Verengung an (ab Fassung 1.8: `GENESIS.license_id`, Abschnitt 4.1).

**Regel 4: Ankertypen.** Für unbekannte Ankertypen gilt ab Fassung 1.10 Abschnitt 7.6.

**Regel 5: Das Prüfpaket-Manifest ist erweiterbar.** Ein Feld in `manifest.json`, das Abschnitt 10.2 nicht definiert, ist KEIN Schemafehler. Der Verifier MUSS den Befund `UNKNOWN_MANIFEST_FIELD` (Exit-Klasse 1) melden, einmal je unbekanntem Feldpfad, mit dem Pfad im `detail`, und ALLE Prüfungen, die er kennt, weiter ausführen, insbesondere die Mindestprüfungen aus Abschnitt 10.5. Das gilt für das Manifest-Objekt selbst UND für die Objekte in seinen Feldern `segments`, `device_pubkeys` und `vendor_pubkeys`; Feldpfade werden ohne Index gemeldet (`manifest.segments[].feld`), damit ein zusätzliches Feld in hundert Segmenten einen Befund ergibt und nicht hundert. Die DEFINIERTEN Felder bleiben unverändert pflichtig und streng: ein fehlendes, falsch getyptes oder außerhalb seines Wertebereichs liegendes definiertes Feld bleibt `FORMAT_ERROR` (Exit 3). Der Befund gilt unabhängig von `spec_version`: auch ein Manifest, das die Version des Verifiers erklärt, aber ein ihm unbekanntes Feld trägt, wird angenommen und gemeldet; ein Erzeuger, der ein Feld ohne Versionssprung hinzufügt, verletzt diese Spezifikation, und der Verifier verlässt sich nicht darauf, dass er es nicht tut.

Der Unterschied zu Regel 3 ist nicht Bequemlichkeit, sondern Beweislast. Das Manifest geht in **keine** Hash-Kette, keine Merkle-Wurzel und keine Signatur ein; ein zusätzliches Feld dort kann keine kryptographische Prüfung verändern. Ein zusätzliches Envelope-Feld verändert dagegen die JCS-Bytes und damit `entry_hash`; deshalb bleibt das Envelope geschlossen und ist eine `MAJOR`-Frage. Und der Befund ist der Preis für die Annahme: Ein Verifier, der ein Manifest-Feld nicht kennt, kann nicht wissen, ob es seine Prüfung einschränkt; ein künftiges Feld könnte ein Paket als Auszug kennzeichnen. Deshalb wird das Feld nicht still übergangen: Der Prüfer erfährt, dass das Paket eine Aussage trägt, die dieses Werkzeug nicht liest, und kann eine neuere Fassung holen. Ohne den Befund wäre die Regel eine Einladung zum falschen Grün.

**Angaben des Prüfers (ab Fassung 1.10).** Ab Fassung 1.10 kommen neue Prüfgegenstände als Angaben des Prüfers (Abschnitt 10.8), nicht im Paket. Ein Verifier ab Fassung 1.10, der eine Angabe nicht kennt, lehnt den Aufruf ab, auf der Befehlszeile wie in der Browser-Fassung; er bewertet das Paket nie anders (Abschnitt 10.8). Paket, Manifest und Liste der Gegenzeichnungsschlüssel haben dieselben Formate wie in Fassung 1.9 (Abschnitte 10.1, 10.2, 10.7.1), und die Kette kennt einen Eintragstyp mehr, `DATA_ACCESS` (Abschnitt 4.25), den nur eine Zugriffskette eines Herstellers schreibt: Ein Verifier der Fassung 1.9 bewertet jedes Paket der Fassung 1.10 wie bisher, ein Eintrag `DATA_ACCESS` ergibt bei ihm einmal `UNKNOWN_ENTRY_TYPE` (Regel 2), und ein Paket, das `spec_version` `"1.10"` erklärt, erhält bei ihm `SPEC_NEWER` (Regel 1). Die Angaben der Abschnitte 7.4 und 8.8, die Rollenliste, Anheftungen als Bescheidschlüssel und die neuen Wurzeln für Zeitstempel kennt er nicht. Einen unbekannten Schalter lehnt der Go-Verifier der Fassung 1.9 als unbrauchbaren Aufruf ab (Exit 3); der Zweitverifier der Fassung 1.9 beendet sich dann mit dem Code 2 seiner Befehlszeilenauswertung, der wie „ungültig“ aussieht, aber nichts über das Paket sagt, und an der veröffentlichten Fassung lässt sich das nicht mehr ändern. Den Schalter `--tsa-root` kennt der Go-Verifier der Fassung 1.9 nur einmal: Wiederholt ihn ein Aufruf, nimmt er ihn ohne Meldung an und liest nur die letzte Datei, und Blöcke, die kein Zertifikat sind, übergeht er; ein Zeitzeuge unter einer Wurzel aus einer früheren Datei ergibt dann `TIME_ANCHOR_UNVERIFIED` statt keines Befunds. Die Browser-Fassung 1.9 übergeht Optionen, die sie nicht kennt, ohne Meldung und beurteilt das Paket ohne sie, mit Urteil und Bericht; `tsaRootsPem` als Liste statt als einzelnes `Uint8Array` bricht sie ab. Für Verifier der Fassung 1.9 gilt der Satz vom Ablehnen unbekannter Angaben also nicht. Ab Fassung 1.10 MUSS ein Verifier jeden Bedienfehler mit Exit 3 beantworten, die Browser-Fassung mit einer Fehlermeldung statt eines Urteils, auch einen unbekannten Namen einer Option (Abschnitt 10.8). Wer eine der neuen Angaben übergibt oder `--tsa-root` wiederholt, MUSS einen Verifier ab Fassung 1.10 verwenden; ein Werkzeug oder eine Seite, die sie übergibt, MUSS vorher dessen Fassung abfragen (Befehlszeile: `--version`; Browser-Fassung: `ledgerVerifyVersion`).

Eine spätere Art der Anker-Historie ist für einen Verifier der Fassung 1.10 eine Seite mit dem Grund `not_v2` (Abschnitt 8.8.4), ein späteres Format einer Datei des Prüfers ein unbrauchbarer Aufruf: Keines liest er anders, als es gemeint ist. Was sich ab Fassung 1.10 an der Bewertung eines unveränderten Pakets ändern kann, kommt aus dem Zeitstempelprofil (Abschnitt 7.5), nicht aus den neuen Angaben: Eigenheiten eines Zertifikats und ein Token ohne Zertifikate führen höchstens zu `TIME_ANCHOR_UNVERIFIED` (Abschnitt 7.3, Schritt 5a), ein `token_base64` mit Zeilenumbruch, eine Hülle, die nicht striktem DER folgt (etwa BER-Längen oder ein `genTime` mit nachgestellter Null, Grammatik T in Abschnitt 7.5.2), und eine CMS-Signatur, die nicht trägt, zu `TIME_ANCHOR_INVALID`, und ein Zeitzeuge, den nur der Wurzelspeicher des Systems bestätigte, zu `TIME_ANCHOR_UNVERIFIED` (Abschnitt 7.5.7). Zwei Verifier, die über dasselbe Token bisher verschieden urteilen konnten, urteilen ab Fassung 1.10 gleich.

**Formate `/2` (ab Fassung 1.10).** Die Protokollschlüsselliste `ledger-protokollschluessel/2` (Abschnitt 7.4.7a) und der Auszug `ledger-protokollauszug/2` (Abschnitt 7.4.8a) treten neben die Formate `/1`, die unverändert bleiben. Für den Hersteller gilt: Jedes Format `/1` erscheint weiter an seiner Stelle, in Form und Inhalt unverändert (`keys.json`, `days/…`, `<YYYY>.json`, `head.json` und jede Route ohne `format=2`, Heartbeat-Spezifikation §9.9), und kein Element der Formate `/2` steht in einem Objekt `/1`; `protocol_keys` eines Auszugs `/1` ist immer eine Liste `/1`; zu jeder Version einer Liste `/2` gibt es die Liste `/1` derselben `version`, die ihre Projektion ist (Abschnitt 7.4.7a); und die Signatur nach ML-DSA-87 ist eine zusätzliche Signatur über dieselben Bytes, sie ändert keine Bytes, die eine bestehende Signatur oder ein bestehender Hash deckt. Ein Verifier, der diese Formate nicht kennt, beantwortet eine Datei `/2` als späteres Format einer Datei des Prüfers mit Exit 3 (oben) und beurteilt Paket und Dateien `/1` wie bisher; mit der Projektion `/1` prüft er jeden Tag nur nach Ed25519. Wer eine Datei `/2` übergibt, MUSS einen Verifier verwenden, der die Abschnitte 7.4.7a, 7.4.8a und 7.4.10 in dieser Fassung umsetzt, und SOLL vorher dessen Fassung abfragen: Verifier, die nur den Entwurf der Fassung 1.10 umsetzen (Kennung `spec-1-10-entwurf`, Referenz-Verifier 1.1.0), kennen die Formate `/2` nicht. Die COSE-Objekte (Abschnitt 7.7) stehen nur in Auszügen `/2`, in Tagesobjekten `/2` und unter der Route der Receipts (Heartbeat-Spezifikation §9.9), nie in einem Objekt `/1`. Eine Rollenliste mit Einträgen der Rolle `transparency` liest ein Verifier, der Abschnitt 7.7 nicht umsetzt, mit dem Hinweis `unknown_role`: Diese Einträge belegen bei ihm nichts, sonst ändert sich nichts (Abschnitt 10.7.2). Die Angabe `--vendor-transparency-key` beantwortet er als unbekannten Schalter (Exit 3, Abschnitt 10.8).

Die Registry bildet diese Regeln ab: `envelope_fields.spec_version` und `pruefpaket_manifest.spec_version` tragen den Typ `version`; `envelope_fields.event_type` trägt den Typ `open_enum` mit `unknown_finding = "UNKNOWN_ENTRY_TYPE"`; `pruefpaket_manifest` trägt `unknown_field_finding = "UNKNOWN_MANIFEST_FIELD"`. Die Testvektoren `format_newer_minor`, `format_unknown_event_type` und `format_unknown_manifest_field` (Registry `testvectors.format`) legen das Sollverhalten fest.

### 10.7 Schlüssellisten des Herstellers

Der Hersteller führt drei Schlüssellisten, die seine Wurzel signiert: die Liste der Gegenzeichnungsschlüssel (Abschnitt 10.7.1), die Rollenliste (Abschnitt 10.7.2) und die Protokollschlüsselliste in den Formaten `/1` und `/2` (Abschnitte 7.4.7, 7.4.7a). Jede trägt ihr eigenes `format`, und ein Leser prüft `format` zuerst; die Wurzel signiert nichts anderes. Dass kein Eintrag einer dieser Listen den Publikey der Wurzel nennt, ist eine Regel für den Hersteller (Heartbeat-Spezifikation §9.11 Punkt 1); der Verifier prüft sie nur an der Rollenliste (Abschnitt 10.7.2), nicht an der Liste der Gegenzeichnungsschlüssel und nicht an der Protokollschlüsselliste. Welche Rolle welches Objekt signiert, nennt Abschnitt 10.7.3, wie der Verifier die Rollen prüft, Abschnitt 10.7.4, und wie ein Hersteller vom Betrieb mit einem Schlüssel zu getrennten Rollen übergeht, Abschnitt 10.7.5.

Die Herstellerwurzel, die der Prüfer beibringt, hat die Form `{"wurzel_id": …, "pubkey": …}` mit genau diesen zwei Feldern. Sie kommt NIE aus dem Prüfpaket: Eine Wurzel aus derselben Hand wie die Liste würde nur beweisen, dass die Liste zu sich selbst passt.

#### 10.7.1 Liste der Gegenzeichnungsschlüssel

Die Liste der Gegenzeichnungsschlüssel des Herstellers (bis Fassung 1.9 „Hersteller-Schlüsselliste“; der Name gilt weiter) liegt, wenn vorhanden, unter `keys/vendor/schluesselliste.json` (Registry `vendor_key_list`). Sie ist ein JSON-Objekt in UTF-8 ohne Byte-Order-Mark, ohne doppelte Membernamen und ohne andere Felder als diese:

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

Ab Fassung 1.10 nennt die Liste nur Schlüssel der Rolle `countersigning` (Abschnitt 10.7.3); der Hersteller nimmt nie einen Schlüssel einer anderen Rolle auf. Format und Leseregeln bleiben, damit Verifier und Appliances der Fassung 1.9 sie weiter lesen: Sie weisen jedes andere Member ab, und eine Liste mit einem Member für Rollen wäre für sie unwirksam, sodass jede Quittung, deren Schlüssel der Prüfer nicht anheftet, `RECEIPT_UNVERIFIED` ergäbe. Die Liste ist die Projektion der Rollenliste auf die Rolle `countersigning` (Abschnitt 10.7.2).

**Übergabe durch den Prüfer (ab Fassung 1.10).** Format und Leseregeln der Liste bleiben unverändert, ebenso ihre Stelle im Paket. Der Prüfer KANN eine Liste dieses Formats auch selbst übergeben (Abschnitt 10.8), etwa die aktuelle, die er beim Hersteller abgeholt hat. Eine solche Liste belegt weder eine Quittung (Abschnitt 7.1) noch eine Seite der Anker-Historie (Abschnitt 8.8.3); ihre Schlüssel gehören zu K_cs^L, der Menge, gegen die der Verifier die Rollen prüft (Abschnitt 10.7.4; Abschnitt 7.4.10, Schritt L1). Ob sie wirkt, bestimmt dieser Abschnitt wie für die Liste im Paket; eine Liste, die nicht trägt, ist unwirksam und kein Befund, der Bericht nennt den Grund.

**Rollen.** Die Schlüssel der Liste signieren Quittungen und, bis zum Ende des Doppelbetriebs (Abschnitt 10.7.5), die Hülle von Lizenzbescheiden, Verweigerungsbescheiden und Aktivierungsquittungen und Seiten der Anker-Historie der Form v1 (Heartbeat-Spezifikation §9, §9.11); nie eine Seite der Form v2, nie das Update-Manifest, nie einen Tageseintrag des Herstellerprotokolls und nie ein COSE-Objekt (Abschnitt 7.7). Die Rollen aller Schlüssel des Herstellers zeigen die Abschnitte 7.4.1 und 10.7.3. Die Protokollschlüssel stehen in der Protokollschlüsselliste in den Formaten `/1` und `/2` (Abschnitte 7.4.7, 7.4.7a), die ein Leser dieser Liste nie annimmt; die Transparenzschlüssel (Rolle `transparency`, ab Fassung 1.10) stehen nur in der Rollenliste (Abschnitt 10.7.2), nie in dieser Liste. Derselbe Publikey in zwei Rollen macht die betroffene Liste unwirksam (Abschnitt 10.7.4; Abschnitt 7.4.10, Schritt L1); eine Anheftung einer Rolle, die in `key_id` oder Publikey einer Anheftung einer anderen Rolle gleicht, ist ein unbrauchbarer Aufruf (Abschnitt 10.7.4). Tageseinträge unter einem Protokollschlüssel mit Ende der Gültigkeit zählen nur mit einem bestätigten Zeitstempel vor diesem Ende (Abschnitt 7.4.10, Schritt L2).

#### 10.7.2 Rollenliste `ledger-schluesselrollen/1`

Die Rollenliste nennt jeden Schlüssel, mit dem der Hersteller im laufenden Betrieb signiert, mit genau einer Rolle (Abschnitt 10.7.3), ausgenommen die Protokollschlüssel; diese nennt die Protokollschlüsselliste (Abschnitt 7.4.7). Die Herstellerwurzel signiert sie. Sie belegt nie eine Quittung (Abschnitt 7.1). Sie ist eine Datei des Prüfers (Abschnitt 2) mit genau diesen Membern:

| Member | Typ | Regel |
|---|---|---|
| `format` | const `"ledger-schluesselrollen/1"` | Formatkennung; eine andere macht die Liste unwirksam |
| `version` | int, 1 … 2^53−1 | vom Hersteller streng steigend vergeben; eine neue Version führt jeden Eintrag früherer Versionen mit derselben `key_id`, demselben `pubkey` und derselben `rolle` weiter; seine Gültigkeitsangaben darf sie ergänzen oder verkürzen |
| `ausgestellt` | rfc3339 | Ausstellungszeit, gelesen nach der Grammatik aus Abschnitt 10.7.1 |
| `ende_doppelbetrieb` | rfc3339, optional | Ende des Doppelbetriebs (Abschnitt 10.7.5): ab diesem Zeitpunkt signieren Schlüssel der Rolle `countersigning` nur Quittungen; einmal vorhanden, trägt jede spätere Version denselben Wert |
| `schluessel` | array, 1 … 256 Objekte | je Schlüssel genau `key_id`, `pubkey` (hex64), `rolle`, `gueltig_ab` und optional `gueltig_bis` und `widerrufen_ab`; alle Werte Zeichenketten; eine `key_id` und ein `pubkey` dürfen je nur einmal vorkommen; `gueltig_bis` liegt nach `gueltig_ab` |
| `signatur` | object | genau `wurzel_id` (key-id) und `sig` (hex128) |

- **`rolle`** folgt der Grammatik `^[a-z][a-z_]{0,31}$`. Bekannt sind `countersigning`, `statements`, `update_manifest` und, ab der Erweiterung der Fassung 1.10, `transparency` (Transparenzschlüssel, Abschnitt 7.7.5); das Format der Rollenliste bleibt dafür `/1`. `protocol` ist vorbehalten: Ein Eintrag mit dieser Rolle macht die Liste unwirksam, denn Protokollschlüssel stehen nur in der Protokollschlüsselliste. Ein Eintrag mit einer anderen, unbekannten Rolle belegt nichts, zählt aber für die Eindeutigkeit und für die Rollenprüfung mit (Hinweis `unknown_role`, Abschnitt 10.7.4). Neue Member auf oberster Ebene verlangen ein neues `format`.
- Für `key_id`, `pubkey`, die Zeitangaben und die Gültigkeit zu einem Zeitpunkt gelten die Regeln aus Abschnitt 10.7.1. Die Zahlregel aus Abschnitt 2 gilt; andere Member gibt es auf keiner Ebene.
- **Signatur:** Signiert wird die JCS-Form des Listenobjekts **ohne** das Member `signatur`, mit der kanonischen Memberreihenfolge `ausgestellt, ende_doppelbetrieb, format, schluessel, version` und in jedem Eintrag `gueltig_ab, gueltig_bis, key_id, pubkey, rolle, widerrufen_ab`, mit Ed25519 durch die Herstellerwurzel, die `signatur.wurzel_id` nennt. Diese Wurzel kommt vom Prüfer oder ist eingebaut und genannt (Abschnitt 7.1), nie aus einem Paket oder einem Auszug. Nennt ein Eintrag den Publikey der Wurzel, gegen die die Signatur geprüft wird, ist die Liste unwirksam (Grund `format`, Abschnitt 10.7.4).
- **Wirksam** ist die Liste nur, wenn jede Regel gilt und die Signatur gegen eine Wurzel mit dieser `wurzel_id` trägt; welche Liste unter mehreren gilt und ob eine Rolle widerspricht, bestimmt Abschnitt 10.7.4. Eine unwirksame Liste belegt keinen Schlüssel und ist selbst kein Befund; der Bericht nennt den Grund (`key_roles`, Abschnitt 10.10.2).
- **Nie im Paket:** Die Rollenliste steht nie in einem Prüfpaket und nie unter `keys/vendor/schluesselliste.json`; dort machte sie die Liste der Gegenzeichnungsschlüssel unwirksam, und jede Quittung, deren Schlüssel der Prüfer nicht anheftet, ergäbe `RECEIPT_UNVERIFIED`. Der Prüfer übergibt sie mit `--vendor-key-list` (Abschnitt 10.8).
- **Projektion:** Die Liste der Gegenzeichnungsschlüssel desselben Signiervorgangs nennt genau die Einträge der Rolle `countersigning`, mit Zeichen für Zeichen gleichen `key_id`, `pubkey`, `gueltig_ab`, `gueltig_bis` und `widerrufen_ab`. Das ist eine Regel für den Hersteller (Heartbeat-Spezifikation §9.11); der Verifier prüft sie nicht.
- **Reserve:** Der Hersteller MUSS in jeder Rollenliste neben dem aktiven Bescheidschlüssel einen Bescheidschlüssel in Reserve nennen, dessen privater Teil offline liegt (Heartbeat-Spezifikation §9.11); nennt sie einen Transparenzschlüssel, SOLL sie ebenso einen Transparenzschlüssel in Reserve nennen. Der Verifier prüft das nicht.
- **Veröffentlichung:** an den Veröffentlichungsorten der Protokollschlüsselliste (Abschnitt 7.4.7, Heartbeat-Spezifikation §9.9) und mit jeder Installation und jedem Update-Bündel.

Referenzwerte (Testschlüssel des Korpus, Startwert jeweils SHA-256 der ASCII-Bytes `REKORDER-TESTVECTOR-KEY:` gefolgt vom Namen): Bescheidschlüssel `vendor-statements-test-001` (Name `vendor-statements-1`) `6122df9ab7a7a83ecd7540b4d66cef184bd08aba2cac06123337b8ab3e56c9c2`; Bescheidschlüssel in Reserve `vendor-statements-test-002` (Name `vendor-statements-2`) `0281ea7e6995a65287fb8b49092636b24cb645eb2a54bd1975a94f1597cc0ef5`; Schlüssel des Update-Manifests `vendor-update-manifest-test-001` (Name `vendor-update-manifest-1`) `8796764cebba035507d86bbf2ebf308738417b88f1bdab4f465484569c838f28`. Die Einträge der Rolle `countersigning` der Version 1 sind die Projektion der Liste der Version 1 des Testkorpus (Testvektor `valid_vendor_list`). Signierte Bytes der Version 1 (eine Zeile, 1221 Bytes, SHA-256 `0faf73e6f479e1c54d1f95933cbe81c18208b2963d007ee51fc6812d02fa6552`; Signatur der Wurzel `testwurzel-1`: `9d478d23691ef3ab633d278292a52acf0b2ab8b1c69be6c826825cc824d6b630e079afab31c6afb4f5a5cb5063e1754347842429ab4c80123583c2912387940e`):

```
{"ausgestellt":"2025-12-30T10:00:00.000Z","format":"ledger-schluesselrollen/1","schluessel":[{"gueltig_ab":"2025-01-01T00:00:00Z","key_id":"vendor-test-001","pubkey":"959c448da9b35ea50abeca1f0a4cac57fc21c5b7ff7216d3e304bb5fc406d36c","rolle":"countersigning"},{"gueltig_ab":"2025-06-01T00:00:00Z","gueltig_bis":"2027-01-01T00:00:00Z","key_id":"vendor-test-002","pubkey":"73edaed42d761a1ab4fcc9be71a95b957542e89be13fa185e6ad1264ddc8b816","rolle":"countersigning"},{"gueltig_ab":"2025-01-01T00:00:00Z","key_id":"vendor-test-003","pubkey":"cc2edbd00b1893b5ead99b913212db9b733243c0b177dee34f7be1e9fe7cc3b2","rolle":"countersigning","widerrufen_ab":"2025-12-15T00:00:00Z"},{"gueltig_ab":"2025-12-30T00:00:00.000Z","key_id":"vendor-statements-test-001","pubkey":"6122df9ab7a7a83ecd7540b4d66cef184bd08aba2cac06123337b8ab3e56c9c2","rolle":"statements"},{"gueltig_ab":"2025-12-30T00:00:00.000Z","key_id":"vendor-statements-test-002","pubkey":"0281ea7e6995a65287fb8b49092636b24cb645eb2a54bd1975a94f1597cc0ef5","rolle":"statements"},{"gueltig_ab":"2025-12-30T00:00:00.000Z","key_id":"vendor-update-manifest-test-001","pubkey":"8796764cebba035507d86bbf2ebf308738417b88f1bdab4f465484569c838f28","rolle":"update_manifest"}],"version":1}
```

#### 10.7.3 Rollen und Signaturgegenstände

Jeder Schlüssel des Herstellers hat genau eine Rolle, für seine ganze Lebensdauer; `key_id` und `pubkey` kommen über alle Versionen aller drei Listen in genau einer Rolle vor (Heartbeat-Spezifikation §9.11). Signiert wird mit Ed25519 (RFC 8032, ohne Prehash und ohne Kontext), außer wo ein Abschnitt ausdrücklich ein anderes Verfahren nennt; ab Fassung 1.10 trägt ein Tageseintrag zusätzlich eine Signatur nach ML-DSA-87 (Abschnitt 7.4.5a), und ein Transparenzschlüssel signiert mit Ed25519 die Sig_structure eines COSE-Objekts (Abschnitt 7.7.2):

| Objekt | Signaturgegenstand | Rolle | bis zum Ende des Doppelbetriebs (Abschnitt 10.7.5) |
|---|---|---|---|
| Quittung (Abschnitt 7.1, Heartbeat-Spezifikation §9.1) | `UTF-8(JCS({chain_id, merkle_root, server_ts, tree_size}))`, genau diese vier Member, ohne `kind` | `countersigning` | `countersigning` |
| Lizenzbescheid `ledger.license_statement.v1`, Verweigerungsbescheid `ledger.anchor_refusal.v1`, Aktivierungsquittung `ledger.activation_receipt.v1` | `UTF-8(statement_jcs)` | `statements` | Paar der Hülle: `countersigning`; Paar in `statement_signatures`: `statements` (Heartbeat-Spezifikation §9.3, §9.4) |
| Seite der Anker-Historie `ledger.anchor_history.v1` | `UTF-8(statement_jcs)` | `statements` | `countersigning`, Bytes wie in Fassung 1.9 |
| Seite der Anker-Historie `ledger.anchor_history.v2` | `UTF-8(statement_jcs)` | `statements` | nur `statements` |
| Update-Manifest | `UTF-8(JCS({"kind": "ledger.update_manifest.v1", "manifest": <Objekt>}))` | `update_manifest` | nur `update_manifest` |
| Tageseintrag `ledger.vendor_log_day.v1` | `UTF-8(statement_jcs)`; ab Fassung 1.10 auch die Signatur nach ML-DSA-87 über dieselben Bytes (Abschnitt 7.4.5a) | `protocol` | `protocol` |
| COSE-Objekte der Profile C1 und C2 (ab Fassung 1.10, Abschnitt 7.7) | Sig_structure nach Abschnitt 7.7.2, beginnend mit `0x84 0x6A "Signature1"` | `transparency` | `transparency` |
| Liste der Gegenzeichnungsschlüssel, Rollenliste, Protokollschlüsselliste (Formate `/1` und `/2`, Abschnitte 7.4.7, 7.4.7a) | `UTF-8(JCS(Liste ohne "signatur"))`, je mit eigenem `format` | Herstellerwurzel | Herstellerwurzel |

1. Ein Schlüssel signiert nur Objekte seiner Rolle. Zwischen den Rollen trennen verschiedene Schlüssel und die Rollenprüfung (Abschnitt 10.7.4), innerhalb einer Rolle das Member `kind` (Registry `object_kinds`). Innerhalb der Rolle `countersigning` gilt im Doppelbetrieb die Regel der Fassung 1.9: Eine Quittung hat genau die vier Member und kein `kind`, jedes andere Objekt trägt ein `kind`.
2. Kein Kontext und kein Präfix kommen hinzu: Beide Signaturen eines Bescheids im Doppelbetrieb decken dieselben Bytes, und die Signaturgegenstände der Fassung 1.9 bleiben gültig.
3. Ein Leser einer Liste, die die Wurzel signiert, prüft zuerst `format`. Die Wurzel signiert nichts anderes, und kein Eintrag einer Liste nennt ihren Publikey; der Verifier prüft das nur an der Rollenliste (Abschnitt 10.7.2).
4. Der Schlüssel der Update-Bündel (Heartbeat-Spezifikation §1) gehört nicht zu diesen Rollen und bleibt, wie er ist.
5. **Rolle `transparency`** (ab Fassung 1.10). Ein Transparenzschlüssel signiert nur die Sig_structure eines COSE-Objekts der Profile C1 und C2, die der Transparenzdienst selbst gebildet hat (Heartbeat-Spezifikation §9.11 Punkt 4); kein Schlüssel einer anderen Rolle signiert eine Sig_structure. Hier kommt der Kontext `Signature1` nach RFC 9052 hinzu, abweichend von Punkt 2; die Rollen trennen verschiedene Schlüssel, und die Bytes trennt das erste Byte: 0x84 bei einer Sig_structure, `{` (0x7B) bei jedem JCS-Signaturgegenstand. Innerhalb der Rolle trennt `typ` (Label 16) die Profile C1 und C2.

#### 10.7.4 Rollenprüfung durch den Verifier

Die Rollenprüfung läuft mit Schritt L1 vor der Prüfung der Quittungen (Abschnitt 10.5, Stufe 5, Schritt 4). Sie liest die Liste der Gegenzeichnungsschlüssel des Pakets und die Listen und Anheftungen, die der Prüfer übergibt.

**Unbrauchbarer Aufruf** (Exit 3 ohne Bericht; ergänzt Schritt L0 aus Abschnitt 7.4.10): eine Anheftung eines Bescheidschlüssels, die nicht die Form `key_id=hex64` hat; zwei Anheftungen von Bescheidschlüsseln mit derselben `key_id` und verschiedenen Publikeys; eine Anheftung einer Rolle, die in `key_id` oder Publikey einer Anheftung einer anderen Rolle gleicht (`--vendor-key` für `countersigning`, `--vendor-log-key` für `protocol`, `--vendor-statement-key` für `statements` und, ab Fassung 1.10, `--vendor-transparency-key` für `transparency`); eine Anheftung eines Transparenzschlüssels, die nicht die Form `key_id=hex64` hat, oder zwei solche Anheftungen mit derselben `key_id` und verschiedenen Publikeys; eine Datei aus `--vendor-key-list`, die kein I-JSON ist, ihre Größe überschreitet oder ein unbekanntes oder fehlendes `format` hat (Abschnitt 10.8). Ein Mangel im Inhalt einer Liste, die ihre Grammatik einhält, ist nie Exit 3.

**Bezeichnungen.** K_cs^L sind die Schlüssel der Liste der Gegenzeichnungsschlüssel des Pakets, wenn sie wirksam ist (Abschnitt 10.7.1), und die Schlüssel der wirksamen Listen dieses Formats, die der Prüfer übergibt. P ist die wirksame Protokollschlüsselliste nach Abschnitt 7.4.10, Schritt L1, Nummer 2, im Format `/1` oder `/2`; ab Fassung 1.10 zählen für die Rollenprüfung alle Einträge von P und des zählenden Kandidaten `/2` mit der größten `version`, gleich welches `alg` (dort, Nummer 3).

- **R1 Kandidaten.** Kandidaten sind die verschiedenen Rollenlisten (verschieden nach ihren JCS-Bytes) aus `--vendor-key-list`. Ein Kandidat zählt, wenn er Abschnitt 10.7.2 genügt und seine Signatur gegen eine Herstellerwurzel des Prüfers oder die eingebaute Wurzel mit dieser `wurzel_id` trägt; der Bericht nennt die Quelle der Wurzel.
- **R2 Wirksame Rollenliste Q.** Q ist der zählende Kandidat mit der größten `version`. Es gibt keine wirksame Rollenliste (Grund `lists_contradictory`), wenn zwei zählende Kandidaten dieselbe `version` und verschiedene Bytes haben, wenn einem zählenden Kandidaten ein Eintrag (dieselbe `key_id` mit demselben `pubkey` und derselben `rolle`) eines zählenden Kandidaten kleinerer `version` fehlt oder wenn zählende Kandidaten verschiedene Werte von `ende_doppelbetrieb` tragen oder einem Kandidaten größerer `version` das Member fehlt, das ein Kandidat kleinerer `version` trägt. Werte von `ende_doppelbetrieb` werden hier als Zeichenketten verglichen, denn der Hersteller übernimmt den Wert Zeichen für Zeichen in jede spätere Version; `…T00:00:00Z` und `…T00:00:00.000Z` sind verschiedene Werte. Gibt es keine wirksame Rollenliste, tritt kein Kandidat kleinerer `version` an ihre Stelle.
- **R3 Rollenprüfung nach Publikey**, in dieser Reihenfolge:
  - (a) Gibt Q einem Publikey aus K_cs^L eine andere Rolle als `countersigning`, ist Q nicht wirksam (Grund `key_in_two_roles`). Dann gibt es keine wirksame Rollenliste, und kein Kandidat kleinerer `version` tritt an ihre Stelle. (b) bis (d) lesen ein solches Q nicht: Ein Publikey, den nur dieses Q nennt, macht P nicht unwirksam und lässt keine Anheftung entfallen.
  - (b) Teilen Q und P einen Publikey, ist keine der beiden wirksam (Grund `key_in_two_roles`; für P der Grund „Schlüssel in zwei Rollen“ aus Abschnitt 7.4.10, Schritt L1, Nummer 4).
  - (c) Teilt P einen Publikey mit einer Anheftung eines Gegenzeichnungsschlüssels oder mit K_cs^L, ist P nicht wirksam (Abschnitt 7.4.10, Schritt L1, Nummer 3).
  - (d) Anheftungen, geprüft gegen die danach wirksamen Q und P: Eine Anheftung eines Gegenzeichnungsschlüssels, deren Publikey Q mit einer anderen Rolle nennt, entfällt. Eine Anheftung eines Bescheidschlüssels, deren Publikey in K_cs^L oder in P steht oder den Q mit einer anderen Rolle nennt, entfällt. Eine Anheftung eines Protokollschlüssels, deren Publikey in K_cs^L steht oder den Q nennt, entfällt. Ab Fassung 1.10: Eine Anheftung eines Transparenzschlüssels, deren Publikey in K_cs^L oder in P steht oder den Q mit einer anderen Rolle als `transparency` nennt, entfällt. Eine entfallene Anheftung belegt nichts (Bericht `pins_dropped`, Hinweis `pin_dropped`).

  Verglichen wird der Publikey, nicht die `key_id`: Jeder Schlüssel wird nur in seiner Rolle nachgeschlagen. K_cs (Abschnitt 7.4.10) ist K_cs^L zusammen mit den angehefteten Gegenzeichnungsschlüsseln, die nicht entfallen.
- **R4 Verwendung je Rolle.** `countersigning`: Abschnitt 7.1 mit den verbliebenen Anheftungen; Q belegt nie eine Quittung. `statements`: zuerst die Anheftungen als Bescheidschlüssel, dann die Einträge von Q mit der Rolle `statements` (Abschnitt 8.8.3); eine Seite unter einem Eintrag mit `widerrufen_ab` zählt nur, wenn sie frisch ist (Abschnitt 8.8.4, Schritt H2), auch unter einer Anheftung, deren Publikey Q so nennt (Abschnitt 8.8.3). `protocol`: Abschnitt 7.4.10, Schritt L1. `transparency` (ab Fassung 1.10): zuerst die Anheftungen als Transparenzschlüssel, dann die Einträge von Q mit der Rolle `transparency` (Abschnitt 7.7.5; Schritte K und L3a); Q belegt mit ihnen nur COSE-Objekte. Die Rolle `update_manifest` und unbekannte Rollen verwendet der Verifier nicht.

**Quittungen.** Die Befunde nach Abschnitt 7.1 ändern sich nicht. Eine Quittung, die nach Abschnitt 7.1 nicht belegt ist und deren Publikey im Manifest ein Eintrag von Q mit einer anderen Rolle, ein Schlüssel von P oder eine Anheftung als Bescheid-, Protokoll- oder Transparenzschlüssel ist, wird beurteilt wie in Fassung 1.9 (`RECEIPT_UNVERIFIED`, wenn das Manifest den Schlüssel nennt); der Bericht gibt den Hinweis `receipt_key_other_role`. Für diesen Hinweis zählt jede Anheftung, die der Prüfer übergibt, auch eine, die nach Schritt R3 entfällt. Eine entfallene Anheftung eines Gegenzeichnungsschlüssels gilt als nicht übergeben.

**Bericht.** Das Ergebnis steht im Berichtsobjekt `key_roles` (Abschnitt 10.10.2): Status `not_supplied` ohne Kandidaten; `effective` mit Q; `not_effective`, wenn es Kandidaten, aber kein Q gibt, mit dem Grund `lists_contradictory` oder `key_in_two_roles`, wo sie zutreffen, sonst mit dem Grund des Kandidaten, der am weitesten kam: Die Gründe sind geordnet `format` < `no_matching_root` < `signature`, und genannt wird der höchste Grund unter den Kandidaten. Hinweise stehen in der Reihenfolge der Registry: `unknown_role`, `receipt_key_other_role`, `pin_dropped`.

**Befunde.** Die Rollenprüfung fügt keine Befundklasse hinzu. Exit 3 entsteht nur beim unbrauchbaren Aufruf oben. Ein Widerspruch der Rollen endet bei Exit 1 über bestehende Klassen, nie bei Exit 2: `ANCHOR_HISTORY_UNVERIFIED` mit dem Grund `key_not_established` oder `key_other_role` (Abschnitt 8.8.4), `VENDOR_LOG_UNVERIFIED` mit dem Grund „Schlüssel in zwei Rollen“ (Abschnitt 7.4.10) und `RECEIPT_UNVERIFIED` (Abschnitt 7.1). `RECEIPT_INVALID` (Exit 2) bleibt dort, wo die Liste der Gegenzeichnungsschlüssel des Pakets einer Quittung widerspricht (Abschnitt 7.1). Ein Widerspruch der Rollen ist eine Aussage über die Listen des Herstellers oder über die Prüfumgebung, nicht über die Kette.

Referenzwerte (Rollenliste aus Abschnitt 10.7.2): Eine Anheftung als Gegenzeichnungsschlüssel mit dem Publikey von `vendor-test-001` ist mit der Rollenliste der Version 1 wirksam; eine Anheftung als Gegenzeichnungsschlüssel mit dem Publikey von `vendor-statements-test-001` entfällt und belegt keine Quittung. Eine Rollenliste, die dem Publikey von `vendor-test-001` die Rolle `statements` gibt, ist im Paket `valid_vendor_list` unter `testwurzel-1` (Liste der Gegenzeichnungsschlüssel des Pakets wirksam, `vendor-test-001` in K_cs^L) nicht wirksam (`key_in_two_roles`), und die Quittungen werden beurteilt wie ohne sie; ohne wirksame Liste der Gegenzeichnungsschlüssel, nur mit `--vendor-key` für `vendor-test-001`, ist dieselbe Rollenliste wirksam, die Anheftung entfällt (`pins_dropped`), und die Quittungen unter `vendor-test-001` ergeben `RECEIPT_UNVERIFIED` mit dem Hinweis `receipt_key_other_role`. Eine Rollenliste mit einer unbekannten Rolle ist wirksam, mit dem Hinweis `unknown_role`; eine Anheftung als Bescheidschlüssel, die einer Anheftung als Gegenzeichnungsschlüssel gleicht, ist ein unbrauchbarer Aufruf. Zwei zählende Rollenlisten, deren `ende_doppelbetrieb` `2026-07-01T00:00:00Z` und `2026-07-01T00:00:00.000Z` lauten, ergeben `lists_contradictory`. Ist die Rollenliste der höchsten `version` nach R3 (a) nicht wirksam, ist keine wirksam, auch wenn eine Rollenliste kleinerer `version` zählt; eine Protokollschlüsselliste, die einen Publikey nur mit dieser Rollenliste teilt, bleibt wirksam. Nennt eine Seite in `server_key_id` die `key_id` einer entfallenen Anheftung, ist ihr Grund `key_not_established`, nicht `key_other_role` (Abschnitt 8.8.4, Schritt H2).

#### 10.7.5 Übergang vom Betrieb mit einem Schlüssel

Bis Fassung 1.9 signiert derselbe Schlüssel des Herstellers Quittungen, Bescheide, Seiten der Anker-Historie und das Update-Manifest. Verifier und Appliances der Fassung 1.9 kennen keine Rollen: Sie prüfen Quittungen und Bescheide gegen die Liste der Gegenzeichnungsschlüssel oder einen angehefteten Schlüssel und weisen jedes unbekannte Member dieser Liste ab. Der Übergang zu getrennten Rollen verläuft deshalb in drei Schritten, nach denen sie weiter arbeiten (Heartbeat-Spezifikation §9.11):

1. **Signiervorgang.** Bevor der Server nach Fassung 1.10 arbeitet und vor dem ersten Tag des Herstellerprotokolls sammelt der Hersteller in einem Signiervorgang die öffentlichen Teile der Schlüssel ein: Der aktive Bescheidschlüssel entsteht im Dienst, der Bescheide signiert, der aktive Protokollschlüssel im Dienst, der Tageseinträge signiert; die Reserven, der Schlüssel des Update-Manifests und das Füllergeheimnis (Abschnitt 7.4.4) entstehen offline (Heartbeat-Spezifikation §9.11). Er signiert die Rollenliste der Version 1 und die Protokollschlüsselliste der Version 1; nimmt er eine Reserve für Gegenzeichnungsschlüssel auf, auch eine neue Version der Liste der Gegenzeichnungsschlüssel.
2. **Doppelbetrieb.** Danach signiert der bisherige Gegenzeichnungsschlüssel weiter Quittungen, Seiten der Form v1 und die Hülle der drei Bescheide, die Appliances erhalten (Lizenzbescheid, Verweigerungsbescheid, Aktivierungsquittung). Denselben `statement_jcs` dieser Bescheide signiert ein Bescheidschlüssel im Member `statement_signatures` der Antwort (Heartbeat-Spezifikation §9.3). Der Dienst, der den Gegenzeichnungsschlüssel hält, liest jeden übergebenen `statement_jcs` vor dem Signieren selbst und signiert nur ein Objekt der Form aus Abschnitt 2 mit einem `kind` dieser drei Bescheide oder der Seite der Form v1, nie ein Objekt ohne `kind` (Heartbeat-Spezifikation §9.11 Punkt 3). Seiten der Form v2 signiert nur ein Bescheidschlüssel, das Update-Manifest nur sein eigener Schlüssel, Tageseinträge nur ein Protokollschlüssel.
3. **Ende des Doppelbetriebs.** Ab dem Zeitpunkt `ende_doppelbetrieb` der Rollenliste signieren Gegenzeichnungsschlüssel nur noch Quittungen; die Hülle der Bescheide und Seiten der Form v1 signiert dann ein Bescheidschlüssel. Der Hersteller setzt diesen Zeitpunkt in einer neuen Version der Rollenliste mindestens 180 Tage im Voraus und nur, wenn er keine Appliance mehr unterstützt, die Bescheide allein gegen die Liste der Gegenzeichnungsschlüssel prüft.

Empfänger und Prüfer, die nach Fassung 1.9 vorgehen, nehmen bis zum Ende des Doppelbetriebs Quittungen unter den Gegenzeichnungsschlüsseln ihrer Liste und Bescheide in der Hülle unter einem Gegenzeichnungsschlüssel an; das Member `statement_signatures` übergehen sie, und ihre Liste nennt nie einen Schlüssel einer anderen Rolle. Nach dem Ende des Doppelbetriebs ist ein Bescheid, den der Hersteller ausstellt, für eine Appliance der Fassung 1.9 nicht mehr wirksam, denn sie kennt keinen Bescheidschlüssel; Aufzeichnung, Kette und Quittungen laufen weiter (Heartbeat-Spezifikation §9.4). Einen Bescheid in der Hülle unter einem Gegenzeichnungsschlüssel nähme sie weiter an (Abschnitt 11.2, Schlüsselrollen). Ein Verifier ab Fassung 1.10 belegt Seiten nur über Bescheidschlüssel (Abschnitt 8.8.3); weil der Server Seiten der Form v2 von Anfang an nur unter Bescheidschlüsseln ausstellt, verliert dadurch keine Seite ihre Wirkung.

### 10.8 Angaben des Prüfers und `verify_args.json`

Was der Prüfer dem Verifier übergibt, liest er nach derselben Grammatik wie das Paket (ab Fassung 1.9); eine Angabe, die sie verletzt, ist ein unbrauchbarer Aufruf: Exit 3 mit Begründung, nie eine stille Auslegung.

- **Prüfzeitpunkt** (Freshness, Abschnitt 8.5): ein Zeitpunkt der Grammatik `rfc3339` aus Abschnitt 2 und 10.7 (UTC mit `Z`, großes `T`, ASCII-Ziffern, Jahr `0001` bis `9999`). Eine Angabe ohne Zone, mit Versatz, mit Leerzeichen statt `T`, als Wochendatum oder ohne Sekunden ist unbrauchbar; sie wird nicht nach der Zeitzone des Rechners gelesen. Ohne Angabe gilt die Systemuhr. Ein angegebener Prüfzeitpunkt geht `verify_args.json` vor; die Datei wird dann nicht gelesen.
- **Erwartete Wurzeln** (Papier-Anker, Abschnitt 7.2; Abgleich, Abschnitt 8.6; Lückenzeugen, Abschnitt 11.2), beliebig viele, je in einer von zwei Formen: `<merkle_root>` oder `<tree_size>:<merkle_root>`; `merkle_root` ist 64 Hex-Zeichen, Groß- und Kleinschreibung gleichwertig; `tree_size` hat die Form `[1-9][0-9]*` und ist höchstens 2^53−1 (`0:` und führende Nullen sind unbrauchbar). Mit `tree_size` ist sie gefunden, wenn die neu berechnete Wurzel über die ersten `tree_size` Einträge gleich ist; ist `tree_size` größer als die Zahl der Einträge, ist sie nicht gefunden. Ohne `tree_size` ist sie gefunden, wenn sie der Wurzel über die ersten t Einträge für irgendein t von 1 bis zur Zahl der Einträge gleicht. Jede nicht gefundene erwartete Wurzel ist `MERKLE_INCONSISTENT` (Exit 2) und verankert nichts; jede gefundene zählt als Verankerung (kein `NO_ANCHOR`). Die Vollständigkeit (Abschnitt 8.6) gilt bis zur größten `tree_size` einer gefundenen Wurzel, auch wenn eine andere nicht gefunden ist. Ab Fassung 1.10 trägt jede erwartete Wurzel eine Quelle: `auditor` für eine Wurzel nach diesem Punkt, `anchor_history` für eine Historienwurzel (Abschnitt 8.8.5); für Historienwurzeln ohne die Quelle `auditor` gilt statt des Satzes über `MERKLE_INCONSISTENT` die Einordnung aus Abschnitt 8.8.5. Eine Wurzel ohne `tree_size`, die zu mehreren Präfixen passt, gilt als gefunden beim größten passenden t. Gleiche Paare (`tree_size`, `merkle_root`) aus beiden Quellen sind eine erwartete Wurzel mit beiden Quellen und ergeben höchstens einen Befund.
- **`verify_args.json`** ist optional und unsigniert; der Erzeuger des Pakets wählt ihren Inhalt. Sie ist I-JSON (Abschnitt 2) und hat genau das Member `now` (rfc3339 wie oben). Der Verifier liest sie nur, wenn der Prüfer es ausdrücklich verlangt (für eingefrorene Testvektoren), und nennt im Bericht die Quelle des Prüfzeitpunkts. Verlangt und fehlend oder nicht konform: Exit 3 mit Begründung, das Paket wird nicht weiter gelesen (einziger Befund `FORMAT_ERROR`); kein Rückfall auf die Systemuhr, damit eine ausdrückliche Anforderung nie still die Grundlage der Freshness-Prüfung wechselt.
- **Frische-Fenster** (Abschnitt 8.5; Schalter und Grammatik ab Fassung 1.10): `--freshness DAUER`, höchstens einmal. DAUER ist eine ganze Zahl von 1 bis 999 999 ohne führende Null, direkt gefolgt von der Einheit `h`, `m` oder `s` (etwa `24h` oder `90m`); ohne Angabe gilt `24h`. Jede andere Form, etwa `0`, ein Vorzeichen, ein Bruch, zwei Einheiten oder eine fehlende Einheit, ist unbrauchbar. Das Fenster wird in ganzen Millisekunden verglichen (Abschnitt 2).

**Weitere Angaben (ab Fassung 1.10).** Die bisherigen Angaben (Prüfzeitpunkt, erwartete Wurzeln, Herstellerwurzel und angeheftete Schlüssel nach Abschnitt 7.1, `verify_args.json`) behalten ihre Regeln; `--vendor-key` heftet ab Fassung 1.10 nur einen Gegenzeichnungsschlüssel an (Abschnitt 10.7.4). Hinzu kommen diese, mit denselben Schaltern im Go-Verifier und im Zweitverifier und denselben Optionen in der Browser-Fassung:

| Angabe | Schalter | Option im Browser | Grammatik, Grenzen und Regeln | gelesen in |
|---|---|---|---|---|
| Wurzeln für Zeitzeugen der Kette (Zweck `chain`) | `--tsa-root FILE`, ab Fassung 1.10 wiederholbar | `tsaRootsPem` (`Uint8Array` oder `Uint8Array[]`) | strenges PEM (unten) | 7.3 Schritt 6; 10.9 Bedingung 1 |
| als qualifiziert benannte Wurzeln (Zwecke `chain` und `qualified`) | `--tsa-qualified-roots FILE`, höchstens einmal | `tsaQualifiedRootsJson` (`Uint8Array`) | `ledger-tsa-qualifiziert/1` (unten), höchstens 8 388 608 Bytes | 7.3 Schritt 6; 10.9 Bedingungen 1, 4 und 7 |
| Wurzeln für Zeitstempel des Herstellerprotokolls (Zweck `log`) | `--vendor-log-tsa-root FILE`, wiederholbar | `vendorLogTsaRootsPem` (`Uint8Array[]`) | strenges PEM | 7.4.6; 10.9 Bedingung 7 |
| Auszüge des Herstellerprotokolls | `--vendor-log FILE`, wiederholbar | `vendorLogJson` (`Uint8Array[]`) | `ledger-protokollauszug/1` (7.4.8) oder, ab Fassung 1.10, `ledger-protokollauszug/2` (7.4.8a); je Datei `/1` höchstens 33 554 432 Bytes, je Datei `/2` höchstens 67 108 864 Bytes, je Aufruf höchstens 128 Dateien und 268 435 456 Bytes, beide Formate zusammen, eingebettete Auszüge (nur `/1`, 8.8.2) eingerechnet | 7.4 |
| angeheftete Protokollschlüssel | `--vendor-log-key ID=HEX`, wiederholbar | `vendorLogKeys` (`string[]`) | `key-id`, `=`, hex64; Widersprüche und Doppelrollen nach 7.4.10, Schritt L0 | 7.4 |
| angeheftete Bescheidschlüssel | `--vendor-statement-key ID=HEX`, wiederholbar | `vendorStatementKeys` (`string[]`) | `key-id`, `=`, hex64; Widersprüche und Doppelrollen nach 10.7.4 | 8.8.3; 10.7.4 |
| Schlüssellisten | `--vendor-key-list FILE`, wiederholbar | `vendorKeyListJson` (`Uint8Array[]`) | I-JSON, höchstens 1 048 576 Bytes; `format` ist `rekorder-herstellerschluessel/1`, `ledger-schluesselrollen/1`, `ledger-protokollschluessel/1` oder, ab Fassung 1.10, `ledger-protokollschluessel/2`, ein anderes oder fehlendes `format` ist ein unbrauchbarer Aufruf, für eine Liste `/2` ebenso und nur so (7.4.7a, Grenze zu Exit 3); den Inhalt beurteilen die Abschnitte 10.7.1, 10.7.2, 7.4.7 und 7.4.7a: eine Liste, die nicht trägt, ist unwirksam (im Bericht genannt), nie Exit 3 | 10.7.4; 8.8.3; 7.4.10 Schritt L1 |
| Anker-Historie | `--anchor-history FILE`, wiederholbar | `anchorHistoryJson` (`Uint8Array[]`) | eine Seite oder `ledger-ankerhistorie/2` (8.8.2); je Datei höchstens 33 554 432 Bytes, je Aufruf höchstens 4 096 Dateien, 65 536 Seiten und 268 435 456 Bytes | 8.8 |
| Anforderungszeitpunkt | `--requested-at RFC3339`, höchstens einmal | `requestedAt` (`string`) | Grammatik `rfc3339` wie beim Prüfzeitpunkt, beliebige Sekundenbruchteile, verglichen in ganzen Millisekunden (Bruchteil abgeschnitten); Regeln unten | 8.8 |

**Angabe der Erweiterung (ab Fassung 1.10, Abschnitt 7.7).** Angeheftete Transparenzschlüssel: Schalter `--vendor-transparency-key ID=HEX`, wiederholbar; Option im Browser `vendorTransparencyKeys` (`string[]`); Grammatik `key-id`, `=`, hex64; zwei Anheftungen mit derselben `key_id` und verschiedenen Publikeys und eine Anheftung, die in `key_id` oder Publikey einer Anheftung einer anderen Rolle gleicht, sind ein unbrauchbarer Aufruf (7.4.10, Schritt L0; 10.7.4); gelesen in 7.7.5, 7.7.6 (Schritt K), 7.4.10 (Schritt L3a) und 10.7.4. Die Angabe kommt in die Tabelle oben, sobald beide Referenz-Verifier und die Browser-Fassung Abschnitt 7.7 umsetzen; ein Verifier, der Abschnitt 7.7 nicht umsetzt, beantwortet sie als unbekannten Schalter mit einem unbrauchbaren Aufruf (Abschnitt 10.6).

Die Angaben der Tabelle liest der Verifier als Bytes beim Aufruf, bevor er das Paket öffnet; im Browser gilt dasselbe für die Optionen. Für die einzelnen Angaben gilt:

- **Strenges PEM** (beide PEM-Angaben): Zeilen enden auf `\n` oder `\r\n`, und eine letzte Zeile ohne Zeilenende zählt als Zeile; Leerzeichen und Tabulatoren am Zeilenende zählen nicht; Text außerhalb eines Blocks wird übergangen (RFC 7468). Ein Block ist eine Zeile genau `-----BEGIN CERTIFICATE-----`, Zeilen des Inhalts und eine Zeile genau `-----END CERTIFICATE-----`; der zusammengefügte Inhalt folgt der Grammatik B64 (Abschnitt 2) und ergibt genau ein Zertifikat nach Z.1 (Abschnitt 7.5.3). Unbrauchbar sind ein Block mit einer anderen Bezeichnung nach `BEGIN`, eine Kopfzeile innerhalb eines Blocks (eine Zeile mit `:` zwischen `BEGIN` und `END`), ein Block ohne Ende und eine Datei ohne einen Block `CERTIFICATE`; eine Zeile mit `:` außerhalb eines Blocks, etwa ein Kommentar einer Sammeldatei, ist Text außerhalb eines Blocks und wird übergangen, ebenso eine END-Zeile außerhalb eines Blocks. Kein Block wird still übergangen, und jede wiederholte Angabe zählt; bisher konnte ein Verifier fehlerhafte Blöcke übergehen oder nur die letzte Datei lesen. Jedes Zertifikat einer solchen Datei zählt als Wurzel des Zwecks; übergibt der Prüfer eine Sammeldatei mit vielen Wurzeln, etwa den Wurzelspeicher eines Systems, zählt jede davon, und ein Token jeder dieser Stellen kann für Bedingung (1) der Beweisstufe reichen (Abschnitt 11.2).
- **`ledger-tsa-qualifiziert/1`:** eine Datei des Prüfers (Abschnitt 2) mit genau den Membern `format` (const `"ledger-tsa-qualifiziert/1"`), `stand` (rfc3339, Grammatik aus Abschnitt 10.7: wann der Prüfer die Datei zusammengestellt hat), `quelle` (Zeichenkette, 1 bis 256 Zeichen ohne U+0000 bis U+001F und U+007F bis U+009F: woher er sie genommen hat) und `wurzeln` (array, 1 bis 256 Objekte mit genau `zertifikat`, der Base64-Form nach B64 eines DER-Zertifikats nach Z.1 mit höchstens 16 384 Bytes, `qualifiziert_ab` (rfc3339) und optional `qualifiziert_bis` (rfc3339, nach `qualifiziert_ab`)). Zwei Einträge mit byte-gleichem Zertifikat machen die Angabe mehrdeutig: Exit 3. Eine Wurzel der Datei zählt für den Zweck `qualified` nur für Token mit `qualifiziert_ab` ≤ `genTime` < `qualifiziert_bis` (die obere Grenze nur, wenn vorhanden), verglichen als Zeitpunkte auf Nanosekunden; für den Zweck `chain` zählt sie immer. `stand` und `quelle` gibt der Bericht aus. Die Datei aus einer Vertrauensliste abzuleiten, ist ein Schritt des Prüfers; der Verifier liest keine signierten XML-Listen.
- **Tabelle der Wurzeln für Zeitstempel.** Jedes Zertifikat aus den drei Wurzel-Angaben ist ein Eintrag mit seinem SPKI-SHA-256-Wert und seinen Zwecken (Abschnitt 7.5.7). Byte-gleiche Zertifikate (DER) aus verschiedenen Angaben sind ein Eintrag mit der Vereinigung ihrer Zwecke; den Zeitraum für den Zweck `qualified` nennt allein die Datei `ledger-tsa-qualifiziert/1`, die nie den Zweck `log` gibt. Für Bedingung (7) übergibt der Prüfer dasselbe Zertifikat deshalb mit `--vendor-log-tsa-root` und in `--tsa-qualified-roots`. Der Wurzelspeicher des Systems kommt für keinen Zweck hinzu, und ein Verifier trägt keine Wurzel einer Zeitstempelstelle eingebaut.
- **Schlüssellisten** (`--vendor-key-list`): Jede Datei ist eine Datei des Prüfers (Abschnitt 2). Ein Verstoß gegen I-JSON, etwa ein doppelter Membername oder eine Zahl außerhalb der Zahlregel aus Abschnitt 2, ist ein unbrauchbarer Aufruf (Exit 3 ohne Bericht). Anders bei der Liste im Paket: Über ihre Wirksamkeit entscheiden die Abschnitte 10.7.1 und 10.7.2; nur ein Verstoß gegen die Zahlregel ist dort `FORMAT_ERROR` (Abschnitt 2).
- **Anforderungszeitpunkt R** (Abschnitt 8.8.1): freiwillig, höchstens einmal. R DARF NICHT nach dem Prüfzeitpunkt liegen. Gegen einen Prüfzeitpunkt aus `--now` oder der Systemuhr prüft der Verifier das beim Aufruf (Exit 3 ohne Bericht). Verlangt der Prüfer den Prüfzeitpunkt aus `verify_args.json`, prüft er R gegen ihn zu Beginn der Stufe 5 (Abschnitt 10.5); liegt R danach, ist das `FORMAT_ERROR` (Exit 3 mit Bericht). Dieser Unterschied ist beabsichtigt: Aus `--now` oder der Systemuhr ist der Prüfzeitpunkt beim Aufruf bekannt, aus `verify_args.json` erst, wenn das Paket geöffnet ist. Der Verifier ergänzt R nie aus `manifest.created_ts`, `verify_args.json`, dem Prüfzeitpunkt oder einer Uhr. Wird R ohne Anker-Historie übergeben, nimmt der Verifier es an und gibt den Hinweis `requested_at_unused`.
- **Unbrauchbarer Aufruf.** Ein Verstoß gegen eine Grammatik oder Grenze dieser Tabelle, eine Angabe, die öfter vorkommt als erlaubt, und jeder andere Bedienfehler (ein unbekannter Schalter, ein fehlender Wert) ist ein unbrauchbarer Aufruf: Exit 3 mit Begründung auf der Fehlerausgabe, ohne Bericht; im Browser eine Fehlermeldung statt eines Urteils, ab Fassung 1.10 auch für einen Namen einer Option, den die Browser-Fassung nicht kennt (Abschnitt 10.6). Mehrfach stehen dürfen nur die Schalter, die die Tabelle wiederholbar nennt, und die Schalter für erwartete Wurzeln, Herstellerwurzeln und angeheftete Gegenzeichnungsschlüssel (oben, Abschnitt 7.1); jeder andere Schalter mit einem Wert steht höchstens einmal, auch `--now`, `--lang` und der Schalter des Frische-Fensters (Abschnitt 8.5), und ein wiederholter ist ein unbrauchbarer Aufruf. Auf der Befehlszeile stehen die Schalter vor dem Paket und beginnen mit zwei Bindestrichen, `--` beendet sie; ein Schalter ohne Wert (`--json`, `--now-from-package`) trägt keinen, ein Schalter mit Wert nimmt ihn als `--name WERT` oder `--name=WERT`, WERT ist dabei das folgende Argument, auch wenn es mit einem Bindestrich beginnt, und `--version` steht allein (ab Fassung 1.10). Ein Argument vor `--`, das mit einem Bindestrich beginnt, ist ein Schalter; ein Paket mit einem solchen Namen steht nach `--`. Jede andere Form, auch ein Schalter oder ein weiteres Argument nach dem Paket, ist ein Bedienfehler, ebenso die Bitte um Hilfe (`--help`, `-h`), die die Schalter auf der Fehlerausgabe nennt. Ausgenommen ist der Vergleich von R mit `verify_args.json` (oben), der erst nach dem Lesen des Pakets möglich ist. Was ein Mangel im Inhalt einer Angabe bewirkt, die ihre Grammatik einhält, bestimmen die Abschnitte 7.4, 8.8 und 10.7; es ist nie Exit 3.

**Prüfumgebung eines Testvektors `ledger-pruefumgebung/1`.** Nur im Testkorpus fasst eine Datei `pruefer_<Vektor>.json` die Angaben des Prüfers zu einem Vektor zusammen. Sie ist eine Datei des Prüfers (Abschnitt 2), alle Member sind vorhanden, und die Prüfwerkzeuge setzen sie in dieser Reihenfolge in Schalter um: `format` (const `"ledger-pruefumgebung/1"`), `korpus` (bool; `true`: zusätzlich die Herstellerwurzel und der angeheftete Schlüssel des Korpus, `pruefer_herstellerwurzel.json` und `pruefer_herstellerschluessel.txt`), `vendor_root` (array von Dateien), `vendor_key` (array von `key_id=hex64`), `vendor_key_list` (array von Dateien), `vendor_log_key` (array von `key_id=hex64`), `vendor_statement_key` (array von `key_id=hex64`), `tsa_root` (array von Dateien), `tsa_qualified_roots` (Datei oder `null`), `vendor_log_tsa_root` (array von Dateien), `expect_root` (array von Zeichenketten wie bei den erwarteten Wurzeln), `vendor_log` (array von Dateien), `anchor_history` (array von Dateien) und `requested_at` (rfc3339 oder `null`). Die genannten Dateien heißen `pruefer_<Vektor>.<Member>-<n>.<Endung>`, liegen auf oberster Ebene der Testvektoren und sind wie die Vektoren mit ihrem SHA-256-Wert festgehalten. Der Prüfzeitpunkt bleibt in der `verify_args.json` des Vektors.

**Prüfumgebung `ledger-pruefumgebung/2` (ab der Erweiterung der Fassung 1.10).** Für Vektoren, die eine Angabe der Erweiterung brauchen, gleicht die Prüfumgebung dem Format `/1` mit zwei Abweichungen: `format` ist die Konstante `"ledger-pruefumgebung/2"`, und nach `vendor_statement_key` steht das Member `vendor_transparency_key` (array von `key_id=hex64`), das die Prüfwerkzeuge in `--vendor-transparency-key` umsetzen. Alle übrigen Regeln des Formats `/1` gelten. Vektoren ohne diese Angabe behalten das Format `/1`.

### 10.9 Beweisstufe

Ab Fassung 1.10. Der Verifier MUSS für jedes Paket, zu dem er einen Bericht ausgibt, eine Beweisstufe bestimmen und ausgeben. Sie fasst zusammen, welche der nach den Abschnitten 7, 8.6, 8.8 und 10.8 geprüften Anker durch Angaben des Prüfers bestätigt sind und bis zu welcher `seq` sie reichen. Sie ist kein Befund, ändert den Exit-Code nicht und ist kein Teil des Urteils (Abschnitt 10.3). Sie gilt für jedes Paket, gleich welche `spec_version` es erklärt. Die Beweisstufe unterstützt Aussagen darüber, wie stark die vorliegende Kette gegen ein Umschreiben durch ihren Schlüsselinhaber belegt ist. Sie gewährleistet nichts, sie ist keine rechtliche Einordnung, und sie sagt nichts über den Inhalt der Aufrufe.

Die Stufe ist eine Funktion der Angaben, die der Verifier bei der Prüfung festhält (Abschnitt 10.9.3), des Exit-Codes und der Befundklassen. Ihre Bestimmung fügt keinen Befund hinzu, entfernt keinen und ändert kein anderes Ergebnis; der Schritt, der sie nach dem Exit-Code bestimmt (Abschnitt 10.5), liest weder eine Uhr noch den Wurzelspeicher des Systems noch eine Datei. Beide Referenz-Verifier bestimmen sie nach diesem Abschnitt und geben für gleiche Eingaben dasselbe Objekt `evidence_level` aus (Abschnitt 10.10). Codes, Reihenfolgen, Regel und Texte stehen in der Registry unter `verifier.evidence_level`.

#### 10.9.1 Bedingungen und Stufen

**Bedingungen.** Jede Bedingung hat einen festen Code; die Nummern in Klammern verwendet dieser Abschnitt.

1. `time_witness`: Ein Zeitzeuge besteht die Schritte 1 bis 6 aus Abschnitt 7.3, und Schritt 6 gelingt mit einer einzelnen Wurzel allein, die der Prüfer für Zeitzeugen der Kette übergeben hat (Zweck `chain`, Abschnitte 7.5.7, 10.9.4).
2. `expected_root_found`: Eine erwartete Wurzel, die der Prüfer übergeben hat (Quelle `auditor`, etwa ein Papier-Anker nach Abschnitt 7.2) oder die aus einer geprüften Anker-Historie stammt (Quelle `anchor_history`, Abschnitt 8.8.5), ist im Paket gefunden (Abschnitt 10.8).
3. `receipt_key_confirmed`: Eine Gegensignatur trägt unter einem Schlüssel, den ein Anker des Prüfers nach Abschnitt 7.1 bestätigt, und dieser Schlüssel ist kein Geräteschlüssel der Kette.
4. `time_witness_qualified`: Ein Zeitzeuge nach (1) kettet zu einer Wurzel, die der Prüfer für den Zeitpunkt des Tokens als qualifiziert benannt hat (Zweck `qualified`, Abschnitt 10.8); sein Token weist sich selbst als qualifizierter Zeitstempel aus (Regel QS, Abschnitt 7.5.6), und seine signierten Attribute nennen das Signiererzertifikat (Z.6, Abschnitt 7.5.6).
5. `receipts_logged`: Die Gegensignaturen sind in bezeugten Tagen des Herstellerprotokolls nachgewiesen (Abschnitt 7.4).
6. `completeness_from_history`: Die Vollständigkeit ist durch eine geprüfte, vollständige Anker-Historie belegt, die nach der Anforderung des Pakets ausgestellt wurde (Abschnitt 8.8.4, Schritt H11).

7. `log_day_qualified`: Gegensignaturen sind in Tagen des Herstellerprotokolls nachgewiesen (wie bei (5)), deren kanonischer Eintrag den Zeitstempel einer Stelle trägt, die der Prüfer für das Protokoll übergibt und für den Zeitpunkt des Tokens als qualifiziert benennt; dieser Token weist sich selbst als qualifizierter Zeitstempel aus (Abschnitte 7.4.6, 7.5.6), und sein `genTime` liegt höchstens G_q = 129 600 000 ms (36 Stunden) nach dem `server_ts` der Gegensignatur (Abschnitt 10.9.4).

**Zwei Wege zum qualifizierten Zeitpunkt (ab Fassung 1.10).** (4) und (7) belegen dasselbe: dass der Stand der Kette bei einer `tree_size` spätestens zu einem Zeitpunkt bestand, den der Token einer vom Prüfer als qualifiziert benannten Stelle trägt. (4) bindet die Kette unmittelbar, über einen Zeitzeugen auf ihr; (7) mittelbar, über die Gegensignatur, deren Einschluss in den Tagesbaum der Auszug nachweist, und den Zeitstempel des Tageseintrags (Abschnitte 7.4.2 bis 7.4.6). Für Stufe 3 genügt einer der beiden Wege. (7) setzt nur ein Protokoll nach Abschnitt 7.4 und eine Stelle voraus, die der Prüfer als qualifiziert benennt: Jeder Hersteller, dessen Protokoll diesen Regeln folgt, eröffnet seinen Kunden diesen Weg gleich, ohne Vertrag je Kunde. Welcher Zeitpunkt belegt ist und mit welchem Abstand zur Gegensignatur, steht in `qualified_time` (Abschnitt 10.10.2); die Grenze dieses Wegs nennt Abschnitt 11.2.

**Stufen.** Die Stufen bauen aufeinander auf; eine Stufe liegt an einer Position vor, wenn ihre Bedingungen diese Position erreichen (Abschnitt 10.9.5).

| Stufe | Name | Bedingungen |
|---|---|---|
| 0 | Selbstauskunft | keine der Stufen 1 bis 3 liegt vor |
| 1 | extern gebunden | (1), (2) oder (3) |
| 2 | gegengezeichnet | (3) |
| 3 | verankert und abgeglichen | (3), (4) oder (7), (5) und (6) |

Die Kopfzeile des Berichts nennt die Stufe von `seq` 1 mit ihrem Namen aus der Tabelle, nie ohne ihre Reichweite und den Verlauf über die Kette.

Jede Bedingung reicht bis zu einer `tree_size` t: Ein Anker für t belegt die Einträge `seq` 1 bis t. Die Stufe einer Position `seq` p ist die höchste Stufe, deren Bedingungen p erreichen. Der Bericht MUSS die Stufe stets mit ihrer Reichweite und dem Verlauf nennen, dazu jede Bedingung mit Grund, was für die nächste Stufe fehlt, die Anker mit Fingerabdruck und die Verbundenheit (Abschnitt 8.8.6, Heartbeat-Spezifikation §9.10). Die Darstellung DARF Farbe und Form des Urteils nicht verändern.

**Stufe 0.** Stufe 0 an einer Position heißt: Kein Beleg einer Stelle außerhalb der Kontrolle des Schlüsselinhabers, den ein Anker des Prüfers bestätigt, reicht bis zu ihr. Stufe 0 ist keine Aussage über eine Manipulation; die Einträge sind geprüft wie alle anderen. Quittungen unter einem Schlüssel, den kein Anker des Prüfers bestätigt (`RECEIPT_UNVERIFIED`), und Zeitzeugen, deren Stelle nur ein Zertifikat aus dem Paket bestätigt (`TIME_ANCHOR_UNVERIFIED`), heben die Stufe nicht über 0: Sie unterdrücken `NO_ANCHOR` (Abschnitte 7.1, 7.3), belegen aber nur Selbstkonsistenz.

**Herkunft der Anker.** Es zählen nur Anker, die der Prüfer beibringt (Abschnitte 7.1, 7.3, 8.8, 10.7, 10.8), und die im Verifier eingebaute Herstellerwurzel, die der Bericht als Quelle nennt (Abschnitt 7.1). Nie zählen: der Wurzelspeicher des Systems; Zertifikate und Schlüssel aus dem Paket (`keys/tsa/`, `keys/vendor/`, `manifest.vendor_pubkeys`); Zertifikate aus einem Token als Vertrauensanker (sie dienen nur als Zwischenzertifikate, Abschnitt 7.5.5); ein Schlüssel eines Signierers oder einer Wurzel einer Zeitstempelstelle, dessen privater Teil veröffentlicht ist (Einträge mit SPKI-SHA-256-Wert in `published_test_keys`, Abschnitt 7.5.7); diese Regel gilt für Schlüssel von Zeitstempelstellen, nicht für die Ed25519-Testschlüssel des Herstellers in derselben Liste, auf die der Hinweis `published_test_key_credited` aufmerksam macht (Abschnitt 10.9.6); ein Herstellerschlüssel, der einem Geräteschlüssel der Kette gleicht; eine Anheftung, die nach Abschnitt 10.7.4 entfällt; ein Schlüssel einer anderen Rolle als der des Objekts, das er belegen soll (Abschnitt 10.7.3); und für Bedingung (4) eine Wurzel mit demselben Schlüssel wie ein Zertifikat aus `keys/tsa/`. Schlüssel von Zertifikaten werden über den SHA-256-Wert ihrer SubjectPublicKeyInfo verglichen (SPKI-SHA-256-Wert), nicht über das Zertifikat: Ein Schlüssel, dessen privater Teil bekannt ist, lässt sich in ein neues Zertifikat setzen.

**Verbundenheit.** Die Verbundenheit des Kunden mit dem Hersteller (Abschnitt 8.8.6) zeigt der Bericht neben der Stufe an. Sie geht in keine Bedingung ein und ändert weder die Zahl der Stufe noch ihre Reichweite noch den Verlauf; kein Hinweis hängt von ihr ab. Keine Bedingung liest `GENESIS.customer_id`, die Edition, Lizenzdaten oder eine Liste von Kunden. Die Liste `published_test_keys` nennt Schlüssel, nie Kunden oder Hersteller, und ändert sich nur mit einer Fassung der Spezifikation. Die Kriterien nennen Formate, keinen Hersteller: Jeder Hersteller, dessen Wurzel, Schlüssellisten, Anker-Historie und Protokoll den Formaten dieser Spezifikation folgen, erreicht mit den Angaben, die der Prüfer übergibt, dieselben Stufen. Eine im Verifier eingebaute Herstellerwurzel ersetzt eine solche Angabe nur für den Hersteller, dessen Wurzel eingebaut ist; für seine Kunden erreicht eine Prüfung ohne Zutun des Prüfers Stufe 2, für die Kunden anderer Hersteller nicht. Der Bericht nennt die eingebaute Wurzel als Quelle und gibt dann den Hinweis `vendor_root_builtin_only` (Abschnitt 10.9.6).

#### 10.9.2 Zustand

Der Zustand `state` folgt aus dem Exit-Code (Abschnitt 10.3) und den Befunden; es gilt die oberste zutreffende Zeile:

| Lage | `state` | `level` |
|---|---|---|
| Exit 3 (Formatfehler) | `format_error` | `null` |
| ein Befund der Exit-Klasse 2, dessen Klasse nicht in `verifier.evidence_level.material_classes` steht; die Liste nennt `CONTENT_MISMATCH` und `REPORT_MISMATCH` | `chain_invalid` | `null` |
| sonst: Exit 0, 1 oder 4, oder Exit 2 nur aus Klassen der Liste `material_classes` | `rated` | 0 bis 3 |

Ein unbrauchbarer Aufruf (Abschnitt 10.8) schreibt keinen Bericht; es gibt dann keine Stufe. Im Zustand `format_error` und `chain_invalid` gibt es keine Stufe, keine Bedingungen und keinen Verlauf (Abschnitt 10.10.2); die Texte lauten „nicht bestimmt (Formatfehler)“ und „keine (Kette ungültig)“.

**Nur vorgelegtes Material widerspricht.** Stammen alle Befunde der Exit-Klasse 2 aus der Liste `material_classes`, widersprechen vorgelegte Klartexte oder Berichte der Kette (Abschnitte 9.1, 10.1), während jede Prüfung der Kette lief und trug. Die Stufe wird dann bestimmt und gilt für die Kette, nicht für dieses Material; der Bericht gibt den Hinweis `material_contradiction`, und seine Kopfzeile lautet „Beweisstufe der Kette: …“ (Abschnitt 10.10.3). Je stärker die Kette verankert ist, desto schwerer wiegt der Widerspruch des Materials; ohne Stufe ginge das verloren.

**Unvollständiges Kettenende.** Exit 4 (Abschnitt 8.6) ergibt den Zustand `rated` wie Exit 0 und 1. Die Stufe gilt für die vorliegenden Einträge `seq` 1 bis N; über Einträge nach N sagt sie nichts, und der Bericht gibt den Hinweis `unsealed_end`. Einträge, die keine Bedingung erreicht, etwa im Restfenster (Abschnitt 11.2), stehen im Verlauf mit Stufe 0.

**Spätere Exit-Klassen.** Die elf Klassen der Abschnitte 7.4.11, 7.7.7 und 8.8.7 haben die Exit-Klasse 1 und ändern den Zustand nie. Erhält eine von ihnen in einer späteren Fassung die Exit-Klasse 2, MUSS sie in eine Liste aufgenommen werden, die wie `material_classes` wirkt: Ein Verhalten des Herstellers ist kein Beweis gegen die Kette des Kunden.

#### 10.9.3 Festgehaltene Angaben

Der Verifier hält während der Prüfung diese Angaben fest. Jede ist eine Funktion des Pakets und der Angaben des Prüfers und ergibt für sich keinen Befund.

- **Je Quittung**, deren Signatur nach Abschnitt 7.1 trägt: `tree_size`, `server_key_id`, die Herkunft des Schlüssels (`pinned`; `list` mit `version` und `wurzel_id` der Liste und der Herkunft der Wurzel, `auditor` oder `builtin`; `manifest`, wie in `evidence_level.anchors.vendor_keys`, Abschnitt 10.10.2), ob der Publikey einem Schlüssel aus D gleicht, und ihre Klasse im Herstellerprotokoll mit Unterklasse (Abschnitt 7.4.10, Schritt L8).
- **D:** jeder Geräteschlüssel, unter dem eine Checkpoint-Signatur dieser Kette angenommen wurde, also `GENESIS.device_pubkey` und jeder nach Abschnitt 6.4 legitimierte Schlüssel aus `KEY_ROTATION`.
- **Je TIME_ANCHOR:** `tree_size`, `genTime`, ob die Schritte 1 bis 4 aus Abschnitt 7.3 bestanden sind, das Ergebnis von Schritt 5 (trägt, oder nach 5a nicht ausführbar mit Grund), für jede Wurzel R der Tabelle aus Abschnitt 10.8 einzeln, ob ein Pfad nach Z.3 und Z.4 zum `genTime` zu R allein besteht, die SPKI-SHA-256-Werte des Signierers und von R, das Ergebnis der Regel QS und ob Z.6 gilt, verletzt oder nicht prüfbar ist.
- **Wurzeln für Zeitstempel:** je Eintrag der Tabelle (Abschnitt 10.8) das Zertifikat, sein SHA-256-Wert, sein SPKI-SHA-256-Wert, seine Zwecke und für den Zweck `qualified` der Zeitraum mit `qualifiziert_ab` und gegebenenfalls `qualifiziert_bis`.
- **Zertifikate des Pakets:** der SPKI-SHA-256-Wert jedes Zertifikats in einem Block `CERTIFICATE` einer Datei `keys/tsa/*.pem`, das sich nach B64 und Z.1 lesen lässt; andere werden übergangen, ohne Befund.
- **Je erwartete Wurzel:** ihre Quellen (`auditor`, `anchor_history`), ob sie gefunden ist, und `found_at`, die `tree_size`, bei der sie gefunden ist (bei einer Wurzel ohne `tree_size` das größte passende t, Abschnitt 10.8).
- **Aus Abschnitt 8.8:** `anchor_history.completeness`, die Hinweise der Anker-Historie und aus der Verbundenheit `status` und `vendor_itself`.
- **Aus Abschnitt 7.4:** `vendor_log.status`, ob ein Befund `VENDOR_LOG_CONTRADICTION` ohne Tag oder an einem Tag des verlangten Bereichs [Lo, T] dieses Pakets vorliegt (Abschnitt 7.4.10, Schritt L7), und die kleinste `tree_size` t_m eines Befunds `LOGGED_ROOT_MISMATCH`.
- **Aus Abschnitt 7.4 für Bedingung (7):** je nutzbarem Tag d, an dem eine Quittung die Klasse `included` hat, je Zeitstempel von c(d), der nicht mangelhaft ist: sein `genTime`, das Ergebnis von Schritt 5 (nach 5a ausführbar oder nicht), für jede Wurzel R der Tabelle aus Abschnitt 10.8 mit den Zwecken `log` und `qualified` einzeln, ob ein Pfad nach Z.3 und Z.4 zum `genTime` zu R allein besteht, die SPKI-SHA-256-Werte des Signierers und von R und das Ergebnis der Regel QS.

#### 10.9.4 Bedingungen im Einzelnen

Jede Bedingung ergibt ein Objekt mit vier Membern: `met` (bool) sagt, ob sie vorliegt; `up_to_tree_size` ist ihre Reichweite, `null`, wenn sie nicht vorliegt; `count` ist die Zahl der angerechneten Gegenstände, 0, wenn keiner angerechnet ist; `reason` ist genau dann `null`, wenn sie vorliegt, sonst ein Grund aus der Tabelle unten.

**Auswertung.** Zuerst werden die Gründe ohne Gegenstand in der Reihenfolge der Tabelle geprüft: Trifft einer zu, liegt die Bedingung nicht vor, und der vorderste zutreffende ist ihr Grund. Sonst wird jeder Gegenstand gegen die Stufen geprüft, bei (1) und (4) jedes Paar aus Gegenstand und Wurzel, bei (7) jedes Tripel aus Quittung, Zeitstempel und Wurzel; s ist die Zahl der Stufen, die das Paar oder Tripel in der Reihenfolge der Tabelle ohne Unterbrechung besteht. Angerechnet ist ein Gegenstand, wenn er für ein und dieselbe Wurzel (bei (7): denselben Zeitstempel und dieselbe Wurzel) jede Stufe besteht; Stufen verschiedener Wurzeln werden nie zusammengesetzt. Ist kein Gegenstand angerechnet, ist der Grund der Code der Stufe mit dem Index max(s) über alle Paare, also der Stufe, an der das am weitesten gekommene Paar scheiterte. Scheitern dort Paare an der Stufe `qualified_statement` mit beiden Ergebnissen, gilt `qualified_statement_malformed` vor `no_qualified_statement`. Weil nur der Code ausgegeben wird, braucht es keine weitere Regel.

| Bedingung | Gegenstände, Wurzeln | Gründe ohne Gegenstand, in dieser Reihenfolge | Stufen je Gegenstand, in dieser Reihenfolge | Reichweite | `count` |
|---|---|---|---|---|---|
| (1) `time_witness` | jeder TIME_ANCHOR, je Wurzel des Zwecks `chain` | `no_time_anchor` (kein TIME_ANCHOR in der Kette); `no_tsa_root_supplied` (keine Wurzel des Zwecks `chain`) | `signature_not_checkable` (Schritt 5 nach 5a nicht ausführbar); `not_chained_to_auditor_root` (kein Pfad nach Z.3 und Z.4 zum `genTime` zu dieser Wurzel allein); `published_test_key` (SPKI des Signierers oder der Wurzel in `published_test_keys`); `token_extensions_unusable` (Regel QS ergibt nach den Nummern 1 bis 3 „unbrauchbar“) | größte `tree_size` eines angerechneten TIME_ANCHOR | angerechnete TIME_ANCHOR |
| (2) `expected_root_found` | jede gefundene erwartete Wurzel der Quelle `auditor` oder `anchor_history` | `no_expected_root_found` (keine solche Wurzel gefunden) | keine | größtes `found_at` | verschiedene gefundene Wurzeln, je (`found_at`, `merkle_root`) |
| (3) `receipt_key_confirmed` | jeder `CHECKPOINT_RECEIPT`, dessen Signatur nach Abschnitt 7.1 trägt | `no_receipt` (keine solche Quittung) | `key_not_confirmed` (Schlüssel nur aus dem Manifest, also `RECEIPT_UNVERIFIED`); `key_is_device_key` (der bestätigte Publikey gleicht einem Schlüssel aus D) | größte `tree_size` einer angerechneten Quittung | angerechnete Quittungen |
| (4) `time_witness_qualified` | jeder TIME_ANCHOR, je Wurzel des Zwecks `qualified` | `no_time_anchor`; `no_qualified_root_supplied` (keine Wurzel des Zwecks `qualified`) | `signature_not_checkable` (Schritt 5 nach 5a nicht ausführbar oder Z.6 nicht prüfbar, Abschnitt 7.5.6); `not_chained_to_qualified_root`; `published_test_key`; `qualified_root_in_package` (SPKI der Wurzel gleicht dem eines Zertifikats aus `keys/tsa/`); `outside_qualified_window` (nicht `qualifiziert_ab` ≤ `genTime` < `qualifiziert_bis`, die obere Grenze nur, wenn vorhanden, verglichen als Zeitpunkte auf Nanosekunden); `signing_certificate_not_bound` (Z.6 verletzt); `token_extensions_unusable`; `qualified_statement` (Regel QS, Nummer 4: `malformed` ergibt `qualified_statement_malformed`, `absent` ergibt `no_qualified_statement`) | größte `tree_size` eines angerechneten TIME_ANCHOR | angerechnete TIME_ANCHOR |
| (5) `receipts_logged` | die Quittungen aus Abschnitt 7.4.10, Schritt L8 (Signatur trägt nach Abschnitt 7.1, kein Befund `RECEIPT_INVALID`), in Kettenreihenfolge, je mit ihrer Klasse aus Schritt L8 | `vendor_log_not_supplied` (Status `not_supplied`); `vendor_log_not_established` (Status `no_protocol_key`); `vendor_log_contradiction` (ein Befund `VENDOR_LOG_CONTRADICTION` ohne Tag oder an einem Tag aus [Lo, T], Abschnitt 10.9.3); `no_receipt` | je Quittung (unten) | unten | gute Quittungen bis zur Reichweite |
| (6) `completeness_from_history` | `anchor_history.completeness` (Abschnitt 8.8.4, Schritt H11) | nach der Zuordnung unten | keine | `completeness.up_to_tree_size` | gefundene Historienwurzeln (`anchor_history.roots.found`) |
| (7) `log_day_qualified` | jede Quittung der Klasse `included` (Abschnitt 7.4.10, Schritt L8), je Zeitstempel s des kanonischen Eintrags c(d) ihres Tages d = day(`server_ts`), der nach Abschnitt 7.5.7 nicht mangelhaft ist, und je Wurzel mit den Zwecken `log` und `qualified` | `vendor_log_not_supplied`; `vendor_log_not_established`; `vendor_log_contradiction` (wie bei (5)); `no_qualified_log_root_supplied` (keine Wurzel der Tabelle trägt beide Zwecke); `no_receipt_included` (keine Quittung hat die Klasse `included`) | `signature_not_checkable`; `not_chained_to_qualified_log_root` (kein Pfad nach Z.3 und Z.4 zum `genTime` zu dieser Wurzel allein); `published_test_key`; `outside_qualified_window`; `qualified_day_stamp_late` (`genTime`, auf ganze Millisekunden abgeschnitten, ist nicht kleiner als end(d) + W, Abschnitt 7.4.6); `qualified_day_stamp_gap` (`genTime`, auf ganze Millisekunden abgeschnitten, minus `server_ts` der Quittung ist größer als G_q); `token_extensions_unusable`; `qualified_statement` (wie bei (4)) | größte `tree_size` einer angerechneten Quittung | angerechnete Quittungen |

**Im Zustand `rated`** haben alle Zeitzeugen die Schritte 1 bis 4 bestanden, und wo Schritt 5 ausgeführt wurde, trägt er; sonst läge `TIME_ANCHOR_INVALID` vor. Ebenso ist jede erwartete Wurzel der Quelle `auditor` gefunden, sonst läge `MERKLE_INCONSISTENT` vor. Ein angerechneter Gegenstand von (4) ist zugleich ein angerechneter Gegenstand von (1), denn eine Wurzel des Zwecks `qualified` trägt auch den Zweck `chain` (Abschnitt 7.5.7).

**Zu (2).** Historienwurzeln zählen, wenn Abschnitt 8.8.5 sie als gefunden einordnet; Wurzeln hinter dem Paketende sind nicht gefunden. Wurzeln aus dem Herstellerprotokoll sind keine erwarteten Wurzeln (Abschnitt 7.4.10, Schritt L9) und zählen nie.

**Zu (3).** Bedingung (3) liest keinen Befund des Herstellerprotokolls und keinen der Anker-Historie. Ein Verhalten des Herstellers unter einem anderen Schlüssel oder ein Datenverlust bei ihm senkt so nie die Stufe 2 eines Kunden. Eine Quittung unter einem Schlüssel einer anderen Rolle (Abschnitt 10.7.4) und eine Quittung, deren Schlüssel nur eine Liste des Prüfers nennt, haben die Herkunft `manifest` (Abschnitt 7.1).

**Zu (5), je Quittung.** Gut ist eine Quittung der Klasse `included`, neutral eine der Klasse `before_start`. Jede andere ist schlecht, mit diesem Code:

| Klasse (Abschnitt 7.4.10, Schritt L8) | Code |
|---|---|
| `not_included` | `receipt_not_logged` |
| `unchecked` mit Unterklasse `day_not_witnessed` | `day_timestamp_not_confirmed` |
| `unchecked` mit anderer Unterklasse | `receipt_not_checkable` |
| `missing` | `log_day_not_supplied` |
| `pending` | `receipt_day_not_closed` |
| `future` | `receipt_after_check_time` |

Quittungen sind hier die aus Abschnitt 7.4.10, Schritt L8: jeder `CHECKPOINT_RECEIPT`, dessen Signatur nach Abschnitt 7.1 trägt und der keinen Befund `RECEIPT_INVALID` hat. Die Vorreichweite r5′ ist die größte `tree_size` t einer guten Quittung, für die jede Quittung mit `tree_size` ≤ t gut oder neutral ist; gibt es keine, ist r5′ = 0. Die Reichweite ist min(r5′, t_m − 1), wenn ein Befund `LOGGED_ROOT_MISMATCH` vorliegt (t_m wie in Abschnitt 10.9.3), sonst r5′. Ein Tag zählt nur durch seinen eigenen bezeugenden Zeitstempel (Abschnitt 7.4.6). Bedingung (5) liegt vor, wenn kein Grund ohne Gegenstand zutrifft und die Reichweite mindestens 1 ist. Sonst ist der Grund, in dieser Reihenfolge: `receipts_before_log_start`, wenn jede Quittung neutral ist; der Code der in Kettenreihenfolge vordersten schlechten Quittung, wenn r5′ = 0 ist; `logged_root_mismatch`, wenn r5′ ≥ 1 ist und die Kappung die Reichweite auf 0 setzt. Endet die Reichweite vor der letzten Quittung, liegt (5) vor, und die Hinweise (Abschnitt 10.9.6) nennen, was die Reichweite begrenzt. Ab Fassung 1.10 ist eine Quittung der Klasse `unchecked` mit der Unterklasse `hybrid_incomplete` (Abschnitt 7.4.10, Schritt L8) schlecht mit dem Code `receipt_not_checkable`: Ein hybrid-unvollständiger Tag wirkt wie ein nicht festgestellter, er kürzt die Reichweite von (5) über r5′, und (7) rechnet seine Quittungen nicht an, denn keine ist `included`; die Bedingungen der Stufe 2 liest er nicht.

So kürzen ein noch nicht fälliger Tag, ein veralteter Auszug und ein weggelassenes Blatt die Reichweite der Stufe 3, statt sie aufzuheben; Stufe 2 bleibt unberührt, und der Hersteller steht bei einem weggelassenen Blatt neben einem Befund gegen sich.

**Zu (6).** Bedingung (6) liegt genau dann vor, wenn `anchor_history.completeness.status` `established` ist; ihre Reichweite ist dann `completeness.up_to_tree_size` und `count` die Zahl der gefundenen Historienwurzeln (`anchor_history.roots.found`). Sonst ist `count` 0, und ihr Grund folgt aus dem Grund der Vollständigkeit:

| Grund in `anchor_history.completeness` (Abschnitt 8.8.4, Schritt H11) | Grund von (6) |
|---|---|
| `not_supplied` | `anchor_history_not_supplied` |
| `no_request_time` | `requested_at_not_supplied` |
| `no_usable_page`, `owner_differs`, `issued_before_request` | `anchor_history_not_established` |
| `pages_missing` | `anchor_history_partial` |
| `contradiction`, `fork` | `anchor_history_contradiction` |
| `no_root_found` | `no_history_root_found` |
| `root_missing` | kommt im Zustand `rated` nicht vor: Ein `MERKLE_INCONSISTENT` aus einer Historienwurzel ergibt `chain_invalid` |

Erwartete Wurzeln der Quelle `auditor` genügen (6) nie: Wann sie im Verhältnis zur Anforderung festgehalten wurden, weiß nur der Prüfer.

Seiten zählen für (2) mit der Quelle `anchor_history` und für (6) nur unter Bescheidschlüsseln (Abschnitt 8.8.3). Stufe 3 verlangt deshalb eine Rollenliste oder eine Anheftung als Bescheidschlüssel.

**Zu (7).** Bedingung (7) bindet den Stand der Kette bei der `tree_size` einer Gegensignatur an den Zeitstempel des Tages, an dem das Herstellerprotokoll diese Gegensignatur nachweist: Die Quittung ist ein Blatt ihres Kettentags, der Kettentag ein Blatt des Tagesbaums, dessen Wurzel der Tageseintrag trägt, und der Zeitstempel deckt den Tageseintrag (Abschnitte 7.4.2 bis 7.4.6). Für eine Quittung der Klasse `included` mit d = day(`server_ts`) ist der Tag d nutzbar und c(d) bestimmt und bezeugt. Angerechnet ist eine Quittung, wenn ein Tripel mit ihr jede Stufe besteht. Es zählen nur Zeitstempel von c(d) selbst, nie ein späterer Tag über `prev_hash` (Abschnitt 7.4.6). Ein mangelhafter Zeitstempel bildet kein Tripel; ein Zeitstempel, der Z.6 verletzt, ist für Tageseinträge mangelhaft (Abschnitt 7.5.7). Verfrühte Zeitstempel kommen nicht vor: Ein bestätigter verfrühter Zeitstempel macht seinen Tag unbrauchbar (Abschnitt 7.4.10, Schritt L2 (h)), und eine Quittung eines solchen Tages ist nie `included`. Eine Stufe für Wurzeln aus `keys/tsa/` hat (7) nicht, denn die Token stammen aus dem Herstellerprotokoll, nicht aus dem Paket. Ein Zeitstempel von c(d) bezeugt den Stand höchstens W nach dem Ende des Tages, also weniger als 72 Stunden nach `server_ts` der Quittung; ein Zeitzeuge nach (4) bezeugt ihn im Takt seiner Anfragen. (7) rechnet eine Quittung nur an, wenn zwischen ihrem `server_ts` und dem `genTime` des Zeitstempels höchstens G_q liegt. **Warum 36 Stunden:** Ein ehrlicher Hersteller schließt einen Tag kurz nach seinem Ende ab, spätestens bis zu seiner Fälligkeit um 06:00 UTC des Folgetags (Heartbeat-Spezifikation §9.9); eine Gegensignatur kurz nach Mitternacht liegt dann bis zu 30 Stunden vor dem Stempel, und sechs Stunden bleiben für einen Ausfall der Stelle. So liegt der belegte Zeitpunkt nicht wesentlich weiter von der Gegensignatur entfernt als bei einem täglichen Zeitzeugen auf der Kette, und ein Hersteller, der mit dem Kunden zusammenwirkt, kann eine Gegensignatur höchstens um diese Spanne zurückdatieren, bevor der Stempel ihren Tag festlegt (Abschnitt 11.2). Eine Quittung zählt für (7) gleich, woher ihr Schlüssel belegt ist, wie bei (5). Bedingung (7) liest weder die Verbundenheit noch die Zeitzeugen der Kette.

**Gründe** (Registry `verifier.evidence_level.reasons`; der Bericht gibt den Text aus, die EN-Fassung steht in der Registry):

| Code | Bedingung | Text im Bericht |
|---|---|---|
| `no_time_anchor` | (1), (4) | kein Zeitzeuge in der Kette |
| `no_tsa_root_supplied` | (1) | keine Wurzel für Zeitzeugen der Kette übergeben (--tsa-root, --tsa-qualified-roots) |
| `signature_not_checkable` | (1), (4), (7) | die Signatur oder, bei (4), die Bindung des Signiererzertifikats keines dieser Zeitstempel ist nach dem Zeitstempelprofil prüfbar (7.5, Z.6) |
| `not_chained_to_auditor_root` | (1) | kein Zeitzeuge kettet zu seinem genTime zu einer übergebenen Wurzel |
| `published_test_key` | (1), (4), (7) | die Stelle nutzt einen Schlüssel, dessen privater Teil veröffentlicht ist (kein Zeuge) |
| `token_extensions_unusable` | (1), (4), (7) | der Token trägt eine unbekannte kritische oder nicht lesbare TSTInfo-Erweiterung |
| `no_expected_root_found` | (2) | keine erwartete Wurzel im Paket gefunden (keine übergeben, oder die Anker-Historie nennt nur Wurzeln hinter dem Paketende) |
| `no_receipt` | (3), (5) | keine Gegensignatur in der Kette |
| `key_not_confirmed` | (3) | Gegensignaturen stimmig, ihr Schlüssel aber durch keinen Anker des Prüfers bestätigt (--vendor-root, --vendor-key) |
| `key_is_device_key` | (3) | der als Herstellerschlüssel bestätigte Schlüssel ist ein Geräteschlüssel dieser Kette |
| `no_qualified_root_supplied` | (4) | keine als qualifiziert benannte Wurzel übergeben (--tsa-qualified-roots) |
| `not_chained_to_qualified_root` | (4) | kein Zeitzeuge kettet zu seinem genTime zu einer als qualifiziert benannten Wurzel |
| `qualified_root_in_package` | (4) | die als qualifiziert benannte Wurzel hat denselben Schlüssel wie ein Zertifikat aus keys/tsa/ des Pakets und zählt dafür nicht |
| `outside_qualified_window` | (4), (7) | genTime liegt außerhalb des Zeitraums, für den der Prüfer die Wurzel als qualifiziert benannt hat |
| `signing_certificate_not_bound` | (4) | die signierten Attribute des Tokens nennen das Signiererzertifikat nicht, eines von signingCertificate und signingCertificateV2 nennt ein anderes, oder eines davon ist nicht nach Z.6 gebildet (RFC 3161 2.4.1, RFC 5816) |
| `qualified_statement_malformed` | (4), (7) | die qcStatements-Erweiterung des Tokens ist nicht lesbar |
| `no_qualified_statement` | (4), (7) | der Token weist sich nicht als qualifizierter Zeitstempel aus (qcStatements mit esi4-qtstStatement-1, ETSI EN 319 422) |
| `vendor_log_not_supplied` | (5), (7) | kein Auszug des Herstellerprotokolls übergeben (--vendor-log) |
| `vendor_log_not_established` | (5), (7) | Auszug übergeben, aber kein Protokollschlüssel durch einen Anker des Prüfers belegt |
| `vendor_log_contradiction` | (5), (7) | das Herstellerprotokoll widerspricht sich (VENDOR_LOG_CONTRADICTION) |
| `receipt_not_logged` | (5) | eine Gegensignatur fehlt im bezeugten Tag ihres Herstellerprotokolls (RECEIPT_NOT_LOGGED) |
| `day_timestamp_not_confirmed` | (5) | der Tageseintrag zum Tag einer Gegensignatur ist durch keinen Zeitstempel bezeugt, den eine Wurzel des Prüfers für das Protokoll bestätigt (--vendor-log-tsa-root) |
| `receipt_not_checkable` | (5) | für den Tag einer Gegensignatur fehlt ein tragender Kettentag-Nachweis, oder Nachweise oder Tageseinträge widersprechen sich, oder ab Fassung 1.10 fehlt dem Tageseintrag ab `hybrid_ab` eine geltende ML-DSA-Signatur |
| `receipt_day_not_closed` | (5) | der Tag einer Gegensignatur ist noch nicht fällig; ab 06:00 UTC des Folgetags erneut prüfen |
| `receipt_after_check_time` | (5) | eine Gegensignatur trägt einen server_ts nach dem Prüfzeitpunkt; kein abgeschlossener Tag kann sie enthalten |
| `log_day_not_supplied` | (5) | für den Tag einer Gegensignatur liegt kein Tageseintrag vor; einen vollständigen, aktuellen Auszug abrufen |
| `receipts_before_log_start` | (5) | alle Gegensignaturen liegen vor dem Beginn des Herstellerprotokolls |
| `logged_root_mismatch` | (5) | eine im Herstellerprotokoll festgehaltene Wurzel widerspricht dem Paket (LOGGED_ROOT_MISMATCH); Stufe 3 endet davor |
| `anchor_history_not_supplied` | (6) | keine Anker-Historie übergeben (--anchor-history) |
| `requested_at_not_supplied` | (6) | ohne Anforderungszeitpunkt (--requested-at) ist die Vollständigkeit nicht beurteilt |
| `anchor_history_not_established` | (6) | Anker-Historie übergeben, für dieses Paket aber nicht belegt (ANCHOR_HISTORY_UNVERIFIED) |
| `anchor_history_partial` | (6) | Seiten der Anker-Historie fehlen (ANCHOR_HISTORY_UNVERIFIED) |
| `anchor_history_contradiction` | (6) | die Anker-Historie widerspricht sich, den Quittungen oder dem Herstellerprotokoll oder zeigt eine zweite Fassung (ANCHOR_HISTORY_CONTRADICTION, ANCHOR_HISTORY_FORK) |
| `no_history_root_found` | (6) | keine Wurzel der Anker-Historie im Paket gefunden |
| `no_qualified_log_root_supplied` | (7) | keine Wurzel übergeben, die zugleich für Zeitstempel des Herstellerprotokolls übergeben und als qualifiziert benannt ist (--vendor-log-tsa-root und --tsa-qualified-roots) |
| `no_receipt_included` | (7) | keine Gegensignatur im bezeugten Tag ihres Herstellerprotokolls nachgewiesen |
| `not_chained_to_qualified_log_root` | (7) | kein Zeitstempel eines Tages mit nachgewiesener Gegensignatur kettet zu seinem genTime zu einer Wurzel, die für das Protokoll übergeben und als qualifiziert benannt ist |
| `qualified_day_stamp_late` | (7) | der Zeitstempel der als qualifiziert benannten Stelle liegt nach dem Zeitfenster von 48 Stunden nach Tagesende (7.4.6) |
| `qualified_day_stamp_gap` | (7) | der Zeitstempel der als qualifiziert benannten Stelle liegt mehr als 36 Stunden nach der Gegensignatur (10.9.4) |

#### 10.9.5 Stufe, Reichweite, Verlauf und nächste Stufe

Mit N = Zahl der Einträge des Pakets und reach(c) = `up_to_tree_size` der Bedingung c, wenn sie vorliegt, sonst 0:

```
r0 = N
r1 = max(reach(1), reach(2), reach(3))
r2 = reach(3)
r3 = min(reach(3), max(reach(4), reach(7)), reach(5), reach(6)), wenn (3), (5), (6) und mindestens eine von (4) und (7) vorliegen, sonst 0
lvl(p) = max{ k in 0..3 : r_k >= p }            für jede Position seq p mit 1 <= p <= N
level = lvl(1)
up_to_tree_size = r_level, bei Stufe 0 gleich N
```

Nach Konstruktion gilt r1 ≥ r2 ≥ r3; die Stufe steigt deshalb entlang der Kette nie wieder an. Liegen (4) und (7) beide vor, zählt die größere Reichweite.

**Verlauf** (`segments`): die größtmöglichen Abschnitte aufeinanderfolgender Positionen mit gleichem lvl(p), aufsteigend nach `seq`, je mit `level`, `first_seq`, `last_seq` und `basis`. Ihre Stufen fallen streng, und sie decken `seq` 1 bis N lückenlos ab. `basis` nennt, woran der Abschnitt endet, in der Reihenfolge der Registry (`condition_order`): bei Stufe 3 die vorliegenden Codes unter (3) bis (7), deren Reichweite gleich r3 ist; bei Stufe 2 `receipt_key_confirmed`; bei Stufe 1 die vorliegenden Codes unter (1) bis (3), deren Reichweite gleich r1 ist; bei Stufe 0 keine.

**Nächste Stufe** (`next`): Im Zustand `rated` und bei einer Stufe L unter 3 ist `next` = `{level: L + 1, need: "any" bei L = 0, sonst "all", missing: [...]}`; `missing` nennt die Bedingungen der Stufe L + 1, die nicht vorliegen, in der Reihenfolge der Registry. Für Stufe 3 gelten (4) und (7) als eine Bedingung: Liegt keine von beiden vor, nennt `missing` beide, und der Bericht sagt, dass eine von ihnen genügt; liegt eine vor, nennt `missing` keine von beiden. Bei Stufe 0 genügt eine der Bedingungen (1) bis (3), ab Stufe 1 sind alle Bedingungen der nächsten Stufe nötig. Fehlt bei Stufe 0 die Bedingung (3), fügt der Bericht den Satz „Eine bestätigte Gegensignatur führt unmittelbar zu Stufe 2.“ an. Bei Stufe 3 und außerhalb des Zustands `rated` ist `next` `null`; bei Stufe 3 nennt der Verlauf, woran der Abschnitt der Stufe 3 endet.

Warum die Reichweite: Ein Anker für die `tree_size` t legt sich auf das ganze Präfix 1 bis t fest; jede Bedingung gilt also für jedes kürzere Präfix. Ohne Reichweite läse eine bestätigte Quittung bei `seq` 5 einer Kette mit 100 000 Einträgen als Stufe 2 der ganzen Kette. Warum die Kopfzeile die Stufe von `seq` 1 nennt: Die Stufe des ganzen Pakets wäre wegen des Restfensters immer 0, und die Stufe am letzten gegengezeichneten Checkpoint zeigte für ein frisch exportiertes Paket nie Stufe 3.

Referenzwerte (Verlauf als Stufe, `first_seq` bis `last_seq`, `basis`):

| Fall | N | Reichweiten der vorliegenden Bedingungen | Ergebnis |
|---|---|---|---|
| KAT1 | 32 | (3) 28 | Stufe 2 bis 28; 2 für 1 bis 28 [`receipt_key_confirmed`]; 0 für 29 bis 32 |
| KAT2 | 5050 | (1) 5000, (3) 1000, (4) 10, (5) 900, (6) 4990 | Stufe 3 bis 10; 3 für 1 bis 10 [`time_witness_qualified`]; 2 für 11 bis 1000; 1 für 1001 bis 5000 [`time_witness`]; 0 für 5001 bis 5050 |
| KAT3 | 400 | (1) 398, (2) 390, (3) 396, (4) 398, (5) 300, (6) 390 | Stufe 3 bis 300; 3 für 1 bis 300 [`receipts_logged`]; 2 für 301 bis 396; 1 für 397 bis 398 [`time_witness`]; 0 für 399 bis 400 |
| KAT4 | 16 | keine | Stufe 0; 0 für 1 bis 16; `next` `{1, any, [time_witness, expected_root_found, receipt_key_confirmed]}` |
| KAT5 | 32 | (2) 14 | Stufe 1 bis 14; 1 für 1 bis 14 [`expected_root_found`]; 0 für 15 bis 32 |
| KAT6 | 30 | (1) 20, (4) 20, (6) 28 | Stufe 1 bis 20; 1 für 1 bis 20 [`time_witness`]; 0 für 21 bis 30; `next` `{2, all, [receipt_key_confirmed]}` |
| KAT7 | 320 | (1) 310, (3) 309, (4) 300, (5) 300, (6) 309 | Stufe 3 bis 300; 3 für 1 bis 300 [`time_witness_qualified`, `receipts_logged`]; 2 für 301 bis 309; 1 für 310 bis 310 [`time_witness`]; 0 für 311 bis 320 |
| KAT8 | 400 | (3) 396, (5) 300, (6) 390, (7) 350 | Stufe 3 bis 300; 3 für 1 bis 300 [`receipts_logged`]; 2 für 301 bis 396 [`receipt_key_confirmed`]; 0 für 397 bis 400 |
| KAT9 | 400 | (1) 10, (3) 396, (4) 10, (5) 300, (6) 390, (7) 200 | Stufe 3 bis 200; 3 für 1 bis 200 [`log_day_qualified`]; 2 für 201 bis 396 [`receipt_key_confirmed`]; 0 für 397 bis 400 |
| KAT10 | 32 | (3) 28, (5) 28, (6) 28 | Stufe 2 bis 28; 2 für 1 bis 28 [`receipt_key_confirmed`]; 0 für 29 bis 32; `next` `{3, all, [time_witness_qualified, log_day_qualified]}` (eine der beiden genügt) |

#### 10.9.6 Hinweise

Hinweise ändern die Stufe nie. Jeder steht im Bericht genau dann, wenn sein Anlass zutrifft, einmal, in dieser Reihenfolge (Registry `verifier.evidence_level.note_order`), nur im Zustand `rated`:

| Code | Anlass | Text im Bericht |
|---|---|---|
| `material_contradiction` | Befunde der Exit-Klasse 2 liegen vor, alle aus `material_classes` | Vorgelegte Klartexte oder Berichte widersprechen der Kette (CONTENT_MISMATCH, REPORT_MISMATCH); die Stufe gilt für die Kette, nicht für dieses Material. |
| `unsealed_end` | `UNSEALED_END` liegt vor | Kettenende nicht versiegelt; die Stufe gilt für die vorliegenden Einträge. |
| `stale_package` | `TRAILING_SILENCE` liegt vor | Die Kette endet vor dem Freshness-Fenster (TRAILING_SILENCE); über die Zeit danach sagt die Stufe nichts. |
| `package_not_fully_known` | `SPEC_NEWER`, `UNKNOWN_ENTRY_TYPE` oder `UNKNOWN_MANIFEST_FIELD` liegt vor | Das Paket trägt Angaben, die diese Verifier-Fassung nicht kennt; die Stufe beruht nur auf dem, was sie liest. |
| `vendor_root_builtin_only` | (3) liegt vor, und der Schlüssel jeder angerechneten Quittung ist nur über eine Liste belegt, die die eingebaute Herstellerwurzel trägt | Der Herstellerschlüssel ist nur über die in diesen Verifier eingebaute Herstellerwurzel bestätigt; die Stufe ist nur so unabhängig wie dieser Build. |
| `published_test_key_credited` | eine vorliegende Bedingung beruht auf einem Schlüssel, dessen Publikey als Ed25519-Testschlüssel oder, ab Fassung 1.10, als Testschlüssel nach ML-DSA-87 (Art `ml_dsa_87`) in `published_test_keys` steht (Abschnitt 7.5.7): bei (3) der Schlüssel einer angerechneten Quittung oder die Herstellerwurzel ihrer Liste, bei (5) ein belegter Protokollschlüssel, ein Schlüssel aus P_mldsa (Abschnitt 7.4.10, Schritt L1) oder die Wurzel der wirksamen Protokollschlüsselliste, bei (2) mit der Quelle `anchor_history` und bei (6) der Schlüssel einer verwendeten Seite des Pakets, auf der (2) oder (6) beruht, oder die Herstellerwurzel der Rollenliste, die diesen Schlüssel belegt (Abschnitt 8.8.3); ein angehefteter Bescheidschlüssel beruht auf keiner Rollenliste | Die Stufe beruht auf einem veröffentlichten Testschlüssel (published_test_keys); mit ihm kann jeder signieren. Gegen eine Fälschung belegt die Stufe damit nichts. |
| `last_receipt_not_confirmed` | (3) liegt vor, und die Quittung, die Abschnitt 8.6 als letzte gegengezeichnete wählt, ist nicht angerechnet; `<t>` ist die Reichweite von (3) | Die Gegensignatur des letzten gegengezeichneten Checkpoints ist über keinen Anker des Prüfers bestätigt; Stufe 2 reicht bis tree_size `<t>`. |
| `expected_root_auditor_only` | Stufe 1 an `seq` 1 beruht nur auf (2), und jede dafür angerechnete Wurzel trägt nur die Quelle `auditor`; „beruht nur auf (2)“ heißt: Die Stufe an `seq` 1 ist 1, und von den Bedingungen der Stufe 1 liegt nur (2) vor. Maßgeblich ist nicht `basis` des ersten Abschnitts | Stufe 1 beruht nur auf erwarteten Wurzeln, die der Prüfer übergeben hat; sie trägt so weit, wie er sie vor der Prüfung und außerhalb des geprüften Hauses erhalten hat. |
| `tsa_root_in_package` | eine Wurzel, die (1) anrechnet, hat den SPKI-SHA-256-Wert eines Zertifikats aus `keys/tsa/` | Eine Wurzel für Zeitstempelstellen, auf der die Stufe beruht, hat denselben Schlüssel wie ein Zertifikat aus keys/tsa/ des Pakets. Das ist kein Mangel des Pakets; der Prüfer sollte sie außerhalb des Pakets beschafft haben. |
| `history_recent_roots_skipped` | die Anker-Historie gibt den Hinweis `recent_roots_not_found` (Abschnitt 8.8.7) | Wurzeln aus den 15 Minuten vor der Anforderung liegen hinter dem Paketende; das Paket neu anfordern (Heartbeat-Spezifikation §9.7). |
| `receipts_pending_log` | eine Quittung hat die Klasse `pending` | Gegensignaturen von Tagen, deren Eintrag noch nicht fällig ist; ab 06:00 UTC des Folgetags erneut prüfen. |
| `receipt_not_logged` | `RECEIPT_NOT_LOGGED` liegt vor | Mindestens eine Gegensignatur ist im Herstellerprotokoll nicht nachgewiesen (RECEIPT_NOT_LOGGED); Stufe 3 endet davor, Stufe 2 bleibt. |
| `log_day_not_supplied` | eine Quittung hat die Klasse `missing` | Für Tage mit Gegensignaturen, deren Eintrag schon vorliegen müsste, wurde kein Tageseintrag übergeben; einen vollständigen, aktuellen Auszug abrufen. |
| `hybrid_signature_missing` | ab Fassung 1.10: eine Quittung hat die Klasse `unchecked` mit der Unterklasse `hybrid_incomplete` (Abschnitt 7.4.10, Schritt L8); `<H>` ist `hybrid_ab` der Liste P2 | Tageseinträge ab <H> verlangen eine geltende ML-DSA-Signatur; für mindestens einen Tag einer Gegensignatur liegt keine vor. Fehlt ein Auszug im Format ledger-protokollauszug/2, diesen abrufen; sonst die Befunde VENDOR_LOG_DEFECTIVE und VENDOR_LOG_UNVERIFIED dieses Tages lesen. |
| `logged_root_mismatch` | `LOGGED_ROOT_MISMATCH` liegt vor | Eine im Herstellerprotokoll festgehaltene Wurzel widerspricht dem Paket (LOGGED_ROOT_MISMATCH); Stufe 3 endet davor, Stufe 2 bleibt. |
| `cms_not_implemented` | der Verifier führt die Schritte 5 und 6 aus Abschnitt 7.3 nicht aus (bei den Referenz-Verifiern nie) | Dieser Verifier prüft Signatur und Signaturkette von Zeitstempeln nicht (7.3); über Zeitzeugen erreicht er keine Stufe, Stufe 3 nicht. |

Warum `tsa_root_in_package` für Stufe 1 nur ein Hinweis ist und für Bedingung (4) ein Ausschluss: `keys/tsa/` ist eine Lesehilfe (Abschnitt 10.1), und ein ehrliches Paket eines Dritten, das die Wurzel seiner Stelle mitliefert, verlöre sonst Stufe 1, obwohl der Prüfer die echte Wurzel übergab; ein Fälscher entginge dem Ausschluss, indem er die Wurzel weglässt. Für Bedingung (4) bleibt der Ausschluss, weil sie die Bindung an eine Stelle ist, die weder Kunde noch Hersteller zuzurechnen ist, und eine aus dem Paket kopierte Wurzel einen selbst gebauten „qualifizierten“ Zeugen anrechnen ließe.

#### 10.9.7 Eigenschaften

Jede Eigenschaft ist ein Test beider Referenz-Verifier:

1. Liegt `NO_ANCHOR` vor und ist der Zustand `rated`, ist die Stufe 0; ab Stufe 1 liegt `NO_ANCHOR` nicht vor.
2. Ab Stufe 2 trägt mindestens eine Quittung unter einem Schlüssel, den ein Anker des Prüfers bestätigt.
3. Bei Stufe 3 ist `anchor_history.completeness.status` `established`.
4. Der Verlauf deckt `seq` 1 bis N lückenlos ab, mit streng fallenden Stufen; sein vorderster Abschnitt hat die Stufe `level`.
5. `state` ist genau dann `format_error`, wenn der Exit-Code 3 ist.
6. Ohne die Bestimmung der Stufe ergibt jeder Lauf denselben Exit-Code und dieselben Befunde.
7. Beide Referenz-Verifier geben für dieselben Eingaben identische Objekte `evidence_level` aus.

**Monotonie.** Die Eigenschaft gilt für Läufe im Zustand `rated`. Für ein Paket P und Angaben des Prüfers I ⊆ I′ (mehr Wurzeln für Zeitstempel, Anheftungen, als qualifiziert benannte Wurzeln, erwartete Wurzeln, Seiten der Anker-Historie, Auszüge, Wurzeln für das Protokoll), bei denen der Lauf mit I den Zustand `rated` hat, gilt r_k(P, I′) ≥ r_k(P, I) für jedes k, außer der Lauf mit I′ hat etwas, das der Lauf mit I nicht hat: den Zustand `chain_invalid`; den Zustand `format_error` (etwa ergibt ein hinzugefügtes `--requested-at` nach dem Prüfzeitpunkt Exit 3, Abschnitt 10.8); einen Befund `RECEIPT_NOT_LOGGED`, `LOGGED_ROOT_MISMATCH`, `VENDOR_LOG_CONTRADICTION`, `ANCHOR_HISTORY_CONTRADICTION` oder `ANCHOR_HISTORY_FORK`; einen Befund `VENDOR_LOG_UNVERIFIED` mit dem Grund „Schlüssel in zwei Rollen“ oder „widersprüchliche Listen“ (Abschnitt 7.4.10, Schritt L1); einen Befund `ANCHOR_HISTORY_UNVERIFIED` mit dem Grund `key_not_valid` oder `signing_time_not_proven`; den Status `not_effective` von `key_roles` mit dem Grund `lists_contradictory` oder `key_in_two_roles` oder einen Eintrag in `key_roles.pins_dropped` (Abschnitt 10.7.4); einen Befund `ANCHOR_HISTORY_UNVERIFIED` mit dem Grund `key_not_established` oder `key_other_role`, wo eine zusätzliche Angabe die Rollenliste unwirksam machte oder eine Anheftung als Bescheidschlüssel entfallen ließ; oder einen Befund `RECEIPT_UNVERIFIED`, wo eine zusätzliche Rollenliste eine Anheftung als Gegenzeichnungsschlüssel entfallen ließ. Diese Ausnahmen entstehen, wenn eine zusätzliche Angabe Widerruf, Gültigkeit oder Rolle eines Schlüssels mitteilt: Eine neuere Schlüsselliste mit `widerrufen_ab`, eine Anheftung, die einem Protokollschlüssel gleicht, eine Rollenliste, die einem angehefteten Schlüssel eine andere Rolle gibt, oder eine zweite Liste derselben Version mit anderem Inhalt nimmt einem Schlüssel zu Recht die Wirkung. Eine geänderte Angabe (ein anderer Anforderungszeitpunkt, ein anderer Prüfzeitpunkt) fällt nicht darunter. Geprüft wird das an jedem Testvektor mit einer Prüfumgebung `ledger-pruefumgebung/1` (Abschnitt 10.8): Prüfumgebung des Korpus gegen die des Vektors.

**Neutralität.** Dasselbe Paket mit der Verbundenheit `affiliated`, `not_affiliated`, `not_determined` und `not_checked` ergibt dieselben `level`, `up_to_tree_size` und `segments`.

#### 10.9.8 Texte

Die Texte stehen in der Registry (`verifier.evidence_level`, DE und EN); der Bericht gibt sie unverändert aus. Namen und Texte der Stufen:

| Stufe | Name | Text |
|---|---|---|
| 0 | Selbstauskunft | Die Kette ist in sich geprüft. Ein Beleg durch eine vom Schlüsselinhaber unabhängige Stelle, den der Prüfer bestätigt hat, liegt nicht vor. |
| 1 | extern gebunden | Mindestens ein Stand der Kette ist an einen Zeitzeugen gebunden, dessen Stelle eine Wurzel des Prüfers bestätigt, oder an eine erwartete Wurzel, die der Prüfer übergibt oder die aus einer geprüften Anker-Historie stammt. |
| 2 | gegengezeichnet | Mindestens eine Gegensignatur trägt unter einem Schlüssel, den ein Anker des Prüfers bestätigt. Über die Vollständigkeit sagt diese Stufe nichts. |
| 3 | verankert und abgeglichen | Zusätzlich liegen vor: ein Zeitstempel einer Stelle, die der Prüfer als qualifiziert benannt hat und deren Token sich als qualifiziert ausweist, als Zeitzeuge auf der Kette oder auf dem Tageseintrag des Herstellerprotokolls, in dem die Gegensignatur nachgewiesen ist; der Nachweis der Gegensignaturen in bezeugten Tagen des Herstellerprotokolls; die Vollständigkeit nach einer geprüften Anker-Historie, die nach der Anforderung des Pakets ausgestellt wurde. Einträge nach der jüngsten verankerten Wurzel bleiben im Restfenster (Abschnitt 11.2). |

Bezeichnungen der Bedingungen im Bericht: (1) „Zeitzeuge, dessen Stelle eine vom Prüfer übergebene Wurzel bestätigt (7.3)“; (2) „erwartete Wurzel des Prüfers oder aus der Anker-Historie im Paket gefunden (10.8)“; (3) „Gegensignatur, deren Schlüssel ein Anker des Prüfers bestätigt (7.1)“; (4) „Zeitzeuge einer vom Prüfer als qualifiziert benannten Stelle, dessen Token sich als qualifiziert ausweist“; (5) „Gegensignaturen in bezeugten Tagen des Herstellerprotokolls nachgewiesen (7.4)“; (6) „Vollständigkeit nach einer geprüften Anker-Historie, ausgestellt nach der Anforderung des Pakets (8.8)“; (7) „Gegensignaturen in Tagen des Herstellerprotokolls nachgewiesen, deren Eintrag den Zeitstempel einer vom Prüfer als qualifiziert benannten Stelle trägt, der sich als qualifiziert ausweist, höchstens 36 Stunden nach der Gegensignatur (7.4.6)“.

Abschluss jedes Blocks der Beweisstufe (Abschnitt 10.10.3): „Die Beweisstufe unterstützt Aussagen darüber, wie stark die vorliegende Kette gegen ein Umschreiben durch ihren Schlüsselinhaber belegt ist. Sie gewährleistet nichts und sagt nichts über den Inhalt der Aufrufe. Sie ist nur so unabhängig wie dieser Verifier und die Angaben, die der Prüfer ihm übergeben hat.“

Für die Texte gilt: Von einer Bedingung sagen sie „liegt vor“ oder „fehlt“. Kein Name einer Stufe enthält „unabhängig“. „Qualifiziert“ steht nur als „vom Prüfer als qualifiziert benannt“ oder „weist sich als qualifiziert aus“, nie als Aussage über den Status einer Stelle. Kein Text sagt, die Kette, der Betreiber oder LEDGER halte eine Vorschrift ein; wie für jeden Beleg gilt die Sprachregel der Pflicht-Deckungs-Tafel (`spec/pflichten.de.md`, §4). Kein Text nennt einen bestimmten Hersteller.

### 10.10 Berichtsangaben

Ab Fassung 1.10. Dieser Abschnitt legt die Angaben des Berichts fest, die keine Befunde sind, für beide Referenz-Verifier gleich: ihren Ort in der JSON-Ausgabe, ihre Member und die Textblöcke. Sie sind kein Teil des Urteils und ändern den Exit-Code nicht (Abschnitt 10.3).

#### 10.10.1 Pfad und `null`

- **Pfad.** Angaben des Berichts, die keine Befunde sind, stehen in der JSON-Ausgabe des Go-Verifiers unter `stats`, in der des Zweitverifiers auf oberster Ebene, jeweils mit denselben Namen und derselben Form: `completeness` (Abschnitt 8.6, ab Fassung 1.10 mit `sources`), `residual_window` und `unanchored_stretches` (Abschnitt 11.2), `key_roles` (Abschnitt 10.7.4), `vendor_log` (Abschnitt 7.4), ab Fassung 1.10 `cose_receipts` (Abschnitt 7.7), `anchor_history` und `affiliation` (Abschnitt 8.8), `evidence_level` (Abschnitt 10.9) und jede künftige Angabe dieser Art. Die Membernamen sind für beide Referenz-Verifier normativ.
- **Immer ein Objekt.** Für jedes Paket, das kein Formatfehler ist, sind `key_roles`, `vendor_log`, `anchor_history`, `affiliation` und `evidence_level` und ab Fassung 1.10 `cose_receipts` Objekte, auch ohne die zugehörige Angabe des Prüfers (`status` `not_supplied` beziehungsweise `not_checked`). Eine fehlende Angabe ist nie ein fehlendes Member.
- **Exit 3.** Bei einem Formatfehler sind `key_roles`, `vendor_log`, `anchor_history`, `affiliation` und ab Fassung 1.10 `cose_receipts` `null`; `evidence_level` ist vorhanden, mit `state` `format_error` (Abschnitt 10.9.2). Für `completeness`, `residual_window` und `unanchored_stretches` gelten weiter die Abschnitte 8.6 und 11.2: Bei einem Formatfehler sind sie nicht bewertet. Die drei Member stehen dann mit dem Wert `null` („nicht bewertet“) im Bericht und fehlen nie.
- **Kein Bericht.** Ein unbrauchbarer Aufruf (Abschnitt 10.8) schreibt keinen Bericht und keines dieser Objekte.
- **Zeitpunkte.** Zeitpunkte, die der Verifier selbst bildet, aus ganzen Millisekunden oder aus einer Angabe des Prüfers (etwa `requested_at` und `span`), schreibt er in der Form `JJJJ-MM-TTThh:mm:ss.sssZ`. Zeitpunkte aus signierten Objekten übernimmt er Zeichen für Zeichen.
- **Ordnung.** Listen von Codes stehen in der Reihenfolge der Registry; andere Listen in der Ordnung, die bei ihrem Member genannt ist.
- **Browser-Fassung.** Ihr Ergebnis trägt zusätzlich `evidenceLevel` (Zahl oder `null`), `evidenceState` (Zeichenkette) und `affiliationStatus` (Zeichenkette oder `null`); die vollständigen Objekte stehen in ihrem Member `json`. Es DARF außerdem die beiden Zeilen unter dem Urteil (Abschnitt 10.10.3) als `evidenceLine` und `affiliationLine` tragen (Zeichenkette oder `null`); sie sind Text für den Leser, keine Angabe für Maschinen.

#### 10.10.2 Objekte

Schreibweise wie in Abschnitt 7.4.8: `x?` heißt `x` oder `null`.

**`key_roles`** (Abschnitt 10.7.4):

```
{"status":         "not_supplied" | "effective" | "not_effective",
 "reason":         "format" | "no_matching_root" | "signature" | "lists_contradictory"
                   | "key_in_two_roles" | null,
 "candidates":     int,
 "list":           {"version": int, "ausgestellt": rfc3339, "wurzel_id": key-id,
                    "root_source": "vendor_root" | "builtin", "ende_doppelbetrieb": rfc3339?}?,
 "statement_keys": [{"key_id": key-id, "source": "role_list" | "pinned"}],
 "pins_dropped":   [{"key_id": key-id, "pinned_as": "countersigning" | "statements" | "protocol" | "transparency",
                     "listed_as": code}],
 "notes":          [code]}
```

- `status` und `reason` nach Abschnitt 10.7.4; `reason` ist bei `not_supplied` und `effective` `null`.
- `candidates`: die Zahl der verschiedenen Rollenlisten (Schritt R1).
- `list`: die wirksame Rollenliste Q mit der Herkunft ihrer Wurzel (Wurzel des Prüfers oder eingebaut), ohne Q `null`. Eine Wurzel, die eingebaut ist und die der Prüfer auch übergibt, zählt als `vendor_root`.
- `statement_keys`: die Bescheidschlüssel, die Seiten belegen können (Anheftungen, die nicht entfallen, und Einträge von Q mit der Rolle `statements`), aufsteigend nach `key_id`. Ein Schlüssel, der angeheftet und zugleich ein Eintrag von Q mit der Rolle `statements` ist (dieselbe `key_id`), steht hier einmal, mit `source` `pinned`, denn Schritt R4 nimmt die Anheftungen zuerst.
- `pins_dropped`: die entfallenen Anheftungen (Schritt R3 (d)), aufsteigend nach `key_id`; `listed_as` ist die Rolle, mit der eine Liste den Publikey nennt (eine Rolle aus Q, `countersigning` für K_cs^L, `protocol` für die Protokollschlüsselliste).
- `notes`: die Hinweise `unknown_role`, `receipt_key_other_role` und `pin_dropped`, soweit sie zutreffen, in dieser Reihenfolge.

Ohne Rollenliste ist `status` `not_supplied`, `reason` und `list` sind `null`, `candidates` ist 0, und `statement_keys` nennt nur Anheftungen.

**`vendor_log`** (Abschnitt 7.4.10, Schritt L10):

```
{"status":             "not_supplied" | "no_protocol_key" | "checked",
 "log_id":             key-id?,
 "first_day":          date?,
 "key_source":         "list" | "pinned" | "list_and_pinned" | null,
 "key_list":           {"version": int, "ausgestellt": rfc3339, "wurzel_id": key-id,
                        "root_source": "vendor_root" | "builtin",
                        "format": "ledger-protokollschluessel/1" | "ledger-protokollschluessel/2",
                        "hybrid_from": date?, "ml_dsa_keys": int, "ml_dsa_list_version": int?,
                        "unknown_alg": bool, "log_uri": string?}?,
 "places":             [string],
 "files":              int,
 "distinct_files":     int,
 "head":               {"day": date, "day_hash": hex64, "tree_size": int,
                        "witnessed": bool, "seen_in": int}?,
 "days":               {"supplied": int, "established": int, "witnessed": int,
                        "contradictory": int, "missing": int,
                        "signatures_not_checked": int,
                        "hybrid_required": int, "hybrid_incomplete": int},
 "seals":              {"ml_dsa": {"carried": int, "defective": int, "key_not_established": int},
                        "not_checked": int},
 "cose_not_checked":   int,
 "day_receipts":       {"supplied": int, "matching": int, "contradicting": int, "defective": int,
                        "key_not_established": int, "key_not_valid": int, "other_log": int,
                        "day_not_determined": int},
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

- `status` nach den Schritten L0 und L1; `log_id` die `log_id` der Auszüge; `first_day` der Beginn F (Schritt L2 (f)), `null`, wenn F unbekannt ist.
- `key_source`: wie die Protokollschlüssel belegt sind, durch die wirksame Liste, durch Anheftungen oder durch beides; `key_list` nennt die wirksame Liste mit der Herkunft ihrer Wurzel (Wurzel des Prüfers oder eingebaut); `places` deren `orte` in der Reihenfolge der Liste, ohne wirksame Liste leer.
- `key_list` ab Fassung 1.10: `format` das Format der wirksamen Liste P; `hybrid_from` der Tag H (Abschnitt 7.4.10, Schritt L1, Nummer 6), sonst `null`; `ml_dsa_keys` die Zahl der Schlüssel in P_mldsa; `ml_dsa_list_version` die `version` von P2, ohne P2 `null`, sodass der Bericht beide Versionen nennt, wenn P ein Kandidat `/1` mit größerer `version` als P2 ist; `unknown_alg` sagt, ob P2 einen Eintrag mit einem unbekannten `alg` nennt (Abschnitt 7.4.7a); `log_uri` ist `log_uri` von P2, ohne P2 `null` (Abschnitt 7.7.5). Ist P ein zusammengelegter Kandidat (Abschnitt 7.4.10, Schritt L1, Nummer 2), stammen `version`, `ausgestellt`, `wurzel_id` und `root_source` aus der Liste `/2`. Ohne P2 ist `unknown_alg` `false`.
- `files` die Zahl der übergebenen Auszüge, eingebettete mitgezählt (Abschnitt 8.8.2), `distinct_files` die Zahl verschiedener nach ihren Bytes.
- `head` der Kopf nach Schritt L4 mit dem Tageshash von c(Kopf), `witnessed` sagt, ob c(Kopf) bezeugt ist.
- `days`: `supplied` die Tagesobjekte nach dem Zusammenlegen (Schritt L2), `established` die festgestellten, `witnessed` die nutzbaren Tage (Schritt L3), `contradictory` die Tage mit einem Befund `VENDOR_LOG_CONTRADICTION`, `missing` die fehlenden Tage des verlangten Bereichs (Schritt L7), `signatures_not_checked` die Summe über alle Tagesobjekte nach dem Zusammenlegen (Schritt L2), festgestellt oder nicht, der Zahl verschiedener Elemente von `additional_signatures`, deren `alg` nicht `ed25519` ist (verschieden nach `alg`, `key_id` und `signature`); Elemente mit `alg` = `ed25519` zählen hier nie, auch nicht unter einem nicht belegten Schlüssel. `signatures_not_checked` wird in denselben Fällen gebildet wie `supplied`. Mit Status `no_protocol_key` läuft Schritt L2 nicht; `supplied` und `signatures_not_checked` sind dann 0. Ab Fassung 1.10 zählt `hybrid_required` bei H ≠ `null` jedes Tagesobjekt nach dem Zusammenlegen mit `dayOf(o)` ≥ H, gleich mit welchem Ergebnis, und `hybrid_incomplete` die hybrid-unvollständigen (Schritt L2 (g′)).
- `seals` (ab Fassung 1.10): Summen über alle Tagesobjekte nach dem Zusammenlegen (Schritt L2), festgestellt oder nicht, je über verschiedene Siegel (verschieden nach `type`, `key_id` und `value`). `ml_dsa.carried` die tragenden ML-DSA-Siegel, `ml_dsa.defective` die Siegel `ml-dsa-87` unter einem Schlüssel aus P_mldsa, die nach Schritt L2 (b′) nicht tragen, `ml_dsa.key_not_established` die Siegel `ml-dsa-87`, deren `key_id` keinen Schlüssel aus P_mldsa nennt, `not_checked` die Siegel jedes anderen `type`, auch `cades-b-t` (Abschnitt 7.4.8a). `seals` wird in denselben Fällen gebildet wie `days.supplied`; mit Status `no_protocol_key` oder ohne Auszug `/2` sind alle Zahlen 0.
- `cose_not_checked` (Fassung 1.10): die Zahl der verschiedenen Elemente von `day_receipts` (je Tagesobjekt nach dem Zusammenlegen) und von `cose_receipts` (je Auszug) aller Auszüge `/2`; ein Verifier 1.10 prüft sie nicht (Abschnitt 7.4.8a). Ohne Auszug `/2` ist der Wert 0. Ab Fassung 1.11 treten `day_receipts` und das Objekt `cose_receipts` an diese Stelle.
- `day_receipts` (ab Fassung 1.10, Abschnitt 7.4.10, Schritt L3a): Summen über alle Tagesobjekte nach dem Zusammenlegen, festgestellt oder nicht, je über die verschiedenen Elemente ihrer `day_receipts`. `supplied` ist ihre Zahl; jedes Element zählt in genau einer der übrigen Klassen. `day_receipts` wird in denselben Fällen gebildet wie `days.supplied`; mit Status `no_protocol_key` oder ohne Auszug `/2` sind alle Zahlen 0.
- `tsa`: `cms_checked` sagt, ob der Verifier Schritt 5 und 6 des Profils ausführt (bei den Referenz-Verifiern `true`); `roots_supplied` die Zahl der Wurzeln des Zwecks `log`.
- `receipts`: die Zahl der Quittungen je Klasse (Schritt L8); `included_up_to_tree_size` ist die Vorreichweite r5′ aus Abschnitt 10.9.4, `null`, wenn sie 0 ist. `receipts` ist `null`, wenn der Status nicht `checked` ist, denn dann sind die Klassen unbestimmt. Ab Fassung 1.10 zählt `unchecked` auch die Quittungen mit der Unterklasse `hybrid_incomplete`.
- `last_countersigned`: die Klasse der Quittung, die Abschnitt 8.6 als letzte gegengezeichnete wählt; `null` ohne sie oder ohne Status `checked`.
- `logged_roots` (Schritt L9): `matching_prefix` und `contradicting_prefix` zählen die verschiedenen (`tree_size`, `merkle_root`) mit t ≤ N, die zum Paket passen oder ihm widersprechen, `matching_without_receipt` die verschiedenen passenden Blätter `countersigned` ohne Quittung desselben Blatts im Paket (eine Quittung mit `RECEIPT_INVALID` ist dafür eine Quittung ihres Blatts), `beyond_package` die mit t > N, `gap_witnesses` die verschiedenen Wurzeln (`tree_size`, `merkle_root`) unter den geprüften Zeilen mit `recorded_as` `gap_witness`, nicht die verschiedenen Blätter, auch solche, die dem Paket widersprechen oder hinter ihm liegen; `null`, wenn der Status nicht `checked` ist.
- `foreign_chain_records`: die Kettentag-Nachweise anderer Ketten (Schritt L6); gezählt wird jeder Nachweis jedes Auszugs, auch ein gleicher Nachweis in mehreren Dateien.

Ohne Auszug ist `status` `not_supplied`, `log_id`, `first_day`, `key_source`, `key_list`, `head`, `receipts`, `last_countersigned` und `logged_roots` sind `null`, `places` ist leer, und jeder Zählwert ist 0, auch `tsa.roots_supplied`, wenn der Prüfer Wurzeln des Zwecks `log` übergibt.

**`cose_receipts`** (Abschnitt 7.7.6, Schritt K, ab Fassung 1.10):

```
{"status":               "not_supplied" | "checked",
 "key_source":           "role_list" | "pinned" | "role_list_and_pinned" | null,
 "supplied":             int,
 "foreign_chain":        int,
 "other_log":            int,
 "defective":            int,
 "key_not_established":  int,
 "key_not_valid":        int,
 "matching_prefix":      int,
 "contradicting_prefix": int,
 "root_not_attributed":  int,
 "beyond_package":       int,
 "with_chain_receipt":   int}
```

- `status` ist `checked`, wenn X_C oder X_F (Schritt K) ein Element hat, sonst `not_supplied`.
- `key_source`: woher die Schlüssel stammen, die T nach dem Vorrang der Anheftungen tatsächlich enthält (Abschnitt 7.7.5), nur aus der Rollenliste, nur aus Anheftungen oder aus beiden; ein Eintrag von Q, dessen `key_id` eine Anheftung trägt, zählt nicht; ohne Schlüssel in T `null`. Es wird auch mit Status `not_supplied` gebildet.
- `supplied` ist die Zahl der Elemente von X_C und X_F zusammen; jedes zählt in genau einer der Klassen von `foreign_chain` bis `beyond_package`, und `with_chain_receipt` ist ein Teil von `matching_prefix` (Schritt K7).
- `contradicting_prefix` zählt Elemente, nicht verschiedene Paare (t, r); den Befund `COSE_RECEIPT_MISMATCH` gibt es je Paar einmal (Abschnitt 7.7.7).

Mit Status `not_supplied` ist jeder Zählwert 0.

**`anchor_history`** (Abschnitt 8.8.4, Schritt H13):

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

- `status` ist `checked`, sobald eine Datei der Anker-Historie übergeben ist; `requested_at` ist R oder `null`; `files` die Zahl der Dateien.
- `pages`: `supplied` alle Seiten aller Dateien, `distinct` die verschiedenen nach Schritt H1, die vier Arten verwendeter Seiten nach Schritt H2, Nummer 10, und `not_used` die übrigen verschiedenen Seiten; `page_reasons` die Gründe aus Schritt H2, an denen nicht verwendete Seiten scheiterten, je einmal.
- `issued`: der früheste und der späteste `server_ts` der verwendeten Seiten des Pakets.
- `keys`: je `server_key_id` einer verwendeten Seite die Herkunft nach Abschnitt 8.8.3, aufsteigend nach `key_id`; `list` nennt die wirksame Rollenliste, bei einer Anheftung `null`.
- `owner`: `matches`, wenn eine Seite des Pakets Schritt H2, Nummer 8 bestanden hat; `differs`, wenn Seiten des Pakets Nummer 8 erreicht und keine sie bestanden hat; sonst `null`.
- `coverage` nach Schritt H4; `gaps` sind die Lücken als Bereiche [a, b), mit `null` für b = ∞, aufsteigend nach a.
- `reference_tree_size`, `predecessor` und `successor` sind die Werte der Seite H* (Abschnitt 8.8.6, Nummer 3), ohne sie `null`.
- `roots`: `distinct` die Historienwurzeln (Schritt H6), `found` die gefundenen (Abschnitt 8.8.5); `differing_before_request` die Wurzeln mit t ≤ N, die dem Paket widersprechen und, mit R übergeben, ein e vor R − W_h haben (Schritt H6), gleich ob sie `MERKLE_INCONSISTENT` oder, nur gemeldet, `ANCHOR_HISTORY_FORK` ergeben, `differing_after_request` die übrigen widersprechenden; `beyond_package_before_request` die Wurzeln mit t > N und e < R − W_h, gleich ob sie `MERKLE_INCONSISTENT` oder, nur gemeldet, `ANCHOR_HISTORY_FORK` ergeben; die drei weiteren Zählwerte nach Abschnitt 8.8.5 und `not_used_vendor_log` nach Schritt H7. Ein Paar, das auch die Quelle `auditor` trägt, zählt hier wie jede Historienwurzel nach t, `root(t)`, e und R; sein Befund folgt Abschnitt 10.8.
- `forks`: `listed` die verschiedenen Fork-Befunde (t, r) nach Schritt H9, `omitted` der größte Wert von `forks_omitted` auf verwendeten Seiten des Pakets.
- `receipts`: die Zählwerte aus Schritt H10, `checked` die Zahl der Quittungen, die Schritt H10 prüft.
- `completeness`: das Ergebnis von Schritt H11; `reasons`: je Befundklasse die gemeldeten Gründe (Abschnitt 8.8.7); `notes`: die Hinweise aus Abschnitt 8.8.7.

Ohne Anker-Historie ist `status` `not_supplied`, jeder Zählwert ist 0, jede Liste leer, `issued.first`, `issued.last`, `owner`, `reference_tree_size`, `predecessor` und `successor` sind `null`, `coverage` ist `{"status": "none", "gaps": []}` und `completeness` ist `{"status": "not_established", "reason": "not_supplied", "up_to_tree_size": null}`; `requested_at` und der Hinweis `requested_at_unused` folgen Abschnitt 10.8.

**`affiliation`** (Abschnitt 8.8.6):

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

- `reason`: bei `not_determined` der Grund (Abschnitt 8.8.6, Nummern 2 und 7), sonst `null`.
- `bases`: bei `affiliated` die Vereinigung der Grundlagen der Zeiträume, die sich mit dem Zeitraum des Pakets überschneiden, in der Reihenfolge der Codes aus Heartbeat-Spezifikation §9.10, sonst leer; `vendor_itself` ist `true`, wenn `vendor` darunter ist.
- `span` der Zeitraum des Pakets (Nummer 5), `as_of` und `known_since` die Werte der Seite H*, `stated_by` deren Schlüssel mit seiner Herkunft.
- `periods`: alle Zeiträume nach Nummer 4, je mit `overlaps_package` (Nummer 8). `until` ist das Ende nach Nummer 4, `null` nur für einen Zeitraum, der auf H* andauert. Gleiche Objekte (gleich nach den Bytes ihrer JCS-Form) stehen einmal; geordnet sind sie aufsteigend nach `from`, dann nach `until` (`null` zuletzt), dann nach den Bytes von JCS(`bases`), dann nach `recorded_ts`, dann `merged` `false` vor `true`, dann `overlaps_package` `false` vor `true`; die drei Zählwerte nach Nummer 10; `contradictory` nach Nummer 9; `linked` je verknüpfte Kette nach Nummer 11, aufsteigend nach `chain_id`.

Ohne verwendete Seite des Pakets (Status `not_checked` oder `not_determined` nach Nummer 2) sind `span`, `as_of`, `known_since`, `stated_by` und die drei Zählwerte `null`, `bases` und `periods` leer und `vendor_itself` und `contradictory` `false`.

**`evidence_level`** (Abschnitt 10.9):

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

- `level`, `entries` (N), `up_to_tree_size`, `conditions`, `next`, `qualified_time` und `anchors` sind `null`, `segments` und `notes` leer, wenn der Zustand nicht `rated` ist.
- `qualified_time`: bei Stufe 3 an `seq` 1 der Gegenstand, der den qualifizierten Zeitpunkt für den Stand bis `up_to_tree_size` belegt. Kandidaten sind die angerechneten Gegenstände von (4) (TIME_ANCHOR je Wurzel) und von (7) (Quittung je Zeitstempel und Wurzel) mit `tree_size` ≥ `up_to_tree_size`; gewählt ist der mit dem frühesten `genTime`, bei Gleichstand (4) vor (7), dann die kleinere `tree_size`, dann bei (7) der frühere `server_ts` der Quittung. „Der mit dem frühesten `genTime`“ vergleicht `genTime` als Zeitpunkt auf Nanosekunden, wie die Zeiträume aus Abschnitt 10.8, vor jedem Abschneiden auf ganze Millisekunden; Gleichstand heißt derselbe Zeitpunkt. `via` nennt die Bedingung, `tree_size` die des Gegenstands, `latest` seinen `genTime`, auf ganze Millisekunden abgeschnitten, in der Form `JJJJ-MM-TTThh:mm:ss.sssZ`: Der Stand bestand spätestens zu diesem Zeitpunkt. `gap_ms` ist bei (7) `latest` minus `server_ts` der Quittung in ganzen Millisekunden, bei (4) `null`. Unterhalb von Stufe 3 an `seq` 1 ist `qualified_time` `null`.
- `anchors.vendor_keys`: je Schlüssel einer angerechneten Quittung, aufsteigend nach `key_id`, wie er belegt ist (Anheftung oder Liste mit Version, `wurzel_id` und Herkunft der Wurzel).
- `anchors.statement_keys`: ohne Wiederholung die Paare aus Bescheidschlüssel und Herkunft (`key_id`, Publikey, Herkunft) der verwendeten Seiten des Pakets, auf denen eine vorliegende Bedingung beruht: für (2) mit der Quelle `anchor_history` die verwendeten Seiten, die die festgehaltene Aufzeichnung einer gefundenen erwarteten Wurzel tragen (Abschnitt 8.8.5); für (6), wenn sie vorliegt, jede verwendete Seite, die in die Vollständigkeit eingeht (Abschnitt 8.8.4, Schritt H11). (6) beruht damit auf den frischen verwendeten Seiten des Pakets: Nur sie gehen in die Vollständigkeit ein, eine ältere Seite nie (Abschnitt 8.8.4, „Ältere Seiten“), und (6) setzt R voraus. Auf dieselben Seiten verweisen der Hinweis `published_test_key_credited` (Abschnitt 10.9.6) und `<Anker>` im Block der Beweisstufe (Abschnitt 10.10.3), wo sie die Seiten nennen, auf denen (6) beruht. Für eine Seite ist das Paar das, das der Bericht für diese Seite in `anchor_history` nennt; nennt er mehrere, jedes davon. Je Paar steht, wie der Schlüssel belegt ist (Anheftung oder Rollenliste mit Version, `wurzel_id` und Herkunft der Wurzel), in der Reihenfolge von `anchor_history.keys`; ohne solche Seite leer.
- **Namen der Herkunft.** Eine Anheftung heißt in jedem Objekt `pinned`. Die Herkunft einer Wurzel heißt in `key_roles.list.root_source`, `vendor_log.key_list.root_source` und `anchor_history.keys[].list.root_source` `vendor_root` oder `builtin`, in `evidence_level.anchors.vendor_keys[].root_from` und `evidence_level.anchors.statement_keys[].root_from` `auditor` oder `builtin` und in `affiliation.stated_by.key_source` `role_list_auditor_root` oder `role_list_builtin_root`. `vendor_root`, `auditor` und `role_list_auditor_root` bezeichnen dieselbe Herkunft: eine Herstellerwurzel, die der Prüfer übergeben hat.
- `anchors.tsa_roots`: je Wurzel, die (1), (4) oder (7) anrechnet, aufsteigend nach `cert_sha256`, dem SHA-256-Wert ihres Zertifikats (DER) als Fingerabdruck; `credited_for` nennt diese Bedingungen in der Reihenfolge der Registry, etwa `["time_witness"]`, `["time_witness", "time_witness_qualified"]` oder `["log_day_qualified"]`.
- `anchors.qualified_roots_file`: `stand` und `quelle` der Datei `ledger-tsa-qualifiziert/1` (Abschnitt 10.8), ohne sie `null`. `stand` schreibt der Verifier in der Form `JJJJ-MM-TTThh:mm:ss.sssZ`, auf ganze Millisekunden abgeschnitten, wie jeden Zeitpunkt aus einer Angabe des Prüfers (Abschnitt 10.10.1, Zeitpunkte); `quelle` übernimmt er, wie sie geschrieben ist; `anchors.expected_root_sources`: die Quellen der Wurzeln, die (2) anrechnet, in der Reihenfolge `auditor`, `anchor_history` wie bei `completeness.sources` (Abschnitt 8.6).
- `affiliation`: `status` und `vendor_itself` des Objekts `affiliation`, auch im Zustand `chain_invalid`; `null` nur im Zustand `format_error`.

Beispiel (Testvektor `valid_basic` in der Prüfumgebung des Korpus, eine Zeile, Member in JCS-Reihenfolge):

```
{"affiliation":{"status":"not_checked","vendor_itself":false},"anchors":{"expected_root_sources":[],"qualified_roots_file":null,"statement_keys":[],"tsa_roots":[],"vendor_keys":[{"key_id":"vendor-test-001","list_version":null,"root_from":null,"root_id":null,"via":"pinned"}]},"conditions":{"completeness_from_history":{"count":0,"met":false,"reason":"anchor_history_not_supplied","up_to_tree_size":null},"expected_root_found":{"count":0,"met":false,"reason":"no_expected_root_found","up_to_tree_size":null},"log_day_qualified":{"count":0,"met":false,"reason":"vendor_log_not_supplied","up_to_tree_size":null},"receipt_key_confirmed":{"count":12,"met":true,"reason":null,"up_to_tree_size":309},"receipts_logged":{"count":0,"met":false,"reason":"vendor_log_not_supplied","up_to_tree_size":null},"time_witness":{"count":0,"met":false,"reason":"no_time_anchor","up_to_tree_size":null},"time_witness_qualified":{"count":0,"met":false,"reason":"no_time_anchor","up_to_tree_size":null}},"entries":311,"level":2,"next":{"level":3,"missing":["time_witness_qualified","receipts_logged","completeness_from_history","log_day_qualified"],"need":"all"},"notes":["unsealed_end","published_test_key_credited"],"qualified_time":null,"segments":[{"basis":["receipt_key_confirmed"],"first_seq":1,"last_seq":309,"level":2},{"basis":[],"first_seq":310,"last_seq":311,"level":0}],"state":"rated","up_to_tree_size":309}
```

Die Schemata `spec/schemas/report_key_roles.schema.json`, `report_vendor_log.schema.json`, `report_anchor_history.schema.json`, `report_affiliation.schema.json` und `report_evidence_level.schema.json` werden aus der Registry erzeugt; jeder Lauf über das Testkorpus prüft die Ausgabe beider Referenz-Verifier gegen sie. Ab der Erweiterung der Fassung 1.10 kommt `report_cose_receipts.schema.json` hinzu; die neuen Member (`cose_receipts`, `vendor_log.day_receipts`, `vendor_log.key_list.log_uri`) verlangen die erzeugten Schemata erst, wenn beide Referenz-Verifier sie ausgeben.

#### 10.10.3 Textblöcke

Beide Referenz-Verifier geben im Textbericht dieselben Blöcke in dieser Reihenfolge aus, jede Wendung aus der Registry, in der Sprache des Berichts, `<…>` ersetzt: die bisherigen Zusammenfassungszeilen (Kettenende, Vollständigkeit, Restfenster, gedeckte Strecken, Hersteller-Schlüsselliste, Hinweis zur Lizenz); den Block des Herstellerprotokolls; ab Fassung 1.10 die Zeilen der COSE Receipts; den Block der Anker-Historie; den Block der Beweisstufe, dessen letzte Zeile die Zeile zur Verbundenheit ist; danach „keine Befunde.“ oder die Befunde. Bei Exit 3 entfallen die Blöcke des Herstellerprotokolls und der Anker-Historie, die Zeilen der COSE Receipts und die Zeile zur Verbundenheit. Für `key_roles` hat der Textbericht in dieser Fassung keinen Block; das Objekt steht nur in der JSON-Ausgabe (Abschnitt 10.10.2).

**Herstellerprotokoll.**

- Status `checked`: drei Zeilen aus den Texten `checked_head`, `receipts` und `compare` der Registry (`vendor_log.texts`), in dieser Reihenfolge; die erste steht ohne Einrückung, die beiden anderen sind um zwei Leerzeichen eingerückt, wie im Block der Anker-Historie:

```
Herstellerprotokoll <log_id>: Kopf <day>, Tageshash <day_hash>, bezeugt: <ja|nein>, in <seen_in> von <distinct_files> Dateien.
  Quittungen: <included> nachgewiesen, <not_included> fehlen, <unchecked> nicht prüfbar, <missing> ohne Tageseintrag, <pending> noch nicht fällig, <before_start> vor Beginn des Protokolls, <future> nach dem Prüfzeitpunkt.
  Vergleichen Sie den Tageshash mit dem zweiten Veröffentlichungsort.
```

  Ist kein Kopf bestimmt (Abschnitt 7.4.10, Schritt L4), lautet die erste Zeile „Herstellerprotokoll `<log_id>`: kein Tageseintrag festgestellt.“ (Text `checked_no_head`). Ersetzt wird nur diese Zeile; die beiden anderen bleiben, auch die Zeile zum Vergleich des Tageshashes.
- Status `no_protocol_key`: „Herstellerprotokoll übergeben, aber kein Protokollschlüssel durch einen Anker des Prüfers belegt (`<Grund>`).“ mit dem Grund aus Schritt L1, Nummer 4.
- Status `not_supplied`: „Herstellerprotokoll: nicht übergeben. Ob der Hersteller die Quittungen protokolliert hat, sagt dieser Bericht nicht (Abschnitt 7.4).“

**COSE Receipts** (ab Fassung 1.10). Die erste Zeile steht nur, wenn `cose_receipts.status` `checked` ist, die zweite nur, wenn `vendor_log.day_receipts.supplied` größer als 0 ist; die erste steht ohne Einrückung, die zweite ist um zwei Leerzeichen eingerückt, ohne die erste ebenfalls ohne Einrückung:

```
COSE Receipts nach RFC 9942: <matching_prefix> von <supplied> Gegensignaturen passen zum Paket, <contradicting_prefix> widersprechen ihm, <beyond_package> liegen dahinter, <defective> tragen nicht.
  COSE Receipts der Tage: <matching> von <supplied> passen zum Tageseintrag, <contradicting> widersprechen ihm, <defective> tragen nicht.
```

Die Zahlen stammen aus `cose_receipts` und `vendor_log.day_receipts`. Kein Text nennt die Objekte anders als „COSE Receipts nach RFC 9942“. COSE-Objekte ändern die Beweisstufe nicht, außer über einen Widerspruch nach Schritt L3a: Ein C1 ändert weder die Beweisstufe noch eine andere Zeile des Berichts; ein Widerspruch eines C2 erscheint wie jeder Widerspruch des Herstellerprotokolls (Abschnitt 7.4.10, Schritt L3a).

**Anker-Historie.**

- Mit verwendeten Seiten des Pakets:

```
Anker-Historie: <u> von <d> Seiten verwendet (<f> nach der Anforderung ausgestellt, <s> ältere Kopien), ausgestellt <first> bis <last>, Schlüssel <key_id> (<Quelle>); Gerät der Kette: passt zum Paket.
  Anforderung des Pakets: <R> (Angabe des Prüfers).
  Wurzeln: <n> verschieden; bis tree_size <N>: <found> gefunden, <diff> weichen ab; dahinter: <b> vor der Anforderung festgehalten, <r> in den 15 Minuten davor (Paket neu anfordern), <a> danach.
  Vollständigkeit aus der Anker-Historie: belegt bis tree_size <T>. | nicht belegt (<Grund>).
```

  Dabei ist `<u>` die Zahl der verwendeten Seiten des Pakets, `<d>` `pages.distinct`, `<f>` `used_fresh`, `<s>` `used_stale`, `<diff>` die Summe von `differing_before_request` und `differing_after_request`, `<b>`, `<r>` und `<a>` die Zählwerte `beyond_package_before_request`, `beyond_package_recent` und `beyond_package_after_request`; bei mehreren Schlüsseln steht je Schlüssel einmal „`<key_id>` (`<Quelle>`)“. `<Quelle>` ist „angeheftet“, „Rollenliste Version `<v>`, Wurzel `<w>` des Prüfers“ oder „Rollenliste Version `<v>`, im Verifier eingebaute Wurzel `<w>`“. Ohne Anforderungszeitpunkt lautet die zweite Zeile „Ohne Anforderungszeitpunkt (--requested-at) ist eine Kürzung des Pakets nicht beurteilt; `<n>` Wurzeln hinter dem Paketende sind gezählt, nicht bewertet.“ mit `<n>` = `beyond_package_unjudged`.
- Übergeben, aber keine Seite des Pakets verwendet: „Anker-Historie: `<d>` Seiten übergeben, keine für dieses Paket verwendet (`<Gründe>`).“ mit den Texten der Gründe aus `page_reasons`; ist `owner` `differs`, folgt als zweite Zeile der Text `owner_differs_detail` (Registry `verifier.anchor_history.texts`); danach die Zeile zur Vollständigkeit.
- Nicht übergeben: „Anker-Historie: nicht übergeben. Ob das Paket alles enthält, was der Hersteller vor der Anforderung festgehalten hat, ist damit nicht geprüft. Holen Sie die Historie mit der chain_id `<id>` selbst beim Hersteller ab (GET /v1/anchors?chain_id=`<id>`&kind=ledger.anchor_history.v2) und übergeben Sie sie mit --anchor-history und --requested-at.“

**Beweisstufe.**

```
Beweisstufe: <level> von 3 (<Name>), belegt für seq 1 bis <up_to_tree_size> von <N>.
  Verlauf: Stufe <l> für seq <first_seq> bis <last_seq> (Ende durch: <Bedingungen>); …
  <Text der Stufe>
  qualifiziert bestätigt: spätestens <latest> (Zeitzeuge der Kette, tree_size <t>) | spätestens <latest> (Zeitstempel des Herstellerprotokolls, tree_size <t>, <Abstand> nach der Gegensignatur)
  liegt vor: <Bedingung> (<count>, bis tree_size <t>; <Anker>)
  für Stufe <n> fehlt eine dieser Bedingungen: | für Stufe <n> fehlt, alles nötig:
    - <Bedingung>: <Grund>
    - <Bedingung (4)> oder <Bedingung (7)>: <Grund von (4)>; <Grund von (7)>
  Hinweis: <Text>
  <Abschluss nach Abschnitt 10.9.8>
  <Zeile zur Verbundenheit>
```

- Kopfzeile bei Stufe 0: „Beweisstufe: 0 von 3 (Selbstauskunft), seq 1 bis `<N>`.“ Liegen Befunde der Exit-Klasse 2 nur aus `material_classes` vor, beginnt die Kopfzeile mit „Beweisstufe der Kette:“.
- „Verlauf“ nennt jeden Abschnitt; „Ende durch“ nennt die Bezeichnungen aus `basis`, bei Stufe 0 entfällt es. „liegt vor“ steht je vorliegender Bedingung; `<Anker>` nennt bei (3) die Schlüssel der angerechneten Quittungen wie `anchors.vendor_keys` („angehefteter Schlüssel `<key_id>`“ oder „Schlüssel `<key_id>` aus Liste Version `<v>`, `<Quelle der Wurzel>`“) und bei den anderen Bedingungen die Anker, die diese nennen: die Fingerabdrücke der anrechnenden Wurzeln für Zeitstempel und bei (4) und (7) `stand` und `quelle` der Datei der qualifizierten Wurzeln, die Quellen der erwarteten Wurzeln, bei (5) und (7) die `log_id` und bei (6) `as_of` der Anker-Historie und die Bescheidschlüssel der Seiten, auf denen (6) beruht: der frischen verwendeten Seiten des Pakets, die in die Vollständigkeit eingehen (Abschnitt 8.8.4, Schritt H11), nicht jedes Paar aus `anchors.statement_keys`; je Paar einmal, in der Reihenfolge von `anchor_history.keys`. Mehrere Anker in `<Anker>` und mehrere Quellen im Text `anchor_expected_sources` sind durch „, “ (Komma und Leerzeichen) verbunden.
- Jede Folgezeile des Blocks ist um zwei Leerzeichen eingerückt, die Zeilen der fehlenden Bedingungen um vier.
- Die Zeilen „fehlt“ stehen bei einer Stufe unter 3 nach `next`, je fehlender Bedingung mit dem Text ihres Grundes; bei Stufe 0 folgt, wenn (3) fehlt, nach den fehlenden Bedingungen die Zeile „Eine bestätigte Gegensignatur führt unmittelbar zu Stufe 2.“, eine Zeile des Blocks, um zwei Leerzeichen eingerückt.
- Die Zeile „qualifiziert bestätigt“ steht genau dann, wenn `qualified_time` nicht `null` ist, direkt nach dem Text der Stufe; `<latest>` ist `qualified_time.latest`, `<Abstand>` `gap_ms` in ganzen Minuten, abgerundet, als „`<h>` Std. `<m>` Min.“: Mit M = `gap_ms` in ganzen Minuten, abgerundet, ist `<h>` = M div 60 und `<m>` = M mod 60, beide ohne führende Nullen (etwa „0 Std. 10 Min.“ für 600 000 ms und „36 Std. 0 Min.“ für 129 600 000 ms). Fehlen für Stufe 3 sowohl (4) als auch (7), stehen sie in einer Zeile „`<Bedingung (4)>` oder `<Bedingung (7)>`“ mit beiden Gründen; die Zeile steht an der Stelle von (4).
- Zustand `chain_invalid`: die Zeile „Beweisstufe: keine (Kette ungültig)“, darauf der Abschluss und die Zeile zur Verbundenheit. Zustand `format_error`: die Zeile „Beweisstufe: nicht bestimmt (Formatfehler)“, darauf der Abschluss. Diese Folgezeilen sind Zeilen des Blocks, um zwei Leerzeichen eingerückt.

Beispiel (Testvektor `valid_basic` in der Prüfumgebung des Korpus):

```
Beweisstufe: 2 von 3 (gegengezeichnet), belegt für seq 1 bis 309 von 311.
  Verlauf: Stufe 2 für seq 1 bis 309 (Ende durch: Gegensignatur, deren Schlüssel ein Anker des Prüfers bestätigt (7.1)); Stufe 0 für seq 310 bis 311.
  Mindestens eine Gegensignatur trägt unter einem Schlüssel, den ein Anker des Prüfers bestätigt. Über die Vollständigkeit sagt diese Stufe nichts.
  liegt vor: Gegensignatur, deren Schlüssel ein Anker des Prüfers bestätigt (7.1) (12, bis tree_size 309; angehefteter Schlüssel vendor-test-001)
  für Stufe 3 fehlt, alles nötig:
    - Zeitzeuge einer vom Prüfer als qualifiziert benannten Stelle, dessen Token sich als qualifiziert ausweist oder Gegensignaturen in Tagen des Herstellerprotokolls nachgewiesen, deren Eintrag den Zeitstempel einer vom Prüfer als qualifiziert benannten Stelle trägt, der sich als qualifiziert ausweist, höchstens 36 Stunden nach der Gegensignatur (7.4.6): kein Zeitzeuge in der Kette; kein Auszug des Herstellerprotokolls übergeben (--vendor-log)
    - Gegensignaturen in bezeugten Tagen des Herstellerprotokolls nachgewiesen (7.4): kein Auszug des Herstellerprotokolls übergeben (--vendor-log)
    - Vollständigkeit nach einer geprüften Anker-Historie, ausgestellt nach der Anforderung des Pakets (8.8): keine Anker-Historie übergeben (--anchor-history)
  Hinweis: Kettenende nicht versiegelt; die Stufe gilt für die vorliegenden Einträge.
  Hinweis: Die Stufe beruht auf einem veröffentlichten Testschlüssel (published_test_keys); mit ihm kann jeder signieren. Gegen eine Fälschung belegt die Stufe damit nichts.
  Die Beweisstufe unterstützt Aussagen darüber, wie stark die vorliegende Kette gegen ein Umschreiben durch ihren Schlüsselinhaber belegt ist. Sie gewährleistet nichts und sagt nichts über den Inhalt der Aufrufe. Sie ist nur so unabhängig wie dieser Verifier und die Angaben, die der Prüfer ihm übergeben hat.
  Verbundenheit mit dem Hersteller: NICHT GEPRÜFT. Diese Angabe kommt aus der Anker-Historie des Herstellers, nicht aus dem Prüfpaket. Holen Sie die Anker-Historie mit der chain_id 18b0ad26-30f2-40b4-88fd-b5dc2926666d selbst beim Hersteller ab und übergeben Sie sie mit --anchor-history. Ob der Gegenzeichner mit dem Kunden verbunden ist, ist damit offen; Stufe 2 sagt darüber nichts.
```

**Zeile zur Verbundenheit** (Registry `verifier.affiliation.texts`; für jeden Bericht mit einem Exit-Code außer 3, auch im Zustand `chain_invalid`):

| Status | Zeile |
|---|---|
| `affiliated` | Verbundenheit mit dem Hersteller: VERBUNDEN nach Angabe des Herstellers (`<Grundlagen>`; `<Zeiträume>`). `<k>` von `<n>` Gegensignaturen dieses Pakets fallen in diese Zeit. Für diese Zeit belegt eine Gegensignatur des Herstellers keine vom Kunden unabhängige Stelle. Ein Zeitzeuge bindet die Zeit an eine dritte Stelle nur, wenn die Zeitstempelstelle weder dem Kunden noch dem Hersteller zuzurechnen ist; das prüft der Verifier nicht. Die Angabe stammt aus der Anker-Historie vom `<as_of>` (Schlüssel `<key_id>`, `<Quelle>`); der Verifier prüft Signatur, Form, Bindung an Kette und Gerät und den Abgleich mit anderen übergebenen Seiten, nicht ihre Richtigkeit. |
| `affiliated` mit `vendor_itself` | wie oben, der Satz am Anfang lautet „Verbundenheit mit dem Hersteller: VERBUNDEN nach Angabe des Herstellers: Kunde ist der Hersteller selbst (`<Zeiträume>`).“ |
| `not_affiliated` | Verbundenheit mit dem Hersteller: keine im Zeitraum dieses Pakets (`<from>` bis `<to>`, Zeiten des Herstellers) nach Angabe des Herstellers in der Anker-Historie vom `<as_of>` (Schlüssel `<key_id>`, `<Quelle>`). Der Verifier prüft Signatur und Form dieser Angabe, nicht ihre Richtigkeit. Gibt es Zeiträume außerhalb, folgt „Außerhalb des Zeitraums dieses Pakets nennt der Hersteller eine Verbundenheit: `<Zeiträume>`.“ |
| `not_determined` | Verbundenheit mit dem Hersteller: NICHT FESTGESTELLT (`<Grund>`). |
| `not_checked` | Verbundenheit mit dem Hersteller: NICHT GEPRÜFT. Diese Angabe kommt aus der Anker-Historie des Herstellers, nicht aus dem Prüfpaket. Trägt das Paket eine Quittung, deren Signatur trägt, folgt „Holen Sie die Anker-Historie mit der chain_id `<id>` selbst beim Hersteller ab und übergeben Sie sie mit --anchor-history.“, sonst „Für eine Kette, von der der Hersteller nie einen Anker angenommen hat, führt er keine Anker-Historie; dann gibt es aus dieser Quelle keine Angabe, auch nicht für einen verbundenen Kunden (Abschnitt 11.2).“ |

Bei `not_checked` und `not_determined` folgt ab Stufe 2 der Satz „Ob der Gegenzeichner mit dem Kunden verbunden ist, ist damit offen; Stufe 2 sagt darüber nichts.“ `<k>` ist `receipts_in_periods`, `<n>` `receipts_total`. `<Grundlagen>` sind die Bezeichnungen der Codes aus Heartbeat-Spezifikation §9.10; `<Zeiträume>` lauten je Zeitraum „ab `<from>` andauernd“ oder „`<from>` bis `<until>`“, mit „(zusammengefasst)“ bei `merged`. `<Quelle>` wie im Block der Anker-Historie. Kein Text nennt einen Zeitzeugen unabhängig.

| Grund bei `not_determined` | Text |
|---|---|
| `history_owner_differs` | die Anker-Historie gehört zu einem anderen Gerät als dieses Paket |
| `history_key_not_established` | Schlüssel der Anker-Historie nicht durch einen Vertrauensanker des Prüfers belegt |
| `history_key_not_valid` | Schlüssel der Anker-Historie zum Ausstellzeitpunkt nicht gültig |
| `history_signing_time_not_proven` | Seite mit widerrufenem Schlüssel und ohne Nachweis ihres Ausstellzeitpunkts |
| `history_not_v2` | übergebene Seiten haben nicht die Form ledger.anchor_history.v2 |
| `history_defective` | Signatur der Anker-Historie trägt nicht |
| `history_contradictory` | Anker-Historie verletzt ihr eigenes Format |
| `history_other_chain` | Anker-Historie einer anderen Kette |
| `known_range_too_short` | der Hersteller kann den Kunden dieser Kette erst ab `<known_since>` benennen; ist `known_since` `null`: der Hersteller kann den Kunden dieser Kette derzeit für keinen Zeitraum benennen |
| `statement_does_not_cover_package` | die Anker-Historie ist älter als die Anforderung des Pakets oder als seine jüngste Gegensignatur |
| `history_pages_missing` | Seiten der Anker-Historie fehlen; ohne alle Seiten ist „nicht verbunden“ nicht belegt |
| `history_no_package_page` | keine Seite der Anker-Historie dieser Kette übergeben |

**Browser-Fassung.** Unter dem Urteil stehen zwei Zeilen: die Stufe mit Reichweite (etwa „Beweisstufe: 2 von 3, belegt bis seq 309 von 311“, Registry `verifier.evidence_level.texts.browser`) und der Status der Verbundenheit, wie ihn die letzte Zeile des Blocks der Beweisstufe nennt. Bei Stufe 0 lautet die erste Zeile wie die Kopfzeile der Stufe 0 (`head_level0`), in den Zuständen `chain_invalid` und `format_error` wie die Zeile des Zustands (`state_line`); denn „belegt bis seq N“ läse sich dort als Beleg, wo keiner ist. Ergeben nur Klassen aus `material_classes` einen Exit 2, beginnt sie mit „Beweisstufe der Kette:“ wie der Textblock. Bei einem unbrauchbaren Aufruf gibt es keine der beiden Zeilen. Die Farbe des Urteils bleibt an den Exit-Code gebunden. Die Seite bietet Eingaben für mehrere Dateien der Anker-Historie, Auszüge, Schlüssellisten (auch die Rollenliste) und PEM-Dateien für Zeitstempel, für die Datei der qualifizierten Wurzeln, für Anheftungen als Bescheidschlüssel und ein Feld für den Anforderungszeitpunkt (Abschnitt 10.8).

## 11. Angreifermodell und Beweisgrenzen

### 11.1 Manipulationsklassen und Erkennung

| Klasse | Angriff | Erkennung |
|---|---|---|
| `rewrite` | Umschreiben eines Eintrags | Hash-Kette (`HASH_MISMATCH`), Signaturen (`SIG_INVALID`), Merkle-Wurzeln, Zeitzeugen (Abschnitt 7.3) |
| `truncate` | Kürzen der Kette gegen verankerte Wurzeln | Konsistenzbeweise gegen Anker und erwartete Wurzeln (`MERKLE_INCONSISTENT`), Handover (`HANDOVER_BROKEN`), Kettenende (`UNSEALED_END`, Abschnitt 8.6) |
| `fork` | Zweitgeschichte gegen Quittungen/Konsistenzbeweise, auch mit selbst signierten „Quittungen" unter einem erfundenen Hersteller-Schlüssel | Quittungs-Präfix-Prüfung (`FORK_DETECTED`, `RECEIPT_INVALID`), Herkunft des Hersteller-Schlüssels (`RECEIPT_UNVERIFIED`, Abschnitt 7.1), cloudseitige `tree_size`-Monotonie, Freshness |
| `clock` | Rückdatierung gegen mono_delta/Serverzeit | `CLOCK_ANOMALY`, `genTime` der Zeitzeugen (`TIME_ANCHOR_INVALID`); `server_ts` der Quittungen ist eine vom Hersteller signierte Zeitangabe, die der Verifier aber mit keiner anderen Zeit der Kette vergleicht; er meldet daran nichts |
| `silent_gap` | verschwiegene Stille ohne deckenden GAP | TICK-Abdeckung (`CONCEALED_SILENCE`) |
| `vendor_omission` (ab Fassung 1.10) | Der Hersteller lässt eine Gegensignatur, die er ausgestellt hat, im Herstellerprotokoll oder in der Anker-Historie weg | `RECEIPT_NOT_LOGGED` (Abschnitt 7.4.10, Schritt L8) und `ANCHOR_HISTORY_CONTRADICTION` mit Grund `receipt_not_in_history` (Abschnitt 8.8.4, Schritt H10), beide nur für eine Quittung, die im vorgelegten Paket steht; ein Datenverlust beim Hersteller sieht ebenso aus |
| `vendor_split_view` (ab Fassung 1.10) | Der Hersteller zeigt verschiedenen Prüfern verschiedene Fassungen des Herstellerprotokolls oder der Anker-Historie | `VENDOR_LOG_CONTRADICTION` und `ANCHOR_HISTORY_CONTRADICTION`, wenn beide Fassungen demselben Verifier vorliegen; Vergleich des Tageshashes mit dem zweiten Veröffentlichungsort und unter Prüfern; Prüfung der Tagesblätter (Abschnitt 7.4.9), die der Verifier nicht ausführt |
| `collusion` (ab Fassung 1.10) | Hersteller und Kunde wirken zusammen, etwa bei einem verbundenen Kunden: Sie kürzen oder schreiben die Kette neu und stellen Gegenzeichnung und Anker-Historie passend aus | gegen ein Neuschreiben nur Zeitzeugen einer Stelle, die keinem von beiden zuzurechnen ist und deren Wurzel der Prüfer beibringt (Abschnitt 7.3); gegen ein Kürzen nur ein Kettentag-Nachweis eines bezeugten Tages, den der Prüfer schon vorher hält, oder ein Abgleich der öffentlichen Tagesblätter von Hand, den der Verifier nicht ausführt (Abschnitt 11.2); Bedingung (7) hilft hier nicht, denn die Stelle des Tageseintrags wählt der Hersteller, und eine neu ausgestellte Gegensignatur steht mit ihrem eigenen `server_ts` in einem späteren Tag (Abschnitt 10.9.4); die Angabe zur Verbundenheit (Abschnitt 8.8.6) zeigt, wo dieses Risiko besteht |

Rollenbetrachtung: **Ein Externer ohne Schlüssel** scheitert an Hash-Kette und Signaturen. **Der Schlüsselinhaber selbst** (der Kunde) kann formal gültige Einträge neu erzeugen, scheitert aber an bereits verankerten Wurzeln: jede Historie, die nicht Präfix-konsistent zu jeder verankerten Wurzel ist, fällt durch. Neue „Quittungen" für seine Neufassung kann er nur unter einem Schlüssel signieren, den er selbst besitzt; den hat kein Anker des Prüfers belegt, und der Verifier meldet `RECEIPT_UNVERIFIED` (Abschnitt 7.1). **Der Hersteller** besitzt den Kundenschlüssel nie und kann daher keine gültigen Einträge erzeugen; er sieht keine Inhalte. Er kann eine Gegenzeichnung verweigern, eine Wurzel nicht festhalten, eine Gegensignatur ausstellen, ohne sie zu protokollieren, oder eine Anker-Historie unvollständig ausliefern. Was er für einen bezeugten Tag des Herstellerprotokolls protokolliert hat (ab Fassung 1.10, Abschnitt 7.4), kann er danach nicht zurücknehmen; verschiedene Fassungen eines Tages für verschiedene Prüfer fallen beim Vergleich der Tageshashes auf, verschiedene Nachweise unter derselben Tageswurzel nur bei einer Prüfung der Tagesblätter (Abschnitt 7.4.3). Seine Angabe zur Verbundenheit mit dem Kunden ist eine eigene Aussage (Abschnitt 11.2); ist der Kunde mit ihm verbunden, gilt die Rollenanalyse des Schlüsselinhabers für beide zusammen.

### 11.2 Ehrliche Beweisgrenzen

- **Restfenster:** Einträge zwischen dem letzten gegengezeichneten Checkpoint und dem Kettenende sind noch nicht extern verankert. Der Schlüsselinhaber könnte dieses **Restfenster** verlustfrei neu schreiben, bevor die nächste Quittung eintrifft. Das Format begrenzt seine Größe nicht: Im lizenzierten Betrieb mit Verbindung zum Hersteller umfasst es meist wenige Minuten (ein Anker alle 5 Minuten), nach einem Lizenzablauf, bei abgeschaltetem Egress oder in einem alten Export beliebig viel. Der Verifier MUSS es deshalb für jedes Paket, das kein Formatfehler ist, **messen und ausgeben** (ab Fassung 1.9): T ist die `tree_size` des letzten gegengezeichneten Checkpoints nach Abschnitt 8.6 (0, wenn es keinen gibt), N die Zahl der Einträge. Das Restfenster sind die Einträge `seq` T+1 bis N; auszugeben sind T, T+1, N, die Zahl N − T, `ts_chained` von `seq` T (nicht bei T = 0) und von `seq` N, die Dauer dazwischen in Millisekunden (Abschnitt 2; nicht bei T = 0), die Zahl der `ADMIN`-Einträge mit `message_type = anchor` nach der Quittung jenes Checkpoints (gesendete Anker ohne Gegenzeichnung im Paket) und ob das Fenster die Taktung überschreitet (T = 0 oder Dauer über 450 000 ms). In der JSON-Ausgabe beider Referenz-Verifier heißt das Objekt `residual_window` mit den Membern `after_tree_size`, `first_seq`, `last_seq`, `entries`, `from_ts`, `to_ts`, `span_ms`, `unanswered_anchor_messages` und `beyond_cadence`. Bei einem Formatfehler ist das Restfenster nicht bewertet; `residual_window` hat dann den Wert `null` und fehlt nie. Das Restfenster ist kein Befund und ändert den Exit-Code nicht; überschreitet es die Taktung, nennt der Bericht die möglichen Ursachen (Lizenzablauf, Egress aus, Hersteller nicht erreichbar, alter Export) und den Abgleich nach Abschnitt 8.6. Ein Zeitzeuge nach Abschnitt 7.3 verkleinert das Fenster nicht, verändert aber, wer es ausnutzen kann: Er verlagert die Aussage auf eine Stelle, die weder Kunde noch Hersteller kontrolliert; wer die Historie neu schreibt, müsste einen Token mit früherem `genTime` beibringen, den er nicht hat. Ohne eigenen Vertrauensanker des Prüfers bleibt auch das nur eine Selbstauskunft (`TIME_ANCHOR_UNVERIFIED`).
- **Gedeckte Strecken (ab Fassung 1.10):** Liegt zwischen zwei aufeinanderfolgenden gegengezeichneten Checkpoints (`tree_size` T1 und T2, T1 < T2) mehr als der Verankerungstakt, also mehr als 450 000 ms zwischen `ts_chained` von `seq` T1 und von `seq` T2, MUSS der Verifier diese Strecke für jedes Paket, das kein Formatfehler ist, ausweisen: `seq` T1+1 bis T2, `ts_chained` von `seq` T1 und von `seq` T2, die Dauer dazwischen in Millisekunden (Abschnitt 2), die Zahl der `ADMIN`-Einträge mit `message_type = anchor` in der Strecke nach der Quittung von T1 (Anker-Nachrichten ohne eigene Gegenzeichnung, gezählt wie beim Restfenster) sowie `seq` und `server_ts` der Quittung von T2, die die Strecke deckt. Gegengezeichnet ist ein Checkpoint, dessen Quittung Abschnitt 8.6 für die Wahl des letzten gegengezeichneten Checkpoints gelten lässt; bei gleicher `tree_size` zählt die erste Quittung in Kettenreihenfolge. In der JSON-Ausgabe beider Referenz-Verifier heißt die Liste `unanchored_stretches`, je Strecke mit den Membern `after_tree_size` (T1), `first_seq`, `last_seq`, `from_ts`, `to_ts`, `span_ms`, `unanswered_anchor_messages`, `receipt_seq` und `receipt_server_ts`; ohne solche Strecke ist sie leer; bei einem Formatfehler hat sie den Wert `null` (nicht bewertet) und fehlt nie. Eine Strecke ist kein Befund und ändert den Exit-Code nicht; eine ehrliche Kette wird dadurch nie ungültig. So zeigt der Bericht auch nach einer Verlängerung, wie lange die Kette ohne Gegenzeichnung lief (etwa nach einem Lizenzablauf oder bei zeitweise abgeschaltetem Egress). Die Einträge vor dem ersten gegengezeichneten Checkpoint sind keine gedeckte Strecke in diesem Sinn; sie stehen im Paket wie jeder andere Eintrag.
- **Ohne Vertrauensanker des Prüfers** belegt eine Quittung nur Selbstkonsistenz: Signatur, Checkpoint und Präfix werden voll geprüft, der Schlüssel aber stammt aus dem Paket (`RECEIPT_UNVERIFIED`, Abschnitt 7.1). Die Aussage „vom Hersteller gegengezeichnet" trägt erst mit der Herstellerwurzel oder einem angehefteten Schlüssel.
- **Ohne jede Verankerung** (Air-Gap, Egress aus) sinkt die Beweiskraft gegen den Schlüsselinhaber auf das Freshness-/Papier-Anker-Niveau; der Verifier weist das als `NO_ANCHOR` aus. Die Kette bleibt gegen externe Manipulation voll beweiskräftig.
- **Fork-Erkennung braucht Vergleichspunkte:** Ein Rollback fällt nur auf, wenn dem Prüfer mindestens eine jüngere Quittung, ein jüngerer Papier-Anker oder das Freshness-Fenster widerspricht.
- **Lizenzablauf (ab Fassung 1.8):** Nach Ablauf von Laufzeit und Kulanz zeichnet der Hersteller keine Anker mehr gegen. Er prüft sie aber weiter auf Konsistenz und hält ihre Wurzeln als Lückenzeugen fest (Heartbeat-Spezifikation §9.2). Das Prüfpaket enthält für diese Zeit keine Quittung; alle Einträge seit der letzten Quittung liegen im Restfenster, das der Schlüsselinhaber aus Sicht des Pakets allein neu schreiben könnte. Beim Hersteller reicht die Neufassung dagegen nur bis zum jüngsten Lückenzeugen zurück. Ein Prüfer, der ein solches Paket bewertet, SOLL die signierte Anker-Historie der Kette selbst beim Hersteller abholen (Heartbeat-Spezifikation §9.7), nicht über das geprüfte Haus, und jede Wurzel daraus, die vor der Anforderung des Pakets festgehalten wurde (gegengezeichnet, Lückenzeuge oder gemeldet), als erwartete Wurzel prüfen (Abschnitte 7.2, 10.8): Widerspricht das Paket einer davon oder fehlt sie ihm, ist das `MERKLE_INCONSISTENT`. Eine Wurzel, die erst nach der Anforderung festgehalten wurde, sagt über dieses Paket nichts; als erwartete Wurzel übergeben, erschiene sie auch bei einem ehrlichen Paket als Widerspruch. Ab Fassung 1.10 übergibt der Prüfer dafür die Anker-Historie selbst dem Verifier (Abschnitt 8.8); die Grenze vor der Anforderung zieht dann der Verifier.
- **Lizenzschlüssel in älteren Ketten:** Bis Fassung 1.7 konnte `GENESIS.license_id` den Lizenzschlüssel im Klartext tragen (Abschnitt 4.1). Das mindert die Beweiskraft der Kette nicht, legt aber den Schlüssel jedem Inhaber des Pakets offen; der Verifier weist darauf hin.
- **Kürzung an einem früheren Siegel (ab Fassung 1.6):** Eine Kette, die unmittelbar hinter dem Sofort-Checkpoint eines früheren `SEAL` abgeschnitten wird, erscheint als ordnungsgemäß versiegelt; dafür ist kein Schlüssel nötig. Das Paket allein kann das nicht widerlegen. Es fällt auf am Zeitpunkt des Siegels im Bericht, an `TRAILING_SILENCE` außerhalb des Freshness-Fensters und sicher am Abgleich mit der jüngsten gegengezeichneten Wurzel des Herstellers (Abschnitt 8.6). Der Testvektor `end_truncated_at_seal` legt diese Grenze offen. Jedes Export-Siegel (ab Fassung 1.9) ist eine solche Stelle; diese Grenze ist seit dem 29.09.2026 als Eigenschaft des Modells festgelegt. Der Verifier sagt deshalb bei jedem Paket, dass ohne gegengezeichnete Wurzel keine Aussage über die Vollständigkeit möglich ist, und fordert sie an (Abschnitt 8.6).
- **Uhrzeit:** Die Kette beweist Reihenfolge (seq, monotone Uhr) hart; absolute Wanduhrzeit ist nur bis zur Klammer aus `server_ts` der Quittungen (≤ 5 Minuten Raster) und deklarierten Uhrensprüngen belegt.
- **Einzelne verlorene Aufrufe (ab Fassung 1.9, 02.10.2026):** Das Paket enthält nur, was verkettet wurde. Fehlt ein Aufruf, den die Appliance beantwortet hat, ohne dass ein `GAP`-Fenster ihn aufnimmt, ist das offline nicht zu erkennen; die Kette bleibt gültig. Abschnitt 8.7 verpflichtet die Appliance, das zu verhindern. Belegen lässt sich die Zusage nur außerhalb des Pakets: gegen Protokolle der aufrufenden Anwendungen, gegen Zählwerte des Anbieters (Abschnitt 4.6) oder durch Prüfläufe mit bekannter Grundwahrheit. Ein `GAP`-Fenster sagt, dass in dieser Zeit Aufrufe fehlen können, nicht, dass welche fehlen; `lost_count = −1` heißt, ihre Zahl ist unbekannt.
- **Inhalte:** Commitments beweisen Integrität vorgelegter Klartexte, nicht deren Existenz oder Vollständigkeit; gelöschte Inhalte (`CONTENT_DELETED`) sind endgültig nicht mehr vorlegbar (ausgewiesen, nicht verschleiert).
- **Souveränität als Beweisgegenstand:** Der Hersteller kennt keine Kundenschlüssel und sieht keine Inhalte; alles, was die Appliance sendet, ist als `ADMIN`-Eintrag wörtlich verkettet und damit selbst Prüfgegenstand.
- **Schlüsselrollen (ab Fassung 1.10):** Jede Rolle hat eigene Schlüssel, und beim Verifier belegt ein Schlüssel einer Rolle nie ein Objekt einer anderen (Abschnitte 10.7.3, 10.7.4). Wer nur einen Bescheidschlüssel hält, erzeugt keine Quittung, die ein Anker des Prüfers bestätigt, sofern der Prüfer ihn nicht selbst als Gegenzeichnungsschlüssel anheftet; übergibt er die Rollenliste, verwirft der Verifier eine solche Anheftung. Wer nur einen Gegenzeichnungsschlüssel hält, erzeugt keine Seite, die ein Verifier verwendet, und keinen Bescheid, dessen Wurzel ein Prüfer nach Fassung 1.10 als erwartete Wurzel übergibt (Heartbeat-Spezifikation §9.5, §9.7). Im Doppelbetrieb signiert der Gegenzeichnungsschlüssel weiter die Hülle von Lizenzbescheiden, Verweigerungsbescheiden und Aktivierungsquittungen und Seiten der Form v1; Empfänger und Prüfer, die nach Fassung 1.9 vorgehen, kennen keine Rollen und nehmen solche Bescheide und Seiten auch nach dem Ende des Doppelbetriebs an. Der Dienst, der den Gegenzeichnungsschlüssel hält, liest deshalb jeden übergebenen `statement_jcs` selbst und signiert auf diesem Weg nur Objekte mit dem `kind` eines dieser Bescheide oder einer Seite der Form v1 (Heartbeat-Spezifikation §9.11 Punkt 3); hielte er sich nicht daran, könnte, wer den Bescheiddienst beherrscht, unter dem Gegenzeichnungsschlüssel beliebige Bytes signieren lassen, auch den Signaturgegenstand einer Quittung. Wie der Hersteller seine Schlüssel verwahrt und ob dieser Dienst so liest, zeigt kein Prüfpaket (kein Beleg durch LEDGER). Die Rollenprüfung sieht nur die Listen, die der Prüfer übergibt. Ohne Rollenliste und ohne Anheftung als Bescheidschlüssel verwendet der Verifier keine Seite der Form v2 (`ANCHOR_HISTORY_UNVERIFIED`), auch bei einer ehrlichen Kette, und Stufe 3 liegt nicht vor. Wer die Herstellerwurzel hält, kann jedem Schlüssel jede Rolle geben; dagegen schützen die Rollen nicht.
- **Herstellerprotokoll (ab Fassung 1.10):** Mit dem signierten Tageseintrag (Abschnitt 7.4) legt sich der Hersteller für jeden abgeschlossenen UTC-Tag auf die Menge seiner Gegensignaturen und Lückenzeugen fest. Ein Zeitstempel einer Stelle, deren Wurzel der Prüfer selbst beibringt, bezeugt diese Festlegung höchstens 48 Stunden nach Tagesende (Abschnitt 7.4.6). Übergibt der Prüfer das Protokoll, meldet der Verifier jede vorgelegte Quittung eines bezeugten Tages, die darin fehlt (`RECEIPT_NOT_LOGGED`), und jede dort festgehaltene Wurzel, der das Paket widerspricht (`LOGGED_ROOT_MISMATCH`). Das stützt zwei Aussagen. Zum einen kann der Hersteller eine Gegensignatur, die ein Kunde vorlegt, nach der Bezeugung ihres Tages nicht aus dem Protokoll verschwinden lassen, ohne dass der Verifier es meldet. Zum anderen fällt es auf, wenn der Hersteller zwei Prüfern verschiedene Fassungen eines Tages zeigt, sobald die Prüfer den Tageshash miteinander oder mit dem zweiten Veröffentlichungsort vergleichen oder beide Fassungen demselben Verifier übergeben (`VENDOR_LOG_CONTRADICTION`); verschiedene Tageslisten einer Kette unter derselben Tageswurzel fallen auf, wenn jemand die veröffentlichten Tagesblätter auf Ordnung und doppelte Positionen prüft (Abschnitt 7.4.9). Der Verifier prüft die Tagesblätter nicht. Ein Abwesenheitsnachweis und die Eigenschaft, dass eine Kette je Tag höchstens ein Kettentag-Blatt hat, sind deshalb nur zusammen mit dieser Prüfung belegt (Abschnitt 7.4.3): Führt ein Hersteller unter einer Tageswurzel zwei Kettentag-Blätter einer Kette, kann er einem Prüfer einen Nachweis ohne eine ehrliche Quittung geben, und der Verifier meldet dann gegen den Kunden `RECEIPT_NOT_LOGGED`, einen Befund, den die Tagesblätter dem Hersteller zurechnen. Ohne einen solchen Vergleich fällt eine geteilte Sicht nicht auf; ob zwei übergebene Dateien von zwei Orten stammen, kann der Verifier nicht erkennen. Das Protokoll belegt nicht, dass eine Kundenkette vollständig ist; dafür bleiben die erwarteten Wurzeln zuständig (Abschnitte 8.6, 8.8). Eine Gegensignatur, die der Hersteller bei Tagesabschluss nicht protokolliert und die in keinem vorgelegten Paket steht, bleibt unsichtbar. Quittungen eines Tages, dessen Eintrag noch nicht fällig ist, und Quittungen vor Beginn des Protokolls sind nicht prüfbar. Erhält der Hersteller für einen Tag innerhalb von 48 Stunden keinen bezeugenden Zeitstempel, bleibt dieser Tag für jede an ihm aktive Kette unbezeugt, und ihre Quittungen dieses Tages bleiben nicht prüfbar. Ein Datenverlust beim Hersteller erscheint wie ein Weglassen; die Kette bleibt gültig. Eine Wurzel, die ein unredlicher Hersteller erfindet und protokolliert, ist ihm zuzurechnen; als erfunden erkennen kann der Verifier sie nicht. Die Baumgröße eines Tages folgt der Größenregel (Abschnitt 7.4.4): Sie zeigt nur, ob an diesem Tag mehr als 1024 Ketten Blätter hatten, und dann die Zweierpotenz, die ihre Zahl nach oben begrenzt; an dem Tag, an dem die Zahl eine Zweierpotenz überschreitet, zeigt sie Wachstum. Ausgenommen ist ein Protokoll, dessen Protokollschlüsselliste eine Wurzel aus `published_test_keys` signiert; es verbirgt nichts. Dass die Größe eine Zweierpotenz und mindestens 1024 ist, kann jeder an den Tageseinträgen prüfen; ob es die kleinste zulässige ist und wie viele Ketten der Tag hatte, zeigt nur die Öffnung des ganzen Tages zusammen mit dem Nachweis des Ursprungs jedes Blatts, das kein Füller der Auswahl ist, und ob die Füller aus dem Füllergeheimnis stammen, nur das Füllergeheimnis selbst, geprüft gegen die Füllerbindung der Protokollschlüsselliste; beides kann allein der Hersteller geben (Abschnitt 7.4.13), und kein Prüfpaket zeigt es (kein Beleg durch LEDGER). Der Verifier prüft die Größenregel nicht. Die Öffnung eines ganzen Tages zeigt, welche Blätter Füller der Auswahl sind, und begrenzt die Zahl der Ketten nach oben, bürgt aber nicht dafür, dass die übrigen Blätter keine Füller sind; ihren Ursprung zeigt der Hersteller nur mit Kundendaten, und diese Fassung legt dafür kein Format fest. Eine Öffnung ist an keinen Empfänger gebunden und lässt sich nicht zurücknehmen. Wer das Füllergeheimnis oder die Öffnung eines ganzen Tages erhält, kennt die Zahl der Ketten der betroffenen Tage; geht das Füllergeheimnis verloren, lassen sich diese Tage nicht mehr öffnen. An der Prüfung einer Kette ändert beides nichts. Sperrungen von Zertifikaten der Zeitstempelstellen prüft der Verifier nicht. Wer einmal ein Prüfpaket hatte, kann an den veröffentlichten Tagesblättern auch später erkennen, an welchen Tagen diese Kette aktiv war, und mit ihrer `chain_id` spätere Auszüge und Seiten der Anker-Historie abrufen; über `successor` erfährt er die Nachfolgekette und kann auch deren aktive Tage erkennen (Abschnitt 7.4.12). Stellt der Hersteller das Protokoll ein, kommen keine Tage hinzu; abgerufene Auszüge bleiben offline prüfbar. Wer die Herstellerwurzel hält, kann Schlüssel aller Rollen bestätigen; gegen einen Missbrauch der Wurzel selbst schützt das Protokoll nicht.
- **Signatur nach ML-DSA-87 (ab Fassung 1.10):** Die zweite Signatur der Tageseinträge (Abschnitt 7.4.5a) trägt nur so weit wie die Ed25519-Herstellerwurzel, die die Protokollschlüsselliste signiert, und wie die Zeitstempel, die den Tag bezeugen. Herstellerwurzel, alle drei Schlüssellisten und die Zeitstempelstellen bleiben bei klassischen Verfahren. Wer die Herstellerwurzel bricht oder hält, kann eine Liste `ledger-protokollschluessel/2` mit einem eigenen Schlüssel nach ML-DSA-87 oder ohne `hybrid_ab` signieren; dagegen hilft die Hybridregel nicht. Sie schützt nur gegen einen Bruch des Ed25519-Protokollschlüssels allein: Ab `hybrid_ab` stellt ein Verifier, der Schritt L2 (g′) umsetzt, keinen Tag fest, dem eine geltende Signatur nach ML-DSA-87 fehlt (Abschnitt 7.4.10). Der Schlüssel nach ML-DSA-87 entsteht wie der Ed25519-Protokollschlüssel im Signierdienst des Herstellers; gegen eine Kompromittierung dieses Dienstes hilft er nicht. Tage vor `hybrid_ab` sind nur durch Ed25519 belegt: Der Verifier prüft eine Signatur nach ML-DSA-87 dort, wenn sie vorliegt, verlangt sie aber nicht. Ebenso ist jeder Tag nur durch Ed25519 belegt für einen Verifier, der das Format `/2` nicht kennt und nur die Projektion `/1` liest (Abschnitt 10.6). Die Hybridpflicht greift nur, wenn der Prüfer eine Liste `ledger-protokollschluessel/2` sieht, die er übergibt oder in einem Auszug `/2` erhält; wer nur die Projektion `/1` sieht, prüft wie bisher nur Ed25519. Der Auszug ist unsigniert, und wer ihn liefert, kann ihn als Auszug `/1` mit der Projektion vorlegen; den Schutz der Hybridregel erhält deshalb sicher nur, wer `keys-2.json` von einem Veröffentlichungsort selbst abruft und mit `--vendor-key-list` übergibt; weil `hybrid_ab` nicht zurückgenommen werden kann, genügt dafür jede Version ab dem Setzen. Ein Siegel `cades-b-t` prüft diese Fassung nicht (kein Beleg durch LEDGER).
- **COSE Receipts (ab Fassung 1.10):** Eine COSE-Gegensignatur (Profil C1, Abschnitt 7.7.3) zeigt nur, was der Hersteller unter seinem Transparenzschlüssel über eine Wurzel sagt; sie verankert nichts, ersetzt die Quittung nicht, belegt keinen Gegenzeichnungsschlüssel und wirkt nie auf die Beweisstufe. COSE-Objekte ändern die Beweisstufe nicht, außer über einen Widerspruch nach Schritt L3a: Ein C2, das vom Tageseintrag abweicht, ist `VENDOR_LOG_CONTRADICTION` und zählt wie jeder andere für die Bedingungen (5) und (7). Ein COSE Receipt eines Tages (Profil C2, Abschnitt 7.7.4) ersetzt den Tageseintrag nicht: Rechtzeitige Bezeugung, Verkettung der Tage, Größenregel, Ordnung der Positionen und Abwesenheit zeigt es nicht (Abschnitt 7.7.8). Tage vor dem ersten C2 des Herstellers haben keines; ein fehlendes COSE-Objekt ist nie ein Befund. Den Transparenzschlüssel hält ein laufender Dienst; wer ihn entwendet, kann COSE-Objekte über beliebige Wurzeln signieren, die gegen Tageseintrag und Paket nur als Widerspruch oder als mangelhaft auffallen. Die Ablageform ist für sich kein Receipt nach RFC 9942 (es fehlt `vdp`); ein solches ist erst die Vorlageform (Abschnitt 7.7.2). Ein allgemeiner COSE-Prüfer, der die privaten Labels nicht kennt, sieht die Bindung der Baumgröße nicht. Nach außen heißen die Objekte „COSE Receipts nach RFC 9942“; ob sie allen Regeln von RFC 9943 folgen, sagt diese Spezifikation nicht (kein Beleg durch LEDGER).
- **Beweisstufe (ab Fassung 1.10):** Die Beweisstufe (Abschnitt 10.9) fasst zusammen, welche Anker der Verifier mit den Angaben des Prüfers bestätigen konnte und bis zu welcher `seq` sie reichen; sie trägt so weit wie diese Angaben. Ob eine Herstellerwurzel, ein angehefteter Schlüssel, eine Wurzel für Zeitstempelstellen, ihre Benennung als qualifiziert oder eine erwartete Wurzel tatsächlich von außerhalb des Pakets und nicht aus der Hand des Schlüsselinhabers stammt, kann der Verifier nicht erkennen; er nennt deshalb die Fingerabdrücke der Anker, auf denen die Stufe beruht. „Qualifiziert“ heißt hier: Der Prüfer hat die Wurzel für den Zeitpunkt des Tokens so benannt, und der Token weist sich selbst so aus. Die Vertrauensliste, den Status der Stelle und Sperrungen prüft der Verifier nicht; mit dem entwendeten Schlüssel einer Stelle lassen sich rückdatierte Token ausstellen. Stufe 2 beruht auf dem Gegenzeichnungsschlüssel: Wer ihn besitzt, ein Dieb oder ein mit dem Kunden zusammenwirkender Hersteller, erreicht sie auch für eine neu geschriebene Kette; dagegen wirken erst die Bedingungen der Stufe 3, das Herstellerprotokoll nur für Tage, die schon bezeugt sind. Stufe 2 sagt nichts über die Vollständigkeit. Stufe 3 belegt sie bis zur größten `tree_size` einer gefundenen Wurzel der Anker-Historie; den Zeitpunkt der Anforderung gibt der Prüfer an, der Verifier kann ihn nicht prüfen, und für die Einträge danach bleibt das Restfenster (oben). Stufe 3 setzt Dienste und signiertes Material des Herstellers voraus: die Anker-Historie, das Herstellerprotokoll und eine Rollenliste oder einen Bescheidschlüssel, den der Prüfer anheftet. Der Hersteller kann sie einer einzelnen Kette verwehren, indem er diese Dienste für sie zurückhält oder eine ihrer Gegensignaturen nicht protokolliert; das Weglassen erscheint als Befund gegen ihn (`RECEIPT_NOT_LOGGED`), das Zurückhalten nicht. Stellt er die Dienste ein, endet eine neue Prüfung höchstens bei Stufe 2, ohne Hersteller höchstens bei Stufe 1; früher abgerufene Unterlagen bleiben offline prüfbar. Für ein frisch exportiertes Paket reicht Stufe 3 höchstens bis zu den Gegensignaturen des letzten bezeugten Tages. Übergibt der Prüfer als Wurzeln für Zeitzeugen eine Sammeldatei vieler Stellen, etwa den Wurzelspeicher eines Systems, zählt jede davon (Abschnitt 10.8); ein Zeitstempel, den der Schlüsselinhaber bei einer dieser Stellen kauft, reicht dann für Bedingung (1). Die Verbundenheit zeigt der Bericht an; die Zahl der Stufe ändert sie nicht. Ein Verifier, den die geprüfte Partei mitliefert, kann jede Stufe anzeigen. Ein Verifier, der die Schritte 5 und 6 aus Abschnitt 7.3 nicht ausführt, erreicht über Zeitzeugen keine Stufe und Stufe 3 nicht.
- **Zeitbindung über das Herstellerprotokoll (ab Fassung 1.10):** Bedingung (7) ist der zweite Weg zu Stufe 3 neben (4): Eine Gegensignatur steht in einem Tag, dessen Eintrag eine als qualifiziert benannte Stelle gestempelt hat. Ein Zeitstempel deckt so alle Ketten eines Tages und bindet den Stand bei der `tree_size` der Gegensignatur höchstens 36 Stunden nach ihrem `server_ts`, nicht im Takt eines Zeitzeugen. Belegt ist nur „spätestens“: dass der Stand zum `genTime` des Stempels bestand (`qualified_time`, Abschnitt 10.10.2). Der Stempel deckt den Tageseintrag des Herstellers, nicht die Kette; die Kette ist nur mittelbar gebunden, über die Gegensignatur und ihren Einschluss in den Tagesbaum. Innerhalb dieser 36 Stunden kann ein Hersteller, der mit dem Kunden zusammenwirkt, eine Gegensignatur zurückdatieren, solange ihr Tag noch nicht gestempelt ist; ein Zeitzeuge nach (4) auf der Kette engt das nicht weiter ein, als sein Takt erlaubt. Die Stelle wählt der Hersteller, nicht der Kunde, und der Nachweis läuft über den Auszug des Herstellers und über seinen Tagesbaum. Ob diese mittelbare Bindung rechtlich wie ein Zeitstempel über die Quittung oder die Kette wirkt, bestimmt diese Spezifikation nicht; sie ist keine rechtliche Einordnung (kein Beleg durch LEDGER). Eine Stelle deckt so alle Ketten: Wird sie nicht mehr als qualifiziert geführt oder wird ihr Schlüssel entwendet, betrifft das jede Kette, und die Anrechnung begrenzt nur der Zeitraum, für den der Prüfer die Wurzel als qualifiziert benennt (Abschnitt 10.8). Ob ein Stand schon zu der Zeit bestand, die die Kette selbst nennt, zeigen weder (4) noch (7): Keine Bedingung vergleicht `genTime` mit `ts_chained`. Wer eine Zeitstempelstelle betreibt, sieht der Verifier nicht; dass keine Stelle des Protokolls vom Hersteller oder einer mit ihm verbundenen Stelle betrieben wird, ist eine Pflicht des Herstellers (Heartbeat-Spezifikation §9.9), die kein Prüfpaket zeigt (kein Beleg durch LEDGER).
- **Vorgeschlagene Zeitstempelstelle (ab Fassung 1.10):** Schlägt die Appliance eine Stelle vor (Abschnitt 7.3), wählt der Kunde sie durch seine Bestätigung; ob sie vom Hersteller unabhängig ist, prüft der Verifier nicht. Ihre Wurzel beschafft der Prüfer selbst. Ein Zeitzeuge hängt von der Verfügbarkeit und den Bedingungen der Stelle ab, und jede Anfrage zeigt der Stelle die Netzadresse der Anlage und den Takt ihrer Anfragen.
- **Verbundenheit mit dem Hersteller (ab Fassung 1.10):** Ob ein Kunde einer Kette mit dem Hersteller verbunden ist (Heartbeat-Spezifikation §9.10), ist eine signierte Aussage des Herstellers in der Anker-Historie. Sie umfasst den Lizenznehmer und den erklärten Betreiber, soweit der Hersteller sie kennt. Der Verifier prüft ihre Signatur gegen einen Vertrauensanker des Prüfers, ihre Form, ihre Bindung an die Kette und an deren Gerät, ihre Frische gegenüber der Anforderung des Pakets und ihre Übereinstimmung mit anderen übergebenen Seiten derselben Kette, nicht aber, ob sie zutrifft (kein Beleg durch LEDGER). Eine von Anfang an falsche Angabe erkennt er nicht; sie ist dem Bescheidschlüssel des Herstellers zuzurechnen. Eine später zurückgenommene oder verkürzte Angabe fällt auf, wenn dem Verifier eine frühere Seite mit ihr vorliegt. Wer einen anderen Lizenznehmer vorschiebt und den Betreiber nicht erklärt, entgeht der Angabe, soweit der Hersteller die Verbindung nicht kennt. Der Kunde kann die Angabe nicht unterdrücken, wenn der Prüfer die Historie selbst abholt; der Hersteller oder wer im Transportweg sitzt, kann sie zurückhalten. Dann meldet der Verifier „nicht geprüft“ oder „nicht festgestellt“, nie „nicht verbunden“. Für eine Kette, von der der Hersteller nie einen Anker angenommen hat, gibt es keine Anker-Historie und damit keine Angabe; ein Kunde, der nie verankert, gibt dem Hersteller keine Quelle für eine Angabe. Für die Zeit einer Verbundenheit belegt eine Gegensignatur keine vom Kunden unabhängige Stelle. Ein Zeitzeuge bindet die Zeit an eine dritte Stelle nur, wenn die Zeitstempelstelle weder dem Kunden noch dem Hersteller zuzurechnen ist; das prüft der Verifier nicht. Ob der Hersteller die Daten seiner Kunden von verbundenen Stellen trennt und wie weit die Ausnahme für eine Person reicht, die für beide Seiten handelt, regelt Heartbeat-Spezifikation §12 (unten, Abruf und Informationssperre).
- **Zusammenwirken von Hersteller und Kunde (ab Fassung 1.10):** Wirken Hersteller und Kunde zusammen, etwa bei einem verbundenen Kunden, können sie eine Kette kürzen oder neu schreiben und die Anker-Historie dazu passend ausstellen, ohne dass Paket und Historie einander widersprechen. Gegen ein Neuschreiben wirken Zeitzeugen einer Stelle, die keinem von beiden zuzurechnen ist und deren Vertrauensanker der Prüfer selbst beibringt (Abschnitt 7.3): Ein neu geschriebener Checkpoint hat keinen Token mit früherem `genTime`. Gegen ein Kürzen wirken sie nicht, denn die `TIME_ANCHOR` des abgeschnittenen Endes gehen mit ihm verloren, und eine Zeitstempelstelle veröffentlicht nichts, was der Prüfer vergleichen könnte. Bezeugte Tage des Herstellerprotokolls wirken gegen ein Kürzen nur, wenn der Prüfer den Kettentag-Nachweis eines solchen Tages selbst schon hält, etwa aus einer früheren Prüfung archiviert: Den Auszug liefert der Hersteller, und der Verifier verlangt Nachweise nur für die Tage der Quittungen im Paket (Abschnitt 7.4.10, Schritte L7 und L8). Lässt ein zusammenwirkender Hersteller die Nachweise der Tage nach der letzten Quittung des gekürzten Pakets weg, meldet der Verifier nichts; dann kann auch die Vollständigkeit aus der Anker-Historie als belegt gelten und Stufe 3 erreicht werden. Ein Abgleich der öffentlichen Tagesblätter von Hand auf `position(C, d)` für Tage vor der Anforderung kann das Kürzen zeigen; der Verifier führt ihn nicht aus. Bevor ein Tag des Herstellerprotokolls bezeugt ist, zeigt es, was beide vereinbart haben. Die Beweisstufe zeigt die Verbundenheit an, ändert ihre Zahl aber nicht.
- **Anker-Historie als Angabe des Prüfers (ab Fassung 1.10):** Wurzeln, die der Hersteller mehr als 15 Minuten vor der Anforderung des Pakets gegengezeichnet oder als Lückenzeuge festgehalten hat und die dem Paket fehlen oder widersprechen, meldet der Verifier als `MERKLE_INCONSISTENT` (Abschnitt 8.8.5); eine nur gemeldete Wurzel ergibt dann `ANCHOR_HISTORY_FORK` (Exit 1). Eine Wurzel, die ein unredlicher Hersteller erfindet oder die jemand mit einem Bescheidschlüssel auf eine Seite setzt, erschiene ebenso; sie ist diesem Schlüssel zuzurechnen, als erfunden erkennen kann der Verifier sie nicht. Dieselbe Wurzel kann aus dem Herstellerprotokoll `LOGGED_ROOT_MISMATCH` (Exit 1) und aus der Anker-Historie `MERKLE_INCONSISTENT` (Exit 2) ergeben; der Bericht nennt beide, denn nur der Abgleich mit der Historie kennt einen Anforderungszeitpunkt und eine Bindung an das Gerät. Eine Seite, deren Gerät nicht zum Paket passt, verwendet der Verifier nicht; das schützt ein ehrliches Paket, wenn eine andere Anlage die `chain_id` einer nie verankerten Kette zuerst vorgelegt hat. Ein Paket, das unter einem anderen Geräteschlüssel neu signiert wurde und keine Quittung trägt, erhält dadurch statt Exit 2 einen benannten Befund mit Exit 1. Ohne Anforderungszeitpunkt beurteilt der Verifier keine Kürzung; nennt der Prüfer einen späteren Zeitpunkt als den tatsächlichen, erscheint ein ehrliches Paket als gekürzt, nennt er einen früheren, prüft der Verifier weniger. Wurzeln aus den 15 Minuten vor der Anforderung, die dem Paket fehlen, sind ein Hinweis, kein Befund; ob dem Paket Wurzeln aus diesen 15 Minuten fehlen, beurteilt der Verifier nicht. Wurzeln, die ein Metadatenserver vor dem Stichtag `legacy_boundary` der Registry festgehalten hat (Abschnitt 8.8.4, Schritt H10), können in der Historie fehlen. Die Historie hängt davon ab, dass der Hersteller sie ausliefert; abgerufene Seiten bleiben offline prüfbar. Ob zwei übergebene Seiten von zwei Stellen stammen, kann der Verifier nicht wissen. Verschiedene Seiten für verschiedene Prüfer fallen nur auf, wenn beide in denselben Lauf gelangen; Seiten der Anker-Historie stehen in keinem Protokoll und an keinem zweiten Ort. Lehnt der Hersteller einen Abruf ab, etwa wegen der Begrenzung der Abrufe (HTTP 429), sagt das nichts über das Paket; erhält der Prüfer dadurch keine frische Seite, meldet der Verifier `ANCHOR_HISTORY_UNVERIFIED` mit dem Grund `issued_before_request`, oder es gibt keine Seite zu übergeben; der Prüfer ruft dann später erneut ab (Heartbeat-Spezifikation §9.7). Die im Verifier eingebaute Herstellerwurzel bürgt wie eine Wurzel des Prüfers; der Bericht nennt, welche verwendet wurde. Ein Verifier, der dem Paket beiliegt, stammt aus derselben Hand wie das Paket; auch seine Angabe zur Verbundenheit ist dann eine Angabe der geprüften Seite.
- **Abruf der Historie und des Protokolls, Informationssperre (ab Fassung 1.10):** Wer die Anker-Historie oder einen Auszug des Herstellerprotokolls zu einer Kette abruft, teilt dem Hersteller mit, welche Kette wann geprüft wird; dass er das nicht festhält, ist eine Pflicht seines Betriebs (Heartbeat-Spezifikation §12), die kein Prüfpaket zeigt (kein Beleg durch LEDGER). Ebenso die Trennung der Kundendaten von verbundenen Stellen. Handelt eine Person zugleich für den Hersteller und für eine verbundene Stelle, darf sie Betriebszugriff behalten, solange der Hersteller die Trennung für sie nicht einrichten kann, höchstens bis zu einem festen Tag, den er mit Umfang und Zeitraum der Ausnahme öffentlich angibt; Heartbeats, Telemetrie und Zusammenfassungen über andere Kunden bleiben ihr auch dann verschlossen, jeder ihrer Zugriffe wird unveränderlich festgehalten, und eine unabhängige Prüfung ist dann Pflicht (Heartbeat-Spezifikation §12). Auch das zeigt kein Prüfpaket (kein Beleg durch LEDGER). Spätestens ab dem ersten Tag seines Herstellerprotokolls hält der Hersteller Zugriffe auf Kundendaten in einer Zugriffskette fest (Eintragstyp `DATA_ACCESS`, Abschnitt 4.25; Heartbeat-Spezifikation §12). Sie zeigt, welche Zugriffe festgehalten wurden, wann, über welches Konto, zu welchem Zweck und in welchem Umfang, und dass ein verankerter Eintrag danach weder entfernt noch geändert wurde; ob jeder Zugriff festgehalten wurde, zeigt sie nicht (kein Beleg durch LEDGER). Wer Zugang zum Rechner hat, kann ohne Eintrag zugreifen, ein Notzugang gibt Daten vor dem bestätigten Eintrag aus, und den Inhalt eines Vorgangs prüft nur, wer Vorgang und Salz erhält. Der Hersteller zeichnet seine Zugriffskette selbst gegen und stellt ihre Anker-Historie aus; er ist für sie Kunde und Gegenzeichner zugleich. Unabhängig binden sie nur Zeitzeugen einer Stelle, die weder er noch eine mit ihm verbundene Stelle betreibt, Wurzeln, die der Prüfer selbst aufbewahrt hat, sein Herstellerprotokoll und die täglichen Köpfe der Zugriffskette an beiden Veröffentlichungsorten. Ob die Kette gekürzt wurde, zeigt der Abgleich dieser Köpfe und der Tagesblätter mit dem Prüfpaket in der jährlichen Prüfung (Heartbeat-Spezifikation §12, Zugriffskette, Punkt 8), nicht der Verifier. Ein Kunde findet seine eigenen Einträge darin nicht, denn kein Eintrag nennt ihn. Tageseinträge, Tagesblätter und den Spiegel am zweiten Veröffentlichungsort kann der Prüfer abrufen, ohne eine Kette zu nennen; die Kettentag-Nachweise und die Seiten seiner Kette erhält er nur mit ihrer `chain_id`. Die Länge einer Seite hängt auch von der Zahl der Zeiträume ab, und gleiche Eintragungszeitpunkte auf den Seiten zweier Ketten lassen erkennen, dass beide demselben verbundenen Kunden gehören.
