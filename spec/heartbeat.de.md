# Cloud-Nachrichten: Aktivierung, Heartbeat, Verankerung

**Spezifikation LEDGER · spec_version 1.9 · Sprache: Deutsch (englische Fassung: `heartbeat.en.md`, identische Struktur)**

Kanonische Feldquelle ist `spec/registry.json`, Abschnitt `cloud_messages`. Bei Abweichung zwischen diesem Dokument und der Registry gilt die Registry.

## 1. Zweck und Geltungsbereich

Dieses Dokument spezifiziert abschließend den gesamten Nachrichtenverkehr von der LEDGER-Appliance zum Hersteller-Metadatenserver. Es existieren **genau drei Nachrichtentypen**:

| Nachrichtentyp | Richtung | Frequenz |
|---|---|---|
| `activation` | Appliance → Hersteller | bei Inbetriebnahme; erneut nur in den Fällen von §4 |
| `heartbeat` | Appliance → Hersteller | stündlich |
| `anchor` | Appliance → Hersteller | alle 5 Minuten |

Es gibt keinen weiteren Nachrichtentyp und keinen weiteren Kanal zum Hersteller. Was der Hersteller antwortet, regelt §9. Jede gesendete Nachricht wird von der Appliance wörtlich (exakte JCS-Bytes) als `ADMIN`-Eintrag in die eigene Kette geschrieben und ist im Portal unter „Was wir senden" einsehbar. Ein Auditor kann den tatsächlichen Netzverkehr per Mitschnitt gegen dieses publizierte Schema abgleichen.

**Update-Bündel (ab Fassung 1.9).** Außerhalb dieser drei Nachrichten lädt der Updater Update-Bündel über HTTPS von der bei der Installation konfigurierten Quelle: dem Metadatenserver oder dem Download-Bereich des Herstellers, einer zweiten Adresse. Er fragt nur mit `GET` nach einem Bündel und sendet dabei nichts über die Anlage außer dem, was jede HTTPS-Abfrage offenlegt (Adresse, Zeitpunkt, Pfad des Bündels; der Pfad nennt die Version und, ab der Ergänzung vom 07.10.2026, die Architektur der Anlage, `amd64` oder `arm64`, §9.3); insbesondere nie den Lizenzschlüssel, das Commitment, `license_proof` oder eine Gerätekennung. Die Quelle ist kein Vertrauensanker: Jedes Bündel MUSS vor jeder Verwendung gegen den bei der Installation angehefteten Update-Schlüssel signaturgeprüft werden, gleich woher es kommt, und wird ohne gültige Signatur verworfen; die Prüfsumme aus dem Update-Hinweis (§9.3) schützt nur den Transport. Verlangt eine Quelle eine Berechtigung, wird deren Form in dieser Spezifikation festgelegt, bevor sie gebaut wird; das Senden des Lizenzschlüssels ist dafür ausgeschlossen. Die Abfragen des Updaters sind keine Nachrichten im Sinn dieses Dokuments und werden nicht verkettet; ein installiertes Update belegt die Kette durch ihren Handover (`SEAL` mit `reason = update`, `RESUME`).

## 2. Grundsatz: bauartbedingt kein Freitext

> **Nur Ganzzahlen, Enums und Hex fester Länge; kein Freitextfeld existiert bauartbedingt.**

Die wiederkehrenden Nachrichten `heartbeat` und `anchor` bestehen ausschließlich aus Ganzzahlen, Enum-Werten aus fest publizierten Wertelisten, Hex-Strings fester Länge und Werten mit fester Grammatik (UUID, RFC-3339-Zeitstempel, SemVer). Ein Feld, in das freier Text (etwa Prompts, Antworten, Benutzernamen, Quellnamen, interne Adressen oder Konfigurationsinhalte) geschrieben werden könnte, ist im Schema nicht vorhanden und kann daher auch durch Fehlbedienung oder Softwarefehler nicht befüllt werden. Die `activation` (bei Inbetriebnahme, erneut nur in den Fällen von §4) trägt zusätzlich längenbegrenzte technische Kennungen (SHA-256-Commitment des Lizenzschlüssels, Besitznachweis `license_proof`, Schlüssel-ID, IANA-Zeitzonenname); auch sie enthält kein Feld für freie Inhalte.

Diese Eigenschaft ist Bauart, nicht Konfiguration: Die Telemetrie serialisiert ausschließlich typisierte Structs, deren Schema per CI eingefroren ist (jedes neue Feld macht die CI rot), und der Server verwirft alles, was nicht im Schema steht (§8).

## 3. Feldtypen

| Typ | Bedeutung |
|---|---|
| `int` | Ganzzahl; Wertebereich je Feld (`min`/`max`) |
| `enum` | genau ein Wert aus der angegebenen festen Werteliste |
| `const` | fester Pflichtwert; jeder andere Wert ist ungültig |
| `hex64` | Hex-String fester Länge: 64 Zeichen `[0-9a-f]` (32 Byte) |
| `hex128` | Hex-String fester Länge: 128 Zeichen `[0-9a-f]` (64 Byte) |
| `uuid` | UUID in kanonischer Kleinbuchstaben-Form (36 Zeichen) |
| `rfc3339` | Zeitstempel nach RFC 3339 in UTC |
| `semver` | Versionsnummer nach Semantic Versioning 2.0.0 |
| `version` | Spezifikationsversion `MAJOR.MINOR` ohne führende Nullen (Format-Spezifikation §10.6); der Server akzeptiert jede Minor-Version seiner eigenen Major-Version und weist eine andere Major-Version ab |
| `string` | technische Kennung, längenbegrenzt (`maxlen`) bzw. mustergebunden (`pattern`); nur in `activation` |
| `intmap` | Objekt: Schlüssel ausschließlich aus der referenzierten Enum → `int ≥ 0`; fehlender Schlüssel bedeutet 0; jeder nicht in der Enum enthaltene Schlüssel ist Freitext in Enum-Position und damit ungültig (§8) |
| `enummap` | Objekt: fest aufgezählte Schlüssel → genau ein Wert aus fester Werteliste |
| `object` | Objekt mit fest aufgezählten Unterfeldern; keine weiteren Felder zulässig |
| `array` | Liste von Werten eines festen Typs, längenbegrenzt (`max_items`); nur in `anchor` (Konsistenzbeweis) |

## 4. Nachrichtentyp `activation`

Bei Inbetriebnahme. Registriert den Ed25519-Geräte-Publikey, gegen den der Server alle späteren Signaturen prüft.

**Erneute Aktivierung (ab Fassung 1.9).** Erneut aktiviert sich eine Appliance nur in zwei Fällen: nachdem der Server `heartbeat` oder `anchor` mit HTTP 403 `unknown_appliance` beantwortet hat, und nach einem Schlüsselersatz (§4.1). Ein Kettenwechsel (§9.2 Schritt 1) ist ein Vorgang beim Hersteller und kein Anlass; die Aktivierung trägt keine `chain_id`. Jede erneute Aktivierung trägt dieselbe `appliance_id` und denselben Geräteschlüssel und wird vor dem Senden verkettet wie jede Nachricht (§1). Zwischen zwei Aktivierungen, gleich aus welchem Anlass, liegen mindestens 30 Sekunden; der Abstand verdoppelt sich mit jeder Aktivierung bis höchstens 15 Minuten und beginnt erst nach einer Stunde ohne Aktivierung wieder bei 30 Sekunden. So sind es höchstens acht Aktivierungen in einer Stunde. Den Abstand misst die Appliance mit einer monotonen Uhr; sie SOLL ihn über einen Neustart hinweg festhalten. Hält sie ihn nicht fest, gilt für die erste erneute Aktivierung nach einem Neustart der größte Abstand von 15 Minuten, damit eine Neustartschleife die Grenze nicht aufhebt.

| Feld | Typ | Beschränkung |
|---|---|---|
| `license_commitment` | hex64 | SHA-256 über die UTF-8-Bytes des Lizenzschlüssels. Der Schlüssel selbst wird nie gesendet, nie verkettet und nie exportiert; der Server findet über das Commitment die Lizenz. Das Commitment ist öffentlich (jedes Prüfpaket trägt es) und beweist für sich nichts |
| `license_proof` | hex64 | Besitznachweis des Lizenzschlüssels (§4.1); ab `spec_version` 1.8, vom Server unabhängig von der erklärten Version verlangt |
| `appliance_id` | uuid | - |
| `device_pubkey` | hex64 | Ed25519-Publikey des Geräteschlüssels |
| `device_key_id` | string | maxlen 64 |
| `version` | semver | Softwareversion der Appliance |
| `spec_version` | version | Spezifikationsversion, die die Appliance umsetzt (`1.0`, `1.1`, …); steuert den Nachrichtenvertrag von `anchor` (§6, §9) |
| `edition` | enum | `starter` \| `pro` \| `group` \| `enterprise` |
| `language` | enum | `de` \| `en` |
| `timezone` | string | maxlen 64 (IANA-Zeitzonenname) |
| `sig` | hex128 | Ed25519-Signatur (§7) |

Die Antwort des Servers regelt §9.3.

### 4.1 Besitznachweis `license_proof`

Das `license_commitment` ist nicht geheim: Es steht in jedem Prüfpaket, in der verketteten Aktivierung und ab Fassung 1.8 auch in `GENESIS` (Format-Spezifikation 4.1). Wer nur das Commitment vorlegt, beweist deshalb nichts. Den Besitz des Lizenzschlüssels beweist die Appliance mit

`license_proof = HEX( HMAC-SHA256( K, M ) )`

- `K` sind die UTF-8-Bytes des Lizenzschlüssels, genau wie ausgegeben (ohne Kürzen und ohne Angleichen der Groß- und Kleinschreibung), also dieselben Bytes, über die `license_commitment` gebildet wird.
- `M` sind die ASCII-Bytes des Feldwerts `device_pubkey` (64 Zeichen) unmittelbar gefolgt von denen des Feldwerts `appliance_id` (36 Zeichen), genau so, wie beide in derselben Nachricht stehen: 100 Bytes ohne Trennzeichen. Beide Felder haben feste Länge; die Verkettung ist eindeutig.
- HMAC nach RFC 2104 mit SHA-256; `HEX` ist die Hex-Kodierung in Kleinbuchstaben (64 Zeichen).
- Referenzwerte: `spec/contract/license_proof.json`.

Der Server prüft eine Aktivierung in dieser Reihenfolge: Signatur (§7) und Schema (§8); Lizenz über `license_commitment` (unbekannt: HTTP 403 `unknown_license`); `license_proof`, neu berechnet mit dem gespeicherten Lizenzschlüssel und in konstanter Zeit verglichen (weicht er ab: HTTP 403 `license_proof_invalid`, nichts wird registriert; fehlt er, scheitert schon das Schema: HTTP 400 `invalid_field`, Feld `license_proof`, vor jeder Lizenzprüfung; so antwortet der Server auch einer Appliance vor Fassung 1.8); erst danach Edition, Gerätegrenze und Registrierung. Eine Anfrage ohne gültigen Nachweis DARF NICHT auf das Anfragekontingent der Lizenz angerechnet werden: Sonst könnte jeder, der ein Prüfpaket hält, mit dem öffentlichen Commitment die Heartbeats und Anker des Kunden in die Drosselung treiben. Der Server verlangt `license_proof` unabhängig von der erklärten `spec_version`. Eine ältere erklärte Version ist kein Weg um den Nachweis herum. Bereits registrierte Appliances bleiben registriert; ihre Heartbeats und Anker prüft der Server wie bisher gegen den registrierten Geräteschlüssel.

**Was der Nachweis bindet.** Er bindet den Lizenzschlüssel an genau ein Paar aus Geräteschlüssel und `appliance_id`. Wer ein Prüfpaket hält, kennt das Commitment und die verkettete Aktivierung samt `license_proof`, aber nicht den Schlüssel: Einen eigenen Geräteschlüssel kann er nicht registrieren. Er kann die verkettete Nachricht nur wörtlich wiederholen. Eine wörtliche Wiederholung (gleiche `appliance_id`, gleicher `device_pubkey`, gleiche Lizenz) MUSS der Server als bereits erledigt behandeln: keine neue Appliance, kein Verbrauch der Gerätegrenze. Eine Aktivierung, die verkettet wurde, den Hersteller aber nie erreicht hat oder abgewiesen wurde (Egress aus, Sendefehler, `appliance_limit_reached`), kann ein Paketinhaber als Erster einreichen. Deshalb zählt eine registrierte Appliance erst gegen die Gerätegrenze, und die Stille-Überwachung (§10) beginnt erst, wenn der erste gültige Heartbeat mit dem registrierten Geräteschlüssel eingegangen ist (ab Fassung 1.9); bis dahin ist die Registrierung nur vorgemerkt. Einen Heartbeat kann ein Paketinhaber nicht signieren. Eine Aktivierung für eine registrierte `appliance_id` mit anderem Geräteschlüssel bleibt HTTP 409 `already_registered`, auch mit gültigem Nachweis; ein Wechsel des Geräteschlüssels ist ein Vorgang beim Hersteller, kein Selbstbedienungsweg.

**Schlüsselform und Schlüsselstärke.** Ein Lizenzschlüssel folgt der Grammatik `^[A-Z0-9-]{19,29}$` (Registry `cloud_messages.activation.license_key_grammar`): höchstens 29 Bytes und nur Großbuchstaben, Ziffern und Bindestrich. Beides ist sicherheitsrelevant: Ein Schlüssel über 64 Bytes würde nach RFC 2104 vor dem HMAC mit SHA-256 gekürzt, und das Ergebnis wäre genau das öffentliche Commitment, aus dem dann jeder `license_proof` berechenbar wäre; und ein Schlüssel aus 64 Kleinbuchstaben-Hexzeichen sähe aus wie ein Commitment und landete im Klartext in `GENESIS` (Format-Spezifikation 4.1). Das Commitment ist ein ungesalzener SHA-256. Ein Lizenzschlüssel MUSS deshalb außerdem mindestens 80 Bit aus einem kryptographisch sicheren Zufallsgenerator tragen, und der Hersteller DARF keine frei gewählten Schlüssel ausgeben: Einen schwächeren Schlüssel gewinnt man aus dem öffentlichen Commitment durch Durchprobieren, und mit ihm jeden `license_proof`. Der Lizenzschlüssel dient in dieser Fassung nur diesem Nachweis; jede künftige weitere HMAC-Verwendung MUSS eine eigene Kennung in die Nachricht aufnehmen, damit sich die Nachweise nicht vertauschen lassen.

**Offengelegte Schlüssel.** Bis Fassung 1.7 schrieb die Standardinstallation den Lizenzschlüssel im Klartext in `GENESIS` (Format-Spezifikation 4.1), und eine Kette kann ihn nie mehr ablegen. Jeder Schlüssel, der je in einem `GENESIS` stand, gilt als offengelegt und MUSS vom Hersteller ersetzt werden; für einen offengelegten Schlüssel beweist `license_proof` nichts. **Ersatz (ab Fassung 1.9 festgelegt):** Die Lizenz bleibt dieselbe (Laufzeit, Registrierungen und Anker-Historie bleiben bestehen); der Hersteller führt zu ihr ab dann das neue Commitment, und jeder Bescheid (§9.4) trägt es. Der Betreiber hinterlegt den neuen Schlüssel an der Appliance; diese aktiviert sich damit erneut (gleiche `appliance_id`, gleicher Geräteschlüssel, gültiger Nachweis unter dem neuen Schlüssel), und der Server bindet die Registrierung um: HTTP 200, kein `already_registered`. Einen Nachweis unter dem ersetzten Schlüssel nimmt er danach nicht mehr an. `GENESIS.license_id` bleibt das Commitment zur Zeit der Kettenerzeugung (Format-Spezifikation 4.1).

**Annahme der Umbindung (ab Fassung 1.9).** Die Appliance wertet eine Umbindung erst als angenommen, wenn die 200-Antwort auf ihre Aktivierung beides trägt:

1. im Member `license` einen nach §9.4 wirksamen Lizenzbescheid mit dem Commitment des hinterlegten, also des neuen Schlüssels, dessen `server_ts` höchstens 15 Minuten von der eigenen Uhr abweicht, in beide Richtungen. Er belegt, dass der Hersteller die Lizenz unter dem neuen Commitment führt; an eine Appliance ist er nicht gebunden;
2. im Member `activation_receipt` eine nach §9.8 wirksame Aktivierungsquittung mit der eigenen `appliance_id`, dem eigenen `device_pubkey` und demselben Commitment, deren `server_ts` ebenso höchstens 15 Minuten abweicht. Erst sie bindet die Antwort an diese Registrierung: Einen Bescheid allein könnte, wer im Transportweg sitzt, aus der Antwort an eine andere Appliance derselben Lizenz übernehmen.

Fehlt eines davon oder ist es nicht wirksam, ist die Umbindung gescheitert. Die Appliance wiederholt sie im Abstand von §4 und meldet das Scheitern. Aufzeichnung und Verankerung hängen davon nicht ab.

**Appliance-Seite des Ersatzes (ab Fassung 1.9).** Eine Appliance gilt für sich als registriert, wenn sie eine angenommene Aktivierung festgehalten hat (eine Umbindung erst, wenn sie nach dem vorigen Absatz angenommen ist) oder wenn ihre Kette eine `CHECKPOINT_RECEIPT` trägt; eine nur verkettete Aktivierung genügt nicht. Eine registrierte Appliance sendet Heartbeat und Anker weiter, gleich wie eine erneute Aktivierung ausgeht. Hat sie weder das eine noch das andere, ist die nächste Aktivierung die erste: Weicht SHA-256 des hinterlegten Schlüssels vom Commitment in `GENESIS` ab, aktiviert sie nicht und meldet den Abgleichfehler; kann sie das Commitment aus `GENESIS` nicht lesen, aktiviert sie ebenfalls nicht und meldet das. Hält eine registrierte Appliance nicht fest, unter welchem Commitment ihre Aktivierung angenommen wurde (Aktivierungszustand aus einer Fassung vor 1.9, oder verloren), entscheidet `GENESIS`: Nennt es ein anderes Commitment als das des hinterlegten Schlüssels, ist das ein Schlüsselersatz; nennt es dasselbe oder ist es nicht lesbar, aktiviert sie nicht erneut. Solange der Server die Registrierung nur vorgemerkt hat (oben, „Was der Nachweis bindet") und die Gerätegrenze der Lizenz erreicht ist, kann er Heartbeats und Anker mit HTTP 403 `appliance_limit_reached` beantworten (§9.5, §9.6); deren Anker zeichnet er dann nicht gegen. Die Appliance sendet dann weiter, meldet es und aktiviert deshalb nicht erneut.

## 5. Nachrichtentyp `heartbeat`

Stündlich. Ausschließlich Zählwerte, Enums und der letzte Checkpoint. Keine Inhalte, keine URLs, keine Namen.

| Feld | Typ | Beschränkung |
|---|---|---|
| `appliance_id` | uuid | - |
| `ts` | rfc3339 | Sendezeitpunkt (Appliance-Uhr) |
| `version` | semver | Softwareversion der Appliance |
| `spec_version` | version | Spezifikationsversion, die die Appliance umsetzt (`1.0`, `1.1`, …); steuert den Nachrichtenvertrag von `anchor` (§6, §9) |
| `uptime_s` | int | min 0 |
| `mode` | enum | `full` \| `hash_only` |
| `disk_pct` | int | min 0, max 100 |
| `spool_backlog` | int | min 0 |
| `loss_counter` | int | min 0 (fsync-persistenter Verlustzähler des Pförtners) |
| `gap_count_24h` | int | min 0 |
| `gap_seconds_24h` | int | min 0; ab Fassung 1.9 die Länge der Vereinigung aller verketteten `GAP`-Fenster, auf die letzten 24 Stunden beschnitten: Überlappende Fenster zählen einmal (Format-Spezifikation 8.7) |
| `oversight_count_24h` | int | min 0 |
| `events_total` | int | min 0 |
| `events_24h` | int | min 0 |
| `events_24h_by_type` | intmap | Schlüssel aus `event_types` (§5.1) |
| `calls_24h_by_provider_class` | intmap | Schlüssel aus `provider_classes` (§5.1) |
| `alarms_24h_by_rule` | intmap | Schlüssel aus `alarm_rules` (§5.1) |
| `health` | enummap | Schlüssel `schleuse` \| `kern` \| `portal` \| `telemetrie`; Werte `green` \| `yellow` \| `red` |
| `last_checkpoint` | object | `{chain_id: uuid, tree_size: int ≥ 0, merkle_root: hex64}` |
| `sig` | hex128 | Ed25519-Signatur (§7) |

Die Antwort des Servers trägt den aktuellen Lizenzbescheid (§9.3, §9.4).

### 5.1 Zulässige Map-Schlüssel (fixe Enums aus der Registry)

- `event_types`: `GENESIS`, `AI_CALL`, `TICK`, `GAP`, `SOURCE_GAP`, `RECONCILIATION`, `CLOCK_JUMP`, `MODE_CHANGE`, `RESTART`, `SEAL`, `RESUME`, `OVERSIGHT`, `ALARM`, `CONFIG_CHANGE`, `KEY_ROTATION`, `REPORT_ISSUED`, `CONTENT_DELETED`, `CONTENT_DISCLOSED`, `ADMIN`, `CHECKPOINT`, `CHECKPOINT_RECEIPT`, `TIME_ANCHOR`, `CAPTURE_TRUNCATED`, `LEGAL_HOLD`
- `provider_classes`: `openai`, `anthropic`, `azure_openai`, `google`, `aws_bedrock`, `mistral`, `aleph_alpha`, `ionos`, `ollama`, `vllm`, `other_us`, `other_eu`, `other_local`, `generic` (Anbieter-**Klassen** aus fester Enum; niemals Freitext, niemals Endpunkt-URLs)
- `alarm_rules`: `source_silence`, `volume_spike`, `error_rate_spike`, `new_provider_class`, `spool_backlog`, `disk_85`, `disk_92`, `disk_97`, `cert_expiry`, `anchor_overdue`, `report_missing`, `report_delivery_failed`, `component_silence`, `test_alarm`

## 6. Nachrichtentyp `anchor`

Alle 5 Minuten. Trägt ausschließlich den Merkle-Root (32 Byte), die Baumgröße und, ab `spec_version` 1.1, den Konsistenzbeweis nach RFC 6962 (Knotenhashes des Merkle-Baums). Aus nichts davon ist ein Inhalt rekonstruierbar.

| Feld | Typ | Beschränkung |
|---|---|---|
| `appliance_id` | uuid | - |
| `chain_id` | uuid | - |
| `tree_size` | int | min 1 |
| `merkle_root` | hex64 | RFC-6962-Merkle-Root über `tree_size` Blätter |
| `consistency_proof` | object | ab `spec_version` 1.1 Pflichtfeld (§9); im Nachrichtenvertrag für `spec_version` 1.0 nicht vorhanden |
| `consistency_proof.from_tree_size` | int | min 0; die Bezugsgröße dieser Kette (§9.2): die größte vom Server gegengezeichnete oder als Lückenzeuge festgehaltene `tree_size` (0 = noch keine) |
| `consistency_proof.hashes` | array (hex64) | RFC-6962-Konsistenzbeweis von `from_tree_size` nach `tree_size`; leer bei `from_tree_size` 0; max 64 Einträge |
| `sig` | hex128 | Ed25519-Signatur (§7) |

## 7. Signaturgegenstand

Für alle drei Nachrichtentypen identisch:

1. Bilde das Nachrichtenobjekt **ohne** das Feld `sig`.
2. Kanonisiere es nach RFC 8785 (JCS).
3. `sig` = Ed25519-Signatur über diese UTF-8-JCS-Bytes, hex-kodiert (128 Zeichen), erstellt mit dem privaten Geräteschlüssel zu `device_pubkey`/`device_key_id` aus der Aktivierung (bei `activation` selbst: der in der Nachricht registrierte Schlüssel; den Besitz des Geräteschlüssels belegt die Selbstsignatur, den des Lizenzschlüssels `license_proof` (§4.1), der über `device_pubkey` und `appliance_id` gebildet und damit an genau diesen Geräteschlüssel gebunden ist).

Der Transportkanal (normales TLS, firmen-proxy-tauglich) ist **nicht** beweistragend; die Ed25519-Signaturen sind es. Der Server verwirft jede Nachricht mit ungültiger Signatur vor jeder weiteren Verarbeitung.

## 8. Serververhalten: harte Validierung

Der Metadatenserver validiert jede eingehende Nachricht hart gegen das publizierte Schema:

- **Überschüssige Felder** (im Schema nicht vorhandene Top-Level-Felder): Die Nachricht wird angenommen, die überschüssigen Felder werden **verworfen und geloggt** (Schutz auch gegen fehlerhafte künftige Appliance-Versionen). Verworfene Felder werden niemals gespeichert.
- **Freitext in Enum-Position** (ungültiger Enum-Wert, unbekannter Map-Schlüssel, Muster-/Grammatikverstoß bei `uuid`/`rfc3339`/`semver`/`version`/`hex`/`const`/`pattern`, überlange `array`-Listen): **HTTP 400**, Nachricht wird vollständig abgewiesen und nicht gespeichert.
- **Nachrichtenvertrag je `spec_version`:** Der Server prüft `anchor` gegen den Vertrag der höchsten `spec_version`, die die Appliance je erklärt hat (Aktivierung, dann jeder Heartbeat). Ab 1.1 ist `consistency_proof` ein Pflichtfeld; für 1.0 existiert es im Vertrag nicht und würde als überschüssiges Feld verworfen (§9). Eine **niedrigere** `spec_version` als die geführte wird nicht übernommen; der Heartbeat wird angenommen, die Herabstufung geloggt und gezählt (`spec_version_downgrades_refused_total`): wer den Geräteschlüssel hält, kann den Vertrag ohne Beweis nicht durch eine Rückerklärung wieder öffnen.
- Bereichsverstöße bei `int` (`min`/`max`), fehlende Pflichtfelder, ungültige Signatur (§7): HTTP 400 bzw. Abweisung.
- **Anfragekontingent (ab Fassung 1.9).** Der Server begrenzt Anfragen je Lizenz. Angerechnet wird eine Anfrage erst, wenn sie alle Prüfungen bestanden hat, die eine Wiederholung erkennen, denn jede gesendete Nachricht steht wörtlich im Prüfpaket (§1), und wer eines hält, könnte sonst mit echten, gültig signierten Nachrichten das Kontingent des Kunden aufbrauchen und dessen Heartbeats und Anker in die Drosselung treiben. Nicht angerechnet werden: eine Aktivierung ohne gültigen `license_proof` (§4.1), eine wörtliche Wiederholung einer Aktivierung, ein Heartbeat, dessen `ts` nicht neuer ist als der zuletzt angenommene dieser Appliance oder außerhalb des Zeitfensters liegt, und ein Anker, den §9.2 Schritt 2 oder 3 als Wiederholung oder als veraltet beantwortet. Solche Anfragen werden ohne Wirkung beantwortet und höchstens je Quelle begrenzt.
- **`spec_version` 1.0** nimmt der Server ab Fassung 1.9 nicht mehr an (§9.2, „Nachrichtenvertrag 1.0“).

Damit gilt: Selbst eine kompromittierte oder fehlerhafte Appliance kann über diesen Kanal keinen freien Inhalt beim Hersteller ablegen; der Server nimmt ihn nicht an.

## 9. Antworten des Herstellers

Der Server antwortet mit einem JSON-Objekt. Beweiskraft haben darin nur signierte Objekte: die Gegensignatur (§9.1), die Lizenzbescheide (§9.4, §9.5) und die Aktivierungsquittung (§9.8). Die Appliance MUSS Member einer Antwort, die dieses Dokument nicht nennt, ignorieren, und sie DARF aus unsignierten Membern keine Entscheidung ableiten, die Aufzeichnung, Kette oder Verankerung betrifft. Eine eng begrenzte Ausnahme ist die Gerätegrenze am Anker (§9.5): Sie entscheidet nur, ob ein Anker überfällig ist und was der Status zeigt. Kein Bescheid des Herstellers sperrt, löscht oder verändert Kundendaten: Die Aufzeichnung läuft in jedem Lizenzzustand weiter.

### 9.1 Gegensignatur

Die Antwort auf eine gültige `anchor`-Nachricht einer gültigen oder in Kulanz befindlichen Lizenz ist die **Gegensignatur** des Herstellers (HTTP 200):

| Feld | Typ | Beschränkung |
|---|---|---|
| `chain_id` | uuid | aus der Anfrage |
| `tree_size` | int | aus der Anfrage |
| `merkle_root` | hex64 | aus der Anfrage |
| `server_ts` | rfc3339 | Serverzeit |
| `server_key_id` | string | maxlen 64 |
| `server_signature` | hex128 | Ed25519 mit dem Hersteller-Schlüssel über JCS(`{chain_id, tree_size, merkle_root, server_ts}`) |

Die Appliance verkettet die Antwort als `CHECKPOINT_RECEIPT`-Eintrag. Jeder Dritte kann die Gegensignatur offline prüfen; den Hersteller-Publikey belegt er über die mit der Lizenz veröffentlichte Herstellerwurzel und die signierte Schlüsselliste im Prüfpaket, nicht über das Paket allein (Format-Spezifikation 7.1, 10.7). Der Server führt zusätzlich je `chain_id` eine **tree_size-Monotonie-Prüfung** gegen die Bezugsgröße (§9.2): Ein `anchor` mit kleinerer `tree_size` wird nicht angenommen; eine andere Wurzel zu einer festgehaltenen Größe ist ein Fork-Befund, ein nur veralteter Anker nicht (§9.2 Schritt 2).

### 9.2 Konsistenzbeweis und Lückenzeuge

**Konsistenzbeweis (ab `spec_version` 1.1).** Monotonie allein beweist nicht, dass die neue Wurzel die alte fortsetzt: Eine umgeschriebene Kette, die nur *gewachsen* ist, bestünde sie. Deshalb nimmt der Server eine größere `tree_size` nur an, wenn `consistency_proof` das Fortsetzen beweist (RFC 6962, Konsistenzbeweis zwischen `from_tree_size` und `tree_size`).

**Festgehaltene Wurzeln und Bezugsgröße.** Der Server hält für jede Kette jede Wurzel fest, die er geprüft und angenommen hat, gegengezeichnet (§9.1) oder als Lückenzeuge (unten), mit `tree_size`, `merkle_root` und Serverzeit; ab Fassung 1.9 MUSS er sie alle aufbewahren (Anker-Historie, §9.7). Die größte davon ist die Bezugsgröße `B` mit ihrer Wurzel; solange es keine gibt, ist `B = 0`. Ein Anker wird in dieser Reihenfolge geprüft:

1. Signatur (§7), Schema (§8) und Zugehörigkeit der Kette zur sendenden Appliance. Ab Fassung 1.9 zusätzlich: Führt der Server für diese Appliance schon eine andere Kette mit `B > 0`, hält er für eine neue `chain_id` nichts fest, bis ein Kettenwechsel beim Hersteller eingetragen ist (ein Vorgang beim Hersteller wie der Wechsel des Geräteschlüssels, §4.1; eingetragen werden Vorgänger und die übergebene `tree_size`): HTTP 409 `chain_succession_required`. Sonst könnte, wer den Geräteschlüssel hält, eine umgeschriebene Geschichte als neue Kette ohne jeden Beweis bei `B = 0` beginnen lassen.
2. `tree_size < B`: Ist für genau diese `tree_size` eine Wurzel festgehalten und gleicht sie der vorgelegten, ist der Anker eine Wiederholung: Bei einer gegengezeichneten antwortet der Server mit der ursprünglichen Gegensignatur, bei einem Lückenzeugen mit HTTP 409 `stale_anchor`; kein Befund. Ist eine andere Wurzel festgehalten, hat der Geräteschlüssel zwei Wurzeln derselben Größe signiert: HTTP 409 `fork_detected`, Fork-Befund. Ist für diese Größe keine festgehalten: HTTP 409 `stale_anchor`, kein Befund, nichts wird festgehalten. Ein veralteter Anker (ein während eines Netzausfalls verketteter und nie zugestellter, einer, der die Wiederholung eines neueren überholt, oder einer aus einem Prüfpaket, wo jeder gesendete Anker wörtlich steht) beweist ohne Konsistenzbeweis zur Bezugsgröße keinen Fork. Der Server zählt solche Anker (`anchors_stale_total`).
3. `tree_size = B`: Mit derselben Wurzel ist der Anker eine Wiederholung: Bei gegengezeichnetem `B` antwortet der Server mit der ursprünglichen Gegensignatur, bei bezeugtem `B` geht es mit Schritt 5 weiter (nach einer Verlängerung wird der Lückenzeuge dort gegengezeichnet); mit anderer Wurzel ist er ein Fork (HTTP 409 `fork_detected`, Fork-Befund).
4. `tree_size > B`: `from_tree_size` MUSS gleich `B` sein, sonst antwortet der Server HTTP 409 `consistency_required` mit `expected_from_tree_size = B`; die Appliance holt den passenden Beweis aus ihrer Kette und sendet den Anker einmal erneut. Trägt der Beweis gegen die Wurzel zu `B` und die neue Wurzel nicht, antwortet er HTTP 409 `consistency_failed`, nimmt nichts an und vermerkt einen Fork-Befund (Alarm über den Sweep, Verlauf in der Anker-Historie). Bei `B = 0` ist `hashes` leer: Die erste festgehaltene Wurzel einer Kette braucht keinen Beweis.
5. Erst jetzt die Lizenz: gültig oder in Kulanz → Gegensignatur (§9.1); abgelaufen → Lückenzeuge und Verweigerung (§9.5).

Die Lizenzprüfung steht hinter der Konsistenzprüfung. Auch ein Anker, den der Server nicht gegenzeichnet, ist damit geprüft, und ein Fork während einer Lizenzlücke fällt auf wie jeder andere.

**Lückenzeuge.** Verweigert der Server die Gegenzeichnung eines Ankers, der die Schritte 1 bis 4 bestanden hat, weil die Lizenz abgelaufen ist, MUSS er dessen `tree_size` und `merkle_root` als **Lückenzeugen** dieser Kette dauerhaft festhalten, bevor er antwortet; sie sind ab dann die Bezugsgröße `B`. Jeder spätere Anker der Kette, in der Lücke wie nach einer Verlängerung, muss damit die Fortsetzung genau dieser Wurzel beweisen. Ein Lückenzeuge ist keine Gegensignatur und wird nie als solche ausgeliefert; die Anker-Historie (§9.7) nennt ihn als solchen.

**Gemeldete Wurzeln (ab Fassung 1.9).** Zusätzlich MUSS der Server jede geräte-signierte Wurzel festhalten, die ihn erreicht, ohne angenommen zu werden: `last_checkpoint` jedes gültigen Heartbeats (§5) und die Wurzel jedes Ankers, den er mit `consistency_required` beantwortet. Sie sind keine Bezugsgröße (ungeprüft beweisen sie keine Fortsetzung), aber sie stehen als gemeldete Wurzeln in der Anker-Historie: Die Appliance hat zu dieser Zeit selbst erklärt, dass ihre Kette diese Wurzel hatte.

Was das schließt: Ohne Lückenzeugen musste der erste Anker nach einer Verlängerung nur die Fortsetzung der letzten Wurzel VOR der Lücke beweisen. Wer Geräteschlüssel und Kettendateien hält, konnte bis dahin jeden Eintrag aus der Lücke umschreiben, den Merkle-Baum neu bauen und die Neufassung gegenzeichnen lassen. Mit Lückenzeugen reicht diese Möglichkeit, wie im lizenzierten Betrieb, nur bis zur jüngsten festgehaltenen Wurzel zurück (Restfenster, Format-Spezifikation 11.2); eine Neufassung davor scheitert am Konsistenzbeweis und wird als Fork gemeldet, und in einem Prüfpaket fällt sie am Abgleich mit der Anker-Historie auf (§9.7). **Grenze:** Wer die Anker während der Lücke gar nicht erst zum Hersteller lässt, verhindert Lückenzeugen; Quittungen verliert er dabei keine, denn in der Lücke gibt es keine. Solange die Heartbeats durchkommen, bleiben ihre gemeldeten Wurzeln festgehalten, und die Anker-Historie zeigt Heartbeats ohne angenommenen Anker. Lässt er auch die Heartbeats nicht durch, meldet der Hersteller die Stille (§10), und die Anker-Historie endet vor der Lücke; das Prüfpaket zeigt das Restfenster über die ganze Zeit (Format-Spezifikation 11.2).

**Wahl von `from_tree_size`.** Die Appliance SOLL als `from_tree_size` die jüngste `tree_size` verwenden, die der Hersteller für diese Kette gegengezeichnet (§9.1) oder in einem wirksamen Verweigerungsbescheid bestätigt hat (§9.5); die Wiederholung nach `consistency_required` bleibt der Rückfall.

**Nachrichtenvertrag 1.0 (beendet ab Fassung 1.9).** Bis Fassung 1.8 gab es für Appliances mit `spec_version` 1.0 einen Nachrichtenvertrag ohne `consistency_proof`. Er ist beendet: Wer eine neue Appliance mit der Erklärung 1.0 aktiviert, könnte ihre Anker ohne jeden Beweis festhalten lassen. Der Server nimmt ab Fassung 1.9 keine Aktivierung und keinen Heartbeat mit `spec_version` 1.0 mehr an (HTTP 400 `invalid_field`, Feld `spec_version`) und keinen Anker ohne `consistency_proof`.

### 9.3 Antworten im Überblick

| Anfrage | HTTP | Antwort |
|---|---|---|
| `activation` | 200 | `{"status": "activated", "customer_id": <string>, "license": <Lizenzbescheid §9.4>, "activation_receipt": <Aktivierungsquittung §9.8>}`, auch bei abgelaufener Lizenz; der Bescheid sagt dann `expired` |
| `heartbeat` | 200 | `{"status": "ok", "license": <Lizenzbescheid §9.4>, "update": <Update-Hinweis, unten>, "update_arch": <Prüfsummen je Architektur, unten>}`; `license` fehlt, wenn der Server keinen Bescheid ausstellen kann, `update`, wenn kein Update angekündigt ist; `update_arch` steht genau dann, wenn `update` steht |
| `anchor` | 200 | Gegensignatur (§9.1) |
| `anchor` | 403 | Verweigerung wegen Lizenzablauf (§9.5) |
| jede | 4xx | Fehlerantwort (§9.6) |

**Update-Hinweis (ab Fassung 1.9).** Das Member `update` der Heartbeat-Antwort kündigt ein Update an (Registry `cloud_response_members.update`):

| Member | Typ | Bedeutung |
|---|---|---|
| `version` | string, `^[0-9]+\.[0-9]+\.[0-9]+$` | angekündigte Softwareversion |
| `channel` | string, `^[a-z]{1,16}$` | Auslieferungskanal |
| `min_version` | string, `^[0-9]+\.[0-9]+\.[0-9]+$` | kleinste Version, von der aus das Bündel installiert werden kann |
| `release_ts` | rfc3339 | Freigabezeit, Form wie in §9.4 Punkt 2 (drei Nachkommastellen, `Z`) |
| `sha256` | hex64 | SHA-256 über das ganze Bündel |

Der Hinweis ist **unsigniert** und nur ein Hinweis. Er ist kein Vertrauensanker und kein Auftrag: Die Appliance DARF auf ihn hin nichts installieren, ohne das Bündel gegen den angehefteten Update-Schlüssel zu prüfen (§1), die Zustimmung des Kunden einzuholen und eine Herabstufung abzulehnen. Ein gefälschter oder verfälschter Hinweis kann deshalb nur eine nicht vorhandene oder eine ohnehin gültig signierte Version nennen oder eine Ankündigung zurückziehen. Fehlt `update`, ist nichts angekündigt; ein Hinweis, der der Tabelle nicht entspricht, wird verworfen und der bisherige Stand behalten. Welche Updates der Hersteller ankündigt und ausliefert, hängt von der Lizenz ab: Sicherheitskorrekturen immer, Funktionsupdates nur mit aktiver Lizenz (Entscheidung vom 29.09.2026); das entscheidet der Hersteller, nicht die Appliance. Ein Hinweis ändert nichts an der Aufzeichnung.

**Prüfsummen je Architektur (ab Fassung 1.9, Ergänzung vom 07.10.2026).** Je Version gibt es ein Bündel je Architektur. Das Member `update_arch` der Heartbeat-Antwort nennt ihre Prüfsummen (Registry `cloud_response_members.update_arch`):

| Member | Typ | Bedeutung |
|---|---|---|
| `amd64` | hex64 | SHA-256 über das ganze Bündel für amd64 (x86_64) |
| `arm64` | hex64 | SHA-256 über das ganze Bündel für arm64 (aarch64) |

`update_arch` hat genau diese zwei Member und steht genau dann in der Antwort, wenn `update` darin steht. `update` bleibt bei seinen fünf Membern; sein `sha256` nennt das amd64-Bündel. Die Appliance nimmt `update_arch` nur zusammen mit `update` an. Steht `update_arch` ohne `update` da oder entspricht es der Tabelle nicht, verwirft sie den ganzen Hinweis wie ein fehlerhaftes `update` und behält den bisherigen Stand. Der Updater holt das Bündel seiner eigenen Architektur, `<Quelle>/<Version>/ledger-<Version>-<Architektur>.rbundle`, und prüft es gegen deren Prüfsumme. Fehlt `update_arch` oder darin die eigene Architektur, holt er nichts. Für `update_arch` gilt alles, was oben für den Hinweis gilt: unsigniert, kein Vertrauensanker, die Prüfsumme schützt nur den Transport, die Signatur gegen den angehefteten Update-Schlüssel bleibt Pflicht (§1). Das signierte Manifest des Bündels ändert sich dadurch nicht. Verfälscht jemand Hinweis und Quelle zugleich, kann er einer Appliance ein gültig signiertes Bündel der anderen Architektur unterschieben; die Signatur allein schließt das nicht aus.

### 9.4 Lizenzbescheid

Ein Bescheid reist im Member `license` einer Antwort, als Objekt mit genau diesen vier Membern (Registry `cloud_statements`):

| Member | Typ | Bedeutung |
|---|---|---|
| `statement_jcs` | string | der Bescheid in JCS-Form (RFC 8785); allein diese Bytes sind signiert |
| `server_key_id` | string, `^[A-Za-z0-9._-]{1,64}$` | Kennung des Hersteller-Schlüssels, desselben Gegenzeichnungsschlüssels wie in §9.1 (Format-Spezifikation 10.7) |
| `server_signature` | hex128 | Ed25519 über die UTF-8-Bytes von `statement_jcs` |
| `statement` | object | unsignierte Lesekopie von `statement_jcs`; der Empfänger MUSS sie ignorieren |

Der Bescheid `ledger.license_statement.v1` hat genau diese Member:

| Member | Typ | Bedeutung |
|---|---|---|
| `kind` | const `"ledger.license_statement.v1"` | Art des Bescheids |
| `license_commitment` | hex64 | Commitment der Lizenz (§4) |
| `state` | enum `valid` \| `grace` \| `expired` | Lizenzzustand zum Zeitpunkt `server_ts` |
| `countersigning` | bool | ob der Hersteller Anker dieser Lizenz gegenzeichnet; `true` genau dann, wenn `state` nicht `expired` ist |
| `updates` | bool | ob die Lizenz zu Funktionsupdates berechtigt; in dieser Fassung gleich `countersigning`. Sicherheitskorrekturen hängen nicht davon ab (Entscheidung vom 29.09.2026) |
| `server_ts` | rfc3339 | Ausstellungszeit nach der Serveruhr |
| `valid_until` | rfc3339 oder `null` | Ende der Laufzeit; `null` bei einer Lizenz ohne Laufzeit |
| `grace_until` | rfc3339 oder `null` | Ende der Kulanz; `null` bei einer Lizenz ohne Laufzeit |

Ein Bescheid ist nur wirksam, wenn der Empfänger (Appliance, Portal) ALLES bestätigt:

1. `statement_jcs` ist I-JSON ohne doppelte Membernamen und genau die JCS-Form seines eigenen Inhalts: Neu kanonisiert ergibt er dieselben Bytes.
2. Die Member sind genau die der Tabelle mit den angegebenen Typen; Zeitpunkte haben genau die Form `YYYY-MM-DDThh:mm:ss.sssZ`: UTC, drei Nachkommastellen, `Z`, wie Format-Spezifikation 10.7 (strenger als §3, der für Anfragen jede RFC-3339-Zeit in UTC zulässt); `kind` ist die erwartete Art.
3. Der Schlüssel `server_key_id` ist zum Zeitpunkt `server_ts` gültig, nach der signierten Hersteller-Schlüsselliste (Format-Spezifikation 10.7) oder als bei der Installation angehefteter Schlüssel, und `server_signature` trägt über die UTF-8-Bytes von `statement_jcs`.
4. `license_commitment` ist das eigene Commitment: das des Lizenzschlüssels, der an der Appliance hinterlegt ist, nicht `GENESIS.license_id`, das nach einem Schlüsselersatz (§4.1) abweicht.
5. Nur bei `ledger.license_statement.v1`: `countersigning` ist `true` genau dann, wenn `state` nicht `expired` ist; ein Widerspruch macht den Bescheid unwirksam.
6. `server_ts` liegt höchstens 15 Minuten nach der eigenen Uhr.

Der Empfänger ersetzt einen wirksamen Bescheid, den er hält, nie durch einen mit älterem `server_ts`; so kann niemand einen alten, günstigeren Bescheid wieder einspielen, auch nicht mit einem inzwischen widerrufenen Schlüssel, der zu seiner Zeit gültig war. Liegt der jüngste wirksame Bescheid mehr als drei Stunden (drei Heartbeats) zurück, zeigt der Empfänger ihn als veraltet an.

Ein unwirksamer Bescheid ist keine Auskunft; er ändert nichts. Ein wirksamer Bescheid dient der Anzeige (Portal, Status der Telemetrie) und ändert ebenfalls nichts an der Aufzeichnung. Gegensignaturen und Bescheide trägt derselbe Schlüssel; verwechseln lassen sie sich nicht: Der Signaturgegenstand einer Gegensignatur ist JCS über genau vier Member ohne `kind`, jeder Bescheid und jede Aktivierungsquittung (§9.8) trägt `kind`. Ein Verifier wertet Bescheide nicht aus. Referenzwerte mit einem Testschlüssel: `spec/contract/license_statement.json`.

### 9.5 Verweigerung wegen Lizenzablauf

Ist die Lizenz abgelaufen (nach Laufzeit und Kulanz), beantwortet der Server einen Anker, der §9.2 Schritte 1 bis 4 bestanden hat, nach dem Speichern des Lückenzeugen mit HTTP 403:

| Member | Typ | Bedeutung |
|---|---|---|
| `error` | const `"license_expired"` | Fehlercode (§9.6) |
| `detail` | string | Erläuterung; wird nicht ausgewertet |
| `valid_until`, `grace_until` | rfc3339 oder `null` | unsignierte Kopien; werden nicht ausgewertet |
| `license` | object | Objekt nach §9.4 mit einem Verweigerungsbescheid `ledger.anchor_refusal.v1` |

Der Verweigerungsbescheid hat genau diese Member:

| Member | Typ | Bedeutung |
|---|---|---|
| `kind` | const `"ledger.anchor_refusal.v1"` | Art des Bescheids |
| `license_commitment` | hex64 | Commitment der Lizenz (§4) |
| `appliance_id` | uuid | aus der Anfrage |
| `chain_id` | uuid | aus der Anfrage |
| `tree_size` | int, min 1 | aus der Anfrage |
| `merkle_root` | hex64 | aus der Anfrage |
| `server_ts` | rfc3339 | Ausstellungszeit nach der Serveruhr |
| `valid_until` | rfc3339 oder `null` | Ende der Laufzeit |
| `grace_until` | rfc3339 oder `null` | Ende der Kulanz |

Er sagt: Der Hersteller hat den Anker (`chain_id`, `tree_size`, `merkle_root`) der Appliance `appliance_id` zum Zeitpunkt `server_ts` geprüft und als Lückenzeugen festgehalten (§9.2), und er zeichnet ihn nicht gegen, weil die Lizenz abgelaufen ist. Er ist keine Gegensignatur: Die Appliance DARF ihn NICHT als `CHECKPOINT_RECEIPT` verketten, und ein Verifier wertet ihn nicht als Verankerung. Er ist aber eine vom Hersteller signierte Aussage über diese Wurzel zum Zeitpunkt `server_ts`: Wer ihn aufbewahrt, kann ihn einem Prüfer vorlegen, und der kann die Wurzel wie einen Lückenzeugen als erwartete Wurzel prüfen (Format-Spezifikation 11.2). Dass nach Ablauf der Lizenz eine solche übertragbare Aussage entsteht, ist gewollt: Sie ist der Lückenzeuge in der Hand des Kunden.

Die Appliance MUSS eine 403-Antwort auf einen Anker nur dann als Lizenzsperre werten, wenn ALLES zutrifft:

1. `error` ist `license_expired`, und `license` ist vorhanden.
2. Der Bescheid ist nach §9.4 Punkt 1 bis 4 wirksam, mit `kind` = `ledger.anchor_refusal.v1`.
3. `appliance_id` ist die eigene; `chain_id`, `tree_size` und `merkle_root` sind genau die des Ankers, den diese Anfrage gesendet hat.
4. `server_ts` weicht höchstens 15 Minuten von der eigenen Uhr ab.

Dann gilt der Anker als beantwortet (er ist nicht überfällig), der Status der Telemetrie zeigt die Sperre, und die Appliance KANN `tree_size` als nächste `from_tree_size` verwenden (§9.2). Trifft etwas nicht zu, ist die Antwort ein gewöhnlicher Fehlschlag: Der Anker bleibt fällig und wird nach den Regeln der Telemetrie als ausbleibend gemeldet.

**Ausnahme: Gerätegrenze am Anker (ab Fassung 1.9, Ergänzung vom 05.10.2026).** Eine 403 `appliance_limit_reached` auf einen Anker ist kein Fehlschlag, solange die Registrierung der Appliance nur vorgemerkt sein kann, also solange der Server ihren Heartbeat selbst mit `appliance_limit_reached` beantwortet oder seit dem Start der Telemetrie noch keinen ihrer Heartbeats angenommen hat (§4.1). Dann ist der Anker nicht überfällig, die Appliance verkettet nichts als `CHECKPOINT_RECEIPT`, sendet im gewohnten Takt weiter und meldet den Zustand. Hat der Server seit dem Start einen Heartbeat angenommen und den zuletzt beantworteten nicht mit `appliance_limit_reached` abgewiesen, ist die Registrierung bestätigt; dieselbe Antwort auf einen Anker ist dann ein gewöhnlicher Fehlschlag. Der Zustand endet mit jeder anderen Antwort des Servers, auch mit einer 200, deren Gegensignatur nicht trägt, nicht aber mit einem Transportfehler. Die 403 ist nicht signiert. Sie entscheidet deshalb nur, ob der Anker überfällig ist und was der Status zeigt, nie über Kette oder Quittung. In diesem Zustand meldet die Appliance für `telemetrie` nie `green`. Wer im Transportweg sitzt, kann den Zustand vortäuschen und halten, solange der Server keinen Heartbeat annimmt; sichtbar bleibt er dabei.

Was die Bindung schließt: Ein mitgeschnittener Bescheid passt nur zu dem Anker, den er beantwortet. Wer im Transportweg sitzt (etwa ein TLS-aufbrechender Firmenproxy), kann für eine neue Wurzel keinen Bescheid erzeugen und einen alten nur für genau den Anker wiederholen, auf den er schon passte. Ein ungebundener Bescheid, gleich wie frisch, hätte jeden Anker eines 15-Minuten-Fensters als „beantwortet" erscheinen lassen, während keine Wurzel den Hersteller erreichte (genau die Wurzeln, die §9.2 als Lückenzeugen braucht). Die Frischeprüfung in Punkt 4 begrenzt darüber hinaus die Wiederholung desselben Ankers. Referenzfälle: `spec/contract/anchor_refusal.json`, Ablauf mit Lückenzeugen: `spec/contract/lueckenzeuge.json`.

### 9.6 Fehlerantworten

Eine Fehlerantwort ist `{"error": <Code>, "detail": <Text>}`, bei einigen Codes mit Zusatzmembern. `detail` ist Erläuterung und wird nicht ausgewertet. Einen hier nicht genannten Code behandelt die Appliance wie jeden anderen Fehlschlag.

| HTTP | `error` | Bedeutung | Zusatzmember |
|---|---|---|---|
| 400 | `invalid_field` | Schema-Verstoß (§8) | `field` |
| 400 | `stale_heartbeat` \| `future_heartbeat` | `ts` eines Heartbeats außerhalb des Zeitfensters des Servers | - |
| 403 | `bad_signature` | Signatur ungültig (§7) | - |
| 403 | `unknown_license` | keine Lizenz zum Commitment | - |
| 403 | `license_proof_invalid` | `license_proof` trägt nicht (§4.1); ein fehlender ist HTTP 400 `invalid_field` | - |
| 403 | `edition_mismatch` | Edition passt nicht zur Lizenz | - |
| 403 | `appliance_limit_reached` | Gerätegrenze der Lizenz erreicht: auf eine Aktivierung; ab Fassung 1.9 auch auf den Heartbeat und (Ergänzung vom 05.10.2026) auf den Anker einer nur vorgemerkten Registrierung (§4.1, §9.5) | - |
| 403 | `unknown_appliance` | keine Aktivierung zu `appliance_id` | - |
| 403 | `chain_owner_mismatch` | Kette gehört einer anderen Appliance | - |
| 403 | `license_expired` | Verweigerung wegen Lizenzablauf (§9.5) | `valid_until`, `grace_until`, `license` |
| 409 | `already_registered` | `appliance_id` ist mit einem anderen Geräteschlüssel registriert (§4.1) | - |
| 409 | `fork_detected` | andere Wurzel zu einer festgehaltenen Größe (§9.2 Schritt 2 und 3) | `chain_id`, `tree_size`, `countersigned_maximum` |
| 409 | `stale_anchor` | veralteter oder wiederholter Anker unter der Bezugsgröße, kein Befund (§9.2 Schritt 2) | `chain_id`, `tree_size`, `countersigned_maximum` |
| 409 | `chain_succession_required` | neue Kette einer Appliance, die schon eine Kette mit `B > 0` hat, ohne eingetragenen Kettenwechsel (§9.2 Schritt 1) | `chain_id` |
| 409 | `consistency_required` | `from_tree_size` ist nicht die Bezugsgröße (§9.2) | `chain_id`, `tree_size`, `presented_from_tree_size`, `expected_from_tree_size` |
| 409 | `consistency_failed` | Konsistenzbeweis trägt nicht (§9.2) | `chain_id`, `tree_size`, `countersigned_maximum` |
| 429 | `rate_limited` | Anfragekontingent erschöpft | - |

`countersigned_maximum` trägt die Bezugsgröße `B`; der Name stammt aus Fassung 1.1 und schließt ab Fassung 1.8 Lückenzeugen ein.

### 9.7 Anker-Historie

Der Server gibt für jede Kette ihre **Anker-Historie** heraus (ab Fassung 1.9 normativ): alle festgehaltenen und gemeldeten Wurzeln (§9.2), signiert wie ein Bescheid (§9.4) mit `kind` = `ledger.anchor_history.v1` (Registry `cloud_statements.anchor_history`). Abgerufen wird sie ohne Anmeldung mit der `chain_id` (`GET /v1/anchors?chain_id=<uuid>`, optional `&since_tree_size=<n>`); die `chain_id` steht in jedem Prüfpaket und ist nicht zu erraten. Die Historie enthält keine personenbezogenen Daten, keine `appliance_id` und kein Commitment.

| Member | Typ | Bedeutung |
|---|---|---|
| `kind` | const `"ledger.anchor_history.v1"` | Art des Bescheids |
| `chain_id` | uuid | die Kette |
| `predecessor` | object oder `null` | eingetragener Kettenwechsel (§9.2 Schritt 1): `chain_id` der Vorgängerkette und die dort übergebene `tree_size` |
| `successor` | object oder `null` | eingetragener Nachfolger: dessen `chain_id` und die aus dieser Kette übergebene `tree_size` |
| `reference_tree_size` | int, min 0 | die Bezugsgröße `B` |
| `roots` | array | je Wurzel: `tree_size`, `merkle_root`, `recorded_as` (`countersigned` \| `gap_witness` \| `reported`), `server_ts`; aufsteigend nach `tree_size`, bei gleicher Größe nach Zeit |
| `forks` | array | je Fork-Befund: `tree_size`, `merkle_root`, `detected_ts` |
| `since_tree_size` | int, min 0 | aus der Anfrage; nur Wurzeln ab dieser Größe |
| `truncated` | bool | `true`: weitere Wurzeln folgen; die nächste Anfrage setzt `since_tree_size` höher |
| `server_ts` | rfc3339 | Ausstellungszeit nach der Serveruhr |

Ein Prüfer, der die Vollständigkeit eines Pakets belegen will (Format-Spezifikation 8.6, 11.2),

1. holt die Historie selbst beim Hersteller ab, nicht über das geprüfte Haus (das kann sie zurückhalten, aber nicht verändern, und ihr Fehlen ist dann selbst eine Auskunft);
2. prüft sie nach §9.4 Punkt 1 bis 3 (JCS-Form, Member, Signatur gegen die Herstellerwurzel oder einen angehefteten Schlüssel; ein Commitment trägt sie nicht);
3. verlangt, dass `server_ts` nach der Anforderung des Pakets liegt, und liest alle Seiten;
4. übergibt jede Wurzel der Historie, deren `server_ts` vor der Anforderung des Pakets liegt, als erwartete Wurzel `<tree_size>:<merkle_root>` (Format-Spezifikation 10.8), gegengezeichnete, Lückenzeugen und gemeldete gleichermaßen. Enthält das Paket eine davon nicht, fehlen ihm Einträge, die die Appliance vor seiner Anforderung schon hatte, oder es widerspricht ihnen: `MERKLE_INCONSISTENT`. Trifft das nur Wurzeln aus den letzten 15 Minuten vor der Anforderung (Uhren, Anker unterwegs), fordert der Prüfer das Paket neu an, statt es als gekürzt zu werten;
5. holt bei einem eingetragenen Kettenwechsel auch die Historie der anderen Kette; nennt ein `GENESIS` eine Vorgängerkette (Format-Spezifikation 4.1), ebenso. Für eine Vorgängerkette ist die übergebene `tree_size` ihr Ende; eine dort festgehaltene Wurzel dahinter ist ein Widerspruch.

Die Historie ist keine Gegensignatur und kein Anker im Sinn der Format-Spezifikation; ein Verifier wertet sie nicht aus. Sie liefert dem Prüfer die erwarteten Wurzeln, die der Verifier dann prüft.

### 9.8 Aktivierungsquittung

Ab Fassung 1.9 trägt jede 200-Antwort auf eine Aktivierung (die erste, eine wörtliche Wiederholung und eine Umbindung) im Member `activation_receipt` eine Aktivierungsquittung. Sie reist als Objekt nach §9.4 (`statement_jcs`, `server_key_id`, `server_signature`, `statement`) mit `kind` = `ledger.activation_receipt.v1` (Registry `cloud_statements.activation_receipt`) und hat genau diese Member:

| Member | Typ | Bedeutung |
|---|---|---|
| `kind` | const `"ledger.activation_receipt.v1"` | Art der Quittung |
| `appliance_id` | uuid | aus der Aktivierung |
| `device_pubkey` | hex64 | aus der Aktivierung |
| `license_commitment` | hex64 | Commitment, unter dem der Hersteller diese Registrierung zum Zeitpunkt `server_ts` führt |
| `server_ts` | rfc3339 | Ausstellungszeit nach der Serveruhr, Form wie §9.4 Punkt 2 |

Sie sagt: Der Hersteller führt zum Zeitpunkt `server_ts` die Registrierung von `appliance_id` mit diesem Geräteschlüssel unter diesem Commitment. Das ist eine Zustandsaussage, keine Antwort auf genau eine Anfrage: Eine Aktivierung trägt weder Zeit noch Einmalwert, und eine wörtliche Wiederholung erhält eine Quittung derselben Aussage. Die Quittung beweist deshalb weder den Besitz des Lizenzschlüssels noch, dass die Appliance lebt; wer ein Prüfpaket hält, kann durch Wiederholen der verketteten Aktivierung eine neue erhalten.

Wirksam ist sie, wenn der Empfänger §9.4 Punkt 1 bis 4 bestätigt: JCS-Form, genau diese Member mit diesen Typen und `kind` wie oben, Schlüssel und Signatur, und `license_commitment` ist das des hinterlegten Schlüssels. Für die Annahme einer Umbindung verlangt §4.1 zusätzlich die eigene `appliance_id`, den eigenen `device_pubkey` und die Frische. Eine Quittung wird nicht wie ein Bescheid gehalten; die Regel gegen ältere Bescheide (§9.4) gilt für sie nicht. Sie wird nicht verkettet, und ein Verifier wertet sie nicht aus. Referenzfälle: `spec/contract/activation_receipt.json`.

## 10. Stille-Alarm: Erwartungstabelle

Bleibt der stündliche Heartbeat einer aktivierten Appliance aus, alarmiert die Cloud nach fester Tabelle. Maßgeblich ist die Zeit seit dem letzten gültigen (signaturgeprüften) Heartbeat dieser `appliance_id`:

| Stille-Dauer | Mail-Verhalten | Empfänger |
|---|---|---|
| < 3 h | **genau 0** Mails | - |
| ≥ 3 h | **genau 1** Stille-Mail (keine Wiederholung) | [Kundenkontakt aus dem Lizenz-Datensatz, Hersteller] |
| ≥ 24 h | **genau 1** zusätzliche Eskalations-Mail (keine Wiederholung) | [Kundenkontakt aus dem Lizenz-Datensatz, Hersteller-Eskalationsliste] |

Pro Stille-Episode werden also maximal zwei Mails versendet. Ein wieder eintreffender gültiger Heartbeat beendet die Episode; eine spätere neue Stille beginnt eine neue Episode. Die Testerwartung (Mailhog-Assert) prüft exakt gegen diese Tabelle.

### 10.1 Betreffmuster

Betreffzeilen sind fest, sprachneutral und maschinell prüfbar; der Mail-Text ist in der Lizenzsprache (`language`) lokalisiert.

| Stufe | Betreff (exakt) |
|---|---|
| 3 h | `[LEDGER] HEARTBEAT-STILLE 3H <appliance_id>` |
| 24 h | `[LEDGER] HEARTBEAT-STILLE 24H-ESKALATION <appliance_id>` |

Prüf-Regex: `^\[LEDGER\] HEARTBEAT-STILLE (3H|24H-ESKALATION) [0-9a-f-]{36}$`

## 11. Alarm-Kontaktadresse: Herkunft und Anzeige

Die Empfängeradresse der Stille-Mails stammt aus dem **Lizenz-Datensatz** beim Hersteller (angelegt beim Kauf, aktualisierbar durch den Kunden). Sie ist das **einzige personenbezogene Datum in der Cloud**: Der Metadatenserver speichert darüber hinaus nur Zählwerte, Enums und 32-Byte-Roots, und es existiert kein Kunden-Login in der Cloud. Das Portal der Appliance zeigt diese Adresse als „bei der Cloud hinterlegte Alarmadresse" an, damit der Kunde jederzeit sieht, wohin im Stille-Fall alarmiert würde. Im Air-Gap-/Egress-aus-Modus ist der Cloud-Stille-Alarm nicht aktiv; das Portal weist dies ausdrücklich aus.
