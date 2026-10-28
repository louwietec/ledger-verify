# LEDGER-Verifier

[English](README.md)

Dieses Repository enthält die offene Spezifikation, die Testvektoren und zwei
unabhängige Verifier für LEDGER-Beweisketten (LEDGER hieß früher „Rekorder“;
Hersteller ist LOUWIETEC). Mit den Dateien hier kann jeder ein
LEDGER-Prüfpaket selbst prüfen: offline, ohne Zutun des Herstellers, ohne Konto
und ohne Geheimnis.

| Pfad | Inhalt |
|---|---|
| `spec/` | die normative Spezifikation (`format.de.md`, `format.en.md`, spec_version 1.10), die maschinenlesbare Registry `registry.json`, JSON-Schemas und die Testvektoren |
| `verifier/` | der freie Verifier in Go (nur Standardbibliothek), als Kommandozeilenwerkzeug und als Browser-Seite in einer Datei |
| `verifier2/` | ein unabhängiger Zweitverifier in Python 3 (nur Standardbibliothek), allein aus der Spezifikation gebaut |
| `tools/` | `bauen.sh` (der reproduzierbare Bau), `aequivalenz.sh` (beide Verifier über alle Testvektoren), `pruefen.sh` (prüft ein Release so, wie es ein Dritter tut) |

## 1. Herunterladen und Signatur prüfen

Jedes Release auf der Release-Seite dieses Repositorys enthält:

- `ledger-verify_<version>_<os>_<arch>`: den Kommandozeilen-Verifier für
  `linux_amd64`, `linux_arm64`, `darwin_amd64`, `darwin_arm64` und
  `windows_amd64` (`.exe`);
- `ledger-verify_<version>.html`: die Browser-Seite (Abschnitt 5);
- `ledger-verify_<version>_source.tar.gz`: dieses Repository im Stand des
  Release-Tags, samt Testvektoren;
- `SHA256SUMS`: die SHA-256-Prüfsummen aller dieser Dateien;
- `SHA256SUMS.sig`: die OpenSSH-Signatur des Herstellers über `SHA256SUMS`
  (Namensraum `file`);
- `allowed_signers`: den Release-Schlüssel des Herstellers im OpenSSH-Format.

Geprüft wird die Signatur mit `ssh-keygen`. Es gehört zum OpenSSH-Client, den
Linux, macOS und Windows 10/11 schon mitbringen. Nötig ist OpenSSH 8.1 oder
neuer (`ssh -V`).

**Vor allem der Fingerabdruck.** Der Schlüssel in `allowed_signers` muss der
Release-Schlüssel des Herstellers sein. Vergleichen Sie seinen Fingerabdruck
mit dem, den LOUWIETEC auf louwietec.com und im Prüferleitfaden
veröffentlicht. Ohne diesen Vergleich beweist eine gültige Signatur nur, dass
`SHA256SUMS` zu *irgendeinem* Schlüssel passt. Erst der Vergleich zeigt, dass
es der Schlüssel des Herstellers ist.

### Linux und macOS

```sh
V=1.1.0-entwurf        # die Version des Releases
P=linux_amd64      # oder linux_arm64, darwin_amd64, darwin_arm64
R=https://github.com/louwietec/ledger-verify/releases/download/v$V
for f in SHA256SUMS SHA256SUMS.sig allowed_signers ledger-verify_${V}_$P ledger-verify_${V}_source.tar.gz; do
  curl -fsSLO "$R/$f"
done

# 1) Fingerabdruck des Signaturschlüssels: mit dem veröffentlichten vergleichen
awk 'NR==1{print $3, $4}' allowed_signers > release.pub && ssh-keygen -lf release.pub

# 2) Signatur über SHA256SUMS, NUR gegen den Schlüssel aus Schritt 1 geprüft, nie gegen die
#    mitgelieferte allowed_signers (eine Zeile darin kann einen Schlüssel zeigen und einen
#    anderen prüfen lassen); erwartet: Good "file" signature for release@louwietec.com with ED25519 key
#    <Fingerabdruck aus Schritt 1>
printf '%s namespaces="file" %s\n' release@louwietec.com "$(cat release.pub)" > geprueft_allowed_signers
ssh-keygen -Y verify -f geprueft_allowed_signers -I release@louwietec.com -n file -s SHA256SUMS.sig < SHA256SUMS

# 3) Prüfsummen der geladenen Dateien (macOS: shasum -a 256 -c --ignore-missing SHA256SUMS)
sha256sum -c --ignore-missing SHA256SUMS

chmod +x ledger-verify_${V}_$P && ./ledger-verify_${V}_$P --version
```

Unter macOS trägt eine mit `curl` geladene Datei keine Quarantäne-Markierung.
Eine im Browser geladene Datei trägt sie, und
`xattr -d com.apple.quarantine <datei>` entfernt sie.

**Alles in einem Schritt.** Legen Sie alle Release-Dateien in ein Verzeichnis.
`tools/pruefen.sh` macht dann die Schritte 1 bis 3 über alle Dateien. Danach
prüft es die Beispielketten aus Abschnitt 2 offline mit dem Binary für Ihren
Rechner:

```sh
bash tools/pruefen.sh <verzeichnis> <vom Hersteller veröffentlichte allowed_signers-Zeile, als Datei> SHA256:<veröffentlichter Fingerabdruck>
```

`tools/pruefen.sh` liegt in diesem Repository und im Quellarchiv. Es ist kurz
genug, um es vor dem Ausführen zu lesen. Die letzte Zeile lautet
`ERGEBNIS: GRUEN` oder `ERGEBNIS: ROT`, danach die Einzelheiten. Schon ein geändertes Byte
in `SHA256SUMS`, in der Signatur oder in einer Release-Datei macht sie ROT.

### Windows (PowerShell)

```powershell
$V = "1.1.0-entwurf"
$R = "https://github.com/louwietec/ledger-verify/releases/download/v$V"
foreach ($f in "SHA256SUMS", "SHA256SUMS.sig", "allowed_signers",
               "ledger-verify_${V}_windows_amd64.exe", "ledger-verify_${V}_source.tar.gz") {
  Invoke-WebRequest -Uri "$R/$f" -OutFile $f
}

# 1) Fingerabdruck des Signaturschlüssels: mit dem veröffentlichten vergleichen
$k = (Get-Content allowed_signers -TotalCount 1).Split(" ")
"$($k[2]) $($k[3])" | Set-Content -Encoding ascii release.pub
ssh-keygen -lf release.pub

# 2) Signatur, NUR gegen den Schlüssel aus Schritt 1 geprüft (nie gegen die mitgelieferte
#    allowed_signers); über cmd, damit SHA256SUMS byte-genau bei ssh-keygen ankommt
[IO.File]::WriteAllText("$PWD\geprueft_allowed_signers", "release@louwietec.com namespaces=`"file`" $($k[2]) $($k[3])`n")
cmd /c "ssh-keygen -Y verify -f geprueft_allowed_signers -I release@louwietec.com -n file -s SHA256SUMS.sig < SHA256SUMS"

# 3) Prüfsummen der geladenen Dateien
Get-Content SHA256SUMS | ForEach-Object {
  $h, $f = $_ -split "  ", 2
  if (Test-Path $f) {
    if ((Get-FileHash -Algorithm SHA256 $f).Hash -eq $h) { "OK      $f" } else { "FALSCH  $f" }
  }
}

.\ledger-verify_${V}_windows_amd64.exe --version
```

## 2. Beispielketten offline prüfen

Das Quellarchiv enthält die Testvektoren und die Vertrauensanker des
**Test**herstellers. Das sind Testschlüssel, nie die eines Herstellers im
Betrieb. Zwei Beispielketten zeigen beide Ausgänge:

```sh
tar -xzf ledger-verify_${V}_source.tar.gz
TV=ledger-verify-$V/spec/testvectors
A="--vendor-root $TV/pruefer_herstellerwurzel.json --vendor-key $(cat $TV/pruefer_herstellerschluessel.txt)"
./ledger-verify_${V}_$P --lang de --now-from-package $A $TV/valid_sealed_export   # Exit 0: gültig, ordnungsgemäß versiegelt
./ledger-verify_${V}_$P --lang de --now-from-package $A $TV/tamper_content_unpaired   # Exit 2: CONTENT_MISMATCH
```

```powershell
tar -xzf "ledger-verify_${V}_source.tar.gz"
$TV = "ledger-verify-$V\spec\testvectors"
$K = Get-Content "$TV\pruefer_herstellerschluessel.txt" -TotalCount 1
.\ledger-verify_${V}_windows_amd64.exe --lang de --now-from-package --vendor-root "$TV\pruefer_herstellerwurzel.json" --vendor-key $K "$TV\valid_sealed_export"; $LASTEXITCODE
.\ledger-verify_${V}_windows_amd64.exe --lang de --now-from-package --vendor-root "$TV\pruefer_herstellerwurzel.json" --vendor-key $K "$TV\tamper_content_unpaired"; $LASTEXITCODE
```

`--now-from-package` gilt nur für die eingefrorenen Testvektoren. Der Schalter
nimmt die Prüfzeit aus der paketeigenen `verify_args.json`, und diese Datei
wählt, wer das Paket vorlegt. Bei einem echten Paket lassen Sie ihn weg (dann
gilt die Systemuhr) oder geben `--now <RFC 3339>` an.

Nach seinen Übersichtszeilen zeigt der Bericht zu `valid_sealed_export` drei
Blöcke: Herstellerprotokoll und Anker-Historie („nicht übergeben“, weil das
Beispiel beides nicht übergibt) und die Beweisstufe, hier „2 von 3
(gegengezeichnet)“ mit dem Hinweis, dass sie auf einem veröffentlichten
Testschlüssel beruht. Abschnitt 3 erklärt diese Blöcke.

**Offline.** Der Verifier braucht kein Netz und öffnet keine Verbindung. Er
liest ein Paket (Verzeichnis oder ZIP) und schreibt einen Bericht. Kopieren
Sie Binary und Paket auf einen Rechner ohne Netz, oder trennen Sie vorher die
Verbindung. Unter Linux lässt `unshare -rn ./ledger-verify_${V}_$P …` ihn in einem
Netz-Namensraum ohne Netz laufen, und genau so macht es `tools/pruefen.sh`,
wo das geht.

## 3. Den Verifier ausführen

```
ledger-verify [Schalter] <Prüfpaket: Verzeichnis oder ZIP>
```

| Schalter | Wirkung |
|---|---|
| `--lang de\|en` | Sprache des Prüfberichts (Vorgabe `en`) |
| `--json` | maschinenlesbare Ausgabe `{valid, status, exit_code, findings, stats}` |
| `--now RFC3339` | Prüfzeitpunkt, UTC mit `Z` (z. B. `2026-01-01T12:00:00Z`); Vorgabe ist die Systemuhr |
| `--freshness DAUER` | Frischefenster für `TRAILING_SILENCE` (Spezifikation 8.5, 10.8): eine ganze Zahl von 1 bis 999999, direkt gefolgt von `h`, `m` oder `s`, etwa `24h` oder `90m`; Vorgabe `24h`; höchstens einmal |
| `--vendor-root DATEI` | Wurzelschlüssel des Herstellers `{"wurzel_id", "pubkey"}` (Spezifikation 7.1, 10.7); wiederholbar |
| `--vendor-key ID=HEX` | heftet einen Gegenzeichnungsschlüssel des Herstellers an (Spezifikation 7.1, 10.7.4); wiederholbar |
| `--vendor-key-list DATEI` | eine Schlüsselliste des Herstellers: Rollenliste, Protokollschlüsselliste oder Liste der Gegenzeichnungsschlüssel (Spezifikation 10.7, 7.4.7); wiederholbar |
| `--vendor-statement-key ID=HEX` | heftet einen Bescheidschlüssel an, den Schlüssel der Seiten der Anker-Historie (Spezifikation 8.8.3, 10.7.4); wiederholbar |
| `--vendor-log-key ID=HEX` | heftet einen Protokollschlüssel des Herstellerprotokolls an (Spezifikation 7.4.10); wiederholbar |
| `--vendor-log DATEI` | ein Auszug `ledger-protokollauszug/1` des Herstellerprotokolls (Spezifikation 7.4.8); wiederholbar |
| `--anchor-history DATEI` | Seiten `ledger.anchor_history.v2` oder eine Datei `ledger-ankerhistorie/2` (Spezifikation 8.8.2); wiederholbar |
| `--requested-at RFC3339` | wann Sie das Paket angefordert haben (Spezifikation 8.8.1, 10.8); höchstens einmal |
| `--expect-root [TREE_SIZE:]ROOT` | erwartete Merkle-Wurzel, 64 Hex-Zeichen, wahlweise mit ihrer `tree_size` (Spezifikation 7.2, 8.6, 10.8); wiederholbar |
| `--tsa-root DATEI` | PEM-Wurzeln für Zeitzeugen der Kette (Spezifikation 7.3, 10.8); wiederholbar; der Wurzelspeicher des Systems zählt für keinen Zweck |
| `--vendor-log-tsa-root DATEI` | PEM-Wurzeln für die Zeitstempel des Herstellerprotokolls (Spezifikation 7.4.6, 10.8); wiederholbar |
| `--tsa-qualified-roots DATEI` | Ihre Datei `ledger-tsa-qualifiziert/1` mit den Wurzeln, die Sie als qualifiziert benennen (Spezifikation 10.8); höchstens einmal |

**Wie ein Aufruf aussieht** (ab Verifier 1.1.0). Jeder Schalter steht vor
dem Paket und beginnt mit zwei Bindestrichen; `--` beendet die Schalter. Ein
Schalter ohne Wert (`--json`, `--now-from-package`) nimmt keinen; ein
Schalter mit Wert nimmt ihn als `--lang de` oder `--lang=de`, und der Wert
ist das folgende Argument, auch wenn es mit einem Bindestrich beginnt. Ein
Paket, dessen Name mit einem Bindestrich beginnt, steht hinter `--`. Jede
andere Form, etwa `-json`, `--json=true`, ein Schalter oder ein `--` nach
dem Paket, eine Abkürzung oder ein unbekannter Schalter, ist ein
unbrauchbarer Aufruf: Exit 3, die Begründung auf der Fehlerausgabe, kein
Bericht (Spezifikation 10.8). Exit 3 ist es auch, wenn sich die Ausgabe
nicht schreiben lässt, etwa auf einen vollen Datenträger. Eine Datei, für
die die Spezifikation keine Grenze nennt (PEM-Wurzeln, Herstellerwurzel),
liest der Verifier bis 33 554 432 Bytes; eine größere ist ebenfalls Exit 3.
verifier2 (Abschnitt 6) liest jeden Aufruf genauso, und die Sprache des
Berichts ist in beiden `en`, solange Sie nicht `--lang de` übergeben.

`--help` (oder `-h`) zeigt alle Schalter auf der Fehlerausgabe und endet mit
Exit 3, ein Bedienfehler nach Spezifikation 10.8. `--version`, ohne weiteres
Argument, nennt die Version und die Spezifikation, die der Verifier umsetzt;
die zweite Zeile sagt, ob eine Herstellerwurzel eingebaut ist. `ledger-verify
zeitstempel --token DATEI (--data DATEI | --statement-jcs DATEI)
[--tsa-root DATEI]...` prüft ein einzelnes RFC-3161-Zeitstempel-Token gegen
Wurzeln, die Sie übergeben (Spezifikation 7.5); für seine Schalter gelten
dieselben Regeln.

### Was der Verifier ab Spezifikation 1.10 prüft

Außer der Kette selbst (Hash-Verkettung, Merkle-Baum, Signaturen, Lücken,
Kettenende) prüft der Verifier, was Sie ihm von außerhalb des Pakets geben:

- **Schlüsselrollen** (Spezifikation 10.7.2 bis 10.7.4). Der Hersteller
  signiert mit Schlüsseln dreier Rollen: Gegenzeichnungsschlüssel für
  Quittungen, Bescheidschlüssel für die Seiten der Anker-Historie,
  Protokollschlüssel für das Herstellerprotokoll. Die signierte Rollenliste
  `ledger-schluesselrollen/1` nennt sie. Ein Schlüssel einer Rolle belegt nie
  ein Objekt einer anderen, und der Bericht führt die Rollen unter
  `key_roles`.
- **Herstellerprotokoll** (Spezifikation 7.4). Für jeden abgeschlossenen
  UTC-Tag legt sich der Hersteller mit einem signierten Tageseintrag auf alle
  seine Gegenzeichnungen und Lückenzeugen fest, und Zeitstempelstellen
  bezeugen diesen Eintrag. Mit Ihren Auszügen zeigt der Verifier, ob jede
  Quittung des Pakets in einem bezeugten Tag steht (sonst
  `RECEIPT_NOT_LOGGED`) und ob eine dort festgehaltene Wurzel dem Paket
  widerspricht (`LOGGED_ROOT_MISMATCH`).
- **Anker-Historie und Verbundenheit** (Spezifikation 8.8). Die signierten
  Seiten des Herstellers nennen jede Wurzel der Kette, die er gegengezeichnet,
  als Lückenzeugen festgehalten oder von der Appliance gemeldet bekommen hat.
  Mit dem Anforderungszeitpunkt, den Sie übergeben, wird jede Wurzel, die mehr
  als 15 Minuten vor Ihrer Anforderung festgehalten war, zur erwarteten
  Wurzel: Fehlt sie dem Paket oder widerspricht es ihr, meldet der Verifier
  `MERKLE_INCONSISTENT` (Exit 2), bei einer Wurzel, die dem Hersteller bloß
  gemeldet wurde, `ANCHOR_HISTORY_FORK` (Exit 1). Dieselben Seiten tragen die
  signierte Angabe des Herstellers, ob ein Kunde der Kette mit ihm verbunden
  ist (Heartbeat-Spezifikation §9.10). Der Verifier prüft Signatur, Form,
  Bindung an Kette und Gerät und Frische dieser Angabe, nicht ob sie wahr ist
  (kein Beleg durch LEDGER).
- **Beweisstufe 0 bis 3** (Spezifikation 10.9). Sie fasst zusammen, welche
  Anker der Verifier mit Ihren Angaben bestätigen konnte und bis zu welcher
  `seq` sie reichen: 0 Selbstauskunft, 1 extern gebunden (ein Zeitzeuge oder
  eine erwartete Wurzel), 2 gegengezeichnet (eine Quittung unter einem
  Schlüssel, den Ihr Anker bestätigt), 3 verankert und abgeglichen (dazu ein
  Zeitstempel einer vom Prüfer als qualifiziert benannten Stelle, Quittungen
  in bezeugten Tagen des Herstellerprotokolls nachgewiesen und Vollständigkeit
  nach einer Anker-Historie, die nach Ihrer Anforderung ausgestellt wurde).
  Der Bericht nennt, was für die nächste Stufe fehlt, und den Schalter, der
  es übergeben würde. Die Beweisstufe ist kein Befund, ändert nie den
  Exit-Code und ist keine rechtliche Einordnung.

Ohne diese Angaben lautet jeder der Blöcke „nicht übergeben“ oder „nicht
geprüft“ und fügt keinen Befund hinzu.

### Angaben des Prüfers übergeben (Spezifikation 10.8)

Keine dieser Angaben kommt aus dem Paket, und keine nehmen Sie vom geprüften
Haus: Holen Sie sie selbst an den beiden Veröffentlichungsorten des
Herstellers, bei seinem Metadatenserver oder beim Betreiber jeder
Zeitstempelstelle ab, und notieren Sie, wann Sie das Paket angefordert haben.
Woher jede Angabe kommt, nennt der Prüferleitfaden in Abschnitt 10. Der
Verifier liest jede Angabe, bevor er das Paket öffnet; eine Angabe, die ihre
Grammatik verletzt, ist ein unbrauchbarer Aufruf (Exit 3 mit Begründung, ohne
Bericht).

```sh
./ledger-verify_${V}_$P --lang de --json \
  --vendor-root herstellerwurzel.json \
  --vendor-key-list rollenliste.json --vendor-key-list keys.json \
  --anchor-history seite-0.json --anchor-history seite-1.json \
  --vendor-log auszug.json \
  --vendor-log-tsa-root log-tsa.pem --tsa-root ketten-tsa.pem \
  --tsa-qualified-roots qualifiziert.json \
  --requested-at 2026-11-02T09:30:00Z \
  pruefpaket.zip > befunde.json
```

Lassen Sie weg, was Sie nicht haben; jede fehlende Angabe nennt der Bericht.
In der JSON-Ausgabe stehen die Ergebnisse unter `stats.key_roles`,
`stats.vendor_log`, `stats.anchor_history`, `stats.affiliation` und
`stats.evidence_level`.

### Vertrauensanker: `--vendor-root` und `--vendor-key` (Spezifikation 7.1, 10.7)

Ein Prüfpaket schreibt genau das Haus, das die Gegenzeichnungen des
Herstellers binden sollen. Ein Herstellerschlüssel aus dem Paket beweist
deshalb allein nichts, und der Vertrauensanker muss von **Ihnen** kommen:

- `--vendor-root DATEI` ist der Wurzelschlüssel des Herstellers, der mit der
  Lizenz veröffentlicht wird. Über die signierte Liste
  `keys/vendor/schluesselliste.json` im Paket oder über die Schlüssellisten,
  die Sie übergeben, bürgt er für die Schlüssel des Herstellers.
- `--vendor-key ID=HEX` heftet einen einzelnen Gegenzeichnungsschlüssel an,
  den Sie selbst beim Hersteller erfragt haben.

Ohne beides meldet der Verifier Quittungen als `RECEIPT_UNVERIFIED` (Exit 1).
Ihre Signaturen sind stimmig, aber ihr Schlüssel kommt aus dem Paket.

**Die Release-Binaries tragen die Herstellerwurzel von LOUWIETEC eingebaut**;
`--version` nennt sie in der zweiten Zeile. Prüfen Sie sie unabhängig vom
Binary: Laden Sie die Wurzel-Datei und ihren Fingerabdruck von louwietec.com
(HTTPS) und übergeben Sie die Datei mit `--vendor-root`. Stimmt sie mit der
eingebauten überein, ändert sich am Urteil nichts. Weicht sie ab, verweigert
der Verifier die Prüfung (Exit 3), statt eine der beiden zu wählen
(Spezifikation 7.1). Ein getauschtes Binary kann seine eingebaute Wurzel also
nicht an Ihnen vorbeischmuggeln.

### Erwartete Wurzeln: `--expect-root` (Spezifikation 7.2, 8.6)

Ein Paket kann aus sich heraus nicht beweisen, dass nach seinem letzten
Eintrag nichts mehr kam. Offline sehen eine unvollständige Kette (Exit 4) und
eine Kette, die direkt hinter einem früheren Siegel abgeschnitten wurde,
gleich aus. Sicherheit gibt erst der Abgleich. Ab Spezifikation 1.10 leistet
ihn die Anker-Historie mit `--requested-at` für jede Wurzel, die der
Hersteller mehr als 15 Minuten vor Ihrer Anforderung festgehalten hat. Eine Wurzel, die Sie auf
anderem Weg kennen, etwa eine im Monatsbericht abgedruckte (Papier-Anker,
Spezifikation 7.2), übergeben Sie mit `--expect-root <merkle_root>` oder
`--expect-root <tree_size>:<merkle_root>`. Fehlen dem Paket Einträge, die zu
ihr gehören, meldet der Verifier `MERKLE_INCONSISTENT` (Exit 2). Machen Sie
den Abgleich auch bei versiegelten Ketten. verifier2 nimmt beide Formen
ebenso.

### Ehrliche Grenzen

Der Verifier belegt nicht mehr, als seine Angaben tragen. Einträge nach dem
letzten gegengezeichneten Checkpoint (das Restfenster) sind noch nicht
verankert und erreichen nie Stufe 3. Ob eine Herstellerwurzel, ein
angehefteter Schlüssel oder eine Wurzel einer Zeitstempelstelle wirklich von
außerhalb des geprüften Hauses stammt, kann der Verifier nicht erkennen; der
Bericht nennt die Fingerabdrücke, auf denen die Stufe beruht. Handeln
Hersteller und Kunde zusammen, können sie zu einer gekürzten Kette eine
passende Anker-Historie ausstellen. Die Angabe zur Verbundenheit ist die des
Herstellers selbst, und wer Historie und Protokoll abholt, verrät dem
Hersteller, welche Kette wann geprüft wird. Die Kette zeigt Existenz, Zeit,
Reihenfolge und Unversehrtheit, nicht, dass der Inhalt eines Aufrufs richtig
war. Abschnitt 11.2 der Spezifikation nennt jede Grenze vollständig.

## 4. Exit-Codes (Spezifikation 10.3)

| Exit | Bedeutung |
|---|---|
| 0 | gültig ohne Befunde |
| 1 | gültig mit Befunden |
| 2 | ungültig |
| 3 | Formatfehler (auch: unbrauchbarer Aufruf) |
| 4 | unvollständig: Kettenende nicht versiegelt (Spezifikation 8.6) |

Treffen mehrere Befunde zu, entscheidet die Rangfolge: 3 vor 2 vor 4 vor 1
vor 0. Die Größe der Zahl entscheidet nicht. Exit 0 und Exit 1 setzen ein
versiegeltes Kettenende voraus. Exit 4 ist kein Fehlschlag: die vorhandenen
Einträge sind intakt, nur belegt das Paket nicht, dass nach ihnen nichts mehr
kam. Exit 1 ist ein gutes Ergebnis, denn eine ehrlich ausgewiesene Lücke macht
die Kette nicht ungültig. Eine verschwiegene schon.

## 5. Die Browser-Seite

`ledger-verify_<version>.html` ist derselbe Go-Verifier, nach WebAssembly übersetzt
und in einer Datei. Er ist keine zweite Implementierung. Vergleichen
Sie die Prüfsumme mit `SHA256SUMS`, öffnen Sie die Datei per Doppelklick (das
geht auch ohne Netz) und ziehen Sie das Prüfpaket auf die Seite.

Unter „Weitere Prüfangaben“ wählen Sie die Angaben des Prüfers aus
Abschnitt 3 als Dateien oder Felder, mit denselben Regeln wie auf der
Kommandozeile: die Herstellerwurzel, Schlüssellisten samt Rollenliste,
angeheftete Schlüssel, Dateien der Anker-Historie, Auszüge des
Herstellerprotokolls, PEM-Wurzeln für Zeitzeugen und für die Zeitstempel des
Herstellerprotokolls, Ihre Datei der als qualifiziert benannten Wurzeln,
erwartete Wurzeln, den Prüfzeitpunkt und den Anforderungszeitpunkt. Eine
Angabe, die ihre Grammatik verletzt, ergibt eine Fehlermeldung statt eines
Urteils. Unter dem Urteil zeigt die Seite dann zwei Zeilen: die Beweisstufe
mit ihrer Reichweite (etwa „Beweisstufe: 2 von 3, belegt bis seq 309 von
311“) und den Stand der Verbundenheit mit dem Hersteller. Die Farbe des
Urteils bleibt an den Exit-Code gebunden; die Beweisstufe färbt nichts
(Spezifikation 10.10.3). Wer die Seite einbettet, übergibt dieselben Angaben
als Optionen (Spezifikation 10.8).

Paket und Angaben verlassen Ihren Rechner nicht, und die Seite lädt nichts
nach und sendet nichts; auch die Angaben holt sie nicht selbst, Sie laden sie
vorher herunter. Das können Sie selbst nachprüfen; jede Zeile soll 0 zeigen:

```sh
for m in 'fetch(' XMLHttpRequest WebSocket sendBeacon EventSource importScripts; do
  printf '%-16s %s\n' "$m" "$(grep -c -F "$m" ledger-verify_${V}.html)"
done
```

## 6. verifier2: die unabhängige Zweitimplementierung

`verifier2/verifier2.py` ist in Python 3 mit der Standardbibliothek
geschrieben. Er entstand allein aus der Spezifikation und teilt keine Zeile
mit dem Go-Verifier. `tools/aequivalenz.sh` schickt beide Verifier über jeden
Testvektor. Von jedem verlangt es das erwartete Urteil, mit demselben
Exit-Code, denselben Befundklassen, demselben Status und demselben
Kettenende. verifier2 läuft dabei in einem Verzeichnis, das nur `spec/` und
`verifier2/` enthält. Die CI dieses Repositorys fährt den Lauf bei jeder
Änderung. verifier2 nimmt die Angaben des Prüfers aus Abschnitt 3 unter
denselben Schalternamen und liest jeden Aufruf wie `ledger-verify` (Abschnitt 3).
Einen eigenen Schalter hat er: `--registry DATEI`, die Registry, die er
liest, ohne Angabe `spec/registry.json` neben ihm. Dieser Schalter ist keine
Angabe des Prüfers und ändert keine Regel der Spezifikation; `ledger-verify` trägt
die Registry eingebaut und weist den Schalter ab.

```sh
python3 verifier2/verifier2.py --now-from-package \
  --vendor-root spec/testvectors/pruefer_herstellerwurzel.json \
  --vendor-key "$(cat spec/testvectors/pruefer_herstellerschluessel.txt)" \
  spec/testvectors/valid_sealed_export
```

## 7. Spezifikation und Testvektoren

- `spec/format.de.md` / `spec/format.en.md` beschreiben das Kettenformat, den
  Prüfablauf, die Exit-Codes, die Befundklassen, das Angreifermodell und die
  Beweisgrenzen (Abschnitt 11.2). `spec/registry.json` ist die
  maschinenlesbare Referenz und geht bei Abweichung vor.
- `spec/heartbeat.*.md` beschreibt die Nachrichten zwischen Appliance und
  Herstellerserver (Aktivierung, Heartbeat, Anker) und ab Spezifikation 1.10,
  was der Hersteller für Prüfer veröffentlicht: die Anker-Historie mit der
  Angabe zur Verbundenheit, das Herstellerprotokoll und seine beiden
  Veröffentlichungsorte.
- `spec/pflichten.*.md` ist die Pflichten-Deckungstabelle. Sie zeigt, bei
  welchen Betreiberpflichten die Kette die Erfüllung mit Belegen unterstützt.
  Sie ist keine Rechtsberatung.
- `spec/testvectors/` enthält die eingefrorenen Testvektoren, jeder mit
  seinem erwarteten Urteil unter `expected/<name>.json`. Jede Datei ist in
  `PINS.sha256` gepinnt, und `spec/testvectors/README.de.md` erklärt den
  Korpus. Die Urteile gelten für die Prüfumgebung des Korpus (Wurzel und
  Schlüssel des Testherstellers, wie in Abschnitt 2). Ab Spezifikation 1.10
  kann ein Vektor zusätzlich eine eigene Prüfumgebung tragen,
  `pruefer_<name>.json` (`ledger-pruefumgebung/1`), mit Angaben des Prüfers
  wie einem Auszug des Herstellerprotokolls oder einer Anker-Historie; seine
  Solldatei nennt dann auch Exit-Code, Befundklassen und Beweisstufe für
  diese Umgebung (Member `auditor_inputs`). `tools/aequivalenz.sh` prüft die
  Urteile der Prüfumgebung des Korpus.

## 8. Ein Release nachbauen

```sh
tar -xzf ledger-verify_${V}_source.tar.gz && cd ledger-verify-$V
# Die eingebaute Herstellerwurzel als Datei: wurzel_id und pubkey wie auf
# louwietec.com und in Zeile 2 von --version eines Release-Binaries
printf '%s\n' '{"wurzel_id":"<wurzel_id>","pubkey":"<pubkey>"}' > ../herstellerwurzel.json
LEDGER_VERIFY_HERSTELLER_WURZEL=../herstellerwurzel.json bash tools/bauen.sh ../nachbau $V ledger-verify
cd ../nachbau && sha256sum -c --ignore-missing ../SHA256SUMS
```

Die Release-Binaries tragen die Herstellerwurzel eingebaut. Ohne die
Wurzel-Datei entstehen Binaries ohne eingebaute Wurzel und damit andere
Prüfsummen.

Der Bau ist mit derselben Go-Fassung (go1.24.7) reproduzierbar. Eine
andere Go-Fassung ergibt andere Bytes, und `tools/bauen.sh` warnt dann.

## 9. Lizenz

Apache License 2.0; siehe `LICENSE` und `NOTICE`. Die LEDGER-Appliance und
die Dienste des Herstellers gehören nicht zu diesem Repository.

## 10. Eine Schwachstelle melden

Siehe [SECURITY.md](SECURITY.md). Bitte kein öffentliches Issue.
