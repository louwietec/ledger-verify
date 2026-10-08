# LEDGER-Verifier

[English](README.md)

Dieses Repository enthält die offene Spezifikation, die Testvektoren und zwei
unabhängige Verifier für LEDGER-Beweisketten (LEDGER hieß früher „Rekorder“;
Hersteller ist LOUWIETEC). Mit den Dateien hier kann jeder ein
LEDGER-Prüfpaket selbst prüfen: offline, ohne Zutun des Herstellers, ohne Konto
und ohne Geheimnis.

| Pfad | Inhalt |
|---|---|
| `spec/` | die normative Spezifikation (`format.de.md`, `format.en.md`, spec_version 1.9), die maschinenlesbare Registry `registry.json`, JSON-Schemas und die Testvektoren |
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
V=1.0.0            # die Version des Releases
P=linux_amd64      # oder linux_arm64, darwin_amd64, darwin_arm64
R=https://github.com/louwietec/ledger-verify/releases/download/v$V
for f in SHA256SUMS SHA256SUMS.sig allowed_signers ledger-verify_${V}_$P ledger-verify_${V}_source.tar.gz; do
  curl -fsSLO "$R/$f"
done

# 1) Fingerabdruck des Signaturschlüssels: mit dem veröffentlichten vergleichen
awk '{print $3, $4}' allowed_signers > release.pub && ssh-keygen -lf release.pub

# 2) Signatur über SHA256SUMS; erwartet: Good "file" signature for release@louwietec.com ...
ssh-keygen -Y verify -f allowed_signers -I release@louwietec.com -n file -s SHA256SUMS.sig < SHA256SUMS

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
bash tools/pruefen.sh <verzeichnis> <verzeichnis>/allowed_signers SHA256:<veröffentlichter Fingerabdruck>
```

`tools/pruefen.sh` liegt in diesem Repository und im Quellarchiv. Es ist kurz
genug, um es vor dem Ausführen zu lesen. Die letzte Zeile lautet
`ERGEBNIS: GRUEN` oder `ERGEBNIS: ROT`, danach die Einzelheiten. Schon ein geändertes Byte
in `SHA256SUMS`, in der Signatur oder in einer Release-Datei macht sie ROT.

### Windows (PowerShell)

```powershell
$V = "1.0.0"
$R = "https://github.com/louwietec/ledger-verify/releases/download/v$V"
foreach ($f in "SHA256SUMS", "SHA256SUMS.sig", "allowed_signers",
               "ledger-verify_${V}_windows_amd64.exe", "ledger-verify_${V}_source.tar.gz") {
  Invoke-WebRequest -Uri "$R/$f" -OutFile $f
}

# 1) Fingerabdruck des Signaturschlüssels: mit dem veröffentlichten vergleichen
$k = (Get-Content allowed_signers -TotalCount 1).Split(" ")
"$($k[2]) $($k[3])" | Set-Content -Encoding ascii release.pub
ssh-keygen -lf release.pub

# 2) Signatur; über cmd, damit SHA256SUMS byte-genau bei ssh-keygen ankommt
cmd /c "ssh-keygen -Y verify -f allowed_signers -I release@louwietec.com -n file -s SHA256SUMS.sig < SHA256SUMS"

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
| `--vendor-root DATEI` | Wurzelschlüssel des Herstellers `{"wurzel_id", "pubkey"}` (Spezifikation 7.1, 10.7); wiederholbar |
| `--vendor-key ID=HEX` | heftet einen einzelnen Gegenzeichnungsschlüssel des Herstellers an (Spezifikation 7.1); wiederholbar |
| `--expect-root HEX` | 64-Hex-Merkle-Wurzel, die in dieser Kette vorkommen MUSS (Spezifikation 7.2, 8.6) |
| `--tsa-root DATEI` | PEM-Vertrauensanker für Zeitzeugen (Spezifikation 7.3) |
| `--now RFC3339` | Prüfzeitpunkt; Vorgabe ist die Systemuhr |
| `--freshness DAUER` | Frischefenster für `TRAILING_SILENCE` (Vorgabe `24h`) |

`--help` zeigt alle Schalter. `--version` nennt die Version und die
Spezifikation, die der Verifier umsetzt. Die zweite Zeile sagt, ob eine
Herstellerwurzel eingebaut ist.

### Vertrauensanker: `--vendor-root` und `--vendor-key` (Spezifikation 7.1, 10.7)

Ein Prüfpaket schreibt genau das Haus, das die Gegenzeichnungen des
Herstellers binden sollen. Ein Herstellerschlüssel aus dem Paket beweist
deshalb allein nichts, und der Vertrauensanker muss von **Ihnen** kommen:

- `--vendor-root DATEI` ist der Wurzelschlüssel des Herstellers, der mit der
  Lizenz veröffentlicht wird. Über die signierte Liste
  `keys/vendor/schluesselliste.json` im Paket bürgt er für die
  Gegenzeichnungsschlüssel.
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

### Abgleich mit der jüngsten gegengezeichneten Wurzel des Herstellers: `--expect-root` (Spezifikation 8.6)

Ein Paket kann aus sich heraus nicht beweisen, dass nach seinem letzten
Eintrag nichts mehr kam. Offline sehen eine unvollständige Kette (Exit 4) und
eine Kette, die direkt hinter einem früheren Siegel abgeschnitten wurde,
gleich aus. Sicherheit gibt erst der Abgleich. Fordern Sie beim Hersteller
die jüngste gegengezeichnete Wurzel zur `chain_id` aus dem Bericht an und
prüfen Sie erneut mit `--expect-root <merkle_root>`. Fehlen dem Paket
Einträge, die der Hersteller schon gegengezeichnet hat, meldet der Verifier
`MERKLE_INCONSISTENT` (Exit 2). Machen Sie den Abgleich auch bei versiegelten
Ketten. Derselbe Schalter nimmt auch eine im Monatsbericht abgedruckte Wurzel
(Papier-Anker, Spezifikation 7.2). verifier2 erwartet ihn in der Form
`--expect-root TREE_SIZE:ROOT`.

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
geht auch ohne Netz) und ziehen Sie das Prüfpaket auf die Seite. Unter
„Weitere Prüfangaben“ wählen Sie die Herstellerwurzel und bei Bedarf das
Wurzelzertifikat einer Zeitstempelstelle. Das Paket verlässt Ihren Rechner
nicht, und die Seite lädt nichts nach und sendet nichts. Das können Sie selbst
nachprüfen; jede Zeile soll 0 zeigen:

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
Änderung.

```sh
python3 verifier2/verifier2.py --now-from-package \
  --vendor-root spec/testvectors/pruefer_herstellerwurzel.json \
  --vendor-key "$(cat spec/testvectors/pruefer_herstellerschluessel.txt)" \
  spec/testvectors/valid_sealed_export
```

## 7. Spezifikation und Testvektoren

- `spec/format.de.md` / `spec/format.en.md` beschreiben das Kettenformat, den
  Prüfablauf, die Exit-Codes, die Befundklassen, das Angreifermodell und die
  Beweisgrenzen. `spec/registry.json` ist die maschinenlesbare Referenz und
  geht bei Abweichung vor.
- `spec/heartbeat.*.md` beschreibt die Nachrichten zwischen Appliance und
  Herstellerserver (Aktivierung, Heartbeat, Anker).
- `spec/pflichten.*.md` ist die Pflichten-Deckungstabelle. Sie zeigt, bei
  welchen Betreiberpflichten die Kette die Erfüllung mit Belegen unterstützt.
  Sie ist keine Rechtsberatung.
- `spec/testvectors/` enthält die eingefrorenen Testvektoren, jeder mit
  seinem erwarteten Urteil unter `expected/<name>.json`. Jede Datei ist in
  `PINS.sha256` gepinnt, und `spec/testvectors/README.de.md` erklärt den
  Korpus.

## 8. Ein Release nachbauen

```sh
tar -xzf ledger-verify_${V}_source.tar.gz && cd ledger-verify-$V
bash tools/bauen.sh ../nachbau $V ledger-verify
cd ../nachbau && sha256sum -c --ignore-missing ../SHA256SUMS
```

Der Bau ist mit derselben Go-Fassung (go1.24.7) reproduzierbar. Eine
andere Go-Fassung ergibt andere Bytes, und `tools/bauen.sh` warnt dann.

## 9. Lizenz

Apache License 2.0; siehe `LICENSE` und `NOTICE`. Die LEDGER-Appliance und
die Dienste des Herstellers gehören nicht zu diesem Repository.

## 10. Eine Schwachstelle melden

Siehe [SECURITY.md](SECURITY.md). Bitte kein öffentliches Issue.
