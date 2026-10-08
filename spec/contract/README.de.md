# Vertragsvektoren der Cloud-Nachrichten (Spezifikation 1.8)

**Sprache: Deutsch (englische Fassung: `README.en.md`, identische Struktur)**

Diese Dateien sind die Referenzwerte für die Hersteller-Seite der Lizenz: was ein Metadatenserver bei der Aktivierung und bei Ankern entscheiden MUSS und was eine Appliance aus seinen Antworten schließen DARF. Normativ ist die Heartbeat-Spezifikation (`spec/heartbeat.de.md`); diese Vektoren machen „nach Spezifikation" byteweise prüfbar. Spur B (Cloud-Betrieb) und Spur C (Lizenz) testen ihren Code gegen sie.

## 1. Dateien

| Datei | Abschnitt | Inhalt |
|---|---|---|
| `license_proof.json` | §4.1 | Referenzwerte für `license_proof` (`cases`) und vorgelegte Werte, die der Server abweisen MUSS (`refused`), je mit Begründung |
| `license_statement.json` | §9.4 | signierte Lizenzbescheide mit dem Urteil, das ein Empfänger erreichen MUSS: wirksam (mit Zustand) oder unwirksam (mit Grund) |
| `anchor_refusal.json` | §9.5 | 403-Antworten auf genau einen gesendeten Anker mit dem Urteil der Appliance: Lizenzsperre oder gewöhnlicher Fehlschlag |
| `lueckenzeuge.json` | §9.2 | Ankerfolgen durch eine Lizenzlücke mit der Entscheidung des Servers nach jedem Schritt: HTTP-Status, Fehlercode, Art der Antwort und Bezugsgröße danach |
| `activation_receipt.json` | §4.1, §9.8 | 200-Antworten auf eine Umbindung nach Schlüsselersatz mit dem Urteil der Appliance: Umbindung angenommen oder gescheitert (Bescheid für das neue Commitment und an die Aktivierung gebundene Quittung, beide frisch) |

Der Herstellerschlüssel in den Dateien ist ein **Testschlüssel**; sein Seed steht offen darin, damit Implementierungen eigene Fälle signieren können. Er wird nie auf einem echten Server konfiguriert.

## 2. Erzeugung und Gegenprüfung

Erzeugt werden die Dateien deterministisch vom Vektorgenerator: `cd appliance && go run ./cmd/vektorgen -vertrag ../spec/contract`. `TestVertragEingefroren` (`appliance/cmd/vektorgen`) hält die eingecheckten Dateien Byte für Byte gegen den Generator. Die Telemetrie prüft ihre Implementierung von `license_proof` gegen `license_proof.json` (`TestLicenseProofVertrag`).

Unabhängig davon leitet `.ci/check_vertrag.py` jede Erwartung neu aus dem Spezifikationstext her: in Python, mit den Primitiven des Zweitverifiers (JCS, Ed25519, RFC-6962-Baum) und den Membermengen der Registry (`cloud_statements`), ohne dem Generator zu glauben. `.ci/check_registry_matrix.py` ruft die Prüfung auf; eine Abweichung ist rot.

## 3. Was sich ändern darf

Ein neuer Fall ist ein neuer Eintrag. Ein bestehender Fall ändert sich nur, wenn die freigegebene Spezifikation ihn widerlegt, wie bei den eingefrorenen Testvektoren (`spec/testvectors/README.de.md` §4).
