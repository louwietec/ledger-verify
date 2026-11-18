# Vertragsvektoren der Cloud-Nachrichten (Spezifikation 1.8 bis 1.10)

**Sprache: Deutsch (englische Fassung: `README.en.md`, identische Struktur)**

Diese Dateien sind die Referenzwerte für die Hersteller-Seite der Lizenz: was ein Metadatenserver bei der Aktivierung und bei Ankern entscheiden MUSS und was eine Appliance aus seinen Antworten schließen DARF. Normativ ist die Heartbeat-Spezifikation (`spec/heartbeat.de.md`); diese Vektoren machen „nach Spezifikation" byteweise prüfbar. Die Hersteller-Seite und die Appliance testen ihren Code gegen sie.

## 1. Dateien

| Datei | Abschnitt | Inhalt |
|---|---|---|
| `license_proof.json` | §4.1 | Referenzwerte für `license_proof` (`cases`) und vorgelegte Werte, die der Server abweisen MUSS (`refused`), je mit Begründung |
| `license_statement.json` | §9.4 | signierte Lizenzbescheide mit dem Urteil, das ein Empfänger erreichen MUSS: wirksam (mit Zustand) oder unwirksam (mit Grund) |
| `anchor_refusal.json` | §9.5 | 403-Antworten auf genau einen gesendeten Anker mit dem Urteil der Appliance: Lizenzsperre oder gewöhnlicher Fehlschlag |
| `lueckenzeuge.json` | §9.2 | Ankerfolgen durch eine Lizenzlücke mit der Entscheidung des Servers nach jedem Schritt: HTTP-Status, Fehlercode, Art der Antwort und Bezugsgröße danach |
| `activation_receipt.json` | §4.1, §9.8 | 200-Antworten auf eine Umbindung nach Schlüsselersatz mit dem Urteil der Appliance: Umbindung angenommen oder gescheitert (Bescheid für das neue Commitment und an die Aktivierung gebundene Quittung, beide frisch) |
| `statement_signatures.json` | §9.3, §9.4, §9.11 | ab Fassung 1.10: Antworten, deren Lizenzbescheid neben dem Paar der Hülle ein Paar in `statement_signatures` trägt, mit dem Urteil eines Empfängers nach Fassung 1.9 und nach Fassung 1.10: wirksam über die Hülle, wirksam über das Paar unter dem Bescheidschlüssel, nur das Paar unter dem Gegenzeichnungsschlüssel (unwirksam), Bescheidschlüssel vor `server_ts` widerrufen (unwirksam), fehlerhafter Eintrag neben der Hülle (ignoriert) |
| `gemeldete_wurzeln.json` | §9.2, §9.7 | ab Fassung 1.10: zwei Appliances mit eigener Lizenz und die Bindung einer Kette mit der Entscheidung des Servers nach jedem Schritt: gebunden wird eine Kette durch ihre erste festgehaltene Wurzel oder einen eingetragenen Kettenwechsel, nie durch einen Heartbeat; eine gemeldete Wurzel wird nur festgehalten, wenn die Kette an die sendende Appliance gebunden ist; den Anker einer anderen Appliance beantwortet der Server mit HTTP 403 `chain_owner_mismatch` |

Die Herstellerschlüssel in den Dateien sind **Testschlüssel**; ihre Seeds stehen offen darin, damit Implementierungen eigene Fälle signieren können. Sie werden nie auf einem echten Server konfiguriert.

## 2. Erzeugung und Gegenprüfung

Erzeugt werden die Dateien deterministisch vom Vektorgenerator: `cd appliance && go run ./cmd/vektorgen -vertrag ../spec/contract`. `TestVertragEingefroren` (`appliance/cmd/vektorgen`) hält die eingecheckten Dateien Byte für Byte gegen den Generator. Die Telemetrie prüft ihre Implementierung von `license_proof` gegen `license_proof.json` (`TestLicenseProofVertrag`).

Unabhängig davon leitet `.ci/check_vertrag.py` jede Erwartung neu aus dem Spezifikationstext her: in Python, mit den Primitiven des Zweitverifiers (JCS, Ed25519, RFC-6962-Baum) und den Membermengen der Registry (`cloud_statements`), ohne dem Generator zu glauben. `.ci/check_registry_matrix.py` ruft die Prüfung auf; eine Abweichung ist rot.

## 3. Was sich ändern darf

Ein neuer Fall ist ein neuer Eintrag. Ein bestehender Fall ändert sich nur, wenn die freigegebene Spezifikation ihn widerlegt, wie bei den eingefrorenen Testvektoren (`spec/testvectors/README.de.md` §4).
