# Testdaten ML-DSA (Verifier)

## acvp_sigver.json: NIST ACVP, ML-DSA sigVer (FIPS 204)

- Quelle: https://github.com/usnistgov/ACVP-Server, Verzeichnis
  `gen-val/json-files/ML-DSA-sigVer-FIPS204/`, Datei `internalProjection.json`
  (Rohdatei: https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json)
- Commit des ACVP-Servers: `975de31eb83d87039ec88934fdc47d8c312b892d`
  (Commit-Datum 2026-08-12, "RELEASE/v1.1.0.43 including hotfix patches")
- Heruntergeladen am 2026-11-03; SHA-256 der Originaldatei:
  `47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437`
- Lizenz: NIST, public domain (in den USA nach 17 U.S.C. 105 nicht
  urheberrechtlich geschuetzt); Hinweis des ACVP-Servers unten im Wortlaut.

Auswahl (`acvp_auswahl.py`, reproduzierbar aus der Originaldatei): die
Gruppen ohne Pre-Hash, also `external`/`pure` (tgId 1, 3, 5), `internal`
(tgId 8, 10, 12) und `internal` mit `externalMu` (tgId 7, 9, 11), je 10 von
15 Faellen: alle 3 gueltigen und 7 ungueltige, reihum ueber die vier
`reason`-Werte (modified message, modified signature - commitment / - hint /
- z). Die Felder `tcId`, `testPassed`, `reason`, `pk`, `message`/`mu`,
`context`, `signature` sind unveraendert; `sk`, `hashAlg` und `deferred`
entfallen. Die Pre-Hash-Gruppen (HashML-DSA) sind nicht ausgewaehlt, der
Verifier unterstuetzt nur die reine Variante.

Pruefung: `TestACVPSigVer` (acvp_test.go). Jeder Fall muss `testPassed`
treffen.

## kreuz_appliance.json: Kreuzvektoren

Signaturen der Signierimplementierung in `appliance/internal/mldsa`
(deterministisch, oeffentliche Testseeds), erzeugt mit
`cd appliance && MLDSA_KREUZ_SCHREIBEN=1 go test ./internal/mldsa/ -run TestKreuzvektoren`.
Ohne die Variable prueft derselbe Test, dass die Datei der Erzeugung
entspricht. Der Verifier liest nur diese Datei, er importiert nichts aus
der Appliance. Pruefung und Negativfaelle: kreuz_test.go.

## acvp_auswahl.py

Erzeugt aus den drei ACVP-Dateien (keyGen, sigGen, sigVer) die reduzierten
Dateien dieses Verzeichnisses und von `appliance/internal/mldsa/testdata/`.

## Herkunftshinweis und Lizenz (NIST)

Quelle: National Institute of Standards and Technology (NIST), ACVP-Server.
Aenderung am 2026-11-03: Auswahl einer Teilmenge der Testgruppen und Faelle
und Weglassen einzelner Felder wie oben beschrieben; die uebernommenen Werte
sind unveraendert.

Hinweis aus README.md des ACVP-Servers (Abschnitt "License"), im Wortlaut:

> NIST-developed software is provided by NIST as a public service. You may use, copy, and distribute copies of the software in any medium, provided that you keep intact this entire notice. You may improve, modify, and create derivative works of the software or any portion of the software, and you may copy and distribute such modifications or works. Modified works should carry a notice stating that you changed the software and should note the date and nature of any such change. Please explicitly acknowledge the National Institute of Standards and Technology as the source of the software.
>
> NIST-developed software is expressly provided "AS IS." NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT, OR ARISING BY OPERATION OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND DATA ACCURACY. NIST NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.
>
> You are solely responsible for determining the appropriateness of using and distributing the software and you assume all risks associated with its use, including but not limited to the risks and costs of program errors, compliance with applicable laws, damage to or loss of data, programs or equipment, and the unavailability or interruption of operation. This software is not intended to be used in any situation where a failure could cause risk of injury or damage to property. The software developed by NIST employees is not subject to copyright protection within the United States.
