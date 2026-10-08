# Sicherheit / Security

[Deutsch](#deutsch) · [English](#english)

## Deutsch

### Was eine Schwachstelle ist

Dieses Repository ist das Prüfwerkzeug. Eine Schwachstelle ist hier alles, was
ein Prüfer nicht bemerken würde. Zum Beispiel:

- ein Prüfpaket, das einer der Verifier **milder** beurteilt, als die
  Spezifikation es verlangt. Etwa eine manipulierte Kette mit Exit 0 oder 1,
  oder eine unvollständige Kette als „versiegelt“;
- zwei Verifier (`verifier/` und `verifier2/`) oder Kommandozeile und
  Browser-Seite, die dasselbe Paket verschieden beurteilen;
- eine Lücke in der Spezifikation (`spec/`), mit der sich eine Fälschung bauen
  lässt, die jeder regelkonforme Verifier annimmt;
- ein Absturz, eine Endlosschleife oder unbegrenzter Speicherverbrauch bei
  einem präparierten Paket (erwartet ist Exit 3, Formatfehler);
- ein Release, dessen Signatur oder Prüfsummen nicht stimmen, oder dessen
  Binärdateien sich aus dem Quellarchiv nicht byte-gleich nachbauen lassen
  (`tools/bauen.sh`).

### Wie Sie melden

Bitte **nicht** als öffentliches Issue. Melden Sie vertraulich:

1. über GitHub: Reiter „Security“ → „Report a vulnerability“ (private Meldung), oder
2. per E-Mail an security@louwietec.com.

Hilfreich sind die Ausgabe von `--version` (bzw. die Versionszeile der
Browser-Seite), die Plattform, ein möglichst kleines Prüfpaket sowie Soll und
Ist: welches Urteil die Spezifikation verlangt und welches der Verifier fällt.
Ein Prüfpaket enthält keine Klartexte, sondern nur Hashes, Signaturen und
öffentliche Schlüssel. Bitte schicken Sie trotzdem keine Pakete aus einem
Produktivbetrieb, wenn ein nachgebautes Paket den Fehler auch zeigt.

Wir bestätigen den Eingang, stimmen die Veröffentlichung mit Ihnen ab und
nennen Sie auf Wunsch in der Korrektur. Eine Korrektur, die das Urteil ändert,
kommt mit einem neuen Testvektor unter `spec/testvectors/`, damit der Fehler
nicht wiederkehrt.

### Welche Fassungen

Unterstützt wird das jeweils neueste Release. Releases sind mit dem
Release-Schlüssel des Herstellers signiert (OpenSSH-Signatur über
`SHA256SUMS`). Dessen Fingerabdruck steht auf louwietec.com und im
Prüferleitfaden, nicht nur in diesem Repository.

## English

### What counts as a vulnerability

This repository is the verification tool. A vulnerability here is anything an
auditor would not notice. For example:

- a verification package that one of the verifiers judges **more leniently**
  than the specification requires. For instance, a tampered chain with exit 0
  or 1, or an incomplete chain reported as "sealed";
- two verifiers (`verifier/` and `verifier2/`), or the command line and the
  browser page, judging the same package differently;
- a gap in the specification (`spec/`) that allows a forgery every conforming
  verifier accepts;
- a crash, an endless loop or unbounded memory use on a crafted package (the
  expected result is exit 3, format error);
- a release whose signature or checksums do not hold, or whose binaries cannot
  be rebuilt byte for byte from the source archive (`tools/bauen.sh`).

### How to report

Please do **not** open a public issue. Report privately:

1. on GitHub: "Security" tab → "Report a vulnerability" (private report), or
2. by e-mail to security@louwietec.com.

Please include the output of `--version` (or the version line of the browser
page), the platform, a verification package that is as small as possible, and
the expected and the actual verdict: which verdict the specification requires,
and which one the verifier gives. A verification package holds no plaintext,
nothing but hashes, signatures and public keys. Even so, please send no package from
production use if a reconstructed package shows the problem as well.

We acknowledge receipt, coordinate disclosure with you and credit you in the
fix if you wish. A fix that changes a verdict comes with a new test vector
under `spec/testvectors/`, so the problem cannot return.

### Supported versions

The latest release is supported. Releases are signed with the vendor's
release key (an OpenSSH signature over `SHA256SUMS`). Its fingerprint is
published on louwietec.com and in the auditor's guide, not just in this
repository.
