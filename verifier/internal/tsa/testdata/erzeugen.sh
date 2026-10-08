#!/usr/bin/env bash
# erzeugen.sh — erzeugt die RFC-3161-Pruefstuecke dieses Verzeichnisses mit
# OpenSSL, also mit einer FREMDEN Implementierung.
#
# WARUM FREMD: der Parser in token.go ist von Hand geschrieben, weil Gos
# Standardbibliothek kein CMS kennt. Ein Test, der nur Tokens aus derselben
# Hand liest, wuerde beweisen, dass mein Parser meinen Schreiber versteht —
# nicht, dass er RFC 3161 versteht. Deshalb kommen die Pruefstuecke aus
# OpenSSL.
#
# Die Ergebnisse sind im Repository eingefroren; dieses Skript ist ihre
# Herkunftsangabe und macht sie nachbaubar. Ein neuer Lauf ergibt andere
# Bytes (Zufallsschluessel, echte Uhr) — das ist richtig so, die eingefrorenen
# Dateien bleiben die Pruefgrundlage.
#
# Aufruf / usage: bash verifier/internal/tsa/testdata/erzeugen.sh
set -euo pipefail

HIER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARBEIT="$(mktemp -d -t tsa-fixtures-XXXXXX)"
trap 'rm -rf "$ARBEIT"' EXIT
cd "$ARBEIT"

konfig() { # $1 = Praefix der Schluessel/Zertifikatdateien
  cat <<EOF
[ tsa ]
default_tsa = t
[ t ]
serial = ./serial
crypto_device = builtin
signer_cert = ./$1.crt
signer_key = ./$1.key
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256, sha512
accuracy = secs:1, millisecs:500, microsecs:100
clock_precision_digits = 0
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
EOF
}

# 1) Die regelkonforme Stelle: extendedKeyUsage kritisch, genau timeStamping.
openssl req -x509 -newkey rsa:2048 -keyout gut.key -out gut.crt -days 3650 -nodes \
  -subj "/CN=Rekorder Test TSA/O=Testfall" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,nonRepudiation" \
  -addext "extendedKeyUsage=critical,timeStamping" 2>/dev/null

# 2) Eine zweite, ebenso regelkonforme Stelle — dieselbe Bauart, anderer
#    Schluessel. Sie belegt, dass die Vertrauensverankerung wirklich prueft
#    und nicht jeden Token durchwinkt, der irgendein Zertifikat mitbringt.
openssl req -x509 -newkey rsa:2048 -keyout fremd.key -out fremd.crt -days 3650 -nodes \
  -subj "/CN=Fremde Test TSA/O=Testfall" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,nonRepudiation" \
  -addext "extendedKeyUsage=critical,timeStamping" 2>/dev/null

# Was hier NICHT entsteht, und warum: ein Token mit zu weiter
# extendedKeyUsage (timeStamping UND serverAuth) und eines mit SHA-1-Abdruck.
# OpenSSL weigert sich, beide auszustellen — `ts -reply` bricht mit
# „response setup error" ab, weil es RFC 3161 Abschnitt 2.3 auf der
# Ausstellerseite selbst durchsetzt. Ein Faelscher benutzt `ts -reply` nicht,
# also braucht der Parser die Pruefung trotzdem; die beiden Pruefstuecke
# entstehen deshalb im Go-Test mit einem eigenen Schreiber
# (testtsa_test.go), nicht hier.

printf 'hallo welt' > daten.bin

stempel() { # $1 = Praefix, $2 = Digest, $3 = Zielname
  echo 01 > serial
  konfig "$1" > tsa.cnf
  openssl ts -query -data daten.bin "-$2" -cert -out anfrage.tsq >/dev/null 2>&1
  openssl ts -reply -config tsa.cnf -queryfile anfrage.tsq -out antwort.tsr >/dev/null 2>&1
  openssl ts -reply -in antwort.tsr -out "$3" -token_out
}

stempel gut   sha256 "$HIER/openssl_token.der"
stempel fremd sha256 "$HIER/fremd_token.der"

cp gut.crt   "$HIER/openssl_tsa.crt"
cp fremd.crt "$HIER/fremd_tsa.crt"
cp daten.bin "$HIER/openssl_data.bin"

echo "Erzeugt / created in $HIER:"
ls -l "$HIER" | awk '/der|crt|bin/ {printf "  %-24s %6s Bytes\n", $9, $5}'
echo "OpenSSL: $(openssl version)"
