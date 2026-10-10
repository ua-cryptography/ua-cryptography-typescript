#!/usr/bin/env bash
# Recreates tests/data/synthetic with ua-sign of the C# reference: tools/make-fixtures.sh /path/to/ua-sign
set -euo pipefail
ua="${1:?usage: tools/make-fixtures.sh /path/to/ua-sign}"
cd "$(dirname "$0")/../tests/data/synthetic"
p='synthetic test password'
rm -f ./*.jks ./*.cer ./*.p7s ./*.xml ./*.asice ./*.asics
printf 'Тестовий документ для перевірки підпису.\nTest document — synthetic, no personal data.\n' > document.txt
"$ua" keygen --keystore signer-257.jks --subject "CN=Тестовий підписувач,O=Synthetic Test,C=UA" --curve 257 --days 3650 --cert signer-257.cer --password "$p"
"$ua" keygen --keystore signer-431-gost.jks --subject "CN=Test Signer GOST,O=Synthetic Test,C=UA" --curve 431 --days 3650 \
  --signature-hash gost34311 --cert signer-431-gost.cer --password "$p"
"$ua" sign --keystore signer-257.jks --password "$p" --format cades --in document.txt --out cades-enveloped.p7s
"$ua" sign --keystore signer-257.jks --password "$p" --format cades --detached --in document.txt --out cades-detached.p7s
"$ua" sign --keystore signer-431-gost.jks --password "$p" --format cades --hash gost34311 --in document.txt --out cades-gost.p7s
"$ua" sign --keystore signer-257.jks --password "$p" --format xades --in document.txt --out xades-detached.xml
"$ua" sign --keystore signer-257.jks --password "$p" --format asic-e --in document.txt --out asic-e.asice
"$ua" sign --keystore signer-257.jks --password "$p" --format asic-s --in document.txt --out asic-s.asics
"$ua" sign --keystore signer-431-gost.jks --password "$p" --format asic-e --hash gost34311 --in document.txt --out asic-e-gost.asice
