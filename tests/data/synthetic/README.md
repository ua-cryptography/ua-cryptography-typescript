# Synthetic signatures

Made by `ua-sign`, the command-line tool of the C# reference
([ua-cryptography-csharp](https://github.com/ua-cryptography/ua-cryptography-csharp)), so the tests verify signatures of
an independent implementation. Nothing here is personal data: the keys and their self-signed certificates were created
for the tests, and the key store password is `synthetic test password`.

| File | What |
|---|---|
| `document.txt` | the signed document |
| `signer-257.jks`, `signer-257.cer` | key on the m = 257 curve of table Г.1, certificate signed with DSTU 4145 + DSTU 7564 |
| `signer-431-gost.jks`, `signer-431-gost.cer` | key on the m = 431 curve, certificate signed with DSTU 4145 + GOST 34.311 |
| `cades-enveloped.p7s`, `cades-detached.p7s` | CAdES-B, DSTU 7564-256 |
| `cades-gost.p7s` | CAdES-B, GOST 34.311 |
| `xades-detached.xml` | XAdES-B-B referencing `document.txt` |
| `asic-e.asice`, `asic-e-gost.asice` | ASiC-E with XAdES-B-B |
| `asic-s.asics` | ASiC-S with a detached CAdES-B |

Regenerate with `tools/make-fixtures.sh /path/to/ua-sign` (the tests expect the signer names and formats above).
