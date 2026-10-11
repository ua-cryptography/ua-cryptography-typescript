# UA e-signature in one HTML page

Verification of Ukrainian qualified electronic signatures, and CAdES signing with a JKS key, in TypeScript — built into
**one self-contained HTML file** that works from disk. Verification is entirely offline; signing reaches out once, and
only when asked, for PrivatBank's qualified time-stamp. A port of the verifier of
[ua-cryptography-csharp](https://github.com/ua-cryptography/ua-cryptography-csharp) (DSTU 4145, DSTU 7564, GOST 34.311,
the PKI layer), limited to the two formats providers hand out:

| Format | File | Made by | Here |
|---|---|---|---|
| CAdES-T, data inside | `.sig` | PrivatBank | verified |
| ASiC-E with a detached XAdES-B-LT | `.asice` | «Дія.Підпис» | verified |

**Open the page:** <https://ua-cryptography.github.io/ua-cryptography-typescript/> — or download the single file from
the [latest release](https://github.com/ua-cryptography/ua-cryptography-typescript/releases/latest) and open it from
disk.

The verifier recognises the same family around them as well — CAdES B/T/X Long enveloped or detached (`.p7s`), ASiC-S,
XAdES as a separate `.xml` — with DSTU 7564-256 or GOST 34.311 and DSTU 4145 keys in the polynomial basis.

## Using the page

`./build.sh` produces `build/ua-signature.html` (it needs Node.js 22 or later and installs the dependencies on the
first run; `./build.sh --watch` rebuilds on every change). Open the file in a browser — a `file://` URL is fine.

- **Verify** — drop a signed file; for a detached signature drop the signed document together with it. The page shows
  the signer, the signing and time-stamp times, the certificate paths, every check made, and offers the signed document
  for saving.
- **Sign** — open the `.jks` key store the bank issued with its password, drop a document, sign. The result is saved as
  `<document>.sig` (or a detached `.p7s`) and verified on the spot. With a PrivatBank key the qualified time-stamp is
  ticked by default: the signature is then CAdES-T, as the bank makes it; unticked, CAdES-B made offline.
- **Certificates** — the trusted roots and intermediate certificates the page relies on. Drop more certificates (DER,
  PEM or a `.p7b` bundle) to add them; they are kept in the browser's local storage.

The page is also published on GitHub Pages from `main`
(<https://ua-cryptography.github.io/ua-cryptography-typescript/>), and every release carries the same single file,
`ua-signature-v<version>.html`, with its SHA-256 in `SHA256SUMS.txt`. A release is made by `npm version x.y.z` and
pushing the tag: the workflow refuses a tag that is not package.json's version.

Built in (`assets/certificates`, all public): the ЦЗО roots (2027, 2030, 2035 with GOST 34.311; 2036 with DSTU 7564) and
the NBU root of 2036 as trusted roots; the «Дія» CA, the PrivatBank CA, and the bundle PrivatBank publishes at its
certificates' caIssuers address (`PB-2026-NBU.p7b`: its CAs, TSP and OCSP servers) as intermediates. The bundle matters:
a PrivatBank `.sig` carries neither its CA's certificate nor the TSP server's, so without it the time-stamp cannot be
checked and the path does not reach the root.

## Network: one exception

The page's Content-Security-Policy allows exactly one origin, `connect-src https://acsk.privatbank.ua` (the build
refuses any other value), and its one script is pinned by hash.

- **The time-stamp at signing.** A PrivatBank signature is CAdES-T: it carries a qualified time-stamp over the signature
  value from the bank's TSP server. The signer's certificate names that server (`http://acsk.privatbank.ua/services/tsp/`);
  the page asks it over HTTPS — the server answers both, allows any origin (CORS), and HTTPS also works from a page served
  over HTTPS. The request is an RFC 3161 TimeStampReq with **only the DSTU 7564 hash of the signature value** and a
  nonce: the document, its hash and the key never leave the page. The answer is checked (status, imprint, nonce) before
  it goes into the signature, and the new signature is verified on the spot. For certificates of other providers the
  option is not offered. Unticked, nothing is sent and the result is CAdES-B.

Everything else stays offline:

- **The current revocation status is not checked.** OCSP responses *embedded* in a signature are verified (signature,
  responder authorization, status); a certificate without one gets a warning. A PrivatBank `.sig` has no revocation data
  at all; a «Дія» `.asice` has the status of the signer's certificate at signing time, but not of its CA or TSP server.
- **Missing CA certificates are not downloaded** from the caIssuers addresses; add them on the Certificates tab.

Also not supported: PAdES, the optimal normal basis (no certificate of the national PKI uses it), DSTU 7624, IIT key
containers (`Key-6.dat`, `.ZS2`) and PKCS#12, CRLs, archive time-stamps, certificate policies and qcStatements.

## How it is checked

`npm run check` = typecheck → unit tests → build → the page in headless Chrome.

- `tests/hash.mjs` — DSTU 7564 against the examples of the standard, GOST 34.311 against the published GOST R 34.11-94
  vectors, SHA-1/256 against Node.
- `tests/dstu4145.mjs` — the worked example Б.1 of DSTU 4145-2002 value by value; field axioms and the trace for
  several degrees of table 1; the ladder against double-and-add; the ten curves of table Г.1 against section 8;
  sign/verify round trips.
- `tests/certificates.mjs` — the real ЦЗО and NBU roots, «Дія» → ЦЗО, PrivatBank → NBU, the PrivatBank bundle, five CA
  certificates of 2005–2015 with three different DKEs.
- `tests/c14n.mjs` — the XML parser and inclusive/exclusive C14N against `xmllint` (libxml2), whole documents and every
  subtree.
- `tests/verify.mjs`, `tests/sign.mjs` — signatures made by `ua-sign` of the C# reference (`tests/data/synthetic`) in
  every format, tampered in several ways; signatures made here, checked field by field against PrivatBank's profile
  and verified by `ua-sign` too when it is available (`UA_SIGN=/path/to/ua-sign`); CAdES-T against a time-stamping
  service of the test itself, and responses with a wrong imprint, nonce or status refused.
- `tests/online.mjs` — only with `UA_ONLINE=1`: PrivatBank's real time-stamping server, a token verified with the
  bundled certificates, and a CAdES-T with the bank's key when the machine has it.
- `tests/app.mjs` — the built page: verification, adding a root, signing, the time-stamp option, no errors; any address
  but PrivatBank's TSP server is blocked by the policy (`--shots DIR` saves screenshots; `UA_ONLINE=1` signs with a real
  time-stamp).

Real signatures and keys carry personal data and are never committed. When a machine has them
(`UA_PRIVATE_SAMPLES`, by default `../ua-cryptography-csharp/private`), the tests also verify a real PrivatBank `.sig`,
a «Дія» `.asice` and PrivatBank's ASiC-E, and sign with the bank's key; they were all checked this way and give the same
results as `ua-sign verify`.

## Layout

```text
.github/workflows/        tests on every push; GitHub Pages from main; a release with the single file for a v* tag
build.sh                  installs the dependencies on the first run and builds the page
build.mjs                 the single HTML file: esbuild, inlined styles and certificates, CSP pinned to the script's hash
src/core/                 no DOM; runs the same in the page and in Node
  bytes.ts, random.ts     byte helpers, the CSPRNG
  hash/                   DSTU 7564 (Kupyna), GOST 28147 / 34.311, SHA-1 / SHA-256
  math/                   GF(2^m) in the polynomial basis, the curve and the Montgomery ladder, integers
  dstu4145.ts             parameters, table Г.1, signing and verification
  zip.ts                  reading ZIP (inflate by DecompressionStream)
  xml/                    a DTD-free XML parser; Canonical XML and Exclusive C14N
  pki/                    DER, X.509, keys, CMS, time-stamps (and RFC 3161 requests), OCSP, paths, CAdES, XAdES, ASiC,
                          JKS, the CAdES signer
src/app/                  the page: template, styles, views; timestamp.ts — the one network exception
assets/                   the icon and the bundled public certificates
tests/, tools/            Node and browser tests, their helpers, the fixture generator
```

## Notes

- JavaScript has no constant-time guarantees; the Montgomery ladder runs the same number of steps for any key, but
  protection against side channels was not a goal (as in the C# reference). The private key lives in the page's memory
  only while it is open.
- Performance (Apple M2, Chrome): a PrivatBank `.sig` or a «Дія» `.asice` verifies in about 0.1 s; a signature takes a
  few milliseconds, plus the round trip to the time-stamping server.

## License

[MIT](LICENSE).
