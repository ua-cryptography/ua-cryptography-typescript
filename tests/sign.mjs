/**
 * Signing with a key from a JKS store: the store and its key protector (wrong passwords refused), CAdES in PrivatBank's
 * layout (docs/provider-formats.md, section 1) checked field by field, verified here, and — when the C# reference is
 * at hand (UA_SIGN=/path/to/ua-sign, or a published one next to this repository) — verified by ua-sign as well. With the
 * real PrivatBank key store on this machine, the same with the bank's key and the NBU root. CAdES-T is made against a
 * time-stamping service of the test itself (tests/online.mjs asks PrivatBank's real one).
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bundledCertificates, hasPrivate, PRIVATE } from '../tools/fixtures.mjs';
import { checker, load, root } from '../tools/load.mjs';

const P = await load('core/pki/jks', 'core/pki/cades-signer', 'core/pki/verifier', 'core/pki/certificate', 'core/pki/cms', 'core/pki/asn1', 'core/pki/oids', 'core/pki/algorithms', 'core/pki/tsp', 'core/bytes');
const { check, done } = checker();
const S = (name) => readFile(join(root, 'tests/data/synthetic', name));
const PASSWORD = 'synthetic test password';
const data = new TextEncoder().encode('Документ для підпису — synthetic.\n');

const published = join(root, '..', 'ua-cryptography-csharp', 'artifacts', 'ua-sign');
const UA_SIGN =
  process.env.UA_SIGN ?? (existsSync(published) ? readdirSync(published).map((rid) => join(published, rid, 'ua-sign')).find((p) => existsSync(p)) : undefined);

const work = await mkdtemp(join(tmpdir(), 'ua-sign-'));
const uaSign = async (name, bytes, ...args) => {
  await writeFile(join(work, name), bytes);
  try {
    return execFileSync(UA_SIGN, ['verify', '--in', join(work, name), '--quiet', ...args], { encoding: 'utf8' }).trim().split('\n').at(-1);
  } catch (e) {
    return (e.stdout ?? '').trim().split('\n').at(-1) || e.message;
  }
};

// ---- The key store ---------------------------------------------------------------------------------------------------
const jks = await S('signer-257.jks');
const entries = P.loadJks(jks, PASSWORD);
check('JKS: one private key entry', entries.map((e) => [e.kind, e.alias, e.chain.length]), [['key', 'key', 1]]);
for (const [label, run] of [
  ['a wrong store password', () => P.loadJks(jks, PASSWORD + '!')],
  ['a damaged store', () => P.loadJks(Uint8Array.from(jks, (b, i) => (i === 100 ? b ^ 1 : b)), PASSWORD)],
  ['a wrong key password', () => P.openSigningKey(entries, PASSWORD, undefined, 'other')],
]) {
  let error = null;
  try {
    run();
  } catch (e) {
    error = e.name;
  }
  check(`JKS: ${label} is refused`, error, 'WrongPasswordError');
}
const signer = P.openSigningKey(entries, PASSWORD);
const certificate = P.Certificate.load(await S('signer-257.cer'));
check('JKS: the key matches its certificate', [signer.certificate.equals(certificate), signer.key.publicKey.equals(certificate.publicKey)], [true, true]);

// ---- CAdES in PrivatBank's layout --------------------------------------------------------------------------------------
/** The profile of provider-formats.md, section 1, minus the time-stamp: what the bank puts where. */
function assertProfile(label, signature, content, signerCertificate, hashOid = P.Oid.Dstu7564_256) {
  const cms = P.SignedData.load(signature);
  check(`${label}: version 1, id-data, the content inside`, [cms.version, cms.contentType, P.toHex(cms.content ?? new Uint8Array())], [1, P.Oid.Data, P.toHex(content)]);
  check(`${label}: only the signer's certificate`, cms.certificates.map((c) => c.equals(signerCertificate)), [true]);
  check(`${label}: one SignerInfo v1 by issuer and serial`, cms.signerInfos.map((s) => [s.version, s.serialNumber === signerCertificate.serialNumber, s.issuer.equals(signerCertificate.issuer)]), [[1, true, true]]);
  const s = cms.signerInfos[0];
  check(`${label}: algorithms`, [s.digestAlgorithm, s.signatureAlgorithm], [hashOid, P.signatureAlgorithmFor(hashOid)]);
  check(`${label}: signed attributes`, s.signedAttributes.map((a) => a.oid).sort(), [P.Oid.ContentType, P.Oid.MessageDigest, P.Oid.SigningTime, P.Oid.SigningCertificateV2].sort());
  check(`${label}: signingTime is a UTCTime in whole seconds`, [s.findSigned(P.Oid.SigningTime).value.tag, s.findSigned(P.Oid.SigningTime).value.time().getUTCMilliseconds()], [P.Tag.UtcTime, 0]);
  check(`${label}: messageDigest`, P.toHex(s.findSigned(P.Oid.MessageDigest).value.octetString()), P.toHex(P.hash(hashOid, content, signerCertificate.dke)));
  const essCertId = s.findSigned(P.Oid.SigningCertificateV2).value.at(0).at(0);
  check(`${label}: ESSCertIDv2 names the hash, the certificate, the issuer and serial`, [
    essCertId.at(0).at(0).oid(),
    P.toHex(essCertId.at(1).octetString()),
    P.toHex(essCertId.at(2).at(0).at(0).at(0).encoded),
    essCertId.at(2).at(1).integer() === signerCertificate.serialNumber,
  ], [hashOid, P.toHex(P.hash(hashOid, signerCertificate.encoded)), P.toHex(signerCertificate.issuer.encoded), true]);
  check(`${label}: no unsigned attributes (CAdES-B)`, s.unsignedAttributes.length, 0);
  check(`${label}: D is ${signerCertificate.publicKey.domain.minimumSignatureBits / 8} bytes`, s.signature.length, signerCertificate.publicKey.domain.minimumSignatureBits / 8);
}

const signature = P.signCades(data, signer);
assertProfile('DSTU 7564', signature, data, certificate);
const options = { trustAnchors: [certificate], extraCertificates: [] };
const verified = await P.verifySignature(signature, () => null, options);
check('DSTU 7564: verifies', [verified.isValid, verified.signatures[0].format], [true, 'CAdES-B, enveloped, DSTU 7564-256']);
const twice = P.signCades(data, signer);
check('a fresh nonce every time', P.toHex(twice) !== P.toHex(signature), true);

const gostEntries = P.loadJks(await S('signer-431-gost.jks'), PASSWORD);
const gostSigner = P.openSigningKey(gostEntries, PASSWORD);
const gostSignature = P.signCades(data, gostSigner, { hashOid: P.Oid.Gost34311 });
assertProfile('GOST 34.311', gostSignature, data, gostSigner.certificate, P.Oid.Gost34311);
check('GOST 34.311, m = 431: verifies', (await P.verifySignature(gostSignature, () => null, { trustAnchors: [gostSigner.certificate], extraCertificates: [] })).isValid, true);

const detached = P.signCades(data, signer, { detached: true });
check('detached: no content inside', P.SignedData.load(detached).content, null);
check('detached: verifies with the data', (await P.verifySignature(detached, () => data, options)).isValid, true);

// ---- CAdES-T: a time-stamping service of the tests, reached through a stand-in for fetch -------------------------------
/**
 * A TSA signing with the GOST test key: it reads the request as RFC 3161 has it and answers with a token over the
 * requested imprint, echoing the nonce — or, for the negative tests, a changed imprint, nonce or status.
 */
function testTsa({ tamper } = {}) {
  const requests = [];
  const fetchImpl = async (url, init) => {
    requests.push({ url, init });
    const request = P.Asn1.parse(new Uint8Array(init.body));
    const hashOid = request.at(1).at(0).at(0).oid();
    let imprint = request.at(1).at(1).octetString();
    let nonce = request.at(2).integer();
    if (tamper === 'refused') return new Response(P.Der.sequence(P.Der.sequence(P.Der.integer(2))), { status: 200 });
    if (tamper === 'imprint') imprint = Uint8Array.from(imprint, (b, i) => (i === 0 ? b ^ 1 : b));
    if (tamper === 'nonce') nonce += 1n;
    const tstInfo = P.Der.sequence(
      P.Der.integer(1),
      P.Der.objectIdentifier(P.Oid.TspPolicyDstu7564),
      P.Der.sequence(P.Der.algorithm(hashOid), P.Der.octetString(imprint)),
      P.Der.integer(424242),
      P.Der.generalizedTime(new Date()),
      P.Der.integer(nonce),
    );
    const signed = P.signAttributes(P.Oid.TstInfo, tstInfo, gostSigner, hashOid);
    const token = P.signedData(P.Oid.TstInfo, tstInfo, hashOid, gostSigner.certificate, P.signerInfo(signed, gostSigner.certificate, hashOid));
    return new Response(P.Der.sequence(P.Der.sequence(P.Der.integer(0)), token), { status: 200, headers: { 'content-type': 'application/timestamp-reply' } });
  };
  return { requests, stamper: (imprint, hashOid) => P.requestTimeStamp('https://tsa.test/tsp/', imprint, hashOid, fetchImpl) };
}
{
  const tsa = testTsa();
  const stamped = await P.signCadesT(data, signer, tsa.stamper);
  const cms = P.SignedData.load(stamped);
  const unsigned = cms.signerInfos[0].unsignedAttributes;
  check('CAdES-T: one unsigned attribute, signatureTimeStampToken', unsigned.map((a) => a.oid), [P.Oid.SignatureTimeStampToken]);
  const request = P.Asn1.parse(new Uint8Array(tsa.requests[0].init.body));
  check('CAdES-T: the request carries only the hash of the signature value, and asks for the certificate', [
    tsa.requests.length,
    tsa.requests[0].init.method,
    tsa.requests[0].init.headers['content-type'],
    P.toHex(request.at(1).at(1).octetString()),
    request.at(3).boolean(),
  ], [1, 'POST', 'application/timestamp-query', P.toHex(P.hash(P.Oid.Dstu7564_256, cms.signerInfos[0].signature)), true]);
  const result = await P.verifySignature(stamped, () => null, { trustAnchors: [certificate, gostSigner.certificate], extraCertificates: [] });
  const s = result.signatures[0];
  const st = Object.fromEntries(s.checks.map((c) => [c.name, c.status]));
  check('CAdES-T: verifies, the time-stamp covers the signature and is signed by the TSA', [result.isValid, s.format, st['signature time-stamp: imprint'], st['signature time-stamp: signature']], [true, 'CAdES-T, enveloped, DSTU 7564-256', 'passed', 'passed']);
  check('CAdES-T: the validation time is the time-stamp', s.timeStampTime !== null && s.validationTime === s.timeStampTime, true);
  if (UA_SIGN) {
    const roots = join(work, 'roots.pem');
    await writeFile(roots, [certificate, gostSigner.certificate].map((c) => `-----BEGIN CERTIFICATE-----\n${P.toBase64(c.encoded)}\n-----END CERTIFICATE-----\n`).join(''));
    check('CAdES-T: ua-sign verifies it', await uaSign('t.p7s', stamped, '--trust', roots), 'Result: VALID (1 warning)');
  }
  for (const tamper of ['imprint', 'nonce', 'refused']) {
    let error = '';
    try {
      await P.signCadesT(data, signer, testTsa({ tamper }).stamper);
    } catch (e) {
      error = e.message;
    }
    check(`CAdES-T: a response with a wrong ${tamper} is refused`, /covers other data|different nonce|refused the request/.test(error), true);
  }
  let unreachable = '';
  try {
    await P.signCadesT(data, signer, (imprint, oid) => P.requestTimeStamp('https://tsa.test/', imprint, oid, async () => { throw new TypeError('Failed to fetch'); }));
  } catch (e) {
    unreachable = e.message;
  }
  check('CAdES-T: an unreachable service is reported', unreachable, 'The time-stamping service https://tsa.test/ could not be reached (Failed to fetch).');
}

// ---- The C# reference verifies what this code signs -------------------------------------------------------------------
if (!UA_SIGN) {
  console.log('sign: ua-sign not found (set UA_SIGN) — the cross-check with the C# reference is skipped');
} else {
  check('ua-sign verifies the DSTU 7564 signature', await uaSign('a.p7s', signature, '--trust', join(root, 'tests/data/synthetic/signer-257.cer')), 'Result: VALID');
  check('ua-sign verifies the GOST signature', await uaSign('b.p7s', gostSignature, '--trust', join(root, 'tests/data/synthetic/signer-431-gost.cer')), 'Result: VALID');
  await writeFile(join(work, 'c.txt'), data);
  check('ua-sign verifies the detached signature', await uaSign('c.p7s', detached, '--data', join(work, 'c.txt'), '--trust', join(root, 'tests/data/synthetic/signer-257.cer')), 'Result: VALID');
  const bad = Uint8Array.from(signature);
  bad[bad.length - 3] ^= 1;
  check('ua-sign rejects a tampered one', await uaSign('d.p7s', bad, '--trust', join(root, 'tests/data/synthetic/signer-257.cer')), 'Result: INVALID');
}

// ---- The real PrivatBank key store ------------------------------------------------------------------------------------
const passwordFile = process.env.UA_PRIVATE_JKS_PASSWORD_FILE ?? join(PRIVATE, 'pb', 'temp.txt');
const storeFile = hasPrivate ? readdirSync(join(PRIVATE, 'pb')).find((n) => n.endsWith('.jks')) : undefined;
if (!storeFile || !existsSync(passwordFile)) {
  console.log('sign: no real PrivatBank key store on this machine — skipped');
} else {
  const password = (await readFile(passwordFile, 'utf8')).trim();
  const bank = P.openSigningKey(P.loadJks(await readFile(join(PRIVATE, 'pb', storeFile)), password), password);
  check('PrivatBank JKS: the path is rebuilt from the signing certificate', bank.chain.length, 3);
  check('PrivatBank JKS: the signing certificate allows signing', (bank.certificate.keyUsage & 0b11) !== 0, true);
  const sig = P.signCades(data, bank);
  assertProfile('PrivatBank key', sig, data, bank.certificate);
  const { anchors, extra } = await bundledCertificates(P);
  const result = await P.verifySignature(sig, () => null, { trustAnchors: anchors, extraCertificates: extra });
  check('PrivatBank key: verifies up to the NBU root', [result.isValid, result.signatures[0].checks.filter((c) => c.status === 'failed').length], [true, 0]);
  if (UA_SIGN) {
    check(
      'PrivatBank key: ua-sign verifies it',
      await uaSign('pb.p7s', sig, '--trust', join(root, 'assets/certificates/roots/nbu-root-2036-dstu7564.cer'), '--certs', join(root, 'assets/certificates/intermediates/privatbank-knedp.cer')),
      'Result: VALID (2 warnings)',
    );
  }
}
await rm(work, { recursive: true, force: true });

done('sign');
