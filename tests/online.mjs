/**
 * The page's network exceptions, against the real services: PrivatBank's time-stamping and OCSP servers, the NBU's
 * OCSP server. Runs only with UA_ONLINE=1 (it needs the network and sends requests to them). A synthetic hash is stamped
 * and the token verified with the bundled certificates; the NBU's OCSP server answers about PrivatBank's CA and TSP
 * server. With the real signatures on this machine, a PrivatBank .sig is verified with the online status of every
 * certificate on its paths, as the page does it; with the real key store, a CAdES-T is made the way the page makes it,
 * verified here and — when available — by ua-sign.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bundledCertificates, hasPrivate, PRIVATE } from '../tools/fixtures.mjs';
import { checker, load, root } from '../tools/load.mjs';

if (process.env.UA_ONLINE !== '1') {
  console.log('online: set UA_ONLINE=1 to ask the time-stamping and OCSP servers of PrivatBank and the NBU — skipped');
  process.exit(0);
}

const P = await load('core/pki/tsp', 'core/pki/ocsp', 'core/pki/jks', 'core/pki/cades-signer', 'core/pki/verifier', 'core/pki/certificate', 'core/pki/report', 'core/pki/oids', 'core/hash/dstu7564', 'app/network');
const { check, done } = checker();
const { anchors, extra } = await bundledCertificates(P);
const URL_ = 'https://acsk.privatbank.ua/services/tsp/';

const stamped = new TextEncoder().encode(`online test ${Date.now()}`);
const imprint = P.Dstu7564.hash(stamped);
const token = await P.requestTimeStamp(URL_, imprint, P.Oid.Dstu7564_256);
check('the token answers the request (imprint, policy)', [token.policy, token.imprintAlgorithm], [P.Oid.TspPolicyDstu7564, P.Oid.Dstu7564_256]);
check('the time is now', Math.abs(token.genTime.getTime() - Date.now()) < 5 * 60 * 1000, true);
const report = new P.VerificationReport('online');
const tsa = token.verify(stamped, extra, report, 'time-stamp');
check('signed by the bank\'s TSP server', [tsa?.subject.get(P.Oid.SerialNumber), report.checks.every((c) => c.status === 'passed')], ['UA-14360570-2611', true]);

// ---- OCSP --------------------------------------------------------------------------------------------------------------
{
  // Public certificates: the bank's CMP server names the bank's responder; the bank's CA and TSP server name the NBU's
  // (both are certified by the NBU root directly). Each is asked at the responder its AIA names, as the page does.
  const bank = (serial) => extra.find((c) => c.subject.get(P.Oid.SerialNumber) === serial && c.shortName.includes('ПриватБанк'));
  const issuerOf = (c) => [...anchors, ...extra].find((i) => !i.equals(c) && c.isSignedBy(i));
  for (const [what, serial, url, responderName] of [
    ['the bank\'s CMP server', 'UA-14360570-2612', 'https://acsk.privatbank.ua/services/ocsp/', 'OCSP-сервер КНЕДП АЦСК АТ КБ "ПриватБанк"'],
    ['the bank\'s CA', 'UA-14360570-2610', 'https://zc.bank.gov.ua/services/ocsp/', 'OCSP-сервер Засвідчувальний центр'],
    ['the bank\'s TSP server', 'UA-14360570-2611', 'https://zc.bank.gov.ua/services/ocsp/', 'OCSP-сервер Засвідчувальний центр'],
  ]) {
    const certificate = bank(serial);
    const issuer = issuerOf(certificate);
    check(`${what}: names ${new URL(url).host}, asked over HTTPS`, P.ocspUrl(certificate), url);
    const response = await P.requestOcsp(url, certificate, issuer);
    const responder = response.findResponder([...extra, issuer]);
    check(`${what}: good (nonce echoed), signed by a responder the issuer certified`, [
      response.find(certificate, issuer)?.status,
      responder?.shortName,
      response.isSignedBy(responder),
      responder.equals(issuer) || (responder.isSignedBy(issuer) && responder.extendedKeyUsage.includes(P.Oid.KeyPurposeOcspSigning)),
    ], ['good', responderName, true, true]);
  }
}
if (!hasPrivate) {
  console.log('online: no real signatures on this machine — the .sig with an online status is skipped');
} else {
  const sig = await readFile(join(PRIVATE, 'pb', 'valid', 'tosign.txt.sig'));
  const options = { trustAnchors: anchors, extraCertificates: extra };
  const offline = await P.verifySignature(sig, () => null, options);
  const targets = offline.unresolvedRevocations.filter((t) => P.ocspUrl(t.certificate));
  check('PrivatBank .sig: every unresolved certificate names a responder the page may ask', targets.length, offline.unresolvedRevocations.length);
  check('PrivatBank .sig: the signer at the bank, its CA and the TSP server at the NBU', targets.map((t) => `${t.certificate.shortName} @ ${new URL(P.ocspUrl(t.certificate)).host}`).sort(), [
    `${offline.signatures[0].signer.shortName} @ acsk.privatbank.ua`,
    'TSP-сервер КНЕДП АЦСК АТ КБ "ПриватБанк" @ zc.bank.gov.ua',
    'КНЕДП АЦСК АТ КБ "ПриватБанк" @ zc.bank.gov.ua',
  ].sort());
  const responses = await Promise.all(targets.map((t) => P.requestOcsp(P.ocspUrl(t.certificate), t.certificate, t.issuer)));
  const result = await P.verifySignature(sig, () => null, { ...options, onlineRevocation: responses, onlineAsked: targets.map((t) => t.certificate) });
  const s = result.signatures[0];
  const revocations = s.checks.filter((c) => c.name.includes(': revocation of '));
  check('PrivatBank .sig: valid with no warnings', [result.isValid, s.hasWarnings, s.checks.filter((c) => c.status !== 'passed').map((c) => c.name)], [true, false, []]);
  check('PrivatBank .sig: three statuses, all good by online responses', revocations.map((c) => /^good, online response of /.test(c.details)), [true, true, true]);
}

const passwordFile = process.env.UA_PRIVATE_JKS_PASSWORD_FILE ?? join(PRIVATE, 'pb', 'temp.txt');
const store = hasPrivate ? readdirSync(join(PRIVATE, 'pb')).find((n) => n.endsWith('.jks')) : undefined;
if (!store || !existsSync(passwordFile)) {
  console.log('online: no real PrivatBank key store on this machine — the CAdES-T signature is skipped');
} else {
  const password = (await readFile(passwordFile, 'utf8')).trim();
  const signer = P.openSigningKey(P.loadJks(await readFile(join(PRIVATE, 'pb', store)), password), password);
  const url = P.timeStampUrl(signer.certificate);
  check('the bank\'s certificate names its TSP server, taken over HTTPS', url, URL_);
  const data = new TextEncoder().encode('Підписано з CAdES-T в тесті.\n');
  const signature = await P.signCadesT(data, signer, (h, oid) => P.requestTimeStamp(url, h, oid));
  const result = await P.verifySignature(signature, () => null, { trustAnchors: anchors, extraCertificates: extra });
  const s = result.signatures[0];
  check('PrivatBank key, CAdES-T: valid, only revocation warnings', [result.isValid, s.format, s.checks.filter((c) => c.status !== 'passed').every((c) => c.name.includes('revocation'))], [true, 'CAdES-T, enveloped, DSTU 7564-256', true]);

  const published = join(root, '..', 'ua-cryptography-csharp', 'artifacts', 'ua-sign');
  const uaSign = process.env.UA_SIGN ?? (existsSync(published) ? readdirSync(published).map((rid) => join(published, rid, 'ua-sign')).find((p) => existsSync(p)) : undefined);
  if (uaSign) {
    const work = await mkdtemp(join(tmpdir(), 'ua-online-'));
    await writeFile(join(work, 'doc.txt.sig'), signature);
    const out = execFileSync(uaSign, ['verify', '--in', join(work, 'doc.txt.sig'), '--quiet', '--trust', join(root, 'assets/certificates/roots/nbu-root-2036-dstu7564.cer'), '--certs', join(root, 'assets/certificates/intermediates/privatbank-PB-2026-NBU.p7b')], { encoding: 'utf8' });
    check('PrivatBank key, CAdES-T: ua-sign verifies it', out.trim().split('\n').at(-1), 'Result: VALID (3 warnings)');
    await rm(work, { recursive: true, force: true });
  }
}

done('online');
