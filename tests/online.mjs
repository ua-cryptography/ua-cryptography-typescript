/**
 * The page's one network exception, against the real service: PrivatBank's time-stamping server. Runs only with
 * UA_ONLINE=1 (it needs the network and sends requests to the bank). A synthetic hash is stamped and the token verified
 * with the bundled certificates; with the real PrivatBank key store on this machine, a CAdES-T is made the way the page
 * makes it, verified here and — when available — by ua-sign.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bundledCertificates, hasPrivate, PRIVATE } from '../tools/fixtures.mjs';
import { checker, load, root } from '../tools/load.mjs';

if (process.env.UA_ONLINE !== '1') {
  console.log('online: set UA_ONLINE=1 to ask PrivatBank\'s time-stamping server — skipped');
  process.exit(0);
}

const P = await load('core/pki/tsp', 'core/pki/jks', 'core/pki/cades-signer', 'core/pki/verifier', 'core/pki/certificate', 'core/pki/report', 'core/pki/oids', 'core/hash/dstu7564', 'app/timestamp');
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
