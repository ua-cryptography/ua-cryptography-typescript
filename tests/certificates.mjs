/**
 * Real public certificates: the ЦЗО and NBU roots (GOST 34.311 and DSTU 7564), the "Дія" and PrivatBank CAs chained to
 * them, the PrivatBank bundle of its caIssuers address, and five CA certificates of 2005–2015 with three different DKEs —
 * parsed, their keys decoded and checked (sections 8 and 10.1), and their signatures verified.
 */
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { checker, load, root } from '../tools/load.mjs';

const P = await load('core/pki/certificate', 'core/pki/oids');
const { check, done } = checker();
const read = async (...path) => P.Certificate.load(await readFile(join(root, ...path)));

const roots = {};
for (const name of await readdir(join(root, 'assets/certificates/roots'))) {
  const c = await read('assets/certificates/roots', name);
  roots[name] = c;
  check(`${name}: self-signed and verifies`, c.isSelfIssued && c.isSignedBy(c), true);
  check(`${name}: m = 431`, c.publicKey.domain.field.m, 431);
  check(`${name}: CA`, c.isCa, true);
}

const dia = await read('assets/certificates/intermediates/dia-knedp.cer');
check('Дія CA → ЦЗО 2036', dia.isSignedBy(roots['czo-root-2036-dstu7564.cer']), true);
check('Дія CA is not signed by the NBU root', dia.isSignedBy(roots['nbu-root-2036-dstu7564.cer']), false);
check('Дія CA: m = 257, no DKE', [dia.publicKey.domain.field.m, dia.publicKey.dke], [257, null]);
check('Дія CA: signed with DSTU 4145 + DSTU 7564', dia.signatureAlgorithm, P.Oid.Dstu4145WithDstu7564);
const pb = await read('assets/certificates/intermediates/privatbank-knedp.cer');
check('ПриватБанк CA → NBU 2036', pb.isSignedBy(roots['nbu-root-2036-dstu7564.cer']), true);
check('ПриватБанк CA: subject serial', pb.subject.get(P.Oid.SerialNumber), 'UA-14360570-2610');

const bundle = P.loadCertificates(await readFile(join(root, 'assets/certificates/intermediates/privatbank-PB-2026-NBU.p7b')));
check('PB-2026-NBU.p7b: 41 certificates', bundle.length, 41);
const tsp = bundle.find((c) => c.subject.get(P.Oid.SerialNumber) === 'UA-14360570-2611');
check('PB bundle: the TSP server 2611 → NBU 2036', tsp?.isSignedBy(roots['nbu-root-2036-dstu7564.cer']), true);
check('PB bundle: the TSP server has timeStamping EKU', tsp?.extendedKeyUsage.includes('1.3.6.1.5.5.7.3.8'), true);
check('PB bundle: holds the PrivatBank CA', bundle.some((c) => c.equals(pb)), true);

// Historical: GOST 34.311 with the issuer's DKE.
const historical = {};
for (const name of await readdir(join(root, 'tests/data/historical'))) {
  if (name.endsWith('.crt')) historical[name] = await read('tests/data/historical', name);
}
for (const [child, parent] of [
  ['czo-root-2005.crt', 'czo-root-2005.crt'],
  ['ucc-ca-2010.crt', 'czo-root-2005.crt'],
  ['ucc-tsp-2010.crt', 'ucc-ca-2010.crt'],
  ['bitis-root-2009.crt', 'bitis-root-2009.crt'],
  ['bitis-corp-2009.crt', 'bitis-root-2009.crt'],
]) {
  check(`${child} is signed by ${parent}`, historical[child].isSignedBy(historical[parent]), true);
}
check('ucc-tsp-2010 is not signed by the 2005 root', historical['ucc-tsp-2010.crt'].isSignedBy(historical['czo-root-2005.crt']), false);
check('czo-root-2005: explicit m = 431 with a DKE', [historical['czo-root-2005.crt'].publicKey.domain.field.m, !!historical['czo-root-2005.crt'].publicKey.dke], [431, true]);

// A changed byte in the TBS breaks the signature.
{
  const bytes = dia.encoded.slice();
  const i = bytes.length - 200;
  bytes[i] ^= 1;
  let ok;
  try {
    ok = P.Certificate.load(bytes).isSignedBy(roots['czo-root-2036-dstu7564.cer']);
  } catch {
    ok = false;
  }
  check('a tampered certificate does not verify', ok, false);
}

done('certificates');
