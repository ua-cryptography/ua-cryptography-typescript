/**
 * Verification of every format end to end. Synthetic signatures made by the C# reference (ua-sign, tests/data/synthetic)
 * verify, and break when the data, the signature, the signed properties or the container change. When this machine has
 * the real signatures (UA_PRIVATE_SAMPLES, by default ../ua-cryptography-csharp/private), the PrivatBank .sig and the
 * "Дія" and PrivatBank ASiC-E verify against the bundled roots and intermediates exactly as the C# verifier reports them.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { bundledCertificates, hasPrivate, PRIVATE, zip } from '../tools/fixtures.mjs';
import { checker, load, root } from '../tools/load.mjs';

const P = await load('core/pki/verifier', 'core/pki/certificate', 'core/zip', 'core/bytes');
const { check, done } = checker();
const S = (name) => readFile(join(root, 'tests/data/synthetic', name));
const document = new Uint8Array(await S("document.txt"));
const trust257 = { trustAnchors: [P.Certificate.load(await S('signer-257.cer'))], extraCertificates: [] };
const trustGost = { trustAnchors: [P.Certificate.load(await S('signer-431-gost.cer'))], extraCertificates: [] };
const statuses = (report) => Object.fromEntries(report.checks.map((c) => [c.name, c.status]));
const failed = (result) => result.signatures.flatMap((s) => s.checks.filter((c) => c.status === 'failed').map((c) => c.name));
const detachedDocument = (name) => (name === null || name === 'document.txt' ? document : null);
const verify = (bytes, options, resolve = detachedDocument) => P.verifySignature(bytes, resolve, options);

// ---- Synthetic signatures, made by ua-sign --------------------------------------------------------------------------
for (const [file, options, format, level] of [
  ['cades-enveloped.p7s', trust257, 'CAdES (enveloped)', 'CAdES-B, enveloped, DSTU 7564-256'],
  ['cades-detached.p7s', trust257, 'CAdES (detached)', 'CAdES-B, detached, DSTU 7564-256'],
  ['cades-gost.p7s', trustGost, 'CAdES (enveloped)', 'CAdES-B, enveloped, GOST 34.311-95'],
  ['xades-detached.xml', trust257, 'XAdES (XML)', 'XAdES-B-B, detached, DSTU 7564-256'],
  ['asic-e.asice', trust257, 'ASiC-E', 'XAdES-B-B, detached, DSTU 7564-256'],
  ['asic-e-gost.asice', trustGost, 'ASiC-E', 'XAdES-B-B, detached, GOST 34.311-95'],
  ['asic-s.asics', trust257, 'ASiC-S', 'CAdES-B, detached, DSTU 7564-256'],
]) {
  const result = await verify(await S(file), options);
  check(`${file}: format`, [result.format, result.signatures.at(-1).format], [format, level]);
  check(`${file}: valid`, [result.isValid, failed(result)], [true, []]);
  const signature = result.signatures.at(-1);
  check(`${file}: signer`, signature.signer?.shortName, file.includes('gost') ? 'Test Signer GOST' : 'Тестовий підписувач');
  check(`${file}: the content is returned`, P.toHex([...result.signedFiles.values()][0] ?? new Uint8Array()), P.toHex(document));
  // Without trusted roots the self-signed certificate is a warning, not a failure.
  const untrusted = await verify(await S(file), { trustAnchors: [], extraCertificates: [] });
  check(`${file}: no roots → valid with a trust warning`, [untrusted.isValid, statuses(untrusted.signatures.at(-1))['signer: trust']], [true, 'warning']);
  // Another root → the path is not trusted.
  const other = await verify(await S(file), file.includes('gost') ? trust257 : trustGost);
  check(`${file}: another root → not trusted`, statuses(other.signatures.at(-1))['signer: trust'], 'failed');
}

// ---- Tampering -------------------------------------------------------------------------------------------------------
const changed = Uint8Array.from(document);
changed[5] ^= 1;
{
  const result = await verify(await S('cades-detached.p7s'), trust257, () => changed);
  check('detached CAdES over changed data', [result.isValid, failed(result)], [false, ['CMS: messageDigest']]);
  const missing = await verify(await S('cades-detached.p7s'), trust257, () => null);
  check('detached CAdES without the data', failed(missing), ['content']);
}
{
  const p7s = await S('cades-enveloped.p7s');
  const at = p7s.indexOf(Buffer.from(document)); // the encapsulated content
  const bad = new Uint8Array(p7s);
  bad[at + 3] ^= 1;
  check('enveloped CAdES with a changed byte of content', failed(await verify(bad, trust257)), ['CMS: messageDigest']);
  const sig = new Uint8Array(p7s);
  sig[sig.length - 5] ^= 1; // inside SignerInfo.signature, the last field
  check('enveloped CAdES with a changed signature', failed(await verify(sig, trust257)), ['CMS: signature']);
}
{
  const xml = (await S('xades-detached.xml')).toString('utf8');
  const result = await verify(new TextEncoder().encode(xml), trust257, () => changed);
  check('XAdES over changed data', failed(result), ["reference 'document.txt'"]);
  const time = /<xades:SigningTime>([^<]*)</.exec(xml)[1];
  const later = xml.replace(time, time.replace(/:\d\d(Z|[+-])/, ':59$1'));
  const props = await verify(new TextEncoder().encode(later), trust257);
  check('XAdES with changed signed properties', failed(props).some((n) => n.startsWith("reference '#")), true);
}
{
  const entries = await P.readZip(await S('asic-e.asice'));
  const rebuild = (patch) => zip(entries.map((e) => [e.name, patch(e), e.name === 'mimetype']));
  const tampered = rebuild((e) => (e.name === 'document.txt' ? changed : e.data));
  check('ASiC-E with a changed document', failed(await verify(tampered, trust257)), ["reference 'document.txt'"]);
  const extra = zip([...entries.map((e) => [e.name, e.data, e.name === 'mimetype']), ['unsigned.txt', new Uint8Array([1, 2, 3])]]);
  check('ASiC-E with an unsigned file added', failed(await verify(extra, trust257)), ["file 'unsigned.txt'"]);
  const compressedMime = zip(entries.map((e) => [e.name, e.data, false]));
  check('ASiC-E whose mimetype is compressed', failed(await verify(compressedMime, trust257)), ['mimetype']);
  const wrapped = rebuild((e) =>
    e.name.startsWith('META-INF/signatures')
      ? new TextEncoder().encode(new TextDecoder().decode(e.data).replace(/(<ds:Object>)/, '$1<xades:SignedProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="dup"/>'))
      : e.data,
  );
  check('ASiC-E with an injected element still verifies (unsigned part)', (await verify(wrapped, trust257)).isValid, true);
  const idOf = /URI="#([^"]+)"/.exec(new TextDecoder().decode(entries.find((e) => e.name.startsWith('META-INF/signatures')).data))[1];
  const duplicate = rebuild((e) =>
    e.name.startsWith('META-INF/signatures')
      ? new TextEncoder().encode(new TextDecoder().decode(e.data).replace(/(<ds:Object>)/, `$1<x Id="${idOf}"/>`))
      : e.data,
  );
  check('ASiC-E with a duplicate Id (signature wrapping) fails', (await verify(duplicate, trust257)).isValid, false);
}

// ---- Real signatures (not in the repository) -------------------------------------------------------------------------
if (!hasPrivate) {
  console.log(`verify: ${PRIVATE} not found — the real signatures are skipped`);
} else {
  const { anchors, extra } = await bundledCertificates(P);
  const bundled = { trustAnchors: anchors, extraCertificates: extra };
  const real = async (name) => verify(await readFile(join(PRIVATE, name)), bundled, () => null);
  const summary = (result) => result.signatures.flatMap((s) => s.checks.filter((c) => c.status !== 'passed').map((c) => `${c.status}: ${c.name}`));

  for (const name of ['pb/tosign.txt.sig', 'pb/valid/tosign.txt.sig', 'pb/ours/tosign.txt.sig']) {
    const result = await real(name);
    const s = result.signatures[0];
    check(`${name}: CAdES-T, valid`, [s.format, result.isValid], ['CAdES-T, enveloped, DSTU 7564-256', true]);
    check(`${name}: time-stamp verified via the bundled TSP certificate`, s.timeStampTime !== null && statuses(s)['signature time-stamp: signature'], 'passed');
    check(`${name}: only revocation is left as a warning`, summary(result), [
      `warning: signature time-stamp service: revocation of 'TSP-сервер КНЕДП АЦСК АТ КБ "ПриватБанк"'`,
      `warning: signer: revocation of '${s.signer.shortName}'`,
      `warning: signer: revocation of 'КНЕДП АЦСК АТ КБ "ПриватБанк"'`,
    ]);
  }
  {
    // As the C# verifier says without --certs: the bank's .sig has no CA and no TSP certificate.
    const result = await verify(await readFile(join(PRIVATE, 'pb/valid/tosign.txt.sig')), { trustAnchors: anchors, extraCertificates: [] }, () => null);
    const st = statuses(result.signatures[0]);
    check('PrivatBank .sig without the bundle: the time-stamp is a warning, the path fails', [st['signature time-stamp: service certificate'], st['signer: trust']], ['warning', 'failed']);
  }
  {
    const result = await real('ASIC-E/tosign.txt.asice');
    const s = result.signatures[1];
    check('Дія ASiC-E: XAdES-B-LT, valid', [result.format, s.format, result.isValid], ['ASiC-E', 'XAdES-B-LT, detached, DSTU 7564-256', true]);
    check('Дія ASiC-E: the zero issuerKeyHash OCSP response is matched', statuses(s)[`signer: revocation of '${s.signer.shortName}'`], 'passed');
    check('Дія ASiC-E: warnings', summary(result), [
      `warning: signature time-stamp service: revocation of 'TSP-сервер КНЕДП "Дія"'`,
      `warning: signer: revocation of '"Дія". Кваліфікований надавач електронних довірчих послуг'`,
    ]);
    const entries = await P.readZip(await readFile(join(PRIVATE, 'ASIC-E/tosign.txt.asice')));
    const tampered = zip(entries.map((e) => [e.name, e.name === 'tosign.txt' ? new TextEncoder().encode('xxxx') : e.data, e.name === 'mimetype']));
    check('Дія ASiC-E with a changed document', failed(await verify(tampered, bundled, () => null)), ["reference 'tosign.txt'"]);
  }
  {
    const result = await real('pb/tosign.txt.asice');
    check('PrivatBank ASiC-E (LT): valid, CA revocation good', [result.isValid, summary(result).length], [true, 1]);
    const b = await real('pb/tosign-B.asice');
    check('PrivatBank ASiC-E (B): valid', [b.isValid, b.signatures[1].format], [true, 'XAdES-B-B, detached, DSTU 7564-256']);
  }
}

done('verify');
