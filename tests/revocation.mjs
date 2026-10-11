/**
 * The online revocation check: the OCSP request the page sends (RFC 6960: one CertID by SHA-1, a nonce), the checks on
 * the answer (status, nonce, the certificate asked for), and verification with an online response — good, revoked
 * before or after the signing time, from a responder without authority. A synthetic CA (the GOST test key) issues a
 * certificate for the m = 257 test key that names PrivatBank's OCSP server, and a responder of the test answers through
 * a stand-in for fetch. tests/online.mjs asks the bank's real responder.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { checker, load, root } from '../tools/load.mjs';

const P = await load('core/pki/jks', 'core/pki/cades-signer', 'core/pki/verifier', 'core/pki/certificate', 'core/pki/ocsp', 'core/pki/asn1', 'core/pki/oids', 'core/hash/sha', 'core/bytes', 'app/network');
const { check, done } = checker();
const S = (name) => readFile(join(root, 'tests/data/synthetic', name));
const PASSWORD = 'synthetic test password';
const utf8 = (s) => new TextEncoder().encode(s);
const DAY = 24 * 60 * 60 * 1000;

const caKey = P.openSigningKey(P.loadJks(await S('signer-431-gost.jks'), PASSWORD), PASSWORD);
const leafKey = P.openSigningKey(P.loadJks(await S('signer-257.jks'), PASSWORD), PASSWORD);
const ALGORITHM = P.Oid.Dstu4145WithGost34311;

// ---- Synthetic certificates ------------------------------------------------------------------------------------------
const name = (cn) => P.Der.sequence(P.Der.setOf(P.Der.sequence(P.Der.objectIdentifier(P.Oid.CommonName), P.Der.encode(P.Tag.Utf8String, utf8(cn)))));
const extension = (oid, value, critical = false) =>
  P.Der.sequence(P.Der.objectIdentifier(oid), ...(critical ? [P.Der.encode(P.Tag.Boolean, Uint8Array.of(0xff))] : []), P.Der.octetString(value));
const bitString = (bytes) => P.Der.encode(P.Tag.BitString, P.concat(Uint8Array.of(0), bytes));

/** A v3 certificate signed with `issuerKey`: a CA, an OCSP responder or an end entity naming `ocsp` in its AIA. */
function issue({ serial, subject, issuer, spki, issuerKey, ca = false, ocspSigning = false, ocsp = null }) {
  const extensions = [];
  if (ca) extensions.push(extension(P.Oid.BasicConstraints, P.Der.sequence(P.Der.encode(P.Tag.Boolean, Uint8Array.of(0xff))), true));
  if (ocspSigning) extensions.push(extension(P.Oid.ExtendedKeyUsage, P.Der.sequence(P.Der.objectIdentifier(P.Oid.KeyPurposeOcspSigning))));
  if (ocsp) extensions.push(extension(P.Oid.AuthorityInfoAccess, P.Der.sequence(P.Der.sequence(P.Der.objectIdentifier(P.Oid.AccessOcsp), P.Der.encode(0x86, utf8(ocsp))))));
  const now = Date.now();
  const tbs = P.Der.sequence(
    P.Der.explicit(0, P.Der.integer(2)),
    P.Der.integer(serial),
    P.Der.algorithm(ALGORITHM),
    issuer,
    P.Der.sequence(P.Der.utcTime(new Date(now - DAY)), P.Der.utcTime(new Date(now + 365 * DAY))),
    subject,
    spki,
    P.Der.explicit(3, P.Der.sequence(...extensions)),
  );
  return P.Certificate.load(P.Der.sequence(tbs, P.Der.algorithm(ALGORITHM), bitString(P.Der.octetString(issuerKey.key.sign(ALGORITHM, tbs)))));
}

const caName = name('Test CA with OCSP');
const ca = issue({ serial: 1, subject: caName, issuer: caName, spki: caKey.certificate.spki, issuerKey: caKey, ca: true });
const leaf = issue({ serial: 0x1234567890n, subject: name('Test signer with OCSP'), issuer: caName, spki: leafKey.certificate.spki, issuerKey: caKey, ocsp: 'http://acsk.privatbank.ua/services/ocsp/' });
const responder = issue({ serial: 2, subject: name('Test OCSP responder'), issuer: caName, spki: leafKey.certificate.spki, issuerKey: caKey, ocspSigning: true });
check('the synthetic CA is a self-signed CA', [ca.isCa, ca.isSignedBy(ca)], [true, true]);
check('the leaf is issued by it', leaf.isSignedBy(ca), true);

// ---- The request -------------------------------------------------------------------------------------------------------
const nonce = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
const request = P.Asn1.parse(P.createOcspRequest(leaf, ca, nonce));
const certId = request.at(0).at(0).at(0).at(0);
check('request: one CertID by SHA-1 of the issuer name and key, and the serial number', [
  request.at(0).at(0).count,
  certId.at(0).at(0).oid(),
  P.toHex(certId.at(1).octetString()),
  P.toHex(certId.at(2).octetString()),
  certId.at(3).integer(),
], [1, P.Oid.Sha1, P.toHex(P.sha1(ca.subject.encoded)), P.toHex(P.sha1(ca.publicKeyBits)), leaf.serialNumber]);
const requestExtension = request.at(0).at(1);
check('request: the nonce extension, [2] EXPLICIT', [requestExtension.isContext(2), requestExtension.at(0).at(0).at(0).oid(), P.toHex(requestExtension.at(0).at(0).at(1).octetString())], [true, P.Oid.OcspNonce, P.toHex(P.Der.octetString(nonce))]);

// ---- A responder of the test, reached through a stand-in for fetch -----------------------------------------------------
/**
 * Answers an OCSP request with a response signed by `signer` (the CA itself unless told otherwise), echoing the nonce —
 * or, for the negative tests, a changed nonce, none, another certificate, an error status or an HTTP error.
 */
function testResponder({ status = 'good', revokedAt = null, signer = { key: caKey, certificate: ca }, tamper = null } = {}) {
  const requests = [];
  const fetchImpl = async (url, init) => {
    requests.push({ url, init });
    if (tamper === 'http') return new Response('busy', { status: 503 });
    if (tamper === 'unreachable') throw new TypeError('Failed to fetch');
    if (tamper === 'refused') return new Response(P.Der.sequence(P.Der.encode(P.Tag.Enumerated, Uint8Array.of(1))), { status: 200 });
    const tbsRequest = P.Asn1.parse(new Uint8Array(init.body)).at(0);
    const id = tbsRequest.at(0).at(0).at(0);
    let certId = id.encoded;
    if (tamper === 'other') certId = P.Der.sequence(id.at(0).encoded, id.at(1).encoded, id.at(2).encoded, P.Der.integer(id.at(3).integer() + 1n));
    let nonceValue = tbsRequest.at(1).at(0).at(0).at(1).octetString();
    if (tamper === 'nonce') nonceValue = Uint8Array.from(nonceValue, (b, i) => (i === nonceValue.length - 1 ? b ^ 1 : b));
    const now = new Date();
    const certStatus =
      status === 'good' ? Uint8Array.of(0x80, 0) : status === 'revoked' ? P.Der.implicit(1, P.Der.sequence(P.Der.generalizedTime(revokedAt))) : Uint8Array.of(0x82, 0);
    const tbs = P.Der.sequence(
      P.Der.explicit(1, signer.certificate.subject.encoded),
      P.Der.generalizedTime(now),
      P.Der.sequence(P.Der.sequence(certId, certStatus, P.Der.generalizedTime(now))),
      ...(tamper === 'no-nonce' ? [] : [P.Der.explicit(1, P.Der.sequence(P.Der.sequence(P.Der.objectIdentifier(P.Oid.OcspNonce), P.Der.octetString(nonceValue))))]),
    );
    const basic = P.Der.sequence(
      tbs,
      P.Der.algorithm(ALGORITHM),
      bitString(P.Der.octetString(signer.key.key.sign(ALGORITHM, tbs))),
      P.Der.explicit(0, P.Der.sequence(signer.certificate.encoded)),
    );
    const body = P.Der.sequence(P.Der.encode(P.Tag.Enumerated, Uint8Array.of(0)), P.Der.explicit(0, P.Der.sequence(P.Der.objectIdentifier(P.Oid.OcspBasic), P.Der.octetString(basic))));
    return new Response(body, { status: 200, headers: { 'content-type': 'application/ocsp-response' } });
  };
  return { requests, ask: () => P.requestOcsp(P.ocspUrl(leaf), leaf, ca, fetchImpl) };
}

check('the leaf names PrivatBank\'s responder, asked over HTTPS', P.ocspUrl(leaf), 'https://acsk.privatbank.ua/services/ocsp/');
check('the NBU\'s responder is asked too, over HTTPS', P.ocspUrl(issue({ serial: 5, subject: name('y'), issuer: caName, spki: leafKey.certificate.spki, issuerKey: caKey, ocsp: 'http://zc.bank.gov.ua/services/ocsp/' })), 'https://zc.bank.gov.ua/services/ocsp/');
check('a certificate naming no responder of PrivatBank or the NBU is not asked', [P.ocspUrl(ca), ...['http://ocsp.example.com/', 'http://czo.gov.ua/services/ocsp/', 'http://bank.gov.ua.example.com/'].map((ocsp) => P.ocspUrl(issue({ serial: 3, subject: name('x'), issuer: caName, spki: leafKey.certificate.spki, issuerKey: caKey, ocsp })))], [null, null, null, null]);
{
  const responderOfTest = testResponder();
  const response = await responderOfTest.ask();
  const sent = responderOfTest.requests[0];
  check('request: one POST of application/ocsp-request, no credentials', [responderOfTest.requests.length, sent.url, sent.init.method, sent.init.headers['content-type'], sent.init.credentials], [1, 'https://acsk.privatbank.ua/services/ocsp/', 'POST', 'application/ocsp-request', 'omit']);
  check('response: about the leaf, good, signed by the CA', [response.find(leaf, ca)?.status, response.isSignedBy(ca)], ['good', true]);
  const second = testResponder();
  await second.ask();
  check('a fresh nonce every time', P.toHex(new Uint8Array(sent.init.body)) !== P.toHex(new Uint8Array(second.requests[0].init.body)), true);
}
for (const [tamper, message] of [
  ['nonce', /does not echo the nonce/],
  ['no-nonce', /does not echo the nonce/],
  ['other', /not about the certificate/],
  ['refused', /returned status 1/],
  ['http', /answered HTTP 503/],
  ['unreachable', /could not be reached \(Failed to fetch\)/],
]) {
  let error = '';
  try {
    await testResponder({ tamper }).ask();
  } catch (e) {
    error = e.message;
  }
  check(`a response with ${tamper} is refused`, message.test(error), true);
}

// ---- Verification with an online response ------------------------------------------------------------------------------
const signer = { ...leafKey, certificate: leaf, chain: [leaf, ca] };
const data = utf8('Документ, підписаний для перевірки статусу.\n');
const signature = P.signCades(data, signer);
const options = { trustAnchors: [ca], extraCertificates: [] };
const revocationCheck = `signer: revocation of '${leaf.shortName}'`;
const checkOf = (result) => result.signatures[0].checks.find((c) => c.name === revocationCheck);

const offline = await P.verifySignature(signature, () => null, options);
check('offline: valid, the status is a warning', [offline.isValid, checkOf(offline).status, checkOf(offline).details], [true, 'warning', 'no OCSP response in the signature; the current status was not checked online']);
check('offline: the leaf is what an online check would ask about', offline.unresolvedRevocations.map((r) => [r.certificate.equals(leaf), r.issuer.equals(ca)]), [[true, true]]);

const withOnline = async (responder) => P.verifySignature(signature, () => null, { ...options, onlineRevocation: [await responder.ask()] });
{
  const result = await withOnline(testResponder());
  const c = checkOf(result);
  check('online good: valid with no warnings', [result.isValid, result.signatures[0].hasWarnings], [true, false]);
  check('online good: passed, named as an online response', [c.status, c.details.startsWith("good, online response of 'Test CA with OCSP'")], ['passed', true]);
  check('online good: recorded as online, nothing left to ask', [result.signatures[0].revocations.map((r) => r.online), result.unresolvedRevocations.length], [[true], 0]);
}
check('online good from a responder the CA certified', checkOf(await withOnline(testResponder({ signer: { key: leafKey, certificate: responder } }))).status, 'passed');
{
  const result = await withOnline(testResponder({ status: 'revoked', revokedAt: new Date(Date.now() - DAY) }));
  check('revoked before the signing time: invalid', [result.isValid, checkOf(result).status], [false, 'failed']);
}
{
  const result = await withOnline(testResponder({ status: 'revoked', revokedAt: new Date(Date.now() + 60 * 60 * 1000) }));
  check('revoked after the signing time: still valid', [result.isValid, checkOf(result).status, /after the validation time; online response/.test(checkOf(result).details)], [true, 'passed', true]);
}
check('unknown to the responder: failed', checkOf(await withOnline(testResponder({ status: 'unknown' }))).status, 'failed');
{
  const stranger = issue({ serial: 4, subject: name('Not a responder'), issuer: caName, spki: leafKey.certificate.spki, issuerKey: caKey });
  const result = await withOnline(testResponder({ signer: { key: leafKey, certificate: stranger } }));
  check('a responder without the OCSP signing purpose: failed', [checkOf(result).status, checkOf(result).details], ['failed', "'Not a responder' is not an OCSP responder of 'Test CA with OCSP'"]);
}
{
  const result = await P.verifySignature(signature, () => null, { ...options, onlineRevocation: [] });
  check('online check made, no answer: the warning says so', [checkOf(result).status, checkOf(result).details], ['warning', 'no OCSP response in the signature, and none from the online check']);
  const asked = await P.verifySignature(signature, () => null, { ...options, onlineRevocation: [], onlineAsked: [leaf] });
  check('asked online, no answer: the same warning', checkOf(asked).details, 'no OCSP response in the signature, and none from the online check');
  const notAsked = await P.verifySignature(signature, () => null, { ...options, onlineRevocation: [], onlineAsked: [] });
  check('online check made, this one not asked: the warning says why', [checkOf(notAsked).status, checkOf(notAsked).details], ['warning', 'no OCSP response in the signature; the online check does not reach the OCSP server it names']);
}

done('revocation');
