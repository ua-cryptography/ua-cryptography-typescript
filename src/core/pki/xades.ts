import { fromBase64 } from '../bytes';
import { C14N, canonicalize, isSupportedC14N } from '../xml/c14n';
import { type XmlDocument, type XmlElement, type XmlNode } from '../xml/dom';
import { digestMatches, hashName, hashOfXmlAlgorithm, UnsupportedError } from './algorithms';
import { Certificate } from './certificate';
import { OcspResponse } from './ocsp';
import { type ValidationOptions, VerificationReport } from './report';
import { TimeStampToken } from './tsp';
import { validatePath } from './validation';

export const DS = 'http://www.w3.org/2000/09/xmldsig#';
export const XADES = 'http://uri.etsi.org/01903/v1.3.2#';
const XADES141 = 'http://uri.etsi.org/01903/v1.4.1#';
const ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

/**
 * Verifies XAdES signatures (docs/signature-formats.md, section 7; XadesVerifier.cs): every ds:Reference, the signed
 * properties and the signing certificate they name, the DSTU 4145 signature over the canonical ds:SignedInfo, the
 * signature time-stamp, the certificate and OCSP values, and the certificate path.
 *
 * Against signature wrapping, same-document references must resolve to exactly one element, and the signed properties
 * are read only from the element the signature actually covers, inside this ds:Signature.
 *
 * `resolve` returns the content of an external reference (a file name, already URI-unescaped) or null.
 */
export function verifyXades(document: XmlDocument, resolve: (name: string) => Uint8Array | null, options: ValidationOptions): VerificationReport[] {
  const signatures = document.allElements().filter((e) => e.namespaceURI === DS && e.localName === 'Signature');
  return signatures.map((signature) => {
    const id = signature.getAttribute('Id');
    const report = new VerificationReport(id ? `XAdES signature ${id}` : 'XAdES signature', options.now);
    try {
      verifySignature(document, signature, resolve, options, report);
    } catch (e) {
      report.fail('structure', (e as Error).message);
    }
    return report;
  });
}

/** The names of the external files the signatures of `document` reference. */
export function externalReferences(document: XmlDocument): string[] {
  return document
    .allElements()
    .filter((e) => e.namespaceURI === DS && e.localName === 'Signature')
    .flatMap((s) => single(s, DS, 'SignedInfo').elements(DS, 'Reference'))
    .map((r) => r.getAttribute('URI'))
    .filter((u) => u.length > 0 && !u.startsWith('#'))
    .map(unescapeUri);
}

type Transform = { algorithm: string; prefixes: string[] | null };

function verifySignature(
  document: XmlDocument,
  signature: XmlElement,
  resolve: (name: string) => Uint8Array | null,
  options: ValidationOptions,
  report: VerificationReport,
): void {
  const signedInfo = single(signature, DS, 'SignedInfo');
  const canonicalizationMethod = single(signedInfo, DS, 'CanonicalizationMethod');
  const signatureMethod = single(signedInfo, DS, 'SignatureMethod').getAttribute('Algorithm');
  const signatureHash = hashOfXmlAlgorithm(signatureMethod);

  // The signed properties: the element of type SignedProperties inside this signature that a reference covers.
  const qualifying = signature.elements(DS, 'Object').map((o) => o.element(XADES, 'QualifyingProperties')).find((q) => q !== null) ?? null;
  let signedProperties: XmlElement | null = null;
  const externalFiles: string[] = [];

  // References: resolve each one first; the digests are compared once the signer's key (and its DKE) is known.
  const references: Array<{ name: string; hash: string; expected: Uint8Array; content: Uint8Array | null }> = [];
  report.signatureAlgorithm = signatureMethod;
  report.digestAlgorithm = signatureHash;
  for (const reference of signedInfo.elements(DS, 'Reference')) {
    const uri = reference.getAttribute('URI');
    const name = `reference '${uri || '(document)'}'`;
    const digestHash = hashOfXmlAlgorithm(single(reference, DS, 'DigestMethod').getAttribute('Algorithm'));
    const expected = fromBase64(single(reference, DS, 'DigestValue').textContent.trim());
    const transforms: Transform[] = (reference.element(DS, 'Transforms')?.elements(DS, 'Transform') ?? []).map((t) => ({
      algorithm: t.getAttribute('Algorithm'),
      prefixes: inclusivePrefixes(t),
    }));
    report.signedObjects.push({ name: uri || '(document)', hashAlgorithm: digestHash, digest: expected });

    let content: Uint8Array | null;
    if (uri.startsWith('#') || uri.length === 0) {
      const target = uri.length === 0 ? document : findById(document, uri.slice(1));
      content = applyTransforms(target, transforms, signature);
      if (
        target !== document &&
        (target as XmlElement).localName === 'SignedProperties' &&
        ((target as XmlElement).namespaceURI === XADES || (target as XmlElement).namespaceURI === XADES141) &&
        (target as XmlElement).isDescendantOf(signature)
      ) {
        signedProperties = target as XmlElement;
      }
    } else {
      const file = unescapeUri(uri);
      if (transforms.length > 0) throw new UnsupportedError(`Transforms on the external reference '${uri}' are not supported.`);
      content = resolve(file);
      if (content) externalFiles.push(file);
    }
    references.push({ name, hash: digestHash, expected, content });
  }

  // The signer's certificate: the one the signed properties name, else ds:KeyInfo.
  const unsigned = qualifying?.element(XADES, 'UnsignedProperties')?.element(XADES, 'UnsignedSignatureProperties') ?? null;
  const certificateValues = (unsigned?.element(XADES, 'CertificateValues')?.elements(XADES, 'EncapsulatedX509Certificate') ?? []).map((e) =>
    Certificate.load(fromBase64(e.textContent)),
  );
  const keyInfo = (signature.element(DS, 'KeyInfo')?.elements(DS, 'X509Data') ?? [])
    .flatMap((d) => d.elements(DS, 'X509Certificate'))
    .map((e) => Certificate.load(fromBase64(e.textContent)));
  const known = [...keyInfo, ...certificateValues, ...options.extraCertificates];

  if (!signedProperties) {
    report.fail(
      'signed properties',
      qualifying ? 'no reference of this signature covers its xades:SignedProperties' : 'the signature has no xades:QualifyingProperties (plain XML-DSig)',
    );
  }
  const certificate = signedProperties ? findSigningCertificate(signedProperties, known, report) : (keyInfo[0] ?? null);
  if (!certificate) {
    report.fail('signer certificate', "the signer's certificate is neither in ds:KeyInfo nor given");
    return;
  }
  report.signer = certificate;
  const dke = certificate.dke;
  for (const { name, hash, expected, content } of references) {
    if (!content) {
      report.fail(name, 'the referenced file was not given');
      continue;
    }
    const matches = digestMatches(hash, content, expected, dke);
    report.check(name, matches, matches ? `${hashName(hash)} digest matches` : 'the content does not match the digest');
  }

  const signingTime = signedProperties?.element(XADES, 'SignedSignatureProperties')?.element(XADES, 'SigningTime');
  if (signingTime) {
    const t = new Date(signingTime.textContent.trim());
    if (!Number.isNaN(t.getTime())) report.claimedSigningTime = t;
  }

  // The signature over the canonical SignedInfo.
  const signatureValue = single(signature, DS, 'SignatureValue');
  const value = fromBase64(signatureValue.textContent.trim());
  const canonical = canonicalize(signedInfo, canonicalizationMethod.getAttribute('Algorithm'), inclusivePrefixes(canonicalizationMethod));
  const valid = certificate.publicKey.verifyData(signatureHash, canonical, value);
  report.check('signature', valid, valid ? `DSTU 4145 signature of ${certificate.shortName} over ds:SignedInfo` : 'the DSTU 4145 signature does not verify');

  // Unsigned properties: the signature time-stamp and the long-term values.
  const pool = [...known];
  let hasTimeStamp = false;
  for (const stamp of unsigned?.elements(XADES, 'SignatureTimeStamp') ?? []) {
    hasTimeStamp = true;
    const method = stamp.element(DS, 'CanonicalizationMethod')?.getAttribute('Algorithm') || C14N.Inclusive;
    const covered = canonicalize(signatureValue, method);
    const token = TimeStampToken.load(fromBase64(single(stamp, XADES, 'EncapsulatedTimeStamp').textContent));
    const before = report.checks.length;
    const tsa = token.verify(covered, pool, report, 'signature time-stamp');
    report.timeStamps.push({ kind: 'signature time-stamp', token, authority: tsa });
    if (!tsa) continue;
    pool.push(...token.cms.certificates);
    validatePath(tsa, pool, [], options, token.genTime, report, 'signature time-stamp service');
    if (report.checks.slice(before).every((c) => c.status !== 'failed')) report.timeStampTime ??= token.genTime;
  }

  const ocsp = (unsigned?.element(XADES, 'RevocationValues')?.element(XADES, 'OCSPValues')?.elements(XADES, 'EncapsulatedOCSPValue') ?? []).map((e) =>
    OcspResponse.load(fromBase64(e.textContent)),
  );
  report.level = `XAdES-B-${certificateValues.length > 0 || ocsp.length > 0 ? 'LT' : hasTimeStamp ? 'T' : 'B'}`;
  report.packaging = externalFiles.length > 0 ? 'detached' : 'enveloped';
  report.format = `${report.level}, ${report.packaging}, ${hashName(signatureHash)}`;

  validatePath(certificate, pool, ocsp, options, report.validationTime, report, 'signer');
}

/** SigningCertificateV2 / SigningCertificate: the certificate whose digest is listed (the first Cert names the signer). */
function findSigningCertificate(signedProperties: XmlElement, known: Certificate[], report: VerificationReport): Certificate | null {
  const properties = signedProperties.element(XADES, 'SignedSignatureProperties');
  const cert = (properties?.element(XADES, 'SigningCertificateV2') ?? properties?.element(XADES, 'SigningCertificate'))?.element(XADES, 'Cert') ?? null;
  if (!cert) {
    report.warn('signing certificate', 'the signed properties do not name the certificate');
    return known[0] ?? null;
  }
  const digest = single(cert, XADES, 'CertDigest');
  const hash = hashOfXmlAlgorithm(single(digest, DS, 'DigestMethod').getAttribute('Algorithm'));
  const expected = fromBase64(single(digest, DS, 'DigestValue').textContent.trim());
  const match = known.find((c) => digestMatches(hash, c.encoded, expected, c.dke)) ?? null;
  report.check(
    'signing certificate',
    match !== null,
    match ? `${hashName(hash)} of the certificate matches the signed properties` : 'the signed properties name a certificate that is not available',
  );
  return match;
}

function inclusivePrefixes(method: XmlElement): string[] | null {
  const list = method.elements().find((e) => e.localName === 'InclusiveNamespaces');
  return list ? list.getAttribute('PrefixList').split(' ').filter(Boolean) : null;
}

/**
 * The XML-DSig processing model (XML-DSig 1.0, 4.3.3.2): a node set goes through the transforms and, if no
 * canonicalization ends it, through inclusive C14N. Supported: enveloped-signature and the four C14N methods.
 */
function applyTransforms(target: XmlDocument | XmlElement, transforms: Transform[], signature: XmlElement): Uint8Array {
  let excluded: XmlNode | null = null;
  for (const { algorithm, prefixes } of transforms) {
    if (algorithm === ENVELOPED_SIGNATURE) excluded = signature;
    else if (isSupportedC14N(algorithm)) return canonicalize(target, algorithm, prefixes, excluded);
    else throw new UnsupportedError(`Transform ${algorithm} is not supported.`);
  }
  return canonicalize(target, C14N.Inclusive, null, excluded);
}

/** The single element whose Id (or ID, id) attribute is `id`. */
function findById(document: XmlDocument, id: string): XmlElement {
  const matches = document.allElements().filter((e) => e.getAttribute('Id') === id || e.getAttribute('ID') === id || e.getAttribute('id') === id);
  if (matches.length === 1) return matches[0]!;
  throw new Error(matches.length === 0 ? `No element with Id '${id}'.` : `Several elements have Id '${id}'.`);
}

function single(parent: XmlElement, namespaceURI: string, localName: string): XmlElement {
  const e = parent.element(namespaceURI, localName);
  if (!e) throw new Error(`${localName} is missing in ${parent.name}.`);
  return e;
}

function unescapeUri(uri: string): string {
  try {
    return decodeURIComponent(uri);
  } catch {
    return uri;
  }
}
