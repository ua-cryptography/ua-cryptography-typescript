import { equal } from '../bytes';
import { hash, hashName, isSupportedHash } from './algorithms';
import { type Asn1, Tag } from './asn1';
import { Certificate } from './certificate';
import { SignedData, verifySigner, type SignerInfo } from './cms';
import { OcspResponse } from './ocsp';
import { Oid } from './oids';
import { type ValidationOptions, VerificationReport, VerificationResult } from './report';
import { TimeStampToken } from './tsp';
import { validatePath } from './validation';

/**
 * Verifies CAdES signatures (docs/signature-formats.md, section 9; CadesVerifier.cs): for every signer the binding to
 * the data and to the certificate, the DSTU 4145 signature, the time-stamps, the long-term validation values and the
 * certificate path. `detachedContent` is the data of a detached signature.
 */
export function verifyCades(signature: Uint8Array, detachedContent: Uint8Array | null, options: ValidationOptions): VerificationResult {
  const cms = SignedData.load(signature);
  const content = cms.content ?? detachedContent;
  const reports = cms.signerInfos.map((signer, i) =>
    verifySigner1(cms, signer, content, options, cms.signerInfos.length === 1 ? 'CAdES signature' : `CAdES signature ${i + 1}`),
  );
  const files = new Map<string, Uint8Array>();
  if (content) files.set('content', content);
  return new VerificationResult(cms.content ? 'CAdES (enveloped)' : 'CAdES (detached)', reports, files);
}

function verifySigner1(cms: SignedData, signer: SignerInfo, content: Uint8Array | null, options: ValidationOptions, title: string): VerificationReport {
  const report = new VerificationReport(title, options.now);
  const certValues = signer.findUnsigned(Oid.CertValues)?.value.children.map((c) => Certificate.load(c.encoded)) ?? [];
  const ocspValues = readRevocationValues(signer);
  const known = [...cms.certificates, ...certValues, ...options.extraCertificates];

  const certificate = cms.findCertificate(signer, known);
  const hasTimeStamp = !!signer.findUnsigned(Oid.SignatureTimeStampToken);
  const longTerm = certValues.length > 0 || ocspValues.length > 0;
  report.level = `CAdES-${longTerm ? 'X Long' : hasTimeStamp ? 'T' : 'B'}`;
  report.packaging = cms.content ? 'enveloped' : 'detached';
  report.format = `${report.level}, ${report.packaging}, ${hashName(signer.digestAlgorithm)}`;
  report.signatureAlgorithm = signer.signatureAlgorithm;
  report.digestAlgorithm = signer.digestAlgorithm;
  const messageDigest = signer.findSigned(Oid.MessageDigest);
  if (messageDigest) report.signedObjects.push({ name: 'content', hashAlgorithm: signer.digestAlgorithm, digest: messageDigest.value.octetString() });
  if (!certificate) {
    report.fail('signer certificate', `the certificate (${signer}) is not in the signature and was not given`);
    return report;
  }
  report.signer = certificate;
  if (!content) {
    report.fail('content', 'the signature is detached and the signed data was not given');
    return report;
  }

  verifySigner(signer, certificate, cms.contentType, content, report, 'CMS');

  const time = signer.findSigned(Oid.SigningTime);
  if (time) report.claimedSigningTime = time.value.time();

  // Time-stamps: contentTimeStamp over the data, signatureTimeStampToken over the signature value.
  const tsaPool = [...known];
  const contentStamp = signer.findSigned(Oid.ContentTimeStamp);
  if (contentStamp) verifyTimeStamp(contentStamp.value, content, tsaPool, options, report, 'content time-stamp');
  const signatureStamp = signer.findUnsigned(Oid.SignatureTimeStampToken);
  if (signatureStamp) {
    const before = report.checks.length;
    const token = verifyTimeStamp(signatureStamp.value, signer.signature, tsaPool, options, report, 'signature time-stamp');
    if (token && report.checks.slice(before).every((c) => c.status !== 'failed')) report.timeStampTime = token.genTime;
  }

  if (signer.findUnsigned(Oid.CertificateRefs) || signer.findUnsigned(Oid.RevocationRefs)) checkReferences(signer, certValues, ocspValues, report);

  validatePath(certificate, [...known, ...tsaPool], ocspValues, options, report.validationTime, report, 'signer');
  return report;
}

/** Verifies a time-stamp; returns the token only when the service's certificate was found and checked. */
function verifyTimeStamp(value: Asn1, covered: Uint8Array, pool: Certificate[], options: ValidationOptions, report: VerificationReport, name: string): TimeStampToken | null {
  let token: TimeStampToken;
  try {
    token = TimeStampToken.load(value.encoded);
  } catch (e) {
    report.fail(name, (e as Error).message);
    return null;
  }
  const tsa = token.verify(covered, pool, report, name);
  report.timeStamps.push({ kind: name, token, authority: tsa });
  if (!tsa) return null;
  pool.push(...token.cms.certificates);
  validatePath(tsa, pool, [], options, token.genTime, report, `${name} service`);
  return token;
}

// RevocationValues ::= SEQUENCE { crlVals [0] OPTIONAL, ocspVals [1] EXPLICIT SEQUENCE OF BasicOCSPResponse OPTIONAL, ... }
function readRevocationValues(signer: SignerInfo): OcspResponse[] {
  const values = signer.findUnsigned(Oid.RevocationValues);
  const ocsp = values?.value.children.find((c) => c.isContext(1));
  return ocsp ? ocsp.at(0).children.map((r) => OcspResponse.loadBasic(r.encoded)) : [];
}

/** Every complete certificate / revocation reference has a value with the same hash (CAdES-C ↔ CAdES-X Long). */
function checkReferences(signer: SignerInfo, certValues: Certificate[], ocspValues: OcspResponse[], report: VerificationReport): void {
  const certRefs = signer.findUnsigned(Oid.CertificateRefs);
  if (certRefs) {
    const missing = certRefs.value.children.filter((r) => !certValues.some((c) => hashMatches(r.at(0), c.encoded))).length;
    report.check(
      'certificate references',
      missing === 0,
      missing === 0 ? `${certRefs.value.count} references match certValues` : `${missing} references have no matching certificate`,
    );
  }
  const revRefs = signer.findUnsigned(Oid.RevocationRefs);
  if (revRefs) {
    // CrlOcspRef ::= SEQUENCE { crlids [0], ocspids [1] EXPLICIT OcspListID, otherRev [2] }
    // OcspListID ::= SEQUENCE { ocspResponses SEQUENCE OF OcspResponsesID { ocspIdentifier, ocspRepHash OPTIONAL } }
    const ids = revRefs.value.children.flatMap((r) => r.children.filter((c) => c.isContext(1))).flatMap((o) => o.at(0).at(0).children);
    const missing = ids.filter((id) => id.count > 1 && !ocspValues.some((r) => hashMatches(id.at(1), r.basicEncoded))).length;
    report.check(
      'revocation references',
      missing === 0,
      missing === 0 ? `${ids.length} OCSP references match revocationValues` : `${missing} OCSP references have no matching response`,
    );
  }
}

// OtherHash ::= CHOICE { sha1Hash OCTET STRING, otherHash SEQUENCE { hashAlgorithm, hashValue } }
function hashMatches(otherHash: Asn1, encoded: Uint8Array): boolean {
  const [oid, value] = otherHash.is(Tag.OctetString) ? [Oid.Sha1, otherHash.octetString()] : [otherHash.at(0).at(0).oid(), otherHash.at(1).octetString()];
  return isSupportedHash(oid) && equal(value, hash(oid, encoded));
}
