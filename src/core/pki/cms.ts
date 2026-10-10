import { equal, toHex } from '../bytes';
import { digestMatches, hashName, isSupportedHash } from './algorithms';
import { Asn1, decodePem, Tag } from './asn1';
import { Certificate } from './certificate';
import { DistinguishedName } from './name';
import { Oid } from './oids';
import type { VerificationReport } from './report';

/** A CMS attribute: its type and the values of its SET. */
export class CmsAttribute {
  constructor(
    readonly oid: string,
    readonly values: readonly Asn1[],
  ) {}

  get value(): Asn1 {
    const v = this.values[0];
    if (!v) throw new Error(`Attribute ${this.oid} has no value.`);
    return v;
  }
}

/**
 * SignerInfo (RFC 5652, 5.3) — a port of SignedData.cs. The signature covers the DER SET OF the signed attributes; for
 * DSTU 4145 the signature field holds D directly, little-endian (docs/signature-formats.md, section 9).
 */
export class SignerInfo {
  readonly encoded: Uint8Array;
  readonly version: number;
  readonly issuer: DistinguishedName | null = null;
  readonly serialNumber: bigint | null = null;
  readonly subjectKeyIdentifier: Uint8Array | null = null;
  readonly digestAlgorithm: string;
  /** The signed attributes as hashed for the signature (with the SET tag), or null when there are none. */
  readonly signedAttributesForSignature: Uint8Array | null = null;
  readonly signedAttributes: readonly CmsAttribute[] = [];
  readonly signatureAlgorithm: string;
  readonly signature: Uint8Array;
  readonly unsignedAttributes: readonly CmsAttribute[];

  constructor(node: Asn1) {
    this.encoded = node.encoded;
    this.version = node.at(0).int();
    const sid = node.at(1);
    if (sid.is(Tag.Sequence)) {
      this.issuer = DistinguishedName.fromAsn1(sid.at(0));
      this.serialNumber = sid.at(1).integer();
    } else if (sid.isContext(0)) {
      this.subjectKeyIdentifier = sid.octetString();
    }
    this.digestAlgorithm = node.at(2).at(0).oid();

    let i = 3;
    if (node.at(i).isContext(0)) {
      // [0] IMPLICIT SET OF Attribute: the signature is over the same bytes with the SET tag (RFC 5652, 5.4).
      const attributes = node.at(i).encoded.slice();
      attributes[0] = Tag.Set;
      this.signedAttributesForSignature = attributes;
      this.signedAttributes = parseAttributes(node.at(i));
      i++;
    }
    this.signatureAlgorithm = node.at(i++).at(0).oid();
    this.signature = node.at(i++).expect(Tag.OctetString).octetString();
    this.unsignedAttributes = i < node.count && node.at(i).isContext(1) ? parseAttributes(node.at(i)) : [];
  }

  findSigned(oid: string): CmsAttribute | undefined {
    return this.signedAttributes.find((a) => a.oid === oid);
  }

  findUnsigned(oid: string): CmsAttribute | undefined {
    return this.unsignedAttributes.find((a) => a.oid === oid);
  }

  /** True when the signer identifier names `certificate`. */
  identifies(certificate: Certificate): boolean {
    if (this.subjectKeyIdentifier) {
      const ski = certificate.subjectKeyIdentifier;
      return !!ski && equal(ski, this.subjectKeyIdentifier);
    }
    return this.serialNumber === certificate.serialNumber && !!this.issuer && this.issuer.equals(certificate.issuer);
  }

  toString(): string {
    return this.subjectKeyIdentifier
      ? `key identifier ${toHex(this.subjectKeyIdentifier)}`
      : `serial number ${this.serialNumber?.toString(16).toUpperCase()} issued by ${this.issuer}`;
  }
}

function parseAttributes(set: Asn1): CmsAttribute[] {
  return set.children.map((a) => new CmsAttribute(a.at(0).oid(), a.at(1).expect(Tag.Set).children));
}

/** ContentInfo with SignedData (RFC 5652, 5.1): the encapsulated content, the certificates and the signers. */
export class SignedData {
  readonly encoded: Uint8Array;
  readonly version: number;
  readonly digestAlgorithms: readonly string[];
  /** eContentType: id-data for signatures, id-ct-TSTInfo for time-stamp tokens. */
  readonly contentType: string;
  /** The encapsulated content, or null for a detached signature. */
  readonly content: Uint8Array | null;
  readonly certificates: readonly Certificate[];
  readonly signerInfos: readonly SignerInfo[];

  private constructor(encoded: Uint8Array) {
    this.encoded = encoded;
    const contentInfo = Asn1.parse(encoded).expect(Tag.Sequence);
    if (contentInfo.at(0).oid() !== Oid.SignedData) throw new Error('The CMS ContentInfo is not SignedData.');
    const signedData = contentInfo.at(1).expect(0xa0).at(0).expect(Tag.Sequence);
    this.version = signedData.at(0).int();
    this.digestAlgorithms = signedData.at(1).children.map((a) => a.at(0).oid());
    const encapsulated = signedData.at(2);
    this.contentType = encapsulated.at(0).oid();
    this.content = encapsulated.count > 1 ? encapsulated.at(1).expect(0xa0).at(0).octetString() : null;

    const certificates: Certificate[] = [];
    let i = 3;
    if (signedData.at(i).isContext(0)) {
      for (const choice of signedData.at(i).children) {
        if (choice.is(Tag.Sequence)) certificates.push(Certificate.load(choice.encoded)); // other choices are skipped
      }
      i++;
    }
    if (signedData.at(i).isContext(1)) i++; // revocation information choices
    this.certificates = certificates;
    this.signerInfos = signedData.at(i).expect(Tag.Set).children.map((s) => new SignerInfo(s));
  }

  /** DER/BER, or PEM / bare base64 of it. */
  static load(data: Uint8Array): SignedData {
    return new SignedData(decodePem(data, 'CMS'));
  }

  /** The certificate the signer identifier names, among the embedded ones and `known`. */
  findCertificate(signer: SignerInfo, known: readonly Certificate[] = []): Certificate | null {
    return [...this.certificates, ...known].find((c) => signer.identifies(c)) ?? null;
  }
}

// ---- The checks of one CMS signer (CmsVerifier.cs) ----------------------------------------------------------------

/**
 * contentType and messageDigest bind the signed attributes to the content, signingCertificate(V2) binds them to the
 * certificate, and the DSTU 4145 signature covers their DER encoding (docs/signature-formats.md, sections 6 and 9).
 */
export function verifySigner(signer: SignerInfo, certificate: Certificate, contentType: string, content: Uint8Array, report: VerificationReport, prefix: string): void {
  const dke = certificate.dke;
  if (!signer.signedAttributesForSignature) {
    report.fail(`${prefix}: signed attributes`, 'the signer has no signed attributes');
    return;
  }

  const type = signer.findSigned(Oid.ContentType);
  if (!type || type.value.oid() !== contentType) {
    report.fail(`${prefix}: contentType`, type ? `${type.value.oid()} instead of ${contentType}` : 'the attribute is missing');
  }

  const digest = signer.findSigned(Oid.MessageDigest);
  if (!digest) {
    report.fail(`${prefix}: messageDigest`, 'the attribute is missing');
  } else if (!isSupportedHash(signer.digestAlgorithm)) {
    report.fail(`${prefix}: messageDigest`, `hash algorithm ${signer.digestAlgorithm} is not supported`);
    return;
  } else {
    const matches = digestMatches(signer.digestAlgorithm, content, digest.value.octetString(), dke);
    report.check(`${prefix}: messageDigest`, matches, matches ? `${hashName(signer.digestAlgorithm)} of the content matches` : 'the content does not match the signed hash');
  }

  checkSigningCertificate(signer, certificate, report, prefix);

  let valid: boolean;
  try {
    valid = certificate.publicKey.verifyData(signer.digestAlgorithm, signer.signedAttributesForSignature, signer.signature);
  } catch (e) {
    report.fail(`${prefix}: signature`, (e as Error).message);
    return;
  }
  report.check(`${prefix}: signature`, valid, valid ? `DSTU 4145 signature of ${certificate.shortName}` : 'the DSTU 4145 signature does not verify');
}

/** signingCertificateV2 (or the SHA-1 signingCertificate) names exactly this certificate. */
export function checkSigningCertificate(signer: SignerInfo, certificate: Certificate, report: VerificationReport, prefix: string): void {
  const v2 = signer.findSigned(Oid.SigningCertificateV2);
  const v1 = signer.findSigned(Oid.SigningCertificate);
  if (!v2 && !v1) {
    report.warn(`${prefix}: signing certificate`, 'neither signingCertificateV2 nor signingCertificate is present');
    return;
  }
  // SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2, ... }
  // ESSCertIDv2 ::= SEQUENCE { hashAlgorithm DEFAULT sha256, certHash OCTET STRING, issuerSerial OPTIONAL }
  // ESSCertID   ::= SEQUENCE { certHash OCTET STRING, issuerSerial OPTIONAL }
  const first = (v2 ?? v1)!.value.at(0).at(0);
  const hasAlgorithm = first.at(0).is(Tag.Sequence);
  const hashOid = !v2 ? Oid.Sha1 : hasAlgorithm ? first.at(0).at(0).oid() : Oid.Sha256;
  const hashIndex = hasAlgorithm ? 1 : 0;
  const expected = first.at(hashIndex).octetString();
  const matches = isSupportedHash(hashOid) && digestMatches(hashOid, certificate.encoded, expected, certificate.dke);
  if (!matches) {
    report.fail(`${prefix}: signing certificate`, 'the signed attributes name a different certificate');
    return;
  }
  const hasIssuerSerial = first.count > hashIndex + 1;
  if (hasIssuerSerial && !issuerSerialMatches(first.at(hashIndex + 1), certificate)) {
    report.fail(`${prefix}: signing certificate`, 'the hash matches, but issuerSerial names another issuer or serial number');
    return;
  }
  report.pass(`${prefix}: signing certificate`, `${hashName(hashOid)} of the certificate matches${hasIssuerSerial ? ', and so do its issuer and serial number' : ''}`);
}

// IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber, issuerUID OPTIONAL }; the issuer is directoryName [4].
function issuerSerialMatches(issuerSerial: Asn1, certificate: Certificate): boolean {
  return (
    issuerSerial.is(Tag.Sequence) &&
    issuerSerial.count >= 2 &&
    issuerSerial.at(1).integer() === certificate.serialNumber &&
    issuerSerial.at(0).children.some((n) => n.isContext(4) && DistinguishedName.fromAsn1(n.at(0)).equals(certificate.issuer))
  );
}
