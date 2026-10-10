import { ascii, equal, toHex } from '../bytes';
import { sha1 } from '../hash/sha';
import { Asn1, decodePem, Tag } from './asn1';
import { isDstu4145, publicKeyFromSpki, type PublicKey } from './keys';
import { DistinguishedName } from './name';
import { Oid } from './oids';

export type Extension = { readonly oid: string; readonly critical: boolean; readonly value: Uint8Array };

/**
 * An X.509 certificate (RFC 5280) — a port of Certificate.cs. The DSTU 4145 key is decoded on first use, so
 * certificates with other key types can still be parsed, listed and matched.
 */
export class Certificate {
  readonly encoded: Uint8Array;
  /** The DER TBSCertificate, the bytes the signature covers. */
  readonly tbs: Uint8Array;
  readonly version: number;
  readonly serialNumber: bigint;
  readonly issuer: DistinguishedName;
  readonly subject: DistinguishedName;
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly signatureAlgorithm: string;
  /** The signatureValue BIT STRING (for DSTU 4145, a DER OCTET STRING with D, little-endian). */
  readonly signatureValue: Uint8Array;
  readonly spki: Uint8Array;
  readonly publicKeyAlgorithm: string;
  /** The subjectPublicKey BIT STRING value (what OCSP CertID's issuerKeyHash covers). */
  readonly publicKeyBits: Uint8Array;
  readonly extensions: readonly Extension[];
  /** Hex of the DER, for maps and equality. */
  readonly id: string;
  private key: PublicKey | null = null;
  private readonly signedBy = new Map<string, boolean>();

  private constructor(encoded: Uint8Array) {
    this.encoded = encoded;
    this.id = toHex(encoded);
    const certificate = Asn1.parse(encoded).expect(Tag.Sequence);
    const tbs = certificate.at(0).expect(Tag.Sequence);
    this.tbs = tbs.encoded;
    this.signatureAlgorithm = certificate.at(1).at(0).oid();
    this.signatureValue = certificate.at(2).bitString();

    let i = 0;
    if (tbs.at(0).isContext(0)) {
      this.version = tbs.at(0).at(0).int() + 1;
      i++;
    } else {
      this.version = 1;
    }
    this.serialNumber = tbs.at(i++).integer();
    i++; // signature AlgorithmIdentifier, repeated from the outer structure
    this.issuer = DistinguishedName.fromAsn1(tbs.at(i++));
    const validity = tbs.at(i++);
    this.notBefore = validity.at(0).time();
    this.notAfter = validity.at(1).time();
    this.subject = DistinguishedName.fromAsn1(tbs.at(i++));
    const spki = tbs.at(i++).expect(Tag.Sequence);
    this.spki = spki.encoded;
    this.publicKeyAlgorithm = spki.at(0).at(0).oid();
    this.publicKeyBits = spki.at(1).bitString();

    const extensions: Extension[] = [];
    for (; i < tbs.count; i++) {
      if (!tbs.at(i).isContext(3)) continue; // issuerUniqueID [1], subjectUniqueID [2]
      for (const extension of tbs.at(i).at(0).expect(Tag.Sequence).children) {
        const critical = extension.count === 3 && extension.at(1).boolean();
        extensions.push({ oid: extension.at(0).oid(), critical, value: extension.last().octetString() });
      }
    }
    this.extensions = extensions;
  }

  /** A DER certificate, or PEM / bare base64 text holding one. */
  static load(data: Uint8Array): Certificate {
    return new Certificate(decodePem(data, 'CERTIFICATE').slice());
  }

  get hasDstu4145Key(): boolean {
    return isDstu4145(this.publicKeyAlgorithm);
  }

  /** The DSTU 4145 key, checked by section 8 (parameters) and 10.1 (point). */
  get publicKey(): PublicKey {
    if (!this.key) {
      if (!this.hasDstu4145Key) throw new Error(`The key of '${this.subject}' is not a DSTU 4145 key (${this.publicKeyAlgorithm}).`);
      this.key = publicKeyFromSpki(Asn1.parse(this.spki));
    }
    return this.key;
  }

  /** The DKE of the key, or null; null too when the key cannot be read. */
  get dke(): Uint8Array | null {
    try {
      return this.hasDstu4145Key ? this.publicKey.dke : null;
    } catch {
      return null;
    }
  }

  get isSelfIssued(): boolean {
    return this.subject.equals(this.issuer);
  }

  equals(other: Certificate): boolean {
    return this === other || equal(this.encoded, other.encoded);
  }

  findExtension(oid: string): Extension | undefined {
    return this.extensions.find((e) => e.oid === oid);
  }

  /** basicConstraints cA (RFC 5280, 4.2.1.9). */
  get isCa(): boolean {
    const e = this.findExtension(Oid.BasicConstraints);
    if (!e) return false;
    const sequence = Asn1.parse(e.value);
    return sequence.count > 0 && sequence.at(0).is(Tag.Boolean) && sequence.at(0).boolean();
  }

  /** keyUsage bits (bit 0 digitalSignature, 1 nonRepudiation, 2 keyEncipherment, 4 keyAgreement, 5 keyCertSign), or null. */
  get keyUsage(): number | null {
    const e = this.findExtension(Oid.KeyUsage);
    return e ? Asn1.parse(e.value).namedBits() : null;
  }

  get extendedKeyUsage(): string[] {
    const e = this.findExtension(Oid.ExtendedKeyUsage);
    return e ? Asn1.parse(e.value).children.map((c) => c.oid()) : [];
  }

  get subjectKeyIdentifier(): Uint8Array | null {
    const e = this.findExtension(Oid.SubjectKeyIdentifier);
    return e ? Asn1.parse(e.value).expect(Tag.OctetString).octetString() : null;
  }

  get authorityKeyIdentifier(): Uint8Array | null {
    const e = this.findExtension(Oid.AuthorityKeyIdentifier);
    if (!e) return null;
    return Asn1.parse(e.value).children.find((c) => c.isContext(0))?.octetString() ?? null;
  }

  /** OCSP responder URLs (authorityInfoAccess, id-ad-ocsp). */
  get ocspUrls(): string[] {
    return this.accessUrls(Oid.AuthorityInfoAccess, Oid.AccessOcsp);
  }

  /** Where the issuer's certificate can be downloaded (authorityInfoAccess, id-ad-caIssuers). */
  get caIssuerUrls(): string[] {
    return this.accessUrls(Oid.AuthorityInfoAccess, Oid.AccessCaIssuers);
  }

  /** The CA's time-stamping service (subjectInfoAccess, id-ad-timeStamping), as Ukrainian CAs publish it. */
  get timeStampUrls(): string[] {
    return this.accessUrls(Oid.SubjectInfoAccess, Oid.AccessTimeStamping);
  }

  private accessUrls(extension: string, method: string): string[] {
    const e = this.findExtension(extension);
    if (!e) return [];
    const urls: string[] = [];
    for (const description of Asn1.parse(e.value).children) {
      const location = description.at(1);
      if (description.at(0).oid() === method && location.isContext(6) && !location.constructed) urls.push(ascii(location.content));
    }
    return urls;
  }

  /** The SHA-1 of the key bits, as an OCSP responder ID "byKey" names it. */
  get keyHashSha1(): Uint8Array {
    return sha1(this.publicKeyBits);
  }

  /**
   * Verifies this certificate's signature with the issuer's key (section 4 of signature-formats.md): the hash comes from
   * the signature algorithm, GOST 34.311 uses the issuer's DKE. Results are cached per issuer.
   */
  isSignedBy(issuer: Certificate): boolean {
    let result = this.signedBy.get(issuer.id);
    if (result === undefined) {
      try {
        const d = Asn1.parse(this.signatureValue).expect(Tag.OctetString).octetString();
        result = issuer.hasDstu4145Key && issuer.publicKey.verify(this.signatureAlgorithm, this.tbs, d);
      } catch {
        result = false;
      }
      this.signedBy.set(issuer.id, result);
    }
    return result;
  }

  isValidAt(time: Date): boolean {
    return time >= this.notBefore && time <= this.notAfter;
  }

  /** The common name, else the whole subject. */
  get shortName(): string {
    return this.subject.get(Oid.CommonName) ?? this.subject.toString();
  }

  toString(): string {
    return this.subject.toString();
  }
}

/**
 * Every certificate in `data`: one DER/PEM certificate, several PEM blocks, or a PKCS#7 / CMS bundle (.p7b, .p7c — the
 * certificates of a SignedData).
 */
export function loadCertificates(data: Uint8Array): Certificate[] {
  const text = ascii(data.subarray(0, Math.min(data.length, 64)));
  if (text.includes('-----BEGIN')) {
    const all = ascii(data);
    const blocks = [...all.matchAll(/-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----/g)];
    return blocks.flatMap((b) => loadCertificates(decodePem(new TextEncoder().encode(b[0]), b[1]!)));
  }
  const node = Asn1.parse(decodePem(data, 'CERTIFICATE'));
  // A certificate is SEQUENCE { SEQUENCE tbs, SEQUENCE algorithm, BIT STRING }; a ContentInfo starts with an OID.
  if (node.count > 0 && node.at(0).is(Tag.ObjectIdentifier)) {
    if (node.at(0).oid() !== Oid.SignedData) throw new Error('The PKCS#7 bundle is not SignedData.');
    const signedData = node.at(1).at(0);
    const certificates = signedData.children.find((c) => c.isContext(0));
    return certificates ? certificates.children.filter((c) => c.is(Tag.Sequence)).map((c) => Certificate.load(c.encoded)) : [];
  }
  return [Certificate.load(node.encoded)];
}
