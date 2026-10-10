import { equal } from '../bytes';
import { sha1 } from '../hash/sha';
import { hash, isSupportedHash } from './algorithms';
import { Asn1, Tag } from './asn1';
import { Certificate } from './certificate';
import { DistinguishedName } from './name';
import { Oid } from './oids';

export type OcspCertificateStatus = 'good' | 'revoked' | 'unknown';

/** A SingleResponse: the certificate identifier (CertID), its status and the validity interval. */
export class OcspSingleResponse {
  constructor(
    readonly hashAlgorithm: string,
    readonly issuerNameHash: Uint8Array,
    readonly issuerKeyHash: Uint8Array,
    readonly serialNumber: bigint,
    readonly status: OcspCertificateStatus,
    readonly thisUpdate: Date,
    readonly nextUpdate: Date | null,
    readonly revocationTime: Date | null,
  ) {}

  /**
   * True when the CertID names `certificate` issued by `issuer`. An issuerKeyHash of zeros (the "Дія" responder sends
   * one) is matched by the serial number and the name hash alone: the response must still be signed by the issuer or by
   * a responder the issuer certified, which binds it to the issuer's key.
   */
  matches(certificate: Certificate, issuer: Certificate): boolean {
    return (
      this.serialNumber === certificate.serialNumber &&
      isSupportedHash(this.hashAlgorithm) &&
      equal(this.issuerNameHash, hash(this.hashAlgorithm, issuer.subject.encoded)) &&
      (this.isZeroKeyHash || equal(this.issuerKeyHash, hash(this.hashAlgorithm, issuer.publicKeyBits)))
    );
  }

  private get isZeroKeyHash(): boolean {
    return this.issuerKeyHash.length > 0 && this.issuerKeyHash.every((b) => b === 0);
  }
}

/**
 * A BasicOCSPResponse (RFC 6960, 4.2.1) as used in the national PKI (docs/signature-formats.md, section 5;
 * OcspResponse.cs): signed over the DER tbsResponseData, the signature value is a BIT STRING wrapping an OCTET STRING
 * with D, the responder is identified by name or key hash and its certificate travels in the response.
 */
export class OcspResponse {
  readonly tbsResponseData: Uint8Array;
  readonly responderName: DistinguishedName | null = null;
  readonly responderKeyHash: Uint8Array | null = null;
  readonly producedAt: Date;
  readonly responses: readonly OcspSingleResponse[];
  readonly signatureAlgorithm: string;
  readonly signatureValue: Uint8Array;
  readonly certificates: readonly Certificate[];

  private constructor(readonly basicEncoded: Uint8Array) {
    const node = Asn1.parse(basicEncoded).expect(Tag.Sequence);
    const tbs = node.at(0).expect(Tag.Sequence);
    this.tbsResponseData = tbs.encoded;
    this.signatureAlgorithm = node.at(1).at(0).oid();
    this.signatureValue = node.at(2).bitString();
    this.certificates = node.count > 3 && node.at(3).isContext(0) ? node.at(3).at(0).children.map((c) => Certificate.load(c.encoded)) : [];

    let i = tbs.at(0).isContext(0) ? 1 : 0; // version [0] EXPLICIT DEFAULT v1
    const responder = tbs.at(i++);
    if (responder.isContext(1)) this.responderName = DistinguishedName.fromAsn1(responder.at(0));
    else if (responder.isContext(2)) this.responderKeyHash = responder.at(0).octetString();
    this.producedAt = tbs.at(i++).time();
    this.responses = tbs.at(i).children.map(parseSingle);
  }

  /** A full OCSPResponse; throws unless its status is successful and it holds a basic response. */
  static load(data: Uint8Array): OcspResponse {
    const response = Asn1.parse(data).expect(Tag.Sequence);
    const status = response.at(0).expect(Tag.Enumerated).content[0];
    if (status !== 0) throw new Error(`The OCSP responder returned status ${status}.`);
    const bytes = response.at(1).at(0);
    if (bytes.at(0).oid() !== Oid.OcspBasic) throw new Error(`Unsupported OCSP response type ${bytes.at(0).oid()}.`);
    return new OcspResponse(bytes.at(1).octetString());
  }

  /** A BasicOCSPResponse, as CAdES revocationValues stores it. */
  static loadBasic(data: Uint8Array): OcspResponse {
    return new OcspResponse(Asn1.parse(data).encoded.slice());
  }

  /** The response about `certificate`, if this response has one. */
  find(certificate: Certificate, issuer: Certificate): OcspSingleResponse | null {
    return this.responses.find((r) => r.matches(certificate, issuer)) ?? null;
  }

  /** The responder's certificate: in the response or among `known`, by name or by key hash. */
  findResponder(known: readonly Certificate[]): Certificate | null {
    return (
      [...this.certificates, ...known].find((c) => {
        if (this.responderName) return c.subject.equals(this.responderName);
        const keyHash = this.responderKeyHash;
        if (!keyHash) return false;
        const ski = c.subjectKeyIdentifier;
        return (ski !== null && equal(ski, keyHash)) || equal(sha1(c.publicKeyBits), keyHash);
      }) ?? null
    );
  }

  isSignedBy(responder: Certificate): boolean {
    try {
      const d = Asn1.parse(this.signatureValue).expect(Tag.OctetString).octetString();
      return responder.hasDstu4145Key && responder.publicKey.verify(this.signatureAlgorithm, this.tbsResponseData, d);
    } catch {
      return false;
    }
  }
}

// SingleResponse ::= SEQUENCE { certID, certStatus CHOICE { good [0] NULL, revoked [1] RevokedInfo, unknown [2] NULL },
//                               thisUpdate GeneralizedTime, nextUpdate [0] EXPLICIT OPTIONAL, singleExtensions [1] OPTIONAL }
function parseSingle(single: Asn1): OcspSingleResponse {
  const certId = single.at(0);
  const status = single.at(1);
  let value: OcspCertificateStatus = 'unknown';
  let revoked: Date | null = null;
  if (status.isContext(0)) value = 'good';
  else if (status.isContext(1)) {
    value = 'revoked';
    revoked = status.at(0).time(); // [1] IMPLICIT RevokedInfo { revocationTime, reason }
  }
  const next = single.count > 3 && single.at(3).isContext(0) ? single.at(3).at(0).time() : null;
  return new OcspSingleResponse(
    certId.at(0).at(0).oid(),
    certId.at(1).octetString(),
    certId.at(2).octetString(),
    certId.at(3).integer(),
    value,
    single.at(2).time(),
    next,
    revoked,
  );
}
