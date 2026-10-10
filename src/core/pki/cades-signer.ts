import { hash, signatureAlgorithmFor } from './algorithms';
import { Der } from './asn1';
import type { Certificate } from './certificate';
import type { SigningKey } from './jks';
import { Oid } from './oids';
import type { TimeStampToken } from './tsp';

/**
 * Creates CAdES signatures laid out as PrivatBank's `.sig` (docs/provider-formats.md, section 1; CadesSigner.cs,
 * CmsBuilder.cs): SignedData version 1 with the document inside, only the signer's certificate, one SignerInfo with
 * issuerAndSerialNumber and the signed attributes contentType, signingTime, messageDigest and signingCertificateV2
 * (with issuerSerial); D = S‖R little-endian.
 *
 * `signCades` gives CAdES-B. `signCadesT` adds what makes the bank's signatures CAdES-T: a signatureTimeStampToken over
 * the signature value, from a time-stamping service the caller reaches (only the hash of the signature leaves).
 */
export type CadesOptions = {
  /** DSTU 7564-256 (default) or GOST 34.311. */
  readonly hashOid?: string;
  /** Leave the data out of the signature (a .p7s next to the file). */
  readonly detached?: boolean;
  /** The signingTime attribute; the current time when omitted, none when null. */
  readonly signingTime?: Date | null;
};

/** Asks a time-stamping service for a token over `imprint` (the hash of the signature value). */
export type TimeStamper = (imprint: Uint8Array, hashOid: string) => Promise<TimeStampToken>;

export function signCades(data: Uint8Array, signer: SigningKey, options: CadesOptions = {}): Uint8Array {
  const hashOid = options.hashOid ?? Oid.Dstu7564_256;
  const signed = signAttributes(Oid.Data, data, signer, hashOid, signingTimeAttributes(options));
  return signedData(Oid.Data, options.detached ? null : data, hashOid, signer.certificate, signerInfo(signed, signer.certificate, hashOid));
}

/** CAdES-T: CAdES-B plus the signatureTimeStampToken `stamp` returns for the hash of the signature value. */
export async function signCadesT(data: Uint8Array, signer: SigningKey, stamp: TimeStamper, options: CadesOptions = {}): Promise<Uint8Array> {
  const hashOid = options.hashOid ?? Oid.Dstu7564_256;
  const signed = signAttributes(Oid.Data, data, signer, hashOid, signingTimeAttributes(options));
  const token = await stamp(hash(hashOid, signed.signature), hashOid);
  const unsigned = [attribute(Oid.SignatureTimeStampToken, token.cms.encoded)];
  return signedData(Oid.Data, options.detached ? null : data, hashOid, signer.certificate, signerInfo(signed, signer.certificate, hashOid, unsigned));
}

function signingTimeAttributes(options: CadesOptions): Uint8Array[] {
  const time = options.signingTime === undefined ? new Date() : options.signingTime;
  return time ? [attribute(Oid.SigningTime, Der.time(new Date(Math.floor(time.getTime() / 1000) * 1000)))] : [];
}

// ---- CMS building blocks (shared with the tests' time-stamping service) ------------------------------------------------

export type SignedAttributes = { readonly attributes: Uint8Array; readonly signature: Uint8Array };

/**
 * The DER SET OF signed attributes for `content` — contentType, `extra`, messageDigest, signingCertificateV2 — and the
 * signature over it.
 */
export function signAttributes(contentType: string, content: Uint8Array, signer: SigningKey, hashOid: string, extra: Uint8Array[] = []): SignedAttributes {
  const attributes = Der.setOf(
    attribute(Oid.ContentType, Der.objectIdentifier(contentType)),
    ...extra,
    attribute(Oid.MessageDigest, Der.octetString(hash(hashOid, content, signer.key.dke))),
    signingCertificateV2(signer.certificate, hashOid),
  );
  return { attributes, signature: signer.key.signHash(hash(hashOid, attributes, signer.key.dke)) };
}

/** SignerInfo version 1 with issuerAndSerialNumber; `unsigned` attributes when given. */
export function signerInfo(signed: SignedAttributes, certificate: Certificate, hashOid: string, unsigned: Uint8Array[] = []): Uint8Array {
  return Der.sequence(
    Der.integer(1),
    Der.sequence(certificate.issuer.encoded, Der.integer(certificate.serialNumber)),
    Der.algorithm(hashOid),
    Der.implicit(0, signed.attributes),
    Der.algorithm(signatureAlgorithmFor(hashOid)),
    Der.octetString(signed.signature),
    ...(unsigned.length > 0 ? [Der.implicit(1, Der.setOf(...unsigned))] : []),
  );
}

/** ContentInfo { SignedData } with one signer and its certificate; the content is encapsulated unless null. */
export function signedData(contentType: string, content: Uint8Array | null, hashOid: string, certificate: Certificate, info: Uint8Array): Uint8Array {
  const encapContentInfo = content
    ? Der.sequence(Der.objectIdentifier(contentType), Der.explicit(0, Der.octetString(content)))
    : Der.sequence(Der.objectIdentifier(contentType));
  return Der.sequence(
    Der.objectIdentifier(Oid.SignedData),
    Der.explicit(
      0,
      Der.sequence(
        Der.integer(contentType === Oid.Data ? 1 : 3),
        Der.setOf(Der.algorithm(hashOid)),
        encapContentInfo,
        Der.implicit(0, Der.setOf(certificate.encoded)),
        Der.setOf(info),
      ),
    ),
  );
}

/** An Attribute ::= SEQUENCE { attrType, SET OF value }. */
export function attribute(oid: string, ...values: Uint8Array[]): Uint8Array {
  return Der.sequence(Der.objectIdentifier(oid), Der.setOf(...values));
}

/**
 * signingCertificateV2 (RFC 5035): one ESSCertIDv2 with the algorithm written out, the hash of the certificate, and
 * issuerSerial — the issuer as a directoryName [4] and the serial number — as IIT and the banks write it.
 */
function signingCertificateV2(certificate: Certificate, hashOid: string): Uint8Array {
  const issuerSerial = Der.sequence(Der.sequence(Der.explicit(4, certificate.issuer.encoded)), Der.integer(certificate.serialNumber));
  return attribute(
    Oid.SigningCertificateV2,
    Der.sequence(Der.sequence(Der.sequence(Der.algorithm(hashOid), Der.octetString(hash(hashOid, certificate.encoded)), issuerSerial))),
  );
}
