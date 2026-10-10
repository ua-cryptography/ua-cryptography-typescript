import { equal } from '../bytes';
import { Dstu7564 } from '../hash/dstu7564';
import { DEFAULT_DKE, Gost34311 } from '../hash/gost';
import { sha1, sha256 } from '../hash/sha';
import { Oid } from './oids';

/**
 * The algorithms of the Ukrainian PKI by their identifiers: hashes by OID and XML URI, and the signature algorithm that
 * goes with each hash (C# PkiAlgorithms.cs).
 */

export const XmlAlgorithm = {
  Dstu7564_256: 'http://www.w3.org/2001/04/xmlenc#dstu7564-256',
  Gost34311: 'http://www.w3.org/2001/04/xmlenc#gost34311',
  SignatureDstu7564: 'http://www.w3.org/2001/04/xmldsig-more#dstu4145-dstu7564-256',
  SignatureGost34311: 'http://www.w3.org/2001/04/xmldsig-more#dstu4145-gost34311',
  Sha1: 'http://www.w3.org/2000/09/xmldsig#sha1',
  Sha256: 'http://www.w3.org/2001/04/xmlenc#sha256',
} as const;

/** The hash of `data` by its OID, as the hash function outputs it; GOST 34.311 with `dke`, or DKE No. 1. */
export function hash(oid: string, data: Uint8Array, dke?: Uint8Array | null): Uint8Array {
  switch (oid) {
    case Oid.Gost34311:
      return Gost34311.hash(data, dke);
    case Oid.Dstu7564_256:
      return Dstu7564.hash(data, 256);
    case Oid.Dstu7564_384:
      return Dstu7564.hash(data, 384);
    case Oid.Dstu7564_512:
      return Dstu7564.hash(data, 512);
    case Oid.Sha1:
      return sha1(data);
    case Oid.Sha256:
      return sha256(data);
    default:
      throw new UnsupportedError(`Hash algorithm ${oid} is not supported.`);
  }
}

export function isSupportedHash(oid: string): boolean {
  return ([Oid.Gost34311, Oid.Dstu7564_256, Oid.Dstu7564_384, Oid.Dstu7564_512, Oid.Sha1, Oid.Sha256] as string[]).includes(oid);
}

/**
 * The hashes a verifier accepts for document data and signed attributes: GOST 34.311 with the signer's DKE and, when it
 * is not DKE No. 1, also with DKE No. 1 (the formats do not fix which table a tool hashes with). Others have one value.
 */
export function candidateHashes(oid: string, data: Uint8Array, dke: Uint8Array | null): Uint8Array[] {
  const first = hash(oid, data, dke);
  if (oid === Oid.Gost34311 && dke && !equal(dke, DEFAULT_DKE)) return [first, hash(oid, data)];
  return [first];
}

export function digestMatches(oid: string, data: Uint8Array, expected: Uint8Array, dke: Uint8Array | null): boolean {
  return candidateHashes(oid, data, dke).some((h) => equal(h, expected));
}

/** The hash a signature algorithm ("DSTU 4145 with …") stands for. */
export function hashOfSignatureAlgorithm(signatureAlgorithm: string): string {
  if (signatureAlgorithm === Oid.Dstu4145WithDstu7564) return Oid.Dstu7564_256;
  if (signatureAlgorithm === Oid.Dstu4145WithGost34311) return Oid.Gost34311;
  throw new UnsupportedError(`Signature algorithm ${signatureAlgorithm} is not supported.`);
}

/** The signature algorithm used with a hash in the national PKI. */
export function signatureAlgorithmFor(hashOid: string): string {
  if (hashOid === Oid.Dstu7564_256) return Oid.Dstu4145WithDstu7564;
  if (hashOid === Oid.Gost34311) return Oid.Dstu4145WithGost34311;
  throw new UnsupportedError(`No DSTU 4145 signature algorithm is defined for hash ${hashOid}.`);
}

/** The hash OID behind an XML DigestMethod or SignatureMethod URI. */
export function hashOfXmlAlgorithm(uri: string): string {
  switch (uri) {
    case XmlAlgorithm.Dstu7564_256:
    case XmlAlgorithm.SignatureDstu7564:
      return Oid.Dstu7564_256;
    case XmlAlgorithm.Gost34311:
    case XmlAlgorithm.SignatureGost34311:
      return Oid.Gost34311;
    case XmlAlgorithm.Sha1:
      return Oid.Sha1;
    case XmlAlgorithm.Sha256:
      return Oid.Sha256;
    default:
      throw new UnsupportedError(`XML algorithm ${uri} is not supported.`);
  }
}

export function hashName(oid: string): string {
  switch (oid) {
    case Oid.Gost34311:
      return 'GOST 34.311-95';
    case Oid.Dstu7564_256:
      return 'DSTU 7564-256';
    case Oid.Dstu7564_384:
      return 'DSTU 7564-384';
    case Oid.Dstu7564_512:
      return 'DSTU 7564-512';
    case Oid.Sha1:
      return 'SHA-1';
    case Oid.Sha256:
      return 'SHA-256';
    default:
      return oid;
  }
}

/** The name of a signature algorithm given by its OID or XML-DSig URI; unknown ones are returned as given. */
export function signatureAlgorithmName(identifier: string): string {
  switch (identifier) {
    case Oid.Dstu4145WithDstu7564:
    case XmlAlgorithm.SignatureDstu7564:
      return 'DSTU 4145 with DSTU 7564-256';
    case Oid.Dstu4145WithGost34311:
    case XmlAlgorithm.SignatureGost34311:
      return 'DSTU 4145 with GOST 34.311-95';
    default:
      return identifier;
  }
}

/** An algorithm or a structure this implementation does not handle (as opposed to a wrong signature). */
export class UnsupportedError extends Error {
  override name = 'UnsupportedError';
}
