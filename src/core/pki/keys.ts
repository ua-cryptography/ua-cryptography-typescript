import { bitLength, bytesToBigInt, reversed, toHex, wipe } from '../bytes';
import { computePublicKey, DomainParameters, NAMED_CURVE_DEGREES, namedCurve, signHash, verifyHash } from '../dstu4145';
import { BinaryCurve, type Point } from '../math/curve';
import { BinaryField } from '../math/field';
import { candidateHashes, hash, hashOfSignatureAlgorithm, UnsupportedError } from './algorithms';
import { Asn1, Tag } from './asn1';
import { Oid } from './oids';

/**
 * DSTU 4145 keys as the national PKI stores them (docs/signature-formats.md, sections 1 and 3; C# Dstu4145PublicKey.cs,
 * Dstu4145PrivateKey.cs): the hash is reversed before 5.9, D = S‖R is stored little-endian, and the octet strings of the
 * key (B, base point, Q, d) are little-endian for the key OID …3.1.1 and big-endian for …3.1.1.1.1.
 */

export function isDstu4145(algorithmOid: string): boolean {
  return algorithmOid === Oid.Dstu4145Le || algorithmOid === Oid.Dstu4145Be;
}

export class PublicKey {
  constructor(
    readonly domain: DomainParameters,
    readonly q: Point,
    /** The GOST 28147 S-box table for GOST 34.311 (64 bytes), or null (DKE No. 1). */
    readonly dke: Uint8Array | null,
    readonly littleEndian = true,
  ) {}

  /** Verifies D (stored little-endian) over a hash as the hash function output it (section 1). */
  verifyHash(rawHash: Uint8Array, signature: Uint8Array): boolean {
    return verifyHash(this.domain, this.q, reversed(rawHash), reversed(signature));
  }

  /** Verifies a signature over `data` hashed with `hashOid`, trying each of the candidate hashes (GOST DKEs). */
  verifyData(hashOid: string, data: Uint8Array, signature: Uint8Array): boolean {
    return candidateHashes(hashOid, data, this.dke).some((h) => this.verifyHash(h, signature));
  }

  /** Hashes `data` with the hash of `signatureAlgorithm` (GOST 34.311 with this key's DKE) and verifies. */
  verify(signatureAlgorithm: string, data: Uint8Array, signature: Uint8Array): boolean {
    return this.verifyHash(hash(hashOfSignatureAlgorithm(signatureAlgorithm), data, this.dke), signature);
  }

  equals(other: PublicKey): boolean {
    return this.domain.field.m === other.domain.field.m && BinaryCurve.pointsEqual(this.q, other.q);
  }

  /** "DSTU 4145, m = 257" and the like, for reports. */
  describe(): string {
    return `DSTU 4145 key, PB m = ${this.domain.field.m}${this.dke ? ', with DKE' : ''}`;
  }
}

const publicKeys = new Map<string, PublicKey>();

/** Parses SubjectPublicKeyInfo; the parameters are checked by section 8 and the key by 10.1 (cached per encoding). */
export function publicKeyFromSpki(spki: Asn1): PublicKey {
  const cacheKey = toHex(spki.encoded);
  const cached = publicKeys.get(cacheKey);
  if (cached) return cached;
  spki.expect(Tag.Sequence);
  const { domain, dke, littleEndian } = parseKeyAlgorithm(spki.at(0));
  let q = Asn1.parse(spki.at(1).bitString()).expect(Tag.OctetString).octetString();
  if (littleEndian) q = reversed(q);
  const point = domain.curve.decompress(bytesToBigInt(q));
  const error = domain.validatePublicKey(point);
  if (error) throw new Error(`Invalid DSTU 4145 public key: ${error}`);
  const key = new PublicKey(domain, point, dke, littleEndian);
  if (publicKeys.size > 256) publicKeys.clear();
  publicKeys.set(cacheKey, key);
  return key;
}

/** The key AlgorithmIdentifier of SubjectPublicKeyInfo or PKCS#8: { key OID, SEQUENCE { curve, DKE OPTIONAL } }. */
export function parseKeyAlgorithm(algorithm: Asn1): { domain: DomainParameters; dke: Uint8Array | null; littleEndian: boolean } {
  const oid = algorithm.expect(Tag.Sequence).at(0).oid();
  if (!isDstu4145(oid)) throw new UnsupportedError(`Key algorithm ${oid} is not DSTU 4145.`);
  const littleEndian = oid === Oid.Dstu4145Le;
  const parameters = algorithm.at(1).expect(Tag.Sequence);
  const dke = parameters.count > 1 ? parameters.at(1).expect(Tag.OctetString).octetString() : null;
  const curve = parameters.at(0);
  const domain = curve.is(Tag.ObjectIdentifier) ? namedCurveByOid(curve.oid()) : parseExplicit(curve, littleEndian);
  return { domain, dke, littleEndian };
}

function namedCurveByOid(oid: string): DomainParameters {
  const index = oid.startsWith(Oid.NamedCurvePrefix) ? Number(oid.slice(Oid.NamedCurvePrefix.length)) : -1;
  const m = NAMED_CURVE_DEGREES[index];
  if (!Number.isInteger(index) || m === undefined) throw new UnsupportedError(`Unknown DSTU 4145 named curve ${oid}.`);
  return namedCurve(m);
}

const explicitDomains = new Map<string, DomainParameters>();

// ECBinary ::= SEQUENCE { version [0] EXPLICIT INTEGER DEFAULT 0, f BinaryField, a INTEGER, b OCTET STRING,
//                         n INTEGER, bp OCTET STRING }
// BinaryField ::= SEQUENCE { m INTEGER, CHOICE { k INTEGER, SEQUENCE { k, j, l } } OPTIONAL } — absent: ONB.
function parseExplicit(ec: Asn1, littleEndian: boolean): DomainParameters {
  const cacheKey = (littleEndian ? 'le:' : 'be:') + toHex(ec.encoded);
  const cached = explicitDomains.get(cacheKey);
  if (cached) return cached;

  ec.expect(Tag.Sequence);
  const i = ec.at(0).isContext(0) ? 1 : 0;
  const fieldNode = ec.at(i).expect(Tag.Sequence);
  const m = fieldNode.at(0).int();
  // Tables 1 and 2 end at m = 509; a larger field from an untrusted certificate would only make section 8 expensive.
  if (m < 163 || m > 509) throw new Error(`Unsupported DSTU 4145 field degree m = ${m} (tables 1 and 2 cover 163 – 509).`);
  let field: BinaryField;
  if (fieldNode.count === 1) {
    throw new UnsupportedError('The optimal normal basis is not supported (no certificate of the national PKI uses it).');
  } else if (fieldNode.at(1).is(Tag.Integer)) {
    field = new BinaryField(m, fieldNode.at(1).int());
  } else {
    const p = fieldNode.at(1).expect(Tag.Sequence);
    field = new BinaryField(m, p.at(0).int(), p.at(1).int(), p.at(2).int());
  }
  const a = ec.at(i + 1).int();
  let b = ec.at(i + 2).expect(Tag.OctetString).octetString();
  const n = ec.at(i + 3).integer();
  let g = ec.at(i + 4).expect(Tag.OctetString).octetString();
  if (littleEndian) {
    b = reversed(b);
    g = reversed(g);
  }
  const curve = new BinaryCurve(field, a, field.fromBigInt(bytesToBigInt(b)));
  let domain = new DomainParameters(curve, curve.decompress(bytesToBigInt(g)), n);

  // The parameters of table Г.1 are the same objects as the named curves; anything else is checked by section 8.
  const named = NAMED_CURVE_DEGREES.includes(m) ? namedCurve(m) : null;
  if (named && named.equals(domain)) {
    domain = named;
  } else {
    const error = domain.validate();
    if (error) throw new Error(`Invalid DSTU 4145 domain parameters: ${error}`);
  }
  if (explicitDomains.size >= 64) explicitDomains.clear();
  explicitDomains.set(cacheKey, domain);
  return domain;
}

/** A DSTU 4145 private key with its parameters and DKE: signs raw hashes by the national convention. */
export class PrivateKey {
  readonly publicKey: PublicKey;

  constructor(
    readonly domain: DomainParameters,
    private readonly d: bigint,
    readonly dke: Uint8Array | null,
    readonly littleEndian = true,
  ) {
    this.publicKey = new PublicKey(domain, computePublicKey(domain, d), dke, littleEndian);
  }

  /** Signs a hash as the hash function output it; returns D little-endian. */
  signHash(rawHash: Uint8Array): Uint8Array {
    return reversed(signHash(this.domain, this.d, reversed(rawHash)));
  }

  /** Hashes `data` with the hash of `signatureAlgorithm` (GOST 34.311 with this key's DKE) and signs. */
  sign(signatureAlgorithm: string, data: Uint8Array): Uint8Array {
    return this.signHash(hash(hashOfSignatureAlgorithm(signatureAlgorithm), data, this.dke));
  }

  /**
   * PKCS#8 PrivateKeyInfo as Ukrainian banks store it in JKS: version 0, the key AlgorithmIdentifier and d as an OCTET
   * STRING in the byte order of the key OID. The BouncyCastle form (an OCTET STRING holding a DER INTEGER) is accepted
   * too; the two are told apart by length. Attributes after the key (the IIT key-agreement key) are ignored.
   */
  static fromPkcs8(pkcs8: Uint8Array): PrivateKey {
    const info = Asn1.parse(pkcs8).expect(Tag.Sequence);
    const { domain, dke, littleEndian } = parseKeyAlgorithm(info.at(1));
    const raw = info.at(2).expect(Tag.OctetString).octetString();
    try {
      const scalarLength = Math.ceil(bitLength(domain.n) / 8);
      const integer = raw.length !== scalarLength ? Asn1.tryParse(raw) : null;
      const d = integer?.is(Tag.Integer) ? integer.integer() : bytesToBigInt(littleEndian ? reversed(raw) : raw);
      if (d <= 0n || d >= domain.n) throw new Error('The DSTU 4145 private key is out of range (0, n).');
      return new PrivateKey(domain, d, dke, littleEndian);
    } finally {
      wipe(raw);
    }
  }
}
