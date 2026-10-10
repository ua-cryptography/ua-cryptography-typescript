import { bitLength, bigIntToBytes, bytesToBigInt } from './bytes';
import { BinaryCurve, type Point } from './math/curve';
import { BinaryField, POLYNOMIAL_TABLE, type Element } from './math/field';
import { isProbablePrime, integerSqrt, modPow } from './math/integers';
import { randomBytes } from './random';

/**
 * DSTU 4145-2002 — domain parameters (7, 8), keys (9, 10), signing (12) and verification (13), with the data
 * conversions of section 5. A port of the C# reference (Dstu4145Signer.cs, Dstu4145Encoding.cs,
 * Dstu4145DomainParameters.cs, Dstu4145NamedCurves.cs), polynomial basis only.
 *
 * Hashes and signatures here are in the order of the standard (most significant byte first); the national PKI stores
 * both reversed — see `pki/keys.ts`.
 */
export class DomainParameters {
  readonly curve: BinaryCurve;
  readonly basePoint: Point;
  readonly n: bigint;

  constructor(curve: BinaryCurve, basePoint: Point, n: bigint) {
    if (basePoint === null) throw new Error('The base point cannot be O.');
    if (n <= 0n) throw new Error('n must be positive.');
    this.curve = curve;
    this.basePoint = basePoint;
    this.n = n;
  }

  get field(): BinaryField {
    return this.curve.field;
  }

  /** The shortest admissible signature length: the least multiple of 16 that is ≥ 2 L(n) (5.7). */
  get minimumSignatureBits(): number {
    return Math.ceil((2 * bitLength(this.n)) / 16) * 16;
  }

  equals(other: DomainParameters): boolean {
    return (
      this === other ||
      (this.curve.equals(other.curve) && this.n === other.n && BinaryCurve.pointsEqual(this.basePoint, other.basePoint))
    );
  }

  /** The checks of 8.1–8.3: null when the parameters are correct, else the first failed condition. */
  validate(): string | null {
    const f = this.field;
    if (!POLYNOMIAL_TABLE.has(f.m)) return '8.1.1: the degree is not listed in table 1';
    // 8.1.2 asks for a primitive polynomial; irreducibility is checked (primitivity needs the factorization of 2^m − 1).
    if (!f.isIrreducible()) return '8.1.2: the reduction polynomial is not irreducible';
    if (this.n % 2n === 0n || !isProbablePrime(this.n)) return '8.2.4: n is not an odd prime';
    const sqrtField = integerSqrt(1n << BigInt(f.m));
    const bound = (1n << 160n) > 4n * (sqrtField + 1n) ? 1n << 160n : 4n * (sqrtField + 1n);
    if (this.n < bound) return '8.2.5: n is too small';
    if (!satisfiesMovCondition(this.n, f.m)) return '8.2.6: the Menezes–Okamoto–Vanstone condition fails';
    if (!this.curve.isOnCurve(this.basePoint)) return '8.3.3: P does not lie on the curve';
    if (this.curve.multiply(this.basePoint, this.n) !== null) return '8.3.4: nP ≠ O';
    return null;
  }

  /** 10.1: null when the public key is correct, else the failed condition. */
  validatePublicKey(q: Point): string | null {
    if (q === null) return '10.1.2: Q = O';
    if (!this.curve.isOnCurve(q)) return '10.1.3: Q does not lie on the curve';
    if (this.curve.multiply(q, this.n) !== null) return '10.1.4: nQ ≠ O';
    return null;
  }

  /** 6.3: a random integer of at most L(n) − 1 bits; the first bits generated are the most significant. */
  randomInteger(): bigint {
    const bits = bitLength(this.n) - 1;
    const bytes = randomBytes(Math.ceil(bits / 8));
    const value = bytesToBigInt(bytes) >> BigInt(8 * bytes.length - bits);
    bytes.fill(0);
    return value;
  }
}

/** 6.13: 2^(mk) ≠ 1 mod n for k = 1 … 32. */
function satisfiesMovCondition(n: bigint, m: number): boolean {
  const k = modPow(2n, BigInt(m), n);
  let j = 1n;
  for (let i = 1; i <= 32; i++) {
    j = (j * k) % n;
    if (j === 1n) return false;
  }
  return true;
}

// ---- Table Г.1 with the base points published by cryptography.org.ua (table 2.1) ------------------------------------

// [m, A, B, n, x(P), y(P)] — generated from the C# reference (Dstu4145NamedCurves.cs).
const SPECS: ReadonlyArray<readonly [number, number, string, string, string, string]> = [
  [163, 1, '5FF6108462A2DC8210AB403925E638A19C1455D21',
    '400000000000000000002BEC12BE2262D39BCF14D',
    '2E2F85F5DD74CE983A5C4237229DAF8A3F35823BE',
    '3826F008A8C51D7B95284D9D03FF0E00CE2CD723A'],
  [167, 1, '6EE3CEEB230811759F20518A0930F1A4315A827DAC',
    '3FFFFFFFFFFFFFFFFFFFFFB12EBCC7D7F29FF7701F',
    '7A1F6653786A68192803910A3D30B2A2018B21CD54',
    '5F49EB26781C0EC6B8909156D98ED435E45FD59918'],
  [173, 0, '108576C80499DB2FC16EDDF6853BBB278F6B6FB437D9',
    '800000000000000000000189B4E67606E3825BB2831',
    '4D41A619BCC6EADF0448FA22FAD567A9181D37389CA',
    '10B51CC12849B234C75E6DD2028BF7FF5C1CE0D991A1'],
  [179, 1, '4A6E0856526436F2F88DD07A341E32D04184572BEB710',
    '3FFFFFFFFFFFFFFFFFFFFFFB981960435FE5AB64236EF',
    '6BA06FE51464B2BD26DC57F48819BA9954667022C7D03',
    '25FBC363582DCEC065080CA8287AAFF09788A66DC3A9E'],
  [191, 1, '7BC86E2102902EC4D5890E8B6B4981FF27E0482750FEFC03',
    '40000000000000000000000069A779CAC1DABC6788F7474F',
    '714114B762F2FF4A7912A6D2AC58B9B5C2FCFE76DAEB7129',
    '29C41E568B77C617EFE5902F11DB96FA9613CD8D03DB08DA'],
  [233, 1, '06973B15095675534C7CF7E64A21BD54EF5DD3B8A0326AA936ECE454D2C',
    '1000000000000000000000000000013E974E72F8A6922031D2603CFE0D7',
    '3FCDA526B6CDF83BA1118DF35B3C31761D3545F32728D003EEB25EFE96',
    '9CA8B57A934C54DEEDA9E54A7BBAD95E3B2E91C54D32BE0B9DF96D8D35'],
  [257, 0, '1CEF494720115657E18F938D7A7942394FF9425C1458C57861F9EEA6ADBE3BE10',
    '800000000000000000000000000000006759213AF182E987D3E17714907D470D',
    '02A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB7',
    '10686D41FF744D4449FCCF6D8EEA03102E6812C93A9D60B978B702CF156D814EF'],
  [307, 1, '393C7F7D53666B5054B5E6C6D3DE94F4296C0C599E2E2E241050DF18B6090BDC90186904968BB',
    '3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC079C2F3825DA70D390FBBA588D4604022B7B7',
    '216EE8B189D291A0224984C1E92F1D16BF75CCD825A087A239B276D3167743C52C02D6E7232AA',
    '5D9306BACD22B7FAEB09D2E049C6E2866C5D1677762A8F2F2DC9A11C7F7BE8340AB2237C7F2A0'],
  [367, 1, '43FC8AD242B0B7A6F3D1627AD5654447556B47BF6AA4A64B0C2AFE42CADAB8F93D92394C79A79755437B56995136',
    '40000000000000000000000000000000000000000000009C300B75A3FA824F22428FD28CE8812245EF44049B2D49',
    '324A6EDDD512F08C49A99AE0D3F961197A76413E7BE81A400CA681E09639B5FE12E59A109F78BF4A373541B3B9A1',
    '1AB597A5B4477F59E39539007C7F977D1A567B92B043A49C6B61984C3FE3481AAF454CD41BA1F051626442B3C10'],
  [431, 1, '03CE10490F6A708FC26DFE8C3D27C4F94E690134D5BFF988D8D28AAEAEDE975936C66BAC536B18AE2DC312CA493117DAA469C640CAF3',
    '3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBA3175458009A8C0A724F02F81AA8A1FCBAF80D90C7A95110504CF',
    '1A62BA79D98133A16BBAE7ED9A8E03C32E0824D57AEF72F88986874E5AAE49C27BED49A2A95058068426C2171E99FD3B43C5947C857D',
    '70B5E1E14031C1F70BBEFE96BDDE66F451754B4CA5F48DA241F331AA396B8D1839A855C1769B1EA14BA53308B5E2723724E090E02DB9'],
];

/** The degrees of the curves of table Г.1; the named-curve OID …3.1.1.2.i is the i-th of them. */
export const NAMED_CURVE_DEGREES: readonly number[] = SPECS.map((s) => s[0]);

const namedCache = new Map<number, DomainParameters>();

/** The curve of table Г.1 over GF(2^m). */
export function namedCurve(m: number): DomainParameters {
  let domain = namedCache.get(m);
  if (!domain) {
    const spec = SPECS.find((s) => s[0] === m);
    if (!spec) throw new Error(`Table Г.1 has no curve over GF(2^${m}).`);
    const [, a, b, n, x, y] = spec;
    const field = BinaryField.recommended(m);
    const curve = new BinaryCurve(field, a, field.fromBigInt(BigInt('0x' + b)));
    domain = new DomainParameters(curve, curve.point(BigInt('0x' + x), BigInt('0x' + y)), BigInt('0x' + n));
    namedCache.set(m, domain);
  }
  return domain;
}

// ---- Section 5: data conversions --------------------------------------------------------------------------------

/** 5.8: field element → integer: the L(n) − 1 least significant bits of its standard representation. */
export function fieldElementToInteger(field: BinaryField, x: Element, n: bigint): bigint {
  return field.toBigInt(x) & ((1n << BigInt(bitLength(n) - 1)) - 1n);
}

/** 5.9: hash (most significant byte first) → field element: its min(m, L_H) least significant bits. */
export function hashToFieldElement(hash: Uint8Array, field: BinaryField): Element {
  return field.fromBigInt(bytesToBigInt(hash) & ((1n << BigInt(field.m)) - 1n));
}

/** 5.10: (r, s) → D = S ‖ R of `signatureBits` bits, big-endian. */
export function encodeSignature(r: bigint, s: bigint, signatureBits: number): Uint8Array {
  if (signatureBits <= 0 || signatureBits % 16 !== 0) throw new Error('The signature length L_D must be a positive multiple of 16.');
  const half = signatureBits / 2;
  if (r <= 0n || s <= 0n || bitLength(r) > half || bitLength(s) > half) throw new Error('r and s must be positive and fit into L_D / 2 bits.');
  return bigIntToBytes((s << BigInt(half)) | r, signatureBits / 8);
}

/** 5.11: D (big-endian) → (r, s). */
export function decodeSignature(signature: Uint8Array): { r: bigint; s: bigint } {
  const half = BigInt((signature.length * 8) / 2);
  const d = bytesToBigInt(signature);
  return { r: d & ((1n << half) - 1n), s: d >> half };
}

// ---- Sections 9, 11–13 ------------------------------------------------------------------------------------------

/** 9.2: Q = −dP. */
export function computePublicKey(domain: DomainParameters, d: bigint): Point {
  if (d <= 0n || d >= domain.n) throw new Error('The private key must satisfy 0 < d < n.');
  return domain.curve.negate(domain.curve.multiplyFixedLength(domain.basePoint, d, domain.n));
}

function hashElement(domain: DomainParameters, hash: Uint8Array): Element {
  if (hash.length === 0) throw new Error('Empty hash.');
  const h = hashToFieldElement(hash, domain.field);
  return BinaryField.isZero(h) ? domain.field.one() : h; // step 7
}

/**
 * Section 12 with an explicit nonce e (for the known-answer tests): returns (r, s), or null when x(eP) = 0, r = 0 or
 * s = 0 — then another e must be taken.
 */
export function signWithNonce(domain: DomainParameters, d: bigint, hash: Uint8Array, e: bigint): { r: bigint; s: bigint } | null {
  if (d <= 0n || d >= domain.n) throw new Error('The private key must satisfy 0 < d < n.');
  if (e <= 0n || e >= domain.n) throw new Error('0 < e < n is required.');
  const f = domain.field;
  const ep = domain.curve.multiplyFixedLength(domain.basePoint, e, domain.n); // section 11
  if (ep === null || BinaryField.isZero(ep.x)) return null;
  const y = f.mul(hashElement(domain, hash), ep.x); // step 9
  const r = fieldElementToInteger(f, y, domain.n); // step 10
  if (r === 0n) return null;
  const s = (e + d * r) % domain.n; // step 12
  if (s === 0n) return null;
  return { r, s };
}

/** Section 12: the signature D (big-endian) of a hash given most significant byte first. */
export function signHash(domain: DomainParameters, d: bigint, hash: Uint8Array, signatureBits = 0): Uint8Array {
  const bits = signatureBits || domain.minimumSignatureBits;
  if (bits % 16 !== 0 || bits < 2 * bitLength(domain.n)) throw new Error('L_D must be a multiple of 16 and at least 2 L(n) (12.3).');
  for (;;) {
    const e = domain.randomInteger();
    if (e === 0n) continue;
    const rs = signWithNonce(domain, d, hash, e);
    if (rs) return encodeSignature(rs.r, rs.s, bits);
  }
}

/**
 * Section 13: verifies D (big-endian) over a hash given most significant byte first. The key is not checked here
 * (10.1 is done when a key is read from a certificate).
 */
export function verifyHash(domain: DomainParameters, q: Point, hash: Uint8Array, signature: Uint8Array): boolean {
  const bits = signature.length * 8;
  if (bits % 16 !== 0 || bits < 2 * bitLength(domain.n)) return false; // step 3
  if (q === null) return false;
  const { r, s } = decodeSignature(signature);
  const n = domain.n;
  if (r <= 0n || r >= n || s <= 0n || s >= n) return false;
  const curve = domain.curve;
  const point = curve.add(curve.multiply(domain.basePoint, s), curve.multiply(q, r)); // R = sP + rQ
  if (point === null) return false;
  const y = domain.field.mul(hashElement(domain, hash), point.x);
  return fieldElementToInteger(domain.field, y, n) === r;
}
