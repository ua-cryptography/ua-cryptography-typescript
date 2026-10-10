import { bitLength } from '../bytes';
import { BinaryField, type Element } from './field';

/** An affine point; `null` stands for the point at infinity O. */
export type Point = { readonly x: Element; readonly y: Element } | null;

/**
 * The curve y² + xy = x³ + Ax² + B over GF(2^m), A ∈ {0, 1}, B ≠ 0 (DSTU 4145-2002, 5.4) — a port of the C# reference
 * (BinaryCurve.cs): the group law of В.7–В.8, kP by the Montgomery ladder in López–Dahab coordinates, and point
 * compression (6.9, 6.10).
 */
export class BinaryCurve {
  readonly field: BinaryField;
  readonly a: 0 | 1;
  readonly b: Element;
  private readonly sqrtB: Element;

  constructor(field: BinaryField, a: number, b: Element) {
    if (a !== 0 && a !== 1) throw new Error('Coefficient A must be 0 or 1 (DSTU 4145-2002, 5.4).');
    if (BinaryField.isZero(b)) throw new Error('Coefficient B must be non-zero.');
    this.field = field;
    this.a = a;
    this.b = b;
    this.sqrtB = field.sqrt(b);
  }

  equals(other: BinaryCurve): boolean {
    return this.field.equals(other.field) && this.a === other.a && BinaryField.equal(this.b, other.b);
  }

  /** A point given by the standard representations of its coordinates; throws unless it lies on the curve. */
  point(x: bigint, y: bigint): Point {
    const p = { x: this.field.fromBigInt(x), y: this.field.fromBigInt(y) };
    if (!this.isOnCurve(p)) throw new Error('The point does not lie on the curve.');
    return p;
  }

  isOnCurve(p: Point): boolean {
    if (p === null) return true;
    const f = this.field;
    const x2 = f.sqr(p.x);
    const lhs = f.add(f.sqr(p.y), f.mul(p.x, p.y));
    let rhs = f.add(f.mul(x2, p.x), this.b);
    if (this.a === 1) rhs = f.add(rhs, x2);
    return BinaryField.equal(lhs, rhs);
  }

  static pointsEqual(p: Point, q: Point): boolean {
    if (p === null || q === null) return p === q;
    return BinaryField.equal(p.x, q.x) && BinaryField.equal(p.y, q.y);
  }

  /** −P = (x, x + y). */
  negate(p: Point): Point {
    return p === null ? null : { x: p.x, y: this.field.add(p.x, p.y) };
  }

  add(p: Point, q: Point): Point {
    if (p === null) return q;
    if (q === null) return p;
    const f = this.field;
    if (BinaryField.equal(p.x, q.x)) return BinaryField.equal(p.y, q.y) ? this.double(p) : null;
    // В.8 prints the denominator of the second formula as (x_P + y_Q); it must be x_P + x_Q.
    const xSum = f.add(p.x, q.x);
    const lambda = f.mul(f.add(p.y, q.y), f.inv(xSum));
    let x3 = f.add(f.add(f.sqr(lambda), lambda), xSum);
    if (this.a === 1) x3 = f.add(x3, f.one());
    const y3 = f.add(f.add(f.mul(lambda, f.add(p.x, x3)), x3), p.y);
    return { x: x3, y: y3 };
  }

  double(p: Point): Point {
    if (p === null) return null;
    const f = this.field;
    if (BinaryField.isZero(p.x)) return null; // the only point of order 2: (0, √B)
    const x2 = f.sqr(p.x);
    const xr = f.add(x2, f.mul(this.b, f.inv(x2)));
    const yr = f.add(f.add(x2, f.mul(f.add(p.x, f.mul(p.y, f.inv(p.x))), xr)), xr);
    return { x: xr, y: yr };
  }

  /** kP for any integer k. */
  multiply(p: Point, k: bigint): Point {
    if (k < 0n) return this.multiply(this.negate(p), -k);
    if (k === 0n || p === null) return null;
    if (BinaryField.isZero(p.x)) return k % 2n === 0n ? null : p; // point of order 2
    return this.ladder(p, k, bitLength(k));
  }

  /**
   * kP for a point of prime order n with a fixed number of ladder steps (k + n or k + 2n has exactly L(n) + 1 bits), so
   * the number of steps does not depend on the secret scalar. JavaScript gives no constant-time guarantees beyond that.
   */
  multiplyFixedLength(p: Point, k: bigint, n: bigint): Point {
    if (p === null || n <= 0n) throw new Error('A finite point of known order is required.');
    let kk = ((k % n) + n) % n;
    if (kk === 0n) return null;
    const bits = bitLength(n) + 1;
    kk += n;
    if (bitLength(kk) < bits) kk += n;
    return this.ladder(p, kk, bits);
  }

  /** The Montgomery ladder (López, Dahab, CHES 1999): 6 multiplications and 5 squarings per bit, one inversion. */
  private ladder(p: { x: Element; y: Element }, k: bigint, bits: number): Point {
    const f = this.field;
    const x = p.x;
    let x1: Element = x.slice();
    let z1: Element = f.one();
    let z2: Element = f.sqr(x);
    let x2: Element = f.add(f.sqr(z2), this.b); // X2 = x⁴ + B, Z2 = x²: (X1 : Z1) = P, (X2 : Z2) = 2P
    const t1 = f.zero();
    const t2 = f.zero();
    const scalar = k.toString(2).padStart(bits, '0');
    for (let i = bits - 2; i >= 0; i--) {
      if (scalar.charCodeAt(bits - 1 - i) === 49) {
        [x1, x2] = [x2, x1];
        [z1, z2] = [z2, z1];
      }
      // (X2 : Z2) ← R0 + R1 (their difference is P), (X1 : Z1) ← 2·R0
      f.mulInto(x2, z1, t1); // T1 = Xa Zb   (a = 2, b = 1)
      f.mulInto(x1, z2, t2); // T2 = Xb Za
      f.addInto(t1, t2, z2);
      f.sqrInto(z2, z2); // Za = (Xa Zb + Xb Za)²
      f.mulInto(t1, t2, t1);
      f.mulInto(x, z2, x2);
      f.addInto(x2, t1, x2); // Xa = x Za + Xa Zb Xb Za
      // (X1 : Z1) ← 2 (X1 : Z1): X = (X² + √B Z²)², Z = X² Z²
      f.sqrInto(x1, t1);
      f.sqrInto(z1, t2);
      f.mulInto(t1, t2, z1);
      f.mulInto(t2, this.sqrtB, t2);
      f.addInto(t1, t2, x1);
      f.sqrInto(x1, x1);
      if (scalar.charCodeAt(bits - 1 - i) === 49) {
        [x1, x2] = [x2, x1];
        [z1, z2] = [z2, z1];
      }
    }
    return this.recoverAffine(p, x1, z1, x2, z2);
  }

  /** The affine kP from (X1 : Z1) = kP, (X2 : Z2) = (k + 1)P and P (López–Dahab, Mxy). */
  private recoverAffine(p: { x: Element; y: Element }, x1: Element, z1: Element, x2: Element, z2: Element): Point {
    const f = this.field;
    if (BinaryField.isZero(z1)) return null;
    if (BinaryField.isZero(z2)) return this.negate(p); // (k + 1)P = O, so kP = −P
    const { x, y } = p;
    const t3 = f.mul(z1, z2);
    const a = f.add(f.mul(z1, x), x1); // X1 + x Z1
    let b = f.mul(z2, x);
    const xk = f.mul(b, x1);
    b = f.mul(a, f.add(b, x2)); // (X1 + x Z1)(X2 + x Z2)
    let t4 = f.add(f.mul(f.add(f.sqr(x), y), t3), b); // numerator
    const inv = f.inv(f.mul(t3, x));
    t4 = f.mul(t4, inv);
    const xr = f.mul(xk, inv);
    const yr = f.add(f.mul(f.add(xr, x), t4), y);
    return { x: xr, y: yr };
  }

  /** Point compression (6.9): the least significant bit of x is replaced by tr(y/x); 0 stands for a point with x = 0. */
  compress(p: Point): bigint {
    if (p === null || BinaryField.isZero(p.x)) return 0n;
    const f = this.field;
    const i = BigInt(f.trace(f.mul(p.y, f.inv(p.x))));
    const compressed = (f.toBigInt(p.x) & ~1n) | i;
    // x = 1 with tr(y/x) = 0 compresses to 0, which 6.10 decodes as (0, √B): a gap in the standard (probability ~2^−m).
    if (compressed === 0n) throw new Error('This point has no unambiguous compressed form (6.9 maps it to 0).');
    return compressed;
  }

  /** Point decompression (6.10); throws when the value encodes no point of this curve. */
  decompress(compressed: bigint): Point {
    const f = this.field;
    if (compressed === 0n) return { x: f.zero(), y: this.sqrtB.slice() };
    const k = Number(compressed & 1n);
    let x = f.fromBigInt(compressed & ~1n);
    if (f.trace(x) !== this.a) x = f.fromBigInt(compressed | 1n);
    if (BinaryField.isZero(x)) throw new Error('The value does not encode a point of the curve.');
    const x2 = f.sqr(x);
    let rhs = f.add(f.mul(x2, x), this.b);
    if (this.a === 1) rhs = f.add(rhs, x2);
    const v = f.mul(rhs, f.inv(x2));
    const z = f.solveQuadratic(f.one(), v);
    if (z === null) throw new Error('The value does not encode a point of the curve.');
    const y = f.trace(z) === k ? f.mul(z, x) : f.mul(f.add(z, f.one()), x);
    return { x, y };
  }
}
