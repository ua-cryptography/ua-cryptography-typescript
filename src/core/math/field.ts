/**
 * GF(2^m) in the polynomial basis t^m + t^k + 1 or t^m + t^l + t^j + t^k + 1 (DSTU 4145-2002, 5.2, table 1) — the
 * only basis the national PKI uses. Elements are Uint32Arrays of ⌈m/32⌉ words, least significant word first: bit i is
 * the coefficient of t^i, exactly the standard representation of 5.3.
 *
 * The C# reference keeps 64-bit words and uses carry-less multiplication instructions; JavaScript has neither, so
 * multiplication is the left-to-right comb with a 4-bit window (Hankerson, Menezes, Vanstone, Algorithm 2.36) over
 * 32-bit words. The generic algorithms (Itoh–Tsujii inversion, trace, half-trace, the quadratic equation of 6.7) are
 * written in terms of multiplication and squaring, as in the reference.
 */

export type Element = Uint32Array;

/** Recommended primitive polynomials of table 1: m → [k, j, l], j = l = 0 for trinomials. */
export const POLYNOMIAL_TABLE: ReadonlyMap<number, readonly [number, number, number]> = new Map([
  [163, [3, 6, 7]], [167, [6, 0, 0]], [173, [1, 2, 10]], [179, [1, 2, 4]], [181, [1, 6, 7]],
  [191, [9, 0, 0]], [193, [15, 0, 0]], [197, [1, 2, 21]], [199, [1, 2, 11]], [211, [1, 6, 12]],
  [223, [1, 2, 12]], [227, [1, 2, 21]], [229, [1, 2, 21]], [233, [1, 4, 9]], [239, [1, 2, 15]],
  [241, [1, 4, 15]], [251, [1, 4, 14]], [257, [12, 0, 0]], [263, [1, 2, 27]], [269, [1, 6, 7]],
  [271, [1, 3, 16]], [277, [2, 3, 23]], [281, [1, 4, 9]], [283, [1, 9, 26]], [293, [1, 6, 11]],
  [307, [2, 4, 8]], [311, [1, 4, 29]], [313, [1, 3, 7]], [317, [2, 5, 9]], [331, [2, 5, 12]],
  [337, [1, 6, 10]], [347, [1, 6, 17]], [349, [2, 5, 6]], [353, [3, 7, 26]], [359, [2, 4, 18]],
  [367, [21, 0, 0]], [373, [1, 6, 9]], [379, [1, 6, 17]], [383, [1, 5, 9]], [389, [1, 10, 17]],
  [397, [1, 3, 22]], [401, [1, 4, 29]], [409, [1, 6, 15]], [419, [1, 14, 21]], [421, [1, 4, 7]],
  [431, [1, 3, 5]], [433, [1, 5, 15]], [439, [2, 3, 8]], [443, [1, 3, 28]], [449, [3, 5, 25]],
  [457, [16, 0, 0]], [461, [1, 4, 23]], [463, [1, 3, 24]], [467, [1, 3, 28]], [479, [1, 6, 25]],
  [487, [1, 2, 15]], [491, [2, 6, 17]], [499, [2, 6, 29]], [503, [3, 0, 0]], [509, [2, 3, 23]],
] as const);

// SPREAD[b]: the 8 bits of b interleaved with zeros (squaring is linear in GF(2)[t]).
const SPREAD = new Uint16Array(256);
for (let b = 0; b < 256; b++) {
  let s = 0;
  for (let i = 0; i < 8; i++) if (b & (1 << i)) s |= 1 << (2 * i);
  SPREAD[b] = s;
}

function popcount(x: number): number {
  x = x - ((x >>> 1) & 0x55555555);
  x = (x & 0x33333333) + ((x >>> 2) & 0x33333333);
  return (((x + (x >>> 4)) & 0x0f0f0f0f) * 0x01010101) >>> 24;
}

export class BinaryField {
  readonly m: number;
  readonly k: number;
  readonly j: number;
  readonly l: number;
  readonly words: number;
  private readonly terms: number[]; // exponents of the reduction polynomial below m, including 0
  private readonly product: Uint32Array; // scratch: 2 · words
  private readonly table: Uint32Array; // scratch: 16 · (words + 1), the comb's precomputed multiples
  private traceMask: Uint32Array | null = null;

  /** `j` and `l` are 0 for a trinomial. */
  constructor(m: number, k: number, j = 0, l = 0) {
    if (!Number.isInteger(m) || m < 2 || m > 4096) throw new Error(`Unsupported field degree m = ${m}.`);
    if (k <= 0 || k >= m) throw new Error('k must satisfy 0 < k < m.');
    if (j === 0 && l === 0) this.terms = [0, k];
    else if (k < j && j < l && l < m) this.terms = [0, k, j, l];
    else throw new Error('A pentanomial requires 0 < k < j < l < m.');
    // Word-level reduction folds a whole word below position m in one step: the middle terms must be well below m.
    if (this.terms[this.terms.length - 1]! > m - 32) throw new Error("The reduction polynomial's middle terms must be below m - 32.");
    this.m = m;
    this.k = k;
    this.j = j;
    this.l = l;
    this.words = (m + 31) >>> 5;
    this.product = new Uint32Array(2 * this.words);
    this.table = new Uint32Array(16 * (this.words + 1));
  }

  /** GF(2^m) with the recommended polynomial of table 1. */
  static recommended(m: number): BinaryField {
    const p = POLYNOMIAL_TABLE.get(m);
    if (!p) throw new Error(`m = ${m} is not listed in table 1.`);
    return new BinaryField(m, p[0], p[1], p[2]);
  }

  get isTrinomial(): boolean {
    return this.j === 0;
  }

  equals(other: BinaryField): boolean {
    return this.m === other.m && this.k === other.k && this.j === other.j && this.l === other.l;
  }

  zero(): Element {
    return new Uint32Array(this.words);
  }

  one(): Element {
    const r = new Uint32Array(this.words);
    r[0] = 1;
    return r;
  }

  /** The element whose standard representation is `value` (0 ≤ value < 2^m). */
  fromBigInt(value: bigint): Element {
    if (value < 0n || value >> BigInt(this.m) !== 0n) throw new Error(`A field element is a non-negative integer of at most ${this.m} bits.`);
    const r = new Uint32Array(this.words);
    let v = value;
    for (let i = 0; i < this.words && v !== 0n; i++) {
      r[i] = Number(v & 0xffffffffn);
      v >>= 32n;
    }
    return r;
  }

  toBigInt(a: Element): bigint {
    let v = 0n;
    for (let i = this.words - 1; i >= 0; i--) v = (v << 32n) | BigInt(a[i]!);
    return v;
  }

  static isZero(a: Element): boolean {
    for (let i = 0; i < a.length; i++) if (a[i] !== 0) return false;
    return true;
  }

  static equal(a: Element, b: Element): boolean {
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }

  isOne(a: Element): boolean {
    if (a[0] !== 1) return false;
    for (let i = 1; i < a.length; i++) if (a[i] !== 0) return false;
    return true;
  }

  add(a: Element, b: Element): Element {
    const r = new Uint32Array(this.words);
    for (let i = 0; i < this.words; i++) r[i] = a[i]! ^ b[i]!;
    return r;
  }

  /** r = a + b; r may alias a or b. */
  addInto(a: Element, b: Element, r: Element): void {
    for (let i = 0; i < this.words; i++) r[i] = a[i]! ^ b[i]!;
  }

  mul(a: Element, b: Element): Element {
    const r = new Uint32Array(this.words);
    this.mulInto(a, b, r);
    return r;
  }

  sqr(a: Element): Element {
    const r = new Uint32Array(this.words);
    this.sqrInto(a, r);
    return r;
  }

  /** r = a · b; r may alias a or b. */
  mulInto(a: Element, b: Element, r: Element): void {
    const w = this.words;
    const w1 = w + 1;
    const t = this.table;
    const c = this.product;
    // t[u] = u(t) · b(t) for every 4-bit polynomial u, each of w + 1 words.
    t.fill(0, 0, w1);
    for (let i = 0; i < w; i++) t[w1 + i] = b[i]!;
    t[w1 + w] = 0;
    for (let u = 2; u < 16; u += 2) {
      const half = (u >> 1) * w1;
      const dst = u * w1;
      let carry = 0;
      for (let i = 0; i < w1; i++) {
        const v = t[half + i]!;
        t[dst + i] = (v << 1) | carry;
        carry = v >>> 31;
      }
      const odd = dst + w1;
      for (let i = 0; i < w1; i++) t[odd + i] = t[dst + i]! ^ t[w1 + i]!;
    }

    c.fill(0);
    for (let shift = 28; shift >= 0; shift -= 4) {
      for (let j = 0; j < w; j++) {
        const u = (a[j]! >>> shift) & 15;
        if (u === 0) continue;
        const src = u * w1;
        const top = Math.min(w1, 2 * w - j);
        for (let i = 0; i < top; i++) c[j + i] = c[j + i]! ^ t[src + i]!;
      }
      if (shift !== 0) {
        for (let i = 2 * w - 1; i > 0; i--) c[i] = (c[i]! << 4) | (c[i - 1]! >>> 28);
        c[0] = c[0]! << 4;
      }
    }
    this.reduce(r);
  }

  /** r = a²; r may alias a. */
  sqrInto(a: Element, r: Element): void {
    const c = this.product;
    for (let i = 0; i < this.words; i++) {
      const x = a[i]!;
      c[2 * i] = SPREAD[x & 0xff]! | (SPREAD[(x >>> 8) & 0xff]! << 16);
      c[2 * i + 1] = SPREAD[(x >>> 16) & 0xff]! | (SPREAD[x >>> 24]! << 16);
    }
    this.reduce(r);
  }

  /** r = this.product mod f(t). */
  private reduce(r: Element): void {
    const c = this.product;
    const m = this.m;
    const top = m >>> 5; // the word that holds bit m
    const shift = m & 31;
    for (let i = c.length - 1; i > top; i--) {
      const v = c[i]!;
      if (v === 0) continue;
      c[i] = 0;
      const base = 32 * i - m;
      for (const e of this.terms) xorAt(c, v, base + e);
    }
    const rest = c[top]! >>> shift;
    if (rest !== 0 || shift === 0) {
      c[top] = shift === 0 ? 0 : c[top]! & ((1 << shift) - 1);
      if (rest !== 0) for (const e of this.terms) xorAt(c, rest, e);
    }
    for (let i = 0; i < this.words; i++) r[i] = c[i]!;
  }

  /** a^(2^k). */
  sqrTimes(a: Element, k: number): Element {
    const r = a.slice();
    for (let i = 0; i < k; i++) this.sqrInto(r, r);
    return r;
  }

  /** a⁻¹ = a^(2^m − 2) by Itoh–Tsujii (DSTU 4145-2002, В.4); the inverse of zero is reported as zero. */
  inv(a: Element): Element {
    const n = this.m - 1;
    const top = 31 - Math.clz32(n);
    const b = a.slice(); // b = a^(2^k − 1), k = 1
    let k = 1;
    for (let i = top - 1; i >= 0; i--) {
      const c = this.sqrTimes(b, k);
      this.mulInto(b, c, b);
      k *= 2;
      if ((n >> i) & 1) {
        this.sqrInto(b, b);
        this.mulInto(b, a, b);
        k++;
      }
    }
    this.sqrInto(b, b);
    return b;
  }

  /** √a = a^(2^(m − 1)). */
  sqrt(a: Element): Element {
    return this.sqrTimes(a, this.m - 1);
  }

  /**
   * Trace (6.5), 0 or 1. It is GF(2)-linear, so it is the parity of a AND a mask computed once per field from the
   * definition.
   */
  trace(a: Element): number {
    const mask = (this.traceMask ??= this.computeTraceMask());
    let acc = 0;
    for (let i = 0; i < this.words; i++) acc ^= a[i]! & mask[i]!;
    return popcount(acc) & 1;
  }

  /** The trace by the definition of 6.5: a + a² + … + a^(2^(m−1)). */
  traceByDefinition(a: Element): number {
    const t = a.slice();
    for (let i = 1; i < this.m; i++) {
      this.sqrInto(t, t);
      this.addInto(t, a, t);
    }
    if (BinaryField.isZero(t)) return 0;
    if (!this.isOne(t)) throw new Error('Trace is neither 0 nor 1: the field arithmetic is broken.');
    return 1;
  }

  /**
   * tr(t^i) for every i: by Newton's identities over the reduction polynomial f, the power sums of its roots satisfy
   * s_i = i·f_(m−i) + Σ f_(m−j) s_(i−j) — over GF(2) they are the traces of the basis elements. Checked against the
   * definition in the tests.
   */
  private computeTraceMask(): Uint32Array {
    const m = this.m;
    // coefficient f_e of t^e in f(t) = t^m + Σ t^e
    const f = new Uint8Array(m + 1);
    f[m] = 1;
    for (const e of this.terms) f[e] = 1;
    const s = new Uint8Array(m);
    s[0] = m & 1; // tr(1) = m mod 2
    for (let i = 1; i < m; i++) {
      let v = (i & 1) & f[m - i]!;
      for (let j = 1; j < i; j++) v ^= f[m - j]! & s[i - j]!;
      s[i] = v;
    }
    const mask = new Uint32Array(this.words);
    for (let i = 0; i < m; i++) if (s[i]) mask[i >>> 5] = mask[i >>> 5]! | (1 << (i & 31));
    return mask;
  }

  /** Half-trace (6.6), m odd: Σ a^(4^i), i = 0 … (m − 1)/2. */
  halfTrace(a: Element): Element {
    if ((this.m & 1) === 0) throw new Error('Half-trace is defined for odd m only.');
    const r = a.slice();
    for (let i = 1; i <= (this.m - 1) / 2; i++) {
      this.sqrInto(r, r);
      this.sqrInto(r, r);
      this.addInto(r, a, r);
    }
    return r;
  }

  /** One solution of z² + uz = w (6.7), or null when there is none. */
  solveQuadratic(u: Element, w: Element): Element | null {
    if (BinaryField.isZero(u)) return this.sqrt(w);
    if (BinaryField.isZero(w)) return this.zero();
    const uInv = this.inv(u);
    const v = this.mul(w, this.sqr(uInv)); // v = w u⁻²
    if (this.trace(v) === 1) return null;
    return this.mul(this.halfTrace(v), u);
  }

  /**
   * For prime m: f is irreducible iff t^(2^m) = t mod f (Rabin's test; f has no roots in GF(2) by construction).
   */
  isIrreducible(): boolean {
    if (!isSmallPrime(this.m)) throw new Error('The quick irreducibility test requires a prime m.');
    const t = this.zero();
    t[0] = 2;
    return BinaryField.equal(this.sqrTimes(t, this.m), t);
  }
}

function xorAt(c: Uint32Array, v: number, bit: number): void {
  const w = bit >>> 5;
  const s = bit & 31;
  c[w] = c[w]! ^ (v << s);
  if (s !== 0) c[w + 1] = c[w + 1]! ^ (v >>> (32 - s));
}

function isSmallPrime(n: number): boolean {
  if (n < 2) return false;
  for (let d = 2; d * d <= n; d++) if (n % d === 0) return false;
  return true;
}
