/**
 * GOST 28147-89 (one 64-bit block, the simple substitution mode) and GOST 34.311-95, the hash of older Ukrainian
 * certificates — a port of the C# reference (Gost28147.cs, Gost34311.cs).
 *
 * The hash returns H as GOST defines it, least significant byte first; DSTU 4145 signs the reversed bytes. The
 * substitution table is a parameter: Ukrainian certificates carry it as a 64-byte DKE, DKE No. 1 when absent.
 */

/** DKE No. 1, the default substitution table of DSTU 4145 (BouncyCastle's Dstu4145Params.GetDefaultDke()). */
export const DEFAULT_DKE = Uint8Array.from([
  0xa9, 0xd6, 0xeb, 0x45, 0xf1, 0x3c, 0x70, 0x82, 0x80, 0xc4, 0x96, 0x7b, 0x23, 0x1f, 0x5e, 0xad,
  0xf6, 0x58, 0xeb, 0xa4, 0xc0, 0x37, 0x29, 0x1d, 0x38, 0xd9, 0x6b, 0xf0, 0x25, 0xca, 0x4e, 0x17,
  0xf8, 0xe9, 0x72, 0x0d, 0xc6, 0x15, 0xb4, 0x3a, 0x28, 0x97, 0x5f, 0x0b, 0xc1, 0xde, 0xa3, 0x64,
  0x38, 0xb5, 0x64, 0xea, 0x2c, 0x17, 0x9f, 0xd0, 0x12, 0x3e, 0x6d, 0xb8, 0xfa, 0xc5, 0x79, 0x04,
]);

/** A 64-byte DKE (two S-box entries per byte, high nibble first) as the 128-entry table. */
export function expandDke(dke: Uint8Array): Uint8Array {
  if (dke.length !== 64) throw new Error('DKE must be 64 bytes long.');
  const sbox = new Uint8Array(128);
  for (let i = 0; i < 64; i++) {
    sbox[2 * i] = dke[i]! >> 4;
    sbox[2 * i + 1] = dke[i]! & 0x0f;
  }
  return sbox;
}

const rotl11 = (x: number): number => ((x << 11) | (x >>> 21)) >>> 0;
const readLe32 = (b: Uint8Array, o: number): number => (b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16) | (b[o + 3]! << 24)) >>> 0;
function writeLe32(b: Uint8Array, o: number, v: number): void {
  b[o] = v & 0xff;
  b[o + 1] = (v >>> 8) & 0xff;
  b[o + 2] = (v >>> 16) & 0xff;
  b[o + 3] = (v >>> 24) & 0xff;
}

/** GOST 28147-89 on single blocks. Entry v of S-box j is sbox[16 j + v]; S-box j substitutes bits 4j..4j+3. */
export class Gost28147 {
  private readonly table = new Uint32Array(4 * 256); // S-boxes merged by bytes and pre-rotated by 11 bits
  private readonly key = new Uint32Array(8);

  constructor(sbox: Uint8Array) {
    if (sbox.length !== 128) throw new Error('A GOST 28147 substitution table has 128 entries.');
    for (const v of sbox) if (v > 15) throw new Error('S-box entries must be 4-bit values.');
    for (let b = 0; b < 4; b++) {
      for (let v = 0; v < 256; v++) {
        const lo = sbox[16 * (2 * b) + (v & 15)]!;
        const hi = sbox[16 * (2 * b + 1) + (v >> 4)]!;
        this.table[256 * b + v] = rotl11(((lo | (hi << 4)) << (8 * b)) >>> 0);
      }
    }
  }

  /** The 256-bit key: eight 32-bit little-endian subkeys K0..K7. */
  setKey(key: Uint8Array): void {
    if (key.length !== 32) throw new Error('GOST 28147 key must be 32 bytes long.');
    for (let i = 0; i < 8; i++) this.key[i] = readLe32(key, 4 * i);
  }

  private f(x: number): number {
    const t = this.table;
    return (t[x & 0xff]! ^ t[256 + ((x >>> 8) & 0xff)]! ^ t[512 + ((x >>> 16) & 0xff)]! ^ t[768 + (x >>> 24)]!) >>> 0;
  }

  /** Encrypts one 8-byte block (N1 = first four bytes, N2 = last four, little-endian). */
  encryptBlock(input: Uint8Array, inOffset: number, output: Uint8Array, outOffset: number): void {
    let n1 = readLe32(input, inOffset);
    let n2 = readLe32(input, inOffset + 4);
    const k = this.key;
    // Subkeys K0..K7 three times, then K7..K0; no swap after the last round.
    for (let r = 0; r < 3; r++) {
      for (let j = 0; j < 8; j++) {
        const t = (n2 ^ this.f((n1 + k[j]!) >>> 0)) >>> 0;
        n2 = n1;
        n1 = t;
      }
    }
    for (let j = 7; j > 0; j--) {
      const t = (n2 ^ this.f((n1 + k[j]!) >>> 0)) >>> 0;
      n2 = n1;
      n1 = t;
    }
    n2 = (n2 ^ this.f((n1 + k[0]!) >>> 0)) >>> 0;
    writeLe32(output, outOffset, n1);
    writeLe32(output, outOffset + 4, n2);
  }

  /** Decrypts one 8-byte block. */
  decryptBlock(input: Uint8Array, inOffset: number, output: Uint8Array, outOffset: number): void {
    let n1 = readLe32(input, inOffset);
    let n2 = readLe32(input, inOffset + 4);
    const k = this.key;
    const step = (j: number): void => {
      const t = (n2 ^ this.f((n1 + k[j]!) >>> 0)) >>> 0;
      n2 = n1;
      n1 = t;
    };
    for (let j = 0; j < 8; j++) step(j);
    for (let r = 0; r < 3; r++) {
      for (let j = 7; j >= 0; j--) {
        if (r === 2 && j === 0) break;
        step(j);
      }
    }
    n2 = (n2 ^ this.f((n1 + k[0]!) >>> 0)) >>> 0;
    writeLe32(output, outOffset, n1);
    writeLe32(output, outOffset + 4, n2);
  }
}

const C2 = Uint8Array.from([
  0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00,
  0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff,
]);

/** GOST 34.311-95 (the Ukrainian adoption of GOST R 34.11-94), zero initial value. */
export class Gost34311 {
  private readonly cipher: Gost28147;
  private readonly h = new Uint8Array(32);
  private readonly sum = new Uint8Array(32);
  private readonly buffer = new Uint8Array(32);
  private bufferLength = 0;
  private length = 0; // bytes

  /** `sbox`: the 128-entry table; use `Gost34311.fromDke` for a 64-byte DKE. */
  constructor(sbox: Uint8Array = expandDke(DEFAULT_DKE)) {
    this.cipher = new Gost28147(sbox);
  }

  static fromDke(dke: Uint8Array): Gost34311 {
    return new Gost34311(expandDke(dke));
  }

  /** One-shot hash with the given DKE, or DKE No. 1. */
  static hash(data: Uint8Array, dke?: Uint8Array | null): Uint8Array {
    return (dke ? Gost34311.fromDke(dke) : new Gost34311()).update(data).digest();
  }

  update(data: Uint8Array): this {
    this.length += data.length;
    let offset = 0;
    while (offset < data.length) {
      const n = Math.min(32 - this.bufferLength, data.length - offset);
      this.buffer.set(data.subarray(offset, offset + n), this.bufferLength);
      this.bufferLength += n;
      offset += n;
      if (this.bufferLength === 32) {
        this.addToSum(this.buffer);
        this.step(this.buffer);
        this.bufferLength = 0;
      }
    }
    return this;
  }

  digest(): Uint8Array {
    if (this.bufferLength > 0) {
      // The last block is padded with zeros; the length below counts only the real message bits.
      this.buffer.fill(0, this.bufferLength);
      this.addToSum(this.buffer);
      this.step(this.buffer);
    }
    const length = new Uint8Array(32);
    let bits = BigInt(this.length) * 8n;
    for (let i = 0; i < 8; i++) {
      length[i] = Number(bits & 0xffn);
      bits >>= 8n;
    }
    this.step(length);
    this.step(this.sum);
    const result = this.h.slice();
    this.h.fill(0);
    this.sum.fill(0);
    this.bufferLength = 0;
    this.length = 0;
    return result;
  }

  /** Σ = Σ + M mod 2^256, little-endian. */
  private addToSum(block: Uint8Array): void {
    let carry = 0;
    for (let i = 0; i < 32; i++) {
      const s = this.sum[i]! + block[i]! + carry;
      this.sum[i] = s & 0xff;
      carry = s >> 8;
    }
  }

  /** Step function H = χ(M, H): key generation, encryption, mixing. */
  private step(m: Uint8Array): void {
    const u = this.h.slice();
    const v = m.slice();
    const w = new Uint8Array(32);
    const key = new Uint8Array(32);
    const s = new Uint8Array(32);

    for (let i = 0; i < 4; i++) {
      if (i > 0) {
        transformA(u);
        if (i === 2) for (let j = 0; j < 32; j++) u[j] = u[j]! ^ C2[j]!;
        transformA(v);
        transformA(v);
      }
      for (let j = 0; j < 32; j++) w[j] = u[j]! ^ v[j]!;
      // Byte permutation φ(i + 1 + 4(k − 1)) = 8i + k.
      for (let k = 0; k < 8; k++) {
        key[4 * k] = w[k]!;
        key[4 * k + 1] = w[8 + k]!;
        key[4 * k + 2] = w[16 + k]!;
        key[4 * k + 3] = w[24 + k]!;
      }
      this.cipher.setKey(key);
      this.cipher.encryptBlock(this.h, 8 * i, s, 8 * i); // s_i = E_Ki(h_i)
    }

    // H = ψ^61(H ⊕ ψ(M ⊕ ψ^12(S)))
    for (let n = 0; n < 12; n++) psi(s);
    for (let j = 0; j < 32; j++) s[j] = s[j]! ^ m[j]!;
    psi(s);
    for (let j = 0; j < 32; j++) s[j] = s[j]! ^ this.h[j]!;
    for (let n = 0; n < 61; n++) psi(s);
    this.h.set(s);
  }
}

/** A(y4 ‖ y3 ‖ y2 ‖ y1) = (y1 ⊕ y2) ‖ y4 ‖ y3 ‖ y2 (64-bit blocks, y1 first in memory). */
function transformA(y: Uint8Array): void {
  const t = new Uint8Array(8);
  for (let j = 0; j < 8; j++) t[j] = y[j]! ^ y[j + 8]!;
  y.copyWithin(0, 8, 32);
  y.set(t, 24);
}

/** ψ: shift the sixteen 16-bit words, the new top word is the XOR of words 1, 2, 3, 4, 13, 16. */
function psi(y: Uint8Array): void {
  const lo = y[0]! ^ y[2]! ^ y[4]! ^ y[6]! ^ y[24]! ^ y[30]!;
  const hi = y[1]! ^ y[3]! ^ y[5]! ^ y[7]! ^ y[25]! ^ y[31]!;
  y.copyWithin(0, 2, 32);
  y[30] = lo;
  y[31] = hi;
}
