import { PI } from './dstu-sboxes';

/**
 * DSTU 7564:2014 ("Kupyna"), hash sizes 256, 384 and 512 bits — a port of the C# reference (Dstu7564Hash.cs).
 *
 * The state is an 8 × c byte matrix kept as c 64-bit columns (byte r of a column is row r, little-endian); JavaScript
 * has no 64-bit integers, so every column is a pair of 32-bit halves: `lo` holds rows 0–3, `hi` rows 4–7. A block M
 * updates the state as H = T⊕(H ⊕ M) ⊕ T+(M) ⊕ H; the result is the tail of T⊕(H) ⊕ H. SubBytes and MixColumns
 * are merged into eight tables built at start-up from the S-boxes, as in the reference implementation.
 */

const ROWS = 8;
const MDS = [0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04];

/** Multiplication in GF(2^8) modulo x^8 + x^4 + x^3 + x^2 + 1. */
function gfMultiply(a: number, b: number): number {
  let result = 0;
  let x = a;
  let y = b;
  while (y !== 0) {
    if (y & 1) result ^= x;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
    y >>= 1;
  }
  return result;
}

// TABLE_LO[k * 256 + b] / TABLE_HI[...]: the column MixColumns makes of π_(k mod 4)(b) in row k.
const TABLE_LO = new Uint32Array(ROWS * 256);
const TABLE_HI = new Uint32Array(ROWS * 256);
for (let k = 0; k < ROWS; k++) {
  for (let b = 0; b < 256; b++) {
    const y = PI[k % 4]![b]!;
    let lo = 0;
    let hi = 0;
    for (let i = 0; i < ROWS; i++) {
      const v = gfMultiply(MDS[(k - i) & 7]!, y);
      if (i < 4) lo |= v << (8 * i);
      else hi |= v << (8 * (i - 4));
    }
    TABLE_LO[k * 256 + b] = lo >>> 0;
    TABLE_HI[k * 256 + b] = hi >>> 0;
  }
}

export class Dstu7564 {
  private readonly hashBytes: number;
  private readonly columns: number;
  private readonly rounds: number;
  private readonly blockSize: number;
  private readonly stateLo: Uint32Array;
  private readonly stateHi: Uint32Array;
  private readonly pLo: Uint32Array;
  private readonly pHi: Uint32Array;
  private readonly qLo: Uint32Array;
  private readonly qHi: Uint32Array;
  private readonly tLo: Uint32Array;
  private readonly tHi: Uint32Array;
  private readonly buffer: Uint8Array;
  private bufferLength = 0;
  private length = 0; // bytes

  constructor(bits: 256 | 384 | 512 = 256) {
    if (bits !== 256 && bits !== 384 && bits !== 512) throw new Error('Supported hash sizes are 256, 384 and 512 bits.');
    this.hashBytes = bits / 8;
    this.columns = bits <= 256 ? 8 : 16;
    this.rounds = bits <= 256 ? 10 : 14;
    this.blockSize = 8 * this.columns;
    const c = this.columns;
    this.stateLo = new Uint32Array(c);
    this.stateHi = new Uint32Array(c);
    this.pLo = new Uint32Array(c);
    this.pHi = new Uint32Array(c);
    this.qLo = new Uint32Array(c);
    this.qHi = new Uint32Array(c);
    this.tLo = new Uint32Array(c);
    this.tHi = new Uint32Array(c);
    this.buffer = new Uint8Array(this.blockSize);
    this.reset();
  }

  static hash(data: Uint8Array, bits: 256 | 384 | 512 = 256): Uint8Array {
    return new Dstu7564(bits).update(data).digest();
  }

  reset(): void {
    this.stateLo.fill(0);
    this.stateHi.fill(0);
    this.stateLo[0] = this.blockSize; // the initial value: the block length in bytes in the first byte
    this.bufferLength = 0;
    this.length = 0;
  }

  update(data: Uint8Array): this {
    this.length += data.length;
    let offset = 0;
    while (offset < data.length) {
      const n = Math.min(this.blockSize - this.bufferLength, data.length - offset);
      this.buffer.set(data.subarray(offset, offset + n), this.bufferLength);
      this.bufferLength += n;
      offset += n;
      if (this.bufferLength === this.blockSize) {
        this.processBlock(this.buffer);
        this.bufferLength = 0;
      }
    }
    return this;
  }

  digest(): Uint8Array {
    // Padding: a single 1 bit (0x80), zeros, and the message length in bits as a 96-bit little-endian number.
    const block = this.buffer;
    block[this.bufferLength++] = 0x80;
    if (this.bufferLength > this.blockSize - 12) {
      block.fill(0, this.bufferLength);
      this.processBlock(block);
      this.bufferLength = 0;
    }
    block.fill(0, this.bufferLength);
    let bits = BigInt(this.length) * 8n;
    for (let i = this.blockSize - 12; i < this.blockSize; i++) {
      block[i] = Number(bits & 0xffn);
      bits >>= 8n;
    }
    this.processBlock(block);

    // H = T⊕(H) ⊕ H; the hash is its last n bits.
    const c = this.columns;
    this.pLo.set(this.stateLo);
    this.pHi.set(this.stateHi);
    this.permutationXor(this.pLo, this.pHi);
    const result = new Uint8Array(this.hashBytes);
    const first = c - this.hashBytes / 8;
    for (let col = first; col < c; col++) {
      const lo = (this.stateLo[col]! ^ this.pLo[col]!) >>> 0;
      const hi = (this.stateHi[col]! ^ this.pHi[col]!) >>> 0;
      const o = 8 * (col - first);
      for (let i = 0; i < 4; i++) {
        result[o + i] = (lo >>> (8 * i)) & 0xff;
        result[o + 4 + i] = (hi >>> (8 * i)) & 0xff;
      }
    }
    this.reset();
    return result;
  }

  private processBlock(block: Uint8Array): void {
    const c = this.columns;
    for (let col = 0; col < c; col++) {
      const o = 8 * col;
      const mLo = (block[o]! | (block[o + 1]! << 8) | (block[o + 2]! << 16) | (block[o + 3]! << 24)) >>> 0;
      const mHi = (block[o + 4]! | (block[o + 5]! << 8) | (block[o + 6]! << 16) | (block[o + 7]! << 24)) >>> 0;
      this.pLo[col] = this.stateLo[col]! ^ mLo;
      this.pHi[col] = this.stateHi[col]! ^ mHi;
      this.qLo[col] = mLo;
      this.qHi[col] = mHi;
    }
    this.permutationXor(this.pLo, this.pHi);
    this.permutationAdd(this.qLo, this.qHi);
    for (let col = 0; col < c; col++) {
      this.stateLo[col] = this.stateLo[col]! ^ this.pLo[col]! ^ this.qLo[col]!;
      this.stateHi[col] = this.stateHi[col]! ^ this.pHi[col]! ^ this.qHi[col]!;
    }
  }

  /** T⊕: the round constant of column j, (j << 4) ⊕ round, is XORed into row 0. */
  private permutationXor(lo: Uint32Array, hi: Uint32Array): void {
    for (let round = 0; round < this.rounds; round++) {
      for (let col = 0; col < this.columns; col++) lo[col] = lo[col]! ^ ((col << 4) ^ round);
      this.round(lo, hi);
    }
  }

  /** T+: column j is increased mod 2^64 by 00F0F0F0F0F0F0F3 with ((c − 1 − j) << 4) ⊕ round in row 7. */
  private permutationAdd(lo: Uint32Array, hi: Uint32Array): void {
    const c = this.columns;
    for (let round = 0; round < this.rounds; round++) {
      for (let col = 0; col < c; col++) {
        const addHi = (0x00f0f0f0 ^ ((((c - 1 - col) << 4) ^ round) << 24)) >>> 0;
        const sum = lo[col]! + 0xf0f0f0f3;
        lo[col] = sum >>> 0;
        hi[col] = (hi[col]! + addHi + (sum > 0xffffffff ? 1 : 0)) >>> 0;
      }
      this.round(lo, hi);
    }
  }

  /** SubBytes, ShiftBytes and MixColumns: output row r of column c comes from column c − shift(r). */
  private round(lo: Uint32Array, hi: Uint32Array): void {
    const c = this.columns;
    const tLo = this.tLo;
    const tHi = this.tHi;
    tLo.set(lo);
    tHi.set(hi);
    const mask = c - 1;
    const lastShift = c === 8 ? 7 : 11;
    for (let col = 0; col < c; col++) {
      let vLo = 0;
      let vHi = 0;
      for (let r = 0; r < ROWS; r++) {
        const source = (col - (r === ROWS - 1 ? lastShift : r)) & mask;
        const byte = r < 4 ? (tLo[source]! >>> (8 * r)) & 0xff : (tHi[source]! >>> (8 * (r - 4))) & 0xff;
        const index = r * 256 + byte;
        vLo ^= TABLE_LO[index]!;
        vHi ^= TABLE_HI[index]!;
      }
      lo[col] = vLo >>> 0;
      hi[col] = vHi >>> 0;
    }
  }
}
