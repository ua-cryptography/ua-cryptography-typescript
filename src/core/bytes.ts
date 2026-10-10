/** Byte helpers shared by every layer: hex, base64, UTF-8, comparison and big-endian integers. */

export function concat(...parts: Uint8Array[]): Uint8Array {
  let length = 0;
  for (const p of parts) length += p.length;
  const result = new Uint8Array(length);
  let offset = 0;
  for (const p of parts) {
    result.set(p, offset);
    offset += p.length;
  }
  return result;
}

export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function reversed(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from(bytes).reverse();
}

/**
 * A plain Uint8Array over the same bytes. Node's Buffer is a Uint8Array whose slice() is a view, not a copy: every
 * entry point passes its input through here, so the code below may rely on slice() copying.
 */
export function plain(bytes: Uint8Array): Uint8Array {
  return bytes.constructor === Uint8Array ? bytes : new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

export function toHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s.toUpperCase();
}

/** Hex digits; whitespace, '/' and ':' are ignored. */
export function fromHex(hex: string): Uint8Array {
  const clean = hex.replace(/[\s/:]/g, '');
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) throw new Error('Invalid hex string.');
  const result = new Uint8Array(clean.length / 2);
  for (let i = 0; i < result.length; i++) result[i] = parseInt(clean.substr(2 * i, 2), 16);
  return result;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_INDEX = new Int16Array(128).fill(-1);
for (let i = 0; i < B64.length; i++) B64_INDEX[B64.charCodeAt(i)] = i;

export function toBase64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!;
    const b = bytes[i + 1];
    const c = bytes[i + 2];
    s += B64[a >> 2]! + B64[((a & 3) << 4) | ((b ?? 0) >> 4)]!;
    s += b === undefined ? '=' : B64[((b & 15) << 2) | ((c ?? 0) >> 6)]!;
    s += c === undefined ? '=' : B64[c & 63]!;
  }
  return s;
}

/** Base64 with any whitespace (XML text, PEM bodies); throws on other characters. */
export function fromBase64(text: string): Uint8Array {
  const clean = text.replace(/[\s]/g, '').replace(/=+$/, '');
  if (clean.length % 4 === 1) throw new Error('Invalid base64 length.');
  const result = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let bits = 0;
  let value = 0;
  let o = 0;
  for (let i = 0; i < clean.length; i++) {
    const code = clean.charCodeAt(i);
    const v = code < 128 ? B64_INDEX[code]! : -1;
    if (v < 0) throw new Error('Invalid base64 character.');
    value = (value << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      result[o++] = (value >> bits) & 0xff;
    }
  }
  return result;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: false });

export const utf8 = (text: string): Uint8Array => encoder.encode(text);
export const fromUtf8 = (bytes: Uint8Array): string => decoder.decode(bytes);

export function ascii(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return s;
}

/** Unsigned big-endian bytes → bigint. */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex.length === 0 ? 0n : BigInt('0x' + hex);
}

/** bigint ≥ 0 → exactly `length` big-endian bytes; throws when it does not fit. */
export function bigIntToBytes(value: bigint, length: number): Uint8Array {
  if (value < 0n) throw new Error('Negative value.');
  const hex = value.toString(16);
  if (hex.length > 2 * length) throw new Error('The value does not fit into the requested length.');
  return fromHex(hex.padStart(2 * length, '0'));
}

/** Number of bits of a non-negative bigint (0 for 0). */
export function bitLength(value: bigint): number {
  return value === 0n ? 0 : value.toString(2).length;
}

/** Overwrites a buffer with zeros (best effort: JS gives no guarantee about copies). */
export function wipe(bytes: Uint8Array | null | undefined): void {
  bytes?.fill(0);
}
