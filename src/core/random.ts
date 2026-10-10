/** Random bytes from the platform's CSPRNG (Web Crypto, also global in Node). */
export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  // getRandomValues fills at most 65536 bytes per call.
  for (let offset = 0; offset < length; offset += 65536) {
    globalThis.crypto.getRandomValues(bytes.subarray(offset, Math.min(length, offset + 65536)));
  }
  return bytes;
}
