import { fromUtf8, plain } from './bytes';

/**
 * Reading ZIP archives (ASiC containers): the central directory, stored and deflated entries, CRC-32 checked.
 * Inflation uses the platform's DecompressionStream ("deflate-raw"), present in current browsers and in Node, so it is
 * asynchronous. ZIP64 and encrypted entries are not supported.
 */

export type ZipEntry = {
  readonly name: string;
  /** 0 stored, 8 deflated. */
  readonly method: number;
  readonly compressedSize: number;
  readonly size: number;
  readonly data: Uint8Array;
};

/** True when the data starts like a ZIP archive. */
export function looksLikeZip(data: Uint8Array): boolean {
  return data.length > 4 && data[0] === 0x50 && data[1] === 0x4b && data[2] === 3 && data[3] === 4;
}

/** The entries in the order of the central directory (folders are skipped). */
export async function readZip(input: Uint8Array, maxTotal = 512 * 1024 * 1024): Promise<ZipEntry[]> {
  const data = plain(input);
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  // End of central directory: the last signature 50 4B 05 06 within the final 64 KiB + 22 bytes.
  let eocd = -1;
  for (let i = data.length - 22; i >= Math.max(0, data.length - 22 - 65535); i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('Not a ZIP archive: no end of central directory.');
  const count = view.getUint16(eocd + 10, true);
  let offset = view.getUint32(eocd + 16, true);
  if (count === 0xffff || offset === 0xffffffff) throw new Error('ZIP64 archives are not supported.');

  const entries: ZipEntry[] = [];
  let total = 0;
  for (let n = 0; n < count; n++) {
    if (offset + 46 > data.length || view.getUint32(offset, true) !== 0x02014b50) throw new Error('Damaged ZIP central directory.');
    const flags = view.getUint16(offset + 8, true);
    const method = view.getUint16(offset + 10, true);
    const crc = view.getUint32(offset + 16, true);
    const compressedSize = view.getUint32(offset + 20, true);
    const size = view.getUint32(offset + 24, true);
    const nameLength = view.getUint16(offset + 28, true);
    const extraLength = view.getUint16(offset + 30, true);
    const commentLength = view.getUint16(offset + 32, true);
    const localOffset = view.getUint32(offset + 42, true);
    const name = fromUtf8(data.subarray(offset + 46, offset + 46 + nameLength));
    offset += 46 + nameLength + extraLength + commentLength;
    if (name.endsWith('/')) continue;
    if (flags & 1) throw new Error(`The ZIP entry '${name}' is encrypted.`);
    total += size;
    if (total > maxTotal) throw new Error('The container is too large when unpacked.');

    if (localOffset + 30 > data.length || view.getUint32(localOffset, true) !== 0x04034b50) throw new Error(`Damaged ZIP entry '${name}'.`);
    const start = localOffset + 30 + view.getUint16(localOffset + 26, true) + view.getUint16(localOffset + 28, true);
    if (start + compressedSize > data.length) throw new Error(`Truncated ZIP entry '${name}'.`);
    const packed = data.subarray(start, start + compressedSize);
    let content: Uint8Array;
    if (method === 0) content = packed.slice();
    else if (method === 8) content = await inflateRaw(packed);
    else throw new Error(`The ZIP entry '${name}' uses compression method ${method}.`);
    if (content.length !== size) throw new Error(`The ZIP entry '${name}' has a wrong size.`);
    if (crc32(content) !== crc) throw new Error(`The ZIP entry '${name}' fails its CRC check.`);
    entries.push({ name, method, compressedSize, size, data: content });
  }
  return entries;
}

async function inflateRaw(packed: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([packed as BlobPart]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

const CRC_TABLE = new Uint32Array(256);
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  CRC_TABLE[n] = c >>> 0;
}

export function crc32(data: Uint8Array): number {
  let c = 0xffffffff;
  for (let i = 0; i < data.length; i++) c = CRC_TABLE[(c ^ data[i]!) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
