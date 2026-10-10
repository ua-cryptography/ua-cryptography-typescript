/**
 * Shared by the tests: the bundled certificates (assets/certificates), a ZIP writer for building tampered containers,
 * and where the real signatures are, when this machine has them.
 */
import { existsSync } from 'node:fs';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { crc32, deflateRawSync } from 'node:zlib';
import { root } from './load.mjs';

/** Real signatures and keys carry personal data and never enter the repository; tests that need them skip without. */
export const PRIVATE = process.env.UA_PRIVATE_SAMPLES ?? join(root, '..', 'ua-cryptography-csharp', 'private');
export const hasPrivate = existsSync(PRIVATE);

/** { anchors, extra } as the page bundles them: the roots and the intermediate CA certificates and bundles. */
export async function bundledCertificates(P) {
  const dir = join(root, 'assets/certificates');
  const anchors = [];
  for (const name of await readdir(join(dir, 'roots'))) anchors.push(...P.loadCertificates(await readFile(join(dir, 'roots', name))));
  const extra = [];
  for (const name of await readdir(join(dir, 'intermediates'))) extra.push(...P.loadCertificates(await readFile(join(dir, 'intermediates', name))));
  return { anchors, extra };
}

/** A ZIP of [name, bytes, store?] entries, in order; stored entries are not compressed. */
export function zip(files) {
  const local = [];
  const central = [];
  let offset = 0;
  for (const [name, data, store] of files) {
    const path = Buffer.from(name, 'utf8');
    const packed = store ? Buffer.from(data) : deflateRawSync(data);
    const fields = (header, at) => {
      header.writeUInt16LE(20, at - 2);
      header.writeUInt16LE(0x0800, at);
      header.writeUInt16LE(store ? 0 : 8, at + 2);
      header.writeUInt32LE(0, at + 4);
      header.writeUInt32LE(crc32(data), at + 8);
      header.writeUInt32LE(packed.length, at + 12);
      header.writeUInt32LE(data.length, at + 16);
      header.writeUInt16LE(path.length, at + 20);
    };
    const head = Buffer.alloc(30);
    head.writeUInt32LE(0x04034b50, 0);
    fields(head, 6);
    const entry = Buffer.alloc(46);
    entry.writeUInt32LE(0x02014b50, 0);
    entry.writeUInt16LE(20, 4);
    fields(entry, 8);
    entry.writeUInt32LE(offset, 42);
    local.push(head, path, packed);
    central.push(entry, path);
    offset += head.length + path.length + packed.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return new Uint8Array(Buffer.concat([...local, directory, end]));
}
