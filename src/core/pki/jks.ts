import { concat, equal, plain, wipe } from '../bytes';
import { sha1 } from '../hash/sha';
import { Asn1, Tag } from './asn1';
import { Certificate } from './certificate';
import { PrivateKey } from './keys';
import { Oid } from './oids';
import { buildChain } from './validation';

/**
 * Sun JKS key stores (docs/signature-formats.md, section 14; JksKeyStore.cs), the container in which PrivatBank issues
 * DSTU 4145 keys. Layout, all integers big-endian: magic FEEDFEED, version 2, the entry count, the entries, then SHA-1
 * over the password (UTF-16BE), "Mighty Aphrodite" and everything before it. A PrivateKeyEntry holds an
 * EncryptedPrivateKeyInfo under the Sun key protector (1.3.6.1.4.1.42.2.17.1.1): salt(20) ‖ key XOR keystream ‖
 * SHA-1(password ‖ key), keystream block i = SHA-1(password ‖ block i − 1), block 0 the salt. Reading only.
 */

export type JksPrivateKeyEntry = {
  readonly kind: 'key';
  readonly alias: string;
  readonly created: Date;
  /** The DER EncryptedPrivateKeyInfo as stored. */
  readonly protectedKey: Uint8Array;
  /** As stored: keytool puts the end entity first, PrivatBank the root first and a key-agreement certificate last. */
  readonly chain: readonly Certificate[];
};

export type JksTrustedCertificateEntry = { readonly kind: 'certificate'; readonly alias: string; readonly created: Date; readonly certificate: Certificate };

export type JksEntry = JksPrivateKeyEntry | JksTrustedCertificateEntry;

const MAGIC = 0xfeedfeed;
const INTEGRITY_SALT = new TextEncoder().encode('Mighty Aphrodite');

/** A wrong password, as opposed to a damaged or unsupported file. */
export class WrongPasswordError extends Error {
  override name = 'WrongPasswordError';
}

/** Reads a key store after checking its integrity with `password`. */
export function loadJks(input: Uint8Array, password: string): JksEntry[] {
  const data = plain(input);
  if (data.length < 32) throw new Error('The file is too short to be a JKS key store.');
  const reader = new Reader(data.subarray(0, data.length - 20));
  if (reader.uint32() !== MAGIC) throw new Error('Not a JKS key store (JCEKS and PKCS#12 are not supported).');

  const pw = passwordBytes(password);
  try {
    const expected = sha1(concat(pw, INTEGRITY_SALT, data.subarray(0, data.length - 20)));
    if (!equal(expected, data.subarray(data.length - 20))) throw new WrongPasswordError('JKS integrity check failed: wrong password or a damaged file.');
  } finally {
    wipe(pw);
  }

  const version = reader.uint32();
  if (version !== 1 && version !== 2) throw new Error(`Unsupported JKS version ${version}.`);
  const count = reader.uint32();
  const entries: JksEntry[] = [];
  for (let n = 0; n < count; n++) {
    const tag = reader.uint32();
    const alias = reader.javaUtf();
    const created = new Date(reader.uint32() * 2 ** 32 + reader.uint32());
    if (tag === 1) {
      const protectedKey = reader.bytes(reader.uint32());
      const chainLength = reader.uint32();
      const chain: Certificate[] = [];
      for (let i = 0; i < chainLength; i++) chain.push(readCertificate(reader, version));
      entries.push({ kind: 'key', alias, created, protectedKey, chain });
    } else if (tag === 2) {
      entries.push({ kind: 'certificate', alias, created, certificate: readCertificate(reader, version) });
    } else {
      throw new Error(`Unknown JKS entry type ${tag}.`);
    }
  }
  if (!reader.atEnd) throw new Error('Unexpected data after the last JKS entry.');
  return entries;
}

function readCertificate(reader: Reader, version: number): Certificate {
  if (version === 2) {
    const type = reader.javaUtf();
    if (type !== 'X.509') throw new Error(`Certificate type ${type} is not supported.`);
  }
  return Certificate.load(reader.bytes(reader.uint32()));
}

/** The PKCS#8 PrivateKeyInfo of a protected key; the caller should wipe it after use. */
export function unprotectKey(encryptedPrivateKeyInfo: Uint8Array, password: string): Uint8Array {
  const info = Asn1.parse(encryptedPrivateKeyInfo).expect(Tag.Sequence);
  const algorithm = info.at(0).at(0).oid();
  if (algorithm !== Oid.JksKeyProtector) throw new Error(`Key protection ${algorithm} is not supported (only the Sun JKS key protector).`);
  const encrypted = info.at(1).octetString();
  if (encrypted.length < 40) throw new Error('The protected key is too short.');
  const pw = passwordBytes(password);
  const length = encrypted.length - 40;
  const stream = keyStream(pw, encrypted.subarray(0, 20), length);
  const key = new Uint8Array(length);
  for (let i = 0; i < length; i++) key[i] = encrypted[20 + i]! ^ stream[i]!;
  const check = sha1(concat(pw, key));
  wipe(pw);
  wipe(stream);
  if (!equal(check, encrypted.subarray(encrypted.length - 20))) {
    wipe(key);
    throw new WrongPasswordError('The key protector check failed: wrong key password.');
  }
  return key;
}

function keyStream(pw: Uint8Array, salt: Uint8Array, length: number): Uint8Array {
  const stream = new Uint8Array(length);
  let previous = salt;
  for (let offset = 0; offset < length; offset += 20) {
    previous = sha1(concat(pw, previous));
    stream.set(previous.subarray(0, Math.min(20, length - offset)), offset);
  }
  return stream;
}

function passwordBytes(password: string): Uint8Array {
  const bytes = new Uint8Array(password.length * 2);
  for (let i = 0; i < password.length; i++) {
    const c = password.charCodeAt(i);
    bytes[2 * i] = c >> 8;
    bytes[2 * i + 1] = c & 0xff;
  }
  return bytes;
}

/** A private key with its certificate and the rest of its path (end entity first): what a signer needs. */
export type SigningKey = { readonly key: PrivateKey; readonly certificate: Certificate; readonly chain: readonly Certificate[]; readonly alias: string };

/**
 * Opens the signing key of a JKS store (SigningKey.FromJks). Without `alias` the store must hold one private key, or
 * exactly one whose chain has an end-entity certificate allowing signing (digitalSignature or nonRepudiation). The key's
 * certificate is found by its public key wherever the store keeps it, and the path is rebuilt from it up through its
 * issuers; certificates off that path (such as PrivatBank's key-agreement certificate) are left out.
 */
export function openSigningKey(entries: readonly JksEntry[], password: string, alias?: string, keyPassword?: string): SigningKey {
  let keys = entries.filter((e): e is JksPrivateKeyEntry => e.kind === 'key');
  if (alias !== undefined) {
    keys = keys.filter((k) => k.alias.toLowerCase() === alias.toLowerCase());
    if (keys.length === 0) throw new Error(`The key store has no private key '${alias}'.`);
  } else if (keys.length > 1) {
    keys = keys.filter((k) => k.chain.some((c) => !c.isCa && (c.keyUsage === null || (c.keyUsage & 0b11) !== 0)));
  }
  if (keys.length === 0) throw new Error('The key store holds no signing key.');
  if (keys.length > 1) throw new Error(`The key store holds several keys; choose one by alias: ${keys.map((k) => k.alias).join(', ')}.`);
  const entry = keys[0]!;

  const pkcs8 = unprotectKey(entry.protectedKey, keyPassword ?? password);
  let key: PrivateKey;
  try {
    key = PrivateKey.fromPkcs8(pkcs8);
  } finally {
    wipe(pkcs8);
  }
  const certificate = entry.chain.find((c) => {
    try {
      return c.hasDstu4145Key && c.publicKey.equals(key.publicKey);
    } catch {
      return false;
    }
  });
  if (!certificate) {
    if (entry.chain.some((c) => c.hasDstu4145Key)) throw new Error(`The private key of '${entry.alias}' does not match its certificates.`);
    throw new Error(`The key '${entry.alias}' has no certificate.`);
  }
  return { key, certificate, chain: buildChain(certificate, entry.chain, []), alias: entry.alias };
}

class Reader {
  private offset = 0;

  constructor(private readonly data: Uint8Array) {}

  get atEnd(): boolean {
    return this.offset === this.data.length;
  }

  bytes(count: number): Uint8Array {
    if (count < 0 || count > this.data.length - this.offset) throw new Error('Truncated JKS key store.');
    const result = this.data.slice(this.offset, this.offset + count);
    this.offset += count;
    return result;
  }

  uint32(): number {
    const b = this.bytes(4);
    return ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0;
  }

  /** Java's modified UTF-8 (DataInput.readUTF). */
  javaUtf(): string {
    const lengthBytes = this.bytes(2);
    const b = this.bytes((lengthBytes[0]! << 8) | lengthBytes[1]!);
    let s = '';
    for (let i = 0; i < b.length; ) {
      const x = b[i]!;
      if (x < 0x80) {
        s += String.fromCharCode(x);
        i += 1;
      } else if ((x & 0xe0) === 0xc0 && i + 1 < b.length) {
        s += String.fromCharCode(((x & 0x1f) << 6) | (b[i + 1]! & 0x3f));
        i += 2;
      } else if ((x & 0xf0) === 0xe0 && i + 2 < b.length) {
        s += String.fromCharCode(((x & 0x0f) << 12) | ((b[i + 1]! & 0x3f) << 6) | (b[i + 2]! & 0x3f));
        i += 3;
      } else {
        throw new Error('Invalid modified UTF-8 in a JKS alias.');
      }
    }
    return s;
  }
}
