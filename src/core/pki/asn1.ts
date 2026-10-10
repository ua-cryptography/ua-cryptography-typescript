import { ascii, bytesToBigInt, concat, fromBase64, fromUtf8, plain } from '../bytes';

/** Identifier octets of the universal types PKI structures use (X.680, 8.4). */
export const Tag = {
  Boolean: 0x01,
  Integer: 0x02,
  BitString: 0x03,
  OctetString: 0x04,
  Null: 0x05,
  ObjectIdentifier: 0x06,
  Enumerated: 0x0a,
  Utf8String: 0x0c,
  NumericString: 0x12,
  PrintableString: 0x13,
  TeletexString: 0x14,
  Ia5String: 0x16,
  UtcTime: 0x17,
  GeneralizedTime: 0x18,
  VisibleString: 0x1a,
  UniversalString: 0x1c,
  BmpString: 0x1e,
  Sequence: 0x30,
  Set: 0x31,
} as const;

const MAX_DEPTH = 64;

/**
 * One parsed ASN.1 element over the original bytes — a port of Asn1Node.cs. The reader accepts DER and the BER forms
 * met in CMS (indefinite lengths, constructed strings); `encoded` is always the exact slice of the input, so signed
 * structures (TBSCertificate, signed attributes, tbsResponseData) are hashed as they were received.
 */
export class Asn1 {
  private childList: Asn1[] | null;

  private constructor(
    readonly tag: number,
    /** The whole element: identifier, length and contents (up to the end-of-contents for an indefinite length). */
    readonly encoded: Uint8Array,
    /** The contents octets (without the end-of-contents octets). */
    readonly content: Uint8Array,
    private readonly depth: number,
    children: Asn1[] | null,
  ) {
    this.childList = children;
  }

  /** Exactly one element; trailing bytes are an error. */
  static parse(data: Uint8Array): Asn1 {
    const { node, length } = Asn1.read(plain(data), 0, 0);
    if (length !== data.length) throw new Error(`Unexpected ${data.length - length} bytes after the ASN.1 element.`);
    return node;
  }

  /** The first element of `data` and its encoded length. */
  static readFirst(data: Uint8Array): { node: Asn1; length: number } {
    return Asn1.read(plain(data), 0, 0);
  }

  static tryParse(data: Uint8Array): Asn1 | null {
    try {
      return Asn1.parse(data);
    } catch {
      return null;
    }
  }

  private static read(data: Uint8Array, offset: number, depth: number): { node: Asn1; length: number } {
    if (depth > MAX_DEPTH) throw new Error('ASN.1 nesting is too deep.');
    if (offset + 2 > data.length) throw new Error('Truncated ASN.1 element.');
    const tag = data[offset]!;
    if ((tag & 0x1f) === 0x1f) throw new Error('High-tag-number ASN.1 forms are not supported.');
    let position = offset + 1;
    const first = data[position++]!;

    if (first === 0x80) {
      // Indefinite length (BER): children up to the end-of-contents octets 00 00.
      if ((tag & 0x20) === 0) throw new Error('A primitive ASN.1 element cannot have an indefinite length.');
      const contentStart = position;
      const children: Asn1[] = [];
      for (;;) {
        if (position + 2 > data.length) throw new Error('Missing end-of-contents octets.');
        if (data[position] === 0 && data[position + 1] === 0) break;
        const child = Asn1.read(data, position, depth + 1);
        children.push(child.node);
        position += child.length;
      }
      const length = position + 2 - offset;
      return {
        node: new Asn1(tag, data.subarray(offset, offset + length), data.subarray(contentStart, position), depth, children),
        length,
      };
    }

    let contentLength: number;
    if (first < 0x80) {
      contentLength = first;
    } else {
      const octets = first & 0x7f;
      if (octets > 4 || position + octets > data.length) throw new Error('Invalid ASN.1 length.');
      contentLength = 0;
      for (let i = 0; i < octets; i++) contentLength = contentLength * 256 + data[position++]!;
    }
    if (contentLength > data.length - position) throw new Error('ASN.1 length exceeds the data.');
    const length = position + contentLength - offset;
    return {
      node: new Asn1(tag, data.subarray(offset, offset + length), data.subarray(position, position + contentLength), depth, null),
      length,
    };
  }

  get constructed(): boolean {
    return (this.tag & 0x20) !== 0;
  }

  /** True for a context-specific tag [n], primitive or constructed. */
  isContext(n: number): boolean {
    return (this.tag & 0xc0) === 0x80 && (this.tag & 0x1f) === n;
  }

  is(tag: number): boolean {
    return this.tag === tag;
  }

  get children(): Asn1[] {
    if (this.childList) return this.childList;
    if (!this.constructed) throw new Error(`ASN.1 element with tag 0x${hex2(this.tag)} is primitive and has no children.`);
    const list: Asn1[] = [];
    let offset = 0;
    while (offset < this.content.length) {
      const child = Asn1.read(this.content, offset, this.depth + 1);
      list.push(child.node);
      offset += child.length;
    }
    this.childList = list;
    return list;
  }

  get count(): number {
    return this.children.length;
  }

  /** Child `index`; throws when it is missing. */
  at(index: number): Asn1 {
    const child = this.children[index];
    if (!child) throw new Error(`ASN.1 element with tag 0x${hex2(this.tag)} has ${this.count} children, element ${index} is missing.`);
    return child;
  }

  /** The last child. */
  last(): Asn1 {
    return this.at(this.count - 1);
  }

  expect(tag: number): this {
    if (this.tag !== tag) throw new Error(`Expected ASN.1 tag 0x${hex2(tag)}, found 0x${hex2(this.tag)}.`);
    return this;
  }

  integer(): bigint {
    this.expect(Tag.Integer);
    const c = this.content;
    if (c.length === 0) throw new Error('Empty INTEGER.');
    const value = bytesToBigInt(c);
    return c[0]! & 0x80 ? value - (1n << BigInt(8 * c.length)) : value;
  }

  int(): number {
    const v = this.integer();
    if (v < -0x80000000n || v > 0x7fffffffn) throw new Error('INTEGER does not fit into 32 bits.');
    return Number(v);
  }

  boolean(): boolean {
    this.expect(Tag.Boolean);
    if (this.content.length !== 1) throw new Error('Invalid BOOLEAN.');
    return this.content[0] !== 0;
  }

  oid(): string {
    this.expect(Tag.ObjectIdentifier);
    return decodeOid(this.content);
  }

  /** The contents of an OCTET STRING, primitive or constructed (BER), with any implicit tag. */
  octetString(): Uint8Array {
    if (!this.constructed) return this.content.slice();
    return concat(...this.children.map((c) => c.octetString()));
  }

  /** The bytes of a BIT STRING with no unused bits (keys and signatures always are). */
  bitString(): Uint8Array {
    this.expect(Tag.BitString);
    const c = this.content;
    if (c.length === 0 || c[0]! > 7) throw new Error('Invalid BIT STRING.');
    return c.slice(1);
  }

  /** A named BIT STRING (keyUsage) as an integer: ASN.1 bit i is bit i of the result. */
  namedBits(): number {
    this.expect(Tag.BitString);
    const c = this.content;
    let result = 0;
    for (let i = 1; i < c.length && i <= 4; i++) {
      for (let bit = 0; bit < 8; bit++) if (c[i]! & (0x80 >> bit)) result |= 1 << ((i - 1) * 8 + bit);
    }
    return result >>> 0;
  }

  /** Any ASN.1 character string type as text. */
  string(): string {
    const c = this.content;
    switch (this.tag) {
      case Tag.Utf8String:
        return fromUtf8(c);
      case Tag.BmpString: {
        let s = '';
        for (let i = 0; i + 1 < c.length; i += 2) s += String.fromCharCode((c[i]! << 8) | c[i + 1]!);
        return s;
      }
      case Tag.UniversalString: {
        let s = '';
        for (let i = 0; i + 3 < c.length; i += 4) s += String.fromCodePoint(((c[i]! << 24) | (c[i + 1]! << 16) | (c[i + 2]! << 8) | c[i + 3]!) >>> 0);
        return s;
      }
      case Tag.PrintableString:
      case Tag.Ia5String:
      case Tag.NumericString:
      case Tag.VisibleString:
      case Tag.TeletexString:
        return ascii(c); // Latin-1
      default:
        throw new Error(`ASN.1 tag 0x${hex2(this.tag)} is not a character string.`);
    }
  }

  /** A UTCTime or GeneralizedTime value. */
  time(): Date {
    const text = ascii(this.content);
    if (this.tag === Tag.UtcTime) {
      const m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{4})$/.exec(text);
      if (!m) throw new Error(`Invalid UTCTime '${text}'.`);
      const yy = Number(m[1]);
      // RFC 5280, 4.1.2.5.1: YY ≥ 50 is 19YY, YY < 50 is 20YY.
      return makeTime(yy >= 50 ? 1900 + yy : 2000 + yy, m[2]!, m[3]!, m[4]!, m[5]!, m[6] ?? '00', '', m[7]!, text);
    }
    if (this.tag === Tag.GeneralizedTime) {
      const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:[.,](\d+))?(Z|[+-]\d{4})?$/.exec(text);
      if (!m) throw new Error(`Invalid GeneralizedTime '${text}'.`);
      return makeTime(Number(m[1]), m[2]!, m[3]!, m[4]!, m[5]!, m[6] ?? '00', m[7] ?? '', m[8] ?? 'Z', text);
    }
    throw new Error(`ASN.1 tag 0x${hex2(this.tag)} is not a time.`);
  }
}

function makeTime(year: number, mo: string, d: string, h: string, mi: string, s: string, fraction: string, zone: string, text: string): Date {
  let ms = Date.UTC(year, Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s), fraction ? Math.floor(Number(`0.${fraction}`) * 1000) : 0);
  if (zone !== 'Z') {
    const sign = zone[0] === '-' ? -1 : 1;
    ms -= sign * (Number(zone.slice(1, 3)) * 60 + Number(zone.slice(3, 5))) * 60000;
  }
  if (Number.isNaN(ms)) throw new Error(`Invalid ASN.1 time '${text}'.`);
  return new Date(ms);
}

const hex2 = (n: number): string => n.toString(16).toUpperCase().padStart(2, '0');

export function decodeOid(content: Uint8Array): string {
  if (content.length === 0 || content[content.length - 1]! & 0x80) throw new Error('Invalid OBJECT IDENTIFIER.');
  const arcs: bigint[] = [];
  let value = 0n;
  let first = true;
  for (const b of content) {
    value = (value << 7n) | BigInt(b & 0x7f);
    if (b & 0x80) continue;
    if (first) {
      const top = value < 40n ? 0n : value < 80n ? 1n : 2n;
      arcs.push(top, value - 40n * top);
      first = false;
    } else {
      arcs.push(value);
    }
    value = 0n;
  }
  return arcs.join('.');
}

// ---- DER writer (X.690, section 10): each function returns one complete element ------------------------------------

export const Der = {
  encode(tag: number, content: Uint8Array): Uint8Array {
    const length = content.length;
    const lengthOctets = length < 0x80 ? 0 : length <= 0xff ? 1 : length <= 0xffff ? 2 : length <= 0xffffff ? 3 : 4;
    const result = new Uint8Array(2 + lengthOctets + length);
    result[0] = tag;
    if (lengthOctets === 0) {
      result[1] = length;
    } else {
      result[1] = 0x80 | lengthOctets;
      for (let i = 0; i < lengthOctets; i++) result[2 + i] = (length >>> (8 * (lengthOctets - 1 - i))) & 0xff;
    }
    result.set(content, 2 + lengthOctets);
    return result;
  },

  sequence(...items: Uint8Array[]): Uint8Array {
    return Der.encode(Tag.Sequence, concat(...items));
  },

  /** A DER SET OF: the encodings sorted as octet strings (X.690, 11.6). */
  setOf(...items: Uint8Array[]): Uint8Array {
    const sorted = [...items].sort(compareEncodings);
    return Der.encode(Tag.Set, concat(...sorted));
  },

  null(): Uint8Array {
    return Uint8Array.of(Tag.Null, 0);
  },

  /** A non-negative INTEGER in the shortest form (the structures written here have no negative ones). */
  integer(value: bigint | number): Uint8Array {
    const v = BigInt(value);
    if (v < 0n) throw new Error('Negative INTEGERs are not written.');
    let hex = v.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    if (parseInt(hex.slice(0, 2), 16) & 0x80) hex = '00' + hex;
    return Der.encode(Tag.Integer, Uint8Array.from(hex.match(/../g)!, (h) => parseInt(h, 16)));
  },

  octetString(value: Uint8Array): Uint8Array {
    return Der.encode(Tag.OctetString, value);
  },

  objectIdentifier(oid: string): Uint8Array {
    return Der.encode(Tag.ObjectIdentifier, encodeOid(oid));
  },

  /** AlgorithmIdentifier with absent parameters, as the Ukrainian PKI writes its own algorithms. */
  algorithm(oid: string): Uint8Array {
    return Der.sequence(Der.objectIdentifier(oid));
  },

  utcTime(time: Date): Uint8Array {
    return Der.encode(Tag.UtcTime, new TextEncoder().encode(formatTime(time).slice(2) + 'Z'));
  },

  generalizedTime(time: Date): Uint8Array {
    return Der.encode(Tag.GeneralizedTime, new TextEncoder().encode(formatTime(time) + 'Z'));
  },

  /** X.509 Time (RFC 5280, 4.1.2.5): UTCTime for 1950–2049, GeneralizedTime otherwise. */
  time(time: Date): Uint8Array {
    const year = time.getUTCFullYear();
    return year >= 1950 && year < 2050 ? Der.utcTime(time) : Der.generalizedTime(time);
  },

  /** [n] EXPLICIT: a constructed context tag around a complete element. */
  explicit(n: number, inner: Uint8Array): Uint8Array {
    return Der.encode(0xa0 | n, inner);
  },

  /** [n] IMPLICIT: the identifier of `encoded` is replaced; the constructed flag is kept. */
  implicit(n: number, encoded: Uint8Array): Uint8Array {
    const result = encoded.slice();
    result[0] = 0x80 | (encoded[0]! & 0x20) | n;
    return result;
  },
};

function formatTime(time: Date): string {
  const p = (n: number, w = 2): string => String(n).padStart(w, '0');
  return (
    p(time.getUTCFullYear(), 4) + p(time.getUTCMonth() + 1) + p(time.getUTCDate()) + p(time.getUTCHours()) + p(time.getUTCMinutes()) + p(time.getUTCSeconds())
  );
}

// Shorter encodings compare as if padded with zero octets at the end.
function compareEncodings(a: Uint8Array, b: Uint8Array): number {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x - y;
  }
  return a.length - b.length;
}

export function encodeOid(oid: string): Uint8Array {
  const parts = oid.split('.');
  if (parts.length < 2 || parts.some((p) => !/^\d+$/.test(p))) throw new Error(`Invalid object identifier '${oid}'.`);
  const arcs = parts.map((p) => BigInt(p));
  if (arcs[0]! > 2n || (arcs[0]! < 2n && arcs[1]! >= 40n)) throw new Error(`Invalid object identifier '${oid}'.`);
  const out: number[] = [];
  const write = (value: bigint): void => {
    const groups = [Number(value & 0x7fn)];
    let v = value >> 7n;
    while (v > 0n) {
      groups.unshift(0x80 | Number(v & 0x7fn));
      v >>= 7n;
    }
    out.push(...groups);
  };
  write(arcs[0]! * 40n + arcs[1]!);
  for (let i = 2; i < arcs.length; i++) write(arcs[i]!);
  return Uint8Array.from(out);
}

/** DER, or PEM / bare base64 text holding it (`label` as in "-----BEGIN CERTIFICATE-----"). */
export function decodePem(data: Uint8Array, label: string): Uint8Array {
  if (data.length > 0 && data[0] === Tag.Sequence) return plain(data);
  let text = ascii(data).trim();
  const begin = `-----BEGIN ${label}-----`;
  const start = text.indexOf(begin);
  if (start >= 0) {
    const stop = text.indexOf(`-----END ${label}-----`, start);
    if (stop < 0) throw new Error(`PEM block ${label} is not terminated.`);
    text = text.slice(start + begin.length, stop);
  } else if (/-----BEGIN [A-Z0-9 ]+-----/.test(text)) {
    // Another label (e.g. PKCS7 for a CMS): take the first block whatever it is called.
    const m = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/.exec(text);
    if (!m) throw new Error('Unterminated PEM block.');
    text = m[2]!;
  }
  const clean = text.replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]+=*$/.test(clean)) throw new Error(`The data is neither DER nor PEM (${label}).`);
  return fromBase64(clean);
}
