import { equal, toHex } from '../bytes';
import { Asn1, Tag } from './asn1';
import { Oid } from './oids';

const KEYS: ReadonlyArray<readonly [string, string]> = [
  ['CN', Oid.CommonName],
  ['SN', Oid.Surname],
  ['SERIALNUMBER', Oid.SerialNumber],
  ['C', Oid.Country],
  ['L', Oid.Locality],
  ['ST', Oid.State],
  ['STREET', Oid.Street],
  ['O', Oid.Organization],
  ['OU', Oid.OrganizationalUnit],
  ['T', Oid.Title],
  ['G', Oid.GivenName],
  ['ORGANIZATIONIDENTIFIER', Oid.OrganizationIdentifier],
  ['E', Oid.EmailAddress],
];

export type NameAttribute = { readonly oid: string; readonly value: string };

/**
 * An X.500 Name (RFC 5280, 4.1.2.4). Two names are equal when their DER encodings are, or else when their attributes
 * match after collapsing spaces and ignoring case (RFC 5280, 7.1, simplified) — as in DistinguishedName.cs.
 */
export class DistinguishedName {
  private constructor(
    /** The DER encoding, exactly as found. */
    readonly encoded: Uint8Array,
    /** All attributes in the order of encoding. */
    readonly attributes: readonly NameAttribute[],
  ) {}

  static fromAsn1(name: Asn1): DistinguishedName {
    name.expect(Tag.Sequence);
    const attributes: NameAttribute[] = [];
    for (const rdn of name.children) {
      for (const attribute of rdn.expect(Tag.Set).children) {
        const value = attribute.at(1);
        let text: string;
        try {
          text = value.string();
        } catch {
          text = '#' + toHex(value.encoded);
        }
        attributes.push({ oid: attribute.at(0).oid(), value: text });
      }
    }
    return new DistinguishedName(name.encoded.slice(), attributes);
  }

  /** The first value of an attribute type, e.g. Oid.CommonName. */
  get(oid: string): string | undefined {
    return this.attributes.find((a) => a.oid === oid)?.value;
  }

  equals(other: DistinguishedName): boolean {
    if (equal(this.encoded, other.encoded)) return true;
    return (
      this.attributes.length === other.attributes.length &&
      this.attributes.every((a, i) => {
        const b = other.attributes[i]!;
        return a.oid === b.oid && normalize(a.value) === normalize(b.value);
      })
    );
  }

  toString(): string {
    return this.attributes.map((a) => `${KEYS.find((k) => k[1] === a.oid)?.[0] ?? a.oid}=${a.value.replaceAll(',', '\\,')}`).join(', ');
  }
}

const normalize = (value: string): string => value.split(' ').filter(Boolean).join(' ').toLowerCase();
