import { bytesToBigInt, equal, plain } from '../bytes';
import { randomBytes } from '../random';
import { hash, hashName, isSupportedHash } from './algorithms';
import { Asn1, Der, Tag } from './asn1';
import type { Certificate } from './certificate';
import { SignedData, verifySigner, type SignerInfo } from './cms';
import { Oid } from './oids';
import type { VerificationReport } from './report';

/**
 * An RFC 3161 time-stamp token: CMS SignedData whose content is a DER TSTInfo (docs/signature-formats.md, section 6;
 * TimeStampToken.cs). The message imprint is the hash of what was time-stamped, not reversed.
 */
export class TimeStampToken {
  readonly policy: string;
  readonly imprintAlgorithm: string;
  readonly imprint: Uint8Array;
  readonly serialNumber: bigint;
  readonly genTime: Date;
  readonly nonce: bigint | null = null;

  private constructor(readonly cms: SignedData) {
    if (cms.contentType !== Oid.TstInfo || !cms.content) throw new Error('The token does not encapsulate a TSTInfo.');
    if (cms.signerInfos.length !== 1) throw new Error('A time-stamp token must have exactly one signer.');
    // TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime, accuracy OPTIONAL,
    //                        ordering DEFAULT FALSE, nonce OPTIONAL, tsa [0] OPTIONAL, extensions [1] OPTIONAL }
    const info = Asn1.parse(cms.content).expect(Tag.Sequence);
    this.policy = info.at(1).oid();
    this.imprintAlgorithm = info.at(2).at(0).at(0).oid();
    this.imprint = info.at(2).at(1).octetString();
    this.serialNumber = info.at(3).integer();
    this.genTime = info.at(4).time();
    for (let i = 5; i < info.count; i++) if (info.at(i).is(Tag.Integer)) this.nonce = info.at(i).integer();
  }

  static load(data: Uint8Array): TimeStampToken {
    return new TimeStampToken(SignedData.load(data));
  }

  get signer(): SignerInfo {
    return this.cms.signerInfos[0]!;
  }

  /** True when the imprint is the hash of `covered` by the imprint's algorithm. */
  covers(covered: Uint8Array): boolean {
    return isSupportedHash(this.imprintAlgorithm) && equal(this.imprint, hash(this.imprintAlgorithm, covered));
  }

  /** The service's certificate: in the token, else among `known`. */
  findSignerCertificate(known: readonly Certificate[] = []): Certificate | null {
    return this.cms.findCertificate(this.signer, known);
  }

  /**
   * Verifies the token over `covered`: the imprint, the CMS signer and the extended key usage of the service certificate.
   * Returns the service certificate, or null when it was not found: the token's signature then stays unverified, which
   * is a warning — the token must not be relied on, but the signature it stamps is not wrong.
   */
  verify(covered: Uint8Array, known: readonly Certificate[], report: VerificationReport, name: string): Certificate | null {
    const covers = this.covers(covered);
    report.check(
      `${name}: imprint`,
      covers,
      covers ? `${hashName(this.imprintAlgorithm)} imprint matches, time ${formatUtc(this.genTime)} UTC` : 'the time-stamp covers other data',
    );
    const tsa = this.findSignerCertificate(known);
    if (!tsa) {
      report.warn(`${name}: service certificate`, `the certificate of the time-stamping service (${this.signer}) is not available, so the time-stamp is not verified`);
      return null;
    }
    verifySigner(this.signer, tsa, Oid.TstInfo, this.cms.content!, report, name);
    if (!tsa.extendedKeyUsage.includes(Oid.KeyPurposeTimeStamping)) {
      report.warn(`${name}: service certificate`, `'${tsa.subject}' has no timeStamping extended key usage`);
    }
    return tsa;
  }
}

/** "2026-10-10 17:34:36". */
export function formatUtc(time: Date): string {
  return time.toISOString().slice(0, 19).replace('T', ' ');
}

// ---- The time-stamp protocol (RFC 3161, 2.4; TimeStampProtocol.cs) ---------------------------------------------------

export const TSP_REQUEST_TYPE = 'application/timestamp-query';

/** A fresh 64-bit nonce for a request. */
export function newNonce(): bigint {
  return bytesToBigInt(randomBytes(8));
}

/**
 * TimeStampReq ::= SEQUENCE { version 1, messageImprint, reqPolicy OPTIONAL, nonce, certReq TRUE }: the service is asked
 * to include its certificate. The request carries only the hash, never the data.
 */
export function createTimeStampRequest(imprint: Uint8Array, hashOid: string, nonce: bigint): Uint8Array {
  return Der.sequence(
    Der.integer(1),
    Der.sequence(Der.algorithm(hashOid), Der.octetString(imprint)),
    Der.integer(nonce),
    Der.encode(Tag.Boolean, Uint8Array.of(0xff)),
  );
}

/**
 * TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken OPTIONAL }: the token, after checking that it answers
 * the request — status granted (0) or grantedWithMods (1), the same imprint and nonce.
 */
export function parseTimeStampResponse(response: Uint8Array, imprint: Uint8Array, hashOid: string, nonce: bigint): TimeStampToken {
  const resp = Asn1.parse(response).expect(Tag.Sequence);
  const statusInfo = resp.at(0);
  const status = statusInfo.at(0).int();
  if (status !== 0 && status !== 1) {
    const text = statusInfo.count > 1 && statusInfo.at(1).is(Tag.Sequence) ? statusInfo.at(1).children.map((c) => c.string()).join('; ') : '';
    throw new Error(`The time-stamping service refused the request (status ${status}) ${text}`.trim());
  }
  if (resp.count < 2) throw new Error('The time-stamp response has no token.');
  const token = TimeStampToken.load(resp.at(1).encoded);
  if (token.imprintAlgorithm !== hashOid || !equal(token.imprint, imprint)) throw new Error('The time-stamp token covers other data than requested.');
  if (token.nonce !== nonce) throw new Error('The time-stamp token has a different nonce than requested.');
  return token;
}

/** Asks `url` for a time-stamp token over `imprint` (an HTTP POST of the DER request). */
export async function requestTimeStamp(url: string, imprint: Uint8Array, hashOid: string, fetchImpl: typeof fetch = fetch): Promise<TimeStampToken> {
  const nonce = newNonce();
  const request = createTimeStampRequest(imprint, hashOid, nonce);
  let response: Response;
  try {
    response = await fetchImpl(url, { method: 'POST', headers: { 'content-type': TSP_REQUEST_TYPE }, body: request as BodyInit, cache: 'no-store', credentials: 'omit' });
  } catch (e) {
    throw new Error(`The time-stamping service ${url} could not be reached (${(e as Error).message}).`);
  }
  if (!response.ok) throw new Error(`The time-stamping service ${url} answered HTTP ${response.status}.`);
  return parseTimeStampResponse(plain(new Uint8Array(await response.arrayBuffer())), imprint, hashOid, nonce);
}
