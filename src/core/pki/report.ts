import type { Certificate } from './certificate';
import type { OcspResponse, OcspSingleResponse } from './ocsp';
import type { TimeStampToken } from './tsp';

/**
 * The outcome of verifying a signature (C# VerificationReport.cs, VerificationResult.cs): every check made, the signer
 * and the times found, and what the checks were made on.
 */

/** "warning": something could not be established (no trust anchor, no revocation data); the signature itself holds. */
export type CheckStatus = 'passed' | 'warning' | 'failed';

export type VerificationCheck = { readonly name: string; readonly status: CheckStatus; readonly details: string };

/** What a signature covers: a reference (XAdES) or the content (CAdES), with the digest the signature holds. */
export type SignedObject = { readonly name: string; readonly hashAlgorithm: string; readonly digest: Uint8Array };

/** A time-stamp on the signature: its kind, the token and the service's certificate when it was found. */
export type TimeStampDetails = { readonly kind: string; readonly token: TimeStampToken; readonly authority: Certificate | null };

/** A certification path built for `name` (e.g. "signer"), from the certificate up to the top. */
export type CertificatePath = { readonly name: string; readonly certificates: readonly Certificate[] };

/** The status of a certificate on a path, established from an authorized OCSP response. */
export type RevocationStatus = {
  readonly path: string;
  readonly certificate: Certificate;
  readonly response: OcspResponse;
  readonly status: OcspSingleResponse;
  readonly responder: Certificate;
  /** True when the response was obtained online for this verification, false when the signature carries it. */
  readonly online: boolean;
};

export class VerificationReport {
  /** "CAdES-T, enveloped, DSTU 7564-256" and the like. */
  format: string | null = null;
  /** "XAdES-B-LT", "CAdES-T". */
  level: string | null = null;
  /** "detached" or "enveloped". */
  packaging: string | null = null;
  /** As the signature names it: an OID in CMS, a URI in XML-DSig. */
  signatureAlgorithm: string | null = null;
  /** The OID of the hash the signature is computed over. */
  digestAlgorithm: string | null = null;
  signer: Certificate | null = null;
  /** The signing time claimed by the signer (signingTime, xades:SigningTime). */
  claimedSigningTime: Date | null = null;
  /** The time of the signature time-stamp, when present and valid. */
  timeStampTime: Date | null = null;
  readonly checks: VerificationCheck[] = [];
  readonly signedObjects: SignedObject[] = [];
  readonly timeStamps: TimeStampDetails[] = [];
  readonly paths: CertificatePath[] = [];
  readonly revocations: RevocationStatus[] = [];

  constructor(
    /** What was verified, e.g. "CAdES signature" or "XAdES signature id-…". */
    public title: string,
    private readonly now: Date = new Date(),
  ) {}

  /** The time the certificates are validated at: the time-stamp, else the claimed time, else now. */
  get validationTime(): Date {
    return this.timeStampTime ?? this.claimedSigningTime ?? this.now;
  }

  /** True when no check failed (warnings allowed). */
  get isValid(): boolean {
    return this.checks.length > 0 && this.checks.every((c) => c.status !== 'failed');
  }

  get hasWarnings(): boolean {
    return this.checks.some((c) => c.status === 'warning');
  }

  pass(name: string, details: string): void {
    this.checks.push({ name, status: 'passed', details });
  }

  warn(name: string, details: string): void {
    this.checks.push({ name, status: 'warning', details });
  }

  fail(name: string, details: string): void {
    this.checks.push({ name, status: 'failed', details });
  }

  check(name: string, passed: boolean, details: string): void {
    this.checks.push({ name, status: passed ? 'passed' : 'failed', details });
  }
}

/** The outcome for a signed file: one report per signature (and the container's, first) and the signed content. */
export class VerificationResult {
  constructor(
    /** "CAdES (enveloped)", "ASiC-E" and the like. */
    readonly format: string,
    readonly signatures: readonly VerificationReport[],
    /** The signed files by name (the encapsulated content of a CAdES signature is named "content"). */
    readonly signedFiles: ReadonlyMap<string, Uint8Array> = new Map(),
  ) {}

  /** True when there is at least one signature and none has a failed check. */
  get isValid(): boolean {
    return this.signatures.length > 0 && this.signatures.every((s) => s.isValid);
  }

  /**
   * The certificates on the paths whose status no authorized OCSP response established, each with its issuer (the next
   * certificate on the path) and once: what an online check could ask about.
   */
  get unresolvedRevocations(): Array<{ readonly certificate: Certificate; readonly issuer: Certificate }> {
    const found = new Map<string, { certificate: Certificate; issuer: Certificate }>();
    for (const report of this.signatures) {
      for (const path of report.paths) {
        path.certificates.forEach((certificate, i) => {
          const issuer = path.certificates[i + 1];
          if (!issuer || found.has(certificate.id)) return;
          if (!report.revocations.some((r) => r.certificate.equals(certificate))) found.set(certificate.id, { certificate, issuer });
        });
      }
    }
    return [...found.values()];
  }
}

/** What the verifier may rely on besides the signature itself. The verifier fetches nothing; online data comes in here. */
export type ValidationOptions = {
  /** Trusted roots. When empty, the chain is built but trust is reported as a warning. */
  readonly trustAnchors: readonly Certificate[];
  /** Certificates that may complete chains and find time-stamping services (CA bundles kept locally). */
  readonly extraCertificates: readonly Certificate[];
  /**
   * OCSP responses the caller obtained online for this verification (the page asks PrivatBank's responder), used for
   * certificates the signature carries no response about. Undefined when no online check was made.
   */
  readonly onlineRevocation?: readonly OcspResponse[];
  /** "Now", when a signature carries no time (tests). */
  readonly now?: Date;
};

/** The title of the report on an ASiC container's structure, which comes before the signatures' reports. */
export const CONTAINER_TITLE = 'container';
