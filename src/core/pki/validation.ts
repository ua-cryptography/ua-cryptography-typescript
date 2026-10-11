import { equal } from '../bytes';
import type { Certificate } from './certificate';
import type { OcspResponse } from './ocsp';
import { Oid } from './oids';
import type { ValidationOptions, VerificationReport } from './report';
import { formatUtc } from './tsp';

/**
 * Certification paths (a subset of RFC 5280, section 6; CertificatePathValidator.cs): each certificate is signed by the
 * next, is valid at the validation time, CA certificates are CAs, the path ends at a trust anchor, and every certificate
 * below the top has a "good" OCSP response from a responder of its issuer.
 *
 * Nothing is fetched here: what the signature does not carry comes from the options — CA certificates kept locally, and
 * OCSP responses the caller obtained online. A missing revocation status is a warning, as in the C# verifier without
 * --online.
 */

const MAX_DEPTH = 10;

const contains = (list: readonly Certificate[], c: Certificate): boolean => list.some((x) => x.equals(c));

/**
 * The path from `leaf` upwards: each next certificate is one whose subject is the issuer and whose key verifies the
 * signature. It stops at a trust anchor, at a self-signed certificate or where no issuer is found.
 */
export function buildChain(leaf: Certificate, pool: readonly Certificate[], anchors: readonly Certificate[]): Certificate[] {
  const candidates = [...anchors, ...pool];
  const chain = [leaf];
  let current = leaf;
  while (chain.length < MAX_DEPTH) {
    if (contains(anchors, current) || (current.isSelfIssued && current.isSignedBy(current))) break;
    const issuer = findIssuer(current, candidates);
    if (!issuer || contains(chain, issuer)) break;
    chain.push(issuer);
    current = issuer;
  }
  return chain;
}

function findIssuer(certificate: Certificate, candidates: readonly Certificate[]): Certificate | null {
  const aki = certificate.authorityKeyIdentifier;
  const matching = candidates.filter((c) => !c.equals(certificate) && c.subject.equals(certificate.issuer));
  const byKeyId = (c: Certificate): boolean => {
    const ski = c.subjectKeyIdentifier;
    return aki !== null && ski !== null && equal(ski, aki);
  };
  // Candidates whose key identifier matches are tried first (stable: the rest keep their order).
  const ordered = [...matching.filter(byKeyId), ...matching.filter((c) => !byKeyId(c))];
  return ordered.find((c) => certificate.isSignedBy(c)) ?? null;
}

/** Validates the path of `leaf` at `time`; `revocation` is the revocation data the signature carries. */
export function validatePath(
  leaf: Certificate,
  pool: readonly Certificate[],
  revocation: readonly OcspResponse[],
  options: ValidationOptions,
  time: Date,
  report: VerificationReport,
  name: string,
): Certificate[] {
  const poolList = [...pool, ...options.extraCertificates];
  const chain = buildChain(leaf, poolList, options.trustAnchors);
  const top = chain[chain.length - 1]!;
  report.paths.push({ name, certificates: chain });
  report.pass(`${name}: path`, chain.map((c) => `'${c.shortName}'`).join(' → '));

  // Signatures, validity and CA flags along the path.
  chain.forEach((c, i) => {
    const issuer = chain[i + 1];
    if (issuer) report.check(`${name}: signature of '${c.shortName}'`, c.isSignedBy(issuer), `issued by '${issuer.shortName}'`);
    if (!c.isValidAt(time)) {
      report.fail(`${name}: validity of '${c.shortName}'`, `${day(c.notBefore)} – ${day(c.notAfter)} does not include ${formatUtc(time).slice(0, 16)} UTC`);
    }
    if (i > 0 && !c.isCa) report.fail(`${name}: '${c.shortName}'`, 'issues certificates but is not a CA (basicConstraints)');
  });

  // Trust.
  const selfSigned = top.isSelfIssued && top.isSignedBy(top);
  if (options.trustAnchors.length > 0) {
    const trusted = contains(options.trustAnchors, top);
    report.check(
      `${name}: trust`,
      trusted,
      trusted
        ? `ends at the trusted '${top.shortName}'`
        : selfSigned
          ? `ends at '${top.shortName}', which is not a trusted root`
          : `the issuer of '${top.shortName}' is not available`,
    );
  } else {
    report.warn(
      `${name}: trust`,
      selfSigned ? `ends at the self-signed '${top.shortName}'; no trusted roots were given` : `incomplete: the issuer of '${top.shortName}' is not available`,
    );
  }

  // Revocation of every certificate below the top of the path (the top has no issuer to ask).
  for (let i = 0; i + 1 < chain.length; i++) checkRevocation(chain[i]!, chain[i + 1]!, revocation, options.onlineRevocation, poolList, time, report, name);
  return chain;
}

/**
 * The status of `certificate` from a response the signature carries, else from one obtained online. Either is checked
 * the same way: signed by the issuer or by a responder the issuer certified for OCSP. An online response tells the
 * status now; a revocation after the validation time still leaves the signature valid.
 */
function checkRevocation(
  certificate: Certificate,
  issuer: Certificate,
  embedded: readonly OcspResponse[],
  online: readonly OcspResponse[] | undefined,
  pool: readonly Certificate[],
  time: Date,
  report: VerificationReport,
  name: string,
): void {
  const check = `${name}: revocation of '${certificate.shortName}'`;
  const find = (responses: readonly OcspResponse[], isOnline: boolean) => {
    for (const response of responses) {
      const single = response.find(certificate, issuer);
      if (single) return { response, single, isOnline };
    }
    return null;
  };
  const found = find(embedded, false) ?? find(online ?? [], true);
  if (!found) {
    report.warn(
      check,
      online ? 'no OCSP response in the signature, and none from the online check' : 'no OCSP response in the signature; the current status was not checked online',
    );
    return;
  }
  const { response, single, isOnline } = found;
  const responder = response.findResponder([...pool, issuer]);
  if (!responder) {
    report.fail(check, "the OCSP responder's certificate is not available");
    return;
  }
  if (!response.isSignedBy(responder)) {
    report.fail(check, `the OCSP response is not signed by '${responder.shortName}'`);
    return;
  }
  const authorized = responder.equals(issuer) || (responder.isSignedBy(issuer) && responder.extendedKeyUsage.includes(Oid.KeyPurposeOcspSigning));
  if (!authorized) {
    report.fail(check, `'${responder.shortName}' is not an OCSP responder of '${issuer.shortName}'`);
    return;
  }

  report.revocations.push({ path: name, certificate, response, status: single, responder, online: isOnline });
  const at = `${isOnline ? 'online' : 'embedded'} response of '${responder.shortName}' at ${formatUtc(single.thisUpdate).slice(0, 16)} UTC`;
  if (single.status === 'good') report.pass(check, `good, ${at}`);
  else if (single.status === 'revoked' && single.revocationTime && single.revocationTime > time) {
    report.pass(check, `revoked on ${formatUtc(single.revocationTime).slice(0, 16)} UTC, after the validation time; ${at}`);
  } else if (single.status === 'revoked') {
    report.fail(check, `revoked on ${single.revocationTime ? formatUtc(single.revocationTime).slice(0, 16) : '?'} UTC; ${at}`);
  } else report.fail(check, `unknown to the responder; ${at}`);
}

const day = (d: Date): string => d.toISOString().slice(0, 10);
