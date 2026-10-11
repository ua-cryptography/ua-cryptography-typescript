import type { Certificate } from '../core/pki/certificate';

/**
 * The page's network exceptions, both at one origin, PrivatBank's: its time-stamping service, asked for a qualified
 * time-stamp when a signature is made (CAdES-T; only the hash of the signature value is sent), and its OCSP responder,
 * asked for the current status of a certificate when a signature is verified (only the certificate's serial number and
 * hashes of its issuer's name and key are sent). The page's Content-Security-Policy allows this origin and no other
 * (src/app/template.html; build.mjs checks it), so any other address fails in the browser too.
 */
export const PRIVATBANK_ORIGIN = 'https://acsk.privatbank.ua';

/**
 * The first of `urls` at PrivatBank's host, over HTTPS — the certificates say http://, the server answers both, and
 * https:// also works from a page served over HTTPS. Null when none is.
 */
function atPrivatBank(urls: readonly string[]): string | null {
  const host = new URL(PRIVATBANK_ORIGIN).hostname;
  for (const url of urls) {
    try {
      const u = new URL(url);
      if (u.hostname === host) return `${PRIVATBANK_ORIGIN}${u.pathname}${u.search}`;
    } catch {
      // not a URL
    }
  }
  return null;
}

/** The time-stamping service the signer's certificate names (subjectInfoAccess) when it is PrivatBank's, else null. */
export function timeStampUrl(certificate: Certificate): string | null {
  return atPrivatBank(certificate.timeStampUrls);
}

/** The OCSP responder a certificate names (authorityInfoAccess) when it is PrivatBank's, else null. */
export function ocspUrl(certificate: Certificate): string | null {
  return atPrivatBank(certificate.ocspUrls);
}
