import type { Certificate } from '../core/pki/certificate';

/**
 * The page's network exceptions, at two origins. PrivatBank's: its time-stamping service, asked for a qualified
 * time-stamp when a signature is made (CAdES-T; only the hash of the signature value is sent), and its OCSP responder.
 * The NBU's: the OCSP responder of its root, which certified PrivatBank's CA and time-stamping server. A responder is
 * asked for the current status of a certificate when a signature is verified (only the certificate's serial number and
 * hashes of its issuer's name and key are sent). The page's Content-Security-Policy allows these origins and no other
 * (src/app/template.html; build.mjs checks it), so any other address fails in the browser too.
 */
export const PRIVATBANK_ORIGIN = 'https://acsk.privatbank.ua';
export const NBU_ORIGIN = 'https://zc.bank.gov.ua';

/** The origins whose OCSP responders the online check may ask. */
const OCSP_ORIGINS = [PRIVATBANK_ORIGIN, NBU_ORIGIN] as const;

/**
 * The first of `urls` at one of `origins`' hosts, over HTTPS — the certificates say http://, the servers answer both,
 * and https:// also works from a page served over HTTPS. Null when none is.
 */
function atOrigins(urls: readonly string[], origins: readonly string[]): string | null {
  for (const url of urls) {
    let u: URL;
    try {
      u = new URL(url);
    } catch {
      continue; // not a URL
    }
    const origin = origins.find((o) => new URL(o).hostname === u.hostname);
    if (origin) return `${origin}${u.pathname}${u.search}`;
  }
  return null;
}

/** The time-stamping service the signer's certificate names (subjectInfoAccess) when it is PrivatBank's, else null. */
export function timeStampUrl(certificate: Certificate): string | null {
  return atOrigins(certificate.timeStampUrls, [PRIVATBANK_ORIGIN]);
}

/** The OCSP responder a certificate names (authorityInfoAccess) when it is PrivatBank's or the NBU's, else null. */
export function ocspUrl(certificate: Certificate): string | null {
  return atOrigins(certificate.ocspUrls, OCSP_ORIGINS);
}
