import type { Certificate } from '../core/pki/certificate';

/**
 * The one network exception of the page: PrivatBank's time-stamping service, asked for a qualified time-stamp when a
 * signature is made (CAdES-T). Only the hash of the signature value is sent. The page's Content-Security-Policy allows
 * this origin and no other (src/app/template.html; build.mjs checks it), so any other address fails in the browser too.
 */
export const TSP_ORIGIN = 'https://acsk.privatbank.ua';

/**
 * The time-stamping service the signer's certificate names (subjectInfoAccess, id-ad-timeStamping) when it is
 * PrivatBank's, over HTTPS — the certificates say http://, the server answers both, and https:// also works from a page
 * served over HTTPS. Null for any other service.
 */
export function timeStampUrl(certificate: Certificate): string | null {
  for (const url of certificate.timeStampUrls) {
    try {
      const u = new URL(url);
      if (u.hostname === new URL(TSP_ORIGIN).hostname) return `${TSP_ORIGIN}${u.pathname}${u.search}`;
    } catch {
      // not a URL
    }
  }
  return null;
}
