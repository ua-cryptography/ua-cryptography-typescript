import { ascii } from '../bytes';
import { looksLikeXml, parseXml } from '../xml/dom';
import { looksLikeZip, readZip } from '../zip';
import { decodePem } from './asn1';
import { verifyCades } from './cades';
import { CONTAINER_TITLE, type ValidationOptions, VerificationReport, VerificationResult } from './report';
import { externalReferences, verifyXades } from './xades';

export const ASIC_S_MIME_TYPE = 'application/vnd.etsi.asic-s+zip';
export const ASIC_E_MIME_TYPE = 'application/vnd.etsi.asic-e+zip';
const MANIFEST_NS = 'urn:oasis:names:tc:opendocument:xmlns:manifest:1.0';

/**
 * Verifies a signed file of any supported format, recognised by its content: ASiC-S / ASiC-E (ZIP), XAdES (XML) or
 * CAdES (DER, PEM or base64) — a port of SignatureVerifier.cs. `detached` resolves the data of detached signatures: it
 * is called with the file name a XAdES reference uses, or with null for a detached CAdES.
 */
export async function verifySignature(
  signature: Uint8Array,
  detached: (name: string | null) => Uint8Array | null,
  options: ValidationOptions,
): Promise<VerificationResult> {
  if (looksLikeZip(signature)) return verifyAsic(signature, options);
  if (looksLikeXml(signature)) {
    const document = parseXml(signature);
    const reports = verifyXades(document, (name) => detached(name), options);
    const files = new Map<string, Uint8Array>();
    for (const name of new Set(externalReferences(document))) {
      const content = detached(name);
      if (content) files.set(name, content);
    }
    return new VerificationResult('XAdES (XML)', reports, files);
  }
  return verifyCades(decodePem(signature, 'CMS'), detached(null), options);
}

async function verifyAsic(container: Uint8Array, options: ValidationOptions): Promise<VerificationResult> {
  const zip = await readZip(container);
  const entries = new Map(zip.map((e) => [e.name, e.data]));
  const first = zip[0];
  const firstAndStored = !!first && first.name === 'mimetype' && first.method === 0;
  const mimeType = entries.has('mimetype') ? ascii(entries.get('mimetype')!).trim() : null;

  const structure = new VerificationReport(CONTAINER_TITLE, options.now);
  structure.check('mimetype', firstAndStored, firstAndStored ? `'${mimeType}', first and stored` : 'the mimetype entry must be first and uncompressed');
  const data = [...entries.keys()].filter((n) => n !== 'mimetype' && !n.startsWith('META-INF/'));
  const files = new Map(data.map((n) => [n, entries.get(n)!]));
  const resolve = (name: string | null): Uint8Array | null => (name !== null && !name.startsWith('META-INF/') ? (entries.get(name) ?? null) : null);

  const xadesEntries = [...entries.keys()].filter((n) => n.startsWith('META-INF/') && /signature/i.test(n) && /\.xml$/i.test(n));
  const cadesEntries = [...entries.keys()].filter((n) => n.startsWith('META-INF/') && /\.p7s$/i.test(n));

  const reports: VerificationReport[] = [];
  let format: string;
  if (mimeType === ASIC_S_MIME_TYPE) {
    format = 'ASiC-S';
    structure.check('data', data.length === 1, data.length === 1 ? `one data file '${data[0]}'` : `${data.length} data files; ASiC-S holds exactly one`);
    const single = data.length === 1 ? entries.get(data[0]!)! : null;
    for (const entry of cadesEntries) reports.push(...titled(verifyCades(entries.get(entry)!, single, options).signatures, entry));
  } else if (mimeType === ASIC_E_MIME_TYPE) {
    format = 'ASiC-E';
    checkManifest(entries, data, structure);
    if (cadesEntries.length > 0) structure.warn('signatures', 'CAdES signatures in ASiC-E (ASiCManifest) are not verified');
  } else {
    format = 'ZIP';
    structure.fail('mimetype', `'${mimeType}' is not an ASiC media type`);
  }

  const covered = new Set<string>();
  for (const entry of xadesEntries) {
    const document = parseXml(entries.get(entry)!);
    for (const name of externalReferences(document)) covered.add(name);
    reports.push(...titled(verifyXades(document, (n) => resolve(n), options), entry));
  }
  if (mimeType === ASIC_S_MIME_TYPE && cadesEntries.length > 0 && data.length === 1) covered.add(data[0]!);
  for (const file of data.filter((f) => !covered.has(f))) structure.fail(`file '${file}'`, 'is in the container but not covered by any signature');
  if (reports.length === 0) structure.fail('signatures', 'the container holds no signature');

  return new VerificationResult(format, [structure, ...reports], files);
}

function checkManifest(entries: Map<string, Uint8Array>, data: string[], structure: VerificationReport): void {
  const bytes = entries.get('META-INF/manifest.xml');
  if (!bytes) {
    structure.warn('manifest', 'META-INF/manifest.xml is missing');
    return;
  }
  const manifest = parseXml(bytes);
  const listed = new Set(manifest.allElements().filter((e) => e.namespaceURI === MANIFEST_NS && e.localName === 'file-entry').map((e) => e.getAttributeNS(MANIFEST_NS, 'full-path')));
  const missing = data.filter((f) => !listed.has(f));
  if (missing.length === 0) structure.pass('manifest', `lists all ${data.length} data files`);
  else structure.warn('manifest', `does not list ${missing.join(', ')}`);
}

function titled(reports: readonly VerificationReport[], entry: string): VerificationReport[] {
  for (const r of reports) r.title = `${r.title} (${entry})`;
  return [...reports];
}
