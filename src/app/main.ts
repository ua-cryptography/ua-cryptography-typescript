import { Oid } from '../core/pki/oids';
import { signCades, signCadesT } from '../core/pki/cades-signer';
import { requestTimeStamp } from '../core/pki/tsp';
import { loadJks, openSigningKey, type SigningKey, WrongPasswordError } from '../core/pki/jks';
import { requestOcsp } from '../core/pki/ocsp';
import type { VerificationResult } from '../core/pki/report';
import { verifySignature } from '../core/pki/verifier';
import { busy, failure, notice, renderResult, verdict } from './report-view';
import { ocspUrl, PRIVATBANK_ORIGIN, timeStampUrl } from './network';
import { parseCertificateFiles, TrustStore, type Role } from './trust';
import { byId, download, errorText, fileDrop, formatDay, h, nextFrame, readFile } from './ui';

const trust = new TrustStore();

// ---- Tabs ------------------------------------------------------------------------------------------------------------

const VIEWS = ['verify', 'sign', 'trust'] as const;
type View = (typeof VIEWS)[number];

function show(view: View): void {
  for (const v of VIEWS) {
    byId(`view-${v}`).hidden = v !== view;
    byId(`tab-${v}`).setAttribute('aria-selected', String(v === view));
  }
}
for (const v of VIEWS) byId(`tab-${v}`).addEventListener('click', () => show(v));

// A file dropped outside a drop zone must not make the browser open it instead of the page.
window.addEventListener('dragover', (event) => event.preventDefault());
window.addEventListener('drop', (event) => event.preventDefault());

// ---- Verify ----------------------------------------------------------------------------------------------------------

const SIGNATURE_EXTENSIONS = /\.(sig|p7s|p7m|asice|sce|asics|scs|xml)$/i;
const verifyResult = byId('verify-result');

// The online revocation check is on unless the user turned it off; the choice is remembered in this browser.
const ONLINE_KEY = 'ua-signature.online-revocation';
const onlineBox = byId<HTMLInputElement>('verify-online');
try {
  onlineBox.checked = localStorage.getItem(ONLINE_KEY) !== 'off';
} catch {
  // Storage may be unavailable: the default stays.
}
onlineBox.addEventListener('change', () => {
  try {
    localStorage.setItem(ONLINE_KEY, onlineBox.checked ? 'on' : 'off');
  } catch {
    // The choice holds for this session only.
  }
});

/**
 * Verifies offline; then, when the online check is on, asks PrivatBank's OCSP responder about the certificates whose
 * status the signature does not carry and that name that responder, and verifies again with the answers. Requests that
 * fail are returned as messages: those certificates keep their warning.
 */
async function verifyWithOnlineStatus(
  signature: Uint8Array,
  detached: (name: string | null) => Uint8Array | null,
  progress: (text: string) => Promise<void>,
): Promise<{ result: VerificationResult; failures: string[] }> {
  const options = trust.options();
  const offline = await verifySignature(signature, detached, options);
  if (!onlineBox.checked) return { result: offline, failures: [] };
  const targets = offline.unresolvedRevocations.flatMap(({ certificate, issuer }) => {
    const url = ocspUrl(certificate);
    return url ? [{ certificate, issuer, url }] : [];
  });
  if (targets.length === 0) return { result: offline, failures: [] };
  await progress(`Asking ${new URL(PRIVATBANK_ORIGIN).host} for the revocation status…`);
  const settled = await Promise.allSettled(targets.map((t) => requestOcsp(t.url, t.certificate, t.issuer)));
  const responses = settled.flatMap((s) => (s.status === 'fulfilled' ? [s.value] : []));
  const failures = settled.flatMap((s, i) => (s.status === 'rejected' ? [`'${targets[i]!.certificate.shortName}': ${errorText(s.reason)}`] : []));
  const result = await verifySignature(signature, detached, { ...options, onlineRevocation: responses });
  return { result, failures };
}

/**
 * The signature among the dropped files — by its extension, else the only file — and the rest as the data of a detached
 * signature.
 */
function splitFiles(files: Array<{ name: string; bytes: Uint8Array }>): { signature: { name: string; bytes: Uint8Array }; data: Map<string, Uint8Array> } | null {
  if (files.length === 0) return null;
  const signature = files.length === 1 ? files[0]! : (files.find((f) => SIGNATURE_EXTENSIONS.test(f.name)) ?? null);
  if (!signature) return null;
  return { signature, data: new Map(files.filter((f) => f !== signature).map((f) => [f.name, f.bytes])) };
}

/** What the signed content is saved as: the document's own name when the container has one, else the signature's name without ".sig". */
function contentName(signatureName: string): (name: string) => string {
  return (name) => (name !== 'content' ? name : signatureName.replace(/\.(sig|p7s|p7m)$/i, '') || 'content.bin');
}

async function verifyFiles(files: File[]): Promise<void> {
  verifyResult.replaceChildren(busy('Verifying…'));
  await nextFrame();
  try {
    const loaded = await Promise.all(files.map(async (f) => ({ name: f.name, bytes: await readFile(f) })));
    const split = splitFiles(loaded);
    if (!split) {
      verifyResult.replaceChildren(failure('Which file is the signature?', 'Drop one signature (.sig, .p7s, .asice, .asics, .xml) and, for a detached signature, the signed file.'));
      return;
    }
    const { signature, data } = split;
    const single = data.size === 1 ? [...data.values()][0]! : null;
    const base = signature.name.replace(/\.(p7s|sig|p7m)$/i, '');
    const detached = (name: string | null): Uint8Array | null => (name === null ? (data.get(base) ?? single) : (data.get(name) ?? null));
    const started = performance.now();
    const { result, failures } = await verifyWithOnlineStatus(signature.bytes, detached, async (text) => {
      verifyResult.replaceChildren(busy(text));
      await nextFrame();
    });
    const view = renderResult(result, signature.name, contentName(signature.name));
    view.dataset.verdict = verdict(result);
    view.dataset.ms = String(Math.round(performance.now() - started));
    if (failures.length > 0) view.prepend(notice('The online revocation check failed', failures.join(' ')));
    verifyResult.replaceChildren(view);
  } catch (error) {
    verifyResult.replaceChildren(failure('The file could not be read as a signature', errorText(error)));
  }
}

fileDrop(byId('verify-drop'), byId<HTMLInputElement>('verify-input'), byId('verify-pick'), (files) => void verifyFiles(files));

// ---- Sign ------------------------------------------------------------------------------------------------------------

let signingKey: SigningKey | null = null;
let document_: { name: string; bytes: Uint8Array } | null = null;
const keyInfo = byId('key-info');
const signRun = byId<HTMLButtonElement>('sign-run');
const signResult = byId('sign-result');

function updateSignButton(): void {
  signRun.disabled = !(signingKey && document_);
  byId('sign-card').classList.toggle('disabled', !signingKey);
  const stamp = byId<HTMLInputElement>('sign-timestamp');
  const url = signingKey ? timeStampUrl(signingKey.certificate) : null;
  const wasAvailable = !stamp.disabled;
  stamp.disabled = url === null;
  if (url === null) stamp.checked = false;
  else if (!wasAvailable) stamp.checked = true;
  byId('sign-timestamp-label').textContent = !signingKey
    ? 'Qualified time-stamp (CAdES-T) — open a key first'
    : url
      ? `Qualified time-stamp (CAdES-T) from ${url} — sends only the hash of the signature`
      : "Qualified time-stamp (CAdES-T) — not available: the certificate names no PrivatBank time-stamping service";
}

function closeKey(): void {
  signingKey = null;
  keyInfo.hidden = true;
  keyInfo.replaceChildren();
  byId('key-form').hidden = false;
  updateSignButton();
}

byId<HTMLFormElement>('key-form').addEventListener('submit', (event) => {
  event.preventDefault();
  void (async () => {
    const fileInput = byId<HTMLInputElement>('key-file');
    const passwordInput = byId<HTMLInputElement>('key-password');
    const file = fileInput.files?.[0];
    keyInfo.hidden = false;
    if (!file) {
      keyInfo.replaceChildren(failure('No key store', 'Choose the .jks file the bank issued.'));
      return;
    }
    keyInfo.replaceChildren(busy('Opening the key…'));
    await nextFrame();
    try {
      const password = passwordInput.value;
      const entries = loadJks(await readFile(file), password);
      signingKey = openSigningKey(entries, password);
      passwordInput.value = '';
      fileInput.value = '';
      const c = signingKey.certificate;
      byId('key-form').hidden = true;
      keyInfo.replaceChildren(
        h(
          'div',
          { class: 'banner banner--ok' },
          h('span', { class: 'icon' }, '🔑'),
          h(
            'div',
            null,
            h('strong', null, c.shortName),
            h('p', null, [c.subject.get(Oid.SerialNumber), `issued by ${c.issuer.get(Oid.CommonName) ?? c.issuer.toString()}`, `valid ${formatDay(c.notBefore)} – ${formatDay(c.notAfter)}`].filter(Boolean).join(' · ')),
            h('p', { class: 'file' }, `${file.name} · key "${signingKey.alias}" · DSTU 4145, m = ${signingKey.key.domain.field.m} · path: ${signingKey.chain.map((x) => x.shortName).join(' → ')}`),
            h('p', null, h('button', { type: 'button', class: 'link', onclick: closeKey }, 'Close the key')),
          ),
        ),
      );
      if (new Date() > c.notAfter) keyInfo.append(failure('The certificate has expired', `It was valid until ${formatDay(c.notAfter)}; a signature made now will not verify.`));
    } catch (error) {
      signingKey = null;
      const wrong = error instanceof WrongPasswordError;
      keyInfo.replaceChildren(failure(wrong ? 'Wrong password' : 'The key could not be opened', wrong ? 'The key store did not accept this password.' : errorText(error)));
    }
    updateSignButton();
  })();
});

fileDrop(byId('sign-drop'), byId<HTMLInputElement>('sign-input'), byId('sign-pick'), (files) => {
  void (async () => {
    const file = files[0]!;
    document_ = { name: file.name, bytes: await readFile(file) };
    byId('sign-file-name').textContent = `${file.name} (${document_.bytes.length.toLocaleString('en')} bytes)`;
    signResult.replaceChildren();
    updateSignButton();
  })();
});

signRun.addEventListener('click', () => {
  void (async () => {
    if (!signingKey || !document_) return;
    const url = byId<HTMLInputElement>('sign-timestamp').checked ? timeStampUrl(signingKey.certificate) : null;
    signResult.replaceChildren(busy(url ? `Signing and asking ${new URL(url).host} for a time-stamp…` : 'Signing…'));
    await nextFrame();
    try {
      const detached = byId<HTMLInputElement>('sign-detached').checked;
      const hashOid = byId<HTMLSelectElement>('sign-hash').value;
      const signature = url
        ? await signCadesT(document_.bytes, signingKey, (imprint, oid) => requestTimeStamp(url, imprint, oid), { detached, hashOid })
        : signCades(document_.bytes, signingKey, { detached, hashOid });
      const name = `${document_.name}.${detached ? 'p7s' : 'sig'}`;
      const data = document_.bytes;
      const result = await verifySignature(signature, () => data, trust.options());
      const view = renderResult(result, name, contentName(name));
      view.dataset.verdict = verdict(result);
      signResult.replaceChildren(
        h(
          'div',
          { class: 'banner banner--ok' },
          h('span', { class: 'icon' }, '✓'),
          h(
            'div',
            null,
            h('strong', null, `Signed: ${name}`),
            h('p', null, `${signature.length.toLocaleString('en')} bytes. Below is the verification of the new signature.`),
            h('p', null, h('button', { type: 'button', class: 'button button--primary', id: 'sign-save', onclick: () => download(name, signature, 'application/pkcs7-signature') }, `Save ${name}`)),
          ),
        ),
        view,
      );
    } catch (error) {
      const hint = url ? ' Check the connection, or untick the time-stamp to sign offline (CAdES-B).' : '';
      signResult.replaceChildren(failure('Signing failed', errorText(error) + hint));
    }
  })();
});
updateSignButton();

// ---- Certificates ----------------------------------------------------------------------------------------------------

function renderTrust(): void {
  const item = (entry: (typeof trust.all)[number]): HTMLLIElement => {
    const c = entry.certificate;
    return h(
      'li',
      null,
      h(
        'div',
        { class: 'who' },
        h('b', null, c.shortName),
        h('span', null, `${c.subject.get(Oid.SerialNumber) ?? ''}${c.subject.get(Oid.SerialNumber) ? ' · ' : ''}valid ${formatDay(c.notBefore)} – ${formatDay(c.notAfter)}${c.isSelfIssued ? ' · self-signed' : ` · issued by ${c.issuer.get(Oid.CommonName) ?? ''}`}`),
      ),
      entry.builtIn
        ? h('span', { class: 'badge' }, 'built in')
        : h('button', { type: 'button', class: 'button button--small', onclick: () => trust.remove(c) }, 'Remove'),
    );
  };
  byId('trust-roots').replaceChildren(...trust.all.filter((e) => e.role === 'root').map(item));
  const intermediates = trust.all.filter((e) => e.role === 'intermediate');
  byId('trust-intermediates').replaceChildren(...intermediates.map(item));
  byId('trust-intermediates-count').textContent = `Show all ${intermediates.length}`;
}

async function addCertificates(files: File[], role: Role): Promise<void> {
  const message = byId('trust-message');
  const parsed = parseCertificateFiles(await Promise.all(files.map(async (f) => ({ name: f.name, bytes: await readFile(f) }))));
  const added = trust.add(parsed.certificates, role);
  const parts = [`${added} certificate${added === 1 ? '' : 's'} added as ${role === 'root' ? 'trusted roots' : 'intermediates'}`];
  if (parsed.certificates.length > added) parts.push(`${parsed.certificates.length - added} already known`);
  if (parsed.failed.length > 0) parts.push(`not certificates: ${parsed.failed.join(', ')}`);
  message.replaceChildren(h('p', { class: `message message--${parsed.failed.length > 0 && added === 0 ? 'fail' : 'ok'}` }, `${parts.join('; ')}.`));
}

trust.onChange(renderTrust);
renderTrust();
fileDrop(byId('add-root'), byId<HTMLInputElement>('add-root-input'), byId('add-root-pick'), (files) => void addCertificates(files, 'root'));
fileDrop(byId('add-intermediate'), byId<HTMLInputElement>('add-intermediate-input'), byId('add-intermediate-pick'), (files) => void addCertificates(files, 'intermediate'));

document.documentElement.dataset.ready = 'true';
