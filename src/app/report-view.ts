import { hashName, signatureAlgorithmName } from '../core/pki/algorithms';
import type { Certificate } from '../core/pki/certificate';
import { Oid } from '../core/pki/oids';
import { CONTAINER_TITLE, type VerificationCheck, type VerificationReport, type VerificationResult } from '../core/pki/report';
import { download, formatDay, formatTime, h } from './ui';

/** The verdict of a whole result: 'ok', 'warn' (valid, something not established) or 'fail'. */
export function verdict(result: VerificationResult): 'ok' | 'warn' | 'fail' {
  if (!result.isValid) return 'fail';
  return result.signatures.some((s) => s.hasWarnings) ? 'warn' : 'ok';
}

const MARK: Record<VerificationCheck['status'], string> = { passed: '✓', warning: '!', failed: '✗' };

function checkList(checks: readonly VerificationCheck[]): HTMLUListElement {
  return h(
    'ul',
    { class: 'checks' },
    ...checks.map((c) => h('li', { class: c.status }, h('span', { class: 'mark', 'aria-label': c.status }, MARK[c.status]), h('div', null, h('span', { class: 'name' }, c.name), ': ', h('span', { class: 'details' }, c.details)))),
  );
}

function who(c: Certificate): string {
  return c.shortName;
}

function certificateFacts(c: Certificate): Array<[string, string]> {
  const facts: Array<[string, string]> = [];
  const organization = c.subject.get(Oid.Organization);
  const serial = c.subject.get(Oid.SerialNumber);
  if (organization) facts.push(['Organization', organization]);
  if (serial) facts.push(['Identifier', serial]);
  facts.push(['Issued by', c.issuer.get(Oid.CommonName) ?? c.issuer.toString()]);
  facts.push(['Certificate valid', `${formatDay(c.notBefore)} – ${formatDay(c.notAfter)}`]);
  return facts;
}

function facts(rows: Array<[string, string]>): HTMLDListElement {
  return h('dl', { class: 'facts' }, ...rows.flatMap(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
}

function signatureCard(report: VerificationReport): HTMLElement {
  const status = !report.isValid ? 'fail' : report.hasWarnings ? 'warn' : 'ok';
  const label = status === 'fail' ? 'INVALID' : status === 'warn' ? 'VALID, WITH WARNINGS' : 'VALID';
  const card = h('div', { class: 'card signature' });
  card.append(
    h(
      'div',
      { class: 'signature-head' },
      h('h3', null, report.signer ? who(report.signer) : report.title),
      h('span', { class: `pill pill--${status}` }, label),
    ),
  );

  const rows: Array<[string, string]> = [];
  if (report.format) rows.push(['Format', report.format]);
  if (report.signatureAlgorithm) rows.push(['Algorithm', signatureAlgorithmName(report.signatureAlgorithm)]);
  if (report.claimedSigningTime) rows.push(['Signed at', `${formatTime(report.claimedSigningTime)} (as the signer's computer says)`]);
  if (report.timeStampTime) rows.push(['Time-stamp', `${formatTime(report.timeStampTime)} (qualified time-stamp, verified)`]);
  if (report.signer) rows.push(...certificateFacts(report.signer));
  rows.push(['Signature', report.title]);
  card.append(facts(rows));

  for (const path of report.paths) {
    card.append(
      h('p', { class: 'section-title' }, `Certificate path — ${path.name}`),
      h('div', { class: 'path' }, ...path.certificates.flatMap((c, i) => [i > 0 ? h('span', { class: 'arrow' }, '→') : null, h('span', { class: 'node', title: c.subject.toString() }, c.shortName)])),
    );
  }

  const problems = report.checks.filter((c) => c.status !== 'passed');
  if (problems.length > 0) card.append(h('p', { class: 'section-title' }, 'Attention'), checkList(problems));
  card.append(h('details', { class: 'all-checks' }, h('summary', null, `All checks (${report.checks.length})`), checkList(report.checks)));
  if (report.signedObjects.length > 0) {
    card.append(
      h(
        'details',
        { class: 'all-checks' },
        h('summary', null, 'Signed digests'),
        facts(report.signedObjects.map((o) => [o.name, `${hashName(o.hashAlgorithm)} ${[...o.digest].map((b) => b.toString(16).padStart(2, '0')).join('')}`])),
      ),
    );
  }
  return card;
}

/** The banner, the container's checks, one card per signature and the signed files. */
export function renderResult(result: VerificationResult, fileName: string, contentName: (name: string) => string): HTMLElement {
  const v = verdict(result);
  const signatures = result.signatures.filter((s) => s.title !== CONTAINER_TITLE);
  const container = result.signatures.find((s) => s.title === CONTAINER_TITLE);
  const headline = v === 'fail' ? 'The signature is NOT valid' : v === 'warn' ? 'The signature is valid' : 'The signature is valid';
  const explanation =
    v === 'fail'
      ? 'At least one check failed — see the marked items below.'
      : v === 'warn'
        ? 'Some things could not be established (usually the revocation status of a certificate); see "Attention".'
        : 'Every check passed.';
  const root = h('div', { class: 'result' });
  root.append(
    h(
      'div',
      { class: `banner banner--${v}` },
      h('span', { class: 'icon' }, v === 'fail' ? '✗' : v === 'warn' ? '✓' : '✓'),
      h('div', null, h('strong', null, headline), h('p', null, explanation), h('p', { class: 'file' }, `${fileName} — ${result.format}, ${signatures.length} signature${signatures.length === 1 ? '' : 's'}`)),
    ),
  );
  if (container && container.checks.some((c) => c.status !== 'passed')) {
    root.append(h('div', { class: 'card' }, h('h3', null, 'Container'), checkList(container.checks)));
  }
  for (const s of signatures) root.append(signatureCard(s));

  if (result.signedFiles.size > 0) {
    const files = h('div', { class: 'files' });
    for (const [name, bytes] of result.signedFiles) {
      const saveAs = contentName(name);
      files.append(h('button', { type: 'button', class: 'button button--small', onclick: () => download(saveAs, bytes) }, `Save ${saveAs} (${bytes.length.toLocaleString('en')} bytes)`));
    }
    root.append(h('div', { class: 'card' }, h('h3', null, 'Signed content'), files));
  }
  return root;
}

export function busy(text: string): HTMLElement {
  return h('div', { class: 'banner banner--busy' }, h('span', { class: 'icon' }, '…'), h('div', null, h('strong', null, text)));
}

/** A warning that does not replace the result: something around it did not work out. */
export function notice(title: string, message: string): HTMLElement {
  return h('div', { class: 'banner banner--warn notice' }, h('span', { class: 'icon' }, '!'), h('div', null, h('strong', null, title), h('p', null, message)));
}

export function failure(title: string, message: string): HTMLElement {
  return h('div', { class: 'banner banner--fail' }, h('span', { class: 'icon' }, '✗'), h('div', null, h('strong', null, title), h('p', null, message)));
}
