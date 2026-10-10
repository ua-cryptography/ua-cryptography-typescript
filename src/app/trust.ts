import { INTERMEDIATES, ROOTS } from 'bundled-certificates';
import { fromBase64, toBase64 } from '../core/bytes';
import { Certificate, loadCertificates } from '../core/pki/certificate';
import type { ValidationOptions } from '../core/pki/report';

export type Role = 'root' | 'intermediate';

export type TrustEntry = { readonly certificate: Certificate; readonly role: Role; readonly builtIn: boolean; readonly source: string };

const STORAGE_KEY = 'ua-signature.certificates';

/**
 * The certificates verification relies on: the roots and intermediates built into the page (assets/certificates) and
 * those the user added, kept in localStorage as { role, der } — public certificates, nothing secret.
 */
export class TrustStore {
  private readonly entries: TrustEntry[] = [];
  private readonly listeners: Array<() => void> = [];

  constructor() {
    for (const { name, base64 } of ROOTS) for (const c of loadCertificates(fromBase64(base64))) this.push(c, 'root', true, name);
    for (const { name, base64 } of INTERMEDIATES) for (const c of loadCertificates(fromBase64(base64))) this.push(c, 'intermediate', true, name);
    for (const stored of readStored()) {
      try {
        this.push(Certificate.load(fromBase64(stored.der)), stored.role, false, 'added');
      } catch {
        // A damaged stored entry is dropped at the next save.
      }
    }
  }

  get all(): readonly TrustEntry[] {
    return this.entries;
  }

  onChange(listener: () => void): void {
    this.listeners.push(listener);
  }

  options(): ValidationOptions {
    return {
      trustAnchors: this.entries.filter((e) => e.role === 'root').map((e) => e.certificate),
      extraCertificates: this.entries.filter((e) => e.role === 'intermediate').map((e) => e.certificate),
    };
  }

  /** Adds certificates with a role; returns how many were new. A known certificate keeps its place (or becomes a root). */
  add(certificates: readonly Certificate[], role: Role): number {
    let added = 0;
    for (const c of certificates) {
      const existing = this.entries.findIndex((e) => e.certificate.equals(c));
      if (existing >= 0) {
        const e = this.entries[existing]!;
        if (role === 'root' && e.role !== 'root') {
          this.entries[existing] = { ...e, role: 'root', builtIn: false, source: 'added' };
          added++;
        }
        continue;
      }
      this.push(c, role, false, 'added');
      added++;
    }
    if (added > 0) this.save();
    return added;
  }

  remove(certificate: Certificate): void {
    const i = this.entries.findIndex((e) => !e.builtIn && e.certificate.equals(certificate));
    if (i >= 0) {
      this.entries.splice(i, 1);
      this.save();
    }
  }

  private push(certificate: Certificate, role: Role, builtIn: boolean, source: string): void {
    if (this.entries.some((e) => e.certificate.equals(certificate))) return;
    this.entries.push({ certificate, role, builtIn, source });
  }

  private save(): void {
    const stored = this.entries.filter((e) => !e.builtIn).map((e) => ({ role: e.role, der: toBase64(e.certificate.encoded) }));
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(stored));
    } catch {
      // Storage may be unavailable (a private window, a file:// policy): the certificates stay for this session.
    }
    for (const listener of this.listeners) listener();
  }
}

function readStored(): Array<{ role: Role; der: string }> {
  try {
    const value: unknown = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '[]');
    if (!Array.isArray(value)) return [];
    return value.filter(
      (v): v is { role: Role; der: string } =>
        typeof v === 'object' && v !== null && (v.role === 'root' || v.role === 'intermediate') && typeof v.der === 'string',
    );
  } catch {
    return [];
  }
}

/** Parses certificate files (DER, PEM, .p7b); returns the certificates and the names that held none. */
export function parseCertificateFiles(files: ReadonlyArray<{ name: string; bytes: Uint8Array }>): { certificates: Certificate[]; failed: string[] } {
  const certificates: Certificate[] = [];
  const failed: string[] = [];
  for (const { name, bytes } of files) {
    try {
      const found = loadCertificates(bytes);
      if (found.length === 0) failed.push(name);
      certificates.push(...found);
    } catch {
      failed.push(name);
    }
  }
  return { certificates, failed };
}
