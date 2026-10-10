/**
 * DOM helpers. Everything a file or a certificate brings (names, subjects, messages) goes into the page as text, never
 * as markup.
 */

type Child = Node | string | null | undefined | false;
type Attributes = Record<string, string | boolean | ((event: Event) => void)>;

/** An element with attributes ("on…" are listeners) and children (strings become text nodes). */
export function h<K extends keyof HTMLElementTagNameMap>(tag: K, attributes: Attributes | null = null, ...children: Child[]): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes ?? {})) {
    if (typeof value === 'function') element.addEventListener(name.slice(2), value);
    else if (value === true) element.setAttribute(name, '');
    else if (value !== false) element.setAttribute(name, value);
  }
  for (const child of children) if (child !== null && child !== undefined && child !== false) element.append(child);
  return element;
}

export function byId<T extends HTMLElement = HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error(`#${id} is missing`);
  return element as T;
}

export async function readFile(file: File): Promise<Uint8Array> {
  return new Uint8Array(await file.arrayBuffer());
}

/** Saves bytes as a file through a temporary blob: URL. */
export function download(name: string, bytes: Uint8Array, type = 'application/octet-stream'): void {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type }));
  const a = h('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

/** "2026-10-10 17:34:36 UTC" — UTC, as the signatures record time. */
export function formatTime(time: Date): string {
  return `${time.toISOString().slice(0, 19).replace('T', ' ')} UTC`;
}

export function formatDay(time: Date): string {
  return time.toISOString().slice(0, 10);
}

/**
 * Makes `zone` accept dropped files and clicks on `button` open `input`. Every handler gets the files at once:
 * the DataTransfer is empty after the first await.
 */
export function fileDrop(zone: HTMLElement, input: HTMLInputElement, button: HTMLElement, onFiles: (files: File[]) => void): void {
  button.addEventListener('click', () => input.click());
  input.addEventListener('change', () => {
    const files = [...(input.files ?? [])];
    input.value = '';
    if (files.length > 0) onFiles(files);
  });
  zone.addEventListener('keydown', (event) => {
    if ((event.key === 'Enter' || event.key === ' ') && event.target === zone) {
      event.preventDefault();
      input.click();
    }
  });
  zone.addEventListener('dragover', (event) => {
    event.preventDefault();
    zone.classList.add('over');
  });
  zone.addEventListener('dragleave', () => zone.classList.remove('over'));
  zone.addEventListener('drop', (event) => {
    event.preventDefault();
    event.stopPropagation();
    zone.classList.remove('over');
    const files = [...(event.dataTransfer?.files ?? [])];
    if (files.length > 0) onFiles(files);
  });
}

/** Lets the browser paint (a "working…" banner) before a long synchronous computation. */
export function nextFrame(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 20));
}

export function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
