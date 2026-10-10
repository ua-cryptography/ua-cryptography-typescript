/**
 * Bundles src/ into ONE self-contained build/ua-signature.html: the styles, the compiled TypeScript and the bundled
 * certificates (assets/certificates) are inlined, so the page opens from a file:// URL and works offline, with no
 * sibling files.
 *
 * The page's Content-Security-Policy allows one kind of request only — a time-stamp from PrivatBank's TSP server when a
 * signature is made (connect-src https://acsk.privatbank.ua) — and its only script is pinned by hash: the page shows
 * names from certificates and files, and a hash keeps any markup that might slip into them from running.
 *
 * The version is package.json's and nowhere else; a build of anything but the commit tagged v<version> shows the commit
 * too (0.1.0+1a2b3c4).
 */
import { build } from 'esbuild';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const at = (...parts) => join(root, ...parts);
const watch = process.argv.includes('--watch');
const outFile = at('build', 'ua-signature.html');

async function readRelease() {
  const { version } = JSON.parse(await readFile(at('package.json'), 'utf8'));
  const git = (...args) => {
    try {
      return execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    } catch {
      return '';
    }
  };
  const tagged = process.env.RELEASE_TAG === `v${version}` || git('tag', '--points-at', 'HEAD').split('\n').includes(`v${version}`);
  const commit = tagged ? '' : git('rev-parse', '--short', 'HEAD');
  return commit ? `${version}+${commit}` : version;
}

/**
 * `import { ROOTS, INTERMEDIATES } from 'bundled-certificates'`: every file of assets/certificates/roots and
 * …/intermediates as { name, base64 } — DER, PEM or a .p7b bundle, parsed by the page.
 */
const bundledCertificates = {
  name: 'bundled-certificates',
  setup(builder) {
    builder.onResolve({ filter: /^bundled-certificates$/ }, () => ({ path: 'bundled-certificates', namespace: 'certificates' }));
    builder.onLoad({ filter: /.*/, namespace: 'certificates' }, async () => {
      const list = async (dir) => {
        const names = (await readdir(at('assets/certificates', dir))).filter((n) => !n.startsWith('.')).sort();
        return Promise.all(names.map(async (name) => ({ name, base64: (await readFile(at('assets/certificates', dir, name))).toString('base64') })));
      };
      const contents = `export const ROOTS = ${JSON.stringify(await list('roots'))};\nexport const INTERMEDIATES = ${JSON.stringify(await list('intermediates'))};\n`;
      return { contents, loader: 'js', watchFiles: [] };
    });
  },
};

async function bundle(entry, label) {
  const result = await build({
    entryPoints: [at(entry)],
    bundle: true,
    format: 'iife',
    target: ['es2022'],
    platform: 'browser',
    minify: !watch,
    sourcemap: false,
    legalComments: 'none',
    charset: 'utf8',
    define: { __APP_VERSION__: JSON.stringify(label) },
    write: false,
    plugins: [bundledCertificates],
  });
  const output = result.outputFiles[0];
  if (!output) throw new Error('esbuild returned an empty result');
  return output.text;
}

/** `</script` inside a string literal would close the inline tag early. */
const guard = (code) => code.replace(/<\/(script|style)/gi, '<\\/$1');

/**
 * `<!--` followed by `<script` before any `-->` switches the HTML parser into the "double escaped" state, in which
 * `</script>` no longer closes the tag and the page runs nothing.
 */
function assertScriptCloses(code) {
  const open = code.indexOf('<!--');
  if (open >= 0 && /<script/i.test(code.slice(open, code.indexOf('-->', open) >>> 0))) throw new Error("The script has '<!--' followed by '<script'");
}

/** The whole point of the build: nothing may be fetched at runtime. */
function assertSelfContained(html) {
  const offenders = [
    [/<script[^>]+\ssrc=/i, '<script src=…>'],
    [/<link[^>]+href=["'](?!data:)/i, '<link href=…>'],
    [/@import\s+(url\()?["']?(?!data:)/i, '@import'],
    [/url\(\s*["']?https?:/i, 'url(http…)'],
  ];
  for (const [pattern, name] of offenders) if (pattern.test(html)) throw new Error(`An external reference is left in the file: ${name}`);
  // The one network exception: PrivatBank's time-stamping service (src/app/timestamp.ts). Nothing else may be added here
  // without a decision of the owner.
  const connect = /http-equiv="Content-Security-Policy" content="[^"]*connect-src ([^;"]*)/.exec(html)?.[1]?.trim();
  if (connect !== 'https://acsk.privatbank.ua') throw new Error(`The Content-Security-Policy must have connect-src https://acsk.privatbank.ua and nothing else, not ${connect}`);
}

/** script-src 'unsafe-inline' → the hash of the one inline script: the page's own code runs, injected handlers do not. */
function pinScript(html) {
  const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  if (scripts.length !== 1) throw new Error(`Expected one inline script, found ${scripts.length}`);
  const hash = createHash('sha256').update(scripts[0][1], 'utf8').digest('base64');
  const pattern = /(http-equiv="Content-Security-Policy" content="[^"]*script-src )'unsafe-inline'/;
  if (!pattern.test(html)) throw new Error("The Content-Security-Policy has no script-src 'unsafe-inline' to replace");
  return html.replace(pattern, (_, before) => `${before}'sha256-${hash}'`);
}

async function buildOnce() {
  const label = await readRelease();
  const [template, styles, icon, appJs] = await Promise.all([
    readFile(at('src/app/template.html'), 'utf8'),
    readFile(at('src/app/styles.css'), 'utf8'),
    readFile(at('assets/icon.svg'), 'utf8'),
    bundle('src/app/main.ts', label),
  ]);
  assertScriptCloses(appJs);
  const iconUri = `data:image/svg+xml;base64,${Buffer.from(icon.trim(), 'utf8').toString('base64')}`;
  let html = template
    .replace('/*__STYLES__*/', () => styles)
    .replace('/*__APP__*/', () => guard(appJs))
    .replaceAll('__ICON__', () => iconUri)
    .replaceAll('__VERSION__', () => label);
  assertSelfContained(html);
  html = pinScript(html);

  await mkdir(at('build'), { recursive: true });
  await writeFile(outFile, html, 'utf8');
  const kb = (n) => (n / 1024).toFixed(1);
  console.log(`build/ua-signature.html ${label} — ${kb(Buffer.byteLength(html, 'utf8'))} KB (code ${kb(appJs.length)} KB, styles ${kb(styles.length)} KB)`);
}

await buildOnce();

if (watch) {
  const { watch: watchDir } = await import('node:fs');
  let pending = null;
  for (const dir of ['src', 'assets']) {
    watchDir(at(dir), { recursive: true }, () => {
      clearTimeout(pending);
      pending = setTimeout(() => buildOnce().catch((error) => console.error(error.message)), 120);
    });
  }
  console.log('watching src/ and assets/ …');
}
