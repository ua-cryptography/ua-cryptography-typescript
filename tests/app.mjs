/**
 * Drives build/ua-signature.html in headless Chrome from a file:// URL: the synthetic signatures fail as untrusted, a
 * certificate added on the Certificates tab makes them valid (and stays after a reload), detached data is matched, a
 * tampered document is rejected; a key store opens (and a wrong password is refused), a document is signed and the
 * new signature verifies. The online revocation check is ticked by default and the choice survives a reload. With the
 * real signatures and key on this machine, the PrivatBank .sig and the «Дія» .asice verify against the bundled roots, and
 * the bank's key signs — with a real time-stamp and the signer's online status only when UA_ONLINE=1. The page may
 * reach PrivatBank's servers and nothing else. No exceptions, console errors or CSP violations allowed.
 *
 * Needs `npm run build` first and a local Chrome (or CHROME=/path/to/chrome); skipped without Chrome.
 * `--shots DIR` saves screenshots of the screens.
 */
import { existsSync, readdirSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { findChrome, launch } from '../tools/chrome.mjs';
import { hasPrivate, PRIVATE } from '../tools/fixtures.mjs';
import { checker, root } from '../tools/load.mjs';

const APP = join(root, 'build', 'ua-signature.html');
const SYNTHETIC = join(root, 'tests', 'data', 'synthetic');
const shotsAt = process.argv.indexOf('--shots');
const SHOTS = shotsAt > 0 ? process.argv[shotsAt + 1] : null;

const chromePath = findChrome();
if (!chromePath) {
  console.log('app: no Chrome found — set CHROME=/path/to/chrome. Skipped.');
  process.exit(0);
}
if (!existsSync(APP)) {
  console.error('app: build/ua-signature.html is missing — run `npm run build` first.');
  process.exit(1);
}

const { check, done } = checker();
const work = await mkdtemp(join(tmpdir(), 'ua-signature-app-'));
const browser = await launch(chromePath);
const { evaluate, until } = browser;
const shot = async (name, width, height) => {
  if (!SHOTS) return;
  await mkdir(SHOTS, { recursive: true });
  await writeFile(join(SHOTS, `${name}.png`), await browser.screenshot(width, height));
};

try {
  await browser.send('Page.addScriptToEvaluateOnNewDocument', {
    source: "window.__violations = []; document.addEventListener('securitypolicyviolation', (e) => window.__violations.push(e.violatedDirective + ' ' + e.blockedURI));",
  });
  await browser.navigate(pathToFileURL(APP).href);
  await until('document.documentElement.dataset.ready === "true"');
  check('the page starts', await evaluate('document.title'), 'Ukrainian e-signature — verify and sign');
  check('built-in roots: ЦЗО ×4 and НБУ', await evaluate('document.querySelectorAll("#trust-roots li").length'), 5);
  check('built-in intermediates (Дія, ПриватБанк and its bundle)', await evaluate('document.querySelectorAll("#trust-intermediates li").length'), 39);
  await shot('verify-empty', 1100, 800);

  /** Verifies the files on the Verify tab; returns [verdict, the failed check names]. */
  const verify = async (...files) => {
    await evaluate('document.getElementById("tab-verify").click(); document.getElementById("verify-result").replaceChildren()');
    await browser.setFiles('#verify-input', files);
    await until('document.querySelector("#verify-result .result, #verify-result .banner--fail") !== null');
    return evaluate(`(() => {
      const r = document.querySelector('#verify-result .result');
      if (!r) return ['error', document.querySelector('#verify-result').textContent];
      return [r.dataset.verdict, [...r.querySelectorAll('.signature details.all-checks .checks li.failed .name, .card:not(.signature) > .checks li.failed .name')].map((n) => n.textContent)];
    })()`);
  };

  // ---- Synthetic signatures: not trusted until their root is added ----
  const [untrustedVerdict, untrustedFailed] = await verify(join(SYNTHETIC, 'asic-e.asice'));
  check('a synthetic ASiC-E is not trusted by default', [untrustedVerdict, untrustedFailed], ['fail', ['signer: trust']]);

  await evaluate('document.getElementById("tab-trust").click()');
  await browser.setFiles('#add-root-input', [join(SYNTHETIC, 'signer-257.cer'), join(SYNTHETIC, 'document.txt')]);
  await until('document.querySelector("#trust-message .message") !== null');
  check('adding a root reports what happened', await evaluate('document.querySelector("#trust-message").textContent'), '1 certificate added as trusted roots; not certificates: document.txt.');
  check('the added root is listed with a Remove button', await evaluate('[...document.querySelectorAll("#trust-roots li")].some((li) => li.textContent.includes("Тестовий підписувач") && li.querySelector("button"))'), true);
  await shot('certificates', 1100, 900);

  // The added root survives a reload (localStorage).
  await browser.navigate(pathToFileURL(APP).href);
  await until('document.documentElement.dataset.ready === "true"');
  check('the added root stays after a reload', await evaluate('document.querySelectorAll("#trust-roots li").length'), 6);

  // The online revocation check: ticked by default, the choice remembered.
  check('the online revocation check is ticked by default', await evaluate('document.getElementById("verify-online").checked'), true);
  await evaluate('document.getElementById("verify-online").click()');
  await browser.navigate(pathToFileURL(APP).href);
  await until('document.documentElement.dataset.ready === "true"');
  check('unticked, it stays so after a reload', await evaluate('document.getElementById("verify-online").checked'), false);
  await evaluate('document.getElementById("verify-online").click()');

  for (const file of ['cades-enveloped.p7s', 'asic-e.asice', 'asic-s.asics']) {
    check(`${file} verifies`, await verify(join(SYNTHETIC, file)), ['ok', []]);
  }
  await shot('verify-valid', 1100, 1100);
  check('a detached CAdES with its document', await verify(join(SYNTHETIC, 'cades-detached.p7s'), join(SYNTHETIC, 'document.txt')), ['ok', []]);
  check('a detached XAdES with its document', await verify(join(SYNTHETIC, 'xades-detached.xml'), join(SYNTHETIC, 'document.txt')), ['ok', []]);
  const [noDataVerdict] = await verify(join(SYNTHETIC, 'cades-detached.p7s'));
  check('a detached CAdES without its document fails', noDataVerdict, 'fail');
  const tampered = join(work, 'document.txt');
  await writeFile(tampered, (await readFile(join(SYNTHETIC, 'document.txt'), 'utf8')).replace('Тестовий', 'Змінений'));
  check('a tampered document is rejected', await verify(join(SYNTHETIC, 'xades-detached.xml'), tampered), ['fail', ["reference 'document.txt'"]]);
  await shot('verify-invalid', 1100, 1000);
  const junk = join(work, 'junk.sig');
  await writeFile(junk, 'not a signature');
  check('junk is reported, not thrown', (await verify(junk))[0], 'error');

  // ---- Signing with the synthetic key ----
  await evaluate('document.getElementById("tab-sign").click()');
  check('Sign is disabled without a key', await evaluate('document.getElementById("sign-run").disabled'), true);
  await browser.setFiles('#key-file', [join(SYNTHETIC, 'signer-257.jks')]);
  await evaluate('document.getElementById("key-password").value = "wrong"; document.getElementById("key-open").click()');
  await until('document.querySelector("#key-info .banner--fail") !== null');
  check('a wrong password is refused', await evaluate('document.querySelector("#key-info strong").textContent'), 'Wrong password');
  await evaluate('document.getElementById("key-password").value = "synthetic test password"; document.getElementById("key-open").click()');
  await until('document.querySelector("#key-info .banner--ok") !== null');
  check('the key opens and shows its owner', await evaluate('document.querySelector("#key-info strong").textContent'), 'Тестовий підписувач');
  check('the password field is cleared', await evaluate('document.getElementById("key-password").value'), '');
  check('no time-stamp for a certificate that names no PrivatBank TSP server', await evaluate('[document.getElementById("sign-timestamp").disabled, document.getElementById("sign-timestamp").checked]'), [true, false]);
  await browser.setFiles('#sign-input', [join(SYNTHETIC, 'document.txt')]);
  await until('!document.getElementById("sign-run").disabled');
  await evaluate('document.getElementById("sign-run").click()');
  await until('document.querySelector("#sign-result .result") !== null');
  check('the new signature verifies', await evaluate('document.querySelector("#sign-result .result").dataset.verdict'), 'ok');
  check('it is CAdES-B, enveloped', await evaluate('document.querySelector("#sign-result .facts dd").textContent'), 'CAdES-B, enveloped, DSTU 7564-256');
  check('a Save button is offered', await evaluate('document.getElementById("sign-save").textContent'), 'Save document.txt.sig');
  await shot('sign', 1100, 1200);

  // ---- Real signatures and key (never in the repository) ----
  if (!hasPrivate) {
    console.log('app: no real signatures on this machine — skipped');
  } else {
    const online = process.env.UA_ONLINE === '1';
    // Without UA_ONLINE the test stays off the network: the online check is unticked (for this page load only).
    if (!online) await evaluate('document.getElementById("verify-online").checked = false');
    const [pbVerdict, pbFailed] = await verify(join(PRIVATE, 'pb', 'valid', 'tosign.txt.sig'));
    check('PrivatBank .sig: valid, warnings only for revocation', [pbVerdict, pbFailed], ['warn', []]);
    const signerRevocation = await evaluate(`[...document.querySelectorAll('#verify-result .signature details.all-checks .checks li')].filter((li) => /^signer: revocation of /.test(li.querySelector('.name').textContent)).map((li) => li.className + ' ' + li.querySelector('.details').textContent.replace(/ of '.*/, ''))[0]`);
    check(`PrivatBank .sig: the signer's status ${online ? 'online' : 'not checked'}`, signerRevocation, online ? 'passed good, online response' : 'warning no OCSP response in the signature; the current status was not checked online');
    if (online) check('PrivatBank .sig: no notice of a failed online check', await evaluate('document.querySelector("#verify-result .notice strong")?.textContent ?? null'), null);
    check('PrivatBank .sig: the time-stamp is verified', await evaluate('[...document.querySelectorAll("#verify-result .facts dt")].some((dt) => dt.textContent === "Time-stamp")'), true);
    check('PrivatBank .sig: the document can be saved', await evaluate('[...document.querySelectorAll("#verify-result .files button")].map((b) => b.textContent.replace(/ \\(.*/, ""))'), ['Save tosign.txt']);
    await shot('verify-privatbank', 1100, 1300);
    check('«Дія» .asice: valid', await verify(join(PRIVATE, 'ASIC-E', 'tosign.txt.asice')), ['warn', []]);
    await shot('verify-diia', 1100, 1300);

    const passwordFile = process.env.UA_PRIVATE_JKS_PASSWORD_FILE ?? join(PRIVATE, 'pb', 'temp.txt');
    const store = readdirSync(join(PRIVATE, 'pb')).find((n) => n.endsWith('.jks'));
    if (store && existsSync(passwordFile)) {
      const password = (await readFile(passwordFile, 'utf8')).trim();
      await evaluate('document.getElementById("tab-sign").click(); document.querySelector("#key-info .link").click()');
      await browser.setFiles('#key-file', [join(PRIVATE, 'pb', store)]);
      await evaluate(`document.getElementById("key-password").value = ${JSON.stringify(password)}; document.getElementById("key-open").click()`);
      await until('document.querySelector("#key-info .banner--ok") !== null');
      check('PrivatBank key: the time-stamp is offered and ticked', await evaluate('[document.getElementById("sign-timestamp").disabled, document.getElementById("sign-timestamp").checked, document.getElementById("sign-timestamp-label").textContent.includes("https://acsk.privatbank.ua/services/tsp/")]'), [false, true, true]);
      // Without UA_ONLINE the test stays off the network: the time-stamp is unticked.
      if (!online) await evaluate('document.getElementById("sign-timestamp").checked = false');
      await evaluate('document.getElementById("sign-result").replaceChildren(); document.getElementById("sign-run").click()');
      await until('document.querySelector("#sign-result .result, #sign-result .banner--fail") !== null', 30000);
      check(`PrivatBank key: ${online ? 'CAdES-T' : 'CAdES-B'} verifies up to the NBU root`, await evaluate('[document.querySelector("#sign-result .result")?.dataset.verdict, document.querySelectorAll("#sign-result li.failed").length, document.querySelector("#sign-result .facts dd")?.textContent]'), ['warn', 0, `CAdES-${online ? 'T' : 'B'}, enveloped, DSTU 7564-256`]);
      if (online) await shot('sign-privatbank-t', 1100, 1400);
    }
  }

  // ---- Phone width ----
  await evaluate('document.getElementById("tab-verify").click()');
  await shot('phone', 390, 844);
  const overflow = await evaluate('document.documentElement.scrollWidth <= window.innerWidth + 1');
  check('no horizontal scroll at the phone width', SHOTS ? overflow : true, true);

  check('no page errors', browser.errors, []);
  // The policy lets the page reach PrivatBank's time-stamping server and nothing else.
  check('any other address is blocked', await evaluate('fetch("https://example.com/").then(() => "reached", () => "blocked")'), 'blocked');
  check('no CSP violations but that one', await evaluate('window.__violations'), ['connect-src https://example.com/']);
  check('the console reports only that refusal', browser.errors.every((e) => e.includes('https://example.com/')), true);
} finally {
  await browser.close();
  await rm(work, { recursive: true, force: true });
}

done('app');
