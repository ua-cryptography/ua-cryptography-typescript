/**
 * Headless Chrome over the DevTools protocol, with nothing but Node: launch, evaluate, wait, hand files to an
 * <input type=file>, screenshot, and collect the page's errors (exceptions, console errors, CSP violations).
 * The path to Chrome comes from CHROME or the usual places; `findChrome()` returns null when there is none.
 */
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export function findChrome() {
  return (
    process.env.CHROME ??
    [
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Chromium.app/Contents/MacOS/Chromium',
      '/usr/bin/google-chrome',
      '/usr/bin/google-chrome-stable',
      '/usr/bin/chromium',
      '/usr/bin/chromium-browser',
    ].find((path) => existsSync(path)) ??
    null
  );
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function launch(chromePath, { width = 1100, height = 900 } = {}) {
  const profile = await mkdtemp(join(tmpdir(), 'ua-signature-chrome-'));
  const flags = ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check', `--window-size=${width},${height}`];
  if (process.platform === 'linux') flags.push('--no-sandbox');
  const chrome = spawn(chromePath, [...flags, 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
  const wsUrl = await new Promise((resolve, reject) => {
    let buffer = '';
    const timer = setTimeout(() => reject(new Error('Chrome did not start')), 20000);
    chrome.stderr.on('data', (d) => {
      buffer += d;
      const m = /DevTools listening on (ws:\/\/\S+)/.exec(buffer);
      if (m) {
        clearTimeout(timer);
        resolve(m[1]);
      }
    });
  });
  const port = new URL(wsUrl).port;
  const targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
  const target = targets.find((t) => t.type === 'page');
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((r) => ws.addEventListener('open', r));

  let id = 0;
  const waiting = new Map();
  const errors = [];
  const events = [];
  ws.addEventListener('message', (e) => {
    const msg = JSON.parse(e.data);
    if (msg.id && waiting.has(msg.id)) {
      waiting.get(msg.id)(msg);
      waiting.delete(msg.id);
      return;
    }
    events.push(msg);
    if (msg.method === 'Runtime.exceptionThrown') errors.push(msg.params.exceptionDetails.exception?.description ?? msg.params.exceptionDetails.text);
    else if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error') errors.push(msg.params.entry.text);
    else if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') errors.push(msg.params.args.map((a) => a.value ?? a.description).join(' '));
  });
  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const n = ++id;
      waiting.set(n, (msg) => (msg.error ? reject(new Error(`${method}: ${JSON.stringify(msg.error)}`)) : resolve(msg.result)));
      ws.send(JSON.stringify({ id: n, method, params }));
    });
  await send('Runtime.enable');
  await send('Log.enable');
  await send('Page.enable');
  await send('DOM.enable');

  const evaluate = async (expression) => {
    const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true, userGesture: true });
    if (r.exceptionDetails) throw new Error(`${expression}\n${r.exceptionDetails.exception?.description ?? 'evaluation failed'}`);
    return r.result.value;
  };

  return {
    send,
    evaluate,
    errors,
    events,
    async navigate(url) {
      await send('Page.navigate', { url });
      await this.until('document.readyState === "complete"');
    },
    async until(expression, timeout = 15000) {
      const end = Date.now() + timeout;
      while (Date.now() < end) {
        try {
          if (await evaluate(expression)) return true;
        } catch (error) {
          if (!/Inspected target navigated or closed|Cannot find context|Execution context was destroyed/.test(error.message)) throw error;
        }
        await sleep(50);
      }
      throw new Error(`Timed out waiting for: ${expression}`);
    },
    /** Puts files into an <input type=file> as a user would pick them, and fires its change event. */
    async setFiles(selector, files) {
      const { result } = await send('Runtime.evaluate', { expression: `document.querySelector(${JSON.stringify(selector)})` });
      if (!result.objectId) throw new Error(`${selector} not found`);
      await send('DOM.setFileInputFiles', { files, objectId: result.objectId });
      await evaluate(`document.querySelector(${JSON.stringify(selector)}).dispatchEvent(new Event('change', { bubbles: true }))`);
    },
    async screenshot(width, height) {
      if (width) await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: width < 700 });
      const { data } = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true });
      return Buffer.from(data, 'base64');
    },
    async close() {
      try {
        ws.close();
      } catch {}
      chrome.kill();
      await new Promise((r) => chrome.once('exit', r));
      await rm(profile, { recursive: true, force: true }).catch(() => {});
    },
  };
}
