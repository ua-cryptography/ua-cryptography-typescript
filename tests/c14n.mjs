/**
 * The XML parser and C14N against xmllint (libxml2) as an independent implementation: inclusive and exclusive
 * canonicalization, with comments, of tricky documents (tests/data/c14n) — as whole documents and for every element
 * subtree. A subtree's expected output comes from xmllint over a standalone copy of the subtree that declares every
 * namespace in scope (and, for inclusive C14N, carries the inherited xml:* attributes): C14N of the subtree and of that
 * copy are the same by definition. Skipped when xmllint is not installed.
 */
import { execFileSync } from 'node:child_process';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { checker, load, root } from '../tools/load.mjs';

const X = await load('core/xml/dom', 'core/xml/c14n', 'core/bytes');
const { check, done } = checker();
const dir = join(root, 'tests/data/c14n');

let xmllint = true;
try {
  execFileSync('xmllint', ['--version'], { stdio: 'ignore' });
} catch {
  xmllint = false;
}

const lint = (mode, xml) => execFileSync('xmllint', [mode, '-'], { input: xml }).toString('utf8');

/** A standalone copy of `element` with every in-scope namespace declared (and inherited xml:* for inclusive). */
function standalone(element, inclusive) {
  const scope = new Map();
  const chain = [];
  for (let n = element; n; n = n.parent) chain.unshift(n);
  for (const e of chain) for (const a of e.attributes) if (a.namespaceURI === X.XMLNS_NS) scope.set(a.prefix === 'xmlns' ? a.localName : '', a.value);
  const escText = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\r/g, '&#13;');
  const escAttr = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;').replace(/\t/g, '&#9;').replace(/\n/g, '&#10;').replace(/\r/g, '&#13;');
  const write = (e, apex) => {
    let s = `<${e.name}`;
    if (apex) {
      for (const [p, u] of scope) if (!(p === '' && u === '')) s += p === '' ? ` xmlns="${escAttr(u)}"` : ` xmlns:${p}="${escAttr(u)}"`;
      if (inclusive) {
        const own = new Set(e.attributes.filter((a) => a.namespaceURI === X.XML_NS).map((a) => a.localName));
        for (let n = e.parent; n; n = n.parent) {
          for (const a of n.attributes) {
            if (a.namespaceURI === X.XML_NS && !own.has(a.localName)) {
              own.add(a.localName);
              s += ` ${a.name}="${escAttr(a.value)}"`;
            }
          }
        }
      }
    }
    for (const a of e.attributes) if (!(apex && a.namespaceURI === X.XMLNS_NS)) s += ` ${a.name}="${escAttr(a.value)}"`;
    s += '>';
    for (const c of e.children) {
      if (c.kind === 'element') s += write(c, false);
      else if (c.kind === 'text') s += escText(c.value);
      else if (c.kind === 'comment') s += `<!--${c.value}-->`;
      else s += `<?${c.target}${c.data ? ' ' + c.data : ''}?>`;
    }
    return s + `</${e.name}>`;
  };
  return write(element, true);
}

if (!xmllint) {
  console.log('c14n: xmllint not found — skipped');
  process.exit(0);
}

for (const name of (await readdir(dir)).filter((n) => n.endsWith('.xml'))) {
  const bytes = await readFile(join(dir, name));
  const document = X.parseXml(bytes);
  check(`${name}: inclusive, whole document`, X.fromUtf8(X.canonicalize(document, X.C14N.InclusiveWithComments)), lint('--c14n', bytes));
  check(`${name}: exclusive, whole document`, X.fromUtf8(X.canonicalize(document, X.C14N.ExclusiveWithComments)), lint('--exc-c14n', bytes));
  // Without comments: the comments are dropped by both; xmllint has no switch, so strip them from the input.
  for (const element of document.allElements()) {
    const label = `${name}: <${element.name}>`;
    check(`${label} inclusive subtree`, X.fromUtf8(X.canonicalize(element, X.C14N.InclusiveWithComments)), lint('--c14n', standalone(element, true)));
    check(`${label} exclusive subtree`, X.fromUtf8(X.canonicalize(element, X.C14N.ExclusiveWithComments)), lint('--exc-c14n', standalone(element, false)));
  }
}

// Without comments, and the InclusiveNamespaces PrefixList.
{
  const document = X.parseXml('<a:r xmlns:a="urn:a" xmlns:b="urn:b"><!--c--><a:e>t</a:e></a:r>');
  check('comments dropped', X.fromUtf8(X.canonicalize(document, X.C14N.Exclusive)), '<a:r xmlns:a="urn:a"><a:e>t</a:e></a:r>');
  check('PrefixList renders b', X.fromUtf8(X.canonicalize(document, X.C14N.Exclusive, ['b'])), '<a:r xmlns:a="urn:a" xmlns:b="urn:b"><a:e>t</a:e></a:r>');
  check('PrefixList on a child: b is rendered once', X.fromUtf8(X.canonicalize(document.root.elements()[0], X.C14N.Exclusive, ['b'])), '<a:e xmlns:a="urn:a" xmlns:b="urn:b">t</a:e>');
}

// What the parser refuses.
for (const [label, xml] of [
  ['a DTD', '<!DOCTYPE r [<!ENTITY x "y">]><r>&x;</r>'],
  ['an undeclared entity', '<r>&nbsp;</r>'],
  ['an undeclared prefix', '<p:r/>'],
  ['mismatched tags', '<a></b>'],
  ['two roots', '<a/><b/>'],
  ['a duplicate attribute', '<a x="1" x="2"/>'],
  ['a duplicate expanded attribute', '<a xmlns:p="u" xmlns:q="u" p:x="1" q:x="2"/>'],
  ['a non-UTF-8 encoding', '<?xml version="1.0" encoding="windows-1251"?><r/>'],
]) {
  let refused = false;
  try {
    X.parseXml(xml);
  } catch {
    refused = true;
  }
  check(`the parser refuses ${label}`, refused, true);
}

done('c14n');
