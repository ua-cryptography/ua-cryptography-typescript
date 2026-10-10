import { fromUtf8, plain } from '../bytes';

/**
 * A small XML parser for signatures, with the data model canonicalization needs and nothing more. It runs the same in
 * the page and in Node (which has no DOMParser), and like XmlSafe.cs it refuses DTDs, so no entity can be declared and
 * nothing external is ever resolved (no XXE). Line ends and attribute values are normalized as XML 1.0 (2.11, 3.3.3)
 * requires, since C14N works on the normalized model.
 *
 * Namespaces are resolved while parsing: every element and attribute knows its prefix, local name and namespace URI,
 * and namespace declarations stay in the attribute list (namespace URI XMLNS_NS), as in the .NET DOM the C# reference
 * canonicalizes.
 */

export const XML_NS = 'http://www.w3.org/XML/1998/namespace';
export const XMLNS_NS = 'http://www.w3.org/2000/xmlns/';

export type XmlNode = XmlElement | XmlText | XmlComment | XmlProcessingInstruction;

export class XmlAttribute {
  constructor(
    /** The qualified name as written ("xmlns:ds", "Id"). */
    readonly name: string,
    readonly prefix: string,
    readonly localName: string,
    readonly namespaceURI: string,
    readonly value: string,
  ) {}
}

export class XmlText {
  readonly kind = 'text';
  parent: XmlElement | null = null;
  constructor(public value: string) {}
}

export class XmlComment {
  readonly kind = 'comment';
  parent: XmlElement | null = null;
  constructor(readonly value: string) {}
}

export class XmlProcessingInstruction {
  readonly kind = 'pi';
  parent: XmlElement | null = null;
  constructor(
    readonly target: string,
    readonly data: string,
  ) {}
}

export class XmlElement {
  readonly kind = 'element';
  parent: XmlElement | null = null;
  readonly children: XmlNode[] = [];
  readonly attributes: XmlAttribute[] = [];
  prefix = '';
  localName = '';
  namespaceURI = '';

  constructor(
    /** The qualified name as written ("ds:Signature"). */
    readonly name: string,
  ) {}

  /** The value of an attribute without a namespace, or '' (as XmlElement.GetAttribute). */
  getAttribute(name: string): string {
    return this.attributes.find((a) => a.name === name && a.namespaceURI !== XMLNS_NS)?.value ?? '';
  }

  getAttributeNS(namespaceURI: string, localName: string): string {
    return this.attributes.find((a) => a.namespaceURI === namespaceURI && a.localName === localName)?.value ?? '';
  }

  /** The child elements, optionally only those with the given namespace and local name. */
  elements(namespaceURI?: string, localName?: string): XmlElement[] {
    return this.children.filter(
      (c): c is XmlElement => c.kind === 'element' && (namespaceURI === undefined || (c.namespaceURI === namespaceURI && c.localName === localName)),
    );
  }

  /** The first child element with this namespace and local name, or null. */
  element(namespaceURI: string, localName: string): XmlElement | null {
    return this.elements(namespaceURI, localName)[0] ?? null;
  }

  /** Every descendant element in document order, optionally only those with the given name. */
  descendants(namespaceURI?: string, localName?: string): XmlElement[] {
    const result: XmlElement[] = [];
    const walk = (e: XmlElement): void => {
      for (const c of e.children) {
        if (c.kind !== 'element') continue;
        if (namespaceURI === undefined || (c.namespaceURI === namespaceURI && c.localName === localName)) result.push(c);
        walk(c);
      }
    };
    walk(this);
    return result;
  }

  /** The concatenated text of the element and its descendants. */
  get textContent(): string {
    let s = '';
    for (const c of this.children) {
      if (c.kind === 'text') s += c.value;
      else if (c.kind === 'element') s += c.textContent;
    }
    return s;
  }

  isDescendantOf(ancestor: XmlElement): boolean {
    for (let n = this.parent; n; n = n.parent) if (n === ancestor) return true;
    return false;
  }
}

export class XmlDocument {
  /** The top-level nodes: the root element and any comments or processing instructions around it. */
  readonly children: XmlNode[] = [];

  get root(): XmlElement {
    const root = this.children.find((c): c is XmlElement => c.kind === 'element');
    if (!root) throw new Error('The XML document has no root element.');
    return root;
  }

  /** Every element of the document in document order. */
  allElements(): XmlElement[] {
    return [this.root, ...this.root.descendants()];
  }
}

/** True when the data looks like XML (after a byte order mark and whitespace). */
export function looksLikeXml(data: Uint8Array): boolean {
  let i = data[0] === 0xef && data[1] === 0xbb && data[2] === 0xbf ? 3 : 0;
  for (; i < data.length; i++) {
    const b = data[i]!;
    if (b === 0x20 || b === 0x09 || b === 0x0d || b === 0x0a) continue;
    return b === 0x3c; // '<'
  }
  return false;
}

export function parseXml(data: Uint8Array | string): XmlDocument {
  let text = typeof data === 'string' ? data : fromUtf8(plain(data));
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  return new Parser(text.replace(/\r\n?/g, '\n')).parse();
}

const NAME = /[A-Za-z_:À-￿][\w.:\-·À-￿]*/y;
const SPACE = /[ \t\n]*/y;

class Parser {
  private pos = 0;

  constructor(private readonly s: string) {}

  parse(): XmlDocument {
    const document = new XmlDocument();
    if (this.s.startsWith('<?xml')) {
      const end = this.s.indexOf('?>');
      if (end < 0) throw this.error('Unterminated XML declaration');
      const declaration = this.s.slice(0, end);
      const encoding = /encoding\s*=\s*["']([^"']+)["']/.exec(declaration)?.[1];
      if (encoding && !/^utf-?8$/i.test(encoding)) throw this.error(`Unsupported encoding '${encoding}' (only UTF-8)`);
      this.pos = end + 2;
    }
    let seenRoot = false;
    while (this.pos < this.s.length) {
      if (this.s.startsWith('<!--', this.pos)) document.children.push(this.comment());
      else if (this.s.startsWith('<?', this.pos)) document.children.push(this.processingInstruction());
      else if (this.s.startsWith('<!DOCTYPE', this.pos) || this.s.startsWith('<!', this.pos)) throw this.error('DTDs are not allowed');
      else if (this.s[this.pos] === '<') {
        if (seenRoot) throw this.error('Only one root element is allowed');
        document.children.push(this.element(null, ROOT_SCOPE));
        seenRoot = true;
      } else {
        const next = this.s.indexOf('<', this.pos);
        const chunk = this.s.slice(this.pos, next < 0 ? undefined : next);
        if (chunk.trim() !== '') throw this.error('Text outside the root element');
        this.pos = next < 0 ? this.s.length : next;
      }
    }
    if (!seenRoot) throw this.error('No root element');
    return document;
  }

  private error(message: string): Error {
    const line = this.s.slice(0, this.pos).split('\n').length;
    return new Error(`XML: ${message} (line ${line}).`);
  }

  private name(): string {
    NAME.lastIndex = this.pos;
    const m = NAME.exec(this.s);
    if (!m) throw this.error('A name was expected');
    this.pos += m[0].length;
    return m[0];
  }

  private space(): void {
    SPACE.lastIndex = this.pos;
    this.pos += SPACE.exec(this.s)![0].length;
  }

  private comment(): XmlComment {
    const end = this.s.indexOf('-->', this.pos + 4);
    if (end < 0) throw this.error('Unterminated comment');
    const value = this.s.slice(this.pos + 4, end);
    this.pos = end + 3;
    return new XmlComment(value);
  }

  private processingInstruction(): XmlProcessingInstruction {
    this.pos += 2;
    const target = this.name();
    if (target.toLowerCase() === 'xml') throw this.error('Misplaced XML declaration');
    const end = this.s.indexOf('?>', this.pos);
    if (end < 0) throw this.error('Unterminated processing instruction');
    const data = this.s.slice(this.pos, end).replace(/^[ \t\n]+/, '');
    this.pos = end + 2;
    return new XmlProcessingInstruction(target, data);
  }

  private element(parent: XmlElement | null, scope: ReadonlyMap<string, string>): XmlElement {
    this.pos++; // '<'
    const element = new XmlElement(this.name());
    element.parent = parent;
    const raw: Array<[string, string]> = [];
    for (;;) {
      const before = this.pos;
      this.space();
      const c = this.s[this.pos];
      if (c === '>' || c === '/') break;
      if (this.pos === before) throw this.error('Whitespace is required between attributes');
      const name = this.name();
      this.space();
      if (this.s[this.pos] !== '=') throw this.error(`'=' expected after attribute ${name}`);
      this.pos++;
      this.space();
      const quote = this.s[this.pos];
      if (quote !== '"' && quote !== "'") throw this.error('A quoted attribute value was expected');
      const end = this.s.indexOf(quote, this.pos + 1);
      if (end < 0) throw this.error('Unterminated attribute value');
      const rawValue = this.s.slice(this.pos + 1, end);
      if (rawValue.includes('<')) throw this.error("'<' in an attribute value");
      if (raw.some(([n]) => n === name)) throw this.error(`Duplicate attribute ${name}`);
      // Attribute-value normalization (3.3.3): literal whitespace becomes a space; character references keep theirs.
      raw.push([name, this.decode(rawValue.replace(/[\t\n]/g, ' '))]);
      this.pos = end + 1;
    }

    // Namespace declarations first, then the names.
    let inScope: Map<string, string> | null = null;
    for (const [name, value] of raw) {
      if (name === 'xmlns' || name.startsWith('xmlns:')) {
        const prefix = name === 'xmlns' ? '' : name.slice(6);
        if (prefix === 'xml' || prefix === 'xmlns') {
          if (prefix === 'xmlns' || value !== XML_NS) throw this.error(`The prefix ${prefix} cannot be redeclared`);
        }
        if (prefix !== '' && value === '') throw this.error(`The prefix ${prefix} cannot be undeclared in XML 1.0`);
        inScope ??= new Map(scope);
        inScope.set(prefix, value);
      }
    }
    const ns = inScope ?? scope;
    const split = (qname: string): [string, string] => {
      const colon = qname.indexOf(':');
      return colon < 0 ? ['', qname] : [qname.slice(0, colon), qname.slice(colon + 1)];
    };
    const [prefix, localName] = split(element.name);
    const uri = ns.get(prefix);
    if (uri === undefined) throw this.error(`Undeclared namespace prefix '${prefix}'`);
    element.prefix = prefix;
    element.localName = localName;
    element.namespaceURI = uri;
    for (const [name, value] of raw) {
      if (name === 'xmlns') element.attributes.push(new XmlAttribute(name, '', 'xmlns', XMLNS_NS, value));
      else if (name.startsWith('xmlns:')) element.attributes.push(new XmlAttribute(name, 'xmlns', name.slice(6), XMLNS_NS, value));
      else {
        const [p, local] = split(name);
        let attributeUri = '';
        if (p !== '') {
          const u = ns.get(p);
          if (u === undefined) throw this.error(`Undeclared namespace prefix '${p}'`);
          attributeUri = u;
        }
        if (element.attributes.some((a) => a.namespaceURI === attributeUri && a.localName === local && a.namespaceURI !== XMLNS_NS)) {
          throw this.error(`Duplicate attribute {${attributeUri}}${local}`);
        }
        element.attributes.push(new XmlAttribute(name, p, local, attributeUri, value));
      }
    }

    if (this.s.startsWith('/>', this.pos)) {
      this.pos += 2;
      return element;
    }
    this.pos++; // '>'
    this.content(element, ns);
    return element;
  }

  private content(element: XmlElement, ns: ReadonlyMap<string, string>): void {
    let text = '';
    const flush = (): void => {
      if (text === '') return;
      const last = element.children[element.children.length - 1];
      if (last?.kind === 'text') last.value += text;
      else {
        const node = new XmlText(text);
        node.parent = element;
        element.children.push(node);
      }
      text = '';
    };
    for (;;) {
      const lt = this.s.indexOf('<', this.pos);
      if (lt < 0) throw this.error(`Element ${element.name} is not closed`);
      const chunk = this.s.slice(this.pos, lt);
      if (chunk.includes(']]>')) throw this.error("']]>' in text");
      text += this.decode(chunk);
      this.pos = lt;
      if (this.s.startsWith('</', this.pos)) {
        flush();
        this.pos += 2;
        const name = this.name();
        if (name !== element.name) throw this.error(`</${name}> closes <${element.name}>`);
        this.space();
        if (this.s[this.pos] !== '>') throw this.error(`'>' expected after </${name}`);
        this.pos++;
        return;
      }
      if (this.s.startsWith('<![CDATA[', this.pos)) {
        const end = this.s.indexOf(']]>', this.pos);
        if (end < 0) throw this.error('Unterminated CDATA section');
        text += this.s.slice(this.pos + 9, end); // C14N renders CDATA as text
        this.pos = end + 3;
        continue;
      }
      flush();
      let node: XmlNode;
      if (this.s.startsWith('<!--', this.pos)) node = this.comment();
      else if (this.s.startsWith('<?', this.pos)) node = this.processingInstruction();
      else if (this.s.startsWith('<!', this.pos)) throw this.error('Declarations are not allowed inside elements');
      else node = this.element(element, ns);
      node.parent = element;
      element.children.push(node);
    }
  }

  /** Replaces the five predefined entities and character references; any other entity is an error (no DTD). */
  private decode(text: string): string {
    if (!text.includes('&')) return text;
    return text.replace(/&([^;&\s]*);|&/g, (match, ref: string | undefined) => {
      if (ref === undefined) throw this.error("A bare '&'");
      switch (ref) {
        case 'lt':
          return '<';
        case 'gt':
          return '>';
        case 'amp':
          return '&';
        case 'quot':
          return '"';
        case 'apos':
          return "'";
      }
      const code = /^#x[0-9a-fA-F]+$/.test(ref) ? parseInt(ref.slice(2), 16) : /^#[0-9]+$/.test(ref) ? parseInt(ref.slice(1), 10) : NaN;
      if (!Number.isFinite(code) || code === 0 || code > 0x10ffff) throw this.error(`Unknown entity ${match}`);
      return String.fromCodePoint(code);
    });
  }
}

const ROOT_SCOPE: ReadonlyMap<string, string> = new Map([
  ['', ''],
  ['xml', XML_NS],
]);
