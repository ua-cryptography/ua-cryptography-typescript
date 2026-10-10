import { utf8 } from '../bytes';
import { XML_NS, XMLNS_NS, XmlDocument, type XmlAttribute, type XmlElement, type XmlNode } from './dom';

/**
 * Canonical XML 1.0 (W3C REC-xml-c14n-20010315) and Exclusive XML Canonicalization 1.0 (W3C REC-xml-exc-c14n-20020718)
 * — a port of XmlCanonicalizer.cs. The input node set is a whole document or one element with its descendants (a
 * same-document reference "#id"), optionally minus one subtree (the enveloped-signature transform).
 *
 * Namespaces are taken from the element and attribute names (prefix and namespace URI) as well as from the xmlns
 * attributes, as in the reference.
 */

export const C14N = {
  Inclusive: 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
  InclusiveWithComments: 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments',
  Exclusive: 'http://www.w3.org/2001/10/xml-exc-c14n#',
  ExclusiveWithComments: 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments',
} as const;

export function isSupportedC14N(algorithm: string): boolean {
  return (Object.values(C14N) as string[]).includes(algorithm);
}

type Scope = ReadonlyMap<string, string>;
const EMPTY_CONTEXT: Scope = new Map([['', '']]);

/**
 * Canonicalizes a document or an element subtree. For exclusive canonicalization `inclusivePrefixes` is the
 * InclusiveNamespaces PrefixList ("#default" names the default namespace); `excluded` and its descendants are left out.
 */
export function canonicalize(node: XmlDocument | XmlElement, algorithm: string, inclusivePrefixes: readonly string[] | null = null, excluded: XmlNode | null = null): Uint8Array {
  if (!isSupportedC14N(algorithm)) throw new Error(`Canonicalization ${algorithm} is not supported.`);
  const writer = new Writer(
    algorithm.startsWith(C14N.Exclusive),
    algorithm.endsWith('WithComments'),
    new Set((inclusivePrefixes ?? []).map((p) => (p === '#default' ? '' : p))),
    excluded,
  );
  if (node instanceof XmlDocument) writer.writeDocument(node);
  else writer.writeApex(node);
  return utf8(writer.output);
}

class Writer {
  output = '';

  constructor(
    private readonly exclusive: boolean,
    private readonly comments: boolean,
    private readonly inclusivePrefixes: ReadonlySet<string>,
    private readonly excluded: XmlNode | null,
  ) {}

  writeDocument(document: XmlDocument): void {
    let afterRoot = false;
    for (const child of document.children) {
      if (child === this.excluded) continue;
      if (child.kind === 'element') {
        this.writeElement(child, EMPTY_CONTEXT, inScope(child, EMPTY_CONTEXT), true);
        afterRoot = true;
      } else if ((child.kind === 'comment' && this.comments) || child.kind === 'pi') {
        if (afterRoot) this.output += '\n';
        this.writeLeaf(child);
        if (!afterRoot) this.output += '\n';
      }
    }
  }

  /** An element and its descendants: the namespaces in scope come from the ancestors as well. */
  writeApex(element: XmlElement): void {
    const ancestors: XmlElement[] = [];
    for (let n = element.parent; n; n = n.parent) ancestors.unshift(n);
    let inherited = EMPTY_CONTEXT;
    for (const ancestor of ancestors) inherited = inScope(ancestor, inherited);
    this.writeElement(element, EMPTY_CONTEXT, inScope(element, inherited), true);
  }

  private writeElement(element: XmlElement, rendered: Scope, scope: Scope, apex: boolean): void {
    // Namespace nodes to render, sorted by prefix (the default namespace, with no prefix, first).
    const namespaces = new Map<string, string>();
    const candidates = this.exclusive ? [...visiblyUtilized(element), ...[...this.inclusivePrefixes].filter((p) => scope.has(p))] : [...scope.keys()];
    for (const prefix of candidates) {
      if (prefix === 'xml') continue;
      const uri = scope.get(prefix);
      if (uri === undefined) continue;
      const current = rendered.get(prefix);
      // xmlns="" only to undo a non-empty default of an output ancestor.
      const render = prefix === '' ? uri !== (current ?? '') : current !== uri;
      if (render && !(prefix !== '' && uri === '')) namespaces.set(prefix, uri);
    }
    const sortedNamespaces = [...namespaces].sort(([a], [b]) => compareOrdinal(a, b));

    const attributes = element.attributes.filter((a) => a.namespaceURI !== XMLNS_NS);
    if (!this.exclusive && apex) attributes.push(...inheritedXmlAttributes(element, attributes));
    attributes.sort((a, b) => compareOrdinal(a.namespaceURI, b.namespaceURI) || compareOrdinal(a.localName, b.localName));

    let out = '<' + element.name;
    for (const [prefix, uri] of sortedNamespaces) out += (prefix === '' ? ' xmlns="' : ` xmlns:${prefix}="`) + escapeAttribute(uri) + '"';
    for (const attribute of attributes) out += ` ${attribute.name}="${escapeAttribute(attribute.value)}"`;
    this.output += out + '>';

    let childRendered = rendered;
    if (sortedNamespaces.length > 0) {
      const copy = new Map(rendered);
      for (const [prefix, uri] of sortedNamespaces) copy.set(prefix, uri);
      childRendered = copy;
    }
    for (const child of element.children) {
      if (child === this.excluded) continue;
      if (child.kind === 'element') this.writeElement(child, childRendered, inScope(child, scope), false);
      else if (child.kind === 'text') this.output += escapeText(child.value);
      else this.writeLeaf(child);
    }
    this.output += '</' + element.name + '>';
  }

  private writeLeaf(node: XmlNode): void {
    if (node.kind === 'comment' && this.comments) this.output += '<!--' + node.value + '-->';
    else if (node.kind === 'pi') this.output += '<?' + node.target + (node.data ? ' ' + node.data : '') + '?>';
  }
}

/** The namespaces in scope at `element`: those of its parent plus its own declarations and names. */
function inScope(element: XmlElement, parent: Scope): Scope {
  let scope: Map<string, string> | null = null;
  const bind = (prefix: string, uri: string): void => {
    if (scope === null && parent.get(prefix) === uri) return;
    scope ??= new Map(parent);
    scope.set(prefix, uri);
  };
  bind(element.prefix, element.namespaceURI);
  for (const attribute of element.attributes) {
    if (attribute.namespaceURI === XMLNS_NS) bind(attribute.prefix === 'xmlns' ? attribute.localName : '', attribute.value);
    else if (attribute.prefix !== '' && attribute.prefix !== 'xml') bind(attribute.prefix, attribute.namespaceURI);
  }
  return scope ?? parent;
}

/** Exclusive C14N: the element's own prefix (or the default namespace) and the prefixes of its attributes. */
function visiblyUtilized(element: XmlElement): string[] {
  const result = [element.prefix];
  for (const attribute of element.attributes) {
    if (attribute.namespaceURI !== XMLNS_NS && attribute.prefix !== '') result.push(attribute.prefix);
  }
  return result;
}

/** Canonical XML 1.0, 2.4: the xml:* attributes of the ancestors are copied to the apex unless it has its own. */
function inheritedXmlAttributes(element: XmlElement, own: readonly XmlAttribute[]): XmlAttribute[] {
  const inherited: XmlAttribute[] = [];
  for (let n = element.parent; n; n = n.parent) {
    for (const attribute of n.attributes) {
      if (
        attribute.namespaceURI === XML_NS &&
        !own.some((a) => a.namespaceURI === XML_NS && a.localName === attribute.localName) &&
        !inherited.some((a) => a.localName === attribute.localName)
      ) {
        inherited.push(attribute);
      }
    }
  }
  return inherited;
}

const compareOrdinal = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

function escapeText(text: string): string {
  return text.replace(/[&<>\r]/g, (c) => (c === '&' ? '&amp;' : c === '<' ? '&lt;' : c === '>' ? '&gt;' : '&#xD;'));
}

function escapeAttribute(value: string): string {
  return value.replace(/[&<"\t\n\r]/g, (c) =>
    c === '&' ? '&amp;' : c === '<' ? '&lt;' : c === '"' ? '&quot;' : c === '\t' ? '&#x9;' : c === '\n' ? '&#xA;' : '&#xD;',
  );
}
