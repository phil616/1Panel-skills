import { requireInput, PanelError } from './errors.js';
export interface Directive {
  name: string;
  args: string[];
  start: number;
  end: number;
  open?: number;
  close?: number;
  children?: Directive[];
}
// Tokenize before editing. Quotes, comments, escaped characters and ${variables} are not block boundaries.
export function parseNginx(source: string): Directive[] {
  const tokens: { value: string; start: number; end: number }[] = [];
  let i = 0;
  while (i < source.length) {
    if (/\s/.test(source[i])) {
      i++;
      continue;
    }
    if (source[i] === '#') {
      while (i < source.length && source[i] !== '\n') i++;
      continue;
    }
    const start = i;
    if ('{};'.includes(source[i])) {
      tokens.push({ value: source[i++], start, end: i });
      continue;
    }
    let value = '',
      quote = '';
    while (i < source.length) {
      const c = source[i];
      if (c === '\\') {
        requireInput(i + 1 < source.length, 'Truncated escape');
        value += source[i + 1];
        i += 2;
        continue;
      }
      if (quote) {
        if (c === quote) quote = '';
        else value += c;
        i++;
        continue;
      }
      if (c === '"' || c === "'") {
        quote = c;
        i++;
        continue;
      }
      if (c === '$' && source[i + 1] === '{') {
        const end = source.indexOf('}', i + 2);
        requireInput(end >= 0, 'Unclosed variable');
        value += source.slice(i, end + 1);
        i = end + 1;
        continue;
      }
      if (/\s/.test(c) || '{};#'.includes(c)) break;
      value += c;
      i++;
    }
    requireInput(!quote && i > start, 'Unclosed quoted token');
    tokens.push({ value, start, end: i });
  }
  let at = 0;
  function list(nested: boolean): Directive[] {
    const out: Directive[] = [];
    while (at < tokens.length) {
      if (tokens[at].value === '}') {
        requireInput(nested, 'Unexpected closing block');
        return out;
      }
      const first = tokens[at++];
      requireInput(!['{', ';'].includes(first.value), 'Missing directive name');
      const args: string[] = [];
      while (at < tokens.length && !['{', '}', ';'].includes(tokens[at].value))
        args.push(tokens[at++].value);
      requireInput(at < tokens.length, 'Missing directive terminator');
      const boundary = tokens[at++];
      if (boundary.value === ';')
        out.push({ name: first.value, args, start: first.start, end: boundary.end });
      else if (boundary.value === '{') {
        const children = list(true);
        requireInput(at < tokens.length && tokens[at].value === '}', 'Unclosed block');
        const close = tokens[at++];
        out.push({
          name: first.value,
          args,
          start: first.start,
          end: close.end,
          open: boundary.start,
          close: close.start,
          children,
        });
      } else throw new PanelError('INVALID_INPUT', 'Unexpected closing block in directive');
    }
    requireInput(!nested, 'Unclosed block');
    return out;
  }
  return list(false);
}
export function flatten(nodes: Directive[]): Directive[] {
  return nodes.flatMap((n) => [n, ...flatten(n.children ?? [])]);
}
const begin = '# BEGIN 1panel-skills mtls v1',
  end = '# END 1panel-skills mtls v1';
export function removeManagedInclude(content: string) {
  const start = content.indexOf(begin),
    finish = content.indexOf(end);
  if (start < 0 && finish < 0) return content;
  requireInput(
    start >= 0 &&
      finish > start &&
      content.indexOf(begin, start + 1) < 0 &&
      content.indexOf(end, finish + 1) < 0,
    'Ambiguous managed block',
  );
  const before = content.slice(0, start),
    block = content.slice(start + begin.length, finish),
    after = content.slice(finish + end.length).replace(/^\r?\n/, '');
  const directives = parseNginx(block);
  requireInput(
    directives.length === 1 &&
      directives[0].name === 'include' &&
      directives[0].args.length === 1 &&
      /^\/www\/sites\/[A-Za-z0-9_.-]+\/mtls\/policy-[a-f0-9]{64}\.conf$/.test(
        directives[0].args[0],
      ),
    'Managed marker contains foreign configuration',
  );
  // Remove only the exact owned comment/include range. Foreign adjacent whitespace is preserved.
  return before + after;
}
export function managedPath(content: string): string | undefined {
  if (!content.includes(begin)) return undefined;
  const start = content.indexOf(begin),
    finish = content.indexOf(end);
  removeManagedInclude(content);
  return parseNginx(content.slice(start + begin.length, finish))[0].args[0];
}
export function inspectNginx(content: string) {
  const nodes = flatten(parseNginx(content));
  return {
    directives: nodes
      .filter((n) =>
        ['ssl_client_certificate', 'ssl_verify_client', 'ssl_verify_depth', 'include'].includes(
          n.name,
        ),
      )
      .map((n) => ({ name: n.name, args: n.args })),
    accessPhase: nodes.filter((n) => /^access_by_lua/.test(n.name)).map((n) => n.name),
    quic: nodes.some(
      (n) =>
        (n.name === 'listen' && n.args.includes('quic')) ||
        (n.name === 'add_header' &&
          n.args[0]?.toLowerCase() === 'alt-svc' &&
          n.args.join(' ').includes('h3')),
    ),
    runtime: 'NOT_VERIFIED',
  };
}
export function managedSiteConfig(content: string, runtimePolicyPath: string) {
  const clean = removeManagedInclude(content);
  const roots = parseNginx(clean);
  requireInput(
    roots.length === 1 &&
      roots[0].name === 'server' &&
      roots[0].children &&
      roots[0].close !== undefined,
    'mTLS currently requires exactly one server block',
  );
  const server = roots[0],
    nodes = flatten(server.children!);
  if (nodes.some((n) => /^access_by_lua/.test(n.name)))
    throw new PanelError(
      'CONFLICT',
      'Existing access phase Lua/WAF handler; composition is not verified',
    );
  if (
    nodes.some((n) =>
      [
        'ssl_client_certificate',
        'ssl_verify_client',
        'ssl_verify_depth',
        'ssl_session_cache',
        'ssl_session_tickets',
      ].includes(n.name),
    )
  )
    throw new PanelError('CONFLICT', 'Existing administrator mTLS directives; do not overwrite');
  if (
    nodes.some(
      (n) =>
        n.name === 'return' ||
        (n.name === 'rewrite' &&
          n.args.some((a) => ['redirect', 'permanent', 'last'].includes(a))) ||
        (n.name === 'satisfy' && n.args.includes('any')),
    )
  )
    throw new PanelError(
      'CONFLICT',
      'Early rewrite/return or satisfy-any may bypass access policy',
    );
  const listens = nodes.filter((n) => n.name === 'listen');
  requireInput(
    listens.length > 0 &&
      listens.every((n) => n.args.includes('ssl') && !n.args.includes('quic')) &&
      !inspectNginx(clean).quic,
    'Require HTTPS-only server without QUIC/HTTP3',
  );
  requireInput(
    nodes.some((n) => n.name === 'ssl_certificate'),
    'Existing server TLS certificate required',
  );
  const insertion = `${begin}\n    include ${runtimePolicyPath};\n    ${end}\n`;
  // Stable insertion: no new whitespace outside the exact managed marker range.
  return clean.slice(0, server.close!) + insertion + clean.slice(server.close!);
}

// Raw Nginx administration must not become an unchecked Lua upload route.
// Preserve existing handlers/dependencies, and route Lua changes through reviewed policy actions.
export function assertLuaUnchanged(before: string, after: string) {
  function signatures(source: string) {
    const out: string[] = [];
    function visit(nodes: Directive[], context: { name: string; args: string[] }[]) {
      for (const node of nodes) {
        if (/_by_lua(?:_|$)/.test(node.name) || node.name.startsWith('lua_'))
          out.push(
            JSON.stringify({
              context,
              name: node.name,
              args: node.args,
              block: node.open === undefined ? undefined : source.slice(node.open + 1, node.close),
            }),
          );
        if (node.children) visit(node.children, [...context, { name: node.name, args: node.args }]);
      }
    }
    visit(parseNginx(source), []);
    return out;
  }
  if (JSON.stringify(signatures(before)) !== JSON.stringify(signatures(after)))
    throw new PanelError(
      'FORBIDDEN',
      'Raw configuration cannot add or alter Lua handlers/dependencies; use the reviewed mTLS template workflow',
    );
}
