// Knowledge graph of this codebase: scans source, writes graph.html.
//   node tools/graph.js          -> regenerate graph.html
//   node tools/graph.js --check  -> self-check the extractor
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const lineOf = (src, i) => src.slice(0, i).split('\n').length;
const esc = (s) => s.replace(/[/\\^$*+?.()|[\]{}]/g, '\\$&');

function walk(dir, out = []) {
  for (const e of fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
    const rel = dir + '/' + e.name;
    if (e.isDirectory()) walk(rel, out);
    else if (/\.(html|js)$/.test(e.name)) out.push(rel);
  }
  return out;
}

// ponytail: regex extraction, not a JS parser. Upgrade to acorn if the codebase
// grows past a couple of entry files or starts nesting route definitions.
function extract() {
  const nodes = new Map();
  const edges = [];
  const add = (id, type, extra = {}) => {
    if (!nodes.has(id)) nodes.set(id, { id, type, ...extra });
    return id;
  };
  const link = (source, target, kind) => {
    if (source && target && source !== target &&
        !edges.some((e) => e.source === source && e.target === target && e.kind === kind)) {
      edges.push({ source, target, kind });
    }
  };

  const pkg = JSON.parse(read('package.json'));
  const src = read('server.js');
  const SERVER = add('server.js', 'file', { label: 'server.js', loc: src.split('\n').length });

  // dependencies actually required by the server
  for (const dep of Object.keys(pkg.dependencies || {})) {
    if (new RegExp('require\\([\'"]' + esc(dep) + '[\'"]\\)').test(src)) {
      link(SERVER, add(dep, 'dep', { label: dep }), 'requires');
    }
  }

  // data stores: const X_FILE = path.join(DATA_DIR, 'y.json')
  const stores = new Map(); // const name -> node id
  for (const m of src.matchAll(/const (\w+_FILE) = path\.join\(DATA_DIR, '([^']+)'\)/g)) {
    stores.set(m[1], add('data/' + m[2], 'store', { label: m[2] }));
  }

  // top-level functions and routes; each gets the body slice up to the next one
  const decls = [];
  for (const m of src.matchAll(/^(?:async )?function (\w+)\s*\(/gm)) {
    decls.push({ id: add('fn:' + m[1], 'fn', { label: m[1], line: lineOf(src, m.index) }), name: m[1], at: m.index });
  }
  for (const m of src.matchAll(/^app\.(get|post|put|delete)\(\s*(\[[^\]]+\]|'[^']+'|`[^`]+`)/gm)) {
    const method = m[1].toUpperCase();
    for (const p of m[2].matchAll(/['"`]([^'"`]+)['"`]/g)) {
      const label = method + ' ' + p[1];
      decls.push({ id: add(label, 'route', { label, line: lineOf(src, m.index) }), at: m.index });
    }
  }
  decls.sort((a, b) => a.at - b.at);

  const fnNames = decls.filter((d) => d.name).map((d) => d.name);
  decls.forEach((d, i) => {
    link(SERVER, d.id, 'defines');
    const body = src.slice(d.at, i + 1 < decls.length ? decls[i + 1].at : src.length);
    const inner = body.slice(body.indexOf('{')); // skip the declaration's own name
    for (const name of fnNames) {
      if (name !== d.name && new RegExp('\\b' + name + '\\s*\\(').test(inner)) link(d.id, 'fn:' + name, 'calls');
    }
    for (const [constName, store] of stores) {
      if (body.includes('readJSON(' + constName)) link(d.id, store, 'reads');
      if (body.includes('writeJSON(' + constName)) link(d.id, store, 'writes');
    }
    if (/plaidClient\.\w+/.test(body)) link(d.id, add('Plaid API', 'ext', { label: 'Plaid API' }), 'calls');
    if (/anthropic\.|new Anthropic/.test(body)) link(d.id, add('Anthropic API', 'ext', { label: 'Anthropic API' }), 'calls');
  });

  // client pages -> the routes they fetch
  for (const page of walk('public').concat(walk('test'))) {
    const body = read(page);
    const id = add(page, 'file', { label: page.replace(/^public\//, ''), loc: body.split('\n').length });
    for (const m of body.matchAll(/fetch\(\s*['"`](\/api\/[^'"`$?]+)/g)) {
      const route = m[1].replace(/\/$/, '');
      const hit = [...nodes.values()].find((n) => n.type === 'route' && n.id.endsWith(' ' + route));
      if (hit) link(id, hit.id, 'fetches');
    }
    if (/<script[^>]+plaid\.com/.test(body)) link(id, add('Plaid Link', 'ext', { label: 'Plaid Link' }), 'loads');
  }

  return { nodes: [...nodes.values()], edges };
}

if (process.argv.includes('--check')) {
  const assert = require('assert');
  const g = extract();
  const has = (id) => assert.ok(g.nodes.some((n) => n.id === id), 'missing node ' + id);
  const edge = (s, t, k) => assert.ok(g.edges.some((e) => e.source === s && e.target === t && e.kind === k),
    'missing edge ' + s + ' -' + k + '-> ' + t);
  ['server.js', 'plaid', 'GET /api/accounts', 'fn:syncItem', 'data/items.json'].forEach(has);
  edge('server.js', 'plaid', 'requires');
  edge('fn:syncItem', 'Plaid API', 'calls');
  edge('fn:syncItem', 'fn:saveTransactions', 'calls');
  edge('fn:saveTransactions', 'data/transactions.json', 'writes');
  edge('POST /api/sync', 'fn:syncItem', 'calls');
  edge('public/ledger/index.html', 'GET /api/transactions', 'fetches');
  assert.ok(g.nodes.length > 30 && g.edges.length > 50, 'graph looks too small');
  console.log('ok — ' + g.nodes.length + ' nodes, ' + g.edges.length + ' edges');
  process.exit(0);
}

const graph = extract();
fs.writeFileSync(path.join(ROOT, 'graph.html'), read('tools/graph.tpl.html').replace('__DATA__', JSON.stringify(graph)));
console.log('graph.html — ' + graph.nodes.length + ' nodes, ' + graph.edges.length + ' edges');
