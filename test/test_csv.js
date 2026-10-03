// CSV export and import: formula injection, Excel encoding, and the amount
// formats banks actually send. Pulls the real functions out of the Ledger
// page and the server rather than keeping copies here.
const fs = require('fs'), vm = require('vm'), assert = require('assert'), path = require('path');
const read = (f) => fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
const ledger = read('public/ledger/index.html'), server = read('server.js');

const take = (src, startMark, end = '\n}\n') => {
  const i = src.indexOf(startMark);
  if (i < 0) throw new Error('not found: ' + startMark);
  return src.slice(i, src.indexOf(end, i) + end.length);
};

const ctx = {};
vm.createContext(ctx);
vm.runInContext(take(ledger, 'function parseCSV(text)') + take(ledger, 'function csvCell(v)') + take(ledger, 'function toCSV(header, rows)')
  + take(ledger, 'function parseMoney(str)') + take(server, 'const esc = (s) => {', '\n  };\n')
  + ';this.parseCSV=parseCSV;this.csvCell=csvCell;this.toCSV=toCSV;this.parseMoney=parseMoney;this.serverEsc=esc;', ctx);
const { parseCSV, csvCell, toCSV, parseMoney, serverEsc } = ctx;
const ok = (name) => console.log('ok  ' + name);

// Formula injection: anything a spreadsheet would evaluate becomes text.
for (const bad of ['=HYPERLINK("http://x","click")', '+cmd|calc', '-2+3', '@SUM(A1)', '\tx', '-50 refund']) {
  assert.ok(csvCell(bad).replace(/^"/, '').startsWith("'"), 'ledger guards ' + JSON.stringify(bad));
  assert.ok(serverEsc(bad).startsWith(`"'`), 'server guards ' + JSON.stringify(bad));
}
ok('formula-looking cells are made text, on both exports');

for (const num of ['-12.50', '12.50', '0', '-3']) {
  assert.strictEqual(csvCell(num), num);
  assert.strictEqual(serverEsc(num), `"${num}"`);
}
ok('plain numbers, negative ones included, are left as numbers');

assert.strictEqual(csvCell('a,b'), '"a,b"');
assert.strictEqual(csvCell('say "hi"'), '"say ""hi"""');
assert.strictEqual(csvCell('two\nlines'), '"two\nlines"');
ok('commas, quotes and newlines are quoted');

const out = toCSV(['Date', 'Description', 'Amount'], [['2026-10-01', 'Café =1+1', '-4.50'], ['2026-10-02', '=evil()', '12.00']]);
assert.strictEqual(out.charCodeAt(0), 0xfeff, 'starts with a byte-order mark for Excel');
assert.ok(out.includes('\r\n'), 'CRLF line endings');
ok('exports open in Excel as UTF-8');

const back = parseCSV(out);
assert.deepStrictEqual([...back[0]], ['Date', 'Description', 'Amount'], 'BOM stripped on import'); // spread: vm arrays have their own prototype
assert.deepStrictEqual([...back[1]], ['2026-10-01', 'Café =1+1', '-4.50']);
assert.strictEqual(back[2][1], "'=evil()", 'guard survives parsing; the import modal strips it');
ok('exports parse back cleanly');

const cases = { '-12.50': -1250, '+12.00': 1200, '$1,234.56': 123456, '(5.00)': -500, '12.00-': -1200, 'USD 3': 300, 'abc': NaN, '': NaN };
for (const [s, want] of Object.entries(cases)) {
  const got = parseMoney(s);
  assert.ok(Number.isNaN(want) ? Number.isNaN(got) : got === want, `parseMoney(${JSON.stringify(s)}) = ${got}, want ${want}`);
}
ok('amount formats banks send: signs, plus, parentheses, $, thousands');

console.log('\nall CSV checks pass');
