// Card packing: no two cards ever overlap, nothing leaves the 12 columns,
// a lone card widens to fill its row, and short cards stack beside tall
// ones. Runs the real packGrid from the Ledger page against fake cards.
const fs = require('fs'), vm = require('vm'), assert = require('assert'), path = require('path');
const h = fs.readFileSync(path.join(__dirname, '..', 'public', 'ledger', 'index.html'), 'utf8');
const take = (mark, end = '\n}\n') => { const i = h.indexOf(mark); if (i < 0) throw new Error('not found: ' + mark); return h.slice(i, h.indexOf(end, i) + end.length); };

const ctx = {
  packSeen: new Set(),
  packWatch: { observe() {} },
  getComputedStyle: (el) => el._cs(),
};
vm.createContext(ctx);
vm.runInContext('const PACK_UNIT = 4;' + take('function packGrid(g)') + ';this.packGrid = packGrid;', ctx);

const UNIT = 4, GAP = 24;
const card = (span, height) => ({
  hidden: false, style: {}, span, height,
  get offsetHeight() { return Math.max(this.height, parseFloat(this.style.minHeight) || 0); },
  _cs() { return { gridColumnStart: 'span ' + this.span, gridColumnEnd: 'auto' }; },
});
function pack(cards) {
  const cls = new Set();
  const g = { children: cards, classList: { add: (c) => cls.add(c), remove: (c) => cls.delete(c) },
    _cs: () => ({ gridTemplateColumns: Array(12).fill('10px').join(' '), columnGap: GAP + 'px' }) };
  ctx.packGrid(g);
  if (!cls.has('packed')) return null;
  return cards.map((c) => {
    const [x, s] = c.style.gridColumn.split(' / span ').map(Number);
    const [y, r] = c.style.gridRow.split(' / span ').map(Number);
    return { x: x - 1, s, y: y - 1, r, c };
  });
}
function checkSound(p, label) {
  for (const a of p) {
    assert.ok(a.x >= 0 && a.x + a.s <= 12, `${label}: card leaves the grid`);
    assert.ok(a.r * UNIT >= a.c.height, `${label}: card area shorter than the card`);
  }
  for (let i = 0; i < p.length; i++) for (let j = i + 1; j < p.length; j++) {
    const a = p[i], b = p[j];
    const overlap = a.x < b.x + b.s && b.x < a.x + a.s && a.y < b.y + b.r && b.y < a.y + a.r;
    assert.ok(!overlap, `${label}: cards ${i} and ${j} overlap`);
  }
}
// Every column ends at the same line: no hole beside or beneath anything.
function checkFull(p, label) {
  const ends = Array.from({ length: 12 }, (_, col) => Math.max(...p.filter((a) => col >= a.x && col < a.x + a.s).map((a) => a.y + a.r)));
  assert.ok(ends.every((e) => e === ends[0]), `${label}: columns end unevenly ${ends}`);
}
const ok = (name) => console.log('ok  ' + name);

assert.strictEqual(pack([card(12, 300), card(12, 200)]), null);
ok('a grid of full-width cards is left alone');

let p = pack([card(12, 400), card(7, 360)]);
checkSound(p, 'lone'); assert.strictEqual(p[1].s, 12, 'a lone 7-wide card widens to 12');
ok('a card alone on its row widens to fill it');

p = pack([card(6, 800), card(6, 200), card(6, 260)]);
checkSound(p, 'stack'); checkFull(p, 'stack');
assert.ok(p[2].x === p[1].x && p[2].y > p[1].y, 'the third card stacks under the short one');
ok('a short card gets the next card stacked under it, beside the tall one');

p = pack([card(4, 800), card(6, 200)]);
checkSound(p, 'pair'); checkFull(p, 'pair'); assert.strictEqual(p[1].s, 8, 'the second card widens into the leftover 2 columns');
ok('leftover columns no card could use are taken by the neighbour');

p = pack([card(6, 372), card(7, 360), card(8, 370), card(7, 360), card(5, 312), card(4, 190)]);
checkSound(p, 'dashboard'); checkFull(p, 'dashboard');
ok('the dashboard\'s This month band packs with no holes');

let seed = 7;
const rnd = (n) => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % n; };
const spans = [3, 4, 5, 6, 7, 8, 12];
for (let t = 0; t < 500; t++) {
  const cards = Array.from({ length: 2 + rnd(9) }, () => card(spans[rnd(spans.length)], 80 + rnd(900)));
  const res = pack(cards);
  if (res) checkSound(res, 'random layout ' + t);
}
ok('500 random layouts: no overlaps, nothing outside the grid');

console.log('\nall packing checks pass');
