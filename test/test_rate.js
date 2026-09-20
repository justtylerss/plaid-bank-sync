const fs = require('fs'), vm = require('vm'), assert = require('assert');
const h = fs.readFileSync(require('path').join(__dirname, '..', 'public', 'ledger', 'index.html'), 'utf8');

const take = (startMark) => {
  const i = h.indexOf(startMark);
  if (i < 0) throw new Error('not found: ' + startMark);
  const j = h.indexOf('\n}\n', i);
  return h.slice(i, j + 3);
};

const code = take('function rateStats(months = 6)')
  + take('function taxPosition(y)')
  + take('function monthTotals(mk)')
  + ';this.rateStats=rateStats;this.taxPosition=taxPosition;';

const ctx = {
  curMonth: () => '2026-09',
  addMonths: (mk, n) => { const [y, m] = mk.split('-').map(Number); return new Date(Date.UTC(y, m - 1 + n, 1)).toISOString().slice(0, 7); },
  sum: (a, f) => a.reduce((t, x) => t + f(x), 0),
  deductible: (t) => Math.round(t.amount * ((t.biz && t.biz.pct != null ? t.biz.pct : 100) / 100)),
  tripDeduction: () => 0,
  S: null,
};
vm.createContext(ctx);
vm.runInContext(code, ctx);

const tx = (date, type, amount, biz) => ({ date, type, amount, biz: biz || null });
const fresh = () => { ctx.S = { transactions: [], trips: [], settings: { taxPct: 25 } }; };
const add = (m, inc, exp) => {
  if (inc) ctx.S.transactions.push(tx(m + '-05', 'income', inc));
  if (exp) ctx.S.transactions.push(tx(m + '-06', 'expense', exp));
};

// ---- rateStats ----
fresh(); add('2026-08', 100, 50); add('2026-07', 300, 60); add('2026-06', 200, 40);
let r = ctx.rateStats();
assert.strictEqual(r.enough, true);
assert.strictEqual(r.income, 200, 'odd-count median income');
assert.strictEqual(r.expense, 50, 'odd-count median expense');
assert.strictEqual(r.gap, 150);
console.log('ok  odd median      -> in', r.income, 'out', r.expense, 'gap', r.gap);

add('2026-05', 400, 80);
r = ctx.rateStats();
assert.strictEqual(r.n, 4);
assert.strictEqual(r.income, 250, 'even count averages the middle two (200,300)');
console.log('ok  even median     -> in', r.income, 'from 4 months');

fresh(); add('2026-08', 100, 50); add('2026-07', 100, 50);
assert.strictEqual(ctx.rateStats().enough, false, 'two months is not a rate');
console.log('ok  refuses a rate on 2 months');

fresh(); add('2026-09', 999900, 1); add('2026-08', 100, 50); add('2026-07', 100, 50); add('2026-06', 100, 50);
assert.strictEqual(ctx.rateStats().income, 100, 'current partial month must be excluded');
console.log('ok  excludes current partial month');

fresh(); add('2026-08', 100, 500); add('2026-07', 100, 600); add('2026-06', 100, 400);
r = ctx.rateStats();
assert.strictEqual(r.gap, -400, 'burning more than earning is a negative gap');
console.log('ok  negative gap    ->', r.gap);

// ---- taxPosition ----
fresh();
ctx.S.transactions = [tx('2026-03', 'income', 50000, { b: 'x', pct: 100 }), tx('2026-04', 'expense', 120000, { b: 'x', pct: 100 })];
let t = ctx.taxPosition('2026');
assert.strictEqual(t.net, -70000, 'loss year net');
assert.strictEqual(t.setAside, 0, 'a loss sets nothing aside');
console.log('ok  loss year       -> net', t.net, 'setAside', t.setAside);

ctx.S.transactions = [tx('2026-03', 'income', 200000, { b: 'x', pct: 100 }), tx('2026-04', 'expense', 40000, { b: 'x', pct: 100 })];
t = ctx.taxPosition('2026');
assert.strictEqual(t.net, 160000);
assert.strictEqual(t.setAside, 40000, '25% of 160000');
console.log('ok  profit year     -> net', t.net, 'setAside', t.setAside);

ctx.S.transactions = [tx('2026-04', 'expense', 10000, { b: 'x', pct: 50 }), tx('2025-04', 'expense', 99999, { b: 'x', pct: 100 })];
t = ctx.taxPosition('2026');
assert.strictEqual(t.ded, 5000, 'business-use % applied, other years excluded');
console.log('ok  pct + year gate -> ded', t.ded);

ctx.S.transactions = [tx('2026-04', 'expense', 10000, null), tx('2026-05', 'income', 90000, null)];
t = ctx.taxPosition('2026');
assert.strictEqual(t.net, 0, 'personal rows never touch the business figure');
console.log('ok  personal excluded -> net', t.net);

console.log('\nall rate/tax checks pass');
