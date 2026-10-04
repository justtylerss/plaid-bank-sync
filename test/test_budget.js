// Budget plan: the total caps category budgets, and the plan chart folds
// the smallest categories into "Other" past seven. Runs the real functions
// from the Ledger page.
const fs = require('fs'), vm = require('vm'), assert = require('assert'), path = require('path');
const h = fs.readFileSync(path.join(__dirname, '..', 'public', 'ledger', 'index.html'), 'utf8');
const take = (mark) => { const i = h.indexOf(mark); if (i < 0) throw new Error('not found: ' + mark); return h.slice(i, h.indexOf('\n}\n', i) + 3); };

const ctx = { sum: (arr, fn = (x) => x) => arr.reduce((a, x) => a + (fn(x) || 0), 0) };
vm.createContext(ctx);
vm.runInContext(take('function budgetRoom(') + take('function budgetSegments(') + ';this.budgetRoom=budgetRoom;this.budgetSegments=budgetSegments;', ctx);
const { budgetRoom, budgetSegments } = ctx;
const ok = (name) => console.log('ok  ' + name);
const cat = (name, budget) => ({ name, budget });

const rent = cat('Rent', 150000), food = cat('Food', 50000), fun = cat('Fun', 20000);
const cats = [rent, food, fun];

assert.strictEqual(budgetRoom(0, cats, food), Infinity);
ok('no total means no cap');

assert.strictEqual(budgetRoom(250000, cats, food), 80000, 'total minus the other categories');
assert.strictEqual(budgetRoom(250000, cats, cat('New', 0)), 30000, 'a new category gets what is left');
ok('a category can take the total minus every other category, its own budget aside');

assert.strictEqual(budgetRoom(100000, cats, fun), 0);
ok('when the others already exceed the total, the room is zero, never negative');

const many = Array.from({ length: 9 }, (_, i) => cat('C' + i, (i + 1) * 1000)).concat([cat('Zero', 0)]);
const segs = budgetSegments(many);
assert.strictEqual(segs.length, 7, 'six named plus Other');
assert.deepStrictEqual([...segs.slice(0, 6).map((s) => s.c.name)], ['C8', 'C7', 'C6', 'C5', 'C4', 'C3'], 'biggest first');
assert.strictEqual(segs[6].c, null);
assert.deepStrictEqual([...segs[6].cats.map((c) => c.name)], ['C2', 'C1', 'C0'], 'Other holds the smallest three');
ok('past seven categories the smallest fold into Other, biggest first');

assert.strictEqual(budgetSegments(many.slice(0, 7)).length, 7);
assert.ok(budgetSegments(many.slice(0, 7)).every((s) => s.c), 'seven fit without folding');
assert.ok(!budgetSegments([cat('Zero', 0), rent]).some((s) => s.c && s.c.name === 'Zero'), 'unbudgeted categories are left out');
ok('seven or fewer are all drawn, and unbudgeted categories never are');

console.log('\nall budget checks pass');
