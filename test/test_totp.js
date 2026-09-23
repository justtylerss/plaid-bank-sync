/* TOTP checked against the test vectors published in RFC 6238, Appendix B.
   Rolling your own crypto is only acceptable when you verify it against the
   spec's own numbers rather than against itself. */
const fs = require('fs'), vm = require('vm'), crypto = require('crypto'), assert = require('assert');
const path = require('path');

const src = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const take = (mark, endMark) => {
  const i = src.indexOf(mark);
  if (i < 0) throw new Error('not found: ' + mark);
  const j = src.indexOf(endMark, i);
  if (j < 0) throw new Error('end not found after: ' + mark);
  return src.slice(i, j);
};

const code = take("const B32_ALPHABET", "/* Recovery codes exist")
  + take("function makeRecoveryCodes", "/* Five wrong codes")
  + ';this.b32encode=b32encode;this.b32decode=b32decode;this.hotp=hotp;this.totpCheck=totpCheck;this.otpauthURI=otpauthURI;this.makeRecoveryCodes=makeRecoveryCodes;';

const ctx = { crypto, Buffer, BigInt, String, Math, encodeURIComponent };
vm.createContext(ctx);
vm.runInContext(code, ctx);

// ---- base32 round trip ----
for (const s of ['', 'a', 'ab', 'abc', 'abcd', 'abcde', 'hello world', '12345678901234567890']) {
  const enc = ctx.b32encode(Buffer.from(s));
  assert.strictEqual(ctx.b32decode(enc).toString(), s, 'round trip: ' + JSON.stringify(s));
}
console.log('ok  base32 round-trips at every length offset');

// RFC 4648 known answers
assert.strictEqual(ctx.b32encode(Buffer.from('foobar')), 'MZXW6YTBOI');
assert.strictEqual(ctx.b32decode('MZXW6YTBOI').toString(), 'foobar');
console.log('ok  base32 matches RFC 4648 vector (foobar -> MZXW6YTBOI)');

// ---- RFC 6238 Appendix B, SHA-1 column ----
// Shared secret is the ASCII string "12345678901234567890".
const SECRET = ctx.b32encode(Buffer.from('12345678901234567890'));
const VECTORS = [
  [59,          '94287082'],
  [1111111109,  '07081804'],
  [1111111111,  '14050471'],
  [1234567890,  '89005924'],
  [2000000000,  '69279037'],
  [20000000000, '65353130'],
];
for (const [t, expected8] of VECTORS) {
  const counter = Math.floor(t / 30);
  const got6 = ctx.hotp(ctx.b32decode(SECRET), counter);
  assert.strictEqual(got6, expected8.slice(-6),
    `RFC 6238 t=${t}: expected ...${expected8.slice(-6)}, got ${got6}`);
}
console.log('ok  matches all six RFC 6238 SHA-1 test vectors');

// ---- totpCheck behaviour ----
const at = 1111111109 * 1000;
const cur = ctx.hotp(ctx.b32decode(SECRET), Math.floor(at / 1000 / 30));
assert.strictEqual(ctx.totpCheck(SECRET, cur, at), true, 'current code accepted');
console.log('ok  accepts the current code');

assert.strictEqual(ctx.totpCheck(SECRET, cur, at + 30000), true, 'one step late still accepted (drift)');
assert.strictEqual(ctx.totpCheck(SECRET, cur, at - 30000), true, 'one step early still accepted (drift)');
console.log('ok  tolerates one step of clock drift either way');

assert.strictEqual(ctx.totpCheck(SECRET, cur, at + 120000), false, 'four steps late rejected');
console.log('ok  rejects a code four steps stale');

assert.strictEqual(ctx.totpCheck(SECRET, '000000', at), false);
assert.strictEqual(ctx.totpCheck(SECRET, '', at), false);
assert.strictEqual(ctx.totpCheck(SECRET, null, at), false);
assert.strictEqual(ctx.totpCheck(SECRET, '12345', at), false, 'five digits rejected, not padded');
assert.strictEqual(ctx.totpCheck(SECRET, '1234567', at), false, 'seven digits rejected, not truncated');
assert.strictEqual(ctx.totpCheck('', cur, at), false, 'empty secret never validates');
console.log('ok  rejects wrong, empty, short, long codes and an empty secret');

// a code for a different secret must not validate
const other = ctx.b32encode(crypto.randomBytes(20));
assert.strictEqual(ctx.totpCheck(other, cur, at), false, 'code from another secret rejected');
console.log('ok  rejects a code minted from a different secret');

// ---- otpauth URI ----
const uri = ctx.otpauthURI('a@b.test', SECRET);
assert.ok(uri.startsWith('otpauth://totp/'), 'scheme');
assert.ok(uri.includes('secret=' + SECRET), 'carries the secret');
assert.ok(uri.includes('period=30') && uri.includes('digits=6') && uri.includes('algorithm=SHA1'), 'parameters');
assert.ok(uri.includes('a%40b.test'), 'label is escaped');
console.log('ok  otpauth URI is well formed and escaped');

// ---- recovery codes ----
const codes = ctx.makeRecoveryCodes();
assert.strictEqual(codes.length, 8);
assert.strictEqual(new Set(codes).size, 8, 'no duplicates');
for (const c of codes) assert.ok(/^[0-9a-f]{5}-[0-9a-f]{5}$/.test(c), 'shape: ' + c);
const again = ctx.makeRecoveryCodes();
assert.strictEqual(codes.filter((c) => again.includes(c)).length, 0, 'two draws do not overlap');
console.log('ok  recovery codes: 8, unique, well shaped, not repeatable');

console.log('\nall TOTP checks pass');
