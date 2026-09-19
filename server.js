require('dotenv').config();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Configuration, PlaidApi, PlaidEnvironments } = require('plaid');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 8080;
const PLAID_ENV = process.env.PLAID_ENV || 'sandbox';
const COUNTRY_CODES = (process.env.PLAID_COUNTRY_CODES || 'US').split(',');
const COOKIE_NAME = 'session';
const SESSION_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

if (!process.env.PLAID_CLIENT_ID || !process.env.PLAID_SECRET) {
  console.error(
    '\nMissing PLAID_CLIENT_ID / PLAID_SECRET.\n' +
    'Copy .env.example to .env and fill in the keys from https://dashboard.plaid.com/developers/keys\n'
  );
  process.exit(1);
}
if (!process.env.SESSION_SECRET) {
  console.error(
    '\nMissing SESSION_SECRET.\n' +
    'Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"\n' +
    'and add it to .env as SESSION_SECRET=...\n'
  );
  process.exit(1);
}

const plaidClient = new PlaidApi(
  new Configuration({
    basePath: PlaidEnvironments[PLAID_ENV],
    baseOptions: {
      headers: {
        'PLAID-CLIENT-ID': process.env.PLAID_CLIENT_ID,
        'PLAID-SECRET': process.env.PLAID_SECRET,
      },
    },
  })
);

// ---------------------------------------------------------------------------
// Tiny file-backed store, now holding real credentials (password hashes) and
// real bank access tokens once you're past Sandbox. Two things matter:
//  1. DATA_DIR should point at a persistent volume in production — plain
//     container storage on most hosts (Railway included) is wiped on
//     redeploy. See README "Persistent storage" section.
//  2. access_token and passwordHash are both as sensitive as a password.
//     Fine on disk for a small personal project; encrypt at rest before
//     this ever holds more than a couple of trusted users' real data.
// ---------------------------------------------------------------------------
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const ITEMS_FILE = path.join(DATA_DIR, 'items.json');
const TX_FILE = path.join(DATA_DIR, 'transactions.json');

function readJSON(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return fallback;
  }
}
function writeJSON(file, data) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// users: { [userId]: { id, email, passwordHash, name, createdAt } }
function getUsers() { return readJSON(USERS_FILE, {}); }
function saveUsers(users) { writeJSON(USERS_FILE, users); }
function findUserByEmail(email) {
  const users = getUsers();
  const needle = String(email || '').trim().toLowerCase();
  return Object.values(users).find((u) => u.email.toLowerCase() === needle) || null;
}

// items: { [item_id]: { userId, accessToken, institutionName, cursor } }
function getItems() { return readJSON(ITEMS_FILE, {}); }
function saveItems(items) { writeJSON(ITEMS_FILE, items); }
function getItemsForUser(userId) {
  const items = getItems();
  return Object.entries(items).filter(([, v]) => v.userId === userId);
}

// transactions keyed by transaction_id, each tagged with the owning userId
// so listing/export/sync can filter without a real database.
function getTransactions() { return readJSON(TX_FILE, {}); }
function saveTransactions(tx) { writeJSON(TX_FILE, tx); }

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------
function signSession(userId) {
  return jwt.sign({ sub: userId }, process.env.SESSION_SECRET, { expiresIn: '30d' });
}
function setSessionCookie(req, res, userId) {
  res.cookie(COOKIE_NAME, signSession(userId), {
    httpOnly: true,
    sameSite: 'lax',
    secure: req.secure || req.headers['x-forwarded-proto'] === 'https',
    maxAge: SESSION_MAX_AGE_MS,
  });
}
function requireAuth(req, res, next) {
  const token = req.cookies && req.cookies[COOKIE_NAME];
  if (!token) return res.status(401).json({ error: 'not_authenticated' });
  try {
    const payload = jwt.verify(token, process.env.SESSION_SECRET);
    req.userId = payload.sub;
    next();
  } catch (e) {
    res.status(401).json({ error: 'not_authenticated' });
  }
}
function publicUser(u) {
  return { id: u.id, email: u.email, name: u.name || null };
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
const app = express();
app.set('trust proxy', 1); // so req.secure is correct behind Railway's proxy
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ---- Auth routes -----------------------------------------------------------

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body || {};
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ error: 'Enter a valid email.' });
    }
    if (!password || password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }
    if (findUserByEmail(email)) {
      return res.status(409).json({ error: 'An account with that email already exists.' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const id = crypto.randomUUID();
    const user = { id, email: email.trim(), passwordHash, name: name || null, createdAt: new Date().toISOString() };
    const users = getUsers();
    users[id] = user;
    saveUsers(users);

    setSessionCookie(req, res, id);
    res.json({ ok: true, user: publicUser(user) });
  } catch (err) {
    console.error('signup error:', err);
    res.status(500).json({ error: 'Could not create account.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = findUserByEmail(email);
    const ok = user && (await bcrypt.compare(password || '', user.passwordHash));
    if (!ok) return res.status(401).json({ error: 'Incorrect email or password.' });

    setSessionCookie(req, res, user.id);
    res.json({ ok: true, user: publicUser(user) });
  } catch (err) {
    console.error('login error:', err);
    res.status(500).json({ error: 'Could not log in.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const users = getUsers();
  const user = users[req.userId];
  if (!user) return res.status(401).json({ error: 'not_authenticated' });
  res.json({ user: publicUser(user) });
});

// ---- Everything below here belongs to the signed-in user only -------------

// Create a Link token for the frontend to open Plaid Link with.
app.post('/api/create_link_token', requireAuth, async (req, res) => {
  try {
    const request = {
      user: { client_user_id: req.userId },
      client_name: 'Ledger Vault Sync',
      products: ['transactions'],
      country_codes: COUNTRY_CODES,
      language: 'en',
    };
    if (process.env.PLAID_REDIRECT_URI) {
      request.redirect_uri = process.env.PLAID_REDIRECT_URI;
    }
    const response = await plaidClient.linkTokenCreate(request);
    res.json({ link_token: response.data.link_token });
  } catch (err) {
    console.error('create_link_token error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// Exchange the public_token Link returns for a durable access_token, tied to
// this user, then run an initial sync so the new account shows up right away.
app.post('/api/exchange_public_token', requireAuth, async (req, res) => {
  try {
    const { public_token, institution_name } = req.body;
    const exchange = await plaidClient.itemPublicTokenExchange({ public_token });
    const { access_token, item_id } = exchange.data;

    const items = getItems();
    items[item_id] = {
      userId: req.userId,
      accessToken: access_token,
      institutionName: institution_name || 'Connected account',
      cursor: null,
    };
    saveItems(items);

    const result = await syncItem(item_id);
    res.json({ ok: true, item_id, synced: result });
  } catch (err) {
    console.error('exchange_public_token error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// Pull the latest changes for one item using the cursor-based sync endpoint,
// paging until has_more is false, then upsert into the local transaction
// store — each transaction tagged with the item's owning userId.
async function syncItem(itemId) {
  const items = getItems();
  const item = items[itemId];
  if (!item) throw new Error(`Unknown item_id: ${itemId}`);

  let cursor = item.cursor || undefined;
  let added = 0, modified = 0, removed = 0, hasMore = true;
  const allTx = getTransactions();

  while (hasMore) {
    const response = await plaidClient.transactionsSync({
      access_token: item.accessToken,
      cursor,
    });
    const data = response.data;

    for (const t of data.added) { allTx[t.transaction_id] = { ...t, userId: item.userId }; added++; }
    for (const t of data.modified) { allTx[t.transaction_id] = { ...t, userId: item.userId }; modified++; }
    for (const t of data.removed) { delete allTx[t.transaction_id]; removed++; }

    cursor = data.next_cursor;
    hasMore = data.has_more;
  }

  item.cursor = cursor;
  items[itemId] = item;
  saveItems(items);
  saveTransactions(allTx);

  return { added, modified, removed };
}

// Sync every item belonging to the signed-in user.
app.post('/api/sync', requireAuth, async (req, res) => {
  try {
    const mine = getItemsForUser(req.userId);
    const results = {};
    for (const [itemId] of mine) {
      results[itemId] = await syncItem(itemId);
    }
    res.json({ ok: true, results });
  } catch (err) {
    console.error('sync error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// List institutions connected by the signed-in user.
app.get('/api/items', requireAuth, (req, res) => {
  const list = getItemsForUser(req.userId).map(([item_id, v]) => ({
    item_id,
    institution_name: v.institutionName,
  }));
  res.json(list);
});

// Return the signed-in user's transactions, newest first.
app.get('/api/transactions', requireAuth, (req, res) => {
  const tx = Object.values(getTransactions()).filter((t) => t.userId === req.userId);
  tx.sort((a, b) => (a.date < b.date ? 1 : -1));
  res.json(tx);
});

// CSV export matching what Ledger Vault Cloud's importer expects:
// Date, Description, Amount — with spending as negative numbers.
// Plaid's convention is the opposite (positive = money out), so the sign
// is flipped here. Scoped to the signed-in user only.
app.get('/api/export.csv', requireAuth, (req, res) => {
  const tx = Object.values(getTransactions())
    .filter((t) => t.userId === req.userId)
    .sort((a, b) => (a.date < b.date ? -1 : 1));

  const esc = (s) => `"${String(s ?? '').replace(/"/g, '""')}"`;
  const rows = [['Date', 'Description', 'Amount']];
  for (const t of tx) {
    if (t.pending) continue; // wait for it to post before exporting
    const amount = (-t.amount).toFixed(2); // flip Plaid's sign convention
    rows.push([t.date, t.merchant_name || t.name, amount]);
  }
  const csv = rows.map((r) => r.map(esc).join(',')).join('\n');

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="bank-transactions.csv"');
  res.send(csv);
});

// Plaid webhook receiver — called by Plaid, not by a signed-in browser, so
// this route intentionally has no requireAuth. It looks up which user the
// item belongs to internally via the items store.
//
// NOTE: this does not verify the webhook's JWT signature — acceptable for a
// personal sandbox project, but before relying on this against real
// accounts, verify signatures per: https://plaid.com/docs/api/webhooks/webhook-verification/
app.post('/api/webhook', async (req, res) => {
  const { webhook_type, webhook_code, item_id } = req.body || {};
  console.log('Webhook received:', webhook_type, webhook_code, item_id);
  try {
    if (webhook_type === 'TRANSACTIONS' && webhook_code === 'SYNC_UPDATES_AVAILABLE' && item_id) {
      const items = getItems();
      if (items[item_id]) await syncItem(item_id);
    }
  } catch (err) {
    console.error('webhook sync error:', err.response?.data || err.message);
  }
  res.sendStatus(200); // ack quickly regardless; Plaid retries on non-2xx
});

app.listen(PORT, () => {
  console.log(`Plaid bank sync running at http://localhost:${PORT} (env: ${PLAID_ENV})`);
});
