require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const { Configuration, PlaidApi, PlaidEnvironments } = require('plaid');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 8080;
const PLAID_ENV = process.env.PLAID_ENV || 'sandbox';
const COUNTRY_CODES = (process.env.PLAID_COUNTRY_CODES || 'US').split(',');

if (!process.env.PLAID_CLIENT_ID || !process.env.PLAID_SECRET) {
  console.error(
    '\nMissing PLAID_CLIENT_ID / PLAID_SECRET.\n' +
    'Copy .env.example to .env and fill in the keys from https://dashboard.plaid.com/team/keys\n'
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
// Tiny file-backed store.
// This is intentionally simple for a personal, single-user project.
// access_token is as sensitive as a password to your bank account — before
// pointing this at a real (non-sandbox) account, encrypt this file at rest
// or move to a real database/secrets manager.
// ---------------------------------------------------------------------------
const DATA_DIR = path.join(__dirname, 'data');
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

// items: { [item_id]: { accessToken, institutionName, cursor } }
function getItems() { return readJSON(ITEMS_FILE, {}); }
function saveItems(items) { writeJSON(ITEMS_FILE, items); }

// transactions keyed by transaction_id so sync can upsert/delete cleanly
function getTransactions() { return readJSON(TX_FILE, {}); }
function saveTransactions(tx) { writeJSON(TX_FILE, tx); }

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Create a Link token for the frontend to open Plaid Link with.
app.post('/api/create_link_token', async (req, res) => {
  try {
    const request = {
      user: { client_user_id: 'local-user' }, // single-user personal tool
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

// Exchange the public_token Link returns for a durable access_token, then
// run an initial sync so the new account's transactions show up right away.
app.post('/api/exchange_public_token', async (req, res) => {
  try {
    const { public_token, institution_name } = req.body;
    const exchange = await plaidClient.itemPublicTokenExchange({ public_token });
    const { access_token, item_id } = exchange.data;

    const items = getItems();
    items[item_id] = {
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
// paging until has_more is false, then upsert into the local transaction store.
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

    for (const t of data.added) { allTx[t.transaction_id] = t; added++; }
    for (const t of data.modified) { allTx[t.transaction_id] = t; modified++; }
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

// Sync every connected item.
app.post('/api/sync', async (req, res) => {
  try {
    const items = getItems();
    const results = {};
    for (const itemId of Object.keys(items)) {
      results[itemId] = await syncItem(itemId);
    }
    res.json({ ok: true, results });
  } catch (err) {
    console.error('sync error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// List connected institutions.
app.get('/api/items', (req, res) => {
  const items = getItems();
  const list = Object.entries(items).map(([item_id, v]) => ({
    item_id,
    institution_name: v.institutionName,
  }));
  res.json(list);
});

// Return stored transactions, newest first.
app.get('/api/transactions', (req, res) => {
  const tx = Object.values(getTransactions());
  tx.sort((a, b) => (a.date < b.date ? 1 : -1));
  res.json(tx);
});

// CSV export matching what Ledger Vault Cloud's importer expects:
// Date, Description, Amount — with spending as negative numbers.
// Plaid's convention is the opposite (positive = money out), so the sign
// is flipped here.
app.get('/api/export.csv', (req, res) => {
  const tx = Object.values(getTransactions());
  tx.sort((a, b) => (a.date < b.date ? -1 : 1));

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

// Plaid webhook receiver. Plaid calls this when new transaction data is
// ready so you don't have to poll. Point PLAID webhook URL (set at
// link_token creation or in the dashboard) at https://<your-host>/api/webhook.
//
// NOTE: this does not verify the webhook's JWT signature — acceptable for a
// personal sandbox project, but before relying on this against a real
// account, verify signatures per: https://plaid.com/docs/api/webhooks/webhook-verification/
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
