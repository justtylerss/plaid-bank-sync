# Bank Sync + Ledger Vault Cloud (self-hosted)

A small self-hosted app with two pages sharing one login:

- **Bank Sync** (`/`) — connects live to your banks and cards via Plaid.
- **Ledger Vault Cloud** (`/ledger/`) — the full budgeting/books app (categories,
  budgets, business write-offs, net worth, recurring bills — everything from
  the original), ported to run on this same server instead of a Claude
  artifact.

They're wired together directly: on the Ledger page's Import screen, **Import
from connected banks** pulls straight from whatever Bank Sync has synced —
no CSV file, no manual download/upload step. (CSV/OFX import is still there
too, for statements from banks you haven't connected via Plaid.)

Each person who uses it creates their own account (email + password). Every
connected bank, every transaction, and every ledger doc (categories, budgets,
transactions, everything) is tagged with the account that created it — what
you connect and what a friend connects never mix, on either page.

**What didn't come over from the Claude-hosted version:** AI receipt
scanning, "ask about your money" chat, and photo storage for receipts. Those
relied on Claude-specific capabilities (`sample`, `assets`) that don't exist
outside an artifact. Everything else — the entire finance-tracking engine —
is untouched. Those buttons show up disabled with a note explaining why,
rather than erroring.

**Design:** Bank Sync and the login page now share Ledger Vault Cloud's
actual design system (same Geist/Onest type, same color tokens, same pill
buttons, same dark mode) instead of a generic default — one visual product
across all three pages, not three different-looking apps bolted together.
Bank Sync also shows real account balances and masked account numbers
(pulled from the same data Plaid already sends on every sync — nothing
extra to request), a net balance figure (assets minus what's owed on credit
accounts, not just everything added together), and transactions grouped by
day the way an actual banking app shows them.

**Auto-categorization:** every sync now requests Plaid's real transaction
categories (the personal_finance_category taxonomy) and the Ledger import
maps them onto your own category list — groceries, gas, streaming
subscriptions, payroll, etc. land pre-categorized instead of defaulting to
"Other." Credit card payments and account transfers are correctly tagged as
transfers rather than miscategorized as spending.

**Duplicate handling:** each connected bank shows its connection date, so
accidentally-duplicated connections (e.g. linking the same bank twice) are
easy to tell apart, and each has its own **Disconnect** button — it revokes
the access token with Plaid and removes that connection's accounts and
transactions. On the Ledger side, a **Find duplicates** button in the inbox
surfaces anything that looks like a repeat (whether it duplicates another
inbox item or something you already approved) for one-click cleanup.

**Higher timeframes:** the Dashboard's Cash flow chart now has a 3M / 6M /
1Y / 2Y range toggle (previously fixed at 6 months), and Spending pace can
compare Month / Quarter / Year, not just the current month against last
month. Both choices are remembered across visits.

## 1. Get Plaid API keys (free, instant)

1. Sign up at https://dashboard.plaid.com/signup
2. Once in the dashboard, go to **Developers → Keys**
   (https://dashboard.plaid.com/developers/keys). Your `client_id` and
   **Sandbox** `secret` are available immediately — no approval needed.
3. Copy `.env.example` to `.env` and fill in `PLAID_CLIENT_ID` and
   `PLAID_SECRET`. Leave `PLAID_ENV=sandbox` for now.
4. Generate a session secret (signs login cookies) and add it as
   `SESSION_SECRET` in `.env`:
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

## 2. Run it locally

```bash
npm install
npm start
```

Open http://localhost:8080 — you'll land on a sign-in page first. Click
**Sign up**, create an account with any email/password (nothing is emailed;
it's just your login for this app), and you'll be dropped into the Bank Sync
page. Each person testing this (you, a friend) makes their own account here.

Click **Connect a bank or card**, and search for any institution (e.g.
"Chase"). In Sandbox mode, Plaid doesn't touch a real bank — use these test
credentials at the login screen:

```
username: user_good
password: pass_good
```

Click **Sync now** to pull transactions. Then open **Ledger Vault Cloud**
(the link in the top bar, or http://localhost:8080/ledger/ directly — same
login, no separate sign-in) → **Import & inbox** → **Import from connected
banks**. That pulls the transactions you just synced straight into your
inbox for categorizing, no file involved. (Export CSV on the Bank Sync page
still works too, for opening the raw data elsewhere.)

## 3. Keeping it current

- **Sync now** on the Bank Sync page re-pulls anytime you click it.
- The `/api/webhook` route lets Plaid notify the server the moment new
  transactions are ready, instead of you remembering to click Sync. Plaid
  needs a public HTTPS URL to call, so this only works once it's deployed
  (step 5) — set that URL as your webhook when you create the Link token, or
  add it under **Team Settings → Webhooks** in the dashboard.
- Either way, getting synced transactions *into your books* is one click:
  **Import from connected banks** on the Ledger page's Import screen. It's
  not automatic on its own — click it after a sync when you want fresh data
  in your inbox — but there's no file to move by hand anymore.

## 4. Moving beyond Sandbox to your real accounts

Sandbox never touches real banks. To connect your actual accounts:

1. In the Plaid dashboard, click **Migrate to Production** and fill out the
   application. Plaid reviews this — for a personal, non-commercial use case
   it's typically a short review, not the older lengthy business approval
   process.
2. Once approved, set `PLAID_ENV=production` and swap in your Production
   `secret` in `.env`.
3. Production API calls aren't free forever — Plaid's pricing has a limited
   free tier of connected accounts (Items) before it starts billing. Check
   current pricing at https://plaid.com/pricing/ before connecting more than
   a couple of accounts.

## 5. Hosting it

This app needs a long-running Node process (for the webhook route and
in-memory-ish sync loop) rather than one-off serverless functions, so:

**Recommended: Railway** (https://railway.app)
- Push this folder to a GitHub repo.
- In Railway: New Project → Deploy from GitHub repo.
- Add the same variables from `.env` under the project's **Variables** tab —
  `PLAID_CLIENT_ID`, `PLAID_SECRET`, `PLAID_ENV`, and `SESSION_SECRET` at
  minimum (use a freshly generated `SESSION_SECRET`, not the same one you
  use locally).
- Railway gives you a public `*.up.railway.app` HTTPS URL automatically —
  that's what you'd register as your Plaid redirect URI / webhook URL.
- Free tier is enough for a personal single-user tool like this.

**Also fine: Render** (https://render.com) — same idea, a "Web Service" from
a GitHub repo, env vars in the dashboard, free HTTPS URL included.

**Not recommended for this: Vercel** — built around short-lived serverless
functions, so persistent webhook listening and the simple file-based store
here don't fit its model without extra rework (you'd want a real database and
to restructure the sync as on-demand functions).

Once deployed, update `PLAID_REDIRECT_URI` in `.env`/Railway variables to
your live URL if you plan to test OAuth institutions (Chase, Wells Fargo,
etc. — they require it), and register that same URI in the Plaid dashboard
under **Team Settings → API → Allowed redirect URIs**.

## 6. Persistent storage (do this before real accounts sign up)

Accounts, password hashes, connected banks, Plaid transactions, and every
Ledger Vault Cloud doc (categories, budgets, business write-offs, net worth
— your whole ledger) all live in `data/*.json` and `data/ledger/<user>/*.json`
on disk. Most container hosts — Railway included — wipe local disk on every
redeploy. That's low-stakes while you're the only Sandbox user; it stops
being low-stakes the moment a real signup, a real bank connection, or real
ledger data depends on those files surviving.

On Railway: close any open settings panel so you can see the project
canvas, then **right-click your service's box** on the canvas (or press
**Ctrl/Cmd+K** and search "volume") → attach it to your service → set the
**Mount Path** to `/app/data`. If your build path differs, set the
`DATA_DIR` variable (also in `.env.example`) to wherever the volume ends up
mounted — `server.js` already reads it. Render has the equivalent under
**Disks**.

## Security notes (read before connecting a real account)

- Passwords are hashed with bcrypt before being stored — never saved in
  plain text. Logins are a signed JWT in an `httpOnly` cookie, valid 30 days.
- Logging out clears the cookie from your browser, but the token itself
  isn't individually revoked server-side (there's no session blacklist).
  Practically: it only matters if someone else captured that exact cookie
  value before you logged out, which isn't a realistic risk for a
  self-hosted personal tool — just know "log out" means "this browser no
  longer has it," not "that token is invalid everywhere."
- Sign-up is open to anyone who reaches the URL — there's no invite code or
  admin approval. Fine for "you + a friend you sent the link to"; if this
  ever gets a wider audience, add an allow-list check in `/api/auth/signup`.
- `data/items.json` stores your Plaid `access_token` in plaintext on disk.
  That token can read your transaction history — treat the file like a
  password. Fine for local Sandbox testing; before pointing this at a real
  account, encrypt it at rest or move to a proper secrets-capable database.
- Same goes for `data/ledger/<userId>/*.json` — your categories, budgets,
  business write-offs, and net worth all sit there as plain JSON, one folder
  per user. Every read/write route checks the session and only ever touches
  that user's own folder (tested — two accounts can't see each other's
  data), but the files themselves aren't encrypted on disk.
- `/api/webhook` doesn't verify Plaid's JWT signature, so in principle
  anyone who finds the URL could POST a fake webhook. It only triggers a
  transaction re-sync (no money movement), but for a hardened setup, verify
  signatures per Plaid's docs:
  https://plaid.com/docs/api/webhooks/webhook-verification/
- This app only requests the `transactions` product — it can't move money or
  see full account/routing numbers.
