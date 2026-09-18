# Bank Sync (Plaid → Ledger Vault Cloud)

A small self-hosted app that connects live to your banks and cards via Plaid,
then exports transactions as a CSV formatted for Ledger Vault Cloud's
importer. It cannot push data directly into the Ledger Vault Cloud artifact
(Claude artifacts can't receive calls from an outside server) — this app is
the live-sync piece; the CSV import is the bridge.

## 1. Get Plaid API keys (free, instant)

1. Sign up at https://dashboard.plaid.com/signup
2. Once in the dashboard, go to **Team Settings → Keys**. Your `client_id`
   and **Sandbox** `secret` are available immediately — no approval needed.
3. Copy `.env.example` to `.env` and fill in `PLAID_CLIENT_ID` and
   `PLAID_SECRET`. Leave `PLAID_ENV=sandbox` for now.

## 2. Run it locally

```bash
npm install
npm start
```

Open http://localhost:8080, click **Connect a bank or card**, and search for
any institution (e.g. "Chase"). In Sandbox mode, Plaid doesn't touch a real
bank — use these test credentials at the login screen:

```
username: user_good
password: pass_good
```

Click **Sync now** to pull transactions, then **Export CSV** to download a
file with `Date, Description, Amount` columns — spending as negative numbers,
which matches what Ledger Vault Cloud's CSV importer expects (it should
auto-detect the columns; if not, map them manually and set "Spending shows
as: Negative numbers").

## 3. Keeping it current

- **Sync now** re-pulls anytime you click it.
- The `/api/webhook` route lets Plaid notify the server the moment new
  transactions are ready, instead of you remembering to click Sync. Plaid
  needs a public HTTPS URL to call, so this only works once it's deployed
  (step 5) — set that URL as your webhook when you create the Link token, or
  add it under **Team Settings → Webhooks** in the dashboard.
- Either way, getting the latest data into Ledger Vault Cloud is still a
  manual "Export CSV → Import" step, since the artifact can't pull from this
  server on its own.

## 4. Moving beyond Sandbox to your real accounts

Sandbox never touches real banks. To connect your actual accounts:

1. In the Plaid dashboard, apply for **Production** access (Team Settings →
   Keys). Plaid reviews this — for a personal, non-commercial use case it's
   typically a short review, not the older lengthy business approval process.
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
- Add the same variables from `.env` under the project's **Variables** tab.
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

## Security notes (read before connecting a real account)

- `data/items.json` stores your Plaid `access_token` in plaintext on disk.
  That token can read your transaction history — treat the file like a
  password. Fine for local Sandbox testing; before pointing this at a real
  account, encrypt it at rest or move to a proper secrets-capable database.
- `/api/webhook` doesn't verify Plaid's JWT signature, so in principle
  anyone who finds the URL could POST a fake webhook. It only triggers a
  transaction re-sync (no money movement), but for a hardened setup, verify
  signatures per Plaid's docs:
  https://plaid.com/docs/api/webhooks/webhook-verification/
- This app only requests the `transactions` product — it can't move money or
  see full account/routing numbers.
