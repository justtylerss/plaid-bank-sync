# Information security policy

Ledger Vault Cloud / Plaid Bank Sync — a private, two-user personal finance
application. It holds bank transaction history, account balances, and Plaid
credentials for the people who own the accounts.

This document records what is protected, how, what is deliberately not done,
and the procedures that keep it that way. It describes the system as it
actually is. Where a control is absent it says so rather than describing an
intention.

**Owner:** Tyler Le — responsible for all security decisions, changes and
incident response.
**Last reviewed:** 19 September 2026

---

## 1. What is at risk

| Asset | Where it lives | Why it matters |
|---|---|---|
| Plaid `access_token` per linked bank | `data/items.json` on the Railway volume | Does not expire. Grants ongoing read access to the bank connection. **Highest value asset in the system.** |
| Transaction history, balances | `data/transactions.json`, `data/accounts.json`, `data/ledger/<user>/` | Complete financial picture of the account owner |
| Password hashes | `data/users.json` | bcrypt; not reversible, but still credential material |
| `SESSION_SECRET` | Railway environment variable | Signs sessions **and** derives the token encryption key. Compromise means both forged sessions and readable bank credentials |
| `PLAID_SECRET`, `ANTHROPIC_API_KEY` | Railway environment variables | Billable API access |

The realistic threats are: someone obtaining a copy of the data directory, a
stolen or forged session, and credential leakage through the repository or
logs. The application is not a target of sophisticated attack; it is a target
of carelessness.

---

## 2. Controls in place

**Authentication.** Email and password. Passwords hashed with bcrypt at cost
10 and never stored or logged in recoverable form. There is no password reset
flow, which also means no reset flow to abuse.

**Sessions.** Signed JWT in a cookie: `httpOnly` (not readable from
JavaScript), `sameSite=lax` (not sent on cross-site requests), and `secure`
whenever the connection is HTTPS. Thirty-day expiry.

**Authorisation.** Every API route that touches data requires an authenticated
session and filters by that user's id. One user cannot read or modify
another's records. There are no roles or privilege tiers — this is per-user
isolation, not RBAC, and should not be described as RBAC.

**Bank credentials at rest.** Plaid access tokens are encrypted with
AES-256-GCM before being written. The key is derived from `SESSION_SECRET`
using HKDF with a distinct info string, so the signing key and the encryption
key are different keys from the same secret. GCM is authenticated: a modified
file fails to decrypt rather than returning wrong data.

**Transport.** HTTPS, terminated by Railway. No plaintext listener is exposed.

**Administrative access.** The systems that hold the data — Railway (the app
and its volume) and GitHub (the source, and the sign-in identity for Railway)
— both require an authenticator-app code on top of a password. Recovery codes
are stored separately. SMS was removed as a factor on GitHub: it was the
weakest enrolled method, and the weakest enrolled method is what an attacker
uses. TOTP is not phishing-resistant; a convincing fake login page can still
relay a code.

**Dependencies.** Dependabot is configured for weekly npm checks
(`.github/dependabot.yml`) and raises a pull request when a dependency has a
known vulnerability. Every dependency is version-pinned and a lockfile is
committed, so a deploy installs what was reviewed rather than whatever is
newest.

**End-of-life software.** Dependabot flags vulnerable versions, not
unsupported ones, so the runtime is tracked by hand. `engines.node` is held at
a release line still receiving security updates and is reviewed when this
document is reviewed. It previously read `>=18`, which permitted a Node major
that had already reached end of life.

**Patching.** Critical and high severity findings are applied within seven
days. Everything else lands with the next change. This is an SLA one person
can actually keep, which is the only kind worth writing down.

**Secrets.** Held in environment variables, never in the repository. `.env` is
gitignored and has been verified as untracked. No secret is written to logs.

**Outbound requests.** The link-preview endpoint resolves each host and refuses
private, loopback, link-local and cloud-metadata addresses, re-checks every
redirect hop, and caps reads at 6 seconds and 512 KB. This prevents the server
being used to reach internal services.

**Third-party data.** Bank data is read-only. The application cannot move
money. Plaid is the only route to the banks; no bank credentials ever reach
this application.

---

## 3. What is deliberately not done

Stated plainly so that no one relies on a control that does not exist.

- **No multi-factor authentication for end users of the app itself.** Two known
  users, both the owner’s own accounts. Accepted risk. This is separate from
  administrative MFA on Railway and GitHub, which is in place (section 2).
- **No encryption of bulk transaction data at rest** beyond whatever the
  hosting volume provides. Only the Plaid tokens are encrypted by the
  application.
- **No audit logging.** Access is not recorded, so unauthorised access would
  not leave a trail in the application.
- **No runtime monitoring or alerting.** Dependency scanning exists (section
  2); nothing watches the running application.
- **No formal access review**, because there are exactly two accounts and one
  administrator.
- **No penetration testing or third-party assessment.**

---

## 4. Retention and deletion

Data is kept while the connection or the account that produced it exists, and
not beyond it.

| What | Kept until | Deleted by |
|---|---|---|
| Transactions, balances, account details | The bank connection is removed | Disconnecting that bank |
| Plaid `access_token` | The bank connection is removed | Disconnecting that bank, which also revokes it at Plaid |
| Everything belonging to a user | The account is removed | Deleting the account |
| Imported files | Not retained | Read once for their transactions, then discarded |

There is no archive of deleted records and nothing is kept back for later
analysis. Copies may survive briefly in the hosting provider’s own
infrastructure backups, which are outside this application’s control and
expire on their schedule.

The user-facing statement of this is `public/privacy.html`, served at
`/privacy` without authentication — a privacy policy you have to log in to
read is not one.

Reviewed annually, with the rest of this document.

---

## 5. Procedures

**Adding a user.** Self-service sign-up exists. Because the application is
private, the owner is expected to know every account that exists. Unrecognised
accounts should be removed directly from `data/users.json`.

**Rotating `SESSION_SECRET`.** Rotating it invalidates all sessions *and*
makes stored Plaid tokens permanently unreadable, because the encryption key
is derived from it. Every bank must then be disconnected and relinked. Keep a
backup of the current value; do not rotate casually.

**Rotating Plaid or Anthropic keys.** Replace the environment variable in
Railway and redeploy. Plaid keys are rotated from the Plaid dashboard.

**Removing a bank.** Disconnect from the Bank Sync screen. This revokes the
token with Plaid and deletes the local copy along with that bank's accounts
and transactions.

**If a device or password is believed compromised.** Change the password,
disconnect every bank (which revokes the tokens at Plaid), then relink.
Revoking at Plaid is the step that matters: the local copy alone is not
enough.

**If the data directory is believed exposed.** Assume every stored Plaid token
is compromised even though they are encrypted, because `SESSION_SECRET` may
have been exposed alongside them. Disconnect every bank, rotate
`SESSION_SECRET`, relink.

**Changes to the application.** Single maintainer. Changes are committed to
git with the reasoning in the commit message, so the history serves as the
change record.

---

## 6. Review

This document is reviewed when the threat picture changes — a new user, a new
integration, a new class of stored data — and at least annually. The date at
the top is the last review, not the last edit.
