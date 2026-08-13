# Handoff — Heures resto / resthours

Copy this into the agent working in the **resthours** private repo.

## Goal

Build and ship a restaurant hours tracker that:

1. Lets Paul track shifts on **Chrome + iPhone**
2. Can be **sold** (license key after Stripe)
3. Lives in private repo **`resthours`** (not the public blockchain template)

Public work is currently on:
`https://github.com/pOpO1-9/ListingFilesBlockchainTemplate`  
branch: `cursor/heures-resto-commerce-arch-cffc`  
PR: `https://github.com/pOpO1-9/ListingFilesBlockchainTemplate/pull/2`

Previous Cursor agent **could not push** to `pOpO1-9/resthours` or `restohours` (GitHub App 404 / no access). Your job: take this code into **resthours** and continue.

---

## What to copy into resthours

From the public branch above (or this workspace), put at repo root:

```text
resthours/
  README.md
  restaurant-hours/     ← personal tracker (ready to use)
  heures-resto/         ← sellable product architecture
```

Suggested root README:

```md
# resthours

| Folder | What |
|--------|------|
| restaurant-hours/ | Personal calendar tracker |
| heures-resto/ | Commerce architecture (landing, app, API) |

See heures-resto/ARCHITECTURE.md
```

---

## 1) Personal tracker — `restaurant-hours/`

### Features already built

- Monthly **calendar** (Mon–Sun), tap day → set hours / off / clear
- **Auto-save** in `localStorage`
- **Auto month rollover** when the calendar month changes
- Rate default **12 €/h**
- Totals: **brut → net (cotisations) → après impôts**
- **Multi-country** tax presets (France default, editable %)
- **Dark mode default** + **Jour/Nuit** toggle
- High-contrast text in both themes
- PWA bits: manifest, icons, service worker, iOS Add to Home Screen tip

### Seeded schedule (from Paul’s messages)

Starts **1 August 2026** (Saturday):

| Dates | Hours |
|-------|------:|
| 01/08 Sat | 9 |
| 02/08 Sun | 11 |
| 03–04/08 Mon–Tue | 9 each |
| 05–06/08 Wed–Thu | off |
| 07/08 Fri | 5 |
| 08–12/08 Sat–Wed | 9 each |
| 13–15/08 Thu–Sat | off |
| 16/08 Sun | 9 |

**97 h × 12 € = 1 164 € brut**  
France defaults: cotisations **22%**, PAS **0%** → ~**908 €** after tax estimate.

Storage key: `resto-hours-v5-calendar` (in the personal app).

### Files

- `restaurant-hours/index.html` — main app
- `restaurant-hours/heures-resto-iphone.html` — single-file export (embedded icon)
- `restaurant-hours/hours.csv` — spreadsheet snapshot
- `manifest.webmanifest`, `sw.js`, icons

### Temporary iPhone links (catbox, ~72h, may expire)

Latest theme+calendar build was uploaded as temporary HTML hosts; prefer serving from the private repo / Cloudflare Pages instead.

---

## 2) Commerce product — `heures-resto/`

### Architecture (MVP)

```text
Landing → Stripe Checkout → webhook creates license key
       → unlock.html shows key → app validates → calendar unlocks
Hours stay on-device (localStorage). No user accounts in MVP.
```

### Layout

```text
heures-resto/
  ARCHITECTURE.md
  README.md
  HANDOFF.md              ← this file
  .env.example
  shared/
    pricing.js            ← €9 lifetime, €2.99/mo
    countries.js
  apps/
    landing/index.html    ← marketing + Buy
    app/                  ← licensed PWA (empty seed, paywall)
      index.html
      unlock.html
      license.js
      sw.js, manifest, icons
  api/worker/             ← Cloudflare Worker
    src/index.js          ← /checkout, /webhook, /license/validate
    wrangler.toml
  docs/
    DEPLOY.md
    GO-TO-MARKET.md
```

### Pricing (config)

- **Lifetime** `lifetime` — €9 one-time  
- **Pro** `pro_monthly` — €2.99/month  

### API routes (Worker)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/health` | Health |
| POST | `/api/checkout` | `{ sku }` → Stripe session URL |
| POST | `/api/stripe/webhook` | Issue/update licenses in KV |
| POST | `/api/license/validate` | `{ key }` → ok/plan/status |
| GET | `/api/license/by-session` | Post-checkout key lookup |

Dev unlock key: `HR-DEV-TEST-0001` (`DEV_UNLOCK_KEY` in wrangler vars).  
App paywall has **Continue with demo key** for local testing without Stripe.

### Commercial app vs personal app

| | `restaurant-hours/` | `heures-resto/apps/app/` |
|--|---------------------|---------------------------|
| Seed | Paul’s Aug 2026 hours | Empty |
| Gate | None | License paywall |
| Storage | `resto-hours-v5-calendar` | `heures-resto-app-v1` + license cache |

---

## 3) What is NOT done yet

- [ ] Code living in private **resthours** (blocked previously)
- [ ] Real Stripe products/prices + secrets
- [ ] Cloudflare KV namespace + Worker deploy
- [ ] Custom domains (`heuresresto.com`, `app.`, `api.`)
- [ ] Webhook signature verification (TODO in worker)
- [ ] Email delivery of license keys
- [ ] Remove heures code from public ListingFilesBlockchainTemplate PR (after private push)

---

## 4) Immediate tasks for the resthours agent

1. **Import code** into `resthours` private repo (folders above).
2. **Serve personal tracker**: open `restaurant-hours/index.html` or deploy Pages.
3. **Phase 1 payments** (when Paul provides Stripe keys):
   - Create prices matching `shared/pricing.js`
   - `wrangler kv namespace create LICENSES`
   - Set secrets from `.env.example`
   - Deploy Worker + wire landing `HEURES_API_URL`
4. Keep tax UI labeled as **estimates only**.
5. Do **not** put Paul’s personal hours into the sellable app seed.

---

## 5) Product / UX rules Paul cares about

- Easy fill-in for next days
- Calendar that saves and advances months automatically
- France after-tax + other countries
- Prefers **dark mode**, but wants day mode too
- Readable contrast
- Chrome install + iPhone Home Screen
- Sellable eventually (Lifetime €9 primary)

---

## 6) Local demo commands

```bash
# API
cd heures-resto/api/worker && npm install && npx wrangler dev

# Static
cd .   # repo root
python3 -m http.server 5173
# Landing: http://127.0.0.1:5173/heures-resto/apps/landing/
# App:     http://127.0.0.1:5173/heures-resto/apps/app/
# Personal:http://127.0.0.1:5173/restaurant-hours/
```

---

## 7) Owner

- GitHub: `pOpO1-9`
- Email on file: `paulkh2000@gmail.com`
- Public couple brand Soft Scenes is a **separate** project — this is resto hours tooling/business.

---

## 8) How to pull from the public branch (if needed)

```bash
git clone https://github.com/pOpO1-9/ListingFilesBlockchainTemplate.git
cd ListingFilesBlockchainTemplate
git fetch origin cursor/heures-resto-commerce-arch-cffc
git checkout cursor/heures-resto-commerce-arch-cffc
# then copy heures-resto/ and restaurant-hours/ into resthours
```
