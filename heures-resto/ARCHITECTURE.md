# Heures resto — Commerce Architecture

Sellable PWA: monthly hours calendar + multi-country tax estimates.

## Goals (MVP)

- Sell **one-time** (`lifetime`) and later **subscription** (`pro_monthly`)
- Work on **Chrome** (installable) and **iPhone Safari** (Add to Home Screen)
- Keep hours **on-device** by default (privacy = selling point)
- Unlock the full app with a **license key** after Stripe payment

## High-level diagram

```text
                    ┌─────────────────────┐
                    │  Landing (marketing) │
                    │  apps/landing        │
                    └──────────┬──────────┘
                               │ Buy
                               ▼
                    ┌─────────────────────┐
                    │  Stripe Checkout     │
                    └──────────┬──────────┘
                               │ webhook
                               ▼
                    ┌─────────────────────┐
                    │  API Worker          │
                    │  api/worker          │
                    │  - checkout session  │
                    │  - webhook → license │
                    │  - validate license  │
                    └──────────┬──────────┘
                               │ license key (email + success URL)
                               ▼
                    ┌─────────────────────┐
                    │  App PWA             │
                    │  apps/app            │
                    │  unlock + calendar    │
                    └─────────────────────┘
```

## Repo layout

```text
heures-resto/
  ARCHITECTURE.md          ← this file
  README.md
  .env.example
  shared/                  ← pricing + tax country presets
  apps/
    landing/               ← public marketing site
    app/                   ← licensed PWA
  api/
    worker/                ← Cloudflare Worker (Stripe + licenses)
  docs/
    GO-TO-MARKET.md
    DEPLOY.md
```

## Products & pricing (config-driven)

Defined in `shared/pricing.js`:

| SKU | Type | Default price | Unlocks |
|-----|------|---------------|---------|
| `lifetime` | one-time | €9 | Full app forever |
| `pro_monthly` | subscription | €2.99/mo | Full app + future cloud sync |

Landing and Worker both import/copy this config so prices stay in one place.

## License model

1. Customer pays via Stripe Checkout.
2. Worker webhook creates a license:
   - `key`: `HR-XXXX-XXXX-XXXX`
   - `plan`: `lifetime` | `pro_monthly`
   - `status`: `active` | `past_due` | `canceled`
   - `email`, `stripeCustomerId`, `stripeSessionId`
3. Success page / email shows the key + deep link:  
   `https://app.heuresresto.com/?key=HR-...`
4. App stores key in `localStorage`, calls `POST /api/license/validate` on launch.
5. If valid → full calendar. If not → paywall / enter key screen.

**Offline:** once validated, app caches `licenseCache` with expiry (24h) so Chrome/iPhone still work without network. Re-check when online.

## API surface (Worker)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/checkout` | Create Stripe Checkout Session `{ sku }` |
| `POST` | `/api/stripe/webhook` | Stripe events → create/update licenses |
| `POST` | `/api/license/validate` | `{ key }` → `{ ok, plan, status }` |
| `GET`  | `/api/health` | Uptime check |

### Storage (MVP)

Cloudflare KV namespace `LICENSES`:

- key: license key string  
- value: JSON license record  

Upgrade path: Supabase/Postgres when you need customer portal + team seats.

## Frontend apps

### Landing (`apps/landing`)

- Hero, features, pricing, FAQ, legal disclaimer (tax estimates)
- CTA → `POST /api/checkout` or direct Stripe Payment Link fallback
- No account system in MVP

### App (`apps/app`)

- Existing calendar PWA (dark default + day mode)
- Gate: `Paywall` → `Enter license` → `App`
- Free preview (optional): current month view, max 3 days logged
- Full: unlimited months, countries, export (later)

## Auth decision (MVP)

**No user accounts.** License key only.

Why: simplest to ship, works offline, less GDPR surface.  
Later: “Sign in with email” magic link that retrieves licenses.

## Hosting

| Piece | Suggested | URL example |
|-------|-----------|-------------|
| Landing | Cloudflare Pages | `https://heuresresto.com` |
| App | Cloudflare Pages | `https://app.heuresresto.com` |
| API | Cloudflare Worker | `https://api.heuresresto.com` |

Alternatives: Vercel (landing+app) + Worker still on CF, or Netlify.

## Env / secrets

See `.env.example`:

- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`
- `STRIPE_PRICE_LIFETIME`
- `STRIPE_PRICE_PRO_MONTHLY`
- `LICENSE_SIGNING_SECRET` (optional HMAC)
- `PUBLIC_APP_URL`
- `PUBLIC_LANDING_URL`
- `PUBLIC_API_URL`

## Security

- Never put Stripe secret key in the frontend
- Verify Stripe webhook signatures
- Rate-limit `/api/license/validate`
- Tax module labeled **estimate only**
- HTTPS everywhere

## Phased delivery

### Phase 0 — Architecture (this PR)

- Folder layout, shared pricing, landing shell, app paywall shell, Worker stubs

### Phase 1 — Payments live

- Real Stripe products/prices
- Webhook writes KV licenses
- Email key (Stripe receipt custom or Resend)

### Phase 2 — Growth

- Customer portal (cancel/refund)
- CSV export
- Optional cloud backup
- Chrome install prompt + SEO landing

### Phase 3 — B2B

- Team seats, manager view, invoice billing

## Local mental model

```text
Customer journey:
  Landing → Checkout → Pay → Get key → Open App → Unlock → Track hours
```

## Non-goals (for now)

- Native App Store / Play Store binaries
- Accountant-grade tax filing
- Multi-employee scheduling
