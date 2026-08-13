# Heures resto (commercial)

Sellable restaurant-hours PWA — calendar, multi-country tax estimates, Stripe licenses.

## Quick map

| Path | What |
|------|------|
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | System design |
| [`apps/landing`](./apps/landing) | Marketing + Buy |
| [`apps/app`](./apps/app) | Licensed calendar PWA |
| [`api/worker`](./api/worker) | Stripe + license API |
| [`shared`](./shared) | Pricing + countries |
| [`docs/DEPLOY.md`](./docs/DEPLOY.md) | Ship checklist |

## Local demo (no Stripe yet)

```bash
# Terminal 1 — API
cd heures-resto/api/worker
npm install
# optional: echo DEV_UNLOCK_KEY in wrangler.toml [vars] or secrets
npx wrangler dev

# Terminal 2 — static sites
cd heures-resto
python3 -m http.server 5173
```

Open:

- Landing: http://127.0.0.1:5173/apps/landing/
- App: http://127.0.0.1:5173/apps/app/
- Tap **Continue with demo key** if API isn’t up

Set `window.HEURES_API_URL` before scripts if the API isn’t on `8787`.

## Customer flow

1. Landing → Buy Lifetime (€9) or Pro (€2.99/mo)
2. Stripe Checkout
3. `unlock.html` shows license key
4. App validates key → calendar unlocks

## Next implementation steps

1. Create Stripe products/prices  
2. `wrangler kv namespace create LICENSES`  
3. Deploy Worker + Pages (see `docs/DEPLOY.md`)  
4. Add webhook signature verification + email delivery  

Tax numbers are **estimates only**.
