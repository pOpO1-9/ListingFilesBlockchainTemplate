# Deploy

## 1. Cloudflare Pages — Landing

- Project root: `heures-resto/apps/landing`
- Build command: none (static)
- Output: `.`

## 2. Cloudflare Pages — App

- Project root: `heures-resto/apps/app`
- Build command: none (static)
- Custom domain: `app.heuresresto.com`

## 3. Cloudflare Worker — API

```bash
cd heures-resto/api/worker
npm install
npx wrangler login
npx wrangler kv namespace create LICENSES
# put id into wrangler.toml
npx wrangler secret put STRIPE_SECRET_KEY
npx wrangler secret put STRIPE_WEBHOOK_SECRET
npx wrangler secret put STRIPE_PRICE_LIFETIME
npx wrangler secret put STRIPE_PRICE_PRO_MONTHLY
npx wrangler deploy
```

## 4. Stripe

1. Create products/prices matching `shared/pricing.js`
2. Webhook endpoint: `https://api.heuresresto.com/api/stripe/webhook`
3. Events: `checkout.session.completed`, `customer.subscription.updated`, `customer.subscription.deleted`
4. Success URL: `https://app.heuresresto.com/unlock.html?session_id={CHECKOUT_SESSION_ID}`

## 5. Smoke test

1. Open landing → Buy lifetime (test mode)
2. Pay with `4242 4242 4242 4242`
3. Land on unlock page with license key
4. App validates and opens calendar
