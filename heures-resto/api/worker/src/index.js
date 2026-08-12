/**
 * Heures resto API — Cloudflare Worker
 * Routes: health, checkout, stripe webhook, license validate
 */

const PRODUCTS = {
  lifetime: { sku: "lifetime", kind: "one_time", envPrice: "STRIPE_PRICE_LIFETIME" },
  pro_monthly: { sku: "pro_monthly", kind: "subscription", envPrice: "STRIPE_PRICE_PRO_MONTHLY" },
};

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": "*",
      "access-control-allow-headers": "content-type, authorization",
      "access-control-allow-methods": "GET,POST,OPTIONS",
      ...extra,
    },
  });
}

function cors(req) {
  if (req.method === "OPTIONS") return json({ ok: true });
  return null;
}

function randomKey() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const block = () =>
    Array.from({ length: 4 }, () => alphabet[Math.floor(Math.random() * alphabet.length)]).join("");
  return `HR-${block()}-${block()}-${block()}`;
}

async function readJson(req) {
  try {
    return await req.json();
  } catch {
    return null;
  }
}

async function createCheckout(env, body) {
  const sku = body?.sku || "lifetime";
  const product = PRODUCTS[sku];
  if (!product) return json({ error: "unknown_sku" }, 400);

  const priceId = env[product.envPrice];
  if (!env.STRIPE_SECRET_KEY || !priceId) {
    return json(
      {
        error: "stripe_not_configured",
        message: "Set STRIPE_SECRET_KEY and price IDs (see .env.example).",
        mockCheckoutUrl: `${env.PUBLIC_APP_URL}/unlock.html?demo=1&sku=${sku}`,
      },
      503
    );
  }

  const params = new URLSearchParams();
  params.set("mode", product.kind === "subscription" ? "subscription" : "payment");
  params.set("success_url", `${env.PUBLIC_APP_URL}/unlock.html?session_id={CHECKOUT_SESSION_ID}`);
  params.set("cancel_url", `${env.PUBLIC_LANDING_URL}/?canceled=1`);
  params.set("line_items[0][price]", priceId);
  params.set("line_items[0][quantity]", "1");
  params.set("metadata[sku]", sku);
  params.set("allow_promotion_codes", "true");

  const res = await fetch("https://api.stripe.com/v1/checkout/sessions", {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: params,
  });
  const data = await res.json();
  if (!res.ok) return json({ error: "stripe_error", details: data }, 502);
  return json({ url: data.url, id: data.id });
}

async function issueLicense(env, record) {
  let key = randomKey();
  // Extremely unlikely collision loop
  for (let i = 0; i < 5; i++) {
    const existing = await env.LICENSES.get(key);
    if (!existing) break;
    key = randomKey();
  }
  const license = {
    key,
    ...record,
    createdAt: new Date().toISOString(),
  };
  await env.LICENSES.put(key, JSON.stringify(license));
  if (record.email) {
    await env.LICENSES.put(`email:${record.email.toLowerCase()}`, key);
  }
  if (record.stripeSessionId) {
    await env.LICENSES.put(`session:${record.stripeSessionId}`, key);
  }
  return license;
}

async function handleWebhook(env, req) {
  const raw = await req.text();
  // MVP: signature verification requires Stripe SDK / subtle crypto.
  // Wire STRIPE_WEBHOOK_SECRET before production traffic.
  if (!env.STRIPE_WEBHOOK_SECRET) {
    return json({ error: "webhook_secret_missing" }, 500);
  }

  let event;
  try {
    event = JSON.parse(raw);
  } catch {
    return json({ error: "invalid_json" }, 400);
  }

  // TODO(prod): verify Stripe-Signature header with webhook secret
  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const sku = session.metadata?.sku || "lifetime";
    const existing = session.id ? await env.LICENSES.get(`session:${session.id}`) : null;
    if (existing) return json({ ok: true, duplicate: true });

    const license = await issueLicense(env, {
      plan: sku,
      status: "active",
      email: session.customer_details?.email || session.customer_email || null,
      stripeCustomerId: session.customer || null,
      stripeSessionId: session.id,
      stripeSubscriptionId: session.subscription || null,
    });
    return json({ ok: true, key: license.key });
  }

  if (
    event.type === "customer.subscription.updated" ||
    event.type === "customer.subscription.deleted"
  ) {
    // Phase 1+: look up by stripeSubscriptionId and flip status
    return json({ ok: true, ignored: false, todo: "map_subscription_status" });
  }

  return json({ ok: true, ignored: true });
}

async function validateLicense(env, body) {
  const key = String(body?.key || "")
    .trim()
    .toUpperCase();
  if (!key) return json({ ok: false, error: "missing_key" }, 400);

  // Local/dev escape hatch
  if (env.DEV_UNLOCK_KEY && key === String(env.DEV_UNLOCK_KEY).toUpperCase()) {
    return json({
      ok: true,
      plan: "lifetime",
      status: "active",
      demo: true,
      checkedAt: new Date().toISOString(),
    });
  }

  if (!env.LICENSES) return json({ ok: false, error: "kv_missing" }, 500);
  const raw = await env.LICENSES.get(key);
  if (!raw) return json({ ok: false, error: "not_found" }, 404);
  const license = JSON.parse(raw);
  const active = license.status === "active";
  return json({
    ok: active,
    plan: license.plan,
    status: license.status,
    checkedAt: new Date().toISOString(),
  });
}

async function resolveSession(env, sessionId) {
  if (!sessionId) return json({ error: "missing_session" }, 400);
  const key = await env.LICENSES.get(`session:${sessionId}`);
  if (key) {
    const license = JSON.parse(await env.LICENSES.get(key));
    return json({ ok: true, key: license.key, plan: license.plan });
  }

  // If webhook lag: optionally fetch session from Stripe (phase 1)
  return json({ ok: false, error: "not_ready" }, 404);
}

export default {
  async fetch(req, env) {
    const preflight = cors(req);
    if (preflight) return preflight;

    const url = new URL(req.url);
    const path = url.pathname.replace(/\/$/, "") || "/";

    try {
      if (req.method === "GET" && (path === "/api/health" || path === "/health")) {
        return json({ ok: true, service: "heures-resto-api", ts: Date.now() });
      }
      if (req.method === "POST" && path === "/api/checkout") {
        return createCheckout(env, await readJson(req));
      }
      if (req.method === "POST" && path === "/api/stripe/webhook") {
        return handleWebhook(env, req);
      }
      if (req.method === "POST" && path === "/api/license/validate") {
        return validateLicense(env, await readJson(req));
      }
      if (req.method === "GET" && path === "/api/license/by-session") {
        return resolveSession(env, url.searchParams.get("session_id"));
      }
      return json({ error: "not_found", path }, 404);
    } catch (err) {
      return json({ error: "server_error", message: String(err?.message || err) }, 500);
    }
  },
};
