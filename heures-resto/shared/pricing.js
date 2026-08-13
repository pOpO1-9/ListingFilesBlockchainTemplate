/**
 * Single source of truth for sellable SKUs.
 * Copied/imported by landing + worker.
 */
export const CURRENCY = "eur";

export const PRODUCTS = {
  lifetime: {
    sku: "lifetime",
    name: "Heures resto — Lifetime",
    description: "Full calendar, multi-country tax estimates, dark/light mode. One payment.",
    kind: "one_time",
    amountCents: 900, // €9.00
    badge: "Best value",
    features: [
      "Monthly calendar that auto-rolls over",
      "Multi-country tax estimates",
      "Dark & light mode",
      "On-device privacy (hours stay on your phone)",
      "Lifetime updates for this major version",
    ],
  },
  pro_monthly: {
    sku: "pro_monthly",
    name: "Heures resto — Pro",
    description: "Full app with ongoing updates. Cancel anytime.",
    kind: "subscription",
    amountCents: 299, // €2.99
    badge: "Flexible",
    features: [
      "Everything in Lifetime",
      "Priority feature access",
      "Cancel anytime",
    ],
  },
};

export function formatEuroFromCents(cents) {
  return new Intl.NumberFormat("fr-FR", {
    style: "currency",
    currency: "EUR",
    maximumFractionDigits: 2,
  }).format(cents / 100);
}
