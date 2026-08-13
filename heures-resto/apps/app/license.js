/**
 * Client license gate for Heures resto.
 * Validate against API, cache locally for offline use.
 */
(function (global) {
  const STORAGE_KEY = "heures-resto-license-v1";
  const CACHE_MS = 24 * 60 * 60 * 1000;

  function apiBase() {
    return global.HEURES_API_URL || "http://127.0.0.1:8787";
  }

  function read() {
    try {
      return JSON.parse(localStorage.getItem(STORAGE_KEY) || "null");
    } catch {
      return null;
    }
  }

  function write(data) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  }

  function clear() {
    localStorage.removeItem(STORAGE_KEY);
  }

  function isFresh(rec) {
    if (!rec?.ok || !rec?.checkedAt) return false;
    return Date.now() - new Date(rec.checkedAt).getTime() < CACHE_MS;
  }

  async function validate(key) {
    const normalized = String(key || "")
      .trim()
      .toUpperCase();
    if (!normalized) return { ok: false, error: "missing_key" };

    try {
      const res = await fetch(`${apiBase()}/api/license/validate`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ key: normalized }),
      });
      const data = await res.json();
      if (data.ok) {
        const rec = {
          ok: true,
          key: normalized,
          plan: data.plan,
          status: data.status,
          checkedAt: data.checkedAt || new Date().toISOString(),
          demo: !!data.demo,
        };
        write(rec);
        return rec;
      }
      return { ok: false, error: data.error || "invalid" };
    } catch {
      // Offline fallback: accept fresh cache for same key
      const cached = read();
      if (cached?.key === normalized && isFresh(cached)) return cached;
      return { ok: false, error: "offline", cached: cached?.ok || false };
    }
  }

  async function ensureLicensed() {
    const cached = read();
    if (cached?.ok && isFresh(cached)) return cached;
    if (cached?.key) return validate(cached.key);
    return { ok: false, error: "no_license" };
  }

  function fromQuery() {
    const u = new URL(location.href);
    return u.searchParams.get("key");
  }

  global.HeuresLicense = {
    read,
    write,
    clear,
    validate,
    ensureLicensed,
    fromQuery,
    apiBase,
  };
})(window);
