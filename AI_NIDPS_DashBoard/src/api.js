const DEFAULT_API_BASE = "http://127.0.0.1:5000/api";
const ADMIN_TOKEN_HEADER = "X-NIDPS-API-Token";
const ADMIN_TOKEN_STORAGE_KEY = "nidpsAdminToken";
const BOOTSTRAP_TOKEN_STORAGE_KEY = "nidpsBootstrapAdminToken";

export const API_BASE = import.meta.env.VITE_NIDPS_API_BASE || DEFAULT_API_BASE;
let bootstrapTokenPromise = null;

function getStoredToken(storageKey, storageName) {
  if (typeof window === "undefined") {
    return "";
  }

  const storage = window[storageName];
  if (!storage) {
    return "";
  }

  return storage.getItem(storageKey) || "";
}

export function getAdminToken() {
  const stored = getStoredToken(ADMIN_TOKEN_STORAGE_KEY, "localStorage");
  if (stored) {
    return stored;
  }

  const configured = import.meta.env.VITE_NIDPS_ADMIN_TOKEN || "";
  if (configured) {
    return configured;
  }

  const bootstrap = getStoredToken(BOOTSTRAP_TOKEN_STORAGE_KEY, "sessionStorage");
  if (bootstrap) {
    return bootstrap;
  }
  return "";
}

export function clearBootstrapAdminToken() {
  bootstrapTokenPromise = null;
  if (typeof window !== "undefined" && window.sessionStorage) {
    window.sessionStorage.removeItem(BOOTSTRAP_TOKEN_STORAGE_KEY);
  }
}

function hasBootstrapAdminToken() {
  return Boolean(getStoredToken(BOOTSTRAP_TOKEN_STORAGE_KEY, "sessionStorage"));
}

export async function ensureAdminToken() {
  const existingToken = getAdminToken();
  if (existingToken) {
    return existingToken;
  }

  if (bootstrapTokenPromise) {
    return bootstrapTokenPromise;
  }

  bootstrapTokenPromise = (async () => {
    const response = await fetch(`${API_BASE}/admin-bootstrap-token`, {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
    });

    let payload = {};
    try {
      payload = await response.json();
    } catch {
      payload = {};
    }

    if (!response.ok || !payload.ok || !payload.token) {
      throw new Error(payload.error || `HTTP ${response.status}`);
    }

    const token = String(payload.token || "");
    if (!token) {
      throw new Error("Bootstrap token response was empty.");
    }

    if (typeof window !== "undefined" && window.sessionStorage) {
      window.sessionStorage.setItem(BOOTSTRAP_TOKEN_STORAGE_KEY, token);
    }

    return token;
  })().catch((error) => {
    clearBootstrapAdminToken();
    throw error;
  });

  return bootstrapTokenPromise;
}

export function buildRequestHeaders({ json = false } = {}) {
  const headers = {};
  if (json) {
    headers["Content-Type"] = "application/json";
  }
  return headers;
}

export async function buildAdminRequestHeaders({ json = false } = {}) {
  const headers = buildRequestHeaders({ json });
  headers[ADMIN_TOKEN_HEADER] = await ensureAdminToken();
  return headers;
}

export async function adminFetch(path, options = {}) {
  const { headers = {}, retryOnUnauthorized = true, ...rest } = options;
  const adminHeaders = {
    ...headers,
    [ADMIN_TOKEN_HEADER]: await ensureAdminToken(),
  };

  const response = await fetch(`${API_BASE}${path}`, {
    ...rest,
    headers: adminHeaders,
  });

  if (response.status === 401 && retryOnUnauthorized && hasBootstrapAdminToken()) {
    clearBootstrapAdminToken();
    return adminFetch(path, {
      ...options,
      retryOnUnauthorized: false,
    });
  }

  return response;
}
