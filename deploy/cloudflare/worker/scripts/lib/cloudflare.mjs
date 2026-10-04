// @ts-check
// Minimal Cloudflare v4 API client for the edge orchestrator.
//
// - Bearer token auth; the token never appears in errors or logs.
// - Retries 429, 5xx and network errors with exponential backoff (Retry-After wins).
// - `list()` follows page/per_page and cursor pagination.
// - `readOnly: true` makes every non-GET call throw, which is how `edge.mjs plan`
//   guarantees it changes nothing.
// - 401/403 errors name the token permission the failing call needed.

import { sleep as realSleep } from "./util.mjs";

export const API_BASE = "https://api.cloudflare.com/client/v4";

/** Error codes Cloudflare returns for a malformed, unknown or expired token. */
const REJECTED_TOKEN = new Set([6003, 6111, 9109]);

export class CloudflareApiError extends Error {
  /**
   * @param {string} message
   * @param {{ status: number, method: string, path: string, codes: number[] }} details
   */
  constructor(message, details) {
    super(message);
    this.name = "CloudflareApiError";
    this.status = details.status;
    this.method = details.method;
    this.path = details.path;
    this.codes = details.codes;
  }
}

/**
 * @typedef {object} CallOptions
 * @property {Record<string, string | number | boolean | undefined>} [query]
 * @property {unknown} [body]
 * @property {string} [need]  the API token permission this call requires, for 401/403 hints
 */

/**
 * @typedef {object} ClientOptions
 * @property {string} token
 * @property {typeof fetch} [fetchImpl]
 * @property {string} [baseUrl]
 * @property {(ms: number) => Promise<unknown>} [sleep]
 * @property {number} [maxRetries]
 * @property {boolean} [readOnly]
 */

/** @param {ClientOptions} options */
export function createCloudflareClient(options) {
  const fetchImpl = options.fetchImpl ?? fetch;
  const baseUrl = options.baseUrl ?? API_BASE;
  const pause = options.sleep ?? realSleep;
  const maxRetries = options.maxRetries ?? 4;
  if (!options.token) throw new Error("createCloudflareClient: token is required");

  /**
   * @param {string} method
   * @param {string} path
   * @param {CallOptions} [opts]
   * @returns {Promise<{ result: any, info: any }>}
   */
  async function call(method, path, opts = {}) {
    if (options.readOnly && method !== "GET") {
      throw new Error(`refusing ${method} ${path}: the client is read-only (plan mode)`);
    }
    const url = new URL(baseUrl + path);
    for (const [key, value] of Object.entries(opts.query ?? {})) {
      if (value !== undefined) url.searchParams.set(key, String(value));
    }
    /** @type {Record<string, string>} */
    const headers = { Authorization: `Bearer ${options.token}`, Accept: "application/json" };
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";

    for (let attempt = 0; ; attempt++) {
      /** @type {Response} */
      let res;
      try {
        res = await fetchImpl(url, {
          method,
          headers,
          body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
        });
      } catch (err) {
        if (attempt < maxRetries) {
          await pause(backoffMs(attempt));
          continue;
        }
        throw new CloudflareApiError(`${method} ${path}: network error: ${errorText(err)}`, {
          status: 0,
          method,
          path,
          codes: [],
        });
      }
      if ((res.status === 429 || res.status >= 500) && attempt < maxRetries) {
        await pause(retryAfterMs(res) ?? backoffMs(attempt));
        continue;
      }
      const text = await res.text();
      /** @type {any} */
      let json;
      try {
        json = text ? JSON.parse(text) : undefined;
      } catch {
        json = undefined;
      }
      if (res.ok && json && json.success !== false) {
        return { result: json.result, info: json.result_info };
      }
      /** @type {{ code?: number, message?: string }[]} */
      const errors = Array.isArray(json?.errors) ? json.errors : [];
      const detail = errors.length
        ? errors.map((e) => `${e.code ?? "?"}: ${e.message ?? ""}`).join("; ")
        : text.slice(0, 200) || res.statusText;
      const codes = errors.map((e) => Number(e.code));
      const hint = codes.some((c) => REJECTED_TOKEN.has(c))
        ? " (Cloudflare rejected CLOUDFLARE_API_TOKEN as invalid or expired; create a new API token)"
        : (res.status === 401 || res.status === 403) && opts.need
          ? ` (the API token needs "${opts.need}")`
          : "";
      throw new CloudflareApiError(`${method} ${path} -> ${res.status}: ${detail}${hint}`, {
        status: res.status,
        method,
        path,
        codes: codes.filter((c) => Number.isFinite(c)),
      });
    }
  }

  return {
    readOnly: options.readOnly ?? false,
    /** @param {string} path @param {CallOptions} [opts] */
    get: async (path, opts) => (await call("GET", path, opts)).result,
    /** @param {string} path @param {CallOptions} [opts] */
    post: async (path, opts) => (await call("POST", path, opts)).result,
    /** @param {string} path @param {CallOptions} [opts] */
    put: async (path, opts) => (await call("PUT", path, opts)).result,
    /** @param {string} path @param {CallOptions} [opts] */
    patch: async (path, opts) => (await call("PATCH", path, opts)).result,
    /** @param {string} path @param {CallOptions} [opts] */
    del: async (path, opts) => (await call("DELETE", path, opts)).result,
    /**
     * Every item of a paginated collection.
     * @param {string} path
     * @param {CallOptions & { perPage?: number }} [opts]
     * @returns {Promise<any[]>}
     */
    async list(path, opts = {}) {
      /** @type {any[]} */
      const items = [];
      const perPage = opts.perPage ?? 50;
      /** @type {string | undefined} */
      let cursor;
      for (let page = 1; page <= 200; page++) {
        const query = { ...opts.query, per_page: perPage, ...(cursor ? { cursor } : { page }) };
        const { result, info } = await call("GET", path, { ...opts, query });
        const batch = Array.isArray(result) ? result : [];
        items.push(...batch);
        if (info?.cursor) {
          if (batch.length === 0) break;
          cursor = info.cursor;
          continue;
        }
        const totalPages = Number(info?.total_pages);
        if (!Number.isFinite(totalPages) || page >= totalPages || batch.length === 0) break;
      }
      return items;
    },
  };
}

/** @typedef {ReturnType<typeof createCloudflareClient>} CloudflareClient */

/** @param {number} attempt */
function backoffMs(attempt) {
  return Math.min(500 * 2 ** attempt, 8000);
}

/** @param {Response} res */
function retryAfterMs(res) {
  const value = Number(res.headers.get("retry-after"));
  return Number.isFinite(value) && value > 0 ? Math.min(value * 1000, 30000) : undefined;
}

/** @param {unknown} err */
function errorText(err) {
  if (err instanceof Error) {
    const cause = /** @type {{ cause?: unknown }} */ (err).cause;
    return cause instanceof Error ? `${err.message} (${cause.message})` : err.message;
  }
  return String(err);
}
