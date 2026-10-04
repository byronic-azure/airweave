// @ts-check
// Small shared helpers for the edge orchestrator (scripts/edge.mjs).

/** An expected, user-actionable failure: printed without a stack trace. */
export class EdgeError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = "EdgeError";
  }
}

/** @param {number} ms */
export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Structural equality for JSON values (objects compare by keys, not key order).
 * @param {unknown} a
 * @param {unknown} b
 * @returns {boolean}
 */
export function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((value, i) => deepEqual(value, b[i]));
  }
  const ra = /** @type {Record<string, unknown>} */ (a);
  const rb = /** @type {Record<string, unknown>} */ (b);
  const keys = Object.keys(ra);
  return keys.length === Object.keys(rb).length && keys.every((k) => k in rb && deepEqual(ra[k], rb[k]));
}

/**
 * True when every field in `want` is present in `have` with an equal value
 * (recursively for objects, element-wise for equal-length arrays). Cloudflare
 * adds server-side fields to what it returns; this compares only what we set.
 * @param {unknown} want
 * @param {unknown} have
 * @returns {boolean}
 */
export function isSubset(want, have) {
  if (Array.isArray(want)) {
    return Array.isArray(have) && want.length === have.length && want.every((w, i) => isSubset(w, have[i]));
  }
  if (typeof want === "object" && want !== null) {
    if (typeof have !== "object" || have === null || Array.isArray(have)) return false;
    const h = /** @type {Record<string, unknown>} */ (have);
    return Object.entries(want).every(([k, v]) => isSubset(v, h[k]));
  }
  return want === have;
}

/**
 * Validates and normalises a DNS hostname (lowercase, no trailing dot).
 * Split into labels instead of one big regex so the check stays linear.
 * @param {string} value
 * @param {string} what  flag name for the error message
 */
export function normalizeHostname(value, what) {
  const host = value.trim().toLowerCase().replace(/\.$/, "");
  const labels = host.split(".");
  const ok =
    host.length > 0 &&
    host.length <= 253 &&
    labels.length >= 2 &&
    labels.every((l) => l.length >= 1 && l.length <= 63 && /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(l));
  if (!ok) throw new EdgeError(`${what}: "${value}" is not a valid hostname`);
  return host;
}

/**
 * Splits a comma-separated list, trimming blanks.
 * @param {string | undefined} value
 * @returns {string[]}
 */
export function splitList(value) {
  return (value ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}
