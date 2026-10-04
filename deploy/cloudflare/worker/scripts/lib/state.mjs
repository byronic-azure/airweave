// @ts-check
// The orchestrator's memory between runs: resource ids, which resources it
// created (so `down` removes only those), and the two credentials Cloudflare
// shows exactly once (the origin service token secret and the gateway API key).
// Written atomically with mode 0600 inside a 0700 directory; gitignored.

import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { EdgeError } from "./util.mjs";

/**
 * @typedef {object} EdgeState
 * @property {number} version
 * @property {string} [accountId]
 * @property {string} [zone]
 * @property {string} [zoneId]
 * @property {string} [apiHost]
 * @property {string} [originHost]
 * @property {string} [authMode]
 * @property {string} [backend]
 * @property {string} [kubeContext]
 * @property {string} [tunnelName]
 * @property {Record<string, string>} ids        resource key -> Cloudflare id
 * @property {Record<string, boolean>} created   resource key -> created by this tool
 * @property {{ id: string, clientId: string, clientSecret: string }} [serviceToken]
 * @property {string} [gatewayApiKey]
 */

/** @returns {EdgeState} */
export function emptyState() {
  return { version: 1, ids: {}, created: {} };
}

/**
 * @param {string} file
 * @returns {EdgeState}
 */
export function loadState(file) {
  if (!existsSync(file)) return emptyState();
  assertPrivate(file);
  /** @type {any} */
  let data;
  try {
    data = JSON.parse(readFileSync(file, "utf8"));
  } catch (err) {
    throw new EdgeError(`${file} is not valid JSON (${/** @type {Error} */ (err).message}); fix or remove it`);
  }
  if (data?.version !== 1) throw new EdgeError(`${file}: unsupported state version ${data?.version}`);
  return { ...emptyState(), ...data, ids: { ...data.ids }, created: { ...data.created } };
}

/**
 * The state file decides where stored credentials are sent (the smoke test
 * authenticates to the hostnames it records). Like ssh with a private key,
 * refuse a file that another user owns or that group/others can write, since
 * whoever can edit it could point those credentials at a host of their choice.
 * POSIX only; Windows has no comparable mode bits.
 * @param {string} file
 */
export function assertPrivate(file) {
  if (process.platform === "win32" || typeof process.getuid !== "function") return;
  const st = statSync(file);
  if (st.uid !== process.getuid()) {
    throw new EdgeError(`${file} is owned by uid ${st.uid}, not you; refusing to use the credentials in it`);
  }
  if ((st.mode & 0o022) !== 0) {
    throw new EdgeError(
      `${file} is writable by group or others (mode ${(st.mode & 0o777).toString(8)}); run chmod 600 on it. ` +
        "On a filesystem without POSIX permissions (e.g. /mnt/c under WSL) pass --state <path in your home directory>.",
    );
  }
}

/**
 * @param {string} file
 * @param {EdgeState} state
 */
export function saveState(file, state) {
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, file);
}

/** @param {string} file */
export function removeState(file) {
  rmSync(file, { force: true });
}
