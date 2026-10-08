// @ts-check
// Runs external commands (kubectl, wrangler) without a shell. Secrets travel
// through stdin or 0600 files, never through argv, where `ps` would show them.

import { spawn } from "node:child_process";

/**
 * @typedef {object} RunOptions
 * @property {string} [input]                  written to stdin, then closed
 * @property {Record<string, string | undefined>} [env]  merged over process.env
 * @property {string} [cwd]
 * @property {boolean} [echo]                  stream output live, indented
 * @property {boolean} [allowFailure]          resolve instead of rejecting on non-zero exit
 */

/** @typedef {{ code: number, stdout: string, stderr: string }} RunResult */
/** @typedef {(cmd: string, args: string[], opts?: RunOptions) => Promise<RunResult>} Runner */

/** @type {Runner} */
export function run(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      env: { ...process.env, ...opts.env },
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    /** @param {string} chunk */
    const echo = (chunk) => {
      if (opts.echo) process.stdout.write(chunk.replace(/^(?=.)/gm, "       | "));
    };
    child.stdout.setEncoding("utf8").on("data", (chunk) => {
      stdout += chunk;
      echo(chunk);
    });
    child.stderr.setEncoding("utf8").on("data", (chunk) => {
      stderr += chunk;
      echo(chunk);
    });
    child.on("error", (err) => {
      const e = /** @type {NodeJS.ErrnoException} */ (err);
      reject(new Error(e.code === "ENOENT" ? `${cmd} not found on PATH` : `${cmd}: ${e.message}`));
    });
    child.on("close", (code) => {
      const result = { code: code ?? 1, stdout, stderr };
      if (result.code === 0 || opts.allowFailure) resolve(result);
      else {
        const tail = (stderr || stdout).trim().split("\n").slice(-12).join("\n");
        reject(new Error(`${cmd} ${args.join(" ")} exited with ${result.code}\n${tail}`));
      }
    });
    child.stdin.on("error", () => {
      /* the child may exit before reading stdin; the exit code reports that */
    });
    child.stdin.end(opts.input ?? "");
  });
}
