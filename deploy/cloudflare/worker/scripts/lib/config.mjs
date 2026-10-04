// @ts-check
// Reads and edits wrangler.jsonc without disturbing its comments or layout.
// jsonc-parser's modify()/applyEdits() rewrite only the value being changed,
// which is also how `wrangler ... --update-config` patches JSONC files.

import { readFileSync } from "node:fs";
import { applyEdits, modify, parse, printParseErrorCode } from "jsonc-parser";
import { EdgeError, deepEqual } from "./util.mjs";

/** @type {import("jsonc-parser").FormattingOptions} */
const FORMAT = { insertSpaces: true, tabSize: 2, eol: "\n" };

/**
 * @param {string} text
 * @param {string} [file]
 * @returns {Record<string, any>}
 */
export function parseJsonc(text, file = "<input>") {
  /** @type {import("jsonc-parser").ParseError[]} */
  const errors = [];
  const data = parse(text, errors, { allowTrailingComma: true, disallowComments: false });
  const first = errors[0];
  if (first) {
    const before = text.slice(0, first.offset).split("\n");
    const line = before.length;
    const column = (before.at(-1)?.length ?? 0) + 1;
    throw new EdgeError(`${file}:${line}:${column}: ${printParseErrorCode(first.error)}`);
  }
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    throw new EdgeError(`${file}: the top level must be an object`);
  }
  return data;
}

/** @param {string} file */
export function readConfig(file) {
  const text = readFileSync(file, "utf8");
  return { text, data: parseJsonc(text, file) };
}

/**
 * Index of the binding entry in `data[section]` whose `key` equals `name`, or -1.
 * @param {Record<string, any>} data
 * @param {string} section  e.g. "kv_namespaces"
 * @param {string} key      e.g. "binding"
 * @param {string} name     e.g. "DENYLIST"
 */
export function bindingIndex(data, section, key, name) {
  const list = data[section];
  return Array.isArray(list) ? list.findIndex((b) => b && b[key] === name) : -1;
}

/**
 * @typedef {{ path: (string | number)[], value: unknown, label: string }} ConfigEdit
 */

/**
 * @param {Record<string, any>} data
 * @param {(string | number)[]} path
 */
function getPath(data, path) {
  /** @type {any} */
  let node = data;
  for (const key of path) {
    if (node === null || typeof node !== "object") return undefined;
    node = node[key];
  }
  return node;
}

/**
 * Applies the edits whose value differs from what the text already holds.
 * Returns the new text and the labels of the edits that changed something.
 * @param {string} text
 * @param {ConfigEdit[]} edits
 * @returns {{ text: string, changed: string[] }}
 */
export function applyConfigEdits(text, edits) {
  let out = text;
  /** @type {string[]} */
  const changed = [];
  for (const edit of edits) {
    if (deepEqual(getPath(parseJsonc(out), edit.path), edit.value)) continue;
    out = applyEdits(out, modify(out, edit.path, edit.value, { formattingOptions: FORMAT }));
    changed.push(edit.label);
  }
  return { text: out, changed };
}
