/**
 * Cheap, deterministic request inspection. No network, no bindings.
 *
 * Hard rules reject the request with 400 before any authentication work:
 *   - method outside GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD
 *   - path traversal (`..` segments, including percent- and double-encoded forms).
 *     Note the boundary: Cloudflare's edge and the Workers runtime resolve plain and
 *     single-percent-encoded dot segments (`/a/../b`, `/a/%2e%2e/b`) before the Worker
 *     runs, so those never reach the Worker or the origin. The rule covers what does
 *     arrive: double-encoded, `..;`, backslash and invalid-escape-shielded spellings.
 *   - null bytes in the URL or a header value
 *
 * Soft signals never block. They tag the request so it gets an evidence row
 * (and, when configured, a TypeSafe judgement) and are forwarded to the origin as
 * `X-Airweave-Suspicion` for correlation. They are intentionally loose: a false
 * positive costs one evidence row, a false negative costs nothing the backend's
 * own validation would not catch.
 */
import { ALLOWED_METHODS } from "./util";

export interface Inspection {
  /** Signals that reject the request with 400. */
  hard: string[];
  /** Signals that only tag the request. */
  soft: string[];
}

/** Longer URLs are tagged (Cloudflare itself rejects URLs over 16 KB at the edge). */
export const MAX_URL_LENGTH = 4096;
export const MAX_HEADER_VALUE_LENGTH = 8192;
export const MAX_HEADER_COUNT = 100;
/** How many times to percent-decode when looking for encoded traversal. */
const DECODE_ROUNDS = 3;

const SQLI_SIGNATURES: readonly RegExp[] = [
  /\bunion\b[\s/*]+(all[\s/*]+)?select\b/, // UNION SELECT, UNION/**/ALL/**/SELECT
  /['"]\s*(or|and)\s+['"\d]/, // ' or 1, " and "a
  /\b(or|and)\s+\d+\s*=\s*\d+/, // or 1=1
  /\b(sleep|benchmark|pg_sleep|load_file)\s*\(/, // time-based / file read
  /\bwaitfor\s+delay\b/,
  /\binformation_schema\b/,
  /;\s*(drop|alter|truncate|delete|insert|update|exec)\b/, // stacked statements
  /\binto\s+(out|dump)file\b/,
  /'\s*(--|#)/, // quote followed by a comment
  /\/\*[\s\S]{0,64}\*\//, // inline comment
];

const SHELL_SIGNATURES: readonly RegExp[] = [
  /[;&|`]\s*(cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|zsh|python\d?|perl|php|powershell|cmd(\.exe)?)\b/,
  /\$\([^)]*\)/, // $(...)
  /`[^`]+`/, // backticks
  /\/etc\/(passwd|shadow|hosts|group)\b/,
  /\/bin\/(ba|z|da)?sh\b/,
  /\b(rm|chmod|chown)\s+-[a-z]+\s/,
];

const SCANNER_USER_AGENTS: readonly string[] = [
  "sqlmap",
  "nikto",
  "nmap",
  "masscan",
  "zgrab",
  "nuclei",
  "acunetix",
  "dirbuster",
  "gobuster",
  "wpscan",
  "ffuf",
  "feroxbuster",
];

interface Decoded {
  value: string;
  malformed: boolean;
}

const LENIENT_DECODER = new TextDecoder(); // non-fatal: invalid UTF-8 becomes U+FFFD

/**
 * One percent-decoding pass that never throws: every valid `%XX` becomes a byte,
 * byte runs are UTF-8 decoded with replacement characters for invalid sequences,
 * and a bare `%` stays literal. `decodeURIComponent` would abort on the first bad
 * escape, and one `%ff` anywhere in the path must not shield a `..` from inspection.
 */
function lenientDecodeOnce(input: string): Decoded {
  let out = "";
  let malformed = false;
  const bytes: number[] = [];
  const flush = (): void => {
    if (bytes.length === 0) return;
    const text = LENIENT_DECODER.decode(new Uint8Array(bytes));
    if (text.includes("\uFFFD")) malformed = true;
    out += text;
    bytes.length = 0;
  };
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (ch === "%") {
      const hex = input.slice(i + 1, i + 3);
      if (/^[0-9a-fA-F]{2}$/.test(hex)) {
        bytes.push(parseInt(hex, 16));
        i += 2;
        continue;
      }
      malformed = true;
    }
    flush();
    out += ch;
  }
  flush();
  return { value: out, malformed };
}

/** Percent-decode repeatedly (bounded) so `%252e%252e` becomes `..`; flags undecodable input. */
export function deepDecode(input: string, rounds = DECODE_ROUNDS): Decoded {
  let current = input;
  let malformed = false;
  for (let i = 0; i < rounds; i++) {
    const next = lenientDecodeOnce(current);
    malformed = malformed || next.malformed;
    if (next.value === current) break;
    current = next.value;
  }
  return { value: current, malformed };
}

/** True when any path segment is `..` (or the `..;` suffix trick) after normalising backslashes. */
export function hasTraversal(decodedPath: string): boolean {
  const segments = decodedPath.replace(/\\/g, "/").split("/");
  return segments.some((segment) => segment === ".." || segment.startsWith("..;"));
}

function containsNullByte(value: string): boolean {
  return value.includes("\0") || /%00/i.test(value);
}

function unique(list: string[]): string[] {
  return [...new Set(list)];
}

export function inspectRequest(request: Request, url: URL): Inspection {
  const hard: string[] = [];
  const soft: string[] = [];

  if (!ALLOWED_METHODS.has(request.method.toUpperCase())) hard.push("method_not_allowed");

  const rawTarget = url.pathname + url.search;
  if (containsNullByte(rawTarget)) hard.push("null_byte");
  for (const [, value] of request.headers) {
    if (value.includes("\0")) {
      hard.push("null_byte");
      break;
    }
  }

  const path = deepDecode(url.pathname);
  if (hasTraversal(path.value)) hard.push("path_traversal");
  if (path.malformed) soft.push("malformed_encoding");
  // `....//`-style variants are not traversal on a sane server, but nobody sends them by accident.
  if (!hard.includes("path_traversal") && /(^|\/)\.{3,}(\/|$)/.test(path.value)) soft.push("dot_segment_variant");

  if (request.url.length > MAX_URL_LENGTH) soft.push("long_url");

  let headerCount = 0;
  for (const [, value] of request.headers) {
    headerCount++;
    if (value.length > MAX_HEADER_VALUE_LENGTH) soft.push("long_header");
  }
  if (headerCount > MAX_HEADER_COUNT) soft.push("many_headers");

  if (/%0a|%0d/i.test(rawTarget)) soft.push("crlf_sequence");

  // Injection signatures are matched against the decoded, lower-cased path + query only.
  const target = deepDecode(rawTarget).value.replace(/\+/g, " ").toLowerCase();
  if (SQLI_SIGNATURES.some((re) => re.test(target))) soft.push("sqli_signature");
  if (SHELL_SIGNATURES.some((re) => re.test(target))) soft.push("shell_signature");

  const userAgent = (request.headers.get("User-Agent") ?? "").toLowerCase();
  if (SCANNER_USER_AGENTS.some((ua) => userAgent.includes(ua))) soft.push("scanner_user_agent");

  return { hard: unique(hard), soft: unique(soft) };
}
