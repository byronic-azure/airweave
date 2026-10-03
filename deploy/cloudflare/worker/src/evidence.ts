/**
 * Evidence log in D1 with a SHA-256 hash chain.
 *
 * Every blocked, rate-limited or soft-flagged request becomes one row in
 * `evidence_events`. Rows form a hash chain:
 *
 *   hash = SHA-256 hex( prev_hash + "\n" + canonicalJSON(row without `hash`) )
 *
 * with the first row chained to 64 zeros. `seq` is chosen by the writer as
 * head.seq + 1 and inserted explicitly, so two writers appending at once collide
 * on the primary key (and the unique `prev_hash` index) instead of forking the
 * chain. Appends from this isolate are serialised through one queue, so a burst
 * of flagged requests never races itself; a writer in another isolate is absorbed
 * by retries with jittered backoff. A row that still cannot be written is logged
 * in full as `evidence_write_failed` (with `dropped: true`), so a gap in the chain
 * is at least visible in Workers Logs.
 *
 * What the chain detects: `verifyChain` recomputes every digest from the genesis
 * value and localises the first in-place edit (`hash_mismatch`), re-link
 * (`chain_break`) or gap (`sequence_gap`) to a `break_at` seq. What it cannot
 * detect: truncation of the tail (the newest rows deleted, after which the next
 * append silently reuses the freed seq) or a full recompute by anyone with D1
 * write access, because the chain carries no secret and no external anchor. It
 * is a consistency check, not proof of integrity. To close that gap, record the
 * head `{seq, hash}` from `/evidence/verify` (or from the `evidence_recorded`
 * log line) somewhere outside D1 and compare it on the next verify.
 *
 * Without an EVIDENCE_DB binding the record is written to the console instead
 * (visible in `wrangler tail` / Workers Logs).
 *
 * Normal, unflagged traffic never touches this module.
 */
import type { Env } from "./env";
import { canonicalJSON, logEvent, sha256Hex } from "./util";

export const GENESIS_HASH = "0".repeat(64);
/** Attempts against writers in other isolates before an append is given up and logged. */
const APPEND_ATTEMPTS = 12;
/** Backoff between attempts: BASE * 2^attempt, capped at MAX, with equal jitter. */
const BACKOFF_BASE_MS = 5;
const BACKOFF_MAX_MS = 250;
const VERIFY_PAGE_SIZE = 500;

export type Verdict = "blocked" | "rate_limited" | "flagged";

export interface EvidenceInput {
  requestId: string;
  principal: string;
  clientIp: string;
  method: string;
  path: string;
  reason: string;
  verdict: Verdict;
  /** Raw TypeSafe answers plus autoblock decision, if a judgement was obtained. */
  judgement?: unknown;
}

/** One row of `evidence_events`; `hash` covers every other field. */
export interface EvidenceRow {
  seq: number;
  event_id: string;
  ts: string;
  request_id: string;
  principal: string;
  client_ip: string;
  method: string;
  path: string;
  reason: string;
  verdict: string;
  judgement_json: string | null;
  prev_hash: string;
  hash: string;
}

export type UnhashedRow = Omit<EvidenceRow, "hash">;

export async function evidenceHash(row: UnhashedRow): Promise<string> {
  const fields: UnhashedRow = {
    seq: row.seq,
    event_id: row.event_id,
    ts: row.ts,
    request_id: row.request_id,
    principal: row.principal,
    client_ip: row.client_ip,
    method: row.method,
    path: row.path,
    reason: row.reason,
    verdict: row.verdict,
    judgement_json: row.judgement_json,
    prev_hash: row.prev_hash,
  };
  return sha256Hex(`${row.prev_hash}\n${canonicalJSON(fields)}`);
}

function isConflict(err: unknown): boolean {
  return /UNIQUE|constraint|conflict/i.test(String(err instanceof Error ? err.message : err));
}

async function readHead(db: D1Database): Promise<{ seq: number; hash: string } | null> {
  return db.prepare("SELECT seq, hash FROM evidence_events ORDER BY seq DESC LIMIT 1").first<{
    seq: number;
    hash: string;
  }>();
}

// Appends from concurrent requests in this isolate (each one a ctx.waitUntil
// task) go through this queue one at a time, so they never race each other for
// the head. The retry loop in appendEvidence only has to absorb other isolates.
let appendQueue: Promise<unknown> = Promise.resolve();

function serialised<T>(task: () => Promise<T>): Promise<T> {
  const run = appendQueue.then(task);
  appendQueue = run.catch(() => undefined);
  return run;
}

/** Equal-jitter exponential backoff. Jitter comes from crypto, never Math.random. */
function backoffMs(attempt: number): number {
  const delay = Math.min(BACKOFF_BASE_MS * 2 ** attempt, BACKOFF_MAX_MS);
  const half = Math.floor(delay / 2);
  const random = crypto.getRandomValues(new Uint32Array(1))[0] ?? 0;
  return half + (random % (delay - half + 1));
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * One attempt: read the head, hash, insert. Throws on a conflict with another
 * writer. Exported so tests can play a writer in another isolate, which the
 * in-isolate queue does not cover.
 */
export async function appendEvidenceOnce(
  db: D1Database,
  input: EvidenceInput,
  now: Date = new Date(),
): Promise<{ seq: number; hash: string }> {
  const head = await readHead(db);
  const unhashed: UnhashedRow = {
    seq: head ? head.seq + 1 : 1,
    event_id: crypto.randomUUID(),
    ts: now.toISOString(),
    request_id: input.requestId,
    principal: input.principal,
    client_ip: input.clientIp,
    method: input.method,
    path: input.path,
    reason: input.reason,
    verdict: input.verdict,
    judgement_json: input.judgement === undefined ? null : canonicalJSON(input.judgement),
    prev_hash: head ? head.hash : GENESIS_HASH,
  };
  const row: EvidenceRow = { ...unhashed, hash: await evidenceHash(unhashed) };
  await db
    .prepare(
      `INSERT INTO evidence_events
         (seq, event_id, ts, request_id, principal, client_ip, method, path, reason, verdict,
          judgement_json, prev_hash, hash)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)`,
    )
    .bind(
      row.seq,
      row.event_id,
      row.ts,
      row.request_id,
      row.principal,
      row.client_ip,
      row.method,
      row.path,
      row.reason,
      row.verdict,
      row.judgement_json,
      row.prev_hash,
      row.hash,
    )
    .run();
  return { seq: row.seq, hash: row.hash };
}

/**
 * Appends one row. Serialised against every other append in this isolate, and
 * retried with jittered backoff when a writer in another isolate extended the
 * chain first. Throws only when every attempt collided.
 */
export function appendEvidence(
  db: D1Database,
  input: EvidenceInput,
  now: Date = new Date(),
): Promise<{ seq: number; hash: string }> {
  return serialised(async () => {
    let lastError: unknown;
    for (let attempt = 0; attempt < APPEND_ATTEMPTS; attempt++) {
      if (attempt > 0) await sleep(backoffMs(attempt - 1));
      try {
        return await appendEvidenceOnce(db, input, now);
      } catch (err) {
        if (!isConflict(err)) throw err;
        lastError = err;
      }
    }
    throw new Error(`evidence append contention after ${APPEND_ATTEMPTS} attempts: ${String(lastError)}`);
  });
}

/**
 * Entry point used from `ctx.waitUntil`. Never throws: a failure to persist
 * evidence is logged with the whole record (`dropped: true`), not surfaced to
 * the client and never discarded silently.
 */
export async function recordEvidence(env: Env, input: EvidenceInput): Promise<void> {
  if (!env.EVIDENCE_DB) {
    logEvent("log", "evidence", {
      ...input,
      judgement: input.judgement ?? null,
      note: "EVIDENCE_DB not bound; record not persisted",
    });
    return;
  }
  try {
    const { seq, hash } = await appendEvidence(env.EVIDENCE_DB, input);
    logEvent("log", "evidence_recorded", { request_id: input.requestId, verdict: input.verdict, seq, hash });
  } catch (err) {
    logEvent("error", "evidence_write_failed", {
      request_id: input.requestId,
      error: String(err),
      dropped: true,
      record: { ...input, judgement: input.judgement ?? null },
    });
  }
}

export type VerifyResult =
  | { ok: true; count: number; head: { seq: number; hash: string } | null }
  | {
      ok: false;
      count: number;
      head: { seq: number; hash: string } | null;
      break_at: number;
      reason: "sequence_gap" | "chain_break" | "hash_mismatch";
    };

/**
 * Walks the whole chain in pages and recomputes every digest. A consistency
 * check over the rows that exist: see the module comment for what it cannot see.
 */
export async function verifyChain(db: D1Database): Promise<VerifyResult> {
  let prevHash = GENESIS_HASH;
  let expectedSeq = 1;
  let count = 0;
  let head: { seq: number; hash: string } | null = null;
  let cursor = 0;

  for (;;) {
    const page = await db
      .prepare("SELECT * FROM evidence_events WHERE seq > ?1 ORDER BY seq ASC LIMIT ?2")
      .bind(cursor, VERIFY_PAGE_SIZE)
      .all<EvidenceRow>();
    const rows = page.results;
    if (rows.length === 0) break;
    for (const row of rows) {
      count++;
      const fail = (reason: "sequence_gap" | "chain_break" | "hash_mismatch"): VerifyResult => ({
        ok: false,
        count,
        head,
        break_at: row.seq,
        reason,
      });
      if (row.seq !== expectedSeq) return fail("sequence_gap");
      if (row.prev_hash !== prevHash) return fail("chain_break");
      const { hash, ...unhashed } = row;
      if ((await evidenceHash(unhashed)) !== hash) return fail("hash_mismatch");
      prevHash = hash;
      head = { seq: row.seq, hash };
      expectedSeq++;
      cursor = row.seq;
    }
    if (rows.length < VERIFY_PAGE_SIZE) break;
  }
  return { ok: true, count, head };
}
