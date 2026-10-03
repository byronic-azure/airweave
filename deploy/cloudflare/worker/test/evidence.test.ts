import { env as testEnv } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  GENESIS_HASH,
  appendEvidence,
  appendEvidenceOnce,
  evidenceHash,
  recordEvidence,
  verifyChain,
  type EvidenceInput,
  type EvidenceRow,
} from "../src/evidence";
import { ORIGIN, FetchStub, gatewayRequest, makeEnv, resetStorage, run } from "./helpers";

const db = () => testEnv.EVIDENCE_DB;

function input(n: number, extra: Partial<EvidenceInput> = {}): EvidenceInput {
  return {
    requestId: `req-${n}`,
    principal: "apikey:0123456789abcdef",
    clientIp: "203.0.113.7",
    method: "GET",
    path: `/items?q=${n}`,
    reason: "soft:sqli_signature",
    verdict: "flagged",
    ...extra,
  };
}

async function allRows(): Promise<EvidenceRow[]> {
  return (await db().prepare("SELECT * FROM evidence_events ORDER BY seq").all<EvidenceRow>()).results;
}

describe("evidence chain", () => {
  beforeEach(resetStorage);

  it("starts empty and verifies", async () => {
    expect(await verifyChain(db())).toEqual({ ok: true, count: 0, head: null });
  });

  it("links every row to the previous one and verifies", async () => {
    await appendEvidence(db(), input(1));
    await appendEvidence(db(), input(2, { judgement: { answers: { is_probe: { noul: 0.2 } } } }));
    await appendEvidence(db(), input(3, { verdict: "blocked" }));

    const rows = await allRows();
    expect(rows.map((r) => r.seq)).toEqual([1, 2, 3]);
    expect(rows[0]?.prev_hash).toBe(GENESIS_HASH);
    expect(rows[1]?.prev_hash).toBe(rows[0]?.hash);
    expect(rows[2]?.prev_hash).toBe(rows[1]?.hash);
    expect(rows[1]?.judgement_json).toBe('{"answers":{"is_probe":{"noul":0.2}}}');
    for (const row of rows) {
      const { hash, ...unhashed } = row;
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
      expect(await evidenceHash(unhashed)).toBe(hash);
    }
    expect(await verifyChain(db())).toEqual({ ok: true, count: 3, head: { seq: 3, hash: rows[2]?.hash } });
  });

  it("localises a tampered row", async () => {
    for (let i = 1; i <= 4; i++) await appendEvidence(db(), input(i));
    await db().prepare("UPDATE evidence_events SET path = '/tampered' WHERE seq = 2").run();
    expect(await verifyChain(db())).toMatchObject({ ok: false, break_at: 2, reason: "hash_mismatch", count: 2 });
  });

  it("localises a deleted row", async () => {
    for (let i = 1; i <= 3; i++) await appendEvidence(db(), input(i));
    await db().prepare("DELETE FROM evidence_events WHERE seq = 2").run();
    expect(await verifyChain(db())).toMatchObject({ ok: false, break_at: 3, reason: "sequence_gap" });
  });

  it("detects a re-linked row whose own hash was recomputed", async () => {
    for (let i = 1; i <= 2; i++) await appendEvidence(db(), input(i));
    const rows = await allRows();
    const { hash: _old, ...unhashed } = rows[1] as EvidenceRow;
    const forged = { ...unhashed, prev_hash: "f".repeat(64) };
    const forgedHash = await evidenceHash(forged);
    await db()
      .prepare("UPDATE evidence_events SET prev_hash = ?1, hash = ?2 WHERE seq = 2")
      .bind(forged.prev_hash, forgedHash)
      .run();
    expect(await verifyChain(db())).toMatchObject({ ok: false, break_at: 2, reason: "chain_break" });
  });

  it("retries when a writer in another isolate extended the chain first", async () => {
    let injected = false;
    const real = db();
    // Wrap the database so the first INSERT finds a row that appeared after the head
    // was read. The competitor uses appendEvidenceOnce: another isolate does not share
    // this isolate's append queue, so it must not wait on it.
    const racy = new Proxy(real, {
      get(target, prop, receiver) {
        if (prop !== "prepare") return Reflect.get(target, prop, receiver);
        return (sql: string) => {
          const stmt = target.prepare(sql);
          if (!sql.includes("INSERT") || injected) return stmt;
          injected = true;
          return new Proxy(stmt, {
            get(s, p, r) {
              if (p !== "bind") return Reflect.get(s, p, r);
              return (...args: unknown[]) => {
                const bound = s.bind(...args);
                return {
                  ...bound,
                  async run() {
                    await appendEvidenceOnce(real, input(99));
                    return bound.run();
                  },
                };
              };
            },
          });
        };
      },
    });
    await appendEvidence(racy as D1Database, input(1));
    const rows = await allRows();
    expect(rows.map((r) => r.request_id)).toEqual(["req-99", "req-1"]);
    expect(await verifyChain(real)).toMatchObject({ ok: true, count: 2 });
  });

  it("keeps every row when many appends race inside one isolate", async () => {
    // Every flagged request of a burst schedules its own append in ctx.waitUntil;
    // they must all land, in some order, and the chain must still be linear.
    const n = 25;
    const results = await Promise.allSettled(
      Array.from({ length: n }, (_, i) => appendEvidence(db(), input(i + 1))),
    );
    expect(results.filter((r) => r.status === "rejected")).toHaveLength(0);
    const rows = await allRows();
    expect(rows).toHaveLength(n);
    expect(new Set(rows.map((r) => r.request_id)).size).toBe(n);
    expect(await verifyChain(db())).toMatchObject({ ok: true, count: n, head: { seq: n } });
  });

  it("never drops a record silently: a failed write is logged in full", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const broken = {
      prepare: () => {
        throw new Error("D1_ERROR: database is locked: SQLITE_BUSY");
      },
    } as unknown as D1Database;
    try {
      await recordEvidence(makeEnv({ EVIDENCE_DB: broken }), input(8));
      const line = error.mock.calls.map((c) => String(c[0])).find((l) => l.includes('"evidence_write_failed"'));
      expect(line).toBeDefined();
      expect(JSON.parse(line as string)).toMatchObject({
        event: "evidence_write_failed",
        request_id: "req-8",
        dropped: true,
        record: { requestId: "req-8", verdict: "flagged", path: "/items?q=8", judgement: null },
      });
    } finally {
      error.mockRestore();
    }
  });

  it("falls back to console logging without a database", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      await recordEvidence(makeEnv(), input(7));
      const line = log.mock.calls.map((c) => String(c[0])).find((l) => l.includes('"event":"evidence"'));
      expect(line).toBeDefined();
      expect(JSON.parse(line as string)).toMatchObject({ event: "evidence", requestId: "req-7", verdict: "flagged" });
    } finally {
      log.mockRestore();
    }
    expect(await verifyChain(db())).toEqual({ ok: true, count: 0, head: null });
  });
});

describe("GET /evidence/verify", () => {
  let stub: FetchStub;
  beforeEach(async () => {
    await resetStorage();
    stub = new FetchStub().echo(ORIGIN);
  });
  afterEach(() => stub.restore());

  it("requires authentication", async () => {
    const res = await run(gatewayRequest("/evidence/verify", { apiKey: null }), makeEnv({ EVIDENCE_DB: db() }));
    expect(res.status).toBe(401);
  });

  it("reports the chain state and a break", async () => {
    const env = makeEnv({ EVIDENCE_DB: db() });
    await run(gatewayRequest("/a/%252e%252e/etc"), env);
    await run(gatewayRequest("/items?q=1%27%20or%201%3D1"), env);
    let res = await run(gatewayRequest("/evidence/verify"), env);
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ok: true, count: 2, head: { seq: 2 } });

    await db().prepare("UPDATE evidence_events SET verdict = 'flagged' WHERE seq = 1").run();
    res = await run(gatewayRequest("/evidence/verify"), env);
    expect(await res.json()).toMatchObject({ ok: false, break_at: 1, reason: "hash_mismatch" });
    expect(stub.callsTo(ORIGIN)).toHaveLength(1); // only the soft-flagged request was proxied
  });

  it("records every event of a concurrent burst of blocked requests", async () => {
    const env = makeEnv({ EVIDENCE_DB: db() });
    const n = 20;
    const responses = await Promise.all(
      Array.from({ length: n }, (_, i) => run(gatewayRequest(`/a/%252e%252e/etc/${i}`, { apiKey: null }), env)),
    );
    expect(responses.map((r) => r.status)).toEqual(Array(n).fill(400));
    const res = await run(gatewayRequest("/evidence/verify"), env);
    expect(await res.json()).toMatchObject({ ok: true, count: n, head: { seq: n } });
    expect(stub.callsTo(ORIGIN)).toHaveLength(0);
  });

  it("answers 503 when no database is bound", async () => {
    const res = await run(gatewayRequest("/evidence/verify"), makeEnv());
    expect(res.status).toBe(503);
    expect(((await res.json()) as { error: string }).error).toBe("evidence_db_not_configured");
  });

  it("answers 503 with a hint when the migrations have not been applied", async () => {
    const unmigrated = {
      prepare: () => {
        throw new Error("D1_ERROR: no such table: evidence_events: SQLITE_ERROR");
      },
    } as unknown as D1Database;
    const res = await run(gatewayRequest("/evidence/verify"), makeEnv({ EVIDENCE_DB: unmigrated }));
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: string; message: string };
    expect(body.error).toBe("evidence_db_not_migrated");
    expect(body.message).toContain("wrangler d1 migrations apply");
  });
});
