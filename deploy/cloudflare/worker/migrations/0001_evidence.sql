-- Hash-chained evidence log for airweave-edge-gateway.
--
-- Each row is chained to the previous one:
--   hash = SHA-256 hex( prev_hash + "\n" + canonical JSON of every column except hash )
-- The first row's prev_hash is 64 zeros. `seq` is assigned by the Worker as
-- head.seq + 1 (explicit insert into the AUTOINCREMENT column), so two writers
-- racing to append collide on the primary key and the unique prev_hash index
-- instead of forking the chain; the Worker serialises its own appends and
-- retries against writers in other isolates.
--
-- GET /evidence/verify on the gateway recomputes every digest and localises an
-- in-place edit, a re-linked row or a gap. It is a consistency check over the
-- rows that exist: it cannot detect the newest rows being deleted (the next
-- append reuses the freed seq) or a full recompute by anyone with write access
-- to this database, because the chain has no secret and no external anchor.
-- Keep the head {seq, hash} outside D1 to detect those.
CREATE TABLE IF NOT EXISTS evidence_events (
  seq            INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id       TEXT    NOT NULL UNIQUE,
  ts             TEXT    NOT NULL,
  request_id     TEXT    NOT NULL,
  principal      TEXT    NOT NULL,
  client_ip      TEXT    NOT NULL,
  method         TEXT    NOT NULL,
  path           TEXT    NOT NULL,
  reason         TEXT    NOT NULL,
  verdict        TEXT    NOT NULL,
  judgement_json TEXT,
  prev_hash      TEXT    NOT NULL,
  hash           TEXT    NOT NULL
);

-- A given head can only be extended once; a second concurrent append fails and retries.
CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_events_prev_hash ON evidence_events (prev_hash);
CREATE INDEX IF NOT EXISTS idx_evidence_events_ts ON evidence_events (ts);
CREATE INDEX IF NOT EXISTS idx_evidence_events_principal ON evidence_events (principal);
