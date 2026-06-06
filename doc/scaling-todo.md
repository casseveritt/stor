# Scaling Issues and Remediation

Current design works well at single-digit contacts and a small registry.
This document tracks what breaks at 1000 contacts or 1M registry nodes,
and what to do about it.

---

## Critical at 1000 contacts

### 1. Unbounded concurrent feed fetch
**File:** `client/main.py:692`

```python
raw_results = await asyncio.gather(*[_fetch_one(url) for url in servers])
```

At 1000 contacts this launches 1001 simultaneous outbound HTTP connections
on every page load.  httpx's connection pool saturates, OS file descriptors
run low, and page-load time becomes "slowest contact wins."

**Fix:** wrap `_fetch_one` with `asyncio.Semaphore(20)` so at most 20
contacts are fetched concurrently.  Contact ordering + caching means the
first 20 slots serve the most-recently-active contacts while the rest wait.

---

### 2. Startup photo refresh fires N concurrent requests
**File:** `client/main.py` — `_refresh_contact_photos()`

Same problem as #1 but at startup: one HTTP request per contact, all fired
simultaneously.

**Fix:** same `asyncio.Semaphore(10)` pattern inside `_refresh_contact_photos`.

---

### 3. Contact list stored as JSON — O(n) scans on every request
**File:** `client/main.py` — 29 linear scans over `config.contacts`

Every request that touches contacts (feed fetch, photo proxy, DM thread
enrichment, add/remove/patch) runs `next(c for c in config.contacts if
c.url == url)` or similar.  These are individually fast but compound:
`_fetch_one` is called N times during feed fetch, each doing an O(n) scan
→ O(n²) total.  Every contact save also rewrites the full JSON blob.

**Fix:** build two lookup dicts at startup inside `create_app` and keep
them in sync on mutations:

```python
_contact_by_url:     dict[str, ContactEntry]
_contact_by_node_id: dict[str, ContactEntry]
```

Replace all `next(c for c in config.contacts if c.url == url)` with
`_contact_by_url.get(url)`, and similarly for node_id.  Update dicts in
`api_add_contact`, `api_remove_contact`, `api_patch_contact`,
`api_refresh_contact_node_ids`, `_startup_consistency_check`, and
`_refresh_url_for_pubkey`.

---

## Critical at 1M registry nodes

### 4. Registry LIKE search is a full table scan
**File:** `registry/main.py:1232`

```python
WHERE (LOWER(username) LIKE ? OR LOWER(display_name) LIKE ?)
```

`%substring%` LIKE cannot use a B-tree index.  At 1M rows each search
scans the whole table.

**Fix:** add SQLite FTS5 virtual table over `username` and `display_name`.
Replace the LIKE query with an FTS5 `MATCH` query.  This also enables
prefix queries and ranking by relevance.

---

### 5. Registry is a single SQLite writer — heartbeat storm on restart
**File:** `registry/main.py`

1M nodes × hourly heartbeat = ~278 writes/second sustained.  SQLite WAL
handles this on fast storage, but a full restart causes a thundering herd:
all nodes retry Tang at 2s/7s/22s simultaneously, flooding the registry.
Our new 60s slow-retry phase reduces the herd size but doesn't eliminate
the initial spike.

**Fix (short term):** add random jitter (0–30s) to Tang retry delays on
the node side so restarts spread their load over half a minute.

**Fix (long term):** if registry load becomes a real bottleneck, shard by
`node_id` prefix across multiple SQLite files (easy to implement, no
external dependencies) or migrate to PostgreSQL.

---

## Significant at either scale

### 6. `posts.created_at` has no index
**File:** `server/db.py`

The primary feed query `ORDER BY p.created_at DESC LIMIT ?` does a full
table scan.  At 1M posts per node this becomes the dominant cost of every
feed request.

**Fix:** add schema version 11:

```python
con.execute("CREATE INDEX IF NOT EXISTS posts_created_at_idx ON posts (created_at DESC)")
```

---

### 7. Aggregate feed pagination is approximate (per-source cursors needed)
**File:** `client/main.py` — `api_feed`

The `cursor` parameter is a single `created_at` timestamp applied uniformly
to all contacts.  A contact that posts rarely is re-fetched in full on
every page turn; a very prolific contact's older posts may be skipped.
Correct multi-source feed pagination requires a cursor map:

```json
{"https://alice.example.com": "1749123456000000000",
 "https://bob.example.com":   "1749099123000000000"}
```

**Fix:** encode/decode a per-source cursor map (JSON → base64) in the
`next_cursor` field.  Each `_fetch_one` call passes only its own cursor.
Breaking change to the client API.

---

### 8. `_incoming_dm_updates` grows unbounded when client subscriber is down
**File:** `server/dm.py`

The list is trimmed at 200 items (dropping the oldest 100 when full).
If the client SSE subscriber is disconnected for a long time many events
are silently discarded.  The `/dm/updates` poll endpoint drains the list
so a reconnecting subscriber misses events that were trimmed.

**Fix:** The actual messages are durable in the DB; this list is just a
notification hint.  Make it explicit: if the subscriber has been
disconnected for more than N minutes, on reconnect have the client scan
`dm_threads` for unread messages rather than relying on the hint list.

---

## Status

| # | Issue                              | Severity          | Status  |
|---|------------------------------------|-------------------|---------|
| 1 | Unbounded feed fetch concurrency   | Critical @1k      | open    |
| 2 | Unbounded photo refresh            | Critical @1k      | open    |
| 3 | O(n) contact list scans            | Significant @1k   | open    |
| 4 | Registry LIKE full table scan      | Critical @1M      | open    |
| 5 | Registry single-writer herd        | Significant @1M   | open    |
| 6 | posts.created_at missing index     | Significant       | open    |
| 7 | Approximate feed pagination        | Moderate          | open    |
| 8 | DM hint list lost on disconnect    | Moderate          | open    |
