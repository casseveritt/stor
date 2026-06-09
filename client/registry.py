"""Registry node lookup with multi-tier caching: memory → DB → peers → registry.

Usage
-----
At application startup (inside create_app), call once::

    registry.init(get_registry_url=..., get_contacts=..., get_db=...)
    registry.set_pub_key(b64_key)   # after fetching /meta

Then from anywhere::

    record = await registry.lookup(node_id)   # raises KeyError if not found
    cached  = registry.get_cached(node_id)    # None if absent / stale
"""
import asyncio
import base64
import json
import logging
import time

import httpx

log = logging.getLogger("contacc")

class RegistryLookup:
    TTL = 4 * 3600      # serve from cache if younger than this
    MAX_AGE = 8 * 3600  # reject peer-served records older than this

    def __init__(self):
        self._cache: dict = {}          # node_id → (record, cached_at_float)
        self._pub_key: str | None = None
        self._get_registry_url = lambda: ""
        self._get_contacts = lambda: []
        self._get_db = lambda: None

    def init(self, *, get_registry_url, get_contacts, get_db):
        self._get_registry_url = get_registry_url
        self._get_contacts = get_contacts
        self._get_db = get_db

    async def _ensure_pub_key(self):
        if self._pub_key:
            return
        try:
            async with httpx.AsyncClient() as hc:
                r = await hc.get(self._get_registry_url() + "/meta", timeout=5)
            if r.is_success:
                pk = r.json().get("public_key")
                if pk:
                    self._pub_key = pk
        except Exception:
            pass

    # ── verification ─────────────────────────────────────────────────────────

    def _verify(self, record: dict) -> bool:
        pub_b64 = self._pub_key
        if not pub_b64:
            return True  # accept provisionally until we have the key
        queried_at = record.get("queried_at")
        sig = record.get("registry_signature")
        if not queried_at or not sig:
            return False
        canonical = (
            f"contacc:node-record:{queried_at}:{record.get('node_id','')}:"
            f"{record.get('server_url','')}:"
            f"{record.get('handle','') or ''}:{record.get('display_name','') or ''}"
        )
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64 + "=="))
            pub.verify(base64.b64decode(sig + "=="), canonical.encode())
            return True
        except Exception:
            return False

    # ── cache ────────────────────────────────────────────────────────────────

    def _store(self, node_id: str, record: dict, now: float) -> dict:
        if not self._verify(record):
            raise ValueError("invalid registry signature")
        qt = record.get("queried_at", now)
        self._cache[node_id] = (record, qt)
        try:
            db = self._get_db()
            if db is not None:
                db.execute(
                    "INSERT OR REPLACE INTO registry_cache (node_id, record, cached_at)"
                    " VALUES (?, ?, ?)",
                    (node_id, json.dumps(record), int(time.time_ns())),
                )
                db.commit()
        except Exception:
            pass
        return record

    # ── lookup ───────────────────────────────────────────────────────────────

    async def lookup(self, node_id: str) -> dict:
        """Return a registry record for node_id, filling the cache as a side effect.

        Search order: memory cache → DB cache → peer caches → registry.
        Raises KeyError if the node cannot be found anywhere.
        """
        await self._ensure_pub_key()
        now = time.time()

        # 1a. Memory cache
        entry = self._cache.get(node_id)
        if entry:
            record, cached_at = entry
            if now - cached_at < self.TTL:
                return record

        # 1b. Persistent DB cache
        try:
            db = self._get_db()
            if db is not None:
                row = db.execute(
                    "SELECT record FROM registry_cache WHERE node_id = ?", (node_id,)
                ).fetchone()
                if row:
                    rec = json.loads(row[0])
                    qt = rec.get("queried_at", 0)
                    if now - qt < self.TTL and self._verify(rec):
                        self._cache[node_id] = (rec, qt)
                        return rec
        except Exception:
            pass

        # 2. Peer caches (parallel, first valid response wins)
        async def _try_peer(url: str):
            try:
                async with httpx.AsyncClient() as hc:
                    r = await hc.get(url.rstrip("/") + "/registry-cache/" + node_id, timeout=2)
                if r.is_success:
                    rec = r.json()
                    qt = rec.get("queried_at", 0)
                    if now - qt < self.MAX_AGE and self._verify(rec):
                        return rec
            except Exception:
                pass
            return None

        contacts = self._get_contacts()
        peer_tasks = [_try_peer(c.url) for c in contacts if c.url]
        if peer_tasks:
            for coro in asyncio.as_completed(peer_tasks):
                result = await coro
                if result:
                    return self._store(node_id, result, now)

        # 3. Registry direct
        reg = self._get_registry_url()
        if reg:
            try:
                async with httpx.AsyncClient() as hc:
                    r = await hc.get(f"{reg}/nodes/{node_id}", timeout=5)
                if r.is_success:
                    return self._store(node_id, r.json(), now)
            except Exception:
                pass

        raise KeyError(f"Node {node_id} not found in registry")


# Module-level singleton — importable from anywhere after init() is called.
registry = RegistryLookup()
