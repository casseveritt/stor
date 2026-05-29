"""Registry lookup client with TTL-based in-memory cache."""
import os
import time
from typing import Optional

import httpx

REGISTRY_URL = os.environ.get("CONTACC_REGISTRY_URL", "https://strk.xyzw.us:8421")

_cache: dict[str, tuple[dict, float]] = {}  # username → (record, expiry)
_key_cache: dict[str, tuple[dict, float]] = {}  # public_key → (record, expiry)


async def lookup(username: str, registry_url: str = REGISTRY_URL) -> Optional[dict]:
    """Return the registry record for username, serving from cache when fresh."""
    now = time.time()
    cached = _cache.get(username)
    if cached:
        record, expiry = cached
        if now < expiry:
            return record

    async with httpx.AsyncClient() as hc:
        try:
            r = await hc.get(f"{registry_url}/lookup/{username}", timeout=10.0)
        except httpx.RequestError:
            return cached[0] if cached else None  # serve stale on network error

    if r.status_code == 404:
        return None
    r.raise_for_status()
    record = r.json()
    _cache[username] = (record, now + record.get("ttl", 14400))
    return record


async def lookup_by_key(public_key: str, registry_url: str = REGISTRY_URL) -> Optional[dict]:
    """Return the registry record for a public key, serving from cache when fresh."""
    now = time.time()
    cached = _key_cache.get(public_key)
    if cached:
        record, expiry = cached
        if now < expiry:
            return record

    async with httpx.AsyncClient() as hc:
        try:
            r = await hc.get(f"{registry_url}/lookup-by-key", params={"public_key": public_key}, timeout=10.0)
        except httpx.RequestError:
            return cached[0] if cached else None

    if r.status_code == 404:
        return None
    if not r.is_success:
        return cached[0] if cached else None
    record = r.json()
    _key_cache[public_key] = (record, now + record.get("ttl", 14400))
    return record
