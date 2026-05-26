"""Registry lookup client with TTL-based in-memory cache."""
import time
from typing import Optional

import httpx

REGISTRY_URL = "https://starkville.hopto.org:8421"

_cache: dict[str, tuple[dict, float]] = {}  # username → (record, expiry)


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
