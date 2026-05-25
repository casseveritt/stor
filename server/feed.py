"""QueryFeed endpoint — paginated asset metadata feed."""
import base64
import json
import time
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request

from .auth import AuthDep

router = APIRouter()

_PAGE_MAX = 200


def _decode_cursor(cursor: str | None) -> int | None:
    """Cursor encodes the rowid of the last-seen asset (base64url JSON int)."""
    if cursor is None:
        return None
    try:
        padding = "=" * (-len(cursor) % 4)
        return json.loads(base64.urlsafe_b64decode(cursor + padding))
    except Exception:
        return None


def _encode_cursor(rowid: int) -> str:
    raw = base64.urlsafe_b64encode(json.dumps(rowid).encode()).rstrip(b"=")
    return raw.decode()


@router.get("/feed")
def query_feed(
    request: Request,
    _auth: AuthDep,
    since: float | None = Query(default=None, description="Start of time window (Unix timestamp, inclusive)"),
    until: float | None = Query(default=None, description="End of time window (Unix timestamp, inclusive)"),
    limit: int = Query(default=50, ge=1, le=_PAGE_MAX),
    cursor: str | None = Query(default=None),
    include_superseded: bool = Query(default=False),
):
    db = request.app.state.db
    until_ts = until if until is not None else time.time()

    conditions = ["created_at <= ?"]
    params: list = [until_ts]

    if since is not None:
        conditions.append("created_at >= ?")
        params.append(since)

    if not include_superseded:
        conditions.append("successor IS NULL")

    last_rowid = _decode_cursor(cursor)
    if last_rowid is not None:
        conditions.append("rowid < ?")
        params.append(last_rowid)

    where = " AND ".join(conditions)
    params.append(limit + 1)

    rows = db.execute(
        f"""
        SELECT rowid, id, content_hash, media_type, size, created_at,
               title, tags, predecessor, successor
        FROM assets
        WHERE {where}
        ORDER BY rowid DESC
        LIMIT ?
        """,
        params,
    ).fetchall()

    has_more = len(rows) > limit
    rows = rows[:limit]

    assets = []
    for row in rows:
        rowid, asset_id, content_hash, media_type, size, created_at, title, tags_json, predecessor, successor = row
        assets.append({
            "id": asset_id,
            "node": str(request.base_url).rstrip("/"),
            "content_hash": content_hash,
            "media_type": media_type,
            "size": size,
            "created_at": created_at,
            "title": title,
            "tags": json.loads(tags_json) if tags_json else [],
            "predecessor": predecessor,
            "successor": successor,
        })

    next_cursor = _encode_cursor(rows[-1][0]) if has_more and rows else None

    return {
        "node": str(request.base_url).rstrip("/"),
        "since": since,
        "until": until_ts,
        "include_superseded": include_superseded,
        "assets": assets,
        **({"next_cursor": next_cursor} if next_cursor else {}),
    }
