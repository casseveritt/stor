"""QueryFeed endpoint — paginated asset metadata feed."""
import base64
import json
import time

from fastapi import APIRouter, Query, Request

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
    return base64.urlsafe_b64encode(json.dumps(rowid).encode()).rstrip(b"=").decode()


@router.get("/feed")
def query_feed(
    request: Request,
    identity: AuthDep,
    since: float | None = Query(default=None),
    until: float | None = Query(default=None),
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

    if not identity.is_owner:
        if identity.is_share:
            if identity.share_asset_ids is not None:
                placeholders = ",".join("?" * len(identity.share_asset_ids))
                conditions.append(f"id IN ({placeholders})")
                params.extend(identity.share_asset_ids)
            # else: node-wide share — no filter needed
        else:
            conditions.append(
                "EXISTS (SELECT 1 FROM acl WHERE asset_id = assets.id AND recipient_id = ?)"
            )
            params.append(identity.recipient_id)

    params.append(limit + 1)
    where = " AND ".join(conditions)

    rows = db.execute(
        f"""
        SELECT rowid, id, content_hash, media_type, size, created_at,
               title, tags, predecessor, successor,
               (SELECT COUNT(*) FROM comments
                WHERE comments.asset_id = assets.id
                  AND comments.parent_id IS NULL AND comments.deleted = 0) AS comment_count
        FROM assets
        WHERE {where}
        ORDER BY rowid DESC
        LIMIT ?
        """,
        params,
    ).fetchall()

    has_more = len(rows) > limit
    rows = rows[:limit]

    node_url = str(request.base_url).rstrip("/")
    assets = [
        {
            "id": row[1],
            "node": node_url,
            "content_hash": row[2],
            "media_type": row[3],
            "size": row[4],
            "created_at": row[5],
            "title": row[6],
            "tags": json.loads(row[7]) if row[7] else [],
            "predecessor": row[8],
            "successor": row[9],
            "comment_count": row[10],
        }
        for row in rows
    ]

    next_cursor = _encode_cursor(rows[-1][0]) if has_more and rows else None

    return {
        "node": node_url,
        "since": since,
        "until": until_ts,
        "include_superseded": include_superseded,
        "assets": assets,
        **({"next_cursor": next_cursor} if next_cursor else {}),
    }
