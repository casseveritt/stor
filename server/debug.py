"""Dev-mode DB consistency checks and fixes."""
import logging
import time
from pathlib import Path

from fastapi import APIRouter, Request
from pydantic import BaseModel


router = APIRouter(prefix="/debug")
log = logging.getLogger("contacc.debug")


def _run_checks(db, store_path: Path) -> list[dict]:
    issues = []
    all_identities = db.execute(
        "SELECT DISTINCT reactor_identity FROM reactions"
    ).fetchall()
    log.info("db-check: distinct reactor_identities = %r", [r[0] for r in all_identities])

    # ── 1. post_assets rows pointing at deleted or missing posts ────────────
    rows = db.execute("""
        SELECT pa.post_id, pa.asset_id
        FROM post_assets pa
        LEFT JOIN posts p ON p.id = pa.post_id
        WHERE p.id IS NULL OR p.deleted = 1
    """).fetchall()
    if rows:
        issues.append({
            "id": "post_assets_orphaned_post",
            "title": "post_assets rows with missing/deleted post",
            "items": [f"post={r[0]} asset={r[1]}" for r in rows],
            "fix": "DELETE FROM post_assets WHERE post_id NOT IN (SELECT id FROM posts WHERE deleted=0)",
        })

    # ── 2. post_assets rows pointing at deleted or missing assets ───────────
    rows = db.execute("""
        SELECT pa.post_id, pa.asset_id
        FROM post_assets pa
        LEFT JOIN assets a ON a.id = pa.asset_id
        WHERE a.id IS NULL OR a.deleted = 1
    """).fetchall()
    if rows:
        issues.append({
            "id": "post_assets_orphaned_asset",
            "title": "post_assets rows with missing/deleted asset",
            "items": [f"post={r[0]} asset={r[1]}" for r in rows],
            "fix": "DELETE FROM post_assets WHERE asset_id NOT IN (SELECT id FROM assets WHERE deleted=0)",
        })

    # ── 3. reactions on deleted/missing posts ───────────────────────────────
    rows = db.execute("""
        SELECT r.id, r.post_id, r.emoji
        FROM reactions r
        LEFT JOIN posts p ON p.id = r.post_id
        WHERE p.id IS NULL OR p.deleted = 1
    """).fetchall()
    if rows:
        issues.append({
            "id": "reactions_orphaned_post",
            "title": "Reactions on deleted/missing posts",
            "items": [f"reaction={r[0]} post={r[1]} emoji={r[2]}" for r in rows],
            "fix": "DELETE FROM reactions WHERE post_id NOT IN (SELECT id FROM posts WHERE deleted=0)",
        })

    # ── 4. reactions on deleted/missing comments ────────────────────────────
    rows = db.execute("""
        SELECT r.id, r.comment_id, r.emoji
        FROM reactions r
        LEFT JOIN comments c ON c.id = r.comment_id
        WHERE r.comment_id != '' AND (c.id IS NULL OR c.deleted = 1)
    """).fetchall()
    if rows:
        issues.append({
            "id": "reactions_orphaned_comment",
            "title": "Reactions on deleted/missing comments",
            "items": [f"reaction={r[0]} comment={r[1]} emoji={r[2]}" for r in rows],
            "fix": "DELETE FROM reactions WHERE comment_id != '' AND comment_id NOT IN (SELECT id FROM comments WHERE deleted=0)",
        })

    # ── 5. comments on deleted/missing posts ────────────────────────────────
    rows = db.execute("""
        SELECT c.id, c.post_id
        FROM comments c
        LEFT JOIN posts p ON p.id = c.post_id
        WHERE c.deleted = 0 AND (p.id IS NULL OR p.deleted = 1)
    """).fetchall()
    if rows:
        issues.append({
            "id": "comments_orphaned_post",
            "title": "Comments on deleted/missing posts",
            "items": [f"comment={r[0]} post={r[1]}" for r in rows],
            "fix": "UPDATE comments SET deleted=1 WHERE post_id NOT IN (SELECT id FROM posts WHERE deleted=0)",
        })

    # ── 6. is_public / visibility mismatch ──────────────────────────────────
    rows = db.execute("""
        SELECT id, is_public, visibility FROM posts WHERE deleted = 0
        AND (
            (is_public = 1 AND visibility != 'public') OR
            (is_public = 0 AND visibility = 'public')
        )
    """).fetchall()
    if rows:
        issues.append({
            "id": "visibility_mismatch",
            "title": "is_public / visibility mismatch",
            "items": [f"post={r[0]} is_public={r[1]} visibility={r[2]}" for r in rows],
            "fix": (
                "UPDATE posts SET is_public = CASE WHEN visibility = 'public' THEN 1 ELSE 0 END "
                "WHERE deleted = 0 AND ("
                "(is_public = 1 AND visibility != 'public') OR "
                "(is_public = 0 AND visibility = 'public'))"
            ),
        })

    # ── 7. asset files missing from disk ────────────────────────────────────
    files_dir = store_path / "files"
    rows = db.execute(
        "SELECT id, content_hash FROM assets WHERE deleted = 0"
    ).fetchall()
    missing = []
    for asset_id, content_hash in rows:
        if content_hash and not (files_dir / content_hash[:2] / content_hash).exists():
            missing.append(f"asset={asset_id} hash={content_hash}")
    if missing:
        issues.append({
            "id": "asset_files_missing",
            "title": "Asset records with no file on disk",
            "items": missing,
            "fix": None,  # can't auto-fix missing files
        })

    # ── 8. orphaned files on disk (no asset record) ─────────────────────────
    known_hashes = {r[1] for r in db.execute("SELECT id, content_hash FROM assets").fetchall()}
    orphaned_files = []
    if files_dir.exists():
        for f in files_dir.rglob("*"):
            if f.is_file() and f.name not in known_hashes:
                orphaned_files.append(str(f.relative_to(store_path)))
    if orphaned_files:
        issues.append({
            "id": "orphaned_files",
            "title": "Files on disk with no asset record",
            "items": orphaned_files,
            "fix": None,  # flag for review; don't auto-delete
        })

    # ── 9. reactions/comments with unrecognized identities ──────────────────
    # Valid reaction identities: '' (owner), '<anon>', '__anon__', or a known node_id.
    # Valid comment author_identity: NULL/'' (owner), or a known recipient identity.
    _valid = "('', '<anon>', '__anon__')"
    _known_node_ids_sub = "SELECT node_id FROM users WHERE node_id IS NOT NULL"
    bad_reactions = db.execute(
        f"SELECT id, reactor_identity FROM reactions "
        f"WHERE reactor_identity NOT IN {_valid} "
        f"AND reactor_identity NOT IN ({_known_node_ids_sub})"
    ).fetchall()
    bad_comments = db.execute(
        f"SELECT id, author_identity FROM comments "
        f"WHERE deleted = 0 AND author_identity IS NOT NULL AND author_identity != '' "
        f"AND author_identity NOT IN {_valid} "
        f"AND author_identity NOT IN ({_known_node_ids_sub})"
    ).fetchall()
    if bad_reactions or bad_comments:
        items = (
            [f"reaction id={r[0]} identity={r[1]}" for r in bad_reactions] +
            [f"comment id={r[0]} identity={r[1]}" for r in bad_comments]
        )
        issues.append({
            "id": "invalid_identity",
            "title": "Reactions/comments with unrecognized identities",
            "items": items,
            "fix": (
                f"DELETE FROM reactions WHERE reactor_identity NOT IN {_valid} "
                f"AND reactor_identity NOT IN ({_known_node_ids_sub}); "
                f"UPDATE comments SET deleted = 1 WHERE deleted = 0 "
                f"AND author_identity IS NOT NULL AND author_identity != '' "
                f"AND author_identity NOT IN {_valid} "
                f"AND author_identity NOT IN ({_known_node_ids_sub})"
            ),
        })

    return issues


class _FixBody(BaseModel):
    fix_ids: list[str]


@router.get("/db-check")
def db_check(request: Request):
    db = request.app.state.db
    store_path = Path(request.app.state.store_path)
    issues = _run_checks(db, store_path)
    return {"issues": issues, "checked_at": time.time()}


@router.get("/asset-state/{asset_id}")
def asset_state(asset_id: str, request: Request):
    db = request.app.state.db
    asset = db.execute(
        "SELECT id, deleted, is_public, title FROM assets WHERE id = ?", (asset_id,)
    ).fetchone()
    if not asset:
        return {"error": "asset not found"}
    links = db.execute(
        "SELECT pa.post_id, p.deleted, p.visibility FROM post_assets pa "
        "LEFT JOIN posts p ON p.id = pa.post_id WHERE pa.asset_id = ?", (asset_id,)
    ).fetchall()
    return {
        "asset": {"id": asset[0], "deleted": bool(asset[1]), "is_public": bool(asset[2]), "title": asset[3]},
        "post_links": [{"post_id": r[0], "post_deleted": bool(r[1]), "visibility": r[2]} for r in links],
    }


@router.post("/db-fix")
def db_fix(body: _FixBody, request: Request):
    db = request.app.state.db
    store_path = Path(request.app.state.store_path)
    issues = _run_checks(db, store_path)
    fix_map = {i["id"]: i["fix"] for i in issues if i.get("fix")}
    applied = []
    for fix_id in body.fix_ids:
        sql = fix_map.get(fix_id)
        if sql:
            for stmt in sql.split(";"):
                stmt = stmt.strip()
                if stmt:
                    db.execute(stmt)
            applied.append(fix_id)
    db.commit()
    remaining = _run_checks(db, store_path)
    return {"applied": applied, "issues": remaining}
