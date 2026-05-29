"""Dev-mode DB consistency checks and fixes."""
import time
from pathlib import Path

from fastapi import APIRouter, Request
from pydantic import BaseModel

from .auth import OwnerDep

router = APIRouter(prefix="/debug")


def _run_checks(db, store_path: Path) -> list[dict]:
    issues = []

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

    return issues


class _FixBody(BaseModel):
    fix_ids: list[str]


@router.get("/db-check")
def db_check(request: Request, identity: OwnerDep):
    db = request.app.state.db
    store_path = Path(request.app.state.store_path)
    issues = _run_checks(db, store_path)
    return {"issues": issues, "checked_at": time.time()}


@router.post("/db-fix")
def db_fix(body: _FixBody, request: Request, identity: OwnerDep):
    db = request.app.state.db
    store_path = Path(request.app.state.store_path)
    issues = _run_checks(db, store_path)
    fix_map = {i["id"]: i["fix"] for i in issues if i.get("fix")}
    applied = []
    for fix_id in body.fix_ids:
        sql = fix_map.get(fix_id)
        if sql:
            db.execute(sql)
            applied.append(fix_id)
    db.commit()
    remaining = _run_checks(db, store_path)
    return {"applied": applied, "issues": remaining}
