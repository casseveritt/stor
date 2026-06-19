"""Owner preferences: a simple key-value store."""
from fastapi import APIRouter, Request
from pydantic import BaseModel

from .auth import OwnerDep

router = APIRouter(prefix="/prefs")


@router.get("")
def get_prefs(request: Request, identity: OwnerDep):
    db = request.app.state.db
    rows = db.execute("SELECT key, value FROM prefs").fetchall()
    return {r[0]: r[1] for r in rows}


class _PatchBody(BaseModel):
    model_config = {"extra": "allow"}


@router.patch("")
def patch_prefs(request: Request, identity: OwnerDep, body: _PatchBody):
    db = request.app.state.db
    updates = body.model_extra or {}
    for key, value in updates.items():
        if value is None:
            db.execute("DELETE FROM prefs WHERE key = ?", (key,))
        else:
            db.execute(
                "INSERT INTO prefs (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, str(value)),
            )
    db.commit()
    rows = db.execute("SELECT key, value FROM prefs").fetchall()
    return {r[0]: r[1] for r in rows}
