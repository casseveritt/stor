"""Server-side user management (trusted nodes that may comment on private posts)."""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from .auth import OwnerDep

router = APIRouter()


class _UserBody(BaseModel):
    server_url: str
    name: str | None = None
    handle: str | None = None
    public_key: str | None = None
    relationship: str = "contact"
    weight: float | None = None  # [0,1] derived from contact category


@router.get("/users")
def list_users(request: Request, _: OwnerDep):
    db = request.app.state.db
    rows = db.execute(
        "SELECT server_url, name, handle, public_key, relationship, weight FROM users ORDER BY id"
    ).fetchall()
    return {"users": [{"server_url": r[0], "name": r[1], "handle": r[2],
                       "public_key": r[3], "relationship": r[4], "weight": r[5]} for r in rows]}


@router.post("/users", status_code=201)
def add_user(payload: _UserBody, request: Request, _: OwnerDep):
    db = request.app.state.db
    try:
        db.execute(
            "INSERT INTO users (server_url, name, handle, public_key, relationship, weight) VALUES (?, ?, ?, ?, ?, ?)",
            (payload.server_url, payload.name, payload.handle, payload.public_key, payload.relationship, payload.weight),
        )
        db.commit()
    except Exception:
        raise HTTPException(status_code=409, detail="User already exists")
    return {"server_url": payload.server_url}


@router.patch("/users", status_code=200)
def update_user(server_url: str, payload: _UserBody, request: Request, _: OwnerDep):
    db = request.app.state.db
    updates, params = [], []
    if payload.name is not None:
        updates.append("name = ?"); params.append(payload.name)
    if payload.weight is not None:
        updates.append("weight = ?"); params.append(payload.weight)
    if updates:
        params.append(server_url)
        db.execute(f"UPDATE users SET {', '.join(updates)} WHERE server_url = ?", params)
        db.commit()
    return {"ok": True}


@router.delete("/users", status_code=204)
def remove_user(server_url: str, request: Request, _: OwnerDep):
    db = request.app.state.db
    db.execute("DELETE FROM users WHERE server_url = ?", (server_url,))
    db.commit()


def is_known_contact(db, server_url: str) -> bool:
    return db.execute(
        "SELECT 1 FROM users WHERE server_url = ? AND relationship = 'contact'", (server_url,)
    ).fetchone() is not None
