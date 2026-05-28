"""Server-side contact management (trusted nodes that may comment on private posts)."""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from .auth import OwnerDep

router = APIRouter()


class _ContactBody(BaseModel):
    server_url: str
    name: str | None = None
    handle: str | None = None


@router.get("/contacts")
def list_contacts(request: Request, _: OwnerDep):
    db = request.app.state.db
    rows = db.execute("SELECT server_url, name, handle FROM contacts ORDER BY id").fetchall()
    return {"contacts": [{"server_url": r[0], "name": r[1], "handle": r[2]} for r in rows]}


@router.post("/contacts", status_code=201)
def add_contact(payload: _ContactBody, request: Request, _: OwnerDep):
    db = request.app.state.db
    try:
        db.execute(
            "INSERT INTO contacts (server_url, name, handle) VALUES (?, ?, ?)",
            (payload.server_url, payload.name, payload.handle),
        )
        db.commit()
    except Exception:
        raise HTTPException(status_code=409, detail="Contact already exists")
    return {"server_url": payload.server_url}


@router.delete("/contacts", status_code=204)
def remove_contact(server_url: str, request: Request, _: OwnerDep):
    db = request.app.state.db
    db.execute("DELETE FROM contacts WHERE server_url = ?", (server_url,))
    db.commit()


def is_known_contact(db, server_url: str) -> bool:
    return db.execute(
        "SELECT 1 FROM contacts WHERE server_url = ?", (server_url,)
    ).fetchone() is not None
