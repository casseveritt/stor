"""Recipient, identity-mapping, and token management endpoints (owner only)."""
import time
import uuid

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

from .auth import OwnerDep, revoke_token

router = APIRouter()


# ── recipients ────────────────────────────────────────────────────────────────

def _recipient_dict(row) -> dict:
    id_, identity, display_name = row
    return {"id": id_, "identity": identity, "display_name": display_name}


@router.get("/recipients")
def list_recipients(request: Request, identity: OwnerDep):
    db = request.app.state.db
    rows = db.execute(
        "SELECT id, identity, display_name FROM recipients ORDER BY display_name"
    ).fetchall()
    return {"recipients": [_recipient_dict(r) for r in rows]}


class _CreateRecipientBody(BaseModel):
    identity: str
    display_name: str | None = None


@router.post("/recipients", status_code=201)
def create_recipient(payload: _CreateRecipientBody, request: Request, identity: OwnerDep):
    db = request.app.state.db
    if db.execute("SELECT id FROM recipients WHERE identity = ?", (payload.identity,)).fetchone():
        raise HTTPException(status_code=409, detail="Identity already exists")
    recipient_id = str(uuid.uuid4())
    display_name = payload.display_name or payload.identity
    db.execute(
        "INSERT INTO recipients (id, identity, display_name) VALUES (?, ?, ?)",
        (recipient_id, payload.identity, display_name),
    )
    db.commit()
    return {"id": recipient_id, "identity": payload.identity, "display_name": display_name}


@router.get("/recipients/{recipient_id}")
def get_recipient(recipient_id: str, request: Request, identity: OwnerDep):
    db = request.app.state.db
    row = db.execute(
        "SELECT id, identity, display_name FROM recipients WHERE id = ?", (recipient_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Recipient not found")
    return _recipient_dict(row)


@router.delete("/recipients/{recipient_id}", status_code=204)
def delete_recipient(recipient_id: str, request: Request, identity: OwnerDep):
    db = request.app.state.db
    if db.execute("SELECT id FROM recipients WHERE id = ?", (recipient_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="Recipient not found")
    db.execute("DELETE FROM acl WHERE recipient_id = ?", (recipient_id,))
    db.execute("DELETE FROM identity_mappings WHERE recipient_id = ?", (recipient_id,))
    db.execute("UPDATE tokens SET revoked = 1 WHERE recipient_id = ?", (recipient_id,))
    db.execute("DELETE FROM recipients WHERE id = ?", (recipient_id,))
    db.commit()


# ── identity mappings ─────────────────────────────────────────────────────────

class _SetMappingBody(BaseModel):
    recipient_id: str


@router.post("/identity-mappings", status_code=201)
def set_identity_mapping(payload: _SetMappingBody, request: Request, identity: OwnerDep,
                         mapped_identity: str = Query(..., alias="identity")):
    db = request.app.state.db
    if db.execute("SELECT id FROM recipients WHERE id = ?", (payload.recipient_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="Recipient not found")
    db.execute(
        "INSERT OR REPLACE INTO identity_mappings (identity, recipient_id) VALUES (?, ?)",
        (mapped_identity, payload.recipient_id),
    )
    db.commit()
    return {"identity": mapped_identity, "recipient_id": payload.recipient_id}


@router.delete("/identity-mappings", status_code=204)
def delete_identity_mapping(request: Request, identity: OwnerDep,
                             mapped_identity: str = Query(..., alias="identity")):
    db = request.app.state.db
    cur = db.execute("DELETE FROM identity_mappings WHERE identity = ?", (mapped_identity,))
    db.commit()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Mapping not found")


# ── tokens ────────────────────────────────────────────────────────────────────

@router.get("/tokens")
def list_tokens(request: Request, identity: OwnerDep):
    db = request.app.state.db
    rows = db.execute(
        """SELECT t.id, t.recipient_id, t.expiry, r.identity
           FROM tokens t
           LEFT JOIN recipients r ON r.id = t.recipient_id
           WHERE t.revoked = 0 AND t.expiry > ?
           ORDER BY t.expiry DESC""",
        (time.time(),),
    ).fetchall()
    return {
        "tokens": [
            {
                "id": r[0],
                "recipient_id": r[1],
                "expiry": r[2],
                "recipient_identity": r[3],
            }
            for r in rows
        ]
    }


@router.post("/tokens/{token_id}/revoke")
def revoke_token_endpoint(token_id: str, request: Request, identity: OwnerDep):
    db = request.app.state.db
    if not revoke_token(db, token_id):
        raise HTTPException(status_code=404, detail="Token not found")
    return {"token_id": token_id, "status": "revoked"}
