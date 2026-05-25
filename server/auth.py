"""Token authentication and ACL enforcement.

Three token kinds:
  Owner tokens   — Ed25519-signed, self-verifying, no DB lookup.
                   Format: base64url(<32B id> | <8B expiry> | <64B sig>), 139 chars.
  Recipient tokens — random 32B stored in `tokens` table; revocable via DB.
                   Format: base64url(<32B random>), 43 chars.
  Share tokens   — Ed25519-signed JSON payload, self-verifying, no DB lookup.
                   Format: s1.<base64url payload>.<base64url sig>
                   Carry a watermark identity and optional per-asset scope.

Verification order: share → owner → DB.
"""
import base64
import json
import os
import struct
import time
import uuid
from dataclasses import dataclass, field
from typing import Annotated

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi import Depends, Header, HTTPException, Request, status

_public_key: Ed25519PublicKey | None = None
_private_key: Ed25519PrivateKey | None = None

ID_LEN = 32
EXPIRY_LEN = 8
SIG_LEN = 64
OWNER_TOKEN_LEN = ID_LEN + EXPIRY_LEN + SIG_LEN  # 104 bytes raw


@dataclass
class TokenIdentity:
    is_owner: bool
    recipient_id: str | None = None       # set for recipient tokens
    share_identity: str | None = None     # set for share tokens (watermark label)
    share_asset_ids: list[str] | None = None  # None = node-wide; list = scoped

    @property
    def is_share(self) -> bool:
        return self.share_identity is not None


# ── setup ─────────────────────────────────────────────────────────────────────

def setup(private_key: Ed25519PrivateKey) -> None:
    global _public_key, _private_key
    _private_key = private_key
    _public_key = private_key.public_key()


# ── owner token (Ed25519, self-verifying) ─────────────────────────────────────

def issue_token(ttl_seconds: int = 86400 * 30) -> str:
    if _private_key is None:
        raise RuntimeError("auth not initialised")
    token_id = os.urandom(ID_LEN)
    expiry = struct.pack(">Q", int(time.time()) + ttl_seconds)
    sig = _private_key.sign(token_id + expiry)
    raw = token_id + expiry + sig
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _verify_owner_token(token: str) -> bool:
    if _public_key is None:
        return False
    try:
        padding = "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(token + padding)
        if len(raw) != OWNER_TOKEN_LEN:
            return False
        token_id = raw[:ID_LEN]
        expiry_bytes = raw[ID_LEN:ID_LEN + EXPIRY_LEN]
        sig = raw[ID_LEN + EXPIRY_LEN:]
        if time.time() > struct.unpack(">Q", expiry_bytes)[0]:
            return False
        _public_key.verify(sig, token_id + expiry_bytes)
        return True
    except (InvalidSignature, Exception):
        return False


# ── recipient token (DB-backed, revocable) ────────────────────────────────────

def issue_recipient_token(db, recipient_id: str, ttl_seconds: int = 86400 * 30) -> str:
    raw = os.urandom(ID_LEN)
    token_str = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    expiry = time.time() + ttl_seconds
    db.execute(
        "INSERT INTO tokens (id, recipient_id, expiry, revoked) VALUES (?, ?, ?, 0)",
        (token_str, recipient_id, expiry),
    )
    db.commit()
    return token_str


def revoke_token(db, token_id: str) -> bool:
    cur = db.execute("UPDATE tokens SET revoked=1 WHERE id=?", (token_id,))
    db.commit()
    return cur.rowcount > 0


# ── share token (Ed25519-signed, self-verifying) ──────────────────────────────

def issue_share_token(
    identity: str,
    asset_ids: list[str] | None,
    ttl_seconds: int = 86400 * 30,
) -> str:
    if _private_key is None:
        raise RuntimeError("auth not initialised")
    payload = {"v": 1, "identity": identity, "assets": asset_ids, "exp": int(time.time()) + ttl_seconds}
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
    to_sign = f"s1.{payload_b64}".encode()
    sig_b64 = base64.urlsafe_b64encode(_private_key.sign(to_sign)).rstrip(b"=").decode()
    return f"s1.{payload_b64}.{sig_b64}"


def _verify_share_token(token: str) -> TokenIdentity | None:
    if not token.startswith("s1."):
        return None
    if _public_key is None:
        return None
    try:
        parts = token.split(".", 2)
        if len(parts) != 3:
            return None
        _, payload_b64, sig_b64 = parts
        to_verify = f"s1.{payload_b64}".encode()
        padding = "=" * (-len(sig_b64) % 4)
        _public_key.verify(base64.urlsafe_b64decode(sig_b64 + padding), to_verify)
        padding = "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
        if payload.get("v") != 1:
            return None
        if time.time() > payload["exp"]:
            return None
        return TokenIdentity(
            is_owner=False,
            share_identity=payload["identity"],
            share_asset_ids=payload.get("assets"),
        )
    except (InvalidSignature, Exception):
        return None


# ── FastAPI dependencies ──────────────────────────────────────────────────────

def get_identity(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> TokenIdentity:
    if authorization and authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ")
    else:
        token = request.query_params.get("token")
        if not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing credentials")

    if token.startswith("s1."):
        identity = _verify_share_token(token)
        if identity is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired share token")
        return identity

    if _verify_owner_token(token):
        return TokenIdentity(is_owner=True)

    db = request.app.state.db
    row = db.execute(
        "SELECT recipient_id, expiry, revoked FROM tokens WHERE id = ?", (token,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    recipient_id, expiry, revoked = row
    if revoked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")
    if time.time() > expiry:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    return TokenIdentity(is_owner=recipient_id is None, recipient_id=recipient_id)


AuthDep = Annotated[TokenIdentity, Depends(get_identity)]


def require_owner(identity: AuthDep) -> TokenIdentity:
    if not identity.is_owner:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Owner access required")
    return identity


OwnerDep = Annotated[TokenIdentity, Depends(require_owner)]


# ── ACL helper ────────────────────────────────────────────────────────────────

def check_acl(db, asset_id: str, identity: TokenIdentity) -> bool:
    if identity.is_owner:
        return True
    if identity.is_share:
        if identity.share_asset_ids is None:
            return True  # node-wide share
        return asset_id in identity.share_asset_ids
    row = db.execute(
        "SELECT 1 FROM acl WHERE asset_id = ? AND recipient_id = ?",
        (asset_id, identity.recipient_id),
    ).fetchone()
    return row is not None
