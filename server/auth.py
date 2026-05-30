"""Token authentication, ACL enforcement, and federated request signing.

Three token kinds:
  Owner tokens   -- Ed25519-signed, self-verifying, no DB lookup.
                    Format: base64url(<32B id> | <8B expiry> | <64B sig>), 139 chars.
  Recipient tokens -- random 32B stored in `tokens` table; revocable via DB.
                    Format: base64url(<32B random>), 43 chars.
  Share tokens   -- Ed25519-signed JSON payload, self-verifying, no DB lookup.
                    Format: s1.<base64url payload>.<base64url sig>

Verification order: share -> owner -> DB.
"""
import base64
import hashlib
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

FEDERATED_TIMESTAMP_TOLERANCE = 300  # 5 minutes

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
    share_post_ids: list[str] | None = None   # None = not present; list = scoped

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
    post_ids: list[str] | None = None,
) -> str:
    if _private_key is None:
        raise RuntimeError("auth not initialised")
    payload: dict = {"v": 1, "identity": identity, "assets": asset_ids, "exp": int(time.time()) + ttl_seconds}
    if post_ids is not None:
        payload["posts"] = post_ids
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
            share_post_ids=payload.get("posts"),
        )
    except (InvalidSignature, Exception):
        return None


# ── FastAPI dependencies ──────────────────────────────────────────────────────

_GUEST = TokenIdentity(is_owner=False)


def _identity_from_token(request: Request, token: str) -> TokenIdentity:
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
    return _identity_from_token(request, token)


AuthDep = Annotated[TokenIdentity, Depends(get_identity)]


def get_identity_optional(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> TokenIdentity:
    """Returns a guest identity when no credentials are provided."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ")
    else:
        token = request.query_params.get("token")
        if not token:
            return _GUEST
    return _identity_from_token(request, token)


OptionalAuthDep = Annotated[TokenIdentity, Depends(get_identity_optional)]


def require_owner(identity: AuthDep) -> TokenIdentity:
    if not identity.is_owner:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Owner access required")
    return identity


OwnerDep = Annotated[TokenIdentity, Depends(require_owner)]


# ── federated request signature verification ─────────────────────────────────

async def verify_federated_signature(request: Request) -> None:
    """Verify Ed25519 signature on federated requests from contacts with known public keys.

    - No X-Origin-Server and no X-Public-Key → not federated, skip.
    - Known contact with no stored public key → accept (can't verify).
    - Known contact with stored public key + valid signature → accept.
    - Known contact with stored public key but missing/invalid signature → reject 401.
    Looks up contact by X-Public-Key first (URL-independent), falls back to X-Origin-Server.
    """
    origin = request.headers.get("X-Origin-Server", "")
    pub_key_header = request.headers.get("X-Public-Key", "")
    if not origin and not pub_key_header:
        return
    db = request.app.state.db
    row = None
    if pub_key_header:
        row = db.execute("SELECT public_key, server_url FROM users WHERE public_key = ?", (pub_key_header,)).fetchone()
        if row and origin and row[1] != origin:
            db.execute("UPDATE users SET server_url = ? WHERE public_key = ?", (origin, pub_key_header))
            db.commit()
    if not row and origin:
        row = db.execute("SELECT public_key, server_url FROM users WHERE server_url = ?", (origin,)).fetchone()
    if not row or not row[0]:
        return  # contact has no public key — cannot verify

    timestamp_str = request.headers.get("X-Timestamp", "")
    signature_b64 = request.headers.get("X-Signature", "")

    if not timestamp_str or not signature_b64:
        raise HTTPException(status_code=401,
                            detail="Federated request from verified contact requires a signature")

    try:
        ts = int(timestamp_str)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid X-Timestamp")

    if abs(time.time() - ts) > FEDERATED_TIMESTAMP_TOLERANCE:
        raise HTTPException(status_code=401, detail="Federated request timestamp too skewed")

    body = await request.body()
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = f"{request.method}\n{request.url.path}\n{timestamp_str}\n{body_hash}"

    try:
        pub_bytes = base64.b64decode(row[0] + "==")
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig = base64.b64decode(signature_b64 + "==")
        pub_key.verify(sig, canonical.encode())
    except (InvalidSignature, Exception):
        raise HTTPException(status_code=401, detail="Invalid federated signature")


FederatedSigDep = Annotated[None, Depends(verify_federated_signature)]


# ── ACL helper ────────────────────────────────────────────────────────────────

def check_acl(db, asset_id: str, identity: TokenIdentity) -> bool:
    if identity.is_owner:
        return True
    pub = db.execute("SELECT is_public FROM assets WHERE id = ?", (asset_id,)).fetchone()
    if pub and pub[0]:
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
