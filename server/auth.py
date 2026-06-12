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
from dataclasses import dataclass, field
from typing import Annotated

from cryptography.exceptions import InvalidSignature
from .db import NS, now_ns
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
    node_id: str | None = None            # set for non-owner tokens
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


# ── node token (DB-backed, revocable) ────────────────────────────────────────

def issue_node_token(db, node_id: str, ttl_seconds: int = 86400 * 30) -> str:
    raw = os.urandom(ID_LEN)
    token_str = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    expiry = now_ns() + ttl_seconds * NS
    db.execute(
        "INSERT INTO tokens (id, node_id, expiry, revoked) VALUES (?, ?, ?, 0)",
        (token_str, node_id, expiry),
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


def sign_federated_request(private_key, method: str = "POST", path: str = "", body_bytes: bytes = b"") -> dict:
    """Return headers for an outgoing federated request signed with our node key."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    ts = str(int(time.time()))
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    canonical = f"{method}\n{path}\n{ts}\n{body_hash}"
    sig = base64.b64encode(private_key.sign(canonical.encode())).decode()
    pub_b64 = base64.b64encode(
        private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    return {"X-Public-Key": pub_b64, "X-Timestamp": ts, "X-Signature": sig}


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
        "SELECT node_id, expiry, revoked FROM tokens WHERE id = ?", (token,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    node_id, expiry, revoked = row
    if revoked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")
    if now_ns() > expiry:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    return TokenIdentity(is_owner=node_id is None, node_id=node_id)


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


async def get_identity_or_federated(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> TokenIdentity:
    """Like OptionalAuthDep but also recognises federated signatures from known contacts.

    If no Bearer token is present, checks X-Public-Key + signature headers. When
    the key is in the users table and the signature is valid, finds or creates a
    recipient record for that server URL so the comment is attributed correctly.
    """
    # 1. Try Bearer / query token first.
    if authorization and authorization.startswith("Bearer "):
        return _identity_from_token(request, authorization.removeprefix("Bearer "))
    token = request.query_params.get("token")
    if token:
        return _identity_from_token(request, token)

    # 2. Try federated signature.
    pub_key_header = request.headers.get("X-Public-Key", "")
    if not pub_key_header:
        return _GUEST

    db = request.app.state.db
    row = db.execute(
        "SELECT public_key, server_url, node_id FROM users WHERE public_key = ?", (pub_key_header,)
    ).fetchone()
    if not row:
        # Unknown key — try to verify it against the origin server on the fly.
        origin = request.headers.get("X-Origin-Server", "")
        if not origin:
            return _GUEST
        try:
            import httpx as _httpx
            nr = await _httpx.AsyncClient().get(origin.rstrip("/") + "/node", timeout=5.0)
            if not nr.is_success:
                return _GUEST
            node_data = nr.json()
            if node_data.get("public_key") != pub_key_header:
                return _GUEST  # claimed key doesn't match the server's actual key
            node_id = node_data.get("node_id") or node_data.get("user_id")
            # Key verified — register as 'external' (not a contact; won't pass contact-level ACL).
            db.execute(
                "INSERT OR IGNORE INTO users (server_url, name, handle, public_key, node_id, relationship) VALUES (?, ?, ?, ?, ?, 'external')",
                (origin, node_data.get("handle") or origin, node_data.get("handle") or "", pub_key_header, node_id),
            )
            db.commit()
            row = (pub_key_header, origin, node_id)
        except Exception:
            return _GUEST

    timestamp_str = request.headers.get("X-Timestamp", "")
    signature_b64 = request.headers.get("X-Signature", "")
    if not timestamp_str or not signature_b64:
        return _GUEST

    try:
        ts = int(timestamp_str)
        if abs(time.time() - ts) > FEDERATED_TIMESTAMP_TOLERANCE:
            return _GUEST
        body = await request.body()
        body_hash = hashlib.sha256(body).hexdigest()
        canonical = f"{request.method}\n{request.url.path}\n{timestamp_str}\n{body_hash}"
        pub_bytes = base64.b64decode(row[0] + "==")
        pub_key_obj = Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig = base64.b64decode(signature_b64 + "==")
        pub_key_obj.verify(sig, canonical.encode())
    except Exception:
        return _GUEST  # invalid signature — treat as guest

    # Signature is valid. Only proceed if we have a node_id — it is the sole identity.
    node_id = row[2]
    if not node_id:
        return _GUEST
    return TokenIdentity(is_owner=False, node_id=node_id)


FederatedOrTokenDep = Annotated[TokenIdentity, Depends(get_identity_or_federated)]


def require_owner(identity: AuthDep) -> TokenIdentity:
    if not identity.is_owner:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Owner access required")
    return identity


OwnerDep = Annotated[TokenIdentity, Depends(require_owner)]


def require_owner_or_internal(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> TokenIdentity:
    """Accept owner Bearer token or internal inter-container token.

    DM endpoints are only called by the client container (them), which always
    includes x-contacc-internal. After a container restart the Bearer token
    may be absent from tokens[], so fall back to the internal token.
    """
    import secrets as _sec
    if authorization and authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ")
        if _verify_owner_token(token):
            return TokenIdentity(is_owner=True)
    internal_token = getattr(request.app.state, "internal_token", None)
    if internal_token:
        provided = request.headers.get("x-contacc-internal", "")
        if provided and _sec.compare_digest(provided, internal_token):
            return TokenIdentity(is_owner=True)
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Owner access required")


InternalOrOwnerDep = Annotated[TokenIdentity, Depends(require_owner_or_internal)]


# ── federated request signature verification ─────────────────────────────────

async def verify_federated_signature(request: Request) -> None:
    """Verify Ed25519 signature on federated requests.

    - No X-Public-Key → not verifiable, skip. sig_verified stays False.
    - Known contact with valid signature → accept, sig_verified = True.
    - Known contact with missing/invalid signature → reject 401.
    - Unknown key with valid signature → sig_verified = True (any contacc node
      can access 'authenticated' content without being a stored contact).
    - Unknown key with invalid/missing signature → sig_verified stays False.

    Sets request.state.sig_verified so downstream visibility checks can use it.
    """
    request.state.sig_verified = False
    pub_key_header = request.headers.get("X-Public-Key", "")
    if not pub_key_header:
        return
    origin = request.headers.get("X-Origin-Server", "")
    db = request.app.state.db
    row = db.execute("SELECT public_key, server_url FROM users WHERE public_key = ?", (pub_key_header,)).fetchone()
    if row and origin and row[1] != origin:
        db.execute("UPDATE users SET server_url = ? WHERE public_key = ?", (origin, pub_key_header))
        db.commit()

    timestamp_str = request.headers.get("X-Timestamp", "")
    signature_b64 = request.headers.get("X-Signature", "")

    if not row or not row[0]:
        # Unknown key — verify opportunistically; don't reject if missing
        if not timestamp_str or not signature_b64:
            return
        try:
            ts = int(timestamp_str)
            if abs(time.time() - ts) > FEDERATED_TIMESTAMP_TOLERANCE:
                return
            body = await request.body()
            body_hash = hashlib.sha256(body).hexdigest()
            canonical = f"{request.method}\n{request.url.path}\n{timestamp_str}\n{body_hash}"
            pub_bytes = base64.b64decode(pub_key_header + "==")
            pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
            sig = base64.b64decode(signature_b64 + "==")
            pub_key.verify(sig, canonical.encode())
            request.state.sig_verified = True
        except Exception:
            pass  # invalid key or signature — sig_verified stays False
        return

    # Known contact — signature is required
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
        request.state.sig_verified = True
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
        "SELECT 1 FROM acl WHERE asset_id = ? AND node_id = ?",
        (asset_id, identity.node_id),
    ).fetchone()
    return row is not None
