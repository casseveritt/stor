"""Static signed token auth — owner credential for Phase 2.

Token format (URL-safe base64, no padding):
  <32-byte random id> | <8-byte expiry unix seconds big-endian> | <Ed25519 signature over id+expiry>

The node signs with its Ed25519 private key; verification uses the public key.
"""
import base64
import os
import struct
import time
from typing import Annotated

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from fastapi import Depends, Header, HTTPException, status

_public_key: Ed25519PublicKey | None = None
_private_key: Ed25519PrivateKey | None = None

ID_LEN = 32
EXPIRY_LEN = 8
SIG_LEN = 64
TOKEN_LEN = ID_LEN + EXPIRY_LEN + SIG_LEN  # 104 bytes


def setup(private_key: Ed25519PrivateKey) -> None:
    global _public_key, _private_key
    _private_key = private_key
    _public_key = private_key.public_key()


def issue_token(ttl_seconds: int = 86400 * 30) -> str:
    if _private_key is None:
        raise RuntimeError("auth not initialised")
    token_id = os.urandom(ID_LEN)
    expiry = struct.pack(">Q", int(time.time()) + ttl_seconds)
    sig = _private_key.sign(token_id + expiry)
    raw = token_id + expiry + sig
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _verify(token: str) -> bool:
    if _public_key is None:
        return False
    try:
        padding = "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(token + padding)
        if len(raw) != TOKEN_LEN:
            return False
        token_id = raw[:ID_LEN]
        expiry_bytes = raw[ID_LEN:ID_LEN + EXPIRY_LEN]
        sig = raw[ID_LEN + EXPIRY_LEN:]
        expiry = struct.unpack(">Q", expiry_bytes)[0]
        if time.time() > expiry:
            return False
        _public_key.verify(sig, token_id + expiry_bytes)
        return True
    except (InvalidSignature, Exception):
        return False


def require_auth(authorization: Annotated[str | None, Header()] = None) -> None:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing credentials")
    token = authorization.removeprefix("Bearer ")
    if not _verify(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")


AuthDep = Annotated[None, Depends(require_auth)]
