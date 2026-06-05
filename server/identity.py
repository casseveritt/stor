"""Permanent identity: delegation cert creation and verification."""
import base64
import json
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

from .db import NS

DELEGATION_TTL_NS = 365 * 24 * 3600 * NS  # 1 year


def make_delegation_cert(identity_private_key: Ed25519PrivateKey,
                         owner_id: str,
                         node_pub_b64: str,
                         ttl_ns: int = DELEGATION_TTL_NS,
                         node_id: str | None = None) -> dict:
    """Sign and return a delegation cert binding owner_id → node_id → node_pub_b64."""
    id_pub_bytes = identity_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    expires_at = time.time_ns() + ttl_ns
    canonical = f"contacc:delegate:{owner_id}:{node_pub_b64}:{expires_at}"
    sig = identity_private_key.sign(canonical.encode())
    cert = {
        "owner_id": owner_id,
        "user_id": owner_id,           # legacy alias — kept for registry compat during transition
        "node_public_key": node_pub_b64,
        "identity_public_key": base64.b64encode(id_pub_bytes).decode(),
        "expires_at": expires_at,
        "signature": base64.b64encode(sig).decode(),
    }
    if node_id:
        cert["node_id"] = node_id
    return cert


def verify_delegation_cert(cert: dict, node_pub_b64: str) -> bool:
    """Return True if cert is valid, unexpired, and authorises node_pub_b64."""
    try:
        if cert.get("node_public_key") != node_pub_b64:
            return False
        if cert.get("expires_at", 0) < time.time_ns():
            return False
        id_pub = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(cert["identity_public_key"] + "=="))
        canonical = (f"contacc:delegate:{cert.get('owner_id') or cert['user_id']}:"
                     f"{cert['node_public_key']}:{cert['expires_at']}")
        id_pub.verify(base64.b64decode(cert["signature"] + "=="), canonical.encode())
        return True
    except Exception:
        return False


def identity_key_from_hex(hex_str: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex_str))


def identity_key_to_hex(key: Ed25519PrivateKey) -> str:
    return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
