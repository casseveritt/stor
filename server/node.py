import base64
from fastapi import APIRouter
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

router = APIRouter()

_node_address: str = ""
_public_key_b64: str = ""
_watermark_enabled: bool = False


def setup(node_address: str, private_key: Ed25519PrivateKey, watermark_enabled: bool) -> None:
    global _node_address, _public_key_b64, _watermark_enabled
    _node_address = node_address
    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    _public_key_b64 = base64.b64encode(pub_bytes).decode()
    _watermark_enabled = watermark_enabled


@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/node")
def node_metadata():
    return {
        "node": _node_address,
        "public_key": _public_key_b64,
        "watermark_policy": "enabled" if _watermark_enabled else "disabled",
    }
