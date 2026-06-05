import os
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32


def derive_master_key(
    passphrase: str,
    salt: bytes,
    time_cost: int = ARGON2_TIME_COST,
    memory_cost: int = ARGON2_MEMORY_COST,
    parallelism: int = ARGON2_PARALLELISM,
) -> bytes:
    return hash_secret_raw(
        secret=passphrase.encode(),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )


def derive_subkeys(master_key: bytes) -> tuple[bytes, bytes]:
    db_key = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"contac-db").derive(master_key)
    file_key = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"contac-files").derive(master_key)
    return db_key, file_key


def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def decrypt_bytes(data: bytes, key: bytes) -> bytes:
    return AESGCM(key).decrypt(data[:12], data[12:], None)


# ── DM crypto ─────────────────────────────────────────────────────────────────

import base64
import hashlib


def generate_dh_key():
    """Generate a fresh X25519 key pair. Returns (private_key, public_key_b64)."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    priv = X25519PrivateKey.generate()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    return priv, pub_b64


def load_dh_key(encrypted_b64: str, master_key: bytes):
    """Decrypt and return the X25519 private key from config."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    priv_bytes = decrypt_bytes(base64.b64decode(encrypted_b64), master_key)
    return X25519PrivateKey.from_private_bytes(priv_bytes)


def dh_public_key_b64(dh_priv) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return base64.b64encode(dh_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def make_thread_id(node_id_a: str, node_id_b: str) -> str:
    """Deterministic thread ID for a pair of node IDs — same for both parties."""
    pair = ":".join(sorted([node_id_a, node_id_b]))
    return hashlib.sha256(pair.encode()).hexdigest()[:32]


def derive_thread_key(dh_priv, peer_dh_pub_b64: str, thread_id: str) -> bytes:
    """Derive shared symmetric key for a DM thread via X25519 DH + HKDF."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    peer_pub_bytes = base64.b64decode(peer_dh_pub_b64 + "==")
    peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared = dh_priv.exchange(peer_pub)
    return HKDF(SHA256(), 32, None, f"contacc-dm-v1:{thread_id}".encode()).derive(shared)


def encrypt_dm(thread_key: bytes, body: str) -> str:
    """Encrypt a DM body; return base64(nonce || ciphertext)."""
    nonce = os.urandom(12)
    ct = AESGCM(thread_key).encrypt(nonce, body.encode(), None)
    return base64.b64encode(nonce + ct).decode()


def decrypt_dm(thread_key: bytes, blob: str) -> str:
    """Decrypt a DM body from base64(nonce || ciphertext)."""
    raw = base64.b64decode(blob + "==")
    return AESGCM(thread_key).decrypt(raw[:12], raw[12:], None).decode()
