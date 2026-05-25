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
