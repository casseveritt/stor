#!/usr/bin/env python3
"""Check whether an owner passphrase can decrypt the identity key escrow.

Usage:
    python scripts/check_owner_passphrase.py [owner_id_or_email] [registry_url]

Defaults:
    owner_id: 829c0447-1e70-467c-b208-378d57185dfa
    registry: https://strk.xyzw.us:8421

The script fetches the encrypted escrow, asks for the passphrase, decrypts it,
and prints the resulting identity public key — so you can compare against
what's stored in the registry.
"""
import base64
import getpass
import json
import sys

import urllib.request
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

OWNER_ID = "829c0447-1e70-467c-b208-378d57185dfa"
REGISTRY = "https://strk.xyzw.us:8421"

owner_id = sys.argv[1] if len(sys.argv) > 1 else OWNER_ID
registry = sys.argv[2] if len(sys.argv) > 2 else REGISTRY

try:
    with urllib.request.urlopen(f"{registry}/identity-key/{owner_id}", timeout=10) as resp:
        escrow = json.loads(resp.read())
except Exception as e:
    print(f"Could not fetch escrow: {e}")
    sys.exit(1)
print(f"Fetched escrow (argon2 params: t={escrow['argon2_time_cost']} m={escrow['argon2_memory_cost']} p={escrow['argon2_parallelism']})")

passphrase = getpass.getpass("Owner passphrase: ")

salt = bytes.fromhex(escrow["argon2_salt"])
key = hash_secret_raw(
    passphrase.encode(), salt,
    time_cost=escrow["argon2_time_cost"],
    memory_cost=escrow["argon2_memory_cost"],
    parallelism=escrow["argon2_parallelism"],
    hash_len=32, type=Type.ID,
)

ciphertext = base64.b64decode(escrow["encrypted_identity_key"])
nonce, ct = ciphertext[:12], ciphertext[12:]
try:
    priv_bytes = AESGCM(key).decrypt(nonce, ct, None)
except Exception:
    print("WRONG PASSPHRASE — decryption failed.")
    sys.exit(1)

priv_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
pub_b64 = base64.b64encode(priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
print(f"Correct! Identity public key: {pub_b64}")
