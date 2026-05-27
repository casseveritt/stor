#!/usr/bin/env python3
"""Register or update a contacc node's handle in the registry.

Usage (first time):
    python tools/register_node.py /path/to/node_config.json --handle yourname \\
        --client-url https://your.domain:8444

Usage (update after moving):
    python tools/register_node.py /path/to/node_config.json --handle yourname --update

The node's Ed25519 private key is used to sign the request; only the key that
originally registered a handle can update it.
"""
import base64
import getpass
import json
import os
import sys
import time
import argparse
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).parent.parent))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from server.crypto import derive_master_key, decrypt_bytes
from registry.client import REGISTRY_URL


def _get_passphrase() -> str:
    env = os.environ.get("CONTACC_PASSPHRASE")
    if env:
        return env
    return getpass.getpass("Passphrase: ")


def _load_private_key(config: dict, passphrase: str) -> Ed25519PrivateKey:
    salt = bytes.fromhex(config["argon2_salt"])
    master_key = derive_master_key(passphrase, salt)
    privkey_bytes = decrypt_bytes(
        base64.b64decode(config["encrypted_private_key"]), master_key
    )
    return Ed25519PrivateKey.from_private_bytes(privkey_bytes)


def main() -> None:
    parser = argparse.ArgumentParser(description="Register/update a contacc node handle")
    parser.add_argument("config", help="Path to node_config.json")
    parser.add_argument("--handle", required=True, help="Username to register (letters, digits, _ or -)")
    parser.add_argument("--client-url", default="", help="URL of your contacc client aggregator")
    parser.add_argument("--ttl", type=int, default=14400, help="Cache TTL in seconds (default: 14400 = 4h)")
    parser.add_argument("--registry", default=REGISTRY_URL, help=f"Registry URL (default: {REGISTRY_URL})")
    parser.add_argument("--update", action="store_true", help="Update an existing registration")
    args = parser.parse_args()

    config = json.loads(Path(args.config).read_text())
    passphrase = _get_passphrase()

    print("Deriving key...")
    private_key = _load_private_key(config, passphrase)
    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_key_b64 = base64.b64encode(pub_bytes).decode()

    server_url = config["node_address"]
    client_url = args.client_url
    timestamp = int(time.time())
    action = "update" if args.update else "register"

    msg = f"contacc:{action}:{args.handle}:{server_url}:{client_url}:{timestamp}"
    signature = base64.b64encode(private_key.sign(msg.encode())).decode()

    payload = {
        "server_url": server_url,
        "client_url": client_url,
        "ttl": args.ttl,
        "timestamp": timestamp,
        "signature": signature,
    }

    if args.update:
        r = httpx.put(f"{args.registry}/update/{args.handle}", json=payload)
    else:
        payload["public_key"] = pub_key_b64
        r = httpx.post(f"{args.registry}/register/{args.handle}", json=payload)

    if r.is_success:
        data = r.json()
        verb = "Updated" if args.update else "Registered"
        print(f"{verb}: {args.handle}")
        print(f"Server: {server_url}")
        print(f"Client: {client_url or '(none)'}")
        print(f"TTL:    {data['ttl']}s ({data['ttl'] // 3600}h)")
    else:
        print(f"Error {r.status_code}: {r.text}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
