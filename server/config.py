import json
import dataclasses
from dataclasses import dataclass
from pathlib import Path


@dataclass
class NodeConfig:
    node_address: str
    store_path: str
    argon2_salt: str          # hex-encoded 16 bytes
    argon2_time_cost: int
    argon2_memory_cost: int
    argon2_parallelism: int
    encrypted_private_key: str  # base64: 12-byte nonce + AES-256-GCM ciphertext
    watermark_enabled: bool
    sso_google_client_id: str | None = None
    sso_google_client_secret: str | None = None
    sso_owner_identity: str | None = None
    identity_proxy_url: str | None = None
    registry_handle: str | None = None
    registry_url: str | None = None
    internal_token: str | None = None
    owner_id: str | None = None             # permanent person identifier (registry)
    node_id: str | None = None              # this node deployment's identifier
    user_id: str | None = None             # legacy alias for owner_id — do not use in new code
    identity_public_key: str | None = None   # base64 raw pubkey bytes — not sensitive
    identity_delegation: str | None = None   # JSON: delegation cert signed by identity key
    tang_enabled: bool = True                # allow registry to unlock via Tang protocol
    tang_url: str | None = None              # registry Tang endpoint base URL
    tang_C: str | None = None               # base64 ephemeral X25519 public key
    tang_E: str | None = None               # base64 AES-GCM encrypted passphrase
    encrypted_dh_private_key: str | None = None  # base64 AES-GCM; X25519 key for DM thread key derivation

    @classmethod
    def load(cls, path: str | Path) -> "NodeConfig":
        with open(path) as f:
            data = json.load(f)
        known = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})

    def save(self, path: str | Path) -> None:
        with open(path, "w") as f:
            json.dump(self.__dict__, f, indent=2)
