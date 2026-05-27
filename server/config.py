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

    @classmethod
    def load(cls, path: str | Path) -> "NodeConfig":
        with open(path) as f:
            data = json.load(f)
        known = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})

    def save(self, path: str | Path) -> None:
        with open(path, "w") as f:
            json.dump(self.__dict__, f, indent=2)
