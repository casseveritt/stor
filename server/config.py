import json
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

    @classmethod
    def load(cls, path: str | Path) -> "NodeConfig":
        with open(path) as f:
            return cls(**json.load(f))

    def save(self, path: str | Path) -> None:
        with open(path, "w") as f:
            json.dump(self.__dict__, f, indent=2)
