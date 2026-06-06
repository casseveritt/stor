import json
import dataclasses
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ContactEntry:
    name: str
    url: str
    handle: str | None = None
    public_key: str | None = None
    node_id: str | None = None  # node deployment identifier
    description: str | None = None
    family: float = 0.0
    close_friends: float = 0.0
    friends: float = 0.0
    colleagues: float = 0.0
    acquaintances: float = 0.0


@dataclass
class NodeKey:
    argon2_salt: str
    encrypted_private_key: str
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65536
    argon2_parallelism: int = 4


@dataclass
class ClientConfig:
    own_server: str
    contacts: list[ContactEntry] = field(default_factory=list)
    node_key: NodeKey | None = None
    internal_token: str | None = None
    own_node_id: str | None = None

    @classmethod
    def load(cls, path: str | Path) -> "ClientConfig":
        p = Path(path)
        if not p.exists():
            own_server = cls._bootstrap_own_server()
            cfg = cls(own_server=own_server)
            cfg.save(p)
            return cfg
        data = json.loads(p.read_text())
        _ce_fields = {f.name for f in dataclasses.fields(ContactEntry)}
        raw_contacts = [ContactEntry(**{k: v for k, v in c.items() if k in _ce_fields})
                        for c in data.get("contacts", [])]
        # Deduplicate by node_id (keep first occurrence per node_id)
        seen_node_ids: set[str] = set()
        contacts = []
        for c in raw_contacts:
            if c.node_id:
                if c.node_id in seen_node_ids:
                    continue
                seen_node_ids.add(c.node_id)
            contacts.append(c)
        node_key = NodeKey(**data["node_key"]) if "node_key" in data else None
        return cls(
            own_server=data["own_server"],
            contacts=contacts,
            node_key=node_key,
            internal_token=data.get("internal_token"),
            own_node_id=data.get("own_node_id"),
        )

    @staticmethod
    def _bootstrap_own_server() -> str:
        import os
        server_url = os.environ.get("CONTACC_NODE_ADDRESS", "")
        if server_url:
            return server_url
        raise RuntimeError(
            "No client_config.json and CONTACC_NODE_ADDRESS is not set — cannot bootstrap client config"
        )

    def save(self, path: str | Path) -> None:
        data: dict = {
            "own_server": self.own_server,
            "contacts": [dataclasses.asdict(c) for c in self.contacts],
        }
        if self.node_key:
            data["node_key"] = dataclasses.asdict(self.node_key)
        if self.internal_token:
            data["internal_token"] = self.internal_token
        if self.own_node_id:
            data["own_node_id"] = self.own_node_id
        Path(path).write_text(json.dumps(data, indent=2) + "\n")


def tokens_path(config_path: Path) -> Path:
    return config_path.with_name("client_tokens.json")


def load_tokens(config_path: Path) -> dict[str, str]:
    p = tokens_path(config_path)
    if p.exists():
        return json.loads(p.read_text())
    return {}


def save_tokens(config_path: Path, tokens: dict[str, str]) -> None:
    tokens_path(config_path).write_text(json.dumps(tokens, indent=2) + "\n")
