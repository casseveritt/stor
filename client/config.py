import json
import dataclasses
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ContactEntry:
    name: str
    url: str


@dataclass
class ClientConfig:
    own_server: str
    contacts: list[ContactEntry] = field(default_factory=list)
    passphrase_hash: str | None = None

    @classmethod
    def load(cls, path: str | Path) -> "ClientConfig":
        data = json.loads(Path(path).read_text())
        contacts = [ContactEntry(**c) for c in data.get("contacts", [])]
        return cls(
            own_server=data["own_server"],
            contacts=contacts,
            passphrase_hash=data.get("passphrase_hash"),
        )

    def save(self, path: str | Path) -> None:
        data = {
            "own_server": self.own_server,
            "contacts": [dataclasses.asdict(c) for c in self.contacts],
            "passphrase_hash": self.passphrase_hash,
        }
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
