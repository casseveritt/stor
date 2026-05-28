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

    @classmethod
    def load(cls, path: str | Path) -> "ClientConfig":
        p = Path(path)
        if not p.exists():
            own_server = cls._bootstrap_own_server()
            cfg = cls(own_server=own_server)
            cfg.save(p)
            return cfg
        data = json.loads(p.read_text())
        contacts = [ContactEntry(**c) for c in data.get("contacts", [])]
        return cls(own_server=data["own_server"], contacts=contacts)

    @staticmethod
    def _bootstrap_own_server() -> str:
        import os
        from urllib.parse import urlparse, urlunparse
        client_url = os.environ.get("CONTACC_CLIENT_URL", "")
        if client_url:
            parsed = urlparse(client_url)
            if parsed.port:
                server_url = urlunparse(parsed._replace(netloc=f"{parsed.hostname}:{parsed.port - 1}"))
                return server_url
        raise RuntimeError(
            "No client_config.json and CONTACC_CLIENT_URL is not set — cannot bootstrap client config"
        )

    def save(self, path: str | Path) -> None:
        data = {
            "own_server": self.own_server,
            "contacts": [dataclasses.asdict(c) for c in self.contacts],
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
