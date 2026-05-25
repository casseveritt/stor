"""Phase 36: client auth hardening — passphrase-protected client session."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

PYTHON = sys.executable
ROOT = Path(__file__).parent.parent


@pytest.fixture
def locked_client(tmp_path):
    from argon2 import PasswordHasher
    from client.config import ClientConfig
    from client.main import create_app
    from fastapi.testclient import TestClient

    config_path = tmp_path / "client_config.json"
    cfg = ClientConfig(own_server="https://node.example.com")
    cfg.passphrase_hash = PasswordHasher().hash("s3cr3t")
    cfg.save(config_path)
    app = create_app(config_path)
    return TestClient(app)


# ── /client/login ─────────────────────────────────────────────────────────

class TestClientLogin:
    def test_correct_passphrase_returns_token(self, locked_client):
        r = locked_client.post("/client/login", json={"passphrase": "s3cr3t"})
        assert r.status_code == 200
        assert "token" in r.json()

    def test_wrong_passphrase_returns_401(self, locked_client):
        r = locked_client.post("/client/login", json={"passphrase": "wrong"})
        assert r.status_code == 401

    def test_no_passphrase_configured_returns_503(self, tmp_path):
        from client.config import ClientConfig
        from client.main import create_app
        from fastapi.testclient import TestClient

        config_path = tmp_path / "client_config.json"
        ClientConfig(own_server="https://node.example.com").save(config_path)
        app = create_app(config_path)
        client = TestClient(app)
        r = client.post("/client/login", json={"passphrase": "anything"})
        assert r.status_code == 503


# ── /api/* auth enforcement ───────────────────────────────────────────────

class TestClientApiAuth:
    def test_api_config_without_token_returns_401(self, locked_client):
        r = locked_client.get("/api/config")
        assert r.status_code == 401

    def test_api_config_with_valid_token(self, locked_client):
        token = locked_client.post("/client/login", json={"passphrase": "s3cr3t"}).json()["token"]
        r = locked_client.get("/api/config", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["own_server"] == "https://node.example.com"

    def test_api_config_with_bad_token_returns_401(self, locked_client):
        r = locked_client.get("/api/config", headers={"Authorization": "Bearer badtoken"})
        assert r.status_code == 401

    def test_api_config_missing_bearer_prefix_returns_401(self, locked_client):
        token = locked_client.post("/client/login", json={"passphrase": "s3cr3t"}).json()["token"]
        r = locked_client.get("/api/config", headers={"Authorization": token})
        assert r.status_code == 401

    def test_no_passphrase_allows_api_without_token(self, tmp_path):
        from client.config import ClientConfig
        from client.main import create_app
        from fastapi.testclient import TestClient

        config_path = tmp_path / "client_config.json"
        ClientConfig(own_server="https://node.example.com").save(config_path)
        app = create_app(config_path)
        client = TestClient(app)
        r = client.get("/api/config")
        assert r.status_code == 200

    def test_multiple_api_routes_require_auth(self, locked_client):
        for path in ["/api/config", "/api/tags", "/api/auth/me"]:
            r = locked_client.get(path)
            assert r.status_code == 401, f"{path} should return 401 without token"

    def test_static_routes_do_not_require_auth(self, locked_client):
        for path in ["/", "/auth/callback"]:
            r = locked_client.get(path)
            assert r.status_code == 200, f"{path} should be accessible without token"


# ── passphrase_hash in ClientConfig ──────────────────────────────────────

class TestPassphraseHash:
    def test_save_and_load_passphrase_hash(self, tmp_path):
        from argon2 import PasswordHasher
        from client.config import ClientConfig

        path = tmp_path / "client_config.json"
        cfg = ClientConfig(own_server="https://node.example.com")
        cfg.passphrase_hash = PasswordHasher().hash("testpass")
        cfg.save(path)

        loaded = ClientConfig.load(path)
        assert loaded.passphrase_hash is not None
        PasswordHasher().verify(loaded.passphrase_hash, "testpass")

    def test_no_passphrase_hash_is_none(self, tmp_path):
        from client.config import ClientConfig

        path = tmp_path / "client_config.json"
        ClientConfig(own_server="https://node.example.com").save(path)
        loaded = ClientConfig.load(path)
        assert loaded.passphrase_hash is None

    def test_passphrase_hash_persisted_as_json_field(self, tmp_path):
        from argon2 import PasswordHasher
        from client.config import ClientConfig

        path = tmp_path / "client_config.json"
        cfg = ClientConfig(own_server="https://node.example.com")
        cfg.passphrase_hash = PasswordHasher().hash("x")
        cfg.save(path)

        data = json.loads(path.read_text())
        assert "passphrase_hash" in data
        assert data["passphrase_hash"] is not None


# ── tools/set_client_passphrase.py ───────────────────────────────────────

class TestSetClientPassphrase:
    def test_sets_passphrase_on_existing_config(self, tmp_path):
        from argon2 import PasswordHasher
        from client.config import ClientConfig

        config_path = tmp_path / "client_config.json"
        ClientConfig(own_server="https://node.example.com").save(config_path)

        r = subprocess.run(
            [PYTHON, str(ROOT / "tools/set_client_passphrase.py"),
             str(config_path), "--passphrase-stdin"],
            input="mynewpass\n", capture_output=True, text=True,
        )
        assert r.returncode == 0, r.stderr

        data = json.loads(config_path.read_text())
        assert data.get("passphrase_hash")
        PasswordHasher().verify(data["passphrase_hash"], "mynewpass")

    def test_overwrites_existing_hash(self, tmp_path):
        from argon2 import PasswordHasher
        from client.config import ClientConfig

        config_path = tmp_path / "client_config.json"
        cfg = ClientConfig(own_server="https://node.example.com")
        cfg.passphrase_hash = PasswordHasher().hash("oldpass")
        cfg.save(config_path)

        subprocess.run(
            [PYTHON, str(ROOT / "tools/set_client_passphrase.py"),
             str(config_path), "--passphrase-stdin"],
            input="newpass\n", capture_output=True, text=True,
        )

        data = json.loads(config_path.read_text())
        PasswordHasher().verify(data["passphrase_hash"], "newpass")

    def test_fails_on_missing_config(self, tmp_path):
        config_path = tmp_path / "nonexistent.json"
        r = subprocess.run(
            [PYTHON, str(ROOT / "tools/set_client_passphrase.py"),
             str(config_path), "--passphrase-stdin"],
            input="pass\n", capture_output=True, text=True,
        )
        assert r.returncode != 0


# ── tools/init_client.py passphrase ──────────────────────────────────────

class TestInitClientPassphrase:
    def test_passphrase_stdin_stores_hash(self, tmp_path):
        from argon2 import PasswordHasher

        config_path = tmp_path / "new" / "client_config.json"
        r = subprocess.run(
            [PYTHON, str(ROOT / "tools/init_client.py"),
             "--config", str(config_path),
             "--own-server", "https://node.example.com",
             "--passphrase-stdin"],
            input="mypassphrase\n", capture_output=True, text=True,
        )
        assert r.returncode == 0, r.stderr
        data = json.loads(config_path.read_text())
        assert data.get("passphrase_hash")
        PasswordHasher().verify(data["passphrase_hash"], "mypassphrase")

    def test_no_passphrase_leaves_hash_null(self, tmp_path):
        config_path = tmp_path / "new" / "client_config.json"
        r = subprocess.run(
            [PYTHON, str(ROOT / "tools/init_client.py"),
             "--config", str(config_path),
             "--own-server", "https://node.example.com",
             "--no-passphrase"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0, r.stderr
        data = json.loads(config_path.read_text())
        assert data.get("passphrase_hash") is None
