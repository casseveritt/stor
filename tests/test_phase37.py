"""Phase 37: SSO-derived client sessions — passphrase removed."""
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

PYTHON = sys.executable
ROOT = Path(__file__).parent.parent


def _make_mock_httpx(role: str = "owner", ok: bool = True):
    mock_resp = MagicMock()
    mock_resp.is_success = ok
    mock_resp.json.return_value = {"role": role, "identity": "google:owner@test.com"}
    mock_hc = MagicMock()
    mock_hc.get = AsyncMock(return_value=mock_resp)
    mock_hc.__aenter__ = AsyncMock(return_value=mock_hc)
    mock_hc.__aexit__ = AsyncMock(return_value=None)
    return mock_hc


@pytest.fixture
def client_app(tmp_path):
    from client.config import ClientConfig
    from client.main import create_app
    from fastapi.testclient import TestClient

    config_path = tmp_path / "client_config.json"
    ClientConfig(own_server="https://node.example.com").save(config_path)
    app = create_app(config_path)
    return TestClient(app), config_path


# ── /client/session ───────────────────────────────────────────────────────

class TestClientSession:
    def test_owner_token_issues_session(self, client_app):
        client, _ = client_app
        with patch("client.main.httpx.AsyncClient", return_value=_make_mock_httpx("owner")):
            r = client.post("/client/session", json={"token": "owner-tok"})
        assert r.status_code == 200
        assert "token" in r.json()

    def test_non_owner_token_returns_403(self, client_app):
        client, _ = client_app
        with patch("client.main.httpx.AsyncClient", return_value=_make_mock_httpx("recipient")):
            r = client.post("/client/session", json={"token": "recip-tok"})
        assert r.status_code == 403

    def test_invalid_server_token_returns_401(self, client_app):
        client, _ = client_app
        with patch("client.main.httpx.AsyncClient", return_value=_make_mock_httpx(ok=False)):
            r = client.post("/client/session", json={"token": "bad-tok"})
        assert r.status_code == 401

    def test_no_body_uses_stored_token(self, tmp_path):
        from client.config import ClientConfig
        from client.config import save_tokens
        from client.main import create_app
        from fastapi.testclient import TestClient

        config_path = tmp_path / "client_config.json"
        ClientConfig(own_server="https://node.example.com").save(config_path)
        save_tokens(config_path, {"https://node.example.com": "stored-tok"})
        app = create_app(config_path)
        client = TestClient(app)

        with patch("client.main.httpx.AsyncClient", return_value=_make_mock_httpx("owner")):
            r = client.post("/client/session")
        assert r.status_code == 200

    def test_no_stored_token_and_no_body_returns_401(self, client_app):
        client, _ = client_app
        r = client.post("/client/session")
        assert r.status_code == 401

    def test_owner_token_stored_in_tokens_file(self, client_app):
        from client.config import load_tokens
        client, config_path = client_app
        with patch("client.main.httpx.AsyncClient", return_value=_make_mock_httpx("owner")):
            client.post("/client/session", json={"token": "owner-tok"})
        assert load_tokens(config_path).get("https://node.example.com") == "owner-tok"


# ── /api/* requires client session ────────────────────────────────────────

class TestApiAuth:
    def test_api_config_without_session_returns_401(self, client_app):
        client, _ = client_app
        r = client.get("/api/config")
        assert r.status_code == 401

    def test_api_config_with_session(self, client_app):
        client, _ = client_app
        with patch("client.main.httpx.AsyncClient", return_value=_make_mock_httpx("owner")):
            token = client.post("/client/session", json={"token": "tok"}).json()["token"]
        r = client.get("/api/config", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    def test_api_config_with_query_param(self, client_app):
        client, _ = client_app
        with patch("client.main.httpx.AsyncClient", return_value=_make_mock_httpx("owner")):
            token = client.post("/client/session", json={"token": "tok"}).json()["token"]
        r = client.get(f"/api/config?client_token={token}")
        assert r.status_code == 200

    def test_bad_session_token_returns_401(self, client_app):
        client, _ = client_app
        r = client.get("/api/config", headers={"Authorization": "Bearer notreal"})
        assert r.status_code == 401

    def test_static_routes_open(self, client_app):
        client, _ = client_app
        for path in ["/", "/auth/callback"]:
            assert client.get(path).status_code == 200


# ── ClientConfig no longer has passphrase_hash ────────────────────────────

class TestClientConfig:
    def test_config_has_no_passphrase_hash(self, tmp_path):
        from client.config import ClientConfig
        path = tmp_path / "c.json"
        ClientConfig(own_server="https://node.example.com").save(path)
        data = json.loads(path.read_text())
        assert "passphrase_hash" not in data

    def test_old_config_with_passphrase_hash_loads_ok(self, tmp_path):
        from client.config import ClientConfig
        path = tmp_path / "c.json"
        path.write_text(json.dumps({
            "own_server": "https://node.example.com",
            "contacts": [],
            "passphrase_hash": "$argon2id$v=19$...some-hash...",
        }) + "\n")
        cfg = ClientConfig.load(path)
        assert cfg.own_server == "https://node.example.com"


# ── tools/init_client.py ─────────────────────────────────────────────────

class TestInitClient:
    def test_creates_config_no_passphrase_prompt(self, tmp_path):
        config_path = tmp_path / "sub" / "client_config.json"
        r = subprocess.run(
            [PYTHON, str(ROOT / "tools/init_client.py"),
             "--config", str(config_path),
             "--own-server", "https://node.example.com"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0, r.stderr
        data = json.loads(config_path.read_text())
        assert data["own_server"] == "https://node.example.com"
        assert "passphrase_hash" not in data
