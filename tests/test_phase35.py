"""Phase 35: client app + return_to auth flow + owner identity."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

PYTHON = sys.executable
ROOT = Path(__file__).parent.parent


# ── server-side: return_to in auth flow ───────────────────────────────────

class TestReturnTo:
    def test_generate_state_stores_return_to(self, tmp_path):
        from tests.conftest import _make_store, TEST_PASSPHRASE
        from server.main import create_app
        from server import sso as sso_module

        store = _make_store(tmp_path)
        app = create_app(store / "node_config.json", TEST_PASSPHRASE)
        db = app.state.db
        state = sso_module.generate_state(db, "google", return_to="https://client.example.com/")
        provider, return_to = sso_module.consume_state(db, state)
        assert provider == "google"
        assert return_to == "https://client.example.com/"

    def test_generate_state_default_return_to_empty(self, tmp_path):
        from tests.conftest import _make_store, TEST_PASSPHRASE
        from server.main import create_app
        from server import sso as sso_module

        store = _make_store(tmp_path)
        app = create_app(store / "node_config.json", TEST_PASSPHRASE)
        db = app.state.db
        state = sso_module.generate_state(db, "google")
        _, return_to = sso_module.consume_state(db, state)
        assert return_to == ""

    def test_login_endpoint_passes_return_to_in_state(self, tmp_path):
        from tests.conftest import _make_store, TEST_PASSPHRASE
        from server.main import create_app
        from server import sso as sso_module
        from fastapi.testclient import TestClient

        store = _make_store(tmp_path)
        app = create_app(store / "node_config.json", TEST_PASSPHRASE)
        app.state.sso_config["google_client_id"] = "test-client-id"
        client = TestClient(app)

        r = client.get("/auth/login?provider=google&return_to=https://client.test/")
        assert r.status_code == 200
        state_val = r.json()["state"]
        _, return_to = sso_module.consume_state(app.state.db, state_val)
        assert return_to == "https://client.test/"

    def test_callback_redirects_to_return_to(self, tmp_path):
        from tests.conftest import _make_store, TEST_PASSPHRASE
        from server.main import create_app
        from server import sso as sso_module
        from fastapi.testclient import TestClient

        store = _make_store(tmp_path)
        app = create_app(store / "node_config.json", TEST_PASSPHRASE)
        app.state.sso_config["google_client_id"] = "cid"
        app.state.sso_config["google_client_secret"] = "csecret"

        db = app.state.db
        db.execute("INSERT OR REPLACE INTO identity_mappings (identity, node_id) VALUES ('google:user@test.com', 'r1')")
        db.commit()
        state = sso_module.generate_state(db, "google", return_to="https://client.test/")

        def mock_exchange(code, redirect_uri, client_id, client_secret):
            return {"email": "user@test.com", "email_verified": True}

        app.state.sso_exchange_google = mock_exchange
        client = TestClient(app, follow_redirects=False)
        r = client.get(f"/auth/callback?code=testcode&state={state}")
        assert r.status_code == 302
        assert r.headers["location"].startswith("https://client.test/")
        assert "#token=" in r.headers["location"]

    def test_callback_without_return_to_redirects_to_root(self, tmp_path):
        from tests.conftest import _make_store, TEST_PASSPHRASE
        from server.main import create_app
        from server import sso as sso_module
        from fastapi.testclient import TestClient

        store = _make_store(tmp_path)
        app = create_app(store / "node_config.json", TEST_PASSPHRASE)
        app.state.sso_config["google_client_id"] = "cid"
        app.state.sso_config["google_client_secret"] = "csecret"

        db = app.state.db
        db.execute("INSERT OR REPLACE INTO identity_mappings (identity, node_id) VALUES ('google:other@test.com', 'r2')")
        db.commit()
        state = sso_module.generate_state(db, "google")

        app.state.sso_exchange_google = lambda *a, **k: {"email": "other@test.com"}
        client = TestClient(app, follow_redirects=False)
        r = client.get(f"/auth/callback?code=testcode&state={state}")
        assert r.status_code == 302
        assert r.headers["location"].startswith("/#token=")


# ── server-side: owner identity ───────────────────────────────────────────

class TestOwnerIdentity:
    def test_owner_identity_gets_owner_token(self, tmp_path):
        from tests.conftest import _make_store, TEST_PASSPHRASE
        from server.main import create_app
        from server import sso as sso_module
        from server.auth import _verify_owner_token
        from fastapi.testclient import TestClient

        store = _make_store(tmp_path)
        app = create_app(store / "node_config.json", TEST_PASSPHRASE)
        app.state.sso_config["google_client_id"] = "cid"
        app.state.sso_config["google_client_secret"] = "csecret"
        app.state.owner_identity = "google:owner@test.com"

        db = app.state.db
        state = sso_module.generate_state(db, "google")
        app.state.sso_exchange_google = lambda *a, **k: {"email": "owner@test.com"}

        client = TestClient(app, follow_redirects=False)
        r = client.get(f"/auth/callback?code=testcode&state={state}")
        assert r.status_code == 302
        token = r.headers["location"].split("#token=")[1]
        assert _verify_owner_token(token)

    def test_non_owner_identity_gets_recipient_token(self, tmp_path):
        from tests.conftest import _make_store, TEST_PASSPHRASE
        from server.main import create_app
        from server import sso as sso_module
        from server.auth import _verify_owner_token
        from fastapi.testclient import TestClient

        store = _make_store(tmp_path)
        app = create_app(store / "node_config.json", TEST_PASSPHRASE)
        app.state.sso_config["google_client_id"] = "cid"
        app.state.sso_config["google_client_secret"] = "csecret"
        app.state.owner_identity = "google:owner@test.com"

        db = app.state.db
        db.execute("INSERT OR REPLACE INTO identity_mappings (identity, node_id) VALUES ('google:user@test.com', 'r3')")
        db.commit()
        state = sso_module.generate_state(db, "google")
        app.state.sso_exchange_google = lambda *a, **k: {"email": "user@test.com"}

        client = TestClient(app, follow_redirects=False)
        r = client.get(f"/auth/callback?code=testcode&state={state}")
        assert r.status_code == 302
        token = r.headers["location"].split("#token=")[1]
        assert not _verify_owner_token(token)


# ── client config ─────────────────────────────────────────────────────────

class TestClientConfig:
    def test_save_and_load(self, tmp_path):
        from client.config import ClientConfig, ContactEntry
        cfg = ClientConfig(
            own_server="https://node.example.com",
            contacts=[ContactEntry(name="Alice", url="https://alice.example.com")],
        )
        path = tmp_path / "client_config.json"
        cfg.save(path)
        loaded = ClientConfig.load(path)
        assert loaded.own_server == "https://node.example.com"
        assert len(loaded.contacts) == 1
        assert loaded.contacts[0].name == "Alice"

    def test_tokens_persist(self, tmp_path):
        from client.config import ClientConfig, load_tokens, save_tokens
        path = tmp_path / "client_config.json"
        ClientConfig(own_server="https://node.example.com").save(path)
        save_tokens(path, {"https://node.example.com": "tok123"})
        loaded = load_tokens(path)
        assert loaded["https://node.example.com"] == "tok123"

    def test_init_client_creates_config(self, tmp_path):
        config_path = tmp_path / "client" / "client_config.json"
        r = subprocess.run(
            [PYTHON, str(ROOT / "tools/init_client.py"),
             "--config", str(config_path),
             "--own-server", "https://node.example.com"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0, r.stderr
        assert config_path.exists()
        data = json.loads(config_path.read_text())
        assert data["own_server"] == "https://node.example.com"

    def test_init_client_fails_if_exists(self, tmp_path):
        config_path = tmp_path / "client_config.json"
        config_path.write_text("{}")
        r = subprocess.run(
            [PYTHON, str(ROOT / "tools/init_client.py"),
             "--config", str(config_path),
             "--own-server", "https://node.example.com"],
            capture_output=True, text=True,
        )
        assert r.returncode != 0


# ── client app ────────────────────────────────────────────────────────────

def _mock_owner_httpx():
    from unittest.mock import AsyncMock, MagicMock
    mock_resp = MagicMock(is_success=True)
    mock_resp.json.return_value = {"role": "owner"}
    mock_hc = MagicMock()
    mock_hc.get = AsyncMock(return_value=mock_resp)
    mock_hc.__aenter__ = AsyncMock(return_value=mock_hc)
    mock_hc.__aexit__ = AsyncMock(return_value=None)
    return mock_hc


@pytest.fixture
def client_app(tmp_path):
    from unittest.mock import patch
    from client.config import ClientConfig
    from client.main import create_app
    from fastapi.testclient import TestClient

    config_path = tmp_path / "client_config.json"
    ClientConfig(own_server="https://node.example.com").save(config_path)
    app = create_app(config_path)
    client = TestClient(app)
    with patch("client.main.httpx.AsyncClient", return_value=_mock_owner_httpx()):
        session = client.post("/client/session", json={"token": "owner-tok"}).json()["token"]
    return client, {"Authorization": f"Bearer {session}"}


class TestClientApp:
    def test_root_returns_html(self, client_app):
        client, _ = client_app
        r = client.get("/")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]

    def test_callback_returns_html(self, client_app):
        client, _ = client_app
        r = client.get("/auth/callback")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]

    def test_api_config(self, client_app):
        client, auth = client_app
        r = client.get("/api/config", headers=auth)
        assert r.status_code == 200
        data = r.json()
        assert data["own_server"] == "https://node.example.com"
        assert isinstance(data["servers"], list)

    def test_api_login_url(self, tmp_path):
        from unittest.mock import AsyncMock, MagicMock, patch
        from client.config import ClientConfig
        from client.main import create_app
        from fastapi.testclient import TestClient

        config_path = tmp_path / "client_config.json"
        ClientConfig(own_server="https://node.example.com").save(config_path)
        app = create_app(config_path)
        client = TestClient(app)

        # First get a session
        with patch("client.main.httpx.AsyncClient", return_value=_mock_owner_httpx()):
            session = client.post("/client/session", json={"token": "owner-tok"}).json()["token"]
        auth = {"Authorization": f"Bearer {session}"}

        # Then mock the login-url fetch
        mock_resp = MagicMock(is_success=True)
        mock_resp.json.return_value = {"auth_url": "https://accounts.google.com/auth?state=x"}
        mock_hc = MagicMock()
        mock_hc.get = AsyncMock(return_value=mock_resp)
        mock_hc.__aenter__ = AsyncMock(return_value=mock_hc)
        mock_hc.__aexit__ = AsyncMock(return_value=None)

        with patch("client.main.httpx.AsyncClient", return_value=mock_hc):
            r = client.get("/client/login-url")

        assert r.status_code == 200
        data = r.json()
        assert "auth_url" in data
        assert "accounts.google.com" in data["auth_url"]

    def test_api_store_token(self, tmp_path):
        from unittest.mock import patch
        from client.config import ClientConfig, load_tokens
        from client.main import create_app
        from fastapi.testclient import TestClient

        config_path = tmp_path / "client_config.json"
        ClientConfig(own_server="https://node.example.com").save(config_path)
        app = create_app(config_path)
        client = TestClient(app)

        with patch("client.main.httpx.AsyncClient", return_value=_mock_owner_httpx()):
            session = client.post("/client/session", json={"token": "owner-tok"}).json()["token"]
        auth = {"Authorization": f"Bearer {session}"}

        r = client.post("/api/auth/token", headers=auth,
                        json={"token": "tok-abc", "server": "https://node.example.com"})
        assert r.status_code == 200
        tokens = load_tokens(config_path)
        assert tokens.get("https://node.example.com") == "tok-abc"

    def test_api_clear_token(self, tmp_path):
        from unittest.mock import patch
        from client.config import ClientConfig, save_tokens, load_tokens
        from client.main import create_app
        from fastapi.testclient import TestClient

        config_path = tmp_path / "client_config.json"
        ClientConfig(own_server="https://node.example.com").save(config_path)
        save_tokens(config_path, {"https://node.example.com": "tok-abc"})
        app = create_app(config_path)
        client = TestClient(app)

        with patch("client.main.httpx.AsyncClient", return_value=_mock_owner_httpx()):
            session = client.post("/client/session", json={"token": "owner-tok"}).json()["token"]
        auth = {"Authorization": f"Bearer {session}"}

        r = client.delete("/api/auth/token?server=https://node.example.com", headers=auth)
        assert r.status_code == 200
        tokens = load_tokens(config_path)
        assert "https://node.example.com" not in tokens
