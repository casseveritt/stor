"""Validate that client routes attach the correct auth headers to server calls.

Focus: the class of bug where a server endpoint gets called without the
internal token (producing 403) or without X-Origin-Server (producing wrong
visibility decisions for cross-node requests).

Each test spins up a real server + client pair via ASGI (no Docker) using
httpx.AsyncClient / TestClient against the ASGI apps directly.
"""
import json
import secrets
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from tests.conftest import _make_store, TEST_PASSPHRASE


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_server_app(tmp_path: Path):
    """Fully initialized server app with an internal_token set."""
    store = _make_store(tmp_path)
    from server.main import create_app
    app = create_app(store / "node_config.json")
    app.state.do_initialize(TEST_PASSPHRASE)
    # Inject an internal token (normally set at setup time)
    internal_token = secrets.token_urlsafe(32)
    app.state.internal_token = internal_token
    return app, internal_token


def _make_client_app(tmp_path: Path, own_server: str, internal_token: str, server_url: str):
    """Client app wired to an internal server URL."""
    from client.config import ClientConfig
    from client.main import create_app
    config_path = tmp_path / "client_config.json"
    ClientConfig(own_server=own_server, internal_token=internal_token).save(config_path)
    import os
    os.environ["CONTACC_SERVER_URL"] = server_url
    app = create_app(config_path)
    return app, config_path


def _session(client: TestClient, internal_token: str) -> dict:
    """Get a valid client session, mocking the server /auth/me check."""
    mock_resp = MagicMock(is_success=True)
    mock_resp.json.return_value = {"role": "owner"}
    mock_hc = MagicMock()
    mock_hc.get = AsyncMock(return_value=mock_resp)
    mock_hc.__aenter__ = AsyncMock(return_value=mock_hc)
    mock_hc.__aexit__ = AsyncMock(return_value=None)
    with patch("client.main.httpx.AsyncClient", return_value=mock_hc):
        token = client.post("/client/session", json={"token": "owner-tok"}).json()["token"]
    return {"Authorization": f"Bearer {token}"}


# ── server: internal token enforcement ───────────────────────────────────────

class TestServerInternalToken:
    def test_rejects_request_without_token(self, tmp_path):
        app, _ = _make_server_app(tmp_path)
        sc = TestClient(app)
        r = sc.get("/profile")
        assert r.status_code == 403

    def test_rejects_request_with_wrong_token(self, tmp_path):
        app, _ = _make_server_app(tmp_path)
        sc = TestClient(app)
        r = sc.get("/profile", headers={"x-contacc-internal": "wrong-token"})
        assert r.status_code == 403

    def test_allows_request_with_correct_token(self, tmp_path):
        app, token = _make_server_app(tmp_path)
        sc = TestClient(app)
        r = sc.get("/profile", headers={"x-contacc-internal": token})
        # Profile GET needs no auth, just internal token
        assert r.status_code == 200

    def test_setup_routes_bypass_internal_token(self, tmp_path):
        store = _make_store(tmp_path)
        from server.main import create_app
        app = create_app(store / "node_config.json")
        app.state.do_initialize(TEST_PASSPHRASE)
        app.state.internal_token = secrets.token_urlsafe(32)
        sc = TestClient(app)
        # /setup/status should work with no internal token
        r = sc.get("/setup/status")
        assert r.status_code == 200


# ── server: OAuth redirect has no trailing slash before fragment ──────────────

class TestOAuthRedirect:
    def test_callback_redirect_has_no_slash_before_fragment(self, tmp_path):
        from server.main import create_app
        from server import sso as sso_module

        store = _make_store(tmp_path)
        app = create_app(store / "node_config.json")
        app.state.do_initialize(TEST_PASSPHRASE)
        token = secrets.token_urlsafe(32)
        app.state.internal_token = token
        app.state.owner_identity = "google:owner@test.com"
        app.state.sso_config["google_client_id"] = "cid"
        app.state.sso_config["google_client_secret"] = "csecret"
        app.state.sso_exchange_google = lambda *a, **k: {"email": "owner@test.com"}

        db = app.state.db
        state = sso_module.generate_state(db, "google", return_to="https://node.example.com/auth/callback")
        sc = TestClient(app, follow_redirects=False)
        r = sc.get(f"/auth/callback?code=x&state={state}",
                   headers={"x-contacc-internal": token})
        assert r.status_code == 302
        location = r.headers["location"]
        # Fragment must come directly after the path with no trailing slash
        assert "/#token=" not in location
        assert "#token=" in location


# ── client: headers on own-server calls ──────────────────────────────────────

class TestClientOwnServerHeaders:
    """Verify client injects x-contacc-internal on calls to its own server."""

    def _captured_headers(self, tmp_path, route: str, method: str = "GET", **kwargs):
        """Return the headers the client sent to the (mocked) server for a given /api/ route."""
        own = "https://node.example.com"
        internal = secrets.token_urlsafe(32)

        from client.config import ClientConfig, save_tokens
        from client.main import create_app
        import os

        config_path = tmp_path / "client_config.json"
        ClientConfig(own_server=own, internal_token=internal).save(config_path)
        save_tokens(config_path, {own: "owner-server-tok"})
        os.environ["CONTACC_SERVER_URL"] = "http://server:9443"
        app = create_app(config_path)
        tc = TestClient(app)
        auth = _session(tc, internal)

        captured = {}

        async def mock_request(*args, **kw):
            captured["headers"] = dict(kw.get("headers", {}))
            resp = MagicMock(is_success=True)
            resp.json.return_value = {}
            resp.status_code = 200
            resp.headers = {"content-type": "application/json"}
            resp.content = b"{}"
            return resp

        mock_hc = MagicMock()
        mock_hc.get = AsyncMock(side_effect=mock_request)
        mock_hc.put = AsyncMock(side_effect=mock_request)
        mock_hc.__aenter__ = AsyncMock(return_value=mock_hc)
        mock_hc.__aexit__ = AsyncMock(return_value=None)

        with patch("client.main.httpx.AsyncClient", return_value=mock_hc):
            getattr(tc, method.lower())(route, headers=auth, **kwargs)

        return captured.get("headers", {}), internal

    def test_profile_get_sends_internal_token(self, tmp_path):
        headers, token = self._captured_headers(tmp_path, "/api/profile")
        assert headers.get("x-contacc-internal") == token

    def test_profile_put_sends_internal_token(self, tmp_path):
        headers, token = self._captured_headers(
            tmp_path, "/api/profile", method="PUT",
            json={"display_name": "Test"}
        )
        assert headers.get("x-contacc-internal") == token

    def test_own_server_calls_do_not_send_origin_header(self, tmp_path):
        headers, _ = self._captured_headers(tmp_path, "/api/profile")
        assert "x-origin-server" not in {k.lower() for k in headers}


# ── client: headers on cross-node calls ──────────────────────────────────────

class TestClientCrossNodeHeaders:
    """Verify client injects X-Origin-Server (not internal token) for remote servers."""

    def test_cross_node_asset_sends_origin_server(self, tmp_path):
        own = "https://node.example.com"
        remote = "https://remote.example.com"
        internal = secrets.token_urlsafe(32)

        from client.config import ClientConfig, ContactEntry
        from client.main import create_app
        import os

        config_path = tmp_path / "client_config.json"
        cfg = ClientConfig(own_server=own, internal_token=internal,
                           contacts=[ContactEntry(name="Remote", url=remote)])
        cfg.save(config_path)
        os.environ["CONTACC_SERVER_URL"] = "http://server:9443"
        app = create_app(config_path)
        tc = TestClient(app)
        auth = _session(tc, internal)

        captured = {}

        async def mock_request(*args, **kw):
            captured["headers"] = dict(kw.get("headers", {}))
            resp = MagicMock(is_success=True)
            resp.content = b"\xff\xd8\xff"  # minimal JPEG header
            resp.headers = {"content-type": "image/jpeg"}
            return resp

        mock_hc = MagicMock()
        mock_hc.get = AsyncMock(side_effect=mock_request)
        mock_hc.__aenter__ = AsyncMock(return_value=mock_hc)
        mock_hc.__aexit__ = AsyncMock(return_value=None)

        with patch("client.main.httpx.AsyncClient", return_value=mock_hc):
            tc.get(f"/api/assets/asset-123/thumb?server={remote}", headers=auth)

        h = {k.lower(): v for k, v in captured.get("headers", {}).items()}
        assert h.get("x-origin-server") == own
        assert "x-contacc-internal" not in h

    def test_cross_node_comments_sends_origin_server(self, tmp_path):
        own = "https://node.example.com"
        remote = "https://remote.example.com"
        internal = secrets.token_urlsafe(32)

        from client.config import ClientConfig, ContactEntry
        from client.main import create_app
        import os

        config_path = tmp_path / "client_config.json"
        ClientConfig(own_server=own, internal_token=internal,
                     contacts=[ContactEntry(name="Remote", url=remote)]).save(config_path)
        os.environ["CONTACC_SERVER_URL"] = "http://server:9443"
        app = create_app(config_path)
        tc = TestClient(app)
        auth = _session(tc, internal)

        captured = {}

        async def mock_request(*args, **kw):
            captured["headers"] = dict(kw.get("headers", {}))
            resp = MagicMock(is_success=True)
            resp.json.return_value = {"post_id": "p1", "comments": []}
            resp.status_code = 200
            resp.headers = {"content-type": "application/json"}
            return resp

        mock_hc = MagicMock()
        mock_hc.get = AsyncMock(side_effect=mock_request)
        mock_hc.__aenter__ = AsyncMock(return_value=mock_hc)
        mock_hc.__aexit__ = AsyncMock(return_value=None)

        with patch("client.main.httpx.AsyncClient", return_value=mock_hc):
            tc.get(f"/api/posts/post-123/comments?server={remote}", headers=auth)

        h = {k.lower(): v for k, v in captured.get("headers", {}).items()}
        assert h.get("x-origin-server") == own


# ── server: cross-node asset access via X-Origin-Server ──────────────────────

class TestServerAssetFederation:
    def _setup(self, tmp_path):
        app, token = _make_server_app(tmp_path)
        from server import auth as auth_module
        from server.db import init_schema
        init_schema(app.state.db)
        owner_token = auth_module.issue_token()
        return app, token, owner_token

    def _create_post_with_asset(self, app, token, owner_token):
        sc = TestClient(app)
        import io
        from PIL import Image
        buf = io.BytesIO()
        Image.new("RGB", (10, 10), color=(100, 100, 100)).save(buf, format="JPEG")
        buf.seek(0)

        r = sc.post("/posts", headers={
            "x-contacc-internal": token,
            "Authorization": f"Bearer {owner_token}",
        }, data={"body": "test post", "visibility": "contacts"},
           files={"files": ("test.jpg", buf, "image/jpeg")})
        assert r.status_code in (200, 201), r.text
        post = r.json()
        asset_ids = [a["id"] for a in post.get("assets", [])]
        return post["id"], asset_ids

    def test_asset_blocked_without_origin(self, tmp_path):
        app, token, owner_token = self._setup(tmp_path)
        post_id, asset_ids = self._create_post_with_asset(app, token, owner_token)
        if not asset_ids:
            pytest.skip("no assets on post")
        sc = TestClient(app)
        r = sc.get(f"/assets/{asset_ids[0]}/thumb",
                   headers={"x-contacc-internal": token})
        assert r.status_code == 403

    def test_asset_allowed_for_known_contact(self, tmp_path):
        app, token, owner_token = self._setup(tmp_path)
        contact_url = "https://contact.example.com"
        app.state.db.execute(
            "INSERT INTO contacts (server_url, name) VALUES (?, ?)", (contact_url, "Friend")
        )
        app.state.db.commit()
        post_id, asset_ids = self._create_post_with_asset(app, token, owner_token)
        if not asset_ids:
            pytest.skip("no assets on post")
        sc = TestClient(app)
        r = sc.get(f"/assets/{asset_ids[0]}/thumb", headers={
            "x-contacc-internal": token,
            "X-Origin-Server": contact_url,
        })
        assert r.status_code == 200
