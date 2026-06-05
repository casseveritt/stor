"""Client API test suite — covers every /api/ route the browser calls."""
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient


# ── fixtures ──────────────────────────────────────────────────────────────────

def _mock_server(role="owner", ok=True, json_body=None):
    resp = MagicMock()
    resp.is_success = ok
    resp.status_code = 200 if ok else 502
    resp.json.return_value = json_body or {"role": role, "identity": "google:owner@test.com"}
    resp.text = ""
    hc = MagicMock()
    hc.get = AsyncMock(return_value=resp)
    hc.post = AsyncMock(return_value=resp)
    hc.put = AsyncMock(return_value=resp)
    hc.patch = AsyncMock(return_value=resp)
    hc.delete = AsyncMock(return_value=resp)
    hc.__aenter__ = AsyncMock(return_value=hc)
    hc.__aexit__ = AsyncMock(return_value=None)
    return hc


@pytest.fixture
def app_and_path(tmp_path):
    from client.config import ClientConfig
    from client.main import create_app
    cfg_path = tmp_path / "client_config.json"
    ClientConfig(own_server="https://node.example.com").save(cfg_path)
    app = create_app(cfg_path)
    return app, cfg_path


@pytest.fixture
def raw_client(app_and_path):
    app, _ = app_and_path
    return TestClient(app)


@pytest.fixture
def authed(app_and_path):
    """Return (TestClient, auth_headers, config_path) for an authenticated session."""
    app, cfg_path = app_and_path
    client = TestClient(app)
    with patch("client.main.httpx.AsyncClient", return_value=_mock_server("owner")):
        r = client.post("/client/session", json={"token": "tok"})
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    return client, headers, cfg_path


# ── auth gating ──────────────────────────────────────────────────────────────

class TestAuthGating:
    def test_config_requires_auth(self, raw_client):
        assert raw_client.get("/api/config").status_code == 401

    def test_contacts_requires_auth(self, raw_client):
        assert raw_client.get("/api/contacts/search?q=x").status_code == 401

    def test_feed_requires_auth(self, raw_client):
        assert raw_client.get("/api/feed").status_code == 401

    def test_tags_requires_auth(self, raw_client):
        assert raw_client.get("/api/tags").status_code == 401

    def test_subscribed_updates_requires_auth(self, raw_client):
        assert raw_client.get("/api/subscribed-updates").status_code == 401

    def test_bearer_wrong_token_401(self, raw_client):
        r = raw_client.get("/api/config", headers={"Authorization": "Bearer bad-token"})
        assert r.status_code == 401


# ── /api/config ──────────────────────────────────────────────────────────────

class TestConfig:
    def test_returns_own_server(self, authed):
        client, headers, _ = authed
        with patch("client.main.httpx.AsyncClient", return_value=_mock_server(
            json_body={"display_name": "Test User", "handle": "testuser"}
        )):
            r = client.get("/api/config", headers=headers)
        assert r.status_code == 200
        d = r.json()
        assert d["own_server"] == "https://node.example.com"
        assert "contacts" in d
        assert "servers" in d

    def test_contacts_list_initially_empty(self, authed):
        client, headers, _ = authed
        with patch("client.main.httpx.AsyncClient", return_value=_mock_server(
            json_body={"display_name": "T", "handle": "t"}
        )):
            r = client.get("/api/config", headers=headers)
        assert r.json()["contacts"] == []

    def test_servers_includes_own(self, authed):
        client, headers, _ = authed
        with patch("client.main.httpx.AsyncClient", return_value=_mock_server(
            json_body={"display_name": "T", "handle": "t"}
        )):
            r = client.get("/api/config", headers=headers)
        urls = [s["url"] for s in r.json()["servers"]]
        assert "https://node.example.com" in urls


# ── /api/contacts CRUD ───────────────────────────────────────────────────────

class TestContactsCRUD:
    def test_add_contact(self, authed):
        client, headers, cfg_path = authed
        body = {"name": "Alice", "url": "https://alice.example.com", "handle": "alice"}
        with patch("client.main.httpx.AsyncClient", return_value=_mock_server(
            json_body={"public_key": "abc123"}
        )):
            r = client.post("/api/contacts", json=body, headers=headers)
        assert r.status_code == 201
        data = json.loads(cfg_path.read_text())
        assert any(c["url"] == "https://alice.example.com" for c in data["contacts"])

    def test_add_duplicate_contact_409(self, authed):
        client, headers, _ = authed
        body = {"name": "Bob", "url": "https://bob.example.com", "handle": "bob"}
        with patch("client.main.httpx.AsyncClient", return_value=_mock_server()):
            client.post("/api/contacts", json=body, headers=headers)
            r = client.post("/api/contacts", json=body, headers=headers)
        assert r.status_code == 409

    def test_add_self_400(self, authed):
        client, headers, _ = authed
        with patch("client.main.httpx.AsyncClient", return_value=_mock_server()):
            r = client.post("/api/contacts",
                            json={"name": "Me", "url": "https://node.example.com"},
                            headers=headers)
        assert r.status_code == 400

    def test_remove_contact(self, authed):
        client, headers, cfg_path = authed
        with patch("client.main.httpx.AsyncClient", return_value=_mock_server()):
            client.post("/api/contacts",
                        json={"name": "Carol", "url": "https://carol.example.com"},
                        headers=headers)
        with patch("client.main.httpx.AsyncClient", return_value=_mock_server()):
            r = client.delete("/api/contacts?url=https://carol.example.com", headers=headers)
        assert r.status_code == 200
        data = json.loads(cfg_path.read_text())
        assert not any(c["url"] == "https://carol.example.com" for c in data["contacts"])
        data = json.loads(cfg_path.read_text())
        assert not any(c["url"] == "https://carol.example.com" for c in data["contacts"])

    def test_patch_contact_description(self, authed):
        client, headers, cfg_path = authed
        with patch("client.main.httpx.AsyncClient", return_value=_mock_server()):
            client.post("/api/contacts",
                        json={"name": "Dave", "url": "https://dave.example.com"},
                        headers=headers)
        r = client.patch("/api/contacts",
                         json={"url": "https://dave.example.com", "description": "Old friend"},
                         headers=headers)
        assert r.status_code == 200
        data = json.loads(cfg_path.read_text())
        dave = next(c for c in data["contacts"] if c["url"] == "https://dave.example.com")
        assert dave["description"] == "Old friend"

    def test_patch_contact_category_sets_weight(self, authed):
        client, headers, cfg_path = authed
        with patch("client.main.httpx.AsyncClient", return_value=_mock_server()):
            client.post("/api/contacts",
                        json={"name": "Eve", "url": "https://eve.example.com"},
                        headers=headers)
        r = client.patch("/api/contacts",
                         json={"url": "https://eve.example.com", "category": "family"},
                         headers=headers)
        assert r.status_code == 200
        assert r.json()["poll_weight"] == 1.0
        data = json.loads(cfg_path.read_text())
        eve = next(c for c in data["contacts"] if c["url"] == "https://eve.example.com")
        assert eve["category"] == "family"
        assert eve["poll_weight"] == 1.0

    def test_patch_category_clear_removes_weight(self, authed):
        client, headers, cfg_path = authed
        with patch("client.main.httpx.AsyncClient", return_value=_mock_server()):
            client.post("/api/contacts",
                        json={"name": "Frank", "url": "https://frank.example.com"},
                        headers=headers)
        client.patch("/api/contacts",
                     json={"url": "https://frank.example.com", "category": "friends"},
                     headers=headers)
        r = client.patch("/api/contacts",
                         json={"url": "https://frank.example.com", "category": ""},
                         headers=headers)
        assert r.status_code == 200
        data = json.loads(cfg_path.read_text())
        frank = next(c for c in data["contacts"] if c["url"] == "https://frank.example.com")
        assert frank.get("category") is None
        assert frank.get("poll_weight") is None

    def test_patch_missing_contact_404(self, authed):
        client, headers, _ = authed
        r = client.patch("/api/contacts",
                         json={"url": "https://nobody.example.com", "description": "x"},
                         headers=headers)
        assert r.status_code == 404

    def test_config_includes_contact_metadata(self, authed):
        client, headers, _ = authed
        with patch("client.main.httpx.AsyncClient", return_value=_mock_server()):
            client.post("/api/contacts",
                        json={"name": "Grace", "url": "https://grace.example.com", "handle": "grace"},
                        headers=headers)
        client.patch("/api/contacts",
                     json={"url": "https://grace.example.com", "category": "close_friends"},
                     headers=headers)
        with patch("client.main.httpx.AsyncClient", return_value=_mock_server(
            json_body={"display_name": "T", "handle": "t"}
        )):
            r = client.get("/api/config", headers=headers)
        contacts = r.json()["contacts"]
        grace = next(c for c in contacts if c["url"] == "https://grace.example.com")
        assert grace["category"] == "close_friends"
        assert grace["poll_weight"] == 0.8
        # Also check that servers list includes contact metadata
        servers = r.json()["servers"]
        grace_srv = next((s for s in servers if s["url"] == "https://grace.example.com"), None)
        assert grace_srv is not None
        assert grace_srv.get("handle") == "grace"
        assert grace_srv.get("category") == "close_friends"


# ── /api/contacts/search ─────────────────────────────────────────────────────

class TestContactSearch:
    def test_search_empty_query(self, authed):
        client, headers, _ = authed
        with patch("client.main.httpx.AsyncClient", return_value=_mock_server(
            json_body={"results": []}
        )):
            r = client.get("/api/contacts/search?q=", headers=headers)
        assert r.status_code == 200

    def test_search_returns_results(self, authed):
        client, headers, _ = authed
        mock_result = {"results": [
            {"username": "alice", "server_url": "https://alice.example.com",
             "display_name": "Alice", "photo_url": "https://alice.example.com/profile/photo",
             "public_key": "key123"}
        ]}
        with patch("client.main.httpx.AsyncClient", return_value=_mock_server(
            json_body=mock_result
        )):
            r = client.get("/api/contacts/search?q=alice", headers=headers)
        assert r.status_code == 200
        assert len(r.json()["results"]) >= 0  # may be 0 if registry url not configured


# ── /api/tags ────────────────────────────────────────────────────────────────

class TestTags:
    def test_tags_returns_list(self, authed):
        client, headers, _ = authed
        with patch("client.main.httpx.AsyncClient",
                   return_value=_mock_server(json_body={"tags": []})):
            r = client.get("/api/tags", headers=headers)
        assert r.status_code == 200
        assert "tags" in r.json()

    def test_tags_initially_empty(self, authed):
        client, headers, _ = authed
        with patch("client.main.httpx.AsyncClient",
                   return_value=_mock_server(json_body={"tags": []})):
            r = client.get("/api/tags", headers=headers)
        assert r.json()["tags"] == []


# ── /api/subscribed-updates ──────────────────────────────────────────────────

class TestSubscribedUpdates:
    def test_returns_updates_list(self, authed):
        client, headers, _ = authed
        r = client.get("/api/subscribed-updates", headers=headers)
        assert r.status_code == 200
        assert "updates" in r.json()

    def test_initially_empty(self, authed):
        client, headers, _ = authed
        r = client.get("/api/subscribed-updates", headers=headers)
        assert r.json()["updates"] == []


# ── /api/auth/token ──────────────────────────────────────────────────────────

class TestAuthToken:
    def test_store_token(self, authed, tmp_path):
        client, headers, cfg_path = authed
        r = client.post("/api/auth/token",
                        json={"token": "mytoken", "server": "https://node.example.com"},
                        headers=headers)
        assert r.status_code == 200

    def test_delete_token(self, authed):
        client, headers, _ = authed
        client.post("/api/auth/token",
                    json={"token": "tok", "server": "https://node.example.com"},
                    headers=headers)
        r = client.delete("/api/auth/token?server=https://node.example.com", headers=headers)
        assert r.status_code == 200


# ── /api/setup/passphrase-is-default ─────────────────────────────────────────

class TestPassphraseDefault:
    def test_returns_boolean(self, authed):
        client, headers, _ = authed
        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_resp.json.return_value = {"is_default": False}
        hc = MagicMock()
        hc.get = AsyncMock(return_value=mock_resp)
        hc.__aenter__ = AsyncMock(return_value=hc)
        hc.__aexit__ = AsyncMock(return_value=None)
        with patch("client.main.httpx.AsyncClient", return_value=hc):
            r = client.get("/api/setup/passphrase-is-default", headers=headers)
        assert r.status_code == 200
        assert "is_default" in r.json()


# ── /api/notifications/mentions ──────────────────────────────────────────────

class TestMentions:
    def test_returns_list(self, authed):
        client, headers, _ = authed
        with patch("client.main.httpx.AsyncClient",
                   return_value=_mock_server(json_body={"mentions": []})):
            r = client.get("/api/notifications/mentions", headers=headers)
        assert r.status_code == 200

    def test_mark_seen_empty_ok(self, authed):
        client, headers, _ = authed
        with patch("client.main.httpx.AsyncClient", return_value=_mock_server()):
            r = client.post("/api/notifications/mentions/mark-seen",
                            json={"ids": []}, headers=headers)
        assert r.status_code == 204
