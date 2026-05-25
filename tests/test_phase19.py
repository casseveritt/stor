"""Phase 19: UI polish — /auth/me endpoint, tags sidebar, keyboard nav, identity badge."""
import base64
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from server.auth import issue_token, issue_recipient_token, issue_share_token, setup as auth_setup
from server.crypto import derive_master_key, decrypt_bytes
from tests.conftest import TEST_PASSPHRASE, TEST_SALT, TEST_ARGON2


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def owner_token(store):
    from server.config import NodeConfig
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    config = NodeConfig.load(store / "node_config.json")
    master_key = derive_master_key(TEST_PASSPHRASE, TEST_SALT, **TEST_ARGON2)
    privkey_bytes = decrypt_bytes(base64.b64decode(config.encrypted_private_key), master_key)
    auth_setup(Ed25519PrivateKey.from_private_bytes(privkey_bytes))
    return issue_token(ttl_seconds=3600)


@pytest.fixture(scope="module")
def recipient_token(client, owner_token):
    r = client.post(
        "/recipients",
        json={"identity": "phase19@example.com", "display_name": "Phase 19 User"},
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert r.status_code == 201
    recipient_id = r.json()["id"]
    db = client.app.state.db
    return issue_recipient_token(db, recipient_id, ttl_seconds=3600)


@pytest.fixture(scope="module")
def share_token(client, owner_token, sample_asset_id):
    r = client.post(
        "/share-tokens",
        json={"identity": "sharer@example.com", "asset_ids": [sample_asset_id]},
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert r.status_code == 201
    return r.json()["token"]


@pytest.fixture(scope="module")
def sample_asset_id(client, owner_token):
    r = client.post(
        "/assets",
        files={"file": ("phase19.txt", b"phase 19 test content", "text/plain")},
        data={"title": "Phase 19 Asset", "tags": json.dumps(["phase19"])},
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert r.status_code == 201
    return r.json()["id"]


# ── GET /auth/me ──────────────────────────────────────────────────────────────

class TestAuthMe:
    def test_owner_returns_owner_role(self, client, owner_token):
        r = client.get("/auth/me", headers={"Authorization": f"Bearer {owner_token}"})
        assert r.status_code == 200
        data = r.json()
        assert data["role"] == "owner"
        assert data["identity"] == "owner"

    def test_recipient_returns_recipient_role(self, client, recipient_token):
        r = client.get("/auth/me", headers={"Authorization": f"Bearer {recipient_token}"})
        assert r.status_code == 200
        data = r.json()
        assert data["role"] == "recipient"
        assert data["identity"] == "phase19@example.com"
        assert data["display_name"] == "Phase 19 User"

    def test_share_returns_share_role(self, client, share_token):
        r = client.get("/auth/me", headers={"Authorization": f"Bearer {share_token}"})
        assert r.status_code == 200
        data = r.json()
        assert data["role"] == "share"
        assert "identity" in data

    def test_no_auth_returns_401(self, client):
        r = client.get("/auth/me")
        assert r.status_code == 401

    def test_bad_token_returns_401(self, client):
        r = client.get("/auth/me", headers={"Authorization": "Bearer not-a-real-token"})
        assert r.status_code == 401

    def test_owner_me_via_query_param(self, client, owner_token):
        r = client.get(f"/auth/me?token={owner_token}")
        assert r.status_code == 200
        assert r.json()["role"] == "owner"


# ── tags sidebar data ─────────────────────────────────────────────────────────

class TestTagsForSidebar:
    def test_tags_endpoint_accessible(self, client, owner_token, sample_asset_id):
        r = client.get("/tags", headers={"Authorization": f"Bearer {owner_token}"})
        assert r.status_code == 200
        data = r.json()
        assert "tags" in data
        assert isinstance(data["tags"], list)

    def test_tags_have_count(self, client, owner_token, sample_asset_id):
        r = client.get("/tags", headers={"Authorization": f"Bearer {owner_token}"})
        tags = r.json()["tags"]
        if tags:
            assert "tag" in tags[0]
            assert "count" in tags[0]

    def test_phase19_tag_present(self, client, owner_token, sample_asset_id):
        r = client.get("/tags", headers={"Authorization": f"Bearer {owner_token}"})
        tag_names = {t["tag"] for t in r.json()["tags"]}
        assert "phase19" in tag_names

    def test_feed_filtered_by_tag(self, client, owner_token, sample_asset_id):
        r = client.get(
            "/feed",
            params={"tags": "phase19"},
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert r.status_code == 200
        assets = r.json()["assets"]
        assert all("phase19" in a["tags"] for a in assets)
        assert any(a["id"] == sample_asset_id for a in assets)


# ── index.html serves SPA ─────────────────────────────────────────────────────

class TestSPAShell:
    def test_root_returns_html(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]

    def test_html_has_sidebar(self, client):
        r = client.get("/")
        assert "sidebar" in r.text

    def test_html_has_identity_badge(self, client):
        r = client.get("/")
        assert "identity-badge" in r.text or "identity" in r.text

    def test_html_has_nav_arrows(self, client):
        r = client.get("/")
        assert "nav-prev" in r.text or "←" in r.text

    def test_html_has_feed_status(self, client):
        r = client.get("/")
        assert "feed-status" in r.text

    def test_html_references_auth_me(self, client):
        r = client.get("/")
        assert "/auth/me" in r.text
