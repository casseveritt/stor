"""Phase 2: QueryFeed tests."""
import json
import time
import uuid
import pytest
from fastapi.testclient import TestClient

from server.auth import issue_token, setup as auth_setup
from tests.conftest import TEST_PASSPHRASE, TEST_SALT, TEST_ARGON2
from server.crypto import derive_master_key, derive_subkeys
import base64
from server.crypto import decrypt_bytes


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def token(store):
    """Issue a valid owner token using the test store's private key."""
    from server.config import NodeConfig
    config = NodeConfig.load(store / "node_config.json")
    master_key = derive_master_key(TEST_PASSPHRASE, TEST_SALT, **TEST_ARGON2)
    privkey_bytes = decrypt_bytes(base64.b64decode(config.encrypted_private_key), master_key)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    private_key = Ed25519PrivateKey.from_private_bytes(privkey_bytes)
    auth_setup(private_key)
    return issue_token(ttl_seconds=3600)


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _insert_asset(db, **kwargs):
    asset_id = kwargs.get("id", str(uuid.uuid4()))
    db.execute(
        """INSERT INTO assets (id, content_hash, media_type, size, created_at, title, tags, predecessor, successor)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            asset_id,
            kwargs.get("content_hash", "deadbeef"),
            kwargs.get("media_type", "image/jpeg"),
            kwargs.get("size", 1024),
            kwargs.get("created_at", time.time()),
            kwargs.get("title", None),
            json.dumps(kwargs.get("tags", [])),
            kwargs.get("predecessor", None),
            kwargs.get("successor", None),
        ),
    )
    db.commit()
    return asset_id


# ── auth enforcement ──────────────────────────────────────────────────────────

class TestFeedAuth:
    def test_no_token_returns_public_feed(self, client):
        r = client.get("/feed")
        assert r.status_code == 200
        assert "assets" in r.json()

    def test_bad_token_rejected(self, client):
        r = client.get("/feed", headers={"Authorization": "Bearer notavalidtoken"})
        assert r.status_code == 401

    def test_valid_token_accepted(self, client, token):
        r = client.get("/feed", headers=_auth(token))
        assert r.status_code == 200


# ── feed content ──────────────────────────────────────────────────────────────

class TestFeedContent:
    def test_empty_feed(self, client, token):
        r = client.get("/feed", headers=_auth(token))
        assert r.status_code == 200
        data = r.json()
        assert "assets" in data
        assert isinstance(data["assets"], list)

    def test_response_envelope(self, client, token):
        r = client.get("/feed", headers=_auth(token))
        data = r.json()
        assert "node" in data
        assert "until" in data
        assert "include_superseded" in data

    def test_asset_appears_in_feed(self, client, token):
        db = client.app.state.db
        asset_id = _insert_asset(db, title="test photo", tags=["vacation"])
        r = client.get("/feed", headers=_auth(token))
        ids = [a["id"] for a in r.json()["assets"]]
        assert asset_id in ids

    def test_asset_fields(self, client, token):
        db = client.app.state.db
        asset_id = _insert_asset(db, title="field check", media_type="image/png", size=2048, tags=["a", "b"])
        r = client.get("/feed", headers=_auth(token))
        asset = next(a for a in r.json()["assets"] if a["id"] == asset_id)
        assert asset["media_type"] == "image/png"
        assert asset["size"] == 2048
        assert asset["title"] == "field check"
        assert asset["tags"] == ["a", "b"]
        assert "content_hash" in asset
        assert "created_at" in asset
        assert "node" in asset

    def test_superseded_hidden_by_default(self, client, token):
        db = client.app.state.db
        old_id = _insert_asset(db, title="old version")
        new_id = _insert_asset(db, title="new version", predecessor=old_id)
        db.execute("UPDATE assets SET successor=? WHERE id=?", (new_id, old_id))
        db.commit()
        r = client.get("/feed", headers=_auth(token))
        ids = [a["id"] for a in r.json()["assets"]]
        assert old_id not in ids
        assert new_id in ids

    def test_include_superseded(self, client, token):
        db = client.app.state.db
        old_id = _insert_asset(db, title="old v2")
        new_id = _insert_asset(db, title="new v2", predecessor=old_id)
        db.execute("UPDATE assets SET successor=? WHERE id=?", (new_id, old_id))
        db.commit()
        r = client.get("/feed?include_superseded=true", headers=_auth(token))
        ids = [a["id"] for a in r.json()["assets"]]
        assert old_id in ids
        assert new_id in ids


# ── pagination ────────────────────────────────────────────────────────────────

class TestFeedPagination:
    def test_limit_respected(self, client, token):
        db = client.app.state.db
        for _ in range(5):
            _insert_asset(db)
        r = client.get("/feed?limit=3", headers=_auth(token))
        assert len(r.json()["assets"]) <= 3

    def test_cursor_advances(self, client, token):
        db = client.app.state.db
        # Insert enough assets to guarantee two pages at limit=2
        for _ in range(4):
            _insert_asset(db)
        r1 = client.get("/feed?limit=2", headers=_auth(token))
        data1 = r1.json()
        assert "next_cursor" in data1
        r2 = client.get(f"/feed?limit=2&cursor={data1['next_cursor']}", headers=_auth(token))
        data2 = r2.json()
        ids1 = {a["id"] for a in data1["assets"]}
        ids2 = {a["id"] for a in data2["assets"]}
        assert ids1.isdisjoint(ids2), "Pages must not overlap"

    def test_no_cursor_when_last_page(self, client, token):
        db = client.app.state.db
        r = client.get(f"/feed?limit={200}", headers=_auth(token))
        data = r.json()
        # If all results fit in one page there should be no next_cursor
        if len(data["assets"]) < 200:
            assert "next_cursor" not in data


# ── time window ───────────────────────────────────────────────────────────────

class TestFeedTimeWindow:
    def test_since_filters_old(self, client, token):
        db = client.app.state.db
        old_id = _insert_asset(db, created_at=1000.0)  # epoch + 1000s, definitely old
        r = client.get("/feed?since=1000000000", headers=_auth(token))  # year 2001+
        ids = [a["id"] for a in r.json()["assets"]]
        assert old_id not in ids

    def test_until_filters_future(self, client, token):
        db = client.app.state.db
        future_id = _insert_asset(db, created_at=time.time() + 9999)
        r = client.get("/feed", headers=_auth(token))  # until defaults to now
        ids = [a["id"] for a in r.json()["assets"]]
        assert future_id not in ids
