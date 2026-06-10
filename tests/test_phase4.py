"""Phase 4: ACL enforcement and recipient token tests."""
import io
import json
import time
import uuid

import pytest
from PIL import Image

from server.auth import (
    TokenIdentity, check_acl, issue_node_token,
    setup as auth_setup, issue_token, revoke_token,
)
from server.crypto import derive_master_key, derive_subkeys, decrypt_bytes, encrypt_bytes
from tests.conftest import TEST_PASSPHRASE, TEST_SALT, TEST_ARGON2
from tests.test_phase3 import _make_jpeg, _store_file


# ── shared helpers ─────────────────────────────────────────────────────────────

def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _insert_asset(db, **kwargs):
    asset_id = kwargs.get("id", str(uuid.uuid4()))
    db.execute(
        """INSERT INTO assets (id, content_hash, media_type, size, created_at, title, tags)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            asset_id,
            kwargs.get("content_hash", "aabbccdd" * 8),
            kwargs.get("media_type", "image/jpeg"),
            kwargs.get("size", 1024),
            kwargs.get("created_at", time.time()),
            kwargs.get("title", None),
            json.dumps(kwargs.get("tags", [])),
        ),
    )
    db.commit()
    return asset_id


def _add_recipient(db, identity="google:alice@example.com", display_name="Alice"):
    recipient_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO recipients (id, identity, display_name) VALUES (?, ?, ?)",
        (recipient_id, identity, display_name),
    )
    db.commit()
    return recipient_id


def _grant_acl(db, asset_id, recipient_id):
    db.execute("INSERT OR IGNORE INTO acl (asset_id, recipient_id) VALUES (?, ?)", (asset_id, recipient_id))
    db.commit()


# ── module-scoped fixtures ─────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def owner_token(store):
    from server.config import NodeConfig
    import base64
    config = NodeConfig.load(store / "node_config.json")
    master_key = derive_master_key(TEST_PASSPHRASE, TEST_SALT, **TEST_ARGON2)
    privkey_bytes = decrypt_bytes(base64.b64decode(config.encrypted_private_key), master_key)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    auth_setup(Ed25519PrivateKey.from_private_bytes(privkey_bytes))
    return issue_token(ttl_seconds=3600)


@pytest.fixture(scope="module")
def alice(client):
    """A recipient with a DB token and two assets: one ACL'd, one not."""
    db = client.app.state.db
    recipient_id = _add_recipient(db, "google:alice@test.com", "Alice")

    # Asset Alice can access
    allowed_id = _insert_asset(db, title="Alice can see this")
    _grant_acl(db, allowed_id, recipient_id)

    # Asset Alice cannot access
    denied_id = _insert_asset(db, title="Alice cannot see this")

    token = issue_node_token(db, recipient_id, ttl_seconds=3600)
    return {
        "recipient_id": recipient_id,
        "token": token,
        "allowed_asset_id": allowed_id,
        "denied_asset_id": denied_id,
    }


@pytest.fixture(scope="module")
def image_asset_acl(store, client, alice):
    """A real encrypted JPEG ACL'd to Alice."""
    content = _make_jpeg(60, 60, color=(0, 128, 0))
    content_hash = "11223344" * 8
    file_key = client.app.state.file_key
    _store_file(store, file_key, content, content_hash)
    db = client.app.state.db
    asset_id = _insert_asset(db, content_hash=content_hash, media_type="image/jpeg", size=len(content))
    _grant_acl(db, asset_id, alice["recipient_id"])
    return {"id": asset_id, "content_hash": content_hash, "content": content}


# ── token validation ──────────────────────────────────────────────────────────

class TestTokenValidation:
    def test_expired_token_rejected(self, client):
        db = client.app.state.db
        recipient_id = _add_recipient(db, "google:expired@test.com", "Expired")
        # Issue a token then manually set its expiry to the past
        token = issue_node_token(db, recipient_id, ttl_seconds=3600)
        db.execute("UPDATE tokens SET expiry = ? WHERE id = ?", (time.time() - 1, token))
        db.commit()
        r = client.get("/feed", headers=_auth(token))
        assert r.status_code == 401

    def test_revoked_token_rejected(self, client):
        db = client.app.state.db
        recipient_id = _add_recipient(db, "google:revoked@test.com", "Revoked")
        token = issue_node_token(db, recipient_id, ttl_seconds=3600)
        revoke_token(db, token)
        r = client.get("/feed", headers=_auth(token))
        assert r.status_code == 401

    def test_owner_token_always_valid(self, client, owner_token):
        r = client.get("/feed", headers=_auth(owner_token))
        assert r.status_code == 200


# ── ACL on fetch endpoints ────────────────────────────────────────────────────

class TestFetchACL:
    def test_recipient_can_fetch_allowed_asset(self, client, alice, image_asset_acl):
        r = client.get(f"/assets/{image_asset_acl['id']}", headers=_auth(alice["token"]))
        assert r.status_code == 200
        assert r.content == image_asset_acl["content"]

    def test_recipient_denied_on_other_asset(self, client, alice):
        r = client.get(f"/assets/{alice['denied_asset_id']}", headers=_auth(alice["token"]))
        assert r.status_code == 403

    def test_recipient_can_fetch_meta_of_allowed(self, client, alice, image_asset_acl):
        r = client.get(f"/assets/{image_asset_acl['id']}/meta", headers=_auth(alice["token"]))
        assert r.status_code == 200

    def test_recipient_denied_meta_of_other(self, client, alice):
        r = client.get(f"/assets/{alice['denied_asset_id']}/meta", headers=_auth(alice["token"]))
        assert r.status_code == 403

    def test_recipient_can_fetch_thumb_of_allowed(self, client, alice, image_asset_acl):
        r = client.get(f"/assets/{image_asset_acl['id']}/thumb", headers=_auth(alice["token"]))
        assert r.status_code == 200

    def test_recipient_denied_thumb_of_other(self, client, alice):
        r = client.get(f"/assets/{alice['denied_asset_id']}/thumb", headers=_auth(alice["token"]))
        assert r.status_code == 403

    def test_owner_sees_all_assets(self, client, owner_token, alice):
        r = client.get("/feed", headers=_auth(owner_token))
        ids = {a["id"] for a in r.json()["assets"]}
        assert alice["allowed_asset_id"] in ids
        assert alice["denied_asset_id"] in ids


# ── feed ACL filtering ────────────────────────────────────────────────────────

class TestFeedACL:
    def test_recipient_sees_only_acl_assets(self, client, alice):
        r = client.get("/feed", headers=_auth(alice["token"]))
        assert r.status_code == 200
        ids = {a["id"] for a in r.json()["assets"]}
        assert alice["allowed_asset_id"] in ids
        assert alice["denied_asset_id"] not in ids

    def test_acl_grant_makes_asset_visible(self, client, alice):
        db = client.app.state.db
        new_asset_id = _insert_asset(db, title="Newly granted")
        # Not yet in feed
        r = client.get("/feed", headers=_auth(alice["token"]))
        ids = {a["id"] for a in r.json()["assets"]}
        assert new_asset_id not in ids
        # Grant ACL
        _grant_acl(db, new_asset_id, alice["recipient_id"])
        r = client.get("/feed", headers=_auth(alice["token"]))
        ids = {a["id"] for a in r.json()["assets"]}
        assert new_asset_id in ids


# ── check_acl helper ──────────────────────────────────────────────────────────

class TestCheckAcl:
    def test_owner_always_passes(self, client, alice):
        db = client.app.state.db
        owner = TokenIdentity(is_owner=True)
        assert check_acl(db, alice["denied_asset_id"], owner) is True

    def test_recipient_with_acl_passes(self, client, alice):
        db = client.app.state.db
        identity = TokenIdentity(is_owner=False, recipient_id=alice["recipient_id"])
        assert check_acl(db, alice["allowed_asset_id"], identity) is True

    def test_recipient_without_acl_fails(self, client, alice):
        db = client.app.state.db
        identity = TokenIdentity(is_owner=False, recipient_id=alice["recipient_id"])
        assert check_acl(db, alice["denied_asset_id"], identity) is False
