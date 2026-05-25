"""Phase 9: Recipient/token management, comment_count, initial ACL on publish."""
import base64
import time
import uuid

import pytest

from server.auth import issue_token, issue_recipient_token, setup as auth_setup
from server.crypto import derive_master_key, decrypt_bytes
from tests.conftest import TEST_PASSPHRASE, TEST_SALT, TEST_ARGON2


# ── helpers ───────────────────────────────────────────────────────────────────

def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _publish(client, owner_token, content=b"data", media_type="text/plain"):
    r = client.post(
        "/assets",
        files={"file": ("f.txt", content, media_type)},
        headers=_auth(owner_token),
    )
    assert r.status_code == 201
    return r.json()["id"]


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


# ── recipient management ──────────────────────────────────────────────────────

class TestRecipients:
    def test_create_recipient(self, client, owner_token):
        r = client.post(
            "/recipients",
            json={"identity": "google:new@test.com", "display_name": "New User"},
            headers=_auth(owner_token),
        )
        assert r.status_code == 201
        data = r.json()
        assert data["identity"] == "google:new@test.com"
        assert data["display_name"] == "New User"
        assert "id" in data

    def test_create_recipient_defaults_display_name(self, client, owner_token):
        r = client.post(
            "/recipients",
            json={"identity": "google:noname@test.com"},
            headers=_auth(owner_token),
        )
        assert r.status_code == 201
        assert r.json()["display_name"] == "google:noname@test.com"

    def test_list_recipients_includes_created(self, client, owner_token):
        r = client.post(
            "/recipients",
            json={"identity": "google:list-test@test.com"},
            headers=_auth(owner_token),
        )
        created_id = r.json()["id"]
        r2 = client.get("/recipients", headers=_auth(owner_token))
        assert r2.status_code == 200
        ids = [rec["id"] for rec in r2.json()["recipients"]]
        assert created_id in ids

    def test_get_recipient(self, client, owner_token):
        r = client.post(
            "/recipients",
            json={"identity": "google:get-test@test.com"},
            headers=_auth(owner_token),
        )
        recipient_id = r.json()["id"]
        r2 = client.get(f"/recipients/{recipient_id}", headers=_auth(owner_token))
        assert r2.status_code == 200
        assert r2.json()["id"] == recipient_id

    def test_duplicate_identity_rejected(self, client, owner_token):
        identity = f"google:dup-{uuid.uuid4()}@test.com"
        client.post("/recipients", json={"identity": identity}, headers=_auth(owner_token))
        r = client.post("/recipients", json={"identity": identity}, headers=_auth(owner_token))
        assert r.status_code == 409

    def test_delete_recipient(self, client, owner_token):
        r = client.post(
            "/recipients",
            json={"identity": "google:todelete@test.com"},
            headers=_auth(owner_token),
        )
        recipient_id = r.json()["id"]
        r2 = client.delete(f"/recipients/{recipient_id}", headers=_auth(owner_token))
        assert r2.status_code == 204
        r3 = client.get(f"/recipients/{recipient_id}", headers=_auth(owner_token))
        assert r3.status_code == 404

    def test_delete_cascades_acl(self, client, owner_token):
        r = client.post(
            "/recipients",
            json={"identity": "google:cascade@test.com"},
            headers=_auth(owner_token),
        )
        recipient_id = r.json()["id"]
        asset_id = _publish(client, owner_token)
        client.put(
            f"/assets/{asset_id}/acl",
            json={"add": [recipient_id]},
            headers=_auth(owner_token),
        )
        client.delete(f"/recipients/{recipient_id}", headers=_auth(owner_token))
        r2 = client.get(f"/assets/{asset_id}/acl", headers=_auth(owner_token))
        # ACL endpoint doesn't exist, check via token that access is gone
        db = client.app.state.db
        row = db.execute(
            "SELECT 1 FROM acl WHERE asset_id = ? AND recipient_id = ?",
            (asset_id, recipient_id),
        ).fetchone()
        assert row is None

    def test_delete_cascades_tokens(self, client, owner_token):
        r = client.post(
            "/recipients",
            json={"identity": "google:tokencascade@test.com"},
            headers=_auth(owner_token),
        )
        recipient_id = r.json()["id"]
        db = client.app.state.db
        token = issue_recipient_token(db, recipient_id, ttl_seconds=3600)
        client.delete(f"/recipients/{recipient_id}", headers=_auth(owner_token))
        # Token should now be revoked
        r2 = client.get("/feed", headers=_auth(token))
        assert r2.status_code == 401

    def test_unknown_recipient_404(self, client, owner_token):
        r = client.get(f"/recipients/{uuid.uuid4()}", headers=_auth(owner_token))
        assert r.status_code == 404

    def test_non_owner_denied(self, client, owner_token):
        r = client.post(
            "/recipients",
            json={"identity": "google:steal@test.com"},
            headers=_auth(owner_token),
        )
        recipient_id = r.json()["id"]
        db = client.app.state.db
        token = issue_recipient_token(db, recipient_id, ttl_seconds=3600)
        r2 = client.get("/recipients", headers=_auth(token))
        assert r2.status_code == 403


# ── identity mappings ─────────────────────────────────────────────────────────

class TestIdentityMappings:
    def test_add_mapping(self, client, owner_token):
        r = client.post(
            "/recipients",
            json={"identity": "google:primary@test.com"},
            headers=_auth(owner_token),
        )
        recipient_id = r.json()["id"]
        r2 = client.post(
            "/identity-mappings",
            params={"identity": "github:primary"},
            json={"recipient_id": recipient_id},
            headers=_auth(owner_token),
        )
        assert r2.status_code == 201
        assert r2.json()["identity"] == "github:primary"
        assert r2.json()["recipient_id"] == recipient_id

    def test_mapping_resolves_for_sso(self, client, owner_token):
        r = client.post(
            "/recipients",
            json={"identity": "google:mapped@test.com"},
            headers=_auth(owner_token),
        )
        recipient_id = r.json()["id"]
        client.post(
            "/identity-mappings",
            params={"identity": "github:mapped"},
            json={"recipient_id": recipient_id},
            headers=_auth(owner_token),
        )
        from server.sso import resolve_identity
        db = client.app.state.db
        resolved = resolve_identity(db, "github:mapped")
        assert resolved == recipient_id

    def test_delete_mapping(self, client, owner_token):
        r = client.post(
            "/recipients",
            json={"identity": "google:delmapping@test.com"},
            headers=_auth(owner_token),
        )
        recipient_id = r.json()["id"]
        client.post(
            "/identity-mappings",
            params={"identity": "github:delmapping"},
            json={"recipient_id": recipient_id},
            headers=_auth(owner_token),
        )
        r2 = client.delete(
            "/identity-mappings",
            params={"identity": "github:delmapping"},
            headers=_auth(owner_token),
        )
        assert r2.status_code == 204
        db = client.app.state.db
        row = db.execute(
            "SELECT 1 FROM identity_mappings WHERE identity = ?", ("github:delmapping",)
        ).fetchone()
        assert row is None

    def test_delete_nonexistent_mapping_404(self, client, owner_token):
        r = client.delete(
            "/identity-mappings",
            params={"identity": "github:doesnotexist"},
            headers=_auth(owner_token),
        )
        assert r.status_code == 404

    def test_unknown_recipient_in_mapping_404(self, client, owner_token):
        r = client.post(
            "/identity-mappings",
            params={"identity": "github:nobody"},
            json={"recipient_id": str(uuid.uuid4())},
            headers=_auth(owner_token),
        )
        assert r.status_code == 404


# ── token management ──────────────────────────────────────────────────────────

class TestTokenManagement:
    def test_list_tokens_shows_active(self, client, owner_token):
        r = client.post(
            "/recipients",
            json={"identity": "google:tokenlist@test.com"},
            headers=_auth(owner_token),
        )
        recipient_id = r.json()["id"]
        db = client.app.state.db
        issue_recipient_token(db, recipient_id, ttl_seconds=3600)
        r2 = client.get("/tokens", headers=_auth(owner_token))
        assert r2.status_code == 200
        assert isinstance(r2.json()["tokens"], list)
        recipient_ids = [t["recipient_id"] for t in r2.json()["tokens"]]
        assert recipient_id in recipient_ids

    def test_revoke_token_via_api(self, client, owner_token):
        r = client.post(
            "/recipients",
            json={"identity": "google:revoke-api@test.com"},
            headers=_auth(owner_token),
        )
        recipient_id = r.json()["id"]
        db = client.app.state.db
        token = issue_recipient_token(db, recipient_id, ttl_seconds=3600)

        r2 = client.post(f"/tokens/{token}/revoke", headers=_auth(owner_token))
        assert r2.status_code == 200
        assert r2.json()["status"] == "revoked"

    def test_revoked_token_rejected(self, client, owner_token):
        r = client.post(
            "/recipients",
            json={"identity": "google:revokecheck@test.com"},
            headers=_auth(owner_token),
        )
        recipient_id = r.json()["id"]
        db = client.app.state.db
        token = issue_recipient_token(db, recipient_id, ttl_seconds=3600)

        client.post(f"/tokens/{token}/revoke", headers=_auth(owner_token))
        r2 = client.get("/feed", headers=_auth(token))
        assert r2.status_code == 401

    def test_revoke_unknown_token_404(self, client, owner_token):
        r = client.post(f"/tokens/{uuid.uuid4()}/revoke", headers=_auth(owner_token))
        assert r.status_code == 404

    def test_list_excludes_revoked(self, client, owner_token):
        r = client.post(
            "/recipients",
            json={"identity": "google:excluderevoked@test.com"},
            headers=_auth(owner_token),
        )
        recipient_id = r.json()["id"]
        db = client.app.state.db
        token = issue_recipient_token(db, recipient_id, ttl_seconds=3600)
        client.post(f"/tokens/{token}/revoke", headers=_auth(owner_token))

        r2 = client.get("/tokens", headers=_auth(owner_token))
        token_ids = [t["id"] for t in r2.json()["tokens"]]
        assert token not in token_ids


# ── comment_count ─────────────────────────────────────────────────────────────

class TestCommentCount:
    def test_meta_has_comment_count_zero(self, client, owner_token):
        asset_id = _publish(client, owner_token)
        r = client.get(f"/assets/{asset_id}/meta", headers=_auth(owner_token))
        assert r.status_code == 200
        assert r.json()["comment_count"] == 0

    def test_meta_comment_count_increments(self, client, owner_token):
        asset_id = _publish(client, owner_token)
        client.post(
            f"/assets/{asset_id}/comments",
            json={"body": "first"},
            headers=_auth(owner_token),
        )
        r = client.get(f"/assets/{asset_id}/meta", headers=_auth(owner_token))
        assert r.json()["comment_count"] == 1

    def test_replies_not_counted_in_comment_count(self, client, owner_token):
        asset_id = _publish(client, owner_token)
        r_top = client.post(
            f"/assets/{asset_id}/comments",
            json={"body": "top"},
            headers=_auth(owner_token),
        )
        parent_id = r_top.json()["id"]
        client.post(
            f"/assets/{asset_id}/comments",
            json={"body": "reply", "parent_id": parent_id},
            headers=_auth(owner_token),
        )
        r = client.get(f"/assets/{asset_id}/meta", headers=_auth(owner_token))
        assert r.json()["comment_count"] == 1  # only top-level

    def test_feed_has_comment_count(self, client, owner_token):
        asset_id = _publish(client, owner_token)
        client.post(
            f"/assets/{asset_id}/comments",
            json={"body": "feed-comment"},
            headers=_auth(owner_token),
        )
        r = client.get("/feed", headers=_auth(owner_token))
        assets_by_id = {a["id"]: a for a in r.json()["assets"]}
        assert asset_id in assets_by_id
        assert assets_by_id[asset_id]["comment_count"] == 1

    def test_deleted_comment_not_counted(self, client, owner_token):
        asset_id = _publish(client, owner_token)
        r = client.post(
            f"/assets/{asset_id}/comments",
            json={"body": "delete me"},
            headers=_auth(owner_token),
        )
        comment_id = r.json()["id"]
        # Request deletion (owner is author here)
        r2 = client.post(
            f"/assets/{asset_id}/comments/{comment_id}/edit_request",
            json={},
            headers=_auth(owner_token),
        )
        request_id = r2.json()["request_id"]
        from server.comments import approve_edit
        approve_edit(client.app.state.db, request_id)
        r3 = client.get(f"/assets/{asset_id}/meta", headers=_auth(owner_token))
        assert r3.json()["comment_count"] == 0


# ── initial ACL on publish ────────────────────────────────────────────────────

class TestPublishWithInitialACL:
    def test_initial_acl_grants_access(self, client, owner_token):
        r = client.post(
            "/recipients",
            json={"identity": "google:init-acl@test.com"},
            headers=_auth(owner_token),
        )
        recipient_id = r.json()["id"]
        db = client.app.state.db
        token = issue_recipient_token(db, recipient_id, ttl_seconds=3600)

        import json as _json
        r2 = client.post(
            "/assets",
            files={"file": ("a.txt", b"secret", "text/plain")},
            data={"acl": _json.dumps([recipient_id])},
            headers=_auth(owner_token),
        )
        asset_id = r2.json()["id"]

        r3 = client.get(f"/assets/{asset_id}", headers=_auth(token))
        assert r3.status_code == 200
        assert r3.content == b"secret"

    def test_publish_initial_acl_unknown_recipient_404(self, client, owner_token):
        import json as _json
        r = client.post(
            "/assets",
            files={"file": ("b.txt", b"x", "text/plain")},
            data={"acl": _json.dumps([str(uuid.uuid4())])},
            headers=_auth(owner_token),
        )
        assert r.status_code == 404

    def test_publish_response_includes_comment_count(self, client, owner_token):
        r = client.post(
            "/assets",
            files={"file": ("c.txt", b"y", "text/plain")},
            headers=_auth(owner_token),
        )
        assert r.status_code == 201
        assert r.json()["comment_count"] == 0
