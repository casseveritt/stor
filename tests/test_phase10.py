"""Phase 10: Asset deletion, ACL read, feed filtering, comment author identity."""
import base64
import uuid

import pytest

from server.auth import issue_token, issue_node_token, setup as auth_setup
from server.crypto import derive_master_key, decrypt_bytes
from tests.conftest import TEST_PASSPHRASE, TEST_SALT, TEST_ARGON2


# ── helpers ───────────────────────────────────────────────────────────────────

def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _publish(client, owner_token, content=b"data", media_type="text/plain",
             title=None, tags="[]"):
    data = {"tags": tags}
    if title:
        data["title"] = title
    r = client.post(
        "/assets",
        files={"file": ("f", content, media_type)},
        data=data,
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


@pytest.fixture(scope="module")
def p10_world(client, owner_token):
    """A recipient used across Phase 10 tests."""
    r = client.post(
        "/recipients",
        json={"identity": "google:p10@test.com"},
        headers=_auth(owner_token),
    )
    recipient_id = r.json()["id"]
    db = client.app.state.db
    token = issue_node_token(db, recipient_id, ttl_seconds=3600)
    return {"recipient_id": recipient_id, "token": token}


# ── asset deletion ────────────────────────────────────────────────────────────

class TestDeleteAsset:
    def test_delete_returns_204(self, client, owner_token):
        asset_id = _publish(client, owner_token)
        r = client.delete(f"/assets/{asset_id}", headers=_auth(owner_token))
        assert r.status_code == 204

    def test_deleted_asset_not_in_feed(self, client, owner_token):
        asset_id = _publish(client, owner_token, content=b"del-feed")
        client.delete(f"/assets/{asset_id}", headers=_auth(owner_token))
        r = client.get("/feed", headers=_auth(owner_token))
        ids = [a["id"] for a in r.json()["assets"]]
        assert asset_id not in ids

    def test_deleted_asset_meta_404(self, client, owner_token):
        asset_id = _publish(client, owner_token)
        client.delete(f"/assets/{asset_id}", headers=_auth(owner_token))
        r = client.get(f"/assets/{asset_id}/meta", headers=_auth(owner_token))
        assert r.status_code == 404

    def test_deleted_asset_content_404(self, client, owner_token):
        asset_id = _publish(client, owner_token)
        client.delete(f"/assets/{asset_id}", headers=_auth(owner_token))
        r = client.get(f"/assets/{asset_id}", headers=_auth(owner_token))
        assert r.status_code == 404

    def test_delete_unknown_asset_404(self, client, owner_token):
        r = client.delete(f"/assets/{uuid.uuid4()}", headers=_auth(owner_token))
        assert r.status_code == 404

    def test_delete_already_deleted_404(self, client, owner_token):
        asset_id = _publish(client, owner_token)
        client.delete(f"/assets/{asset_id}", headers=_auth(owner_token))
        r = client.delete(f"/assets/{asset_id}", headers=_auth(owner_token))
        assert r.status_code == 404

    def test_non_owner_cannot_delete(self, client, owner_token, p10_world):
        asset_id = _publish(client, owner_token)
        r = client.delete(f"/assets/{asset_id}", headers=_auth(p10_world["token"]))
        assert r.status_code == 403


# ── ACL read ──────────────────────────────────────────────────────────────────

class TestGetACL:
    def test_empty_acl_for_new_asset(self, client, owner_token):
        asset_id = _publish(client, owner_token)
        r = client.get(f"/assets/{asset_id}/acl", headers=_auth(owner_token))
        assert r.status_code == 200
        assert r.json()["asset_id"] == asset_id
        assert r.json()["recipients"] == []

    def test_acl_includes_added_recipients(self, client, owner_token, p10_world):
        asset_id = _publish(client, owner_token)
        client.put(
            f"/assets/{asset_id}/acl",
            json={"add": [p10_world["recipient_id"]]},
            headers=_auth(owner_token),
        )
        r = client.get(f"/assets/{asset_id}/acl", headers=_auth(owner_token))
        assert r.status_code == 200
        ids = [rec["id"] for rec in r.json()["recipients"]]
        assert p10_world["recipient_id"] in ids

    def test_acl_recipient_has_identity(self, client, owner_token, p10_world):
        asset_id = _publish(client, owner_token)
        client.put(
            f"/assets/{asset_id}/acl",
            json={"add": [p10_world["recipient_id"]]},
            headers=_auth(owner_token),
        )
        r = client.get(f"/assets/{asset_id}/acl", headers=_auth(owner_token))
        recs = {rec["id"]: rec for rec in r.json()["recipients"]}
        assert p10_world["recipient_id"] in recs
        assert recs[p10_world["recipient_id"]]["identity"] == "google:p10@test.com"

    def test_acl_excludes_removed_recipients(self, client, owner_token, p10_world):
        asset_id = _publish(client, owner_token)
        client.put(f"/assets/{asset_id}/acl", json={"add": [p10_world["recipient_id"]]}, headers=_auth(owner_token))
        client.put(f"/assets/{asset_id}/acl", json={"remove": [p10_world["recipient_id"]]}, headers=_auth(owner_token))
        r = client.get(f"/assets/{asset_id}/acl", headers=_auth(owner_token))
        ids = [rec["id"] for rec in r.json()["recipients"]]
        assert p10_world["recipient_id"] not in ids

    def test_get_acl_unknown_asset_404(self, client, owner_token):
        r = client.get(f"/assets/{uuid.uuid4()}/acl", headers=_auth(owner_token))
        assert r.status_code == 404

    def test_non_owner_denied(self, client, owner_token, p10_world):
        asset_id = _publish(client, owner_token)
        r = client.get(f"/assets/{asset_id}/acl", headers=_auth(p10_world["token"]))
        assert r.status_code == 403

    def test_get_acl_deleted_asset_404(self, client, owner_token):
        asset_id = _publish(client, owner_token)
        client.delete(f"/assets/{asset_id}", headers=_auth(owner_token))
        r = client.get(f"/assets/{asset_id}/acl", headers=_auth(owner_token))
        assert r.status_code == 404


# ── feed filtering ────────────────────────────────────────────────────────────

class TestFeedFiltering:
    def test_filter_by_media_type_includes_match(self, client, owner_token):
        asset_id = _publish(client, owner_token, content=b"img", media_type="image/png")
        r = client.get("/feed", params={"media_type": "image/png"}, headers=_auth(owner_token))
        ids = [a["id"] for a in r.json()["assets"]]
        assert asset_id in ids

    def test_filter_by_media_type_excludes_other_types(self, client, owner_token):
        text_id = _publish(client, owner_token, content=b"txt", media_type="text/plain")
        r = client.get("/feed", params={"media_type": "image/png"}, headers=_auth(owner_token))
        ids = [a["id"] for a in r.json()["assets"]]
        assert text_id not in ids

    def test_filter_by_single_tag(self, client, owner_token):
        asset_id = _publish(client, owner_token, tags='["vacation","2024"]')
        r = client.get("/feed", params={"tags": "vacation"}, headers=_auth(owner_token))
        ids = [a["id"] for a in r.json()["assets"]]
        assert asset_id in ids

    def test_filter_by_tag_excludes_untagged(self, client, owner_token):
        untagged_id = _publish(client, owner_token, tags='[]')
        r = client.get("/feed", params={"tags": "vacation"}, headers=_auth(owner_token))
        ids = [a["id"] for a in r.json()["assets"]]
        assert untagged_id not in ids

    def test_filter_by_multiple_tags_requires_all(self, client, owner_token):
        both_id = _publish(client, owner_token, tags='["a","b"]')
        only_a_id = _publish(client, owner_token, tags='["a"]')
        r = client.get("/feed", params=[("tags", "a"), ("tags", "b")], headers=_auth(owner_token))
        ids = [a["id"] for a in r.json()["assets"]]
        assert both_id in ids
        assert only_a_id not in ids

    def test_deleted_excluded_from_feed(self, client, owner_token):
        asset_id = _publish(client, owner_token)
        client.delete(f"/assets/{asset_id}", headers=_auth(owner_token))
        r = client.get("/feed", headers=_auth(owner_token))
        ids = [a["id"] for a in r.json()["assets"]]
        assert asset_id not in ids

    def test_combined_media_type_and_tag_filter(self, client, owner_token):
        match_id = _publish(client, owner_token, content=b"x", media_type="image/jpeg", tags='["beach"]')
        wrong_type_id = _publish(client, owner_token, content=b"y", media_type="text/plain", tags='["beach"]')
        wrong_tag_id = _publish(client, owner_token, content=b"z", media_type="image/jpeg", tags='["mountain"]')
        r = client.get(
            "/feed",
            params=[("media_type", "image/jpeg"), ("tags", "beach")],
            headers=_auth(owner_token),
        )
        ids = [a["id"] for a in r.json()["assets"]]
        assert match_id in ids
        assert wrong_type_id not in ids
        assert wrong_tag_id not in ids


# ── comment author identity ───────────────────────────────────────────────────

class TestCommentAuthorIdentity:
    def test_owner_comment_has_null_author_identity(self, client, owner_token):
        asset_id = _publish(client, owner_token)
        r = client.post(
            f"/assets/{asset_id}/comments",
            json={"body": "owner post"},
            headers=_auth(owner_token),
        )
        assert r.status_code == 201
        assert r.json()["author_identity"] is None

    def test_recipient_comment_has_author_identity(self, client, owner_token, p10_world):
        asset_id = _publish(client, owner_token)
        client.put(
            f"/assets/{asset_id}/acl",
            json={"add": [p10_world["recipient_id"]]},
            headers=_auth(owner_token),
        )
        r = client.post(
            f"/assets/{asset_id}/comments",
            json={"body": "recipient post"},
            headers=_auth(p10_world["token"]),
        )
        assert r.status_code == 201
        assert r.json()["author_identity"] == "google:p10@test.com"

    def test_fetch_comments_includes_author_identity(self, client, owner_token, p10_world):
        asset_id = _publish(client, owner_token)
        client.put(
            f"/assets/{asset_id}/acl",
            json={"add": [p10_world["recipient_id"]]},
            headers=_auth(owner_token),
        )
        client.post(
            f"/assets/{asset_id}/comments",
            json={"body": "fetched"},
            headers=_auth(p10_world["token"]),
        )
        r = client.get(f"/assets/{asset_id}/comments", headers=_auth(owner_token))
        comments = r.json()["comments"]
        recipient_comments = [c for c in comments if c["author_recipient_id"] == p10_world["recipient_id"]]
        assert len(recipient_comments) >= 1
        assert recipient_comments[0]["author_identity"] == "google:p10@test.com"

    def test_response_shape_includes_author_identity_field(self, client, owner_token):
        asset_id = _publish(client, owner_token)
        client.post(
            f"/assets/{asset_id}/comments",
            json={"body": "shape check"},
            headers=_auth(owner_token),
        )
        r = client.get(f"/assets/{asset_id}/comments", headers=_auth(owner_token))
        c = r.json()["comments"][0]
        assert "author_identity" in c
