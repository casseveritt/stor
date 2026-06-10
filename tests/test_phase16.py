"""Phase 16: Comments in the UI — API patterns used by the comment section."""
import base64
import io
import json
import uuid

import pytest

from server.auth import issue_token, issue_node_token, setup as auth_setup
from server.crypto import derive_master_key, decrypt_bytes
from tests.conftest import TEST_PASSPHRASE, TEST_SALT, TEST_ARGON2


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _json_post(token, url, payload, client):
    return client.post(url, content=json.dumps(payload),
                       headers={**_auth(token), "Content-Type": "application/json"})


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
def recipient(client):
    db = client.app.state.db
    rid = str(uuid.uuid4())
    db.execute("INSERT INTO recipients (id, identity, display_name) VALUES (?, ?, ?)",
               (rid, "google:commenter@example.com", "Commenter"))
    db.commit()
    return {"id": rid, "token": issue_node_token(db, rid)}


@pytest.fixture(scope="module")
def asset(client, owner_token):
    r = client.post("/assets",
        files={"file": ("comments-asset.txt", b"comment target", "text/plain")},
        data={"title": "Comment Target"},
        headers=_auth(owner_token))
    assert r.status_code == 201
    asset_id = r.json()["id"]
    return {"id": asset_id}


@pytest.fixture(scope="module")
def asset_with_acl(client, owner_token, recipient, asset):
    client.put(f"/assets/{asset['id']}/acl",
               json={"add": [recipient["id"]]},
               headers=_auth(owner_token))
    return asset


# ── comment fetch shape ───────────────────────────────────────────────────────

class TestCommentFetchShape:
    def test_returns_empty_comments_list(self, client, owner_token, asset):
        r = client.get(f"/assets/{asset['id']}/comments", headers=_auth(owner_token))
        assert r.status_code == 200
        data = r.json()
        assert "asset_id" in data
        assert "comments" in data
        assert isinstance(data["comments"], list)

    def test_comment_has_required_fields(self, client, owner_token, asset):
        _json_post(owner_token, f"/assets/{asset['id']}/comments", {"body": "field check"}, client)
        r = client.get(f"/assets/{asset['id']}/comments", headers=_auth(owner_token))
        c = next(x for x in r.json()["comments"] if x["body"] == "field check")
        for field in ("id", "body", "created_at", "parent_id", "deleted", "author_identity"):
            assert field in c, f"missing field: {field}"

    def test_comments_ordered_by_created_at(self, client, owner_token, asset):
        for body in ("first", "second", "third"):
            _json_post(owner_token, f"/assets/{asset['id']}/comments", {"body": body}, client)
        r = client.get(f"/assets/{asset['id']}/comments", headers=_auth(owner_token))
        times = [c["created_at"] for c in r.json()["comments"]]
        assert times == sorted(times)


# ── posting comments ──────────────────────────────────────────────────────────

class TestPostComment:
    def test_owner_can_post(self, client, owner_token, asset):
        r = _json_post(owner_token, f"/assets/{asset['id']}/comments", {"body": "owner comment"}, client)
        assert r.status_code == 201
        assert r.json()["body"] == "owner comment"

    def test_owner_comment_has_null_author_identity(self, client, owner_token, asset):
        r = _json_post(owner_token, f"/assets/{asset['id']}/comments", {"body": "anon"}, client)
        assert r.json()["author_identity"] is None

    def test_recipient_can_post(self, client, recipient, asset_with_acl):
        r = _json_post(recipient["token"], f"/assets/{asset_with_acl['id']}/comments",
                       {"body": "recipient comment"}, client)
        assert r.status_code == 201

    def test_recipient_comment_shows_identity(self, client, recipient, asset_with_acl):
        r = _json_post(recipient["token"], f"/assets/{asset_with_acl['id']}/comments",
                       {"body": "identity check"}, client)
        assert r.json()["author_identity"] == "google:commenter@example.com"

    def test_unauthenticated_cannot_post(self, client, asset):
        r = client.post(f"/assets/{asset['id']}/comments",
                        content=json.dumps({"body": "anon"}),
                        headers={"Content-Type": "application/json"})
        assert r.status_code == 403


# ── threading ─────────────────────────────────────────────────────────────────

class TestCommentThreading:
    def test_reply_sets_parent_id(self, client, owner_token, asset):
        parent = _json_post(owner_token, f"/assets/{asset['id']}/comments",
                            {"body": "parent"}, client).json()
        reply = _json_post(owner_token, f"/assets/{asset['id']}/comments",
                           {"body": "child", "parent_id": parent["id"]}, client).json()
        assert reply["parent_id"] == parent["id"]

    def test_reply_appears_in_fetch(self, client, owner_token, asset):
        parent = _json_post(owner_token, f"/assets/{asset['id']}/comments",
                            {"body": "thread parent"}, client).json()
        _json_post(owner_token, f"/assets/{asset['id']}/comments",
                   {"body": "thread child", "parent_id": parent["id"]}, client)
        comments = client.get(f"/assets/{asset['id']}/comments",
                              headers=_auth(owner_token)).json()["comments"]
        child = next((c for c in comments if c["body"] == "thread child"), None)
        assert child is not None
        assert child["parent_id"] == parent["id"]

    def test_invalid_parent_id_404(self, client, owner_token, asset):
        r = _json_post(owner_token, f"/assets/{asset['id']}/comments",
                       {"body": "orphan", "parent_id": str(uuid.uuid4())}, client)
        assert r.status_code == 404


# ── comment count in feed ─────────────────────────────────────────────────────

class TestCommentCountInFeed:
    def test_comment_count_increments_after_post(self, client, owner_token):
        r = client.post("/assets",
            files={"file": ("count-test.txt", b"count", "text/plain")},
            headers=_auth(owner_token))
        asset_id = r.json()["id"]

        def get_count():
            feed = client.get(f"/feed?limit=200", headers=_auth(owner_token)).json()
            a = next((x for x in feed["assets"] if x["id"] == asset_id), None)
            return a["comment_count"] if a else None

        assert get_count() == 0
        _json_post(owner_token, f"/assets/{asset_id}/comments", {"body": "one"}, client)
        assert get_count() == 1
        _json_post(owner_token, f"/assets/{asset_id}/comments", {"body": "two"}, client)
        assert get_count() == 2
