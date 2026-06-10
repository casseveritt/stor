"""Phase 7: Comments — post, fetch, threading, edit requests, approval."""
import hashlib
import json
import time
import uuid

import pytest

from server.auth import issue_node_token, setup as auth_setup, issue_token
from server.comments import approve_edit, reject_edit
from server.crypto import derive_master_key, decrypt_bytes
from tests.conftest import TEST_PASSPHRASE, TEST_SALT, TEST_ARGON2


# ── helpers ───────────────────────────────────────────────────────────────────

def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _insert_asset(db):
    asset_id = str(uuid.uuid4())
    db.execute(
        """INSERT INTO assets (id, content_hash, media_type, size, created_at, title, tags)
           VALUES (?, 'hash', 'image/jpeg', 0, ?, NULL, '[]')""",
        (asset_id, time.time()),
    )
    db.commit()
    return asset_id


def _add_recipient(db, identity=None):
    return str(uuid.uuid4())


def _grant_acl(db, asset_id, recipient_id):
    db.execute("INSERT OR IGNORE INTO acl (asset_id, node_id) VALUES (?, ?)", (asset_id, recipient_id))
    db.commit()


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def owner_token(store):
    import base64
    from server.config import NodeConfig
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    config = NodeConfig.load(store / "node_config.json")
    master_key = derive_master_key(TEST_PASSPHRASE, TEST_SALT, **TEST_ARGON2)
    privkey_bytes = decrypt_bytes(base64.b64decode(config.encrypted_private_key), master_key)
    auth_setup(Ed25519PrivateKey.from_private_bytes(privkey_bytes))
    return issue_token(ttl_seconds=3600)


@pytest.fixture(scope="module")
def comment_world(client, owner_token):
    """One asset with two recipients: Alice (has ACL) and Bob (no ACL)."""
    db = client.app.state.db
    asset_id = _insert_asset(db)
    alice_id = _add_recipient(db, "google:alice-c@test.com")
    bob_id = _add_recipient(db, "google:bob-c@test.com")
    _grant_acl(db, asset_id, alice_id)
    alice_token = issue_node_token(db, alice_id, ttl_seconds=3600)
    bob_token = issue_node_token(db, bob_id, ttl_seconds=3600)
    return {
        "asset_id": asset_id,
        "alice_id": alice_id,
        "bob_id": bob_id,
        "alice_token": alice_token,
        "bob_token": bob_token,
    }


# ── post comment ──────────────────────────────────────────────────────────────

class TestPostComment:
    def test_owner_can_post(self, client, owner_token, comment_world):
        r = client.post(
            f"/assets/{comment_world['asset_id']}/comments",
            json={"body": "Owner comment"},
            headers=_auth(owner_token),
        )
        assert r.status_code == 201
        data = r.json()
        assert data["body"] == "Owner comment"
        assert data["author_node_id"] is None

    def test_content_hash_matches_body(self, client, owner_token, comment_world):
        body = "Hash verification comment"
        r = client.post(
            f"/assets/{comment_world['asset_id']}/comments",
            json={"body": body},
            headers=_auth(owner_token),
        )
        expected_hash = hashlib.sha256(body.encode()).hexdigest()
        assert r.json()["content_hash"] == expected_hash

    def test_recipient_with_acl_can_post(self, client, comment_world):
        r = client.post(
            f"/assets/{comment_world['asset_id']}/comments",
            json={"body": "Alice's comment"},
            headers=_auth(comment_world["alice_token"]),
        )
        assert r.status_code == 201
        assert r.json()["author_node_id"] == comment_world["alice_id"]

    def test_recipient_without_acl_denied(self, client, comment_world):
        r = client.post(
            f"/assets/{comment_world['asset_id']}/comments",
            json={"body": "Bob's sneaky comment"},
            headers=_auth(comment_world["bob_token"]),
        )
        assert r.status_code == 403

    def test_unauthenticated_denied(self, client, comment_world):
        r = client.post(
            f"/assets/{comment_world['asset_id']}/comments",
            json={"body": "No token"},
        )
        assert r.status_code == 403

    def test_unknown_asset_404(self, client, owner_token):
        r = client.post(
            f"/assets/{uuid.uuid4()}/comments",
            json={"body": "ghost"},
            headers=_auth(owner_token),
        )
        assert r.status_code == 404


# ── fetch comments ────────────────────────────────────────────────────────────

class TestFetchComments:
    def test_returns_posted_comments(self, client, owner_token, comment_world):
        client.post(
            f"/assets/{comment_world['asset_id']}/comments",
            json={"body": "Fetch test comment"},
            headers=_auth(owner_token),
        )
        r = client.get(
            f"/assets/{comment_world['asset_id']}/comments",
            headers=_auth(owner_token),
        )
        assert r.status_code == 200
        bodies = [c["body"] for c in r.json()["comments"]]
        assert "Fetch test comment" in bodies

    def test_recipient_without_acl_cannot_fetch(self, client, comment_world):
        r = client.get(
            f"/assets/{comment_world['asset_id']}/comments",
            headers=_auth(comment_world["bob_token"]),
        )
        assert r.status_code == 403

    def test_response_shape(self, client, owner_token, comment_world):
        r = client.get(
            f"/assets/{comment_world['asset_id']}/comments",
            headers=_auth(owner_token),
        )
        data = r.json()
        assert data["asset_id"] == comment_world["asset_id"]
        assert isinstance(data["comments"], list)
        if data["comments"]:
            c = data["comments"][0]
            for field in ("id", "content_hash", "asset_id", "parent_id",
                          "author_node_id", "body", "deleted", "created_at"):
                assert field in c


# ── threading ─────────────────────────────────────────────────────────────────

class TestThreading:
    def test_reply_sets_parent_id(self, client, owner_token, comment_world):
        r = client.post(
            f"/assets/{comment_world['asset_id']}/comments",
            json={"body": "Top-level"},
            headers=_auth(owner_token),
        )
        parent_id = r.json()["id"]

        r = client.post(
            f"/assets/{comment_world['asset_id']}/comments",
            json={"body": "Reply", "parent_id": parent_id},
            headers=_auth(owner_token),
        )
        assert r.status_code == 201
        assert r.json()["parent_id"] == parent_id

    def test_reply_appears_in_fetch(self, client, owner_token, comment_world):
        r_top = client.post(
            f"/assets/{comment_world['asset_id']}/comments",
            json={"body": "Thread root"},
            headers=_auth(owner_token),
        )
        top_id = r_top.json()["id"]
        client.post(
            f"/assets/{comment_world['asset_id']}/comments",
            json={"body": "Thread reply", "parent_id": top_id},
            headers=_auth(owner_token),
        )
        r = client.get(
            f"/assets/{comment_world['asset_id']}/comments",
            headers=_auth(owner_token),
        )
        by_id = {c["id"]: c for c in r.json()["comments"]}
        assert top_id in by_id
        replies = [c for c in r.json()["comments"] if c["parent_id"] == top_id]
        assert len(replies) >= 1

    def test_invalid_parent_404(self, client, owner_token, comment_world):
        r = client.post(
            f"/assets/{comment_world['asset_id']}/comments",
            json={"body": "Orphan", "parent_id": str(uuid.uuid4())},
            headers=_auth(owner_token),
        )
        assert r.status_code == 404


# ── edit requests ─────────────────────────────────────────────────────────────

class TestEditRequests:
    def test_author_can_request_edit(self, client, comment_world):
        # Alice posts, then requests an edit
        r = client.post(
            f"/assets/{comment_world['asset_id']}/comments",
            json={"body": "Alice original"},
            headers=_auth(comment_world["alice_token"]),
        )
        comment_id = r.json()["id"]
        r = client.post(
            f"/assets/{comment_world['asset_id']}/comments/{comment_id}/edit_request",
            json={"new_body": "Alice edited"},
            headers=_auth(comment_world["alice_token"]),
        )
        assert r.status_code == 202
        data = r.json()
        assert "request_id" in data
        assert data["status"] == "pending"

    def test_non_author_cannot_request_edit(self, client, owner_token, comment_world):
        # Owner posts, Alice tries to request edit
        r = client.post(
            f"/assets/{comment_world['asset_id']}/comments",
            json={"body": "Owner original"},
            headers=_auth(owner_token),
        )
        comment_id = r.json()["id"]
        r = client.post(
            f"/assets/{comment_world['asset_id']}/comments/{comment_id}/edit_request",
            json={"new_body": "Alice hijack"},
            headers=_auth(comment_world["alice_token"]),
        )
        assert r.status_code == 403

    def test_request_deletion(self, client, comment_world):
        r = client.post(
            f"/assets/{comment_world['asset_id']}/comments",
            json={"body": "Delete me"},
            headers=_auth(comment_world["alice_token"]),
        )
        comment_id = r.json()["id"]
        r = client.post(
            f"/assets/{comment_world['asset_id']}/comments/{comment_id}/edit_request",
            json={},
            headers=_auth(comment_world["alice_token"]),
        )
        assert r.status_code == 202


# ── edit approval (owner action) ──────────────────────────────────────────────

class TestEditApproval:
    def test_approve_edit_creates_successor(self, client, comment_world):
        db = client.app.state.db
        r = client.post(
            f"/assets/{comment_world['asset_id']}/comments",
            json={"body": "Original text"},
            headers=_auth(comment_world["alice_token"]),
        )
        comment_id = r.json()["id"]
        r = client.post(
            f"/assets/{comment_world['asset_id']}/comments/{comment_id}/edit_request",
            json={"new_body": "Revised text"},
            headers=_auth(comment_world["alice_token"]),
        )
        request_id = r.json()["request_id"]

        result = approve_edit(db, request_id)
        assert result["status"] == "approved"

        # Original gains a successor
        old = db.execute("SELECT successor FROM comments WHERE id = ?", (comment_id,)).fetchone()
        assert old[0] is not None

        # New comment has predecessor link
        new_id = old[0]
        new = db.execute("SELECT predecessor, body FROM comments WHERE id = ?", (new_id,)).fetchone()
        assert new[0] == comment_id
        assert new[1] == "Revised text"

    def test_approve_deletion_tombstones_comment(self, client, comment_world):
        db = client.app.state.db
        r = client.post(
            f"/assets/{comment_world['asset_id']}/comments",
            json={"body": "Tombstone me"},
            headers=_auth(comment_world["alice_token"]),
        )
        comment_id = r.json()["id"]
        r = client.post(
            f"/assets/{comment_world['asset_id']}/comments/{comment_id}/edit_request",
            json={},
            headers=_auth(comment_world["alice_token"]),
        )
        request_id = r.json()["request_id"]
        approve_edit(db, request_id)

        # Comment marked deleted; body is None in fetch response
        r = client.get(
            f"/assets/{comment_world['asset_id']}/comments",
            headers=_auth(comment_world["alice_token"]),
        )
        tombstoned = next(c for c in r.json()["comments"] if c["id"] == comment_id)
        assert tombstoned["deleted"] is True
        assert tombstoned["body"] is None

    def test_reject_edit_request(self, client, comment_world):
        db = client.app.state.db
        r = client.post(
            f"/assets/{comment_world['asset_id']}/comments",
            json={"body": "Reject test"},
            headers=_auth(comment_world["alice_token"]),
        )
        comment_id = r.json()["id"]
        r = client.post(
            f"/assets/{comment_world['asset_id']}/comments/{comment_id}/edit_request",
            json={"new_body": "Rejected edit"},
            headers=_auth(comment_world["alice_token"]),
        )
        request_id = r.json()["request_id"]
        result = reject_edit(db, request_id)
        assert result["status"] == "rejected"

        row = db.execute(
            "SELECT status FROM comment_edit_requests WHERE id = ?", (request_id,)
        ).fetchone()
        assert row[0] == "rejected"

    def test_double_approve_raises(self, client, comment_world):
        db = client.app.state.db
        r = client.post(
            f"/assets/{comment_world['asset_id']}/comments",
            json={"body": "Double approve"},
            headers=_auth(comment_world["alice_token"]),
        )
        comment_id = r.json()["id"]
        r = client.post(
            f"/assets/{comment_world['asset_id']}/comments/{comment_id}/edit_request",
            json={"new_body": "New"},
            headers=_auth(comment_world["alice_token"]),
        )
        request_id = r.json()["request_id"]
        approve_edit(db, request_id)
        with pytest.raises(ValueError):
            approve_edit(db, request_id)
