"""Phase 29: Post share tokens — time-limited access links for private posts."""
import json
import pytest

from server.auth import issue_token, setup as auth_setup
import base64


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def owner_token(store):
    from server.config import NodeConfig
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from server.crypto import derive_master_key, decrypt_bytes
    from tests.conftest import TEST_PASSPHRASE, TEST_SALT, TEST_ARGON2
    config = NodeConfig.load(store / "node_config.json")
    master_key = derive_master_key(TEST_PASSPHRASE, TEST_SALT, **TEST_ARGON2)
    privkey_bytes = decrypt_bytes(base64.b64decode(config.encrypted_private_key), master_key)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    auth_setup(Ed25519PrivateKey.from_private_bytes(privkey_bytes))
    return issue_token(ttl_seconds=3600)


@pytest.fixture(scope="module")
def owner_headers(owner_token):
    return {"Authorization": f"Bearer {owner_token}"}


@pytest.fixture(scope="module")
def private_post(client, owner_headers):
    r = client.post(
        "/posts",
        data={"body": "share-token test post p29", "public": "false"},
        headers=owner_headers,
    )
    assert r.status_code == 201
    return r.json()


@pytest.fixture(scope="module")
def other_private_post(client, owner_headers):
    r = client.post(
        "/posts",
        data={"body": "other private post p29", "public": "false"},
        headers=owner_headers,
    )
    assert r.status_code == 201
    return r.json()


def _issue_post_share(client, owner_headers, post_id, identity="viewer@example.com", ttl=3600):
    r = client.post(
        "/share-tokens",
        json={"identity": identity, "post_ids": [post_id], "ttl_seconds": ttl},
        headers=owner_headers,
    )
    assert r.status_code == 201
    return r.json()["token"]


# ── token issuance ────────────────────────────────────────────────────────────

class TestPostShareTokenIssuance:
    def test_issue_post_share_token(self, client, owner_headers, private_post):
        r = client.post(
            "/share-tokens",
            json={"identity": "viewer@example.com", "post_ids": [private_post["id"]]},
            headers=owner_headers,
        )
        assert r.status_code == 201
        assert "token" in r.json()
        assert r.json()["post_ids"] == [private_post["id"]]

    def test_nonexistent_post_id_rejected(self, client, owner_headers):
        r = client.post(
            "/share-tokens",
            json={"identity": "x@example.com", "post_ids": ["00000000-0000-0000-0000-000000000000"]},
            headers=owner_headers,
        )
        assert r.status_code == 404

    def test_combined_asset_and_post_share(self, client, owner_headers, private_post):
        # can issue a token that shares both assets and posts
        r = client.post(
            "/share-tokens",
            json={"identity": "multi@example.com", "post_ids": [private_post["id"]], "asset_ids": None},
            headers=owner_headers,
        )
        assert r.status_code == 201


# ── access with post share token ──────────────────────────────────────────────

class TestPostShareTokenAccess:
    def test_scoped_token_can_get_post(self, client, owner_headers, private_post):
        token = _issue_post_share(client, owner_headers, private_post["id"])
        r = client.get(f"/posts/{private_post['id']}", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["id"] == private_post["id"]

    def test_scoped_token_sees_post_in_feed(self, client, owner_headers, private_post):
        token = _issue_post_share(client, owner_headers, private_post["id"])
        r = client.get("/posts", headers={"Authorization": f"Bearer {token}"})
        ids = [p["id"] for p in r.json()["posts"]]
        assert private_post["id"] in ids

    def test_scoped_token_cannot_see_other_posts(self, client, owner_headers, private_post, other_private_post):
        token = _issue_post_share(client, owner_headers, private_post["id"])
        r = client.get(f"/posts/{other_private_post['id']}", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    def test_scoped_token_cannot_see_other_posts_in_feed(self, client, owner_headers, private_post, other_private_post):
        token = _issue_post_share(client, owner_headers, private_post["id"])
        r = client.get("/posts", headers={"Authorization": f"Bearer {token}"})
        ids = [p["id"] for p in r.json()["posts"]]
        assert other_private_post["id"] not in ids

    def test_scoped_token_can_comment(self, client, owner_headers, private_post):
        token = _issue_post_share(client, owner_headers, private_post["id"])
        r = client.post(
            f"/posts/{private_post['id']}/comments",
            json={"body": "comment via share token"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 201

    def test_scoped_token_can_fetch_comments(self, client, owner_headers, private_post):
        token = _issue_post_share(client, owner_headers, private_post["id"])
        r = client.get(
            f"/posts/{private_post['id']}/comments",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200

    def test_expired_token_denied(self, client, owner_headers, private_post):
        r = client.post(
            "/share-tokens",
            json={"identity": "expired@example.com", "post_ids": [private_post["id"]], "ttl_seconds": -1},
            headers=owner_headers,
        )
        assert r.status_code == 201
        token = r.json()["token"]
        r2 = client.get(f"/posts/{private_post['id']}", headers={"Authorization": f"Bearer {token}"})
        assert r2.status_code == 401
