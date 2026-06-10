"""Phase 21: Posts API — create/read/update/delete posts with embedded asset refs."""
import base64
import json
import io
from pathlib import Path
import sys

import pytest
from PIL import Image

sys.path.insert(0, str(Path(__file__).parent.parent))

from server.auth import issue_token, setup as auth_setup
from server.crypto import derive_master_key, decrypt_bytes
from tests.conftest import TEST_PASSPHRASE, TEST_SALT, TEST_ARGON2


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _png_bytes():
    buf = io.BytesIO()
    Image.new("RGB", (4, 4), color=(10, 20, 30)).save(buf, format="PNG")
    return buf.getvalue()


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
def pre_asset(client, owner_token):
    """An asset uploaded directly (not via a post)."""
    r = client.post(
        "/assets",
        files={"file": ("pre.txt", b"pre-uploaded asset", "text/plain")},
        data={"title": "Pre-uploaded"},
        headers=_auth(owner_token),
    )
    assert r.status_code == 201
    return r.json()


# ── POST /posts ───────────────────────────────────────────────────────────────

class TestCreatePost:
    def test_text_only_post(self, client, owner_token):
        r = client.post("/posts", data={"body": "Hello world"}, headers=_auth(owner_token))
        assert r.status_code == 201
        data = r.json()
        assert data["body"] == "Hello world"
        assert data["assets"] == []
        assert data["id"]

    def test_post_with_uploaded_file(self, client, owner_token):
        r = client.post(
            "/posts",
            data={"body": "Look at this image"},
            files=[("files", ("img.png", _png_bytes(), "image/png"))],
            headers=_auth(owner_token),
        )
        assert r.status_code == 201
        data = r.json()
        assert len(data["assets"]) == 1
        assert data["assets"][0]["media_type"] == "image/png"
        # uploaded file ref appended to body
        assert "[asset:" in data["body"]

    def test_post_with_multiple_files(self, client, owner_token):
        r = client.post(
            "/posts",
            data={"body": "Two images"},
            files=[
                ("files", ("a.png", _png_bytes(), "image/png")),
                ("files", ("b.png", _png_bytes(), "image/png")),
            ],
            headers=_auth(owner_token),
        )
        assert r.status_code == 201
        assert len(r.json()["assets"]) == 2

    def test_post_with_inline_ref(self, client, owner_token, pre_asset):
        body = f"See this: [asset:{pre_asset['id']}]"
        r = client.post("/posts", data={"body": body}, headers=_auth(owner_token))
        assert r.status_code == 201
        data = r.json()
        assert len(data["assets"]) == 1
        assert data["assets"][0]["id"] == pre_asset["id"]

    def test_inline_ref_to_unknown_asset_fails(self, client, owner_token):
        r = client.post(
            "/posts",
            data={"body": "[asset:00000000-0000-0000-0000-000000000000]"},
            headers=_auth(owner_token),
        )
        assert r.status_code == 422

    def test_tags_stored(self, client, owner_token):
        r = client.post(
            "/posts",
            data={"body": "tagged post", "tags": json.dumps(["alpha", "beta"])},
            headers=_auth(owner_token),
        )
        assert r.status_code == 201
        assert set(r.json()["tags"]) == {"alpha", "beta"}

    def test_requires_auth(self, client):
        r = client.post("/posts", data={"body": "no auth"})
        assert r.status_code == 401

    def test_requires_owner(self, client, owner_token):
        import uuid
        from server.auth import issue_node_token
        rid = str(uuid.uuid4())
        tok = issue_node_token(client.app.state.db, rid)
        r = client.post("/posts", data={"body": "recipient post"}, headers=_auth(tok))
        assert r.status_code == 403


# ── GET /posts ────────────────────────────────────────────────────────────────

class TestGetPosts:
    def test_returns_posts_list(self, client, owner_token):
        r = client.get("/posts", headers=_auth(owner_token))
        assert r.status_code == 200
        assert "posts" in r.json()
        assert isinstance(r.json()["posts"], list)

    def test_newest_first(self, client, owner_token):
        r = client.get("/posts", headers=_auth(owner_token))
        posts = r.json()["posts"]
        timestamps = [p["created_at"] for p in posts]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_limit_respected(self, client, owner_token):
        r = client.get("/posts", params={"limit": 2}, headers=_auth(owner_token))
        assert len(r.json()["posts"]) <= 2

    def test_tag_filter(self, client, owner_token):
        client.post(
            "/posts",
            data={"body": "filtered", "tags": json.dumps(["phase21-unique"])},
            headers=_auth(owner_token),
        )
        r = client.get("/posts", params={"tags": "phase21-unique"}, headers=_auth(owner_token))
        posts = r.json()["posts"]
        assert len(posts) >= 1
        assert all("phase21-unique" in p["tags"] for p in posts)

    def test_cursor_pagination(self, client, owner_token):
        r1 = client.get("/posts", params={"limit": 2}, headers=_auth(owner_token))
        data1 = r1.json()
        if "next_cursor" not in data1:
            pytest.skip("not enough posts to paginate")
        r2 = client.get("/posts", params={"limit": 2, "cursor": data1["next_cursor"]}, headers=_auth(owner_token))
        ids1 = {p["id"] for p in data1["posts"]}
        ids2 = {p["id"] for p in r2.json()["posts"]}
        assert ids1.isdisjoint(ids2)


# ── GET /posts/{id} ───────────────────────────────────────────────────────────

class TestGetPost:
    @pytest.fixture(scope="class")
    def post(self, client, owner_token):
        r = client.post(
            "/posts",
            data={"body": "detail test", "tags": json.dumps(["detail"])},
            files=[("files", ("img.png", _png_bytes(), "image/png"))],
            headers=_auth(owner_token),
        )
        return r.json()

    def test_returns_post(self, client, owner_token, post):
        r = client.get(f"/posts/{post['id']}", headers=_auth(owner_token))
        assert r.status_code == 200
        assert r.json()["id"] == post["id"]

    def test_has_all_fields(self, client, owner_token, post):
        data = client.get(f"/posts/{post['id']}", headers=_auth(owner_token)).json()
        for f in ("id", "body", "tags", "created_at", "assets", "comment_count", "deleted"):
            assert f in data

    def test_asset_order_matches_body(self, client, owner_token, post):
        data = client.get(f"/posts/{post['id']}", headers=_auth(owner_token)).json()
        from server.posts import _asset_ids_in_order
        expected = _asset_ids_in_order(data["body"])
        actual = [a["id"] for a in data["assets"]]
        assert actual == expected

    def test_404_for_unknown(self, client, owner_token):
        r = client.get("/posts/no-such-post", headers=_auth(owner_token))
        assert r.status_code == 404


# ── PATCH /posts/{id} ────────────────────────────────────────────────────────

class TestUpdatePost:
    @pytest.fixture(scope="class")
    def post(self, client, owner_token):
        r = client.post("/posts", data={"body": "original"}, headers=_auth(owner_token))
        return r.json()

    def test_update_body(self, client, owner_token, post):
        r = client.patch(f"/posts/{post['id']}", json={"body": "updated"}, headers=_auth(owner_token))
        assert r.status_code == 200
        assert r.json()["body"] == "updated"

    def test_update_tags(self, client, owner_token, post):
        r = client.patch(f"/posts/{post['id']}", json={"tags": ["new-tag"]}, headers=_auth(owner_token))
        assert r.status_code == 200
        assert r.json()["tags"] == ["new-tag"]

    def test_no_fields_returns_422(self, client, owner_token, post):
        r = client.patch(f"/posts/{post['id']}", json={}, headers=_auth(owner_token))
        assert r.status_code == 422

    def test_404_for_unknown(self, client, owner_token):
        r = client.patch("/posts/no-such", json={"body": "x"}, headers=_auth(owner_token))
        assert r.status_code == 404


# ── DELETE /posts/{id} ────────────────────────────────────────────────────────

class TestDeletePost:
    def test_delete_removes_from_feed(self, client, owner_token):
        r = client.post("/posts", data={"body": "to be deleted"}, headers=_auth(owner_token))
        post_id = r.json()["id"]
        client.delete(f"/posts/{post_id}", headers=_auth(owner_token))
        r2 = client.get(f"/posts/{post_id}", headers=_auth(owner_token))
        assert r2.status_code == 404

    def test_delete_returns_204(self, client, owner_token):
        r = client.post("/posts", data={"body": "delete me"}, headers=_auth(owner_token))
        r2 = client.delete(f"/posts/{r.json()['id']}", headers=_auth(owner_token))
        assert r2.status_code == 204

    def test_double_delete_404(self, client, owner_token):
        r = client.post("/posts", data={"body": "once"}, headers=_auth(owner_token))
        pid = r.json()["id"]
        client.delete(f"/posts/{pid}", headers=_auth(owner_token))
        r2 = client.delete(f"/posts/{pid}", headers=_auth(owner_token))
        assert r2.status_code == 404


# ── post comments ─────────────────────────────────────────────────────────────

class TestPostComments:
    @pytest.fixture(scope="class")
    def post(self, client, owner_token):
        r = client.post("/posts", data={"body": "comment target"}, headers=_auth(owner_token))
        return r.json()

    def test_empty_comments(self, client, owner_token, post):
        r = client.get(f"/posts/{post['id']}/comments", headers=_auth(owner_token))
        assert r.status_code == 200
        assert r.json()["comments"] == []

    def test_post_comment(self, client, owner_token, post):
        r = client.post(
            f"/posts/{post['id']}/comments",
            json={"body": "great post"},
            headers=_auth(owner_token),
        )
        assert r.status_code == 201
        assert r.json()["body"] == "great post"
        assert r.json()["post_id"] == post["id"]

    def test_comment_appears_in_fetch(self, client, owner_token, post):
        client.post(f"/posts/{post['id']}/comments", json={"body": "hi"}, headers=_auth(owner_token))
        r = client.get(f"/posts/{post['id']}/comments", headers=_auth(owner_token))
        assert any(c["body"] == "hi" for c in r.json()["comments"])

    def test_comment_count_increments(self, client, owner_token):
        r = client.post("/posts", data={"body": "count test"}, headers=_auth(owner_token))
        pid = r.json()["id"]
        assert r.json()["comment_count"] == 0
        client.post(f"/posts/{pid}/comments", json={"body": "one"}, headers=_auth(owner_token))
        r2 = client.get(f"/posts/{pid}", headers=_auth(owner_token))
        assert r2.json()["comment_count"] == 1

    def test_threaded_reply(self, client, owner_token, post):
        parent = client.post(
            f"/posts/{post['id']}/comments", json={"body": "parent"}, headers=_auth(owner_token)
        ).json()
        reply = client.post(
            f"/posts/{post['id']}/comments",
            json={"body": "reply", "parent_id": parent["id"]},
            headers=_auth(owner_token),
        ).json()
        assert reply["parent_id"] == parent["id"]

    def test_comments_on_unknown_post_404(self, client, owner_token):
        r = client.get("/posts/no-such/comments", headers=_auth(owner_token))
        assert r.status_code == 404
