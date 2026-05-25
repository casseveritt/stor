"""Phase 25: Post visibility (public/private flag)."""
import json
import pytest


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def owner_token(client):
    r = client.post("/auth/owner", json={})
    # fall back to conftest pattern — issue via auth module directly
    import base64
    from server.auth import issue_token
    return issue_token(ttl_seconds=3600)


@pytest.fixture(scope="module")
def owner_headers(owner_token):
    return {"Authorization": f"Bearer {owner_token}"}


@pytest.fixture(scope="module")
def private_post(client, owner_headers):
    r = client.post(
        "/posts",
        data={"body": "private phase25 post", "tags": json.dumps(["p25"]), "public": "false"},
        headers=owner_headers,
    )
    assert r.status_code == 201
    return r.json()


@pytest.fixture(scope="module")
def public_post(client, owner_headers):
    r = client.post(
        "/posts",
        data={"body": "public phase25 post", "tags": json.dumps(["p25"]), "public": "true"},
        headers=owner_headers,
    )
    assert r.status_code == 201
    return r.json()


# ── visibility flag on create ─────────────────────────────────────────────────

class TestCreateVisibility:
    def test_default_is_private(self, client, owner_headers):
        r = client.post("/posts", data={"body": "default vis"}, headers=owner_headers)
        assert r.status_code == 201
        assert r.json()["public"] is False

    def test_public_true(self, public_post):
        assert public_post["public"] is True

    def test_public_false(self, private_post):
        assert private_post["public"] is False


# ── owner sees everything ─────────────────────────────────────────────────────

class TestOwnerAccess:
    def test_owner_feed_includes_private(self, client, owner_headers, private_post):
        r = client.get("/posts", headers=owner_headers)
        ids = [p["id"] for p in r.json()["posts"]]
        assert private_post["id"] in ids

    def test_owner_feed_includes_public(self, client, owner_headers, public_post):
        r = client.get("/posts", headers=owner_headers)
        ids = [p["id"] for p in r.json()["posts"]]
        assert public_post["id"] in ids

    def test_owner_get_private(self, client, owner_headers, private_post):
        r = client.get(f"/posts/{private_post['id']}", headers=owner_headers)
        assert r.status_code == 200

    def test_owner_get_public(self, client, owner_headers, public_post):
        r = client.get(f"/posts/{public_post['id']}", headers=owner_headers)
        assert r.status_code == 200


# ── unauthenticated access ────────────────────────────────────────────────────

class TestUnauthenticatedAccess:
    def test_feed_excludes_private(self, client, private_post):
        r = client.get("/posts")
        ids = [p["id"] for p in r.json()["posts"]]
        assert private_post["id"] not in ids

    def test_feed_includes_public(self, client, public_post):
        r = client.get("/posts")
        ids = [p["id"] for p in r.json()["posts"]]
        assert public_post["id"] in ids

    def test_get_public_post_allowed(self, client, public_post):
        r = client.get(f"/posts/{public_post['id']}")
        assert r.status_code == 200

    def test_get_private_post_denied(self, client, private_post):
        r = client.get(f"/posts/{private_post['id']}")
        assert r.status_code == 403


# ── update visibility ─────────────────────────────────────────────────────────

class TestUpdateVisibility:
    def test_make_private_post_public(self, client, owner_headers):
        r = client.post(
            "/posts",
            data={"body": "will go public", "public": "false"},
            headers=owner_headers,
        )
        post_id = r.json()["id"]
        r2 = client.patch(f"/posts/{post_id}", json={"public": True}, headers=owner_headers)
        assert r2.status_code == 200
        assert r2.json()["public"] is True

    def test_make_public_post_private(self, client, owner_headers):
        r = client.post(
            "/posts",
            data={"body": "will go private", "public": "true"},
            headers=owner_headers,
        )
        post_id = r.json()["id"]
        r2 = client.patch(f"/posts/{post_id}", json={"public": False}, headers=owner_headers)
        assert r2.status_code == 200
        assert r2.json()["public"] is False
        # now unauthenticated should not see it
        r3 = client.get(f"/posts/{post_id}")
        assert r3.status_code == 403

    def test_anon_cannot_see_after_privatize(self, client, owner_headers):
        r = client.post(
            "/posts",
            data={"body": "privatized", "public": "true"},
            headers=owner_headers,
        )
        post_id = r.json()["id"]
        client.patch(f"/posts/{post_id}", json={"public": False}, headers=owner_headers)
        r2 = client.get(f"/posts/{post_id}")
        assert r2.status_code == 403


# ── comments on private posts ─────────────────────────────────────────────────

class TestPrivatePostComments:
    def test_anon_cannot_comment_on_private(self, client, private_post):
        r = client.post(f"/posts/{private_post['id']}/comments", json={"body": "sneaky"})
        assert r.status_code == 403

    def test_anon_cannot_fetch_comments_on_private(self, client, private_post):
        r = client.get(f"/posts/{private_post['id']}/comments")
        assert r.status_code == 403

    def test_owner_can_comment_on_private(self, client, owner_headers, private_post):
        r = client.post(
            f"/posts/{private_post['id']}/comments",
            json={"body": "owner comment"},
            headers=owner_headers,
        )
        assert r.status_code == 201
