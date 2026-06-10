"""Phase 28: Post ACL — grant specific recipients access to private posts."""
import json
import pytest

from server.auth import issue_node_token


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def owner_token(client):
    from server.auth import issue_token
    return issue_token(ttl_seconds=3600)


@pytest.fixture(scope="module")
def owner_headers(owner_token):
    return {"Authorization": f"Bearer {owner_token}"}


@pytest.fixture(scope="module")
def recipient_a(client, owner_headers):
    r = client.post("/recipients", json={"identity": "p28-recip-a@example.com"}, headers=owner_headers)
    assert r.status_code == 201
    rid = r.json()["id"]
    db = client.app.state.db
    token = issue_node_token(db, rid)
    return {"id": rid, "token": token, "headers": {"Authorization": f"Bearer {token}"}}


@pytest.fixture(scope="module")
def recipient_b(client, owner_headers):
    r = client.post("/recipients", json={"identity": "p28-recip-b@example.com"}, headers=owner_headers)
    assert r.status_code == 201
    rid = r.json()["id"]
    db = client.app.state.db
    token = issue_node_token(db, rid)
    return {"id": rid, "token": token, "headers": {"Authorization": f"Bearer {token}"}}


@pytest.fixture(scope="module")
def private_post(client, owner_headers):
    r = client.post(
        "/posts",
        data={"body": "ACL-gated private post p28", "public": "false"},
        headers=owner_headers,
    )
    assert r.status_code == 201
    return r.json()


# ── baseline: no ACL ─────────────────────────────────────────────────────────

class TestNoAcl:
    def test_recipient_cannot_see_private_post_in_feed(self, client, recipient_a, private_post):
        r = client.get("/posts", headers=recipient_a["headers"])
        ids = [p["id"] for p in r.json()["posts"]]
        assert private_post["id"] not in ids

    def test_recipient_cannot_get_private_post(self, client, recipient_a, private_post):
        r = client.get(f"/posts/{private_post['id']}", headers=recipient_a["headers"])
        assert r.status_code == 403

    def test_recipient_cannot_comment_on_private_post(self, client, recipient_a, private_post):
        r = client.post(
            f"/posts/{private_post['id']}/comments",
            json={"body": "sneaky"},
            headers=recipient_a["headers"],
        )
        assert r.status_code == 403


# ── ACL management ────────────────────────────────────────────────────────────

class TestAclManagement:
    def test_get_acl_empty(self, client, owner_headers, private_post):
        r = client.get(f"/posts/{private_post['id']}/acl", headers=owner_headers)
        assert r.status_code == 200
        assert r.json()["recipients"] == []

    def test_add_recipient(self, client, owner_headers, recipient_a, private_post):
        r = client.patch(
            f"/posts/{private_post['id']}/acl",
            json={"add": [recipient_a["id"]]},
            headers=owner_headers,
        )
        assert r.status_code == 200
        ids = [rec["id"] for rec in r.json()["recipients"]]
        assert recipient_a["id"] in ids

    def test_get_acl_reflects_change(self, client, owner_headers, recipient_a, private_post):
        r = client.get(f"/posts/{private_post['id']}/acl", headers=owner_headers)
        ids = [rec["id"] for rec in r.json()["recipients"]]
        assert recipient_a["id"] in ids

    def test_add_nonexistent_recipient_404(self, client, owner_headers, private_post):
        r = client.patch(
            f"/posts/{private_post['id']}/acl",
            json={"add": ["00000000-0000-0000-0000-000000000000"]},
            headers=owner_headers,
        )
        assert r.status_code == 404

    def test_non_owner_cannot_manage_acl(self, client, recipient_a, private_post):
        r = client.patch(
            f"/posts/{private_post['id']}/acl",
            json={"add": []},
            headers=recipient_a["headers"],
        )
        assert r.status_code == 403


# ── granted recipient access ──────────────────────────────────────────────────

class TestGrantedAccess:
    def test_granted_recipient_sees_post_in_feed(self, client, recipient_a, private_post, owner_headers):
        # ensure recipient_a is in ACL (idempotent add)
        client.patch(f"/posts/{private_post['id']}/acl", json={"add": [recipient_a["id"]]}, headers=owner_headers)
        r = client.get("/posts", headers=recipient_a["headers"])
        ids = [p["id"] for p in r.json()["posts"]]
        assert private_post["id"] in ids

    def test_granted_recipient_can_get_post(self, client, recipient_a, private_post, owner_headers):
        client.patch(f"/posts/{private_post['id']}/acl", json={"add": [recipient_a["id"]]}, headers=owner_headers)
        r = client.get(f"/posts/{private_post['id']}", headers=recipient_a["headers"])
        assert r.status_code == 200

    def test_granted_recipient_can_comment(self, client, recipient_a, private_post, owner_headers):
        client.patch(f"/posts/{private_post['id']}/acl", json={"add": [recipient_a["id"]]}, headers=owner_headers)
        r = client.post(
            f"/posts/{private_post['id']}/comments",
            json={"body": "hello from recipient_a"},
            headers=recipient_a["headers"],
        )
        assert r.status_code == 201

    def test_ungrant_removes_access(self, client, owner_headers, recipient_a, private_post):
        r = client.patch(
            f"/posts/{private_post['id']}/acl",
            json={"remove": [recipient_a["id"]]},
            headers=owner_headers,
        )
        assert r.status_code == 200
        r2 = client.get(f"/posts/{private_post['id']}", headers=recipient_a["headers"])
        assert r2.status_code == 403

    def test_other_recipient_still_denied(self, client, owner_headers, recipient_a, recipient_b, private_post):
        # grant a, check b is still denied
        client.patch(f"/posts/{private_post['id']}/acl", json={"add": [recipient_a["id"]]}, headers=owner_headers)
        r = client.get(f"/posts/{private_post['id']}", headers=recipient_b["headers"])
        assert r.status_code == 403
