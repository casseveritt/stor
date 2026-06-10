"""Phase 31: Node statistics endpoint."""
import io
import json
import pytest


@pytest.fixture(scope="module")
def owner_token(client):
    from server.auth import issue_token
    return issue_token(ttl_seconds=3600)


@pytest.fixture(scope="module")
def owner_headers(owner_token):
    return {"Authorization": f"Bearer {owner_token}"}


# ── /node (public) ────────────────────────────────────────────────────────────

class TestNodePublic:
    def test_node_returns_public_counts(self, client):
        r = client.get("/node")
        assert r.status_code == 200
        data = r.json()
        assert "public_posts" in data
        assert "public_assets" in data
        assert isinstance(data["public_posts"], int)
        assert isinstance(data["public_assets"], int)

    def test_public_counts_reflect_published_content(self, client, owner_headers):
        before = client.get("/node").json()["public_posts"]
        client.post(
            "/posts",
            data={"body": "public post for stats p31", "public": "true"},
            headers=owner_headers,
        )
        after = client.get("/node").json()["public_posts"]
        assert after == before + 1

    def test_private_post_not_counted(self, client, owner_headers):
        before = client.get("/node").json()["public_posts"]
        client.post(
            "/posts",
            data={"body": "private post for stats p31", "public": "false"},
            headers=owner_headers,
        )
        after = client.get("/node").json()["public_posts"]
        assert after == before  # unchanged


# ── /node/stats (owner only) ──────────────────────────────────────────────────

class TestNodeStats:
    def test_owner_can_access_stats(self, client, owner_headers):
        r = client.get("/node/stats", headers=owner_headers)
        assert r.status_code == 200

    def test_unauthenticated_denied(self, client):
        r = client.get("/node/stats")
        assert r.status_code in (401, 403)

    def test_stats_structure(self, client, owner_headers):
        r = client.get("/node/stats", headers=owner_headers)
        data = r.json()
        assert "posts" in data
        assert "assets" in data
        assert "storage_bytes" in data
        assert "comments" in data
        assert "total" in data["posts"]
        assert "public" in data["posts"]
        assert "private" in data["posts"]

    def test_post_counts_consistent(self, client, owner_headers):
        r = client.get("/node/stats", headers=owner_headers)
        p = r.json()["posts"]
        assert p["total"] == p["public"] + p["private"]

    def test_asset_counts_consistent(self, client, owner_headers):
        r = client.get("/node/stats", headers=owner_headers)
        a = r.json()["assets"]
        assert a["total"] == a["public"] + a["private"]

    def test_storage_bytes_positive(self, client, owner_headers):
        r = client.get("/node/stats", headers=owner_headers)
        assert r.json()["storage_bytes"] >= 0

    def test_post_count_increases(self, client, owner_headers):
        before = client.get("/node/stats", headers=owner_headers).json()["posts"]["total"]
        client.post("/posts", data={"body": "stats count check p31"}, headers=owner_headers)
        after = client.get("/node/stats", headers=owner_headers).json()["posts"]["total"]
        assert after == before + 1

    def test_asset_count_increases(self, client, owner_headers):
        before = client.get("/node/stats", headers=owner_headers).json()["assets"]["total"]
        client.post(
            "/assets",
            files={"file": ("stats_test.txt", io.BytesIO(b"stats"), "text/plain")},
            headers=owner_headers,
        )
        after = client.get("/node/stats", headers=owner_headers).json()["assets"]["total"]
        assert after == before + 1
