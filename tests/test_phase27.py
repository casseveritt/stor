"""Phase 27: Asset visibility (public/private flag on assets)."""
import io
import json
import pytest


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def owner_token(client):
    from server.auth import issue_token
    return issue_token(ttl_seconds=3600)


@pytest.fixture(scope="module")
def owner_headers(owner_token):
    return {"Authorization": f"Bearer {owner_token}"}


def _upload(client, headers, content=b"hello", content_type="text/plain", public="false"):
    return client.post(
        "/assets",
        files={"file": ("test.txt", io.BytesIO(content), content_type)},
        data={"public": public},
        headers=headers,
    )


@pytest.fixture(scope="module")
def private_asset(client, owner_headers):
    r = _upload(client, owner_headers, content=b"private p27", public="false")
    assert r.status_code == 201
    return r.json()


@pytest.fixture(scope="module")
def public_asset(client, owner_headers):
    r = _upload(client, owner_headers, content=b"public p27", public="true")
    assert r.status_code == 201
    return r.json()


# ── visibility flag on create ─────────────────────────────────────────────────

class TestAssetCreateVisibility:
    def test_default_is_private(self, client, owner_headers):
        r = _upload(client, owner_headers, content=b"default-vis-p27")
        assert r.status_code == 201
        assert r.json()["public"] is False

    def test_public_true(self, public_asset):
        assert public_asset["public"] is True

    def test_private_flag(self, private_asset):
        assert private_asset["public"] is False


# ── owner sees everything ─────────────────────────────────────────────────────

class TestOwnerAssetAccess:
    def test_owner_feed_includes_private(self, client, owner_headers, private_asset):
        r = client.get("/feed", headers=owner_headers)
        ids = [a["id"] for a in r.json()["assets"]]
        assert private_asset["id"] in ids

    def test_owner_feed_includes_public(self, client, owner_headers, public_asset):
        r = client.get("/feed", headers=owner_headers)
        ids = [a["id"] for a in r.json()["assets"]]
        assert public_asset["id"] in ids

    def test_owner_fetch_private_meta(self, client, owner_headers, private_asset):
        r = client.get(f"/assets/{private_asset['id']}/meta", headers=owner_headers)
        assert r.status_code == 200

    def test_owner_fetch_private_content(self, client, owner_headers, private_asset):
        r = client.get(f"/assets/{private_asset['id']}", headers=owner_headers)
        assert r.status_code == 200


# ── unauthenticated access ────────────────────────────────────────────────────

class TestUnauthenticatedAssetAccess:
    def test_feed_excludes_private(self, client, private_asset):
        r = client.get("/feed")
        ids = [a["id"] for a in r.json()["assets"]]
        assert private_asset["id"] not in ids

    def test_feed_includes_public(self, client, public_asset):
        r = client.get("/feed")
        ids = [a["id"] for a in r.json()["assets"]]
        assert public_asset["id"] in ids

    def test_fetch_public_meta_allowed(self, client, public_asset):
        r = client.get(f"/assets/{public_asset['id']}/meta")
        assert r.status_code == 200

    def test_fetch_public_content_allowed(self, client, public_asset):
        r = client.get(f"/assets/{public_asset['id']}")
        assert r.status_code == 200

    def test_fetch_private_meta_denied(self, client, private_asset):
        r = client.get(f"/assets/{private_asset['id']}/meta")
        assert r.status_code == 403

    def test_fetch_private_content_denied(self, client, private_asset):
        r = client.get(f"/assets/{private_asset['id']}")
        assert r.status_code == 403

    def test_comment_on_public_allowed(self, client, public_asset):
        r = client.post(
            f"/assets/{public_asset['id']}/comments",
            json={"body": "anon comment on public asset"},
        )
        assert r.status_code == 201

    def test_comment_on_private_denied(self, client, private_asset):
        r = client.post(
            f"/assets/{private_asset['id']}/comments",
            json={"body": "sneaky"},
        )
        assert r.status_code == 403

    def test_fetch_comments_public_allowed(self, client, public_asset):
        r = client.get(f"/assets/{public_asset['id']}/comments")
        assert r.status_code == 200

    def test_fetch_comments_private_denied(self, client, private_asset):
        r = client.get(f"/assets/{private_asset['id']}/comments")
        assert r.status_code == 403


# ── update visibility ─────────────────────────────────────────────────────────

class TestUpdateAssetVisibility:
    def test_make_private_public(self, client, owner_headers):
        r = _upload(client, owner_headers, content=b"will-go-public", public="false")
        asset_id = r.json()["id"]
        r2 = client.patch(f"/assets/{asset_id}", json={"public": True}, headers=owner_headers)
        assert r2.status_code == 200
        assert r2.json()["public"] is True
        r3 = client.get(f"/assets/{asset_id}/meta")
        assert r3.status_code == 200

    def test_make_public_private(self, client, owner_headers):
        r = _upload(client, owner_headers, content=b"will-go-private", public="true")
        asset_id = r.json()["id"]
        r2 = client.patch(f"/assets/{asset_id}", json={"public": False}, headers=owner_headers)
        assert r2.status_code == 200
        assert r2.json()["public"] is False
        r3 = client.get(f"/assets/{asset_id}/meta")
        assert r3.status_code == 403
