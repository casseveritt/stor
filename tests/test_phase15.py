"""Phase 15: Browser upload UI — upload endpoint patterns the SPA uses."""
import base64
import io
import json
import uuid

import pytest
from PIL import Image

from server.auth import issue_token, issue_node_token, setup as auth_setup
from server.crypto import derive_master_key, decrypt_bytes
from tests.conftest import TEST_PASSPHRASE, TEST_SALT, TEST_ARGON2


def _tiny_png(color=(80, 120, 200)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (16, 16), color=color).save(buf, format="PNG")
    return buf.getvalue()


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


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
    return {"id": rid, "token": issue_node_token(db, rid)}


# ── response shape (fields the SPA's makeCard() needs) ────────────────────────

class TestUploadResponseShape:
    def test_upload_returns_201(self, client, owner_token):
        r = client.post("/assets",
            files={"file": ("shape.png", _tiny_png(), "image/png")},
            headers=_auth(owner_token))
        assert r.status_code == 201

    def test_response_has_required_fields(self, client, owner_token):
        r = client.post("/assets",
            files={"file": ("fields.png", _tiny_png(), "image/png")},
            headers=_auth(owner_token))
        data = r.json()
        for field in ("id", "content_hash", "media_type", "size", "created_at", "title", "tags"):
            assert field in data, f"missing field: {field}"

    def test_title_stored_and_returned(self, client, owner_token):
        r = client.post("/assets",
            files={"file": ("titled.txt", b"hello", "text/plain")},
            data={"title": "My Document"},
            headers=_auth(owner_token))
        assert r.json()["title"] == "My Document"

    def test_tags_as_json_string_stored(self, client, owner_token):
        r = client.post("/assets",
            files={"file": ("tagged.txt", b"tagged", "text/plain")},
            data={"title": "Tagged", "tags": json.dumps(["nature", "photo"])},
            headers=_auth(owner_token))
        assert r.json()["tags"] == ["nature", "photo"]

    def test_media_type_preserved(self, client, owner_token):
        r = client.post("/assets",
            files={"file": ("doc.pdf", b"%PDF", "application/pdf")},
            headers=_auth(owner_token))
        assert r.json()["media_type"] == "application/pdf"


# ── upload access control ─────────────────────────────────────────────────────

class TestUploadAccess:
    def test_non_owner_cannot_upload(self, client, recipient):
        r = client.post("/assets",
            files={"file": ("x.txt", b"x", "text/plain")},
            headers=_auth(recipient["token"]))
        assert r.status_code == 403

    def test_unauthenticated_cannot_upload(self, client):
        r = client.post("/assets",
            files={"file": ("x.txt", b"x", "text/plain")})
        assert r.status_code == 401

    def test_owner_can_upload_with_authorization_header(self, client, owner_token):
        r = client.post("/assets",
            files={"file": ("auth-header.png", _tiny_png(), "image/png")},
            headers=_auth(owner_token))
        assert r.status_code == 201


# ── upload-then-read flow ─────────────────────────────────────────────────────

class TestUploadThenRead:
    def test_uploaded_asset_appears_in_feed(self, client, owner_token):
        r = client.post("/assets",
            files={"file": ("feed-check.txt", b"feed content", "text/plain")},
            data={"title": "FeedCheck"},
            headers=_auth(owner_token))
        asset_id = r.json()["id"]
        feed = client.get("/feed", headers=_auth(owner_token)).json()
        ids = [a["id"] for a in feed["assets"]]
        assert asset_id in ids

    def test_uploaded_image_has_thumbnail(self, client, owner_token):
        r = client.post("/assets",
            files={"file": ("thumb-test.png", _tiny_png((200, 100, 50)), "image/png")},
            headers=_auth(owner_token))
        asset_id = r.json()["id"]
        thumb = client.get(f"/assets/{asset_id}/thumb", headers=_auth(owner_token))
        assert thumb.status_code == 200
        assert "image/" in thumb.headers["content-type"]

    def test_sequential_uploads_all_appear_in_feed(self, client, owner_token):
        ids = []
        for i in range(3):
            r = client.post("/assets",
                files={"file": (f"seq-{i}.txt", f"content {i}".encode(), "text/plain")},
                data={"title": f"Sequential {i}"},
                headers=_auth(owner_token))
            assert r.status_code == 201
            ids.append(r.json()["id"])
        feed = client.get("/feed?limit=200", headers=_auth(owner_token)).json()
        feed_ids = {a["id"] for a in feed["assets"]}
        for id_ in ids:
            assert id_ in feed_ids

    def test_same_content_same_hash(self, client, owner_token):
        content = b"identical content bytes"
        r1 = client.post("/assets",
            files={"file": ("dup-a.txt", content, "text/plain")},
            headers=_auth(owner_token))
        r2 = client.post("/assets",
            files={"file": ("dup-b.txt", content, "text/plain")},
            headers=_auth(owner_token))
        assert r1.json()["content_hash"] == r2.json()["content_hash"]


# ── download link (modal action) ──────────────────────────────────────────────

class TestDownloadAction:
    def test_asset_downloadable_via_get(self, client, owner_token):
        content = b"download me"
        r = client.post("/assets",
            files={"file": ("dl.txt", content, "text/plain")},
            headers=_auth(owner_token))
        asset_id = r.json()["id"]
        dl = client.get(f"/assets/{asset_id}", headers=_auth(owner_token))
        assert dl.status_code == 200
        assert dl.content == content

    def test_asset_downloadable_via_token_param(self, client, owner_token):
        r = client.post("/assets",
            files={"file": ("dl-param.txt", b"query param download", "text/plain")},
            headers=_auth(owner_token))
        asset_id = r.json()["id"]
        dl = client.get(f"/assets/{asset_id}?token={owner_token}")
        assert dl.status_code == 200
