"""Phase 23: post edit/delete UI — PATCH and DELETE via API, SPA shell checks."""
import base64
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from server.auth import issue_token, setup as auth_setup
from server.crypto import derive_master_key, decrypt_bytes
from tests.conftest import TEST_PASSPHRASE, TEST_SALT, TEST_ARGON2


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def owner_token(store):
    from server.config import NodeConfig
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    config = NodeConfig.load(store / "node_config.json")
    master_key = derive_master_key(TEST_PASSPHRASE, TEST_SALT, **TEST_ARGON2)
    privkey_bytes = decrypt_bytes(base64.b64decode(config.encrypted_private_key), master_key)
    auth_setup(Ed25519PrivateKey.from_private_bytes(privkey_bytes))
    return issue_token(ttl_seconds=3600)


# ── PATCH /posts/{id} ─────────────────────────────────────────────────────────

class TestEditPost:
    @pytest.fixture
    def post(self, client, owner_token):
        r = client.post(
            "/posts",
            data={"body": "original body", "tags": json.dumps(["orig"])},
            headers=_auth(owner_token),
        )
        assert r.status_code == 201
        return r.json()

    def test_edit_body(self, client, owner_token, post):
        r = client.patch(
            f"/posts/{post['id']}",
            json={"body": "updated body", "tags": ["orig"]},
            headers=_auth(owner_token),
        )
        assert r.status_code == 200
        assert r.json()["body"] == "updated body"

    def test_edit_tags(self, client, owner_token, post):
        r = client.patch(
            f"/posts/{post['id']}",
            json={"body": post["body"], "tags": ["new-tag"]},
            headers=_auth(owner_token),
        )
        assert r.status_code == 200
        assert r.json()["tags"] == ["new-tag"]

    def test_edit_preserves_assets(self, client, owner_token):
        r = client.post(
            "/posts",
            data={"body": "has attachment"},
            files=[("files", ("f.txt", b"content", "text/plain"))],
            headers=_auth(owner_token),
        )
        post = r.json()
        asset_id = post["assets"][0]["id"]
        new_body = "updated body\n[asset:" + asset_id + "]"
        r2 = client.patch(
            f"/posts/{post['id']}",
            json={"body": new_body, "tags": []},
            headers=_auth(owner_token),
        )
        assert r2.status_code == 200
        assert any(a["id"] == asset_id for a in r2.json()["assets"])

    def test_edit_returned_body_matches(self, client, owner_token, post):
        r = client.patch(
            f"/posts/{post['id']}",
            json={"body": "final body", "tags": []},
            headers=_auth(owner_token),
        )
        fetched = client.get(f"/posts/{post['id']}", headers=_auth(owner_token)).json()
        assert fetched["body"] == "final body"

    def test_edit_requires_owner(self, client, owner_token, post):
        from server.auth import issue_recipient_token
        r = client.post("/recipients", json={"identity": "p23e@x.com"}, headers=_auth(owner_token))
        tok = issue_recipient_token(client.app.state.db, r.json()["id"])
        r2 = client.patch(f"/posts/{post['id']}", json={"body": "hack"}, headers=_auth(tok))
        assert r2.status_code == 403


# ── DELETE /posts/{id} ────────────────────────────────────────────────────────

class TestDeletePost:
    @pytest.fixture
    def post(self, client, owner_token):
        r = client.post("/posts", data={"body": "to delete"}, headers=_auth(owner_token))
        assert r.status_code == 201
        return r.json()

    def test_delete_returns_204(self, client, owner_token, post):
        r = client.delete(f"/posts/{post['id']}", headers=_auth(owner_token))
        assert r.status_code == 204

    def test_deleted_post_not_in_feed(self, client, owner_token, post):
        client.delete(f"/posts/{post['id']}", headers=_auth(owner_token))
        r = client.get("/posts", headers=_auth(owner_token))
        ids = [p["id"] for p in r.json()["posts"]]
        assert post["id"] not in ids

    def test_deleted_post_returns_404(self, client, owner_token):
        r = client.post("/posts", data={"body": "gone"}, headers=_auth(owner_token))
        pid = r.json()["id"]
        client.delete(f"/posts/{pid}", headers=_auth(owner_token))
        assert client.get(f"/posts/{pid}", headers=_auth(owner_token)).status_code == 404

    def test_delete_requires_owner(self, client, owner_token):
        r = client.post("/posts", data={"body": "protected"}, headers=_auth(owner_token))
        pid = r.json()["id"]
        from server.auth import issue_recipient_token
        r2 = client.post("/recipients", json={"identity": "p23d@x.com"}, headers=_auth(owner_token))
        tok = issue_recipient_token(client.app.state.db, r2.json()["id"])
        assert client.delete(f"/posts/{pid}", headers=_auth(tok)).status_code == 403


# ── SPA shell checks ──────────────────────────────────────────────────────────

class TestSPAEditDeleteUI:
    def test_edit_function_present(self, client):
        assert "startEditPost" in client.get("/").text

    def test_delete_function_present(self, client):
        assert "executeDeletePost" in client.get("/").text

    def test_confirm_delete_present(self, client):
        assert "confirmDeletePost" in client.get("/").text

    def test_btn_danger_style_present(self, client):
        assert "btn-danger" in client.get("/").text

    def test_edit_body_textarea_style(self, client):
        assert "edit-body" in client.get("/").text
