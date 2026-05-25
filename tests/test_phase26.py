"""Phase 26: MCP post edit and delete tools."""
import base64
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import tools.mcp_server as mcp_mod

from server.auth import issue_token, setup as auth_setup
from server.crypto import derive_master_key, decrypt_bytes
from tests.conftest import TEST_PASSPHRASE, TEST_SALT, TEST_ARGON2


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
def live_mcp(client, owner_token):
    auth = {"Authorization": f"Bearer {owner_token}"}

    class _Bridge:
        def get(self, path, params=None, **_kw):
            return client.get(path, params=params or {}, headers=auth)
        def post(self, path, json=None, data=None, **_kw):
            if data is not None:
                return client.post(path, data=data, headers=auth)
            return client.post(path, json=json, headers=auth)
        def patch(self, path, json=None, **_kw):
            return client.patch(path, json=json, headers=auth)
        def delete(self, path, **_kw):
            return client.delete(path, headers=auth)

    mcp_mod._setup("http://testserver", owner_token, _client=_Bridge())
    yield
    mcp_mod._http = None


@pytest.fixture(scope="module")
def editable_post(client, owner_token, live_mcp):
    r = client.post(
        "/posts",
        data={"body": "original body p26", "tags": json.dumps(["p26"])},
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert r.status_code == 201
    return r.json()


# ── update_post ───────────────────────────────────────────────────────────────

class TestUpdatePost:
    def test_update_body(self, live_mcp, editable_post):
        result = json.loads(mcp_mod.update_post(editable_post["id"], body="updated body p26"))
        assert result["body"] == "updated body p26"
        assert result["id"] == editable_post["id"]

    def test_update_tags(self, live_mcp, editable_post):
        result = json.loads(mcp_mod.update_post(editable_post["id"], tags="p26 edited"))
        assert "edited" in result["tags"]
        assert "p26" in result["tags"]

    def test_update_public(self, live_mcp, editable_post):
        result = json.loads(mcp_mod.update_post(editable_post["id"], public=True))
        assert result["public"] is True
        result2 = json.loads(mcp_mod.update_post(editable_post["id"], public=False))
        assert result2["public"] is False

    def test_update_body_reflects_in_get(self, live_mcp):
        post = json.loads(mcp_mod.create_post("round-trip body check"))
        mcp_mod.update_post(post["id"], body="updated round-trip")
        fetched = json.loads(mcp_mod.get_post(post["id"]))
        assert fetched["body"] == "updated round-trip"

    def test_update_no_fields_errors(self, live_mcp, editable_post):
        result = json.loads(mcp_mod.update_post(editable_post["id"]))
        assert "error" in result or "detail" in result

    def test_update_nonexistent_post(self, live_mcp):
        result = json.loads(mcp_mod.update_post("00000000-0000-0000-0000-000000000000", body="x"))
        assert "error" in result or "detail" in result


# ── delete_post ───────────────────────────────────────────────────────────────

class TestDeletePost:
    def test_delete_removes_post(self, live_mcp):
        post = json.loads(mcp_mod.create_post("to be deleted p26"))
        result = json.loads(mcp_mod.delete_post(post["id"]))
        assert result.get("deleted") is True or result.get("ok") is True

    def test_deleted_post_not_in_feed(self, live_mcp):
        post = json.loads(mcp_mod.create_post("feed-disappear p26"))
        mcp_mod.delete_post(post["id"])
        feed = json.loads(mcp_mod.get_posts(q="feed-disappear p26"))
        ids = [p["id"] for p in feed["posts"]]
        assert post["id"] not in ids

    def test_delete_nonexistent_returns_error(self, live_mcp):
        result = json.loads(mcp_mod.delete_post("00000000-0000-0000-0000-000000000000"))
        assert "error" in result or "detail" in result
