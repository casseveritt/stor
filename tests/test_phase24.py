"""Phase 24: MCP server post tools."""
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

    mcp_mod._setup("http://testserver", owner_token, _client=_Bridge())
    yield
    mcp_mod._http = None


@pytest.fixture(scope="module")
def sample_post(client, owner_token, live_mcp):
    r = client.post(
        "/posts",
        data={"body": "MCP test post — hello from phase 24", "tags": json.dumps(["mcp24", "test"])},
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert r.status_code == 201
    return r.json()


# ── get_posts ─────────────────────────────────────────────────────────────────

class TestGetPosts:
    def test_returns_posts_list(self, live_mcp):
        data = json.loads(mcp_mod.get_posts())
        assert "posts" in data
        assert isinstance(data["posts"], list)

    def test_limit_respected(self, live_mcp):
        data = json.loads(mcp_mod.get_posts(limit=2))
        assert len(data["posts"]) <= 2

    def test_tag_filter(self, live_mcp, sample_post):
        data = json.loads(mcp_mod.get_posts(tags="mcp24"))
        ids = [p["id"] for p in data["posts"]]
        assert sample_post["id"] in ids

    def test_q_search(self, live_mcp, sample_post):
        data = json.loads(mcp_mod.get_posts(q="phase 24"))
        ids = [p["id"] for p in data["posts"]]
        assert sample_post["id"] in ids

    def test_q_no_match(self, live_mcp):
        data = json.loads(mcp_mod.get_posts(q="zzzqqq-no-match-ever"))
        assert data["posts"] == []

    def test_posts_have_required_fields(self, live_mcp, sample_post):
        data = json.loads(mcp_mod.get_posts())
        if data["posts"]:
            p = data["posts"][0]
            for f in ("id", "body", "tags", "created_at", "assets", "comment_count"):
                assert f in p


# ── get_post ──────────────────────────────────────────────────────────────────

class TestGetPost:
    def test_returns_post(self, live_mcp, sample_post):
        data = json.loads(mcp_mod.get_post(sample_post["id"]))
        assert data["id"] == sample_post["id"]

    def test_body_correct(self, live_mcp, sample_post):
        data = json.loads(mcp_mod.get_post(sample_post["id"]))
        assert "phase 24" in data["body"]

    def test_tags_present(self, live_mcp, sample_post):
        data = json.loads(mcp_mod.get_post(sample_post["id"]))
        assert "mcp24" in data["tags"]

    def test_assets_field_present(self, live_mcp, sample_post):
        data = json.loads(mcp_mod.get_post(sample_post["id"]))
        assert isinstance(data["assets"], list)


# ── create_post ───────────────────────────────────────────────────────────────

class TestCreatePost:
    def test_creates_text_post(self, live_mcp):
        result = json.loads(mcp_mod.create_post("Created by MCP agent"))
        assert result["body"] == "Created by MCP agent"
        assert result["id"]

    def test_creates_with_tags(self, live_mcp):
        result = json.loads(mcp_mod.create_post("Tagged MCP post", tags="mcp-created agent"))
        assert "mcp-created" in result["tags"]
        assert "agent" in result["tags"]

    def test_post_appears_in_feed(self, live_mcp):
        result = json.loads(mcp_mod.create_post("Feed visibility check mcp24-unique"))
        feed = json.loads(mcp_mod.get_posts(q="Feed visibility check mcp24-unique"))
        ids = [p["id"] for p in feed["posts"]]
        assert result["id"] in ids


# ── get_post_comments ─────────────────────────────────────────────────────────

class TestGetPostComments:
    def test_returns_list(self, live_mcp, sample_post):
        result = json.loads(mcp_mod.get_post_comments(sample_post["id"]))
        assert isinstance(result, list)

    def test_excludes_deleted(self, live_mcp, sample_post):
        # All returned comments should not be deleted
        comments = json.loads(mcp_mod.get_post_comments(sample_post["id"]))
        assert all(not c.get("deleted") for c in comments)


# ── comment_on_post ───────────────────────────────────────────────────────────

class TestCommentOnPost:
    def test_post_and_fetch(self, live_mcp, sample_post):
        result = json.loads(mcp_mod.comment_on_post(sample_post["id"], "Hello from MCP phase 24"))
        assert result["body"] == "Hello from MCP phase 24"
        assert result["post_id"] == sample_post["id"]

        comments = json.loads(mcp_mod.get_post_comments(sample_post["id"]))
        bodies = [c["body"] for c in comments]
        assert "Hello from MCP phase 24" in bodies

    def test_reply(self, live_mcp, sample_post):
        parent = json.loads(mcp_mod.comment_on_post(sample_post["id"], "parent"))
        reply = json.loads(mcp_mod.comment_on_post(sample_post["id"], "reply", parent_id=parent["id"]))
        assert reply["parent_id"] == parent["id"]

    def test_comment_count_increments(self, live_mcp):
        post = json.loads(mcp_mod.create_post("comment count test"))
        before = post["comment_count"]
        mcp_mod.comment_on_post(post["id"], "bump")
        after = json.loads(mcp_mod.get_post(post["id"]))["comment_count"]
        assert after == before + 1
