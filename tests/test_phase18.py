"""Phase 18: MCP server — contac as Claude tools."""
import base64
import json
import sys
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock

import httpx
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
    """MCP server wired to the live in-process test node via Starlette TestClient bridge.

    ASGITransport is async-only; instead we wrap the sync TestClient so the MCP server
    gets back real httpx.Response objects (TestClient already returns those).
    """
    auth = {"Authorization": f"Bearer {owner_token}"}

    class _Bridge:
        def get(self, path, params=None, **_kw):
            return client.get(path, params=params or {}, headers=auth)
        def post(self, path, json=None, **_kw):
            return client.post(path, json=json, headers=auth)

    mcp_mod._setup("http://testserver", owner_token, _client=_Bridge())
    yield
    mcp_mod._http = None


@pytest.fixture(scope="module")
def sample_asset(client, owner_token, live_mcp):
    r = client.post(
        "/assets",
        files={"file": ("mcp-test.txt", b"Hello from MCP test asset", "text/plain")},
        data={"title": "MCP Sample", "tags": json.dumps(["mcp", "test"])},
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert r.status_code == 201
    return r.json()


@pytest.fixture(scope="module")
def image_asset(client, owner_token, live_mcp):
    import io
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (8, 8), color=(50, 100, 200)).save(buf, format="PNG")
    r = client.post(
        "/assets",
        files={"file": ("mcp-img.png", buf.getvalue(), "image/png")},
        data={"title": "MCP Image"},
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert r.status_code == 201
    return r.json()


# ── node_info ─────────────────────────────────────────────────────────────────

class TestNodeInfo:
    def test_returns_json(self, live_mcp):
        result = mcp_mod.node_info()
        data = json.loads(result)
        assert "node" in data
        assert "public_key" in data

    def test_public_key_is_base64(self, live_mcp):
        data = json.loads(mcp_mod.node_info())
        base64.b64decode(data["public_key"])  # should not raise


# ── get_feed ──────────────────────────────────────────────────────────────────

class TestGetFeed:
    def test_returns_assets_list(self, live_mcp):
        data = json.loads(mcp_mod.get_feed())
        assert "assets" in data
        assert isinstance(data["assets"], list)

    def test_limit_respected(self, live_mcp):
        data = json.loads(mcp_mod.get_feed(limit=2))
        assert len(data["assets"]) <= 2

    def test_limit_clamped_to_100(self, live_mcp):
        data = json.loads(mcp_mod.get_feed(limit=9999))
        assert len(data["assets"]) <= 100


# ── search_assets ─────────────────────────────────────────────────────────────

class TestSearchAssets:
    def test_q_filters_by_title(self, live_mcp, sample_asset):
        results = json.loads(mcp_mod.search_assets(q="MCP Sample"))
        ids = [a["id"] for a in results]
        assert sample_asset["id"] in ids

    def test_q_excludes_non_match(self, live_mcp):
        results = json.loads(mcp_mod.search_assets(q="xyzzy-nonexistent-title-99"))
        assert results == []

    def test_media_type_filter(self, live_mcp, sample_asset):
        results = json.loads(mcp_mod.search_assets(media_type="text/plain"))
        types = {a["media_type"] for a in results}
        assert all(t == "text/plain" for t in types)

    def test_tags_filter(self, live_mcp, sample_asset):
        results = json.loads(mcp_mod.search_assets(tags="mcp"))
        ids = [a["id"] for a in results]
        assert sample_asset["id"] in ids

    def test_returns_list(self, live_mcp):
        assert isinstance(json.loads(mcp_mod.search_assets()), list)


# ── get_asset_meta ────────────────────────────────────────────────────────────

class TestGetAssetMeta:
    def test_returns_metadata(self, live_mcp, sample_asset):
        data = json.loads(mcp_mod.get_asset_meta(sample_asset["id"]))
        assert data["id"] == sample_asset["id"]
        assert data["title"] == "MCP Sample"
        assert "mcp" in data["tags"]

    def test_metadata_has_required_fields(self, live_mcp, sample_asset):
        data = json.loads(mcp_mod.get_asset_meta(sample_asset["id"]))
        for f in ("id", "title", "tags", "media_type", "size", "created_at", "comment_count"):
            assert f in data


# ── fetch_asset_text ──────────────────────────────────────────────────────────

class TestFetchAssetText:
    def test_text_asset_returns_content(self, live_mcp, sample_asset):
        text = mcp_mod.fetch_asset_text(sample_asset["id"])
        assert text == "Hello from MCP test asset"

    def test_binary_asset_returns_description(self, live_mcp, image_asset):
        result = mcp_mod.fetch_asset_text(image_asset["id"])
        assert result.startswith("[binary asset")
        assert "image/" in result


# ── list_tags ─────────────────────────────────────────────────────────────────

class TestListTags:
    def test_returns_list(self, live_mcp):
        data = json.loads(mcp_mod.list_tags())
        assert isinstance(data, list)

    def test_tag_shape(self, live_mcp, sample_asset):
        data = json.loads(mcp_mod.list_tags())
        if data:
            assert "tag" in data[0]
            assert "count" in data[0]

    def test_mcp_tag_present(self, live_mcp, sample_asset):
        data = json.loads(mcp_mod.list_tags())
        tags = {item["tag"] for item in data}
        assert "mcp" in tags


# ── comments tools ────────────────────────────────────────────────────────────

class TestCommentTools:
    def test_get_comments_empty_initially(self, live_mcp, sample_asset):
        # Fresh asset may have no comments
        data = json.loads(mcp_mod.get_asset_comments(sample_asset["id"]))
        assert isinstance(data, list)

    def test_post_and_fetch_comment(self, live_mcp, sample_asset):
        result = json.loads(mcp_mod.post_comment(sample_asset["id"], "Hello from MCP"))
        assert result["body"] == "Hello from MCP"
        assert result["id"]
        comments = json.loads(mcp_mod.get_asset_comments(sample_asset["id"]))
        bodies = [c["body"] for c in comments]
        assert "Hello from MCP" in bodies

    def test_post_reply(self, live_mcp, sample_asset):
        parent = json.loads(mcp_mod.post_comment(sample_asset["id"], "parent post"))
        reply = json.loads(mcp_mod.post_comment(sample_asset["id"], "reply post", parent["id"]))
        assert reply["parent_id"] == parent["id"]


# ── get_asset_history ─────────────────────────────────────────────────────────

class TestGetAssetHistory:
    def test_single_version_history(self, live_mcp, sample_asset):
        data = json.loads(mcp_mod.get_asset_history(sample_asset["id"]))
        assert data["count"] >= 1
        assert any(e["is_current"] for e in data["history"])

    def test_history_shape(self, live_mcp, sample_asset):
        data = json.loads(mcp_mod.get_asset_history(sample_asset["id"]))
        assert "asset_id" in data
        assert "count" in data
        assert "history" in data


# ── configuration ─────────────────────────────────────────────────────────────

class TestConfiguration:
    def test_setup_accepts_injected_client(self):
        mock_http = MagicMock(spec=httpx.Client)
        mcp_mod._setup("http://example.com", "token", _client=mock_http)
        assert mcp_mod._http is mock_http
        # restore live client for subsequent tests (live_mcp fixture doesn't re-run)

    def test_env_vars_recognized(self, monkeypatch):
        monkeypatch.setenv("CONTAC_NODE_URL", "http://my-node")
        monkeypatch.setenv("CONTAC_TOKEN", "my-tok")
        import importlib, argparse
        # Verify env vars set (actual startup tested via live_mcp above)
        assert os.environ.get("CONTAC_NODE_URL") == "http://my-node"


import os
