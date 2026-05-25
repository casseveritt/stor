"""Phase 30: MCP update_asset tool."""
import base64
import io
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
        def post(self, path, json=None, data=None, files=None, **_kw):
            if files is not None:
                return client.post(path, files=files, data=data or {}, headers=auth)
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
def sample_asset(client, owner_token, live_mcp):
    r = client.post(
        "/assets",
        files={"file": ("phase30.txt", io.BytesIO(b"phase 30 asset"), "text/plain")},
        data={"title": "Original Title p30", "tags": '["p30"]'},
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert r.status_code == 201
    return r.json()


# ── update_asset ──────────────────────────────────────────────────────────────

class TestUpdateAsset:
    def test_update_title(self, live_mcp, sample_asset):
        result = json.loads(mcp_mod.update_asset(sample_asset["id"], title="Updated Title p30"))
        assert result["title"] == "Updated Title p30"

    def test_update_tags(self, live_mcp, sample_asset):
        result = json.loads(mcp_mod.update_asset(sample_asset["id"], tags="p30 updated"))
        assert "updated" in result["tags"]
        assert "p30" in result["tags"]

    def test_update_public(self, live_mcp, sample_asset):
        result = json.loads(mcp_mod.update_asset(sample_asset["id"], public=True))
        assert result["public"] is True
        result2 = json.loads(mcp_mod.update_asset(sample_asset["id"], public=False))
        assert result2["public"] is False

    def test_update_reflects_in_meta(self, live_mcp, sample_asset):
        mcp_mod.update_asset(sample_asset["id"], title="Reflect Check p30")
        meta = json.loads(mcp_mod.get_asset_meta(sample_asset["id"]))
        assert meta["title"] == "Reflect Check p30"

    def test_update_no_fields_errors(self, live_mcp, sample_asset):
        result = json.loads(mcp_mod.update_asset(sample_asset["id"]))
        assert "error" in result

    def test_update_nonexistent_asset_errors(self, live_mcp):
        result = json.loads(mcp_mod.update_asset("00000000-0000-0000-0000-000000000000", title="x"))
        assert "error" in result or "status" in result

    def test_clear_title(self, live_mcp, sample_asset):
        result = json.loads(mcp_mod.update_asset(sample_asset["id"], title=""))
        assert result["title"] is None or result["title"] == ""
