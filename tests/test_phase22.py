"""Phase 22: posts UI — merged tags, post search, SPA post-centric checks."""
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


@pytest.fixture(scope="module")
def tagged_post(client, owner_token):
    r = client.post(
        "/posts",
        data={"body": "ui-tag-test post", "tags": json.dumps(["ui-phase22"])},
        headers=_auth(owner_token),
    )
    assert r.status_code == 201
    return r.json()


@pytest.fixture(scope="module")
def tagged_asset(client, owner_token):
    r = client.post(
        "/assets",
        files={"file": ("p22.txt", b"phase22 asset", "text/plain")},
        data={"title": "P22 Asset", "tags": json.dumps(["asset-phase22"])},
        headers=_auth(owner_token),
    )
    assert r.status_code == 201
    return r.json()


# ── merged tags endpoint ──────────────────────────────────────────────────

class TestMergedTags:
    def test_post_tags_appear(self, client, owner_token, tagged_post):
        r = client.get("/tags", headers=_auth(owner_token))
        tag_names = {t["tag"] for t in r.json()["tags"]}
        assert "ui-phase22" in tag_names

    def test_asset_tags_still_appear(self, client, owner_token, tagged_asset):
        r = client.get("/tags", headers=_auth(owner_token))
        tag_names = {t["tag"] for t in r.json()["tags"]}
        assert "asset-phase22" in tag_names

    def test_counts_are_positive(self, client, owner_token, tagged_post):
        r = client.get("/tags", headers=_auth(owner_token))
        for t in r.json()["tags"]:
            assert t["count"] > 0

    def test_sorted_by_count_desc(self, client, owner_token):
        r = client.get("/tags", headers=_auth(owner_token))
        counts = [t["count"] for t in r.json()["tags"]]
        assert counts == sorted(counts, reverse=True)


# ── post search ───────────────────────────────────────────────────────────

class TestPostSearch:
    def test_q_matches_body(self, client, owner_token):
        client.post("/posts", data={"body": "unique-xyzzy-search-phrase"}, headers=_auth(owner_token))
        r = client.get("/posts", params={"q": "unique-xyzzy-search-phrase"}, headers=_auth(owner_token))
        assert r.status_code == 200
        posts = r.json()["posts"]
        assert len(posts) >= 1
        assert all("unique-xyzzy-search-phrase" in p["body"] for p in posts)

    def test_q_excludes_non_match(self, client, owner_token):
        r = client.get("/posts", params={"q": "zzzqqq-no-match-ever-99"}, headers=_auth(owner_token))
        assert r.json()["posts"] == []

    def test_q_and_tags_combined(self, client, owner_token, tagged_post):
        r = client.get(
            "/posts",
            params={"q": "ui-tag-test", "tags": "ui-phase22"},
            headers=_auth(owner_token),
        )
        assert r.status_code == 200
        posts = r.json()["posts"]
        assert any(p["id"] == tagged_post["id"] for p in posts)


# ── SPA shell ─────────────────────────────────────────────────────────────

class TestSPAPostUI:
    def test_root_serves_html(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]

    def test_compose_button_present(self, client):
        r = client.get("/")
        assert "compose-btn" in r.text or "New post" in r.text

    def test_posts_endpoint_referenced(self, client):
        r = client.get("/")
        assert "/posts" in r.text

    def test_post_comment_endpoint_referenced(self, client):
        r = client.get("/")
        assert "/posts/" in r.text and "/comments" in r.text

    def test_asset_ref_pattern_in_js(self, client):
        r = client.get("/")
        assert "asset:" in r.text

    def test_sidebar_present(self, client):
        r = client.get("/")
        assert "sidebar" in r.text

    def test_no_upload_btn(self, client):
        # old upload button gone, replaced by compose
        r = client.get("/")
        assert "upload-btn" not in r.text
