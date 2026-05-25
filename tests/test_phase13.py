"""Phase 13: Title search, tag enumeration, asset version history, recipient feed preview."""
import base64
import uuid

import pytest

from server.auth import issue_token, issue_recipient_token, setup as auth_setup
from server.crypto import derive_master_key, decrypt_bytes
from tests.conftest import TEST_PASSPHRASE, TEST_SALT, TEST_ARGON2


# ── helpers ───────────────────────────────────────────────────────────────────

def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _publish(client, owner_token, content=b"data", media_type="text/plain",
             title=None, tags="[]"):
    data = {"tags": tags}
    if title:
        data["title"] = title
    r = client.post(
        "/assets",
        files={"file": ("f", content, media_type)},
        data=data,
        headers=_auth(owner_token),
    )
    assert r.status_code == 201
    return r.json()["id"]


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
def p13_world(client, owner_token):
    r = client.post(
        "/recipients",
        json={"identity": "google:p13@test.com"},
        headers=_auth(owner_token),
    )
    recipient_id = r.json()["id"]
    db = client.app.state.db
    token = issue_recipient_token(db, recipient_id, ttl_seconds=3600)
    return {"recipient_id": recipient_id, "token": token}


# ── title search ──────────────────────────────────────────────────────────────

class TestSearch:
    def test_search_finds_title_match(self, client, owner_token):
        uid = uuid.uuid4().hex[:8]
        asset_id = _publish(client, owner_token, title=f"Sunset-{uid}")
        r = client.get("/feed", params={"q": f"Sunset-{uid}"}, headers=_auth(owner_token))
        ids = [a["id"] for a in r.json()["assets"]]
        assert asset_id in ids

    def test_search_excludes_non_match(self, client, owner_token):
        uid = uuid.uuid4().hex[:8]
        asset_id = _publish(client, owner_token, title=f"Mountain-{uid}")
        r = client.get("/feed", params={"q": "zzz-no-match-zzz"}, headers=_auth(owner_token))
        ids = [a["id"] for a in r.json()["assets"]]
        assert asset_id not in ids

    def test_search_is_case_insensitive(self, client, owner_token):
        uid = uuid.uuid4().hex[:8]
        asset_id = _publish(client, owner_token, title=f"CamelCase-{uid}")
        r = client.get("/feed", params={"q": f"camelcase-{uid}"}, headers=_auth(owner_token))
        ids = [a["id"] for a in r.json()["assets"]]
        assert asset_id in ids

    def test_search_partial_match(self, client, owner_token):
        uid = uuid.uuid4().hex[:8]
        asset_id = _publish(client, owner_token, title=f"BeachPhoto-{uid}")
        r = client.get("/feed", params={"q": f"Beach"}, headers=_auth(owner_token))
        ids = [a["id"] for a in r.json()["assets"]]
        assert asset_id in ids

    def test_search_combined_with_media_type(self, client, owner_token):
        uid = uuid.uuid4().hex[:8]
        img_id = _publish(client, owner_token, content=b"img", media_type="image/png",
                          title=f"CombinedImg-{uid}")
        txt_id = _publish(client, owner_token, content=b"txt", media_type="text/plain",
                          title=f"CombinedTxt-{uid}")
        r = client.get("/feed", params={"q": f"Combined", "media_type": "image/png"},
                       headers=_auth(owner_token))
        ids = [a["id"] for a in r.json()["assets"]]
        assert img_id in ids
        assert txt_id not in ids

    def test_search_combined_with_tags(self, client, owner_token):
        uid = uuid.uuid4().hex[:8]
        tagged_id = _publish(client, owner_token, title=f"TagSearch-{uid}",
                              tags=f'["p13-{uid}"]')
        untagged_id = _publish(client, owner_token, title=f"TagSearch-{uid}",
                                tags='[]')
        r = client.get("/feed", params={"q": f"TagSearch-{uid}", "tags": f"p13-{uid}"},
                       headers=_auth(owner_token))
        ids = [a["id"] for a in r.json()["assets"]]
        assert tagged_id in ids
        assert untagged_id not in ids

    def test_search_acl_scoped_for_recipient(self, client, owner_token, p13_world):
        uid = uuid.uuid4().hex[:8]
        acl_id = _publish(client, owner_token, title=f"AclSearch-{uid}")
        no_acl_id = _publish(client, owner_token, title=f"AclSearch-{uid}")
        client.put(f"/assets/{acl_id}/acl",
                   json={"add": [p13_world["recipient_id"]]}, headers=_auth(owner_token))
        r = client.get("/feed", params={"q": f"AclSearch-{uid}"},
                       headers=_auth(p13_world["token"]))
        ids = [a["id"] for a in r.json()["assets"]]
        assert acl_id in ids
        assert no_acl_id not in ids

    def test_no_q_returns_all_accessible(self, client, owner_token):
        r = client.get("/feed", headers=_auth(owner_token))
        assert r.status_code == 200
        assert isinstance(r.json()["assets"], list)

    def test_search_response_echoes_q(self, client, owner_token):
        r = client.get("/feed", params={"q": "test"}, headers=_auth(owner_token))
        assert r.json().get("q") == "test"


# ── tag enumeration ───────────────────────────────────────────────────────────

class TestTags:
    def test_list_tags_returns_published_tags(self, client, owner_token):
        uid = uuid.uuid4().hex[:8]
        tag = f"p13tag-{uid}"
        _publish(client, owner_token, tags=f'["{tag}"]')
        r = client.get("/tags", headers=_auth(owner_token))
        assert r.status_code == 200
        tag_names = [t["tag"] for t in r.json()["tags"]]
        assert tag in tag_names

    def test_tag_count_reflects_asset_count(self, client, owner_token):
        uid = uuid.uuid4().hex[:8]
        tag = f"countable-{uid}"
        _publish(client, owner_token, tags=f'["{tag}"]')
        _publish(client, owner_token, tags=f'["{tag}"]')
        r = client.get("/tags", headers=_auth(owner_token))
        found = next((t for t in r.json()["tags"] if t["tag"] == tag), None)
        assert found is not None
        assert found["count"] == 2

    def test_deleted_asset_excluded_from_tag_count(self, client, owner_token):
        uid = uuid.uuid4().hex[:8]
        tag = f"deletedtag-{uid}"
        asset_id = _publish(client, owner_token, tags=f'["{tag}"]')
        r_before = client.get("/tags", headers=_auth(owner_token))
        found_before = next((t for t in r_before.json()["tags"] if t["tag"] == tag), None)
        assert found_before is not None

        client.delete(f"/assets/{asset_id}", headers=_auth(owner_token))
        r_after = client.get("/tags", headers=_auth(owner_token))
        found_after = next((t for t in r_after.json()["tags"] if t["tag"] == tag), None)
        assert found_after is None

    def test_tags_sorted_by_count_descending(self, client, owner_token):
        uid = uuid.uuid4().hex[:8]
        rare = f"rare-{uid}"
        common = f"common-{uid}"
        _publish(client, owner_token, tags=f'["{rare}", "{common}"]')
        _publish(client, owner_token, tags=f'["{common}"]')
        r = client.get("/tags", headers=_auth(owner_token))
        tags = r.json()["tags"]
        rare_idx = next(i for i, t in enumerate(tags) if t["tag"] == rare)
        common_idx = next(i for i, t in enumerate(tags) if t["tag"] == common)
        assert common_idx < rare_idx  # common has higher count, comes first

    def test_non_owner_denied(self, client, p13_world):
        r = client.get("/tags", headers=_auth(p13_world["token"]))
        assert r.status_code == 403

    def test_tag_response_shape(self, client, owner_token):
        uid = uuid.uuid4().hex[:8]
        _publish(client, owner_token, tags=f'["shape-{uid}"]')
        r = client.get("/tags", headers=_auth(owner_token))
        assert "tags" in r.json()
        if r.json()["tags"]:
            t = r.json()["tags"][0]
            assert "tag" in t
            assert "count" in t


# ── asset version history ─────────────────────────────────────────────────────

class TestAssetHistory:
    def test_single_asset_history(self, client, owner_token):
        asset_id = _publish(client, owner_token, content=b"sole")
        r = client.get(f"/assets/{asset_id}/history", headers=_auth(owner_token))
        assert r.status_code == 200
        assert r.json()["count"] == 1
        assert r.json()["history"][0]["id"] == asset_id
        assert r.json()["history"][0]["is_current"] is True

    def test_history_follows_successor(self, client, owner_token):
        v1_id = _publish(client, owner_token, content=b"v1", title="v1")
        v2_id = _publish(client, owner_token, content=b"v2", title="v2")
        # Link v2 as successor of v1 via publish with predecessor
        r = client.post(
            "/assets",
            files={"file": ("v2.txt", b"v2-linked", "text/plain")},
            data={"predecessor": v1_id, "title": "v2-linked"},
            headers=_auth(owner_token),
        )
        v2_linked_id = r.json()["id"]

        r = client.get(f"/assets/{v2_linked_id}/history", headers=_auth(owner_token))
        history_ids = [h["id"] for h in r.json()["history"]]
        assert v1_id in history_ids
        assert v2_linked_id in history_ids
        assert history_ids.index(v1_id) < history_ids.index(v2_linked_id)

    def test_history_from_predecessor_reaches_successor(self, client, owner_token):
        r1 = client.post("/assets", files={"file": ("a.txt", b"a", "text/plain")},
                         data={"title": "hist-v1"}, headers=_auth(owner_token))
        v1_id = r1.json()["id"]
        r2 = client.post("/assets", files={"file": ("b.txt", b"b", "text/plain")},
                         data={"predecessor": v1_id, "title": "hist-v2"},
                         headers=_auth(owner_token))
        v2_id = r2.json()["id"]

        # Requesting v1 should show both v1 and v2
        r = client.get(f"/assets/{v1_id}/history", headers=_auth(owner_token))
        history_ids = [h["id"] for h in r.json()["history"]]
        assert v1_id in history_ids
        assert v2_id in history_ids

    def test_history_marks_is_current_correctly(self, client, owner_token):
        r1 = client.post("/assets", files={"file": ("x.txt", b"x", "text/plain")},
                         data={"title": "current-v1"}, headers=_auth(owner_token))
        v1_id = r1.json()["id"]
        r2 = client.post("/assets", files={"file": ("y.txt", b"y", "text/plain")},
                         data={"predecessor": v1_id, "title": "current-v2"},
                         headers=_auth(owner_token))
        v2_id = r2.json()["id"]

        r = client.get(f"/assets/{v2_id}/history", headers=_auth(owner_token))
        by_id = {h["id"]: h for h in r.json()["history"]}
        assert by_id[v2_id]["is_current"] is True
        assert by_id[v1_id]["is_current"] is False

    def test_history_includes_deleted_versions(self, client, owner_token):
        r1 = client.post("/assets", files={"file": ("d.txt", b"d", "text/plain")},
                         data={"title": "del-v1"}, headers=_auth(owner_token))
        v1_id = r1.json()["id"]
        r2 = client.post("/assets", files={"file": ("e.txt", b"e", "text/plain")},
                         data={"predecessor": v1_id, "title": "del-v2"},
                         headers=_auth(owner_token))
        v2_id = r2.json()["id"]
        # Delete v1 (it has a successor so is now superseded AND deleted)
        client.delete(f"/assets/{v1_id}", headers=_auth(owner_token))

        # Requesting v2 history should still show v1 (deleted but in chain)
        r = client.get(f"/assets/{v2_id}/history", headers=_auth(owner_token))
        history_ids = [h["id"] for h in r.json()["history"]]
        assert v1_id in history_ids
        deleted_entry = next(h for h in r.json()["history"] if h["id"] == v1_id)
        assert deleted_entry["deleted"] is True

    def test_history_unknown_asset_404(self, client, owner_token):
        r = client.get(f"/assets/{uuid.uuid4()}/history", headers=_auth(owner_token))
        assert r.status_code == 404

    def test_history_requires_acl(self, client, owner_token, p13_world):
        asset_id = _publish(client, owner_token, content=b"private-hist")
        r = client.get(f"/assets/{asset_id}/history", headers=_auth(p13_world["token"]))
        assert r.status_code == 403

    def test_history_accessible_with_acl(self, client, owner_token, p13_world):
        asset_id = _publish(client, owner_token, content=b"acl-hist")
        client.put(f"/assets/{asset_id}/acl",
                   json={"add": [p13_world["recipient_id"]]}, headers=_auth(owner_token))
        r = client.get(f"/assets/{asset_id}/history", headers=_auth(p13_world["token"]))
        assert r.status_code == 200


# ── recipient feed preview ────────────────────────────────────────────────────

class TestRecipientFeed:
    def test_recipient_feed_shows_acl_assets(self, client, owner_token, p13_world):
        asset_id = _publish(client, owner_token, content=b"rf-acl")
        client.put(f"/assets/{asset_id}/acl",
                   json={"add": [p13_world["recipient_id"]]}, headers=_auth(owner_token))
        r = client.get(f"/recipients/{p13_world['recipient_id']}/feed",
                       headers=_auth(owner_token))
        assert r.status_code == 200
        ids = [a["id"] for a in r.json()["assets"]]
        assert asset_id in ids

    def test_recipient_feed_excludes_no_acl_assets(self, client, owner_token, p13_world):
        asset_id = _publish(client, owner_token, content=b"rf-no-acl")
        # deliberately not granting ACL
        r = client.get(f"/recipients/{p13_world['recipient_id']}/feed",
                       headers=_auth(owner_token))
        ids = [a["id"] for a in r.json()["assets"]]
        assert asset_id not in ids

    def test_recipient_feed_response_shape(self, client, owner_token, p13_world):
        r = client.get(f"/recipients/{p13_world['recipient_id']}/feed",
                       headers=_auth(owner_token))
        data = r.json()
        assert data["recipient_id"] == p13_world["recipient_id"]
        assert data["recipient_identity"] == "google:p13@test.com"
        assert "assets" in data
        assert "until" in data

    def test_recipient_feed_excludes_superseded_by_default(self, client, owner_token, p13_world):
        r1 = client.post("/assets", files={"file": ("s.txt", b"s1", "text/plain")},
                         headers=_auth(owner_token))
        v1_id = r1.json()["id"]
        r2 = client.post("/assets", files={"file": ("s2.txt", b"s2", "text/plain")},
                         data={"predecessor": v1_id}, headers=_auth(owner_token))
        v2_id = r2.json()["id"]
        for aid in [v1_id, v2_id]:
            client.put(f"/assets/{aid}/acl",
                       json={"add": [p13_world["recipient_id"]]}, headers=_auth(owner_token))
        r = client.get(f"/recipients/{p13_world['recipient_id']}/feed",
                       headers=_auth(owner_token))
        ids = [a["id"] for a in r.json()["assets"]]
        assert v1_id not in ids  # superseded, excluded by default
        assert v2_id in ids

    def test_recipient_feed_unknown_recipient_404(self, client, owner_token):
        r = client.get(f"/recipients/{uuid.uuid4()}/feed", headers=_auth(owner_token))
        assert r.status_code == 404

    def test_recipient_feed_non_owner_denied(self, client, p13_world):
        r = client.get(f"/recipients/{p13_world['recipient_id']}/feed",
                       headers=_auth(p13_world["token"]))
        assert r.status_code == 403

    def test_recipient_feed_supports_pagination_cursor(self, client, owner_token, p13_world):
        # Grant 3 assets to p13 recipient
        ids = []
        for i in range(3):
            aid = _publish(client, owner_token, content=f"page-{i}".encode())
            client.put(f"/assets/{aid}/acl",
                       json={"add": [p13_world["recipient_id"]]}, headers=_auth(owner_token))
            ids.append(aid)

        r1 = client.get(f"/recipients/{p13_world['recipient_id']}/feed",
                        params={"limit": 1}, headers=_auth(owner_token))
        assert len(r1.json()["assets"]) == 1
        assert "next_cursor" in r1.json()

        r2 = client.get(f"/recipients/{p13_world['recipient_id']}/feed",
                        params={"limit": 1, "cursor": r1.json()["next_cursor"]},
                        headers=_auth(owner_token))
        assert len(r2.json()["assets"]) == 1
        assert r2.json()["assets"][0]["id"] != r1.json()["assets"][0]["id"]