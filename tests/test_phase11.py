"""Phase 11: Access logging and node statistics."""
import base64
import io
import time
import uuid

import pytest

from server.auth import issue_token, issue_recipient_token, setup as auth_setup
from server.crypto import derive_master_key, decrypt_bytes
from tests.conftest import TEST_PASSPHRASE, TEST_SALT, TEST_ARGON2


# ── helpers ───────────────────────────────────────────────────────────────────

def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _publish(client, owner_token, content=b"data", media_type="text/plain"):
    r = client.post(
        "/assets",
        files={"file": ("f", content, media_type)},
        headers=_auth(owner_token),
    )
    assert r.status_code == 201
    return r.json()["id"]


def _jpeg_bytes():
    from PIL import Image
    img = Image.new("RGB", (64, 64), color=(80, 120, 200))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return buf.getvalue()


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
def p11_world(client, owner_token):
    r = client.post(
        "/recipients",
        json={"identity": "google:p11@test.com"},
        headers=_auth(owner_token),
    )
    recipient_id = r.json()["id"]
    db = client.app.state.db
    token = issue_recipient_token(db, recipient_id, ttl_seconds=3600)
    return {"recipient_id": recipient_id, "token": token}


# ── access logging ────────────────────────────────────────────────────────────

class TestAccessLogging:
    def _asset_with_access(self, client, owner_token, p11_world, content=b"log-test"):
        asset_id = _publish(client, owner_token, content=content)
        client.put(
            f"/assets/{asset_id}/acl",
            json={"add": [p11_world["recipient_id"]]},
            headers=_auth(owner_token),
        )
        return asset_id

    def test_fetch_asset_logged(self, client, owner_token, p11_world):
        asset_id = self._asset_with_access(client, owner_token, p11_world, b"log-fetch")
        client.get(f"/assets/{asset_id}", headers=_auth(p11_world["token"]))
        r = client.get(f"/assets/{asset_id}/access-log", headers=_auth(owner_token))
        endpoints = [e["endpoint"] for e in r.json()["entries"]]
        assert "fetch_asset" in endpoints

    def test_fetch_meta_logged(self, client, owner_token, p11_world):
        asset_id = self._asset_with_access(client, owner_token, p11_world, b"log-meta")
        client.get(f"/assets/{asset_id}/meta", headers=_auth(p11_world["token"]))
        r = client.get(f"/assets/{asset_id}/access-log", headers=_auth(owner_token))
        endpoints = [e["endpoint"] for e in r.json()["entries"]]
        assert "fetch_meta" in endpoints

    def test_fetch_thumbnail_logged(self, client, owner_token, p11_world):
        jpeg = _jpeg_bytes()
        asset_id = _publish(client, owner_token, content=jpeg, media_type="image/jpeg")
        client.put(
            f"/assets/{asset_id}/acl",
            json={"add": [p11_world["recipient_id"]]},
            headers=_auth(owner_token),
        )
        client.get(f"/assets/{asset_id}/thumb", headers=_auth(p11_world["token"]))
        r = client.get(f"/assets/{asset_id}/access-log", headers=_auth(owner_token))
        endpoints = [e["endpoint"] for e in r.json()["entries"]]
        assert "fetch_thumbnail" in endpoints

    def test_fetch_comments_logged(self, client, owner_token, p11_world):
        asset_id = self._asset_with_access(client, owner_token, p11_world, b"log-comments")
        client.get(f"/assets/{asset_id}/comments", headers=_auth(p11_world["token"]))
        r = client.get(f"/assets/{asset_id}/access-log", headers=_auth(owner_token))
        endpoints = [e["endpoint"] for e in r.json()["entries"]]
        assert "fetch_comments" in endpoints

    def test_owner_access_not_logged(self, client, owner_token):
        asset_id = _publish(client, owner_token, b"log-owner")
        client.get(f"/assets/{asset_id}", headers=_auth(owner_token))
        r = client.get(f"/assets/{asset_id}/access-log", headers=_auth(owner_token))
        assert r.json()["total"] == 0

    def test_log_entry_has_recipient_id_and_identity(self, client, owner_token, p11_world):
        asset_id = self._asset_with_access(client, owner_token, p11_world, b"log-identity")
        client.get(f"/assets/{asset_id}", headers=_auth(p11_world["token"]))
        r = client.get(f"/assets/{asset_id}/access-log", headers=_auth(owner_token))
        entry = next(e for e in r.json()["entries"] if e["endpoint"] == "fetch_asset")
        assert entry["recipient_id"] == p11_world["recipient_id"]
        assert entry["recipient_identity"] == "google:p11@test.com"
        assert entry["share_identity"] is None

    def test_share_token_access_logged_with_share_identity(self, client, owner_token):
        asset_id = _publish(client, owner_token, b"log-share")
        r = client.post(
            "/share-tokens",
            json={"identity": "ext:shared-user", "asset_ids": [asset_id]},
            headers=_auth(owner_token),
        )
        share_token = r.json()["token"]
        client.get(f"/assets/{asset_id}", headers=_auth(share_token))
        r2 = client.get(f"/assets/{asset_id}/access-log", headers=_auth(owner_token))
        share_entries = [e for e in r2.json()["entries"] if e["share_identity"] is not None]
        assert len(share_entries) >= 1
        assert share_entries[0]["share_identity"] == "ext:shared-user"
        assert share_entries[0]["recipient_id"] is None

    def test_global_access_log_includes_all_entries(self, client, owner_token, p11_world):
        asset_id = self._asset_with_access(client, owner_token, p11_world, b"log-global")
        client.get(f"/assets/{asset_id}", headers=_auth(p11_world["token"]))
        r = client.get("/access-log", headers=_auth(owner_token))
        assert r.status_code == 200
        asset_ids = [e["asset_id"] for e in r.json()["entries"]]
        assert asset_id in asset_ids

    def test_access_log_filter_by_asset(self, client, owner_token, p11_world):
        a1 = self._asset_with_access(client, owner_token, p11_world, b"log-filter-a1")
        a2 = self._asset_with_access(client, owner_token, p11_world, b"log-filter-a2")
        client.get(f"/assets/{a1}", headers=_auth(p11_world["token"]))
        client.get(f"/assets/{a2}", headers=_auth(p11_world["token"]))
        r = client.get("/access-log", params={"asset_id": a1}, headers=_auth(owner_token))
        asset_ids = {e["asset_id"] for e in r.json()["entries"]}
        assert a1 in asset_ids
        assert a2 not in asset_ids

    def test_access_log_filter_by_recipient(self, client, owner_token, p11_world):
        asset_id = self._asset_with_access(client, owner_token, p11_world, b"log-filter-r")
        client.get(f"/assets/{asset_id}", headers=_auth(p11_world["token"]))
        r = client.get(
            "/access-log",
            params={"recipient_id": p11_world["recipient_id"]},
            headers=_auth(owner_token),
        )
        assert r.status_code == 200
        recipient_ids = {e["recipient_id"] for e in r.json()["entries"]}
        assert p11_world["recipient_id"] in recipient_ids

    def test_access_log_pagination(self, client, owner_token, p11_world):
        asset_id = self._asset_with_access(client, owner_token, p11_world, b"log-page")
        for _ in range(5):
            client.get(f"/assets/{asset_id}", headers=_auth(p11_world["token"]))
        r1 = client.get(
            f"/assets/{asset_id}/access-log",
            params={"limit": 2, "offset": 0},
            headers=_auth(owner_token),
        )
        r2 = client.get(
            f"/assets/{asset_id}/access-log",
            params={"limit": 2, "offset": 2},
            headers=_auth(owner_token),
        )
        assert len(r1.json()["entries"]) == 2
        ids1 = {e["id"] for e in r1.json()["entries"]}
        ids2 = {e["id"] for e in r2.json()["entries"]}
        assert ids1.isdisjoint(ids2)

    def test_asset_access_log_unknown_asset_404(self, client, owner_token):
        r = client.get(f"/assets/{uuid.uuid4()}/access-log", headers=_auth(owner_token))
        assert r.status_code == 404

    def test_non_owner_cannot_read_access_log(self, client, owner_token, p11_world):
        asset_id = self._asset_with_access(client, owner_token, p11_world, b"log-denied")
        r = client.get(f"/assets/{asset_id}/access-log", headers=_auth(p11_world["token"]))
        assert r.status_code == 403

    def test_access_log_time_filter(self, client, owner_token, p11_world):
        asset_id = self._asset_with_access(client, owner_token, p11_world, b"log-time")
        before = time.time()
        client.get(f"/assets/{asset_id}", headers=_auth(p11_world["token"]))
        r = client.get(
            f"/assets/{asset_id}/access-log",
            params={"since": before},
            headers=_auth(owner_token),
        )
        assert r.json()["total"] >= 1


# ── node statistics ───────────────────────────────────────────────────────────

class TestStats:
    def test_stats_returns_200(self, client, owner_token):
        r = client.get("/stats", headers=_auth(owner_token))
        assert r.status_code == 200

    def test_stats_shape(self, client, owner_token):
        r = client.get("/stats", headers=_auth(owner_token))
        data = r.json()
        assert "assets" in data
        assert "recipients" in data
        assert "tokens" in data
        assert "comments" in data
        assert "access_log" in data
        assert all(k in data["assets"] for k in ("total", "active", "deleted", "total_size_bytes"))

    def test_stats_counts_assets(self, client, owner_token):
        r_before = client.get("/stats", headers=_auth(owner_token)).json()
        _publish(client, owner_token, b"stats-asset")
        r_after = client.get("/stats", headers=_auth(owner_token)).json()
        assert r_after["assets"]["total"] == r_before["assets"]["total"] + 1
        assert r_after["assets"]["active"] == r_before["assets"]["active"] + 1

    def test_stats_deleted_asset_updates_counts(self, client, owner_token):
        asset_id = _publish(client, owner_token, b"stats-del")
        r_before = client.get("/stats", headers=_auth(owner_token)).json()
        client.delete(f"/assets/{asset_id}", headers=_auth(owner_token))
        r_after = client.get("/stats", headers=_auth(owner_token)).json()
        assert r_after["assets"]["deleted"] == r_before["assets"]["deleted"] + 1
        assert r_after["assets"]["active"] == r_before["assets"]["active"] - 1
        assert r_after["assets"]["total"] == r_before["assets"]["total"]

    def test_stats_counts_recipients(self, client, owner_token):
        r_before = client.get("/stats", headers=_auth(owner_token)).json()
        client.post(
            "/recipients",
            json={"identity": f"google:stats-r-{uuid.uuid4()}@test.com"},
            headers=_auth(owner_token),
        )
        r_after = client.get("/stats", headers=_auth(owner_token)).json()
        assert r_after["recipients"]["total"] == r_before["recipients"]["total"] + 1

    def test_stats_total_size_reflects_content(self, client, owner_token):
        r_before = client.get("/stats", headers=_auth(owner_token)).json()
        content = b"x" * 1000
        _publish(client, owner_token, content=content)
        r_after = client.get("/stats", headers=_auth(owner_token)).json()
        assert r_after["assets"]["total_size_bytes"] >= r_before["assets"]["total_size_bytes"] + 1000

    def test_stats_access_log_total_reflects_accesses(self, client, owner_token, p11_world):
        asset_id = _publish(client, owner_token, b"stats-log")
        client.put(
            f"/assets/{asset_id}/acl",
            json={"add": [p11_world["recipient_id"]]},
            headers=_auth(owner_token),
        )
        r_before = client.get("/stats", headers=_auth(owner_token)).json()
        client.get(f"/assets/{asset_id}", headers=_auth(p11_world["token"]))
        r_after = client.get("/stats", headers=_auth(owner_token)).json()
        assert r_after["access_log"]["total"] == r_before["access_log"]["total"] + 1

    def test_stats_non_owner_denied(self, client, owner_token, p11_world):
        r = client.get("/stats", headers=_auth(p11_world["token"]))
        assert r.status_code == 403
