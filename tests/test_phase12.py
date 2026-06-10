"""Phase 12: Edit request management via API, per-recipient stats, import tool."""
import base64
import uuid
from pathlib import Path

import pytest

from server.auth import issue_token, issue_node_token, setup as auth_setup
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


def _post_comment(client, token, asset_id, body):
    r = client.post(
        f"/assets/{asset_id}/comments",
        json={"body": body},
        headers=_auth(token),
    )
    assert r.status_code == 201
    return r.json()["id"]


def _request_edit(client, token, asset_id, comment_id, new_body=None):
    payload = {} if new_body is None else {"new_body": new_body}
    r = client.post(
        f"/assets/{asset_id}/comments/{comment_id}/edit_request",
        json=payload,
        headers=_auth(token),
    )
    assert r.status_code == 202
    return r.json()["request_id"]


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
def p12_world(client, owner_token):
    r = client.post(
        "/recipients",
        json={"identity": "google:p12@test.com"},
        headers=_auth(owner_token),
    )
    recipient_id = r.json()["id"]
    db = client.app.state.db
    token = issue_node_token(db, recipient_id, ttl_seconds=3600)
    return {"recipient_id": recipient_id, "token": token}


# ── edit request management via API ──────────────────────────────────────────

class TestEditRequestManagement:
    def _setup_request(self, client, owner_token, p12_world, body="original", new_body="edited"):
        asset_id = _publish(client, owner_token)
        client.put(
            f"/assets/{asset_id}/acl",
            json={"add": [p12_world["recipient_id"]]},
            headers=_auth(owner_token),
        )
        comment_id = _post_comment(client, p12_world["token"], asset_id, body)
        request_id = _request_edit(client, p12_world["token"], asset_id, comment_id, new_body)
        return asset_id, comment_id, request_id

    def test_list_edit_requests_shows_pending(self, client, owner_token, p12_world):
        _, _, request_id = self._setup_request(client, owner_token, p12_world, "list-orig", "list-edit")
        r = client.get("/edit-requests", headers=_auth(owner_token))
        assert r.status_code == 200
        ids = [req["id"] for req in r.json()["requests"]]
        assert request_id in ids

    def test_list_edit_requests_shape(self, client, owner_token, p12_world):
        _, _, request_id = self._setup_request(client, owner_token, p12_world, "shape-orig", "shape-edit")
        r = client.get("/edit-requests", headers=_auth(owner_token))
        req = next(req for req in r.json()["requests"] if req["id"] == request_id)
        for field in ("id", "comment_id", "asset_id", "original_body", "new_body",
                      "action", "status", "created_at", "requester_recipient_id",
                      "requester_identity"):
            assert field in req
        assert req["action"] == "edit"
        assert req["status"] == "pending"
        assert req["requester_identity"] == "google:p12@test.com"

    def test_list_deletion_requests_show_action_delete(self, client, owner_token, p12_world):
        asset_id = _publish(client, owner_token)
        client.put(f"/assets/{asset_id}/acl", json={"add": [p12_world["recipient_id"]]}, headers=_auth(owner_token))
        comment_id = _post_comment(client, p12_world["token"], asset_id, "delete me")
        request_id = _request_edit(client, p12_world["token"], asset_id, comment_id, new_body=None)
        r = client.get("/edit-requests", headers=_auth(owner_token))
        req = next(req for req in r.json()["requests"] if req["id"] == request_id)
        assert req["action"] == "delete"
        assert req["new_body"] is None

    def test_filter_by_asset_id(self, client, owner_token, p12_world):
        a1, _, r1 = self._setup_request(client, owner_token, p12_world, "a1-orig", "a1-edit")
        a2, _, r2 = self._setup_request(client, owner_token, p12_world, "a2-orig", "a2-edit")
        r = client.get("/edit-requests", params={"asset_id": a1}, headers=_auth(owner_token))
        ids = [req["id"] for req in r.json()["requests"]]
        assert r1 in ids
        assert r2 not in ids

    def test_filter_by_status(self, client, owner_token, p12_world):
        _, _, request_id = self._setup_request(client, owner_token, p12_world, "status-orig", "status-edit")
        client.post(f"/edit-requests/{request_id}/approve", headers=_auth(owner_token))
        r = client.get("/edit-requests", params={"status": "approved"}, headers=_auth(owner_token))
        ids = [req["id"] for req in r.json()["requests"]]
        assert request_id in ids
        r2 = client.get("/edit-requests", params={"status": "pending"}, headers=_auth(owner_token))
        ids2 = [req["id"] for req in r2.json()["requests"]]
        assert request_id not in ids2

    def test_approve_edit_via_api(self, client, owner_token, p12_world):
        asset_id, comment_id, request_id = self._setup_request(
            client, owner_token, p12_world, "approve-orig", "approve-edit"
        )
        r = client.post(f"/edit-requests/{request_id}/approve", headers=_auth(owner_token))
        assert r.status_code == 200
        assert r.json()["status"] == "approved"
        # New version should appear in comments
        r2 = client.get(f"/assets/{asset_id}/comments", headers=_auth(owner_token))
        bodies = [c["body"] for c in r2.json()["comments"] if not c["deleted"]]
        assert "approve-edit" in bodies

    def test_reject_edit_via_api(self, client, owner_token, p12_world):
        asset_id, comment_id, request_id = self._setup_request(
            client, owner_token, p12_world, "reject-orig", "reject-edit"
        )
        r = client.post(f"/edit-requests/{request_id}/reject", headers=_auth(owner_token))
        assert r.status_code == 200
        assert r.json()["status"] == "rejected"
        # Original comment should be unchanged
        r2 = client.get(f"/assets/{asset_id}/comments", headers=_auth(owner_token))
        bodies = [c["body"] for c in r2.json()["comments"] if not c["deleted"]]
        assert "reject-orig" in bodies
        assert "reject-edit" not in bodies

    def test_approve_deletion_via_api(self, client, owner_token, p12_world):
        asset_id = _publish(client, owner_token)
        client.put(f"/assets/{asset_id}/acl", json={"add": [p12_world["recipient_id"]]}, headers=_auth(owner_token))
        comment_id = _post_comment(client, p12_world["token"], asset_id, "tombstone me")
        request_id = _request_edit(client, p12_world["token"], asset_id, comment_id)
        client.post(f"/edit-requests/{request_id}/approve", headers=_auth(owner_token))
        r = client.get(f"/assets/{asset_id}/comments", headers=_auth(owner_token))
        tombstone = next(c for c in r.json()["comments"] if c["id"] == comment_id)
        assert tombstone["deleted"] is True
        assert tombstone["body"] is None

    def test_double_approve_409(self, client, owner_token, p12_world):
        _, _, request_id = self._setup_request(client, owner_token, p12_world, "double-orig", "double-edit")
        client.post(f"/edit-requests/{request_id}/approve", headers=_auth(owner_token))
        r = client.post(f"/edit-requests/{request_id}/approve", headers=_auth(owner_token))
        assert r.status_code == 409

    def test_unknown_request_404(self, client, owner_token):
        r = client.post(f"/edit-requests/{uuid.uuid4()}/approve", headers=_auth(owner_token))
        assert r.status_code == 404

    def test_non_owner_denied(self, client, owner_token, p12_world):
        _, _, request_id = self._setup_request(client, owner_token, p12_world, "deny-orig", "deny-edit")
        r = client.post(f"/edit-requests/{request_id}/approve", headers=_auth(p12_world["token"]))
        assert r.status_code == 403


# ── per-recipient stats ───────────────────────────────────────────────────────

class TestRecipientStats:
    def test_stats_shape(self, client, owner_token, p12_world):
        r = client.get(f"/recipients/{p12_world['recipient_id']}/stats", headers=_auth(owner_token))
        assert r.status_code == 200
        data = r.json()
        for field in ("recipient_id", "identity", "display_name", "acl", "tokens", "access"):
        	assert field in data
        assert "asset_count" in data["acl"]
        assert "total" in data["access"]
        assert "last_accessed_at" in data["access"]
        assert "unique_assets_accessed" in data["access"]
        assert "by_endpoint" in data["access"]

    def test_stats_has_correct_identity(self, client, owner_token, p12_world):
        r = client.get(f"/recipients/{p12_world['recipient_id']}/stats", headers=_auth(owner_token))
        assert r.json()["identity"] == "google:p12@test.com"

    def test_stats_acl_count_reflects_grants(self, client, owner_token, p12_world):
        r_before = client.get(f"/recipients/{p12_world['recipient_id']}/stats", headers=_auth(owner_token)).json()
        asset_id = _publish(client, owner_token)
        client.put(f"/assets/{asset_id}/acl", json={"add": [p12_world["recipient_id"]]}, headers=_auth(owner_token))
        r_after = client.get(f"/recipients/{p12_world['recipient_id']}/stats", headers=_auth(owner_token)).json()
        assert r_after["acl"]["asset_count"] == r_before["acl"]["asset_count"] + 1

    def test_stats_access_total_reflects_fetches(self, client, owner_token, p12_world):
        asset_id = _publish(client, owner_token)
        client.put(f"/assets/{asset_id}/acl", json={"add": [p12_world["recipient_id"]]}, headers=_auth(owner_token))
        r_before = client.get(f"/recipients/{p12_world['recipient_id']}/stats", headers=_auth(owner_token)).json()
        client.get(f"/assets/{asset_id}", headers=_auth(p12_world["token"]))
        r_after = client.get(f"/recipients/{p12_world['recipient_id']}/stats", headers=_auth(owner_token)).json()
        assert r_after["access"]["total"] == r_before["access"]["total"] + 1

    def test_stats_by_endpoint_populated(self, client, owner_token, p12_world):
        asset_id = _publish(client, owner_token)
        client.put(f"/assets/{asset_id}/acl", json={"add": [p12_world["recipient_id"]]}, headers=_auth(owner_token))
        client.get(f"/assets/{asset_id}", headers=_auth(p12_world["token"]))
        client.get(f"/assets/{asset_id}/meta", headers=_auth(p12_world["token"]))
        r = client.get(f"/recipients/{p12_world['recipient_id']}/stats", headers=_auth(owner_token))
        by_ep = r.json()["access"]["by_endpoint"]
        assert "fetch_asset" in by_ep
        assert "fetch_meta" in by_ep

    def test_stats_unknown_recipient_404(self, client, owner_token):
        r = client.get(f"/recipients/{uuid.uuid4()}/stats", headers=_auth(owner_token))
        assert r.status_code == 404

    def test_stats_non_owner_denied(self, client, owner_token, p12_world):
        r = client.get(
            f"/recipients/{p12_world['recipient_id']}/stats",
            headers=_auth(p12_world["token"]),
        )
        assert r.status_code == 403


# ── import tool ───────────────────────────────────────────────────────────────

class TestImportTool:
    def test_import_files_from_directory(self, client, tmp_path, store):
        from server.config import NodeConfig
        from server.crypto import derive_subkeys
        from server.db import open_db, init_schema as _init
        from tools.import_assets import import_directory

        # Get DB and file_key from the running app
        db = client.app.state.db
        file_key = client.app.state.file_key
        store_path = client.app.state.store_path

        # Create test files
        (tmp_path / "photo.jpg").write_bytes(b"\xff\xd8\xff" + b"fake-jpeg" * 10)
        (tmp_path / "note.txt").write_text("Hello from import")
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "doc.txt").write_text("Subdirectory file")

        results = import_directory(db, file_key, store_path, tmp_path, tags=["imported"])
        assert len(results) == 3
        statuses = {r["status"] for r in results}
        assert statuses == {"imported"}

    def test_import_sets_tags(self, client, tmp_path):
        from tools.import_assets import import_directory

        db = client.app.state.db
        file_key = client.app.state.file_key
        store_path = client.app.state.store_path

        content = b"tagged-content-" + uuid.uuid4().bytes
        (tmp_path / "tagged.txt").write_bytes(content)

        results = import_directory(db, file_key, store_path, tmp_path, tags=["tag-a", "tag-b"])
        assert results[0]["status"] == "imported"
        asset_id = results[0]["asset_id"]

        r = client.get(f"/assets/{asset_id}/meta", headers={"Authorization": "Bearer dummy"})
        # Need owner token — fetch from the running app indirectly via DB
        import json as _json
        row = db.execute("SELECT tags FROM assets WHERE id = ?", (asset_id,)).fetchone()
        assert _json.loads(row[0]) == ["tag-a", "tag-b"]

    def test_import_deduplicates_content(self, client, tmp_path):
        from tools.import_assets import import_directory

        db = client.app.state.db
        file_key = client.app.state.file_key
        store_path = client.app.state.store_path

        content = b"dedup-import-" + uuid.uuid4().bytes
        (tmp_path / "a.txt").write_bytes(content)
        (tmp_path / "b.txt").write_bytes(content)  # same content

        results = import_directory(db, file_key, store_path, tmp_path)
        statuses = [r["status"] for r in results]
        assert "imported" in statuses
        assert "duplicate" in statuses

    def test_import_dry_run_does_not_write(self, client, tmp_path):
        from tools.import_assets import import_directory

        db = client.app.state.db
        file_key = client.app.state.file_key
        store_path = client.app.state.store_path

        content = b"dry-run-" + uuid.uuid4().bytes
        (tmp_path / "dry.txt").write_bytes(content)

        results = import_directory(db, file_key, store_path, tmp_path, dry_run=True)
        assert results[0]["status"] == "would_import"

        # Nothing should be in DB
        import hashlib
        h = hashlib.sha256(content).hexdigest()
        row = db.execute("SELECT id FROM assets WHERE content_hash = ?", (h,)).fetchone()
        assert row is None

    def test_import_non_recursive_skips_subdirs(self, client, tmp_path):
        from tools.import_assets import import_directory

        db = client.app.state.db
        file_key = client.app.state.file_key
        store_path = client.app.state.store_path

        content_top = b"top-level-" + uuid.uuid4().bytes
        content_sub = b"sub-level-" + uuid.uuid4().bytes
        (tmp_path / "top.txt").write_bytes(content_top)
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "nested.txt").write_bytes(content_sub)

        results = import_directory(db, file_key, store_path, tmp_path, recursive=False)
        assert len(results) == 1
        assert results[0]["status"] == "imported"

    def test_import_infers_media_type(self, client, tmp_path):
        from tools.import_assets import import_directory

        db = client.app.state.db
        file_key = client.app.state.file_key
        store_path = client.app.state.store_path

        (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + uuid.uuid4().bytes)

        results = import_directory(db, file_key, store_path, tmp_path)
        imported = [r for r in results if r["status"] == "imported"]
        assert len(imported) == 1
        assert imported[0]["media_type"] == "image/png"

    def test_imported_assets_appear_in_feed(self, client, owner_token, tmp_path):
        from tools.import_assets import import_directory

        db = client.app.state.db
        file_key = client.app.state.file_key
        store_path = client.app.state.store_path

        content = b"feed-import-" + uuid.uuid4().bytes
        (tmp_path / "feed.txt").write_bytes(content)

        results = import_directory(db, file_key, store_path, tmp_path)
        asset_id = results[0]["asset_id"]

        r = client.get("/feed", headers=_auth(owner_token))
        ids = [a["id"] for a in r.json()["assets"]]
        assert asset_id in ids

    def test_imported_assets_fetchable(self, client, owner_token, tmp_path):
        from tools.import_assets import import_directory

        db = client.app.state.db
        file_key = client.app.state.file_key
        store_path = client.app.state.store_path

        content = b"fetchable-import-" + uuid.uuid4().bytes
        (tmp_path / "fetch.txt").write_bytes(content)

        results = import_directory(db, file_key, store_path, tmp_path)
        asset_id = results[0]["asset_id"]

        r = client.get(f"/assets/{asset_id}", headers=_auth(owner_token))
        assert r.status_code == 200
        assert r.content == content
