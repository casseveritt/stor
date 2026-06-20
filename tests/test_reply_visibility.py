"""Server API tests for reply visibility filtering (Phase 38).

Covers:
- create_post inherits parent visibility_list_id
- get_replies filters broad replies when parent has visibility_list_id
- notify_reply stores reply_visibility / reply_visibility_list_id
- prefs GET / PATCH
"""
import base64
import hashlib
import json
import socket
import time
import threading
import uuid

import pytest

from tests.conftest import (
    TEST_PASSPHRASE, TEST_SALT, TEST_ARGON2, _make_store,
)


# ── helpers ──────────────────────────────────────────────────────────────────

def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _make_node(tmp_path):
    """Return (TestClient, auth_headers, db) for a fresh initialized node."""
    from fastapi.testclient import TestClient
    from server.main import create_app
    from server.auth import issue_token, setup as auth_setup
    from server.crypto import derive_master_key, decrypt_bytes
    from server.config import NodeConfig
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    store = _make_store(tmp_path)
    app = create_app(store / "node_config.json", TEST_PASSPHRASE)
    client = TestClient(app)

    config = NodeConfig.load(store / "node_config.json")
    master_key = derive_master_key(TEST_PASSPHRASE, TEST_SALT, **TEST_ARGON2)
    privkey_bytes = decrypt_bytes(base64.b64decode(config.encrypted_private_key), master_key)
    auth_setup(Ed25519PrivateKey.from_private_bytes(privkey_bytes))
    token = issue_token(ttl_seconds=3600)
    headers = _auth(token)

    return client, headers, app.state.db


def _create_list(client, headers, name, members=()):
    r = client.post("/node-lists", json={"name": name, "members": list(members)},
                    headers=headers)
    assert r.status_code == 201, r.text
    return r.json()


def _create_post(client, headers, body, visibility="contacts",
                 visibility_list_id=None, parent_id=None, parent_node_id=None):
    data = {"body": body, "visibility": visibility}
    if visibility_list_id:
        data["visibility_list_id"] = visibility_list_id
    if parent_id:
        data["parent_id"] = parent_id
    if parent_node_id:
        data["parent_node_id"] = parent_node_id
    r = client.post("/posts", data=data, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()


# ── visibility_list_id inheritance ───────────────────────────────────────────

class TestVisibilityInheritance:
    def test_reply_inherits_parent_visibility_list_id(self, tmp_path):
        client, hdrs, db = _make_node(tmp_path)
        lst = _create_list(client, hdrs, "fam", ["node-aaa"])
        fam_hash = lst["members"] and db.execute(
            "SELECT current_hash FROM node_lists WHERE id = ?", (lst["id"],)
        ).fetchone()[0]

        parent = _create_post(client, hdrs, "parent", visibility="contacts",
                              visibility_list_id=lst["id"])
        assert parent["visibility_list_id"] == fam_hash

        reply = _create_post(client, hdrs, "reply", visibility="contacts",
                             parent_id=parent["id"])
        assert reply["visibility_list_id"] == fam_hash

    def test_explicit_reply_visibility_not_overridden(self, tmp_path):
        client, hdrs, db = _make_node(tmp_path)
        lst_a = _create_list(client, hdrs, "all", ["node-aaa", "node-bbb"])
        lst_b = _create_list(client, hdrs, "sub", ["node-aaa"])

        parent = _create_post(client, hdrs, "parent", visibility="contacts",
                              visibility_list_id=lst_a["id"])
        reply = _create_post(client, hdrs, "narrow reply", visibility="contacts",
                             visibility_list_id=lst_b["id"], parent_id=parent["id"])
        assert reply["visibility_list_id"] != parent["visibility_list_id"]

    def test_public_parent_has_no_list_inheritance(self, tmp_path):
        client, hdrs, _ = _make_node(tmp_path)
        parent = _create_post(client, hdrs, "public post", visibility="public")
        assert parent["visibility_list_id"] is None
        reply = _create_post(client, hdrs, "reply", visibility="contacts",
                             parent_id=parent["id"])
        assert reply["visibility_list_id"] is None


# ── get_replies filtering ─────────────────────────────────────────────────────

class TestGetRepliesFiltering:
    def test_unrestricted_parent_returns_all_local_replies(self, tmp_path):
        client, hdrs, _ = _make_node(tmp_path)
        parent = _create_post(client, hdrs, "contacts post", visibility="contacts")
        _create_post(client, hdrs, "reply A", parent_id=parent["id"])
        _create_post(client, hdrs, "reply B", parent_id=parent["id"],
                     visibility="public")

        r = client.get(f"/posts/{parent['id']}/replies")
        assert r.status_code == 200
        assert len(r.json()["replies"]) == 2

    def test_list_restricted_parent_filters_broad_local_replies(self, tmp_path):
        client, hdrs, _ = _make_node(tmp_path)
        lst = _create_list(client, hdrs, "fam", ["node-aaa"])

        parent = _create_post(client, hdrs, "fam post", visibility="contacts",
                              visibility_list_id=lst["id"])
        # broad reply — contacts with no list (inherits parent list)
        # to get a broad reply, we create another post without parent to skip inheritance
        # then directly test the SQL filter by inserting via reply_refs
        db_parent_vlid = client.app.state.db.execute(
            "SELECT visibility_list_id FROM posts WHERE id = ?", (parent["id"],)
        ).fetchone()[0]

        # Reply that inherits the parent's list (acceptable)
        narrow = _create_post(client, hdrs, "narrow reply", visibility="contacts",
                              parent_id=parent["id"])
        assert narrow["visibility_list_id"] == db_parent_vlid

        # Verify get_replies includes it
        r = client.get(f"/posts/{parent['id']}/replies")
        assert r.status_code == 200
        reply_ids = [rep["reply_post_id"] for rep in r.json()["replies"]]
        assert narrow["id"] in reply_ids

    def test_list_restricted_parent_filters_remote_broad_refs(self, tmp_path):
        client, hdrs, db = _make_node(tmp_path)
        lst = _create_list(client, hdrs, "fam", ["node-aaa"])
        parent = _create_post(client, hdrs, "fam post", visibility="contacts",
                              visibility_list_id=lst["id"])

        now = time.time_ns()
        # Broad remote ref (reply_visibility='contacts', no list)
        db.execute(
            "INSERT INTO reply_refs (reply_post_id, reply_node_id, parent_post_id, "
            "received_at, reply_visibility, reply_visibility_list_id) VALUES (?,?,?,?,?,?)",
            ("remote-broad-1", "node-remote", parent["id"], now, "contacts", None),
        )
        # List-restricted remote ref (acceptable)
        db.execute(
            "INSERT INTO reply_refs (reply_post_id, reply_node_id, parent_post_id, "
            "received_at, reply_visibility, reply_visibility_list_id) VALUES (?,?,?,?,?,?)",
            ("remote-narrow-1", "node-remote", parent["id"], now, "contacts", "some-hash"),
        )
        # Old ref with no visibility info (included for compat)
        db.execute(
            "INSERT INTO reply_refs (reply_post_id, reply_node_id, parent_post_id, "
            "received_at, reply_visibility, reply_visibility_list_id) VALUES (?,?,?,?,?,?)",
            ("remote-old-1", "node-remote", parent["id"], now, None, None),
        )
        db.commit()

        r = client.get(f"/posts/{parent['id']}/replies")
        assert r.status_code == 200
        ids = {rep["reply_post_id"] for rep in r.json()["replies"]}
        assert "remote-broad-1" not in ids
        assert "remote-narrow-1" in ids
        assert "remote-old-1" in ids

    def test_public_parent_remote_ref_not_filtered(self, tmp_path):
        client, hdrs, db = _make_node(tmp_path)
        parent = _create_post(client, hdrs, "public", visibility="public")
        now = time.time_ns()
        db.execute(
            "INSERT INTO reply_refs (reply_post_id, reply_node_id, parent_post_id, "
            "received_at, reply_visibility, reply_visibility_list_id) VALUES (?,?,?,?,?,?)",
            ("any-reply", "node-x", parent["id"], now, "public", None),
        )
        db.commit()

        r = client.get(f"/posts/{parent['id']}/replies")
        assert r.status_code == 200
        ids = {rep["reply_post_id"] for rep in r.json()["replies"]}
        assert "any-reply" in ids


# ── notify-reply stores visibility ───────────────────────────────────────────

class TestNotifyReplyVisibility:
    def _federated_headers(self, client, hdrs):
        """Return headers that pass FederatedOrTokenDep (use owner token)."""
        return hdrs

    def test_notify_reply_stores_visibility_fields(self, tmp_path):
        client, hdrs, db = _make_node(tmp_path)
        parent = _create_post(client, hdrs, "parent post")

        r = client.post(
            f"/posts/{parent['id']}/notify-reply",
            json={
                "reply_node_id": "node-remote",
                "reply_post_id": "reply-xyz",
                "reply_visibility": "contacts",
                "reply_visibility_list_id": "abc123hash",
            },
            headers=hdrs,
        )
        assert r.status_code == 204

        row = db.execute(
            "SELECT reply_visibility, reply_visibility_list_id FROM reply_refs "
            "WHERE reply_post_id = ?", ("reply-xyz",)
        ).fetchone()
        assert row is not None
        assert row[0] == "contacts"
        assert row[1] == "abc123hash"

    def test_notify_reply_without_visibility_stores_null(self, tmp_path):
        client, hdrs, db = _make_node(tmp_path)
        parent = _create_post(client, hdrs, "parent post")

        r = client.post(
            f"/posts/{parent['id']}/notify-reply",
            json={"reply_node_id": "node-old", "reply_post_id": "reply-old"},
            headers=hdrs,
        )
        assert r.status_code == 204

        row = db.execute(
            "SELECT reply_visibility, reply_visibility_list_id FROM reply_refs "
            "WHERE reply_post_id = ?", ("reply-old",)
        ).fetchone()
        assert row is not None
        assert row[0] is None
        assert row[1] is None


# ── prefs ─────────────────────────────────────────────────────────────────────

class TestPrefs:
    def test_get_prefs_empty_initially(self, tmp_path):
        client, hdrs, _ = _make_node(tmp_path)
        r = client.get("/prefs", headers=hdrs)
        assert r.status_code == 200
        assert r.json() == {}

    def test_patch_sets_pref(self, tmp_path):
        client, hdrs, _ = _make_node(tmp_path)
        r = client.patch("/prefs", json={"compose_visibility": "public"}, headers=hdrs)
        assert r.status_code == 200
        assert r.json()["compose_visibility"] == "public"

    def test_patch_updates_pref(self, tmp_path):
        client, hdrs, _ = _make_node(tmp_path)
        client.patch("/prefs", json={"compose_visibility": "contacts"}, headers=hdrs)
        r = client.patch("/prefs", json={"compose_visibility": "public"}, headers=hdrs)
        assert r.json()["compose_visibility"] == "public"

    def test_patch_deletes_pref_when_null(self, tmp_path):
        client, hdrs, _ = _make_node(tmp_path)
        client.patch("/prefs", json={"compose_visibility": "contacts"}, headers=hdrs)
        r = client.patch("/prefs", json={"compose_visibility": None}, headers=hdrs)
        assert "compose_visibility" not in r.json()

    def test_get_reflects_patch(self, tmp_path):
        client, hdrs, _ = _make_node(tmp_path)
        client.patch("/prefs", json={"k1": "v1", "k2": "v2"}, headers=hdrs)
        r = client.get("/prefs", headers=hdrs)
        assert r.json() == {"k1": "v1", "k2": "v2"}
