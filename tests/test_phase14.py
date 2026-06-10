"""Phase 14: Minimal web UI — static SPA, token-via-query-param, OAuth redirect."""
import base64
import io
import uuid

import pytest
from PIL import Image

from server import sso as sso_module
from server.auth import issue_token, setup as auth_setup
from server.crypto import derive_master_key, decrypt_bytes
from tests.conftest import TEST_PASSPHRASE, TEST_SALT, TEST_ARGON2

TEST_CLIENT_ID = "test_google_client_id"
TEST_CLIENT_SECRET = "test_google_client_secret"
TEST_EMAIL = "ui-user@example.com"
TEST_IDENTITY = f"google:{TEST_EMAIL}"


def _mock_exchange(email: str):
    return lambda code, ruri, cid, cs: {"email": email, "sub": "uid-" + email}


def _tiny_png() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (8, 8), color=(100, 150, 200)).save(buf, format="PNG")
    return buf.getvalue()


# ── helpers ───────────────────────────────────────────────────────────────────

def _auth(token):
    return {"Authorization": f"Bearer {token}"}


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
def sso_client(client):
    client.app.state.sso_config = {
        "google_client_id": TEST_CLIENT_ID,
        "google_client_secret": TEST_CLIENT_SECRET,
    }
    client.app.state.sso_exchange_google = _mock_exchange(TEST_EMAIL)
    yield client
    client.app.state.sso_config = {"google_client_id": None, "google_client_secret": None}
    client.app.state.sso_exchange_google = sso_module.exchange_google_code


@pytest.fixture(scope="module")
def ui_user(client):
    db = client.app.state.db
    node_id = str(uuid.uuid4())
    db.execute(
        "INSERT OR REPLACE INTO identity_mappings (identity, node_id) VALUES (?, ?)",
        (TEST_IDENTITY, node_id),
    )
    db.commit()
    return {"recipient_id": node_id, "identity": TEST_IDENTITY}


@pytest.fixture(scope="module")
def image_asset(client, owner_token):
    r = client.post(
        "/assets",
        files={"file": ("photo.png", _tiny_png(), "image/png")},
        data={"title": "UI test image"},
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert r.status_code == 201
    return r.json()


# ── root endpoint ─────────────────────────────────────────────────────────────

class TestRootEndpoint:
    def test_get_root_returns_html(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]

    def test_html_contains_app_name(self, client):
        r = client.get("/")
        assert b"contacc" in r.content

    def test_html_has_login_elements(self, client):
        r = client.get("/")
        assert b"login" in r.content.lower()


# ── token-via-query-param ─────────────────────────────────────────────────────

class TestQueryParamAuth:
    def test_feed_via_query_param(self, client, owner_token):
        r = client.get(f"/feed?token={owner_token}")
        assert r.status_code == 200
        assert "assets" in r.json()

    def test_asset_fetch_via_query_param(self, client, owner_token, image_asset):
        r = client.get(f"/assets/{image_asset['id']}?token={owner_token}")
        assert r.status_code == 200
        assert r.headers["content-type"] == "image/png"

    def test_thumbnail_via_query_param(self, client, owner_token, image_asset):
        r = client.get(f"/assets/{image_asset['id']}/thumb?token={owner_token}")
        assert r.status_code == 200
        assert "image/" in r.headers["content-type"]

    def test_asset_meta_via_query_param(self, client, owner_token, image_asset):
        r = client.get(f"/assets/{image_asset['id']}/meta?token={owner_token}")
        assert r.status_code == 200
        assert r.json()["id"] == image_asset["id"]

    def test_invalid_token_query_param_returns_401(self, client, image_asset):
        r = client.get(f"/assets/{image_asset['id']}?token=notavalidtoken")
        assert r.status_code == 401

    def test_missing_token_returns_403_for_private_asset(self, client, image_asset):
        r = client.get(f"/assets/{image_asset['id']}")
        assert r.status_code == 403

    def test_header_takes_precedence_over_query_param(self, client, owner_token, image_asset):
        r = client.get(
            f"/assets/{image_asset['id']}?token=badtoken",
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert r.status_code == 200

    def test_recipient_token_via_query_param(self, client, owner_token, image_asset, ui_user):
        # Grant ACL, issue recipient token, fetch via query param
        r_acl = client.put(
            f"/assets/{image_asset['id']}/acl",
            json={"add": [ui_user["recipient_id"]]},
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert r_acl.status_code == 200
        from server.auth import issue_node_token
        db = client.app.state.db
        recip_token = issue_node_token(db, ui_user["recipient_id"])
        r = client.get(f"/assets/{image_asset['id']}?token={recip_token}")
        assert r.status_code == 200


# ── OAuth callback redirect ───────────────────────────────────────────────────

class TestOAuthCallbackRedirect:
    def _get_state(self, sso_client):
        return sso_client.get("/auth/login?provider=google").json()["state"]

    def test_callback_redirects_302(self, sso_client, ui_user):
        state = self._get_state(sso_client)
        r = sso_client.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)
        assert r.status_code == 302

    def test_callback_location_contains_token(self, sso_client, ui_user):
        state = self._get_state(sso_client)
        r = sso_client.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)
        loc = r.headers["location"]
        assert "token=" in loc

    def test_callback_token_is_usable(self, sso_client, ui_user):
        state = self._get_state(sso_client)
        r = sso_client.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)
        token = r.headers["location"].split("token=", 1)[1]
        r2 = sso_client.get("/feed", headers={"Authorization": f"Bearer {token}"})
        assert r2.status_code == 200

    def test_callback_redirects_to_root_fragment(self, sso_client, ui_user):
        state = self._get_state(sso_client)
        r = sso_client.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)
        loc = r.headers["location"]
        assert loc.startswith("/")
