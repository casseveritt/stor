"""Phase 6: SSO / OAuth2-OIDC tests.

Google exchange is mocked via app.state.sso_exchange_google so no real
network calls are made. The tests verify the state lifecycle, identity
resolution, token issuance, and that the issued token works end-to-end.
"""
import uuid
import time

import pytest

from server import sso as sso_module
from server.sso import SSOError, UnknownIdentityError

TEST_CLIENT_ID = "test_google_client_id"
TEST_CLIENT_SECRET = "test_google_client_secret"

ALICE_EMAIL = "alice@sso-test.com"
ALICE_IDENTITY = f"google:{ALICE_EMAIL}"


def _mock_exchange(email: str):
    return lambda code, ruri, cid, cs: {"email": email, "sub": "uid-" + email}


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def sso_client(client):
    client.app.state.sso_config = {
        "google_client_id": TEST_CLIENT_ID,
        "google_client_secret": TEST_CLIENT_SECRET,
    }
    client.app.state.sso_exchange_google = _mock_exchange(ALICE_EMAIL)
    yield client
    client.app.state.sso_config = {"google_client_id": None, "google_client_secret": None}
    client.app.state.sso_exchange_google = sso_module.exchange_google_code


@pytest.fixture(scope="module")
def alice(client):
    db = client.app.state.db
    recipient_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO recipients (id, identity, display_name) VALUES (?, ?, ?)",
        (recipient_id, ALICE_IDENTITY, "Alice SSO"),
    )
    db.commit()
    return {"recipient_id": recipient_id, "identity": ALICE_IDENTITY}


@pytest.fixture(scope="module")
def bob_with_alias(client):
    """Bob has a primary identity plus an alias in identity_mappings."""
    db = client.app.state.db
    recipient_id = str(uuid.uuid4())
    primary = "google:bob-primary@example.com"
    alias = "google:bob-alias@gmail.com"
    db.execute(
        "INSERT INTO recipients (id, identity, display_name) VALUES (?, ?, ?)",
        (recipient_id, primary, "Bob SSO"),
    )
    db.execute(
        "INSERT INTO identity_mappings (identity, recipient_id) VALUES (?, ?)",
        (alias, recipient_id),
    )
    db.commit()
    return {"recipient_id": recipient_id, "primary": primary, "alias": alias}


# ── login endpoint ────────────────────────────────────────────────────────────

class TestLoginEndpoint:
    def test_returns_google_auth_url(self, sso_client, alice):
        r = sso_client.get("/auth/login?provider=google")
        assert r.status_code == 200
        data = r.json()
        assert "accounts.google.com" in data["auth_url"]
        assert TEST_CLIENT_ID in data["auth_url"]
        assert "state" in data

    def test_state_is_single_use_in_db(self, sso_client, alice):
        r = sso_client.get("/auth/login?provider=google")
        state = r.json()["state"]
        db = sso_client.app.state.db
        row = db.execute("SELECT state FROM sso_states WHERE state = ?", (state,)).fetchone()
        assert row is not None

    def test_unknown_provider_rejected(self, sso_client):
        r = sso_client.get("/auth/login?provider=github")
        assert r.status_code == 400

    def test_unconfigured_provider_503(self, client):
        prev = client.app.state.sso_config
        client.app.state.sso_config = {"google_client_id": None, "google_client_secret": None}
        try:
            r = client.get("/auth/login?provider=google")
            assert r.status_code == 503
        finally:
            client.app.state.sso_config = prev


# ── callback endpoint ─────────────────────────────────────────────────────────

class TestCallbackEndpoint:
    def _get_state(self, sso_client):
        return sso_client.get("/auth/login?provider=google").json()["state"]

    def _token_from_redirect(self, r) -> str:
        """Extract the token from a /#token=<token> redirect Location header."""
        loc = r.headers["location"]
        assert "token=" in loc, f"No token in redirect: {loc}"
        return loc.split("token=", 1)[1]

    def test_issues_token_for_known_identity(self, sso_client, alice):
        state = self._get_state(sso_client)
        r = sso_client.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)
        assert r.status_code == 302
        token = self._token_from_redirect(r)
        assert token

    def test_issued_token_accepted_on_feed(self, sso_client, alice):
        state = self._get_state(sso_client)
        r = sso_client.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)
        token = self._token_from_redirect(r)
        r = sso_client.get("/feed", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    def test_unknown_identity_returns_403(self, sso_client, alice):
        prev = sso_client.app.state.sso_exchange_google
        sso_client.app.state.sso_exchange_google = _mock_exchange("nobody@unknown.com")
        try:
            state = self._get_state(sso_client)
            r = sso_client.get(f"/auth/callback?code=fake&state={state}")
            assert r.status_code == 403
        finally:
            sso_client.app.state.sso_exchange_google = prev

    def test_invalid_state_returns_400(self, sso_client):
        r = sso_client.get("/auth/callback?code=fake&state=totallyinvalid")
        assert r.status_code == 400

    def test_state_is_consumed_after_use(self, sso_client, alice):
        state = self._get_state(sso_client)
        r = sso_client.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)
        assert r.status_code == 302
        # Second use of same state must fail
        r = sso_client.get(f"/auth/callback?code=fake&state={state}")
        assert r.status_code == 400

    def test_expired_state_returns_400(self, sso_client, alice):
        db = sso_client.app.state.db
        state = sso_module.generate_state(db, "google", ttl=-1)
        r = sso_client.get(f"/auth/callback?code=fake&state={state}")
        assert r.status_code == 400


# ── identity mapping ──────────────────────────────────────────────────────────

class TestIdentityMapping:
    def test_alias_resolves_to_correct_recipient(self, sso_client, bob_with_alias):
        prev = sso_client.app.state.sso_exchange_google
        sso_client.app.state.sso_exchange_google = _mock_exchange("bob-alias@gmail.com")
        try:
            state = sso_client.get("/auth/login?provider=google").json()["state"]
            r = sso_client.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)
            assert r.status_code == 302
            token = r.headers["location"].split("token=", 1)[1]
            db = sso_client.app.state.db
            row = db.execute("SELECT recipient_id FROM tokens WHERE id = ?", (token,)).fetchone()
            assert row[0] == bob_with_alias["recipient_id"]
        finally:
            sso_client.app.state.sso_exchange_google = prev

    def test_primary_identity_still_resolves(self, sso_client, bob_with_alias):
        prev = sso_client.app.state.sso_exchange_google
        sso_client.app.state.sso_exchange_google = _mock_exchange("bob-primary@example.com")
        try:
            state = sso_client.get("/auth/login?provider=google").json()["state"]
            r = sso_client.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)
            assert r.status_code == 302
        finally:
            sso_client.app.state.sso_exchange_google = prev


# ── sso module unit tests ─────────────────────────────────────────────────────

class TestSSOModule:
    def test_google_auth_url_shape(self):
        url = sso_module.google_auth_url("my_id", "https://node/cb", "st8")
        assert "accounts.google.com" in url
        assert "my_id" in url
        assert "st8" in url
        assert "email" in url

    def test_normalize_google_identity(self):
        assert sso_module.normalize_google_identity({"email": "x@y.com"}) == "google:x@y.com"

    def test_normalize_missing_email_raises(self):
        with pytest.raises(SSOError):
            sso_module.normalize_google_identity({"sub": "123"})

    def test_resolve_via_direct_match(self, client, alice):
        db = client.app.state.db
        assert sso_module.resolve_identity(db, alice["identity"]) == alice["recipient_id"]

    def test_resolve_via_mapping(self, client, bob_with_alias):
        db = client.app.state.db
        assert sso_module.resolve_identity(db, bob_with_alias["alias"]) == bob_with_alias["recipient_id"]

    def test_resolve_unknown_returns_none(self, client):
        assert sso_module.resolve_identity(client.app.state.db, "google:ghost@nowhere.com") is None

    def test_complete_callback_unknown_raises(self, client):
        with pytest.raises(UnknownIdentityError):
            sso_module.complete_callback(client.app.state.db, "google:ghost@nowhere.com")

    def test_state_is_single_use(self, client):
        db = client.app.state.db
        state = sso_module.generate_state(db, "google")
        assert sso_module.consume_state(db, state) == ("google", "")
        with pytest.raises(SSOError):
            sso_module.consume_state(db, state)
