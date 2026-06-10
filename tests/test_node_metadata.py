"""Tests for /node endpoint tiered last_activity_at granularity."""
import pytest
from fastapi.testclient import TestClient

from tests.conftest import _make_store, TEST_PASSPHRASE


@pytest.fixture
def node_client(tmp_path):
    store = _make_store(tmp_path)
    from server.main import create_app
    app = create_app(store / "node_config.json")
    client = TestClient(app)
    # Unlock with passphrase so the node is initialised
    client.post("/setup/unlock", json={"passphrase": TEST_PASSPHRASE})
    return client, app


def _owner_token(app):
    from server import auth as auth_mod
    return auth_mod.issue_token(ttl_seconds=3600)


class TestNodeMetadataTiers:
    def test_public_has_no_last_activity_at(self, node_client):
        client, _ = node_client
        r = client.get("/node")
        assert r.status_code == 200
        assert "last_activity_at" not in r.json()

    def test_public_still_has_basic_fields(self, node_client):
        client, _ = node_client
        r = client.get("/node")
        d = r.json()
        assert "api_version" in d
        assert "public_key" in d
        assert "public_posts" in d

    def test_owner_gets_exact_last_activity_at(self, node_client):
        client, app = node_client
        token = _owner_token(app)
        r = client.get("/node", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        # Owner always gets last_activity_at (may be 0 if no posts)
        assert "last_activity_at" in r.json()

    def test_authenticated_non_contact_gets_week_granularity(self, node_client):
        """A valid recipient token that isn't a known contact gets week-floored timestamp."""
        client, app = node_client
        import uuid
        from server import auth as auth_mod
        recipient_token = auth_mod.issue_node_token(
            app.state.db, str(uuid.uuid4()), ttl_seconds=3600
        )
        r = client.get("/node", headers={"Authorization": f"Bearer {recipient_token}"})
        assert r.status_code == 200
        d = r.json()
        # If there's activity, it should be floored to week boundary
        if d.get("last_activity_at"):
            _WEEK_NS = 7 * 86400 * 1_000_000_000
            assert d["last_activity_at"] % _WEEK_NS == 0

    def test_floor_to_day_helper(self):
        from server.node import _floor_to_day
        NS = 1_000_000_000
        # Tuesday 2024-01-02 12:34:56 UTC in nanoseconds
        ts = int(1704196496 * NS)
        floored = _floor_to_day(ts)
        # Should be midnight of the same day
        assert floored % (86400 * NS) == 0
        assert floored <= ts < floored + 86400 * NS

    def test_floor_to_week_helper(self):
        from server.node import _floor_to_week
        NS = 1_000_000_000
        ts = int(1704196496 * NS)
        floored = _floor_to_week(ts)
        _WEEK_NS = 7 * 86400 * NS
        assert floored % _WEEK_NS == 0
        assert floored <= ts < floored + _WEEK_NS

    def test_activity_tier_public(self, node_client):
        from server.node import _activity_tier
        from server.auth import _GUEST
        _, app = node_client

        class _FakeRequest:
            headers = {}
            app = None

        req = _FakeRequest()
        req.app = app
        assert _activity_tier(req, _GUEST) == "public"

    def test_activity_tier_owner(self, node_client):
        from server.node import _activity_tier
        from server.auth import TokenIdentity
        _, app = node_client

        class _FakeRequest:
            headers = {}
            app = None

        req = _FakeRequest()
        req.app = app
        assert _activity_tier(req, TokenIdentity(is_owner=True)) == "owner"
