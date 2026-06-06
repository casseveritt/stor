"""Tests for SSE-based real-time event delivery.

Streaming tests require a real HTTP server because both Starlette's TestClient
and httpx.ASGITransport block until the ASGI app completes — which never happens
for infinite SSE streams.  The `live_server` fixture spins up a real uvicorn
instance in a background thread for those tests.  Non-streaming tests use the
normal TestClient.
"""
import asyncio
import json
import os
import socket
import threading
import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient


# ── shared helpers ────────────────────────────────────────────────────────────

def _mock_server(role="owner", ok=True, json_body=None):
    resp = MagicMock()
    resp.is_success = ok
    resp.status_code = 200 if ok else 502
    resp.json.return_value = json_body or {"role": role, "identity": "google:owner@test.com"}
    resp.text = ""
    hc = MagicMock()
    hc.get = AsyncMock(return_value=resp)
    hc.post = AsyncMock(return_value=resp)
    hc.__aenter__ = AsyncMock(return_value=hc)
    hc.__aexit__ = AsyncMock(return_value=None)
    return hc


@pytest.fixture
def app_and_path(tmp_path):
    from client.config import ClientConfig
    from client.main import create_app
    cfg_path = tmp_path / "client_config.json"
    ClientConfig(own_server="https://node.example.com").save(cfg_path)
    app = create_app(cfg_path)
    return app, cfg_path


@pytest.fixture
def authed(app_and_path):
    app, cfg_path = app_and_path
    client = TestClient(app, raise_server_exceptions=False)
    with patch("client.main.httpx.AsyncClient", return_value=_mock_server("owner")):
        r = client.post("/client/session", json={"token": "tok"})
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    return client, headers, cfg_path, app


@pytest.fixture
def live_server(app_and_path):
    """Start a real uvicorn server in a background thread; yield its base URL."""
    import uvicorn

    app, _ = app_and_path

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    server.install_signal_handlers = lambda: None

    t = threading.Thread(target=server.run, daemon=True)
    t.start()

    # Wait for server to be ready
    base = f"http://127.0.0.1:{port}"
    for _ in range(30):
        try:
            httpx.get(f"{base}/setup/status", timeout=0.5)
            break
        except Exception:
            time.sleep(0.1)

    yield base

    server.should_exit = True
    t.join(timeout=3.0)


@pytest.fixture
def live_authed(live_server, app_and_path):
    """Return (base_url, auth_headers) for a live server session."""
    app, _ = app_and_path
    base = live_server
    # Establish a session via the TestClient (same app instance)
    sync_client = TestClient(app, raise_server_exceptions=False)
    with patch("client.main.httpx.AsyncClient", return_value=_mock_server("owner")):
        r = sync_client.post("/client/session", json={"token": "tok"})
    assert r.status_code == 200
    token = r.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    return base, headers


# ── SSE streaming helper ──────────────────────────────────────────────────────

def _open_sse(base_url, headers, collected, ready, stop_after=1, timeout=5.0):
    """Open SSE stream in a background thread against a live server."""
    def _run():
        try:
            with httpx.stream("GET", f"{base_url}/api/events",
                              headers=headers, timeout=timeout) as r:
                buf = ""
                for chunk in r.iter_text():
                    buf += chunk
                    while "\n\n" in buf:
                        block, buf = buf.split("\n\n", 1)
                        for line in block.splitlines():
                            if line.startswith("data:"):
                                try:
                                    collected.append(json.loads(line[5:].strip()))
                                except Exception:
                                    pass
                        if len(collected) >= stop_after:
                            ready.set()
                            return
        except Exception:
            pass
        ready.set()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


# ── auth gating (no live server needed) ──────────────────────────────────────

class TestSSEAuth:
    def test_events_requires_auth(self, app_and_path):
        app, _ = app_and_path
        client = TestClient(app, raise_server_exceptions=False)
        r = client.get("/api/events")
        assert r.status_code == 401

    def test_events_wrong_token_401(self, app_and_path):
        app, _ = app_and_path
        client = TestClient(app, raise_server_exceptions=False)
        r = client.get("/api/events", headers={"Authorization": "Bearer bad"})
        assert r.status_code == 401


# ── streaming delivery (live server) ─────────────────────────────────────────

class TestSSEPostUpdates:
    def test_post_update_delivered_via_sse(self, live_authed):
        base, headers = live_authed
        events, ready = [], threading.Event()
        t = _open_sse(base, headers, events, ready, stop_after=1)
        time.sleep(0.2)

        r = httpx.post(f"{base}/notifications/post-update", json={
            "post_id": "post-abc", "event": "comment", "data": {}
        })
        assert r.status_code == 204

        ready.wait(timeout=3.0)
        t.join(timeout=1.0)

        assert len(events) >= 1
        assert events[0]["post_id"] == "post-abc"
        assert events[0]["event"] == "comment"

    def test_multiple_updates_all_delivered(self, live_authed):
        base, headers = live_authed
        events, ready = [], threading.Event()
        t = _open_sse(base, headers, events, ready, stop_after=3)
        time.sleep(0.2)

        for i in range(3):
            httpx.post(f"{base}/notifications/post-update", json={
                "post_id": f"post-{i}", "event": "comment", "data": {}
            })

        ready.wait(timeout=3.0)
        t.join(timeout=1.0)

        post_ids = {e["post_id"] for e in events}
        assert {"post-0", "post-1", "post-2"}.issubset(post_ids)


class TestSSEDmUpdates:
    def test_dm_update_delivered_via_sse(self, live_authed):
        base, headers = live_authed
        events, ready = [], threading.Event()
        t = _open_sse(base, headers, events, ready, stop_after=1)
        time.sleep(0.2)

        r = httpx.post(f"{base}/notifications/dm-update", json={
            "thread_id": "thread-xyz", "type": "dm"
        })
        assert r.status_code == 204

        ready.wait(timeout=3.0)
        t.join(timeout=1.0)

        assert len(events) >= 1
        assert events[0]["type"] == "dm"
        assert events[0]["thread_id"] == "thread-xyz"


# ── fallback queue (no SSE connected) ────────────────────────────────────────

class TestFallbackQueue:
    def test_subscribed_updates_returns_queued_post_events(self, authed):
        client, headers, _, _ = authed
        client.post("/notifications/post-update", json={
            "post_id": "post-fallback", "event": "reaction", "data": {}
        })
        with patch("client.main.httpx.AsyncClient", return_value=_mock_server(
            json_body={"updates": []}
        )):
            r = client.get("/api/subscribed-updates", headers=headers)
        assert r.status_code == 200
        post_ids = [u.get("post_id") for u in r.json()["updates"]]
        assert "post-fallback" in post_ids

    def test_dm_update_in_fallback_queue(self, authed):
        client, headers, _, _ = authed
        client.post("/notifications/dm-update", json={
            "thread_id": "thread-fallback", "type": "dm"
        })
        with patch("client.main.httpx.AsyncClient", return_value=_mock_server(
            json_body={"updates": []}
        )):
            r = client.get("/api/subscribed-updates", headers=headers)
        assert r.status_code == 200
        types = [u.get("type") for u in r.json()["updates"]]
        assert "dm" in types


# ── server-side SSE (me→them direction) ──────────────────────────────────────

@pytest.fixture
def server_live(tmp_path):
    """Spin up a real server (server/main.py) with internal_token configured."""
    import uvicorn
    from tests.conftest import _make_store, TEST_PASSPHRASE

    store = _make_store(tmp_path)
    cfg_path = store / "node_config.json"
    cfg_data = json.loads(cfg_path.read_text())
    internal_tok = "test-server-internal-token"
    cfg_data["internal_token"] = internal_tok
    cfg_path.write_text(json.dumps(cfg_data))

    # Capture the server's event loop so tests can inject events thread-safely.
    _loop_holder: list[asyncio.AbstractEventLoop] = [None]

    old_pp = os.environ.get("CONTACC_PASSPHRASE_UNSECURE")
    os.environ["CONTACC_PASSPHRASE_UNSECURE"] = TEST_PASSPHRASE
    try:
        from server.main import create_app
        app = create_app(cfg_path)
    finally:
        if old_pp is None:
            os.environ.pop("CONTACC_PASSPHRASE_UNSECURE", None)
        else:
            os.environ["CONTACC_PASSPHRASE_UNSECURE"] = old_pp

    @app.on_event("startup")
    async def _grab_loop():
        _loop_holder[0] = asyncio.get_event_loop()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    server.install_signal_handlers = lambda: None

    t = threading.Thread(target=server.run, daemon=True)
    t.start()

    base = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            httpx.get(f"{base}/health", timeout=0.5)
            break
        except Exception:
            time.sleep(0.1)

    yield base, internal_tok, _loop_holder

    server.should_exit = True
    t.join(timeout=3.0)


def _open_server_sse(base_url, headers, collected, ready, stop_after=1, timeout=5.0):
    """Open server's /dm/events SSE in a background thread."""
    def _run():
        try:
            with httpx.stream("GET", f"{base_url}/dm/events",
                              headers=headers, timeout=timeout) as r:
                buf = ""
                for chunk in r.iter_text():
                    buf += chunk
                    while "\n\n" in buf:
                        block, buf = buf.split("\n\n", 1)
                        for line in block.splitlines():
                            if line.startswith("data:"):
                                try:
                                    collected.append(json.loads(line[5:].strip()))
                                except Exception:
                                    pass
                        if len(collected) >= stop_after:
                            ready.set()
                            return
        except Exception:
            pass
        ready.set()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


class TestServerSSE:
    def test_dm_events_requires_auth(self, server_live):
        # Server middleware returns 403 when internal_token is configured but not provided
        base, _, _ = server_live
        r = httpx.get(f"{base}/dm/events", timeout=2.0)
        assert r.status_code == 403

    def test_dm_events_wrong_token_403(self, server_live):
        base, _, _ = server_live
        r = httpx.get(f"{base}/dm/events",
                      headers={"x-contacc-internal": "wrong"}, timeout=2.0)
        assert r.status_code == 403

    def test_dm_events_delivers_update(self, server_live):
        import server.dm as _dm
        base, tok, loop_holder = server_live
        headers = {"x-contacc-internal": tok}
        events, ready = [], threading.Event()

        t = _open_server_sse(base, headers, events, ready, stop_after=1)
        time.sleep(0.3)  # wait for SSE connection to register

        loop = loop_holder[0]
        assert loop is not None, "Server loop not captured"
        loop.call_soon_threadsafe(
            _dm._push_dm_update, "new_message", {"thread_id": "svr-test-thread"}
        )

        ready.wait(timeout=3.0)
        t.join(timeout=1.0)

        assert len(events) >= 1
        assert events[0]["type"] == "dm"
        assert events[0]["thread_id"] == "svr-test-thread"
