"""Playwright E2E tests for reply compose visibility UI.

The web UI is served by Caddy in production, not by the Python server apps.
For testing we create a minimal stub server that:
  1. Serves web/ static files at /
  2. Stubs the API routes the SPA needs to boot (setup/status, client/session,
     api/config, api/feed, node-lists, api/prefs, node/metadata)
  3. Seeds two test posts (one list-restricted, one public) and one named list

Tests verify:
  - Reply compose on a list-restricted post pre-selects the named list
  - Switching to a different visibility auto-checks "Subset of parent visibility"
  - Unchecking the subset checkbox shows the warning message
  - Reverting to "Parent visibility" hides the subset label
"""
import json
import socket
import threading
import time
import uuid
from pathlib import Path

import pytest

# ── test data ─────────────────────────────────────────────────────────────────

FAM_LIST_ID = str(uuid.uuid4())
FAM_HASH = "deadbeef" * 8          # 64-char fake sha256
FAM_POST_ID = str(uuid.uuid4())
PUB_POST_ID = str(uuid.uuid4())
OWN_SERVER = "http://127.0.0.1"    # placeholder; replaced at startup

_FAM_LIST = {"id": FAM_LIST_ID, "name": "fam", "current_hash": FAM_HASH, "members": []}
_FAM_POST = {
    "id": FAM_POST_ID,
    "body": "Hello fam only!",
    "created_at": 1_700_000_001_000_000_000,
    "tags": [],
    "visibility": "contacts",
    "visibility_list_id": FAM_HASH,
    "is_public": False,
    "reactions": [],
    "reply_count": 0,
    "_server_url": None,  # replaced at startup
}
_PUB_POST = {
    "id": PUB_POST_ID,
    "body": "Hello everyone!",
    "created_at": 1_700_000_000_000_000_000,
    "tags": [],
    "visibility": "public",
    "visibility_list_id": None,
    "is_public": True,
    "reactions": [],
    "reply_count": 0,
    "_server_url": None,
}

# ── stub server ───────────────────────────────────────────────────────────────

def _build_stub_app(base_url: str) -> "FastAPI":
    """Build a minimal FastAPI app that stubs the APIs the SPA needs."""
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    from fastapi.staticfiles import StaticFiles

    web_dir = Path(__file__).parent.parent / "web"
    app = FastAPI()

    fam_post = {**_FAM_POST, "_server_url": base_url}
    pub_post = {**_PUB_POST, "_server_url": base_url}

    @app.get("/setup/status")
    def setup_status():
        return {"state": "running"}

    @app.post("/client/session")
    async def client_session():
        return {"token": "stub-token"}

    @app.get("/api/config")
    def api_config():
        return {
            "own_server": base_url,
            "own_display_name": "Test User",
            "own_handle": "test",
            "own_identity": None,
            "identity_proxy_url": "",
            "provider_url": None,
            "servers": [{"name": "me", "url": base_url, "authenticated": True}],
            "contacts": [],
            "cached_photos": [],
        }

    @app.get("/api/feed")
    def api_feed(request: Request):
        return {"posts": [fam_post, pub_post], "next_cursor": None, "server_status": {}}

    @app.get("/node-lists")
    def node_lists():
        return {"lists": [_FAM_LIST]}

    @app.get("/api/prefs")
    def api_prefs():
        return {}

    @app.get("/node/metadata")
    def node_metadata():
        return {"node_id": "test-node-001", "handle": "test", "public_key": "aaa"}

    @app.get("/node/handle")
    def node_handle():
        return {"handle": "test"}

    # Catch-all for any other API-ish routes so the SPA doesn't throw
    @app.get("/api/{path:path}")
    async def api_fallback(path: str):
        return JSONResponse({}, status_code=404)

    @app.get("/node/{path:path}")
    async def node_fallback(path: str):
        return JSONResponse({}, status_code=404)

    # Serve static files last (fallback)
    app.mount("/", StaticFiles(directory=str(web_dir), html=True))

    return app


# ── live stub server fixture ──────────────────────────────────────────────────

@pytest.fixture(scope="module")
def stub_server():
    """Start the stub server; yield {"url": ..., "ids": {...}}."""
    import uvicorn

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    base = f"http://127.0.0.1:{port}"
    app = _build_stub_app(base)

    cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(cfg)
    server.install_signal_handlers = lambda: None
    t = threading.Thread(target=server.run, daemon=True)
    t.start()

    import httpx
    for _ in range(50):
        try:
            httpx.get(f"{base}/setup/status", timeout=0.5)
            break
        except Exception:
            time.sleep(0.1)

    yield {
        "url": base,
        "fam_list_id": FAM_LIST_ID,
        "fam_hash": FAM_HASH,
        "fam_post_id": FAM_POST_ID,
        "pub_post_id": PUB_POST_ID,
    }

    server.should_exit = True
    t.join(timeout=3.0)


@pytest.fixture
def authed_page(page, stub_server):
    """Playwright page authenticated against the stub server."""
    base = stub_server["url"]
    # Inject token before page load so apiHeaders() picks it up immediately
    page.context.add_init_script(
        "localStorage.setItem('contacc_client_session', 'stub-token')"
    )
    page.goto(base)
    # Wait for feed-view to appear (proves auth + config + feed all resolved)
    page.wait_for_selector("#feed-view:not([hidden])", timeout=15_000)
    # Wait for post cards to render
    page.wait_for_selector(".post-card", timeout=10_000)
    # Wait for _nlRenderSidebar to run (indicates _nlLoadLists completed)
    page.wait_for_selector("#node-lists-sidebar .nl-sidebar-item", timeout=10_000)
    return page, stub_server


# ── helpers ───────────────────────────────────────────────────────────────────

def _open_reply_panel(page, post_id: str):
    """Click the Reply button on a post card and return the reply panel locator."""
    card = page.locator(f'.post-card[data-post-id="{post_id}"]').first
    card.wait_for(state="visible")
    card.locator("button.reaction-add[title='Reply']").click()
    panel = card.locator(".reply-panel")
    panel.wait_for(state="visible")
    return panel


# ── test classes ──────────────────────────────────────────────────────────────

class TestReplyComposeVisibility:
    """Pre-selection behaviour based on the parent post's visibility_list_id."""

    def test_fam_post_defaults_to_fam_list(self, authed_page):
        page, node = authed_page
        panel = _open_reply_panel(page, node["fam_post_id"])
        vis_sel = panel.locator("select.reply-vis-select")
        expected = f"list:{node['fam_list_id']}"
        assert vis_sel.input_value() == expected, (
            f"Expected {expected!r} but got {vis_sel.input_value()!r}"
        )

    def test_public_post_defaults_to_parent_visibility(self, authed_page):
        page, node = authed_page
        panel = _open_reply_panel(page, node["pub_post_id"])
        vis_sel = panel.locator("select.reply-vis-select")
        assert vis_sel.input_value() == "_parent"

    def test_subset_label_hidden_when_parent_selected(self, authed_page):
        page, node = authed_page
        panel = _open_reply_panel(page, node["pub_post_id"])
        subset_label = panel.locator(f"[id^='reply-sub-'][id$='-label']")
        assert subset_label.evaluate("el => el.style.display") == "none"

    def test_subset_label_visible_when_list_preselected(self, authed_page):
        page, node = authed_page
        panel = _open_reply_panel(page, node["fam_post_id"])
        subset_label = panel.locator(f"[id^='reply-sub-'][id$='-label']")
        assert subset_label.evaluate("el => el.style.display") != "none"


class TestSubsetCheckboxAndWarning:
    """Subset checkbox and warning message interactions."""

    def test_changing_visibility_shows_subset_label(self, authed_page):
        page, node = authed_page
        panel = _open_reply_panel(page, node["pub_post_id"])
        vis_sel = panel.locator("select.reply-vis-select")
        subset_label = panel.locator(f"[id^='reply-sub-'][id$='-label']")
        assert subset_label.evaluate("el => el.style.display") == "none"
        vis_sel.select_option("contacts")
        assert subset_label.evaluate("el => el.style.display") != "none"

    def test_changing_visibility_auto_checks_subset(self, authed_page):
        page, node = authed_page
        panel = _open_reply_panel(page, node["pub_post_id"])
        panel.locator("select.reply-vis-select").select_option("contacts")
        subset_cb = panel.locator(f"[id^='reply-sub-']:not([id$='-label'])")
        assert subset_cb.is_checked()

    def test_warning_hidden_while_subset_checked(self, authed_page):
        page, node = authed_page
        panel = _open_reply_panel(page, node["pub_post_id"])
        panel.locator("select.reply-vis-select").select_option("contacts")
        warn = panel.locator(f"[id^='reply-vis-warn-']")
        assert warn.evaluate("el => el.style.display") == "none"

    def test_unchecking_subset_shows_warning(self, authed_page):
        page, node = authed_page
        panel = _open_reply_panel(page, node["pub_post_id"])
        panel.locator("select.reply-vis-select").select_option("contacts")
        subset_cb = panel.locator(f"[id^='reply-sub-']:not([id$='-label'])")
        subset_cb.uncheck()
        warn = panel.locator(f"[id^='reply-vis-warn-']")
        assert warn.evaluate("el => el.style.display") != "none"

    def test_reverting_to_parent_hides_subset_label(self, authed_page):
        page, node = authed_page
        panel = _open_reply_panel(page, node["pub_post_id"])
        vis_sel = panel.locator("select.reply-vis-select")
        vis_sel.select_option("contacts")
        vis_sel.select_option("_parent")
        subset_label = panel.locator(f"[id^='reply-sub-'][id$='-label']")
        assert subset_label.evaluate("el => el.style.display") == "none"

    def test_recheckng_subset_hides_warning(self, authed_page):
        page, node = authed_page
        panel = _open_reply_panel(page, node["pub_post_id"])
        panel.locator("select.reply-vis-select").select_option("contacts")
        subset_cb = panel.locator(f"[id^='reply-sub-']:not([id$='-label'])")
        subset_cb.uncheck()
        subset_cb.check()
        warn = panel.locator(f"[id^='reply-vis-warn-']")
        assert warn.evaluate("el => el.style.display") == "none"
