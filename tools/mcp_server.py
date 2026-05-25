#!/usr/bin/env python3
"""contac MCP server — exposes a personal data node as Claude tools.

Usage:
    python tools/mcp_server.py --node-url https://your.node --token <owner-or-recipient-token>

Or via environment variables:
    CONTAC_NODE_URL=https://your.node CONTAC_TOKEN=<token> python tools/mcp_server.py

Configure in Claude Code (claude_code_settings.json or .claude/settings.json):
    {
      "mcpServers": {
        "contac": {
          "command": "/path/to/.venv/bin/python",
          "args": ["/path/to/tools/mcp_server.py",
                   "--node-url", "https://your.node",
                   "--token", "<token>"]
        }
      }
    }
"""
import json
import os
import sys
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "contac",
    instructions="Personal data node — search assets, read text content, browse feed and tags",
)

# Module-level HTTP client, initialised by _setup() / main()
_http: httpx.Client | None = None


def _setup(node_url: str, token: str, _client: httpx.Client | None = None) -> None:
    """Initialise the module-level HTTP client. _client is injected in tests."""
    global _http
    if _client is not None:
        _http = _client
    else:
        _http = httpx.Client(
            base_url=node_url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}"},
            timeout=30.0,
        )


def _get(path: str, **params) -> dict:
    assert _http is not None, "call _setup() first"
    clean = {k: v for k, v in params.items() if v is not None and v != "" and v != []}
    r = _http.get(path, params=clean)
    r.raise_for_status()
    return r.json()


def _post(path: str, payload: dict) -> dict:
    assert _http is not None, "call _setup() first"
    r = _http.post(path, json=payload)
    r.raise_for_status()
    return r.json()


# ── tools ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def node_info() -> str:
    """Get information about this contac node: its address, public key, and watermark policy."""
    return json.dumps(_get("/node"), indent=2)


@mcp.tool()
def get_feed(limit: int = 20, cursor: str = "") -> str:
    """Get the most recent assets, newest first.

    limit: number of results (1-100).
    cursor: pagination token from a previous call's next_cursor field.

    Returns JSON with {assets: [...], next_cursor?}.
    """
    params = {"limit": max(1, min(limit, 100))}
    if cursor:
        params["cursor"] = cursor
    data = _get("/feed", **params)
    result = {"assets": data["assets"]}
    if "next_cursor" in data:
        result["next_cursor"] = data["next_cursor"]
    return json.dumps(result, indent=2)


@mcp.tool()
def search_assets(
    q: str = "",
    media_type: str = "",
    tags: str = "",
    limit: int = 20,
    include_superseded: bool = False,
) -> str:
    """Search assets in the contac node.

    q: substring match on asset titles.
    media_type: exact MIME type filter, e.g. "image/jpeg" or "text/plain".
    tags: space-separated tag names that assets must all have.
    limit: max results (1-100).
    include_superseded: if true, include older versions of edited assets.

    Returns a JSON list of asset metadata objects.
    """
    params: dict = {"limit": max(1, min(limit, 100))}
    if q:
        params["q"] = q
    if media_type:
        params["media_type"] = media_type
    if include_superseded:
        params["include_superseded"] = "true"
    # httpx sends list params as repeated keys automatically
    tag_list = tags.split() if tags else []
    data = _http.get("/feed", params={**params, **({"tags": tag_list} if tag_list else {})})
    data.raise_for_status()
    return json.dumps(data.json()["assets"], indent=2)


@mcp.tool()
def get_asset_meta(asset_id: str) -> str:
    """Get full metadata for an asset: title, tags, media_type, size,
    created_at, predecessor/successor version links, comment_count.
    """
    return json.dumps(_get(f"/assets/{asset_id}/meta"), indent=2)


@mcp.tool()
def fetch_asset_text(asset_id: str) -> str:
    """Read the text content of a text/* asset (plain text, markdown, code, etc.).

    Returns the raw text for text/* assets.
    Returns a description for binary assets (images, PDFs, etc.).
    """
    assert _http is not None, "call _setup() first"
    r = _http.get(f"/assets/{asset_id}")
    r.raise_for_status()
    ct = r.headers.get("content-type", "")
    if ct.startswith("text/"):
        return r.text
    return f"[binary asset — type: {ct}, size: {len(r.content):,} bytes]"


@mcp.tool()
def list_tags(limit: int = 50) -> str:
    """List all tags used across assets, ordered by frequency descending.

    Returns a JSON list of {tag, count} objects.
    """
    data = _get("/tags")
    return json.dumps(data["tags"][:limit], indent=2)


@mcp.tool()
def get_asset_comments(asset_id: str) -> str:
    """Fetch all non-deleted comments on an asset, in chronological order.

    Each comment includes: id, body, author_identity (null for owner),
    parent_id (for replies), created_at.
    """
    data = _get(f"/assets/{asset_id}/comments")
    live = [c for c in data["comments"] if not c.get("deleted")]
    return json.dumps(live, indent=2)


@mcp.tool()
def post_comment(asset_id: str, body: str, parent_id: str = "") -> str:
    """Post a comment on an asset.

    asset_id: the asset to comment on.
    body: comment text (plain text, may use markdown).
    parent_id: optional ID of the comment being replied to.

    Returns the created comment object.
    """
    payload: dict = {"body": body}
    if parent_id:
        payload["parent_id"] = parent_id
    return json.dumps(_post(f"/assets/{asset_id}/comments", payload), indent=2)


@mcp.tool()
def get_asset_history(asset_id: str) -> str:
    """Get the full version history chain for an asset.

    Follows predecessor/successor links to return all versions, oldest first.
    Each entry has is_current=true for the requested version.
    Includes deleted intermediate versions so the chain is complete.
    """
    return json.dumps(_get(f"/assets/{asset_id}/history"), indent=2)


# ── post tools ────────────────────────────────────────────────────────────────

@mcp.tool()
def get_posts(
    limit: int = 20,
    cursor: str = "",
    tags: str = "",
    q: str = "",
) -> str:
    """Get posts from the feed, newest first.

    limit: number of results (1-100).
    cursor: pagination token from a previous call's next_cursor field.
    tags: space-separated tag names that posts must all have.
    q: substring search on post body text.

    Returns JSON with {posts: [...], next_cursor?}.
    Each post includes id, body, tags, created_at, assets, comment_count.
    """
    params: dict = {"limit": max(1, min(limit, 100))}
    if cursor:
        params["cursor"] = cursor
    if q:
        params["q"] = q
    tag_list = tags.split() if tags else []
    if tag_list:
        params["tags"] = tag_list
    data = _http.get("/posts", params=params)
    data.raise_for_status()
    result = {"posts": data.json()["posts"]}
    if "next_cursor" in data.json():
        result["next_cursor"] = data.json()["next_cursor"]
    return json.dumps(result, indent=2)


@mcp.tool()
def get_post(post_id: str) -> str:
    """Get full detail for a single post: body, tags, assets list, comment_count.

    post_id: the UUID of the post.
    The body text may contain [asset:uuid] inline references.
    """
    return json.dumps(_get(f"/posts/{post_id}"), indent=2)


@mcp.tool()
def create_post(body: str, tags: str = "") -> str:
    """Create a new text post.

    body: the post body text. May include [asset:uuid] references to
          existing assets (use get_feed or search_assets to find asset IDs).
    tags: space-separated tag names.

    Returns the created post object.
    """
    payload: dict = {"body": body}
    if tags:
        payload["tags"] = tags.split()
    assert _http is not None, "call _setup() first"
    r = _http.post("/posts", data={"body": body, "tags": json.dumps(tags.split() if tags else [])})
    r.raise_for_status()
    return json.dumps(r.json(), indent=2)


@mcp.tool()
def get_post_comments(post_id: str) -> str:
    """Fetch all non-deleted comments on a post, in chronological order.

    Each comment includes: id, body, author_identity (null for owner),
    parent_id (for replies), created_at.
    """
    data = _get(f"/posts/{post_id}/comments")
    live = [c for c in data["comments"] if not c.get("deleted")]
    return json.dumps(live, indent=2)


@mcp.tool()
def comment_on_post(post_id: str, body: str, parent_id: str = "") -> str:
    """Post a comment on a post.

    post_id: the post to comment on.
    body: comment text (plain text, may use markdown).
    parent_id: optional ID of the comment being replied to.

    Returns the created comment object.
    """
    payload: dict = {"body": body}
    if parent_id:
        payload["parent_id"] = parent_id
    return json.dumps(_post(f"/posts/{post_id}/comments", payload), indent=2)


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="contac MCP server")
    parser.add_argument(
        "--node-url",
        default=os.environ.get("CONTAC_NODE_URL", ""),
        help="contac node base URL (env: CONTAC_NODE_URL)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("CONTAC_TOKEN", ""),
        help="auth token — owner or recipient (env: CONTAC_TOKEN)",
    )
    args = parser.parse_args()

    if not args.node_url:
        print("Error: --node-url or CONTAC_NODE_URL is required", file=sys.stderr)
        sys.exit(1)
    if not args.token:
        print("Error: --token or CONTAC_TOKEN is required", file=sys.stderr)
        sys.exit(1)

    _setup(args.node_url, args.token)
    mcp.run()


if __name__ == "__main__":
    main()
