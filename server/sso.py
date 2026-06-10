"""SSO / OAuth2-OIDC support.

Handles state lifecycle, identity resolution, and the Google OIDC
code-exchange flow. The exchange function is a plain callable so it
can be swapped out in tests without monkey-patching HTTP libraries.
"""
import os
import time
import base64
from urllib.parse import urlencode

import httpx

from .auth import issue_node_token
from .db import NS, now_ns

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


class SSOError(Exception):
    pass


class UnknownIdentityError(SSOError):
    pass


# ── state management (CSRF) ───────────────────────────────────────────────────

def generate_state(db, provider: str, ttl: int = 600, return_to: str = "") -> str:
    state = base64.urlsafe_b64encode(os.urandom(24)).rstrip(b"=").decode()
    db.execute(
        "INSERT INTO sso_states (state, provider, expiry, return_to) VALUES (?, ?, ?, ?)",
        (state, provider, now_ns() + ttl * NS, return_to),
    )
    db.commit()
    return state


def consume_state(db, state: str) -> tuple[str, str]:
    """Verify and consume a one-time state token. Returns (provider, return_to)."""
    row = db.execute(
        "SELECT provider, expiry, return_to FROM sso_states WHERE state = ?", (state,)
    ).fetchone()
    if row is None:
        raise SSOError("Invalid or unknown state")
    provider, expiry, return_to = row
    db.execute("DELETE FROM sso_states WHERE state = ?", (state,))
    db.commit()
    if now_ns() > expiry:
        raise SSOError("State has expired")
    return provider, return_to


# ── Google OIDC ───────────────────────────────────────────────────────────────

def google_auth_url(client_id: str, redirect_uri: str, state: str) -> str:
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


def exchange_google_code(
    code: str, redirect_uri: str, client_id: str, client_secret: str
) -> dict:
    """Exchange an auth code for user-info claims via Google's token + userinfo endpoints."""
    token_resp = httpx.post(GOOGLE_TOKEN_URL, data={
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "authorization_code",
    })
    token_resp.raise_for_status()
    access_token = token_resp.json()["access_token"]

    user_resp = httpx.get(
        GOOGLE_USERINFO_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    user_resp.raise_for_status()
    return user_resp.json()


def normalize_google_identity(claims: dict) -> str:
    email = claims.get("email")
    if not email:
        raise SSOError("No email claim in Google response")
    return f"google:{email}"


# ── identity resolution ───────────────────────────────────────────────────────

def resolve_identity(db, identity: str) -> str | None:
    """Map provider:identifier → node_id via identity_mappings."""
    row = db.execute(
        "SELECT recipient_id FROM identity_mappings WHERE identity = ?", (identity,)
    ).fetchone()
    return row[0] if row else None


def complete_callback(db, identity: str, ttl_seconds: int = 86400) -> str:
    """Resolve SSO identity to a node_id and issue a session token."""
    node_id = resolve_identity(db, identity)
    if node_id is None:
        raise UnknownIdentityError(f"No node configured for identity: {identity}")
    return issue_node_token(db, node_id, ttl_seconds=ttl_seconds)
