"""OAuth2/OIDC login and callback endpoints."""
import base64
from urllib.parse import quote

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from . import auth as auth_module
from . import node as node_module
from . import sso as sso_module
from .auth import AuthDep
from .sso import SSOError, UnknownIdentityError

router = APIRouter(prefix="/auth")


def _callback_uri(request: Request) -> str:
    node_address = getattr(request.app.state, "node_address", None)
    if node_address:
        return node_address.rstrip("/") + "/auth/callback"
    return str(request.base_url).rstrip("/") + "/auth/callback"


@router.get("/login")
def login(request: Request, provider: str = "google", return_to: str = ""):
    proxy_url = getattr(request.app.state, "identity_proxy_url", None)
    if proxy_url:
        state = sso_module.generate_state(request.app.state.db, "proxy", return_to=return_to)
        server_callback = _callback_uri(request) + "?state=" + state
        auth_url = proxy_url.rstrip("/") + "/auth/start?return_to=" + quote(server_callback, safe="")
        return {"provider": "google_proxy", "auth_url": auth_url}

    cfg = request.app.state.sso_config
    if provider == "google":
        client_id = cfg.get("google_client_id")
        if not client_id:
            raise HTTPException(status_code=503, detail="Google SSO not configured")
        state = sso_module.generate_state(request.app.state.db, "google", return_to=return_to)
        auth_url = sso_module.google_auth_url(client_id, _callback_uri(request), state)
        return {"provider": "google", "auth_url": auth_url, "state": state}
    raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")


@router.get("/callback")
def callback(request: Request, code: str = None, state: str = None, proxy_token: str = None):
    db = request.app.state.db

    if proxy_token:
        if not state:
            raise HTTPException(status_code=400, detail="Missing state")
        try:
            provider, return_to = sso_module.consume_state(db, state)
        except SSOError as e:
            raise HTTPException(status_code=400, detail=str(e))
        if provider != "proxy":
            raise HTTPException(status_code=400, detail="State provider mismatch")

        proxy_url = getattr(request.app.state, "identity_proxy_url", None)
        if not proxy_url:
            raise HTTPException(status_code=503, detail="Identity proxy not configured")

        r = httpx.get(proxy_url.rstrip("/") + "/auth/verify", params={"token": proxy_token})
        if not r.is_success:
            raise HTTPException(status_code=403, detail="Invalid or expired proxy token")

        data = r.json()
        identity = data["identity"]
        display_name = data.get("display_name")

        owner_identity = getattr(request.app.state, "owner_identity", None)
        if owner_identity and identity == owner_identity:
            if display_name:
                request.app.state.owner_display_name = display_name
            token = auth_module.issue_token(ttl_seconds=86400 * 30)
        else:
            try:
                token = sso_module.complete_callback(db, identity)
            except UnknownIdentityError as e:
                raise HTTPException(status_code=403, detail=str(e))

        dest = return_to.rstrip("/") + "#token=" + token if return_to else "/#token=" + token
        return RedirectResponse(url=dest, status_code=302)

    # Direct Google OAuth flow
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state")

    cfg = request.app.state.sso_config
    try:
        provider, return_to = sso_module.consume_state(db, state)
    except SSOError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        if provider == "google":
            exchange_fn = request.app.state.sso_exchange_google
            claims = exchange_fn(
                code,
                _callback_uri(request),
                cfg["google_client_id"],
                cfg["google_client_secret"],
            )
            identity = sso_module.normalize_google_identity(claims)
        else:
            raise SSOError(f"Unknown provider: {provider}")

        owner_identity = getattr(request.app.state, "owner_identity", None)
        if owner_identity and identity == owner_identity:
            request.app.state.owner_display_name = claims.get("name") or claims.get("email")
            token = auth_module.issue_token(ttl_seconds=86400 * 30)
        else:
            token = sso_module.complete_callback(db, identity)
    except UnknownIdentityError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except SSOError as e:
        raise HTTPException(status_code=400, detail=str(e))

    dest = return_to.rstrip("/") + "#token=" + token if return_to else "/#token=" + token
    return RedirectResponse(url=dest, status_code=302)


@router.get("/me")
def me(request: Request, identity: AuthDep):
    """Return the current user's role and identity."""
    if identity.is_owner:
        return {
            "role": "owner",
            "identity": getattr(request.app.state, "owner_identity", None),
            "display_name": getattr(request.app.state, "owner_display_name", None),
        }
    if identity.is_share:
        return {"role": "share", "identity": identity.share_identity}
    db = request.app.state.db
    row = db.execute(
        "SELECT identity, display_name FROM recipients WHERE id = ?",
        (identity.recipient_id,),
    ).fetchone()
    if row:
        return {"role": "recipient", "identity": row[0], "display_name": row[1]}
    return {"role": "recipient", "identity": None}


class _SignBody(BaseModel):
    canonical: str


@router.post("/sign-federated")
def sign_federated(body: _SignBody, request: Request):
    """Internal: sign a canonical string with the node's private key for outbound federated requests."""
    private_key = getattr(request.app.state, "private_key", None)
    if not private_key:
        raise HTTPException(status_code=503, detail="Node locked")
    sig = base64.b64encode(private_key.sign(body.canonical.encode())).decode()
    return {"signature": sig, "public_key": node_module._public_key_b64}
