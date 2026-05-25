"""OAuth2/OIDC login and callback endpoints."""
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from . import sso as sso_module
from .sso import SSOError, UnknownIdentityError

router = APIRouter(prefix="/auth")


def _callback_uri(request: Request) -> str:
    return str(request.base_url).rstrip("/") + "/auth/callback"


@router.get("/login")
def login(request: Request, provider: str = "google"):
    cfg = request.app.state.sso_config
    if provider == "google":
        client_id = cfg.get("google_client_id")
        if not client_id:
            raise HTTPException(status_code=503, detail="Google SSO not configured")
        state = sso_module.generate_state(request.app.state.db, "google")
        auth_url = sso_module.google_auth_url(client_id, _callback_uri(request), state)
        return {"provider": "google", "auth_url": auth_url, "state": state}
    raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")


@router.get("/callback")
def callback(request: Request, code: str, state: str):
    db = request.app.state.db
    cfg = request.app.state.sso_config

    try:
        provider = sso_module.consume_state(db, state)
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

        token = sso_module.complete_callback(db, identity)
    except UnknownIdentityError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except SSOError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return RedirectResponse(url=f"/#token={token}", status_code=302)
