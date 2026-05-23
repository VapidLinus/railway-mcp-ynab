"""mcp-ynab server with native streamable-http transport and OAuth-shim auth.

Wraps FastMCP's streamable_http_app() with:
  - OAuth 2.0 metadata endpoints (we are our own minimal authorization server)
  - /authorize and /token endpoints
  - Bearer-token middleware on /mcp

The credential check is one client_secret string compare against an env var.
Everything else is OAuth ceremony so Claude.ai's connector flow works.
"""

import base64
import hashlib
import os
import secrets
import sys
import time
from urllib.parse import urlencode

import uvicorn
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Route

from src.server import mcp


CLIENT_ID = os.environ["OAUTH_CLIENT_ID"]
CLIENT_SECRET = os.environ["OAUTH_CLIENT_SECRET"]
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")

CODE_TTL = 600
TOKEN_TTL = 3600


def _log(*args):
    print("[serve]", *args, file=sys.stderr, flush=True)


_codes: dict[str, dict] = {}
_tokens: dict[str, float] = {}


def _now() -> float:
    return time.time()


def _gc():
    cutoff = _now()
    for k in [k for k, v in _codes.items() if v["expires_at"] < cutoff]:
        _codes.pop(k, None)
    for k in [k for k, v in _tokens.items() if v < cutoff]:
        _tokens.pop(k, None)


def _base_url(request: Request) -> str:
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL
    return f"{request.url.scheme}://{request.url.netloc}"


async def protected_resource_metadata(request: Request):
    base = _base_url(request)
    return JSONResponse({
        "resource": f"{base}/mcp",
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
    })


async def authorization_server_metadata(request: Request):
    base = _base_url(request)
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post", "client_secret_basic",
        ],
    })


async def authorize(request: Request):
    p = request.query_params
    client_id = p.get("client_id")
    redirect_uri = p.get("redirect_uri")
    state = p.get("state", "")
    code_challenge = p.get("code_challenge")
    method = p.get("code_challenge_method", "S256")

    _log("authorize", "client_id_ok=", client_id == CLIENT_ID, "redirect_uri=", redirect_uri)

    if client_id != CLIENT_ID:
        return JSONResponse({"error": "invalid_client"}, status_code=400)
    if not redirect_uri:
        return JSONResponse({"error": "invalid_request", "error_description": "redirect_uri required"}, status_code=400)
    if not code_challenge:
        return JSONResponse({"error": "invalid_request", "error_description": "PKCE required"}, status_code=400)
    if method != "S256":
        return JSONResponse({"error": "invalid_request", "error_description": "only S256 supported"}, status_code=400)

    _gc()
    code = secrets.token_urlsafe(32)
    _codes[code] = {
        "code_challenge": code_challenge,
        "redirect_uri": redirect_uri,
        "expires_at": _now() + CODE_TTL,
    }

    sep = "&" if "?" in redirect_uri else "?"
    callback = f"{redirect_uri}{sep}{urlencode({'code': code, 'state': state})}"
    return RedirectResponse(callback, status_code=302)


def _creds_from_request(request: Request, form: dict) -> tuple[str | None, str | None]:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth.split(" ", 1)[1]).decode()
            cid, _, csec = decoded.partition(":")
            return cid, csec
        except Exception:
            return None, None
    return form.get("client_id"), form.get("client_secret")


async def token(request: Request):
    form = dict((await request.form()).items())
    if form.get("grant_type") != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    client_id, client_secret = _creds_from_request(request, form)
    creds_ok = (
        client_id is not None
        and client_secret is not None
        and secrets.compare_digest(client_id, CLIENT_ID)
        and secrets.compare_digest(client_secret, CLIENT_SECRET)
    )
    _log("token", "creds_ok=", creds_ok)
    if not creds_ok:
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    code = form.get("code")
    redirect_uri = form.get("redirect_uri")
    code_verifier = form.get("code_verifier")
    if not (code and redirect_uri and code_verifier):
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    entry = _codes.pop(code, None)
    if not entry:
        _log("token", "unknown code")
        return JSONResponse({"error": "invalid_grant", "error_description": "unknown code"}, status_code=400)
    if entry["expires_at"] < _now():
        _log("token", "code expired")
        return JSONResponse({"error": "invalid_grant", "error_description": "code expired"}, status_code=400)
    if not secrets.compare_digest(entry["redirect_uri"], redirect_uri):
        _log("token", "redirect_uri mismatch")
        return JSONResponse({"error": "invalid_grant", "error_description": "redirect_uri mismatch"}, status_code=400)

    expected = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b"=").decode()
    if not secrets.compare_digest(expected, entry["code_challenge"]):
        _log("token", "PKCE mismatch")
        return JSONResponse({"error": "invalid_grant", "error_description": "PKCE verification failed"}, status_code=400)

    _gc()
    access_token = secrets.token_urlsafe(32)
    _tokens[access_token] = _now() + TOKEN_TTL
    _log("token", "issued, ttl=", TOKEN_TTL)

    return JSONResponse({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL,
    })


class BearerAuthOnMcp:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if not (path == "/mcp" or path.startswith("/mcp/")):
            await self.app(scope, receive, send)
            return

        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        auth = headers.get("authorization", "")
        tok = auth[7:] if auth.lower().startswith("bearer ") else ""

        expires_at = _tokens.get(tok)
        if not expires_at or expires_at < _now():
            host = headers.get("host", "")
            scheme = scope.get("scheme") or "http"
            base = PUBLIC_BASE_URL or f"{scheme}://{host}"
            www_auth = f'Bearer resource_metadata="{base}/.well-known/oauth-protected-resource"'
            _log("mcp 401")
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"www-authenticate", www_auth.encode()),
                    (b"content-type", b"application/json"),
                ],
            })
            await send({"type": "http.response.body", "body": b'{"error":"unauthorized"}'})
            return

        await self.app(scope, receive, send)


app = mcp.streamable_http_app()

oauth_routes = [
    Route("/.well-known/oauth-protected-resource", protected_resource_metadata, methods=["GET"]),
    Route("/.well-known/oauth-authorization-server", authorization_server_metadata, methods=["GET"]),
    Route("/authorize", authorize, methods=["GET"]),
    Route("/token", token, methods=["POST"]),
]
for r in reversed(oauth_routes):
    app.routes.insert(0, r)

app = BearerAuthOnMcp(app)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    _log(f"starting on port {port}, public_base={PUBLIC_BASE_URL or '(derived)'}")
    uvicorn.run(app, host="0.0.0.0", port=port)
