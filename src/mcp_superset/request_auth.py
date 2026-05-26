"""Per-request Superset authentication for HTTP (token provider mode)."""

from __future__ import annotations

from contextvars import ContextVar, Token
from typing import TYPE_CHECKING

import httpx
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from mcp_superset.auth import AuthError, AuthManager
from mcp_superset.token_cache import token_session_cache

if TYPE_CHECKING:
    from collections.abc import Sequence

HEADER_REFRESH_TOKEN = "x-superset-refresh-token"

_request_auth: ContextVar[AuthManager | None] = ContextVar("superset_request_auth", default=None)

# Shared client for middleware refresh only (no Superset API calls from tools).
_refresh_client: httpx.AsyncClient | None = None


def _get_refresh_client() -> httpx.AsyncClient:
    global _refresh_client
    if _refresh_client is None:
        _refresh_client = httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=10.0),
            follow_redirects=True,
        )
    return _refresh_client


class MissingRequestTokenError(RuntimeError):
    """Raised when token auth mode is active but no per-request credentials are set."""


def get_request_auth() -> AuthManager | None:
    """Return the AuthManager bound to the current MCP HTTP request, if any."""
    return _request_auth.get()


def set_request_auth(auth: AuthManager) -> Token:
    """Bind an AuthManager to the current asyncio task."""
    return _request_auth.set(auth)


def reset_request_auth(token: Token) -> None:
    """Clear the per-request AuthManager after the HTTP request completes."""
    _request_auth.reset(token)


def is_token_provider() -> bool:
    """True when SUPERSET_AUTH_PROVIDER is token (client-supplied JWT headers)."""
    import os

    return os.getenv("SUPERSET_AUTH_PROVIDER", "db") == "token"


def _is_health_path(path: str) -> bool:
    return path.rstrip("/").endswith("/health")


class SupersetTokenMiddleware:
    """Inject per-request AuthManager from X-SUPERSET-REFRESH-TOKEN (cached access)."""

    def __init__(self, app: ASGIApp, base_url: str) -> None:
        self.app = app
        self.base_url = base_url

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        if _is_health_path(request.url.path):
            await self.app(scope, receive, send)
            return

        refresh_token = request.headers.get(HEADER_REFRESH_TOKEN)
        if not refresh_token:
            response = JSONResponse(
                {
                    "error": "missing_token",
                    "message": "Missing required header X-SUPERSET-REFRESH-TOKEN",
                },
                status_code=401,
            )
            await response(scope, receive, send)
            return

        try:
            cached = await token_session_cache.get_access_token(
                refresh_token,
                self.base_url,
                _get_refresh_client(),
            )
        except AuthError as exc:
            response = JSONResponse(
                {"error": "auth_failed", "message": str(exc)},
                status_code=401,
            )
            await response(scope, receive, send)
            return

        auth = AuthManager(
            base_url=self.base_url,
            provider="token",
            access_token=cached.access_token,
            refresh_token=refresh_token,
            access_expires_at=cached.expires_at,
        )
        ctx_token = set_request_auth(auth)
        try:
            await self.app(scope, receive, send)
        finally:
            reset_request_auth(ctx_token)


def build_token_middleware(base_url: str) -> Sequence[Middleware]:
    """Starlette middleware list for token provider mode."""
    return [Middleware(SupersetTokenMiddleware, base_url=base_url)]
