"""Process-wide access-token cache keyed by refresh token (multi-tenant HTTP)."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

import httpx

from mcp_superset.auth import AuthError, AuthManager

ACCESS_TOKEN_TTL_SEC = 900
CACHE_SAFETY_MARGIN_SEC = 30


@dataclass(frozen=True)
class CachedAccess:
    access_token: str
    expires_at: float


class TokenSessionCache:
    """Short-lived access tokens per refresh token, with per-key refresh locking."""

    def __init__(self) -> None:
        self._entries: dict[str, CachedAccess] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._meta_lock = asyncio.Lock()

    async def _lock_for(self, refresh_token: str) -> asyncio.Lock:
        async with self._meta_lock:
            lock = self._locks.get(refresh_token)
            if lock is None:
                lock = asyncio.Lock()
                self._locks[refresh_token] = lock
            return lock

    def get_if_valid(self, refresh_token: str) -> CachedAccess | None:
        entry = self._entries.get(refresh_token)
        if entry and time.time() < entry.expires_at - CACHE_SAFETY_MARGIN_SEC:
            return entry
        return None

    def store(self, refresh_token: str, access_token: str, expires_at: float | None = None) -> None:
        self._entries[refresh_token] = CachedAccess(
            access_token=access_token,
            expires_at=expires_at if expires_at is not None else time.time() + ACCESS_TOKEN_TTL_SEC,
        )

    def invalidate(self, refresh_token: str) -> None:
        self._entries.pop(refresh_token, None)

    def clear(self) -> None:
        """Reset cache (tests only)."""
        self._entries.clear()
        self._locks.clear()

    async def get_access_token(
        self,
        refresh_token: str,
        base_url: str,
        client: httpx.AsyncClient,
    ) -> CachedAccess:
        lock = await self._lock_for(refresh_token)
        async with lock:
            entry = self.get_if_valid(refresh_token)
            if entry:
                return entry

            auth = AuthManager(
                base_url=base_url,
                provider="token",
                refresh_token=refresh_token,
            )
            if await auth._refresh(client):
                entry = CachedAccess(
                    access_token=auth._access_token,
                    expires_at=auth._token_expires_at,
                )
                self._entries[refresh_token] = entry
                return entry

            raise AuthError(
                "Superset refresh token is invalid or expired. "
                "Provide a new X-SUPERSET-REFRESH-TOKEN."
            )


token_session_cache = TokenSessionCache()
