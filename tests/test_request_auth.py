"""Tests for per-request token auth and concurrent isolation."""

from __future__ import annotations

import asyncio
import os
import time
import unittest
from unittest.mock import AsyncMock, patch

from mcp_superset.auth import AuthManager
from mcp_superset.client import SupersetClient
from mcp_superset.request_auth import (
    MissingRequestTokenError,
    reset_request_auth,
    set_request_auth,
)
from mcp_superset.token_cache import token_session_cache


class RequestAuthIsolationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._env_patch = patch.dict(os.environ, {"SUPERSET_AUTH_PROVIDER": "token"}, clear=False)
        self._env_patch.start()
        token_session_cache.clear()

    async def asyncTearDown(self) -> None:
        self._env_patch.stop()
        token_session_cache.clear()

    async def test_effective_auth_requires_context_in_token_mode(self) -> None:
        default = AuthManager(base_url="http://example.com", provider="token", refresh_token="r")
        client = SupersetClient(default, base_url="http://example.com")

        with self.assertRaises(MissingRequestTokenError):
            client._effective_auth()

    async def test_concurrent_requests_use_isolated_auth_managers(self) -> None:
        default = AuthManager(base_url="http://example.com", provider="token", refresh_token="default")
        client = SupersetClient(default, base_url="http://example.com")

        async def run_as_client(refresh_token: str, access_token: str) -> str:
            auth = AuthManager(
                base_url="http://example.com",
                provider="token",
                refresh_token=refresh_token,
                access_token=access_token,
                access_expires_at=time.time() + 900,
            )
            token = set_request_auth(auth)
            try:
                resolved = client._effective_auth()
                with patch.object(
                    resolved,
                    "get_token",
                    new=AsyncMock(return_value=access_token),
                ):
                    return await resolved.get_token(client._client)
            finally:
                reset_request_auth(token)

        results = await asyncio.gather(
            run_as_client("refresh-a", "access-a"),
            run_as_client("refresh-b", "access-b"),
            run_as_client("refresh-c", "access-c"),
        )

        self.assertEqual(results, ["access-a", "access-b", "access-c"])
        with self.assertRaises(MissingRequestTokenError):
            client._effective_auth()

    async def test_token_invalidate_preserves_refresh_token_and_clears_cache(self) -> None:
        token_session_cache.store("refresh", "access", time.time() + 900)
        auth = AuthManager(
            base_url="http://example.com",
            provider="token",
            access_token="access",
            refresh_token="refresh",
            access_expires_at=time.time() + 900,
        )
        auth.invalidate()

        self.assertIsNone(auth._access_token)
        self.assertEqual(auth._refresh_token, "refresh")
        self.assertIsNone(auth._csrf_token)
        self.assertIsNone(token_session_cache.get_if_valid("refresh"))


if __name__ == "__main__":
    unittest.main()
