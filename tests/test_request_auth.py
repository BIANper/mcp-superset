"""Tests for per-request token auth and concurrent isolation."""

from __future__ import annotations

import asyncio
import os
import unittest
from unittest.mock import AsyncMock, patch

from mcp_superset.auth import AuthManager
from mcp_superset.client import SupersetClient
from mcp_superset.request_auth import (
    MissingRequestTokenError,
    reset_request_auth,
    set_request_auth,
)


class RequestAuthIsolationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._env_patch = patch.dict(os.environ, {"SUPERSET_AUTH_PROVIDER": "token"}, clear=False)
        self._env_patch.start()

    async def asyncTearDown(self) -> None:
        self._env_patch.stop()

    async def test_effective_auth_requires_context_in_token_mode(self) -> None:
        default = AuthManager(base_url="http://example.com", provider="token")
        client = SupersetClient(default, base_url="http://example.com")

        with self.assertRaises(MissingRequestTokenError):
            client._effective_auth()

    async def test_concurrent_requests_use_isolated_auth_managers(self) -> None:
        default = AuthManager(base_url="http://example.com", provider="token")
        client = SupersetClient(default, base_url="http://example.com")

        async def run_as_client(access_token: str) -> str:
            auth = AuthManager(
                base_url="http://example.com",
                provider="token",
                access_token=access_token,
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
            run_as_client("token-a"),
            run_as_client("token-b"),
            run_as_client("token-c"),
        )

        self.assertEqual(results, ["token-a", "token-b", "token-c"])
        with self.assertRaises(MissingRequestTokenError):
            client._effective_auth()

    async def test_token_invalidate_preserves_refresh_token(self) -> None:
        auth = AuthManager(
            base_url="http://example.com",
            provider="token",
            access_token="access",
            refresh_token="refresh",
        )
        auth.invalidate()

        self.assertIsNone(auth._access_token)
        self.assertEqual(auth._refresh_token, "refresh")
        self.assertIsNone(auth._csrf_token)


if __name__ == "__main__":
    unittest.main()
