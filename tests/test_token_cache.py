"""Tests for refresh-token-keyed access token cache."""

from __future__ import annotations

import asyncio
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from mcp_superset.auth import AuthError
from mcp_superset.token_cache import TokenSessionCache


class TokenSessionCacheTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.cache = TokenSessionCache()

    async def test_cache_hit_skips_refresh(self) -> None:
        self.cache.store("refresh-a", "access-a", time.time() + 900)
        client = MagicMock(spec=httpx.AsyncClient)

        entry = await self.cache.get_access_token("refresh-a", "http://example.com", client)

        self.assertEqual(entry.access_token, "access-a")
        client.post.assert_not_called()

    async def test_different_refresh_tokens_are_isolated(self) -> None:
        self.cache.store("refresh-a", "access-a", time.time() + 900)
        self.cache.store("refresh-b", "access-b", time.time() + 900)

        self.assertEqual(self.cache.get_if_valid("refresh-a").access_token, "access-a")
        self.assertEqual(self.cache.get_if_valid("refresh-b").access_token, "access-b")

    async def test_concurrent_miss_calls_refresh_once(self) -> None:
        client = MagicMock(spec=httpx.AsyncClient)
        refresh_count = 0

        async def fake_refresh(c: httpx.AsyncClient) -> bool:
            nonlocal refresh_count
            refresh_count += 1
            await asyncio.sleep(0.05)
            auth._access_token = "new-access"
            auth._token_expires_at = time.time() + 900
            return True

        auth = MagicMock()
        with patch("mcp_superset.token_cache.AuthManager") as manager_cls:
            manager_cls.return_value = auth
            auth._refresh = fake_refresh
            auth._access_token = "new-access"
            auth._token_expires_at = time.time() + 900

            results = await asyncio.gather(
                self.cache.get_access_token("refresh-x", "http://example.com", client),
                self.cache.get_access_token("refresh-x", "http://example.com", client),
                self.cache.get_access_token("refresh-x", "http://example.com", client),
            )

        self.assertEqual(refresh_count, 1)
        self.assertTrue(all(r.access_token == "new-access" for r in results))

    async def test_invalidate_forces_refresh(self) -> None:
        self.cache.store("refresh-a", "access-old", time.time() + 900)
        self.cache.invalidate("refresh-a")

        client = MagicMock(spec=httpx.AsyncClient)
        auth = MagicMock()
        auth._refresh = AsyncMock(return_value=True)
        auth._access_token = "access-new"
        auth._token_expires_at = time.time() + 900

        with patch("mcp_superset.token_cache.AuthManager", return_value=auth):
            entry = await self.cache.get_access_token("refresh-a", "http://example.com", client)

        self.assertEqual(entry.access_token, "access-new")
        auth._refresh.assert_awaited_once()

    async def test_invalid_refresh_raises(self) -> None:
        client = MagicMock(spec=httpx.AsyncClient)
        auth = MagicMock()
        auth._refresh = AsyncMock(return_value=False)

        with patch("mcp_superset.token_cache.AuthManager", return_value=auth):
            with self.assertRaises(AuthError):
                await self.cache.get_access_token("bad-refresh", "http://example.com", client)


if __name__ == "__main__":
    unittest.main()
