"""Authentication manager for Superset — JWT with CSRF and refresh."""

import time

import httpx


class AuthError(Exception):
    """Authentication failed and cannot be recovered in the current mode."""


class AuthManager:
    """Manages authentication with Superset REST API.

    Uses JWT authentication flow:
    - Login: POST /api/v1/security/login with refresh=true
    - CSRF: GET /api/v1/security/csrf_token/ (required for POST/PUT/DELETE)
    - Refresh: POST /api/v1/security/refresh when access_token expires
    """

    def __init__(
        self,
        base_url: str,
        username: str | None = None,
        password: str | None = None,
        provider: str = "db",
        access_token: str | None = None,
        refresh_token: str | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.provider = provider

        # JWT state
        self._access_token: str | None = access_token
        self._refresh_token: str | None = refresh_token
        self._csrf_token: str | None = None
        self._token_expires_at: float = float("inf") if provider == "token" and access_token else 0

    async def get_token(self, client: httpx.AsyncClient) -> str:
        """Return a valid access_token, refreshing or re-logging in as needed.

        Args:
            client: httpx async client used for HTTP requests.

        Returns:
            A valid JWT access token string.
        """
        # Check if token is still valid (with 30 sec safety margin)
        if self._access_token and time.time() < self._token_expires_at - 30:
            return self._access_token

        # Try refresh if we have a refresh token
        if self._refresh_token:
            refreshed = await self._refresh(client)
            if refreshed:
                return self._access_token

        if self.provider == "token":
            raise AuthError(
                "Superset access token is invalid or expired and could not be refreshed. "
                "Provide a new X-SUPERSET-ACCESS-TOKEN (and X-SUPERSET-REFRESH-TOKEN if needed)."
            )

        # Full login
        await self._login(client)
        if not self._access_token:
            raise AuthError("Superset login did not return an access token")
        return self._access_token

    async def get_csrf_token(self, client: httpx.AsyncClient) -> str:
        """Return a valid CSRF token, fetching one if necessary.

        Args:
            client: httpx async client used for HTTP requests.

        Returns:
            A CSRF token string.
        """
        if self._csrf_token:
            return self._csrf_token
        await self._fetch_csrf(client)
        return self._csrf_token

    async def _login(self, client: httpx.AsyncClient) -> None:
        """Perform JWT login via POST /api/v1/security/login.

        Args:
            client: httpx async client used for HTTP requests.
        """
        if self.provider == "token":
            raise AuthError("Password login is disabled when SUPERSET_AUTH_PROVIDER=token")

        url = f"{self.base_url}/api/v1/security/login"
        payload = {
            "username": self.username,
            "password": self.password,
            "provider": self.provider,
            "refresh": True,
        }
        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()
        self._access_token = data["access_token"]
        self._refresh_token = data.get("refresh_token")
        # Default JWT_ACCESS_TOKEN_EXPIRES = 15 minutes (900 sec)
        self._token_expires_at = time.time() + 900
        # Reset CSRF — it is bound to the session/token
        self._csrf_token = None

    async def _refresh(self, client: httpx.AsyncClient) -> bool:
        """Attempt to refresh the JWT using the refresh token.

        Args:
            client: httpx async client used for HTTP requests.

        Returns:
            True if refresh succeeded, False otherwise.
        """
        url = f"{self.base_url}/api/v1/security/refresh"
        headers = {"Authorization": f"Bearer {self._refresh_token}"}
        try:
            resp = await client.post(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            self._access_token = data["access_token"]
            self._token_expires_at = time.time() + 900
            # Reset CSRF — a new one is needed for the new token
            self._csrf_token = None
            return True
        except (httpx.HTTPStatusError, KeyError):
            if self.provider == "token":
                self._refresh_token = None
            return False

    async def _fetch_csrf(self, client: httpx.AsyncClient) -> None:
        """Fetch CSRF token via GET /api/v1/security/csrf_token/.

        Args:
            client: httpx async client used for HTTP requests.
        """
        token = await self.get_token(client)
        url = f"{self.base_url}/api/v1/security/csrf_token/"
        headers = {"Authorization": f"Bearer {token}"}
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        self._csrf_token = data["result"]

    def invalidate(self) -> None:
        """Reset cached tokens, forcing re-authentication on next request."""
        if self.provider == "token":
            # Keep refresh token so a 401 can trigger /security/refresh for this client only.
            self._access_token = None
            self._csrf_token = None
            self._token_expires_at = 0
            return

        self._access_token = None
        self._refresh_token = None
        self._csrf_token = None
        self._token_expires_at = 0
