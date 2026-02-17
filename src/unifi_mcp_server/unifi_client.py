"""UniFi REST client with API key or cookie-based authentication."""

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class UniFiClient:
    """REST client for the UniFi Network API.

    Supports two auth methods:
    - API key (preferred, stateless): sends X-API-KEY header
    - Username/password (cookie-based): logs in via /api/auth/login
    """

    def __init__(
        self,
        url: str,
        site: str = "default",
        api_key: str = "",
        username: str = "",
        password: str = "",
    ) -> None:
        self.base_url = url.rstrip("/")
        self.site = site
        self.api_key = api_key
        self.username = username
        self.password = password
        self._client = httpx.Client(timeout=30.0, verify=True)
        self._authenticated = False

    def _login(self) -> None:
        """Cookie-based login via /api/auth/login."""
        if not self.username or not self.password:
            raise ValueError("Username and password required for cookie auth")
        logger.debug("Logging in to UniFi controller")
        resp = self._client.post(
            f"{self.base_url}/api/auth/login",
            json={"username": self.username, "password": self.password},
        )
        resp.raise_for_status()
        self._authenticated = True
        logger.debug("Login successful")

    def _resolve_url(self, endpoint: str) -> str:
        """Resolve endpoint to full URL.

        - Endpoints starting with /api/ or /proxy/ are used as-is
        - Otherwise, prefixed with /proxy/network/api/s/{site}/
        """
        if endpoint.startswith(("/api/", "/proxy/")):
            return f"{self.base_url}{endpoint}"
        return f"{self.base_url}/proxy/network/api/s/{self.site}/{endpoint}"

    def get(self, endpoint: str, params: dict[str, Any] | None = None) -> Any:
        """Make authenticated GET request.

        Returns the parsed JSON response. For standard UniFi API responses,
        the data is in the 'data' key.
        """
        url = self._resolve_url(endpoint)
        headers: dict[str, str] = {}

        if self.api_key:
            headers["X-API-KEY"] = self.api_key
        elif not self._authenticated:
            self._login()

        resp = self._client.get(url, headers=headers, params=params)

        # Re-auth on 401 for cookie-based auth
        if resp.status_code == 401 and not self.api_key:
            logger.debug("Session expired, re-authenticating")
            self._login()
            resp = self._client.get(url, params=params)

        resp.raise_for_status()
        return resp.json()

    def get_data(
        self, endpoint: str, params: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """GET and return the 'data' array from the response."""
        result = self.get(endpoint, params=params)
        if isinstance(result, dict):
            return result.get("data", [])
        return result
