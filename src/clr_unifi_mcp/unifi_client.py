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
        """Perform cookie-based login via /api/auth/login.

        Raises:
            ValueError: If username or password is not configured.
            httpx.HTTPStatusError: If the login request fails.
        """
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
        """Resolve an API endpoint to a full URL.

        Endpoints starting with ``/api/`` or ``/proxy/`` are used as-is.
        All other endpoints are prefixed with ``/proxy/network/api/s/{site}/``.

        Args:
            endpoint: The API endpoint path.

        Returns:
            The fully-qualified URL string.
        """
        if endpoint.startswith(("/api/", "/proxy/")):
            return f"{self.base_url}{endpoint}"
        return f"{self.base_url}/proxy/network/api/s/{self.site}/{endpoint}"

    def get(self, endpoint: str, params: dict[str, Any] | None = None) -> Any:
        """Make an authenticated GET request to the UniFi API.

        Automatically handles authentication (API key header or cookie login)
        and retries once on 401 for cookie-based sessions.

        Args:
            endpoint: The API endpoint path.
            params: Optional query parameters.

        Returns:
            The parsed JSON response body.

        Raises:
            httpx.HTTPStatusError: If the request fails after authentication.
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
        """Make a GET request and return the ``data`` array from the response.

        Args:
            endpoint: The API endpoint path.
            params: Optional query parameters.

        Returns:
            The list of result dictionaries from the ``data`` key.
        """
        result = self.get(endpoint, params=params)
        if isinstance(result, dict):
            return result.get("data", [])
        return result

    def post(self, endpoint: str, json: dict[str, Any] | None = None) -> Any:
        """Make an authenticated POST request to the UniFi API.

        Several read-only query endpoints (stat/report/*, the v2
        system-log endpoints that replaced stat/alarm and stat/event on
        Network 10.x) take their filter -- time range, attrs, paging --
        as a POST body rather than query params; there is no UniFi
        endpoint this client calls that mutates state via POST.

        Args:
            endpoint: The API endpoint path.
            json: Optional JSON request body.

        Returns:
            The parsed JSON response body.

        Raises:
            httpx.HTTPStatusError: If the request fails after authentication.
        """
        url = self._resolve_url(endpoint)
        headers: dict[str, str] = {}

        if self.api_key:
            headers["X-API-KEY"] = self.api_key
        elif not self._authenticated:
            self._login()

        resp = self._client.post(url, headers=headers, json=json)

        if resp.status_code == 401 and not self.api_key:
            logger.debug("Session expired, re-authenticating")
            self._login()
            resp = self._client.post(url, json=json)

        resp.raise_for_status()
        return resp.json()

    def post_data(
        self, endpoint: str, json: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """Make a POST request and return the ``data`` array from the response.

        Args:
            endpoint: The API endpoint path.
            json: Optional JSON request body.

        Returns:
            The list of result dictionaries from the ``data`` key.
        """
        result = self.post(endpoint, json=json)
        if isinstance(result, dict):
            return result.get("data", [])
        return result
