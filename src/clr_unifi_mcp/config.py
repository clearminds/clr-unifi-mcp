"""Configuration management for UniFi MCP Server."""

import json
import logging
import logging.config
from pathlib import Path
from typing import Any, Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

CREDS_PATH = Path.home() / ".config" / "unifi" / "credentials.json"


class Settings(BaseSettings):
    """Centralized configuration for UniFi MCP Server.

    Configuration precedence: CLI > credentials.json > Environment > .env file > Defaults

    Priority order for credentials:
    1. ~/.config/unifi/credentials.json
    2. Environment variables (UNIFI_URL, UNIFI_USERNAME, UNIFI_PASSWORD, UNIFI_SITE) - override
    """

    unifi_url: str = ""
    unifi_api_key: str = ""
    unifi_username: str = ""
    unifi_password: str = ""
    unifi_site: str = "default"

    transport: Literal["stdio", "http"] = "stdio"
    host: str = "127.0.0.1"
    port: int = 8000

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        """Validate that the port number is within the valid TCP range.

        Args:
            v: The port number to validate.

        Returns:
            The validated port number.

        Raises:
            ValueError: If the port is not between 1 and 65535.
        """
        if not (0 < v < 65536):
            raise ValueError(f"Port must be between 1 and 65535, got {v}")
        return v

    @field_validator("unifi_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Validate and normalize the UniFi controller URL.

        Args:
            v: The URL string to validate.

        Returns:
            The URL with any trailing slash removed.

        Raises:
            ValueError: If the URL does not start with http:// or https://.
        """
        if v and not v.startswith(("http://", "https://")):
            raise ValueError("UNIFI_URL must start with http:// or https://")
        return v.rstrip("/") if v else v

    def load_credentials(self) -> dict[str, Any]:
        """Load credentials with config-file-first, env-override pattern.

        Returns:
            Dict with url, username, password, and site.
        """
        creds: dict[str, Any] = {}

        # 1. FIRST: Load from environment variables (base/fallback)
        if self.unifi_url:
            creds["url"] = self.unifi_url
        if self.unifi_api_key:
            creds["api_key"] = self.unifi_api_key
        if self.unifi_username:
            creds["username"] = self.unifi_username
        if self.unifi_password:
            creds["password"] = self.unifi_password
        if self.unifi_site:
            creds["site"] = self.unifi_site

        # 2. THEN: Override with credentials.json file (takes priority)
        if CREDS_PATH.exists():
            try:
                file_creds: dict[str, Any] = json.loads(CREDS_PATH.read_text())

                if "url" in file_creds:
                    creds["url"] = file_creds["url"]
                if "api_key" in file_creds:
                    creds["api_key"] = file_creds["api_key"]
                if "username" in file_creds:
                    creds["username"] = file_creds["username"]
                if "password" in file_creds:
                    creds["password"] = file_creds["password"]
                if "site" in file_creds:
                    creds["site"] = file_creds["site"]

                logger.info(f"Loaded UniFi credentials from {CREDS_PATH}")
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Failed to load {CREDS_PATH}: {e}")

        has_auth = creds.get("api_key") or (creds.get("username") and creds.get("password"))
        if not (creds.get("url") and has_auth):
            logger.warning(
                "No UniFi credentials configured. Set UNIFI_URL + UNIFI_API_KEY (or UNIFI_USERNAME/UNIFI_PASSWORD) "
                f"env vars or create {CREDS_PATH}"
            )

        # Set default site if not specified
        if not creds.get("site"):
            creds["site"] = "default"

        return creds


def configure_logging(
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
) -> None:
    """Configure application-wide logging with a console handler on stderr.

    Args:
        log_level: The root logger level to apply.
    """
    config: dict[str, Any] = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "console": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "console",
                "stream": "ext://sys.stderr",
            },
        },
        "loggers": {
            "httpx": {
                "level": "WARNING" if log_level != "DEBUG" else "DEBUG",
            },
        },
        "root": {
            "level": log_level,
            "handlers": ["console"],
        },
    }
    logging.config.dictConfig(config)
