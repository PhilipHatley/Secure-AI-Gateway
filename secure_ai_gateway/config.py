"""Configuration — implements the deployable PoC settings for the thesis gateway.

This module centralises environment-driven configuration for the DORA/NIS2
proxy proof-of-concept, keeping API keys, target provider selection, logging,
and demo behaviour outside the business logic.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None


if load_dotenv is not None:
    load_dotenv()


def _bool_from_env(value: str | None, default: bool) -> bool:
    """Parse common environment boolean values."""
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int_from_env(value: str | None, default: int) -> int:
    """Parse an integer environment value with a safe fallback."""
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    """Runtime settings loaded from environment variables."""

    openai_api_key: str | None
    anthropic_api_key: str | None
    target_api: str
    target_model: str
    gateway_port: int
    demo_mode: bool
    log_file: str

    @classmethod
    def from_env(cls) -> "Settings":
        """Create a Settings object from environment variables."""
        return cls(
            openai_api_key=os.getenv("OPENAI_API_KEY"),
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
            target_api=os.getenv("TARGET_API", "mock").strip().lower(),
            target_model=os.getenv("TARGET_MODEL", "gpt-4o-mini"),
            gateway_port=_int_from_env(os.getenv("GATEWAY_PORT"), 8000),
            demo_mode=_bool_from_env(os.getenv("DEMO_MODE"), True),
            log_file=os.getenv("LOG_FILE", "audit.log"),
        )

    @property
    def target_endpoint(self) -> str:
        """Return the provider endpoint used in audit metadata."""
        endpoints = {
            "openai": "https://api.openai.com/v1/chat/completions",
            "anthropic": "https://api.anthropic.com/v1/messages",
            "mock": "mock://secure-ai-gateway/demo",
        }
        return endpoints.get(self.target_api, endpoints["mock"])


def get_settings() -> Settings:
    """Load current settings without caching, which helps demos change env vars."""
    return Settings.from_env()
