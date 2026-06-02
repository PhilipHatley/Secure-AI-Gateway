"""Configuration — miljøstyret og reproducerbar PoC-drift."""

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
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int_from_env(value: str | None, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    openai_api_key: str | None
    anthropic_api_key: str | None
    gemini_api_key: str | None
    target_api: str
    target_model: str
    gateway_port: int
    demo_mode: bool
    log_file: str

    @classmethod
    def from_env(cls) -> "Settings":
        gemini_api_key = os.getenv("GEMINI_API_KEY")
        target_api = _target_api_from_env(os.getenv("TARGET_API"), gemini_api_key)
        return cls(
            openai_api_key=os.getenv("OPENAI_API_KEY"),
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
            gemini_api_key=gemini_api_key,
            target_api=target_api,
            target_model=os.getenv("TARGET_MODEL") or _default_model(target_api),
            gateway_port=_int_from_env(os.getenv("GATEWAY_PORT"), 8000),
            demo_mode=_bool_from_env(os.getenv("DEMO_MODE"), True),
            log_file=os.getenv("LOG_FILE", "audit.log"),
        )

    @property
    def target_endpoint(self) -> str:
        endpoints = {
            "openai": "https://api.openai.com/v1/chat/completions",
            "anthropic": "https://api.anthropic.com/v1/messages",
            "gemini": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
            "mock": "mock://secure-ai-gateway/demo",
        }
        return endpoints.get(self.target_api, endpoints["mock"])


def _target_api_from_env(value: str | None, gemini_api_key: str | None) -> str:
    if value:
        return value.strip().lower()
    return "gemini" if gemini_api_key else "mock"


def _default_model(target_api: str) -> str:
    if target_api == "gemini":
        return "gemini-2.0-flash"
    return "gpt-4o-mini"


def get_settings() -> Settings:
    return Settings.from_env()
