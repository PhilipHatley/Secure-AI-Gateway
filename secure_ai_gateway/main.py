"""FastAPI Gateway — implements the thesis proxy architecture control point.

The app exposes an OpenAI-compatible HTTP endpoint that scans prompts before
forwarding them, supporting the OWASP LLM02 and DORA Art. 28 argument for a
technical third-party LLM risk control.
"""

from __future__ import annotations

import time
import json
from copy import deepcopy
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .audit_logger import build_audit_entry, log_interaction, read_last_entries
from .aup import blocked_message, warning_header_value
from .config import Settings, get_settings
from .dlp_pipeline import DLPResult, analyze_prompt
from .masker import MaskingResult, mask_text
from .policy_engine import PolicyDecision, decide_policy


app = FastAPI(title="Secure AI Gateway", version="0.1.0")


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    """Serve the single-page demonstration UI."""
    template = Path(__file__).resolve().parent.parent / "templates" / "index.html"
    return HTMLResponse(template.read_text(encoding="utf-8"))


@app.get("/health")
async def health() -> dict[str, str | bool]:
    """Return gateway status for operational checks."""
    settings = get_settings()
    return {"status": "ok", "target_api": settings.target_api, "demo_mode": settings.demo_mode}


@app.get("/audit")
async def audit() -> dict[str, Any]:
    """Return the last 20 sanitized audit entries for demo purposes."""
    return {"entries": read_last_entries(get_settings().log_file, limit=20)}


@app.post("/v1/chat/completions")
async def chat_completions(request: Request) -> JSONResponse:
    """Scan, decide, audit, and optionally forward an OpenAI-style request."""
    payload = await _read_json_payload(request)
    settings = get_settings()
    request_id = str(uuid4())
    prompt = _extract_last_user_content(payload)
    dlp_result = analyze_prompt(prompt)
    decision = decide_policy(dlp_result)
    masking = _maybe_mask(prompt, dlp_result, decision)

    if decision.action == "BLOCK":
        _write_audit(request_id, settings, prompt, dlp_result, decision, masking, False)
        labels = [entity.label for entity in dlp_result.detected_entities]
        return JSONResponse(status_code=403, content=blocked_message(labels, request_id))

    forwarded_payload = _payload_for_forwarding(payload, masking)
    response_body = await _forward_with_audit(request_id, settings, prompt, dlp_result, decision, masking, forwarded_payload)
    headers = _response_headers(decision)
    return JSONResponse(content=response_body, headers=headers)


async def _read_json_payload(request: Request) -> dict[str, Any]:
    """Read JSON, tolerating Windows-encoded demo clients when needed."""
    try:
        return await request.json()
    except UnicodeDecodeError:
        raw_body = await request.body()
        return json.loads(raw_body.decode("cp1252"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON request body.") from exc


def _extract_last_user_content(payload: dict[str, Any]) -> str:
    """Extract the latest user message from an OpenAI-compatible body."""
    messages = payload.get("messages", [])
    for message in reversed(messages):
        if message.get("role") == "user":
            return str(message.get("content", ""))
    raise HTTPException(status_code=400, detail="No user message found in request body.")


def _maybe_mask(prompt: str, result: DLPResult, decision: PolicyDecision) -> MaskingResult | None:
    """Run masking only when the policy decision requires it."""
    if decision.action != "MASK_AND_FORWARD":
        return None
    return mask_text(prompt, result.detected_entities)


def _payload_for_forwarding(payload: dict[str, Any], masking: MaskingResult | None) -> dict[str, Any]:
    """Return a copy of the request with the last user message masked if needed."""
    forwarded = deepcopy(payload)
    if masking is None:
        return forwarded
    for message in reversed(forwarded.get("messages", [])):
        if message.get("role") == "user":
            message["content"] = masking.masked_text
            break
    return forwarded


async def _forward_with_audit(
    request_id: str,
    settings: Settings,
    prompt: str,
    result: DLPResult,
    decision: PolicyDecision,
    masking: MaskingResult | None,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Forward the sanitized request and always write a sanitized audit entry."""
    try:
        response = await _forward_to_llm(payload, settings)
        response["gateway"] = _gateway_metadata(request_id, result, decision)
    finally:
        _write_audit(request_id, settings, prompt, result, decision, masking, True)
    return response


async def _forward_to_llm(payload: dict[str, Any], settings: Settings) -> dict[str, Any]:
    """Forward to the configured provider or return a canned demo response."""
    if settings.demo_mode or settings.target_api == "mock":
        return _demo_response(payload, settings)
    if settings.target_api == "openai":
        return await _call_openai(payload, settings)
    if settings.target_api == "anthropic":
        return await _call_anthropic(payload, settings)
    raise HTTPException(status_code=500, detail=f"Unsupported TARGET_API: {settings.target_api}")


async def _call_openai(payload: dict[str, Any], settings: Settings) -> dict[str, Any]:
    """Forward the request to OpenAI's chat completions API."""
    if not settings.openai_api_key:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY is not configured.")
    headers = {"Authorization": f"Bearer {settings.openai_api_key}"}
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(settings.target_endpoint, headers=headers, json=payload)
    return _checked_json_response(response)


async def _call_anthropic(payload: dict[str, Any], settings: Settings) -> dict[str, Any]:
    """Forward the request to Anthropic's messages API with a minimal conversion."""
    if not settings.anthropic_api_key:
        raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY is not configured.")
    anthropic_payload = _anthropic_payload(payload, settings)
    headers = {"x-api-key": settings.anthropic_api_key, "anthropic-version": "2023-06-01"}
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(settings.target_endpoint, headers=headers, json=anthropic_payload)
    return _checked_json_response(response)


def _anthropic_payload(payload: dict[str, Any], settings: Settings) -> dict[str, Any]:
    """Convert the OpenAI-style body into Anthropic's basic messages shape."""
    return {
        "model": payload.get("model") or settings.target_model,
        "max_tokens": payload.get("max_tokens", 512),
        "messages": payload.get("messages", []),
    }


def _checked_json_response(response: httpx.Response) -> dict[str, Any]:
    """Return provider JSON or convert provider errors into gateway errors."""
    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    return response.json()


def _demo_response(payload: dict[str, Any], settings: Settings) -> dict[str, Any]:
    """Return an OpenAI-compatible canned response for offline demonstrations."""
    return {
        "id": f"chatcmpl-demo-{int(time.time())}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": payload.get("model") or settings.target_model,
        "choices": [_demo_choice()],
    }


def _demo_choice() -> dict[str, Any]:
    """Build a stable demo completion choice."""
    return {
        "index": 0,
        "message": {"role": "assistant", "content": "DEMO_MODE: Prompten blev behandlet af Secure AI Gateway."},
        "finish_reason": "stop",
    }


def _gateway_metadata(request_id: str, result: DLPResult, decision: PolicyDecision) -> dict[str, Any]:
    """Build sanitized response metadata for the demo UI."""
    return {
        "request_id": request_id,
        "policy_action": decision.action,
        "policy_reason": decision.reason,
        "policy_rule_triggered": decision.triggered_rule,
        "detected_entities": [{"label": entity.label, "stage": entity.stage} for entity in result.detected_entities],
    }


def _response_headers(decision: PolicyDecision) -> dict[str, str]:
    """Return response headers for the policy action."""
    if decision.action == "MASK_AND_FORWARD":
        return {"X-DLP-Warning": warning_header_value()}
    return {}


def _write_audit(
    request_id: str,
    settings: Settings,
    prompt: str,
    result: DLPResult,
    decision: PolicyDecision,
    masking: MaskingResult | None,
    forwarded: bool,
) -> None:
    """Write a sanitized audit entry for every gateway interaction."""
    entry = build_audit_entry(
        request_id=request_id,
        target_api=settings.target_endpoint,
        original_prompt_length=len(prompt),
        detected_entities=result.detected_entities,
        masked_values_stored=bool(masking and masking.token_mapping),
        policy_decision=decision,
        forwarded_to_llm=forwarded,
    )
    log_interaction(entry, settings.log_file)
