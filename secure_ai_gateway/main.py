"""FastAPI Gateway — adresserer Gap G2: manglende kontrolleret LLM-proxy.

The app exposes an OpenAI-compatible HTTP endpoint that scans prompts before
forwarding them, supporting the OWASP LLM02 and DORA Art. 28 argument for a
technical third-party LLM risk control.
"""

from __future__ import annotations

import asyncio
import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any, AsyncIterator
from uuid import uuid4

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse

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
    template = Path(__file__).resolve().parent / "templates" / "index.html"
    return HTMLResponse(template.read_text(encoding="utf-8"))


@app.get("/health")
async def health() -> dict[str, str | bool]:
    """Return gateway status for operational checks."""
    settings = get_settings()
    return {"status": "ok", "target_api": settings.target_api, "demo_mode": settings.demo_mode}


@app.get("/audit")
async def audit() -> list[dict[str, Any]]:
    """Return the last 20 sanitized audit entries for demo purposes."""
    return read_last_entries(get_settings().log_file, limit=20)


@app.post("/v1/chat/completions")
async def chat_completions(request: Request) -> JSONResponse:
    """Scan, decide, audit, and optionally forward an OpenAI-style request."""
    payload = await _read_json_payload(request)
    settings = _settings_for_payload(payload, get_settings())
    request_id = str(uuid4())
    prompt = _extract_last_user_content(payload)
    dlp_result = analyze_prompt(prompt)
    decision = decide_policy(dlp_result)
    masking = _maybe_mask(prompt, dlp_result, decision)

    if decision.action == "BLOCK":
        _write_audit(request_id, settings, prompt, dlp_result, decision, masking, False)
        labels = [entity.label for entity in dlp_result.detected_entities]
        return JSONResponse(status_code=403, content=blocked_message(labels, request_id))

    forwarded_payload = _payload_for_forwarding(payload, masking, settings)
    response_body = await _forward_with_audit(
        request_id, settings, prompt, dlp_result, decision, masking, forwarded_payload
    )
    headers = _response_headers(decision)
    return JSONResponse(content=response_body, headers=headers)


@app.post("/v1/chat/completions/stream")
async def chat_completions_stream(request: Request) -> Response:
    """Scan first, then stream allowed Gemini-compatible responses as SSE."""
    payload = await _read_json_payload(request)
    settings = _settings_for_payload(payload, get_settings())
    request_id = str(uuid4())
    prompt = _extract_last_user_content(payload)
    dlp_result = analyze_prompt(prompt)
    decision = decide_policy(dlp_result)
    masking = _maybe_mask(prompt, dlp_result, decision)

    if decision.action == "BLOCK":
        _write_audit(request_id, settings, prompt, dlp_result, decision, masking, False)
        labels = [entity.label for entity in dlp_result.detected_entities]
        return JSONResponse(status_code=403, content=blocked_message(labels, request_id))

    stream_settings = _streaming_settings(settings)
    _validate_streaming_settings(stream_settings)
    forwarded_payload = _payload_for_forwarding(payload, masking, stream_settings)
    stream = _sse_stream(request_id, stream_settings, prompt, dlp_result, decision, masking, forwarded_payload)
    return StreamingResponse(stream, media_type="text/event-stream", headers=_stream_headers(decision))


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


def _settings_for_payload(payload: dict[str, Any], settings: Settings) -> Settings:
    """Apply the optional request-level target override."""
    target = str(payload.get("target") or settings.target_api).strip().lower()
    if target not in {"openai", "anthropic", "gemini", "mock"}:
        raise HTTPException(status_code=400, detail="target must be openai, anthropic, gemini, or mock.")
    return replace(settings, target_api=target)


def _validate_streaming_settings(settings: Settings) -> None:
    """Validate that the streaming endpoint can reach Gemini or demo mode."""
    if settings.demo_mode or settings.target_api == "mock":
        return
    if not settings.gemini_api_key:
        raise HTTPException(status_code=500, detail="GEMINI_API_KEY is not configured.")


def _streaming_settings(settings: Settings) -> Settings:
    """Use Gemini for live streaming, while preserving demo/mock streaming."""
    if settings.demo_mode or settings.target_api == "mock":
        return settings
    return replace(settings, target_api="gemini", target_model="gemini-2.0-flash")


def _maybe_mask(prompt: str, result: DLPResult, decision: PolicyDecision) -> MaskingResult | None:
    """Run masking only when the policy decision requires it."""
    if decision.action != "MASK_AND_FORWARD":
        return None
    return mask_text(prompt, result.detected_entities)


def _payload_for_forwarding(
    payload: dict[str, Any], masking: MaskingResult | None, settings: Settings
) -> dict[str, Any]:
    """Return a copy of the request with the last user message masked if needed."""
    forwarded = deepcopy(payload)
    forwarded.pop("target", None)
    forwarded["model"] = _model_for_target(forwarded, settings)
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
        _write_audit(request_id, settings, prompt, result, decision, masking, True)
        response["gateway"] = _gateway_metadata(request_id, result, decision, masking, settings)
    except Exception:
        _write_audit(request_id, settings, prompt, result, decision, masking, False)
        raise
    return response


async def _forward_to_llm(payload: dict[str, Any], settings: Settings) -> dict[str, Any]:
    """Forward to the configured provider or return a canned demo response."""
    if settings.demo_mode or settings.target_api == "mock":
        return _demo_response(payload, settings)
    if settings.target_api == "openai":
        return await _call_openai(payload, settings)
    if settings.target_api == "anthropic":
        return await _call_anthropic(payload, settings)
    if settings.target_api == "gemini":
        return await _call_gemini(payload, settings)
    raise HTTPException(status_code=500, detail=f"Unsupported TARGET_API: {settings.target_api}")


async def _sse_stream(
    request_id: str,
    settings: Settings,
    prompt: str,
    result: DLPResult,
    decision: PolicyDecision,
    masking: MaskingResult | None,
    payload: dict[str, Any],
) -> AsyncIterator[str]:
    """Yield text chunks followed by final DLP metadata."""
    try:
        async for text in _llm_text_stream(payload, settings):
            yield _sse_event("chunk", {"text": text})
    except Exception as exc:
        audit_entry = _write_audit(request_id, settings, prompt, result, decision, masking, False)
        gateway = _gateway_metadata(request_id, result, decision, masking, settings)
        yield _sse_event("error", {"message": str(exc), "gateway": gateway, "audit_entry": audit_entry})
        return
    audit_entry = _write_audit(request_id, settings, prompt, result, decision, masking, True)
    gateway = _gateway_metadata(request_id, result, decision, masking, settings)
    yield _sse_event("done", {"gateway": gateway, "audit_entry": audit_entry})


async def _llm_text_stream(payload: dict[str, Any], settings: Settings) -> AsyncIterator[str]:
    """Stream demo chunks or Gemini chunks."""
    if settings.demo_mode or settings.target_api == "mock":
        async for text in _demo_text_stream(settings):
            yield text
        return
    async for text in _gemini_text_stream(payload, settings):
        yield text


async def _demo_text_stream(settings: Settings) -> AsyncIterator[str]:
    """Stream a short demo response in small chunks."""
    text = f"[DEMO] Gateway streamer et Gemini-svar til {settings.target_api}."
    for chunk in text.split(" "):
        yield f"{chunk} "
        await asyncio.sleep(0.035)


async def _gemini_text_stream(payload: dict[str, Any], settings: Settings) -> AsyncIterator[str]:
    """Stream Gemini's OpenAI-compatible SSE chunks."""
    stream_payload = {**payload, "stream": True, "model": "gemini-2.0-flash"}
    headers = {"Authorization": f"Bearer {settings.gemini_api_key}"}
    async with httpx.AsyncClient(timeout=90) as client:
        async with client.stream("POST", settings.target_endpoint, headers=headers, json=stream_payload) as response:
            await _raise_for_stream_error(response)
            async for line in response.aiter_lines():
                text = _text_from_stream_line(line)
                if text:
                    yield text


async def _raise_for_stream_error(response: httpx.Response) -> None:
    """Convert provider stream errors into a readable exception."""
    if response.status_code < 400:
        return
    body = (await response.aread()).decode("utf-8", errors="replace")
    raise RuntimeError(f"Gemini streaming failed ({response.status_code}): {body}")


def _text_from_stream_line(line: str) -> str:
    """Extract an OpenAI-compatible text delta from one SSE data line."""
    if not line.startswith("data: "):
        return ""
    data = line.removeprefix("data: ").strip()
    if data == "[DONE]":
        return ""
    return _text_from_stream_payload(data)


def _text_from_stream_payload(data: str) -> str:
    """Parse provider stream JSON and return only text deltas."""
    try:
        chunk = json.loads(data)
    except json.JSONDecodeError:
        return ""
    choice = (chunk.get("choices") or [{}])[0]
    delta = choice.get("delta") or {}
    message = choice.get("message") or {}
    return str(delta.get("content") or message.get("content") or "")


async def _call_openai(payload: dict[str, Any], settings: Settings) -> dict[str, Any]:
    """Forward the request to OpenAI's chat completions API."""
    if not settings.openai_api_key:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY is not configured.")
    headers = {"Authorization": f"Bearer {settings.openai_api_key}"}
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(settings.target_endpoint, headers=headers, json=payload)
    return _checked_json_response(response)


async def _call_gemini(payload: dict[str, Any], settings: Settings) -> dict[str, Any]:
    """Forward to Gemini through Google's OpenAI-compatible endpoint."""
    if not settings.gemini_api_key:
        raise HTTPException(status_code=500, detail="GEMINI_API_KEY is not configured.")
    headers = {"Authorization": f"Bearer {settings.gemini_api_key}"}
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
        "model": _model_for_target(payload, settings),
        "max_tokens": payload.get("max_tokens", 512),
        "messages": payload.get("messages", []),
    }


def _model_for_target(payload: dict[str, Any], settings: Settings) -> str:
    """Return the outgoing model name for the selected target."""
    if settings.target_api == "gemini":
        return "gemini-2.0-flash"
    return payload.get("model") or settings.target_model


def _checked_json_response(response: httpx.Response) -> dict[str, Any]:
    """Return provider JSON or convert provider errors into gateway errors."""
    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    return response.json()


def _demo_response(payload: dict[str, Any], settings: Settings) -> dict[str, Any]:
    """Return an OpenAI-compatible canned response for offline demonstrations."""
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": (
                        "[DEMO] Gateway modtog din maskerede prompt og ville "
                        f"have sendt den til {settings.target_api}."
                    ),
                }
            }
        ]
    }


def _gateway_metadata(
    request_id: str,
    result: DLPResult,
    decision: PolicyDecision,
    masking: MaskingResult | None,
    settings: Settings,
) -> dict[str, Any]:
    """Build sanitized response metadata for the demo UI."""
    return {
        "request_id": request_id,
        "target_api": settings.target_api,
        "policy_action": decision.action,
        "policy_reason": decision.reason,
        "policy_rule_triggered": decision.triggered_rule,
        "masked_tokens": list(masking.token_mapping.keys()) if masking else [],
        "detected_entities": [{"label": entity.label, "stage": entity.stage} for entity in result.detected_entities],
    }


def _response_headers(decision: PolicyDecision) -> dict[str, str]:
    """Return response headers for the policy action."""
    if decision.action == "MASK_AND_FORWARD":
        return {"X-DLP-Warning": warning_header_value()}
    return {}


def _stream_headers(decision: PolicyDecision) -> dict[str, str]:
    """Return headers for SSE responses."""
    headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    if decision.action == "MASK_AND_FORWARD":
        headers["X-DLP-Warning"] = "Sensitive data masked. See security policy."
    return headers


def _sse_event(event: str, data: dict[str, Any]) -> str:
    """Format one Server-Sent Event."""
    payload = json.dumps(data, ensure_ascii=False)
    return f"event: {event}\ndata: {payload}\n\n"


def _write_audit(
    request_id: str,
    settings: Settings,
    prompt: str,
    result: DLPResult,
    decision: PolicyDecision,
    masking: MaskingResult | None,
    forwarded: bool,
) -> dict[str, Any]:
    """Write a sanitized audit entry for every gateway interaction."""
    entry = build_audit_entry(
        request_id=request_id,
        target_api=settings.target_api,
        original_prompt_length=len(prompt),
        detected_entities=result.detected_entities,
        masked_values_stored=bool(masking and masking.token_mapping),
        policy_decision=decision,
        forwarded_to_llm=forwarded,
    )
    log_interaction(entry, settings.log_file)
    return entry
